#import "bundle_exclusion.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum {
    MaximumProcessCount = 16384,
    MaximumSurveyAttempts = 2,
};

static const uint64_t SurveyWindowNanoseconds = UINT64_C(3000000000);

static void UACloseDirectory(int *descriptor) {
    if (*descriptor >= 0) {
        close(*descriptor);
    }
}

static void UAFreeProcessIDs(pid_t **processIDs) {
    free(*processIDs);
}

static bool UASameBundle(const struct stat *first, const struct stat *second) {
    return S_ISDIR(first->st_mode) && S_ISDIR(second->st_mode)
        && first->st_uid == 0 && second->st_uid == 0
        && first->st_dev == second->st_dev && first->st_ino == second->st_ino
        && first->st_birthtimespec.tv_sec == second->st_birthtimespec.tv_sec
        && first->st_birthtimespec.tv_nsec == second->st_birthtimespec.tv_nsec;
}

static int UACheckNamedBundle(int applications, const char *basename, const struct stat *expected) {
    struct stat actual;
    if (fstatat(applications, basename, &actual, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno;
    }
    return UASameBundle(&actual, expected) ? 0 : ESTALE;
}

static const char *UAApplicationsEntry(const char *executable) {
    static const char *const scopes[] = {"/Applications/", "/System/Volumes/Data/Applications/"};
    for (size_t index = 0; index < sizeof(scopes) / sizeof(scopes[0]); index++) {
        size_t length = strlen(scopes[index]);
        if (strncasecmp(executable, scopes[index], length) == 0) {
            return executable + length;
        }
    }
    return NULL;
}

static int UACheckExecutableLocation(const char *executable, int applications,
                                    const struct stat *bundle) {
    const char *entry = UAApplicationsEntry(executable);
    if (entry == NULL) {
        return 0;
    }
    const char *separator = strchr(entry, '/');
    size_t length = separator == NULL ? strlen(entry) : (size_t)(separator - entry);
    if (length == 0 || length > NAME_MAX) {
        return EPROTO;
    }
    char name[NAME_MAX + 1];
    memcpy(name, entry, length);
    name[length] = '\0';
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return EPROTO;
    }
    // APFS may resolve different case or Unicode spellings to the same
    // directory. Compare the immediate entry without using the path tail.
    struct stat actual;
    if (fstatat(applications, name, &actual, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno;
    }
    if (S_ISLNK(actual.st_mode)) {
        return ELOOP;
    }
    return UASameBundle(&actual, bundle) ? EBUSY : 0;
}

static int UAReadProcess(pid_t pid, struct proc_bsdinfo *process) {
    errno = 0;
    int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, process, sizeof(*process));
    if (count == 0) {
        if (errno == ESRCH) {
            return EAGAIN;
        }
        return errno != 0 ? errno : EIO;
    }
    if ((size_t)count != sizeof(*process) || process->pbi_pid != (uint32_t)pid) {
        return EPROTO;
    }
    return 0;
}

static int UASampleProcess(pid_t pid, int applications, const struct stat *bundle,
                           CC_SHA256_CTX *hash) {
    struct proc_bsdinfo before;
    int status = UAReadProcess(pid, &before);
    if (status != 0) {
        return status;
    }
    char path[PROC_PIDPATHINFO_MAXSIZE];
    int length = 0;
    if (before.pbi_status != SZOMB) {
        errno = 0;
        length = proc_pidpath(pid, path, sizeof(path));
        if (length == 0) {
            if (errno != ESRCH) {
                return errno != 0 ? errno : EIO;
            }
            if ((before.pbi_flags & PROC_FLAG_SYSTEM) == 0) {
                return EAGAIN;
            }
        }
        if (length < 0 || (size_t)length >= sizeof(path) || (length > 0 && path[0] != '/')) {
            return EPROTO;
        }
    }
    struct proc_bsdinfo after;
    status = UAReadProcess(pid, &after);
    if (status != 0) {
        return status;
    }
    if (before.pbi_start_tvsec != after.pbi_start_tvsec
        || before.pbi_start_tvusec != after.pbi_start_tvusec
        || (before.pbi_status == SZOMB) != (after.pbi_status == SZOMB)) {
        return EAGAIN;
    }
    if (length > 0) {
        if (path[length] != '\0' || strnlen(path, sizeof(path)) != (size_t)length) {
            return EPROTO;
        }
        status = UACheckExecutableLocation(path, applications, bundle);
        if (status != 0) {
            return status;
        }
    }
    const uint64_t sample[] = {
        (uint64_t)pid, before.pbi_start_tvsec, before.pbi_start_tvusec, (uint64_t)length,
    };
    CC_SHA256_Update(hash, sample, sizeof(sample));
    if (length > 0) {
        CC_SHA256_Update(hash, path, (CC_LONG)length);
    }
    return 0;
}

static int UACompareProcessIDs(const void *left, const void *right) {
    pid_t first = *(const pid_t *)left;
    pid_t second = *(const pid_t *)right;
    return (first > second) - (first < second);
}

static int UASurveyProcesses(pid_t *processIDs, int applications, const struct stat *bundle,
                             uint64_t deadline, unsigned char digest[CC_SHA256_DIGEST_LENGTH]) {
    if (clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) >= deadline) {
        return ETIMEDOUT;
    }
    const int capacity = MaximumProcessCount * sizeof(*processIDs);
    errno = 0;
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, processIDs, capacity);
    if (bytes <= 0) {
        return errno != 0 ? errno : EIO;
    }
    if (bytes >= capacity) {
        return E2BIG;
    }
    if ((size_t)bytes % sizeof(*processIDs) != 0) {
        return EPROTO;
    }
    size_t count = (size_t)bytes / sizeof(*processIDs);
    // The kernel can reorder its process list between otherwise equal reads.
    qsort(processIDs, count, sizeof(*processIDs), UACompareProcessIDs);
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    bool hasUserspaceProcess = false;
    for (size_t index = 0; index < count; index++) {
        pid_t pid = processIDs[index];
        if (pid < 0 || (index > 0 && processIDs[index - 1] == pid)) {
            return EPROTO;
        }
        if (pid == 0) {
            continue;
        }
        hasUserspaceProcess = true;
        if (clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) >= deadline) {
            return ETIMEDOUT;
        }
        int status = UASampleProcess(pid, applications, bundle, &hash);
        if (status != 0) {
            return status;
        }
    }
    if (!hasUserspaceProcess) {
        return EPROTO;
    }
    CC_SHA256_Final(digest, &hash);
    return 0;
}

int UACheckSystemBundleActivity(NSString *basename, int bundleDescriptor) {
    // The caller holds the guarded descriptor. Check near the move to
    // narrow the window for a new launch. An interpreter or library host
    // can have an executable vnode outside the bundle it loads.
    if (geteuid() != 0) {
        return EACCES;
    }
    char name[NAME_MAX + 1];
    if (![basename getFileSystemRepresentation:name maxLength:sizeof(name)]
        || name[0] == '.' || strchr(name, '/') != NULL
        || [basename.pathExtension caseInsensitiveCompare:@"app"] != NSOrderedSame) {
        return EINVAL;
    }
    struct stat bundle;
    if (fstat(bundleDescriptor, &bundle) != 0) {
        return errno;
    }
    int applications __attribute__((cleanup(UACloseDirectory))) =
        open("/Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (applications < 0) {
        return errno;
    }
    int status = UACheckNamedBundle(applications, name, &bundle);
    if (status != 0) {
        return status;
    }
    pid_t *processIDs __attribute__((cleanup(UAFreeProcessIDs))) =
        malloc(MaximumProcessCount * sizeof(*processIDs));
    if (processIDs == NULL) {
        return ENOMEM;
    }
    uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + SurveyWindowNanoseconds;
    // Read process birth identity and executable paths twice so a reused
    // PID or a process changing executables cannot provide stale evidence.
    for (size_t attempt = 0; attempt < MaximumSurveyAttempts; attempt++) {
        unsigned char first[CC_SHA256_DIGEST_LENGTH], second[CC_SHA256_DIGEST_LENGTH];
        status = UASurveyProcesses(processIDs, applications, &bundle, deadline, first);
        if (status == 0) {
            status = UASurveyProcesses(processIDs, applications, &bundle, deadline, second);
            if (status == 0 && memcmp(first, second, sizeof(first)) == 0) {
                if (clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) >= deadline) {
                    return ETIMEDOUT;
                }
                return UACheckNamedBundle(applications, name, &bundle);
            }
        }
        if (status != 0 && status != EAGAIN) {
            return status;
        }
    }
    return EAGAIN;
}
