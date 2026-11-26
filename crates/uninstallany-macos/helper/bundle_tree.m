#import "bundle_exclusion.h"
#import "isolated_bundle.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    MaximumBundleDepth = 48,
    MaximumBundleEntries = 100000,
};

static const int DirectoryFlags = O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW;
static const int LeafFlags = O_EVTONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
static const uint32_t ProtectedFlags =
    UF_IMMUTABLE | UF_APPEND | UF_OPAQUE | UF_DATAVAULT | SF_IMMUTABLE | SF_APPEND
    | SF_NOUNLINK | SF_RESTRICTED | SF_FIRMLINK | SF_DATALESS;

typedef struct {
    dev_t device;
    fsid_t volume;
    size_t inspected;
    bool standalone;
} UABundleTree;

static void UACloseDescriptor(int *descriptor) {
    if (*descriptor >= 0) {
        close(*descriptor);
    }
}

static void UACloseDirectory(DIR **directory) {
    if (*directory != NULL) {
        closedir(*directory);
    }
}

static int UARequireNoACL(int descriptor) {
    errno = 0;
    acl_t acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
    if (acl != NULL) {
        acl_free(acl);
        return EPERM;
    }
    // ACL lookup failures must not give the mode bits authority.
    if (errno == ENOENT) {
        return 0;
    }
    return errno != 0 ? errno : EIO;
}

static int UARequireProtectedEntry(const struct stat *entry, const UABundleTree *tree) {
    if (entry->st_dev != tree->device) {
        return EXDEV;
    }
    if (entry->st_uid != 0 || (entry->st_flags & ProtectedFlags) != 0) {
        return EPERM;
    }
    bool isLink = S_ISLNK(entry->st_mode);
    // Symlinks report 0777. Their own ACL is checked through the link fd.
    if (!isLink && (entry->st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID)) != 0) {
        return EPERM;
    }
    if (S_ISDIR(entry->st_mode)) {
        return 0;
    }
    if (!isLink && !S_ISREG(entry->st_mode)) {
        return ENOTSUP;
    }
    return entry->st_nlink == 1 ? 0 : EMLINK;
}

static bool UASameTime(struct timespec first, struct timespec second) {
    return first.tv_sec == second.tv_sec && first.tv_nsec == second.tv_nsec;
}

static bool UASameEntry(const struct stat *expected, const struct stat *actual) {
    return expected->st_dev == actual->st_dev && expected->st_ino == actual->st_ino
        && expected->st_mode == actual->st_mode && expected->st_uid == actual->st_uid
        && expected->st_gid == actual->st_gid && expected->st_flags == actual->st_flags
        && expected->st_nlink == actual->st_nlink && expected->st_size == actual->st_size
        && UASameTime(expected->st_birthtimespec, actual->st_birthtimespec)
        && UASameTime(expected->st_ctimespec, actual->st_ctimespec)
        && UASameTime(expected->st_mtimespec, actual->st_mtimespec);
}

static int UARequireSameVolume(int descriptor, const UABundleTree *tree) {
    struct statfs volume;
    if (fstatfs(descriptor, &volume) != 0) {
        return errno;
    }
    return memcmp(&volume.f_fsid, &tree->volume, sizeof(tree->volume)) == 0 ? 0 : EXDEV;
}

static int UACheckOpenDirectory(int descriptor, UABundleTree *tree, unsigned int depth);

static int UACheckChild(int parent, const char *name, UABundleTree *tree, unsigned int depth) {
    struct stat expected;
    if (fstatat(parent, name, &expected, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno;
    }
    int status = UARequireProtectedEntry(&expected, tree);
    if (status != 0) {
        return status;
    }

    bool isDirectory = S_ISDIR(expected.st_mode);
    if (tree->standalone) {
        const char *extension = strrchr(name, '.');
        if (S_ISLNK(expected.st_mode)
            || (isDirectory && extension != NULL && strcasecmp(extension, ".app") == 0)) {
            return ENOTSUP;
        }
    }
    // Only enumeration needs a readable fd. O_SYMLINK opens the link itself
    // so the verifier can check its ACL without resolving its target.
    int flags = isDirectory ? DirectoryFlags : LeafFlags;
    if (S_ISLNK(expected.st_mode)) {
        flags |= O_SYMLINK;
    }
    int descriptor __attribute__((cleanup(UACloseDescriptor))) = openat(parent, name, flags);
    if (descriptor < 0) {
        return errno;
    }
    struct stat actual;
    if (fstat(descriptor, &actual) != 0) {
        return errno;
    }
    if (!UASameEntry(&expected, &actual)) {
        return ESTALE;
    }
    status = UARequireSameVolume(descriptor, tree);
    if (status == 0) {
        status = UARequireNoACL(descriptor);
    }
    if (status != 0) {
        return status;
    }
    if (isDirectory) {
        int subtree = descriptor;
        descriptor = -1;
        status = UACheckOpenDirectory(subtree, tree, depth);
        if (status != 0) {
            return status;
        }
    }
    if (fstatat(parent, name, &actual, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno;
    }
    return UASameEntry(&expected, &actual) ? 0 : ESTALE;
}

// Consumes the descriptor including error paths so only one directory
// stream per level remains open.
static int UACheckOpenDirectory(int descriptor, UABundleTree *tree, unsigned int depth) {
    DIR *directory __attribute__((cleanup(UACloseDirectory))) = fdopendir(descriptor);
    if (directory == NULL) {
        int failure = errno;
        close(descriptor);
        return failure;
    }
    if (depth >= MaximumBundleDepth) {
        return ELOOP;
    }
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            return errno;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (tree->inspected == MaximumBundleEntries) {
            return E2BIG;
        }
        tree->inspected++;
        int status = UACheckChild(descriptor, entry->d_name, tree, depth + 1);
        if (status != 0) {
            return status;
        }
    }
}

// Validate a borrowed, preverified bundle descriptor before an exclusive
// rename. The caller still checks the parent and current basename binding.
// These checks restrict namespace changes by ordinary users. They do not
// freeze existing writable fds/mappings or concurrent privileged writers.
static int UACheckBundleTree(int bundleDescriptor, bool standalone) {
    struct stat expected;
    struct statfs volume;
    if (fstat(bundleDescriptor, &expected) != 0 || fstatfs(bundleDescriptor, &volume) != 0) {
        return errno;
    }
    if (!S_ISDIR(expected.st_mode)) {
        return ENOTDIR;
    }
    if (strcmp(volume.f_fstypename, "apfs") != 0 || (volume.f_flags & MNT_LOCAL) == 0
        || (volume.f_flags & (MNT_IGNORE_OWNERSHIP | MNT_RDONLY)) != 0) {
        return ENOTSUP;
    }
    UABundleTree tree = {
        .device = expected.st_dev,
        .volume = volume.f_fsid,
        .standalone = standalone,
    };
    int status = UARequireProtectedEntry(&expected, &tree);
    if (status == 0) {
        status = UARequireNoACL(bundleDescriptor);
    }
    if (status != 0) {
        return status;
    }
    // dup() would share the caller's directory enumeration offset.
    int descriptor = openat(bundleDescriptor, ".", DirectoryFlags);
    if (descriptor < 0) {
        return errno;
    }
    status = UACheckOpenDirectory(descriptor, &tree, 0);
    if (status != 0) {
        return status;
    }
    struct stat actual;
    if (fstat(bundleDescriptor, &actual) != 0) {
        return errno;
    }
    return UASameEntry(&expected, &actual) ? 0 : ESTALE;
}

int UACheckProtectedBundleTree(int bundleDescriptor) {
    return UACheckBundleTree(bundleDescriptor, false);
}

int UACheckProtectedStandaloneBundleTree(int bundleDescriptor) {
    return UACheckBundleTree(bundleDescriptor, true);
}
