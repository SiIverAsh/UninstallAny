#import "bundle_exclusion.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    MaximumInfoBytes = 2 * 1024 * 1024,
    MaximumLaunchdPlistBytes = 256 * 1024,
    MaximumLaunchdTotalBytes = 16 * 1024 * 1024,
    MaximumLaunchdEntries = 512,
    MaximumServiceValues = 256,
};

static const int DirectoryFlags = O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW;
static const int PlistFlags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;

static void UACloseBackgroundFD(int *descriptor) {
    if (*descriptor >= 0) {
        int failure = errno;
        close(*descriptor);
        errno = failure;
    }
}

static void UACloseBackgroundDirectory(DIR **directory) {
    if (*directory != NULL) {
        closedir(*directory);
    }
}

static int UAGuardBackgroundMetadata(int descriptor, const struct stat *entry) {
    if (entry->st_uid != 0 || (entry->st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return EPERM;
    }
    // A writable ACL can give away mutation rights hidden by the mode bits.
    errno = 0;
    acl_t acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
    if (acl == NULL) {
        return errno == ENOENT ? 0 : (errno != 0 ? errno : EIO);
    }
    acl_free(acl);
    return EPERM;
}

static bool UASameBackgroundTime(struct timespec expected, struct timespec actual) {
    return expected.tv_sec == actual.tv_sec && expected.tv_nsec == actual.tv_nsec;
}

static bool UASameBackgroundEntry(const struct stat *expected, const struct stat *actual) {
    return expected->st_dev == actual->st_dev && expected->st_ino == actual->st_ino
        && expected->st_mode == actual->st_mode && expected->st_uid == actual->st_uid
        && expected->st_gid == actual->st_gid && expected->st_flags == actual->st_flags
        && expected->st_size == actual->st_size && expected->st_nlink == actual->st_nlink
        && UASameBackgroundTime(expected->st_birthtimespec, actual->st_birthtimespec)
        && UASameBackgroundTime(expected->st_ctimespec, actual->st_ctimespec)
        && UASameBackgroundTime(expected->st_mtimespec, actual->st_mtimespec);
}

static int UAOpenBackgroundDirectory(int parent, const char *name, struct stat *entry) {
    int descriptor = openat(parent, name, DirectoryFlags);
    if (descriptor < 0) {
        return -1;
    }
    int status = fstat(descriptor, entry) == 0
        ? UAGuardBackgroundMetadata(descriptor, entry) : errno;
    if (status != 0) {
        UACloseBackgroundFD(&descriptor);
        errno = status;
        return -1;
    }
    return descriptor;
}

static int UAReadBackgroundPlist(int parent, const char *name, dev_t device,
                                 size_t *remaining, NSDictionary **plist) {
    struct stat expected;
    if (fstatat(parent, name, &expected, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno;
    }
    if (!S_ISREG(expected.st_mode) || expected.st_nlink != 1 || expected.st_dev != device
        || (expected.st_flags & (UF_DATAVAULT | SF_DATALESS)) != 0) {
        return EPERM;
    }
    if (expected.st_size <= 0 || (uintmax_t)expected.st_size > *remaining) {
        return EFBIG;
    }
    int file __attribute__((cleanup(UACloseBackgroundFD))) = openat(parent, name, PlistFlags);
    if (file < 0) {
        return errno;
    }
    struct stat actual;
    if (fstat(file, &actual) != 0 || !UASameBackgroundEntry(&expected, &actual)) {
        return ESTALE;
    }
    int status = UAGuardBackgroundMetadata(file, &actual);
    if (status != 0) {
        return status;
    }
    NSMutableData *bytes = [NSMutableData dataWithLength:(NSUInteger)expected.st_size];
    unsigned char *buffer = bytes.mutableBytes;
    for (size_t offset = 0; offset < bytes.length;) {
        ssize_t count = pread(file, buffer + offset, bytes.length - offset, (off_t)offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return count == 0 ? EIO : errno;
        }
        offset += (size_t)count;
    }
    if (fstatat(parent, name, &actual, AT_SYMLINK_NOFOLLOW) != 0
        || !UASameBackgroundEntry(&expected, &actual)) {
        return ESTALE;
    }
    id decoded = [NSPropertyListSerialization propertyListWithData:bytes
                                                           options:NSPropertyListImmutable
                                                            format:NULL
                                                             error:NULL];
    if (![decoded isKindOfClass:NSDictionary.class]) {
        return EBADMSG;
    }
    *remaining -= bytes.length;
    *plist = decoded;
    return 0;
}

static int UAEmbeddedBackgroundEvidence(int bundle, const struct stat *bundleEntry,
                                        NSString *identifier) {
    struct stat contentsEntry;
    int contents __attribute__((cleanup(UACloseBackgroundFD))) =
        UAOpenBackgroundDirectory(bundle, "Contents", &contentsEntry);
    if (contents < 0 || contentsEntry.st_dev != bundleEntry->st_dev) {
        return contents < 0 ? errno : EXDEV;
    }
    NSDictionary *info = nil;
    size_t remaining = MaximumInfoBytes;
    int status = UAReadBackgroundPlist(contents, "Info.plist", bundleEntry->st_dev,
                                      &remaining, &info);
    if (status != 0) {
        return status;
    }
    id observedIdentifier = info[@"CFBundleIdentifier"];
    if (![observedIdentifier isKindOfClass:NSString.class]
        || ![identifier isEqualToString:observedIdentifier]) {
        return ESTALE;
    }
    id legacyHelpers = info[@"SMPrivilegedExecutables"];
    if (legacyHelpers != nil) {
        if (![legacyHelpers isKindOfClass:NSDictionary.class]) {
            return EBADMSG;
        }
        if ([legacyHelpers count] != 0) {
            return EBUSY;
        }
    }

    struct stat libraryEntry;
    int library __attribute__((cleanup(UACloseBackgroundFD))) =
        UAOpenBackgroundDirectory(contents, "Library", &libraryEntry);
    if (library < 0 && errno != ENOENT) {
        return errno;
    }
    if (library >= 0 && libraryEntry.st_dev != bundleEntry->st_dev) {
        return EXDEV;
    }
    // A declaration can outlive an inactive job. Preserve the whole bundle
    // while it contains a ServiceManagement or system extension layout.
    const char *locations[] = {"LaunchAgents", "LaunchDaemons", "LoginItems",
                               "LaunchServices", "SystemExtensions"};
    struct stat current;
    if (library >= 0) {
        for (size_t index = 0; index < sizeof(locations) / sizeof(locations[0]); index++) {
            if (fstatat(library, locations[index], &current, AT_SYMLINK_NOFOLLOW) == 0) {
                return EBUSY;
            }
            if (errno != ENOENT) {
                return errno;
            }
        }
        if (fstatat(contents, "Library", &current, AT_SYMLINK_NOFOLLOW) != 0
            || !UASameBackgroundEntry(&libraryEntry, &current)) {
            return ESTALE;
        }
    }
    return fstatat(bundle, "Contents", &current, AT_SYMLINK_NOFOLLOW) == 0
        && UASameBackgroundEntry(&contentsEntry, &current) ? 0 : ESTALE;
}

static bool UAServiceNamespace(NSString *label, NSString *identifier) {
    NSString *namespace = [identifier stringByAppendingString:@"."];
    return [label caseInsensitiveCompare:identifier] == NSOrderedSame
        || [label rangeOfString:namespace options:NSCaseInsensitiveSearch | NSAnchoredSearch].location
            != NSNotFound;
}

static bool UALaunchdValueReferencesBundle(NSString *value, NSString *basename,
                                           NSString *identifier) {
    if ([value caseInsensitiveCompare:identifier] == NSOrderedSame
        || [value caseInsensitiveCompare:basename] == NSOrderedSame) {
        return true;
    }
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    // Comparison is lexical. Check both visible and Data volume path
    // spellings without opening a service's executable or any symlink.
    for (NSString *part in [value componentsSeparatedByString:@"/"]) {
        if (part.length == 0 || [part isEqualToString:@"."]) {
            continue;
        }
        if ([part isEqualToString:@".."] && parts.count != 0) {
            [parts removeLastObject];
            continue;
        }
        [parts addObject:part];
    }
    for (NSUInteger index = 1; index < parts.count; index++) {
        if ([parts[index - 1] caseInsensitiveCompare:@"Applications"] == NSOrderedSame
            && [parts[index] caseInsensitiveCompare:basename] == NSOrderedSame) {
            return true;
        }
    }
    return false;
}

static int UACheckLaunchdRecord(NSDictionary *plist, NSString *basename, NSString *identifier) {
    id label = plist[@"Label"];
    if (![label isKindOfClass:NSString.class] || [label length] == 0) {
        return EBADMSG;
    }
    if (UAServiceNamespace(label, identifier)) {
        return EBUSY;
    }

    id associations = plist[@"AssociatedBundleIdentifiers"];
    if ([associations isKindOfClass:NSString.class]) {
        associations = @[associations];
    }
    if (associations != nil) {
        if (![associations isKindOfClass:NSArray.class] || [associations count] > MaximumServiceValues) {
            return EBADMSG;
        }
        for (id entry in associations) {
            if (![entry isKindOfClass:NSString.class] || [entry length] == 0) {
                return EBADMSG;
            }
            if (UAServiceNamespace(entry, identifier)) {
                return EBUSY;
            }
        }
    }

    for (NSString *key in @[@"Program", @"BundleProgram", @"RootDirectory", @"WorkingDirectory"]) {
        id value = plist[key];
        if (value != nil) {
            if (![value isKindOfClass:NSString.class] || [value length] == 0) {
                return EBADMSG;
            }
            if (UALaunchdValueReferencesBundle(value, basename, identifier)) {
                return EBUSY;
            }
        }
    }
    id arguments = plist[@"ProgramArguments"];
    if (arguments != nil) {
        if (![arguments isKindOfClass:NSArray.class] || [arguments count] > MaximumServiceValues) {
            return EBADMSG;
        }
        for (id argument in arguments) {
            if (![argument isKindOfClass:NSString.class]) {
                return EBADMSG;
            }
            if (UALaunchdValueReferencesBundle(argument, basename, identifier)) {
                return EBUSY;
            }
        }
    }
    return 0;
}

typedef struct {
    size_t remainingEntries;
    size_t remainingBytes;
} UALaunchdBudget;

static int UAScanLaunchdDirectory(int library, const char *name, NSString *basename,
                                  NSString *identifier, UALaunchdBudget *budget) {
    struct stat entry, libraryEntry;
    int descriptor __attribute__((cleanup(UACloseBackgroundFD))) =
        UAOpenBackgroundDirectory(library, name, &entry);
    if (descriptor < 0) {
        return errno == ENOENT ? 0 : errno;
    }
    if (fstat(library, &libraryEntry) != 0 || entry.st_dev != libraryEntry.st_dev) {
        return EXDEV;
    }
    DIR *directory __attribute__((cleanup(UACloseBackgroundDirectory))) = fdopendir(descriptor);
    if (directory == NULL) {
        return errno;
    }
    int parent = descriptor;
    descriptor = -1;
    for (;;) {
        errno = 0;
        struct dirent *item = readdir(directory);
        if (item == NULL) {
            if (errno != 0) {
                return errno;
            }
            struct stat current;
            return fstatat(library, name, &current, AT_SYMLINK_NOFOLLOW) == 0
                && UASameBackgroundEntry(&entry, &current) ? 0 : ESTALE;
        }
        if (strcmp(item->d_name, ".") == 0 || strcmp(item->d_name, "..") == 0) {
            continue;
        }
        if (budget->remainingEntries == 0) {
            return E2BIG;
        }
        budget->remainingEntries--;
        @autoreleasepool {
            NSString *filename = [NSString stringWithUTF8String:item->d_name];
            if (filename == nil) {
                return EBADMSG;
            }
            if ([filename.pathExtension caseInsensitiveCompare:@"plist"] != NSOrderedSame) {
                continue;
            }
            if (UAServiceNamespace(filename.stringByDeletingPathExtension, identifier)) {
                return EBUSY;
            }
            size_t cap = MIN(budget->remainingBytes, (size_t)MaximumLaunchdPlistBytes);
            size_t remaining = cap;
            NSDictionary *plist = nil;
            int status = UAReadBackgroundPlist(parent, item->d_name, entry.st_dev, &remaining, &plist);
            if (status != 0) {
                return status;
            }
            budget->remainingBytes -= cap - remaining;
            status = UACheckLaunchdRecord(plist, basename, identifier);
            if (status != 0) {
                return status;
            }
        }
    }
}

int UACheckSystemBundleBackground(NSString *basename, NSString *bundleIdentifier,
                                   int bundleDescriptor) {
    struct stat bundleEntry;
    if (fstat(bundleDescriptor, &bundleEntry) != 0) {
        return errno;
    }
    if (!S_ISDIR(bundleEntry.st_mode)) {
        return ENOTDIR;
    }
    int status = UAGuardBackgroundMetadata(bundleDescriptor, &bundleEntry);
    if (status != 0) {
        return status;
    }
    status = UAEmbeddedBackgroundEvidence(bundleDescriptor, &bundleEntry, bundleIdentifier);
    if (status != 0) {
        return status;
    }

    struct stat rootEntry, libraryEntry;
    int root __attribute__((cleanup(UACloseBackgroundFD))) =
        UAOpenBackgroundDirectory(AT_FDCWD, "/", &rootEntry);
    if (root < 0) {
        return errno;
    }
    int library __attribute__((cleanup(UACloseBackgroundFD))) =
        UAOpenBackgroundDirectory(root, "Library", &libraryEntry);
    if (library < 0) {
        return errno;
    }
    struct statfs mount;
    if (libraryEntry.st_dev != bundleEntry.st_dev || fstatfs(library, &mount) != 0
        || strcmp(mount.f_fstypename, "apfs") != 0 || (mount.f_flags & MNT_LOCAL) == 0
        || (mount.f_flags & MNT_IGNORE_OWNERSHIP) != 0) {
        return ENOTSUP;
    }
    UALaunchdBudget budget = {MaximumLaunchdEntries, MaximumLaunchdTotalBytes};
    status = UAScanLaunchdDirectory(library, "LaunchAgents", basename, bundleIdentifier, &budget);
    if (status == 0) {
        status = UAScanLaunchdDirectory(library, "LaunchDaemons", basename, bundleIdentifier, &budget);
    }
    if (status != 0) {
        return status;
    }
    struct stat current;
    // Only disk declarations in this scope are verified. Launchd can also
    // manage per-user and dynamically submitted jobs outside this catalog.
    return fstatat(root, "Library", &current, AT_SYMLINK_NOFOLLOW) == 0
        && UASameBackgroundEntry(&libraryEntry, &current) ? 0 : ESTALE;
}
