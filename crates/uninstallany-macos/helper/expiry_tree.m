#import "expiry_tree.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CFByteOrder.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    MaximumExpiryDepth = 48,
    MaximumExpiryEntries = 100000,
    FingerprintLength = CC_SHA256_DIGEST_LENGTH * 2,
    NanosecondsPerSecond = 1000000000,
};

static const int DirectoryFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
static const int FileFlags = O_EVTONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
static const uint32_t ProtectedFlags =
    UF_IMMUTABLE | UF_APPEND | UF_OPAQUE | UF_DATAVAULT | SF_IMMUTABLE | SF_APPEND
    | SF_NOUNLINK | SF_RESTRICTED | SF_FIRMLINK | SF_DATALESS;
static const char PendingName[] = "expiry.pending";

typedef struct {
    unsigned char bytes[CC_SHA256_DIGEST_LENGTH];
    size_t length;
} UAExpiryPath;

typedef struct UAExpiryDirectory {
    const struct UAExpiryDirectory *ancestor;
    const char *name;
    int parent;
    int descriptor;
    struct stat entry;
} UAExpiryDirectory;

typedef int (^UAExpiryVisitor)(NSString *);
typedef BOOL (^UAExpiryContinuation)(void);

typedef struct {
    dev_t device;
    fsid_t volume;
    size_t remainingNames;
    __unsafe_unretained UAExpiryVisitor visit;
    __unsafe_unretained UAExpiryContinuation mayContinue;
} UAExpiryWalk;

static void UACloseFD(int *descriptor) {
    if (*descriptor >= 0) {
        int failure = errno;
        close(*descriptor);
        errno = failure;
    }
}

static void UACloseDirectory(DIR **directory) {
    if (*directory != NULL) {
        closedir(*directory);
    }
}

static bool UASameTime(struct timespec first, struct timespec second) {
    return first.tv_sec == second.tv_sec && first.tv_nsec == second.tv_nsec;
}

static bool UASameMetadata(const struct stat *first, const struct stat *second) {
    return first->st_dev == second->st_dev && first->st_ino == second->st_ino
        && first->st_mode == second->st_mode && first->st_uid == second->st_uid
        && first->st_gid == second->st_gid && first->st_flags == second->st_flags
        && UASameTime(first->st_birthtimespec, second->st_birthtimespec);
}

static bool UASameEntry(const struct stat *first, const struct stat *second) {
    return UASameMetadata(first, second) && first->st_size == second->st_size
        && first->st_nlink == second->st_nlink
        && UASameTime(first->st_ctimespec, second->st_ctimespec)
        && UASameTime(first->st_mtimespec, second->st_mtimespec);
}

static bool UAUsableVolume(const struct statfs *volume) {
    return strcmp(volume->f_fstypename, "apfs") == 0
        && (volume->f_flags & MNT_LOCAL) != 0
        && (volume->f_flags & (MNT_IGNORE_OWNERSHIP | MNT_RDONLY)) == 0;
}

static int UAPrepareWalk(int directory, UAExpiryWalk *walk) {
    struct stat entry;
    struct statfs volume;
    if (fstat(directory, &entry) != 0 || fstatfs(directory, &volume) != 0) {
        return errno;
    }
    if (!S_ISDIR(entry.st_mode) || !UAUsableVolume(&volume)) {
        return ENOTSUP;
    }
    walk->device = entry.st_dev;
    walk->volume = volume.f_fsid;
    walk->remainingNames = MaximumExpiryEntries - 1;
    return 0;
}

static int UARequireMetadata(const UAExpiryWalk *walk, const struct stat *entry) {
    if (entry->st_dev != walk->device) {
        return EXDEV;
    }
    if (entry->st_ino == 0 || entry->st_birthtimespec.tv_sec <= 0
        || entry->st_birthtimespec.tv_nsec < 0
        || entry->st_birthtimespec.tv_nsec >= NanosecondsPerSecond) {
        return ESTALE;
    }
    if (entry->st_uid != 0 || (entry->st_flags & ProtectedFlags) != 0
        || (entry->st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID)) != 0) {
        return EPERM;
    }
    if (S_ISDIR(entry->st_mode)) {
        return 0;
    }
    if (!S_ISREG(entry->st_mode)) {
        return ENOTSUP;
    }
    return entry->st_nlink == 1 ? 0 : EMLINK;
}

static int UARequireDescriptor(int descriptor, const UAExpiryWalk *walk) {
    struct statfs volume;
    if (fstatfs(descriptor, &volume) != 0) {
        return errno;
    }
    if (!UAUsableVolume(&volume) || memcmp(&volume.f_fsid, &walk->volume, sizeof(walk->volume)) != 0) {
        return EXDEV;
    }
    errno = 0;
    acl_t acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
    if (acl != NULL) {
        acl_free(acl);
        return EPERM;
    }
    return errno == ENOENT ? 0 : (errno != 0 ? errno : EIO);
}

static int UAOpenMember(int parent, const char *name, const UAExpiryWalk *walk,
                        struct stat *entry, int *descriptor) {
    if (fstatat(parent, name, entry, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno;
    }
    int status = UARequireMetadata(walk, entry);
    if (status != 0) {
        return status;
    }
    int opened __attribute__((cleanup(UACloseFD))) =
        openat(parent, name, S_ISDIR(entry->st_mode) ? DirectoryFlags : FileFlags);
    if (opened < 0) {
        return errno;
    }
    struct stat actual;
    if (fstat(opened, &actual) != 0) {
        return errno;
    }
    if (!UASameEntry(entry, &actual)) {
        return ESTALE;
    }
    status = UARequireDescriptor(opened, walk);
    if (status != 0) {
        return status;
    }
    *descriptor = opened;
    opened = -1;
    return 0;
}

static UAExpiryPath UARootPath(void) {
    static const char Domain[] = "UninstallAny.expiry-root.v1";
    UAExpiryPath path = {0};
    CC_SHA256(Domain, sizeof(Domain), path.bytes);
    return path;
}

static int UAChildPath(const UAExpiryPath *parent, NSData *name, UAExpiryPath *child) {
    // The stored name includes its terminating null, used as a path byte
    // budget for this component and its separator.
    if (name.length > PATH_MAX - parent->length) {
        return ENAMETOOLONG;
    }
    child->length = parent->length + name.length;
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    CC_SHA256_Update(&hash, parent->bytes, sizeof(parent->bytes));
    CC_SHA256_Update(&hash, name.bytes, (CC_LONG)name.length);
    CC_SHA256_Final(child->bytes, &hash);
    return 0;
}

static NSString *UAEntryFingerprint(const UAExpiryPath *path, const struct stat *entry) {
    static const char Domain[] = "UninstallAny.expiry-entry.v1";
    static const char Hex[] = "0123456789abcdef";
    // The persisted journal binds the APFS volume UUID. Live device numbers
    // can change on remount, so they are checked locally rather than hashed.
    const uint64_t identity[] = {
        CFSwapInt64HostToBig((uint64_t)entry->st_ino),
        CFSwapInt64HostToBig((uint64_t)entry->st_birthtimespec.tv_sec),
        CFSwapInt64HostToBig((uint64_t)entry->st_birthtimespec.tv_nsec),
        CFSwapInt64HostToBig((uint64_t)entry->st_uid),
        CFSwapInt64HostToBig((uint64_t)entry->st_gid),
        CFSwapInt64HostToBig((uint64_t)entry->st_mode),
        CFSwapInt64HostToBig((uint64_t)entry->st_flags),
    };
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    CC_SHA256_Update(&hash, Domain, sizeof(Domain));
    CC_SHA256_Update(&hash, path->bytes, sizeof(path->bytes));
    CC_SHA256_Update(&hash, identity, sizeof(identity));
    // Removing members changes a directory's times, length and link count.
    if (S_ISREG(entry->st_mode)) {
        const uint64_t contents[] = {
            CFSwapInt64HostToBig((uint64_t)entry->st_size),
            CFSwapInt64HostToBig((uint64_t)entry->st_nlink),
            CFSwapInt64HostToBig((uint64_t)entry->st_ctimespec.tv_sec),
            CFSwapInt64HostToBig((uint64_t)entry->st_ctimespec.tv_nsec),
            CFSwapInt64HostToBig((uint64_t)entry->st_mtimespec.tv_sec),
            CFSwapInt64HostToBig((uint64_t)entry->st_mtimespec.tv_nsec),
        };
        CC_SHA256_Update(&hash, contents, sizeof(contents));
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &hash);
    char encoded[FingerprintLength + 1] = {0};
    for (size_t index = 0; index < sizeof(digest); ++index) {
        encoded[index * 2] = Hex[digest[index] >> 4];
        encoded[index * 2 + 1] = Hex[digest[index] & 0x0f];
    }
    return [NSString stringWithUTF8String:encoded];
}

static int UAEntryNames(const UAExpiryDirectory *frame, UAExpiryWalk *walk,
                        NSMutableArray<NSData *> *names) {
    // Open a fresh description so enumeration never changes the held fd's
    // offset. Collect names before removing any child from the directory.
    int cursor __attribute__((cleanup(UACloseFD))) = openat(frame->descriptor, ".", DirectoryFlags);
    if (cursor < 0) {
        return errno;
    }
    DIR *directory __attribute__((cleanup(UACloseDirectory))) = fdopendir(cursor);
    if (directory == NULL) {
        return errno;
    }
    cursor = -1;
    NSMutableSet<NSData *> *seen = [NSMutableSet set];
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            return errno;
        }
        size_t length = entry->d_namlen;
        if (length == 0 || length > NAME_MAX || strnlen(entry->d_name, length + 1) != length
            || memchr(entry->d_name, '/', length) != NULL) {
            return EINVAL;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (walk->remainingNames == 0) {
            return E2BIG;
        }
        walk->remainingNames--;
        NSData *name = [NSData dataWithBytes:entry->d_name length:length + 1];
        if ([seen containsObject:name]) {
            return ESTALE;
        }
        [seen addObject:name];
        [names addObject:name];
    }
}

static int UARecheckDirectoryChain(const UAExpiryDirectory *frame, const UAExpiryWalk *walk) {
    for (const UAExpiryDirectory *current = frame; current != NULL; current = current->ancestor) {
        struct stat opened;
        if (fstat(current->descriptor, &opened) != 0) {
            return errno;
        }
        if (!UASameMetadata(&current->entry, &opened)) {
            return ESTALE;
        }
        int status = UARequireDescriptor(current->descriptor, walk);
        if (status != 0) {
            return status;
        }
        if (current->parent >= 0) {
            struct stat named;
            if (fstatat(current->parent, current->name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
                return errno;
            }
            if (!UASameMetadata(&current->entry, &named)) {
                return ESTALE;
            }
        }
    }
    return 0;
}

static int UAUnlinkMember(const UAExpiryDirectory *parent, const char *name,
                          const struct stat *expected, int descriptor, const UAExpiryWalk *walk) {
    if (!walk->mayContinue()) {
        return ECANCELED;
    }
    int status = UARecheckDirectoryChain(parent, walk);
    if (status != 0) {
        return status;
    }
    status = UARequireDescriptor(descriptor, walk);
    if (status != 0) {
        return status;
    }
    struct stat opened, named;
    if (fstat(descriptor, &opened) != 0
        || fstatat(parent->descriptor, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno;
    }
    bool directory = S_ISDIR(expected->st_mode);
    bool unchanged = directory ? UASameMetadata(expected, &opened) && UASameMetadata(expected, &named)
        : UASameEntry(expected, &opened) && UASameEntry(expected, &named);
    if (!unchanged) {
        return ESTALE;
    }
    // Only held, root-private parents may reach here. The kernel refuses to
    // unlink a directory with children that arrived after the snapshot.
    return unlinkat(parent->descriptor, name, directory ? AT_REMOVEDIR : 0) == 0 ? 0 : errno;
}

static int UAWalkDirectory(const UAExpiryDirectory *frame, const UAExpiryPath *path,
                           UAExpiryWalk *walk, unsigned int depth);

static int UAWalkMember(const UAExpiryDirectory *parent, NSData *name, const UAExpiryPath *parentPath,
                        UAExpiryWalk *walk, unsigned int depth) {
    UAExpiryPath path;
    int status = UAChildPath(parentPath, name, &path);
    if (status != 0) {
        return status;
    }
    struct stat entry;
    int descriptor __attribute__((cleanup(UACloseFD))) = -1;
    status = UAOpenMember(parent->descriptor, name.bytes, walk, &entry, &descriptor);
    if (status != 0) {
        return status;
    }
    if (S_ISDIR(entry.st_mode)) {
        UAExpiryDirectory frame = {
            .ancestor = parent,
            .name = name.bytes,
            .parent = parent->descriptor,
            .descriptor = descriptor,
            .entry = entry,
        };
        status = UAWalkDirectory(&frame, &path, walk, depth);
    } else {
        status = walk->visit(UAEntryFingerprint(&path, &entry));
    }
    if (status != 0) {
        return status;
    }
    return walk->mayContinue == nil ? 0 : UAUnlinkMember(parent, name.bytes, &entry, descriptor, walk);
}

static int UAWalkDirectory(const UAExpiryDirectory *frame, const UAExpiryPath *path,
                           UAExpiryWalk *walk, unsigned int depth) {
    if (depth >= MaximumExpiryDepth) {
        return ELOOP;
    }
    int status = walk->visit(UAEntryFingerprint(path, &frame->entry));
    if (status != 0) {
        return status;
    }
    NSMutableArray<NSData *> *names = [NSMutableArray array];
    status = UAEntryNames(frame, walk, names);
    struct stat after;
    if (status != 0 || fstat(frame->descriptor, &after) != 0) {
        return status != 0 ? status : errno;
    }
    if (!UASameEntry(&frame->entry, &after)) {
        return ESTALE;
    }
    for (NSData *name in names) {
        @autoreleasepool {
            status = UAWalkMember(frame, name, path, walk, depth + 1);
        }
        if (status != 0) {
            break;
        }
    }
    if (walk->mayContinue != nil) {
        // Flush partial results too. Recovery compares the surviving entries
        // against the previously committed tree plan before it may continue.
        int synced = fsync(frame->descriptor);
        return status == 0 && synced != 0 ? errno : status;
    }
    if (status != 0) {
        return status;
    }
    if (fstat(frame->descriptor, &after) != 0) {
        return errno;
    }
    return UASameEntry(&frame->entry, &after) ? 0 : ESTALE;
}

static NSArray<NSDictionary *> *UAOrderedRows(NSMutableArray<NSString *> *members) {
    NSString *root = members.firstObject;
    if (root == nil) {
        return nil;
    }
    [members removeObjectAtIndex:0];
    [members sortUsingSelector:@selector(compare:)];
    NSMutableArray<NSDictionary *> *rows = [NSMutableArray arrayWithObject:@{@"fingerprint": root}];
    NSString *previous = nil;
    for (NSString *member in members) {
        if ([member isEqual:root] || [member isEqual:previous]) {
            return nil;
        }
        [rows addObject:@{@"fingerprint": member}];
        previous = member;
    }
    return rows;
}

static bool UAValidFingerprint(id value) {
    if (![value isKindOfClass:NSString.class] || [value length] != FingerprintLength) {
        return false;
    }
    NSData *encoded = [value dataUsingEncoding:NSASCIIStringEncoding];
    if (encoded.length != FingerprintLength) {
        return false;
    }
    const unsigned char *bytes = encoded.bytes;
    for (size_t index = 0; index < encoded.length; ++index) {
        unsigned char byte = bytes[index];
        if ((byte < '0' || byte > '9') && (byte < 'a' || byte > 'f')) {
            return false;
        }
    }
    return true;
}

static NSSet<NSString *> *UAApprovedFingerprints(NSArray<NSDictionary *> *rows) {
    if (![rows isKindOfClass:NSArray.class] || rows.count == 0 || rows.count > MaximumExpiryEntries) {
        return nil;
    }
    NSMutableSet<NSString *> *stamps = [NSMutableSet setWithCapacity:rows.count];
    NSString *previous = nil;
    for (NSDictionary *row in rows) {
        if (![row isKindOfClass:NSDictionary.class] || row.count != 1) {
            return nil;
        }
        NSString *stamp = row[@"fingerprint"];
        if (!UAValidFingerprint(stamp) || [stamps containsObject:stamp]
            || (previous != nil && [previous compare:stamp] != NSOrderedAscending)) {
            return nil;
        }
        if (stamps.count != 0) {
            previous = stamp;
        }
        [stamps addObject:stamp];
    }
    return stamps;
}

static int UACaptureBoundTree(int descriptor, NSArray<NSDictionary *> *approved,
                              NSArray<NSDictionary *> **entries) {
    *entries = nil;
    UAExpiryWalk walk = {0};
    int status = UAPrepareWalk(descriptor, &walk);
    if (status != 0) {
        return status;
    }
    UAExpiryDirectory root = {.parent = -1, .descriptor = descriptor};
    if (fstat(descriptor, &root.entry) != 0) {
        return errno;
    }
    status = UARequireMetadata(&walk, &root.entry);
    if (status == 0) {
        status = UARequireDescriptor(descriptor, &walk);
    }
    if (status != 0) {
        return status;
    }
    UAExpiryPath rootPath = UARootPath();
    NSSet<NSString *> *allowed = nil;
    if (approved != nil) {
        allowed = UAApprovedFingerprints(approved);
        if (allowed == nil) {
            return EINVAL;
        }
        if (![approved[0][@"fingerprint"] isEqual:UAEntryFingerprint(&rootPath, &root.entry)]) {
            return ESTALE;
        }
        walk.remainingNames = approved.count - 1;
    }
    NSMutableArray<NSString *> *members = [NSMutableArray array];
    UAExpiryVisitor accept __attribute__((objc_precise_lifetime)) = ^int(NSString *stamp) {
        if (stamp == nil) {
            return EIO;
        }
        if (allowed != nil && ![allowed containsObject:stamp]) {
            return ESTALE;
        }
        [members addObject:stamp];
        return 0;
    };
    walk.visit = accept;
    status = UAWalkDirectory(&root, &rootPath, &walk, 0);
    if (status != 0) {
        return status;
    }
    *entries = UAOrderedRows(members);
    return *entries != nil ? 0 : ESTALE;
}

int UACaptureExpiryTree(int bundleDescriptor, NSArray<NSDictionary *> **entries) {
    return UACaptureBoundTree(bundleDescriptor, nil, entries);
}

int UACheckRemainingExpiryTree(int bundleDescriptor, NSArray<NSDictionary *> *approved,
                               NSArray<NSDictionary *> **remaining) {
    if (approved == nil) {
        *remaining = nil;
        return EINVAL;
    }
    return UACaptureBoundTree(bundleDescriptor, approved, remaining);
}

int UARemovePendingExpiryTree(int slotDescriptor, const char *pendingName,
                             NSArray<NSDictionary *> *reviewedRemaining,
                             BOOL (^mayContinue)(void)) {
    if (pendingName == NULL || strcmp(pendingName, PendingName) != 0 || mayContinue == nil) {
        return EINVAL;
    }
    if (!mayContinue()) {
        return ECANCELED;
    }
    UAExpiryWalk walk = {0};
    int status = UAPrepareWalk(slotDescriptor, &walk);
    if (status != 0) {
        return status;
    }
    UAExpiryDirectory slot = {.parent = -1, .descriptor = slotDescriptor};
    if (fstat(slotDescriptor, &slot.entry) != 0) {
        return errno;
    }
    if (slot.entry.st_uid != 0 || (slot.entry.st_mode & 07777) != 0700
        || (slot.entry.st_flags & ProtectedFlags) != 0) {
        return EPERM;
    }
    status = UARequireDescriptor(slotDescriptor, &walk);
    if (status != 0) {
        return status;
    }
    int descriptor __attribute__((cleanup(UACloseFD))) = -1;
    struct stat entry;
    status = UAOpenMember(slotDescriptor, pendingName, &walk, &entry, &descriptor);
    if (status != 0) {
        return status;
    }
    if (!S_ISDIR(entry.st_mode)) {
        return ENOTDIR;
    }
    NSArray<NSDictionary *> *current = nil;
    status = UACheckRemainingExpiryTree(descriptor, reviewedRemaining, &current);
    if (status != 0 || ![current isEqualToArray:reviewedRemaining]) {
        return status != 0 ? status : ESTALE;
    }
    NSSet<NSString *> *allowed = UAApprovedFingerprints(current);
    UAExpiryVisitor accept __attribute__((objc_precise_lifetime)) = ^int(NSString *stamp) {
        return stamp != nil && [allowed containsObject:stamp] ? 0 : ESTALE;
    };
    walk.visit = accept;
    walk.mayContinue = mayContinue;
    walk.remainingNames = current.count - 1;
    UAExpiryDirectory root = {
        .ancestor = &slot,
        .name = pendingName,
        .parent = slotDescriptor,
        .descriptor = descriptor,
        .entry = entry,
    };
    UAExpiryPath path = UARootPath();
    status = UAWalkDirectory(&root, &path, &walk, 0);
    if (status == 0) {
        status = UAUnlinkMember(&slot, pendingName, &entry, descriptor, &walk);
    }
    if (status != 0) {
        return status;
    }
    return fsync(slotDescriptor) == 0 ? 0 : errno;
}
