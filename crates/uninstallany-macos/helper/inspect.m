#import "isolated_bundle.h"
#import "protocol.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CFByteOrder.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static const int64_t MaximumInfoBytes = 2 * 1024 * 1024;
static const int DirectoryFlags = O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW;
static const mode_t OtherWriteBits = S_IWGRP | S_IWOTH;
static const uint32_t ProtectedFlags =
    UF_IMMUTABLE | UF_APPEND | SF_IMMUTABLE | SF_APPEND | SF_NOUNLINK | SF_RESTRICTED;

static void UACloseDescriptor(int *descriptor) {
    if (*descriptor >= 0) {
        close(*descriptor);
    }
}

static bool UAPlainOwnershipACL(int descriptor) {
    acl_t acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
    if (acl == NULL) {
        return errno == ENOENT;
    }
    acl_entry_t first;
    errno = 0;
    int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &first);
    int failure = errno;
    acl_free(acl);
    return result == -1 && (failure == EINVAL || failure == ENOENT);
}

static bool UARootDirectory(int descriptor, bool applicationParent, struct stat *snapshot) {
    if (fstat(descriptor, snapshot) != 0 || !S_ISDIR(snapshot->st_mode)
        || snapshot->st_uid != 0 || !UAPlainOwnershipACL(descriptor)) {
        return false;
    }
    mode_t mode = snapshot->st_mode;
    return (mode & OtherWriteBits) == 0
        || (applicationParent && (mode & (S_ISVTX | S_IWOTH)) == S_ISVTX);
}

static bool UALocalOwnedVolume(int descriptor) {
    struct statfs volume;
    return fstatfs(descriptor, &volume) == 0
        && strcmp(volume.f_fstypename, "apfs") == 0
        && (volume.f_flags & MNT_LOCAL) != 0
        && (volume.f_flags & (MNT_IGNORE_OWNERSHIP | MNT_RDONLY)) == 0;
}

static bool UASameTime(struct timespec first, struct timespec second) {
    return first.tv_sec == second.tv_sec && first.tv_nsec == second.tv_nsec;
}

static bool UAUnchangedAt(int parent, const char *name, const struct stat *expected) {
    struct stat actual;
    return fstatat(parent, name, &actual, AT_SYMLINK_NOFOLLOW) == 0
        && actual.st_dev == expected->st_dev && actual.st_ino == expected->st_ino
        && actual.st_mode == expected->st_mode && actual.st_uid == expected->st_uid
        && actual.st_gid == expected->st_gid && actual.st_size == expected->st_size
        && actual.st_nlink == expected->st_nlink && actual.st_flags == expected->st_flags
        && UASameTime(actual.st_birthtimespec, expected->st_birthtimespec)
        && UASameTime(actual.st_ctimespec, expected->st_ctimespec)
        && UASameTime(actual.st_mtimespec, expected->st_mtimespec);
}

static void UAHashFields(CC_SHA256_CTX *hash, const uint64_t *fields, size_t count) {
    for (size_t index = 0; index < count; index++) {
        uint64_t encoded = CFSwapInt64HostToBig(fields[index]);
        CC_SHA256_Update(hash, &encoded, sizeof(encoded));
    }
}

static void UAHashEntry(CC_SHA256_CTX *hash, const struct stat *entry, bool includeContents) {
    // Encode fields directly so compiler padding and native byte order cannot
    // change the stamp. Parent contents are unrelated to the inspected app.
    const uint64_t identity[] = {
        (uint64_t)entry->st_dev, (uint64_t)entry->st_ino, (uint64_t)entry->st_mode,
        (uint64_t)entry->st_uid, (uint64_t)entry->st_gid, (uint64_t)entry->st_flags,
        (uint64_t)entry->st_birthtimespec.tv_sec, (uint64_t)entry->st_birthtimespec.tv_nsec,
    };
    UAHashFields(hash, identity, sizeof(identity) / sizeof(identity[0]));
    if (includeContents) {
        const uint64_t contents[] = {
            (uint64_t)entry->st_size, (uint64_t)entry->st_nlink,
            (uint64_t)entry->st_ctimespec.tv_sec, (uint64_t)entry->st_ctimespec.tv_nsec,
            (uint64_t)entry->st_mtimespec.tv_sec, (uint64_t)entry->st_mtimespec.tv_nsec,
        };
        UAHashFields(hash, contents, sizeof(contents) / sizeof(contents[0]));
    }
}

static NSString *UARootStamp(const struct stat *applications, const struct stat *bundle,
                             const struct stat *contents, const struct stat *manifest,
                             NSData *name, NSData *plist) {
    static const char Domain[] = "UninstallAny.bundle-root.v2";
    static const char Hex[] = "0123456789abcdef";
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    CC_SHA256_Update(&hash, Domain, sizeof(Domain));
    uint64_t nameLength = (uint64_t)name.length;
    UAHashFields(&hash, &nameLength, 1);
    CC_SHA256_Update(&hash, name.bytes, (CC_LONG)name.length);
    UAHashEntry(&hash, applications, false);
    UAHashEntry(&hash, bundle, true);
    UAHashEntry(&hash, contents, true);
    UAHashEntry(&hash, manifest, true);
    uint64_t plistLength = (uint64_t)plist.length;
    UAHashFields(&hash, &plistLength, 1);
    // The descriptor read already limited this buffer to MaximumInfoBytes.
    CC_SHA256_Update(&hash, plist.bytes, (CC_LONG)plist.length);
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &hash);
    char encoded[sizeof(digest) * 2 + 1];
    for (size_t index = 0; index < sizeof(digest); index++) {
        encoded[index * 2] = Hex[digest[index] >> 4];
        encoded[index * 2 + 1] = Hex[digest[index] & 0x0f];
    }
    encoded[sizeof(encoded) - 1] = '\0';
    return [NSString stringWithUTF8String:encoded];
}

static bool UAValidBundleIdentifier(NSString *identifier) {
    NSData *bytes = [identifier dataUsingEncoding:NSASCIIStringEncoding];
    if (bytes.length < 3 || bytes.length > 255) {
        return false;
    }
    NSString *lower = identifier.lowercaseString;
    if ([lower isEqualToString:@"com.apple"] || [lower hasPrefix:@"com.apple."]
        || [lower isEqualToString:UA_GUI_SIGNING_ID]) {
        return false;
    }
    const uint8_t *characters = bytes.bytes;
    bool componentHasContent = false;
    bool dotted = false;
    for (NSUInteger index = 0; index < bytes.length; index++) {
        uint8_t character = characters[index];
        if (character == '.') {
            if (!componentHasContent) {
                return false;
            }
            dotted = true;
            componentHasContent = false;
        } else if ((character >= 'a' && character <= 'z')
                   || (character >= 'A' && character <= 'Z')
                   || (character >= '0' && character <= '9') || character == '-' || character == '_') {
            componentHasContent = true;
        } else {
            return false;
        }
    }
    return dotted && componentHasContent;
}

static NSString *UAResult(NSString *status) {
    // Only the constant status codes in this file reach the response.
    return [NSString stringWithFormat:@"{\"status\":\"%@\"}", status];
}

static NSData *UAReadInfoPlist(int descriptor, off_t length) {
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)length];
    uint8_t *bytes = data.mutableBytes;
    for (size_t offset = 0; offset < data.length;) {
        ssize_t count = pread(descriptor, bytes + offset, data.length - offset, (off_t)offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return nil;
        }
        offset += (size_t)count;
    }
    return data;
}

static bool UAIsStartupDataVolume(int root, const struct stat *applications) {
    // The Installer query is scoped to the startup volume. Verify it is
    // also the volume holding the reviewed Applications directory.
    int system __attribute__((cleanup(UACloseDescriptor))) = openat(root, "System", DirectoryFlags);
    struct stat systemEntry;
    if (system < 0 || !UARootDirectory(system, false, &systemEntry)) {
        return false;
    }
    int volumes __attribute__((cleanup(UACloseDescriptor))) =
        openat(system, "Volumes", DirectoryFlags);
    struct stat volumesEntry;
    if (volumes < 0 || !UARootDirectory(volumes, false, &volumesEntry)) {
        return false;
    }
    int data __attribute__((cleanup(UACloseDescriptor))) = openat(volumes, "Data", DirectoryFlags);
    struct stat dataEntry;
    return data >= 0 && UARootDirectory(data, false, &dataEntry) && UALocalOwnedVolume(data)
        && dataEntry.st_dev == applications->st_dev;
}

static NSString *UAReceiptExecutable(id candidate, int contents, dev_t device) {
    if (![candidate isKindOfClass:NSString.class]) {
        return nil;
    }
    NSString *name = candidate;
    const char *filename = name.fileSystemRepresentation;
    if (filename == NULL || name.length == 0 || strlen(filename) > NAME_MAX
        || strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0
        || strchr(filename, '/') != NULL || strchr(filename, '\\') != NULL
        || [name rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location != NSNotFound) {
        return nil;
    }
    int macOS __attribute__((cleanup(UACloseDescriptor))) = openat(contents, "MacOS", DirectoryFlags);
    struct stat macOSEntry;
    if (macOS < 0 || !UARootDirectory(macOS, false, &macOSEntry)
        || macOSEntry.st_dev != device || (macOSEntry.st_flags & ProtectedFlags) != 0) {
        return nil;
    }
    struct stat namedExecutable;
    if (fstatat(macOS, filename, &namedExecutable, AT_SYMLINK_NOFOLLOW) != 0
        || !S_ISREG(namedExecutable.st_mode)) {
        return nil;
    }
    int executable __attribute__((cleanup(UACloseDescriptor))) =
        openat(macOS, filename, O_EVTONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat executableEntry;
    if (executable < 0 || fstat(executable, &executableEntry) != 0 || !S_ISREG(executableEntry.st_mode)
        || executableEntry.st_uid != 0 || executableEntry.st_dev != device
        || executableEntry.st_nlink != 1 || (executableEntry.st_mode & OtherWriteBits) != 0
        || (executableEntry.st_flags & ProtectedFlags) != 0 || !UAPlainOwnershipACL(executable)
        || !UAUnchangedAt(contents, "MacOS", &macOSEntry)
        || !UAUnchangedAt(macOS, filename, &executableEntry)) {
        return nil;
    }
    return name;
}

static NSString *UAInspectBundleRoot(NSString *basename, NSString *bundleIdentifier,
                                     NSString *expectedStamp, UAReviewedBundle *reviewed,
                                     NSString **receiptExecutable) {
    NSData *nameBytes = [basename dataUsingEncoding:NSUTF8StringEncoding];
    if (nameBytes.length < 5 || nameBytes.length > NAME_MAX
        || memchr(nameBytes.bytes, '\0', nameBytes.length) != NULL
        || [basename.pathExtension caseInsensitiveCompare:@"app"] != NSOrderedSame
        || !UAValidBundleIdentifier(bundleIdentifier)) {
        return UAResult(@"invalid_target");
    }
    const char *name = basename.fileSystemRepresentation;
    if (name == NULL || name[0] == '.' || strchr(name, '/') != NULL || strlen(name) > NAME_MAX) {
        return UAResult(@"invalid_target");
    }

    int root __attribute__((cleanup(UACloseDescriptor))) = open("/", DirectoryFlags);
    struct stat rootEntry;
    if (root < 0 || !UARootDirectory(root, false, &rootEntry)) {
        return UAResult(@"untrusted_applications_directory");
    }
    int applications __attribute__((cleanup(UACloseDescriptor))) =
        openat(root, "Applications", DirectoryFlags);
    struct stat applicationsEntry;
    if (applications < 0 || !UARootDirectory(applications, true, &applicationsEntry)
        || !UALocalOwnedVolume(applications)) {
        return UAResult(@"untrusted_applications_directory");
    }
    int app __attribute__((cleanup(UACloseDescriptor))) = openat(applications, name, DirectoryFlags);
    if (app < 0) {
        return UAResult(errno == ENOENT ? @"target_missing" : @"target_not_private_root_bundle");
    }
    int contents __attribute__((cleanup(UACloseDescriptor))) =
        openat(app, "Contents", DirectoryFlags);
    struct stat appEntry;
    struct stat contentsEntry;
    if (contents < 0 || !UARootDirectory(app, false, &appEntry)
        || !UARootDirectory(contents, false, &contentsEntry)
        || appEntry.st_dev != applicationsEntry.st_dev || contentsEntry.st_dev != appEntry.st_dev
        || (appEntry.st_flags & ProtectedFlags) != 0
        || (contentsEntry.st_flags & ProtectedFlags) != 0) {
        return UAResult(@"target_not_private_root_bundle");
    }
    int manifest __attribute__((cleanup(UACloseDescriptor))) =
        openat(contents, "Info.plist", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat manifestEntry;
    if (manifest < 0 || fstat(manifest, &manifestEntry) != 0 || !S_ISREG(manifestEntry.st_mode)
        || manifestEntry.st_uid != 0 || manifestEntry.st_dev != appEntry.st_dev
        || manifestEntry.st_nlink != 1 || (manifestEntry.st_mode & OtherWriteBits) != 0
        || (manifestEntry.st_flags & ProtectedFlags) != 0
        || manifestEntry.st_size <= 0 || manifestEntry.st_size > MaximumInfoBytes
        || !UAPlainOwnershipACL(manifest)) {
        return UAResult(@"target_not_private_root_bundle");
    }
    NSData *plist = UAReadInfoPlist(manifest, manifestEntry.st_size);
    if (plist == nil) {
        return UAResult(@"entry_changed");
    }
    id decoded = [NSPropertyListSerialization propertyListWithData:plist
                                                           options:NSPropertyListImmutable
                                                            format:NULL
                                                             error:NULL];
    id bundleID = [decoded isKindOfClass:NSDictionary.class] ? decoded[@"CFBundleIdentifier"] : nil;
    if (![bundleID isKindOfClass:NSString.class] || ![bundleID isEqualToString:bundleIdentifier]) {
        return UAResult(@"bundle_identifier_mismatch");
    }
    if (!UAUnchangedAt(root, "Applications", &applicationsEntry)
        || !UAUnchangedAt(applications, name, &appEntry)
        || !UAUnchangedAt(app, "Contents", &contentsEntry)
        || !UAUnchangedAt(contents, "Info.plist", &manifestEntry)) {
        return UAResult(@"entry_changed");
    }
    NSString *rootStamp =
        UARootStamp(&applicationsEntry, &appEntry, &contentsEntry, &manifestEntry, nameBytes, plist);
    if (reviewed != NULL) {
        if (rootStamp == nil || ![rootStamp isEqualToString:expectedStamp]) {
            return UAResult(@"entry_changed");
        }
        if (receiptExecutable != NULL && UAIsStartupDataVolume(root, &applicationsEntry)) {
            *receiptExecutable = UAReceiptExecutable(decoded[@"CFBundleExecutable"], contents, appEntry.st_dev);
        }
        // Transfer the descriptors that produced the stamp. Reopening from
        // an unchecked path would lose the identity proved above.
        reviewed->applications = applications;
        reviewed->bundle = app;
        applications = -1;
        app = -1;
        return nil;
    }
    return [NSString stringWithFormat:
        @"{\"status\":\"verified\",\"device\":%llu,\"inode\":%llu,"
         @"\"birth_seconds\":%lld,\"birth_nanoseconds\":%lld,\"root_stamp\":\"%@\"}",
        (unsigned long long)appEntry.st_dev, (unsigned long long)appEntry.st_ino,
        (long long)appEntry.st_birthtimespec.tv_sec, (long long)appEntry.st_birthtimespec.tv_nsec,
        rootStamp];
}

NSString *UAInspectApplicationBundle(NSString *basename, NSString *bundleIdentifier) {
    return UAInspectBundleRoot(basename, bundleIdentifier, nil, NULL, NULL);
}

int UAOpenReviewedApplicationBundle(NSString *basename, NSString *bundleIdentifier,
                                    NSString *rootStamp, UAReviewedBundle *reviewed,
                                    NSString **receiptExecutable) {
    *reviewed = (UAReviewedBundle){.applications = -1, .bundle = -1};
    if (receiptExecutable != NULL) {
        *receiptExecutable = nil;
    }
    UAInspectBundleRoot(basename, bundleIdentifier, rootStamp, reviewed, receiptExecutable);
    if (reviewed->bundle < 0) {
        return ESTALE;
    }
    if (receiptExecutable != NULL && *receiptExecutable == nil) {
        UACloseReviewedApplicationBundle(reviewed);
        return ENOTSUP;
    }
    return 0;
}

void UACloseReviewedApplicationBundle(UAReviewedBundle *reviewed) {
    UACloseDescriptor(&reviewed->bundle);
    UACloseDescriptor(&reviewed->applications);
    *reviewed = (UAReviewedBundle){.applications = -1, .bundle = -1};
}
