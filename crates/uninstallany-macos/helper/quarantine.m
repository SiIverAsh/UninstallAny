#import "bundle_exclusion.h"
#import "expiry_tree.h"
#import "isolated_bundle.h"
#import "protocol.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CFByteOrder.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

static const int DirectoryFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
static const int FileFlags = O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
static const mode_t GroupOrOtherWrite = S_IWGRP | S_IWOTH;
static const uint32_t ProtectedFlags =
    UF_IMMUTABLE | UF_APPEND | SF_IMMUTABLE | SF_APPEND | SF_NOUNLINK | SF_RESTRICTED;
static const off_t MaximumRecordBytes = 4096;
static const off_t MaximumExpiryPlanBytes = 16 * 1024 * 1024;
static const NSUInteger MaximumCatalogEntries = 4096;
static const uint64_t MillisecondsPerSecond = 1000;
static const uint64_t MillisecondsPerDay = UINT64_C(24) * 60 * 60 * 1000;
static const uint64_t MaximumExactUnixMilliseconds = (UINT64_C(1) << 53) - 1;
static const char RecordName[] = "record.json";
static const char PendingRecordName[] = "record.pending";
static const char PayloadName[] = "payload.app";
static const char QuarantinedMarker[] = "quarantined";
static const char RestoreIntentMarker[] = "restore.intent";
static const char RestoredMarker[] = "restored";
static const char ExpiryPendingName[] = "expiry.pending";
static const char ExpiryPlanName[] = "expiry.plan.json";
static const char ExpiryPlanTemporary[] = "expiry.plan.tmp";
static const char ExpiryCommitName[] = "expiry.committed";
static const char ExpiryCommitTemporary[] = "expiry.commit.tmp";
static const char PurgedMarker[] = "purged";

static void UACloseDescriptor(int *descriptor) {
    if (*descriptor >= 0) {
        int failure = errno;
        close(*descriptor);
        errno = failure;
    }
}

static void UACloseCatalogDirectory(DIR **directory) {
    if (*directory != NULL) {
        closedir(*directory);
    }
}

static bool UAHasNoACL(int descriptor) {
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

static bool UAPlainRootDirectory(int fd, struct stat *entry, bool allowStickyGroup) {
    if (fstat(fd, entry) != 0 || !S_ISDIR(entry->st_mode)
        || entry->st_uid != 0 || !UAHasNoACL(fd)) {
        return false;
    }
    return (entry->st_mode & GroupOrOtherWrite) == 0
        || (allowStickyGroup && (entry->st_mode & (S_ISVTX | S_IWOTH)) == S_ISVTX);
}

static bool UAPrivateFile(int fd, struct stat *entry, dev_t device) {
    return fstat(fd, entry) == 0 && S_ISREG(entry->st_mode) && entry->st_uid == 0
        && entry->st_dev == device && entry->st_nlink == 1
        && (entry->st_mode & 07777) == 0600 && UAHasNoACL(fd);
}

static NSString *UAVolumeIdentifier(int descriptor) {
    struct statfs mount;
    if (fstatfs(descriptor, &mount) != 0 || strcmp(mount.f_fstypename, "apfs") != 0
        || (mount.f_flags & MNT_LOCAL) == 0
        || (mount.f_flags & (MNT_IGNORE_OWNERSHIP | MNT_RDONLY)) != 0) {
        return nil;
    }
    struct attrlist requested = {
        .bitmapcount = ATTR_BIT_MAP_COUNT,
        .volattr = ATTR_VOL_INFO | ATTR_VOL_UUID,
    };
    struct {
        uint32_t length;
        uuid_t identifier;
    } attributes = {0};
    if (fgetattrlist(descriptor, &requested, &attributes, sizeof(attributes), 0) != 0
        || attributes.length != sizeof(attributes) || uuid_is_null(attributes.identifier)) {
        return nil;
    }
    // The mounted device number can change across restarts. Use the APFS
    // volume identity in the journal and compare live device numbers as well.
    char encoded[37];
    uuid_unparse_lower(attributes.identifier, encoded);
    return [NSString stringWithUTF8String:encoded];
}

static bool UASameTime(struct timespec first, struct timespec second) {
    return first.tv_sec == second.tv_sec && first.tv_nsec == second.tv_nsec;
}

static bool UASameEntry(const struct stat *first, const struct stat *second) {
    return first->st_dev == second->st_dev && first->st_ino == second->st_ino
        && UASameTime(first->st_birthtimespec, second->st_birthtimespec);
}

static bool UAUnchangedBundle(const struct stat *first, const struct stat *second) {
    return UASameEntry(first, second)
        && first->st_mode == second->st_mode && first->st_uid == second->st_uid
        && first->st_gid == second->st_gid && first->st_flags == second->st_flags
        && first->st_nlink == second->st_nlink && first->st_size == second->st_size
        && UASameTime(first->st_ctimespec, second->st_ctimespec)
        && UASameTime(first->st_mtimespec, second->st_mtimespec);
}

static NSDictionary *UAEntryRecord(const struct stat *entry) {
    // Decimal text preserves the full file ID without JSON number rounding.
    return @{
        @"inode": [@(entry->st_ino) stringValue],
        @"birth_seconds": [@(entry->st_birthtimespec.tv_sec) stringValue],
        @"birth_nanoseconds": [@(entry->st_birthtimespec.tv_nsec) stringValue],
    };
}

static bool UAIsCanonicalUUID(NSString *value) {
    if (![value isKindOfClass:NSString.class] || value.length != 36) {
        return false;
    }
    NSUUID *parsed = [[NSUUID alloc] initWithUUIDString:value];
    return [value isEqualToString:parsed.UUIDString.lowercaseString];
}

static const char *UAApplicationName(NSString *basename) {
    if (![basename isKindOfClass:NSString.class] || basename.length <= 4
        || basename.length > NAME_MAX
        || [basename.pathExtension caseInsensitiveCompare:@"app"] != NSOrderedSame) {
        return NULL;
    }
    NSData *bytes = [basename dataUsingEncoding:NSUTF8StringEncoding];
    if (bytes.length == 0 || memchr(bytes.bytes, '\0', bytes.length) != NULL) {
        return NULL;
    }
    const char *name = basename.fileSystemRepresentation;
    if (name == NULL || name[0] == '.' || strlen(name) > NAME_MAX) {
        return NULL;
    }
    for (const unsigned char *character = (const unsigned char *)name;
         *character != '\0'; character++) {
        if (*character < 0x20 || *character == 0x7f
            || *character == '/' || *character == '\\') {
            return NULL;
        }
    }
    return name;
}

static bool UAValidStamp(NSString *stamp) {
    if (![stamp isKindOfClass:NSString.class] || stamp.length != UA_ROOT_STAMP_LENGTH) {
        return false;
    }
    NSData *bytes = [stamp dataUsingEncoding:NSASCIIStringEncoding];
    if (bytes.length != UA_ROOT_STAMP_LENGTH) {
        return false;
    }
    const uint8_t *hex = bytes.bytes;
    for (NSUInteger index = 0; index < bytes.length; index++) {
        uint8_t character = hex[index];
        if ((character < '0' || character > '9') && (character < 'a' || character > 'f')) {
            return false;
        }
    }
    return true;
}

static bool UAValidDescription(NSString *identifier, NSString *stamp) {
    if (![identifier isKindOfClass:NSString.class] || identifier.length == 0
        || identifier.length > 255 || !UAValidStamp(stamp)) {
        return false;
    }
    NSString *lower = identifier.lowercaseString;
    return ![lower isEqualToString:@"com.apple"] && ![lower hasPrefix:@"com.apple."]
        && ![lower isEqualToString:UA_GUI_SIGNING_ID];
}

static NSDictionary *UAResult(NSString *status, NSString *operationID, int failure) {
    return @{
        @"status": status,
        @"operation_id": operationID ?: @"",
        @"errno": @(failure),
    };
}

static NSDictionary *UARecordedResult(NSString *status, NSDictionary *record,
                                      int failure, bool destinationOccupied) {
    NSMutableDictionary *result = [UAResult(status, record[@"operation_id"], failure) mutableCopy];
    NSString *slot = [NSString stringWithFormat:@"/private/var/db/%@/%@/%@",
                      UA_HELPER_SIGNING_ID, record[@"uid"], record[@"operation_id"]];
    NSNumber *prepared = record[@"prepared_at_unix_ms"];
    NSNumber *preparedSeconds = prepared == nil ? record[@"prepared_at_epoch_seconds"]
        : @((double)prepared.unsignedLongLongValue / MillisecondsPerSecond);
    NSMutableDictionary *details = [@{
        @"original_path": [@"/Applications" stringByAppendingPathComponent:record[@"basename"]],
        @"backup_path": [slot stringByAppendingPathComponent:[NSString stringWithUTF8String:PayloadName]],
        @"bundle_id": record[@"bundle_id"],
        @"root_stamp": record[@"root_stamp"],
        @"prepared_at_epoch_seconds": preparedSeconds,
        @"destination_occupied": @(destinationOccupied),
    } mutableCopy];
    if (record[@"retention_days"] != nil) {
        details[@"retention_days"] = record[@"retention_days"];
        details[@"expires_at_unix_ms"] = record[@"expires_at_unix_ms"];
    }
    result[@"record"] = details;
    return result;
}

static NSDictionary *UAResultWithCompletion(NSDictionary *result, NSString *field,
                                             const struct timespec *completed) {
    if (completed == NULL) {
        return result;
    }
    NSMutableDictionary *details = [result[@"record"] mutableCopy];
    details[field] = @((double)completed->tv_sec + (double)completed->tv_nsec / 1e9);
    NSMutableDictionary *dated = [result mutableCopy];
    dated[@"record"] = details;
    return dated;
}

static int UAOpenApplications(struct stat *entry) {
    int root __attribute__((cleanup(UACloseDescriptor))) = open("/", DirectoryFlags);
    struct stat rootEntry;
    if (root < 0 || !UAPlainRootDirectory(root, &rootEntry, false)) {
        errno = EPERM;
        return -1;
    }
    int applications = openat(root, "Applications", DirectoryFlags);
    if (applications >= 0 && !UAPlainRootDirectory(applications, entry, true)) {
        close(applications);
        errno = EPERM;
        return -1;
    }
    return applications;
}

static bool UAApplicationsStillMatch(int reviewedFD, const struct stat *expected) {
    struct stat current;
    int applications __attribute__((cleanup(UACloseDescriptor))) = UAOpenApplications(&current);
    struct stat reviewed;
    return applications >= 0 && UASameEntry(expected, &current)
        && UAPlainRootDirectory(reviewedFD, &reviewed, true)
        && UASameEntry(expected, &reviewed);
}

static int UAOpenStoreComponent(int parent, const char *name, bool create,
                                bool private, bool exclusive, dev_t device) {
    if (create && mkdirat(parent, name, 0700) != 0 && (exclusive || errno != EEXIST)) {
        return -1;
    }
    int next = openat(parent, name, DirectoryFlags);
    if (next < 0) {
        return -1;
    }
    struct stat entry;
    if (!UAPlainRootDirectory(next, &entry, false)
        || (private && ((entry.st_mode & 07777) != 0700 || entry.st_dev != device
                       || (entry.st_flags & ProtectedFlags) != 0))) {
        close(next);
        errno = EPERM;
        return -1;
    }
    if (create && fsync(parent) != 0) {
        UACloseDescriptor(&next);
        return -1;
    }
    return next;
}

static int UAOpenUserStore(uid_t uid, const dev_t *requiredDevice, struct stat *userEntry) {
    int current __attribute__((cleanup(UACloseDescriptor))) = open("/", DirectoryFlags);
    struct stat rootEntry;
    if (current < 0 || !UAPlainRootDirectory(current, &rootEntry, false)) {
        errno = EPERM;
        return -1;
    }
    const char *ancestors[] = {"private", "var", "db"};
    for (size_t index = 0; index < sizeof(ancestors) / sizeof(ancestors[0]); index++) {
        int next = UAOpenStoreComponent(current, ancestors[index], false, false, false, 0);
        if (next < 0) {
            return -1;
        }
        UACloseDescriptor(&current);
        current = next;
    }
    struct stat databaseEntry;
    if (UAVolumeIdentifier(current) == nil || fstat(current, &databaseEntry) != 0) {
        errno = ENOTSUP;
        return -1;
    }
    if (requiredDevice != NULL && databaseEntry.st_dev != *requiredDevice) {
        errno = EXDEV;
        return -1;
    }
    NSString *uidString __attribute__((objc_precise_lifetime)) = [@(uid) stringValue];
    const char *components[] = {
        UA_HELPER_SIGNING_ID.fileSystemRepresentation,
        uidString.fileSystemRepresentation,
    };
    for (size_t index = 0; index < sizeof(components) / sizeof(components[0]); index++) {
        int next = UAOpenStoreComponent(current, components[index], requiredDevice != NULL,
                                        true, false, databaseEntry.st_dev);
        if (next < 0) {
            return -1;
        }
        UACloseDescriptor(&current);
        current = next;
    }
    if (fstat(current, userEntry) != 0) {
        return -1;
    }
    int user = current;
    current = -1;
    return user;
}

static int UAOpenUserSlot(int user, NSString *operationID, bool create, dev_t device,
                          struct stat *slotEntry) {
    int slot = UAOpenStoreComponent(user, operationID.fileSystemRepresentation, create,
                                    true, true, device);
    if (slot >= 0 && fstat(slot, slotEntry) != 0) {
        UACloseDescriptor(&slot);
        return -1;
    }
    return slot;
}

static int UAOpenSlot(uid_t uid, NSString *operationID, const dev_t *requiredDevice,
                      struct stat *slotEntry) {
    struct stat userEntry;
    int user __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenUserStore(uid, requiredDevice, &userEntry);
    if (user < 0) {
        return -1;
    }
    return UAOpenUserSlot(user, operationID, requiredDevice != NULL, userEntry.st_dev, slotEntry);
}

static int UAWriteAll(int fd, NSData *contents) {
    const uint8_t *bytes = contents.bytes;
    for (size_t offset = 0; offset < contents.length;) {
        ssize_t count = write(fd, bytes + offset, contents.length - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return count == 0 ? EIO : errno;
        }
        offset += (size_t)count;
    }
    return 0;
}

static int UAPublishRecord(int slot, dev_t device, NSDictionary *record) {
    NSData *encoded = [NSJSONSerialization dataWithJSONObject:record options:0 error:NULL];
    if (encoded.length == 0 || encoded.length > (NSUInteger)MaximumRecordBytes) {
        errno = EINVAL;
        return -1;
    }
    int file __attribute__((cleanup(UACloseDescriptor))) =
        openat(slot, PendingRecordName, O_RDWR | O_CREAT | O_EXCL | FileFlags, 0600);
    struct stat fileEntry;
    if (file < 0) {
        return -1;
    }
    if (!UAPrivateFile(file, &fileEntry, device) || fileEntry.st_size != 0) {
        errno = EPERM;
        return -1;
    }
    int error = UAWriteAll(file, encoded);
    if (error != 0) {
        errno = error;
        return -1;
    }
    // This same file descriptor holds the exclusive slot lock after publish.
    // Flush both the bytes and the directory entry before moving the app.
    if (flock(file, LOCK_EX | LOCK_NB) != 0 || fsync(file) != 0
        || renameatx_np(slot, PendingRecordName, slot, RecordName, RENAME_EXCL) != 0
        || fsync(slot) != 0 || fcntl(file, F_FULLFSYNC) != 0) {
        return -1;
    }
    int locked = file;
    file = -1;
    return locked;
}

static int UAOpenLockedRecord(int slot, dev_t device, int lock) {
    int file = openat(slot, RecordName, O_RDONLY | FileFlags);
    if (file < 0) {
        return -1;
    }
    struct stat entry;
    if (!UAPrivateFile(file, &entry, device)
        || entry.st_size <= 0 || entry.st_size > MaximumRecordBytes) {
        close(file);
        errno = EINVAL;
        return -1;
    }
    if (flock(file, lock | LOCK_NB) != 0) {
        UACloseDescriptor(&file);
        return -1;
    }
    return file;
}

static bool UAReadPositiveInteger(id value, uint64_t maximum, uint64_t *result) {
    if (![value isKindOfClass:NSNumber.class]
        || CFGetTypeID((__bridge CFTypeRef)value) != CFNumberGetTypeID()) {
        return false;
    }
    CFNumberRef number = (__bridge CFNumberRef)value;
    int64_t signedValue;
    if (CFNumberIsFloatType(number) || !CFNumberGetValue(number, kCFNumberSInt64Type, &signedValue)
        || signedValue <= 0 || (uint64_t)signedValue > maximum) {
        return false;
    }
    *result = (uint64_t)signedValue;
    return true;
}

static bool UAValidRecordRetention(NSDictionary *record) {
    uint64_t version;
    if (!UAReadPositiveInteger(record[@"version"], 2, &version)) {
        return false;
    }
    if (version == 1) {
        return [record[@"prepared_at_epoch_seconds"] isKindOfClass:NSNumber.class]
            && record[@"prepared_at_unix_ms"] == nil && record[@"retention_days"] == nil
            && record[@"expires_at_unix_ms"] == nil;
    }
    uint64_t days, prepared, expiration;
    if (!UAReadPositiveInteger(record[@"retention_days"], UINT16_MAX, &days)
        || !UAReadPositiveInteger(record[@"prepared_at_unix_ms"], MaximumExactUnixMilliseconds,
                                  &prepared)
        || !UAReadPositiveInteger(record[@"expires_at_unix_ms"], MaximumExactUnixMilliseconds,
                                  &expiration)
        || record[@"prepared_at_epoch_seconds"] != nil) {
        return false;
    }
    uint64_t lifetime = days * MillisecondsPerDay;
    // The policy uses exact milliseconds. The fraction in the display reply
    // doesn't participate in validating a serialized quarantine journal.
    return expiration > lifetime && expiration - lifetime == prepared;
}

static NSDictionary *UAReadRecord(int file, uid_t uid, NSString *operationID,
                                  NSData **encoded, struct stat *recordEntry) {
    struct stat entry;
    if (fstat(file, &entry) != 0 || entry.st_size <= 0 || entry.st_size > MaximumRecordBytes) {
        return nil;
    }
    NSMutableData *contents = [NSMutableData dataWithLength:(NSUInteger)entry.st_size];
    uint8_t *bytes = contents.mutableBytes;
    for (size_t offset = 0; offset < contents.length;) {
        ssize_t count = pread(file, bytes + offset, contents.length - offset, (off_t)offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return nil;
        }
        offset += (size_t)count;
    }
    struct stat current;
    if (fstat(file, &current) != 0 || !UAUnchangedBundle(&entry, &current)) {
        return nil;
    }
    id record = [NSJSONSerialization JSONObjectWithData:contents options:0 error:NULL];
    if (![record isKindOfClass:NSDictionary.class]
        || ![@(uid) isEqual:record[@"uid"]]
        || ![operationID isEqual:record[@"operation_id"]]
        || UAApplicationName(record[@"basename"]) == NULL
        || !UAValidDescription(record[@"bundle_id"], record[@"root_stamp"])
        || !UAIsCanonicalUUID(record[@"volume_id"])
        || ![record[@"parent_identity"] isKindOfClass:NSDictionary.class]
        || ![record[@"bundle_identity"] isKindOfClass:NSDictionary.class]
        || !UAValidRecordRetention(record)) {
        return nil;
    }
    *encoded = contents;
    *recordEntry = entry;
    return record;
}

static int UAPublishMarker(int slot, dev_t device, const char *name, struct timespec *creation) {
    int file __attribute__((cleanup(UACloseDescriptor))) =
        openat(slot, name, O_RDWR | O_CREAT | O_EXCL | FileFlags, 0600);
    if (file < 0 && errno == EEXIST) {
        file = openat(slot, name, O_RDWR | FileFlags);
    }
    if (file < 0) {
        return errno;
    }
    struct stat entry;
    if (!UAPrivateFile(file, &entry, device) || entry.st_size != 0) {
        return EINVAL;
    }
    if (fsync(slot) != 0 || fcntl(file, F_FULLFSYNC) != 0) {
        return errno;
    }
    if (creation != NULL) {
        *creation = entry.st_birthtimespec;
    }
    return 0;
}

static int UAReadMarker(int slot, dev_t device, const char *name, bool *present,
                        struct timespec *creation) {
    int file __attribute__((cleanup(UACloseDescriptor))) = openat(slot, name, O_RDONLY | FileFlags);
    struct stat entry;
    *present = file >= 0;
    if (file < 0) {
        return errno == ENOENT ? 0 : errno;
    }
    if (!UAPrivateFile(file, &entry, device) || entry.st_size != 0) {
        return EINVAL;
    }
    if (creation != NULL) {
        *creation = entry.st_birthtimespec;
    }
    return 0;
}

static bool UABundleAt(int parent, const char *name, int openBundle, const struct stat *expected) {
    struct stat actual, named;
    return UAPlainRootDirectory(openBundle, &actual, false)
        && (actual.st_flags & ProtectedFlags) == 0
        && UAUnchangedBundle(expected, &actual)
        && fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0
        && UAUnchangedBundle(expected, &named);
}

static bool UABasenameIsExact(int bundleFD, const char *basename) {
    char path[PATH_MAX];
    if (fcntl(bundleFD, F_GETPATH, path) != 0) {
        return false;
    }
    const char *lastSeparator = strrchr(path, '/');
    return lastSeparator != NULL && strcmp(lastSeparator + 1, basename) == 0;
}

typedef NS_ENUM(NSInteger, UAEntryState) {
    UAEntryMissing,
    UAEntryExpected,
    UAEntryDifferent,
    UAEntryUnreadable,
};

static UAEntryState UARecordEntryAt(int parent, const char *name, dev_t device,
                                    NSDictionary *identity, struct stat *snapshot) {
    struct stat named;
    if (fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno == ENOENT ? UAEntryMissing : UAEntryUnreadable;
    }
    if (named.st_dev != device || !S_ISDIR(named.st_mode)
        || ![identity isEqual:UAEntryRecord(&named)]) {
        return UAEntryDifferent;
    }
    int bundle __attribute__((cleanup(UACloseDescriptor))) = openat(parent, name, DirectoryFlags);
    if (bundle < 0 || !UABundleAt(parent, name, bundle, &named) || !UABasenameIsExact(bundle, name)) {
        return UAEntryUnreadable;
    }
    if (snapshot != NULL) {
        *snapshot = named;
    }
    return UAEntryExpected;
}

typedef struct {
    int slot;
    int applications;
    struct stat slotEntry;
    struct stat parentEntry;
    struct stat recordEntry;
} UAQuarantineObservation;

static void UAHashNamespaceEntry(CC_SHA256_CTX *hash, const struct stat *entry, bool includeContents) {
    // The journal includes the volume UUID. Device numbers can change
    // across restarts, so they are only compared when the objects are open.
    const uint64_t identity[] = {
        CFSwapInt64HostToBig((uint64_t)entry->st_ino),
        CFSwapInt64HostToBig((uint64_t)entry->st_birthtimespec.tv_sec),
        CFSwapInt64HostToBig((uint64_t)entry->st_birthtimespec.tv_nsec),
        CFSwapInt64HostToBig((uint64_t)entry->st_uid),
        CFSwapInt64HostToBig((uint64_t)entry->st_gid),
        CFSwapInt64HostToBig((uint64_t)entry->st_mode),
        CFSwapInt64HostToBig((uint64_t)entry->st_flags),
    };
    CC_SHA256_Update(hash, identity, sizeof(identity));
    if (includeContents) {
        const uint64_t contents[] = {
            CFSwapInt64HostToBig((uint64_t)entry->st_size),
            CFSwapInt64HostToBig((uint64_t)entry->st_nlink),
            CFSwapInt64HostToBig((uint64_t)entry->st_ctimespec.tv_sec),
            CFSwapInt64HostToBig((uint64_t)entry->st_ctimespec.tv_nsec),
            CFSwapInt64HostToBig((uint64_t)entry->st_mtimespec.tv_sec),
            CFSwapInt64HostToBig((uint64_t)entry->st_mtimespec.tv_nsec),
        };
        CC_SHA256_Update(hash, contents, sizeof(contents));
    }
}

static NSString *UAFinishStamp(CC_SHA256_CTX *hash) {
    static const char Hex[] = "0123456789abcdef";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, hash);
    char encoded[sizeof(digest) * 2 + 1];
    for (size_t index = 0; index < sizeof(digest); index++) {
        encoded[index * 2] = Hex[digest[index] >> 4];
        encoded[index * 2 + 1] = Hex[digest[index] & 0x0f];
    }
    encoded[sizeof(encoded) - 1] = '\0';
    return [NSString stringWithUTF8String:encoded];
}

static void UAHashExpiryData(CC_SHA256_CTX *hash, NSData *bytes) {
    uint64_t length = CFSwapInt64HostToBig((uint64_t)bytes.length);
    CC_SHA256_Update(hash, &length, sizeof(length));
    if (bytes.length != 0) {
        CC_SHA256_Update(hash, bytes.bytes, (CC_LONG)bytes.length);
    }
}

static NSString *UAExpiryRecordDigest(NSData *encodedRecord) {
    static const char Domain[] = "UninstallAny.expiry-record.v1";
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    CC_SHA256_Update(&hash, Domain, sizeof(Domain));
    UAHashExpiryData(&hash, encodedRecord);
    return UAFinishStamp(&hash);
}

static NSData *UAExpiryCommitment(NSData *encodedRecord, NSData *planBytes) {
    static const char Domain[] = "UninstallAny.expiry-commit.v1";
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    CC_SHA256_Update(&hash, Domain, sizeof(Domain));
    UAHashExpiryData(&hash, encodedRecord);
    UAHashExpiryData(&hash, planBytes);
    return [UAFinishStamp(&hash) dataUsingEncoding:NSASCIIStringEncoding];
}

static bool UAExpiryFileAt(int slot, const char *name, int descriptor, dev_t device,
                            struct stat *entry) {
    struct stat named;
    return UAPrivateFile(descriptor, entry, device)
        && (entry->st_flags & ProtectedFlags) == 0
        && fstatat(slot, name, &named, AT_SYMLINK_NOFOLLOW) == 0
        && UAUnchangedBundle(entry, &named);
}

static int UAReadExpiryFile(int slot, dev_t device, const char *name, off_t limit,
                            NSData **bytes) {
    *bytes = nil;
    int fd __attribute__((cleanup(UACloseDescriptor))) = openat(slot, name, O_RDONLY | FileFlags);
    if (fd < 0) {
        return errno == ENOENT ? 0 : errno;
    }
    struct stat entry;
    if (!UAExpiryFileAt(slot, name, fd, device, &entry) || entry.st_size <= 0
        || entry.st_size > limit) {
        return EINVAL;
    }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)entry.st_size];
    uint8_t *buffer = data.mutableBytes;
    for (size_t offset = 0; offset < data.length;) {
        ssize_t count = pread(fd, buffer + offset, data.length - offset, (off_t)offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return count == 0 ? EIO : errno;
        }
        offset += (size_t)count;
    }
    struct stat current;
    if (!UAExpiryFileAt(slot, name, fd, device, &current) || !UAUnchangedBundle(&entry, &current)) {
        return ESTALE;
    }
    *bytes = data;
    return 0;
}

static int UAPublishExpiryFile(int slot, dev_t device, const char *temporary, const char *name,
                               NSData *contents) {
    if (contents.length == 0 || contents.length > (NSUInteger)MaximumExpiryPlanBytes) {
        return EINVAL;
    }
    int fd __attribute__((cleanup(UACloseDescriptor))) =
        openat(slot, temporary, O_RDWR | O_CREAT | O_EXCL | FileFlags, 0600);
    if (fd < 0 && errno == EEXIST) {
        fd = openat(slot, temporary, O_RDWR | FileFlags);
    }
    if (fd < 0) {
        return errno;
    }
    struct stat entry;
    if (!UAExpiryFileAt(slot, temporary, fd, device, &entry)) {
        return EPERM;
    }
    // A crash can leave an unpublished temporary file. Rewrite it only
    // under the journal lock, after the operation has been confirmed.
    if (ftruncate(fd, 0) != 0) {
        return errno;
    }
    int error = UAWriteAll(fd, contents);
    if (error != 0) {
        return error;
    }
    if (fsync(fd) != 0 || renameatx_np(slot, temporary, slot, name, RENAME_EXCL) != 0
        || fsync(slot) != 0 || fcntl(fd, F_FULLFSYNC) != 0) {
        return errno;
    }
    return 0;
}

static int UAFlushExpiryFile(int slot, dev_t device, const char *name, NSData *approved) {
    int fd __attribute__((cleanup(UACloseDescriptor))) = openat(slot, name, O_RDWR | FileFlags);
    if (fd < 0) {
        return errno;
    }
    struct stat entry, current;
    NSData *saved = nil;
    if (!UAExpiryFileAt(slot, name, fd, device, &entry)) {
        return EPERM;
    }
    int error = UAReadExpiryFile(slot, device, name, (off_t)approved.length, &saved);
    if (error != 0) {
        return error;
    }
    if (![approved isEqualToData:saved] || !UAExpiryFileAt(slot, name, fd, device, &current)
        || !UAUnchangedBundle(&entry, &current)) {
        return ESTALE;
    }
    // If publication was interrupted after the exclusive rename, re-sync
    // its name before using the file as authority for irreversible work.
    return fsync(slot) == 0 && fcntl(fd, F_FULLFSYNC) == 0 ? 0 : errno;
}

static NSArray<NSDictionary *> *UAExpiryPlanEntries(NSData *plan, NSData *encodedRecord) {
    if (plan == nil) {
        return nil;
    }
    id parsed = [NSJSONSerialization JSONObjectWithData:plan options:0 error:NULL];
    if (![parsed isKindOfClass:NSDictionary.class] || [parsed count] != 3
        || ![@1 isEqual:parsed[@"version"]]
        || ![UAExpiryRecordDigest(encodedRecord) isEqual:parsed[@"record_sha256"]]) {
        return nil;
    }
    id entries = parsed[@"entries"];
    return [entries isKindOfClass:NSArray.class] && [entries count] > 0 ? entries : nil;
}

static NSData *UAEncodeExpiryPlan(NSArray<NSDictionary *> *entries, NSData *encodedRecord) {
    NSDictionary *plan = @{@"version": @1, @"record_sha256": UAExpiryRecordDigest(encodedRecord),
                            @"entries": entries};
    NSData *bytes = [NSJSONSerialization dataWithJSONObject:plan options:NSJSONWritingSortedKeys
                                                      error:NULL];
    return bytes.length <= (NSUInteger)MaximumExpiryPlanBytes ? bytes : nil;
}

static NSDictionary *UAPendingExpiryResult(NSDictionary *record, int failure, bool destinationOccupied) {
    NSMutableDictionary *result = [UARecordedResult(@"expiry_pending", record, failure,
                                                    destinationOccupied) mutableCopy];
    NSMutableDictionary *details = [result[@"record"] mutableCopy];
    NSString *held = details[@"backup_path"];
    details[@"backup_path"] = [held.stringByDeletingLastPathComponent
        stringByAppendingPathComponent:[NSString stringWithUTF8String:ExpiryPendingName]];
    result[@"record"] = details;
    return result;
}

static NSDictionary *UAObserveExpirySlot(const UAQuarantineObservation *observation,
                                         NSDictionary *record, NSData *encodedRecord,
                                         UAEntryState original, UAEntryState payload,
                                         bool allowsExpiry) {
    int slot = observation->slot;
    dev_t device = observation->slotEntry.st_dev;
    UAEntryState pending = UARecordEntryAt(slot, ExpiryPendingName, device,
                                         record[@"bundle_identity"], NULL);
    NSData *commit = nil;
    bool purged;
    struct timespec completed;
    int error = UAReadExpiryFile(slot, device, ExpiryCommitName, UA_ROOT_STAMP_LENGTH, &commit);
    if (error == 0) {
        error = UAReadMarker(slot, device, PurgedMarker, &purged, &completed);
    }
    if (error != 0) {
        return UARecordedResult(@"ambiguous", record, error, false);
    }
    if (pending == UAEntryMissing && commit == nil && !purged) {
        return nil;
    }

    // Once detached, a backup may only appear in the private disposal name.
    // A restored original or another root under that name invalidates proof.
    if (!allowsExpiry || record[@"expires_at_unix_ms"] == nil || payload != UAEntryMissing
        || (original != UAEntryMissing && original != UAEntryDifferent)) {
        return UARecordedResult(@"ambiguous", record, ESTALE, false);
    }
    NSData *plan = nil;
    error = UAReadExpiryFile(slot, device, ExpiryPlanName, MaximumExpiryPlanBytes, &plan);
    // A matching commitment already binds a validated plan, so catalog
    // queries need not decode its entire tree again after commitment.
    if (error != 0 || plan == nil
        || (commit == nil ? UAExpiryPlanEntries(plan, encodedRecord) == nil
                          : ![commit isEqualToData:UAExpiryCommitment(encodedRecord, plan)])) {
        return UARecordedResult(@"ambiguous", record, error == 0 ? ESTALE : error, false);
    }
    if (pending == UAEntryExpected && !purged) {
        return UAPendingExpiryResult(record, 0, original == UAEntryDifferent);
    }
    if (pending == UAEntryMissing && commit != nil) {
        return UAResultWithCompletion(UARecordedResult(@"purged", record, 0,
                                                       original == UAEntryDifferent),
                                      @"purged_at_epoch_seconds", purged ? &completed : NULL);
    }
    return UARecordedResult(@"ambiguous", record, ESTALE, false);
}

static NSString *UARestoreStamp(const UAQuarantineObservation *observation,
                                const struct stat *payload, NSData *encodedRecord) {
    static const char Domain[] = "UninstallAny.restore-preview.v1";
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    CC_SHA256_Update(&hash, Domain, sizeof(Domain));
    UAHashNamespaceEntry(&hash, &observation->slotEntry, false);
    UAHashNamespaceEntry(&hash, &observation->parentEntry, false);
    UAHashNamespaceEntry(&hash, &observation->recordEntry, true);
    UAHashNamespaceEntry(&hash, payload, true);
    // This includes the reviewed paths, UID, volume and identities. The
    // record reader has already bounded the size of the final field.
    CC_SHA256_Update(&hash, encodedRecord.bytes, (CC_LONG)encodedRecord.length);
    return UAFinishStamp(&hash);
}

static NSDictionary *UAObserveSlot(const UAQuarantineObservation *observation,
                                   NSDictionary *record, NSData *encodedRecord) {
    int applications = observation->applications;
    int slot = observation->slot;
    const struct stat *parentEntry = &observation->parentEntry;
    const struct stat *slotEntry = &observation->slotEntry;
    if (applications < 0 || parentEntry->st_dev != slotEntry->st_dev
        || ![record[@"volume_id"] isEqual:UAVolumeIdentifier(applications)]
        || ![record[@"volume_id"] isEqual:UAVolumeIdentifier(slot)]
        || ![record[@"parent_identity"] isEqual:UAEntryRecord(parentEntry)]) {
        return UARecordedResult(@"ambiguous", record, ESTALE, false);
    }
    UAEntryState original = UARecordEntryAt(applications, UAApplicationName(record[@"basename"]),
                                          parentEntry->st_dev, record[@"bundle_identity"], NULL);
    struct stat payloadEntry;
    UAEntryState payload = UARecordEntryAt(slot, PayloadName, slotEntry->st_dev,
                                         record[@"bundle_identity"], &payloadEntry);
    bool quarantined, restoreIntent, restored;
    struct timespec quarantineTime, restoreTime;
    if (UAReadMarker(slot, slotEntry->st_dev, QuarantinedMarker, &quarantined, &quarantineTime) != 0
        || UAReadMarker(slot, slotEntry->st_dev, RestoreIntentMarker, &restoreIntent, NULL) != 0
        || UAReadMarker(slot, slotEntry->st_dev, RestoredMarker, &restored, &restoreTime) != 0) {
        return UARecordedResult(@"ambiguous", record, EIO, false);
    }
    NSDictionary *expiry = UAObserveExpirySlot(observation, record, encodedRecord, original, payload,
                                               quarantined && !restored);
    if (expiry != nil) {
        return UAResultWithCompletion(expiry, @"quarantine_completed_at_epoch_seconds",
                                      quarantined ? &quarantineTime : NULL);
    }
    if (payload == UAEntryExpected && !restored
        && (original == UAEntryDifferent || original == UAEntryMissing)) {
        NSDictionary *recorded = UARecordedResult(@"quarantined", record, 0, original == UAEntryDifferent);
        recorded = UAResultWithCompletion(recorded, @"quarantine_completed_at_epoch_seconds",
                                          quarantined ? &quarantineTime : NULL);
        if (original == UAEntryDifferent) {
            return recorded;
        }
        NSMutableDictionary *result = [recorded mutableCopy];
        NSMutableDictionary *details = [result[@"record"] mutableCopy];
        details[@"restore_stamp"] = UARestoreStamp(observation, &payloadEntry, encodedRecord);
        result[@"record"] = details;
        return result;
    }
    if (payload == UAEntryMissing && original == UAEntryExpected) {
        if (restoreIntent) {
            return UAResultWithCompletion(UARecordedResult(@"restored", record, 0, false),
                                          @"restore_completed_at_epoch_seconds",
                                          restored ? &restoreTime : NULL);
        }
        if (!quarantined && !restored) {
            return UARecordedResult(@"not_quarantined", record, 0, false);
        }
    }
    return UARecordedResult(@"ambiguous", record, ESTALE, false);
}

static bool UAValidStoreUser(uid_t uid) {
    return geteuid() == 0 && uid != 0 && uid != (uid_t)-1;
}

static bool UAValidOperation(uid_t uid, NSString *operationID) {
    return UAValidStoreUser(uid) && UAIsCanonicalUUID(operationID);
}

static bool UARecordStillMatches(const UAQuarantineObservation *observation, int locked) {
    const struct stat *expected = &observation->recordEntry;
    struct stat opened, named;
    return UAPrivateFile(locked, &opened, observation->slotEntry.st_dev)
        && UAUnchangedBundle(expected, &opened)
        && fstatat(observation->slot, RecordName, &named, AT_SYMLINK_NOFOLLOW) == 0
        && UAUnchangedBundle(expected, &named);
}

static bool UARefreshOperationDirectories(UAQuarantineObservation *observation, uid_t uid,
                                           NSString *operationID) {
    struct stat parentEntry, slotEntry;
    int applications __attribute__((cleanup(UACloseDescriptor))) = UAOpenApplications(&parentEntry);
    int slot __attribute__((cleanup(UACloseDescriptor))) = UAOpenSlot(uid, operationID, NULL, &slotEntry);
    if (applications < 0 || slot < 0 || !UASameEntry(&parentEntry, &observation->parentEntry)
        || !UASameEntry(&slotEntry, &observation->slotEntry)) {
        return false;
    }
    observation->parentEntry = parentEntry;
    observation->slotEntry = slotEntry;
    return true;
}

static int UACurrentMilliseconds(uint64_t *milliseconds) {
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
        return errno;
    }
    if (now.tv_sec <= 0 || (uint64_t)now.tv_sec > MaximumExactUnixMilliseconds / MillisecondsPerSecond) {
        return EOVERFLOW;
    }
    uint64_t value = (uint64_t)now.tv_sec * MillisecondsPerSecond + (uint64_t)now.tv_nsec / 1000000;
    if (value > MaximumExactUnixMilliseconds) {
        return EOVERFLOW;
    }
    *milliseconds = value;
    return 0;
}

static int UAQuarantineDeadline(uint16_t retentionDays, uint64_t *prepared, uint64_t *expiration) {
    uint64_t milliseconds;
    int error = UACurrentMilliseconds(&milliseconds);
    if (error != 0) {
        return error;
    }
    uint64_t lifetime = (uint64_t)retentionDays * MillisecondsPerDay;
    if (milliseconds > MaximumExactUnixMilliseconds - lifetime) {
        return EOVERFLOW;
    }
    *prepared = milliseconds;
    *expiration = milliseconds + lifetime;
    return 0;
}

NSDictionary *UAQuarantineVerifiedBundle(uid_t uid, NSString *operationID, int applicationsFD,
                                         int bundleFD, NSString *basename, NSString *identifier,
                                         NSString *rootStamp, uint16_t retentionDays,
                                         BOOL (^mayCommit)(void)) {
    const char *name = UAApplicationName(basename);
    if (!UAValidOperation(uid, operationID) || name == NULL
        || !UAValidDescription(identifier, rootStamp) || retentionDays == 0 || mayCommit == nil) {
        return UAResult(@"invalid_request", nil, EINVAL);
    }
    struct stat applications, bundle;
    NSString *volume = UAVolumeIdentifier(applicationsFD);
    if (volume == nil || !UAPlainRootDirectory(applicationsFD, &applications, true)
        || !UAApplicationsStillMatch(applicationsFD, &applications)
        || fstat(bundleFD, &bundle) != 0 || bundle.st_dev != applications.st_dev
        || !UABundleAt(applicationsFD, name, bundleFD, &bundle)
        || !UABasenameIsExact(bundleFD, name)) {
        return UAResult(@"subject_changed_or_untrusted", operationID, EPERM);
    }
    int treeFailure = UACheckProtectedStandaloneBundleTree(bundleFD);
    if (treeFailure != 0) {
        return UAResult(@"subject_changed_or_untrusted", operationID, treeFailure);
    }
    if (!mayCommit()) {
        return UAResult(@"authorization_revoked", operationID, ECANCELED);
    }
    uint64_t prepared, expiration;
    int failure = UAQuarantineDeadline(retentionDays, &prepared, &expiration);
    if (failure != 0) {
        return UAResult(@"journal_failed", operationID, failure);
    }
    struct stat slotEntry;
    int slot __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenSlot(uid, operationID, &applications.st_dev, &slotEntry);
    if (slot < 0) {
        int failure = errno;
        NSString *status = @"store_unavailable";
        if (failure == EEXIST) {
            status = @"operation_already_exists";
        } else if (failure == EXDEV) {
            status = @"cross_volume";
        }
        return UAResult(status, operationID, failure);
    }
    if (slotEntry.st_dev != applications.st_dev || ![volume isEqual:UAVolumeIdentifier(slot)]) {
        return UAResult(@"cross_volume", operationID, EXDEV);
    }
    NSDictionary *record = @{
        @"version": @2,
        @"operation_id": operationID,
        @"uid": @(uid),
        @"basename": basename,
        @"bundle_id": identifier,
        @"root_stamp": rootStamp,
        @"volume_id": volume,
        @"parent_identity": UAEntryRecord(&applications),
        @"bundle_identity": UAEntryRecord(&bundle),
        @"prepared_at_unix_ms": @(prepared),
        @"retention_days": @(retentionDays),
        @"expires_at_unix_ms": @(expiration),
    };
    int locked __attribute__((cleanup(UACloseDescriptor))) =
        UAPublishRecord(slot, slotEntry.st_dev, record);
    if (locked < 0) {
        return UAResult(@"journal_failed", operationID, errno);
    }
    UAQuarantineObservation observation = {
        .slot = slot,
        .applications = applicationsFD,
        .slotEntry = slotEntry,
        .parentEntry = applications,
    };
    if (fstat(locked, &observation.recordEntry) != 0) {
        return UARecordedResult(@"journal_failed", record, errno, false);
    }
    failure = UACheckStandardCaskrooms();
    if (failure == 0) {
        failure = UACheckSystemBundleBackground(basename, identifier, bundleFD);
    }
    if (failure == 0) {
        failure = UACheckSystemBundleActivity(basename, bundleFD);
    }
    if (failure != 0) {
        return UARecordedResult(@"subject_changed_or_untrusted", record, failure, false);
    }
    // Darwin's exclusive rename is name-based. A trusted parent and the
    // still-open root-owned bundle prevent user replacement of the source.
    if (!UARefreshOperationDirectories(&observation, uid, operationID)
        || !UARecordStillMatches(&observation, locked)
        || !UABundleAt(applicationsFD, name, bundleFD, &bundle)
        || !UABasenameIsExact(bundleFD, name)) {
        return UARecordedResult(@"subject_changed_or_untrusted", record, ESTALE, false);
    }
    if (!mayCommit()) {
        return UARecordedResult(@"authorization_revoked", record, ECANCELED, false);
    }
    if (renameatx_np(applicationsFD, name, slot, PayloadName, RENAME_EXCL) != 0) {
        return UARecordedResult(@"ambiguous", record, errno, false);
    }
    if (UARecordEntryAt(slot, PayloadName, slotEntry.st_dev, record[@"bundle_identity"], NULL)
        != UAEntryExpected) {
        return UARecordedResult(@"ambiguous", record, ESTALE, false);
    }
    if (fsync(applicationsFD) != 0 || fsync(slot) != 0) {
        return UARecordedResult(@"ambiguous", record, errno, false);
    }
    struct timespec completed;
    failure = UAPublishMarker(slot, slotEntry.st_dev, QuarantinedMarker, &completed);
    if (failure != 0) {
        return UARecordedResult(@"ambiguous", record, failure, false);
    }
    // A held directory can outlive its name. Success requires the backup
    // and its journal to remain reachable by the published operation ID.
    if (!UARefreshOperationDirectories(&observation, uid, operationID)
        || !UARecordStillMatches(&observation, locked)
        || UARecordEntryAt(slot, PayloadName, slotEntry.st_dev, record[@"bundle_identity"], NULL)
            != UAEntryExpected) {
        return UARecordedResult(@"ambiguous", record, ESTALE, false);
    }
    return UAResultWithCompletion(UARecordedResult(@"quarantined", record, 0, false),
                                  @"quarantine_completed_at_epoch_seconds", &completed);
}

static NSDictionary *UARecordOpenFailure(NSString *operationID, int failure) {
    NSString *status = @"store_unavailable";
    if (failure == ENOENT) {
        status = @"incomplete_preparation";
    } else if (failure == EWOULDBLOCK) {
        status = @"busy";
    } else if (failure == EINVAL) {
        status = @"ambiguous";
    }
    return UAResult(status, operationID, failure);
}

static NSDictionary *UAQuerySlot(uid_t uid, NSString *operationID, int slot,
                                 const struct stat *slotEntry) {
    if (slot < 0) {
        int failure = errno;
        return UAResult(failure == ENOENT ? @"missing" : @"store_unavailable",
                        operationID, failure);
    }
    UAQuarantineObservation observation = {.slot = slot, .slotEntry = *slotEntry};
    int locked __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenLockedRecord(slot, observation.slotEntry.st_dev, LOCK_SH);
    if (locked < 0) {
        return UARecordOpenFailure(operationID, errno);
    }
    NSData *encoded = nil;
    NSDictionary *record = UAReadRecord(locked, uid, operationID, &encoded, &observation.recordEntry);
    if (record == nil || !UARecordStillMatches(&observation, locked)) {
        return UAResult(@"ambiguous", operationID, EINVAL);
    }
    int applications __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenApplications(&observation.parentEntry);
    observation.applications = applications;
    return UAObserveSlot(&observation, record, encoded);
}

NSDictionary *UAQueryBundleQuarantine(uid_t uid, NSString *operationID) {
    if (!UAValidOperation(uid, operationID)) {
        return UAResult(@"invalid_request", nil, EINVAL);
    }
    struct stat slotEntry;
    int slot __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenSlot(uid, operationID, NULL, &slotEntry);
    return UAQuerySlot(uid, operationID, slot, &slotEntry);
}

static int UAReadCatalogNames(int user, NSMutableArray<NSString *> *names, NSUInteger *ignored) {
    int cursor __attribute__((cleanup(UACloseDescriptor))) = openat(user, ".", DirectoryFlags);
    if (cursor < 0) {
        return errno;
    }
    DIR *directory __attribute__((cleanup(UACloseCatalogDirectory))) = fdopendir(cursor);
    if (directory == NULL) {
        return errno;
    }
    cursor = -1;
    *ignored = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            return errno;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (names.count + *ignored >= MaximumCatalogEntries) {
            return E2BIG;
        }
        NSString *name = entry->d_namlen == UA_OPERATION_ID_LENGTH
            ? [[NSString alloc] initWithBytes:entry->d_name length:entry->d_namlen
                                    encoding:NSASCIIStringEncoding]
            : nil;
        if (UAIsCanonicalUUID(name)) {
            [names addObject:name];
        } else {
            (*ignored)++;
        }
    }
}

static NSString *UACatalogStamp(uid_t uid, const struct stat *userEntry, NSString *volume,
                                NSArray<NSString *> *names, NSUInteger ignored) {
    static const char Domain[] = "UninstallAny.quarantine-catalog.v1";
    const uint64_t scope[] = {
        CFSwapInt64HostToBig(uid),
        CFSwapInt64HostToBig(userEntry != NULL),
        CFSwapInt64HostToBig(names.count),
        CFSwapInt64HostToBig(ignored),
    };
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    CC_SHA256_Update(&hash, Domain, sizeof(Domain));
    CC_SHA256_Update(&hash, scope, sizeof(scope));
    if (userEntry != NULL) {
        UAHashNamespaceEntry(&hash, userEntry, true);
        CC_SHA256_Update(&hash, volume.UTF8String, UA_OPERATION_ID_LENGTH);
    }
    for (NSString *name in names) {
        CC_SHA256_Update(&hash, name.UTF8String, UA_OPERATION_ID_LENGTH);
    }
    return UAFinishStamp(&hash);
}

static bool UACatalogStillMatches(uid_t uid, int user, const struct stat *expected, NSString *volume) {
    struct stat heldEntry, namedEntry;
    int named __attribute__((cleanup(UACloseDescriptor))) = UAOpenUserStore(uid, NULL, &namedEntry);
    return named >= 0 && fstat(user, &heldEntry) == 0
        && UAUnchangedBundle(expected, &heldEntry) && UAUnchangedBundle(expected, &namedEntry)
        && [volume isEqual:UAVolumeIdentifier(named)];
}

int UAListBundleQuarantine(uid_t uid, NSString *afterOperationID, NSString *expectedCatalogStamp,
                           NSDictionary **page) {
    *page = nil;
    bool firstPage = afterOperationID == nil && expectedCatalogStamp == nil;
    if (!UAValidStoreUser(uid)
        || (!firstPage && (!UAIsCanonicalUUID(afterOperationID) || !UAValidStamp(expectedCatalogStamp)))) {
        return EINVAL;
    }
    struct stat userEntry;
    int user __attribute__((cleanup(UACloseDescriptor))) = UAOpenUserStore(uid, NULL, &userEntry);
    if (user < 0) {
        if (errno != ENOENT) {
            return errno;
        }
        if (!firstPage) {
            return ESTALE;
        }
        *page = @{@"catalog_stamp": UACatalogStamp(uid, NULL, nil, @[], 0),
                  @"entries": @[], @"ignored_entries": @0};
        return 0;
    }
    NSString *volume = UAVolumeIdentifier(user);
    if (volume == nil) {
        return ENOTSUP;
    }
    NSUInteger ignored;
    NSMutableArray<NSString *> *names = [NSMutableArray array];
    int status = UAReadCatalogNames(user, names, &ignored);
    if (status != 0) {
        return status;
    }
    [names sortUsingComparator:^NSComparisonResult(NSString *left, NSString *right) {
        return [left compare:right options:NSLiteralSearch];
    }];
    if (!UACatalogStillMatches(uid, user, &userEntry, volume)) {
        return ESTALE;
    }
    NSString *stamp = UACatalogStamp(uid, &userEntry, volume, names, ignored);
    NSUInteger start = 0;
    if (!firstPage) {
        NSUInteger index = [names indexOfObject:afterOperationID];
        if (![stamp isEqual:expectedCatalogStamp] || index == NSNotFound) {
            return ESTALE;
        }
        start = index + 1;
    }
    NSUInteger end = MIN(names.count, start + UA_QUARANTINE_PAGE_ENTRIES);
    NSMutableArray<NSDictionary *> *entries = [NSMutableArray arrayWithCapacity:end - start];
    for (NSUInteger index = start; index < end; index++) {
        @autoreleasepool {
            NSString *name = names[index];
            struct stat slotEntry;
            int slot __attribute__((cleanup(UACloseDescriptor))) =
                UAOpenUserSlot(user, name, false, userEntry.st_dev, &slotEntry);
            [entries addObject:UAQuerySlot(uid, name, slot, &slotEntry)];
        }
    }
    // The catalog describes a stable namespace. Each slot's volatile state
    // is sampled independently using its own journal lock.
    if (!UACatalogStillMatches(uid, user, &userEntry, volume)) {
        return ESTALE;
    }
    NSMutableDictionary *result = [@{@"catalog_stamp": stamp, @"entries": entries,
                                     @"ignored_entries": @(ignored)} mutableCopy];
    if (end < names.count) {
        result[@"next_operation_id"] = names[end - 1];
    }
    *page = result;
    return 0;
}

@interface UAExpiryReview : NSObject
@property(nonatomic, copy) NSDictionary *display;
@property(nonatomic, copy) NSData *plan;
@property(nonatomic, copy) NSData *commitment;
@property(nonatomic, copy) NSArray<NSDictionary *> *remaining;
@property(nonatomic) BOOL hasSavedPlan;
@property(nonatomic) BOOL isPending;
@end

@implementation UAExpiryReview
@end

static int UAExpiryDeadlineReached(NSDictionary *record, NSNumber *completed) {
    uint64_t expiration;
    if (!UAReadPositiveInteger(record[@"expires_at_unix_ms"], MaximumExactUnixMilliseconds,
                               &expiration)
        || ![completed isKindOfClass:NSNumber.class] || !(completed.doubleValue > 0.0)) {
        return ENOTSUP;
    }
    uint64_t now;
    int error = UACurrentMilliseconds(&now);
    if (error != 0) {
        return error;
    }
    if (expiration > now || completed.doubleValue > (double)now / MillisecondsPerSecond) {
        return EAGAIN;
    }
    return 0;
}

static int UAOpenExpiryPayload(const UAQuarantineObservation *observation, NSDictionary *record,
                               const char *name, struct stat *entry) {
    int bundle = openat(observation->slot, name, DirectoryFlags);
    if (bundle < 0) {
        return -1;
    }
    if (fstat(bundle, entry) != 0 || entry->st_dev != observation->slotEntry.st_dev
        || ![record[@"bundle_identity"] isEqual:UAEntryRecord(entry)]
        || !UABundleAt(observation->slot, name, bundle, entry) || !UABasenameIsExact(bundle, name)) {
        close(bundle);
        errno = ESTALE;
        return -1;
    }
    return bundle;
}

static NSString *UAExpiryReviewStamp(const UAQuarantineObservation *observation, bool pending,
                                      NSData *plan, NSData *commit, NSData *remaining) {
    static const char Domain[] = "UninstallAny.expiry-preview.v1";
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    CC_SHA256_Update(&hash, Domain, sizeof(Domain));
    UAHashNamespaceEntry(&hash, &observation->slotEntry, false);
    UAHashNamespaceEntry(&hash, &observation->parentEntry, false);
    UAHashNamespaceEntry(&hash, &observation->recordEntry, true);
    const unsigned char phase = pending ? 1 : 0;
    CC_SHA256_Update(&hash, &phase, sizeof(phase));
    UAHashExpiryData(&hash, plan);
    UAHashExpiryData(&hash, commit);
    UAHashExpiryData(&hash, remaining);
    return UAFinishStamp(&hash);
}

static int UAReadExpiryReview(const UAQuarantineObservation *observation, NSDictionary *record,
                              NSData *encoded, UAExpiryReview **result) {
    *result = nil;
    NSDictionary *observed = UAObserveSlot(observation, record, encoded);
    NSString *state = observed[@"status"];
    BOOL pending = [state isEqualToString:@"expiry_pending"];
    if (!pending && ![state isEqualToString:@"quarantined"]) {
        return ESTALE;
    }
    NSDictionary *details = observed[@"record"];
    int error = UAExpiryDeadlineReached(record, details[@"quarantine_completed_at_epoch_seconds"]);
    if (error != 0) {
        return error;
    }

    const char *name = pending ? ExpiryPendingName : PayloadName;
    int slot = observation->slot;
    dev_t device = observation->slotEntry.st_dev;
    struct stat entry;
    int bundle __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenExpiryPayload(observation, record, name, &entry);
    if (bundle < 0) {
        return errno;
    }
    NSData *plan = nil;
    NSData *commit = nil;
    error = UAReadExpiryFile(slot, device, ExpiryPlanName, MaximumExpiryPlanBytes, &plan);
    if (error == 0) {
        error = UAReadExpiryFile(slot, device, ExpiryCommitName, UA_ROOT_STAMP_LENGTH, &commit);
    }
    if (error != 0) {
        return error;
    }
    bool hasSavedPlan = plan != nil;
    NSArray<NSDictionary *> *remaining = nil;
    if (!hasSavedPlan) {
        if (pending || commit != nil) {
            return ESTALE;
        }
        error = UACaptureExpiryTree(bundle, &remaining);
        if (error == 0) {
            plan = UAEncodeExpiryPlan(remaining, encoded);
        }
    } else {
        NSArray<NSDictionary *> *approved = UAExpiryPlanEntries(plan, encoded);
        if (approved == nil
            || (commit != nil && (!pending || ![commit isEqualToData:UAExpiryCommitment(encoded, plan)]))) {
            return ESTALE;
        }
        error = UACheckRemainingExpiryTree(bundle, approved, &remaining);
        if (error == 0 && commit == nil && ![remaining isEqualToArray:approved]) {
            // Removals are only legitimate after a durable commitment.
            return ESTALE;
        }
    }
    if (error != 0) {
        return error;
    }
    NSData *remainingBytes = [NSJSONSerialization dataWithJSONObject:remaining
                                      options:NSJSONWritingSortedKeys error:NULL];
    if (plan == nil || remainingBytes.length == 0
        || remainingBytes.length > (NSUInteger)MaximumExpiryPlanBytes) {
        return EFBIG;
    }
    if (!UABundleAt(slot, name, bundle, &entry)) {
        return ESTALE;
    }

    UAExpiryReview *review = [UAExpiryReview new];
    review.display = @{@"operation_id": record[@"operation_id"],
                       @"expiry_stamp": UAExpiryReviewStamp(observation, pending, plan, commit,
                                                            remainingBytes),
                       @"bundle_id": record[@"bundle_id"],
                       @"original_path": details[@"original_path"],
                       @"backup_path": details[@"backup_path"],
                       @"expires_at_unix_ms": record[@"expires_at_unix_ms"],
                       @"remaining_entries": @(remaining.count), @"is_pending": @(pending)};
    review.plan = plan;
    review.commitment = commit;
    review.remaining = remaining;
    review.hasSavedPlan = hasSavedPlan;
    review.isPending = pending;
    *result = review;
    return 0;
}

int UAPreviewBundleExpiry(uid_t uid, NSString *operationID, NSDictionary **review) {
    *review = nil;
    if (!UAValidOperation(uid, operationID)) {
        return EINVAL;
    }
    UAQuarantineObservation observation = {0};
    int slot __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenSlot(uid, operationID, NULL, &observation.slotEntry);
    if (slot < 0) {
        return errno;
    }
    observation.slot = slot;
    int locked __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenLockedRecord(slot, observation.slotEntry.st_dev, LOCK_SH);
    if (locked < 0) {
        return errno;
    }
    NSData *encoded = nil;
    NSDictionary *record = UAReadRecord(locked, uid, operationID, &encoded, &observation.recordEntry);
    if (record == nil || !UARecordStillMatches(&observation, locked)) {
        return ESTALE;
    }
    int applications __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenApplications(&observation.parentEntry);
    observation.applications = applications;
    UAExpiryReview *sample = nil;
    int error = UAReadExpiryReview(&observation, record, encoded, &sample);
    if (error != 0) {
        return error;
    }
    if (!UARefreshOperationDirectories(&observation, uid, operationID)
        || !UARecordStillMatches(&observation, locked)) {
        return ESTALE;
    }
    *review = sample.display;
    return 0;
}

static bool UAExpiryScopeStillMatches(UAQuarantineObservation *observation, NSDictionary *record,
                                      int locked, bool *destinationOccupied) {
    uid_t uid = [record[@"uid"] unsignedIntValue];
    if (!UARefreshOperationDirectories(observation, uid, record[@"operation_id"])
        || !UARecordStillMatches(observation, locked)) {
        return false;
    }
    UAEntryState original = UARecordEntryAt(observation->applications,
        UAApplicationName(record[@"basename"]), observation->parentEntry.st_dev,
        record[@"bundle_identity"], NULL);
    *destinationOccupied = original == UAEntryDifferent;
    return original == UAEntryMissing || original == UAEntryDifferent;
}

static NSDictionary *UAExpiryInterrupted(UAQuarantineObservation *observation, NSDictionary *record,
                                         NSData *encoded, int locked, int failure) {
    bool destinationOccupied;
    if (UAExpiryScopeStillMatches(observation, record, locked, &destinationOccupied)) {
        NSDictionary *observed = UAObserveSlot(observation, record, encoded);
        if ([observed[@"status"] isEqualToString:@"expiry_pending"]) {
            NSMutableDictionary *result = [observed mutableCopy];
            result[@"errno"] = @(failure);
            return result;
        }
    }
    return UARecordedResult(@"ambiguous", record, failure, false);
}

static int UAValidatePendingExpiryTree(const UAQuarantineObservation *observation,
                                       NSDictionary *record, NSArray<NSDictionary *> *reviewed) {
    int slot = observation->slot;
    dev_t device = observation->slotEntry.st_dev;
    if (UARecordEntryAt(slot, PayloadName, device, record[@"bundle_identity"], NULL)
        != UAEntryMissing) {
        return ESTALE;
    }
    struct stat entry;
    int bundle __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenExpiryPayload(observation, record, ExpiryPendingName, &entry);
    if (bundle < 0) {
        return errno;
    }
    NSArray<NSDictionary *> *remaining = nil;
    int error = UACheckRemainingExpiryTree(bundle, reviewed, &remaining);
    if (error != 0) {
        return error;
    }
    return [remaining isEqualToArray:reviewed] && UABundleAt(slot, ExpiryPendingName, bundle, &entry)
        ? 0 : ESTALE;
}

static int UAExpiryRetainsMarker(const UAQuarantineObservation *observation, NSDictionary *record) {
    bool quarantined, restored, purged;
    struct timespec completed;
    int slot = observation->slot;
    dev_t device = observation->slotEntry.st_dev;
    if (UAReadMarker(slot, device, QuarantinedMarker, &quarantined, &completed) != 0
        || UAReadMarker(slot, device, RestoredMarker, &restored, NULL) != 0
        || UAReadMarker(slot, device, PurgedMarker, &purged, NULL) != 0
        || !quarantined || restored || purged) {
        return ESTALE;
    }
    return UAExpiryDeadlineReached(record, @((double)completed.tv_sec + (double)completed.tv_nsec / 1e9));
}

NSDictionary *UAExpireVerifiedBundle(uid_t uid, NSString *operationID, NSString *expiryStamp,
                                     BOOL (^mayCommit)(void)) {
    if (!UAValidOperation(uid, operationID) || !UAValidStamp(expiryStamp) || mayCommit == nil) {
        return UAResult(@"invalid_request", nil, EINVAL);
    }
    UAQuarantineObservation observation = {0};
    int slot __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenSlot(uid, operationID, NULL, &observation.slotEntry);
    if (slot < 0) {
        int failure = errno;
        return UAResult(failure == ENOENT ? @"missing" : @"store_unavailable", operationID, failure);
    }
    observation.slot = slot;
    int locked __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenLockedRecord(slot, observation.slotEntry.st_dev, LOCK_EX);
    if (locked < 0) {
        return UARecordOpenFailure(operationID, errno);
    }
    NSData *encoded = nil;
    NSDictionary *record = UAReadRecord(locked, uid, operationID, &encoded, &observation.recordEntry);
    if (record == nil || !UARecordStillMatches(&observation, locked)) {
        return UAResult(@"ambiguous", operationID, ESTALE);
    }
    int applications __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenApplications(&observation.parentEntry);
    observation.applications = applications;
    UAExpiryReview *review = nil;
    int error = UAReadExpiryReview(&observation, record, encoded, &review);
    if (error != 0 || ![expiryStamp isEqual:review.display[@"expiry_stamp"]]) {
        return UARecordedResult(@"expiry_preview_changed", record, error == 0 ? ESTALE : error, false);
    }

    bool destinationOccupied;
    if (!UAExpiryScopeStillMatches(&observation, record, locked, &destinationOccupied)) {
        return UARecordedResult(@"expiry_preview_changed", record, ESTALE, false);
    }
    if (!mayCommit()) {
        return UARecordedResult(@"authorization_revoked", record, ECANCELED, destinationOccupied);
    }
    dev_t device = observation.slotEntry.st_dev;
    if (!review.hasSavedPlan) {
        error = UAPublishExpiryFile(slot, device, ExpiryPlanTemporary, ExpiryPlanName, review.plan);
    }
    if (error == 0) {
        error = UAFlushExpiryFile(slot, device, ExpiryPlanName, review.plan);
    }
    if (error != 0) {
        return review.isPending ? UAExpiryInterrupted(&observation, record, encoded, locked, error)
            : UARecordedResult(@"journal_failed", record, error, destinationOccupied);
    }

    if (!review.isPending) {
        struct stat heldEntry;
        int payload __attribute__((cleanup(UACloseDescriptor))) =
            UAOpenExpiryPayload(&observation, record, PayloadName, &heldEntry);
        NSArray<NSDictionary *> *checked = nil;
        error = payload < 0 ? errno : UACheckRemainingExpiryTree(payload, review.remaining, &checked);
        if (error != 0 || ![checked isEqualToArray:review.remaining]
            || !UAExpiryScopeStillMatches(&observation, record, locked, &destinationOccupied)
            || !UABundleAt(slot, PayloadName, payload, &heldEntry)) {
            return UARecordedResult(@"expiry_preview_changed", record,
                                    error == 0 ? ESTALE : error, destinationOccupied);
        }
        error = UAExpiryRetainsMarker(&observation, record);
        if (error != 0 || !mayCommit()) {
            return UARecordedResult(@"authorization_revoked", record,
                                    error == 0 ? ECANCELED : error, destinationOccupied);
        }
        if (renameatx_np(slot, PayloadName, slot, ExpiryPendingName, RENAME_EXCL) != 0) {
            return UAExpiryInterrupted(&observation, record, encoded, locked, errno);
        }
    }

    // A saved tree outline does not authorize deletion until the detachment
    // and a matching commitment are both durable in this exact slot.
    error = fsync(slot) == 0 ? UAValidatePendingExpiryTree(&observation, record, review.remaining) : errno;
    if (error == 0 && !UAExpiryScopeStillMatches(&observation, record, locked, &destinationOccupied)) {
        error = ESTALE;
    }
    if (error == 0) {
        error = UAExpiryRetainsMarker(&observation, record);
    }
    if (error != 0 || !mayCommit()) {
        return UAExpiryInterrupted(&observation, record, encoded, locked, error == 0 ? ECANCELED : error);
    }
    NSData *commit = UAExpiryCommitment(encoded, review.plan);
    if (review.commitment == nil) {
        error = UAPublishExpiryFile(slot, device, ExpiryCommitTemporary, ExpiryCommitName, commit);
    }
    if (error == 0) {
        error = UAFlushExpiryFile(slot, device, ExpiryCommitName, commit);
    }
    if (error == 0) {
        error = UAFlushExpiryFile(slot, device, ExpiryPlanName, review.plan);
    }
    if (error == 0 && !UAExpiryScopeStillMatches(&observation, record, locked, &destinationOccupied)) {
        error = ESTALE;
    }
    if (error == 0) {
        error = UAExpiryRetainsMarker(&observation, record);
    }
    if (error == 0) {
        const UAQuarantineObservation *held = &observation;
        error = UARemovePendingExpiryTree(slot, ExpiryPendingName, review.remaining, ^BOOL {
            return mayCommit() && UARecordStillMatches(held, locked);
        });
    }
    if (error != 0) {
        return UAExpiryInterrupted(&observation, record, encoded, locked, error);
    }
    NSDictionary *verified = UAObserveSlot(&observation, record, encoded);
    if (![verified[@"status"] isEqualToString:@"purged"]
        || !UAExpiryScopeStillMatches(&observation, record, locked, &destinationOccupied)) {
        return UARecordedResult(@"ambiguous", record, ESTALE, destinationOccupied);
    }
    error = UAPublishMarker(slot, device, PurgedMarker, NULL);
    if (error != 0 || !UAExpiryScopeStillMatches(&observation, record, locked, &destinationOccupied)) {
        return UARecordedResult(@"ambiguous", record, error == 0 ? ESTALE : error, destinationOccupied);
    }
    verified = UAObserveSlot(&observation, record, encoded);
    if (![verified[@"status"] isEqualToString:@"purged"]
        || verified[@"record"][@"purged_at_epoch_seconds"] == nil) {
        return UARecordedResult(@"ambiguous", record, ESTALE, destinationOccupied);
    }
    return verified;
}

static NSDictionary *UARestoreReviewFailure(NSDictionary *observed, NSDictionary *record,
                                             NSString *expectedStamp) {
    NSString *state = observed[@"status"];
    if ([state isEqualToString:@"ambiguous"]) {
        return observed;
    }
    NSDictionary *details = observed[@"record"];
    if ([state isEqualToString:@"quarantined"]) {
        if ([details[@"destination_occupied"] boolValue]) {
            return UARecordedResult(@"destination_occupied", record, EEXIST, true);
        }
        if ([expectedStamp isEqualToString:details[@"restore_stamp"]]) {
            return nil;
        }
    }
    return UARecordedResult(@"restore_preview_changed", record, ESTALE, false);
}

NSDictionary *UARestoreVerifiedBundle(uid_t uid, NSString *operationID, NSString *expectedRestoreStamp,
                                      BOOL (^mayCommit)(void)) {
    if (!UAValidOperation(uid, operationID) || !UAValidStamp(expectedRestoreStamp) || mayCommit == nil) {
        return UAResult(@"invalid_request", nil, EINVAL);
    }
    UAQuarantineObservation observation = {0};
    int slot __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenSlot(uid, operationID, NULL, &observation.slotEntry);
    if (slot < 0) {
        int failure = errno;
        return UAResult(failure == ENOENT ? @"missing" : @"store_unavailable",
                        operationID, failure);
    }
    observation.slot = slot;
    int locked __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenLockedRecord(slot, observation.slotEntry.st_dev, LOCK_EX);
    if (locked < 0) {
        return UARecordOpenFailure(operationID, errno);
    }
    NSData *encoded = nil;
    NSDictionary *record = UAReadRecord(locked, uid, operationID, &encoded, &observation.recordEntry);
    if (record == nil || !UARecordStillMatches(&observation, locked)) {
        return UAResult(@"ambiguous", operationID, EINVAL);
    }
    int applicationsFD __attribute__((cleanup(UACloseDescriptor))) =
        UAOpenApplications(&observation.parentEntry);
    if (applicationsFD < 0) {
        return UARecordedResult(@"destination_changed_or_untrusted", record, EPERM, false);
    }
    observation.applications = applicationsFD;
    NSDictionary *rejection = UARestoreReviewFailure(
        UAObserveSlot(&observation, record, encoded), record, expectedRestoreStamp);
    if (rejection != nil) {
        return rejection;
    }
    const char *name = UAApplicationName(record[@"basename"]);
    int payload __attribute__((cleanup(UACloseDescriptor))) =
        openat(slot, PayloadName, DirectoryFlags);
    struct stat bundle;
    if (payload < 0 || fstat(payload, &bundle) != 0
        || bundle.st_dev != observation.slotEntry.st_dev
        || ![record[@"bundle_identity"] isEqual:UAEntryRecord(&bundle)]
        || !UABundleAt(slot, PayloadName, payload, &bundle)) {
        return UARecordedResult(@"subject_changed_or_untrusted", record, ESTALE, false);
    }
    int failure = UACheckProtectedBundleTree(payload);
    if (failure != 0) {
        return UARecordedResult(@"subject_changed_or_untrusted", record, failure, false);
    }
    if (!UARefreshOperationDirectories(&observation, uid, operationID)
        || !UARecordStillMatches(&observation, locked)
        || !UABundleAt(slot, PayloadName, payload, &bundle)) {
        return UARecordedResult(@"subject_changed_or_untrusted", record, ESTALE, false);
    }
    // Reject changes during the tree check before writing the intent. The
    // caller's approval and both paths are checked once more before rename.
    rejection = UARestoreReviewFailure(UAObserveSlot(&observation, record, encoded),
                                        record, expectedRestoreStamp);
    if (rejection != nil) {
        return rejection;
    }
    if (!mayCommit()) {
        return UARecordedResult(@"authorization_revoked", record, ECANCELED, false);
    }
    failure = UAPublishMarker(slot, observation.slotEntry.st_dev, RestoreIntentMarker, NULL);
    if (failure != 0) {
        return UARecordedResult(@"journal_failed", record, failure, false);
    }
    if (!UARefreshOperationDirectories(&observation, uid, operationID)
        || !UARecordStillMatches(&observation, locked)
        || !UABundleAt(slot, PayloadName, payload, &bundle)) {
        return UARecordedResult(@"subject_changed_or_untrusted", record, ESTALE, false);
    }
    rejection = UARestoreReviewFailure(UAObserveSlot(&observation, record, encoded),
                                        record, expectedRestoreStamp);
    if (rejection != nil) {
        return rejection;
    }
    if (!mayCommit()) {
        return UARecordedResult(@"authorization_revoked", record, ECANCELED, false);
    }
    if (renameatx_np(slot, PayloadName, applicationsFD, name, RENAME_EXCL) != 0) {
        failure = errno;
        // A filesystem error can leave completion uncertain. The durable
        // intent and the expected identity let a later query reconcile it.
        return UARecordedResult(failure == EEXIST ? @"destination_occupied" : @"ambiguous",
                                record, failure, failure == EEXIST);
    }
    if (UARecordEntryAt(applicationsFD, name, observation.slotEntry.st_dev,
                        record[@"bundle_identity"], NULL)
        != UAEntryExpected) {
        return UARecordedResult(@"ambiguous", record, ESTALE, false);
    }
    if (fsync(slot) != 0 || fsync(applicationsFD) != 0) {
        return UARecordedResult(@"ambiguous", record, errno, false);
    }
    struct timespec completed;
    failure = UAPublishMarker(slot, observation.slotEntry.st_dev, RestoredMarker, &completed);
    if (failure != 0) {
        return UARecordedResult(@"ambiguous", record, failure, false);
    }
    if (!UARefreshOperationDirectories(&observation, uid, operationID)
        || !UARecordStillMatches(&observation, locked)
        || UARecordEntryAt(applicationsFD, name, observation.slotEntry.st_dev,
                           record[@"bundle_identity"], NULL) != UAEntryExpected) {
        return UARecordedResult(@"ambiguous", record, ESTALE, false);
    }
    return UAResultWithCompletion(UARecordedResult(@"restored", record, 0, false),
                                  @"restore_completed_at_epoch_seconds", &completed);
}
