#import "bundle_exclusion.h"
#import <Security/Security.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { CodeDirectoryHashBytes = 20 };

static bool UASameTime(struct timespec first, struct timespec second) {
    return first.tv_sec == second.tv_sec && first.tv_nsec == second.tv_nsec;
}

static bool UASameSignedRoot(const struct stat *expected, const struct stat *entry) {
    return S_ISDIR(entry->st_mode) && entry->st_dev == expected->st_dev
        && entry->st_ino == expected->st_ino && entry->st_mode == expected->st_mode
        && entry->st_uid == expected->st_uid && entry->st_gid == expected->st_gid
        && entry->st_flags == expected->st_flags
        && UASameTime(entry->st_birthtimespec, expected->st_birthtimespec)
        && UASameTime(entry->st_ctimespec, expected->st_ctimespec)
        && UASameTime(entry->st_mtimespec, expected->st_mtimespec);
}

static bool UAStillNamesSignedRoot(int applications, int bundle, const char *name,
                                   const struct stat *expected) {
    int live = open("/Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (live < 0) {
        return false;
    }
    struct stat liveParent, reviewedParent;
    bool sameParent = fstat(live, &liveParent) == 0 && fstat(applications, &reviewedParent) == 0
        && liveParent.st_dev == reviewedParent.st_dev && liveParent.st_ino == reviewedParent.st_ino
        && UASameTime(liveParent.st_birthtimespec, reviewedParent.st_birthtimespec);
    close(live);
    struct stat opened, named;
    return sameParent && fstat(bundle, &opened) == 0 && UASameSignedRoot(expected, &opened)
        && fstatat(applications, name, &named, AT_SYMLINK_NOFOLLOW) == 0
        && UASameSignedRoot(expected, &named);
}

static NSData *UAReadCodeDirectoryHash(NSURL *url, NSString *identifier) {
    SecRequirementRef requirement = NULL;
    // Restrict this path to certificate-signed standalone distributions.
    CFStringRef expression = CFSTR("anchor apple generic"
        " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
        " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists");
    if (SecRequirementCreateWithString(expression, kSecCSDefaultFlags, &requirement) != errSecSuccess) {
        return nil;
    }
    SecStaticCodeRef code = NULL;
    OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags, &code);
    if (status != errSecSuccess || code == NULL) {
        CFRelease(requirement);
        return nil;
    }
    SecCSFlags flags = kSecCSCheckAllArchitectures | kSecCSCheckNestedCode | kSecCSStrictValidate
        | kSecCSRestrictSymlinks | kSecCSRestrictSidebandData | kSecCSNoNetworkAccess;
    status = SecStaticCodeCheckValidity(code, flags, requirement);
    CFRelease(requirement);
    CFDictionaryRef signing = NULL;
    if (status == errSecSuccess) {
        status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &signing);
    }
    CFRelease(code);
    NSDictionary *details = CFBridgingRelease(signing);
    if (status != errSecSuccess
        || ![identifier isEqual:details[(__bridge NSString *)kSecCodeInfoIdentifier]]) {
        return nil;
    }
    id digest = details[(__bridge NSString *)kSecCodeInfoUnique];
    if (![digest isKindOfClass:NSData.class] || [digest length] != CodeDirectoryHashBytes) {
        return nil;
    }
    return digest;
}

int UACheckStandaloneBundleSignature(NSString *basename, NSString *bundleIdentifier,
                                     int applicationsDescriptor, int bundleDescriptor,
                                     NSData **codeDirectoryHash) {
    *codeDirectoryHash = nil;
    const char *name = basename.fileSystemRepresentation;
    if (name == NULL || name[0] == '.' || strchr(name, '/') != NULL) {
        return EINVAL;
    }
    struct stat before;
    if (fstat(bundleDescriptor, &before) != 0
        || !UAStillNamesSignedRoot(applicationsDescriptor, bundleDescriptor, name, &before)) {
        return ESTALE;
    }
    // The signing API uses a URL. Reject links anywhere in the protected
    // tree before handing it a path so validation cannot walk through them.
    int status = UACheckProtectedStandaloneBundleTree(bundleDescriptor);
    if (status != 0) {
        return status;
    }
    NSString *path = [@"/Applications" stringByAppendingPathComponent:basename];
    NSURL *url = [NSURL fileURLWithPath:path isDirectory:YES];
    NSData *digest = UAReadCodeDirectoryHash(url, bundleIdentifier);
    if (digest == nil) {
        return EACCES;
    }
    if (!UAStillNamesSignedRoot(applicationsDescriptor, bundleDescriptor, name, &before)) {
        return ESTALE;
    }
    *codeDirectoryHash = digest;
    return 0;
}
