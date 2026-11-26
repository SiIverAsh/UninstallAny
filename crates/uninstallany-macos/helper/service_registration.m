#import "protocol.h"
#import <Security/Security.h>
#import <ServiceManagement/ServiceManagement.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    UATeamLength = 10,
    UAMaxDaemonPlistBytes = 16384,
};

static const int DirectoryFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
static const char HelperFilename[] = "UninstallAnyPrivilegedHelper";

typedef struct {
    struct stat bundle;
    struct stat helper;
    struct stat plist;
} UAServiceFiles;

static void UACloseServiceFD(int *descriptor) {
    if (*descriptor >= 0) {
        int failure = errno;
        close(*descriptor);
        errno = failure;
    }
}

static BOOL UASameTime(struct timespec first, struct timespec second) {
    return first.tv_sec == second.tv_sec && first.tv_nsec == second.tv_nsec;
}

static BOOL UASameFile(const struct stat *first, const struct stat *second) {
    return first->st_dev == second->st_dev && first->st_ino == second->st_ino
        && first->st_mode == second->st_mode && first->st_uid == second->st_uid
        && first->st_gid == second->st_gid && first->st_nlink == second->st_nlink
        && first->st_size == second->st_size && first->st_flags == second->st_flags
        && UASameTime(first->st_birthtimespec, second->st_birthtimespec)
        && UASameTime(first->st_ctimespec, second->st_ctimespec)
        && UASameTime(first->st_mtimespec, second->st_mtimespec);
}

static BOOL UASameServiceFiles(const UAServiceFiles *first, const UAServiceFiles *second) {
    return UASameFile(&first->bundle, &second->bundle)
        && UASameFile(&first->helper, &second->helper)
        && UASameFile(&first->plist, &second->plist);
}

static int UAOpenBundleAtURL(NSURL *url) {
    NSArray<NSString *> *components = url.path.pathComponents;
    if (!url.isFileURL || components.count < 2 || ![components.firstObject isEqualToString:@"/"]
        || [url.pathExtension caseInsensitiveCompare:@"app"] != NSOrderedSame) {
        errno = ENOENT;
        return -1;
    }
    int descriptor __attribute__((cleanup(UACloseServiceFD))) = open("/", DirectoryFlags);
    if (descriptor < 0) {
        return -1;
    }
    // Open each component from the held parent. A symlink anywhere in the
    // installation path would make the later path-based checks ambiguous.
    for (NSUInteger index = 1; index < components.count; ++index) {
        const char *name = components[index].fileSystemRepresentation;
        if (name == NULL || name[0] == '\0' || strchr(name, '/') != NULL
            || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            errno = EINVAL;
            return -1;
        }
        int next = openat(descriptor, name, DirectoryFlags);
        if (next < 0) {
            return -1;
        }
        UACloseServiceFD(&descriptor);
        descriptor = next;
    }
    int bundle = descriptor;
    descriptor = -1;
    return bundle;
}

static int UAOpenServiceFile(int parent, const char *name, int mode, struct stat *snapshot) {
    struct stat named;
    if (fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    if (!S_ISREG(named.st_mode) || named.st_nlink != 1) {
        errno = EACCES;
        return -1;
    }
    int descriptor __attribute__((cleanup(UACloseServiceFD))) =
        openat(parent, name, mode | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, snapshot) != 0) {
        return -1;
    }
    if (!UASameFile(&named, snapshot)) {
        errno = ESTALE;
        return -1;
    }
    int result = descriptor;
    descriptor = -1;
    return result;
}

static int UAOpenServiceDirectory(int parent, const char *name, dev_t device) {
    int descriptor __attribute__((cleanup(UACloseServiceFD))) = openat(parent, name, DirectoryFlags);
    struct stat entry;
    if (descriptor < 0 || fstat(descriptor, &entry) != 0) {
        return -1;
    }
    if (entry.st_dev != device) {
        errno = EXDEV;
        return -1;
    }
    int result = descriptor;
    descriptor = -1;
    return result;
}

static NSString *UAHelperProgram(void) {
    return [@"Contents/MacOS" stringByAppendingPathComponent:
        [NSString stringWithUTF8String:HelperFilename]];
}

static int UACheckDaemonPlist(int descriptor, const struct stat *snapshot) {
    if (snapshot->st_size <= 0 || snapshot->st_size > UAMaxDaemonPlistBytes) {
        return EINVAL;
    }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)snapshot->st_size];
    uint8_t *bytes = data.mutableBytes;
    for (NSUInteger offset = 0; offset < data.length;) {
        ssize_t count = pread(descriptor, bytes + offset, data.length - offset, (off_t)offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return count == 0 ? ESTALE : errno;
        }
        offset += (NSUInteger)count;
    }
    struct stat after;
    if (fstat(descriptor, &after) != 0) {
        return errno;
    }
    if (!UASameFile(snapshot, &after)) {
        return ESTALE;
    }
    id value = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable
                                                          format:NULL error:NULL];
    if (![value isKindOfClass:NSDictionary.class]) {
        return EINVAL;
    }
    NSDictionary *plist = value;
    id services = plist[@"MachServices"];
    // An inner Developer ID signature does not authorize alternative
    // launchd arguments or additional Mach service names.
    if (plist.count != 3 || ![UA_HELPER_SIGNING_ID isEqual:plist[@"Label"]]
        || ![UAHelperProgram() isEqual:plist[@"BundleProgram"]]
        || ![services isKindOfClass:NSDictionary.class] || [services count] != 1
        || (__bridge CFTypeRef)services[UA_MACH_SERVICE] != kCFBooleanTrue) {
        return EINVAL;
    }
    return 0;
}

static int UAReadServiceFiles(NSURL *bundleURL, UAServiceFiles *files) {
    int bundle __attribute__((cleanup(UACloseServiceFD))) = UAOpenBundleAtURL(bundleURL);
    if (bundle < 0 || fstat(bundle, &files->bundle) != 0) {
        return errno;
    }
    struct statfs mount;
    if (fstatfs(bundle, &mount) != 0) {
        return errno;
    }
    if ((mount.f_flags & MNT_LOCAL) == 0) {
        return ENOTSUP;
    }
    // The bundle may be installed on a local volume, but its signed helper
    // and launch metadata must not be shadows from another mounted tree.
    dev_t device = files->bundle.st_dev;
    int contents __attribute__((cleanup(UACloseServiceFD))) =
        UAOpenServiceDirectory(bundle, "Contents", device);
    if (contents < 0) {
        return errno;
    }
    int executables __attribute__((cleanup(UACloseServiceFD))) =
        UAOpenServiceDirectory(contents, "MacOS", device);
    if (executables < 0) {
        return errno;
    }
    int helper __attribute__((cleanup(UACloseServiceFD))) =
        UAOpenServiceFile(executables, HelperFilename, O_EVTONLY, &files->helper);
    if (helper < 0) {
        return errno;
    }
    if (files->helper.st_dev != device) {
        return EXDEV;
    }
    if ((files->helper.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
        return EACCES;
    }
    int library __attribute__((cleanup(UACloseServiceFD))) =
        UAOpenServiceDirectory(contents, "Library", device);
    if (library < 0) {
        return errno;
    }
    int daemons __attribute__((cleanup(UACloseServiceFD))) =
        UAOpenServiceDirectory(library, "LaunchDaemons", device);
    if (daemons < 0) {
        return errno;
    }
    int plist __attribute__((cleanup(UACloseServiceFD))) =
        UAOpenServiceFile(daemons, UA_DAEMON_PLIST.fileSystemRepresentation, O_RDONLY, &files->plist);
    if (plist < 0) {
        return errno;
    }
    if (files->plist.st_dev != device) {
        return EXDEV;
    }
    return UACheckDaemonPlist(plist, &files->plist);
}

static NSString *UAServiceTeam(const char *team) {
    if (team == NULL || strnlen(team, UATeamLength + 1) != UATeamLength) {
        return nil;
    }
    for (size_t index = 0; index < UATeamLength; ++index) {
        char character = team[index];
        if (!((character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9'))) {
            return nil;
        }
    }
    return [NSString stringWithUTF8String:team];
}

static SecRequirementRef UACopyServiceRequirement(NSString *identifier, NSString *team) {
    NSString *expression = [NSString stringWithFormat:
        @"anchor apple generic and identifier \"%@\""
         @" and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
         @" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
         @" and certificate leaf[subject.OU] = \"%@\""
         @" and !(entitlement[com.apple.security.get-task-allow] exists)"
         @" and !(entitlement[com.apple.security.cs.disable-library-validation] exists)"
         @" and !(entitlement[com.apple.security.cs.allow-dyld-environment-variables] exists)",
        identifier, team];
    SecRequirementRef requirement = NULL;
    OSStatus status = SecRequirementCreateWithString((__bridge CFStringRef)expression,
                                                     kSecCSDefaultFlags, &requirement);
    return status == errSecSuccess ? requirement : NULL;
}

static NSData *UAServiceRuntimeIdentity(SecStaticCodeRef code, SecCSFlags flags) {
    CFDictionaryRef information = NULL;
    if (SecCodeCopySigningInformation(code, kSecCSSigningInformation | flags, &information)
        != errSecSuccess || information == NULL) {
        return nil;
    }
    NSDictionary *signing = CFBridgingRelease(information);
    id signatureFlags = signing[(__bridge NSString *)kSecCodeInfoFlags];
    if (![signatureFlags isKindOfClass:NSNumber.class]
        || ([signatureFlags unsignedIntValue] & kSecCodeSignatureRuntime) == 0) {
        return nil;
    }
    if ((flags & kSecCSDynamicInformation) != 0) {
        id dynamicStatus = signing[(__bridge NSString *)kSecCodeInfoStatus];
        if (![dynamicStatus isKindOfClass:NSNumber.class]
            || ([dynamicStatus unsignedIntValue] & kSecCodeStatusDebugged) != 0) {
            return nil;
        }
    }
    id identity = signing[(__bridge NSString *)kSecCodeInfoUnique];
    return [identity isKindOfClass:NSData.class] && [identity length] > 0 ? identity : nil;
}

static NSData *UAServiceCurrentIdentity(SecRequirementRef requirement) {
    SecCodeRef code = NULL;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &code) != errSecSuccess || code == NULL) {
        return nil;
    }
    NSData *identity = nil;
    if (SecCodeCheckValidity(code, kSecCSNoNetworkAccess, requirement) == errSecSuccess) {
        identity = UAServiceRuntimeIdentity(code, kSecCSDynamicInformation);
    }
    CFRelease(code);
    return identity;
}

static NSData *UAServiceDiskIdentity(NSURL *url, SecRequirementRef requirement) {
    SecStaticCodeRef code = NULL;
    if (SecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags, &code) != errSecSuccess
        || code == NULL) {
        return nil;
    }
    SecCSFlags flags = kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode
        | kSecCSRestrictSymlinks | kSecCSRestrictSidebandData | kSecCSNoNetworkAccess;
    NSData *identity = nil;
    if (SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess) {
        identity = UAServiceRuntimeIdentity(code, kSecCSDefaultFlags);
    }
    CFRelease(code);
    return identity;
}

static BOOL UACheckServiceSignatures(NSURL *bundleURL, NSString *team) {
    SecRequirementRef requirement = UACopyServiceRequirement(UA_GUI_SIGNING_ID, team);
    if (requirement == NULL) {
        return NO;
    }
    NSData *running = UAServiceCurrentIdentity(requirement);
    NSData *installed = running == nil ? nil : UAServiceDiskIdentity(bundleURL, requirement);
    CFRelease(requirement);
    if (![running isEqual:installed]) {
        return NO;
    }

    requirement = UACopyServiceRequirement(UA_HELPER_SIGNING_ID, team);
    if (requirement == NULL) {
        return NO;
    }
    NSString *helperPath = [bundleURL.path stringByAppendingPathComponent:UAHelperProgram()];
    NSURL *helper = [NSURL fileURLWithPath:helperPath isDirectory:NO];
    BOOL valid = UAServiceDiskIdentity(helper, requirement) != nil;
    CFRelease(requirement);
    return valid;
}

API_AVAILABLE(macos(13.0))
static int UAGetVerifiedService(const char *team, SMAppService **service, NSURL **url,
                                UAServiceFiles *reviewedFiles) {
    NSBundle *bundle = NSBundle.mainBundle;
    if (bundle.bundleIdentifier == nil) {
        return ENOENT;
    }
    if (![bundle.bundleIdentifier isEqualToString:UA_GUI_SIGNING_ID]) {
        return EACCES;
    }
    NSURL *bundleURL = bundle.bundleURL;
    int status = UAReadServiceFiles(bundleURL, reviewedFiles);
    if (status != 0) {
        return status;
    }
    NSString *identifier = UAServiceTeam(team);
    if (identifier == nil || !UACheckServiceSignatures(bundleURL, identifier)) {
        return EACCES;
    }
    UAServiceFiles current;
    status = UAReadServiceFiles(bundleURL, &current);
    if (status != 0 || !UASameServiceFiles(reviewedFiles, &current)) {
        return status == 0 ? ESTALE : status;
    }
    *service = [SMAppService daemonServiceWithPlistName:UA_DAEMON_PLIST];
    *url = bundleURL;
    return *service != nil ? 0 : EIO;
}

API_AVAILABLE(macos(13.0))
static int UACopyHelperServiceState(SMAppService *service, int32_t *state) {
    switch (service.status) {
        case SMAppServiceStatusNotRegistered:
            *state = UA_SERVICE_NOT_REGISTERED;
            return 0;
        case SMAppServiceStatusEnabled:
            *state = UA_SERVICE_ENABLED;
            return 0;
        case SMAppServiceStatusRequiresApproval:
            *state = UA_SERVICE_REQUIRES_APPROVAL;
            return 0;
        case SMAppServiceStatusNotFound:
            *state = UA_SERVICE_NOT_FOUND;
            return 0;
        default:
            return EIO;
    }
}

static int UARegistrationError(NSError *error) {
    if ([error.domain isEqualToString:NSPOSIXErrorDomain]
        && error.code > 0 && error.code <= INT32_MAX) {
        return (int32_t)error.code;
    }
    // The framework exposes this error domain constant starting with macOS 15.
    if (![error.domain isEqualToString:@"SMAppServiceErrorDomain"]) {
        return EIO;
    }
    switch (error.code) {
        case EPERM:
        case kSMErrorInvalidSignature:
        case kSMErrorAuthorizationFailure:
        case kSMErrorJobMustBeEnabled:
        case kSMErrorLaunchDeniedByUser:
            return EACCES;
        case kSMErrorJobNotFound:
        case kSMErrorJobPlistNotFound:
            return ENOENT;
        case kSMErrorToolNotValid:
        case kSMErrorInvalidPlist:
            return EINVAL;
        case kSMErrorServiceUnavailable:
            return EAGAIN;
        case kSMErrorAlreadyRegistered:
            return EALREADY;
        default:
            return EIO;
    }
}

int32_t UAQueryHelperService(const char *team, int32_t *serviceState) {
    if (serviceState == NULL) {
        return EINVAL;
    }
    *serviceState = UA_SERVICE_NOT_FOUND;
    if (@available(macOS 13.0, *)) {
        @autoreleasepool {
            @try {
                SMAppService *service = nil;
                NSURL *url = nil;
                UAServiceFiles files;
                int status = UAGetVerifiedService(team, &service, &url, &files);
                if (status == ENOENT) {
                    return 0;
                }
                return status == 0 ? UACopyHelperServiceState(service, serviceState) : status;
            } @catch (NSException *exception) {
                (void)exception;
                return EIO;
            }
        }
    }
    return ENOTSUP;
}

int32_t UARegisterHelperService(const char *team, int32_t *serviceState) {
    if (serviceState == NULL) {
        return EINVAL;
    }
    *serviceState = UA_SERVICE_NOT_FOUND;
    if (@available(macOS 13.0, *)) {
        @autoreleasepool {
            @try {
                @synchronized (SMAppService.class) {
                    SMAppService *service = nil;
                    NSURL *url = nil;
                    UAServiceFiles reviewed;
                    int status = UAGetVerifiedService(team, &service, &url, &reviewed);
                    if (status != 0) {
                        return status;
                    }
                    status = UACopyHelperServiceState(service, serviceState);
                    if (status != 0 || *serviceState != UA_SERVICE_NOT_REGISTERED) {
                        return status;
                    }
                    UAServiceFiles current;
                    status = UAReadServiceFiles(url, &current);
                    if (status != 0 || !UASameServiceFiles(&reviewed, &current)) {
                        return status == 0 ? ESTALE : status;
                    }
                    NSError *error = nil;
                    BOOL registered = [service registerAndReturnError:&error];
                    // macOS can queue admin approval even when the call
                    // returns an error. Report the observed state first.
                    status = UACopyHelperServiceState(service, serviceState);
                    if (status != 0 || registered || *serviceState == UA_SERVICE_ENABLED
                        || *serviceState == UA_SERVICE_REQUIRES_APPROVAL) {
                        return status;
                    }
                    return UARegistrationError(error);
                }
            } @catch (NSException *exception) {
                (void)exception;
                return EIO;
            }
        }
    }
    return ENOTSUP;
}
