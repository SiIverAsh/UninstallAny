#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include <CommonCrypto/CommonDigest.h>
#include <bsm/audit.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#import "bundle_exclusion.h"
#import "installer_ownership.h"
#import "isolated_bundle.h"
#import "protocol.h"

static const NSUInteger MaxAddressBytes = 255;
static const NSUInteger MaxReplyBytes = 4096;
static const NSUInteger TeamIdentifierLength = 10;
static const uint64_t AuthorizationWindow = UA_QUARANTINE_AUTHORIZATION_SECONDS * NSEC_PER_SEC;
static const uint64_t StandalonePreviewWindow = UA_STANDALONE_PREVIEW_SECONDS * NSEC_PER_SEC;
static const uint64_t InstallerReceiptWindow = 30 * NSEC_PER_SEC;
static NSString *const InvalidRequest = @"invalid-request";
static NSString *const UnauthorizedPeer = @"unauthorized-peer";
static NSString *const InspectionFailed = @"inspection-failed";

static BOOL IsASCIIAlphanumeric(uint8_t byte) {
    return (byte >= '0' && byte <= '9') ||
           (byte >= 'A' && byte <= 'Z') ||
           (byte >= 'a' && byte <= 'z');
}

static NSData *AddressBytes(NSString *value) {
    if (![value isKindOfClass:NSString.class] ||
        value.length == 0 || value.length > MaxAddressBytes) {
        return nil;
    }
    NSData *bytes = [value dataUsingEncoding:NSUTF8StringEncoding];
    return bytes.length > 0 && bytes.length <= MaxAddressBytes ? bytes : nil;
}

static BOOL IsApplicationBasename(NSString *name) {
    NSData *data = AddressBytes(name);
    const uint8_t *bytes = data.bytes;
    if (data.length <= 4 || bytes[0] == '.') {
        return NO;
    }
    for (NSUInteger index = 0; index < data.length; index++) {
        uint8_t byte = bytes[index];
        if (byte < 0x20 || byte == 0x7f || byte == '/' || byte == '\\') {
            return NO;
        }
    }
    const uint8_t *extension = bytes + data.length - 4;
    return extension[0] == '.' &&
           (extension[1] == 'a' || extension[1] == 'A') &&
           (extension[2] == 'p' || extension[2] == 'P') &&
           (extension[3] == 'p' || extension[3] == 'P');
}

static BOOL IsBundleIdentifier(NSString *identifier) {
    NSData *data = AddressBytes(identifier);
    if (data == nil) {
        return NO;
    }
    const uint8_t *bytes = data.bytes;
    BOOL hasSeparator = NO;
    BOOL hasComponent = NO;
    for (NSUInteger index = 0; index < data.length; index++) {
        uint8_t byte = bytes[index];
        if (byte == '.') {
            if (!hasComponent) {
                return NO;
            }
            hasSeparator = YES;
            hasComponent = NO;
        } else if (IsASCIIAlphanumeric(byte) || byte == '-' || byte == '_') {
            hasComponent = YES;
        } else {
            return NO;
        }
    }
    return hasSeparator && hasComponent;
}

static BOOL IsTeamIdentifier(NSString *identifier) {
    NSData *data = AddressBytes(identifier);
    if (data.length != TeamIdentifierLength) {
        return NO;
    }
    const uint8_t *bytes = data.bytes;
    for (NSUInteger index = 0; index < data.length; index++) {
        uint8_t byte = bytes[index];
        if ((byte < '0' || byte > '9') && (byte < 'A' || byte > 'Z')) {
            return NO;
        }
    }
    return YES;
}

static BOOL IsRootStamp(NSString *value) {
    NSData *data = AddressBytes(value);
    if (data.length != UA_ROOT_STAMP_LENGTH) {
        return NO;
    }
    const uint8_t *bytes = data.bytes;
    for (NSUInteger index = 0; index < data.length; index++) {
        uint8_t byte = bytes[index];
        if ((byte < '0' || byte > '9') && (byte < 'a' || byte > 'f')) {
            return NO;
        }
    }
    return YES;
}

static BOOL MatchesReviewedRoot(NSString *basename, NSString *identifier, NSString *stamp) {
    UAReviewedBundle reviewed __attribute__((cleanup(UACloseReviewedApplicationBundle)));
    return UAOpenReviewedApplicationBundle(basename, identifier, stamp, &reviewed, NULL) == 0;
}

static int InstallerReceiptStatus(NSString *basename, NSString *executable, uint64_t upperDeadline) {
    uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + InstallerReceiptWindow;
    if (upperDeadline < deadline) {
        deadline = upperDeadline;
    }
    BOOL claimed = NO;
    int status = UACheckInstallerBundleOwnership(basename, executable, deadline, &claimed);
    if (status != 0) {
        return status;
    }
    return claimed ? EEXIST : 0;
}

static int CheckReviewedInstallerReceipts(NSString *basename, NSString *identifier,
                                          NSString *stamp, uint64_t authorizationDeadline) {
    UAReviewedBundle reviewed __attribute__((cleanup(UACloseReviewedApplicationBundle)));
    NSString *executable = nil;
    int status = UAOpenReviewedApplicationBundle(basename, identifier, stamp, &reviewed, &executable);
    if (status == 0) {
        status = InstallerReceiptStatus(basename, executable, authorizationDeadline);
    }
    return status == 0 && !MatchesReviewedRoot(basename, identifier, stamp) ? ESTALE : status;
}

static NSString *HexStamp(const uint8_t bytes[CC_SHA256_DIGEST_LENGTH]) {
    const char *hex = "0123456789abcdef";
    char encoded[UA_ROOT_STAMP_LENGTH];
    for (size_t index = 0; index < CC_SHA256_DIGEST_LENGTH; index++) {
        encoded[2 * index] = hex[bytes[index] >> 4];
        encoded[2 * index + 1] = hex[bytes[index] & 15];
    }
    return [[NSString alloc] initWithBytes:encoded length:sizeof(encoded) encoding:NSASCIIStringEncoding];
}

static NSString *NewAuthorizationChallenge(void) {
    uint8_t bytes[CC_SHA256_DIGEST_LENGTH];
    return SecRandomCopyBytes(kSecRandomDefault, sizeof(bytes), bytes) == errSecSuccess
        ? HexStamp(bytes) : nil;
}

static NSString *StandaloneReviewStamp(NSString *rootStamp, NSData *seal) {
    static const char Domain[] = "UninstallAny.standalone-quarantine.v1";
    NSData *root = [rootStamp dataUsingEncoding:NSASCIIStringEncoding];
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    CC_SHA256_Update(&hash, Domain, sizeof(Domain));
    CC_SHA256_Update(&hash, root.bytes, (CC_LONG)root.length);
    CC_SHA256_Update(&hash, seal.bytes, (CC_LONG)seal.length);
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &hash);
    return HexStamp(digest);
}

static int32_t CheckStandaloneReview(NSString *basename, NSString *identifier, uint64_t deadline,
                                     UAReviewedBundle *opened, NSDictionary **evidence) {
    *opened = (UAReviewedBundle){.applications = -1, .bundle = -1};
    NSString *description = UAInspectApplicationBundle(basename, identifier);
    NSData *encoded = [description dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *descriptionFields = [NSJSONSerialization JSONObjectWithData:encoded
                                                                      options:0 error:NULL];
    NSString *rootStamp = descriptionFields[@"root_stamp"];
    if (![descriptionFields[@"status"] isEqualToString:@"verified"] || !IsRootStamp(rootStamp)) {
        return ENOTSUP;
    }
    NSString *executable = nil;
    int status = UAOpenReviewedApplicationBundle(basename, identifier, rootStamp, opened, &executable);
    if (status == 0) {
        status = UACheckStandardCaskrooms();
    }
    if (status == 0) {
        status = UACheckSystemBundleBackground(basename, identifier, opened->bundle);
    }
    if (status == 0) {
        status = InstallerReceiptStatus(basename, executable, deadline);
    }
    NSData *seal = nil;
    if (status == 0) {
        status = UACheckStandaloneBundleSignature(basename, identifier, opened->applications,
                                                  opened->bundle, &seal);
    }
    if (status == 0) {
        status = UACheckSystemBundleActivity(basename, opened->bundle);
    }
    if (status != 0) {
        return status;
    }
    if (clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) >= deadline) {
        return ETIMEDOUT;
    }
    if (!MatchesReviewedRoot(basename, identifier, rootStamp)) {
        return ESTALE;
    }
    NSString *stamp = StandaloneReviewStamp(rootStamp, seal);
    if (stamp == nil) {
        return EIO;
    }
    *evidence = @{@"root_stamp": rootStamp, @"review_stamp": stamp};
    return 0;
}

static dispatch_semaphore_t BundleAuthorizationGate(void) {
    static dispatch_semaphore_t gate;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gate = dispatch_semaphore_create(1);
    });
    return gate;
}

static int32_t RecordedError(NSDictionary *result) {
    int32_t failure = [result[@"errno"] intValue];
    return failure > 0 ? failure : ESTALE;
}

static NSString *BoundedResultJSON(NSDictionary *result, NSUInteger maximumBytes) {
    if (result == nil) {
        return nil;
    }
    NSData *bytes = [NSJSONSerialization dataWithJSONObject:result options:0 error:NULL];
    if (bytes.length == 0 || bytes.length > maximumBytes) {
        return nil;
    }
    return [[NSString alloc] initWithData:bytes encoding:NSUTF8StringEncoding];
}

static NSString *QuarantineResultJSON(NSDictionary *result) {
    return BoundedResultJSON(result, MaxReplyBytes);
}

static BOOL IsReviewedBackupTarget(NSDictionary *record) {
    NSString *path = record[@"original_path"];
    NSString *basename = path.lastPathComponent;
    return IsApplicationBasename(basename) && IsBundleIdentifier(record[@"bundle_id"])
        && [path isEqualToString:[@"/Applications" stringByAppendingPathComponent:basename]];
}

static int32_t ReviewedRestoreTarget(uid_t uid, NSString *operationID, NSString *stamp,
                                     NSDictionary **target) {
    NSDictionary *result = UAQueryBundleQuarantine(uid, operationID);
    if (![result[@"status"] isEqualToString:@"quarantined"]) {
        return RecordedError(result);
    }
    NSDictionary *record = result[@"record"];
    if ([record[@"destination_occupied"] boolValue]) {
        return EEXIST;
    }
    if (![record[@"restore_stamp"] isEqualToString:stamp]
        || !IsReviewedBackupTarget(record)) {
        return ESTALE;
    }
    if (target != NULL) {
        *target = record;
    }
    return 0;
}

static int32_t ReviewedExpiryTarget(uid_t uid, NSString *operationID, NSString *stamp,
                                    NSDictionary **target) {
    NSDictionary *review = nil;
    int status = UAPreviewBundleExpiry(uid, operationID, &review);
    if (status != 0) {
        return status;
    }
    if (![stamp isEqual:review[@"expiry_stamp"]] || !IsReviewedBackupTarget(review)) {
        return ESTALE;
    }
    *target = review;
    return 0;
}

static NSString *SigningRequirement(NSString *identifier, NSString *team) {
    // Bind the exact product role and Apple-issued Developer ID team.
    return [NSString stringWithFormat:
        @"anchor apple generic and identifier \"%@\" "
         @"and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
         @"and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
         @"and certificate leaf[subject.OU] = \"%@\" "
         @"and !(entitlement[com.apple.security.get-task-allow] exists) "
         @"and !(entitlement[com.apple.security.cs.disable-library-validation] exists) "
         @"and !(entitlement[com.apple.security.cs.allow-dyld-environment-variables] exists)",
        identifier, team];
}

static SecRequirementRef CopyRequirement(NSString *expression) {
    SecRequirementRef requirement = NULL;
    if (SecRequirementCreateWithString((__bridge CFStringRef)expression,
                                       kSecCSDefaultFlags, &requirement) != errSecSuccess) {
        return NULL;
    }
    return requirement;
}

static NSString *VerifiedTeamForCode(SecCodeRef code) {
    // Reading signing information can evaluate certificate trust. Apply the
    // offline flag to this code object before deriving its Team ID.
    if (SecCodeCheckValidity(code, kSecCSNoNetworkAccess, NULL) != errSecSuccess) {
        return nil;
    }
    CFDictionaryRef rawSigningInfo = NULL;
    SecCSFlags flags = kSecCSSigningInformation | kSecCSDynamicInformation;
    if (SecCodeCopySigningInformation(code, flags, &rawSigningInfo) != errSecSuccess ||
        rawSigningInfo == NULL) {
        return nil;
    }
    NSDictionary *info = CFBridgingRelease(rawSigningInfo);
    NSString *team = info[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
    NSNumber *signatureFlags = info[(__bridge NSString *)kSecCodeInfoFlags];
    NSNumber *dynamicStatus = info[(__bridge NSString *)kSecCodeInfoStatus];
    if (!IsTeamIdentifier(team) ||
        ![signatureFlags isKindOfClass:NSNumber.class] ||
        (signatureFlags.unsignedIntValue & kSecCodeSignatureRuntime) == 0 ||
        ![dynamicStatus isKindOfClass:NSNumber.class] ||
        (dynamicStatus.unsignedIntValue & kSecCodeStatusDebugged) != 0) {
        return nil;
    }
    NSString *selfRequirement = SigningRequirement(UA_HELPER_SIGNING_ID, team);
    SecRequirementRef requirement = CopyRequirement(selfRequirement);
    if (requirement == NULL) {
        return nil;
    }
    OSStatus status = SecCodeCheckValidity(code, kSecCSNoNetworkAccess, requirement);
    CFRelease(requirement);
    return status == errSecSuccess ? team : nil;
}

static NSString *VerifiedHelperTeam(void) {
    SecCodeRef selfCode = NULL;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &selfCode) != errSecSuccess ||
        selfCode == NULL) {
        return nil;
    }
    NSString *team = VerifiedTeamForCode(selfCode);
    CFRelease(selfCode);
    return team;
}

typedef NS_ENUM(NSUInteger, UASessionState) {
    SessionWaitingForProbe,
    SessionReadyForInspection,
    SessionWaitingForQuarantineAuthorization,
    SessionWaitingForStandaloneQuarantineAuthorization,
    SessionWaitingForRestoreAuthorization,
    SessionWaitingForExpiryAuthorization,
    SessionFinished,
};

@interface UAInspectionSession : NSObject <UAHousekeepingHelper>
- (instancetype)initWithConnection:(NSXPCConnection *)connection
                               uid:(uid_t)uid
                      auditSession:(au_asid_t)auditSession;
- (void)markDisconnected;
@end

@implementation UAInspectionSession {
    __weak NSXPCConnection *_connection;
    uid_t _uid;
    au_asid_t _auditSession;
    UASessionState _state;
    BOOL _disconnected;
    NSString *_quarantineBasename;
    NSString *_quarantineIdentifier;
    NSString *_quarantineStamp;
    NSString *_quarantineChallenge;
    uint64_t _quarantineDeadline;
    NSString *_standaloneOperationID;
    uint16_t _standaloneRetentionDays;
    NSString *_backupOperationID;
    NSString *_backupStamp;
    NSString *_backupChallenge;
    uint64_t _backupDeadline;
}

- (instancetype)initWithConnection:(NSXPCConnection *)connection
                               uid:(uid_t)uid
                      auditSession:(au_asid_t)auditSession {
    self = [super init];
    if (self != nil) {
        _connection = connection;
        _uid = uid;
        _auditSession = auditSession;
        _state = SessionWaitingForProbe;
    }
    return self;
}

- (BOOL)isBoundPeer {
    return [self isActivePeer:[NSXPCConnection currentConnection]];
}

- (BOOL)isActivePeer:(NSXPCConnection *)connection {
    @synchronized (self) {
        return !_disconnected && connection != nil && connection == _connection
            && connection.effectiveUserIdentifier == _uid
            && connection.auditSessionIdentifier == _auditSession;
    }
}

- (void)markDisconnected {
    @synchronized (self) {
        _disconnected = YES;
    }
}

- (BOOL)advanceFrom:(UASessionState)previous to:(UASessionState)next {
    if (![self isBoundPeer]) {
        return NO;
    }
    @synchronized (self) {
        if (_disconnected || _state != previous) {
            return NO;
        }
        _state = next;
        return YES;
    }
}

- (void)probeWithReply:(void (^)(NSString *))reply {
    if (reply != nil) {
        reply([self advanceFrom:SessionWaitingForProbe to:SessionReadyForInspection]
              ? UA_PROBE_REPLY : UnauthorizedPeer);
    }
}

- (void)inspectApplicationBundle:(NSString *)basename
                bundleIdentifier:(NSString *)bundleIdentifier
                           reply:(void (^)(NSString *))reply {
    if (reply == nil) {
        return;
    }
    if (![self advanceFrom:SessionReadyForInspection to:SessionFinished]) {
        reply(UnauthorizedPeer);
        return;
    }
    if (!IsApplicationBasename(basename) || !IsBundleIdentifier(bundleIdentifier)) {
        reply(InvalidRequest);
        return;
    }
    NSString *result = UAInspectApplicationBundle([basename copy], [bundleIdentifier copy]);
    NSUInteger length = [result lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    reply(length > 0 && length <= MaxReplyBytes ? result : InspectionFailed);
}

- (void)queryBundleQuarantine:(NSString *)operationID
                         reply:(void (^)(int32_t, NSString *))reply {
    if (reply == nil) {
        return;
    }
    if (![self advanceFrom:SessionReadyForInspection to:SessionFinished]) {
        reply(EACCES, nil);
        return;
    }
    if (AddressBytes(operationID).length != UA_OPERATION_ID_LENGTH) {
        reply(EINVAL, nil);
        return;
    }
    // The store is always selected by the authenticated peer's effective UID.
    NSDictionary *record = UAQueryBundleQuarantine(_uid, [operationID copy]);
    if ([record[@"status"] isEqualToString:@"invalid_request"]) {
        reply(EINVAL, nil);
        return;
    }
    NSString *result = QuarantineResultJSON(record);
    reply(result == nil ? EIO : 0, result);
}

- (void)listBundleQuarantineAfter:(NSString *)afterOperationID
                      catalogStamp:(NSString *)catalogStamp
                             reply:(void (^)(int32_t, NSString *))reply {
    if (reply == nil) {
        return;
    }
    if (![self advanceFrom:SessionReadyForInspection to:SessionFinished]) {
        reply(EACCES, nil);
        return;
    }
    BOOL isFirstPage = afterOperationID == nil && catalogStamp == nil;
    if (!isFirstPage && (AddressBytes(afterOperationID).length != UA_OPERATION_ID_LENGTH
        || !IsRootStamp(catalogStamp))) {
        reply(EINVAL, nil);
        return;
    }
    NSDictionary *page = nil;
    int32_t status = UAListBundleQuarantine(_uid, [afterOperationID copy], [catalogStamp copy], &page);
    if (status != 0) {
        reply(status, nil);
        return;
    }
    NSString *result = BoundedResultJSON(page, UA_QUARANTINE_PAGE_BYTES);
    reply(result == nil ? EIO : 0, result);
}

- (void)previewStandaloneQuarantine:(NSString *)basename
                    bundleIdentifier:(NSString *)bundleIdentifier
                               reply:(void (^)(int32_t, NSString *))reply {
    if (reply == nil) {
        return;
    }
    if (![self advanceFrom:SessionReadyForInspection to:SessionFinished]) {
        reply(EACCES, nil);
        return;
    }
    if (!IsApplicationBasename(basename) || !IsBundleIdentifier(bundleIdentifier)) {
        reply(EINVAL, nil);
        return;
    }
    dispatch_semaphore_t gate = BundleAuthorizationGate();
    if (dispatch_semaphore_wait(gate, DISPATCH_TIME_NOW) != 0) {
        reply(EBUSY, nil);
        return;
    }
    NSString *name = [basename copy];
    NSString *identifier = [bundleIdentifier copy];
    NSXPCConnection *peer = [NSXPCConnection currentConnection];
    uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + StandalonePreviewWindow;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            NSDictionary *evidence = nil;
            int32_t status = EACCES;
            @try {
                UAReviewedBundle opened __attribute__((cleanup(UACloseReviewedApplicationBundle))) =
                    {.applications = -1, .bundle = -1};
                if ([self isActivePeer:peer]) {
                    status = CheckStandaloneReview(name, identifier, deadline, &opened, &evidence);
                }
                if (status == 0 && ![self isActivePeer:peer]) {
                    status = EACCES;
                }
            } @catch (NSException *exception) {
                (void)exception;
                status = EIO;
            } @finally {
                dispatch_semaphore_signal(gate);
            }
            reply(status, status == 0 ? evidence[@"review_stamp"] : nil);
        }
    });
}

- (void)prepareStandaloneQuarantine:(NSString *)basename
                    bundleIdentifier:(NSString *)bundleIdentifier
                         operationID:(NSString *)operationID
                         reviewStamp:(NSString *)reviewStamp
                       retentionDays:(uint16_t)retentionDays
                               reply:(void (^)(int32_t, NSString *))reply {
    if (reply == nil) {
        return;
    }
    if (![self advanceFrom:SessionReadyForInspection to:SessionFinished]) {
        reply(EACCES, nil);
        return;
    }
    if (!IsApplicationBasename(basename) || !IsBundleIdentifier(bundleIdentifier)
        || AddressBytes(operationID).length != UA_OPERATION_ID_LENGTH || !IsRootStamp(reviewStamp)
        || retentionDays == 0) {
        reply(EINVAL, nil);
        return;
    }
    NSDictionary *record = UAQueryBundleQuarantine(_uid, operationID);
    if (![record[@"status"] isEqualToString:@"missing"]) {
        int32_t status = [record[@"status"] isEqualToString:@"store_unavailable"]
            ? RecordedError(record) : EEXIST;
        reply(status, nil);
        return;
    }
    NSString *challenge = NewAuthorizationChallenge();
    if (challenge == nil) {
        reply(EIO, nil);
        return;
    }
    @synchronized (self) {
        _standaloneOperationID = [operationID copy];
        _standaloneRetentionDays = retentionDays;
        _quarantineBasename = [basename copy];
        _quarantineIdentifier = [bundleIdentifier copy];
        _quarantineStamp = [reviewStamp copy];
        _quarantineChallenge = challenge;
        _quarantineDeadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + AuthorizationWindow;
        _state = SessionWaitingForStandaloneQuarantineAuthorization;
    }
    reply(0, challenge);
}

- (void)quarantineStandaloneWithAuthorization:(NSString *)ticket
                                  externalForm:(NSData *)externalForm
                                         reply:(void (^)(int32_t, NSString *))reply {
    if (reply == nil) {
        return;
    }
    if (![self advanceFrom:SessionWaitingForStandaloneQuarantineAuthorization to:SessionFinished]) {
        reply(EACCES, nil);
        return;
    }
    NSString *operationID = _standaloneOperationID;
    uint16_t retentionDays = _standaloneRetentionDays;
    NSString *name = _quarantineBasename;
    NSString *identifier = _quarantineIdentifier;
    NSString *stamp = _quarantineStamp;
    NSString *challenge = _quarantineChallenge;
    uint64_t deadline = _quarantineDeadline;
    _standaloneOperationID = nil;
    _standaloneRetentionDays = 0;
    _quarantineBasename = nil;
    _quarantineIdentifier = nil;
    _quarantineStamp = nil;
    _quarantineChallenge = nil;
    if (!IsRootStamp(ticket) || ![ticket isEqualToString:challenge]
        || ![externalForm isKindOfClass:NSData.class]
        || externalForm.length != sizeof(AuthorizationExternalForm)) {
        reply(EACCES, nil);
        return;
    }
    if (clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) >= deadline) {
        reply(ETIMEDOUT, nil);
        return;
    }
    NSXPCConnection *peer = [NSXPCConnection currentConnection];
    NSData *form = [externalForm copy];
    dispatch_semaphore_t gate = BundleAuthorizationGate();
    if (dispatch_semaphore_wait(gate, DISPATCH_TIME_NOW) != 0) {
        reply(EBUSY, nil);
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            BOOL (^mayCommit)(void) = ^BOOL {
                return [self isActivePeer:peer] && clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) < deadline;
            };
            NSString *response = nil;
            int32_t status = EACCES;
            BOOL stageStarted = NO;
            @try {
                UAReviewedBundle before __attribute__((cleanup(UACloseReviewedApplicationBundle))) =
                    {.applications = -1, .bundle = -1};
                NSDictionary *earlier = nil;
                if (mayCommit()) {
                    status = CheckStandaloneReview(name, identifier, deadline, &before, &earlier);
                }
                if (status == 0 && ![stamp isEqual:earlier[@"review_stamp"]]) {
                    status = ESTALE;
                }
                if (status == 0) {
                    status = mayCommit() ? UAEnsureBundleQuarantineRight() : EACCES;
                }
                if (status == 0) {
                    status = mayCommit() ? UAAuthenticateAndConsumeBundleQuarantineAuthorization(
                        form, name, identifier) : EACCES;
                }
                UAReviewedBundle after __attribute__((cleanup(UACloseReviewedApplicationBundle))) =
                    {.applications = -1, .bundle = -1};
                NSDictionary *latest = nil;
                if (status == 0) {
                    status = mayCommit() ? CheckStandaloneReview(name, identifier, deadline, &after, &latest)
                                         : EACCES;
                }
                if (status == 0 && ![stamp isEqual:latest[@"review_stamp"]]) {
                    status = ESTALE;
                }
                if (status == 0 && mayCommit()) {
                    stageStarted = YES;
                    NSDictionary *result = UAQuarantineVerifiedBundle(self->_uid, operationID,
                        after.applications, after.bundle, name, identifier, latest[@"root_stamp"],
                        retentionDays, mayCommit);
                    NSString *state = result[@"status"];
                    if ([state isEqualToString:@"quarantined"] || [state isEqualToString:@"ambiguous"]) {
                        response = QuarantineResultJSON(result);
                        status = response == nil ? UA_QUARANTINE_OUTCOME_UNKNOWN : 0;
                    } else if ([result[@"errno"] intValue] > 0) {
                        status = RecordedError(result);
                    } else {
                        status = UA_QUARANTINE_OUTCOME_UNKNOWN;
                    }
                } else if (status == 0) {
                    status = EACCES;
                }
            } @catch (NSException *exception) {
                (void)exception;
                status = stageStarted ? UA_QUARANTINE_OUTCOME_UNKNOWN : EIO;
            } @finally {
                dispatch_semaphore_signal(gate);
            }
            reply(status, response);
        }
    });
}

- (void)previewBundleExpiry:(NSString *)operationID
                       reply:(void (^)(int32_t, NSString *))reply {
    if (reply == nil) {
        return;
    }
    if (![self advanceFrom:SessionReadyForInspection to:SessionFinished]) {
        reply(EACCES, nil);
        return;
    }
    if (AddressBytes(operationID).length != UA_OPERATION_ID_LENGTH) {
        reply(EINVAL, nil);
        return;
    }
    dispatch_semaphore_t gate = BundleAuthorizationGate();
    if (dispatch_semaphore_wait(gate, DISPATCH_TIME_NOW) != 0) {
        reply(EBUSY, nil);
        return;
    }
    NSString *identifier = [operationID copy];
    NSXPCConnection *peer = [NSXPCConnection currentConnection];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            NSString *response = nil;
            int32_t status = EACCES;
            @try {
                if ([self isActivePeer:peer]) {
                    NSDictionary *review = nil;
                    status = UAPreviewBundleExpiry(self->_uid, identifier, &review);
                    if (status == 0) {
                        response = QuarantineResultJSON(review);
                        status = response == nil ? EIO : 0;
                    }
                }
            } @catch (NSException *exception) {
                (void)exception;
                status = EIO;
            } @finally {
                dispatch_semaphore_signal(gate);
            }
            reply(status, response);
        }
    });
}

- (void)prepareBackupOperation:(NSString *)operationID
                           stamp:(NSString *)stamp
                        awaiting:(UASessionState)authorizationState
                           reply:(void (^)(int32_t, NSString *))reply {
    if (reply == nil) {
        return;
    }
    if (![self advanceFrom:SessionReadyForInspection to:SessionFinished]) {
        reply(EACCES, nil);
        return;
    }
    if (AddressBytes(operationID).length != UA_OPERATION_ID_LENGTH || !IsRootStamp(stamp)) {
        reply(EINVAL, nil);
        return;
    }
    NSString *identifier = [operationID copy];
    NSString *reviewStamp = [stamp copy];
    if (authorizationState == SessionWaitingForRestoreAuthorization) {
        int32_t status = ReviewedRestoreTarget(_uid, identifier, reviewStamp, NULL);
        if (status != 0) {
            reply(status, nil);
            return;
        }
    }
    NSString *challenge = NewAuthorizationChallenge();
    if (challenge == nil) {
        reply(EIO, nil);
        return;
    }
    @synchronized (self) {
        _backupOperationID = identifier;
        _backupStamp = reviewStamp;
        _backupChallenge = challenge;
        _backupDeadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + AuthorizationWindow;
        _state = authorizationState;
    }
    reply(0, challenge);
}

- (void)prepareBundleRestore:(NSString *)operationID
                  restoreStamp:(NSString *)restoreStamp
                         reply:(void (^)(int32_t, NSString *))reply {
    [self prepareBackupOperation:operationID stamp:restoreStamp
                         awaiting:SessionWaitingForRestoreAuthorization reply:reply];
}

- (void)prepareBundleExpiry:(NSString *)operationID
                  expiryStamp:(NSString *)expiryStamp
                        reply:(void (^)(int32_t, NSString *))reply {
    [self prepareBackupOperation:operationID stamp:expiryStamp
                         awaiting:SessionWaitingForExpiryAuthorization reply:reply];
}

- (void)completeBackupOperation:(NSString *)ticket
                    externalForm:(NSData *)externalForm
                         awaiting:(UASessionState)authorizationState
                            reply:(void (^)(int32_t, NSString *))reply {
    if (reply == nil) {
        return;
    }
    if (![self advanceFrom:authorizationState to:SessionFinished]) {
        reply(EACCES, nil);
        return;
    }
    NSString *operationID = _backupOperationID;
    NSString *stamp = _backupStamp;
    NSString *challenge = _backupChallenge;
    uint64_t deadline = _backupDeadline;
    _backupOperationID = nil;
    _backupStamp = nil;
    _backupChallenge = nil;
    if (!IsRootStamp(ticket) || ![ticket isEqualToString:challenge]
        || ![externalForm isKindOfClass:NSData.class]
        || externalForm.length != sizeof(AuthorizationExternalForm)) {
        reply(EACCES, nil);
        return;
    }
    if (clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) >= deadline) {
        reply(ETIMEDOUT, nil);
        return;
    }

    NSXPCConnection *peer = [NSXPCConnection currentConnection];
    NSData *form = [externalForm copy];
    BOOL isExpiry = authorizationState == SessionWaitingForExpiryAuthorization;
    int32_t unknown = isExpiry ? UA_EXPIRY_OUTCOME_UNKNOWN : UA_RESTORE_OUTCOME_UNKNOWN;
    dispatch_semaphore_t gate = BundleAuthorizationGate();
    if (dispatch_semaphore_wait(gate, DISPATCH_TIME_NOW) != 0) {
        reply(EBUSY, nil);
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            BOOL (^mayCommit)(void) = ^BOOL {
                return [self isActivePeer:peer] && clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) < deadline;
            };
            NSDictionary *reviewed = nil;
            NSString *response = nil;
            int32_t status = EACCES;
            BOOL mutationStarted = NO;
            @try {
                if (mayCommit()) {
                    status = isExpiry ? ReviewedExpiryTarget(self->_uid, operationID, stamp, &reviewed)
                                     : ReviewedRestoreTarget(self->_uid, operationID, stamp, &reviewed);
                }
                if (status == 0) {
                    if (mayCommit()) {
                        status = isExpiry ? UAEnsureBundleExpiryRight() : UAEnsureBundleRestoreRight();
                    } else {
                        status = EACCES;
                    }
                }
                if (status == 0) {
                    NSString *path = reviewed[@"original_path"];
                    NSString *name = path.lastPathComponent;
                    NSString *identifier = reviewed[@"bundle_id"];
                    if (mayCommit()) {
                        status = isExpiry ? UAAuthenticateAndConsumeBundleExpiryAuthorization(form, name, identifier)
                                         : UAAuthenticateAndConsumeBundleRestoreAuthorization(form, name, identifier);
                    } else {
                        status = EACCES;
                    }
                }
                if (status == 0 && !mayCommit()) {
                    status = EACCES;
                }
                if (status == 0) {
                    mutationStarted = YES;
                    NSDictionary *result = isExpiry ? UAExpireVerifiedBundle(self->_uid, operationID, stamp, mayCommit)
                                                   : UARestoreVerifiedBundle(self->_uid, operationID, stamp, mayCommit);
                    NSString *state = result[@"status"];
                    BOOL recorded = isExpiry
                        ? [state isEqualToString:@"purged"] || [state isEqualToString:@"expiry_pending"]
                        : [state isEqualToString:@"restored"];
                    if (recorded || [state isEqualToString:@"ambiguous"]) {
                        response = QuarantineResultJSON(result);
                        status = response == nil ? unknown : 0;
                    } else if ([result[@"errno"] intValue] > 0) {
                        status = RecordedError(result);
                    } else {
                        status = unknown;
                    }
                }
            } @catch (NSException *exception) {
                (void)exception;
                status = mutationStarted ? unknown : EIO;
            } @finally {
                dispatch_semaphore_signal(gate);
            }
            reply(status, response);
        }
    });
}

- (void)restoreBundleWithAuthorization:(NSString *)ticket
                           externalForm:(NSData *)externalForm
                                  reply:(void (^)(int32_t, NSString *))reply {
    [self completeBackupOperation:ticket externalForm:externalForm
                         awaiting:SessionWaitingForRestoreAuthorization reply:reply];
}

- (void)expireBundleWithAuthorization:(NSString *)ticket
                          externalForm:(NSData *)externalForm
                                 reply:(void (^)(int32_t, NSString *))reply {
    [self completeBackupOperation:ticket externalForm:externalForm
                         awaiting:SessionWaitingForExpiryAuthorization reply:reply];
}

- (void)prepareBundleQuarantine:(NSString *)basename
               bundleIdentifier:(NSString *)bundleIdentifier
                      rootStamp:(NSString *)rootStamp
                          reply:(void (^)(int32_t, NSString *))reply {
    if (reply == nil) {
        return;
    }
    if (![self advanceFrom:SessionReadyForInspection to:SessionFinished]) {
        reply(EACCES, nil);
        return;
    }
    if (!IsApplicationBasename(basename) || !IsBundleIdentifier(bundleIdentifier)
        || !IsRootStamp(rootStamp)) {
        reply(EINVAL, nil);
        return;
    }
    NSString *name = [basename copy];
    NSString *identifier = [bundleIdentifier copy];
    NSString *stamp = [rootStamp copy];
    if (!MatchesReviewedRoot(name, identifier, stamp)) {
        reply(ESTALE, nil);
        return;
    }
    NSString *challenge = NewAuthorizationChallenge();
    if (challenge == nil) {
        reply(EIO, nil);
        return;
    }
    @synchronized (self) {
        _quarantineBasename = name;
        _quarantineIdentifier = identifier;
        _quarantineStamp = stamp;
        _quarantineChallenge = challenge;
        _quarantineDeadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + AuthorizationWindow;
        _state = SessionWaitingForQuarantineAuthorization;
    }
    reply(0, challenge);
}

- (void)verifyBundleQuarantineAuthorization:(NSString *)ticket
                               externalForm:(NSData *)externalForm
                                      reply:(void (^)(int32_t))reply {
    if (reply == nil) {
        return;
    }
    // Consume the challenge before touching Authorization Services. The
    // reference on its own cannot identify a bundle or authorize a replay.
    if (![self advanceFrom:SessionWaitingForQuarantineAuthorization to:SessionFinished]) {
        reply(EACCES);
        return;
    }
    NSString *name = _quarantineBasename;
    NSString *identifier = _quarantineIdentifier;
    NSString *stamp = _quarantineStamp;
    NSString *challenge = _quarantineChallenge;
    uint64_t deadline = _quarantineDeadline;
    _quarantineBasename = nil;
    _quarantineIdentifier = nil;
    _quarantineStamp = nil;
    _quarantineChallenge = nil;
    if (!IsRootStamp(ticket) || ![ticket isEqualToString:challenge]
        || ![externalForm isKindOfClass:NSData.class]
        || externalForm.length != sizeof(AuthorizationExternalForm)) {
        reply(EACCES);
        return;
    }
    if (clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) >= deadline) {
        reply(ETIMEDOUT);
        return;
    }
    if (!MatchesReviewedRoot(name, identifier, stamp)) {
        reply(ESTALE);
        return;
    }
    NSXPCConnection *peer = [NSXPCConnection currentConnection];
    NSData *form = [externalForm copy];
    dispatch_semaphore_t gate = BundleAuthorizationGate();
    if (dispatch_semaphore_wait(gate, DISPATCH_TIME_NOW) != 0) {
        reply(EBUSY);
        return;
    }
    // Keep the connection's message queue free to disarm this request
    // while the system's authentication dialog is open.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            int32_t status = EACCES;
            @try {
                if ([self isActivePeer:peer] && clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) < deadline) {
                    status = CheckReviewedInstallerReceipts(name, identifier, stamp, deadline);
                    if (status == 0) {
                        if ([self isActivePeer:peer] && clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) < deadline) {
                            status = UAEnsureBundleQuarantineRight();
                        } else {
                            status = EACCES;
                        }
                    }
                    if (status == 0) {
                        if ([self isActivePeer:peer] && clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) < deadline) {
                            status = UAAuthenticateAndConsumeBundleQuarantineAuthorization(form, name, identifier);
                        } else {
                            status = EACCES;
                        }
                    }
                }
                if (status == 0) {
                    if (![self isActivePeer:peer] || clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) >= deadline) {
                        status = EACCES;
                    } else {
                        UAReviewedBundle reviewed __attribute__((cleanup(UACloseReviewedApplicationBundle)));
                        status = UAOpenReviewedApplicationBundle(name, identifier, stamp, &reviewed, NULL);
                        if (status == 0) {
                            status = UACheckProtectedBundleTree(reviewed.bundle);
                        }
                        if (status == 0 && (![self isActivePeer:peer]
                            || clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) >= deadline)) {
                            status = EACCES;
                        }
                    }
                }
            } @catch (NSException *exception) {
                (void)exception;
                status = EIO;
            } @finally {
                dispatch_semaphore_signal(gate);
            }
            reply(status);
        }
    });
}
@end

@interface UAHelperListenerDelegate : NSObject <NSXPCListenerDelegate>
@end

@implementation UAHelperListenerDelegate
- (BOOL)listener:(NSXPCListener *)listener
    shouldAcceptNewConnection:(NSXPCConnection *)connection {
    (void)listener;
    uid_t uid = connection.effectiveUserIdentifier;
    au_asid_t auditSession = connection.auditSessionIdentifier;
    if (uid == 0 || uid == (uid_t)-1 || auditSession <= AU_DEFAUDITSID
        || auditSession == (au_asid_t)AU_ASSIGN_ASID) {
        return NO;
    }
    connection.exportedInterface =
        [NSXPCInterface interfaceWithProtocol:@protocol(UAHousekeepingHelper)];
    UAInspectionSession *session = [[UAInspectionSession alloc] initWithConnection:connection
                                                                              uid:uid
                                                                     auditSession:auditSession];
    connection.exportedObject = session;
    __weak UAInspectionSession *weakSession = session;
    connection.interruptionHandler = ^{ [weakSession markDisconnected]; };
    connection.invalidationHandler = ^{ [weakSession markDisconnected]; };
    [connection activate];
    return YES;
}
@end

int main(void) {
    @autoreleasepool {
        if (getuid() != 0 || geteuid() != 0) {
            fputs("The installed helper must be launched by the system.\n", stderr);
            return EXIT_FAILURE;
        }
        NSString *team = VerifiedHelperTeam();
        if (team == nil) {
            fputs("The helper's Developer ID signature could not be verified.\n", stderr);
            return EXIT_FAILURE;
        }
        NSString *peerRequirement = SigningRequirement(UA_GUI_SIGNING_ID, team);
        SecRequirementRef compiled = CopyRequirement(peerRequirement);
        if (compiled == NULL) {
            fputs("The helper's client signing requirement is invalid.\n", stderr);
            return EXIT_FAILURE;
        }
        CFRelease(compiled);

        __attribute__((objc_precise_lifetime)) NSXPCListener *listener =
            [[NSXPCListener alloc] initWithMachServiceName:UA_MACH_SERVICE];
        if (listener == nil) {
            return EXIT_FAILURE;
        }
        __attribute__((objc_precise_lifetime)) UAHelperListenerDelegate *delegate =
            [UAHelperListenerDelegate new];
        [listener setConnectionCodeSigningRequirement:peerRequirement];
        listener.delegate = delegate;
        [listener activate];
        dispatch_main();
    }
}
