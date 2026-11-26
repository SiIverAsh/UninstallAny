#import "protocol.h"
#import <ServiceManagement/ServiceManagement.h>

#include <dispatch/dispatch.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

enum {
    UA_TEAM_LENGTH = 10,
    UA_INSPECTION_TIMEOUT_MS = 750,
    UA_MAX_INSPECTION_BYTES = 4096,
};

static BOOL UAValidTeam(const char *team) {
    if (team == NULL || strnlen(team, UA_TEAM_LENGTH + 1) != UA_TEAM_LENGTH) {
        return NO;
    }
    for (size_t index = 0; index < UA_TEAM_LENGTH; ++index) {
        const char character = team[index];
        if (!((character >= 'A' && character <= 'Z')
              || (character >= '0' && character <= '9'))) {
            return NO;
        }
    }
    return YES;
}

static BOOL UAValidStamp(const char *stamp) {
    if (stamp == NULL || strnlen(stamp, UA_ROOT_STAMP_LENGTH + 1) != UA_ROOT_STAMP_LENGTH) {
        return NO;
    }
    for (size_t index = 0; index < UA_ROOT_STAMP_LENGTH; ++index) {
        const char character = stamp[index];
        if (!((character >= '0' && character <= '9')
              || (character >= 'a' && character <= 'f'))) {
            return NO;
        }
    }
    return YES;
}

@interface UAInspectionReply : NSObject
- (void)completeWithStatus:(int32_t)status text:(NSString *)text;
- (int32_t)status;
- (int32_t)waitUntil:(dispatch_time_t)deadline text:(NSString **)text;
- (int32_t)waitUntil:(dispatch_time_t)deadline
       timeoutStatus:(int32_t)timeoutStatus
                text:(NSString **)text;
@end

@implementation UAInspectionReply {
    dispatch_semaphore_t _completion;
    int32_t _status;
    NSString *_text;
}

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _completion = dispatch_semaphore_create(0);
        _status = EINPROGRESS;
    }
    return self;
}

- (void)completeWithStatus:(int32_t)status text:(NSString *)text {
    @synchronized (self) {
        if (_status != EINPROGRESS) {
            return;
        }
        _status = status;
        _text = [text copy];
        dispatch_semaphore_signal(_completion);
    }
}

- (int32_t)status {
    @synchronized (self) {
        return _status;
    }
}

- (int32_t)waitUntil:(dispatch_time_t)deadline text:(NSString **)text {
    return [self waitUntil:deadline timeoutStatus:ETIMEDOUT text:text];
}

- (int32_t)waitUntil:(dispatch_time_t)deadline
       timeoutStatus:(int32_t)timeoutStatus
                text:(NSString **)text {
    if (dispatch_semaphore_wait(_completion, deadline) != 0) {
        return timeoutStatus;
    }
    @synchronized (self) {
        *text = _text;
        return _status;
    }
}

@end

static int32_t UAConnectionError(NSError *error) {
    if (@available(macOS 13.0, *)) {
        if ([error.domain isEqualToString:NSCocoaErrorDomain]
            && error.code == NSXPCConnectionCodeSigningRequirementFailure) {
            return EACCES;
        }
    }
    return EIO;
}

typedef int32_t (^UAAuthenticatedRequest)(
    NSXPCConnection *connection, UAInspectionReply *health, dispatch_time_t deadline
);

API_AVAILABLE(macos(13.0))
static int32_t UAUseSignedConnection(NSString *team, UAAuthenticatedRequest request) {
    // The initial deadline covers the signed probe and the first scoped call.
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW,
        UA_INSPECTION_TIMEOUT_MS * NSEC_PER_MSEC);
    NSXPCConnection *connection = nil;
    @try {
        // Global lookup excludes a caller-owned per-user impersonator.
        connection = [[NSXPCConnection alloc] initWithMachServiceName:UA_MACH_SERVICE
                                                             options:NSXPCConnectionPrivileged];
        connection.remoteObjectInterface =
            [NSXPCInterface interfaceWithProtocol:@protocol(UAHousekeepingHelper)];
        NSString *requirement = [NSString stringWithFormat:
            @"anchor apple generic and identifier \"%@\""
            @" and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
            @" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
            @" and certificate leaf[subject.OU] = \"%@\""
            @" and !(entitlement[com.apple.security.get-task-allow] exists)"
            @" and !(entitlement[com.apple.security.cs.disable-library-validation] exists)"
            @" and !(entitlement[com.apple.security.cs.allow-dyld-environment-variables] exists)",
            UA_HELPER_SIGNING_ID, team];
        [connection setCodeSigningRequirement:requirement];

        UAInspectionReply *probe = [UAInspectionReply new];
        UAInspectionReply *health = [UAInspectionReply new];
        // Reply blocks own their state. They never access the caller buffer.
        void (^failConnection)(void) = ^{
            [probe completeWithStatus:EIO text:nil];
            [health completeWithStatus:EIO text:nil];
        };
        __weak NSXPCConnection *weakConnection = connection;
        connection.interruptionHandler = ^{
            failConnection();
            [weakConnection invalidate];
        };
        connection.invalidationHandler = failConnection;
        [connection activate];

        id<UAHousekeepingHelper> probeProxy =
            [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
                [probe completeWithStatus:UAConnectionError(error) text:nil];
            }];
        [probeProxy probeWithReply:^(NSString *reply) {
            [probe completeWithStatus:0 text:reply];
        }];
        NSString *version = nil;
        int32_t status = [probe waitUntil:deadline text:&version];
        if (status != 0) {
            return status;
        }
        if (![version isKindOfClass:NSString.class] || ![version isEqualToString:UA_PROBE_REPLY]) {
            return EACCES;
        }
        // The code requirement authenticates replies. The first request
        // therefore carries no app identity or other operation metadata.
        status = [health status];
        if (status != EINPROGRESS) {
            return status;
        }
        if (dispatch_time(DISPATCH_TIME_NOW, 0) >= deadline) {
            return ETIMEDOUT;
        }

        return request(connection, health, deadline);
    } @catch (NSException *exception) {
        (void)exception;
        return EIO;
    } @finally {
        [connection invalidate];
    }
}

static id<UAHousekeepingHelper> UAHelperProxy(NSXPCConnection *connection, UAInspectionReply *result) {
    return [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        [result completeWithStatus:UAConnectionError(error) text:nil];
    }];
}

static int32_t UACopyJSONResponse(NSString *result, dispatch_time_t deadline,
                                 char *response, size_t responseCapacity, size_t maximumBytes) {
    if (![result isKindOfClass:NSString.class] || result.length > maximumBytes) {
        return EIO;
    }
    NSData *bytes = [result dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    if (bytes.length == 0 || bytes.length > maximumBytes
        || memchr(bytes.bytes, '\0', bytes.length) != NULL) {
        return EIO;
    }
    if (bytes.length >= responseCapacity) {
        return ENOSPC;
    }
    id decoded = [NSJSONSerialization JSONObjectWithData:bytes options:0 error:NULL];
    if (![decoded isKindOfClass:NSDictionary.class]) {
        return EIO;
    }
    if (dispatch_time(DISPATCH_TIME_NOW, 0) >= deadline) {
        return ETIMEDOUT;
    }
    memcpy(response, bytes.bytes, bytes.length);
    response[bytes.length] = '\0';
    return 0;
}

static int32_t UACopyJSONReply(UAInspectionReply *pending, dispatch_time_t deadline,
                               char *response, size_t responseCapacity, size_t maximumBytes) {
    NSString *result = nil;
    int32_t status = [pending waitUntil:deadline text:&result];
    return status == 0
        ? UACopyJSONResponse(result, deadline, response, responseCapacity, maximumBytes) : status;
}

static int32_t UAInspectBundle(NSXPCConnection *connection, NSString *name, NSString *identifier,
                              dispatch_time_t deadline, char *response, size_t responseCapacity) {
    UAInspectionReply *inspection = [UAInspectionReply new];
    [UAHelperProxy(connection, inspection) inspectApplicationBundle:name
        bundleIdentifier:identifier reply:^(NSString *reply) {
            [inspection completeWithStatus:0 text:reply];
        }];
    return UACopyJSONReply(inspection, deadline, response, responseCapacity, UA_MAX_INSPECTION_BYTES);
}

typedef int32_t (^UAAuthorizedBundleRequest)(NSString *, NSData *, dispatch_time_t);

static int32_t UAWithPreparedAuthorization(UAInspectionReply *prepared, UAInspectionReply *health,
                                          dispatch_time_t deadline, UAAuthorizedBundleRequest request) {
    NSString *ticket = nil;
    int32_t status = [prepared waitUntil:deadline text:&ticket];
    if (status != 0) {
        return status;
    }
    if (![ticket isKindOfClass:NSString.class] || !UAValidStamp(ticket.UTF8String)) {
        return EACCES;
    }
    status = [health status];
    if (status != EINPROGRESS) {
        return status;
    }
    AuthorizationRef reference = NULL;
    NSData *externalForm = nil;
    status = UACreateEmptyBundleAuthorization(&reference, &externalForm);
    if (status != 0) {
        return status;
    }
    @try {
        if ([health status] != EINPROGRESS) {
            return EACCES;
        }
        // The helper owns the earlier transaction deadline. This wait lets
        // the user respond to the system prompt without opening a new session.
        dispatch_time_t promptDeadline = dispatch_time(DISPATCH_TIME_NOW,
            UA_QUARANTINE_AUTHORIZATION_SECONDS * NSEC_PER_SEC);
        return request(ticket, externalForm, promptDeadline);
    } @finally {
        if (reference != NULL) {
            AuthorizationFree(reference, kAuthorizationFlagDestroyRights);
        }
    }
}

static int32_t UAAuthorizeBundle(NSXPCConnection *connection, UAInspectionReply *health,
                                NSString *name, NSString *identifier, NSString *stamp,
                                dispatch_time_t deadline) {
    UAInspectionReply *prepared = [UAInspectionReply new];
    [UAHelperProxy(connection, prepared) prepareBundleQuarantine:name
        bundleIdentifier:identifier rootStamp:stamp reply:^(int32_t status, NSString *ticket) {
            [prepared completeWithStatus:status text:ticket];
        }];
    return UAWithPreparedAuthorization(prepared, health, deadline,
        ^int32_t(NSString *ticket, NSData *externalForm, dispatch_time_t promptDeadline) {
            UAInspectionReply *authorized = [UAInspectionReply new];
            [UAHelperProxy(connection, authorized) verifyBundleQuarantineAuthorization:ticket
                externalForm:externalForm reply:^(int32_t result) {
                    [authorized completeWithStatus:result text:nil];
                }];
            NSString *unused = nil;
            int32_t status = [authorized waitUntil:promptDeadline text:&unused];
            return status == 0 && [health status] != EINPROGRESS ? EACCES : status;
        });
}

typedef struct {
    char *bytes;
    size_t capacity;
} UAMutationResponse;

typedef void (^UAMutationReply)(int32_t status, NSString *result);
typedef void (^UAMutationCall)(id<UAHousekeepingHelper> proxy, UAMutationReply reply);

static int32_t UASubmitBundleMutation(NSXPCConnection *connection, dispatch_time_t deadline,
                                      UAMutationResponse response, int32_t uncertainStatus,
                                      UAMutationCall send) {
    UAInspectionReply *completed = [UAInspectionReply new];
    id<UAHousekeepingHelper> proxy = [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        (void)error;
        [completed completeWithStatus:uncertainStatus text:nil];
    }];
    // A lost reply leaves the submitted operation uncertain. The caller
    // can query its record on a fresh connection.
    @try {
        send(proxy, ^(int32_t status, NSString *result) {
            int32_t outcome = status >= 0 && status != EINPROGRESS ? status : uncertainStatus;
            [completed completeWithStatus:outcome text:result];
        });
        NSString *result = nil;
        int32_t status = [completed waitUntil:deadline timeoutStatus:uncertainStatus text:&result];
        if (status != 0) {
            return status;
        }
        return UACopyJSONResponse(result, deadline, response.bytes, response.capacity,
                                  UA_MAX_INSPECTION_BYTES) == 0
            ? 0 : uncertainStatus;
    } @catch (NSException *exception) {
        (void)exception;
        return uncertainStatus;
    }
}

typedef int32_t (^UABundleRequest)(
    NSXPCConnection *, UAInspectionReply *, NSString *, NSString *, dispatch_time_t
);

static int32_t UAWithSignedHelper(const char *team, UAAuthenticatedRequest request) {
    if (!UAValidTeam(team)) {
        return EACCES;
    }
    if (@available(macOS 13.0, *)) {
        @autoreleasepool {
            SMAppServiceStatus status =
                [SMAppService daemonServiceWithPlistName:UA_DAEMON_PLIST].status;
            if (status != SMAppServiceStatusEnabled) {
                return status == SMAppServiceStatusRequiresApproval ? EACCES : ENOENT;
            }
            return UAUseSignedConnection([NSString stringWithUTF8String:team], request);
        }
    }
    return ENOTSUP;
}

static int32_t UAWithBundleRequest(const char *team, const char *basename,
                                  const char *bundleIdentifier, UABundleRequest request) {
    if (basename == NULL || bundleIdentifier == NULL || basename[0] == '.'
        || strnlen(basename, NAME_MAX + 1) > NAME_MAX
        || strnlen(bundleIdentifier, NAME_MAX + 1) > NAME_MAX
        || strchr(basename, '/') != NULL) {
        return EINVAL;
    }
    @autoreleasepool {
        NSString *name = [NSString stringWithUTF8String:basename];
        NSString *identifier = [NSString stringWithUTF8String:bundleIdentifier];
        if (name.length == 0 || identifier.length == 0
            || [name.pathExtension caseInsensitiveCompare:@"app"] != NSOrderedSame) {
            return EINVAL;
        }
        return UAWithSignedHelper(team,
            ^int32_t(NSXPCConnection *connection, UAInspectionReply *health,
                     dispatch_time_t deadline) {
                return request(connection, health, name, identifier, deadline);
            });
    }
}

int32_t UAInspectThroughSignedHelper(const char *team, const char *basename,
                                    const char *bundleIdentifier, char *response,
                                    size_t responseCapacity) {
    if (response == NULL || responseCapacity == 0) {
        return EINVAL;
    }
    response[0] = '\0';
    return UAWithBundleRequest(team, basename, bundleIdentifier,
        ^int32_t(NSXPCConnection *connection, UAInspectionReply *health,
                 NSString *name, NSString *identifier, dispatch_time_t deadline) {
            (void)health;
            return UAInspectBundle(connection, name, identifier, deadline, response, responseCapacity);
        });
}

int32_t UAVerifyQuarantineThroughSignedHelper(const char *team, const char *basename,
                                             const char *bundleIdentifier, const char *rootStamp) {
    if (!UAValidStamp(rootStamp)) {
        return EINVAL;
    }
    @autoreleasepool {
        NSString *stamp = [[NSString alloc] initWithBytes:rootStamp
            length:UA_ROOT_STAMP_LENGTH encoding:NSASCIIStringEncoding];
        return UAWithBundleRequest(team, basename, bundleIdentifier,
            ^int32_t(NSXPCConnection *connection, UAInspectionReply *health,
                     NSString *name, NSString *identifier, dispatch_time_t deadline) {
                return UAAuthorizeBundle(connection, health, name, identifier, stamp, deadline);
            });
    }
}

static NSString *UAOperationIdentifier(const char *operationID) {
    if (operationID == NULL
        || strnlen(operationID, UA_OPERATION_ID_LENGTH + 1) != UA_OPERATION_ID_LENGTH) {
        return nil;
    }
    NSString *identifier = [[NSString alloc] initWithBytes:operationID
        length:UA_OPERATION_ID_LENGTH encoding:NSASCIIStringEncoding];
    if (identifier == nil) {
        return nil;
    }
    NSUUID *operation = [[NSUUID alloc] initWithUUIDString:identifier];
    return operation != nil && [identifier isEqualToString:operation.UUIDString.lowercaseString]
        ? identifier : nil;
}

int32_t UAQueryQuarantineThroughSignedHelper(const char *team, const char *operationID,
                                             char *response, size_t responseCapacity) {
    if (response == NULL || responseCapacity == 0) {
        return EINVAL;
    }
    response[0] = '\0';
    @autoreleasepool {
        NSString *identifier = UAOperationIdentifier(operationID);
        if (identifier == nil) {
            return EINVAL;
        }
        return UAWithSignedHelper(team,
            ^int32_t(NSXPCConnection *connection, UAInspectionReply *health,
                     dispatch_time_t deadline) {
                (void)health;
                UAInspectionReply *query = [UAInspectionReply new];
                [UAHelperProxy(connection, query) queryBundleQuarantine:identifier
                    reply:^(int32_t status, NSString *result) {
                        [query completeWithStatus:status text:result];
                    }];
                return UACopyJSONReply(query, deadline, response, responseCapacity, UA_MAX_INSPECTION_BYTES);
            });
    }
}

int32_t UAListQuarantineThroughSignedHelper(const char *team, const char *afterOperationID,
                                            const char *catalogStamp, char *response,
                                            size_t responseCapacity) {
    if (response == NULL || responseCapacity == 0) {
        return EINVAL;
    }
    response[0] = '\0';
    if ((afterOperationID == NULL) != (catalogStamp == NULL)) {
        return EINVAL;
    }
    @autoreleasepool {
        NSString *after = nil;
        NSString *stamp = nil;
        if (afterOperationID != NULL) {
            after = UAOperationIdentifier(afterOperationID);
            if (after == nil || !UAValidStamp(catalogStamp)) {
                return EINVAL;
            }
            stamp = [[NSString alloc] initWithBytes:catalogStamp length:UA_ROOT_STAMP_LENGTH
                                            encoding:NSASCIIStringEncoding];
        }
        return UAWithSignedHelper(team,
            ^int32_t(NSXPCConnection *connection, UAInspectionReply *health,
                     dispatch_time_t probeDeadline) {
                (void)probeDeadline;
                int32_t status = [health status];
                if (status != EINPROGRESS) {
                    return status;
                }
                dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW,
                    UA_QUARANTINE_PAGE_SECONDS * NSEC_PER_SEC);
                UAInspectionReply *page = [UAInspectionReply new];
                [UAHelperProxy(connection, page) listBundleQuarantineAfter:after catalogStamp:stamp
                    reply:^(int32_t status, NSString *result) {
                        [page completeWithStatus:status text:result];
                    }];
                return UACopyJSONReply(page, deadline, response, responseCapacity,
                                       UA_QUARANTINE_PAGE_BYTES);
            });
    }
}

int32_t UARestoreThroughSignedHelper(const char *team, const char *operationID,
                                     const char *restoreStamp, char *response, size_t responseCapacity) {
    if (response == NULL || responseCapacity == 0) {
        return EINVAL;
    }
    response[0] = '\0';
    @autoreleasepool {
        NSString *identifier = UAOperationIdentifier(operationID);
        if (identifier == nil || !UAValidStamp(restoreStamp)) {
            return EINVAL;
        }
        NSString *stamp = [[NSString alloc] initWithBytes:restoreStamp
            length:UA_ROOT_STAMP_LENGTH encoding:NSASCIIStringEncoding];
        UAMutationResponse output = {.bytes = response, .capacity = responseCapacity};
        return UAWithSignedHelper(team,
            ^int32_t(NSXPCConnection *connection, UAInspectionReply *health,
                     dispatch_time_t deadline) {
                UAInspectionReply *prepared = [UAInspectionReply new];
                [UAHelperProxy(connection, prepared) prepareBundleRestore:identifier restoreStamp:stamp
                    reply:^(int32_t status, NSString *ticket) {
                        [prepared completeWithStatus:status text:ticket];
                    }];
                return UAWithPreparedAuthorization(prepared, health, deadline,
                    ^int32_t(NSString *ticket, NSData *externalForm, dispatch_time_t promptDeadline) {
                        return UASubmitBundleMutation(connection, promptDeadline, output,
                            UA_RESTORE_OUTCOME_UNKNOWN,
                            ^(id<UAHousekeepingHelper> proxy, UAMutationReply reply) {
                                [proxy restoreBundleWithAuthorization:ticket
                                    externalForm:externalForm reply:reply];
                            });
                    });
            });
    }
}

int32_t UAPreviewExpiryThroughSignedHelper(const char *team, const char *operationID,
                                          char *response, size_t responseCapacity) {
    if (response == NULL || responseCapacity == 0) {
        return EINVAL;
    }
    response[0] = '\0';
    @autoreleasepool {
        NSString *identifier = UAOperationIdentifier(operationID);
        if (identifier == nil) {
            return EINVAL;
        }
        return UAWithSignedHelper(team,
            ^int32_t(NSXPCConnection *connection, UAInspectionReply *health,
                     dispatch_time_t probeDeadline) {
                (void)probeDeadline;
                int32_t status = [health status];
                if (status != EINPROGRESS) {
                    return status;
                }
                // The read-only tree survey has its own deadline after
                // the short authenticated probe.
                dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW,
                    UA_EXPIRY_PREVIEW_SECONDS * NSEC_PER_SEC);
                UAInspectionReply *preview = [UAInspectionReply new];
                [UAHelperProxy(connection, preview) previewBundleExpiry:identifier
                    reply:^(int32_t status, NSString *result) {
                        [preview completeWithStatus:status text:result];
                    }];
                return UACopyJSONReply(preview, deadline, response, responseCapacity,
                                       UA_MAX_INSPECTION_BYTES);
            });
    }
}

int32_t UAExpireThroughSignedHelper(const char *team, const char *operationID,
                                   const char *expiryStamp, char *response,
                                   size_t responseCapacity) {
    if (response == NULL || responseCapacity == 0) {
        return EINVAL;
    }
    response[0] = '\0';
    @autoreleasepool {
        NSString *identifier = UAOperationIdentifier(operationID);
        if (identifier == nil || !UAValidStamp(expiryStamp)) {
            return EINVAL;
        }
        NSString *stamp = [[NSString alloc] initWithBytes:expiryStamp
            length:UA_ROOT_STAMP_LENGTH encoding:NSASCIIStringEncoding];
        UAMutationResponse output = {.bytes = response, .capacity = responseCapacity};
        return UAWithSignedHelper(team,
            ^int32_t(NSXPCConnection *connection, UAInspectionReply *health,
                     dispatch_time_t deadline) {
                UAInspectionReply *prepared = [UAInspectionReply new];
                [UAHelperProxy(connection, prepared) prepareBundleExpiry:identifier expiryStamp:stamp
                    reply:^(int32_t status, NSString *ticket) {
                        [prepared completeWithStatus:status text:ticket];
                    }];
                return UAWithPreparedAuthorization(prepared, health, deadline,
                    ^int32_t(NSString *ticket, NSData *externalForm, dispatch_time_t promptDeadline) {
                        return UASubmitBundleMutation(connection, promptDeadline, output,
                            UA_EXPIRY_OUTCOME_UNKNOWN,
                            ^(id<UAHousekeepingHelper> proxy, UAMutationReply reply) {
                                [proxy expireBundleWithAuthorization:ticket
                                    externalForm:externalForm reply:reply];
                            });
                    });
            });
    }
}

int32_t UAPreviewStandaloneQuarantineThroughSignedHelper(const char *team, const char *basename,
                                                         const char *bundleIdentifier, char *stamp,
                                                         size_t stampCapacity) {
    if (stamp == NULL || stampCapacity == 0) {
        return EINVAL;
    }
    stamp[0] = '\0';
    if (stampCapacity <= UA_ROOT_STAMP_LENGTH) {
        return ENOSPC;
    }
    return UAWithBundleRequest(team, basename, bundleIdentifier,
        ^int32_t(NSXPCConnection *connection, UAInspectionReply *health,
                 NSString *name, NSString *identifier, dispatch_time_t probeDeadline) {
            (void)health;
            (void)probeDeadline;
            // Package attribution needs a separate read-only allowance after
            // the peer has authenticated within the short probe deadline.
            dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW,
                UA_STANDALONE_PREVIEW_SECONDS * NSEC_PER_SEC);
            UAInspectionReply *preview = [UAInspectionReply new];
            [UAHelperProxy(connection, preview) previewStandaloneQuarantine:name
                bundleIdentifier:identifier reply:^(int32_t status, NSString *reviewStamp) {
                    [preview completeWithStatus:status text:reviewStamp];
                }];
            NSString *reviewStamp = nil;
            int32_t status = [preview waitUntil:deadline text:&reviewStamp];
            if (status != 0) {
                return status;
            }
            if (dispatch_time(DISPATCH_TIME_NOW, 0) >= deadline) {
                return ETIMEDOUT;
            }
            if (![reviewStamp isKindOfClass:NSString.class]
                || reviewStamp.length != UA_ROOT_STAMP_LENGTH || !UAValidStamp(reviewStamp.UTF8String)) {
                return EIO;
            }
            memcpy(stamp, reviewStamp.UTF8String, UA_ROOT_STAMP_LENGTH + 1);
            return 0;
        });
}

int32_t UAQuarantineStandaloneThroughSignedHelper(const char *team,
                                                  const UAStandaloneQuarantineRequest *request,
                                                  char *response, size_t responseCapacity) {
    if (response == NULL || responseCapacity == 0 || request == NULL) {
        return EINVAL;
    }
    response[0] = '\0';
    @autoreleasepool {
        NSString *operation = UAOperationIdentifier(request->operationID);
        uint16_t retentionDays = request->retentionDays;
        if (operation == nil || !UAValidStamp(request->reviewStamp) || retentionDays == 0) {
            return EINVAL;
        }
        NSString *stamp = [[NSString alloc] initWithBytes:request->reviewStamp
            length:UA_ROOT_STAMP_LENGTH encoding:NSASCIIStringEncoding];
        UAMutationResponse output = {.bytes = response, .capacity = responseCapacity};
        return UAWithBundleRequest(team, request->basename, request->bundleIdentifier,
            ^int32_t(NSXPCConnection *connection, UAInspectionReply *health,
                     NSString *name, NSString *identifier, dispatch_time_t deadline) {
                UAInspectionReply *prepared = [UAInspectionReply new];
                [UAHelperProxy(connection, prepared) prepareStandaloneQuarantine:name
                    bundleIdentifier:identifier operationID:operation reviewStamp:stamp
                    retentionDays:retentionDays
                    reply:^(int32_t status, NSString *ticket) {
                        [prepared completeWithStatus:status text:ticket];
                    }];
                return UAWithPreparedAuthorization(prepared, health, deadline,
                    ^int32_t(NSString *ticket, NSData *externalForm, dispatch_time_t promptDeadline) {
                        return UASubmitBundleMutation(connection, promptDeadline, output,
                            UA_QUARANTINE_OUTCOME_UNKNOWN,
                            ^(id<UAHousekeepingHelper> proxy, UAMutationReply reply) {
                                [proxy quarantineStandaloneWithAuthorization:ticket
                                    externalForm:externalForm reply:reply];
                            });
                    });
            });
    }
}
