#import <Foundation/Foundation.h>
#import <Security/Authorization.h>
#include <stddef.h>
#include <stdint.h>

#define UA_GUI_SIGNING_ID @"io.github.siiverash.uninstallany"
#define UA_HELPER_SIGNING_ID @"io.github.siiverash.uninstallany.privileged-helper"
#define UA_MACH_SERVICE UA_HELPER_SIGNING_ID
#define UA_DAEMON_PLIST @"io.github.siiverash.uninstallany.privileged-helper.plist"
#define UA_PROBE_REPLY @"uninstallany-macos-helper-v7"

enum {
    UA_RESTORE_OUTCOME_UNKNOWN = -1,
    UA_QUARANTINE_OUTCOME_UNKNOWN = -1,
    UA_EXPIRY_OUTCOME_UNKNOWN = -1,
    UA_OPERATION_ID_LENGTH = 36,
    UA_ROOT_STAMP_LENGTH = 64,
    UA_QUARANTINE_AUTHORIZATION_SECONDS = 120,
    UA_STANDALONE_PREVIEW_SECONDS = 45,
    UA_QUARANTINE_PAGE_BYTES = 32768,
    UA_QUARANTINE_PAGE_ENTRIES = 12,
    UA_QUARANTINE_PAGE_SECONDS = 3,
    UA_EXPIRY_PREVIEW_SECONDS = 15,
};

enum {
    UA_SERVICE_NOT_REGISTERED = 0,
    UA_SERVICE_ENABLED = 1,
    UA_SERVICE_REQUIRES_APPROVAL = 2,
    UA_SERVICE_NOT_FOUND = 3,
};

@protocol UAHousekeepingHelper
- (void)probeWithReply:(void (^)(NSString *))reply;
- (void)inspectApplicationBundle:(NSString *)basename
                bundleIdentifier:(NSString *)bundleIdentifier
                           reply:(void (^)(NSString *))reply;
- (void)prepareBundleQuarantine:(NSString *)basename
               bundleIdentifier:(NSString *)bundleIdentifier
                      rootStamp:(NSString *)rootStamp
                          reply:(void (^)(int32_t, NSString *))reply;
- (void)verifyBundleQuarantineAuthorization:(NSString *)ticket
                               externalForm:(NSData *)externalForm
                                      reply:(void (^)(int32_t))reply;
- (void)queryBundleQuarantine:(NSString *)operationID
                         reply:(void (^)(int32_t, NSString *))reply;
- (void)listBundleQuarantineAfter:(NSString *)afterOperationID
                      catalogStamp:(NSString *)catalogStamp
                             reply:(void (^)(int32_t, NSString *))reply;
- (void)prepareBundleRestore:(NSString *)operationID
                  restoreStamp:(NSString *)restoreStamp
                         reply:(void (^)(int32_t, NSString *))reply;
- (void)restoreBundleWithAuthorization:(NSString *)ticket
                           externalForm:(NSData *)externalForm
                                  reply:(void (^)(int32_t, NSString *))reply;
- (void)previewBundleExpiry:(NSString *)operationID
                       reply:(void (^)(int32_t, NSString *))reply;
- (void)prepareBundleExpiry:(NSString *)operationID
                  expiryStamp:(NSString *)expiryStamp
                        reply:(void (^)(int32_t, NSString *))reply;
- (void)expireBundleWithAuthorization:(NSString *)ticket
                          externalForm:(NSData *)externalForm
                                 reply:(void (^)(int32_t, NSString *))reply;
- (void)previewStandaloneQuarantine:(NSString *)basename
                    bundleIdentifier:(NSString *)bundleIdentifier
                               reply:(void (^)(int32_t, NSString *))reply;
- (void)prepareStandaloneQuarantine:(NSString *)basename
                    bundleIdentifier:(NSString *)bundleIdentifier
                         operationID:(NSString *)operationID
                         reviewStamp:(NSString *)reviewStamp
                       retentionDays:(uint16_t)retentionDays
                               reply:(void (^)(int32_t, NSString *))reply;
- (void)quarantineStandaloneWithAuthorization:(NSString *)ticket
                                  externalForm:(NSData *)externalForm
                                         reply:(void (^)(int32_t, NSString *))reply;
@end

NSString *UAInspectApplicationBundle(NSString *basename, NSString *bundleIdentifier);
int32_t UAEnsureBundleQuarantineRight(void);
int32_t UAEnsureBundleRestoreRight(void);
int32_t UAEnsureBundleExpiryRight(void);
int32_t UACreateEmptyBundleAuthorization(AuthorizationRef *reference, NSData **externalForm);
int32_t UAQueryHelperService(const char *team, int32_t *serviceState);
int32_t UARegisterHelperService(const char *team, int32_t *serviceState);
int32_t UAAuthenticateAndConsumeBundleQuarantineAuthorization(
    NSData *externalForm,
    NSString *basename,
    NSString *bundleIdentifier
);
int32_t UAAuthenticateAndConsumeBundleRestoreAuthorization(
    NSData *externalForm,
    NSString *basename,
    NSString *bundleIdentifier
);
int32_t UAAuthenticateAndConsumeBundleExpiryAuthorization(
    NSData *externalForm,
    NSString *basename,
    NSString *bundleIdentifier
);

int32_t UAInspectThroughSignedHelper(
    const char *team,
    const char *basename,
    const char *bundleIdentifier,
    char *response,
    size_t responseCapacity
);

int32_t UAVerifyQuarantineThroughSignedHelper(
    const char *team,
    const char *basename,
    const char *bundleIdentifier,
    const char *rootStamp
);

int32_t UAQueryQuarantineThroughSignedHelper(
    const char *team,
    const char *operationID,
    char *response,
    size_t responseCapacity
);

int32_t UAListQuarantineThroughSignedHelper(
    const char *team,
    const char *afterOperationID,
    const char *catalogStamp,
    char *response,
    size_t responseCapacity
);

int32_t UARestoreThroughSignedHelper(
    const char *team,
    const char *operationID,
    const char *restoreStamp,
    char *response,
    size_t responseCapacity
);

int32_t UAPreviewExpiryThroughSignedHelper(
    const char *team,
    const char *operationID,
    char *response,
    size_t responseCapacity
);

int32_t UAExpireThroughSignedHelper(
    const char *team,
    const char *operationID,
    const char *expiryStamp,
    char *response,
    size_t responseCapacity
);

typedef struct {
    const char *basename;
    const char *bundleIdentifier;
    const char *reviewStamp;
    const char *operationID;
    uint16_t retentionDays;
} UAStandaloneQuarantineRequest;

int32_t UAPreviewStandaloneQuarantineThroughSignedHelper(
    const char *team,
    const char *basename,
    const char *bundleIdentifier,
    char *stamp,
    size_t stampCapacity
);

int32_t UAQuarantineStandaloneThroughSignedHelper(
    const char *team,
    const UAStandaloneQuarantineRequest *request,
    char *response,
    size_t responseCapacity
);
