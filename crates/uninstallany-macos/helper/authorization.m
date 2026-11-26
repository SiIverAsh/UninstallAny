#define __STDC_WANT_LIB_EXT1__ 1

#import "protocol.h"

#include <errno.h>
#include <string.h>

#if defined(UA_AUTHORIZATION_DAEMON)
#include <Security/AuthorizationDB.h>
#include <Security/AuthorizationTags.h>
#include <unistd.h>
#endif

static int32_t UAStatusToError(OSStatus status) {
    switch (status) {
        case errAuthorizationSuccess:
            return 0;
        case errAuthorizationCanceled:
            return ECANCELED;
        case errAuthorizationDenied:
        case errAuthorizationInvalidRef:
        case errAuthorizationInteractionNotAllowed:
        case errAuthorizationExternalizeNotAllowed:
        case errAuthorizationInternalizeNotAllowed:
            return EACCES;
        default:
            return EIO;
    }
}

#if defined(UA_AUTHORIZATION_DAEMON)

static const char BundleQuarantineRight[] = "io.github.siiverash.uninstallany.quarantine-bundle";
static const char BundleRestoreRight[] = "io.github.siiverash.uninstallany.restore-bundle";
static const char BundleExpiryRight[] = "io.github.siiverash.uninstallany.expire-bundle";
static const int AuthenticationTries = 3;

static NSDictionary<NSString *, id> *UABundleAuthorizationRule(void) {
    // Define the user rule directly so no shared admin alias can weaken it.
    return @{
        @"class": @"user",
        @"group": @"admin",
        @"authenticate-user": @YES,
        @"allow-root": @NO,
        @"shared": @NO,
        @"timeout": @0,
        @"tries": @(AuthenticationTries),
    };
}

static BOOL UAHasExpectedBundleRule(NSDictionary<NSString *, id> *rule) {
    NSDictionary<NSString *, id> *expected = UABundleAuthorizationRule();
    for (NSString *key in expected) {
        id value = rule[key];
        id required = expected[key];
        if (value == nil
            || CFGetTypeID((__bridge CFTypeRef)value) != CFGetTypeID((__bridge CFTypeRef)required)
            || ![required isEqual:value]) {
            return NO;
        }
    }

    // authd serializes its own metadata and may report session-owner=false.
    NSArray<NSString *> *metadata = @[
        @"version", @"created", @"modified", @"identifier", @"requirement",
    ];
    for (NSString *key in rule) {
        if (expected[key] != nil || [metadata containsObject:key]) {
            continue;
        }
        if ([key isEqualToString:@"session-owner"]
            && (__bridge CFTypeRef)rule[key] == kCFBooleanFalse) {
            continue;
        }
        return NO;
    }
    return YES;
}

static OSStatus UACopyBundleRule(const char *right, NSDictionary<NSString *, id> **rule) {
    CFDictionaryRef definition = NULL;
    OSStatus status = AuthorizationRightGet(right, &definition);
    *rule = CFBridgingRelease(definition);
    return status;
}

static int32_t UAEnsureBundleRight(const char *right) {
    if (geteuid() != 0) {
        return EACCES;
    }

    @synchronized (NSProcessInfo.processInfo) {
        NSDictionary<NSString *, id> *rule = nil;
        OSStatus status = UACopyBundleRule(right, &rule);
        if (status == errAuthorizationSuccess) {
            return UAHasExpectedBundleRule(rule) ? 0 : EACCES;
        }
        if (status != errAuthorizationDenied) {
            return UAStatusToError(status);
        }

        // Only an absent right may be provisioned. The Security framework
        // exposes an upsert, so serialize provisioning within the daemon.
        NSDictionary<NSString *, id> *definition = UABundleAuthorizationRule();
        AuthorizationRef authorization = NULL;
        status = AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &authorization);
        if (status != errAuthorizationSuccess) {
            return UAStatusToError(status);
        }
        status = AuthorizationRightSet(
            authorization, right, (__bridge CFDictionaryRef)definition,
            NULL, NULL, NULL
        );
        OSStatus released = AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
        if (status != errAuthorizationSuccess || released != errAuthorizationSuccess) {
            return UAStatusToError(status == errAuthorizationSuccess ? released : status);
        }

        status = UACopyBundleRule(right, &rule);
        if (status != errAuthorizationSuccess) {
            return UAStatusToError(status);
        }
        return UAHasExpectedBundleRule(rule) ? 0 : EACCES;
    }
}

int32_t UAEnsureBundleQuarantineRight(void) {
    return UAEnsureBundleRight(BundleQuarantineRight);
}

int32_t UAEnsureBundleRestoreRight(void) {
    return UAEnsureBundleRight(BundleRestoreRight);
}

int32_t UAEnsureBundleExpiryRight(void) {
    return UAEnsureBundleRight(BundleExpiryRight);
}

static NSData *UABundlePrompt(NSString *basename, NSString *bundleIdentifier, NSString *format) {
    // The caller checked the on-disk identity. Reject formatting controls
    // that could make the reviewed target appear as a different path.
    NSCharacterSet *controls = NSCharacterSet.controlCharacterSet;
    NSCharacterSet *newlines = NSCharacterSet.newlineCharacterSet;
    if (basename.length == 0 || bundleIdentifier.length == 0
        || [basename rangeOfCharacterFromSet:controls].location != NSNotFound
        || [basename rangeOfCharacterFromSet:newlines].location != NSNotFound
        || [bundleIdentifier rangeOfCharacterFromSet:controls].location != NSNotFound
        || [bundleIdentifier rangeOfCharacterFromSet:newlines].location != NSNotFound) {
        return nil;
    }
    NSString *text = [NSString stringWithFormat:format, basename, bundleIdentifier];
    return [text dataUsingEncoding:NSUTF8StringEncoding];
}

static OSStatus UARequestBundleRight(AuthorizationRef authorization, const char *right,
                                     NSData *prompt) {
    AuthorizationItem requested = {.name = right};
    AuthorizationRights rights = {.count = 1, .items = &requested};
    AuthorizationItem promptItem = {
        .name = kAuthorizationEnvironmentPrompt,
        .valueLength = prompt.length,
        .value = (void *)prompt.bytes,
    };
    AuthorizationEnvironment environment = {.count = 1, .items = &promptItem};
    AuthorizationRights *granted = NULL;
    // Timeout-zero credentials must be obtained at the point of use.
    OSStatus status = AuthorizationCopyRights(
        authorization, &rights, &environment,
        kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights,
        &granted
    );
    if (status == errAuthorizationSuccess
        && (granted == NULL || granted->count != 1 || granted->items == NULL
            || granted->items[0].name == NULL
            || strcmp(granted->items[0].name, right) != 0)) {
        status = errAuthorizationDenied;
    }
    if (granted != NULL) {
        AuthorizationFreeItemSet(granted);
    }
    return status;
}

static int32_t UAAuthenticateAndConsumeBundleAuthorization(
    NSData *externalForm,
    const char *right,
    NSString *basename,
    NSString *bundleIdentifier,
    NSString *promptFormat
) {
    AuthorizationExternalForm form;
    if (geteuid() != 0 || externalForm.length != sizeof(form)) {
        return EACCES;
    }
    __attribute__((objc_precise_lifetime)) NSData *prompt =
        UABundlePrompt(basename, bundleIdentifier, promptFormat);
    if (prompt == nil) {
        return EACCES;
    }

    [externalForm getBytes:&form length:sizeof(form)];
    AuthorizationRef authorization = NULL;
    OSStatus status = AuthorizationCreateFromExternalForm(&form, &authorization);
    (void)memset_s(&form, sizeof(form), 0, sizeof(form));
    if (status != errAuthorizationSuccess) {
        return UAStatusToError(status);
    }

    NSDictionary<NSString *, id> *rule = nil;
    OSStatus released = errAuthorizationDenied;
    @try {
        status = UACopyBundleRule(right, &rule);
        if (status == errAuthorizationSuccess) {
            status = UAHasExpectedBundleRule(rule)
                ? UARequestBundleRight(authorization, right, prompt)
                : errAuthorizationDenied;
        }
    } @finally {
        released = AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
    }
    if (status != errAuthorizationSuccess) {
        return UAStatusToError(status);
    }
    if (released != errAuthorizationSuccess) {
        return UAStatusToError(released);
    }

    // Reject drift during the system prompt as well.
    status = UACopyBundleRule(right, &rule);
    if (status != errAuthorizationSuccess) {
        return UAStatusToError(status);
    }
    return UAHasExpectedBundleRule(rule) ? 0 : EACCES;
}

int32_t UAAuthenticateAndConsumeBundleQuarantineAuthorization(
    NSData *externalForm,
    NSString *basename,
    NSString *bundleIdentifier
) {
    return UAAuthenticateAndConsumeBundleAuthorization(
        externalForm, BundleQuarantineRight, basename, bundleIdentifier,
        @"Allow UninstallAny to move “/Applications/%@” (%@) into quarantine?"
    );
}

int32_t UAAuthenticateAndConsumeBundleRestoreAuthorization(
    NSData *externalForm,
    NSString *basename,
    NSString *bundleIdentifier
) {
    return UAAuthenticateAndConsumeBundleAuthorization(
        externalForm, BundleRestoreRight, basename, bundleIdentifier,
        @"Allow UninstallAny to restore the quarantined application to “/Applications/%@” (%@)?"
    );
}

int32_t UAAuthenticateAndConsumeBundleExpiryAuthorization(
    NSData *externalForm,
    NSString *basename,
    NSString *bundleIdentifier
) {
    return UAAuthenticateAndConsumeBundleAuthorization(
        externalForm, BundleExpiryRight, basename, bundleIdentifier,
        @"Permanently remove the expired quarantine backup of “%@” (%@)?"
    );
}

#elif defined(UA_AUTHORIZATION_CLIENT)

int32_t UACreateEmptyBundleAuthorization(AuthorizationRef *reference, NSData **externalForm) {
    *reference = NULL;
    *externalForm = nil;
    AuthorizationRef authorization = NULL;
    OSStatus status = AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &authorization);
    if (status != errAuthorizationSuccess) {
        return UAStatusToError(status);
    }

    AuthorizationExternalForm form = {0};
    status = AuthorizationMakeExternalForm(authorization, &form);
    if (status == errAuthorizationSuccess) {
        // The caller owns the empty reference until the XPC exchange ends.
        *reference = authorization;
        *externalForm = [NSData dataWithBytes:&form length:sizeof(form)];
    } else {
        AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
    }
    (void)memset_s(&form, sizeof(form), 0, sizeof(form));
    return UAStatusToError(status);
}

#endif
