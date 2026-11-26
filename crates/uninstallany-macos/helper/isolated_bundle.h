#pragma once

#import <Foundation/Foundation.h>

#include <stdint.h>
#include <sys/types.h>

typedef struct {
    int applications;
    int bundle;
} UAReviewedBundle;

// Opens the same no-follow objects bound by the reviewed root stamp.
// A requested receipt executable is checked on the startup data volume.
// Release successful results with UACloseReviewedApplicationBundle.
int UAOpenReviewedApplicationBundle(NSString *basename, NSString *bundleIdentifier,
                                    NSString *rootStamp, UAReviewedBundle *reviewed,
                                    NSString **receiptExecutable);
void UACloseReviewedApplicationBundle(UAReviewedBundle *reviewed);

// Verifies the descriptor-rooted tree without reading through links.
int UACheckProtectedBundleTree(int bundleDescriptor);

// Internal transaction primitives. Callers must enforce whole-bundle
// ownership, the reviewed plan and separate authorization for each move.
// The callback runs just before each exclusive rename and must be fast.
NSDictionary *UAQuarantineVerifiedBundle(uid_t authenticatedUID, NSString *operationID,
                                         int applicationsFD, int bundleFD, NSString *basename,
                                         NSString *identifier, NSString *rootStamp,
                                         uint16_t retentionDays,
                                         BOOL (^mayCommit)(void));
// The read-only query offers a restore stamp only when the held bundle
// matches its verified record and the original name is free.
NSDictionary *UAQueryBundleQuarantine(uid_t authenticatedUID, NSString *operationID);
// A null cursor pair starts a stable catalog and an existing pair continues
// that catalog. Entry statuses are sampled through the held UID directory.
int UAListBundleQuarantine(uid_t authenticatedUID, NSString *afterOperationID,
                           NSString *expectedCatalogStamp, NSDictionary **page);
// Reopens the protected original directory and checks the confirmed stamp
// under the slot lock before writing the intent and before renaming.
NSDictionary *UARestoreVerifiedBundle(uid_t authenticatedUID, NSString *operationID,
                                      NSString *expectedRestoreStamp, BOOL (^mayCommit)(void));

// Captures the exact existing contents of one expired, durable backup.
// This also reviews the remaining members of an interrupted expiry.
int UAPreviewBundleExpiry(uid_t authenticatedUID, NSString *operationID, NSDictionary **review);

// Detaches the approved backup into the private pending slot and persists
// the corresponding commitment before deleting any member.
NSDictionary *UAExpireVerifiedBundle(uid_t authenticatedUID, NSString *operationID,
                                     NSString *expectedExpiryStamp, BOOL (^mayCommit)(void));
