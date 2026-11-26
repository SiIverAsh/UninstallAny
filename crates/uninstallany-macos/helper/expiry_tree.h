#pragma once

#import <Foundation/Foundation.h>

// The caller verifies the slot and the journaled APFS volume UUID.
// Snapshots contain the root first and then sorted member fingerprints.
int UACaptureExpiryTree(int bundleDescriptor, NSArray<NSDictionary *> **entries);

// Verifies each remaining member against the original inventory.
int UACheckRemainingExpiryTree(int bundleDescriptor, NSArray<NSDictionary *> *approved,
                               NSArray<NSDictionary *> **remaining);

// The caller must hold the slot lock and persist the disposal commitment.
// On error the caller reconciles the remaining tree with that commitment.
int UARemovePendingExpiryTree(int slotDescriptor, const char *pendingName,
                             NSArray<NSDictionary *> *reviewedRemaining,
                             BOOL (^mayContinue)(void));
