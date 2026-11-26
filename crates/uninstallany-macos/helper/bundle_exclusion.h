#pragma once

#import <Foundation/Foundation.h>

// Observes executable paths across users. This does not freeze new launches.
int UACheckSystemBundleActivity(NSString *basename, int bundleDescriptor);

// Checks bundle service declarations and standard system launchd manifests.
int UACheckSystemBundleBackground(NSString *basename, NSString *bundleIdentifier,
                                  int bundleDescriptor);

// Requires an empty or absent Caskroom at both standard Homebrew prefixes.
int UACheckStandardCaskrooms(void);

// Verifies one independently sealed Developer ID application. The strict
// tree gate rules out following links or including nested app bundles.
int UACheckStandaloneBundleSignature(NSString *basename, NSString *bundleIdentifier,
                                     int applicationsDescriptor, int bundleDescriptor,
                                     NSData **codeDirectoryHash);

int UACheckProtectedStandaloneBundleTree(int bundleDescriptor);
