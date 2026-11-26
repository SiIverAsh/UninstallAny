#pragma once

#import <Foundation/Foundation.h>

#include <stddef.h>
#include <stdint.h>

// Runs only read-only pkgutil queries against the startup receipt catalog.
// The absolute monotonic deadline is shared by every query in one check.
int UARunInstallerQuery(NSArray<NSString *> *arguments, size_t maximumOutput,
                        uint64_t monotonicDeadline, NSData **output);

// Requires a guarded bundle on the startup data volume and a verified
// executable basename. A zero return describes Installer receipts only.
int UACheckInstallerBundleOwnership(NSString *basename, NSString *executable,
                                    uint64_t monotonicDeadline, BOOL *claimed);
