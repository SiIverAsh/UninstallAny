#import "installer_ownership.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <string.h>
#include <time.h>

enum {
    MaximumReceiptCount = 4096,
    ReceiptQueryBatch = 48,
    MaximumMetadataBytes = 1024 * 1024,
    MaximumBOMBytes = 16 * 1024 * 1024,
    MaximumPathBytes = 4096,
    MaximumNameBytes = 255,
};

static BOOL UAValidPathText(NSString *text, NSUInteger maximumBytes) {
    if (![text isKindOfClass:NSString.class]) {
        return NO;
    }
    NSUInteger bytes = [text lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    return bytes > 0 && bytes <= maximumBytes
        && [text rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location == NSNotFound
        && ![text containsString:@"\\"];
}

static BOOL UAValidPathComponent(NSString *name) {
    return UAValidPathText(name, MaximumNameBytes) && ![name containsString:@"/"]
        && ![name isEqualToString:@"."] && ![name isEqualToString:@".."];
}

static NSArray<NSString *> *UARelativePathParts(NSString *path) {
    if (!UAValidPathText(path, MaximumPathBytes)) {
        return nil;
    }
    NSArray<NSString *> *parts = [path componentsSeparatedByString:@"/"];
    for (NSString *part in parts) {
        if (part.length == 0 || [part isEqualToString:@"."] || [part isEqualToString:@".."]) {
            return nil;
        }
    }
    return parts;
}

static BOOL UAHasPossiblePrefix(NSArray<NSString *> *path, NSArray<NSString *> *prefix) {
    if (path.count < prefix.count) {
        return NO;
    }
    for (NSUInteger index = 0; index < prefix.count; index++) {
        NSString *component = path[index];
        NSString *expected = prefix[index];
        // A non-ASCII component may have a spelling that aliases on APFS.
        // Treat ambiguous matches as claims to avoid moving owned files.
        BOOL isASCII = [component lengthOfBytesUsingEncoding:NSUTF8StringEncoding] == component.length
            && [expected lengthOfBytesUsingEncoding:NSUTF8StringEncoding] == expected.length;
        if (isASCII && [component caseInsensitiveCompare:expected] != NSOrderedSame) {
            return NO;
        }
    }
    return YES;
}

static NSArray<NSString *> *UAStartupDataAlias(NSArray<NSString *> *parts) {
    NSArray<NSString *> *prefix = @[@"System", @"Volumes", @"Data"];
    return UAHasPossiblePrefix(parts, prefix)
        ? [parts subarrayWithRange:NSMakeRange(prefix.count, parts.count - prefix.count)]
        : nil;
}

static BOOL UAReceiptIdentifierIsValid(NSString *identifier) {
    if (![identifier isKindOfClass:NSString.class] || identifier.length > MaximumNameBytes) {
        return NO;
    }
    NSData *characters = [identifier dataUsingEncoding:NSASCIIStringEncoding];
    const unsigned char *bytes = characters.bytes;
    BOOL hasComponent = NO;
    for (NSUInteger index = 0; index < characters.length; index++) {
        unsigned char character = bytes[index];
        BOOL alphanumeric = (character >= 'A' && character <= 'Z')
            || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9');
        if (alphanumeric || (index > 0 && (character == '-' || character == '_'))) {
            hasComponent = YES;
        } else if (character == '.' && hasComponent) {
            hasComponent = NO;
        } else {
            return NO;
        }
    }
    return hasComponent;
}

static void UAHashEvidence(CC_SHA256_CTX *hash, NSData *bytes) {
    uint64_t length = bytes.length;
    CC_SHA256_Update(hash, &length, sizeof(length));
    CC_SHA256_Update(hash, bytes.bytes, (CC_LONG)bytes.length);
}

static id UAReadPropertyList(NSData *bytes) {
    if (bytes.length == 0) {
        return nil;
    }
    return [NSPropertyListSerialization propertyListWithData:bytes
                                                    options:NSPropertyListImmutable
                                                     format:NULL error:NULL];
}

static int UACheckReceiptAnchor(NSString *path, uint64_t deadline,
                                CC_SHA256_CTX *hash, BOOL *claimed) {
    NSData *output = nil;
    int status = UARunInstallerQuery(@[@"--volume", @"/", @"--file-info-plist", path],
                                     MaximumMetadataBytes, deadline, &output);
    if (status != 0) {
        return status;
    }
    id record = UAReadPropertyList(output);
    if (![record isKindOfClass:NSDictionary.class] || ![path isEqual:record[@"path"]]
        || ![record[@"path-info"] isKindOfClass:NSArray.class]) {
        return EBADMSG;
    }
    *claimed = [record[@"path-info"] count] != 0;
    UAHashEvidence(hash, output);
    return 0;
}

static int UAReadReceiptIDs(uint64_t deadline, NSArray<NSString *> **identifiers) {
    NSData *output = nil;
    int status = UARunInstallerQuery(@[@"--volume", @"/", @"--pkgs-plist"],
                                     MaximumMetadataBytes, deadline, &output);
    if (status != 0) {
        return status;
    }
    id decoded = UAReadPropertyList(output);
    if (![decoded isKindOfClass:NSArray.class] || [decoded count] > MaximumReceiptCount) {
        return EBADMSG;
    }
    NSMutableSet<NSString *> *unique = [NSMutableSet set];
    for (id identifier in decoded) {
        if (!UAReceiptIdentifierIsValid(identifier) || [unique containsObject:identifier]) {
            return EBADMSG;
        }
        [unique addObject:identifier];
    }
    *identifiers = [unique.allObjects sortedArrayUsingSelector:@selector(compare:)];
    return 0;
}

static NSArray<NSString *> *UAGroupedReceiptQuery(NSArray<NSString *> *packages,
                                                 NSRange range, NSString *command) {
    NSMutableArray<NSString *> *arguments = [NSMutableArray arrayWithArray:@[@"--volume", @"/"]];
    for (NSUInteger index = range.location; index < NSMaxRange(range); index++) {
        [arguments addObject:command];
        [arguments addObject:packages[index]];
    }
    return arguments;
}

static NSArray<NSString *> *UAInstallLocation(NSDictionary<NSString *, NSString *> *record) {
    if (![@"/" isEqualToString:record[@"volume"]]) {
        return nil;
    }
    NSString *location = record[@"location"];
    if ([location isEqualToString:@"/"] || [location isEqualToString:@"."]) {
        return @[];
    }
    if ([location hasPrefix:@"/"]) {
        location = [location substringFromIndex:1];
    }
    if ([location hasSuffix:@"/"]) {
        location = [location substringToIndex:location.length - 1];
    }
    return UARelativePathParts(location);
}

static int UACollectReceiptBases(NSData *output, NSArray<NSString *> *packages,
                                 NSRange range, NSArray<NSString *> *target,
                                 NSArray<NSMutableArray<NSString *> *> *bomGroups, BOOL *claimed) {
    NSString *text = [[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding];
    if (![text hasSuffix:@"\n"]) {
        return EBADMSG;
    }
    NSArray<NSString *> *lines = [text componentsSeparatedByString:@"\n"];
    NSUInteger lineIndex = 0;
    for (NSUInteger index = range.location; index < NSMaxRange(range); index++) {
        NSString *package = packages[index];
        NSString *header = [@"package-id: " stringByAppendingString:package];
        if (lineIndex >= lines.count || ![header isEqualToString:lines[lineIndex++]]) {
            return EBADMSG;
        }
        NSMutableDictionary<NSString *, NSString *> *fields = [NSMutableDictionary dictionary];
        while (lineIndex < lines.count && ![lines[lineIndex] hasPrefix:@"package-id: "]) {
            NSString *line = lines[lineIndex++];
            if (line.length == 0) {
                continue;
            }
            NSRange separator = [line rangeOfString:@": "];
            if (separator.location == NSNotFound || separator.location == 0
                || !UAValidPathText(line, MaximumPathBytes)) {
                return EBADMSG;
            }
            NSString *key = [line substringToIndex:separator.location];
            if (fields[key] != nil) {
                return EBADMSG;
            }
            fields[key] = [line substringFromIndex:NSMaxRange(separator)];
        }
        NSArray<NSString *> *base = UAInstallLocation(fields);
        if (base == nil) {
            return EBADMSG;
        }
        NSArray<NSString *> *alias = UAStartupDataAlias(base);
        if (UAHasPossiblePrefix(base, target) || (alias != nil && UAHasPossiblePrefix(alias, target))) {
            *claimed = YES;
            return 0;
        }
        if (UAHasPossiblePrefix(target, base)) {
            [bomGroups[base.count] addObject:package];
        }
        if (alias != nil && UAHasPossiblePrefix(target, alias)) {
            [bomGroups[alias.count] addObject:package];
        }
    }
    return lineIndex == lines.count ? 0 : EBADMSG;
}

static int UACheckReceiptFiles(NSData *output, NSArray<NSString *> *suffix,
                               uint64_t deadline, BOOL *claimed) {
    const char *bytes = output.bytes;
    NSUInteger length = output.length;
    if (length == 0) {
        return EBADMSG;
    }
    for (NSUInteger offset = 0; offset < length;) {
        @autoreleasepool {
            const char *begin = bytes + offset;
            const char *end = memchr(begin, '\n', length - offset);
            if (end == NULL || end == begin || (size_t)(end - begin) > MaximumPathBytes) {
                return EBADMSG;
            }
            offset += (NSUInteger)(end - begin) + 1;
            if (clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) >= deadline) {
                return ETIMEDOUT;
            }
            NSString *path = [[NSString alloc] initWithBytes:begin length:(NSUInteger)(end - begin)
                                                   encoding:NSUTF8StringEncoding];
            if ([path isEqualToString:@"."]) {
                continue;
            }
            if ([path hasPrefix:@"./"]) {
                path = [path substringFromIndex:2];
            }
            NSArray<NSString *> *parts = UARelativePathParts(path);
            if (parts == nil) {
                return EBADMSG;
            }
            NSArray<NSString *> *alias = UAStartupDataAlias(parts);
            if (UAHasPossiblePrefix(parts, suffix) || (alias != nil && UAHasPossiblePrefix(alias, suffix))) {
                *claimed = YES;
                return 0;
            }
        }
    }
    return 0;
}

static int UAReadReceiptSnapshot(NSArray<NSString *> *target, NSArray<NSString *> *anchors,
                                 uint64_t deadline, NSData **digest, BOOL *claimed) {
    NSArray<NSString *> *packages = nil;
    int status = UAReadReceiptIDs(deadline, &packages);
    if (status != 0) {
        return status;
    }
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    for (NSString *anchor in anchors) {
        status = UACheckReceiptAnchor(anchor, deadline, &hash, claimed);
        if (status != 0 || *claimed) {
            return status;
        }
    }
    NSArray<NSMutableArray<NSString *> *> *bomGroups = @[[NSMutableArray array], [NSMutableArray array]];
    for (NSUInteger start = 0; start < packages.count; start += ReceiptQueryBatch) {
        @autoreleasepool {
            NSRange range = NSMakeRange(start, MIN(ReceiptQueryBatch, packages.count - start));
            NSData *output = nil;
            status = UARunInstallerQuery(UAGroupedReceiptQuery(packages, range, @"--pkg-info"),
                                         MaximumMetadataBytes, deadline, &output);
            if (status != 0) {
                return status;
            }
            status = UACollectReceiptBases(output, packages, range, target, bomGroups, claimed);
            if (status != 0 || *claimed) {
                return status;
            }
            UAHashEvidence(&hash, output);
        }
    }
    // Group only receipts whose bases share the same candidate suffix. Their
    // concatenated BOM entries then need no undocumented record separators.
    for (NSUInteger depth = 0; depth < bomGroups.count; depth++) {
        NSArray<NSString *> *group = bomGroups[depth];
        NSArray<NSString *> *suffix = [target subarrayWithRange:NSMakeRange(depth, target.count - depth)];
        for (NSUInteger start = 0; start < group.count; start += ReceiptQueryBatch) {
            @autoreleasepool {
                NSRange range = NSMakeRange(start, MIN(ReceiptQueryBatch, group.count - start));
                NSData *output = nil;
                status = UARunInstallerQuery(UAGroupedReceiptQuery(group, range, @"--files"),
                                             MaximumBOMBytes, deadline, &output);
                if (status != 0) {
                    return status;
                }
                status = UACheckReceiptFiles(output, suffix, deadline, claimed);
                if (status != 0 || *claimed) {
                    return status;
                }
                UAHashEvidence(&hash, output);
            }
        }
    }
    NSArray<NSString *> *current = nil;
    status = UAReadReceiptIDs(deadline, &current);
    if (status != 0 || ![packages isEqualToArray:current]) {
        return status != 0 ? status : ESTALE;
    }
    for (NSString *package in packages) {
        UAHashEvidence(&hash, [package dataUsingEncoding:NSASCIIStringEncoding]);
    }
    unsigned char bytes[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(bytes, &hash);
    *digest = [NSData dataWithBytes:bytes length:sizeof(bytes)];
    return 0;
}

int UACheckInstallerBundleOwnership(NSString *basename, NSString *executable,
                                    uint64_t deadline, BOOL *claimed) {
    *claimed = NO;
    if (!UAValidPathComponent(basename) || [basename hasPrefix:@"."]
        || [basename.pathExtension caseInsensitiveCompare:@"app"] != NSOrderedSame
        || !UAValidPathComponent(executable)) {
        return EINVAL;
    }
    NSArray<NSString *> *target = @[@"Applications", basename];
    NSString *bundle = [@"/Applications" stringByAppendingPathComponent:basename];
    NSArray<NSString *> *anchors = @[
        bundle,
        [bundle stringByAppendingPathComponent:@"Contents/Info.plist"],
        [[bundle stringByAppendingPathComponent:@"Contents/MacOS"] stringByAppendingPathComponent:executable],
    ];
    NSData *first = nil;
    int status = UAReadReceiptSnapshot(target, anchors, deadline, &first, claimed);
    if (status != 0 || *claimed) {
        return status;
    }
    // Replacing a receipt can preserve its ID, so compare both its observed
    // data and the catalog before reporting a negative receipt result.
    NSData *second = nil;
    status = UAReadReceiptSnapshot(target, anchors, deadline, &second, claimed);
    if (status != 0 || *claimed) {
        return status;
    }
    if (clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) >= deadline) {
        return ETIMEDOUT;
    }
    return [first isEqualToData:second] ? 0 : ESTALE;
}
