/*
 * FF MAX License Tweak
 * Hooks Free Fire MAX to validate UDID against license server
 * before loading modded asset bundles.
 *
 * Build: make package FINALPACKAGE=1
 * Target: com.dts.freefiremax (iOS arm64)
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonCrypto.h>
#import <dlfcn.h>

// --- Configuration (production keys synced with server) ---
static NSString *const kServerURL = @"http://208.84.100.17:9843";
static NSString *const kHMACSecret = @"b1Mzm13QNyWDljpfIQZxZ60FF6vw2mgYOJoBYUi9Y40";
static NSString *const kAESKey = @"BTIhftRGMtIbf-JtJdQjFRM7Rf5t_-KO";

// Encrypted bundle filename (ships with the tweak or placed via Filza)
static NSString *const kEncryptedBundleName = @"assetindexer.enc";

// Original bundle name in the game's content cache
static NSString *const kOriginalBundleName = @"assetindexer.PENojQAQf9a1l6Dzjs0n1Z3rtVU~3D";

// Asset path relative to Documents
static NSString *const kAssetRelativePath = @"contentcache/Compulsory/ios/gameassetbundles/avatar";

// Grace period: how long (seconds) a cached validation stays valid
static const NSTimeInterval kGracePeriod = 24 * 3600; // 24 hours

// Cache key for UserDefaults
static NSString *const kCacheKey = @"_lvc_ts";
static NSString *const kCacheValidKey = @"_lvc_ok";


#pragma mark - UDID Resolution

static NSString *getDeviceUDID(void) {
    // Method 1: MobileGestalt (jailbroken — requires entitlement or root)
    void *gestalt = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
    if (gestalt) {
        typedef CFStringRef (*MGCopyAnswer_t)(CFStringRef);
        MGCopyAnswer_t MGCopyAnswer = (MGCopyAnswer_t)dlsym(gestalt, "MGCopyAnswer");
        if (MGCopyAnswer) {
            CFStringRef udid = MGCopyAnswer(CFSTR("UniqueDeviceID"));
            if (udid) {
                NSString *result = (__bridge_transfer NSString *)udid;
                dlclose(gestalt);
                return result;
            }
        }
        dlclose(gestalt);
    }

    // Method 2: identifierForVendor (sideloaded — less unique but works without JB)
    NSUUID *vendorID = [[UIDevice currentDevice] identifierForVendor];
    if (vendorID) {
        return [vendorID UUIDString];
    }

    return nil;
}


#pragma mark - Crypto Helpers

static NSData *aesDecrypt(NSData *data, NSString *keyString) {
    // Key: raw bytes from the 32-char key string
    NSData *keyData = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    if (keyData.length < kCCKeySizeAES256) return nil;

    // IV is prepended to the ciphertext (first 16 bytes)
    if (data.length < kCCBlockSizeAES128) return nil;

    NSData *iv = [data subdataWithRange:NSMakeRange(0, kCCBlockSizeAES128)];
    NSData *ciphertext = [data subdataWithRange:NSMakeRange(kCCBlockSizeAES128, data.length - kCCBlockSizeAES128)];

    size_t bufferSize = ciphertext.length + kCCBlockSizeAES128;
    NSMutableData *buffer = [NSMutableData dataWithLength:bufferSize];

    size_t numBytesDecrypted = 0;
    CCCryptorStatus status = CCCrypt(
        kCCDecrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        keyData.bytes, kCCKeySizeAES256,
        iv.bytes,
        ciphertext.bytes, ciphertext.length,
        buffer.mutableBytes, bufferSize,
        &numBytesDecrypted
    );

    if (status != kCCSuccess) return nil;

    buffer.length = numBytesDecrypted;
    return buffer;
}


static NSString *hmacSHA256(NSString *data, NSString *key) {
    const char *cKey = [key UTF8String];
    const char *cData = [data UTF8String];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];

    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), digest);

    NSMutableString *hash = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", digest[i]];
    }
    return hash;
}


#pragma mark - File Path Helpers

static NSString *getDocumentsPath(void) {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    return paths.firstObject;
}

static NSString *getAssetBundlePath(void) {
    return [[getDocumentsPath() stringByAppendingPathComponent:kAssetRelativePath]
            stringByAppendingPathComponent:kOriginalBundleName];
}

static NSString *getEncryptedBundlePath(void) {
    // Check multiple possible locations for the encrypted bundle
    NSFileManager *fm = [NSFileManager defaultManager];

    // Location 1: Same directory as the original asset
    NSString *path1 = [[getDocumentsPath() stringByAppendingPathComponent:kAssetRelativePath]
                        stringByAppendingPathComponent:kEncryptedBundleName];
    if ([fm fileExistsAtPath:path1]) return path1;

    // Location 2: Documents root
    NSString *path2 = [getDocumentsPath() stringByAppendingPathComponent:kEncryptedBundleName];
    if ([fm fileExistsAtPath:path2]) return path2;

    // Location 3: Tweak's own bundle (for sideloaded IPA)
    NSString *path3 = [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:kEncryptedBundleName];
    if ([fm fileExistsAtPath:path3]) return path3;

    return nil;
}


#pragma mark - License Validation

static BOOL verifyServerResponse(NSDictionary *response) {
    // Extract signature
    NSString *signature = response[@"signature"];
    if (!signature) return NO;

    // Reconstruct the signed payload (all keys except "signature", sorted, compact JSON)
    NSMutableDictionary *payload = [response mutableCopy];
    [payload removeObjectForKey:@"signature"];

    // Sort keys and build compact JSON
    NSArray *sortedKeys = [[payload allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray *pairs = [NSMutableArray array];
    for (NSString *key in sortedKeys) {
        id value = payload[key];
        if ([value isKindOfClass:[NSString class]]) {
            [pairs addObject:[NSString stringWithFormat:@"\"%@\":\"%@\"", key, value]];
        } else if ([value isKindOfClass:[NSNumber class]]) {
            // Check if it's a boolean
            if (strcmp([value objCType], @encode(BOOL)) == 0 || strcmp([value objCType], "c") == 0) {
                [pairs addObject:[NSString stringWithFormat:@"\"%@\":%@", key, [value boolValue] ? @"true" : @"false"]];
            } else {
                [pairs addObject:[NSString stringWithFormat:@"\"%@\":%@", key, value]];
            }
        } else if ([value isKindOfClass:[NSNull class]]) {
            [pairs addObject:[NSString stringWithFormat:@"\"%@\":null", key]];
        }
    }
    NSString *jsonPayload = [NSString stringWithFormat:@"{%@}", [pairs componentsJoinedByString:@","]];

    // Compute expected HMAC
    NSString *expected = hmacSHA256(jsonPayload, kHMACSecret);

    return [expected isEqualToString:signature];
}


static void validateAndLoadBundle(void) {
    @autoreleasepool {
        NSString *udid = getDeviceUDID();
        if (!udid) {
            NSLog(@"[FFML] Failed to get device UDID");
            return;
        }

        NSString *encPath = getEncryptedBundlePath();
        if (!encPath) {
            NSLog(@"[FFML] Encrypted bundle not found");
            return;
        }

        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];

        // --- Attempt online validation ---
        NSString *urlString = [NSString stringWithFormat:@"%@/api/license/validate?udid=%@",
                               kServerURL,
                               [udid stringByAddingPercentEncodingWithAllowedCharacters:
                                [NSCharacterSet URLQueryAllowedCharacterSet]]];

        NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:[NSURL URLWithString:urlString]];
        request.timeoutInterval = 10.0;
        request.HTTPMethod = @"GET";

        __block NSDictionary *responseDict = nil;
        __block BOOL requestDone = NO;

        // Use ephemeral session to avoid caching credentials/cookies in the game's storage.
        // If using HTTP (not recommended), you may need to bypass ATS at the plist level
        // or use a server with a valid HTTPS certificate.
        NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        sessionConfig.timeoutIntervalForRequest = 10.0;
        sessionConfig.timeoutIntervalForResource = 15.0;
        NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionConfig];

        NSURLSessionDataTask *task = [session
            dataTaskWithRequest:request
            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                if (!error && data) {
                    NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
                    if (httpResp.statusCode == 200) {
                        responseDict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                    }
                }
                requestDone = YES;
            }];
        [task resume];

        // Block until response or timeout
        NSDate *timeout = [NSDate dateWithTimeIntervalSinceNow:12.0];
        while (!requestDone && [[NSDate date] compare:timeout] == NSOrderedAscending) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:
             [NSDate dateWithTimeIntervalSinceNow:0.1]];
        }

        BOOL valid = NO;

        if (responseDict) {
            // Verify HMAC signature
            if (verifyServerResponse(responseDict)) {
                valid = [responseDict[@"valid"] boolValue];
                if (valid) {
                    // Cache the successful validation
                    [defaults setDouble:[[NSDate date] timeIntervalSince1970] forKey:kCacheKey];
                    [defaults setBool:YES forKey:kCacheValidKey];
                    [defaults synchronize];
                }
            } else {
                NSLog(@"[FFML] HMAC verification failed — possible MITM");
            }
        } else {
            // Server unreachable — check grace period cache
            NSTimeInterval lastValidation = [defaults doubleForKey:kCacheKey];
            BOOL lastWasValid = [defaults boolForKey:kCacheValidKey];

            if (lastWasValid && lastValidation > 0) {
                NSTimeInterval elapsed = [[NSDate date] timeIntervalSince1970] - lastValidation;
                if (elapsed < kGracePeriod) {
                    valid = YES;
                    NSLog(@"[FFML] Using cached validation (%.0f seconds remaining)",
                          kGracePeriod - elapsed);
                }
            }
        }

        if (!valid) {
            NSLog(@"[FFML] License validation failed");
            // Clear cache on explicit rejection
            if (responseDict) {
                [defaults removeObjectForKey:kCacheKey];
                [defaults removeObjectForKey:kCacheValidKey];
                [defaults synchronize];
            }
            return;
        }

        // --- Decrypt and deploy the modded bundle ---
        NSData *encData = [NSData dataWithContentsOfFile:encPath];
        if (!encData || encData.length == 0) {
            NSLog(@"[FFML] Failed to read encrypted bundle");
            return;
        }

        NSData *decrypted = aesDecrypt(encData, kAESKey);
        if (!decrypted || decrypted.length == 0) {
            NSLog(@"[FFML] Bundle decryption failed");
            return;
        }

        // Verify it's a valid UnityFS bundle
        if (decrypted.length < 8) {
            NSLog(@"[FFML] Decrypted data too small");
            return;
        }

        const char *header = (const char *)decrypted.bytes;
        if (memcmp(header, "UnityFS\0", 8) != 0) {
            NSLog(@"[FFML] Decrypted data is not a valid UnityFS bundle");
            return;
        }

        // Write to the game's asset path
        NSString *targetPath = getAssetBundlePath();
        NSFileManager *fm = [NSFileManager defaultManager];

        // Ensure directory exists
        NSString *targetDir = [targetPath stringByDeletingLastPathComponent];
        if (![fm fileExistsAtPath:targetDir]) {
            [fm createDirectoryAtPath:targetDir withIntermediateDirectories:YES attributes:nil error:nil];
        }

        NSError *writeError = nil;
        BOOL written = [decrypted writeToFile:targetPath options:NSDataWritingAtomic error:&writeError];
        if (written) {
            NSLog(@"[FFML] Modded bundle deployed successfully (%lu bytes)", (unsigned long)decrypted.length);
        } else {
            NSLog(@"[FFML] Failed to write bundle: %@", writeError);
        }
    }
}


#pragma mark - Tweak Entry

%hook AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    BOOL result = %orig;

    // Run validation on a background thread to avoid blocking app launch
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        validateAndLoadBundle();
    });

    return result;
}

%end


%ctor {
    // Constructor — runs when the dylib is loaded
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    if (![bundleID isEqualToString:@"com.dts.freefiremax"]) {
        return; // Not our target
    }

    %init;
}
