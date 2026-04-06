#include <Foundation/Foundation.h>
#include <Foundation/NSObjCRuntime.h>
#include <objc/runtime.h>
// #include <substrate.h>  // disabled — using objc runtime directly

#define LOG(fmt, ...) NSLog(@"[rubberstamp] " fmt "\n", ##__VA_ARGS__)

#pragma mark - Forward declarations
__attribute__((constructor)) void init(void);
void sanitize(NSMutableDictionary *plist);

@interface MICodeSigningInfo : NSObject
- (instancetype)initWithSignerIdentity:(NSString *)signerIdentity
                    signerOrganization:(NSString *)signerOrganization
                    codeInfoIdentifier:(NSString *)codeInfoIdentifier
                        teamIdentifier:(NSString *)teamIdentifier
                      signatureVersion:(NSString *)signatureVersion
                          entitlements:(id)entitlements
                            signerType:(int)signerType
                           profileType:(int)profileType
                     signingInfoSource:(int)signingInfoSource
                    launchWarningData:(id)launchWarningData;
@end

#if 0
#pragma mark - Hooks

static NSMutableDictionary *(*orig_MILoadInfoPlist)(NSURL *bundle, NSSet *keys);
static NSMutableDictionary *hooked_MILoadInfoPlist(NSURL *bundle, NSSet *keys) {
  NSMutableDictionary *plist = orig_MILoadInfoPlist(bundle, keys);
  sanitize(plist);
  return plist;
}

static NSMutableDictionary *(*orig_MILoadInfoPlistWithError)(NSURL *bundle,
                                                             NSSet *keys,
                                                             NSError **err);
static NSMutableDictionary *
hooked_MILoadInfoPlistWithError(NSURL *bundle, NSSet *keys, NSError **err) {
  NSMutableDictionary *plist = orig_MILoadInfoPlistWithError(bundle, keys, err);
  sanitize(plist);
  return plist;
}

#endif

// Generic validation bypass — always returns YES and clears the error out-param
static BOOL hooked_validatePass(id self, SEL _cmd, NSError **err) {
  if (err)
    *err = nil;
  return YES;
}

// Simple YES stub for methods with no error out-param (e.g. bool getters)
static BOOL hooked_alwaysYes(id self, SEL _cmd) { return YES; }

// performValidationWithError: hook — calls through, and on failure fabricates
// signing info (like the simulator stub) so codeInfoIdentifier isn't null.
static BOOL (*orig_performValidation)(id self, SEL _cmd, NSError **err);
static BOOL hooked_performValidation(id self, SEL _cmd, NSError **err) {
  BOOL ok = orig_performValidation(self, _cmd, err);
  if (ok)
    return YES;

  // Fabricate signing info matching the bundle identifier
  id bundle = [self valueForKey:@"bundle"];
  NSString *bundleId = [bundle valueForKey:@"identifier"];
  LOG(@"fabricating signing info for %@", bundleId);

  id sigInfo = [[NSClassFromString(@"MICodeSigningInfo") alloc]
      initWithSignerIdentity:@"Apple iPhone OS Application Signing"
          signerOrganization:@"Apple Inc."
          codeInfoIdentifier:bundleId
              teamIdentifier:@"FAKETEAMID"
            signatureVersion:@"1"
                entitlements:nil
                  signerType:2
                 profileType:1
           signingInfoSource:1
           launchWarningData:nil];

  [self setValue:sigInfo forKey:@"signingInfo"];

  if (err)
    *err = nil;
  return YES;
}

#pragma mark - Entry

static void hookValidation(Class cls, SEL sel, IMP replacement) {
  if (!cls)
    return;
  Method m = class_getInstanceMethod(cls, sel);
  if (!m) {
    LOG(@"method %s not found on %s", sel_getName(sel), class_getName(cls));
    return;
  }
  method_setImplementation(m, replacement);
  LOG(@"hooked %s on %s", sel_getName(sel), class_getName(cls));
}

void init() {
  LOG(@"loaded in installd (%d)", getpid());

#if 0
  MSImageRef image = MSGetImageByName(
      "/System/Library/PrivateFrameworks/InstalledContentLibrary.framework/"
      "InstalledContentLibrary");
  if (!image) {
    LOG(@"failed to find InstalledContentLibrary framework");
    return;
  }

  // MILoadInfoPlist(NSURL *bundle, NSSet *keys);
  void *symbol1 = MSFindSymbol(image, "_MILoadInfoPlist");
  if (symbol1) {
    MSHookFunction(symbol1, (void *)&hooked_MILoadInfoPlist,
                   (void **)&orig_MILoadInfoPlist);
  }

  // MILoadInfoPlistWithErorr(NSURL *bundle, NSSet *keys, NSError **err);
  void *symbol2 = MSFindSymbol(image, "_MILoadInfoPlistWithError");
  if (symbol2) {
    MSHookFunction(symbol2, (void *)&hooked_MILoadInfoPlistWithError,
                   (void **)&orig_MILoadInfoPlistWithError);
  }
#endif

  // Bypass bundle validation — minimum kill switch (3 hooks).
  // See report.md for the full call tree and rationale.
  Class MIBundle = objc_getClass("MIBundle");
  Class MIPluginKitBundle = objc_getClass("MIPluginKitBundle");
  Class MIExtensionKitBundle = objc_getClass("MIExtensionKitBundle");

  // Covers _validateNSExtension + _validateXPCService (user's error)
  hookValidation(MIPluginKitBundle,
                 @selector(validateBundleMetadataWithError:),
                 (IMP)hooked_validatePass);
  // Covers ExtensionKit delegate class + Swift entry checks
  hookValidation(MIExtensionKitBundle,
                 @selector(validateBundleMetadataWithError:),
                 (IMP)hooked_validatePass);
  // Covers loop-level checks (duplicates, WatchKit constraints)
  hookValidation(MIBundle, @selector(validatePluginKitMetadataWithError:),
                 (IMP)hooked_validatePass);

  // Code signature verification — calls through, fabricates signing info on failure
  Class MICodeSigningVerifier = objc_getClass("MICodeSigningVerifier");
  if (MICodeSigningVerifier) {
    Method m = class_getInstanceMethod(MICodeSigningVerifier,
                                       @selector(performValidationWithError:));
    if (m) {
      orig_performValidation = (void *)method_setImplementation(
          m, (IMP)hooked_performValidation);
      LOG(@"hooked performValidationWithError: on MICodeSigningVerifier");
    }
  }

  // Disable code signing enforcement — relaxes verifier settings
  // (allowAdhocSigning:YES, verifyTrustCachePresence:NO, etc.)
  Class MIDaemonConfiguration = objc_getClass("MIDaemonConfiguration");
  hookValidation(MIDaemonConfiguration,
                 @selector(codeSigningEnforcementIsDisabled),
                 (IMP)hooked_alwaysYes);
}

void sanitize(NSMutableDictionary *plist) {
  NSArray *keysToRemove = @[
    @"MinimumOSVersion", @"MinimumProductVersion", @"UIDeviceFamily",
    @"UIRequiredDeviceCapabilities", @"UISupportedDevices", @"SupportedDevices",
    @"WKWatchOnly", @"LSRequiresIPhoneOS", @"CFBundleSupportedPlatforms"
  ];

  if (!plist)
    return;

  for (NSString *key in keysToRemove) {
    [plist removeObjectForKey:key];
  }
}
