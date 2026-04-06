#include <Foundation/Foundation.h>
#include <objc/runtime.h>
#include <substrate.h>

#define LOG(fmt, ...) NSLog(@"[rubberstamp] " fmt "\n", ##__VA_ARGS__)

#pragma mark - Prototypes
__attribute__((constructor)) void init(void);
void sanitize(NSMutableDictionary *plist);

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

// Generic validation bypass — always returns YES and clears the error out-param
static BOOL hooked_validatePass(id self, SEL _cmd, NSError **err) {
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
