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

static BOOL (*orig_MIBundle_validatePluginKitMetadataWithError)(id self,
                                                                SEL _cmd,
                                                                NSError **error);
static BOOL hooked_MIBundle_validatePluginKitMetadataWithError(id self,
                                                               SEL _cmd,
                                                               NSError **error) {
  LOG(@"Skipping validatePluginKitMetadataWithError:");
  return YES;
}

#pragma mark - Entry

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

  Class MIBundleClass = objc_getClass("MIBundle");
  if (MIBundleClass) {
    MSHookMessageEx(MIBundleClass,
                    @selector(validatePluginKitMetadataWithError:),
                    (IMP)hooked_MIBundle_validatePluginKitMetadataWithError,
                    (IMP *)&orig_MIBundle_validatePluginKitMetadataWithError);
  } else {
    LOG(@"failed to find MIBundle class");
  }
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
