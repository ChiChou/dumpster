const mod = Module.load(
  "/System/Library/PrivateFrameworks/InstalledContentLibrary.framework/InstalledContentLibrary",
);

const symbolLoadInfoPlist = mod.findExportByName("MILoadInfoPlist");
const symbolLoadInfoPlistWithError = mod.findExportByName(
  "MILoadInfoPlistWithError",
);

// Define our sanitize logic
const keysToRemove = [
  "MinimumOSVersion",
  "MinimumProductVersion",
  "UIDeviceFamily",
  "UIRequiredDeviceCapabilities",
  "UISupportedDevices",
  "SupportedDevices",
  "WKWatchOnly",
  "LSRequiresIPhoneOS",
  "CFBundleSupportedPlatforms",
];

function sanitize(retval) {
  if (retval.isNull()) {
    return;
  }

  const plist = new ObjC.Object(retval);

  if (typeof plist.removeObjectForKey_ === "function") {
    for (const key of keysToRemove) {
      const nsKey = ObjC.classes.NSString.stringWithString_(key);
      plist.removeObjectForKey_(nsKey);
    }
    return;
  }

  console.log("Warning: Returned plist is not mutable.");
}

// Hook MILoadInfoPlist
if (symbolLoadInfoPlist) {
  Interceptor.attach(symbolLoadInfoPlist, {
    onLeave(retval) {
      sanitize(retval);
    },
  });
  console.log("Hooked MILoadInfoPlist");
}

// Hook MILoadInfoPlistWithError
if (symbolLoadInfoPlistWithError) {
  Interceptor.attach(symbolLoadInfoPlistWithError, {
    onLeave: function (retval) {
      sanitize(retval);
    },
  });
  console.log("Hooked MILoadInfoPlistWithError");
}

// Bypass bundle validation checks — minimum kill switch (3 hooks).
// See report.md for the full call tree and rationale.
//
// validateBundleMetadataWithError: on each subclass covers all per-bundle checks
// (including _validateNSExtension, _validateXPCService, delegate class, etc.)
// validatePluginKitMetadataWithError: covers the loop-level checks (duplicates, WatchKit).

const validationHooks = [
  // [className, selectorString, index of NSError** arg (0-based, excluding self/cmd)]
  ["MIPluginKitBundle", "- validateBundleMetadataWithError:", 0],
  ["MIExtensionKitBundle", "- validateBundleMetadataWithError:", 0],
  ["MIBundle", "- validatePluginKitMetadataWithError:", 0],
];

validationHooks.forEach(([className, selName, errArgIdx]) => {
  const cls = ObjC.classes[className];
  if (!cls) {
    console.log(`Class ${className} not found`);
    return;
  }

  const method = cls[selName];
  if (!method) {
    console.log(`Method ${selName} not found on ${className}`);
    return;
  }

  Interceptor.attach(method.implementation, {
    onEnter(args) {
      // args: [self, _cmd, arg0, arg1, ...]
      // NSError** is at args[2 + errArgIdx]
      this.errPtr = args[2 + errArgIdx];
    },
    onLeave(retval) {
      retval.replace(ptr(1));
      if (!this.errPtr.isNull()) {
        this.errPtr.writePointer(ptr(0));
      }
    },
  });

  console.log(`Hooked -[${className} ${selName.slice(2)}]`);
});

// Disable code signing enforcement — makes the verifier set allowAdhocSigning:YES,
// verifyTrustCachePresence:NO, validateUsingDetachedSignature:NO
const cseMethod =
  ObjC.classes.MIDaemonConfiguration["- codeSigningEnforcementIsDisabled"];
if (cseMethod) {
  Interceptor.attach(cseMethod.implementation, {
    onLeave(retval) {
      retval.replace(ptr(1));
    },
  });
  console.log("Hooked -[MIDaemonConfiguration codeSigningEnforcementIsDisabled]");
}

// Code signature verification bypass.
// performValidationWithError: on device calls libmis and may fail.
// When it fails, the caller reads [verifier signingInfo] which is nil, causing
// "MismatchedBundleIDSigningIdentifier" downstream (null codeInfoIdentifier).
// Fix: hook performValidationWithError: to create fake signing info (like the simulator stub)
// with codeInfoIdentifier = bundle identifier, then set it on the verifier.
const perfValMethod =
  ObjC.classes.MICodeSigningVerifier["- performValidationWithError:"];
if (perfValMethod) {
  Interceptor.attach(perfValMethod.implementation, {
    onEnter(args) {
      this.self = new ObjC.Object(args[0]);
      this.errPtr = args[2];
    },
    onLeave(retval) {
      if (!retval.toInt32()) {
        // Verification failed — fabricate signing info like the simulator stub
        const verifier = this.self;
        const bundle = verifier.bundle();
        const bundleId = bundle.identifier();

        const sigInfo = ObjC.classes.MICodeSigningInfo.alloc()
          .initWithSignerIdentity_signerOrganization_codeInfoIdentifier_teamIdentifier_signatureVersion_entitlements_signerType_profileType_signingInfoSource_launchWarningData_(
            ObjC.classes.NSString.stringWithString_("Apple iPhone OS Application Signing"),
            ObjC.classes.NSString.stringWithString_("Apple Inc."),
            bundleId,
            ObjC.classes.NSString.stringWithString_("FAKETEAMID"),
            ObjC.classes.NSString.stringWithString_("1"),
            NULL,
            2, // signerType
            1, // profileType
            1, // signingInfoSource
            NULL,
          );

        // Set _signingInfo on the verifier so the caller can read it
        verifier.setValue_forKey_(sigInfo, ObjC.classes.NSString.stringWithString_("signingInfo"));

        retval.replace(ptr(1));
        if (!this.errPtr.isNull()) {
          this.errPtr.writePointer(ptr(0));
        }

        console.log(`Fabricated signing info for ${bundleId}`);
      }
    },
  });
  console.log("Hooked -[MICodeSigningVerifier performValidationWithError:]");
}
