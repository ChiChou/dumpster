# RubberStamp

Disable MinimumOSVersion verification so you can install IPA that requires higher iOS version and then use fouldecrypt to fetch executables.

## Requirements

* jailbroken iOS
* [Frida](https://frida.re/) on the host and device, or
  [theos](https://theos.dev/) for the compiled tweak

## Frida

Attach the supplied script before installing an IPA and keep it attached for
the duration of the install:

```sh
frida -U -n installd -l installd.js
```

In addition to minimum-version checks, the script disables Watch validation
and resource-seal verification for dumpster's Watch-free intermediate IPA.
Executable signatures are left intact so FairPlay pages can still be decrypted.

## Build

```sh
export ROOTLESS=1  # for rootless jailbreak
make package
THEOS_DEVICE_IP=localhost THEOS_DEVICE_PORT=2222 make install
```
