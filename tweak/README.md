# installd.js

[Frida](https://frida.re/) script that patches `installd` so you can install IPAs that require a higher iOS version, then use dumpster to fetch the decrypted executables.

It disables `MinimumOSVersion` and related Info.plist checks, bundle metadata validation, code signing enforcement, Watch verification, and resource-seal validation (so dumpster's Watch-free intermediate IPA can be installed without re-signing).

## Requirements

* jailbroken iOS with `frida-server` running on the device
* `frida` CLI on your computer (`pip install frida-tools`)

## Usage

```sh
frida -U -n installd -l installd.js
```

Keep the script running while you install the IPA (e.g. with `ideviceinstaller` or `dumpster`).
