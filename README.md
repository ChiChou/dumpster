# dumpster

Decrypt IPA executables on jailbroken iOS devices.

## Prerequisites

Jailbroken iPhone

* `installd` patch — run the [installd.js](tweak/installd.js) Frida script ([instructions](tweak/README.md))
* `unfairplay` decryptor [decrypt](decrypt/README.md)
* `dumpster` wrapper [wrapper](wrapper/) — deployed automatically on first run

Server

* macOS (uses `codesign` and `zip`)
* [libimobiledevice](https://libimobiledevice.org/) and [ideviceinstaller](https://github.com/libimobiledevice/ideviceinstaller)
* [ipatool](https://github.com/majd/ipatool) (to download IPAs from App Store)
* Python 3.14+ and [uv](https://docs.astral.sh/uv/)

## Install

```
uv tool install .
```

This installs the `dumpster` command to `~/.local/bin/` (make sure it's in your `$PATH`).

To install in development mode:

```
uv tool install -e .
```

To uninstall:

```
uv tool uninstall dumpster
```

## Usage

List installed apps on the connected device:

```
dumpster -l
```

Decrypt a single app by bundle ID:

```
dumpster --host iphone com.example.app
```

Batch decrypt multiple bundle IDs:

```
dumpster --host iphone com.example.app1 com.example.app2 com.example.app3
```

Decrypt from IPA files (installs if needed, then decrypts and repacks):

```
dumpster --host iphone app1.ipa app2.ipa
```

When an IPA contains a bundled Watch app, dumpster creates a temporary
copy for installation and removes the Watch app in place with `zip -d`. The
Frida `installd.js` hooks must remain attached while the temporary IPA is
installed.

If all targets are existing files they are treated as IPAs, otherwise as bundle IDs.

Pull decrypted binaries without repacking into IPA:

```
dumpster --host iphone --no-repack app.ipa
```

Skip extensions, only decrypt main binary and frameworks:

```
dumpster --host iphone --no-ext com.example.app
```

Skip failed targets and continue with the rest:

```
dumpster --host iphone -k com.example.app1 com.example.app2
```

Specify device UDID when multiple devices are connected:

```
dumpster --host iphone -u DEVICE_UDID com.example.app
```

Decrypted output is saved to `dump/<bundle_id>/`. Binaries are always kept regardless of repacking.

### Repack separately

If you decrypted with `--no-repack` (or just want to repack again after modifying binaries), use `dumpster-repack`:

```
dumpster-repack app.ipa
```

It reads the original IPA, substitutes any Mach-O files found in `dump/<bundle_id>/`, and writes a `.decrypted.ipa`. The bundled Watch app is excluded from the repacked IPA. Use `-d` to point to a different dump directory:

```
dumpster-repack -d /path/to/dump app.ipa
```

## SSH Setup

Configure the device as an alias in `~/.ssh/config`; dumpster delegates the user,
identity, host key, port, and transport settings to OpenSSH. For a USB connection:

```sshconfig
Host iphone
    HostName localhost
    User root
    IdentityFile ~/.ssh/iphone
    IdentitiesOnly yes
    ProxyCommand inetcat 22
```

For a network connection, configure `HostName` and `Port` for the device and omit
`ProxyCommand`. Verify that `ssh iphone` works with key authentication, then pass
the alias to dumpster with `--host iphone`.

If you have multiple devices, put the device UDID in the alias's `ProxyCommand`
(`inetcat -u DEVICE_UDID 22`) and also pass `--udid` / `-u` so the
libimobiledevice commands select the same device.

Device tools default to `/var/jb/bin`. Set `DUMPSTER_REMOTE_BIN` when the
jailbreak uses a different executable directory:

```sh
DUMPSTER_REMOTE_BIN=/usr/local/bin dumpster --host iphone com.example.app
```
