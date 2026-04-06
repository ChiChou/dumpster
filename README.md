# dumpster

Decrypt IPA executables on jailbroken iOS devices.

## Prerequisites

Jailbroken iPhone

* `installd` patch [tweak](tweak/README.md)
* `unfairplay` decryptor [decrypt](decrypt/README.md)
* `dumpster` wrapper [wrapper](wrapper/) — deployed automatically on first run

Server

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
dumpster com.example.app
```

Batch decrypt multiple bundle IDs:

```
dumpster com.example.app1 com.example.app2 com.example.app3
```

Decrypt from IPA files (installs if needed, then decrypts and repacks):

```
dumpster app1.ipa app2.ipa
```

If all targets are existing files they are treated as IPAs, otherwise as bundle IDs.

Pull decrypted binaries without repacking into IPA:

```
dumpster --no-repack app.ipa
```

Skip extensions, only decrypt main binary and frameworks:

```
dumpster --no-ext com.example.app
```

Skip failed targets and continue with the rest:

```
dumpster -k com.example.app1 com.example.app2
```

Specify device UDID when multiple devices are connected:

```
dumpster -u DEVICE_UDID com.example.app
```

Decrypted output is saved to `dump/<bundle_id>/`. Binaries are always kept regardless of repacking.

### Repack separately

If you decrypted with `--no-repack` (or just want to repack again after modifying binaries), use `dumpster-repack`:

```
dumpster-repack app.ipa
```

It reads the original IPA, substitutes any Mach-O files found in `dump/<bundle_id>/`, and writes a `.decrypted.ipa`. Use `-d` to point to a different dump directory:

```
dumpster-repack -d /path/to/dump app.ipa
```

## SSH Setup

The tool connects to the device via USB using `inetcat`. No SSH config is needed — it handles the proxy command internally.

If you have multiple devices, pass `--udid` / `-u` to select one.
