from __future__ import annotations

import argparse
import logging
import os
import plistlib
import shlex
import shutil
import struct
import subprocess
import sys
import zipfile


def _find_data_file(build_dir: str, name: str) -> str:
    """Locate a bundled iOS binary from the installed ios_tools package."""
    import ios_tools

    return ios_tools.get(build_dir, name)


class MachO:
    MH_MAGIC = 0xFEEDFACE
    MH_MAGIC_64 = 0xFEEDFACF
    MH_CIGAM = 0xCEFAEDFE
    MH_CIGAM_64 = 0xCFFAEDFE

    FAT_MAGIC = 0xCAFEBABE
    FAT_CIGAM = 0xBEBAFECA

    LC_ENCRYPTION_INFO = 0x21
    LC_ENCRYPTION_INFO_64 = 0x2C

    _MAGICS = {MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64}
    _FAT = {FAT_MAGIC, FAT_CIGAM}

    @staticmethod
    def parse(data: bytes) -> MachO | None:
        if len(data) < 4:
            return None
        (magic,) = struct.unpack_from("<I", data, 0)
        if magic in MachO._FAT:
            return FatBinary(data)
        if magic in MachO._MAGICS:
            return ThinBinary(data, 0)
        return None

    @staticmethod
    def is_macho(data: bytes) -> bool:
        if len(data) < 4:
            return False
        (magic,) = struct.unpack_from("<I", data, 0)
        return magic in MachO._MAGICS or magic in MachO._FAT

    def encryption_info(self) -> ...:
        raise NotImplementedError


EncryptionInfo = dict[str, int]


class ThinBinary(MachO):
    def __init__(self, data: bytes, offset: int = 0) -> None:
        self.data = data
        self.offset = offset

        (magic,) = struct.unpack_from("<I", data, offset)
        if magic in (MachO.MH_MAGIC, MachO.MH_CIGAM):
            self.is64, self.swap = False, False if magic == MachO.MH_MAGIC else True
        else:
            self.is64, self.swap = True, magic == MachO.MH_CIGAM_64

        self._fmt = ">" if self.swap else "<"
        self._header_size = 32 if self.is64 else 28
        self.ncmds, _ = struct.unpack_from(self._fmt + "II", data, offset + 16)

    def encryption_info(self) -> list[EncryptionInfo]:
        results: list[EncryptionInfo] = []
        lc_offset = self.offset + self._header_size
        for _ in range(self.ncmds):
            if lc_offset + 8 > len(self.data):
                break
            cmd, cmdsize = struct.unpack_from(self._fmt + "II", self.data, lc_offset)
            if cmd in (MachO.LC_ENCRYPTION_INFO, MachO.LC_ENCRYPTION_INFO_64):
                fmt = "<III" if not self.swap else ">III"
                cryptoff, cryptsize, cryptid = struct.unpack_from(
                    fmt, self.data, lc_offset + 8
                )
                results.append(
                    {"cryptoff": cryptoff, "cryptsize": cryptsize, "cryptid": cryptid}
                )
            lc_offset += cmdsize
        return results


class FatBinary(MachO):
    def __init__(self, data: bytes) -> None:
        self.data = data
        (magic,) = struct.unpack_from("<I", data, 0)
        self.swap = magic == MachO.FAT_CIGAM
        fmt = ">" if not self.swap else "<"
        (self.nfat,) = struct.unpack_from(fmt + "I", data, 4)
        self._fmt = fmt

    def slices(self) -> list[ThinBinary]:
        result: list[ThinBinary] = []
        for i in range(self.nfat):
            fa_offset = 8 + i * 20
            _, _, arch_offset, _, _ = struct.unpack_from(
                self._fmt + "IIIII", self.data, fa_offset
            )
            result.append(ThinBinary(self.data, arch_offset))
        return result

    def encryption_info(self) -> list[EncryptionInfo]:
        results: list[EncryptionInfo] = []
        for s in self.slices():
            results.extend(s.encryption_info())
        return results


def repack_ipa(
    ipa: zipfile.ZipFile, dumpdir: str, replacements: set[str] | None = None
) -> str:
    """Repack an IPA, substituting decrypted binaries from dumpdir.

    If replacements is None, auto-detect by scanning dumpdir for Mach-O files.
    Returns the path to the output IPA.
    """
    if replacements is None:
        replacements = set()
        for root, _, files in os.walk(dumpdir):
            for name in files:
                path = os.path.join(root, name)
                with open(path, "rb") as f:
                    header = f.read(4)
                if MachO.is_macho(header):
                    replacements.add(os.path.relpath(path, dumpdir))

    assert ipa.filename is not None
    prefix, *_ = os.path.splitext(os.path.basename(ipa.filename))
    out_ipa = os.path.join(dumpdir, prefix + ".decrypted.ipa")

    logging.info("creating decrypted archive")
    with zipfile.ZipFile(out_ipa, "w") as new_ipa:
        for item in ipa.infolist():
            filename = item.filename[len("Payload/") :]
            if filename in replacements:
                with open(os.path.join(dumpdir, filename), "rb") as f:
                    data = f.read()
            else:
                with ipa.open(item) as f:
                    data = f.read()
            new_ipa.writestr(item, data)

    logging.info(f"decrypted IPA saved to {out_ipa}")
    return out_ipa


def load_info_plist(ipa: zipfile.ZipFile) -> tuple[str, dict]:
    for zi in ipa.filelist:
        segments = zi.filename.split("/")
        if len(segments) != 3:
            continue

        payload, app, info_plist = segments
        if payload == "Payload" and info_plist == "Info.plist" and app.endswith(".app"):
            with ipa.open(zi) as o:
                return app, plistlib.loads(o.read())
    raise RuntimeError("Info.plist not found in IPA")


def encrypted_machos(ipa: zipfile.ZipFile) -> list[str]:
    results: list[str] = []
    for zi in ipa.filelist:
        if zi.is_dir():
            continue
        with ipa.open(zi) as o:
            data = o.read()
        binary = MachO.parse(data)
        if binary is None:
            continue
        for info in binary.encryption_info():
            if info["cryptid"]:
                results.append(zi.filename[len("Payload/") :])
                break
    return results


SSH_OPTIONS = [
    "-o",
    "LogLevel=ERROR",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
]


class Device:
    def __init__(self, udid: str | None = None, user: str = "mobile") -> None:
        self.udid = udid
        self.user = user
        proxy = f"inetcat -u {udid} 22" if udid else "inetcat 22"
        self._conn = [*SSH_OPTIONS, "-o", f"ProxyCommand={proxy}"]
        self._remote = f"{user}@localhost"

    def idevice(self, *args: str) -> list[str]:
        cmd = list(args)
        if self.udid:
            cmd.insert(1, self.udid)
            cmd.insert(1, "-u")
        return cmd

    def ssh(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        cmd = " ".join(shlex.quote(a) for a in args)
        return subprocess.run(
            ["ssh", *self._conn, self._remote, cmd],
            check=check,
            capture_output=True,
        )

    def pull(self, remote: str, local: str) -> None:
        subprocess.run(
            ["scp", "-O", *self._conn, f"{self._remote}:{shlex.quote(remote)}", local],
            check=True,
        )

    def push(self, *local: str, remote: str) -> None:
        subprocess.run(
            ["scp", "-O", *self._conn, *local, f"{self._remote}:{shlex.quote(remote)}"],
            check=True,
        )

    def ensure_tool(self, name: str, build_dir: str) -> None:
        result = self.ssh("test", "-x", f"/var/jb/bin/{name}", check=False)
        if result.returncode == 0:
            return
        logging.info(f"{name} not found on device, deploying")

        binary = _find_data_file(build_dir, name)
        entxml = _find_data_file(build_dir, "ent.xml")
        self.push(binary, entxml, remote="/tmp/")

        target = f"/var/jb/bin/{name}"
        self.ssh(
            "mv",
            f"/tmp/{name}",
            target,
            "&&",
            "chmod",
            "755",
            target,
            "&&",
            "ldid",
            "-S/tmp/ent.xml",
            target,
        )

    def get_installed_apps(self) -> list[dict]:
        cmd = self.idevice("ideviceinstaller", "list", "--xml", "--user")
        return plistlib.loads(subprocess.check_output(cmd))

    def find_app(self, bundle_id: str) -> dict | None:
        for app in self.get_installed_apps():
            if app.get("CFBundleIdentifier") == bundle_id:
                return app
        return None


def filter_executables(
    executables: set[str], app_name: str, all_binaries: bool
) -> set[str]:
    if all_binaries:
        return executables
    # main binary + Frameworks/ only
    prefix = f"{app_name}/Frameworks/"
    return {f for f in executables if f.startswith(prefix) or f.count("/") == 1}


def list_codesign_identities() -> list[str]:
    """Return available signing identities from the macOS keychain."""
    result = subprocess.run(
        ["security", "find-identity", "-v", "-p", "codesigning"],
        capture_output=True,
        text=True,
    )
    identities: list[str] = []
    for line in result.stdout.strip().splitlines():
        # lines look like:  1) HASH "Name"
        if '"' in line:
            name = line.split('"')[1]
            identities.append(name)
    return identities


def codesign_binaries(outdir: str, mode: str, identity: str | None = None) -> None:
    """Run codesign on all Mach-O files in outdir. macOS only.

    mode: 'strip' to remove signatures, 'resign' to ad-hoc sign,
          'sign' to sign with a specific identity.
    """
    if sys.platform != "darwin":
        logging.warning("codesign is only available on macOS, skipping")
        return

    for root, _, files in os.walk(outdir):
        for name in files:
            path = os.path.join(root, name)
            with open(path, "rb") as f:
                header = f.read(4)
            if not MachO.is_macho(header):
                continue
            if mode == "strip":
                logging.info(f"stripping code signature: {path}")
                subprocess.run(["codesign", "--remove-signature", path], check=True)
            elif mode == "resign":
                logging.info(f"ad-hoc signing: {path}")
                subprocess.run(["codesign", "-f", "-s", "-", path], check=True)
            elif mode == "sign":
                assert identity is not None, "identity must be provided for signing"
                logging.info(f"signing with '{identity}': {path}")
                subprocess.run(["codesign", "-f", "-s", identity, path], check=True)


def decrypt(
    dev: Device,
    bundle_id: str,
    ipa: zipfile.ZipFile | None = None,
    all_binaries: bool = False,
    repack: bool = True,
    codesign_mode: str | None = None,
    codesign_identity: str | None = None,
) -> None:
    dev.ensure_tool("unfairplay", "decrypt")
    dev.ensure_tool("dumpster", "wrapper")

    match = dev.find_app(bundle_id)
    if not match:
        sys.exit(f"error: {bundle_id} is not installed on device")

    bundle_path: str = match["Path"]
    app_name = os.path.basename(bundle_path)

    if ipa:
        executables = set(encrypted_machos(ipa))
    else:
        result = dev.ssh("/var/jb/bin/dumpster", bundle_id)
        lines = result.stdout.decode().strip().splitlines()
        # first line is bundle path, rest are relative encrypted binary paths
        executables = {f"{app_name}/{line}" for line in lines[1:] if line}

    executables = filter_executables(executables, app_name, all_binaries)

    output = f"/var/mobile/unfairplay/{app_name}"
    decrypted: set[str] = set()

    for filename in executables:
        tail = "/".join(filename.split("/")[1:])
        logging.info(f"decrypting {filename}")
        src = f"{bundle_path}/{tail}"
        dst = f"{output}/{tail}"
        parent_dir = dst[: dst.rfind("/")]

        dev.ssh("mkdir", "-p", parent_dir)
        dev.ssh("rm", "-f", dst)
        result = dev.ssh("/var/jb/bin/unfairplay", src, dst, check=False)
        if result.returncode != 0:
            stderr = result.stderr.decode().strip()
            logging.warning(f"unfairplay failed for {filename}: {stderr}")
            dev.ssh("rm", "-f", dst)
            continue
        decrypted.add(filename)

    if not decrypted:
        sys.exit("error: no binaries were decrypted")

    outdir = os.path.join("dump", bundle_id)
    shutil.rmtree(outdir, ignore_errors=True)
    os.makedirs(outdir, exist_ok=True)

    for filename in decrypted:
        tail = "/".join(filename.split("/")[1:])
        remote = f"{output}/{tail}"
        local = os.path.join(outdir, filename)
        os.makedirs(os.path.dirname(local), exist_ok=True)
        dev.pull(remote, local)

    # pull Info.plist for context
    plist_local = os.path.join(outdir, app_name, "Info.plist")
    dev.pull(f"{bundle_path}/Info.plist", plist_local)

    if codesign_mode:
        codesign_binaries(outdir, codesign_mode, identity=codesign_identity)

    if not ipa or not repack:
        logging.info(f"decrypted binaries saved to {outdir}")
        return

    repack_ipa(ipa, outdir, decrypted)


def list_apps(dev: Device) -> None:
    apps = dev.get_installed_apps()
    if not apps:
        print("no apps installed")
        return

    rows: list[tuple[str, ...]] = []
    for app in apps:
        rows.append(
            (
                app.get("CFBundleIdentifier", ""),
                app.get("CFBundleShortVersionString", ""),
                app.get("CFBundleVersion", ""),
                app.get("CFBundleDisplayName") or app.get("CFBundleName", ""),
            )
        )
    rows.sort()

    headers = ("Bundle ID", "Version", "Build", "Name")
    widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(val))

    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*("-" * w for w in widths)))
    for row in rows:
        print(fmt.format(*row))


def process_ipa(
    dev: Device,
    path: str,
    all_binaries: bool,
    repack: bool,
    codesign_mode: str | None = None,
    codesign_identity: str | None = None,
) -> None:
    ipa = zipfile.ZipFile(path, "r")
    _, metadata = load_info_plist(ipa)
    bundle_id = metadata["CFBundleIdentifier"]
    version = metadata.get("CFBundleShortVersionString", "")

    installed = dev.find_app(bundle_id)
    if installed and installed.get("CFBundleShortVersionString") == version:
        logging.info(f"{bundle_id} v{version} already installed, skipping")
    else:
        logging.info(f"installing {path}")
        subprocess.run(
            dev.idevice("ideviceinstaller", "install", path),
            check=True,
        )

    decrypt(
        dev,
        bundle_id,
        ipa=ipa,
        all_binaries=all_binaries,
        repack=repack,
        codesign_mode=codesign_mode,
        codesign_identity=codesign_identity,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decrypt IPA executables on jailbroken iOS device"
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="one or more .ipa files or bundle identifiers",
    )
    parser.add_argument(
        "--no-ext",
        action="store_true",
        help="skip extensions, only decrypt main binary and frameworks",
    )
    parser.add_argument(
        "--no-repack",
        action="store_true",
        help="pull decrypted binaries without repacking into IPA",
    )
    parser.add_argument("-l", "--list", action="store_true", help="list installed apps")
    parser.add_argument("-u", "--udid", help="device UDID (for multiple devices)")
    codesign_group = parser.add_mutually_exclusive_group()
    codesign_group.add_argument(
        "--strip-codesign",
        action="store_true",
        help="strip code signatures from pulled binaries (macOS only)",
    )
    codesign_group.add_argument(
        "--resign",
        action="store_true",
        help="ad-hoc re-sign pulled binaries with codesign (macOS only)",
    )
    codesign_group.add_argument(
        "--sign",
        metavar="IDENTITY",
        help="sign pulled binaries with a developer identity (macOS only, use 'list' to show available identities)",
    )
    parser.add_argument(
        "-k",
        "--skip-errors",
        action="store_true",
        help="skip failed targets and continue",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable verbose logging"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )

    dev = Device(udid=args.udid)

    if args.list:
        list_apps(dev)
        return

    if not args.targets:
        parser.error("at least one target is required unless using -l")

    if args.sign == "list":
        if sys.platform != "darwin":
            sys.exit("error: codesign is only available on macOS")
        identities = list_codesign_identities()
        if not identities:
            sys.exit("error: no codesigning identities found in keychain")
        for ident in identities:
            print(ident)
        return

    if args.strip_codesign:
        codesign_mode: str | None = "strip"
    elif args.resign:
        codesign_mode = "resign"
    elif args.sign:
        codesign_mode = "sign"
    else:
        codesign_mode = None

    ipa_mode = all(os.path.isfile(t) for t in args.targets)

    failed: list[str] = []
    for target in args.targets:
        try:
            if ipa_mode:
                process_ipa(
                    dev,
                    target,
                    all_binaries=not args.no_ext,
                    repack=not args.no_repack,
                    codesign_mode=codesign_mode,
                    codesign_identity=args.sign,
                )
            else:
                decrypt(
                    dev,
                    target,
                    all_binaries=not args.no_ext,
                    codesign_mode=codesign_mode,
                    codesign_identity=args.sign,
                )
        except Exception as e:
            logging.error(f"failed to process {target}: {e}")
            failed.append(target)
            if not args.skip_errors:
                break

    if failed:
        sys.exit(f"error: failed targets: {', '.join(failed)}")


def repack_main() -> None:
    parser = argparse.ArgumentParser(
        description="Repack IPA with decrypted binaries from dump directory"
    )
    parser.add_argument("ipa", nargs="+", help="original .ipa file(s)")
    parser.add_argument(
        "-d",
        "--dump-dir",
        default="dump",
        help="base dump directory (default: dump/)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable verbose logging"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )

    for path in args.ipa:
        ipa = zipfile.ZipFile(path, "r")
        _, metadata = load_info_plist(ipa)
        bundle_id = metadata["CFBundleIdentifier"]
        outdir = os.path.join(args.dump_dir, bundle_id)
        if not os.path.isdir(outdir):
            logging.error(f"no dump found for {bundle_id} at {outdir}, skipping")
            continue
        repack_ipa(ipa, outdir)


if __name__ == "__main__":
    main()
