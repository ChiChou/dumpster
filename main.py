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


def load_info_plist(ipa: zipfile.ZipFile) -> tuple[str, dict]:
    for zi in ipa.filelist:
        segments = zi.filename.split("/", 3)
        if len(segments) < 3:
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
        logging.info(f"{name} not found on device, building and deploying")
        subprocess.run(["make", "-C", build_dir, "ios"], check=True)
        self.push(
            os.path.join(build_dir, name),
            os.path.join(build_dir, "ent.xml"),
            remote="/tmp/",
        )
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


def decrypt(
    dev: Device,
    bundle_id: str,
    ipa: zipfile.ZipFile | None = None,
    all_binaries: bool = False,
    repack: bool = True,
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

    if not ipa or not repack:
        logging.info(f"decrypted binaries saved to {outdir}")
        return

    logging.info("creating decrypted archive")

    assert ipa.filename is not None
    prefix, *_ = os.path.splitext(os.path.basename(ipa.filename))
    out_ipa = os.path.join(outdir, prefix + ".decrypted.ipa")
    with zipfile.ZipFile(out_ipa, "w") as new_ipa:
        for item in ipa.infolist():
            filename = item.filename[len("Payload/") :]
            if filename in decrypted:
                with open(os.path.join(outdir, filename), "rb") as f:
                    data = f.read()
            else:
                with ipa.open(item) as f:
                    data = f.read()
            new_ipa.writestr(item, data)

    logging.info(f"decrypted IPA saved to {out_ipa}")


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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decrypt IPA executables on jailbroken iOS device"
    )
    parser.add_argument(
        "target", nargs="?", help="path to .ipa file or bundle identifier"
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

    if not args.target:
        parser.error("target is required unless using -l")

    if args.target.endswith(".ipa"):
        ipa = zipfile.ZipFile(args.target, "r")
        _, metadata = load_info_plist(ipa)
        bundle_id = metadata["CFBundleIdentifier"]
        version = metadata.get("CFBundleShortVersionString", "")

        installed = dev.find_app(bundle_id)
        if installed and installed.get("CFBundleShortVersionString") == version:
            logging.info(f"{bundle_id} v{version} already installed, skipping")
        else:
            logging.info(f"installing {args.target}")
            subprocess.run(
                dev.idevice("ideviceinstaller", "install", args.target),
                check=True,
            )

        decrypt(
            dev,
            bundle_id,
            ipa=ipa,
            all_binaries=not args.no_ext,
            repack=not args.no_repack,
        )
    else:
        decrypt(dev, args.target, all_binaries=not args.no_ext)


if __name__ == "__main__":
    main()
