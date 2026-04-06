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

# Mach-O magic numbers
MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

MACHO_MAGICS = {MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64}


def parse_encryption_info(data, offset, swap):
    fmt = "<III" if not swap else ">III"
    cryptoff, cryptsize, cryptid = struct.unpack_from(fmt, data, offset + 8)
    return cryptoff, cryptsize, cryptid


def parse_macho(data, offset=0):
    if len(data) - offset < 28:
        return

    (magic,) = struct.unpack_from("<I", data, offset)

    if magic == MH_MAGIC:
        is64, swap = False, False
    elif magic == MH_CIGAM:
        is64, swap = False, True
    elif magic == MH_MAGIC_64:
        is64, swap = True, False
    elif magic == MH_CIGAM_64:
        is64, swap = True, True
    else:
        return

    fmt = ">" if swap else "<"
    header_size = 28 if not is64 else 32
    ncmds, _ = struct.unpack_from(fmt + "II", data, offset + 16)

    lc_offset = offset + header_size
    for _ in range(ncmds):
        if lc_offset + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(fmt + "II", data, lc_offset)
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            cryptoff, cryptsize, cryptid = parse_encryption_info(data, lc_offset, swap)
            yield {"cryptoff": cryptoff, "cryptsize": cryptsize, "cryptid": cryptid}
        lc_offset += cmdsize


def parse_fat(data):
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic == FAT_MAGIC:
        swap = False
    elif magic == FAT_CIGAM:
        swap = True
    else:
        return

    fmt = ">" if not swap else "<"
    (nfat,) = struct.unpack_from(fmt + "I", data, 4)

    for i in range(nfat):
        fa_offset = 8 + i * 20
        _, _, arch_offset, _, _ = struct.unpack_from(fmt + "IIIII", data, fa_offset)
        yield from parse_macho(data, arch_offset)


def scan_macho(data):
    if len(data) < 4:
        return
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic in (FAT_MAGIC, FAT_CIGAM):
        yield from parse_fat(data)
    elif magic in MACHO_MAGICS:
        yield from parse_macho(data, 0)


def is_macho(data):
    if len(data) < 4:
        return False
    (magic,) = struct.unpack_from("<I", data, 0)
    return magic in MACHO_MAGICS or magic in (FAT_MAGIC, FAT_CIGAM)


def load_info_plist(ipa):
    for zi in ipa.filelist:
        segments = zi.filename.split("/", 3)
        if len(segments) < 3:
            continue
        if (
            segments[0] == "Payload"
            and segments[2] == "Info.plist"
            and segments[1].endswith(".app")
        ):
            with ipa.open(zi) as o:
                return segments[1], plistlib.loads(o.read())
    raise RuntimeError("Info.plist not found in IPA")


def encrypted_machos(ipa):
    for zi in ipa.filelist:
        if zi.is_dir():
            continue
        with ipa.open(zi) as o:
            data = o.read()
        if not is_macho(data):
            continue
        for info in scan_macho(data):
            if info["cryptid"]:
                yield zi.filename[len("Payload/") :]
                break


def idevice(*args, udid=None):
    cmd = list(args)
    if udid:
        cmd.insert(1, udid)
        cmd.insert(1, "-u")
    return cmd


def ssh(host, *args, check=True):
    cmd = " ".join(shlex.quote(a) for a in args)
    return subprocess.run(["ssh", host, cmd], check=check, capture_output=True)


def ensure_tool(host, name, build_dir):
    result = ssh(host, "test", "-x", f"/var/jb/bin/{name}", check=False)
    if result.returncode == 0:
        return
    logging.info(f"{name} not found on device, building and deploying")
    subprocess.run(["make", "-C", build_dir, "ios"], check=True)
    subprocess.run(
        ["make", "-C", build_dir, "deploy", f"IOS_HOST={host}"], check=True
    )


def get_installed_apps(udid=None):
    cmd = idevice("ideviceinstaller", "list", "--xml", "--user", udid=udid)
    return plistlib.loads(subprocess.check_output(cmd))


def find_app(bundle_id, udid=None):
    for app in get_installed_apps(udid):
        if app.get("CFBundleIdentifier") == bundle_id:
            return app
    return None


def filter_executables(executables, app_name, all_binaries):
    if all_binaries:
        return executables
    # main binary + Frameworks/ only
    prefix = f"{app_name}/Frameworks/"
    main = f"{app_name}/"
    return {
        f for f in executables
        if f.startswith(prefix) or f.count("/") == 1
    }


def decrypt(host, bundle_id, ipa=None, udid=None, all_binaries=False, repack=True):
    ensure_tool(host, "unfairplay", "decrypt")
    ensure_tool(host, "dumpster", "wrapper")

    match = find_app(bundle_id, udid)
    if not match:
        sys.exit(f"error: {bundle_id} is not installed on device")

    bundle_path = match["Path"]
    app_name = os.path.basename(bundle_path)

    if ipa:
        executables = set(encrypted_machos(ipa))
    else:
        result = ssh(host, "/var/jb/bin/dumpster", bundle_id)
        lines = result.stdout.decode().strip().splitlines()
        # first line is bundle path, rest are relative encrypted binary paths
        executables = {f"{app_name}/{l}" for l in lines[1:] if l}

    executables = filter_executables(executables, app_name, all_binaries)

    output = f"/var/mobile/unfairplay/{app_name}"
    decrypted = set()

    for filename in executables:
        tail = "/".join(filename.split("/")[1:])
        logging.info(f"decrypting {filename}")
        src = f"{bundle_path}/{tail}"
        dst = f"{output}/{tail}"
        parent_dir = dst[: dst.rfind("/")]

        ssh(host, "mkdir", "-p", parent_dir)
        ssh(host, "rm", "-f", dst)
        result = ssh(host, "/var/jb/bin/unfairplay", src, dst, check=False)
        if result.returncode != 0:
            stderr = result.stderr.decode().strip()
            logging.warning(f"unfairplay failed for {filename}: {stderr}")
            ssh(host, "rm", "-f", dst)
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
        subprocess.run(
            ["scp", "-O", f"{host}:{shlex.quote(remote)}", local], check=True
        )

    # pull Info.plist for context
    plist_remote = f"{bundle_path}/Info.plist"
    plist_local = os.path.join(outdir, app_name, "Info.plist")
    subprocess.run(
        ["scp", "-O", f"{host}:{shlex.quote(plist_remote)}", plist_local], check=True
    )

    if not ipa or not repack:
        logging.info(f"decrypted binaries saved to {outdir}")
        return

    logging.info("creating decrypted archive")

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


def list_apps(udid=None):
    apps = get_installed_apps(udid)
    if not apps:
        print("no apps installed")
        return

    rows = []
    for app in apps:
        rows.append((
            app.get("CFBundleIdentifier", ""),
            app.get("CFBundleShortVersionString", ""),
            app.get("CFBundleVersion", ""),
            app.get("CFBundleDisplayName") or app.get("CFBundleName", ""),
        ))
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


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt IPA executables on jailbroken iOS device"
    )
    parser.add_argument("target", nargs="?", help="path to .ipa file or bundle identifier")
    parser.add_argument("host", nargs="?", help="SSH host (e.g. root@ios)")
    parser.add_argument("--no-ext", action="store_true", help="skip extensions, only decrypt main binary and frameworks")
    parser.add_argument("--no-repack", action="store_true", help="pull decrypted binaries without repacking into IPA")
    parser.add_argument("-l", "--list", action="store_true", help="list installed apps")
    parser.add_argument("-u", "--udid", help="device UDID for ideviceinstaller")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable verbose logging"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )

    if args.list:
        list_apps(args.udid)
        return

    if not args.target or not args.host:
        parser.error("target and host are required unless using -l")

    if args.target.endswith(".ipa"):
        ipa = zipfile.ZipFile(args.target, "r")
        _, metadata = load_info_plist(ipa)
        bundle_id = metadata["CFBundleIdentifier"]
        version = metadata.get("CFBundleShortVersionString", "")

        installed = find_app(bundle_id, args.udid)
        if installed and installed.get("CFBundleShortVersionString") == version:
            logging.info(f"{bundle_id} v{version} already installed, skipping")
        else:
            logging.info(f"installing {args.target}")
            subprocess.run(
                idevice("ideviceinstaller", "install", args.target, udid=args.udid),
                check=True,
            )

        decrypt(args.host, bundle_id, ipa=ipa, udid=args.udid,
                all_binaries=not args.no_ext, repack=not args.no_repack)
    else:
        decrypt(args.host, args.target, udid=args.udid, all_binaries=not args.no_ext)


if __name__ == "__main__":
    main()
