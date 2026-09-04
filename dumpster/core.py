from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys

from .codesign import codesign_binaries
from .device import Device
from .ipa import IPA


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
    ipa: IPA | None = None,
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
        executables = set(ipa.encrypted_machos())
    else:
        result = dev.ssh(dev.tool_path("dumpster"), bundle_id)
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
        result = dev.ssh(dev.tool_path("unfairplay"), src, dst, check=False)
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

    ipa.repack(outdir, decrypted)


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
    with IPA(path, "r") as ipa:
        bundle_id = ipa.bundle_id
        version = ipa.metadata.get("CFBundleShortVersionString", "")

        installed = dev.find_app(bundle_id)
        if installed and installed.get("CFBundleShortVersionString") == version:
            logging.info(f"{bundle_id} v{version} already installed, skipping")
        else:
            logging.info(f"installing {path}")
            stripped = ipa.strip_watch_app()
            try:
                subprocess.run(
                    dev.idevice("ideviceinstaller", "install", stripped or path),
                    check=True,
                )
            finally:
                if stripped:
                    os.remove(stripped)

        decrypt(
            dev,
            bundle_id,
            ipa=ipa,
            all_binaries=all_binaries,
            repack=repack,
            codesign_mode=codesign_mode,
            codesign_identity=codesign_identity,
        )
