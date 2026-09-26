from __future__ import annotations

import logging
import os
import subprocess
import sys

from .macho import MachO


def list_codesign_identities() -> list[str]:
    """Return available signing identities from the macOS keychain."""
    if sys.platform != "darwin":
        return []

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
    """Update signatures on all Mach-O files in outdir.

    mode: 'strip' to remove signatures, 'resign' to ad-hoc sign,
          'sign' to sign with a specific identity.

    macOS uses codesign for every mode. Linux uses zsign for ad-hoc signing;
    stripping and Keychain identity signing are unavailable there.
    """
    if sys.platform not in {"darwin", "linux"}:
        raise RuntimeError("code signing is only supported on macOS and Linux")
    if mode not in {"strip", "resign", "sign"}:
        raise ValueError(f"unknown codesign mode: {mode}")

    if sys.platform == "linux":
        if mode != "resign":
            raise RuntimeError(f"{mode} signing mode is only available on macOS")
        action = "ad-hoc signing"
        command = ["zsign", "-a"]
    elif mode == "strip":
        action = "stripping code signature"
        command = ["codesign", "--remove-signature"]
    elif mode == "resign":
        action = "ad-hoc signing"
        command = ["codesign", "-f", "-s", "-"]
    else:
        if identity is None:
            raise ValueError("identity must be provided for signing")
        action = f"signing with '{identity}'"
        command = ["codesign", "-f", "-s", identity]

    # codesign --deep only discovers nested code in macOS-style bundles
    for root, _, files in os.walk(outdir):
        for name in files:
            path = os.path.join(root, name)
            with open(path, "rb") as f:
                header = f.read(4)
            if not MachO.is_macho(header):
                continue
            logging.info(f"{action}: {path}")
            subprocess.run([*command, path], check=True)
