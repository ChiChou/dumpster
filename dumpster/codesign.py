from __future__ import annotations

import logging
import os
import subprocess
import sys

from .macho import MachO


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
