from __future__ import annotations

import copy
import logging
import os
import plistlib
import shutil
import subprocess
import tempfile
import zipfile
from functools import cached_property

from .macho import MachO


class IPA(zipfile.ZipFile):
    """An IPA archive, with helpers for the decryption workflow."""

    @cached_property
    def app_path(self) -> str:
        """Path of the main .app bundle inside the IPA."""
        for zi in self.filelist:
            segments = zi.filename.split("/")
            if len(segments) != 3:
                continue

            payload, app, info_plist = segments
            if (
                payload == "Payload"
                and info_plist == "Info.plist"
                and app.endswith(".app")
            ):
                return f"{payload}/{app}"
        raise RuntimeError("main .app not found in IPA")

    @property
    def app_name(self) -> str:
        return os.path.basename(self.app_path)

    @cached_property
    def metadata(self) -> dict:
        """Parsed Info.plist of the main .app bundle."""
        with self.open(f"{self.app_path}/Info.plist") as o:
            return plistlib.loads(o.read())

    @property
    def bundle_id(self) -> str:
        return self.metadata["CFBundleIdentifier"]

    def strip_watch_app(self) -> str | None:
        """Write a copy of the IPA without the bundled Watch app.

        Returns the path to the temporary copy, or None if the IPA
        has no Watch app to strip.
        """
        watch_prefix = f"{self.app_path}/Watch/"
        if not any(item.filename.startswith(watch_prefix) for item in self.infolist()):
            return None

        fd, copy_path = tempfile.mkstemp(suffix=".ipa")
        os.close(fd)
        logging.info(f"stripping bundled Watch app into {copy_path}")
        assert self.filename is not None
        shutil.copy(self.filename, copy_path)
        # zip -d is much faster than re-writing the archive in Python
        subprocess.run(["zip", "-dq", copy_path, f"{watch_prefix}*"], check=True)
        return copy_path

    def encrypted_machos(self) -> list[str]:
        """Paths (relative to Payload/) of encrypted Mach-O files in the IPA."""
        results: list[str] = []
        for zi in self.filelist:
            if zi.is_dir():
                continue
            with self.open(zi) as o:
                data = o.read()
            binary = MachO.parse(data)
            if binary is None:
                continue
            for info in binary.encryption_info():
                if info.cryptid:
                    results.append(zi.filename[len("Payload/") :])
                    break
        return results

    def repack(self, dumpdir: str, replacements: set[str] | None = None) -> str:
        """Repack the IPA, substituting decrypted binaries from dumpdir.

        If replacements is None, auto-detect by scanning dumpdir for Mach-O files.
        The bundled Watch app is excluded from the output.
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

        assert self.filename is not None
        prefix, *_ = os.path.splitext(os.path.basename(self.filename))
        out_ipa = os.path.join(dumpdir, prefix + ".decrypted.ipa")

        logging.info("creating decrypted archive")
        watch_prefix = f"{self.app_path}/Watch/"
        with zipfile.ZipFile(out_ipa, "w") as new_ipa:
            for item in self.infolist():
                if item.filename.startswith(watch_prefix):
                    continue
                filename = item.filename[len("Payload/") :]
                if filename in replacements:
                    with open(os.path.join(dumpdir, filename), "rb") as f:
                        data = f.read()
                else:
                    with self.open(item) as f:
                        data = f.read()
                # writestr mutates the ZipInfo; pass a copy so the source
                # archive stays readable afterwards
                new_ipa.writestr(copy.copy(item), data)

        logging.info(f"decrypted IPA saved to {out_ipa}")
        return out_ipa
