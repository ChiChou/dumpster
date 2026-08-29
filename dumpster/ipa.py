from __future__ import annotations

import logging
import os
import plistlib
import shutil
import subprocess
import tempfile
import zipfile
from functools import cached_property

from .macho import MachO

logger = logging.getLogger(__name__)


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
        logger.info(f"creating Watch-free intermediate IPA at {copy_path}")
        try:
            self._native_repack(copy_path)
        except Exception:
            try:
                os.remove(copy_path)
            except FileNotFoundError:
                pass
            raise
        return copy_path

    def _native_repack(
        self,
        output_path: str,
        replacements: set[str] | None = None,
        replacement_dir: str | None = None,
    ) -> None:
        """Copy the IPA, remove unwanted entries, and add replacements."""
        assert self.filename is not None
        source_path = os.path.abspath(self.filename)
        output_path = os.path.abspath(output_path)
        replacements = replacements or set()
        watch_replacement_prefix = f"{self.app_name}/Watch/"
        replacements = {
            filename
            for filename in replacements
            if not filename.startswith(watch_replacement_prefix)
        }
        if replacements and replacement_dir is None:
            raise ValueError("replacement_dir is required for replacements")
        existing_entries = set(self.namelist())

        shutil.copyfile(source_path, output_path)

        watch_prefix = f"{self.app_path}/Watch/"
        delete_entries = []
        if any(name.startswith(watch_prefix) for name in existing_entries):
            delete_entries.append(f"{watch_prefix}*")
        delete_entries.extend(
            f"Payload/{filename}"
            for filename in sorted(replacements)
            if f"Payload/{filename}" in existing_entries
        )
        if delete_entries:
            logger.info("removing bundled Watch app and replaced entries")
            subprocess.run(
                ["zip", "-dq", output_path, *delete_entries],
                check=True,
            )

        if not replacements:
            return
        assert replacement_dir is not None

        with tempfile.TemporaryDirectory(prefix="dumpster-ipa-") as staging_dir:
            payload_dir = os.path.join(staging_dir, "Payload")
            archive_paths: list[str] = []
            for filename in sorted(replacements):
                source = os.path.join(replacement_dir, filename)
                archive_path = f"Payload/{filename}"
                destination = os.path.abspath(os.path.join(staging_dir, archive_path))
                if os.path.commonpath([payload_dir, destination]) != payload_dir:
                    raise ValueError(f"replacement escapes Payload/: {filename}")
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                shutil.copy2(source, destination)
                archive_paths.append(archive_path)

            logger.info("adding decrypted binaries to archive")
            subprocess.run(
                ["zip", "-q", "-0", "-y", output_path, *archive_paths],
                cwd=staging_dir,
                check=True,
            )

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

        logger.info("creating decrypted archive")
        self._native_repack(out_ipa, replacements, replacement_dir=dumpdir)

        logger.info(f"decrypted IPA saved to {out_ipa}")
        return out_ipa
