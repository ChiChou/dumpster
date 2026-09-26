from __future__ import annotations

import argparse
import logging
import os
import sys

from .core import decrypt, list_apps, process_ipa
from .device import Device
from .ipa import IPA


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
    parser.add_argument(
        "--no-installd-hook",
        action="store_true",
        help="install IPAs without loading the bundled Frida installd hook",
    )
    parser.add_argument("-l", "--list", action="store_true", help="list installed apps")
    parser.add_argument("-u", "--udid", help="device UDID (for multiple devices)")
    parser.add_argument(
        "--host",
        metavar="ALIAS",
        help="SSH host alias configured in ~/.ssh/config",
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

    if args.list:
        list_apps(Device(udid=args.udid))
        return

    if not args.targets:
        parser.error("at least one target is required unless using -l")
    if not args.host:
        parser.error("--host is required")

    dev = Device(args.host, udid=args.udid)

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
                    use_installd_hook=not args.no_installd_hook,
                )
            else:
                decrypt(
                    dev,
                    target,
                    all_binaries=not args.no_ext,
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
        with IPA(path, "r") as ipa:
            bundle_id = ipa.bundle_id
            outdir = os.path.join(args.dump_dir, bundle_id)
            if not os.path.isdir(outdir):
                logging.error(f"no dump found for {bundle_id} at {outdir}, skipping")
                continue
            ipa.repack(outdir)


if __name__ == "__main__":
    main()
