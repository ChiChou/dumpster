from __future__ import annotations

import argparse
import logging
import os
import sys

from .codesign import list_codesign_identities
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
    parser.add_argument("-l", "--list", action="store_true", help="list installed apps")
    parser.add_argument("-u", "--udid", help="device UDID (for multiple devices)")
    parser.add_argument(
        "--host",
        metavar="ALIAS",
        help="SSH host alias configured in ~/.ssh/config",
    )
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

    if args.list:
        list_apps(Device(udid=args.udid))
        return

    if not args.targets:
        parser.error("at least one target is required unless using -l")
    if not args.host:
        parser.error("--host is required")

    dev = Device(args.host, udid=args.udid)

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
        with IPA(path, "r") as ipa:
            bundle_id = ipa.bundle_id
            outdir = os.path.join(args.dump_dir, bundle_id)
            if not os.path.isdir(outdir):
                logging.error(f"no dump found for {bundle_id} at {outdir}, skipping")
                continue
            ipa.repack(outdir)


if __name__ == "__main__":
    main()
