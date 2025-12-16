import argparse
import logging
import os
import plistlib
import shutil
import subprocess
import zipfile
import shlex
import lief

from utils import sizeof_fmt


class Job:
    def __init__(self, filename: str):
        self.filename = filename
        self.ipa = zipfile.ZipFile(self.filename, "r")
        self.app, self.metadata = self.load_info_plist()
        self.bundle_id = self.metadata["CFBundleIdentifier"]

    def load_info_plist(self) -> tuple[str, dict]:
        for zi in self.ipa.filelist:
            segments = zi.filename.split("/", 3)
            if len(segments) < 3:
                continue

            if (
                segments[0] != "Payload"
                or segments[2] != "Info.plist"
                or not segments[1].endswith(".app")
            ):
                continue

            with self.ipa.open(zi) as o:
                plist_data = o.read()
                plist = plistlib.loads(plist_data)
                return segments[1], plist

        raise RuntimeError("Info.plist not found in IPA")

    def encrypted_machos(self):
        assert self.ipa is not None, "invalid state"

        for zi in self.ipa.filelist:
            with self.ipa.open(zi) as o:
                data = o.read()
                binary = lief.parse(list(data))

            if isinstance(binary, lief.MachO.FatBinary):
                raise NotImplementedError("todo: handle fat binaries")

            if not isinstance(binary, lief.MachO.Binary):
                continue

            if not (binary.has_encryption_info and binary.encryption_info.crypt_id):
                continue

            logging.debug(
                f"encrypted executable: {zi.filename} {sizeof_fmt(zi.file_size)}"
            )

            yield zi.filename[len("Payload/") :]

    def run(self, host: str):
        subprocess.run(["ideviceinstaller", "install", self.filename], check=True)

        # get all app container
        xml = subprocess.check_output(["ideviceinstaller", "list", "--xml", "--user"])
        all_apps_info = plistlib.loads(xml)
        match = next(
            (
                app_info
                for app_info in all_apps_info
                if app_info.get("CFBundleIdentifier") == self.bundle_id
            )
        )

        bundle_path = match["Path"]

        def ssh(*remote_argv):
            # remote_argv: tokens for the remote command (do NOT pre-quote them)
            remote_cmd = shlex.join(remote_argv)  # properly quotes spaces, etc.
            subprocess.run(["ssh", host, remote_cmd], check=True)

        output = f"/tmp/unfairplay/{self.app}"

        executables = set(self.encrypted_machos())
        for filename in executables:
            # remove '*.app'
            tail = "/".join(filename.split("/")[1:])
            logging.info(f"decrypting {filename}")
            src = f"{bundle_path}/{tail}"
            dst = f"{output}/{tail}"
            parent_dir = dst[: dst.rfind("/")]

            ssh("mkdir", "-p", parent_dir)
            ssh("rm", "-rf", dst)
            ssh("/var/jb/unfair", src, dst)

        tmp = ".dump"
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp, exist_ok=True)
        subprocess.run(
            ["scp", "-O", "-r", f"{host}:{output}", tmp],
            check=True,
        )

        logging.info("successfully pulled decrypted files, now creating new archive")

        # make a copy
        prefix, *_ = os.path.splitext(os.path.basename(self.filename))
        out_ipa = prefix + ".decrypted.ipa"
        with zipfile.ZipFile(out_ipa, "w") as new_ipa:
            for item in self.ipa.infolist():
                filename = item.filename[len("Payload/") :]
                f = (
                    open(os.path.join(tmp, filename), "rb")
                    if filename in executables
                    else self.ipa.open(item)
                )
                with f:
                    data = f.read()
                new_ipa.writestr(item, data)
                logging.info(f"update {item.filename}")

        logging.info(f"decrypted ipa saved to {out_ipa}")


def main():
    parser = argparse.ArgumentParser(description="decrypt ipa downloaded from ipatool")
    parser.add_argument("filename", help="Path to the ipa file")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument("host", help="ssh host")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    Job(args.filename).run(args.host)


if __name__ == "__main__":
    main()
