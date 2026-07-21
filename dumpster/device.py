from __future__ import annotations

import logging
import plistlib
import shlex
import subprocess

import ios_tools

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
        # SFTP mode (default since OpenSSH 9): the legacy SCP protocol (-O)
        # can't handle paths with spaces with modern clients
        subprocess.run(
            ["scp", *self._conn, f"{self._remote}:{remote}", local],
            check=True,
        )

    def push(self, *local: str, remote: str) -> None:
        subprocess.run(
            ["scp", *self._conn, *local, f"{self._remote}:{remote}"],
            check=True,
        )

    def ensure_tool(self, name: str, build_dir: str) -> None:
        result = self.ssh("test", "-x", f"/var/jb/bin/{name}", check=False)
        if result.returncode == 0:
            return
        logging.info(f"{name} not found on device, deploying")

        binary = ios_tools.get(build_dir, name)
        entxml = ios_tools.get(build_dir, "ent.xml")
        self.push(binary, entxml, remote="/tmp/")

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
