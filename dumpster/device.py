from __future__ import annotations

import logging
import os
import plistlib
import posixpath
import shlex
import subprocess
import time

import ios_tools

TRANSPORT_FAILURE_CODE = 255
TRANSPORT_RETRY_ATTEMPTS = 3
TRANSPORT_RETRY_DELAY = 2.0
REMOTE_BIN_DIR_ENV = "DUMPSTER_REMOTE_BIN"
DEFAULT_REMOTE_BIN_DIR = "/var/jb/bin"


class RemoteError(RuntimeError):
    """An SSH or SCP invocation failed."""

    HINTS = {
        127: "command not found on device",
        TRANSPORT_FAILURE_CODE: "SSH transport failure",
    }

    def __init__(
        self,
        program: str,
        remote_cmd: str | None,
        returncode: int,
        stderr: bytes,
    ) -> None:
        self.returncode = returncode
        self.stderr = stderr.decode(errors="replace").strip()

        message = f"{program} exited {returncode}"
        if remote_cmd:
            message += f" running `{remote_cmd}`"
        if hint := self.HINTS.get(returncode):
            message += f" ({hint})"
        if self.stderr:
            message += f": {self.stderr}"
        super().__init__(message)


def _run_transport(
    cmd: list[str],
    *,
    check: bool,
    remote_cmd: str | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(cmd, capture_output=True)
    for attempt in range(1, TRANSPORT_RETRY_ATTEMPTS):
        if result.returncode != TRANSPORT_FAILURE_CODE:
            break
        logging.warning(
            "SSH connection lost, retrying (%d/%d)",
            attempt,
            TRANSPORT_RETRY_ATTEMPTS - 1,
        )
        time.sleep(TRANSPORT_RETRY_DELAY)
        result = subprocess.run(cmd, capture_output=True)

    # A transport failure is never a meaningful remote command result. Raise it
    # even when callers want to inspect ordinary non-zero remote exit statuses.
    if result.returncode == TRANSPORT_FAILURE_CODE or (
        check and result.returncode != 0
    ):
        raise RemoteError(cmd[0], remote_cmd, result.returncode, result.stderr)
    return result


class Device:
    def __init__(self, host: str | None = None, udid: str | None = None) -> None:
        self.host = host
        self.udid = udid
        remote_bin_dir = os.environ.get(REMOTE_BIN_DIR_ENV, DEFAULT_REMOTE_BIN_DIR)
        if not posixpath.isabs(remote_bin_dir):
            raise ValueError(f"{REMOTE_BIN_DIR_ENV} must be an absolute path")
        self.remote_bin_dir = posixpath.normpath(remote_bin_dir)

    def _require_host(self) -> str:
        if not self.host:
            raise RuntimeError("SSH host alias is required")
        return self.host

    def idevice(self, *args: str) -> list[str]:
        cmd = list(args)
        if self.udid:
            cmd.insert(1, self.udid)
            cmd.insert(1, "-u")
        return cmd

    def tool_path(self, name: str) -> str:
        return posixpath.join(self.remote_bin_dir, name)

    def ssh(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        host = self._require_host()
        remote_cmd = shlex.join(args)
        return _run_transport(
            ["ssh", host, remote_cmd],
            check=check,
            remote_cmd=remote_cmd,
        )

    def pull(self, remote: str, local: str) -> None:
        host = self._require_host()
        # SFTP mode (default since OpenSSH 9): the legacy SCP protocol (-O)
        # can't handle paths with spaces with modern clients
        _run_transport(
            ["scp", f"{host}:{remote}", local],
            check=True,
        )

    def push(self, *local: str, remote: str) -> None:
        host = self._require_host()
        _run_transport(
            ["scp", *local, f"{host}:{remote}"],
            check=True,
        )

    def ensure_tool(self, name: str, build_dir: str) -> None:
        target = self.tool_path(name)
        result = self.ssh("ldid", "-e", target, check=False)
        if result.returncode == 0 and b"platform-application" in result.stdout:
            return
        logging.info(f"{name} missing or unsigned on device, deploying")

        binary = ios_tools.get(build_dir, name)
        entxml = ios_tools.get(build_dir, "ent.xml")
        self.push(binary, entxml, remote="/tmp/")

        self.ssh("mv", f"/tmp/{name}", target)
        self.ssh("chmod", "755", target)
        self.ssh("ldid", "-S/tmp/ent.xml", target)

    def get_installed_apps(self) -> list[dict]:
        cmd = self.idevice("ideviceinstaller", "list", "--xml", "--user")
        return plistlib.loads(subprocess.check_output(cmd))

    def find_app(self, bundle_id: str) -> dict | None:
        for app in self.get_installed_apps():
            if app.get("CFBundleIdentifier") == bundle_id:
                return app
        return None
