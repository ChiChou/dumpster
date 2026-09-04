from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from dumpster.device import Device, RemoteError, _run_transport


def completed(returncode: int = 0, stderr: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], returncode, stdout=b"", stderr=stderr)


class DeviceTransportTests(unittest.TestCase):
    @mock.patch("dumpster.device.subprocess.run", return_value=completed())
    def test_ssh_quotes_each_remote_argument(self, run: mock.Mock) -> None:
        Device("iphone").ssh("mkdir", "-p", "/tmp/path with spaces")

        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["ssh", "iphone"])
        self.assertEqual(command[-1], "mkdir -p '/tmp/path with spaces'")

    @mock.patch("dumpster.device.subprocess.run", return_value=completed())
    def test_sftp_remote_path_with_spaces_stays_one_argument(
        self, run: mock.Mock
    ) -> None:
        Device("iphone").pull("/tmp/path with spaces/file", "local")

        command = run.call_args.args[0]
        self.assertIn("iphone:/tmp/path with spaces/file", command)
        self.assertNotIn("-O", command)

    @mock.patch("dumpster.device.time.sleep")
    @mock.patch("dumpster.device.subprocess.run")
    def test_transport_retries_exit_255(
        self, run: mock.Mock, sleep: mock.Mock
    ) -> None:
        run.side_effect = [completed(255), completed()]

        result = _run_transport(["ssh"], check=True)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once()

    @mock.patch("dumpster.device.time.sleep")
    @mock.patch("dumpster.device.subprocess.run", return_value=completed(255, b"gone"))
    def test_transport_failure_raises_even_without_check(
        self, run: mock.Mock, sleep: mock.Mock
    ) -> None:
        with self.assertRaisesRegex(RemoteError, "SSH transport failure.*gone"):
            _run_transport(["ssh"], check=False)

        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_count, 2)


class ToolDeploymentTests(unittest.TestCase):
    def test_valid_signed_tool_is_kept(self) -> None:
        dev = Device("iphone")
        dev.ssh = mock.Mock(
            return_value=subprocess.CompletedProcess(
                [], 0, stdout=b"<key>platform-application</key>", stderr=b""
            )
        )
        dev.push = mock.Mock()

        dev.ensure_tool("dumpster", "wrapper")

        dev.push.assert_not_called()

    @mock.patch("dumpster.device.ios_tools.get")
    @mock.patch.dict(
        "dumpster.device.os.environ",
        {"DUMPSTER_REMOTE_BIN": "/opt/jailbreak/bin"},
    )
    def test_unsigned_tool_is_deployed_with_separate_commands(
        self, get: mock.Mock
    ) -> None:
        get.side_effect = ["local-tool", "local-entitlements"]
        dev = Device("iphone")
        dev.ssh = mock.Mock(return_value=completed())
        dev.push = mock.Mock()

        dev.ensure_tool("dumpster", "wrapper")

        dev.push.assert_called_once_with(
            "local-tool", "local-entitlements", remote="/tmp/"
        )
        self.assertEqual(
            dev.ssh.call_args_list,
            [
                mock.call(
                    "ldid", "-e", "/opt/jailbreak/bin/dumpster", check=False
                ),
                mock.call("mv", "/tmp/dumpster", "/opt/jailbreak/bin/dumpster"),
                mock.call("chmod", "755", "/opt/jailbreak/bin/dumpster"),
                mock.call(
                    "ldid", "-S/tmp/ent.xml", "/opt/jailbreak/bin/dumpster"
                ),
            ],
        )


if __name__ == "__main__":
    unittest.main()
