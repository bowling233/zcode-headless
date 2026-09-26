import base64
import hashlib
import json
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

import zcode_headless as z


class FakeProcess:
    def __init__(self, returncode=None):
        self.returncode = returncode

    def poll(self):
        return self.returncode


class ZCodeHeadlessTests(unittest.TestCase):
    def test_appimage_names_support_x64_and_arm64(self):
        self.assertEqual(
            z.app_version_from_path("ZCode-3.14.3-linux-x64.AppImage"), "3.14.3"
        )
        self.assertEqual(
            z.app_version_from_path("ZCode-3.14.3-linux-arm64.AppImage"), "3.14.3"
        )

    def test_find_appimage_ignores_other_cpu_architecture(self):
        with tempfile.TemporaryDirectory() as td:
            apps = Path(td)
            expected = apps / "ZCode-3.14.3-linux-x64.AppImage"
            other = apps / "ZCode-9.0.0-linux-arm64.AppImage"
            expected.touch()
            other.touch()
            with (
                mock.patch.object(z, "APPS_DIR", apps),
                mock.patch.object(z, "release_platform", return_value="linux-x64"),
            ):
                self.assertEqual(z.find_appimage(), expected)

    def test_remote_route_matches_official_version_gate(self):
        self.assertEqual(z.web_remote_path("3.3.9"), "/remote/v3")
        self.assertEqual(z.web_remote_path("3.4.0-beta.1"), "/remote/v3")
        self.assertEqual(z.web_remote_path("3.4.0"), "/remote/v4")
        self.assertEqual(z.web_remote_path("3.5.0-beta.1"), "/remote/v4")
        self.assertEqual(z.web_remote_path("3.14.3"), "/remote/v4")

    def test_explicit_credential_secret_matches_official_precedence(self):
        with mock.patch.dict(
            z.os.environ, {"ZCODE_CREDENTIAL_SECRET": "configured-secret"}
        ):
            self.assertEqual(z.credential_secret(), "configured-secret")

    def test_process_match_only_accepts_executable_token(self):
        appimage = "/home/test/Applications/ZCode-3.14.3-linux-x64.AppImage"
        self.assertTrue(z.is_zcode_executable(appimage))
        self.assertFalse(z.is_zcode_executable("rg"))
        # find_running 只把 argv[0] 交给匹配器，因此参数里出现路径不会误报。
        self.assertFalse(z.is_zcode_executable("python"))

    def test_start_app_uses_private_appimage_tmpdir(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            control = root / "control"
            appimage_tmp = control / "tmp"
            fake_process = mock.Mock(pid=123)
            with (
                mock.patch.object(z, "CTL_DIR", control),
                mock.patch.object(z, "APPIMAGE_TMP_DIR", appimage_tmp),
                mock.patch.object(z, "APP_LOG", control / "app.log"),
                mock.patch.object(z, "STATE_FILE", control / "state.json"),
                mock.patch.object(z, "V2_DIR", root / "v2"),
                mock.patch.object(z.shutil, "which", return_value=None),
                mock.patch.object(
                    z.subprocess, "Popen", return_value=fake_process
                ) as popen,
                mock.patch.dict(z.os.environ, {"DISPLAY": ":99"}),
            ):
                process, display, _ = z.start_app(root / "ZCode.AppImage", [])
            self.assertIs(process, fake_process)
            self.assertEqual(display, "当前会话显示")
            self.assertEqual(popen.call_args.kwargs["env"]["TMPDIR"], str(appimage_tmp))
            self.assertEqual(appimage_tmp.stat().st_mode & 0o777, 0o700)

    def test_wait_relay_ready_observes_data_after_checkpoint(self):
        with tempfile.TemporaryDirectory() as td:
            v2_dir = Path(td)
            log_dir = v2_dir / "logs"
            log_dir.mkdir()
            log_path = log_dir / time.strftime("%Y-%m-%d.log", time.localtime())
            log_path.write_text("old\n")
            with mock.patch.object(z, "V2_DIR", v2_dir):
                checkpoint = z.relay_log_checkpoint()
                with log_path.open("a") as fp:
                    fp.write('external relay device state {"state":"paired"}\n')
                state = z.wait_relay_ready(
                    FakeProcess(), checkpoint, deadline=time.time() + 0.5
                )
            self.assertEqual(state, "paired")

    def test_wait_relay_ready_reports_exited_child_immediately(self):
        started = time.monotonic()
        state = z.wait_relay_ready(FakeProcess(1), {}, deadline=time.time() + 60)
        self.assertEqual(state, "process-exited")
        self.assertLess(time.monotonic() - started, 0.5)

    def test_wait_relay_ready_reports_restore_failure(self):
        with tempfile.TemporaryDirectory() as td:
            v2_dir = Path(td)
            log_dir = v2_dir / "logs"
            log_dir.mkdir()
            log_path = log_dir / time.strftime("%Y-%m-%d.log", time.localtime())
            log_path.write_text("old\n")
            with mock.patch.object(z, "V2_DIR", v2_dir):
                checkpoint = z.relay_log_checkpoint()
                with log_path.open("a") as fp:
                    fp.write(
                        "[web-remote-control] restore previous enabled state failed Error\n"
                    )
                state = z.wait_relay_ready(
                    FakeProcess(), checkpoint, deadline=time.time() + 0.5
                )
            self.assertEqual(state, "relay-error")

    def test_rotate_stops_a_running_instance_before_registering(self):
        with (
            mock.patch.object(
                z, "find_running", return_value=[(123, "3.14.3", "ZCode")]
            ),
            mock.patch.object(z, "do_stop") as stop,
            mock.patch.object(z, "logged_in", return_value=True),
            mock.patch.object(z, "do_enable") as enable,
            mock.patch.object(z, "find_appimage", return_value=None),
            mock.patch.object(z, "log"),
            mock.patch.object(z, "die", side_effect=SystemExit),
            self.assertRaises(SystemExit),
        ):
            z.do_start(rotate=True)
        stop.assert_called_once_with(quiet=True)
        enable.assert_called_once_with()

    def test_enable_persists_official_pass_hash_not_password(self):
        with tempfile.TemporaryDirectory() as td:
            v2_dir = Path(td) / "v2"
            fixed_random = b"a" * 24
            password = base64.urlsafe_b64encode(fixed_random).decode().rstrip("=")
            pass_hash = base64.b64encode(
                hashlib.sha256(password.encode()).digest()
            ).decode()
            exchange = mock.Mock(return_value=("d_test", "waiting"))
            with (
                mock.patch.object(z, "V2_DIR", v2_dir),
                mock.patch.object(z, "find_appimage", return_value=None),
                mock.patch.object(z, "log"),
                mock.patch.object(z, "relay_exchange", exchange),
                mock.patch.object(
                    z.os, "urandom", side_effect=lambda size: b"a" * size
                ),
            ):
                z.do_enable()
                creds = json.loads((v2_dir / "credentials.json").read_text())
                saved = z.decrypt_enc_v1(
                    creds["web-remote-control:external-relay:pass_hash"],
                    z.credential_secret(),
                )
            self.assertEqual(saved, pass_hash)
            self.assertNotEqual(saved, password)
            self.assertEqual(exchange.call_args.kwargs["proof_key"], pass_hash)
            self.assertEqual(
                exchange.call_args.kwargs["device_mid"],
                exchange.call_args.args[0]["device_mid"],
            )

    def test_build_link_uses_persisted_hash_and_v4(self):
        with tempfile.TemporaryDirectory() as td:
            v2_dir = Path(td)
            (v2_dir / "setting.json").write_text(
                json.dumps(
                    {
                        "webRemoteControlExternalRelayDevice": {"deviceSid": "d_test"},
                    }
                )
            )
            (v2_dir / "credentials.json").write_text(
                json.dumps(
                    {
                        "web-remote-control:external-relay:pass_hash": z.encrypt_secret(
                            "hash_test"
                        ),
                    }
                )
            )
            (v2_dir / "telemetry-state.json").write_text(
                json.dumps({"deviceMid": "mid_test"})
            )
            with mock.patch.object(z, "V2_DIR", v2_dir):
                url, problem = z.build_link("3.14.3")
            parsed = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qs(parsed.query)
            self.assertIsNone(problem)
            self.assertEqual(parsed.path, "/remote/v4")
            self.assertEqual(query["sid"], ["d_test"])
            self.assertEqual(query["hash"], ["hash_test"])
            self.assertEqual(query["mid"], ["mid_test"])

    def test_merge_json_is_atomic_and_private(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "credentials.json"
            z._merge_json(path, {"secret": "value"})
            self.assertEqual(json.loads(path.read_text()), {"secret": "value"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(path.parent.glob(".credentials.json.*")), [])


if __name__ == "__main__":
    unittest.main()
