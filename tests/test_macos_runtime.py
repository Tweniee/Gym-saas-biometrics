"""Mac security and lifecycle boundaries, without touching the real login Keychain/launchd."""
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from zenvore_connector.auth import CredentialStore
from zenvore_connector.macos_keychain import account_for
from zenvore_connector.macos_service import LABEL, MacService


class MacCredentialTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Mac branch uses POSIX paths")
    def test_production_secrets_go_to_keychain_and_disk_has_only_reference(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            keychain = Mock()
            secret = {"connectorId": "gym", "credential": "private-secret"}
            with patch("zenvore_connector.auth.sys.platform", "darwin"), \
                 patch("zenvore_connector.macos_keychain.Keychain", return_value=keychain):
                store = CredentialStore(directory)
                store.save(secret)
                account, payload = keychain.save.call_args.args
                self.assertEqual(json.loads(payload), secret)
                self.assertNotIn(b"private-secret", store.path.read_bytes())
                self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)
                keychain.load.return_value = payload
                self.assertEqual(store.load(), secret)
                self.assertEqual(keychain.load.call_args.args, (account,))
                keychain.load.return_value = None
                self.assertIsNone(store.load())
                self.assertNotEqual(account, account_for(directory, "devices.credential"))

    @unittest.skipIf(os.name == "nt", "Mac branch uses POSIX paths")
    def test_keychain_failure_does_not_fall_back_to_plaintext(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch("zenvore_connector.auth.sys.platform", "darwin"), \
                 patch("zenvore_connector.macos_keychain.Keychain") as backend:
                backend.return_value.save.side_effect = RuntimeError("Keychain locked")
                store = CredentialStore(Path(temporary))
                with self.assertRaises(RuntimeError):
                    store.save({"credential": "private-secret"})
                self.assertFalse(store.path.exists())
                backend.return_value.load.side_effect = RuntimeError("Keychain locked")
                with self.assertRaises(RuntimeError):
                    store.load()


@unittest.skipUnless(hasattr(os, "getuid"), "Per-user POSIX launchd agent")
class MacServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Zenvore Mac ")
        self.root = Path(self.temp.name)
        self.exe = self.root / "Applications/Zenvore Connector.app/Contents/MacOS/Zenvore Connector"
        self.exe.parent.mkdir(parents=True)
        self.exe.write_bytes(b"test")
        self.config = self.root / "state/config.json"
        self.config.parent.mkdir()
        self.config.write_text('{"api_url":"https://api.example.com/api/v1"}')
        self.service = MacService(self.config, self.exe, self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_enable_uses_exact_installed_app_and_per_user_config_with_no_secrets(self):
        with patch("zenvore_connector.macos_service.subprocess.run") as invoke:
            invoke.side_effect = [subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0)]
            self.service.enable()
        payload = plistlib.loads(self.service.plist_path.read_bytes())
        self.assertEqual(payload["ProgramArguments"], [str(self.exe.resolve()), "--config", str(self.config.resolve()), "run"])
        self.assertEqual(payload["Label"], LABEL)
        self.assertTrue(payload["RunAtLoad"])
        self.assertTrue(payload["KeepAlive"])
        self.assertEqual(payload["Umask"], 0o077)
        self.assertNotIn("EnvironmentVariables", payload)
        self.assertEqual(invoke.call_args.args[0][1:3], ["bootstrap", self.service.domain])

    def test_disable_removes_only_agent_and_preserves_state(self):
        self.service.plist_path.parent.mkdir(parents=True)
        self.service.plist_path.write_bytes(b"agent")
        with patch.object(self.service, "enabled", return_value=True), patch.object(self.service, "command") as invoke:
            self.service.disable()
        invoke.assert_called_once_with("bootout", self.service.domain + "/" + LABEL)
        self.assertFalse(self.service.plist_path.exists())
        self.assertTrue(self.config.exists())

    def test_source_python_and_mounted_dmg_are_rejected_before_installing_agent(self):
        source = MacService(self.config, self.root / "python", self.root)
        with self.assertRaisesRegex(RuntimeError, "installed Mac application"):
            source.enable()
        mounted = MacService(self.config, "/Volumes/Zenvore/Zenvore Connector.app/Contents/MacOS/Zenvore Connector", self.root)
        with patch.object(Path, "is_file", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "Applications"):
                mounted.enable()
        self.assertFalse(self.service.plist_path.exists())

    def test_launchd_failure_is_reported_without_subprocess_output(self):
        with patch("zenvore_connector.macos_service.subprocess.run", return_value=subprocess.CompletedProcess([], 5, b"private", b"private")):
            with self.assertRaisesRegex(RuntimeError, "launchd 5") as error:
                self.service.command("bootstrap", self.service.domain, "file")
        self.assertNotIn("private", str(error.exception))


class MacEthernetTests(unittest.TestCase):
    def test_hardware_port_types_distinguish_wifi_from_usb_ethernet(self):
        from zenvore_connector.discovery import macos_ethernet_names
        listing = b"""Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 00:00:00:00:00:00

Hardware Port: USB 10/100/1000 LAN
Device: en5
Ethernet Address: 00:00:00:00:00:01

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 00:00:00:00:00:02

Hardware Port: Ethernet Adapter (en6)
Device: en6
Ethernet Address: 00:00:00:00:00:03
"""
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, listing, b"")):
            self.assertEqual(macos_ethernet_names(), {"en5", "en6"})

    def test_missing_hardware_types_never_authorize_an_automatic_scan(self):
        from zenvore_connector.discovery import macos_ethernet_names
        with patch("subprocess.run", side_effect=OSError("unavailable")):
            self.assertEqual(macos_ethernet_names(), set())
