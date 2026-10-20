"""The short-lived code is consumed once; device failures do not undo pairing."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from zenvore_connector.cloud import CloudError
from zenvore_connector.config import Config
from zenvore_connector.main import build
from zenvore_connector.pairing import ServerConnection


class ServerPairingFixture:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.config = Config("http://127.0.0.1:3000/api/v1", Path(self.temporary.name), development=True)
        self.runtime = build(self.config)
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(self.runtime.store.close)
        self.credential = {"connectorId": "connector-1", "credential": "installation-secret"}
        self.setup = {"gymId": "gym-1", "gymName": "Test gym"}
        self.runtime.cloud.raw = Mock(side_effect=self.respond)
        self.runtime.discover = Mock(side_effect=AssertionError("Pairing must not scan Ethernet"))
        self.runtime.handshake = Mock(side_effect=AssertionError("Pairing must not connect to a device"))
        self.connection = ServerConnection(self.runtime)

    def respond(self, method, route, body=None, token=None, timeout=None):
        if route == "/connectors/pair":
            return dict(self.credential)
        if route == "/connectors/token":
            self.assertEqual(body, self.credential)
            return {"accessToken": "access-token", "expiresIn": 900}
        self.assertEqual(token, "access-token")
        if route == "/connectors/me/setup":
            return self.setup
        if route == "/connectors/me/heartbeat":
            return {}
        raise AssertionError("Unexpected device request: " + route)

    def pair_count(self):
        return sum(call.args[1] == "/connectors/pair" for call in self.runtime.cloud.raw.call_args_list)


class ServerPairingTests(ServerPairingFixture, unittest.TestCase):
    def test_pair_saves_credential_authenticates_and_sends_heartbeat_without_device(self):
        status = self.connection.pair(" short-lived-code ")
        self.assertEqual(status.setup, self.setup)
        self.assertTrue(status.paired)
        self.assertFalse(status.needs_pairing)
        self.assertEqual(self.runtime.cloud.credentials.load(), self.credential)
        self.assertIsNotNone(self.runtime.store.get("lastHeartbeat"))
        self.runtime.discover.assert_not_called()
        self.runtime.handshake.assert_not_called()
        self.assertEqual(self.pair_count(), 1)

    def test_restart_and_access_token_expiry_reuse_saved_installation(self):
        self.connection.pair("short-lived-code")
        restarted = build(self.config)
        self.addCleanup(restarted.store.close)
        restarted.cloud.raw = Mock(side_effect=self.respond)
        connection = ServerConnection(restarted)
        self.assertEqual(connection.check().setup, self.setup)
        restarted.cloud.expires = 0
        self.assertEqual(connection.check().setup, self.setup)
        routes = [call.args[1] for call in restarted.cloud.raw.call_args_list]
        self.assertEqual(routes.count("/connectors/pair"), 0)
        self.assertEqual(routes.count("/connectors/token"), 2)

    def test_failure_after_redemption_keeps_pairing_and_retries_without_a_new_code(self):
        def unavailable(method, route, *args, **kwargs):
            if route != "/connectors/pair":
                raise CloudError("CLOUD_NETWORK")
            return self.respond(method, route, *args, **kwargs)
        self.runtime.cloud.raw.side_effect = unavailable
        status = self.connection.pair("short-lived-code")
        self.assertTrue(status.paired)
        self.assertFalse(status.needs_pairing)
        self.assertEqual(status.error, "CLOUD_NETWORK")
        # Even an additional click with a different code preserves the pairing.
        self.assertFalse(self.connection.pair("another-code").needs_pairing)
        self.assertEqual(self.pair_count(), 1)
        self.runtime.cloud.raw.side_effect = self.respond
        self.assertEqual(self.connection.check().setup, self.setup)
        self.assertEqual(self.pair_count(), 1)

    def test_failed_device_operation_does_not_require_pairing_again(self):
        self.connection.pair("short-lived-code")
        with self.assertRaises(AssertionError):
            self.runtime.handshake({"ip": "192.168.1.201", "port": 4370})
        self.assertEqual(self.connection.check().setup, self.setup)
        self.assertEqual(self.pair_count(), 1)

    def test_locked_secure_store_does_not_consume_code(self):
        with patch.object(self.runtime.cloud.credentials, "load", side_effect=RuntimeError("Keychain locked")):
            with self.assertRaises(RuntimeError):
                self.connection.pair("short-lived-code")
        self.runtime.cloud.raw.assert_not_called()

    def test_unpaired_status_does_not_call_server_or_hardware(self):
        self.assertTrue(self.connection.check().needs_pairing)
        self.runtime.cloud.raw.assert_not_called()
        with self.assertRaises(ValueError):
            self.connection.pair(" ")
        self.runtime.cloud.raw.assert_not_called()

    def test_tls_failure_during_redemption_does_not_save_unverified_credentials(self):
        self.runtime.cloud.raw.side_effect = CloudError("CLOUD_TLS")
        with self.assertRaises(CloudError):
            self.connection.pair("short-lived-code")
        self.assertIsNone(self.runtime.cloud.credentials.load())

    def test_revoked_pairing_requires_explicit_new_pair_action(self):
        self.connection.pair("short-lived-code")
        self.runtime.cloud.raw.side_effect = CloudError("CLOUD_AUTH", 401)
        status = self.connection.check()
        self.assertTrue(status.needs_pairing)
        self.assertTrue(status.paired)
        self.assertEqual(self.pair_count(), 1)
        self.runtime.cloud.raw.side_effect = self.respond
        self.assertEqual(self.runtime.cloud.credentials.load(), self.credential)

    def test_status_refresh_throttles_heartbeats(self):
        with patch("zenvore_connector.pairing.time.monotonic", return_value=100):
            self.connection.pair("short-lived-code")
            self.connection.check()
        with patch("zenvore_connector.pairing.time.monotonic", return_value=161):
            self.connection.check()
        heartbeats = [call for call in self.runtime.cloud.raw.call_args_list if call.args[1] == "/connectors/me/heartbeat"]
        self.assertEqual(len(heartbeats), 2)
