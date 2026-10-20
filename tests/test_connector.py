import json
import os
import sys
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock

from zenvore_connector.adapters import AdapterError, adapter_for
from zenvore_connector.adapters.simulator import Simulator
from zenvore_connector.auth import CredentialStore
from zenvore_connector.cloud import Cloud, CloudError
from zenvore_connector.config import Config
from zenvore_connector.discovery import bounded_discover
from zenvore_connector.health import Health
from zenvore_connector.main import InstanceLock
from zenvore_connector.runtime import Runtime
from zenvore_connector.storage import Store
from zenvore_connector.sync import DeviceLocks, Sync, normalize

DEVICE = {"_id": "111111111111111111111111", "adapter": "simulator", "ip": "127.0.0.1", "port": 4370,
          "timezone": "Asia/Kolkata", "historySince": "2026-01-01T00:00:00Z"}
RECORD = {"index": 1, "deviceUserId": "1001", "timestamp": "2026-10-19T14:00:00+05:30", "eventType": "check-in"}


class ConnectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = self.root / "fixture.json"
        self.data = {"devices": {"4370": {"identity": "SIM-001", "generation": "gen-1", "users": ["1001"], "events": [dict(RECORD)]}}}
        self.save_fixture()
        self.config = Config("http://127.0.0.1:3000/api/v1", self.root, True, self.fixture)
        self.store = Store(self.root)
        self.cloud = Mock()
        self.cloud.request.side_effect = self.ack
        self.health = Health()
        self.sync = Sync(self.store, self.cloud, DeviceLocks(), self.health)
        self.adapter = Simulator(DEVICE, self.fixture, self.store)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def save_fixture(self):
        self.fixture.write_text(json.dumps(self.data), encoding="utf-8")

    @staticmethod
    def ack(method, route, body):
        return {"committed": True, "acceptedEventIds": [e["eventId"] for e in body["events"]],
                "position": body["position"], "generation": body["generation"]}

    def test_restart_replays_exact_persisted_batch_after_lost_acknowledgement(self):
        committed = set()
        first = True
        def lose_ack(method, route, body):
            nonlocal first
            committed.update(e["eventId"] for e in body["events"])
            if first:
                first = False
                raise CloudError("CLOUD_NETWORK")
            return self.ack(method, route, body)
        self.cloud.request.side_effect = lose_ack
        with self.assertRaises(CloudError):
            self.sync.run(DEVICE, self.adapter)
        pending = self.store.pending(DEVICE["_id"])
        self.assertIsNone(self.store.checkpoint(DEVICE["_id"]))
        self.store.close()
        self.store = Store(self.root)
        self.adapter = Simulator(DEVICE, self.fixture, self.store)
        self.sync = Sync(self.store, self.cloud, DeviceLocks(), self.health)
        self.sync.run(DEVICE, self.adapter)
        self.assertEqual(len(committed), 1)
        self.assertEqual(self.cloud.request.call_args_list[1].args[2], pending)
        self.assertEqual(self.store.checkpoint(DEVICE["_id"])["position"], "1")
        self.assertIsNone(self.store.pending(DEVICE["_id"]))

    def test_mismatched_ack_keeps_pending_and_cursor_unchanged(self):
        self.cloud.request.return_value = {"committed": True, "acceptedEventIds": [], "position": "1", "generation": "gen-1"}
        self.cloud.request.side_effect = None
        with self.assertRaises(ValueError):
            self.sync.run(DEVICE, self.adapter)
        self.assertIsNotNone(self.store.pending(DEVICE["_id"]))
        self.assertIsNone(self.store.checkpoint(DEVICE["_id"]))

    def test_disk_full_does_not_upload_or_advance_cursor(self):
        import sqlite3
        original = self.store.stage
        self.store.stage = Mock(side_effect=sqlite3.OperationalError("database or disk is full"))
        with self.assertRaises(sqlite3.OperationalError):
            self.sync.run(DEVICE, self.adapter)
        self.cloud.request.assert_not_called()
        self.assertIsNone(self.store.checkpoint(DEVICE["_id"]))
        self.store.stage = original

    def test_zero_events_is_success_and_disconnection_is_separate(self):
        self.data["devices"]["4370"]["events"] = []
        self.save_fixture()
        self.assertEqual(self.sync.run(DEVICE, self.adapter), 0)
        self.assertIn("lastAttendanceFetch", self.health.snapshot())
        self.data["devices"]["4370"]["reachable"] = False
        self.save_fixture()
        with self.assertRaisesRegex(AdapterError, "DEVICE_UNREACHABLE"):
            self.sync.run(DEVICE, self.adapter)

    def test_manual_and_scheduled_syncs_do_not_overlap(self):
        entered, release = threading.Event(), threading.Event()
        original = self.adapter.fetch
        calls = []
        def fetch(*args):
            calls.append(1)
            entered.set()
            release.wait(2)
            return original(*args)
        self.adapter.fetch = fetch
        failures = []
        def execute():
            try:
                self.sync.run(DEVICE, self.adapter)
            except Exception as exc:
                failures.append(exc)
        one, two = threading.Thread(target=execute), threading.Thread(target=execute)
        one.start()
        self.assertTrue(entered.wait(1))
        two.start()
        time.sleep(.03)
        self.assertEqual(len(calls), 1)
        release.set()
        one.join(2); two.join(2)
        self.assertFalse(one.is_alive() or two.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(calls), 2)

    def test_generation_change_and_retention_gap_are_reported(self):
        page = self.adapter.fetch({"generation": "gen-1", "position": "1"}, DEVICE["historySince"])
        self.assertFalse(page.data_gap)
        self.data["devices"]["4370"]["events"] = [{**RECORD, "index": 5}]
        self.save_fixture()
        self.assertTrue(self.adapter.fetch({"generation": "gen-1", "position": "1"}, DEVICE["historySince"]).data_gap)
        self.data["devices"]["4370"]["generation"] = "gen-2"
        self.data["devices"]["4370"]["events"] = [dict(RECORD)]
        self.save_fixture()
        self.assertTrue(self.adapter.fetch({"generation": "gen-1", "position": "5"}, DEVICE["historySince"]).data_gap)
        a = normalize(DEVICE, "gen-1", RECORD)
        b = normalize(DEVICE, "gen-2", RECORD)
        self.assertNotEqual(a["eventId"], b["eventId"])

    def test_native_record_id_disambiguates_simultaneous_scans_and_normalizes_utc(self):
        a = normalize(DEVICE, "gen-1", RECORD)
        b = normalize(DEVICE, "gen-1", {**RECORD, "index": 2})
        self.assertNotEqual(a["eventId"], b["eventId"])
        self.assertEqual(a["occurredAt"], "2026-10-19T08:30:00Z")
        self.assertEqual(a["rawTimestamp"], RECORD["timestamp"])
        with self.assertRaises(AdapterError):
            normalize(DEVICE, "gen-1", {**RECORD, "timestamp": "2026-10-19T14:00:00"})

    def test_stale_enable_does_not_override_later_disable(self):
        self.adapter.set_access("1001", False, None, 2)
        self.adapter.set_access("1001", True, None, 1)
        self.assertEqual(self.adapter.read_access("1001"), {"version": 2, "enabled": False, "expiresAt": None})
        self.data["devices"]["4370"]["access"] = False
        self.save_fixture()
        with self.assertRaisesRegex(AdapterError, "UNSUPPORTED"):
            self.adapter.set_access("1001", True, None, 3)

    def test_runtime_rejects_stale_access_command_before_device_write(self):
        runtime = Runtime(self.config, self.store, self.cloud)
        runtime.handshake = Mock(return_value=self.adapter)
        runtime.desired = Mock(return_value=iter([{"memberId": "member", "version": 2, "enabled": False}]))
        self.cloud.request.side_effect = lambda *args: [DEVICE]
        self.assertEqual(runtime.execute({"type": "SET_MEMBER_ACCESS", "deviceId": DEVICE["_id"],
            "payload": {"memberId": "member", "version": 1}}), {"status": "superseded"})
        self.assertIsNone(self.adapter.read_access("1001"))

    def test_runtime_cannot_confuse_pairing_with_device_identity(self):
        runtime = Runtime(self.config, self.store, self.cloud)
        self.cloud.request.side_effect = None
        with self.assertRaisesRegex(AdapterError, "IDENTITY_MISMATCH"):
            runtime.handshake({**DEVICE, "identity": "SIM-OTHER"})
        self.cloud.request.assert_not_called()

    def test_completed_command_replays_without_repeating_device_operation(self):
        runtime = Runtime(self.config, self.store, self.cloud)
        self.cloud.request.side_effect = None
        runtime.execute = Mock(return_value={"status": "succeeded"})
        command = {"_id": "command", "leaseToken": "a" * 32, "attempts": 1}
        runtime.handle_command(command)
        runtime.handle_command({**command, "leaseToken": "b" * 32, "attempts": 2})
        runtime.execute.assert_called_once()
        self.assertEqual(self.cloud.request.call_args.args[2]["leaseToken"], "b" * 32)

    def test_transient_command_failure_reexecutes_on_new_attempt(self):
        runtime = Runtime(self.config, self.store, self.cloud)
        self.cloud.request.side_effect = None
        runtime.execute = Mock(side_effect=[AdapterError("DEVICE_UNREACHABLE", True), {"status": "succeeded"}])
        command = {"_id": "command", "leaseToken": "a" * 32, "attempts": 1}
        runtime.handle_command(command)
        runtime.handle_command({**command, "attempts": 2})
        self.assertEqual(runtime.execute.call_count, 2)

    def test_configuration_tls_and_secret_store_boundaries(self):
        for url, development in [("http://api.example.com", False), ("https://api.example.com", True),
                                 ("http://127.0.0.1", False), ("https://user:password@example.com", False)]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                Config(url, self.root, development)
        if os.name != "nt" and sys.platform != "darwin":
            with self.assertRaises(RuntimeError):
                CredentialStore(self.root)
        credentials = CredentialStore(self.root, development=True)
        credentials.save({"connectorId": "id", "credential": "secret"})
        self.assertEqual(credentials.load()["credential"], "secret")
        if os.name != "nt":
            self.assertEqual(credentials.path.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(AdapterError, "UNSUPPORTED"):
            adapter_for({**DEVICE, "adapter": "invented-vendor"}, self.config, self.store)

    def test_an_unrelated_open_tcp_port_is_not_a_device(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0)); server.listen()
        self.addCleanup(server.close)
        port = server.getsockname()[1]
        def handshake(ip, port, timeout):
            with socket.create_connection((ip, port), timeout):
                return True  # An open socket is deliberately not an identity.
        self.assertEqual(bounded_discover(["127.0.0.1/32"], [port], handshake), [])
        for subnet in ["192.168.0.0/16", "8.8.8.8/32"]:
            with self.assertRaises(ValueError):
                bounded_discover([subnet], [4370], handshake)

    def test_single_instance_and_pending_queue_cannot_be_overwritten(self):
        lock = InstanceLock(self.root)
        try:
            with self.assertRaises(RuntimeError):
                InstanceLock(self.root)
        finally:
            lock.close()
        batch = {"events": []}
        self.store.stage(DEVICE["_id"], batch)
        with self.assertRaises(RuntimeError):
            self.store.stage(DEVICE["_id"], batch)

    def test_access_token_refresh_on_expiry_and_authentication_failure(self):
        credentials = Mock()
        credentials.load.return_value = {"connectorId": "id", "credential": "secret"}
        cloud = Cloud(self.config, credentials)
        cloud.raw = Mock(side_effect=[{"accessToken": "old", "expiresIn": 900}, CloudError("CLOUD_AUTH", 401),
                                      {"accessToken": "fresh", "expiresIn": 900}, {"receivedAt": "now"}])
        cloud.request("POST", "/connectors/me/heartbeat", {})
        self.assertEqual(cloud.raw.call_args.args[3], "fresh")
        cloud.expires = 0
        cloud.raw.return_value = {"accessToken": "new", "expiresIn": 900}
        cloud.raw.side_effect = None
        self.assertEqual(cloud.access_token(), "new")


if __name__ == "__main__":
    unittest.main()
