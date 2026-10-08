"""Behavior tests using simulated devices; no LAN scanning or GUI is started."""

import json
import logging
import os
import queue
import struct
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import identix_manager as manager


class DiscoveryTests(unittest.TestCase):
    def test_ip_subnet_port_range_and_duplicate_expansion(self):
        targets = manager.parse_scan_targets(
            "192.168.1.0/30,192.168.1.1", "4370,4370-4372")
        self.assertEqual(targets, [(ip, port)
                                  for ip in ("192.168.1.1", "192.168.1.2")
                                  for port in (4370, 4371, 4372)])

    def test_default_subnet_has_254_hosts(self):
        targets = manager.parse_scan_targets("192.168.1.201/24", "4370")
        self.assertEqual(len(targets), 254)
        self.assertEqual(targets[0], ("192.168.1.1", 4370))
        self.assertEqual(targets[-1], ("192.168.1.254", 4370))

    def test_single_ip_and_nonstandard_port(self):
        self.assertEqual(manager.parse_scan_targets("192.168.1.201", "5005"),
                         [("192.168.1.201", 5005)])

    def test_rejects_invalid_and_excessive_scans(self):
        for addresses, ports in (("", "4370"), ("::1", "4370"),
                                 ("192.168.0.0/16", "4370"),
                                 ("192.168.0.0/24,192.168.1.0/24", "4370"),
                                 ("192.168.1.1", ""), ("192.168.1.1", "0"),
                                 ("192.168.1.1", "65536"),
                                 ("192.168.1.1", "4372-4370"),
                                 ("192.168.1.1", "1-33"),
                                 ("192.168.1.1", "1-32,4370")):
            with self.subTest(addresses=addresses, ports=ports):
                with self.assertRaises(ValueError):
                    manager.parse_scan_targets(addresses, ports)

    def test_background_scan_reports_only_open_endpoints(self):
        targets = manager.parse_scan_targets("192.168.1.1,192.168.1.2", "4370,5005")
        out = queue.Queue()
        with patch.object(manager, "port_open", side_effect=lambda ip, port, timeout: port == 5005):
            worker = manager.DiscoveryWorker(targets, out)
            worker.start()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        messages = list(out.queue)
        self.assertEqual({msg[1:] for msg in messages if msg[0] == "found"},
                         {("192.168.1.1", 5005), ("192.168.1.2", 5005)})
        self.assertEqual(messages[-1], ("done", 4, 2, False))

    def test_cancelled_scan_does_not_probe(self):
        out = queue.Queue()
        worker = manager.DiscoveryWorker([("192.168.1.1", 4370)], out)
        worker.stop()
        with patch.object(manager, "port_open") as probe:
            worker.start()
            worker.join(2)
            probe.assert_not_called()
        self.assertEqual(out.get(timeout=1), ("done", 0, 0, True))


class SyncTests(unittest.TestCase):
    def start_worker(self, cfg=None):
        config = dict(manager.DEFAULT_CONFIG if cfg is None else cfg)
        out = queue.Queue()
        worker = manager.SyncWorker(lambda: dict(config), out)
        self.addCleanup(lambda: (worker.stop(), worker.join(2)))
        worker.start()
        return worker, out, config

    def test_launch_fetches_without_button(self):
        with patch.object(manager, "port_open", return_value=True), \
                patch.object(manager.Device, "fetch_users", return_value=[{"uid": 1}]):
            worker, out, cfg = self.start_worker()
            message = out.get(timeout=2)
            worker.stop()
            worker.join(2)
        self.assertEqual(message[0:2], ("users", [{"uid": 1}]))
        self.assertEqual(message[-1], cfg)

    def test_offline_retries_and_fetches_when_device_returns(self):
        with patch.object(manager, "RETRY_SECONDS", 0.01), \
                patch.object(manager, "port_open", side_effect=[False, True]), \
                patch.object(manager.Device, "fetch_users", return_value=[]):
            worker, out, _cfg = self.start_worker()
            self.assertEqual(out.get(timeout=2)[0], "offline")
            self.assertEqual(out.get(timeout=2)[0], "users")
            worker.stop()
            worker.join(2)

    def test_successful_read_waits_for_cache_interval(self):
        with patch.object(manager, "port_open", return_value=True), \
                patch.object(manager.Device, "fetch_users", return_value=[]) as fetch:
            worker, out, _cfg = self.start_worker()
            self.assertEqual(out.get(timeout=2)[0], "users")
            with self.assertRaises(queue.Empty):
                out.get(timeout=0.05)
            fetch.assert_called_once()
            worker.stop()
            worker.join(2)

    def test_periodic_fetch_runs_without_button(self):
        with patch.object(manager, "port_open", return_value=True), \
                patch.object(manager.Device, "fetch_users", return_value=[]):
            worker, out, _cfg = self.start_worker(dict(manager.DEFAULT_CONFIG, cache_seconds=0.01))
            self.assertEqual(out.get(timeout=2)[0], "users")
            self.assertEqual(out.get(timeout=2)[0], "users")
            worker.stop()
            worker.join(2)

    def test_forced_refresh_failure_retries_before_cache_expiry(self):
        with patch.object(manager, "RETRY_SECONDS", 0.01), \
                patch.object(manager, "port_open", side_effect=[True, False, True]), \
                patch.object(manager.Device, "fetch_users", return_value=[]):
            worker, out, _cfg = self.start_worker()
            self.assertEqual(out.get(timeout=2)[0], "users")
            worker.refresh_now()
            self.assertEqual(out.get(timeout=2)[0], "offline")
            self.assertEqual(out.get(timeout=2)[0], "users")
            worker.stop()
            worker.join(2)

    def test_read_failure_retries(self):
        with patch.object(manager, "RETRY_SECONDS", 0.01), \
                patch.object(manager, "port_open", return_value=True), \
                patch.object(manager.Device, "fetch_users",
                             side_effect=[manager.DeviceError("Bad packet header"), []]):
            worker, out, _cfg = self.start_worker()
            self.assertEqual(out.get(timeout=2)[0:2], ("error", "Bad packet header"))
            self.assertEqual(out.get(timeout=2)[0], "users")
            worker.stop()
            worker.join(2)

    def test_target_change_discards_inflight_previous_device_read(self):
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def fetch(device):
            if device.ip == "192.168.1.201":
                entered.set()
                if not release.wait(2):
                    raise RuntimeError("Test did not release old read")
            return [{"user_id": device.ip}]

        with patch.object(manager, "port_open", return_value=True), \
                patch.object(manager.Device, "fetch_users", fetch):
            worker, out, cfg = self.start_worker()
            self.assertTrue(entered.wait(2))
            cfg["ip"] = "192.168.1.202"
            worker.refresh_now()
            release.set()
            message = out.get(timeout=2)
            worker.stop()
            worker.join(2)
        self.assertEqual(message[1], [{"user_id": "192.168.1.202"}])
        self.assertEqual(message[-1]["ip"], "192.168.1.202")
        self.assertTrue(out.empty())


class StateAndLoggingTests(unittest.TestCase):
    def test_non_device_packet_lengths_fail_cleanly(self):
        for size in (0, 7, 16 * 1024 * 1024 + 1):
            with self.subTest(size=size):
                device = manager.Device("192.168.1.201", 4370)
                device.sock = Mock()
                device.sock.recv.return_value = manager.MAGIC + struct.pack("<I", size)
                with self.assertRaisesRegex(manager.DeviceError, "packet length"):
                    device._recv_packet()

    def test_invalid_settings_do_not_reach_network(self):
        for changes in ({"ip": "not-an-ip"}, {"port": 0}, {"port": 65536},
                        {"commkey": -1}, {"commkey": 2 ** 32}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                manager.validate_config(dict(manager.DEFAULT_CONFIG, **changes))
        self.assertEqual(manager.validate_config(dict(manager.DEFAULT_CONFIG, cache_seconds=1))
                         ["cache_seconds"], 5)

    def test_state_roundtrip_and_malformed_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "state.json")
            with patch.object(manager, "STATE_FILE", path):
                manager.save_state(manager.DEFAULT_CONFIG, {"3", "1"})
                self.assertEqual(manager.load_state(), (manager.DEFAULT_CONFIG, {"1", "3"}))
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump({"config": {"port": 99999}}, handle)
                self.assertEqual(manager.load_state(), (manager.DEFAULT_CONFIG, set()))

    def test_log_records_actions_and_protocol_without_authentication_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "logs", "manager.log")
            handler = manager.setup_logging(path)
            try:
                device = manager.Device("192.168.1.201", 5005, commkey=987654321)
                with patch.object(manager.socket, "create_connection", return_value=Mock()), \
                        patch.object(device, "_drain"), \
                        patch.object(device, "_recv_packet", side_effect=[
                            (manager.CMD_ACK_UNAUTH, 1, 1, b""),
                            (manager.CMD_ACK_OK, 1, 2, b"")]):
                    device.connect()
                with patch.object(manager, "STATE_FILE", os.path.join(directory, "state.json")):
                    manager.save_state(dict(manager.DEFAULT_CONFIG, commkey=987654321), set())
                handler.flush()
                with open(path, encoding="utf-8") as handle:
                    content = handle.read()
                self.assertIn("target=192.168.1.201:5005", content)
                self.assertIn("command=1102", content)
                self.assertIn("State saved", content)
                self.assertNotIn("987654321", content)
                self.assertEqual(handler.backupCount, 3)
                self.assertEqual(handler.maxBytes, 2 * 1024 * 1024)
            finally:
                manager.LOG.removeHandler(handler)
                handler.close()

    def test_failed_settings_save_keeps_current_target(self):
        original = dict(manager.DEFAULT_CONFIG)
        app = SimpleNamespace(cfg=original, inactive=set(), cfg_lock=threading.Lock(),
                              v_ip=Mock(), v_port=Mock(), v_key=Mock(), v_cache=Mock(),
                              worker=Mock())
        for variable, value in ((app.v_ip, "192.168.1.202"), (app.v_port, "5005"),
                                (app.v_key, "0"), (app.v_cache, "150")):
            variable.get.return_value = value
        with patch.object(manager, "save_state", side_effect=OSError("read-only directory")), \
                patch.object(manager.messagebox, "showerror"):
            self.assertFalse(manager.App._apply_config(app))
        self.assertEqual(app.cfg, original)
        app.worker.refresh_now.assert_not_called()

    def test_apply_new_target_clears_old_users_and_requests_fetch(self):
        app = SimpleNamespace(cfg=dict(manager.DEFAULT_CONFIG), inactive=set(),
                              cfg_lock=threading.Lock(), users=[{"uid": 1}], last_sync=123,
                              v_ip=Mock(), v_port=Mock(), v_key=Mock(), v_cache=Mock(),
                              worker=Mock(), refresh_view=Mock())
        for variable, value in ((app.v_ip, "192.168.1.202"), (app.v_port, "5005"),
                                (app.v_key, "12345"), (app.v_cache, "150")):
            variable.get.return_value = value
        with patch.object(manager, "save_state") as save:
            self.assertTrue(manager.App._apply_config(app))
        self.assertEqual((app.cfg["ip"], app.cfg["port"], app.cfg["commkey"]),
                         ("192.168.1.202", 5005, 12345))
        self.assertEqual(app.users, [])
        self.assertIsNone(app.last_sync)
        self.assertEqual(app.conn_state, "waiting")
        save.assert_called_once_with(app.cfg, set())
        app.worker.refresh_now.assert_called_once()

    def test_ui_ignores_queued_results_from_old_target(self):
        old_cfg = dict(manager.DEFAULT_CONFIG)
        current = dict(old_cfg, ip="192.168.1.202")
        out = queue.Queue()
        out.put(("users", [{"uid": 1}], 123, old_cfg))
        app = SimpleNamespace(q=out, _cfg_snapshot=lambda: dict(current),
                              users=[], refresh_view=Mock(), after=Mock(), _poll_queue=Mock())
        manager.App._poll_queue(app)
        self.assertEqual(app.users, [])
        app.refresh_view.assert_not_called()


if __name__ == "__main__":
    manager.LOG.addHandler(logging.NullHandler())
    unittest.main()
