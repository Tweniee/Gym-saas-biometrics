import json
import socket
import socketserver
import struct
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from unittest.mock import Mock

from zenvore_connector.adapters.base import AdapterError
from zenvore_connector.adapters.zk_protocol import Protocol, MAGIC
from zenvore_connector.adapters.zk_tcp import ZKTcp, local_time
from zenvore_connector.config import Config
from zenvore_connector.health import Health
from zenvore_connector.storage import Store
from zenvore_connector.sync import DeviceLocks, Sync


def stamp(year=2026, month=10, day=19, hour=14, minute=0, second=0):
    value = (((((year - 2000) * 12 + month - 1) * 31 + day - 1) * 24 + hour) * 60 + minute) * 60 + second
    return value.to_bytes(4, "little")


def attendance(user="1001", punch=0, record_size=40):
    if record_size == 40:
        return struct.pack("<H24sB4sB8s", 1, user.encode(), 1, stamp(), punch, b"")
    if record_size == 16:
        return struct.pack("<I4sBB2sI", int(user), stamp(), 1, punch, b"", 0)
    return struct.pack("<HB4sB", 1, 1, stamp(), punch)


class DeviceHandler(socketserver.BaseRequestHandler):
    def exact(self, size):
        data = b""
        while len(data) < size:
            part = self.request.recv(size - len(data))
            if not part:
                raise EOFError()
            data += part
        return data

    def handle(self):
        try:
            while True:
                header = self.exact(8)
                size = struct.unpack("<I", header[4:])[0]
                request = self.exact(size)
                command, _, _, reply = struct.unpack("<4H", request[:8])
                self.server.commands.append(command)
                code, data = 2000, b""
                if command == 11:
                    data = b"~SerialNumber=DEVICE-001\0"
                elif command == 50:
                    values = [0] * 9
                    values[4], values[8] = 1, len(self.server.records)
                    data = struct.pack("<9i", *values)
                elif command == 1503:
                    target = struct.unpack("<bhii", request[8:])[1]
                    if target == 9:
                        user = bytearray(72)
                        struct.pack_into("<H", user, 0, 1)
                        user[48:52] = b"1001"
                        body = bytes(user)
                    else:
                        body = b"".join(self.server.records)
                    self.transfer = struct.pack("<I", len(body)) + body
                    if getattr(self.server, "buffered", False):
                        code, data = 1500, b"\x01" + struct.pack("<I", len(self.transfer))
                    else:
                        code, data = 1501, self.transfer
                elif command == 1504:
                    offset, length = struct.unpack("<ii", request[8:])
                    chunk = self.transfer[offset:offset + length]
                    for extra_code, extra_data in ((1500, struct.pack("<I", len(chunk))), (1501, chunk[:5]), (1501, chunk[5:]), (2000, b"")):
                        packet = struct.pack("<4H", extra_code, 0, 10, reply) + extra_data
                        self.request.sendall(MAGIC + struct.pack("<I", len(packet)) + packet)
                    continue
                elif command not in (1000, 1001, 1502):
                    code = 2001
                packet = struct.pack("<4H", code, 0, 10, reply) + data
                # Real TCP fragmentation must not corrupt framing.
                packet = MAGIC + struct.pack("<I", len(packet)) + packet
                self.request.sendall(packet[:5]); self.request.sendall(packet[5:])
                if command == 1001:
                    return
        except (EOFError, OSError):
            return


class DeviceServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ZKTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.store = Store(self.directory)
        self.config = Config("http://127.0.0.1:3000/api/v1", self.directory, True)
        self.server = DeviceServer(("127.0.0.1", 0), DeviceHandler)
        self.server.commands = []
        self.server.records = [attendance()]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.device = {"_id": "a" * 24, "adapter": "zk-tcp", "ip": "127.0.0.1",
                       "port": self.server.server_address[1], "timezone": "Asia/Kolkata",
                       "historySince": "2026-10-01T00:00:00Z", "eventPolicy": "check-in"}

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.store.close(); self.temp.cleanup()

    def test_handshake_reads_identity_users_and_attendance_without_writes(self):
        adapter = ZKTcp(self.device, self.config, self.store)
        self.assertFalse(adapter.capabilities().attendance)
        self.assertEqual(adapter.health(), "ZK:DEVICE-001")
        self.assertTrue(adapter.capabilities().attendance)
        self.assertFalse(adapter.capabilities().access)
        self.assertEqual(adapter.lookup_user("1001"), {"deviceUserId": "1001"})
        page = adapter.fetch(None, self.device["historySince"])
        self.assertEqual(page.records[0]["timestamp"], "2026-10-19T14:00:00+05:30")
        self.assertEqual(page.records[0]["eventType"], "check-in")
        self.assertTrue({11, 50, 1503}.issubset(set(self.server.commands)))
        self.assertTrue(set(self.server.commands).issubset({1000, 1001, 11, 50, 1503, 1502, 1504}))

    def test_prepared_buffer_chunk_transfer_reads_exact_bytes_and_frees_transfer(self):
        self.server.buffered = True
        adapter = ZKTcp(self.device, self.config, self.store)
        self.assertEqual(adapter.health(), "ZK:DEVICE-001")
        self.assertEqual(adapter.fetch(None, self.device["historySince"]).records[0]["deviceUserId"], "1001")
        self.assertIn(1504, self.server.commands)
        self.assertIn(1502, self.server.commands)

    def test_snapshot_reordering_and_restart_do_not_duplicate_acknowledged_scans(self):
        cloud = Mock()
        def ack(method, route, batch):
            return {"committed": True, "position": batch["position"], "generation": batch["generation"],
                    "acceptedEventIds": [e["eventId"] for e in batch["events"]]}
        cloud.request.side_effect = ack
        sync = Sync(self.store, cloud, DeviceLocks(), Health())
        self.server.records = [attendance(), attendance(punch=1)]
        self.assertEqual(sync.run(self.device, ZKTcp(self.device, self.config, self.store)), 2)
        self.server.records.reverse()
        self.store.close()
        self.store = Store(self.directory)
        sync = Sync(self.store, cloud, DeviceLocks(), Health())
        self.assertEqual(sync.run(self.device, ZKTcp(self.device, self.config, self.store)), 0)
        self.assertEqual(len(self.store.seen(self.device["_id"], "zk-v1:DEVICE-001")), 2)

    def test_lost_ack_does_not_mark_records_seen(self):
        cloud = Mock()
        cloud.request.side_effect = OSError()
        with self.assertRaises(OSError):
            Sync(self.store, cloud, DeviceLocks(), Health()).run(self.device, ZKTcp(self.device, self.config, self.store))
        self.assertEqual(self.store.seen(self.device["_id"], "zk-v1:DEVICE-001"), set())
        self.assertIsNotNone(self.store.pending(self.device["_id"]))

    def test_known_layouts_uid_mapping_and_explicit_event_policy(self):
        for size in (8, 16, 40):
            self.server.records = [attendance(record_size=size, punch=1)]
            self.device["eventPolicy"] = "zk-in-out"
            page = ZKTcp(self.device, self.config, self.store).fetch(None, self.device["historySince"])
            self.assertEqual(page.records[0]["deviceUserId"], "1001")
            self.assertEqual(page.records[0]["eventType"], "check-out")
        self.device["eventPolicy"] = "unknown"
        page = ZKTcp(self.device, self.config, self.store).fetch(None, self.device["historySince"])
        self.assertEqual(page.records[0]["eventType"], "unknown")

    def test_unknown_layout_is_not_connection_ready(self):
        self.server.records = [b"bad record"]
        adapter = ZKTcp(self.device, self.config, self.store)
        with self.assertRaises(AdapterError) as error:
            adapter.health()
        self.assertEqual(error.exception.code, "UNSUPPORTED")
        self.assertFalse(adapter.capabilities().attendance)

    def test_dst_fold_and_missing_wall_time_are_rejected(self):
        zone = ZoneInfo("America/New_York")
        for encoded in (stamp(2026, 11, 1, 1, 30), stamp(2026, 3, 8, 2, 30)):
            with self.assertRaises(AdapterError):
                local_time(encoded, zone)

    def test_protocol_has_absolute_deadline_and_rejects_unrelated_tcp_listener(self):
        class Stall(socketserver.BaseRequestHandler):
            def handle(self):
                time.sleep(.2)
        with DeviceServer(("127.0.0.1", 0), Stall) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            started = time.monotonic()
            with self.assertRaises(AdapterError):
                with Protocol("127.0.0.1", server.server_address[1], timeout=.05).connected():
                    pass
            self.assertLess(time.monotonic() - started, .2)
            server.shutdown(); thread.join()

    def test_device_lock_coordinates_separate_runtime_instances(self):
        first, second = DeviceLocks(self.directory).for_device("device"), DeviceLocks(self.directory).for_device("device")
        with first:
            with first:
                self.assertFalse(second.acquire(blocking=False))
        self.assertTrue(second.acquire(blocking=False))
        second.release()

    def test_windows_adapter_type_limits_automatic_ethernet_selection(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from zenvore_connector.discovery import windows_ethernet_names
        result = SimpleNamespace(stdout=json.dumps([{"Name": "Wired LAN", "InterfaceType": 6},
                                                    {"Name": "Wireless LAN", "InterfaceType": 71}]).encode())
        with patch("subprocess.run", return_value=result) as call:
            self.assertEqual(windows_ethernet_names(), {"Wired LAN"})
            self.assertEqual(call.call_args.kwargs["timeout"], 5)

    def test_discovery_never_scans_a_whole_large_ethernet_subnet(self):
        from unittest.mock import patch
        from zenvore_connector.discovery import ethernet_candidates
        with patch("zenvore_connector.discovery.bounded_discover", return_value=[]) as scan:
            ethernet_candidates(self.config, self.store, [{"address": "192.168.5.9", "subnet": "192.168.0.0/16"}])
            self.assertEqual(scan.call_args.args[:2], (["192.168.5.0/24"], [4370]))

    def test_recovery_requires_the_same_serial_at_the_discovered_endpoint(self):
        from unittest.mock import patch
        from zenvore_connector.adapters import Capabilities
        from zenvore_connector.runtime import Runtime
        cloud = Mock()
        runtime = Runtime(self.config, self.store, cloud)
        device = {**self.device, "identity": "ZK:DEVICE-001"}
        old, recovered = Mock(), Mock()
        old.health.side_effect = AdapterError("DEVICE_UNREACHABLE", True)
        recovered.health.return_value = "ZK:DEVICE-001"
        recovered.capabilities.return_value = Capabilities(attendance=True)
        runtime.discover = Mock(return_value=[{"identity": "ZK:OTHER", "ip": "192.168.1.8", "port": 4370},
                                              {"identity": "ZK:DEVICE-001", "ip": "192.168.1.9", "port": 4370}])
        with patch("zenvore_connector.runtime.adapter_for", side_effect=[old, recovered]):
            self.assertIs(runtime.handshake(device), recovered)
        report = cloud.request.call_args.args[2]
        self.assertEqual(report["ip"], "192.168.1.9")
        self.assertEqual(report["identity"], "ZK:DEVICE-001")
        self.assertTrue(report["attendance"])


if __name__ == "__main__":
    unittest.main()
