"""ZK adapter behaviour against a checksum-validating device emulator: races, bad records, snapshots."""
import dataclasses
import hashlib
import json
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from zenvore_connector.adapters.base import AdapterError
from zenvore_connector.adapters.zk_protocol import Protocol
from zenvore_connector.adapters.zk_tcp import ZKTcp
from zenvore_connector.config import Config
from zenvore_connector.runtime import Runtime
from zenvore_connector.storage import Store
from zenvore_connector.sync import DeviceLocks, Sync
from zk_emulator import Device, Server, encode_time, sample

SINCE = "2026-10-01T00:00:00Z"


def stamp(year=2026, month=10, day=19, hour=14, minute=0, second=0):
    value = (((((year - 2000) * 12 + month - 1) * 31 + day - 1) * 24 + hour) * 60 + minute) * 60 + second
    return value.to_bytes(4, "little")


def accepting_cloud():
    cloud = Mock()
    cloud.request.side_effect = lambda method, route, batch: {
        "committed": True, "position": batch["position"], "generation": batch["generation"],
        "acceptedEventIds": [e["eventId"] for e in batch["events"]]}
    return cloud


class AdapterCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.store = Store(self.directory)
        self.addCleanup(self.store.close)
        self.config = Config("http://127.0.0.1:3000/api/v1", self.directory, True)
        self.servers = []

    def start(self, device, udp=False):
        server = Server(device, udp=udp)
        server.__enter__()
        self.addCleanup(server.__exit__)
        self.addCleanup(lambda: self.assertEqual(device.bad_checksums, 0))
        self.servers.append(server)
        return server

    def adapter(self, device, server, zone="Asia/Kolkata", policy="check-in", config=None, protocol=Protocol):
        entry = {"_id": "a" * 24, "adapter": "zk-tcp", "ip": "127.0.0.1", "port": server.port, "timezone": zone,
                 "historySince": SINCE, "eventPolicy": policy}
        return ZKTcp(entry, config or self.config, self.store, protocol), entry

    def rows(self, device, **options):
        server = self.start(device)
        adapter, _ = self.adapter(device, server, **options)
        adapter.health()
        return adapter, adapter.snapshot[2]

    def sync(self, device, server, cloud=None, health=None):
        adapter, entry = self.adapter(device, server)
        sync = Sync(self.store, cloud or accepting_cloud(), DeviceLocks(self.directory), health or Mock())
        return sync.run(entry, adapter), adapter


def punch_once(count, user="1001"):
    state = {"done": False}
    def hook(device):
        if not state["done"]:
            state["done"] = True
            for number in range(count):
                device.records.append((1, user, 1, datetime(2026, 10, 25, 9, number), 0))
    return hook


class CountRaceTests(AdapterCase):
    def test_member_punching_between_size_read_and_dump_is_not_a_layout_error(self):
        users, records = sample(5, 5)
        device = Device(users=users, records=records, after_sizes=punch_once(1))  # reports 5, delivers 6
        adapter, rows = self.rows(device)
        self.assertEqual(len(rows), 6)
        self.assertEqual(adapter.device_total, 6)
        self.assertEqual(device.commands.count(50), 2)  # sizes re-read once

    def test_two_punches_during_the_read(self):
        users, records = sample(5, 4)
        device = Device(users=users, records=records, after_sizes=punch_once(2))  # reports 4, delivers 6
        self.assertEqual(len(self.rows(device)[1]), 6)

    def test_user_enrolled_and_punching_between_size_read_and_dump(self):
        users, records = sample(3, 6)
        def enrol(device):
            if len(device.users) == 3:
                device.users.append((4, "1004"))
                device.records.append((4, "1004", 1, datetime(2026, 10, 25, 9, 0), 0))
        device = Device(users=users, records=records, record_format=8, after_sizes=enrol)
        adapter, rows = self.rows(device)
        self.assertEqual(len(rows), 7)
        self.assertEqual(adapter.snapshot[1][4], "1004")
        self.assertIn("1004", {r["deviceUserId"] for r in rows})

    def test_28_byte_user_layout_survives_the_same_race(self):
        users, records = sample(3, 6)
        def enrol(device):
            if len(device.users) == 3:
                device.users.append((4, "1004"))
        device = Device(users=users, records=records, user_format=28, after_sizes=enrol)
        self.assertEqual(len(self.rows(device)[0].snapshot[1]), 4)

    def test_layout_that_no_count_explains_is_still_unsupported(self):
        users, records = sample(2, 5)
        device = Device(users=users, records=records, reported=(2, 3))  # recount says 3 as well
        server = self.start(device)
        with self.assertRaises(AdapterError) as error:
            self.adapter(device, server)[0].health()
        self.assertEqual(error.exception.code, "UNSUPPORTED")

    def test_cleared_log_confirmed_by_a_recount_yields_no_rows(self):
        device = Device(users=[(1, "1001")], records=[], reported=(1, 3),
                        after_sizes=lambda d: setattr(d, "reported", None))  # the fresh count says 0
        adapter, rows = self.rows(device)
        self.assertEqual((rows, adapter.device_total), ([], 0))
        self.assertEqual(device.commands.count(50), 2)

    def test_empty_dump_with_a_count_that_stays_positive_is_transient_and_leaves_the_stored_count(self):
        device = Device(users=[(1, "1001")], records=[], reported=(1, 3))
        server = self.start(device)
        adapter, entry = self.adapter(device, server)
        self.store.set("zk-count:" + entry["_id"], 5)
        with self.assertRaises(AdapterError) as error:
            adapter.fetch(None, SINCE)
        self.assertEqual((error.exception.code, error.exception.transient), ("INVALID_DEVICE_DATA", True))
        self.assertEqual(self.store.get("zk-count:" + entry["_id"]), 5)
        self.assertEqual(device.commands.count(50), 2)  # recounted exactly once

    def test_shrinking_log_is_still_a_data_gap(self):
        users, records = sample(3, 6)
        device = Device(users=users, records=records)
        server = self.start(device)
        self.assertFalse(self.adapter(device, server)[0].fetch(None, SINCE).data_gap)
        device.records = device.records[:3]
        self.assertTrue(self.adapter(device, server)[0].fetch(None, SINCE).data_gap)


class BadRecordTests(AdapterCase):
    def test_eight_byte_record_of_a_deleted_user_is_skipped_not_guessed(self):
        users, records = sample(2, 4)
        records.append((999, "777", 1, datetime(2026, 10, 2, 7, 0), 0))
        device = Device(users=users, records=records, record_format=8)
        with self.assertLogs("zenvore.connector", "WARNING") as logs:
            adapter, rows = self.rows(device)
        self.assertEqual(len(rows), 4)
        self.assertEqual(adapter.device_total, 5)
        self.assertEqual({r["deviceUserId"] for r in rows}, {"1001", "1002"})
        self.assertEqual(logs.records[0].getMessage(), "ZK read skipped 1 of 5 records (0 undecodable)")

    def test_deleting_a_member_does_not_duplicate_events_or_fake_a_data_gap(self):
        users, records = sample(2, 6)
        device = Device(users=users, records=records, record_format=8)
        server = self.start(device)
        cloud, health = accepting_cloud(), Mock()
        first, _ = self.sync(device, server, cloud, health)
        self.assertEqual(first, 6)
        device.users.pop()  # Member 2's three-record share of the log is now orphaned.
        second, _ = self.sync(device, server, cloud, health)
        self.assertEqual(second, 0)
        self.assertFalse([c for c in health.update.call_args_list if c.kwargs.get("errorCode") == "DATA_GAP"])
        sent = [e["eventId"] for c in cloud.request.call_args_list for e in c.args[2]["events"]]
        self.assertEqual(len(sent), len(set(sent)))

    def test_fingerprints_of_decodable_records_are_unchanged(self):
        users, records = sample(1, 3)
        records.append(records[0])  # Identical scan twice: the ordinal separates them.
        _, rows = self.rows(Device(users=users, records=records))
        expected = [hashlib.sha256(json.dumps(["1001", encode_time(r[3]).hex(), 1, r[4]], separators=(",", ":")).encode()).hexdigest()
                    for r in records]
        self.assertEqual([r["index"] for r in rows], [expected[0] + ":0", expected[1] + ":0", expected[2] + ":0", expected[0] + ":1"])

    def test_impossible_calendar_stamp_is_skipped_and_valid_records_returned(self):
        users, records = sample(1, 2)
        records.insert(1, (1, "1001", 1, stamp(2026, 2, 31), 0))
        adapter, rows = self.rows(Device(users=users, records=records))
        self.assertEqual(len(rows), 2)
        self.assertEqual(adapter.device_total, 3)

    def test_ambiguous_dst_wall_time_is_skipped_and_valid_records_returned(self):
        users, records = sample(1, 1)
        records.append((1, "1001", 1, datetime(2026, 11, 1, 1, 30), 0))
        records.append((1, "1001", 1, datetime(2026, 3, 8, 2, 30), 0))
        adapter, rows = self.rows(Device(users=users, records=records), zone="America/New_York")
        self.assertEqual(len(rows), 1)
        self.assertEqual(adapter.device_total, 3)

    def test_bad_utf8_and_empty_user_ids_are_skipped(self):
        users, records = sample(2, 3)
        records.append((1, b"\xff\xfe\xfd", 1, datetime(2026, 10, 3, 7, 0), 0))
        records.append((1, "", 1, datetime(2026, 10, 3, 7, 1), 0))
        _, rows = self.rows(Device(users=users, records=records))
        self.assertEqual(len(rows), 3)

    def test_unreadable_user_names_do_not_hide_other_users(self):
        users, records = sample(2, 2)
        users.append((3, b"\xff\xfe"))
        users.append((4, ""))
        adapter, rows = self.rows(Device(users=users, records=records))
        self.assertEqual(adapter.snapshot[1], {1: "1001", 2: "1002"})

    def test_mostly_bad_stamps_mean_a_misdetected_layout(self):
        users, records = sample(1, 1)
        records += [(1, "1001", 1, stamp(2026, 2, 31, minute=i), 0) for i in range(20)]
        server = self.start(Device(users=users, records=records))
        with self.assertRaises(AdapterError) as error:
            self.adapter(None, server)[0].health()
        self.assertEqual(error.exception.code, "INVALID_DEVICE_DATA")

    def test_guard_boundary_is_more_than_half_undecodable(self):
        users, records = sample(1, 5)
        records += [(1, "1001", 1, stamp(2026, 2, 31, minute=i), 0) for i in range(5)]
        self.assertEqual(len(self.rows(Device(users=users, records=records))[1]), 5)  # 5 of 10: allowed
        users, records = sample(1, 4)
        records += [(1, "1001", 1, stamp(2026, 2, 31, minute=i), 0) for i in range(6)]
        server = self.start(Device(users=users, records=records))
        with self.assertRaises(AdapterError):
            self.adapter(None, server)[0].health()  # 6 of 10: refused

    def test_many_orphans_are_tolerated_while_one_record_maps(self):
        users, records = sample(1, 1)
        records += [(900 + i, "x", 1, datetime(2026, 10, 3, 7, i), 0) for i in range(30)]
        adapter, rows = self.rows(Device(users=users, records=records, record_format=8))
        self.assertEqual((len(rows), adapter.device_total), (1, 31))

    def test_attendance_that_matches_no_user_at_all_is_a_misread_not_an_empty_sync(self):
        users, _ = sample(1, 1)
        records = [(900 + i, "x", 1, datetime(2026, 10, 3, 7, i), 0) for i in range(10)]
        server = self.start(Device(users=users, records=records, record_format=8))
        with self.assertRaises(AdapterError) as error:
            self.adapter(None, server)[0].health()
        self.assertEqual(error.exception.code, "INVALID_DEVICE_DATA")

    def test_few_all_orphan_records_stay_below_the_guard(self):
        users, _ = sample(1, 1)
        records = [(900 + i, "x", 1, datetime(2026, 10, 3, 7, i), 0) for i in range(9)]
        adapter, rows = self.rows(Device(users=users, records=records, record_format=8))
        self.assertEqual((rows, adapter.device_total), ([], 9))

    def test_eight_byte_attendance_with_users_reported_but_an_empty_dump_is_refused(self):
        _, records = sample(5, 40)
        device = Device(users=[], records=records, record_format=8, reported=(5, 40))
        server = self.start(device)
        with self.assertRaises(AdapterError) as error:
            self.adapter(device, server)[0].health()
        self.assertEqual(error.exception.code, "INVALID_DEVICE_DATA")

    def test_forty_byte_attendance_does_not_need_the_user_table(self):
        _, records = sample(5, 40)
        device = Device(users=[], records=records, record_format=40, reported=(5, 40))
        adapter, rows = self.rows(device)
        self.assertEqual((adapter.snapshot[1], len(rows)), ({}, 40))

    def test_sixteen_byte_attendance_does_not_need_the_user_table(self):
        _, records = sample(5, 40)
        device = Device(users=[], records=records, record_format=16, reported=(5, 40))
        adapter, rows = self.rows(device)
        self.assertEqual((adapter.snapshot[1], len(rows)), ({}, 40))

    def test_every_user_id_unreadable_is_refused_for_eight_byte_attendance(self):
        users, records = sample(2, 12)
        users = [(1, ""), (2, b"\xff\xfe")]
        server = self.start(Device(users=users, records=records, record_format=8))
        with self.assertRaises(AdapterError) as error:
            self.adapter(None, server)[0].health()
        self.assertEqual(error.exception.code, "INVALID_DEVICE_DATA")

    def test_every_user_id_unreadable_still_reads_forty_byte_attendance(self):
        users, records = sample(2, 12)
        users = [(1, ""), (2, b"\xff\xfe")]
        adapter, rows = self.rows(Device(users=users, records=records, record_format=40))
        self.assertEqual((adapter.snapshot[1], len(rows)), ({}, 12))


class SnapshotTests(AdapterCase):
    def test_pages_of_one_sync_reuse_a_single_device_dump(self):
        users, records = sample(5, 450)
        device = Device(users=users, records=records)
        server = self.start(device)
        count, adapter = self.sync(device, server)
        self.assertEqual(count, 450)
        self.assertEqual(device.commands.count(1503), 2)  # users + attendance, once
        self.assertIsNone(adapter.snapshot)  # The last page releases it.
        self.assertEqual(self.sync(device, server)[0], 0)
        self.assertEqual(device.commands.count(1503), 4)  # the next sync reads afresh

    def test_snapshot_older_than_the_ttl_is_read_again(self):
        users, records = sample(3, 10)
        device = Device(users=users, records=records)
        server = self.start(device)
        adapter, _ = self.adapter(device, server)
        adapter.health()
        adapter.snapshot_at -= 121
        adapter.fetch(None, SINCE)
        self.assertEqual(device.commands.count(1503), 4)

    def test_young_snapshot_from_health_serves_the_first_fetch(self):
        users, records = sample(3, 10)
        device = Device(users=users, records=records)
        server = self.start(device)
        adapter, _ = self.adapter(device, server)
        adapter.health()
        adapter.fetch(None, SINCE)
        self.assertEqual(device.commands.count(1503), 2)


class TransportWiringTests(AdapterCase):
    def test_session_timeout_comes_from_config_and_udp_fallback_is_enabled(self):
        seen = {}
        class Spy(Protocol):
            def __init__(self, *args, **options):
                seen.update(options)
                super().__init__(*args, **options)
        users, records = sample(2, 3)
        device = Device(users=users, records=records)
        server = self.start(device)
        # The cloud HTTP timeout is a different setting and must not leak into the device session.
        config = dataclasses.replace(self.config, timeout_seconds=3, device_timeout_seconds=7)
        adapter, _ = self.adapter(device, server, config=config, protocol=Spy)
        adapter.health()
        self.assertEqual(seen, {"timeout": 7, "transport": "auto"})

    def test_device_timeout_defaults_to_fifteen_seconds_whatever_the_cloud_timeout_is(self):
        seen = {}
        class Spy(Protocol):
            def __init__(self, *args, **options):
                seen.update(options)
                super().__init__(*args, **options)
        users, records = sample(2, 3)
        device = Device(users=users, records=records)
        server = self.start(device)
        config = dataclasses.replace(self.config, timeout_seconds=2)
        self.adapter(device, server, config=config, protocol=Spy)[0].health()
        self.assertEqual(seen["timeout"], 15)

    def test_cancellation_is_handed_to_the_transport_only_when_there_is_one(self):
        seen = {}
        class Spy(Protocol):
            def __init__(self, *args, **options):
                seen.update(options)
                super().__init__(*args, **options)
        users, records = sample(2, 3)
        device = Device(users=users, records=records)
        server = self.start(device)
        flag = lambda: False
        entry = {"_id": "a" * 24, "adapter": "zk-tcp", "ip": "127.0.0.1", "port": server.port,
                 "timezone": "Asia/Kolkata", "historySince": SINCE, "eventPolicy": "check-in"}
        ZKTcp(entry, self.config, self.store, Spy, cancelled=flag).health()
        self.assertIs(seen["cancelled"], flag)

    def test_adapter_for_passes_the_cancel_check_to_the_zk_adapter(self):
        from zenvore_connector.adapters import adapter_for
        flag = lambda: False
        entry = {"_id": "a" * 24, "adapter": "zk-tcp", "ip": "127.0.0.1", "port": 4370}
        self.assertIs(adapter_for(entry, self.config, self.store, flag).cancelled, flag)
        self.assertIsNone(adapter_for(entry, self.config, self.store).cancelled)

    def test_udp_only_device_is_read_through_the_adapter(self):
        users, records = sample(10, 200)
        device = Device(users=users, records=records)
        server = self.start(device, udp=True)
        adapter, _ = self.adapter(device, server)
        self.assertEqual(adapter.health(), "ZK:CDQ9201760123")
        self.assertEqual(len(adapter.snapshot[2]), 200)

    def test_60001_eight_byte_records_are_read_end_to_end(self):
        start = datetime(2026, 10, 1, 0, 0, 0)
        records = [(1, "1001", 1, start + timedelta(seconds=i), 0) for i in range(60_001)]
        device = Device(users=[(1, "1001")], records=records, record_format=8)
        adapter, rows = self.rows(device)
        self.assertEqual((len(rows), adapter.device_total), (60_001, 60_001))


class BusyDeviceTests(AdapterCase):
    def test_background_sync_holding_the_device_is_reported_as_busy_not_as_a_network_fault(self):
        from unittest.mock import patch
        from zenvore_connector.runtime import error_code
        from zenvore_connector.sync import ProcessDeviceLock
        device = Device(users=[(1, "1001")], records=[])
        server = self.start(device)
        adapter, _ = self.adapter(device, server)
        held = ProcessDeviceLock(self.directory, "endpoint:127.0.0.1:" + str(server.port))
        with held, patch.object(ProcessDeviceLock, "WAIT", .2):
            with self.assertRaises(AdapterError) as error:
                adapter.health()
        self.assertEqual((error.exception.code, error.exception.transient, error.exception.reason),
                         ("DEVICE_UNREACHABLE", True, "DEVICE_BUSY"))
        self.assertEqual(error_code(error.exception), "DEVICE_UNREACHABLE")
        self.assertEqual(device.commands, [])  # The device itself was never contacted

    def test_a_busy_registered_device_is_skipped_without_rediscovery_report_or_error_code(self):
        from zenvore_connector.sync import ProcessDeviceLock
        device = Device(users=[(1, "1001")], records=[])
        server = self.start(device)
        entry = {"_id": "a" * 24, "adapter": "zk-tcp", "ip": "127.0.0.1", "port": server.port, "identity": "ZK:CDQ9201760123",
                 "timezone": "Asia/Kolkata", "historySince": SINCE, "eventPolicy": "check-in"}
        runtime = Runtime(self.config, self.store, Mock())
        runtime.discover = Mock(return_value=[])
        runtime.cloud.request.side_effect = lambda method, route, *rest, **options: [entry] if method == "GET" else {}
        runtime.network_signature = ()  # No network change: only a rediscovery could call discover().
        held = ProcessDeviceLock(self.directory, "endpoint:127.0.0.1:" + str(server.port))
        with held, patch.object(ProcessDeviceLock, "WAIT", .2), patch("zenvore_connector.runtime.interfaces", return_value=[]):
            runtime.scheduled_once()
        runtime.discover.assert_not_called()
        self.assertEqual([call.args[:2] for call in runtime.cloud.request.call_args_list], [("GET", "/connectors/me/devices")])
        self.assertNotIn("errorCode", runtime.health.snapshot())
        self.assertNotIn("DEVICE_UNREACHABLE", json.dumps(self.store.get("health", {})))
        self.assertEqual(device.commands, [])


class ShutdownTests(AdapterCase):
    def slow_device(self):
        users, records = sample(10, 3000)  # 120 KB at 32 KB/s: about four seconds of transfer
        return Device(users=users, records=records, throughput=16384 / .5)

    def entry(self, server, **extra):
        return {"_id": "a" * 24, "adapter": "zk-tcp", "ip": "127.0.0.1", "port": server.port,
                "timezone": "Asia/Kolkata", "historySince": SINCE, "eventPolicy": "check-in", **extra}

    def runtime(self):
        config = dataclasses.replace(self.config, device_timeout_seconds=30)
        runtime = Runtime(config, self.store, Mock())
        runtime.discover = Mock(return_value=[])
        return runtime

    def start_worker(self, runtime, work):
        outcome = []
        def worker():
            try:
                work()
            except Exception as exc:
                outcome.append(exc)
        thread = threading.Thread(target=worker)
        runtime.threads.append(thread)
        thread.start()
        return outcome

    def wait_for_transfer(self, device):
        deadline = time.monotonic() + 5
        while device.commands.count(1504) < 1 and time.monotonic() < deadline:
            time.sleep(.02)  # The transfer is under way.

    def test_runtime_shutdown_cancels_a_session_that_is_mid_transfer(self):
        device = self.slow_device()
        server = self.start(device)
        entry = self.entry(server)
        runtime = self.runtime()
        outcome = self.start_worker(runtime, lambda: runtime.handshake(entry))
        self.wait_for_transfer(device)
        started = time.monotonic()
        runtime.shutdown()  # Raises RuntimeError if the worker outlives its bound.
        self.assertLess(time.monotonic() - started, 3.5)
        self.assertFalse(runtime.threads[0].is_alive())
        self.assertEqual((outcome[0].code, outcome[0].transient, outcome[0].reason), ("DEVICE_UNREACHABLE", True, "CANCELLED"))

    def test_shutdown_of_a_known_device_mid_transfer_is_not_an_outage(self):
        # The common case: the device has a stored identity, so a real outage would trigger rediscovery.
        device = self.slow_device()
        server = self.start(device)
        entry = self.entry(server, identity="ZK:CDQ9201760123")
        runtime = self.runtime()
        cloud = runtime.cloud
        cloud.request.side_effect = lambda method, route, *rest, **options: [entry] if method == "GET" else {}
        runtime.network_signature = ()  # No network change: only a rediscovery could call discover().
        with patch("zenvore_connector.runtime.interfaces", return_value=[]):
            outcome = self.start_worker(runtime, runtime.scheduled_once)
            self.wait_for_transfer(device)
            started = time.monotonic()
            runtime.stop.set()
            runtime.threads[0].join(5)
        self.assertFalse(runtime.threads[0].is_alive())
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertEqual(outcome, [])  # scheduled_once swallows and classifies its own errors
        runtime.discover.assert_not_called()
        self.assertEqual([call.args[:2] for call in cloud.request.call_args_list], [("GET", "/connectors/me/devices")])
        snapshot = runtime.health.snapshot()
        self.assertNotIn("errorCode", snapshot)
        self.assertNotIn("DEVICE_UNREACHABLE", json.dumps(snapshot))
        self.assertNotIn("DEVICE_UNREACHABLE", json.dumps(self.store.get("health", {})))

    def test_a_real_outage_of_a_known_device_still_rediscovers_and_reports(self):
        runtime = self.runtime()
        entry = {"_id": "a" * 24, "adapter": "zk-tcp", "ip": "127.0.0.1", "port": 1, "identity": "ZK:CDQ9201760123",
                 "timezone": "Asia/Kolkata", "historySince": SINCE, "eventPolicy": "check-in"}
        runtime.cloud.request.side_effect = lambda method, route, *rest, **options: [entry] if method == "GET" else {}
        runtime.network_signature = ()
        with patch("zenvore_connector.runtime.interfaces", return_value=[]):
            runtime.scheduled_once()
        runtime.discover.assert_called_once()
        reports = [call.args for call in runtime.cloud.request.call_args_list if call.args[0] == "PUT"]
        self.assertEqual([report[2]["errorCode"] for report in reports], ["DEVICE_UNREACHABLE"])
        self.assertEqual(runtime.health.snapshot()["errorCode"], "DEVICE_UNREACHABLE")

    def test_nothing_is_discovered_once_shutdown_has_begun(self):
        runtime = self.runtime()
        runtime.cloud.request.side_effect = lambda method, route, *rest, **options: []
        runtime.stop.set()
        with patch("zenvore_connector.runtime.interfaces", return_value=[]):
            runtime.scheduled_once()
        runtime.discover.assert_not_called()

    def test_a_command_cut_off_by_shutdown_is_left_for_the_lease_to_expire(self):
        runtime = self.runtime()
        runtime.cloud.request.side_effect = None
        runtime.execute = Mock(side_effect=AdapterError("DEVICE_UNREACHABLE", True, reason="CANCELLED"))
        command = {"_id": "c" * 24, "leaseToken": "t" * 32, "attempts": 1, "type": "SYNC_ATTENDANCE", "deviceId": "a" * 24}
        runtime.handle_command(command)
        routes = [call.args[1] for call in runtime.cloud.request.call_args_list]
        self.assertEqual(routes, ["/connectors/me/commands/" + "c" * 24 + "/ack"])  # No result is posted
        self.assertIsNone(self.store.completion("c" * 24))  # No receipt either: a later attempt runs the command
        self.assertNotIn("errorCode", runtime.health.snapshot())

    def test_a_command_failing_while_stopping_is_not_finalised_as_failed_either(self):
        runtime = self.runtime()
        runtime.cloud.request.side_effect = None
        runtime.stop.set()
        runtime.execute = Mock(side_effect=AdapterError("DEVICE_UNREACHABLE", True))
        runtime.handle_command({"_id": "c" * 24, "leaseToken": "t" * 32, "attempts": 1, "type": "SYNC_ATTENDANCE"})
        self.assertEqual([call.args[1].rsplit("/", 1)[1] for call in runtime.cloud.request.call_args_list], ["ack"])

    def test_an_ordinary_device_failure_still_posts_a_failed_result(self):
        runtime = self.runtime()
        runtime.cloud.request.side_effect = None
        runtime.execute = Mock(side_effect=AdapterError("DEVICE_UNREACHABLE", True))
        runtime.handle_command({"_id": "c" * 24, "leaseToken": "t" * 32, "attempts": 1, "type": "SYNC_ATTENDANCE"})
        posted = runtime.cloud.request.call_args_list[-1].args
        self.assertEqual((posted[1].rsplit("/", 1)[1], posted[2]["status"], posted[2]["errorCode"]), ("result", "failed", "DEVICE_UNREACHABLE"))

    def test_a_busy_device_command_posts_a_transient_failure_and_logs_why(self):
        from zenvore_connector.sync import ProcessDeviceLock
        runtime = self.runtime()
        entry = {"_id": "a" * 24, "adapter": "zk-tcp", "ip": "127.0.0.1", "port": 1, "identity": "ZK:CDQ9201760123",
                 "timezone": "Asia/Kolkata", "historySince": SINCE, "eventPolicy": "check-in"}
        runtime.cloud.request.side_effect = lambda method, route, *rest, **options: [entry] if method == "GET" else {}
        # execute() is real: another holder owns the device lock, so it fails on the lock before any handshake.
        held = ProcessDeviceLock(self.directory, "a" * 24)
        with held, patch.object(ProcessDeviceLock, "WAIT", .2), self.assertLogs("zenvore.connector", level="INFO") as logs:
            runtime.handle_command({"_id": "c" * 24, "leaseToken": "t" * 32, "attempts": 1, "type": "SYNC_ATTENDANCE",
                                    "deviceId": "a" * 24})
        posted = runtime.cloud.request.call_args_list[-1].args
        self.assertEqual((posted[1].rsplit("/", 1)[1], posted[2]["status"], posted[2]["errorCode"], posted[2]["transient"]),
                         ("result", "failed", "DEVICE_UNREACHABLE", True))
        self.assertFalse([call for call in runtime.cloud.request.call_args_list if call.args[1].endswith("/report")])
        self.assertNotIn("errorCode", runtime.health.snapshot())
        self.assertEqual(logs.output, ["INFO:zenvore.connector:device_busy"])


class SkippedRecordTests(AdapterCase):
    def device_with_skips(self):
        users, records = sample(2, 4)
        records.append((999, "777", 1, datetime(2026, 10, 2, 7, 0), 0))  # A deleted member
        records.append((999, "778", 1, datetime(2026, 10, 2, 7, 1), 0))
        return Device(users=users, records=records, record_format=8)

    def test_the_skip_counts_of_the_last_read_are_stored_locally(self):
        adapter, _ = self.rows(self.device_with_skips())
        stored = self.store.get("zk-skipped:" + "a" * 24)
        self.assertEqual((stored["orphans"], stored["undecodable"]), (2, 0))
        self.assertTrue(stored["at"].endswith("Z"))
        datetime.fromisoformat(stored["at"].replace("Z", "+00:00"))

    def test_undecodable_records_are_counted_separately(self):
        users, records = sample(1, 2)
        records.insert(1, (1, "1001", 1, stamp(2026, 2, 31), 0))
        self.rows(Device(users=users, records=records))
        stored = self.store.get("zk-skipped:" + "a" * 24)
        self.assertEqual((stored["orphans"], stored["undecodable"]), (0, 1))

    def test_a_clean_read_resets_the_counts(self):
        self.rows(self.device_with_skips())
        users, records = sample(2, 4)
        self.rows(Device(users=users, records=records))
        stored = self.store.get("zk-skipped:" + "a" * 24)
        self.assertEqual((stored["orphans"], stored["undecodable"]), (0, 0))

    def test_the_setup_status_line_mentions_skipped_records_only_when_there_are_some(self):
        from zenvore_connector.setup_ui import skipped_note
        devices = [{"_id": "a" * 24}]
        self.assertEqual(skipped_note(self.store, devices), "")
        self.rows(self.device_with_skips())
        self.assertEqual(skipped_note(self.store, devices), " · 2 records skipped (deleted members/invalid times; see log)")
        self.assertEqual(skipped_note(self.store, [{"_id": "b" * 24}]), "")  # Other devices' reads do not count
        self.store.set("zk-skipped:" + "a" * 24, {"orphans": 1, "undecodable": 0, "at": "x"})
        self.assertIn(" · 1 record skipped", skipped_note(self.store, devices))
        self.store.set("zk-skipped:" + "a" * 24, {"orphans": "bad"})
        self.assertEqual(skipped_note(self.store, devices), "")  # A damaged entry never breaks the status line

    def test_local_diagnostics_show_the_totals(self):
        from zenvore_connector.main import diagnostics
        self.rows(self.device_with_skips())
        runtime = Runtime(self.config, self.store, Mock())
        self.assertEqual(diagnostics(runtime)["skippedRecords"], {"orphans": 2, "undecodable": 0})

    def test_nothing_about_skipped_records_reaches_a_cloud_payload(self):
        device = self.device_with_skips()
        server = self.start(device)
        entry = {"_id": "a" * 24, "adapter": "zk-tcp", "ip": "127.0.0.1", "port": server.port, "timezone": "Asia/Kolkata",
                 "historySince": SINCE, "eventPolicy": "check-in"}
        cloud = Mock()
        runtime = Runtime(self.config, self.store, cloud)
        runtime.handshake(entry)
        runtime.heartbeat_once()
        sent = {call.args[1]: call.args[2] for call in cloud.request.call_args_list}
        report = sent["/connectors/me/devices/" + "a" * 24 + "/report"]
        self.assertEqual(set(report), {"reachable", "identity", "attendance", "access", "expiry"})
        heartbeat = sent["/connectors/me/heartbeat"]
        self.assertEqual(set(heartbeat), {"appVersion", "pendingCount", "operation", "lastDeviceCommunication"})
        self.assertFalse([key for payload in (report, heartbeat) for key in payload if "skip" in key.lower() or "orphan" in key.lower()])
        self.assertNotIn("zk-skipped", json.dumps([report, heartbeat]))


if __name__ == "__main__":
    unittest.main()
