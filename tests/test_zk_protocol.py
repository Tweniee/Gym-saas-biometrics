"""Wire-level tests of the ZK client against a checksum-validating device emulator."""
import socket
import socketserver
import struct
import threading
import time
import types
import unittest
from unittest.mock import patch

from zenvore_connector.adapters import zk_protocol
from zenvore_connector.adapters.base import AdapterError
from zenvore_connector.adapters.zk_protocol import (
    MAGIC, MAX_BYTES, MAX_RECORDS, MAX_USERS, RECV_LIMIT, UDP_ATTEMPTS, ChunkLost, Protocol, checksum, layout)
from zk_emulator import Device, Server, sample


def run_in_thread(target):
    outcome = []
    def body():
        try:
            outcome.append(target())
        except Exception as exc:
            outcome.append(exc)
    thread = threading.Thread(target=body, daemon=True)
    thread.start()
    return thread, outcome


class StubSocket:
    """Records what is sent and answers with canned bytes, so exact packets can be asserted."""

    def __init__(self, replies=b""):
        self.sent, self.replies, self.recv_sizes = [], bytearray(replies), []

    def settimeout(self, value):
        pass

    def sendall(self, data):
        self.sent.append(bytes(data))

    send = sendall

    def recv(self, count):
        self.recv_sizes.append(count)
        chunk, self.replies = bytes(self.replies[:count]), self.replies[count:]
        return chunk

    def close(self):
        pass


def reply_frame(code, session, reply, data=b"", top=True):
    body = struct.pack("<4H", code, 0, session, reply) + data
    return (MAGIC + struct.pack("<I", len(body)) if top else b"") + body


def stubbed(replies=b"", session=0, reply=65534):
    protocol = Protocol("127.0.0.1")
    protocol.sock, protocol.session, protocol.reply = StubSocket(replies), session, reply
    protocol.started = time.monotonic()
    protocol.deadline = protocol.started + 5
    return protocol


class ChecksumTests(unittest.TestCase):
    def test_checksum_matches_real_captured_device_packet(self):
        # Captured from a real device: cmd 11, chk 0xef58, session 0xc0c5, reply 5, data "~OS\0".
        packet = bytes.fromhex("0b0058efc5c005007e4f5300")
        self.assertEqual(checksum(packet[:2] + b"\0\0" + packet[4:]), 0xef58)

    def test_command_checksums_the_packet_as_sent_with_the_incremented_reply_id(self):
        protocol = stubbed(reply_frame(2000, 0xc0c5, 5), session=0xc0c5, reply=4)
        protocol.command(11, bytes.fromhex("7e4f5300"))
        sent = protocol.sock.sent[0]
        self.assertEqual(sent[:4], MAGIC)
        self.assertEqual(sent[8:16], struct.pack("<4H", 11, 0xef58, 0xc0c5, 5))
        self.assertEqual(sent[16:], bytes.fromhex("7e4f5300"))

    def test_first_connect_packet_is_byte_exact(self):
        protocol = stubbed(reply_frame(2000, 1234, 0))
        protocol.command(1000)
        self.assertEqual(protocol.sock.sent[0][8:], bytes.fromhex("e80317fc00000000"))

    def test_reply_id_wraps_to_zero_after_65534(self):
        for before, after in ((65534, 0), (65533, 65534), (0, 1)):
            protocol = stubbed(reply_frame(2000, 7, after), session=7, reply=before)
            protocol.command(1000)
            self.assertEqual(struct.unpack("<4H", protocol.sock.sent[0][8:16])[3], after)

    def test_two_sessions_against_a_validating_device_have_no_checksum_errors(self):
        users, records = sample(5, 20)
        device = Device(users=users, records=records)
        with Server(device) as server:
            for _ in range(2):
                with Protocol("127.0.0.1", server.port, 0, timeout=2).connected() as session:
                    session.serial()
                    session.counts()
        self.assertEqual(device.bad_checksums, 0)
        self.assertGreater(len(device.commands), 6)


class SerialTests(unittest.TestCase):
    def serial(self, body):
        with Server(Device(serial_reply=body)) as server:
            with Protocol("127.0.0.1", server.port, 0, timeout=2).connected() as session:
                return session.serial()

    def test_serial_ignores_everything_after_the_first_nul(self):
        self.assertEqual(self.serial(b"~SerialNumber=CDQ9201760123\0\xff\xfejunk\0"), "ZK:CDQ9201760123")
        self.assertEqual(self.serial(b"~SerialNumber=AB-1.x\0\0\0\0"), "ZK:AB-1.x")

    def test_serial_rejects_wrong_prefix_charset_length_and_non_ascii(self):
        with self.assertRaises(AdapterError) as error:
            self.serial(b"~Other=ABC\0")
        self.assertEqual(error.exception.code, "UNSUPPORTED")
        for body in (b"~SerialNumber=\0", b"~SerialNumber=AB CD\0", b"~SerialNumber=" + b"A" * 65 + b"\0",
                     b"~SerialNumber=AB\xc3\xa9\0"):
            with self.assertRaises(AdapterError) as error:
                self.serial(body)
            self.assertEqual(error.exception.code, "INVALID_DEVICE_DATA", body)


class BoundsTests(unittest.TestCase):
    def counts(self, users, records):
        with Server(Device(reported=(users, records))) as server:
            with Protocol("127.0.0.1", server.port, 0, timeout=2).connected() as session:
                return session.counts()

    def test_constants(self):
        self.assertEqual((MAX_USERS, MAX_RECORDS, MAX_BYTES), (100_000, 500_000, 32 * 1024 * 1024))

    def test_counts_accepts_large_real_world_logs(self):
        self.assertEqual(self.counts(300, 150_000), (300, 150_000))
        self.assertEqual(self.counts(100_000, 500_000), (100_000, 500_000))

    def test_counts_rejects_implausible_sizes(self):
        for users, records in ((10, 600_000), (100_001, 10), (-1, 10), (10, -1)):
            with self.assertRaises(AdapterError) as error:
                self.counts(users, records)
            self.assertEqual(error.exception.code, "INVALID_DEVICE_DATA")

    def test_recv_never_requests_more_than_one_mebibyte(self):
        protocol = stubbed(b"x" * (3 * RECV_LIMIT + 5))
        self.assertEqual(len(protocol.exact(3 * RECV_LIMIT + 5)), 3 * RECV_LIMIT + 5)
        self.assertTrue(all(size <= RECV_LIMIT for size in protocol.sock.recv_sizes))

    def test_layout_picks_the_single_matching_size(self):
        self.assertEqual(layout(400, 10, 10, (8, 16, 40)), 40)
        self.assertEqual(layout(400, 9, 11, (8, 16, 40)), 40)
        self.assertIsNone(layout(401, 10, 10, (8, 16, 40)))
        self.assertIsNone(layout(400, 11, 12, (40,)))
        self.assertIsNone(layout(80, 1, 10, (8, 16, 40)))  # 10x8, 5x16 and 2x40 all fit: ambiguous


class SessionBudgetTests(unittest.TestCase):
    def test_slow_trickling_multi_chunk_read_outlives_the_connect_timeout(self):
        users, records = sample(10, 1800)  # 72 KB: two chunks, five 16 KiB steps
        device = Device(users=users, records=records, throughput=16384 / .3)
        with Server(device) as server:
            started = time.monotonic()
            with Protocol("127.0.0.1", server.port, 0, timeout=.6).connected() as session:
                session.serial()
                self.assertEqual(session.counts(), (10, 1800))
                size, body = session.records(1800)
            elapsed = time.monotonic() - started
        self.assertEqual((size, len(body)), (40, 1800 * 40))
        self.assertGreater(elapsed, .65)  # Longer than the whole connect budget: the old fixed deadline would fail.
        self.assertEqual(device.bad_checksums, 0)

    def test_connection_reset_is_a_transient_unreachable_device(self):
        users, records = sample(10, 1800)
        device = Device(users=users, records=records, reset_after_bytes=0)
        with Server(device) as server:
            started = time.monotonic()
            with self.assertRaises(AdapterError) as error:
                with Protocol("127.0.0.1", server.port, 0, timeout=.3).connected() as session:
                    session.serial()
            self.assertTrue(error.exception.transient)
            self.assertLess(time.monotonic() - started, 5)

    def test_connected_budget_is_the_timeout_for_connect_and_auth(self):
        class Stall(socketserver.BaseRequestHandler):
            def handle(self):
                time.sleep(3)
        class Quiet(socketserver.ThreadingTCPServer):
            allow_reuse_address = daemon_threads = True
        with Quiet(("127.0.0.1", 0), Stall) as server:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            started = time.monotonic()
            with self.assertRaises(AdapterError):
                with Protocol("127.0.0.1", server.server_address[1], timeout=.05).connected():
                    pass
            self.assertLess(time.monotonic() - started, 2)  # Far below the 3 s the listener stalls
            server.shutdown()


class SpyProtocol(Protocol):
    """Remembers every command code sent and the (session, reply) it was sent with."""
    def __init__(self, *args, **options):
        super().__init__(*args, **options)
        self.sent = []

    def command(self, code, data=b""):
        self.sent.append((code, self.session, self.reply))
        return super().command(code, data)

    def codes(self):
        return [entry[0] for entry in self.sent]


class DatagramStub:
    """UDP socket double: replays queued datagrams, then behaves like a silent device."""
    def __init__(self, datagrams=()):
        self.queue, self.sent = list(datagrams), []

    def settimeout(self, value):
        pass

    def send(self, data):
        self.sent.append(bytes(data))

    def recv(self, count):
        if not self.queue:
            raise socket.timeout()
        return self.queue.pop(0)

    def close(self):
        pass


def udp_stubbed(datagrams=(), session=7, reply=4):
    protocol = stubbed(session=session, reply=reply)
    protocol.sock, protocol.udp = DatagramStub(datagrams), True
    protocol.timeout = .05
    protocol.deadline = time.monotonic() + 5
    return protocol


class ReplyIdTests(unittest.TestCase):
    def test_follow_on_frames_do_not_change_the_reply_id(self):
        protocol = stubbed(reply_frame(2000, 7, 5) + reply_frame(1501, 7, 99), session=7, reply=4)
        protocol.command(11)
        self.assertEqual(protocol.reply, 5)
        protocol.packet(strict=False)
        self.assertEqual(protocol.reply, 5)  # pyzk only takes the id from the first reply

    def test_a_reused_protocol_starts_every_session_from_scratch(self):
        users, records = sample(2, 4)
        with Server(Device(users=users, records=records)) as server:
            protocol = SpyProtocol("127.0.0.1", server.port, 0, timeout=2)
            for _ in range(2):
                with protocol.connected() as session:
                    session.serial()
            firsts = [entry for entry in protocol.sent if entry[0] == 1000]
            self.assertEqual(firsts, [(1000, 0, 65534)] * 2)


class UdpDatagramTests(unittest.TestCase):
    def test_stale_datagrams_of_another_request_are_ignored(self):
        protocol = udp_stubbed([reply_frame(1501, 7, 4, b"stale", top=False), reply_frame(2000, 7, 5, b"ok", top=False)])
        protocol.expect_reply = 5
        self.assertEqual(protocol.packet(), (2000, 7, b"ok"))
        protocol = udp_stubbed([reply_frame(1501, 7, 4, b"first", top=False)])
        self.assertEqual(protocol.packet()[2], b"first")  # Without a filter every datagram counts.

    def test_only_a_retried_read_buffer_command_sets_the_filter_to_its_own_reply_id(self):
        protocol = udp_stubbed([reply_frame(1500, 7, 5, struct.pack("<I", 4), top=False)])
        protocol.command(1504, struct.pack("<ii", 0, 4))
        self.assertIsNone(protocol.expect_reply)  # The first attempt accepts any datagram, like pyzk
        protocol = udp_stubbed([reply_frame(1500, 7, 5, struct.pack("<I", 4), top=False)])
        protocol.filter_stale = True
        protocol.command(1504, struct.pack("<ii", 0, 4))
        self.assertEqual(protocol.expect_reply, 5)
        protocol.filter_stale = False  # chunk() clears the retry state after every attempt
        protocol.sock.queue.append(reply_frame(2000, 7, 6, top=False))
        protocol.command(1502)
        self.assertIsNone(protocol.expect_reply)

    def test_after_a_lost_chunk_every_command_reply_must_carry_the_request_id(self):
        protocol = udp_stubbed([reply_frame(2000, 7, 4, b"stale", top=False), reply_frame(2000, 7, 5, b"ok", top=False)])
        protocol.recovered = True
        self.assertEqual(protocol.command(50), (2000, b"ok"))  # The queued reply to an older request is skipped
        self.assertEqual(protocol.expect_reply, 5)
        # Without a recovery the first datagram counts, so firmware that never echoes the id still works.
        protocol = udp_stubbed([reply_frame(2000, 7, 0, b"first", top=False)])
        self.assertEqual(protocol.command(50), (2000, b"first"))
        self.assertIsNone(protocol.expect_reply)

    def test_a_lost_chunk_switches_on_the_reply_id_filter_for_the_rest_of_the_session(self):
        protocol = udp_stubbed()
        with self.assertRaises(AdapterError):
            protocol.chunk(0, 100)
        self.assertTrue(protocol.recovered)
        protocol.sock.queue = [reply_frame(2000, 7, 1, b"stale", top=False)]
        with self.assertRaises(socket.timeout):
            protocol.command(1502)  # The only datagram answers another request

    def test_first_attempt_of_a_chunk_is_unfiltered_and_retries_are_filtered(self):
        seen = []
        protocol = udp_stubbed()
        original = protocol.chunk_once
        def spy(offset, size):
            seen.append(protocol.filter_stale)
            return original(offset, size)
        protocol.chunk_once = spy
        with self.assertRaises(AdapterError):
            protocol.chunk(0, 100)
        self.assertEqual(seen, [False, True, True])
        self.assertFalse(protocol.filter_stale)

    def test_a_chunk_is_requested_three_times_then_the_device_is_unreachable(self):
        protocol = udp_stubbed()
        with self.assertRaises(AdapterError) as error:
            protocol.chunk(0, 100)
        self.assertEqual((error.exception.code, error.exception.transient), ("DEVICE_UNREACHABLE", True))
        self.assertEqual(len(protocol.sock.sent), 3)
        replies = [struct.unpack("<4H", sent[:8])[3] for sent in protocol.sock.sent]
        self.assertEqual(replies, [5, 6, 7])  # Each attempt is a fresh request id

    def test_tcp_chunks_are_never_retried(self):
        protocol = stubbed()
        protocol.sock.recv = lambda count: (_ for _ in ()).throw(socket.timeout())
        protocol.timeout = .05
        with self.assertRaises(socket.timeout):
            protocol.chunk(0, 100)
        self.assertEqual(len(protocol.sock.sent), 1)


class ScriptedUdp:
    """UDP double that answers each request sent with the next scripted list of datagrams."""
    def __init__(self, script):
        self.script, self.queue, self.sent = list(script), [], []

    def settimeout(self, value):
        pass

    def send(self, data):
        self.sent.append(bytes(data))
        self.queue = [bytes(d) for d in self.script.pop(0)] if self.script else []

    def recv(self, count):
        if not self.queue:
            raise socket.timeout()
        return self.queue.pop(0)

    def close(self):
        pass


def scripted(script):
    protocol = udp_stubbed()
    protocol.sock = ScriptedUdp(script)
    return protocol


def data_frame(reply, part):
    return reply_frame(1501, 7, reply, part, top=False)


def prepare(reply, size):
    return reply_frame(1500, 7, reply, struct.pack("<I", size), top=False)


def ack(reply):
    return reply_frame(2000, 7, reply, top=False)


class UdpRetryStrayTests(unittest.TestCase):
    def test_a_late_stray_of_the_failed_attempt_cannot_fill_in_for_a_lost_datagram(self):
        protocol = scripted([
            [prepare(5, 8), data_frame(0, b"AAAA")],  # Attempt 1 (id 5) stalls after one datagram.
            # Attempt 2 (id 6): the stray of attempt 1 arrives after the new PREPARE_DATA and BBBB is lost.
            [prepare(6, 8), data_frame(5, b"ZZZZ"), data_frame(0, b"AAAA"), ack(6)],
            [prepare(7, 8), data_frame(0, b"AAAA"), data_frame(0, b"BBBB"), ack(7)],
        ])
        self.assertEqual(protocol.chunk(0, 8), b"AAAABBBB")
        self.assertEqual(len(protocol.sock.sent), 3)
        self.assertEqual(protocol.failed_ids, {5, 6})  # Kept for the whole session: a stray may arrive during a later chunk

    def test_strays_of_every_failed_attempt_are_dropped_but_other_ids_are_accepted(self):
        protocol = scripted([
            [],
            [prepare(6, 8), data_frame(5, b"ZZZZ")],
            [prepare(7, 8), data_frame(5, b"ZZZZ"), data_frame(6, b"YYYY"), data_frame(0, b"AAAA"), data_frame(0, b"BBBB"), ack(7)],
        ])
        self.assertEqual(protocol.chunk(0, 8), b"AAAABBBB")

    def test_a_datagram_with_the_current_request_id_is_accepted(self):
        protocol = scripted([
            [],
            [prepare(6, 8), data_frame(6, b"AAAA"), data_frame(6, b"BBBB"), ack(6)],
        ])
        self.assertEqual(protocol.chunk(0, 8), b"AAAABBBB")

    def test_udp_overflow_is_a_lost_chunk_and_is_requested_again(self):
        protocol = udp_stubbed([prepare(5, 8), data_frame(0, b"A" * 5), data_frame(0, b"B" * 5)])
        with self.assertRaises(ChunkLost):
            protocol.chunk_once(0, 8)
        protocol = scripted([
            [prepare(5, 8), data_frame(0, b"A" * 5), data_frame(0, b"B" * 5)],
            [prepare(6, 8), data_frame(0, b"AAAA"), data_frame(0, b"BBBB"), ack(6)],
        ])
        self.assertEqual(protocol.chunk(0, 8), b"AAAABBBB")
        self.assertEqual(len(protocol.sock.sent), 2)

    def test_tcp_overflow_is_still_invalid_device_data(self):
        protocol = stubbed(reply_frame(1500, 7, 5, struct.pack("<I", 8)) + reply_frame(1501, 7, 5, b"A" * 5)
                           + reply_frame(1501, 7, 5, b"B" * 5), session=7, reply=4)
        with self.assertRaises(AdapterError) as error:
            protocol.chunk_once(0, 8)
        self.assertEqual(error.exception.code, "INVALID_DEVICE_DATA")


class UdpSessionIdTests(unittest.TestCase):
    def sent_ids(self, protocol):
        return [struct.unpack("<4H", sent[:8])[3] for sent in protocol.sock.sent]

    def test_a_late_stray_cannot_make_a_retry_reuse_a_failed_attempts_reply_id(self):
        # Chunk K-1 (id 5) is answered inline; its trailing ACK arrives late and is taken as the reply to chunk K's
        # first attempt (id 6). The next id follows the last id sent, so attempt 2 is 7, never 6 again.
        protocol = scripted([
            [data_frame(5, b"PPPPQQQQ")],
            [ack(5), prepare(6, 8), data_frame(6, b"AAAA"), data_frame(6, b"BBBB"), ack(6)],
            [prepare(6, 8), data_frame(6, b"BBBB"), data_frame(6, b"AAAA"), ack(6)],
            [prepare(7, 8), data_frame(7, b"AAAA"), data_frame(7, b"BBBB"), ack(7)],
        ])
        self.assertEqual(protocol.chunk(0, 8), b"PPPPQQQQ")
        try:
            data = protocol.chunk(8, 8)
        except AdapterError:
            data = None  # Running out of attempts is acceptable; reordered bytes are not.
        ids = self.sent_ids(protocol)
        self.assertEqual(len(ids), len(set(ids)), ids)
        self.assertEqual(ids, sorted(ids))
        self.assertIn(data, (None, b"AAAABBBB"))
        self.assertNotEqual(data, b"BBBBAAAA")

    def test_reply_ids_follow_the_last_id_sent_over_udp_even_when_the_device_answers_another(self):
        protocol = udp_stubbed([reply_frame(2000, 7, 4, b"late", top=False)])
        protocol.command(50)
        self.assertEqual(self.sent_ids(protocol), [5])
        protocol.sock.queue.append(reply_frame(2000, 7, 4, b"late", top=False))
        protocol.command(50)
        self.assertEqual(self.sent_ids(protocol), [5, 6])  # A reply carrying 4 does not rewind the counter

    def test_tcp_still_derives_the_next_reply_id_from_the_device_reply(self):
        protocol = stubbed(reply_frame(2000, 7, 40) + reply_frame(2000, 7, 50), session=7, reply=4)
        protocol.command(11)
        protocol.command(11)
        sent = [struct.unpack("<4H", frame[8:16])[3] for frame in protocol.sock.sent]
        self.assertEqual(sent, [5, 41])

    def test_a_stray_of_an_earlier_chunks_failed_attempt_is_not_spliced_into_the_next_chunk(self):
        protocol = scripted([
            [prepare(5, 8), data_frame(5, b"AAAA")],
            [prepare(6, 8), data_frame(6, b"AAAA"), data_frame(6, b"BBBB"), ack(6)],
            [prepare(7, 8), data_frame(7, b"CCCC"), data_frame(5, b"BBBB"), ack(7)],
            [prepare(8, 8), data_frame(8, b"CCCC"), data_frame(8, b"DDDD"), ack(8)],
        ])
        self.assertEqual(protocol.chunk(0, 8), b"AAAABBBB")
        self.assertEqual(protocol.failed_ids, {5})
        self.assertEqual(protocol.chunk(8, 8), b"CCCCDDDD")
        self.assertEqual(self.sent_ids(protocol), [5, 6, 7, 8])

    def test_failed_ids_are_reset_only_by_a_new_session(self):
        users, records = sample(2, 4)
        with Server(Device(users=users, records=records)) as server:
            protocol = Protocol("127.0.0.1", server.port, 0, timeout=2)
            protocol.failed_ids.add(9)
            with protocol.connected():
                self.assertEqual(protocol.failed_ids, set())

    def test_a_data_datagram_where_the_trailing_ack_belongs_is_a_lost_chunk_and_retried(self):
        protocol = scripted([
            [prepare(5, 8), data_frame(0, b"AAAA"), data_frame(0, b"BBBB"), data_frame(0, b"BBBB"), ack(0)],
            [prepare(6, 8), data_frame(0, b"AAAA"), data_frame(0, b"BBBB"), ack(0)],
        ])
        self.assertEqual(protocol.chunk(0, 8), b"AAAABBBB")
        self.assertEqual(len(protocol.sock.sent), 2)
        with self.assertRaises(ChunkLost):
            udp_stubbed([prepare(5, 8), data_frame(0, b"AAAA"), data_frame(0, b"BBBB"), data_frame(0, b"BBBB")]).chunk_once(0, 8)

    def test_an_extra_data_datagram_in_place_of_the_ack_is_still_invalid_over_tcp(self):
        protocol = stubbed(reply_frame(1500, 7, 5, struct.pack("<I", 8)) + reply_frame(1501, 7, 5, b"AAAA")
                           + reply_frame(1501, 7, 5, b"BBBB") + reply_frame(1501, 7, 5, b"CCCC"), session=7, reply=4)
        with self.assertRaises(AdapterError) as error:
            protocol.chunk_once(0, 8)
        self.assertEqual(error.exception.code, "INVALID_DEVICE_DATA")

    def test_consistent_overflow_is_an_incompatible_device_not_a_transient_outage(self):
        protocol = scripted([[prepare(reply, 8), data_frame(0, b"A" * 5), data_frame(0, b"B" * 5)] for reply in (5, 6, 7)])
        with self.assertRaises(AdapterError) as error:
            protocol.chunk(0, 8)
        self.assertEqual((error.exception.code, error.exception.transient), ("INVALID_DEVICE_DATA", False))
        self.assertEqual(len(protocol.sock.sent), UDP_ATTEMPTS)

    def test_overflow_mixed_with_other_failures_is_still_a_transient_outage(self):
        protocol = scripted([[prepare(5, 8), data_frame(0, b"A" * 5), data_frame(0, b"B" * 5)], [], []])
        with self.assertRaises(AdapterError) as error:
            protocol.chunk(0, 8)
        self.assertEqual((error.exception.code, error.exception.transient), ("DEVICE_UNREACHABLE", True))


class FollowOnFrameTests(unittest.TestCase):
    def test_data_frames_of_a_transfer_need_not_repeat_the_session_id(self):
        users, records = sample(5, 50)
        device = Device(users=users, records=records, follow_session=4242)
        with Server(device) as server:
            with Protocol("127.0.0.1", server.port, 0, timeout=2).connected() as session:
                self.assertEqual(session.counts(), (5, 50))
                size, body = session.records(50)
        self.assertEqual((size, len(body)), (40, 2000))

    def test_command_replies_still_require_the_session_id(self):
        protocol = stubbed(reply_frame(2000, 99, 5), session=7, reply=4)
        with self.assertRaises(AdapterError) as error:
            protocol.command(50)
        self.assertEqual(error.exception.code, "INVALID_DEVICE_DATA")


def fake_socket_module(pending=True):
    """The socket module whose connect_ex reports a connect still in progress (the real one has finished)."""
    class Slow(socket.socket):
        def connect_ex(self, address):
            result = super().connect_ex(address)
            return errno_in_progress if pending and result in (0, errno_in_progress) else result
    errno_in_progress = zk_protocol.errno.EINPROGRESS
    module = types.SimpleNamespace(**{name: getattr(socket, name) for name in dir(socket) if not name.startswith("__")})
    module.socket = Slow
    return module


class TcpConnectTests(unittest.TestCase):
    def listener(self):
        class Quiet(socketserver.ThreadingTCPServer):
            allow_reuse_address = daemon_threads = True
        class Hold(socketserver.BaseRequestHandler):
            def handle(self):
                time.sleep(2)
        server = Quiet(("127.0.0.1", 0), Hold)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def protocol(self, port, timeout, **options):
        protocol = Protocol("127.0.0.1", port, 0, timeout=timeout, **options)
        protocol.started = time.monotonic()
        protocol.deadline = protocol.started + timeout
        return protocol

    def test_a_handshake_slower_than_one_slice_still_connects(self):
        waits, begun = [], time.monotonic()
        def late_select(readable, writable, failed, timeout):
            waits.append(timeout)
            time.sleep(timeout)
            return ([], list(writable), []) if time.monotonic() - begun >= 2.5 else ([], [], [])
        protocol = self.protocol(self.listener(), 5)
        with patch.object(zk_protocol, "socket", fake_socket_module()), \
                patch.object(zk_protocol, "select", types.SimpleNamespace(select=late_select)):
            protocol.open_tcp()
        self.addCleanup(protocol.sock.close)
        self.assertGreaterEqual(time.monotonic() - begun, 2.5)
        self.assertGreaterEqual(len(waits), 3)
        self.assertTrue(all(wait <= 1.0 for wait in waits))
        self.assertTrue(protocol.sock.getpeername())  # One connect attempt that was never abandoned

    def test_a_connect_that_never_completes_gives_up_after_the_timeout(self):
        quiet = types.SimpleNamespace(select=lambda r, w, x, timeout: (time.sleep(timeout), ([], [], []))[1])
        protocol = self.protocol(self.listener(), 1.5)
        started = time.monotonic()
        with patch.object(zk_protocol, "socket", fake_socket_module()), patch.object(zk_protocol, "select", quiet):
            with self.assertRaises(socket.timeout):
                protocol.open_tcp()
        self.assertLess(time.monotonic() - started, 2.7)
        self.assertIsNone(protocol.sock)

    def test_a_cancel_is_noticed_between_slices_of_a_pending_connect(self):
        cancel = threading.Event()
        threading.Timer(.4, cancel.set).start()
        quiet = types.SimpleNamespace(select=lambda r, w, x, timeout: (time.sleep(timeout), ([], [], []))[1])
        protocol = self.protocol(self.listener(), 30, cancelled=cancel.is_set)
        started = time.monotonic()
        with patch.object(zk_protocol, "socket", fake_socket_module()), patch.object(zk_protocol, "select", quiet):
            with self.assertRaises(AdapterError) as error:
                protocol.open_tcp()
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual((error.exception.code, error.exception.reason), ("DEVICE_UNREACHABLE", "CANCELLED"))

    def test_a_failed_connect_in_the_exceptional_set_reports_its_error(self):
        # Windows reports a failed connect in the exceptional set; SO_ERROR then names the failure.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]
        import select as real
        def exceptional_only(readable, writable, failed, timeout):
            _, done, broken = real.select([], writable, failed, timeout)
            return [], [], done + broken
        exceptional = types.SimpleNamespace(select=exceptional_only)
        protocol = self.protocol(closed, 5)
        with patch.object(zk_protocol, "socket", fake_socket_module()), patch.object(zk_protocol, "select", exceptional):
            with self.assertRaises(ConnectionRefusedError):
                protocol.open_tcp()
        self.assertIsNone(protocol.sock)

    def test_a_refusal_returns_at_once_and_still_allows_the_udp_fallback(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]
        started = time.monotonic()
        with self.assertRaises(AdapterError):
            with Protocol("127.0.0.1", closed, 0, timeout=10, transport="tcp").connected():
                pass
        self.assertLess(time.monotonic() - started, 1)


class UdpFallbackTests(unittest.TestCase):
    def read(self, device, key=0, transport="auto", timeout=2):
        with Server(device, udp=True) as server:
            with Protocol("127.0.0.1", server.port, key, timeout=timeout, transport=transport).connected() as session:
                identity = session.serial()
                users_count, count = session.counts()
                users = session.users(users_count)
                size, body = session.records(count)
                return identity, users, size, body, session.udp

    def test_refused_tcp_falls_back_to_udp(self):
        users, records = sample(20, 100)
        device = Device(users=users, records=records)
        identity, found, size, body, udp = self.read(device)
        self.assertTrue(udp)
        self.assertEqual((identity, len(found), size, len(body)), ("ZK:CDQ9201760123", 20, 40, 4000))
        self.assertEqual(device.bad_checksums, 0)

    def test_udp_comm_key(self):
        users, records = sample(5, 10)
        device = Device(users=users, records=records, comm_key=123456)
        identity, _, _, body, _ = self.read(device, key=123456)
        self.assertEqual((identity, len(body)), ("ZK:CDQ9201760123", 400))
        with self.assertRaises(AdapterError) as error:
            self.read(Device(users=users, records=records, comm_key=123456), key=1)
        self.assertEqual((error.exception.code, error.exception.reason), ("UNSUPPORTED", "COMM_KEY_REJECTED"))

    def test_udp_multi_chunk_5000_records_and_small_inline_reply(self):
        users, records = sample(100, 5000)
        device = Device(users=users, records=records)
        _, found, size, body, udp = self.read(device)
        self.assertTrue(udp)
        self.assertEqual((len(found), size, len(body)), (100, 40, 200_000))
        self.assertGreaterEqual(device.commands.count(1504), 13)  # 16 KiB chunks over UDP
        self.assertEqual(device.bad_checksums, 0)
        users, records = sample(3, 4)
        self.assertEqual(self.read(Device(users=users, records=records, inline_threshold=4096))[2], 40)

    def test_udp_record_formats(self):
        for record_format, user_format in ((8, 72), (16, 28)):
            users, records = sample(5, 30)
            device = Device(users=users, records=records, record_format=record_format, user_format=user_format)
            _, _, size, body, _ = self.read(device)
            self.assertEqual((size, len(body)), (record_format, 30 * record_format))

    def test_udp_silence_is_a_transient_unreachable_device(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
            silent.bind(("127.0.0.1", 0))
            started = time.monotonic()
            with self.assertRaises(AdapterError) as error:
                with Protocol("127.0.0.1", silent.getsockname()[1], 0, timeout=.2, transport="udp").connected():
                    pass
            self.assertEqual((error.exception.code, error.exception.transient), ("DEVICE_UNREACHABLE", True))
            self.assertLess(time.monotonic() - started, 3)

    def test_discovery_style_default_never_tries_udp(self):
        with Server(Device(), udp=True) as server:
            protocol = Protocol("127.0.0.1", server.port, 0, .6)
            self.assertEqual(protocol.transport, "tcp")
            with self.assertRaises(AdapterError) as error:
                with protocol.connected():
                    pass
            self.assertEqual((error.exception.code, error.exception.transient), ("DEVICE_UNREACHABLE", True))
            self.assertFalse(protocol.udp)

    def test_stalled_tcp_listener_does_not_trigger_a_second_udp_wait(self):
        class Stall(socketserver.BaseRequestHandler):
            def handle(self):
                time.sleep(3)
        class Quiet(socketserver.ThreadingTCPServer):
            allow_reuse_address = daemon_threads = True
        opened = []
        class Spy(Protocol):
            def open_udp(self):
                opened.append(True)
                super().open_udp()
        with Quiet(("127.0.0.1", 0), Stall) as server:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            started = time.monotonic()
            protocol = Spy("127.0.0.1", server.server_address[1], 0, timeout=.5, transport="auto")
            with self.assertRaises(AdapterError):
                with protocol.connected():
                    pass
            self.assertFalse(protocol.udp)
            self.assertEqual(opened, [])  # No UDP attempt, hence no second wait
            self.assertLess(time.monotonic() - started, 2.5)
            server.shutdown()

    def attempts(self, device, timeout=.6):
        with Server(device, udp=True) as server:
            users, records = sample(10, 200)
            protocol = SpyProtocol("127.0.0.1", server.port, 0, timeout=timeout, transport="auto")
            with protocol.connected() as session:
                session.serial()
                users_count, count = session.counts()
                found = session.users(users_count)
                size, body = session.records(count)
            return protocol, len(found), size, len(body)

    def test_a_lost_data_datagram_is_recovered_by_asking_for_the_chunk_again(self):
        users, records = sample(10, 200)
        device = Device(users=users, records=records, drop_udp_data_once=True)
        protocol, found, size, length = self.attempts(device)
        self.assertEqual((found, size, length), (10, 40, 8000))
        self.assertEqual(device.commands.count(1504), 3)  # users once, attendance twice
        self.assertEqual(device.bad_checksums, 0)

    def test_a_lost_reply_is_recovered_after_the_timeout(self):
        users, records = sample(10, 200)
        device = Device(users=users, records=records, drop_udp_reply_once=True)
        _, found, size, length = self.attempts(device, timeout=1)  # The slack no longer hinges on a ~150 ms margin
        self.assertEqual((found, size, length), (10, 40, 8000))
        self.assertEqual(device.commands.count(1504), 3)
        self.assertEqual(device.bad_checksums, 0)

    def test_a_small_log_survives_two_lost_replies(self):
        users, records = sample(10, 200)
        device = Device(users=users, records=records, drop_udp_reply_once=2)
        _, found, size, length = self.attempts(device)
        self.assertEqual((found, size, length), (10, 40, 8000))
        self.assertEqual(device.commands.count(1504), 4)  # users three times, attendance once
        self.assertEqual(device.bad_checksums, 0)

    def test_udp_session_budget_leaves_room_for_every_attempt_of_a_chunk(self):
        with Server(Device(), udp=True) as server:
            protocol = Protocol("127.0.0.1", server.port, 0, timeout=2, transport="udp")
            with protocol.connected() as session:
                session.counts()
                self.assertGreater(protocol.deadline - time.monotonic(), 2 + UDP_ATTEMPTS * 2 - .5)
        with Server(Device()) as server:
            protocol = Protocol("127.0.0.1", server.port, 0, timeout=2)
            with protocol.connected() as session:
                session.counts()
                self.assertLess(protocol.deadline - time.monotonic(), 2 + .5)  # TCP has no such slack

    def test_a_lost_reply_is_retried_after_a_short_wait_not_the_full_operation_timeout(self):
        users, records = sample(10, 200)
        device = Device(users=users, records=records, drop_udp_reply_once=True)
        with patch.object(zk_protocol, "UDP_WAIT", .3):
            started = time.monotonic()
            _, found, size, length = self.attempts(device, timeout=30)
        self.assertEqual((found, size, length), (10, 40, 8000))
        self.assertEqual(device.commands.count(1504), 3)
        self.assertLess(time.monotonic() - started, 5)

    def test_a_lost_prepare_data_of_a_long_chunk_is_requested_again(self):
        users, records = sample(10, 200)  # 8 KB attendance: eight 1 KiB datagrams after the PREPARE_DATA
        device = Device(users=users, records=records, drop_udp_prepare_once=True, drop_udp_prepare_over=1024)
        protocol, found, size, length = self.attempts(device)
        self.assertEqual((found, size, length), (10, 40, 8000))
        self.assertEqual(device.commands.count(1504), 3)  # The first 1501 is not an inline reply: asked again
        self.assertEqual(device.bad_checksums, 0)

    def test_a_lost_prepare_data_of_a_one_datagram_chunk_leaves_no_stale_ack_behind(self):
        users, records = sample(2, 5)  # 148 and 204 bytes: each chunk fits one datagram
        device = Device(users=users, records=records, drop_udp_prepare_once=True)
        with Server(device, udp=True) as server:
            protocol = SpyProtocol("127.0.0.1", server.port, 0, timeout=1, transport="auto")
            with protocol.connected() as session:
                session.serial()
                users_count, count = session.counts()
                found = session.users(users_count)
                size, body = session.records(count)
                self.assertEqual(session.command(50)[0], 2000)
        self.assertEqual((len(found), size, len(body)), (2, 40, 200))
        replies = [reply for _, _, reply in protocol.sent]
        self.assertEqual(replies[1:], list(range(len(replies) - 1)))  # No reply id is ever reused (the first is the id before CONNECT)
        self.assertEqual(protocol.codes()[-1], 1001)
        self.assertEqual(device.bad_checksums, 0)

    def test_an_inline_chunk_reply_without_a_trailing_ack_is_still_accepted(self):
        data = b"x" * 40
        protocol = udp_stubbed([reply_frame(1501, 7, 5, data, top=False)])
        self.assertEqual(protocol.chunk(0, 40), data)
        self.assertEqual(len(protocol.sock.sent), 1)  # No retry for firmware that sends no ACK

    def test_an_inline_first_datagram_shorter_than_the_chunk_is_a_lost_prepare_data(self):
        protocol = udp_stubbed([reply_frame(1501, 7, 5, b"x" * 10, top=False)])
        with self.assertRaises(ChunkLost):
            protocol.chunk_once(0, 40)

    def test_a_device_that_does_not_echo_the_reply_id_on_data_datagrams_is_still_read(self):
        users, records = sample(10, 200)
        device = Device(users=users, records=records, udp_reply_override=0)
        _, found, size, length = self.attempts(device)
        self.assertEqual((found, size, length), (10, 40, 8000))
        self.assertEqual(device.commands.count(1504), 2)  # users once, attendance once: no retry needed
        self.assertEqual(device.bad_checksums, 0)

    def test_a_lost_data_datagram_is_recovered_when_the_device_does_not_echo_the_reply_id(self):
        users, records = sample(10, 200)
        device = Device(users=users, records=records, udp_reply_override=0, drop_udp_data_once=True)
        _, found, size, length = self.attempts(device)
        self.assertEqual((found, size, length), (10, 40, 8000))
        self.assertEqual(device.commands.count(1504), 3)  # users once, attendance twice
        self.assertEqual(device.bad_checksums, 0)

    def test_a_lost_reply_is_recovered_when_the_device_does_not_echo_the_reply_id(self):
        users, records = sample(10, 200)
        device = Device(users=users, records=records, udp_reply_override=0, drop_udp_reply_once=True)
        _, found, size, length = self.attempts(device, timeout=1)
        self.assertEqual((found, size, length), (10, 40, 8000))
        self.assertEqual(device.commands.count(1504), 3)
        self.assertEqual(device.bad_checksums, 0)

    def test_follow_on_frames_are_not_filtered_by_reply_id(self):
        protocol = udp_stubbed([reply_frame(1501, 7, 0, b"data", top=False)])
        protocol.expect_reply = 5
        self.assertEqual(protocol.packet(strict=False), (1501, 7, b"data"))

    def test_unknown_transport_is_rejected(self):
        with self.assertRaises(ValueError):
            Protocol("127.0.0.1", transport="sctp")


class CancellationTests(unittest.TestCase):
    def slow(self):
        users, records = sample(10, 3000)  # 120 KB at 32 KB/s
        return Device(users=users, records=records, throughput=16384 / .5)

    def read_all(self, protocol):
        with protocol.connected() as session:
            session.serial()
            users_count, count = session.counts()
            session.users(users_count)
            return session.records(count)

    def test_a_cancel_interrupts_a_slow_transfer_within_a_couple_of_seconds(self):
        device = self.slow()
        cancel = threading.Event()
        with Server(device) as server:
            protocol = SpyProtocol("127.0.0.1", server.port, 0, timeout=30, cancelled=cancel.is_set)
            thread, outcome = run_in_thread(lambda: self.read_all(protocol))
            deadline = time.monotonic() + 5
            while device.commands.count(1504) < 2 and time.monotonic() < deadline:
                time.sleep(.02)
            cancel.set()
            started = time.monotonic()
            thread.join(10)
            self.assertFalse(thread.is_alive())
        self.assertLess(time.monotonic() - started, 3)
        error = outcome[0]
        self.assertIsInstance(error, AdapterError)
        self.assertEqual((error.code, error.transient, error.reason), ("DEVICE_UNREACHABLE", True, "CANCELLED"))
        self.assertNotIn(1001, protocol.codes())  # No EXIT is awaited after a cancel

    def test_an_already_cancelled_session_never_touches_the_network(self):
        protocol = Protocol("127.0.0.1", 9, cancelled=lambda: True)
        with self.assertRaises(AdapterError) as error:
            with protocol.connected():
                pass
        self.assertEqual((error.exception.code, error.exception.transient, error.exception.reason),
                         ("DEVICE_UNREACHABLE", True, "CANCELLED"))
        self.assertIsNone(protocol.sock)

    def test_a_silent_udp_device_is_cancelled_during_the_wait(self):
        cancel = threading.Event()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
            silent.bind(("127.0.0.1", 0))
            protocol = Protocol("127.0.0.1", silent.getsockname()[1], 0, timeout=30, transport="udp", cancelled=cancel.is_set)
            def connect():
                with protocol.connected():
                    pass
            thread, outcome = run_in_thread(connect)
            time.sleep(.3)
            cancel.set()
            started = time.monotonic()
            thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(outcome[0].code, "DEVICE_UNREACHABLE")


class ExitTests(unittest.TestCase):
    def test_exit_is_sent_after_a_finished_session(self):
        users, records = sample(2, 4)
        with Server(Device(users=users, records=records)) as server:
            protocol = SpyProtocol("127.0.0.1", server.port, 0, timeout=2)
            with protocol.connected() as session:
                session.serial()
        self.assertEqual(protocol.codes()[-1], 1001)

    def test_a_failed_transfer_just_closes_the_socket_within_about_one_timeout(self):
        users, records = sample(10, 3000)
        device = Device(users=users, records=records, throughput=16384 / 3)  # stalls after the first 16 KiB
        with Server(device) as server:
            protocol = SpyProtocol("127.0.0.1", server.port, 0, timeout=1)
            started = time.monotonic()
            with self.assertRaises(AdapterError) as error:
                with protocol.connected() as session:
                    session.serial()
                    users_count, count = session.counts()
                    session.users(users_count)
                    session.records(count)
            elapsed = time.monotonic() - started
        self.assertEqual((error.exception.code, error.exception.transient), ("DEVICE_UNREACHABLE", True))
        self.assertNotIn(1001, protocol.codes())
        self.assertLess(elapsed, 1.8)  # The old code waited a second full timeout for EXIT


class CommKeyRejectionTests(unittest.TestCase):
    def test_wrong_key_keeps_the_cloud_code_but_carries_a_local_reason(self):
        users, records = sample(2, 2)
        device = Device(users=users, records=records, comm_key=123456)  # 2005 to CONNECT, then to AUTH
        with Server(device) as server:
            with self.assertRaises(AdapterError) as error:
                with Protocol("127.0.0.1", server.port, 999, timeout=2).connected():
                    pass
        self.assertEqual(error.exception.code, "UNSUPPORTED")
        self.assertFalse(error.exception.transient)
        self.assertEqual(error.exception.reason, "COMM_KEY_REJECTED")
        self.assertIn(1102, device.commands)

    def test_unauthorised_answer_to_a_later_command_is_the_same_failure(self):
        protocol = stubbed(reply_frame(2005, 7, 5), session=7, reply=4)
        with self.assertRaises(AdapterError) as error:
            protocol.command(50)
        self.assertEqual((error.exception.code, error.exception.reason), ("UNSUPPORTED", "COMM_KEY_REJECTED"))

    def test_connect_asking_for_auth_is_not_an_error_by_itself(self):
        protocol = stubbed(reply_frame(2005, 7, 0))
        self.assertEqual(protocol.command(1000)[0], 2005)

    def test_other_adapter_errors_have_no_reason(self):
        self.assertIsNone(AdapterError("DEVICE_UNREACHABLE", True).reason)


if __name__ == "__main__":
    unittest.main()
