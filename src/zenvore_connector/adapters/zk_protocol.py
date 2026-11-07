"""Read-only ZK transport (TCP, with a UDP fallback), adapted from this repository's Identix client.

No third-party SDK is bundled. Only CONNECT/AUTH, option reads, size reads,
user/attendance transfer, transfer cleanup and EXIT are permitted.
"""
import errno
import os
import select
import socket
import struct
import time
from contextlib import contextmanager
from .base import AdapterError

MAGIC = b"\x50\x50\x82\x7d"
# Upper bounds protect memory. 500,000 records is about 125 MiB of dedupe rows in the local store,
# which storage.py caps at 262144 pages of 4 KiB (1 GiB) shared by every device.
MAX_USERS = 100_000
MAX_RECORDS = 500_000
MAX_BYTES = 32 * 1024 * 1024
RECV_LIMIT = 1 << 20  # One recv never asks the kernel for more than this.
MIN_RATE = 50 * 1024  # Slowest device throughput (bytes/second) a session budget allows for.
MAX_SESSION = 600  # Hard cap, in seconds, on one device session however large the log is.
TCP_CHUNK = 0xffc0
UDP_CHUNK = 16 * 1024
UDP_ATTEMPTS = 3  # A UDP chunk is requested at most this many times (pyzk retries three times as well).
SLICE = 1.0  # Longest single blocking socket wait, so a cancel is noticed within about a second.
UDP_WAIT = 5.0  # Longest wait for one UDP chunk reply, so a lost datagram is retried well before the per-op timeout.
ACK_PEEK = 0.25  # How long an inline UDP chunk waits for a trailing ACK that a lost PREPARE_DATA may have left queued.
IN_PROGRESS = {errno.EINPROGRESS, errno.EWOULDBLOCK, 10035}  # 10035 is WSAEWOULDBLOCK, which connect_ex returns on Windows.
EXIT_WAIT = 2  # Seconds EXIT may take; the session's data is already complete by then.
OK = (2000, 2002)
CMD_ACK_UNAUTH = 2005
COMM_KEY_REJECTED = "COMM_KEY_REJECTED"


def checksum(data):
    total = sum(data[i] | ((data[i + 1] if i + 1 < len(data) else 0) << 8) for i in range(0, len(data), 2))
    while total > 65535:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def comm_key(key, session):
    reversed_bits = int(format(key, "032b")[::-1], 2)
    data = bytearray(struct.pack("<I", (reversed_bits + session) & 0xffffffff))
    data = bytearray(a ^ b for a, b in zip(data, b"ZKSO"))
    data = data[2:] + data[:2]
    return bytes((data[0] ^ 50, data[1] ^ 50, 50, data[3] ^ 50))


def layout(length, low, high, sizes):
    """Return the one record size that explains `length` bytes holding between low and high records."""
    found = [size for size in sizes if length % size == 0 and low <= length // size <= high]
    return found[0] if len(found) == 1 else None


class ChunkLost(Exception):
    """A UDP datagram of a chunk was lost, so the chunk is requested again."""


class ChunkOverflow(ChunkLost):
    """A UDP chunk carried more data than requested. Retried like a loss, but if every attempt overflows
    the firmware is incompatible, not the network lossy."""


class Protocol:
    def __init__(self, ip, port=4370, password=0, timeout=15, transport="tcp", cancelled=None):
        self.ip, self.port, self.password = ip, int(port), int(password)
        if not 0 <= self.password <= 0xffffffff:
            raise ValueError("Communication key must be an unsigned 32-bit integer")
        if transport not in ("tcp", "udp", "auto"):
            raise ValueError("Transport must be tcp, udp or auto")
        # `timeout` limits each socket operation. connected() also uses it as the
        # budget for connect + CONNECT + AUTH; counts() then sizes the transfer budget.
        self.timeout, self.transport = timeout, transport
        self.cancelled = cancelled or (lambda: False)
        self.sock = None
        self.udp = False
        self.session, self.reply = 0, 65534
        self.expect_reply = None  # While set, UDP datagrams with another reply id are stale and ignored.
        self.filter_stale = False  # Only retries filter: pyzk never does, and some firmware may not echo the id.
        self.recovered = False  # Set once a UDP chunk was lost; from then on every command reply is matched by id.
        self.request = None  # Reply id of the command last sent.
        self.failed_ids = set()  # Reply ids of every failed chunk attempt of this session (UDP); ids are never reused.
        self.wait = None  # Per-attempt UDP reply wait while a chunk is read; None means the per-operation timeout.
        self.started = self.deadline = time.monotonic()

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise AdapterError("DEVICE_UNREACHABLE", True)
        return min(self.timeout, remaining)

    def cancel_check(self):
        if self.cancelled():
            # The cloud code stays DEVICE_UNREACHABLE (whitelisted); the reason tells the runtime this is a
            # shutdown, not an outage, so it neither rediscovers nor reports the device as unreachable.
            raise AdapterError("DEVICE_UNREACHABLE", True, reason="CANCELLED")

    def receive(self, size, end=None):
        """recv() in short slices: honours cancellation, the per-operation timeout and the session deadline."""
        end = time.monotonic() + self.timeout if end is None else end
        while True:
            self.cancel_check()
            now = time.monotonic()
            if now >= self.deadline:
                raise AdapterError("DEVICE_UNREACHABLE", True)
            left = min(end, self.deadline) - now
            if left <= 0:
                raise socket.timeout()
            self.sock.settimeout(min(SLICE, left))
            try:
                return self.sock.recv(size)
            except socket.timeout:
                continue

    def exact(self, count):
        result = bytearray()
        while len(result) < count:
            chunk = self.receive(min(count - len(result), RECV_LIMIT))
            if not chunk:
                raise AdapterError("DEVICE_UNREACHABLE", True)
            result.extend(chunk)
        return bytes(result)

    def drain(self):
        """Discard datagrams already queued for this socket."""
        self.sock.settimeout(0)
        try:
            while True:
                self.sock.recv(65535)
        except OSError:
            pass

    def packet(self, strict=True, wait=None):
        """Read one frame. Follow-on data frames of a transfer pass strict=False."""
        if self.udp:
            # Skipping stale datagrams must not extend the wait.
            end = time.monotonic() + (wait or self.wait or self.timeout)
            while True:
                body = self.receive(65535, end)
                if len(body) < 8:
                    raise AdapterError("UNSUPPORTED")
                reply_id = struct.unpack_from("<H", body, 6)[0]
                # Only the first reply to a command is matched by id, and only after a loss. Follow-on frames
                # (data, trailing ACK) are accepted whatever id they carry, since firmware may not echo it, except
                # a datagram carrying the id of a failed attempt of this chunk: that one arrived late, and
                # drain() could not have removed it.
                if strict:
                    if self.expect_reply is None or reply_id == self.expect_reply:
                        break
                elif reply_id not in self.failed_ids or reply_id == self.request:
                    break
        else:
            header = self.exact(8)
            size = struct.unpack("<I", header[4:])[0]
            if header[:4] != MAGIC or not 8 <= size <= MAX_BYTES:
                raise AdapterError("UNSUPPORTED")
            body = self.exact(size)
        command, _, session, reply = struct.unpack("<4H", body[:8])
        if strict and self.session and session != self.session:
            raise AdapterError("INVALID_DEVICE_DATA")
        if strict:
            self.reply = reply  # Like pyzk, only the first reply to a command carries the reply id.
        return command, session, body[8:]

    def command(self, code, data=b""):
        if code not in {1000, 1001, 1102, 11, 50, 1502, 1503, 1504}:
            raise AdapterError("UNSUPPORTED")
        # The device checksums the packet exactly as sent, so advance the reply id first. Over UDP the next id
        # follows the last id sent, not the last reply: a stale datagram carrying an older id must never make
        # a retry reuse the id of a failed attempt. TCP derives it from the device reply, as pyzk does.
        last = self.request if self.udp and self.request is not None else self.reply
        self.reply = (last + 1) % 65535
        self.request = self.reply
        header = struct.pack("<4H", code, 0, self.session, self.reply)
        body = struct.pack("<4H", code, checksum(header + data), self.session, self.reply) + data
        self.cancel_check()
        self.sock.settimeout(self.remaining())
        self.expect_reply = self.reply if self.udp and (self.filter_stale or self.recovered) else None
        if self.udp:
            self.sock.send(body)
        else:
            self.sock.sendall(MAGIC + struct.pack("<I", len(body)) + body)
        answer, session, payload = self.packet()
        if not self.session:
            self.session = session
        if answer == CMD_ACK_UNAUTH and code != 1000:
            # CONNECT may legitimately ask for AUTH; anything later means the key is wrong.
            raise AdapterError("UNSUPPORTED", reason=COMM_KEY_REJECTED)
        return answer, payload

    def open_udp(self):
        self.udp = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.remaining())
        self.sock.connect((self.ip, self.port))

    def open_tcp(self):
        """One non-blocking connect polled in short slices, so a cancel is noticed while the handshake
        of a slow link (VPN, slow ARP) is still in progress; a refusal still ends the attempt at once."""
        end = time.monotonic() + self.timeout
        self.cancel_check()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setblocking(False)
            result = sock.connect_ex((self.ip, self.port))
            while result in IN_PROGRESS:
                self.cancel_check()
                left = min(end, self.deadline) - time.monotonic()
                if left <= 0:
                    raise socket.timeout()
                # A failed connect shows in the exceptional set on Windows, so watch both.
                _, writable, failed = select.select([], [sock], [sock], min(SLICE, left))
                if writable or failed:
                    result = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    break
            if result:
                raise OSError(result, os.strerror(result))  # ECONNREFUSED becomes ConnectionRefusedError.
            sock.setblocking(True)
        except BaseException:
            sock.close()
            raise
        self.sock = sock

    @contextmanager
    def connected(self):
        self.started = time.monotonic()
        self.deadline = self.started + self.timeout
        self.udp = False
        self.session, self.reply, self.expect_reply = 0, 65534, None
        self.request, self.failed_ids = None, set()
        self.filter_stale = self.recovered = False
        self.wait = None
        completed = False
        try:
            if self.transport == "udp":
                self.open_udp()
            else:
                try:
                    self.open_tcp()
                except ConnectionRefusedError:
                    # Older firmware answers on UDP only. A timeout is not a refusal: no second wait.
                    if self.transport != "auto":
                        raise
                    self.open_udp()
            code, _ = self.command(1000)
            if code == CMD_ACK_UNAUTH:
                code, _ = self.command(1102, comm_key(self.password, self.session))
            if code not in OK:
                raise AdapterError("UNSUPPORTED")
            yield self
            completed = True
        except (socket.timeout, ConnectionError, OSError):
            raise AdapterError("DEVICE_UNREACHABLE", True) from None
        except (struct.error, UnicodeError, ValueError, IndexError):
            raise AdapterError("INVALID_DEVICE_DATA") from None
        finally:
            if self.sock:
                # EXIT is a courtesy after a finished session only; after a failure or a cancel the
                # socket is simply closed. Closing always completes even if EXIT times out.
                if completed and not self.cancelled():
                    try:
                        self.deadline = time.monotonic() + min(self.timeout, EXIT_WAIT)
                        self.command(1001)
                    except Exception:
                        pass
                self.sock.close()
                self.sock = None

    def serial(self):
        code, body = self.command(11, b"~SerialNumber\0")
        if code not in OK:
            raise AdapterError("UNSUPPORTED")
        try:
            text = body.split(b"\0", 1)[0].decode("ascii")
        except UnicodeDecodeError:
            raise AdapterError("INVALID_DEVICE_DATA") from None
        name, separator, serial = text.partition("=")
        if not separator or name != "~SerialNumber":
            raise AdapterError("UNSUPPORTED")
        serial = serial.strip()
        if not serial or len(serial) > 64 or not all(c.isalnum() or c in "-_." for c in serial):
            raise AdapterError("INVALID_DEVICE_DATA")
        return "ZK:" + serial

    def counts(self):
        code, body = self.command(50)
        if code not in OK or len(body) < 36:
            raise AdapterError("UNSUPPORTED")
        values = struct.unpack("<9i", body[:36])
        users, records = values[4], values[8]
        if not 0 <= users <= MAX_USERS or not 0 <= records <= MAX_RECORDS:
            raise AdapterError("INVALID_DEVICE_DATA")
        # Now the transfer size is known: allow time for it at the slowest accepted rate.
        budget = time.monotonic() + self.timeout + (users * 72 + records * 40) / MIN_RATE
        if self.udp:
            budget += UDP_ATTEMPTS * self.timeout  # Every timed-out UDP attempt burns a wait; retries must still fit.
        self.deadline = max(self.deadline, min(budget, self.started + MAX_SESSION))
        return users, records

    def read_buffer(self, target, function=0):
        if target not in (9, 13):
            raise AdapterError("UNSUPPORTED")
        code, data = self.command(1503, struct.pack("<bhii", 1, target, function, 0))
        if code == 1501:
            return data
        if code not in (1500, 2000) or len(data) < 5:
            raise AdapterError("UNSUPPORTED")
        total = struct.unpack("<I", data[1:5])[0]
        if not 4 <= total <= MAX_BYTES:
            raise AdapterError("INVALID_DEVICE_DATA")
        out = bytearray()
        while len(out) < total:
            size = min(UDP_CHUNK if self.udp else TCP_CHUNK, total - len(out))
            out.extend(self.chunk(len(out), size))
        self.command(1502)
        return bytes(out)

    def chunk(self, offset, size):
        if not self.udp:
            return self.chunk_once(offset, size)
        self.wait = min(self.timeout, UDP_WAIT)
        overflows = []  # Per failed attempt: was it an overflow?
        try:
            for attempt in range(UDP_ATTEMPTS):
                # The first attempt accepts any datagram, as pyzk does. Only after a failed attempt can its
                # late datagrams arrive, so only the retries (and the commands after them) ignore datagrams
                # that do not carry the reply id of the request they answer.
                self.filter_stale = attempt > 0
                try:
                    return self.chunk_once(offset, size)
                except (socket.timeout, ChunkLost) as lost:
                    overflows.append(isinstance(lost, ChunkOverflow))
                    self.recovered = True
                    self.failed_ids.add(self.request)
                    self.drain()  # Late datagrams of the failed attempt must not be mistaken for the next.
                finally:
                    self.filter_stale = False
            if all(overflows):
                # Every attempt got more than was asked for: a protocol incompatibility, not a lossy link.
                raise AdapterError("INVALID_DEVICE_DATA")
            raise AdapterError("DEVICE_UNREACHABLE", True)
        finally:
            self.wait = None

    def chunk_once(self, offset, size):
        code, body = self.command(1504, struct.pack("<ii", offset, size))
        if code == 1500:
            if len(body) < 4 or struct.unpack("<I", body[:4])[0] != size:
                raise AdapterError("INVALID_DEVICE_DATA")
            body = bytearray()
            while len(body) < size:
                code, _, part = self.packet(strict=False)
                if self.udp and code == 2000:
                    raise ChunkLost()  # The final ACK overtook a datagram that never arrived.
                if self.udp and code == 1501 and part and len(body) + len(part) > size:
                    raise ChunkOverflow()  # Datagrams of two attempts mixed up; ask for the chunk again.
                if code != 1501 or not part or len(body) + len(part) > size:
                    raise AdapterError("INVALID_DEVICE_DATA")
                body.extend(part)
            ack, _, _ = self.packet(strict=False)
            if self.udp and ack == 1501:
                raise ChunkOverflow()  # Another data datagram where the trailing ACK belongs: more than requested.
            if ack != 2000:
                raise AdapterError("INVALID_DEVICE_DATA")
        elif code == 1501:
            if self.udp:
                if len(body) != size:
                    raise ChunkLost()  # The PREPARE_DATA was lost and this is the first datagram of a longer chunk.
                self.trailing_ack()
        elif self.udp and code == 2000:
            raise ChunkLost()  # An ACK answering something else, or a reply whose data never came.
        else:
            raise AdapterError("INVALID_DEVICE_DATA")
        if len(body) != size:
            raise AdapterError("INVALID_DEVICE_DATA")
        return bytes(body)

    def trailing_ack(self):
        """A chunk that fits one datagram looks the same whether the device replied inline or its
        PREPARE_DATA was lost; in the second case the 2000 ACK is still on its way. Consume it so it
        cannot answer the next command and shift every later reply by one."""
        try:
            self.packet(strict=False, wait=min(ACK_PEEK, self.timeout))
        except socket.timeout:
            pass  # Firmware that answers inline sends no ACK (pyzk does not wait for one either).

    def sized(self, body, count, index, sizes):
        """Record size of a dump. A member may punch or enrol between the size read and the dump,
        so on a mismatch the sizes are read once more and any count between the two is accepted."""
        size = layout(len(body), count, count, sizes)
        if size is None:
            fresh = self.counts()[index]
            size = layout(len(body), min(count, fresh), max(count, fresh), sizes)
        if size is None:
            raise AdapterError("UNSUPPORTED")
        return size

    def users(self, count):
        if count == 0:
            return {}
        body = self.body(self.read_buffer(9, 5))
        if not body:
            # 16- and 40-byte attendance carries its own user id; the caller decides whether the
            # 8-byte layout, which needs this table, can be mapped.
            return {}
        size = self.sized(body, count, 0, (28, 72))
        users = {}
        for offset in range(0, len(body), size):
            uid = struct.unpack_from("<H", body, offset)[0]
            try:
                user = (body[offset + 48:offset + 72].split(b"\0")[0].decode("utf-8")
                        if size == 72 else str(struct.unpack_from("<I", body, offset + 24)[0]))
            except UnicodeError:
                continue  # One unreadable name must not hide every other member.
            if user:
                users[uid] = user
        return users  # Possibly a subset, or empty when no name is readable; see ZKTcp for the 8-byte case.

    def records(self, count):
        """Return (record size, raw records) of the attendance log; (0, b"") when it is empty."""
        if count == 0:
            return 0, b""
        body = self.body(self.read_buffer(13))
        if not body:
            # A cleared log is real, but a stale count is a read glitch: never reset the stored count
            # or report a data gap for it. A transient error retries on the next cycle.
            if self.counts()[1] == 0:
                return 0, b""
            raise AdapterError("INVALID_DEVICE_DATA", True)
        return self.sized(body, count, 1, (8, 16, 40)), body

    @staticmethod
    def body(data):
        if len(data) < 4 or struct.unpack("<I", data[:4])[0] != len(data) - 4:
            raise AdapterError("INVALID_DEVICE_DATA")
        return data[4:]
