"""Strict ZKTeco/Identix device emulator (TCP and UDP, port 4370 protocol) for tests.

Behaviour follows the public reverse-engineered protocol (adrobinoga/zk-protocol, pyzk 0.9)
and real captured packets. The emulator was validated against pyzk 0.9 in both transports.
  * TCP wrapper 50 50 82 7d + u32 length; UDP datagrams carry only the 8-byte ZK header + data.
  * Header: u16 command, checksum, session, reply id.
  * Checksum = ones' complement of the 16-bit LE word sum over the packet AS SENT (verified
    against the captured packet 0b00 58ef c5c0 0500 7e4f5300). With strict_checksum=True a
    packet with a bad checksum is dropped without any reply, as validating firmware does.
  * CONNECT -> session id; 2005 (ACK_UNAUTH) when a comm key is set; AUTH 1102 is checked
    against pyzk's make_commkey (commpro.c MakeKey).
  * 1503 PREPARE_BUFFER -> ACK_OK + data stat, or inline CMD_DATA for small sets.
  * 1504 READ_BUFFER -> PREPARE_DATA(size) + CMD_DATA(chunk) + ACK_OK with the same reply id;
    over UDP the chunk is split into CMD_DATA datagrams of at most 1024 bytes.
"""
import socket
import socketserver
import struct
import threading
import time
from datetime import datetime, timedelta

MAGIC = b"\x50\x50\x82\x7d"


def checksum(data):
    total = 0
    for i in range(0, len(data), 2):
        total += data[i] | ((data[i + 1] if i + 1 < len(data) else 0) << 8)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def make_commkey(key, session_id, ticks=50):  # pyzk reference (commpro.c MakeKey)
    k = 0
    for i in range(32):
        k = (k << 1 | 1) if key & (1 << i) else k << 1
    k += session_id
    k = struct.pack("I", k & 0xffffffff)
    k = struct.unpack("BBBB", k)
    k = struct.pack("BBBB", k[0] ^ ord("Z"), k[1] ^ ord("K"), k[2] ^ ord("S"), k[3] ^ ord("O"))
    k = struct.unpack("HH", k)
    k = struct.pack("HH", k[1], k[0])
    b = 0xff & ticks
    k = struct.unpack("BBBB", k)
    return struct.pack("BBBB", k[0] ^ b, k[1] ^ b, b, k[3] ^ b)


def raw(value):
    return value if isinstance(value, bytes) else value.encode()


def encode_time(t):
    return ((((((t.year - 2000) * 12 + t.month - 1) * 31 + t.day - 1) * 24 + t.hour) * 60 + t.minute) * 60 + t.second).to_bytes(4, "little")


class Device:
    """`records` rows are (uid, user_id_str, verify, datetime|4 raw bytes, state)."""

    def __init__(self, serial="CDQ9201760123", comm_key=0, users=None, records=None,
                 record_format=40, user_format=72, strict_checksum=True, inline_threshold=None,
                 throughput=None, fragment=False, after_sizes=None, reset_after_bytes=None,
                 free_sizes_len=92, reported=None, serial_reply=None, follow_session=None,
                 drop_udp_data_once=False, drop_udp_reply_once=False, udp_reply_override=None,
                 drop_udp_prepare_once=False, drop_udp_prepare_over=0):
        self.serial, self.comm_key = serial, comm_key
        self.users = users if users is not None else []        # [(uid, user_id_str)]
        self.records = records if records is not None else []
        self.record_format, self.user_format = record_format, user_format
        self.strict_checksum, self.inline_threshold = strict_checksum, inline_threshold
        self.throughput, self.fragment = throughput, fragment
        self.after_sizes, self.reset_after_bytes = after_sizes, reset_after_bytes
        self.free_sizes_len = free_sizes_len
        self.reported = reported            # (users, records) to report instead of the real counts
        self.serial_reply = serial_reply    # raw CMD 11 reply body, to test odd firmware
        self.follow_session = follow_session  # session id stamped on follow-on 1501/2000 frames
        self.drop_udp_data_once = drop_udp_data_once    # UDP: lose one CMD_DATA datagram of a chunk, once
        self.drop_udp_reply_once = drop_udp_reply_once  # UDP: lose the whole reply to a READ_BUFFER; an int loses that many replies
        self.drop_udp_prepare_once = drop_udp_prepare_once  # UDP: lose only the PREPARE_DATA of a READ_BUFFER reply, once
        self.udp_reply_override = udp_reply_override    # UDP: reply id stamped on data/ACK datagrams instead of the echo
        self.drop_udp_prepare_over = drop_udp_prepare_over  # ...only for a chunk longer than this many bytes
        self.bad_checksums = 0
        self.commands = []
        self.lock = threading.Lock()

    def user_bytes(self):
        out = bytearray()
        for uid, user_id in self.users:
            if self.user_format == 72:
                out += struct.pack("<HB8s24sIx7sx24s", uid, 0, b"", b"U" + raw(user_id), 0, b"1", raw(user_id))
            else:
                out += struct.pack("<HB5s8sIxBhI", uid, 0, b"", b"name", 0, 1, 0, int(user_id))
        return struct.pack("<I", len(out)) + bytes(out)

    def attendance_bytes(self):
        out = bytearray()
        for uid, user_id, verify, when, state in self.records:
            stamp = when if isinstance(when, bytes) else encode_time(when)
            if self.record_format == 40:
                out += struct.pack("<H24sB4sB8s", uid, raw(user_id), verify, stamp, state, b"\x00\x00\x00\x00\xff\x00\x00\x00")
            elif self.record_format == 16:
                out += struct.pack("<I4sBB2sI", int(user_id), stamp, verify, state, b"", 0)
            else:
                out += struct.pack("<HB4sB", uid, verify, stamp, state)
        return struct.pack("<I", len(out)) + bytes(out)

    def free_sizes(self):
        users, records = self.reported or (len(self.users), len(self.records))
        f = [0] * 20
        f[4], f[6], f[8] = users, users, records
        f[14], f[15], f[16] = 3000, 10000, 100000
        data = struct.pack("<20i", *f) + struct.pack("<3i", 0, 0, 0)
        return data[: self.free_sizes_len]


class Core:
    """Protocol state of one client connection; subclasses supply `write`."""

    def __init__(self, dev):
        self.dev = dev
        self.session = 0
        self.authed = False
        self.buffer = None
        self.sent = 0

    def frame(self, code, reply, data=b"", session=None):
        session = self.session if session is None else session
        header = struct.pack("<4H", code, 0, session, reply)
        return struct.pack("<4H", code, checksum(header + data), session, reply) + data

    def handle_packet(self, body):
        """Process one ZK packet; False means the connection should close."""
        code, chk, session, reply = struct.unpack("<4H", body[:8])
        data = body[8:]
        expect = checksum(struct.pack("<4H", code, 0, session, reply) + data)
        with self.dev.lock:
            self.dev.commands.append(code)
        if chk != expect:
            self.dev.bad_checksums += 1
            if self.dev.strict_checksum:
                return True  # Validating firmware drops a corrupt packet without replying.
        return self.dispatch(code, session, reply, data)

    def one(self, code, reply, data=b""):
        self.write([self.frame(code, reply, data)])

    def dispatch(self, code, session, reply, data):
        dev = self.dev
        if code == 1000:
            self.session = (int(time.time() * 1000) % 60000) + 1000
            self.authed = dev.comm_key == 0
            self.one(2000 if self.authed else 2005, reply)
            return True
        if session != self.session:
            self.one(2001, reply)
            return True
        if code == 1102:
            self.authed = data == make_commkey(dev.comm_key, self.session)
            self.one(2000 if self.authed else 2005, reply)
            return True
        if not self.authed:
            self.one(2005, reply)
            return True
        if code == 1001:
            self.one(2000, reply)
            return False
        if code == 11:
            name = data.split(b"\0")[0]
            if name == b"~SerialNumber":
                body = dev.serial_reply if dev.serial_reply is not None else b"~SerialNumber=" + dev.serial.encode() + b"\0"
                self.one(2000, reply, body)
            else:
                self.one(2001, reply)
            return True
        if code == 50:
            self.one(2000, reply, dev.free_sizes())
            if dev.after_sizes:
                dev.after_sizes(dev)
            return True
        if code == 1503:
            _, target, fct, _ = struct.unpack("<bhii", data[:11])
            if target == 9 and fct == 5:
                self.buffer = dev.user_bytes()
            elif target == 13:
                self.buffer = dev.attendance_bytes()
            else:
                self.one(2001, reply)
                return True
            if dev.inline_threshold is not None and len(self.buffer) <= dev.inline_threshold:
                self.write([self.frame(1501, reply, self.buffer)], bulk=True)
                self.buffer = None
            else:
                n = len(self.buffer)
                self.one(2000, reply, b"\x00" + struct.pack("<II", n, n) + b"\x00\x00\x00\x00")
            return True
        if code == 1504:
            if self.buffer is None:
                self.one(2001, reply)
                return True
            start, size = struct.unpack("<ii", data[:8])
            chunk = self.buffer[start:start + size]
            frames = [self.frame(1500, reply, struct.pack("<I", len(chunk)) + b"\x00\x10\x00\x00")]
            other = dev.follow_session
            follow = reply
            if self.udp and dev.udp_reply_override is not None:
                follow = dev.udp_reply_override  # Firmware that does not echo the request id on data datagrams.
            if self.udp:
                frames += [self.frame(1501, follow, chunk[i:i + 1024], other) for i in range(0, len(chunk), 1024)]
            else:
                frames.append(self.frame(1501, reply, chunk, other))
            frames.append(self.frame(2000, follow, b"", other))
            if self.udp and dev.drop_udp_reply_once:
                dev.drop_udp_reply_once -= 1  # True counts as one
                return True
            if self.udp and dev.drop_udp_prepare_once and len(chunk) > dev.drop_udp_prepare_over:
                dev.drop_udp_prepare_once = False
                del frames[0]  # The data datagrams and the final ACK still arrive.
            if self.udp and dev.drop_udp_data_once and len(frames) > 3:
                dev.drop_udp_data_once = False
                del frames[2]  # The second CMD_DATA datagram; the final ACK still arrives.
            self.write(frames, bulk=True)
            return True
        if code == 1502:
            self.buffer = None
            self.one(2000, reply)
            return True
        self.one(2001, reply)
        return True

    udp = False


class TcpHandler(socketserver.BaseRequestHandler):
    def setup(self):
        self.core = Core(self.server.device)
        self.core.write = self.write
        self.sent = 0

    def recv_exact(self, n):
        data = b""
        while len(data) < n:
            part = self.request.recv(n - len(data))
            if not part:
                raise EOFError
            data += part
        return data

    def write(self, frames, bulk=False):
        dev = self.server.device
        raw = b"".join(MAGIC + struct.pack("<I", len(f)) + f for f in frames)
        if dev.reset_after_bytes is not None and self.sent + len(raw) > dev.reset_after_bytes:
            self.request.sendall(raw[: max(0, dev.reset_after_bytes - self.sent)])
            self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            raise EOFError
        self.sent += len(raw)
        if bulk and (dev.throughput or dev.fragment):
            step = 1460 if dev.fragment else 16384
            for i in range(0, len(raw), step):
                self.request.sendall(raw[i:i + step])
                time.sleep(len(raw[i:i + step]) / dev.throughput if dev.throughput else 0.0005)
        else:
            self.request.sendall(raw)

    def handle(self):
        try:
            while True:
                top = self.recv_exact(8)
                if top[:4] != MAGIC:
                    return
                body = self.recv_exact(struct.unpack("<I", top[4:])[0])
                if not self.core.handle_packet(body):
                    return
        except (EOFError, ConnectionError, OSError):
            return


class UdpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        core = self.server.clients.get(self.client_address)
        if core is None:
            core = self.server.clients[self.client_address] = Core(self.server.device)
            core.udp = True
        core.write = lambda frames, bulk=False: [sock.sendto(f, self.client_address) for f in frames]
        if len(data) >= 8 and not core.handle_packet(data):
            self.server.clients.pop(self.client_address, None)


class _TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _UdpServer(socketserver.UDPServer):
    allow_reuse_address = True


class Server:
    def __init__(self, device, udp=False):
        self.device, self.udp = device, udp
        if udp:
            self.server = self.udp_only_server()
            self.server.clients = {}
        else:
            self.server = _TcpServer(("127.0.0.1", 0), TcpHandler)
        self.server.device = device

    @staticmethod
    def udp_only_server(attempts=50):
        """Bind a UDP port whose TCP twin is verifiably closed, so TCP-first clients fall back to UDP."""
        for _ in range(attempts):
            server = _UdpServer(("127.0.0.1", 0), UdpHandler)
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.settimeout(2)
            try:
                probe.connect(server.server_address)
            except ConnectionRefusedError:
                return server
            except OSError:
                pass
            finally:
                probe.close()
            server.server_close()  # Something listens on that TCP port: try another one.
        raise RuntimeError("no UDP port with a closed TCP twin")

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()

    @property
    def port(self):
        return self.server.server_address[1]


def sample(n_users=50, n_records=500, start=datetime(2026, 10, 1, 6, 0, 0)):
    users = [(i, str(1000 + i)) for i in range(1, n_users + 1)]
    records = []
    for k in range(n_records):
        uid, user_id = users[k % n_users]
        records.append((uid, user_id, 1, start + timedelta(minutes=7 * k), k % 2))
    return users, records
