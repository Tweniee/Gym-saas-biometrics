"""Read-only ZK TCP transport, adapted from this repository's Identix client.

No third-party SDK is bundled. Only CONNECT/AUTH, option reads, size reads,
user/attendance transfer, transfer cleanup and EXIT are permitted.
"""
import socket
import struct
import time
from contextlib import contextmanager
from .base import AdapterError

MAGIC = b"\x50\x50\x82\x7d"
MAX_BYTES = 8 * 1024 * 1024


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


class Protocol:
    def __init__(self, ip, port=4370, password=0, timeout=15):
        self.ip, self.port, self.password = ip, int(port), int(password)
        if not 0 <= self.password <= 0xffffffff:
            raise ValueError("Communication key must be an unsigned 32-bit integer")
        self.timeout = timeout
        self.sock = None
        self.session, self.reply = 0, 65534

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise AdapterError("DEVICE_UNREACHABLE", True)
        return min(self.timeout, remaining)

    def exact(self, count):
        result = bytearray()
        while len(result) < count:
            self.sock.settimeout(self.remaining())
            chunk = self.sock.recv(count - len(result))
            if not chunk:
                raise AdapterError("DEVICE_UNREACHABLE", True)
            result.extend(chunk)
        return bytes(result)

    def packet(self):
        header = self.exact(8)
        size = struct.unpack("<I", header[4:])[0]
        if header[:4] != MAGIC or not 8 <= size <= MAX_BYTES:
            raise AdapterError("UNSUPPORTED")
        body = self.exact(size)
        command, _, session, reply = struct.unpack("<4H", body[:8])
        if self.session and session != self.session:
            raise AdapterError("INVALID_DEVICE_DATA")
        self.reply = reply
        return command, session, body[8:]

    def command(self, code, data=b""):
        if code not in {1000, 1001, 1102, 11, 50, 1502, 1503, 1504}:
            raise AdapterError("UNSUPPORTED")
        header = struct.pack("<4H", code, 0, self.session, self.reply)
        check = checksum(header + data)
        self.reply = (self.reply + 1) % 65535
        body = struct.pack("<4H", code, check, self.session, self.reply) + data
        self.sock.settimeout(self.remaining())
        self.sock.sendall(MAGIC + struct.pack("<I", len(body)) + body)
        code, session, payload = self.packet()
        if not self.session:
            self.session = session
        return code, payload

    @contextmanager
    def connected(self):
        self.deadline = time.monotonic() + self.timeout
        try:
            self.sock = socket.create_connection((self.ip, self.port), timeout=self.remaining())
            code, _ = self.command(1000)
            if code == 2005:
                code, _ = self.command(1102, comm_key(self.password, self.session))
            if code not in (2000, 2002):
                raise AdapterError("UNSUPPORTED")
            yield self
        except (socket.timeout, ConnectionError, OSError):
            raise AdapterError("DEVICE_UNREACHABLE", True) from None
        except (struct.error, UnicodeError, ValueError, IndexError):
            raise AdapterError("INVALID_DEVICE_DATA") from None
        finally:
            if self.sock:
                # Closing the transport always completes even if EXIT times out.
                try:
                    if time.monotonic() < self.deadline:
                        self.command(1001)
                except Exception:
                    pass
                self.sock.close()
                self.sock = None

    def serial(self):
        code, body = self.command(11, b"~SerialNumber\0")
        if code not in (2000, 2002):
            raise AdapterError("UNSUPPORTED")
        value = body.rstrip(b"\0").decode("ascii").split("=", 1)
        if len(value) != 2 or value[0] != "~SerialNumber":
            raise AdapterError("UNSUPPORTED")
        serial = value[1].strip()
        if not serial or len(serial) > 64 or not all(c.isalnum() or c in "-_." for c in serial):
            raise AdapterError("INVALID_DEVICE_DATA")
        return "ZK:" + serial

    def counts(self):
        code, body = self.command(50)
        if code not in (2000, 2002) or len(body) < 36:
            raise AdapterError("UNSUPPORTED")
        values = struct.unpack("<9i", body[:36])
        users, records = values[4], values[8]
        if not 0 <= users <= 10000 or not 0 <= records <= 50000:
            raise AdapterError("INVALID_DEVICE_DATA")
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
            size = min(0xffc0, total - len(out))
            code, body = self.command(1504, struct.pack("<ii", len(out), size))
            if code == 1500:
                if len(body) < 4 or struct.unpack("<I", body[:4])[0] != size:
                    raise AdapterError("INVALID_DEVICE_DATA")
                body = bytearray()
                while len(body) < size:
                    code, _, part = self.packet()
                    if code != 1501 or not part or len(body) + len(part) > size:
                        raise AdapterError("INVALID_DEVICE_DATA")
                    body.extend(part)
                ack, _, _ = self.packet()
                if ack != 2000:
                    raise AdapterError("INVALID_DEVICE_DATA")
            elif code != 1501:
                raise AdapterError("INVALID_DEVICE_DATA")
            if len(body) != size:
                raise AdapterError("INVALID_DEVICE_DATA")
            out.extend(body)
        self.command(1502)
        return bytes(out)

    def users(self, count):
        if count == 0:
            return {}
        data = self.read_buffer(9, 5)
        body = self.body(data)
        if len(body) % count or len(body) // count not in (28, 72):
            raise AdapterError("UNSUPPORTED")
        size = len(body) // count
        users = {}
        for offset in range(0, len(body), size):
            uid = struct.unpack_from("<H", body, offset)[0]
            user = (body[offset + 48:offset + 72].split(b"\0")[0].decode("utf-8")
                    if size == 72 else str(struct.unpack_from("<I", body, offset + 24)[0]))
            if not user:
                raise AdapterError("INVALID_DEVICE_DATA")
            users[uid] = user
        return users

    @staticmethod
    def body(data):
        if len(data) < 4 or struct.unpack("<I", data[:4])[0] != len(data) - 4:
            raise AdapterError("INVALID_DEVICE_DATA")
        return data[4:]
