"""ZK-compatible TCP attendance adapter. Physical models require acceptance testing."""
import hashlib
import json
import struct
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from .base import Adapter, AdapterError, Capabilities, FetchResult
from .zk_protocol import Protocol
from ..auth import CredentialStore


def local_time(encoded, zone):
    value = int.from_bytes(encoded, "little")
    second, value = value % 60, value // 60
    minute, value = value % 60, value // 60
    hour, value = value % 24, value // 24
    day, value = value % 31 + 1, value // 31
    month, year = value % 12 + 1, value // 12 + 2000
    try:
        naive = datetime(year, month, day, hour, minute, second)
        first, second_fold = naive.replace(tzinfo=zone, fold=0), naive.replace(tzinfo=zone, fold=1)
        # Reject both nonexistent and ambiguous wall times; never silently guess a DST fold.
        if first.utcoffset() != second_fold.utcoffset() or first.astimezone(timezone.utc).astimezone(zone).replace(tzinfo=None) != naive:
            raise ValueError()
        return first.isoformat()
    except (ValueError, OverflowError):
        raise AdapterError("INVALID_DEVICE_DATA") from None


class ZKTcp(Adapter):
    def __init__(self, device, config, store, protocol=Protocol):
        self.device, self.config, self.store, self.protocol = device, config, store, protocol
        self.snapshot = None

    def read(self):
        try:
            return self._read()
        except (ValueError, KeyError, UnicodeError, struct.error, OverflowError):
            raise AdapterError("INVALID_DEVICE_DATA") from None

    def _read(self):
        secrets = CredentialStore(self.config.state_dir, self.config.development, "devices.credential").load() or {}
        key = secrets.get(self.device["ip"] + ":" + str(self.device["port"]), 0)
        transport = self.protocol(self.device["ip"], self.device["port"], key, timeout=15)
        from ..sync import ProcessDeviceLock
        lock = ProcessDeviceLock(self.config.state_dir, "endpoint:" + self.device["ip"] + ":" + str(self.device["port"]))
        with lock, transport.connected() as session:
            identity = session.serial()
            users_count, count = session.counts()
            users = session.users(users_count)  # An actual non-destructive data read, never just an open socket.
            body = session.body(session.read_buffer(13)) if count else b""
        if count and (len(body) % count or len(body) // count not in (8, 16, 40)):
            raise AdapterError("UNSUPPORTED")
        zone = ZoneInfo(self.device["timezone"])
        size = len(body) // count if count else 0
        rows, occurrences = [], {}
        for offset in range(0, len(body), size or 1):
            record = body[offset:offset + size]
            if size == 40:
                uid, raw_user, status, stamp, punch, _ = struct.unpack("<H24sB4sB8s", record)
                user = raw_user.split(b"\0")[0].decode("utf-8")
            elif size == 16:
                uid, stamp, status, punch, _, _ = struct.unpack("<I4sBB2sI", record)
                user = str(uid)
            else:
                uid, status, stamp, punch = struct.unpack("<HB4sB", record)
                if uid not in users:  # UID is not necessarily the enrolled user ID.
                    raise AdapterError("INVALID_DEVICE_DATA")
                user = users[uid]
            if not user or len(user) > 100:
                raise AdapterError("INVALID_DEVICE_DATA")
            timestamp = local_time(stamp, zone)
            fingerprint = hashlib.sha256(json.dumps([user, stamp.hex(), status, punch], separators=(",", ":")).encode()).hexdigest()
            ordinal = occurrences.get(fingerprint, 0)
            occurrences[fingerprint] = ordinal + 1
            policy = self.device.get("eventPolicy", "unknown")
            kind = "check-in" if policy == "check-in" else ({0: "check-in", 1: "check-out"}.get(punch, "unknown") if policy == "zk-in-out" else "unknown")
            rows.append({"index": fingerprint + ":" + str(ordinal), "timestamp": timestamp, "deviceUserId": user, "eventType": kind})
        self.snapshot = (identity, users, rows)
        return self.snapshot

    def identity(self):
        return self.read()[0]

    def health(self):
        return self.identity()

    def capabilities(self):
        return Capabilities(attendance=self.snapshot is not None)

    def lookup_user(self, device_user_id):
        users = self.snapshot[1] if self.snapshot else self.read()[1]
        return {"deviceUserId": device_user_id} if device_user_id in users.values() else None

    def fetch(self, checkpoint, history_since, limit=200):
        identity, _, rows = self.snapshot if self.snapshot is not None else self.read()
        self.snapshot = None
        generation = "zk-v1:" + identity[3:]
        if checkpoint and checkpoint["generation"] != generation:
            raise AdapterError("IDENTITY_MISMATCH")
        seen = self.store.seen(self.device["_id"], generation)
        since = datetime.fromisoformat(history_since.replace("Z", "+00:00"))
        eligible = [r for r in rows if r["index"] not in seen and datetime.fromisoformat(r["timestamp"]) >= since]
        prior_count = self.store.get("zk-count:" + self.device["_id"], 0)
        self.store.set("zk-count:" + self.device["_id"], len(rows))
        page = eligible[:min(limit, 200)]
        position = str(int(checkpoint["position"] if checkpoint else 0) + len(page))
        return FetchResult(generation, position, page, len(rows) < prior_count, len(eligible) > len(page))
