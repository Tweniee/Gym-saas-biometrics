"""ZK-compatible TCP attendance adapter. Physical models require acceptance testing."""
import hashlib
import json
import logging
import struct
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from .base import Adapter, AdapterError, Capabilities, FetchResult
from .zk_protocol import Protocol
from ..auth import CredentialStore

LOG = logging.getLogger("zenvore.connector")
SNAPSHOT_TTL = 120  # Seconds a device dump may serve the pages of one sync.


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
    def __init__(self, device, config, store, protocol=Protocol, cancelled=None):
        self.device, self.config, self.store, self.protocol = device, config, store, protocol
        self.cancelled = cancelled  # Polled by the transport so a shutdown interrupts a long session.
        self.snapshot = None
        self.snapshot_at = 0.0
        self.device_total = 0  # Raw records on the device, including any we could not decode.

    def read(self):
        try:
            return self._read()
        except (ValueError, KeyError, UnicodeError, struct.error, OverflowError):
            raise AdapterError("INVALID_DEVICE_DATA") from None

    def _read(self):
        secrets = CredentialStore(self.config.state_dir, self.config.development, "devices.credential").load() or {}
        key = secrets.get(self.device["ip"] + ":" + str(self.device["port"]), 0)
        options = {"cancelled": self.cancelled} if self.cancelled else {}
        transport = self.protocol(self.device["ip"], self.device["port"], key,
                                  timeout=self.config.device_timeout_seconds, transport="auto", **options)
        from ..sync import ProcessDeviceLock
        lock = ProcessDeviceLock(self.config.state_dir, "endpoint:" + self.device["ip"] + ":" + str(self.device["port"]))
        with lock, transport.connected() as session:
            identity = session.serial()
            users_count, count = session.counts()
            users = session.users(users_count)  # An actual non-destructive data read, never just an open socket.
            size, body = session.records(count)
        if size == 8 and users_count > 0 and not users:
            # 8-byte records carry only the user slot, which cannot be mapped without the user table.
            raise AdapterError("INVALID_DEVICE_DATA")
        zone = ZoneInfo(self.device["timezone"])
        total = len(body) // size if size else 0
        rows, occurrences = [], {}
        skipped = undecodable = orphans = 0
        policy = self.device.get("eventPolicy", "unknown")
        for offset in range(0, len(body), size or 1):
            record = body[offset:offset + size]
            try:
                if size == 40:
                    uid, raw_user, status, stamp, punch, _ = struct.unpack("<H24sB4sB8s", record)
                    user = raw_user.split(b"\0")[0].decode("utf-8")
                elif size == 16:
                    uid, stamp, status, punch, _, _ = struct.unpack("<I4sBB2sI", record)
                    user = str(uid)
                else:
                    uid, status, stamp, punch = struct.unpack("<HB4sB", record)
                    if uid not in users:
                        # The slot is not the enrolled ID, and guessing str(uid) would change the
                        # fingerprints of records already uploaded or collide with another member.
                        skipped += 1
                        orphans += 1
                        continue
                    user = users[uid]
                if not user or len(user) > 100:
                    raise AdapterError("INVALID_DEVICE_DATA")
                timestamp = local_time(stamp, zone)
            except (AdapterError, UnicodeError):
                skipped += 1
                undecodable += 1
                continue
            fingerprint = hashlib.sha256(json.dumps([user, stamp.hex(), status, punch], separators=(",", ":")).encode()).hexdigest()
            ordinal = occurrences.get(fingerprint, 0)
            occurrences[fingerprint] = ordinal + 1
            kind = "check-in" if policy == "check-in" else ({0: "check-in", 1: "check-out"}.get(punch, "unknown") if policy == "zk-in-out" else "unknown")
            rows.append({"index": fingerprint + ":" + str(ordinal), "timestamp": timestamp, "deviceUserId": user, "eventType": kind})
        if skipped:
            LOG.warning("ZK read skipped %d of %d records (%d undecodable)", skipped, total, undecodable)
        # Local only: the backend whitelists heartbeat/report fields, so nothing here goes to the cloud.
        self.store.set("zk-skipped:" + self.device["_id"], {
            "orphans": orphans, "undecodable": undecodable,
            "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")})
        if total >= 10 and undecodable * 2 > total:
            raise AdapterError("INVALID_DEVICE_DATA")  # Most records unreadable: the layout was probably mis-detected.
        if total >= 10 and orphans and not rows:
            # Every readable record names a member the user table does not know: the table and the
            # log do not belong together, and syncing nothing silently would hide that.
            raise AdapterError("INVALID_DEVICE_DATA")
        self.device_total = total
        self.snapshot = (identity, users, rows)
        self.snapshot_at = time.monotonic()
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
        fresh = self.snapshot is not None and time.monotonic() - self.snapshot_at < SNAPSHOT_TTL
        identity, _, rows = self.snapshot if fresh else self.read()
        generation = "zk-v1:" + identity[3:]
        if checkpoint and checkpoint["generation"] != generation:
            self.snapshot = None
            raise AdapterError("IDENTITY_MISMATCH")
        seen = self.store.seen(self.device["_id"], generation)
        since = datetime.fromisoformat(history_since.replace("Z", "+00:00"))
        eligible = [r for r in rows if r["index"] not in seen and datetime.fromisoformat(r["timestamp"]) >= since]
        prior_count = self.store.get("zk-count:" + self.device["_id"], 0)
        # Compare the raw device count, so records we skip never look like a shrinking log.
        self.store.set("zk-count:" + self.device["_id"], self.device_total)
        page = eligible[:min(limit, 200)]
        more = len(eligible) > len(page)
        if not more:
            self.snapshot = None  # Later pages of this sync reuse the dump; the next sync reads afresh.
        position = str(int(checkpoint["position"] if checkpoint else 0) + len(page))
        return FetchResult(generation, position, page, self.device_total < prior_count, more)
