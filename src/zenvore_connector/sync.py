from __future__ import annotations
import hashlib
import json
import threading
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from .adapters import AdapterError


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize(device, generation, record):
    """Simulator uses an immutable index within an explicit device generation.

    Timestamps must have an offset. A future real adapter with naive local time
    must define a DST fold/drift policy before producing normalized events.
    """
    try:
        raw = record["timestamp"]
        date = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        ZoneInfo(device["timezone"])
        if date.tzinfo is None:
            raise ValueError()
        native = str(record["index"])
        user = str(record["deviceUserId"])
        event_type = record.get("eventType", "unknown")
        if event_type not in {"check-in", "check-out", "access-granted", "access-denied", "unknown"}:
            raise ValueError()
        if not user or len(user) > 100 or len(native) > 100 or len(generation) > 100:
            raise ValueError()
        identity = json.dumps([device["_id"], generation, native], separators=(",", ":"), ensure_ascii=False)
        return {"eventId": hashlib.sha256(identity.encode()).hexdigest(), "nativeId": native, "deviceUserId": user,
                "occurredAt": date.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                "rawTimestamp": raw, "timezone": device["timezone"], "eventType": event_type}
    except (ValueError, KeyError, TypeError):
        raise AdapterError("INVALID_DEVICE_DATA") from None


class DeviceLocks:
    def __init__(self, directory=None):
        self.directory = directory
        self.guard = threading.Lock()
        self.locks = {}

    def for_device(self, device):
        with self.guard:
            if device not in self.locks:
                self.locks[device] = ProcessDeviceLock(self.directory, device) if self.directory else threading.RLock()
            return self.locks[device]


class Sync:
    def __init__(self, store, cloud, locks, health, cancelled=lambda: False):
        self.store, self.cloud, self.locks, self.health = store, cloud, locks, health
        self.cancelled = cancelled

    def upload(self, device, batch):
        response = self.cloud.request("POST", "/connectors/me/attendance/batches", batch)
        self.store.acknowledge(device["_id"], batch, response)
        self.health.update(lastAcknowledgedUpload=utc_now())

    def run(self, device, adapter):
        with self.locks.for_device(device["_id"]):
            self.health.update(operation="sync")
            count = 0
            try:
                # Retry pending bytes before reading the device again.
                pending = self.store.pending(device["_id"])
                if pending:
                    self.upload(device, pending)
                # A bounded operation yields to manual commands and other devices.
                for _ in range(10):
                    if self.cancelled():
                        break
                    checkpoint = self.store.checkpoint(device["_id"])
                    page = adapter.fetch(checkpoint, device["historySince"], 200)
                    self.health.update(lastDeviceCommunication=utc_now(), lastAttendanceFetch=utc_now())
                    batch = {"deviceId": device["_id"], "generation": page.generation, "position": page.position,
                             "dataGap": page.data_gap, "events": [normalize(device, page.generation, row) for row in page.records]}
                    self.store.stage(device["_id"], batch)
                    self.upload(device, batch)
                    count += len(batch["events"])
                    if page.data_gap:
                        self.health.update(errorCode="DATA_GAP")
                    if not page.more:
                        break
                return count
            finally:
                self.health.update(operation="idle")

class ProcessDeviceLock:
    """Coordinate the elevated setup app and LocalSystem service on Windows."""
    def __init__(self, directory, name):
        from pathlib import Path
        self.path = Path(directory) / ("device-" + hashlib.sha256(name.encode()).hexdigest()[:32] + ".lock")
        self.local = threading.RLock()
        self.state = threading.local()

    def acquire(self, blocking=True):
        import os
        import time
        if not self.local.acquire(blocking=blocking):
            return False
        depth = getattr(self.state, "depth", 0)
        if depth:
            self.state.depth = depth + 1
            return True
        try:
            handle = self.path.open("a+b")
        except BaseException:
            self.local.release()
            raise
        deadline = time.monotonic() + (5 if blocking else 0)
        try:
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt
                        if self.path.stat().st_size == 0:
                            handle.write(b"0"); handle.flush()
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.state.handle, self.state.depth = handle, 1
                    return True
                except OSError:
                    if time.monotonic() >= deadline:
                        handle.close()
                        self.local.release()
                        return False
                    time.sleep(.05)
        except BaseException:
            handle.close()
            self.local.release()
            raise

    def release(self):
        self.state.depth -= 1
        if not self.state.depth:
            self.state.handle.close()
            del self.state.handle
        self.local.release()

    def __enter__(self):
        if not self.acquire():
            raise AdapterError("DEVICE_UNREACHABLE", True)
        return self

    def __exit__(self, *_):
        self.release()
