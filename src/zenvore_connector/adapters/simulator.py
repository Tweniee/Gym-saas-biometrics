from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime
from .base import Adapter, AdapterError, Capabilities, FetchResult


def timestamp(value):
    date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if date.tzinfo is None:
        raise AdapterError("INVALID_DEVICE_DATA")
    return date


class Simulator(Adapter):
    """File-backed development device; no physical hardware compatibility."""
    def __init__(self, device, fixture: Path, store):
        self.device, self.fixture, self.store = device, fixture, store

    def data(self):
        if self.device.get("ip") != "127.0.0.1":
            raise AdapterError("UNSUPPORTED")
        try:
            if self.fixture.stat().st_size > 2 * 1024 * 1024:
                raise AdapterError("INVALID_DEVICE_DATA")
            content = json.loads(self.fixture.read_text(encoding="utf-8"))
            value = content["devices"][str(self.device["port"])]
            if not value.get("reachable", True):
                raise AdapterError("DEVICE_UNREACHABLE", True)
            if not isinstance(value["identity"], str) or not value["identity"].startswith("SIM-"):
                raise AdapterError("INVALID_DEVICE_DATA")
            if not isinstance(value["generation"], str) or not value["generation"]:
                raise AdapterError("INVALID_DEVICE_DATA")
            return value
        except (OSError, KeyError):
            raise AdapterError("DEVICE_UNREACHABLE", True) from None
        except (ValueError, TypeError):
            raise AdapterError("INVALID_DEVICE_DATA") from None

    def identity(self):
        return self.data()["identity"]

    def capabilities(self):
        data = self.data()
        access = bool(data.get("access", True))
        return Capabilities(attendance=True, access=access, expiry=access and bool(data.get("expiry", True)))

    def fetch(self, checkpoint, history_since, limit=200):
        data = self.data()
        records = data.get("events", [])
        try:
            positions = [int(row["index"]) for row in records]
            if positions != sorted(set(positions)) or any(pos < 1 for pos in positions):
                raise AdapterError("INVALID_DEVICE_DATA")
            same_generation = checkpoint and checkpoint["generation"] == data["generation"]
            position = int(checkpoint["position"]) if same_generation else 0
            oldest = int(data.get("oldestIndex", positions[0] if positions else 1))
            gap = (position > 0 and oldest > position + 1) or bool(checkpoint and not same_generation)
            if same_generation and positions and position > positions[-1]:
                # Record indices reused without a new generation are unsafe.
                raise AdapterError("DATA_GAP")
            since = timestamp(history_since)
            fresh = [row for row in records if int(row["index"]) > position]
            page = fresh[:min(200, max(1, limit))]
            selected = [row for row in page if timestamp(row["timestamp"]) >= since]
            next_position = str(page[-1]["index"]) if page else str(position)
            return FetchResult(data["generation"], next_position, selected, gap, len(fresh) > len(page))
        except (ValueError, KeyError, TypeError):
            raise AdapterError("INVALID_DEVICE_DATA") from None

    def lookup_user(self, device_user_id):
        return {"deviceUserId": device_user_id} if device_user_id in self.data().get("users", []) else None

    def read_access(self, device_user_id):
        if not self.capabilities().access:
            raise AdapterError("UNSUPPORTED")
        if not self.lookup_user(device_user_id):
            raise AdapterError("INVALID_DEVICE_DATA")
        return self.store.access(self.identity(), device_user_id)

    def set_access(self, device_user_id, enabled, expires_at, version):
        caps = self.capabilities()
        if not caps.access or (expires_at and not caps.expiry):
            raise AdapterError("UNSUPPORTED")
        if not self.lookup_user(device_user_id):
            raise AdapterError("INVALID_DEVICE_DATA")
        self.store.apply_access(self.identity(), device_user_id, version, enabled, expires_at)
