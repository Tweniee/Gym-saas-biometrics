from __future__ import annotations
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path


class QueueFull(Exception):
    code = "QUEUE_FULL"
    transient = False


class Store:
    """WAL + FULL fsync. A cursor denotes cloud-committed work only."""
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            directory.chmod(0o700)
        self.path = directory / "state.sqlite3"
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False, timeout=5)
        if os.name != "nt":
            self.path.chmod(0o600)
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            PRAGMA busy_timeout=5000;
            PRAGMA max_page_count=65536;
            CREATE TABLE IF NOT EXISTS seen_events(device TEXT, generation TEXT, native TEXT, PRIMARY KEY(device,generation,native));
            CREATE TABLE IF NOT EXISTS checkpoints(device TEXT PRIMARY KEY, generation TEXT, position TEXT);
            CREATE TABLE IF NOT EXISTS pending(device TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS completions(id TEXT PRIMARY KEY, body TEXT NOT NULL, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS access_state(device TEXT, user TEXT, version INTEGER, enabled INTEGER, expiry TEXT,
                PRIMARY KEY(device,user));
        """)

    @contextmanager
    def transaction(self):
        with self.lock, self.db:
            yield self.db

    def seen(self, device, generation):
        with self.lock:
            return {r[0] for r in self.db.execute("SELECT native FROM seen_events WHERE device=? AND generation=?", (device, generation))}

    def checkpoint(self, device):
        with self.lock:
            row = self.db.execute("SELECT generation, position FROM checkpoints WHERE device=?", (device,)).fetchone()
        return {"generation": row[0], "position": row[1]} if row else None

    def pending(self, device):
        with self.lock:
            row = self.db.execute("SELECT body FROM pending WHERE device=?", (device,)).fetchone()
        return json.loads(row[0]) if row else None

    def stage(self, device, batch):
        body = json.dumps(batch, separators=(",", ":"))
        if len(body.encode()) > 1024 * 1024 or len(batch["events"]) > 200:
            raise QueueFull()
        with self.transaction() as db:
            # Never replace an unacknowledged fetch, even after a crash.
            if db.execute("SELECT 1 FROM pending WHERE device=?", (device,)).fetchone():
                raise RuntimeError("Unacknowledged batch must be uploaded first")
            total = db.execute("SELECT coalesce(sum(length(body)),0) FROM pending").fetchone()[0]
            if total + len(body) > 64 * 1024 * 1024:
                raise QueueFull()
            db.execute("INSERT INTO pending VALUES (?,?)", (device, body))

    def acknowledge(self, device, batch, response):
        expected = [event["eventId"] for event in batch["events"]]
        if (response.get("committed") is not True or response.get("position") != batch["position"]
                or response.get("generation") != batch["generation"] or response.get("acceptedEventIds") != expected):
            raise ValueError("Cloud acknowledgement does not match committed batch")
        with self.transaction() as db:
            current = db.execute("SELECT body FROM pending WHERE device=?", (device,)).fetchone()
            if not current or json.loads(current[0]) != batch:
                raise RuntimeError("Pending batch changed")
            db.execute("INSERT OR REPLACE INTO checkpoints VALUES (?,?,?)", (device, batch["generation"], batch["position"]))
            db.executemany("INSERT OR IGNORE INTO seen_events VALUES (?,?,?)", [(device, batch["generation"], e["nativeId"]) for e in batch["events"]])
            db.execute("DELETE FROM pending WHERE device=?", (device,))

    def pending_count(self):
        with self.lock:
            rows = self.db.execute("SELECT body FROM pending").fetchall()
        return sum(len(json.loads(row[0])["events"]) for row in rows)

    def get(self, key, default=None):
        with self.lock:
            row = self.db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key, value):
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (key, json.dumps(value)))

    def completion(self, command):
        with self.lock:
            row = self.db.execute("SELECT body FROM completions WHERE id=?", (command,)).fetchone()
        return json.loads(row[0]) if row else None

    def complete(self, command, result):
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO completions VALUES (?,?,?)", (command, json.dumps(result), time.time()))
            # Commands expire after 1 day; retain crash-replay receipts for 7 days.
            db.execute("DELETE FROM completions WHERE created < ?", (time.time() - 7 * 86400,))
            db.execute("DELETE FROM completions WHERE id IN (SELECT id FROM completions ORDER BY created DESC LIMIT -1 OFFSET 10000)")

    def access(self, device, user):
        with self.lock:
            row = self.db.execute("SELECT version,enabled,expiry FROM access_state WHERE device=? AND user=?", (device, user)).fetchone()
        return {"version": row[0], "enabled": bool(row[1]), "expiresAt": row[2]} if row else None

    def apply_access(self, device, user, version, enabled, expiry):
        with self.transaction() as db:
            db.execute("""INSERT INTO access_state VALUES (?,?,?,?,?) ON CONFLICT(device,user) DO UPDATE SET
                version=excluded.version,enabled=excluded.enabled,expiry=excluded.expiry WHERE excluded.version >= access_state.version""",
                       (device, user, version, enabled, expiry))

    def close(self):
        with self.lock:
            self.db.close()
