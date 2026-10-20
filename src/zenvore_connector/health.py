import sqlite3
import threading


class Health:
    def __init__(self, store=None):
        self.lock = threading.RLock()
        self.store = store
        self.values = store.get("health", {}) if store else {}
        self.values["operation"] = "idle"

    def persist(self):
        if self.store:
            try:
                self.store.set("health", self.values)
            except (sqlite3.Error, OSError):
                # Health reporting must survive a full disk; durable sync still
                # fails rather than acknowledging work that was not persisted.
                self.values["errorCode"] = "STORAGE_ERROR"

    def update(self, **values):
        with self.lock:
            self.values.update(values)
            self.persist()

    def snapshot(self):
        with self.lock:
            return dict(self.values)

    def clear_error(self):
        with self.lock:
            if self.values.get("errorCode") != "DATA_GAP":
                self.values.pop("errorCode", None)
                self.persist()
