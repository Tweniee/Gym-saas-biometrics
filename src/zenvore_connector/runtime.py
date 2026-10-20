from __future__ import annotations
import logging
import sqlite3
import threading
import time
from . import __version__
from .adapters import AdapterError, adapter_for
from .cloud import CloudError
from .discovery import simulator_candidates, ethernet_candidates, interfaces
from .health import Health
from .storage import QueueFull
from .sync import DeviceLocks, Sync, utc_now

LOG = logging.getLogger("zenvore.connector")


def error_code(exc):
    if isinstance(exc, (CloudError, AdapterError, QueueFull)):
        return exc.code
    if isinstance(exc, (sqlite3.Error, OSError)):
        return "STORAGE_ERROR"
    return "INTERNAL_ERROR"


class Runtime:
    def __init__(self, config, store, cloud):
        self.config, self.store, self.cloud = config, store, cloud
        self.health = Health(store)
        self.locks = DeviceLocks(config.state_dir)
        self.stop = threading.Event()
        self.sync = Sync(store, cloud, self.locks, self.health, self.stop.is_set)
        self.threads = []
        self.network_signature = None
        self.last_discovery = 0

    def failure(self, exc):
        code = error_code(exc)
        self.health.update(errorCode=code)
        # Never log exception text, HTTP bodies, user IDs or credentials.
        LOG.warning("operation_failed code=%s", code)

    def handshake(self, device):
        adapter = adapter_for(device, self.config, self.store)
        expected = device.get("identity") or self.store.get("identity:" + device["_id"])
        rediscovered = False
        try:
            identity = adapter.health()
        except AdapterError as exc:
            if exc.code != "DEVICE_UNREACHABLE" or not expected:
                raise
            if device.get("adapter") == "simulator":
                candidates = simulator_candidates(self.config, self.store)
            else:
                candidates = self.discover() if time.monotonic() - self.last_discovery >= 60 else self.store.get("discovered", [])
            matches = [c for c in candidates if c["identity"] == expected]
            if len(matches) != 1:
                raise
            device.update(ip=matches[0]["ip"], port=matches[0]["port"])
            adapter = adapter_for(device, self.config, self.store)
            identity = adapter.health()
            rediscovered = True
        if expected and expected != identity:
            raise AdapterError("IDENTITY_MISMATCH")
        capabilities = adapter.capabilities()
        self.cloud.request("PUT", "/connectors/me/devices/" + device["_id"] + "/report", {
            "reachable": True, "identity": identity, "attendance": capabilities.attendance,
            "access": capabilities.access, "expiry": capabilities.expiry,
            **({"ip": device["ip"], "port": device["port"]} if rediscovered else {})})
        self.store.set("identity:" + device["_id"], identity)
        self.health.update(lastDeviceCommunication=utc_now())
        return adapter

    def unreachable(self, device, exc):
        if not isinstance(exc, AdapterError):
            return
        try:
            self.cloud.request("PUT", "/connectors/me/devices/" + device["_id"] + "/report", {
                "reachable": False, "attendance": False, "access": False, "expiry": False, "errorCode": exc.code})
        except CloudError:
            pass

    def desired(self, device):
        after = ""
        while not self.stop.is_set():
            page = self.cloud.request("GET", "/connectors/me/devices/" + device["_id"] + "/access-state" + ("?after=" + after if after else ""))
            yield from page["states"]
            after = page.get("next")
            if not after:
                break

    def apply(self, device, adapter, state):
        if not adapter.capabilities().access:
            raise AdapterError("UNSUPPORTED")
        observed = adapter.read_access(state["deviceUserId"])
        if observed and observed["version"] > state["version"]:
            return False
        expected = {"version": state["version"], "enabled": state["enabled"], "expiresAt": state.get("expiresAt")}
        if observed == expected and state.get("confirmedVersion") == state["version"]:
            return True
        if observed != expected:
            # Read back before retrying a write whose acknowledgement was lost.
            adapter.set_access(state["deviceUserId"], state["enabled"], state.get("expiresAt"), state["version"])
            if adapter.read_access(state["deviceUserId"]) != expected:
                raise AdapterError("INVALID_DEVICE_DATA")
        payload = {"memberId": state["memberId"], "version": state["version"], "enabled": state["enabled"]}
        if state.get("expiresAt"):
            payload["expiresAt"] = state["expiresAt"]
        self.cloud.request("POST", "/connectors/me/devices/" + device["_id"] + "/access-observed", payload)
        return True

    def scheduled_once(self):
        # A cloud-authenticated assignment fetch gates device work: no offline management.
        devices = self.cloud.request("GET", "/connectors/me/devices")
        signature = tuple(sorted((i["name"], i["address"]) for i in interfaces() if i["selectedByDefault"]))
        if signature != self.network_signature or (not devices and time.monotonic() - self.last_discovery >= 60):
            self.network_signature = signature
            self.store.set("discovered", self.discover())
        for device in devices:
            if self.stop.is_set():
                break
            lock = self.locks.for_device(device["_id"])
            if not lock.acquire(blocking=False):
                continue
            try:
                adapter = self.handshake(device)
                access_failed = False
                if adapter.capabilities().access:
                    for state in self.desired(device):
                        if self.stop.is_set():
                            break
                        try:
                            self.apply(device, adapter, state)
                        except AdapterError as exc:
                            access_failed = True
                            self.failure(exc)
                        except CloudError as exc:
                            if exc.status == 429:
                                access_failed = True
                                self.failure(exc)
                                break
                            if exc.status != 409:
                                raise
                self.sync.run(device, adapter)
                if not access_failed and self.health.snapshot().get("errorCode") != "DATA_GAP":
                    self.health.clear_error()
            except Exception as exc:
                self.unreachable(device, exc)
                self.failure(exc)
            finally:
                lock.release()

    def discover(self, selected=None):
        self.last_discovery = time.monotonic()
        if self.config.development and self.config.simulator_file:
            candidates = simulator_candidates(self.config, self.store)
        elif self.config.development:
            candidates = []
        else:
            candidates = ethernet_candidates(self.config, self.store, selected)
        self.store.set("discovered", candidates)
        return candidates

    def execute(self, command):
        if command["type"] == "DISCOVER_DEVICES":
            return {"status": "succeeded", "candidates": self.discover()}
        devices = self.cloud.request("GET", "/connectors/me/devices")
        device = next((device for device in devices if device["_id"] == command["deviceId"]), None)
        if not device:
            raise AdapterError("UNSUPPORTED")
        with self.locks.for_device(device["_id"]):
            try:
                adapter = self.handshake(device)
                if command["type"] == "TEST_DEVICE_CONNECTION":
                    return {"status": "succeeded"}
                if command["type"] == "SYNC_ATTENDANCE":
                    return {"status": "succeeded", "count": self.sync.run(device, adapter)}
                if command["type"] == "SET_MEMBER_ACCESS":
                    desired = next((state for state in self.desired(device) if state["memberId"] == command["payload"]["memberId"]), None)
                    if not desired or desired["version"] != command["payload"]["version"]:
                        return {"status": "superseded"}
                    return {"status": "succeeded" if self.apply(device, adapter, desired) else "superseded"}
                raise AdapterError("UNSUPPORTED")
            except Exception as exc:
                self.unreachable(device, exc)
                raise

    def handle_command(self, command):
        route = "/connectors/me/commands/" + command["_id"]
        lease = {"leaseToken": command["leaseToken"]}
        self.cloud.request("POST", route + "/ack", lease)
        finished = threading.Event()
        def renew():
            while not finished.wait(30):
                try:
                    self.cloud.request("POST", route + "/ack", lease)
                except Exception as exc:
                    self.failure(exc)
                    break
        renewal = threading.Thread(target=renew, name="command-lease", daemon=True)
        renewal.start()
        try:
            receipt = self.store.completion(command["_id"])
            if receipt and (receipt["attempt"] == command["attempts"] or not receipt["result"].get("transient")):
                result = receipt["result"]
            else:
                try:
                    result = self.execute(command)
                except Exception as exc:
                    self.failure(exc)
                    result = {"status": "failed", "errorCode": error_code(exc), "transient": bool(getattr(exc, "transient", False))}
                    # Cloud failures do not imply a device failure. Leave the lease
                    # recoverable instead of sending a misleading device result.
                    if isinstance(exc, CloudError):
                        raise
                self.store.complete(command["_id"], {"attempt": command["attempts"], "result": result})
            self.cloud.request("POST", route + "/result", {**result, **lease})
        finally:
            finished.set()
            renewal.join(self.config.timeout_seconds + 1)

    def heartbeat_once(self):
        values = self.health.snapshot()
        payload = {"appVersion": __version__, "pendingCount": self.store.pending_count(), **values}
        self.cloud.request("POST", "/connectors/me/heartbeat", payload)
        self.store.set("lastHeartbeat", utc_now())
        self.cloud.rotate_if_due()

    def periodic(self, operation, seconds):
        failures = 0
        while not self.stop.is_set():
            try:
                operation()
                failures = 0
            except Exception as exc:
                self.failure(exc)
                failures += 1
            delay = min(seconds, 2 ** min(failures, 6)) if failures else seconds
            self.stop.wait(delay)

    def command_loop(self):
        failures = 0
        while not self.stop.is_set():
            try:
                commands = self.cloud.request("GET", "/connectors/me/commands?waitSeconds=15", timeout=25)
                for command in commands:
                    if not self.stop.is_set():
                        self.handle_command(command)
                failures = 0
            except Exception as exc:
                self.failure(exc)
                failures += 1
                self.stop.wait(min(60, 2 ** min(failures, 6)))

    def start(self):
        for target, args, name in [(self.periodic, (self.heartbeat_once, self.config.heartbeat_seconds), "heartbeat"),
                                   (self.periodic, (self.scheduled_once, self.config.sync_seconds), "attendance"),
                                   (self.command_loop, (), "commands")]:
            thread = threading.Thread(target=target, args=args, name=name, daemon=True)
            self.threads.append(thread)
            thread.start()

    def shutdown(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(30)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("Worker did not stop within its I/O bound")
