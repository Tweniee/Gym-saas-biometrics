from __future__ import annotations
import argparse
import getpass
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import signal
import sys
import time
from .auth import CredentialStore, atomic_private_write
from .cloud import Cloud, CloudError
from .config import Config, default_home
from .runtime import Runtime, error_code
from .storage import Store


def configure_logging(directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    handler = RotatingFileHandler(directory / "connector.log", maxBytes=1024 * 1024, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(threadName)s %(message)s"))
    logger = logging.getLogger("zenvore.connector")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return handler


class InstanceLock:
    def __init__(self, directory):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.handle = (directory / "service.lock").open("a+b")
        self.handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                if self.handle.read(1) == b"":
                    self.handle.write(b"0")
                    self.handle.flush()
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            raise RuntimeError("Another connector service is already running") from None

    def close(self):
        self.handle.close()


def build(config):
    credentials = CredentialStore(config.state_dir, config.development)
    cloud = Cloud(config, credentials)
    store = Store(config.state_dir)
    return Runtime(config, store, cloud)


def diagnostics(runtime):
    health = runtime.health.snapshot()
    return {"version": __import__('zenvore_connector').__version__, "paired": runtime.cloud.credentials.path.exists(),
            "pendingCount": runtime.store.pending_count(), "lastHeartbeat": runtime.store.get("lastHeartbeat"),
            "errorCode": health.get("errorCode"), "platform": sys.platform}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Zenvore biometric connector (simulator framework; hardware support unverified)")
    parser.add_argument("--config", type=Path, default=default_home() / "config.json")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init-dev", help="Create loopback development configuration and simulator fixture")
    init.add_argument("--api-url", default="http://127.0.0.1:3000/api/v1")
    commands.add_parser("pair", help="Prompt for single-use pairing code; never accept credentials as CLI arguments")
    commands.add_parser("setup", help="Open the pairing utility")
    run = commands.add_parser("run", help="Run the background connector")
    run.add_argument("--once", action="store_true", help="One heartbeat and scheduled cycle for development verification")
    commands.add_parser("diagnostics", help="Print allowlisted diagnostics without credentials or member details")
    commands.add_parser("interfaces", help="List LAN interfaces without scanning")
    args = parser.parse_args(argv)
    if args.command == "init-dev":
        if args.config.exists():
            parser.error("Configuration already exists")
        root = args.config.parent.resolve()
        fixture = root / "simulator.json"
        config = Config(args.api_url, root, True, fixture)
        atomic_private_write(args.config, json.dumps({"api_url": config.api_url, "state_dir": str(root),
            "development": True, "simulator_file": str(fixture)}, indent=2).encode())
        if not fixture.exists():
            atomic_private_write(fixture, json.dumps({"devices": {"4370": {"identity": "SIM-001", "generation": "generation-1",
                "reachable": True, "access": True, "expiry": True, "users": ["1001"], "events": []}}}, indent=2).encode())
        print("Development configuration created. Simulator only; no hardware connection.")
        return 0
    config = Config.load(args.config)
    handler = configure_logging(config.state_dir)
    runtime = build(config)
    lock = None
    try:
        if args.command == "pair":
            runtime.cloud.pair(getpass.getpass("Pairing code: "))
            print("Connector paired with Zenvore. Device connection and attendance have not been tested.")
        elif args.command == "setup":
            from .setup_ui import show
            show(runtime, args.config)
        elif args.command == "interfaces":
            from .discovery import interfaces
            print(json.dumps(interfaces(), indent=2))
        elif args.command == "diagnostics":
            print(json.dumps(diagnostics(runtime), indent=2))
        elif args.command == "run":
            lock = InstanceLock(config.state_dir)
            if args.once:
                runtime.heartbeat_once()
                runtime.scheduled_once()
            else:
                signal.signal(signal.SIGINT, lambda *_: runtime.stop.set())
                signal.signal(signal.SIGTERM, lambda *_: runtime.stop.set())
                runtime.start()
                runtime.stop.wait()
                runtime.shutdown()
        return 0
    except (CloudError, OSError, ValueError, RuntimeError) as exc:
        print("Connector operation failed: " + error_code(exc), file=sys.stderr)
        return 1
    finally:
        if lock:
            lock.close()
        runtime.store.close()
        logging.getLogger("zenvore.connector").removeHandler(handler)
        handler.close()


if __name__ == "__main__":
    raise SystemExit(main())
