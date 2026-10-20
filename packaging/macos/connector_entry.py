"""Finder launches setup; launchd and terminal invocations use the regular CLI."""
import json
from pathlib import Path
import sys
from zenvore_connector.auth import atomic_private_write
from zenvore_connector.config import Config, default_home
from zenvore_connector.main import main


def entry():
    if sys.argv[1:] == ["--self-test"]:
        import _tkinter
        import psutil
        import sqlite3
        from zoneinfo import ZoneInfo
        from zenvore_connector.macos_keychain import Keychain
        Keychain()  # Resolve framework symbols, without reading or writing any Keychain item.
        ZoneInfo("Asia/Kolkata")
        print(json.dumps({"platform": sys.platform, "tk": _tkinter.TK_VERSION, "sqlite": sqlite3.sqlite_version}))
        return 0
    if len(sys.argv) > 1:
        return main()
    config_path = default_home() / "config.json"
    if not config_path.exists():
        defaults = json.loads((Path(__file__).parent / "defaults.json").read_text())
        Config(defaults["api_url"], config_path.parent)
        atomic_private_write(config_path, json.dumps(defaults).encode())
    return main(["--config", str(config_path), "setup"])


if __name__ == "__main__":
    raise SystemExit(entry())
