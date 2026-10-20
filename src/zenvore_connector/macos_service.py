"""Opt-in, per-user launchd agent; shares the setup user's login Keychain."""
import os
from pathlib import Path
import plistlib
import subprocess
import sys
from .auth import atomic_private_write

LABEL = "com.zenvore.biometricconnector"


class MacService:
    def __init__(self, config_path, executable=None, home=None):
        self.config_path = Path(config_path).resolve()
        self.executable = Path(executable or sys.executable).resolve()
        self.home = Path(home) if home else Path.home()
        self.plist_path = self.home / "Library/LaunchAgents" / (LABEL + ".plist")
        self.domain = "gui/" + str(os.getuid())

    def command(self, *args, check=True):
        result = subprocess.run(["/bin/launchctl", *args], capture_output=True, timeout=15)
        if check and result.returncode:
            raise RuntimeError("Background sync could not be configured (launchd " + str(result.returncode) + ")")
        return result

    def enabled(self):
        return self.command("print", self.domain + "/" + LABEL, check=False).returncode == 0

    def enable(self):
        if not self.executable.is_file() or not any(part.endswith(".app") for part in self.executable.parts):
            raise RuntimeError("Enable background sync from the installed Mac application")
        if str(self.executable).startswith("/Volumes/"):
            raise RuntimeError("Copy the app to Applications and open it there before enabling background sync")
        payload = {
            "Label": LABEL,
            "ProgramArguments": [str(self.executable), "--config", str(self.config_path), "run"],
            "RunAtLoad": True,
            "KeepAlive": True,
            "ThrottleInterval": 30,
            "ProcessType": "Background",
            "Umask": 0o077,
            "LimitLoadToSessionType": "Aqua",
        }
        if self.enabled():
            self.command("bootout", self.domain + "/" + LABEL)
        atomic_private_write(self.plist_path, plistlib.dumps(payload))
        self.command("bootstrap", self.domain, str(self.plist_path))
        return "Background sync enabled. It continues after closing setup and starts when you log in."

    def disable(self):
        if self.enabled():
            self.command("bootout", self.domain + "/" + LABEL)
        self.plist_path.unlink(missing_ok=True)
        return "Background sync disabled. Pairing and recovery data are retained."
