from __future__ import annotations
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


def default_home() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "Zenvore" / "BiometricConnector"
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/Zenvore/BiometricConnector"
    return Path.home() / ".zenvore-connector"


@dataclass(frozen=True)
class Config:
    api_url: str
    state_dir: Path
    development: bool = False
    simulator_file: Path | None = None
    heartbeat_seconds: int = 60
    sync_seconds: int = 60
    timeout_seconds: int = 15

    def __post_init__(self):
        url = urlsplit(self.api_url)
        local = url.hostname in {"localhost", "127.0.0.1", "::1"}
        if url.username or url.password or url.query or url.fragment or not url.hostname:
            raise ValueError("Invalid API URL")
        if url.scheme != "https" and not (self.development and local and url.scheme == "http"):
            raise ValueError("HTTPS is required; HTTP is allowed only on explicit development loopback")
        if self.development and not local:
            raise ValueError("Development credentials may only be used with a loopback API")
        if self.simulator_file and not self.development:
            raise ValueError("The simulator requires explicit development mode")
        if not (5 <= self.heartbeat_seconds <= 300 and 5 <= self.sync_seconds <= 300 and 1 <= self.timeout_seconds <= 30):
            raise ValueError("Intervals or timeout outside permitted bounds")

    @classmethod
    def load(cls, file: Path) -> "Config":
        data = json.loads(file.read_text(encoding="utf-8"))
        return cls(api_url=data["api_url"].rstrip("/"), state_dir=Path(data.get("state_dir", file.parent)).expanduser().resolve(),
                   development=data.get("development", False),
                   simulator_file=Path(data["simulator_file"]).expanduser().resolve() if data.get("simulator_file") else None,
                   heartbeat_seconds=data.get("heartbeat_seconds", 60), sync_seconds=data.get("sync_seconds", 60),
                   timeout_seconds=data.get("timeout_seconds", 15))
