"""Server pairing and reconnects, independent of biometric device discovery."""
from dataclasses import dataclass
import time
from .cloud import CloudError


@dataclass(frozen=True)
class ServerStatus:
    paired: bool
    setup: dict | None = None
    error: str | None = None

    @property
    def needs_pairing(self):
        return not self.paired or self.error == "CLOUD_AUTH"


class ServerConnection:
    def __init__(self, runtime):
        self.runtime = runtime
        self.last_heartbeat = None

    def check(self):
        # Read secure storage before consuming a single-use code. A locked or
        # unavailable credential store must fail without starting a new pairing.
        if not self.runtime.cloud.credentials.load():
            return ServerStatus(paired=False)
        try:
            setup = self.runtime.cloud.request("GET", "/connectors/me/setup")
            if self.last_heartbeat is None or time.monotonic() - self.last_heartbeat >= self.runtime.config.heartbeat_seconds:
                self.runtime.heartbeat_once()
                self.last_heartbeat = time.monotonic()
        except CloudError as exc:
            return ServerStatus(paired=True, error=exc.code)
        return ServerStatus(paired=True, setup=setup)

    def pair(self, code):
        status = self.check()
        if not status.needs_pairing:
            return status
        if not code.strip():
            raise ValueError("Enter the five-minute pairing code")
        self.runtime.cloud.pair(code)
        # The installation credential is already durable. If this verification
        # fails, check() reports a saved pairing rather than redeeming again.
        return self.check()
