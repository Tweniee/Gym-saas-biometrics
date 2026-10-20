from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass


class AdapterError(Exception):
    def __init__(self, code, transient=False):
        super().__init__(code)
        self.code, self.transient = code, transient


@dataclass(frozen=True)
class Capabilities:
    attendance: bool = False
    access: bool = False
    expiry: bool = False


@dataclass(frozen=True)
class FetchResult:
    generation: str
    position: str
    records: list[dict]
    data_gap: bool = False
    more: bool = False


class Adapter(ABC):
    """All methods must use bounded I/O. Handshake/lookup/fetch are read-only.

    No SDK or vendor commands are inferred from a brand, open port or TCP link.
    Real adapters must declare their tested model/firmware and timestamp policy.
    """
    @abstractmethod
    def identity(self) -> str: ...

    @abstractmethod
    def capabilities(self) -> Capabilities: ...

    def health(self):
        return self.identity()

    @abstractmethod
    def fetch(self, checkpoint: dict | None, history_since: str, limit: int = 200) -> FetchResult: ...

    @abstractmethod
    def lookup_user(self, device_user_id: str) -> dict | None: ...

    def read_access(self, device_user_id: str) -> dict | None:
        raise AdapterError("UNSUPPORTED")

    def set_access(self, device_user_id: str, enabled: bool, expires_at: str | None, version: int):
        raise AdapterError("UNSUPPORTED")
