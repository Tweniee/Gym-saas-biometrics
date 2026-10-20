from __future__ import annotations
import json
import os
import tempfile
import sys
from pathlib import Path


def atomic_private_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".credential-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            path.chmod(0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class CredentialStore:
    """Windows machine DPAPI + installer-restricted SYSTEM/Administrators ACL.

    Setup runs elevated and writes the same ProgramData store as LocalSystem.
    Machine DPAPI alone is NOT access control; the directory ACL is required.
    macOS uses the logged-in user’s Keychain, shared with a per-user LaunchAgent.
    Plaintext storage is confined to explicit loopback development.
    """
    def __init__(self, directory: Path, development=False, filename="installation.credential"):
        self.path = directory / filename
        self.development = development
        if os.name != "nt" and sys.platform != "darwin" and not development:
            raise RuntimeError("Production secure storage is implemented only for Windows and macOS")

    def save(self, credential):
        data = json.dumps(credential).encode()
        if os.name == "nt":
            import win32crypt
            data = win32crypt.CryptProtectData(data, "Zenvore Connector", None, None, None, 0x4)
        elif sys.platform == "darwin" and not self.development:
            from .macos_keychain import Keychain, account_for
            Keychain().save(account_for(self.path.parent, self.path.name), data)
            data = b"macOS Keychain credential reference\n"
        atomic_private_write(self.path, data)

    def load(self):
        if os.name != "nt" and sys.platform == "darwin" and not self.development:
            from .macos_keychain import Keychain, account_for
            data = Keychain().load(account_for(self.path.parent, self.path.name))
            return json.loads(data) if data is not None else None
        if not self.path.exists():
            return None
        data = self.path.read_bytes()
        if os.name == "nt":
            import win32crypt
            data = win32crypt.CryptUnprotectData(data, None, None, None, 0)[1]
        return json.loads(data)
