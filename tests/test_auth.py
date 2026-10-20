"""Regression coverage for pywin32's asymmetric protect/unprotect return types."""
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
from zenvore_connector.auth import CredentialStore


class CredentialProtectionTests(unittest.TestCase):
    def test_machine_dpapi_persists_complete_ciphertext_and_round_trips(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CredentialStore(Path(directory), development=True)
            protected = b"\x01encrypted-payload\x00\xff"
            crypt = types.SimpleNamespace(
                CryptProtectData=Mock(return_value=protected),
                CryptUnprotectData=Mock(return_value=("Zenvore Connector", b'{"credential":"secret"}')),
            )
            with patch.dict(sys.modules, {"win32crypt": crypt}), patch.object(os, "name", "nt"):
                store.save({"credential": "secret"})
                self.assertEqual(store.path.read_bytes(), protected)
                self.assertEqual(store.load(), {"credential": "secret"})
            self.assertEqual(crypt.CryptProtectData.call_args.args[-1], 0x4)
            self.assertEqual(crypt.CryptUnprotectData.call_args.args[0], protected)
