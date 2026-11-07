"""A rejected communication key gets a specific message while the cloud-facing code stays UNSUPPORTED."""
import unittest
from unittest.mock import Mock, patch

from zenvore_connector.adapters.base import AdapterError
from zenvore_connector.runtime import error_code
from zenvore_connector.setup_ui import BUSY_NOTE, COMM_KEY_NOTE, setup_failure_note
import test_setup_ui
from test_pairing import ServerPairingFixture


class SetupNoteTests(unittest.TestCase):
    def test_comm_key_rejection_names_the_device_menu_and_the_fix(self):
        note = setup_failure_note("UNSUPPORTED", "COMM_KEY_REJECTED")
        self.assertEqual(note, COMM_KEY_NOTE)
        self.assertIn("rejected the communication key", note)
        self.assertIn("COMM → Comm Key / Communication Password", note)
        self.assertNotIn("UNSUPPORTED", note)

    def test_other_failures_keep_the_generic_note_with_the_code(self):
        for reason in (None, "SOMETHING_ELSE"):
            note = setup_failure_note("UNSUPPORTED", reason)
            self.assertTrue(note.startswith("Setup did not complete (UNSUPPORTED)."))

    def test_busy_device_has_its_own_note_and_keeps_the_cloud_code(self):
        note = setup_failure_note("DEVICE_UNREACHABLE", "DEVICE_BUSY")
        self.assertEqual(note, BUSY_NOTE)
        self.assertEqual(note, "Background sync is reading the device right now. "
                               "Wait a minute and press Verify and connect again.")
        self.assertEqual(error_code(AdapterError("DEVICE_UNREACHABLE", True, reason="DEVICE_BUSY")), "DEVICE_UNREACHABLE")

    def test_process_lock_timeout_carries_the_busy_reason(self):
        import tempfile
        from zenvore_connector.sync import ProcessDeviceLock
        with tempfile.TemporaryDirectory() as directory:
            first, second = ProcessDeviceLock(directory, "x"), ProcessDeviceLock(directory, "x")
            second.WAIT = .1
            with first:
                with self.assertRaises(AdapterError) as error:
                    with second:
                        pass
        self.assertEqual((error.exception.code, error.exception.transient, error.exception.reason),
                         ("DEVICE_UNREACHABLE", True, "DEVICE_BUSY"))

    def test_the_cloud_facing_code_is_unchanged_by_the_reason(self):
        self.assertEqual(error_code(AdapterError("UNSUPPORTED", reason="COMM_KEY_REJECTED")), "UNSUPPORTED")


class SetupWindowTests(ServerPairingFixture, unittest.TestCase):
    def test_wizard_shows_the_specific_message_and_records_the_reason_for_support(self):
        def drive(variables, entries, buttons, scheduled):
            entries[0].insert(0, "short-lived-code")
            buttons["Pair app"].options["command"]()
            scheduled[200]()
            entries[1].insert(0, "192.168.1.50")
            adapter = Mock()
            adapter.health.side_effect = AdapterError("UNSUPPORTED", reason="COMM_KEY_REJECTED")
            with patch("zenvore_connector.setup_ui.adapter_for", return_value=adapter):
                buttons["Verify and connect"].options["command"]()
                scheduled[200]()
            self.assertEqual(variables[3].get(), COMM_KEY_NOTE)
        test_setup_ui.PairButtonTests.exercise(self, drive)

    def test_wizard_shows_the_busy_message_when_background_sync_holds_the_device(self):
        def drive(variables, entries, buttons, scheduled):
            entries[0].insert(0, "short-lived-code")
            buttons["Pair app"].options["command"]()
            scheduled[200]()
            entries[1].insert(0, "192.168.1.50")
            adapter = Mock()
            adapter.health.side_effect = AdapterError("DEVICE_UNREACHABLE", True, reason="DEVICE_BUSY")
            with patch("zenvore_connector.setup_ui.adapter_for", return_value=adapter):
                buttons["Verify and connect"].options["command"]()
                scheduled[200]()
            self.assertEqual(variables[3].get(), BUSY_NOTE)
        test_setup_ui.PairButtonTests.exercise(self, drive)


if __name__ == "__main__":
    unittest.main()
