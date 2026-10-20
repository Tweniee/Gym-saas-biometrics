"""Exercise the downloaded app's Pair button without a display or real secrets."""
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from zenvore_connector.cloud import CloudError
from zenvore_connector.setup_ui import show
from test_pairing import ServerPairingFixture


class Widget:
    def __init__(self, *args, **options):
        self.options = options
        self.value = options.get("value", "")
        self.index = -1

    def __getattr__(self, name):
        return lambda *args, **kwargs: None

    def get(self):
        return self.value

    def set(self, value):
        self.value = value

    def configure(self, **options):
        self.options.update(options)

    def delete(self, *args):
        self.value = ""

    def insert(self, index, value):
        self.value = value

    def current(self, index=None):
        if index is not None:
            self.index = index
        return self.index


class PairButtonTests(ServerPairingFixture, unittest.TestCase):
    def exercise(self, drive, interface_error=True):
        import tkinter as tk
        from tkinter import ttk, font
        variables, entries, buttons, scheduled = [], [], {}, {}
        def variable(**options):
            value = Widget(**options)
            variables.append(value)
            return value
        def entry(*args, **options):
            value = Widget(*args, **options)
            entries.append(value)
            return value
        def button(*args, **options):
            value = Widget(*args, **options)
            buttons[options["text"]] = value
            return value
        window = Mock()
        window.winfo_screenheight.return_value = 1000
        window.after.side_effect = lambda delay, action: scheduled.update({delay: action})
        window.mainloop.side_effect = lambda: drive(variables, entries, buttons, scheduled)
        # Execute workers synchronously; poll() still consumes the real queue.
        def thread(*, target, **options):
            return SimpleNamespace(start=target)
        with ExitStack() as stack:
            stack.enter_context(patch.multiple(tk, Tk=lambda: window, StringVar=variable, Canvas=Widget, Text=Widget))
            stack.enter_context(patch.multiple(ttk, Frame=Widget, Scrollbar=Widget, Label=Widget,
                                              Separator=Widget, Entry=entry, Button=button, Combobox=Widget))
            stack.enter_context(patch.object(font, "nametofont", return_value=SimpleNamespace(actual=lambda _: "Helvetica")))
            stack.enter_context(patch("zenvore_connector.setup_ui.threading.Thread", side_effect=thread))
            interfaces = stack.enter_context(patch("zenvore_connector.setup_ui.interfaces"))
            interfaces.side_effect = OSError("Ethernet unavailable") if interface_error else None
            interfaces.return_value = []
            show(self.runtime)

    def test_pair_button_confirms_cloud_even_if_interface_enumeration_fails(self):
        def drive(variables, entries, buttons, scheduled):
            entries[0].insert(0, "short-lived-code")
            buttons["Pair app"].options["command"]()
            scheduled[200]()
            self.assertIn("Cloud: connected", variables[0].get())
            self.assertIn("Device: current status unavailable", variables[1].get())
            self.assertIn("Server connected", variables[3].get())
            self.assertEqual(entries[0].get(), "")
            self.assertEqual(entries[0].options["state"], "disabled")
            self.assertEqual(self.pair_count(), 1)
            buttons["Pair app"].options["command"]()
            scheduled[200]()
            self.assertEqual(self.pair_count(), 1)
        self.exercise(drive)

    def test_pair_button_preserves_saved_pairing_when_verification_is_temporarily_offline(self):
        def unavailable(method, route, *args, **kwargs):
            if route != "/connectors/pair":
                raise CloudError("CLOUD_NETWORK")
            return self.respond(method, route, *args, **kwargs)
        self.runtime.cloud.raw.side_effect = unavailable
        def drive(variables, entries, buttons, scheduled):
            entries[0].insert(0, "short-lived-code")
            buttons["Pair app"].options["command"]()
            scheduled[200]()
            self.assertIn("Cloud: pairing saved", variables[0].get())
            self.assertIn("no new code is needed", variables[3].get())
            self.runtime.cloud.raw.side_effect = self.respond
            scheduled[5000]()
            scheduled[200]()
            self.assertIn("Cloud: connected", variables[0].get())
            self.assertEqual(self.pair_count(), 1)
        self.exercise(drive, interface_error=False)
