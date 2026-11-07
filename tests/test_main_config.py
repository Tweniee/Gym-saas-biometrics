import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from zenvore_connector.config import Config
from zenvore_connector.main import main


class ConfigErrorTests(unittest.TestCase):
    def run_main(self, path):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(["--config", str(path), "diagnostics"])
        return code, err.getvalue()

    def assert_clean_error(self, path, reason):
        code, message = self.run_main(path)
        self.assertEqual(code, 2)
        self.assertEqual(len(message.strip().splitlines()), 1)
        self.assertTrue(message.startswith("Config error: "))
        self.assertIn(str(path), message)
        self.assertIn(reason, message)
        self.assertIn("Run init-dev or reinstall", message)

    def test_missing_config(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assert_clean_error(Path(directory) / "config.json", "file not found")

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text("{not json", encoding="utf-8")
            self.assert_clean_error(path, "invalid JSON")

    def test_missing_api_url(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"state_dir": directory}), encoding="utf-8")
            self.assert_clean_error(path, "api_url")

    def test_invalid_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"api_url": "http://example.com", "state_dir": directory}), encoding="utf-8")
            self.assert_clean_error(path, "invalid settings")

    def test_json_root_that_is_not_an_object(self):
        for content in ("[]", "5", '"text"', "null"):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "config.json"
                path.write_text(content, encoding="utf-8")
                self.assert_clean_error(path, "invalid settings")

    def test_values_of_the_wrong_type(self):
        good = "https://api.example.com/api/v1"
        for settings in ({"api_url": good, "heartbeat_seconds": "60"}, {"api_url": good, "state_dir": 5},
                         {"api_url": good, "timeout_seconds": None}, {"api_url": good, "development": [], "sync_seconds": {}}):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "config.json"
                path.write_text(json.dumps(settings), encoding="utf-8")
                self.assert_clean_error(path, "invalid settings")


class DeviceTimeoutTests(unittest.TestCase):
    def load(self, **settings):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"api_url": "https://api.example.com/api/v1", "state_dir": directory, **settings}), encoding="utf-8")
            return Config.load(path)

    def test_default_is_fifteen_seconds_and_independent_of_the_cloud_timeout(self):
        config = self.load(timeout_seconds=4)
        self.assertEqual((config.device_timeout_seconds, config.timeout_seconds), (15, 4))

    def test_the_key_is_read_from_the_settings_file(self):
        self.assertEqual(self.load(device_timeout_seconds=45).device_timeout_seconds, 45)
        self.assertEqual(self.load(device_timeout_seconds=45).timeout_seconds, 15)

    def test_bounds_are_one_to_sixty_seconds(self):
        self.assertEqual([self.load(device_timeout_seconds=v).device_timeout_seconds for v in (1, 60)], [1, 60])
        for value in (0, -1, 61, 300):
            with self.assertRaises(ValueError):
                self.load(device_timeout_seconds=value)

    def test_a_value_of_the_wrong_type_is_a_clean_config_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"api_url": "https://api.example.com/api/v1", "device_timeout_seconds": None}), encoding="utf-8")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = main(["--config", str(path), "diagnostics"])
            self.assertEqual(code, 2)
            self.assertIn("invalid settings", err.getvalue())

    def test_the_cloud_timeout_keeps_its_own_bound(self):
        with self.assertRaises(ValueError):
            self.load(timeout_seconds=31)


if __name__ == "__main__":
    unittest.main()
