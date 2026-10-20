"""Mac launcher tests use a fake Docker executable; no network or images needed."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
NAME = "ZenvoreBiometricConnector-0.1.0-windows-x64.exe"


@unittest.skipUnless(os.name != "nt" and shutil.which("bash"), "Mac/Linux shell launcher")
class MacBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="Zenvore Build ")
        self.directory = Path(self.temporary.name)
        self.project = self.directory / "Gym Saas"
        (self.project / "packaging/windows/docker").mkdir(parents=True)
        self.script = self.project / "packaging/windows/build-macos.sh"
        shutil.copy2(ROOT / "packaging/windows/build-macos.sh", self.script)
        for directory in ("src", "tests", ".git"):
            (self.project / directory).mkdir()
        (self.project / "pyproject.toml").write_text("")
        (self.project / ".env").write_text("SECRET=do-not-copy")
        for name in ("connector_entry.py", "installer.nsi", "docker/Dockerfile"):
            (self.project / "packaging/windows" / name).write_text("fixture")
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.trace = self.directory / "docker.jsonl"
        docker = self.bin / "docker"
        docker.write_text("""#!/usr/bin/env python3
import hashlib, json, os, pathlib, sys
with open(os.environ['DOCKER_TRACE'], 'a') as handle:
    handle.write(json.dumps(sys.argv[1:]) + '\\n')
if sys.argv[1] == 'info' and os.environ.get('DOCKER_OFFLINE'):
    sys.exit(1)
if sys.argv[1:3] == ['buildx', 'build']:
    context = pathlib.Path(sys.argv[-1])
    with open(os.environ['CONTEXT_TRACE'], 'w') as handle:
        json.dump(sorted(str(p.relative_to(context)) for p in context.rglob('*')), handle)
    if os.environ.get('BUILD_FAIL'):
        sys.exit(42)
    output_arg = sys.argv[sys.argv.index('--output') + 1]
    output = pathlib.Path(output_arg.split('dest=', 1)[1])
    output.mkdir(parents=True)
    name = 'ZenvoreBiometricConnector-0.1.0-windows-x64.exe'
    data = b'MZ-fake-test-installer'
    (output / name).write_bytes(data)
    digest = '0' * 64 if os.environ.get('BAD_HASH') else hashlib.sha256(data).hexdigest()
    (output / (name + '.sha256')).write_text(digest + '  ' + name + '\\n')
""")
        docker.chmod(0o700)
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                    "DOCKER_TRACE": str(self.trace), "CONTEXT_TRACE": str(self.directory / "context.json")}

    def tearDown(self):
        self.temporary.cleanup()

    def run_build(self, *arguments):
        return subprocess.run(["bash", str(self.script), *arguments], env=self.env, capture_output=True, text=True)

    def calls(self):
        return [json.loads(line) for line in self.trace.read_text().splitlines()] if self.trace.exists() else []

    def test_direct_export_preserves_spaces_and_stages_only_source_inputs(self):
        result = self.run_build("--api-url", "https://api.example.invalid/api/v1")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual([call[0] for call in calls], ["info", "buildx"])
        build = calls[1]
        self.assertEqual(build[1], "build")
        self.assertIn("linux/amd64", build)
        self.assertIn("API_URL=https://api.example.invalid/api/v1", build)
        self.assertIn("artifact", build)
        self.assertNotIn("--load", build)
        context = json.loads((self.directory / "context.json").read_text())
        self.assertIn("source/windows/installer.nsi", context)
        self.assertIn("source/pyproject.toml", context)
        self.assertFalse(any(".env" in entry or ".git" in entry for entry in context))
        self.assertFalse(Path(build[-1]).exists(), "Temporary source context should be removed")
        self.assertTrue((self.project / "dist/installer" / NAME).exists())

    def test_failure_or_invalid_checksum_preserves_previous_installer(self):
        output = self.project / "dist/installer" / NAME
        output.parent.mkdir(parents=True)
        output.write_bytes(b"previous installer")
        for failure in ("BUILD_FAIL", "BAD_HASH"):
            self.env[failure] = "1"
            result = self.run_build("--api-url", "https://api.example.invalid/api/v1")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_bytes(), b"previous installer")
            del self.env[failure]

    def test_invalid_urls_fail_before_docker_or_output_creation(self):
        for url in ("http://localhost:3000/api/v1", "https://api.example.invalid",
                    "https://api.example.invalid/api/v1;whoami", "https://api.example.invalid/api/v1\n"):
            self.assertNotEqual(self.run_build("--api-url", url).returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.project / "dist").exists())

    def test_stopped_docker_reports_actionable_error_without_starting_a_build(self):
        self.env["DOCKER_OFFLINE"] = "1"
        result = self.run_build("--api-url", "https://api.example.invalid/api/v1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Docker Desktop is not running", result.stderr)
        self.assertEqual([call[0] for call in self.calls()], ["info"])

    def test_missing_arguments_print_mac_usage(self):
        result = self.run_build()
        self.assertEqual(result.returncode, 2)
        self.assertIn("bash packaging/windows/build-macos.sh", result.stdout)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
