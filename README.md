# Zenvore Biometric Connector

The Python connector lives directly in this repository: `pyproject.toml`, `src/`, `tests/`, and `packaging/`. The current implementation also integrates the authorized sibling projects `../gym_saas_backend` (NestJS) and `../Gym-saas-admin` (Angular).

The setup flow is: super admin uploads the Windows installer through the backend → owner downloads it from the gym Biometrics page → owner generates a five-minute pairing code → Windows app pairs with that gym → app discovers or accepts an Ethernet endpoint → reads serial number, users and attendance through a supported protocol → reports device readiness and acknowledged attendance uploads. Owners link enrolled device user IDs to gym members in the same admin page.

The hardware adapter targets **Identix / ZK-compatible TCP**, normally port 4370, using this repository's protocol implementation. It has protocol-emulator tests; no physical model/firmware is certified yet. Attendance is read-only. Door access writes and expiry enforcement are unsupported for this adapter. Unsupported layouts/protocols fail visibly.

No email is drafted or sent on setup failure. The owner sees retry guidance and diagnostics and can contact **support@thezenvore.com**.

## Local development

Use Python 3.11 or later, from this root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
zenvore-connector --config .dev/config.json init-dev --api-url http://127.0.0.1:3000/api/v1
zenvore-connector --config .dev/config.json pair
zenvore-connector --config .dev/config.json run
```

Enter the code at the hidden prompt. On Windows use `.venv\Scripts\Activate.ps1` and `python`. Simulator development requires a loopback backend. Production uses HTTPS and Windows machine DPAPI plus restricted ProgramData ACLs; credentials and communication keys are never stored by Angular.

`setup` opens the Windows setup wizard. `interfaces` lists active IPv4 interfaces without scanning. `diagnostics` prints allowlisted health counters. The installed service runs independently of the setup window.

## Verify and release

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 test_identix_manager.py -v
```

See [complete setup and test instructions](docs/setup-and-testing.md), [backend API](docs/backend.md), [protocol and recovery](docs/protocol.md), [Windows packaging](packaging/windows/README.md) and [remaining production checks](docs/production.md).

The Windows installer has been built locally on macOS through Docker/Wine using `bash packaging/windows/build-macos.sh --api-url "https://api.zenvore.com/api/v1"`. Output is `dist/installer/ZenvoreBiometricConnector-0.1.0-windows-x64.exe` with a SHA-256 sidecar. See [Mac build instructions](docs/building-windows-on-macos.md). Test installation and hardware pairing on Windows, verify/sign the installer, then upload from the super-admin page. No release has been uploaded. Only the backend uses the existing R2 integration; there are no direct R2 upload commands or cloud credentials in the connector/admin.

The legacy `identix_manager.py` remains available; its local active/inactive flags do not enforce door access. See [reader guide](docs/identix-reader.md) and [LAN walkthrough](RUNNING.md). Files under [integration references](integrations/reference/README.md) are historical snapshots and should not be applied over the active code.

Native macOS app: `bash packaging/macos/build.sh --api-url "https://api.zenvore.com/api/v1"` creates an architecture-specific DMG. It uses login Keychain credentials and opt-in background sync at user login. See [Mac app build and installation](packaging/macos/README.md), including signing/notarization and remaining pilot checks. Super admins can publish Windows, Apple Silicon and Intel installers separately in Biometrics; owners choose their computer platform before downloading.
