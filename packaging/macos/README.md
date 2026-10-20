# Native macOS app and DMG

Build on macOS using Python 3.11+ with Tk (the Python.org installer includes it):

```bash
bash packaging/macos/build.sh --api-url "https://api.zenvore.com/api/v1"
```

Docker is not needed for this build. It creates a native Mac app, not a Windows EXE. To use a particular interpreter, set `PYTHON_BIN=/path/to/python3` before the command. The script creates its isolated build environment under `build/macos/<architecture>/venv`, runs tests, freezes the app, checks its signature and dependencies, creates a DMG and verifies the disk-image checksum.

Output on Apple Silicon:

```text
dist/installer/ZenvoreBiometricConnector-0.1.0-macos-arm64.dmg
dist/installer/ZenvoreBiometricConnector-0.1.0-macos-arm64.dmg.sha256
build/macos/arm64/dist/Zenvore Connector.app
```

An Intel build uses `macos-x86_64.dmg`. Choose an architecture explicitly:

```bash
# Intel build on this Apple Silicon Mac: requires Rosetta and universal Python.org Python.
PYTHON_BIN=/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 \
  bash packaging/macos/build.sh --api-url "https://api.zenvore.com/api/v1" --arch x86_64

# Apple Silicon build
bash packaging/macos/build.sh --api-url "https://api.zenvore.com/api/v1" --arch arm64
```

The Intel command runs x86_64 Python, pip and PyInstaller through Rosetta and explicitly targets x86_64. On an Intel Mac it runs natively. Dependencies and work directories are isolated per architecture. The script does not rename an ARM app or claim a universal app. If Rosetta or a matching Python architecture is unavailable, the build fails before exporting a DMG.

## Install and connect

Open the DMG, drag **Zenvore Connector** to **Applications**, eject the DMG and launch the installed app. Generate the five-minute pairing code in the gym dashboard, pair, select Ethernet or enter IP/port, then **Verify and connect**. Identity, users and attendance must be read before reporting device readiness.

Click **Enable background sync** to register the per-user LaunchAgent. It continues after closing setup and starts at user login. Keep the Mac awake and logged in; this is not a system service that runs before login. macOS may request Local Network and Keychain access. If blocked, check System Settings → Privacy & Security → Local Network, and General → Login Items & Extensions.

**Disable background sync** removes only the LaunchAgent. Disable it before moving or deleting the app. Pairing and attendance recovery data are retained; revoke the connector in Zenvore before retiring the Mac.

## Storage and security

Production installation credentials and device communication keys use the logged-in user's login Keychain through Security.framework. Secrets never go through a shell or appear in process arguments. Files ending in `*.credential` contain only a reference marker; unavailable/locked Keychain access fails without plaintext fallback. The app and LaunchAgent use the same app executable and user identity.

Configuration, private attendance recovery state and rotating logs are in:

```text
~/Library/Application Support/Zenvore/BiometricConnector
```

The LaunchAgent plist is `~/Library/LaunchAgents/com.zenvore.biometricconnector.plist`. Development mode permits plaintext storage only with an explicit loopback API. The bundled default is production HTTPS; an existing configuration is preserved.

## Signing and public distribution

The default local build is **ad-hoc signed, not Apple-notarized**. On a trusted local build, use Finder's Open action / Privacy & Security → Open Anyway if Gatekeeper blocks it. Do not disable Gatekeeper globally.

To create a distributable release, provide your Developer ID Application signing identity and an existing notarytool Keychain profile:

```bash
MACOS_SIGN_IDENTITY="Developer ID Application: YOUR COMPANY (TEAMID)" \
MACOS_NOTARY_PROFILE="zenvore-notary" \
bash packaging/macos/build.sh --api-url "https://api.zenvore.com/api/v1"
```

These variables are optional and are not populated by this repository. Without your certificate/profile the script does not attempt Apple notarization. A configured notarization must finish successfully before the DMG is exported.

The super-admin Biometrics page provides separate upload forms for Windows, macOS (Apple Silicon) and macOS (Intel). Select the matching DMG, enter its release version and publish through the backend. The owner page offers a platform selector and independently selects the highest published version for that platform. Builds do not publish anything automatically or access R2.

## Validation and device support

The Apple Silicon app/DMG and Intel x86_64 app/DMG compiled locally; all 42 connector tests passed in the Intel build. The Intel executable was confirmed as Mach-O x86_64 and its frozen self-test ran under Rosetta. The native setup window also opened and rendered its pairing/device/background controls with cloud access mocked. Automated tests exercise Keychain routing/failure behavior with a fake backend, per-user launchd registration/removal with mocked launchctl, and Ethernet hardware-port classification. The frozen app resolves real Security.framework symbols and imports Tk, SQLite and timezone data. DMG and app signatures/checksums are verified by the builder.

Live Keychain consent, login/reboot persistence, updates, sleep recovery, backend pairing and the exact hardware model/firmware require a Mac pilot. Windows-only vendor SDKs are not included. The generic read-only Identix/ZK-compatible TCP adapter is portable only where the model/firmware implements its supported protocol.

To build the separate Windows EXE on a Mac, use the [Docker/Wine Windows build](../../docs/building-windows-on-macos.md).
