# Windows packaging

On macOS with Docker Desktop running, use:

```bash
bash packaging/windows/build-macos.sh --api-url "https://api.zenvore.com/api/v1"
```

This builds the Windows EXE locally through Docker/Wine. See [Mac build instructions](../../docs/building-windows-on-macos.md). It does not create a Mac app. The PowerShell command below is for a native Windows build.

Build on a Windows x64 environment with Python 3.11+ x64 and Inno Setup 6 installed. The build bundles Python, Tk, pywin32, timezone data and dependencies; gym owners do not install Python. No vendor SDK is included.

```powershell
./packaging/windows/build.ps1 -ApiUrl https://api.zenvore.com/api/v1
```

The repository's manually triggered `connector-windows.yml` workflow runs the same build and stores an installer artifact. It does not publish a release or upload to R2. Local output is `dist/installer/ZenvoreBiometricConnector-0.1.0-windows-x64.exe`; the build prints its SHA-256.

The installer creates an automatically starting LocalSystem service and configures restart on failure. The setup shortcut requests elevation and writes a machine-DPAPI installation credential into the restricted ProgramData directory. It preserves configuration and state on upgrades. An uninstaller stops/deletes the service and removes application files; local recovery state is intentionally retained. Revoke the installation in Admin before retiring a computer, then remove its retained state as an explicit administrative action.

Sign both executables and the final installer using your production signing certificate and timestamp service. Verify signatures and checksum before uploading through Super admin → Biometrics → Publish Windows installer. The backend stores the immutable version in private R2 and proxies authenticated owner downloads. Never upload to R2 directly from the browser or connector. A checksum is an integrity check; it does not replace publisher signing.

The macOS Docker/Wine build has compiled both x64 executables and the NSIS installer, passed the connector tests under Windows Python/Wine, and started the frozen setup CLI. Actual installation and hardware pairing have not been exercised on Windows. Validate pywin32/PyInstaller service startup, UAC, ACLs, recovery, restart after reboot, upgrades, uninstall and rollback on Windows. SDK architecture/licensing and code signing remain release responsibilities.
