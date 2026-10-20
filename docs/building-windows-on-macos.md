# Build the Windows EXE locally on macOS

Use the Mac launcher, not the Windows PowerShell command:

```bash
bash packaging/windows/build-macos.sh --api-url "https://api.zenvore.com/api/v1"
```

Run it from the `Gym-saas-biometrics` repository root. Docker Desktop must be installed and running. Both Intel and Apple Silicon Macs use the local `linux/amd64` Docker build environment. No GitHub Actions runner or separate Windows computer is used to compile the EXE.

The image uses a 64-bit-only Wine runtime. It extracts the official Windows Python x64 MSI packages directly and compiles the installer with native Linux NSIS, avoiding Windows bootstrap installers under Rosetta. The bundled setup application and service are Windows x64 executables.

The first invocation downloads the builder dependencies and can take several minutes. Later invocations reuse Docker build layers. Official Windows Python MSI downloads are pinned by version and SHA-256.

Output after a successful build:

```text
dist/installer/ZenvoreBiometricConnector-0.1.0-windows-x64.exe
dist/installer/ZenvoreBiometricConnector-0.1.0-windows-x64.exe.sha256
```

The builder runs the connector tests under Windows Python/Wine, freezes the setup utility and service with PyInstaller, and compiles `packaging/windows/installer.nsi`. Native Windows builds continue to use Inno Setup. It checks the PE header and exports the final installer only after all steps succeed. A failed build does not replace a previous installer.

Only project source, tests, project metadata and selected Windows packaging inputs are staged in a temporary build context. BuildKit exports just the installer and checksum directly to the Mac; it does not load a large builder image. The Wine prefix and compilation directory use temporary memory-backed mounts. The launcher does not copy your home directory, Git credentials, local connector state or root environment files.

## Validation recorded

A local Apple Silicon build completed with Docker’s existing 8 GB disk limit and approximately 2 GB RAM, without changing settings or restarting the existing MongoDB/Redis containers. All 34 host tests passed. Under Windows Python/Wine, 29 tests passed and the five Mac launcher tests were skipped. The frozen setup CLI started successfully, NSIS compiled the installer, and the exported checksum verified. This does not establish minimum resource requirements for other machines.

The build also caught and fixed Windows credential persistence: `CryptProtectData` returns encrypted bytes directly; `CryptUnprotectData` returns a description/data tuple. A regression test covers both return shapes and the machine-protection flag.

## Choose the backend address

The supplied URL is embedded in the installer configuration. Use the backend address that the eventual **Windows gym computer** can reach.

- `https://api.zenvore.com/api/v1` uses that hosted API.
- `http://localhost:3000/api/v1` on your Mac is not reachable as `localhost` from another computer.
- Production installers require verified HTTPS. The development simulator and its loopback HTTP configuration remain separate from production packaging.
- Building does not contact the supplied API, publish to R2 or verify cloud pairing.

## Verify before publishing

The resulting EXE is a Windows installer, not a Mac application. Compilation under Wine does not validate Windows service registration, DPAPI/ACL sharing, reboot recovery, device SDK behavior or physical hardware.

Test installation and the service on Windows, verify/sign the setup/service executables and final installer using your release process, then upload the EXE through **Super Admin → Biometrics → Publish Windows installer**. The backend handles R2 storage and owner downloads. If signing changes the final EXE, recompute its SHA-256 before publication.

For native Windows builds, continue using `packaging/windows/build.ps1`.

## Docker disk space

Docker Desktop has its own virtual disk limit. Free space on the Mac does not guarantee free space inside Docker. This launcher avoids loading/unpacking a builder image and keeps the Wine prefix and compilation work in temporary memory-backed mounts. It does not change Docker settings, restart running containers or prune images, caches or volumes. Resource requirements also depend on other running containers and existing build caches.
