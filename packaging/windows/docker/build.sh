#!/usr/bin/env bash
set -euo pipefail
trap 'wineserver -k >/dev/null 2>&1 || true' EXIT
if [[ $# -ne 1 ]]; then printf 'Supply the HTTPS API base URL.\n' >&2; exit 2; fi
api_url=$1
python3 - "$api_url" <<'PY'
import re, sys
if not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9_-]+)*/api/v1", sys.argv[1]):
    raise SystemExit("Use an HTTPS API URL ending in /api/v1")
PY
bash /opt/provision.sh
# Copy only the explicitly staged source inputs.
cp /source/pyproject.toml /build/
cp -R /source/src /source/tests /build/
mkdir -p /build/packaging/windows
cp /source/windows/connector_entry.py /source/windows/installer.nsi /build/packaging/windows/
wine 'C:\Python\python.exe' -m pip install --no-deps --no-build-isolation .
wine 'C:\Python\python.exe' -m unittest discover -s tests -v
wine 'C:\Python\python.exe' -m PyInstaller --noconfirm --clean --onedir --exclude-module sitecustomize --name ZenvoreConnector \
    --uac-admin --collect-all tzdata --hidden-import win32timezone --hidden-import win32crypt packaging/windows/connector_entry.py
wine 'C:\Python\python.exe' -m PyInstaller --noconfirm --clean --onedir --exclude-module sitecustomize --name ZenvoreConnectorService \
    --hidden-import win32timezone --hidden-import win32crypt --collect-all tzdata src/zenvore_connector/windows_service.py
# Check that the frozen Windows application can start before packaging it.
wine 'Z:\build\dist\ZenvoreConnector\ZenvoreConnector.exe' --help
mkdir -p /build/dist/installer
makensis "-DApiUrl=$api_url" -DDistDir=/build/dist /build/packaging/windows/installer.nsi
result=/build/dist/installer/ZenvoreBiometricConnector-0.1.0-windows-x64.exe
python3 - "$result" <<'PY'
import pathlib, struct, sys
data = pathlib.Path(sys.argv[1]).read_bytes()
if len(data) < 256 or data[:2] != b"MZ":
    raise SystemExit("Compiler did not produce a Windows executable")
offset = struct.unpack_from("<I", data, 60)[0]
if offset + 24 > len(data) or data[offset:offset+4] != b"PE\0\0":
    raise SystemExit("Invalid Windows executable header")
PY
# Export only after every build step succeeds; leave an earlier installer intact on failure.
name=$(basename "$result")
cp "$result" "/artifacts/.$name.tmp"
mv "/artifacts/.$name.tmp" "/artifacts/$name"
(cd /artifacts && sha256sum "$name" > "$name.sha256")
printf 'Created: dist/installer/%s\n' "$name"
cat "/artifacts/$name.sha256"
