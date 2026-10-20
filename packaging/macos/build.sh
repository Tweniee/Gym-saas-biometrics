#!/usr/bin/env bash
# Native macOS app/DMG build. This is separate from the Docker/Wine Windows build.
set -euo pipefail
if [[ ( $# -ne 2 && $# -ne 4 ) || "$1" != "--api-url" || ( $# -eq 4 && "$3" != "--arch" ) ]]; then
  printf 'Usage: bash packaging/macos/build.sh --api-url https://YOUR-BACKEND/api/v1 [--arch arm64|x86_64]\n'; exit 2
fi
api_url=$2
target_arch="${4:-}"
if [[ -n "$target_arch" && "$target_arch" != arm64 && "$target_arch" != x86_64 ]]; then
  printf "Choose --arch arm64 or x86_64.\n" >&2; exit 2
fi
if [[ ! "$api_url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9_-]+)*/api/v1$ ]]; then
  printf 'An HTTPS API URL ending in /api/v1 is required.\n' >&2; exit 2
fi
if [[ "$(uname -s)" != Darwin ]]; then
  printf 'Build this app on macOS. Docker is not required.\n' >&2; exit 1
fi
project_dir="$(cd "$(dirname "$0")/../.." && pwd)"
python_bin="${PYTHON_BIN:-python3}"
sign_identity="${MACOS_SIGN_IDENTITY:--}"
notary_profile="${MACOS_NOTARY_PROFILE:-}"
if [[ -n "$notary_profile" && "$sign_identity" == "-" ]]; then
  printf 'Notarization requires MACOS_SIGN_IDENTITY (Developer ID Application).\n' >&2; exit 2
fi
python_host=("$python_bin")
if [[ -n "$target_arch" ]]; then python_host=(/usr/bin/arch "-$target_arch" "$python_bin"); fi
"${python_host[@]}" -c 'import sys, tkinter; assert sys.version_info >= (3, 11), "Python 3.11+ with Tk is required"'
arch="$("${python_host[@]}" -c 'import platform; print(platform.machine())')"
if [[ "$arch" != arm64 && "$arch" != x86_64 ]]; then printf "Unsupported Python architecture.\n" >&2; exit 2; fi
build_dir="$project_dir/build/macos/$arch"
mkdir -p "$build_dir"
"${python_host[@]}" -m venv "$build_dir/venv"
python=(/usr/bin/arch "-$arch" "$build_dir/venv/bin/python")
"${python[@]}" -m pip install --upgrade pip
"${python[@]}" -m pip install "$project_dir[build]"
cd "$project_dir"
"${python[@]}" -m unittest discover -s tests -v
version="$("${python[@]}" -c 'from zenvore_connector import __version__; print(__version__)')"
stage="$(mktemp -d "$build_dir/staging.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
"${python[@]}" - "$api_url" "$stage/defaults.json" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[2]).write_text(json.dumps({"api_url": sys.argv[1], "development": False}))
PY
"${python[@]}" -m PyInstaller --noconfirm --clean --onedir --windowed \
  --name "Zenvore Connector" --osx-bundle-identifier com.zenvore.biometricconnector \
  --codesign-identity "$sign_identity" --target-architecture "$arch" --collect-all tzdata \
  --add-data "$stage/defaults.json:." \
  --distpath "$build_dir/dist" --workpath "$build_dir/work" --specpath "$build_dir" \
  packaging/macos/connector_entry.py
app="$build_dir/dist/Zenvore Connector.app"
"${python[@]}" - "$app/Contents/Info.plist" "$version" <<'PY'
import pathlib, plistlib, sys
p = pathlib.Path(sys.argv[1])
info = plistlib.loads(p.read_bytes())
info.update(CFBundleShortVersionString=sys.argv[2], CFBundleVersion=sys.argv[2],
            NSLocalNetworkUsageDescription="Connect to your selected gym biometric device over Ethernet to verify and sync attendance.",
            NSHighResolutionCapable=True)
p.write_bytes(plistlib.dumps(info))
PY
if [[ "$sign_identity" == "-" ]]; then
  codesign --force --sign - "$app"
else
  codesign --force --options runtime --timestamp --sign "$sign_identity" "$app"
fi
codesign --verify --deep --strict "$app"
"$app/Contents/MacOS/Zenvore Connector" --self-test
mkdir -p "$stage/disk"
ditto "$app" "$stage/disk/Zenvore Connector.app"
ln -s /Applications "$stage/disk/Applications"
cp packaging/macos/INSTALL.txt "$stage/disk/Read me first.txt"
name="ZenvoreBiometricConnector-$version-macos-$arch.dmg"
hdiutil create -volname "Zenvore Connector" -srcfolder "$stage/disk" -ov -format UDZO -o "$stage/$name"
if [[ "$sign_identity" != "-" ]]; then
  codesign --timestamp --sign "$sign_identity" "$stage/$name"
fi
if [[ -n "$notary_profile" ]]; then
  xcrun notarytool submit "$stage/$name" --keychain-profile "$notary_profile" --wait
  xcrun stapler staple "$stage/$name"
fi
hdiutil verify "$stage/$name"
(cd "$stage" && shasum -a 256 "$name" > "$name.sha256")
artifact_dir="$project_dir/dist/installer"
mkdir -p "$artifact_dir"
cp "$stage/$name" "$artifact_dir/.$name.tmp"
mv "$artifact_dir/.$name.tmp" "$artifact_dir/$name"
cp "$stage/$name.sha256" "$artifact_dir/$name.sha256"
printf 'Created: %s/%s\n' "$artifact_dir" "$name"
if [[ "$sign_identity" == "-" ]]; then
  printf 'Local build: ad-hoc signed, not Apple-notarized. See packaging/macos/README.md before distribution.\n'
fi
