#!/usr/bin/env bash
# Build a Windows installer on macOS without loading a builder image into Docker.
set -euo pipefail
usage() {
  printf 'Usage: bash packaging/windows/build-macos.sh --api-url https://YOUR-BACKEND/api/v1\n'
}
if [[ $# -ne 2 || "$1" != "--api-url" ]]; then usage; exit 2; fi
api_url=$2
if [[ ! "$api_url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9_-]+)*/api/v1$ ]]; then
  printf 'An HTTPS API URL ending in /api/v1 is required.\n' >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  printf 'Install and start Docker Desktop, then retry this command.\n' >&2; exit 1
fi
if ! docker info >/dev/null 2>&1; then
  printf 'Docker Desktop is not running. Start it and retry.\n' >&2; exit 1
fi
project_dir="$(cd "$(dirname "$0")/../.." && pwd)"
artifact_dir="$project_dir/dist/installer"
stage="$(mktemp -d /tmp/zenvore-windows-build.XXXXXX)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/context/source/windows"
# Deliberately exclude repository metadata, environment files and local device state.
cp "$project_dir/pyproject.toml" "$stage/context/source/"
cp -R "$project_dir/src" "$project_dir/tests" "$stage/context/source/"
cp "$project_dir/packaging/windows/connector_entry.py" "$project_dir/packaging/windows/installer.nsi" "$stage/context/source/windows/"
cp "$project_dir/packaging/windows/docker/"* "$stage/context/"
printf 'Building Windows x64 locally through Docker/Wine. The first build downloads the toolchain.\n'
docker buildx build --platform linux/amd64 --target artifact \
  --build-arg "API_URL=$api_url" --output "type=local,dest=$stage/output" "$stage/context"
name=ZenvoreBiometricConnector-0.1.0-windows-x64.exe
if [[ ! -s "$stage/output/$name" || ! -s "$stage/output/$name.sha256" ]]; then
  printf 'Build did not export an installer and checksum.\n' >&2; exit 1
fi
(cd "$stage/output" && shasum -a 256 -c "$name.sha256")
mkdir -p "$artifact_dir"
cp "$stage/output/$name" "$artifact_dir/.$name.tmp"
mv "$artifact_dir/.$name.tmp" "$artifact_dir/$name"
cp "$stage/output/$name.sha256" "$artifact_dir/$name.sha256"
printf 'Installer: %s/%s\n' "$artifact_dir" "$name"
