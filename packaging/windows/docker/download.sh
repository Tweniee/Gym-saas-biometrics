#!/usr/bin/env bash
set -euo pipefail
mkdir -p /opt/windows-inputs
for part in core exe lib pip tcltk; do
  curl --fail --location --retry 3 "https://www.python.org/ftp/python/$PYTHON_VERSION/amd64/$part.msi" -o "/tmp/$part.msi"
done
sha256sum --check /opt/python-msi.sha256
mv /tmp/*.msi /opt/windows-inputs/
