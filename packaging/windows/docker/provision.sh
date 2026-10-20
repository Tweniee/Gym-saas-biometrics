#!/usr/bin/env bash
set -euo pipefail
export ZENVORE_WINE_BUILD=1
wine 'C:\windows\system32\wineboot.exe' --init
wine reg add 'HKCU\Software\Wine' /v Version /t REG_SZ /d win10 /f
mkdir -p "$WINEPREFIX/drive_c/Python"
for part in core exe lib pip tcltk; do
  msiextract --directory "$WINEPREFIX/drive_c/Python" "/opt/windows-inputs/$part.msi" >/dev/null
done
mkdir -p "$WINEPREFIX/drive_c/Python/Lib/site-packages"
cp /opt/wine_compat.py "$WINEPREFIX/drive_c/Python/Lib/site-packages/sitecustomize.py"
wine 'C:\Python\python.exe' -c 'import sys, tkinter; assert sys.platform == "win32"; assert sys.maxsize > 2**32; print(sys.version)'
wine 'C:\Python\python.exe' -m ensurepip --upgrade
wine 'C:\Python\python.exe' -m pip install --no-cache-dir --use-deprecated=legacy-certs \
    'setuptools>=75' wheel 'pyinstaller>=6.11,<7' 'psutil>=6,<8' 'tzdata>=2025.1' 'pywin32>=308'
