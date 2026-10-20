"""Build-container-only compatibility for Wine 9's missing CopyFile2."""
import os
import sys

if sys.platform == "win32" and os.environ.get("ZENVORE_WINE_BUILD") == "1":
    import _winapi
    # Let Python's shutil.copy2 use its supported portable fallback.
    if hasattr(_winapi, "CopyFile2"):
        del _winapi.CopyFile2
