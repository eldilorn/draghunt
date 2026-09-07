#!/usr/bin/env bash
# Build a self-contained Draghunt.AppImage. Requires network + build tools the
# first time (python-appimage). Run from the repo root: packaging/build-appimage.sh
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/dist"; mkdir -p "$out"

# python-appimage bundles a Python runtime + your package into one AppImage.
# See: https://github.com/niess/python-appimage
python3 -m pip install --user python-appimage >/dev/null

# Build an AppImage around the app entrypoint. GTK/Qt WebKit for the native
# window must be present on the build host to be bundled (webkit2gtk on Arch).
python3 -m python_appimage build app \
  --name Draghunt \
  --icon "$here/packaging/draghunt.svg" \
  --python-version 3.12 \
  "$here[desktop]"

echo "==> AppImage written under $out (see python-appimage output above)."
echo "    Note: the native window needs a WebKit backend on the target host."
