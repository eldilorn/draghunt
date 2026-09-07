#!/usr/bin/env bash
# User-level install of Draghunt on Linux (no root). Installs the app plus the
# native-window extra, and registers the launcher + icon for your desktop.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Installing Draghunt (with the desktop extra)"
if command -v pipx >/dev/null 2>&1; then
  pipx install --force "$here[desktop]"
else
  python3 -m pip install --user --upgrade "$here[desktop]"
fi

apps="$HOME/.local/share/applications"
icons="$HOME/.local/share/icons/hicolor/scalable/apps"
mkdir -p "$apps" "$icons"
cp "$here/packaging/draghunt.desktop" "$apps/draghunt.desktop"
cp "$here/packaging/draghunt.svg"     "$icons/draghunt.svg"
update-desktop-database "$apps" 2>/dev/null || true
gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" 2>/dev/null || true

echo "==> Done. Launch 'Draghunt' from your app menu, or run: draghunt desktop"
