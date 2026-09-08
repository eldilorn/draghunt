#!/usr/bin/env bash
# Install into an isolated user environment and register an absolute launcher.
set -euo pipefail
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
app_dir="${XDG_DATA_HOME:-$HOME/.local/share}/draghunt"
bin_dir="${PIPX_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$app_dir" "$bin_dir"
if command -v pipx >/dev/null 2>&1; then
  pipx install --force "$project_dir"
  pipx inject draghunt pywebview || printf '%s\n' 'Native window unavailable; the browser dashboard is still usable.'
  launcher="$bin_dir/draghunt"
  if [ ! -x "$launcher" ]; then
    launcher="$(command -v draghunt || true)"
  fi
else
  python3 -m venv "$app_dir/venv"
  "$app_dir/venv/bin/python" -m pip install --upgrade "$project_dir"
  "$app_dir/venv/bin/python" -m pip install pywebview || printf '%s\n' 'Native window unavailable; the browser dashboard is still usable.'
  launcher="$app_dir/venv/bin/draghunt"
  ln -sfn "$launcher" "$bin_dir/draghunt"
fi
if [ -z "$launcher" ] || [ ! -x "$launcher" ]; then
  printf '%s\n' 'Could not find the installed draghunt command. Check your pipx bin directory.' >&2
  exit 1
fi
# Use the installed interpreter from a directory outside the source checkout.
(cd /tmp && "$launcher" --help >/dev/null)
apps="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
icons="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"
mkdir -p "$apps" "$icons"
python3 - "$project_dir/packaging/draghunt.desktop" "$apps/draghunt.desktop" "$launcher" <<'PY'
from pathlib import Path
import sys
source, destination, command = sys.argv[1:]
# Desktop Entry quoting differs from shell quoting.
quoted = command.replace('\\', '\\\\').replace('"', '\\"').replace('`', '\\`').replace('$', '\\$').replace('%', '%%')
text = Path(source).read_text().replace('Exec=draghunt desktop', f'Exec="{quoted}" desktop')
Path(destination).write_text(text)
PY
cp "$project_dir/packaging/draghunt.svg" "$icons/draghunt.svg"
update-desktop-database "$apps" 2>/dev/null || true
printf '%s\n' "Installed. Launch Draghunt from the app menu, or: $launcher desktop"
printf '%s\n' 'Native windows require a supported pywebview GTK/Qt backend. The app falls back to your browser when unavailable.'
