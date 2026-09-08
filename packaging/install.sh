#!/usr/bin/env bash
# User-level install of Draghunt on Linux (no root for the app itself).
# Picks the best available installer, adds the native-window extra reliably
# (even on distros with an externally-managed system Python, e.g. Arch), and
# registers the launcher + icon. The WebKit backend needs root, so we only
# detect it and print the command.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*"; }
ok()   { printf '\033[32m  ok\033[0m %s\n' "$*"; }

# ---- 1. install the app + the desktop (pywebview) extra ----------------------
install_with_pipx() {
  say "Installing Draghunt with pipx (isolated venv)"
  pipx install --force "$here"
  # pipx can't take extras on a local path, so inject the optional dep:
  pipx inject draghunt pywebview || warn "couldn't inject pywebview; browser fallback still works"
}

install_with_pip() {
  say "Installing Draghunt with pip --user"
  if python3 -m pip install --user --upgrade "$here[desktop]" 2>/dev/null; then
    return 0
  fi
  warn "pip --user failed (likely an externally-managed Python). Retrying with --break-system-packages."
  python3 -m pip install --user --break-system-packages --upgrade "$here[desktop]"
}

if command -v pipx >/dev/null 2>&1; then
  install_with_pipx
elif python3 -m pip --version >/dev/null 2>&1; then
  install_with_pip
else
  warn "Neither pipx nor pip found."
  warn "Install one first:  sudo pacman -S python-pipx   (Arch)   or   python3 -m ensurepip --user"
  warn "You can still run Draghunt from the repo without installing:  python3 -m draghunt web"
  exit 1
fi
ok "app installed"

# ---- 2. check the native-window backend (needs root; we only advise) ---------
have_webkit() {
  pkg-config --exists webkit2gtk-4.1 2>/dev/null && return 0
  pkg-config --exists webkit2gtk-4.0 2>/dev/null && return 0
  ldconfig -p 2>/dev/null | grep -q 'libwebkit2gtk' && return 0
  return 1
}
if have_webkit; then
  ok "WebKit backend present — the native window will work"
else
  warn "No WebKit backend found; the native window needs it."
  if command -v pacman >/dev/null 2>&1; then
    warn "Install it with:  sudo pacman -S --needed webkit2gtk-4.1"
  else
    warn "Install your distro's webkit2gtk (GTK) package."
  fi
  warn "Until then, 'draghunt desktop' opens in your browser instead."
fi

# ---- 3. register the launcher + icon -----------------------------------------
say "Registering the desktop launcher"
apps="$HOME/.local/share/applications"
icons="$HOME/.local/share/icons/hicolor/scalable/apps"
mkdir -p "$apps" "$icons"
cp "$here/packaging/draghunt.desktop" "$apps/draghunt.desktop"
cp "$here/packaging/draghunt.svg"     "$icons/draghunt.svg"
update-desktop-database "$apps" 2>/dev/null || true
gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
ok "launcher registered"

# ---- 4. PATH hint ------------------------------------------------------------
if ! command -v draghunt >/dev/null 2>&1; then
  warn "The 'draghunt' command isn't on your PATH yet."
  warn "pipx:  run 'pipx ensurepath' then restart your shell."
  warn "pip:   add ~/.local/bin to PATH (e.g. in ~/.bashrc)."
fi

say "Done. Launch 'Draghunt' from your app menu, or run:  draghunt desktop"
