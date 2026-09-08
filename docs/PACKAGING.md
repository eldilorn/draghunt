# Packaging Draghunt as a desktop app

Draghunt's dashboard is a local web server plus a plain HTML/JS frontend. The
desktop app is that same frontend shown in a native window instead of a browser
tab. No rewrite: `draghunt/desktop.py` starts the server on a private localhost
port in a background thread and opens a window at it.

## Run it

```bash
draghunt desktop            # native window if pywebview is installed
```

Without the optional `pywebview` dependency it falls back to opening your default
browser, so the command always works.

## Install on your machine (Linux, no root)

```bash
packaging/install.sh
```

What it does, automatically:

1. **Installs the app with the native-window extra**, picking the installer that
   fits your machine:
   * `pipx` if present (isolated venv), then `pipx inject draghunt pywebview`;
   * otherwise `pip install --user`, and if the system Python is
     externally-managed (Arch), it retries with `--break-system-packages`;
   * if neither is available, it tells you how to get one and how to run from the
     repo without installing.
2. **Checks for the WebKit backend** pywebview needs. Installing it needs root, so
   the script only detects it and prints the exact command (Arch:
   `sudo pacman -S --needed webkit2gtk-4.1`). Until it's present, `draghunt
   desktop` opens in your browser instead of a native window.
3. **Registers the launcher and icon** so "Draghunt" appears in your app menu:
   * `packaging/draghunt.desktop` -> `~/.local/share/applications/`
   * `packaging/draghunt.svg` -> `~/.local/share/icons/hicolor/scalable/apps/`
4. **Warns if the `draghunt` command isn't on your PATH** and says how to fix it
   (`pipx ensurepath`, or add `~/.local/bin`).

## A single-file AppImage (optional)

```bash
packaging/build-appimage.sh
```

Uses [`python-appimage`](https://github.com/niess/python-appimage) to bundle a
Python runtime and Draghunt into one portable file under `dist/`. This step needs
network and build tools the first time, and the target host still needs a WebKit
backend for the native window (the browser fallback works regardless).

## Why not Electron

Electron ships a whole Chromium and Node runtime per app: heavy to build and to
maintain solo. pywebview reuses the system WebKit and stays pure Python, so the
desktop app is a thin shell over code that already exists.
