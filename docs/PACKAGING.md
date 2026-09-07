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

This installs Draghunt with the `desktop` extra (via `pipx` if present, else
`pip --user`) and registers the launcher and icon:

* `packaging/draghunt.desktop` -> `~/.local/share/applications/`
* `packaging/draghunt.svg` -> `~/.local/share/icons/hicolor/scalable/apps/`

Then "Draghunt" appears in your app menu.

The native window needs a WebKit backend, which pywebview uses. On Arch/Omarchy:

```bash
sudo pacman -S --needed webkit2gtk
pip install 'draghunt[desktop]'
```

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
