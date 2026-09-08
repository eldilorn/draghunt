# Packaging and desktop use

The package contains the Python core, `draghunt.siem`, demo metadata, and static web
assets. The native window is optional and uses exactly the same protected localhost
server and persistent case storage as the browser and CLI.

```bash
python -m draghunt desktop
packaging/install.sh
```

The installer uses pipx when available, otherwise a dedicated venv under the user data
directory. It does not pass `--break-system-packages`. A missing native dependency/backend
falls back to the browser. A desktop launcher uses the installed command's absolute path,
so it does not depend on the desktop session's PATH or current directory.

Pywebview needs a supported platform backend in addition to its Python package. Backend
initialization failures are handled as native-window unavailability.
[Pywebview backend initialization](https://github.com/r0x0r/pywebview/blob/master/webview/guilib.py).

```bash
packaging/build-appimage.sh
```

This creates an isolated build environment, builds the wheel, stages an upstream recipe
from `packaging/appimage/`, supplies the wheel plus desktop extra in `requirements.txt`,
and runs the builder from `dist/`. Recipe metadata, the icon, and an entrypoint launch
`python -I -m draghunt desktop`. It downloads build tools and a Python runtime; a target
native window still needs a supported backend. The browser fallback remains available.
[Python AppImage recipe format](https://python-appimage.readthedocs.io/en/latest/apps/).

Validation should include a wheel import/smoke run from outside the repository, as source
checkout imports can hide missing packages. The automated app tests do not establish that
a complete AppImage was built or that every target desktop backend is installed. A full
AppImage build is a separate network-dependent release check.
