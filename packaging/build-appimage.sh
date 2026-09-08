#!/usr/bin/env bash
# Build an AppImage using the upstream recipe-directory interface.
set -euo pipefail
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
out="$project_dir/dist"
mkdir -p "$out"
python3 -m venv "$out/build-venv"
build_python="$out/build-venv/bin/python"
"$build_python" -m pip install --upgrade build python-appimage
"$build_python" -m build --wheel --outdir "$out/wheels" "$project_dir"
recipe="$out/appimage-recipe"
mkdir -p "$recipe"
cp "$project_dir/packaging/appimage/draghunt.desktop" "$recipe/"
cp "$project_dir/packaging/appimage/entrypoint.sh" "$recipe/"
cp "$project_dir/packaging/draghunt.svg" "$recipe/"
"$build_python" - "$out/wheels" "$recipe/requirements.txt" <<'PY'
from pathlib import Path
import sys
wheels = sorted(Path(sys.argv[1]).glob('draghunt-*.whl'), key=lambda p: p.stat().st_mtime)
Path(sys.argv[2]).write_text(str(wheels[-1].resolve()) + '[desktop]\n')
PY
cd "$out"
"$build_python" -m python_appimage build app --python-version 3.12 "$recipe"
printf '%s\n' "AppImage output: $out"
