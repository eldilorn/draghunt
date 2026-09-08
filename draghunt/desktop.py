"""Desktop launcher — Draghunt in a native window.

Wraps the existing local web control center: it starts the server on a private
localhost port in a background thread, then opens a native window pointing at it
via pywebview. If pywebview isn't installed, it falls back to the system browser,
so `draghunt desktop` always does something useful.

Install the native window with:  pip install 'draghunt[desktop]'
"""

from __future__ import annotations

import threading
import webbrowser

from .web import make_httpd
from .config import RangeConfig


def start_server(port: int = 0, cfg: RangeConfig | None = None, config_path=None) -> tuple:
    """Start the control center in a daemon thread. port=0 picks a free port."""
    httpd = make_httpd("127.0.0.1", port, cfg, config_path)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread, httpd.server_address[1]


class NativeUnavailable(RuntimeError):
    pass


def _open_native(url: str) -> None:
    import webview  # optional dep; ImportError handled by caller
    try:
        webview.create_window("Draghunt", url, width=1200, height=900, min_size=(720, 560))
        webview.start()
    except webview.WebViewException as exc:
        raise NativeUnavailable(str(exc)) from exc


def _open_browser_and_block(url: str) -> None:
    print(f"Native window unavailable — opening {url} in your browser.")
    print("For a native window:  pip install 'draghunt[desktop]'")
    print("Ctrl-C to stop.")
    webbrowser.open(url)
    stop = threading.Event()
    try:
        while not stop.wait(1):
            pass
    except KeyboardInterrupt:
        pass


def run(port: int | None = None, opener=None, cfg: RangeConfig | None = None, config_path=None) -> str:
    """Launch the desktop app. `opener(url)` is injectable for testing."""
    httpd, _thread, actual = start_server(port or 0, cfg, config_path)
    url = f"http://127.0.0.1:{actual}"
    try:
        if opener is not None:
            opener(url)
        else:
            try:
                _open_native(url)
            except (ImportError, NativeUnavailable):
                _open_browser_and_block(url)
    finally:
        httpd.shutdown()
        httpd.server_close()
        _thread.join(timeout=5)
    return url


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="draghunt-desktop",
                                 description="Draghunt in a native window.")
    ap.add_argument("--port", type=int, default=0, help="fixed port (default: auto)")
    args = ap.parse_args()
    run(port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
