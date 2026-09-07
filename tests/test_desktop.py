"""Desktop launcher: server-in-thread + graceful behavior, minus the GUI window."""
import unittest
import urllib.request

from draghunt import desktop


class TestDesktopLauncher(unittest.TestCase):
    def test_run_serves_and_shuts_down(self):
        seen = {}

        def opener(url):
            # stands in for the native window: verify the server is live
            seen["url"] = url
            with urllib.request.urlopen(url + "/api/state", timeout=5) as r:
                seen["status"] = r.status

        url = desktop.run(opener=opener)
        self.assertTrue(seen["url"].startswith("http://127.0.0.1:"))
        self.assertEqual(seen["status"], 200)
        self.assertEqual(url, seen["url"])

    def test_auto_port_is_free_and_returned(self):
        httpd, thread, port = desktop.start_server(0)
        try:
            self.assertGreater(port, 0)
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=5) as r:
                self.assertEqual(r.status, 200)
        finally:
            httpd.shutdown()

    def test_native_open_without_pywebview_raises_importerror(self):
        # pywebview is an optional extra; without it, _open_native must raise
        # ImportError (which run() catches to fall back to the browser).
        try:
            import webview  # noqa: F401
            self.skipTest("pywebview is installed; fallback path not exercised here")
        except ImportError:
            with self.assertRaises(ImportError):
                desktop._open_native("http://127.0.0.1:1")


if __name__ == "__main__":
    unittest.main()
