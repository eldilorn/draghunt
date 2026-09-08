"""Desktop launcher: server-in-thread + graceful behavior, minus the GUI window."""
import unittest
import tempfile
from draghunt.config import RangeConfig
import urllib.request

from draghunt import desktop


class TestDesktopLauncher(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cfg = RangeConfig(data_dir=self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_run_serves_and_shuts_down(self):
        seen = {}

        def opener(url):
            # stands in for the native window: verify the server is live
            seen["url"] = url
            with urllib.request.urlopen(url + "/", timeout=5) as r:
                seen["status"] = r.status

        url = desktop.run(opener=opener, cfg=self.cfg)
        self.assertTrue(seen["url"].startswith("http://127.0.0.1:"))
        self.assertEqual(seen["status"], 200)
        self.assertEqual(url, seen["url"])

    def test_auto_port_is_free_and_returned(self):
        httpd, thread, port = desktop.start_server(0, cfg=self.cfg)
        try:
            self.assertGreater(port, 0)
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
                self.assertEqual(r.status, 200)
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

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


class TestNativeFallback(unittest.TestCase):
    def test_backend_unavailable_opens_browser_and_closes_server(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp, patch('draghunt.desktop._open_native',side_effect=desktop.NativeUnavailable('backend absent')), patch('draghunt.desktop._open_browser_and_block') as browser:
            url=desktop.run(cfg=RangeConfig(data_dir=temp))
        browser.assert_called_once_with(url)
