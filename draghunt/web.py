"""Local dashboard with protected requests and a shared persistent workflow."""
from __future__ import annotations

import json
import secrets
import threading
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import config, telemetry
from .fire import FireBlocked
from .reset import ResetBlocked
from .schema import SchemaError, boolean
from .store import BusyError, CASE_ID as _CASE_ID, new_case_id, private_write
from .workflow import Workflow

STATIC = Path(__file__).parent / "static"
# Exact-literal routes only; nothing user-controlled ever maps to a filesystem path.
STATIC_FILES = {"/app.js": "text/javascript; charset=utf-8", "/app.css": "text/css; charset=utf-8",
                "/logo.png": "image/png", "/mark.png": "image/png", "/mark-light.png": "image/png",
                "/favicon.png": "image/png"}


class Handler(BaseHTTPRequestHandler):
    server_version = "Draghunt/0.8"

    def log_message(self, *args):
        pass

    @property
    def workflow(self) -> Workflow:
        return self.server.workflow

    def _send(self, code: int, body: bytes, ctype: str, attachment: str | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _authorize(self, api: bool = False) -> bool:
        host = self.headers.get("Host", "")
        valid_hosts = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        origin = self.headers.get("Origin")
        if host not in valid_hosts or (origin is not None and origin != "http://" + host):
            self._json(403, {"error": "request host/origin is not allowed"})
            return False
        # A cross-site *top-level navigation* to the page is just the user opening the app
        # from a link or bookmark; the initiator cannot read the response. Cross-site
        # fetches, subresources, and every API call are still refused.
        navigating = (self.headers.get("Sec-Fetch-Mode") == "navigate"
                      and self.headers.get("Sec-Fetch-Dest") == "document" and not api)
        if self.headers.get("Sec-Fetch-Site") not in (None, "none", "same-origin") and not navigating:
            self._json(403, {"error": "cross-site request refused"})
            return False
        if api and not secrets.compare_digest(self.headers.get("X-Draghunt-Token", ""), self.server.session_token):
            self._json(403, {"error": "session expired; reopen the dashboard"})
            return False
        return True

    def _save_config(self, body: dict) -> dict:
        """Validate a settings-form payload, write range.toml at 0600, and reload the profile.

        Secrets absent from the form are preserved from whatever is already on disk, so the
        browser never has to hold a secret to leave it unchanged. Validation reuses
        RangeConfig.from_dict, so the HTTPS, TLS, and rollback-binding rules apply here too.
        """
        path = Path(self.server.config_path)
        existing = {}
        if path.exists():
            try:
                existing = tomllib.loads(path.read_text())
            except (tomllib.TOMLDecodeError, OSError):
                existing = {}
        tables = config.form_to_tables(body, existing)
        config.RangeConfig.from_dict(tables)  # raises ConfigError on any invalid field
        private_write(path, config.to_toml(tables))
        cfg = config.load(path)
        self.workflow.reload_config(cfg)
        return config.public_profile(cfg, path)

    def _read_body(self) -> dict:
        if self.headers.get_content_type() != "application/json":
            raise SchemaError("Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise SchemaError("invalid Content-Length") from exc
        if not 1 <= length <= 1_000_000 or self.headers.get("Transfer-Encoding"):
            raise SchemaError("request must contain a JSON object of at most 1 MB")
        try:
            doc = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeError) as exc:
            raise SchemaError("invalid JSON request") from exc
        if not isinstance(doc, dict):
            raise SchemaError("expected a JSON object")
        return doc

    def do_GET(self):
        route = urlsplit(self.path)
        if not self._authorize(api=route.path.startswith("/api/")):
            return
        try:
            if route.path == "/":
                page = (STATIC / "index.html").read_text().replace("__SESSION_TOKEN__", self.server.session_token)
                self._send(200, page.encode(), "text/html; charset=utf-8")
            elif route.path in STATIC_FILES:
                self._send(200, (STATIC / route.path[1:]).read_bytes(), STATIC_FILES[route.path])
            elif route.path == "/api/state":
                cfg = self.workflow.cfg
                self._json(200, {"deck": [{"id": s.id, "title": s.title, "live": s.live, "offline": telemetry.supports(s)} for s in self.workflow.deck().values()],
                                 "fire_ready": not cfg.missing_for_fire(), "gaps": cfg.missing_for_fire(),
                                 "target": cfg.target.host, "reset_mode": cfg.reset.mode,
                                 "reset_target": {k: cfg.reset.proxmox.get(k) for k in ("node", "vmid", "snapshot")},
                                 "dashboard_url": cfg.siem.options.get("dashboard_url", ""),
                                 "events_available": bool(cfg.siem.options.get("events_index"))})
            elif route.path == "/api/config":
                self._json(200, config.public_profile(self.workflow.cfg, self.server.config_path))
            elif route.path == "/api/scores":
                self._json(200, self.workflow.scores())
            elif route.path == "/api/cases":
                self._json(200, self.workflow.cases())
            elif route.path in ("/api/case", "/api/export"):
                query = parse_qs(route.query)
                case_id = query.get("id", [""])[0]
                if route.path == "/api/case":
                    self._json(200, self.workflow.get(case_id))
                else:
                    fmt = query.get("format", ["markdown"])[0]
                    body = self.workflow.export(case_id, fmt)
                    self._send(200, body.encode(), "text/plain; charset=utf-8", case_id + (".json" if fmt == "json" else ".md"))
            else:
                self._json(404, {"error": "not found"})
        except (SchemaError, config.ConfigError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception:
            self._json(500, {"error": "could not load the requested resource"})

    def do_POST(self):
        if not self._authorize(api=True):
            return
        try:
            body = self._read_body()
            case_id = body.get("case_id", "")
            if self.path == "/api/lay":
                live = boolean(body.get("fire", False), "fire")
                reset_first = boolean(body.get("reset", False), "reset")
                if live and body.get("confirm") is not True:
                    raise FireBlocked("confirm the named target before running a live exercise")
                result = self.workflow.create(body.get("scenario") or None, body.get("seed"), live,
                                              reset_first, body.get("replay_of"))
                if live:
                    thread = threading.Thread(target=self.workflow.run_live, args=(result["id"], True), daemon=True)
                    thread.start()
            elif self.path == "/api/draft":
                result = self.workflow.save_draft(case_id, body.get("verdict", {}), body.get("version"))
            elif self.path == "/api/grade":
                result = self.workflow.submit(case_id, body.get("verdict", {}))
            elif self.path == "/api/alerts":
                result = self.workflow.collect(case_id, body.get("kind", "alerts"), body.get("limit", 2000))
            elif self.path == "/api/detection":
                result = self.workflow.detection(case_id, body.get("rule_id"), body.get("revision"), body.get("rule_text"), body.get("minimum", 1), body.get("maximum"))
            elif self.path == "/api/config":
                result = self._save_config(body)
            else:
                self._json(404, {"error": "not found"})
                return
            self._json(200, result)
        except BusyError as exc:
            self._json(409, {"error": str(exc)})
        except (SchemaError, config.ConfigError, FireBlocked, ResetBlocked, ValueError) as exc:
            self._json(400, {"error": str(exc)})
        except OSError:
            self._json(502, {"error": "lab service unavailable; check connectivity and credentials, then retry"})
        except Exception:
            self._json(500, {"error": "operation failed; your saved case remains available"})


def make_httpd(host: str = "127.0.0.1", port: int = 8787, cfg: config.RangeConfig | None = None,
               config_path: str | Path | None = None) -> ThreadingHTTPServer:
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("refusing to bind off localhost")
    httpd = ThreadingHTTPServer((host, port), Handler)
    try:
        httpd.session_token = secrets.token_urlsafe(32)
        httpd.config_path = str(config_path or config.default_path())
        httpd.workflow = Workflow(cfg if cfg is not None else config.load())
        httpd.workflow.recover()
        return httpd
    except Exception:
        httpd.server_close()
        raise


def serve(host: str = "127.0.0.1", port: int = 8787, cfg: config.RangeConfig | None = None,
          config_path: str | Path | None = None):
    httpd = make_httpd(host, port, cfg, config_path)
    print(f"Draghunt dashboard: http://{host}:{httpd.server_port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
