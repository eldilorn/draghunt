"""Wazuh adapter — the one SIEM shipped today.

Pulls alerts by querying the Wazuh indexer (the OpenSearch behind the Wazuh
dashboard) for the `wazuh-alerts-*` index over a time window. Uses stdlib
urllib so the core stays dependency-free.

The network call is only made when query_alerts runs (phase 4 wires it into the
UI). Defining it now fixes the contract every other adapter follows.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any

from . import Alert, SiemAdapter, register


@register("wazuh")
class WazuhAdapter(SiemAdapter):
    def _ctx(self) -> ssl.SSLContext | None:
        if str(self.options.get("verify_tls", "false")).lower() in ("false", "0", "no"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return None

    def _request(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        base = str(self.options.get("indexer_url", "")).rstrip("/")
        if not base:
            raise RuntimeError("wazuh: indexer_url not configured")
        user = self.options.get("username", "")
        pw = self.options.get("password", "") or ""
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        req = urllib.request.Request(
            f"{base}{path}",
            data=json.dumps(body).encode(),
            headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, context=self._ctx(), timeout=15) as resp:
            return json.loads(resp.read().decode())

    def query_alerts(self, start: datetime, end: datetime, limit: int = 200) -> list[Alert]:
        index = self.options.get("index", "wazuh-alerts-*")
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {"range": {"timestamp": {
                "gte": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "lte": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }}},
        }
        data = self._request(f"/{index}/_search", query)
        out: list[Alert] = []
        for hit in data.get("hits", {}).get("hits", []):
            s = hit.get("_source", {})
            rule = s.get("rule", {})
            agent = s.get("agent", {})
            out.append(Alert(
                timestamp=s.get("timestamp", ""),
                rule=str(rule.get("id", "?")),
                level=rule.get("level", "?"),
                source=agent.get("name", agent.get("ip", "?")),
                description=rule.get("description", ""),
                raw=s,
            ))
        return out

    def health(self) -> tuple[bool, str]:
        base = str(self.options.get("indexer_url", "")).rstrip("/")
        if not base:
            return (False, "indexer_url not configured")
        try:
            req = urllib.request.Request(f"{base}/", method="GET")
            user = self.options.get("username", "")
            pw = self.options.get("password", "") or ""
            token = base64.b64encode(f"{user}:{pw}".encode()).decode()
            req.add_header("Authorization", f"Basic {token}")
            with urllib.request.urlopen(req, context=self._ctx(), timeout=8) as resp:
                return (resp.status == 200, f"HTTP {resp.status}")
        except (urllib.error.URLError, OSError) as exc:
            return (False, f"unreachable: {exc}")
