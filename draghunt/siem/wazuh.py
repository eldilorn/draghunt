"""Scoped Wazuh evidence collection with complete events and bounded scroll pagination."""
from __future__ import annotations

import base64
import hashlib
import json
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import quote

from . import Alert, AlertBatch, SiemAdapter, register


@register("wazuh")
class WazuhAdapter(SiemAdapter):
    def _ctx(self):
        if self.options.get("verify_tls", True) is False:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return ssl.create_default_context(cafile=self.options.get("ca_file"))

    def _request(self, path: str, body: dict | None, method: str = "POST") -> dict:
        base = str(self.options.get("indexer_url", "")).rstrip("/")
        if not base:
            raise RuntimeError("wazuh: indexer_url not configured")
        token = base64.b64encode(f"{self.options.get('username', '')}:{self.options.get('password') or ''}".encode()).decode()
        req = urllib.request.Request(f"{base}{path}", data=None if body is None else json.dumps(body).encode(),
                                     headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"}, method=method)
        with urllib.request.urlopen(req, context=self._ctx(), timeout=15) as resp:
            return json.loads(resp.read().decode())

    @staticmethod
    def _query(start: datetime, end: datetime, size: int, agent_id: str = "") -> dict:
        if start.utcoffset() is None or end.utcoffset() is None or end < start:
            raise ValueError("query requires an ordered, timezone-aware time window")
        window = {"range": {"timestamp": {"gte": start.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                           "lte": end.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}}}
        query = {"bool": {"filter": [window, {"term": {"agent.id": agent_id}}]}} if agent_id else window
        return {"size": size, "track_total_hits": True, "sort": [{"timestamp": {"order": "asc"}}], "query": query}

    @staticmethod
    def _alert(hit: dict) -> Alert:
        raw = hit.get("_source", {})
        rule, agent = raw.get("rule", {}), raw.get("agent", {})
        identity = f"{hit.get('_index', '')}/{hit['_id']}" if hit.get("_id") else json.dumps(raw, sort_keys=True)
        event_id = "E-" + hashlib.sha256(identity.encode()).hexdigest()[:24]
        return Alert(raw.get("timestamp", ""), str(rule.get("id", "")), rule.get("level", ""),
                     agent.get("name", agent.get("ip", "")), rule.get("description", "Raw event"), raw, event_id)

    def query_alerts(self, start: datetime, end: datetime, limit: int = 200) -> list[Alert]:
        """Compatibility API. The case workflow uses collect() and its completeness metadata."""
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError("limit must be between 1 and 10000")
        index = quote(str(self.options.get("index", "wazuh-alerts-*")), safe="*,-_")
        data = self._request(f"/{index}/_search", self._query(start, end, limit))
        return [self._alert(hit) for hit in data.get("hits", {}).get("hits", [])]

    def collect(self, start: datetime, end: datetime, agent_id: str, limit: int = 2000,
                kind: str = "alerts") -> AlertBatch:
        if not agent_id:
            raise ValueError("target.agent_id is required to scope evidence")
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError("limit must be between 1 and 10000")
        if kind not in ("alerts", "events"):
            raise ValueError("unknown evidence source")
        index = self.options.get("events_index") if kind == "events" else self.options.get("index", "wazuh-alerts-*")
        if not index:
            raise ValueError("raw event indexing is not configured; set siem.wazuh.events_index after enabling Wazuh archives")
        scroll = None
        alerts = []
        total, exact, healthy = 0, True, True
        detail = ""
        try:
            data = self._request(f"/{quote(str(index), safe='*,-_')}/_search?scroll=1m", self._query(start, end, min(limit, 500), agent_id))
            count = data.get("hits", {}).get("total", {})
            if isinstance(count, dict):
                total = count.get("value", 0)
                exact = count.get("relation") == "eq"
            else:
                total = int(count)
            while True:
                scroll = data.get("_scroll_id") or scroll
                healthy = healthy and not data.get("timed_out", False) and data.get("_shards", {}).get("failed", 0) == 0
                hits = data.get("hits", {}).get("hits", [])
                alerts.extend(self._alert(h) for h in hits[:limit - len(alerts)])
                if not hits or len(alerts) >= limit or (exact and len(alerts) >= total):
                    break
                if not scroll:
                    detail = "indexer did not return a continuation ID"
                    break
                data = self._request("/_search/scroll", {"scroll": "1m", "scroll_id": scroll})
            unique = {a.event_id: a for a in alerts}
            complete = healthy and exact and len(unique) == total
            if not complete and not detail:
                detail = "partial results: increase the limit or check indexer timeouts/shard failures"
            return AlertBatch(list(unique.values()), total, complete, detail)
        finally:
            if scroll:
                try:
                    self._request("/_search/scroll", {"scroll_id": [scroll]}, method="DELETE")
                except (OSError, ValueError):
                    pass  # The bounded scroll context expires automatically.

    def health(self) -> tuple[bool, str]:
        try:
            self._request("/", None, method="GET")
            return True, "Indexer reachable"
        except (OSError, ValueError, RuntimeError) as exc:
            return False, str(exc)
