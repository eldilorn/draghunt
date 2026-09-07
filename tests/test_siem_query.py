"""Wazuh adapter query parsing, tested without a live indexer via a fake _request."""
import unittest
from datetime import datetime, timezone

from dealer.siem import get_adapter, Alert


FAKE_RESPONSE = {
    "hits": {"hits": [
        {"_source": {
            "timestamp": "2026-09-07T16:00:05Z",
            "rule": {"id": "5710", "level": 5, "description": "sshd: failed password"},
            "agent": {"name": "moria", "ip": "10.0.0.6"},
        }},
        {"_source": {
            "timestamp": "2026-09-07T16:00:09Z",
            "rule": {"id": "5715", "level": 3, "description": "sshd: accepted password"},
            "agent": {"name": "moria"},
        }},
    ]}
}


class TestWazuhQuery(unittest.TestCase):
    def _adapter(self):
        a = get_adapter("wazuh", {"indexer_url": "https://x:9200", "index": "wazuh-alerts-*"})
        captured = {}

        def fake_request(path, body):
            captured["path"] = path
            captured["body"] = body
            return FAKE_RESPONSE

        a._request = fake_request  # type: ignore[attr-defined]
        return a, captured

    def test_builds_time_range_query(self):
        a, cap = self._adapter()
        start = datetime(2026, 9, 7, 16, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 9, 7, 16, 5, 0, tzinfo=timezone.utc)
        a.query_alerts(start, end, limit=50)
        self.assertIn("wazuh-alerts-*", cap["path"])
        rng = cap["body"]["query"]["range"]["timestamp"]
        self.assertEqual(rng["gte"], "2026-09-07T16:00:00Z")
        self.assertEqual(rng["lte"], "2026-09-07T16:05:00Z")
        self.assertEqual(cap["body"]["size"], 50)

    def test_normalizes_hits_to_alerts(self):
        a, _ = self._adapter()
        alerts = a.query_alerts(datetime.now(timezone.utc), datetime.now(timezone.utc))
        self.assertEqual(len(alerts), 2)
        self.assertIsInstance(alerts[0], Alert)
        self.assertEqual(alerts[0].rule, "5710")
        self.assertEqual(alerts[0].source, "moria")
        self.assertEqual(alerts[0].description, "sshd: failed password")
        # missing agent.ip still resolves to a source
        self.assertEqual(alerts[1].source, "moria")

    def test_missing_indexer_url_raises(self):
        a = get_adapter("wazuh", {})
        with self.assertRaises(RuntimeError):
            a.query_alerts(datetime.now(timezone.utc), datetime.now(timezone.utc))


if __name__ == "__main__":
    unittest.main()
