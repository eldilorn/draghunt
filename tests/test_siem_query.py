"""Wazuh adapter query parsing, tested without a live indexer via a fake _request."""
import unittest
from datetime import datetime, timezone

from draghunt.siem import get_adapter, Alert


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
        a.query_alerts(start, end, "001", limit=50)
        self.assertIn("wazuh-alerts-*", cap["path"])
        filters = cap["body"]["query"]["bool"]["filter"]
        self.assertIn({"term": {"agent.id": "001"}}, filters)
        rng = filters[0]["range"]["timestamp"]
        self.assertEqual(rng["gte"], "2026-09-07T16:00:00Z")
        self.assertEqual(rng["lte"], "2026-09-07T16:05:00Z")
        self.assertEqual(cap["body"]["size"], 50)

    def test_normalizes_hits_to_alerts(self):
        a, _ = self._adapter()
        alerts = a.query_alerts(datetime.now(timezone.utc), datetime.now(timezone.utc), "001")
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
            a.query_alerts(datetime.now(timezone.utc), datetime.now(timezone.utc), "001")

    def test_query_cannot_be_unscoped(self):
        a, cap = self._adapter()
        with self.assertRaisesRegex(ValueError, "agent_id is required"):
            a.query_alerts(datetime.now(timezone.utc), datetime.now(timezone.utc), "")
        self.assertNotIn("body", cap)  # rejected before any request was built


if __name__ == "__main__":
    unittest.main()


class TestScopedCollection(unittest.TestCase):
    def test_pagination_preserves_raw_and_scopes_target(self):
        a = get_adapter('wazuh', {'indexer_url':'https://indexer.test'})
        calls = []
        def hit(i):
            return {'_id':str(i),'_index':'wazuh-alerts-test','_source':{'timestamp':'2026-09-08T12:00:00Z','agent':{'id':'001'},'data':{'srcip':'10.0.0.5'},'full_log':'event '+str(i)}}
        pages = [{'hits':{'total':{'value':3,'relation':'eq'},'hits':[hit(1),hit(2)]},'_scroll_id':'first'},
                 {'hits':{'hits':[hit(3)]},'_scroll_id':'second'}]
        def request(path, body, method='POST'):
            calls.append((path,body,method))
            return {} if method=='DELETE' else pages.pop(0)
        a._request = request
        start = datetime(2026,9,8,12,tzinfo=timezone.utc)
        batch = a.collect(start,start,'001',limit=10)
        self.assertTrue(batch.complete)
        self.assertEqual(len(batch.alerts),3)
        self.assertEqual(batch.alerts[0].raw['data']['srcip'],'10.0.0.5')
        self.assertIn({'term':{'agent.id':'001'}},calls[0][1]['query']['bool']['filter'])
        self.assertEqual(calls[-1],('/_search/scroll',{'scroll_id':['second']},'DELETE'))
        self.assertEqual(len({a.event_id for a in batch.alerts}),3)

    def test_truncation_and_partial_shards_are_reported(self):
        for extra in ({},{'timed_out':True},{'_shards':{'failed':1}}):
            a = get_adapter('wazuh', {'indexer_url':'https://indexer.test'})
            a._request = lambda *args,**kwargs: {'hits':{'total':{'value':3,'relation':'eq'},'hits':[{'_id':'1','_source':{}}]},**extra}
            batch = a.collect(datetime.now(timezone.utc),datetime.now(timezone.utc),'001',limit=1)
            self.assertFalse(batch.complete)
            self.assertEqual(batch.total,3)

    def test_raw_event_source_is_explicit(self):
        a = get_adapter('wazuh', {'indexer_url':'https://indexer.test'})
        with self.assertRaisesRegex(ValueError,'raw event indexing'):
            a.collect(datetime.now(timezone.utc),datetime.now(timezone.utc),'001',kind='events')
        with self.assertRaises(ValueError):
            a.collect(datetime.now(timezone.utc),datetime.now(timezone.utc),'')
