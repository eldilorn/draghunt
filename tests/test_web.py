"""HTTP-level authorization and persisted report workflow, using a temporary range."""
import json
import re
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from pathlib import Path

from draghunt.config import RangeConfig
from draghunt.web import make_httpd


class WebTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = make_httpd(port=0, cfg=RangeConfig(data_dir=self.temp.name))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f'http://127.0.0.1:{self.server.server_port}'
        with urllib.request.urlopen(self.url) as response:
            self.page = response.read().decode()
            self.assertIn("script-src 'self'", response.headers['Content-Security-Policy'])
        self.token = re.search(r'name="session-token" content="([^"]+)"', self.page).group(1)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp.cleanup()

    def request(self, path, body=None, headers=None, token=True):
        request_headers = {'Content-Type':'application/json'}
        if token:
            request_headers['X-Draghunt-Token'] = self.token
        request_headers.update(headers or {})
        request = urllib.request.Request(self.url + path, data=None if body is None else json.dumps(body).encode(), headers=request_headers)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read().decode()

    def test_foreign_and_unauthenticated_requests_cannot_create_cases(self):
        for headers, token in (({},False),({'Origin':'https://outside.invalid'},True),({'Host':'outside.invalid'},True),({'Sec-Fetch-Site':'cross-site'},True)):
            status, _ = self.request('/api/lay', {'scenario':'DEMO-BRUTE','fire':True,'confirm':True}, headers, token)
            self.assertEqual(status, 403)
        self.assertEqual(self.server.workflow.cases(), [])
        self.assertEqual(self.request('/api/cases',token=False)[0],403)

    def test_strict_request_body_and_confirmation(self):
        self.assertEqual(self.request('/api/lay',{}, {'Content-Type':'text/plain'})[0],400)
        self.assertEqual(self.request('/api/lay', {'fire':'false'})[0],400)
        self.assertEqual(self.request('/api/lay', {'fire':True})[0],400)
        self.assertEqual(self.request('/api/lay', [1,2])[0],400)
        self.assertEqual(self.server.workflow.cases(), [])

    def test_http_loop_persists_report_and_hides_truth(self):
        status, body = self.request('/api/lay',{})
        self.assertEqual(status,200)
        case = json.loads(body)
        self.assertNotIn('truth',case)
        self.assertNotIn('fire_plan',case)
        self.assertEqual(case['title'],'Blind assessment')
        case_id = case['id']
        truth = self.server.workflow.store.get(case_id)['truth']
        verdict = {k:truth[k] for k in ('disposition','technique','source_ip','account','succeeded')}
        verdict.update(narrative='<img src=x onerror="window.injected=true">Evidence-based report',evidence_ids=['E-0001'])
        self.assertEqual(self.request('/api/draft', {'case_id':case_id,'verdict':verdict,'version':0})[0],200)
        reopened = json.loads(self.request('/api/case?id='+case_id)[1])
        self.assertEqual(reopened['draft']['narrative'],verdict['narrative'])
        self.assertNotIn('debrief',reopened)
        result = json.loads(self.request('/api/grade', {'case_id':case_id,'verdict':verdict})[1])
        self.assertEqual(result['submission']['finding_score']['total'],100)
        self.assertIn('debrief',result)
        self.request('/api/grade', {'case_id':case_id,'verdict':verdict})
        scores = json.loads(self.request('/api/scores')[1])
        self.assertEqual(scores['attempts'],1)
        exported = self.request('/api/export?id='+case_id+'&format=markdown')[1]
        self.assertIn(verdict['narrative'],exported)
        self.assertIn('E-0001',exported)

    def test_assets_and_path_protection(self):
        self.assertEqual(self.request('/app.js')[0],200)
        self.assertEqual(self.request('/app.css')[0],200)
        for asset in ('/favicon.png', '/mark-light.png', '/logo.png'):
            with urllib.request.urlopen(self.url + asset) as r:
                self.assertEqual((r.status, r.headers['Content-Type']), (200, 'image/png'), asset)
                self.assertTrue(r.read().startswith(b'\x89PNG'), asset)
        self.assertEqual(self.request('/api/case?id=../../etc/passwd')[0],400)
        self.assertEqual(self.request('/../../etc/passwd')[0],404)
        js = (Path(__file__).parents[1]/'draghunt/static/app.js').read_text()
        self.assertNotIn('innerHTML',js)

    def test_cross_site_navigation_loads_page_but_api_is_refused(self):
        # Opening the page from a link or bookmark is a cross-site navigation and must work;
        # cross-site API calls must still be refused.
        nav = {'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document'}
        self.assertEqual(self.request('/', headers=nav, token=False)[0], 200)
        self.assertEqual(self.request('/api/state', headers=nav)[0], 403)
        self.assertEqual(self.request('/api/lay', {'scenario': 'DEMO-BRUTE'}, headers=nav)[0], 403)
        self.assertEqual(self.server.workflow.cases(), [])


class ConfigEndpointTest(unittest.TestCase):
    """The Settings panel: GET redacts secrets, POST writes the profile and enables live runs."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cfg_path = Path(self.temp.name) / "range.toml"
        self.server = make_httpd(port=0, cfg=RangeConfig(data_dir=self.temp.name), config_path=str(self.cfg_path))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f'http://127.0.0.1:{self.server.server_port}'
        with urllib.request.urlopen(self.url) as response:
            self.token = re.search(r'name="session-token" content="([^"]+)"', response.read().decode()).group(1)

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5); self.temp.cleanup()

    def request(self, path, body=None):
        headers = {'Content-Type': 'application/json', 'X-Draghunt-Token': self.token}
        req = urllib.request.Request(self.url + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read().decode()

    def test_saves_profile_hides_secrets_and_enables_live(self):
        status, body = self.request('/api/config')
        self.assertEqual(status, 200)
        self.assertNotIn('password', json.loads(body)['siem'])   # only has_password is exposed
        self.assertGreater(len(json.loads(body)['gaps']), 0)

        form = {'attacker': {'host': '10.0.0.5', 'user': 'kali'},
                'target': {'host': '10.0.0.6', 'agent_id': '001'},
                'siem': {'indexer_url': 'https://indexer.test:9200', 'username': 'reader', 'password': 'sekret'}}
        status, body = self.request('/api/config', form)
        self.assertEqual(status, 200)
        saved = json.loads(body)
        self.assertEqual(saved['gaps'], [])              # now fire-ready
        self.assertTrue(saved['siem']['has_password'])
        self.assertNotIn('password', saved['siem'])      # value withheld; only has_password
        self.assertNotIn('sekret', body)
        self.assertEqual(self.cfg_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.server.workflow.cfg.target.host, '10.0.0.6')
        self.assertTrue(json.loads(self.request('/api/state')[1])['fire_ready'])

        # A blank secret on the next save keeps the stored one.
        self.request('/api/config', {**form, 'siem': {**form['siem'], 'password': ''}})
        self.assertEqual(self.server.workflow.cfg.siem.options['password'], 'sekret')

    def test_rejects_unsafe_profile(self):
        for bad in ({'siem': {'indexer_url': 'http://indexer.test'}},
                    {'target': {'host': '10.0.0.6'}, 'reset': {'mode': 'both', 'proxmox': {'vmid': '101', 'target_host': '10.9.9.9'}}}):
            self.assertEqual(self.request('/api/config', bad)[0], 400)

