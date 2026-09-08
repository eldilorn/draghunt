"""Regression coverage for complete exercises and failure boundaries; no real lab calls."""
import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from dataclasses import asdict, replace
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

from draghunt import catalog, fire, telemetry, cli
from draghunt.config import RangeConfig, ConfigError, load
from draghunt.grader import grade
from draghunt.schema import GroundTruth, Verdict, SchemaError
from draghunt.siem import Alert, AlertBatch
from draghunt.store import BusyError
from draghunt.reset import ResetResult, ResetStep
from draghunt.workflow import Workflow


class WorkflowFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cfg = RangeConfig(data_dir=str(Path(self.temp.name) / 'data'))
        self.workflow = Workflow(self.cfg)

    def correct_verdict(self, case_id):
        doc = self.workflow.store.get(case_id)
        gt = doc['truth']
        return {k: gt[k] for k in ('disposition', 'technique', 'source_ip', 'account', 'succeeded')}

class WorkflowTest(WorkflowFixture):
    def test_draft_resume_submit_export_and_idempotent_grade(self):
        case = self.workflow.create('DEMO-BRUTE', 7)
        verdict = {**self.correct_verdict(case['id']), 'narrative': 'A repeated SSH guessing attempt.',
                   'timeline': 'Failures then acceptance; E-0001.', 'assets': 'moria', 'impact': 'Account access',
                   'actions': 'Revoke credentials and review activity.', 'confidence': 'high',
                   'evidence_ids': ['E-0001'], 'self_review': 'Distinguished observed authentication from unobserved follow-on activity.'}
        saved = self.workflow.save_draft(case['id'], verdict, 0)
        reopened = Workflow(self.cfg)
        self.assertEqual(reopened.get(case['id'])['draft']['narrative'], verdict['narrative'])
        with self.assertRaises(BusyError):
            reopened.save_draft(case['id'], verdict, 0)
        self.assertEqual(saved['draft_version'], 1)
        result = reopened.submit(case['id'], verdict)
        self.assertEqual(result['submission']['finding_score']['total'], 100)
        self.assertEqual(result['submission']['report_score']['total'], 100)
        self.assertIn('debrief', result)
        reopened.submit(case['id'], {'disposition': 'benign'})
        self.assertEqual(reopened.scores()['attempts'], 1)
        self.assertIn(verdict['narrative'], reopened.export(case['id'], 'markdown'))
        self.assertIn('raw', json.loads(reopened.export(case['id']))['events'][0])

    def test_blind_payload_contains_no_truth_or_plan(self):
        case = self.workflow.create()
        self.assertEqual(case['title'], 'Blind assessment')
        for key in ('truth', 'intended', 'seed', 'scenario', 'execution', 'fire_plan', 'debrief'):
            self.assertNotIn(key, case)
        self.assertNotIn('DEMO-', case['id'])
        self.assertNotIn('DEMO-', case['brief'])
        self.assertEqual(self.workflow.cases()[0]['title'], 'Blind assessment')
        path = self.workflow.store.root / 'sealed' / (case['id'] + '.json')
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.workflow.store.db.stat().st_mode), 0o600)

    def test_incomplete_draft_is_preserved_but_invalid_submission_rejected(self):
        case = self.workflow.create('DEMO-BRUTE', 7)
        draft = {'source_ip': '192.', 'technique': 'T', 'narrative': 'Work in progress'}
        self.workflow.save_draft(case['id'], draft)
        self.assertEqual(self.workflow.get(case['id'])['draft'], draft)
        with self.assertRaises(SchemaError):
            self.workflow.submit(case['id'], {'disposition': 'malicious', **draft})

    def test_random_case_can_be_reproduced_from_recorded_seed(self):
        first = self.workflow.create()
        stored = self.workflow.store.get(first['id'])
        second = self.workflow.create(seed=stored['seed'])
        replayed = self.workflow.store.get(second['id'])
        self.assertEqual(stored['scenario'], replayed['scenario'])
        for key in ('source_ip','account','succeeded'):
            self.assertEqual(stored['intended'][key], replayed['intended'][key])

    def test_citations_must_belong_to_case(self):
        case = self.workflow.create('DEMO-BRUTE', 7)
        with self.assertRaises(SchemaError):
            self.workflow.submit(case['id'], {**self.correct_verdict(case['id']), 'evidence_ids': ['not-a-saved-event']})
        self.assertEqual(self.workflow.scores()['attempts'], 0)

    def test_replay_uses_original_parameters_and_does_not_inflate_scores(self):
        case = self.workflow.create('DEMO-BRUTE', 7)
        self.workflow.submit(case['id'], self.correct_verdict(case['id']))
        replay = self.workflow.create(replay_of=case['id'])
        a, b = (self.workflow.store.get(c['id']) for c in (case, replay))
        self.assertEqual((a['seed'], a['variant']), (b['seed'], b['variant']))
        self.workflow.submit(replay['id'], self.correct_verdict(replay['id']))
        self.assertEqual(self.workflow.scores()['attempts'], 1)
        self.assertEqual(len(self.workflow.cases()), 2)

    def test_synthetic_scenarios_cannot_fire(self):
        with self.assertRaisesRegex(SchemaError, 'synthetic'):
            self.workflow.create('DEMO-BRUTE', 7, live=True)

    def test_dns_unknown_facts_are_excluded(self):
        case = catalog.lay('DEMO-DNSEXFIL', 7)
        self.assertIsNone(case.ground_truth.account)
        self.assertIsNone(case.ground_truth.succeeded)
        self.assertEqual(case.ground_truth.technique, 'T1048.003')
        gt = case.ground_truth
        report = grade(gt, Verdict(disposition=gt.disposition, technique=gt.technique, source_ip=gt.source_ip))
        self.assertEqual(report.total, 100)
        self.assertEqual(sum(i.weight for i in report.items if i.dimension in ('account', 'succeeded')), 0)

    def test_webshell_has_process_or_rejection_evidence(self):
        outcomes = set()
        for seed in range(20):
            case = catalog.lay('DEMO-WEBSHELL', seed)
            blob = '\n'.join(telemetry.generate(case))
            outcomes.add(case.ground_truth.succeeded)
            self.assertIn('exe=/usr/bin/id' if case.ground_truth.succeeded else 'result=rejected', blob)
            self.assertIsNone(case.ground_truth.account)
        self.assertEqual(outcomes, {True, False})

    def test_benign_control_has_authorization_evidence(self):
        case = catalog.lay('DEMO-MAINTENANCE', 7)
        self.assertEqual(case.ground_truth.disposition, 'benign')
        blob = '\n'.join(telemetry.generate(case))
        self.assertIn('approved', blob)
        self.assertIn(case.ground_truth.account, blob)
        self.assertIn(case.ground_truth.source_ip, blob)
        self.assertIsNone(case.ground_truth.technique)

    def test_invalid_case_id_and_unknown_case(self):
        for case_id in ('../../secret', '20260908-120000-ABC\n', '20260908-120000-ABC'):
            with self.assertRaises(SchemaError):
                self.workflow.get(case_id)


class LiveFixture(WorkflowFixture):
    def setUp(self):
        super().setUp()
        self.cfg.attacker.host, self.cfg.attacker.user = '10.0.0.5', 'kali'
        self.cfg.target.host, self.cfg.target.agent_id = '10.0.0.6', '001'
        self.cfg.siem.options = {'indexer_url': 'https://indexer.test'}
        self.cfg.siem.ingest_wait = 0
        deck_dir = Path(self.temp.name) / 'catalog'
        deck_dir.mkdir()
        scenario = asdict(catalog.load_catalog()['DEMO-BRUTE'])
        scenario.update(id='PRIVATE-01', live=True)
        (deck_dir / 'private.json').write_text(json.dumps(scenario))
        self.cfg.catalog_dir = str(deck_dir)
        self.real_preflight = fire.wait_ready
        preflight_patch = patch('draghunt.workflow.fire.wait_ready')
        self.preflight = preflight_patch.start()
        self.addCleanup(preflight_patch.stop)
        adapter_patch = patch('draghunt.workflow.get_adapter')
        self.adapter_patch = adapter_patch.start()
        self.addCleanup(adapter_patch.stop)
        self.adapter = self.adapter_patch.return_value
        self.adapter.health.return_value = (True, 'ok')
        self.adapter.collect.return_value = AlertBatch([], 0, True)

    # Base offline tests explicitly use the public deck.
    def create_live(self, reset_first=False):
        return self.workflow.create('PRIVATE-01', 7, live=True, reset_first=reset_first)

    def result(self, case_id, returncode=0, succeeded=False):
        stored = self.workflow.store.get(case_id)
        start = datetime.now(timezone.utc) - timedelta(minutes=3)
        end = start + timedelta(seconds=5)
        start, end = (v.strftime('%Y-%m-%dT%H:%M:%SZ') for v in (start, end))
        truth = {**stored['intended'], 'source_ip': '10.0.0.5', 'succeeded': succeeded}
        body = {'protocol_version': 1, 'case_id': case_id, 'scenario_id': 'PRIVATE-01', 'target': '10.0.0.6',
                'status': 'completed', 'ground_truth': truth, 'evidence': ['target audit verification'],
                'completed_actions': ['authentication exercise'], 'started_utc': start, 'finished_utc': end}
        return fire.FireResult('PRIVATE-01', returncode, start, end, 'MOCK', stdout=json.dumps(body))

class LiveWorkflowTest(LiveFixture):
    def test_observed_source_and_outcome_replace_intention(self):
        case = self.create_live()
        with patch('draghunt.workflow.fire.execute', return_value=self.result(case['id'], succeeded=False)):
            result = self.workflow.run_live(case['id'], confirm=True)
        self.assertEqual(result['state'], 'awaiting_telemetry')
        stored = self.workflow.store.get(case['id'])
        self.assertEqual(stored['truth']['source_ip'], '10.0.0.5')
        self.assertFalse(stored['truth']['succeeded'])
        self.assertTrue(stored['intended']['succeeded'])
        self.assertNotIn('debrief', result)
        with self.assertRaises(SchemaError):
            self.workflow.submit(case['id'], self.correct_verdict(case['id']))

    def test_reset_failure_stops_fire(self):
        self.cfg.reset.mode = 'snapshot'
        case = self.create_live(reset_first=True)
        with patch('draghunt.workflow.reset.reset_target', return_value=ResetResult([ResetStep('snapshot',False,'failure')])), patch('draghunt.workflow.fire.execute') as execute:
            result = self.workflow.run_live(case['id'], confirm=True)
        self.assertEqual(result['state'], 'reset_failed')
        execute.assert_not_called()
        with self.assertRaises(SchemaError):
            self.workflow.submit(case['id'], {'disposition': 'malicious'})

    def test_nonzero_and_malformed_results_are_not_gradeable(self):
        for code in (7, 0):
            case = self.create_live()
            result = self.result(case['id'], returncode=code)
            if code == 0:
                result.stdout = '{}'
            with patch('draghunt.workflow.fire.execute', return_value=result):
                saved = self.workflow.run_live(case['id'], confirm=True)
            self.assertEqual(saved['state'], 'execution_failed' if code else 'execution_unknown')
            self.assertIsNone(self.workflow.store.get(case['id'])['truth'])
        self.assertEqual(self.workflow.scores()['attempts'], 0)

    def test_target_lock_blocks_other_runs(self):
        case = self.create_live()
        with self.workflow.store.target_lock(self.cfg.target.host), patch('draghunt.workflow.fire.execute') as execute:
            result = self.workflow.run_live(case['id'], confirm=True)
        self.assertEqual(result['state'], 'blocked')
        execute.assert_not_called()

    def test_evidence_is_retained_and_detection_requires_complete_late_snapshot(self):
        case = self.create_live()
        with patch('draghunt.workflow.fire.execute', return_value=self.result(case['id'])):
            self.workflow.run_live(case['id'], confirm=True)
        stored = self.workflow.store.get(case['id'])
        event = Alert(stored['observed']['finished_utc'],'100001',8,'target','SSH exercise',{'full_log':'failed password from 10.0.0.5', 'data':{'srcip':'10.0.0.5'}},'E-one')
        self.adapter.collect.return_value = AlertBatch([event], 1, False, 'partial')
        snapshot = self.workflow.collect(case['id'])
        self.assertEqual(snapshot['events'][0]['raw']['data']['srcip'], '10.0.0.5')
        self.workflow.submit(case['id'], {**self.correct_verdict(case['id']), 'evidence_ids':['E-one']})
        with self.assertRaises(SchemaError):
            self.workflow.detection(case['id'],'100001','v1','<rule/>')
        self.adapter.collect.return_value = AlertBatch([event], 1, True)
        self.workflow.collect(case['id'])
        result = self.workflow.detection(case['id'],'100001','v1','<rule/>')
        self.assertTrue(result['detections'][0]['passed'])
        self.assertEqual(result['detections'][0]['matches'], 1)
        self.assertEqual(result['detections'][0]['latency_seconds'], 5)
        self.workflow.store.update(case['id'], lambda d: d.update(telemetry_ready_after='2099-01-01T00:00:00Z'))
        with self.assertRaises(SchemaError):
            self.workflow.detection(case['id'],'100001','v2','<rule/>')

    def test_cli_returns_failure_when_fire_fails(self):
        with patch('draghunt.cli.config.load', return_value=self.cfg), patch('draghunt.workflow.fire.execute', return_value=fire.FireResult('PRIVATE-01',7,'2026-09-08T00:00:00Z','2026-09-08T00:00:01Z','MOCK')), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(['lay','--scenario','PRIVATE-01','--fire'])
        self.assertEqual(rc, 1)


class ValidationTest(unittest.TestCase):
    def test_boolean_strings_are_rejected(self):
        truth = catalog.seal_dict(catalog.lay('DEMO-BRUTE', 7).ground_truth)
        for value in ('false', 'true', 0, 1, [], {}):
            with self.assertRaises(SchemaError):
                Verdict.from_dict({'disposition':'malicious','succeeded':value})
            with self.assertRaises(SchemaError):
                GroundTruth.from_dict({**truth, 'succeeded':value})

    def test_environment_only_secrets_and_invalid_config(self):
        with patch.dict(os.environ, {'DRAGHUNT_SIEM_PASSWORD':'secret','DRAGHUNT_PROXMOX_SECRET':'px'}):
            cfg = RangeConfig.from_dict({'siem':{'wazuh':{}},'reset':{'proxmox':{}}})
        self.assertEqual(cfg.siem.options['password'],'secret')
        self.assertEqual(cfg.reset.proxmox['token_secret'],'px')
        for doc in ({'reset':{'mode':'snapshott'}},{'siem':{'wazuh':{'verify_tls':'false'}}},{'attacker':{'host':'host; command'}},{'runner':{'entry':'../run.sh'}}):
            with self.assertRaises(ConfigError):
                RangeConfig.from_dict(doc)

    def test_relative_config_paths_resolve_against_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'range.toml'
            path.write_text('[control]\ndata_dir="data"\ncatalog_dir="catalog"\n')
            cfg = load(path)
            self.assertEqual(cfg.data_dir, str(Path(temp)/'data'))
            self.assertEqual(cfg.catalog_dir, str(Path(temp)/'catalog'))

    def test_remote_home_expands_without_evaluating_path_text(self):
        cfg = RangeConfig()
        cfg.attacker.user, cfg.attacker.host = 'kali', '10.0.0.5'
        cfg.runner.dir = '~/folder with spaces'
        command = fire.ssh_command(cfg, {'ACTION':'preflight'})[-1]
        self.assertIn('"$HOME"/', command)
        self.assertIn("'folder with spaces/fire.sh'", command)


class LiveRecoveryTest(LiveFixture):
    # Separate cases below use the same fully mocked range fixture.
    def test_reset_waits_for_readiness_before_execution(self):
        self.cfg.reset.mode = 'snapshot'
        case = self.create_live(reset_first=True)
        with patch('draghunt.workflow.reset.reset_target',return_value=ResetResult([ResetStep('snapshot',True,'done')])), patch('draghunt.workflow.fire.execute',return_value=self.result(case['id'])):
            result = self.workflow.run_live(case['id'],confirm=True)
        self.assertEqual(result['state'],'awaiting_telemetry')
        self.assertEqual(self.preflight.call_count,2)
        self.assertTrue(self.preflight.call_args_list[0].kwargs['runner_only'])
        self.assertEqual(self.preflight.call_args_list[1].kwargs,{})

    def test_unknown_remote_outcome_blocks_until_confirmed_reset(self):
        case = self.create_live()
        with patch('draghunt.workflow.fire.execute',return_value=self.result(case['id'],returncode=-1)):
            self.workflow.run_live(case['id'],confirm=True)
        other = self.create_live()
        with patch('draghunt.workflow.fire.execute') as execute:
            self.workflow.run_live(other['id'],confirm=True)
        execute.assert_not_called()
        self.cfg.reset.mode='cleanup'
        with patch('draghunt.cli.config.load',return_value=self.cfg), patch('draghunt.cli.reset.reset_target',return_value=ResetResult([ResetStep('cleanup',True,'done')])), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['reset','--confirm']),0)
        self.assertEqual(self.workflow.store.get(case['id'])['state'],'execution_failed')

    def test_recovery_does_not_touch_locked_live_run(self):
        case = self.create_live()
        self.workflow._state(case['id'],'running')
        with self.workflow.store.target_lock(self.cfg.target.host):
            Workflow(self.cfg).recover()
        self.assertEqual(self.workflow.store.get(case['id'])['state'],'running')
        Workflow(self.cfg).recover()
        self.assertEqual(self.workflow.store.get(case['id'])['state'],'execution_unknown')

    def test_private_catalog_keeps_public_synthetic_exercises_available(self):
        case = self.workflow.create('DEMO-BRUTE',7)
        self.assertEqual(case['state'],'investigating')
        self.assertIn('PRIVATE-01',self.workflow.deck())
        self.assertIn('DEMO-MAINTENANCE',self.workflow.deck())

    def test_unavailable_siem_stops_execution(self):
        case = self.create_live()
        self.adapter.health.return_value=(False,'offline')
        with patch('draghunt.workflow.fire.execute') as execute:
            result=self.workflow.run_live(case['id'],confirm=True)
        self.assertEqual(result['state'],'preflight_failed')
        execute.assert_not_called()

    def test_runner_only_preflight_can_precede_booting_target(self):
        case = self.create_live()
        stored=self.workflow.store.get(case['id'])
        hunt=catalog.Hunt(GroundTruth.from_dict(stored['intended']),catalog.Scenario.from_dict(stored['scenario']),stored['seed'],stored['variant'])
        body={'protocol_version':1,'case_id':case['id'],'scenario_id':'PRIVATE-01','target':self.cfg.target.host,
              'ready':False,'checks':{'runner':True,'target':False,'telemetry':False}}
        from types import SimpleNamespace
        self.cfg.runner.ready_timeout=0
        with patch('draghunt.fire.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(body))) as run:
            self.real_preflight(hunt,self.cfg,case['id'],runner_only=True)
            with self.assertRaises(fire.FireBlocked):
                self.real_preflight(hunt,self.cfg,case['id'])
        self.assertIn('ACTION=preflight',run.call_args.args[0][-1])

    def test_benign_control_records_false_positive(self):
        metadata=asdict(catalog.load_catalog()['DEMO-MAINTENANCE'])
        metadata.update(id='CONTROL-01',live=True)
        (Path(self.cfg.catalog_dir)/'control.json').write_text(json.dumps(metadata))
        case=self.workflow.create('CONTROL-01',7,live=True)
        result=self.result(case['id'])
        body=json.loads(result.stdout)
        body['scenario_id']='CONTROL-01'
        result.scenario_id='CONTROL-01'
        body['ground_truth']['succeeded']=None
        result.stdout=json.dumps(body)
        with patch('draghunt.workflow.fire.execute',return_value=result):
            self.workflow.run_live(case['id'],confirm=True)
        stored=self.workflow.store.get(case['id'])
        event=Alert(stored['observed']['finished_utc'],'100001',8,'target','False positive',{'full_log':'authorized maintenance'},'E-control')
        self.adapter.collect.return_value=AlertBatch([event],1,True)
        self.workflow.collect(case['id'])
        self.workflow.submit(case['id'],self.correct_verdict(case['id']))
        with self.assertRaises(SchemaError):
            self.workflow.detection(case['id'],'100001','v1','<rule/>',minimum=1)
        checked=self.workflow.detection(case['id'],'100001','v1','<rule/>',minimum=0,maximum=0)['detections'][-1]
        self.assertTrue(checked['control'])
        self.assertFalse(checked['passed'])
        self.assertEqual(checked['matches'],1)
