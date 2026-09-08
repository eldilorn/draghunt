"""Verify the private runner's result contract without executing any attack."""
import json
import unittest
from dataclasses import asdict
from datetime import datetime, timezone

from draghunt import catalog, fire
from draghunt.schema import SchemaError


class TestProtocol(unittest.TestCase):
    def setUp(self):
        self.case=catalog.lay('DEMO-BRUTE',7)
        self.timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.body={'protocol_version':1,'case_id':'test-case','scenario_id':'DEMO-BRUTE','target':'10.0.0.6',
                   'status':'completed','ground_truth':asdict(self.case.ground_truth),
                   'started_utc':self.timestamp,'finished_utc':self.timestamp,
                   'evidence':['observed authentication check'], 'completed_actions':['authentication exercise']}

    def result(self):
        return fire.FireResult('DEMO-BRUTE',0,self.timestamp,self.timestamp,'mock',stdout=json.dumps(self.body))

    def test_actual_source_and_failed_objective_are_accepted(self):
        self.body['ground_truth'].update(source_ip='10.0.0.5',succeeded=False)
        truth,_=fire.observed_truth(self.result(),self.case,'test-case','10.0.0.6')
        self.assertEqual(truth.source_ip,'10.0.0.5')
        self.assertFalse(truth.succeeded)

    def test_case_identity_and_proof_are_required(self):
        for key,value in (('case_id','other-case'),('protocol_version',True),('protocol_version',2),('evidence',[]),('completed_actions',[]),('status','partial'),('target','other-target')):
            with self.subTest(key=key):
                old=self.body[key];self.body[key]=value
                with self.assertRaises(SchemaError):
                    fire.observed_truth(self.result(),self.case,'test-case','10.0.0.6')
                self.body[key]=old

    def test_unknown_outcome_excludes_that_dimension(self):
        self.body['ground_truth']['succeeded']=None
        truth,_=fire.observed_truth(self.result(),self.case,'test-case','10.0.0.6')
        self.assertIsNone(truth.succeeded)

    def test_stale_naive_and_boolean_text_results_are_rejected(self):
        for timestamp in ('2000-01-01T00:00:00Z','2026-09-08T12:00:00'):
            self.body['started_utc']=timestamp
            with self.assertRaises(SchemaError):
                fire.observed_truth(self.result(),self.case,'test-case','10.0.0.6')
        self.body['started_utc']=self.timestamp
        self.body['ground_truth']['succeeded']='false'
        with self.assertRaises(SchemaError):
            fire.observed_truth(self.result(),self.case,'test-case','10.0.0.6')
