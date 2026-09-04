"""Tests for the deal -> telemetry -> history loop (stdlib unittest)."""
import tempfile
import unittest
from pathlib import Path

from dealer.catalog import deal, load_catalog
from dealer.telemetry import generate
from dealer.grader import grade
from dealer.schema import Verdict
from dealer import history


class TestCatalog(unittest.TestCase):
    def test_catalog_loads(self):
        deck = load_catalog()
        self.assertIn("DEMO-BRUTE", deck)

    def test_deal_is_deterministic(self):
        a = deal("DEMO-BRUTE", seed=42)
        b = deal("DEMO-BRUTE", seed=42)
        self.assertEqual(a.ground_truth.account, b.ground_truth.account)
        self.assertEqual(a.ground_truth.source_ip, b.ground_truth.source_ip)
        self.assertEqual(a.ground_truth.succeeded, b.ground_truth.succeeded)

    def test_dealt_truth_grades_perfectly(self):
        # A verdict that reads the sealed truth correctly should score 100.
        case = deal("DEMO-BRUTE", seed=7)
        gt = case.ground_truth
        v = Verdict(disposition=gt.disposition, technique=gt.technique,
                    source_ip=gt.source_ip, account=gt.account, succeeded=gt.succeeded)
        self.assertEqual(grade(gt, v).total, 100.0)

    def test_blind_brief_hides_the_answer(self):
        case = deal("DEMO-BRUTE", seed=7)
        brief = case.blind_brief
        self.assertNotIn(case.ground_truth.source_ip, brief)
        self.assertNotIn(str(case.ground_truth.account), brief)


class TestTelemetry(unittest.TestCase):
    def test_source_ip_and_account_appear_in_logs(self):
        case = deal("DEMO-BRUTE", seed=7)
        blob = "\n".join(generate(case))
        self.assertIn(case.ground_truth.source_ip, blob)
        self.assertIn(case.ground_truth.account, blob)

    def test_success_line_only_when_attack_succeeded(self):
        # find a seed that lands and one that doesn't, check the accepted line follows
        for seed in range(50):
            case = deal("DEMO-BRUTE", seed=seed)
            blob = "\n".join(generate(case))
            accepted_from_src = f"Accepted password for {case.ground_truth.account} from {case.ground_truth.source_ip}"
            if case.ground_truth.succeeded:
                self.assertIn(accepted_from_src, blob)

    def test_all_scenarios_generate(self):
        for sid in load_catalog():
            case = deal(sid, seed=1)
            self.assertGreater(len(generate(case)), 5)


class TestHistory(unittest.TestCase):
    def test_record_and_stats(self):
        with tempfile.TemporaryDirectory() as d:
            store = Path(d) / "h.jsonl"
            case = deal("DEMO-BRUTE", seed=7)
            gt = case.ground_truth
            v = Verdict(disposition=gt.disposition, technique=gt.technique,
                        source_ip=gt.source_ip, account=gt.account, succeeded=gt.succeeded)
            history.record(grade(gt, v), gt, store=store)
            history.record(grade(gt, Verdict(disposition="benign")), gt, store=store)
            s = history.stats(store=store)
            self.assertEqual(s.attempts, 2)
            self.assertEqual(s.passed, 1)
            self.assertEqual(s.streak, 0)  # last one failed
            self.assertIn(gt.tactic, s.by_tactic)


if __name__ == "__main__":
    unittest.main()
