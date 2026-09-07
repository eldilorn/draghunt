"""Tests for phase-1 live-mode scaffolding: config, SIEM seam, fire plan."""
import tempfile
import unittest
from pathlib import Path

from draghunt.config import RangeConfig, load, EXAMPLE_TOML, ConfigError
from draghunt.siem import available, get_adapter, SiemAdapter
from draghunt.catalog import lay
from draghunt.fire import build_plan, execute, FirePlan, FireResult, FireBlocked


class TestConfig(unittest.TestCase):
    def test_empty_config_is_not_fire_ready(self):
        self.assertTrue(load("does-not-exist.toml").missing_for_fire())

    def test_example_toml_parses_and_is_fire_ready(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "range.toml"
            p.write_text(EXAMPLE_TOML)
            cfg = load(p)
            self.assertEqual(cfg.missing_for_fire(), [])
            self.assertEqual(cfg.siem.adapter, "wazuh")
            self.assertEqual(cfg.reset.mode, "both")

    def test_env_overrides_secret(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "range.toml"
            p.write_text(EXAMPLE_TOML)
            os.environ["DRAGHUNT_SIEM_PASSWORD"] = "sekret"
            try:
                cfg = load(p)
                self.assertEqual(cfg.siem.options["password"], "sekret")
            finally:
                del os.environ["DRAGHUNT_SIEM_PASSWORD"]

    def test_bad_toml_raises(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "range.toml"
            p.write_text("this = = broken")
            with self.assertRaises(ConfigError):
                load(p)


class TestSiemSeam(unittest.TestCase):
    def test_wazuh_registered(self):
        self.assertIn("wazuh", available())

    def test_get_adapter_returns_instance(self):
        a = get_adapter("wazuh", {"indexer_url": ""})
        self.assertIsInstance(a, SiemAdapter)

    def test_unknown_adapter_raises(self):
        with self.assertRaises(KeyError):
            get_adapter("splunk", {})

    def test_wazuh_health_without_config_is_false(self):
        ok, _ = get_adapter("wazuh", {}).health()
        self.assertFalse(ok)


class TestFirePlan(unittest.TestCase):
    def test_plan_not_ready_with_empty_config(self):
        plan = build_plan(lay("DEMO-BRUTE", seed=7), RangeConfig())
        self.assertFalse(plan.ready)
        self.assertIn("attacker.host", plan.gaps)

    def test_plan_ready_with_full_config(self):
        cfg = RangeConfig()
        cfg.attacker.host = "10.0.0.5"; cfg.attacker.user = "kali"
        cfg.target.host = "10.0.0.6"
        plan = build_plan(lay("DEMO-BRUTE", seed=7), cfg)
        self.assertTrue(plan.ready)
        self.assertEqual(plan.gaps, [])

    def test_plan_injects_sealed_params(self):
        case = lay("DEMO-BRUTE", seed=7)
        plan = build_plan(case, RangeConfig())
        self.assertEqual(plan.params["ACCOUNT"], case.ground_truth.account)
        self.assertEqual(plan.params["SUCCEED"], "yes" if case.ground_truth.succeeded else "no")
        self.assertEqual(plan.params["DRY_RUN"], "1")  # never fires in phase 1

    def test_dry_plan_marks_dry_run(self):
        plan = build_plan(lay("DEMO-BRUTE", seed=7), RangeConfig(), live=False)
        self.assertEqual(plan.params["DRY_RUN"], "1")

    def test_live_plan_flips_dry_run(self):
        plan = build_plan(lay("DEMO-BRUTE", seed=7), RangeConfig(), live=True)
        self.assertEqual(plan.params["DRY_RUN"], "0")


class TestFireGates(unittest.TestCase):
    def _ready_live_plan(self):
        cfg = RangeConfig()
        cfg.attacker.host = "10.0.0.5"; cfg.attacker.user = "kali"; cfg.target.host = "10.0.0.6"
        return build_plan(lay("DEMO-BRUTE", seed=7), cfg, live=True)

    def test_execute_without_confirm_refuses(self):
        with self.assertRaises(FireBlocked):
            execute(self._ready_live_plan(), confirm=False)

    def test_execute_dry_plan_refuses(self):
        plan = build_plan(lay("DEMO-BRUTE", seed=7), RangeConfig(), live=False)
        with self.assertRaises(FireBlocked):
            execute(plan, confirm=True)

    def test_execute_unready_live_plan_refuses(self):
        plan = build_plan(lay("DEMO-BRUTE", seed=7), RangeConfig(), live=True)
        with self.assertRaises(FireBlocked):
            execute(plan, confirm=True)

    def test_execute_runs_and_captures(self):
        # a ready, live plan whose command is a harmless local stand-in for the ssh
        plan = FirePlan("DEMO-BRUTE", {"SCN": "DEMO-BRUTE"},
                        ["bash", "-c", "echo hi; exit 0"], ready=True, gaps=[], live=True)
        r = execute(plan, confirm=True)
        self.assertTrue(r.ok)
        self.assertEqual(r.returncode, 0)
        self.assertIn("hi", r.stdout)
        w = r.window()
        self.assertIn("start", w)
        self.assertIn("end", w)

    def test_execute_nonzero_is_not_ok_but_returns(self):
        plan = FirePlan("DEMO-BRUTE", {}, ["bash", "-c", "exit 7"], ready=True, gaps=[], live=True)
        r = execute(plan, confirm=True)
        self.assertFalse(r.ok)
        self.assertEqual(r.returncode, 7)


if __name__ == "__main__":
    unittest.main()


class TestCaseId(unittest.TestCase):
    def test_ids_are_unique_within_the_same_second(self):
        from datetime import datetime, timezone
        from draghunt.web import new_case_id, _CASE_ID
        now = datetime(2026, 9, 7, 17, 24, 52, tzinfo=timezone.utc)
        a = new_case_id("DEMO-BRUTE", now)
        b = new_case_id("DEMO-BRUTE", now)
        self.assertNotEqual(a, b)          # no collision even at the same instant
        self.assertTrue(_CASE_ID.match(a))
        self.assertTrue(_CASE_ID.match(b))


class TestScores(unittest.TestCase):
    def test_stats_as_dict_shape(self):
        from draghunt.history import Stats
        s = Stats(3, 2, 66.7, 1, 80.0, "exfiltration", {"exfiltration": 60.0})
        d = s.as_dict()
        for k in ("attempts", "passed", "pass_rate", "streak", "avg_score",
                  "weakest_tactic", "by_tactic"):
            self.assertIn(k, d)
        self.assertEqual(d["weakest_tactic"], "exfiltration")
