"""Tests for phase-1 live-mode scaffolding: config, SIEM seam, fire plan."""
import tempfile
import unittest
from pathlib import Path

from dealer.config import RangeConfig, load, EXAMPLE_TOML, ConfigError
from dealer.siem import available, get_adapter, SiemAdapter
from dealer.catalog import deal
from dealer.fire import build_plan, execute, FirePlan


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
            os.environ["DEALER_SIEM_PASSWORD"] = "sekret"
            try:
                cfg = load(p)
                self.assertEqual(cfg.siem.options["password"], "sekret")
            finally:
                del os.environ["DEALER_SIEM_PASSWORD"]

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
        plan = build_plan(deal("DEMO-BRUTE", seed=7), RangeConfig())
        self.assertFalse(plan.ready)
        self.assertIn("attacker.host", plan.gaps)

    def test_plan_ready_with_full_config(self):
        cfg = RangeConfig()
        cfg.attacker.host = "10.0.0.5"; cfg.attacker.user = "kali"
        cfg.target.host = "10.0.0.6"
        plan = build_plan(deal("DEMO-BRUTE", seed=7), cfg)
        self.assertTrue(plan.ready)
        self.assertEqual(plan.gaps, [])

    def test_plan_injects_sealed_params(self):
        case = deal("DEMO-BRUTE", seed=7)
        plan = build_plan(case, RangeConfig())
        self.assertEqual(plan.params["ACCOUNT"], case.ground_truth.account)
        self.assertEqual(plan.params["SUCCEED"], "yes" if case.ground_truth.succeeded else "no")
        self.assertEqual(plan.params["DRY_RUN"], "1")  # never fires in phase 1

    def test_execute_is_a_phase2_stub(self):
        plan = build_plan(deal("DEMO-BRUTE", seed=7), RangeConfig())
        with self.assertRaises(NotImplementedError):
            execute(plan, confirm=True)


if __name__ == "__main__":
    unittest.main()
