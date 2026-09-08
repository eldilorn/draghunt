"""Reset logic tested without a live Proxmox, via a faked _req sequence."""
import unittest

from draghunt.config import RangeConfig
from draghunt.reset import ProxmoxReset, reset_target, ResetBlocked


PX = {"api_url": "https://pve:8006", "node": "pve", "vmid": 101,
      "snapshot": "clean", "token_id": "root@pam!draghunt", "token_secret": "s"}


class FakePx(ProxmoxReset):
    """ProxmoxReset with a scripted request sequence, no network, no sleeping."""
    def __init__(self, px, script):
        super().__init__(px, poll_interval=0, poll_max=5)
        self._script = list(script)
        self.calls = []

    def _req(self, method, path):
        self.calls.append((method, path))
        return self._script.pop(0)


class TestProxmoxRollback(unittest.TestCase):
    def test_successful_rollback(self):
        px = FakePx(PX, [
            {"data": "UPID:pve:rollback"},                 # rollback POST
            {"data": {"status": "stopped", "exitstatus": "OK"}},  # task poll
            {"data": {"status": "stopped"}},             # VM status
            {"data": "UPID:pve:start"},                    # start POST
            {"data": {"status": "stopped", "exitstatus": "OK"}},
            {"data": {"status": "running"}},
        ])
        step = px.rollback()
        self.assertTrue(step.ok)
        self.assertIn("snapshot 'clean'", step.detail)
        # first call must be the rollback endpoint
        self.assertEqual(px.calls[0][0], "POST")
        self.assertIn("/snapshot/clean/rollback", px.calls[0][1])

    def test_task_failure_is_reported(self):
        px = FakePx(PX, [
            {"data": "UPID:pve:rollback"},
            {"data": {"status": "stopped", "exitstatus": "err: locked"}},
        ])
        step = px.rollback()
        self.assertFalse(step.ok)
        self.assertIn("err", step.detail)

    def test_no_task_id_is_failure(self):
        px = FakePx(PX, [{"data": None}])
        self.assertFalse(px.rollback().ok)


class TestOrchestrator(unittest.TestCase):
    def _cfg(self, mode):
        c = RangeConfig()
        c.reset.mode = mode
        c.reset.proxmox = dict(PX)
        c.attacker.host = "10.0.0.5"; c.attacker.user = "kali"; c.target.host = "10.0.0.6"
        return c

    def test_mode_none_is_noop(self):
        self.assertEqual(reset_target(self._cfg("none")).steps, [])

    def test_snapshot_requires_confirm(self):
        with self.assertRaises(ResetBlocked):
            reset_target(self._cfg("snapshot"), confirm=False)

    def test_snapshot_uses_factory(self):
        c = self._cfg("snapshot")
        factory = lambda px: FakePx(px, [
            {"data": "UPID:x"}, {"data": {"status": "stopped", "exitstatus": "OK"}},
            {"data": {"status": "running"}}, {"data": {"status": "running"}}])
        res = reset_target(c, confirm=True, proxmox_factory=factory)
        self.assertTrue(res.ok)
        self.assertEqual(res.steps[0].name, "proxmox-rollback")

    def test_missing_proxmox_config_fails_gracefully(self):
        c = self._cfg("snapshot")
        c.reset.proxmox = {}
        res = reset_target(c, confirm=True)
        self.assertFalse(res.ok)
        self.assertIn("not configured", res.steps[0].detail)


if __name__ == "__main__":
    unittest.main()


class TestResetFailureBoundaries(unittest.TestCase):
    def test_vm_start_failure_is_not_ignored(self):
        from urllib.error import HTTPError
        px = FakePx(PX, [])
        responses = iter([{'data':'UPID:rollback'},{'data':{'status':'stopped','exitstatus':'OK'}},{'data':{'status':'stopped'}}])
        def req(method,path):
            if path.endswith('/status/start'):
                raise HTTPError('https://pve',500,'disk unavailable',{},None)
            return next(responses)
        px._req=req
        self.assertFalse(px.rollback().ok)

    def test_failed_rollback_does_not_run_cleanup(self):
        from unittest.mock import patch
        from draghunt.reset import ResetStep
        cfg=RangeConfig()
        cfg.reset.mode='both'; cfg.reset.proxmox=PX
        with patch('draghunt.reset._cleanup_step') as cleanup:
            result=reset_target(cfg,confirm=True,proxmox_factory=lambda px:FakePx(px,[{'data':None}]))
        self.assertFalse(result.ok)
        cleanup.assert_not_called()

    def test_cleanup_also_requires_confirmation(self):
        cfg=RangeConfig(); cfg.reset.mode='cleanup'
        with self.assertRaises(ResetBlocked):
            reset_target(cfg)
