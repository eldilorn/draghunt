"""Reset the target between reps.

Two mechanisms, both requested:

* Proxmox snapshot rollback — the hard reset. Reverts the target VM to a clean
  snapshot, discarding whatever the last attack left behind. This is destructive
  and irreversible, so it is gated behind an explicit confirm and always names
  the VM it will revert.
* Cleanup job — the light reset. Delegates to the user's PRIVATE runner over SSH
  (ACTION=cleanup), so scenario-specific undo commands stay in the lab, not in
  this product.

`reset_target()` orchestrates based on `reset.mode` in range.toml
(snapshot | cleanup | both | none). Uses stdlib urllib/subprocess; no deps.
"""

from __future__ import annotations

import json
import shlex
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .config import RangeConfig


class ResetBlocked(RuntimeError):
    """Raised when a reset is attempted without explicit confirm."""


@dataclass
class ResetStep:
    name: str
    ok: bool
    detail: str


@dataclass
class ResetResult:
    steps: list[ResetStep] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.steps) if self.steps else True

    def render(self) -> str:
        if not self.steps:
            return "reset: nothing to do (mode=none)"
        return "\n".join(f"  [{'ok' if s.ok else 'FAIL'}] {s.name}: {s.detail}" for s in self.steps)


# --- Proxmox ------------------------------------------------------------------

def _px_missing(px: dict) -> list[str]:
    need = ["api_url", "node", "vmid", "snapshot", "token_id", "token_secret"]
    return [k for k in need if not px.get(k)]


class ProxmoxReset:
    def __init__(self, px: dict, poll_interval: float = 2.0, poll_max: int = 60):
        self.px = px
        self.poll_interval = poll_interval
        self.poll_max = poll_max

    def _ctx(self):
        if str(self.px.get("verify_tls", "false")).lower() in ("false", "0", "no"):
            c = ssl.create_default_context()
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            return c
        return None

    def _req(self, method: str, path: str) -> dict:
        base = str(self.px["api_url"]).rstrip("/")
        token = f"PVEAPIToken={self.px['token_id']}={self.px['token_secret']}"
        req = urllib.request.Request(f"{base}/api2/json{path}", method=method,
                                     headers={"Authorization": token})
        with urllib.request.urlopen(req, context=self._ctx(), timeout=15) as resp:
            return json.loads(resp.read().decode() or "{}")

    def rollback(self) -> ResetStep:
        node, vmid, snap = self.px["node"], self.px["vmid"], self.px["snapshot"]
        try:
            r = self._req("POST", f"/nodes/{node}/qemu/{vmid}/snapshot/{snap}/rollback")
            upid = r.get("data")
            if not upid:
                return ResetStep("proxmox-rollback", False, f"no task id returned: {r}")
            # poll the task to completion
            for _ in range(self.poll_max):
                st = self._req("GET", f"/nodes/{node}/tasks/{upid}/status").get("data", {})
                if st.get("status") == "stopped":
                    if st.get("exitstatus") == "OK":
                        break
                    return ResetStep("proxmox-rollback", False,
                                     f"task exit {st.get('exitstatus')}")
                time.sleep(self.poll_interval)
            else:
                return ResetStep("proxmox-rollback", False, "task did not finish in time")
            # ensure it's running (tolerate 'already running')
            if str(self.px.get("start_after", "true")).lower() not in ("false", "0", "no"):
                try:
                    self._req("POST", f"/nodes/{node}/qemu/{vmid}/status/start")
                except urllib.error.HTTPError as exc:
                    if exc.code not in (400, 500):
                        raise
            return ResetStep("proxmox-rollback", True,
                             f"VM {vmid} on {node} reverted to snapshot '{snap}'")
        except (urllib.error.URLError, OSError, KeyError) as exc:
            return ResetStep("proxmox-rollback", False, f"{type(exc).__name__}: {exc}")

    def health(self) -> tuple[bool, str]:
        miss = _px_missing(self.px)
        if miss:
            return (False, "not configured: " + ", ".join(miss))
        try:
            self._req("GET", f"/nodes/{self.px['node']}/qemu/{self.px['vmid']}/status/current")
            return (True, f"VM {self.px['vmid']} reachable")
        except (urllib.error.URLError, OSError) as exc:
            return (False, f"unreachable: {exc}")


# --- Cleanup (delegates to the private runner) --------------------------------

def _cleanup_step(cfg: RangeConfig, scenario_id: str, timeout: int = 120) -> ResetStep:
    if not cfg.attacker.host or not cfg.attacker.user:
        return ResetStep("cleanup", False, "attacker not configured")
    runner = cfg.runner.dir.rstrip("/") + "/" + cfg.runner.entry
    env = " ".join(f"{k}={shlex.quote(v)}" for k, v in {
        "ACTION": "cleanup", "SCN": scenario_id,
        "TARGET": cfg.target.host or "", "TARGET_USER": cfg.target.user or "",
    }.items())
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           "-o", "StrictHostKeyChecking=accept-new"]
    if cfg.attacker.ssh_key:
        ssh += ["-i", cfg.attacker.ssh_key]
    ssh += [f"{cfg.attacker.user}@{cfg.attacker.host}", f"{env} bash {shlex.quote(runner)}"]
    try:
        proc = subprocess.run(ssh, capture_output=True, text=True, timeout=timeout)
        ok = proc.returncode == 0
        return ResetStep("cleanup", ok, "ran ACTION=cleanup on runner"
                         if ok else f"runner rc={proc.returncode}: {proc.stderr.strip()[-200:]}")
    except (OSError, subprocess.SubprocessError) as exc:
        return ResetStep("cleanup", False, f"{type(exc).__name__}: {exc}")


# --- Orchestrator -------------------------------------------------------------

def reset_target(cfg: RangeConfig, scenario_id: str = "", confirm: bool = False,
                 proxmox_factory=ProxmoxReset) -> ResetResult:
    """Reset the target per reset.mode. Snapshot rollback requires confirm=True."""
    mode = (cfg.reset.mode or "none").lower()
    if mode == "none":
        return ResetResult()

    result = ResetResult()
    if mode in ("snapshot", "both"):
        if not confirm:
            raise ResetBlocked(
                "snapshot rollback is destructive; pass confirm=True to proceed")
        miss = _px_missing(cfg.reset.proxmox)
        if miss:
            result.steps.append(ResetStep("proxmox-rollback", False,
                                          "not configured: " + ", ".join(miss)))
        else:
            result.steps.append(proxmox_factory(cfg.reset.proxmox).rollback())
    if mode in ("cleanup", "both"):
        result.steps.append(_cleanup_step(cfg, scenario_id))
    return result
