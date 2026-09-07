"""Turn a dealt case into a fire plan, and (phase 2) actually fire it.

Safety model:
* Dry-run is the default. `build_plan(..., live=False)` bakes DRY_RUN=1 into the
  command, so the attacker box prints its plan and touches nothing.
* Live fire requires BOTH an explicit `confirm=True` from the caller AND a fully
  configured range. Missing either, `execute()` refuses and raises. There is no
  implicit path from a dealt case to a real attack.
* Every fire records its start/finish window, which is exactly what the SIEM
  alert pull (phase 4) needs to scope the investigation.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .catalog import DealtCase
from .config import RangeConfig


class FireBlocked(RuntimeError):
    """Raised when a live fire is attempted without confirm or a ready range."""


@dataclass
class FirePlan:
    scenario_id: str
    params: dict[str, str]
    ssh_command: list[str]
    ready: bool
    gaps: list[str]
    live: bool

    def render(self) -> str:
        lines = [f"Fire plan — {self.scenario_id}  ({'LIVE' if self.live else 'dry run'})",
                 "  parameters:"]
        for k, v in self.params.items():
            lines.append(f"    {k}={v}")
        lines.append("  would run:")
        lines.append("    " + " ".join(shlex.quote(a) for a in self.ssh_command))
        if not self.ready:
            lines.append("  NOT READY — configure: " + ", ".join(self.gaps))
        return "\n".join(lines)


@dataclass
class FireResult:
    scenario_id: str
    returncode: int
    started_utc: str
    finished_utc: str
    command: str
    stdout: str = ""
    stderr: str = ""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0

    def window(self, pad_seconds: int = 120) -> dict[str, str]:
        """Investigation window (padded) for the SIEM alert pull."""
        from datetime import timedelta
        s = datetime.strptime(self.started_utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        e = datetime.strptime(self.finished_utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        pad = timedelta(seconds=pad_seconds)
        return {"start": (s - pad).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "end": (e + pad).strftime("%Y-%m-%dT%H:%M:%SZ")}


def build_plan(case: DealtCase, cfg: RangeConfig, live: bool = False) -> FirePlan:
    gt = case.ground_truth
    src = cfg.attacker.host or "<attacker-host>"
    params = {
        "SCN": case.scenario.id,
        "SRC_IP": src,
        "TARGET": cfg.target.host or "<target-host>",
        "TARGET_USER": cfg.target.user or "<target-user>",
        "ACCOUNT": gt.account or "",
        "VARIANT": str(case.variant),
        "SUCCEED": "yes" if gt.succeeded else "no",
        "DRY_RUN": "0" if live else "1",
    }
    runner_dir = cfg.runner.dir.rstrip("/")
    remote_env = " ".join(f"{k}={shlex.quote(v)}" for k, v in params.items())
    remote_cmd = f"{remote_env} bash {shlex.quote(runner_dir + '/' + cfg.runner.entry)}"

    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           "-o", "StrictHostKeyChecking=accept-new"]
    if cfg.attacker.ssh_key:
        ssh += ["-i", cfg.attacker.ssh_key]
    dest = f"{cfg.attacker.user or '<user>'}@{cfg.attacker.host or '<attacker-host>'}"
    ssh += [dest, remote_cmd]

    gaps = cfg.missing_for_fire()
    return FirePlan(case.scenario.id, params, ssh, ready=not gaps, gaps=gaps, live=live)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def execute(plan: FirePlan, confirm: bool = False, timeout: int = 300) -> FireResult:
    """Fire the plan against the range. Gated: needs confirm=True and a ready plan."""
    if not confirm:
        raise FireBlocked("live fire requires explicit confirm=True")
    if not plan.live:
        raise FireBlocked("refusing to execute a dry-run plan; build with live=True")
    if not plan.ready:
        raise FireBlocked("range not configured: " + ", ".join(plan.gaps))

    started = _now()
    cmd_str = " ".join(shlex.quote(a) for a in plan.ssh_command)
    try:
        proc = subprocess.run(plan.ssh_command, capture_output=True, text=True, timeout=timeout)
        return FireResult(plan.scenario_id, proc.returncode, started, _now(), cmd_str,
                          stdout=proc.stdout[-8000:], stderr=proc.stderr[-4000:])
    except subprocess.TimeoutExpired:
        return FireResult(plan.scenario_id, -1, started, _now(), cmd_str,
                          error=f"timed out after {timeout}s")
    except (OSError, subprocess.SubprocessError) as exc:
        return FireResult(plan.scenario_id, -1, started, _now(), cmd_str,
                          error=f"{type(exc).__name__}: {exc}")
