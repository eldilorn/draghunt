"""Turn a dealt case into a fire plan against the range.

Phase 1 renders the plan only: the exact SSH command the app WOULD run against
the attacker box, with the randomized parameters injected. Nothing executes.

`execute()` is intentionally a phase-2 stub that raises. There is deliberately
no code path in phase 1 that touches the network, so "nothing fires" is a
guarantee of the code, not a promise in a comment.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from .catalog import DealtCase
from .config import RangeConfig


@dataclass
class FirePlan:
    scenario_id: str
    params: dict[str, str]
    ssh_command: list[str]     # argv the app would exec
    ready: bool                # is the range configured enough to fire?
    gaps: list[str]            # what's missing if not ready

    def render(self) -> str:
        lines = [f"Fire plan — {self.scenario_id}", "  parameters:"]
        for k, v in self.params.items():
            lines.append(f"    {k}={v}")
        lines.append("  would run:")
        lines.append("    " + " ".join(shlex.quote(a) for a in self.ssh_command))
        if not self.ready:
            lines.append("  NOT READY — configure: " + ", ".join(self.gaps))
        return "\n".join(lines)


def build_plan(case: DealtCase, cfg: RangeConfig) -> FirePlan:
    gt = case.ground_truth
    # In live mode the source is the attacker box itself.
    src = cfg.attacker.host or "<attacker-host>"
    params = {
        "SCN": case.scenario.id,
        "SRC_IP": src,
        "TARGET": cfg.target.host or "<target-host>",
        "TARGET_USER": cfg.target.user or "<target-user>",
        "ACCOUNT": gt.account or "",
        "VARIANT": str(case.variant),
        "SUCCEED": "yes" if gt.succeeded else "no",
        "DRY_RUN": "1",   # flips to 0 only in phase 2, behind an explicit gate
    }
    runner_dir = cfg.runner.dir.rstrip("/")
    remote_env = " ".join(f"{k}={shlex.quote(v)}" for k, v in params.items())
    remote_cmd = f"{remote_env} bash {shlex.quote(runner_dir + '/' + cfg.runner.entry)}"

    ssh = ["ssh"]
    if cfg.attacker.ssh_key:
        ssh += ["-i", cfg.attacker.ssh_key]
    dest = f"{cfg.attacker.user or '<user>'}@{cfg.attacker.host or '<attacker-host>'}"
    ssh += [dest, remote_cmd]

    gaps = cfg.missing_for_fire()
    return FirePlan(case.scenario.id, params, ssh, ready=not gaps, gaps=gaps)


def execute(plan: FirePlan, confirm: bool = False) -> None:
    """Live fire. Phase 2. Not implemented on purpose in phase 1."""
    raise NotImplementedError(
        "live fire lands in phase 2; phase 1 renders the plan only"
    )
