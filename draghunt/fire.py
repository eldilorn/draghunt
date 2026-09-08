"""Versioned private-runner transport. A process exit code is not ground truth."""
from __future__ import annotations

import json
import shlex
import subprocess
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone, timedelta
from pathlib import Path

from .catalog import Hunt
from .config import RangeConfig
from .schema import GroundTruth, SchemaError, boolean

PROTOCOL_VERSION = 1


class FireBlocked(RuntimeError):
    pass


@dataclass
class FirePlan:
    scenario_id: str
    params: dict[str, str]
    ssh_command: list[str]
    ready: bool
    gaps: list[str]
    live: bool

    def render(self) -> str:
        return "Execution plan (debrief only)\n" + "\n".join(f"{k}={v}" for k, v in self.params.items())


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

    def window(self, pad_seconds: int = 30) -> dict[str, str]:
        start = datetime.fromisoformat(self.started_utc.replace("Z", "+00:00"))
        end = datetime.fromisoformat(self.finished_utc.replace("Z", "+00:00"))
        pad = timedelta(seconds=pad_seconds)
        return {"start": (start - pad).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "end": (end + pad).strftime("%Y-%m-%dT%H:%M:%SZ")}


def ssh_command(cfg: RangeConfig, params: dict[str, str]) -> list[str]:
    runner = cfg.runner.dir.rstrip("/") + "/" + cfg.runner.entry
    # Expand only the leading home marker on the remote machine. Quote all user text.
    remote_path = '"$HOME"/' + shlex.quote(runner[2:]) if runner.startswith("~/") else shlex.quote(runner)
    remote_env = " ".join(f"{k}={shlex.quote(v)}" for k, v in params.items())
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"]
    if cfg.attacker.ssh_key:
        ssh += ["-i", str(Path(cfg.attacker.ssh_key).expanduser())]
    return ssh + ["--", f"{cfg.attacker.user}@{cfg.attacker.host}", f"{remote_env} bash {remote_path}"]


def build_plan(case: Hunt, cfg: RangeConfig, live: bool = False, case_id: str = "") -> FirePlan:
    gt = case.ground_truth
    # SRC_IP is the real attacker host: a single box cannot spoof its source. The catalog's
    # source_pool only randomizes synthetic exercises; live grading uses the observed source.
    params = {
        "DRAGHUNT_PROTOCOL": str(PROTOCOL_VERSION), "CASE_ID": case_id,
        "ACTION": "run", "SCN": case.scenario.id, "SRC_IP": cfg.attacker.host,
        "TARGET": cfg.target.host, "TARGET_USER": cfg.target.user,
        "ACCOUNT": gt.account or "", "VARIANT": str(case.variant), "SEED": str(case.seed),
        "SUCCEED": "unknown" if gt.succeeded is None else ("yes" if gt.succeeded else "no"),
        "DRY_RUN": "0" if live else "1",
    }
    gaps = cfg.missing_for_fire()
    return FirePlan(case.scenario.id, params, ssh_command(cfg, params), not gaps, gaps, live)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def execute(plan: FirePlan, confirm: bool = False, timeout: int = 300) -> FireResult:
    if not confirm:
        raise FireBlocked("live fire requires explicit confirmation")
    if not plan.live:
        raise FireBlocked("refusing to execute a dry-run plan")
    if not plan.ready:
        raise FireBlocked("range not configured: " + ", ".join(plan.gaps))
    started = _now()
    command = shlex.join(plan.ssh_command)
    try:
        proc = subprocess.run(plan.ssh_command, capture_output=True, text=True, timeout=timeout)
        oversized = len(proc.stdout) > 1_000_000
        return FireResult(plan.scenario_id, proc.returncode, started, _now(), command,
                          stdout=proc.stdout[:1_000_000], stderr=proc.stderr[-8000:],
                          error="runner result exceeds 1 MB" if oversized else None)
    except subprocess.TimeoutExpired:
        return FireResult(plan.scenario_id, -1, started, _now(), command,
                          error=f"execution timed out after {timeout}s; remote outcome unknown")
    except (OSError, subprocess.SubprocessError) as exc:
        return FireResult(plan.scenario_id, -1, started, _now(), command, error=f"{type(exc).__name__}: {exc}")


def _envelope(stdout: str, case: Hunt, case_id: str, target: str) -> dict:
    try:
        doc = json.loads(stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise SchemaError("runner must return one JSON result using protocol version 1") from exc
    if not isinstance(doc, dict) or type(doc.get("protocol_version")) is not int or doc["protocol_version"] != PROTOCOL_VERSION:
        raise SchemaError("unsupported runner protocol")
    if doc.get("case_id") != case_id or doc.get("scenario_id") != case.scenario.id or doc.get("target") != target:
        raise SchemaError("runner result does not match this case, scenario, and target")
    return doc


def wait_ready(case: Hunt, cfg: RangeConfig, case_id: str, runner_only: bool = False) -> None:
    plan = build_plan(case, cfg, case_id=case_id)
    if not plan.ready:
        raise FireBlocked("range not configured: " + ", ".join(plan.gaps))
    params = {**plan.params, "ACTION": "preflight", "DRY_RUN": "1"}
    deadline = time.monotonic() + cfg.runner.ready_timeout
    while True:
        proc = subprocess.run(ssh_command(cfg, params), capture_output=True, text=True, timeout=20)
        if proc.returncode:
            raise FireBlocked("runner preflight failed; check SSH and the protocol-v1 dispatcher")
        doc = _envelope(proc.stdout, case, case_id, cfg.target.host)
        ready = boolean(doc.get("ready"), "preflight.ready")
        checks = doc.get("checks", {})
        if not isinstance(checks, dict) or any(type(checks.get(k)) is not bool for k in ("runner", "target", "telemetry")):
            raise SchemaError("preflight must report runner, target, and telemetry checks")
        if (runner_only and checks["runner"]) or (ready and all(checks[k] for k in ("runner", "target", "telemetry"))):
            return
        if time.monotonic() >= deadline:
            raise FireBlocked("target/runner/telemetry did not become ready before the deadline")
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def observed_truth(result: FireResult, case: Hunt, case_id: str, target: str) -> tuple[GroundTruth, dict]:
    if not result.ok:
        raise SchemaError("cannot grade an unsuccessful execution")
    doc = _envelope(result.stdout, case, case_id, target)
    if doc.get("status") != "completed":
        raise SchemaError("runner did not complete the exercise")
    gt = GroundTruth.from_dict(doc.get("ground_truth", {}))
    if gt.scenario_id != case.scenario.id or gt.technique != case.scenario.technique or gt.disposition != case.scenario.disposition or gt.tactic != case.scenario.tactic:
        raise SchemaError("observed result conflicts with the scenario's classification")
    proof = doc.get("evidence")
    if not isinstance(proof, list) or not proof or any(not isinstance(e, str) or not e.strip() for e in proof):
        raise SchemaError("runner must supply verification evidence references")
    actions = doc.get("completed_actions")
    if not isinstance(actions, list) or not actions or any(not isinstance(a, str) or not a.strip() for a in actions):
        raise SchemaError("runner must identify completed actions")
    for field in ("started_utc", "finished_utc"):
        try:
            dt = datetime.fromisoformat(doc[field].replace("Z", "+00:00"))
            if dt.utcoffset() is None:
                raise ValueError("timezone required")
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise SchemaError(f"runner {field} must be a timezone-aware timestamp") from exc
    start = datetime.fromisoformat(doc["started_utc"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(doc["finished_utc"].replace("Z", "+00:00"))
    transport_start = datetime.fromisoformat(result.started_utc.replace("Z", "+00:00"))
    transport_end = datetime.fromisoformat(result.finished_utc.replace("Z", "+00:00"))
    if end < start or start < transport_start - timedelta(seconds=30) or end > transport_end + timedelta(seconds=30):
        raise SchemaError("runner timestamps are outside this execution window; check clock synchronization")
    return replace(gt, laid_utc=case.ground_truth.laid_utc), doc
