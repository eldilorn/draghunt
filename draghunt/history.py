"""Legacy JSONL comparisons and shared score aggregation. Saved cases use SQLite."""

from __future__ import annotations

import json
import fcntl
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .grader import Report
from .schema import GroundTruth

DEFAULT_STORE = Path(".draghunt") / "history.jsonl"


def record(report: Report, gt: GroundTruth, store: Path | None = None, case_id: str | None = None) -> Path:
    path = store or DEFAULT_STORE
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "case_id": case_id,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scenario_id": report.scenario_id,
        "technique": gt.technique,
        "tactic": gt.tactic,
        "total": report.total,
        "band": report.band,
        "passed": report.total >= 60,
        "capped": report.capped,
    }
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, "r+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        rows = [json.loads(line) for line in fh if line.strip()]
        if case_id is None or not any(row.get("case_id") == case_id for row in rows):
            fh.seek(0, 2)
            fh.write(json.dumps(entry) + "\n")
    return path


def load(store: Path | None = None) -> list[dict]:
    path = store or DEFAULT_STORE
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


@dataclass
class Stats:
    attempts: int
    passed: int
    pass_rate: float
    streak: int
    avg_score: float
    weakest_tactic: str | None
    by_tactic: dict[str, float]

    def as_text(self) -> str:
        if self.attempts == 0:
            return "No reps recorded yet. Lay a drag and grade it with --record."
        lines = [
            "Draghunt stats",
            f"  reps      : {self.attempts}",
            f"  passed    : {self.passed} ({self.pass_rate:.0f}%)",
            f"  avg score : {self.avg_score:.0f}/100",
            f"  streak    : {self.streak} in a row",
        ]
        if self.by_tactic:
            lines.append("  by tactic :")
            for tactic, avg in sorted(self.by_tactic.items(), key=lambda kv: kv[1]):
                flag = "   <- weakest" if tactic == self.weakest_tactic else ""
                lines.append(f"      {tactic:<20} {avg:>4.0f}/100{flag}")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "attempts": self.attempts,
            "passed": self.passed,
            "pass_rate": round(self.pass_rate, 1),
            "streak": self.streak,
            "avg_score": round(self.avg_score, 1),
            "weakest_tactic": self.weakest_tactic,
            "by_tactic": {k: round(v, 1) for k, v in self.by_tactic.items()},
        }


def stats(store: Path | None = None) -> Stats:
    return from_rows(load(store))


def from_rows(rows: list[dict]) -> Stats:
    n = len(rows)
    if n == 0:
        return Stats(0, 0, 0.0, 0, 0.0, None, {})

    passed = sum(1 for r in rows if r.get("passed"))
    avg = sum(r.get("total", 0.0) for r in rows) / n

    streak = 0
    for r in reversed(rows):
        if r.get("passed"):
            streak += 1
        else:
            break

    by: dict[str, list[float]] = {}
    for r in rows:
        by.setdefault(r.get("tactic", "unknown"), []).append(r.get("total", 0.0))
    by_avg = {k: sum(v) / len(v) for k, v in by.items()}
    weakest = min(by_avg, key=by_avg.get) if by_avg else None

    return Stats(
        attempts=n,
        passed=passed,
        pass_rate=100 * passed / n,
        streak=streak,
        avg_score=avg,
        weakest_tactic=weakest,
        by_tactic=by_avg,
    )


def recent(n: int = 20, store: Path | None = None) -> list[dict]:
    """The last n graded reps, oldest-first, for the score-history chart."""
    rows = load(store)
    return rows[-n:]
