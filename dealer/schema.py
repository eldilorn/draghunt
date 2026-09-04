"""Data contracts for the Dealer grading loop.

Two documents flow through the grader:

* GroundTruth — the sealed truth the Dealer produces when it deals a case.
  It is written blind and never shown to the analyst until after they submit.
* Verdict — what the analyst submits after investigating the telemetry.

Both are plain JSON so the open-source runner and the (future) hosted layer
share one on-the-wire format. No third-party dependencies: the whole contract
is dataclasses plus a hand-rolled validator, so the core runs on a stock
Python install.

Nothing in this file is scenario content. These are field *shapes*; the
scenario deck itself lives in the user's private lab and is never vendored here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DISPOSITIONS = ("malicious", "benign", "inconclusive")


class SchemaError(ValueError):
    """Raised when a ground-truth or verdict document is malformed."""


def _require(doc: dict[str, Any], key: str, kind: str) -> Any:
    if key not in doc:
        raise SchemaError(f"{kind}: missing required field '{key}'")
    return doc[key]


@dataclass(frozen=True)
class GroundTruth:
    """The sealed truth for one dealt case.

    scenario_id  Stable id of the dealt scenario (e.g. "S01"). Opaque here.
    technique    MITRE ATT&CK technique id, e.g. "T1110" or "T1110.001".
    tactic       ATT&CK tactic slug, e.g. "credential-access".
    source_ip    Origin of the activity the analyst should identify.
    account      Targeted or abused account, if the scenario has one.
    succeeded    Did the attack achieve its objective?
    disposition  Correct call: malicious / benign / inconclusive.
    """

    scenario_id: str
    technique: str
    tactic: str
    source_ip: str
    succeeded: bool
    disposition: str
    account: str | None = None
    dealt_utc: str | None = None
    notes: str | None = None

    @staticmethod
    def from_dict(doc: dict[str, Any]) -> "GroundTruth":
        kind = "ground-truth"
        disposition = str(_require(doc, "disposition", kind)).lower()
        if disposition not in DISPOSITIONS:
            raise SchemaError(
                f"{kind}: disposition must be one of {DISPOSITIONS}, got '{disposition}'"
            )
        return GroundTruth(
            scenario_id=str(_require(doc, "scenario_id", kind)),
            technique=str(_require(doc, "technique", kind)).upper(),
            tactic=str(_require(doc, "tactic", kind)).lower(),
            source_ip=str(_require(doc, "source_ip", kind)),
            succeeded=bool(_require(doc, "succeeded", kind)),
            disposition=disposition,
            account=(str(doc["account"]) if doc.get("account") is not None else None),
            dealt_utc=(str(doc["dealt_utc"]) if doc.get("dealt_utc") else None),
            notes=(str(doc["notes"]) if doc.get("notes") else None),
        )


@dataclass(frozen=True)
class Verdict:
    """What the analyst submits after investigating blind.

    Every field except disposition is optional: a partial verdict still grades,
    it just leaves points on the table. That mirrors real triage, where you
    commit to a call before every observable is nailed down.
    """

    disposition: str
    technique: str | None = None
    source_ip: str | None = None
    account: str | None = None
    succeeded: bool | None = None
    narrative: str | None = None
    analyst: str | None = None

    @staticmethod
    def from_dict(doc: dict[str, Any]) -> "Verdict":
        kind = "verdict"
        disposition = str(_require(doc, "disposition", kind)).lower()
        if disposition not in DISPOSITIONS:
            raise SchemaError(
                f"{kind}: disposition must be one of {DISPOSITIONS}, got '{disposition}'"
            )

        def opt(key: str) -> str | None:
            v = doc.get(key)
            return str(v) if v not in (None, "") else None

        succeeded = doc.get("succeeded")
        return Verdict(
            disposition=disposition,
            technique=(opt("technique").upper() if opt("technique") else None),
            source_ip=opt("source_ip"),
            account=opt("account"),
            succeeded=(bool(succeeded) if succeeded is not None else None),
            narrative=opt("narrative"),
            analyst=opt("analyst"),
        )


def load_json(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    try:
        return json.loads(p.read_text())
    except FileNotFoundError as exc:
        raise SchemaError(f"file not found: {p}") from exc
    except json.JSONDecodeError as exc:
        raise SchemaError(f"invalid JSON in {p}: {exc}") from exc


def load_ground_truth(path: str | Path) -> GroundTruth:
    return GroundTruth.from_dict(load_json(path))


def load_verdict(path: str | Path) -> Verdict:
    return Verdict.from_dict(load_json(path))
