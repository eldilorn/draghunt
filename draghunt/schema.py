"""Data contracts for Draghunt grading loop.

Two documents flow through the grader:

* GroundTruth — the sealed truth Draghunt produces when it lays a case.
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
import ipaddress
import re
from pathlib import Path
from typing import Any


DISPOSITIONS = ("malicious", "benign", "inconclusive")


class SchemaError(ValueError):
    """Raised when a ground-truth or verdict document is malformed."""


def _require(doc: dict[str, Any], key: str, kind: str) -> Any:
    if not isinstance(doc, dict):
        raise SchemaError(f"{kind}: expected an object")
    if key not in doc:
        raise SchemaError(f"{kind}: missing required field '{key}'")
    return doc[key]


def boolean(value: Any, name: str, nullable: bool = False) -> bool | None:
    if value is None and nullable:
        return None
    if type(value) is not bool:
        raise SchemaError(f"{name}: expected a JSON boolean" + (" or null" if nullable else ""))
    return value


def text(value: Any, name: str, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or len(value) > 50000:
        raise SchemaError(f"{name}: expected text (at most 50000 characters)")
    value = value.strip()
    if not value:
        if optional:
            return None
        raise SchemaError(f"{name}: must not be empty")
    return value


def technique(value: Any) -> str | None:
    value = text(value, "technique", optional=True)
    if value and not re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", value.upper()):
        raise SchemaError("technique: expected an ATT&CK ID or null")
    return value.upper() if value else None


def ip(value: Any, optional: bool = False) -> str | None:
    value = text(value, "source_ip", optional)
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise SchemaError("source_ip: expected an IP address") from exc


@dataclass(frozen=True)
class GroundTruth:
    """The sealed truth for one laid case.

    scenario_id  Stable id of the laid scenario (e.g. "S01"). Opaque here.
    technique    MITRE ATT&CK technique id, e.g. "T1110" or "T1110.001".
    tactic       ATT&CK tactic slug, e.g. "credential-access".
    source_ip    Origin of the activity the analyst should identify.
    account      Targeted or abused account, if the scenario has one.
    succeeded    Did the attack achieve its objective?
    disposition  Correct call: malicious / benign / inconclusive.
    """

    scenario_id: str
    technique: str | None
    tactic: str
    source_ip: str
    succeeded: bool | None
    disposition: str
    account: str | None = None
    laid_utc: str | None = None
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
            scenario_id=text(_require(doc, "scenario_id", kind), "scenario_id"),
            technique=technique(_require(doc, "technique", kind)),
            tactic=str(_require(doc, "tactic", kind)).lower(),
            source_ip=ip(_require(doc, "source_ip", kind)),
            succeeded=boolean(_require(doc, "succeeded", kind), "succeeded", nullable=True),
            disposition=disposition,
            account=text(doc.get("account"), "account", optional=True),
            laid_utc=(str(doc["laid_utc"]) if doc.get("laid_utc") else None),
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
    timeline: str | None = None
    assets: str | None = None
    impact: str | None = None
    actions: str | None = None
    confidence: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    self_review: str | None = None

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
            return text(v, key, optional=True)

        succeeded = doc.get("succeeded")
        evidence_ids = doc.get("evidence_ids", [])
        if not isinstance(evidence_ids, list) or len(evidence_ids) > 500:
            raise SchemaError("evidence_ids: expected a list of at most 500 IDs")
        evidence_ids = list(dict.fromkeys(text(v, "evidence ID") for v in evidence_ids))
        confidence = opt("confidence")
        if confidence not in (None, "low", "medium", "high"):
            raise SchemaError("confidence: use low, medium, or high")
        return Verdict(
            disposition=disposition,
            technique=technique(doc.get("technique")),
            source_ip=ip(doc.get("source_ip"), optional=True),
            account=opt("account"),
            succeeded=boolean(succeeded, "succeeded", nullable=True),
            narrative=opt("narrative"),
            analyst=opt("analyst"),
            timeline=opt("timeline"), assets=opt("assets"), impact=opt("impact"),
            actions=opt("actions"), confidence=confidence, evidence_ids=evidence_ids,
            self_review=opt("self_review"),
        )


def load_json(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    try:
        doc = json.loads(p.read_text())
        if not isinstance(doc, dict):
            raise SchemaError(f"expected a JSON object in {p}")
        return doc
    except FileNotFoundError as exc:
        raise SchemaError(f"file not found: {p}") from exc
    except json.JSONDecodeError as exc:
        raise SchemaError(f"invalid JSON in {p}: {exc}") from exc


def load_ground_truth(path: str | Path) -> GroundTruth:
    return GroundTruth.from_dict(load_json(path))


def load_verdict(path: str | Path) -> Verdict:
    return Verdict.from_dict(load_json(path))
