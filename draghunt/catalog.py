"""The deck: load public scenarios and lay one into a sealed ground truth.

A *scenario* here is metadata only — an ATT&CK mapping, a set of randomizable
knobs, and a telemetry recipe. It contains no attack commands. The actual
execution against a live range is delegated to the user's own private runner;
this module only decides *what* case to lay and seals the truth of it.

`lay()` is deterministic given a seed, so a case can be re-laid for testing or
review. When no seed is passed one is drawn and returned, then written into the
sealed truth, so any laid case is reproducible after the fact.
"""

from __future__ import annotations

import json
import random
import re
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .schema import GroundTruth, SchemaError, technique

CATALOG_DIR = Path(__file__).parent / "data" / "catalog"


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    technique: str | None
    tactic: str
    difficulty: str
    disposition: str
    accounts: list[str]
    source_pool: list[str]
    succeed_prob: float
    telemetry: dict[str, Any]
    brief: str
    live: bool = False

    @staticmethod
    def from_dict(doc: dict[str, Any]) -> "Scenario":
        try:
            if not isinstance(doc, dict):
                raise ValueError("expected an object")
            if not isinstance(doc.get("id"), str) or not re.fullmatch(r"[A-Z0-9][A-Z0-9-]*", doc["id"]):
                raise ValueError("id must contain uppercase letters, numbers, and hyphens")
            for key in ("accounts", "source_pool"):
                values = doc.get(key, [])
                if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values):
                    raise ValueError(f"{key} must contain strings")
            for value in doc.get("source_pool", []):
                ipaddress.ip_address(value)
            if not doc.get("source_pool"):
                raise ValueError("source_pool must not be empty")
            if type(doc.get("live", False)) is not bool:
                raise ValueError("live must be a boolean")
            if doc.get("disposition", "malicious") not in ("malicious", "benign", "inconclusive"):
                raise ValueError("invalid disposition")
            probability = doc.get("succeed_prob", 0.5)
            if type(probability) not in (float, int) or not 0 <= probability <= 1:
                raise ValueError("succeed_prob must be between 0 and 1")
            return Scenario(
                id=str(doc["id"]),
                title=str(doc["title"]),
                technique=technique(doc.get("technique")),
                tactic=str(doc["tactic"]).lower(),
                difficulty=str(doc.get("difficulty", "unknown")),
                disposition=str(doc.get("disposition", "malicious")).lower(),
                accounts=list(doc.get("accounts") or []),
                source_pool=list(doc["source_pool"]),
                succeed_prob=float(doc.get("succeed_prob", 0.5)),
                telemetry=dict(doc.get("telemetry") or {}),
                brief=str(doc.get("brief", "Investigate the available events.")),
                live=doc.get("live", False),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise SchemaError(f"bad scenario: {exc}") from exc


def load_catalog(catalog_dir: Path | None = None) -> dict[str, Scenario]:
    d = catalog_dir or CATALOG_DIR
    deck: dict[str, Scenario] = {}
    for path in sorted(d.glob("*.json")):
        try:
            s = Scenario.from_dict(json.loads(path.read_text()))
        except (OSError, ValueError) as exc:
            raise SchemaError(f"{path}: {exc}") from exc
        if s.id in deck:
            raise SchemaError(f"duplicate scenario ID: {s.id}")
        deck[s.id] = s
    if not deck:
        raise SchemaError(f"no scenarios found in {d}")
    return deck


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Hunt:
    """One laid case: the sealed truth plus the blind brief the analyst sees."""

    ground_truth: GroundTruth
    scenario: Scenario
    seed: int
    variant: int

    @property
    def blind_brief(self) -> str:
        s = self.scenario
        return (
            f"Investigation started\n"
            f"  difficulty : {s.difficulty}\n"
            f"  laid (UTC): {self.ground_truth.laid_utc}\n"
            f"  telemetry  : {s.telemetry.get('log_source', 'unknown')}\n\n"
            f"{s.brief}\n"
        )


def lay(
    scenario_id: str | None = None,
    seed: int | None = None,
    catalog_dir: Path | None = None,
    *, deck: dict[str, Scenario] | None = None,
) -> Hunt:
    deck = deck if deck is not None else load_catalog(catalog_dir)
    if scenario_id is not None and not isinstance(scenario_id, str):
        raise SchemaError("scenario must be an ID")
    if seed is not None and (type(seed) is not int or not 0 <= seed < 2**63):
        raise SchemaError("seed must be an integer between 0 and 2**63-1")

    if seed is None:
        seed = random.SystemRandom().randint(0, 2**31 - 1)
    rng = random.Random(seed)

    if scenario_id:
        key = scenario_id.upper()
        if key not in deck:
            raise SchemaError(f"no such scenario: {scenario_id} (have {sorted(deck)})")
        scenario = deck[key]
    else:
        scenario = rng.choice(list(deck.values()))

    account = rng.choice(scenario.accounts) if scenario.accounts else None
    source_ip = rng.choice(scenario.source_pool)
    succeeded = rng.random() < scenario.succeed_prob
    variant = rng.randint(1, 3)
    if scenario.telemetry.get("outcome_observable") is False or scenario.disposition == "benign":
        succeeded = None

    gt = GroundTruth(
        scenario_id=scenario.id,
        technique=scenario.technique,
        tactic=scenario.tactic,
        source_ip=source_ip,
        account=account,
        succeeded=succeeded,
        disposition=scenario.disposition,
        laid_utc=_now_utc(),
        notes=f"seed={seed}; variant={variant}",
    )
    return Hunt(ground_truth=gt, scenario=scenario, seed=seed, variant=variant)


def seal_dict(gt: GroundTruth) -> dict[str, Any]:
    """Serialize ground truth to the on-disk JSON seal."""
    return {
        "scenario_id": gt.scenario_id,
        "technique": gt.technique,
        "tactic": gt.tactic,
        "source_ip": gt.source_ip,
        "account": gt.account,
        "succeeded": gt.succeeded,
        "disposition": gt.disposition,
        "laid_utc": gt.laid_utc,
        "notes": gt.notes,
    }
