"""Shared exercise lifecycle for the CLI and dashboard."""
from __future__ import annotations

import hashlib
import json
import random
from dataclasses import asdict, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import catalog, fire, reset, telemetry, history
from .config import RangeConfig
from .grader import grade, report_dict, report_completeness
from .schema import GroundTruth, Verdict, SchemaError
from .siem import get_adapter
from .store import CaseStore, BusyError, new_case_id, now, private_write

ACTIVE = {"queued", "preflight", "resetting", "waiting_for_target", "running"}


def utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


class Workflow:
    def __init__(self, cfg: RangeConfig):
        self.cfg = cfg
        self.store = CaseStore(cfg.data_dir)

    def deck(self) -> dict[str, catalog.Scenario]:
        deck = catalog.load_catalog()
        if self.cfg.catalog_dir:
            private = catalog.load_catalog(Path(self.cfg.catalog_dir))
            overlap = deck.keys() & private.keys()
            if overlap:
                raise SchemaError("private scenario IDs conflict with the demo deck: " + ", ".join(sorted(overlap)))
            deck.update(private)
        return deck

    def create(self, scenario_id: str | None = None, seed: int | None = None,
               live: bool = False, reset_first: bool = False, replay_of: str | None = None) -> dict:
        if type(live) is not bool or type(reset_first) is not bool:
            raise SchemaError("fire and reset must be booleans")
        if reset_first and not live:
            raise SchemaError("reset is only available for live exercises")
        blind = not scenario_id and seed is None
        if replay_of:
            if scenario_id is not None or seed is not None:
                raise SchemaError("replay cannot be combined with a scenario or seed override")
            previous = self.store.get(replay_of)
            if not previous.get("submission"):
                raise SchemaError("submit the original case before replaying it")
            scenario = catalog.Scenario.from_dict(previous["scenario"])
            if live != (previous["mode"] == "live"):
                raise SchemaError("a replay must use the original run mode")
            case = catalog.Hunt(GroundTruth.from_dict({**previous["intended"], "laid_utc": now()}),
                                scenario, previous["seed"], previous["variant"])
            blind = False
        else:
            if seed is None:
                seed = random.SystemRandom().randint(0, 2**31 - 1)
            deck = self.deck()
            if not scenario_id:
                eligible = [s.id for s in deck.values() if (s.live if live else telemetry.supports(s))]
                if not eligible:
                    raise SchemaError("no scenarios support this mode; configure a compatible private catalog")
                if seed is not None and type(seed) is not int:
                    raise SchemaError("seed must be an integer")
                scenario_id = random.Random(seed).choice(eligible)
            case = catalog.lay(scenario_id, seed, deck=deck)
        if not live and not telemetry.supports(case.scenario):
            raise SchemaError("this scenario requires a live range; select a synthetic exercise or enable live mode")
        if live:
            if not case.scenario.live:
                raise SchemaError("this scenario only supports synthetic exercises")
            gaps = self.cfg.missing_for_fire()
            if gaps:
                raise SchemaError("range not configured: " + ", ".join(gaps))
            if reset_first and self.cfg.reset.mode == "none":
                raise SchemaError("configure a reset mode before requesting a reset")
        case_id = new_case_id()
        events = [] if live else [{"event_id": f"E-{i:04d}", "raw": {"full_log": line},
                                  "timestamp": "", "rule": "", "source": "synthetic", "description": line}
                                 for i, line in enumerate(telemetry.generate(case), 1)]
        doc = {
            "id": case_id, "created_utc": now(), "updated_utc": now(),
            "mode": "live" if live else "synthetic", "state": "queued" if live else "investigating",
            "blind": blind, "replay_of": replay_of, "scenario": asdict(case.scenario),
            "seed": case.seed, "variant": case.variant, "intended": catalog.seal_dict(case.ground_truth),
            "truth": None if live else catalog.seal_dict(case.ground_truth),
            "brief": "Investigate the available events. Document your evidence, what happened, and whether it warrants escalation." if blind else case.blind_brief,
            "target": self.cfg.target.host if live else "synthetic lab", "agent_id": self.cfg.target.agent_id if live else "",
            "reset_first": reset_first, "events": events, "draft": {}, "draft_version": 0,
            "submission": None, "collections": {}, "detections": [], "error": None,
        }
        self.store.create(doc)
        if not live:
            self._seal(doc)
        return self.public(doc)

    def _seal(self, doc: dict) -> None:
        private_write(self.store.root / "sealed" / (doc["id"] + ".json"), json.dumps(doc["truth"], indent=2))

    def _state(self, case_id: str, state: str, **extra) -> dict:
        return self.store.update(case_id, lambda d: d.update(state=state, **extra))

    def run_live(self, case_id: str, confirm: bool = False) -> dict:
        if not confirm:
            raise fire.FireBlocked("live execution requires confirmation")
        doc = self.store.get(case_id)
        if doc["mode"] != "live" or doc["state"] != "queued":
            raise SchemaError("case is not queued for execution")
        if doc["target"] != self.cfg.target.host or doc["agent_id"] != self.cfg.target.agent_id:
            raise SchemaError("case target differs from the active range profile")
        case = catalog.Hunt(GroundTruth.from_dict(doc["intended"]), catalog.Scenario.from_dict(doc["scenario"]), doc["seed"], doc["variant"])
        try:
            with self.store.target_lock(doc["target"]):
                # An earlier SSH timeout may have left a remote process alive.
                uncertain = any(d["target"] == doc["target"] and d["state"] == "execution_unknown" for d in self.store.all())
                if uncertain and not doc["reset_first"]:
                    raise fire.FireBlocked("a previous remote outcome is unknown; reset the target before another run")
                self._state(case_id, "preflight")
                fire.wait_ready(case, self.cfg, case_id, runner_only=doc["reset_first"])
                if doc["reset_first"]:
                    self._state(case_id, "resetting")
                    result = reset.reset_target(self.cfg, case.scenario.id, confirm=True)
                    self.store.update(case_id, lambda d: d.update(reset=asdict(result)))
                    if not result.ok:
                        self._state(case_id, "reset_failed", error="Reset failed. Review the reset diagnostics before retrying.")
                        return self.get(case_id)
                    self.acknowledge_reset(doc["target"])
                    self._state(case_id, "waiting_for_target")
                    fire.wait_ready(case, self.cfg, case_id)
                adapter = get_adapter(self.cfg.siem.adapter, self.cfg.siem.options)
                ready, _ = adapter.health()
                if not ready:
                    raise fire.FireBlocked("SIEM is unavailable; restore telemetry before running the exercise")
                # Validate the target filter and read permissions before executing.
                check_time = datetime.now(timezone.utc)
                adapter.collect(check_time - timedelta(minutes=1), check_time, doc["agent_id"], limit=1)
                plan = fire.build_plan(case, self.cfg, live=True, case_id=case_id)
                self._state(case_id, "running")
                result = fire.execute(plan, confirm=True)
                self.store.update(case_id, lambda d: d.update(execution=asdict(result)))
                if not result.ok:
                    state = "execution_unknown" if result.returncode == -1 else "execution_failed"
                    self._state(case_id, state, error="Execution failed; this case will not be graded. See execution diagnostics.")
                    return self.get(case_id)
                try:
                    truth, observed = fire.observed_truth(result, case, case_id, doc["target"])
                except SchemaError:
                    self._state(case_id, "execution_unknown", error="Runner result could not be verified. Check protocol-v1 output and reset before retrying.")
                    return self.get(case_id)
                window = result.window()
                window["start"] = (utc(observed["started_utc"]) - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
                window["end"] = (utc(observed["finished_utc"]) + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
                ready_at = (utc(window["end"]) + timedelta(seconds=self.cfg.siem.ingest_wait)).strftime("%Y-%m-%dT%H:%M:%SZ")
                saved = self._state(case_id, "awaiting_telemetry", truth=catalog.seal_dict(truth), observed=observed,
                                    window=window, telemetry_ready_after=ready_at)
                self._seal(saved)
        except BusyError as exc:
            self._state(case_id, "blocked", error=str(exc))
        except Exception as exc:
            current = self.store.get(case_id)
            state = "execution_unknown" if current["state"] == "running" else "preflight_failed"
            self._state(case_id, state, error="Run stopped before a verified result. Check execution diagnostics.", diagnostic=f"{type(exc).__name__}: {exc}")
        return self.get(case_id)

    def acknowledge_reset(self, target: str) -> None:
        for old in self.store.all():
            if old["target"] == target and old["state"] == "execution_unknown":
                self._state(old["id"], "execution_failed", error="Outcome was unknown; target has since been reset.")

    def recover(self) -> None:
        """Mark interrupted jobs only when their target is not locked by another process."""
        for doc in self.store.all():
            if doc["state"] not in ACTIVE:
                continue
            try:
                with self.store.target_lock(doc["target"]):
                    self._state(doc["id"], "execution_unknown" if doc["state"] == "running" else "interrupted",
                                error="The controller stopped during this run. It is not eligible for grading.")
            except BusyError:
                pass

    def collect(self, case_id: str, kind: str = "alerts", limit: int = 2000) -> dict:
        doc = self.store.get(case_id)
        if doc["mode"] != "live" or not doc.get("window"):
            raise SchemaError("this case has no verified live execution window")
        if self.cfg.target.host != doc["target"] or self.cfg.target.agent_id != doc["agent_id"]:
            raise SchemaError("switch to this case's range profile before collecting evidence")
        start, end = (utc(doc["window"][k]) for k in ("start", "end"))
        batch = get_adapter(self.cfg.siem.adapter, self.cfg.siem.options).collect(start, end, doc["agent_id"], limit=limit, kind=kind)
        rows = [asdict(a) for a in batch.alerts]
        collection = {"kind": kind, "fetched_utc": now(), "total": batch.total, "complete": batch.complete,
                      "detail": batch.detail, "event_ids": [r["event_id"] for r in rows]}
        def change(d):
            existing = {r["event_id"]: r for r in d["events"]}
            for row in rows:
                existing.setdefault(row["event_id"], row)
            if len(existing) > 20000:
                raise SchemaError("case evidence limit reached (20000 events)")
            d["events"] = list(existing.values())
            d["collections"][kind] = collection
            if not d["submission"]:
                d["state"] = "investigating" if d["events"] else "awaiting_telemetry"
        return self.public(self.store.update(case_id, change))

    def save_draft(self, case_id: str, verdict: dict, version: int | None = None) -> dict:
        if not isinstance(verdict, dict):
            raise SchemaError("draft must be an object")
        allowed = {f.name for f in fields(Verdict)}
        draft = {k: v for k, v in verdict.items() if k in allowed}
        for key, value in draft.items():
            if key == "succeeded":
                if value is not None and type(value) is not bool:
                    raise SchemaError("draft succeeded must be a boolean or null")
            elif key == "evidence_ids":
                if not isinstance(value, list) or len(value) > 500 or any(not isinstance(v, str) or len(v) > 200 for v in value):
                    raise SchemaError("draft evidence_ids must be a list of IDs")
            elif value is not None and (not isinstance(value, str) or len(value) > 50000):
                raise SchemaError(f"invalid draft {key}")
        def change(d):
            if d["submission"]:
                raise SchemaError("this report is already submitted; replay the exercise for another attempt")
            if version is not None and (type(version) is not int or version != d["draft_version"]):
                raise BusyError("the draft changed in another window; reopen the case before saving")
            d["draft"] = draft
            d["draft_version"] += 1
        return self.public(self.store.update(case_id, change))

    def submit(self, case_id: str, verdict: dict) -> dict:
        v = Verdict.from_dict(verdict)
        def change(d):
            if d["submission"]:
                return  # The first submission is immutable and repeated clicks are idempotent.
            if d["state"] not in ("investigating", "awaiting_telemetry") or not d.get("truth"):
                raise SchemaError("this exercise has no verified, gradeable outcome")
            if not d["events"]:
                raise SchemaError("collect evidence before submitting; missing telemetry is not an analyst failure")
            ids = {e["event_id"] for e in d["events"]}
            if not set(v.evidence_ids) <= ids:
                raise SchemaError("report cites evidence IDs not saved in this case")
            report = grade(GroundTruth.from_dict(d["truth"]), v)
            d["submission"] = {"submitted_utc": now(), "verdict": asdict(v), "finding_score": report_dict(report),
                               "report_score": report_completeness(v, ids)}
            d["draft"] = asdict(v)
            d["state"] = "submitted"
        return self.public(self.store.update(case_id, change))

    def detection(self, case_id: str, rule_id: str, revision: str, rule_text: str, minimum: int = 1, maximum: int | None = None) -> dict:
        for name, value in (("rule_id", rule_id), ("revision", revision), ("rule_text", rule_text)):
            if not isinstance(value, str) or not value.strip() or len(value) > 100000:
                raise SchemaError(f"{name} is required (at most 100000 characters)")
        if type(minimum) is not int or minimum < 0 or (maximum is not None and (type(maximum) is not int or maximum < minimum)):
            raise SchemaError("invalid expected match range")
        def change(d):
            if not d["submission"] or d["mode"] != "live":
                raise SchemaError("detection checks require a submitted live case")
            collection = d["collections"].get("alerts")
            if not collection or not collection["complete"] or utc(collection["fetched_utc"]) < utc(d["telemetry_ready_after"]):
                raise SchemaError("refresh a complete alert snapshot after the ingestion wait before judging a detection")
            if d["truth"]["disposition"] == "benign" and (minimum != 0 or maximum != 0):
                raise SchemaError("benign controls must expect zero matches")
            ids = set(collection["event_ids"])
            start, end = utc(d["observed"]["started_utc"]), utc(d["window"]["end"])
            matches = []
            for row in d["events"]:
                if row["event_id"] in ids and row.get("rule") == rule_id.strip() and row.get("timestamp"):
                    if start <= utc(row["timestamp"]) <= end:
                        matches.append(row)
            total = len(matches)
            latency = min((utc(r["timestamp"]) - start).total_seconds() for r in matches) if matches else None
            check = {"checked_utc": now(), "rule_id": rule_id.strip(), "revision": revision.strip(),
                     "rule_text": rule_text, "rule_sha256": hashlib.sha256(rule_text.encode()).hexdigest(),
                     "minimum": minimum, "maximum": maximum, "matches": total,
                     "passed": total >= minimum and (maximum is None or total <= maximum),
                     "latency_seconds": latency, "evidence_ids": [r["event_id"] for r in matches],
                     "snapshot_utc": collection["fetched_utc"], "control": d["truth"]["disposition"] == "benign"}
            d["detections"].append(check)
        return self.public(self.store.update(case_id, change))

    @staticmethod
    def public(doc: dict) -> dict:
        keys = ("id", "state", "mode", "brief", "created_utc", "updated_utc", "target", "draft", "draft_version",
                "submission", "events", "collections", "detections", "error", "window", "telemetry_ready_after", "replay_of")
        out = {k: doc[k] for k in keys if k in doc}
        out["case_id"] = doc["id"]
        out["title"] = "Blind assessment" if doc["blind"] and not doc["submission"] else doc["scenario"]["title"]
        out["active"] = doc["state"] in ACTIVE
        if doc["submission"]:
            out["debrief"] = {k: doc.get(k) for k in ("truth", "intended", "observed", "execution", "scenario", "seed", "variant", "reset")}
        # Failed operational runs are ungraded; diagnostics can then be reviewed safely.
        if doc["state"] in ("preflight_failed", "reset_failed", "execution_failed", "execution_unknown", "interrupted", "blocked"):
            out["diagnostics"] = {k: doc.get(k) for k in ("diagnostic", "execution", "reset")}
        return out

    def get(self, case_id: str) -> dict:
        return self.public(self.store.get(case_id))

    def cases(self) -> list[dict]:
        result = []
        for d in self.store.all():
            p = self.public(d)
            result.append({k: p[k] for k in ("id", "state", "mode", "title", "created_utc", "replay_of")})
        return result

    def scores(self) -> dict:
        rows, report_scores, mode_rows, detections = [], [], {}, []
        for d in reversed(self.store.all()):
            if d["submission"] and not d.get("replay_of"):
                report = d["submission"]["finding_score"]
                row = {"case_id": d["id"], "scenario_id": d["scenario"]["id"], "ts": d["submission"]["submitted_utc"],
                       "mode": d["mode"], "tactic": d["truth"]["tactic"], "total": report["total"], "passed": report["total"] >= 60}
                rows.append(row)
                report_scores.append(d["submission"]["report_score"]["total"])
                mode_rows.setdefault(d["mode"], []).append(row)
            for detection in d["detections"]:
                detections.append({k: v for k, v in {"case_id": d["id"], **detection}.items() if k != "rule_text"})
        rows.sort(key=lambda r: (r["ts"], r["case_id"]))
        stats = history.from_rows(rows).as_dict()
        stats.update(recent=rows[-20:], by_mode={k: history.from_rows(v).as_dict() for k, v in mode_rows.items()},
                     report_average=round(sum(report_scores) / len(report_scores), 1) if report_scores else 0,
                     detections=detections[-50:])
        return stats

    def export(self, case_id: str, format: str = "json") -> str:
        doc = self.get(case_id)
        if format == "json":
            return json.dumps(doc, indent=2) + "\n"
        if format != "markdown":
            raise SchemaError("export format must be json or markdown")
        verdict = doc["submission"]["verdict"] if doc["submission"] else doc["draft"]
        lines = [f"# Investigation {case_id}", "", f"Status: {doc['state']} | Mode: {doc['mode']}", ""]
        for key in ("narrative", "disposition", "technique", "source_ip", "account", "succeeded", "timeline", "assets", "impact", "actions", "confidence", "self_review"):
            value = verdict.get(key)
            lines += [f"## {key.replace('_', ' ').title()}", "", "Unknown / not supplied" if value is None else str(value), ""]
        cited = set(verdict.get("evidence_ids", []))
        lines += ["## Cited evidence", ""]
        for event in doc["events"]:
            if event["event_id"] in cited:
                lines += [event["event_id"], "", "    " + json.dumps(event["raw"]).replace("\n", "\n    "), ""]
        if doc["submission"]:
            sub = doc["submission"]
            lines += [f"Finding accuracy: {sub['finding_score']['total']}/100", f"Report completeness: {sub['report_score']['total']}/100", "", sub['report_score']['note']]
        return "\n".join(lines) + "\n"
