"""`dealer` — the investigation-rep loop.

    dealer list                         show the deck
    dealer deal [--scenario ID]         seal a case, drop telemetry, print a blind brief
    dealer verdict --out V.json         write a blank verdict to fill in
    dealer grade --truth T --verdict V  score it, optionally --record
    dealer stats                        reps, pass rate, streak, weakest tactic

A full offline rep needs no live range:

    dealer deal --scenario DEMO-BRUTE
    # investigate the printed telemetry file, then:
    dealer verdict --out my_verdict.json      # edit it
    dealer grade --truth <sealed> --verdict my_verdict.json --record
    dealer stats

Exit status: 0 pass / 0 ok, 1 failing grade, 2 usage or schema error.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from .schema import SchemaError, load_ground_truth, load_verdict
from .grader import grade
from . import catalog as catalog_mod
from . import telemetry as telemetry_mod
from . import history as history_mod

SEAL_DIR = Path(".groundtruth")
TELEMETRY_DIR = Path("telemetry")


def _cmd_list(args: argparse.Namespace) -> int:
    deck = catalog_mod.load_catalog()
    for s in deck.values():
        print(f"{s.id:<14} {s.technique:<11} {s.tactic:<16} {s.difficulty:<7} {s.title}")
    return 0


def _cmd_deal(args: argparse.Namespace) -> int:
    try:
        case = catalog_mod.deal(scenario_id=args.scenario, seed=args.seed)
    except SchemaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    SEAL_DIR.mkdir(parents=True, exist_ok=True)
    seal_path = SEAL_DIR / f"{stamp}-{case.scenario.id}.json"
    seal_path.write_text(json.dumps(catalog_mod.seal_dict(case.ground_truth), indent=2))
    os.chmod(seal_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

    print(case.blind_brief)

    if not args.no_telemetry:
        TELEMETRY_DIR.mkdir(parents=True, exist_ok=True)
        tel_path = TELEMETRY_DIR / f"{stamp}-{case.scenario.id}.log"
        tel_path.write_text("\n".join(telemetry_mod.generate(case)) + "\n")
        print(f"Telemetry to investigate : {tel_path}")

    print(f"Ground truth (sealed)     : {seal_path}  (do not open until you submit)")
    print()
    print("Next: investigate, then")
    print(f"  dealer verdict --out verdict.json     # fill it in")
    print(f"  dealer grade --truth {seal_path} --verdict verdict.json --record")
    return 0


_VERDICT_TEMPLATE = {
    "analyst": os.environ.get("USER", "you"),
    "disposition": "malicious | benign | inconclusive",
    "technique": "T____",
    "source_ip": "",
    "account": "",
    "succeeded": False,
    "narrative": "What you saw and why you made this call.",
}


def _cmd_verdict(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"error: {out} exists (use --force to overwrite)", file=sys.stderr)
        return 2
    out.write_text(json.dumps(_VERDICT_TEMPLATE, indent=2) + "\n")
    print(f"Blank verdict written to {out} — fill it in, then grade.")
    return 0


def _cmd_grade(args: argparse.Namespace) -> int:
    try:
        gt = load_ground_truth(args.truth)
        v = load_verdict(args.verdict)
    except SchemaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = grade(gt, v)

    if args.json:
        payload = {
            "scenario_id": report.scenario_id,
            "total": report.total,
            "band": report.band,
            "capped": report.capped,
            "items": [
                {"dimension": i.dimension, "weight": i.weight, "earned": i.earned,
                 "expected": i.expected, "got": i.got, "note": i.note}
                for i in report.items
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(report.as_text())

    if args.record:
        path = history_mod.record(report, gt)
        print(f"\nRecorded to {path}")

    return 0 if report.total >= 60 else 1


def _cmd_stats(args: argparse.Namespace) -> int:
    print(history_mod.stats().as_text())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dealer", description="The Dealer investigation-rep loop.")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show the scenario deck").set_defaults(func=_cmd_list)

    d = sub.add_parser("deal", help="seal a case, drop telemetry, print a blind brief")
    d.add_argument("--scenario", help="scenario id (default: random)")
    d.add_argument("--seed", type=int, help="deterministic seed (default: random)")
    d.add_argument("--no-telemetry", action="store_true", help="seal only, no synthetic logs")
    d.set_defaults(func=_cmd_deal)

    v = sub.add_parser("verdict", help="write a blank verdict template")
    v.add_argument("--out", default="verdict.json", help="output path (default: verdict.json)")
    v.add_argument("--force", action="store_true", help="overwrite if it exists")
    v.set_defaults(func=_cmd_verdict)

    g = sub.add_parser("grade", help="score a verdict against sealed ground truth")
    g.add_argument("--truth", required=True, help="path to sealed ground-truth JSON")
    g.add_argument("--verdict", required=True, help="path to analyst verdict JSON")
    g.add_argument("--json", action="store_true", help="emit a JSON report")
    g.add_argument("--record", action="store_true", help="append the result to local history")
    g.set_defaults(func=_cmd_grade)

    sub.add_parser("stats", help="reps, pass rate, streak, weakest tactic").set_defaults(func=_cmd_stats)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
