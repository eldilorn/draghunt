"""`dealer grade` — score a verdict against sealed ground truth.

    python -m dealer grade --truth GT.json --verdict V.json
    python -m dealer grade --truth GT.json --verdict V.json --json

Exit status is 0 on a passing score (>= 60), 1 on a failing score, and 2 on a
usage or schema error, so it drops cleanly into a script or CI gate.
"""

from __future__ import annotations

import argparse
import json
import sys

from .schema import SchemaError, load_ground_truth, load_verdict
from .grader import grade


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
                {
                    "dimension": i.dimension,
                    "weight": i.weight,
                    "earned": i.earned,
                    "expected": i.expected,
                    "got": i.got,
                    "note": i.note,
                }
                for i in report.items
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(report.as_text())

    return 0 if report.total >= 60 else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dealer", description="The Dealer grading core.")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("grade", help="score a verdict against sealed ground truth")
    g.add_argument("--truth", required=True, help="path to sealed ground-truth JSON")
    g.add_argument("--verdict", required=True, help="path to analyst verdict JSON")
    g.add_argument("--json", action="store_true", help="emit a JSON report")
    g.set_defaults(func=_cmd_grade)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
