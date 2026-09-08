"""Command-line access to the same saved exercises as the dashboard."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import config, history, reset
from .grader import grade, report_dict
from .schema import SchemaError, load_ground_truth, load_verdict
from .store import BusyError, private_write
from .workflow import Workflow


VERDICT_TEMPLATE = {"disposition": "inconclusive", "technique": None, "source_ip": None,
                    "account": None, "succeeded": None, "narrative": "", "timeline": "", "assets": "",
                    "impact": "", "actions": "", "confidence": None, "evidence_ids": [], "self_review": ""}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="draghunt", description="Run, investigate, report, and review saved lab exercises.")
    parser.add_argument("--config", help="range profile (default: XDG config directory or DRAGHUNT_CONFIG)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list configured scenario metadata")
    lay = sub.add_parser("lay", aliases=["run"], help="create and run an exercise")
    lay.add_argument("--scenario")
    lay.add_argument("--seed", type=int)
    lay.add_argument("--fire", action="store_true", help="explicitly authorize live execution against the configured target")
    lay.add_argument("--reset", action="store_true", help="reset the configured target before live execution")
    lay.add_argument("--replay", help="replay a submitted case as practice")
    sub.add_parser("cases", help="list saved exercises")
    show = sub.add_parser("case", help="resume a case, including saved evidence and report")
    show.add_argument("case_id")
    verdict = sub.add_parser("verdict", help="export the case draft or a blank report template")
    verdict.add_argument("--case")
    verdict.add_argument("--out", default="verdict.json")
    verdict.add_argument("--force", action="store_true")
    draft = sub.add_parser("save", help="save a draft report")
    draft.add_argument("--case", required=True)
    draft.add_argument("--verdict", required=True)
    grade_parser = sub.add_parser("grade", help="submit the first report for a case")
    source = grade_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--case")
    source.add_argument("--truth", help="legacy standalone JSON comparison")
    grade_parser.add_argument("--verdict", required=True)
    grade_parser.add_argument("--record", action="store_true", help="legacy comparisons only; new case submissions are always saved")
    grade_parser.add_argument("--json", action="store_true")
    export = sub.add_parser("export", help="export a saved report and evidence")
    export.add_argument("--case", required=True)
    export.add_argument("--format", choices=["json", "markdown"], default="markdown")
    export.add_argument("--out")
    export.add_argument("--force", action="store_true")
    alerts = sub.add_parser("alerts", help="collect complete, scoped SIEM evidence")
    alerts.add_argument("--case", required=True)
    alerts.add_argument("--kind", choices=["alerts", "events"], default="alerts")
    alerts.add_argument("--limit", type=int, default=2000)
    detection = sub.add_parser("detection", help="record a rule check against a submitted live case")
    detection.add_argument("--case", required=True)
    detection.add_argument("--rule-id", required=True)
    detection.add_argument("--revision", required=True)
    detection.add_argument("--rule-file", required=True)
    detection.add_argument("--minimum", type=int, default=1)
    detection.add_argument("--maximum", type=int)
    sub.add_parser("stats", help="first-submission scores and detection checks")
    web = sub.add_parser("web", help="open the local dashboard server")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8787)
    desktop = sub.add_parser("desktop", help="open the native window or browser fallback")
    desktop.add_argument("--port", type=int, default=0)
    init = sub.add_parser("init-config", help="write a private example range profile")
    init.add_argument("--out")
    init.add_argument("--force", action="store_true")
    reset_parser = sub.add_parser("reset", help="reset the configured target")
    reset_parser.add_argument("--scenario", default="")
    reset_parser.add_argument("--confirm", action="store_true")
    return parser


def write_output(path: str, content: str, force: bool = False) -> None:
    target = Path(path).expanduser()
    if target.exists() and not force:
        raise SchemaError(f"{target} already exists; use --force to replace it")
    private_write(target, content)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init-config":
            target = args.out or args.config or str(config.default_path())
            write_output(target, config.EXAMPLE_TOML, args.force)
            print(f"Example profile: {target}. Fill in the target, credentials, and private runner catalog.")
            return 0
        config_path = args.config or config.default_path()
        if args.command in ("web", "desktop"):
            # First-run friendly: a missing profile starts synthetic; Settings creates it.
            cfg = config.load(config_path, missing_ok=True)
            if args.command == "web":
                from .web import serve
                serve(args.host, args.port, cfg, config_path)
            else:
                from .desktop import run
                run(port=args.port, cfg=cfg, config_path=config_path)
            return 0
        cfg = config.load(args.config)
        workflow = Workflow(cfg)
        if args.command == "list":
            for scenario in workflow.deck().values():
                print(f"{scenario.id:20} {scenario.technique or 'n/a':10} {'live' if scenario.live else 'synthetic':10} {scenario.title}")
        elif args.command in ("lay", "run"):
            case = workflow.create(args.scenario, args.seed, args.fire, args.reset, args.replay)
            if args.fire:
                print(f"Running case {case['id']} against {cfg.target.host}")
                case = workflow.run_live(case["id"], confirm=True)
            print(f"Case: {case['id']}\nState: {case['state']}\n{case['brief']}")
            if case.get("error"):
                print(case["error"], file=sys.stderr)
            print(f"Resume: draghunt case {case['id']}\nReport: draghunt verdict --case {case['id']} --out verdict.json")
            return 0 if case["state"] in ("investigating", "awaiting_telemetry") else 1
        elif args.command == "cases":
            print(json.dumps(workflow.cases(), indent=2))
        elif args.command == "case":
            print(json.dumps(workflow.get(args.case_id), indent=2))
        elif args.command == "verdict":
            if args.case:
                case = workflow.get(args.case)
                verdict = case["submission"]["verdict"] if case["submission"] else case["draft"] or VERDICT_TEMPLATE
            else:
                verdict = VERDICT_TEMPLATE
            write_output(args.out, json.dumps(verdict, indent=2) + "\n", args.force)
            print(f"Report draft: {args.out}")
        elif args.command == "save":
            workflow.save_draft(args.case, json.loads(Path(args.verdict).read_text()))
            print("Draft saved.")
        elif args.command == "grade":
            verdict = load_verdict(args.verdict)
            if args.case:
                case = workflow.submit(args.case, asdict(verdict))
                report = case["submission"]
                total = report["finding_score"]["total"]
                if args.json:
                    print(json.dumps(report, indent=2))
                else:
                    print(f"Finding accuracy: {total}/100\nReport completeness: {report['report_score']['total']}/100")
                    print(report["report_score"]["note"])
            else:
                truth = load_ground_truth(args.truth)
                report = grade(truth, verdict)
                total = report.total
                if args.record:
                    # Keep historical comparisons separate from verified case scores.
                    key = hashlib.sha256(Path(args.truth).resolve().as_posix().encode() + Path(args.truth).read_bytes()).hexdigest()
                    history.record(report, truth, workflow.store.root / "legacy-history.jsonl", case_id=key)
                print(json.dumps(report_dict(report), indent=2) if args.json else report.as_text())
            return 0 if total >= 60 else 1
        elif args.command == "export":
            text = workflow.export(args.case, args.format)
            if args.out:
                write_output(args.out, text, args.force)
                print(f"Report exported: {args.out}")
            else:
                print(text, end="")
        elif args.command == "alerts":
            print(json.dumps(workflow.collect(args.case, args.kind, args.limit), indent=2))
        elif args.command == "detection":
            case = workflow.detection(args.case, args.rule_id, args.revision, Path(args.rule_file).read_text(), args.minimum, args.maximum)
            print(json.dumps(case["detections"][-1], indent=2))
            return 0 if case["detections"][-1]["passed"] else 1
        elif args.command == "stats":
            print(json.dumps(workflow.scores(), indent=2))
            legacy = workflow.store.root / "legacy-history.jsonl"
            if legacy.exists():
                print("Legacy standalone comparisons (excluded from case scores):")
                print(history.stats(legacy).as_text())
        elif args.command == "reset":
            if cfg.reset.mode != "none" and not args.confirm:
                px = cfg.reset.proxmox
                raise SchemaError(f"reset needs --confirm: target {cfg.target.host}, VM {px.get('vmid', 'n/a')}, snapshot {px.get('snapshot', 'n/a')}")
            with workflow.store.target_lock(cfg.target.host):
                result = reset.reset_target(cfg, args.scenario, confirm=args.confirm)
                if result.ok and cfg.reset.mode != "none":
                    workflow.acknowledge_reset(cfg.target.host)
            print(result.render())
            return 0 if result.ok else 1
        return 0
    except (SchemaError, config.ConfigError, BusyError, reset.ResetBlocked, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
