"""`draghunt` — the investigation-rep loop.

    draghunt list                         show the deck
    draghunt deal [--scenario ID]         seal a case, drop telemetry, print a blind brief
    draghunt verdict --out V.json         write a blank verdict to fill in
    draghunt grade --truth T --verdict V  score it, optionally --record
    draghunt stats                        reps, pass rate, streak, weakest tactic

A full offline rep needs no live range:

    draghunt deal --scenario DEMO-BRUTE
    # investigate the printed telemetry file, then:
    draghunt verdict --out my_verdict.json      # edit it
    draghunt grade --truth <sealed> --verdict my_verdict.json --record
    draghunt stats

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
from . import config as config_mod
from . import fire as fire_mod
from . import reset as reset_mod

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

    from .web import new_case_id
    case_id = new_case_id(case.scenario.id)
    SEAL_DIR.mkdir(parents=True, exist_ok=True)
    seal_path = SEAL_DIR / f"{case_id}.json"
    seal_path.write_text(json.dumps(catalog_mod.seal_dict(case.ground_truth), indent=2))
    os.chmod(seal_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

    print(case.blind_brief)

    if args.fire:
        cfg = config_mod.load()
        plan = fire_mod.build_plan(case, cfg, live=True)
        if not plan.ready:
            print("error: cannot fire, range not configured: " + ", ".join(plan.gaps),
                  file=sys.stderr)
            print("       run `draghunt init-config` and fill in range.toml.", file=sys.stderr)
            return 2
        if args.reset:
            print(f"Resetting target (mode={cfg.reset.mode}) ...")
            rr = reset_mod.reset_target(cfg, case.scenario.id, confirm=True)
            print(rr.render())
            if not rr.ok:
                print("  warning: reset had failures; the rep may not be clean.", file=sys.stderr)
        print(f"FIRING LIVE against {cfg.target.host} via {cfg.attacker.host} ...")
        result = fire_mod.execute(plan, confirm=True)
        win = result.window()
        (SEAL_DIR / f"{case_id}.fire.json").write_text(json.dumps({
            "returncode": result.returncode, "started_utc": result.started_utc,
            "finished_utc": result.finished_utc, "window": win, "command": result.command,
            "error": result.error}, indent=2))
        if result.ok:
            print(f"  fired OK. Investigate your SIEM for {win['start']} .. {win['end']}")
        else:
            print(f"  fire returned rc={result.returncode} error={result.error}", file=sys.stderr)
            if result.stderr:
                print("  stderr:", result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "", file=sys.stderr)
    elif not args.no_telemetry:
        TELEMETRY_DIR.mkdir(parents=True, exist_ok=True)
        tel_path = TELEMETRY_DIR / f"{case_id}.log"
        tel_path.write_text("\n".join(telemetry_mod.generate(case)) + "\n")
        print(f"Telemetry to investigate : {tel_path}")

    print(f"Ground truth (sealed)     : {seal_path}  (do not open until you submit)")
    print()
    print("Next: investigate, then")
    print(f"  draghunt verdict --out verdict.json     # fill it in")
    print(f"  draghunt grade --truth {seal_path} --verdict verdict.json --record")
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




def _cmd_desktop(args: argparse.Namespace) -> int:
    from . import desktop
    desktop.run(port=args.port)
    return 0


def _cmd_web(args: argparse.Namespace) -> int:
    from . import web
    web.serve(host=args.host, port=args.port)
    return 0


def _cmd_init_config(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"error: {out} exists (use --force)", file=sys.stderr)
        return 2
    out.write_text(config_mod.EXAMPLE_TOML)
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    print(f"Example range config written to {out} (0600). Fill it in for live mode.")
    return 0




def _cmd_reset(args: argparse.Namespace) -> int:
    cfg = config_mod.load()
    if cfg.reset.mode == "none":
        print("reset.mode is 'none' in range.toml — nothing to do.")
        return 0
    needs_confirm = cfg.reset.mode in ("snapshot", "both")
    if needs_confirm and not args.confirm:
        print("error: snapshot rollback is destructive. Re-run with --confirm.", file=sys.stderr)
        px = cfg.reset.proxmox
        print(f"       would revert VM {px.get('vmid','?')} on node {px.get('node','?')} "
              f"to snapshot '{px.get('snapshot','?')}'.", file=sys.stderr)
        return 2
    rr = reset_mod.reset_target(cfg, args.scenario or "", confirm=True)
    print(rr.render())
    return 0 if rr.ok else 1


def _cmd_alerts(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone
    from .siem import get_adapter
    cfg = config_mod.load()
    fire_path = SEAL_DIR / f"{args.case}.fire.json"
    if not fire_path.exists():
        print(f"error: no fire record for case {args.case} (offline case, or not fired)",
              file=sys.stderr)
        return 2
    window = json.loads(fire_path.read_text()).get("window", {})
    start = datetime.strptime(window["start"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    end = datetime.strptime(window["end"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    try:
        alerts = get_adapter(cfg.siem.adapter, cfg.siem.options).query_alerts(start, end, limit=args.limit)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {cfg.siem.adapter} query failed: {exc}", file=sys.stderr)
        return 1
    print(f"{len(alerts)} alerts in {window['start']} .. {window['end']}")
    for a in alerts:
        print(f"  {a.timestamp}  rule {a.rule} (lvl {a.level})  {a.source}  {a.description}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="draghunt", description="Draghunt investigation-rep loop.")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show the scenario deck").set_defaults(func=_cmd_list)

    d = sub.add_parser("deal", help="seal a case, drop telemetry, print a blind brief")
    d.add_argument("--scenario", help="scenario id (default: random)")
    d.add_argument("--seed", type=int, help="deterministic seed (default: random)")
    d.add_argument("--no-telemetry", action="store_true", help="seal only, no synthetic logs")
    d.add_argument("--fire", action="store_true", help="LIVE: fire against the configured range (needs range.toml)")
    d.add_argument("--reset", action="store_true", help="reset the target first (snapshot/cleanup per range.toml)")
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
    w = sub.add_parser("web", help="run the local control-center dashboard")
    w.add_argument("--host", default="127.0.0.1", help="bind host (localhost only)")
    w.add_argument("--port", type=int, default=8787)
    w.set_defaults(func=_cmd_web)

    dk = sub.add_parser("desktop", help="run Draghunt in a native window (falls back to browser)")
    dk.add_argument("--port", type=int, default=0, help="fixed port (default: auto)")
    dk.set_defaults(func=_cmd_desktop)

    ic = sub.add_parser("init-config", help="write an example range.toml")
    ic.add_argument("--out", default="range.toml")
    ic.add_argument("--force", action="store_true")
    ic.set_defaults(func=_cmd_init_config)

    rs = sub.add_parser("reset", help="reset the target (snapshot rollback and/or cleanup)")
    rs.add_argument("--scenario", help="scenario id, for scenario-specific cleanup")
    rs.add_argument("--confirm", action="store_true", help="required for destructive snapshot rollback")
    rs.set_defaults(func=_cmd_reset)

    al = sub.add_parser("alerts", help="pull SIEM alerts for a fired case's window")
    al.add_argument("--case", required=True, help="case id (see .groundtruth/*.fire.json)")
    al.add_argument("--limit", type=int, default=200)
    al.set_defaults(func=_cmd_alerts)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
