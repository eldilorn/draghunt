# Architecture

## Why the grader is the first slice

The seed prototype (`casefiles-lab`, private) already fires attacks and seals ground
truth. That's the lab half. What turns it from a lab script into a *product* is
**automated grading** — the piece that makes "I own the ground truth" repeatable and
scoreable. It also needs no live range to be useful, so it's the highest-leverage thing
to build first and the natural spine for everything downstream.

## Shape

```
                 ┌─────────────────┐
   deal a case → │  ground truth   │ ── sealed JSON ──┐
                 │  (private lab)   │                  │
                 └─────────────────┘                  ▼
                                              ┌──────────────┐
   investigate blind in Wazuh                 │   grader     │ → report (text / JSON)
                                              │ (this repo)  │
   write a verdict ──────── verdict JSON ────►└──────────────┘
```

Two JSON documents, one scoring engine. The runner (open source) and the future hosted
layer both speak the same contract, so nothing is re-modeled at the boundary.

## Modules

| File               | Responsibility |
|--------------------|----------------|
| `dealer/schema.py` | The `GroundTruth` and `Verdict` contracts + validation. No deps. |
| `dealer/grader.py` | Data-driven rubric → `Report`. All scoring policy lives here. |
| `dealer/cli.py`    | `dealer grade` argparse front end; text or `--json`; scriptable exit codes. |

## Deliberately not built yet

* **Hosted layer** (FastAPI + SQLite): attempt history, streaks, weak-spot tracking.
  Reserved in `pyproject.toml` under the `hosted` extra. Same language, self-hostable.
* **`dealer deal`**: a bridge that seals a scenario to this JSON format. The existing
  bash `dealer.sh` writes a text seal; a converter is the clean seam, not a rewrite.
* **Multi-SIEM, auth, billing**: out of scope for v1 on purpose.

## Boundary rule

The private scenario deck (attack specifics, scenario text) is never vendored into this
product repo. The grader consumes a generic ground-truth *shape*, not any scenario's
content. Example fixtures are synthetic and use documentation-only IP ranges
(RFC 5737 / RFC 2606).
