# Architecture

## What makes it a product, not a scorer

A grader that diffs two hand-written JSON files is a function, not a product. The value
is the **closed loop** and the **reason to return**. So the unit of work is a *rep* you
can actually run, and the thing that pulls you back is your trend over reps. Both had to
exist for this to be a product; v0.2 builds them around the grader.

```
  deal ─────────────► seal (JSON ground truth, 0600, git-ignored)
   │                        │
   ├─► synthetic telemetry ─┼──► investigate blind
   │   OR your own runner   │           │
   │      (real range)      │        verdict (JSON)
   │                        ▼           │
   │                     grade ◄────────┘
   │                        │
   └────────────────────► record ──► stats (reps, streak, weakest tactic)
```

## Modules

| File                  | Responsibility |
|-----------------------|----------------|
| `dealer/schema.py`    | `GroundTruth` / `Verdict` contracts + validation. No deps. |
| `dealer/catalog.py`   | Load the public deck; `deal()` randomizes (seeded) and seals a case. |
| `dealer/telemetry.py` | Synthetic, investigable logs for a dealt case. No private content. |
| `dealer/grader.py`    | Data-driven rubric → `Report`. All scoring policy lives here. |
| `dealer/history.py`   | Append reps to a local JSONL ledger; compute `stats`. |
| `dealer/cli.py`       | `list / deal / verdict / grade / stats`. |
| `dealer/data/catalog/`| Public scenarios: ATT&CK metadata + randomization knobs only. |

## The public/private boundary

The catalog is metadata: an ATT&CK mapping, which accounts and source IPs to randomize
over, a telemetry recipe. It contains **no attack commands**. Two run modes keep the
boundary clean:

* **Offline:** `telemetry.py` synthesizes logs from the sealed truth. Fully public.
* **Live:** `deal` seals the truth, then the user fires their *own* private runner
  (the maintainer's `casefiles-lab`) against a real range. The product orchestrates and
  grades; it never carries the attack content.

So the open-source repo can be public in full, and private scenario decks plug in without
ever being vendored.

## Determinism

`deal(seed=N)` is reproducible: same seed, same case. When no seed is given one is drawn
and written into the sealed truth's `notes`, so any dealt case can be re-dealt for review
or bug reports.

## Deliberately not built yet

* **Live bridge**: fire a user runner and pull real Wazuh telemetry. The seam exists
  (deal already seals the JSON the runner would need); the fire-and-collect step is next.
* **Benign decoys**: today every demo case is malicious, so the disposition call is real
  but not yet adversarial. Decoy scenarios make "malicious vs benign" a genuine decision.
* **Hosted layer** (FastAPI + SQLite): syncs the same JSONL records. Reserved in
  `pyproject.toml` under the `hosted` extra.
