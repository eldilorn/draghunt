# The Dealer

Realistic blue-team investigation reps in **your own lab**, not on a stranger's frozen incident.

The Dealer fires a randomized, MITRE-mapped attack into your own SIEM, seals the ground
truth, lets you investigate the telemetry blind and write a verdict, then **grades that
verdict against the sealed truth**. You own the whole loop:

> attack → telemetry → detection → investigation → verdict → grade

LetsDefend and CyberDefenders hand you a stranger's frozen pcap that everyone else also
downloaded, so you never own the ground truth and can't tune a detection against it. The
Dealer flips that.

## Status

**v0.1 — the grading core.** The scoring brain is done and runnable today with zero
dependencies. The attack runner and the hosted tracking layer are on the roadmap below.

* **SIEM:** Wazuh only for v1. It's the maintainer's homelab stack.
* **Shape:** open-source, self-hostable core; a hosted grading/tracking layer is the
  eventual open-core line. No billing or multi-tenant auth yet, by design.

## The loop, concretely

1. **Deal a case.** A scenario is picked and its parameters randomized, then the truth is
   sealed to disk — source IP, account, technique, whether it succeeded, the correct call.
2. **Investigate blind.** You work the telemetry in Wazuh without opening the seal.
3. **Write a verdict** as JSON (see `fixtures/verdict.example.json`).
4. **Grade it:**

   ```
   python -m dealer grade --truth sealed.json --verdict my_verdict.json
   ```

## Quick start

No install, no dependencies — Python 3.11+ standard library only.

```bash
python -m dealer grade \
  --truth   fixtures/ground_truth.example.json \
  --verdict fixtures/verdict.example.json
```

```
Dealer verdict report — scenario EXAMPLE-01
Score: 90/100   Grade: A — clean read

  OK disposition  30.0/30  expected='malicious' got='malicious'
  ~  technique    15.0/25  expected='T1110.001' got='T1110'  (right technique, wrong sub-technique)
  OK source_ip    15.0/15  expected='203.0.113.7' got='203.0.113.7'
  OK account      15.0/15  expected='svc-backup' got='svc-backup'
  OK succeeded    15.0/15  expected='true' got='true'
```

Add `--json` for a machine-readable report. Exit code is `0` for a pass (score ≥ 60),
`1` for a fail, `2` for a bad file — so it slots straight into a script or CI gate.

Run the tests:

```bash
python -m unittest discover -s tests -v
```

## How grading works

The rubric is data-driven (`dealer/grader.py`, `WEIGHTS`). Defaults:

| Dimension   | Weight | Notes |
|-------------|:------:|-------|
| disposition |   30   | The spine. Calling malicious "benign" (or vice versa) caps the whole score. |
| technique   |   25   | Exact ATT&CK sub-technique = full; right parent technique = partial. |
| source_ip   |   15   | Exact match. |
| account     |   15   | Case-insensitive; a scenario with no account gives the points for free. |
| succeeded   |   15   | Did the attack achieve its objective? |

Reweight by editing `WEIGHTS`; the engine renormalizes to 100.

## The documents

Two JSON contracts, shared by the runner and the future hosted layer
(`dealer/schema.py`):

* **Ground truth** — sealed when a case is dealt, never shown until after you submit.
* **Verdict** — what you submit. Every field but `disposition` is optional; a partial
  verdict still grades, it just leaves points on the table.

## Roadmap

- [x] Grading core (`dealer grade`) with a data-driven rubric and tests
- [ ] `dealer deal` — seal a scenario to the Dealer's JSON format (bridges the existing bash runner)
- [ ] Wazuh telemetry helpers for investigating blind
- [ ] Hosted grading/tracking layer (FastAPI + SQLite) — attempt history, streaks, per-technique weak spots

## A note on scope

This repo is the **product**. The maintainer's private scenario lab (the actual attack
content) lives elsewhere and is deliberately not vendored here. The example fixtures are
synthetic and use only RFC 5737 / RFC 2606 documentation ranges.

## License

Apache-2.0.
