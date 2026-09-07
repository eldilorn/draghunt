# The Dealer

Realistic blue-team investigation reps in **your own lab**, not on a stranger's frozen
incident. You own the whole loop:

> deal → seal ground truth → investigate telemetry blind → write a verdict → grade → track

LetsDefend and CyberDefenders hand you a stranger's frozen pcap that everyone else also
downloaded, so you never own the ground truth and can't tune a detection against it. The
Dealer flips that: it deals *you* a randomized, MITRE-mapped case, seals the truth before
you look, and grades your verdict against it.

## Status

**v0.6 — offline loop, web control center, gated live fire + reset, and SIEM alert pull.** Deal a case, get
synthetic telemetry to investigate, submit a verdict, get graded, and track your reps
over time. When you have a range, the same `deal` bridges to your own attack runner
instead of the synthetic telemetry (see "Two ways to run" below).

* **SIEM:** Wazuh is the target for the live path. It's the maintainer's homelab stack.
* **Shape:** open-source, self-hostable loop; a hosted grading/tracking layer is the
  eventual open-core line. No billing or multi-tenant auth yet, by design.

## Run a full rep in 60 seconds

No install, no dependencies — Python 3.11+ standard library only.

```bash
# 1. deal a case: seals the truth, drops telemetry to investigate, prints a blind brief
python -m dealer deal --scenario DEMO-BRUTE

# 2. investigate the printed telemetry/*.log file the way you'd work Wazuh

# 3. write your verdict, then fill it in
python -m dealer verdict --out verdict.json

# 4. grade it against the sealed truth, and record the rep
python -m dealer grade --truth .groundtruth/<sealed>.json --verdict verdict.json --record

# 5. see how you're trending
python -m dealer stats
```

A graded rep looks like this:

```
Dealer verdict report — scenario DEMO-BRUTE
Score: 100/100   Grade: A — clean read

  OK disposition  30.0/30  expected='malicious' got='malicious'
  OK technique    25.0/25  expected='T1110.001' got='T1110.001'  (exact)
  OK source_ip    15.0/15  expected='203.0.113.42' got='203.0.113.42'
  OK account      15.0/15  expected='deploy' got='deploy'
  OK succeeded    15.0/15  expected='true' got='true'
```

And `stats` is the reason to come back:

```
Dealer stats
  reps      : 3
  passed    : 3 (100%)
  avg score : 77/100
  streak    : 3 in a row
  by tactic :
      exfiltration           60/100   <- weakest
      credential-access      85/100
```

## The deck

```bash
python -m dealer list
```

Ships with three synthetic demo scenarios (SSH brute force, web shell, DNS exfil), each
mapped to ATT&CK. Every deal randomizes the source, the account, and whether the attack
lands, and seals that truth blind — so no two reps are the same and the answer key is
never the one everyone else downloaded.


## Control center (web dashboard)

A local, zero-dependency dashboard drives the whole loop from the browser:

```bash
python -m dealer web        # http://127.0.0.1:8787
```

Deal a case, read the synthetic telemetry, submit a verdict, and see it graded,
all in one page. It binds to localhost only, on purpose: live mode can fire real
attacks, so nothing on your network may reach the button.

## Live mode (planned, phased)

The same dashboard is the control center for a real range: it deals and seals a
case, drives your Kali box over SSH to fire your own attack runner, pulls the
alerts from your SIEM, grades your verdict, and resets the target between reps.
Live fire is real as of v0.4, behind an explicit gate: it refuses unless the range
is configured and you confirm. Fire from the CLI with `dealer deal --scenario S01 --fire`,
or tick the live-fire box in the dashboard. Set it up with:

```bash
python -m dealer init-config   # writes an example range.toml (0600)
```

See `docs/LIVE-MODE-PLAN.md` for the architecture, the phased build, and the
config you'll need (Kali, target, SIEM, Proxmox).

### Any SIEM, one seam

Everything is SIEM-agnostic except pulling alerts, which lives behind a small
adapter interface (`dealer/siem`). **Wazuh** is the one shipped adapter; adding
Splunk, Elastic, or anything else is a new class, not a fork.

## Two ways to run

1. **Offline (default).** `deal` writes synthetic telemetry you investigate directly. No
   range needed. This is how the demo scenarios above work.
2. **Against your range.** `deal` seals the same JSON truth, and you fire the matching
   attack from your **own private runner** (e.g. the maintainer's `casefiles-lab`), then
   investigate the real telemetry in Wazuh. The Dealer never ships attack code; it deals
   the case and grades the verdict. Your scenarios stay yours.

## How grading works

Data-driven rubric (`dealer/grader.py`, `WEIGHTS`):

| Dimension   | Weight | Notes |
|-------------|:------:|-------|
| disposition |   30   | The spine. Calling malicious "benign" (or vice versa) caps the whole score at 40. |
| technique   |   25   | Exact ATT&CK sub-technique = full; right parent technique = partial. |
| source_ip   |   15   | Exact match. |
| account     |   15   | Case-insensitive; a scenario with no account gives the points for free. |
| succeeded   |   15   | Did the attack achieve its objective? |

Exit codes: `0` pass (≥60) / ok, `1` failing grade, `2` bad input — so it slots into CI.

## Commands

| Command | What it does |
|---------|--------------|
| `dealer list` | show the scenario deck |
| `dealer deal [--scenario ID] [--seed N]` | seal a case, drop telemetry, print a blind brief |
| `dealer verdict --out V.json` | write a blank verdict to fill in |
| `dealer grade --truth T --verdict V [--record] [--json]` | score it, optionally record |
| `dealer reset --confirm` | reset the target (snapshot rollback and/or cleanup) |
| `dealer alerts --case <id>` | pull SIEM alerts for a fired case's window |
| `dealer stats` | reps, pass rate, streak, weakest tactic |

## Roadmap

- [x] Grading core with a data-driven rubric
- [x] `deal` — seal a case to JSON, deterministic with `--seed`
- [x] Synthetic telemetry so a rep is playable offline
- [x] Local tracking (`stats`): reps, pass rate, streak, weakest tactic
- [ ] Bridge `deal` to fire a user-supplied runner and pull real Wazuh telemetry
- [ ] Benign decoy scenarios (so "malicious vs benign" is a real call, not a given)
- [ ] Hosted grading/tracking layer (FastAPI + SQLite) syncing the same records

## Scope notes

This repo is the **product**. The maintainer's private scenario lab (real attack content)
lives elsewhere and is deliberately not vendored here. The demo scenarios and all
telemetry are synthetic and use only RFC 5737 / RFC 2606 documentation ranges and
example.com.

## License

Apache-2.0.
