# Draghunt

Practice alert triage, incident reporting, and detection engineering in your own lab.
The dashboard lets you run an exercise, investigate its events, save an evidence-backed
report, submit it, and revisit your scores and debrief.

The build includes persistent cases and reports, protected local controls, synthetic
exercises, and a versioned private-runner integration. The synthetic workflow works
without a lab. Live use requires a compatible private dispatcher and a configured
Wazuh/target environment; installing this repository alone does not provide attacks.

## Start the dashboard

Linux with Python 3.11+; the application core uses the standard library.

```bash
python -m draghunt web
# Open http://127.0.0.1:8787
```

The dashboard has three tabs: **Practice**, **Progress**, and **Settings**.

1. Choose **Blind draw** or a named exercise on Practice, then click **Run**. Synthetic
   exercises need no lab. To run against your own range, fill in **Settings** first (see
   below); **Run against my real lab** stays disabled, and tells you what is missing,
   until the range is configured.
2. Expand/search saved events and use **Cite** to reference evidence in your report.
3. Write your findings, timeline, affected assets, impact, and recommendations.
   Drafts autosave; **Save draft** also saves immediately.
4. Submit the report. The answer key and execution details become available in the debrief.
5. Reopen an exercise from **Saved exercises**, or export its report as Markdown/JSON.
   **Replay as practice** preserves the scenario parameters and saves another case.
6. **Progress** holds your scores, per-tactic accuracy, run-mode breakdown, and detection
   history.

Enter your environment on the **Settings** tab: the attacker box, target, Wazuh indexer
and credentials, an optional reset, and your private scenario catalog. It is saved to the
profile file on this machine at owner-only permissions. Passwords and API tokens are stored
but never shown back in the page; leave a secret field blank to keep the current value.
The **Advanced** control on Practice holds a repeatable seed for debugging; leave it blank
for a fresh draw.

The default deck contains SSH password guessing, a web-shell attempt, suspicious DNS
exfiltration activity, and authorized backup activity as a benign control. These are
synthetic exercises with fictional events. Facts the evidence cannot establish are
excluded from scoring; resolver queries alone do not establish completed exfiltration.

## Scores

**Finding accuracy** compares disposition, ATT&CK technique, source IP, account, and
objective outcome against the hidden answer key. Applicable weights are 30/25/15/15/15,
normalized to 100 after excluding unobservable/not-applicable fields. A wrong
malicious/benign disposition caps accuracy at 40. Parent-technique matches earn partial
credit. A score of 60 or more passes the findings rubric.

**Report completeness** separately checks summary, timeline, affected assets, impact,
actions, confidence, valid saved evidence references, and self-review. It does not
claim to judge prose quality or whether every citation logically supports a claim.
Use the self-review prompt for that assessment.

The first submission is immutable. Clicking Submit again cannot create another score.
Replays remain available in history but are excluded from first-submission averages and
streaks. Synthetic and live results are also broken out by mode.

## Configuration and storage

The dashboard, desktop app, and CLI share stable locations:

- Config: `$XDG_CONFIG_HOME/draghunt/range.toml`, normally `~/.config/draghunt/range.toml`.
- Data: `$XDG_DATA_HOME/draghunt`, normally `~/.local/share/draghunt`.
- Overrides: `DRAGHUNT_CONFIG`, `DRAGHUNT_DATA_DIR`, or `draghunt --config /path/range.toml …`.

```bash
python -m draghunt init-config
```

`control.data_dir` and `control.catalog_dir` may override these locations; relative
paths resolve against the profile file. Cases, drafts, reports, evidence snapshots,
and detection checks are stored in `cases.sqlite3`. Final answer keys also have private
JSON files under `sealed/`. Treat the whole data directory as private and back it up.
The answer key is hidden by the application, not encrypted against the machine owner.

Existing legacy `range.toml`, `.groundtruth/`, `telemetry/`, and `.draghunt/history.jsonl`
are left untouched. Select an old profile explicitly with `--config ./range.toml` and
update its runner/agent settings before live use. Old truth/verdict files can still be
compared with `grade --truth`; recorded legacy comparisons are kept separately from
new case scores. Old score-only history cannot reconstruct reports that were never saved.

## Connect your lab

Keep private attack content in your own runner repository. Configure its metadata path
with `control.catalog_dir`, and mark supported private scenarios `"live": true`.
The private catalog extends the included demo deck for both CLI and dashboard. Use unique
IDs. Public demo scenarios cannot be fired live.

The dispatcher must implement [runner protocol v1](docs/RUNNER-PROTOCOL.md): a read-only
preflight plus a structured, case-linked result with actual source/account/outcome,
action timestamps, and verification references. An exit code of zero is insufficient.
An intended success parameter is never treated as the observed outcome. Live runs always
originate from the configured attacker host, since one box cannot spoof its source; the
catalog's `source_pool` randomizes synthetic exercises only, and the graded source IP is
the one the runner observed.

Set the target's Wazuh `agent_id`, indexer URL, and read credential. Alert collection is
restricted to that agent and the saved execution window; complete raw documents are
retained with stable evidence IDs. Collection paginates and reports truncation or
partial indexer results. **Raw Wazuh events** additionally requires archive indexing and
`siem.wazuh.events_index`. Missing alerts alone do not prove missing activity.

The indexer and Proxmox API URLs must be HTTPS and are always certificate-verified; for a
self-signed lab CA set `ca_file` rather than disabling verification. Prefer the
`DRAGHUNT_SIEM_PASSWORD` and `DRAGHUNT_PROXMOX_SECRET` environment variables for secrets.
A profile that holds a secret inline is refused unless it is mode 0600.

Optional reset modes are `snapshot`, `cleanup`, `both`, and `none`. Set
`reset.proxmox.target_host` to the same address as `target.host`; a rollback refuses to
run unless they match, so a stale `vmid` can never revert the wrong VM. Snapshot resets wait
for Proxmox rollback/start tasks. Failed resets stop the run. The runner must confirm
target services and telemetry readiness before execution. One controller data directory
serializes operations against each configured target. Use the same data directory for
profiles that control the same target.

Live runs require explicit CLI `--fire` or confirmation of the named target in the UI.
A timed-out or unverifiable execution is ungraded and requires a successful reset before
another live run; remote processes may outlive a disconnected SSH session.

See [live operation and acceptance checks](docs/LIVE-MODE-PLAN.md). No live lab execution
is implied by the automated test suite.

## Detection exercises

Deploy/edit your Wazuh rule using your existing lab tools, then run or replay an exercise.
After submitting its report, refresh a complete alert snapshot after the configured
ingestion wait. Record the rule ID, revision, definition, and expected match range under
**Detection check**. Benign controls must expect zero matches.

Checks retain the declared rule definition/hash, revision, matched evidence, pass/fail,
and first-match latency. The dashboard compares results across cases and revisions.
Use a fresh replay after changing a rule: querying old indexed alerts does not rerun the
new rule against old events. Revision labels are supplied by the analyst; Draghunt does
not inspect/deploy manager rule files or independently verify the deployed revision.
Matches are measured within a target/time window, not proof of causality in a busy lab.

## CLI

Use `--config` before the command when selecting a profile.

```bash
python -m draghunt list
python -m draghunt lay --scenario DEMO-BRUTE --seed 7
python -m draghunt cases
python -m draghunt case CASE_ID
python -m draghunt verdict --case CASE_ID --out verdict.json
# Edit the report and cite event IDs from the case.
python -m draghunt save --case CASE_ID --verdict verdict.json
python -m draghunt grade --case CASE_ID --verdict verdict.json
python -m draghunt export --case CASE_ID --format markdown --out report.md
python -m draghunt stats
```

For a configured private scenario:

```bash
python -m draghunt --config /path/to/range.toml lay --scenario PRIVATE-01 --fire --reset
python -m draghunt --config /path/to/range.toml alerts --case CASE_ID --limit 5000
python -m draghunt --config /path/to/range.toml alerts --case CASE_ID --kind events
python -m draghunt --config /path/to/range.toml detection --case CASE_ID \
  --rule-id 100001 --revision v2 --rule-file rule.xml --minimum 1
```

New case submissions are always recorded. `grade --truth T.json --verdict V.json` remains
a standalone legacy comparison; `--record` deduplicates by truth-file identity and keeps
those comparisons separate. `--json` emits parseable JSON without trailing prose.
CLI exit codes: 0 success/pass, 1 completed failing grade/check or unsuccessful live run,
2 invalid input/configuration or a refused operation.

## Desktop and packaging

`python -m draghunt desktop` opens a pywebview window when its optional dependency and
GUI backend are available, otherwise a browser dashboard. The server stays running until
the native window closes or the launching process is stopped.

`packaging/install.sh` installs into an isolated environment and registers a desktop
launcher. See [packaging](docs/PACKAGING.md) for the AppImage recipe and validation scope.

## Development

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v
node --check draghunt/static/app.js
```

Tests use temporary data, harmless local commands, and fake runner/SIEM/reset responses.
HTTP tests require localhost sockets. [Architecture](docs/ARCHITECTURE.md) describes the
shared workflow and storage boundaries. Hosting, billing, and additional SIEM adapters
are outside the current build.

Apache-2.0.
