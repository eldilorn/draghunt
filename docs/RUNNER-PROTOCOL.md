# Private runner protocol v1

Draghunt invokes your dispatcher on the attacker over system SSH. Scenario metadata and
attack implementations remain private. This contract is intentionally stricter than the
old environment-only wrapper: the controller must distinguish intended behavior, actual
outcome, and infrastructure failure.

A private catalog has the same JSON metadata fields as `draghunt/data/catalog/`, plus
`"live": true`. Set `control.catalog_dir` to its directory. IDs use uppercase letters,
digits, and hyphens. `technique` may be null for a benign control. `source_pool` and
`succeed_prob` select intended parameters; the result must supply actual values.
Metadata may include an offline telemetry generator when it also supports synthetic use.

The controller passes these environment variables to `bash <runner.dir>/<runner.entry>`:

| Variable | Meaning |
|---|---|
| `DRAGHUNT_PROTOCOL` | `1` |
| `ACTION` | `preflight`, `run`, or `cleanup` |
| `CASE_ID` | Opaque case identity, present for preflight/run |
| `SCN` | Private scenario ID |
| `TARGET`, `TARGET_USER` | Configured victim and optional login |
| `SRC_IP` | Configured attacker address; report the observed address if routing/NAT differs |
| `ACCOUNT`, `VARIANT`, `SEED` | Intended randomized parameters |
| `SUCCEED` | Requested variant outcome: `yes`, `no`, or `unknown`; never a verification result |
| `DRY_RUN` | `1` for preflight; `0` for a confirmed run/cleanup |

Preflight must be read-only. Write exactly one JSON document to stdout; send diagnostics
to stderr. An old dispatcher that treats every action as an attack must be updated before
it is connected to this application.

Example preflight response (identities must echo the request):

```json
{
  "protocol_version": 1,
  "case_id": "20260908-150000-ABCD0123456789AB",
  "scenario_id": "PRIVATE-01",
  "target": "192.0.2.20",
  "ready": true,
  "checks": {"runner": true, "target": true, "telemetry": true}
}
```

`runner` verifies the selected scenario exists and this protocol is supported. `target`
checks required services, accounts, and prerequisites. `telemetry` checks the target's
required logging/agent health. Report booleans, not strings. Before a requested reset,
the controller initially requires runner compatibility only; target/telemetry may be down.
After reset it requires all checks, polling up to `runner.ready_timeout`. The controller
also validates indexer access and a scoped search before firing.

A completed exercise exits zero and returns a JSON result like this:

```json
{
  "protocol_version": 1,
  "case_id": "20260908-150000-ABCD0123456789AB",
  "scenario_id": "PRIVATE-01",
  "target": "192.0.2.20",
  "status": "completed",
  "started_utc": "2026-09-08T15:00:01Z",
  "finished_utc": "2026-09-08T15:00:09Z",
  "ground_truth": {
    "scenario_id": "PRIVATE-01",
    "technique": "T1110.001",
    "tactic": "credential-access",
    "source_ip": "192.0.2.10",
    "account": "lab-account",
    "succeeded": false,
    "disposition": "malicious"
  },
  "completed_actions": ["Completed the configured authentication exercise"],
  "evidence": ["Private verification artifact: run-123/authentication-check.json"]
}
```

The controller verifies protocol/case/scenario/target identity, classification consistency,
strict field types, action/evidence references, and timezone-aware timestamps inside the
SSH execution window (30 seconds of clock tolerance). Keep lab clocks synchronized.
The example is illustrative: do not return static evidence or copy intended success into
this result. Your dispatcher must verify actual results. The controller cannot independently
validate the content of private artifact references; the dispatcher is trusted for that task.

An attack whose objective failed is still a completed exercise: use exit zero and
`succeeded: false`. If available evidence cannot establish the objective outcome, use
`succeeded: null`; that dimension is excluded from scoring. Use `account: null` or
`technique: null` only when not applicable/observable. Scenario classification must match
metadata, including benign controls.

Infrastructure failure, missing prerequisites, or a partial/unverified execution must not
return a completed result. Exit nonzero and place diagnostics on stderr. A zero exit with
invalid/unverifiable output is treated as an unknown remote outcome. The controller never
grades these runs, and an unknown outcome requires reset before another execution.

Cleanup receives `ACTION=cleanup`, `SCN`, `TARGET`, `TARGET_USER`, `DRY_RUN=0`, and the
protocol version. It must terminate outstanding exercise processes and remove relevant
artifacts, and exit zero only on successful cleanup. Standalone reset may omit a scenario;
then cleanup must safely restore the configured range as a whole or fail clearly. The
controller never interprets cleanup output as attack evidence.

Keep stdout below 1 MB. Successful runner diagnostics and verification references remain
hidden from the analyst until report submission. Failed runs expose diagnostics for repair
and cannot contribute an investigation score.
