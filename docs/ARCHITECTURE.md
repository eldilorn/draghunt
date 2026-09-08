# Architecture

Draghunt is a local Python application with a browser UI and optional native shell.
Both UI and CLI call `Workflow`; neither implements a separate execution/grading loop.

| Module | Responsibility |
|---|---|
| `catalog.py`, `data/catalog/` | Validate scenario metadata and choose reproducible parameters; private catalogs are configured separately. |
| `telemetry.py` | Generate fictional offline evidence, including benign activity. |
| `config.py` | Validated profiles, stable user locations, environment credentials, relative path resolution. |
| `fire.py` | SSH quoting, protocol-v1 preflight, execution capture, observed-result validation. |
| `reset.py` | Confirmed Proxmox rollback/start and private-runner cleanup; stop after failures. |
| `workflow.py` | Run states, final truth, evidence collection, reports, scoring, replay, detection checks, export. |
| `store.py` | Private SQLite documents, transactional draft/submission updates, target locks, private file writes. |
| `schema.py`, `grader.py` | Strict submitted contracts; applicable finding weights and separate report-completeness feedback. |
| `siem/` | Agent-scoped collection with full event documents, bounded pagination, completeness metadata. |
| `web.py`, `static/` | Local HTTP API and accessible plain JavaScript UI. Protected requests, text-only dynamic rendering. |
| `cli.py`, `desktop.py` | Alternate entry points to the same workflow. |
| `history.py` | Shared statistical aggregation and isolated legacy comparison history. |

A case owns its intended parameters, finalized observed truth, execution record, evidence,
draft, first submission, and optional detection checks. Each case has an opaque ID that
does not encode its scenario. The database and answer-key files are private to the local
user; they are not an anti-cheating security boundary against that user.

Live cases transition through queued, preflight, optional resetting/readiness, running,
and awaiting telemetry/investigating. Only verified completed executions become gradeable.
Reset/preflight/execution errors are separate from an attack objective that was attempted
and did not succeed. Interrupted or unknown remote outcomes require attention and, for
unknown execution, a subsequent reset. No action runs merely because a case is resumed.

A target file lock covers preflight/reset/execution across processes sharing a data
root. Profiles controlling the same target must share that root. SQLite transactions
protect draft version checks and immutable first submissions. Reports cannot silently
replace a newer draft from another window. Evidence references remain available in saved
cases after subsequent queries, so a debrief/export does not depend on SIEM retention.

Analyst API responses omit the answer key, seed, scenario selection for blind cases,
runner output, and execution plan until submission. Failed runs can expose diagnostics
because they are excluded from grading. Choosing a named drill deliberately discloses its
category. Replays deliberately disclose the prior case and do not count as new first attempts.

The web server binds to loopback. Requests validate Host/Origin/Fetch-Site; API calls also
require a random per-server token. Mutations require bounded JSON bodies and live requests
require confirmation. Static assets are served through explicit routes, and a restrictive
Content Security Policy backs text-node rendering of logs and reports. This is a local
single-user application, not a remotely deployable multi-user service.

Scoring has three distinct outputs: finding accuracy, report completeness, and detection
checks. Report completeness measures fields/references, not semantic truth. Detection
checks use saved scoped alert snapshots, require completed pagination and an ingestion
wait, and retain the analyst-declared rule revision and artifact. Rule deployment and
semantic report review remain in the analyst's workflow.

A seed reproduces randomized parameters. Event timestamps reflect the new run; replay is
not a byte-for-byte replay of historic timestamps. Live evidence is always collected again.
