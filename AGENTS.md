# AGENTS.md — Draghunt

Project rules. These add to my global `~/.codex/AGENTS.md`; where they conflict, these win.

## Dependencies

- Standard library only for the application core. Do not add a runtime dependency
  without asking first.
- Optional extras (pywebview for the desktop window, packaging tooling) stay optional:
  the synthetic web/CLI workflow must keep working with a bare `python`.

## Architecture

- Keep the CLI, web, and desktop entry points calling the shared `workflow`. Don't add
  a second execution, grading, or storage path.
- Respect the module boundaries in `docs/ARCHITECTURE.md` (catalog, telemetry, fire,
  reset, workflow, store, schema/grader, siem, web/static, cli/desktop, history).
- Private attack content and answer keys stay out of the repo. Don't inline scenario
  specifics from the private runner catalog.

## Tests and checks

- Run the suite before finishing and report the real result:
  `PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v`
- After touching the UI JS: `node --check draghunt/static/app.js`
- Tests use temporary data and fake runner/SIEM/reset responses. Don't make a test hit
  a real range, network, or the user's live data directory.

## Scope

- The web server is loopback-only, single-user, and token-guarded. Don't loosen the
  Host/Origin/token checks or make it remotely deployable.
- Hosting, billing, multi-tenant auth, and additional SIEM adapters are out of scope
  unless asked.
