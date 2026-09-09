# Draghunt roadmap

Current version: **0.9.0**. Status: feature-complete for its stated scope, 99 tests
green, working end to end on the synthetic deck. The one substantial gap is real-lab
acceptance validation.

This roadmap reflects a deliberate now-versus-later split:

- **Now** — Draghunt stays a single-user, loopback-only, token-guarded personal tool.
  The security model in `AGENTS.md` does not loosen. The core stays standard-library
  only, with CLI, web, and desktop routed through the shared `workflow`.
- **Later** — a hosted, in-browser version anyone can use, backed by a database. This is
  a separate architecture and a separate track, not a relaxation of the personal build.
  It is a goal, not a scheduled commitment, and its shape is undecided.

Priorities below run in order. Each phase should leave the suite green
(`python -m unittest discover -s tests`) and `node --check draghunt/static/app.js` clean.

---

## Phase 1 — Real-lab validation → 1.0

**Goal:** exercise the whole live path against an actual Wazuh + Proxmox range (available
now), fix what real use surfaces, and cut a stable 1.0. No new scope; prove what exists.

Work the acceptance checklist in [`docs/LIVE-MODE-PLAN.md`](docs/LIVE-MODE-PLAN.md) against
one disposable target:

- [ ] Installed dashboard and CLI select the same profile and saved cases.
- [ ] The private runner's reported source and objective outcome match the actual exercise.
- [ ] Reset and preflight failures stop execution; an interrupted run cannot be graded.
- [ ] Wazuh retrieval returns the target's full evidence and exposes partial/early results.
- [ ] Refreshing or reopening the app preserves the draft and cited events.
- [ ] Submission saves an exportable report, reveals the debrief, records exactly one score.
- [ ] A replay after a rule change records a new rule revision and matching events; a benign
      control expecting zero matches can fail on a false positive.

Alongside the checklist:

- [ ] Implement or finalize a runner-protocol-v1 dispatcher for the private catalog.
- [ ] Confirm TLS verification and the mode-0600 secret refusal behave against the real lab.
- [ ] Capture any bugs found during live runs as fixes, not scope growth.

**Exit criteria:** every checklist item passes on the real range; the version is tagged
**1.0.0**; `LIVE-MODE-PLAN.md` is updated to reflect validated (not just implemented) status.

## Phase 2 — Content and scenarios

**Goal:** more and better exercises. This is the main sanctioned scope expansion.

- [ ] Grow the synthetic deck beyond the current four (SSH brute, web shell, DNS exfil,
      benign backup) with new ATT&CK techniques and tactics.
- [ ] Broaden ATT&CK coverage and sharpen answer keys, especially the unobservable /
      not-applicable exclusions that keep scoring fair.
- [ ] Richer debriefs: clearer explanation of the correct disposition and evidence.
- [ ] Expand the private-runner catalog (kept out of this repo; no scenario specifics inline).
- [ ] Keep every synthetic addition lab-free and deterministic under a fixed seed.

**Exit criteria:** a meaningfully larger deck with tests covering new scenarios' grading.

## Phase 3 — UX and onboarding

**Goal:** make the personal tool pleasant and fast to use day to day.

- [ ] Refine the dashboard: Practice, Progress, and Settings flows.
- [ ] Improve the reporting UI: evidence citation, timeline, drafting ergonomics.
- [ ] Strengthen progress views: per-tactic accuracy, run-mode breakdown, detection history.
- [ ] First-run and empty states that continue to explain themselves.

**Exit criteria:** the common loop (run → investigate → report → submit → debrief) needs
fewer clicks and less doc-reading; `node --check` stays clean.

## Phase 4 — Distribution and docs

**Goal:** a clean install and reference story. Light-touch while the audience is just me,
but this is also the on-ramp for eventually sharing the tool.

- [ ] Validate `packaging/install.sh` and the AppImage recipe on a fresh machine.
- [ ] Keep README, ARCHITECTURE, RUNNER-PROTOCOL, PACKAGING, and this file in sync with code.
- [ ] Document the real-lab setup end to end, learned from Phase 1.

**Exit criteria:** a from-scratch install and first run succeed following only the docs.

---

## Future track — hosted in-browser version (unscheduled)

A version that runs in the browser for anyone, backed by a database I host. Undecided
between a server-plus-hosted-DB shape (closest to today's architecture) and a more
client-side rewrite. Gated behind a solid personal build; the architecture decision is
deferred until the phases above are done.

Open questions to resolve before this starts:

- Server-backed API + hosted DB, or client-side (WASM/Pyodide) with a thin backend?
- How much of the standard-library-only core ports directly versus needs rework.
- The multi-user security model — auth, isolation, and safety rails — which is out of
  scope for the personal build and must be designed fresh here, not by loosening it.
- Where synthetic-only content lives, and how (or whether) any live capability fits a
  hosted context at all.

Nothing in Phases 1–4 should assume this exists, and nothing should foreclose it.

---

_Kept in sync by hand. Update the checkboxes and exit criteria as phases land._
