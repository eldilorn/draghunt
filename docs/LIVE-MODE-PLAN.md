# Live mode — control-center architecture (planning)

Status: **planned, not built.** Nothing here fires. Live attacks begin only in
phase 2, behind an explicit `--fire` gate.

## The planes

The laptop never attacks anything directly. It tells Kali what to fire.

```
   LAPTOP (control)          KALI (attacker)        TARGET VM(s)      WAZUH
   - Dealer web app  --SSH-> - runners            - victims          - SIEM
   - click "deal"            - fires attack  --->  (agent ships  ---> - you
   - seals the truth                               telemetry)          investigate
   - grades verdict  <----------------------------  <-- alerts via indexer API
   - tracks reps
```

- **Control plane (laptop):** picks + randomizes the scenario, seals the truth
  locally, drives Kali over SSH, pulls alerts from Wazuh, grades, tracks reps.
- **Execution plane (Kali):** receives scenario id + params, fires the attack,
  reports back. Stays a dumb executor. Attack code lives here, not in the app.
- **Target plane (VMs):** the victims. Reset between reps (see below).
- **Telemetry plane (Wazuh):** where alerts land and where you investigate.

## Decisions (locked)

| Area        | Choice |
|-------------|--------|
| Interface   | Small local web UI now (FastAPI + plain HTML/JS, no build step). |
| Web binding | `127.0.0.1` only. The app can fire attacks; nothing on the LAN may reach it. |
| Target addr | Entered in the app config; app passes victim to Kali at fire time. |
| SIEM        | Pluggable adapter seam; **Wazuh** is the one shipped adapter, others plug in. |
| Reset       | BOTH: Proxmox snapshot revert (hard reset, step zero) + runner cleanup job. |
| Transport   | Shell out to system `ssh`; no SSH library dependency. |
| Safety      | Dry-run default; `--fire` gate; Proxmox revert names the VM and confirms. |

## Phased build (each phase is runnable and safe on its own)

1. **Web skeleton + dry-run deal.** Dashboard runs locally. Click deal -> seals
   truth, SSHes to Kali, Kali prints the plan only. Nothing fires. Grading and
   stats wired in from here.
2. **Live fire.** `--fire` turns the dry run into a real attack on the target.
   Click -> attack -> telemetry in Wazuh. Investigation is manual in the console.
3. **Reset.** Proxmox snapshot revert as step zero + runner cleanup, so reps run
   against a clean box. Lands before drift accumulates.
4. **Wazuh alert pull.** Dashboard queries the indexer and shows the window's
   alerts inline. Later home of "did my detection rule fire?".

## Config the app will need (one file, laptop, tight perms, never committed)

- **Kali:** address, SSH user, path to the lab SSH key.
- **Target VM:** address, runner login.
- **Wazuh indexer:** address + port, read-only credential for the alert index.
- **Proxmox:** API host, API token, node name, target VM id, clean snapshot name.

## SIEM adapters (any SIEM, one seam)

The app is SIEM-agnostic except for one operation: pulling the alerts for an
investigation window. That lives behind a small interface (`dealer/siem`), so a
new SIEM is a new class, not a fork.

* **Shipped:** Wazuh, querying the indexer's `wazuh-alerts-*` over a time range.
* **To add one:** subclass `SiemAdapter`, implement `query_alerts`, register it
  with `@register("name")`. Users pick it via `siem.adapter = "name"` in
  `range.toml`.
* This keeps v1 solo-maintainable (one real adapter) while being genuinely open
  to Splunk, Elastic, or anything else, ideally via community contributions.

## Phase 5 — packaging and desktop app (future)

The dashboard is a local backend plus a plain HTML/JS frontend. "Web UI" vs
"installable app" is only a choice about that frontend's shell and packaging;
the backend is unchanged. So the web build is the road to a desktop app, not a
detour.

* **Installable via pip** — already true; the project ships a `dealer` command.
* **Desktop app** — wrap the existing frontend in a native window with
  **pywebview** (stays all-Python, tiny), then package as an **AppImage** or
  **.deb**. Avoid Electron (heavy for a solo maintainer); Tauri is an option but
  adds Rust.
* **Alternative** — a terminal UI (Textual) if the browser is unwanted, but it
  would not carry forward into a graphical desktop app.

## Open design notes

- **Blind until submit.** The UI must never render sealed fields (technique,
  source, account, succeeded) before the verdict is submitted. Alerts are the
  investigation surface, not the answer key.
- **Jitter.** `dealer.sh`'s pre-fire delay fights an interactive click-and-watch
  UI. Off by default for live reps, optional.
- **Source IP.** Kali is the attacker now, so the "source" answer is Kali's real
  address, not a synthetic documentation IP.
- **Boundary.** The app invokes the user's private runner; it never contains
  attack code. Private scenario decks plug in without being vendored.
