# Dealer product — new-session kickoff prompt

*(Paste everything in the code block below into a fresh Claude Code session tomorrow.
Do your case study first. Then have fun.)*

```
I'm starting a side project for fun, and I want your help shaping and building it. Read
this whole brief, then propose a lean plan before writing code.

WHO I AM
I'm a SOC analyst moving toward detection engineering. I run a Wazuh homelab (Proxmox,
Sysmon, auditd). I'm comfortable in bash and on Linux, fine with Python, and I want a
stack I can realistically maintain solo.

THE PRODUCT
Working name: the Dealer. It gives blue-teamers realistic investigation reps in their
OWN lab instead of on someone else's frozen incident. It fires a randomized, MITRE-mapped
attack into the user's own SIEM, seals the ground truth, lets them investigate the
telemetry blind and write a verdict, then grades that verdict against the sealed truth.

The differentiator, in one line: LetsDefend and CyberDefenders hand you a stranger's
frozen pcap that everyone else also downloaded, so you never own the ground truth and
can't tune a detection against it. The Dealer flips that. You own the whole loop:
attack -> telemetry -> detection -> investigation -> verdict.

THE SEED (v0 already exists)
I have a working prototype in a separate PRIVATE repo, casefiles-lab, at:
  lab/dealer.sh          # picks a random scenario, randomizes params, seals ground truth
  lab/runners/S01..S10.sh # ten MITRE-mapped attack runners, fired over SSH from a Kali box
  lab/lab.env            # range config
Treat that as the concept proof, not the product. The scenarios themselves are private
lab content: do NOT copy scenario text or attack specifics into any public/product repo
without me confirming the public/private boundary first. Ask before crossing it.

MVP SCOPE (already decided, keep me honest about it)
- Wazuh ONLY for the first version. It's what I run and can support. No multi-SIEM yet.
- Shape: an open-source, self-hostable runner + a hosted grading/tracking layer.
  Open-core is the eventual monetization; don't build billing or multi-tenant auth on day one.
- This is fun and portfolio first. Building it in public IS the point, so favor shipping
  something runnable over architecting for scale.

WHAT I WANT FROM THIS FIRST SESSION
1. Push back on the idea and scope if you see a problem, then help me lock a lean v1 cut.
2. Recommend a stack (don't just ask me), given my background above, and say why.
3. Start a FRESH repo/scaffold for the product, separate from casefiles-lab.
4. Get one tangible vertical slice working or cleanly stubbed by the end, so I leave with
   momentum, not just a plan.

HOW TO WORK WITH ME
Propose the plan and the key decisions up front with a recommendation for each, rather
than asking me a long list of questions. Keep scope tight. Call out anywhere I'm
over-engineering. Prioritize something I can actually run today.

Start by giving me the plan.
```
