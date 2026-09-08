# Live operation

The controller, SSH transport, reset handling, Wazuh collection, reports, and scoring are
implemented. Real use still requires compatible private scenario metadata/runner code
and validation against the user's lab. The automated suite uses fakes, not a real range.

The laptop runs the controller; an SSH dispatcher on the attacker executes the user's
private scenarios against the configured target. A Wazuh agent supplies evidence. Optional
Proxmox rollback and runner cleanup establish a clean starting point. No private attack
code is bundled with this product.

1. Generate a profile with `draghunt init-config`. Set attacker/target addresses, SSH key,
   Wazuh agent ID/indexer credentials, private catalog path, and reset details.
2. Implement [runner protocol v1](RUNNER-PROTOCOL.md). Mark compatible metadata `live: true`.
   Old unstructured `fire.sh` output is intentionally not accepted as ground truth.
3. Use a read credential permitting the configured index search and scroll/clear operations.
   Configure a trusted CA or explicitly choose `verify_tls = false` for an appropriate lab.
4. Validate the profile against one disposable target. Run only after explicitly choosing
   the named target and any reset action. Preflight must be read-only.
5. Collect alerts and, where configured, raw events. Collections preserve full documents,
   use `agent.id`, paginate, and indicate incomplete results. The controller stores the
   investigation window and waits before interpreting absent detections.

Wazuh alert indices contain rule-generated alerts; archive indices can contain events
that never caused alerts. Archive indexing must be enabled independently in the lab.
[Wazuh index documentation](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html).
Pagination uses a bounded scroll context and closes it after retrieval.
[OpenSearch scroll API](https://docs.opensearch.org/latest/api-reference/search-apis/scroll/).

A failed reset stops the exercise. VM startup is checked through Proxmox; application and
telemetry readiness is the private runner's responsibility. A successful process exit
without a valid case-linked result is an unknown execution, never a passing exercise.
An SSH timeout does not guarantee the remote process stopped. Reset before retrying an
unknown execution. Cleanup implementations must terminate leftover exercise processes.

The first manual acceptance run should demonstrate all of these:

- The installed dashboard and CLI select the same profile and saved cases.
- The private runner's reported source and objective outcome match the actual exercise.
- Reset and preflight failures stop execution; an interrupted run cannot be graded.
- Wazuh retrieval returns the expected target's full evidence and exposes partial/early results.
- Refreshing or reopening the app preserves the draft and cited events.
- Submission saves an exportable report, reveals the debrief, and records exactly one score.
- A replay after a rule change records a new rule revision and matching events; a benign
  control expecting zero matches can fail when the rule creates a false positive.

No hosted layer or further SIEM integration is required for this acceptance test.
