# IP Fragment Live Audit

Audit time: 2026-06-08T03:55:07Z

Scope: Step 56 reviewed provider-backed artifacts from the IP fragment smoke
workload. No tracked packet captures, credentials, public addresses, or cloud
resource IDs are stored here.

## Resource State

- `tools/lab/run list-sessions --json` reports one tracked `oracle-live`
  virtualbox session record.
- The virtualbox session's original live report records artifact collection and
  teardown as completed for both roles.
- A safe rerun of `tools/lab/run destroy --session oracle-live --json` attempted
  to re-collect artifacts from already-destroyed endpoints, then returned exit 1;
  the same rerun still reported both endpoint destroy operations as ok.
- `tools/endpoint/run list --json` reports 24 tracked endpoint manifests and all
  have status `destroyed`; there are no active endpoint records for this
  worktree.
- Process audit found no active qemu or virtualbox process matching the IP
  fragment endpoint identifiers. Other virtualization processes on the host were
  unrelated to this plan.

## qemu

- Outcome: pass.
- Live matrix: `target/oracle/ip-fragment-qemu-live/matrix-summary.json`
  reports matrix status `passed`, provider status `passed`, and
  `live_packet_exchange=true`.
- Live report:
  `target/oracle/ip-fragment-qemu-live/providers/qemu/live/report.json`.
- Lab audit: `target/lab/ip-fragment-qemu-audit/report.json` reports provider
  status `passed`.
- Local endpoint identifiers from the live report:
  `qemu-private-libcrafter-20260608024039-e72bd4` and
  `qemu-private-reference-backend-20260608024319-47babd`.
- Teardown: completed; artifact collection succeeded for `libcrafter` and
  `reference_backend`; destroy succeeded for `reference_backend` and
  `libcrafter`.
- Packet checks: 2 generated packets, 2 wire-eligible packets, 4 sends,
  4 captures, 4 parsed records, 4 byte comparisons passed, 4 decode comparisons
  passed, 0 failures.
- Payload hash comparison: skipped with reason `no_hashes`; the audit passed via
  `oracle_live_report_passed` because this live artifact set did not emit a
  separate payload hash file.

## virtualbox

- Outcome: pass.
- Live matrix: `target/oracle/ip-fragment-virtualbox-live/matrix-summary.json`
  reports matrix status `passed`, provider status `passed`, and
  `live_packet_exchange=true`.
- Live report:
  `target/oracle/ip-fragment-virtualbox-live/providers/virtualbox/live/report.json`.
- Lab audit: `target/lab/ip-fragment-virtualbox-audit/report.json` reports
  provider status `passed`.
- Local endpoint identifiers from the live report:
  `virtualbox-private-libcrafter-20260608033100-4d174b` and
  `virtualbox-private-reference-backend-20260608033251-41ce44`.
- Teardown: completed; artifact collection succeeded for `libcrafter` and
  `reference_backend`; destroy succeeded for `reference_backend` and
  `libcrafter`.
- Packet checks: 2 generated packets, 2 wire-eligible packets, 4 sends,
  4 captures, 4 parsed records, 4 byte comparisons passed, 4 decode comparisons
  passed, 0 failures.
- Payload hash comparison: skipped with reason `no_hashes`; the audit passed via
  `oracle_live_report_passed` because this live artifact set did not emit a
  separate payload hash file.

## hetzner

- Dry-run outcome: skip.
- Dry-run report: `target/oracle/ip-fragment-hetzner-dry-run/report.json`
  reports status `skipped`, 2 generated packets, 0 wire-eligible packets, and
  skip reason `no_wire_eligible_packets`.
- Dry-run workload plan:
  `target/oracle/ip-fragment-hetzner-dry-run/artifacts/ip-fragment-smoke/workload-plan.json`.
- Live outcome: skip.
- Live matrix: `target/oracle/ip-fragment-hetzner-live/matrix-summary.json`
  reports matrix status `passed`, provider status `skipped`, and
  `live_packet_exchange=false`.
- Live skip reason: provider doctor failed because `HETZNER_API_TOKEN` or
  `HCLOUD_TOKEN` is not configured.
- Lab audit: `target/lab/ip-fragment-hetzner-audit/report.json` reports provider
  status `skipped`.
- Resource identifiers: no real Hetzner resources were created. Dry-run artifacts
  include planned endpoint labels only.
- Teardown: no live Hetzner endpoints required teardown because the provider was
  skipped before resource creation.
- Payload hash comparison: skipped with reason `no_hashes`; no live packet
  exchange occurred.

## Artifact Completeness

- qemu and virtualbox have matrix summaries, live provider reports, baseline
  offline reports, baseline pcap reports, logs, corpus plans, and lab audit
  reports under `target/oracle/ip-fragment-*` and `target/lab/ip-fragment-*`.
- hetzner has dry-run and live skip artifacts, including a workload plan for the
  dry-run and a matrix summary plus audit report for the live skip.
- No provider emitted a separate payload hash artifact. The qemu and virtualbox
  artifact audits therefore rely on passing live byte/decode comparisons as the
  pass evidence; the hetzner payload hash comparison is skipped because no live
  exchange was attempted.
