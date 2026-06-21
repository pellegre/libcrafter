# IP Fragment Transforms Final Audit

Audit time: 2026-06-08T04:30:00Z

Scope: final readiness review for the `IpDefrag` receive transform and
`IpFragment` transmit transform. This document records tracked source scope,
offline and pcap validation, provider-backed live outcomes, artifacts, and
residual risks. It intentionally stores no packet captures, credentials, public
addresses, or live host identifiers.

## Supported Scope

- `IpDefrag` is a packet-stream `PacketTransform` for IPv4 and IPv6 fragment
  records. It preserves the `PacketRecord` abstraction, emits packet-shaped
  records, and attaches inspectable defrag metadata and transform traces.
- IPv4 defrag groups by source address, destination address, protocol, and
  Identification. It handles out-of-order fragments, exact duplicates,
  conflicting overlaps, missing finals, bounded state, and link or raw L3 input.
- IPv6 defrag groups by source address, destination address, and Fragment
  Identification. Fragment Header Next Header is stored as context for chain
  repair and metadata, not as reassembly key material.
- IPv6 defrag supports plain IPv6 plus Hop-by-Hop Options, Destination Options,
  and Routing headers before the Fragment Header. Atomic fragments normalize by
  default without entering defrag state.
- `IpFragment` is a transmit-side `PacketTransform` that fragments oversized
  IPv4 and IPv6 packet records according to an explicit MTU, preserving packet
  shape, metadata, and link framing where supported.
- IPv4 fragmentation honors Don't Fragment by default, supports explicit
  override/pass-through policies, emits 8-byte-aligned non-final fragments, and
  recomputes lengths and checksums through normal packet compile behavior.
- IPv6 fragmentation is source-side and inserts Fragment Headers for the same
  narrow extension-header scope documented for defrag.
- The public API is exported through `crafter::prelude::*`, crate-root exports,
  and `crafter::wire`, with public smoke coverage for `IpDefrag::new` and
  `IpFragment::new`.

## Unsupported Cases

- TCP stream reassembly, IP fragmentation across a full TCP/IP stack, and
  application-layer reconstruction remain unsupported.
- IPv6 packet shapes outside the documented narrow extension-header scope pass
  through or report explicit unsupported trace metadata instead of guessing.
- Ambiguous overlapping fragments with conflicting bytes are not silently
  emitted as reassembled datagrams.
- Invalid MTUs, unsupported packet shapes, malformed buffers, and incomplete
  datagrams produce structured errors, explicit pass-through/drop behavior, or
  bounded no-output state according to transform configuration.
- Live raw traffic from the developer machine remains unsupported. Real packet
  exchange is restricted to explicit provider-backed lab/oracle workflows.

## Validation Commands

- `cargo test --workspace`
- `cargo doc --workspace --no-deps`
- `tools/oracle/run offline --backend "$ORACLE_BACKEND" --family ip --profile fragmentation-smoke --seed 1201 --count 50 --out target/oracle/ip-fragment-final-offline`
- `tools/oracle/run pcap --backend "$ORACLE_BACKEND" --family ip --profile fragmentation-smoke --seed 1203 --count 50 --out target/oracle/ip-fragment-final-pcap`
- `python3 tools/oracle/engine/live_provider_matrix.py --providers qemu --backend "$ORACLE_BACKEND" --profile ip-fragment-smoke --seed 1302 --count 2 --real --skip-unavailable --allow-vm-create --confirm-live-run --out target/oracle/ip-fragment-qemu-live`
- `python3 tools/oracle/engine/live_provider_matrix.py --providers virtualbox --backend "$ORACLE_BACKEND" --profile ip-fragment-smoke --seed 1303 --count 2 --real --skip-unavailable --allow-vm-create --confirm-live-run --out target/oracle/ip-fragment-virtualbox-live`
- `tools/oracle/run live --backend "$ORACLE_BACKEND" --provider hetzner --dry-run --profile ip-fragment-smoke --seed 1304 --count 2 --out target/oracle/ip-fragment-hetzner-dry-run`
- `python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner --backend "$ORACLE_BACKEND" --profile ip-fragment-smoke --seed 1305 --count 2 --real --skip-unavailable --confirm-live-run --out target/oracle/ip-fragment-hetzner-live`
- `.agents/scripts/check-crafter-release --static`

## Offline And Pcap Artifacts

- Final offline oracle artifacts are under
  `target/oracle/ip-fragment-final-offline`.
- Final pcap oracle artifacts are under `target/oracle/ip-fragment-final-pcap`.
  The final pcap run passed; libpcap emitted mixed-linktype warnings during
  generation, but the roundtrip report passed all generated cases.
- Fixture hygiene covers IP fragment byte fixtures, RawIp fragment pcaps,
  focused docs, and `.agents/context` audit files for documentation address
  space and ignored artifact paths.

## Provider Live Outcomes

- qemu: passed. Matrix summary:
  `target/oracle/ip-fragment-qemu-live/matrix-summary.json`. Lab audit:
  `target/lab/ip-fragment-qemu-audit/report.json`. The provider performed live
  packet exchange and passed byte and decode comparisons with teardown complete.
- virtualbox: passed. Matrix summary:
  `target/oracle/ip-fragment-virtualbox-live/matrix-summary.json`. Lab audit:
  `target/lab/ip-fragment-virtualbox-audit/report.json`. The provider performed
  live packet exchange and passed byte and decode comparisons with teardown
  complete.
- hetzner: skipped. Dry-run artifact:
  `target/oracle/ip-fragment-hetzner-dry-run/report.json`. Live matrix summary:
  `target/oracle/ip-fragment-hetzner-live/matrix-summary.json`. Lab audit:
  `target/lab/ip-fragment-hetzner-audit/report.json`. The live run reached
  provider doctor and produced a structured missing-credentials skip because
  `HETZNER_API_TOKEN` or `HCLOUD_TOKEN` was unavailable; no live Hetzner
  resources or packets were created.

## Residual Risks

- qemu and virtualbox pass evidence comes from live oracle byte/decode
  comparisons, not separate payload hash artifacts. Current live artifacts do
  not emit `payload-hashes.json`.
- Hetzner live behavior was not exercised on the wire in this environment due
  to missing credentials; readiness is represented by dry-run planning and a
  structured live skip artifact.
- Provider-backed artifacts live under ignored `target/oracle/ip-fragment-*` and
  `target/lab/ip-fragment-*` paths. They should remain untracked unless a future
  maintainer sanitizes and promotes a fixture deliberately.
- The Step 56 resource audit found no active endpoint records for this worktree,
  but one already-destroyed VirtualBox session record remained in local lab
  state after a safe destroy rerun returned exit 1 during artifact re-collection.
