# IGMP Implementation Inventory

Reviewed: 2026-06-19

This inventory records the local protocol patterns IGMP must follow before
source files are added. It complements `docs/igmp-rfc-manifest.md`; it does not
replace the per-step RFC and IANA review required before encoding exact field
layouts.

## Existing Protocol Patterns

### `crafter/src/protocols/icmp/`

- ICMP keeps the public layer surface on typed Rust structs that implement
  `Layer`, `Div`, and inspection methods. The fixed header is a layer and
  structured bodies are separate layers composed with `/`.
- Field storage uses `Field<T>` so `compile()` can fill unset defaults while
  caller-set values survive unchanged, including deliberately invalid values.
- ICMPv4 decode enters through `append_icmp_packet` /
  `append_icmp_packet_with_checksum_validation`. The decoder pushes a typed
  header first, then defensibly types known bodies. Ambiguous or unsupported
  trailing bytes become `Raw`.
- Header truncation is a structured `CrafterError::buffer_too_short` with a
  stable context such as `icmp header`; malformed typed bodies often stay `Raw`
  rather than panicking or dropping bytes.
- ICMPv6 already contains MLD bodies under `icmp/v6/message/mld.rs`. IGMP must
  remain a separate IPv4 protocol module and must not absorb MLD.
- The ICMP module shows the scale of public re-exports needed by
  `protocols::exports` and `crafter::prelude::*`, but IGMP should start with a
  smaller source-backed surface.

### `crafter/src/protocols/rip/`

- RIP is the best folderized protocol model: `auth.rs`, `constants.rs`,
  `entry.rs`, `message.rs`, `registry.rs`, `ripng/`, and `mod.rs` separate
  wire constants, metadata, message views, and subprotocol variants.
- `registry.rs` is metadata only. It names and classifies codepoints while
  preserving unknown values as `Other(value)` instead of rejecting them.
- `message.rs` maps raw wire codes to typed enums and back. Unknowns round-trip
  through explicit `Other` variants.
- The main `Rip` layer keeps its header plus repeated entries together because
  the repeated 20-octet entry slots are integral to the message. IGMPv3 reports
  have a similar repeated-record shape and should follow this pattern where it
  improves round-trip clarity.
- RIP decode is bound through UDP application dispatch in `registry.rs` with a
  conservative shape gate. IGMP differs: it is an IPv4 protocol number binding,
  not a UDP or TCP application binding.

### `crafter/src/protocols/ip/v4/`

- `header.rs` owns IPv4 compile-time auto-fill for total length, IHL, checksum,
  and protocol number. `effective_protocol()` honors caller-set protocol values
  before inferring from the following layer.
- `layer_ipv4_protocol()` currently recognizes TCP, UDP, and ICMPv4. IGMP must
  be added here so `Ipv4::new() / Igmp::...` auto-fills protocol `2` unless the
  caller pinned another value.
- IPv4 decode in `decode.rs` pushes the typed `Ipv4` layer, then dispatches the
  payload through `ProtocolRegistry::decode_ipv4_protocol`. Non-initial
  fragments preserve payload bytes as `Raw`; initial fragments with more
  fragments fall back to `Raw` if protocol decode fails.
- IPv4 options already include Router Alert support. IGMP documentation and
  tests should use existing `Ipv4Option::router_alert(0)` composition instead
  of adding an IGMP-specific option API.

### `crafter/src/protocols/ip/shared/protocol_numbers.rs`

- Shared IPv4 `Protocol` and IPv6 `Next Header` constants live here, with
  version modules re-exporting the public names.
- IGMP needs `IPPROTO_IGMP: u8 = 2`, a protocol label of `igmp`, an IPv4
  re-export from `ip/v4/mod.rs`, and an `Ipv4Protocol::Igmp` variant in
  `ip/v4/protocol.rs`.
- IGMP is IPv4-only. Do not add an IPv6 next-header label or route MLD through
  IGMP.

### `crafter/src/packet.rs`

- `Packet` stores optimized variants for common layers plus a boxed fallback.
  New public layers can work through `push()`, but first-class decode paths use
  typed variants and `push_*` helpers for frequent access and consistency.
- The IGMP packet-storage step should add an `Igmp` variant and helper methods
  only after the base layer exists. Body layers that are less common can remain
  boxed unless a later step shows value in specialized storage.
- `Packet::decode_from_l3` and `Packet::decode_from_link` already delegate to
  `ProtocolRegistry::builtin()`. No parallel IGMP decode entrypoint is needed.

### `crafter/src/registry.rs`

- Built-in dispatch is explicit and immutable after construction. IPv4 protocol
  bindings live in `ProtocolRegistry::with_builtin_bindings()`.
- IGMP should add one IPv4 protocol binding:
  `bind_ipv4_protocol_with_registry(IPPROTO_IGMP, |_registry, packet, payload| append_igmp_packet(packet, payload))`.
- IGMP does not need UDP/TCP application dispatch. It may need checksum
  validation toggles later if decode-time checksum status becomes inspectable;
  that should follow the existing registry checksum policy rather than a global
  switch.
- `transport_only()` should not include IGMP unless a later ICMP quoted-datagram
  or probe step requires shallow IGMP typing. The bootstrap should leave it out.

### `crafter/tests/fixtures/`

- Fixture bytes belong under `bytes/`; summaries under `summaries/`; classic
  pcap fixtures under `pcaps/`; malformed corpus rows under `malformed/`.
- Every valid byte fixture must be listed in `crafter/tests/fixture_suite.rs`
  `VALID_FIXTURES`; pcap fixtures must be listed in `PCAP_FIXTURES`; malformed
  rows are consumed by `crafter/tests/resilience.rs`.
- Names are lowercase and dash-separated. IGMP should use stack-first names:
  `ipv4-igmp-membership-query.hex`,
  `ipv4-igmp-v1-membership-report.hex`,
  `ipv4-igmp-v2-membership-report.hex`,
  `ipv4-igmp-v2-leave-group.hex`,
  `ipv4-igmp-v3-membership-query.hex`,
  `ipv4-igmp-v3-membership-report.hex`,
  `ipv4-igmp-extension-noop.hex`, and `ipv4-igmp-mrd-advertisement.hex`.
- Summary fixture names should mirror byte fixture names with `.summary.txt`.
  Pcap names should use `raw-ipv4-igmp-...pcap` unless a link-layer behavior is
  intentionally under test.
- Valid fixtures must use documentation-space addresses and deterministic
  fields. Live captures from real networks do not belong in this tree.

### `tools/oracle/specs/`

- Layer specs live in `layers/*.yaml`; feature specs live in
  `features/*.yaml`; stack grammar is in `stacks.yaml`; sampling profiles are
  in `profiles.yaml`; backend-owned case matrices live under `fixtures/`.
- IGMP needs a new `layers/igmp.yaml` with parent `ipv4` and child `payload`
  for raw tails or typed internal bodies. Field names should be backend-neutral:
  `type`, `code`, `checksum`, `group_address`, `max_response_code`,
  `qqic`, `flags`, `sources`, `records`, `aux_data`, and `extension_bytes`.
- Feature specs should be split by behavior rather than by implementation file:
  `igmp-bootstrap.yaml`, `igmp-v2.yaml`, `igmp-v3-query.yaml`,
  `igmp-v3-report.yaml`, `igmp-extensions.yaml`, `igmp-mrd.yaml`, and
  `igmp-live.yaml` when live cases are introduced.
- `stacks.yaml` should add IGMP to IPv4-capable roots and families only. It
  should not add IGMP to IPv6 roots.
- `profiles.yaml` can add focused offline and dry-run profiles such as
  `igmp-smoke`, `igmp-boundary`, and `igmp-live-dry-run` once executable specs
  exist.
- Scapy integration will need materialization and normalization updates under
  `tools/oracle/engine/backends/scapy/`, plus case rows in
  `tools/oracle/specs/fixtures/scapy-cases.json`.

## Intended IGMP Module Layout

Create `crafter/src/protocols/igmp/` with these logical blocks:

- `mod.rs`: module docs, shared local macros, public re-exports, and the main
  `Igmp` layer export.
- `constants.rs`: source-backed type numbers, fixed header lengths, flag masks,
  query/report limits, extension constants, and MRD type constants.
- `registry.rs`: type/code/record/extension metadata and helper functions that
  classify unknowns without rejecting them.
- `message.rs`: base `Igmp` layer, type views, common builders, checksum
  handling, summaries, and inspection fields.
- `query.rs`: membership query body/view helpers, including v1/v2 max response
  code and v3 source-list fields.
- `record.rs`: IGMPv3 group record model, record type metadata, source lists,
  auxiliary data, and unknown-record preservation.
- `report.rs`: membership report builders and encode/decode support for v1,
  v2, and v3 reports.
- `decode.rs`: fixed-header decode, typed body dispatch, raw fallback, and
  structured truncation errors.
- `validation.rs`: non-panicking validation helpers for group addresses, counts,
  source list lengths, flags, and extension lengths.

If RFC 9279 extension or RFC 4286 MRD support grows beyond small helpers, later
steps may split `extension.rs` or `mrd.rs`; the bootstrap should not add those
extra files without the dedicated source-review steps.

## Public Export Points

- Add `pub mod igmp;` to `crafter/src/protocols/mod.rs`.
- Add `igmp` to the `protocols::exports` import list and re-export the public
  IGMP layer, message/body types, registry metadata helpers, and constants.
- The crate root already re-exports `protocols::exports::*`; `crafter::core`
  and `crafter::prelude::*` inherit those names from the same export path.
- Add `IPPROTO_IGMP` to shared protocol-number constants, IPv4 module
  re-exports, and the curated export list.
- Avoid a second public API such as `decode_igmp()`; users should keep using
  `Packet::decode_from_l3(NetworkLayer::Ipv4, ...)` and `/` composition.

## Decode Registration Points

- IPv4 compile inference: update `ip/v4/header.rs` so a following `Igmp` layer
  fills the IPv4 protocol field with `IPPROTO_IGMP` unless caller-set.
- IPv4 protocol metadata: update `ip/shared/protocol_numbers.rs` and
  `ip/v4/protocol.rs`.
- Built-in decode: update `registry.rs` to bind IPv4 protocol `2` to
  `igmp::decode::append_igmp_packet`.
- Packet storage: add `Igmp` to `PacketLayer` and typed push helpers when the
  base layer lands; typed body layers can remain boxed unless later tests need
  optimized storage.
- Link decoders require no direct IGMP changes. Ethernet, Linux cooked,
  null-loopback, raw IPv4, and pcap paths already reach IPv4 registry dispatch.

## Oracle And Probe Integration Points

- Oracle specs:
  - `tools/oracle/specs/layers/igmp.yaml`
  - `tools/oracle/specs/features/igmp-*.yaml`
  - `tools/oracle/specs/stacks.yaml`
  - `tools/oracle/specs/profiles.yaml`
  - `tools/oracle/specs/fixtures/scapy-cases.json`
- Oracle Scapy backend:
  - `tools/oracle/engine/backends/scapy/packets.py` for materialization.
  - `tools/oracle/engine/backends/scapy/normalize.py` for normalized layer and
    field names.
  - `tools/oracle/engine/backends/scapy/live.py` only for protected live
    protocol detection and capture comparison.
- Oracle loader and generator tests should validate new spec names before any
  live work. Malformed IGMP cases should use `byte_policy: structured_error`
  where strict byte comparison is not meaningful.
- Probe:
  - Add probe cases and capability gates in `tools/probe/engine/cases.py`,
    `capabilities.py`, and planning/report tests.
  - Add `tools/probe/adapters/src/igmp.rs` only when the crate-side IGMP
    builders exist.
  - Add target-service setup only for controlled multicast behavior. Provider
    capability failures must skip with stable reasons instead of failing.
- Lab/live:
  - IGMP live validation must run through `tools/lab`, `tools/oracle`, or
    `tools/probe` dry-run first.
  - Real provider runs require explicit confirmation and must write artifacts
    under ignored `target/` paths.

## Gap List

- IGMPv1: fixed header, membership query, v1 membership report, group address,
  checksum, raw unknown preservation, and compatibility fixtures.
- IGMPv2: max response time/code view, v2 membership report, leave group, group
  address validation helpers, Router Alert composition guidance, and dry-run
  send/reply filtering.
- IGMPv3 query/report: source-list query fields, response-code and QQIC views,
  S/QRV flags, v3 membership report records, record types, auxiliary data,
  count auto-fill, malformed count/length errors, and round-trip fixtures.
- RFC 9279 extensions: extension flag bit, generic extension framing, no-op
  extension, extension type metadata, unknown extension preservation, and
  source-backed limits before typed extension bodies.
- RFC 4286 multicast router discovery: type metadata and packet construction or
  decode for advertisement, solicitation, and termination only. No router state
  machine or daemon belongs in `crafter`.
- Operational-only documents: snooping, proxy, SSM operation, MIB, YANG,
  tuning, and deployment guidance should stay in generated tools or docs unless
  a later source-review step extracts a concrete wire-level packet field.
- Live validation: provider multicast, link-layer send/capture, controlled
  services, and safe teardown are unproven. All live steps must keep dry-run
  defaults and protected confirmation gates.
