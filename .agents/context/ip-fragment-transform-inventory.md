# IP Fragment Transform Implementation Inventory

This inventory maps the current `libcrafter` surfaces that the planned
`IpDefrag` and `IpFragment` packet-stream transforms must integrate with. It is
factual context for later implementation steps and does not introduce code or a
new public API.

## Source And Scope Anchors

- `docs/guide/ipv6.md` records the source-backed
  facts for the transform work, including the correction that IPv6 reassembly
  identity is source address, destination address, and Fragment Identification.
- `docs/guide/ipv4.md` describes current
  IPv4 field support and explicitly states that base IPv4 generation and decode
  do not split or reassemble datagrams today.
- `docs/guide/ipv6.md` describes current
  IPv6 base and extension-header support and states that base IPv6 does not
  generate fragments or maintain fragment queues today.
- `docs/reference/wire.md` describes the packet-stream
  abstraction that the transforms must preserve: each stream item is a
  `PacketRecord`, and `PacketTransform` is the stateful extension point.
- `docs/operations/validation.md`, `docs/operations/lab.md`, and `tools/oracle/README.md` document
  the offline-first and provider-backed validation boundaries relevant to this
  work.

## Public API And Export Surfaces

- `crafter/src/wire/mod.rs` exports wire pipeline types including
  `PacketRecord`, `PacketMetadata`, `TransformTrace`, `PacketTransform`,
  `TransformOutput`, `Sniffer`, `Transmitter`, `PacketSource`, and
  `PacketWriter`. A future `crafter/src/wire/ip/` module would need to be
  exported here for `IpDefrag` and `IpFragment`.
- `crafter/src/lib.rs` reexports public protocol and wire types at the crate
  root and in `crafter::prelude`; future public transform types need root and
  prelude reexports if they are part of the generated-tool surface.
- `crafter/src/protocols/mod.rs`, `crafter/src/protocols/ip/mod.rs`,
  `crafter/src/protocols/ip/v4/mod.rs`, `crafter/src/protocols/ip/v6/mod.rs`,
  and `crafter/src/protocols/ip/v6/extension/mod.rs` are the existing protocol
  module export points for IP helpers used by the transforms.

## Wire Pipeline Surfaces

- `crafter/src/wire/transform.rs` defines `PacketTransform` as a stateful
  transform from one `PacketRecord` to zero, one, or many emitted
  `PacketRecord` values. `TransformOutput` is the small collection helper used
  by tests and convenience wrappers.
- `crafter/src/wire/record.rs` defines `PacketRecord`, `PacketMetadata`,
  `PacketOrigin`, `BackendKind`, medium metadata, and `TransformTrace`.
  Transform trace metadata currently has name, note, input length, and output
  length fields; there are no IP-specific metadata variants yet.
- `crafter/src/wire/sniffer.rs` owns inbound `PacketSource` values, applies an
  ordered `PacketTransform` chain, buffers fan-out output, and yields
  transformed `PacketRecord` values. This is the receive-side integration point
  for `IpDefrag`.
- `crafter/src/wire/transmitter.rs` owns outbound `PacketWriter` values,
  applies an ordered `PacketTransform` chain, and writes every emitted record in
  order. This is the transmit-side integration point for `IpFragment`.
- `crafter/src/wire/source.rs` defines `PacketSource` and `VecPacketSource`;
  `VecPacketSource` is the in-memory source useful for transform unit tests and
  out-of-order fragment input tests.
- `crafter/src/wire/writer.rs` defines `PacketWriter`, `WriteReport`, and
  `MemoryPacketWriter`; `MemoryPacketWriter` is the in-memory writer useful for
  checking `IpFragment` fan-out behavior without live traffic.
- `crafter/src/wire/packet_wire.rs` opens backend-neutral packet sources and
  writers and hands them to `Sniffer` or `Transmitter`.
- `crafter/src/wire/backend/pcap.rs` and `crafter/src/wire/backend/raw_socket.rs`
  are current backend adapters. Fragment transform work should stay above these
  adapters as packet-record transforms.
- `crafter/src/wire/transform_contract.rs` contains contract tests for
  transform fan-out, drops, failures, stateful ordering, and transmitter write
  behavior. Later transform tests should preserve those assumptions.
- `crafter/src/wire/dot11_metadata.rs` and `crafter/src/wire/wpa/` are examples
  of existing inbound transforms that annotate or emit packet-shaped records
  while appending `TransformTrace` metadata.

## IPv4 Protocol Surfaces

- `crafter/src/protocols/ip/v4/fragment.rs` provides current IPv4 fragment-field
  helpers: `Ipv4FragmentInfo`, flag predicates, offset accessors,
  `compose_flags_fragment`, `flags_from_flags_fragment`,
  `fragment_offset_from_flags_fragment`, and `validate_fragment_fields`.
  Several helper functions are currently `pub(super)`, so transform code outside
  the v4 module cannot call them directly without a scoped API change.
- `crafter/src/protocols/ip/v4/constants.rs` defines IPv4 fragment-related
  constants including `IPV4_FLAG_DONT_FRAGMENT`, `IPV4_FLAG_MORE_FRAGMENTS`,
  `IPV4_FLAG_RESERVED`, and `IPV4_MAX_FRAGMENT_OFFSET`.
- `crafter/src/protocols/ip/v4/header.rs` defines `Ipv4` builder and accessors
  for `identification`, `flags`, `dont_fragment`, `more_fragments`,
  `fragment_offset`, `fragment_info`, `is_fragmented`, `total_length`, and
  `checksum`. Compile currently auto-fills total length and header checksum
  unless the caller explicitly set those fields.
- `crafter/src/protocols/ip/v4/decode.rs` decodes IPv4 headers, validates
  header length and total length, records checksum status, and keeps non-initial
  fragment payloads as `Raw`. Offset-zero MF fragments may decode a complete
  registered transport header and otherwise preserve payload as `Raw`.
- `crafter/src/protocols/ip/v4/display.rs` includes fragment fields in
  `summary()` and `show()` output.
- `crafter/src/protocols/ipv4.rs` is the compatibility reexport module for the
  public IPv4 surface.

## IPv6 Protocol Surfaces

- `crafter/src/protocols/ip/v6/extension/fragment.rs` defines
  `Ipv6FragmentHeader`, `Ipv6FragmentHeaderStatus`, fragment offset accessors,
  byte-offset conversion, reserved-field inspection, M flag helpers, and
  identification accessors. Compile emits the 8-octet Fragment Header and
  auto-fills its Next Header from the following layer unless explicitly set.
- `crafter/src/protocols/ip/v6/constants.rs` defines IPv6 extension-header
  constants including Fragment Header length, protocol number, and maximum
  fragment offset.
- `crafter/src/protocols/ip/v6/header.rs` defines `Ipv6` builder and accessors
  for payload length, Next Header, hop limit, source, and destination. Compile
  auto-fills payload length and Next Header unless explicitly set.
- `crafter/src/protocols/ip/v6/decode.rs` traverses supported extension headers
  and decodes Fragment Header. Non-initial IPv6 fragments stop upper-layer
  decode and preserve remaining bytes as `Raw`; atomic and initial fragments
  continue decode when the following bytes contain a supported complete header.
- `crafter/src/protocols/ip/v6/extension/{hop_by_hop,destination,routing,segment,mobile}.rs`
  are the supported extension-header chain pieces that later narrow-scope IPv6
  fragmentation and defragmentation need to recognize or reject explicitly.
- `crafter/src/protocols/ip/shared/protocol_numbers.rs` labels IP protocol
  numbers, including the IPv6 Fragment Header value.
- `crafter/src/protocols/ipv6.rs` is the compatibility reexport module for the
  public IPv6 surface.

## Packet Shape And Link Wrapping

- `crafter/src/packet.rs` owns the typed `Packet` stack, `/` composition,
  `compile()`, `decode_from_l3`, `decode_from_link`, `summary()`, and `show()`.
  `IpDefrag` and `IpFragment` need to preserve packet-shaped output rather than
  returning bare byte buffers.
- `crafter/src/protocols/link/ethernet.rs`,
  `crafter/src/protocols/link/vlan.rs`, `crafter/src/protocols/link/linux_sll.rs`,
  and `crafter/src/protocols/link/null_loopback.rs` are the link wrappers that
  currently carry IPv4 and IPv6 records in decoded packets and pcap fixtures.
- `crafter/src/pcap/{reader,writer,codec,types,libpcap}.rs` are the classic pcap
  read/write surfaces used by offline and pcap validation. `PacketRecord`
  preserves pcap timestamps, original length, captured length, captured bytes,
  and link type when built from pcap input.

## Current Tests And Fixtures

- `crafter/src/protocols/ip/v4/tests.rs` covers IPv4 compile/decode,
  `Ipv4FragmentInfo`, MF/DF/offset fields, non-initial fragment raw decode, and
  offset-zero MF decode behavior.
- `crafter/tests/ipv4_public_api.rs` and `crafter/tests/public_api.rs` cover
  public IPv4 fragment-field accessors and reexports.
- `crafter/tests/fixtures/bytes/ipv4-fragment-noninitial-raw.hex` and its
  summary fixture cover current IPv4 non-initial fragment decode.
- `crafter/src/protocols/ip/v6/tests.rs` and `crafter/tests/ipv6_public_api.rs`
  cover IPv6 base and extension-header behavior, including Fragment Header
  status, atomic fragments, initial fragments, non-initial raw preservation,
  reserved fields, offset boundaries, and chain traversal.
- `crafter/tests/fixtures/bytes/ipv6-fragment-udp-raw.hex`,
  `crafter/tests/fixtures/bytes/ipv6-fragment-atomic-udp-raw.hex`,
  `crafter/tests/fixtures/bytes/ipv6-fragment-non-initial-udp-raw.hex`, and the
  matching `crafter/tests/fixtures/summaries/*.summary.txt` files cover current
  IPv6 Fragment Header fixtures.
- `crafter/tests/fixture_suite.rs` runs fixture decode/summary checks.
- `crafter/tests/fixtures/pcaps/raw-ipv4-icmp-echo-request.pcap`,
  `crafter/tests/fixtures/pcaps/raw-ipv6-base-traffic-flow-udp-raw.pcap`, and
  related raw/null-loopback pcaps are current pcap fixtures for L3 and link
  input paths; no dedicated fragmented pcap fixture exists yet.

## Oracle Validation Surfaces

- `tools/oracle/run` is the command entrypoint for corpus, offline, pcap, and
  live validation.
- `tools/oracle/specs/layers/ipv4.yaml` declares IPv4 fields and existing
  coverage cases such as `ipv4-fragment-mf-offset` and
  `crafter-ipv4-fragment-mf-offset`.
- `tools/oracle/specs/layers/ipv6.yaml` declares the `ipv6_fragment` extension
  layer and current Fragment Header field/status coverage.
- `tools/oracle/specs/features/ipv6-fragment-routing.yaml` declares focused
  IPv6 Fragment Header, extension-header, and routing coverage cases including
  `ipv6-fragment-udp` and `crafter-ipv6-fragment-udp`.
- `tools/oracle/specs/{profiles.yaml,stacks.yaml}` define profiles and stack
  shapes used by generated oracle plans.
- `tools/oracle/specs/features/{icmpv4-errors.yaml,icmpv6-errors.yaml}` are
  relevant MTU-feedback validation context, not transform implementation scope.
- The oracle reference backend surfaces under `tools/oracle/engine/backends/`
  cover packet generation, normalization, pcap, and live exchange.
- `tools/oracle/engine/backends/wireshark/{normalize,pcap}.py` are parser-only
  reference surfaces for decode and pcap comparisons.
- `tools/oracle/adapters/src/bin/vectors/cases.rs` contains current
  libcrafter-generated vector cases for IPv4 and IPv6 fragment-field examples.
- `tools/oracle/tests/test_generator.py`,
  `tools/oracle/tests/test_ipv6_normalize.py`,
  oracle backend tests,
  `tools/oracle/tests/test_pcap_cli.py`, and
  `tools/oracle/tests/test_live_provider_matrix.py` are existing test surfaces
  likely to need extension when new transform oracle specs are added.

## Lab And Live Validation Surfaces

- `tools/lab/run` is the command entrypoint for provider-backed multi-endpoint
  sessions. It supports `providers`, `plan`, `doctor`, `create`, `destroy`,
  `list-sessions`, and `session-info`.
- `tools/lab/engine/cli.py` defines the lab command parser and protected
  `--confirm-live-run` boundary for real provider creation.
- `tools/lab/engine/model.py`, `tools/lab/engine/session.py`,
  `tools/lab/engine/bootstrap.py`, `tools/lab/engine/repo.py`, and
  `tools/lab/engine/endpoint_client.py` define session modeling,
  persistence, bootstrap, repo sync, and endpoint delegation.
- `tools/lab/engine/providers/{hetzner,qemu,virtualbox,docker}.py` are the
  provider adapters. The plan requires Hetzner, QEMU, and VirtualBox/VM
  provider-backed validation for live fragmented traffic.
- `tools/lab/tests/test_{hetzner_provider,qemu_provider,virtualbox_provider,provider_matrix,cli_dry_run,cli_create_destroy}.py`
  cover provider planning, dry-run behavior, and guarded create/destroy paths.
- `tools/oracle/engine/providers/{hetzner,qemu,virtualbox,docker,registry,policy}.py`
  bridge oracle live validation to provider-backed lab sessions.
- `tools/oracle/engine/live_provider_matrix.py` runs offline/pcap baselines and
  provider live dry-runs across selected providers.
- Existing documented dry-run commands relevant to future IP fragment work are:
  `tools/lab/run plan --provider hetzner --dry-run --profile smoke --seed 1 --role stimulus --role target --json`,
  `tools/lab/run plan --provider qemu --dry-run --profile smoke --seed 1 --role stimulus --role target --json`,
  `tools/lab/run plan --provider virtualbox --dry-run --profile smoke --seed 1 --role stimulus --role target --json`,
  `tools/oracle/run live --backend "$ORACLE_BACKEND" --provider hetzner --dry-run --profile smoke --seed 12345 --count 10`,
  `tools/oracle/run live --backend "$ORACLE_BACKEND" --provider qemu --dry-run --profile smoke --seed 12345 --count 10`,
  and `tools/oracle/run live --backend "$ORACLE_BACKEND" --provider virtualbox --dry-run --profile smoke --seed 12345 --count 10`.

## Integration Constraints For Later Steps

- `IpDefrag` should be a receive-side `PacketTransform` that emits zero records
  until a datagram is complete, then emits a packet-shaped `PacketRecord` with
  preserved metadata and appended trace metadata.
- `IpFragment` should be a transmit-side `PacketTransform` that emits the
  original packet record unchanged when no split is needed or emits multiple
  packet-shaped fragment records through the existing `Transmitter` fan-out
  behavior.
- Current `TransformTrace` is generic and small. IP-specific fragment and
  defrag metadata will need either new metadata fields/types in
  `crafter/src/wire/record.rs` or an explicitly documented encoding into
  transform trace notes.
- Existing IPv4 and IPv6 protocol helpers preserve explicit user-set length,
  checksum, and Next Header fields. Later implementation needs to decide which
  fragment-output fields are rewritten by the transform and which user
  overrides remain honored.
- Existing decode behavior intentionally preserves non-initial fragments as
  `Raw`. `IpDefrag` must consume that packet shape instead of requiring a typed
  transport layer on every fragment.
- Existing validation is offline-first. New oracle specs and pcap fixtures
  should be added before any guarded provider-backed live workload.
