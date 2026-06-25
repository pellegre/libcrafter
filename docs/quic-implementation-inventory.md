# QUIC Implementation Inventory

Reviewed: 2026-06-25

This inventory records the repo integration points for the planned QUIC packet
primitive before source files are added. It is not a wire-format authority by
itself. Exact packet grammar, codepoints, transport parameters, extension rows,
and packet-protection behavior must cite `.agents/docs/quic-manifest.md`,
`.agents/docs/quic-codepoints.md`, or a narrower source-backed QUIC note before
code, fixtures, oracle specs, or docs rely on them.

QUIC must stay a UDP-carried packet primitive in the existing `Packet`
abstraction: `Ipv4` or `Ipv6` / `Udp` / typed QUIC datagram or packet layers /
typed cleartext frames or raw protected bytes. Generated examples and fixtures
must use documentation address space such as `192.0.2.0/24`,
`198.51.100.0/24`, and `2001:db8::/32`. Builders must preserve caller-set
malformed values, and decode failures must return structured `CrafterError`
values rather than panicking or silently discarding bytes.

## Stop Conditions

- Multipath IANA rows remain non-default until their final RFC status is
  resolved. Preserve their numeric values only when an enclosing parser has a
  source-backed extent; do not export stable convenience constants yet.
- Provisional, draft, and experiment rows for SCONE, ACK_FREQUENCY, Google
  experiments, BDP token behavior, and similar registry entries remain
  non-default unless a later source-backed step selects them.
- RFC 9000 verified or held errata must be checked before implementing any
  affected section. Do not copy a packet rule from base RFC text if the errata
  note changes the rule or leaves it disputed.
- Short-header destination connection ID length is context-dependent. Decode
  must not guess it from an unrelated UDP datagram; ambiguous short-header bytes
  stay raw unless a later API supplies enough connection context.
- Unknown frame types are byte-preserving only when a source-backed rule or
  caller-supplied boundary determines the frame extent. Otherwise return a
  structured parse error instead of guessing.
- Packet protection utilities are deferred until the dependency and vector
  review step. They may not imply arbitrary session decryption, TLS transcript
  ownership, or a QUIC endpoint.
- UDP recognition must not displace DNS, DHCP, IKE, ESP NAT traversal, RIP,
  RIPng, custom UDP bindings, or `application_decoding(false)` behavior.

## Comparable Local Patterns

- `crafter/src/protocols/mqtt/` is the closest application-layer module pattern:
  a foldered protocol with constants, decode, varint helpers, wire helpers,
  public exports, source-backed module docs, public API tests, golden tests, and
  malformed tests.
- `crafter/src/protocols/rip/` shows conservative UDP application dispatch with
  `looks_like_*_payload` gates, unknown-code preservation through metadata
  helpers, and fixture/oracle integration for a UDP-carried protocol.
- `crafter/src/protocols/ipsec/` shows crypto-adjacent packet primitives that
  preserve protected payload bytes by default and require explicit caller-owned
  keys or security associations for authenticated/decrypted paths.
- `crafter/src/protocols/igmp/` and `docs/igmp-implementation-inventory.md`
  show the inventory-first shape for public exports, fixture naming, oracle
  specs, probe cases, and lab dry-run boundaries.
- `crafter/src/protocols/transport/udp/datagram.rs` owns UDP payload length,
  checksum context, application-layer consumption, surplus bytes, and raw
  fallback behavior. QUIC integration must cooperate with that existing payload
  model.
- `crafter/src/packet.rs` owns the typed stack, `Layer` dispatch,
  `summary()`, `show()`, raw preservation, and decode entrypoints. QUIC should
  use the normal layer path and only add optimized `PacketLayer` storage if a
  later step demonstrates a need.

## Intended Module Layout

Create `crafter/src/protocols/quic/` with small, source-backed pieces:

- `mod.rs`: module docs, public re-exports, non-goal boundary, and the top-level
  QUIC datagram or packet layer exports.
- `constants.rs`: selected RFC/IANA constants only after source-backed review.
- `version.rs`: version labels, reserved/grease classification, v1/v2 constants,
  and non-default handling for provisional rows.
- `varint.rs`: QUIC variable-length integer encode/decode with structured
  truncation and range errors.
- `packet_number.rs`: packet number length helpers and explicit override
  support.
- `connection_id.rs`: byte-preserving connection ID type and length checks.
- `header.rs`: version-independent header classifier plus long-header and
  short-header bitfield accessors.
- `packet.rs` or `datagram.rs`: coalesced datagram model, packet sequence
  compile/decode, raw protected payload preservation, and summaries.
- `decode.rs`: UDP payload append helpers, conservative recognition helpers,
  and structured malformed-header errors.
- `frame/`: frame enum, frame sequence encode/decode, frame-specific parsers,
  unknown preservation, and malformed-frame errors.
- `transport_parameter.rs` or `transport_parameter/`: transport-parameter tuple
  parsing, typed default-eligible parameters, grease helpers, and unknown value
  preservation.
- `protection.rs`: only after review, explicit Initial secret/header-protection
  and Retry integrity helpers for caller-supplied inputs and fixed vectors.

Do not add endpoint state, connection management, loss recovery, congestion
control, HTTP/3, QPACK, MASQUE, DNS-over-QUIC client/server behavior, scanner
logic, or fuzzer logic to `crafter`.

## Public Export Points

- `crafter/src/protocols/mod.rs`: add `pub mod quic;`, import `quic` in
  `protocols::exports`, and re-export selected stable packet primitive symbols.
- `crafter/src/lib.rs`: no separate QUIC root module is needed; root, `core`,
  and `prelude` exports flow through `pub use protocols::exports::*`.
- Public symbols should stay packet-layer oriented, for example `Quic`,
  `QuicDatagram`, `QuicPacket`, `QuicHeader`, `QuicFrame`,
  `QuicTransportParameter`, `QuicConnectionId`, `QuicVersion`, and reviewed
  constants. Final names belong to the implementation steps that create the
  source files.
- Avoid a parallel public decode surface. Normal callers should continue using
  `/` composition, `compile()`, `Packet::decode_from_l3`, `summary()`, and
  `show()`.
- Unknown versions, unknown transport parameters, unsupported encrypted content,
  and user-pinned malformed fields must remain inspectable or fail with
  structured errors according to the source-backed boundary.

## Registry And UDP Hooks

- `crafter/src/registry.rs`: add any built-in QUIC UDP application binding only
  after the dedicated recognition-policy step defines a conservative gate. It
  must run through the existing `decode_udp_application` path, respect
  `application_decoding(false)`, and leave custom bindings usable.
- `crafter/src/protocols/transport/udp/datagram.rs`: include the QUIC layer in
  `is_udp_application_layer` once a compiling QUIC layer exists, so UDP length
  and surplus handling match DNS/DHCP behavior.
- `crafter/src/protocols/transport/udp/datagram.rs`: keep raw fallback for
  non-QUIC and ambiguous UDP payloads. A malformed QUIC-looking payload should
  return a structured `CrafterError` only after the recognizer has positively
  selected QUIC.
- `crafter/src/registry.rs`: keep existing DNS/53, IKE/500, NAT-T/4500,
  DHCP/67-68, RIP/520, RIPng/521, BGP/TCP, and MQTT/TCP behavior unchanged.
- `crafter/src/protocols/quic/decode.rs`: provide the append function and shape
  predicates used by the registry; do not embed registry policy in unrelated
  UDP code.

## Fixture And Test Targets

- `crafter/tests/quic_public_api.rs`: construction and decode through
  `crafter::prelude::*` and documentation-space IPv4/IPv6 UDP stacks.
- `crafter/tests/quic_golden.rs`: byte-exact packet, header, frame, transport
  parameter, and packet-protection vector tests as each feature lands.
- `crafter/tests/quic_malformed.rs`: structured truncation and malformed corpus
  tests for varints, headers, connection IDs, packet numbers, frames, transport
  parameters, Retry tags, and coalesced datagrams.
- `crafter/tests/quic_property.rs` or focused proptest modules: varint, packet
  number, connection ID, frame, and transport-parameter round trips.
- `crafter/tests/fixture_suite.rs`: add expected layers, coverage families,
  valid fixtures, pcap fixtures, and summary/show fixtures when fixture files
  are created.
- `crafter/tests/resilience.rs`: include QUIC malformed fixture labels once the
  parser returns stable structured errors.
- `crafter/tests/fixtures/bytes/`: use names such as
  `ipv4-udp-quic-v1-initial.hex`, `ipv4-udp-quic-version-negotiation.hex`,
  `ipv6-udp-quic-v2-initial.hex`, and `ipv4-udp-quic-coalesced.hex`.
- `crafter/tests/fixtures/malformed/`: use names such as
  `quic-truncated-varint.hex`, `quic-truncated-long-header.hex`,
  `quic-truncated-connection-id.hex`, `quic-truncated-frame.hex`, and
  `quic-truncated-transport-parameter.hex`.
- `crafter/tests/fixtures/pcaps/`: add classic pcap fixtures such as
  `raw-ipv4-udp-quic-bootstrap.pcap` and `raw-ipv6-udp-quic-bootstrap.pcap`
  only from synthetic documentation-space bytes.
- `crafter/tests/fixtures/summaries/`: mirror valid byte fixture names with
  `.summary.txt` and `-show.summary.txt` files for stable inspection output.

## Oracle Integration Points

- `tools/oracle/specs/layers/quic.yaml`: top-level QUIC datagram or packet layer
  fields, backend support, raw payload behavior, and coverage cases.
- `tools/oracle/specs/layers/quic_frame.yaml` and
  `tools/oracle/specs/layers/quic_transport_parameter.yaml`: add only when the
  frame and transport-parameter scaffolds exist.
- `tools/oracle/specs/features/quic-headers.yaml`,
  `tools/oracle/specs/features/quic-frames.yaml`,
  `tools/oracle/specs/features/quic-transport-parameters.yaml`,
  `tools/oracle/specs/features/quic-packet-protection.yaml`,
  `tools/oracle/specs/features/quic-pcap.yaml`, and
  `tools/oracle/specs/features/quic-live.yaml`: split by behavior rather than by
  implementation file.
- `tools/oracle/specs/stacks.d/quic.yaml` and
  `tools/oracle/specs/profiles.d/quic.yaml`: prefer protocol fragments if the
  loader validation accepts them; otherwise update `tools/oracle/specs/stacks.yaml`
  and `tools/oracle/specs/profiles.yaml` in the step that adds executable specs.
- `tools/oracle/engine/protocols/quic.py`: generator-stage sampler and feature
  behavior for QUIC packet plans.
- `tools/oracle/engine/backends/scapy/protocols/quic.py`: Scapy reference
  encode/decode support or explicit unsupported-case normalization for features
  Scapy cannot model.
- `tools/oracle/engine/backends/wireshark/protocols/quic.py`: optional
  parser-only normalization for pcap/decode comparisons once the layer declares
  Wireshark backend support.
- `tools/oracle/specs/fixtures/quic-scapy-coverage.md`: backend coverage notes
  for unsupported encrypted or extension cases.

## Probe And Lab Integration Points

- `tools/probe/engine/protocols/quic.py`: QUIC probe cases, dry-run plan
  builders, live-plan candidates, failure reasons, lab capability derivation,
  and target-service contribution if a controlled peer is required.
- `tools/probe/tests/test_quic_behavior.py`: deterministic plan and builder
  identity tests once probe cases exist.
- `tools/probe/tests/test_probe_protocol_coverage.py`,
  `tools/probe/tests/test_probe_plan_snapshot.py`, and
  `tools/probe/tests/test_probe_rewrite_snapshot.py`: update deliberately when
  the QUIC plugin adds cases or stimulus-endpoint routing.
- `tools/probe/adapters/src/quic.rs`: Rust stimulus adapter only for
  live-capable cases after crate builders exist.
- `tools/probe/adapters/src/common.rs` and `tools/probe/adapters/src/lib.rs`:
  dispatch and module wiring for the adapter step only.
- `tools/probe/target_services/quic/`: add only if live probe cases need a
  controlled service; do not add a general QUIC server or HTTP/3 endpoint to the
  crate.
- `tools/lab/run plan --provider qemu --dry-run --profile quic-smoke --seed 1 --role stimulus --role target --json`
  is the initial lab substrate check once `quic-smoke` exists.
- `tools/oracle/run live --provider local-dry-run --profile quic-smoke --seed 1 --count 10`
  is the oracle live dry-run shape. Real provider runs require the later
  protected live step and `--confirm-live-run`.
- `tools/probe/run --provider qemu --dry-run --profile quic-smoke --seed 1 --count 10`
  is the probe dry-run shape. Real traffic is not part of this inventory step.

## Documentation Targets

- `docs/guide/quic.md`: user-facing crate guide for packet construction, decode,
  inspection, raw protected payloads, and non-goals.
- `docs/reference/api.md` and `docs/reference/wire.md`: public API and wire
  validation references after stable symbols exist.
- `docs/operations/validation.md`: QUIC fixture, oracle, pcap, dry-run live,
  probe, lab, and release-gate commands.
- `.agents/docs/cookbook.md`: agent workflow guidance for generated QUIC tools,
  dry-run defaults, provider-backed live boundaries, and artifact collection.
- Module rustdoc in `crafter/src/protocols/quic/mod.rs`: source boundary,
  examples using documentation address space, and explicit endpoint/application
  non-goals.
- Later boundary docs for HTTP/3, QPACK, MASQUE, DoQ, operational guidance, and
  compatible version negotiation should cite the relevant QUIC notes instead of
  expanding crate scope.

## Acceptance And Validation Commands

Inventory-step acceptance:

```sh
test -f docs/quic-implementation-inventory.md
rg -n "crafter/src/protocols|tools/oracle|tools/probe|check-crafter-release" docs/quic-implementation-inventory.md
```

Focused commands for later implementation steps, run from the repository root as
the relevant files land:

```sh
cargo test -p crafter --test quic_public_api
cargo test -p crafter --test quic_golden
cargo test -p crafter --test quic_malformed
cargo test -p crafter --test fixture_suite quic
cargo test -p crafter --test resilience quic
tools/oracle/run specs validate
tools/oracle/run offline --profile quic-smoke --seed 1 --count 10
tools/oracle/run pcap --profile quic-smoke --seed 1 --count 10
tools/oracle/run live --provider local-dry-run --profile quic-smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile quic-smoke --seed 1 --count 10
tools/lab/run plan --provider qemu --dry-run --profile quic-smoke --seed 1 --role stimulus --role target --json
.agents/scripts/check-crafter-release --static
```

If any focused command exposes a real defect, fix the affected library, fixture,
spec, or documentation file in the step that owns that surface and rerun the
focused command before moving on.
