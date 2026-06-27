# SSDP source scope

This note records the repo integration points that SSDP must fit before any
wire behavior is implemented. It is an inventory document, not authority for
SSDP methods, headers, multicast destinations, ports, or message grammar. Those
facts must come from later source manifests that cite public SSDP or UPnP
specifications, RFC Editor documents, IANA registries, IETF Datatracker
metadata, and errata.

SSDP belongs in `crafter` as a packet primitive. The crate may build, compile,
decode, summarize, show, persist, and validate SSDP packet bytes through the
normal `Packet` abstraction. It must not become a scanner, UPnP control point,
device daemon, service cache, retry engine, HTTP client, or discovery workflow.
Generated tools can compose those workflows on top of the primitive.

## Crate integration points

- `crafter/src/protocols/ssdp/` is the intended home for the typed layer,
  parser, serializer, constants, registry labels, builders, and unit tests.
- `crafter/src/protocols/mod.rs` must declare and later export the public SSDP
  surface only after the layer shape is stable.
- `crafter/src/lib.rs` and `crafter::prelude::*` should expose SSDP through the
  same curated public path used by existing protocol layers.
- `crafter/src/registry.rs` owns default decode dispatch. SSDP should use the
  existing UDP application binding path and must keep custom UDP bindings and
  the application-decoding toggle meaningful.
- `crafter/src/protocols/transport/udp/` owns UDP length, checksum, surplus, and
  payload handoff behavior. SSDP must be only the application payload layer.

Comparable UDP application protocols:

- `crafter/src/protocols/dns/` shows a UDP application layer with builders,
  source-backed constants, typed records, raw preservation for unsupported data,
  and default UDP-port registry dispatch.
- `crafter/src/protocols/snmp/` shows a conservative UDP payload shape gate,
  source-gated registry metadata, structured BER errors, unknown-value
  preservation, and pcap fixtures for synthetic UDP application packets.
- `crafter/src/protocols/rip/` and `crafter/src/protocols/rip/ripng/` show
  source-backed codepoint metadata, UDP-port dispatch guarded by payload shape,
  unknown codepoint preservation, multicast packet guidance, and IPv4/IPv6
  sibling layers where the wire shape requires it.
- `crafter/src/protocols/dhcp/` shows port-pair and payload-structure gating for
  UDP decode so unrelated traffic on well-known ports stays `Raw`.

SSDP decode should follow the same pattern: match only source-backed UDP
application bindings, accept only a conservative HTTP-like message shape, and
leave unrelated text or binary UDP payloads as `Raw`.

## Fixture and test surfaces

- `crafter/tests/fixtures/README.md` defines the fixture catalog model for
  `bytes/`, `summaries/`, `pcaps/`, and `malformed/`.
- `crafter/tests/fixture_suite.rs` is the catalog owner for valid byte fixtures,
  pcap fixtures, summary fixtures, and coverage mappings.
- `crafter/tests/resilience.rs` and protocol-specific malformed tests consume
  malformed corpora and assert structured error outcomes instead of panics.
- `crafter/tests/fixtures/pcaps/README.md` records deterministic pcap provenance
  for synthetic packets and regeneration commands.
- `crafter/tests/fixtures/malformed/README.md` records line-oriented malformed
  corpus formats and expected error categories.

SSDP fixtures should be deterministic and offline: valid HTTP-like UDP payloads,
boundary messages, unrelated UDP payloads that must remain `Raw`, malformed
messages with structured error expectations, summary/show outputs, and raw and
Ethernet pcap records generated from documentation-safe packets.

## Oracle integration points

- `tools/oracle/docs/adding-a-protocol.md` is the recipe for a data-driven
  oracle protocol: layer specs, feature specs, optional stack/profile fragments,
  generator plugin, Scapy backend, and optional Wireshark normalizer.
- `tools/oracle/specs/README.md` defines oracle modes: `offline`, `pcap`, and
  provider-backed `live`, with artifacts under `target/oracle/`.
- `tools/oracle/specs/layers/` holds layer specs such as `dns.yaml`,
  `snmp.yaml`, `rip.yaml`, and `udp.yaml`.
- `tools/oracle/specs/features/` holds behavior slices, malformed cases,
  pcap cases, and live-plan contracts.
- `tools/oracle/engine/protocols/` holds generator plugins.
- `tools/oracle/engine/backends/scapy/protocols/` and
  `tools/oracle/engine/backends/wireshark/protocols/` hold backend encoders and
  normalizers.

SSDP oracle work should start with layer and feature specs, then add generator
and backend support. Reference-backend gaps must be recorded as unsupported or
parser-only rather than hidden.

## Probe and lab integration points

- `tools/probe/docs/adding-a-protocol.md` describes the auto-discovered probe
  plugin shape under `tools/probe/engine/protocols/<name>.py`.
- `tools/probe/README.md` separates probe behavior validation from oracle byte
  validation and keeps live work on disposable lab endpoints.
- `tools/probe/adapters/src/` holds Rust stimulus adapters for live-capable
  probe cases.
- `tools/probe/target_services/` holds optional controlled service assets when
  a protocol needs a target-side responder.
- `docs/operations/tools.md`, `docs/operations/probe.md`,
  `docs/operations/lab.md`, and `docs/operations/endpoint.md` document the
  dry-run-first provider workflow.

SSDP probe work should plan discovery-like packet exchanges only as controlled
behavior validation. The crate must still expose only packet construction and
decode primitives, while probe and lab own dry-run planning, endpoint roles,
artifact collection, protected live confirmation, and teardown.

## Examples and documentation

- `crafter/examples/README.md` is the public examples index and safety legend.
  SSDP examples should be offline or dry-run by default and use
  `crafter::prelude::*`.
- Existing protocol examples such as `dns_query`, `snmp_get`, `rip_request`,
  and `igmp_query` show packet construction, compile/decode inspection, and
  dry-run send planning without live defaults.
- `docs/README.md` indexes user-facing protocol guides under `docs/guide/` and
  operations workflows under `docs/operations/`.
- `.agents/docs/cookbook.md` is the generated-tool guidance location; it is not
  the user-facing crate guide.

Later SSDP docs should split audiences: user-facing packet API and validation
coverage belong under `docs/guide/`, while generated-tool operating guidance
belongs under `.agents/docs/`.

## Source and safety constraints

- Do not use model memory for SSDP wire facts. Record every relied-upon method,
  header, status, URI, multicast, port, or grammar rule in the source manifest
  before implementing code or fixtures from it.
- Preserve unknown methods, status codes, headers, extension values, bodies, and
  unsupported but structurally valid payload bytes.
- Return structured errors for malformed SSDP inputs with useful context,
  required length, and available length where applicable.
- Keep examples, fixtures, and validation records offline or dry-run by
  default, using documentation address space and documentation-safe identifiers.
- Do not store credentials, public provider addresses, live host identifiers,
  sensitive capture identifiers, or local absolute paths in tracked SSDP
  artifacts.
