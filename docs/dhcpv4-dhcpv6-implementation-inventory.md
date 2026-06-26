# DHCPv4/DHCPv6 Implementation Inventory

Reviewed: 2026-06-26

This inventory maps the current DHCPv4 implementation and artifacts to the
versioned DHCP family layout planned for DHCPv4 and DHCPv6. It is an
implementation map only. DHCPv6 wire behavior remains sourced from
`docs/dhcpv6-rfc-manifest.md`.

## Target Names

- Public Rust packet layers: `Dhcpv4` and `Dhcpv6`.
- Family root: `crafter/src/protocols/dhcp/`.
- Target implementation folders: `crafter/src/protocols/dhcp/v4/` and
  `crafter/src/protocols/dhcp/v6/`.
- Target oracle and probe layer names: `dhcpv4` and `dhcpv6`.
- Target artifact naming: use `dhcpv4-*`, `ipv4-udp-dhcpv4-*`,
  `dhcpv6-*`, and `ipv6-udp-dhcpv6-*` names.

## Crate Source Touchpoints

| Path | Current DHCPv4 role | Target versioned role |
| --- | --- | --- |
| `crafter/src/protocols/dhcp/` | Owns the current DHCPv4 module as `constants.rs`, `message.rs`, `option.rs`, `registry.rs`, and `mod.rs`. | Becomes the family root with shared organization plus `v4/` and `v6/` implementation folders. |
| `crafter/src/protocols/dhcp/mod.rs` | Exports DHCPv4 layer, constants, message types, option model, registry metadata, and append/decode helpers. | Re-export `Dhcpv4` from `v4/`, `Dhcpv6` from `v6/`, and any family-shared helpers that remain intentionally version-neutral. |
| `crafter/src/protocols/dhcp/constants.rs` | Holds BOOTP/DHCPv4 ports, message values, option codes, fixed lengths, and relay-option constants. | Move under `v4/` with `DHCPV4_*` constants; DHCPv6 uses separate 16-bit option, status, DUID, and port constants under `v6/`. |
| `crafter/src/protocols/dhcp/message.rs` | Defines DHCPv4 message-type symbols for DHCPv4 option 53 values. | Use `Dhcpv4MessageType`; DHCPv6 gets a separate `Dhcpv6MessageType` with 8-bit client/server and relay message codepoints. |
| `crafter/src/protocols/dhcp/option.rs` | Defines DHCPv4 option TLVs, typed option values, option overload, RFC 3396 concatenation, relay option 82, client identifiers, authentication, and leasequery packet fields. | Own the `v4/` option model with `Dhcpv4*` names; DHCPv6 gets a distinct 16-bit TLV option model, DUIDs, IA containers, prefix delegation, status options, relay options, and raw preservation. |
| `crafter/src/protocols/dhcp/registry.rs` | Provides DHCPv4 option metadata, port-pair recognition, payload shape gates, and option labels. | Own `v4/registry.rs`; DHCPv6 gets registry metadata for message types, option codes, status codes, DUID types, singleton metadata, placement metadata, and UDP port recognition. |
| `crafter/src/protocols/mod.rs` | Re-exports DHCP family symbols through `protocols::exports`, crate root, `core`, and `prelude`. | Export only versioned public DHCP names such as `Dhcpv4`, `Dhcpv4Option`, `Dhcpv6`, and `Dhcpv6Option`. |
| `crafter/src/protocols/transport/udp/` | Provides DHCPv4 UDP helper constructors and treats DHCPv4 as a UDP application layer. `tests.rs` covers DHCPv4 surplus decode. | Add versioned helpers for DHCPv4 and DHCPv6 ports and recognize `Dhcpv4` and `Dhcpv6` as UDP application layers without changing raw fallback behavior. |
| `crafter/src/registry.rs` | Built-in UDP application dispatch binds conservative DHCPv4 decode to the 67/68 port pair through DHCPv4 helper functions. | Keep the DHCPv4 binding versioned and add a separate conservative DHCPv6 binding for UDP 546/547 once the `Dhcpv6` decoder exists. |
| `crafter/src/net/reply.rs` | Reply filters and request/reply matching cover `Dhcpv4`, DHCPv4 ports, BOOTP reply opcodes, transaction IDs, client identifiers, server identifiers, relay `giaddr`, and DHCPv4 message-type compatibility. | Split reply filters and matchers into `Dhcpv4` and `Dhcpv6` paths, with DHCPv6 BPF/reply matching added only after source-backed message and option fields exist. |
| `crafter/src/net/tests.rs` | Contains send/reply planning coverage that mentions DHCPv4 behavior. | Keep DHCPv4 cases versioned as `Dhcpv4`/`dhcpv4` and add DHCPv6 coverage only for explicit dry-run or provider-backed paths. |

## Test And Fixture Touchpoints

| Path | Current DHCPv4 role | Target versioned role |
| --- | --- | --- |
| `crafter/tests/fixture_suite.rs` | Lists DHCPv4 option-only byte fixtures, DHCPv4 packet fixtures, DHCPv4 coverage families, layer expectations, and DHCPv4-specific field assertions. | Keep current entries versioned as DHCPv4 fixture names, layer expectations, and coverage families; add DHCPv6 fixture, pcap, summary, malformed, and round-trip coverage as later steps create artifacts. |
| `crafter/tests/public_api.rs` | Exercises DHCPv4 UDP helper constructors. | Cover `Udp::dhcpv4_*()` and `Udp::dhcpv6_*()` helpers plus `crafter::prelude::*` use of `Dhcpv4` and `Dhcpv6`. |
| `crafter/tests/resilience.rs` | Reads malformed fixture corpora that include DHCP decode cases. | Keep DHCPv4 malformed rows versioned and add DHCPv6 structured-error rows without sending traffic. |
| `crafter/tests/fixtures/README.md` | Documents the current DHCP byte fixture family as "IPv4 UDP DHCP message and DHCP option corpus." | Rename the matrix language to DHCPv4 and add DHCPv6 fixture rules when those fixtures land. |
| `crafter/tests/fixtures/bytes/` | Holds current DHCPv4 option fixtures and IPv4/UDP/DHCPv4 packet fixtures. | Keep current files versioned as `dhcpv4-*` / `ipv4-udp-dhcpv4-*`; add deterministic DHCPv6 byte fixtures such as `ipv6-udp-dhcpv6-solicit.hex` and relay examples. |
| `crafter/tests/fixtures/summaries/` | Holds DHCPv4 summary fixtures. | Keep current summaries matched to DHCPv4 byte fixture names and add DHCPv6 summary/show fixtures. |
| `crafter/tests/fixtures/pcaps/` | No DHCPv4 pcap fixture is currently named in this tree. | Add only synthetic classic pcap fixtures with documentation-space addresses, using names such as `raw-ipv6-udp-dhcpv6-solicit.pcap` when later steps require them. |
| `crafter/tests/fixtures/malformed/` | Contains shared malformed decode rows that mention DHCP. | Keep DHCPv4 malformed labels versioned and add DHCPv6 malformed client/server, relay, option, DUID, and IA container rows. |

DHCPv4 fixture rename steps should use the fixture directory listings as the
source of truth and produce only `dhcpv4-*` or `ipv4-udp-dhcpv4-*` tracked
artifact names.

## Example And Documentation Touchpoints

| Path | Current DHCPv4 role | Target versioned role |
| --- | --- | --- |
| `crafter/examples/dhcp_discover.rs` | Builds a DHCPv4 discover packet; live mode is explicitly gated and dry-run is default. | Rename to DHCPv4 naming and API; keep dry-run default and documentation-space behavior. |
| `crafter/examples/dhcp_option82.rs` | Demonstrates DHCPv4 relay agent information, classless routes, and option overload offline. | Rename to DHCPv4 naming and API. |
| `crafter/examples/dhcp_leasequery.rs` | Demonstrates DHCPv4 leasequery, typed client identifiers, authentication, and status/state packet fields offline. | Rename to DHCPv4 naming and API. |
| `crafter/examples/README.md` | Lists DHCPv4 examples. | List DHCPv4 examples with versioned names and add DHCPv6 examples only after they compile offline. |
| `README.md` | Holds protocol coverage and example references. | Keep protocol coverage versioned and add DHCPv6 only after implementation and validation land. |
| `docs/reference/api.md` | Documents the DHCPv4 layer and examples. | Keep the API section named `Dhcpv4` and add a separate DHCPv6 guide/API section later. |
| `docs/reference/examples.md`, `docs/reference/wire.md`, and `docs/README.md` | May reference examples, packet surfaces, or documentation index entries. | Keep all DHCP mentions versioned as `Dhcpv4`/`dhcpv4` or `Dhcpv6`/`dhcpv6`. |
| `docs/dhcpv6-rfc-manifest.md` | Records public RFC/IANA evidence for DHCPv6 packet-layer work. | Remains the standards authority for later DHCPv6 code, tests, fixtures, oracle specs, probe cases, and docs. |

## Oracle Touchpoints

| Path | Current DHCPv4 role | Target versioned role |
| --- | --- | --- |
| `tools/oracle/specs/layers/` | Defines the DHCPv4 layer schema for BOOTP/DHCPv4 over UDP. | Keep the layer name `dhcpv4` and add a separate `dhcpv6` layer schema when the Rust model exists. |
| `tools/oracle/specs/features/dhcp-behavior.yaml` | Defines current DHCPv4 behavior cases and option matrix coverage. | Rename current cases to DHCPv4 and add DHCPv6 feature files split by core messages, relay, options, malformed handling, pcap, dry-run live planning, and guarded live validation. |
| `tools/oracle/specs/stacks.yaml` | Contains Ethernet/IPv4/UDP/DHCPv4 stack declarations. | Keep current stacks/layers versioned as `dhcpv4`; add IPv6/UDP/DHCPv6 stacks with `dhcpv6` only on explicit offline or dry-run profiles before live gating. |
| `tools/oracle/specs/fixtures/scapy-cases.json` | Contains backend-owned DHCPv4 reference cases. | Rename current rows to DHCPv4 and add DHCPv6 backend cases or structured skips as reference support allows. |
| `tools/oracle/engine/protocols/` | Contains the DHCPv4 generator-stage sampler and feature behavior plugin. | Keep the plugin surface versioned as `dhcpv4.py` or versioned registration; add `dhcpv6.py` for DHCPv6 packet plans. |
| `tools/oracle/engine/backends/` | Contains DHCP support under Scapy and Wireshark backend protocol plugins, plus compatibility references in shared normalize/materialize code. | Rename current backend normalization and materialization to `dhcpv4`; add DHCPv6 backend support or explicit unsupported-case normalization. |
| `tools/oracle/adapters/src/bin/` | Rust oracle adapter binaries contain DHCPv4 plan materialization, decode, pcap, vector, and live-endpoint references. | Rename current adapter fields/layers to DHCPv4 and add DHCPv6 adapter support only after crate builders and decoders exist. |
| `tools/oracle/tests/` | Contains DHCPv4 oracle and Wireshark tests plus protocol coverage tests. | Keep current tests versioned as DHCPv4 and add DHCPv6 tests for offline, pcap, dry-run, and guarded live behavior. |
| `tools/oracle/README.md` and `tools/oracle/LIVE.md` | Describe DHCP oracle behavior and live constraints. | Keep DHCPv4/DHCPv6 names explicit and preserve the provider-backed live opt-in boundary. |

## Probe Touchpoints

| Path | Current DHCPv4 role | Target versioned role |
| --- | --- | --- |
| `tools/probe/engine/protocols/` | Contains the DHCPv4 probe planning plugin, controlled responder planning, failure reasons, target-service contribution, address rewrite, and lab capability hooks. | Keep the plugin surface versioned as DHCPv4 and add `dhcpv6` probe planning only for source-backed dry-run/provider-backed cases. |
| `tools/probe/engine/protocols/` | Registers DHCPv4 protocol cases for offer/ack/repeat behavior. | Keep cases named `dhcpv4-*`; add `dhcpv6-*` cases for Information-request, IA_NA, prefix delegation, relay, reconfigure, and leasequery only in later planned steps. |
| `tools/probe/adapters/src/` | Builds DHCPv4 stimulus packets through `crafter`. | Keep adapter names versioned as DHCPv4 and add a DHCPv6 adapter only after public `Dhcpv6` builders exist. |
| `tools/probe/adapters/src/common.rs` and `tools/probe/adapters/src/lib.rs` | Dispatch to the DHCPv4 adapter. | Keep dispatch names versioned once adapter names split. |
| `tools/probe/engine/cases.py`, `capabilities.py`, `planning.py`, `target_services.py`, `lab.py`, and CLI parser files | Contain DHCPv4 case/profile/capability wiring and target-service integration. | Keep existing wiring versioned as DHCPv4 and add DHCPv6 capability skips and dry-run planning without sending traffic from the developer host. |
| `tools/probe/tests/` | Contains DHCP behavior, plan snapshot, rewrite, capability, provider matrix, target service, and protocol coverage tests. | Rename current expectations to DHCPv4 and add DHCPv6 dry-run/provider-matrix expectations. |
| `tools/probe/README.md` | Describes DHCP probe workflow and live constraints. | Keep DHCPv4 and DHCPv6 probe documentation separate and explicit. |

## Planned DHCPv6 Additions

DHCPv6 must be added as a normal packet layer over IPv6/UDP, not as a client,
server, relay daemon, scanner, or lease engine. The planned core touchpoints
are:

- `crafter/src/protocols/dhcp/v6/` for message headers, relay headers, option
  TLVs, DUIDs, IA_NA, IA Address, IA_PD, IA Prefix, status codes, registry
  metadata, summaries, show output, and raw escape hatches.
- `crafter/src/protocols/transport/udp/` for DHCPv6 helper constructors on
  UDP ports 546 and 547.
- `crafter/src/registry.rs` for conservative DHCPv6 UDP application dispatch.
- `crafter/src/net/reply.rs` for explicit DHCPv6 send/receive filters and
  reply matching after the packet fields exist.
- `crafter/tests/fixture_suite.rs`, `crafter/tests/public_api.rs`, and fixture
  directories for deterministic offline DHCPv6 byte, pcap, summary, and
  malformed cases.
- `crafter/examples/` and `docs/` for offline examples and user-facing guides.
- `tools/oracle/specs/stacks.yaml`, `tools/oracle/engine/protocols/`, and
  `tools/oracle/engine/backends/` for DHCPv6 oracle layer plans and backend
  normalization.
- `tools/probe/engine/protocols/` and probe adapter/test paths for DHCPv6
  dry-run and provider-backed behavior validation.

## Boundaries

- Keep public DHCP names versioned as `Dhcpv4`/`dhcpv4` or
  `Dhcpv6`/`dhcpv6`.
- Do not add DHCPv6 live behavior without explicit provider-backed opt-in,
  artifacts, and teardown records.
- Do not store credentials, live host identifiers, public IPs, workstation
  paths, sensitive captures, or untracked scratch paths in source, docs,
  examples, fixtures, oracle files, or probe files.
