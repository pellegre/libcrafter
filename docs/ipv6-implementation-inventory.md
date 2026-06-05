# IPv6 Implementation Inventory

This inventory maps the current `crafter` IPv6 implementation to the
source-backed facts recorded in [`docs/ipv6-rfc-manifest.md`](ipv6-rfc-manifest.md).
It was prepared before behavior edits so later IPv6 enrichment can separate
existing behavior, coverage gaps, and explicit exclusions.

Date checked: 2026-06-04. The RFC manifest was read first. No live packet
exchange is required by this inventory.

Each item uses one primary status:

- **Implemented** - current code implements the packet-layer behavior and the
  behavior is traceable to the manifest.
- **Partial** - current code implements part of the behavior, but typed fields,
  registry coverage, validation, docs, or tests are incomplete.
- **Missing** - source-backed behavior is not represented in the current packet
  surface.
- **Compatibility only** - public surface is retained so older callers compile,
  but it is not source-backed wire behavior.
- **Obsolete** - current behavior models or defaults to deprecated wire behavior.
- **Unsupported** - current code deliberately does not implement the behavior.
- **Ambiguous** - current behavior needs source reconciliation before it should
  guide code changes.
- **Out of scope** - explicitly excluded by the manifest and Clew scope.

## Current File Map

| Area | Current files | Status | Notes |
| --- | --- | --- | --- |
| IPv6 protocol implementation | `crafter/src/protocols/ipv6.rs` | Partial | Contains the base `Ipv6` layer, generic Routing header, Fragment header, Mobile Routing Type 2 header, Segment Routing header, decode chain, summaries, inspection fields, and unit tests. It does not contain Hop-by-Hop Options, Destination Options, option TLVs, Mobility Header protocol 135, or a complete current SRH TLV model. |
| Common IP protocol constants | `crafter/src/protocols/ip.rs`, `crafter/src/protocols/ipv6.rs` | Partial | `ip.rs` exports TCP, UDP, IPv6 encapsulation, and ICMPv6 protocol values. `ipv6.rs` exports HOPOPT(0), Route(43), Fragment(44), and DSTOPTS(60). Constants for No Next Header(59), ESP(50), AH(51), Mobility Header(135), HIP(139), Shim6(140), and experimental extension values 253/254 are missing. |
| Decode registry | `crafter/src/registry.rs` | Implemented | Built-ins bind Ethernet IPv6 to `append_ipv6_packet_with_registry`, and bind IPv6 Next Header values 58, 6, and 17 to ICMPv6, TCP, and UDP. Unbound IPv6 next-header payloads are preserved as `Raw` when non-empty. Extension-header traversal for Routing and Fragment is implemented inside `ipv6.rs`, not as registry bindings. |
| Public exports | `crafter/src/protocols/mod.rs`, `crafter/src/lib.rs` | Partial | Root, `core`, and `prelude` exports include `Ipv6`, `Ipv6FragmentHeader`, `Ipv6RoutingHeader`, `Ipv6MobileRoutingHeader`, `Ipv6SegmentRoutingHeader`, extension constants 0/43/44/60, routing type constants 2/4, and SRH policy constants. Missing surfaces are not exported because they do not exist yet. |
| Packet abstraction | `crafter/src/packet.rs`, layer impls in `ipv6.rs` | Implemented | IPv6 layers use the existing `Layer`, `/`, `Packet`, `compile`, `decode_from_l3`, `summary`, `show`/inspection-field shape. |

## Source-Backed Requirement Matrix

| Requirement | Manifest source | Current location | Status | Notes |
| --- | --- | --- | --- | --- |
| 40-octet IPv6 base header: version, Traffic Class, Flow Label, Payload Length, Next Header, Hop Limit, source, destination | RFC 8200 | `Ipv6` in `ipv6.rs` | Implemented | Builders, aliases, getters, `summary`, inspection fields, compile, and decode are present. Decode rejects short headers and bad version. |
| Protocol-correct auto-fill for payload length and next header | RFC 8200 | `Ipv6::compile`, `layer_ipv6_next_header` | Implemented | Unset payload length is computed from following layers. Unset next header is inferred for Routing, Fragment, TCP, UDP, and ICMPv6. Explicit caller values are preserved. |
| Traffic Class raw field | RFC 8200 | `Ipv6::traffic_class`, `tc`, `traffic_class_value` | Implemented | Raw 8-bit value is preserved and fixture-tested. |
| Traffic Class DSCP/ECN helpers | RFC 2474 / RFC 3168 still noted for review in manifest | none | Missing | The manifest says DSCP/ECN semantics require additional source review before helpers beyond raw Traffic Class access. |
| Flow Label raw field | RFC 8200 | `Ipv6::flow_label`, `fl`, `flow_label_value` | Implemented | Compile validates 20-bit range. Fixtures and oracle vectors cover nonzero and max flow-label values. |
| Flow Label generation or policy | RFC 6437 still noted for review in manifest | none | Missing | Current behavior preserves explicit values and defaults to zero; no automatic generation policy exists. |
| Payload Length preservation and truncation errors | RFC 8200 | `decode_ipv6_parts` | Implemented | Declared payload length bounds the payload slice; shorter buffers return structured `buffer_too_short`. Extra bytes after the declared payload are appended as `Raw`. |
| Jumbogram payload-length-zero invariant and Jumbo Payload option | RFC 2675 | none | Missing | The current `effective_payload_length` rejects payloads over 65535 unless caller sets an explicit 16-bit payload length. There is no Hop-by-Hop Jumbo Payload option or jumbogram invariant support. |
| Upper-layer pseudo-header context for TCP, UDP, ICMPv6 | RFC 8200 | `Ipv6::transport_checksum_context`; TCP/UDP/ICMPv6 layers | Implemented | IPv6 checksum contexts are exercised by IPv6 TCP, UDP, and ICMPv6 tests/fixtures. |
| Unknown Next Header preservation | RFC 8200; IANA protocol numbers | `ProtocolRegistry::decode_ipv6_next_header` | Implemented | Unknown/unbound payloads are preserved as `Raw`; unit tests and oracle vectors cover value 253. Empty unknown payloads stay absent rather than adding empty `Raw`. |
| No Next Header 59 | RFC 8200; IANA protocol numbers | registry raw fallback only | Partial | Value 59 has no named constant, summary label, or explicit test. With zero payload it naturally decodes to no child layer; with nonzero payload it currently follows generic raw fallback. |
| Extension-header chain traversal and extension order preservation | RFC 8200; RFC 7045 | `append_ipv6_next_with_registry`; `Layer` composition | Partial | Hop-by-Hop(0), Destination Options(60), Routing(43), and Fragment(44) are traversed when typed, including zero-offset Fragment Header continuation. RFC 8200's recommended extension order is guidance for callers; libcrafter does not silently reorder user-composed layers. AH(51), ESP(50), Mobility Header(135), HIP(139), Shim6(140), and experimental next-header values remain unsupported by default and are preserved as `Raw`; explicit custom registry bindings are still invoked after supported extension chains. |
| Hop-by-Hop Options header | RFC 8200; RFC 9673 ambiguity noted in manifest | constant only | Missing | `IPPROTO_IPV6_HOPOPTS` exists and summaries can name it, but there is no layer, option parser, builder, or chain traversal. |
| Destination Options header | RFC 8200; RFC 6275 Home Address option | constant only | Missing | `IPPROTO_IPV6_DSTOPTS` exists and summaries can name it, but there is no Destination Options layer or option parser. |
| IPv6 option TLV action/change bits | RFC 8200; RFC 9673 ambiguity noted in manifest | none | Missing | Pad1, PadN, Jumbo Payload, Router Alert, Home Address, and unknown options have no common TLV representation. |
| Router Alert option | RFC 2711; IANA deprecates for new protocols | none | Missing | Should be explicit and inspectable only if added; no automatic router-intercept behavior should be added. |
| Home Address Destination Option | RFC 6275 Section 6.3 | `Ipv6Option::home_address` in `ipv6.rs` | Implemented | Option Type 0xC9 with exact 16-octet IPv6 address data decodes typed; malformed lengths remain `Generic` for byte preservation. This is packet-layer field support only; Mobile IPv6 Binding Cache and state machines remain out of scope. |
| Generic Routing Header base format | RFC 8200; IANA Routing Types | `Ipv6RoutingHeader` | Implemented | Generic header encodes/decodes next header, Hdr Ext Len, Routing Type, Segments Left, and type-specific data. Unknown type data is preserved. |
| Routing Header Type 0 deprecation | RFC 5095; IANA Routing Types | `Ipv6RoutingHeader::new` | Obsolete | The generic routing header defaults to routing type 0, which the manifest marks deprecated. Current code can decode and preserve type 0, but generated defaults should not emit it without an explicit caller request. |
| Mobile IPv6 Type 2 Routing Header | RFC 6275 | `Ipv6MobileRoutingHeader` | Implemented | Type 2 builder/decode preserve next header, length, segments left, reserved field, and home address. Unit tests and oracle vectors cover encode/decode. |
| Mobility Header protocol 135 | RFC 6275; IANA protocol numbers | `IPPROTO_IPV6_MOBILITY`; registry raw fallback | Unsupported | The Mobility Header next-header value is named for inspection, but there is no Mobility Header layer, no default parser, and no registry binding. Payload bytes are preserved as `Raw` by default; Mobile IPv6 state machines remain out of scope. |
| Segment Routing Header Routing Type 4 | RFC 8754; RFC 9800 update noted in manifest | `Ipv6SegmentRoutingHeader` | Partial | Fixed fields are aligned with RFC 8754: Routing Type 4, Last Entry, one-octet Flags, Tag, Segment List, and raw trailing data are public and byte-preserving. Compatibility aliases such as `segleft`, `push_ipv6_segment`, first-segment, C/P flags, and extra data still compile. Endpoint behavior and current IANA SRH Flags/TLV semantics are not implemented here. |
| SRH legacy compatibility fields | Historical libcrafter SRH surface; RFC 8754 current packet format | `Ipv6SegmentRoutingHeader` | Compatibility only | Policy address/flag setters, HMAC key ID, and HMAC bytes remain public so older callers compile and can inspect builder state. They are not emitted as source-backed RFC 8754 fields, do not round-trip through decode, and do not implement SRv6 endpoint behavior, HMAC verification, policy installation, or live SR domain behavior. |
| SRH segment list preservation | RFC 8754 | `Ipv6SegmentRoutingHeader` | Partial | Segment List entries are exposed as encoded 128-bit IPv6 addresses, starting from the last segment of the SR Policy as described by RFC 8754. Raw trailing data after the segment list is preserved for unsupported TLVs and padding. TLVs are not typed; HMAC verification is not implemented. |
| SRv6 endpoint behavior | RFC 8754 operational behavior | none | Unsupported | Out of scope. No SID execution, endpoint action, policy installation, HMAC verification, or live SR domain behavior should be added here. |
| Fragment Header field inspection | RFC 8200; RFC 6946; RFC 7112 | `Ipv6FragmentHeader` | Implemented | Encodes/decodes next header, reserved byte, offset, reserved bits, M flag, and identification; summary/show expose fields. Unit tests and fixtures cover initial fragments and non-initial raw preservation. |
| Atomic fragment notes | RFC 6946 | `Ipv6FragmentHeader`; `Ipv6FragmentHeaderStatus` | Implemented | Offset zero and M flag false are classified as atomic fragments through status helpers and show inspection. Public tests cover terminal-layer decode continuation and byte-for-byte round trips. This is packet-layer inspection only; no reassembly, queue, fragment cache, or stateful processing is implemented. |
| First-fragment complete-header-chain validation | RFC 7112 | field exposure only | Partial | The crate exposes fragment offset and extension-chain structure but does not validate oversized header-chain placement across fragments. This remains validation/oracle guidance, not reassembly. |
| Fragment generation across multiple packets | Manifest scope | none | Out of scope | `crafter` can build one Fragment Header layer but does not split payloads into fragments. Fragmentation generation is out of scope. |
| IPv6 reassembly or fragment cache | Manifest scope | none | Out of scope | Non-initial fragments are preserved as `Raw`; there is no reassembly, overlap handling, queue, timeout, or fragment cache. |
| PMTUD probing | RFC 8201 | docs/oracle guidance only | Out of scope | The manifest allows docs, sizing notes, and dry-run oracle profiles. The crate should not perform live PMTUD probing by default. |
| AH and ESP cryptography | IANA extension-header types; manifest exclusion | `IPPROTO_IPV6_AH`, `IPPROTO_IPV6_ESP`; registry raw fallback | Unsupported | Next Header 51 (AH) and 50 (ESP) payloads are not typed and no crypto, authentication, key management, or verification is implemented. Packet-layer raw preservation does not imply AH/ESP support; custom registry bindings are required for caller-owned decoding. |
| HIP, Shim6, and experimental next-header values | IANA Assigned Internet Protocol Numbers | `IPPROTO_IPV6_HIP`, `IPPROTO_IPV6_SHIM6`, `IPPROTO_IPV6_EXPERIMENTAL_1`, `IPPROTO_IPV6_EXPERIMENTAL_2`; registry raw fallback | Unsupported | These unsupported values are named for inspection and summary output, but there are no built-in protocol layers or default parsers. Non-empty payloads are preserved as `Raw` unless the caller installs an explicit registry binding. |
| Malformed/truncated decode behavior | RFC 8200 and extension sources | `decode_ipv6_parts`, `decode_extension_total_len`, `decode_fragment_header`, `decode_segment_routing_header` | Partial | Base IPv6, routing, fragment, and SRH length failures produce structured errors. Hop-by-Hop and Destination Options malformed behavior is missing because those layers are missing. |

## Tests

| Coverage | Current files | Status | Notes |
| --- | --- | --- | --- |
| Base IPv6 unit tests | `crafter/src/protocols/ipv6.rs` module `ipv6_tests` | Implemented | Covers TCP checksum context, auto-filled payload length/next header, Traffic Class, Flow Label, Hop Limit, explicit base Next Header preservation, short header, bad version, and payload-length mismatch. |
| Fragment unit tests | `crafter/src/protocols/ipv6.rs` module `ipv6_extensions` | Implemented | Covers Fragment Header chaining to UDP, IPv6 pseudo-header checksum preservation, non-initial fragment raw preservation, unknown next-header raw fallback, and short fragment header error. |
| Routing unit tests | `crafter/src/protocols/ipv6.rs` module `ipv6_routing_header` | Partial | Covers RFC 8754 SRH fixed-field shape, Mobile Routing Type 2, generic routing unknown type data, and builder rejection for some malformed SRH fields. It does not cover Hop-by-Hop, Destination Options, Home Address option, No Next Header, atomic fragments, or current RFC 8754 TLVs. |
| Public API path tests | `crafter/tests/public_api.rs` | Missing | Public API tests exercise UDP/TCP exports but do not currently assert IPv6 extension types through root, `core`, `prelude`, and `protocols` paths. |
| Fixture suite IPv6 base/transport | `crafter/tests/fixture_suite.rs` | Implemented | Catalog covers `ipv6-icmp-echo-request`, `ipv6-icmpv6-time-exceeded`, `ipv6-udp-raw`, `ipv6-udp-options-unknown-unsafe`, `ipv6-udp-options-frag`, `ipv6-tcp-raw`, and `ipv6-tcp-rich-options`. Field assertions cover addresses, Traffic Class, Flow Label, Next Header, Hop Limit, transport fields, checksums, and raw payloads. |
| Fixture suite IPv6 extension headers | `crafter/tests/fixture_suite.rs` | Partial | Local byte fixtures include `ipv6-fragment-udp-raw` only. There are no committed byte fixtures for generic routing, Mobile Routing Type 2, SRH, Hop-by-Hop Options, Destination Options, Home Address option, No Next Header, or atomic fragments. |
| Pcap fixtures | `crafter/tests/fixture_suite.rs`, `crafter/tests/fixtures/pcaps/raw-ipv6-icmp-echo-request.pcap` | Implemented | Offline RawIP IPv6 pcap coverage exists for an ICMPv6 echo request. No pcap fixture currently exercises IPv6 extension headers. |
| Malformed corpus | `crafter/tests/fixtures/malformed/core-decode-corpus.hex`, `crafter/tests/resilience.rs` | Partial | Covers short IPv6 base header, bad version, payload-length mismatch, truncated routing header, truncated fragment header, and malformed SRH length. No malformed Hop-by-Hop or Destination Options cases exist. |
| ICMPv6/NDP tests over IPv6 | `crafter/tests/icmpv6_ndp.rs`, ICMPv6 module tests | Implemented | These exercise IPv6 as the enclosing layer for ICMPv6, NDP, MLD, and hop-limit-sensitive workflows, but they are not IPv6 extension-header coverage. |

## Fixtures

| Fixture class | Current files | Status | Notes |
| --- | --- | --- | --- |
| IPv6 byte fixtures | `crafter/tests/fixtures/bytes/ipv6-*.{bin,hex}` | Partial | Existing fixtures cover ICMPv6, UDP, TCP, UDP options, and one Fragment Header stack. Routing, Mobile Routing, SRH, Hop-by-Hop, Destination Options, Home Address, and No Next Header fixtures are missing. |
| IPv6 summary fixtures | `crafter/tests/fixtures/summaries/ipv6-*.summary.txt` | Partial | Summaries exist for IPv6 TCP options, IPv6 UDP options, and IPv6 Fragment Header. No summaries exist for routing/mobile/SRH/option-header stacks. |
| IPv6 pcap fixtures | `crafter/tests/fixtures/pcaps/raw-ipv6-icmp-echo-request.pcap` | Implemented | Covers raw IPv6 pcap decode. Extension-header pcaps are missing. |
| Fixture documentation | `crafter/tests/fixtures/README.md` | Partial | Documents current IPv6 fixture coverage and malformed IPv6 extension-header entries; it correctly reflects the absence of broader IPv6 option/routing fixtures. |

## Oracle And Probe Specs

| Area | Current files | Status | Notes |
| --- | --- | --- | --- |
| IPv6 oracle layer spec | `tools/oracle/specs/layers/ipv6.yaml` | Partial | Declares base IPv6 fields and coverage cases for boundary fields, unknown next-header raw, fragment, generic routing, mobile routing, SRH, routing to TCP, and routing to ICMPv6. It lists `hop_by_hop` as a next-header domain, but there is no Hop-by-Hop layer/materializer support. |
| IPv6 fragment/routing feature spec | `tools/oracle/specs/features/ipv6-fragment-routing.yaml` | Implemented | Declares fragment, generic routing, mobile routing, SRH, routing-to-TCP, routing-to-ICMPv6, and malformed extension coverage in both Scapy-to-libcrafter and libcrafter-to-reference directions. |
| Oracle stack registry | `tools/oracle/specs/stacks.yaml` | Implemented | Defines `ipv6_fragment_udp`, `ipv6_routing_payload`, `ipv6_routing_tcp_payload`, and `ipv6_routing_icmpv6` stacks. |
| Oracle fixture case index | `tools/oracle/specs/fixtures/scapy-cases.json` | Implemented | Marks IPv6 boundary, unknown next-header, fragment, generic routing, mobile routing, SRH, routing-to-TCP, routing-to-ICMPv6, and malformed extension cases as implemented. |
| Scapy materializer | `tools/oracle/engine/backends/scapy/packets.py` | Partial | Materializes IPv6, Fragment, and generic Routing through Scapy. It has no Hop-by-Hop, Destination Options, Mobility Header, or option-TLV materializer. |
| libcrafter oracle vectors | `tools/oracle/adapters/src/bin/vectors/cases.rs` | Implemented | Builds libcrafter-originated IPv6 boundary, unknown next-header, fragment, generic routing, mobile routing, SRH, routing-to-TCP, and routing-to-ICMPv6 vectors. |
| Oracle profiles | `tools/oracle/specs/profiles.yaml` | Partial | Generic smoke/ci/wild/boundary/fuzz profiles include IPv6 weights. There is no dedicated IPv6 extension dry-run profile analogous to focused TCP profiles. |
| Probe specs and live plans | `tools/probe/**` | Partial | Probe coverage is mostly NDP and live behavior planning, not IPv6 extension-header enrichment. Live packet exchange remains opt-in and is not a prerequisite for this inventory. |

## Examples And Docs

| Area | Current files | Status | Notes |
| --- | --- | --- | --- |
| IPv6 extension example | `crafter/examples/ipv6_extensions.rs`, `crafter/examples/README.md` | Partial | Offline example builds and decodes SRH-like and Fragment Header packets. It does not demonstrate generic routing, Mobile Routing Type 2, Hop-by-Hop Options, Destination Options, Home Address option, No Next Header, or malformed handling. |
| ICMPv6 echo example | `crafter/examples/icmpv6_echo.rs` | Implemented | Demonstrates IPv6 plus ICMPv6 construction and optional dry-run send/receive. It does not exercise extension headers. |
| User-facing API docs | `docs/api.md`, `README.md` | Partial | Lists IPv6 and current extension header types, and maps the `ipv6_extensions` example. There is no dedicated user-facing `docs/ipv6.md` that explains base fields, extension chaining, unsupported areas, or source-backed option status. |
| RFC manifest | `docs/ipv6-rfc-manifest.md` | Implemented | Source-backed manifest exists and should remain the authority for future behavior edits. |
| Existing TCP/UDP docs with IPv6 notes | `docs/tcp.md`, `docs/tcp-rfc-manifest.md`, `docs/udp-rfc-manifest.md`, `docs/api.md` | Implemented | These correctly state that fragmentation/reassembly is out of scope and that IPv6 checksum or minimum-MTU facts are guidance where relevant. |

## Priority Gap List

1. **Missing IPv6 option headers** - add Hop-by-Hop Options and Destination
   Options layers with a shared option TLV representation before adding Jumbo
   Payload, Router Alert, Home Address, Pad1/PadN, or unknown-option behavior.
   Status: Missing.
2. **Missing DSCP/ECN helpers** - raw Traffic Class exists, but DSCP/ECN helpers
   need RFC 2474/RFC 3168/IANA review before being added. Status: Missing.
3. **Missing No Next Header surface** - value 59 needs a named constant,
   summary label, explicit tests, and a policy for nonzero payload bytes.
   Status: Partial.
4. **Obsolete Routing Type 0 default** - `Ipv6RoutingHeader::new()` defaults to
   type 0 even though RFC 5095 deprecates RH0. Later behavior edits should avoid
   generated defaults that emit RH0 accidentally. Status: Obsolete.
5. **SRH TLV and flag registry follow-up** - fixed SRH fields now follow RFC
   8754, but RFC 9800 and the current IANA SRH flags/TLV registries still need
   review before adding typed TLV or later flag semantics. Status: Partial.
6. **Mobile IPv6 completion within packet scope** - Type 2 routing is present,
   but Home Address Destination Option and Mobility Header protocol 135 are
   missing. Mobile IPv6 state machines remain out of scope. Status: Partial.
7. **Fixture expansion** - add local byte/summary fixtures for generic routing,
   mobile routing, SRH, Hop-by-Hop, Destination Options, Home Address, No Next
   Header, atomic fragments, and malformed option headers. Status: Partial.
8. **Oracle/profile expansion** - oracle cases already cover routing and
   fragment paths, but not Hop-by-Hop or Destination Options; a focused IPv6
   extension dry-run profile would make later validation easier. Status:
   Partial.
9. **User docs** - add a dedicated IPv6 protocol doc after behavior settles,
   with explicit unsupported/out-of-scope sections. Status: Partial.

## Out-of-Scope Notes

| Item | Status | Notes |
| --- | --- | --- |
| IPv6 fragmentation generation | Out of scope | Building one `Ipv6FragmentHeader` layer is supported; splitting payloads into multiple IPv6 fragments is not. |
| IPv6 reassembly, overlap handling, queues, timers, or fragment cache | Out of scope | Non-initial fragments preserve remaining bytes as `Raw`. No reassembly is implemented or planned in this enrichment step. |
| PMTUD probing or live Packet Too Big workflow | Out of scope | RFC 8201 guides docs, examples, dry-run profiles, and sizing notes only. |
| AH/ESP cryptography, keys, authentication, encryption, or verification | Out of scope | Raw preservation of Next Header 50/51 payload bytes must not be described as AH/ESP support. |
| SRv6 endpoint/SID behavior, HMAC verification, policy installation, live SR domain operation | Out of scope | Packet-layer SRH build/decode/inspect is the only in-scope SRH work. |
| Mobile IPv6 state machines, binding caches, return routability, home-agent behavior, route optimization workflows | Out of scope | Packet-layer Mobile IPv6 artifacts only: Type 2 Routing Header, Home Address option, and Mobility Header bytes if added later. |
| Live packet exchange by default | Out of scope | Examples, tests, oracle, and probe defaults must stay offline or dry-run unless explicitly live-gated. |
