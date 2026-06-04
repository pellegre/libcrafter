# IPv4 Implementation Inventory

This inventory maps the current `crafter` IPv4 implementation to the
source-backed behavior recorded in
[`docs/ipv4-rfc-manifest.md`](ipv4-rfc-manifest.md). It is a working map for the
IPv4 enrichment plan: later steps should use it to avoid duplicating existing
behavior and to target gaps in the right files.

Current IPv4 behavior is implemented primarily in
`crafter/src/protocols/ip.rs`, decoded through the protocol registry in
`crafter/src/registry.rs`, re-exported through `crafter/src/protocols/mod.rs`
and `crafter/src/lib.rs`, and covered by unit tests in
`crafter/src/protocols/ip.rs`, integration fixtures in
`crafter/tests/fixture_suite.rs`, and malformed corpus checks in
`crafter/tests/resilience.rs`.

Date checked: 2026-06-04, against the current worktree and
`docs/ipv4-rfc-manifest.md`.

## Status Key

- **implemented** - the current code already exposes or tests the behavior.
- **partial** - the current code covers part of the source-backed behavior but
  later steps need code, tests, fixtures, or docs.
- **gap** - the source-backed behavior is not currently implemented.
- **compatibility-only** - a public existing name must be preserved even if new
  source-backed names are added.
- **out of scope** - explicitly excluded by the spec and manifest.

## Current API Surface

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| `Ipv4` layer struct | `crafter/src/protocols/ip.rs` | implemented | Holds version, IHL, raw TOS/DS byte, total length, identification, flags, fragment offset, TTL, protocol, checksum, source, destination, and raw option bytes using `Field<T>` for explicit/default/unset tracking where applicable. |
| Packet composition | `crafter/src/protocols/ip.rs` | implemented | `Ipv4` implements `Layer`, object cloning, and `/` composition, so it fits the `Packet` abstraction. |
| Constructors | `crafter/src/protocols/ip.rs` | implemented | `Ipv4::new()` and `Ipv4::with_addresses(...)` exist. Defaults are builder conveniences, not host-stack policy. |
| Field builders | `crafter/src/protocols/ip.rs` | partial | Builders cover `version`, `ihl`, `tos`, `total_length`, `identification`, `flags`, DF, MF, fragment offset, TTL, protocol, checksum, source, destination, and options. DSCP and ECN helpers are not present yet. |
| Compatibility aliases | `crafter/src/protocols/ip.rs` | compatibility-only | `len`, `id`, `frag`, `proto`, `chksum`, and `ip_option` are public aliases and must remain available. |
| Field getters | `crafter/src/protocols/ip.rs` | partial | Getters expose raw values for version, IHL, header length, TOS, total length, identification, flags, DF/MF, fragment offset, TTL, protocol, checksum, addresses, raw options, option iterator, and parsed options. DSCP, ECN, checksum-status, and option metadata getters are absent. |
| Protocol constants | `crafter/src/protocols/ip.rs` | partial | Constants exist for ICMP, TCP, UDP, IPv6 encapsulation, and ICMPv6 only. The IANA protocol-number registry in `docs/ipv4-rfc-manifest.md` authorizes richer labels/constants later. |
| `IpProtocol` enum | `crafter/src/protocols/ip.rs` | partial | Variants cover Hop-by-Hop, ICMP, TCP, UDP, IPv6 encapsulation, and ICMPv6. No registry-wide enum, classifier, or label helper is public yet. |
| Flag constants | `crafter/src/protocols/ip.rs` | implemented | `IPV4_FLAG_RESERVED`, `IPV4_FLAG_DONT_FRAGMENT`, and `IPV4_FLAG_MORE_FRAGMENTS` exist. |
| Option constants | `crafter/src/protocols/ip.rs` | partial | Constants exist for EOL, NOP, Record Route, Traceroute, Loose Source Route, and Strict Source Route. Timestamp, Router Alert, experiment, and registry metadata constants/helpers are missing. |
| Option types | `crafter/src/protocols/ip.rs` | partial | `Ipv4Option` supports EOL, NOP, Generic, route-style options, and RFC 1393 Traceroute. Router Alert, Timestamp, copied/class/number metadata, and experiment helpers are not typed yet. |
| Public re-exports | `crafter/src/protocols/mod.rs`, `crafter/src/lib.rs` | implemented | `Ipv4`, `IpProtocol`, `Ipv4Option`, `Ipv4OptionIter`, `Ipv4RouteOptionKind`, current constants, and flags/options are re-exported through protocol, root, core, and prelude surfaces. New helpers must be added to these same paths. |

## Compile Defaults And Override Behavior

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| Builder defaults | `crafter/src/protocols/ip.rs` | implemented | Defaults are version 4, raw TOS/DS byte 0, deterministic Identification 1, flags 0, fragment offset 0, TTL 64, protocol 0, source/destination loopback, unset IHL, unset total length, unset checksum, and no options. The Identification default is reproducible packet-builder state, not a global IPv4 ID generator. |
| IHL fill | `crafter/src/protocols/ip.rs` | implemented | When unset, IHL is derived from the fixed header plus option bytes padded to a 32-bit boundary. Explicit IHL changes the compiled header length. |
| Total length fill | `crafter/src/protocols/ip.rs` | partial | When unset, total length is derived from effective header length plus following layer encoded lengths. Explicit total length is preserved only after validation; values shorter than the effective header are rejected. |
| Protocol fill | `crafter/src/protocols/ip.rs` | partial | When unset, protocol is inferred from next `Tcp`, `Udp`, or `Icmpv4` layer. Other next layers default to protocol 0 unless explicitly set. |
| Identification fill | `crafter/src/protocols/ip.rs` | implemented | When unset, compile uses the deterministic builder default value `1`. Explicit `.identification(...)` and `.id(...)` overrides are preserved exactly. The crate does not allocate unique IDs across source/destination/protocol tuples and does not enforce RFC 6864 non-atomic datagram rate or uniqueness requirements. |
| Checksum fill | `crafter/src/protocols/ip.rs` | implemented | Compile writes zero into the checksum field, computes the IPv4 header checksum, then writes it unless the caller set an explicit checksum. |
| Option padding | `crafter/src/protocols/ip.rs` | implemented | Raw option bytes are appended and the compiled header is padded with zero bytes to the effective IHL. |
| Explicit checksum override | `crafter/src/protocols/ip.rs` | implemented | Explicit `checksum`/`chksum` values survive compile, including intentionally invalid checksums. |
| Explicit malformed fields | `crafter/src/protocols/ip.rs` | partial | The current validator rejects non-4 versions, IHL below 5 or above 15, too-long options, flags outside 3 bits, fragment offset outside 13 bits, and total length shorter than the header. The manifest calls for preserving explicit malformed values that fit their wire fields, so later steps need to reconcile these current guardrails with malformed-packet construction requirements. |

## TTL Behavior

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| TTL source and default | `docs/ipv4-rfc-manifest.md`, `crafter/src/protocols/ip.rs` | implemented | RFC 791 defines TTL as the IPv4 datagram lifetime bound, RFC 1122 requires hosts not to send TTL zero and to make TTL settable, and IANA IPv4 Parameters records the current recommended default TTL as 64. `Ipv4::new()` currently uses TTL 64. |
| TTL override and preservation | `crafter/src/protocols/ip.rs` | implemented | Builders and getters expose TTL. Compile writes the configured TTL byte and preserves explicit caller values rather than deriving TTL from routing or host stack state. |
| TTL forwarding semantics | none | out of scope | `crafter` does not implement routing and does not decrement TTL during compile or decode. Route selection, forwarding, gateway TTL expiration, ICMP Time Exceeded generation caused by forwarding, and hop-by-hop checksum recomputation after TTL decrement are not crate primitive responsibilities. |

## Decode Behavior

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| L3 IPv4 entrypoint | `crafter/src/registry.rs`, `crafter/src/protocols/ip.rs` | implemented | `Packet::decode_from_l3(NetworkLayer::Ipv4, ...)` reaches `ProtocolRegistry::decode_ipv4`, then `append_ipv4_packet_with_registry`. |
| Link-layer IPv4 dispatch | `crafter/src/registry.rs` | implemented | Built-in Ethernet/VLAN/Linux cooked/null-loopback paths dispatch Ethertype or link protocol values to IPv4 decode where appropriate. |
| Header validation | `crafter/src/protocols/ip.rs` | implemented | Decode returns structured errors for a truncated fixed header, non-4 version, IHL below 5, header truncation, total length shorter than header length, packet truncation, and malformed option envelopes. |
| Field preservation | `crafter/src/protocols/ip.rs` | implemented | Decoded header fields are stored as user-set field values, including raw TOS/DS byte, total length, ID, flags, fragment offset, TTL, protocol, checksum, addresses, and options. |
| Total-length boundary | `crafter/src/protocols/ip.rs` | implemented | Payload is sliced from header length to IPv4 total length. Bytes after total length are appended as a following `Raw` layer. |
| Unknown protocols | `crafter/src/registry.rs` | implemented | If no IPv4 protocol binding matches, remaining payload bytes are preserved as `Raw`. |
| Built-in protocol dispatch | `crafter/src/registry.rs` | partial | Built-ins dispatch ICMP, TCP, and UDP. Application decode can continue from UDP/TCP through registry bindings. The registry does not yet expose IANA labels or richer protocol classification. |
| Fragment-aware dispatch | `crafter/src/protocols/ip.rs`, `crafter/src/registry.rs` | gap | `decode_ipv4_protocol` receives only the protocol number and payload. It does not know the IPv4 fragment offset or MF flag, so non-initial fragments are not forced to `Raw` before transport decode. |
| Quoted IPv4 in ICMPv4 errors | `crafter/src/protocols/ip.rs`, `crafter/src/protocols/icmp/decode.rs` | implemented | `decode_quoted_ipv4` leniently types parseable quoted IPv4 headers and uses a transport-only registry so truncated ICMP quotes can keep transport headers inspectable without requiring full application payloads. |

## Checksum Behavior

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| Compile-time header checksum | `crafter/src/protocols/ip.rs`, `crafter/src/checksum.rs` | implemented | Compile-time checksum fill is in place and covered by unit tests in `crafter/src/protocols/ip.rs`. |
| Explicit checksum preservation | `crafter/src/protocols/ip.rs` | implemented | Explicit checksums are preserved during compile and can intentionally make the header checksum invalid. |
| Decode-time checksum value | `crafter/src/protocols/ip.rs` | implemented | Decode stores the checksum word and exposes it through `checksum_value()`. |
| Decode-time checksum status | `crafter/src/protocols/ip.rs` | gap | There is no `Ipv4` checksum status API, no status field in `summary()` or `show()`, and no stored distinction between valid and invalid decoded headers. Unit tests verify a fixture externally with `verify_internet_checksum`, but the packet remains unable to report status itself. |

## Options

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| Raw option bytes | `crafter/src/protocols/ip.rs` | implemented | Builders can append raw bytes, replace all option bytes, clear option bytes, and return raw option bytes. |
| Option iterator | `crafter/src/protocols/ip.rs` | implemented | `Ipv4OptionIter` handles EOL, NOP, kind/length options, length underflow, and length overrun without panics. |
| Generic options | `crafter/src/protocols/ip.rs` | partial | Unknown non-EOL/NOP options decode as `Generic { kind, data }`, preserving bytes after the kind and length. Generic options do not expose copied flag, class, number, registry status, or experiment classification. |
| Route options | `crafter/src/protocols/ip.rs` | implemented | Record Route, Loose Source Route, and Strict Source Route encode/decode through `Ipv4RouteOptionKind`, pointer validation, and whole-IPv4-address payload checks. |
| Traceroute option | `crafter/src/protocols/ip.rs` | implemented | RFC 1393 Traceroute option encodes and decodes the 12-byte layout. |
| Router Alert | `crafter/src/protocols/ip.rs` | gap | `docs/ipv4-rfc-manifest.md` lists RFC 2113 and IANA Router Alert values, but no typed Router Alert option exists yet. |
| Timestamp | `crafter/src/protocols/ip.rs` | gap | The manifest records Timestamp as source-backed future work. No typed Timestamp option exists yet. |
| Experiment option helpers | `crafter/src/protocols/ip.rs` | gap | RFC 4727 experiment option values are not exposed or classified yet. |
| Malformed option errors | `crafter/src/protocols/ip.rs`, `crafter/tests/resilience.rs` | implemented | Option envelope errors are structured and covered by the malformed corpus, including direct `ipv4-options` decode. |

## Fragmentation Fields

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| Identification field | `crafter/src/protocols/ip.rs` | implemented | Builder, `.id(...)` alias, getter, compile, decode, and inspection support exist. The field is exposed and preserved as a 16-bit header value. |
| Flags field | `crafter/src/protocols/ip.rs` | implemented | Raw flags, reserved bit constant, DF helper/getter, MF helper/getter, compile, decode, and summary formatting exist. |
| Fragment offset field | `crafter/src/protocols/ip.rs` | implemented | Builder, alias, getter, compile, decode, and validation for 13-bit range exist. |
| RFC 6864 atomic datagram semantics | `crafter/src/protocols/ip.rs` | partial | Current helpers expose DF, MF, fragment offset, and `is_fragmented()` for headers that already carry fragment metadata. RFC 6864's atomic datagram test also requires DF=1, so generated tools should use the raw helpers when that distinction matters. No ID meaning is inferred for atomic datagrams. |
| Global Identification generation | none | out of scope | RFC 6864 leaves non-atomic datagram uniqueness with datagram sources. `crafter` is a packet primitive: it does not maintain per-tuple counters, choose live-safe IDs, rate-limit non-atomic output, or coordinate IDs for reassembly. |
| Fragment generation | none | out of scope | The manifest excludes automatic fragmentation. No crate fragmenter should be added. |
| Fragment reassembly | none | out of scope | The manifest excludes reassembly, caches, timers, overlap policy, and stack delivery. No reassembly module should be added. |
| Non-initial fragment decode policy | `crafter/src/protocols/ip.rs`, `crafter/src/registry.rs` | gap | The manifest requires non-initial IPv4 fragments to keep payload as `Raw`; current dispatch is protocol-only and can attempt transport decode. |

## Fixture Coverage

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| Fixture catalog | `crafter/tests/fixture_suite.rs` | implemented | The fixture suite lists IPv4 coverage families and asserts required families are present. |
| L3 IPv4 ICMP fixture | `crafter/tests/fixtures/bytes/ipv4-icmp-echo-request.bin`, `crafter/tests/fixture_suite.rs` | implemented | Exercises IPv4 decode from L3 with ICMP and raw payload. Also used by IPv4 unit tests in `crafter/src/protocols/ip.rs`. |
| ICMP error with quoted IPv4 | `crafter/tests/fixtures/bytes/ipv4-icmp-destination-unreachable.hex`, `crafter/tests/fixture_suite.rs` | implemented | Exercises IPv4 plus ICMP error handling and quoted original data behavior. |
| IPv4 options fixture | `crafter/tests/fixtures/bytes/ipv4-options-traceroute-udp-raw.hex`, `crafter/tests/fixture_suite.rs` | implemented | Exercises route/traceroute option decode plus UDP/raw payload. |
| IPv4/TCP fixtures | `crafter/tests/fixtures/bytes/ipv4-tcp-syn-options.hex`, `crafter/tests/fixtures/bytes/ipv4-tcp-syn-rich-options.hex`, `crafter/tests/fixture_suite.rs` | implemented | Exercise IPv4 as a TCP envelope with summary snapshots. |
| IPv4/UDP/DNS fixtures | `crafter/tests/fixtures/bytes/ipv4-udp-dns-*.hex`, `crafter/tests/fixture_suite.rs` | implemented | Exercise IPv4 as a UDP/DNS envelope across queries, responses, DNSSEC, SVCB/HTTPS, EDNS(0), unknown records, and section placement. |
| IPv4/UDP/DHCP fixture | `crafter/tests/fixtures/bytes/ipv4-udp-dhcp-discover.hex`, `crafter/tests/fixture_suite.rs` | implemented | Exercises IPv4 as a UDP/DHCP envelope. |
| IPv4/UDP options fixtures | `crafter/tests/fixtures/bytes/ipv4-udp-options-known.hex`, `crafter/tests/fixtures/bytes/ipv4-udp-options-unknown-safe.hex`, `crafter/tests/fixture_suite.rs` | implemented | Exercise IPv4 as a UDP-options envelope, not IPv4 options. |
| Link wrappers with IPv4 payloads | `crafter/tests/fixtures/bytes/ethernet-vlan-ipv4-udp-raw.bin`, `crafter/tests/fixtures/bytes/null-loopback-ipv4-udp-raw.hex`, `crafter/tests/fixture_suite.rs` | implemented | Exercise link-layer dispatch into IPv4. |
| Pcap coverage | `crafter/tests/fixtures/pcaps/raw-ipv4-icmp-echo-request.pcap`, `crafter/tests/fixtures/pcaps/null-loopback-ipv4-udp-raw.pcap`, `crafter/tests/fixture_suite.rs` | implemented | Classic pcap coverage includes RawIp IPv4 and null-loopback IPv4 payloads. |
| IPv4-specific enrichment fixtures | `crafter/tests/fixtures/bytes/`, `crafter/tests/fixtures/summaries/`, `crafter/tests/fixtures/pcaps/` | gap | Dedicated fixtures are still needed for DSCP/ECN helpers, checksum-status display, unknown protocol labels, total-length trailing bytes, non-initial fragments, Router Alert, Timestamp, and malformed option variants added by later steps. |

## Malformed Corpus Coverage

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| Malformed corpus rows | `crafter/tests/fixtures/malformed/core-decode-corpus.hex` | implemented | Current IPv4 rows cover short IPv4 header, bad version, bad IHL, total length shorter than header, option length overrun through IPv4 decode, and direct option decoder overrun. |
| Malformed corpus runner | `crafter/tests/resilience.rs` | implemented | The resilience runner maps `ipv4` to `Packet::decode_from_l3(NetworkLayer::Ipv4, ...)` and `ipv4-options` to `Ipv4Option::decode_all(...)`. |
| Required IPv4 malformed families | `crafter/tests/resilience.rs` | implemented | Required families include short IPv4, bad IPv4 version, bad IPv4 IHL, short IPv4 total length, and IPv4 option overrun. |
| Additional enrichment malformed cases | `crafter/tests/fixtures/malformed/core-decode-corpus.hex`, `crafter/tests/resilience.rs` | gap | Later steps should add cases for checksum-status inspection if represented as status rather than hard error, malformed typed Router Alert/Timestamp options, total-length trailing-byte preservation, and fragment-dispatch policy where applicable. |

## Public Re-exports

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| Protocol module exports | `crafter/src/protocols/mod.rs` | implemented | Re-exports current IPv4 layer, protocol enum, option enum/iterator/kind, protocol constants, flag constants, and option constants. |
| Root crate exports | `crafter/src/lib.rs` | implemented | Re-exports the same current IPv4 names through the root crate and `core`; `prelude` inherits `core`. |
| New public helpers | `crafter/src/protocols/mod.rs`, `crafter/src/lib.rs` | gap | Future DSCP/ECN helpers, protocol labels/constants, checksum status, and typed option helpers must be re-exported here so generated tools using `crafter::prelude::*` can reach them. |

## Documentation Gaps

| Item | Current location | Status | Notes |
| --- | --- | --- | --- |
| Source manifest | `docs/ipv4-rfc-manifest.md` | implemented | The source-backed authority file exists and should be updated when later behavior depends on additional RFC, IANA, Datatracker, or errata evidence. |
| IPv4 user guide | `docs/ipv4.md` | gap | No dedicated user-facing IPv4 guide exists yet. Later docs should cover DSCP/ECN, protocol numbers, checksum status, options, fragmentation fields, decode policy, and explicit live/offline boundaries. |
| Docs index | `docs/README.md` | gap | The docs index does not link an IPv4 guide yet. |
| API guide | `docs/api.md` | partial | The API guide shows basic `Ipv4` composition and decode, but not the enriched IPv4 behavior planned here. |
| Repository README | `README.md` | partial | The README mentions IPv4 and IPv4 options in the broad protocol list and basic packet construction, but not the planned enriched IPv4 surface. |
| Agent cookbook | `.agents/docs/cookbook.md` | out of scope for this file | Operating guidance for generated tools belongs in the agent cookbook, not in user-facing crate docs. |

## Priority Gap Map For Later Steps

1. **Public baseline tests** - add tests under `crafter/tests/ipv4_public_api.rs`
   proving current `prelude`, root, `core`, and `protocols` paths remain usable.
2. **DSCP and ECN helpers** - update `crafter/src/protocols/ip.rs`, then
   re-export through `crafter/src/protocols/mod.rs` and `crafter/src/lib.rs`.
3. **Protocol-number labels and constants** - expand IANA-backed protocol
   support in `crafter/src/protocols/ip.rs`; update `summary()`/`show()` output
   and public re-exports.
4. **Checksum status** - add decode-time status to `Ipv4` in
   `crafter/src/protocols/ip.rs` and pin it in unit tests, fixture summaries,
   and docs.
5. **Length and boundary behavior** - add focused tests for explicit total
   length, trailing bytes after total length, option padding, and override
   preservation in `crafter/src/protocols/ip.rs` and `crafter/tests/fixture_suite.rs`.
6. **Fragment-aware decode** - update `crafter/src/protocols/ip.rs` and likely
   `crafter/src/registry.rs` so non-initial IPv4 fragments keep payload as
   `Raw` without transport dispatch.
7. **Typed options** - add Router Alert, Timestamp, option metadata, and
   experiment helpers in `crafter/src/protocols/ip.rs`, with malformed corpus
   rows in `crafter/tests/fixtures/malformed/core-decode-corpus.hex`.
8. **Fixture and pcap coverage** - add deterministic fixtures and summaries
   under `crafter/tests/fixtures/bytes/`,
   `crafter/tests/fixtures/summaries/`, and `crafter/tests/fixtures/pcaps/`,
   cataloged in `crafter/tests/fixture_suite.rs`.
9. **User docs** - add `docs/ipv4.md` and link it from `docs/README.md`,
   `docs/api.md`, and `README.md`, citing `docs/ipv4-rfc-manifest.md`.
