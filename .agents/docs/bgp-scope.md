# BGP-4 scope and feature matrix

The shared definition of "fully implemented" for BGP-4 in the `crafter` crate.
Each in-scope row below names the RFC that defines it and the plan step that
delivers it; a feature is done only when its step's acceptance gate passes. This
matrix is derived from `spec.md` and the codepoint authority in
[`bgp-codepoints.md`](bgp-codepoints.md) and
[`bgp-manifest.md`](bgp-manifest.md).

`crafter` is a wire-level primitive. The matrix scopes message construction,
compilation, decoding, `summary()`/`show()`, golden fixtures, oracle validation,
and live session establishment. It deliberately excludes the BGP state machine,
the routing information base, and the decision process: those are agent-built
tools, not crate surface.

Step numbers reference the files under
`.clew/plans/implement-bgp-protocol-live-tests/`.

## In scope (build + decode + golden + oracle)

### Message types

| Feature | Codepoint | RFC | Step(s) |
| --- | --- | --- | --- |
| KEEPALIVE | `MSG_TYPE_KEEPALIVE = 4` | RFC 4271 §4.4 | 09-13 |
| OPEN | `MSG_TYPE_OPEN = 1` | RFC 4271 §4.2 | 14-22 |
| NOTIFICATION | `MSG_TYPE_NOTIFICATION = 3` | RFC 4271 §4.5, §6 | 23-25, 27 |
| ROUTE-REFRESH | `MSG_TYPE_ROUTE_REFRESH = 5` | RFC 2918; RFC 7313 | 26, 28 |
| UPDATE | `MSG_TYPE_UPDATE = 2` | RFC 4271 §4.3 | 29-42 |

The 19-octet message header (marker, length, type) and KEEPALIVE establish the
layer trait and shared framing (steps 09-13). NOTIFICATION carries the full
error-code/subcode set from `bgp-codepoints.md` (RFC 4271 §6, RFC 4486, RFC 6608,
RFC 7313, RFC 8538, RFC 9003, RFC 9384). ROUTE-REFRESH carries the
`AFI | Subtype/Reserved | SAFI` body and the NORMAL/BoRR/EoRR subtypes
(RFC 2918, RFC 7313).

### Path attributes

| Feature | Codepoint | RFC | Step(s) |
| --- | --- | --- | --- |
| Attribute framing (flags/type/length/extended-length) | `ATTR_FLAG_*` | RFC 4271 §4.3 | 30 |
| NLRI / withdrawn-route prefix codec | — | RFC 4271 §4.3 | 29 |
| ORIGIN | `ATTR_ORIGIN = 1` | RFC 4271 §5.1.1 | 32 |
| AS_PATH | `ATTR_AS_PATH = 2` | RFC 4271 §5.1.2 | 33 |
| NEXT_HOP | `ATTR_NEXT_HOP = 3` | RFC 4271 §5.1.3 | 34 |
| MULTI_EXIT_DISC | `ATTR_MULTI_EXIT_DISC = 4` | RFC 4271 §5.1.4 | 35 |
| LOCAL_PREF | `ATTR_LOCAL_PREF = 5` | RFC 4271 §5.1.5 | 35 |
| ATOMIC_AGGREGATE | `ATTR_ATOMIC_AGGREGATE = 6` | RFC 4271 §5.1.6 | 36 |
| AGGREGATOR | `ATTR_AGGREGATOR = 7` | RFC 4271 §5.1.7 | 36 |
| COMMUNITIES | `ATTR_COMMUNITIES = 8` | RFC 1997 | 43-44 |
| EXTENDED COMMUNITIES | `ATTR_EXTENDED_COMMUNITIES = 16` | RFC 4360 | 45-46 |
| LARGE COMMUNITIES | `ATTR_LARGE_COMMUNITY = 32` | RFC 8092 | 47-48 |
| MP_REACH_NLRI | `ATTR_MP_REACH_NLRI = 14` | RFC 4760 §3 | 49, 51-52 |
| MP_UNREACH_NLRI | `ATTR_MP_UNREACH_NLRI = 15` | RFC 4760 §4 | 50-52 |
| AS4_PATH | `ATTR_AS4_PATH = 17` | RFC 6793 §3 | 53-54 |
| AS4_AGGREGATOR | `ATTR_AS4_AGGREGATOR = 18` | RFC 6793 §3 | 53-54 |

UPDATE struct, `compile()`, decode, and `summary()` that assemble the well-known
attributes and NLRI into a message are steps 37-39, with golden announce/withdraw
and unknown-attribute round-trip fixtures at steps 40-42. MP-BGP carries
`<AFI_IPV4, SAFI_UNICAST>` and `<AFI_IPV6, SAFI_UNICAST>` (RFC 4760, IPv6 per
RFC 2545). Unknown optional attributes round-trip verbatim (RFC 4271 §5).

### Capabilities (OPEN optional parameters)

| Feature | Codepoint | RFC | Step(s) |
| --- | --- | --- | --- |
| OPEN optional parameters / capability framing | `OPT_PARAM_CAPABILITIES = 2` | RFC 5492 §4 | 16-17 |
| MP-BGP (Multiprotocol) | `CAP_MULTIPROTOCOL = 1` | RFC 4760 §8 | 18 |
| Route-Refresh | `CAP_ROUTE_REFRESH = 2` | RFC 2918 | 19 |
| 4-octet ASN | `CAP_FOUR_OCTET_AS = 65` | RFC 6793 | 19 |
| Graceful Restart | `CAP_GRACEFUL_RESTART = 64` | RFC 4724 | 19 |
| ADD-PATH | `CAP_ADD_PATH = 69` | RFC 7911 | 19 |

OPEN struct and `compile()` (version, AS / AS_TRANS, hold time, BGP identifier)
are steps 14-15; OPEN decode, `summary()`, and golden fixture are steps 20-22.
Unknown capability codes round-trip verbatim (RFC 5492 §5).

### Behaviors

| Feature | RFC / spec basis | Step(s) |
| --- | --- | --- |
| Malformed / edge handling (bad marker, length < 19 or > 4096, length mismatch, truncated/zero-length attribute, NLRI overrun, trailing octets) | RFC 4271 §4.1, §6.1; spec Edge Cases | 63-67 |
| Override of auto-filled fields to emit deliberately wrong bytes | CLAUDE.md "honored overrides"; spec Requirements | 66 |
| BGP-bearing TCP stream decode (pipelined messages as stacked layers, partial tail preserved as raw) | spec Requirements; RFC 4271 §4.1 | 55, 57 |
| TCP/179 registry dispatch (source or destination port) | spec Requirements; RFC 4271 §1 (BGP_PORT = 179) | 56 |
| Golden hex / summary / pcap fixture suite | spec Acceptance | 58-62 |
| Oracle validation (layer + feature specs, profiles, scapy backend, libcrafter adapter, offline + pcap runs) | spec Acceptance | 68-74 |
| Live session establishment + documentation-prefix announcement against a real peer | spec Acceptance | 75-82 |

Live work uses disposable lab/endpoint providers (QEMU step 79, VirtualBox step
80, Hetzner step 81) with offline dry-run plans first (steps 75, 78); the final
docs and release gate is step 82. All examples, tests, and defaults use
documentation address space.

## Out of scope (state, not wire)

These are routing-control-plane state and analysis concerns. They are not
wire-construction primitives and are intentionally excluded; agents build them as
tools on top of `crafter`.

| Excluded item | Why excluded |
| --- | --- |
| BGP finite state machine (FSM) | Connection/session state (RFC 4271 §8); the crate emits and decodes messages, it does not drive sessions. |
| RIB storage (Adj-RIB-In/Loc-RIB/Adj-RIB-Out) | Route storage and bookkeeping (RFC 4271 §3.2). |
| Best-path / decision process | Route selection (RFC 4271 §9). |
| Route reflection | Topology state and ORIGINATOR_ID/CLUSTER_LIST processing (RFC 4456); attributes are preserved verbatim only. |
| Confederations | AS_CONFED_* segment processing semantics (RFC 5065); segment types are preserved verbatim only. |
| BMP (BGP Monitoring Protocol) | Separate monitoring protocol (RFC 7854). |
| BGP-LS (Link-State) | Separate NLRI family / use case (RFC 7752). |
| FlowSpec | Separate NLRI family / use case (RFC 8955). |
| MRT | Routing-information export file format (RFC 6396). |
| TCP-AO / TCP-MD5 | Transport authentication (RFC 5925 / RFC 2385); outside the BGP message layer. |

## Deferred (note only)

| Deferred item | Note |
| --- | --- |
| Graceful Restart restart procedures | Only the Graceful Restart **capability** advertisement (`CAP_GRACEFUL_RESTART = 64`, RFC 4724) is in scope (step 19). The restart timing/forwarding-state procedures that depend on the FSM are deferred, consistent with the out-of-scope FSM exclusion. |
