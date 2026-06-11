# BGP-4 Codepoint Manifest

Source-backed codepoint authority for the `crafter` BGP-4 layer. Later steps
(constants, specs, fixtures, tests) **must** cite this manifest rather than model
memory for wire-level facts. Each codepoint below is annotated with its defining
RFC; values were taken from the authoritative IANA "BGP Parameters" registry
family and confirmed against RFC text, not from recollection.

## Provenance

Evidence was gathered through the repo's `rfc-protocol-bootstrap` skill, which
opts into the canonical evidence corpus at `/home/e/practicas/rfc-protocol-spec/`
(`python -m proto discover|graph|classify|extract|manifest BGP`). That tooling
confirmed the authoritative BGP RFC set and document relationships (RFC 4271 is
the current BGP-4 core; RFC 4760 obsoletes RFC 2858; RFC 6793 obsoletes RFC 4893
and updates RFC 4271; RFC 5492 is the capability-advertisement umbrella). The
corpus does not cache the BGP IANA registry XML or extract per-codepoint values,
so the actual numeric codepoints were fetched directly from the authoritative
IANA registries and cross-checked against the RFC text:

- IANA "BGP Parameters" — <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xml>
  (sub-registries: Message Types, Path Attributes, Error/Notification Codes and
  all subcode registries, OPEN Optional Parameter Types, Route Refresh Subcodes)
- IANA "Capability Codes" — <https://www.iana.org/assignments/capability-codes/capability-codes.xml>
- IANA "BGP Extended Communities" — <https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xml>
- IANA "Address Family Numbers" (AFI) — <https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xml>
- IANA "SAFI Values" — <https://www.iana.org/assignments/safi-namespace/safi-namespace.xml>
- RFC text: RFC 4271, RFC 2918, RFC 1997, RFC 4360, RFC 8092, RFC 4760, RFC 6793,
  RFC 5492 (fetched from rfc-editor.org and quoted by section below).

"Defining RFC" reflects the IANA `xref` for each row. Where IANA cites an
obsoleted document (e.g. RFC 2858 for capability code 1), the current obsoleting
RFC is noted in parentheses because the crate should cite the live spec.

## Message header structure (RFC 4271 §4.1)

Constants for later code (`constants.rs`):

| Constant | Value | Source |
| --- | --- | --- |
| Marker length | 16 octets (all-ones default) | RFC 4271 §4.1 |
| Header length (marker + length + type) | 19 octets | RFC 4271 §4.1 ("BGP header without a data portion (19 octets)") |
| Maximum message size | 4096 octets | RFC 4271 §4.1 ("the maximum message size is 4096") |
| BGP version | 4 | RFC 4271 §4.2 |
| Default port | TCP 179 | RFC 4271 §1 / IANA service registry |
| Minimum OPEN length | 29 octets | RFC 4271 §4.2 |
| Minimum UPDATE length | 23 octets | RFC 4271 §4.3 |
| Minimum NOTIFICATION length | 21 octets | RFC 4271 §4.5 |
| KEEPALIVE length | 19 octets (header only) | RFC 4271 §4.4 |
| AS_TRANS | 23456 | RFC 6793 §9 |

## Message Types (IANA `bgp-parameters-1`)

| Type | Name | Defining RFC |
| --- | --- | --- |
| 0 | Reserved | — |
| 1 | OPEN | RFC 4271 |
| 2 | UPDATE | RFC 4271 |
| 3 | NOTIFICATION | RFC 4271 |
| 4 | KEEPALIVE | RFC 4271 |
| 5 | ROUTE-REFRESH | RFC 2918 |
| 6-255 | Unassigned | — |

## OPEN Optional Parameter Types (IANA `bgp-parameters-11`)

| Type | Name | Defining RFC |
| --- | --- | --- |
| 0 | Reserved | RFC 5492 |
| 1 | Authentication (deprecated) | RFC 4271 / RFC 5492 |
| 2 | Capabilities | RFC 5492 |
| 3-254 | Unassigned | — |
| 255 | Extended Length | RFC 9072 |

The Capabilities optional parameter (type 2) carries one or more
`<Capability Code (1), Capability Length (1), Capability Value (variable)>`
triples (RFC 5492 §4). In scope: parameter type 2 only.

## Capability Codes (IANA `capability-codes-2`)

| Code | Name | Defining RFC | In scope |
| --- | --- | --- | --- |
| 0 | Reserved | RFC 5492 | — |
| 1 | Multiprotocol Extensions for BGP-4 (MP-BGP) | RFC 2858 (obsoleted by RFC 4760) | yes |
| 2 | Route Refresh Capability for BGP-4 | RFC 2918 | yes |
| 64 | Graceful Restart Capability | RFC 4724 | yes |
| 65 | Support for 4-octet AS number capability | RFC 6793 | yes |
| 69 | ADD-PATH Capability | RFC 7911 | yes |
| 70 | Enhanced Route Refresh Capability | RFC 7313 | preserve only |
| 128 | Prestandard Route Refresh (deprecated) | RFC 8810 | preserve only |

Notes on codepoints called out by the step:

- **Route-Refresh "2/128"**: The standardized Route-Refresh capability code is
  **2** (RFC 2918). Code **128** is the *prestandard* Route-Refresh capability
  (RFC 8810, "Prestandard Route Refresh (deprecated)"); some legacy speakers
  advertise it. The crate advertises 2 and preserves 128 verbatim if received.
- **MP-BGP capability value (code 1)** is 4 octets: `AFI(2) | Reserved(1) | SAFI(1)`
  (RFC 4760 §8, "The Capability Length field is set to 4").
- **4-octet ASN capability (code 65)** value is the speaker's 4-octet AS number
  (RFC 6793 §3).
- Unknown capability codes MUST round-trip verbatim (RFC 5492 §5).

## Path Attribute Type Codes (IANA `bgp-parameters-2`)

| Type | Name | Defining RFC | In scope |
| --- | --- | --- | --- |
| 1 | ORIGIN | RFC 4271 | yes (well-known mandatory) |
| 2 | AS_PATH | RFC 4271 | yes (well-known mandatory) |
| 3 | NEXT_HOP | RFC 4271 | yes (well-known mandatory) |
| 4 | MULTI_EXIT_DISC (MED) | RFC 4271 | yes (optional non-transitive) |
| 5 | LOCAL_PREF | RFC 4271 | yes (well-known discretionary) |
| 6 | ATOMIC_AGGREGATE | RFC 4271 | yes (well-known discretionary) |
| 7 | AGGREGATOR | RFC 4271 | yes (optional transitive) |
| 8 | COMMUNITIES | RFC 1997 | yes |
| 9 | ORIGINATOR_ID | RFC 4456 | preserve only |
| 10 | CLUSTER_LIST | RFC 4456 | preserve only |
| 14 | MP_REACH_NLRI | RFC 4760 | yes |
| 15 | MP_UNREACH_NLRI | RFC 4760 | yes |
| 16 | EXTENDED COMMUNITIES | RFC 4360 | yes |
| 17 | AS4_PATH | RFC 6793 | yes |
| 18 | AS4_AGGREGATOR | RFC 6793 | yes |
| 32 | LARGE_COMMUNITY | RFC 8092 | yes |
| 255 | Reserved for development | RFC 2042 | — |

Type codes not listed above (11-13, 19-31, 33-42, 128-243, etc.) exist in the
IANA registry but are out of scope for the minimal layer; decode preserves them
as `Unknown(flags, type, bytes)`.

### Path attribute flag semantics (RFC 4271 §4.3)

The Attribute Flags octet high-order bits (bit 0 = most significant):

| Bit | Mask | Name | Meaning | Source |
| --- | --- | --- | --- | --- |
| 0 | 0x80 | Optional | 1 = optional, 0 = well-known | RFC 4271 §4.3 |
| 1 | 0x40 | Transitive | 1 = transitive, 0 = non-transitive (well-known MUST be 1) | RFC 4271 §4.3 |
| 2 | 0x20 | Partial | 1 = partial, 0 = complete (well-known & optional non-transitive MUST be 0) | RFC 4271 §4.3 |
| 3 | 0x10 | Extended Length | 0 = length is 1 octet, 1 = length is 2 octets | RFC 4271 §4.3 |
| 4-7 | 0x0F | Unused | MUST be 0 on send, ignored on receive | RFC 4271 §4.3 |

Attribute framing: `Flags(1) | Type Code(1) | Length(1 or 2) | Value(Length)`.
Extended-length is selected by flag bit 3; the builder chooses extended length
automatically when a value exceeds 255 octets unless the caller overrides
(per plan).

### ORIGIN attribute values (type 1, RFC 4271 §5.1.1)

| Value | Meaning | Source |
| --- | --- | --- |
| 0 | IGP | RFC 4271 §4.3 / §5.1.1 |
| 1 | EGP | RFC 4271 §4.3 / §5.1.1 |
| 2 | INCOMPLETE | RFC 4271 §4.3 / §5.1.1 |

### AS_PATH segment types (type 2, RFC 4271 §4.3 / §5.1.2)

Each segment is `<segment type(1), segment length(1, count of ASes), segment value>`.

| Value | Segment Type | Source |
| --- | --- | --- |
| 1 | AS_SET (unordered) | RFC 4271 §4.3 |
| 2 | AS_SEQUENCE (ordered) | RFC 4271 §4.3 |
| 3 | AS_CONFED_SEQUENCE | RFC 5065 |
| 4 | AS_CONFED_SET | RFC 5065 |

AS numbers in AS_PATH are 2 octets unless 4-octet-AS capability is negotiated, in
which case they are 4 octets (RFC 6793 §4). AS_PATH/AS4_PATH have identical
encoding except AS4_PATH always carries 4-octet ASes and is optional-transitive
(RFC 6793 §3). AS_CONFED_SEQUENCE/AS_CONFED_SET MUST NOT appear in AS4_PATH
(RFC 6793 §3).

### AGGREGATOR / AS4_AGGREGATOR (types 7 / 18)

AGGREGATOR (type 7, RFC 4271): `AS(2) | BGP identifier(4)`. AS4_AGGREGATOR
(type 18, RFC 6793 §3): `AS(4) | BGP identifier(4)`; same semantics, 4-octet AS.

## Communities, Extended Communities, Large Communities

### COMMUNITIES (type 8, RFC 1997)

A community is a 4-octet value; the attribute is a list of 4-octet communities.
Reserved well-known communities (RFC 1997, "well-known communities"):

| Value | Name | Source |
| --- | --- | --- |
| 0xFFFFFF01 | NO_EXPORT | RFC 1997 |
| 0xFFFFFF02 | NO_ADVERTISE | RFC 1997 |
| 0xFFFFFF03 | NO_EXPORT_SUBCONFED | RFC 1997 |

Ranges 0x00000000-0x0000FFFF and 0xFFFF0000-0xFFFFFFFF are reserved (RFC 1997).

### EXTENDED COMMUNITIES (type 16, RFC 4360)

Each extended community is **8 octets**. The high-order octet is the Type field
(with the IANA "transitive" bit: 0x40 of the type high octet distinguishes
transitive vs non-transitive ranges), optionally followed by a Sub-Type octet,
then a 6- or 7-octet value (RFC 4360 §2). The crate models the 8-octet item as
`type_high(1) | type_low/sub-type(1) | value(6)` and preserves the full 8 octets;
the extensive IANA sub-type tables (Two-Octet AS, Four-Octet AS, IPv4-Address,
Opaque, etc.) are out of scope for the minimal layer and round-trip as raw
8-octet items. Defining RFC for the attribute and 8-octet structure: RFC 4360.

### LARGE_COMMUNITY (type 32, RFC 8092)

Each large community is **12 octets**: `Global Administrator(4) | Local Data
Part 1(4) | Local Data Part 2(4)` (RFC 8092 §3). The attribute is a list of
12-octet large communities. IANA assigned the value 32 (RFC 8092 §9).

## Multiprotocol Reachability (RFC 4760)

### MP_REACH_NLRI (type 14, RFC 4760 §3)

```
Address Family Identifier (2 octets)
Subsequent Address Family Identifier (1 octet)
Length of Next Hop Network Address (1 octet)
Network Address of Next Hop (variable)
Reserved (1 octet)         # SNPA-related, set to 0
Network Layer Reachability Information (variable)
```

### MP_UNREACH_NLRI (type 15, RFC 4760 §4)

```
Address Family Identifier (2 octets)
Subsequent Address Family Identifier (1 octet)
Withdrawn Routes (variable)
```

Both are optional non-transitive (RFC 4760 §3-§4). The MP capability (code 1)
and these attributes share the AFI/SAFI codepoints below.

## NLRI / Withdrawn-route prefix encoding (RFC 4271 §4.3)

Each prefix is `<length(1, in bits), prefix(ceil(length/8) octets)>`. Trailing
bits of the last prefix octet beyond `length` are not used. Withdrawn routes and
NLRI use the identical codec; MP-BGP NLRI (RFC 4760) reuses the same prefix shape
under the announced `<AFI, SAFI>`.

## NOTIFICATION Error Codes (IANA `bgp-parameters-3`, RFC 4271 §6)

| Code | Name | Defining RFC |
| --- | --- | --- |
| 0 | Reserved | — |
| 1 | Message Header Error | RFC 4271 |
| 2 | OPEN Message Error | RFC 4271 |
| 3 | UPDATE Message Error | RFC 4271 |
| 4 | Hold Timer Expired | RFC 4271 |
| 5 | Finite State Machine Error | RFC 4271 |
| 6 | Cease | RFC 4271 |
| 7 | ROUTE-REFRESH Message Error | RFC 7313 |
| 8 | Send Hold Timer Expired | RFC 9687 |
| 9 | Loss of LSDB Synchronization | RFC 9815 |

### Message Header Error subcodes (code 1, IANA `bgp-parameters-5`, RFC 4271 §6.1)

| Subcode | Name | Defining RFC |
| --- | --- | --- |
| 0 | Unspecific | — |
| 1 | Connection Not Synchronized | RFC 4271 |
| 2 | Bad Message Length | RFC 4271 |
| 3 | Bad Message Type | RFC 4271 |

### OPEN Message Error subcodes (code 2, IANA `bgp-parameters-6`, RFC 4271 §6.2)

| Subcode | Name | Defining RFC |
| --- | --- | --- |
| 0 | Unspecific | — |
| 1 | Unsupported Version Number | RFC 4271 |
| 2 | Bad Peer AS | RFC 4271 |
| 3 | Bad BGP Identifier | RFC 4271 |
| 4 | Unsupported Optional Parameter | RFC 4271 |
| 5 | [Deprecated] | RFC 4271 |
| 6 | Unacceptable Hold Time | RFC 4271 |
| 7 | Unsupported Capability | RFC 5492 |
| 11 | Role Mismatch | RFC 9234 |

### UPDATE Message Error subcodes (code 3, IANA `bgp-parameters-7`, RFC 4271 §6.3)

| Subcode | Name | Defining RFC |
| --- | --- | --- |
| 0 | Unspecific | — |
| 1 | Malformed Attribute List | RFC 4271 |
| 2 | Unrecognized Well-known Attribute | RFC 4271 |
| 3 | Missing Well-known Attribute | RFC 4271 |
| 4 | Attribute Flags Error | RFC 4271 |
| 5 | Attribute Length Error | RFC 4271 |
| 6 | Invalid ORIGIN Attribute | RFC 4271 |
| 7 | [Deprecated] | RFC 4271 |
| 8 | Invalid NEXT_HOP Attribute | RFC 4271 |
| 9 | Optional Attribute Error | RFC 4271 |
| 10 | Invalid Network Field | RFC 4271 |
| 11 | Malformed AS_PATH | RFC 4271 |

### Finite State Machine Error subcodes (code 5, IANA `bgp-finite-state-machine-error-subcodes`)

| Subcode | Name | Defining RFC |
| --- | --- | --- |
| 0 | Unspecified Error | RFC 6608 |
| 1 | Receive Unexpected Message in OpenSent State | RFC 6608 |
| 2 | Receive Unexpected Message in OpenConfirm State | RFC 6608 |
| 3 | Receive Unexpected Message in Established State | RFC 6608 |

RFC 4271 §6.5 defines code 5 (Finite State Machine Error) with subcode 0; the
granular subcodes 1-3 were added by RFC 6608.

### Cease NOTIFICATION subcodes (code 6, IANA `bgp-parameters-8`)

| Subcode | Name | Defining RFC |
| --- | --- | --- |
| 0 | Reserved | — |
| 1 | Maximum Number of Prefixes Reached | RFC 4486 |
| 2 | Administrative Shutdown | RFC 4486 (RFC 9003) |
| 3 | Peer De-configured | RFC 4486 |
| 4 | Administrative Reset | RFC 4486 (RFC 9003) |
| 5 | Connection Rejected | RFC 4486 |
| 6 | Other Configuration Change | RFC 4486 |
| 7 | Connection Collision Resolution | RFC 4486 |
| 8 | Out of Resources | RFC 4486 |
| 9 | Hard Reset | RFC 8538 |
| 10 | BFD Down | RFC 9384 |

RFC 4271 §6.7 defines the Cease error code (6); the subcode registry is governed
by RFC 4486. The live driver's clean close uses Cease (code 6).

### ROUTE-REFRESH Message Error subcodes (code 7, IANA `route-refresh-error-subcodes`)

| Subcode | Name | Defining RFC |
| --- | --- | --- |
| 0 | Reserved | RFC 7313 |
| 1 | Invalid Message Length | RFC 7313 |

## ROUTE-REFRESH message (type 5) body (RFC 2918, subcodes RFC 7313)

The ROUTE-REFRESH message body is `AFI(2) | Subtype/Reserved(1) | SAFI(1)`
(RFC 2918 §3). The middle octet is "Reserved" in RFC 2918 and reused as a
message subtype by Enhanced Route Refresh (RFC 7313):

| Subtype | Name | Defining RFC |
| --- | --- | --- |
| 0 | Route-Refresh (normal) | RFC 2918 (also RFC 5291) |
| 1 | BoRR (Begin of RR) | RFC 7313 |
| 2 | EoRR (End of RR) | RFC 7313 |
| 255 | Reserved | RFC 7313 |

## AFI / SAFI (RFC 4760, IANA registries)

Only the values needed for IPv4-unicast and IPv6-unicast MP-BGP are in scope.

### Address Family Identifier (AFI) — IANA `address-family-numbers-2`

| AFI | Meaning | Source |
| --- | --- | --- |
| 1 | IP (IPv4) | IANA Address Family Numbers |
| 2 | IP6 (IPv6) | IANA Address Family Numbers |

### Subsequent Address Family Identifier (SAFI) — IANA `safi-namespace-2`

| SAFI | Meaning | Defining RFC |
| --- | --- | --- |
| 1 | Unicast forwarding | RFC 4760 |
| 2 | Multicast forwarding | RFC 4760 |

In-scope combinations: `<AFI=1, SAFI=1>` IPv4 unicast and `<AFI=2, SAFI=1>` IPv6
unicast (RFC 4760; IPv6 usage per RFC 2545).

## Errata affecting the wire format

A verified-errata query for RFC 4271 was run against the RFC Editor errata
service. The wire-level codepoints recorded here (message types, path-attribute
type codes, attribute-flag bit semantics, ORIGIN/AS_PATH segment values,
NOTIFICATION error codes and subcodes) are taken from the IANA registry rows and
confirmed verbatim against RFC 4271 §4.1, §4.3, §5, and §6 text, and against the
defining RFCs for the extensions (RFC 4760 §3-§4 and §8, RFC 6793 §3 and §9,
RFC 1997, RFC 8092 §3, RFC 5492 §4). No errata changing these specific codepoint
values or flag-bit assignments was found; known RFC 4271 errata are clarifying or
editorial and do not alter the byte-level encodings above. If a later step
depends on a subtler RFC 4271 rule (e.g. NLRI handling corner cases), re-check
the verified errata for that specific section before pinning behavior.

## Out of scope (preserve-only / not implemented)

Recorded so later steps do not silently invent behavior:

- Path attributes 9-13, 19-31, 33-42, 128-243 and other registered codepoints
  decode as `Unknown` and round-trip verbatim.
- Extended-community sub-type tables (Two-Octet AS, Four-Octet AS, IPv4-Address,
  Opaque, EVPN, etc.) — the 8-octet item is preserved as raw bytes.
- AFI/SAFI values beyond IPv4/IPv6 unicast.
- Confederation path-segment types (AS_CONFED_SEQUENCE/SET) are recognized as
  segment-type codepoints but no confederation processing is implemented.
- BGP FSM, RIB, route selection, BMP, BGP-LS, FlowSpec, TCP-AO/TCP-MD5: out of
  scope per the plan's Non-Goals.
