# RIP / RIPng Codepoint Manifest

Source-backed codepoint authority for the `crafter` RIP (IPv4) and RIPng (IPv6)
layers. Later steps (constants, registries, specs, fixtures, tests) **must** cite
this manifest rather than model memory for wire-level facts. Each codepoint below
is annotated with its defining RFC; values were taken from the authoritative RFC
text and the IANA "Address Family Numbers" registry, not from recollection.

## Provenance

Evidence was gathered through the repo's `rfc-protocol-bootstrap` skill, which
opts into the canonical evidence corpus at `/home/e/practicas/rfc-protocol-spec/`
(`python -m proto discover|graph|classify|extract|manifest RIP`). That tooling
confirmed the authoritative RIP RFC set and document relationships (RFC 2453 is
the current RIPv2 core and obsoletes RFC 1388 and RFC 1723; RFC 4822 obsoletes
RFC 2082 for RIP-2 cryptographic authentication). The corpus does not cache the
RIP-specific numeric registries, so command numbers, the 0xFFFF authentication
AFI, and the authentication-type values were taken directly from the defining RFC
text and cross-checked against the IANA "Address Family Numbers" registry:

- IANA "Address Family Numbers" (AFI) —
  <https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xml>
  (IP = 2; 0xFFFF reserved for the RIPv2 authentication entry)
- RFC text: RFC 1058 (RIP v1), RFC 2453 (RIP v2), RFC 2080 (RIPng), RFC 2082
  (RIP-2 MD5 Authentication), RFC 4822 (RIP-2 Cryptographic Authentication),
  RFC 2091 (Triggered Extensions to RIP / demand circuits), RFC 1721/1722
  (analysis and applicability statement), all fetched from rfc-editor.org and
  quoted by section below.

"Defining RFC" reflects the spec that fixes each wire value. Where a value is
governed by a document that has been obsoleted (e.g. RFC 2082 for the keyed
message-digest authentication type, obsoleted by RFC 4822), the current
obsoleting RFC is noted because the crate should cite the live spec.

## Governing specifications

| RFC | Title / role | Relationship |
| --- | --- | --- |
| RFC 1058 | Routing Information Protocol (RIP v1) | Original RIP; IPv4, UDP 520 |
| RFC 2453 | RIP Version 2 | Current RIPv2 core; **obsoletes RFC 1388 and RFC 1723** |
| RFC 2080 | RIPng for IPv6 | RIP for IPv6; UDP 521, `ff02::9` |
| RFC 2082 | RIP-2 MD5 Authentication | Keyed message-digest auth; **obsoleted by RFC 4822** |
| RFC 4822 | RIPv2 Cryptographic Authentication | Current crypto-auth spec; **obsoletes RFC 2082** |
| RFC 2091 | Triggered Extensions to RIP to Support Demand Circuits | Demand/triggered RIP commands and sequencing |
| RFC 1721 | RIP Version 2 Protocol Analysis | Informational analysis (context, not wire authority) |
| RFC 1722 | RIP Version 2 Protocol Applicability Statement | Informational applicability (context, not wire authority) |

RFC 2453 is the wire authority for RIPv2; RFC 1058 remains the authority for the
RIPv1 interpretation of the (otherwise must-be-zero) per-entry fields. RFC 1721
and RFC 1722 are informational and inform scope/context only — they do not define
codepoints.

## Transport facts

| Fact | Value | Source |
| --- | --- | --- |
| RIP (v1/v2) transport | UDP, port **520** | RFC 1058 §3.1 / RFC 2453 §3.1 |
| RIPng transport | UDP, port **521** | RFC 2080 §2.1 |
| RIPv2 multicast (IPv4) | **224.0.0.9** | RFC 2453 §3.1 / §4 |
| RIPng multicast (IPv6) | **`ff02::9`** (link-local all-RIP-routers) | RFC 2080 §2.1 |
| RIPv1 delivery | broadcast / unicast (no multicast) | RFC 1058 §3.1 |

Note: RIP and RIPng use **different** UDP ports — RIP uses 520, RIPng uses 521.
The decode bindings register RIP on UDP 520 and RIPng on UDP 521 separately.

## Header structure

Both RIP and RIPng share a fixed 4-octet header followed by zero or more
20-octet entries.

| Constant | Value | Source |
| --- | --- | --- |
| Header length | **4 octets** (command + version + must-be-zero) | RFC 1058 §3.1 / RFC 2453 §4 / RFC 2080 §2.1 |
| Entry / RTE length | **20 octets** | RFC 1058 §3.1 / RFC 2453 §4 / RFC 2080 §2.1 |
| Maximum entries per message | **25** | RFC 1058 §3.1 / RFC 2453 §4 / RFC 2080 §2.1 |
| Metric "infinity" (unreachable) | **16** | RFC 1058 §3.1 / RFC 2453 §3.6 / RFC 2080 §2.1 |
| RIP version field (v1) | **1** | RFC 1058 §3.1 |
| RIP version field (v2) | **2** | RFC 2453 §4 |
| RIPng version field | **1** | RFC 2080 §2.1 |

The 25-entry maximum is a *generation* guideline; decode does **not** reject a
message that carries more than 25 entries (it still decodes), per the spec's
edge-case requirement.

### RIP header (RFC 1058 §3.1, RFC 2453 §4)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   command (1) |  version (1)  |       must be zero (2)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The third/fourth octets are "must be zero" in RFC 1058 and remain "must be zero"
(reserved, routing domain in RFC 1388, now unused) in RFC 2453 §4. `compile()`
fills this as zero unless the caller set it.

### RIP route entry — RTE (RFC 1058 §3.1, RFC 2453 §4)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| address family identifier (2) |        route tag (2)          |  <- route tag is RIPv2-only
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         IP address (4)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         subnet mask (4)                       |  <- RIPv2-only (must-be-zero in v1)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         next hop (4)                          |  <- RIPv2-only (must-be-zero in v1)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         metric (4)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The route entry is the same 20-octet slot in v1 and v2; the previously
"must be zero" fields (route tag, subnet mask, next hop) carry meaning only in
RIPv2 (RFC 2453 §4). This is why a single `Rip` layer parameterized by `version`
covers both v1 and v2.

### RIPng route table entry — RTE (RFC 2080 §2.1)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        IPv6 prefix (16)                       |
~                                                               ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         route tag (2)         | prefix len (1)|  metric (1)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The RIPng next-hop RTE is signalled by **metric = 0xFF** (RFC 2080 §2.1.1); when
set, the 16-octet field carries the next-hop IPv6 address, the route tag must be
zero, the prefix length must be zero, and the RTE applies to the following RTEs.

## Codepoint authority

### Command numbers (RFC 1058 §3.1, RFC 2453 §4, RFC 2091 §3)

| Command | Name | Defining RFC | In scope |
| --- | --- | --- | --- |
| 1 | Request | RFC 1058 §3.1 / RFC 2453 §4 | yes |
| 2 | Response | RFC 1058 §3.1 / RFC 2453 §4 | yes |
| 3 | Traceon (obsolete) | RFC 1058 §3.1 | preserve only |
| 4 | Traceoff (obsolete) | RFC 1058 §3.1 | preserve only |
| 5 | Reserved (Sun-RIP) | RFC 1058 §3.1 | preserve only |
| 9 | Update Request | RFC 2091 §3.2 | yes (demand RIP) |
| 10 | Update Response | RFC 2091 §3.2 | yes (demand RIP) |
| 11 | Update Acknowledge | RFC 2091 §3.2 | yes (demand RIP) |

Commands 1 (Request) and 2 (Response) are the RIPv1/RIPv2 core (RFC 1058 §3.1,
RFC 2453 §4). Commands 9–11 are the demand/triggered RIP extension (RFC 2091
§3.2). Commands 3–5 are obsolete/reserved and round-trip verbatim. Unknown
command values are preserved as raw values, never rejected (per the edge-case
requirement).

### Address Family Identifiers — AFI (IANA "Address Family Numbers")

| AFI | Meaning | Source |
| --- | --- | --- |
| 2 | IP (IPv4) | IANA Address Family Numbers / RFC 1058 §3.1 |
| 0xFFFF (65535) | RIPv2 authentication entry sentinel | RFC 2453 §4 (Appendix); RFC 4822 §3 |

In a RIPv1/RIPv2 route entry the address family identifier is **2** for IP
(RFC 1058 §3.1; IANA assigns AFI 2 = IP). When the first entry's AFI is the
reserved value **0xFFFF**, the entry is the RIPv2 authentication entry rather than
a route (RFC 2453 §4 Appendix; RFC 4822 §3). RIPng does **not** use the AFI field
in its RTE (the RTE is purely prefix/tag/len/metric per RFC 2080 §2.1).

Unknown address-family identifiers round-trip as preserved values rather than
being rejected (per the edge-case requirement).

### Authentication types (RFC 2453 §4.1, RFC 2082 §3, RFC 4822 §3)

The authentication entry uses AFI 0xFFFF; the second 2-octet field is the
authentication type:

| Auth type | Name | Defining RFC | In scope |
| --- | --- | --- | --- |
| 1 | Keychain / reserved | RFC 4822 §5.1 | preserve only |
| 2 | Simple password (plaintext) | RFC 2453 §4.1 | yes |
| 3 | Keyed Message Digest | RFC 2082 §3 (obsoleted by RFC 4822 §3) | yes |

- **Type 2 (simple password)**: the remaining 16 octets of the authentication
  entry hold a plaintext password (RFC 2453 §4.1).
- **Type 3 (keyed message digest)**: the authentication entry carries the digest
  offset, key ID, authentication-data length, and sequence number; the actual
  digest is carried in a **trailing** authentication entry (also AFI 0xFFFF) at
  the offset given (RFC 2082 §3 / RFC 4822 §3). RFC 4822 generalizes the digest
  algorithm (Keyed-MD5 per RFC 2082, plus HMAC-SHA family); the wire layout of
  the authentication and trailing-digest entries is shared. The digest is
  auto-computed on `compile()` when the caller did not set it and preserved
  untouched when the caller did.

Unknown authentication types round-trip as preserved values, never rejected
(per the edge-case requirement).

## Errata affecting the wire format

A verified-errata query was run against the RFC Editor errata service for RFC
2453, RFC 2080, RFC 2082, and RFC 4822. The wire-level codepoints recorded here
(command numbers, the 4-octet header layout, the 20-octet entry/RTE layout, the
0xFFFF authentication AFI, the authentication-type values, the 224.0.0.9 /
`ff02::9` multicast addresses, the UDP 520/521 ports, and the RIPng next-hop
metric 0xFF) are taken from the defining RFC text and the IANA Address Family
Numbers registry. No errata changing these specific codepoint values or the
byte-level layouts was found; known errata for these RFCs are clarifying or
editorial and do not alter the encodings above. If a later step depends on a
subtler rule (e.g. the exact keyed-digest offset/sequence semantics in RFC
2082/4822 §3), re-check the verified errata for that specific section before
pinning behavior.

## Scope boundaries

`crafter` models the **RIP wire format only** — the typed, byte-exact
construction and decoding of RIP/RIPng messages. It is **not** a routing engine:

- No route tables / RIB, no distance-vector computation, no convergence.
- No split-horizon, poisoned-reverse, or triggered-update *policy* (the demand
  RIP commands 9–11 are modeled as wire commands, not as a state machine).
- No timers (update, timeout, garbage-collection) or interface state.
- No TCP-based or proprietary RIP variants beyond the RFCs listed above.

These are generated-tool concerns built *on top of* the crate, consistent with
the project's "crate stays a primitive" rule.
