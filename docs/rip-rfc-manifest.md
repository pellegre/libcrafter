# RIP RFC Manifest

This manifest records the Routing Information Protocol behavior that `crafter`
models for source-backed compile, decode, display, fixture, and oracle work. It
is intentionally narrow: `crafter` stays a packet primitive. It builds and
decodes individual RIP and RIPng messages — the header, the route entries, and
the RIPv2 authentication entries — fills dependent fields on `compile()`,
preserves deliberate overrides, and keeps unknown or malformed input
inspectable. It does **not** implement a RIP routing engine, a route table,
distance-vector convergence, split-horizon, triggered-update timing, or any
timer/state machine. Those are router behavior, not packet behavior, and are
out of scope (see [Explicit Exclusions](#explicit-exclusions)).

The user-facing wire guide is [`docs/rip.md`](rip.md); the field-by-field map
from this manifest to the implemented surface is
[`docs/rip-implementation-inventory.md`](rip-implementation-inventory.md). The
agent-facing codepoint and scope notes live in
[`.agents/docs/rip-codepoints.md`](../.agents/docs/rip-codepoints.md) and
[`.agents/docs/rip-scope.md`](../.agents/docs/rip-scope.md).

Date checked: 2026-06-16 (RFC Editor and the IANA Address Family Numbers
registry reviewed on this date).

## Source Authority And How To Read This Manifest

Every wire fact `crafter` relies on must trace to one of the entries below.
Model memory may suggest what to look up, but it is not the authority; the cited
RFC or IANA registry is. Each row names the specific RFC section or IANA
registry that backs it, so the fact can be re-verified directly against the
official source. Any future addition must add or update a citation here before
code, tests, fixtures, docs, or oracle specs depend on it.

"Normative for wire behavior" means the source defines bytes on the wire that
`crafter` must construct, fill, or decode correctly. "Registry authority" means
IANA is the current source for names or numeric assignments. "Guidance only"
means the source informs documentation or defaults but does not itself dictate a
field encoding that `crafter` serializes.

## Source Set

### Normative for wire behavior

- **RFC 1058 — Routing Information Protocol** defines RIP version 1: the
  4-octet message header (command, version, and a 2-octet reserved field that
  must be zero), the fixed 20-octet route entry layout (Address Family
  Identifier, IPv4 address, and metric, with the route-tag, subnet-mask, and
  next-hop octets reserved/zero in v1), the metric-infinity value 16, UDP port
  520, and the whole-table Request sentinel (a single entry with AFI 0 and
  metric 16). Source: https://www.rfc-editor.org/rfc/rfc1058.html
- **RFC 2453 — RIP Version 2** defines RIPv2 as an extension of RFC 1058 that
  reuses the same header and 20-octet entry slot and reinterprets the
  previously-reserved entry octets as the Route Tag (2 octets), Subnet Mask
  (4 octets), and Next Hop (4 octets). It defines the RIPv2 IPv4 multicast
  group 224.0.0.9 for periodic responses and the AFI 0xFFFF authentication
  entry that replaces the first route entry. Source:
  https://www.rfc-editor.org/rfc/rfc2453.html
- **RFC 2082 — RIP-2 MD5 Authentication** defines Keyed-MD5 authentication: the
  leading AFI 0xFFFF / authentication-type 3 entry carrying the offset to the
  trailing digest, the Key Identifier, the Authentication Data Length, a
  Sequence Number, and two reserved words, plus the trailing authentication
  block (AFI 0xFFFF, trailer type 0x0001) carrying a 16-octet MD5 digest
  computed over the message with the trailing digest region replaced by the
  zero-padded key before hashing. Source:
  https://www.rfc-editor.org/rfc/rfc2082.html
- **RFC 4822 — RIPv2 Cryptographic Authentication** obsoletes RFC 2082 and
  generalizes the keyed-message-digest framing to the HMAC-SHA family
  (HMAC-SHA-1, HMAC-SHA-256) while keeping the same leading-entry and
  trailing-digest layout; the digest is the full-length HMAC of the message up
  to the digest region keyed by the shared secret. The Authentication Data
  Length octet fixes the trailing digest length (16 Keyed-MD5, 20 HMAC-SHA-1,
  32 HMAC-SHA-256). Source: https://www.rfc-editor.org/rfc/rfc4822.html
- **RFC 2080 — RIPng for IPv6** defines RIPng: the 4-octet header (command,
  version, 2-octet reserved), the fixed 20-octet Route Table Entry (16-octet
  IPv6 prefix, 2-octet Route Tag, 1-octet Prefix Length, 1-octet Metric), the
  next-hop RTE (metric 0xFF, prefix carrying the IPv6 next hop, route tag and
  prefix length zero), the metric-infinity value 16, the whole-table Request
  sentinel (prefix ::, prefix length 0, metric 16), UDP port 521, and the
  link-local all-RIP-routers multicast group ff02::9. Source:
  https://www.rfc-editor.org/rfc/rfc2080.html
- **RFC 2091 — Triggered Extensions to RIP to Support Demand Circuits** defines
  demand/triggered RIP for on-demand circuits: the Update Request (command 9),
  Update Response (command 10), and Update Acknowledge (command 11) commands and
  the per-message Sequence Number carried in the 2 octets RIP otherwise
  reserves, used to match retransmitted updates with their acknowledgements over
  unicast. Source: https://www.rfc-editor.org/rfc/rfc2091.html

### Registry authority

- **IANA Address Family Numbers** is the authority for the 2-octet Address
  Family Identifier that begins each RIP route entry. `crafter` relies on
  IP (IPv4) = 2 for routeable entries; the 0xFFFF value is the RFC 2453 §4.1
  authentication-entry marker. Source:
  https://www.iana.org/assignments/address-family-numbers

### Guidance only (no `crafter`-serialized field)

- The RFC 2453 §4 / RFC 2080 §2.1 guideline that a single message carries at
  most 25 route entries is a **generation** guideline, not a decode-time
  rejection. `crafter` builders may emit any number of entries, and decode reads
  every present entry, so an over-length message still decodes.

## RIP Header (RFC 1058 §3.1, RFC 2453 §4)

A RIP message is a 4-octet header followed by zero or more fixed 20-octet route
entries. The same `Rip` layer covers versions 1 and 2; they share the header
and entry slot and differ only in how the previously-reserved entry octets are
interpreted, selected by the `version` field.

| Field | Offset | Size | Source | Source-backed behavior |
| --- | ---: | ---: | --- | --- |
| Command | 0 | 1 octet | RFC 1058 §3.1; RFC 2091 §3.2 | Message type: 1 Request, 2 Response (RFC 1058); 9/10/11 demand commands (RFC 2091). Unknown codes are preserved verbatim, never rejected. |
| Version | 1 | 1 octet | RFC 1058 §3.1; RFC 2453 §4 | RIP version: 1 (RFC 1058) or 2 (RFC 2453). `compile()` defaults the version when unset; a caller-set value survives. |
| Reserved / Sequence | 2 | 2 octets | RFC 1058 §3.1; RFC 2091 §2.3 | Must be zero for RFC 1058 / RFC 2453 messages. For the RFC 2091 demand commands these 2 octets carry the Sequence Number. |

`compile()` fills version and reserved when unset, plus the enclosing UDP port
520 and IPv4/UDP lengths and checksums through the existing packet composition.
Caller-set command, version, and reserved values — including deliberately wrong
ones — serialize exactly as set. Decode never panics: a body shorter than 4
octets returns a structured `buffer_too_short` error exposing
`context`/`required`/`available`.

## RIP Route Entry (RFC 1058 §3.1, RFC 2453 §4)

Each route entry is a fixed 20-octet record, big-endian.

| Field | Offset | Size | Source | Source-backed behavior |
| --- | ---: | ---: | --- | --- |
| Address Family Identifier | 0 | 2 octets | RFC 2453 §4.1; IANA Address Family Numbers | IP = 2 for routeable entries; 0xFFFF marks an authentication entry; 0 is the whole-table-request sentinel AFI. Unknown values are preserved. |
| Route Tag | 2 | 2 octets | RFC 2453 §3.1 | Opaque 2-octet tag carried unchanged in RIPv2 (zero in RIPv1). |
| IPv4 Address | 4 | 4 octets | RFC 1058 §3.1; RFC 2453 §4 | Destination IPv4 address. |
| Subnet Mask | 8 | 4 octets | RFC 2453 §4 | Destination subnet mask in RIPv2 (zero in RIPv1). Non-contiguous masks are preserved as set. |
| Next Hop | 12 | 4 octets | RFC 2453 §4.4 | Immediate next hop in RIPv2; 0.0.0.0 means the route originator (zero in RIPv1). |
| Metric | 16 | 4 octets | RFC 1058 §3.1 | Distance metric; 16 (infinity) means unreachable. |

A trailing run of bytes that is not a whole multiple of 20 surfaces a structured
length error for the partial entry rather than dropping bytes.

### RIPv1 vs RIPv2 (RFC 1058 vs RFC 2453)

RFC 1058 RIPv1 entries leave the route-tag, subnet-mask, and next-hop octets
zero; RFC 2453 RIPv2 reinterprets those same octets as the typed fields above.
`crafter` models both with the one 20-octet `RipEntry` and version-specific
constructors, so a v1 entry simply leaves the v2 octets at their zero defaults.

### Whole-table Request sentinel (RFC 1058 §3.4.1, RFC 2453 §3.9.1)

A request for the entire routing table is a Request message carrying a single
route entry whose AFI is 0 and whose metric is 16 (infinity), with all addresses
0.0.0.0. `crafter` builds and recognizes this sentinel and marks the AFI 0
caller-set so it survives `compile()` rather than being defaulted to IP = 2.

### RIPv2 multicast response (RFC 2453 §3.5)

RIPv2 sends periodic and triggered responses to the well-known IPv4 multicast
group 224.0.0.9 over UDP port 520. `crafter` provides a convenience that
assembles the IPv4 / UDP(520) / RIPv2 response stack to that group.

## RIPv2 Authentication (RFC 2453 §4.1, RFC 2082, RFC 4822 §3)

RIPv2 authentication replaces the first route entry with an AFI 0xFFFF
authentication entry. The 2 octets that would be a route entry's Route Tag carry
the Authentication Type.

### Simple password (RFC 2453 §4.1, type 2)

The leading AFI 0xFFFF / type 2 entry carries 16 octets of plaintext password,
right-padded with zeros, in the entry's address/subnet-mask/next-hop/metric
slots. A decode-side helper recovers the password and verifies it in constant
time against the supplied key.

### Keyed message digest (RFC 2082 / RFC 4822 §3, type 3)

| Field | Offset within leading entry | Size | Source | Behavior |
| --- | ---: | ---: | --- | --- |
| AFI marker | 0 | 2 octets | RFC 2453 §4.1 | 0xFFFF authentication marker. |
| Authentication Type | 2 | 2 octets | RFC 2082; RFC 4822 §3.1 | 3 = keyed message digest. |
| Offset to digest | 4 | 2 octets | RFC 4822 §3.1 | Offset, from the message start, to the trailing digest. |
| Key Identifier | 6 | 1 octet | RFC 4822 §3.1 | Identifies the key/algorithm in use. |
| Authentication Data Length | 7 | 1 octet | RFC 4822 §3.1 | Trailing digest length: 16 Keyed-MD5, 20 HMAC-SHA-1, 32 HMAC-SHA-256. |
| Sequence Number | 8 | 4 octets | RFC 4822 §3.1 | Monotonically non-decreasing per-message counter. |
| Reserved word 1 | 12 | 4 octets | RFC 4822 §3.1 | Must be zero. |
| Reserved word 2 | 16 | 4 octets | RFC 4822 §3.1 | Must be zero. |

The digest itself follows the last route entry in a trailing authentication
block: a 4-octet introduction (AFI 0xFFFF, trailer type 0x0001) followed by the
raw digest octets. On `compile()`, when the caller did not pin a digest,
`crafter` auto-computes it — RFC 2082 §3.2.1 Keyed-MD5 (the trailing 16-octet
region is overwritten with the zero-padded key before MD5 over the whole
message) or RFC 4822 §3 HMAC-SHA over the message up to the digest region — and
the decode-side verification helper recomputes and compares it in constant time.
A caller-pinned digest (including a deliberately wrong one) survives untouched.

## RIPng (RFC 2080)

RIPng is the IPv6 variant, modeled as its own `Ripng` layer following the
project's v4/v6 layer-naming convention. It runs over UDP port 521 and the
link-local multicast group ff02::9, and reuses the Request/Response command
codepoints.

### RIPng header (RFC 2080 §2)

| Field | Offset | Size | Source | Source-backed behavior |
| --- | ---: | ---: | --- | --- |
| Command | 0 | 1 octet | RFC 2080 §2.1 | 1 Request, 2 Response. |
| Version | 1 | 1 octet | RFC 2080 §2 | RIPng version 1. |
| Reserved | 2 | 2 octets | RFC 2080 §2 | Must be zero. |

### RIPng Route Table Entry (RFC 2080 §2.1)

| Field | Offset | Size | Source | Source-backed behavior |
| --- | ---: | ---: | --- | --- |
| IPv6 Prefix | 0 | 16 octets | RFC 2080 §2.1 | Destination IPv6 prefix (or next-hop address in a next-hop RTE). |
| Route Tag | 16 | 2 octets | RFC 2080 §2.1 | Opaque 2-octet tag, carried unchanged. |
| Prefix Length | 18 | 1 octet | RFC 2080 §2.1 | Significant bits of the prefix; deliberately out-of-range values are preserved. |
| Metric | 19 | 1 octet | RFC 2080 §2.1 / §2.1.1 | Distance metric; 16 is infinity; 0xFF marks a next-hop RTE. |

### Next-hop RTE (RFC 2080 §2.1.1)

A next-hop RTE specifies the next hop for the RTEs that immediately follow it:
its metric octet is 0xFF, its prefix field carries the IPv6 next-hop address,
and its route tag and prefix length are zero. `crafter` builds, classifies, and
round-trips it.

### RIPng whole-table Request sentinel (RFC 2080 §2.4.1)

A request for the peer's complete routing table is a Request message carrying a
single RTE whose prefix is ::, prefix length 0, route tag 0, and metric 16
(infinity). `crafter` builds and recognizes this sentinel.

## Demand / Triggered RIP (RFC 2091)

Demand RIP layers on the RIPv2 core for on-demand circuits and runs over unicast
rather than the 224.0.0.9 multicast group:

| Command | Code | Source | Behavior |
| --- | ---: | --- | --- |
| Update Request | 9 | RFC 2091 §3.2 | Demand request for routes on an on-demand circuit. |
| Update Response | 10 | RFC 2091 §3.2 | Demand routing update, carrying route entries. |
| Update Acknowledge | 11 | RFC 2091 §3.2 | Acknowledgement of an Update Response. |

Each demand message carries a 2-octet Sequence Number in the header field RIP
otherwise reserves (RFC 2091 §2.3), used to match retransmitted updates with
their acknowledgements. `crafter` records and reads back this sequence only for
the demand Update* commands; for a plain Request/Response those octets are just
the reserved field.

## Decode And Compile Guardrails

- `compile()` fills the version, the reserved field, the entry address
  families, the authentication digest (Keyed-MD5 / HMAC-SHA), and the enclosing
  UDP port and IPv4/IPv6 lengths and checksums only when those dependent fields
  are unset.
- Caller-set values that fit their wire fields are preserved, including values
  that are deliberately wrong for malformed-packet tests (a wrong reserved
  field, an out-of-range prefix length, a non-contiguous mask, an over-infinity
  metric, a pinned wrong digest).
- Unknown commands, unknown Address Family Identifiers, and unknown
  authentication types round-trip as preserved raw/typed values rather than
  being rejected or silently rewritten.
- A truncated header (fewer than 4 octets) and a partial or non-multiple-of-20
  route entry / RTE body surface a structured `buffer_too_short` error exposing
  `context`/`required`/`available`, and never panic.
- The UDP/520 (RIP) and UDP/521 (RIPng) decode bindings are conservative: the
  payload must have a known command, a valid version, and a whole-multiple-of-20
  entry body, or it falls through to `Raw` rather than misdecoding.
- The 25-entry generation guideline is not enforced at decode time; an
  over-length message still decodes every present entry.

## Explicit Exclusions

`crafter` does not implement, and this manifest does not authorize, a RIP
routing engine, a route table, distance-vector route computation, convergence,
split-horizon or poison-reverse logic, route timers, garbage-collection timers,
triggered-update timing as a behavior (the RFC 2091 demand *messages* and
sequence field are modeled; the on-demand circuit state machine is not), or any
RIP stack delivery semantics. Authentication keys are used only to compute or
verify a digest; `crafter` performs no key management or rotation. A scanner, a
fuzzer, and a packet-analyzer workflow are generated tools built on the crate,
not crate modules. RIPng cross-validation is constrained where the reference
oracle backend lacks a native RIPng dissector; those cases fall back to
parser-backend decode plus libcrafter internal round-trip and are marked
accordingly, never silently skipped.
