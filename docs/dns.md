# DNS Wire Coverage

This page describes the DNS wire-message support in the `crafter` crate: what
the `Dns` packet layer encodes and decodes today, which RFC-backed features are
planned, and which records and features are intentionally kept as raw bytes or
deferred.

`crafter` treats DNS as one packet layer. It builds, compiles, decodes,
summarizes, and shows like every other layer. It is not a resolver, a cache, a
validator, or a scanner. EDNS, DNSSEC, and service-binding support is in scope
only as wire encoding and decoding, never as resolver or cryptographic
behavior.

All protocol facts on this page are taken from reviewed IANA registries and RFC
text, not model memory. See [Evidence](#evidence) for the exact registries and
sections.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| Header (id, flags, section counts) | Supported | Counts auto-filled from typed vectors; explicit flags honored. |
| Questions (name, type, class) | Supported | Trailing-dot string names; arbitrary type and class values. |
| Name decode (compressed) | Supported | Pointer cycles, out-of-range pointers, truncated pointers, label/full-name overrun, and reserved markers are rejected. |
| Name encode (uncompressed) | Supported | Deterministic; compression is not emitted by default. |
| Byte-preserving names (non-UTF-8 labels) | Supported | Trailing-dot string API for text labels; exact wire bytes retained for non-text labels via `\DDD` escapes. |
| A, AAAA, NS, CNAME, PTR, MX, TXT | Supported | Typed `DnsRecordData` variants. |
| Unknown / unsupported record types | Supported (Raw) | Preserved as `DnsRecordData::Raw` when the message is structurally valid. |
| Opcodes, rcodes, types, classes as named constants | Planned | Inspectable, constructible helpers from the IANA registries. |
| SOA, SRV, additional base RDATA | Planned | Typed where the wire format is unambiguous. |
| EDNS(0) OPT pseudo-record and options | Planned | Wire encode/decode only. |
| DNSSEC RDATA (DNSKEY, RRSIG, DS, NSEC, NSEC3) | Planned | Wire structures only; no cryptographic validation. |
| SVCB / HTTPS service binding | Planned | Wire encode/decode of SvcParams. |
| Obsolete, cryptographic-only, or rarely used RDATA | Raw | Left as `DnsRecordData::Raw` unless evidence and fit justify a typed primitive. |
| DNS over TCP (length-prefixed stream) | Deferred | Out of scope unless a narrow length-prefixed primitive is approved. |

## Current coverage

The shipped `Dns` layer covers the base DNS message shape from RFC 1035:

- Header: 16-bit id, 16-bit flags, and the four section counts. Section counts
  are filled from the typed question, answer, authority, and additional vectors
  at compile time. User-set flags, including intentionally unusual values, are
  preserved.
- Questions: owner name, QTYPE, and QCLASS. Names use the ergonomic
  trailing-dot string form for text-compatible labels.
- Names: decoding follows compression pointers and consumes the correct number
  of wire bytes. Encoding emits uncompressed names deterministically. Names are
  byte-preserving: the exact wire-label octets are retained, so labels that are
  not valid UTF-8 are not silently lost. See
  [Name presentation form](#name-presentation-form).
- Resource record data, typed today as `DnsRecordData`:
  - `A` (type 1) and `AAAA` (type 28) address records.
  - `Name` for NS (2), CNAME (5), and PTR (12).
  - `Mx` (15) preference plus exchange name.
  - `Txt` (16) as a list of DNS character-strings.
  - `Raw` for every other record type, preserving the original RDATA bytes.
- Dispatch: UDP port 53 decodes payloads into the `Dns` layer through the
  packet registry.

Header flag constants currently exported include QR, AA, TC, RD, RA, AD, and
CD, plus the common record type and class constants.

## Name presentation form

DNS labels are byte sequences, not text (RFC 1035 Section 3.1), but the wire
format permits arbitrary octets inside a label. `crafter` stores names as a
byte-preserving `DnsName` that keeps the exact wire labels while still exposing
a stable presentation string:

- `DnsQuestion::name()` and `DnsRecord::name()` return the canonical
  trailing-dot presentation string, unchanged for text-compatible names.
- `DnsQuestion::dns_name()` / `DnsRecord::dns_name()` return the typed
  `DnsName`, and `name_labels()` returns the exact wire-label bytes.
- `decode_dns_name` returns the presentation string; `decode_dns_name_typed`
  returns the byte-preserving `DnsName`.

The presentation string uses the RFC 1035 Section 5.1 master-file escaping
convention (see also RFC 4343 Section 2.1) so that non-text and special bytes
survive a string round trip:

- Bytes that are not printable ASCII, and the `.` and `\` characters inside a
  label, are written as `\DDD`: a backslash followed by exactly three decimal
  digits giving the octet value (for example `\000` or `\255`).
- All other (printable, unambiguous ASCII) bytes are written verbatim.
- The trailing dot terminates the name; the root name is `"."`.

`DnsName::parse` accepts the same `\DDD` decimal escape and a `\X`
literal-character escape, so a non-text name can be expressed as text and
parsed back to the same wire labels. A name built from a text string, decoded
from the wire, rendered to its presentation form, and recompiled preserves the
original label bytes exactly; encoding remains deterministic and never emits
compression by default.

## Source-backed gaps

The base layer is intentionally compact. Comparing it against the IANA DNS
registries and the core RFC wire formats surfaces these source-backed gaps:

- Named codepoints are incomplete. The IANA DNS Parameters registry defines
  opcodes (QUERY, IQUERY, STATUS, NOTIFY, UPDATE, DSO), response codes
  (NOERROR through the extended BADxxx range), classes (IN, CH, HS, NONE, ANY),
  and a large RR type table. Only a handful are exposed as constants today.
- Several base RDATA formats with unambiguous wire layouts are still raw,
  including SOA (type 6) and SRV (type 33).
- There is no typed support for the EDNS(0) OPT pseudo-record (type 41), whose
  CLASS and TTL fields carry UDP payload size, extended RCODE, version, and
  flags rather than ordinary class and TTL meaning.
- DNSSEC wire records (DNSKEY 48, RRSIG 46, DS 43, NSEC 47, NSEC3 50) are raw.
  Their RDATA has well-defined wire structures that can be parsed without any
  cryptographic validation.
- Service-binding records SVCB (64) and HTTPS (65) are raw. Their RDATA is a
  SvcPriority, a target name, and a list of SvcParam key/value pairs.

## Planned coverage

These features are selected for typed support because their wire formats are
unambiguous in the cited sources and they fit the existing `DnsRecordData`,
builder, decode, and summary shape:

- Header, opcode, rcode, type, and class helpers: named constants and small
  accessors backed by the IANA DNS Parameters registry. Building remains free
  to use arbitrary numeric values.
- Base RDATA: typed `SOA` (MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE,
  MINIMUM) and `SRV` (priority, weight, port, target).
- EDNS(0): an OPT pseudo-record representation that exposes UDP payload size,
  extended RCODE, version, and flags from the reused CLASS and TTL fields, plus
  a TLV list of EDNS options (OPTION-CODE, OPTION-LENGTH, OPTION-DATA).
- DNSSEC wire RDATA: typed `DNSKEY`, `RRSIG`, `DS`, `NSEC`, and `NSEC3` parsed
  as wire structures only. Algorithm, digest, key, bitmap, and signature bytes
  are carried verbatim and never cryptographically validated. The Signer's Name
  in RRSIG and the Next Domain Name in NSEC are emitted uncompressed, as the
  source requires.
- Service binding: typed `SVCB` and `HTTPS` RDATA carrying SvcPriority, an
  uncompressed target name, and SvcParam key/value pairs.

Each planned slice keeps section counts auto-filled, keeps explicit values
honored, and keeps unknown record data as `Raw`.

## Records and features kept as Raw

Some record types stay as `DnsRecordData::Raw` on purpose. Raw preserves the
exact RDATA bytes and keeps the packet inspectable without committing the crate
to ambiguous, obsolete, or niche structure:

- Obsolete or experimental types such as MD (3), MF (4), MB (7), MG (8), MR
  (9), NULL (10), WKS (11), and A6 (38).
- Cryptographic-key and signature transport types whose value is opaque bytes
  for wire purposes, such as KEY (25), SIG (24), CERT (37), IPSECKEY (45),
  SSHFP (44), TLSA (52), and OPENPGPKEY (61). Where a DNSSEC structure above is
  typed, only its fixed wire fields are parsed; key and signature material stays
  as bytes.
- Rarely used or registry-churn types such as HINFO (13), RP (17), AFSDB (18),
  X25 (19), ISDN (20), RT (21), LOC (29), NAPTR (35), and URI (256). These may
  become typed later if evidence and project fit justify it.
- Any unknown or unassigned RR type. Structurally valid records with an unknown
  type decode to `Raw` and recompile to the same bytes.

## Deferred

These are explicitly out of scope for the current DNS wire work:

- Resolver behavior, caching, retransmission, server selection, and any live
  DNS workflow.
- Cryptographic validation of DNSSEC material. The crate parses and emits wire
  structures only.
- DNS over TCP stream framing. The two-octet length prefix and stream
  reassembly are deferred unless a narrow length-prefixed packet primitive is
  approved and fits the existing abstraction.
- Zone file presentation parsing. The crate works on wire bytes, not master
  file text.

## Evidence

Protocol facts above come from the following reviewed sources. Compact
references are kept here intentionally; large generated manifests are not
committed.

Registries (IANA Domain Name System Parameters, `dns-parameters`):

- Resource Record (RR) TYPEs: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, OPT,
  DS, RRSIG, NSEC, DNSKEY, NSEC3, NSEC3PARAM, TLSA, SVCB, HTTPS, and the full
  type space including obsolete and experimental entries.
- DNS OpCodes: QUERY (0), IQUERY (1, obsolete), STATUS (2), NOTIFY (4),
  UPDATE (5), DSO (6).
- DNS RCODEs: NOERROR (0) through REFUSED (5), the dynamic-update codes (6-11),
  and the extended BADSIG/BADVERS family (16+).
- DNS CLASSes: IN (1), CH (3), HS (4), NONE (254), ANY (255).
- DNS EDNS0 Option Codes: NSID (3), DAU/DHU/N3U (5-7), edns-client-subnet (8),
  EDNS EXPIRE (9), COOKIE (10), edns-tcp-keepalive (11), Padding (12),
  Extended DNS Error (15), and others.
- DNS Header Flags and EDNS Header Flags (DO, CO).

RFC wire formats:

- RFC 1035: message format, header, question, resource record framing, name
  compression, and the base RDATA formats (including SOA, RFC 1035 Section
  3.3.13).
- RFC 3596: AAAA record (type 28).
- RFC 2782: SRV record (type 33): priority, weight, port, target.
- RFC 6891: EDNS(0) and the OPT pseudo-record (type 41), Section 6.1.2 wire
  format and Section 6.1.3 TTL field use.
- RFC 4034: DNSSEC RDATA wire formats for DS (Section 5.1), DNSKEY
  (Section 2.1), RRSIG (Section 3.1), and NSEC (Section 4.1). RRSIG Signer's
  Name and NSEC Next Domain Name MUST NOT be compressed (Sections 3.1.7 and
  6.2).
- RFC 5155: NSEC3 and NSEC3PARAM (types 50 and 51).
- RFC 9460: SVCB and HTTPS service binding (types 64 and 65), Section 2.2 RDATA
  wire format.
</content>
</invoke>
