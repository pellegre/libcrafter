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
| Opcodes, rcodes, types, classes as named constants | Supported | Inspectable, constructible helpers from the IANA registries; arbitrary numeric values still build. |
| SOA, SRV base RDATA | Supported | Typed `DnsRecordData::Soa` and `DnsRecordData::Srv`. |
| EDNS(0) OPT pseudo-record and options | Supported | Wire encode/decode only; option values stay opaque. |
| DNSSEC RDATA (DNSKEY, RRSIG, DS, NSEC, NSEC3) | Supported | Wire structures only; no cryptographic validation. |
| SVCB / HTTPS service binding | Supported | Typed SvcPriority, uncompressed target, and ordered SvcParams; values stay opaque. |
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
  - `Soa` (6): MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, and MINIMUM.
  - `Srv` (33): priority, weight, port, and an uncompressed target name.
  - `Txt` (16) as a list of DNS character-strings.
  - `Opt` (41): the EDNS(0) pseudo-record, a list of {code, length, data}
    options with the UDP payload size and extended RCODE/version/flags carried
    in the reused CLASS and TTL fields. See
    [EDNS(0) OPT pseudo-record](#edns0-opt-pseudo-record).
  - `Ds` (43), `Dnskey` (48), `Rrsig` (46), `Nsec` (47), and `Nsec3` (50):
    DNSSEC wire structures parsed without cryptographic validation. See
    [DNSSEC wire records](#dnssec-wire-records).
  - `Svcb` (64) and `Https` (65) service-binding records: a SvcPriority, an
    uncompressed target name, and an ordered list of SvcParams. SvcParam values
    stay opaque wire bytes; unknown SvcParamKeys are preserved verbatim. See
    [Service binding records](#service-binding-records).
  - `Raw` for every other record type, preserving the original RDATA bytes.
- Dispatch: UDP port 53 decodes payloads into the `Dns` layer through the
  packet registry.

Header flag constants exported include QR, AA, TC, RD, RA, AD, and CD. Named
constants and accessors back the IANA opcodes (`DNS_OPCODE_*`), response codes
(`DNS_RCODE_*`), classes (`DNS_CLASS_*`), and resource record types
(`DNS_TYPE_*`), with `dns_type_name`, `edns_option_code_name`, and
`svcb_param_key_name` returning registry mnemonics. Opcode and rcode accessors
(`Dns::opcode_value`, `Dns::rcode_value`) read the packed flag bits while the
raw flags word stays available for intentionally unusual values.

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

## Service binding records

SVCB (type 64) and HTTPS (type 65) share one RDATA wire format (RFC 9460
Section 2.2): a 2-octet SvcPriority, an uncompressed TargetName, and a list of
SvcParams that consume the remainder of the record. `crafter` types both as
`DnsRecordData::Svcb` and `DnsRecordData::Https`, built with `DnsRecord::svcb`
and `DnsRecord::https`.

Each SvcParam is a {SvcParamKey, length, SvcParamValue} tuple. The crate models
them as an ordered `SvcParams` list of `SvcParam` values:

- SvcPriority is carried verbatim. The mode (AliasMode at priority 0,
  ServiceMode otherwise) is a resolver concept and is not interpreted here; the
  wire primitive does not strip or rewrite SvcParams based on the priority.
- The TargetName is emitted uncompressed, as the source requires, and may be the
  root name `.` (RFC 9460 Section 2.5).
- SvcParamKeys are sorted into strictly increasing numeric order on encode, so
  output is deterministic and conformant regardless of construction order.
  Duplicate keys are rejected, both when building `SvcParams` and when decoding,
  matching the wire rule that keys are strictly increasing.
- Each SvcParamValue is kept as opaque wire bytes because its format is
  "determined by the SvcParamKey". The crate does not parse the internal
  structure of any value. Source-backed keys (`mandatory`, `alpn`,
  `no-default-alpn`, `port`, `ipv4hint`, `ech`, `ipv6hint`, `dohpath`) have
  named constructors and a registry mnemonic through `svcb_param_key_name`;
  unknown keys round trip verbatim with no mnemonic.

Decoding returns structured errors, never a panic, when the RDATA is too short
for the priority, the SvcParams are truncated mid-tuple, a declared value length
overruns the RDATA, or the keys are not strictly increasing (RFC 9460
Section 2.2 malformed conditions).

The following service/application material is deliberately deferred and left as
`DnsRecordData::Raw`:

- Per-SvcParamValue structure. The internal layout of values such as `alpn`,
  `mandatory`, and `ech` is not parsed into typed sub-fields; only the
  key-ordered byte values are exposed. Parsing each value format is resolver- and
  application-leaning work that can be layered on top of the raw bytes.
- Other service/application records whose evidence is ambiguous, whose layout is
  too large for this pass, or whose behavior belongs outside a packet primitive:
  NAPTR (35, naming authority pointer), URI (256), TLSA (52) and other
  certificate-association records, and SSHFP (44). These stay `Raw` and may
  become typed later if evidence and project fit justify it.

## EDNS(0) OPT pseudo-record

The OPT pseudo-record (type 41, RFC 6891 Section 6.1) is an additional-section
record whose ordinary resource-record fields carry EDNS meanings: the owner name
is root, the CLASS field is the requestor's UDP payload size, and the TTL field
packs the extended RCODE, EDNS version, the DO flag, and the Z bits. `crafter`
types OPT RDATA as `DnsRecordData::Opt`, a list of `EdnsOption` values, and keeps
the EDNS fields in the underlying class and TTL so the record still encodes
through the normal name/type/class/ttl/rdlength/RDATA path.

- Build with `DnsRecord::opt(udp_payload_size, extended_rcode, version,
  dnssec_ok, options)`; inspect with `DnsRecord::is_opt`,
  `edns_udp_payload_size`, `edns_extended_rcode`, `edns_version`,
  `edns_dnssec_ok`, `edns_flags`, and `edns_options`.
- Each `EdnsOption` is a {OPTION-CODE, OPTION-LENGTH, OPTION-DATA} tuple
  (RFC 6891 Section 6.1.2). The OPTION-DATA is treated as opaque wire bytes; the
  source-backed option codes (`DNS_EDNS_OPTION_*`) have a registry mnemonic
  through `edns_option_code_name`, and `EdnsOption::nsid`, `cookie`, and
  `padding` build common options. Unknown option codes round trip verbatim.
- Decoding rejects truncated options and OPTION-LENGTH values that overrun the
  RDATA with structured errors rather than panicking.

## DNSSEC wire records

DS (43), DNSKEY (48), RRSIG (46), NSEC (47), and NSEC3 (50) are parsed as wire
structures only; no key, digest, or signature material is cryptographically
validated. Algorithm, digest-type, flags, protocol, key, digest, salt, and
signature values stay raw numeric fields or opaque bytes. Build with
`DnsRecord::ds`, `dnskey`, `rrsig`, `nsec`, and `nsec3`.

- DS (RFC 4034 Section 5.1): key tag, algorithm, digest type, and verbatim
  digest bytes.
- DNSKEY (RFC 4034 Section 2.1): flags, protocol, algorithm, and verbatim public
  key bytes.
- RRSIG (RFC 4034 Section 3.1): the covered type, algorithm, label count, TTLs,
  signature validity window, key tag, an uncompressed Signer's Name
  (Section 3.1.7), and verbatim signature bytes.
- NSEC (RFC 4034 Section 4.1): an uncompressed Next Domain Name (Section 6.2)
  and a Type Bit Maps field.
- NSEC3 (RFC 5155 Section 3.2): hash algorithm, flags, iterations, a verbatim
  salt, the binary Next Hashed Owner Name, and a Type Bit Maps field.

The NSEC and NSEC3 Type Bit Maps are modeled as a `DnsTypeBitmaps` type-set that
sorts and deduplicates present RR types for deterministic minimal-window
encoding while preserving unknown or unassigned codepoints. NSEC3PARAM (51) and
KEY (25) stay `Raw`.

Decoding returns structured errors, never a panic, for RDATA that is too short
for the fixed fields, declares a length that overruns the record, or carries a
malformed type-bitmap window.

## Source-backed gaps closed in this pass

Earlier releases shipped a compact base layer. This pass closed the
source-backed gaps that the IANA DNS registries and the core RFC wire formats
surfaced, keeping section counts auto-filled, explicit values honored, and
unknown record data as `Raw`:

- Named codepoints are now exported. The IANA DNS Parameters registry opcodes
  (QUERY, IQUERY, STATUS, NOTIFY, UPDATE, DSO), response codes (NOERROR through
  the dynamic-update and extended BADxxx ranges), classes (IN, CH, HS, NONE,
  ANY), and the supported RR type table are available as `DNS_OPCODE_*`,
  `DNS_RCODE_*`, `DNS_CLASS_*`, and `DNS_TYPE_*` constants, with `opcode_value`
  and `rcode_value` accessors and `dns_type_name` mnemonics.
- The base RDATA formats with unambiguous wire layouts are typed: SOA (type 6)
  and SRV (type 33).
- The EDNS(0) OPT pseudo-record (type 41) is typed, exposing the UDP payload
  size and the extended RCODE/version/DO/Z fields from the reused CLASS and TTL
  plus a TLV list of options. See
  [EDNS(0) OPT pseudo-record](#edns0-opt-pseudo-record).
- The DNSSEC wire records (DS 43, DNSKEY 48, RRSIG 46, NSEC 47, NSEC3 50) are
  typed as wire structures, with no cryptographic validation. See
  [DNSSEC wire records](#dnssec-wire-records).
- The SVCB (64) and HTTPS (65) service-binding records are typed. See
  [Service binding records](#service-binding-records).

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

## Validation coverage

The DNS wire layer is validated against the oracle reference backend through the
`tools/oracle/` boundary. The suite validates packet construction, decode, and
capture behavior, not DNS client, resolver, or server semantics. All cases use
documentation address space and reserved names; offline is the default path and
real live exchange is opt-in. See [Oracle validation](validation.md) for the
boundary and command shapes.

The oracle cases and the deterministic crate fixtures together cover every
implemented DNS group:

- Header (transaction id, QR, AA/TC/RD/RA/AD/CD flags, user opcodes and rcodes,
  the raw flags escape hatch, auto-filled and empty section counts).
- Names and compression (root, trailing-dot, label-boundary, `\DDD`-escaped,
  non-UTF-8 labels, and compressed-name decode).
- Questions (single and multi-question, the QTYPE/QCLASS axes, and unknown
  numeric codepoints).
- A and AAAA address records.
- NS, CNAME, and PTR name records.
- MX and TXT records (including empty, binary, and 255-octet character-strings).
- SOA and SRV records.
- Unknown and intentionally deferred record types preserved as
  `DnsRecordData::Raw`.
- EDNS(0) OPT basic fields and the option TLV matrix.
- DNSSEC DS, DNSKEY, RRSIG, NSEC, and NSEC3 wire records.
- SVCB and HTTPS service binding.
- Section placement across answer, authority, and additional.
- Malformed names and malformed RDATA, asserted as structured errors with no
  panic.

A few features cannot be compared as strict reference bytes and use raw bytes or
a normalized-model comparison instead:

- Compressed names compare as the normalized decoded model: libcrafter
  re-encodes names uncompressed, so the decoded `DnsName` agrees while the wire
  bytes intentionally differ from the compressed reference input.
- SVCB/HTTPS RDATA is supplied as backend-owned raw bytes, because the reference
  backend's high-level SvcParam encoder re-interprets known keys; the crate
  keeps each SvcParamValue opaque.
- `\DDD` name escapes are flattened to literal text by the reference high-level
  encoder, so byte-faithful agreement for special labels is proven by the
  libcrafter encode direction and the byte-preserving crate name tests.
- Malformed inputs are covered by the deterministic crate corpus and
  `resilience.rs` structured-error assertions, not by an offline oracle
  comparison.

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

Registry (IANA DNS Service Bindings, `dns-svcb`):

- SVCB SvcParamKeys: mandatory (0), alpn (1), no-default-alpn (2), port (3),
  ipv4hint (4), ech (5), ipv6hint (6), dohpath (7), and the unassigned and
  private-use ranges. SvcParamValue formats stay opaque.

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
  wire format (SvcPriority, uncompressed TargetName, SvcParams in strictly
  increasing SvcParamKey order with no duplicates), and Section 2.5 special
  handling of the root `.` TargetName. SvcParamKey numbers and presentation names
  are defined in Section 7 and the IANA SvcParamKeys registry.
