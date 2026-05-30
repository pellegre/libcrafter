# DNS Scapy Coverage Matrix

This matrix inventories every DNS wire feature implemented on the
`feature/complete-dns` branch under `crafter/src/protocols/dns/` and maps each
one to the oracle cases that will prove it against Scapy. It is the source of
truth for the planned DNS oracle expansion (plan
`dns-scapy-protocol-coverage`, steps 2 through 29). Later steps add the spec
entries, materializers, normalization, and the cases listed here; this document
is the coverage contract they implement against.

## How to read this matrix

Each row names one implemented DNS feature and records:

- **Case ID** — the oracle case `name` used in
  `tools/oracle/specs/fixtures/scapy-cases.json` and the feature/layer specs.
  Case IDs follow the existing convention: `dns-*` for offline Scapy<->crafter
  cases, `crafter-dns-*` for cases whose canonical source is a libcrafter
  vector, and `malformed-dns-*` for structured-error decode cases.
- **Directions** — which oracle directions the case exercises:
  `reference_to_libcrafter` (Scapy or Scapy-owned raw bytes are the source),
  `libcrafter_to_reference` (a libcrafter `Packet` is the source), or both. The
  case `direction` field in the fixture uses the equivalent
  `scapy_to_libcrafter` / `libcrafter_to_scapy` spellings.
- **Byte policy** — `strict_bytes` when the deterministic uncompressed encode
  must match Scapy octet-for-octet, or `normalized` when libcrafter normalizes
  the wire shape on encode (for example compressed input, sorted SvcParams, or
  minimal type bitmaps) so only the normalized decoded DNS model must agree. A
  `normalized` policy row documents the specific non-strict difference.
- **Scapy high-level?** — `yes` when Scapy can build the packet shape from its
  own high-level fields (`DNS`, `DNSQR`, `DNSRR`, and typed RDATA fields),
  `partial` when Scapy builds the frame but the RDATA must be supplied as
  Scapy-owned raw bytes, and `no` when Scapy has no helper and the case uses a
  Scapy-owned raw byte string or `DNSRR(type=N, rdata=...)` raw RDATA as the
  reference boundary.
- **Raw bytes needed?** — `yes` when the case must use Scapy-owned raw bytes,
  raw DNS RDATA, or a hand-built byte string because Scapy lacks a typed
  encoder for the feature; `no` when Scapy's typed fields suffice.

When Scapy lacks a high-level helper, the case still uses Scapy as the
reference boundary: it either decodes Scapy-owned raw bytes, or feeds raw RDATA
through `DNSRR`/`DNSQR`, or compares the normalized decoded DNS model. No case
asserts against libcrafter alone.

All addresses, names, and payloads in every case use documentation space
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, and the
`example.com` / `example.net` / `example.org` reserved names).

## Implementation surface inventoried

Source read for this matrix:

- `crafter/src/protocols/dns/mod.rs` — `Dns` layer, header, section vectors,
  message decode, UDP port-53 dispatch, `dns_type_name`.
- `crafter/src/protocols/dns/name.rs` — byte-preserving `DnsName`,
  presentation escaping, compressed-name decode and its rejections.
- `crafter/src/protocols/dns/record.rs` — `DnsQuestion`, `DnsRecord`, and the
  typed record builders including the OPT pseudo-record and its EDNS accessors.
- `crafter/src/protocols/dns/rdata.rs` — `DnsRecordData` variants and the
  per-type RDATA codec, including `Raw` fallback.
- `crafter/src/protocols/dns/edns.rs` — `EdnsOption` and OPT TTL packing.
- `crafter/src/protocols/dns/dnssec.rs` — `DnsTypeBitmaps` and the DNSSEC
  RDATA round trips.
- `crafter/src/protocols/dns/svcb.rs` — `SvcParam` / `SvcParams` and the
  SVCB/HTTPS RDATA codec.
- `crafter/src/protocols/dns/constants.rs` — codepoints.
- `docs/dns.md` — the user-facing coverage statement this matrix matches.

## 1. Header / flags

| Feature | Case ID | Directions | Byte policy | Scapy high-level? | Raw bytes needed? |
| --- | --- | --- | --- | --- | --- |
| Transaction id (deterministic + boundary 0x0000 / 0xffff) | `dns-header-id` | both | strict_bytes | yes | no |
| QR query vs response | `dns-header-qr` | both | strict_bytes | yes | no |
| AA, TC, RD, RA flag bits | `dns-header-flags` | both | strict_bytes | yes | no |
| User-specified opcode (QUERY, STATUS, UPDATE, NOTIFY, unknown 0xf) | `dns-header-opcode` | both | strict_bytes | yes (`DNS(opcode=...)`) | no |
| User-specified rcode (NOERROR, SERVFAIL, NXDOMAIN, REFUSED, unknown 0xf) | `dns-header-rcode` | both | strict_bytes | yes (`DNS(rcode=...)`) | no |
| Raw flags word escape hatch (AD, CD, Z bits, unusual combos) | `dns-header-raw-flags` | both | strict_bytes | yes (`DNS(...)` with explicit bits) | no |
| Section counts auto-filled from typed vectors | `dns-header-counts` | both | strict_bytes | yes | no |
| Empty sections (qdcount/ancount/nscount/arcount = 0) | `dns-header-empty-sections` | both | strict_bytes | yes | no |

## 2. Names / compression

| Feature | Case ID | Directions | Byte policy | Scapy high-level? | Raw bytes needed? |
| --- | --- | --- | --- | --- | --- |
| Root name `.` | `dns-name-root` | both | strict_bytes | yes | no |
| Trailing-dot text name | `dns-name-trailing-dot` | both | strict_bytes | yes | no |
| 63-octet label boundary | `dns-name-label-boundary` | both | strict_bytes | yes | no |
| Escaped presentation name (`\DDD`) | `dns-name-escaped` | both | strict_bytes | partial (raw qname bytes) | yes |
| Non-text label (non-UTF-8 octets, `\000`, `\255`) | `dns-name-non-text` | both | strict_bytes | no | yes |
| Combined root + escaped + non-UTF-8 names in one message (root question owner, trailing-dot answer, literal dot/backslash CNAME target, `\000`/`\255` PTR target) | `dns-name-root-escaped` | both | strict_bytes (header + section counts compared) | no (Scapy high-level flattens `\DDD`/`\.`/`\\` to literal text on encode, so the reference encode is not byte-faithful; libcrafter re-encodes the exact octets, so the `libcrafter_to_reference` bytes are faithful and the `crafter` name tests carry the lossless byte-preserving assertions) | partial (faithful only via libcrafter encode) |
| Compressed-name decode (pointer to earlier name) | `dns-name-compressed` | reference_to_libcrafter | normalized: libcrafter emits the uncompressed name on re-encode, so the decoded `DnsName` model must agree while bytes differ from the compressed Scapy input | partial (Scapy compresses; raw bytes pin the pointer) | yes |
| Explicit compression pointers across owner names and embedded RDATA <domain-name> fields (compressed question/answer owner names plus pointers in CNAME, NS, PTR, MX exchange, SOA MNAME/RNAME, SRV target, RRSIG signer, NSEC next-domain, and SVCB/HTTPS target RDATA, all built by the Scapy raw helper) | `dns-compressed-names` | reference_to_libcrafter | normalized: libcrafter re-encodes every name uncompressed, so the decoded `DnsName` model agrees while bytes differ from the raw pointer input | no (Scapy raw DNS helper pins the `0xC0` pointers; high-level fields will not emit them) | yes |
| Compressed NS/CNAME/PTR name records (owner and embedded RDATA names are `0xC0` pointers in the Scapy raw bytes) | `dns-name-records-compressed` | reference_to_libcrafter | normalized: libcrafter re-encodes every name uncompressed, so the decoded `DnsRecordData::Name` model agrees with `dns-name-records` while bytes differ from the raw pointer input | no (Scapy raw DNS helper pins the pointers) | yes |
| Uncompressed deterministic encode (no compression by default) | `crafter-dns-name-uncompressed` | libcrafter_to_reference | strict_bytes | yes | no |

## 3. Questions

| Feature | Case ID | Directions | Byte policy | Scapy high-level? | Raw bytes needed? |
| --- | --- | --- | --- | --- | --- |
| Single A/IN question | `dns-query` (existing) | both | strict_bytes | yes | no |
| Multiple questions, mixed QTYPE | `dns-multiple-questions` (existing) | both | strict_bytes | yes | no |
| Multiple questions spanning the QTYPE and QCLASS axes (A/AAAA/MX/TXT/ANY + unknown numeric QTYPE; IN/CH/HS/NONE/ANY + unknown numeric QCLASS) in one deterministic ordered query | `dns-multi-question-classes` | both | strict_bytes | partial (named QTYPE/QCLASS via `DNSQR`; numeric for the private-use codepoints) | no |
| QCLASS variants (IN, CH, HS, NONE, ANY) | `dns-question-class` | both | strict_bytes | yes (`DNSQR(qclass=...)`) | no |
| Unknown numeric QTYPE / QCLASS | `dns-question-unknown-codes` | both | strict_bytes | partial (numeric qtype/qclass) | no |

## 4. Base RDATA

| Feature | Case ID | Directions | Byte policy | Scapy high-level? | Raw bytes needed? |
| --- | --- | --- | --- | --- | --- |
| A (type 1) | `dns-record-a` | both | strict_bytes | yes | no |
| AAAA (type 28) | `dns-record-aaaa` | both | strict_bytes | yes | no |
| NS (type 2) | `dns-record-ns` | both | strict_bytes | yes | no |
| CNAME (type 5) | `dns-record-cname` | both | strict_bytes | yes | no |
| PTR (type 12) | `dns-record-ptr` | both | strict_bytes | yes | no |
| MX (type 15) preference + exchange | `dns-record-mx` | both | strict_bytes | yes | no |
| TXT (type 16) char-strings (single, multiple, empty, 255-byte) | `dns-record-txt` | both | strict_bytes | yes | no |
| Existing combined response (A/AAAA/CNAME) | `dns-response-records` (existing) | both | strict_bytes | yes | no |
| Combined NS/CNAME/PTR name records (`DnsRecordData::Name`, root-adjacent CNAME target, reverse-DNS PTR owner) | `dns-name-records` | both | strict_bytes | yes | no |

## 5. SOA / SRV

| Feature | Case ID | Directions | Byte policy | Scapy high-level? | Raw bytes needed? |
| --- | --- | --- | --- | --- | --- |
| SOA (type 6) MNAME/RNAME + 5 fixed fields | `dns-record-soa` | both | strict_bytes | yes (`DNSRRSOA`) | no |
| SRV (type 33) priority/weight/port/target | `dns-record-srv` | both | strict_bytes | yes (`DNSRRSRV`) | no |

## 6. Raw fallback

| Feature | Case ID | Directions | Byte policy | Scapy high-level? | Raw bytes needed? |
| --- | --- | --- | --- | --- | --- |
| Unknown RR type decodes to `DnsRecordData::Raw` (not mis-typed) | `dns-record-raw-unknown` | both | strict_bytes | partial (`DNSRR(type=N, rdata=...)` raw RDATA) | yes |
| Intentionally deferred typed RR stays `Raw` (NSEC3PARAM 51, KEY 25, NAPTR 35, TLSA 52) | `dns-record-raw-deferred` | both | strict_bytes | partial (raw RDATA) | yes |
| Zero-length RDATA under unknown type stays `Raw` empty | `dns-record-raw-empty` | both | strict_bytes | partial (raw RDATA) | yes |

## 7. EDNS

| Feature | Case ID | Directions | Byte policy | Scapy high-level? | Raw bytes needed? |
| --- | --- | --- | --- | --- | --- |
| OPT (type 41) bare record, UDP payload size in CLASS | `dns-edns-opt-basic` | both | strict_bytes | yes (`DNSRROPT`) | no |
| OPT TTL fields: extended RCODE, version, DO flag, Z bits | `dns-edns-opt-ttl-fields` | both | strict_bytes | yes (`DNSRROPT` z/extrcode/version) | no |
| EDNS option TLVs: NSID, COOKIE, Padding | `dns-edns-options-known` | both | strict_bytes | partial (`EDNS0TLV` raw option data) | yes |
| Unknown EDNS option code round trips verbatim | `dns-edns-options-unknown` | both | strict_bytes | partial (`EDNS0TLV(optcode=N)`) | yes |

## 8. DNSSEC

| Feature | Case ID | Directions | Byte policy | Scapy high-level? | Raw bytes needed? |
| --- | --- | --- | --- | --- | --- |
| DS (type 43) key tag / algorithm / digest type / digest | `dns-dnssec-ds` | both | strict_bytes | partial (raw digest bytes) | yes |
| DNSKEY (type 48) flags / protocol / algorithm / key | `dns-dnssec-dnskey` | both | strict_bytes | partial (raw key bytes) | yes |
| RRSIG (type 46) fixed fields + uncompressed signer name + signature | `dns-dnssec-rrsig` | both | strict_bytes | partial (raw signature bytes) | yes |
| NSEC (type 47) next name + type bitmaps (RFC 4034 4.3 example) | `dns-dnssec-nsec` | both | strict_bytes (matches the RFC example bytes) | partial (raw bitmap or `DNSRRNSEC`) | yes |
| NSEC type bitmap multi-window + unknown codepoint (TYPE1234) | `dns-dnssec-nsec-bitmap` | both | normalized: libcrafter sorts/dedups and emits minimal windows, so the decoded type set must agree even if the source byte order differs | partial (raw bitmap bytes) | yes |
| NSEC3 (type 50) hash alg / flags / iterations / salt / next hash / bitmaps | `dns-dnssec-nsec3` | both | strict_bytes | partial (raw salt/hash/bitmap bytes) | yes |
| NSEC3 empty salt | `dns-dnssec-nsec3-empty-salt` | both | strict_bytes | partial (raw bytes) | yes |
| Unknown algorithm / digest-type values preserved verbatim | `dns-dnssec-unknown-algorithm` | both | strict_bytes | partial (raw RDATA) | yes |

## 9. SVCB / HTTPS

| Feature | Case ID | Directions | Byte policy | Scapy high-level? | Raw bytes needed? |
| --- | --- | --- | --- | --- | --- |
| SVCB (type 64) AliasMode (priority 0), real target, no params | `dns-svcb-alias` | both | strict_bytes | partial (raw RDATA or `DNSRRSVCB`) | yes |
| SVCB ServiceMode with sorted SvcParams (alpn, port, ipv4hint) | `dns-svcb-service` | both | normalized: libcrafter sorts SvcParamKeys into strictly increasing order on encode, so an out-of-order source compares by the normalized decoded SvcParams model | partial (raw RDATA) | yes |
| SVCB/HTTPS root target `.` | `dns-svcb-root-target` | both | strict_bytes | partial (raw RDATA) | yes |
| HTTPS (type 65) ServiceMode with params | `dns-https-service` | both | strict_bytes | partial (raw RDATA) | yes |
| Unknown SvcParamKey round trips verbatim | `dns-svcb-unknown-param` | both | strict_bytes | partial (raw RDATA) | yes |

## 10. Section placement

| Feature | Case ID | Directions | Byte policy | Scapy high-level? | Raw bytes needed? |
| --- | --- | --- | --- | --- | --- |
| Answer-section records | covered by `dns-response-records` | both | strict_bytes | yes | no |
| Authority-section records (SOA / NS in `ns`) | `dns-section-authority` | both | strict_bytes | yes (`DNS(ns=...)`) | no |
| Additional-section records (OPT in `ar`) | `dns-section-additional` | both | strict_bytes | yes (`DNS(ar=...)`) | no |
| Multi-section response (answer + authority + additional) | `dns-section-multi` | both | strict_bytes | yes | no |

## 11. Malformed names

| Feature | Case ID | Directions | Byte policy | Scapy high-level? | Raw bytes needed? |
| --- | --- | --- | --- | --- | --- |
| Compressed-name pointer cycle | `malformed-dns-pointer-cycle` | reference_to_libcrafter | n/a (structured error, no panic) | no | yes |
| Out-of-range / impossible pointer offset | `malformed-dns-pointer-range` | reference_to_libcrafter | n/a (structured error) | no | yes |
| Truncated pointer / truncated question | `malformed-dns-truncated-name` | reference_to_libcrafter | n/a (structured error) | no | yes |
| Reserved label-length marker (0b10) | `malformed-dns-reserved-marker` | reference_to_libcrafter | n/a (structured error) | no | yes |
| Label / full-name length overrun (>63, >255) | `malformed-dns-name-overrun` | reference_to_libcrafter | n/a (structured error) | no | yes |
| Trailing bytes after declared records | `malformed-dns-trailing-bytes` | reference_to_libcrafter | n/a (structured error) | no | yes |

## 12. Malformed RDATA

| Feature | Case ID | Directions | Byte policy | Scapy high-level? | Raw bytes needed? |
| --- | --- | --- | --- | --- | --- |
| A / AAAA wrong rdlength | `malformed-dns-address-rdlength` | reference_to_libcrafter | n/a (structured error) | no | yes |
| SOA wrong fixed-tail length | `malformed-dns-soa-rdlength` | reference_to_libcrafter | n/a (structured error) | no | yes |
| SRV short header / trailing bytes | `malformed-dns-srv-boundary` | reference_to_libcrafter | n/a (structured error) | no | yes |
| EDNS option length overrun / truncated header | `malformed-dns-edns-option` | reference_to_libcrafter | n/a (structured error) | no | yes |
| DNSSEC fixed-header truncation (DS, DNSKEY, RRSIG) | `malformed-dns-dnssec-truncation` | reference_to_libcrafter | n/a (structured error) | no | yes |
| NSEC3 salt / hash length overrun | `malformed-dns-nsec3-overrun` | reference_to_libcrafter | n/a (structured error) | no | yes |
| Type-bitmap malformed (zero length, >32, out-of-order window, trailing zero) | `malformed-dns-bitmap` | reference_to_libcrafter | n/a (structured error) | no | yes |
| SVCB duplicate / out-of-order keys, value length overrun, truncated param | `malformed-dns-svcb-params` | reference_to_libcrafter | n/a (structured error) | no | yes |
| Encode rejection: TXT >255, EDNS option >65535, record-data/type mismatch | `malformed-dns-encode-reject` | libcrafter_to_reference | n/a (encode error) | no | no |

## 13. Offline

Every case above must have a forced offline oracle run (no live network, no
Scapy send). Offline is the default path and the acceptance baseline.

| Coverage | Case ID | Notes |
| --- | --- | --- |
| Forced offline run for all DNS cases | (all `dns-*`, `crafter-dns-*`, `malformed-dns-*`) | Offline materialize + decode + compare; no provider, no capture. |

## 14. Pcap

Every representable (non-malformed-by-byte-truncation) DNS case must round trip
through deterministic pcap write/read.

| Coverage | Case ID | Notes |
| --- | --- | --- |
| Pcap round trip for representable DNS cases | (all `dns-*` and `crafter-dns-*`) | Deterministic pcap bytes; malformed truncation cases that cannot frame are excluded and stay decode-error fixtures. |

## 15. Live dry-run

Every live-eligible DNS case must default to a provider-backed dry-run send
plan. Real packet exchange is gated behind `--confirm-live-run` and the
protected provider workflow; it is never part of ordinary acceptance. Live byte
comparison tolerates documented in-transit mutation while preserving DNS
semantic comparison.

| Coverage | Case ID | Notes |
| --- | --- | --- |
| Live dry-run plan for all live-eligible DNS cases | (all `dns-*` and `crafter-dns-*`) | Default `--dry-run` send plan in documentation address space; malformed decode-only cases are not live-eligible. |
| Protected live exchange (opt-in only) | same case IDs under `--confirm-live-run` | Not run by default; semantic DNS comparison tolerates documented in-transit mutation. |

## Summary of byte-comparison policy

- **strict_bytes** is the default for every deterministic uncompressed encode:
  header/flags, questions, base RDATA, SOA/SRV, OPT, the fixed DNSSEC RDATA
  fields, and uncompressed names.
- **normalized** is required only where libcrafter deterministically rewrites
  the wire shape on encode and the rewrite is documented in the case row:
  compressed-name input (`dns-name-compressed`, `dns-compressed-names`), sorted
  SvcParams (`dns-svcb-service`), and minimal/sorted type bitmaps
  (`dns-dnssec-nsec-bitmap`).
- **structured error** rows assert a typed `CrafterError` context with no
  panic, in line with the malformed-input requirement.
