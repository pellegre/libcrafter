# IPSec RFC Manifest

This manifest records the source-backed RFC/IANA evidence that `crafter` uses
to construct and decode IPSec packets: ESP, AH, IKEv2 message/payload wire
format, NAT-T (UDP-encapsulated ESP), and the cryptographic transforms that
drive them. It is the authority every later step cites for codepoints, field
widths, and algorithm parameters. Model memory may suggest where to look, but
only the sources listed here are authority for serialized bytes.

Date checked: 2026-06-08 (RFC Editor and the IANA "Internet Key Exchange
Version 2 (IKEv2) Parameters" and "Assigned Internet Protocol Numbers"
registries reviewed on this date).

The `rfc-protocol-bootstrap` / `rfc-protocol-spec` discovery workflow was run
for the IPSec protocol family. The curated source set below — not noisy
discovery output and not model memory — is the authority for this work.

## Scope

`crafter` exposes IPSec as a wire-level packet primitive that generated tools
build on. It is **not** a kernel-style security stack. Matching `spec.md`:

- **ESP** (RFC 4303) and **AH** (RFC 4302) are first-class layers with real
  confidentiality/integrity, in transport and tunnel mode, composing with `/`
  over IPv4 and IPv6.
- **IKEv2** (RFC 7296) is **message and payload wire format only**: the IKE
  header, the generic-payload chain, the standard payload set, and the
  Encrypted (SK) payload. Round-trip construction and decoding only.
- **NAT-T** (RFC 3948): UDP-encapsulated ESP and the non-ESP marker.
- A lightweight `SecurityAssociation` carries SPI, mode, algorithms, keys,
  salt, and ESN flag. It is a **per-packet crypto context**, not a database.

Explicitly **out of scope** (no serialized behavior depends on these):

- A full IKEv2 negotiation state machine, Diffie-Hellman key agreement,
  SK_d/keymat derivation, EAP method logic, or rekey/liveness timers. IKEv2 is
  wire format only.
- A kernel-style Security Association Database (SAD) or Security Policy
  Database (SPD), policy lookup, or anti-replay window enforcement. Sequence
  numbers and ESN are built and parsed; replay acceptance is not a crate
  concern.
- Automatic key management or PKI. Keys are supplied by the caller.

## Source Authority And How To Read This Manifest

"Normative for wire behavior" means the source defines bytes that `crafter`
must construct, fill, or decode correctly. "Registry authority" means IANA is
the current source for names, numeric assignments, or registry status.
"Guidance only" informs documentation, diagnostics, or exclusions but does not
add a serialized field by itself.

## Source Set

### Architecture and core protocols (normative for wire behavior)

| RFC | Title | Role in `crafter` |
| --- | --- | --- |
| RFC 4301 | Security Architecture for the Internet Protocol | Defines the IPSec architecture, transport vs. tunnel mode, the SA concept, and the SPI. Guidance for mode semantics; `crafter` models packets, not the SAD/SPD it describes. |
| RFC 4302 | IP Authentication Header (AH) | Normative AH header format, Payload Length encoding, ICV scope, and the mutable-field canonicalization (§3.3.3.1) used for ICV computation. |
| RFC 4303 | IP Encapsulating Security Payload (ESP) | Normative ESP header/trailer format, padding rules (§2.4), Pad/Pad Length/Next Header trailer, ICV placement, and transport/tunnel framing. |
| RFC 7296 | Internet Key Exchange Protocol Version 2 (IKEv2) | Normative IKE header (28 bytes), generic payload header (4 bytes), payload set, and the Encrypted (SK) payload format. |
| RFC 3948 | UDP Encapsulation of IPsec ESP Packets | Normative NAT-T framing: UDP/4500, the 4-byte non-ESP marker, and UDP-encapsulated ESP disambiguation. |

### Algorithm requirements (registry authority + guidance)

| RFC | Title | Role in `crafter` |
| --- | --- | --- |
| RFC 8221 | Cryptographic Algorithm Implementation Requirements and Usage Guidance for ESP and AH | Current MUST/SHOULD/MAY status for ESP/AH encryption and integrity algorithms; selects the transform coverage below. Updates RFC 7321. |

### Cryptographic transforms (normative for wire behavior)

| RFC | Title | Role in `crafter` |
| --- | --- | --- |
| RFC 4106 | The Use of Galois/Counter Mode (GCM) in IPsec ESP | AES-GCM AEAD: nonce = salt(4) ‖ IV(8), AAD = SPI‖Seq (‖ ESN high bits), 16-byte ICV for `ENCR_AES_GCM_16`. |
| RFC 4309 | Using AES CCM Mode with IPsec ESP | AES-CCM AEAD framing; `ENCR_AES_CCM_8` (8-byte ICV). |
| RFC 3602 | The AES-CBC Cipher Algorithm and Its Use with IPsec | AES-CBC: explicit IV precedes ciphertext; pad to 16-byte block; separate integrity. |
| RFC 3686 | Using AES Counter Mode With IPsec ESP | AES-CTR: explicit IV/counter block layout; separate integrity. |
| RFC 3566 | The AES-XCBC-MAC-96 Algorithm and Its Use With IPsec | `AUTH_AES_XCBC_96` integrity (96-bit truncated MAC). |
| RFC 4543 | The Use of Galois Message Authentication Code (GMAC) in IPsec ESP and AH | `AUTH_AES_GMAC` / AES-GMAC integrity (also `ENCR_NULL_AUTH_AES_GMAC` for ESP). |
| RFC 4868 | Using HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with IPsec | HMAC-SHA-2 integrity with truncation: SHA-256→128, SHA-384→192, SHA-512→256. |
| RFC 2404 | The Use of HMAC-SHA-1-96 within ESP and AH | Legacy `AUTH_HMAC_SHA1_96` (96-bit truncated MAC). |
| RFC 2410 | The NULL Encryption Algorithm and Its Use With IPsec | `ENCR_NULL`: no confidentiality, 1-byte block, no IV. |
| RFC 7634 | ChaCha20, Poly1305, and Their Use in the IKE and IPsec | `ENCR_CHACHA20_POLY1305` AEAD: 8-byte explicit IV, 4-byte salt, 16-byte tag. |

### Registry sources (registry authority)

- **IANA, Assigned Internet Protocol Numbers** — authority for IP protocol
  numbers **50 (ESP)** and **51 (AH)**.
  https://www.iana.org/assignments/protocol-numbers/
- **IANA, Internet Key Exchange Version 2 (IKEv2) Parameters** — authority for
  IKEv2 Exchange Types, Payload Types, Transform Type and Transform ID values,
  and Notify Message Types.
  https://www.iana.org/assignments/ikev2-parameters/

## IP Protocol Numbers (IANA Assigned Internet Protocol Numbers)

| Number | Keyword | Protocol | Defining RFC |
| ---: | --- | --- | --- |
| 50 | ESP | Encapsulating Security Payload | RFC 4303 |
| 51 | AH | Authentication Header | RFC 4302 |

These appear in the IPv4 `Protocol` field and the IPv6 `Next Header` field (and
in any preceding extension header's Next Header). The constants
`IPPROTO_ESP = 50` and `IPPROTO_AH = 51` already exist in
`crafter/src/protocols/ip/shared/protocol_numbers.rs` with their `esp`/`ah`
display labels and the `Ipv4Protocol::Esp` / `::Ah` variants; later steps must
reuse them, not redefine them.

## ESP Wire Format (RFC 4303 §2)

ESP frames a (possibly encrypted) payload between a fixed header and an
encrypted trailer, with the ICV appended last.

| Field | Width | Source-backed behavior |
| --- | ---: | --- |
| Security Parameters Index (SPI) | 32 bits | Identifies the SA. Values 0–255 are reserved (RFC 4303 §2.1). |
| Sequence Number | 32 bits | Monotonic per-SA counter; with Extended Sequence Numbers (ESN) the low 32 bits are on the wire and the high 32 bits feed integrity only (RFC 4303 §2.2.1). |
| Payload Data | variable | Protected data; for CBC/CTR/AEAD the explicit IV precedes the ciphertext (RFC 3602/3686/4106). |
| Padding | 0–255 bytes | Aligns the trailer so Pad Length and Next Header end on a 4-byte boundary and meets the cipher's block size (RFC 4303 §2.4). |
| Pad Length | 8 bits | Number of padding bytes (RFC 4303 §2.5). |
| Next Header | 8 bits | IP protocol number of the protected payload (transport mode) or the inner IP version (tunnel mode), using the IANA protocol-number space (RFC 4303 §2.6). |
| Integrity Check Value (ICV) | variable | Present when integrity is in effect; an integral multiple of 32 bits sized by the integrity/AEAD algorithm (RFC 4303 §2.8). For AEAD this is the authentication tag. |

Trailer order on the wire (the encrypted region for non-AEAD, the ciphertext +
tag for AEAD): `Payload Data ‖ Padding ‖ Pad Length ‖ Next Header`, followed by
the ICV. Padding plus the 2 trailing bytes must make the encrypted region a
multiple of the cipher block size, and the whole ESP must be a multiple of
4 bytes (RFC 4303 §2.4). With **no SA supplied**, `crafter` parses SPI and
Sequence Number and preserves the remaining bytes as opaque ciphertext that
re-compiles byte-for-byte.

## AH Wire Format (RFC 4302 §2)

AH provides integrity and data-origin authentication with no confidentiality.

| Field | Width | Source-backed behavior |
| --- | ---: | --- |
| Next Header | 8 bits | IP protocol number of the data after AH (RFC 4302 §2.1). |
| Payload Length | 8 bits | Length of AH **in 32-bit words, minus 2** (RFC 4302 §2.2). For the common default ICV the value is computed from header + ICV length. |
| Reserved | 16 bits | Sent as zero, ignored on receipt, but **included in the ICV** (RFC 4302 §2.3). |
| Security Parameters Index (SPI) | 32 bits | Identifies the SA; values 0–255 reserved (RFC 4302 §2.4). |
| Sequence Number | 32 bits | Per-SA counter; ESN puts the high 32 bits into the ICV only (RFC 4302 §2.5). |
| Integrity Check Value (ICV) | variable | Integral multiple of 32 bits; padded to a 32-bit boundary for IPv4 and a 64-bit boundary for IPv6 so the total datagram length constraints hold (RFC 4302 §2.6). |

The AH ICV is computed over: the immutable IP header fields (mutable fields
zeroed, see below), the AH header **with the ICV field set to zero**, and the
upper-layer protocol data, treating mutable-but-predictable fields as their
final-destination value (RFC 4302 §3.3.3).

### AH Immutable-Field Rules (RFC 4302 §3.3.3.1)

Before ICV computation the sender and receiver canonicalize the IP header by
zeroing the fields that change in transit ("mutable") and using the predicted
final value for mutable-but-predictable fields.

**IPv4 (RFC 4302 §3.3.3.1.1).** Fields classified *Mutable (zeroed prior to ICV
calculation)*:

> Differentiated Services Code Point (DSCP) (6 bits, see RFC 2474), Explicit
> Congestion Notification (ECN) (2 bits, see RFC 3168), Flags, Fragment Offset,
> Time to Live (TTL), Header Checksum

The remaining base-header fields (Version, IHL, Total Length, Identification,
Protocol, Source Address, Destination Address) are immutable and covered as-is.
IPv4 options are handled per their option type (§3.3.3.1.1.2): some options are
immutable and covered, others are zeroed.

**IPv6 base header (RFC 4302 §3.3.3.1.2.1).** Fields classified *Mutable (zeroed
prior to ICV calculation)*:

> DSCP (6 bits, see RFC 2474), ECN (2 bits, see RFC 3168), Flow Label, Hop Limit

The remaining base-header fields (Version, Payload Length, Next Header, Source
Address, Destination Address) are immutable and covered as-is. IPv6 extension
headers are handled per §3.3.3.1.2.2: mutable extension-header fields are zeroed
and the destination-options/routing semantics use final-destination values.

`crafter`'s AH ICV input therefore is: canonicalized immutable IP header
(IPv4 mutable: DSCP+ECN, Flags+Fragment Offset, TTL, Header Checksum; IPv6
mutable: DSCP+ECN, Flow Label, Hop Limit) ‖ AH header with ICV zeroed ‖
upper-layer data.

## IKEv2 Message Wire Format (RFC 7296)

### IKE Header — 28 bytes (RFC 7296 §3.1)

| Field | Width | Source-backed behavior |
| --- | ---: | --- |
| IKE SA Initiator's SPI | 64 bits | Cookie/SPI chosen by the initiator. |
| IKE SA Responder's SPI | 64 bits | Zero in the first `IKE_SA_INIT` request; set by the responder thereafter. |
| Next Payload | 8 bits | Payload type of the first payload in the message (see Payload Types). |
| Major/Minor Version | 8 bits | `0x20` for IKEv2 (major 2, minor 0). |
| Exchange Type | 8 bits | See Exchange Types. |
| Flags | 8 bits | Bit 3 Initiator (I), bit 4 Version (V), bit 5 Response (R) (RFC 7296 §3.1). |
| Message ID | 32 bits | Per-exchange counter for matching requests and responses. |
| Length | 32 bits | Total message length (header + all payloads) in octets; `crafter` auto-fills this when unset. |

### Generic Payload Header — 4 bytes (RFC 7296 §3.2)

| Field | Width | Source-backed behavior |
| --- | ---: | --- |
| Next Payload | 8 bits | Payload type of the next payload in the chain, or 0 to end the chain. |
| Critical (C) + Reserved | 8 bits | High bit is the Critical flag; remaining 7 bits reserved (sent zero). |
| Payload Length | 16 bits | Length of this payload including the generic header, in octets. |

A `Next Payload` of **0** terminates the payload chain. Unknown payload types
whose Critical bit is clear are skipped/preserved; `crafter` decodes unknown
payload types as a preserved `Raw` payload.

### IKEv2 Exchange Types (IANA IKEv2 Parameters)

| Value | Exchange |
| ---: | --- |
| 34 | IKE_SA_INIT |
| 35 | IKE_AUTH |
| 36 | CREATE_CHILD_SA |
| 37 | INFORMATIONAL |

(Values 0–33 are reserved/unused for IKEv2 exchanges; 38+ such as
IKE_SESSION_RESUME (38) and IKE_INTERMEDIATE (43) are later extensions outside
this scope. The four above, 34–37, are the RFC 7296 core set.)

### IKEv2 Payload Types (IANA IKEv2 Parameters; RFC 7296 §3.2)

| Value | Payload | Notation |
| ---: | --- | --- |
| 0 | No Next Payload | (chain terminator) |
| 33 | Security Association | SA |
| 34 | Key Exchange | KE |
| 35 | Identification - Initiator | IDi |
| 36 | Identification - Responder | IDr |
| 37 | Certificate | CERT |
| 38 | Certificate Request | CERTREQ |
| 39 | Authentication | AUTH |
| 40 | Nonce | Ni, Nr |
| 41 | Notify | N |
| 42 | Delete | D |
| 43 | Vendor ID | V |
| 44 | Traffic Selector - Initiator | TSi |
| 45 | Traffic Selector - Responder | TSr |
| 46 | Encrypted and Authenticated | SK |
| 47 | Configuration | CP |
| 48 | Extensible Authentication | EAP |
| 49 | Generic Secure Password Method | GSPM |

The **SK (Encrypted, type 46)** payload layout is: IV ‖ encrypted inner
payloads ‖ Padding ‖ Pad Length ‖ Integrity Check Value, driven by the SA
(RFC 7296 §3.14). With an SA supplied, `crafter` decrypts and re-verifies; with
no SA, the body is preserved opaque.

### IKEv2 Transform Substructure (RFC 7296 §3.3.2)

Each Transform inside an SA Proposal carries a Transform Type and a Transform
ID. The relevant Transform Types (IANA IKEv2 Parameters):

| Type | Meaning |
| ---: | --- |
| 1 | Encryption Algorithm (ENCR) |
| 2 | Pseudo-random Function (PRF) |
| 3 | Integrity Algorithm (INTEG) |
| 4 | Key Exchange Method (KE / former D-H Group) |
| 5 | Extended Sequence Numbers (ESN) |

Transform Type 1 — Encryption Algorithm Transform IDs (the set in plan.md):

| ID | Name | Defining RFC | Notes |
| ---: | --- | --- | --- |
| 11 | ENCR_NULL | RFC 2410 | No confidentiality. |
| 12 | ENCR_AES_CBC | RFC 3602 | Cipher + separate integrity. |
| 13 | ENCR_AES_CTR | RFC 3686 | Cipher + separate integrity. |
| 14 | ENCR_AES_CCM_8 | RFC 4309 | AEAD, 8-byte ICV. |
| 20 | ENCR_AES_GCM_16 | RFC 4106 | AEAD, 16-byte ICV (MUST per RFC 8221). |
| 28 | ENCR_CHACHA20_POLY1305 | RFC 7634 | AEAD (SHOULD per RFC 8221). |

Transform Type 3 — Integrity Algorithm Transform IDs (the set in plan.md):

| ID | Name | Defining RFC | Notes |
| ---: | --- | --- | --- |
| 2 | AUTH_HMAC_SHA1_96 | RFC 2404 | Legacy. |
| 5 | AUTH_AES_XCBC_96 | RFC 3566 | 96-bit truncated MAC. |
| 9 | AUTH_AES_128_GMAC | RFC 4543 | AES-GMAC (128-bit key variant). |
| 12 | AUTH_HMAC_SHA2_256_128 | RFC 4868 | MUST per RFC 8221. |
| 13 | AUTH_HMAC_SHA2_384_192 | RFC 4868 | |
| 14 | AUTH_HMAC_SHA2_512_256 | RFC 4868 | |

### IKEv2 Notify Message Types (IANA IKEv2 Parameters; RFC 7296 §3.10.1)

Notify Message Types referenced by later steps. Types 1–16383 are errors;
16384–65535 are status. Representative codepoints:

| Value | Class | Name |
| ---: | --- | --- |
| 7 | Error | INVALID_SYNTAX |
| 14 | Error | NO_PROPOSAL_CHOSEN |
| 17 | Error | INVALID_KE_PAYLOAD |
| 24 | Error | AUTHENTICATION_FAILED |
| 16388 | Status | INITIAL_CONTACT |
| 16389 | Status | SET_WINDOW_SIZE |
| 16390 | Status | ADDITIONAL_TS_POSSIBLE |
| 16391 | Status | IPCOMP_SUPPORTED |
| 16392 | Status | NAT_DETECTION_SOURCE_IP |
| 16393 | Status | NAT_DETECTION_DESTINATION_IP |
| 16394 | Status | COOKIE |
| 16395 | Status | USE_TRANSPORT_MODE |
| 16396 | Status | HTTP_CERT_LOOKUP_SUPPORTED |
| 16397 | Status | REKEY_SA |
| 16398 | Status | ESP_TFC_PADDING_NOT_SUPPORTED |
| 16399 | Status | NON_FIRST_FRAGMENTS_ALSO |

The IANA "IKEv2 Notify Message Types - Status Types / Error Types" registries
remain the authority; `crafter` preserves unknown Notify types verbatim.

## NAT-T / UDP Encapsulation (RFC 3948)

UDP-encapsulated ESP runs over **UDP destination port 4500**. Disambiguation
within UDP/4500 (RFC 3948 §2.1, §2.2):

| First 4 bytes of UDP payload | Interpretation |
| --- | --- |
| All zero (the "Non-ESP Marker") | An IKE message follows (IKEv2 over UDP/4500). |
| Non-zero (a valid ESP SPI, which must not be 0) | A UDP-encapsulated ESP packet follows. |

IKE on the classic **UDP port 500** has no marker. `crafter`'s registry binds
UDP/500 to IKEv2 directly, and UDP/4500 to a predicate that routes the 4-byte
zero marker to IKEv2 and everything else to UDP-encapsulated ESP. The ESP SPI
of zero is reserved, which is what makes the zero marker unambiguous (RFC 3948
§2.2).

## Algorithm Coverage Status (RFC 8221)

The transforms `crafter` implements and the requirement level that selects them
(RFC 8221, which updates RFC 7321). Each transform is verified against a
Known-Answer Test from its defining RFC (or referenced test-vector RFC) before
ESP/AH/SK uses it.

| Transform | IKEv2 ID | RFC 8221 status | Defining RFC |
| --- | --- | --- | --- |
| ENCR_AES_GCM_16 | ENCR 20 | MUST | RFC 4106 |
| ENCR_CHACHA20_POLY1305 | ENCR 28 | SHOULD | RFC 7634 |
| ENCR_AES_CCM_8 | ENCR 14 | MAY | RFC 4309 |
| ENCR_AES_CBC | ENCR 12 | MAY (with separate integrity) | RFC 3602 |
| ENCR_AES_CTR | ENCR 13 | MAY (with separate integrity) | RFC 3686 |
| ENCR_NULL | ENCR 11 | MUST (for AH-equivalent / integrity-only ESP) | RFC 2410 |
| AUTH_HMAC_SHA2_256_128 | INTEG 12 | MUST | RFC 4868 |
| AUTH_HMAC_SHA2_384_192 | INTEG 13 | MAY | RFC 4868 |
| AUTH_HMAC_SHA2_512_256 | INTEG 14 | MAY | RFC 4868 |
| AUTH_AES_XCBC_96 | INTEG 5 | MAY | RFC 3566 |
| AUTH_AES_128_GMAC | INTEG 9 | MAY | RFC 4543 |
| AUTH_HMAC_SHA1_96 | INTEG 2 | MUST- (legacy, being deprecated) | RFC 2404 |

The exact RFC 8221 keyword for each algorithm should be re-checked against the
RFC when a crypto step depends on the requirement level; the column above is the
selection rationale, and the defining RFC is the authority for each transform's
serialized bytes and KAT.
