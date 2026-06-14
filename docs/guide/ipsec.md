# IPSec Wire Coverage

This page describes the IPSec packet-layer support in the `crafter` crate: the
`Esp`, `Ah`, and IKEv2 layers, the `SecurityAssociation` crypto context, how
dependent fields (lengths, padding, next-header, ICV, IKE message length) are
filled on `compile()`, how deliberate overrides are preserved, how decoding
behaves with and without a security association, and what is intentionally out
of scope.

`crafter` exposes IPSec as a set of ordinary packet layers. ESP, AH, and the
IKEv2 message/payload set compose with `/` over IPv4 and IPv6, compile into a
single datagram, decode from the `decode_from_l3` entrypoints, and stay
inspectable through `summary()`, `show()`, `hexdump()`, and typed getters. They
slot into the same builder/decode/summary shape as every other layer.

IPSec here is a **wire-level primitive**, not a kernel security stack. There is
no Security Association Database (SAD), no Security Policy Database (SPD), no
anti-replay window, no IKEv2 negotiation state machine, no Diffie-Hellman key
agreement, and no key management. IKEv2 is **message and payload wire format
only**: round-trip construction and decoding. Keys are always supplied by the
caller. See [Explicit exclusions](#explicit-exclusions).

All wire facts on this page trace to reviewed RFC text and IANA registries. The
authoritative source record is
[`docs/internal/manifests/ipsec-rfc-manifest.md`](../internal/manifests/ipsec-rfc-manifest.md); this guide summarizes the
user-facing API built on top of that manifest.

## Coverage at a glance

| Area | State | Notes |
| --- | --- | --- |
| ESP (RFC 4303) | Supported | SPI + Sequence header, encrypted trailer (Pad/Pad Length/Next Header), ICV, transport and tunnel mode, over IPv4 and IPv6. |
| AH (RFC 4302) | Supported | Next Header, Payload Length, Reserved, SPI, Sequence, ICV over canonicalized immutable IP fields, transport and tunnel mode. |
| IKEv2 (RFC 7296) | Supported | 28-octet IKE header, generic payload chain, the standard payload set, and the Encrypted (SK) payload. Wire format only. |
| NAT-T (RFC 3948) | Supported | UDP-encapsulated ESP on UDP/4500 and the four-octet non-ESP marker (`NatTraversal`). |
| `SecurityAssociation` | Supported | Per-packet crypto context: SPI, mode, encryption/integrity algorithms, keys, salt, ESN flag. Not a SAD/SPD. |
| Encryption / AEAD | Supported | AES-GCM-16, AES-CCM-8, ChaCha20-Poly1305 (AEAD); AES-CBC, AES-CTR (cipher + separate integrity); NULL. |
| Integrity | Supported | HMAC-SHA-256-128 / -384-192 / -512-256, HMAC-SHA1-96, AES-XCBC-96, AES-GMAC. |
| Auto-filled fields | Supported | ESP pad / pad-length / next-header / ICV, AH Payload Length / ICV, SK IV / pad / ICV, IKE message length. |
| Deliberate overrides | Supported | Explicit SPI, sequence, IV, pad, ICV, next-header, AH Payload Length, and IKE length are emitted verbatim, including deliberately wrong values. |
| Decode with SA | Supported | `ProtocolRegistry::with_security_association` decrypts + verifies ESP, verifies AH, and decrypts the SK payload, then dispatches inner layers. |
| Decode without SA | Supported | SPI/Seq exposed; the encrypted body is preserved opaquely and re-compiles byte-for-byte. |
| Decode errors | Supported | Truncation, bad pad length, and ICV-mismatch return structured `CrafterError` values; never a panic or a silently wrong plaintext. |
| Inspection | Supported | `summary()`, `show()`, `hexdump()`, and per-field getters. Keys and salt bytes are never printed. |
| Pcap / oracle / probe coverage | Supported | Public API tests, golden byte locks, malformed corpus, deterministic fixtures, pcap round-trip, the ESP/AH/IKEv2 oracle profiles, and the `ipsec` behavioral probe profile. |

## The SecurityAssociation crypto context

ESP, AH, and the IKEv2 Encrypted (SK) payload are driven by a
`SecurityAssociation`: a lightweight, per-packet crypto context. It carries the
SPI, the [`IpsecMode`](#transport-and-tunnel-mode), the encryption and integrity
algorithms with their key material, the optional AEAD/CTR salt, and the ESN
flag. It is **not** a SAD/SPD entry: there is no policy lookup, no replay window,
and no key management.

Build one with the fluent, consuming builder. All examples use
documentation-only key material (fixed repeated bytes — never a real key):

```rust
use crafter::prelude::*;

// AES-GCM-16 (AEAD) transport-mode SA. AEAD supplies its own integrity, so no
// separate integrity algorithm is set; AEAD/CTR suites carry a salt.
let aead_sa = SecurityAssociation::new(0x0000_2000)
    .encryption(EncryptionAlgorithm::AesGcm16, vec![0x24u8; 16])
    .salt(vec![0xA1, 0xB2, 0xC3, 0xD4])
    .transport()
    .extended_sequence(false);
assert!(aead_sa.validate().is_ok());

// AES-CBC + HMAC-SHA-256-128: a cipher plus a separate integrity algorithm.
let cbc_sa = SecurityAssociation::new(0x0000_2800)
    .encryption(EncryptionAlgorithm::AesCbc, vec![0x11u8; 16])
    .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x33u8; 32])
    .transport();
assert!(cbc_sa.validate().is_ok());

// Integrity-only SA for AH (AH never encrypts).
let ah_sa = SecurityAssociation::new(0x0000_3000)
    .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x33u8; 32])
    .transport();
assert!(ah_sa.validate().is_ok());
```

`SecurityAssociation::new(spi)` defaults to transport mode, `NULL` encryption
with no key, `NONE` integrity with no key, an empty salt, and ESN disabled.

`validate()` checks that key and salt lengths match the algorithm metadata and
returns a structured `CrafterError::InvalidFieldValue` (on `ipsec.sa.enc_key`,
`ipsec.sa.salt`, or `ipsec.sa.integ_key`) when they do not. It **never** mutates
the caller's values — a deliberately wrong key is reported, not silently
corrected, so malformed packets remain buildable by skipping `validate()`.
`Unknown` algorithms carry no length metadata and validate as-is.

### Encryption and integrity algorithms

`EncryptionAlgorithm` and `IntegrityAlgorithm` map the IANA IKEv2 transform IDs
to the crypto primitives. Each unrecognized transform ID is preserved as
`Unknown(u16)` rather than rejected, so a decoded SA proposal round-trips its
codepoint.

| `EncryptionAlgorithm` | IKEv2 ID | Kind | Key | IV | Salt | ICV | RFC |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AesGcm16` | 20 | AEAD | 16 | 8 | 4 | 16 | 4106 |
| `AesCcm8` | 14 | AEAD | 16 | 8 | 3 | 8 | 4309 |
| `ChaCha20Poly1305` | 28 | AEAD | 32 | 8 | 4 | 16 | 7634 |
| `AesCbc` | 12 | cipher + integrity | 16 | 16 | 0 | — | 3602 |
| `AesCtr` | 13 | cipher + integrity | 16 | 8 | 4 | — | 3686 |
| `Null` | 11 | none | — | 0 | 0 | — | 2410 |

| `IntegrityAlgorithm` | IKEv2 ID | ICV octets | RFC |
| --- | --- | --- | --- |
| `HmacSha2_256_128` | 12 | 16 | 4868 |
| `HmacSha2_384_192` | 13 | 24 | 4868 |
| `HmacSha2_512_256` | 14 | 32 | 4868 |
| `HmacSha1_96` | 2 | 12 | 2404 |
| `AesXcbc96` | 5 | 12 | 3566 |
| `AesGmac` | 9 | 16 | 4543 |
| `None` | 0 | — | — |

AEAD suites pair with `IntegrityAlgorithm::None`: the AEAD tag is the ICV. The
non-AEAD ciphers (`AesCbc`, `AesCtr`) require a separate `IntegrityAlgorithm`.
`EncryptionAlgorithm::is_aead()`, `key_len()`, `iv_len()`, `salt_len()`,
`block_size()`, and `icv_len()` expose the metadata.

### Transport and tunnel mode

`IpsecMode::Transport` protects the upper-layer payload of a single IP datagram;
`IpsecMode::Tunnel` protects an entire inner IP datagram (RFC 4301 §3.2). The SA
carries the mode so `compile()` and decode know whether the protected Next
Header is an upper-layer protocol or an inner IP version. Select it with
`.transport()` (the default) or `.tunnel()`.

## Building ESP

ESP is the `Esp` layer. Compose it under an IP layer that advertises ESP
(protocol 50, or `IPPROTO_IPV6_ESP` as an IPv6 next-header). `Esp::secured(sa)`
attaches the SA that seals the protected data; the following layers are the
plaintext that ESP encrypts and consumes.

### Transport mode, AEAD (AES-GCM)

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let sa = SecurityAssociation::new(0x0000_2100)
    .encryption(EncryptionAlgorithm::AesGcm16, vec![0x24u8; 16])
    .salt(vec![0xA1, 0xB2, 0xC3, 0xD4])
    .transport();

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(Ipv4Addr::new(198, 51, 100, 20))
    .protocol(IPPROTO_ESP)
    / Esp::secured(sa).spi(0x0000_2100).sequence(1).iv(vec![1, 2, 3, 4, 5, 6, 7, 8])
    / Tcp::new().sport(40001).dport(443)
    / Raw::from("esp-gcm");

let compiled = packet.compile()?;
println!("{}", packet.summary());
# Ok::<(), crafter::CrafterError>(())
```

For an AEAD suite, the explicit IV precedes the ciphertext, the AAD is
`SPI || Seq` (plus the high-order 32 ESN bits when ESN is enabled), and the
authentication tag becomes the ICV. The TCP/Raw tail is encrypted *inside* the
ESP body, so there is no cleartext copy of it on the wire.

### Transport mode, CBC + HMAC

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let sa = SecurityAssociation::new(0x0000_2800)
    .encryption(EncryptionAlgorithm::AesCbc, vec![0x11u8; 16])
    .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x33u8; 32])
    .transport();

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(Ipv4Addr::new(198, 51, 100, 20))
    .protocol(IPPROTO_ESP)
    / Esp::secured(sa).spi(0x0000_2800).sequence(1).iv((0u8..16).collect::<Vec<u8>>())
    / Tcp::new().sport(41000).dport(443)
    / Raw::from("esp-cbc-hmac");
# let _ = packet;
```

For a cipher + separate integrity suite, the payload, padding, pad-length, and
next-header are padded to the cipher block size per RFC 4303 §2.4, the explicit
IV precedes the ciphertext (RFC 3602), and a separately computed ICV (HMAC over
`SPI || Seq || IV || ciphertext`, plus the ESN high bits when enabled) is
appended after the ciphertext.

### Tunnel mode

Tunnel mode protects an entire inner IP datagram. Use a tunnel-mode SA and place
a complete inner IP stack after `Esp`:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let sa = SecurityAssociation::new(0x0000_2700)
    .encryption(EncryptionAlgorithm::AesGcm16, vec![0x24u8; 16])
    .salt(vec![0xA1, 0xB2, 0xC3, 0xD4])
    .tunnel();

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(Ipv4Addr::new(198, 51, 100, 20))
    .protocol(IPPROTO_ESP)
    / Esp::secured(sa).spi(0x0000_2700).sequence(1).iv(vec![1, 2, 3, 4, 5, 6, 7, 8])
    / Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 71))
        .dst(Ipv4Addr::new(198, 51, 100, 72))
        .protocol(IPPROTO_TCP)
    / Tcp::new().sport(33000).dport(22)
    / Raw::from("esp-tunnel");
# let _ = packet;
```

The ESP Next Header is the inner IP version (4 for IPv4-in-IPv4, 41 for
IPv6-in-IPv6) instead of an upper-layer protocol number.

### NULL and opaque (no-SA) ESP

`EncryptionAlgorithm::Null` builds an authenticated-or-bare ESP datagram with no
confidentiality, routed through the same path. To emit an ESP datagram whose
body is already-sealed opaque bytes (for example, replaying a captured payload),
use `Esp::new()` with `.opaque(bytes)` and no SA. Without an SA, `compile()`
emits `SPI || Seq || opaque-body` verbatim.

## Building AH

AH is the `Ah` layer. It **authenticates but never encrypts**: the protected
upper layer (or inner IP datagram) travels in the clear, and AH appends an ICV
computed over the canonicalized immutable IP fields, the AH header with its ICV
field zeroed, and the upper-layer data (RFC 4302 §3.3). Use an integrity-only
SA. Compose AH under an IP layer that advertises AH (protocol 51, or
`IPPROTO_IPV6_AH`).

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let sa = SecurityAssociation::new(0x0000_3100)
    .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x33u8; 32])
    .transport();

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(Ipv4Addr::new(198, 51, 100, 20))
    .protocol(IPPROTO_AH)
    .ttl(64)
    / Ah::secured(sa).spi(0x0000_3100).sequence(1)
    / Tcp::new().sport(43000).dport(443)
    / Raw::from("ah-v4");

let compiled = packet.compile()?;
# let _ = compiled;
# Ok::<(), crafter::CrafterError>(())
```

The mutable IP fields are zeroed for the ICV input (IPv4: DS field, Flags +
Fragment Offset, TTL, Header Checksum; IPv6: Traffic Class, Flow Label, Hop
Limit, and mutable extension-header option data) per RFC 4302 §3.3.3.1. AH works
over IPv4 and IPv6 and in tunnel mode (a complete inner IP datagram after `Ah`,
where the AH Next Header is the inner IP version).

## Building IKEv2 messages

IKEv2 is **message and payload wire format only**: there is no negotiation state
machine, no key derivation, and no Diffie-Hellman. The `IkeHeader` layer plus
the typed payload set round-trip the bytes.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

// One proposal carrying an ENCR transform (AES-128) and a D-H group transform.
let proposal = Proposal::new(1, PROTOCOL_ID_IKE)
    .with_transform(
        Transform::new(TRANSFORM_TYPE_ENCR, 20)
            .with_attribute(TransformAttribute::key_length(128)),
    )
    .with_transform(Transform::new(TRANSFORM_TYPE_DH, DH_GROUP_MODP_2048));

let header = IkeHeader::new()
    .initiator_spi(0x0102_0304_0506_0708)
    .exchange(IKE_SA_INIT)
    .initiator();

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(Ipv4Addr::new(198, 51, 100, 20))
    .protocol(IPPROTO_UDP)
    / Udp::new().sport(500).dport(500)
    / header
    / IkeSaPayload::new().with_proposal(proposal)
    / IkeKePayload::new(DH_GROUP_MODP_2048, vec![0xAB; 32])
    / IkeNoncePayload::new(vec![0x5A; 16]);

let compiled = packet.compile()?;
# let _ = compiled;
# Ok::<(), crafter::CrafterError>(())
```

The payload set is reachable through `crafter::prelude::*`: `IkeSaPayload`
(with `Proposal` / `Transform` / `TransformAttribute`), `IkeKePayload`,
`IkeNoncePayload`, `IkeNotifyPayload`, `IkeDeletePayload`, `IkeIdPayload`,
`IkeAuthPayload`, `IkeTsPayload`, `IkeCertPayload`, `IkeCertReqPayload`,
`IkeVendorIdPayload`, `IkeConfigPayload`, `IkeEapPayload`, and
`IkeEncryptedPayload`. Each is an ordinary `Layer`; `compile()` derives the
Next Payload chain from the order the payloads were composed and fills the IKE
message length.

### The Encrypted (SK) payload

`IkeEncryptedPayload` owns its inner payload chain and seals it under an SA. The
SK body is `IV || encrypted(inner || pad || pad-length) || ICV`:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let sk_sa = SecurityAssociation::new(0x0000_4400)
    .encryption(EncryptionAlgorithm::AesGcm16, vec![0x24u8; 16])
    .salt(vec![0xA1, 0xB2, 0xC3, 0xD4]);

let sk = IkeEncryptedPayload::new(sk_sa)
    .iv(vec![1, 2, 3, 4, 5, 6, 7, 8])
    .payload(IkeIdPayload::initiator_ipv4(Ipv4Addr::new(192, 0, 2, 10)))
    .payload(IkeAuthPayload::new(AuthMethod::SharedKeyMic, vec![0x9Au8; 8]));

let header = IkeHeader::new()
    .initiator_spi(0x1122_3344_5566_7788)
    .responder_spi(0x99AA_BBCC_DDEE_FF00)
    .exchange(IKE_AUTH)
    .initiator();

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(Ipv4Addr::new(198, 51, 100, 20))
    .protocol(IPPROTO_UDP)
    / Udp::new().sport(500).dport(500)
    / header
    / sk;
# let _ = packet;
```

The SK payload is always the last payload of a message (it owns the inner chain
rather than emitting siblings). The generic-header Next Payload names the first
inner payload's type.

## NAT-T (UDP-encapsulated ESP)

RFC 3948 carries ESP over UDP/4500 and disambiguates it from IKE with a
four-octet non-ESP (all-zero) marker. UDP-encapsulated ESP is just `Udp` on port
4500 followed by `Esp`; an IKE message over UDP/4500 is prefixed by the marker
layer `non_esp_marker()` (the `NatTraversal` layer):

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let sa = SecurityAssociation::new(0x0000_4500)
    .encryption(EncryptionAlgorithm::AesGcm16, vec![0x24u8; 16])
    .salt(vec![0xA1, 0xB2, 0xC3, 0xD4]);

// UDP-encapsulated ESP (no marker).
let esp_over_4500 = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(Ipv4Addr::new(198, 51, 100, 20))
    .protocol(IPPROTO_UDP)
    / Udp::new().sport(4500).dport(4500)
    / Esp::secured(sa).spi(0x0000_4500).sequence(1).iv(vec![1, 2, 3, 4, 5, 6, 7, 8])
    / Tcp::new().sport(48000).dport(443)
    / Raw::from("natt-esp");
# let _ = esp_over_4500;
```

## Auto-filled fields and honored overrides

`compile()` fills the fields the caller left unset and emits any caller-set
field verbatim — including a deliberately wrong one for malformed testing.

| Layer | Field | Auto-filled from | Override setter |
| --- | --- | --- | --- |
| `Esp` | SPI | the attached SA's SPI (else default 1) | `.spi(u32)` |
| `Esp` | Sequence | default 1 | `.sequence(u32)` |
| `Esp` | IV | the algorithm IV (default all-zero unless pinned) | `.iv(bytes)` |
| `Esp` | Padding | RFC 4303 §2.4 alignment to the cipher block | `.pad(bytes)` |
| `Esp` | Pad Length | the number of padding octets | — |
| `Esp` | Next Header | the protected protocol (transport) or inner IP version (tunnel) | `.next_header(u8)` |
| `Esp` | ICV | the AEAD tag or the separate integrity MAC | `.icv(bytes)` |
| `Esp` | high ESN word | 0 (added to AAD only when the SA's ESN is set) | `.high_sequence(u32)` |
| `Ah` | Payload Length | header + padded ICV length, in 32-bit words minus 2 | `.payload_len(u8)` |
| `Ah` | Reserved | 0 | `.reserved(u16)` |
| `Ah` | Next Header | the protected protocol or inner IP version | `.next_header(u8)` |
| `Ah` | ICV | the integrity MAC over the canonicalized input, boundary-padded | `.icv(bytes)` |
| `IkeHeader` | Next Payload | the first composed payload's type | `.next_payload(u8)` |
| `IkeHeader` | Length | 28 + the payload bytes that follow | `.length(u32)` |
| `IkeEncryptedPayload` | IV / pad / pad-length / ICV | the SA crypto parameters | `.iv(bytes)` / `.pad(bytes)` / `.icv(bytes)` |
| generic payload | Next Payload / Length | derived from the chain | per-payload setters |

A caller-set value is never rewritten just because it is unusual. An explicit
pad, IV, ICV, AH Payload Length, or IKE Length is emitted as requested, which is
exactly what a generated tool needs to build malformed packets that exercise a
peer's stack.

## Decoding

Use `Packet::decode_from_l3(NetworkLayer::Ipv4 | NetworkLayer::Ipv6, bytes)` (or
the link-layer decoders) for raw datagrams. The protocol registry routes
protocol 50 to ESP, 51 to AH, UDP/500 to IKEv2, and UDP/4500 to either the
non-ESP marker + IKEv2 or UDP-encapsulated ESP.

### Decoding without an SA (opaque)

The built-in registry carries no SA. ESP and AH decode as typed headers, and the
encrypted/protected body is preserved opaquely so the datagram re-compiles
byte-for-byte:

```rust
use crafter::prelude::*;

let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
let esp = decoded.layer::<Esp>().expect("typed ESP header");
assert_eq!(esp.spi_value(), Some(0x0000_2100));
assert!(esp.opaque_body().is_some(), "no SA: the body stays encrypted");

// The decoded packet re-compiles to the original wire bytes.
assert_eq!(decoded.compile()?.as_bytes(), bytes);
# Ok::<(), crafter::CrafterError>(())
```

An IKEv2 message decodes its Next Payload chain into typed payloads with no SA;
an SK payload decodes as opaque bytes, and unknown payload types decode as a
preserved `Raw` payload.

### Decoding with an SA

Register a `SecurityAssociation` on the registry to decrypt and verify. SAs are
keyed by SPI; `ProtocolRegistry::with_security_association(sa)` (or
`register_security_association`) attaches one. The SA-aware path verifies the
ESP ICV (constant-time), decrypts the body, strips the RFC 4303 padding, exposes
the ESP Next Header, and dispatches the inner protocol (transport) or inner IP
(tunnel) as nested typed layers. For AH it re-verifies the ICV and records a
verified status. For an SK payload it decrypts and re-verifies the inner chain.

```rust
use crafter::prelude::*;

let sa = SecurityAssociation::new(0x0000_2100)
    .encryption(EncryptionAlgorithm::AesGcm16, vec![0x24u8; 16])
    .salt(vec![0xA1, 0xB2, 0xC3, 0xD4])
    .transport();

let registry = ProtocolRegistry::new().with_security_association(sa);
let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, bytes)?;

// The inner TCP / Raw are recovered as typed layers.
let tcp = decoded.layer::<Tcp>().expect("inner TCP decrypted");
assert_eq!(tcp.destination_port_value(), 443);
# Ok::<(), crafter::CrafterError>(())
```

For AH, inspect the verification status:

```rust
use crafter::prelude::*;

let registry = ProtocolRegistry::new().with_security_association(ah_sa);
let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, bytes)?;
let ah = decoded.layer::<Ah>().expect("typed AH");
assert_eq!(ah.verification_status(), Some(true), "the SA verifies the AH ICV");
# Ok::<(), crafter::CrafterError>(())
```

Without an SA, `verification_status()` is `None`; with a matching SA that
verifies, it is `Some(true)`. A verification *mismatch* never becomes
`Some(false)` — it fails the decode with a structured error instead (below).

### Structured decode errors

Decoding malformed or tampered input returns a structured `CrafterError`; it
never panics and never yields a silently wrong plaintext.

- **Truncation** — a buffer too short for the ESP/AH/IKE header, the IV, the
  trailer, or the ICV is a `CrafterError::BufferTooShort` carrying `context`,
  `required`, and `available`.
- **Bad ESP pad length** — a pad length that overruns the decrypted plaintext,
  or padding that fails the RFC 4303 §2.4 monotonic check for a block cipher, is
  a `CrafterError::InvalidFieldValue` on `esp.pad_length`.
- **ESP integrity failure** — a one-bit change to the ciphertext or ICV fails
  the AEAD/MAC check and surfaces as a `CrafterError::InvalidFieldValue` on
  `ipsec.sa.icv`. Decoding fails closed: no decrypted bytes are exposed.
- **AH integrity failure** — a change to any protected immutable field or to the
  upper-layer data fails verification with a `CrafterError::InvalidFieldValue` on
  `ipsec.ah.icv`.
- **Oversized AH Payload Length / runaway Next Payload chain** — an
  AH Payload Length that overruns the buffer, or an IKE Next Payload chain that
  runs off the end, returns a structured error rather than reading out of bounds.

## Inspection

Every IPSec packet stays inspectable, and **key and salt bytes are never
printed** — only SPIs, sequence numbers, mode labels, algorithm labels, and
lengths.

- `SecurityAssociation::summary()` renders, for example,
  `SA(spi=0x00002000, mode=transport, enc=AES_GCM_16, integ=NONE, esn=false)`.
  The `Debug` impl redacts key/salt bytes as `<N bytes redacted>`.
- `Esp` summary: `Esp(spi=0x..., seq=..., enc=..., mode=...)`.
- `Ah` summary: `Ah(spi=0x..., seq=..., integ=..., nh=...)`.
- `Packet::summary()` joins each layer's one-line summary; `Packet::show()`
  prints the full field tree; `hexdump()` produces a canonical byte dump.

```rust
use crafter::prelude::*;

let sa = SecurityAssociation::new(0x0000_2000)
    .encryption(EncryptionAlgorithm::AesGcm16, vec![0xDEu8; 16])
    .salt(vec![0xBEu8; 4]);

println!("{}", sa.summary());
// The key byte 0xDE never appears in the rendered summary or debug output.
assert!(!sa.summary().to_lowercase().contains("dede"));
```

The decoded `summary()` and `show()` of a packet that was decrypted with an SA
likewise never expose the SA's key, salt, or integrity-key material.

## Validation coverage

IPSec behavior is covered by offline crate tests, deterministic fixtures, an
oracle parity suite, and a behavioral probe profile:

- `crafter/tests/ipsec_public_api.rs` pins prelude-only construction, compile
  output, decode with and without an SA, ESP/AH transport and tunnel over IPv4
  and IPv6, the IKE_SA_INIT and IKE_AUTH (SK) round-trips, NAT-T, tamper
  detection, and the no-key-leak inspection contract.
- `crafter/tests/ipsec_golden.rs` locks pinned wire bytes for ESP (AES-GCM and
  CBC+HMAC), AH (HMAC-SHA-256-128), and IKE_SA_INIT.
- `crafter/tests/fixtures/bytes/` and `crafter/tests/fixtures/pcaps/raw-ipsec-esp-ah-ikev2.pcap`
  carry deterministic ESP/AH/IKEv2 fixtures, cataloged in `fixture_suite.rs` and
  exercised through pcap round-trip.
- `crafter/tests/fixtures/malformed/ipsec-decode-corpus.hex` and the
  `resilience.rs` IPSec module assert structured-error / no-panic behavior for
  truncated, bad-pad, short-ICV, and tampered inputs, including SA-bearing
  tamper cases.
- `tools/oracle/specs/layers/{esp,ah,ikev2}.yaml` and
  `tools/oracle/specs/features/{esp-aead,esp-cbc,ah-integrity,ikev2-header,ikev2-payloads,*-malformed}.yaml`
  drive offline byte/decode parity and pcap round-trip against the oracle
  reference backend; the `esp`, `ah`, `ikev2`, and `ipsec-smoke` profiles in
  `tools/oracle/specs/profiles.yaml` select them. Malformed cases are excluded
  from byte comparison as `structured_error`.
- `tools/probe/engine/cases.py` defines the `ipsec` behavioral profile (ESP/AH
  transport + tunnel and an IKE_SA_INIT exchange) and an engine-level
  cross-crypto parity check — libcrafter-sealed ESP/AH/SK opened by the reference
  crypto and vice versa — that runs deterministically without a network.
  `--dry-run` is the default; live execution against a controlled IPSec-capable
  peer is opt-in through providers and lab sessions.

All documented examples use documentation address space (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and documentation-only key
material with offline construction or decode. Live raw traffic remains opt-in
through the crate's live send, capture, provider, and lab-session APIs.

## Explicit exclusions

`crafter` stays a packet primitive. The IPSec layers do **not** implement:

- A Security Association Database (SAD) or Security Policy Database (SPD),
  policy lookup, or anti-replay window enforcement. The `SecurityAssociation` is
  a per-packet crypto context; sequence numbers and ESN are built and parsed,
  but replay acceptance is not a crate concern.
- A full IKEv2 negotiation state machine, Diffie-Hellman key agreement,
  SK_d/keymat derivation, EAP method logic, or rekey/liveness timers. IKEv2 is
  message wire format only.
- Automatic key management or PKI. Keys are supplied by the caller.
- A kernel IPSec stack, packet forwarding, tunnel-interface management, or live
  traffic policy.

The fields and crypto needed to build or inspect these packets are present; the
workflows that decide when to send them belong outside the crate primitive.

## Evidence

Protocol facts above come from
[`docs/internal/manifests/ipsec-rfc-manifest.md`](../internal/manifests/ipsec-rfc-manifest.md). The source set, in brief:

- **RFC 4303** — ESP header/trailer format, padding (§2.4), ICV placement, and
  transport/tunnel framing.
- **RFC 4302** — AH header format, Payload Length encoding, ICV scope, and the
  immutable-field canonicalization (§3.3.3.1).
- **RFC 7296** — the IKE header, generic payload header, payload set, and the
  Encrypted (SK) payload.
- **RFC 3948** — NAT-T: UDP/4500, the non-ESP marker, and UDP-encapsulated ESP.
- **RFC 4301** — transport vs. tunnel mode, the SA concept, and the SPI.
- **RFC 8221** — the current MUST/SHOULD/MAY algorithm requirements that select
  the transform coverage.
- **RFC 4106 / 4309 / 7634 / 3602 / 3686 / 2410** — the encryption and AEAD
  transforms (AES-GCM, AES-CCM, ChaCha20-Poly1305, AES-CBC, AES-CTR, NULL).
- **RFC 4868 / 2404 / 3566 / 4543** — the integrity transforms (HMAC-SHA-2,
  HMAC-SHA1-96, AES-XCBC-96, AES-GMAC).
- **IANA IKEv2 Parameters** and **IANA Assigned Internet Protocol Numbers** —
  the transform IDs, payload types, and ESP/AH protocol numbers (50 / 51).
```
