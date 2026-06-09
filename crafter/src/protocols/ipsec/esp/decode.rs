//! ESP opaque (no-SA) decode and the registry append hook (RFC 4303).
//!
//! Without keys a receiver cannot decrypt or strip the ESP trailer (RFC 4303
//! §3.4.2). The crate's contract is to surface what *is* parseable — the
//! unencrypted SPI and Sequence Number — and preserve the remaining encrypted
//! body (IV + ciphertext + trailer + ICV) as opaque bytes that re-compile
//! byte-for-byte. Truncation before the 8-octet header is a structured error,
//! never a panic. Mirrors UDP's `decode_<proto>_parts` /
//! `append_<proto>_packet_with_registry` shape.

use crate::endian::read_u32_be;
use crate::error::{CrafterError, Result};
use crate::packet::Packet;
use crate::protocols::ip::shared::protocol_numbers::IPPROTO_IPV6;
use crate::protocols::ipsec::sa::{open, SecurityAssociation};
use crate::registry::ProtocolRegistry;

use super::header::{ESP_HEADER_LEN, ESP_NEXT_HEADER_FIELD_LEN, ESP_PAD_LENGTH_FIELD_LEN};
use super::Esp;

/// IP protocol number for IPv4-in-IP encapsulation (tunnel-mode inner IPv4).
///
/// IANA assigns protocol number 4 to "IPv4 encapsulation". The shared
/// `protocol_numbers` table has no constant for it, so the ESP decode carries a
/// local one to recognize a tunnel-mode inner IPv4 datagram via the ESP trailer
/// Next Header (RFC 4303 §2.6). The inner IPv6 case uses the shared
/// [`IPPROTO_IPV6`] (41).
const IPPROTO_IPV4: u8 = 4;

/// Decode an ESP datagram with no Security Association into an opaque [`Esp`].
///
/// The fixed header is the Security Parameters Index (4 octets) and the
/// Sequence Number (4 octets); both are stored as caller-set fields so a
/// re-compile reproduces them exactly. Everything after the header — the
/// explicit IV, ciphertext, encrypted trailer, and ICV — is captured verbatim
/// in the `opaque` body, which `compile()` emits unchanged (see
/// `Esp::compile_opaque`). No inner protocol is dispatched: without keys there
/// is no plaintext to decode.
///
/// A buffer shorter than the 8-octet ESP header yields a structured
/// [`CrafterError::buffer_too_short`] carrying `context`, `required`, and
/// `available` — never a panic.
pub(crate) fn decode_esp_opaque(bytes: &[u8]) -> Result<Esp> {
    if bytes.len() < ESP_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "esp header",
            ESP_HEADER_LEN,
            bytes.len(),
        ));
    }

    let spi = read_u32_be(&bytes[0..4])?;
    let sequence = read_u32_be(&bytes[4..8])?;

    // SPI and Sequence become caller-set fields; the rest is the opaque body.
    // `Esp::spi` / `Esp::sequence` mark the fields `Field::user`, and
    // `Esp::opaque` stores `Some(..)`, so the round-trip is byte-exact.
    Ok(Esp::new()
        .spi(spi)
        .sequence(sequence)
        .opaque(bytes[ESP_HEADER_LEN..].to_vec()))
}

/// The result of decoding an ESP datagram with a matching SA (Step 17).
///
/// Carries the typed [`Esp`] header layer recovered from the wire alongside the
/// decrypted, pad-stripped inner plaintext and the ESP trailer fields the
/// receiver needs to dispatch the inner protocol. The inner-protocol dispatch
/// itself (building the nested transport/IP layers from `next_header` and
/// `plaintext`) is wired by a later step; this type exposes the recovered pieces
/// so that decode and tests can verify the round-trip.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DecodedEsp {
    /// The decoded ESP header layer (SPI / Sequence as caller-set fields).
    pub esp: Esp,
    /// The recovered upper-layer plaintext with the ESP trailer stripped
    /// (`pad || pad-length || next-header` removed; RFC 4303 §2.4–2.6).
    pub plaintext: Vec<u8>,
    /// The ESP trailer Next Header octet (RFC 4303 §2.6): the protected
    /// upper-layer protocol (transport mode) or inner IP version (tunnel mode).
    pub next_header: u8,
    /// The ESP trailer Pad Length octet (RFC 4303 §2.4): how many pad octets
    /// preceded the Pad Length / Next Header fields inside the ciphertext.
    pub pad_length: u8,
}

/// Resolve the on-wire ICV (authentication tag) length in octets for `sa`.
///
/// For AEAD suites (AES-GCM/CCM/ChaCha20) the ICV is the AEAD tag, whose length
/// comes from the encryption algorithm. For cipher + separate-integrity suites
/// it comes from the integrity algorithm. A suite with neither (NULL + NONE)
/// carries no ICV (length 0).
fn sa_icv_len(sa: &SecurityAssociation) -> usize {
    if sa.enc.is_aead() {
        sa.enc.icv_len().unwrap_or(0)
    } else {
        sa.integ.icv_len().unwrap_or(0)
    }
}

/// Decode an ESP datagram with the matching SA: verify, decrypt, strip padding.
///
/// Splits `bytes` into `SPI || Seq || IV || ciphertext || ICV` using the SA's
/// explicit-IV length ([`EncryptionAlgorithm::iv_len`]) and ICV length
/// ([`sa_icv_len`]), then drives the [`open`] crypto primitive (Step 09):
///
/// - The AAD is `SPI || Seq` — the ESP header octets verbatim (RFC 4303 §3.4.4;
///   the high-order ESN bits are folded in by Step 20). `open` verifies the ICV
///   in constant time (cipher+integrity) or via the AEAD tag, decrypting only on
///   a match. On an integrity failure `open`'s structured error is propagated
///   unchanged and no plaintext is returned — the decode fails closed.
/// - On success the recovered plaintext is `inner || pad || pad-length ||
///   next-header`. The trailing Next Header and Pad Length octets are read, the
///   Pad Length is validated against the remaining length, and (for block
///   ciphers) the pad octets are checked to follow the RFC 4303 §2.4 monotonic
///   `1, 2, 3, …` pattern. A bad pad yields a structured
///   [`CrafterError::invalid_field_value`] on `esp.pad_length`.
///
/// Returns a [`DecodedEsp`] carrying the [`Esp`] header layer (with the decoded
/// SPI/Sequence as caller-set fields), the pad-stripped inner plaintext, and the
/// recovered Pad Length / Next Header. A buffer too short to hold the header, IV,
/// trailer, and ICV is a structured [`CrafterError::buffer_too_short`].
///
/// [`EncryptionAlgorithm::iv_len`]: crate::protocols::ipsec::sa::EncryptionAlgorithm::iv_len
#[allow(dead_code)]
pub(crate) fn decode_esp_with_sa(bytes: &[u8], sa: &SecurityAssociation) -> Result<DecodedEsp> {
    let iv_len = sa.enc.iv_len();
    let icv_len = sa_icv_len(sa);

    // The datagram must hold at least the 8-octet header, the explicit IV, the
    // trailing ICV, and the two fixed trailer octets (pad-length + next-header).
    let trailer_fixed = ESP_PAD_LENGTH_FIELD_LEN + ESP_NEXT_HEADER_FIELD_LEN;
    let minimum = ESP_HEADER_LEN + iv_len + icv_len + trailer_fixed;
    if bytes.len() < minimum {
        return Err(CrafterError::buffer_too_short(
            "esp datagram",
            minimum,
            bytes.len(),
        ));
    }

    let spi = read_u32_be(&bytes[0..4])?;
    let sequence = read_u32_be(&bytes[4..8])?;

    // AAD = SPI || Seq (the unencrypted ESP header). ESN high bits: Step 20.
    let aad = &bytes[0..ESP_HEADER_LEN];
    let iv = &bytes[ESP_HEADER_LEN..ESP_HEADER_LEN + iv_len];
    let icv_start = bytes.len() - icv_len;
    let ciphertext = &bytes[ESP_HEADER_LEN + iv_len..icv_start];
    let icv = &bytes[icv_start..];

    // Verify + decrypt. An integrity failure surfaces `open`'s structured error
    // (field `ipsec.sa.icv`) and never plaintext: the decode fails closed.
    let plaintext = open(sa, iv, aad, ciphertext, icv)?;

    // The decrypted buffer is `inner || pad || pad-length || next-header`.
    // There must be at least the two fixed trailer octets to read.
    if plaintext.len() < trailer_fixed {
        return Err(CrafterError::invalid_field_value(
            "esp.pad_length",
            "decrypted ESP trailer is shorter than the pad-length + next-header octets",
        ));
    }
    let next_header = plaintext[plaintext.len() - 1];
    let pad_length = plaintext[plaintext.len() - 2];

    // The pad octets sit immediately before the pad-length / next-header fields.
    let trailer_start = plaintext.len() - trailer_fixed;
    let pad_len = usize::from(pad_length);
    // Pad Length must not claim more octets than precede the fixed trailer.
    if pad_len > trailer_start {
        return Err(CrafterError::invalid_field_value(
            "esp.pad_length",
            "pad length exceeds the available padding in the decrypted ESP trailer",
        ));
    }
    let pad = &plaintext[trailer_start - pad_len..trailer_start];

    // RFC 4303 §2.4: for block ciphers the pad octets are the monotonic sequence
    // 1, 2, 3, …. Keystream/AEAD modes (block size 1) impose no such pattern, so
    // only their pad-length bound is checked.
    if sa.enc.block_size() > 1 {
        for (offset, &octet) in pad.iter().enumerate() {
            let expected = u8::try_from(offset + 1).unwrap_or(0);
            if octet != expected {
                return Err(CrafterError::invalid_field_value(
                    "esp.pad_length",
                    "ESP pad bytes do not follow the RFC 4303 monotonic 1,2,3,... pattern",
                ));
            }
        }
    }

    // The inner upper-layer plaintext is everything before the padding.
    let inner = plaintext[..trailer_start - pad_len].to_vec();

    // Reconstruct the ESP header layer with the decoded SPI/Sequence as
    // caller-set fields so a re-compile reproduces them. The recovered trailer
    // fields travel on the `DecodedEsp` rather than the header layer.
    let esp = Esp::new()
        .spi(spi)
        .sequence(sequence)
        .next_header(next_header);

    Ok(DecodedEsp {
        esp,
        plaintext: inner,
        next_header,
        pad_length,
    })
}

/// Dispatch the recovered ESP plaintext to nested typed layers (RFC 4303 §2.6).
///
/// The ESP trailer Next Header tells the receiver what the decrypted plaintext
/// is, exactly as the enclosing IP header's Protocol / Next Header field would:
///
/// - **Tunnel mode** (`next_header` 4 = IPv4-in-IP or 41 = IPv6): the plaintext
///   is an entire inner IP datagram (RFC 4303 §3.1.2). It is decoded through the
///   registry's L3 path ([`ProtocolRegistry::decode_ipv4`] /
///   [`ProtocolRegistry::decode_ipv6`]) — the same routing every other inner-IP
///   site uses — and the resulting layers (inner IP + its own nested layers) are
///   appended in order.
/// - **Transport mode** (any other `next_header`): the plaintext is the protected
///   upper-layer payload, so it is dispatched by protocol number through the
///   registry's IPv4-protocol routing
///   ([`ProtocolRegistry::decode_ipv4_protocol`]). A bound protocol (TCP, UDP,
///   ICMP, …) decodes to its typed layer; an unknown protocol number falls back
///   to a preserved `Raw` payload, matching the crate's unknown-next-protocol
///   contract.
///
/// The IPv4-protocol routing is shared across IP versions (the protocol-number
/// space is identical for IPv4 Protocol and IPv6 Next Header), so it is the
/// correct transport-mode dispatcher regardless of the enclosing IP version.
fn dispatch_esp_inner(
    registry: &ProtocolRegistry,
    packet: Packet,
    next_header: u8,
    plaintext: &[u8],
) -> Result<Packet> {
    match next_header {
        // Tunnel mode: the plaintext is a full inner IP datagram. Decode it with
        // the registry's L3 path and append the recovered layers in order.
        IPPROTO_IPV4 => {
            let inner = registry.decode_ipv4(plaintext)?;
            Ok(packet.concat(inner))
        }
        IPPROTO_IPV6 => {
            let inner = registry.decode_ipv6(plaintext)?;
            Ok(packet.concat(inner))
        }
        // Transport mode: dispatch the upper-layer plaintext by protocol number,
        // falling back to `Raw` for an unknown protocol.
        protocol => registry.decode_ipv4_protocol(packet, protocol, plaintext),
    }
}

/// Append a decoded opaque ESP datagram using an explicit registry.
///
/// Decodes the SPI/Sequence header and pushes the opaque [`Esp`] layer onto the
/// packet. There is no inner dispatch in the no-SA path, so the `registry`
/// argument is unused. The built-in IPv4-protocol-50 / IPv6-next-header ESP
/// bindings (Step 19) call this hook. Mirrors UDP's
/// `append_udp_packet_with_registry` shape.
pub(crate) fn append_esp_packet_with_registry(
    _registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let esp = decode_esp_opaque(bytes)?;
    Ok(packet.push(esp))
}

/// Append a decoded ESP datagram using an explicit registry and an optional SA.
///
/// This is the entry point the registry binding (Step 19) calls once it can look
/// up an SA for the on-wire SPI:
///
/// - **`Some(sa)`** — the SA-decode path: verify the ICV, decrypt, strip the
///   RFC 4303 §2.4 padding ([`decode_esp_with_sa`]), push the recovered [`Esp`]
///   header layer (its decoded SPI/Sequence as caller-set fields, with the
///   trailer Next Header recorded), then dispatch the recovered plaintext to
///   nested typed layers via [`dispatch_esp_inner`] (transport mode by protocol
///   number, tunnel mode as an inner IP datagram). An integrity/padding/length
///   failure surfaces the structured error from `decode_esp_with_sa` — the decode
///   fails closed, never producing a wrong plaintext or a panic.
/// - **`None`** — the opaque path (Step 16): the registry has no SA for this SPI,
///   so the body cannot be decrypted. The SPI/Sequence are exposed and the
///   encrypted remainder is preserved verbatim
///   ([`append_esp_packet_with_registry`]); no inner dispatch occurs.
///
/// Mirrors UDP's `append_udp_packet_with_registry` shape: decode parts, push the
/// layer, dispatch inner.
#[allow(dead_code)]
pub(crate) fn append_esp_packet_with_registry_sa(
    registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
    sa: Option<&SecurityAssociation>,
) -> Result<Packet> {
    let Some(sa) = sa else {
        // No SA for this SPI: fall back to the opaque (no-crypto) decode path.
        return append_esp_packet_with_registry(registry, packet, bytes);
    };

    let DecodedEsp {
        esp,
        plaintext,
        next_header,
        ..
    } = decode_esp_with_sa(bytes, sa)?;

    // Push the recovered ESP header layer, then dispatch the plaintext to nested
    // typed layers (transport mode by protocol, tunnel mode as inner IP).
    let packet = packet.push(esp);
    dispatch_esp_inner(registry, packet, next_header, &plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet};

    /// A fixed ESP datagram: SPI || Seq || encrypted body (IV+ct+trailer+ICV).
    ///
    /// The body bytes are arbitrary (the no-SA path never interprets them); the
    /// only contract is that they round-trip verbatim.
    fn fixed_esp_bytes() -> Vec<u8> {
        vec![
            // SPI = 0x0000_2000.
            0x00, 0x00, 0x20, 0x00, //
            // Sequence = 0x0000_0001.
            0x00, 0x00, 0x00, 0x01, //
            // Opaque encrypted body (12 octets, arbitrary).
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD,
        ]
    }

    /// Compile a bare `Esp` layer in isolation to its on-wire ESP bytes.
    fn compile_esp(esp: Esp) -> Vec<u8> {
        let packet = Packet::from_layer(esp);
        let mut out = Vec::new();
        let ctx = LayerContext::new(&packet, 0);
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    #[test]
    fn decode_opaque_exposes_spi_and_sequence() {
        let bytes = fixed_esp_bytes();
        let esp = decode_esp_opaque(&bytes).expect("decode opaque ESP");

        assert_eq!(esp.spi_value(), Some(0x0000_2000));
        assert_eq!(esp.sequence_value(), Some(0x0000_0001));
        // The remainder (everything after the 8-octet header) is the opaque body.
        assert_eq!(esp.opaque_body(), Some(&bytes[ESP_HEADER_LEN..]));
        // No SA, no inner dispatch on the no-SA path.
        assert!(esp.attached_security_association().is_none());
    }

    #[test]
    fn decode_opaque_round_trips_to_original_bytes() {
        let bytes = fixed_esp_bytes();
        let esp = decode_esp_opaque(&bytes).expect("decode opaque ESP");

        // Re-compiling the decoded ESP reproduces the original datagram exactly:
        // SPI || Seq || opaque (the opaque path adds nothing back).
        let recompiled = compile_esp(esp);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn truncated_buffer_is_structured_error_not_panic() {
        // A 4-octet buffer is shorter than the 8-octet ESP header.
        let truncated = vec![0x00, 0x00, 0x20, 0x00];
        let err = decode_esp_opaque(&truncated).expect_err("must reject truncated ESP");

        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "esp header");
                assert_eq!(required, ESP_HEADER_LEN);
                assert_eq!(available, truncated.len());
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
    }

    #[test]
    fn append_with_registry_pushes_the_opaque_esp() {
        let bytes = fixed_esp_bytes();
        let registry = ProtocolRegistry::with_builtin_bindings();
        let packet = append_esp_packet_with_registry(&registry, Packet::new(), &bytes)
            .expect("append opaque ESP");

        // Exactly one layer (the ESP) was pushed; no inner dispatch.
        assert_eq!(packet.len(), 1);
        let esp = packet
            .get(0)
            .unwrap()
            .as_any()
            .downcast_ref::<Esp>()
            .expect("pushed layer is Esp");
        assert_eq!(esp.spi_value(), Some(0x0000_2000));
        assert_eq!(esp.sequence_value(), Some(0x0000_0001));
        assert_eq!(esp.opaque_body(), Some(&bytes[ESP_HEADER_LEN..]));
    }

    // --- decode with SA: verify + decrypt + strip padding -----------------

    use crate::packet::Raw;
    use crate::protocols::ipsec::sa::{
        EncryptionAlgorithm, IntegrityAlgorithm, SecurityAssociation,
    };
    use crate::protocols::ipv4::{Ipv4, IPPROTO_ESP};
    use crate::protocols::transport::common::payload_bytes_after;
    use crate::protocols::Tcp;

    /// Build `Ipv4 / Esp::secured(sa) / Tcp / Raw`, whole-packet compile it, and
    /// return `(esp_bytes, inner_plaintext)`:
    ///
    /// - `esp_bytes` are the ESP datagram bytes that follow the IPv4 header (the
    ///   header length is read from the compiled IHL nibble so options would be
    ///   handled too). Step 15's tail-consumption means whole-packet compile no
    ///   longer double-emits the inner layers, so the bytes after the IP header
    ///   are exactly the ESP datagram.
    /// - `inner_plaintext` is the cleartext the ESP layer encrypted: every layer
    ///   following ESP, compiled through its own context (exactly what
    ///   `payload_bytes_after` gathers at seal time). The decode must recover
    ///   this byte-for-byte.
    fn compile_esp_packet(sa: SecurityAssociation, iv: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        // Pin the IPv4 protocol to ESP (50). Auto-deriving 50 from an inner Esp
        // layer is a later registry step; the decode path takes the ESP bytes
        // directly and does not depend on the enclosing IP protocol.
        let ipv4 = Ipv4::new()
            .protocol(IPPROTO_ESP)
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap());
        // Stamp the on-wire SPI to match the SA's SPI (the realistic case);
        // `secured()` otherwise leaves the builder default SPI in place.
        let spi = sa.spi;
        let esp = Esp::secured(sa).spi(spi).iv(iv);
        let tcp = Tcp::new().sport(1234).dport(443);
        let raw = Raw::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40]);

        let packet: Packet = Packet::from_layer(ipv4) / esp / tcp / raw;

        // The cleartext the ESP layer seals: the bytes of every following layer.
        let esp_ctx = LayerContext::new(&packet, 1);
        let inner_plaintext = payload_bytes_after(esp_ctx).expect("inner plaintext");

        // Whole-packet compile; ESP consumes the following layers (Step 15).
        let compiled = packet.compile().expect("compile packet").into_bytes();

        // Strip the IPv4 header using its IHL nibble (×4 octets).
        let ip_header_len = usize::from(compiled[0] & 0x0f) * 4;
        let esp_bytes = compiled[ip_header_len..].to_vec();
        // The enclosing IPv4 datagram advertises ESP (protocol 50).
        assert_eq!(compiled[9], IPPROTO_ESP);

        (esp_bytes, inner_plaintext)
    }

    /// A 16-octet AES-128 key (fixed, documentation-only).
    fn aes_key() -> Vec<u8> {
        vec![0x11u8; 16]
    }

    /// A 32-octet HMAC-SHA-256 integrity key (fixed, documentation-only).
    fn hmac_key() -> Vec<u8> {
        vec![0x33u8; 32]
    }

    /// Round-trip + tamper assertions for a sealed ESP datagram under `sa`.
    ///
    /// Compiles `Ipv4 / Esp(sa) / Tcp / Raw`, decodes the ESP bytes with the same
    /// SA, asserts the recovered inner equals the cleartext ESP sealed, then flips
    /// one ciphertext bit and (separately) one ICV bit and asserts each decode
    /// errors — never a panic, never a wrong plaintext.
    fn round_trip_and_tamper(sa: SecurityAssociation, iv: Vec<u8>, icv_len: usize) {
        let (esp_bytes, inner) = compile_esp_packet(sa.clone(), iv);

        // Decode with the matching SA recovers the inner plaintext exactly.
        let decoded = decode_esp_with_sa(&esp_bytes, &sa).expect("decode ESP with SA");
        assert_eq!(
            decoded.plaintext, inner,
            "recovered inner must match cleartext"
        );
        assert_eq!(decoded.esp.spi_value(), Some(sa.spi));
        // Next header is TCP (the inner upper-layer protocol, transport mode).
        assert_eq!(decoded.next_header, 6);
        assert_eq!(decoded.esp.next_header_value(), Some(6));

        // Flip one ciphertext bit (the first octet after SPI||Seq||IV). The IV
        // length is the SA's; the ciphertext starts right after it.
        let iv_len = sa.enc.iv_len();
        let mut bad_ct = esp_bytes.clone();
        let ct_index = ESP_HEADER_LEN + iv_len;
        bad_ct[ct_index] ^= 0x01;
        assert!(
            decode_esp_with_sa(&bad_ct, &sa).is_err(),
            "a tampered ciphertext bit must make decode fail closed"
        );

        // Flip one ICV bit (the trailing ICV occupies the last icv_len octets).
        let mut bad_icv = esp_bytes.clone();
        let last = bad_icv.len() - 1;
        bad_icv[last] ^= 0x01;
        assert!(
            decode_esp_with_sa(&bad_icv, &sa).is_err(),
            "a tampered ICV bit must make decode fail closed"
        );
        // The ICV really is icv_len octets at the tail (length sanity check).
        assert!(icv_len > 0 && esp_bytes.len() > iv_len + icv_len + ESP_HEADER_LEN);
    }

    #[test]
    fn decode_with_sa_round_trips_aes_gcm() {
        // AEAD suite: AES-GCM-16 (RFC 4106), 16-octet ICV, 4-octet salt.
        let sa = SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::AesGcm16, aes_key())
            .salt(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(sa.validate().is_ok());
        let iv = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        round_trip_and_tamper(sa, iv, 16);
    }

    #[test]
    fn decode_with_sa_round_trips_aes_cbc_hmac_sha256() {
        // CBC + HMAC suite: AES-CBC (RFC 3602) + HMAC-SHA-256-128 (RFC 4868).
        let sa = SecurityAssociation::new(0x0000_3000)
            .encryption(EncryptionAlgorithm::AesCbc, aes_key())
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key());
        assert!(sa.validate().is_ok());
        let iv: Vec<u8> = (0u8..16).collect();
        round_trip_and_tamper(sa, iv, 16);
    }

    #[test]
    fn decode_with_sa_rejects_bad_cbc_pad_pattern() {
        // A CBC datagram whose decrypted pad bytes do not follow the RFC 4303
        // §2.4 monotonic 1,2,3,... pattern must surface a structured pad error,
        // not a wrong plaintext. We build it by sealing a deliberately malformed
        // plaintext (block-aligned, but with garbage pad octets) and wrapping it
        // in the ESP wire layout by hand.
        use crate::protocols::ipsec::sa::seal;

        let sa = SecurityAssociation::new(0x40)
            .encryption(EncryptionAlgorithm::AesCbc, aes_key())
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key());
        let iv: Vec<u8> = (0u8..16).collect();

        // inner(2) || bad-pad(0xFF,0xFF,0xFF,0xFF...) || pad_len(12) || nh(6),
        // padded to the 16-octet CBC block. The pad bytes are NOT 1,2,3,...
        let mut plaintext = vec![0xAA, 0xBB];
        plaintext.extend_from_slice(&[0xFFu8; 12]); // 12 garbage pad octets
        plaintext.push(12); // pad length
        plaintext.push(6); // next header = TCP
        assert_eq!(plaintext.len() % 16, 0);

        let mut aad = Vec::new();
        aad.extend_from_slice(&0x40u32.to_be_bytes());
        aad.extend_from_slice(&1u32.to_be_bytes());
        let sealed = seal(&sa, &iv, &aad, &plaintext).expect("seal malformed-pad plaintext");

        let mut esp_bytes = Vec::new();
        esp_bytes.extend_from_slice(&aad);
        esp_bytes.extend_from_slice(&iv);
        esp_bytes.extend_from_slice(&sealed.ciphertext);
        esp_bytes.extend_from_slice(&sealed.icv);

        let err = decode_esp_with_sa(&esp_bytes, &sa).expect_err("bad CBC pad must error");
        match err {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "esp.pad_length");
            }
            other => panic!("expected esp.pad_length error, got {other:?}"),
        }
    }

    #[test]
    fn decode_with_sa_truncated_buffer_is_structured_error() {
        // Fewer octets than header + IV + ICV + trailer must be a structured
        // buffer error, never a panic.
        let sa = SecurityAssociation::new(0x50)
            .encryption(EncryptionAlgorithm::AesGcm16, aes_key())
            .salt(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let truncated = vec![0u8; ESP_HEADER_LEN + 4];
        let err = decode_esp_with_sa(&truncated, &sa).expect_err("must reject truncated ESP");
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }

    // --- inner-protocol dispatch (Step 18) --------------------------------

    use crate::protocols::ipv4::IPPROTO_TCP;

    /// Compile `Ipv4 / Esp::secured(sa) / <inner...>` and return the ESP bytes
    /// that follow the outer IPv4 header (the ESP datagram the wire would carry).
    ///
    /// `inner` is the packet ESP protects (an upper-layer header in transport
    /// mode, or a whole inner IP datagram in tunnel mode). Step 15's tail
    /// consumption means the bytes after the outer IPv4 header are exactly the
    /// ESP datagram.
    fn compile_esp_datagram_bytes(sa: SecurityAssociation, iv: Vec<u8>, inner: Packet) -> Vec<u8> {
        let ipv4 = Ipv4::new()
            .protocol(IPPROTO_ESP)
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap());
        let spi = sa.spi;
        let esp = Esp::secured(sa).spi(spi).iv(iv);

        let packet: Packet = (Packet::from_layer(ipv4) / esp).concat(inner);
        let compiled = packet.compile().expect("compile packet").into_bytes();

        // Strip the outer IPv4 header using its IHL nibble (×4 octets).
        let ip_header_len = usize::from(compiled[0] & 0x0f) * 4;
        compiled[ip_header_len..].to_vec()
    }

    #[test]
    fn transport_mode_dispatches_inner_tcp() {
        // Transport mode: the ESP next-header is the upper-layer protocol (TCP),
        // so the recovered plaintext must decode back into a typed Tcp layer.
        let sa = SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::AesGcm16, aes_key())
            .salt(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let iv = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let inner = Packet::from_layer(Tcp::new().sport(1234).dport(443))
            / Raw::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40]);
        let esp_bytes = compile_esp_datagram_bytes(sa.clone(), iv, inner);

        let registry = ProtocolRegistry::with_builtin_bindings();
        let packet =
            append_esp_packet_with_registry_sa(&registry, Packet::new(), &esp_bytes, Some(&sa))
                .expect("decode transport-mode ESP with SA");

        // ESP header layer, then the nested typed TCP layer (transport mode).
        let esp = packet
            .get(0)
            .unwrap()
            .as_any()
            .downcast_ref::<Esp>()
            .expect("first layer is Esp");
        assert_eq!(esp.spi_value(), Some(sa.spi));
        assert_eq!(esp.next_header_value(), Some(IPPROTO_TCP));

        let tcp = packet.layer::<Tcp>().expect("inner Tcp decoded");
        assert_eq!(tcp.source_port_value(), 1234);
        assert_eq!(tcp.destination_port_value(), 443);
        // The TCP payload survived as a trailing Raw layer.
        assert_eq!(
            packet.layer::<Raw>().expect("inner Raw decoded").as_bytes(),
            &[0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40]
        );
    }

    #[test]
    fn tunnel_mode_dispatches_inner_ipv4_tcp() {
        // Tunnel mode: the ESP next-header is IPv4-in-IP (4), so the recovered
        // plaintext is an entire inner IPv4 datagram that must decode back into a
        // typed Ipv4 / Tcp stack.
        let sa = SecurityAssociation::new(0x0000_3000)
            .encryption(EncryptionAlgorithm::AesGcm16, aes_key())
            .salt(vec![0xAA, 0xBB, 0xCC, 0xDD])
            .tunnel();
        let iv = vec![0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];

        // Inner IP datagram: a complete IPv4 / Tcp over documentation addresses.
        let inner_ipv4 = Ipv4::new()
            .protocol(IPPROTO_TCP)
            .src("198.51.100.1".parse().unwrap())
            .dst("198.51.100.2".parse().unwrap());
        let inner = Packet::from_layer(inner_ipv4) / Tcp::new().sport(2222).dport(8080);
        let esp_bytes = compile_esp_datagram_bytes(sa.clone(), iv, inner);

        let registry = ProtocolRegistry::with_builtin_bindings();
        let packet =
            append_esp_packet_with_registry_sa(&registry, Packet::new(), &esp_bytes, Some(&sa))
                .expect("decode tunnel-mode ESP with SA");

        // ESP header layer, then the nested inner IPv4 / Tcp stack.
        let esp = packet
            .get(0)
            .unwrap()
            .as_any()
            .downcast_ref::<Esp>()
            .expect("first layer is Esp");
        assert_eq!(esp.spi_value(), Some(sa.spi));
        // Tunnel mode next-header is IPv4-in-IP (4).
        assert_eq!(esp.next_header_value(), Some(IPPROTO_IPV4));

        let inner_ip = packet.layer::<Ipv4>().expect("inner Ipv4 decoded");
        assert_eq!(inner_ip.source().to_string(), "198.51.100.1");
        assert_eq!(inner_ip.destination().to_string(), "198.51.100.2");
        let inner_tcp = packet.layer::<Tcp>().expect("inner Tcp decoded");
        assert_eq!(inner_tcp.source_port_value(), 2222);
        assert_eq!(inner_tcp.destination_port_value(), 8080);
    }

    #[test]
    fn no_sa_uses_the_opaque_path() {
        // When the registry has no SA for the SPI, the SA-aware entry point falls
        // back to the opaque path: SPI/Sequence exposed, body preserved verbatim,
        // and no inner dispatch.
        let bytes = fixed_esp_bytes();
        let registry = ProtocolRegistry::with_builtin_bindings();
        let packet = append_esp_packet_with_registry_sa(&registry, Packet::new(), &bytes, None)
            .expect("opaque fallback");

        assert_eq!(packet.len(), 1);
        let esp = packet
            .get(0)
            .unwrap()
            .as_any()
            .downcast_ref::<Esp>()
            .expect("pushed layer is Esp");
        assert_eq!(esp.opaque_body(), Some(&bytes[ESP_HEADER_LEN..]));
    }
}
