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
use crate::protocols::ipsec::sa::{open, SecurityAssociation};
use crate::registry::ProtocolRegistry;

use super::header::{ESP_HEADER_LEN, ESP_NEXT_HEADER_FIELD_LEN, ESP_PAD_LENGTH_FIELD_LEN};
use super::Esp;

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

/// Append a decoded opaque ESP datagram using an explicit registry.
///
/// Decodes the SPI/Sequence header and pushes the opaque [`Esp`] layer onto the
/// packet. There is no inner dispatch in the no-SA path, so the `registry`
/// argument is currently unused; the IP-protocol/next-header bindings that call
/// this hook are wired in a later step. Mirrors UDP's
/// `append_udp_packet_with_registry` shape.
#[allow(dead_code)]
pub(crate) fn append_esp_packet_with_registry(
    _registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let esp = decode_esp_opaque(bytes)?;
    Ok(packet.push(esp))
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
}
