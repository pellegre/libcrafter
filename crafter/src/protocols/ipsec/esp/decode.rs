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
use crate::registry::ProtocolRegistry;

use super::header::ESP_HEADER_LEN;
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
}
