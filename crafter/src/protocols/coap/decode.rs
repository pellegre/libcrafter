//! Strict CoAP decoding primitives.
//!
//! Datagram boundaries follow `.agents/docs/coap-wire-grammar.md` and RFC
//! 7252 Sections 3, 3.1, and 4.1, including the RFC 8974 Section 2.1 token
//! update. Stable failures follow `.agents/docs/coap-error-policy.md`.

use crate::error::{CrafterError, Result};
use crate::packet::Packet;

use super::constants::{
    COAPS_UDP_PORT, COAP_HEADER_LEN, COAP_TKL_MASK, COAP_TKL_SHIFT, COAP_TYPE_MASK,
    COAP_TYPE_SHIFT, COAP_UDP_PORT, COAP_VERSION_1, COAP_VERSION_MASK, COAP_VERSION_SHIFT,
};
use super::message::{
    Coap, CoapCode, CoapMessageType, CoapOptionOrder, CoapPayloadMarker, CoapToken,
    CoapTokenLength, CoapVersion,
};
use super::option::decode_option_sequence;

/// A CoAP datagram decoded through its ordered option boundary.
///
/// `consumed` includes the fixed header, token-length extension, token, and
/// option bytes. When `payload_marker` is true, the next input byte is the
/// unconsumed marker so the payload decoder can preserve it independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DecodedTokenOptions {
    pub(super) message: Coap,
    pub(super) consumed: usize,
    pub(super) payload_marker: bool,
}

/// Decode the four-byte CoAP datagram header into explicit layer fields.
///
/// Token-length extensions, token bytes, options, and payload are decoded by
/// later grammar stages. Keeping the raw TKL nibble explicit here ensures the
/// fixed header can be inspected and recompiled without normalization.
pub(super) fn decode_fixed_header(bytes: &[u8]) -> Result<Coap> {
    if bytes.len() < COAP_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "coap.header",
            COAP_HEADER_LEN,
            bytes.len(),
        ));
    }

    let first = bytes[0];
    let version = (first & COAP_VERSION_MASK) >> COAP_VERSION_SHIFT;
    let message_type = (first & COAP_TYPE_MASK) >> COAP_TYPE_SHIFT;
    let token_length = (first & COAP_TKL_MASK) >> COAP_TKL_SHIFT;

    Ok(Coap::new()
        .version(CoapVersion::from_wire(version))
        .message_type(CoapMessageType::from_wire(message_type))
        .token_length(CoapTokenLength::explicit(
            token_length,
            Vec::new(),
            usize::from(token_length),
        ))
        .code(CoapCode::from_wire(bytes[1]))
        .message_id(u16::from_be_bytes([bytes[2], bytes[3]])))
}

/// Decode the CoAP token and ordered option sequence without consuming a
/// payload marker or payload bytes.
pub(super) fn decode_token_and_options(bytes: &[u8]) -> Result<DecodedTokenOptions> {
    let message = decode_fixed_header(bytes)?;
    let token_length_nibble = message.token_length_value()?.nibble();

    if message.code_value().is_empty()
        && (token_length_nibble != 0 || bytes.len() > COAP_HEADER_LEN)
    {
        return Err(CrafterError::invalid_field_value(
            "coap.empty-message",
            "empty message contains token, options, marker, or payload",
        ));
    }

    let after_header = bytes.get(COAP_HEADER_LEN..).unwrap_or_default();
    let (token_length, extension_len) = decode_token_length(token_length_nibble, after_header)?;
    let after_extension = after_header.get(extension_len..).unwrap_or_default();
    let token_len = token_length.declared_len();
    let token = after_extension.get(..token_len).ok_or_else(|| {
        CrafterError::buffer_too_short("coap.token", token_len, after_extension.len())
    })?;

    let token_and_extension_len = extension_len.checked_add(token_len).ok_or_else(|| {
        CrafterError::invalid_field_value("coap.token-length", "decoded token boundary overflow")
    })?;
    let option_bytes = after_header
        .get(token_and_extension_len..)
        .unwrap_or_default();
    let decoded_options = decode_option_sequence(option_bytes)?;
    let consumed = COAP_HEADER_LEN
        .checked_add(token_and_extension_len)
        .and_then(|value| value.checked_add(decoded_options.consumed))
        .ok_or_else(|| {
            CrafterError::invalid_field_value(
                "coap.option.length",
                "option sequence cursor overflow",
            )
        })?;

    Ok(DecodedTokenOptions {
        message: message
            .token_length(token_length)
            .token(CoapToken::from_bytes(token))
            .options(decoded_options.options)
            .option_order(CoapOptionOrder::Wire),
        consumed,
        payload_marker: decoded_options.payload_marker,
    })
}

impl Coap {
    /// Decode one complete CoAP UDP payload as a typed datagram layer.
    ///
    /// This direct parser is strict because the caller has explicitly selected
    /// CoAP: malformed input returns a structured [`CrafterError`]. Registry
    /// auto-dispatch is deliberately more conservative and retains candidates
    /// that fail its shape gate as `Raw` application payloads instead.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_coap(bytes)
    }
}

/// Decode one complete CoAP UDP payload as a typed datagram layer.
///
/// The whole slice is treated as one datagram. Unlike conservative registry
/// classification, this explicit parser never silently falls back to `Raw`:
/// malformed or truncated input returns a structured [`CrafterError`].
pub fn decode_coap(bytes: &[u8]) -> Result<Coap> {
    decode_datagram(bytes)
}

/// Return true when a UDP payload is a complete cleartext CoAP datagram.
///
/// The built-in registry uses service ports only as hints. Secure UDP/5684
/// traffic is rejected before its ciphertext is inspected, while UDP/5683
/// candidates must use Version 1 and pass the complete structural decoder.
/// Unknown code and option values remain eligible when their wire grammar is
/// otherwise sound.
pub(crate) fn looks_like_coap_payload(
    source_port: u16,
    destination_port: u16,
    bytes: &[u8],
) -> bool {
    if source_port == COAPS_UDP_PORT || destination_port == COAPS_UDP_PORT {
        return false;
    }
    if source_port != COAP_UDP_PORT && destination_port != COAP_UDP_PORT {
        return false;
    }

    let Some(first) = bytes.first() else {
        return false;
    };
    let version = (first & COAP_VERSION_MASK) >> COAP_VERSION_SHIFT;
    if version != COAP_VERSION_1 {
        return false;
    }

    decode_datagram(bytes).is_ok()
}

/// Append one explicitly decoded CoAP datagram to an existing packet stack.
pub(crate) fn append_coap_packet(packet: Packet, bytes: &[u8]) -> Result<Packet> {
    Ok(packet.push(decode_coap(bytes)?))
}

/// Decode one complete CoAP datagram, preserving its payload boundary.
///
/// Payload bytes remain opaque regardless of any Content-Format option. An
/// absent marker is recorded independently from an empty payload, while a
/// present marker must be followed by at least one payload byte.
pub(super) fn decode_datagram(bytes: &[u8]) -> Result<Coap> {
    let decoded = decode_token_and_options(bytes)?;

    if !decoded.payload_marker {
        return Ok(decoded
            .message
            .payload_marker(CoapPayloadMarker::Absent)
            .payload(Vec::new()));
    }

    let marker_and_payload = bytes.get(decoded.consumed..).unwrap_or_default();
    let payload = marker_and_payload.get(1..).unwrap_or_default();
    if payload.is_empty() {
        return Err(CrafterError::buffer_too_short(
            "coap.payload",
            1,
            payload.len(),
        ));
    }

    Ok(decoded
        .message
        .payload_marker(CoapPayloadMarker::Present)
        .payload(payload.to_vec()))
}

fn decode_token_length(nibble: u8, bytes: &[u8]) -> Result<(CoapTokenLength, usize)> {
    match nibble {
        0..=12 => Ok((
            CoapTokenLength::explicit(nibble, Vec::new(), usize::from(nibble)),
            0,
        )),
        13 => {
            let extension = *bytes.first().ok_or_else(|| {
                CrafterError::buffer_too_short("coap.token-length.extended8", 1, bytes.len())
            })?;
            let declared_len = 13usize.checked_add(usize::from(extension)).ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "coap.token-length",
                    "decoded token length overflow",
                )
            })?;
            Ok((
                CoapTokenLength::explicit(nibble, vec![extension], declared_len),
                1,
            ))
        }
        14 => {
            let extension = bytes.get(..2).ok_or_else(|| {
                CrafterError::buffer_too_short("coap.token-length.extended16", 2, bytes.len())
            })?;
            let extension_value = u16::from_be_bytes([extension[0], extension[1]]);
            let declared_len = 269usize
                .checked_add(usize::from(extension_value))
                .ok_or_else(|| {
                    CrafterError::invalid_field_value(
                        "coap.token-length",
                        "decoded token length overflow",
                    )
                })?;
            Ok((
                CoapTokenLength::explicit(nibble, extension.to_vec(), declared_len),
                2,
            ))
        }
        15 => Err(CrafterError::invalid_field_value(
            "coap.token-length",
            "reserved TKL encoding 15",
        )),
        _ => Err(CrafterError::invalid_field_value(
            "coap.token-length",
            "token-length discriminator exceeds four bits",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldState;
    use crate::packet::Packet;
    use crate::protocols::coap::constants::COAP_PAYLOAD_MARKER;

    fn assert_header_roundtrip(bytes: [u8; COAP_HEADER_LEN]) -> Coap {
        let decoded = decode_fixed_header(&bytes).expect("decode fixed CoAP header");
        let encoded = Packet::from_layer(decoded.clone())
            .compile()
            .expect("recompile fixed CoAP header");

        assert_eq!(encoded.as_bytes(), &bytes);
        assert_eq!(decoded.version_state(), FieldState::User);
        assert_eq!(decoded.message_type_state(), FieldState::User);
        assert_eq!(decoded.token_length_state(), FieldState::User);
        assert_eq!(decoded.code_state(), FieldState::User);
        assert_eq!(decoded.message_id_state(), FieldState::User);
        decoded
    }

    #[test]
    fn truncated_headers_report_stable_context_and_size() {
        let bytes = [0x40, 0x01, 0x12];

        for available in 0..COAP_HEADER_LEN {
            assert_eq!(
                decode_fixed_header(&bytes[..available]),
                Err(CrafterError::BufferTooShort {
                    context: "coap.header",
                    required: COAP_HEADER_LEN,
                    available,
                })
            );
        }
    }

    #[test]
    fn every_message_type_decodes_without_value_loss() {
        let cases = [
            (0u8, CoapMessageType::Confirmable),
            (1, CoapMessageType::NonConfirmable),
            (2, CoapMessageType::Acknowledgement),
            (3, CoapMessageType::Reset),
        ];

        for (wire_type, expected) in cases {
            let first = (1 << COAP_VERSION_SHIFT) | (wire_type << COAP_TYPE_SHIFT);
            let decoded = assert_header_roundtrip([first, 0x01, 0x12, 0x34]);
            assert_eq!(decoded.message_type_value(), expected);
        }
    }

    #[test]
    fn boundary_message_ids_decode_in_network_byte_order() {
        for message_id in [u16::MIN, u16::MAX] {
            let [high, low] = message_id.to_be_bytes();
            let decoded = assert_header_roundtrip([0x40, 0x45, high, low]);
            assert_eq!(decoded.message_id_value(), message_id);
        }
    }

    #[test]
    fn unknown_codes_and_non_current_versions_remain_lossless() {
        for version in [0u8, 2, 3] {
            let first = version << COAP_VERSION_SHIFT;
            let decoded = assert_header_roundtrip([first, 0x1f, 0xab, 0xcd]);

            assert_eq!(decoded.version_value(), CoapVersion::from_wire(version));
            assert_eq!(decoded.code_value(), CoapCode::from_wire(0x1f));
        }
    }

    #[test]
    fn every_token_length_nibble_is_preserved_by_fixed_header_decode() {
        for nibble in 0u8..=15 {
            let decoded = assert_header_roundtrip([0x40 | nibble, 0xff, 0x01, 0x02]);
            let token_length = decoded
                .token_length_value()
                .expect("explicit fixed-header token length");

            assert_eq!(token_length.nibble(), nibble);
            assert!(token_length.extension_bytes().is_empty());
            assert_eq!(token_length.declared_len(), usize::from(nibble));
            assert_eq!(decoded.code_value(), CoapCode::from_wire(0xff));
        }
    }

    #[test]
    fn maximum_base_token_decodes_exactly_before_options() {
        let token = [0x00, 0xff, 0x80, 0x7f, 0x01, 0x02, 0x03, 0x04];
        let mut bytes = vec![0x48, 0x01, 0x12, 0x34];
        bytes.extend_from_slice(&token);

        let decoded = decode_token_and_options(&bytes).expect("decode maximum base token");

        assert_eq!(decoded.message.token_value().as_bytes(), token);
        assert_eq!(
            decoded.message.token_length_value().unwrap(),
            CoapTokenLength::explicit(8, Vec::new(), 8)
        );
        assert!(decoded.message.options_value().is_empty());
        assert_eq!(decoded.message.option_order_value(), CoapOptionOrder::Wire);
        assert_eq!(decoded.consumed, bytes.len());
        assert!(!decoded.payload_marker);
    }

    #[test]
    fn direct_and_extended_token_lengths_preserve_their_wire_forms() {
        let direct_token = vec![0xa5; 12];
        let mut direct = vec![0x4c, 0x01, 0x00, 0x01];
        direct.extend_from_slice(&direct_token);
        let decoded = decode_token_and_options(&direct).expect("decode direct TKL 12");
        assert_eq!(decoded.message.token_value().as_bytes(), direct_token);
        assert_eq!(
            decoded.message.token_length_value().unwrap(),
            CoapTokenLength::explicit(12, Vec::new(), 12)
        );

        let extended8_token = vec![0x5a; 13];
        let mut extended8 = vec![0x4d, 0x01, 0x00, 0x02, 0x00];
        extended8.extend_from_slice(&extended8_token);
        let decoded = decode_token_and_options(&extended8).expect("decode TKL 13 extension");
        assert_eq!(decoded.message.token_value().as_bytes(), extended8_token);
        assert_eq!(
            decoded.message.token_length_value().unwrap(),
            CoapTokenLength::explicit(13, vec![0x00], 13)
        );

        let extended16_token = vec![0x3c; 269];
        let mut extended16 = vec![0x4e, 0x01, 0x00, 0x03, 0x00, 0x00];
        extended16.extend_from_slice(&extended16_token);
        let decoded = decode_token_and_options(&extended16).expect("decode TKL 14 extension");
        assert_eq!(decoded.message.token_value().as_bytes(), extended16_token);
        assert_eq!(
            decoded.message.token_length_value().unwrap(),
            CoapTokenLength::explicit(14, vec![0x00, 0x00], 269)
        );
    }

    #[test]
    fn options_preserve_empty_repeated_unknown_and_extended_headers() {
        let bytes = [
            0x40,
            0x01,
            0x00,
            0x01, // fixed header
            0xd0,
            0x00, // option 13, empty value, extended delta
            0x00, // repeated option 13, empty value
            0xe2,
            0x00,
            0x00,
            0xde,
            0xad, // unknown option 282, extended delta
            COAP_PAYLOAD_MARKER,
            0xaa,
        ];

        let decoded = decode_token_and_options(&bytes).expect("decode ordered options");
        let options = decoded.message.options_value();

        assert_eq!(options.len(), 3);
        assert_eq!(options[0].number().value(), 13);
        assert_eq!(options[0].value(), b"");
        assert_eq!(
            options[0].encoding().unwrap().raw_bytes(),
            Some(&[0xd0, 0x00][..])
        );
        assert_eq!(options[1].number().value(), 13);
        assert_eq!(options[1].value(), b"");
        assert_eq!(
            options[1].encoding().unwrap().raw_bytes(),
            Some(&[0x00][..])
        );
        assert_eq!(options[2].number().value(), 282);
        assert_eq!(options[2].value(), [0xde, 0xad]);
        assert_eq!(
            options[2].encoding().unwrap().raw_bytes(),
            Some(&[0xe2, 0x00, 0x00][..])
        );
        assert_eq!(decoded.consumed, bytes.len() - 2);
        assert!(decoded.payload_marker);
    }

    #[test]
    fn token_length_boundaries_return_structured_errors() {
        let cases: &[(&[u8], &'static str, usize, usize)] = &[
            (
                &[0x4d, 0x01, 0x00, 0x01],
                "coap.token-length.extended8",
                1,
                0,
            ),
            (
                &[0x4e, 0x01, 0x00, 0x01, 0x00],
                "coap.token-length.extended16",
                2,
                1,
            ),
            (&[0x48, 0x01, 0x00, 0x01, 0xaa, 0xbb], "coap.token", 8, 2),
            (
                &[0x40, 0x01, 0x00, 0x01, 0xd0],
                "coap.option.delta.extended8",
                1,
                0,
            ),
            (
                &[0x40, 0x01, 0x00, 0x01, 0xe0, 0x00],
                "coap.option.delta.extended16",
                2,
                1,
            ),
            (
                &[0x40, 0x01, 0x00, 0x01, 0x0d],
                "coap.option.length.extended8",
                1,
                0,
            ),
            (
                &[0x40, 0x01, 0x00, 0x01, 0x0e, 0x00],
                "coap.option.length.extended16",
                2,
                1,
            ),
            (
                &[0x40, 0x01, 0x00, 0x01, 0x03, 0xaa],
                "coap.option.value",
                3,
                1,
            ),
        ];

        for &(bytes, context, required, available) in cases {
            assert_eq!(
                decode_token_and_options(bytes),
                Err(CrafterError::BufferTooShort {
                    context,
                    required,
                    available,
                }),
                "bytes: {bytes:02x?}",
            );
        }

        assert_eq!(
            decode_token_and_options(&[0x4f, 0x01, 0x00, 0x01]),
            Err(CrafterError::invalid_field_value(
                "coap.token-length",
                "reserved TKL encoding 15",
            ))
        );
    }

    #[test]
    fn datagram_invalid_fields_report_stable_names_and_reasons() {
        let cases: &[(&[u8], &'static str, &'static str)] = &[
            (
                &[0x4f, 0x01, 0x00, 0x01],
                "coap.token-length",
                "reserved TKL encoding 15",
            ),
            (
                &[0x40, 0x01, 0x00, 0x01, 0xf0],
                "coap.option.delta",
                "reserved delta nibble 15 is not a payload marker",
            ),
            (
                &[0x40, 0x01, 0x00, 0x01, 0x0f],
                "coap.option.length",
                "reserved option length nibble 15",
            ),
            (
                &[0x40, 0x01, 0x00, 0x01, 0xe0, 0xff, 0xff],
                "coap.option-number",
                "cumulative option number exceeds 65535",
            ),
            (
                &[0x41, 0x00, 0x00, 0x01],
                "coap.empty-message",
                "empty message contains token, options, marker, or payload",
            ),
            (
                &[0x40, 0x00, 0x00, 0x01, 0x00],
                "coap.empty-message",
                "empty message contains token, options, marker, or payload",
            ),
        ];

        for &(bytes, field, reason) in cases {
            assert_eq!(
                decode_datagram(bytes),
                Err(CrafterError::InvalidFieldValue { field, reason }),
                "bytes: {bytes:02x?}",
            );
        }
    }

    #[test]
    fn absent_marker_preserves_an_empty_payload_boundary() {
        let bytes = [0x40, 0x01, 0x12, 0x34];

        let decoded = decode_datagram(&bytes).expect("decode empty CoAP payload");

        assert_eq!(decoded.payload_marker_state(), FieldState::User);
        assert_eq!(decoded.payload_marker_value(), CoapPayloadMarker::Absent);
        assert!(decoded.payload_value().is_empty());
        assert_eq!(
            Packet::from_layer(decoded).compile().unwrap().as_bytes(),
            bytes
        );
    }

    #[test]
    fn utf8_payload_remains_owned_opaque_bytes() {
        let text = "Gr\u{fc}\u{df}e";
        let mut bytes = vec![
            0x40,
            0x45,
            0x12,
            0x34,
            0xc1,
            0x00, // Content-Format: text/plain;charset=utf-8
            COAP_PAYLOAD_MARKER,
        ];
        bytes.extend_from_slice(text.as_bytes());

        let decoded = decode_datagram(&bytes).expect("decode UTF-8 CoAP payload");

        assert_eq!(decoded.payload_marker_state(), FieldState::User);
        assert_eq!(decoded.payload_marker_value(), CoapPayloadMarker::Present);
        assert_eq!(decoded.options_value()[0].number().value(), 12);
        assert_eq!(decoded.payload_value(), text.as_bytes());
        assert_eq!(
            Packet::from_layer(decoded).compile().unwrap().as_bytes(),
            bytes
        );
    }

    #[test]
    fn binary_payload_can_begin_with_and_contain_marker_octets() {
        let payload = [COAP_PAYLOAD_MARKER, 0x00, 0x80, COAP_PAYLOAD_MARKER];
        let mut bytes = vec![0x40, 0x45, 0xab, 0xcd, COAP_PAYLOAD_MARKER];
        bytes.extend_from_slice(&payload);

        let decoded = decode_datagram(&bytes).expect("decode binary CoAP payload");

        assert_eq!(decoded.payload_value(), payload);
        assert_eq!(
            Packet::from_layer(decoded).compile().unwrap().as_bytes(),
            bytes
        );
    }

    #[test]
    fn marker_without_payload_reports_stable_boundary_error() {
        assert_eq!(
            decode_datagram(&[0x40, 0x45, 0x12, 0x34, COAP_PAYLOAD_MARKER]),
            Err(CrafterError::BufferTooShort {
                context: "coap.payload",
                required: 1,
                available: 0,
            })
        );
    }

    #[test]
    fn public_decode_entrypoints_round_trip_complete_udp_payloads() {
        let messages: &[&[u8]] = &[
            &[0x40, 0x01, 0x12, 0x34],
            &[
                0x41,
                0x02,
                0x00,
                0x01,
                0xaa,
                0xb1,
                b'x',
                COAP_PAYLOAD_MARKER,
                0x00,
                0xff,
            ],
            &[0x60, 0x45, 0xbe, 0xef, COAP_PAYLOAD_MARKER, b'o', b'k'],
        ];

        for &bytes in messages {
            let decoded = decode_coap(bytes).expect("decode complete CoAP UDP payload");
            let decoded_by_type = Coap::decode(bytes).expect("decode through Coap::decode");

            assert_eq!(decoded_by_type, decoded);
            assert_eq!(
                Packet::from_layer(decoded).compile().unwrap().as_bytes(),
                bytes
            );
        }
    }

    #[test]
    fn append_helper_pushes_the_typed_coap_layer() {
        let bytes = [0x40, 0x01, 0x12, 0x34];

        let packet = append_coap_packet(Packet::new(), &bytes).expect("append decoded CoAP");

        assert!(packet.layer::<Coap>().is_some());
        assert_eq!(packet.compile().unwrap().as_bytes(), bytes);
    }

    #[test]
    fn udp_shape_gate_accepts_complete_cleartext_messages() {
        let cases: &[&[u8]] = &[
            &[0x40, 0x01, 0x12, 0x34],
            &[0x40, 0x1f, 0x00, 0x01, 0x20],
            &[0x41, 0x45, 0x00, 0x02, 0xaa, 0xd0, 0x00],
            &[0x40, 0x45, 0x00, 0x03, COAP_PAYLOAD_MARKER, 0x00],
        ];

        for &bytes in cases {
            assert!(looks_like_coap_payload(49_152, COAP_UDP_PORT, bytes));
            assert!(looks_like_coap_payload(COAP_UDP_PORT, 49_152, bytes));
        }
    }

    #[test]
    fn udp_shape_gate_rejects_malformed_and_unrelated_payloads() {
        let cases: &[&[u8]] = &[
            &[],
            &[0x40, 0x01, 0x00],
            &[0x00, 0x01, 0x00, 0x01],
            &[0x80, 0x01, 0x00, 0x01],
            &[0xc0, 0x01, 0x00, 0x01],
            &[0x48, 0x01, 0x00, 0x01, 0xaa],
            &[0x4f, 0x01, 0x00, 0x01],
            &[0x40, 0x01, 0x00, 0x01, 0xf0],
            &[0x40, 0x01, 0x00, 0x01, 0x0f],
            &[0x40, 0x45, 0x00, 0x01, COAP_PAYLOAD_MARKER],
            &[0x40, 0x00, 0x00, 0x01, 0x00],
            b"random UDP",
        ];

        for &bytes in cases {
            assert!(
                !looks_like_coap_payload(49_152, COAP_UDP_PORT, bytes),
                "bytes: {bytes:02x?}",
            );
        }
    }

    #[test]
    fn udp_shape_gate_never_inspects_secure_or_unassigned_ports_as_cleartext() {
        let structurally_valid_bytes = [0x40, 0x01, 0x12, 0x34];

        assert!(!looks_like_coap_payload(
            49_152,
            COAPS_UDP_PORT,
            &structurally_valid_bytes,
        ));
        assert!(!looks_like_coap_payload(
            COAPS_UDP_PORT,
            49_152,
            &structurally_valid_bytes,
        ));
        assert!(!looks_like_coap_payload(
            COAP_UDP_PORT,
            COAPS_UDP_PORT,
            &structurally_valid_bytes,
        ));
        assert!(!looks_like_coap_payload(
            49_152,
            49_153,
            &structurally_valid_bytes,
        ));
    }
}
