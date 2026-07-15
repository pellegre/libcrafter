//! Strict CoAP decoding primitives.

use crate::error::{CrafterError, Result};

use super::constants::{
    COAP_HEADER_LEN, COAP_TKL_MASK, COAP_TKL_SHIFT, COAP_TYPE_MASK, COAP_TYPE_SHIFT,
    COAP_VERSION_MASK, COAP_VERSION_SHIFT,
};
use super::message::{
    Coap, CoapCode, CoapMessageType, CoapOptionOrder, CoapToken, CoapTokenLength, CoapVersion,
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
        assert_eq!(
            decode_token_and_options(&[0x4d, 0x01, 0x00, 0x01]),
            Err(CrafterError::BufferTooShort {
                context: "coap.token-length.extended8",
                required: 1,
                available: 0,
            })
        );
        assert_eq!(
            decode_token_and_options(&[0x4e, 0x01, 0x00, 0x01, 0x00]),
            Err(CrafterError::BufferTooShort {
                context: "coap.token-length.extended16",
                required: 2,
                available: 1,
            })
        );
        assert_eq!(
            decode_token_and_options(&[0x48, 0x01, 0x00, 0x01, 0xaa, 0xbb]),
            Err(CrafterError::BufferTooShort {
                context: "coap.token",
                required: 8,
                available: 2,
            })
        );
        assert_eq!(
            decode_token_and_options(&[0x4f, 0x01, 0x00, 0x01]),
            Err(CrafterError::invalid_field_value(
                "coap.token-length",
                "reserved TKL encoding 15",
            ))
        );
    }

    #[test]
    fn malformed_option_boundaries_propagate_local_size_errors() {
        assert_eq!(
            decode_token_and_options(&[0x40, 0x01, 0x00, 0x01, 0x03, 0xaa]),
            Err(CrafterError::BufferTooShort {
                context: "coap.option.value",
                required: 3,
                available: 1,
            })
        );
        assert_eq!(
            decode_token_and_options(&[0x40, 0x01, 0x00, 0x01, 0xd0]),
            Err(CrafterError::BufferTooShort {
                context: "coap.option.delta.extended8",
                required: 1,
                available: 0,
            })
        );
    }
}
