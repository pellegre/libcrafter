//! Strict CoAP decoding primitives.

use crate::error::{CrafterError, Result};

use super::constants::{
    COAP_HEADER_LEN, COAP_TKL_MASK, COAP_TKL_SHIFT, COAP_TYPE_MASK, COAP_TYPE_SHIFT,
    COAP_VERSION_MASK, COAP_VERSION_SHIFT,
};
use super::message::{Coap, CoapCode, CoapMessageType, CoapTokenLength, CoapVersion};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldState;
    use crate::packet::Packet;

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
}
