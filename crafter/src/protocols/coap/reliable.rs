//! Reliable-transport CoAP framing primitives.
//!
//! RFC 8974 token boundaries are decoded here independently from the later
//! RFC 8323 frame-length and typed-layer stages. The input begins immediately
//! after the reliable Code byte, so the returned consumed length stops at the
//! first option byte.

use crate::error::{CrafterError, Result};

use super::decode::{decode_token_boundary, DecodedTokenBoundary, TokenDecodeContext};
use super::message::{CoapToken, CoapTokenLength};

/// Encode the exact TKL extension followed by all owned Token bytes.
///
/// Canonical metadata supplies the shortest RFC 8974 extension. Explicit
/// metadata is copied without repair even when its discriminator, extension,
/// declared length, and owned token disagree.
#[allow(dead_code)]
pub(super) fn encode_reliable_token(
    token_length: &CoapTokenLength,
    token: &CoapToken,
    out: &mut Vec<u8>,
) -> Result<usize> {
    let consumed = token_length
        .extension_bytes()
        .len()
        .checked_add(token.len())
        .ok_or_else(|| {
            CrafterError::invalid_field_value(
                "coap.reliable.token-length",
                "encoded token boundary overflow",
            )
        })?;

    token_length.encode_extension(out);
    out.extend_from_slice(token.as_bytes());
    Ok(consumed)
}

/// Decode the TKL extension and complete Token at a reliable-frame boundary.
///
/// This staged primitive is shared by the forthcoming complete reliable frame
/// decoder; it performs no stream buffering and never consumes option bytes.
#[allow(dead_code)]
pub(super) fn decode_reliable_token(
    nibble: u8,
    bytes_after_code: &[u8],
) -> Result<DecodedTokenBoundary<'_>> {
    decode_token_boundary(nibble, bytes_after_code, TokenDecodeContext::RELIABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reliable_token_boundaries_stop_before_options_at_every_transition() {
        let cases: &[(usize, u8, &[u8])] = &[
            (8, 8, &[]),
            (9, 9, &[]),
            (12, 12, &[]),
            (13, 13, &[0x00]),
            (268, 13, &[0xff]),
            (269, 14, &[0x00, 0x00]),
            (CoapTokenLength::MAX_LEN, 14, &[0xff, 0xff]),
        ];

        for &(token_len, nibble, extension) in cases {
            let token = CoapToken::from_bytes(vec![0xa5; token_len]);
            let token_length = CoapTokenLength::canonical_for_len(token_len).unwrap();
            let mut bytes = Vec::new();
            let encoded = encode_reliable_token(&token_length, &token, &mut bytes)
                .expect("encode reliable token boundary");
            bytes.extend_from_slice(&[0xb1, b'x']);

            let decoded =
                decode_reliable_token(nibble, &bytes).expect("decode reliable token boundary");

            assert_eq!(encoded, extension.len() + token_len);
            assert_eq!(&bytes[..extension.len()], extension);
            assert_eq!(decoded.token_length.nibble(), nibble);
            assert_eq!(decoded.token_length.extension_bytes(), extension);
            assert_eq!(decoded.token_length.declared_len(), token_len);
            assert_eq!(
                decoded.token,
                &bytes[extension.len()..extension.len() + token_len]
            );
            assert_eq!(decoded.consumed, extension.len() + token_len);
            assert_eq!(&bytes[decoded.consumed..], &[0xb1, b'x']);
        }
    }

    #[test]
    fn reliable_encoding_preserves_explicit_extension_overrides_exactly() {
        let token_length = CoapTokenLength::explicit(13, vec![0xfe, 0xed], usize::MAX);
        let token = CoapToken::from_bytes([0xaa, 0xbb]);
        let mut encoded = Vec::new();

        assert_eq!(
            encode_reliable_token(&token_length, &token, &mut encoded).unwrap(),
            4,
        );
        assert_eq!(encoded, [0xfe, 0xed, 0xaa, 0xbb]);
    }

    #[test]
    fn reliable_token_failures_use_stable_reliable_contexts() {
        assert_eq!(
            decode_reliable_token(13, &[]),
            Err(CrafterError::buffer_too_short(
                "coap.reliable.token-length.extended8",
                1,
                0,
            ))
        );
        assert_eq!(
            decode_reliable_token(14, &[0x00]),
            Err(CrafterError::buffer_too_short(
                "coap.reliable.token-length.extended16",
                2,
                1,
            ))
        );
        assert_eq!(
            decode_reliable_token(12, &[0xa5; 11]),
            Err(CrafterError::buffer_too_short(
                "coap.reliable.token",
                12,
                11,
            ))
        );
        assert_eq!(
            decode_reliable_token(15, &[]),
            Err(CrafterError::invalid_field_value(
                "coap.reliable.token-length",
                "reserved TKL encoding 15",
            ))
        );
    }
}
