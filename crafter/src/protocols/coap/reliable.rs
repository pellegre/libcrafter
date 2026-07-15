//! Reliable-transport CoAP framing primitives.
//!
//! RFC 8323 Section 3.2 supplies the reliable message-length grammar. RFC
//! 8974 updates the TKL grammar shared by datagram and reliable messages. The
//! decoder below identifies exactly one complete frame; it never buffers or
//! searches a transport stream.

use crate::error::{CrafterError, Result};

use super::decode::{decode_token_boundary, DecodedTokenBoundary, TokenDecodeContext};
use super::message::{CoapCode, CoapToken, CoapTokenLength};

const RELIABLE_DIRECT_MAX_BODY_LEN: usize = 12;
const RELIABLE_EXTENDED8_MIN_BODY_LEN: usize = 13;
const RELIABLE_EXTENDED8_MAX_BODY_LEN: usize = 268;
const RELIABLE_EXTENDED16_MIN_BODY_LEN: usize = 269;
const RELIABLE_EXTENDED16_MAX_BODY_LEN: usize = 65_804;
const RELIABLE_EXTENDED32_MIN_BODY_LEN: usize = 65_805;

/// Lossless RFC 8323 reliable-message body-length metadata.
///
/// The discriminator, extension bytes, and declared body length remain
/// independent so a later typed layer can preserve caller-supplied malformed
/// overrides without repairing them during compilation.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoapReliableLength {
    nibble: u8,
    extension_bytes: Vec<u8>,
    declared_body_len: usize,
}

#[allow(dead_code)]
impl CoapReliableLength {
    /// Build the shortest RFC 8323 representation for `body_len`.
    pub fn canonical_for_body_len(body_len: usize) -> Result<Self> {
        match body_len {
            0..=RELIABLE_DIRECT_MAX_BODY_LEN => {
                Ok(Self::explicit(body_len as u8, Vec::new(), body_len))
            }
            RELIABLE_EXTENDED8_MIN_BODY_LEN..=RELIABLE_EXTENDED8_MAX_BODY_LEN => {
                Ok(Self::explicit(
                    13,
                    vec![(body_len - RELIABLE_EXTENDED8_MIN_BODY_LEN) as u8],
                    body_len,
                ))
            }
            RELIABLE_EXTENDED16_MIN_BODY_LEN..=RELIABLE_EXTENDED16_MAX_BODY_LEN => {
                Ok(Self::explicit(
                    14,
                    ((body_len - RELIABLE_EXTENDED16_MIN_BODY_LEN) as u16)
                        .to_be_bytes()
                        .to_vec(),
                    body_len,
                ))
            }
            _ => {
                let extension = body_len
                    .checked_sub(RELIABLE_EXTENDED32_MIN_BODY_LEN)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(reliable_length_range_error)?;
                Ok(Self::explicit(
                    15,
                    extension.to_be_bytes().to_vec(),
                    body_len,
                ))
            }
        }
    }

    /// Preserve explicit length metadata without requiring its parts to agree.
    pub fn explicit(
        nibble: u8,
        extension_bytes: impl Into<Vec<u8>>,
        declared_body_len: usize,
    ) -> Self {
        Self {
            nibble,
            extension_bytes: extension_bytes.into(),
            declared_body_len,
        }
    }

    /// Return the preserved four-bit Len discriminator without masking.
    pub const fn nibble(&self) -> u8 {
        self.nibble
    }

    /// Borrow the exact preserved Len extension bytes.
    pub fn extension_bytes(&self) -> &[u8] {
        &self.extension_bytes
    }

    /// Return the preserved logical body length.
    pub const fn declared_body_len(&self) -> usize {
        self.declared_body_len
    }

    /// Decode a body length from the preserved wire representation.
    pub(super) fn wire_body_len(&self) -> Result<usize> {
        match (self.nibble, self.extension_bytes.as_slice()) {
            (nibble @ 0..=12, []) => Ok(usize::from(nibble)),
            (13, [extension]) => RELIABLE_EXTENDED8_MIN_BODY_LEN
                .checked_add(usize::from(*extension))
                .ok_or_else(reliable_length_overflow_error),
            (14, [high, low]) => RELIABLE_EXTENDED16_MIN_BODY_LEN
                .checked_add(usize::from(u16::from_be_bytes([*high, *low])))
                .ok_or_else(reliable_length_overflow_error),
            (15, [first, second, third, fourth]) => {
                let extension = u32::from_be_bytes([*first, *second, *third, *fourth]);
                let extension =
                    usize::try_from(extension).map_err(|_| reliable_length_overflow_error())?;
                RELIABLE_EXTENDED32_MIN_BODY_LEN
                    .checked_add(extension)
                    .ok_or_else(reliable_length_overflow_error)
            }
            (0..=12, _) => Err(CrafterError::invalid_field_value(
                "coap.reliable.length",
                "direct Len encoding must not contain extension bytes",
            )),
            (13, _) => Err(CrafterError::invalid_field_value(
                "coap.reliable.length",
                "Len 13 encoding requires exactly one extension byte",
            )),
            (14, _) => Err(CrafterError::invalid_field_value(
                "coap.reliable.length",
                "Len 14 encoding requires exactly two extension bytes",
            )),
            (15, _) => Err(CrafterError::invalid_field_value(
                "coap.reliable.length",
                "Len 15 encoding requires exactly four extension bytes",
            )),
            (_, _) => Err(CrafterError::invalid_field_value(
                "coap.reliable.length",
                "Len discriminator exceeds four bits",
            )),
        }
    }

    pub(super) fn declared_frame_len(&self, token_length: &CoapTokenLength) -> Result<usize> {
        checked_reliable_frame_len(
            self.extension_bytes.len(),
            token_length.extension_bytes().len(),
            token_length.declared_len(),
            self.declared_body_len,
        )
    }

    fn encode_extension(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.extension_bytes);
    }
}

/// The checked byte boundaries of one complete reliable CoAP frame.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DecodedReliableFrameBoundary<'a> {
    pub(super) length: CoapReliableLength,
    pub(super) token_length: CoapTokenLength,
    pub(super) code: CoapCode,
    pub(super) token: &'a [u8],
    pub(super) body: &'a [u8],
    /// Bytes through the Len/TKL octet and optional Len extension.
    pub(super) length_header_len: usize,
    /// Bytes through Code, optional TKL extension, and Token.
    pub(super) header_len: usize,
    /// Exact boundary immediately after this frame's declared body.
    pub(super) frame_len: usize,
}

/// Encode the complete framing header through the Token boundary.
///
/// Exact Len and TKL extension bytes are copied without normalization. The
/// returned length is the number of bytes appended before the body.
#[allow(dead_code)]
pub(super) fn encode_reliable_header(
    length: &CoapReliableLength,
    token_length: &CoapTokenLength,
    code: CoapCode,
    token: &CoapToken,
    out: &mut Vec<u8>,
) -> Result<usize> {
    let header_len = checked_reliable_frame_len(
        length.extension_bytes().len(),
        token_length.extension_bytes().len(),
        token.len(),
        0,
    )?;
    let mut encoded = Vec::with_capacity(header_len);
    encoded.push(((length.nibble() & 0x0f) << 4) | (token_length.nibble() & 0x0f));
    length.encode_extension(&mut encoded);
    encoded.push(code.wire_value());
    encode_reliable_token(token_length, token, &mut encoded)?;
    out.extend_from_slice(&encoded);
    Ok(header_len)
}

/// Decode the boundaries and borrowed fields of exactly one reliable frame.
///
/// Bytes after `frame_len` belong to a following frame or to caller-owned
/// trailing data and are never included in `body`.
#[allow(dead_code)]
pub(super) fn decode_reliable_frame_boundary(
    bytes: &[u8],
) -> Result<DecodedReliableFrameBoundary<'_>> {
    let first = *bytes
        .first()
        .ok_or_else(|| CrafterError::buffer_too_short("coap.reliable.header", 1, bytes.len()))?;
    let length_nibble = first >> 4;
    let token_length_nibble = first & 0x0f;
    let after_first = bytes.get(1..).unwrap_or_default();
    let (length, length_extension_len) = decode_reliable_length(length_nibble, after_first)?;
    let length_header_len = 1usize
        .checked_add(length_extension_len)
        .ok_or_else(reliable_length_overflow_error)?;
    let after_length = bytes.get(length_header_len..).unwrap_or_default();
    let code = *after_length.first().ok_or_else(|| {
        CrafterError::buffer_too_short("coap.reliable.code", 1, after_length.len())
    })?;
    let after_code = after_length.get(1..).unwrap_or_default();
    let decoded_token = decode_reliable_token(token_length_nibble, after_code)?;
    let header_len = length_header_len
        .checked_add(1)
        .and_then(|value| value.checked_add(decoded_token.consumed))
        .ok_or_else(reliable_length_overflow_error)?;
    let body_len = length.declared_body_len();
    let after_header = bytes.get(header_len..).unwrap_or_default();
    let body = after_header.get(..body_len).ok_or_else(|| {
        CrafterError::buffer_too_short("coap.reliable.body", body_len, after_header.len())
    })?;
    let frame_len = header_len
        .checked_add(body_len)
        .ok_or_else(reliable_length_overflow_error)?;

    Ok(DecodedReliableFrameBoundary {
        length,
        token_length: decoded_token.token_length,
        code: CoapCode::from_wire(code),
        token: decoded_token.token,
        body,
        length_header_len,
        header_len,
        frame_len,
    })
}

fn decode_reliable_length(
    nibble: u8,
    bytes_after_first: &[u8],
) -> Result<(CoapReliableLength, usize)> {
    let (extension_bytes, extension_len) = match nibble {
        0..=12 => (Vec::new(), 0),
        13 => {
            let extension = bytes_after_first.first().ok_or_else(|| {
                CrafterError::buffer_too_short(
                    "coap.reliable.length.extended8",
                    1,
                    bytes_after_first.len(),
                )
            })?;
            (vec![*extension], 1)
        }
        14 => {
            let extension = bytes_after_first.get(..2).ok_or_else(|| {
                CrafterError::buffer_too_short(
                    "coap.reliable.length.extended16",
                    2,
                    bytes_after_first.len(),
                )
            })?;
            (extension.to_vec(), 2)
        }
        15 => {
            let extension = bytes_after_first.get(..4).ok_or_else(|| {
                CrafterError::buffer_too_short(
                    "coap.reliable.length.extended32",
                    4,
                    bytes_after_first.len(),
                )
            })?;
            (extension.to_vec(), 4)
        }
        _ => {
            return Err(CrafterError::invalid_field_value(
                "coap.reliable.length",
                "Len discriminator exceeds four bits",
            ))
        }
    };
    let length = CoapReliableLength::explicit(nibble, extension_bytes, 0);
    let declared_body_len = length.wire_body_len()?;

    Ok((
        CoapReliableLength::explicit(nibble, length.extension_bytes().to_vec(), declared_body_len),
        extension_len,
    ))
}

fn checked_reliable_frame_len(
    length_extension_len: usize,
    token_extension_len: usize,
    token_len: usize,
    body_len: usize,
) -> Result<usize> {
    1usize
        .checked_add(length_extension_len)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(token_extension_len))
        .and_then(|value| value.checked_add(token_len))
        .and_then(|value| value.checked_add(body_len))
        .ok_or_else(reliable_length_overflow_error)
}

fn reliable_length_overflow_error() -> CrafterError {
    CrafterError::invalid_field_value("coap.reliable.length", "reliable frame length overflow")
}

fn reliable_length_range_error() -> CrafterError {
    CrafterError::invalid_field_value(
        "coap.reliable.length",
        "body length exceeds the RFC 8323 encoding range",
    )
}

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

    fn encode_complete_frame(body_len: usize, token_len: usize) -> Vec<u8> {
        let length = CoapReliableLength::canonical_for_body_len(body_len).unwrap();
        let token_length = CoapTokenLength::canonical_for_len(token_len).unwrap();
        let token = CoapToken::from_bytes(vec![0xa5; token_len]);
        let mut bytes = Vec::new();
        encode_reliable_header(&length, &token_length, CoapCode::get(), &token, &mut bytes)
            .unwrap();
        bytes.extend(std::iter::repeat(0xb0).take(body_len));
        bytes
    }

    #[test]
    fn reliable_length_transitions_encode_and_decode_exact_boundaries() {
        let cases: &[(usize, u8, &[u8])] = &[
            (0, 0, &[]),
            (12, 12, &[]),
            (13, 13, &[0x00]),
            (268, 13, &[0xff]),
            (269, 14, &[0x00, 0x00]),
            (65_804, 14, &[0xff, 0xff]),
            (65_805, 15, &[0x00, 0x00, 0x00, 0x00]),
        ];

        for &(body_len, nibble, extension) in cases {
            let bytes = encode_complete_frame(body_len, 0);
            let decoded = decode_reliable_frame_boundary(&bytes).unwrap();

            assert_eq!(decoded.length.nibble(), nibble);
            assert_eq!(decoded.length.extension_bytes(), extension);
            assert_eq!(decoded.length.declared_body_len(), body_len);
            assert_eq!(decoded.length.wire_body_len().unwrap(), body_len);
            assert_eq!(decoded.length_header_len, 1 + extension.len());
            assert_eq!(decoded.header_len, 2 + extension.len());
            assert_eq!(decoded.frame_len, bytes.len());
            assert_eq!(decoded.body.len(), body_len);
            assert_eq!(decoded.code, CoapCode::get());
        }
    }

    #[test]
    fn extended32_length_covers_its_full_wire_range_without_allocation() {
        let maximum = u64::from(u32::MAX) + RELIABLE_EXTENDED32_MIN_BODY_LEN as u64;
        let maximum = usize::try_from(maximum).expect("64-bit test target");
        let length = CoapReliableLength::canonical_for_body_len(maximum).unwrap();

        assert_eq!(length.nibble(), 15);
        assert_eq!(length.extension_bytes(), &[0xff; 4]);
        assert_eq!(length.wire_body_len().unwrap(), maximum);
        assert_eq!(length.declared_body_len(), maximum);
        assert!(CoapReliableLength::canonical_for_body_len(maximum + 1).is_err());
    }

    #[test]
    fn reliable_token_boundaries_stop_before_body_at_every_transition() {
        let cases: &[(usize, u8, &[u8])] = &[
            (0, 0, &[]),
            (8, 8, &[]),
            (12, 12, &[]),
            (13, 13, &[0x00]),
            (268, 13, &[0xff]),
            (269, 14, &[0x00, 0x00]),
            (CoapTokenLength::MAX_LEN, 14, &[0xff, 0xff]),
        ];

        for &(token_len, nibble, extension) in cases {
            let mut bytes = encode_complete_frame(1, token_len);
            bytes.extend_from_slice(&[0xcc, 0xdd]);
            let decoded = decode_reliable_frame_boundary(&bytes).unwrap();

            assert_eq!(decoded.token_length.nibble(), nibble);
            assert_eq!(decoded.token_length.extension_bytes(), extension);
            assert_eq!(decoded.token_length.declared_len(), token_len);
            assert_eq!(decoded.token, vec![0xa5; token_len]);
            assert_eq!(decoded.body, &[0xb0]);
            assert_eq!(decoded.header_len, 2 + extension.len() + token_len);
            assert_eq!(&bytes[decoded.frame_len..], &[0xcc, 0xdd]);
        }
    }

    #[test]
    fn reliable_decoder_leaves_complete_following_frames_unconsumed() {
        let first = encode_complete_frame(2, 1);
        let second = encode_complete_frame(0, 0);
        let mut stream_slice = first.clone();
        stream_slice.extend_from_slice(&second);

        let decoded = decode_reliable_frame_boundary(&stream_slice).unwrap();

        assert_eq!(decoded.frame_len, first.len());
        assert_eq!(decoded.body, &[0xb0, 0xb0]);
        assert_eq!(&stream_slice[decoded.frame_len..], second);
    }

    #[test]
    fn reliable_header_encoding_preserves_explicit_extensions_exactly() {
        let length = CoapReliableLength::explicit(13, vec![0xfe, 0xed], usize::MAX);
        let token_length = CoapTokenLength::explicit(13, vec![0xca, 0xfe], usize::MAX);
        let token = CoapToken::from_bytes([0xaa, 0xbb]);
        let mut encoded = Vec::new();

        assert_eq!(
            encode_reliable_header(
                &length,
                &token_length,
                CoapCode::from_wire(0xe1),
                &token,
                &mut encoded,
            )
            .unwrap(),
            8,
        );
        assert_eq!(encoded, [0xdd, 0xfe, 0xed, 0xe1, 0xca, 0xfe, 0xaa, 0xbb]);
    }

    #[test]
    fn reliable_truncation_reports_each_stable_boundary() {
        let cases = [
            (
                Vec::new(),
                CrafterError::buffer_too_short("coap.reliable.header", 1, 0),
            ),
            (
                vec![0xd0],
                CrafterError::buffer_too_short("coap.reliable.length.extended8", 1, 0),
            ),
            (
                vec![0xe0, 0x00],
                CrafterError::buffer_too_short("coap.reliable.length.extended16", 2, 1),
            ),
            (
                vec![0xf0, 0x00, 0x00, 0x00],
                CrafterError::buffer_too_short("coap.reliable.length.extended32", 4, 3),
            ),
            (
                vec![0x00],
                CrafterError::buffer_too_short("coap.reliable.code", 1, 0),
            ),
            (
                vec![0x0d, 0x01],
                CrafterError::buffer_too_short("coap.reliable.token-length.extended8", 1, 0),
            ),
            (
                vec![0x0e, 0x01, 0x00],
                CrafterError::buffer_too_short("coap.reliable.token-length.extended16", 2, 1),
            ),
            (
                vec![0x02, 0x01, 0xaa],
                CrafterError::buffer_too_short("coap.reliable.token", 2, 1),
            ),
            (
                vec![0x30, 0x01, 0xaa, 0xbb],
                CrafterError::buffer_too_short("coap.reliable.body", 3, 2),
            ),
        ];

        for (bytes, expected) in cases {
            assert_eq!(decode_reliable_frame_boundary(&bytes), Err(expected));
        }
    }

    #[test]
    fn reliable_length_arithmetic_reports_overflow() {
        assert_eq!(
            checked_reliable_frame_len(usize::MAX, 0, 0, 0),
            Err(reliable_length_overflow_error())
        );
        assert_eq!(
            CoapReliableLength::explicit(0, Vec::new(), usize::MAX)
                .declared_frame_len(&CoapTokenLength::default()),
            Err(reliable_length_overflow_error())
        );
        assert_eq!(
            CoapReliableLength::explicit(0, Vec::new(), 0)
                .declared_frame_len(&CoapTokenLength::explicit(0, Vec::new(), usize::MAX),),
            Err(reliable_length_overflow_error())
        );
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
