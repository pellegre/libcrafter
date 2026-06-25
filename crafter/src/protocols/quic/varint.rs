//! QUIC variable-length integer encoding.
//!
//! RFC 9000 Section 16 defines a 62-bit integer space where the two high bits
//! of the first byte encode the total width: 1, 2, 4, or 8 bytes. Encoders here
//! emit the shortest valid representation by default and return structured
//! errors for values outside the 62-bit wire space. Decoders accept byte-complete
//! non-shortest encodings and return the consumed width so callers can decide
//! whether that matters for their protocol field.

use crate::error::{CrafterError, Result};

/// Maximum value encoded in a one-byte QUIC varint.
pub const QUIC_VARINT_ONE_BYTE_MAX: u64 = (1 << 6) - 1;
/// Maximum value encoded in a two-byte QUIC varint.
pub const QUIC_VARINT_TWO_BYTE_MAX: u64 = (1 << 14) - 1;
/// Maximum value encoded in a four-byte QUIC varint.
pub const QUIC_VARINT_FOUR_BYTE_MAX: u64 = (1 << 30) - 1;
/// Maximum value representable by a QUIC varint.
pub const QUIC_VARINT_MAX: u64 = (1u64 << 62) - 1;

const QUIC_VARINT_TWO_BYTE_PREFIX: u16 = 0x4000;
const QUIC_VARINT_FOUR_BYTE_PREFIX: u32 = 0x8000_0000;
const QUIC_VARINT_EIGHT_BYTE_PREFIX: u64 = 0xc000_0000_0000_0000;

/// QUIC variable-length integer value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicVarInt {
    value: u64,
}

impl QuicVarInt {
    /// Create a validated QUIC varint.
    pub const fn new(value: u64) -> Result<Self> {
        if value <= QUIC_VARINT_MAX {
            Ok(Self { value })
        } else {
            Err(CrafterError::invalid_field_value(
                "quic.varint",
                "QUIC varint value exceeds 62 bits",
            ))
        }
    }

    /// Preserve a caller-supplied value without applying future range policy.
    pub const fn from_u64_unchecked(value: u64) -> Self {
        Self { value }
    }

    /// Return the preserved numeric value.
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Shortest valid encoded length for this value.
    pub const fn encoded_len(self) -> Result<usize> {
        encoded_len_for_value(self.value)
    }

    /// Append the shortest valid wire encoding and return the width used.
    pub fn encode(self, out: &mut Vec<u8>) -> Result<usize> {
        let len = self.encoded_len()?;
        self.encode_with_len(len, out)?;
        Ok(len)
    }

    /// Return the shortest valid wire encoding as a new vector.
    pub fn encode_to_vec(self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Append this value using an explicit QUIC varint width.
    ///
    /// The width must be one of 1, 2, 4, or 8 bytes, and the value must fit in
    /// the requested width. This supports later builder code that preserves a
    /// caller-pinned non-shortest length while still rejecting impossible wire
    /// encodings.
    pub fn encode_with_len(self, len: usize, out: &mut Vec<u8>) -> Result<()> {
        encode_value_with_len(self.value, len, out)
    }

    /// Compatibility alias for older skeleton callers.
    pub fn encode_placeholder(self, out: &mut Vec<u8>) -> Result<()> {
        self.encode(out).map(|_| ())
    }

    /// Decode one QUIC varint and return the value plus consumed byte length.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize)> {
        decode(bytes)
    }

    /// Compatibility alias for older skeleton callers.
    pub fn decode_placeholder(bytes: &[u8]) -> Result<(Self, usize)> {
        Self::decode(bytes)
    }
}

/// Create a validated QUIC varint.
pub const fn quic_varint(value: u64) -> Result<QuicVarInt> {
    QuicVarInt::new(value)
}

/// Shortest valid QUIC varint encoded length for a value.
pub const fn encoded_len_for_value(value: u64) -> Result<usize> {
    if value <= QUIC_VARINT_ONE_BYTE_MAX {
        Ok(1)
    } else if value <= QUIC_VARINT_TWO_BYTE_MAX {
        Ok(2)
    } else if value <= QUIC_VARINT_FOUR_BYTE_MAX {
        Ok(4)
    } else if value <= QUIC_VARINT_MAX {
        Ok(8)
    } else {
        Err(CrafterError::invalid_field_value(
            "quic.varint",
            "QUIC varint value exceeds 62 bits",
        ))
    }
}

/// Append the shortest valid QUIC varint encoding for a value.
pub fn encode_value(value: u64, out: &mut Vec<u8>) -> Result<usize> {
    QuicVarInt::new(value)?.encode(out)
}

/// Append a QUIC varint using an explicit width of 1, 2, 4, or 8 bytes.
pub fn encode_value_with_len(value: u64, len: usize, out: &mut Vec<u8>) -> Result<()> {
    match len {
        1 if value <= QUIC_VARINT_ONE_BYTE_MAX => out.push(value as u8),
        2 if value <= QUIC_VARINT_TWO_BYTE_MAX => {
            out.extend_from_slice(&((value as u16) | QUIC_VARINT_TWO_BYTE_PREFIX).to_be_bytes());
        }
        4 if value <= QUIC_VARINT_FOUR_BYTE_MAX => {
            out.extend_from_slice(&((value as u32) | QUIC_VARINT_FOUR_BYTE_PREFIX).to_be_bytes());
        }
        8 if value <= QUIC_VARINT_MAX => {
            out.extend_from_slice(&(value | QUIC_VARINT_EIGHT_BYTE_PREFIX).to_be_bytes());
        }
        1 | 2 | 4 | 8 => {
            return Err(CrafterError::invalid_field_value(
                "quic.varint",
                "value does not fit requested QUIC varint length",
            ))
        }
        _ => {
            return Err(CrafterError::invalid_field_value(
                "quic.varint.length",
                "QUIC varint length must be 1, 2, 4, or 8 bytes",
            ))
        }
    }
    Ok(())
}

/// Decode one QUIC varint from the front of a byte slice.
pub fn decode(bytes: &[u8]) -> Result<(QuicVarInt, usize)> {
    let Some(first) = bytes.first().copied() else {
        return Err(CrafterError::buffer_too_short("quic.varint", 1, 0));
    };
    let len = encoded_len_from_prefix(first);
    if bytes.len() < len {
        return Err(CrafterError::buffer_too_short(
            "quic.varint",
            len,
            bytes.len(),
        ));
    }

    let value = match len {
        1 => (first & 0x3f) as u64,
        2 => (u16::from_be_bytes([bytes[0], bytes[1]]) & 0x3fff) as u64,
        4 => (u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & 0x3fff_ffff) as u64,
        8 => {
            u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]) & 0x3fff_ffff_ffff_ffff
        }
        _ => unreachable!("QUIC varint prefix maps only to 1, 2, 4, or 8 bytes"),
    };

    Ok((QuicVarInt::from_u64_unchecked(value), len))
}

/// Encoded length indicated by a QUIC varint prefix byte.
pub const fn encoded_len_from_prefix(first: u8) -> usize {
    match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    }
}

/// Return true when a decoded value used its shortest possible QUIC varint
/// encoding.
pub const fn is_shortest_encoding(value: u64, encoded_len: usize) -> bool {
    if value <= QUIC_VARINT_ONE_BYTE_MAX {
        encoded_len == 1
    } else if value <= QUIC_VARINT_TWO_BYTE_MAX {
        encoded_len == 2
    } else if value <= QUIC_VARINT_FOUR_BYTE_MAX {
        encoded_len == 4
    } else if value <= QUIC_VARINT_MAX {
        encoded_len == 8
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(value: u64) -> Vec<u8> {
        QuicVarInt::new(value).unwrap().encode_to_vec().unwrap()
    }

    #[test]
    fn quic_varint_encoding_uses_shortest_widths_at_boundaries() {
        assert_eq!(encoded(0), [0x00]);
        assert_eq!(encoded(QUIC_VARINT_ONE_BYTE_MAX), [0x3f]);
        assert_eq!(encoded(QUIC_VARINT_ONE_BYTE_MAX + 1), [0x40, 0x40]);
        assert_eq!(encoded(QUIC_VARINT_TWO_BYTE_MAX), [0x7f, 0xff]);
        assert_eq!(
            encoded(QUIC_VARINT_TWO_BYTE_MAX + 1),
            [0x80, 0x00, 0x40, 0x00]
        );
        assert_eq!(encoded(QUIC_VARINT_FOUR_BYTE_MAX), [0xbf, 0xff, 0xff, 0xff]);
        assert_eq!(
            encoded(QUIC_VARINT_FOUR_BYTE_MAX + 1),
            [0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encoded(QUIC_VARINT_MAX),
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn quic_varint_encoding_reports_canonical_lengths() {
        assert_eq!(encoded_len_for_value(0).unwrap(), 1);
        assert_eq!(encoded_len_for_value(64).unwrap(), 2);
        assert_eq!(encoded_len_for_value(16_384).unwrap(), 4);
        assert_eq!(encoded_len_for_value(1_073_741_824).unwrap(), 8);
    }

    #[test]
    fn quic_varint_encoding_supports_explicit_valid_widths() {
        let mut out = Vec::new();

        encode_value_with_len(63, 1, &mut out).unwrap();
        encode_value_with_len(64, 2, &mut out).unwrap();
        encode_value_with_len(16_384, 4, &mut out).unwrap();
        encode_value_with_len(1_073_741_824, 8, &mut out).unwrap();

        assert_eq!(
            out,
            [
                0x3f, 0x40, 0x40, 0x80, 0x00, 0x40, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
                0x00,
            ]
        );
    }

    #[test]
    fn quic_varint_encoding_rejects_impossible_values_and_widths() {
        assert_eq!(
            QuicVarInt::new(QUIC_VARINT_MAX + 1).unwrap_err(),
            CrafterError::invalid_field_value("quic.varint", "QUIC varint value exceeds 62 bits")
        );

        let mut out = Vec::new();
        assert_eq!(
            encode_value_with_len(64, 1, &mut out).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.varint",
                "value does not fit requested QUIC varint length"
            )
        );
        assert_eq!(
            encode_value_with_len(0, 3, &mut out).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.varint.length",
                "QUIC varint length must be 1, 2, 4, or 8 bytes"
            )
        );
        assert!(out.is_empty());
    }

    #[test]
    fn quic_varint_decode_errors_report_empty_and_truncated_inputs() {
        assert_eq!(
            decode(&[]).unwrap_err(),
            CrafterError::buffer_too_short("quic.varint", 1, 0)
        );
        assert_eq!(
            decode(&[0x40]).unwrap_err(),
            CrafterError::buffer_too_short("quic.varint", 2, 1)
        );
        assert_eq!(
            decode(&[0x80, 0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("quic.varint", 4, 3)
        );
        assert_eq!(
            decode(&[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("quic.varint", 8, 7)
        );
    }

    #[test]
    fn quic_varint_decode_errors_consume_one_complete_value() {
        let cases: &[(&[u8], u64, usize)] = &[
            (&[0x25, 0xaa], 0x25, 1),
            (&[0x40, 0x25, 0xaa], 0x25, 2),
            (&[0x80, 0x00, 0x00, 0x25, 0xaa], 0x25, 4),
            (
                &[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0xaa],
                0x25,
                8,
            ),
        ];

        for (bytes, expected, consumed) in cases {
            let (decoded, actual_consumed) = decode(bytes).unwrap();

            assert_eq!(decoded.value(), *expected);
            assert_eq!(actual_consumed, *consumed);
            assert_eq!(bytes[actual_consumed], 0xaa);
        }
    }

    #[test]
    fn quic_varint_decode_errors_cover_overlong_and_maximum_values() {
        let (overlong, consumed) = decode(&[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25])
            .expect("complete overlong value decodes");
        assert_eq!(overlong.value(), 0x25);
        assert_eq!(consumed, 8);
        assert!(!is_shortest_encoding(overlong.value(), consumed));

        let (max, consumed) = decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
            .expect("maximum value decodes");
        assert_eq!(max.value(), QUIC_VARINT_MAX);
        assert_eq!(consumed, 8);
        assert!(is_shortest_encoding(max.value(), consumed));
    }
}
