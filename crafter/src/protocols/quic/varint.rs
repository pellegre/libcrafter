//! QUIC variable-length integer encoding.
//!
//! RFC 9000 Section 16 defines a 62-bit integer space where the two high bits
//! of the first byte encode the total width: 1, 2, 4, or 8 bytes. Encoders here
//! emit the shortest valid representation by default and return structured
//! errors for values outside the 62-bit wire space.

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

    /// Placeholder decoder that reports truncation before unsupported parsing.
    pub fn decode_placeholder(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.is_empty() {
            return Err(CrafterError::buffer_too_short(
                "quic.varint.prefix",
                1,
                bytes.len(),
            ));
        }

        Err(CrafterError::invalid_field_value(
            "quic.varint",
            "QUIC varint decoding is not implemented in the module skeleton",
        ))
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
}
