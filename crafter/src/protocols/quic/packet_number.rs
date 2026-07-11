//! QUIC packet-number encoding helpers.
//!
//! QUIC packet headers encode only the low 1, 2, 3, or 4 bytes of a packet
//! number. The header packet-number length bits carry `encoded_len - 1`.
//! Full packet-number reconstruction remains explicit because it requires the
//! endpoint's expected next packet number.

use crate::error::{CrafterError, Result};

/// Maximum packet number value encoded in one byte.
pub const QUIC_PACKET_NUMBER_ONE_BYTE_MAX: u64 = 0xff;
/// Maximum packet number value encoded in two bytes.
pub const QUIC_PACKET_NUMBER_TWO_BYTE_MAX: u64 = 0xffff;
/// Maximum packet number value encoded in three bytes.
pub const QUIC_PACKET_NUMBER_THREE_BYTE_MAX: u64 = 0xff_ffff;
/// Maximum packet number value encoded in four bytes.
pub const QUIC_PACKET_NUMBER_FOUR_BYTE_MAX: u64 = 0xffff_ffff;
const QUIC_PACKET_NUMBER_LIMIT: u64 = 1 << 62;

/// Packet-number value and optional encoded length override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicPacketNumber {
    value: u64,
    encoded_len: Option<usize>,
}

impl QuicPacketNumber {
    /// Preserve a packet-number value without applying future length policy.
    pub const fn new(value: u64) -> Self {
        Self {
            value,
            encoded_len: None,
        }
    }

    /// Preserve an explicit encoded length override, including malformed ones.
    pub const fn with_encoded_len(mut self, encoded_len: usize) -> Self {
        self.encoded_len = Some(encoded_len);
        self
    }

    /// Return the preserved packet-number value.
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Return the explicit encoded length override, if present.
    pub const fn encoded_len_value(self) -> Option<usize> {
        self.encoded_len
    }

    /// Effective encoded length, including an explicit caller override.
    pub const fn effective_encoded_len(self) -> Result<usize> {
        match self.encoded_len {
            Some(len) => validate_value_for_len(self.value, len),
            None => encoded_len_for_value(self.value),
        }
    }

    /// Append this packet number using its effective encoded length.
    pub fn encode(self, out: &mut Vec<u8>) -> Result<usize> {
        let len = self.effective_encoded_len()?;
        encode_value_with_len(self.value, len, out)?;
        Ok(len)
    }

    /// Return this packet number as encoded bytes.
    pub fn encode_to_vec(self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.effective_encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode a packet number when the caller already knows the encoded length.
    pub fn decode(bytes: &[u8], encoded_len: usize) -> Result<(Self, usize)> {
        decode(bytes, encoded_len)
    }

    /// Compatibility alias for older skeleton callers.
    pub fn decode_placeholder(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() > 4 {
            return Err(CrafterError::invalid_field_value(
                "quic.packet_number.length",
                "QUIC packet-number length must be 1, 2, 3, or 4 bytes",
            ));
        }
        decode(bytes, bytes.len())
    }

    /// Reconstruct the full packet number closest to `expected_next`.
    ///
    /// This implements the RFC 9000 Appendix A.3 decoding window after header
    /// protection has been removed. The preserved value is treated as the
    /// truncated packet number and the effective encoded length supplies the
    /// one-, two-, three-, or four-byte window width.
    pub fn reconstruct(self, expected_next: u64) -> Result<u64> {
        if expected_next >= QUIC_PACKET_NUMBER_LIMIT {
            return Err(CrafterError::invalid_field_value(
                "quic.packet_number.expected_next",
                "expected next QUIC packet number exceeds the 62-bit limit",
            ));
        }

        let encoded_len = self.effective_encoded_len()?;
        let window = 1u64 << (encoded_len * 8);
        let half_window = window / 2;
        let mask = window - 1;
        let mut candidate = (expected_next & !mask) | self.value;

        // Write the RFC's lower-bound comparison without subtracting when the
        // mathematical bound is negative.
        if expected_next >= half_window
            && candidate <= expected_next - half_window
            && candidate < QUIC_PACKET_NUMBER_LIMIT - window
        {
            candidate += window;
        } else if candidate > expected_next + half_window && candidate >= window {
            candidate -= window;
        }

        if candidate >= QUIC_PACKET_NUMBER_LIMIT {
            return Err(CrafterError::invalid_field_value(
                "quic.packet_number",
                "reconstructed QUIC packet number exceeds the 62-bit limit",
            ));
        }
        Ok(candidate)
    }

    /// Stable summary for packet inspection.
    pub fn summary(self) -> String {
        match self.effective_encoded_len() {
            Ok(len) => format!("value={} encoded_len={len}", self.value),
            Err(err) => format!("value={} encoded_len=invalid ({err})", self.value),
        }
    }
}

/// Shortest valid packet-number encoded length for a value.
pub const fn encoded_len_for_value(value: u64) -> Result<usize> {
    if value <= QUIC_PACKET_NUMBER_ONE_BYTE_MAX {
        Ok(1)
    } else if value <= QUIC_PACKET_NUMBER_TWO_BYTE_MAX {
        Ok(2)
    } else if value <= QUIC_PACKET_NUMBER_THREE_BYTE_MAX {
        Ok(3)
    } else if value <= QUIC_PACKET_NUMBER_FOUR_BYTE_MAX {
        Ok(4)
    } else {
        Err(CrafterError::invalid_field_value(
            "quic.packet_number",
            "QUIC packet number exceeds 32 encoded bits",
        ))
    }
}

/// Header packet-number length bits for an encoded length.
pub const fn header_bits_for_len(encoded_len: usize) -> Result<u8> {
    match encoded_len {
        1 => Ok(0),
        2 => Ok(1),
        3 => Ok(2),
        4 => Ok(3),
        _ => Err(CrafterError::invalid_field_value(
            "quic.packet_number.length",
            "QUIC packet-number length must be 1, 2, 3, or 4 bytes",
        )),
    }
}

/// Decode packet-number header length bits to a byte length.
pub const fn len_from_header_bits(bits: u8) -> usize {
    ((bits & 0x03) as usize) + 1
}

/// Append a packet number using an explicit encoded width.
pub fn encode_value_with_len(value: u64, encoded_len: usize, out: &mut Vec<u8>) -> Result<()> {
    validate_value_for_len(value, encoded_len)?;
    let be = (value as u32).to_be_bytes();
    match encoded_len {
        1 => out.push(be[3]),
        2 => out.extend_from_slice(&be[2..4]),
        3 => out.extend_from_slice(&be[1..4]),
        4 => out.extend_from_slice(&be),
        _ => unreachable!("validated QUIC packet-number length"),
    }
    Ok(())
}

/// Decode a packet number from a known encoded width.
pub fn decode(bytes: &[u8], encoded_len: usize) -> Result<(QuicPacketNumber, usize)> {
    validate_len(encoded_len)?;
    if bytes.len() < encoded_len {
        return Err(CrafterError::buffer_too_short(
            "quic.packet_number",
            encoded_len,
            bytes.len(),
        ));
    }

    let value = match encoded_len {
        1 => bytes[0] as u64,
        2 => u16::from_be_bytes([bytes[0], bytes[1]]) as u64,
        3 => u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as u64,
        4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
        _ => unreachable!("validated QUIC packet-number length"),
    };
    Ok((
        QuicPacketNumber {
            value,
            encoded_len: Some(encoded_len),
        },
        encoded_len,
    ))
}

const fn validate_len(encoded_len: usize) -> Result<()> {
    match encoded_len {
        1 | 2 | 3 | 4 => Ok(()),
        _ => Err(CrafterError::invalid_field_value(
            "quic.packet_number.length",
            "QUIC packet-number length must be 1, 2, 3, or 4 bytes",
        )),
    }
}

const fn validate_value_for_len(value: u64, encoded_len: usize) -> Result<usize> {
    match encoded_len {
        1 if value <= QUIC_PACKET_NUMBER_ONE_BYTE_MAX => Ok(1),
        2 if value <= QUIC_PACKET_NUMBER_TWO_BYTE_MAX => Ok(2),
        3 if value <= QUIC_PACKET_NUMBER_THREE_BYTE_MAX => Ok(3),
        4 if value <= QUIC_PACKET_NUMBER_FOUR_BYTE_MAX => Ok(4),
        1 | 2 | 3 | 4 => Err(CrafterError::invalid_field_value(
            "quic.packet_number",
            "value does not fit requested QUIC packet-number length",
        )),
        _ => Err(CrafterError::invalid_field_value(
            "quic.packet_number.length",
            "QUIC packet-number length must be 1, 2, 3, or 4 bytes",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(value: u64) -> Vec<u8> {
        QuicPacketNumber::new(value).encode_to_vec().unwrap()
    }

    #[test]
    fn quic_packet_number_encoding_uses_shortest_widths_at_boundaries() {
        assert_eq!(encoded(0), [0x00]);
        assert_eq!(encoded(QUIC_PACKET_NUMBER_ONE_BYTE_MAX), [0xff]);
        assert_eq!(encoded(QUIC_PACKET_NUMBER_ONE_BYTE_MAX + 1), [0x01, 0x00]);
        assert_eq!(encoded(QUIC_PACKET_NUMBER_TWO_BYTE_MAX), [0xff, 0xff]);
        assert_eq!(
            encoded(QUIC_PACKET_NUMBER_TWO_BYTE_MAX + 1),
            [0x01, 0x00, 0x00]
        );
        assert_eq!(
            encoded(QUIC_PACKET_NUMBER_THREE_BYTE_MAX),
            [0xff, 0xff, 0xff]
        );
        assert_eq!(
            encoded(QUIC_PACKET_NUMBER_THREE_BYTE_MAX + 1),
            [0x01, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encoded(QUIC_PACKET_NUMBER_FOUR_BYTE_MAX),
            [0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn quic_packet_number_encoding_honors_explicit_widths() {
        let packet_number = QuicPacketNumber::new(0x12).with_encoded_len(3);

        assert_eq!(packet_number.effective_encoded_len().unwrap(), 3);
        assert_eq!(packet_number.encode_to_vec().unwrap(), [0x00, 0x00, 0x12]);
        assert_eq!(header_bits_for_len(3).unwrap(), 2);
        assert_eq!(len_from_header_bits(2), 3);
    }

    #[test]
    fn quic_packet_number_encoding_decodes_known_widths_and_consumed_len() {
        let cases: &[(&[u8], usize, u64)] = &[
            (&[0x7b, 0xaa], 1, 0x7b),
            (&[0x12, 0x34, 0xaa], 2, 0x1234),
            (&[0x12, 0x34, 0x56, 0xaa], 3, 0x12_3456),
            (&[0x12, 0x34, 0x56, 0x78, 0xaa], 4, 0x1234_5678),
        ];

        for (bytes, len, expected) in cases {
            let (decoded, consumed) = decode(bytes, *len).unwrap();

            assert_eq!(decoded.value(), *expected);
            assert_eq!(decoded.encoded_len_value(), Some(*len));
            assert_eq!(consumed, *len);
            assert_eq!(bytes[consumed], 0xaa);
        }
    }

    #[test]
    fn quic_packet_number_encoding_reports_invalid_lengths_and_truncation() {
        assert_eq!(
            decode(&[], 1).unwrap_err(),
            CrafterError::buffer_too_short("quic.packet_number", 1, 0)
        );
        assert_eq!(
            decode(&[0x12], 2).unwrap_err(),
            CrafterError::buffer_too_short("quic.packet_number", 2, 1)
        );
        assert_eq!(
            header_bits_for_len(5).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.packet_number.length",
                "QUIC packet-number length must be 1, 2, 3, or 4 bytes"
            )
        );
        assert_eq!(
            QuicPacketNumber::new(0x0100)
                .with_encoded_len(1)
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.packet_number",
                "value does not fit requested QUIC packet-number length"
            )
        );
        assert_eq!(
            QuicPacketNumber::new(QUIC_PACKET_NUMBER_FOUR_BYTE_MAX + 1)
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.packet_number",
                "QUIC packet number exceeds 32 encoded bits"
            )
        );
    }

    #[test]
    fn quic_summary_inspection_packet_number_summary_is_stable() {
        assert_eq!(
            QuicPacketNumber::new(0x12).with_encoded_len(2).summary(),
            "value=18 encoded_len=2"
        );
        assert!(QuicPacketNumber::new(0x0100)
            .with_encoded_len(1)
            .summary()
            .starts_with("value=256 encoded_len=invalid"));
    }
}
