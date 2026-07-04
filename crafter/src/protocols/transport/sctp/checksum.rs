//! SCTP CRC32c checksum helpers.
//!
//! RFC 9260 section 6.8 computes CRC32c over the complete SCTP packet with the
//! common-header checksum field set to zero.

#![allow(dead_code)]

use crate::checksum::crc32c;
use crate::error::{CrafterError, Result};

use super::constants::{SCTP_CHECKSUM_LEN, SCTP_CHECKSUM_OFFSET, SCTP_COMMON_HEADER_LEN};

const SCTP_COMMON_HEADER_CONTEXT: &str = "sctp common header";
const SCTP_CHECKSUM_END: usize = SCTP_CHECKSUM_OFFSET + SCTP_CHECKSUM_LEN;

/// Inspection status for an SCTP common-header checksum observed on decode.
///
/// RFC 9653 gives zero checksum handling explicit negotiation context, so a
/// received zero field is reported separately instead of being collapsed into
/// ordinary valid or invalid CRC32c status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SctpChecksumStatus {
    /// Checksum validation was not attempted.
    NotChecked,
    /// Nonzero checksum validates against the SCTP packet bytes.
    Valid,
    /// Nonzero checksum failed validation.
    Invalid,
    /// The wire checksum field was explicitly zero.
    ZeroChecksum,
}

impl SctpChecksumStatus {
    /// Stable lowercase label for summaries and inspection output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::ZeroChecksum => "zero_checksum",
        }
    }
}

/// Compute CRC32c/Castagnoli over bytes that are already in SCTP checksum form.
pub(crate) fn sctp_crc32c(data: &[u8]) -> u32 {
    crc32c(data)
}

/// Compute the SCTP packet CRC32c after zeroing the common-header checksum field.
pub(crate) fn sctp_packet_crc32c(packet: &[u8]) -> Result<u32> {
    if packet.len() < SCTP_COMMON_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_COMMON_HEADER_CONTEXT,
            SCTP_COMMON_HEADER_LEN,
            packet.len(),
        ));
    }

    let mut checksum_input = packet.to_vec();
    checksum_input[SCTP_CHECKSUM_OFFSET..SCTP_CHECKSUM_END].fill(0);
    Ok(sctp_crc32c(&checksum_input))
}

/// Report decode-time SCTP checksum status without rejecting inspectable bytes.
pub(crate) fn decoded_sctp_checksum_status(packet: &[u8]) -> Result<SctpChecksumStatus> {
    if packet.len() < SCTP_COMMON_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_COMMON_HEADER_CONTEXT,
            SCTP_COMMON_HEADER_LEN,
            packet.len(),
        ));
    }

    let wire_checksum = u32::from_be_bytes([
        packet[SCTP_CHECKSUM_OFFSET],
        packet[SCTP_CHECKSUM_OFFSET + 1],
        packet[SCTP_CHECKSUM_OFFSET + 2],
        packet[SCTP_CHECKSUM_OFFSET + 3],
    ]);

    if wire_checksum == 0 {
        return Ok(SctpChecksumStatus::ZeroChecksum);
    }

    if sctp_packet_crc32c(packet)? == wire_checksum {
        Ok(SctpChecksumStatus::Valid)
    } else {
        Ok(SctpChecksumStatus::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sctp_crc32c_matches_standard_castagnoli_check_value() {
        assert_eq!(sctp_crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn sctp_crc32c_zeroes_common_header_checksum_field() -> Result<()> {
        let mut packet = vec![0u8; SCTP_COMMON_HEADER_LEN + 4];
        packet[0..2].copy_from_slice(&5_000u16.to_be_bytes());
        packet[2..4].copy_from_slice(&9_899u16.to_be_bytes());
        packet[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
        packet[SCTP_COMMON_HEADER_LEN..].copy_from_slice(&[1, 0, 0, 4]);

        let mut with_first_checksum = packet.clone();
        with_first_checksum[SCTP_CHECKSUM_OFFSET..SCTP_CHECKSUM_END]
            .copy_from_slice(&0xdead_beefu32.to_be_bytes());

        let mut with_second_checksum = packet.clone();
        with_second_checksum[SCTP_CHECKSUM_OFFSET..SCTP_CHECKSUM_END]
            .copy_from_slice(&0x0102_0304u32.to_be_bytes());

        let mut expected_input = with_first_checksum.clone();
        expected_input[SCTP_CHECKSUM_OFFSET..SCTP_CHECKSUM_END].fill(0);

        let expected = sctp_crc32c(&expected_input);
        assert_eq!(sctp_packet_crc32c(&with_first_checksum)?, expected);
        assert_eq!(sctp_packet_crc32c(&with_second_checksum)?, expected);
        assert_ne!(sctp_crc32c(&with_first_checksum), expected);
        Ok(())
    }

    #[test]
    fn sctp_crc32c_rejects_short_common_header() {
        let short = [0u8; SCTP_COMMON_HEADER_LEN - 1];
        let err = sctp_packet_crc32c(&short).unwrap_err();

        assert_eq!(
            err,
            CrafterError::BufferTooShort {
                context: SCTP_COMMON_HEADER_CONTEXT,
                required: SCTP_COMMON_HEADER_LEN,
                available: short.len(),
            }
        );
    }

    #[test]
    fn sctp_checksum_status_rejects_short_common_header() {
        let short = [0u8; SCTP_COMMON_HEADER_LEN - 1];
        let err = decoded_sctp_checksum_status(&short).unwrap_err();

        assert_eq!(
            err,
            CrafterError::BufferTooShort {
                context: SCTP_COMMON_HEADER_CONTEXT,
                required: SCTP_COMMON_HEADER_LEN,
                available: short.len(),
            }
        );
    }
}
