//! NTP packet decode helpers.

use super::constants::NTP_FIXED_HEADER_LEN;
use super::message::{ntp_parse_first_octet, Ntp, NtpReferenceId, NtpShortFormat, NtpTimestamp};
use crate::error::{CrafterError, Result};

const NTP_HEADER_CONTEXT: &str = "ntp.header";

/// Decode an NTP packet fixed header.
pub fn decode_ntp(bytes: &[u8]) -> Result<Ntp> {
    if bytes.len() < NTP_FIXED_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            NTP_HEADER_CONTEXT,
            NTP_FIXED_HEADER_LEN,
            bytes.len(),
        ));
    }

    let (leap_indicator, version, mode) = ntp_parse_first_octet(bytes[0]);

    Ok(Ntp::new()
        .leap_indicator(leap_indicator)
        .version(version)
        .mode(mode)
        .stratum(bytes[1])
        .poll(bytes[2] as i8)
        .precision(bytes[3] as i8)
        .root_delay(NtpShortFormat::from_raw(read_u32(bytes, 4)))
        .root_dispersion(NtpShortFormat::from_raw(read_u32(bytes, 8)))
        .reference_id(NtpReferenceId::from_bytes([
            bytes[12], bytes[13], bytes[14], bytes[15],
        ]))
        .reference_timestamp(NtpTimestamp::from_raw(read_u64(bytes, 16)))
        .origin_timestamp(NtpTimestamp::from_raw(read_u64(bytes, 24)))
        .receive_timestamp(NtpTimestamp::from_raw(read_u64(bytes, 32)))
        .transmit_timestamp(NtpTimestamp::from_raw(read_u64(bytes, 40))))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    #[test]
    fn ntp_parse_header_decodes_all_fixed_fields() {
        let bytes = [
            0xdb, 0x10, 0xf4, 0xe9, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, b'G', b'P',
            b'S', 0x00, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x51, 0x52,
            0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        ];

        let ntp = decode_ntp(&bytes).unwrap();

        assert_eq!(ntp.first_octet_value(), 0xdb);
        assert_eq!(ntp.stratum_value().value(), 0x10);
        assert_eq!(ntp.poll_value(), -12);
        assert_eq!(ntp.precision_value(), -23);
        assert_eq!(ntp.root_delay_value().raw(), 0x0102_0304);
        assert_eq!(ntp.root_dispersion_value().raw(), 0x1112_1314);
        assert_eq!(ntp.reference_id_value().bytes(), [b'G', b'P', b'S', 0x00]);
        assert_eq!(ntp.reference_timestamp_value().raw(), 0x2122_2324_2526_2728);
        assert_eq!(ntp.origin_timestamp_value().raw(), 0x3132_3334_3536_3738);
        assert_eq!(ntp.receive_timestamp_value().raw(), 0x4142_4344_4546_4748);
        assert_eq!(ntp.transmit_timestamp_value().raw(), 0x5152_5354_5556_5758);
        assert_eq!(Packet::from_layer(ntp).compile().unwrap().as_bytes(), bytes);
    }

    #[test]
    fn ntp_parse_errors_header_reports_stable_truncation_context() {
        match decode_ntp(&[0u8; NTP_FIXED_HEADER_LEN - 1]).unwrap_err() {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ntp.header");
                assert_eq!(required, NTP_FIXED_HEADER_LEN);
                assert_eq!(available, NTP_FIXED_HEADER_LEN - 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
