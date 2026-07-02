//! NTP packet decode helpers.

use super::constants::{NTP_FIXED_HEADER_LEN, NTP_MODE_RESERVED, NTP_VERSION_1, NTP_VERSION_4};
use super::extension::{self, NtpExtensionField};
use super::message::{ntp_parse_first_octet, Ntp, NtpLegacyMac};
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NtpDecodedTail {
    pub(super) extension_fields: Vec<NtpExtensionField>,
    pub(super) legacy_mac: Option<NtpLegacyMac>,
}

/// Decode a standalone NTP UDP payload.
pub fn decode_ntp(bytes: &[u8]) -> Result<Ntp> {
    Ntp::decode(bytes)
}

/// Conservative UDP/123 shape gate for built-in registry dispatch.
pub fn looks_like_ntp_payload(bytes: &[u8]) -> bool {
    if bytes.len() < NTP_FIXED_HEADER_LEN {
        return false;
    }

    let (_, version, mode) = ntp_parse_first_octet(bytes[0]);
    if !(NTP_VERSION_1..=NTP_VERSION_4).contains(&version.value()) {
        return false;
    }
    if mode.value() == NTP_MODE_RESERVED {
        return false;
    }

    tail_shape_is_plausible(&bytes[NTP_FIXED_HEADER_LEN..])
}

pub(super) fn encoded_tail_len(
    extension_fields: &[NtpExtensionField],
    legacy_mac: Option<&NtpLegacyMac>,
) -> usize {
    extension::encoded_all_len(extension_fields, legacy_mac.is_some())
        + legacy_mac.map_or(0, NtpLegacyMac::len)
}

pub(super) fn encode_tail(
    extension_fields: &[NtpExtensionField],
    legacy_mac: Option<&NtpLegacyMac>,
    out: &mut Vec<u8>,
) -> Result<()> {
    extension::encode_all(extension_fields, legacy_mac.is_some(), out)?;
    if let Some(mac) = legacy_mac {
        out.extend_from_slice(mac.bytes());
    }
    Ok(())
}

/// Parse bytes after the fixed NTP header into extension fields and MAC tail.
pub(super) fn parse_tail(tail: &[u8]) -> Result<NtpDecodedTail> {
    let decoded = extension::decode_all(tail)?;
    Ok(NtpDecodedTail {
        extension_fields: decoded.fields,
        legacy_mac: decoded.legacy_mac.map(NtpLegacyMac::from_bytes),
    })
}

pub(super) fn decode_tail(tail: &[u8]) -> Result<NtpDecodedTail> {
    parse_tail(tail)
}

pub(super) fn tail_shape_is_plausible(tail: &[u8]) -> bool {
    extension::tail_shape_is_plausible(tail)
}

#[cfg(test)]
mod tests {
    use super::super::constants::{
        NTP_EXTENSION_FIELD_HEADER_LEN, NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN,
        NTP_EXTENSION_FIELD_MIN_LEN, NTP_FIXED_HEADER_LEN, NTP_LEGACY_MAC_KEY_ID_LEN,
    };
    use super::*;
    use crate::error::CrafterError;
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

    #[test]
    fn ntp_extension_roundtrip_decode_helpers_preserve_tail_partition() -> Result<()> {
        let extension = NtpExtensionField::new(0xbeef, [0xaa, 0xbb])
            .padding([0xcc, 0xdd])
            .declared_length(16);
        let legacy_mac = NtpLegacyMac::from_key_id_and_digest(0x0102_0304, [0xee; 16]);
        let mut tail = Vec::new();

        encode_tail(&[extension], Some(&legacy_mac), &mut tail)?;
        let decoded = decode_tail(&tail)?;

        assert_eq!(decoded.extension_fields.len(), 1);
        assert_eq!(decoded.extension_fields[0].field_type(), 0xbeef);
        assert_eq!(
            decoded.extension_fields[0].value(),
            &[0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(decoded.legacy_mac.as_ref(), Some(&legacy_mac));

        let mut reencoded = Vec::new();
        encode_tail(
            &decoded.extension_fields,
            decoded.legacy_mac.as_ref(),
            &mut reencoded,
        )?;
        assert_eq!(reencoded, tail);
        Ok(())
    }

    #[test]
    fn ntp_tail_parser_parse_tail_preserves_standalone_crypto_nak() -> Result<()> {
        let tail = [0x01, 0x02, 0x03, 0x04];

        let decoded = parse_tail(&tail)?;

        assert!(decoded.extension_fields.is_empty());
        let legacy_mac = decoded.legacy_mac.expect("crypto-NAK tail");
        assert_eq!(legacy_mac.bytes(), tail.as_slice());
        assert_eq!(legacy_mac.key_id(), Some(0x0102_0304));
        assert_eq!(legacy_mac.digest(), &[]);
        Ok(())
    }

    #[test]
    fn ntp_tail_parser_parse_tail_preserves_standalone_legacy_mac_lengths() -> Result<()> {
        for tail_len in [20, 24] {
            let mut tail = vec![0x7f; tail_len];
            tail[..NTP_LEGACY_MAC_KEY_ID_LEN].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);

            let decoded = parse_tail(&tail)?;

            assert!(decoded.extension_fields.is_empty());
            let legacy_mac = decoded.legacy_mac.expect("standalone legacy MAC");
            assert_eq!(legacy_mac.bytes(), tail.as_slice());
            assert_eq!(legacy_mac.key_id(), Some(0x0102_0304));
            assert_eq!(
                legacy_mac.digest().len(),
                tail_len - NTP_LEGACY_MAC_KEY_ID_LEN
            );
        }
        Ok(())
    }

    #[test]
    fn ntp_tail_parser_parse_tail_preserves_extension_without_mac() -> Result<()> {
        let body =
            [0xaa; NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN - NTP_EXTENSION_FIELD_HEADER_LEN];
        let mut tail = Vec::new();
        tail.extend_from_slice(&0xdeadu16.to_be_bytes());
        tail.extend_from_slice(
            &(NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN as u16).to_be_bytes(),
        );
        tail.extend_from_slice(&body);

        let decoded = parse_tail(&tail)?;

        assert_eq!(decoded.extension_fields.len(), 1);
        assert_eq!(decoded.extension_fields[0].field_type(), 0xdead);
        assert_eq!(
            decoded.extension_fields[0].declared_length_value(),
            Some(NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN as u16)
        );
        assert_eq!(decoded.extension_fields[0].value(), body.as_slice());
        assert!(decoded.legacy_mac.is_none());
        Ok(())
    }

    #[test]
    fn ntp_tail_parser_parse_tail_splits_extension_and_crypto_nak() -> Result<()> {
        let body = [0xaa; NTP_EXTENSION_FIELD_MIN_LEN - NTP_EXTENSION_FIELD_HEADER_LEN];
        let crypto_nak = [0x01, 0x02, 0x03, 0x04];
        let mut tail = Vec::new();
        tail.extend_from_slice(&0xbeefu16.to_be_bytes());
        tail.extend_from_slice(&(NTP_EXTENSION_FIELD_MIN_LEN as u16).to_be_bytes());
        tail.extend_from_slice(&body);
        tail.extend_from_slice(&crypto_nak);

        let decoded = parse_tail(&tail)?;

        assert_eq!(decoded.extension_fields.len(), 1);
        assert_eq!(decoded.extension_fields[0].field_type(), 0xbeef);
        assert_eq!(decoded.extension_fields[0].value(), body.as_slice());
        let legacy_mac = decoded.legacy_mac.expect("crypto-NAK after extension");
        assert_eq!(legacy_mac.bytes(), crypto_nak.as_slice());
        Ok(())
    }

    #[test]
    fn ntp_tail_parser_parse_tail_reports_truncated_mac_after_extension() {
        let mut tail = Vec::new();
        tail.extend_from_slice(&0xbeefu16.to_be_bytes());
        tail.extend_from_slice(&(NTP_EXTENSION_FIELD_MIN_LEN as u16).to_be_bytes());
        tail.extend_from_slice(
            &[0xaa; NTP_EXTENSION_FIELD_MIN_LEN - NTP_EXTENSION_FIELD_HEADER_LEN],
        );
        tail.extend_from_slice(&[0xcc, 0xdd]);

        match parse_tail(&tail).unwrap_err() {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, extension::NTP_MAC_CONTEXT);
                assert_eq!(required, NTP_LEGACY_MAC_KEY_ID_LEN);
                assert_eq!(available, 2);
            }
            other => panic!("unexpected tail error: {other:?}"),
        }
    }
}
