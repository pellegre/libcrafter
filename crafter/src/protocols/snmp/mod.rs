//! Simple Network Management Protocol (SNMP) module scaffold.
//!
//! SNMP support is being added in source-backed slices. This module exposes
//! the community-based packet layer and source-backed BER/PDU primitives; it
//! does not expose a manager workflow, SNMPv3 security behavior, or UDP
//! registry dispatch yet.
//!
//! Source gate: any SNMP wire behavior added here must first be authorized by
//! `docs/snmp-rfc-manifest.md`.

mod ber;
mod constants;
mod decode;
mod message;
mod oid;
mod pdu;
mod registry;
mod value;
mod varbind;

pub use constants::{
    SNMP_PDU_TAG_GET_BULK_REQUEST, SNMP_PDU_TAG_GET_NEXT_REQUEST, SNMP_PDU_TAG_GET_REQUEST,
    SNMP_PDU_TAG_INFORM_REQUEST, SNMP_PDU_TAG_REPORT, SNMP_PDU_TAG_RESPONSE,
    SNMP_PDU_TAG_SET_REQUEST, SNMP_PDU_TAG_TRAP, SNMP_PDU_TAG_TRAP_V2, SNMP_PORT, SNMP_TRAP_PORT,
};
pub use message::{
    Snmp, SnmpEncryptedScopedData, SnmpRawSecurityParameters, SnmpScopedPdu, SnmpUsmEngineTime,
    SnmpUsmSecurityParameters, SnmpV3GlobalData, SnmpV3Message, SnmpVersion,
};
pub use oid::SnmpOid;
pub use pdu::{SnmpGetBulkPdu, SnmpPdu, SnmpRawPdu, SnmpRawPduBody, SnmpRequestPdu, SnmpV1TrapPdu};
pub use registry::{
    snmp_error_status_label, snmp_error_status_meta, snmp_error_status_name,
    snmp_error_status_status, snmp_error_status_summary, snmp_pdu_tag_meta, snmp_pdu_tag_name,
    snmp_pdu_tag_status, snmp_security_model_label, snmp_security_model_meta,
    snmp_security_model_name, snmp_security_model_status, snmp_security_model_summary,
    snmp_udp_port_label, snmp_udp_port_meta, snmp_udp_port_name, snmp_udp_port_summary,
    snmp_v3_flags_label, SnmpErrorStatus, SnmpErrorStatusAssignment, SnmpErrorStatusMeta,
    SnmpPduTagMeta, SnmpPduTagStatus, SnmpSecurityModel, SnmpSecurityModelMeta,
    SnmpSecurityModelStatus, SnmpUdpPortMeta, SnmpV3Flags, SNMP_ERROR_STATUS_AUTHORIZATION_ERROR,
    SNMP_ERROR_STATUS_BAD_VALUE, SNMP_ERROR_STATUS_COMMIT_FAILED, SNMP_ERROR_STATUS_GEN_ERR,
    SNMP_ERROR_STATUS_INCONSISTENT_NAME, SNMP_ERROR_STATUS_INCONSISTENT_VALUE,
    SNMP_ERROR_STATUS_NOT_WRITABLE, SNMP_ERROR_STATUS_NO_ACCESS, SNMP_ERROR_STATUS_NO_CREATION,
    SNMP_ERROR_STATUS_NO_ERROR, SNMP_ERROR_STATUS_NO_SUCH_NAME, SNMP_ERROR_STATUS_READ_ONLY,
    SNMP_ERROR_STATUS_RESOURCE_UNAVAILABLE, SNMP_ERROR_STATUS_TOO_BIG,
    SNMP_ERROR_STATUS_UNDO_FAILED, SNMP_ERROR_STATUS_WRONG_ENCODING,
    SNMP_ERROR_STATUS_WRONG_LENGTH, SNMP_ERROR_STATUS_WRONG_TYPE, SNMP_ERROR_STATUS_WRONG_VALUE,
    SNMP_SECURITY_MODEL_ANY, SNMP_SECURITY_MODEL_SNMPV1, SNMP_SECURITY_MODEL_SNMPV2C,
    SNMP_SECURITY_MODEL_TSM, SNMP_SECURITY_MODEL_USM, SNMP_V3_FLAG_AUTH, SNMP_V3_FLAG_KNOWN_MASK,
    SNMP_V3_FLAG_PRIVACY, SNMP_V3_FLAG_REPORTABLE, SNMP_V3_FLAG_RESERVED_MASK,
};
pub use varbind::{SnmpVarBind, SnmpVarBindList};

#[cfg(test)]
mod tests {
    use super::{ber, oid::SnmpOid, value::SnmpValue};
    use crate::error::{CrafterError, Result};

    fn assert_buffer_too_short(
        error: CrafterError,
        expected_context: &'static str,
        expected_required: usize,
        expected_available: usize,
    ) {
        match error {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, expected_context);
                assert_eq!(required, expected_required);
                assert_eq!(available, expected_available);
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }

    fn assert_invalid_field(
        error: CrafterError,
        expected_field: &'static str,
        expected_reason: &'static str,
    ) {
        match error {
            CrafterError::InvalidFieldValue { field, reason } => {
                assert_eq!(field, expected_field);
                assert_eq!(reason, expected_reason);
            }
            other => panic!("expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn snmp_ber_roundtrip_identifier_and_length_forms() -> Result<()> {
        let identifier_cases = [
            (
                ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_INTEGER),
                0x02,
            ),
            (
                ber::BerTag::new(ber::BerClass::Universal, true, ber::BER_TAG_SEQUENCE),
                0x30,
            ),
            (
                ber::BerTag::new(
                    ber::BerClass::Application,
                    false,
                    ber::SNMP_APPLICATION_TAG_COUNTER64,
                ),
                0x46,
            ),
            (
                ber::BerTag::new(
                    ber::BerClass::ContextSpecific,
                    true,
                    ber::SNMP_PDU_TAG_REPORT,
                ),
                0xa8,
            ),
        ];

        // Source-backed: docs/snmp-rfc-manifest.md, RFC 3417 Section 8
        // records SNMP BER definite-length encoding and constructed SEQUENCE
        // form; RFC 3416 Section 3 records application and PDU tag choices.
        for (tag, expected_octet) in identifier_cases {
            let mut encoded = Vec::new();
            ber::encode_identifier(tag, &mut encoded)?;
            assert_eq!(encoded, [expected_octet]);

            encoded.push(0xaa);
            let (decoded, rest) = ber::decode_identifier(&encoded)?;
            assert_eq!(decoded, tag);
            assert_eq!(rest, &[0xaa]);
        }

        let length_cases: &[(usize, &[u8])] = &[
            (0, &[0x00]),
            (127, &[0x7f]),
            (128, &[0x81, 0x80]),
            (256, &[0x82, 0x01, 0x00]),
        ];

        // Source-backed: docs/snmp-rfc-manifest.md, RFC 3417 Sections 8 and
        // 8.1 record definite length form and permit non-minimal long-form
        // length decoding while the encoder emits minimal definite lengths.
        for (length, expected) in length_cases {
            let mut encoded = Vec::new();
            ber::encode_length(*length, &mut encoded)?;
            assert_eq!(&encoded, expected);

            encoded.push(0xbb);
            let (decoded, rest) = ber::decode_length(&encoded)?;
            assert_eq!(decoded, *length);
            assert_eq!(rest, &[0xbb]);
        }

        let (decoded, rest) = ber::decode_length(&[0x82, 0x00, 0x80, 0xcc])?;
        assert_eq!(decoded, 128);
        assert_eq!(rest, &[0xcc]);

        Ok(())
    }

    #[test]
    fn snmp_ber_roundtrip_scalar_values_inside_sequence() -> Result<()> {
        let mut content = Vec::new();
        ber::encode_integer(-1, &mut content)?;
        SnmpValue::octet_string([0x00, 0xff, b'A']).encode(&mut content)?;
        SnmpValue::null().encode(&mut content)?;

        let mut encoded = Vec::new();
        ber::encode_sequence(&content, &mut encoded)?;

        // Source-backed: docs/snmp-rfc-manifest.md, RFC 3417 Section 8
        // records primitive form for simple types and constructed form for
        // SEQUENCE under SNMP BER restrictions.
        assert_eq!(
            encoded,
            [0x30, 0x0a, 0x02, 0x01, 0xff, 0x04, 0x03, 0x00, 0xff, b'A', 0x05, 0x00]
        );

        let sequence_content = ber::decode_sequence_exact(&encoded)?;
        let (integer, rest) = ber::decode_integer(sequence_content)?;
        assert_eq!(integer, -1);

        let (octets, rest) = SnmpValue::decode_octet_string(rest)?;
        assert_eq!(octets.as_octets(), Some(&[0x00, 0xff, b'A'][..]));

        let (null, rest) = SnmpValue::decode_null(rest)?;
        assert_eq!(null, SnmpValue::Null);
        ber::require_sequence_exact(rest)?;

        Ok(())
    }

    #[test]
    fn snmp_ber_roundtrip_object_identifier() -> Result<()> {
        let oid = SnmpOid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0])?;
        let encoded = oid.to_bytes()?;

        // Source-backed: docs/snmp-rfc-manifest.md, RFC 2578 Section 3.5
        // records OBJECT IDENTIFIER values as ordered sub-identifiers.
        assert_eq!(
            encoded,
            [0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00]
        );

        let mut with_rest = encoded.clone();
        with_rest.push(0xaa);
        let (decoded, rest) = SnmpOid::decode(&with_rest)?;

        assert_eq!(decoded.as_slice(), oid.as_slice());
        assert_eq!(rest, &[0xaa]);

        Ok(())
    }

    #[test]
    fn snmp_ber_roundtrip_application_values() -> Result<()> {
        let cases = [
            (
                SnmpValue::ip_address([192, 0, 2, 1]),
                vec![0x40, 0x04, 192, 0, 2, 1],
            ),
            (
                SnmpValue::counter32(u32::MAX),
                vec![0x41, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff],
            ),
            (SnmpValue::gauge32(128), vec![0x42, 0x02, 0x00, 0x80]),
            (SnmpValue::time_ticks(12_345), vec![0x43, 0x02, 0x30, 0x39]),
            (
                SnmpValue::opaque([0x30, 0x03, 0x02, 0x01, 0x05]),
                vec![0x44, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05],
            ),
            (
                SnmpValue::counter64(u64::MAX),
                vec![
                    0x46, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
            ),
            (
                SnmpValue::raw_application(5, true, [0x05, 0x00]),
                vec![0x65, 0x02, 0x05, 0x00],
            ),
        ];

        // Source-backed: docs/snmp-rfc-manifest.md, RFC 2578 Sections 7.1.5
        // through 7.1.11 and RFC 3416 Section 3 record the SNMP application
        // value tags used by these BER fixtures.
        for (value, expected) in cases {
            let encoded = value.to_bytes()?;
            assert_eq!(encoded, expected);

            let mut with_rest = encoded.clone();
            with_rest.push(0xaa);
            let (decoded, rest) = SnmpValue::decode_application(&with_rest)?;

            assert_eq!(decoded, value);
            assert_eq!(rest, &[0xaa]);
        }

        Ok(())
    }

    #[test]
    fn snmp_ber_malformed_short_identifier_reports_structured_error() {
        let error = ber::decode_identifier(&[]).expect_err("missing identifier must error");

        assert_buffer_too_short(error, "snmp.ber.identifier", 1, 0);
    }

    #[test]
    fn snmp_ber_malformed_short_length_reports_structured_error() {
        let error = ber::decode_sequence(&[0x30]).expect_err("missing length must error");

        assert_buffer_too_short(error, "snmp.ber.length", 1, 0);
    }

    #[test]
    fn snmp_ber_malformed_indefinite_length_is_rejected_by_manifest_scope() {
        let error = ber::decode_sequence(&[0x30, 0x80, 0x00, 0x00]).expect_err("indefinite length");

        assert_invalid_field(
            error,
            "snmp.ber.length",
            "indefinite length is not valid for SNMP",
        );
    }

    #[test]
    fn snmp_ber_malformed_truncated_content_reports_required_and_available() {
        let error = SnmpValue::decode_octet_string(&[0x04, 0x02, 0xaa])
            .expect_err("truncated OCTET STRING content must error");

        assert_buffer_too_short(error, "snmp.ber.octet_string", 4, 3);
    }

    #[test]
    fn snmp_ber_malformed_invalid_oid_continuation_reports_structured_error() {
        let error = SnmpOid::decode(&[0x06, 0x02, 0x2b, 0x80]).expect_err("unterminated OID arc");

        assert_buffer_too_short(error, "snmp.ber.object_identifier.base128", 3, 2);
    }

    #[test]
    fn snmp_ber_malformed_application_values_report_structured_errors() {
        let error = SnmpValue::decode_ip_address(&[0x40, 0x03, 192, 0, 2])
            .expect_err("short IpAddress content must error");
        assert_invalid_field(
            error,
            "snmp.ber.application.ip_address",
            "IpAddress content must be exactly 4 octets",
        );

        let error = SnmpValue::decode_counter32(&[0x41, 0x00])
            .expect_err("empty Counter32 content must error");
        assert_invalid_field(
            error,
            "snmp.ber.application.counter32",
            "application integer requires at least one content octet",
        );

        let error = SnmpValue::decode_counter64(&[
            0x46, 0x0a, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
        ])
        .expect_err("wide Counter64 content must error");
        assert_invalid_field(
            error,
            "snmp.ber.application.counter64",
            "application integer exceeds source-backed wire width",
        );
    }
}
