//! Simple Network Management Protocol (SNMP) module scaffold.
//!
//! SNMP support is being added in source-backed slices. This module is only
//! the Rust home for those later slices; it does not expose a packet layer,
//! builders, decode entrypoint, or UDP registry dispatch yet.
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

#[cfg(test)]
mod tests {
    use super::{ber, oid::SnmpOid, value::SnmpValue};
    use crate::error::Result;

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
}
