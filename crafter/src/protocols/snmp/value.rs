//! SNMP value scaffold.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`; value types and BER-backed
//! preservation behavior are added in later slices.

#![cfg_attr(not(test), allow(dead_code))]

use super::ber;
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SnmpValue {
    Integer(i64),
    OctetString(SnmpOctetString),
    Null,
    RawTlv(RawTlv),
}

impl SnmpValue {
    pub(super) const fn integer(value: i64) -> Self {
        Self::Integer(value)
    }

    pub(super) fn octet_string(bytes: impl Into<Vec<u8>>) -> Self {
        Self::OctetString(SnmpOctetString::new(bytes))
    }

    pub(super) const fn null() -> Self {
        Self::Null
    }

    pub(super) fn raw_tlv(bytes: impl Into<Vec<u8>>) -> Self {
        Self::RawTlv(RawTlv::new(bytes))
    }

    pub(super) fn decode_octet_string(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (content, rest) = decode_primitive_content(
            bytes,
            ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_OCTET_STRING),
            "snmp.ber.octet_string",
            "expected universal primitive OCTET STRING",
            "octet string length exceeds supported size",
        )?;

        Ok((Self::octet_string(content.to_vec()), rest))
    }

    pub(super) fn decode_null(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (content, rest) = decode_primitive_content(
            bytes,
            ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_NULL),
            "snmp.ber.null",
            "expected universal primitive NULL",
            "NULL length exceeds supported size",
        )?;
        if !content.is_empty() {
            return Err(ber::invalid_ber_field(
                "snmp.ber.null",
                "NULL must have zero content length",
            ));
        }

        Ok((Self::Null, rest))
    }

    pub(super) fn as_octets(&self) -> Option<&[u8]> {
        match self {
            Self::OctetString(value) => Some(value.as_bytes()),
            _ => None,
        }
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Integer(value) => ber::encode_integer(*value, out),
            Self::OctetString(value) => encode_tlv(
                ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_OCTET_STRING),
                value.as_bytes(),
                out,
            ),
            Self::Null => {
                ber::encode_identifier(
                    ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_NULL),
                    out,
                )?;
                ber::encode_length(0, out)
            }
            Self::RawTlv(raw) => {
                out.extend_from_slice(raw.as_bytes());
                Ok(())
            }
        }
    }

    pub(super) fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SnmpOctetString {
    bytes: Vec<u8>,
}

impl SnmpOctetString {
    pub(super) fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RawTlv {
    bytes: Vec<u8>,
}

impl RawTlv {
    pub(super) fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn encode_tlv(tag: ber::BerTag, content: &[u8], out: &mut Vec<u8>) -> Result<()> {
    ber::encode_identifier(tag, out)?;
    ber::encode_length(content.len(), out)?;
    out.extend_from_slice(content);
    Ok(())
}

fn decode_primitive_content<'a>(
    bytes: &'a [u8],
    expected_tag: ber::BerTag,
    context: &'static str,
    tag_reason: &'static str,
    overflow_reason: &'static str,
) -> Result<(&'a [u8], &'a [u8])> {
    let (tag, rest) = ber::decode_identifier(bytes)?;
    if tag != expected_tag {
        return Err(ber::invalid_ber_field(context, tag_reason));
    }

    let (length, rest) = ber::decode_length(rest)?;
    if rest.len() < length {
        let prefix_len = bytes.len() - rest.len();
        let required = prefix_len
            .checked_add(length)
            .ok_or_else(|| ber::invalid_ber_field(context, overflow_reason))?;
        return Err(ber::truncated_ber(context, required, bytes.len()));
    }

    let (content, rest) = rest.split_at(length);
    Ok((content, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CrafterError;

    #[test]
    fn snmp_ber_integer_value_constructor_emits_minimal_integer_tlv() {
        assert_eq!(
            SnmpValue::integer(-129)
                .to_bytes()
                .expect("encode SNMP integer"),
            [0x02, 0x02, 0xff, 0x7f]
        );
        assert_eq!(
            SnmpValue::integer(128)
                .to_bytes()
                .expect("encode SNMP integer"),
            [0x02, 0x02, 0x00, 0x80]
        );
    }

    #[test]
    fn snmp_ber_integer_non_minimal_raw_tlv_is_preserved() {
        let bytes = [0x02, 0x02, 0x00, 0x7f];
        let value = SnmpValue::raw_tlv(bytes.to_vec());

        assert_eq!(value.to_bytes().expect("encode raw TLV"), bytes);
    }

    #[test]
    fn snmp_ber_integer_malformed_raw_tlv_constructor_preserves_bytes() {
        let bytes = [0x02, 0x02, 0x7f];
        let value = SnmpValue::raw_tlv(bytes.to_vec());

        assert_eq!(value.to_bytes().expect("encode raw TLV"), bytes);
    }

    #[test]
    fn snmp_ber_string_null_empty_octet_string_roundtrips() {
        let value = SnmpValue::octet_string(Vec::<u8>::new());

        assert_eq!(value.to_bytes().expect("encode OCTET STRING"), [0x04, 0x00]);
        assert_eq!(value.as_octets(), Some(&[][..]));

        let mut bytes = value.to_bytes().expect("encode OCTET STRING");
        bytes.push(0xaa);
        let (decoded, rest) = SnmpValue::decode_octet_string(&bytes).expect("decode OCTET STRING");

        assert_eq!(decoded.as_octets(), Some(&[][..]));
        assert_eq!(rest, &[0xaa]);
    }

    #[test]
    fn snmp_ber_string_null_non_utf8_octets_are_preserved() {
        let octets = [0x00, 0xff, 0x80, b'a'];
        let value = SnmpValue::octet_string(octets.to_vec());

        assert_eq!(
            value.to_bytes().expect("encode OCTET STRING"),
            [0x04, 0x04, 0x00, 0xff, 0x80, b'a']
        );
        assert_eq!(value.as_octets(), Some(&octets[..]));

        let (decoded, rest) = SnmpValue::decode_octet_string(&[0x04, 0x04, 0x00, 0xff, 0x80, b'a'])
            .expect("decode OCTET STRING");

        assert_eq!(decoded.as_octets(), Some(&octets[..]));
        assert!(rest.is_empty());
    }

    #[test]
    fn snmp_ber_string_null_long_form_octet_string_length_roundtrips() {
        let octets = (0..128).map(|value| value as u8).collect::<Vec<_>>();
        let value = SnmpValue::octet_string(octets.clone());
        let encoded = value.to_bytes().expect("encode OCTET STRING");

        assert_eq!(&encoded[..3], &[0x04, 0x81, 0x80]);
        assert_eq!(&encoded[3..], &octets);

        let (decoded, rest) =
            SnmpValue::decode_octet_string(&encoded).expect("decode OCTET STRING");

        assert_eq!(decoded.as_octets(), Some(&octets[..]));
        assert!(rest.is_empty());
    }

    #[test]
    fn snmp_ber_string_null_zero_length_null_encodes_and_decodes() {
        let value = SnmpValue::null();

        assert_eq!(value.to_bytes().expect("encode NULL"), [0x05, 0x00]);

        let (decoded, rest) = SnmpValue::decode_null(&[0x05, 0x00, 0xaa]).expect("decode NULL");

        assert_eq!(decoded, SnmpValue::Null);
        assert_eq!(rest, &[0xaa]);
    }

    #[test]
    fn snmp_ber_string_null_malformed_null_uses_error_or_raw_tlv_preservation() {
        let bytes = [0x05, 0x01, 0x00];

        assert_eq!(
            SnmpValue::decode_null(&bytes),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.null",
                "NULL must have zero content length"
            ))
        );

        let value = SnmpValue::raw_tlv(bytes.to_vec());
        assert_eq!(value.to_bytes().expect("encode raw TLV"), bytes);
    }
}
