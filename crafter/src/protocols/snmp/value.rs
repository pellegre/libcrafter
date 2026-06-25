//! SNMP value scaffold.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`; value types and BER-backed
//! preservation behavior are added in later slices.

#![cfg_attr(not(test), allow(dead_code))]

use super::{ber, registry};
use crate::error::Result;

const SNMP_IP_ADDRESS_LEN: usize = 4;
const SNMP_APPLICATION_U32_MAX_CONTENT_LEN: usize = 5;
const SNMP_APPLICATION_U64_MAX_CONTENT_LEN: usize = 9;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SnmpValue {
    Integer(i64),
    OctetString(SnmpOctetString),
    Null,
    IpAddress([u8; SNMP_IP_ADDRESS_LEN]),
    Counter32(u32),
    Gauge32OrUnsigned32(u32),
    TimeTicks(u32),
    Opaque(SnmpOctetString),
    Counter64(u64),
    RawApplication(RawApplicationValue),
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

    pub(super) const fn ip_address(octets: [u8; SNMP_IP_ADDRESS_LEN]) -> Self {
        Self::IpAddress(octets)
    }

    pub(super) const fn counter32(value: u32) -> Self {
        Self::Counter32(value)
    }

    pub(super) const fn gauge32(value: u32) -> Self {
        Self::Gauge32OrUnsigned32(value)
    }

    pub(super) const fn unsigned32(value: u32) -> Self {
        Self::Gauge32OrUnsigned32(value)
    }

    pub(super) const fn time_ticks(value: u32) -> Self {
        Self::TimeTicks(value)
    }

    pub(super) fn opaque(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Opaque(SnmpOctetString::new(bytes))
    }

    pub(super) const fn counter64(value: u64) -> Self {
        Self::Counter64(value)
    }

    pub(super) fn raw_application(
        tag_number: u8,
        constructed: bool,
        content: impl Into<Vec<u8>>,
    ) -> Self {
        Self::RawApplication(RawApplicationValue::new(tag_number, constructed, content))
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

    pub(super) fn decode_application(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (tag, content, rest) = decode_application_content(bytes, "snmp.ber.application")?;

        let value = match (tag.is_constructed(), tag.number()) {
            (false, ber::SNMP_APPLICATION_TAG_IP_ADDRESS) => {
                Self::IpAddress(decode_ip_address_content(content)?)
            }
            (false, ber::SNMP_APPLICATION_TAG_COUNTER32) => Self::Counter32(
                decode_unsigned_u32_content(content, "snmp.ber.application.counter32")?,
            ),
            (false, ber::SNMP_APPLICATION_TAG_GAUGE32_OR_UNSIGNED32) => Self::Gauge32OrUnsigned32(
                decode_unsigned_u32_content(content, "snmp.ber.application.gauge32_or_unsigned32")?,
            ),
            (false, ber::SNMP_APPLICATION_TAG_TIME_TICKS) => Self::TimeTicks(
                decode_unsigned_u32_content(content, "snmp.ber.application.time_ticks")?,
            ),
            (false, ber::SNMP_APPLICATION_TAG_OPAQUE) => {
                Self::Opaque(SnmpOctetString::new(content.to_vec()))
            }
            (false, ber::SNMP_APPLICATION_TAG_COUNTER64) => Self::Counter64(
                decode_unsigned_u64_content(content, "snmp.ber.application.counter64")?,
            ),
            _ => Self::raw_application(tag.number(), tag.is_constructed(), content.to_vec()),
        };

        Ok((value, rest))
    }

    pub(super) fn decode_ip_address(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (content, rest) = decode_known_application_content(
            bytes,
            ber::SNMP_APPLICATION_TAG_IP_ADDRESS,
            "snmp.ber.application.ip_address",
            "expected application primitive IpAddress",
        )?;

        Ok((Self::IpAddress(decode_ip_address_content(content)?), rest))
    }

    pub(super) fn decode_counter32(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (content, rest) = decode_known_application_content(
            bytes,
            ber::SNMP_APPLICATION_TAG_COUNTER32,
            "snmp.ber.application.counter32",
            "expected application primitive Counter32",
        )?;

        Ok((
            Self::Counter32(decode_unsigned_u32_content(
                content,
                "snmp.ber.application.counter32",
            )?),
            rest,
        ))
    }

    pub(super) fn decode_gauge32_or_unsigned32(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (content, rest) = decode_known_application_content(
            bytes,
            ber::SNMP_APPLICATION_TAG_GAUGE32_OR_UNSIGNED32,
            "snmp.ber.application.gauge32_or_unsigned32",
            "expected application primitive Gauge32/Unsigned32",
        )?;

        Ok((
            Self::Gauge32OrUnsigned32(decode_unsigned_u32_content(
                content,
                "snmp.ber.application.gauge32_or_unsigned32",
            )?),
            rest,
        ))
    }

    pub(super) fn decode_time_ticks(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (content, rest) = decode_known_application_content(
            bytes,
            ber::SNMP_APPLICATION_TAG_TIME_TICKS,
            "snmp.ber.application.time_ticks",
            "expected application primitive TimeTicks",
        )?;

        Ok((
            Self::TimeTicks(decode_unsigned_u32_content(
                content,
                "snmp.ber.application.time_ticks",
            )?),
            rest,
        ))
    }

    pub(super) fn decode_opaque(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (content, rest) = decode_known_application_content(
            bytes,
            ber::SNMP_APPLICATION_TAG_OPAQUE,
            "snmp.ber.application.opaque",
            "expected application primitive Opaque",
        )?;

        Ok((Self::opaque(content.to_vec()), rest))
    }

    pub(super) fn decode_counter64(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (content, rest) = decode_known_application_content(
            bytes,
            ber::SNMP_APPLICATION_TAG_COUNTER64,
            "snmp.ber.application.counter64",
            "expected application primitive Counter64",
        )?;

        Ok((
            Self::Counter64(decode_unsigned_u64_content(
                content,
                "snmp.ber.application.counter64",
            )?),
            rest,
        ))
    }

    pub(super) fn as_octets(&self) -> Option<&[u8]> {
        match self {
            Self::OctetString(value) => Some(value.as_bytes()),
            _ => None,
        }
    }

    pub(super) fn as_ip_address(&self) -> Option<[u8; SNMP_IP_ADDRESS_LEN]> {
        match self {
            Self::IpAddress(octets) => Some(*octets),
            _ => None,
        }
    }

    pub(super) fn as_counter32(&self) -> Option<u32> {
        match self {
            Self::Counter32(value) => Some(*value),
            _ => None,
        }
    }

    pub(super) fn as_gauge32_or_unsigned32(&self) -> Option<u32> {
        match self {
            Self::Gauge32OrUnsigned32(value) => Some(*value),
            _ => None,
        }
    }

    pub(super) fn as_time_ticks(&self) -> Option<u32> {
        match self {
            Self::TimeTicks(value) => Some(*value),
            _ => None,
        }
    }

    pub(super) fn as_opaque(&self) -> Option<&[u8]> {
        match self {
            Self::Opaque(value) => Some(value.as_bytes()),
            _ => None,
        }
    }

    pub(super) fn as_counter64(&self) -> Option<u64> {
        match self {
            Self::Counter64(value) => Some(*value),
            _ => None,
        }
    }

    pub(super) fn as_raw_application(&self) -> Option<&RawApplicationValue> {
        match self {
            Self::RawApplication(value) => Some(value),
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
            Self::IpAddress(octets) => {
                encode_application_tlv(ber::SNMP_APPLICATION_TAG_IP_ADDRESS, false, octets, out)
            }
            Self::Counter32(value) => {
                encode_unsigned_application_tlv(ber::SNMP_APPLICATION_TAG_COUNTER32, *value, out)
            }
            Self::Gauge32OrUnsigned32(value) => encode_unsigned_application_tlv(
                ber::SNMP_APPLICATION_TAG_GAUGE32_OR_UNSIGNED32,
                *value,
                out,
            ),
            Self::TimeTicks(value) => {
                encode_unsigned_application_tlv(ber::SNMP_APPLICATION_TAG_TIME_TICKS, *value, out)
            }
            Self::Opaque(value) => encode_application_tlv(
                ber::SNMP_APPLICATION_TAG_OPAQUE,
                false,
                value.as_bytes(),
                out,
            ),
            Self::Counter64(value) => encode_unsigned_application_tlv_u64(
                ber::SNMP_APPLICATION_TAG_COUNTER64,
                *value,
                out,
            ),
            Self::RawApplication(raw) => raw.encode(out),
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
pub(super) struct RawApplicationValue {
    tag_number: u8,
    constructed: bool,
    content: Vec<u8>,
}

impl RawApplicationValue {
    pub(super) fn new(tag_number: u8, constructed: bool, content: impl Into<Vec<u8>>) -> Self {
        Self {
            tag_number,
            constructed,
            content: content.into(),
        }
    }

    pub(super) const fn tag_number(&self) -> u8 {
        self.tag_number
    }

    pub(super) const fn is_constructed(&self) -> bool {
        self.constructed
    }

    pub(super) fn content(&self) -> &[u8] {
        &self.content
    }

    pub(super) fn label(&self) -> String {
        registry::application_tag_label(self.tag_number, self.constructed)
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_application_tlv(self.tag_number, self.constructed, &self.content, out)
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

fn encode_application_tlv(
    tag_number: u8,
    constructed: bool,
    content: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    if tag_number > ber::BER_LOW_TAG_NUMBER_MAX {
        return Err(ber::invalid_ber_field(
            "snmp.ber.application",
            "high-tag-number form is not supported for SNMP",
        ));
    }

    encode_tlv(
        ber::BerTag::new(ber::BerClass::Application, constructed, tag_number),
        content,
        out,
    )
}

fn encode_unsigned_application_tlv(tag_number: u8, value: u32, out: &mut Vec<u8>) -> Result<()> {
    encode_unsigned_application_tlv_u64(tag_number, u64::from(value), out)
}

fn encode_unsigned_application_tlv_u64(
    tag_number: u8,
    value: u64,
    out: &mut Vec<u8>,
) -> Result<()> {
    let mut content = Vec::new();
    encode_unsigned_integer_content(value, &mut content);
    encode_application_tlv(tag_number, false, &content, out)
}

fn encode_unsigned_integer_content(value: u64, out: &mut Vec<u8>) {
    let bytes = value.to_be_bytes();
    let first_non_zero = bytes
        .iter()
        .position(|octet| *octet != 0)
        .unwrap_or(bytes.len() - 1);
    let content = &bytes[first_non_zero..];

    if content[0] & 0x80 != 0 {
        out.push(0x00);
    }
    out.extend_from_slice(content);
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

fn decode_application_content<'a>(
    bytes: &'a [u8],
    context: &'static str,
) -> Result<(ber::BerTag, &'a [u8], &'a [u8])> {
    let (tag, rest) = ber::decode_identifier(bytes)?;
    if tag.class() != ber::BerClass::Application {
        return Err(ber::invalid_ber_field(
            context,
            "expected application-class value",
        ));
    }

    let (length, rest) = ber::decode_length(rest)?;
    if rest.len() < length {
        let prefix_len = bytes.len() - rest.len();
        let required = prefix_len.checked_add(length).ok_or_else(|| {
            ber::invalid_ber_field(context, "application length exceeds supported size")
        })?;
        return Err(ber::truncated_ber(context, required, bytes.len()));
    }

    let (content, rest) = rest.split_at(length);
    Ok((tag, content, rest))
}

fn decode_known_application_content<'a>(
    bytes: &'a [u8],
    expected_tag_number: u8,
    context: &'static str,
    tag_reason: &'static str,
) -> Result<(&'a [u8], &'a [u8])> {
    let (tag, content, rest) = decode_application_content(bytes, context)?;
    if tag != ber::BerTag::new(ber::BerClass::Application, false, expected_tag_number) {
        return Err(ber::invalid_ber_field(context, tag_reason));
    }

    Ok((content, rest))
}

fn decode_ip_address_content(content: &[u8]) -> Result<[u8; SNMP_IP_ADDRESS_LEN]> {
    if content.len() != SNMP_IP_ADDRESS_LEN {
        return Err(ber::invalid_ber_field(
            "snmp.ber.application.ip_address",
            "IpAddress content must be exactly 4 octets",
        ));
    }

    Ok([content[0], content[1], content[2], content[3]])
}

fn decode_unsigned_u32_content(content: &[u8], context: &'static str) -> Result<u32> {
    let value = decode_unsigned_integer_content(
        content,
        SNMP_APPLICATION_U32_MAX_CONTENT_LEN,
        u64::from(u32::MAX),
        context,
    )?;

    Ok(value as u32)
}

fn decode_unsigned_u64_content(content: &[u8], context: &'static str) -> Result<u64> {
    decode_unsigned_integer_content(
        content,
        SNMP_APPLICATION_U64_MAX_CONTENT_LEN,
        u64::MAX,
        context,
    )
}

fn decode_unsigned_integer_content(
    content: &[u8],
    max_content_len: usize,
    max_value: u64,
    context: &'static str,
) -> Result<u64> {
    if content.is_empty() {
        return Err(ber::invalid_ber_field(
            context,
            "application integer requires at least one content octet",
        ));
    }
    if content.len() > max_content_len {
        return Err(ber::invalid_ber_field(
            context,
            "application integer exceeds source-backed wire width",
        ));
    }
    if content[0] & 0x80 != 0 {
        return Err(ber::invalid_ber_field(
            context,
            "application integer must be non-negative",
        ));
    }

    let mut value = 0u64;
    for octet in content {
        value = value
            .checked_mul(256)
            .and_then(|value| value.checked_add(u64::from(*octet)))
            .ok_or_else(|| {
                ber::invalid_ber_field(context, "application integer exceeds supported size")
            })?;
    }
    if value > max_value {
        return Err(ber::invalid_ber_field(
            context,
            "application integer exceeds source-backed value range",
        ));
    }

    Ok(value)
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

    #[test]
    fn snmp_application_values_ip_address_roundtrips() {
        let value = SnmpValue::ip_address([192, 0, 2, 1]);
        let mut bytes = value.to_bytes().expect("encode IpAddress");
        bytes.push(0xaa);

        assert_eq!(bytes, [0x40, 0x04, 192, 0, 2, 1, 0xaa]);

        let (decoded, rest) = SnmpValue::decode_application(&bytes).expect("decode IpAddress");
        assert_eq!(decoded.as_ip_address(), Some([192, 0, 2, 1]));
        assert_eq!(rest, &[0xaa]);

        let (decoded, rest) = SnmpValue::decode_ip_address(&bytes).expect("decode typed IpAddress");
        assert_eq!(decoded, value);
        assert_eq!(rest, &[0xaa]);
    }

    #[test]
    fn snmp_application_values_counter32_roundtrips() {
        let value = SnmpValue::counter32(u32::MAX);
        let mut bytes = value.to_bytes().expect("encode Counter32");
        bytes.push(0xaa);

        assert_eq!(bytes, [0x41, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, 0xaa]);

        let (decoded, rest) = SnmpValue::decode_application(&bytes).expect("decode Counter32");
        assert_eq!(decoded.as_counter32(), Some(u32::MAX));
        assert_eq!(rest, &[0xaa]);

        let (decoded, rest) = SnmpValue::decode_counter32(&[0x41, 0x02, 0x00, 0x7f, 0xbb])
            .expect("decode typed Counter32");
        assert_eq!(decoded.as_counter32(), Some(127));
        assert_eq!(rest, &[0xbb]);
    }

    #[test]
    fn snmp_application_values_gauge32_unsigned32_roundtrips() {
        let gauge = SnmpValue::gauge32(128);
        let unsigned = SnmpValue::unsigned32(128);

        assert_eq!(gauge, unsigned);
        assert_eq!(
            gauge.to_bytes().expect("encode Gauge32"),
            [0x42, 0x02, 0x00, 0x80]
        );

        let (decoded, rest) = SnmpValue::decode_gauge32_or_unsigned32(&[0x42, 0x01, 0x7f, 0xaa])
            .expect("decode Gauge32/Unsigned32");

        assert_eq!(decoded.as_gauge32_or_unsigned32(), Some(127));
        assert_eq!(rest, &[0xaa]);
    }

    #[test]
    fn snmp_application_values_time_ticks_roundtrips() {
        let value = SnmpValue::time_ticks(12_345);

        assert_eq!(
            value.to_bytes().expect("encode TimeTicks"),
            [0x43, 0x02, 0x30, 0x39]
        );

        let (decoded, rest) = SnmpValue::decode_time_ticks(&[0x43, 0x02, 0x30, 0x39, 0xaa])
            .expect("decode TimeTicks");
        assert_eq!(decoded.as_time_ticks(), Some(12_345));
        assert_eq!(rest, &[0xaa]);
    }

    #[test]
    fn snmp_application_values_opaque_roundtrips() {
        let value = SnmpValue::opaque([0x30, 0x03, 0x02, 0x01, 0x05]);
        let mut bytes = value.to_bytes().expect("encode Opaque");
        bytes.push(0xaa);

        assert_eq!(bytes, [0x44, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05, 0xaa]);

        let (decoded, rest) = SnmpValue::decode_opaque(&bytes).expect("decode Opaque");
        assert_eq!(
            decoded.as_opaque(),
            Some(&[0x30, 0x03, 0x02, 0x01, 0x05][..])
        );
        assert_eq!(rest, &[0xaa]);
    }

    #[test]
    fn snmp_application_values_counter64_roundtrips() {
        let value = SnmpValue::counter64(u64::MAX);
        let bytes = value.to_bytes().expect("encode Counter64");

        assert_eq!(
            bytes,
            [0x46, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );

        let (decoded, rest) = SnmpValue::decode_counter64(&bytes).expect("decode Counter64");
        assert_eq!(decoded.as_counter64(), Some(u64::MAX));
        assert!(rest.is_empty());
    }

    #[test]
    fn snmp_application_values_unknown_application_tags_preserve_tag_constructed_and_content() {
        let primitive = SnmpValue::decode_application(&[0x45, 0x03, 0xde, 0xad, 0xbe, 0xaa])
            .expect("decode unknown primitive application tag")
            .0;
        let raw = primitive
            .as_raw_application()
            .expect("unknown primitive application value");

        assert_eq!(raw.tag_number(), 5);
        assert!(!raw.is_constructed());
        assert_eq!(raw.content(), &[0xde, 0xad, 0xbe]);
        assert_eq!(raw.label(), "application-5");
        assert_eq!(
            primitive
                .to_bytes()
                .expect("encode unknown primitive application tag"),
            [0x45, 0x03, 0xde, 0xad, 0xbe]
        );

        let constructed = SnmpValue::decode_application(&[0x65, 0x02, 0x05, 0x00, 0xaa])
            .expect("decode unknown constructed application tag")
            .0;
        let raw = constructed
            .as_raw_application()
            .expect("unknown constructed application value");

        assert_eq!(raw.tag_number(), 5);
        assert!(raw.is_constructed());
        assert_eq!(raw.content(), &[0x05, 0x00]);
        assert_eq!(raw.label(), "constructed-application-5");
        assert_eq!(
            constructed
                .to_bytes()
                .expect("encode unknown constructed application tag"),
            [0x65, 0x02, 0x05, 0x00]
        );
    }

    #[test]
    fn snmp_application_values_wrong_tags_return_structured_errors() {
        assert_eq!(
            SnmpValue::decode_application(&[0x04, 0x00]),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.application",
                "expected application-class value"
            ))
        );
        assert_eq!(
            SnmpValue::decode_ip_address(&[0x41, 0x01, 0x00]),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.application.ip_address",
                "expected application primitive IpAddress"
            ))
        );
        assert_eq!(
            SnmpValue::decode_counter32(&[0x61, 0x01, 0x00]),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.application.counter32",
                "expected application primitive Counter32"
            ))
        );
    }

    #[test]
    fn snmp_application_values_truncation_and_length_errors_are_structured() {
        assert_eq!(
            SnmpValue::decode_application(&[0x40, 0x04, 192, 0, 2]),
            Err(CrafterError::buffer_too_short("snmp.ber.application", 6, 5))
        );
        assert_eq!(
            SnmpValue::decode_ip_address(&[0x40, 0x03, 192, 0, 2]),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.application.ip_address",
                "IpAddress content must be exactly 4 octets"
            ))
        );
        assert_eq!(
            SnmpValue::decode_counter32(&[0x41, 0x00]),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.application.counter32",
                "application integer requires at least one content octet"
            ))
        );
        assert_eq!(
            SnmpValue::decode_counter32(&[0x41, 0x06, 0, 0, 0, 0, 0, 1]),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.application.counter32",
                "application integer exceeds source-backed wire width"
            ))
        );
        assert_eq!(
            SnmpValue::decode_counter32(&[0x41, 0x05, 0x01, 0, 0, 0, 0]),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.application.counter32",
                "application integer exceeds source-backed value range"
            ))
        );
        assert_eq!(
            SnmpValue::decode_counter64(&[0x46, 0x01, 0x80]),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.application.counter64",
                "application integer must be non-negative"
            ))
        );
    }
}
