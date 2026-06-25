//! SNMP value scaffold.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`; value types and BER-backed
//! preservation behavior are added in later slices.

#![cfg_attr(not(test), allow(dead_code))]

use super::{ber, oid::SnmpOid, registry};
use crate::error::Result;

const SNMP_IP_ADDRESS_LEN: usize = 4;
const SNMP_APPLICATION_U32_MAX_CONTENT_LEN: usize = 5;
const SNMP_APPLICATION_U64_MAX_CONTENT_LEN: usize = 9;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SnmpValue {
    Integer(i64),
    OctetString(SnmpOctetString),
    Null,
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
    ObjectIdentifier(SnmpOid),
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

    pub(super) const fn no_such_object() -> Self {
        Self::NoSuchObject
    }

    pub(super) const fn no_such_instance() -> Self {
        Self::NoSuchInstance
    }

    pub(super) const fn end_of_mib_view() -> Self {
        Self::EndOfMibView
    }

    pub(super) fn object_identifier(oid: SnmpOid) -> Self {
        Self::ObjectIdentifier(oid)
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

    pub(super) fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (tag, content, tlv, rest) =
            decode_tlv(bytes, "snmp.value", "value length exceeds supported size")?;

        let value = match tag {
            tag if tag
                == ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_INTEGER) =>
            {
                Self::Integer(ber::decode_integer_content(content)?)
            }
            tag if tag
                == ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_OCTET_STRING) =>
            {
                Self::octet_string(content.to_vec())
            }
            tag if tag == ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_NULL) => {
                if !content.is_empty() {
                    return Err(ber::invalid_ber_field(
                        "snmp.ber.null",
                        "NULL must have zero content length",
                    ));
                }
                Self::Null
            }
            tag if tag
                == ber::BerTag::new(
                    ber::BerClass::ContextSpecific,
                    false,
                    ber::SNMP_CONTEXT_TAG_NO_SUCH_OBJECT,
                ) =>
            {
                decode_exception_content(content)?;
                Self::NoSuchObject
            }
            tag if tag
                == ber::BerTag::new(
                    ber::BerClass::ContextSpecific,
                    false,
                    ber::SNMP_CONTEXT_TAG_NO_SUCH_INSTANCE,
                ) =>
            {
                decode_exception_content(content)?;
                Self::NoSuchInstance
            }
            tag if tag
                == ber::BerTag::new(
                    ber::BerClass::ContextSpecific,
                    false,
                    ber::SNMP_CONTEXT_TAG_END_OF_MIB_VIEW,
                ) =>
            {
                decode_exception_content(content)?;
                Self::EndOfMibView
            }
            tag if tag
                == ber::BerTag::new(
                    ber::BerClass::Universal,
                    false,
                    ber::BER_TAG_OBJECT_IDENTIFIER,
                ) =>
            {
                Self::ObjectIdentifier(SnmpOid::decode_content(content)?)
            }
            tag if tag.class() == ber::BerClass::Application => {
                decode_application_value(tag, content, Some(tlv))?
            }
            _ => Self::raw_tlv(tlv.to_vec()),
        };

        Ok((value, rest))
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

    pub(super) fn decode_object_identifier(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (oid, rest) = SnmpOid::decode(bytes)?;
        Ok((Self::ObjectIdentifier(oid), rest))
    }

    pub(super) fn decode_application(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (tag, content, tlv, rest) = decode_application_tlv(bytes, "snmp.ber.application")?;
        let value = decode_application_value(tag, content, Some(tlv))?;

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

    pub(super) fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    pub(super) fn as_octets(&self) -> Option<&[u8]> {
        match self {
            Self::OctetString(value) => Some(value.as_bytes()),
            _ => None,
        }
    }

    pub(super) fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub(super) fn is_no_such_object(&self) -> bool {
        matches!(self, Self::NoSuchObject)
    }

    pub(super) fn is_no_such_instance(&self) -> bool {
        matches!(self, Self::NoSuchInstance)
    }

    pub(super) fn is_end_of_mib_view(&self) -> bool {
        matches!(self, Self::EndOfMibView)
    }

    pub(super) fn as_object_identifier(&self) -> Option<&SnmpOid> {
        match self {
            Self::ObjectIdentifier(value) => Some(value),
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

    pub(super) fn as_raw_tlv(&self) -> Option<&RawTlv> {
        match self {
            Self::RawTlv(value) => Some(value),
            _ => None,
        }
    }

    pub(super) fn unknown_value_class(&self) -> Option<&'static str> {
        match self {
            Self::RawApplication(_) => Some(ber::BerClass::Application.label()),
            Self::RawTlv(raw) => raw.class_label(),
            _ => None,
        }
    }

    pub(super) fn unknown_value_is_constructed(&self) -> Option<bool> {
        match self {
            Self::RawApplication(raw) => Some(raw.is_constructed()),
            Self::RawTlv(raw) => raw.is_constructed(),
            _ => None,
        }
    }

    pub(super) fn unknown_value_tag_number(&self) -> Option<u8> {
        match self {
            Self::RawApplication(raw) => Some(raw.tag_number()),
            Self::RawTlv(raw) => raw.tag_number(),
            _ => None,
        }
    }

    pub(super) fn unknown_value_content(&self) -> Option<&[u8]> {
        match self {
            Self::RawApplication(raw) => Some(raw.content()),
            Self::RawTlv(raw) => raw.content(),
            _ => None,
        }
    }

    pub(super) fn unknown_value_tlv_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::RawApplication(raw) => raw.tlv_bytes(),
            Self::RawTlv(raw) => Some(raw.as_bytes()),
            _ => None,
        }
    }

    pub(super) fn summary_label(&self) -> String {
        match self {
            Self::Integer(_) => "integer".to_string(),
            Self::OctetString(_) => "octet-string".to_string(),
            Self::Null => "null".to_string(),
            Self::NoSuchObject => "no-such-object".to_string(),
            Self::NoSuchInstance => "no-such-instance".to_string(),
            Self::EndOfMibView => "end-of-mib-view".to_string(),
            Self::ObjectIdentifier(_) => "object-identifier".to_string(),
            Self::IpAddress(_) => "ip-address".to_string(),
            Self::Counter32(_) => "counter32".to_string(),
            Self::Gauge32OrUnsigned32(_) => "gauge32-or-unsigned32".to_string(),
            Self::TimeTicks(_) => "time-ticks".to_string(),
            Self::Opaque(_) => "opaque".to_string(),
            Self::Counter64(_) => "counter64".to_string(),
            Self::RawApplication(raw) => raw.label(),
            Self::RawTlv(raw) => raw.label(),
        }
    }

    pub(super) fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![("value_type", self.summary_label())];

        match self {
            Self::Integer(value) => fields.push(("value", value.to_string())),
            Self::OctetString(value) => {
                fields.push(("value_len", value.as_bytes().len().to_string()))
            }
            Self::Null | Self::NoSuchObject | Self::NoSuchInstance | Self::EndOfMibView => {}
            Self::ObjectIdentifier(value) => {
                fields.push(("value", value.to_string()));
                fields.push(("value_arc_count", value.arcs().len().to_string()));
            }
            Self::IpAddress(octets) => fields.push((
                "value",
                format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]),
            )),
            Self::Counter32(value) | Self::Gauge32OrUnsigned32(value) | Self::TimeTicks(value) => {
                fields.push(("value", value.to_string()))
            }
            Self::Opaque(value) => fields.push(("value_len", value.as_bytes().len().to_string())),
            Self::Counter64(value) => fields.push(("value", value.to_string())),
            Self::RawApplication(raw) => {
                push_unknown_inspection_fields(
                    &mut fields,
                    ber::BerTag::new(
                        ber::BerClass::Application,
                        raw.is_constructed(),
                        raw.tag_number(),
                    ),
                    Some(raw.content().len()),
                    Some(raw.tlv_len()),
                );
            }
            Self::RawTlv(raw) => {
                if let Some(tag) = raw.tag() {
                    push_unknown_inspection_fields(
                        &mut fields,
                        tag,
                        raw.content().map(<[u8]>::len),
                        Some(raw.as_bytes().len()),
                    );
                } else {
                    fields.push(("value_tlv_len", raw.as_bytes().len().to_string()));
                }
            }
        }

        fields
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
            Self::NoSuchObject => encode_exception_tlv(ber::SNMP_CONTEXT_TAG_NO_SUCH_OBJECT, out),
            Self::NoSuchInstance => {
                encode_exception_tlv(ber::SNMP_CONTEXT_TAG_NO_SUCH_INSTANCE, out)
            }
            Self::EndOfMibView => encode_exception_tlv(ber::SNMP_CONTEXT_TAG_END_OF_MIB_VIEW, out),
            Self::ObjectIdentifier(value) => value.encode(out),
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

    pub(super) fn compile(&self) -> Result<Vec<u8>> {
        self.to_bytes()
    }
}

#[derive(Debug, Clone)]
pub(super) struct RawApplicationValue {
    tag_number: u8,
    constructed: bool,
    content: Vec<u8>,
    raw_tlv: Option<RawTlv>,
}

impl PartialEq for RawApplicationValue {
    fn eq(&self, other: &Self) -> bool {
        self.tag_number == other.tag_number
            && self.constructed == other.constructed
            && self.content == other.content
    }
}

impl Eq for RawApplicationValue {}

impl RawApplicationValue {
    pub(super) fn new(tag_number: u8, constructed: bool, content: impl Into<Vec<u8>>) -> Self {
        Self {
            tag_number,
            constructed,
            content: content.into(),
            raw_tlv: None,
        }
    }

    fn from_tlv(
        tag_number: u8,
        constructed: bool,
        content: impl Into<Vec<u8>>,
        tlv: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            tag_number,
            constructed,
            content: content.into(),
            raw_tlv: Some(RawTlv::new(tlv)),
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

    pub(super) fn tlv_bytes(&self) -> Option<&[u8]> {
        self.raw_tlv.as_ref().map(RawTlv::as_bytes)
    }

    fn tlv_len(&self) -> usize {
        self.tlv_bytes()
            .map(<[u8]>::len)
            .unwrap_or_else(|| encoded_tlv_len(self.content.len()))
    }

    pub(super) fn label(&self) -> String {
        registry::application_tag_label(self.tag_number, self.constructed)
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        if let Some(raw_tlv) = &self.raw_tlv {
            out.extend_from_slice(raw_tlv.as_bytes());
            return Ok(());
        }

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

    pub(super) fn tag(&self) -> Option<ber::BerTag> {
        ber::decode_identifier(&self.bytes).ok().map(|(tag, _)| tag)
    }

    pub(super) fn class_label(&self) -> Option<&'static str> {
        self.tag().map(|tag| tag.class().label())
    }

    pub(super) fn is_constructed(&self) -> Option<bool> {
        self.tag().map(|tag| tag.is_constructed())
    }

    pub(super) fn tag_number(&self) -> Option<u8> {
        self.tag().map(|tag| tag.number())
    }

    pub(super) fn content(&self) -> Option<&[u8]> {
        let (_, rest) = ber::decode_identifier(&self.bytes).ok()?;
        let (length, rest) = ber::decode_length(rest).ok()?;
        if rest.len() < length {
            return None;
        }

        Some(&rest[..length])
    }

    pub(super) fn label(&self) -> String {
        self.tag()
            .map(ber::BerTag::label)
            .unwrap_or_else(|| "raw-tlv".to_string())
    }
}

fn decode_application_value(
    tag: ber::BerTag,
    content: &[u8],
    raw_tlv: Option<&[u8]>,
) -> Result<SnmpValue> {
    Ok(match (tag.is_constructed(), tag.number()) {
        (false, ber::SNMP_APPLICATION_TAG_IP_ADDRESS) => {
            SnmpValue::IpAddress(decode_ip_address_content(content)?)
        }
        (false, ber::SNMP_APPLICATION_TAG_COUNTER32) => SnmpValue::Counter32(
            decode_unsigned_u32_content(content, "snmp.ber.application.counter32")?,
        ),
        (false, ber::SNMP_APPLICATION_TAG_GAUGE32_OR_UNSIGNED32) => SnmpValue::Gauge32OrUnsigned32(
            decode_unsigned_u32_content(content, "snmp.ber.application.gauge32_or_unsigned32")?,
        ),
        (false, ber::SNMP_APPLICATION_TAG_TIME_TICKS) => SnmpValue::TimeTicks(
            decode_unsigned_u32_content(content, "snmp.ber.application.time_ticks")?,
        ),
        (false, ber::SNMP_APPLICATION_TAG_OPAQUE) => {
            SnmpValue::Opaque(SnmpOctetString::new(content.to_vec()))
        }
        (false, ber::SNMP_APPLICATION_TAG_COUNTER64) => SnmpValue::Counter64(
            decode_unsigned_u64_content(content, "snmp.ber.application.counter64")?,
        ),
        _ => {
            if let Some(raw_tlv) = raw_tlv {
                SnmpValue::RawApplication(RawApplicationValue::from_tlv(
                    tag.number(),
                    tag.is_constructed(),
                    content.to_vec(),
                    raw_tlv.to_vec(),
                ))
            } else {
                SnmpValue::raw_application(tag.number(), tag.is_constructed(), content.to_vec())
            }
        }
    })
}

fn encode_tlv(tag: ber::BerTag, content: &[u8], out: &mut Vec<u8>) -> Result<()> {
    ber::encode_identifier(tag, out)?;
    ber::encode_length(content.len(), out)?;
    out.extend_from_slice(content);
    Ok(())
}

fn encoded_tlv_len(content_len: usize) -> usize {
    ber::BER_IDENTIFIER_LEN + encoded_length_len(content_len) + content_len
}

fn encoded_length_len(length: usize) -> usize {
    if length <= ber::BER_LENGTH_SHORT_FORM_MAX {
        return ber::BER_LENGTH_FIELD_MIN_LEN;
    }

    let mut value = length;
    let mut octets = 0usize;
    while value != 0 {
        octets += 1;
        value >>= 8;
    }

    ber::BER_LENGTH_FIELD_MIN_LEN + octets
}

fn push_unknown_inspection_fields(
    fields: &mut Vec<(&'static str, String)>,
    tag: ber::BerTag,
    content_len: Option<usize>,
    tlv_len: Option<usize>,
) {
    fields.push(("value_ber_class", tag.class().label().to_string()));
    fields.push((
        "value_ber_class_bits",
        format!("0x{:02x}", tag.class().bits()),
    ));
    fields.push(("value_ber_constructed", tag.is_constructed().to_string()));
    fields.push(("value_ber_tag_number", tag.number().to_string()));
    fields.push((
        "value_ber_identifier",
        format!("0x{:02x}", tag.identifier_octet()),
    ));
    if let Some(content_len) = content_len {
        fields.push(("value_content_len", content_len.to_string()));
    }
    if let Some(tlv_len) = tlv_len {
        fields.push(("value_tlv_len", tlv_len.to_string()));
    }
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

fn encode_exception_tlv(tag_number: u8, out: &mut Vec<u8>) -> Result<()> {
    encode_tlv(
        ber::BerTag::new(ber::BerClass::ContextSpecific, false, tag_number),
        &[],
        out,
    )
}

fn decode_exception_content(content: &[u8]) -> Result<()> {
    if !content.is_empty() {
        return Err(ber::invalid_ber_field(
            "snmp.ber.exception",
            "exception value must have zero content length",
        ));
    }

    Ok(())
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

fn decode_tlv<'a>(
    bytes: &'a [u8],
    context: &'static str,
    overflow_reason: &'static str,
) -> Result<(ber::BerTag, &'a [u8], &'a [u8], &'a [u8])> {
    let (tag, rest) = ber::decode_identifier(bytes)?;
    let (length, rest) = ber::decode_length(rest)?;
    if rest.len() < length {
        let prefix_len = bytes.len() - rest.len();
        let required = prefix_len
            .checked_add(length)
            .ok_or_else(|| ber::invalid_ber_field(context, overflow_reason))?;
        return Err(ber::truncated_ber(context, required, bytes.len()));
    }

    let content_offset = bytes.len() - rest.len();
    let value_end = content_offset + length;
    let content = &bytes[content_offset..value_end];
    let tlv = &bytes[..value_end];
    let rest = &bytes[value_end..];
    Ok((tag, content, tlv, rest))
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
    let (tag, content, _, rest) = decode_application_tlv(bytes, context)?;
    Ok((tag, content, rest))
}

fn decode_application_tlv<'a>(
    bytes: &'a [u8],
    context: &'static str,
) -> Result<(ber::BerTag, &'a [u8], &'a [u8], &'a [u8])> {
    let (tag, content, tlv, rest) =
        decode_tlv(bytes, context, "application length exceeds supported size")?;
    if tag.class() != ber::BerClass::Application {
        return Err(ber::invalid_ber_field(
            context,
            "expected application-class value",
        ));
    }

    Ok((tag, content, tlv, rest))
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
    fn snmp_value_compile_decode_universal_and_application_values() -> Result<()> {
        let oid = SnmpOid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0])?;
        let cases = vec![
            (SnmpValue::integer(128), vec![0x02, 0x02, 0x00, 0x80]),
            (
                SnmpValue::octet_string([0x00, 0xff, b'a']),
                vec![0x04, 0x03, 0x00, 0xff, b'a'],
            ),
            (SnmpValue::null(), vec![0x05, 0x00]),
            (
                SnmpValue::object_identifier(oid.clone()),
                vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00],
            ),
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
        ];

        // Source-backed: docs/snmp-rfc-manifest.md, RFC 2578 Sections 7.1.1
        // through 7.1.11 and RFC 3416 Section 3 record these value choices.
        for (value, expected) in cases {
            assert_eq!(value.compile()?, expected);

            let mut with_rest = expected.clone();
            with_rest.push(0xaa);
            let (decoded, rest) = SnmpValue::decode(&with_rest)?;
            assert_eq!(decoded.compile()?, expected);
            assert_eq!(rest, &[0xaa]);
        }

        let mut oid_bytes = vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00];
        oid_bytes.push(0xbb);
        let (decoded, rest) = SnmpValue::decode_object_identifier(&oid_bytes)?;
        assert_eq!(
            decoded.as_object_identifier().map(SnmpOid::as_slice),
            Some(oid.as_slice())
        );
        assert_eq!(rest, &[0xbb]);

        Ok(())
    }

    #[test]
    fn snmp_value_summary_labels_cover_all_variants() -> Result<()> {
        let oid = SnmpOid::from_slice(&[1, 3, 6, 1])?;
        let cases = vec![
            (SnmpValue::integer(1), "integer"),
            (SnmpValue::octet_string([0xaa]), "octet-string"),
            (SnmpValue::null(), "null"),
            (SnmpValue::no_such_object(), "no-such-object"),
            (SnmpValue::no_such_instance(), "no-such-instance"),
            (SnmpValue::end_of_mib_view(), "end-of-mib-view"),
            (SnmpValue::object_identifier(oid), "object-identifier"),
            (SnmpValue::ip_address([192, 0, 2, 1]), "ip-address"),
            (SnmpValue::counter32(1), "counter32"),
            (SnmpValue::gauge32(1), "gauge32-or-unsigned32"),
            (SnmpValue::time_ticks(1), "time-ticks"),
            (SnmpValue::opaque([0xaa]), "opaque"),
            (SnmpValue::counter64(1), "counter64"),
            (
                SnmpValue::raw_application(5, true, [0x05, 0x00]),
                "constructed-application-5",
            ),
            (SnmpValue::raw_tlv([0xc3, 0x01, 0xaa]), "private-3"),
        ];

        for (value, label) in cases {
            assert_eq!(value.summary_label(), label);
        }

        Ok(())
    }

    #[test]
    fn snmp_value_summary_show_fields_expose_supported_and_unknown_metadata() -> Result<()> {
        let time_ticks = SnmpValue::time_ticks(12_345);
        assert_eq!(time_ticks.summary_label(), "time-ticks");
        assert_eq!(
            time_ticks.inspection_fields(),
            [
                ("value_type", "time-ticks".to_string()),
                ("value", "12345".to_string()),
            ]
        );

        let oid = SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?;
        let oid_value = SnmpValue::object_identifier(oid);
        assert_eq!(oid_value.summary_label(), "object-identifier");
        assert_eq!(
            oid_value.inspection_fields(),
            [
                ("value_type", "object-identifier".to_string()),
                ("value", "1.3.6.1.2.1.1.3.0".to_string()),
                ("value_arc_count", "9".to_string()),
            ]
        );

        let (unknown, rest) = SnmpValue::decode(&[0x45, 0x81, 0x02, 0xde, 0xad, 0xbb])?;
        assert_eq!(rest, &[0xbb]);
        assert_eq!(unknown.summary_label(), "application-5");
        assert_eq!(
            unknown.inspection_fields(),
            [
                ("value_type", "application-5".to_string()),
                ("value_ber_class", "application".to_string()),
                ("value_ber_class_bits", "0x40".to_string()),
                ("value_ber_constructed", "false".to_string()),
                ("value_ber_tag_number", "5".to_string()),
                ("value_ber_identifier", "0x45".to_string()),
                ("value_content_len", "2".to_string()),
                ("value_tlv_len", "5".to_string()),
            ]
        );

        Ok(())
    }

    #[test]
    fn snmp_value_typed_inspection_helpers_cover_all_variants() -> Result<()> {
        let oid = SnmpOid::from_slice(&[1, 3, 6, 1])?;

        assert_eq!(SnmpValue::integer(-1).as_integer(), Some(-1));
        assert_eq!(
            SnmpValue::octet_string([0xde, 0xad]).as_octets(),
            Some(&[0xde, 0xad][..])
        );
        assert!(SnmpValue::null().is_null());
        assert!(SnmpValue::no_such_object().is_no_such_object());
        assert!(SnmpValue::no_such_instance().is_no_such_instance());
        assert!(SnmpValue::end_of_mib_view().is_end_of_mib_view());
        assert_eq!(
            SnmpValue::object_identifier(oid.clone())
                .as_object_identifier()
                .map(SnmpOid::as_slice),
            Some(oid.as_slice())
        );
        assert_eq!(
            SnmpValue::ip_address([192, 0, 2, 1]).as_ip_address(),
            Some([192, 0, 2, 1])
        );
        assert_eq!(SnmpValue::counter32(7).as_counter32(), Some(7));
        assert_eq!(SnmpValue::unsigned32(8).as_gauge32_or_unsigned32(), Some(8));
        assert_eq!(SnmpValue::time_ticks(9).as_time_ticks(), Some(9));
        assert_eq!(SnmpValue::opaque([0xaa]).as_opaque(), Some(&[0xaa][..]));
        assert_eq!(SnmpValue::counter64(10).as_counter64(), Some(10));

        let raw_application = SnmpValue::raw_application(5, false, [0xde, 0xad]);
        let raw_application = raw_application
            .as_raw_application()
            .expect("raw application value");
        assert_eq!(raw_application.tag_number(), 5);
        assert!(!raw_application.is_constructed());
        assert_eq!(raw_application.content(), &[0xde, 0xad]);

        let raw_tlv = SnmpValue::raw_tlv([0xc3, 0x01, 0xaa]);
        let raw_tlv = raw_tlv.as_raw_tlv().expect("raw TLV value");
        assert_eq!(
            raw_tlv.tag(),
            Some(ber::BerTag::new(ber::BerClass::Private, false, 3))
        );
        assert_eq!(raw_tlv.content(), Some(&[0xaa][..]));

        Ok(())
    }

    #[test]
    fn snmp_value_raw_unknown_tlv_preservation_is_byte_exact() -> Result<()> {
        let raw_private = [0xc3, 0x81, 0x02, 0xde, 0xad, 0xaa];
        let (decoded, rest) = SnmpValue::decode(&raw_private)?;
        let raw = decoded.as_raw_tlv().expect("raw private value");

        assert_eq!(raw.as_bytes(), &raw_private[..5]);
        assert_eq!(raw.content(), Some(&[0xde, 0xad][..]));
        assert_eq!(raw.label(), "private-3");
        assert_eq!(decoded.compile()?, raw_private[..5]);
        assert_eq!(rest, &[0xaa]);

        let raw_application = [0x45, 0x81, 0x02, 0xde, 0xad, 0xbb];
        let (decoded, rest) = SnmpValue::decode(&raw_application)?;
        let raw = decoded.as_raw_application().expect("raw application value");

        assert_eq!(raw.tag_number(), 5);
        assert_eq!(raw.content(), &[0xde, 0xad]);
        assert_eq!(raw.tlv_bytes(), Some(&raw_application[..5]));
        assert_eq!(decoded.compile()?, raw_application[..5]);
        assert_eq!(rest, &[0xbb]);

        Ok(())
    }

    #[test]
    fn snmp_unknown_value_metadata_and_compile_are_preserved_for_all_classes() -> Result<()> {
        let cases: &[(&[u8], &str, bool, u8, &[u8])] = &[
            (&[0x01, 0x01, 0xff, 0xaa], "universal", false, 1, &[0xff]),
            (
                &[0x45, 0x81, 0x02, 0xde, 0xad, 0xbb],
                "application",
                false,
                5,
                &[0xde, 0xad],
            ),
            (
                &[0xb4, 0x02, 0x05, 0x00, 0xcc],
                "context-specific",
                true,
                20,
                &[0x05, 0x00],
            ),
            (
                &[0xe3, 0x02, 0x04, 0x00, 0xdd],
                "private",
                true,
                3,
                &[0x04, 0x00],
            ),
        ];

        for (bytes, class, constructed, tag_number, content) in cases {
            let (decoded, rest) = SnmpValue::decode(bytes)?;
            let tlv_len = bytes.len() - rest.len();

            assert_eq!(decoded.unknown_value_class(), Some(*class));
            assert_eq!(decoded.unknown_value_is_constructed(), Some(*constructed));
            assert_eq!(decoded.unknown_value_tag_number(), Some(*tag_number));
            assert_eq!(decoded.unknown_value_content(), Some(*content));
            assert_eq!(decoded.unknown_value_tlv_bytes(), Some(&bytes[..tlv_len]));
            assert_eq!(decoded.compile()?, bytes[..tlv_len]);
            assert_eq!(rest, &bytes[tlv_len..]);
        }

        Ok(())
    }

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
