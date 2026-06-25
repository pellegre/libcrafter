//! SNMP PDU tag metadata, request fields, and raw-body preservation.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`; only GetRequest-style common
//! request fields are modeled here. Other PDU bodies remain raw until their
//! implementation slices land.

use super::{ber, constants, registry, varbind::SnmpVarBindList};
use crate::error::Result;

/// Raw BER content bytes for one SNMP PDU body.
#[derive(Debug, Clone, Default)]
pub struct SnmpRawPduBody {
    bytes: Vec<u8>,
    raw_tlv: Option<Vec<u8>>,
}

impl PartialEq for SnmpRawPduBody {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for SnmpRawPduBody {}

impl SnmpRawPduBody {
    /// Build a raw PDU body from BER content bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            raw_tlv: None,
        }
    }

    fn from_tlv(bytes: impl Into<Vec<u8>>, raw_tlv: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            raw_tlv: Some(raw_tlv.into()),
        }
    }

    /// Raw BER content bytes inside the PDU TLV.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Byte-exact PDU TLV bytes, when this body came from decode.
    pub fn raw_tlv_bytes(&self) -> Option<&[u8]> {
        self.raw_tlv.as_deref()
    }

    /// Length of the raw PDU content in octets.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the raw PDU content is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consume the body and return the raw BER content bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}

/// A context-specific SNMP PDU tag that is not modeled as a source-backed PDU.
#[derive(Debug, Clone)]
pub struct SnmpRawPdu {
    tag_number: u8,
    constructed: bool,
    body: SnmpRawPduBody,
}

impl PartialEq for SnmpRawPdu {
    fn eq(&self, other: &Self) -> bool {
        self.tag_number == other.tag_number
            && self.constructed == other.constructed
            && self.body.as_bytes() == other.body.as_bytes()
    }
}

impl Eq for SnmpRawPdu {}

impl SnmpRawPdu {
    /// Build an unknown context-specific PDU from a tag number and body bytes.
    pub fn new(tag_number: u8, constructed: bool, body: impl Into<Vec<u8>>) -> Self {
        Self {
            tag_number,
            constructed,
            body: SnmpRawPduBody::new(body),
        }
    }

    /// Low-tag-number value from the context-specific BER identifier.
    pub const fn tag_number(&self) -> u8 {
        self.tag_number
    }

    /// Whether the BER identifier used the constructed bit.
    pub const fn is_constructed(&self) -> bool {
        self.constructed
    }

    /// Raw BER content bytes inside the unknown PDU TLV.
    pub fn body(&self) -> &[u8] {
        self.body.as_bytes()
    }

    /// Byte-exact PDU TLV bytes, when this value came from decode.
    pub fn raw_tlv_bytes(&self) -> Option<&[u8]> {
        self.body.raw_tlv_bytes()
    }
}

/// Common GetRequest-style PDU fields.
///
/// RFC-backed request PDUs carry request-id, error-status, error-index, and
/// a VarBindList as the PDU body content. This type models those fields as
/// packet bytes only; it does not add manager/session behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpRequestPdu {
    request_id: i64,
    error_status: i64,
    error_index: i64,
    varbinds: SnmpVarBindList,
}

impl SnmpRequestPdu {
    /// Build request fields with noError/noErrorIndex convention values.
    pub fn new(request_id: i64, varbinds: SnmpVarBindList) -> Self {
        Self::with_fields(request_id, 0, 0, varbinds)
    }

    /// Build request fields with caller-supplied integer values.
    pub fn with_fields(
        request_id: i64,
        error_status: i64,
        error_index: i64,
        varbinds: SnmpVarBindList,
    ) -> Self {
        Self {
            request_id,
            error_status,
            error_index,
            varbinds,
        }
    }

    /// Decode the body content of one GetRequest-style PDU.
    pub fn decode_body(bytes: &[u8]) -> Result<Self> {
        let (request_id, rest) = ber::decode_integer(bytes)?;
        let (error_status, rest) = ber::decode_integer(rest)?;
        let (error_index, rest) = ber::decode_integer(rest)?;
        let (varbinds, rest) = SnmpVarBindList::decode(rest)?;
        if !rest.is_empty() {
            return Err(ber::invalid_ber_field(
                "snmp.pdu.request",
                "trailing bytes after request PDU fields",
            ));
        }

        Ok(Self::with_fields(
            request_id,
            error_status,
            error_index,
            varbinds,
        ))
    }

    /// Encode the body content of this GetRequest-style PDU.
    pub fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        ber::encode_integer(self.request_id, out)?;
        ber::encode_integer(self.error_status, out)?;
        ber::encode_integer(self.error_index, out)?;
        self.varbinds.encode(out)
    }

    /// Return this request PDU body encoded as BER content bytes.
    pub fn to_body_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode_body(&mut out)?;
        Ok(out)
    }

    /// Request-id INTEGER value.
    pub const fn request_id(&self) -> i64 {
        self.request_id
    }

    /// Error-status INTEGER value.
    pub const fn error_status(&self) -> i64 {
        self.error_status
    }

    /// Error-index INTEGER value.
    pub const fn error_index(&self) -> i64 {
        self.error_index
    }

    /// Ordered VarBindList carried by this request PDU.
    pub const fn varbinds(&self) -> &SnmpVarBindList {
        &self.varbinds
    }

    /// Consume this request PDU and return the ordered VarBindList.
    pub fn into_varbinds(self) -> SnmpVarBindList {
        self.varbinds
    }
}

/// Source-backed SNMP PDU tag variants with raw body preservation.
///
/// This enum preserves operation tag bytes. GetRequest-style common fields can
/// be decoded through [`SnmpPdu::as_get_request`]; other PDU body fields are
/// parsed by later implementation slices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpPdu {
    /// GetRequest-PDU.
    GetRequest(SnmpRawPduBody),
    /// GetNextRequest-PDU.
    GetNextRequest(SnmpRawPduBody),
    /// Response/GetResponse PDU.
    Response(SnmpRawPduBody),
    /// SetRequest-PDU.
    SetRequest(SnmpRawPduBody),
    /// SNMPv1 Trap-PDU.
    Trap(SnmpRawPduBody),
    /// GetBulkRequest-PDU.
    GetBulkRequest(SnmpRawPduBody),
    /// InformRequest-PDU.
    InformRequest(SnmpRawPduBody),
    /// SNMPv2-Trap-PDU.
    SnmpV2Trap(SnmpRawPduBody),
    /// Report-PDU.
    Report(SnmpRawPduBody),
    /// Context-specific tag not assigned by the manifest-backed PDU matrix, or
    /// a non-constructed context-specific TLV in PDU position.
    Unknown(SnmpRawPdu),
}

impl SnmpPdu {
    /// GetRequest-PDU tag number.
    pub const TAG_GET_REQUEST: u8 = constants::SNMP_PDU_TAG_GET_REQUEST;
    /// GetNextRequest-PDU tag number.
    pub const TAG_GET_NEXT_REQUEST: u8 = constants::SNMP_PDU_TAG_GET_NEXT_REQUEST;
    /// Response/GetResponse PDU tag number.
    pub const TAG_RESPONSE: u8 = constants::SNMP_PDU_TAG_RESPONSE;
    /// SetRequest-PDU tag number.
    pub const TAG_SET_REQUEST: u8 = constants::SNMP_PDU_TAG_SET_REQUEST;
    /// SNMPv1 Trap-PDU tag number.
    pub const TAG_TRAP: u8 = constants::SNMP_PDU_TAG_TRAP;
    /// GetBulkRequest-PDU tag number.
    pub const TAG_GET_BULK_REQUEST: u8 = constants::SNMP_PDU_TAG_GET_BULK_REQUEST;
    /// InformRequest-PDU tag number.
    pub const TAG_INFORM_REQUEST: u8 = constants::SNMP_PDU_TAG_INFORM_REQUEST;
    /// SNMPv2-Trap-PDU tag number.
    pub const TAG_TRAP_V2: u8 = constants::SNMP_PDU_TAG_TRAP_V2;
    /// Report-PDU tag number.
    pub const TAG_REPORT: u8 = constants::SNMP_PDU_TAG_REPORT;

    /// Build a raw-body PDU from a BER PDU tag number and constructed bit.
    pub fn from_raw_parts(tag_number: u8, constructed: bool, body: impl Into<Vec<u8>>) -> Self {
        let body = SnmpRawPduBody::new(body);
        Self::from_body(tag_number, constructed, body)
    }

    /// Build a raw GetRequest-PDU body.
    pub fn raw_get_request(body: impl Into<Vec<u8>>) -> Self {
        Self::GetRequest(SnmpRawPduBody::new(body))
    }

    /// Build a GetRequest-PDU with noError/noErrorIndex convention fields.
    pub fn get_request(request_id: i64, varbinds: SnmpVarBindList) -> Result<Self> {
        Self::get_request_with_fields(request_id, 0, 0, varbinds)
    }

    /// Build a GetRequest-PDU preserving caller-supplied integer fields.
    pub fn get_request_with_fields(
        request_id: i64,
        error_status: i64,
        error_index: i64,
        varbinds: SnmpVarBindList,
    ) -> Result<Self> {
        let request = SnmpRequestPdu::with_fields(request_id, error_status, error_index, varbinds);
        Ok(Self::GetRequest(SnmpRawPduBody::new(
            request.to_body_bytes()?,
        )))
    }

    /// Build a raw GetNextRequest-PDU body.
    pub fn raw_get_next_request(body: impl Into<Vec<u8>>) -> Self {
        Self::GetNextRequest(SnmpRawPduBody::new(body))
    }

    /// Build a raw Response/GetResponse PDU body.
    pub fn raw_response(body: impl Into<Vec<u8>>) -> Self {
        Self::Response(SnmpRawPduBody::new(body))
    }

    /// Build a raw SetRequest-PDU body.
    pub fn raw_set_request(body: impl Into<Vec<u8>>) -> Self {
        Self::SetRequest(SnmpRawPduBody::new(body))
    }

    /// Build a raw SNMPv1 Trap-PDU body.
    pub fn raw_trap(body: impl Into<Vec<u8>>) -> Self {
        Self::Trap(SnmpRawPduBody::new(body))
    }

    /// Build a raw GetBulkRequest-PDU body.
    pub fn raw_get_bulk_request(body: impl Into<Vec<u8>>) -> Self {
        Self::GetBulkRequest(SnmpRawPduBody::new(body))
    }

    /// Build a raw InformRequest-PDU body.
    pub fn raw_inform_request(body: impl Into<Vec<u8>>) -> Self {
        Self::InformRequest(SnmpRawPduBody::new(body))
    }

    /// Build a raw SNMPv2-Trap-PDU body.
    pub fn raw_snmpv2_trap(body: impl Into<Vec<u8>>) -> Self {
        Self::SnmpV2Trap(SnmpRawPduBody::new(body))
    }

    /// Build a raw Report-PDU body.
    pub fn raw_report(body: impl Into<Vec<u8>>) -> Self {
        Self::Report(SnmpRawPduBody::new(body))
    }

    /// Build an unknown context-specific PDU body.
    pub fn unknown(tag_number: u8, constructed: bool, body: impl Into<Vec<u8>>) -> Self {
        Self::Unknown(SnmpRawPdu::new(tag_number, constructed, body))
    }

    fn from_body(tag_number: u8, constructed: bool, body: SnmpRawPduBody) -> Self {
        match (constructed, tag_number) {
            (true, constants::SNMP_PDU_TAG_GET_REQUEST) => Self::GetRequest(body),
            (true, constants::SNMP_PDU_TAG_GET_NEXT_REQUEST) => Self::GetNextRequest(body),
            (true, constants::SNMP_PDU_TAG_RESPONSE) => Self::Response(body),
            (true, constants::SNMP_PDU_TAG_SET_REQUEST) => Self::SetRequest(body),
            (true, constants::SNMP_PDU_TAG_TRAP) => Self::Trap(body),
            (true, constants::SNMP_PDU_TAG_GET_BULK_REQUEST) => Self::GetBulkRequest(body),
            (true, constants::SNMP_PDU_TAG_INFORM_REQUEST) => Self::InformRequest(body),
            (true, constants::SNMP_PDU_TAG_TRAP_V2) => Self::SnmpV2Trap(body),
            (true, constants::SNMP_PDU_TAG_REPORT) => Self::Report(body),
            _ => Self::Unknown(SnmpRawPdu {
                tag_number,
                constructed,
                body,
            }),
        }
    }

    /// Decode one SNMP PDU TLV and return remaining bytes.
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (tag, body, tlv, rest) = decode_pdu_tlv(bytes)?;
        let body = SnmpRawPduBody::from_tlv(body.to_vec(), tlv.to_vec());
        let pdu = Self::from_body(tag.number(), tag.is_constructed(), body);

        Ok((pdu, rest))
    }

    /// Encode this PDU TLV into BER bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        if let Some(raw_tlv) = self.raw_tlv_bytes() {
            out.extend_from_slice(raw_tlv);
            return Ok(());
        }

        encode_pdu_tlv(self.tag_number(), self.is_constructed(), self.body(), out)
    }

    /// Return this PDU encoded as BER bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile this PDU into BER bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.to_bytes()
    }

    /// Low-tag-number value from the context-specific BER identifier.
    pub const fn tag_number(&self) -> u8 {
        match self {
            Self::GetRequest(_) => constants::SNMP_PDU_TAG_GET_REQUEST,
            Self::GetNextRequest(_) => constants::SNMP_PDU_TAG_GET_NEXT_REQUEST,
            Self::Response(_) => constants::SNMP_PDU_TAG_RESPONSE,
            Self::SetRequest(_) => constants::SNMP_PDU_TAG_SET_REQUEST,
            Self::Trap(_) => constants::SNMP_PDU_TAG_TRAP,
            Self::GetBulkRequest(_) => constants::SNMP_PDU_TAG_GET_BULK_REQUEST,
            Self::InformRequest(_) => constants::SNMP_PDU_TAG_INFORM_REQUEST,
            Self::SnmpV2Trap(_) => constants::SNMP_PDU_TAG_TRAP_V2,
            Self::Report(_) => constants::SNMP_PDU_TAG_REPORT,
            Self::Unknown(raw) => raw.tag_number(),
        }
    }

    /// Whether the BER identifier uses the constructed bit.
    pub const fn is_constructed(&self) -> bool {
        match self {
            Self::Unknown(raw) => raw.is_constructed(),
            _ => true,
        }
    }

    /// Source-backed PDU tag name, when assigned.
    pub const fn tag_name(&self) -> Option<&'static str> {
        registry::snmp_pdu_tag_name(self.tag_number())
    }

    /// Source-backed PDU tag assignment status.
    pub const fn tag_status(&self) -> registry::SnmpPduTagStatus {
        registry::snmp_pdu_tag_status(self.tag_number())
    }

    /// Stable PDU tag label.
    pub fn tag_label(&self) -> String {
        registry::pdu_tag_label(self.tag_number())
    }

    /// Raw BER content bytes inside the PDU TLV.
    pub fn body(&self) -> &[u8] {
        match self {
            Self::GetRequest(body)
            | Self::GetNextRequest(body)
            | Self::Response(body)
            | Self::SetRequest(body)
            | Self::Trap(body)
            | Self::GetBulkRequest(body)
            | Self::InformRequest(body)
            | Self::SnmpV2Trap(body)
            | Self::Report(body) => body.as_bytes(),
            Self::Unknown(raw) => raw.body(),
        }
    }

    /// Byte-exact PDU TLV bytes, when this value came from decode.
    pub fn raw_tlv_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::GetRequest(body)
            | Self::GetNextRequest(body)
            | Self::Response(body)
            | Self::SetRequest(body)
            | Self::Trap(body)
            | Self::GetBulkRequest(body)
            | Self::InformRequest(body)
            | Self::SnmpV2Trap(body)
            | Self::Report(body) => body.raw_tlv_bytes(),
            Self::Unknown(raw) => raw.raw_tlv_bytes(),
        }
    }

    /// Unknown PDU metadata, if this value carries an unmodeled raw PDU.
    pub fn as_unknown(&self) -> Option<&SnmpRawPdu> {
        match self {
            Self::Unknown(raw) => Some(raw),
            _ => None,
        }
    }

    /// Decode typed GetRequest-style fields when this PDU has the GetRequest tag.
    pub fn as_get_request(&self) -> Result<Option<SnmpRequestPdu>> {
        match self {
            Self::GetRequest(body) => Ok(Some(SnmpRequestPdu::decode_body(body.as_bytes())?)),
            _ => Ok(None),
        }
    }
}

fn decode_pdu_tlv(bytes: &[u8]) -> Result<(ber::BerTag, &[u8], &[u8], &[u8])> {
    let (tag, rest) = ber::decode_identifier(bytes)?;
    if tag.class() != ber::BerClass::ContextSpecific {
        return Err(ber::invalid_ber_field(
            "snmp.pdu",
            "expected context-specific PDU tag",
        ));
    }

    let (length, rest) = ber::decode_length(rest)?;
    if rest.len() < length {
        let prefix_len = bytes.len() - rest.len();
        let required = prefix_len.checked_add(length).ok_or_else(|| {
            ber::invalid_ber_field("snmp.pdu", "PDU length exceeds supported size")
        })?;
        return Err(ber::truncated_ber("snmp.pdu", required, bytes.len()));
    }

    let content_offset = bytes.len() - rest.len();
    let value_end = content_offset + length;
    let body = &bytes[content_offset..value_end];
    let tlv = &bytes[..value_end];
    let rest = &bytes[value_end..];

    Ok((tag, body, tlv, rest))
}

fn encode_pdu_tlv(tag_number: u8, constructed: bool, body: &[u8], out: &mut Vec<u8>) -> Result<()> {
    if tag_number > ber::BER_LOW_TAG_NUMBER_MAX {
        return Err(ber::invalid_ber_field(
            "snmp.pdu.tag",
            "high-tag-number form is not supported for SNMP",
        ));
    }

    ber::encode_identifier(
        ber::BerTag::new(ber::BerClass::ContextSpecific, constructed, tag_number),
        out,
    )?;
    ber::encode_length(body.len(), out)?;
    out.extend_from_slice(body);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CrafterError;

    #[test]
    fn snmp_pdu_tags_constants_match_source_backed_matrix() {
        let tags = [
            (
                SnmpPdu::TAG_GET_REQUEST,
                constants::SNMP_PDU_TAG_GET_REQUEST,
            ),
            (
                SnmpPdu::TAG_GET_NEXT_REQUEST,
                constants::SNMP_PDU_TAG_GET_NEXT_REQUEST,
            ),
            (SnmpPdu::TAG_RESPONSE, constants::SNMP_PDU_TAG_RESPONSE),
            (
                SnmpPdu::TAG_SET_REQUEST,
                constants::SNMP_PDU_TAG_SET_REQUEST,
            ),
            (SnmpPdu::TAG_TRAP, constants::SNMP_PDU_TAG_TRAP),
            (
                SnmpPdu::TAG_GET_BULK_REQUEST,
                constants::SNMP_PDU_TAG_GET_BULK_REQUEST,
            ),
            (
                SnmpPdu::TAG_INFORM_REQUEST,
                constants::SNMP_PDU_TAG_INFORM_REQUEST,
            ),
            (SnmpPdu::TAG_TRAP_V2, constants::SNMP_PDU_TAG_TRAP_V2),
            (SnmpPdu::TAG_REPORT, constants::SNMP_PDU_TAG_REPORT),
        ];

        for (actual, expected) in tags {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn snmp_pdu_tags_decode_known_raw_body_and_reencode_tlv() -> Result<()> {
        let bytes = [
            0xa0, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00, 0xbb,
        ];
        let (decoded, rest) = SnmpPdu::decode(&bytes)?;

        assert!(matches!(decoded, SnmpPdu::GetRequest(_)));
        assert_eq!(decoded.tag_number(), constants::SNMP_PDU_TAG_GET_REQUEST);
        assert_eq!(decoded.tag_name(), Some("get-request"));
        assert_eq!(decoded.tag_status(), registry::SnmpPduTagStatus::Assigned);
        assert!(decoded.is_constructed());
        assert_eq!(
            decoded.body(),
            &[0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00]
        );
        assert_eq!(decoded.raw_tlv_bytes(), Some(&bytes[..13]));
        assert_eq!(decoded.compile()?, bytes[..13]);
        assert_eq!(rest, &[0xbb]);

        Ok(())
    }

    #[test]
    fn snmp_pdu_tags_decode_all_assigned_tags_as_typed_variants() -> Result<()> {
        let cases = [
            (
                constants::SNMP_PDU_TAG_GET_REQUEST,
                SnmpPdu::raw_get_request(Vec::<u8>::new()),
                "get-request",
            ),
            (
                constants::SNMP_PDU_TAG_GET_NEXT_REQUEST,
                SnmpPdu::raw_get_next_request(Vec::<u8>::new()),
                "get-next-request",
            ),
            (
                constants::SNMP_PDU_TAG_RESPONSE,
                SnmpPdu::raw_response(Vec::<u8>::new()),
                "response",
            ),
            (
                constants::SNMP_PDU_TAG_SET_REQUEST,
                SnmpPdu::raw_set_request(Vec::<u8>::new()),
                "set-request",
            ),
            (
                constants::SNMP_PDU_TAG_TRAP,
                SnmpPdu::raw_trap(Vec::<u8>::new()),
                "trap",
            ),
            (
                constants::SNMP_PDU_TAG_GET_BULK_REQUEST,
                SnmpPdu::raw_get_bulk_request(Vec::<u8>::new()),
                "get-bulk-request",
            ),
            (
                constants::SNMP_PDU_TAG_INFORM_REQUEST,
                SnmpPdu::raw_inform_request(Vec::<u8>::new()),
                "inform-request",
            ),
            (
                constants::SNMP_PDU_TAG_TRAP_V2,
                SnmpPdu::raw_snmpv2_trap(Vec::<u8>::new()),
                "snmpv2-trap",
            ),
            (
                constants::SNMP_PDU_TAG_REPORT,
                SnmpPdu::raw_report(Vec::<u8>::new()),
                "report",
            ),
        ];

        for (tag, expected, label) in cases {
            let bytes = [0xa0 | tag, 0x00];
            let (decoded, rest) = SnmpPdu::decode(&bytes)?;

            assert_eq!(decoded, expected);
            assert!(rest.is_empty());
            assert_eq!(decoded.tag_label(), label);
            assert_eq!(decoded.compile()?, bytes);
        }

        Ok(())
    }

    #[test]
    fn snmp_pdu_tags_unknown_context_specific_pdu_is_byte_exact() -> Result<()> {
        let bytes = [0xa9, 0x81, 0x02, 0xde, 0xad, 0xcc];
        let (decoded, rest) = SnmpPdu::decode(&bytes)?;
        let unknown = decoded.as_unknown().expect("unknown PDU");

        assert_eq!(unknown.tag_number(), 9);
        assert!(unknown.is_constructed());
        assert_eq!(unknown.body(), &[0xde, 0xad]);
        assert_eq!(unknown.raw_tlv_bytes(), Some(&bytes[..5]));
        assert_eq!(decoded.tag_name(), None);
        assert_eq!(decoded.tag_label(), "pdu-9");
        assert_eq!(decoded.tag_status(), registry::SnmpPduTagStatus::Unknown);
        assert_eq!(decoded.compile()?, bytes[..5]);
        assert_eq!(rest, &[0xcc]);

        Ok(())
    }

    #[test]
    fn snmp_pdu_tags_non_constructed_context_specific_pdu_is_preserved() -> Result<()> {
        let decoded = SnmpPdu::from_raw_parts(constants::SNMP_PDU_TAG_GET_REQUEST, false, [0xaa]);
        let unknown = decoded.as_unknown().expect("non-constructed PDU");

        assert_eq!(unknown.tag_number(), constants::SNMP_PDU_TAG_GET_REQUEST);
        assert!(!unknown.is_constructed());
        assert_eq!(unknown.body(), &[0xaa]);
        assert_eq!(decoded.tag_name(), Some("get-request"));
        assert_eq!(decoded.compile()?, [0x80, 0x01, 0xaa]);

        Ok(())
    }

    #[test]
    fn snmp_pdu_tags_reject_non_context_specific_tlv() {
        let error = SnmpPdu::decode(&[0x30, 0x00]).expect_err("not a PDU tag");

        assert_eq!(
            error,
            CrafterError::invalid_field_value("snmp.pdu", "expected context-specific PDU tag")
        );
    }

    #[test]
    fn snmp_request_pdu_empty_varbinds_compile_and_decode() -> Result<()> {
        let pdu = SnmpPdu::get_request(1, SnmpVarBindList::empty())?;

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 1157 Section
        // 4.1.1 and RFC 3416 Section 3 for request-id, error-status,
        // error-index, and VarBindList as the common request PDU fields.
        let expected = [
            0xa0, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];
        assert_eq!(pdu.compile()?, expected);
        assert_eq!(pdu.body(), &expected[2..]);

        let request = pdu.as_get_request()?.expect("GetRequest fields");
        assert_eq!(request.request_id(), 1);
        assert_eq!(request.error_status(), 0);
        assert_eq!(request.error_index(), 0);
        assert!(request.varbinds().is_empty());

        let (decoded, rest) = SnmpPdu::decode(&expected)?;
        assert!(rest.is_empty());
        let decoded_request = decoded
            .as_get_request()?
            .expect("decoded GetRequest fields");
        assert_eq!(decoded_request, request);
        assert_eq!(decoded.compile()?, expected);

        Ok(())
    }

    #[test]
    fn snmp_request_pdu_multi_varbind_preserves_order_and_fields() -> Result<()> {
        let first = crate::protocols::snmp::SnmpVarBind::null(
            crate::protocols::snmp::SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?,
        );
        let second = crate::protocols::snmp::SnmpVarBind::null(
            crate::protocols::snmp::SnmpOid::from_dotted("1.3.6.1.2.1.1.5.0")?,
        );
        let varbinds = SnmpVarBindList::new(vec![first.clone(), second.clone()]);
        let pdu = SnmpPdu::get_request_with_fields(12_345, 7, 2, varbinds)?;

        let expected = [
            0xa0, 0x28, 0x02, 0x02, 0x30, 0x39, 0x02, 0x01, 0x07, 0x02, 0x01, 0x02, 0x30, 0x1c,
            0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
            0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x05, 0x00,
        ];
        assert_eq!(pdu.compile()?, expected);

        let request = pdu.as_get_request()?.expect("GetRequest fields");
        assert_eq!(request.request_id(), 12_345);
        assert_eq!(request.error_status(), 7);
        assert_eq!(request.error_index(), 2);
        assert_eq!(request.varbinds().as_slice(), &[first, second]);

        let (decoded, rest) = SnmpPdu::decode(&expected)?;
        assert!(rest.is_empty());
        assert_eq!(decoded.as_get_request()?.expect("decoded fields"), request);
        assert_eq!(decoded.compile()?, expected);

        Ok(())
    }

    #[test]
    fn snmp_request_pdu_unknown_request_id_value_is_not_special_cased() -> Result<()> {
        let pdu = SnmpPdu::get_request(2_147_483_647, SnmpVarBindList::empty())?;

        let expected = [
            0xa0, 0x0e, 0x02, 0x04, 0x7f, 0xff, 0xff, 0xff, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x00,
        ];
        assert_eq!(pdu.compile()?, expected);

        let (decoded, rest) = SnmpPdu::decode(&expected)?;
        assert!(rest.is_empty());
        let request = decoded.as_get_request()?.expect("GetRequest fields");
        assert_eq!(request.request_id(), 2_147_483_647);
        assert_eq!(request.error_status(), 0);
        assert_eq!(request.error_index(), 0);
        assert!(request.varbinds().is_empty());

        Ok(())
    }

    #[test]
    fn snmp_request_pdu_decoded_bytes_round_trip_without_normalizing_lengths() -> Result<()> {
        let bytes = [
            0xa0, 0x0c, 0x02, 0x02, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];
        let (decoded, rest) = SnmpPdu::decode(&bytes)?;

        assert!(rest.is_empty());
        let request = decoded.as_get_request()?.expect("GetRequest fields");
        assert_eq!(request.request_id(), 0);
        assert!(request.varbinds().is_empty());
        assert_eq!(decoded.compile()?, bytes);

        Ok(())
    }
}
