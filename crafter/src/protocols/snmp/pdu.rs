//! SNMP PDU tag metadata, request/trap fields, and raw-body preservation.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`; GetRequest-style common
//! request fields are modeled here for GetRequest, GetNextRequest, Response,
//! SetRequest, InformRequest, SNMPv2-Trap, and Report, plus source-backed
//! GetBulkRequest and SNMPv1 Trap-PDU wire fields.
//! Walk, polling, trap listener, authorization, and set workflows belong in
//! generated tools, not in this packet primitive.

use super::{ber, constants, oid::SnmpOid, registry, value::SnmpValue, varbind::SnmpVarBindList};
use crate::error::Result;

/// Raw BER content bytes for one SNMP PDU body.
#[derive(Debug, Clone, Default)]
pub struct SnmpRawPduBody {
    bytes: Vec<u8>,
    raw_tlv: Option<Vec<u8>>,
    length: Option<usize>,
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
            length: None,
        }
    }

    fn from_tlv(bytes: impl Into<Vec<u8>>, raw_tlv: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            raw_tlv: Some(raw_tlv.into()),
            length: None,
        }
    }

    /// Pin the enclosing PDU BER length field to an explicit value.
    ///
    /// Unset PDU lengths are auto-filled from the body length. A pinned value
    /// is emitted verbatim, even when it deliberately disagrees with the body
    /// bytes; the body bytes are still emitted unchanged.
    pub fn length(mut self, length: usize) -> Self {
        self.set_length(length);
        self
    }

    /// Drop any explicit PDU BER length override so encode auto-fills it.
    pub fn clear_length(mut self) -> Self {
        self.clear_length_override();
        self
    }

    fn set_length(&mut self, length: usize) {
        self.length = Some(length);
        self.raw_tlv = None;
    }

    fn clear_length_override(&mut self) {
        self.length = None;
        self.raw_tlv = None;
    }

    /// Explicit PDU BER length override, if one is pinned.
    pub const fn explicit_length(&self) -> Option<usize> {
        self.length
    }

    /// Effective PDU BER length: caller override when set, else body length.
    pub fn effective_length(&self) -> usize {
        self.length.unwrap_or(self.bytes.len())
    }

    /// Raw BER content bytes inside the PDU TLV.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Byte-exact PDU TLV bytes, when this body came from decode.
    pub fn raw_tlv_bytes(&self) -> Option<&[u8]> {
        if self.length.is_some() {
            return None;
        }
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

/// Common GetRequest-style request/response PDU fields.
///
/// RFC-backed GetRequest, GetNextRequest, Response, SetRequest, InformRequest,
/// SNMPv2-Trap, and Report PDUs carry request-id, error-status, error-index,
/// and a VarBindList as the PDU body content. This type models those fields as
/// packet bytes only; it does not add manager/session behavior, notification
/// delivery, security-engine behavior, or validate application success
/// semantics.
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

    /// Typed error-status wrapper for the INTEGER value.
    pub const fn error_status_value(&self) -> registry::SnmpErrorStatus {
        registry::SnmpErrorStatus::new(self.error_status)
    }

    /// Source-backed error-status name, when assigned.
    pub const fn error_status_name(&self) -> Option<&'static str> {
        registry::snmp_error_status_name(self.error_status)
    }

    /// Source-backed error-status assignment status.
    pub const fn error_status_assignment(&self) -> registry::SnmpErrorStatusAssignment {
        registry::snmp_error_status_status(self.error_status)
    }

    /// Stable error-status label that preserves unknown values.
    pub fn error_status_label(&self) -> String {
        registry::snmp_error_status_label(self.error_status)
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

    /// A compact summary of the common PDU fields.
    pub fn summary(&self) -> String {
        self.summary_with_label("request")
    }

    /// A compact summary of the common PDU fields with a tag-specific label.
    pub fn summary_with_label(&self, label: &str) -> String {
        format!(
            "{label} request_id={} error_status={} error_index={} varbinds={}",
            self.request_id,
            registry::snmp_error_status_summary(self.error_status),
            self.error_index,
            self.varbinds.len()
        )
    }

    /// Stable inspection fields for generated tools.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("request_id", self.request_id.to_string()),
            ("error_status", self.error_status.to_string()),
            ("error_status_label", self.error_status_label()),
            (
                "error_status_assignment",
                self.error_status_assignment().to_string(),
            ),
            ("error_index", self.error_index.to_string()),
        ];
        fields.extend(self.varbinds.inspection_fields());
        fields
    }
}

/// SNMP GetBulkRequest-PDU wire fields.
///
/// RFC-backed GetBulkRequest PDUs carry request-id, non-repeaters,
/// max-repetitions, and a VarBindList as the PDU body content. This type
/// preserves the integer fields exactly as supplied or decoded; it does not
/// perform table walks or enforce application-level repetition limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpGetBulkPdu {
    request_id: i64,
    non_repeaters: i64,
    max_repetitions: i64,
    varbinds: SnmpVarBindList,
}

impl SnmpGetBulkPdu {
    /// Build GetBulkRequest fields with caller-supplied integer values.
    pub fn new(
        request_id: i64,
        non_repeaters: i64,
        max_repetitions: i64,
        varbinds: SnmpVarBindList,
    ) -> Self {
        Self {
            request_id,
            non_repeaters,
            max_repetitions,
            varbinds,
        }
    }

    /// Decode the body content of one GetBulkRequest-PDU.
    pub fn decode_body(bytes: &[u8]) -> Result<Self> {
        let (request_id, rest) = ber::decode_integer(bytes)?;
        let (non_repeaters, rest) = ber::decode_integer(rest)?;
        let (max_repetitions, rest) = ber::decode_integer(rest)?;
        let (varbinds, rest) = SnmpVarBindList::decode(rest)?;
        if !rest.is_empty() {
            return Err(ber::invalid_ber_field(
                "snmp.pdu.get_bulk",
                "trailing bytes after GetBulk PDU fields",
            ));
        }

        Ok(Self::new(
            request_id,
            non_repeaters,
            max_repetitions,
            varbinds,
        ))
    }

    /// Encode the body content of this GetBulkRequest-PDU.
    pub fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        ber::encode_integer(self.request_id, out)?;
        ber::encode_integer(self.non_repeaters, out)?;
        ber::encode_integer(self.max_repetitions, out)?;
        self.varbinds.encode(out)
    }

    /// Return this GetBulkRequest-PDU body encoded as BER content bytes.
    pub fn to_body_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode_body(&mut out)?;
        Ok(out)
    }

    /// Request-id INTEGER value.
    pub const fn request_id(&self) -> i64 {
        self.request_id
    }

    /// Non-repeaters INTEGER value.
    pub const fn non_repeaters(&self) -> i64 {
        self.non_repeaters
    }

    /// Max-repetitions INTEGER value.
    pub const fn max_repetitions(&self) -> i64 {
        self.max_repetitions
    }

    /// Ordered VarBindList carried by this GetBulkRequest-PDU.
    pub const fn varbinds(&self) -> &SnmpVarBindList {
        &self.varbinds
    }

    /// Consume this GetBulkRequest-PDU and return the ordered VarBindList.
    pub fn into_varbinds(self) -> SnmpVarBindList {
        self.varbinds
    }

    /// A compact summary of the GetBulkRequest-PDU fields.
    pub fn summary(&self) -> String {
        format!(
            "get-bulk request_id={} non_repeaters={} max_repetitions={} varbinds={}",
            self.request_id,
            self.non_repeaters,
            self.max_repetitions,
            self.varbinds.len()
        )
    }

    /// Stable inspection fields for generated tools.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("request_id", self.request_id.to_string()),
            ("non_repeaters", self.non_repeaters.to_string()),
            ("max_repetitions", self.max_repetitions.to_string()),
        ];
        fields.extend(self.varbinds.inspection_fields());
        fields
    }
}

/// SNMPv1 Trap-PDU wire fields.
///
/// RFC-backed SNMPv1 Trap-PDUs carry enterprise OBJECT IDENTIFIER, agent
/// address, generic trap, specific trap, timestamp, and VarBindList fields.
/// This type preserves generic and specific trap INTEGER values as supplied; it
/// does not validate assigned generic-trap names or implement listener/service
/// behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpV1TrapPdu {
    enterprise: SnmpOid,
    agent_address: [u8; 4],
    generic_trap: i64,
    specific_trap: i64,
    timestamp: u32,
    varbinds: SnmpVarBindList,
}

impl SnmpV1TrapPdu {
    /// Build SNMPv1 Trap-PDU fields.
    pub fn new(
        enterprise: SnmpOid,
        agent_address: [u8; 4],
        generic_trap: i64,
        specific_trap: i64,
        timestamp: u32,
        varbinds: SnmpVarBindList,
    ) -> Self {
        Self {
            enterprise,
            agent_address,
            generic_trap,
            specific_trap,
            timestamp,
            varbinds,
        }
    }

    /// Decode the body content of one SNMPv1 Trap-PDU.
    pub fn decode_body(bytes: &[u8]) -> Result<Self> {
        let (enterprise, rest) = SnmpOid::decode(bytes)?;
        let (agent_address, rest) = SnmpValue::decode_ip_address(rest)?;
        let Some(agent_address) = agent_address.as_ip_address() else {
            return Err(ber::invalid_ber_field(
                "snmp.pdu.trap.agent_address",
                "expected IpAddress value",
            ));
        };
        let (generic_trap, rest) = ber::decode_integer(rest)?;
        let (specific_trap, rest) = ber::decode_integer(rest)?;
        let (timestamp, rest) = SnmpValue::decode_time_ticks(rest)?;
        let Some(timestamp) = timestamp.as_time_ticks() else {
            return Err(ber::invalid_ber_field(
                "snmp.pdu.trap.timestamp",
                "expected TimeTicks value",
            ));
        };
        let (varbinds, rest) = SnmpVarBindList::decode(rest)?;
        if !rest.is_empty() {
            return Err(ber::invalid_ber_field(
                "snmp.pdu.trap",
                "trailing bytes after trap PDU fields",
            ));
        }

        Ok(Self::new(
            enterprise,
            agent_address,
            generic_trap,
            specific_trap,
            timestamp,
            varbinds,
        ))
    }

    /// Encode the body content of this SNMPv1 Trap-PDU.
    pub fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.enterprise.encode(out)?;
        SnmpValue::ip_address(self.agent_address).encode(out)?;
        ber::encode_integer(self.generic_trap, out)?;
        ber::encode_integer(self.specific_trap, out)?;
        SnmpValue::time_ticks(self.timestamp).encode(out)?;
        self.varbinds.encode(out)
    }

    /// Return this Trap-PDU body encoded as BER content bytes.
    pub fn to_body_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode_body(&mut out)?;
        Ok(out)
    }

    /// Enterprise OBJECT IDENTIFIER.
    pub fn enterprise(&self) -> &SnmpOid {
        &self.enterprise
    }

    /// Agent IPv4 address octets from the SNMPv1 NetworkAddress choice.
    pub const fn agent_address(&self) -> [u8; 4] {
        self.agent_address
    }

    /// Generic trap INTEGER value.
    pub const fn generic_trap(&self) -> i64 {
        self.generic_trap
    }

    /// Specific trap INTEGER value.
    pub const fn specific_trap(&self) -> i64 {
        self.specific_trap
    }

    /// Timestamp TimeTicks value.
    pub const fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Ordered VarBindList carried by this trap PDU.
    pub const fn varbinds(&self) -> &SnmpVarBindList {
        &self.varbinds
    }

    /// Consume this trap PDU and return the ordered VarBindList.
    pub fn into_varbinds(self) -> SnmpVarBindList {
        self.varbinds
    }

    /// A compact summary of the SNMPv1 Trap-PDU fields.
    pub fn summary(&self) -> String {
        format!(
            "trap enterprise={} agent={} generic={} specific={} timestamp={} varbinds={}",
            self.enterprise,
            format_agent_address(self.agent_address),
            self.generic_trap,
            self.specific_trap,
            self.timestamp,
            self.varbinds.len()
        )
    }

    /// Stable inspection fields for generated tools.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("enterprise", self.enterprise.to_string()),
            ("agent_address", format_agent_address(self.agent_address)),
            ("generic_trap", self.generic_trap.to_string()),
            ("specific_trap", self.specific_trap.to_string()),
            ("timestamp", self.timestamp.to_string()),
        ];
        fields.extend(self.varbinds.inspection_fields());
        fields
    }
}

/// Source-backed SNMP PDU tag variants with raw body preservation.
///
/// This enum preserves operation tag bytes. GetRequest-style common fields can
/// be decoded through the tag-specific request accessors; other PDU body
/// fields are parsed by later implementation slices.
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
        Ok(Self::GetRequest(Self::request_body_with_fields(
            request_id,
            error_status,
            error_index,
            varbinds,
        )?))
    }

    /// Build a raw GetNextRequest-PDU body.
    pub fn raw_get_next_request(body: impl Into<Vec<u8>>) -> Self {
        Self::GetNextRequest(SnmpRawPduBody::new(body))
    }

    /// Build a GetNextRequest-PDU with noError/noErrorIndex convention fields.
    ///
    /// This only builds the wire PDU. Walk and retry behavior belongs in
    /// generated tools outside the crate.
    pub fn get_next_request(request_id: i64, varbinds: SnmpVarBindList) -> Result<Self> {
        Self::get_next_request_with_fields(request_id, 0, 0, varbinds)
    }

    /// Build a GetNextRequest-PDU preserving caller-supplied integer fields.
    ///
    /// This only builds the wire PDU. Walk and retry behavior belongs in
    /// generated tools outside the crate.
    pub fn get_next_request_with_fields(
        request_id: i64,
        error_status: i64,
        error_index: i64,
        varbinds: SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::GetNextRequest(Self::request_body_with_fields(
            request_id,
            error_status,
            error_index,
            varbinds,
        )?))
    }

    /// Build a raw Response/GetResponse PDU body.
    pub fn raw_response(body: impl Into<Vec<u8>>) -> Self {
        Self::Response(SnmpRawPduBody::new(body))
    }

    /// Build a Response/GetResponse PDU with noError/noErrorIndex convention fields.
    pub fn response(request_id: i64, varbinds: SnmpVarBindList) -> Result<Self> {
        Self::response_with_fields(request_id, 0, 0, varbinds)
    }

    /// Build a Response/GetResponse PDU carrying an error status and index.
    ///
    /// This helper preserves the supplied integer values. It does not validate
    /// whether the error status is source-assigned or whether the index matches
    /// an application-level variable binding.
    pub fn response_error(
        request_id: i64,
        error_status: i64,
        error_index: i64,
        varbinds: SnmpVarBindList,
    ) -> Result<Self> {
        Self::response_with_fields(request_id, error_status, error_index, varbinds)
    }

    /// Build a Response/GetResponse PDU preserving caller-supplied integer fields.
    pub fn response_with_fields(
        request_id: i64,
        error_status: i64,
        error_index: i64,
        varbinds: SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::Response(Self::request_body_with_fields(
            request_id,
            error_status,
            error_index,
            varbinds,
        )?))
    }

    /// Build a raw SetRequest-PDU body.
    pub fn raw_set_request(body: impl Into<Vec<u8>>) -> Self {
        Self::SetRequest(SnmpRawPduBody::new(body))
    }

    /// Build a SetRequest-PDU with noError/noErrorIndex convention fields.
    ///
    /// This only builds the wire PDU. Authorization and mutation workflows
    /// belong in generated tools outside the crate.
    pub fn set_request(request_id: i64, varbinds: SnmpVarBindList) -> Result<Self> {
        Self::set_request_with_fields(request_id, 0, 0, varbinds)
    }

    /// Build a SetRequest-PDU preserving caller-supplied integer fields.
    ///
    /// This only builds the wire PDU. Authorization and mutation workflows
    /// belong in generated tools outside the crate.
    pub fn set_request_with_fields(
        request_id: i64,
        error_status: i64,
        error_index: i64,
        varbinds: SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::SetRequest(Self::request_body_with_fields(
            request_id,
            error_status,
            error_index,
            varbinds,
        )?))
    }

    /// Build a raw SNMPv1 Trap-PDU body.
    pub fn raw_trap(body: impl Into<Vec<u8>>) -> Self {
        Self::Trap(SnmpRawPduBody::new(body))
    }

    /// Build an SNMPv1 Trap-PDU from source-backed wire fields.
    ///
    /// This only builds packet bytes. Trap listener and notification-service
    /// behavior belongs in generated tools outside the crate.
    pub fn v1_trap(
        enterprise: SnmpOid,
        agent_address: [u8; 4],
        generic_trap: i64,
        specific_trap: i64,
        timestamp: u32,
        varbinds: SnmpVarBindList,
    ) -> Result<Self> {
        let trap = SnmpV1TrapPdu::new(
            enterprise,
            agent_address,
            generic_trap,
            specific_trap,
            timestamp,
            varbinds,
        );
        Ok(Self::Trap(SnmpRawPduBody::new(trap.to_body_bytes()?)))
    }

    /// Build a raw GetBulkRequest-PDU body.
    pub fn raw_get_bulk_request(body: impl Into<Vec<u8>>) -> Self {
        Self::GetBulkRequest(SnmpRawPduBody::new(body))
    }

    /// Build a GetBulkRequest-PDU from source-backed wire fields.
    ///
    /// This only builds packet bytes. Table walking, retry behavior, and
    /// response interpretation belong in generated tools outside the crate.
    pub fn get_bulk_request(
        request_id: i64,
        non_repeaters: i64,
        max_repetitions: i64,
        varbinds: SnmpVarBindList,
    ) -> Result<Self> {
        let bulk = SnmpGetBulkPdu::new(request_id, non_repeaters, max_repetitions, varbinds);
        Ok(Self::GetBulkRequest(SnmpRawPduBody::new(
            bulk.to_body_bytes()?,
        )))
    }

    /// Build a raw InformRequest-PDU body.
    pub fn raw_inform_request(body: impl Into<Vec<u8>>) -> Self {
        Self::InformRequest(SnmpRawPduBody::new(body))
    }

    /// Build an InformRequest-PDU with noError/noErrorIndex convention fields.
    ///
    /// This only builds packet bytes. Delivery confirmation, retransmission,
    /// and notification workflow behavior belong in generated tools outside
    /// the crate.
    pub fn inform_request(request_id: i64, varbinds: SnmpVarBindList) -> Result<Self> {
        Self::inform_request_with_fields(request_id, 0, 0, varbinds)
    }

    /// Build an InformRequest-PDU preserving caller-supplied integer fields.
    ///
    /// This only builds packet bytes. Delivery confirmation, retransmission,
    /// and notification workflow behavior belong in generated tools outside
    /// the crate.
    pub fn inform_request_with_fields(
        request_id: i64,
        error_status: i64,
        error_index: i64,
        varbinds: SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::InformRequest(Self::request_body_with_fields(
            request_id,
            error_status,
            error_index,
            varbinds,
        )?))
    }

    /// Build a raw SNMPv2-Trap-PDU body.
    pub fn raw_snmpv2_trap(body: impl Into<Vec<u8>>) -> Self {
        Self::SnmpV2Trap(SnmpRawPduBody::new(body))
    }

    /// Build an SNMPv2-Trap-PDU with noError/noErrorIndex convention fields.
    ///
    /// This only builds packet bytes. Trap listener and notification-service
    /// behavior belongs in generated tools outside the crate.
    pub fn snmpv2_trap(request_id: i64, varbinds: SnmpVarBindList) -> Result<Self> {
        Self::snmpv2_trap_with_fields(request_id, 0, 0, varbinds)
    }

    /// Build an SNMPv2-Trap-PDU preserving caller-supplied integer fields.
    ///
    /// This only builds packet bytes. Trap listener and notification-service
    /// behavior belongs in generated tools outside the crate.
    pub fn snmpv2_trap_with_fields(
        request_id: i64,
        error_status: i64,
        error_index: i64,
        varbinds: SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::SnmpV2Trap(Self::request_body_with_fields(
            request_id,
            error_status,
            error_index,
            varbinds,
        )?))
    }

    /// Build a raw Report-PDU body.
    pub fn raw_report(body: impl Into<Vec<u8>>) -> Self {
        Self::Report(SnmpRawPduBody::new(body))
    }

    /// Build a Report-PDU with noError/noErrorIndex convention fields.
    ///
    /// This only builds packet bytes. SNMPv3 security validation and engine
    /// behavior belong in later packet validation or generated tools, not in
    /// this PDU helper.
    pub fn report(request_id: i64, varbinds: SnmpVarBindList) -> Result<Self> {
        Self::report_with_fields(request_id, 0, 0, varbinds)
    }

    /// Build a Report-PDU preserving caller-supplied integer fields.
    ///
    /// This only builds packet bytes. SNMPv3 security validation and engine
    /// behavior belong in later packet validation or generated tools, not in
    /// this PDU helper.
    pub fn report_with_fields(
        request_id: i64,
        error_status: i64,
        error_index: i64,
        varbinds: SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::Report(Self::request_body_with_fields(
            request_id,
            error_status,
            error_index,
            varbinds,
        )?))
    }

    /// Build an unknown context-specific PDU body.
    pub fn unknown(tag_number: u8, constructed: bool, body: impl Into<Vec<u8>>) -> Self {
        Self::Unknown(SnmpRawPdu::new(tag_number, constructed, body))
    }

    /// Pin the enclosing PDU BER length field to an explicit value.
    ///
    /// The normal builder path auto-fills the PDU length from the body. This
    /// override is for deliberately malformed packets: the length field is
    /// emitted as supplied while the body bytes remain unchanged.
    pub fn length(mut self, length: usize) -> Self {
        self.raw_body_mut().set_length(length);
        self
    }

    /// Drop any explicit PDU BER length override so encode auto-fills it.
    pub fn clear_length(mut self) -> Self {
        self.raw_body_mut().clear_length_override();
        self
    }

    /// Explicit PDU BER length override, if one is pinned.
    pub fn explicit_length(&self) -> Option<usize> {
        self.raw_body().explicit_length()
    }

    /// Effective PDU BER length: caller override when set, else body length.
    pub fn effective_length(&self) -> usize {
        self.raw_body().effective_length()
    }

    fn request_body_with_fields(
        request_id: i64,
        error_status: i64,
        error_index: i64,
        varbinds: SnmpVarBindList,
    ) -> Result<SnmpRawPduBody> {
        let request = SnmpRequestPdu::with_fields(request_id, error_status, error_index, varbinds);
        Ok(SnmpRawPduBody::new(request.to_body_bytes()?))
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

        encode_pdu_tlv(
            self.tag_number(),
            self.is_constructed(),
            self.body(),
            self.explicit_length(),
            out,
        )
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
        self.raw_body().as_bytes()
    }

    fn raw_body(&self) -> &SnmpRawPduBody {
        match self {
            Self::GetRequest(body)
            | Self::GetNextRequest(body)
            | Self::Response(body)
            | Self::SetRequest(body)
            | Self::Trap(body)
            | Self::GetBulkRequest(body)
            | Self::InformRequest(body)
            | Self::SnmpV2Trap(body)
            | Self::Report(body) => body,
            Self::Unknown(raw) => &raw.body,
        }
    }

    fn raw_body_mut(&mut self) -> &mut SnmpRawPduBody {
        match self {
            Self::GetRequest(body)
            | Self::GetNextRequest(body)
            | Self::Response(body)
            | Self::SetRequest(body)
            | Self::Trap(body)
            | Self::GetBulkRequest(body)
            | Self::InformRequest(body)
            | Self::SnmpV2Trap(body)
            | Self::Report(body) => body,
            Self::Unknown(raw) => &mut raw.body,
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

    /// Decode typed GetRequest-style fields when this PDU has the GetNextRequest tag.
    pub fn as_get_next_request(&self) -> Result<Option<SnmpRequestPdu>> {
        match self {
            Self::GetNextRequest(body) => Ok(Some(SnmpRequestPdu::decode_body(body.as_bytes())?)),
            _ => Ok(None),
        }
    }

    /// Decode typed request-id/error fields when this PDU has the Response tag.
    pub fn as_response(&self) -> Result<Option<SnmpRequestPdu>> {
        match self {
            Self::Response(body) => Ok(Some(SnmpRequestPdu::decode_body(body.as_bytes())?)),
            _ => Ok(None),
        }
    }

    /// Decode typed GetRequest-style fields when this PDU has the SetRequest tag.
    pub fn as_set_request(&self) -> Result<Option<SnmpRequestPdu>> {
        match self {
            Self::SetRequest(body) => Ok(Some(SnmpRequestPdu::decode_body(body.as_bytes())?)),
            _ => Ok(None),
        }
    }

    /// Decode typed SNMPv1 Trap-PDU fields when this PDU has the Trap tag.
    pub fn as_v1_trap(&self) -> Result<Option<SnmpV1TrapPdu>> {
        match self {
            Self::Trap(body) => Ok(Some(SnmpV1TrapPdu::decode_body(body.as_bytes())?)),
            _ => Ok(None),
        }
    }

    /// Decode typed GetBulkRequest-PDU fields when this PDU has the GetBulkRequest tag.
    pub fn as_get_bulk_request(&self) -> Result<Option<SnmpGetBulkPdu>> {
        match self {
            Self::GetBulkRequest(body) => Ok(Some(SnmpGetBulkPdu::decode_body(body.as_bytes())?)),
            _ => Ok(None),
        }
    }

    /// Decode typed common fields when this PDU has the InformRequest tag.
    pub fn as_inform_request(&self) -> Result<Option<SnmpRequestPdu>> {
        match self {
            Self::InformRequest(body) => Ok(Some(SnmpRequestPdu::decode_body(body.as_bytes())?)),
            _ => Ok(None),
        }
    }

    /// Decode typed common fields when this PDU has the SNMPv2-Trap tag.
    pub fn as_snmpv2_trap(&self) -> Result<Option<SnmpRequestPdu>> {
        match self {
            Self::SnmpV2Trap(body) => Ok(Some(SnmpRequestPdu::decode_body(body.as_bytes())?)),
            _ => Ok(None),
        }
    }

    /// Decode typed common fields when this PDU has the Report tag.
    pub fn as_report(&self) -> Result<Option<SnmpRequestPdu>> {
        match self {
            Self::Report(body) => Ok(Some(SnmpRequestPdu::decode_body(body.as_bytes())?)),
            _ => Ok(None),
        }
    }
}

fn format_agent_address(octets: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
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

fn encode_pdu_tlv(
    tag_number: u8,
    constructed: bool,
    body: &[u8],
    explicit_length: Option<usize>,
    out: &mut Vec<u8>,
) -> Result<()> {
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
    ber::encode_length(explicit_length.unwrap_or(body.len()), out)?;
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

    #[test]
    fn snmp_length_overrides_auto_fill_unset_pdu_length() -> Result<()> {
        let pdu = SnmpPdu::get_request(1, SnmpVarBindList::empty())?;

        let expected = [
            0xa0, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];
        assert_eq!(pdu.explicit_length(), None);
        assert_eq!(pdu.effective_length(), pdu.body().len());
        assert_eq!(pdu.compile()?, expected);

        Ok(())
    }

    #[test]
    fn snmp_length_overrides_preserve_wrong_pdu_and_nested_value_lengths() -> Result<()> {
        let name = SnmpOid::from_dotted("1.3.6.1.2.1.1.5.0")?;
        let malformed_value =
            crate::protocols::snmp::SnmpVarBind::raw_value_tlv_with_length(name, 0x04, 5, [0xaa])?;
        let pdu = SnmpPdu::get_request(1, SnmpVarBindList::new(vec![malformed_value]))?.length(0);

        let expected_body = [
            0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0f, 0x30, 0x0d, 0x06,
            0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x04, 0x05, 0xaa,
        ];
        let mut expected = vec![0xa0, 0x00];
        expected.extend_from_slice(&expected_body);
        assert_eq!(pdu.explicit_length(), Some(0));
        assert_eq!(pdu.effective_length(), 0);
        assert_eq!(pdu.compile()?, expected);

        let mut auto_filled = vec![0xa0, expected_body.len() as u8];
        auto_filled.extend_from_slice(&expected_body);
        assert_eq!(pdu.clear_length().compile()?, auto_filled);

        Ok(())
    }

    #[test]
    fn snmp_response_pdu_success_builder_compiles_decodes_and_preserves_varbinds() -> Result<()> {
        let varbind = crate::protocols::snmp::SnmpVarBind::time_ticks(
            crate::protocols::snmp::SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?,
            12_345,
        );
        let pdu = SnmpPdu::response(42, SnmpVarBindList::new(vec![varbind.clone()]))?;

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 1157 Section
        // 4.1.4 and RFC 3416 Sections 3 and 4.2.4 for Response/GetResponse
        // using request-id, error-status, error-index, and VarBindList fields.
        let expected = [
            0xa2, 0x1b, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x10, 0x30,
            0x0e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43, 0x02, 0x30,
            0x39,
        ];
        assert_eq!(pdu.tag_number(), constants::SNMP_PDU_TAG_RESPONSE);
        assert_eq!(pdu.tag_name(), Some("response"));
        assert_eq!(pdu.tag_label(), "response");
        assert_eq!(pdu.compile()?, expected);
        assert!(pdu.as_get_request()?.is_none());
        assert!(pdu.as_get_next_request()?.is_none());
        assert!(pdu.as_set_request()?.is_none());

        let response = pdu.as_response()?.expect("Response fields");
        assert_eq!(response.request_id(), 42);
        assert_eq!(response.error_status(), 0);
        assert_eq!(response.error_index(), 0);
        assert_eq!(response.varbinds().as_slice(), &[varbind]);

        let (decoded, rest) = SnmpPdu::decode(&expected)?;
        assert!(rest.is_empty());
        assert_eq!(decoded.as_response()?.expect("decoded fields"), response);
        assert_eq!(decoded.compile()?, expected);

        Ok(())
    }

    #[test]
    fn snmp_response_pdu_error_helper_preserves_status_and_index() -> Result<()> {
        let pdu = SnmpPdu::response_error(128, 2, 3, SnmpVarBindList::empty())?;

        let expected = [
            0xa2, 0x0c, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x30, 0x00,
        ];
        assert_eq!(pdu.compile()?, expected);

        let response = pdu.as_response()?.expect("Response fields");
        assert_eq!(response.request_id(), 128);
        assert_eq!(response.error_status(), 2);
        assert_eq!(response.error_index(), 3);
        assert!(response.varbinds().is_empty());

        let (decoded, rest) = SnmpPdu::decode(&expected)?;
        assert!(rest.is_empty());
        assert_eq!(decoded.tag_number(), constants::SNMP_PDU_TAG_RESPONSE);
        assert_eq!(decoded.as_response()?.expect("decoded fields"), response);

        Ok(())
    }

    #[test]
    fn snmp_response_pdu_unknown_error_status_value_is_preserved() -> Result<()> {
        let pdu = SnmpPdu::response_with_fields(5, 99, 300, SnmpVarBindList::empty())?;

        let expected = [
            0xa2, 0x0c, 0x02, 0x01, 0x05, 0x02, 0x01, 0x63, 0x02, 0x02, 0x01, 0x2c, 0x30, 0x00,
        ];
        assert_eq!(pdu.compile()?, expected);

        let response = pdu.as_response()?.expect("Response fields");
        assert_eq!(response.request_id(), 5);
        assert_eq!(response.error_status(), 99);
        assert_eq!(response.error_index(), 300);
        assert_eq!(response.error_status_name(), None);
        assert_eq!(
            response.error_status_assignment(),
            registry::SnmpErrorStatusAssignment::Unknown
        );
        assert_eq!(response.error_status_label(), "error-status-99");
        assert!(response.varbinds().is_empty());

        let (decoded, rest) = SnmpPdu::decode(&expected)?;
        assert!(rest.is_empty());
        assert_eq!(decoded.as_response()?.expect("decoded fields"), response);
        assert_eq!(decoded.compile()?, expected);

        Ok(())
    }

    #[test]
    fn snmp_error_status_summary_formatting_preserves_known_and_unknown_codes() {
        let known = SnmpRequestPdu::with_fields(
            7,
            registry::SNMP_ERROR_STATUS_TOO_BIG,
            0,
            SnmpVarBindList::empty(),
        );
        assert_eq!(
            known.error_status_value(),
            registry::SnmpErrorStatus::new(registry::SNMP_ERROR_STATUS_TOO_BIG)
        );
        assert_eq!(known.error_status_name(), Some("too-big"));
        assert_eq!(
            known.error_status_assignment(),
            registry::SnmpErrorStatusAssignment::Assigned
        );
        assert_eq!(known.error_status_label(), "too-big");
        assert_eq!(
            known.summary_with_label("response"),
            "response request_id=7 error_status=too-big(1) error_index=0 varbinds=0"
        );

        let unknown = SnmpRequestPdu::with_fields(7, 99, 3, SnmpVarBindList::empty());
        assert_eq!(unknown.error_status(), 99);
        assert_eq!(unknown.error_status_name(), None);
        assert_eq!(
            unknown.error_status_assignment(),
            registry::SnmpErrorStatusAssignment::Unknown
        );
        assert_eq!(unknown.error_status_label(), "error-status-99");
        assert_eq!(
            unknown.summary_with_label("response"),
            "response request_id=7 error_status=error-status-99(99) error_index=3 varbinds=0"
        );
        assert_eq!(
            unknown.inspection_fields(),
            [
                ("request_id", "7".to_string()),
                ("error_status", "99".to_string()),
                ("error_status_label", "error-status-99".to_string()),
                ("error_status_assignment", "unknown".to_string()),
                ("error_index", "3".to_string()),
                ("varbind_count", "0".to_string()),
            ]
        );
    }

    #[test]
    fn snmp_getnext_set_pdu_builders_select_tags_and_summary_labels() -> Result<()> {
        let get_next = SnmpPdu::get_next_request(1, SnmpVarBindList::empty())?;
        let set = SnmpPdu::set_request(1, SnmpVarBindList::empty())?;
        let expected_get_next = [
            0xa1, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];
        let expected_set = [
            0xa3, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 1157 Sections
        // 4.1.3 and 4.1.5 plus RFC 3416 Sections 3, 4.2.2, and 4.2.5 for
        // GetNextRequest and SetRequest tags using the common request PDU
        // fields. Walk and set workflows are explicitly outside the crate.
        assert_eq!(
            get_next.tag_number(),
            constants::SNMP_PDU_TAG_GET_NEXT_REQUEST
        );
        assert_eq!(get_next.tag_name(), Some("get-next-request"));
        assert_eq!(get_next.tag_label(), "get-next-request");
        assert_eq!(get_next.compile()?, expected_get_next);
        assert!(get_next.as_get_request()?.is_none());
        assert!(get_next.as_set_request()?.is_none());
        let get_next_request = get_next
            .as_get_next_request()?
            .expect("GetNextRequest fields");
        assert_eq!(get_next_request.request_id(), 1);
        assert_eq!(get_next_request.error_status(), 0);
        assert_eq!(get_next_request.error_index(), 0);
        assert!(get_next_request.varbinds().is_empty());

        assert_eq!(set.tag_number(), constants::SNMP_PDU_TAG_SET_REQUEST);
        assert_eq!(set.tag_name(), Some("set-request"));
        assert_eq!(set.tag_label(), "set-request");
        assert_eq!(set.compile()?, expected_set);
        assert!(set.as_get_request()?.is_none());
        assert!(set.as_get_next_request()?.is_none());
        let set_request = set.as_set_request()?.expect("SetRequest fields");
        assert_eq!(set_request.request_id(), 1);
        assert_eq!(set_request.error_status(), 0);
        assert_eq!(set_request.error_index(), 0);
        assert!(set_request.varbinds().is_empty());

        Ok(())
    }

    #[test]
    fn snmp_getnext_set_pdu_roundtrip_bytes_preserve_explicit_fields() -> Result<()> {
        let cases = [
            (
                SnmpPdu::get_next_request_with_fields(128, 7, 2, SnmpVarBindList::empty())?,
                constants::SNMP_PDU_TAG_GET_NEXT_REQUEST,
                [
                    0xa1, 0x0c, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x07, 0x02, 0x01, 0x02, 0x30,
                    0x00,
                ],
            ),
            (
                SnmpPdu::set_request_with_fields(128, 7, 2, SnmpVarBindList::empty())?,
                constants::SNMP_PDU_TAG_SET_REQUEST,
                [
                    0xa3, 0x0c, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x07, 0x02, 0x01, 0x02, 0x30,
                    0x00,
                ],
            ),
        ];

        for (pdu, tag, expected) in cases {
            assert_eq!(pdu.tag_number(), tag);
            assert_eq!(pdu.compile()?, expected);

            let request = match tag {
                constants::SNMP_PDU_TAG_GET_NEXT_REQUEST => {
                    pdu.as_get_next_request()?.expect("GetNextRequest fields")
                }
                constants::SNMP_PDU_TAG_SET_REQUEST => {
                    pdu.as_set_request()?.expect("SetRequest fields")
                }
                _ => unreachable!("test only covers GetNextRequest and SetRequest"),
            };
            assert_eq!(request.request_id(), 128);
            assert_eq!(request.error_status(), 7);
            assert_eq!(request.error_index(), 2);
            assert!(request.varbinds().is_empty());

            let (decoded, rest) = SnmpPdu::decode(&expected)?;
            assert!(rest.is_empty());
            assert_eq!(decoded.tag_number(), tag);
            assert_eq!(decoded.compile()?, expected);
            let decoded_request = match tag {
                constants::SNMP_PDU_TAG_GET_NEXT_REQUEST => decoded
                    .as_get_next_request()?
                    .expect("decoded GetNextRequest fields"),
                constants::SNMP_PDU_TAG_SET_REQUEST => decoded
                    .as_set_request()?
                    .expect("decoded SetRequest fields"),
                _ => unreachable!("test only covers GetNextRequest and SetRequest"),
            };
            assert_eq!(decoded_request, request);
        }

        Ok(())
    }

    #[test]
    fn snmp_getbulk_pdu_builder_compiles_decodes_and_summarizes() -> Result<()> {
        let varbind =
            crate::protocols::snmp::SnmpVarBind::null(SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?);
        let pdu = SnmpPdu::get_bulk_request(7, 1, 10, SnmpVarBindList::new(vec![varbind.clone()]))?;

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 3416 Sections
        // 3 and 4.2.3 for GetBulkRequest-PDU fields: request-id,
        // non-repeaters, max-repetitions, and VarBindList. This builds only
        // the wire PDU, not a table walk.
        let expected = [
            0xa5, 0x19, 0x02, 0x01, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0a, 0x30, 0x0e, 0x30,
            0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
        ];
        assert_eq!(pdu.tag_number(), constants::SNMP_PDU_TAG_GET_BULK_REQUEST);
        assert_eq!(pdu.tag_name(), Some("get-bulk-request"));
        assert_eq!(pdu.tag_label(), "get-bulk-request");
        assert_eq!(pdu.compile()?, expected);
        assert!(pdu.as_get_request()?.is_none());
        assert!(pdu.as_get_next_request()?.is_none());
        assert!(pdu.as_response()?.is_none());
        assert!(pdu.as_set_request()?.is_none());

        let bulk = pdu.as_get_bulk_request()?.expect("GetBulkRequest fields");
        assert_eq!(bulk.request_id(), 7);
        assert_eq!(bulk.non_repeaters(), 1);
        assert_eq!(bulk.max_repetitions(), 10);
        assert_eq!(bulk.varbinds().as_slice(), &[varbind]);
        assert_eq!(
            bulk.summary(),
            "get-bulk request_id=7 non_repeaters=1 max_repetitions=10 varbinds=1"
        );
        assert_eq!(
            bulk.inspection_fields(),
            [
                ("request_id", "7".to_string()),
                ("non_repeaters", "1".to_string()),
                ("max_repetitions", "10".to_string()),
                ("varbind_count", "1".to_string()),
                ("varbind[0]", "1.3.6.1.2.1.1.3.0=null".to_string()),
            ]
        );

        let (decoded, rest) = SnmpPdu::decode(&expected)?;
        assert!(rest.is_empty());
        assert_eq!(
            decoded
                .as_get_bulk_request()?
                .expect("decoded GetBulkRequest fields"),
            bulk
        );
        assert_eq!(decoded.compile()?, expected);

        Ok(())
    }

    #[test]
    fn snmp_getbulk_pdu_boundary_values_are_preserved() -> Result<()> {
        let pdu = SnmpPdu::get_bulk_request(128, -1, 2_147_483_647, SnmpVarBindList::empty())?;

        let expected = [
            0xa5, 0x0f, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0xff, 0x02, 0x04, 0x7f, 0xff, 0xff,
            0xff, 0x30, 0x00,
        ];
        assert_eq!(pdu.compile()?, expected);

        let bulk = pdu.as_get_bulk_request()?.expect("GetBulkRequest fields");
        assert_eq!(bulk.request_id(), 128);
        assert_eq!(bulk.non_repeaters(), -1);
        assert_eq!(bulk.max_repetitions(), 2_147_483_647);
        assert!(bulk.varbinds().is_empty());

        let (decoded, rest) = SnmpPdu::decode(&expected)?;
        assert!(rest.is_empty());
        assert_eq!(
            decoded
                .as_get_bulk_request()?
                .expect("decoded GetBulkRequest fields"),
            bulk
        );
        assert_eq!(decoded.compile()?, expected);

        Ok(())
    }

    #[test]
    fn snmp_getbulk_pdu_decoded_bytes_round_trip_without_normalizing_integers() -> Result<()> {
        let bytes = [
            0xa5, 0x0d, 0x02, 0x02, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x02, 0x00, 0x01, 0x30,
            0x00,
        ];
        let (decoded, rest) = SnmpPdu::decode(&bytes)?;

        assert!(rest.is_empty());
        let bulk = decoded
            .as_get_bulk_request()?
            .expect("decoded GetBulkRequest fields");
        assert_eq!(bulk.request_id(), 0);
        assert_eq!(bulk.non_repeaters(), 0);
        assert_eq!(bulk.max_repetitions(), 1);
        assert!(bulk.varbinds().is_empty());
        assert_eq!(decoded.compile()?, bytes);

        Ok(())
    }

    #[test]
    fn snmp_advanced_pdus_inform_request_compiles_decodes_and_summarizes() -> Result<()> {
        let varbind =
            crate::protocols::snmp::SnmpVarBind::null(SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?);
        let pdu = SnmpPdu::inform_request(7, SnmpVarBindList::new(vec![varbind.clone()]))?;

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 3416 Sections
        // 3 and 4.2.7 for InformRequest-PDU tag 6 using the common PDU
        // fields. This builds only packet bytes, not delivery confirmation.
        let expected = [
            0xa6, 0x19, 0x02, 0x01, 0x07, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
            0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
        ];
        assert_eq!(pdu.tag_number(), constants::SNMP_PDU_TAG_INFORM_REQUEST);
        assert_eq!(pdu.tag_name(), Some("inform-request"));
        assert_eq!(pdu.tag_label(), "inform-request");
        assert_eq!(pdu.compile()?, expected);
        assert!(pdu.as_get_request()?.is_none());
        assert!(pdu.as_get_bulk_request()?.is_none());
        assert!(pdu.as_snmpv2_trap()?.is_none());
        assert!(pdu.as_report()?.is_none());

        let inform = pdu.as_inform_request()?.expect("InformRequest fields");
        assert_eq!(inform.request_id(), 7);
        assert_eq!(inform.error_status(), 0);
        assert_eq!(inform.error_index(), 0);
        assert_eq!(inform.varbinds().as_slice(), &[varbind]);
        assert_eq!(
            inform.summary_with_label("inform-request"),
            "inform-request request_id=7 error_status=no-error(0) error_index=0 varbinds=1"
        );
        assert_eq!(
            inform.inspection_fields(),
            [
                ("request_id", "7".to_string()),
                ("error_status", "0".to_string()),
                ("error_status_label", "no-error".to_string()),
                ("error_status_assignment", "assigned".to_string()),
                ("error_index", "0".to_string()),
                ("varbind_count", "1".to_string()),
                ("varbind[0]", "1.3.6.1.2.1.1.3.0=null".to_string()),
            ]
        );

        let (decoded, rest) = SnmpPdu::decode(&expected)?;
        assert!(rest.is_empty());
        assert_eq!(
            decoded
                .as_inform_request()?
                .expect("decoded InformRequest fields"),
            inform
        );
        assert_eq!(decoded.compile()?, expected);

        Ok(())
    }

    #[test]
    fn snmp_advanced_pdus_snmpv2_trap_keeps_notification_varbinds_as_fields() -> Result<()> {
        let uptime = crate::protocols::snmp::SnmpVarBind::time_ticks(
            SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?,
            12_345,
        );
        let trap_oid = crate::protocols::snmp::SnmpVarBind::object_identifier(
            SnmpOid::from_dotted("1.3.6.1.6.3.1.1.4.1.0")?,
            SnmpOid::from_dotted("1.3.6.1.6.3.1.1.5.1")?,
        );
        let pdu = SnmpPdu::snmpv2_trap(
            42,
            SnmpVarBindList::new(vec![uptime.clone(), trap_oid.clone()]),
        )?;

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 3416 Sections
        // 3 and 4.2.6 for SNMPv2-Trap-PDU tag 7 using the common PDU fields.
        // The notification object ordering remains a VarBindList byte shape;
        // listener or delivery semantics stay outside this packet primitive.
        let expected = [
            0xa7, 0x34, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x29, 0x30,
            0x0e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43, 0x02, 0x30,
            0x39, 0x30, 0x17, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x04, 0x01,
            0x00, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x05, 0x01,
        ];
        assert_eq!(pdu.tag_number(), constants::SNMP_PDU_TAG_TRAP_V2);
        assert_eq!(pdu.tag_name(), Some("snmpv2-trap"));
        assert_eq!(pdu.tag_label(), "snmpv2-trap");
        assert_eq!(pdu.compile()?, expected);
        assert!(pdu.as_v1_trap()?.is_none());
        assert!(pdu.as_inform_request()?.is_none());
        assert!(pdu.as_report()?.is_none());

        let trap = pdu.as_snmpv2_trap()?.expect("SNMPv2-Trap fields");
        assert_eq!(trap.request_id(), 42);
        assert_eq!(trap.error_status(), 0);
        assert_eq!(trap.error_index(), 0);
        assert_eq!(trap.varbinds().as_slice(), &[uptime, trap_oid]);
        assert_eq!(
            trap.summary_with_label("snmpv2-trap"),
            "snmpv2-trap request_id=42 error_status=no-error(0) error_index=0 varbinds=2"
        );

        let (decoded, rest) = SnmpPdu::decode(&expected)?;
        assert!(rest.is_empty());
        assert_eq!(
            decoded
                .as_snmpv2_trap()?
                .expect("decoded SNMPv2-Trap fields"),
            trap
        );
        assert_eq!(decoded.compile()?, expected);

        Ok(())
    }

    #[test]
    fn snmp_advanced_pdus_report_preserves_fields_without_security_engine() -> Result<()> {
        let pdu = SnmpPdu::report_with_fields(128, 2, 3, SnmpVarBindList::empty())?;

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 3416 Sections
        // 3 and 4.2 notes for Report-PDU tag 8 using the common PDU byte
        // shape, with administrative-framework behavior left outside this
        // helper.
        let expected = [
            0xa8, 0x0c, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x30, 0x00,
        ];
        assert_eq!(pdu.tag_number(), constants::SNMP_PDU_TAG_REPORT);
        assert_eq!(pdu.tag_name(), Some("report"));
        assert_eq!(pdu.tag_label(), "report");
        assert_eq!(pdu.compile()?, expected);
        assert!(pdu.as_response()?.is_none());
        assert!(pdu.as_inform_request()?.is_none());
        assert!(pdu.as_snmpv2_trap()?.is_none());

        let report = pdu.as_report()?.expect("Report fields");
        assert_eq!(report.request_id(), 128);
        assert_eq!(report.error_status(), 2);
        assert_eq!(report.error_index(), 3);
        assert!(report.varbinds().is_empty());
        assert_eq!(
            report.summary_with_label("report"),
            "report request_id=128 error_status=no-such-name(2) error_index=3 varbinds=0"
        );

        let default_report = SnmpPdu::report(9, SnmpVarBindList::empty())?;
        assert_eq!(
            default_report
                .as_report()?
                .expect("default Report fields")
                .summary_with_label("report"),
            "report request_id=9 error_status=no-error(0) error_index=0 varbinds=0"
        );

        let (decoded, rest) = SnmpPdu::decode(&expected)?;
        assert!(rest.is_empty());
        assert_eq!(decoded.as_report()?.expect("decoded Report fields"), report);
        assert_eq!(decoded.compile()?, expected);

        Ok(())
    }

    #[test]
    fn snmp_v1_trap_pdu_builder_compiles_decodes_and_summarizes() -> Result<()> {
        let enterprise = SnmpOid::from_dotted("1.3.6.1.4.1")?;
        let varbind =
            crate::protocols::snmp::SnmpVarBind::null(SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?);
        let pdu = SnmpPdu::v1_trap(
            enterprise.clone(),
            [192, 0, 2, 44],
            6,
            4_321,
            12_345,
            SnmpVarBindList::new(vec![varbind.clone()]),
        )?;

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 1157 Sections
        // 4.1.6 and 5 for SNMPv1 Trap-PDU fields: enterprise, agent address,
        // generic trap, specific trap, timestamp, and VarBindList.
        let expected = [
            0xa4, 0x28, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x40, 0x04, 192, 0, 2, 44, 0x02,
            0x01, 0x06, 0x02, 0x02, 0x10, 0xe1, 0x43, 0x02, 0x30, 0x39, 0x30, 0x0e, 0x30, 0x0c,
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
        ];
        assert_eq!(pdu.tag_number(), constants::SNMP_PDU_TAG_TRAP);
        assert_eq!(pdu.tag_name(), Some("trap"));
        assert_eq!(pdu.tag_label(), "trap");
        assert_eq!(pdu.compile()?, expected);
        assert!(pdu.as_get_request()?.is_none());
        assert!(pdu.as_response()?.is_none());

        let trap = pdu.as_v1_trap()?.expect("Trap fields");
        assert_eq!(trap.enterprise(), &enterprise);
        assert_eq!(trap.agent_address(), [192, 0, 2, 44]);
        assert_eq!(trap.generic_trap(), 6);
        assert_eq!(trap.specific_trap(), 4_321);
        assert_eq!(trap.timestamp(), 12_345);
        assert_eq!(trap.varbinds().as_slice(), &[varbind]);
        assert_eq!(
            trap.summary(),
            "trap enterprise=1.3.6.1.4.1 agent=192.0.2.44 generic=6 specific=4321 timestamp=12345 varbinds=1"
        );
        assert_eq!(
            trap.inspection_fields(),
            [
                ("enterprise", "1.3.6.1.4.1".to_string()),
                ("agent_address", "192.0.2.44".to_string()),
                ("generic_trap", "6".to_string()),
                ("specific_trap", "4321".to_string()),
                ("timestamp", "12345".to_string()),
                ("varbind_count", "1".to_string()),
                ("varbind[0]", "1.3.6.1.2.1.1.3.0=null".to_string()),
            ]
        );

        let (decoded, rest) = SnmpPdu::decode(&expected)?;
        assert!(rest.is_empty());
        assert_eq!(decoded.as_v1_trap()?.expect("decoded fields"), trap);
        assert_eq!(decoded.compile()?, expected);

        Ok(())
    }

    #[test]
    fn snmp_v1_trap_pdu_unknown_trap_codes_are_preserved_as_integers() -> Result<()> {
        let pdu = SnmpPdu::v1_trap(
            SnmpOid::from_dotted("1.3.6.1.4.1")?,
            [198, 51, 100, 10],
            -1,
            300,
            0,
            SnmpVarBindList::empty(),
        )?;

        let expected = [
            0xa4, 0x19, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x40, 0x04, 198, 51, 100, 10,
            0x02, 0x01, 0xff, 0x02, 0x02, 0x01, 0x2c, 0x43, 0x01, 0x00, 0x30, 0x00,
        ];
        assert_eq!(pdu.compile()?, expected);

        let trap = pdu.as_v1_trap()?.expect("Trap fields");
        assert_eq!(trap.agent_address(), [198, 51, 100, 10]);
        assert_eq!(trap.generic_trap(), -1);
        assert_eq!(trap.specific_trap(), 300);
        assert_eq!(trap.timestamp(), 0);
        assert!(trap.varbinds().is_empty());

        let (decoded, rest) = SnmpPdu::decode(&expected)?;
        assert!(rest.is_empty());
        let decoded_trap = decoded.as_v1_trap()?.expect("decoded Trap fields");
        assert_eq!(decoded_trap.generic_trap(), -1);
        assert_eq!(decoded_trap.specific_trap(), 300);
        assert_eq!(decoded.compile()?, expected);

        Ok(())
    }

    #[test]
    fn snmp_v1_trap_pdu_truncated_field_returns_structured_error() -> Result<()> {
        let bytes = [
            0xa4, 0x16, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x40, 0x04, 192, 0, 2, 44, 0x02,
            0x01, 0x06, 0x02, 0x01, 0x2a, 0x43, 0x02, 0x30,
        ];
        let (decoded, rest) = SnmpPdu::decode(&bytes)?;

        assert!(rest.is_empty());
        assert_eq!(
            decoded
                .as_v1_trap()
                .expect_err("truncated TimeTicks must error"),
            CrafterError::buffer_too_short("snmp.ber.application.time_ticks", 4, 3)
        );

        Ok(())
    }
}
