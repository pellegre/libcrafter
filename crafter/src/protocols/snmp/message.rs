//! SNMP message layer.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`; this module models
//! community-based SNMPv1/SNMPv2c packet bytes only. Manager sessions,
//! credentials, retries, walks, and SNMPv3 security behavior belong outside
//! this packet primitive until the corresponding source-backed slices land.

#![cfg_attr(not(test), allow(dead_code))]

use core::any::Any;
use core::fmt;
use core::ops::Div;

use super::{ber, pdu::SnmpPdu};
use crate::error::Result;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

pub(super) const SNMP_VERSION_VALUE_V1: i64 = 0;
pub(super) const SNMP_VERSION_VALUE_V2C: i64 = 1;

const SNMP_MESSAGE_COMMUNITY_CONTEXT: &str = "snmp.message.community";

/// Source-backed SNMP message version value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpVersion {
    /// SNMPv1 message wrapper version value 0.
    V1,
    /// Community-based SNMPv2 message wrapper version value 1.
    V2c,
    /// Well-formed but unsupported or unassigned version value.
    Unknown(i64),
}

impl SnmpVersion {
    pub(super) const fn from_integer(value: i64) -> Self {
        match value {
            SNMP_VERSION_VALUE_V1 => Self::V1,
            SNMP_VERSION_VALUE_V2C => Self::V2c,
            value => Self::Unknown(value),
        }
    }

    /// Raw INTEGER value carried in the SNMP message wrapper.
    pub const fn as_integer(self) -> i64 {
        match self {
            Self::V1 => SNMP_VERSION_VALUE_V1,
            Self::V2c => SNMP_VERSION_VALUE_V2C,
            Self::Unknown(value) => value,
        }
    }

    /// Stable version label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2c => "v2c",
            Self::Unknown(_) => "unknown",
        }
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (value, rest) = ber::decode_integer(bytes)?;
        Ok((Self::from_integer(value), rest))
    }

    pub(super) fn encode(self, out: &mut Vec<u8>) -> Result<()> {
        ber::encode_integer(self.as_integer(), out)
    }
}

impl fmt::Display for SnmpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(value) => write!(f, "unknown({value})"),
            _ => f.write_str(self.label()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SnmpCommunity {
    bytes: Vec<u8>,
}

impl SnmpCommunity {
    pub(super) fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (content, rest) = decode_community_octet_string(bytes)?;
        Ok((Self::new(content.to_vec()), rest))
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_community_octet_string(self.as_bytes(), out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnmpMessageHeader {
    version: SnmpVersion,
    community: SnmpCommunity,
}

impl SnmpMessageHeader {
    fn new(version: SnmpVersion, community: impl Into<Vec<u8>>) -> Self {
        Self {
            version,
            community: SnmpCommunity::new(community),
        }
    }

    const fn version(&self) -> SnmpVersion {
        self.version
    }

    fn community(&self) -> &[u8] {
        self.community.as_bytes()
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (version, rest) = SnmpVersion::decode(bytes)?;
        let (community, rest) = SnmpCommunity::decode(rest)?;

        Ok((Self { version, community }, rest))
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.version.encode(out)?;
        self.community.encode(out)
    }

    pub(super) fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }
}

/// Top-level SNMP packet layer.
///
/// The initial public constructors are limited to source-backed SNMPv1 and
/// community-based SNMPv2 wrappers. The layer composes with [`Packet`] and `/`
/// like every other packet layer and leaves application workflows to generated
/// tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snmp {
    header: SnmpMessageHeader,
    pdu: SnmpPdu,
}

impl Snmp {
    /// Build an SNMPv1 community message carrying one PDU.
    pub fn v1(community: impl Into<Vec<u8>>, pdu: SnmpPdu) -> Self {
        Self::community_message(SnmpVersion::V1, community, pdu)
    }

    /// Build an SNMPv1 GetRequest message with noError/noErrorIndex fields.
    ///
    /// This only builds packet bytes. Polling, retries, and response matching
    /// belong in generated tools outside the crate.
    pub fn v1_get_request(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v1(
            community,
            SnmpPdu::get_request(request_id, varbinds)?,
        ))
    }

    /// Build an SNMPv1 GetNextRequest message with noError/noErrorIndex fields.
    ///
    /// This only builds packet bytes. Walk behavior belongs in generated tools
    /// outside the crate.
    pub fn v1_get_next_request(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v1(
            community,
            SnmpPdu::get_next_request(request_id, varbinds)?,
        ))
    }

    /// Build an SNMPv1 SetRequest message with noError/noErrorIndex fields.
    ///
    /// This only builds packet bytes. Authorization and mutation workflows
    /// belong in generated tools outside the crate.
    pub fn v1_set_request(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v1(
            community,
            SnmpPdu::set_request(request_id, varbinds)?,
        ))
    }

    /// Build an SNMPv1 GetResponse message with noError/noErrorIndex fields.
    pub fn v1_response(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v1(
            community,
            SnmpPdu::response(request_id, varbinds)?,
        ))
    }

    /// Build an SNMPv1 GetResponse message carrying explicit error fields.
    ///
    /// This helper preserves supplied integer values; it does not validate
    /// whether an error status is assigned or whether the index matches an
    /// application-level variable binding.
    pub fn v1_response_error(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        error_status: i64,
        error_index: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v1(
            community,
            SnmpPdu::response_error(request_id, error_status, error_index, varbinds)?,
        ))
    }

    /// Build an SNMPv1 Trap message from source-backed wire fields.
    ///
    /// This only builds packet bytes. Trap listener and notification-service
    /// behavior belongs in generated tools outside the crate.
    pub fn v1_trap(
        community: impl Into<Vec<u8>>,
        enterprise: super::SnmpOid,
        agent_address: [u8; 4],
        generic_trap: i64,
        specific_trap: i64,
        timestamp: u32,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v1(
            community,
            SnmpPdu::v1_trap(
                enterprise,
                agent_address,
                generic_trap,
                specific_trap,
                timestamp,
                varbinds,
            )?,
        ))
    }

    /// Build an SNMPv2c community message carrying one PDU.
    pub fn v2c(community: impl Into<Vec<u8>>, pdu: SnmpPdu) -> Self {
        Self::community_message(SnmpVersion::V2c, community, pdu)
    }

    /// Build an SNMPv2c GetRequest message with noError/noErrorIndex fields.
    ///
    /// This only builds packet bytes. Polling, retries, and response matching
    /// belong in generated tools outside the crate.
    pub fn v2c_get_request(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v2c(
            community,
            SnmpPdu::get_request(request_id, varbinds)?,
        ))
    }

    /// Build an SNMPv2c GetNextRequest message with noError/noErrorIndex fields.
    ///
    /// This only builds packet bytes. Walk behavior belongs in generated tools
    /// outside the crate.
    pub fn v2c_get_next_request(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v2c(
            community,
            SnmpPdu::get_next_request(request_id, varbinds)?,
        ))
    }

    /// Build an SNMPv2c SetRequest message with noError/noErrorIndex fields.
    ///
    /// This only builds packet bytes. Authorization and mutation workflows
    /// belong in generated tools outside the crate.
    pub fn v2c_set_request(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v2c(
            community,
            SnmpPdu::set_request(request_id, varbinds)?,
        ))
    }

    /// Build an SNMPv2c Response message with noError/noErrorIndex fields.
    pub fn v2c_response(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v2c(
            community,
            SnmpPdu::response(request_id, varbinds)?,
        ))
    }

    /// Build an SNMPv2c Response message carrying explicit error fields.
    ///
    /// This helper preserves supplied integer values; it does not validate
    /// whether an error status is assigned or whether the index matches an
    /// application-level variable binding.
    pub fn v2c_response_error(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        error_status: i64,
        error_index: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v2c(
            community,
            SnmpPdu::response_error(request_id, error_status, error_index, varbinds)?,
        ))
    }

    /// Build an SNMPv2c GetBulkRequest message from source-backed wire fields.
    ///
    /// This only builds packet bytes. Table walking, retry behavior, and
    /// response interpretation belong in generated tools outside the crate.
    pub fn v2c_get_bulk_request(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        non_repeaters: i64,
        max_repetitions: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v2c(
            community,
            SnmpPdu::get_bulk_request(request_id, non_repeaters, max_repetitions, varbinds)?,
        ))
    }

    /// Build an SNMPv2c InformRequest message with noError/noErrorIndex fields.
    ///
    /// This only builds packet bytes. Delivery confirmation, retransmission,
    /// and notification workflow behavior belong in generated tools outside
    /// the crate.
    pub fn v2c_inform_request(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v2c(
            community,
            SnmpPdu::inform_request(request_id, varbinds)?,
        ))
    }

    /// Build an SNMPv2c Trap message with noError/noErrorIndex fields.
    ///
    /// This only builds packet bytes. Trap listener and notification-service
    /// behavior belongs in generated tools outside the crate.
    pub fn v2c_snmpv2_trap(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v2c(
            community,
            SnmpPdu::snmpv2_trap(request_id, varbinds)?,
        ))
    }

    /// Build an SNMPv2c Report message with noError/noErrorIndex fields.
    ///
    /// This only builds packet bytes. SNMPv3 security validation and engine
    /// behavior belong in later packet validation or generated tools, not in
    /// this message helper.
    pub fn v2c_report(
        community: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::v2c(community, SnmpPdu::report(request_id, varbinds)?))
    }

    fn community_message(
        version: SnmpVersion,
        community: impl Into<Vec<u8>>,
        pdu: SnmpPdu,
    ) -> Self {
        Self {
            header: SnmpMessageHeader::new(version, community),
            pdu,
        }
    }

    /// Message wrapper version.
    pub const fn version(&self) -> SnmpVersion {
        self.header.version()
    }

    /// Raw message wrapper version INTEGER.
    pub const fn version_value(&self) -> i64 {
        self.version().as_integer()
    }

    /// Stable message wrapper version label.
    pub const fn version_label(&self) -> &'static str {
        self.version().label()
    }

    /// Raw community OCTET STRING bytes.
    ///
    /// Summaries and inspection output report only the byte length; callers can
    /// opt in to inspecting the bytes through this accessor.
    pub fn community(&self) -> &[u8] {
        self.header.community()
    }

    /// PDU body carried by this message.
    pub const fn pdu(&self) -> &SnmpPdu {
        &self.pdu
    }

    /// Return a copy of this message with an explicit version INTEGER value.
    pub fn with_version(mut self, version: SnmpVersion) -> Self {
        self.header.version = version;
        self
    }

    /// Return a copy of this message with explicit community OCTET STRING bytes.
    pub fn with_community(mut self, community: impl Into<Vec<u8>>) -> Self {
        self.header.community = SnmpCommunity::new(community);
        self
    }

    /// Return a copy of this message carrying an explicit PDU.
    pub fn with_pdu(mut self, pdu: SnmpPdu) -> Self {
        self.pdu = pdu;
        self
    }

    /// Mutable PDU body carried by this message.
    pub fn pdu_mut(&mut self) -> &mut SnmpPdu {
        &mut self.pdu
    }

    /// Consume the message and return its PDU body.
    pub fn into_pdu(self) -> SnmpPdu {
        self.pdu
    }

    /// Encoded SNMP message length in octets.
    pub fn encoded_len(&self) -> usize {
        encoded_tlv_len(self.encoded_content_len())
    }

    /// Encode this SNMP message into BER bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut content = Vec::with_capacity(self.encoded_content_len());
        self.header.encode(&mut content)?;
        self.pdu.encode(&mut content)?;
        ber::encode_sequence(&content, out)
    }

    /// Decode one complete SNMP message from BER bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let content = ber::decode_sequence_exact(bytes)?;
        let (header, rest) = SnmpMessageHeader::decode(content)?;
        let (pdu, rest) = SnmpPdu::decode(rest)?;
        ber::require_sequence_exact(rest)?;

        Ok(Self { header, pdu })
    }

    /// Return this SNMP message encoded as BER bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile this SNMP message into BER bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.to_bytes()
    }

    fn encoded_content_len(&self) -> usize {
        encoded_integer_tlv_len(self.version_value())
            + encoded_tlv_len(self.community().len())
            + encoded_pdu_len(&self.pdu)
    }
}

impl Layer for Snmp {
    fn name(&self) -> &'static str {
        "Snmp"
    }

    fn summary(&self) -> String {
        format!(
            "Snmp(version={}, community_len={}, pdu={})",
            self.version(),
            self.community().len(),
            self.pdu.summary()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("version", self.version().to_string()),
            ("version_value", self.version_value().to_string()),
            ("community_len", self.community().len().to_string()),
            ("message_len", self.encoded_len().to_string()),
        ];
        fields.extend(self.pdu.inspection_fields());
        fields
    }

    fn encoded_len(&self) -> usize {
        Snmp::encoded_len(self)
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.encode(out)
    }

    fn clone_layer(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl<R> Div<R> for Snmp
where
    R: IntoPacket,
{
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

fn decode_community_octet_string(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    let (tag, rest) = ber::decode_identifier(bytes)?;
    if tag != ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_OCTET_STRING) {
        return Err(ber::invalid_ber_field(
            SNMP_MESSAGE_COMMUNITY_CONTEXT,
            "expected universal primitive OCTET STRING",
        ));
    }

    let (length, rest) = ber::decode_length(rest)?;
    if rest.len() < length {
        let prefix_len = bytes.len() - rest.len();
        let required = prefix_len.checked_add(length).ok_or_else(|| {
            ber::invalid_ber_field(
                SNMP_MESSAGE_COMMUNITY_CONTEXT,
                "community length exceeds supported size",
            )
        })?;
        return Err(ber::truncated_ber(
            SNMP_MESSAGE_COMMUNITY_CONTEXT,
            required,
            bytes.len(),
        ));
    }

    Ok(rest.split_at(length))
}

fn encode_community_octet_string(bytes: &[u8], out: &mut Vec<u8>) -> Result<()> {
    ber::encode_identifier(
        ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_OCTET_STRING),
        out,
    )?;
    ber::encode_length(bytes.len(), out)?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn encoded_pdu_len(pdu: &SnmpPdu) -> usize {
    pdu.raw_tlv_bytes().map(<[u8]>::len).unwrap_or_else(|| {
        ber::BER_IDENTIFIER_LEN + encoded_length_len(pdu.effective_length()) + pdu.body().len()
    })
}

fn encoded_integer_tlv_len(value: i64) -> usize {
    encoded_tlv_len(encoded_integer_content_len(value))
}

fn encoded_integer_content_len(value: i64) -> usize {
    let bytes = value.to_be_bytes();
    let mut start = 0;

    if value >= 0 {
        while start < bytes.len() - 1 && bytes[start] == 0x00 && bytes[start + 1] & 0x80 == 0 {
            start += 1;
        }
    } else {
        while start < bytes.len() - 1 && bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0 {
            start += 1;
        }
    }

    bytes.len() - start
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::snmp::{SnmpOid, SnmpVarBind, SnmpVarBindList};
    use crate::protocols::transport::Udp;
    use crate::Layer;

    #[test]
    fn snmp_version_labels_source_backed_values() {
        // Source-backed: docs/snmp-rfc-manifest.md records RFC 1157 Section
        // 4.1.2 for SNMPv1 value 0 and RFC 1901 Section 3 for SNMPv2c value 1.
        let cases = [
            (SNMP_VERSION_VALUE_V1, SnmpVersion::V1, "v1"),
            (SNMP_VERSION_VALUE_V2C, SnmpVersion::V2c, "v2c"),
        ];

        for (integer, version, label) in cases {
            assert_eq!(SnmpVersion::from_integer(integer), version);
            assert_eq!(version.as_integer(), integer);
            assert_eq!(version.label(), label);
            assert_eq!(version.to_string(), label);
        }

        let unknown = SnmpVersion::from_integer(3);
        assert_eq!(unknown.label(), "unknown");
        assert_eq!(unknown.to_string(), "unknown(3)");
    }

    #[test]
    fn snmp_version_unknown_version_preservation() -> Result<()> {
        let mut bytes =
            SnmpMessageHeader::new(SnmpVersion::from_integer(3), b"example".to_vec()).to_bytes()?;
        bytes.extend_from_slice(&[0xa0, 0x00]);

        let (decoded, rest) = SnmpMessageHeader::decode(&bytes)?;
        assert_eq!(decoded.version(), SnmpVersion::Unknown(3));
        assert_eq!(decoded.version().as_integer(), 3);
        assert_eq!(decoded.version().label(), "unknown");
        assert_eq!(decoded.community(), b"example");
        assert_eq!(rest, &[0xa0, 0x00]);

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded)?;
        assert_eq!(reencoded, &bytes[..bytes.len() - rest.len()]);

        let negative = SnmpVersion::from_integer(-1);
        assert_eq!(negative, SnmpVersion::Unknown(-1));
        assert_eq!(negative.as_integer(), -1);

        Ok(())
    }

    #[test]
    fn snmp_version_empty_community_strings() -> Result<()> {
        let header = SnmpMessageHeader::new(SnmpVersion::V1, Vec::<u8>::new());
        let mut bytes = header.to_bytes()?;
        bytes.extend_from_slice(&[0xa0, 0x00]);

        assert_eq!(header.community(), b"");
        assert_eq!(&bytes[..bytes.len() - 2], &[0x02, 0x01, 0x00, 0x04, 0x00]);

        let (decoded, rest) = SnmpMessageHeader::decode(&bytes)?;
        assert_eq!(decoded.version(), SnmpVersion::V1);
        assert_eq!(decoded.community(), b"");
        assert_eq!(rest, &[0xa0, 0x00]);

        Ok(())
    }

    #[test]
    fn snmp_version_non_utf8_community_bytes() -> Result<()> {
        let community = [0x00, 0xff, 0x80, b'a'];
        let header = SnmpMessageHeader::new(SnmpVersion::V2c, community.to_vec());
        let bytes = header.to_bytes()?;

        assert_eq!(
            bytes,
            [0x02, 0x01, 0x01, 0x04, 0x04, 0x00, 0xff, 0x80, b'a']
        );

        let (decoded, rest) = SnmpMessageHeader::decode(&bytes)?;
        assert_eq!(decoded.version(), SnmpVersion::V2c);
        assert_eq!(decoded.community(), &community);
        assert!(rest.is_empty());

        Ok(())
    }

    #[test]
    fn snmp_layer_v1_v2c_messages_compile_as_packet_layers() -> Result<()> {
        let v1 = Snmp::v1(
            b"public".to_vec(),
            SnmpPdu::get_request(1, crate::protocols::snmp::SnmpVarBindList::empty())?,
        );
        assert_eq!(v1.version(), SnmpVersion::V1);
        assert_eq!(v1.version_value(), 0);
        assert_eq!(v1.community(), b"public");

        let v2c = Snmp::v2c(
            b"public".to_vec(),
            SnmpPdu::get_request(1, crate::protocols::snmp::SnmpVarBindList::empty())?,
        );
        let expected = [
            0x30, 0x18, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
            0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];
        assert_eq!(v2c.encoded_len(), expected.len());
        assert_eq!(v2c.compile()?, expected);

        let packet = Udp::new().sport(53000).dport(161) / v2c.clone();
        assert_eq!(packet.encoded_len(), 8 + v2c.encoded_len());
        assert!(packet.layer::<Snmp>().is_some());
        assert!(packet.compile()?.as_bytes().ends_with(&expected));

        Ok(())
    }

    #[test]
    fn snmp_v1_message_builders_emit_source_backed_request_response_and_trap_bytes() -> Result<()> {
        let request = Snmp::v1_get_request(b"public".to_vec(), 1, SnmpVarBindList::empty())?;

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 1157 Sections
        // 4.1.2 and 4.1.3 for the SNMPv1 Message wrapper and GetRequest-PDU.
        assert_eq!(
            request.compile()?,
            [
                0x30, 0x18, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
                0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
            ]
        );

        let response = Snmp::v1_response([0x00, 0xff], 128, SnmpVarBindList::empty())?;

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 1157 Sections
        // 4.1.2 and 4.1.4 for the SNMPv1 Message wrapper and GetResponse-PDU.
        assert_eq!(
            response.compile()?,
            [
                0x30, 0x15, 0x02, 0x01, 0x00, 0x04, 0x02, 0x00, 0xff, 0xa2, 0x0c, 0x02, 0x02, 0x00,
                0x80, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
            ]
        );

        let trap_varbind = SnmpVarBind::null(SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?);
        let trap = Snmp::v1_trap(
            b"public".to_vec(),
            SnmpOid::from_dotted("1.3.6.1.4.1")?,
            [192, 0, 2, 44],
            6,
            4_321,
            12_345,
            SnmpVarBindList::new(vec![trap_varbind]),
        )?;

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 1157 Sections
        // 4.1.2, 4.1.6, and 5 for the SNMPv1 Message wrapper and Trap-PDU.
        assert_eq!(
            trap.compile()?,
            [
                0x30, 0x35, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa4,
                0x28, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x40, 0x04, 192, 0, 2, 44, 0x02,
                0x01, 0x06, 0x02, 0x02, 0x10, 0xe1, 0x43, 0x02, 0x30, 0x39, 0x30, 0x0e, 0x30, 0x0c,
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
            ]
        );

        Ok(())
    }

    #[test]
    fn snmp_v1_message_get_next_set_and_error_response_builders_select_v1_pdu_tags() -> Result<()> {
        let get_next = Snmp::v1_get_next_request(b"public".to_vec(), 2, SnmpVarBindList::empty())?;
        let set = Snmp::v1_set_request(b"public".to_vec(), 3, SnmpVarBindList::empty())?;
        let error_response = Snmp::v1_response_error(
            b"public".to_vec(),
            4,
            super::super::registry::SNMP_ERROR_STATUS_NO_SUCH_NAME,
            1,
            SnmpVarBindList::empty(),
        )?;

        assert_eq!(get_next.version(), SnmpVersion::V1);
        assert_eq!(get_next.pdu().tag_number(), SnmpPdu::TAG_GET_NEXT_REQUEST);
        assert_eq!(set.pdu().tag_number(), SnmpPdu::TAG_SET_REQUEST);
        assert_eq!(error_response.pdu().tag_number(), SnmpPdu::TAG_RESPONSE);
        assert_eq!(
            error_response
                .pdu()
                .as_response()?
                .expect("response fields")
                .error_status(),
            super::super::registry::SNMP_ERROR_STATUS_NO_SUCH_NAME,
        );

        Ok(())
    }

    #[test]
    fn snmp_v1_message_decode_round_trips_header_and_pdu_without_public_decode() -> Result<()> {
        let snmp = Snmp::v1_get_request([0x00, 0xff, b'a'], 7, SnmpVarBindList::empty())?;
        let bytes = snmp.compile()?;

        let content = ber::decode_sequence_exact(&bytes)?;
        let (header, rest) = SnmpMessageHeader::decode(content)?;
        let (pdu, rest) = SnmpPdu::decode(rest)?;
        ber::require_sequence_exact(rest)?;

        assert_eq!(header.version(), SnmpVersion::V1);
        assert_eq!(header.community(), &[0x00, 0xff, b'a']);
        assert_eq!(pdu.tag_number(), SnmpPdu::TAG_GET_REQUEST);
        assert_eq!(
            pdu.as_get_request()?
                .expect("GetRequest fields")
                .request_id(),
            7
        );
        assert_eq!(pdu.compile()?, snmp.pdu().compile()?);

        Ok(())
    }

    #[test]
    fn snmp_message_decode_v1_raw_bytes_to_typed_layer() -> Result<()> {
        let bytes = [
            0x30, 0x18, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
            0x0b, 0x02, 0x01, 0x07, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];

        let decoded = Snmp::decode(&bytes)?;
        let request = decoded.pdu().as_get_request()?.expect("GetRequest fields");

        assert_eq!(decoded.version(), SnmpVersion::V1);
        assert_eq!(decoded.community(), b"public");
        assert_eq!(decoded.pdu().tag_number(), SnmpPdu::TAG_GET_REQUEST);
        assert_eq!(request.request_id(), 7);
        assert_eq!(request.error_status(), 0);
        assert_eq!(request.error_index(), 0);
        assert!(request.varbinds().is_empty());
        assert_eq!(decoded.compile()?, bytes);

        Ok(())
    }

    #[test]
    fn snmp_message_decode_v2c_raw_bytes_to_typed_layer() -> Result<()> {
        let bytes = [
            0x30, 0x18, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa5,
            0x0b, 0x02, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0a, 0x30, 0x00,
        ];

        let decoded = Snmp::decode(&bytes)?;
        let bulk = decoded
            .pdu()
            .as_get_bulk_request()?
            .expect("GetBulk fields");

        assert_eq!(decoded.version(), SnmpVersion::V2c);
        assert_eq!(decoded.community(), b"public");
        assert_eq!(decoded.pdu().tag_number(), SnmpPdu::TAG_GET_BULK_REQUEST);
        assert_eq!(bulk.request_id(), 4);
        assert_eq!(bulk.non_repeaters(), 1);
        assert_eq!(bulk.max_repetitions(), 10);
        assert!(bulk.varbinds().is_empty());
        assert_eq!(decoded.compile()?, bytes);

        Ok(())
    }

    #[test]
    fn snmp_message_decode_preserves_unknown_version_and_unknown_pdu() -> Result<()> {
        let bytes = [
            0x30, 0x0b, 0x02, 0x01, 0x03, 0x04, 0x01, b'x', 0xa9, 0x03, 0x02, 0x01, 0x05,
        ];

        let decoded = Snmp::decode(&bytes)?;
        let unknown = decoded.pdu().as_unknown().expect("unknown PDU");

        assert_eq!(decoded.version(), SnmpVersion::Unknown(3));
        assert_eq!(decoded.version_value(), 3);
        assert_eq!(decoded.community(), b"x");
        assert_eq!(unknown.tag_number(), 9);
        assert!(unknown.is_constructed());
        assert_eq!(unknown.body(), &[0x02, 0x01, 0x05]);
        assert_eq!(unknown.raw_tlv_bytes(), Some(&bytes[8..]));
        assert_eq!(decoded.compile()?, bytes);

        Ok(())
    }

    #[test]
    fn snmp_message_decode_rejects_non_pdu_tlv() {
        let bytes = [0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x00, 0x30, 0x00];
        let error = Snmp::decode(&bytes).expect_err("non-PDU TLV");

        assert_eq!(
            error,
            crate::error::CrafterError::invalid_field_value(
                "snmp.pdu",
                "expected context-specific PDU tag"
            )
        );
    }

    #[test]
    fn snmp_v1_message_override_setters_preserve_explicit_wire_choices() -> Result<()> {
        let malformed_pdu = SnmpPdu::get_request(1, SnmpVarBindList::empty())?.length(0);
        let snmp = Snmp::v1_get_request(b"public".to_vec(), 99, SnmpVarBindList::empty())?
            .with_version(SnmpVersion::Unknown(3))
            .with_community([0xff])
            .with_pdu(malformed_pdu);

        assert_eq!(snmp.version(), SnmpVersion::Unknown(3));
        assert_eq!(snmp.community(), &[0xff]);
        assert_eq!(snmp.pdu().explicit_length(), Some(0));
        assert_eq!(
            snmp.compile()?,
            [
                0x30, 0x13, 0x02, 0x01, 0x03, 0x04, 0x01, 0xff, 0xa0, 0x00, 0x02, 0x01, 0x01, 0x02,
                0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
            ]
        );

        Ok(())
    }

    #[test]
    fn snmp_v2c_message_request_response_builders_emit_source_backed_wrappers() -> Result<()> {
        let request = Snmp::v2c_get_request(b"public".to_vec(), 1, SnmpVarBindList::empty())?;

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 1901 Section
        // 3 for the SNMPv2c Message wrapper and RFC 3416 Sections 3 and 4.2.1
        // for the GetRequest-PDU.
        assert_eq!(
            request.compile()?,
            [
                0x30, 0x18, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
                0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
            ]
        );

        let response = Snmp::v2c_response(b"public".to_vec(), 128, SnmpVarBindList::empty())?;

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 1901 Section
        // 3 for the SNMPv2c Message wrapper and RFC 3416 Sections 3 and 4.2.2
        // for the Response-PDU.
        assert_eq!(
            response.compile()?,
            [
                0x30, 0x19, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa2,
                0x0c, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
            ]
        );

        let error_response = Snmp::v2c_response_error(
            b"public".to_vec(),
            129,
            super::super::registry::SNMP_ERROR_STATUS_GEN_ERR,
            2,
            SnmpVarBindList::empty(),
        )?;

        assert_eq!(request.version(), SnmpVersion::V2c);
        assert_eq!(request.pdu().tag_number(), SnmpPdu::TAG_GET_REQUEST);
        assert_eq!(response.pdu().tag_number(), SnmpPdu::TAG_RESPONSE);
        assert_eq!(
            error_response
                .pdu()
                .as_response()?
                .expect("response fields")
                .error_status(),
            super::super::registry::SNMP_ERROR_STATUS_GEN_ERR,
        );

        Ok(())
    }

    #[test]
    fn snmp_v2c_message_request_set_bulk_inform_trap_report_builders_select_tags() -> Result<()> {
        let get_next = Snmp::v2c_get_next_request(b"public".to_vec(), 2, SnmpVarBindList::empty())?;
        let set = Snmp::v2c_set_request(b"public".to_vec(), 3, SnmpVarBindList::empty())?;
        let bulk =
            Snmp::v2c_get_bulk_request(b"public".to_vec(), 4, 1, 10, SnmpVarBindList::empty())?;
        let inform = Snmp::v2c_inform_request(b"public".to_vec(), 5, SnmpVarBindList::empty())?;
        let trap = Snmp::v2c_snmpv2_trap(b"public".to_vec(), 6, SnmpVarBindList::empty())?;
        let report = Snmp::v2c_report(b"public".to_vec(), 7, SnmpVarBindList::empty())?;

        assert_eq!(get_next.version(), SnmpVersion::V2c);
        assert_eq!(get_next.pdu().tag_number(), SnmpPdu::TAG_GET_NEXT_REQUEST);
        assert_eq!(set.pdu().tag_number(), SnmpPdu::TAG_SET_REQUEST);
        assert_eq!(bulk.pdu().tag_number(), SnmpPdu::TAG_GET_BULK_REQUEST);
        assert_eq!(inform.pdu().tag_number(), SnmpPdu::TAG_INFORM_REQUEST);
        assert_eq!(trap.pdu().tag_number(), SnmpPdu::TAG_TRAP_V2);
        assert_eq!(report.pdu().tag_number(), SnmpPdu::TAG_REPORT);

        assert_eq!(
            bulk.compile()?,
            [
                0x30, 0x18, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa5,
                0x0b, 0x02, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0a, 0x30, 0x00,
            ]
        );
        assert!(inform.summary().contains("pdu_type=inform-request"));
        assert!(trap.summary().contains("pdu_type=snmpv2-trap"));
        assert!(report.summary().contains("pdu_type=report"));

        Ok(())
    }

    #[test]
    fn snmp_v2c_message_preserves_raw_community_bytes_and_unknown_version_override() -> Result<()> {
        let community = [0x00, 0xff, 0x80, b'a'];
        let snmp = Snmp::v2c_get_bulk_request(community, 7, 1, 10, SnmpVarBindList::empty())?
            .with_version(SnmpVersion::Unknown(3));

        assert_eq!(snmp.version(), SnmpVersion::Unknown(3));
        assert_eq!(snmp.community(), &community);
        assert_eq!(
            snmp.compile()?,
            [
                0x30, 0x16, 0x02, 0x01, 0x03, 0x04, 0x04, 0x00, 0xff, 0x80, b'a', 0xa5, 0x0b, 0x02,
                0x01, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0a, 0x30, 0x00,
            ]
        );

        let bytes = snmp.compile()?;
        let content = ber::decode_sequence_exact(&bytes)?;
        let (header, rest) = SnmpMessageHeader::decode(content)?;
        let (pdu, rest) = SnmpPdu::decode(rest)?;
        ber::require_sequence_exact(rest)?;

        assert_eq!(header.version(), SnmpVersion::Unknown(3));
        assert_eq!(header.community(), &community);
        assert_eq!(pdu.tag_number(), SnmpPdu::TAG_GET_BULK_REQUEST);

        Ok(())
    }

    #[test]
    fn snmp_layer_summary_and_inspection_keep_pdu_fields_visible() -> Result<()> {
        let snmp = Snmp::v2c(
            b"private".to_vec(),
            SnmpPdu::response_error(128, 2, 3, crate::protocols::snmp::SnmpVarBindList::empty())?,
        );

        let summary = snmp.summary();
        assert!(summary.contains("version=v2c"));
        assert!(summary.contains("community_len=7"));
        assert!(summary.contains("pdu_type=response"));
        assert!(!summary.contains("private"));

        let fields = snmp.inspection_fields();
        assert!(fields.contains(&("version", "v2c".to_string())));
        assert!(fields.contains(&("version_value", "1".to_string())));
        assert!(fields.contains(&("community_len", "7".to_string())));
        assert!(fields.contains(&("pdu_type", "response".to_string())));
        assert!(fields.contains(&("request_id", "128".to_string())));
        assert!(!fields.iter().any(|(_, value)| value == "private"));

        Ok(())
    }

    #[test]
    fn snmp_layer_clone_downcast_and_mutable_accessors_work() -> Result<()> {
        let snmp = Snmp::v2c(
            b"public".to_vec(),
            SnmpPdu::get_request(7, crate::protocols::snmp::SnmpVarBindList::empty())?,
        );
        let mut boxed: Box<dyn Layer> = Box::new(snmp.clone());

        assert!(boxed.as_any().downcast_ref::<Snmp>().is_some());
        let pdu = boxed
            .as_any_mut()
            .downcast_mut::<Snmp>()
            .expect("boxed SNMP")
            .pdu_mut();
        *pdu = pdu.clone().length(0);
        assert_eq!(pdu.explicit_length(), Some(0));

        let cloned = boxed.clone_layer();
        assert!(cloned.as_any().downcast_ref::<Snmp>().is_some());
        let owned = cloned
            .into_any()
            .downcast::<Snmp>()
            .expect("owned SNMP downcast");
        assert_eq!(owned.version(), SnmpVersion::V2c);

        Ok(())
    }

    #[test]
    fn snmp_layer_prelude_exports_layer_surface() -> crate::Result<()> {
        use crate::prelude::*;

        let pdu = SnmpPdu::get_request(9, SnmpVarBindList::empty())?;
        let packet = Packet::from_layer(Snmp::v2c(b"public".to_vec(), pdu));

        assert!(packet.layer::<Snmp>().is_some());
        assert!(packet.summary().contains("Snmp(version=v2c"));

        Ok(())
    }
}
