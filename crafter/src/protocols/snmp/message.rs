//! SNMP message layer.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`; this module models
//! community-based SNMPv1/SNMPv2c packet bytes and the SNMPv3 top-level
//! message wrapper. Manager sessions, credentials, retries, walks, and SNMPv3
//! security behavior belong outside this packet primitive.

#![cfg_attr(not(test), allow(dead_code))]

use core::any::Any;
use core::fmt;
use core::ops::Div;

use super::{ber, pdu::SnmpPdu, registry};
use crate::error::Result;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

pub(super) const SNMP_VERSION_VALUE_V1: i64 = 0;
pub(super) const SNMP_VERSION_VALUE_V2C: i64 = 1;
pub(super) const SNMP_VERSION_VALUE_V3: i64 = 3;

const SNMP_MESSAGE_COMMUNITY_CONTEXT: &str = "snmp.message.community";
const SNMP_V3_HEADER_DATA_CONTEXT: &str = "snmp.v3.header_data";
const SNMP_V3_FLAGS_CONTEXT: &str = "snmp.v3.flags";
const SNMP_V3_SECURITY_PARAMETERS_CONTEXT: &str = "snmp.v3.security_parameters";
const SNMP_V3_SCOPED_DATA_CONTEXT: &str = "snmp.v3.scoped_data";
const SNMP_V3_SCOPED_PDU_CONTEXT: &str = "snmp.v3.scoped_pdu";
const SNMP_V3_CONTEXT_ENGINE_ID_CONTEXT: &str = "snmp.v3.context_engine_id";
const SNMP_V3_CONTEXT_NAME_CONTEXT: &str = "snmp.v3.context_name";
const SNMP_USM_SECURITY_PARAMETERS_CONTEXT: &str = "snmp.usm.security_parameters";
const SNMP_USM_ENGINE_ID_CONTEXT: &str = "snmp.usm.engine_id";
const SNMP_USM_USER_NAME_CONTEXT: &str = "snmp.usm.user_name";
const SNMP_USM_AUTHENTICATION_PARAMETERS_CONTEXT: &str = "snmp.usm.authentication_parameters";
const SNMP_USM_PRIVACY_PARAMETERS_CONTEXT: &str = "snmp.usm.privacy_parameters";

/// Source-backed SNMP message version value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpVersion {
    /// SNMPv1 message wrapper version value 0.
    V1,
    /// Community-based SNMPv2 message wrapper version value 1.
    V2c,
    /// SNMPv3 message wrapper version value 3.
    V3,
    /// Well-formed but unsupported or unassigned version value.
    Unknown(i64),
}

impl SnmpVersion {
    pub(super) const fn from_integer(value: i64) -> Self {
        match value {
            SNMP_VERSION_VALUE_V1 => Self::V1,
            SNMP_VERSION_VALUE_V2C => Self::V2c,
            SNMP_VERSION_VALUE_V3 => Self::V3,
            value => Self::Unknown(value),
        }
    }

    /// Raw INTEGER value carried in the SNMP message wrapper.
    pub const fn as_integer(self) -> i64 {
        match self {
            Self::V1 => SNMP_VERSION_VALUE_V1,
            Self::V2c => SNMP_VERSION_VALUE_V2C,
            Self::V3 => SNMP_VERSION_VALUE_V3,
            Self::Unknown(value) => value,
        }
    }

    /// Stable version label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2c => "v2c",
            Self::V3 => "v3",
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum SnmpMessageData {
    Community {
        header: SnmpMessageHeader,
        pdu: SnmpPdu,
    },
    V3(SnmpV3Message),
}

/// RFC 3412 SNMPv3 `HeaderData` global message fields.
///
/// These are wire fields only. The packet layer preserves caller-supplied
/// values and unknown security-model numbers without applying session policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpV3GlobalData {
    msg_id: i64,
    max_size: i64,
    flags: Vec<u8>,
    security_model: i64,
}

impl SnmpV3GlobalData {
    /// Build SNMPv3 global data from explicit wire values.
    pub fn new(msg_id: i64, max_size: i64, flags: impl Into<Vec<u8>>, security_model: i64) -> Self {
        Self {
            msg_id,
            max_size,
            flags: flags.into(),
            security_model,
        }
    }

    /// Return a copy with an explicit `msgID` INTEGER.
    pub fn with_msg_id(mut self, msg_id: i64) -> Self {
        self.msg_id = msg_id;
        self
    }

    /// Return a copy with an explicit `msgMaxSize` INTEGER.
    pub fn with_max_size(mut self, max_size: i64) -> Self {
        self.max_size = max_size;
        self
    }

    /// Return a copy with explicit raw `msgFlags` OCTET STRING bytes.
    pub fn with_flags(mut self, flags: impl Into<Vec<u8>>) -> Self {
        self.flags = flags.into();
        self
    }

    /// Return a copy with an explicit `msgSecurityModel` INTEGER.
    pub fn with_security_model(mut self, security_model: i64) -> Self {
        self.security_model = security_model;
        self
    }

    /// RFC 3412 `msgID` INTEGER value.
    pub const fn msg_id(&self) -> i64 {
        self.msg_id
    }

    /// RFC 3412 `msgMaxSize` INTEGER value.
    pub const fn max_size(&self) -> i64 {
        self.max_size
    }

    /// Raw RFC 3412 `msgFlags` OCTET STRING bytes.
    pub fn flags(&self) -> &[u8] {
        &self.flags
    }

    /// Typed view of the first `msgFlags` octet.
    pub fn flags_value(&self) -> registry::SnmpV3Flags {
        registry::SnmpV3Flags::from_octets(&self.flags)
    }

    /// RFC 3412 `msgSecurityModel` INTEGER value.
    pub const fn security_model(&self) -> i64 {
        self.security_model
    }

    /// Typed security-model wrapper for the INTEGER value.
    pub const fn security_model_value(&self) -> registry::SnmpSecurityModel {
        registry::SnmpSecurityModel::new(self.security_model)
    }

    /// Source-backed security-model name, when assigned or reserved.
    pub const fn security_model_name(&self) -> Option<&'static str> {
        registry::snmp_security_model_name(self.security_model)
    }

    /// Source-backed assignment status for the security-model value.
    pub const fn security_model_status(&self) -> registry::SnmpSecurityModelStatus {
        registry::snmp_security_model_status(self.security_model)
    }

    /// Stable security-model label that preserves unassigned values.
    pub fn security_model_label(&self) -> String {
        registry::snmp_security_model_label(self.security_model)
    }

    /// Decode one SNMPv3 `HeaderData` SEQUENCE.
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (header_content, rest) = ber::decode_sequence(bytes)?;
        let (msg_id, header_rest) = ber::decode_integer(header_content)?;
        let (max_size, header_rest) = ber::decode_integer(header_rest)?;
        let (flags, header_rest) = decode_octet_string_tlv(
            header_rest,
            SNMP_V3_FLAGS_CONTEXT,
            "expected universal primitive OCTET STRING for msgFlags",
            "msgFlags length exceeds supported size",
        )?;
        let (security_model, header_rest) = ber::decode_integer(header_rest)?;
        if !header_rest.is_empty() {
            return Err(ber::invalid_ber_field(
                SNMP_V3_HEADER_DATA_CONTEXT,
                "trailing bytes after HeaderData fields",
            ));
        }

        Ok((
            Self::new(msg_id, max_size, flags.to_vec(), security_model),
            rest,
        ))
    }

    /// Encode this SNMPv3 `HeaderData` SEQUENCE.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut content = Vec::with_capacity(self.encoded_content_len());
        ber::encode_integer(self.msg_id, &mut content)?;
        ber::encode_integer(self.max_size, &mut content)?;
        encode_octet_string_tlv(&self.flags, &mut content)?;
        ber::encode_integer(self.security_model, &mut content)?;
        ber::encode_sequence(&content, out)
    }

    /// Return this global data encoded as BER bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile this global data into BER bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.to_bytes()
    }

    /// Encoded SNMPv3 `HeaderData` length in octets.
    pub fn encoded_len(&self) -> usize {
        encoded_tlv_len(self.encoded_content_len())
    }

    fn encoded_content_len(&self) -> usize {
        encoded_integer_tlv_len(self.msg_id)
            + encoded_integer_tlv_len(self.max_size)
            + encoded_tlv_len(self.flags.len())
            + encoded_integer_tlv_len(self.security_model)
    }

    /// A compact summary of the SNMPv3 global message fields.
    pub fn summary(&self) -> String {
        format!("SnmpV3GlobalData({})", self.summary_fields())
    }

    fn summary_fields(&self) -> String {
        let flags = self.flags_value();
        format!(
            "msg_id={} msg_max_size={} msg_flags={} msg_flags_len={} msg_security_model={} msg_security_model_label={}",
            self.msg_id,
            self.max_size,
            flags,
            self.flags.len(),
            self.security_model,
            self.security_model_label()
        )
    }

    /// Stable inspection fields for generated tools.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let flags = self.flags_value();
        vec![
            ("msg_id", self.msg_id.to_string()),
            ("msg_max_size", self.max_size.to_string()),
            ("msg_flags_len", self.flags.len().to_string()),
            ("msg_flags", ber::hex_bytes(&self.flags)),
            ("msg_flags_label", flags.label()),
            ("msg_flags_auth", flags.auth().to_string()),
            ("msg_flags_privacy", flags.privacy().to_string()),
            ("msg_flags_reportable", flags.reportable().to_string()),
            (
                "msg_flags_reserved_bits",
                format!("0x{:02x}", flags.reserved_bits()),
            ),
            (
                "msg_flags_reserved_auth_priv",
                flags.has_reserved_auth_priv_combination().to_string(),
            ),
            ("msg_security_model", self.security_model.to_string()),
            ("msg_security_model_label", self.security_model_label()),
            (
                "msg_security_model_status",
                self.security_model_status().to_string(),
            ),
        ]
    }
}

/// RFC 3412 plaintext SNMPv3 `ScopedPDU`.
///
/// This is a wire container for context engine ID bytes, context name bytes,
/// and an ordinary SNMP PDU. It does not add session state, VACM policy, or
/// manager behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpScopedPdu {
    context_engine_id: Vec<u8>,
    context_name: Vec<u8>,
    pdu: SnmpPdu,
}

impl SnmpScopedPdu {
    /// Build a plaintext scoped PDU from byte-oriented context fields.
    pub fn new(
        context_engine_id: impl Into<Vec<u8>>,
        context_name: impl Into<Vec<u8>>,
        pdu: SnmpPdu,
    ) -> Self {
        Self {
            context_engine_id: context_engine_id.into(),
            context_name: context_name.into(),
            pdu,
        }
    }

    /// Raw contextEngineID OCTET STRING bytes.
    pub fn context_engine_id(&self) -> &[u8] {
        &self.context_engine_id
    }

    /// Raw contextName OCTET STRING bytes.
    pub fn context_name(&self) -> &[u8] {
        &self.context_name
    }

    /// PDU carried by this plaintext scoped PDU.
    pub const fn pdu(&self) -> &SnmpPdu {
        &self.pdu
    }

    /// Mutable PDU carried by this plaintext scoped PDU.
    pub fn pdu_mut(&mut self) -> &mut SnmpPdu {
        &mut self.pdu
    }

    /// Consume this scoped PDU and return its PDU body.
    pub fn into_pdu(self) -> SnmpPdu {
        self.pdu
    }

    /// Decode one plaintext `ScopedPDU` SEQUENCE.
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (content, rest) = ber::decode_sequence(bytes)?;
        let (context_engine_id, content_rest) = decode_octet_string_tlv(
            content,
            SNMP_V3_CONTEXT_ENGINE_ID_CONTEXT,
            "expected universal primitive OCTET STRING for contextEngineID",
            "contextEngineID length exceeds supported size",
        )?;
        let (context_name, content_rest) = decode_octet_string_tlv(
            content_rest,
            SNMP_V3_CONTEXT_NAME_CONTEXT,
            "expected universal primitive OCTET STRING for contextName",
            "contextName length exceeds supported size",
        )?;
        let (pdu, content_rest) = SnmpPdu::decode(content_rest)?;
        if !content_rest.is_empty() {
            return Err(ber::invalid_ber_field(
                SNMP_V3_SCOPED_PDU_CONTEXT,
                "trailing bytes after ScopedPDU fields",
            ));
        }

        Ok((
            Self::new(context_engine_id.to_vec(), context_name.to_vec(), pdu),
            rest,
        ))
    }

    /// Encode this plaintext `ScopedPDU` SEQUENCE.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut content = Vec::with_capacity(self.encoded_content_len());
        encode_octet_string_tlv(&self.context_engine_id, &mut content)?;
        encode_octet_string_tlv(&self.context_name, &mut content)?;
        self.pdu.encode(&mut content)?;
        ber::encode_sequence(&content, out)
    }

    /// Return this scoped PDU encoded as BER bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile this scoped PDU into BER bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.to_bytes()
    }

    /// Encoded plaintext `ScopedPDU` length in octets.
    pub fn encoded_len(&self) -> usize {
        encoded_tlv_len(self.encoded_content_len())
    }

    fn encoded_content_len(&self) -> usize {
        encoded_tlv_len(self.context_engine_id.len())
            + encoded_tlv_len(self.context_name.len())
            + encoded_pdu_len(&self.pdu)
    }

    /// A compact scoped-PDU summary that reports context byte lengths.
    pub fn summary(&self) -> String {
        format!(
            "SnmpScopedPdu(context_engine_id_len={} context_name_len={} pdu={})",
            self.context_engine_id.len(),
            self.context_name.len(),
            self.pdu.summary()
        )
    }

    /// Stable inspection fields for generated tools.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "context_engine_id_len",
                self.context_engine_id.len().to_string(),
            ),
            (
                "context_engine_id_bytes",
                ber::hex_bytes(&self.context_engine_id),
            ),
            ("context_name_len", self.context_name.len().to_string()),
            ("context_name_bytes", ber::hex_bytes(&self.context_name)),
        ];
        fields.extend(self.pdu.inspection_fields());
        fields
    }

    /// Multi-line scoped-PDU inspection output.
    pub fn show(&self) -> String {
        let mut output = "SnmpScopedPdu".to_string();
        for (name, value) in self.inspection_fields() {
            output.push_str(&format!("\n  {name}: {value}"));
        }
        output
    }
}

/// RFC 3414 USM authoritative engine boots/time wire fields.
///
/// This is an inspectable pair of INTEGER values. It does not imply local
/// engine state, replay windows, authoritative-engine discovery, or timeliness
/// validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnmpUsmEngineTime {
    engine_boots: i64,
    engine_time: i64,
}

impl SnmpUsmEngineTime {
    /// Build a wire-level USM authoritative engine boots/time pair.
    ///
    /// RFC 3414 timeliness windows and authoritative-engine discovery are
    /// operational behavior for generated tools or probe cases, not crate
    /// validation policy.
    pub const fn new(engine_boots: i64, engine_time: i64) -> Self {
        Self {
            engine_boots,
            engine_time,
        }
    }

    /// msgAuthoritativeEngineBoots INTEGER value.
    pub const fn engine_boots(self) -> i64 {
        self.engine_boots
    }

    /// msgAuthoritativeEngineTime INTEGER value.
    pub const fn engine_time(self) -> i64 {
        self.engine_time
    }

    /// A compact summary of the USM authoritative engine counters.
    pub fn summary(self) -> String {
        format!(
            "SnmpUsmEngineTime(engine_boots={} engine_time={})",
            self.engine_boots, self.engine_time
        )
    }

    /// Stable inspection fields for generated tools.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("usm_engine_boots", self.engine_boots.to_string()),
            ("usm_engine_time", self.engine_time.to_string()),
        ]
    }

    /// Multi-line USM engine-time inspection output.
    pub fn show(self) -> String {
        let mut output = "SnmpUsmEngineTime".to_string();
        for (name, value) in self.inspection_fields() {
            output.push_str(&format!("\n  {name}: {value}"));
        }
        output
    }
}

/// RFC 3414 USM security-parameters wire structure.
///
/// This models the BER bytes carried inside SNMPv3 `msgSecurityParameters`.
/// It does not store keys, derive localized keys, authenticate, decrypt, or
/// enforce timeliness policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpUsmSecurityParameters {
    engine_id: Vec<u8>,
    engine_boots: i64,
    engine_time: i64,
    user_name: Vec<u8>,
    authentication_parameters: Vec<u8>,
    privacy_parameters: Vec<u8>,
}

impl SnmpUsmSecurityParameters {
    /// Build USM security parameters from explicit wire fields.
    pub fn new(
        engine_id: impl Into<Vec<u8>>,
        engine_boots: i64,
        engine_time: i64,
        user_name: impl Into<Vec<u8>>,
        authentication_parameters: impl Into<Vec<u8>>,
        privacy_parameters: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            engine_id: engine_id.into(),
            engine_boots,
            engine_time,
            user_name: user_name.into(),
            authentication_parameters: authentication_parameters.into(),
            privacy_parameters: privacy_parameters.into(),
        }
    }

    /// Build USM security parameters from an authoritative engine boots/time pair.
    pub fn from_engine_time(
        engine_id: impl Into<Vec<u8>>,
        engine_time: SnmpUsmEngineTime,
        user_name: impl Into<Vec<u8>>,
        authentication_parameters: impl Into<Vec<u8>>,
        privacy_parameters: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(
            engine_id,
            engine_time.engine_boots(),
            engine_time.engine_time(),
            user_name,
            authentication_parameters,
            privacy_parameters,
        )
    }

    /// Return a copy with an explicit msgAuthoritativeEngineBoots value.
    pub fn with_engine_boots(mut self, engine_boots: i64) -> Self {
        self.engine_boots = engine_boots;
        self
    }

    /// Return a copy with an explicit msgAuthoritativeEngineTime value.
    pub fn with_engine_time(mut self, engine_time: i64) -> Self {
        self.engine_time = engine_time;
        self
    }

    /// Return a copy with an explicit authoritative engine boots/time pair.
    pub fn with_engine_time_fields(mut self, engine_time: SnmpUsmEngineTime) -> Self {
        self.engine_boots = engine_time.engine_boots();
        self.engine_time = engine_time.engine_time();
        self
    }

    /// Return a copy with explicit msgAuthenticationParameters bytes.
    pub fn with_authentication_parameters(
        mut self,
        authentication_parameters: impl Into<Vec<u8>>,
    ) -> Self {
        self.authentication_parameters = authentication_parameters.into();
        self
    }

    /// Return a copy with explicit msgPrivacyParameters bytes.
    pub fn with_privacy_parameters(mut self, privacy_parameters: impl Into<Vec<u8>>) -> Self {
        self.privacy_parameters = privacy_parameters.into();
        self
    }

    /// msgAuthoritativeEngineID OCTET STRING bytes.
    pub fn engine_id(&self) -> &[u8] {
        &self.engine_id
    }

    /// msgAuthoritativeEngineBoots INTEGER value.
    pub const fn engine_boots(&self) -> i64 {
        self.engine_boots
    }

    /// msgAuthoritativeEngineTime INTEGER value.
    pub const fn engine_time(&self) -> i64 {
        self.engine_time
    }

    /// Authoritative engine boots/time pair as packet-level wire fields.
    pub const fn engine_time_fields(&self) -> SnmpUsmEngineTime {
        SnmpUsmEngineTime::new(self.engine_boots, self.engine_time)
    }

    /// msgUserName OCTET STRING bytes.
    pub fn user_name(&self) -> &[u8] {
        &self.user_name
    }

    /// msgAuthenticationParameters OCTET STRING bytes.
    pub fn authentication_parameters(&self) -> &[u8] {
        &self.authentication_parameters
    }

    /// msgAuthenticationParameters OCTET STRING content length.
    pub fn authentication_parameters_len(&self) -> usize {
        self.authentication_parameters.len()
    }

    /// msgPrivacyParameters OCTET STRING bytes.
    pub fn privacy_parameters(&self) -> &[u8] {
        &self.privacy_parameters
    }

    /// msgPrivacyParameters OCTET STRING content length.
    pub fn privacy_parameters_len(&self) -> usize {
        self.privacy_parameters.len()
    }

    /// Decode one USM security-parameters SEQUENCE.
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (content, rest) = ber::decode_sequence(bytes)?;
        let (engine_id, content_rest) = decode_octet_string_tlv(
            content,
            SNMP_USM_ENGINE_ID_CONTEXT,
            "expected universal primitive OCTET STRING for msgAuthoritativeEngineID",
            "msgAuthoritativeEngineID length exceeds supported size",
        )?;
        let (engine_boots, content_rest) = ber::decode_integer(content_rest)?;
        let (engine_time, content_rest) = ber::decode_integer(content_rest)?;
        let (user_name, content_rest) = decode_octet_string_tlv(
            content_rest,
            SNMP_USM_USER_NAME_CONTEXT,
            "expected universal primitive OCTET STRING for msgUserName",
            "msgUserName length exceeds supported size",
        )?;
        let (authentication_parameters, content_rest) = decode_octet_string_tlv(
            content_rest,
            SNMP_USM_AUTHENTICATION_PARAMETERS_CONTEXT,
            "expected universal primitive OCTET STRING for msgAuthenticationParameters",
            "msgAuthenticationParameters length exceeds supported size",
        )?;
        let (privacy_parameters, content_rest) = decode_octet_string_tlv(
            content_rest,
            SNMP_USM_PRIVACY_PARAMETERS_CONTEXT,
            "expected universal primitive OCTET STRING for msgPrivacyParameters",
            "msgPrivacyParameters length exceeds supported size",
        )?;
        if !content_rest.is_empty() {
            return Err(ber::invalid_ber_field(
                SNMP_USM_SECURITY_PARAMETERS_CONTEXT,
                "trailing bytes after USM security parameter fields",
            ));
        }

        Ok((
            Self::new(
                engine_id.to_vec(),
                engine_boots,
                engine_time,
                user_name.to_vec(),
                authentication_parameters.to_vec(),
                privacy_parameters.to_vec(),
            ),
            rest,
        ))
    }

    /// Encode this USM security-parameters SEQUENCE.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut content = Vec::with_capacity(self.encoded_content_len());
        encode_octet_string_tlv(&self.engine_id, &mut content)?;
        ber::encode_integer(self.engine_boots, &mut content)?;
        ber::encode_integer(self.engine_time, &mut content)?;
        encode_octet_string_tlv(&self.user_name, &mut content)?;
        encode_octet_string_tlv(&self.authentication_parameters, &mut content)?;
        encode_octet_string_tlv(&self.privacy_parameters, &mut content)?;
        ber::encode_sequence(&content, out)
    }

    /// Return this USM structure encoded as BER bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile this USM structure into BER bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.to_bytes()
    }

    /// Encoded USM security-parameters length in octets.
    pub fn encoded_len(&self) -> usize {
        encoded_tlv_len(self.encoded_content_len())
    }

    fn encoded_content_len(&self) -> usize {
        encoded_tlv_len(self.engine_id.len())
            + encoded_integer_tlv_len(self.engine_boots)
            + encoded_integer_tlv_len(self.engine_time)
            + encoded_tlv_len(self.user_name.len())
            + encoded_tlv_len(self.authentication_parameters.len())
            + encoded_tlv_len(self.privacy_parameters.len())
    }

    /// A compact summary that avoids printing credential-like bytes.
    pub fn summary(&self) -> String {
        format!(
            "SnmpUsmSecurityParameters(engine_id_len={} engine_boots={} engine_time={} user_name_len={} authentication_parameters_len={} privacy_parameters_len={})",
            self.engine_id.len(),
            self.engine_boots,
            self.engine_time,
            self.user_name.len(),
            self.authentication_parameters.len(),
            self.privacy_parameters.len()
        )
    }

    /// Stable inspection fields that avoid printing credential-like bytes.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("usm_engine_id_len", self.engine_id.len().to_string()),
            ("usm_engine_boots", self.engine_boots.to_string()),
            ("usm_engine_time", self.engine_time.to_string()),
            ("usm_user_name_len", self.user_name.len().to_string()),
            (
                "usm_authentication_parameters_len",
                self.authentication_parameters.len().to_string(),
            ),
            (
                "usm_privacy_parameters_len",
                self.privacy_parameters.len().to_string(),
            ),
        ]
    }

    /// Multi-line USM inspection output.
    pub fn show(&self) -> String {
        let mut output = "SnmpUsmSecurityParameters".to_string();
        for (name, value) in self.inspection_fields() {
            output.push_str(&format!("\n  {name}: {value}"));
        }
        output
    }
}

/// Raw SNMPv3 security-parameters bytes for model-specific payloads.
///
/// This records the security model that selected the payload syntax and keeps
/// the security parameter bytes opaque. USM or other model-specific decoding
/// belongs in dedicated source-backed slices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpRawSecurityParameters {
    security_model: i64,
    bytes: Vec<u8>,
}

impl SnmpRawSecurityParameters {
    /// Build raw security parameters for one msgSecurityModel value.
    pub fn new(security_model: i64, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            security_model,
            bytes: bytes.into(),
        }
    }

    /// Build raw security parameters from a USM structure.
    pub fn from_usm(usm: &SnmpUsmSecurityParameters) -> Result<Self> {
        Ok(Self::new(registry::SNMP_SECURITY_MODEL_USM, usm.compile()?))
    }

    /// RFC 3412 `msgSecurityModel` value associated with these bytes.
    pub const fn security_model(&self) -> i64 {
        self.security_model
    }

    /// Typed security-model wrapper for the INTEGER value.
    pub const fn security_model_value(&self) -> registry::SnmpSecurityModel {
        registry::SnmpSecurityModel::new(self.security_model)
    }

    /// Stable security-model label that preserves unassigned values.
    pub fn security_model_label(&self) -> String {
        registry::snmp_security_model_label(self.security_model)
    }

    /// Source-backed assignment status for the security-model value.
    pub const fn security_model_status(&self) -> registry::SnmpSecurityModelStatus {
        registry::snmp_security_model_status(self.security_model)
    }

    /// Raw msgSecurityParameters OCTET STRING content bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Raw msgSecurityParameters byte length.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the raw msgSecurityParameters byte string is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Decode raw msgSecurityParameters for one security model.
    pub fn decode(security_model: i64, bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (parameters, rest) = decode_octet_string_tlv(
            bytes,
            SNMP_V3_SECURITY_PARAMETERS_CONTEXT,
            "expected universal primitive OCTET STRING for msgSecurityParameters",
            "msgSecurityParameters length exceeds supported size",
        )?;
        Ok((Self::new(security_model, parameters.to_vec()), rest))
    }

    /// Decode these bytes as USM security parameters when the model is USM.
    ///
    /// Malformed USM bytes return a structured error while the original raw
    /// bytes remain available through [`SnmpRawSecurityParameters::bytes`].
    pub fn as_usm(&self) -> Result<Option<SnmpUsmSecurityParameters>> {
        if self.security_model != registry::SNMP_SECURITY_MODEL_USM {
            return Ok(None);
        }

        let (usm, rest) = SnmpUsmSecurityParameters::decode(&self.bytes)?;
        ber::require_sequence_exact(rest)?;
        Ok(Some(usm))
    }

    /// Encode these raw security parameters as msgSecurityParameters.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_octet_string_tlv(&self.bytes, out)
    }

    /// Return these raw security parameters encoded as BER bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile these raw security parameters into BER bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.to_bytes()
    }

    /// Encoded msgSecurityParameters length in octets.
    pub fn encoded_len(&self) -> usize {
        encoded_tlv_len(self.bytes.len())
    }

    /// A compact summary that avoids printing security parameter bytes.
    pub fn summary(&self) -> String {
        format!(
            "SnmpRawSecurityParameters(security_model={} security_model_label={} len={})",
            self.security_model,
            self.security_model_label(),
            self.bytes.len()
        )
    }

    /// Stable inspection fields that avoid printing security parameter bytes.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("msg_security_model", self.security_model.to_string()),
            ("msg_security_model_label", self.security_model_label()),
            (
                "msg_security_model_status",
                self.security_model_status().to_string(),
            ),
            ("msg_security_parameters_len", self.bytes.len().to_string()),
        ]
    }
}

/// Opaque encrypted SNMPv3 scoped data and associated privacy bytes.
///
/// This stores encrypted PDU bytes exactly as packet content and pairs them
/// with the USM privacy-parameter bytes when those are available. It never
/// decrypts, derives keys, or validates privacy algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpEncryptedScopedData {
    privacy_parameters: Vec<u8>,
    encrypted_pdu: Vec<u8>,
}

impl SnmpEncryptedScopedData {
    /// Build encrypted scoped data from explicit packet bytes.
    pub fn new(privacy_parameters: impl Into<Vec<u8>>, encrypted_pdu: impl Into<Vec<u8>>) -> Self {
        Self {
            privacy_parameters: privacy_parameters.into(),
            encrypted_pdu: encrypted_pdu.into(),
        }
    }

    /// Raw msgPrivacyParameters OCTET STRING content bytes, when available.
    pub fn privacy_parameters(&self) -> &[u8] {
        &self.privacy_parameters
    }

    /// Raw msgPrivacyParameters content length.
    pub fn privacy_parameters_len(&self) -> usize {
        self.privacy_parameters.len()
    }

    /// Raw encryptedPDU OCTET STRING content bytes.
    pub fn encrypted_pdu(&self) -> &[u8] {
        &self.encrypted_pdu
    }

    /// Raw encryptedPDU content length.
    pub fn encrypted_pdu_len(&self) -> usize {
        self.encrypted_pdu.len()
    }

    /// Encode this encrypted scoped data as the RFC 3412 encryptedPDU OCTET STRING.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_octet_string_tlv(&self.encrypted_pdu, out)
    }

    /// Return the encoded encryptedPDU OCTET STRING.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Compile this encrypted scoped data into BER bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.to_bytes()
    }

    /// Encoded encryptedPDU OCTET STRING length in octets.
    pub fn encoded_len(&self) -> usize {
        encoded_tlv_len(self.encrypted_pdu.len())
    }

    /// A compact summary that avoids printing privacy or encrypted payload bytes.
    pub fn summary(&self) -> String {
        format!(
            "SnmpEncryptedScopedData(encrypted_pdu_len={} privacy_parameters_len={})",
            self.encrypted_pdu.len(),
            self.privacy_parameters.len()
        )
    }

    /// Stable inspection fields for generated tools.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "encrypted_scoped_pdu_len",
                self.encrypted_pdu.len().to_string(),
            ),
            (
                "usm_privacy_parameters_len",
                self.privacy_parameters.len().to_string(),
            ),
        ]
    }

    /// Multi-line encrypted scoped-data inspection output.
    pub fn show(&self) -> String {
        let mut output = "SnmpEncryptedScopedData".to_string();
        for (name, value) in self.inspection_fields() {
            output.push_str(&format!("\n  {name}: {value}"));
        }
        output
    }
}

/// SNMPv3 top-level message wrapper fields.
///
/// This models the RFC 3412 message framing only. Security-model processing,
/// USM credentials, encryption, authentication, timeliness, and scoped-PDU
/// interpretation belong to later packet slices or generated tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpV3Message {
    version: SnmpVersion,
    global_data: SnmpV3GlobalData,
    security_parameters: SnmpRawSecurityParameters,
    scoped_data: Vec<u8>,
}

impl SnmpV3Message {
    /// Build an SNMPv3 message wrapper with raw security/scoped-data bytes.
    pub fn new(
        msg_id: i64,
        max_size: i64,
        flags: impl Into<Vec<u8>>,
        security_model: i64,
        security_parameters: impl Into<Vec<u8>>,
        scoped_data: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            version: SnmpVersion::V3,
            global_data: SnmpV3GlobalData::new(msg_id, max_size, flags, security_model),
            security_parameters: SnmpRawSecurityParameters::new(
                security_model,
                security_parameters,
            ),
            scoped_data: scoped_data.into(),
        }
    }

    /// Build an SNMPv3 message wrapper carrying plaintext scoped-PDU data.
    pub fn new_plaintext(
        msg_id: i64,
        max_size: i64,
        flags: impl Into<Vec<u8>>,
        security_model: i64,
        security_parameters: impl Into<Vec<u8>>,
        scoped_pdu: SnmpScopedPdu,
    ) -> Result<Self> {
        Ok(Self::new(
            msg_id,
            max_size,
            flags,
            security_model,
            security_parameters,
            scoped_pdu.compile()?,
        ))
    }

    /// Build an SNMPv3 message wrapper carrying USM security parameters.
    pub fn new_usm(
        msg_id: i64,
        max_size: i64,
        flags: impl Into<Vec<u8>>,
        usm: SnmpUsmSecurityParameters,
        scoped_data: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self::new(
            msg_id,
            max_size,
            flags,
            registry::SNMP_SECURITY_MODEL_USM,
            usm.compile()?,
            scoped_data,
        ))
    }

    /// Build an SNMPv3 USM message carrying opaque encrypted scoped data.
    pub fn new_encrypted_usm(
        msg_id: i64,
        max_size: i64,
        flags: impl Into<Vec<u8>>,
        usm: SnmpUsmSecurityParameters,
        encrypted_pdu: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        let encrypted_scoped_data =
            SnmpEncryptedScopedData::new(usm.privacy_parameters().to_vec(), encrypted_pdu);
        Self::new_usm(
            msg_id,
            max_size,
            flags,
            usm,
            encrypted_scoped_data.compile()?,
        )
    }

    /// Build an SNMPv3 message with a plaintext Report-PDU.
    pub fn new_plaintext_report(
        msg_id: i64,
        max_size: i64,
        flags: impl Into<Vec<u8>>,
        security_model: i64,
        security_parameters: impl Into<Vec<u8>>,
        context_engine_id: impl Into<Vec<u8>>,
        context_name: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Self::new_plaintext(
            msg_id,
            max_size,
            flags,
            security_model,
            security_parameters,
            SnmpScopedPdu::new(
                context_engine_id,
                context_name,
                SnmpPdu::report(request_id, varbinds)?,
            ),
        )
    }

    /// Build an SNMPv3 USM message with a plaintext Report-PDU.
    pub fn new_usm_report(
        msg_id: i64,
        max_size: i64,
        flags: impl Into<Vec<u8>>,
        usm: SnmpUsmSecurityParameters,
        context_engine_id: impl Into<Vec<u8>>,
        context_name: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        let scoped_pdu = SnmpScopedPdu::new(
            context_engine_id,
            context_name,
            SnmpPdu::report(request_id, varbinds)?,
        );
        Self::new_usm(msg_id, max_size, flags, usm, scoped_pdu.compile()?)
    }

    const fn with_version(mut self, version: SnmpVersion) -> Self {
        self.version = version;
        self
    }

    /// Message wrapper version.
    pub const fn version(&self) -> SnmpVersion {
        self.version
    }

    /// Raw message wrapper version INTEGER.
    pub const fn version_value(&self) -> i64 {
        self.version.as_integer()
    }

    /// RFC 3412 `HeaderData` global message fields.
    pub const fn global_data(&self) -> &SnmpV3GlobalData {
        &self.global_data
    }

    /// RFC 3412 `msgID` INTEGER value.
    pub const fn msg_id(&self) -> i64 {
        self.global_data.msg_id()
    }

    /// RFC 3412 `msgMaxSize` INTEGER value.
    pub const fn max_size(&self) -> i64 {
        self.global_data.max_size()
    }

    /// Raw RFC 3412 `msgFlags` OCTET STRING bytes.
    pub fn flags(&self) -> &[u8] {
        self.global_data.flags()
    }

    /// Typed view of the first `msgFlags` octet.
    pub fn flags_value(&self) -> registry::SnmpV3Flags {
        self.global_data.flags_value()
    }

    /// RFC 3412 `msgSecurityModel` INTEGER value.
    pub const fn security_model(&self) -> i64 {
        self.global_data.security_model()
    }

    /// Raw RFC 3412 `msgSecurityParameters` OCTET STRING bytes.
    pub fn security_parameters(&self) -> &[u8] {
        self.security_parameters.bytes()
    }

    /// Raw security-parameters representation with security-model metadata.
    pub const fn raw_security_parameters(&self) -> &SnmpRawSecurityParameters {
        &self.security_parameters
    }

    /// Decode USM security parameters when this message uses the USM model.
    pub fn usm_security_parameters(&self) -> Result<Option<SnmpUsmSecurityParameters>> {
        self.security_parameters.as_usm()
    }

    /// Raw RFC 3412 `ScopedPduData` TLV bytes.
    pub fn scoped_data(&self) -> &[u8] {
        &self.scoped_data
    }

    /// Decode plaintext scoped-PDU data, if this message carries plaintext.
    pub fn scoped_pdu(&self) -> Result<Option<SnmpScopedPdu>> {
        let (tag, _) = ber::decode_identifier(&self.scoped_data)?;
        if tag != ber::BerTag::new(ber::BerClass::Universal, true, ber::BER_TAG_SEQUENCE) {
            return Ok(None);
        }

        let (scoped_pdu, rest) = SnmpScopedPdu::decode(&self.scoped_data)?;
        ber::require_sequence_exact(rest)?;
        Ok(Some(scoped_pdu))
    }

    /// Decode encrypted scoped data as opaque bytes, if this message carries it.
    pub fn encrypted_scoped_data(&self) -> Result<Option<SnmpEncryptedScopedData>> {
        let Some(encrypted_pdu) = decode_encrypted_scoped_pdu_content(&self.scoped_data)? else {
            return Ok(None);
        };
        let privacy_parameters = self
            .usm_security_parameters()?
            .map(|usm| usm.privacy_parameters().to_vec())
            .unwrap_or_default();

        Ok(Some(SnmpEncryptedScopedData::new(
            privacy_parameters,
            encrypted_pdu.to_vec(),
        )))
    }

    /// Source-backed scoped-data CHOICE label.
    pub fn scoped_data_kind(&self) -> &'static str {
        scoped_data_kind_label(&self.scoped_data)
    }

    /// Raw encryptedPDU content length, if scoped data is encrypted.
    pub fn encrypted_scoped_pdu_len(&self) -> Result<Option<usize>> {
        Ok(decode_encrypted_scoped_pdu_content(&self.scoped_data)?.map(<[u8]>::len))
    }

    fn decode_after_version(version: SnmpVersion, bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (global_data, rest) = SnmpV3GlobalData::decode(bytes)?;
        let (security_parameters, rest) =
            SnmpRawSecurityParameters::decode(global_data.security_model(), rest)?;
        let (scoped_data, rest) = decode_scoped_data_tlv(rest)?;

        Ok((
            Self {
                version,
                global_data,
                security_parameters,
                scoped_data: scoped_data.to_vec(),
            },
            rest,
        ))
    }

    fn encode_content_after_version(&self, out: &mut Vec<u8>) -> Result<()> {
        self.global_data.encode(out)?;
        self.security_parameters.encode(out)?;
        out.extend_from_slice(&self.scoped_data);
        Ok(())
    }

    fn encoded_content_after_version_len(&self) -> usize {
        self.global_data.encoded_len()
            + self.security_parameters.encoded_len()
            + self.scoped_data.len()
    }

    fn summary_fields(&self) -> String {
        let encrypted_len = self.encrypted_scoped_pdu_len().ok().flatten().unwrap_or(0);
        let scoped_summary = self
            .scoped_pdu()
            .ok()
            .flatten()
            .map(|scoped_pdu| format!(" scoped_pdu={}", scoped_pdu.summary()))
            .unwrap_or_default();
        format!(
            "{} msg_security_parameters_len={} scoped_data_kind={} scoped_data_len={} encrypted_scoped_pdu_len={}{}",
            self.global_data.summary_fields(),
            self.security_parameters.len(),
            self.scoped_data_kind(),
            self.scoped_data.len(),
            encrypted_len,
            scoped_summary
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = self.global_data.inspection_fields();
        fields.extend(self.security_parameters.inspection_fields());
        fields.push(("scoped_data_kind", self.scoped_data_kind().to_string()));
        fields.push(("scoped_data_len", self.scoped_data.len().to_string()));
        if let Ok(Some(encrypted_len)) = self.encrypted_scoped_pdu_len() {
            fields.push(("encrypted_scoped_pdu_len", encrypted_len.to_string()));
        }
        fields
    }
}

/// Top-level SNMP packet layer.
///
/// Public constructors cover source-backed SNMPv1, community-based SNMPv2c,
/// and the SNMPv3 message wrapper. The layer composes with [`Packet`] and `/`
/// like every other packet layer and leaves application workflows to generated
/// tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snmp {
    data: SnmpMessageData,
    length: Option<usize>,
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

    /// Build an SNMPv3 top-level message wrapper.
    ///
    /// This preserves raw `msgFlags`, `msgSecurityParameters`, and
    /// `ScopedPduData` bytes. It does not perform security-model processing or
    /// parse the scoped PDU payload.
    pub fn v3(
        msg_id: i64,
        max_size: i64,
        flags: impl Into<Vec<u8>>,
        security_model: i64,
        security_parameters: impl Into<Vec<u8>>,
        scoped_data: impl Into<Vec<u8>>,
    ) -> Self {
        Self::from_v3_message(SnmpV3Message::new(
            msg_id,
            max_size,
            flags,
            security_model,
            security_parameters,
            scoped_data,
        ))
    }

    /// Build an SNMPv3 top-level message with plaintext scoped-PDU data.
    pub fn v3_plaintext(
        msg_id: i64,
        max_size: i64,
        flags: impl Into<Vec<u8>>,
        security_model: i64,
        security_parameters: impl Into<Vec<u8>>,
        scoped_pdu: SnmpScopedPdu,
    ) -> Result<Self> {
        Ok(Self::from_v3_message(SnmpV3Message::new_plaintext(
            msg_id,
            max_size,
            flags,
            security_model,
            security_parameters,
            scoped_pdu,
        )?))
    }

    /// Build an SNMPv3 USM message with encrypted scoped-PDU bytes.
    pub fn v3_encrypted_usm(
        msg_id: i64,
        max_size: i64,
        flags: impl Into<Vec<u8>>,
        usm: SnmpUsmSecurityParameters,
        encrypted_pdu: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self::from_v3_message(SnmpV3Message::new_encrypted_usm(
            msg_id,
            max_size,
            flags,
            usm,
            encrypted_pdu,
        )?))
    }

    /// Build an SNMPv3 top-level message with a plaintext Report-PDU.
    pub fn v3_report(
        msg_id: i64,
        max_size: i64,
        flags: impl Into<Vec<u8>>,
        security_model: i64,
        security_parameters: impl Into<Vec<u8>>,
        context_engine_id: impl Into<Vec<u8>>,
        context_name: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::from_v3_message(SnmpV3Message::new_plaintext_report(
            msg_id,
            max_size,
            flags,
            security_model,
            security_parameters,
            context_engine_id,
            context_name,
            request_id,
            varbinds,
        )?))
    }

    /// Build an SNMPv3 USM top-level message with a plaintext Report-PDU.
    pub fn v3_usm_report(
        msg_id: i64,
        max_size: i64,
        flags: impl Into<Vec<u8>>,
        usm: SnmpUsmSecurityParameters,
        context_engine_id: impl Into<Vec<u8>>,
        context_name: impl Into<Vec<u8>>,
        request_id: i64,
        varbinds: super::SnmpVarBindList,
    ) -> Result<Self> {
        Ok(Self::from_v3_message(SnmpV3Message::new_usm_report(
            msg_id,
            max_size,
            flags,
            usm,
            context_engine_id,
            context_name,
            request_id,
            varbinds,
        )?))
    }

    /// Build a top-level SNMP layer from explicit SNMPv3 wrapper fields.
    pub fn from_v3_message(message: SnmpV3Message) -> Self {
        Self {
            data: SnmpMessageData::V3(message),
            length: None,
        }
    }

    fn community_message(
        version: SnmpVersion,
        community: impl Into<Vec<u8>>,
        pdu: SnmpPdu,
    ) -> Self {
        Self {
            data: SnmpMessageData::Community {
                header: SnmpMessageHeader::new(version, community),
                pdu,
            },
            length: None,
        }
    }

    /// Message wrapper version.
    pub const fn version(&self) -> SnmpVersion {
        match &self.data {
            SnmpMessageData::Community { header, .. } => header.version(),
            SnmpMessageData::V3(message) => message.version(),
        }
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
        match &self.data {
            SnmpMessageData::Community { header, .. } => header.community(),
            SnmpMessageData::V3(_) => &[],
        }
    }

    /// PDU body carried by a community-based message.
    ///
    /// SNMPv3 scoped-PDU parsing is added by a later packet slice; use
    /// [`Snmp::as_v3`] to inspect raw v3 wrapper fields.
    pub const fn pdu(&self) -> &SnmpPdu {
        match &self.data {
            SnmpMessageData::Community { pdu, .. } => pdu,
            SnmpMessageData::V3(_) => panic!("SNMPv3 scoped PDU parsing is not available"),
        }
    }

    /// PDU body carried by a community-based message, if present.
    pub const fn pdu_opt(&self) -> Option<&SnmpPdu> {
        match &self.data {
            SnmpMessageData::Community { pdu, .. } => Some(pdu),
            SnmpMessageData::V3(_) => None,
        }
    }

    /// SNMPv3 wrapper fields, if this message uses v3 framing.
    pub const fn as_v3(&self) -> Option<&SnmpV3Message> {
        match &self.data {
            SnmpMessageData::Community { .. } => None,
            SnmpMessageData::V3(message) => Some(message),
        }
    }

    /// Return a copy of this message with an explicit version INTEGER value.
    pub fn with_version(mut self, version: SnmpVersion) -> Self {
        match &mut self.data {
            SnmpMessageData::Community { header, .. } => header.version = version,
            SnmpMessageData::V3(message) => {
                *message = message.clone().with_version(version);
            }
        }
        self
    }

    /// Return a copy of this message with explicit community OCTET STRING bytes.
    pub fn with_community(mut self, community: impl Into<Vec<u8>>) -> Self {
        if let SnmpMessageData::Community { header, .. } = &mut self.data {
            header.community = SnmpCommunity::new(community);
        }
        self
    }

    /// Return a copy of this message carrying an explicit PDU.
    pub fn with_pdu(mut self, pdu: SnmpPdu) -> Self {
        if let SnmpMessageData::Community {
            pdu: current_pdu, ..
        } = &mut self.data
        {
            *current_pdu = pdu;
        }
        self
    }

    /// Pin the outer SNMP Message SEQUENCE length field to an explicit value.
    ///
    /// The normal builder path auto-fills this length from the encoded header
    /// and PDU bytes. This override is for deliberately malformed packets: the
    /// length field is emitted as supplied while the content bytes remain
    /// unchanged.
    pub fn length(mut self, length: usize) -> Self {
        self.length = Some(length);
        self
    }

    /// Drop any explicit outer message length override so encode auto-fills it.
    pub fn clear_length(mut self) -> Self {
        self.length = None;
        self
    }

    /// Explicit outer message BER length override, if one is pinned.
    pub const fn explicit_length(&self) -> Option<usize> {
        self.length
    }

    /// Effective outer message BER length: caller override when set, else
    /// encoded content length.
    pub fn effective_length(&self) -> usize {
        self.length.unwrap_or_else(|| self.encoded_content_len())
    }

    /// Mutable PDU body carried by this message.
    pub fn pdu_mut(&mut self) -> &mut SnmpPdu {
        match &mut self.data {
            SnmpMessageData::Community { pdu, .. } => pdu,
            SnmpMessageData::V3(_) => panic!("SNMPv3 scoped PDU parsing is not available"),
        }
    }

    /// Consume the message and return its PDU body.
    pub fn into_pdu(self) -> SnmpPdu {
        match self.data {
            SnmpMessageData::Community { pdu, .. } => pdu,
            SnmpMessageData::V3(_) => panic!("SNMPv3 scoped PDU parsing is not available"),
        }
    }

    /// Encoded SNMP message length in octets.
    pub fn encoded_len(&self) -> usize {
        ber::BER_IDENTIFIER_LEN
            + encoded_length_len(self.effective_length())
            + self.encoded_content_len()
    }

    /// Encode this SNMP message into BER bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut content = Vec::with_capacity(self.encoded_content_len());
        match &self.data {
            SnmpMessageData::Community { header, pdu } => {
                header.encode(&mut content)?;
                pdu.encode(&mut content)?;
            }
            SnmpMessageData::V3(message) => {
                message.version().encode(&mut content)?;
                message.encode_content_after_version(&mut content)?;
            }
        }
        encode_message_sequence(&content, self.explicit_length(), out)
    }

    /// Decode one complete SNMP message from BER bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let content = ber::decode_sequence_exact(bytes)?;
        let (version, rest) = SnmpVersion::decode(content)?;
        let data = if version == SnmpVersion::V3 {
            let (message, rest) = SnmpV3Message::decode_after_version(version, rest)?;
            ber::require_sequence_exact(rest)?;
            SnmpMessageData::V3(message)
        } else {
            let (community, rest) = SnmpCommunity::decode(rest)?;
            let (pdu, rest) = SnmpPdu::decode(rest)?;
            ber::require_sequence_exact(rest)?;
            SnmpMessageData::Community {
                header: SnmpMessageHeader { version, community },
                pdu,
            }
        };

        Ok(Self { data, length: None })
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

    /// A compact SNMP message summary that avoids printing community bytes.
    pub fn summary(&self) -> String {
        match &self.data {
            SnmpMessageData::Community { pdu, .. } => format!(
                "Snmp(version={}, community_len={}, pdu={})",
                self.version(),
                self.community().len(),
                pdu.summary()
            ),
            SnmpMessageData::V3(message) => {
                format!(
                    "Snmp(version={}, {})",
                    self.version(),
                    message.summary_fields()
                )
            }
        }
    }

    /// Stable inspection fields for generated tools.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("version", self.version().to_string()),
            ("version_value", self.version_value().to_string()),
            ("message_len", self.encoded_len().to_string()),
        ];
        match &self.data {
            SnmpMessageData::Community { pdu, .. } => {
                fields.push(("community_len", self.community().len().to_string()));
                fields.extend(pdu.inspection_fields());
            }
            SnmpMessageData::V3(message) => fields.extend(message.inspection_fields()),
        }
        fields
    }

    /// Multi-line SNMP message inspection output.
    pub fn show(&self) -> String {
        let mut output = "Snmp".to_string();
        for (name, value) in self.inspection_fields() {
            output.push_str(&format!("\n  {name}: {value}"));
        }
        output
    }

    fn encoded_content_len(&self) -> usize {
        encoded_integer_tlv_len(self.version_value())
            + match &self.data {
                SnmpMessageData::Community { pdu, .. } => {
                    encoded_tlv_len(self.community().len()) + encoded_pdu_len(pdu)
                }
                SnmpMessageData::V3(message) => message.encoded_content_after_version_len(),
            }
    }
}

impl Layer for Snmp {
    fn name(&self) -> &'static str {
        "Snmp"
    }

    fn summary(&self) -> String {
        Snmp::summary(self)
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        Snmp::inspection_fields(self)
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
    decode_octet_string_tlv(
        bytes,
        SNMP_MESSAGE_COMMUNITY_CONTEXT,
        "expected universal primitive OCTET STRING",
        "community length exceeds supported size",
    )
}

fn encode_community_octet_string(bytes: &[u8], out: &mut Vec<u8>) -> Result<()> {
    encode_octet_string_tlv(bytes, out)
}

fn decode_octet_string_tlv<'a>(
    bytes: &'a [u8],
    context: &'static str,
    tag_reason: &'static str,
    overflow_reason: &'static str,
) -> Result<(&'a [u8], &'a [u8])> {
    let (tag, rest) = ber::decode_identifier(bytes)?;
    if tag != ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_OCTET_STRING) {
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

    Ok(rest.split_at(length))
}

fn encode_octet_string_tlv(bytes: &[u8], out: &mut Vec<u8>) -> Result<()> {
    ber::encode_identifier(
        ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_OCTET_STRING),
        out,
    )?;
    ber::encode_length(bytes.len(), out)?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_scoped_data_tlv(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    let (tag, rest) = ber::decode_identifier(bytes)?;
    let is_plaintext =
        tag == ber::BerTag::new(ber::BerClass::Universal, true, ber::BER_TAG_SEQUENCE);
    let is_encrypted =
        tag == ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_OCTET_STRING);
    if !is_plaintext && !is_encrypted {
        return Err(ber::invalid_ber_field(
            SNMP_V3_SCOPED_DATA_CONTEXT,
            "expected plaintext ScopedPDU SEQUENCE or encrypted OCTET STRING",
        ));
    }

    let (length, rest) = ber::decode_length(rest)?;
    if rest.len() < length {
        let prefix_len = bytes.len() - rest.len();
        let required = prefix_len.checked_add(length).ok_or_else(|| {
            ber::invalid_ber_field(
                SNMP_V3_SCOPED_DATA_CONTEXT,
                "ScopedPduData length exceeds supported size",
            )
        })?;
        return Err(ber::truncated_ber(
            SNMP_V3_SCOPED_DATA_CONTEXT,
            required,
            bytes.len(),
        ));
    }

    let tlv_len = bytes.len() - rest.len() + length;
    Ok(bytes.split_at(tlv_len))
}

fn scoped_data_kind_label(bytes: &[u8]) -> &'static str {
    match ber::decode_identifier(bytes) {
        Ok((tag, _))
            if tag == ber::BerTag::new(ber::BerClass::Universal, true, ber::BER_TAG_SEQUENCE) =>
        {
            "plaintext"
        }
        Ok((tag, _))
            if tag
                == ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_OCTET_STRING) =>
        {
            "encrypted"
        }
        _ => "unknown",
    }
}

fn decode_encrypted_scoped_pdu_content(bytes: &[u8]) -> Result<Option<&[u8]>> {
    let (tag, _) = ber::decode_identifier(bytes)?;
    if tag != ber::BerTag::new(ber::BerClass::Universal, false, ber::BER_TAG_OCTET_STRING) {
        return Ok(None);
    }

    let (encrypted_pdu, rest) = decode_octet_string_tlv(
        bytes,
        SNMP_V3_SCOPED_DATA_CONTEXT,
        "expected universal primitive OCTET STRING for encryptedPDU",
        "encryptedPDU length exceeds supported size",
    )?;
    if !rest.is_empty() {
        return Err(ber::invalid_ber_field(
            SNMP_V3_SCOPED_DATA_CONTEXT,
            "trailing bytes after encryptedPDU",
        ));
    }

    Ok(Some(encrypted_pdu))
}

fn encode_message_sequence(
    content: &[u8],
    explicit_length: Option<usize>,
    out: &mut Vec<u8>,
) -> Result<()> {
    ber::encode_identifier(
        ber::BerTag::new(ber::BerClass::Universal, true, ber::BER_TAG_SEQUENCE),
        out,
    )?;
    ber::encode_length(explicit_length.unwrap_or(content.len()), out)?;
    out.extend_from_slice(content);
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
        // 4.1.2 for SNMPv1 value 0, RFC 1901 Section 3 for SNMPv2c value 1,
        // and RFC 3412 Section 6.1 for SNMPv3 value 3.
        let cases = [
            (SNMP_VERSION_VALUE_V1, SnmpVersion::V1, "v1"),
            (SNMP_VERSION_VALUE_V2C, SnmpVersion::V2c, "v2c"),
            (SNMP_VERSION_VALUE_V3, SnmpVersion::V3, "v3"),
        ];

        for (integer, version, label) in cases {
            assert_eq!(SnmpVersion::from_integer(integer), version);
            assert_eq!(version.as_integer(), integer);
            assert_eq!(version.label(), label);
            assert_eq!(version.to_string(), label);
        }

        let unknown = SnmpVersion::from_integer(4);
        assert_eq!(unknown.label(), "unknown");
        assert_eq!(unknown.to_string(), "unknown(4)");
    }

    #[test]
    fn snmp_version_unknown_version_preservation() -> Result<()> {
        let mut bytes =
            SnmpMessageHeader::new(SnmpVersion::from_integer(4), b"example".to_vec()).to_bytes()?;
        bytes.extend_from_slice(&[0xa0, 0x00]);

        let (decoded, rest) = SnmpMessageHeader::decode(&bytes)?;
        assert_eq!(decoded.version(), SnmpVersion::Unknown(4));
        assert_eq!(decoded.version().as_integer(), 4);
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

    fn minimal_plaintext_v3_scoped_data() -> Vec<u8> {
        vec![
            0x30, 0x11, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00,
            0x02, 0x01, 0x00, 0x30, 0x00,
        ]
    }

    #[test]
    fn snmp_v3_global_data_boundary_values_compile_decode_and_summarize() -> Result<()> {
        let global = SnmpV3GlobalData::new(2_147_483_647, 0, [0x07], 999);
        let expected = [
            0x30, 0x10, 0x02, 0x04, 0x7f, 0xff, 0xff, 0xff, 0x02, 0x01, 0x00, 0x04, 0x01, 0x07,
            0x02, 0x02, 0x03, 0xe7,
        ];

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 3412 Sections
        // 6.2 through 6.5 for HeaderData msgID, msgMaxSize, msgFlags, and
        // msgSecurityModel wire fields.
        assert_eq!(global.encoded_len(), expected.len());
        assert_eq!(global.compile()?, expected);

        let mut with_rest = expected.to_vec();
        with_rest.push(0xaa);
        let (decoded, rest) = SnmpV3GlobalData::decode(&with_rest)?;
        assert_eq!(rest, &[0xaa]);
        assert_eq!(decoded.msg_id(), 2_147_483_647);
        assert_eq!(decoded.max_size(), 0);
        assert_eq!(decoded.flags(), &[0x07]);
        assert_eq!(decoded.security_model(), 999);
        assert_eq!(decoded.compile()?, expected);

        assert_eq!(
            decoded.summary(),
            "SnmpV3GlobalData(msg_id=2147483647 msg_max_size=0 msg_flags=auth|privacy|reportable msg_flags_len=1 msg_security_model=999 msg_security_model_label=security-model-999)"
        );
        let fields = decoded.inspection_fields();
        assert_eq!(inspection_value(&fields, "msg_id"), Some("2147483647"));
        assert_eq!(inspection_value(&fields, "msg_max_size"), Some("0"));
        assert_eq!(inspection_value(&fields, "msg_flags"), Some("07"));
        assert_eq!(
            inspection_value(&fields, "msg_flags_label"),
            Some("auth|privacy|reportable")
        );
        assert_eq!(inspection_value(&fields, "msg_security_model"), Some("999"));
        assert_eq!(
            inspection_value(&fields, "msg_security_model_status"),
            Some("unknown")
        );

        Ok(())
    }

    #[test]
    fn snmp_v3_global_data_builders_preserve_explicit_wire_values() -> Result<()> {
        let global = SnmpV3GlobalData::new(0, 484, Vec::<u8>::new(), 3)
            .with_msg_id(-1)
            .with_max_size(65_535)
            .with_flags([0xaa, 0xbb])
            .with_security_model(65_535);

        let bytes = global.compile()?;
        let (decoded, rest) = SnmpV3GlobalData::decode(&bytes)?;

        assert!(rest.is_empty());
        assert_eq!(decoded.msg_id(), -1);
        assert_eq!(decoded.max_size(), 65_535);
        assert_eq!(decoded.flags(), &[0xaa, 0xbb]);
        assert_eq!(decoded.flags_value().reserved_bits(), 0xa8);
        assert_eq!(decoded.flags_value().label(), "privacy|reserved-0xa8");
        assert_eq!(decoded.security_model(), 65_535);
        assert_eq!(decoded.compile()?, bytes);

        Ok(())
    }

    #[test]
    fn snmp_v3_global_data_malformed_sequence_length_is_structured_error() {
        let bytes = [
            0x30, 0x0e, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x04, 0x01, 0x00, 0x02, 0x01, 0x03,
        ];
        let error = SnmpV3GlobalData::decode(&bytes).expect_err("overreported HeaderData length");

        assert_eq!(
            error,
            crate::error::CrafterError::buffer_too_short("snmp.ber.sequence", 16, bytes.len())
        );
    }

    #[test]
    fn snmp_v3_flags_message_decode_inspects_raw_flags_and_unknown_security_model() -> Result<()> {
        let scoped_data = minimal_plaintext_v3_scoped_data();
        let snmp = Snmp::v3(9, 1500, [0xff, 0x55], 99, [0xaa], scoped_data);
        let decoded = Snmp::decode(&snmp.compile()?)?;
        let global = decoded.as_v3().expect("v3 wrapper").global_data();
        let flags = global.flags_value();

        assert_eq!(global.flags(), &[0xff, 0x55]);
        assert_eq!(flags.bits(), 0xff);
        assert!(flags.auth());
        assert!(flags.privacy());
        assert!(flags.reportable());
        assert_eq!(flags.reserved_bits(), 0xf8);
        assert_eq!(flags.label(), "auth|privacy|reportable|reserved-0xf8");
        assert_eq!(global.security_model(), 99);
        assert_eq!(global.security_model_label(), "security-model-99");
        assert_eq!(
            global.security_model_status(),
            registry::SnmpSecurityModelStatus::Unassigned
        );

        let fields = decoded.inspection_fields();
        assert_eq!(inspection_value(&fields, "msg_flags"), Some("ff 55"));
        assert_eq!(
            inspection_value(&fields, "msg_flags_label"),
            Some("auth|privacy|reportable|reserved-0xf8")
        );
        assert_eq!(inspection_value(&fields, "msg_flags_auth"), Some("true"));
        assert_eq!(inspection_value(&fields, "msg_flags_privacy"), Some("true"));
        assert_eq!(
            inspection_value(&fields, "msg_flags_reportable"),
            Some("true")
        );
        assert_eq!(
            inspection_value(&fields, "msg_flags_reserved_bits"),
            Some("0xf8")
        );
        assert_eq!(
            inspection_value(&fields, "msg_security_model_label"),
            Some("security-model-99")
        );
        assert_eq!(
            inspection_value(&fields, "msg_security_model_status"),
            Some("unassigned")
        );

        Ok(())
    }

    #[test]
    fn snmp_v3_scoped_pdu_wraps_request_pdu_and_v3_message() -> Result<()> {
        let scoped = SnmpScopedPdu::new(
            Vec::<u8>::new(),
            Vec::<u8>::new(),
            SnmpPdu::get_request(1, SnmpVarBindList::empty())?,
        );
        let expected = minimal_plaintext_v3_scoped_data();

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 3412 Sections
        // 6.7 and 6.8 for plaintext ScopedPDU contextEngineID, contextName,
        // and PDU payload fields.
        assert_eq!(scoped.encoded_len(), expected.len());
        assert_eq!(scoped.compile()?, expected);
        assert_eq!(scoped.context_engine_id(), b"");
        assert_eq!(scoped.context_name(), b"");
        assert_eq!(scoped.pdu().tag_number(), SnmpPdu::TAG_GET_REQUEST);

        let (decoded, rest) = SnmpScopedPdu::decode(&expected)?;
        assert!(rest.is_empty());
        assert_eq!(decoded.context_engine_id(), b"");
        assert_eq!(decoded.context_name(), b"");
        assert_eq!(decoded.pdu().tag_number(), SnmpPdu::TAG_GET_REQUEST);
        assert_eq!(
            decoded
                .pdu()
                .as_get_request()?
                .expect("get request fields")
                .request_id(),
            1
        );
        assert_eq!(decoded.compile()?, expected);
        assert!(decoded.summary().contains("context_engine_id_len=0"));
        assert!(decoded.summary().contains("pdu_type=get-request"));

        let snmp = Snmp::v3_plaintext(
            1,
            1500,
            [0x00],
            registry::SNMP_SECURITY_MODEL_USM,
            Vec::<u8>::new(),
            scoped,
        )?;
        let decoded_snmp = Snmp::decode(&snmp.compile()?)?;
        let decoded_scoped = decoded_snmp
            .as_v3()
            .expect("v3 wrapper")
            .scoped_pdu()?
            .expect("plaintext scoped PDU");
        assert_eq!(decoded_scoped.compile()?, expected);

        Ok(())
    }

    #[test]
    fn snmp_v3_scoped_pdu_preserves_non_utf8_context_name_and_response_pdu() -> Result<()> {
        let scoped = SnmpScopedPdu::new(
            [0x80, 0x00, 0x1f],
            [0xff, 0x00, b'a'],
            SnmpPdu::response_error(128, 2, 3, SnmpVarBindList::empty())?,
        );
        let bytes = scoped.compile()?;
        let (decoded, rest) = SnmpScopedPdu::decode(&bytes)?;

        assert!(rest.is_empty());
        assert_eq!(decoded.context_engine_id(), &[0x80, 0x00, 0x1f]);
        assert_eq!(decoded.context_name(), &[0xff, 0x00, b'a']);
        assert_eq!(decoded.pdu().tag_number(), SnmpPdu::TAG_RESPONSE);
        let response = decoded.pdu().as_response()?.expect("response fields");
        assert_eq!(response.request_id(), 128);
        assert_eq!(response.error_status(), 2);
        assert_eq!(response.error_index(), 3);
        assert_eq!(decoded.compile()?, bytes);

        let fields = decoded.inspection_fields();
        assert_eq!(
            inspection_value(&fields, "context_engine_id_len"),
            Some("3")
        );
        assert_eq!(
            inspection_value(&fields, "context_engine_id_bytes"),
            Some("80 00 1f")
        );
        assert_eq!(inspection_value(&fields, "context_name_len"), Some("3"));
        assert_eq!(
            inspection_value(&fields, "context_name_bytes"),
            Some("ff 00 61")
        );
        assert_eq!(inspection_value(&fields, "pdu_type"), Some("response"));

        Ok(())
    }

    #[test]
    fn snmp_v3_scoped_pdu_wraps_report_pdu() -> Result<()> {
        let scoped = SnmpScopedPdu::new(
            b"engine".to_vec(),
            b"context".to_vec(),
            SnmpPdu::report(7, SnmpVarBindList::empty())?,
        );
        let snmp = Snmp::v3_plaintext(
            44,
            1500,
            [registry::SNMP_V3_FLAG_REPORTABLE],
            registry::SNMP_SECURITY_MODEL_USM,
            Vec::<u8>::new(),
            scoped.clone(),
        )?;
        let decoded = Snmp::decode(&snmp.compile()?)?;
        let decoded_scoped = decoded
            .as_v3()
            .expect("v3 wrapper")
            .scoped_pdu()?
            .expect("plaintext scoped PDU");

        assert_eq!(decoded_scoped.context_engine_id(), b"engine");
        assert_eq!(decoded_scoped.context_name(), b"context");
        assert_eq!(decoded_scoped.pdu().tag_number(), SnmpPdu::TAG_REPORT);
        assert_eq!(
            decoded_scoped
                .pdu()
                .as_report()?
                .expect("report fields")
                .request_id(),
            7
        );
        assert_eq!(decoded_scoped.compile()?, scoped.compile()?);
        assert!(decoded_scoped.summary().contains("pdu_type=report"));

        Ok(())
    }

    #[test]
    fn snmp_v3_raw_security_parameters_compile_decode_and_hide_bytes() -> Result<()> {
        let raw = SnmpRawSecurityParameters::new(999, [0xde, 0xad, 0xbe, 0xef]);
        let expected = [0x04, 0x04, 0xde, 0xad, 0xbe, 0xef];

        assert_eq!(raw.security_model(), 999);
        assert_eq!(
            raw.security_model_status(),
            registry::SnmpSecurityModelStatus::Unknown
        );
        assert_eq!(raw.security_model_label(), "security-model-999");
        assert_eq!(raw.bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(raw.len(), 4);
        assert!(!raw.is_empty());
        assert_eq!(raw.compile()?, expected);

        let mut with_rest = expected.to_vec();
        with_rest.push(0xaa);
        let (decoded, rest) = SnmpRawSecurityParameters::decode(999, &with_rest)?;
        assert_eq!(rest, &[0xaa]);
        assert_eq!(decoded.bytes(), raw.bytes());
        assert_eq!(decoded.compile()?, expected);
        assert!(decoded.summary().contains("len=4"));
        assert!(!decoded.summary().contains("de ad"));
        assert!(!decoded
            .inspection_fields()
            .iter()
            .any(|(_, value)| value == "de ad be ef"));

        Ok(())
    }

    #[test]
    fn snmp_v3_raw_security_parameters_unknown_model_message_roundtrips() -> Result<()> {
        let scoped_data = minimal_plaintext_v3_scoped_data();
        let snmp = Snmp::v3(7, 1500, [0x00], 999, [0xaa, 0xbb], scoped_data);
        let bytes = snmp.compile()?;
        let decoded = Snmp::decode(&bytes)?;
        let v3 = decoded.as_v3().expect("v3 wrapper");
        let raw = v3.raw_security_parameters();

        assert_eq!(raw.security_model(), 999);
        assert_eq!(
            raw.security_model_status(),
            registry::SnmpSecurityModelStatus::Unknown
        );
        assert_eq!(raw.security_model_label(), "security-model-999");
        assert_eq!(raw.bytes(), &[0xaa, 0xbb]);
        assert_eq!(v3.security_parameters(), &[0xaa, 0xbb]);
        assert_eq!(raw.compile()?, [0x04, 0x02, 0xaa, 0xbb]);
        assert_eq!(decoded.compile()?, bytes);
        assert!(decoded.summary().contains("msg_security_parameters_len=2"));
        assert!(!decoded.summary().contains("aa bb"));
        assert!(!decoded.show().contains("aa bb"));

        Ok(())
    }

    fn sample_usm_parameters() -> SnmpUsmSecurityParameters {
        SnmpUsmSecurityParameters::new(
            [0x80, 0x00, 0x1f],
            7,
            9,
            [0xff, 0x00, b'u'],
            [0xaa, 0xbb, 0xcc],
            [0xde, 0xad],
        )
    }

    #[test]
    fn snmp_usm_parameters_compile_decode_and_hide_sensitive_bytes() -> Result<()> {
        let usm = sample_usm_parameters();
        let expected = [
            0x30, 0x19, 0x04, 0x03, 0x80, 0x00, 0x1f, 0x02, 0x01, 0x07, 0x02, 0x01, 0x09, 0x04,
            0x03, 0xff, 0x00, b'u', 0x04, 0x03, 0xaa, 0xbb, 0xcc, 0x04, 0x02, 0xde, 0xad,
        ];

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 3414 Section
        // 2.4 for the UsmSecurityParameters SEQUENCE and its six fields.
        assert_eq!(usm.encoded_len(), expected.len());
        assert_eq!(usm.compile()?, expected);

        let (decoded, rest) = SnmpUsmSecurityParameters::decode(&expected)?;
        assert!(rest.is_empty());
        assert_eq!(decoded.engine_id(), &[0x80, 0x00, 0x1f]);
        assert_eq!(decoded.engine_boots(), 7);
        assert_eq!(decoded.engine_time(), 9);
        assert_eq!(decoded.user_name(), &[0xff, 0x00, b'u']);
        assert_eq!(decoded.authentication_parameters(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(decoded.privacy_parameters(), &[0xde, 0xad]);
        assert_eq!(decoded.compile()?, expected);

        let summary = decoded.summary();
        assert!(summary.contains("engine_id_len=3"));
        assert!(summary.contains("user_name_len=3"));
        assert!(summary.contains("authentication_parameters_len=3"));
        assert!(!summary.contains("aa bb"));
        assert!(!decoded.show().contains("aa bb"));
        assert!(!decoded.show().contains("ff 00 75"));

        let raw = SnmpRawSecurityParameters::from_usm(&decoded)?;
        assert_eq!(raw.security_model(), registry::SNMP_SECURITY_MODEL_USM);
        assert_eq!(raw.bytes(), expected);
        assert_eq!(raw.as_usm()?.expect("USM parameters"), decoded);

        Ok(())
    }

    #[test]
    fn snmp_usm_parameters_v3_message_decode_preserves_raw_and_typed_forms() -> Result<()> {
        let usm = sample_usm_parameters();
        let message = SnmpV3Message::new_usm(
            11,
            1500,
            [0x00],
            usm.clone(),
            minimal_plaintext_v3_scoped_data(),
        )?;
        let snmp = Snmp::from_v3_message(message);
        let decoded = Snmp::decode(&snmp.compile()?)?;
        let v3 = decoded.as_v3().expect("v3 wrapper");
        let decoded_usm = v3
            .usm_security_parameters()?
            .expect("USM security parameters");

        assert_eq!(v3.security_model(), registry::SNMP_SECURITY_MODEL_USM);
        assert_eq!(v3.raw_security_parameters().bytes(), usm.compile()?);
        assert_eq!(decoded_usm, usm);
        assert_eq!(decoded.compile()?, snmp.compile()?);

        Ok(())
    }

    #[test]
    fn snmp_usm_parameters_malformed_uses_raw_fallback() -> Result<()> {
        let malformed = vec![0x30, 0x03, 0x04, 0x01, 0xaa];
        let snmp = Snmp::v3(
            12,
            1500,
            [0x00],
            registry::SNMP_SECURITY_MODEL_USM,
            malformed.clone(),
            minimal_plaintext_v3_scoped_data(),
        );
        let decoded = Snmp::decode(&snmp.compile()?)?;
        let v3 = decoded.as_v3().expect("v3 wrapper");
        let raw = v3.raw_security_parameters();

        assert_eq!(raw.security_model(), registry::SNMP_SECURITY_MODEL_USM);
        assert_eq!(raw.bytes(), malformed);
        assert_eq!(
            v3.usm_security_parameters().expect_err("malformed USM"),
            crate::error::CrafterError::buffer_too_short("snmp.ber.identifier", 1, 0)
        );
        assert_eq!(decoded.compile()?, snmp.compile()?);

        Ok(())
    }

    #[test]
    fn snmp_usm_engine_time_helpers_preserve_boundary_values() -> Result<()> {
        let engine_time = SnmpUsmEngineTime::new(0, i64::from(i32::MAX));
        assert_eq!(engine_time.engine_boots(), 0);
        assert_eq!(engine_time.engine_time(), i64::from(i32::MAX));
        assert!(engine_time.summary().contains("engine_boots=0"));
        assert!(engine_time.summary().contains("engine_time=2147483647"));

        let usm = SnmpUsmSecurityParameters::from_engine_time(
            [0x80, 0x00, 0x1f],
            engine_time,
            [b'u'],
            Vec::<u8>::new(),
            Vec::<u8>::new(),
        )
        .with_engine_boots(i64::from(i32::MAX))
        .with_engine_time(0);

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 3414 Section
        // 2.4 for msgAuthoritativeEngineBoots and msgAuthoritativeEngineTime.
        // The packet primitive preserves the caller's INTEGER values instead
        // of enforcing RFC 3414 timeliness windows.
        assert_eq!(
            usm.engine_time_fields(),
            SnmpUsmEngineTime::new(i64::from(i32::MAX), 0)
        );

        let encoded = usm.compile()?;
        assert!(encoded
            .windows(6)
            .any(|window| window == [0x02, 0x04, 0x7f, 0xff, 0xff, 0xff]));
        assert!(encoded
            .windows(3)
            .any(|window| window == [0x02, 0x01, 0x00]));

        let (decoded, rest) = SnmpUsmSecurityParameters::decode(&encoded)?;
        assert!(rest.is_empty());
        assert_eq!(
            decoded.engine_time_fields(),
            SnmpUsmEngineTime::new(i64::from(i32::MAX), 0)
        );
        assert_eq!(decoded.compile()?, encoded);

        Ok(())
    }

    #[test]
    fn snmp_usm_engine_time_decode_summary_and_inspection() -> Result<()> {
        let engine_time = SnmpUsmEngineTime::new(123, 456);
        let usm = sample_usm_parameters().with_engine_time_fields(engine_time);
        let encoded = usm.compile()?;
        let (decoded, rest) = SnmpUsmSecurityParameters::decode(&encoded)?;

        assert!(rest.is_empty());
        assert_eq!(decoded.engine_boots(), 123);
        assert_eq!(decoded.engine_time(), 456);
        assert_eq!(decoded.engine_time_fields(), engine_time);

        let summary = decoded.summary();
        assert!(summary.contains("engine_boots=123"));
        assert!(summary.contains("engine_time=456"));
        assert!(!summary.contains("aa bb"));
        assert!(engine_time.show().contains("usm_engine_boots: 123"));

        let fields = decoded.inspection_fields();
        assert!(fields
            .iter()
            .any(|(name, value)| *name == "usm_engine_boots" && value == "123"));
        assert!(fields
            .iter()
            .any(|(name, value)| *name == "usm_engine_time" && value == "456"));

        Ok(())
    }

    #[test]
    fn snmp_usm_engine_time_unknown_model_preserves_raw_bytes() -> Result<()> {
        let usm = sample_usm_parameters().with_engine_time_fields(SnmpUsmEngineTime::new(1, 2));
        let raw_bytes = usm.compile()?;
        let raw = SnmpRawSecurityParameters::new(999, raw_bytes.clone());

        assert_eq!(raw.as_usm()?, None);
        assert_eq!(raw.bytes(), raw_bytes);

        let snmp = Snmp::v3(
            13,
            1500,
            [0x00],
            raw.security_model(),
            raw.bytes().to_vec(),
            minimal_plaintext_v3_scoped_data(),
        );
        let decoded = Snmp::decode(&snmp.compile()?)?;
        let v3 = decoded.as_v3().expect("v3 wrapper");

        assert_eq!(v3.security_model(), 999);
        assert_eq!(v3.usm_security_parameters()?, None);
        assert_eq!(v3.raw_security_parameters().bytes(), raw_bytes);
        assert_eq!(decoded.compile()?, snmp.compile()?);

        Ok(())
    }

    #[test]
    fn snmp_usm_auth_params_setter_preserves_exact_bytes_and_lengths() -> Result<()> {
        let auth_parameters = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        ];
        let usm = sample_usm_parameters().with_authentication_parameters(auth_parameters);

        assert_eq!(usm.authentication_parameters(), auth_parameters);
        assert_eq!(usm.authentication_parameters_len(), auth_parameters.len());

        let encoded = usm.compile()?;
        let mut auth_tlv = vec![0x04, auth_parameters.len() as u8];
        auth_tlv.extend_from_slice(&auth_parameters);
        assert!(encoded
            .windows(auth_tlv.len())
            .any(|window| window == auth_tlv.as_slice()));

        let (decoded, rest) = SnmpUsmSecurityParameters::decode(&encoded)?;
        assert!(rest.is_empty());
        assert_eq!(decoded.authentication_parameters(), auth_parameters);
        assert_eq!(
            decoded.authentication_parameters_len(),
            auth_parameters.len()
        );
        assert_eq!(decoded.compile()?, encoded);

        Ok(())
    }

    #[test]
    fn snmp_usm_auth_params_arbitrary_lengths_remain_packet_bytes() -> Result<()> {
        let cases = [Vec::<u8>::new(), vec![0xaa], vec![0xbb; 12], vec![0xcc; 13]];

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 3414 Sections
        // 2.4, 6, and 7 for authentication-parameter bytes. `crafter`
        // preserves caller-provided bytes and lengths without requiring keys.
        for auth_parameters in cases {
            let usm =
                sample_usm_parameters().with_authentication_parameters(auth_parameters.clone());
            let decoded = SnmpUsmSecurityParameters::decode(&usm.compile()?)?.0;

            assert_eq!(decoded.authentication_parameters(), auth_parameters);
            assert_eq!(
                decoded.authentication_parameters_len(),
                auth_parameters.len()
            );
        }

        Ok(())
    }

    #[test]
    fn snmp_usm_auth_params_v3_message_roundtrips_without_secrets() -> Result<()> {
        let auth_parameters = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
        ];
        let usm = sample_usm_parameters().with_authentication_parameters(auth_parameters);
        let message = SnmpV3Message::new_usm(
            14,
            1500,
            [registry::SNMP_V3_FLAG_AUTH],
            usm.clone(),
            minimal_plaintext_v3_scoped_data(),
        )?;
        let snmp = Snmp::from_v3_message(message);
        let bytes = snmp.compile()?;
        let decoded = Snmp::decode(&bytes)?;
        let v3 = decoded.as_v3().expect("v3 wrapper");
        let decoded_usm = v3
            .usm_security_parameters()?
            .expect("USM security parameters");

        assert_eq!(decoded_usm.authentication_parameters(), auth_parameters);
        assert_eq!(v3.raw_security_parameters().bytes(), usm.compile()?);
        assert_eq!(decoded.compile()?, bytes);
        assert!(!decoded_usm.summary().contains("a0 a1"));
        assert!(!decoded_usm.show().contains("a0 a1"));
        assert!(!decoded.summary().contains("a0 a1"));

        Ok(())
    }

    #[test]
    fn snmp_v3_encrypted_pdu_builder_preserves_payload_and_privacy_params() -> Result<()> {
        let privacy_parameters = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        let encrypted_pdu = [0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
        let usm = sample_usm_parameters().with_privacy_parameters(privacy_parameters);
        let flags = [registry::SNMP_V3_FLAG_AUTH | registry::SNMP_V3_FLAG_PRIVACY];
        let snmp = Snmp::v3_encrypted_usm(15, 1500, flags, usm.clone(), encrypted_pdu)?;
        let decoded = Snmp::decode(&snmp.compile()?)?;
        let v3 = decoded.as_v3().expect("v3 wrapper");
        let encrypted = v3.encrypted_scoped_data()?.expect("encrypted scoped data");

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 3412 Section 6
        // for encryptedPDU as OCTET STRING and RFC 3414 Section 8 for privacy
        // parameter bytes. The packet primitive preserves both without keys.
        assert_eq!(v3.flags_value().privacy(), true);
        assert_eq!(v3.scoped_data_kind(), "encrypted");
        assert_eq!(v3.encrypted_scoped_pdu_len()?, Some(encrypted_pdu.len()));
        assert!(v3.scoped_pdu()?.is_none());
        assert_eq!(encrypted.encrypted_pdu(), encrypted_pdu);
        assert_eq!(encrypted.encrypted_pdu_len(), encrypted_pdu.len());
        assert_eq!(encrypted.privacy_parameters(), privacy_parameters);
        assert_eq!(encrypted.privacy_parameters_len(), privacy_parameters.len());
        assert_eq!(encrypted.compile()?, v3.scoped_data());
        assert_eq!(v3.raw_security_parameters().bytes(), usm.compile()?);
        assert_eq!(decoded.compile()?, snmp.compile()?);

        Ok(())
    }

    #[test]
    fn snmp_v3_encrypted_pdu_decode_opaque_variant_from_raw_wrapper() -> Result<()> {
        let privacy_parameters = [0x21, 0x22, 0x23, 0x24];
        let encrypted_pdu = [0x8a, 0x8b, 0x8c, 0x8d, 0x8e];
        let usm = sample_usm_parameters().with_privacy_parameters(privacy_parameters);
        let encrypted = SnmpEncryptedScopedData::new(privacy_parameters, encrypted_pdu);
        let snmp = Snmp::v3(
            16,
            1500,
            [registry::SNMP_V3_FLAG_PRIVACY],
            registry::SNMP_SECURITY_MODEL_USM,
            usm.compile()?,
            encrypted.compile()?,
        );
        let decoded = Snmp::decode(&snmp.compile()?)?;
        let v3 = decoded.as_v3().expect("v3 wrapper");
        let decoded_encrypted = v3.encrypted_scoped_data()?.expect("encrypted scoped data");

        assert_eq!(v3.scoped_data_kind(), "encrypted");
        assert_eq!(v3.scoped_data(), encrypted.compile()?);
        assert_eq!(decoded_encrypted.encrypted_pdu(), encrypted_pdu);
        assert_eq!(decoded_encrypted.privacy_parameters(), privacy_parameters);
        assert_eq!(decoded.compile()?, snmp.compile()?);

        Ok(())
    }

    #[test]
    fn snmp_v3_encrypted_pdu_safe_summaries_hide_secret_bytes() -> Result<()> {
        let privacy_parameters = [0x30, 0x31, 0x32, 0x33];
        let encrypted_pdu = [0xfa, 0xfb, 0xfc, 0xfd, 0xfe];
        let usm = sample_usm_parameters().with_privacy_parameters(privacy_parameters);
        let snmp = Snmp::v3_encrypted_usm(
            17,
            1500,
            [registry::SNMP_V3_FLAG_PRIVACY],
            usm,
            encrypted_pdu,
        )?;
        let decoded = Snmp::decode(&snmp.compile()?)?;
        let encrypted = decoded
            .as_v3()
            .expect("v3 wrapper")
            .encrypted_scoped_data()?
            .expect("encrypted scoped data");

        assert!(encrypted.summary().contains("encrypted_pdu_len=5"));
        assert!(encrypted.summary().contains("privacy_parameters_len=4"));
        assert!(!encrypted.summary().contains("fa fb"));
        assert!(!encrypted.show().contains("fa fb"));
        assert!(!encrypted.show().contains("30 31"));
        assert!(decoded.summary().contains("scoped_data_kind=encrypted"));
        assert!(decoded.summary().contains("encrypted_scoped_pdu_len=5"));
        assert!(!decoded.summary().contains("fa fb"));
        assert!(!decoded.show().contains("fa fb"));

        Ok(())
    }

    #[test]
    fn snmp_v3_report_plaintext_builder_compiles_decodes_and_summarizes() -> Result<()> {
        let oid = SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?;
        let varbinds = SnmpVarBindList::new(vec![SnmpVarBind::time_ticks(oid, 42)]);
        let snmp = Snmp::v3_report(
            18,
            1500,
            [registry::SNMP_V3_FLAG_REPORTABLE],
            registry::SNMP_SECURITY_MODEL_USM,
            Vec::<u8>::new(),
            b"engine".to_vec(),
            b"context".to_vec(),
            99,
            varbinds,
        )?;
        let bytes = snmp.compile()?;
        let decoded = Snmp::decode(&bytes)?;
        let v3 = decoded.as_v3().expect("v3 wrapper");
        let scoped = v3.scoped_pdu()?.expect("plaintext scoped PDU");
        let report = scoped.pdu().as_report()?.expect("Report fields");

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 3412 Section 6
        // for plaintext ScopedPDU and RFC 3416 Section 3 for Report-PDU tag 8.
        // The helper accepts caller-supplied report varbinds rather than
        // inventing source-unsupported named report shortcuts.
        assert_eq!(v3.scoped_data_kind(), "plaintext");
        assert_eq!(scoped.context_engine_id(), b"engine");
        assert_eq!(scoped.context_name(), b"context");
        assert_eq!(scoped.pdu().tag_number(), SnmpPdu::TAG_REPORT);
        assert_eq!(report.request_id(), 99);
        assert_eq!(report.error_status(), 0);
        assert_eq!(report.error_index(), 0);
        assert_eq!(report.varbinds().len(), 1);
        assert_eq!(decoded.compile()?, bytes);
        assert!(decoded.summary().contains("scoped_data_kind=plaintext"));
        assert!(scoped.summary().contains("pdu_type=report"));
        assert!(decoded.show().contains("msg_flags_reportable: true"));

        Ok(())
    }

    #[test]
    fn snmp_v3_report_usm_builder_preserves_security_and_context() -> Result<()> {
        let usm = sample_usm_parameters();
        let message = SnmpV3Message::new_usm_report(
            19,
            1500,
            [registry::SNMP_V3_FLAG_REPORTABLE],
            usm.clone(),
            [0x80, 0x00, 0x1f],
            Vec::<u8>::new(),
            100,
            SnmpVarBindList::empty(),
        )?;
        let snmp = Snmp::from_v3_message(message);
        let decoded = Snmp::decode(&snmp.compile()?)?;
        let v3 = decoded.as_v3().expect("v3 wrapper");
        let decoded_usm = v3
            .usm_security_parameters()?
            .expect("USM security parameters");
        let scoped = v3.scoped_pdu()?.expect("plaintext scoped PDU");
        let report = scoped.pdu().as_report()?.expect("Report fields");

        assert_eq!(decoded_usm, usm);
        assert_eq!(v3.raw_security_parameters().bytes(), usm.compile()?);
        assert_eq!(scoped.context_engine_id(), &[0x80, 0x00, 0x1f]);
        assert_eq!(scoped.context_name(), b"");
        assert_eq!(report.request_id(), 100);
        assert!(report.varbinds().is_empty());
        assert!(decoded.summary().contains("pdu_type=report"));
        assert_eq!(decoded.compile()?, snmp.compile()?);

        Ok(())
    }

    #[test]
    fn snmp_v3_report_layer_usm_builder_returns_packet_surface() -> Result<()> {
        let usm = sample_usm_parameters();
        let snmp = Snmp::v3_usm_report(
            20,
            1500,
            [registry::SNMP_V3_FLAG_REPORTABLE],
            usm,
            b"engine".to_vec(),
            Vec::<u8>::new(),
            101,
            SnmpVarBindList::empty(),
        )?;
        let packet = Packet::from_layer(snmp.clone());
        let decoded = Snmp::decode(&packet.compile()?)?;
        let report = decoded
            .as_v3()
            .expect("v3 wrapper")
            .scoped_pdu()?
            .expect("plaintext scoped PDU")
            .pdu()
            .as_report()?
            .expect("Report fields");

        assert_eq!(snmp.as_v3().expect("v3 wrapper").version(), SnmpVersion::V3);
        assert_eq!(report.request_id(), 101);
        assert!(packet.summary().contains("Snmp(version=v3"));
        assert!(packet.summary().contains("pdu_type=report"));

        Ok(())
    }

    #[test]
    fn snmp_v3_message_minimal_plaintext_compile_decode_roundtrips() -> Result<()> {
        let scoped_data = minimal_plaintext_v3_scoped_data();
        let snmp = Snmp::v3(1, 1500, [0x00], 3, Vec::<u8>::new(), scoped_data.clone());

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 3412 Sections
        // 6.1 through 6.8 for the v3 message wrapper fields and plaintext
        // ScopedPduData CHOICE.
        let expected = [
            0x30, 0x27, 0x02, 0x01, 0x03, 0x30, 0x0d, 0x02, 0x01, 0x01, 0x02, 0x02, 0x05, 0xdc,
            0x04, 0x01, 0x00, 0x02, 0x01, 0x03, 0x04, 0x00, 0x30, 0x11, 0x04, 0x00, 0x04, 0x00,
            0xa0, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];

        assert_eq!(snmp.version(), SnmpVersion::V3);
        assert_eq!(snmp.version_value(), 3);
        assert_eq!(snmp.community(), b"");
        assert!(snmp.pdu_opt().is_none());
        let v3 = snmp.as_v3().expect("v3 wrapper");
        assert_eq!(v3.msg_id(), 1);
        assert_eq!(v3.max_size(), 1500);
        assert_eq!(v3.flags(), &[0x00]);
        assert_eq!(v3.security_model(), 3);
        assert_eq!(v3.security_parameters(), b"");
        assert_eq!(v3.scoped_data(), scoped_data);
        assert_eq!(snmp.encoded_len(), expected.len());
        assert_eq!(snmp.compile()?, expected);

        let decoded = Snmp::decode(&expected)?;
        let decoded_v3 = decoded.as_v3().expect("decoded v3 wrapper");
        assert_eq!(decoded.version(), SnmpVersion::V3);
        assert_eq!(decoded_v3.msg_id(), 1);
        assert_eq!(decoded_v3.max_size(), 1500);
        assert_eq!(decoded_v3.flags(), &[0x00]);
        assert_eq!(decoded_v3.security_model(), 3);
        assert_eq!(decoded_v3.security_parameters(), b"");
        assert_eq!(decoded_v3.scoped_data(), scoped_data);
        assert_eq!(decoded.compile()?, expected);

        let summary = decoded.summary();
        assert!(summary.contains("version=v3"));
        assert!(summary.contains("msg_id=1"));
        assert!(summary.contains("msg_max_size=1500"));
        assert!(summary.contains("msg_security_model=3"));
        assert!(summary.contains("msg_security_parameters_len=0"));
        assert!(summary.contains("scoped_data_len=19"));

        let fields = decoded.inspection_fields();
        assert_eq!(inspection_value(&fields, "version"), Some("v3"));
        assert_eq!(inspection_value(&fields, "version_value"), Some("3"));
        assert_eq!(inspection_value(&fields, "msg_id"), Some("1"));
        assert_eq!(inspection_value(&fields, "msg_max_size"), Some("1500"));
        assert_eq!(inspection_value(&fields, "msg_flags"), Some("00"));
        assert_eq!(inspection_value(&fields, "msg_security_model"), Some("3"));
        assert_eq!(
            inspection_value(&fields, "msg_security_parameters_len"),
            Some("0")
        );
        assert_eq!(inspection_value(&fields, "scoped_data_len"), Some("19"));
        assert!(decoded.show().contains("  msg_id: 1"));

        Ok(())
    }

    #[test]
    fn snmp_v3_message_preserves_unknown_security_model_and_security_bytes() -> Result<()> {
        let scoped_data = minimal_plaintext_v3_scoped_data();
        let snmp = Snmp::v3(7, 65_535, [0x01], 999, [0xaa, 0xbb], scoped_data.clone());

        let bytes = snmp.compile()?;
        let decoded = Snmp::decode(&bytes)?;
        let v3 = decoded.as_v3().expect("decoded v3 wrapper");

        assert_eq!(v3.msg_id(), 7);
        assert_eq!(v3.max_size(), 65_535);
        assert_eq!(v3.flags(), &[0x01]);
        assert_eq!(v3.security_model(), 999);
        assert_eq!(v3.security_parameters(), &[0xaa, 0xbb]);
        assert_eq!(v3.scoped_data(), scoped_data);
        assert_eq!(decoded.compile()?, bytes);
        assert!(decoded.summary().contains("msg_security_parameters_len=2"));
        assert!(!decoded.summary().contains("aa bb"));
        assert!(!decoded.show().contains("aa bb"));

        Ok(())
    }

    #[test]
    fn snmp_message_decode_preserves_unknown_version_and_unknown_pdu() -> Result<()> {
        let bytes = [
            0x30, 0x0b, 0x02, 0x01, 0x04, 0x04, 0x01, b'x', 0xa9, 0x03, 0x02, 0x01, 0x05,
        ];

        let decoded = Snmp::decode(&bytes)?;
        let unknown = decoded.pdu().as_unknown().expect("unknown PDU");

        assert_eq!(decoded.version(), SnmpVersion::Unknown(4));
        assert_eq!(decoded.version_value(), 4);
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
            .with_version(SnmpVersion::Unknown(4))
            .with_community([0xff])
            .with_pdu(malformed_pdu);

        assert_eq!(snmp.version(), SnmpVersion::Unknown(4));
        assert_eq!(snmp.community(), &[0xff]);
        assert_eq!(snmp.pdu().explicit_length(), Some(0));
        assert_eq!(
            snmp.compile()?,
            [
                0x30, 0x13, 0x02, 0x01, 0x04, 0x04, 0x01, 0xff, 0xa0, 0x00, 0x02, 0x01, 0x01, 0x02,
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
            .with_version(SnmpVersion::Unknown(4));

        assert_eq!(snmp.version(), SnmpVersion::Unknown(4));
        assert_eq!(snmp.community(), &community);
        assert_eq!(
            snmp.compile()?,
            [
                0x30, 0x16, 0x02, 0x01, 0x04, 0x04, 0x04, 0x00, 0xff, 0x80, b'a', 0xa5, 0x0b, 0x02,
                0x01, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0a, 0x30, 0x00,
            ]
        );

        let bytes = snmp.compile()?;
        let content = ber::decode_sequence_exact(&bytes)?;
        let (header, rest) = SnmpMessageHeader::decode(content)?;
        let (pdu, rest) = SnmpPdu::decode(rest)?;
        ber::require_sequence_exact(rest)?;

        assert_eq!(header.version(), SnmpVersion::Unknown(4));
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

    fn inspection_value<'a>(
        fields: &'a [(&'static str, String)],
        name: &'static str,
    ) -> Option<&'a str> {
        fields
            .iter()
            .find_map(|(field, value)| (*field == name).then_some(value.as_str()))
    }

    fn assert_message_hides_community(snmp: &Snmp, community: &[u8]) {
        let secret = String::from_utf8_lossy(community);
        assert!(!snmp.summary().contains(secret.as_ref()));
        assert!(!snmp.show().contains(secret.as_ref()));
        assert!(!snmp
            .inspection_fields()
            .iter()
            .any(|(_, value)| value == secret.as_ref()));
    }

    #[test]
    fn snmp_message_summary_v1_request_exposes_safe_fields() -> Result<()> {
        let community = b"public";
        let varbind =
            crate::protocols::snmp::SnmpVarBind::null(SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?);
        let snmp = Snmp::v1_get_request(
            community.to_vec(),
            7,
            crate::protocols::snmp::SnmpVarBindList::new(vec![varbind]),
        )?;

        let summary = snmp.summary();
        assert!(summary.contains("version=v1"));
        assert!(summary.contains("community_len=6"));
        assert!(summary.contains("pdu_type=get-request"));
        assert!(summary.contains("request_id=7"));
        assert!(summary.contains("varbind_count=1"));

        let fields = snmp.inspection_fields();
        assert_eq!(inspection_value(&fields, "version"), Some("v1"));
        assert_eq!(inspection_value(&fields, "version_value"), Some("0"));
        assert_eq!(inspection_value(&fields, "community_len"), Some("6"));
        assert_eq!(inspection_value(&fields, "pdu_type"), Some("get-request"));
        assert_eq!(inspection_value(&fields, "request_id"), Some("7"));
        assert_eq!(inspection_value(&fields, "varbind_count"), Some("1"));
        assert_message_hides_community(&snmp, community);

        let show = snmp.show();
        assert!(show.starts_with("Snmp\n"));
        assert!(show.contains("  version: v1"));
        assert!(show.contains("  community_len: 6"));
        assert!(show.contains("  pdu_type: get-request"));

        Ok(())
    }

    #[test]
    fn snmp_message_summary_v2c_response_exposes_request_and_error_fields() -> Result<()> {
        let community = b"private";
        let snmp = Snmp::v2c_response_error(
            community.to_vec(),
            128,
            2,
            3,
            crate::protocols::snmp::SnmpVarBindList::empty(),
        )?;

        let summary = snmp.summary();
        assert!(summary.contains("version=v2c"));
        assert!(summary.contains("community_len=7"));
        assert!(summary.contains("pdu_type=response"));
        assert!(summary.contains("request_id=128"));
        assert!(summary.contains("error_status=no-such-name(2)"));
        assert!(summary.contains("varbind_count=0"));

        let fields = snmp.inspection_fields();
        assert_eq!(inspection_value(&fields, "version"), Some("v2c"));
        assert_eq!(inspection_value(&fields, "version_value"), Some("1"));
        assert_eq!(inspection_value(&fields, "pdu_type"), Some("response"));
        assert_eq!(inspection_value(&fields, "request_id"), Some("128"));
        assert_eq!(inspection_value(&fields, "error_status"), Some("2"));
        assert_eq!(
            inspection_value(&fields, "error_status_label"),
            Some("no-such-name")
        );
        assert_message_hides_community(&snmp, community);

        Ok(())
    }

    #[test]
    fn snmp_message_summary_unknown_pdu_keeps_raw_metadata_visible() {
        let community = b"public";
        let snmp = Snmp::v2c(
            community.to_vec(),
            SnmpPdu::unknown(9, true, [0x02, 0x01, 0x05]),
        );

        assert_eq!(
            snmp.summary(),
            "Snmp(version=v2c, community_len=6, pdu=SnmpPdu(pdu_type=pdu-9 pdu_tag=9 constructed=true body_length=3))"
        );
        let fields = snmp.inspection_fields();
        assert_eq!(inspection_value(&fields, "pdu_type"), Some("pdu-9"));
        assert_eq!(inspection_value(&fields, "pdu_tag"), Some("9"));
        assert_eq!(inspection_value(&fields, "pdu_tag_status"), Some("unknown"));
        assert_eq!(inspection_value(&fields, "pdu_ber_length"), Some("3"));
        assert_eq!(inspection_value(&fields, "body_bytes"), Some("02 01 05"));
        assert_message_hides_community(&snmp, community);
    }

    #[test]
    fn snmp_message_summary_raw_tlv_varbind_keeps_value_metadata_visible() -> Result<()> {
        let community = b"agent-secret";
        let raw = crate::protocols::snmp::SnmpVarBind::raw_value_tlv(
            SnmpOid::from_dotted("1.3.6.1.2.1.1.5.0")?,
            [0xc3, 0x81, 0x02, 0xde, 0xad],
        );
        let snmp = Snmp::v2c_response(
            community.to_vec(),
            9,
            crate::protocols::snmp::SnmpVarBindList::new(vec![raw]),
        )?;

        let summary = snmp.summary();
        assert!(summary.contains("pdu_type=response"));
        assert!(summary.contains("request_id=9"));
        assert!(summary.contains("varbind_count=1"));

        let fields = snmp.inspection_fields();
        assert_eq!(
            inspection_value(&fields, "varbind[0]"),
            Some("1.3.6.1.2.1.1.5.0=private-3")
        );
        assert!(snmp.show().contains("private-3"));
        assert_message_hides_community(&snmp, community);

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

    #[test]
    fn snmp_defaults_overrides_auto_fill_and_preserve_malformed_message_fields() -> Result<()> {
        let name = SnmpOid::from_dotted("1.3.6.1.2.1.1.5.0")?;
        let raw_varbind = SnmpVarBind::raw_value_tlv_with_length(name, 0x04, 5, [0xaa])?;
        let varbinds = SnmpVarBindList::new(vec![raw_varbind]).length(0);
        let pdu = SnmpPdu::get_request_with_fields(127, 99, 300, varbinds)?.length(0);
        let snmp = Snmp::v2c_get_request(b"public".to_vec(), 1, SnmpVarBindList::empty())?
            .with_version(SnmpVersion::Unknown(4))
            .with_community([0x00, 0xff])
            .with_pdu(pdu)
            .length(3);

        let bytes = snmp.compile()?;
        assert_eq!(snmp.explicit_length(), Some(3));
        assert_eq!(snmp.effective_length(), 3);
        assert_eq!(snmp.encoded_len(), bytes.len());
        assert_eq!(&bytes[..2], &[0x30, 0x03]);
        assert_eq!(&bytes[2..9], &[0x02, 0x01, 0x04, 0x04, 0x02, 0x00, 0xff]);
        assert_eq!(&bytes[9..11], &[0xa0, 0x00]);
        assert_eq!(
            &bytes[11..],
            &[
                0x02, 0x01, 0x7f, 0x02, 0x01, 0x63, 0x02, 0x02, 0x01, 0x2c, 0x30, 0x00, 0x30, 0x0d,
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x04, 0x05, 0xaa,
            ]
        );

        let auto = snmp.clone().clear_length();
        let auto_bytes = auto.compile()?;
        assert_eq!(auto.explicit_length(), None);
        assert_eq!(auto.effective_length(), auto_bytes.len() - 2);
        assert_eq!(&auto_bytes[..2], &[0x30, 0x24]);
        assert_eq!(&auto_bytes[2..], &bytes[2..]);

        let raw_pdu_message = [
            0x30, 0x0c, 0x02, 0x01, 0x04, 0x04, 0x01, b'x', 0xa9, 0x81, 0x03, 0x02, 0x01, 0x05,
        ];
        let decoded = Snmp::decode(&raw_pdu_message)?;
        assert_eq!(decoded.version(), SnmpVersion::Unknown(4));
        assert_eq!(decoded.community(), b"x");
        assert_eq!(decoded.pdu().raw_tlv_bytes(), Some(&raw_pdu_message[8..]));
        assert_eq!(decoded.compile()?, raw_pdu_message);

        Ok(())
    }
}
