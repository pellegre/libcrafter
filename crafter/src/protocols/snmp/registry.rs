//! SNMP registry metadata.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`; this module does not register
//! UDP dispatch or expose payload detection.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use super::{ber, constants};

/// Source-backed assignment status for an SNMP PDU tag number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnmpPduTagStatus {
    /// Assigned by the manifest-backed SNMP PDU sources.
    Assigned,
    /// Not assigned by the manifest-backed SNMP PDU sources.
    Unknown,
}

impl SnmpPduTagStatus {
    /// Stable lowercase status label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for SnmpPduTagStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Source-backed SNMP UDP service metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnmpUdpPortMeta {
    /// UDP port number.
    pub port: u16,
    /// IANA service name.
    pub name: &'static str,
    /// Packet-layer role of the port for SNMP traffic.
    pub role: &'static str,
}

/// Return source-backed metadata for SNMP UDP ports.
///
/// Source: `docs/snmp-rfc-manifest.md` records the IANA Service Name and
/// Transport Protocol Port Number Registry rows for `snmp`/UDP and
/// `snmptrap`/UDP, plus RFC 3417 Section 3 for UDP/IPv4 SNMP messages.
pub const fn snmp_udp_port_meta(port: u16) -> Option<SnmpUdpPortMeta> {
    match port {
        constants::SNMP_PORT => Some(SnmpUdpPortMeta {
            port,
            name: "snmp",
            role: "message",
        }),
        constants::SNMP_TRAP_PORT => Some(SnmpUdpPortMeta {
            port,
            name: "snmptrap",
            role: "notification",
        }),
        _ => None,
    }
}

/// Return the IANA service name for a source-backed SNMP UDP port.
pub const fn snmp_udp_port_name(port: u16) -> Option<&'static str> {
    match snmp_udp_port_meta(port) {
        Some(meta) => Some(meta.name),
        None => None,
    }
}

/// Return a stable SNMP UDP port label while preserving unknown values.
pub fn snmp_udp_port_label(port: u16) -> String {
    snmp_udp_port_name(port)
        .map(str::to_string)
        .unwrap_or_else(|| format!("udp-port-{port}"))
}

/// Return a compact summary label for an SNMP UDP port.
pub fn snmp_udp_port_summary(port: u16) -> String {
    format!("{}({port})", snmp_udp_port_label(port))
}

/// SNMPv3 msgFlags authFlag bit.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3412 Section 6.4.
pub const SNMP_V3_FLAG_AUTH: u8 = 0x01;
/// SNMPv3 msgFlags privFlag bit.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3412 Section 6.4.
pub const SNMP_V3_FLAG_PRIVACY: u8 = 0x02;
/// SNMPv3 msgFlags reportableFlag bit.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3412 Section 6.4.
pub const SNMP_V3_FLAG_REPORTABLE: u8 = 0x04;
/// Source-backed SNMPv3 msgFlags bits currently named by RFC 3412.
pub const SNMP_V3_FLAG_KNOWN_MASK: u8 =
    SNMP_V3_FLAG_AUTH | SNMP_V3_FLAG_PRIVACY | SNMP_V3_FLAG_REPORTABLE;
/// SNMPv3 msgFlags bits reserved by RFC 3412 Section 6.4.
pub const SNMP_V3_FLAG_RESERVED_MASK: u8 = !SNMP_V3_FLAG_KNOWN_MASK;

/// Typed view of one SNMPv3 msgFlags octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnmpV3Flags {
    bits: u8,
}

impl SnmpV3Flags {
    /// Wrap one raw msgFlags octet without validation.
    pub const fn new(bits: u8) -> Self {
        Self { bits }
    }

    /// Build from raw OCTET STRING bytes, using the first octet when present.
    pub fn from_octets(octets: &[u8]) -> Self {
        Self::new(octets.first().copied().unwrap_or(0))
    }

    /// Raw msgFlags bits.
    pub const fn bits(self) -> u8 {
        self.bits
    }

    /// Whether authFlag is set.
    pub const fn auth(self) -> bool {
        self.bits & SNMP_V3_FLAG_AUTH != 0
    }

    /// Whether privFlag is set.
    pub const fn privacy(self) -> bool {
        self.bits & SNMP_V3_FLAG_PRIVACY != 0
    }

    /// Whether reportableFlag is set.
    pub const fn reportable(self) -> bool {
        self.bits & SNMP_V3_FLAG_REPORTABLE != 0
    }

    /// Reserved msgFlags bits preserved from the raw octet.
    pub const fn reserved_bits(self) -> u8 {
        self.bits & SNMP_V3_FLAG_RESERVED_MASK
    }

    /// Whether any reserved msgFlags bit is set.
    pub const fn has_reserved_bits(self) -> bool {
        self.reserved_bits() != 0
    }

    /// Whether privFlag is set without authFlag.
    ///
    /// RFC 3412 names this bit combination as reserved. The packet layer only
    /// reports it; it does not reject or enforce security policy.
    pub const fn has_reserved_auth_priv_combination(self) -> bool {
        self.privacy() && !self.auth()
    }

    /// Stable label preserving named and reserved bits.
    pub fn label(self) -> String {
        snmp_v3_flags_label(self.bits)
    }
}

impl From<u8> for SnmpV3Flags {
    fn from(bits: u8) -> Self {
        Self::new(bits)
    }
}

impl From<SnmpV3Flags> for u8 {
    fn from(flags: SnmpV3Flags) -> Self {
        flags.bits()
    }
}

impl fmt::Display for SnmpV3Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Return a stable label for one SNMPv3 msgFlags octet.
pub fn snmp_v3_flags_label(bits: u8) -> String {
    let flags = SnmpV3Flags::new(bits);
    let mut labels = Vec::new();
    if flags.auth() {
        labels.push("auth".to_string());
    }
    if flags.privacy() {
        labels.push("privacy".to_string());
    }
    if flags.reportable() {
        labels.push("reportable".to_string());
    }
    if flags.has_reserved_bits() {
        labels.push(format!("reserved-0x{:02x}", flags.reserved_bits()));
    }

    if labels.is_empty() {
        "none".to_string()
    } else {
        labels.join("|")
    }
}

/// Source-backed assignment status for an SNMPv3 security model value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnmpSecurityModelStatus {
    /// Reserved by the IANA SNMP number-space registry.
    Reserved,
    /// Assigned by the IANA SNMP number-space registry.
    Assigned,
    /// In-range but unassigned by the IANA SNMP number-space registry.
    Unassigned,
    /// Outside the manifest-backed registry range.
    Unknown,
}

impl SnmpSecurityModelStatus {
    /// Stable lowercase status label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Assigned => "assigned",
            Self::Unassigned => "unassigned",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for SnmpSecurityModelStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// any(0) security model value, reserved by IANA.
pub const SNMP_SECURITY_MODEL_ANY: i64 = 0;
/// SNMPv1 security model value.
pub const SNMP_SECURITY_MODEL_SNMPV1: i64 = 1;
/// SNMPv2c security model value.
pub const SNMP_SECURITY_MODEL_SNMPV2C: i64 = 2;
/// User-based Security Model value.
pub const SNMP_SECURITY_MODEL_USM: i64 = 3;
/// Transport Security Model value.
pub const SNMP_SECURITY_MODEL_TSM: i64 = 4;

/// One source-backed SNMPv3 security model metadata entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnmpSecurityModelMeta {
    /// INTEGER value carried by msgSecurityModel.
    pub code: i64,
    /// Stable short name, or a preservation label for unassigned/unknown.
    pub name: &'static str,
    /// Assignment status from the manifest-backed IANA registry.
    pub status: SnmpSecurityModelStatus,
}

/// A typed SNMPv3 security model value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnmpSecurityModel {
    code: i64,
}

impl SnmpSecurityModel {
    /// Wrap a raw msgSecurityModel INTEGER value without validation.
    pub const fn new(code: i64) -> Self {
        Self { code }
    }

    /// Raw INTEGER value carried by msgSecurityModel.
    pub const fn code(self) -> i64 {
        self.code
    }

    /// Source-backed metadata for this security model value.
    pub const fn meta(self) -> SnmpSecurityModelMeta {
        snmp_security_model_meta(self.code)
    }

    /// Source-backed name for assigned or reserved values.
    pub const fn name(self) -> Option<&'static str> {
        snmp_security_model_name(self.code)
    }

    /// Source-backed assignment status for this value.
    pub const fn status(self) -> SnmpSecurityModelStatus {
        snmp_security_model_status(self.code)
    }

    /// Stable label that preserves unassigned and unknown values.
    pub fn label(self) -> String {
        snmp_security_model_label(self.code)
    }

    /// Compact summary label with the numeric code.
    pub fn summary(self) -> String {
        snmp_security_model_summary(self.code)
    }
}

impl From<i64> for SnmpSecurityModel {
    fn from(code: i64) -> Self {
        Self::new(code)
    }
}

impl From<SnmpSecurityModel> for i64 {
    fn from(model: SnmpSecurityModel) -> Self {
        model.code()
    }
}

impl fmt::Display for SnmpSecurityModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Return source-backed metadata for an SNMPv3 security model value.
///
/// Source: `docs/snmp-rfc-manifest.md` records the IANA SNMP Number Spaces
/// Security Models rows: 0 reserved for any, 1 SNMPv1, 2 SNMPv2c, 3 USM,
/// 4 TSM, and 5-255 unassigned.
pub const fn snmp_security_model_meta(code: i64) -> SnmpSecurityModelMeta {
    let (name, status) = match code {
        SNMP_SECURITY_MODEL_ANY => ("any", SnmpSecurityModelStatus::Reserved),
        SNMP_SECURITY_MODEL_SNMPV1 => ("snmpv1", SnmpSecurityModelStatus::Assigned),
        SNMP_SECURITY_MODEL_SNMPV2C => ("snmpv2c", SnmpSecurityModelStatus::Assigned),
        SNMP_SECURITY_MODEL_USM => ("usm", SnmpSecurityModelStatus::Assigned),
        SNMP_SECURITY_MODEL_TSM => ("tsm", SnmpSecurityModelStatus::Assigned),
        5..=255 => (
            "unassigned-security-model",
            SnmpSecurityModelStatus::Unassigned,
        ),
        _ => ("unknown-security-model", SnmpSecurityModelStatus::Unknown),
    };

    SnmpSecurityModelMeta { code, name, status }
}

/// Return the source-backed security model name for assigned or reserved values.
pub const fn snmp_security_model_name(code: i64) -> Option<&'static str> {
    let meta = snmp_security_model_meta(code);
    match meta.status {
        SnmpSecurityModelStatus::Reserved | SnmpSecurityModelStatus::Assigned => Some(meta.name),
        SnmpSecurityModelStatus::Unassigned | SnmpSecurityModelStatus::Unknown => None,
    }
}

/// Return the source-backed assignment status for a security model value.
pub const fn snmp_security_model_status(code: i64) -> SnmpSecurityModelStatus {
    snmp_security_model_meta(code).status
}

/// Return a stable security-model label while preserving unknown values.
pub fn snmp_security_model_label(code: i64) -> String {
    snmp_security_model_name(code)
        .map(str::to_string)
        .unwrap_or_else(|| format!("security-model-{code}"))
}

/// Return a compact summary label with the numeric security-model code.
pub fn snmp_security_model_summary(code: i64) -> String {
    format!("{}({code})", snmp_security_model_label(code))
}

/// noError(0) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 1157 Section 4.1.1 and
/// RFC 3416 Section 3 as error-status authority.
pub const SNMP_ERROR_STATUS_NO_ERROR: i64 = 0;
/// tooBig(1) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 1157 Section 4.1.1 and
/// RFC 3416 Section 3 as error-status authority.
pub const SNMP_ERROR_STATUS_TOO_BIG: i64 = 1;
/// noSuchName(2) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 1157 Section 4.1.1 and
/// RFC 3416 Section 3 as error-status authority.
pub const SNMP_ERROR_STATUS_NO_SUCH_NAME: i64 = 2;
/// badValue(3) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 1157 Section 4.1.1 and
/// RFC 3416 Section 3 as error-status authority.
pub const SNMP_ERROR_STATUS_BAD_VALUE: i64 = 3;
/// readOnly(4) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 1157 Section 4.1.1 and
/// RFC 3416 Section 3 as error-status authority.
pub const SNMP_ERROR_STATUS_READ_ONLY: i64 = 4;
/// genErr(5) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 1157 Section 4.1.1 and
/// RFC 3416 Section 3 as error-status authority.
pub const SNMP_ERROR_STATUS_GEN_ERR: i64 = 5;
/// noAccess(6) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3416 Section 3 as
/// error-status authority.
pub const SNMP_ERROR_STATUS_NO_ACCESS: i64 = 6;
/// wrongType(7) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3416 Section 3 as
/// error-status authority.
pub const SNMP_ERROR_STATUS_WRONG_TYPE: i64 = 7;
/// wrongLength(8) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3416 Section 3 as
/// error-status authority.
pub const SNMP_ERROR_STATUS_WRONG_LENGTH: i64 = 8;
/// wrongEncoding(9) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3416 Section 3 as
/// error-status authority.
pub const SNMP_ERROR_STATUS_WRONG_ENCODING: i64 = 9;
/// wrongValue(10) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3416 Section 3 as
/// error-status authority.
pub const SNMP_ERROR_STATUS_WRONG_VALUE: i64 = 10;
/// noCreation(11) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3416 Section 3 as
/// error-status authority.
pub const SNMP_ERROR_STATUS_NO_CREATION: i64 = 11;
/// inconsistentValue(12) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3416 Section 3 as
/// error-status authority.
pub const SNMP_ERROR_STATUS_INCONSISTENT_VALUE: i64 = 12;
/// resourceUnavailable(13) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3416 Section 3 as
/// error-status authority.
pub const SNMP_ERROR_STATUS_RESOURCE_UNAVAILABLE: i64 = 13;
/// commitFailed(14) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3416 Section 3 as
/// error-status authority.
pub const SNMP_ERROR_STATUS_COMMIT_FAILED: i64 = 14;
/// undoFailed(15) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3416 Section 3 as
/// error-status authority.
pub const SNMP_ERROR_STATUS_UNDO_FAILED: i64 = 15;
/// authorizationError(16) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3416 Section 3 as
/// error-status authority.
pub const SNMP_ERROR_STATUS_AUTHORIZATION_ERROR: i64 = 16;
/// notWritable(17) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3416 Section 3 as
/// error-status authority.
pub const SNMP_ERROR_STATUS_NOT_WRITABLE: i64 = 17;
/// inconsistentName(18) error-status value.
///
/// Source: `docs/snmp-rfc-manifest.md` records RFC 3416 Section 3 as
/// error-status authority.
pub const SNMP_ERROR_STATUS_INCONSISTENT_NAME: i64 = 18;

/// Source-backed assignment status for an SNMP PDU error-status value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnmpErrorStatusAssignment {
    /// Assigned by the manifest-backed SNMP error-status sources.
    Assigned,
    /// Not assigned by the manifest-backed SNMP error-status sources.
    Unknown,
}

impl SnmpErrorStatusAssignment {
    /// Stable lowercase status label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for SnmpErrorStatusAssignment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One source-backed SNMP error-status metadata entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnmpErrorStatusMeta {
    /// INTEGER value carried by the PDU error-status field.
    pub code: i64,
    /// Stable short name, or `"unknown-error-status"` for unassigned values.
    pub name: &'static str,
    /// Assignment status from the manifest-backed error-status registry.
    pub status: SnmpErrorStatusAssignment,
}

/// A typed SNMP PDU error-status value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnmpErrorStatus {
    code: i64,
}

impl SnmpErrorStatus {
    /// Wrap a raw PDU error-status INTEGER value without validation.
    pub const fn new(code: i64) -> Self {
        Self { code }
    }

    /// Raw INTEGER value carried by the PDU error-status field.
    pub const fn code(self) -> i64 {
        self.code
    }

    /// Source-backed metadata for this error-status value.
    pub const fn meta(self) -> SnmpErrorStatusMeta {
        snmp_error_status_meta(self.code)
    }

    /// Source-backed name for assigned values.
    pub const fn name(self) -> Option<&'static str> {
        snmp_error_status_name(self.code)
    }

    /// Source-backed assignment status for this value.
    pub const fn status(self) -> SnmpErrorStatusAssignment {
        snmp_error_status_status(self.code)
    }

    /// Stable label that preserves unknown values.
    pub fn label(self) -> String {
        snmp_error_status_label(self.code)
    }

    /// Compact summary label with the numeric code.
    pub fn summary(self) -> String {
        snmp_error_status_summary(self.code)
    }
}

impl From<i64> for SnmpErrorStatus {
    fn from(code: i64) -> Self {
        Self::new(code)
    }
}

impl From<SnmpErrorStatus> for i64 {
    fn from(status: SnmpErrorStatus) -> Self {
        status.code()
    }
}

impl fmt::Display for SnmpErrorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Return source-backed metadata for an SNMP PDU error-status value.
///
/// Source: RFC 1157 Section 4.1.1 and RFC 3416 Section 3, both recorded in
/// `docs/snmp-rfc-manifest.md`.
pub const fn snmp_error_status_meta(code: i64) -> SnmpErrorStatusMeta {
    let (name, status) = match code {
        SNMP_ERROR_STATUS_NO_ERROR => ("no-error", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_TOO_BIG => ("too-big", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_NO_SUCH_NAME => ("no-such-name", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_BAD_VALUE => ("bad-value", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_READ_ONLY => ("read-only", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_GEN_ERR => ("gen-err", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_NO_ACCESS => ("no-access", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_WRONG_TYPE => ("wrong-type", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_WRONG_LENGTH => ("wrong-length", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_WRONG_ENCODING => ("wrong-encoding", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_WRONG_VALUE => ("wrong-value", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_NO_CREATION => ("no-creation", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_INCONSISTENT_VALUE => {
            ("inconsistent-value", SnmpErrorStatusAssignment::Assigned)
        }
        SNMP_ERROR_STATUS_RESOURCE_UNAVAILABLE => {
            ("resource-unavailable", SnmpErrorStatusAssignment::Assigned)
        }
        SNMP_ERROR_STATUS_COMMIT_FAILED => ("commit-failed", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_UNDO_FAILED => ("undo-failed", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_AUTHORIZATION_ERROR => {
            ("authorization-error", SnmpErrorStatusAssignment::Assigned)
        }
        SNMP_ERROR_STATUS_NOT_WRITABLE => ("not-writable", SnmpErrorStatusAssignment::Assigned),
        SNMP_ERROR_STATUS_INCONSISTENT_NAME => {
            ("inconsistent-name", SnmpErrorStatusAssignment::Assigned)
        }
        _ => ("unknown-error-status", SnmpErrorStatusAssignment::Unknown),
    };

    SnmpErrorStatusMeta { code, name, status }
}

/// Return the source-backed error-status name for an assigned value.
pub const fn snmp_error_status_name(code: i64) -> Option<&'static str> {
    let meta = snmp_error_status_meta(code);
    match meta.status {
        SnmpErrorStatusAssignment::Assigned => Some(meta.name),
        SnmpErrorStatusAssignment::Unknown => None,
    }
}

/// Return the source-backed assignment status for an error-status value.
pub const fn snmp_error_status_status(code: i64) -> SnmpErrorStatusAssignment {
    snmp_error_status_meta(code).status
}

/// Return a stable error-status label while preserving unknown values.
pub fn snmp_error_status_label(code: i64) -> String {
    snmp_error_status_name(code)
        .map(str::to_string)
        .unwrap_or_else(|| format!("error-status-{code}"))
}

/// Return a compact summary label with the numeric error-status code.
pub fn snmp_error_status_summary(code: i64) -> String {
    format!("{}({code})", snmp_error_status_label(code))
}

/// One source-backed SNMP PDU tag metadata entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnmpPduTagMeta {
    /// Low-tag-number value from the context-specific BER identifier.
    pub tag_number: u8,
    /// Stable short name, or `"unknown-pdu"` for unassigned tags.
    pub name: &'static str,
    /// Assignment status from the manifest-backed PDU matrix.
    pub status: SnmpPduTagStatus,
}

/// Return source-backed metadata for an SNMP PDU tag number.
///
/// Source: RFC 1157 Sections 4.1.2 through 4.1.6 and RFC 3416 Section 3.
pub const fn snmp_pdu_tag_meta(tag_number: u8) -> SnmpPduTagMeta {
    let (name, status) = match tag_number {
        constants::SNMP_PDU_TAG_GET_REQUEST => ("get-request", SnmpPduTagStatus::Assigned),
        constants::SNMP_PDU_TAG_GET_NEXT_REQUEST => {
            ("get-next-request", SnmpPduTagStatus::Assigned)
        }
        constants::SNMP_PDU_TAG_RESPONSE => ("response", SnmpPduTagStatus::Assigned),
        constants::SNMP_PDU_TAG_SET_REQUEST => ("set-request", SnmpPduTagStatus::Assigned),
        constants::SNMP_PDU_TAG_TRAP => ("trap", SnmpPduTagStatus::Assigned),
        constants::SNMP_PDU_TAG_GET_BULK_REQUEST => {
            ("get-bulk-request", SnmpPduTagStatus::Assigned)
        }
        constants::SNMP_PDU_TAG_INFORM_REQUEST => ("inform-request", SnmpPduTagStatus::Assigned),
        constants::SNMP_PDU_TAG_TRAP_V2 => ("snmpv2-trap", SnmpPduTagStatus::Assigned),
        constants::SNMP_PDU_TAG_REPORT => ("report", SnmpPduTagStatus::Assigned),
        _ => ("unknown-pdu", SnmpPduTagStatus::Unknown),
    };

    SnmpPduTagMeta {
        tag_number,
        name,
        status,
    }
}

/// Return the source-backed PDU name for an assigned tag number.
pub const fn snmp_pdu_tag_name(tag_number: u8) -> Option<&'static str> {
    let meta = snmp_pdu_tag_meta(tag_number);
    match meta.status {
        SnmpPduTagStatus::Assigned => Some(meta.name),
        SnmpPduTagStatus::Unknown => None,
    }
}

/// Return the source-backed assignment status for a PDU tag number.
pub const fn snmp_pdu_tag_status(tag_number: u8) -> SnmpPduTagStatus {
    snmp_pdu_tag_meta(tag_number).status
}

pub(super) fn pdu_tag_label(tag_number: u8) -> String {
    snmp_pdu_tag_name(tag_number)
        .map(str::to_string)
        .unwrap_or_else(|| format!("pdu-{tag_number}"))
}

pub(super) fn application_tag_name(tag_number: u8) -> Option<&'static str> {
    match tag_number {
        ber::SNMP_APPLICATION_TAG_IP_ADDRESS => Some("ip-address"),
        ber::SNMP_APPLICATION_TAG_COUNTER32 => Some("counter32"),
        ber::SNMP_APPLICATION_TAG_GAUGE32_OR_UNSIGNED32 => Some("gauge32-or-unsigned32"),
        ber::SNMP_APPLICATION_TAG_TIME_TICKS => Some("time-ticks"),
        ber::SNMP_APPLICATION_TAG_OPAQUE => Some("opaque"),
        ber::SNMP_APPLICATION_TAG_COUNTER64 => Some("counter64"),
        _ => None,
    }
}

pub(super) fn application_tag_label(tag_number: u8, constructed: bool) -> String {
    if !constructed {
        if let Some(name) = application_tag_name(tag_number) {
            return name.to_string();
        }
    }

    if constructed {
        format!("constructed-application-{tag_number}")
    } else {
        format!("application-{tag_number}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_udp_ports_constants_and_labels_source_backed() {
        let cases = [
            (constants::SNMP_PORT, "snmp", "message"),
            (constants::SNMP_TRAP_PORT, "snmptrap", "notification"),
        ];

        // Source-backed: docs/snmp-rfc-manifest.md records the IANA service
        // name registry rows for UDP/161 `snmp` and UDP/162 `snmptrap`; RFC
        // 3417 Section 3 records the preferred UDP/IPv4 mapping for messages.
        assert_eq!(constants::SNMP_PORT, 161);
        assert_eq!(constants::SNMP_TRAP_PORT, 162);
        for (port, name, role) in cases {
            let meta = snmp_udp_port_meta(port).expect("SNMP UDP port");

            assert_eq!(meta.port, port);
            assert_eq!(meta.name, name);
            assert_eq!(meta.role, role);
            assert_eq!(snmp_udp_port_name(port), Some(name));
            assert_eq!(snmp_udp_port_label(port), name);
            assert_eq!(snmp_udp_port_summary(port), format!("{name}({port})"));
        }

        assert_eq!(snmp_udp_port_meta(5161), None);
        assert_eq!(snmp_udp_port_name(5161), None);
        assert_eq!(snmp_udp_port_label(5161), "udp-port-5161");
        assert_eq!(snmp_udp_port_summary(5161), "udp-port-5161(5161)");
    }

    #[test]
    fn snmp_v3_flags_helpers_name_bits_and_preserve_reserved_bits() {
        let flags = SnmpV3Flags::new(
            SNMP_V3_FLAG_AUTH | SNMP_V3_FLAG_PRIVACY | SNMP_V3_FLAG_REPORTABLE | 0x80,
        );

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 3412 Section
        // 6.4 for authFlag, privFlag, reportableFlag, reserved msgFlags bits,
        // and the reserved privFlag-without-authFlag combination.
        assert_eq!(flags.bits(), 0x87);
        assert!(flags.auth());
        assert!(flags.privacy());
        assert!(flags.reportable());
        assert_eq!(flags.reserved_bits(), 0x80);
        assert!(flags.has_reserved_bits());
        assert!(!flags.has_reserved_auth_priv_combination());
        assert_eq!(flags.label(), "auth|privacy|reportable|reserved-0x80");
        assert_eq!(flags.to_string(), flags.label());
        assert_eq!(u8::from(flags), 0x87);
        assert_eq!(
            SnmpV3Flags::from_octets(&[0xff, 0x00]),
            SnmpV3Flags::new(0xff)
        );
        assert_eq!(SnmpV3Flags::from_octets(&[]).label(), "none");

        let privacy_without_auth = SnmpV3Flags::new(SNMP_V3_FLAG_PRIVACY);
        assert!(privacy_without_auth.privacy());
        assert!(!privacy_without_auth.auth());
        assert!(privacy_without_auth.has_reserved_auth_priv_combination());
        assert_eq!(snmp_v3_flags_label(0), "none");
    }

    #[test]
    fn snmp_v3_flags_security_model_registry_names_source_backed_values() {
        let cases = [
            (
                SNMP_SECURITY_MODEL_ANY,
                "any",
                SnmpSecurityModelStatus::Reserved,
            ),
            (
                SNMP_SECURITY_MODEL_SNMPV1,
                "snmpv1",
                SnmpSecurityModelStatus::Assigned,
            ),
            (
                SNMP_SECURITY_MODEL_SNMPV2C,
                "snmpv2c",
                SnmpSecurityModelStatus::Assigned,
            ),
            (
                SNMP_SECURITY_MODEL_USM,
                "usm",
                SnmpSecurityModelStatus::Assigned,
            ),
            (
                SNMP_SECURITY_MODEL_TSM,
                "tsm",
                SnmpSecurityModelStatus::Assigned,
            ),
        ];

        // Source-backed: docs/snmp-rfc-manifest.md records the IANA SNMP
        // Number Spaces Security Models rows.
        for (code, name, status) in cases {
            let meta = snmp_security_model_meta(code);
            let model = SnmpSecurityModel::new(code);

            assert_eq!(meta.code, code);
            assert_eq!(meta.name, name);
            assert_eq!(meta.status, status);
            assert_eq!(snmp_security_model_name(code), Some(name));
            assert_eq!(snmp_security_model_status(code), status);
            assert_eq!(snmp_security_model_label(code), name);
            assert_eq!(snmp_security_model_summary(code), format!("{name}({code})"));
            assert_eq!(model.meta(), meta);
            assert_eq!(model.name(), Some(name));
            assert_eq!(model.status(), status);
            assert_eq!(model.to_string(), name);
            assert_eq!(i64::from(model), code);
        }

        assert_eq!(SnmpSecurityModelStatus::Assigned.label(), "assigned");
        assert_eq!(SnmpSecurityModelStatus::Reserved.to_string(), "reserved");
    }

    #[test]
    fn snmp_v3_flags_security_model_registry_preserves_unassigned_and_unknowns() {
        let unassigned = snmp_security_model_meta(99);
        assert_eq!(unassigned.name, "unassigned-security-model");
        assert_eq!(unassigned.status, SnmpSecurityModelStatus::Unassigned);
        assert_eq!(snmp_security_model_name(99), None);
        assert_eq!(snmp_security_model_label(99), "security-model-99");
        assert_eq!(snmp_security_model_summary(99), "security-model-99(99)");

        for code in [-1, 256, 999] {
            let meta = snmp_security_model_meta(code);
            let model = SnmpSecurityModel::new(code);

            assert_eq!(meta.code, code);
            assert_eq!(meta.name, "unknown-security-model");
            assert_eq!(meta.status, SnmpSecurityModelStatus::Unknown);
            assert_eq!(snmp_security_model_name(code), None);
            assert_eq!(
                snmp_security_model_status(code),
                SnmpSecurityModelStatus::Unknown
            );
            assert_eq!(
                snmp_security_model_label(code),
                format!("security-model-{code}")
            );
            assert_eq!(model.summary(), format!("security-model-{code}({code})"));
        }
    }

    #[test]
    fn snmp_pdu_tags_registry_names_source_backed_tags_and_unknowns() {
        let cases = [
            (constants::SNMP_PDU_TAG_GET_REQUEST, "get-request"),
            (constants::SNMP_PDU_TAG_GET_NEXT_REQUEST, "get-next-request"),
            (constants::SNMP_PDU_TAG_RESPONSE, "response"),
            (constants::SNMP_PDU_TAG_SET_REQUEST, "set-request"),
            (constants::SNMP_PDU_TAG_TRAP, "trap"),
            (constants::SNMP_PDU_TAG_GET_BULK_REQUEST, "get-bulk-request"),
            (constants::SNMP_PDU_TAG_INFORM_REQUEST, "inform-request"),
            (constants::SNMP_PDU_TAG_TRAP_V2, "snmpv2-trap"),
            (constants::SNMP_PDU_TAG_REPORT, "report"),
        ];

        for (tag, name) in cases {
            let meta = snmp_pdu_tag_meta(tag);
            assert_eq!(meta.tag_number, tag);
            assert_eq!(meta.name, name);
            assert_eq!(meta.status, SnmpPduTagStatus::Assigned);
            assert_eq!(snmp_pdu_tag_name(tag), Some(name));
            assert_eq!(snmp_pdu_tag_status(tag), SnmpPduTagStatus::Assigned);
            assert_eq!(pdu_tag_label(tag), name);
        }

        let unknown = snmp_pdu_tag_meta(9);
        assert_eq!(unknown.name, "unknown-pdu");
        assert_eq!(unknown.status, SnmpPduTagStatus::Unknown);
        assert_eq!(snmp_pdu_tag_name(9), None);
        assert_eq!(snmp_pdu_tag_status(9), SnmpPduTagStatus::Unknown);
        assert_eq!(pdu_tag_label(9), "pdu-9");
        assert_eq!(SnmpPduTagStatus::Assigned.label(), "assigned");
        assert_eq!(SnmpPduTagStatus::Unknown.to_string(), "unknown");
    }

    #[test]
    fn snmp_error_status_registry_names_source_backed_values() {
        let cases = [
            (SNMP_ERROR_STATUS_NO_ERROR, "no-error"),
            (SNMP_ERROR_STATUS_TOO_BIG, "too-big"),
            (SNMP_ERROR_STATUS_NO_SUCH_NAME, "no-such-name"),
            (SNMP_ERROR_STATUS_BAD_VALUE, "bad-value"),
            (SNMP_ERROR_STATUS_READ_ONLY, "read-only"),
            (SNMP_ERROR_STATUS_GEN_ERR, "gen-err"),
            (SNMP_ERROR_STATUS_NO_ACCESS, "no-access"),
            (SNMP_ERROR_STATUS_WRONG_TYPE, "wrong-type"),
            (SNMP_ERROR_STATUS_WRONG_LENGTH, "wrong-length"),
            (SNMP_ERROR_STATUS_WRONG_ENCODING, "wrong-encoding"),
            (SNMP_ERROR_STATUS_WRONG_VALUE, "wrong-value"),
            (SNMP_ERROR_STATUS_NO_CREATION, "no-creation"),
            (SNMP_ERROR_STATUS_INCONSISTENT_VALUE, "inconsistent-value"),
            (
                SNMP_ERROR_STATUS_RESOURCE_UNAVAILABLE,
                "resource-unavailable",
            ),
            (SNMP_ERROR_STATUS_COMMIT_FAILED, "commit-failed"),
            (SNMP_ERROR_STATUS_UNDO_FAILED, "undo-failed"),
            (SNMP_ERROR_STATUS_AUTHORIZATION_ERROR, "authorization-error"),
            (SNMP_ERROR_STATUS_NOT_WRITABLE, "not-writable"),
            (SNMP_ERROR_STATUS_INCONSISTENT_NAME, "inconsistent-name"),
        ];

        // Source-backed: docs/snmp-rfc-manifest.md records RFC 1157 Section
        // 4.1.1 for values 0 through 5 and RFC 3416 Section 3 for values
        // 0 through 18.
        for (code, name) in cases {
            let meta = snmp_error_status_meta(code);
            assert_eq!(meta.code, code);
            assert_eq!(meta.name, name);
            assert_eq!(meta.status, SnmpErrorStatusAssignment::Assigned);
            assert_eq!(snmp_error_status_name(code), Some(name));
            assert_eq!(
                snmp_error_status_status(code),
                SnmpErrorStatusAssignment::Assigned
            );
            assert_eq!(snmp_error_status_label(code), name);
            assert_eq!(SnmpErrorStatus::new(code).name(), Some(name));
            assert_eq!(SnmpErrorStatus::new(code).code(), code);
            assert_eq!(SnmpErrorStatus::new(code).to_string(), name);
        }

        assert_eq!(SnmpErrorStatusAssignment::Assigned.label(), "assigned");
        assert_eq!(SnmpErrorStatusAssignment::Unknown.to_string(), "unknown");
    }

    #[test]
    fn snmp_error_status_registry_unknown_values_are_preserved() {
        for code in [-1, 19, 99] {
            let meta = snmp_error_status_meta(code);
            let status = SnmpErrorStatus::new(code);

            assert_eq!(meta.code, code);
            assert_eq!(meta.name, "unknown-error-status");
            assert_eq!(meta.status, SnmpErrorStatusAssignment::Unknown);
            assert_eq!(snmp_error_status_name(code), None);
            assert_eq!(
                snmp_error_status_status(code),
                SnmpErrorStatusAssignment::Unknown
            );
            assert_eq!(
                snmp_error_status_label(code),
                format!("error-status-{code}")
            );
            assert_eq!(
                snmp_error_status_summary(code),
                format!("error-status-{code}({code})")
            );
            assert_eq!(status.meta(), meta);
            assert_eq!(status.status(), SnmpErrorStatusAssignment::Unknown);
            assert_eq!(i64::from(status), code);
        }
    }

    #[test]
    fn snmp_application_values_registry_labels_source_backed_tags_and_unknowns() {
        let cases = [
            (ber::SNMP_APPLICATION_TAG_IP_ADDRESS, "ip-address"),
            (ber::SNMP_APPLICATION_TAG_COUNTER32, "counter32"),
            (
                ber::SNMP_APPLICATION_TAG_GAUGE32_OR_UNSIGNED32,
                "gauge32-or-unsigned32",
            ),
            (ber::SNMP_APPLICATION_TAG_TIME_TICKS, "time-ticks"),
            (ber::SNMP_APPLICATION_TAG_OPAQUE, "opaque"),
            (ber::SNMP_APPLICATION_TAG_COUNTER64, "counter64"),
        ];

        for (tag, label) in cases {
            assert_eq!(application_tag_name(tag), Some(label));
            assert_eq!(application_tag_label(tag, false), label);
        }

        assert_eq!(application_tag_name(5), None);
        assert_eq!(application_tag_label(5, false), "application-5");
        assert_eq!(application_tag_label(5, true), "constructed-application-5");
        assert_eq!(
            application_tag_label(ber::SNMP_APPLICATION_TAG_IP_ADDRESS, true),
            "constructed-application-0"
        );
    }
}
