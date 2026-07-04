//! SCTP parameter model.
//!
//! RFC 9260 section 3.2.1 defines SCTP parameters as four-octet-aligned TLVs:
//! type, length, value bytes, and padding. This module keeps that envelope
//! byte-preserving while later steps add parameter-specific semantic fields.

#![allow(dead_code)]

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::str;

use crate::error::{CrafterError, Result};

use super::chunk::SctpChunkType;
use super::constants::{
    SCTP_ALIGNMENT, SCTP_CHUNK_TYPE_ASCONF, SCTP_CHUNK_TYPE_ASCONF_ACK, SCTP_CHUNK_TYPE_AUTH,
    SCTP_CHUNK_TYPE_COOKIE_ECHO, SCTP_CHUNK_TYPE_DATA, SCTP_CHUNK_TYPE_FORWARD_TSN,
    SCTP_CHUNK_TYPE_INIT, SCTP_CHUNK_TYPE_INIT_ACK, SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE,
    SCTP_PARAMETER_HEADER_LEN, SCTP_PARAMETER_TYPE_ADAPTATION_LAYER_INDICATION,
    SCTP_PARAMETER_TYPE_ADD_INCOMING_STREAMS_REQUEST, SCTP_PARAMETER_TYPE_ADD_IP_ADDRESS,
    SCTP_PARAMETER_TYPE_ADD_OUTGOING_STREAMS_REQUEST, SCTP_PARAMETER_TYPE_CHUNK_LIST,
    SCTP_PARAMETER_TYPE_COOKIE_PRESERVATIVE, SCTP_PARAMETER_TYPE_DELETE_IP_ADDRESS,
    SCTP_PARAMETER_TYPE_DTLS_KEY_MANAGEMENT, SCTP_PARAMETER_TYPE_ECN_CAPABLE,
    SCTP_PARAMETER_TYPE_ERROR_CAUSE_INDICATION, SCTP_PARAMETER_TYPE_FORWARD_TSN_SUPPORTED,
    SCTP_PARAMETER_TYPE_HEARTBEAT_INFO, SCTP_PARAMETER_TYPE_HOST_NAME_ADDRESS,
    SCTP_PARAMETER_TYPE_IETF_DEFINED_EXTENSION, SCTP_PARAMETER_TYPE_INCOMING_SSN_RESET_REQUEST,
    SCTP_PARAMETER_TYPE_IPV4_ADDRESS, SCTP_PARAMETER_TYPE_IPV6_ADDRESS,
    SCTP_PARAMETER_TYPE_OUTGOING_SSN_RESET_REQUEST, SCTP_PARAMETER_TYPE_PADDING,
    SCTP_PARAMETER_TYPE_RANDOM, SCTP_PARAMETER_TYPE_REQUESTED_HMAC_ALGORITHM,
    SCTP_PARAMETER_TYPE_RE_CONFIGURATION_RESPONSE, SCTP_PARAMETER_TYPE_SET_PRIMARY_ADDRESS,
    SCTP_PARAMETER_TYPE_SSN_TSN_RESET_REQUEST, SCTP_PARAMETER_TYPE_STATE_COOKIE,
    SCTP_PARAMETER_TYPE_SUCCESS_INDICATION, SCTP_PARAMETER_TYPE_SUPPORTED_ADDRESS_TYPES,
    SCTP_PARAMETER_TYPE_SUPPORTED_EXTENSIONS, SCTP_PARAMETER_TYPE_UNRECOGNIZED_PARAMETER,
    SCTP_PARAMETER_TYPE_ZERO_CHECKSUM_ACCEPTABLE,
};

/// Mask for the two highest bits carrying the unknown-parameter action class.
pub const SCTP_PARAMETER_TYPE_UNKNOWN_ACTION_MASK: u16 = 0xc000;
/// Mask for the lower 14 bits of an SCTP parameter type value.
pub const SCTP_PARAMETER_TYPE_VALUE_BITS_MASK: u16 = 0x3fff;
/// Unknown-parameter action bits: stop processing further parameters in this chunk.
pub const SCTP_PARAMETER_UNKNOWN_ACTION_STOP: u8 = 0b00;
/// Unknown-parameter action bits: stop processing and report the parameter.
pub const SCTP_PARAMETER_UNKNOWN_ACTION_STOP_AND_REPORT: u8 = 0b01;
/// Unknown-parameter action bits: skip this parameter and continue processing.
pub const SCTP_PARAMETER_UNKNOWN_ACTION_SKIP: u8 = 0b10;
/// Unknown-parameter action bits: skip this parameter, continue processing, and report it.
pub const SCTP_PARAMETER_UNKNOWN_ACTION_SKIP_AND_REPORT: u8 = 0b11;

/// Registry classification for an SCTP parameter type codepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SctpParameterTypeStatus {
    /// Assigned by the current SCTP parameter-type registry.
    Assigned,
    /// Reserved by the current SCTP parameter-type registry.
    Reserved,
    /// Temporary or draft-backed registry row.
    Temporary,
    /// Currently unassigned registry value.
    Unassigned,
}

impl SctpParameterTypeStatus {
    /// Stable lowercase status label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::Reserved => "reserved",
            Self::Temporary => "temporary",
            Self::Unassigned => "unassigned",
        }
    }
}

impl fmt::Display for SctpParameterTypeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// RFC 9260 unknown-parameter action encoded in the highest two type bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SctpUnknownParameterAction {
    /// Stop processing this parameter and any further parameters in this chunk.
    Stop,
    /// Stop processing this parameter and any further parameters in this chunk, and report it.
    StopAndReport,
    /// Skip this parameter and continue processing.
    Skip,
    /// Skip this parameter, continue processing, and report it.
    SkipAndReport,
}

impl SctpUnknownParameterAction {
    /// Preserve or classify raw unknown-parameter action bits.
    pub const fn new(bits: u8) -> Self {
        match bits & 0b11 {
            SCTP_PARAMETER_UNKNOWN_ACTION_STOP => Self::Stop,
            SCTP_PARAMETER_UNKNOWN_ACTION_STOP_AND_REPORT => Self::StopAndReport,
            SCTP_PARAMETER_UNKNOWN_ACTION_SKIP => Self::Skip,
            _ => Self::SkipAndReport,
        }
    }

    /// Preserve or classify raw unknown-parameter action bits.
    pub const fn from_bits(bits: u8) -> Self {
        Self::new(bits)
    }

    /// Return the raw two-bit action value.
    pub const fn raw_bits(self) -> u8 {
        match self {
            Self::Stop => SCTP_PARAMETER_UNKNOWN_ACTION_STOP,
            Self::StopAndReport => SCTP_PARAMETER_UNKNOWN_ACTION_STOP_AND_REPORT,
            Self::Skip => SCTP_PARAMETER_UNKNOWN_ACTION_SKIP,
            Self::SkipAndReport => SCTP_PARAMETER_UNKNOWN_ACTION_SKIP_AND_REPORT,
        }
    }

    /// Stable lowercase action label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::StopAndReport => "stop-and-report",
            Self::Skip => "skip",
            Self::SkipAndReport => "skip-and-report",
        }
    }

    /// Return true when this action stops further parameter processing in the containing chunk.
    pub const fn stops_parameter_processing(self) -> bool {
        matches!(self, Self::Stop | Self::StopAndReport)
    }

    /// Return true when this action skips the unknown parameter and continues processing.
    pub const fn skips_parameter(self) -> bool {
        matches!(self, Self::Skip | Self::SkipAndReport)
    }

    /// Return true when this action requires reporting the unrecognized parameter.
    pub const fn reports_unrecognized_parameter(self) -> bool {
        matches!(self, Self::StopAndReport | Self::SkipAndReport)
    }
}

impl fmt::Display for SctpUnknownParameterAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<u8> for SctpUnknownParameterAction {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<SctpUnknownParameterAction> for u8 {
    fn from(value: SctpUnknownParameterAction) -> Self {
        value.raw_bits()
    }
}

/// Return the RFC 9260 unknown-parameter action bits from a parameter type value.
pub const fn sctp_parameter_type_unknown_action_bits(parameter_type: u16) -> u8 {
    ((parameter_type & SCTP_PARAMETER_TYPE_UNKNOWN_ACTION_MASK) >> 14) as u8
}

/// Return the RFC 9260 unknown-parameter action from a parameter type value.
pub const fn sctp_parameter_type_unknown_action(parameter_type: u16) -> SctpUnknownParameterAction {
    SctpUnknownParameterAction::new(sctp_parameter_type_unknown_action_bits(parameter_type))
}

/// Return the lower 14 parameter type bits without the unknown-parameter action class.
pub const fn sctp_parameter_type_value_bits_without_unknown_action(parameter_type: u16) -> u16 {
    parameter_type & SCTP_PARAMETER_TYPE_VALUE_BITS_MASK
}

/// Build a parameter type value from an unknown-parameter action and lower 14 type bits.
pub const fn sctp_parameter_type_from_unknown_action_and_value_bits(
    action: SctpUnknownParameterAction,
    value_bits: u16,
) -> u16 {
    ((action.raw_bits() as u16) << 14) | (value_bits & SCTP_PARAMETER_TYPE_VALUE_BITS_MASK)
}

/// Return the source-backed registry status for an SCTP parameter type.
pub const fn sctp_parameter_type_status(parameter_type: u16) -> SctpParameterTypeStatus {
    match parameter_type {
        SCTP_PARAMETER_TYPE_HEARTBEAT_INFO
        | SCTP_PARAMETER_TYPE_IPV4_ADDRESS
        | SCTP_PARAMETER_TYPE_IPV6_ADDRESS
        | SCTP_PARAMETER_TYPE_STATE_COOKIE
        | SCTP_PARAMETER_TYPE_UNRECOGNIZED_PARAMETER
        | SCTP_PARAMETER_TYPE_COOKIE_PRESERVATIVE
        | SCTP_PARAMETER_TYPE_HOST_NAME_ADDRESS
        | SCTP_PARAMETER_TYPE_SUPPORTED_ADDRESS_TYPES
        | SCTP_PARAMETER_TYPE_OUTGOING_SSN_RESET_REQUEST
        | SCTP_PARAMETER_TYPE_INCOMING_SSN_RESET_REQUEST
        | SCTP_PARAMETER_TYPE_SSN_TSN_RESET_REQUEST
        | SCTP_PARAMETER_TYPE_RE_CONFIGURATION_RESPONSE
        | SCTP_PARAMETER_TYPE_ADD_OUTGOING_STREAMS_REQUEST
        | SCTP_PARAMETER_TYPE_ADD_INCOMING_STREAMS_REQUEST
        | SCTP_PARAMETER_TYPE_ZERO_CHECKSUM_ACCEPTABLE
        | SCTP_PARAMETER_TYPE_RANDOM
        | SCTP_PARAMETER_TYPE_CHUNK_LIST
        | SCTP_PARAMETER_TYPE_REQUESTED_HMAC_ALGORITHM
        | SCTP_PARAMETER_TYPE_PADDING
        | SCTP_PARAMETER_TYPE_SUPPORTED_EXTENSIONS
        | SCTP_PARAMETER_TYPE_FORWARD_TSN_SUPPORTED
        | SCTP_PARAMETER_TYPE_ADD_IP_ADDRESS
        | SCTP_PARAMETER_TYPE_DELETE_IP_ADDRESS
        | SCTP_PARAMETER_TYPE_ERROR_CAUSE_INDICATION
        | SCTP_PARAMETER_TYPE_SET_PRIMARY_ADDRESS
        | SCTP_PARAMETER_TYPE_SUCCESS_INDICATION
        | SCTP_PARAMETER_TYPE_ADAPTATION_LAYER_INDICATION => SctpParameterTypeStatus::Assigned,
        SCTP_PARAMETER_TYPE_ECN_CAPABLE | SCTP_PARAMETER_TYPE_IETF_DEFINED_EXTENSION => {
            SctpParameterTypeStatus::Reserved
        }
        SCTP_PARAMETER_TYPE_DTLS_KEY_MANAGEMENT => SctpParameterTypeStatus::Temporary,
        _ => SctpParameterTypeStatus::Unassigned,
    }
}

/// Return true when the parameter type is currently assigned.
pub const fn sctp_parameter_type_is_assigned(parameter_type: u16) -> bool {
    matches!(
        sctp_parameter_type_status(parameter_type),
        SctpParameterTypeStatus::Assigned
    )
}

/// Return true when the parameter type is currently reserved.
pub const fn sctp_parameter_type_is_reserved(parameter_type: u16) -> bool {
    matches!(
        sctp_parameter_type_status(parameter_type),
        SctpParameterTypeStatus::Reserved
    )
}

/// Return true when the parameter type is currently temporary.
pub const fn sctp_parameter_type_is_temporary(parameter_type: u16) -> bool {
    matches!(
        sctp_parameter_type_status(parameter_type),
        SctpParameterTypeStatus::Temporary
    )
}

/// Return true when the parameter type is currently unassigned.
pub const fn sctp_parameter_type_is_unassigned(parameter_type: u16) -> bool {
    matches!(
        sctp_parameter_type_status(parameter_type),
        SctpParameterTypeStatus::Unassigned
    )
}

/// Return the source-backed registry label for a known SCTP parameter type.
pub const fn sctp_parameter_type_name(parameter_type: u16) -> Option<&'static str> {
    match parameter_type {
        SCTP_PARAMETER_TYPE_HEARTBEAT_INFO => Some("Heartbeat Info"),
        SCTP_PARAMETER_TYPE_IPV4_ADDRESS => Some("IPv4 Address"),
        SCTP_PARAMETER_TYPE_IPV6_ADDRESS => Some("IPv6 Address"),
        SCTP_PARAMETER_TYPE_STATE_COOKIE => Some("State Cookie"),
        SCTP_PARAMETER_TYPE_UNRECOGNIZED_PARAMETER => Some("Unrecognized Parameter"),
        SCTP_PARAMETER_TYPE_COOKIE_PRESERVATIVE => Some("Cookie Preservative"),
        SCTP_PARAMETER_TYPE_HOST_NAME_ADDRESS => Some("Host Name Address"),
        SCTP_PARAMETER_TYPE_SUPPORTED_ADDRESS_TYPES => Some("Supported Address Types"),
        SCTP_PARAMETER_TYPE_OUTGOING_SSN_RESET_REQUEST => {
            Some("Outgoing SSN Reset Request Parameter")
        }
        SCTP_PARAMETER_TYPE_INCOMING_SSN_RESET_REQUEST => {
            Some("Incoming SSN Reset Request Parameter")
        }
        SCTP_PARAMETER_TYPE_SSN_TSN_RESET_REQUEST => Some("SSN/TSN Reset Request Parameter"),
        SCTP_PARAMETER_TYPE_RE_CONFIGURATION_RESPONSE => {
            Some("Re-configuration Response Parameter")
        }
        SCTP_PARAMETER_TYPE_ADD_OUTGOING_STREAMS_REQUEST => {
            Some("Add Outgoing Streams Request Parameter")
        }
        SCTP_PARAMETER_TYPE_ADD_INCOMING_STREAMS_REQUEST => {
            Some("Add Incoming Streams Request Parameter")
        }
        SCTP_PARAMETER_TYPE_ECN_CAPABLE => Some("Reserved for ECN Capable"),
        SCTP_PARAMETER_TYPE_ZERO_CHECKSUM_ACCEPTABLE => Some("Zero Checksum Acceptable"),
        SCTP_PARAMETER_TYPE_RANDOM => Some("Random"),
        SCTP_PARAMETER_TYPE_CHUNK_LIST => Some("Chunk List"),
        SCTP_PARAMETER_TYPE_REQUESTED_HMAC_ALGORITHM => Some("Requested HMAC Algorithm Parameter"),
        SCTP_PARAMETER_TYPE_PADDING => Some("Padding"),
        SCTP_PARAMETER_TYPE_DTLS_KEY_MANAGEMENT => Some("DTLS Key Management"),
        SCTP_PARAMETER_TYPE_SUPPORTED_EXTENSIONS => Some("Supported Extensions"),
        SCTP_PARAMETER_TYPE_FORWARD_TSN_SUPPORTED => Some("Forward TSN supported"),
        SCTP_PARAMETER_TYPE_ADD_IP_ADDRESS => Some("Add IP Address"),
        SCTP_PARAMETER_TYPE_DELETE_IP_ADDRESS => Some("Delete IP Address"),
        SCTP_PARAMETER_TYPE_ERROR_CAUSE_INDICATION => Some("Error Cause Indication"),
        SCTP_PARAMETER_TYPE_SET_PRIMARY_ADDRESS => Some("Set Primary Address"),
        SCTP_PARAMETER_TYPE_SUCCESS_INDICATION => Some("Success Indication"),
        SCTP_PARAMETER_TYPE_ADAPTATION_LAYER_INDICATION => Some("Adaptation Layer Indication"),
        SCTP_PARAMETER_TYPE_IETF_DEFINED_EXTENSION => {
            Some("Reserved for IETF-defined Chunk Extensions")
        }
        _ => None,
    }
}

/// Raw-preserving SCTP parameter type value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SctpParameterType(u16);

impl SctpParameterType {
    /// Preserve a raw 16-bit SCTP parameter type codepoint.
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Preserve a raw 16-bit SCTP parameter type codepoint.
    pub const fn from_u16(raw: u16) -> Self {
        Self::new(raw)
    }

    /// Return the preserved raw SCTP parameter type codepoint.
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Return the preserved raw SCTP parameter type codepoint.
    pub const fn as_u16(self) -> u16 {
        self.raw()
    }

    /// Return the RFC 9260 unknown-parameter action bits from the type value.
    pub const fn unknown_action_bits(self) -> u8 {
        sctp_parameter_type_unknown_action_bits(self.raw())
    }

    /// Return the RFC 9260 unknown-parameter action label from the type value.
    pub const fn unknown_action(self) -> SctpUnknownParameterAction {
        sctp_parameter_type_unknown_action(self.raw())
    }

    /// Return the lower 14 type bits without the unknown-parameter action class.
    pub const fn value_bits_without_unknown_action(self) -> u16 {
        sctp_parameter_type_value_bits_without_unknown_action(self.raw())
    }

    /// Build a parameter type from an unknown-parameter action and lower 14 type bits.
    pub const fn from_unknown_action_and_value_bits(
        action: SctpUnknownParameterAction,
        value_bits: u16,
    ) -> Self {
        Self::new(sctp_parameter_type_from_unknown_action_and_value_bits(
            action, value_bits,
        ))
    }

    /// Return the source-backed registry status for this parameter type.
    pub const fn status(self) -> SctpParameterTypeStatus {
        sctp_parameter_type_status(self.raw())
    }

    /// Return true when this parameter type is currently assigned.
    pub const fn is_assigned(self) -> bool {
        sctp_parameter_type_is_assigned(self.raw())
    }

    /// Return true when this parameter type is currently reserved.
    pub const fn is_reserved(self) -> bool {
        sctp_parameter_type_is_reserved(self.raw())
    }

    /// Return true when this parameter type is currently temporary.
    pub const fn is_temporary(self) -> bool {
        sctp_parameter_type_is_temporary(self.raw())
    }

    /// Return true when this parameter type is currently unassigned.
    pub const fn is_unassigned(self) -> bool {
        sctp_parameter_type_is_unassigned(self.raw())
    }

    /// Return the source-backed registry label for this parameter type, when known.
    pub const fn name(self) -> Option<&'static str> {
        sctp_parameter_type_name(self.raw())
    }
}

impl From<u16> for SctpParameterType {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<SctpParameterType> for u16 {
    fn from(value: SctpParameterType) -> Self {
        value.raw()
    }
}

/// Return the SCTP parameter padding length implied by a declared parameter length.
///
/// RFC 9260 section 3.2.1 keeps parameter padding outside the declared Length
/// field and aligns each parameter to a four-octet boundary.
pub const fn sctp_parameter_padding_len(declared_length: usize) -> usize {
    (SCTP_ALIGNMENT - (declared_length % SCTP_ALIGNMENT)) % SCTP_ALIGNMENT
}

/// Return a declared SCTP parameter length rounded up to the next parameter boundary.
pub const fn sctp_parameter_padded_len(declared_length: usize) -> usize {
    declared_length + sctp_parameter_padding_len(declared_length)
}

/// Decode a byte sequence of SCTP parameters into raw-preserving parameter models.
pub fn decode_parameters(bytes: impl AsRef<[u8]>) -> Result<Vec<SctpParameter>> {
    let bytes = bytes.as_ref();
    let mut parameters = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() {
        let available = bytes.len() - offset;
        if available < SCTP_PARAMETER_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "sctp.parameter.header",
                SCTP_PARAMETER_HEADER_LEN,
                available,
            ));
        }

        let parameter_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let declared_length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
        let declared_length_usize = usize::from(declared_length);
        if declared_length_usize < SCTP_PARAMETER_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "sctp.parameter.length",
                "declared length must be at least 4 bytes",
            ));
        }

        let padded_length = sctp_parameter_padded_len(declared_length_usize);
        if padded_length > available {
            return Err(CrafterError::buffer_too_short(
                "sctp.parameter",
                padded_length,
                available,
            ));
        }

        let value_start = offset + SCTP_PARAMETER_HEADER_LEN;
        let value_end = offset + declared_length_usize;
        let padding_end = offset + padded_length;
        parameters.push(SctpParameter::from_preserved_parts(
            parameter_type,
            declared_length,
            bytes[value_start..value_end].to_vec(),
            bytes[value_end..padding_end].to_vec(),
        ));
        offset += padded_length;
    }

    Ok(parameters)
}

/// Append one SCTP parameter envelope to `out`.
pub fn encode_parameter(parameter: &SctpParameter, out: &mut Vec<u8>) -> Result<()> {
    let declared_length = parameter.explicit_declared_length().map_or_else(
        || {
            let declared_length = SCTP_PARAMETER_HEADER_LEN
                .checked_add(parameter.value_len())
                .ok_or_else(|| {
                    CrafterError::invalid_field_value("sctp.parameter.length", "length overflow")
                })?;
            u16::try_from(declared_length).map_err(|_| {
                CrafterError::invalid_field_value(
                    "sctp.parameter.length",
                    "length must fit in two bytes",
                )
            })
        },
        Ok,
    )?;

    out.extend_from_slice(&parameter.parameter_type_value().to_be_bytes());
    out.extend_from_slice(&declared_length.to_be_bytes());
    out.extend_from_slice(parameter.value());

    if parameter.padding().is_empty() {
        out.resize(
            out.len() + sctp_parameter_padding_len(usize::from(declared_length)),
            0,
        );
    } else {
        out.extend_from_slice(parameter.padding());
    }

    Ok(())
}

/// Append a sequence of SCTP parameter envelopes to `out`.
pub fn encode_parameters(parameters: &[SctpParameter], out: &mut Vec<u8>) -> Result<()> {
    for parameter in parameters {
        encode_parameter(parameter, out)?;
    }
    Ok(())
}

/// IPv4 Address parameter value length in octets (RFC 9260 section 3.3.2.1.1).
pub const SCTP_IPV4_ADDRESS_PARAMETER_VALUE_LEN: usize = 4;
/// IPv6 Address parameter value length in octets (RFC 9260 section 3.3.2.1.2).
pub const SCTP_IPV6_ADDRESS_PARAMETER_VALUE_LEN: usize = 16;
/// Cookie Preservative parameter value length in octets (RFC 9260 section 3.3.2.1.3).
pub const SCTP_COOKIE_PRESERVATIVE_PARAMETER_VALUE_LEN: usize = 4;
/// Supported Address Types entry width in octets (RFC 9260 section 3.3.2.1.5).
pub const SCTP_SUPPORTED_ADDRESS_TYPE_LEN: usize = 2;
/// Supported Extensions chunk-type entry width in octets (RFC 5061 section 4.2.7).
pub const SCTP_SUPPORTED_EXTENSION_CHUNK_TYPE_LEN: usize = 1;
/// Forward-TSN-Supported parameter value length in octets (RFC 3758 section 3.1).
pub const SCTP_FORWARD_TSN_SUPPORTED_PARAMETER_VALUE_LEN: usize = 0;
/// Adaptation Layer Indication parameter value length in octets (RFC 5061 section 4.2.6).
pub const SCTP_ADAPTATION_LAYER_INDICATION_PARAMETER_VALUE_LEN: usize = 4;
/// Zero Checksum Acceptable parameter value length in octets (RFC 9653 section 4).
pub const SCTP_ZERO_CHECKSUM_ACCEPTABLE_PARAMETER_VALUE_LEN: usize = 4;
/// SCTP-AUTH RANDOM value length required during association setup (RFC 4895 section 6.1).
pub const SCTP_AUTH_RANDOM_NUMBER_LEN: usize = 32;
/// SCTP-AUTH CHUNKS maximum value length in octets (RFC 4895 section 3.2).
pub const SCTP_AUTH_CHUNK_LIST_MAX_VALUE_LEN: usize = 256;
/// SCTP-AUTH HMAC Identifier width in octets (RFC 4895 section 3.3).
pub const SCTP_AUTH_HMAC_IDENTIFIER_LEN: usize = 2;
/// Reserved SCTP-AUTH HMAC Identifier value 0 (RFC 4895 / IANA).
pub const SCTP_HMAC_IDENTIFIER_RESERVED_ZERO: u16 = 0;
/// SCTP-AUTH HMAC Identifier for SHA-1 (RFC 4895 / IANA).
pub const SCTP_HMAC_IDENTIFIER_SHA1: u16 = 1;
/// Reserved SCTP-AUTH HMAC Identifier value 2 (RFC 4895 / IANA).
pub const SCTP_HMAC_IDENTIFIER_RESERVED_TWO: u16 = 2;
/// SCTP-AUTH HMAC Identifier for SHA-256 (RFC 4895 / IANA).
pub const SCTP_HMAC_IDENTIFIER_SHA256: u16 = 3;
/// SCTP-AUTH Shared Key Identifier used when no endpoint-pair shared key exists (RFC 4895).
pub const SCTP_AUTH_EMPTY_SHARED_KEY_IDENTIFIER: u16 = 0;
/// IANA Adaptation Code Point for DDP (RFC 5043 / IANA).
pub const SCTP_ADAPTATION_CODE_POINT_DDP: u32 = 1;
/// Reserved Error Detection Method Identifier (RFC 9653 / IANA).
pub const SCTP_ERROR_DETECTION_METHOD_RESERVED: u32 = 0;
/// Error Detection Method Identifier for SCTP over DTLS (RFC 9653 / IANA).
pub const SCTP_ERROR_DETECTION_METHOD_SCTP_OVER_DTLS: u32 = 1;
/// ASCONF request/response correlation identifier width in octets (RFC 5061 section 4.2).
pub const SCTP_ASCONF_CORRELATION_ID_LEN: usize = 4;
/// Minimum value length for Add/Delete/Set Primary address parameters.
pub const SCTP_ASCONF_ADDRESS_PARAMETER_MIN_VALUE_LEN: usize =
    SCTP_ASCONF_CORRELATION_ID_LEN + SCTP_PARAMETER_HEADER_LEN;
/// Success Indication value length in octets (RFC 5061 section 4.2.5).
pub const SCTP_SUCCESS_INDICATION_PARAMETER_VALUE_LEN: usize = SCTP_ASCONF_CORRELATION_ID_LEN;
/// Minimum Error Cause Indication value length in octets (RFC 5061 section 4.2.3).
pub const SCTP_ERROR_CAUSE_INDICATION_PARAMETER_MIN_VALUE_LEN: usize =
    SCTP_ASCONF_CORRELATION_ID_LEN;
/// Re-configuration sequence number field width in octets (RFC 6525 section 4).
pub const SCTP_RECONFIGURATION_SEQUENCE_NUMBER_LEN: usize = 4;
/// SCTP stream number field width in octets (RFC 6525 section 4).
pub const SCTP_RECONFIGURATION_STREAM_NUMBER_LEN: usize = 2;
/// Outgoing SSN Reset Request fixed value length before stream numbers.
pub const SCTP_OUTGOING_SSN_RESET_REQUEST_FIXED_VALUE_LEN: usize = 12;
/// Incoming SSN Reset Request fixed value length before stream numbers.
pub const SCTP_INCOMING_SSN_RESET_REQUEST_FIXED_VALUE_LEN: usize = 4;
/// SSN/TSN Reset Request value length in octets.
pub const SCTP_SSN_TSN_RESET_REQUEST_VALUE_LEN: usize = SCTP_RECONFIGURATION_SEQUENCE_NUMBER_LEN;
/// Re-configuration Response value length without optional TSNs.
pub const SCTP_RE_CONFIGURATION_RESPONSE_VALUE_LEN: usize = 8;
/// Re-configuration Response value length with Sender/Receiver Next TSN fields.
pub const SCTP_RE_CONFIGURATION_RESPONSE_WITH_NEXT_TSNS_VALUE_LEN: usize = 16;
/// Add Outgoing/Incoming Streams Request value length in octets.
pub const SCTP_ADD_STREAMS_REQUEST_VALUE_LEN: usize = 8;
/// RFC 6525 result: success, nothing to do.
pub const SCTP_RECONFIGURATION_RESULT_SUCCESS_NOTHING_TO_DO: u32 = 0;
/// RFC 6525 result: success, performed.
pub const SCTP_RECONFIGURATION_RESULT_SUCCESS_PERFORMED: u32 = 1;
/// RFC 6525 result: denied.
pub const SCTP_RECONFIGURATION_RESULT_DENIED: u32 = 2;
/// RFC 6525 result: error, wrong SSN.
pub const SCTP_RECONFIGURATION_RESULT_ERROR_WRONG_SSN: u32 = 3;
/// RFC 6525 result: error, request already in progress.
pub const SCTP_RECONFIGURATION_RESULT_ERROR_REQUEST_ALREADY_IN_PROGRESS: u32 = 4;
/// RFC 6525 result: error, bad sequence number.
pub const SCTP_RECONFIGURATION_RESULT_ERROR_BAD_SEQUENCE_NUMBER: u32 = 5;
/// RFC 6525 result: in progress.
pub const SCTP_RECONFIGURATION_RESULT_IN_PROGRESS: u32 = 6;

const SCTP_IPV4_ADDRESS_PARAMETER_CONTEXT: &str = "sctp.ipv4_address_parameter.value";
const SCTP_IPV6_ADDRESS_PARAMETER_CONTEXT: &str = "sctp.ipv6_address_parameter.value";
const SCTP_COOKIE_PRESERVATIVE_PARAMETER_CONTEXT: &str = "sctp.cookie_preservative_parameter.value";
const SCTP_HOST_NAME_ADDRESS_PARAMETER_FIELD: &str = "sctp.host_name_address.host_name";
const SCTP_SUPPORTED_ADDRESS_TYPES_PARAMETER_FIELD: &str = "sctp.supported_address_types.value";
const SCTP_FORWARD_TSN_SUPPORTED_PARAMETER_CONTEXT: &str = "sctp.forward_tsn_supported.value";
const SCTP_ADAPTATION_LAYER_INDICATION_PARAMETER_CONTEXT: &str =
    "sctp.adaptation_layer_indication.value";
const SCTP_ZERO_CHECKSUM_ACCEPTABLE_PARAMETER_CONTEXT: &str = "sctp.zero_checksum_acceptable.value";
const SCTP_RANDOM_PARAMETER_CONTEXT: &str = "sctp.random.value";
const SCTP_CHUNK_LIST_PARAMETER_CONTEXT: &str = "sctp.chunk_list.value";
const SCTP_REQUESTED_HMAC_ALGORITHM_PARAMETER_CONTEXT: &str = "sctp.requested_hmac_algorithm.value";
const SCTP_ADD_IP_ADDRESS_PARAMETER_CONTEXT: &str = "sctp.add_ip_address.value";
const SCTP_DELETE_IP_ADDRESS_PARAMETER_CONTEXT: &str = "sctp.delete_ip_address.value";
const SCTP_SET_PRIMARY_ADDRESS_PARAMETER_CONTEXT: &str = "sctp.set_primary_address.value";
const SCTP_ASCONF_ADDRESS_PARAMETER_CONTEXT: &str = "sctp.asconf_address_parameter";
const SCTP_ASCONF_ADDRESS_PARAMETER_TYPE_FIELD: &str = "sctp.asconf_address_parameter.type";
const SCTP_ASCONF_ADDRESS_IPV4_CONTEXT: &str = "sctp.asconf_address_parameter.ipv4_address";
const SCTP_ASCONF_ADDRESS_IPV6_CONTEXT: &str = "sctp.asconf_address_parameter.ipv6_address";
const SCTP_SUCCESS_INDICATION_PARAMETER_CONTEXT: &str = "sctp.success_indication.value";
const SCTP_ERROR_CAUSE_INDICATION_PARAMETER_CONTEXT: &str = "sctp.error_cause_indication.value";
const SCTP_ERROR_CAUSE_INDICATION_ERROR_CAUSES_CONTEXT: &str =
    "sctp.error_cause_indication.error_causes";
const SCTP_OUTGOING_SSN_RESET_REQUEST_PARAMETER_CONTEXT: &str =
    "sctp.outgoing_ssn_reset_request.value";
const SCTP_OUTGOING_SSN_RESET_REQUEST_STREAMS_CONTEXT: &str =
    "sctp.outgoing_ssn_reset_request.stream_numbers";
const SCTP_INCOMING_SSN_RESET_REQUEST_PARAMETER_CONTEXT: &str =
    "sctp.incoming_ssn_reset_request.value";
const SCTP_INCOMING_SSN_RESET_REQUEST_STREAMS_CONTEXT: &str =
    "sctp.incoming_ssn_reset_request.stream_numbers";
const SCTP_SSN_TSN_RESET_REQUEST_PARAMETER_CONTEXT: &str = "sctp.ssn_tsn_reset_request.value";
const SCTP_RE_CONFIGURATION_RESPONSE_PARAMETER_CONTEXT: &str =
    "sctp.re_configuration_response.value";
const SCTP_ADD_OUTGOING_STREAMS_REQUEST_PARAMETER_CONTEXT: &str =
    "sctp.add_outgoing_streams_request.value";
const SCTP_ADD_INCOMING_STREAMS_REQUEST_PARAMETER_CONTEXT: &str =
    "sctp.add_incoming_streams_request.value";

/// SCTP adaptation code point values used by the Adaptation Layer Indication parameter.
///
/// RFC 5061 defines the parameter as an opaque upper-layer indication. Current
/// IANA rows label DDP while unassigned, future, or private values remain
/// inspectable numeric values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SctpAdaptationCodePoint {
    /// DDP adaptation code point value `1`.
    Ddp,
    /// Unknown, reserved, unassigned, private, or future adaptation code point.
    Unknown(u32),
}

impl SctpAdaptationCodePoint {
    /// Preserve or classify a raw Adaptation Code Point value.
    pub const fn new(raw: u32) -> Self {
        match raw {
            SCTP_ADAPTATION_CODE_POINT_DDP => Self::Ddp,
            other => Self::Unknown(other),
        }
    }

    /// Preserve or classify a raw Adaptation Code Point value.
    pub const fn from_u32(raw: u32) -> Self {
        Self::new(raw)
    }

    /// Return the raw 32-bit Adaptation Code Point value.
    pub const fn raw(self) -> u32 {
        match self {
            Self::Ddp => SCTP_ADAPTATION_CODE_POINT_DDP,
            Self::Unknown(value) => value,
        }
    }

    /// Return the raw 32-bit Adaptation Code Point value.
    pub const fn as_u32(self) -> u32 {
        self.raw()
    }
}

impl From<u32> for SctpAdaptationCodePoint {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<SctpAdaptationCodePoint> for u32 {
    fn from(value: SctpAdaptationCodePoint) -> Self {
        value.raw()
    }
}

/// SCTP Error Detection Method Identifier values used by Zero Checksum Acceptable.
///
/// RFC 9653 registers SCTP over DTLS and reserves zero. Other values remain
/// raw-preserving labels until their specifications are admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SctpErrorDetectionMethod {
    /// Reserved Error Detection Method Identifier value `0`.
    Reserved,
    /// SCTP over DTLS Error Detection Method Identifier value `1`.
    SctpOverDtls,
    /// Unknown, unassigned, private, or future Error Detection Method Identifier.
    Unknown(u32),
}

impl SctpErrorDetectionMethod {
    /// Preserve or classify a raw Error Detection Method Identifier.
    pub const fn new(raw: u32) -> Self {
        match raw {
            SCTP_ERROR_DETECTION_METHOD_RESERVED => Self::Reserved,
            SCTP_ERROR_DETECTION_METHOD_SCTP_OVER_DTLS => Self::SctpOverDtls,
            other => Self::Unknown(other),
        }
    }

    /// Preserve or classify a raw Error Detection Method Identifier.
    pub const fn from_u32(raw: u32) -> Self {
        Self::new(raw)
    }

    /// Return the raw 32-bit Error Detection Method Identifier.
    pub const fn raw(self) -> u32 {
        match self {
            Self::Reserved => SCTP_ERROR_DETECTION_METHOD_RESERVED,
            Self::SctpOverDtls => SCTP_ERROR_DETECTION_METHOD_SCTP_OVER_DTLS,
            Self::Unknown(value) => value,
        }
    }

    /// Return the raw 32-bit Error Detection Method Identifier.
    pub const fn as_u32(self) -> u32 {
        self.raw()
    }
}

impl From<u32> for SctpErrorDetectionMethod {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<SctpErrorDetectionMethod> for u32 {
    fn from(value: SctpErrorDetectionMethod) -> Self {
        value.raw()
    }
}

/// SCTP stream reconfiguration response result values.
///
/// RFC 6525 section 4.4 defines result values 0 through 6. Unknown values are
/// preserved as packet data so future assignments and malformed tests remain
/// representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SctpReconfigurationResult {
    /// Success: nothing to do.
    SuccessNothingToDo,
    /// Success: performed.
    SuccessPerformed,
    /// Request denied.
    Denied,
    /// Error: wrong SSN.
    ErrorWrongSsn,
    /// Error: request already in progress.
    ErrorRequestAlreadyInProgress,
    /// Error: bad sequence number.
    ErrorBadSequenceNumber,
    /// Request is in progress.
    InProgress,
    /// Unknown, unassigned, private, or future result value.
    Unknown(u32),
}

impl SctpReconfigurationResult {
    /// Preserve or classify a raw Re-configuration Response result value.
    pub const fn new(raw: u32) -> Self {
        match raw {
            SCTP_RECONFIGURATION_RESULT_SUCCESS_NOTHING_TO_DO => Self::SuccessNothingToDo,
            SCTP_RECONFIGURATION_RESULT_SUCCESS_PERFORMED => Self::SuccessPerformed,
            SCTP_RECONFIGURATION_RESULT_DENIED => Self::Denied,
            SCTP_RECONFIGURATION_RESULT_ERROR_WRONG_SSN => Self::ErrorWrongSsn,
            SCTP_RECONFIGURATION_RESULT_ERROR_REQUEST_ALREADY_IN_PROGRESS => {
                Self::ErrorRequestAlreadyInProgress
            }
            SCTP_RECONFIGURATION_RESULT_ERROR_BAD_SEQUENCE_NUMBER => Self::ErrorBadSequenceNumber,
            SCTP_RECONFIGURATION_RESULT_IN_PROGRESS => Self::InProgress,
            other => Self::Unknown(other),
        }
    }

    /// Preserve or classify a raw Re-configuration Response result value.
    pub const fn from_u32(raw: u32) -> Self {
        Self::new(raw)
    }

    /// Return the raw 32-bit result value.
    pub const fn raw(self) -> u32 {
        match self {
            Self::SuccessNothingToDo => SCTP_RECONFIGURATION_RESULT_SUCCESS_NOTHING_TO_DO,
            Self::SuccessPerformed => SCTP_RECONFIGURATION_RESULT_SUCCESS_PERFORMED,
            Self::Denied => SCTP_RECONFIGURATION_RESULT_DENIED,
            Self::ErrorWrongSsn => SCTP_RECONFIGURATION_RESULT_ERROR_WRONG_SSN,
            Self::ErrorRequestAlreadyInProgress => {
                SCTP_RECONFIGURATION_RESULT_ERROR_REQUEST_ALREADY_IN_PROGRESS
            }
            Self::ErrorBadSequenceNumber => SCTP_RECONFIGURATION_RESULT_ERROR_BAD_SEQUENCE_NUMBER,
            Self::InProgress => SCTP_RECONFIGURATION_RESULT_IN_PROGRESS,
            Self::Unknown(value) => value,
        }
    }

    /// Return the raw 32-bit result value.
    pub const fn as_u32(self) -> u32 {
        self.raw()
    }
}

impl From<u32> for SctpReconfigurationResult {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<SctpReconfigurationResult> for u32 {
    fn from(value: SctpReconfigurationResult) -> Self {
        value.raw()
    }
}

/// SCTP-AUTH HMAC Identifier values.
///
/// RFC 4895 and IANA define labels for SHA-1 and SHA-256, with two reserved
/// values. This type intentionally labels identifiers only; it does not imply
/// HMAC calculation or verification support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SctpHmacIdentifier {
    /// Reserved HMAC Identifier value `0`.
    ReservedZero,
    /// SHA-1 HMAC Identifier value `1`.
    Sha1,
    /// Reserved HMAC Identifier value `2`.
    ReservedTwo,
    /// SHA-256 HMAC Identifier value `3`.
    Sha256,
    /// Unknown, unassigned, private, or future HMAC Identifier.
    Unknown(u16),
}

impl SctpHmacIdentifier {
    /// Preserve or classify a raw HMAC Identifier.
    pub const fn new(raw: u16) -> Self {
        match raw {
            SCTP_HMAC_IDENTIFIER_RESERVED_ZERO => Self::ReservedZero,
            SCTP_HMAC_IDENTIFIER_SHA1 => Self::Sha1,
            SCTP_HMAC_IDENTIFIER_RESERVED_TWO => Self::ReservedTwo,
            SCTP_HMAC_IDENTIFIER_SHA256 => Self::Sha256,
            other => Self::Unknown(other),
        }
    }

    /// Preserve or classify a raw HMAC Identifier.
    pub const fn from_u16(raw: u16) -> Self {
        Self::new(raw)
    }

    /// Return the raw 16-bit HMAC Identifier.
    pub const fn raw(self) -> u16 {
        match self {
            Self::ReservedZero => SCTP_HMAC_IDENTIFIER_RESERVED_ZERO,
            Self::Sha1 => SCTP_HMAC_IDENTIFIER_SHA1,
            Self::ReservedTwo => SCTP_HMAC_IDENTIFIER_RESERVED_TWO,
            Self::Sha256 => SCTP_HMAC_IDENTIFIER_SHA256,
            Self::Unknown(value) => value,
        }
    }

    /// Return the raw 16-bit HMAC Identifier.
    pub const fn as_u16(self) -> u16 {
        self.raw()
    }
}

impl From<u16> for SctpHmacIdentifier {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<SctpHmacIdentifier> for u16 {
    fn from(value: SctpHmacIdentifier) -> Self {
        value.raw()
    }
}

/// Raw-preserving SCTP-AUTH Shared Key Identifier field value.
///
/// RFC 4895 carries this identifier in AUTH chunks. The value is packet data
/// only here; secret-key management and MAC calculation stay out of scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SctpSharedKeyIdentifier(u16);

impl SctpSharedKeyIdentifier {
    /// Preserve a raw 16-bit Shared Key Identifier.
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Preserve a raw 16-bit Shared Key Identifier.
    pub const fn from_u16(raw: u16) -> Self {
        Self::new(raw)
    }

    /// Return the preserved raw Shared Key Identifier.
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Return the preserved raw Shared Key Identifier.
    pub const fn as_u16(self) -> u16 {
        self.raw()
    }

    /// Return true for the RFC 4895 empty endpoint-pair shared-key identifier.
    pub const fn is_empty_shared_key_identifier(self) -> bool {
        self.raw() == SCTP_AUTH_EMPTY_SHARED_KEY_IDENTIFIER
    }
}

impl From<u16> for SctpSharedKeyIdentifier {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<SctpSharedKeyIdentifier> for u16 {
    fn from(value: SctpSharedKeyIdentifier) -> Self {
        value.raw()
    }
}

/// SCTP address type values used by the Supported Address Types parameter.
///
/// RFC 9260 section 3.3.2.1.5 encodes each entry as the corresponding address
/// TLV parameter type value. Unknown values are preserved so callers can inspect
/// or construct future address-family advertisements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SctpAddressType {
    /// IPv4 Address parameter type value `5`.
    Ipv4,
    /// IPv6 Address parameter type value `6`.
    Ipv6,
    /// Host Name Address parameter type value `11`.
    HostName,
    /// Unknown, reserved, temporary, private, obsolete, or future address type.
    Unknown(u16),
}

impl SctpAddressType {
    /// Preserve or classify a raw Supported Address Types entry.
    pub const fn new(raw: u16) -> Self {
        match raw {
            SCTP_PARAMETER_TYPE_IPV4_ADDRESS => Self::Ipv4,
            SCTP_PARAMETER_TYPE_IPV6_ADDRESS => Self::Ipv6,
            SCTP_PARAMETER_TYPE_HOST_NAME_ADDRESS => Self::HostName,
            other => Self::Unknown(other),
        }
    }

    /// Preserve or classify a raw Supported Address Types entry.
    pub const fn from_u16(raw: u16) -> Self {
        Self::new(raw)
    }

    /// Return the raw 16-bit Supported Address Types entry value.
    pub const fn raw(self) -> u16 {
        match self {
            Self::Ipv4 => SCTP_PARAMETER_TYPE_IPV4_ADDRESS,
            Self::Ipv6 => SCTP_PARAMETER_TYPE_IPV6_ADDRESS,
            Self::HostName => SCTP_PARAMETER_TYPE_HOST_NAME_ADDRESS,
            Self::Unknown(value) => value,
        }
    }

    /// Return the raw 16-bit Supported Address Types entry value.
    pub const fn as_u16(self) -> u16 {
        self.raw()
    }

    /// Return the IPv4 or IPv6 address family represented by this value.
    pub const fn address_family(self) -> Option<SctpAddressFamily> {
        match self {
            Self::Ipv4 => Some(SctpAddressFamily::Ipv4),
            Self::Ipv6 => Some(SctpAddressFamily::Ipv6),
            Self::HostName | Self::Unknown(_) => None,
        }
    }
}

impl From<u16> for SctpAddressType {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<SctpParameterType> for SctpAddressType {
    fn from(value: SctpParameterType) -> Self {
        Self::new(value.raw())
    }
}

impl From<SctpAddressType> for u16 {
    fn from(value: SctpAddressType) -> Self {
        value.raw()
    }
}

/// IPv4/IPv6 address family helper for SCTP address parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SctpAddressFamily {
    /// IPv4 Address parameter family.
    Ipv4,
    /// IPv6 Address parameter family.
    Ipv6,
}

impl SctpAddressFamily {
    /// Return the Supported Address Types entry for this address family.
    pub const fn address_type(self) -> SctpAddressType {
        match self {
            Self::Ipv4 => SctpAddressType::Ipv4,
            Self::Ipv6 => SctpAddressType::Ipv6,
        }
    }

    /// Return the SCTP address TLV parameter type value for this family.
    pub const fn parameter_type_value(self) -> u16 {
        self.address_type().raw()
    }
}

impl From<SctpAddressFamily> for SctpAddressType {
    fn from(value: SctpAddressFamily) -> Self {
        value.address_type()
    }
}

/// Byte-preserving storage for one SCTP parameter envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctpRawParameter {
    parameter_type: SctpParameterType,
    declared_length: Option<u16>,
    value: Vec<u8>,
    padding: Vec<u8>,
}

impl SctpRawParameter {
    /// Construct a parameter envelope with an auto-derived declared length.
    pub fn new(parameter_type: impl Into<SctpParameterType>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            parameter_type: parameter_type.into(),
            declared_length: None,
            value: value.into(),
            padding: Vec::new(),
        }
    }

    /// Construct a parameter envelope from observed or caller-preserved wire parts.
    pub fn from_raw_parts(
        parameter_type: impl Into<SctpParameterType>,
        value: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            padding: padding.into(),
            ..Self::new(parameter_type, value)
        }
    }

    /// Construct a parameter envelope with an explicit declared length override.
    pub fn from_preserved_parts(
        parameter_type: impl Into<SctpParameterType>,
        declared_length: u16,
        value: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            parameter_type: parameter_type.into(),
            declared_length: Some(declared_length),
            value: value.into(),
            padding: padding.into(),
        }
    }

    /// Replace the raw parameter type codepoint.
    pub fn with_parameter_type(mut self, parameter_type: impl Into<SctpParameterType>) -> Self {
        self.parameter_type = parameter_type.into();
        self
    }

    /// Preserve an explicit parameter length field value.
    pub fn with_declared_length(mut self, declared_length: u16) -> Self {
        self.declared_length = Some(declared_length);
        self
    }

    /// Compatibility alias for preserving an explicit parameter length field value.
    pub fn with_length(self, length: u16) -> Self {
        self.with_declared_length(length)
    }

    /// Return to auto-derived parameter length behavior.
    pub fn with_auto_length(mut self) -> Self {
        self.declared_length = None;
        self
    }

    /// Replace the declared value bytes.
    pub fn with_value(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.value = value.into();
        self
    }

    /// Replace the transmitted padding bytes.
    pub fn with_padding(mut self, padding: impl Into<Vec<u8>>) -> Self {
        self.padding = padding.into();
        self
    }

    /// SCTP parameter type codepoint.
    pub const fn parameter_type(&self) -> SctpParameterType {
        self.parameter_type
    }

    /// Raw SCTP parameter type codepoint.
    pub const fn parameter_type_value(&self) -> u16 {
        self.parameter_type.raw()
    }

    /// RFC 9260 unknown-parameter action bits from the parameter type.
    pub const fn unknown_action_bits(&self) -> u8 {
        self.parameter_type.unknown_action_bits()
    }

    /// RFC 9260 unknown-parameter action label from the parameter type.
    pub const fn unknown_action(&self) -> SctpUnknownParameterAction {
        self.parameter_type.unknown_action()
    }

    /// Lower 14 type bits without the unknown-parameter action class.
    pub const fn type_value_bits_without_unknown_action(&self) -> u16 {
        self.parameter_type.value_bits_without_unknown_action()
    }

    /// Source-backed registry status for this parameter type.
    pub const fn parameter_type_status(&self) -> SctpParameterTypeStatus {
        self.parameter_type.status()
    }

    /// Source-backed registry label for this parameter type, when known.
    pub const fn parameter_type_name(&self) -> Option<&'static str> {
        self.parameter_type.name()
    }

    /// Declared parameter length value, using the explicit value when present.
    pub fn declared_length(&self) -> usize {
        self.declared_length
            .map(usize::from)
            .unwrap_or_else(|| SCTP_PARAMETER_HEADER_LEN + self.value.len())
    }

    /// Compatibility alias for the declared parameter length value.
    pub fn length(&self) -> usize {
        self.declared_length()
    }

    /// Explicit declared parameter length override, if one is preserved.
    pub const fn explicit_declared_length(&self) -> Option<u16> {
        self.declared_length
    }

    /// Compatibility alias for the explicit declared parameter length override.
    pub const fn explicit_length(&self) -> Option<u16> {
        self.explicit_declared_length()
    }

    /// Declared parameter value bytes, excluding padding.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Transmitted parameter padding bytes, excluded from semantic value bytes.
    pub fn padding(&self) -> &[u8] {
        &self.padding
    }

    /// Declared parameter value length, excluding padding.
    pub fn value_len(&self) -> usize {
        self.value.len()
    }

    /// Transmitted parameter padding length.
    pub fn padding_len(&self) -> usize {
        self.padding.len()
    }

    /// Protocol padding length implied by the declared parameter length.
    pub fn required_padding_len(&self) -> usize {
        sctp_parameter_padding_len(self.declared_length())
    }

    /// Padding length an encoder would emit: preserved bytes, or auto zero padding.
    pub fn encoded_padding_len(&self) -> usize {
        if self.padding.is_empty() {
            self.required_padding_len()
        } else {
            self.padding.len()
        }
    }

    /// Declared parameter length rounded up to the next four-octet boundary.
    pub fn padded_declared_len(&self) -> usize {
        sctp_parameter_padded_len(self.declared_length())
    }

    /// Number of bytes encoded for this envelope, including padding.
    pub fn encoded_len(&self) -> usize {
        SCTP_PARAMETER_HEADER_LEN + self.value.len() + self.encoded_padding_len()
    }
}

macro_rules! define_sctp_typed_parameter_structs {
    ($($name:ident),+ $(,)?) => {
        $(
            /// Raw-envelope storage for a typed SCTP parameter variant.
            #[derive(Debug, Clone, PartialEq, Eq)]
            pub struct $name {
                raw: SctpRawParameter,
            }
        )+
    };
}

define_sctp_typed_parameter_structs!(
    SctpHeartbeatInfoParameter,
    SctpIpv4AddressParameter,
    SctpIpv6AddressParameter,
    SctpStateCookieParameter,
    SctpUnrecognizedParameter,
    SctpCookiePreservativeParameter,
    SctpHostNameAddressParameter,
    SctpSupportedAddressTypesParameter,
    SctpOutgoingSsnResetRequestParameter,
    SctpIncomingSsnResetRequestParameter,
    SctpSsnTsnResetRequestParameter,
    SctpReConfigurationResponseParameter,
    SctpAddOutgoingStreamsRequestParameter,
    SctpAddIncomingStreamsRequestParameter,
    SctpZeroChecksumAcceptableParameter,
    SctpRandomParameter,
    SctpChunkListParameter,
    SctpRequestedHmacAlgorithmParameter,
    SctpPaddingParameter,
    SctpSupportedExtensionsParameter,
    SctpForwardTsnSupportedParameter,
    SctpAddIpAddressParameter,
    SctpDeleteIpAddressParameter,
    SctpErrorCauseIndicationParameter,
    SctpSetPrimaryAddressParameter,
    SctpSuccessIndicationParameter,
    SctpAdaptationLayerIndicationParameter,
);

/// Raw-envelope storage for an untyped SCTP parameter codepoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctpUnknownParameter {
    raw: SctpRawParameter,
}

impl SctpUnknownParameter {
    /// Construct an unknown parameter with an auto-derived declared length.
    pub fn new(parameter_type: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            raw: SctpRawParameter::new(parameter_type, value),
        }
    }

    /// Construct an unknown parameter from raw wire parts.
    pub fn from_raw_parts(
        parameter_type: u16,
        value: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            raw: SctpRawParameter::from_raw_parts(parameter_type, value, padding),
        }
    }

    /// Construct an unknown parameter with an explicit declared length override.
    pub fn from_preserved_parts(
        parameter_type: u16,
        declared_length: u16,
        value: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            raw: SctpRawParameter::from_preserved_parts(
                parameter_type,
                declared_length,
                value,
                padding,
            ),
        }
    }

    /// Preserve an explicit parameter length field value.
    pub fn with_declared_length(mut self, declared_length: u16) -> Self {
        self.raw = self.raw.with_declared_length(declared_length);
        self
    }

    /// Compatibility alias for preserving an explicit parameter length field value.
    pub fn with_length(self, length: u16) -> Self {
        self.with_declared_length(length)
    }

    /// Replace the declared value bytes.
    pub fn with_value(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.raw = self.raw.with_value(value);
        self
    }

    /// Replace the transmitted padding bytes.
    pub fn with_padding(mut self, padding: impl Into<Vec<u8>>) -> Self {
        self.raw = self.raw.with_padding(padding);
        self
    }

    /// Borrow the preserved raw parameter envelope.
    pub fn raw_parameter(&self) -> &SctpRawParameter {
        &self.raw
    }

    /// SCTP parameter type codepoint.
    pub const fn parameter_type(&self) -> SctpParameterType {
        self.raw.parameter_type()
    }

    /// Raw SCTP parameter type codepoint.
    pub const fn parameter_type_value(&self) -> u16 {
        self.raw.parameter_type_value()
    }

    /// RFC 9260 unknown-parameter action bits from the parameter type.
    pub const fn unknown_action_bits(&self) -> u8 {
        self.raw.unknown_action_bits()
    }

    /// RFC 9260 unknown-parameter action label from the parameter type.
    pub const fn unknown_action(&self) -> SctpUnknownParameterAction {
        self.raw.unknown_action()
    }

    /// Lower 14 type bits without the unknown-parameter action class.
    pub const fn type_value_bits_without_unknown_action(&self) -> u16 {
        self.raw.type_value_bits_without_unknown_action()
    }

    /// Source-backed registry status for this parameter type.
    pub const fn parameter_type_status(&self) -> SctpParameterTypeStatus {
        self.raw.parameter_type_status()
    }

    /// Source-backed registry label for this parameter type, when known.
    pub const fn parameter_type_name(&self) -> Option<&'static str> {
        self.raw.parameter_type_name()
    }

    /// Return true when an unknown receiver would stop processing further parameters.
    pub const fn stops_parameter_processing(&self) -> bool {
        self.unknown_action().stops_parameter_processing()
    }

    /// Return true when an unknown receiver would skip this parameter and continue.
    pub const fn skips_parameter(&self) -> bool {
        self.unknown_action().skips_parameter()
    }

    /// Return true when an unknown receiver would report this unrecognized parameter.
    pub const fn reports_unrecognized_parameter(&self) -> bool {
        self.unknown_action().reports_unrecognized_parameter()
    }

    /// Declared parameter length value, using the explicit value when present.
    pub fn declared_length(&self) -> usize {
        self.raw.declared_length()
    }

    /// Compatibility alias for the declared parameter length value.
    pub fn length(&self) -> usize {
        self.declared_length()
    }

    /// Explicit declared parameter length override, if one is preserved.
    pub const fn explicit_declared_length(&self) -> Option<u16> {
        self.raw.explicit_declared_length()
    }

    /// Compatibility alias for the explicit declared parameter length override.
    pub const fn explicit_length(&self) -> Option<u16> {
        self.explicit_declared_length()
    }

    /// Declared parameter value bytes, excluding padding.
    pub fn value(&self) -> &[u8] {
        self.raw.value()
    }

    /// Transmitted parameter padding bytes, excluded from semantic value bytes.
    pub fn padding(&self) -> &[u8] {
        self.raw.padding()
    }

    /// Declared parameter value length, excluding padding.
    pub fn value_len(&self) -> usize {
        self.raw.value_len()
    }

    /// Transmitted parameter padding length.
    pub fn padding_len(&self) -> usize {
        self.raw.padding_len()
    }

    /// Protocol padding length implied by the declared parameter length.
    pub fn required_padding_len(&self) -> usize {
        self.raw.required_padding_len()
    }

    /// Padding length an encoder would emit: preserved bytes, or auto zero padding.
    pub fn encoded_padding_len(&self) -> usize {
        self.raw.encoded_padding_len()
    }

    /// Declared parameter length rounded up to the next four-octet boundary.
    pub fn padded_declared_len(&self) -> usize {
        self.raw.padded_declared_len()
    }

    /// Number of bytes encoded for this envelope, including padding.
    pub fn encoded_len(&self) -> usize {
        self.raw.encoded_len()
    }
}

/// SCTP parameter with typed variants and raw-preserving fallback storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SctpParameter {
    /// Heartbeat Info parameter.
    HeartbeatInfo(SctpHeartbeatInfoParameter),
    /// IPv4 Address parameter.
    Ipv4Address(SctpIpv4AddressParameter),
    /// IPv6 Address parameter.
    Ipv6Address(SctpIpv6AddressParameter),
    /// State Cookie parameter.
    StateCookie(SctpStateCookieParameter),
    /// Unrecognized Parameter parameter.
    UnrecognizedParameter(SctpUnrecognizedParameter),
    /// Cookie Preservative parameter.
    CookiePreservative(SctpCookiePreservativeParameter),
    /// Host Name Address parameter.
    HostNameAddress(SctpHostNameAddressParameter),
    /// Supported Address Types parameter.
    SupportedAddressTypes(SctpSupportedAddressTypesParameter),
    /// Outgoing SSN Reset Request parameter.
    OutgoingSsnResetRequest(SctpOutgoingSsnResetRequestParameter),
    /// Incoming SSN Reset Request parameter.
    IncomingSsnResetRequest(SctpIncomingSsnResetRequestParameter),
    /// SSN/TSN Reset Request parameter.
    SsnTsnResetRequest(SctpSsnTsnResetRequestParameter),
    /// Re-configuration Response parameter.
    ReConfigurationResponse(SctpReConfigurationResponseParameter),
    /// Add Outgoing Streams Request parameter.
    AddOutgoingStreamsRequest(SctpAddOutgoingStreamsRequestParameter),
    /// Add Incoming Streams Request parameter.
    AddIncomingStreamsRequest(SctpAddIncomingStreamsRequestParameter),
    /// Zero Checksum Acceptable parameter.
    ZeroChecksumAcceptable(SctpZeroChecksumAcceptableParameter),
    /// AUTH Random parameter.
    Random(SctpRandomParameter),
    /// AUTH Chunk List parameter.
    ChunkList(SctpChunkListParameter),
    /// AUTH Requested HMAC Algorithm parameter.
    RequestedHmacAlgorithm(SctpRequestedHmacAlgorithmParameter),
    /// Padding parameter.
    Padding(SctpPaddingParameter),
    /// Supported Extensions parameter.
    SupportedExtensions(SctpSupportedExtensionsParameter),
    /// Forward TSN supported parameter.
    ForwardTsnSupported(SctpForwardTsnSupportedParameter),
    /// Add IP Address parameter.
    AddIpAddress(SctpAddIpAddressParameter),
    /// Delete IP Address parameter.
    DeleteIpAddress(SctpDeleteIpAddressParameter),
    /// Error Cause Indication parameter.
    ErrorCauseIndication(SctpErrorCauseIndicationParameter),
    /// Set Primary Address parameter.
    SetPrimaryAddress(SctpSetPrimaryAddressParameter),
    /// Success Indication parameter.
    SuccessIndication(SctpSuccessIndicationParameter),
    /// Adaptation Layer Indication parameter.
    AdaptationLayerIndication(SctpAdaptationLayerIndicationParameter),
    /// Unknown, reserved, temporary, private, obsolete, or future parameter.
    Unknown(SctpUnknownParameter),
}

macro_rules! impl_sctp_typed_parameter {
    ($name:ident, $variant:ident, $type_const:ident) => {
        impl $name {
            /// Construct the parameter with an auto-derived declared length.
            pub fn new(value: impl Into<Vec<u8>>) -> Self {
                Self {
                    raw: SctpRawParameter::new($type_const, value),
                }
            }

            /// Construct the parameter from raw wire parts.
            pub fn from_raw_parts(value: impl Into<Vec<u8>>, padding: impl Into<Vec<u8>>) -> Self {
                Self {
                    raw: SctpRawParameter::from_raw_parts($type_const, value, padding),
                }
            }

            /// Construct the parameter with an explicit declared length override.
            pub fn from_preserved_parts(
                declared_length: u16,
                value: impl Into<Vec<u8>>,
                padding: impl Into<Vec<u8>>,
            ) -> Self {
                Self {
                    raw: SctpRawParameter::from_preserved_parts(
                        $type_const,
                        declared_length,
                        value,
                        padding,
                    ),
                }
            }

            /// Preserve an explicit parameter length field value.
            pub fn with_declared_length(mut self, declared_length: u16) -> Self {
                self.raw = self.raw.with_declared_length(declared_length);
                self
            }

            /// Compatibility alias for preserving an explicit parameter length field value.
            pub fn with_length(self, length: u16) -> Self {
                self.with_declared_length(length)
            }

            /// Replace the declared value bytes.
            pub fn with_value(mut self, value: impl Into<Vec<u8>>) -> Self {
                self.raw = self.raw.with_value(value);
                self
            }

            /// Replace the transmitted padding bytes.
            pub fn with_padding(mut self, padding: impl Into<Vec<u8>>) -> Self {
                self.raw = self.raw.with_padding(padding);
                self
            }

            /// Borrow the preserved raw parameter envelope.
            pub fn raw_parameter(&self) -> &SctpRawParameter {
                &self.raw
            }

            /// SCTP parameter type codepoint.
            pub const fn parameter_type(&self) -> SctpParameterType {
                self.raw.parameter_type()
            }

            /// Raw SCTP parameter type codepoint.
            pub const fn parameter_type_value(&self) -> u16 {
                self.raw.parameter_type_value()
            }

            /// RFC 9260 unknown-parameter action bits from the parameter type.
            pub const fn unknown_action_bits(&self) -> u8 {
                self.raw.unknown_action_bits()
            }

            /// RFC 9260 unknown-parameter action label from the parameter type.
            pub const fn unknown_action(&self) -> SctpUnknownParameterAction {
                self.raw.unknown_action()
            }

            /// Lower 14 type bits without the unknown-parameter action class.
            pub const fn type_value_bits_without_unknown_action(&self) -> u16 {
                self.raw.type_value_bits_without_unknown_action()
            }

            /// Source-backed registry status for this parameter type.
            pub const fn parameter_type_status(&self) -> SctpParameterTypeStatus {
                self.raw.parameter_type_status()
            }

            /// Source-backed registry label for this parameter type, when known.
            pub const fn parameter_type_name(&self) -> Option<&'static str> {
                self.raw.parameter_type_name()
            }

            /// Declared parameter length value, using the explicit value when present.
            pub fn declared_length(&self) -> usize {
                self.raw.declared_length()
            }

            /// Compatibility alias for the declared parameter length value.
            pub fn length(&self) -> usize {
                self.declared_length()
            }

            /// Explicit declared parameter length override, if one is preserved.
            pub const fn explicit_declared_length(&self) -> Option<u16> {
                self.raw.explicit_declared_length()
            }

            /// Compatibility alias for the explicit declared parameter length override.
            pub const fn explicit_length(&self) -> Option<u16> {
                self.explicit_declared_length()
            }

            /// Declared parameter value bytes, excluding padding.
            pub fn value(&self) -> &[u8] {
                self.raw.value()
            }

            /// Transmitted parameter padding bytes, excluded from semantic value bytes.
            pub fn padding(&self) -> &[u8] {
                self.raw.padding()
            }

            /// Declared parameter value length, excluding padding.
            pub fn value_len(&self) -> usize {
                self.raw.value_len()
            }

            /// Transmitted parameter padding length.
            pub fn padding_len(&self) -> usize {
                self.raw.padding_len()
            }

            /// Protocol padding length implied by the declared parameter length.
            pub fn required_padding_len(&self) -> usize {
                self.raw.required_padding_len()
            }

            /// Padding length an encoder would emit: preserved bytes, or auto zero padding.
            pub fn encoded_padding_len(&self) -> usize {
                self.raw.encoded_padding_len()
            }

            /// Declared parameter length rounded up to the next four-octet boundary.
            pub fn padded_declared_len(&self) -> usize {
                self.raw.padded_declared_len()
            }

            /// Number of bytes encoded for this envelope, including padding.
            pub fn encoded_len(&self) -> usize {
                self.raw.encoded_len()
            }
        }

        impl From<$name> for SctpParameter {
            fn from(value: $name) -> Self {
                Self::$variant(value)
            }
        }
    };
}

impl_sctp_typed_parameter!(
    SctpHeartbeatInfoParameter,
    HeartbeatInfo,
    SCTP_PARAMETER_TYPE_HEARTBEAT_INFO
);
impl_sctp_typed_parameter!(
    SctpIpv4AddressParameter,
    Ipv4Address,
    SCTP_PARAMETER_TYPE_IPV4_ADDRESS
);
impl_sctp_typed_parameter!(
    SctpIpv6AddressParameter,
    Ipv6Address,
    SCTP_PARAMETER_TYPE_IPV6_ADDRESS
);
impl_sctp_typed_parameter!(
    SctpStateCookieParameter,
    StateCookie,
    SCTP_PARAMETER_TYPE_STATE_COOKIE
);
impl_sctp_typed_parameter!(
    SctpUnrecognizedParameter,
    UnrecognizedParameter,
    SCTP_PARAMETER_TYPE_UNRECOGNIZED_PARAMETER
);
impl_sctp_typed_parameter!(
    SctpCookiePreservativeParameter,
    CookiePreservative,
    SCTP_PARAMETER_TYPE_COOKIE_PRESERVATIVE
);
impl_sctp_typed_parameter!(
    SctpHostNameAddressParameter,
    HostNameAddress,
    SCTP_PARAMETER_TYPE_HOST_NAME_ADDRESS
);
impl_sctp_typed_parameter!(
    SctpSupportedAddressTypesParameter,
    SupportedAddressTypes,
    SCTP_PARAMETER_TYPE_SUPPORTED_ADDRESS_TYPES
);
impl_sctp_typed_parameter!(
    SctpOutgoingSsnResetRequestParameter,
    OutgoingSsnResetRequest,
    SCTP_PARAMETER_TYPE_OUTGOING_SSN_RESET_REQUEST
);
impl_sctp_typed_parameter!(
    SctpIncomingSsnResetRequestParameter,
    IncomingSsnResetRequest,
    SCTP_PARAMETER_TYPE_INCOMING_SSN_RESET_REQUEST
);
impl_sctp_typed_parameter!(
    SctpSsnTsnResetRequestParameter,
    SsnTsnResetRequest,
    SCTP_PARAMETER_TYPE_SSN_TSN_RESET_REQUEST
);
impl_sctp_typed_parameter!(
    SctpReConfigurationResponseParameter,
    ReConfigurationResponse,
    SCTP_PARAMETER_TYPE_RE_CONFIGURATION_RESPONSE
);
impl_sctp_typed_parameter!(
    SctpAddOutgoingStreamsRequestParameter,
    AddOutgoingStreamsRequest,
    SCTP_PARAMETER_TYPE_ADD_OUTGOING_STREAMS_REQUEST
);
impl_sctp_typed_parameter!(
    SctpAddIncomingStreamsRequestParameter,
    AddIncomingStreamsRequest,
    SCTP_PARAMETER_TYPE_ADD_INCOMING_STREAMS_REQUEST
);
impl_sctp_typed_parameter!(
    SctpZeroChecksumAcceptableParameter,
    ZeroChecksumAcceptable,
    SCTP_PARAMETER_TYPE_ZERO_CHECKSUM_ACCEPTABLE
);
impl_sctp_typed_parameter!(SctpRandomParameter, Random, SCTP_PARAMETER_TYPE_RANDOM);
impl_sctp_typed_parameter!(
    SctpChunkListParameter,
    ChunkList,
    SCTP_PARAMETER_TYPE_CHUNK_LIST
);
impl_sctp_typed_parameter!(
    SctpRequestedHmacAlgorithmParameter,
    RequestedHmacAlgorithm,
    SCTP_PARAMETER_TYPE_REQUESTED_HMAC_ALGORITHM
);
impl_sctp_typed_parameter!(SctpPaddingParameter, Padding, SCTP_PARAMETER_TYPE_PADDING);
impl_sctp_typed_parameter!(
    SctpSupportedExtensionsParameter,
    SupportedExtensions,
    SCTP_PARAMETER_TYPE_SUPPORTED_EXTENSIONS
);
impl_sctp_typed_parameter!(
    SctpForwardTsnSupportedParameter,
    ForwardTsnSupported,
    SCTP_PARAMETER_TYPE_FORWARD_TSN_SUPPORTED
);
impl_sctp_typed_parameter!(
    SctpAddIpAddressParameter,
    AddIpAddress,
    SCTP_PARAMETER_TYPE_ADD_IP_ADDRESS
);
impl_sctp_typed_parameter!(
    SctpDeleteIpAddressParameter,
    DeleteIpAddress,
    SCTP_PARAMETER_TYPE_DELETE_IP_ADDRESS
);
impl_sctp_typed_parameter!(
    SctpErrorCauseIndicationParameter,
    ErrorCauseIndication,
    SCTP_PARAMETER_TYPE_ERROR_CAUSE_INDICATION
);
impl_sctp_typed_parameter!(
    SctpSetPrimaryAddressParameter,
    SetPrimaryAddress,
    SCTP_PARAMETER_TYPE_SET_PRIMARY_ADDRESS
);
impl_sctp_typed_parameter!(
    SctpSuccessIndicationParameter,
    SuccessIndication,
    SCTP_PARAMETER_TYPE_SUCCESS_INDICATION
);
impl_sctp_typed_parameter!(
    SctpAdaptationLayerIndicationParameter,
    AdaptationLayerIndication,
    SCTP_PARAMETER_TYPE_ADAPTATION_LAYER_INDICATION
);

impl SctpPaddingParameter {
    /// Construct a PAD parameter from ignored padding data bytes.
    pub fn from_padding_data(padding_data: impl Into<Vec<u8>>) -> Self {
        Self::new(padding_data)
    }

    /// Replace the ignored padding data bytes.
    pub fn with_padding_data(self, padding_data: impl Into<Vec<u8>>) -> Self {
        self.with_value(padding_data)
    }

    /// Ignored PAD parameter data bytes, excluding parameter alignment padding.
    pub fn padding_data(&self) -> &[u8] {
        self.value()
    }

    /// Ignored PAD parameter data bytes, excluding parameter alignment padding.
    pub fn padding_data_bytes(&self) -> &[u8] {
        self.padding_data()
    }
}

impl SctpIpv4AddressParameter {
    /// Construct an IPv4 Address parameter from an IPv4 address.
    pub fn from_address(address: Ipv4Addr) -> Self {
        Self::new(address.octets())
    }

    /// Construct an IPv4 Address parameter from an IPv4 address.
    pub fn from_ipv4_address(address: Ipv4Addr) -> Self {
        Self::from_address(address)
    }

    /// Replace the semantic IPv4 address value.
    pub fn with_address(self, address: Ipv4Addr) -> Self {
        self.with_value(address.octets())
    }

    /// Replace the semantic IPv4 address value.
    pub fn with_ipv4_address(self, address: Ipv4Addr) -> Self {
        self.with_address(address)
    }

    /// Interpret the declared value bytes as an IPv4 address.
    pub fn address(&self) -> Result<Ipv4Addr> {
        expect_parameter_value_len(
            self.value(),
            SCTP_IPV4_ADDRESS_PARAMETER_CONTEXT,
            SCTP_IPV4_ADDRESS_PARAMETER_VALUE_LEN,
        )?;

        let value = self.value();
        Ok(Ipv4Addr::new(value[0], value[1], value[2], value[3]))
    }

    /// Interpret the declared value bytes as an IPv4 address.
    pub fn ipv4_address(&self) -> Result<Ipv4Addr> {
        self.address()
    }
}

impl SctpIpv6AddressParameter {
    /// Construct an IPv6 Address parameter from an IPv6 address.
    pub fn from_address(address: Ipv6Addr) -> Self {
        Self::new(address.octets())
    }

    /// Construct an IPv6 Address parameter from an IPv6 address.
    pub fn from_ipv6_address(address: Ipv6Addr) -> Self {
        Self::from_address(address)
    }

    /// Replace the semantic IPv6 address value.
    pub fn with_address(self, address: Ipv6Addr) -> Self {
        self.with_value(address.octets())
    }

    /// Replace the semantic IPv6 address value.
    pub fn with_ipv6_address(self, address: Ipv6Addr) -> Self {
        self.with_address(address)
    }

    /// Interpret the declared value bytes as an IPv6 address.
    pub fn address(&self) -> Result<Ipv6Addr> {
        expect_parameter_value_len(
            self.value(),
            SCTP_IPV6_ADDRESS_PARAMETER_CONTEXT,
            SCTP_IPV6_ADDRESS_PARAMETER_VALUE_LEN,
        )?;

        let mut octets = [0; SCTP_IPV6_ADDRESS_PARAMETER_VALUE_LEN];
        octets.copy_from_slice(self.value());
        Ok(Ipv6Addr::from(octets))
    }

    /// Interpret the declared value bytes as an IPv6 address.
    pub fn ipv6_address(&self) -> Result<Ipv6Addr> {
        self.address()
    }
}

impl SctpStateCookieParameter {
    /// Construct a State Cookie parameter from opaque cookie bytes.
    pub fn from_cookie(cookie: impl Into<Vec<u8>>) -> Self {
        Self::new(cookie)
    }

    /// Replace the opaque state-cookie bytes.
    pub fn with_cookie(self, cookie: impl Into<Vec<u8>>) -> Self {
        self.with_value(cookie)
    }

    /// Opaque state-cookie bytes, excluding parameter padding.
    pub fn cookie(&self) -> &[u8] {
        self.value()
    }

    /// Opaque state-cookie bytes, excluding parameter padding.
    pub fn cookie_bytes(&self) -> &[u8] {
        self.cookie()
    }
}

impl SctpUnrecognizedParameter {
    /// Construct an Unrecognized Parameter parameter from copied parameter bytes.
    pub fn from_copied_parameter(parameter: impl Into<Vec<u8>>) -> Self {
        Self::new(parameter)
    }

    /// Construct an Unrecognized Parameter parameter from copied parameter bytes.
    pub fn from_unrecognized_parameter(parameter: impl Into<Vec<u8>>) -> Self {
        Self::from_copied_parameter(parameter)
    }

    /// Replace the copied unrecognized parameter bytes.
    pub fn with_copied_parameter(self, parameter: impl Into<Vec<u8>>) -> Self {
        self.with_value(parameter)
    }

    /// Replace the copied unrecognized parameter bytes.
    pub fn with_unrecognized_parameter(self, parameter: impl Into<Vec<u8>>) -> Self {
        self.with_copied_parameter(parameter)
    }

    /// Copied unrecognized parameter bytes, excluding this container's padding.
    pub fn copied_parameter(&self) -> &[u8] {
        self.value()
    }

    /// Copied unrecognized parameter bytes, excluding this container's padding.
    pub fn copied_parameter_bytes(&self) -> &[u8] {
        self.copied_parameter()
    }

    /// Copied unrecognized parameter bytes, excluding this container's padding.
    pub fn unrecognized_parameter(&self) -> &[u8] {
        self.copied_parameter()
    }

    /// Copied unrecognized parameter bytes, excluding this container's padding.
    pub fn unrecognized_parameter_bytes(&self) -> &[u8] {
        self.copied_parameter()
    }
}

impl SctpCookiePreservativeParameter {
    /// Construct a Cookie Preservative parameter from a suggested life-span increment.
    pub fn from_suggested_cookie_life_span_increment_millis(increment_millis: u32) -> Self {
        Self::new(increment_millis.to_be_bytes())
    }

    /// Construct a Cookie Preservative parameter from a suggested life-span increment.
    pub fn from_cookie_life_span_increment_millis(increment_millis: u32) -> Self {
        Self::from_suggested_cookie_life_span_increment_millis(increment_millis)
    }

    /// Replace the suggested cookie life-span increment.
    pub fn with_suggested_cookie_life_span_increment_millis(self, increment_millis: u32) -> Self {
        self.with_value(increment_millis.to_be_bytes())
    }

    /// Replace the suggested cookie life-span increment.
    pub fn with_cookie_life_span_increment_millis(self, increment_millis: u32) -> Self {
        self.with_suggested_cookie_life_span_increment_millis(increment_millis)
    }

    /// Raw Cookie Preservative value bytes, excluding parameter padding.
    pub fn suggested_cookie_life_span_increment_bytes(&self) -> &[u8] {
        self.value()
    }

    /// Decode the suggested cookie life-span increment in milliseconds.
    pub fn suggested_cookie_life_span_increment_millis(&self) -> Result<u32> {
        expect_cookie_preservative_value_len(self.value())?;

        let value = self.value();
        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }

    /// Decode the suggested cookie life-span increment in milliseconds.
    pub fn cookie_life_span_increment_millis(&self) -> Result<u32> {
        self.suggested_cookie_life_span_increment_millis()
    }
}

impl SctpHostNameAddressParameter {
    /// Construct a Host Name Address parameter and append the required null terminator.
    pub fn from_host_name(host_name: impl AsRef<str>) -> Self {
        Self::new(host_name_parameter_value(host_name))
    }

    /// Compatibility spelling for constructing a Host Name Address parameter.
    pub fn from_hostname(hostname: impl AsRef<str>) -> Self {
        Self::from_host_name(hostname)
    }

    /// Replace the semantic host name value and append the required null terminator.
    pub fn with_host_name(self, host_name: impl AsRef<str>) -> Self {
        self.with_value(host_name_parameter_value(host_name))
    }

    /// Compatibility spelling for replacing the semantic host name value.
    pub fn with_hostname(self, hostname: impl AsRef<str>) -> Self {
        self.with_host_name(hostname)
    }

    /// Raw Host Name Address value bytes, including the transmitted null terminator.
    pub fn host_name_wire_bytes(&self) -> &[u8] {
        self.value()
    }

    /// Host name bytes before the first null terminator.
    pub fn host_name_bytes(&self) -> Result<&[u8]> {
        parse_host_name_parameter_value(self.value())
    }

    /// Interpret the declared value bytes as an RFC 1123 host name string.
    pub fn host_name(&self) -> Result<&str> {
        str::from_utf8(self.host_name_bytes()?).map_err(|_| {
            CrafterError::invalid_field_value(
                SCTP_HOST_NAME_ADDRESS_PARAMETER_FIELD,
                "host name must be valid ASCII",
            )
        })
    }

    /// Compatibility spelling for interpreting the declared value bytes as a host name.
    pub fn hostname(&self) -> Result<&str> {
        self.host_name()
    }
}

impl SctpSupportedAddressTypesParameter {
    /// Construct a Supported Address Types parameter from raw-preserving entries.
    pub fn from_address_types<T>(address_types: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<SctpAddressType>,
    {
        Self::new(encode_supported_address_types(address_types))
    }

    /// Construct a Supported Address Types parameter from raw entry values.
    pub fn from_address_type_values(address_types: impl IntoIterator<Item = u16>) -> Self {
        Self::from_address_types(address_types)
    }

    /// Construct a Supported Address Types parameter from IPv4/IPv6 families.
    pub fn from_address_families(
        address_families: impl IntoIterator<Item = SctpAddressFamily>,
    ) -> Self {
        Self::from_address_types(address_families)
    }

    /// Replace the Supported Address Types value from raw-preserving entries.
    pub fn with_address_types<T>(self, address_types: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<SctpAddressType>,
    {
        self.with_value(encode_supported_address_types(address_types))
    }

    /// Replace the Supported Address Types value from IPv4/IPv6 families.
    pub fn with_address_families(
        self,
        address_families: impl IntoIterator<Item = SctpAddressFamily>,
    ) -> Self {
        self.with_address_types(address_families)
    }

    /// Decode raw-preserving Supported Address Types entries.
    pub fn address_types(&self) -> Result<Vec<SctpAddressType>> {
        parse_supported_address_types(self.value())
    }

    /// Decode Supported Address Types entries as raw 16-bit values.
    pub fn address_type_values(&self) -> Result<Vec<u16>> {
        Ok(self.address_types()?.into_iter().map(u16::from).collect())
    }

    /// Decode the IPv4/IPv6 address families represented by this parameter.
    pub fn address_families(&self) -> Result<Vec<SctpAddressFamily>> {
        Ok(self
            .address_types()?
            .into_iter()
            .filter_map(SctpAddressType::address_family)
            .collect())
    }

    /// Return true when the raw Supported Address Types list contains `address_type`.
    pub fn supports_address_type(&self, address_type: impl Into<SctpAddressType>) -> Result<bool> {
        let address_type = address_type.into();
        Ok(self.address_types()?.contains(&address_type))
    }

    /// Return true when this parameter advertises an IPv4 or IPv6 family.
    pub fn supports_address_family(&self, address_family: SctpAddressFamily) -> Result<bool> {
        self.supports_address_type(address_family.address_type())
    }

    /// Return true when this parameter advertises IPv4 addresses.
    pub fn supports_ipv4(&self) -> Result<bool> {
        self.supports_address_family(SctpAddressFamily::Ipv4)
    }

    /// Return true when this parameter advertises IPv6 addresses.
    pub fn supports_ipv6(&self) -> Result<bool> {
        self.supports_address_family(SctpAddressFamily::Ipv6)
    }
}

impl SctpZeroChecksumAcceptableParameter {
    /// Construct a Zero Checksum Acceptable parameter from an error detection method.
    pub fn from_error_detection_method(
        method: impl Into<SctpErrorDetectionMethod>,
    ) -> SctpZeroChecksumAcceptableParameter {
        Self::new(method.into().raw().to_be_bytes())
    }

    /// Construct a Zero Checksum Acceptable parameter from a raw EDMID value.
    pub fn from_error_detection_method_identifier(identifier: u32) -> Self {
        Self::from_error_detection_method(identifier)
    }

    /// Construct a Zero Checksum Acceptable parameter from a raw EDMID value.
    pub fn from_edmid(identifier: u32) -> Self {
        Self::from_error_detection_method_identifier(identifier)
    }

    /// Replace the Error Detection Method Identifier.
    pub fn with_error_detection_method(self, method: impl Into<SctpErrorDetectionMethod>) -> Self {
        self.with_value(method.into().raw().to_be_bytes())
    }

    /// Replace the Error Detection Method Identifier with a raw EDMID value.
    pub fn with_error_detection_method_identifier(self, identifier: u32) -> Self {
        self.with_error_detection_method(identifier)
    }

    /// Replace the Error Detection Method Identifier with a raw EDMID value.
    pub fn with_edmid(self, identifier: u32) -> Self {
        self.with_error_detection_method_identifier(identifier)
    }

    /// Raw Error Detection Method Identifier bytes, excluding parameter padding.
    pub fn error_detection_method_bytes(&self) -> &[u8] {
        self.value()
    }

    /// Decode the Error Detection Method Identifier as a raw value.
    pub fn error_detection_method_identifier(&self) -> Result<u32> {
        expect_parameter_value_exact_len(
            self.value(),
            SCTP_ZERO_CHECKSUM_ACCEPTABLE_PARAMETER_CONTEXT,
            SCTP_ZERO_CHECKSUM_ACCEPTABLE_PARAMETER_VALUE_LEN,
            "value length must be four bytes",
        )?;

        let value = self.value();
        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }

    /// Decode the Error Detection Method Identifier as a raw value.
    pub fn edmid(&self) -> Result<u32> {
        self.error_detection_method_identifier()
    }

    /// Decode the Error Detection Method Identifier.
    pub fn error_detection_method(&self) -> Result<SctpErrorDetectionMethod> {
        Ok(SctpErrorDetectionMethod::new(
            self.error_detection_method_identifier()?,
        ))
    }

    /// Return true when this parameter advertises SCTP over DTLS as the error detection method.
    pub fn accepts_sctp_over_dtls(&self) -> Result<bool> {
        Ok(self.error_detection_method()? == SctpErrorDetectionMethod::SctpOverDtls)
    }
}

impl SctpRandomParameter {
    /// Construct a RANDOM parameter from raw random-number bytes.
    pub fn from_random_number(random_number: impl Into<Vec<u8>>) -> Self {
        Self::new(random_number)
    }

    /// Replace the raw random-number bytes.
    pub fn with_random_number(self, random_number: impl Into<Vec<u8>>) -> Self {
        self.with_value(random_number)
    }

    /// Raw random-number bytes, excluding parameter padding.
    pub fn random_number(&self) -> &[u8] {
        self.value()
    }

    /// Raw random-number bytes, excluding parameter padding.
    pub fn random_number_bytes(&self) -> &[u8] {
        self.random_number()
    }

    /// Validate the RFC 4895 association-setup RANDOM length.
    pub fn validate_association_random_number_len(&self) -> Result<()> {
        expect_parameter_value_exact_len(
            self.value(),
            SCTP_RANDOM_PARAMETER_CONTEXT,
            SCTP_AUTH_RANDOM_NUMBER_LEN,
            "random number must be 32 bytes",
        )
    }
}

impl SctpChunkListParameter {
    /// Construct a CHUNKS parameter from raw-preserving chunk types.
    pub fn from_chunk_types<T>(chunk_types: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<SctpChunkType>,
    {
        Self::new(encode_auth_chunk_types(chunk_types))
    }

    /// Construct a CHUNKS parameter from raw chunk type values.
    pub fn from_chunk_type_values(chunk_types: impl IntoIterator<Item = u8>) -> Self {
        Self::from_chunk_types(chunk_types)
    }

    /// Replace the CHUNKS value from raw-preserving chunk types.
    pub fn with_chunk_types<T>(self, chunk_types: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<SctpChunkType>,
    {
        self.with_value(encode_auth_chunk_types(chunk_types))
    }

    /// Replace the CHUNKS value from raw chunk type values.
    pub fn with_chunk_type_values(self, chunk_types: impl IntoIterator<Item = u8>) -> Self {
        self.with_chunk_types(chunk_types)
    }

    /// Decode raw-preserving CHUNKS entries.
    pub fn chunk_types(&self) -> Vec<SctpChunkType> {
        parse_auth_chunk_types(self.value())
    }

    /// Decode CHUNKS entries as raw 8-bit chunk type values.
    pub fn chunk_type_values(&self) -> Vec<u8> {
        self.chunk_types().into_iter().map(u8::from).collect()
    }

    /// Validate the RFC 4895 CHUNKS maximum parameter length.
    pub fn validate_max_length(&self) -> Result<()> {
        if self.value().len() > SCTP_AUTH_CHUNK_LIST_MAX_VALUE_LEN {
            return Err(CrafterError::invalid_field_value(
                SCTP_CHUNK_LIST_PARAMETER_CONTEXT,
                "parameter length must not exceed 260 bytes",
            ));
        }

        Ok(())
    }

    /// Return true when this CHUNKS parameter requests authentication for a chunk type.
    ///
    /// RFC 4895 says INIT, INIT ACK, SHUTDOWN COMPLETE, and AUTH entries are
    /// ignored if received, so this semantic helper never treats those entries
    /// as authentication requirements even when their raw bytes are preserved.
    pub fn requires_authentication_for_chunk_type(
        &self,
        chunk_type: impl Into<SctpChunkType>,
    ) -> bool {
        let chunk_type = chunk_type.into();
        !sctp_auth_chunk_list_ignored_chunk_type(chunk_type.raw())
            && self.chunk_types().contains(&chunk_type)
    }

    /// Return true when this CHUNKS parameter requests authentication for DATA chunks.
    pub fn requires_authentication_for_data(&self) -> bool {
        self.requires_authentication_for_chunk_type(SCTP_CHUNK_TYPE_DATA)
    }

    /// Return true when this CHUNKS parameter requests authentication for COOKIE ECHO chunks.
    pub fn requires_authentication_for_cookie_echo(&self) -> bool {
        self.requires_authentication_for_chunk_type(SCTP_CHUNK_TYPE_COOKIE_ECHO)
    }
}

impl SctpRequestedHmacAlgorithmParameter {
    /// Construct an HMAC-ALGO parameter from raw-preserving HMAC Identifiers.
    pub fn from_hmac_identifiers<T>(identifiers: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<SctpHmacIdentifier>,
    {
        Self::new(encode_hmac_identifiers(identifiers))
    }

    /// Construct an HMAC-ALGO parameter from raw HMAC Identifier values.
    pub fn from_hmac_identifier_values(identifiers: impl IntoIterator<Item = u16>) -> Self {
        Self::from_hmac_identifiers(identifiers)
    }

    /// Replace the HMAC-ALGO value from raw-preserving HMAC Identifiers.
    pub fn with_hmac_identifiers<T>(self, identifiers: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<SctpHmacIdentifier>,
    {
        self.with_value(encode_hmac_identifiers(identifiers))
    }

    /// Replace the HMAC-ALGO value from raw HMAC Identifier values.
    pub fn with_hmac_identifier_values(self, identifiers: impl IntoIterator<Item = u16>) -> Self {
        self.with_hmac_identifiers(identifiers)
    }

    /// Decode raw-preserving HMAC Identifiers listed by sender preference.
    pub fn hmac_identifiers(&self) -> Result<Vec<SctpHmacIdentifier>> {
        parse_hmac_identifiers(self.value())
    }

    /// Decode HMAC Identifiers as raw 16-bit values.
    pub fn hmac_identifier_values(&self) -> Result<Vec<u16>> {
        Ok(self
            .hmac_identifiers()?
            .into_iter()
            .map(u16::from)
            .collect())
    }

    /// Return the first HMAC Identifier listed by sender preference.
    pub fn preferred_hmac_identifier(&self) -> Result<Option<SctpHmacIdentifier>> {
        Ok(self.hmac_identifiers()?.into_iter().next())
    }

    /// Return true when the HMAC-ALGO list includes `identifier`.
    pub fn requests_hmac_identifier(
        &self,
        identifier: impl Into<SctpHmacIdentifier>,
    ) -> Result<bool> {
        let identifier = identifier.into().raw();
        Ok(self.hmac_identifier_values()?.contains(&identifier))
    }

    /// Return true when the HMAC-ALGO list includes SHA-1.
    pub fn requests_sha1(&self) -> Result<bool> {
        self.requests_hmac_identifier(SctpHmacIdentifier::Sha1)
    }

    /// Return true when the HMAC-ALGO list includes SHA-256.
    pub fn requests_sha256(&self) -> Result<bool> {
        self.requests_hmac_identifier(SctpHmacIdentifier::Sha256)
    }

    /// Validate the RFC 4895 sender-side requirement to include SHA-1.
    pub fn validate_includes_sha1(&self) -> Result<()> {
        if !self.requests_sha1()? {
            return Err(CrafterError::invalid_field_value(
                SCTP_REQUESTED_HMAC_ALGORITHM_PARAMETER_CONTEXT,
                "HMAC identifier list must include SHA-1",
            ));
        }

        Ok(())
    }
}

impl SctpSupportedExtensionsParameter {
    /// Construct a Supported Extensions parameter from raw-preserving chunk types.
    pub fn from_chunk_types<T>(chunk_types: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<SctpChunkType>,
    {
        Self::new(encode_supported_extension_chunk_types(chunk_types))
    }

    /// Construct a Supported Extensions parameter from raw chunk type values.
    pub fn from_chunk_type_values(chunk_types: impl IntoIterator<Item = u8>) -> Self {
        Self::from_chunk_types(chunk_types)
    }

    /// Replace the Supported Extensions value from raw-preserving chunk types.
    pub fn with_chunk_types<T>(self, chunk_types: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<SctpChunkType>,
    {
        self.with_value(encode_supported_extension_chunk_types(chunk_types))
    }

    /// Replace the Supported Extensions value from raw chunk type values.
    pub fn with_chunk_type_values(self, chunk_types: impl IntoIterator<Item = u8>) -> Self {
        self.with_chunk_types(chunk_types)
    }

    /// Decode raw-preserving Supported Extensions chunk type entries.
    pub fn chunk_types(&self) -> Vec<SctpChunkType> {
        parse_supported_extension_chunk_types(self.value())
    }

    /// Decode Supported Extensions entries as raw 8-bit chunk type values.
    pub fn chunk_type_values(&self) -> Vec<u8> {
        self.chunk_types().into_iter().map(u8::from).collect()
    }

    /// Return true when the Supported Extensions list contains `chunk_type`.
    pub fn supports_chunk_type(&self, chunk_type: impl Into<SctpChunkType>) -> bool {
        let chunk_type = chunk_type.into();
        self.chunk_types().contains(&chunk_type)
    }

    /// Return true when this parameter advertises ASCONF support.
    pub fn supports_asconf(&self) -> bool {
        self.supports_chunk_type(SCTP_CHUNK_TYPE_ASCONF)
    }

    /// Return true when this parameter advertises ASCONF ACK support.
    pub fn supports_asconf_ack(&self) -> bool {
        self.supports_chunk_type(SCTP_CHUNK_TYPE_ASCONF_ACK)
    }

    /// Return true when this parameter advertises AUTH support.
    pub fn supports_auth(&self) -> bool {
        self.supports_chunk_type(SCTP_CHUNK_TYPE_AUTH)
    }

    /// Return true when this parameter advertises FORWARD TSN support by chunk type.
    pub fn supports_forward_tsn_chunk(&self) -> bool {
        self.supports_chunk_type(SCTP_CHUNK_TYPE_FORWARD_TSN)
    }
}

impl SctpForwardTsnSupportedParameter {
    /// Construct a well-formed Forward-TSN-Supported parameter.
    pub fn from_supported() -> Self {
        Self::new([])
    }

    /// Validate that this Forward-TSN-Supported parameter carries no value bytes.
    pub fn validate_supported(&self) -> Result<()> {
        expect_parameter_value_exact_len(
            self.value(),
            SCTP_FORWARD_TSN_SUPPORTED_PARAMETER_CONTEXT,
            SCTP_FORWARD_TSN_SUPPORTED_PARAMETER_VALUE_LEN,
            "value length must be zero bytes",
        )
    }

    /// Return true when this well-formed parameter advertises Forward TSN support.
    pub fn is_forward_tsn_supported(&self) -> Result<bool> {
        self.validate_supported()?;
        Ok(true)
    }
}

impl SctpOutgoingSsnResetRequestParameter {
    /// Construct an Outgoing SSN Reset Request from its fixed fields and optional stream numbers.
    pub fn from_request_response_sequence_numbers_sender_last_assigned_tsn_and_stream_numbers(
        request_sequence_number: u32,
        response_sequence_number: u32,
        sender_last_assigned_tsn: u32,
        stream_numbers: impl IntoIterator<Item = u16>,
    ) -> Self {
        Self::new(encode_outgoing_ssn_reset_request_value(
            request_sequence_number,
            response_sequence_number,
            sender_last_assigned_tsn,
            stream_numbers,
        ))
    }

    /// Construct an Outgoing SSN Reset Request for all outgoing streams.
    pub fn from_request_response_sequence_numbers_and_sender_last_assigned_tsn(
        request_sequence_number: u32,
        response_sequence_number: u32,
        sender_last_assigned_tsn: u32,
    ) -> Self {
        Self::from_request_response_sequence_numbers_sender_last_assigned_tsn_and_stream_numbers(
            request_sequence_number,
            response_sequence_number,
            sender_last_assigned_tsn,
            [],
        )
    }

    /// Replace the value with fixed fields and optional stream numbers.
    pub fn with_request_response_sequence_numbers_sender_last_assigned_tsn_and_stream_numbers(
        self,
        request_sequence_number: u32,
        response_sequence_number: u32,
        sender_last_assigned_tsn: u32,
        stream_numbers: impl IntoIterator<Item = u16>,
    ) -> Self {
        self.with_value(encode_outgoing_ssn_reset_request_value(
            request_sequence_number,
            response_sequence_number,
            sender_last_assigned_tsn,
            stream_numbers,
        ))
    }

    /// Decode the Re-configuration Request Sequence Number.
    pub fn reconfiguration_request_sequence_number(&self) -> Result<u32> {
        parse_reconfiguration_u32_field(
            self.value(),
            0,
            SCTP_OUTGOING_SSN_RESET_REQUEST_PARAMETER_CONTEXT,
        )
    }

    /// Decode the Re-configuration Request Sequence Number.
    pub fn request_sequence_number(&self) -> Result<u32> {
        self.reconfiguration_request_sequence_number()
    }

    /// Decode the Re-configuration Response Sequence Number.
    pub fn reconfiguration_response_sequence_number(&self) -> Result<u32> {
        parse_reconfiguration_u32_field(
            self.value(),
            SCTP_RECONFIGURATION_SEQUENCE_NUMBER_LEN,
            SCTP_OUTGOING_SSN_RESET_REQUEST_PARAMETER_CONTEXT,
        )
    }

    /// Decode the Re-configuration Response Sequence Number.
    pub fn response_sequence_number(&self) -> Result<u32> {
        self.reconfiguration_response_sequence_number()
    }

    /// Decode the Sender's Last Assigned TSN field.
    pub fn sender_last_assigned_tsn(&self) -> Result<u32> {
        parse_reconfiguration_u32_field(
            self.value(),
            SCTP_RECONFIGURATION_SEQUENCE_NUMBER_LEN * 2,
            SCTP_OUTGOING_SSN_RESET_REQUEST_PARAMETER_CONTEXT,
        )
    }

    /// Decode the optional stream-number list.
    pub fn stream_numbers(&self) -> Result<Vec<u16>> {
        parse_reconfiguration_stream_numbers(
            self.value(),
            SCTP_OUTGOING_SSN_RESET_REQUEST_FIXED_VALUE_LEN,
            SCTP_OUTGOING_SSN_RESET_REQUEST_PARAMETER_CONTEXT,
            SCTP_OUTGOING_SSN_RESET_REQUEST_STREAMS_CONTEXT,
        )
    }

    /// Return true when the request resets all outgoing streams.
    pub fn resets_all_streams(&self) -> Result<bool> {
        Ok(self.stream_numbers()?.is_empty())
    }

    /// Validate the RFC 6525 Outgoing SSN Reset Request value shape.
    pub fn validate_outgoing_ssn_reset_request(&self) -> Result<()> {
        validate_reconfiguration_stream_list_value(
            self.value(),
            SCTP_OUTGOING_SSN_RESET_REQUEST_FIXED_VALUE_LEN,
            SCTP_OUTGOING_SSN_RESET_REQUEST_PARAMETER_CONTEXT,
            SCTP_OUTGOING_SSN_RESET_REQUEST_STREAMS_CONTEXT,
        )
    }
}

impl SctpIncomingSsnResetRequestParameter {
    /// Construct an Incoming SSN Reset Request from its request sequence and optional stream numbers.
    pub fn from_request_sequence_number_and_stream_numbers(
        request_sequence_number: u32,
        stream_numbers: impl IntoIterator<Item = u16>,
    ) -> Self {
        Self::new(encode_incoming_ssn_reset_request_value(
            request_sequence_number,
            stream_numbers,
        ))
    }

    /// Construct an Incoming SSN Reset Request for all incoming streams.
    pub fn from_request_sequence_number(request_sequence_number: u32) -> Self {
        Self::from_request_sequence_number_and_stream_numbers(request_sequence_number, [])
    }

    /// Replace the value with a request sequence and optional stream numbers.
    pub fn with_request_sequence_number_and_stream_numbers(
        self,
        request_sequence_number: u32,
        stream_numbers: impl IntoIterator<Item = u16>,
    ) -> Self {
        self.with_value(encode_incoming_ssn_reset_request_value(
            request_sequence_number,
            stream_numbers,
        ))
    }

    /// Decode the Re-configuration Request Sequence Number.
    pub fn reconfiguration_request_sequence_number(&self) -> Result<u32> {
        parse_reconfiguration_u32_field(
            self.value(),
            0,
            SCTP_INCOMING_SSN_RESET_REQUEST_PARAMETER_CONTEXT,
        )
    }

    /// Decode the Re-configuration Request Sequence Number.
    pub fn request_sequence_number(&self) -> Result<u32> {
        self.reconfiguration_request_sequence_number()
    }

    /// Decode the optional stream-number list.
    pub fn stream_numbers(&self) -> Result<Vec<u16>> {
        parse_reconfiguration_stream_numbers(
            self.value(),
            SCTP_INCOMING_SSN_RESET_REQUEST_FIXED_VALUE_LEN,
            SCTP_INCOMING_SSN_RESET_REQUEST_PARAMETER_CONTEXT,
            SCTP_INCOMING_SSN_RESET_REQUEST_STREAMS_CONTEXT,
        )
    }

    /// Return true when the request resets all incoming streams.
    pub fn resets_all_streams(&self) -> Result<bool> {
        Ok(self.stream_numbers()?.is_empty())
    }

    /// Validate the RFC 6525 Incoming SSN Reset Request value shape.
    pub fn validate_incoming_ssn_reset_request(&self) -> Result<()> {
        validate_reconfiguration_stream_list_value(
            self.value(),
            SCTP_INCOMING_SSN_RESET_REQUEST_FIXED_VALUE_LEN,
            SCTP_INCOMING_SSN_RESET_REQUEST_PARAMETER_CONTEXT,
            SCTP_INCOMING_SSN_RESET_REQUEST_STREAMS_CONTEXT,
        )
    }
}

impl SctpSsnTsnResetRequestParameter {
    /// Construct an SSN/TSN Reset Request from a request sequence number.
    pub fn from_request_sequence_number(request_sequence_number: u32) -> Self {
        Self::new(request_sequence_number.to_be_bytes())
    }

    /// Replace the request sequence number.
    pub fn with_request_sequence_number(self, request_sequence_number: u32) -> Self {
        self.with_value(request_sequence_number.to_be_bytes())
    }

    /// Decode the Re-configuration Request Sequence Number.
    pub fn reconfiguration_request_sequence_number(&self) -> Result<u32> {
        expect_parameter_value_exact_len(
            self.value(),
            SCTP_SSN_TSN_RESET_REQUEST_PARAMETER_CONTEXT,
            SCTP_SSN_TSN_RESET_REQUEST_VALUE_LEN,
            "value length must be four bytes",
        )?;
        parse_reconfiguration_u32_field(
            self.value(),
            0,
            SCTP_SSN_TSN_RESET_REQUEST_PARAMETER_CONTEXT,
        )
    }

    /// Decode the Re-configuration Request Sequence Number.
    pub fn request_sequence_number(&self) -> Result<u32> {
        self.reconfiguration_request_sequence_number()
    }

    /// Validate the RFC 6525 SSN/TSN Reset Request value shape.
    pub fn validate_ssn_tsn_reset_request(&self) -> Result<()> {
        expect_parameter_value_exact_len(
            self.value(),
            SCTP_SSN_TSN_RESET_REQUEST_PARAMETER_CONTEXT,
            SCTP_SSN_TSN_RESET_REQUEST_VALUE_LEN,
            "value length must be four bytes",
        )
    }
}

impl SctpReConfigurationResponseParameter {
    /// Construct a Re-configuration Response without optional next-TSN fields.
    pub fn from_response_sequence_number_and_result(
        response_sequence_number: u32,
        result: impl Into<SctpReconfigurationResult>,
    ) -> Self {
        Self::new(encode_reconfiguration_response_value(
            response_sequence_number,
            result,
            None,
        ))
    }

    /// Construct a Re-configuration Response from a raw result value.
    pub fn from_response_sequence_number_and_result_value(
        response_sequence_number: u32,
        result: u32,
    ) -> Self {
        Self::from_response_sequence_number_and_result(response_sequence_number, result)
    }

    /// Construct a Re-configuration Response with Sender's and Receiver's Next TSN fields.
    pub fn from_response_sequence_number_result_and_next_tsns(
        response_sequence_number: u32,
        result: impl Into<SctpReconfigurationResult>,
        sender_next_tsn: u32,
        receiver_next_tsn: u32,
    ) -> Self {
        Self::new(encode_reconfiguration_response_value(
            response_sequence_number,
            result,
            Some((sender_next_tsn, receiver_next_tsn)),
        ))
    }

    /// Replace the response sequence number and result without optional next-TSN fields.
    pub fn with_response_sequence_number_and_result(
        self,
        response_sequence_number: u32,
        result: impl Into<SctpReconfigurationResult>,
    ) -> Self {
        self.with_value(encode_reconfiguration_response_value(
            response_sequence_number,
            result,
            None,
        ))
    }

    /// Replace the response sequence number, result, and optional next-TSN fields.
    pub fn with_response_sequence_number_result_and_next_tsns(
        self,
        response_sequence_number: u32,
        result: impl Into<SctpReconfigurationResult>,
        sender_next_tsn: u32,
        receiver_next_tsn: u32,
    ) -> Self {
        self.with_value(encode_reconfiguration_response_value(
            response_sequence_number,
            result,
            Some((sender_next_tsn, receiver_next_tsn)),
        ))
    }

    /// Decode the Re-configuration Response Sequence Number.
    pub fn reconfiguration_response_sequence_number(&self) -> Result<u32> {
        parse_reconfiguration_u32_field(
            self.value(),
            0,
            SCTP_RE_CONFIGURATION_RESPONSE_PARAMETER_CONTEXT,
        )
    }

    /// Decode the Re-configuration Response Sequence Number.
    pub fn response_sequence_number(&self) -> Result<u32> {
        self.reconfiguration_response_sequence_number()
    }

    /// Decode the raw response result value.
    pub fn result_value(&self) -> Result<u32> {
        parse_reconfiguration_u32_field(
            self.value(),
            SCTP_RECONFIGURATION_SEQUENCE_NUMBER_LEN,
            SCTP_RE_CONFIGURATION_RESPONSE_PARAMETER_CONTEXT,
        )
    }

    /// Decode the response result label.
    pub fn result(&self) -> Result<SctpReconfigurationResult> {
        Ok(SctpReconfigurationResult::new(self.result_value()?))
    }

    /// Decode the optional Sender's and Receiver's Next TSN fields.
    pub fn next_tsns(&self) -> Result<Option<(u32, u32)>> {
        validate_reconfiguration_response_value(self.value())?;
        if self.value().len() == SCTP_RE_CONFIGURATION_RESPONSE_VALUE_LEN {
            return Ok(None);
        }

        Ok(Some((
            parse_reconfiguration_u32_field(
                self.value(),
                SCTP_RE_CONFIGURATION_RESPONSE_VALUE_LEN,
                SCTP_RE_CONFIGURATION_RESPONSE_PARAMETER_CONTEXT,
            )?,
            parse_reconfiguration_u32_field(
                self.value(),
                SCTP_RE_CONFIGURATION_RESPONSE_VALUE_LEN + SCTP_RECONFIGURATION_SEQUENCE_NUMBER_LEN,
                SCTP_RE_CONFIGURATION_RESPONSE_PARAMETER_CONTEXT,
            )?,
        )))
    }

    /// Decode the optional Sender's Next TSN field.
    pub fn sender_next_tsn(&self) -> Result<Option<u32>> {
        Ok(self.next_tsns()?.map(|(sender, _)| sender))
    }

    /// Decode the optional Receiver's Next TSN field.
    pub fn receiver_next_tsn(&self) -> Result<Option<u32>> {
        Ok(self.next_tsns()?.map(|(_, receiver)| receiver))
    }

    /// Validate the RFC 6525 Re-configuration Response value shape.
    pub fn validate_reconfiguration_response(&self) -> Result<()> {
        validate_reconfiguration_response_value(self.value())
    }
}

macro_rules! impl_sctp_add_streams_request_parameter {
    ($name:ident, $context:ident) => {
        impl $name {
            /// Construct an Add Streams Request with an explicit reserved field.
            pub fn from_request_sequence_number_number_of_new_streams_and_reserved(
                request_sequence_number: u32,
                number_of_new_streams: u16,
                reserved: u16,
            ) -> Self {
                Self::new(encode_add_streams_request_value(
                    request_sequence_number,
                    number_of_new_streams,
                    reserved,
                ))
            }

            /// Construct an Add Streams Request with the reserved field set to zero.
            pub fn from_request_sequence_number_and_number_of_new_streams(
                request_sequence_number: u32,
                number_of_new_streams: u16,
            ) -> Self {
                Self::from_request_sequence_number_number_of_new_streams_and_reserved(
                    request_sequence_number,
                    number_of_new_streams,
                    0,
                )
            }

            /// Replace the value with an explicit reserved field.
            pub fn with_request_sequence_number_number_of_new_streams_and_reserved(
                self,
                request_sequence_number: u32,
                number_of_new_streams: u16,
                reserved: u16,
            ) -> Self {
                self.with_value(encode_add_streams_request_value(
                    request_sequence_number,
                    number_of_new_streams,
                    reserved,
                ))
            }

            /// Replace the value with the reserved field set to zero.
            pub fn with_request_sequence_number_and_number_of_new_streams(
                self,
                request_sequence_number: u32,
                number_of_new_streams: u16,
            ) -> Self {
                self.with_request_sequence_number_number_of_new_streams_and_reserved(
                    request_sequence_number,
                    number_of_new_streams,
                    0,
                )
            }

            /// Decode the Re-configuration Request Sequence Number.
            pub fn reconfiguration_request_sequence_number(&self) -> Result<u32> {
                parse_reconfiguration_u32_field(self.value(), 0, $context)
            }

            /// Decode the Re-configuration Request Sequence Number.
            pub fn request_sequence_number(&self) -> Result<u32> {
                self.reconfiguration_request_sequence_number()
            }

            /// Decode the Number of new streams field.
            pub fn number_of_new_streams(&self) -> Result<u16> {
                parse_reconfiguration_u16_field(
                    self.value(),
                    SCTP_RECONFIGURATION_SEQUENCE_NUMBER_LEN,
                    $context,
                )
            }

            /// Decode the reserved field.
            pub fn reserved(&self) -> Result<u16> {
                parse_reconfiguration_u16_field(
                    self.value(),
                    SCTP_RECONFIGURATION_SEQUENCE_NUMBER_LEN
                        + SCTP_RECONFIGURATION_STREAM_NUMBER_LEN,
                    $context,
                )
            }

            /// Validate the RFC 6525 Add Streams Request value shape.
            pub fn validate_add_streams_request(&self) -> Result<()> {
                expect_parameter_value_exact_len(
                    self.value(),
                    $context,
                    SCTP_ADD_STREAMS_REQUEST_VALUE_LEN,
                    "value length must be eight bytes",
                )
            }
        }
    };
}

impl_sctp_add_streams_request_parameter!(
    SctpAddOutgoingStreamsRequestParameter,
    SCTP_ADD_OUTGOING_STREAMS_REQUEST_PARAMETER_CONTEXT
);
impl_sctp_add_streams_request_parameter!(
    SctpAddIncomingStreamsRequestParameter,
    SCTP_ADD_INCOMING_STREAMS_REQUEST_PARAMETER_CONTEXT
);

macro_rules! impl_sctp_asconf_address_parameter {
    ($name:ident, $context:ident) => {
        impl $name {
            /// Construct the parameter from an ASCONF correlation ID and raw address-parameter TLV bytes.
            pub fn from_correlation_id_and_address_parameter_bytes(
                correlation_id: u32,
                address_parameter: impl Into<Vec<u8>>,
            ) -> Self {
                Self::new(sctp_asconf_correlation_id_and_value(
                    correlation_id,
                    address_parameter,
                ))
            }

            /// Construct the parameter from an ASCONF request correlation ID and raw address-parameter TLV bytes.
            pub fn from_request_correlation_id_and_address_parameter_bytes(
                correlation_id: u32,
                address_parameter: impl Into<Vec<u8>>,
            ) -> Self {
                Self::from_correlation_id_and_address_parameter_bytes(
                    correlation_id,
                    address_parameter,
                )
            }

            /// Construct the parameter from an ASCONF correlation ID and IPv4 address.
            pub fn from_correlation_id_and_ipv4_address(
                correlation_id: u32,
                address: Ipv4Addr,
            ) -> Self {
                Self::from_correlation_id_and_address_parameter_bytes(
                    correlation_id,
                    sctp_ipv4_address_parameter_bytes(address),
                )
            }

            /// Construct the parameter from an ASCONF request correlation ID and IPv4 address.
            pub fn from_request_correlation_id_and_ipv4_address(
                correlation_id: u32,
                address: Ipv4Addr,
            ) -> Self {
                Self::from_correlation_id_and_ipv4_address(correlation_id, address)
            }

            /// Construct the parameter from an ASCONF correlation ID and IPv6 address.
            pub fn from_correlation_id_and_ipv6_address(
                correlation_id: u32,
                address: Ipv6Addr,
            ) -> Self {
                Self::from_correlation_id_and_address_parameter_bytes(
                    correlation_id,
                    sctp_ipv6_address_parameter_bytes(address),
                )
            }

            /// Construct the parameter from an ASCONF request correlation ID and IPv6 address.
            pub fn from_request_correlation_id_and_ipv6_address(
                correlation_id: u32,
                address: Ipv6Addr,
            ) -> Self {
                Self::from_correlation_id_and_ipv6_address(correlation_id, address)
            }

            /// Replace the value with an ASCONF correlation ID and raw address-parameter TLV bytes.
            pub fn with_correlation_id_and_address_parameter_bytes(
                self,
                correlation_id: u32,
                address_parameter: impl Into<Vec<u8>>,
            ) -> Self {
                self.with_value(sctp_asconf_correlation_id_and_value(
                    correlation_id,
                    address_parameter,
                ))
            }

            /// Replace the value with an ASCONF request correlation ID and raw address-parameter TLV bytes.
            pub fn with_request_correlation_id_and_address_parameter_bytes(
                self,
                correlation_id: u32,
                address_parameter: impl Into<Vec<u8>>,
            ) -> Self {
                self.with_correlation_id_and_address_parameter_bytes(
                    correlation_id,
                    address_parameter,
                )
            }

            /// Replace the value with an ASCONF correlation ID and IPv4 address.
            pub fn with_correlation_id_and_ipv4_address(
                self,
                correlation_id: u32,
                address: Ipv4Addr,
            ) -> Self {
                self.with_correlation_id_and_address_parameter_bytes(
                    correlation_id,
                    sctp_ipv4_address_parameter_bytes(address),
                )
            }

            /// Replace the value with an ASCONF correlation ID and IPv6 address.
            pub fn with_correlation_id_and_ipv6_address(
                self,
                correlation_id: u32,
                address: Ipv6Addr,
            ) -> Self {
                self.with_correlation_id_and_address_parameter_bytes(
                    correlation_id,
                    sctp_ipv6_address_parameter_bytes(address),
                )
            }

            /// Decode the ASCONF request correlation ID.
            pub fn correlation_id(&self) -> Result<u32> {
                parse_asconf_correlation_id(self.value(), $context)
            }

            /// Decode the ASCONF request correlation ID.
            pub fn request_correlation_id(&self) -> Result<u32> {
                self.correlation_id()
            }

            /// Raw nested IPv4 or IPv6 address-parameter TLV bytes.
            pub fn address_parameter_bytes(&self) -> Result<&[u8]> {
                parse_asconf_address_parameter_bytes(self.value(), $context)
            }

            /// Raw nested IPv4 or IPv6 address-parameter TLV bytes.
            pub fn raw_address_parameter_bytes(&self) -> Result<&[u8]> {
                self.address_parameter_bytes()
            }

            /// Decode the nested address parameter type codepoint.
            pub fn address_parameter_type_value(&self) -> Result<u16> {
                let (parameter_type, _, _, _) =
                    parse_nested_parameter(self.address_parameter_bytes()?)?;
                Ok(parameter_type)
            }

            /// Decode the nested address parameter declared length.
            pub fn address_parameter_declared_length(&self) -> Result<usize> {
                let (_, declared_length, _, _) =
                    parse_nested_parameter(self.address_parameter_bytes()?)?;
                Ok(declared_length)
            }

            /// Decode the nested address parameter value bytes, excluding its TLV header and padding.
            pub fn address_value_bytes(&self) -> Result<&[u8]> {
                let (_, _, value, _) = parse_nested_parameter(self.address_parameter_bytes()?)?;
                Ok(value)
            }

            /// Validate that the nested address parameter is a single IPv4 or IPv6 address TLV.
            pub fn validate_address_parameter(&self) -> Result<()> {
                validate_asconf_address_parameter(self.address_parameter_bytes()?)
            }

            /// Interpret the nested address parameter as an IPv4 address.
            pub fn ipv4_address(&self) -> Result<Ipv4Addr> {
                parse_asconf_ipv4_address(self.address_parameter_bytes()?)
            }

            /// Interpret the nested address parameter as an IPv6 address.
            pub fn ipv6_address(&self) -> Result<Ipv6Addr> {
                parse_asconf_ipv6_address(self.address_parameter_bytes()?)
            }
        }
    };
}

impl_sctp_asconf_address_parameter!(
    SctpAddIpAddressParameter,
    SCTP_ADD_IP_ADDRESS_PARAMETER_CONTEXT
);
impl_sctp_asconf_address_parameter!(
    SctpDeleteIpAddressParameter,
    SCTP_DELETE_IP_ADDRESS_PARAMETER_CONTEXT
);
impl_sctp_asconf_address_parameter!(
    SctpSetPrimaryAddressParameter,
    SCTP_SET_PRIMARY_ADDRESS_PARAMETER_CONTEXT
);

impl SctpSuccessIndicationParameter {
    /// Construct a Success Indication parameter from an ASCONF response correlation ID.
    pub fn from_response_correlation_id(correlation_id: u32) -> Self {
        Self::new(correlation_id.to_be_bytes())
    }

    /// Construct a Success Indication parameter from an ASCONF response correlation ID.
    pub fn from_correlation_id(correlation_id: u32) -> Self {
        Self::from_response_correlation_id(correlation_id)
    }

    /// Replace the ASCONF response correlation ID.
    pub fn with_response_correlation_id(self, correlation_id: u32) -> Self {
        self.with_value(correlation_id.to_be_bytes())
    }

    /// Replace the ASCONF response correlation ID.
    pub fn with_correlation_id(self, correlation_id: u32) -> Self {
        self.with_response_correlation_id(correlation_id)
    }

    /// Decode the ASCONF response correlation ID.
    pub fn response_correlation_id(&self) -> Result<u32> {
        parse_exact_asconf_correlation_id(self.value(), SCTP_SUCCESS_INDICATION_PARAMETER_CONTEXT)
    }

    /// Decode the ASCONF response correlation ID.
    pub fn correlation_id(&self) -> Result<u32> {
        self.response_correlation_id()
    }

    /// Validate the RFC 5061 fixed Success Indication value length.
    pub fn validate_success_indication(&self) -> Result<()> {
        expect_parameter_value_exact_len(
            self.value(),
            SCTP_SUCCESS_INDICATION_PARAMETER_CONTEXT,
            SCTP_SUCCESS_INDICATION_PARAMETER_VALUE_LEN,
            "value length must be four bytes",
        )
    }
}

impl SctpErrorCauseIndicationParameter {
    /// Construct an Error Cause Indication parameter from an ASCONF response correlation ID and raw cause bytes.
    pub fn from_response_correlation_id_and_error_cause_bytes(
        correlation_id: u32,
        error_causes: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(sctp_asconf_correlation_id_and_value(
            correlation_id,
            error_causes,
        ))
    }

    /// Construct an Error Cause Indication parameter from an ASCONF response correlation ID and raw cause bytes.
    pub fn from_correlation_id_and_error_cause_bytes(
        correlation_id: u32,
        error_causes: impl Into<Vec<u8>>,
    ) -> Self {
        Self::from_response_correlation_id_and_error_cause_bytes(correlation_id, error_causes)
    }

    /// Replace the value with an ASCONF response correlation ID and raw cause bytes.
    pub fn with_response_correlation_id_and_error_cause_bytes(
        self,
        correlation_id: u32,
        error_causes: impl Into<Vec<u8>>,
    ) -> Self {
        self.with_value(sctp_asconf_correlation_id_and_value(
            correlation_id,
            error_causes,
        ))
    }

    /// Replace the value with an ASCONF response correlation ID and raw cause bytes.
    pub fn with_correlation_id_and_error_cause_bytes(
        self,
        correlation_id: u32,
        error_causes: impl Into<Vec<u8>>,
    ) -> Self {
        self.with_response_correlation_id_and_error_cause_bytes(correlation_id, error_causes)
    }

    /// Decode the ASCONF response correlation ID.
    pub fn response_correlation_id(&self) -> Result<u32> {
        parse_asconf_correlation_id(self.value(), SCTP_ERROR_CAUSE_INDICATION_PARAMETER_CONTEXT)
    }

    /// Decode the ASCONF response correlation ID.
    pub fn correlation_id(&self) -> Result<u32> {
        self.response_correlation_id()
    }

    /// Raw error-cause bytes following the ASCONF response correlation ID.
    pub fn error_cause_bytes(&self) -> Result<&[u8]> {
        parse_asconf_trailing_value(self.value(), SCTP_ERROR_CAUSE_INDICATION_PARAMETER_CONTEXT)
    }

    /// Raw error-cause bytes following the ASCONF response correlation ID.
    pub fn error_causes(&self) -> Result<&[u8]> {
        self.error_cause_bytes()
    }

    /// Validate that the response includes at least one error-cause TLV header.
    pub fn validate_contains_error_cause(&self) -> Result<()> {
        let error_causes = self.error_cause_bytes()?;
        if error_causes.len() < SCTP_PARAMETER_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                SCTP_ERROR_CAUSE_INDICATION_ERROR_CAUSES_CONTEXT,
                SCTP_PARAMETER_HEADER_LEN,
                error_causes.len(),
            ));
        }

        Ok(())
    }
}

impl SctpAdaptationLayerIndicationParameter {
    /// Construct an Adaptation Layer Indication parameter from an adaptation code point.
    pub fn from_adaptation_code_point(code_point: impl Into<SctpAdaptationCodePoint>) -> Self {
        Self::new(code_point.into().raw().to_be_bytes())
    }

    /// Construct an Adaptation Layer Indication parameter from a raw code point.
    pub fn from_adaptation_code_point_value(code_point: u32) -> Self {
        Self::from_adaptation_code_point(code_point)
    }

    /// Replace the Adaptation Code Point.
    pub fn with_adaptation_code_point(
        self,
        code_point: impl Into<SctpAdaptationCodePoint>,
    ) -> Self {
        self.with_value(code_point.into().raw().to_be_bytes())
    }

    /// Replace the Adaptation Code Point with a raw value.
    pub fn with_adaptation_code_point_value(self, code_point: u32) -> Self {
        self.with_adaptation_code_point(code_point)
    }

    /// Raw Adaptation Code Point bytes, excluding parameter padding.
    pub fn adaptation_code_point_bytes(&self) -> &[u8] {
        self.value()
    }

    /// Decode the Adaptation Code Point as a raw value.
    pub fn adaptation_code_point_value(&self) -> Result<u32> {
        expect_parameter_value_exact_len(
            self.value(),
            SCTP_ADAPTATION_LAYER_INDICATION_PARAMETER_CONTEXT,
            SCTP_ADAPTATION_LAYER_INDICATION_PARAMETER_VALUE_LEN,
            "value length must be four bytes",
        )?;

        let value = self.value();
        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }

    /// Decode the Adaptation Code Point.
    pub fn adaptation_code_point(&self) -> Result<SctpAdaptationCodePoint> {
        Ok(SctpAdaptationCodePoint::new(
            self.adaptation_code_point_value()?,
        ))
    }
}

fn encode_outgoing_ssn_reset_request_value(
    request_sequence_number: u32,
    response_sequence_number: u32,
    sender_last_assigned_tsn: u32,
    stream_numbers: impl IntoIterator<Item = u16>,
) -> Vec<u8> {
    let stream_numbers = stream_numbers.into_iter();
    let (lower, _) = stream_numbers.size_hint();
    let mut value = Vec::with_capacity(
        SCTP_OUTGOING_SSN_RESET_REQUEST_FIXED_VALUE_LEN
            + lower * SCTP_RECONFIGURATION_STREAM_NUMBER_LEN,
    );
    value.extend_from_slice(&request_sequence_number.to_be_bytes());
    value.extend_from_slice(&response_sequence_number.to_be_bytes());
    value.extend_from_slice(&sender_last_assigned_tsn.to_be_bytes());
    append_reconfiguration_stream_numbers(&mut value, stream_numbers);
    value
}

fn encode_incoming_ssn_reset_request_value(
    request_sequence_number: u32,
    stream_numbers: impl IntoIterator<Item = u16>,
) -> Vec<u8> {
    let stream_numbers = stream_numbers.into_iter();
    let (lower, _) = stream_numbers.size_hint();
    let mut value = Vec::with_capacity(
        SCTP_INCOMING_SSN_RESET_REQUEST_FIXED_VALUE_LEN
            + lower * SCTP_RECONFIGURATION_STREAM_NUMBER_LEN,
    );
    value.extend_from_slice(&request_sequence_number.to_be_bytes());
    append_reconfiguration_stream_numbers(&mut value, stream_numbers);
    value
}

fn encode_reconfiguration_response_value(
    response_sequence_number: u32,
    result: impl Into<SctpReconfigurationResult>,
    next_tsns: Option<(u32, u32)>,
) -> Vec<u8> {
    let mut value = Vec::with_capacity(match next_tsns {
        Some(_) => SCTP_RE_CONFIGURATION_RESPONSE_WITH_NEXT_TSNS_VALUE_LEN,
        None => SCTP_RE_CONFIGURATION_RESPONSE_VALUE_LEN,
    });
    value.extend_from_slice(&response_sequence_number.to_be_bytes());
    value.extend_from_slice(&result.into().raw().to_be_bytes());
    if let Some((sender_next_tsn, receiver_next_tsn)) = next_tsns {
        value.extend_from_slice(&sender_next_tsn.to_be_bytes());
        value.extend_from_slice(&receiver_next_tsn.to_be_bytes());
    }
    value
}

fn encode_add_streams_request_value(
    request_sequence_number: u32,
    number_of_new_streams: u16,
    reserved: u16,
) -> Vec<u8> {
    let mut value = Vec::with_capacity(SCTP_ADD_STREAMS_REQUEST_VALUE_LEN);
    value.extend_from_slice(&request_sequence_number.to_be_bytes());
    value.extend_from_slice(&number_of_new_streams.to_be_bytes());
    value.extend_from_slice(&reserved.to_be_bytes());
    value
}

fn append_reconfiguration_stream_numbers(
    value: &mut Vec<u8>,
    stream_numbers: impl IntoIterator<Item = u16>,
) {
    for stream_number in stream_numbers {
        value.extend_from_slice(&stream_number.to_be_bytes());
    }
}

fn parse_reconfiguration_u32_field(
    value: &[u8],
    offset: usize,
    context: &'static str,
) -> Result<u32> {
    let required = offset + SCTP_RECONFIGURATION_SEQUENCE_NUMBER_LEN;
    if value.len() < required {
        return Err(CrafterError::buffer_too_short(
            context,
            required,
            value.len(),
        ));
    }

    Ok(u32::from_be_bytes([
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
    ]))
}

fn parse_reconfiguration_u16_field(
    value: &[u8],
    offset: usize,
    context: &'static str,
) -> Result<u16> {
    let required = offset + SCTP_RECONFIGURATION_STREAM_NUMBER_LEN;
    if value.len() < required {
        return Err(CrafterError::buffer_too_short(
            context,
            required,
            value.len(),
        ));
    }

    Ok(u16::from_be_bytes([value[offset], value[offset + 1]]))
}

fn parse_reconfiguration_stream_numbers(
    value: &[u8],
    fixed_value_len: usize,
    context: &'static str,
    streams_context: &'static str,
) -> Result<Vec<u16>> {
    validate_reconfiguration_stream_list_value(value, fixed_value_len, context, streams_context)?;

    Ok(value[fixed_value_len..]
        .chunks_exact(SCTP_RECONFIGURATION_STREAM_NUMBER_LEN)
        .map(|entry| u16::from_be_bytes([entry[0], entry[1]]))
        .collect())
}

fn validate_reconfiguration_stream_list_value(
    value: &[u8],
    fixed_value_len: usize,
    context: &'static str,
    streams_context: &'static str,
) -> Result<()> {
    if value.len() < fixed_value_len {
        return Err(CrafterError::buffer_too_short(
            context,
            fixed_value_len,
            value.len(),
        ));
    }

    if (value.len() - fixed_value_len) % SCTP_RECONFIGURATION_STREAM_NUMBER_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            streams_context,
            "stream number list must contain complete 16-bit values",
        ));
    }

    Ok(())
}

fn validate_reconfiguration_response_value(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_RE_CONFIGURATION_RESPONSE_VALUE_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_RE_CONFIGURATION_RESPONSE_PARAMETER_CONTEXT,
            SCTP_RE_CONFIGURATION_RESPONSE_VALUE_LEN,
            value.len(),
        ));
    }

    match value.len() {
        SCTP_RE_CONFIGURATION_RESPONSE_VALUE_LEN
        | SCTP_RE_CONFIGURATION_RESPONSE_WITH_NEXT_TSNS_VALUE_LEN => Ok(()),
        _ => Err(CrafterError::invalid_field_value(
            SCTP_RE_CONFIGURATION_RESPONSE_PARAMETER_CONTEXT,
            "value length must be eight or sixteen bytes",
        )),
    }
}

fn sctp_asconf_correlation_id_and_value(
    correlation_id: u32,
    trailing_value: impl Into<Vec<u8>>,
) -> Vec<u8> {
    let trailing_value = trailing_value.into();
    let mut value = Vec::with_capacity(SCTP_ASCONF_CORRELATION_ID_LEN + trailing_value.len());
    value.extend_from_slice(&correlation_id.to_be_bytes());
    value.extend_from_slice(&trailing_value);
    value
}

fn sctp_ipv4_address_parameter_bytes(address: Ipv4Addr) -> Vec<u8> {
    let address = address.octets();
    let mut bytes = Vec::with_capacity(SCTP_PARAMETER_HEADER_LEN + address.len());
    bytes.extend_from_slice(&SCTP_PARAMETER_TYPE_IPV4_ADDRESS.to_be_bytes());
    bytes.extend_from_slice(
        &(SCTP_PARAMETER_HEADER_LEN as u16 + address.len() as u16).to_be_bytes(),
    );
    bytes.extend_from_slice(&address);
    bytes
}

fn sctp_ipv6_address_parameter_bytes(address: Ipv6Addr) -> Vec<u8> {
    let address = address.octets();
    let mut bytes = Vec::with_capacity(SCTP_PARAMETER_HEADER_LEN + address.len());
    bytes.extend_from_slice(&SCTP_PARAMETER_TYPE_IPV6_ADDRESS.to_be_bytes());
    bytes.extend_from_slice(
        &(SCTP_PARAMETER_HEADER_LEN as u16 + address.len() as u16).to_be_bytes(),
    );
    bytes.extend_from_slice(&address);
    bytes
}

fn parse_asconf_correlation_id(value: &[u8], context: &'static str) -> Result<u32> {
    if value.len() < SCTP_ASCONF_CORRELATION_ID_LEN {
        return Err(CrafterError::buffer_too_short(
            context,
            SCTP_ASCONF_CORRELATION_ID_LEN,
            value.len(),
        ));
    }

    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn parse_exact_asconf_correlation_id(value: &[u8], context: &'static str) -> Result<u32> {
    expect_parameter_value_exact_len(
        value,
        context,
        SCTP_ASCONF_CORRELATION_ID_LEN,
        "value length must be four bytes",
    )?;
    parse_asconf_correlation_id(value, context)
}

fn parse_asconf_trailing_value<'a>(value: &'a [u8], context: &'static str) -> Result<&'a [u8]> {
    parse_asconf_correlation_id(value, context)?;
    Ok(&value[SCTP_ASCONF_CORRELATION_ID_LEN..])
}

fn parse_asconf_address_parameter_bytes<'a>(
    value: &'a [u8],
    context: &'static str,
) -> Result<&'a [u8]> {
    if value.len() < SCTP_ASCONF_ADDRESS_PARAMETER_MIN_VALUE_LEN {
        return Err(CrafterError::buffer_too_short(
            context,
            SCTP_ASCONF_ADDRESS_PARAMETER_MIN_VALUE_LEN,
            value.len(),
        ));
    }

    Ok(&value[SCTP_ASCONF_CORRELATION_ID_LEN..])
}

fn parse_nested_parameter(bytes: &[u8]) -> Result<(u16, usize, &[u8], &[u8])> {
    if bytes.len() < SCTP_PARAMETER_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_ASCONF_ADDRESS_PARAMETER_CONTEXT,
            SCTP_PARAMETER_HEADER_LEN,
            bytes.len(),
        ));
    }

    let parameter_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    let declared_length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if declared_length < SCTP_PARAMETER_HEADER_LEN {
        return Err(CrafterError::invalid_field_value(
            SCTP_ASCONF_ADDRESS_PARAMETER_CONTEXT,
            "declared length must be at least 4 bytes",
        ));
    }

    let padded_length = sctp_parameter_padded_len(declared_length);
    if padded_length > bytes.len() {
        return Err(CrafterError::buffer_too_short(
            SCTP_ASCONF_ADDRESS_PARAMETER_CONTEXT,
            padded_length,
            bytes.len(),
        ));
    }

    if padded_length < bytes.len() {
        return Err(CrafterError::invalid_field_value(
            SCTP_ASCONF_ADDRESS_PARAMETER_CONTEXT,
            "address parameter bytes must contain exactly one TLV",
        ));
    }

    Ok((
        parameter_type,
        declared_length,
        &bytes[SCTP_PARAMETER_HEADER_LEN..declared_length],
        &bytes[declared_length..padded_length],
    ))
}

fn validate_asconf_address_parameter(bytes: &[u8]) -> Result<()> {
    let (parameter_type, _, value, _) = parse_nested_parameter(bytes)?;
    match parameter_type {
        SCTP_PARAMETER_TYPE_IPV4_ADDRESS => expect_parameter_value_exact_len(
            value,
            SCTP_ASCONF_ADDRESS_IPV4_CONTEXT,
            SCTP_IPV4_ADDRESS_PARAMETER_VALUE_LEN,
            "IPv4 address parameter value must be four bytes",
        ),
        SCTP_PARAMETER_TYPE_IPV6_ADDRESS => expect_parameter_value_exact_len(
            value,
            SCTP_ASCONF_ADDRESS_IPV6_CONTEXT,
            SCTP_IPV6_ADDRESS_PARAMETER_VALUE_LEN,
            "IPv6 address parameter value must be 16 bytes",
        ),
        _ => Err(CrafterError::invalid_field_value(
            SCTP_ASCONF_ADDRESS_PARAMETER_TYPE_FIELD,
            "address parameter must be IPv4 or IPv6",
        )),
    }
}

fn parse_asconf_ipv4_address(bytes: &[u8]) -> Result<Ipv4Addr> {
    let (parameter_type, _, value, _) = parse_nested_parameter(bytes)?;
    if parameter_type != SCTP_PARAMETER_TYPE_IPV4_ADDRESS {
        return Err(CrafterError::invalid_field_value(
            SCTP_ASCONF_ADDRESS_PARAMETER_TYPE_FIELD,
            "address parameter must be IPv4",
        ));
    }
    expect_parameter_value_exact_len(
        value,
        SCTP_ASCONF_ADDRESS_IPV4_CONTEXT,
        SCTP_IPV4_ADDRESS_PARAMETER_VALUE_LEN,
        "IPv4 address parameter value must be four bytes",
    )?;

    Ok(Ipv4Addr::new(value[0], value[1], value[2], value[3]))
}

fn parse_asconf_ipv6_address(bytes: &[u8]) -> Result<Ipv6Addr> {
    let (parameter_type, _, value, _) = parse_nested_parameter(bytes)?;
    if parameter_type != SCTP_PARAMETER_TYPE_IPV6_ADDRESS {
        return Err(CrafterError::invalid_field_value(
            SCTP_ASCONF_ADDRESS_PARAMETER_TYPE_FIELD,
            "address parameter must be IPv6",
        ));
    }
    expect_parameter_value_exact_len(
        value,
        SCTP_ASCONF_ADDRESS_IPV6_CONTEXT,
        SCTP_IPV6_ADDRESS_PARAMETER_VALUE_LEN,
        "IPv6 address parameter value must be 16 bytes",
    )?;

    let mut octets = [0; SCTP_IPV6_ADDRESS_PARAMETER_VALUE_LEN];
    octets.copy_from_slice(value);
    Ok(Ipv6Addr::from(octets))
}

fn expect_parameter_value_len(value: &[u8], context: &'static str, required: usize) -> Result<()> {
    if value.len() < required {
        return Err(CrafterError::buffer_too_short(
            context,
            required,
            value.len(),
        ));
    }
    if value.len() > required {
        return Err(CrafterError::invalid_field_value(
            context,
            "value length must match the parameter address width",
        ));
    }

    Ok(())
}

fn expect_parameter_value_exact_len(
    value: &[u8],
    context: &'static str,
    required: usize,
    invalid_message: &'static str,
) -> Result<()> {
    if value.len() < required {
        return Err(CrafterError::buffer_too_short(
            context,
            required,
            value.len(),
        ));
    }
    if value.len() > required {
        return Err(CrafterError::invalid_field_value(context, invalid_message));
    }

    Ok(())
}

fn expect_cookie_preservative_value_len(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_COOKIE_PRESERVATIVE_PARAMETER_VALUE_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_COOKIE_PRESERVATIVE_PARAMETER_CONTEXT,
            SCTP_COOKIE_PRESERVATIVE_PARAMETER_VALUE_LEN,
            value.len(),
        ));
    }
    if value.len() > SCTP_COOKIE_PRESERVATIVE_PARAMETER_VALUE_LEN {
        return Err(CrafterError::invalid_field_value(
            SCTP_COOKIE_PRESERVATIVE_PARAMETER_CONTEXT,
            "value length must be four bytes",
        ));
    }

    Ok(())
}

fn host_name_parameter_value(host_name: impl AsRef<str>) -> Vec<u8> {
    let host_name = host_name.as_ref();
    let mut value = Vec::with_capacity(host_name.len() + 1);
    value.extend_from_slice(host_name.as_bytes());
    value.push(0);
    value
}

fn parse_host_name_parameter_value(value: &[u8]) -> Result<&[u8]> {
    let Some(null_index) = value.iter().position(|byte| *byte == 0) else {
        return Err(CrafterError::invalid_field_value(
            SCTP_HOST_NAME_ADDRESS_PARAMETER_FIELD,
            "missing null terminator",
        ));
    };

    if null_index == 0 {
        return Err(CrafterError::invalid_field_value(
            SCTP_HOST_NAME_ADDRESS_PARAMETER_FIELD,
            "host name must not be empty",
        ));
    }

    if value[null_index + 1..].iter().any(|byte| *byte != 0) {
        return Err(CrafterError::invalid_field_value(
            SCTP_HOST_NAME_ADDRESS_PARAMETER_FIELD,
            "non-null bytes after null terminator",
        ));
    }

    let host_name = &value[..null_index];
    if !host_name.is_ascii() {
        return Err(CrafterError::invalid_field_value(
            SCTP_HOST_NAME_ADDRESS_PARAMETER_FIELD,
            "host name must be valid ASCII",
        ));
    }

    Ok(host_name)
}

fn encode_supported_address_types<T>(address_types: impl IntoIterator<Item = T>) -> Vec<u8>
where
    T: Into<SctpAddressType>,
{
    let iter = address_types.into_iter();
    let (lower, _) = iter.size_hint();
    let mut value = Vec::with_capacity(lower * SCTP_SUPPORTED_ADDRESS_TYPE_LEN);
    for address_type in iter {
        value.extend_from_slice(&address_type.into().raw().to_be_bytes());
    }
    value
}

fn parse_supported_address_types(value: &[u8]) -> Result<Vec<SctpAddressType>> {
    if value.len() % SCTP_SUPPORTED_ADDRESS_TYPE_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            SCTP_SUPPORTED_ADDRESS_TYPES_PARAMETER_FIELD,
            "address type list must contain complete 16-bit values",
        ));
    }

    Ok(value
        .chunks_exact(SCTP_SUPPORTED_ADDRESS_TYPE_LEN)
        .map(|entry| SctpAddressType::new(u16::from_be_bytes([entry[0], entry[1]])))
        .collect())
}

fn encode_supported_extension_chunk_types<T>(chunk_types: impl IntoIterator<Item = T>) -> Vec<u8>
where
    T: Into<SctpChunkType>,
{
    let iter = chunk_types.into_iter();
    let (lower, _) = iter.size_hint();
    let mut value = Vec::with_capacity(lower * SCTP_SUPPORTED_EXTENSION_CHUNK_TYPE_LEN);
    for chunk_type in iter {
        value.push(chunk_type.into().raw());
    }
    value
}

fn parse_supported_extension_chunk_types(value: &[u8]) -> Vec<SctpChunkType> {
    value.iter().copied().map(SctpChunkType::new).collect()
}

fn encode_auth_chunk_types<T>(chunk_types: impl IntoIterator<Item = T>) -> Vec<u8>
where
    T: Into<SctpChunkType>,
{
    let iter = chunk_types.into_iter();
    let (lower, _) = iter.size_hint();
    let mut value = Vec::with_capacity(lower);
    for chunk_type in iter {
        value.push(chunk_type.into().raw());
    }
    value
}

fn parse_auth_chunk_types(value: &[u8]) -> Vec<SctpChunkType> {
    value.iter().copied().map(SctpChunkType::new).collect()
}

const fn sctp_auth_chunk_list_ignored_chunk_type(chunk_type: u8) -> bool {
    matches!(
        chunk_type,
        SCTP_CHUNK_TYPE_INIT
            | SCTP_CHUNK_TYPE_INIT_ACK
            | SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE
            | SCTP_CHUNK_TYPE_AUTH
    )
}

fn encode_hmac_identifiers<T>(identifiers: impl IntoIterator<Item = T>) -> Vec<u8>
where
    T: Into<SctpHmacIdentifier>,
{
    let iter = identifiers.into_iter();
    let (lower, _) = iter.size_hint();
    let mut value = Vec::with_capacity(lower * SCTP_AUTH_HMAC_IDENTIFIER_LEN);
    for identifier in iter {
        value.extend_from_slice(&identifier.into().raw().to_be_bytes());
    }
    value
}

fn parse_hmac_identifiers(value: &[u8]) -> Result<Vec<SctpHmacIdentifier>> {
    if value.len() % SCTP_AUTH_HMAC_IDENTIFIER_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            SCTP_REQUESTED_HMAC_ALGORITHM_PARAMETER_CONTEXT,
            "HMAC identifier list must contain complete 16-bit values",
        ));
    }

    Ok(value
        .chunks_exact(SCTP_AUTH_HMAC_IDENTIFIER_LEN)
        .map(|entry| SctpHmacIdentifier::new(u16::from_be_bytes([entry[0], entry[1]])))
        .collect())
}

impl From<SctpUnknownParameter> for SctpParameter {
    fn from(value: SctpUnknownParameter) -> Self {
        Self::Unknown(value)
    }
}

impl From<SctpRawParameter> for SctpParameter {
    fn from(raw: SctpRawParameter) -> Self {
        match raw.parameter_type_value() {
            SCTP_PARAMETER_TYPE_HEARTBEAT_INFO => {
                Self::HeartbeatInfo(SctpHeartbeatInfoParameter { raw })
            }
            SCTP_PARAMETER_TYPE_IPV4_ADDRESS => Self::Ipv4Address(SctpIpv4AddressParameter { raw }),
            SCTP_PARAMETER_TYPE_IPV6_ADDRESS => Self::Ipv6Address(SctpIpv6AddressParameter { raw }),
            SCTP_PARAMETER_TYPE_STATE_COOKIE => Self::StateCookie(SctpStateCookieParameter { raw }),
            SCTP_PARAMETER_TYPE_UNRECOGNIZED_PARAMETER => {
                Self::UnrecognizedParameter(SctpUnrecognizedParameter { raw })
            }
            SCTP_PARAMETER_TYPE_COOKIE_PRESERVATIVE => {
                Self::CookiePreservative(SctpCookiePreservativeParameter { raw })
            }
            SCTP_PARAMETER_TYPE_HOST_NAME_ADDRESS => {
                Self::HostNameAddress(SctpHostNameAddressParameter { raw })
            }
            SCTP_PARAMETER_TYPE_SUPPORTED_ADDRESS_TYPES => {
                Self::SupportedAddressTypes(SctpSupportedAddressTypesParameter { raw })
            }
            SCTP_PARAMETER_TYPE_OUTGOING_SSN_RESET_REQUEST => {
                Self::OutgoingSsnResetRequest(SctpOutgoingSsnResetRequestParameter { raw })
            }
            SCTP_PARAMETER_TYPE_INCOMING_SSN_RESET_REQUEST => {
                Self::IncomingSsnResetRequest(SctpIncomingSsnResetRequestParameter { raw })
            }
            SCTP_PARAMETER_TYPE_SSN_TSN_RESET_REQUEST => {
                Self::SsnTsnResetRequest(SctpSsnTsnResetRequestParameter { raw })
            }
            SCTP_PARAMETER_TYPE_RE_CONFIGURATION_RESPONSE => {
                Self::ReConfigurationResponse(SctpReConfigurationResponseParameter { raw })
            }
            SCTP_PARAMETER_TYPE_ADD_OUTGOING_STREAMS_REQUEST => {
                Self::AddOutgoingStreamsRequest(SctpAddOutgoingStreamsRequestParameter { raw })
            }
            SCTP_PARAMETER_TYPE_ADD_INCOMING_STREAMS_REQUEST => {
                Self::AddIncomingStreamsRequest(SctpAddIncomingStreamsRequestParameter { raw })
            }
            SCTP_PARAMETER_TYPE_ZERO_CHECKSUM_ACCEPTABLE => {
                Self::ZeroChecksumAcceptable(SctpZeroChecksumAcceptableParameter { raw })
            }
            SCTP_PARAMETER_TYPE_RANDOM => Self::Random(SctpRandomParameter { raw }),
            SCTP_PARAMETER_TYPE_CHUNK_LIST => Self::ChunkList(SctpChunkListParameter { raw }),
            SCTP_PARAMETER_TYPE_REQUESTED_HMAC_ALGORITHM => {
                Self::RequestedHmacAlgorithm(SctpRequestedHmacAlgorithmParameter { raw })
            }
            SCTP_PARAMETER_TYPE_PADDING => Self::Padding(SctpPaddingParameter { raw }),
            SCTP_PARAMETER_TYPE_SUPPORTED_EXTENSIONS => {
                Self::SupportedExtensions(SctpSupportedExtensionsParameter { raw })
            }
            SCTP_PARAMETER_TYPE_FORWARD_TSN_SUPPORTED => {
                Self::ForwardTsnSupported(SctpForwardTsnSupportedParameter { raw })
            }
            SCTP_PARAMETER_TYPE_ADD_IP_ADDRESS => {
                Self::AddIpAddress(SctpAddIpAddressParameter { raw })
            }
            SCTP_PARAMETER_TYPE_DELETE_IP_ADDRESS => {
                Self::DeleteIpAddress(SctpDeleteIpAddressParameter { raw })
            }
            SCTP_PARAMETER_TYPE_ERROR_CAUSE_INDICATION => {
                Self::ErrorCauseIndication(SctpErrorCauseIndicationParameter { raw })
            }
            SCTP_PARAMETER_TYPE_SET_PRIMARY_ADDRESS => {
                Self::SetPrimaryAddress(SctpSetPrimaryAddressParameter { raw })
            }
            SCTP_PARAMETER_TYPE_SUCCESS_INDICATION => {
                Self::SuccessIndication(SctpSuccessIndicationParameter { raw })
            }
            SCTP_PARAMETER_TYPE_ADAPTATION_LAYER_INDICATION => {
                Self::AdaptationLayerIndication(SctpAdaptationLayerIndicationParameter { raw })
            }
            _ => Self::Unknown(SctpUnknownParameter { raw }),
        }
    }
}

impl SctpParameter {
    /// Construct a parameter from raw wire parts, dispatching known codepoints.
    pub fn from_raw_parts(
        parameter_type: u16,
        value: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        SctpRawParameter::from_raw_parts(parameter_type, value, padding).into()
    }

    /// Construct a parameter with an explicit declared length, dispatching known codepoints.
    pub fn from_preserved_parts(
        parameter_type: u16,
        declared_length: u16,
        value: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        SctpRawParameter::from_preserved_parts(parameter_type, declared_length, value, padding)
            .into()
    }

    /// Construct an unknown parameter with an auto-derived declared length.
    pub fn unknown(parameter_type: u16, value: impl Into<Vec<u8>>) -> Self {
        SctpUnknownParameter::new(parameter_type, value).into()
    }

    /// Borrow the preserved raw parameter envelope.
    pub fn raw_parameter(&self) -> &SctpRawParameter {
        match self {
            Self::HeartbeatInfo(value) => value.raw_parameter(),
            Self::Ipv4Address(value) => value.raw_parameter(),
            Self::Ipv6Address(value) => value.raw_parameter(),
            Self::StateCookie(value) => value.raw_parameter(),
            Self::UnrecognizedParameter(value) => value.raw_parameter(),
            Self::CookiePreservative(value) => value.raw_parameter(),
            Self::HostNameAddress(value) => value.raw_parameter(),
            Self::SupportedAddressTypes(value) => value.raw_parameter(),
            Self::OutgoingSsnResetRequest(value) => value.raw_parameter(),
            Self::IncomingSsnResetRequest(value) => value.raw_parameter(),
            Self::SsnTsnResetRequest(value) => value.raw_parameter(),
            Self::ReConfigurationResponse(value) => value.raw_parameter(),
            Self::AddOutgoingStreamsRequest(value) => value.raw_parameter(),
            Self::AddIncomingStreamsRequest(value) => value.raw_parameter(),
            Self::ZeroChecksumAcceptable(value) => value.raw_parameter(),
            Self::Random(value) => value.raw_parameter(),
            Self::ChunkList(value) => value.raw_parameter(),
            Self::RequestedHmacAlgorithm(value) => value.raw_parameter(),
            Self::Padding(value) => value.raw_parameter(),
            Self::SupportedExtensions(value) => value.raw_parameter(),
            Self::ForwardTsnSupported(value) => value.raw_parameter(),
            Self::AddIpAddress(value) => value.raw_parameter(),
            Self::DeleteIpAddress(value) => value.raw_parameter(),
            Self::ErrorCauseIndication(value) => value.raw_parameter(),
            Self::SetPrimaryAddress(value) => value.raw_parameter(),
            Self::SuccessIndication(value) => value.raw_parameter(),
            Self::AdaptationLayerIndication(value) => value.raw_parameter(),
            Self::Unknown(value) => value.raw_parameter(),
        }
    }

    /// SCTP parameter type codepoint.
    pub fn parameter_type(&self) -> SctpParameterType {
        self.raw_parameter().parameter_type()
    }

    /// Raw SCTP parameter type codepoint.
    pub fn parameter_type_value(&self) -> u16 {
        self.raw_parameter().parameter_type_value()
    }

    /// RFC 9260 unknown-parameter action bits from the parameter type.
    pub fn unknown_action_bits(&self) -> u8 {
        self.raw_parameter().unknown_action_bits()
    }

    /// RFC 9260 unknown-parameter action label from the parameter type.
    pub fn unknown_action(&self) -> SctpUnknownParameterAction {
        self.raw_parameter().unknown_action()
    }

    /// Lower 14 type bits without the unknown-parameter action class.
    pub fn type_value_bits_without_unknown_action(&self) -> u16 {
        self.raw_parameter()
            .type_value_bits_without_unknown_action()
    }

    /// Source-backed registry status for this parameter type.
    pub fn parameter_type_status(&self) -> SctpParameterTypeStatus {
        self.raw_parameter().parameter_type_status()
    }

    /// Source-backed registry label for this parameter type, when known.
    pub fn parameter_type_name(&self) -> Option<&'static str> {
        self.raw_parameter().parameter_type_name()
    }

    /// Declared parameter length value, using the explicit value when present.
    pub fn declared_length(&self) -> usize {
        self.raw_parameter().declared_length()
    }

    /// Compatibility alias for the declared parameter length value.
    pub fn length(&self) -> usize {
        self.declared_length()
    }

    /// Explicit declared parameter length override, if one is preserved.
    pub fn explicit_declared_length(&self) -> Option<u16> {
        self.raw_parameter().explicit_declared_length()
    }

    /// Compatibility alias for the explicit declared parameter length override.
    pub fn explicit_length(&self) -> Option<u16> {
        self.explicit_declared_length()
    }

    /// Declared parameter value bytes, excluding padding.
    pub fn value(&self) -> &[u8] {
        self.raw_parameter().value()
    }

    /// Transmitted parameter padding bytes, excluded from semantic value bytes.
    pub fn padding(&self) -> &[u8] {
        self.raw_parameter().padding()
    }

    /// Declared parameter value length, excluding padding.
    pub fn value_len(&self) -> usize {
        self.raw_parameter().value_len()
    }

    /// Transmitted parameter padding length.
    pub fn padding_len(&self) -> usize {
        self.raw_parameter().padding_len()
    }

    /// Protocol padding length implied by the declared parameter length.
    pub fn required_padding_len(&self) -> usize {
        self.raw_parameter().required_padding_len()
    }

    /// Padding length an encoder would emit: preserved bytes, or auto zero padding.
    pub fn encoded_padding_len(&self) -> usize {
        self.raw_parameter().encoded_padding_len()
    }

    /// Declared parameter length rounded up to the next four-octet boundary.
    pub fn padded_declared_len(&self) -> usize {
        self.raw_parameter().padded_declared_len()
    }

    /// Number of bytes encoded for this envelope, including padding.
    pub fn encoded_len(&self) -> usize {
        self.raw_parameter().encoded_len()
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::super::constants::{
        SCTP_PARAMETER_TYPE_DTLS_KEY_MANAGEMENT, SCTP_PARAMETER_TYPE_ECN_CAPABLE,
        SCTP_PARAMETER_TYPE_IETF_DEFINED_EXTENSION,
    };
    use super::*;

    #[test]
    fn sctp_parameter_model_typed_variants_keep_common_wire_fields() {
        let parameter =
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_HEARTBEAT_INFO, [1, 2, 3], [0xaa]);

        assert!(matches!(parameter, SctpParameter::HeartbeatInfo(_)));
        assert_eq!(
            parameter.parameter_type(),
            SctpParameterType::new(SCTP_PARAMETER_TYPE_HEARTBEAT_INFO)
        );
        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_HEARTBEAT_INFO
        );
        assert_eq!(parameter.length(), SCTP_PARAMETER_HEADER_LEN + 3);
        assert_eq!(parameter.explicit_length(), None);
        assert_eq!(parameter.value(), &[1, 2, 3]);
        assert_eq!(parameter.padding(), &[0xaa]);
        assert_eq!(parameter.encoded_len(), SCTP_PARAMETER_HEADER_LEN + 4);
    }

    #[test]
    fn sctp_parameter_model_preserves_explicit_length_without_normalizing_storage() {
        let parameter = SctpParameter::from_preserved_parts(
            SCTP_PARAMETER_TYPE_STATE_COOKIE,
            4,
            [1, 2, 3],
            [0xbb, 0xcc],
        );

        assert!(matches!(parameter, SctpParameter::StateCookie(_)));
        assert_eq!(parameter.length(), 4);
        assert_eq!(parameter.explicit_declared_length(), Some(4));
        assert_eq!(parameter.value(), &[1, 2, 3]);
        assert_eq!(parameter.padding(), &[0xbb, 0xcc]);
        assert_eq!(parameter.encoded_len(), SCTP_PARAMETER_HEADER_LEN + 5);
    }

    #[test]
    fn sctp_parameter_model_unknown_preserves_type_declared_length_value_and_padding() {
        let parameter = SctpParameter::from_preserved_parts(
            SCTP_PARAMETER_TYPE_IETF_DEFINED_EXTENSION,
            9,
            [0xde, 0xad, 0xbe],
            [0xef],
        );

        let SctpParameter::Unknown(unknown) = parameter else {
            panic!("reserved extension codepoint must remain an unknown parameter");
        };
        assert_eq!(
            unknown.parameter_type_value(),
            SCTP_PARAMETER_TYPE_IETF_DEFINED_EXTENSION
        );
        assert_eq!(
            unknown.parameter_type(),
            SctpParameterType::new(SCTP_PARAMETER_TYPE_IETF_DEFINED_EXTENSION)
        );
        assert_eq!(unknown.length(), 9);
        assert_eq!(unknown.explicit_length(), Some(9));
        assert_eq!(unknown.value(), &[0xde, 0xad, 0xbe]);
        assert_eq!(unknown.value_len(), 3);
        assert_eq!(unknown.padding(), &[0xef]);
        assert_eq!(unknown.padding_len(), 1);
        assert_eq!(unknown.encoded_len(), SCTP_PARAMETER_HEADER_LEN + 4);
    }

    #[test]
    fn sctp_parameter_model_typed_wrappers_share_raw_envelope_accessors() {
        let parameter = SctpSupportedExtensionsParameter::new([0x01, 0x02, 0x03])
            .with_declared_length(1)
            .with_padding([0x00, 0x01]);

        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_SUPPORTED_EXTENSIONS
        );
        assert_eq!(parameter.length(), 1);
        assert_eq!(parameter.explicit_length(), Some(1));
        assert_eq!(parameter.value(), &[0x01, 0x02, 0x03]);
        assert_eq!(parameter.padding(), &[0x00, 0x01]);

        let enum_parameter = SctpParameter::from(parameter);
        assert!(matches!(
            enum_parameter,
            SctpParameter::SupportedExtensions(_)
        ));
        assert_eq!(enum_parameter.length(), 1);
    }

    #[test]
    fn sctp_parameter_model_padding_helpers_round_declared_lengths_to_four_octets() {
        assert_eq!(sctp_parameter_padding_len(SCTP_PARAMETER_HEADER_LEN), 0);
        assert_eq!(sctp_parameter_padding_len(SCTP_PARAMETER_HEADER_LEN + 1), 3);
        assert_eq!(sctp_parameter_padding_len(SCTP_PARAMETER_HEADER_LEN + 2), 2);
        assert_eq!(sctp_parameter_padding_len(SCTP_PARAMETER_HEADER_LEN + 3), 1);
        assert_eq!(sctp_parameter_padding_len(SCTP_PARAMETER_HEADER_LEN + 4), 0);
        assert_eq!(sctp_parameter_padded_len(SCTP_PARAMETER_HEADER_LEN + 1), 8);
    }

    #[test]
    fn sctp_parameter_model_auto_padding_keeps_padding_out_of_value_bytes() {
        let parameter = SctpPaddingParameter::new([0xaa]);

        assert_eq!(parameter.length(), SCTP_PARAMETER_HEADER_LEN + 1);
        assert_eq!(parameter.value(), &[0xaa]);
        assert_eq!(parameter.value_len(), 1);
        assert_eq!(parameter.padding(), &[]);
        assert_eq!(parameter.padding_len(), 0);
        assert_eq!(parameter.required_padding_len(), 3);
        assert_eq!(parameter.encoded_padding_len(), 3);
        assert_eq!(
            parameter.padded_declared_len(),
            SCTP_PARAMETER_HEADER_LEN + 4
        );
        assert_eq!(parameter.encoded_len(), SCTP_PARAMETER_HEADER_LEN + 4);

        let enum_parameter = SctpParameter::from(parameter);
        assert_eq!(enum_parameter.value(), &[0xaa]);
        assert_eq!(enum_parameter.padding(), &[]);
        assert_eq!(enum_parameter.encoded_padding_len(), 3);
    }

    #[test]
    fn sctp_pad_chunk_parameter_preserves_padding_data_and_alignment_padding() {
        let parameter =
            SctpPaddingParameter::from_padding_data([0xaa, 0xbb, 0xcc]).with_padding([0xdd]);

        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_PADDING
        );
        assert_eq!(parameter.length(), SCTP_PARAMETER_HEADER_LEN + 3);
        assert_eq!(parameter.padding_data(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(parameter.padding_data_bytes(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(parameter.padding(), &[0xdd]);
        assert_eq!(parameter.encoded_padding_len(), 1);

        let replaced = parameter.with_padding_data([0x11, 0x22, 0x33, 0x44]);
        assert_eq!(replaced.padding_data(), &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(replaced.length(), SCTP_PARAMETER_HEADER_LEN + 4);

        let enum_parameter = SctpParameter::from(replaced);
        assert!(matches!(enum_parameter, SctpParameter::Padding(_)));
    }

    #[test]
    fn sctp_parameter_model_reserved_temporary_and_unassigned_codepoints_remain_unknown() {
        for parameter_type in [
            SCTP_PARAMETER_TYPE_ECN_CAPABLE,
            SCTP_PARAMETER_TYPE_DTLS_KEY_MANAGEMENT,
            SCTP_PARAMETER_TYPE_IETF_DEFINED_EXTENSION,
            0x0002,
        ] {
            let parameter = SctpParameter::from_raw_parts(parameter_type, [], []);

            assert!(
                matches!(parameter, SctpParameter::Unknown(_)),
                "{parameter_type}"
            );
            assert_eq!(parameter.parameter_type_value(), parameter_type);
            assert_eq!(parameter.length(), SCTP_PARAMETER_HEADER_LEN);
        }
    }

    #[test]
    fn sctp_parameter_classification_status_names_and_predicates_are_source_backed() {
        let heartbeat = SctpParameterType::new(SCTP_PARAMETER_TYPE_HEARTBEAT_INFO);
        assert_eq!(heartbeat.status(), SctpParameterTypeStatus::Assigned);
        assert!(heartbeat.is_assigned());
        assert_eq!(heartbeat.name(), Some("Heartbeat Info"));

        let ecn = SctpParameterType::new(SCTP_PARAMETER_TYPE_ECN_CAPABLE);
        assert_eq!(ecn.status(), SctpParameterTypeStatus::Reserved);
        assert!(ecn.is_reserved());
        assert_eq!(ecn.name(), Some("Reserved for ECN Capable"));

        let dtls = SctpParameterType::new(SCTP_PARAMETER_TYPE_DTLS_KEY_MANAGEMENT);
        assert_eq!(dtls.status(), SctpParameterTypeStatus::Temporary);
        assert!(dtls.is_temporary());
        assert_eq!(dtls.name(), Some("DTLS Key Management"));

        let extension_slot = SctpParameterType::new(SCTP_PARAMETER_TYPE_IETF_DEFINED_EXTENSION);
        assert_eq!(extension_slot.status(), SctpParameterTypeStatus::Reserved);
        assert_eq!(
            extension_slot.name(),
            Some("Reserved for IETF-defined Chunk Extensions")
        );

        let unassigned = SctpParameterType::new(0x8007);
        assert_eq!(unassigned.status(), SctpParameterTypeStatus::Unassigned);
        assert!(unassigned.is_unassigned());
        assert_eq!(unassigned.name(), None);

        assert!(sctp_parameter_type_is_assigned(SCTP_PARAMETER_TYPE_RANDOM));
        assert!(sctp_parameter_type_is_reserved(
            SCTP_PARAMETER_TYPE_IETF_DEFINED_EXTENSION
        ));
        assert!(sctp_parameter_type_is_temporary(
            SCTP_PARAMETER_TYPE_DTLS_KEY_MANAGEMENT
        ));
        assert!(sctp_parameter_type_is_unassigned(0x0002));
        assert_eq!(SctpParameterTypeStatus::Temporary.to_string(), "temporary");
    }

    #[test]
    fn sctp_parameter_classification_action_bit_helpers_expose_raw_type_parts() {
        let parameter_type = 0xd234;

        assert_eq!(
            sctp_parameter_type_unknown_action_bits(parameter_type),
            SCTP_PARAMETER_UNKNOWN_ACTION_SKIP_AND_REPORT
        );
        assert_eq!(
            sctp_parameter_type_unknown_action(parameter_type),
            SctpUnknownParameterAction::SkipAndReport
        );
        assert_eq!(
            sctp_parameter_type_value_bits_without_unknown_action(parameter_type),
            0x1234
        );
        assert_eq!(
            sctp_parameter_type_from_unknown_action_and_value_bits(
                SctpUnknownParameterAction::SkipAndReport,
                0x9234
            ),
            parameter_type
        );
        assert_eq!(SctpUnknownParameterAction::Skip.as_str(), "skip");
        assert_eq!(
            SctpUnknownParameterAction::StopAndReport.to_string(),
            "stop-and-report"
        );
    }

    #[test]
    fn sctp_parameter_classification_metadata_is_available_on_parameter_values() {
        let padding = SctpPaddingParameter::new([0xaa]);
        assert_eq!(
            padding.parameter_type_status(),
            SctpParameterTypeStatus::Assigned
        );
        assert_eq!(padding.parameter_type_name(), Some("Padding"));
        assert_eq!(padding.unknown_action(), SctpUnknownParameterAction::Skip);
        assert_eq!(padding.type_value_bits_without_unknown_action(), 5);

        let ecn = SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_ECN_CAPABLE, [], []);
        assert!(matches!(ecn, SctpParameter::Unknown(_)));
        assert_eq!(
            ecn.parameter_type_status(),
            SctpParameterTypeStatus::Reserved
        );
        assert_eq!(ecn.parameter_type_name(), Some("Reserved for ECN Capable"));
        assert_eq!(ecn.unknown_action(), SctpUnknownParameterAction::Skip);
        assert_eq!(ecn.type_value_bits_without_unknown_action(), 0);

        let unknown = SctpUnknownParameter::new(0x0002, []);
        assert_eq!(
            unknown.parameter_type_status(),
            SctpParameterTypeStatus::Unassigned
        );
        assert_eq!(unknown.parameter_type_name(), None);
        assert_eq!(unknown.unknown_action(), SctpUnknownParameterAction::Stop);

        let raw = SctpRawParameter::new(SCTP_PARAMETER_TYPE_SUPPORTED_EXTENSIONS, []);
        assert_eq!(
            raw.parameter_type_status(),
            SctpParameterTypeStatus::Assigned
        );
        assert_eq!(raw.parameter_type_name(), Some("Supported Extensions"));
    }

    #[test]
    fn sctp_unknown_parameters_expose_all_unknown_action_classes() {
        let cases = [
            (0x1234, SctpUnknownParameterAction::Stop),
            (0x5234, SctpUnknownParameterAction::StopAndReport),
            (0x9234, SctpUnknownParameterAction::Skip),
            (0xd234, SctpUnknownParameterAction::SkipAndReport),
        ];

        for (parameter_type, action) in cases {
            let parameter = SctpUnknownParameter::new(parameter_type, [action.raw_bits(), 0xee])
                .with_padding([0xaa, 0xbb]);

            assert_eq!(parameter.parameter_type_value(), parameter_type);
            assert_eq!(parameter.unknown_action_bits(), action.raw_bits());
            assert_eq!(parameter.unknown_action(), action);
            assert_eq!(parameter.type_value_bits_without_unknown_action(), 0x1234);
            assert_eq!(
                parameter.stops_parameter_processing(),
                action.stops_parameter_processing()
            );
            assert_eq!(parameter.skips_parameter(), action.skips_parameter());
            assert_eq!(
                parameter.reports_unrecognized_parameter(),
                action.reports_unrecognized_parameter()
            );
            assert_eq!(parameter.value(), &[action.raw_bits(), 0xee]);
            assert_eq!(parameter.padding(), &[0xaa, 0xbb]);
            assert_eq!(parameter.length(), SCTP_PARAMETER_HEADER_LEN + 2);

            let parameter_type = SctpParameterType::new(parameter_type);
            assert_eq!(parameter_type.unknown_action(), action);
            assert_eq!(parameter_type.unknown_action_bits(), action.raw_bits());
            assert_eq!(parameter_type.value_bits_without_unknown_action(), 0x1234);
            assert_eq!(
                SctpParameterType::from_unknown_action_and_value_bits(action, 0x9234),
                SctpParameterType::new(((action.raw_bits() as u16) << 14) | 0x1234)
            );
            assert_eq!(
                SctpUnknownParameterAction::from_bits(action.raw_bits()),
                action
            );
            assert_eq!(u8::from(action), action.raw_bits());
        }
    }

    #[test]
    fn sctp_unknown_parameters_preserve_reserved_temporary_and_padding_bits() {
        let ecn = SctpParameter::from_preserved_parts(
            SCTP_PARAMETER_TYPE_ECN_CAPABLE,
            7,
            [0xde, 0xad, 0xbe],
            [0xcc],
        );
        let SctpParameter::Unknown(ecn) = ecn else {
            panic!("reserved ECN Capable value must stay unknown");
        };
        assert_eq!(ecn.parameter_type_value(), SCTP_PARAMETER_TYPE_ECN_CAPABLE);
        assert_eq!(ecn.unknown_action(), SctpUnknownParameterAction::Skip);
        assert_eq!(ecn.type_value_bits_without_unknown_action(), 0);
        assert_eq!(ecn.length(), 7);
        assert_eq!(ecn.explicit_length(), Some(7));
        assert_eq!(ecn.value(), &[0xde, 0xad, 0xbe]);
        assert_eq!(ecn.padding(), &[0xcc]);
        assert_eq!(ecn.required_padding_len(), 1);
        assert_eq!(ecn.encoded_len(), SCTP_PARAMETER_HEADER_LEN + 4);

        let dtls = SctpParameter::from_raw_parts(
            SCTP_PARAMETER_TYPE_DTLS_KEY_MANAGEMENT,
            [0x01, 0x02, 0x03, 0x04, 0x05],
            [0x00, 0x00, 0x00],
        );
        let SctpParameter::Unknown(dtls) = dtls else {
            panic!("temporary DTLS Key Management value must stay unknown");
        };
        assert_eq!(
            dtls.parameter_type_value(),
            SCTP_PARAMETER_TYPE_DTLS_KEY_MANAGEMENT
        );
        assert_eq!(dtls.unknown_action(), SctpUnknownParameterAction::Skip);
        assert_eq!(dtls.type_value_bits_without_unknown_action(), 0x0006);
        assert_eq!(dtls.value(), &[0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(dtls.padding(), &[0x00, 0x00, 0x00]);
        assert_eq!(dtls.encoded_padding_len(), 3);

        let ietf = SctpUnknownParameter::from_raw_parts(
            SCTP_PARAMETER_TYPE_IETF_DEFINED_EXTENSION,
            [],
            [0xaa, 0xbb],
        );
        assert_eq!(
            ietf.unknown_action(),
            SctpUnknownParameterAction::SkipAndReport
        );
        assert_eq!(ietf.type_value_bits_without_unknown_action(), 0x3fff);
        assert!(ietf.skips_parameter());
        assert!(ietf.reports_unrecognized_parameter());
        assert_eq!(ietf.value(), &[]);
        assert_eq!(ietf.padding(), &[0xaa, 0xbb]);
    }

    #[test]
    fn sctp_decode_parameters_walks_declared_lengths_and_preserves_padding() -> Result<()> {
        let bytes = [
            0x00, 0x01, 0x00, 0x05, 0xaa, 0x00, 0xbb, 0xcc, 0x92, 0x34, 0x00, 0x04, 0x00, 0x05,
            0x00, 0x08, 192, 0, 2, 1,
        ];

        let parameters = decode_parameters(bytes)?;
        assert_eq!(parameters.len(), 3);

        let SctpParameter::HeartbeatInfo(heartbeat) = &parameters[0] else {
            panic!("expected Heartbeat Info parameter");
        };
        assert_eq!(
            heartbeat.parameter_type_value(),
            SCTP_PARAMETER_TYPE_HEARTBEAT_INFO
        );
        assert_eq!(heartbeat.length(), 5);
        assert_eq!(heartbeat.explicit_length(), Some(5));
        assert_eq!(heartbeat.value(), &[0xaa]);
        assert_eq!(heartbeat.padding(), &[0x00, 0xbb, 0xcc]);
        assert_eq!(heartbeat.encoded_len(), 8);

        let SctpParameter::Unknown(unknown) = &parameters[1] else {
            panic!("expected unknown parameter");
        };
        assert_eq!(unknown.parameter_type_value(), 0x9234);
        assert_eq!(unknown.unknown_action(), SctpUnknownParameterAction::Skip);
        assert_eq!(unknown.length(), 4);
        assert_eq!(unknown.value(), &[]);
        assert_eq!(unknown.padding(), &[]);

        let SctpParameter::Ipv4Address(ipv4) = &parameters[2] else {
            panic!("expected IPv4 Address parameter");
        };
        assert_eq!(ipv4.address()?, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(ipv4.length(), 8);
        assert_eq!(ipv4.padding(), &[]);

        Ok(())
    }

    #[test]
    fn sctp_decode_parameters_dispatches_known_types_without_semantic_validation() -> Result<()> {
        let bytes = [
            0x00, 0x05, 0x00, 0x07, 192, 0, 2, 0xee, 0x80, 0x00, 0x00, 0x04,
        ];

        let parameters = decode_parameters(bytes)?;
        assert_eq!(parameters.len(), 2);

        let SctpParameter::Ipv4Address(ipv4) = &parameters[0] else {
            panic!("expected malformed IPv4 Address parameter to keep its typed envelope");
        };
        assert_eq!(ipv4.length(), 7);
        assert_eq!(ipv4.value(), &[192, 0, 2]);
        assert_eq!(ipv4.padding(), &[0xee]);
        assert_eq!(
            ipv4.address().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_IPV4_ADDRESS_PARAMETER_CONTEXT,
                SCTP_IPV4_ADDRESS_PARAMETER_VALUE_LEN,
                3,
            )
        );

        let SctpParameter::Unknown(ecn) = &parameters[1] else {
            panic!("reserved ECN Capable parameter must remain unknown");
        };
        assert_eq!(ecn.parameter_type_value(), SCTP_PARAMETER_TYPE_ECN_CAPABLE);
        assert_eq!(ecn.unknown_action(), SctpUnknownParameterAction::Skip);
        assert_eq!(ecn.value(), &[]);
        assert_eq!(ecn.padding(), &[]);

        Ok(())
    }

    #[test]
    fn sctp_malformed_parameters_reject_short_header_and_invalid_length() {
        assert_eq!(
            decode_parameters([0x00, 0x01, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("sctp.parameter.header", SCTP_PARAMETER_HEADER_LEN, 3)
        );

        assert_eq!(
            decode_parameters([0x00, 0x01, 0x00, 0x03]).unwrap_err(),
            CrafterError::invalid_field_value(
                "sctp.parameter.length",
                "declared length must be at least 4 bytes",
            )
        );
    }

    #[test]
    fn sctp_malformed_parameters_reject_declared_length_or_padding_overrun() {
        assert_eq!(
            decode_parameters([0x00, 0x01, 0x00, 0x05, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("sctp.parameter", 8, 5)
        );

        assert_eq!(
            decode_parameters([0x00, 0x01, 0x00, 0x04, 0xff]).unwrap_err(),
            CrafterError::buffer_too_short("sctp.parameter.header", SCTP_PARAMETER_HEADER_LEN, 1)
        );
    }

    #[test]
    fn sctp_encode_parameters_writes_envelopes_and_auto_zero_padding() -> Result<()> {
        let parameters = vec![
            SctpParameter::from(SctpHeartbeatInfoParameter::new([0xaa])),
            SctpParameter::from(SctpIpv4AddressParameter::from_address(Ipv4Addr::new(
                192, 0, 2, 1,
            ))),
            SctpParameter::from(SctpUnknownParameter::new(0x9234, [])),
        ];
        let mut bytes = Vec::new();

        encode_parameters(&parameters, &mut bytes)?;

        assert_eq!(
            bytes,
            [
                0x00, 0x01, 0x00, 0x05, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x08, 192, 0, 2,
                1, 0x92, 0x34, 0x00, 0x04,
            ]
        );

        let decoded = decode_parameters(&bytes)?;
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].padding(), &[0x00, 0x00, 0x00]);
        assert_eq!(decoded[1].padding(), &[]);
        assert_eq!(decoded[2].padding(), &[]);

        Ok(())
    }

    #[test]
    fn sctp_encode_parameters_preserves_explicit_malformed_length_and_padding() -> Result<()> {
        let parameter = SctpParameter::from(SctpUnknownParameter::from_preserved_parts(
            0x9234,
            4,
            [0xde, 0xad, 0xbe],
            [0xef],
        ));
        let mut bytes = Vec::new();

        encode_parameter(&parameter, &mut bytes)?;

        assert_eq!(bytes, [0x92, 0x34, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]);

        Ok(())
    }

    #[test]
    fn sctp_encode_parameters_rejects_auto_declared_length_overflow() {
        let oversized_value = vec![0; usize::from(u16::MAX) - SCTP_PARAMETER_HEADER_LEN + 1];
        let parameter = SctpParameter::from(SctpUnknownParameter::new(0x9234, oversized_value));
        let mut bytes = Vec::new();

        assert_eq!(
            encode_parameter(&parameter, &mut bytes).unwrap_err(),
            CrafterError::invalid_field_value(
                "sctp.parameter.length",
                "length must fit in two bytes",
            )
        );
        assert!(bytes.is_empty());
    }

    #[test]
    fn sctp_parameter_model_dispatches_source_backed_known_codepoints() {
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_IPV4_ADDRESS, [], []),
            SctpParameter::Ipv4Address(_)
        ));
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_IPV6_ADDRESS, [], []),
            SctpParameter::Ipv6Address(_)
        ));
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_UNRECOGNIZED_PARAMETER, [], []),
            SctpParameter::UnrecognizedParameter(_)
        ));
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_COOKIE_PRESERVATIVE, [], []),
            SctpParameter::CookiePreservative(_)
        ));
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_SUPPORTED_ADDRESS_TYPES, [], []),
            SctpParameter::SupportedAddressTypes(_)
        ));
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_OUTGOING_SSN_RESET_REQUEST, [], []),
            SctpParameter::OutgoingSsnResetRequest(_)
        ));
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_ADD_INCOMING_STREAMS_REQUEST, [], []),
            SctpParameter::AddIncomingStreamsRequest(_)
        ));
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_ZERO_CHECKSUM_ACCEPTABLE, [], []),
            SctpParameter::ZeroChecksumAcceptable(_)
        ));
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_RANDOM, [], []),
            SctpParameter::Random(_)
        ));
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_REQUESTED_HMAC_ALGORITHM, [], []),
            SctpParameter::RequestedHmacAlgorithm(_)
        ));
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_FORWARD_TSN_SUPPORTED, [], []),
            SctpParameter::ForwardTsnSupported(_)
        ));
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_ADD_IP_ADDRESS, [], []),
            SctpParameter::AddIpAddress(_)
        ));
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_ERROR_CAUSE_INDICATION, [], []),
            SctpParameter::ErrorCauseIndication(_)
        ));
        assert!(matches!(
            SctpParameter::from_raw_parts(SCTP_PARAMETER_TYPE_ADAPTATION_LAYER_INDICATION, [], []),
            SctpParameter::AdaptationLayerIndication(_)
        ));
    }

    #[test]
    fn sctp_parameter_model_value_bytes_roundtrip_without_padding_bytes() {
        let parameter = SctpParameter::from_preserved_parts(
            SCTP_PARAMETER_TYPE_HOST_NAME_ADDRESS,
            7,
            b"abc",
            [0x00],
        );

        assert!(matches!(parameter, SctpParameter::HostNameAddress(_)));
        assert_eq!(parameter.value(), b"abc");
        assert_eq!(parameter.padding(), &[0x00]);
        assert_eq!(parameter.required_padding_len(), 1);
        assert_eq!(parameter.encoded_padding_len(), 1);

        let replaced = SctpRawParameter::new(SCTP_PARAMETER_TYPE_CHUNK_LIST, [0x01])
            .with_value([0x02, 0x03])
            .with_padding([0xfe, 0xff]);
        let parameter = SctpParameter::from(replaced);
        assert!(matches!(parameter, SctpParameter::ChunkList(_)));
        assert_eq!(parameter.value(), &[0x02, 0x03]);
        assert_eq!(parameter.padding(), &[0xfe, 0xff]);
    }

    #[test]
    fn sctp_cookie_parameters_state_cookie_preserves_opaque_cookie_bytes() {
        let parameter =
            SctpStateCookieParameter::from_cookie([0xde, 0xad, 0xbe, 0xef]).with_padding([0xaa]);

        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_STATE_COOKIE
        );
        assert_eq!(parameter.length(), SCTP_PARAMETER_HEADER_LEN + 4);
        assert_eq!(parameter.cookie(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parameter.cookie_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parameter.value(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parameter.padding(), &[0xaa]);
        assert_eq!(parameter.encoded_len(), SCTP_PARAMETER_HEADER_LEN + 5);

        let replaced = parameter.with_cookie([0x01, 0x02, 0x03]);
        assert_eq!(replaced.cookie(), &[0x01, 0x02, 0x03]);
        assert_eq!(replaced.required_padding_len(), 1);

        let preserved = SctpStateCookieParameter::from_preserved_parts(4, [0xff], [0xee]);
        assert_eq!(preserved.length(), 4);
        assert_eq!(preserved.explicit_length(), Some(4));
        assert_eq!(preserved.cookie(), &[0xff]);
        assert_eq!(preserved.padding(), &[0xee]);

        let enum_parameter = SctpParameter::from(preserved);
        assert!(matches!(enum_parameter, SctpParameter::StateCookie(_)));
        assert_eq!(enum_parameter.value(), &[0xff]);
    }

    #[test]
    fn sctp_cookie_parameters_unrecognized_parameter_preserves_copied_parameter_bytes() {
        let copied = [0x80, 0x00, 0x00, 0x07, 0xde, 0xad, 0xbe];
        let parameter = SctpUnrecognizedParameter::from_copied_parameter(copied)
            .with_declared_length(11)
            .with_padding([0xcc]);

        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_UNRECOGNIZED_PARAMETER
        );
        assert_eq!(parameter.length(), 11);
        assert_eq!(parameter.explicit_declared_length(), Some(11));
        assert_eq!(parameter.copied_parameter(), &copied);
        assert_eq!(parameter.copied_parameter_bytes(), &copied);
        assert_eq!(parameter.unrecognized_parameter(), &copied);
        assert_eq!(parameter.unrecognized_parameter_bytes(), &copied);
        assert_eq!(parameter.value(), &copied);
        assert_eq!(parameter.padding(), &[0xcc]);

        let replaced = parameter.with_unrecognized_parameter([0x00, 0x0a, 0x00, 0x04]);
        assert_eq!(replaced.copied_parameter(), &[0x00, 0x0a, 0x00, 0x04]);
        assert_eq!(replaced.length(), 11);
        assert_eq!(replaced.padding(), &[0xcc]);

        let enum_parameter = SctpParameter::from(replaced);
        assert!(matches!(
            enum_parameter,
            SctpParameter::UnrecognizedParameter(_)
        ));
        assert_eq!(enum_parameter.value(), &[0x00, 0x0a, 0x00, 0x04]);
    }

    #[test]
    fn sctp_cookie_parameters_cookie_preservative_encodes_and_validates_life_span_increment(
    ) -> Result<()> {
        let parameter =
            SctpCookiePreservativeParameter::from_suggested_cookie_life_span_increment_millis(
                30_000,
            );

        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_COOKIE_PRESERVATIVE
        );
        assert_eq!(
            parameter.length(),
            SCTP_PARAMETER_HEADER_LEN + SCTP_COOKIE_PRESERVATIVE_PARAMETER_VALUE_LEN
        );
        assert_eq!(parameter.value(), &[0x00, 0x00, 0x75, 0x30]);
        assert_eq!(
            parameter.suggested_cookie_life_span_increment_bytes(),
            &[0x00, 0x00, 0x75, 0x30]
        );
        assert_eq!(
            parameter.suggested_cookie_life_span_increment_millis()?,
            30_000
        );
        assert_eq!(parameter.cookie_life_span_increment_millis()?, 30_000);

        let replaced = parameter.with_cookie_life_span_increment_millis(45_000);
        assert_eq!(replaced.value(), &[0x00, 0x00, 0xaf, 0xc8]);
        assert_eq!(
            replaced.suggested_cookie_life_span_increment_millis()?,
            45_000
        );

        let preserved =
            SctpCookiePreservativeParameter::from_preserved_parts(5, [0x00, 0x00, 0x75], [0xaa]);
        assert_eq!(preserved.length(), 5);
        assert_eq!(preserved.value(), &[0x00, 0x00, 0x75]);
        assert_eq!(preserved.padding(), &[0xaa]);
        assert_eq!(
            preserved
                .suggested_cookie_life_span_increment_millis()
                .unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_COOKIE_PRESERVATIVE_PARAMETER_CONTEXT,
                SCTP_COOKIE_PRESERVATIVE_PARAMETER_VALUE_LEN,
                3
            )
        );

        let long = SctpCookiePreservativeParameter::new([0, 0, 0, 1, 2]);
        assert_eq!(
            long.suggested_cookie_life_span_increment_millis()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_COOKIE_PRESERVATIVE_PARAMETER_CONTEXT,
                "value length must be four bytes"
            )
        );
        assert_eq!(long.value(), &[0, 0, 0, 1, 2]);

        let enum_parameter = SctpParameter::from(replaced);
        assert!(matches!(
            enum_parameter,
            SctpParameter::CookiePreservative(_)
        ));
        assert_eq!(enum_parameter.value(), &[0x00, 0x00, 0xaf, 0xc8]);

        Ok(())
    }

    #[test]
    fn sctp_address_parameters_ipv4_and_ipv6_helpers_encode_and_parse_addresses() -> Result<()> {
        let ipv4 = Ipv4Addr::new(192, 0, 2, 10);
        let ipv4_parameter = SctpIpv4AddressParameter::from_address(ipv4);
        assert_eq!(
            ipv4_parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_IPV4_ADDRESS
        );
        assert_eq!(
            ipv4_parameter.length(),
            SCTP_PARAMETER_HEADER_LEN + SCTP_IPV4_ADDRESS_PARAMETER_VALUE_LEN
        );
        assert_eq!(ipv4_parameter.value(), &ipv4.octets());
        assert_eq!(ipv4_parameter.address()?, ipv4);
        assert_eq!(ipv4_parameter.ipv4_address()?, ipv4);

        let replaced = ipv4_parameter.with_address(Ipv4Addr::new(198, 51, 100, 20));
        assert_eq!(replaced.address()?, Ipv4Addr::new(198, 51, 100, 20));

        let short_ipv4 = SctpIpv4AddressParameter::from_preserved_parts(5, [192, 0, 2], [0xaa]);
        assert_eq!(short_ipv4.length(), 5);
        assert_eq!(short_ipv4.value(), &[192, 0, 2]);
        assert_eq!(short_ipv4.padding(), &[0xaa]);
        assert_eq!(
            short_ipv4.address().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_IPV4_ADDRESS_PARAMETER_CONTEXT,
                SCTP_IPV4_ADDRESS_PARAMETER_VALUE_LEN,
                3
            )
        );

        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let ipv6_parameter = SctpIpv6AddressParameter::from_address(ipv6);
        assert_eq!(
            ipv6_parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_IPV6_ADDRESS
        );
        assert_eq!(
            ipv6_parameter.length(),
            SCTP_PARAMETER_HEADER_LEN + SCTP_IPV6_ADDRESS_PARAMETER_VALUE_LEN
        );
        assert_eq!(ipv6_parameter.value(), &ipv6.octets());
        assert_eq!(ipv6_parameter.address()?, ipv6);
        assert_eq!(ipv6_parameter.ipv6_address()?, ipv6);

        let long_ipv6 = ipv6_parameter.with_value([0u8; SCTP_IPV6_ADDRESS_PARAMETER_VALUE_LEN + 1]);
        assert_eq!(
            long_ipv6.address().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_IPV6_ADDRESS_PARAMETER_CONTEXT,
                "value length must match the parameter address width"
            )
        );

        Ok(())
    }

    #[test]
    fn sctp_address_parameters_host_name_helper_appends_null_and_preserves_raw_overrides(
    ) -> Result<()> {
        let parameter = SctpHostNameAddressParameter::from_host_name("node.example");
        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_HOST_NAME_ADDRESS
        );
        assert_eq!(parameter.value(), b"node.example\0");
        assert_eq!(parameter.host_name_wire_bytes(), b"node.example\0");
        assert_eq!(parameter.host_name_bytes()?, b"node.example");
        assert_eq!(parameter.host_name()?, "node.example");
        assert_eq!(parameter.hostname()?, "node.example");

        let replaced = parameter.with_hostname("next.example");
        assert_eq!(replaced.value(), b"next.example\0");
        assert_eq!(replaced.host_name()?, "next.example");

        let preserved =
            SctpHostNameAddressParameter::from_preserved_parts(7, b"bad".to_vec(), [0x00]);
        assert_eq!(preserved.length(), 7);
        assert_eq!(preserved.value(), b"bad");
        assert_eq!(preserved.padding(), &[0x00]);
        assert_eq!(
            preserved.host_name().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_HOST_NAME_ADDRESS_PARAMETER_FIELD,
                "missing null terminator"
            )
        );

        let trailing_nulls = SctpHostNameAddressParameter::new(b"host.example\0\0".to_vec());
        assert_eq!(trailing_nulls.host_name()?, "host.example");

        let non_null_tail = SctpHostNameAddressParameter::new(b"host\0tail".to_vec());
        assert_eq!(
            non_null_tail.host_name().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_HOST_NAME_ADDRESS_PARAMETER_FIELD,
                "non-null bytes after null terminator"
            )
        );

        Ok(())
    }

    #[test]
    fn sctp_address_parameters_supported_address_types_encode_parse_and_expose_families(
    ) -> Result<()> {
        let parameter = SctpSupportedAddressTypesParameter::from_address_types([
            SctpAddressType::Ipv4,
            SctpAddressType::Ipv6,
            SctpAddressType::Unknown(0x1234),
        ]);
        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_SUPPORTED_ADDRESS_TYPES
        );
        assert_eq!(parameter.value(), &[0x00, 0x05, 0x00, 0x06, 0x12, 0x34]);
        assert_eq!(
            parameter.address_types()?,
            vec![
                SctpAddressType::Ipv4,
                SctpAddressType::Ipv6,
                SctpAddressType::Unknown(0x1234),
            ]
        );
        assert_eq!(
            parameter.address_type_values()?,
            vec![
                SCTP_PARAMETER_TYPE_IPV4_ADDRESS,
                SCTP_PARAMETER_TYPE_IPV6_ADDRESS,
                0x1234,
            ]
        );
        assert_eq!(
            parameter.address_families()?,
            vec![SctpAddressFamily::Ipv4, SctpAddressFamily::Ipv6]
        );
        assert!(parameter.supports_ipv4()?);
        assert!(parameter.supports_ipv6()?);
        assert!(parameter.supports_address_type(SctpAddressType::Unknown(0x1234))?);
        assert!(parameter.supports_address_family(SctpAddressFamily::Ipv4)?);

        let values = SctpSupportedAddressTypesParameter::from_address_type_values([
            SCTP_PARAMETER_TYPE_IPV4_ADDRESS,
            SCTP_PARAMETER_TYPE_IPV6_ADDRESS,
        ]);
        assert_eq!(
            values.address_types()?,
            vec![SctpAddressType::Ipv4, SctpAddressType::Ipv6]
        );

        let families = SctpSupportedAddressTypesParameter::new([])
            .with_address_families([SctpAddressFamily::Ipv4, SctpAddressFamily::Ipv6]);
        assert_eq!(families.value(), &[0x00, 0x05, 0x00, 0x06]);
        assert_eq!(
            SctpAddressFamily::Ipv4.parameter_type_value(),
            SCTP_PARAMETER_TYPE_IPV4_ADDRESS
        );
        assert_eq!(SctpAddressType::from_u16(0x000b), SctpAddressType::HostName);
        assert_eq!(SctpAddressType::HostName.address_family(), None);

        Ok(())
    }

    #[test]
    fn sctp_address_parameters_supported_address_types_preserve_host_name_and_reject_odd_values(
    ) -> Result<()> {
        let host_name =
            SctpSupportedAddressTypesParameter::from_address_types([SctpAddressType::HostName]);
        assert_eq!(host_name.value(), &[0x00, 0x0b]);
        assert_eq!(host_name.address_types()?, vec![SctpAddressType::HostName]);
        assert_eq!(
            host_name.address_families()?,
            Vec::<SctpAddressFamily>::new()
        );
        assert!(!host_name.supports_ipv4()?);
        assert!(!host_name.supports_ipv6()?);

        let odd = SctpSupportedAddressTypesParameter::new([0x00, 0x05, 0xff]);
        assert_eq!(
            odd.address_types().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_SUPPORTED_ADDRESS_TYPES_PARAMETER_FIELD,
                "address type list must contain complete 16-bit values"
            )
        );
        assert_eq!(odd.value(), &[0x00, 0x05, 0xff]);

        Ok(())
    }

    #[test]
    fn sctp_capability_parameters_supported_extensions_encode_parse_and_query_chunk_types() {
        let parameter = SctpSupportedExtensionsParameter::from_chunk_type_values([
            SCTP_CHUNK_TYPE_ASCONF,
            SCTP_CHUNK_TYPE_ASCONF_ACK,
            SCTP_CHUNK_TYPE_AUTH,
            0xfe,
        ]);

        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_SUPPORTED_EXTENSIONS
        );
        assert_eq!(
            parameter.value(),
            &[
                SCTP_CHUNK_TYPE_ASCONF,
                SCTP_CHUNK_TYPE_ASCONF_ACK,
                SCTP_CHUNK_TYPE_AUTH,
                0xfe,
            ]
        );
        assert_eq!(
            parameter.chunk_types(),
            vec![
                SctpChunkType::new(SCTP_CHUNK_TYPE_ASCONF),
                SctpChunkType::new(SCTP_CHUNK_TYPE_ASCONF_ACK),
                SctpChunkType::new(SCTP_CHUNK_TYPE_AUTH),
                SctpChunkType::new(0xfe),
            ]
        );
        assert_eq!(
            parameter.chunk_type_values(),
            vec![
                SCTP_CHUNK_TYPE_ASCONF,
                SCTP_CHUNK_TYPE_ASCONF_ACK,
                SCTP_CHUNK_TYPE_AUTH,
                0xfe,
            ]
        );
        assert!(parameter.supports_asconf());
        assert!(parameter.supports_asconf_ack());
        assert!(parameter.supports_auth());
        assert!(parameter.supports_chunk_type(SctpChunkType::new(0xfe)));
        assert!(!parameter.supports_forward_tsn_chunk());

        let replaced =
            parameter.with_chunk_types([SctpChunkType::new(SCTP_CHUNK_TYPE_FORWARD_TSN)]);
        assert_eq!(replaced.value(), &[SCTP_CHUNK_TYPE_FORWARD_TSN]);
        assert!(replaced.supports_forward_tsn_chunk());

        let enum_parameter = SctpParameter::from(replaced);
        assert!(matches!(
            enum_parameter,
            SctpParameter::SupportedExtensions(_)
        ));
    }

    #[test]
    fn sctp_capability_parameters_forward_tsn_supported_is_empty_and_ecn_stays_unknown(
    ) -> Result<()> {
        let parameter = SctpForwardTsnSupportedParameter::from_supported().with_padding([0xaa]);

        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_FORWARD_TSN_SUPPORTED
        );
        assert_eq!(
            parameter.length(),
            SCTP_PARAMETER_HEADER_LEN + SCTP_FORWARD_TSN_SUPPORTED_PARAMETER_VALUE_LEN
        );
        assert_eq!(parameter.value(), &[]);
        assert_eq!(parameter.padding(), &[0xaa]);
        parameter.validate_supported()?;
        assert!(parameter.is_forward_tsn_supported()?);

        let malformed = SctpForwardTsnSupportedParameter::new([0xde]);
        assert_eq!(
            malformed.validate_supported().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_FORWARD_TSN_SUPPORTED_PARAMETER_CONTEXT,
                "value length must be zero bytes",
            )
        );
        assert_eq!(malformed.value(), &[0xde]);

        let ecn = SctpParameter::from_preserved_parts(
            SCTP_PARAMETER_TYPE_ECN_CAPABLE,
            7,
            [0x01, 0x02, 0x03],
            [0xee],
        );
        let SctpParameter::Unknown(unknown) = ecn else {
            panic!("reserved ECN Capable value must remain byte-preserving unknown");
        };
        assert_eq!(
            unknown.parameter_type_value(),
            SCTP_PARAMETER_TYPE_ECN_CAPABLE
        );
        assert_eq!(unknown.length(), 7);
        assert_eq!(unknown.explicit_length(), Some(7));
        assert_eq!(unknown.value(), &[0x01, 0x02, 0x03]);
        assert_eq!(unknown.padding(), &[0xee]);

        Ok(())
    }

    #[test]
    fn sctp_capability_parameters_adaptation_layer_indication_encodes_and_validates_codepoints(
    ) -> Result<()> {
        let parameter = SctpAdaptationLayerIndicationParameter::from_adaptation_code_point(
            SctpAdaptationCodePoint::Ddp,
        );

        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_ADAPTATION_LAYER_INDICATION
        );
        assert_eq!(
            parameter.length(),
            SCTP_PARAMETER_HEADER_LEN + SCTP_ADAPTATION_LAYER_INDICATION_PARAMETER_VALUE_LEN
        );
        assert_eq!(parameter.value(), &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(
            parameter.adaptation_code_point_bytes(),
            &[0x00, 0x00, 0x00, 0x01]
        );
        assert_eq!(
            parameter.adaptation_code_point()?,
            SctpAdaptationCodePoint::Ddp
        );
        assert_eq!(
            parameter.adaptation_code_point_value()?,
            SCTP_ADAPTATION_CODE_POINT_DDP
        );

        let unknown = parameter.with_adaptation_code_point_value(0x1234_5678);
        assert_eq!(unknown.value(), &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(
            unknown.adaptation_code_point()?,
            SctpAdaptationCodePoint::Unknown(0x1234_5678)
        );
        assert_eq!(SctpAdaptationCodePoint::from_u32(0).as_u32(), 0);

        let short = SctpAdaptationLayerIndicationParameter::from_preserved_parts(
            7,
            [0x00, 0x00, 0x01],
            [0xaa],
        );
        assert_eq!(
            short.adaptation_code_point().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_ADAPTATION_LAYER_INDICATION_PARAMETER_CONTEXT,
                SCTP_ADAPTATION_LAYER_INDICATION_PARAMETER_VALUE_LEN,
                3,
            )
        );
        assert_eq!(short.value(), &[0x00, 0x00, 0x01]);
        assert_eq!(short.padding(), &[0xaa]);

        let long = SctpAdaptationLayerIndicationParameter::new([0, 0, 0, 1, 2]);
        assert_eq!(
            long.adaptation_code_point().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_ADAPTATION_LAYER_INDICATION_PARAMETER_CONTEXT,
                "value length must be four bytes",
            )
        );
        assert_eq!(long.value(), &[0, 0, 0, 1, 2]);

        let enum_parameter = SctpParameter::from(unknown);
        assert!(matches!(
            enum_parameter,
            SctpParameter::AdaptationLayerIndication(_)
        ));

        Ok(())
    }

    #[test]
    fn sctp_capability_parameters_zero_checksum_acceptable_encodes_error_detection_methods(
    ) -> Result<()> {
        let parameter = SctpZeroChecksumAcceptableParameter::from_error_detection_method(
            SctpErrorDetectionMethod::SctpOverDtls,
        );

        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_ZERO_CHECKSUM_ACCEPTABLE
        );
        assert_eq!(
            parameter.length(),
            SCTP_PARAMETER_HEADER_LEN + SCTP_ZERO_CHECKSUM_ACCEPTABLE_PARAMETER_VALUE_LEN
        );
        assert_eq!(parameter.value(), &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(
            parameter.error_detection_method_bytes(),
            &[0x00, 0x00, 0x00, 0x01]
        );
        assert_eq!(
            parameter.error_detection_method()?,
            SctpErrorDetectionMethod::SctpOverDtls
        );
        assert_eq!(
            parameter.error_detection_method_identifier()?,
            SCTP_ERROR_DETECTION_METHOD_SCTP_OVER_DTLS
        );
        assert_eq!(
            parameter.edmid()?,
            SCTP_ERROR_DETECTION_METHOD_SCTP_OVER_DTLS
        );
        assert!(parameter.accepts_sctp_over_dtls()?);

        let reserved = parameter
            .clone()
            .with_error_detection_method(SctpErrorDetectionMethod::Reserved);
        assert_eq!(
            reserved.error_detection_method()?,
            SctpErrorDetectionMethod::Reserved
        );
        assert_eq!(
            reserved.error_detection_method_identifier()?,
            SCTP_ERROR_DETECTION_METHOD_RESERVED
        );
        assert!(!reserved.accepts_sctp_over_dtls()?);

        let unknown = SctpZeroChecksumAcceptableParameter::from_error_detection_method_identifier(
            0xfeed_beef,
        );
        assert_eq!(
            unknown.error_detection_method()?,
            SctpErrorDetectionMethod::Unknown(0xfeed_beef)
        );
        assert_eq!(
            SctpErrorDetectionMethod::from_u32(0xfeed_beef).as_u32(),
            0xfeed_beef
        );

        let short = SctpZeroChecksumAcceptableParameter::from_preserved_parts(
            7,
            [0x00, 0x00, 0x01],
            [0xaa],
        );
        assert_eq!(
            short.error_detection_method().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_ZERO_CHECKSUM_ACCEPTABLE_PARAMETER_CONTEXT,
                SCTP_ZERO_CHECKSUM_ACCEPTABLE_PARAMETER_VALUE_LEN,
                3,
            )
        );
        assert_eq!(short.value(), &[0x00, 0x00, 0x01]);
        assert_eq!(short.padding(), &[0xaa]);

        let long = SctpZeroChecksumAcceptableParameter::new([0, 0, 0, 1, 2]);
        assert_eq!(
            long.error_detection_method().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_ZERO_CHECKSUM_ACCEPTABLE_PARAMETER_CONTEXT,
                "value length must be four bytes",
            )
        );
        assert_eq!(long.value(), &[0, 0, 0, 1, 2]);

        let enum_parameter = SctpParameter::from(unknown);
        assert!(matches!(
            enum_parameter,
            SctpParameter::ZeroChecksumAcceptable(_)
        ));

        Ok(())
    }

    #[test]
    fn sctp_addip_parameters_address_requests_encode_correlation_ids_and_address_tlvs() -> Result<()>
    {
        let ipv4 = Ipv4Addr::new(192, 0, 2, 1);
        let add =
            SctpAddIpAddressParameter::from_correlation_id_and_ipv4_address(0x0102_3474, ipv4)
                .with_padding([0xaa, 0xbb]);

        assert_eq!(
            add.parameter_type_value(),
            SCTP_PARAMETER_TYPE_ADD_IP_ADDRESS
        );
        assert_eq!(add.length(), 16);
        assert_eq!(
            add.value(),
            &[0x01, 0x02, 0x34, 0x74, 0x00, 0x05, 0x00, 0x08, 192, 0, 2, 1]
        );
        assert_eq!(add.padding(), &[0xaa, 0xbb]);
        assert_eq!(add.correlation_id()?, 0x0102_3474);
        assert_eq!(add.request_correlation_id()?, 0x0102_3474);
        assert_eq!(
            add.address_parameter_bytes()?,
            &[0x00, 0x05, 0x00, 0x08, 192, 0, 2, 1]
        );
        assert_eq!(
            add.raw_address_parameter_bytes()?,
            &[0x00, 0x05, 0x00, 0x08, 192, 0, 2, 1]
        );
        assert_eq!(
            add.address_parameter_type_value()?,
            SCTP_PARAMETER_TYPE_IPV4_ADDRESS
        );
        assert_eq!(add.address_parameter_declared_length()?, 8);
        assert_eq!(add.address_value_bytes()?, &[192, 0, 2, 1]);
        add.validate_address_parameter()?;
        assert_eq!(add.ipv4_address()?, ipv4);
        assert_eq!(
            add.ipv6_address().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_ASCONF_ADDRESS_PARAMETER_TYPE_FIELD,
                "address parameter must be IPv6",
            )
        );

        let delete = SctpDeleteIpAddressParameter::from_request_correlation_id_and_ipv4_address(
            0x0102_3476,
            ipv4,
        );
        assert_eq!(
            delete.parameter_type_value(),
            SCTP_PARAMETER_TYPE_DELETE_IP_ADDRESS
        );
        assert_eq!(delete.request_correlation_id()?, 0x0102_3476);
        assert_eq!(delete.ipv4_address()?, ipv4);

        let ipv6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let set =
            SctpSetPrimaryAddressParameter::from_correlation_id_and_ipv6_address(0x0102_3479, ipv6);
        assert_eq!(
            set.parameter_type_value(),
            SCTP_PARAMETER_TYPE_SET_PRIMARY_ADDRESS
        );
        assert_eq!(set.length(), 28);
        assert_eq!(set.correlation_id()?, 0x0102_3479);
        assert_eq!(
            set.address_parameter_type_value()?,
            SCTP_PARAMETER_TYPE_IPV6_ADDRESS
        );
        set.validate_address_parameter()?;
        assert_eq!(set.ipv6_address()?, ipv6);

        let enum_parameter = SctpParameter::from(add);
        assert!(matches!(enum_parameter, SctpParameter::AddIpAddress(_)));

        Ok(())
    }

    #[test]
    fn sctp_addip_parameters_preserve_malformed_address_values_lengths_and_padding() -> Result<()> {
        let raw_address_parameter = [0x00, 0x05, 0x00, 0x07, 192, 0, 2, 0xee];
        let add = SctpAddIpAddressParameter::from_correlation_id_and_address_parameter_bytes(
            0x0102_3474,
            raw_address_parameter,
        )
        .with_declared_length(0x000f)
        .with_padding([0xcc]);

        assert_eq!(add.length(), 0x000f);
        assert_eq!(add.explicit_length(), Some(0x000f));
        assert_eq!(
            add.value()[..SCTP_ASCONF_CORRELATION_ID_LEN],
            [0x01, 0x02, 0x34, 0x74]
        );
        assert_eq!(add.address_parameter_bytes()?, &raw_address_parameter);
        assert_eq!(add.address_value_bytes()?, &[192, 0, 2]);
        assert_eq!(
            add.validate_address_parameter().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_ASCONF_ADDRESS_IPV4_CONTEXT,
                SCTP_IPV4_ADDRESS_PARAMETER_VALUE_LEN,
                3,
            )
        );
        assert_eq!(add.padding(), &[0xcc]);

        let short = SctpDeleteIpAddressParameter::from_preserved_parts(7, [0xde, 0xad], [0xbb]);
        assert_eq!(short.length(), 7);
        assert_eq!(short.explicit_length(), Some(7));
        assert_eq!(short.value(), &[0xde, 0xad]);
        assert_eq!(short.padding(), &[0xbb]);
        assert_eq!(
            short.correlation_id().unwrap_err(),
            CrafterError::buffer_too_short(SCTP_DELETE_IP_ADDRESS_PARAMETER_CONTEXT, 4, 2)
        );
        assert_eq!(
            short.address_parameter_bytes().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_DELETE_IP_ADDRESS_PARAMETER_CONTEXT,
                SCTP_ASCONF_ADDRESS_PARAMETER_MIN_VALUE_LEN,
                2,
            )
        );

        let host_name_tlv = [0x00, 0x0b, 0x00, 0x08, b'h', b'i', 0x00, 0x00];
        let set = SctpSetPrimaryAddressParameter::from_correlation_id_and_address_parameter_bytes(
            0x0102_3479,
            host_name_tlv,
        );
        assert_eq!(
            set.address_parameter_type_value()?,
            SCTP_PARAMETER_TYPE_HOST_NAME_ADDRESS
        );
        assert_eq!(
            set.validate_address_parameter().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_ASCONF_ADDRESS_PARAMETER_TYPE_FIELD,
                "address parameter must be IPv4 or IPv6",
            )
        );
        assert_eq!(set.raw_address_parameter_bytes()?, &host_name_tlv);

        Ok(())
    }

    #[test]
    fn sctp_addip_parameters_success_indication_is_fixed_width_and_raw_preserving() -> Result<()> {
        let success = SctpSuccessIndicationParameter::from_response_correlation_id(0x0102_3474)
            .with_padding([0xaa, 0xbb, 0xcc]);

        assert_eq!(
            success.parameter_type_value(),
            SCTP_PARAMETER_TYPE_SUCCESS_INDICATION
        );
        assert_eq!(
            success.length(),
            SCTP_PARAMETER_HEADER_LEN + SCTP_SUCCESS_INDICATION_PARAMETER_VALUE_LEN
        );
        assert_eq!(success.value(), &[0x01, 0x02, 0x34, 0x74]);
        assert_eq!(success.padding(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(success.response_correlation_id()?, 0x0102_3474);
        assert_eq!(success.correlation_id()?, 0x0102_3474);
        success.validate_success_indication()?;

        let replaced = success.with_correlation_id(0x0102_3476);
        assert_eq!(replaced.value(), &[0x01, 0x02, 0x34, 0x76]);

        let short =
            SctpSuccessIndicationParameter::from_preserved_parts(7, [0x01, 0x02, 0x03], [0xdd]);
        assert_eq!(short.length(), 7);
        assert_eq!(short.padding(), &[0xdd]);
        assert_eq!(
            short.response_correlation_id().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_SUCCESS_INDICATION_PARAMETER_CONTEXT,
                SCTP_SUCCESS_INDICATION_PARAMETER_VALUE_LEN,
                3,
            )
        );

        let long = SctpSuccessIndicationParameter::new([0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(
            long.validate_success_indication().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_SUCCESS_INDICATION_PARAMETER_CONTEXT,
                "value length must be four bytes",
            )
        );

        let enum_parameter = SctpParameter::from(replaced);
        assert!(matches!(
            enum_parameter,
            SctpParameter::SuccessIndication(_)
        ));

        Ok(())
    }

    #[test]
    fn sctp_addip_parameters_error_cause_indication_preserves_raw_cause_bytes() -> Result<()> {
        let cause = [0x00, 0xa1, 0x00, 0x04];
        let error =
            SctpErrorCauseIndicationParameter::from_response_correlation_id_and_error_cause_bytes(
                0x0102_3474,
                cause,
            )
            .with_padding([0xee]);

        assert_eq!(
            error.parameter_type_value(),
            SCTP_PARAMETER_TYPE_ERROR_CAUSE_INDICATION
        );
        assert_eq!(error.length(), 12);
        assert_eq!(error.response_correlation_id()?, 0x0102_3474);
        assert_eq!(error.correlation_id()?, 0x0102_3474);
        assert_eq!(error.error_cause_bytes()?, &cause);
        assert_eq!(error.error_causes()?, &cause);
        assert_eq!(error.padding(), &[0xee]);
        error.validate_contains_error_cause()?;

        let replaced =
            error.with_correlation_id_and_error_cause_bytes(0x0102_3476, [0x00, 0xa0, 0x00, 0x04]);
        assert_eq!(replaced.response_correlation_id()?, 0x0102_3476);
        assert_eq!(replaced.error_cause_bytes()?, &[0x00, 0xa0, 0x00, 0x04]);

        let empty = SctpErrorCauseIndicationParameter::from_correlation_id_and_error_cause_bytes(
            0x0102_3479,
            [],
        );
        assert_eq!(empty.error_cause_bytes()?, &[]);
        assert_eq!(
            empty.validate_contains_error_cause().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_ERROR_CAUSE_INDICATION_ERROR_CAUSES_CONTEXT,
                SCTP_PARAMETER_HEADER_LEN,
                0,
            )
        );

        let short =
            SctpErrorCauseIndicationParameter::from_preserved_parts(7, [0x01, 0x02, 0x03], [0xdd]);
        assert_eq!(short.value(), &[0x01, 0x02, 0x03]);
        assert_eq!(short.padding(), &[0xdd]);
        assert_eq!(
            short.response_correlation_id().unwrap_err(),
            CrafterError::buffer_too_short(SCTP_ERROR_CAUSE_INDICATION_PARAMETER_CONTEXT, 4, 3)
        );

        let enum_parameter = SctpParameter::from(replaced);
        assert!(matches!(
            enum_parameter,
            SctpParameter::ErrorCauseIndication(_)
        ));

        Ok(())
    }

    #[test]
    fn sctp_reconfig_parameters_stream_reset_requests_encode_sequences_and_streams() -> Result<()> {
        let outgoing =
            SctpOutgoingSsnResetRequestParameter::from_request_response_sequence_numbers_sender_last_assigned_tsn_and_stream_numbers(
                0x0102_0304,
                0x1112_1314,
                0x2122_2324,
                [7u16, 9],
            )
            .with_padding([0xaa, 0xbb]);

        assert_eq!(
            outgoing.parameter_type_value(),
            SCTP_PARAMETER_TYPE_OUTGOING_SSN_RESET_REQUEST
        );
        assert_eq!(outgoing.length(), 20);
        assert_eq!(
            outgoing.value(),
            &[
                0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24, 0x00, 0x07,
                0x00, 0x09,
            ]
        );
        assert_eq!(outgoing.padding(), &[0xaa, 0xbb]);
        assert_eq!(outgoing.request_sequence_number()?, 0x0102_0304);
        assert_eq!(
            outgoing.reconfiguration_request_sequence_number()?,
            0x0102_0304
        );
        assert_eq!(outgoing.response_sequence_number()?, 0x1112_1314);
        assert_eq!(
            outgoing.reconfiguration_response_sequence_number()?,
            0x1112_1314
        );
        assert_eq!(outgoing.sender_last_assigned_tsn()?, 0x2122_2324);
        assert_eq!(outgoing.stream_numbers()?, vec![7, 9]);
        assert!(!outgoing.resets_all_streams()?);
        outgoing.validate_outgoing_ssn_reset_request()?;

        let all =
            SctpOutgoingSsnResetRequestParameter::from_request_response_sequence_numbers_and_sender_last_assigned_tsn(
                0x0102_0305,
                0x1112_1315,
                0x2122_2325,
            );
        assert_eq!(all.length(), 16);
        assert_eq!(all.stream_numbers()?, Vec::<u16>::new());
        assert!(all.resets_all_streams()?);

        let incoming =
            SctpIncomingSsnResetRequestParameter::from_request_sequence_number_and_stream_numbers(
                0x3132_3334,
                [3u16],
            );
        assert_eq!(
            incoming.parameter_type_value(),
            SCTP_PARAMETER_TYPE_INCOMING_SSN_RESET_REQUEST
        );
        assert_eq!(incoming.length(), 10);
        assert_eq!(incoming.required_padding_len(), 2);
        assert_eq!(incoming.value(), &[0x31, 0x32, 0x33, 0x34, 0x00, 0x03]);
        assert_eq!(incoming.request_sequence_number()?, 0x3132_3334);
        assert_eq!(incoming.stream_numbers()?, vec![3]);
        incoming.validate_incoming_ssn_reset_request()?;

        let enum_parameter = SctpParameter::from(outgoing);
        assert!(matches!(
            enum_parameter,
            SctpParameter::OutgoingSsnResetRequest(_)
        ));
        let enum_parameter = SctpParameter::from(incoming);
        assert!(matches!(
            enum_parameter,
            SctpParameter::IncomingSsnResetRequest(_)
        ));

        Ok(())
    }

    #[test]
    fn sctp_reconfig_parameters_preserve_malformed_stream_reset_values() -> Result<()> {
        let short =
            SctpOutgoingSsnResetRequestParameter::from_preserved_parts(7, [0xde, 0xad], [0xee]);
        assert_eq!(short.length(), 7);
        assert_eq!(short.explicit_length(), Some(7));
        assert_eq!(short.value(), &[0xde, 0xad]);
        assert_eq!(short.padding(), &[0xee]);
        assert_eq!(
            short.request_sequence_number().unwrap_err(),
            CrafterError::buffer_too_short(SCTP_OUTGOING_SSN_RESET_REQUEST_PARAMETER_CONTEXT, 4, 2)
        );
        assert_eq!(
            short.stream_numbers().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_OUTGOING_SSN_RESET_REQUEST_PARAMETER_CONTEXT,
                SCTP_OUTGOING_SSN_RESET_REQUEST_FIXED_VALUE_LEN,
                2,
            )
        );

        let odd_stream_list =
            SctpIncomingSsnResetRequestParameter::new([0x01, 0x02, 0x03, 0x04, 0x00]);
        assert_eq!(odd_stream_list.value(), &[0x01, 0x02, 0x03, 0x04, 0x00]);
        assert_eq!(odd_stream_list.request_sequence_number()?, 0x0102_0304);
        assert_eq!(
            odd_stream_list.stream_numbers().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_INCOMING_SSN_RESET_REQUEST_STREAMS_CONTEXT,
                "stream number list must contain complete 16-bit values",
            )
        );
        assert_eq!(
            odd_stream_list
                .validate_incoming_ssn_reset_request()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_INCOMING_SSN_RESET_REQUEST_STREAMS_CONTEXT,
                "stream number list must contain complete 16-bit values",
            )
        );

        Ok(())
    }

    #[test]
    fn sctp_reconfig_parameters_ssn_tsn_reset_and_response_fields() -> Result<()> {
        let request = SctpSsnTsnResetRequestParameter::from_request_sequence_number(0x0102_0304)
            .with_padding([0xaa, 0xbb, 0xcc]);
        assert_eq!(
            request.parameter_type_value(),
            SCTP_PARAMETER_TYPE_SSN_TSN_RESET_REQUEST
        );
        assert_eq!(request.length(), 8);
        assert_eq!(request.value(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(request.padding(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(request.request_sequence_number()?, 0x0102_0304);
        request.validate_ssn_tsn_reset_request()?;

        let long = request
            .clone()
            .with_request_sequence_number(0x0102_0305)
            .with_value([0x01, 0x02, 0x03, 0x05, 0xff]);
        assert_eq!(
            long.validate_ssn_tsn_reset_request().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_SSN_TSN_RESET_REQUEST_PARAMETER_CONTEXT,
                "value length must be four bytes",
            )
        );

        let response =
            SctpReConfigurationResponseParameter::from_response_sequence_number_and_result(
                0x1112_1314,
                SctpReconfigurationResult::SuccessPerformed,
            )
            .with_padding([0xdd]);
        assert_eq!(
            response.parameter_type_value(),
            SCTP_PARAMETER_TYPE_RE_CONFIGURATION_RESPONSE
        );
        assert_eq!(response.length(), 12);
        assert_eq!(response.response_sequence_number()?, 0x1112_1314);
        assert_eq!(
            response.result()?,
            SctpReconfigurationResult::SuccessPerformed
        );
        assert_eq!(
            response.result_value()?,
            SCTP_RECONFIGURATION_RESULT_SUCCESS_PERFORMED
        );
        assert_eq!(response.next_tsns()?, None);
        assert_eq!(response.sender_next_tsn()?, None);
        assert_eq!(response.receiver_next_tsn()?, None);
        response.validate_reconfiguration_response()?;

        let with_tsns =
            SctpReConfigurationResponseParameter::from_response_sequence_number_result_and_next_tsns(
                0x1112_1315,
                SctpReconfigurationResult::ErrorBadSequenceNumber,
                0x2122_2324,
                0x3132_3334,
            );
        assert_eq!(with_tsns.length(), 20);
        assert_eq!(
            with_tsns.result()?,
            SctpReconfigurationResult::ErrorBadSequenceNumber
        );
        assert_eq!(with_tsns.next_tsns()?, Some((0x2122_2324, 0x3132_3334)));
        assert_eq!(with_tsns.sender_next_tsn()?, Some(0x2122_2324));
        assert_eq!(with_tsns.receiver_next_tsn()?, Some(0x3132_3334));
        with_tsns.validate_reconfiguration_response()?;

        let unknown =
            SctpReConfigurationResponseParameter::from_response_sequence_number_and_result_value(
                0x1112_1316,
                0xbeef,
            );
        assert_eq!(
            unknown.result()?,
            SctpReconfigurationResult::Unknown(0xbeef)
        );
        assert_eq!(SctpReconfigurationResult::from_u32(6).as_u32(), 6);

        let partial_next_tsn = SctpReConfigurationResponseParameter::new([
            0x11, 0x12, 0x13, 0x17, 0x00, 0x00, 0x00, 0x01, 0x21, 0x22, 0x23, 0x24,
        ]);
        assert_eq!(
            partial_next_tsn
                .validate_reconfiguration_response()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_RE_CONFIGURATION_RESPONSE_PARAMETER_CONTEXT,
                "value length must be eight or sixteen bytes",
            )
        );

        let enum_parameter = SctpParameter::from(with_tsns);
        assert!(matches!(
            enum_parameter,
            SctpParameter::ReConfigurationResponse(_)
        ));
        let enum_parameter = SctpParameter::from(request);
        assert!(matches!(
            enum_parameter,
            SctpParameter::SsnTsnResetRequest(_)
        ));

        Ok(())
    }

    #[test]
    fn sctp_reconfig_parameters_add_streams_requests_preserve_reserved_field() -> Result<()> {
        let outgoing =
            SctpAddOutgoingStreamsRequestParameter::from_request_sequence_number_and_number_of_new_streams(
                0x0102_0304,
                3,
            )
            .with_padding([0xee]);

        assert_eq!(
            outgoing.parameter_type_value(),
            SCTP_PARAMETER_TYPE_ADD_OUTGOING_STREAMS_REQUEST
        );
        assert_eq!(outgoing.length(), 12);
        assert_eq!(
            outgoing.value(),
            &[0x01, 0x02, 0x03, 0x04, 0x00, 0x03, 0x00, 0x00]
        );
        assert_eq!(outgoing.request_sequence_number()?, 0x0102_0304);
        assert_eq!(outgoing.number_of_new_streams()?, 3);
        assert_eq!(outgoing.reserved()?, 0);
        assert_eq!(outgoing.padding(), &[0xee]);
        outgoing.validate_add_streams_request()?;

        let incoming =
            SctpAddIncomingStreamsRequestParameter::from_request_sequence_number_number_of_new_streams_and_reserved(
                0x1112_1314,
                4,
                0xbeef,
            );
        assert_eq!(
            incoming.parameter_type_value(),
            SCTP_PARAMETER_TYPE_ADD_INCOMING_STREAMS_REQUEST
        );
        assert_eq!(incoming.request_sequence_number()?, 0x1112_1314);
        assert_eq!(incoming.number_of_new_streams()?, 4);
        assert_eq!(incoming.reserved()?, 0xbeef);
        incoming.validate_add_streams_request()?;

        let replaced =
            incoming.with_request_sequence_number_and_number_of_new_streams(0x1112_1315, 5);
        assert_eq!(
            replaced.value(),
            &[0x11, 0x12, 0x13, 0x15, 0x00, 0x05, 0x00, 0x00]
        );

        let short = SctpAddOutgoingStreamsRequestParameter::from_preserved_parts(
            11,
            [0x01, 0x02, 0x03, 0x04, 0x00, 0x03, 0x00],
            [0xdd],
        );
        assert_eq!(short.length(), 11);
        assert_eq!(short.padding(), &[0xdd]);
        assert_eq!(short.number_of_new_streams()?, 3);
        assert_eq!(
            short.reserved().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_ADD_OUTGOING_STREAMS_REQUEST_PARAMETER_CONTEXT,
                SCTP_ADD_STREAMS_REQUEST_VALUE_LEN,
                7,
            )
        );
        assert_eq!(
            short.validate_add_streams_request().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_ADD_OUTGOING_STREAMS_REQUEST_PARAMETER_CONTEXT,
                SCTP_ADD_STREAMS_REQUEST_VALUE_LEN,
                7,
            )
        );

        let enum_parameter = SctpParameter::from(outgoing);
        assert!(matches!(
            enum_parameter,
            SctpParameter::AddOutgoingStreamsRequest(_)
        ));
        let enum_parameter = SctpParameter::from(replaced);
        assert!(matches!(
            enum_parameter,
            SctpParameter::AddIncomingStreamsRequest(_)
        ));

        Ok(())
    }

    #[test]
    fn sctp_auth_parameters_random_preserves_raw_value_padding_and_validates_length() -> Result<()>
    {
        let random = [0x5a; SCTP_AUTH_RANDOM_NUMBER_LEN];
        let parameter = SctpRandomParameter::from_random_number(random).with_padding([0xaa]);

        assert_eq!(parameter.parameter_type_value(), SCTP_PARAMETER_TYPE_RANDOM);
        assert_eq!(
            parameter.length(),
            SCTP_PARAMETER_HEADER_LEN + SCTP_AUTH_RANDOM_NUMBER_LEN
        );
        assert_eq!(parameter.random_number(), &random);
        assert_eq!(parameter.random_number_bytes(), &random);
        assert_eq!(parameter.value(), &random);
        assert_eq!(parameter.padding(), &[0xaa]);
        parameter.validate_association_random_number_len()?;

        let replaced = parameter.with_random_number([0x33; SCTP_AUTH_RANDOM_NUMBER_LEN]);
        assert_eq!(
            replaced.random_number(),
            &[0x33; SCTP_AUTH_RANDOM_NUMBER_LEN]
        );

        let short = SctpRandomParameter::from_preserved_parts(
            35,
            [0x11; SCTP_AUTH_RANDOM_NUMBER_LEN - 1],
            [0xbb],
        );
        assert_eq!(short.length(), 35);
        assert_eq!(short.padding(), &[0xbb]);
        assert_eq!(
            short.validate_association_random_number_len().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_RANDOM_PARAMETER_CONTEXT,
                SCTP_AUTH_RANDOM_NUMBER_LEN,
                SCTP_AUTH_RANDOM_NUMBER_LEN - 1,
            )
        );

        let long = SctpRandomParameter::new([0x22; SCTP_AUTH_RANDOM_NUMBER_LEN + 1]);
        assert_eq!(
            long.validate_association_random_number_len().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_RANDOM_PARAMETER_CONTEXT,
                "random number must be 32 bytes",
            )
        );

        let enum_parameter = SctpParameter::from(replaced);
        assert!(matches!(enum_parameter, SctpParameter::Random(_)));
        assert_eq!(enum_parameter.value(), &[0x33; SCTP_AUTH_RANDOM_NUMBER_LEN]);

        Ok(())
    }

    #[test]
    fn sctp_auth_parameters_chunk_list_preserves_values_and_ignores_forbidden_entries() -> Result<()>
    {
        let parameter = SctpChunkListParameter::from_chunk_type_values([
            SCTP_CHUNK_TYPE_DATA,
            SCTP_CHUNK_TYPE_COOKIE_ECHO,
            SCTP_CHUNK_TYPE_INIT,
            SCTP_CHUNK_TYPE_AUTH,
            0xfe,
        ])
        .with_padding([0x00, 0x00, 0x00]);

        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_CHUNK_LIST
        );
        assert_eq!(
            parameter.value(),
            &[
                SCTP_CHUNK_TYPE_DATA,
                SCTP_CHUNK_TYPE_COOKIE_ECHO,
                SCTP_CHUNK_TYPE_INIT,
                SCTP_CHUNK_TYPE_AUTH,
                0xfe,
            ]
        );
        assert_eq!(
            parameter.chunk_types(),
            vec![
                SctpChunkType::new(SCTP_CHUNK_TYPE_DATA),
                SctpChunkType::new(SCTP_CHUNK_TYPE_COOKIE_ECHO),
                SctpChunkType::new(SCTP_CHUNK_TYPE_INIT),
                SctpChunkType::new(SCTP_CHUNK_TYPE_AUTH),
                SctpChunkType::new(0xfe),
            ]
        );
        assert_eq!(
            parameter.chunk_type_values(),
            vec![
                SCTP_CHUNK_TYPE_DATA,
                SCTP_CHUNK_TYPE_COOKIE_ECHO,
                SCTP_CHUNK_TYPE_INIT,
                SCTP_CHUNK_TYPE_AUTH,
                0xfe,
            ]
        );
        assert_eq!(parameter.padding(), &[0x00, 0x00, 0x00]);
        parameter.validate_max_length()?;
        assert!(parameter.requires_authentication_for_data());
        assert!(parameter.requires_authentication_for_cookie_echo());
        assert!(parameter.requires_authentication_for_chunk_type(0xfe));
        assert!(!parameter.requires_authentication_for_chunk_type(SCTP_CHUNK_TYPE_INIT));
        assert!(!parameter.requires_authentication_for_chunk_type(SCTP_CHUNK_TYPE_AUTH));

        let replaced =
            parameter.with_chunk_types([SctpChunkType::new(SCTP_CHUNK_TYPE_FORWARD_TSN)]);
        assert_eq!(replaced.value(), &[SCTP_CHUNK_TYPE_FORWARD_TSN]);
        assert!(replaced.requires_authentication_for_chunk_type(SCTP_CHUNK_TYPE_FORWARD_TSN));

        let too_long =
            SctpChunkListParameter::new(vec![0u8; SCTP_AUTH_CHUNK_LIST_MAX_VALUE_LEN + 1]);
        assert_eq!(
            too_long.validate_max_length().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_CHUNK_LIST_PARAMETER_CONTEXT,
                "parameter length must not exceed 260 bytes",
            )
        );

        let enum_parameter = SctpParameter::from(replaced);
        assert!(matches!(enum_parameter, SctpParameter::ChunkList(_)));

        Ok(())
    }

    #[test]
    fn sctp_auth_parameters_requested_hmac_algorithm_labels_and_preserves_raw_ids() -> Result<()> {
        let parameter = SctpRequestedHmacAlgorithmParameter::from_hmac_identifiers([
            SctpHmacIdentifier::Sha1,
            SctpHmacIdentifier::Sha256,
            SctpHmacIdentifier::ReservedTwo,
            SctpHmacIdentifier::Unknown(0xbeef),
        ])
        .with_padding([0xaa, 0xbb]);

        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_REQUESTED_HMAC_ALGORITHM
        );
        assert_eq!(
            parameter.value(),
            &[0x00, 0x01, 0x00, 0x03, 0x00, 0x02, 0xbe, 0xef]
        );
        assert_eq!(
            parameter.hmac_identifiers()?,
            vec![
                SctpHmacIdentifier::Sha1,
                SctpHmacIdentifier::Sha256,
                SctpHmacIdentifier::ReservedTwo,
                SctpHmacIdentifier::Unknown(0xbeef),
            ]
        );
        assert_eq!(
            parameter.hmac_identifier_values()?,
            vec![
                SCTP_HMAC_IDENTIFIER_SHA1,
                SCTP_HMAC_IDENTIFIER_SHA256,
                SCTP_HMAC_IDENTIFIER_RESERVED_TWO,
                0xbeef,
            ]
        );
        assert_eq!(
            parameter.preferred_hmac_identifier()?,
            Some(SctpHmacIdentifier::Sha1)
        );
        assert!(parameter.requests_sha1()?);
        assert!(parameter.requests_sha256()?);
        assert!(parameter.requests_hmac_identifier(0xbeef)?);
        assert_eq!(parameter.padding(), &[0xaa, 0xbb]);
        parameter.validate_includes_sha1()?;
        assert_eq!(SctpHmacIdentifier::from_u16(0).as_u16(), 0);
        assert_eq!(
            SctpHmacIdentifier::from_u16(SCTP_HMAC_IDENTIFIER_SHA256),
            SctpHmacIdentifier::Sha256
        );

        let replaced = parameter.with_hmac_identifier_values([SCTP_HMAC_IDENTIFIER_SHA256, 0x1234]);
        assert_eq!(replaced.value(), &[0x00, 0x03, 0x12, 0x34]);
        assert_eq!(
            replaced.hmac_identifiers()?,
            vec![
                SctpHmacIdentifier::Sha256,
                SctpHmacIdentifier::Unknown(0x1234)
            ]
        );
        assert!(!replaced.requests_sha1()?);
        assert_eq!(
            replaced.validate_includes_sha1().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_REQUESTED_HMAC_ALGORITHM_PARAMETER_CONTEXT,
                "HMAC identifier list must include SHA-1",
            )
        );

        let odd = SctpRequestedHmacAlgorithmParameter::new([0x00, 0x01, 0x00]);
        assert_eq!(
            odd.hmac_identifiers().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_REQUESTED_HMAC_ALGORITHM_PARAMETER_CONTEXT,
                "HMAC identifier list must contain complete 16-bit values",
            )
        );
        assert_eq!(odd.value(), &[0x00, 0x01, 0x00]);

        let enum_parameter = SctpParameter::from(replaced);
        assert!(matches!(
            enum_parameter,
            SctpParameter::RequestedHmacAlgorithm(_)
        ));

        Ok(())
    }

    #[test]
    fn sctp_auth_parameters_shared_key_identifier_preserves_raw_field_values() {
        let empty = SctpSharedKeyIdentifier::new(SCTP_AUTH_EMPTY_SHARED_KEY_IDENTIFIER);
        assert_eq!(empty.raw(), 0);
        assert_eq!(empty.as_u16(), 0);
        assert!(empty.is_empty_shared_key_identifier());

        let preserved = SctpSharedKeyIdentifier::from_u16(0xbeef);
        assert_eq!(preserved.raw(), 0xbeef);
        assert_eq!(u16::from(preserved), 0xbeef);
        assert_eq!(SctpSharedKeyIdentifier::from(0xbeef), preserved);
        assert!(!preserved.is_empty_shared_key_identifier());
    }
}
