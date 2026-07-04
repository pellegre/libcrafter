//! SCTP chunk model.
//!
//! RFC 9260 section 3.2 defines the common chunk envelope: type, flags,
//! length, chunk-specific value bytes, and four-octet alignment padding. This
//! module keeps that envelope byte-preserving while later steps add
//! chunk-specific field models.

#![allow(dead_code)]

use std::fmt;

use crate::error::{CrafterError, Result};

use super::cause::{decode_causes, encode_causes, SctpErrorCause};
use super::constants::{
    sctp_ppid_name, sctp_ppid_status, SctpPpidStatus, SCTP_ALIGNMENT, SCTP_CHUNK_HEADER_LEN,
    SCTP_CHUNK_TYPE_ABORT, SCTP_CHUNK_TYPE_ASCONF, SCTP_CHUNK_TYPE_ASCONF_ACK,
    SCTP_CHUNK_TYPE_AUTH, SCTP_CHUNK_TYPE_COOKIE_ACK, SCTP_CHUNK_TYPE_COOKIE_ECHO,
    SCTP_CHUNK_TYPE_CWR, SCTP_CHUNK_TYPE_DATA, SCTP_CHUNK_TYPE_DTLS, SCTP_CHUNK_TYPE_ECNE,
    SCTP_CHUNK_TYPE_ERROR, SCTP_CHUNK_TYPE_FORWARD_TSN, SCTP_CHUNK_TYPE_HEARTBEAT,
    SCTP_CHUNK_TYPE_HEARTBEAT_ACK, SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_1,
    SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_2, SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_3,
    SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4, SCTP_CHUNK_TYPE_INIT, SCTP_CHUNK_TYPE_INIT_ACK,
    SCTP_CHUNK_TYPE_I_DATA, SCTP_CHUNK_TYPE_I_FORWARD_TSN, SCTP_CHUNK_TYPE_PAD,
    SCTP_CHUNK_TYPE_RE_CONFIG, SCTP_CHUNK_TYPE_SACK, SCTP_CHUNK_TYPE_SHUTDOWN,
    SCTP_CHUNK_TYPE_SHUTDOWN_ACK, SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE, SCTP_PARAMETER_HEADER_LEN,
    SCTP_PARAMETER_TYPE_HEARTBEAT_INFO,
};
use super::parameter::{
    decode_parameters, encode_parameter, encode_parameters, sctp_parameter_padded_len,
    SctpHeartbeatInfoParameter, SctpHmacIdentifier, SctpParameter, SctpSharedKeyIdentifier,
};

const SCTP_DATA_CHUNK_VALUE_HEADER_LEN: usize = 12;
const SCTP_DATA_CHUNK_TSN_OFFSET: usize = 0;
const SCTP_DATA_CHUNK_STREAM_ID_OFFSET: usize = 4;
const SCTP_DATA_CHUNK_STREAM_SEQUENCE_NUMBER_OFFSET: usize = 6;
const SCTP_DATA_CHUNK_PPID_OFFSET: usize = 8;
const SCTP_DATA_CHUNK_USER_DATA_OFFSET: usize = 12;
const SCTP_DATA_CHUNK_VALUE_CONTEXT: &str = "sctp.data_chunk.value";

const SCTP_IDATA_CHUNK_VALUE_HEADER_LEN: usize = 16;
const SCTP_IDATA_CHUNK_TSN_OFFSET: usize = 0;
const SCTP_IDATA_CHUNK_STREAM_ID_OFFSET: usize = 4;
const SCTP_IDATA_CHUNK_RESERVED_OFFSET: usize = 6;
const SCTP_IDATA_CHUNK_MESSAGE_ID_OFFSET: usize = 8;
const SCTP_IDATA_CHUNK_PPID_FSN_OFFSET: usize = 12;
const SCTP_IDATA_CHUNK_USER_DATA_OFFSET: usize = 16;
const SCTP_IDATA_CHUNK_VALUE_CONTEXT: &str = "sctp.idata_chunk.value";

const SCTP_INIT_CHUNK_VALUE_HEADER_LEN: usize = 16;
const SCTP_INIT_CHUNK_INITIATE_TAG_OFFSET: usize = 0;
const SCTP_INIT_CHUNK_A_RWND_OFFSET: usize = 4;
const SCTP_INIT_CHUNK_OUTBOUND_STREAMS_OFFSET: usize = 8;
const SCTP_INIT_CHUNK_INBOUND_STREAMS_OFFSET: usize = 10;
const SCTP_INIT_CHUNK_INITIAL_TSN_OFFSET: usize = 12;
const SCTP_INIT_CHUNK_PARAMETERS_OFFSET: usize = 16;
const SCTP_INIT_CHUNK_VALUE_CONTEXT: &str = "sctp.init_chunk.value";
const SCTP_INIT_ACK_CHUNK_VALUE_HEADER_LEN: usize = SCTP_INIT_CHUNK_VALUE_HEADER_LEN;
const SCTP_INIT_ACK_CHUNK_VALUE_CONTEXT: &str = "sctp.init_ack_chunk.value";

const SCTP_SACK_CHUNK_VALUE_HEADER_LEN: usize = 12;
const SCTP_SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET: usize = 0;
const SCTP_SACK_CHUNK_A_RWND_OFFSET: usize = 4;
const SCTP_SACK_CHUNK_GAP_ACK_BLOCK_COUNT_OFFSET: usize = 8;
const SCTP_SACK_CHUNK_DUPLICATE_TSN_COUNT_OFFSET: usize = 10;
const SCTP_SACK_CHUNK_VARIABLE_OFFSET: usize = 12;
const SCTP_SACK_GAP_ACK_BLOCK_LEN: usize = 4;
const SCTP_SACK_DUPLICATE_TSN_LEN: usize = 4;
const SCTP_SACK_CHUNK_VALUE_CONTEXT: &str = "sctp.sack_chunk.value";
const SCTP_SACK_CHUNK_GAP_ACK_BLOCK_COUNT_FIELD: &str = "sctp.sack_chunk.gap_ack_block_count";
const SCTP_SACK_CHUNK_DUPLICATE_TSN_COUNT_FIELD: &str = "sctp.sack_chunk.duplicate_tsn_count";

const SCTP_HEARTBEAT_CHUNK_VALUE_CONTEXT: &str = "sctp.heartbeat_chunk.value";
const SCTP_HEARTBEAT_INFO_PARAMETER_FIELD: &str = "sctp.heartbeat_chunk.heartbeat_info_parameter";
const SCTP_HEARTBEAT_ACK_CHUNK_VALUE_CONTEXT: &str = "sctp.heartbeat_ack_chunk.value";
const SCTP_HEARTBEAT_ACK_INFO_PARAMETER_FIELD: &str =
    "sctp.heartbeat_ack_chunk.heartbeat_info_parameter";

const SCTP_SHUTDOWN_CHUNK_VALUE_LEN: usize = 4;
const SCTP_SHUTDOWN_CHUNK_VALUE_CONTEXT: &str = "sctp.shutdown_chunk.value";
const SCTP_SHUTDOWN_ACK_CHUNK_VALUE_CONTEXT: &str = "sctp.shutdown_ack_chunk.value";
const SCTP_SHUTDOWN_COMPLETE_CHUNK_VALUE_CONTEXT: &str = "sctp.shutdown_complete_chunk.value";
const SCTP_COOKIE_ACK_CHUNK_VALUE_CONTEXT: &str = "sctp.cookie_ack_chunk.value";
const SCTP_ECNE_CHUNK_VALUE_LEN: usize = 4;
const SCTP_ECNE_CHUNK_VALUE_CONTEXT: &str = "sctp.ecne_chunk.value";
const SCTP_CWR_CHUNK_VALUE_LEN: usize = 4;
const SCTP_CWR_CHUNK_VALUE_CONTEXT: &str = "sctp.cwr_chunk.value";
const SCTP_FORWARD_TSN_CHUNK_VALUE_HEADER_LEN: usize = 4;
const SCTP_FORWARD_TSN_SKIPPED_STREAM_SEQUENCE_LEN: usize = 4;
const SCTP_FORWARD_TSN_CHUNK_VALUE_CONTEXT: &str = "sctp.forward_tsn_chunk.value";
const SCTP_IFORWARD_TSN_CHUNK_VALUE_HEADER_LEN: usize = 4;
const SCTP_IFORWARD_TSN_SKIPPED_STREAM_LEN: usize = 8;
const SCTP_IFORWARD_TSN_CHUNK_VALUE_CONTEXT: &str = "sctp.iforward_tsn_chunk.value";
const SCTP_AUTH_CHUNK_VALUE_HEADER_LEN: usize = 4;
const SCTP_AUTH_CHUNK_SHARED_KEY_IDENTIFIER_OFFSET: usize = 0;
const SCTP_AUTH_CHUNK_HMAC_IDENTIFIER_OFFSET: usize = 2;
const SCTP_AUTH_CHUNK_HMAC_OFFSET: usize = 4;
const SCTP_AUTH_CHUNK_VALUE_CONTEXT: &str = "sctp.auth_chunk.value";
const SCTP_ASCONF_CHUNK_VALUE_HEADER_LEN: usize = 4;
const SCTP_ASCONF_CHUNK_PARAMETERS_OFFSET: usize = 4;
const SCTP_ASCONF_CHUNK_VALUE_CONTEXT: &str = "sctp.asconf_chunk.value";
const SCTP_ASCONF_CHUNK_PARAMETERS_CONTEXT: &str = "sctp.asconf_chunk.parameters";
const SCTP_ASCONF_ACK_CHUNK_VALUE_HEADER_LEN: usize = 4;
const SCTP_ASCONF_ACK_CHUNK_PARAMETERS_OFFSET: usize = 4;
const SCTP_ASCONF_ACK_CHUNK_VALUE_CONTEXT: &str = "sctp.asconf_ack_chunk.value";
const SCTP_ASCONF_ACK_CHUNK_PARAMETERS_CONTEXT: &str = "sctp.asconf_ack_chunk.parameters";
const SCTP_RECONFIG_CHUNK_PARAMETERS_CONTEXT: &str = "sctp.reconfig_chunk.parameters";

/// SCTP DATA E (Ending Fragment) flag bit (RFC 9260 / IANA).
pub const SCTP_DATA_FLAG_END: u8 = 0x01;
/// SCTP DATA B (Beginning Fragment) flag bit (RFC 9260 / IANA).
pub const SCTP_DATA_FLAG_BEGIN: u8 = 0x02;
/// SCTP DATA U (Unordered) flag bit (RFC 9260 / IANA).
pub const SCTP_DATA_FLAG_UNORDERED: u8 = 0x04;
/// SCTP DATA I (Immediate SACK) flag bit (RFC 9260 / IANA).
pub const SCTP_DATA_FLAG_SACK_IMMEDIATELY: u8 = 0x08;
/// SCTP DATA E bit compatibility alias.
pub const SCTP_DATA_FLAG_E: u8 = SCTP_DATA_FLAG_END;
/// SCTP DATA B bit compatibility alias.
pub const SCTP_DATA_FLAG_B: u8 = SCTP_DATA_FLAG_BEGIN;
/// SCTP DATA U bit compatibility alias.
pub const SCTP_DATA_FLAG_U: u8 = SCTP_DATA_FLAG_UNORDERED;
/// SCTP DATA I bit compatibility alias.
pub const SCTP_DATA_FLAG_I: u8 = SCTP_DATA_FLAG_SACK_IMMEDIATELY;

/// SCTP I-DATA E (Ending Fragment) flag bit (RFC 8260 / IANA).
pub const SCTP_IDATA_FLAG_END: u8 = 0x01;
/// SCTP I-DATA B (Beginning Fragment) flag bit (RFC 8260 / IANA).
pub const SCTP_IDATA_FLAG_BEGIN: u8 = 0x02;
/// SCTP I-DATA U (Unordered) flag bit (RFC 8260 / IANA).
pub const SCTP_IDATA_FLAG_UNORDERED: u8 = 0x04;
/// SCTP I-DATA I (Immediate SACK) flag bit (RFC 8260 / IANA).
pub const SCTP_IDATA_FLAG_SACK_IMMEDIATELY: u8 = 0x08;
/// SCTP I-DATA E bit compatibility alias.
pub const SCTP_IDATA_FLAG_E: u8 = SCTP_IDATA_FLAG_END;
/// SCTP I-DATA B bit compatibility alias.
pub const SCTP_IDATA_FLAG_B: u8 = SCTP_IDATA_FLAG_BEGIN;
/// SCTP I-DATA U bit compatibility alias.
pub const SCTP_IDATA_FLAG_U: u8 = SCTP_IDATA_FLAG_UNORDERED;
/// SCTP I-DATA I bit compatibility alias.
pub const SCTP_IDATA_FLAG_I: u8 = SCTP_IDATA_FLAG_SACK_IMMEDIATELY;

/// SCTP ABORT T bit (RFC 9260 / IANA).
pub const SCTP_ABORT_FLAG_T: u8 = 0x01;
/// SCTP SHUTDOWN COMPLETE T bit (RFC 9260 / IANA).
pub const SCTP_SHUTDOWN_COMPLETE_FLAG_T: u8 = 0x01;
/// SCTP I-FORWARD-TSN skipped-stream U bit (RFC 8260).
pub const SCTP_IFORWARD_TSN_SKIPPED_STREAM_FLAG_UNORDERED: u16 = 0x0001;
/// SCTP I-FORWARD-TSN skipped-stream U bit compatibility alias.
pub const SCTP_IFORWARD_TSN_SKIPPED_STREAM_FLAG_U: u16 =
    SCTP_IFORWARD_TSN_SKIPPED_STREAM_FLAG_UNORDERED;

/// Registry classification for an SCTP chunk type codepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SctpChunkTypeStatus {
    /// Assigned by the current SCTP chunk-type registry.
    Assigned,
    /// Reserved by the current SCTP chunk-type registry.
    Reserved,
    /// Temporary or draft-backed registry row preserved as experimental metadata.
    Experimental,
    /// Unknown, future, or currently unassigned registry value.
    Unknown,
}

impl SctpChunkTypeStatus {
    /// Stable lowercase status label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::Reserved => "reserved",
            Self::Experimental => "experimental",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for SctpChunkTypeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One assigned SCTP chunk flag name for a specific chunk type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SctpChunkFlagName {
    mask: u8,
    name: &'static str,
    description: &'static str,
}

impl SctpChunkFlagName {
    /// Construct flag metadata from its one-bit mask, short name, and meaning.
    pub const fn new(mask: u8, name: &'static str, description: &'static str) -> Self {
        Self {
            mask,
            name,
            description,
        }
    }

    /// One-bit flag mask.
    pub const fn mask(self) -> u8 {
        self.mask
    }

    /// IANA/RFC short flag name.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Human-readable flag meaning.
    pub const fn description(self) -> &'static str {
        self.description
    }
}

/// Assigned DATA chunk flag names.
pub const SCTP_DATA_CHUNK_FLAG_NAMES: [SctpChunkFlagName; 4] = [
    SctpChunkFlagName::new(SCTP_DATA_FLAG_END, "E", "Ending Fragment"),
    SctpChunkFlagName::new(SCTP_DATA_FLAG_BEGIN, "B", "Beginning Fragment"),
    SctpChunkFlagName::new(SCTP_DATA_FLAG_UNORDERED, "U", "Unordered"),
    SctpChunkFlagName::new(SCTP_DATA_FLAG_SACK_IMMEDIATELY, "I", "Immediate SACK"),
];

/// Assigned I-DATA chunk flag names.
pub const SCTP_IDATA_CHUNK_FLAG_NAMES: [SctpChunkFlagName; 4] = [
    SctpChunkFlagName::new(SCTP_IDATA_FLAG_END, "E", "Ending Fragment"),
    SctpChunkFlagName::new(SCTP_IDATA_FLAG_BEGIN, "B", "Beginning Fragment"),
    SctpChunkFlagName::new(SCTP_IDATA_FLAG_UNORDERED, "U", "Unordered"),
    SctpChunkFlagName::new(SCTP_IDATA_FLAG_SACK_IMMEDIATELY, "I", "Immediate SACK"),
];

/// Assigned ABORT chunk flag names.
pub const SCTP_ABORT_CHUNK_FLAG_NAMES: [SctpChunkFlagName; 1] = [SctpChunkFlagName::new(
    SCTP_ABORT_FLAG_T,
    "T",
    "TCB Destroyed",
)];

/// Assigned SHUTDOWN COMPLETE chunk flag names.
pub const SCTP_SHUTDOWN_COMPLETE_CHUNK_FLAG_NAMES: [SctpChunkFlagName; 1] =
    [SctpChunkFlagName::new(
        SCTP_SHUTDOWN_COMPLETE_FLAG_T,
        "T",
        "TCB Destroyed",
    )];

const SCTP_NO_CHUNK_FLAG_NAMES: [SctpChunkFlagName; 0] = [];

/// Return the source-backed registry status for an SCTP chunk type.
pub const fn sctp_chunk_type_status(chunk_type: u8) -> SctpChunkTypeStatus {
    match chunk_type {
        SCTP_CHUNK_TYPE_DATA
        | SCTP_CHUNK_TYPE_INIT
        | SCTP_CHUNK_TYPE_INIT_ACK
        | SCTP_CHUNK_TYPE_SACK
        | SCTP_CHUNK_TYPE_HEARTBEAT
        | SCTP_CHUNK_TYPE_HEARTBEAT_ACK
        | SCTP_CHUNK_TYPE_ABORT
        | SCTP_CHUNK_TYPE_SHUTDOWN
        | SCTP_CHUNK_TYPE_SHUTDOWN_ACK
        | SCTP_CHUNK_TYPE_ERROR
        | SCTP_CHUNK_TYPE_COOKIE_ECHO
        | SCTP_CHUNK_TYPE_COOKIE_ACK
        | SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE
        | SCTP_CHUNK_TYPE_AUTH
        | SCTP_CHUNK_TYPE_I_DATA
        | SCTP_CHUNK_TYPE_ASCONF_ACK
        | SCTP_CHUNK_TYPE_RE_CONFIG
        | SCTP_CHUNK_TYPE_PAD
        | SCTP_CHUNK_TYPE_FORWARD_TSN
        | SCTP_CHUNK_TYPE_ASCONF
        | SCTP_CHUNK_TYPE_I_FORWARD_TSN => SctpChunkTypeStatus::Assigned,
        SCTP_CHUNK_TYPE_ECNE
        | SCTP_CHUNK_TYPE_CWR
        | SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_1
        | SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_2
        | SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_3
        | SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4 => SctpChunkTypeStatus::Reserved,
        SCTP_CHUNK_TYPE_DTLS => SctpChunkTypeStatus::Experimental,
        _ => SctpChunkTypeStatus::Unknown,
    }
}

/// Return true when the chunk type is currently assigned.
pub const fn sctp_chunk_type_is_assigned(chunk_type: u8) -> bool {
    matches!(
        sctp_chunk_type_status(chunk_type),
        SctpChunkTypeStatus::Assigned
    )
}

/// Return true when the chunk type is currently reserved.
pub const fn sctp_chunk_type_is_reserved(chunk_type: u8) -> bool {
    matches!(
        sctp_chunk_type_status(chunk_type),
        SctpChunkTypeStatus::Reserved
    )
}

/// Return true when the chunk type is temporary or draft-backed.
pub const fn sctp_chunk_type_is_experimental(chunk_type: u8) -> bool {
    matches!(
        sctp_chunk_type_status(chunk_type),
        SctpChunkTypeStatus::Experimental
    )
}

/// Return true when the chunk type is currently unknown or unassigned.
pub const fn sctp_chunk_type_is_unknown(chunk_type: u8) -> bool {
    matches!(
        sctp_chunk_type_status(chunk_type),
        SctpChunkTypeStatus::Unknown
    )
}

/// Return the source-backed registry label for a known SCTP chunk type.
pub const fn sctp_chunk_type_name(chunk_type: u8) -> Option<&'static str> {
    match chunk_type {
        SCTP_CHUNK_TYPE_DATA => Some("DATA"),
        SCTP_CHUNK_TYPE_INIT => Some("INIT"),
        SCTP_CHUNK_TYPE_INIT_ACK => Some("INIT ACK"),
        SCTP_CHUNK_TYPE_SACK => Some("SACK"),
        SCTP_CHUNK_TYPE_HEARTBEAT => Some("HEARTBEAT"),
        SCTP_CHUNK_TYPE_HEARTBEAT_ACK => Some("HEARTBEAT ACK"),
        SCTP_CHUNK_TYPE_ABORT => Some("ABORT"),
        SCTP_CHUNK_TYPE_SHUTDOWN => Some("SHUTDOWN"),
        SCTP_CHUNK_TYPE_SHUTDOWN_ACK => Some("SHUTDOWN ACK"),
        SCTP_CHUNK_TYPE_ERROR => Some("ERROR"),
        SCTP_CHUNK_TYPE_COOKIE_ECHO => Some("COOKIE ECHO"),
        SCTP_CHUNK_TYPE_COOKIE_ACK => Some("COOKIE ACK"),
        SCTP_CHUNK_TYPE_ECNE => Some("ECNE"),
        SCTP_CHUNK_TYPE_CWR => Some("CWR"),
        SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE => Some("SHUTDOWN COMPLETE"),
        SCTP_CHUNK_TYPE_AUTH => Some("AUTH"),
        SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_1
        | SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_2
        | SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_3
        | SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4 => {
            Some("Reserved for IETF-defined Chunk Extensions")
        }
        SCTP_CHUNK_TYPE_I_DATA => Some("I-DATA"),
        SCTP_CHUNK_TYPE_DTLS => Some("DTLS"),
        SCTP_CHUNK_TYPE_ASCONF_ACK => Some("ASCONF-ACK"),
        SCTP_CHUNK_TYPE_RE_CONFIG => Some("RE-CONFIG"),
        SCTP_CHUNK_TYPE_PAD => Some("PAD"),
        SCTP_CHUNK_TYPE_FORWARD_TSN => Some("FORWARD TSN"),
        SCTP_CHUNK_TYPE_ASCONF => Some("ASCONF"),
        SCTP_CHUNK_TYPE_I_FORWARD_TSN => Some("I-FORWARD-TSN"),
        _ => None,
    }
}

/// Return all assigned flag names for the given SCTP chunk type.
pub const fn sctp_chunk_flag_names(chunk_type: u8) -> &'static [SctpChunkFlagName] {
    match chunk_type {
        SCTP_CHUNK_TYPE_DATA => &SCTP_DATA_CHUNK_FLAG_NAMES,
        SCTP_CHUNK_TYPE_I_DATA => &SCTP_IDATA_CHUNK_FLAG_NAMES,
        SCTP_CHUNK_TYPE_ABORT => &SCTP_ABORT_CHUNK_FLAG_NAMES,
        SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE => &SCTP_SHUTDOWN_COMPLETE_CHUNK_FLAG_NAMES,
        _ => &SCTP_NO_CHUNK_FLAG_NAMES,
    }
}

/// Return the assigned name for one SCTP chunk flag mask, when defined.
pub const fn sctp_chunk_flag_name(chunk_type: u8, mask: u8) -> Option<&'static str> {
    match (chunk_type, mask) {
        (SCTP_CHUNK_TYPE_DATA, SCTP_DATA_FLAG_END)
        | (SCTP_CHUNK_TYPE_I_DATA, SCTP_IDATA_FLAG_END) => Some("E"),
        (SCTP_CHUNK_TYPE_DATA, SCTP_DATA_FLAG_BEGIN)
        | (SCTP_CHUNK_TYPE_I_DATA, SCTP_IDATA_FLAG_BEGIN) => Some("B"),
        (SCTP_CHUNK_TYPE_DATA, SCTP_DATA_FLAG_UNORDERED)
        | (SCTP_CHUNK_TYPE_I_DATA, SCTP_IDATA_FLAG_UNORDERED) => Some("U"),
        (SCTP_CHUNK_TYPE_DATA, SCTP_DATA_FLAG_SACK_IMMEDIATELY)
        | (SCTP_CHUNK_TYPE_I_DATA, SCTP_IDATA_FLAG_SACK_IMMEDIATELY) => Some("I"),
        (SCTP_CHUNK_TYPE_ABORT, SCTP_ABORT_FLAG_T)
        | (SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE, SCTP_SHUTDOWN_COMPLETE_FLAG_T) => Some("T"),
        _ => None,
    }
}

/// Return the mask of assigned flag bits for the given SCTP chunk type.
pub const fn sctp_chunk_assigned_flag_mask(chunk_type: u8) -> u8 {
    match chunk_type {
        SCTP_CHUNK_TYPE_DATA => {
            SCTP_DATA_FLAG_END
                | SCTP_DATA_FLAG_BEGIN
                | SCTP_DATA_FLAG_UNORDERED
                | SCTP_DATA_FLAG_SACK_IMMEDIATELY
        }
        SCTP_CHUNK_TYPE_I_DATA => {
            SCTP_IDATA_FLAG_END
                | SCTP_IDATA_FLAG_BEGIN
                | SCTP_IDATA_FLAG_UNORDERED
                | SCTP_IDATA_FLAG_SACK_IMMEDIATELY
        }
        SCTP_CHUNK_TYPE_ABORT => SCTP_ABORT_FLAG_T,
        SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE => SCTP_SHUTDOWN_COMPLETE_FLAG_T,
        _ => 0,
    }
}

/// Return the flag bits set outside the assigned flag mask for a chunk type.
pub const fn sctp_chunk_unassigned_flag_bits(chunk_type: u8, flags: u8) -> u8 {
    flags & !sctp_chunk_assigned_flag_mask(chunk_type)
}

/// Return assigned flag names whose bits are set in a raw flag byte.
pub fn sctp_chunk_active_flag_names(chunk_type: u8, flags: u8) -> Vec<&'static str> {
    sctp_chunk_flag_names(chunk_type)
        .iter()
        .filter_map(|flag| (flags & flag.mask() != 0).then_some(flag.name()))
        .collect()
}

/// Raw-preserving SCTP chunk type value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SctpChunkType(u8);

impl SctpChunkType {
    /// Preserve a raw 8-bit SCTP chunk type codepoint.
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Preserve a raw 8-bit SCTP chunk type codepoint.
    pub const fn from_u8(raw: u8) -> Self {
        Self::new(raw)
    }

    /// Return the preserved raw SCTP chunk type codepoint.
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Return the preserved raw SCTP chunk type codepoint.
    pub const fn as_u8(self) -> u8 {
        self.raw()
    }

    /// Return the source-backed registry status for this chunk type.
    pub const fn status(self) -> SctpChunkTypeStatus {
        sctp_chunk_type_status(self.raw())
    }

    /// Return true when this chunk type is currently assigned.
    pub const fn is_assigned(self) -> bool {
        sctp_chunk_type_is_assigned(self.raw())
    }

    /// Return true when this chunk type is currently reserved.
    pub const fn is_reserved(self) -> bool {
        sctp_chunk_type_is_reserved(self.raw())
    }

    /// Return true when this chunk type is temporary or draft-backed.
    pub const fn is_experimental(self) -> bool {
        sctp_chunk_type_is_experimental(self.raw())
    }

    /// Return true when this chunk type is currently unknown or unassigned.
    pub const fn is_unknown(self) -> bool {
        sctp_chunk_type_is_unknown(self.raw())
    }

    /// Return the source-backed registry label for this chunk type, when known.
    pub const fn name(self) -> Option<&'static str> {
        sctp_chunk_type_name(self.raw())
    }

    /// Return all assigned flag names for this chunk type.
    pub const fn flag_names(self) -> &'static [SctpChunkFlagName] {
        sctp_chunk_flag_names(self.raw())
    }

    /// Return the mask of assigned flag bits for this chunk type.
    pub const fn assigned_flag_mask(self) -> u8 {
        sctp_chunk_assigned_flag_mask(self.raw())
    }

    /// Return the flag bits set outside this chunk type's assigned flag mask.
    pub const fn unassigned_flag_bits(self, flags: u8) -> u8 {
        sctp_chunk_unassigned_flag_bits(self.raw(), flags)
    }

    /// Return assigned flag names whose bits are set in the supplied flag byte.
    pub fn active_flag_names(self, flags: u8) -> Vec<&'static str> {
        sctp_chunk_active_flag_names(self.raw(), flags)
    }
}

impl From<u8> for SctpChunkType {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<SctpChunkType> for u8 {
    fn from(value: SctpChunkType) -> Self {
        value.raw()
    }
}

/// One SCTP SACK Gap Ack Block, using offsets from the cumulative TSN ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SctpSackGapAckBlock {
    start: u16,
    end: u16,
}

impl SctpSackGapAckBlock {
    /// Construct a Gap Ack Block from the inclusive start and end offsets.
    pub const fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    /// Inclusive start offset from the cumulative TSN ACK.
    pub const fn start(&self) -> u16 {
        self.start
    }

    /// Inclusive end offset from the cumulative TSN ACK.
    pub const fn end(&self) -> u16 {
        self.end
    }

    /// Inclusive start offset from the cumulative TSN ACK.
    pub const fn start_offset(&self) -> u16 {
        self.start()
    }

    /// Inclusive end offset from the cumulative TSN ACK.
    pub const fn end_offset(&self) -> u16 {
        self.end()
    }
}

/// One skipped Stream Sequence entry carried by a FORWARD TSN chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SctpForwardTsnSkippedStreamSequence {
    stream_id: u16,
    stream_sequence_number: u16,
}

impl SctpForwardTsnSkippedStreamSequence {
    /// Construct a skipped Stream Sequence entry.
    pub const fn new(stream_id: u16, stream_sequence_number: u16) -> Self {
        Self {
            stream_id,
            stream_sequence_number,
        }
    }

    /// SCTP Stream Identifier for this skipped entry.
    pub const fn stream_id(&self) -> u16 {
        self.stream_id
    }

    /// SCTP Stream Identifier for this skipped entry.
    pub const fn stream_identifier(&self) -> u16 {
        self.stream_id()
    }

    /// SCTP Stream Sequence Number for this skipped entry.
    pub const fn stream_sequence_number(&self) -> u16 {
        self.stream_sequence_number
    }
}

/// One skipped stream entry carried by an I-FORWARD-TSN chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SctpIForwardTsnSkippedStream {
    stream_id: u16,
    flags: u16,
    message_identifier: u32,
}

impl SctpIForwardTsnSkippedStream {
    /// Construct an ordered skipped stream entry.
    pub const fn new(stream_id: u16, message_identifier: u32) -> Self {
        Self::from_parts(stream_id, 0, message_identifier)
    }

    /// Construct an unordered skipped stream entry.
    pub const fn unordered(stream_id: u16, message_identifier: u32) -> Self {
        Self::from_parts(
            stream_id,
            SCTP_IFORWARD_TSN_SKIPPED_STREAM_FLAG_UNORDERED,
            message_identifier,
        )
    }

    /// Construct a skipped stream entry with raw reserved/U bits.
    pub const fn from_parts(stream_id: u16, flags: u16, message_identifier: u32) -> Self {
        Self {
            stream_id,
            flags,
            message_identifier,
        }
    }

    /// SCTP Stream Identifier for this skipped entry.
    pub const fn stream_id(&self) -> u16 {
        self.stream_id
    }

    /// SCTP Stream Identifier for this skipped entry.
    pub const fn stream_identifier(&self) -> u16 {
        self.stream_id()
    }

    /// Raw reserved/U-bit field.
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    /// Whether the U bit is set for unordered Message Identifier interpretation.
    pub const fn is_u_bit_set(&self) -> bool {
        self.flags & SCTP_IFORWARD_TSN_SKIPPED_STREAM_FLAG_UNORDERED != 0
    }

    /// Whether the U bit is set for unordered Message Identifier interpretation.
    pub const fn is_unordered(&self) -> bool {
        self.is_u_bit_set()
    }

    /// Largest skipped Message Identifier for this stream and ordering class.
    pub const fn message_identifier(&self) -> u32 {
        self.message_identifier
    }

    /// Largest skipped Message Identifier for this stream and ordering class.
    pub const fn message_id(&self) -> u32 {
        self.message_identifier()
    }
}

/// Return the SCTP chunk padding length implied by a declared chunk length.
///
/// RFC 9260 section 3.2 keeps chunk padding outside the declared Length field
/// and aligns each chunk to a four-octet boundary.
pub const fn sctp_chunk_padding_len(declared_length: usize) -> usize {
    (SCTP_ALIGNMENT - (declared_length % SCTP_ALIGNMENT)) % SCTP_ALIGNMENT
}

/// Return a declared SCTP chunk length rounded up to the next chunk boundary.
pub const fn sctp_chunk_padded_len(declared_length: usize) -> usize {
    declared_length + sctp_chunk_padding_len(declared_length)
}

/// Decode a byte sequence of SCTP chunks into raw-preserving chunk models.
pub fn decode_chunks(bytes: impl AsRef<[u8]>) -> Result<Vec<SctpChunk>> {
    let bytes = bytes.as_ref();
    let mut chunks = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() {
        let available = bytes.len() - offset;
        if available < SCTP_CHUNK_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "sctp.chunk.header",
                SCTP_CHUNK_HEADER_LEN,
                available,
            ));
        }

        let chunk_type = bytes[offset];
        let flags = bytes[offset + 1];
        let declared_length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
        let declared_length_usize = usize::from(declared_length);
        if declared_length_usize < SCTP_CHUNK_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "sctp.chunk.length",
                "declared length must be at least 4 bytes",
            ));
        }

        let padded_length = sctp_chunk_padded_len(declared_length_usize);
        if padded_length > available {
            return Err(CrafterError::buffer_too_short(
                "sctp.chunk",
                padded_length,
                available,
            ));
        }

        let value_start = offset + SCTP_CHUNK_HEADER_LEN;
        let value_end = offset + declared_length_usize;
        let padding_end = offset + padded_length;
        let chunk = SctpChunk::from_preserved_parts(
            chunk_type,
            flags,
            declared_length,
            bytes[value_start..value_end].to_vec(),
            bytes[value_end..padding_end].to_vec(),
        );
        validate_decoded_chunk(&chunk)?;
        chunks.push(chunk);
        offset += padded_length;
    }

    Ok(chunks)
}

fn validate_decoded_chunk(chunk: &SctpChunk) -> Result<()> {
    match chunk {
        SctpChunk::Data(data) => validate_sctp_data_value_len(data.value())?,
        SctpChunk::Init(init) => validate_sctp_init_value_len(init.value())?,
        SctpChunk::InitAck(init_ack) => validate_sctp_init_ack_value_len(init_ack.value())?,
        SctpChunk::Sack(sack) => validate_sctp_sack_value_len(sack.value())?,
        SctpChunk::Heartbeat(heartbeat) => validate_sctp_heartbeat_value(heartbeat.value())?,
        SctpChunk::HeartbeatAck(heartbeat_ack) => {
            validate_sctp_heartbeat_ack_value(heartbeat_ack.value())?
        }
        SctpChunk::Abort(abort) => validate_sctp_abort_value(abort.value())?,
        SctpChunk::Shutdown(shutdown) => validate_sctp_shutdown_value_len(shutdown.value())?,
        SctpChunk::ShutdownAck(shutdown_ack) => {
            validate_sctp_shutdown_ack_value(shutdown_ack.value())?
        }
        SctpChunk::Error(error) => validate_sctp_error_value(error.value())?,
        SctpChunk::CookieAck(cookie_ack) => validate_sctp_cookie_ack_value(cookie_ack.value())?,
        SctpChunk::Ecne(ecne) => validate_sctp_ecne_value_len(ecne.value())?,
        SctpChunk::Cwr(cwr) => validate_sctp_cwr_value_len(cwr.value())?,
        SctpChunk::ForwardTsn(forward_tsn) => {
            validate_sctp_forward_tsn_value_len(forward_tsn.value())?
        }
        SctpChunk::IForwardTsn(iforward_tsn) => {
            validate_sctp_iforward_tsn_value_len(iforward_tsn.value())?
        }
        SctpChunk::Auth(auth) => validate_sctp_auth_value_len(auth.value())?,
        SctpChunk::AsconfAck(asconf_ack) => validate_sctp_asconf_ack_value(asconf_ack.value())?,
        SctpChunk::Asconf(asconf) => validate_sctp_asconf_value(asconf.value())?,
        SctpChunk::ReConfig(reconfig) => validate_sctp_reconfig_value(reconfig.value())?,
        SctpChunk::ShutdownComplete(shutdown_complete) => {
            validate_sctp_shutdown_complete_value(shutdown_complete.value())?
        }
        SctpChunk::IData(data) => validate_sctp_idata_value_len(data.value())?,
        _ => {}
    }

    Ok(())
}

fn validate_sctp_data_value_len(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_DATA_CHUNK_VALUE_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_DATA_CHUNK_VALUE_CONTEXT,
            SCTP_DATA_CHUNK_VALUE_HEADER_LEN,
            value.len(),
        ));
    }

    Ok(())
}

fn validate_sctp_idata_value_len(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_IDATA_CHUNK_VALUE_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_IDATA_CHUNK_VALUE_CONTEXT,
            SCTP_IDATA_CHUNK_VALUE_HEADER_LEN,
            value.len(),
        ));
    }

    Ok(())
}

fn validate_sctp_init_value_len(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_INIT_CHUNK_VALUE_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_INIT_CHUNK_VALUE_CONTEXT,
            SCTP_INIT_CHUNK_VALUE_HEADER_LEN,
            value.len(),
        ));
    }

    Ok(())
}

fn validate_sctp_init_ack_value_len(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_INIT_ACK_CHUNK_VALUE_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_INIT_ACK_CHUNK_VALUE_CONTEXT,
            SCTP_INIT_ACK_CHUNK_VALUE_HEADER_LEN,
            value.len(),
        ));
    }

    Ok(())
}

fn validate_sctp_sack_value_len(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_SACK_CHUNK_VALUE_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_SACK_CHUNK_VALUE_CONTEXT,
            SCTP_SACK_CHUNK_VALUE_HEADER_LEN,
            value.len(),
        ));
    }

    let gap_ack_block_count = usize::from(u16::from_be_bytes([
        value[SCTP_SACK_CHUNK_GAP_ACK_BLOCK_COUNT_OFFSET],
        value[SCTP_SACK_CHUNK_GAP_ACK_BLOCK_COUNT_OFFSET + 1],
    ]));
    let duplicate_tsn_count = usize::from(u16::from_be_bytes([
        value[SCTP_SACK_CHUNK_DUPLICATE_TSN_COUNT_OFFSET],
        value[SCTP_SACK_CHUNK_DUPLICATE_TSN_COUNT_OFFSET + 1],
    ]));
    let gap_ack_block_bytes = gap_ack_block_count
        .checked_mul(SCTP_SACK_GAP_ACK_BLOCK_LEN)
        .ok_or_else(|| {
            CrafterError::invalid_field_value(SCTP_SACK_CHUNK_VALUE_CONTEXT, "length overflow")
        })?;
    let duplicate_tsn_bytes = duplicate_tsn_count
        .checked_mul(SCTP_SACK_DUPLICATE_TSN_LEN)
        .ok_or_else(|| {
            CrafterError::invalid_field_value(SCTP_SACK_CHUNK_VALUE_CONTEXT, "length overflow")
        })?;
    let required_len = SCTP_SACK_CHUNK_VALUE_HEADER_LEN
        .checked_add(gap_ack_block_bytes)
        .and_then(|len| len.checked_add(duplicate_tsn_bytes))
        .ok_or_else(|| {
            CrafterError::invalid_field_value(SCTP_SACK_CHUNK_VALUE_CONTEXT, "length overflow")
        })?;

    if value.len() < required_len {
        return Err(CrafterError::buffer_too_short(
            SCTP_SACK_CHUNK_VALUE_CONTEXT,
            required_len,
            value.len(),
        ));
    }

    if value.len() > required_len {
        return Err(CrafterError::invalid_field_value(
            SCTP_SACK_CHUNK_VALUE_CONTEXT,
            "value length must match gap ack block and duplicate TSN counts",
        ));
    }

    Ok(())
}

fn validate_sctp_heartbeat_value(value: &[u8]) -> Result<()> {
    validate_sctp_heartbeat_info_parameter_value(
        value,
        SCTP_HEARTBEAT_CHUNK_VALUE_CONTEXT,
        SCTP_HEARTBEAT_INFO_PARAMETER_FIELD,
        "HEARTBEAT chunk must contain exactly one Heartbeat Info parameter",
    )
}

fn validate_sctp_heartbeat_ack_value(value: &[u8]) -> Result<()> {
    validate_sctp_heartbeat_info_parameter_value(
        value,
        SCTP_HEARTBEAT_ACK_CHUNK_VALUE_CONTEXT,
        SCTP_HEARTBEAT_ACK_INFO_PARAMETER_FIELD,
        "HEARTBEAT ACK chunk must contain exactly one Heartbeat Info parameter",
    )
}

fn validate_sctp_heartbeat_info_parameter_value(
    value: &[u8],
    value_context: &'static str,
    parameter_field: &'static str,
    extra_bytes_reason: &'static str,
) -> Result<()> {
    if value.len() < SCTP_PARAMETER_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            value_context,
            SCTP_PARAMETER_HEADER_LEN,
            value.len(),
        ));
    }

    let parameter_type = u16::from_be_bytes([value[0], value[1]]);
    if parameter_type != SCTP_PARAMETER_TYPE_HEARTBEAT_INFO {
        return Err(CrafterError::invalid_field_value(
            parameter_field,
            "parameter type must be Heartbeat Info",
        ));
    }

    let declared_length = usize::from(u16::from_be_bytes([value[2], value[3]]));
    if declared_length < SCTP_PARAMETER_HEADER_LEN {
        return Err(CrafterError::invalid_field_value(
            parameter_field,
            "declared length must be at least 4 bytes",
        ));
    }

    let padded_length = sctp_parameter_padded_len(declared_length);
    if value.len() < padded_length {
        return Err(CrafterError::buffer_too_short(
            value_context,
            padded_length,
            value.len(),
        ));
    }

    if value.len() > padded_length {
        return Err(CrafterError::invalid_field_value(
            value_context,
            extra_bytes_reason,
        ));
    }

    Ok(())
}

fn validate_sctp_abort_value(value: &[u8]) -> Result<()> {
    decode_causes(value)?;
    Ok(())
}

fn validate_sctp_error_value(value: &[u8]) -> Result<()> {
    decode_causes(value)?;
    Ok(())
}

fn validate_sctp_shutdown_value_len(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_SHUTDOWN_CHUNK_VALUE_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_SHUTDOWN_CHUNK_VALUE_CONTEXT,
            SCTP_SHUTDOWN_CHUNK_VALUE_LEN,
            value.len(),
        ));
    }

    if value.len() > SCTP_SHUTDOWN_CHUNK_VALUE_LEN {
        return Err(CrafterError::invalid_field_value(
            SCTP_SHUTDOWN_CHUNK_VALUE_CONTEXT,
            "value length must be four bytes",
        ));
    }

    Ok(())
}

fn validate_sctp_shutdown_ack_value(value: &[u8]) -> Result<()> {
    if !value.is_empty() {
        return Err(CrafterError::invalid_field_value(
            SCTP_SHUTDOWN_ACK_CHUNK_VALUE_CONTEXT,
            "value must be empty",
        ));
    }

    Ok(())
}

fn validate_sctp_shutdown_complete_value(value: &[u8]) -> Result<()> {
    if !value.is_empty() {
        return Err(CrafterError::invalid_field_value(
            SCTP_SHUTDOWN_COMPLETE_CHUNK_VALUE_CONTEXT,
            "value must be empty",
        ));
    }

    Ok(())
}

fn validate_sctp_cookie_ack_value(value: &[u8]) -> Result<()> {
    if !value.is_empty() {
        return Err(CrafterError::invalid_field_value(
            SCTP_COOKIE_ACK_CHUNK_VALUE_CONTEXT,
            "value must be empty",
        ));
    }

    Ok(())
}

fn validate_sctp_ecne_value_len(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_ECNE_CHUNK_VALUE_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_ECNE_CHUNK_VALUE_CONTEXT,
            SCTP_ECNE_CHUNK_VALUE_LEN,
            value.len(),
        ));
    }

    if value.len() > SCTP_ECNE_CHUNK_VALUE_LEN {
        return Err(CrafterError::invalid_field_value(
            SCTP_ECNE_CHUNK_VALUE_CONTEXT,
            "value length must be four bytes",
        ));
    }

    Ok(())
}

fn validate_sctp_cwr_value_len(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_CWR_CHUNK_VALUE_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_CWR_CHUNK_VALUE_CONTEXT,
            SCTP_CWR_CHUNK_VALUE_LEN,
            value.len(),
        ));
    }

    if value.len() > SCTP_CWR_CHUNK_VALUE_LEN {
        return Err(CrafterError::invalid_field_value(
            SCTP_CWR_CHUNK_VALUE_CONTEXT,
            "value length must be four bytes",
        ));
    }

    Ok(())
}

fn validate_sctp_forward_tsn_value_len(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_FORWARD_TSN_CHUNK_VALUE_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_FORWARD_TSN_CHUNK_VALUE_CONTEXT,
            SCTP_FORWARD_TSN_CHUNK_VALUE_HEADER_LEN,
            value.len(),
        ));
    }

    let skipped_bytes = value.len() - SCTP_FORWARD_TSN_CHUNK_VALUE_HEADER_LEN;
    if skipped_bytes % SCTP_FORWARD_TSN_SKIPPED_STREAM_SEQUENCE_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            SCTP_FORWARD_TSN_CHUNK_VALUE_CONTEXT,
            "skipped stream sequence entries must be four bytes each",
        ));
    }

    Ok(())
}

fn validate_sctp_iforward_tsn_value_len(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_IFORWARD_TSN_CHUNK_VALUE_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_IFORWARD_TSN_CHUNK_VALUE_CONTEXT,
            SCTP_IFORWARD_TSN_CHUNK_VALUE_HEADER_LEN,
            value.len(),
        ));
    }

    let skipped_bytes = value.len() - SCTP_IFORWARD_TSN_CHUNK_VALUE_HEADER_LEN;
    if skipped_bytes % SCTP_IFORWARD_TSN_SKIPPED_STREAM_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            SCTP_IFORWARD_TSN_CHUNK_VALUE_CONTEXT,
            "skipped stream entries must be eight bytes each",
        ));
    }

    Ok(())
}

fn validate_sctp_auth_value_len(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_AUTH_CHUNK_VALUE_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_AUTH_CHUNK_VALUE_CONTEXT,
            SCTP_AUTH_CHUNK_VALUE_HEADER_LEN,
            value.len(),
        ));
    }

    Ok(())
}

fn validate_sctp_asconf_value(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_ASCONF_CHUNK_VALUE_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_ASCONF_CHUNK_VALUE_CONTEXT,
            SCTP_ASCONF_CHUNK_VALUE_HEADER_LEN,
            value.len(),
        ));
    }

    let parameter_bytes = &value[SCTP_ASCONF_CHUNK_PARAMETERS_OFFSET..];
    if parameter_bytes.len() < SCTP_PARAMETER_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_ASCONF_CHUNK_PARAMETERS_CONTEXT,
            SCTP_PARAMETER_HEADER_LEN,
            parameter_bytes.len(),
        ));
    }

    decode_parameters(parameter_bytes)?;
    Ok(())
}

fn validate_sctp_asconf_ack_value(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_ASCONF_ACK_CHUNK_VALUE_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_ASCONF_ACK_CHUNK_VALUE_CONTEXT,
            SCTP_ASCONF_ACK_CHUNK_VALUE_HEADER_LEN,
            value.len(),
        ));
    }

    let parameter_bytes = &value[SCTP_ASCONF_ACK_CHUNK_PARAMETERS_OFFSET..];
    if parameter_bytes.is_empty() {
        return Ok(());
    }

    if parameter_bytes.len() < SCTP_PARAMETER_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_ASCONF_ACK_CHUNK_PARAMETERS_CONTEXT,
            SCTP_PARAMETER_HEADER_LEN,
            parameter_bytes.len(),
        ));
    }

    decode_parameters(parameter_bytes)?;
    Ok(())
}

fn validate_sctp_reconfig_value(value: &[u8]) -> Result<()> {
    if value.len() < SCTP_PARAMETER_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            SCTP_RECONFIG_CHUNK_PARAMETERS_CONTEXT,
            SCTP_PARAMETER_HEADER_LEN,
            value.len(),
        ));
    }

    decode_parameters(value)?;
    Ok(())
}

fn sctp_data_value(
    tsn: u32,
    stream_id: u16,
    stream_sequence_number: u16,
    payload_protocol_identifier: u32,
    user_data: impl Into<Vec<u8>>,
) -> Vec<u8> {
    let user_data = user_data.into();
    let mut value = Vec::with_capacity(SCTP_DATA_CHUNK_VALUE_HEADER_LEN + user_data.len());
    value.extend_from_slice(&tsn.to_be_bytes());
    value.extend_from_slice(&stream_id.to_be_bytes());
    value.extend_from_slice(&stream_sequence_number.to_be_bytes());
    value.extend_from_slice(&payload_protocol_identifier.to_be_bytes());
    value.extend_from_slice(&user_data);
    value
}

fn sctp_idata_value(
    tsn: u32,
    stream_id: u16,
    reserved: u16,
    message_identifier: u32,
    ppid_or_fsn: u32,
    user_data: impl Into<Vec<u8>>,
) -> Vec<u8> {
    let user_data = user_data.into();
    let mut value = Vec::with_capacity(SCTP_IDATA_CHUNK_VALUE_HEADER_LEN + user_data.len());
    value.extend_from_slice(&tsn.to_be_bytes());
    value.extend_from_slice(&stream_id.to_be_bytes());
    value.extend_from_slice(&reserved.to_be_bytes());
    value.extend_from_slice(&message_identifier.to_be_bytes());
    value.extend_from_slice(&ppid_or_fsn.to_be_bytes());
    value.extend_from_slice(&user_data);
    value
}

fn sctp_init_value(
    initiate_tag: u32,
    advertised_receiver_window_credit: u32,
    outbound_streams: u16,
    inbound_streams: u16,
    initial_tsn: u32,
    parameters: impl Into<Vec<u8>>,
) -> Vec<u8> {
    let parameters = parameters.into();
    let mut value = Vec::with_capacity(SCTP_INIT_CHUNK_VALUE_HEADER_LEN + parameters.len());
    value.extend_from_slice(&initiate_tag.to_be_bytes());
    value.extend_from_slice(&advertised_receiver_window_credit.to_be_bytes());
    value.extend_from_slice(&outbound_streams.to_be_bytes());
    value.extend_from_slice(&inbound_streams.to_be_bytes());
    value.extend_from_slice(&initial_tsn.to_be_bytes());
    value.extend_from_slice(&parameters);
    value
}

fn sctp_sack_value(
    cumulative_tsn_ack: u32,
    advertised_receiver_window_credit: u32,
    gap_ack_blocks: impl IntoIterator<Item = SctpSackGapAckBlock>,
    duplicate_tsns: impl IntoIterator<Item = u32>,
) -> Result<Vec<u8>> {
    let gap_ack_blocks: Vec<_> = gap_ack_blocks.into_iter().collect();
    let duplicate_tsns: Vec<_> = duplicate_tsns.into_iter().collect();
    let gap_ack_block_count = u16::try_from(gap_ack_blocks.len()).map_err(|_| {
        CrafterError::invalid_field_value(
            SCTP_SACK_CHUNK_GAP_ACK_BLOCK_COUNT_FIELD,
            "count must fit in two bytes",
        )
    })?;
    let duplicate_tsn_count = u16::try_from(duplicate_tsns.len()).map_err(|_| {
        CrafterError::invalid_field_value(
            SCTP_SACK_CHUNK_DUPLICATE_TSN_COUNT_FIELD,
            "count must fit in two bytes",
        )
    })?;
    let mut value = Vec::with_capacity(
        SCTP_SACK_CHUNK_VALUE_HEADER_LEN
            + gap_ack_blocks.len() * SCTP_SACK_GAP_ACK_BLOCK_LEN
            + duplicate_tsns.len() * SCTP_SACK_DUPLICATE_TSN_LEN,
    );

    value.extend_from_slice(&cumulative_tsn_ack.to_be_bytes());
    value.extend_from_slice(&advertised_receiver_window_credit.to_be_bytes());
    value.extend_from_slice(&gap_ack_block_count.to_be_bytes());
    value.extend_from_slice(&duplicate_tsn_count.to_be_bytes());
    for gap_ack_block in gap_ack_blocks {
        value.extend_from_slice(&gap_ack_block.start().to_be_bytes());
        value.extend_from_slice(&gap_ack_block.end().to_be_bytes());
    }
    for duplicate_tsn in duplicate_tsns {
        value.extend_from_slice(&duplicate_tsn.to_be_bytes());
    }

    Ok(value)
}

fn sctp_heartbeat_value(heartbeat_info: impl Into<Vec<u8>>) -> Result<Vec<u8>> {
    let parameter = SctpParameter::from(SctpHeartbeatInfoParameter::new(heartbeat_info));
    let mut value = Vec::new();
    encode_parameter(&parameter, &mut value)?;
    Ok(value)
}

fn sctp_shutdown_value(cumulative_tsn_ack: u32) -> Vec<u8> {
    cumulative_tsn_ack.to_be_bytes().to_vec()
}

fn sctp_ecne_value(lowest_tsn: u32) -> Vec<u8> {
    lowest_tsn.to_be_bytes().to_vec()
}

fn sctp_cwr_value(lowest_tsn: u32) -> Vec<u8> {
    lowest_tsn.to_be_bytes().to_vec()
}

fn sctp_auth_value(
    shared_key_identifier: SctpSharedKeyIdentifier,
    hmac_identifier: SctpHmacIdentifier,
    hmac: impl Into<Vec<u8>>,
) -> Vec<u8> {
    let hmac = hmac.into();
    let mut value = Vec::with_capacity(SCTP_AUTH_CHUNK_VALUE_HEADER_LEN + hmac.len());
    value.extend_from_slice(&shared_key_identifier.raw().to_be_bytes());
    value.extend_from_slice(&hmac_identifier.raw().to_be_bytes());
    value.extend_from_slice(&hmac);
    value
}

fn sctp_asconf_value(
    serial_number: u32,
    address_parameter: &SctpParameter,
    parameters: &[SctpParameter],
) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    value.extend_from_slice(&serial_number.to_be_bytes());
    encode_parameter(address_parameter, &mut value)?;
    encode_parameters(parameters, &mut value)?;
    Ok(value)
}

fn sctp_asconf_ack_value(serial_number: u32, parameters: &[SctpParameter]) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    value.extend_from_slice(&serial_number.to_be_bytes());
    encode_parameters(parameters, &mut value)?;
    Ok(value)
}

fn sctp_reconfig_value(parameters: &[SctpParameter]) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    encode_parameters(parameters, &mut value)?;
    validate_sctp_reconfig_value(&value)?;
    Ok(value)
}

fn sctp_forward_tsn_value(
    new_cumulative_tsn: u32,
    skipped_stream_sequences: &[SctpForwardTsnSkippedStreamSequence],
) -> Vec<u8> {
    let mut value = Vec::with_capacity(
        SCTP_FORWARD_TSN_CHUNK_VALUE_HEADER_LEN
            + skipped_stream_sequences.len() * SCTP_FORWARD_TSN_SKIPPED_STREAM_SEQUENCE_LEN,
    );
    value.extend_from_slice(&new_cumulative_tsn.to_be_bytes());
    for skipped in skipped_stream_sequences {
        value.extend_from_slice(&skipped.stream_id().to_be_bytes());
        value.extend_from_slice(&skipped.stream_sequence_number().to_be_bytes());
    }
    value
}

fn sctp_iforward_tsn_value(
    new_cumulative_tsn: u32,
    skipped_streams: &[SctpIForwardTsnSkippedStream],
) -> Vec<u8> {
    let mut value = Vec::with_capacity(
        SCTP_IFORWARD_TSN_CHUNK_VALUE_HEADER_LEN
            + skipped_streams.len() * SCTP_IFORWARD_TSN_SKIPPED_STREAM_LEN,
    );
    value.extend_from_slice(&new_cumulative_tsn.to_be_bytes());
    for skipped in skipped_streams {
        value.extend_from_slice(&skipped.stream_id().to_be_bytes());
        value.extend_from_slice(&skipped.flags().to_be_bytes());
        value.extend_from_slice(&skipped.message_identifier().to_be_bytes());
    }
    value
}

fn sctp_error_causes_value(error_causes: &[SctpErrorCause]) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    encode_causes(error_causes, &mut value)?;
    Ok(value)
}

/// Append one SCTP chunk envelope to `out`.
pub fn encode_chunk(chunk: &SctpChunk, out: &mut Vec<u8>) -> Result<()> {
    let declared_length = chunk.explicit_declared_length().map_or_else(
        || {
            let declared_length = SCTP_CHUNK_HEADER_LEN
                .checked_add(chunk.value_len())
                .ok_or_else(|| {
                    CrafterError::invalid_field_value("sctp.chunk.length", "length overflow")
                })?;
            u16::try_from(declared_length).map_err(|_| {
                CrafterError::invalid_field_value(
                    "sctp.chunk.length",
                    "length must fit in two bytes",
                )
            })
        },
        Ok,
    )?;

    out.push(chunk.chunk_type_value());
    out.push(chunk.flags());
    out.extend_from_slice(&declared_length.to_be_bytes());
    out.extend_from_slice(chunk.value());

    if chunk.padding().is_empty() {
        out.resize(
            out.len() + sctp_chunk_padding_len(usize::from(declared_length)),
            0,
        );
    } else {
        out.extend_from_slice(chunk.padding());
    }

    Ok(())
}

/// Append a sequence of SCTP chunk envelopes to `out`.
pub fn encode_chunks(chunks: &[SctpChunk], out: &mut Vec<u8>) -> Result<()> {
    for chunk in chunks {
        encode_chunk(chunk, out)?;
    }
    Ok(())
}

/// Byte-preserving storage for one SCTP chunk envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctpRawChunk {
    chunk_type: SctpChunkType,
    flags: u8,
    declared_length: Option<u16>,
    value: Vec<u8>,
    padding: Vec<u8>,
}

impl SctpRawChunk {
    /// Construct a chunk envelope with an auto-derived declared length.
    pub fn new(chunk_type: impl Into<SctpChunkType>, flags: u8, value: impl Into<Vec<u8>>) -> Self {
        Self {
            chunk_type: chunk_type.into(),
            flags,
            declared_length: None,
            value: value.into(),
            padding: Vec::new(),
        }
    }

    /// Construct a chunk envelope from observed or caller-preserved wire parts.
    pub fn from_raw_parts(
        chunk_type: impl Into<SctpChunkType>,
        flags: u8,
        value: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            padding: padding.into(),
            ..Self::new(chunk_type, flags, value)
        }
    }

    /// Construct a chunk envelope with an explicit declared length override.
    pub fn from_preserved_parts(
        chunk_type: impl Into<SctpChunkType>,
        flags: u8,
        declared_length: u16,
        value: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            chunk_type: chunk_type.into(),
            flags,
            declared_length: Some(declared_length),
            value: value.into(),
            padding: padding.into(),
        }
    }

    /// Replace the raw chunk type codepoint.
    pub fn with_chunk_type(mut self, chunk_type: impl Into<SctpChunkType>) -> Self {
        self.chunk_type = chunk_type.into();
        self
    }

    /// Replace the raw chunk flags.
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Preserve an explicit chunk length field value.
    pub fn with_declared_length(mut self, declared_length: u16) -> Self {
        self.declared_length = Some(declared_length);
        self
    }

    /// Compatibility alias for preserving an explicit chunk length field value.
    pub fn with_length(self, length: u16) -> Self {
        self.with_declared_length(length)
    }

    /// Return to auto-derived chunk length behavior.
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

    /// SCTP chunk type codepoint.
    pub const fn chunk_type(&self) -> SctpChunkType {
        self.chunk_type
    }

    /// Raw SCTP chunk type codepoint.
    pub const fn chunk_type_value(&self) -> u8 {
        self.chunk_type.raw()
    }

    /// Raw SCTP chunk flags.
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Source-backed registry status for this chunk type.
    pub const fn chunk_type_status(&self) -> SctpChunkTypeStatus {
        self.chunk_type.status()
    }

    /// Source-backed registry label for this chunk type, when known.
    pub const fn chunk_type_name(&self) -> Option<&'static str> {
        self.chunk_type.name()
    }

    /// All assigned flag names for this chunk type.
    pub const fn flag_names(&self) -> &'static [SctpChunkFlagName] {
        self.chunk_type.flag_names()
    }

    /// Assigned flag names whose bits are set in this chunk's flag byte.
    pub fn active_flag_names(&self) -> Vec<&'static str> {
        self.chunk_type.active_flag_names(self.flags)
    }

    /// Flag bits set outside this chunk type's assigned flag mask.
    pub const fn unassigned_flag_bits(&self) -> u8 {
        self.chunk_type.unassigned_flag_bits(self.flags)
    }

    /// Declared chunk length value, using the explicit value when present.
    pub fn declared_length(&self) -> usize {
        self.declared_length
            .map(usize::from)
            .unwrap_or_else(|| SCTP_CHUNK_HEADER_LEN + self.value.len())
    }

    /// Compatibility alias for the declared chunk length value.
    pub fn length(&self) -> usize {
        self.declared_length()
    }

    /// Explicit declared chunk length override, if one is preserved.
    pub const fn explicit_declared_length(&self) -> Option<u16> {
        self.declared_length
    }

    /// Compatibility alias for the explicit declared chunk length override.
    pub const fn explicit_length(&self) -> Option<u16> {
        self.explicit_declared_length()
    }

    /// Declared chunk value bytes, excluding padding.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Transmitted chunk padding bytes, excluded from semantic value bytes.
    pub fn padding(&self) -> &[u8] {
        &self.padding
    }

    /// Declared chunk value length, excluding padding.
    pub fn value_len(&self) -> usize {
        self.value.len()
    }

    /// Transmitted chunk padding length.
    pub fn padding_len(&self) -> usize {
        self.padding.len()
    }

    /// Protocol padding length implied by the declared chunk length.
    pub fn required_padding_len(&self) -> usize {
        sctp_chunk_padding_len(self.declared_length())
    }

    /// Padding length an encoder would emit: preserved bytes, or auto zero padding.
    pub fn encoded_padding_len(&self) -> usize {
        if self.padding.is_empty() {
            self.required_padding_len()
        } else {
            self.padding.len()
        }
    }

    /// Declared chunk length rounded up to the next four-octet boundary.
    pub fn padded_declared_len(&self) -> usize {
        sctp_chunk_padded_len(self.declared_length())
    }

    /// Number of bytes encoded for this envelope, including padding.
    pub fn encoded_len(&self) -> usize {
        SCTP_CHUNK_HEADER_LEN + self.value.len() + self.encoded_padding_len()
    }
}

macro_rules! define_sctp_typed_chunk_structs {
    ($($name:ident),+ $(,)?) => {
        $(
            /// Raw-envelope storage for a typed SCTP chunk variant.
            #[derive(Debug, Clone, PartialEq, Eq)]
            pub struct $name {
                raw: SctpRawChunk,
            }
        )+
    };
}

define_sctp_typed_chunk_structs!(
    SctpDataChunk,
    SctpInitChunk,
    SctpInitAckChunk,
    SctpSackChunk,
    SctpHeartbeatChunk,
    SctpHeartbeatAckChunk,
    SctpAbortChunk,
    SctpShutdownChunk,
    SctpShutdownAckChunk,
    SctpErrorChunk,
    SctpCookieEchoChunk,
    SctpCookieAckChunk,
    SctpEcneChunk,
    SctpCwrChunk,
    SctpShutdownCompleteChunk,
    SctpAuthChunk,
    SctpIDataChunk,
    SctpAsconfAckChunk,
    SctpReConfigChunk,
    SctpPadChunk,
    SctpForwardTsnChunk,
    SctpAsconfChunk,
    SctpIForwardTsnChunk,
);

/// Raw-envelope storage for an untyped SCTP chunk codepoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctpUnknownChunk {
    raw: SctpRawChunk,
}

impl SctpUnknownChunk {
    /// Construct an unknown chunk with an auto-derived declared length.
    pub fn new(chunk_type: u8, flags: u8, value: impl Into<Vec<u8>>) -> Self {
        Self {
            raw: SctpRawChunk::new(chunk_type, flags, value),
        }
    }

    /// Construct an unknown chunk from raw wire parts.
    pub fn from_raw_parts(
        chunk_type: u8,
        flags: u8,
        value: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            raw: SctpRawChunk::from_raw_parts(chunk_type, flags, value, padding),
        }
    }

    /// Construct an unknown chunk with an explicit declared length override.
    pub fn from_preserved_parts(
        chunk_type: u8,
        flags: u8,
        declared_length: u16,
        value: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            raw: SctpRawChunk::from_preserved_parts(
                chunk_type,
                flags,
                declared_length,
                value,
                padding,
            ),
        }
    }

    /// Replace the raw chunk flags.
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.raw = self.raw.with_flags(flags);
        self
    }

    /// Preserve an explicit chunk length field value.
    pub fn with_declared_length(mut self, declared_length: u16) -> Self {
        self.raw = self.raw.with_declared_length(declared_length);
        self
    }

    /// Compatibility alias for preserving an explicit chunk length field value.
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

    /// Borrow the preserved raw chunk envelope.
    pub fn raw_chunk(&self) -> &SctpRawChunk {
        &self.raw
    }

    /// SCTP chunk type codepoint.
    pub const fn chunk_type(&self) -> SctpChunkType {
        self.raw.chunk_type()
    }

    /// Raw SCTP chunk type codepoint.
    pub const fn chunk_type_value(&self) -> u8 {
        self.raw.chunk_type_value()
    }

    /// Raw SCTP chunk flags.
    pub const fn flags(&self) -> u8 {
        self.raw.flags()
    }

    /// Source-backed registry status for this chunk type.
    pub const fn chunk_type_status(&self) -> SctpChunkTypeStatus {
        self.raw.chunk_type_status()
    }

    /// Source-backed registry label for this chunk type, when known.
    pub const fn chunk_type_name(&self) -> Option<&'static str> {
        self.raw.chunk_type_name()
    }

    /// All assigned flag names for this chunk type.
    pub const fn flag_names(&self) -> &'static [SctpChunkFlagName] {
        self.raw.flag_names()
    }

    /// Assigned flag names whose bits are set in this chunk's flag byte.
    pub fn active_flag_names(&self) -> Vec<&'static str> {
        self.raw.active_flag_names()
    }

    /// Flag bits set outside this chunk type's assigned flag mask.
    pub const fn unassigned_flag_bits(&self) -> u8 {
        self.raw.unassigned_flag_bits()
    }

    /// Declared chunk length value, using the explicit value when present.
    pub fn declared_length(&self) -> usize {
        self.raw.declared_length()
    }

    /// Compatibility alias for the declared chunk length value.
    pub fn length(&self) -> usize {
        self.declared_length()
    }

    /// Explicit declared chunk length override, if one is preserved.
    pub const fn explicit_declared_length(&self) -> Option<u16> {
        self.raw.explicit_declared_length()
    }

    /// Compatibility alias for the explicit declared chunk length override.
    pub const fn explicit_length(&self) -> Option<u16> {
        self.explicit_declared_length()
    }

    /// Declared chunk value bytes, excluding padding.
    pub fn value(&self) -> &[u8] {
        self.raw.value()
    }

    /// Transmitted chunk padding bytes, excluded from semantic value bytes.
    pub fn padding(&self) -> &[u8] {
        self.raw.padding()
    }

    /// Declared chunk value length, excluding padding.
    pub fn value_len(&self) -> usize {
        self.raw.value_len()
    }

    /// Transmitted chunk padding length.
    pub fn padding_len(&self) -> usize {
        self.raw.padding_len()
    }

    /// Protocol padding length implied by the declared chunk length.
    pub fn required_padding_len(&self) -> usize {
        self.raw.required_padding_len()
    }

    /// Padding length an encoder would emit: preserved bytes, or auto zero padding.
    pub fn encoded_padding_len(&self) -> usize {
        self.raw.encoded_padding_len()
    }

    /// Declared chunk length rounded up to the next four-octet boundary.
    pub fn padded_declared_len(&self) -> usize {
        self.raw.padded_declared_len()
    }

    /// Number of bytes encoded for this envelope, including padding.
    pub fn encoded_len(&self) -> usize {
        self.raw.encoded_len()
    }
}

/// SCTP chunk with typed variants and raw-preserving fallback storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SctpChunk {
    /// DATA chunk.
    Data(SctpDataChunk),
    /// INIT chunk.
    Init(SctpInitChunk),
    /// INIT ACK chunk.
    InitAck(SctpInitAckChunk),
    /// SACK chunk.
    Sack(SctpSackChunk),
    /// HEARTBEAT chunk.
    Heartbeat(SctpHeartbeatChunk),
    /// HEARTBEAT ACK chunk.
    HeartbeatAck(SctpHeartbeatAckChunk),
    /// ABORT chunk.
    Abort(SctpAbortChunk),
    /// SHUTDOWN chunk.
    Shutdown(SctpShutdownChunk),
    /// SHUTDOWN ACK chunk.
    ShutdownAck(SctpShutdownAckChunk),
    /// ERROR chunk.
    Error(SctpErrorChunk),
    /// COOKIE ECHO chunk.
    CookieEcho(SctpCookieEchoChunk),
    /// COOKIE ACK chunk.
    CookieAck(SctpCookieAckChunk),
    /// ECNE chunk.
    Ecne(SctpEcneChunk),
    /// CWR chunk.
    Cwr(SctpCwrChunk),
    /// SHUTDOWN COMPLETE chunk.
    ShutdownComplete(SctpShutdownCompleteChunk),
    /// AUTH chunk.
    Auth(SctpAuthChunk),
    /// I-DATA chunk.
    IData(SctpIDataChunk),
    /// ASCONF ACK chunk.
    AsconfAck(SctpAsconfAckChunk),
    /// RE-CONFIG chunk.
    ReConfig(SctpReConfigChunk),
    /// PAD chunk.
    Pad(SctpPadChunk),
    /// FORWARD TSN chunk.
    ForwardTsn(SctpForwardTsnChunk),
    /// ASCONF chunk.
    Asconf(SctpAsconfChunk),
    /// I-FORWARD-TSN chunk.
    IForwardTsn(SctpIForwardTsnChunk),
    /// Unknown, reserved, temporary, private, obsolete, or future chunk.
    Unknown(SctpUnknownChunk),
}

macro_rules! impl_sctp_typed_chunk {
    ($name:ident, $variant:ident, $type_const:ident) => {
        impl $name {
            /// Construct the chunk with an auto-derived declared length.
            pub fn new(value: impl Into<Vec<u8>>) -> Self {
                Self {
                    raw: SctpRawChunk::new($type_const, 0, value),
                }
            }

            /// Construct the chunk from raw wire parts.
            pub fn from_raw_parts(
                flags: u8,
                value: impl Into<Vec<u8>>,
                padding: impl Into<Vec<u8>>,
            ) -> Self {
                Self {
                    raw: SctpRawChunk::from_raw_parts($type_const, flags, value, padding),
                }
            }

            /// Construct the chunk with an explicit declared length override.
            pub fn from_preserved_parts(
                flags: u8,
                declared_length: u16,
                value: impl Into<Vec<u8>>,
                padding: impl Into<Vec<u8>>,
            ) -> Self {
                Self {
                    raw: SctpRawChunk::from_preserved_parts(
                        $type_const,
                        flags,
                        declared_length,
                        value,
                        padding,
                    ),
                }
            }

            /// Replace the raw chunk flags.
            pub fn with_flags(mut self, flags: u8) -> Self {
                self.raw = self.raw.with_flags(flags);
                self
            }

            /// Preserve an explicit chunk length field value.
            pub fn with_declared_length(mut self, declared_length: u16) -> Self {
                self.raw = self.raw.with_declared_length(declared_length);
                self
            }

            /// Compatibility alias for preserving an explicit chunk length field value.
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

            /// Borrow the preserved raw chunk envelope.
            pub fn raw_chunk(&self) -> &SctpRawChunk {
                &self.raw
            }

            /// SCTP chunk type codepoint.
            pub const fn chunk_type(&self) -> SctpChunkType {
                self.raw.chunk_type()
            }

            /// Raw SCTP chunk type codepoint.
            pub const fn chunk_type_value(&self) -> u8 {
                self.raw.chunk_type_value()
            }

            /// Raw SCTP chunk flags.
            pub const fn flags(&self) -> u8 {
                self.raw.flags()
            }

            /// Source-backed registry status for this chunk type.
            pub const fn chunk_type_status(&self) -> SctpChunkTypeStatus {
                self.raw.chunk_type_status()
            }

            /// Source-backed registry label for this chunk type, when known.
            pub const fn chunk_type_name(&self) -> Option<&'static str> {
                self.raw.chunk_type_name()
            }

            /// All assigned flag names for this chunk type.
            pub const fn flag_names(&self) -> &'static [SctpChunkFlagName] {
                self.raw.flag_names()
            }

            /// Assigned flag names whose bits are set in this chunk's flag byte.
            pub fn active_flag_names(&self) -> Vec<&'static str> {
                self.raw.active_flag_names()
            }

            /// Flag bits set outside this chunk type's assigned flag mask.
            pub const fn unassigned_flag_bits(&self) -> u8 {
                self.raw.unassigned_flag_bits()
            }

            /// Declared chunk length value, using the explicit value when present.
            pub fn declared_length(&self) -> usize {
                self.raw.declared_length()
            }

            /// Compatibility alias for the declared chunk length value.
            pub fn length(&self) -> usize {
                self.declared_length()
            }

            /// Explicit declared chunk length override, if one is preserved.
            pub const fn explicit_declared_length(&self) -> Option<u16> {
                self.raw.explicit_declared_length()
            }

            /// Compatibility alias for the explicit declared chunk length override.
            pub const fn explicit_length(&self) -> Option<u16> {
                self.explicit_declared_length()
            }

            /// Declared chunk value bytes, excluding padding.
            pub fn value(&self) -> &[u8] {
                self.raw.value()
            }

            /// Transmitted chunk padding bytes, excluded from semantic value bytes.
            pub fn padding(&self) -> &[u8] {
                self.raw.padding()
            }

            /// Declared chunk value length, excluding padding.
            pub fn value_len(&self) -> usize {
                self.raw.value_len()
            }

            /// Transmitted chunk padding length.
            pub fn padding_len(&self) -> usize {
                self.raw.padding_len()
            }

            /// Protocol padding length implied by the declared chunk length.
            pub fn required_padding_len(&self) -> usize {
                self.raw.required_padding_len()
            }

            /// Padding length an encoder would emit: preserved bytes, or auto zero padding.
            pub fn encoded_padding_len(&self) -> usize {
                self.raw.encoded_padding_len()
            }

            /// Declared chunk length rounded up to the next four-octet boundary.
            pub fn padded_declared_len(&self) -> usize {
                self.raw.padded_declared_len()
            }

            /// Number of bytes encoded for this envelope, including padding.
            pub fn encoded_len(&self) -> usize {
                self.raw.encoded_len()
            }
        }

        impl From<$name> for SctpChunk {
            fn from(value: $name) -> Self {
                Self::$variant(value)
            }
        }
    };
}

impl_sctp_typed_chunk!(SctpDataChunk, Data, SCTP_CHUNK_TYPE_DATA);
impl_sctp_typed_chunk!(SctpInitChunk, Init, SCTP_CHUNK_TYPE_INIT);
impl_sctp_typed_chunk!(SctpInitAckChunk, InitAck, SCTP_CHUNK_TYPE_INIT_ACK);
impl_sctp_typed_chunk!(SctpSackChunk, Sack, SCTP_CHUNK_TYPE_SACK);
impl_sctp_typed_chunk!(SctpHeartbeatChunk, Heartbeat, SCTP_CHUNK_TYPE_HEARTBEAT);
impl_sctp_typed_chunk!(
    SctpHeartbeatAckChunk,
    HeartbeatAck,
    SCTP_CHUNK_TYPE_HEARTBEAT_ACK
);
impl_sctp_typed_chunk!(SctpAbortChunk, Abort, SCTP_CHUNK_TYPE_ABORT);
impl_sctp_typed_chunk!(SctpShutdownChunk, Shutdown, SCTP_CHUNK_TYPE_SHUTDOWN);
impl_sctp_typed_chunk!(
    SctpShutdownAckChunk,
    ShutdownAck,
    SCTP_CHUNK_TYPE_SHUTDOWN_ACK
);
impl_sctp_typed_chunk!(SctpErrorChunk, Error, SCTP_CHUNK_TYPE_ERROR);
impl_sctp_typed_chunk!(SctpCookieEchoChunk, CookieEcho, SCTP_CHUNK_TYPE_COOKIE_ECHO);
impl_sctp_typed_chunk!(SctpCookieAckChunk, CookieAck, SCTP_CHUNK_TYPE_COOKIE_ACK);
impl_sctp_typed_chunk!(SctpEcneChunk, Ecne, SCTP_CHUNK_TYPE_ECNE);
impl_sctp_typed_chunk!(SctpCwrChunk, Cwr, SCTP_CHUNK_TYPE_CWR);
impl_sctp_typed_chunk!(
    SctpShutdownCompleteChunk,
    ShutdownComplete,
    SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE
);
impl_sctp_typed_chunk!(SctpAuthChunk, Auth, SCTP_CHUNK_TYPE_AUTH);
impl_sctp_typed_chunk!(SctpIDataChunk, IData, SCTP_CHUNK_TYPE_I_DATA);
impl_sctp_typed_chunk!(SctpAsconfAckChunk, AsconfAck, SCTP_CHUNK_TYPE_ASCONF_ACK);
impl_sctp_typed_chunk!(SctpReConfigChunk, ReConfig, SCTP_CHUNK_TYPE_RE_CONFIG);
impl_sctp_typed_chunk!(SctpPadChunk, Pad, SCTP_CHUNK_TYPE_PAD);
impl_sctp_typed_chunk!(SctpForwardTsnChunk, ForwardTsn, SCTP_CHUNK_TYPE_FORWARD_TSN);
impl_sctp_typed_chunk!(SctpAsconfChunk, Asconf, SCTP_CHUNK_TYPE_ASCONF);
impl_sctp_typed_chunk!(
    SctpIForwardTsnChunk,
    IForwardTsn,
    SCTP_CHUNK_TYPE_I_FORWARD_TSN
);

impl SctpDataChunk {
    /// Construct a DATA chunk from RFC 9260 semantic fields with zero flags.
    pub fn from_data(
        tsn: u32,
        stream_id: u16,
        stream_sequence_number: u16,
        payload_protocol_identifier: u32,
        user_data: impl Into<Vec<u8>>,
    ) -> Self {
        Self::from_data_parts(
            0,
            tsn,
            stream_id,
            stream_sequence_number,
            payload_protocol_identifier,
            user_data,
        )
    }

    /// Construct a DATA chunk from RFC 9260 semantic fields and raw flags.
    pub fn from_data_parts(
        flags: u8,
        tsn: u32,
        stream_id: u16,
        stream_sequence_number: u16,
        payload_protocol_identifier: u32,
        user_data: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_DATA,
                flags,
                sctp_data_value(
                    tsn,
                    stream_id,
                    stream_sequence_number,
                    payload_protocol_identifier,
                    user_data,
                ),
            ),
        }
    }

    /// Replace the DATA semantic fields while preserving the raw envelope flags.
    pub fn with_data(
        mut self,
        tsn: u32,
        stream_id: u16,
        stream_sequence_number: u16,
        payload_protocol_identifier: u32,
        user_data: impl Into<Vec<u8>>,
    ) -> Self {
        self.raw = self.raw.with_value(sctp_data_value(
            tsn,
            stream_id,
            stream_sequence_number,
            payload_protocol_identifier,
            user_data,
        ));
        self
    }

    /// Set or clear one raw DATA chunk flag bit.
    ///
    /// This is the DATA-specific flag escape hatch: it touches only `flag` and
    /// preserves every other bit, including unassigned bits.
    pub fn flag(mut self, flag: u8, enabled: bool) -> Self {
        let mut flags = self.flags();
        if enabled {
            flags |= flag;
        } else {
            flags &= !flag;
        }
        self.raw = self.raw.with_flags(flags);
        self
    }

    /// Set the U (Unordered) DATA flag.
    pub fn unordered(self) -> Self {
        self.set_unordered(true)
    }

    /// Set or clear the U (Unordered) DATA flag.
    pub fn set_unordered(self, enabled: bool) -> Self {
        self.flag(SCTP_DATA_FLAG_UNORDERED, enabled)
    }

    /// Set the B (Beginning Fragment) DATA flag.
    pub fn begin(self) -> Self {
        self.set_begin(true)
    }

    /// Set or clear the B (Beginning Fragment) DATA flag.
    pub fn set_begin(self, enabled: bool) -> Self {
        self.flag(SCTP_DATA_FLAG_BEGIN, enabled)
    }

    /// Set the E (Ending Fragment) DATA flag.
    pub fn end(self) -> Self {
        self.set_end(true)
    }

    /// Set or clear the E (Ending Fragment) DATA flag.
    pub fn set_end(self, enabled: bool) -> Self {
        self.flag(SCTP_DATA_FLAG_END, enabled)
    }

    /// Mark this DATA chunk as carrying a complete, unfragmented user message.
    ///
    /// This sets B and E while preserving U, I, and any unrelated raw flag bits.
    pub fn complete_message(self) -> Self {
        self.set_begin(true).set_end(true)
    }

    /// Mark this DATA chunk as carrying a non-boundary fragmented message part.
    ///
    /// This clears B and E while preserving U, I, and any unrelated raw flag
    /// bits. Use [`SctpDataChunk::begin`] or [`SctpDataChunk::end`] after this
    /// helper to build first-fragment or last-fragment shapes.
    pub fn fragmented_message(self) -> Self {
        self.set_begin(false).set_end(false)
    }

    /// Set the I (Immediate SACK) DATA flag.
    pub fn sack_immediately(self) -> Self {
        self.set_sack_immediately(true)
    }

    /// Set or clear the I (Immediate SACK) DATA flag.
    pub fn set_sack_immediately(self, enabled: bool) -> Self {
        self.flag(SCTP_DATA_FLAG_SACK_IMMEDIATELY, enabled)
    }

    /// DATA Transmission Sequence Number.
    pub fn tsn(&self) -> Result<u32> {
        self.transmission_sequence_number()
    }

    /// DATA Transmission Sequence Number.
    pub fn transmission_sequence_number(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([
            value[SCTP_DATA_CHUNK_TSN_OFFSET],
            value[SCTP_DATA_CHUNK_TSN_OFFSET + 1],
            value[SCTP_DATA_CHUNK_TSN_OFFSET + 2],
            value[SCTP_DATA_CHUNK_TSN_OFFSET + 3],
        ]))
    }

    /// DATA Stream Identifier.
    pub fn stream_id(&self) -> Result<u16> {
        self.stream_identifier()
    }

    /// DATA Stream Identifier.
    pub fn stream_identifier(&self) -> Result<u16> {
        let value = self.semantic_value()?;
        Ok(u16::from_be_bytes([
            value[SCTP_DATA_CHUNK_STREAM_ID_OFFSET],
            value[SCTP_DATA_CHUNK_STREAM_ID_OFFSET + 1],
        ]))
    }

    /// DATA Stream Sequence Number.
    pub fn stream_sequence_number(&self) -> Result<u16> {
        let value = self.semantic_value()?;
        Ok(u16::from_be_bytes([
            value[SCTP_DATA_CHUNK_STREAM_SEQUENCE_NUMBER_OFFSET],
            value[SCTP_DATA_CHUNK_STREAM_SEQUENCE_NUMBER_OFFSET + 1],
        ]))
    }

    /// DATA Payload Protocol Identifier.
    pub fn ppid(&self) -> Result<u32> {
        self.payload_protocol_identifier()
    }

    /// DATA Payload Protocol Identifier.
    pub fn payload_protocol_identifier(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([
            value[SCTP_DATA_CHUNK_PPID_OFFSET],
            value[SCTP_DATA_CHUNK_PPID_OFFSET + 1],
            value[SCTP_DATA_CHUNK_PPID_OFFSET + 2],
            value[SCTP_DATA_CHUNK_PPID_OFFSET + 3],
        ]))
    }

    /// DATA Payload Protocol Identifier registry status.
    pub fn ppid_status(&self) -> Result<SctpPpidStatus> {
        self.payload_protocol_identifier_status()
    }

    /// DATA Payload Protocol Identifier registry status.
    pub fn payload_protocol_identifier_status(&self) -> Result<SctpPpidStatus> {
        Ok(sctp_ppid_status(self.payload_protocol_identifier()?))
    }

    /// DATA Payload Protocol Identifier registry label, when known.
    pub fn ppid_name(&self) -> Result<Option<&'static str>> {
        self.payload_protocol_identifier_name()
    }

    /// DATA Payload Protocol Identifier registry label, when known.
    pub fn payload_protocol_identifier_name(&self) -> Result<Option<&'static str>> {
        Ok(sctp_ppid_name(self.payload_protocol_identifier()?))
    }

    /// DATA User Data bytes, excluding chunk padding.
    pub fn user_data(&self) -> Result<&[u8]> {
        let value = self.semantic_value()?;
        Ok(&value[SCTP_DATA_CHUNK_USER_DATA_OFFSET..])
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_data_value_len(value)?;
        Ok(value)
    }
}

impl SctpInitChunk {
    /// Construct an INIT chunk from RFC 9260 semantic fields with zero flags and no parameters.
    pub fn from_init(
        initiate_tag: u32,
        advertised_receiver_window_credit: u32,
        outbound_streams: u16,
        inbound_streams: u16,
        initial_tsn: u32,
    ) -> Self {
        Self::from_init_with_parameters(
            initiate_tag,
            advertised_receiver_window_credit,
            outbound_streams,
            inbound_streams,
            initial_tsn,
            Vec::new(),
        )
    }

    /// Construct an INIT chunk from RFC 9260 semantic fields and preserved parameter bytes.
    ///
    /// Parameter bytes are the encoded SCTP parameter sequence that follows the
    /// fixed INIT fields. Later parameter-model steps parse those TLVs; this
    /// helper keeps them byte-preserving for construction and decode.
    pub fn from_init_with_parameters(
        initiate_tag: u32,
        advertised_receiver_window_credit: u32,
        outbound_streams: u16,
        inbound_streams: u16,
        initial_tsn: u32,
        parameters: impl Into<Vec<u8>>,
    ) -> Self {
        Self::from_init_parts(
            0,
            initiate_tag,
            advertised_receiver_window_credit,
            outbound_streams,
            inbound_streams,
            initial_tsn,
            parameters,
        )
    }

    /// Construct an INIT chunk from RFC 9260 semantic fields, raw flags, and parameter bytes.
    pub fn from_init_parts(
        flags: u8,
        initiate_tag: u32,
        advertised_receiver_window_credit: u32,
        outbound_streams: u16,
        inbound_streams: u16,
        initial_tsn: u32,
        parameters: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_INIT,
                flags,
                sctp_init_value(
                    initiate_tag,
                    advertised_receiver_window_credit,
                    outbound_streams,
                    inbound_streams,
                    initial_tsn,
                    parameters,
                ),
            ),
        }
    }

    /// Replace the INIT semantic fields while preserving the raw envelope flags.
    pub fn with_init(
        mut self,
        initiate_tag: u32,
        advertised_receiver_window_credit: u32,
        outbound_streams: u16,
        inbound_streams: u16,
        initial_tsn: u32,
        parameters: impl Into<Vec<u8>>,
    ) -> Self {
        self.raw = self.raw.with_value(sctp_init_value(
            initiate_tag,
            advertised_receiver_window_credit,
            outbound_streams,
            inbound_streams,
            initial_tsn,
            parameters,
        ));
        self
    }

    /// INIT Initiate Tag.
    pub fn initiate_tag(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([
            value[SCTP_INIT_CHUNK_INITIATE_TAG_OFFSET],
            value[SCTP_INIT_CHUNK_INITIATE_TAG_OFFSET + 1],
            value[SCTP_INIT_CHUNK_INITIATE_TAG_OFFSET + 2],
            value[SCTP_INIT_CHUNK_INITIATE_TAG_OFFSET + 3],
        ]))
    }

    /// INIT Advertised Receiver Window Credit (`a_rwnd`).
    pub fn advertised_receiver_window_credit(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([
            value[SCTP_INIT_CHUNK_A_RWND_OFFSET],
            value[SCTP_INIT_CHUNK_A_RWND_OFFSET + 1],
            value[SCTP_INIT_CHUNK_A_RWND_OFFSET + 2],
            value[SCTP_INIT_CHUNK_A_RWND_OFFSET + 3],
        ]))
    }

    /// INIT Advertised Receiver Window Credit (`a_rwnd`).
    pub fn a_rwnd(&self) -> Result<u32> {
        self.advertised_receiver_window_credit()
    }

    /// INIT Number of Outbound Streams.
    pub fn outbound_streams(&self) -> Result<u16> {
        self.number_of_outbound_streams()
    }

    /// INIT Number of Outbound Streams.
    pub fn number_of_outbound_streams(&self) -> Result<u16> {
        let value = self.semantic_value()?;
        Ok(u16::from_be_bytes([
            value[SCTP_INIT_CHUNK_OUTBOUND_STREAMS_OFFSET],
            value[SCTP_INIT_CHUNK_OUTBOUND_STREAMS_OFFSET + 1],
        ]))
    }

    /// INIT Number of Inbound Streams.
    pub fn inbound_streams(&self) -> Result<u16> {
        self.number_of_inbound_streams()
    }

    /// INIT Number of Inbound Streams.
    pub fn number_of_inbound_streams(&self) -> Result<u16> {
        let value = self.semantic_value()?;
        Ok(u16::from_be_bytes([
            value[SCTP_INIT_CHUNK_INBOUND_STREAMS_OFFSET],
            value[SCTP_INIT_CHUNK_INBOUND_STREAMS_OFFSET + 1],
        ]))
    }

    /// INIT Initial Transmission Sequence Number.
    pub fn initial_tsn(&self) -> Result<u32> {
        self.initial_transmission_sequence_number()
    }

    /// INIT Initial Transmission Sequence Number.
    pub fn initial_transmission_sequence_number(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([
            value[SCTP_INIT_CHUNK_INITIAL_TSN_OFFSET],
            value[SCTP_INIT_CHUNK_INITIAL_TSN_OFFSET + 1],
            value[SCTP_INIT_CHUNK_INITIAL_TSN_OFFSET + 2],
            value[SCTP_INIT_CHUNK_INITIAL_TSN_OFFSET + 3],
        ]))
    }

    /// Encoded INIT parameter bytes, excluding chunk padding.
    pub fn parameters(&self) -> Result<&[u8]> {
        self.parameter_bytes()
    }

    /// Encoded INIT parameter bytes, excluding chunk padding.
    pub fn parameter_bytes(&self) -> Result<&[u8]> {
        let value = self.semantic_value()?;
        Ok(&value[SCTP_INIT_CHUNK_PARAMETERS_OFFSET..])
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_init_value_len(value)?;
        Ok(value)
    }
}

impl SctpInitAckChunk {
    /// Construct an INIT ACK chunk from RFC 9260 semantic fields with zero flags and no parameters.
    pub fn from_init_ack(
        initiate_tag: u32,
        advertised_receiver_window_credit: u32,
        outbound_streams: u16,
        inbound_streams: u16,
        initial_tsn: u32,
    ) -> Self {
        Self::from_init_ack_with_parameters(
            initiate_tag,
            advertised_receiver_window_credit,
            outbound_streams,
            inbound_streams,
            initial_tsn,
            Vec::new(),
        )
    }

    /// Construct an INIT ACK chunk from RFC 9260 semantic fields and preserved parameter bytes.
    ///
    /// Parameter bytes are the encoded SCTP parameter sequence that follows the
    /// fixed INIT ACK fields. Later parameter-model steps parse those TLVs;
    /// this helper keeps them byte-preserving for construction and decode.
    pub fn from_init_ack_with_parameters(
        initiate_tag: u32,
        advertised_receiver_window_credit: u32,
        outbound_streams: u16,
        inbound_streams: u16,
        initial_tsn: u32,
        parameters: impl Into<Vec<u8>>,
    ) -> Self {
        Self::from_init_ack_parts(
            0,
            initiate_tag,
            advertised_receiver_window_credit,
            outbound_streams,
            inbound_streams,
            initial_tsn,
            parameters,
        )
    }

    /// Construct an INIT ACK chunk from RFC 9260 semantic fields, raw flags, and parameter bytes.
    pub fn from_init_ack_parts(
        flags: u8,
        initiate_tag: u32,
        advertised_receiver_window_credit: u32,
        outbound_streams: u16,
        inbound_streams: u16,
        initial_tsn: u32,
        parameters: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_INIT_ACK,
                flags,
                sctp_init_value(
                    initiate_tag,
                    advertised_receiver_window_credit,
                    outbound_streams,
                    inbound_streams,
                    initial_tsn,
                    parameters,
                ),
            ),
        }
    }

    /// Replace the INIT ACK semantic fields while preserving the raw envelope flags.
    pub fn with_init_ack(
        mut self,
        initiate_tag: u32,
        advertised_receiver_window_credit: u32,
        outbound_streams: u16,
        inbound_streams: u16,
        initial_tsn: u32,
        parameters: impl Into<Vec<u8>>,
    ) -> Self {
        self.raw = self.raw.with_value(sctp_init_value(
            initiate_tag,
            advertised_receiver_window_credit,
            outbound_streams,
            inbound_streams,
            initial_tsn,
            parameters,
        ));
        self
    }

    /// INIT ACK Initiate Tag.
    pub fn initiate_tag(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([
            value[SCTP_INIT_CHUNK_INITIATE_TAG_OFFSET],
            value[SCTP_INIT_CHUNK_INITIATE_TAG_OFFSET + 1],
            value[SCTP_INIT_CHUNK_INITIATE_TAG_OFFSET + 2],
            value[SCTP_INIT_CHUNK_INITIATE_TAG_OFFSET + 3],
        ]))
    }

    /// INIT ACK Advertised Receiver Window Credit (`a_rwnd`).
    pub fn advertised_receiver_window_credit(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([
            value[SCTP_INIT_CHUNK_A_RWND_OFFSET],
            value[SCTP_INIT_CHUNK_A_RWND_OFFSET + 1],
            value[SCTP_INIT_CHUNK_A_RWND_OFFSET + 2],
            value[SCTP_INIT_CHUNK_A_RWND_OFFSET + 3],
        ]))
    }

    /// INIT ACK Advertised Receiver Window Credit (`a_rwnd`).
    pub fn a_rwnd(&self) -> Result<u32> {
        self.advertised_receiver_window_credit()
    }

    /// INIT ACK Number of Outbound Streams.
    pub fn outbound_streams(&self) -> Result<u16> {
        self.number_of_outbound_streams()
    }

    /// INIT ACK Number of Outbound Streams.
    pub fn number_of_outbound_streams(&self) -> Result<u16> {
        let value = self.semantic_value()?;
        Ok(u16::from_be_bytes([
            value[SCTP_INIT_CHUNK_OUTBOUND_STREAMS_OFFSET],
            value[SCTP_INIT_CHUNK_OUTBOUND_STREAMS_OFFSET + 1],
        ]))
    }

    /// INIT ACK Number of Inbound Streams.
    pub fn inbound_streams(&self) -> Result<u16> {
        self.number_of_inbound_streams()
    }

    /// INIT ACK Number of Inbound Streams.
    pub fn number_of_inbound_streams(&self) -> Result<u16> {
        let value = self.semantic_value()?;
        Ok(u16::from_be_bytes([
            value[SCTP_INIT_CHUNK_INBOUND_STREAMS_OFFSET],
            value[SCTP_INIT_CHUNK_INBOUND_STREAMS_OFFSET + 1],
        ]))
    }

    /// INIT ACK Initial Transmission Sequence Number.
    pub fn initial_tsn(&self) -> Result<u32> {
        self.initial_transmission_sequence_number()
    }

    /// INIT ACK Initial Transmission Sequence Number.
    pub fn initial_transmission_sequence_number(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([
            value[SCTP_INIT_CHUNK_INITIAL_TSN_OFFSET],
            value[SCTP_INIT_CHUNK_INITIAL_TSN_OFFSET + 1],
            value[SCTP_INIT_CHUNK_INITIAL_TSN_OFFSET + 2],
            value[SCTP_INIT_CHUNK_INITIAL_TSN_OFFSET + 3],
        ]))
    }

    /// Encoded INIT ACK parameter bytes, excluding chunk padding.
    pub fn parameters(&self) -> Result<&[u8]> {
        self.parameter_bytes()
    }

    /// Encoded INIT ACK parameter bytes, excluding chunk padding.
    pub fn parameter_bytes(&self) -> Result<&[u8]> {
        let value = self.semantic_value()?;
        Ok(&value[SCTP_INIT_CHUNK_PARAMETERS_OFFSET..])
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_init_ack_value_len(value)?;
        Ok(value)
    }
}

impl SctpSackChunk {
    /// Construct a SACK chunk from RFC 9260 semantic fields with zero flags.
    pub fn try_from_sack(
        cumulative_tsn_ack: u32,
        advertised_receiver_window_credit: u32,
        gap_ack_blocks: impl IntoIterator<Item = SctpSackGapAckBlock>,
        duplicate_tsns: impl IntoIterator<Item = u32>,
    ) -> Result<Self> {
        Self::try_from_sack_parts(
            0,
            cumulative_tsn_ack,
            advertised_receiver_window_credit,
            gap_ack_blocks,
            duplicate_tsns,
        )
    }

    /// Construct a SACK chunk from RFC 9260 semantic fields and raw flags.
    pub fn try_from_sack_parts(
        flags: u8,
        cumulative_tsn_ack: u32,
        advertised_receiver_window_credit: u32,
        gap_ack_blocks: impl IntoIterator<Item = SctpSackGapAckBlock>,
        duplicate_tsns: impl IntoIterator<Item = u32>,
    ) -> Result<Self> {
        Ok(Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_SACK,
                flags,
                sctp_sack_value(
                    cumulative_tsn_ack,
                    advertised_receiver_window_credit,
                    gap_ack_blocks,
                    duplicate_tsns,
                )?,
            ),
        })
    }

    /// Replace the SACK semantic fields while preserving the raw envelope flags.
    pub fn try_with_sack(
        mut self,
        cumulative_tsn_ack: u32,
        advertised_receiver_window_credit: u32,
        gap_ack_blocks: impl IntoIterator<Item = SctpSackGapAckBlock>,
        duplicate_tsns: impl IntoIterator<Item = u32>,
    ) -> Result<Self> {
        self.raw = self.raw.with_value(sctp_sack_value(
            cumulative_tsn_ack,
            advertised_receiver_window_credit,
            gap_ack_blocks,
            duplicate_tsns,
        )?);
        Ok(self)
    }

    /// SACK Cumulative TSN Ack.
    pub fn cumulative_tsn_ack(&self) -> Result<u32> {
        self.cumulative_transmission_sequence_number_ack()
    }

    /// SACK Cumulative TSN Ack.
    pub fn cumulative_transmission_sequence_number_ack(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([
            value[SCTP_SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET],
            value[SCTP_SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET + 1],
            value[SCTP_SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET + 2],
            value[SCTP_SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET + 3],
        ]))
    }

    /// SACK Advertised Receiver Window Credit (`a_rwnd`).
    pub fn advertised_receiver_window_credit(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([
            value[SCTP_SACK_CHUNK_A_RWND_OFFSET],
            value[SCTP_SACK_CHUNK_A_RWND_OFFSET + 1],
            value[SCTP_SACK_CHUNK_A_RWND_OFFSET + 2],
            value[SCTP_SACK_CHUNK_A_RWND_OFFSET + 3],
        ]))
    }

    /// SACK Advertised Receiver Window Credit (`a_rwnd`).
    pub fn a_rwnd(&self) -> Result<u32> {
        self.advertised_receiver_window_credit()
    }

    /// Number of Gap Ack Blocks in the SACK.
    pub fn gap_ack_block_count(&self) -> Result<u16> {
        self.number_of_gap_ack_blocks()
    }

    /// Number of Gap Ack Blocks in the SACK.
    pub fn number_of_gap_ack_blocks(&self) -> Result<u16> {
        let value = self.semantic_value()?;
        Ok(u16::from_be_bytes([
            value[SCTP_SACK_CHUNK_GAP_ACK_BLOCK_COUNT_OFFSET],
            value[SCTP_SACK_CHUNK_GAP_ACK_BLOCK_COUNT_OFFSET + 1],
        ]))
    }

    /// Number of duplicate TSNs in the SACK.
    pub fn duplicate_tsn_count(&self) -> Result<u16> {
        self.number_of_duplicate_tsns()
    }

    /// Number of duplicate TSNs in the SACK.
    pub fn number_of_duplicate_tsns(&self) -> Result<u16> {
        let value = self.semantic_value()?;
        Ok(u16::from_be_bytes([
            value[SCTP_SACK_CHUNK_DUPLICATE_TSN_COUNT_OFFSET],
            value[SCTP_SACK_CHUNK_DUPLICATE_TSN_COUNT_OFFSET + 1],
        ]))
    }

    /// Decode SACK Gap Ack Blocks.
    pub fn gap_ack_blocks(&self) -> Result<Vec<SctpSackGapAckBlock>> {
        let value = self.semantic_value()?;
        let count = usize::from(self.number_of_gap_ack_blocks()?);
        let mut offset = SCTP_SACK_CHUNK_VARIABLE_OFFSET;
        let mut gap_ack_blocks = Vec::with_capacity(count);

        for _ in 0..count {
            let start = u16::from_be_bytes([value[offset], value[offset + 1]]);
            let end = u16::from_be_bytes([value[offset + 2], value[offset + 3]]);
            gap_ack_blocks.push(SctpSackGapAckBlock::new(start, end));
            offset += SCTP_SACK_GAP_ACK_BLOCK_LEN;
        }

        Ok(gap_ack_blocks)
    }

    /// Decode duplicate TSNs.
    pub fn duplicate_tsns(&self) -> Result<Vec<u32>> {
        let value = self.semantic_value()?;
        let gap_ack_block_count = usize::from(self.number_of_gap_ack_blocks()?);
        let duplicate_tsn_count = usize::from(self.number_of_duplicate_tsns()?);
        let mut offset =
            SCTP_SACK_CHUNK_VARIABLE_OFFSET + gap_ack_block_count * SCTP_SACK_GAP_ACK_BLOCK_LEN;
        let mut duplicate_tsns = Vec::with_capacity(duplicate_tsn_count);

        for _ in 0..duplicate_tsn_count {
            duplicate_tsns.push(u32::from_be_bytes([
                value[offset],
                value[offset + 1],
                value[offset + 2],
                value[offset + 3],
            ]));
            offset += SCTP_SACK_DUPLICATE_TSN_LEN;
        }

        Ok(duplicate_tsns)
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_sack_value_len(value)?;
        Ok(value)
    }
}

impl SctpHeartbeatChunk {
    /// Construct a HEARTBEAT chunk from encoded Heartbeat Info parameter bytes.
    pub fn from_heartbeat_info_parameter_bytes(parameter: impl Into<Vec<u8>>) -> Self {
        Self::new(parameter)
    }

    /// Replace the value with encoded Heartbeat Info parameter bytes.
    pub fn with_heartbeat_info_parameter_bytes(self, parameter: impl Into<Vec<u8>>) -> Self {
        self.with_value(parameter)
    }

    /// Construct a HEARTBEAT chunk from Heartbeat Info parameter contents with zero flags.
    pub fn try_from_heartbeat_info(heartbeat_info: impl Into<Vec<u8>>) -> Result<Self> {
        Self::try_from_heartbeat_info_parts(0, heartbeat_info)
    }

    /// Construct a HEARTBEAT chunk from Heartbeat Info parameter contents and raw flags.
    pub fn try_from_heartbeat_info_parts(
        flags: u8,
        heartbeat_info: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_HEARTBEAT,
                flags,
                sctp_heartbeat_value(heartbeat_info)?,
            ),
        })
    }

    /// Replace the Heartbeat Info parameter contents while preserving raw flags.
    pub fn try_with_heartbeat_info(mut self, heartbeat_info: impl Into<Vec<u8>>) -> Result<Self> {
        self.raw = self.raw.with_value(sctp_heartbeat_value(heartbeat_info)?);
        Ok(self)
    }

    /// Encoded Heartbeat Info parameter bytes, including parameter padding.
    pub fn heartbeat_info_parameter_bytes(&self) -> Result<&[u8]> {
        self.semantic_value()
    }

    /// Decode the Heartbeat Info parameter while preserving its padding bytes.
    pub fn heartbeat_info_parameter(&self) -> Result<SctpHeartbeatInfoParameter> {
        let value = self.semantic_value()?;
        let declared_length = u16::from_be_bytes([value[2], value[3]]);
        let declared_length_usize = usize::from(declared_length);
        let padded_length = sctp_parameter_padded_len(declared_length_usize);
        Ok(SctpHeartbeatInfoParameter::from_preserved_parts(
            declared_length,
            value[SCTP_PARAMETER_HEADER_LEN..declared_length_usize].to_vec(),
            value[declared_length_usize..padded_length].to_vec(),
        ))
    }

    /// Heartbeat Information bytes, excluding parameter header and padding.
    pub fn heartbeat_info(&self) -> Result<&[u8]> {
        let value = self.semantic_value()?;
        let declared_length = usize::from(u16::from_be_bytes([value[2], value[3]]));
        Ok(&value[SCTP_PARAMETER_HEADER_LEN..declared_length])
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_heartbeat_value(value)?;
        Ok(value)
    }
}

impl SctpHeartbeatAckChunk {
    /// Construct a HEARTBEAT ACK chunk from encoded Heartbeat Info parameter bytes.
    pub fn from_heartbeat_info_parameter_bytes(parameter: impl Into<Vec<u8>>) -> Self {
        Self::new(parameter)
    }

    /// Replace the value with encoded Heartbeat Info parameter bytes.
    pub fn with_heartbeat_info_parameter_bytes(self, parameter: impl Into<Vec<u8>>) -> Self {
        self.with_value(parameter)
    }

    /// Construct a HEARTBEAT ACK chunk from Heartbeat Info parameter contents with zero flags.
    pub fn try_from_heartbeat_info(heartbeat_info: impl Into<Vec<u8>>) -> Result<Self> {
        Self::try_from_heartbeat_info_parts(0, heartbeat_info)
    }

    /// Construct a HEARTBEAT ACK chunk from Heartbeat Info parameter contents and raw flags.
    pub fn try_from_heartbeat_info_parts(
        flags: u8,
        heartbeat_info: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_HEARTBEAT_ACK,
                flags,
                sctp_heartbeat_value(heartbeat_info)?,
            ),
        })
    }

    /// Replace the Heartbeat Info parameter contents while preserving raw flags.
    pub fn try_with_heartbeat_info(mut self, heartbeat_info: impl Into<Vec<u8>>) -> Result<Self> {
        self.raw = self.raw.with_value(sctp_heartbeat_value(heartbeat_info)?);
        Ok(self)
    }

    /// Encoded Heartbeat Info parameter bytes, including parameter padding.
    pub fn heartbeat_info_parameter_bytes(&self) -> Result<&[u8]> {
        self.semantic_value()
    }

    /// Decode the Heartbeat Info parameter while preserving its padding bytes.
    pub fn heartbeat_info_parameter(&self) -> Result<SctpHeartbeatInfoParameter> {
        let value = self.semantic_value()?;
        let declared_length = u16::from_be_bytes([value[2], value[3]]);
        let declared_length_usize = usize::from(declared_length);
        let padded_length = sctp_parameter_padded_len(declared_length_usize);
        Ok(SctpHeartbeatInfoParameter::from_preserved_parts(
            declared_length,
            value[SCTP_PARAMETER_HEADER_LEN..declared_length_usize].to_vec(),
            value[declared_length_usize..padded_length].to_vec(),
        ))
    }

    /// Heartbeat Information bytes, excluding parameter header and padding.
    pub fn heartbeat_info(&self) -> Result<&[u8]> {
        let value = self.semantic_value()?;
        let declared_length = usize::from(u16::from_be_bytes([value[2], value[3]]));
        Ok(&value[SCTP_PARAMETER_HEADER_LEN..declared_length])
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_heartbeat_ack_value(value)?;
        Ok(value)
    }
}

impl SctpAbortChunk {
    /// Construct an ABORT chunk from encoded error-cause bytes with zero flags.
    pub fn from_error_cause_bytes(error_causes: impl Into<Vec<u8>>) -> Self {
        Self::new(error_causes)
    }

    /// Replace the value with encoded error-cause bytes.
    pub fn with_error_cause_bytes(self, error_causes: impl Into<Vec<u8>>) -> Self {
        self.with_value(error_causes)
    }

    /// Construct an ABORT chunk from typed error causes with zero flags.
    pub fn try_from_error_causes(error_causes: &[SctpErrorCause]) -> Result<Self> {
        Self::try_from_error_causes_parts(0, error_causes)
    }

    /// Construct an ABORT chunk from typed error causes and raw flags.
    pub fn try_from_error_causes_parts(flags: u8, error_causes: &[SctpErrorCause]) -> Result<Self> {
        Ok(Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_ABORT,
                flags,
                sctp_error_causes_value(error_causes)?,
            ),
        })
    }

    /// Replace ABORT error causes while preserving raw flags.
    pub fn try_with_error_causes(mut self, error_causes: &[SctpErrorCause]) -> Result<Self> {
        self.raw = self.raw.with_value(sctp_error_causes_value(error_causes)?);
        Ok(self)
    }

    /// Set or clear one raw ABORT chunk flag bit.
    ///
    /// This touches only `flag` and preserves every other bit, including
    /// unassigned bits.
    pub fn flag(mut self, flag: u8, enabled: bool) -> Self {
        let mut flags = self.flags();
        if enabled {
            flags |= flag;
        } else {
            flags &= !flag;
        }
        self.raw = self.raw.with_flags(flags);
        self
    }

    /// Set the ABORT T bit.
    pub fn t_bit(self) -> Self {
        self.set_t_bit(true)
    }

    /// Set or clear the ABORT T bit.
    pub fn set_t_bit(self, enabled: bool) -> Self {
        self.flag(SCTP_ABORT_FLAG_T, enabled)
    }

    /// Whether the ABORT T bit is set.
    pub fn is_t_bit_set(&self) -> bool {
        self.flags() & SCTP_ABORT_FLAG_T != 0
    }

    /// Encoded ABORT error-cause bytes.
    pub fn error_cause_bytes(&self) -> &[u8] {
        self.value()
    }

    /// Decode the ABORT error-cause sequence.
    pub fn error_causes(&self) -> Result<Vec<SctpErrorCause>> {
        decode_causes(self.value())
    }
}

impl SctpErrorChunk {
    /// Construct an ERROR chunk from encoded error-cause bytes with zero flags.
    pub fn from_error_cause_bytes(error_causes: impl Into<Vec<u8>>) -> Self {
        Self::new(error_causes)
    }

    /// Replace the value with encoded error-cause bytes.
    pub fn with_error_cause_bytes(self, error_causes: impl Into<Vec<u8>>) -> Self {
        self.with_value(error_causes)
    }

    /// Construct an ERROR chunk from typed error causes with zero flags.
    pub fn try_from_error_causes(error_causes: &[SctpErrorCause]) -> Result<Self> {
        Self::try_from_error_causes_parts(0, error_causes)
    }

    /// Construct an ERROR chunk from typed error causes and raw flags.
    pub fn try_from_error_causes_parts(flags: u8, error_causes: &[SctpErrorCause]) -> Result<Self> {
        Ok(Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_ERROR,
                flags,
                sctp_error_causes_value(error_causes)?,
            ),
        })
    }

    /// Replace ERROR causes while preserving raw flags.
    pub fn try_with_error_causes(mut self, error_causes: &[SctpErrorCause]) -> Result<Self> {
        self.raw = self.raw.with_value(sctp_error_causes_value(error_causes)?);
        Ok(self)
    }

    /// Encoded ERROR error-cause bytes.
    pub fn error_cause_bytes(&self) -> &[u8] {
        self.value()
    }

    /// Decode the ERROR error-cause sequence.
    pub fn error_causes(&self) -> Result<Vec<SctpErrorCause>> {
        decode_causes(self.value())
    }
}

impl SctpCookieEchoChunk {
    /// Construct a COOKIE ECHO chunk from opaque cookie bytes.
    pub fn from_cookie(cookie: impl Into<Vec<u8>>) -> Self {
        Self::new(cookie)
    }

    /// Replace the opaque cookie bytes while preserving raw flags.
    pub fn with_cookie(self, cookie: impl Into<Vec<u8>>) -> Self {
        self.with_value(cookie)
    }

    /// Opaque cookie bytes, excluding chunk padding.
    pub fn cookie(&self) -> &[u8] {
        self.value()
    }

    /// Opaque cookie bytes, excluding chunk padding.
    pub fn cookie_bytes(&self) -> &[u8] {
        self.cookie()
    }
}

impl SctpCookieAckChunk {
    /// Construct a COOKIE ACK chunk with zero flags and no value.
    pub fn cookie_ack() -> Self {
        Self::from_cookie_ack_parts(0)
    }

    /// Construct a COOKIE ACK chunk with raw flags and no value.
    pub fn from_cookie_ack_parts(flags: u8) -> Self {
        Self {
            raw: SctpRawChunk::new(SCTP_CHUNK_TYPE_COOKIE_ACK, flags, Vec::new()),
        }
    }

    /// Validate the fixed-header-only COOKIE ACK value.
    pub fn validate_empty_value(&self) -> Result<()> {
        validate_sctp_cookie_ack_value(self.value())
    }
}

impl SctpEcneChunk {
    /// Construct an ECNE chunk from the Lowest TSN field with zero flags.
    pub fn from_lowest_tsn(lowest_tsn: u32) -> Self {
        Self::from_lowest_tsn_parts(0, lowest_tsn)
    }

    /// Construct an ECNE chunk from the Lowest TSN field and raw flags.
    pub fn from_lowest_tsn_parts(flags: u8, lowest_tsn: u32) -> Self {
        Self {
            raw: SctpRawChunk::new(SCTP_CHUNK_TYPE_ECNE, flags, sctp_ecne_value(lowest_tsn)),
        }
    }

    /// Replace the ECNE Lowest TSN field while preserving raw flags.
    pub fn with_lowest_tsn(mut self, lowest_tsn: u32) -> Self {
        self.raw = self.raw.with_value(sctp_ecne_value(lowest_tsn));
        self
    }

    /// ECNE Lowest TSN field.
    pub fn lowest_tsn(&self) -> Result<u32> {
        self.lowest_transmission_sequence_number()
    }

    /// ECNE Lowest TSN field.
    pub fn lowest_transmission_sequence_number(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_ecne_value_len(value)?;
        Ok(value)
    }
}

impl SctpCwrChunk {
    /// Construct a CWR chunk from the Lowest TSN field with zero flags.
    pub fn from_lowest_tsn(lowest_tsn: u32) -> Self {
        Self::from_lowest_tsn_parts(0, lowest_tsn)
    }

    /// Construct a CWR chunk from the Lowest TSN field and raw flags.
    pub fn from_lowest_tsn_parts(flags: u8, lowest_tsn: u32) -> Self {
        Self {
            raw: SctpRawChunk::new(SCTP_CHUNK_TYPE_CWR, flags, sctp_cwr_value(lowest_tsn)),
        }
    }

    /// Replace the CWR Lowest TSN field while preserving raw flags.
    pub fn with_lowest_tsn(mut self, lowest_tsn: u32) -> Self {
        self.raw = self.raw.with_value(sctp_cwr_value(lowest_tsn));
        self
    }

    /// CWR Lowest TSN field.
    pub fn lowest_tsn(&self) -> Result<u32> {
        self.lowest_transmission_sequence_number()
    }

    /// CWR Lowest TSN field.
    pub fn lowest_transmission_sequence_number(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_cwr_value_len(value)?;
        Ok(value)
    }
}

impl SctpForwardTsnChunk {
    /// Construct a FORWARD TSN chunk with zero flags.
    pub fn from_forward_tsn(
        new_cumulative_tsn: u32,
        skipped_stream_sequences: &[SctpForwardTsnSkippedStreamSequence],
    ) -> Self {
        Self::from_forward_tsn_parts(0, new_cumulative_tsn, skipped_stream_sequences)
    }

    /// Construct a FORWARD TSN chunk with raw flags.
    pub fn from_forward_tsn_parts(
        flags: u8,
        new_cumulative_tsn: u32,
        skipped_stream_sequences: &[SctpForwardTsnSkippedStreamSequence],
    ) -> Self {
        Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_FORWARD_TSN,
                flags,
                sctp_forward_tsn_value(new_cumulative_tsn, skipped_stream_sequences),
            ),
        }
    }

    /// Replace FORWARD TSN fields while preserving raw flags.
    pub fn with_forward_tsn(
        mut self,
        new_cumulative_tsn: u32,
        skipped_stream_sequences: &[SctpForwardTsnSkippedStreamSequence],
    ) -> Self {
        self.raw = self.raw.with_value(sctp_forward_tsn_value(
            new_cumulative_tsn,
            skipped_stream_sequences,
        ));
        self
    }

    /// FORWARD TSN New Cumulative TSN.
    pub fn new_cumulative_tsn(&self) -> Result<u32> {
        self.new_cumulative_transmission_sequence_number()
    }

    /// FORWARD TSN New Cumulative TSN.
    pub fn new_cumulative_transmission_sequence_number(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }

    /// Number of skipped Stream Sequence entries.
    pub fn skipped_stream_sequence_count(&self) -> Result<usize> {
        let value = self.semantic_value()?;
        Ok((value.len() - SCTP_FORWARD_TSN_CHUNK_VALUE_HEADER_LEN)
            / SCTP_FORWARD_TSN_SKIPPED_STREAM_SEQUENCE_LEN)
    }

    /// Decode skipped Stream Sequence entries.
    pub fn skipped_stream_sequences(&self) -> Result<Vec<SctpForwardTsnSkippedStreamSequence>> {
        let value = self.semantic_value()?;
        let mut skipped = Vec::with_capacity(self.skipped_stream_sequence_count()?);
        for entry in value[SCTP_FORWARD_TSN_CHUNK_VALUE_HEADER_LEN..]
            .chunks_exact(SCTP_FORWARD_TSN_SKIPPED_STREAM_SEQUENCE_LEN)
        {
            skipped.push(SctpForwardTsnSkippedStreamSequence::new(
                u16::from_be_bytes([entry[0], entry[1]]),
                u16::from_be_bytes([entry[2], entry[3]]),
            ));
        }
        Ok(skipped)
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_forward_tsn_value_len(value)?;
        Ok(value)
    }
}

impl SctpIForwardTsnChunk {
    /// Construct an I-FORWARD-TSN chunk with zero flags.
    pub fn from_iforward_tsn(
        new_cumulative_tsn: u32,
        skipped_streams: &[SctpIForwardTsnSkippedStream],
    ) -> Self {
        Self::from_iforward_tsn_parts(0, new_cumulative_tsn, skipped_streams)
    }

    /// Construct an I-FORWARD-TSN chunk with raw flags.
    pub fn from_iforward_tsn_parts(
        flags: u8,
        new_cumulative_tsn: u32,
        skipped_streams: &[SctpIForwardTsnSkippedStream],
    ) -> Self {
        Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_I_FORWARD_TSN,
                flags,
                sctp_iforward_tsn_value(new_cumulative_tsn, skipped_streams),
            ),
        }
    }

    /// Replace I-FORWARD-TSN fields while preserving raw flags.
    pub fn with_iforward_tsn(
        mut self,
        new_cumulative_tsn: u32,
        skipped_streams: &[SctpIForwardTsnSkippedStream],
    ) -> Self {
        self.raw = self
            .raw
            .with_value(sctp_iforward_tsn_value(new_cumulative_tsn, skipped_streams));
        self
    }

    /// I-FORWARD-TSN New Cumulative TSN.
    pub fn new_cumulative_tsn(&self) -> Result<u32> {
        self.new_cumulative_transmission_sequence_number()
    }

    /// I-FORWARD-TSN New Cumulative TSN.
    pub fn new_cumulative_transmission_sequence_number(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }

    /// Number of skipped stream entries.
    pub fn skipped_stream_count(&self) -> Result<usize> {
        let value = self.semantic_value()?;
        Ok((value.len() - SCTP_IFORWARD_TSN_CHUNK_VALUE_HEADER_LEN)
            / SCTP_IFORWARD_TSN_SKIPPED_STREAM_LEN)
    }

    /// Decode skipped stream entries.
    pub fn skipped_streams(&self) -> Result<Vec<SctpIForwardTsnSkippedStream>> {
        let value = self.semantic_value()?;
        let mut skipped = Vec::with_capacity(self.skipped_stream_count()?);
        for entry in value[SCTP_IFORWARD_TSN_CHUNK_VALUE_HEADER_LEN..]
            .chunks_exact(SCTP_IFORWARD_TSN_SKIPPED_STREAM_LEN)
        {
            skipped.push(SctpIForwardTsnSkippedStream::from_parts(
                u16::from_be_bytes([entry[0], entry[1]]),
                u16::from_be_bytes([entry[2], entry[3]]),
                u32::from_be_bytes([entry[4], entry[5], entry[6], entry[7]]),
            ));
        }
        Ok(skipped)
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_iforward_tsn_value_len(value)?;
        Ok(value)
    }
}

impl SctpShutdownChunk {
    /// Construct a SHUTDOWN chunk from the cumulative TSN ACK with zero flags.
    pub fn from_shutdown(cumulative_tsn_ack: u32) -> Self {
        Self::from_shutdown_parts(0, cumulative_tsn_ack)
    }

    /// Construct a SHUTDOWN chunk from the cumulative TSN ACK and raw flags.
    pub fn from_shutdown_parts(flags: u8, cumulative_tsn_ack: u32) -> Self {
        Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_SHUTDOWN,
                flags,
                sctp_shutdown_value(cumulative_tsn_ack),
            ),
        }
    }

    /// Replace the SHUTDOWN semantic field while preserving raw flags.
    pub fn with_shutdown(mut self, cumulative_tsn_ack: u32) -> Self {
        self.raw = self.raw.with_value(sctp_shutdown_value(cumulative_tsn_ack));
        self
    }

    /// SHUTDOWN Cumulative TSN Ack.
    pub fn cumulative_tsn_ack(&self) -> Result<u32> {
        self.cumulative_transmission_sequence_number_ack()
    }

    /// SHUTDOWN Cumulative TSN Ack.
    pub fn cumulative_transmission_sequence_number_ack(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_shutdown_value_len(value)?;
        Ok(value)
    }
}

impl SctpShutdownAckChunk {
    /// Construct a SHUTDOWN ACK chunk with zero flags and no value.
    pub fn shutdown_ack() -> Self {
        Self::from_shutdown_ack_parts(0)
    }

    /// Construct a SHUTDOWN ACK chunk with raw flags and no value.
    pub fn from_shutdown_ack_parts(flags: u8) -> Self {
        Self {
            raw: SctpRawChunk::new(SCTP_CHUNK_TYPE_SHUTDOWN_ACK, flags, Vec::new()),
        }
    }

    /// Validate the fixed-header-only SHUTDOWN ACK value.
    pub fn validate_empty_value(&self) -> Result<()> {
        validate_sctp_shutdown_ack_value(self.value())
    }
}

impl SctpShutdownCompleteChunk {
    /// Construct a SHUTDOWN COMPLETE chunk with zero flags and no value.
    pub fn shutdown_complete() -> Self {
        Self::from_shutdown_complete_parts(0)
    }

    /// Construct a SHUTDOWN COMPLETE chunk with raw flags and no value.
    pub fn from_shutdown_complete_parts(flags: u8) -> Self {
        Self {
            raw: SctpRawChunk::new(SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE, flags, Vec::new()),
        }
    }

    /// Set or clear a raw SHUTDOWN COMPLETE flag bit while preserving other bits.
    pub fn flag(mut self, mask: u8, enabled: bool) -> Self {
        let flags = if enabled {
            self.flags() | mask
        } else {
            self.flags() & !mask
        };
        self.raw = self.raw.with_flags(flags);
        self
    }

    /// Set the SHUTDOWN COMPLETE T bit.
    pub fn t_bit(self) -> Self {
        self.set_t_bit(true)
    }

    /// Set or clear the SHUTDOWN COMPLETE T bit.
    pub fn set_t_bit(self, enabled: bool) -> Self {
        self.flag(SCTP_SHUTDOWN_COMPLETE_FLAG_T, enabled)
    }

    /// Whether the SHUTDOWN COMPLETE T bit is set.
    pub fn is_t_bit_set(&self) -> bool {
        self.flags() & SCTP_SHUTDOWN_COMPLETE_FLAG_T != 0
    }

    /// Validate the fixed-header-only SHUTDOWN COMPLETE value.
    pub fn validate_empty_value(&self) -> Result<()> {
        validate_sctp_shutdown_complete_value(self.value())
    }
}

impl SctpAuthChunk {
    /// Construct an AUTH chunk with zero flags.
    ///
    /// The HMAC bytes are packet data only; this helper does not compute or
    /// verify SCTP-AUTH authentication material.
    pub fn from_auth(
        shared_key_identifier: impl Into<SctpSharedKeyIdentifier>,
        hmac_identifier: impl Into<SctpHmacIdentifier>,
        hmac: impl Into<Vec<u8>>,
    ) -> Self {
        Self::from_auth_parts(0, shared_key_identifier, hmac_identifier, hmac)
    }

    /// Construct an AUTH chunk with raw flags.
    pub fn from_auth_parts(
        flags: u8,
        shared_key_identifier: impl Into<SctpSharedKeyIdentifier>,
        hmac_identifier: impl Into<SctpHmacIdentifier>,
        hmac: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_AUTH,
                flags,
                sctp_auth_value(shared_key_identifier.into(), hmac_identifier.into(), hmac),
            ),
        }
    }

    /// Replace AUTH fields while preserving raw flags.
    pub fn with_auth(
        mut self,
        shared_key_identifier: impl Into<SctpSharedKeyIdentifier>,
        hmac_identifier: impl Into<SctpHmacIdentifier>,
        hmac: impl Into<Vec<u8>>,
    ) -> Self {
        self.raw = self.raw.with_value(sctp_auth_value(
            shared_key_identifier.into(),
            hmac_identifier.into(),
            hmac,
        ));
        self
    }

    /// AUTH Shared Key Identifier.
    pub fn shared_key_identifier(&self) -> Result<SctpSharedKeyIdentifier> {
        Ok(SctpSharedKeyIdentifier::new(
            self.shared_key_identifier_value()?,
        ))
    }

    /// Raw AUTH Shared Key Identifier value.
    pub fn shared_key_identifier_value(&self) -> Result<u16> {
        let value = self.semantic_value()?;
        Ok(u16::from_be_bytes([
            value[SCTP_AUTH_CHUNK_SHARED_KEY_IDENTIFIER_OFFSET],
            value[SCTP_AUTH_CHUNK_SHARED_KEY_IDENTIFIER_OFFSET + 1],
        ]))
    }

    /// AUTH HMAC Identifier.
    pub fn hmac_identifier(&self) -> Result<SctpHmacIdentifier> {
        Ok(SctpHmacIdentifier::new(self.hmac_identifier_value()?))
    }

    /// Raw AUTH HMAC Identifier value.
    pub fn hmac_identifier_value(&self) -> Result<u16> {
        let value = self.semantic_value()?;
        Ok(u16::from_be_bytes([
            value[SCTP_AUTH_CHUNK_HMAC_IDENTIFIER_OFFSET],
            value[SCTP_AUTH_CHUNK_HMAC_IDENTIFIER_OFFSET + 1],
        ]))
    }

    /// AUTH HMAC bytes, excluding chunk padding.
    pub fn hmac(&self) -> Result<&[u8]> {
        self.hmac_bytes()
    }

    /// AUTH HMAC bytes, excluding chunk padding.
    pub fn hmac_bytes(&self) -> Result<&[u8]> {
        let value = self.semantic_value()?;
        Ok(&value[SCTP_AUTH_CHUNK_HMAC_OFFSET..])
    }

    /// Validate that the AUTH value contains the fixed identifier fields.
    pub fn validate_auth_value(&self) -> Result<()> {
        validate_sctp_auth_value_len(self.value())
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_auth_value_len(value)?;
        Ok(value)
    }
}

impl SctpAsconfChunk {
    /// Construct an ASCONF chunk with zero flags.
    pub fn try_from_asconf(
        serial_number: u32,
        address_parameter: impl Into<SctpParameter>,
        parameters: &[SctpParameter],
    ) -> Result<Self> {
        Self::try_from_asconf_parts(0, serial_number, address_parameter, parameters)
    }

    /// Construct an ASCONF chunk with raw flags.
    pub fn try_from_asconf_parts(
        flags: u8,
        serial_number: u32,
        address_parameter: impl Into<SctpParameter>,
        parameters: &[SctpParameter],
    ) -> Result<Self> {
        let address_parameter = address_parameter.into();
        Ok(Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_ASCONF,
                flags,
                sctp_asconf_value(serial_number, &address_parameter, parameters)?,
            ),
        })
    }

    /// Replace ASCONF fields while preserving raw flags.
    pub fn try_with_asconf(
        mut self,
        serial_number: u32,
        address_parameter: impl Into<SctpParameter>,
        parameters: &[SctpParameter],
    ) -> Result<Self> {
        let address_parameter = address_parameter.into();
        self.raw = self.raw.with_value(sctp_asconf_value(
            serial_number,
            &address_parameter,
            parameters,
        )?);
        Ok(self)
    }

    /// ASCONF Sequence Number.
    pub fn sequence_number(&self) -> Result<u32> {
        self.serial_number()
    }

    /// ASCONF Sequence Number, using RFC 5061 serial-number arithmetic.
    pub fn serial_number(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }

    /// ASCONF parameter bytes following the Sequence Number.
    pub fn parameter_bytes(&self) -> Result<&[u8]> {
        let value = self.semantic_value()?;
        Ok(&value[SCTP_ASCONF_CHUNK_PARAMETERS_OFFSET..])
    }

    /// Decode the complete ASCONF parameter sequence.
    ///
    /// The first parameter is the sender address parameter. Remaining entries
    /// are ASCONF request parameters.
    pub fn parameters(&self) -> Result<Vec<SctpParameter>> {
        decode_parameters(self.parameter_bytes()?)
    }

    /// Decode the mandatory ASCONF sender address parameter.
    pub fn address_parameter(&self) -> Result<SctpParameter> {
        let parameters = self.parameters()?;
        parameters.first().cloned().ok_or_else(|| {
            CrafterError::buffer_too_short(
                SCTP_ASCONF_CHUNK_PARAMETERS_CONTEXT,
                SCTP_PARAMETER_HEADER_LEN,
                0,
            )
        })
    }

    /// Decode ASCONF request parameters after the sender address parameter.
    pub fn request_parameters(&self) -> Result<Vec<SctpParameter>> {
        let parameters = self.parameters()?;
        Ok(parameters.into_iter().skip(1).collect())
    }

    /// Decode ASCONF request parameters after the sender address parameter.
    pub fn asconf_parameters(&self) -> Result<Vec<SctpParameter>> {
        self.request_parameters()
    }

    /// Count all decoded ASCONF parameters, including the sender address parameter.
    pub fn parameter_count(&self) -> Result<usize> {
        Ok(self.parameters()?.len())
    }

    /// Validate the ASCONF value shape.
    pub fn validate_asconf_value(&self) -> Result<()> {
        validate_sctp_asconf_value(self.value())
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_asconf_value(value)?;
        Ok(value)
    }
}

impl SctpAsconfAckChunk {
    /// Construct an ASCONF-ACK chunk with zero flags.
    pub fn try_from_asconf_ack(serial_number: u32, parameters: &[SctpParameter]) -> Result<Self> {
        Self::try_from_asconf_ack_parts(0, serial_number, parameters)
    }

    /// Construct an ASCONF-ACK chunk with raw flags.
    pub fn try_from_asconf_ack_parts(
        flags: u8,
        serial_number: u32,
        parameters: &[SctpParameter],
    ) -> Result<Self> {
        Ok(Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_ASCONF_ACK,
                flags,
                sctp_asconf_ack_value(serial_number, parameters)?,
            ),
        })
    }

    /// Replace ASCONF-ACK fields while preserving raw flags.
    pub fn try_with_asconf_ack(
        mut self,
        serial_number: u32,
        parameters: &[SctpParameter],
    ) -> Result<Self> {
        self.raw = self
            .raw
            .with_value(sctp_asconf_ack_value(serial_number, parameters)?);
        Ok(self)
    }

    /// ASCONF-ACK Sequence Number.
    pub fn sequence_number(&self) -> Result<u32> {
        self.serial_number()
    }

    /// ASCONF-ACK Sequence Number copied from the acknowledged ASCONF chunk.
    pub fn serial_number(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }

    /// ASCONF-ACK response parameter bytes following the Sequence Number.
    pub fn parameter_bytes(&self) -> Result<&[u8]> {
        let value = self.semantic_value()?;
        Ok(&value[SCTP_ASCONF_ACK_CHUNK_PARAMETERS_OFFSET..])
    }

    /// Decode ASCONF-ACK response parameters.
    pub fn response_parameters(&self) -> Result<Vec<SctpParameter>> {
        decode_parameters(self.parameter_bytes()?)
    }

    /// Decode ASCONF-ACK response parameters.
    pub fn parameters(&self) -> Result<Vec<SctpParameter>> {
        self.response_parameters()
    }

    /// Count decoded ASCONF-ACK response parameters.
    pub fn response_parameter_count(&self) -> Result<usize> {
        Ok(self.response_parameters()?.len())
    }

    /// Count decoded ASCONF-ACK response parameters.
    pub fn parameter_count(&self) -> Result<usize> {
        self.response_parameter_count()
    }

    /// Validate the ASCONF-ACK value shape.
    pub fn validate_asconf_ack_value(&self) -> Result<()> {
        validate_sctp_asconf_ack_value(self.value())
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_asconf_ack_value(value)?;
        Ok(value)
    }
}

impl SctpReConfigChunk {
    /// Construct a RE-CONFIG chunk with zero flags.
    pub fn try_from_reconfig(parameters: &[SctpParameter]) -> Result<Self> {
        Self::try_from_reconfig_parts(0, parameters)
    }

    /// Construct a RE-CONFIG chunk with raw flags.
    pub fn try_from_reconfig_parts(flags: u8, parameters: &[SctpParameter]) -> Result<Self> {
        Ok(Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_RE_CONFIG,
                flags,
                sctp_reconfig_value(parameters)?,
            ),
        })
    }

    /// Replace RE-CONFIG parameters while preserving raw flags.
    pub fn try_with_reconfig(mut self, parameters: &[SctpParameter]) -> Result<Self> {
        self.raw = self.raw.with_value(sctp_reconfig_value(parameters)?);
        Ok(self)
    }

    /// Encoded RE-CONFIG parameter bytes.
    pub fn parameter_bytes(&self) -> Result<&[u8]> {
        self.semantic_value()
    }

    /// Decode the RE-CONFIG parameter sequence.
    pub fn parameters(&self) -> Result<Vec<SctpParameter>> {
        decode_parameters(self.parameter_bytes()?)
    }

    /// Decode the RE-CONFIG parameter sequence.
    pub fn reconfiguration_parameters(&self) -> Result<Vec<SctpParameter>> {
        self.parameters()
    }

    /// Count decoded RE-CONFIG parameters.
    pub fn parameter_count(&self) -> Result<usize> {
        Ok(self.parameters()?.len())
    }

    /// Validate the RE-CONFIG value shape.
    pub fn validate_reconfig_value(&self) -> Result<()> {
        validate_sctp_reconfig_value(self.value())
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_reconfig_value(value)?;
        Ok(value)
    }
}

impl SctpPadChunk {
    /// Construct a PAD chunk from ignored padding data bytes.
    pub fn from_padding_data(padding_data: impl Into<Vec<u8>>) -> Self {
        Self::new(padding_data)
    }

    /// Replace the ignored padding data bytes while preserving raw flags.
    pub fn with_padding_data(mut self, padding_data: impl Into<Vec<u8>>) -> Self {
        self.raw = self.raw.with_value(padding_data);
        self
    }

    /// Ignored PAD chunk data bytes, excluding SCTP chunk alignment padding.
    pub fn padding_data(&self) -> &[u8] {
        self.value()
    }

    /// Ignored PAD chunk data bytes, excluding SCTP chunk alignment padding.
    pub fn padding_data_bytes(&self) -> &[u8] {
        self.padding_data()
    }
}

impl SctpIDataChunk {
    /// Construct an I-DATA chunk from RFC 8260 semantic fields with zero flags and reserved bits.
    ///
    /// The last 32-bit word is preserved raw. With the B flag clear it is the
    /// Fragment Sequence Number; set B to make it the Payload Protocol
    /// Identifier for a beginning fragment.
    pub fn from_idata(
        tsn: u32,
        stream_id: u16,
        message_identifier: u32,
        ppid_or_fsn: u32,
        user_data: impl Into<Vec<u8>>,
    ) -> Self {
        Self::from_idata_parts(
            0,
            tsn,
            stream_id,
            0,
            message_identifier,
            ppid_or_fsn,
            user_data,
        )
    }

    /// Construct an I-DATA chunk from RFC 8260 semantic fields and raw flags.
    pub fn from_idata_parts(
        flags: u8,
        tsn: u32,
        stream_id: u16,
        reserved: u16,
        message_identifier: u32,
        ppid_or_fsn: u32,
        user_data: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            raw: SctpRawChunk::new(
                SCTP_CHUNK_TYPE_I_DATA,
                flags,
                sctp_idata_value(
                    tsn,
                    stream_id,
                    reserved,
                    message_identifier,
                    ppid_or_fsn,
                    user_data,
                ),
            ),
        }
    }

    /// Replace the I-DATA semantic fields while preserving the raw envelope flags.
    pub fn with_idata(
        mut self,
        tsn: u32,
        stream_id: u16,
        reserved: u16,
        message_identifier: u32,
        ppid_or_fsn: u32,
        user_data: impl Into<Vec<u8>>,
    ) -> Self {
        self.raw = self.raw.with_value(sctp_idata_value(
            tsn,
            stream_id,
            reserved,
            message_identifier,
            ppid_or_fsn,
            user_data,
        ));
        self
    }

    /// Set or clear one raw I-DATA chunk flag bit.
    ///
    /// This touches only `flag` and preserves every other bit, including
    /// unassigned bits.
    pub fn flag(mut self, flag: u8, enabled: bool) -> Self {
        let mut flags = self.flags();
        if enabled {
            flags |= flag;
        } else {
            flags &= !flag;
        }
        self.raw = self.raw.with_flags(flags);
        self
    }

    /// Set the U (Unordered) I-DATA flag.
    pub fn unordered(self) -> Self {
        self.set_unordered(true)
    }

    /// Set or clear the U (Unordered) I-DATA flag.
    pub fn set_unordered(self, enabled: bool) -> Self {
        self.flag(SCTP_IDATA_FLAG_UNORDERED, enabled)
    }

    /// Set the B (Beginning Fragment) I-DATA flag.
    pub fn begin(self) -> Self {
        self.set_begin(true)
    }

    /// Set or clear the B (Beginning Fragment) I-DATA flag.
    pub fn set_begin(self, enabled: bool) -> Self {
        self.flag(SCTP_IDATA_FLAG_BEGIN, enabled)
    }

    /// Set the E (Ending Fragment) I-DATA flag.
    pub fn end(self) -> Self {
        self.set_end(true)
    }

    /// Set or clear the E (Ending Fragment) I-DATA flag.
    pub fn set_end(self, enabled: bool) -> Self {
        self.flag(SCTP_IDATA_FLAG_END, enabled)
    }

    /// Mark this I-DATA chunk as carrying a complete, unfragmented user message.
    ///
    /// This sets B and E while preserving U, I, and any unrelated raw flag bits.
    pub fn complete_message(self) -> Self {
        self.set_begin(true).set_end(true)
    }

    /// Mark this I-DATA chunk as carrying a non-boundary fragmented message part.
    ///
    /// This clears B and E while preserving U, I, and any unrelated raw flag
    /// bits. The raw PPID/FSN word is not changed.
    pub fn fragmented_message(self) -> Self {
        self.set_begin(false).set_end(false)
    }

    /// Set the I (Immediate SACK) I-DATA flag.
    pub fn sack_immediately(self) -> Self {
        self.set_sack_immediately(true)
    }

    /// Set or clear the I (Immediate SACK) I-DATA flag.
    pub fn set_sack_immediately(self, enabled: bool) -> Self {
        self.flag(SCTP_IDATA_FLAG_SACK_IMMEDIATELY, enabled)
    }

    /// Whether the B (Beginning Fragment) I-DATA flag is set.
    pub fn is_begin(&self) -> bool {
        self.flags() & SCTP_IDATA_FLAG_BEGIN != 0
    }

    /// Whether the E (Ending Fragment) I-DATA flag is set.
    pub fn is_end(&self) -> bool {
        self.flags() & SCTP_IDATA_FLAG_END != 0
    }

    /// Whether the U (Unordered) I-DATA flag is set.
    pub fn is_unordered(&self) -> bool {
        self.flags() & SCTP_IDATA_FLAG_UNORDERED != 0
    }

    /// Whether the I (Immediate SACK) I-DATA flag is set.
    pub fn is_sack_immediately(&self) -> bool {
        self.flags() & SCTP_IDATA_FLAG_SACK_IMMEDIATELY != 0
    }

    /// I-DATA Transmission Sequence Number.
    pub fn tsn(&self) -> Result<u32> {
        self.transmission_sequence_number()
    }

    /// I-DATA Transmission Sequence Number.
    pub fn transmission_sequence_number(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([
            value[SCTP_IDATA_CHUNK_TSN_OFFSET],
            value[SCTP_IDATA_CHUNK_TSN_OFFSET + 1],
            value[SCTP_IDATA_CHUNK_TSN_OFFSET + 2],
            value[SCTP_IDATA_CHUNK_TSN_OFFSET + 3],
        ]))
    }

    /// I-DATA Stream Identifier.
    pub fn stream_id(&self) -> Result<u16> {
        self.stream_identifier()
    }

    /// I-DATA Stream Identifier.
    pub fn stream_identifier(&self) -> Result<u16> {
        let value = self.semantic_value()?;
        Ok(u16::from_be_bytes([
            value[SCTP_IDATA_CHUNK_STREAM_ID_OFFSET],
            value[SCTP_IDATA_CHUNK_STREAM_ID_OFFSET + 1],
        ]))
    }

    /// I-DATA reserved field, preserved as transmitted.
    pub fn reserved(&self) -> Result<u16> {
        self.reserved_value()
    }

    /// I-DATA reserved field, preserved as transmitted.
    pub fn reserved_value(&self) -> Result<u16> {
        let value = self.semantic_value()?;
        Ok(u16::from_be_bytes([
            value[SCTP_IDATA_CHUNK_RESERVED_OFFSET],
            value[SCTP_IDATA_CHUNK_RESERVED_OFFSET + 1],
        ]))
    }

    /// I-DATA Message Identifier.
    pub fn message_id(&self) -> Result<u32> {
        self.message_identifier()
    }

    /// I-DATA Message Identifier.
    pub fn message_identifier(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([
            value[SCTP_IDATA_CHUNK_MESSAGE_ID_OFFSET],
            value[SCTP_IDATA_CHUNK_MESSAGE_ID_OFFSET + 1],
            value[SCTP_IDATA_CHUNK_MESSAGE_ID_OFFSET + 2],
            value[SCTP_IDATA_CHUNK_MESSAGE_ID_OFFSET + 3],
        ]))
    }

    /// Raw PPID/FSN word.
    pub fn ppid_fsn(&self) -> Result<u32> {
        self.payload_protocol_identifier_or_fragment_sequence_number()
    }

    /// Raw PPID/FSN word.
    pub fn payload_protocol_identifier_or_fragment_sequence_number(&self) -> Result<u32> {
        let value = self.semantic_value()?;
        Ok(u32::from_be_bytes([
            value[SCTP_IDATA_CHUNK_PPID_FSN_OFFSET],
            value[SCTP_IDATA_CHUNK_PPID_FSN_OFFSET + 1],
            value[SCTP_IDATA_CHUNK_PPID_FSN_OFFSET + 2],
            value[SCTP_IDATA_CHUNK_PPID_FSN_OFFSET + 3],
        ]))
    }

    /// Payload Protocol Identifier when B is set.
    pub fn ppid(&self) -> Result<Option<u32>> {
        self.payload_protocol_identifier()
    }

    /// Payload Protocol Identifier when B is set.
    pub fn payload_protocol_identifier(&self) -> Result<Option<u32>> {
        let word = self.ppid_fsn()?;
        Ok(self.is_begin().then_some(word))
    }

    /// I-DATA Payload Protocol Identifier registry status when B is set.
    pub fn ppid_status(&self) -> Result<Option<SctpPpidStatus>> {
        self.payload_protocol_identifier_status()
    }

    /// I-DATA Payload Protocol Identifier registry status when B is set.
    pub fn payload_protocol_identifier_status(&self) -> Result<Option<SctpPpidStatus>> {
        Ok(self.payload_protocol_identifier()?.map(sctp_ppid_status))
    }

    /// I-DATA Payload Protocol Identifier registry label when B is set and known.
    pub fn ppid_name(&self) -> Result<Option<&'static str>> {
        self.payload_protocol_identifier_name()
    }

    /// I-DATA Payload Protocol Identifier registry label when B is set and known.
    pub fn payload_protocol_identifier_name(&self) -> Result<Option<&'static str>> {
        Ok(self.payload_protocol_identifier()?.and_then(sctp_ppid_name))
    }

    /// Fragment Sequence Number when B is clear.
    pub fn fsn(&self) -> Result<Option<u32>> {
        self.fragment_sequence_number()
    }

    /// Fragment Sequence Number when B is clear.
    pub fn fragment_sequence_number(&self) -> Result<Option<u32>> {
        let word = self.ppid_fsn()?;
        Ok((!self.is_begin()).then_some(word))
    }

    /// I-DATA User Data bytes, excluding chunk padding.
    pub fn user_data(&self) -> Result<&[u8]> {
        let value = self.semantic_value()?;
        Ok(&value[SCTP_IDATA_CHUNK_USER_DATA_OFFSET..])
    }

    fn semantic_value(&self) -> Result<&[u8]> {
        let value = self.value();
        validate_sctp_idata_value_len(value)?;
        Ok(value)
    }
}

impl From<SctpUnknownChunk> for SctpChunk {
    fn from(value: SctpUnknownChunk) -> Self {
        Self::Unknown(value)
    }
}

impl From<SctpRawChunk> for SctpChunk {
    fn from(raw: SctpRawChunk) -> Self {
        match raw.chunk_type_value() {
            SCTP_CHUNK_TYPE_DATA => Self::Data(SctpDataChunk { raw }),
            SCTP_CHUNK_TYPE_INIT => Self::Init(SctpInitChunk { raw }),
            SCTP_CHUNK_TYPE_INIT_ACK => Self::InitAck(SctpInitAckChunk { raw }),
            SCTP_CHUNK_TYPE_SACK => Self::Sack(SctpSackChunk { raw }),
            SCTP_CHUNK_TYPE_HEARTBEAT => Self::Heartbeat(SctpHeartbeatChunk { raw }),
            SCTP_CHUNK_TYPE_HEARTBEAT_ACK => Self::HeartbeatAck(SctpHeartbeatAckChunk { raw }),
            SCTP_CHUNK_TYPE_ABORT => Self::Abort(SctpAbortChunk { raw }),
            SCTP_CHUNK_TYPE_SHUTDOWN => Self::Shutdown(SctpShutdownChunk { raw }),
            SCTP_CHUNK_TYPE_SHUTDOWN_ACK => Self::ShutdownAck(SctpShutdownAckChunk { raw }),
            SCTP_CHUNK_TYPE_ERROR => Self::Error(SctpErrorChunk { raw }),
            SCTP_CHUNK_TYPE_COOKIE_ECHO => Self::CookieEcho(SctpCookieEchoChunk { raw }),
            SCTP_CHUNK_TYPE_COOKIE_ACK => Self::CookieAck(SctpCookieAckChunk { raw }),
            SCTP_CHUNK_TYPE_ECNE => Self::Ecne(SctpEcneChunk { raw }),
            SCTP_CHUNK_TYPE_CWR => Self::Cwr(SctpCwrChunk { raw }),
            SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE => {
                Self::ShutdownComplete(SctpShutdownCompleteChunk { raw })
            }
            SCTP_CHUNK_TYPE_AUTH => Self::Auth(SctpAuthChunk { raw }),
            SCTP_CHUNK_TYPE_I_DATA => Self::IData(SctpIDataChunk { raw }),
            SCTP_CHUNK_TYPE_ASCONF_ACK => Self::AsconfAck(SctpAsconfAckChunk { raw }),
            SCTP_CHUNK_TYPE_RE_CONFIG => Self::ReConfig(SctpReConfigChunk { raw }),
            SCTP_CHUNK_TYPE_PAD => Self::Pad(SctpPadChunk { raw }),
            SCTP_CHUNK_TYPE_FORWARD_TSN => Self::ForwardTsn(SctpForwardTsnChunk { raw }),
            SCTP_CHUNK_TYPE_ASCONF => Self::Asconf(SctpAsconfChunk { raw }),
            SCTP_CHUNK_TYPE_I_FORWARD_TSN => Self::IForwardTsn(SctpIForwardTsnChunk { raw }),
            _ => Self::Unknown(SctpUnknownChunk { raw }),
        }
    }
}

impl SctpChunk {
    /// Construct a chunk from raw wire parts, dispatching known codepoints.
    pub fn from_raw_parts(
        chunk_type: u8,
        flags: u8,
        value: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        SctpRawChunk::from_raw_parts(chunk_type, flags, value, padding).into()
    }

    /// Construct a chunk with an explicit declared length, dispatching known codepoints.
    pub fn from_preserved_parts(
        chunk_type: u8,
        flags: u8,
        declared_length: u16,
        value: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        SctpRawChunk::from_preserved_parts(chunk_type, flags, declared_length, value, padding)
            .into()
    }

    /// Construct an unknown chunk with an auto-derived declared length.
    pub fn unknown(chunk_type: u8, flags: u8, value: impl Into<Vec<u8>>) -> Self {
        SctpUnknownChunk::new(chunk_type, flags, value).into()
    }

    /// Borrow the preserved raw chunk envelope.
    pub fn raw_chunk(&self) -> &SctpRawChunk {
        match self {
            Self::Data(value) => value.raw_chunk(),
            Self::Init(value) => value.raw_chunk(),
            Self::InitAck(value) => value.raw_chunk(),
            Self::Sack(value) => value.raw_chunk(),
            Self::Heartbeat(value) => value.raw_chunk(),
            Self::HeartbeatAck(value) => value.raw_chunk(),
            Self::Abort(value) => value.raw_chunk(),
            Self::Shutdown(value) => value.raw_chunk(),
            Self::ShutdownAck(value) => value.raw_chunk(),
            Self::Error(value) => value.raw_chunk(),
            Self::CookieEcho(value) => value.raw_chunk(),
            Self::CookieAck(value) => value.raw_chunk(),
            Self::Ecne(value) => value.raw_chunk(),
            Self::Cwr(value) => value.raw_chunk(),
            Self::ShutdownComplete(value) => value.raw_chunk(),
            Self::Auth(value) => value.raw_chunk(),
            Self::IData(value) => value.raw_chunk(),
            Self::AsconfAck(value) => value.raw_chunk(),
            Self::ReConfig(value) => value.raw_chunk(),
            Self::Pad(value) => value.raw_chunk(),
            Self::ForwardTsn(value) => value.raw_chunk(),
            Self::Asconf(value) => value.raw_chunk(),
            Self::IForwardTsn(value) => value.raw_chunk(),
            Self::Unknown(value) => value.raw_chunk(),
        }
    }

    /// SCTP chunk type codepoint.
    pub fn chunk_type(&self) -> SctpChunkType {
        self.raw_chunk().chunk_type()
    }

    /// Raw SCTP chunk type codepoint.
    pub fn chunk_type_value(&self) -> u8 {
        self.raw_chunk().chunk_type_value()
    }

    /// Raw SCTP chunk flags.
    pub fn flags(&self) -> u8 {
        self.raw_chunk().flags()
    }

    /// Source-backed registry status for this chunk type.
    pub fn chunk_type_status(&self) -> SctpChunkTypeStatus {
        self.raw_chunk().chunk_type_status()
    }

    /// Source-backed registry label for this chunk type, when known.
    pub fn chunk_type_name(&self) -> Option<&'static str> {
        self.raw_chunk().chunk_type_name()
    }

    /// All assigned flag names for this chunk type.
    pub fn flag_names(&self) -> &'static [SctpChunkFlagName] {
        self.raw_chunk().flag_names()
    }

    /// Assigned flag names whose bits are set in this chunk's flag byte.
    pub fn active_flag_names(&self) -> Vec<&'static str> {
        self.raw_chunk().active_flag_names()
    }

    /// Flag bits set outside this chunk type's assigned flag mask.
    pub fn unassigned_flag_bits(&self) -> u8 {
        self.raw_chunk().unassigned_flag_bits()
    }

    /// Declared chunk length value, using the explicit value when present.
    pub fn declared_length(&self) -> usize {
        self.raw_chunk().declared_length()
    }

    /// Compatibility alias for the declared chunk length value.
    pub fn length(&self) -> usize {
        self.declared_length()
    }

    /// Explicit declared chunk length override, if one is preserved.
    pub fn explicit_declared_length(&self) -> Option<u16> {
        self.raw_chunk().explicit_declared_length()
    }

    /// Compatibility alias for the explicit declared chunk length override.
    pub fn explicit_length(&self) -> Option<u16> {
        self.explicit_declared_length()
    }

    /// Declared chunk value bytes, excluding padding.
    pub fn value(&self) -> &[u8] {
        self.raw_chunk().value()
    }

    /// Transmitted chunk padding bytes, excluded from semantic value bytes.
    pub fn padding(&self) -> &[u8] {
        self.raw_chunk().padding()
    }

    /// Declared chunk value length, excluding padding.
    pub fn value_len(&self) -> usize {
        self.raw_chunk().value_len()
    }

    /// Transmitted chunk padding length.
    pub fn padding_len(&self) -> usize {
        self.raw_chunk().padding_len()
    }

    /// Protocol padding length implied by the declared chunk length.
    pub fn required_padding_len(&self) -> usize {
        self.raw_chunk().required_padding_len()
    }

    /// Padding length an encoder would emit: preserved bytes, or auto zero padding.
    pub fn encoded_padding_len(&self) -> usize {
        self.raw_chunk().encoded_padding_len()
    }

    /// Declared chunk length rounded up to the next four-octet boundary.
    pub fn padded_declared_len(&self) -> usize {
        self.raw_chunk().padded_declared_len()
    }

    /// Number of bytes encoded for this envelope, including padding.
    pub fn encoded_len(&self) -> usize {
        self.raw_chunk().encoded_len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::error::CrafterError;

    use super::super::constants::{
        SCTP_CHUNK_TYPE_DTLS, SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_1,
        SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4, SCTP_PPID_DTLS_CHUNK_KEY_MANAGEMENT,
        SCTP_PPID_WEBRTC_DCEP,
    };
    use super::super::parameter::{
        SctpAddIpAddressParameter, SctpIpv4AddressParameter, SctpReConfigurationResponseParameter,
        SctpSsnTsnResetRequestParameter, SctpSuccessIndicationParameter,
    };
    use super::*;

    #[test]
    fn sctp_chunk_model_typed_variants_keep_common_wire_fields() {
        let chunk = SctpChunk::from_raw_parts(SCTP_CHUNK_TYPE_DATA, 0xff, [1, 2, 3], [0xaa]);

        assert!(matches!(chunk, SctpChunk::Data(_)));
        assert_eq!(chunk.chunk_type(), SctpChunkType::new(SCTP_CHUNK_TYPE_DATA));
        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_DATA);
        assert_eq!(chunk.flags(), 0xff);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 3);
        assert_eq!(chunk.explicit_length(), None);
        assert_eq!(chunk.value(), &[1, 2, 3]);
        assert_eq!(chunk.padding(), &[0xaa]);
        assert_eq!(chunk.encoded_len(), SCTP_CHUNK_HEADER_LEN + 4);
    }

    #[test]
    fn sctp_chunk_model_preserves_explicit_length_without_normalizing_storage() {
        let chunk =
            SctpChunk::from_preserved_parts(SCTP_CHUNK_TYPE_INIT, 0x7e, 4, [1, 2, 3], [0xbb, 0xcc]);

        assert!(matches!(chunk, SctpChunk::Init(_)));
        assert_eq!(chunk.flags(), 0x7e);
        assert_eq!(chunk.length(), 4);
        assert_eq!(chunk.explicit_declared_length(), Some(4));
        assert_eq!(chunk.value(), &[1, 2, 3]);
        assert_eq!(chunk.padding(), &[0xbb, 0xcc]);
        assert_eq!(chunk.encoded_len(), SCTP_CHUNK_HEADER_LEN + 5);
    }

    #[test]
    fn sctp_unknown_chunk_preserves_type_flags_declared_length_value_and_padding() {
        let chunk = SctpChunk::from_preserved_parts(
            SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_1,
            0x80,
            9,
            [0xde, 0xad, 0xbe],
            [0xef],
        );

        let SctpChunk::Unknown(unknown) = chunk else {
            panic!("reserved extension codepoint must remain an unknown chunk");
        };
        assert_eq!(
            unknown.chunk_type_value(),
            SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_1
        );
        assert_eq!(unknown.chunk_type(), SctpChunkType::new(63));
        assert_eq!(unknown.flags(), 0x80);
        assert_eq!(unknown.length(), 9);
        assert_eq!(unknown.explicit_length(), Some(9));
        assert_eq!(unknown.value(), &[0xde, 0xad, 0xbe]);
        assert_eq!(unknown.value_len(), 3);
        assert_eq!(unknown.padding(), &[0xef]);
        assert_eq!(unknown.padding_len(), 1);
        assert_eq!(unknown.encoded_len(), SCTP_CHUNK_HEADER_LEN + 4);
    }

    #[test]
    fn sctp_unknown_chunk_temporary_reserved_and_unassigned_codepoints_remain_unknown() {
        for chunk_type in [
            SCTP_CHUNK_TYPE_DTLS,
            SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4,
            254,
        ] {
            let chunk = SctpChunk::from_raw_parts(chunk_type, 0x01, [], []);

            assert!(matches!(chunk, SctpChunk::Unknown(_)), "{chunk_type}");
            assert_eq!(chunk.chunk_type_value(), chunk_type);
            assert_eq!(chunk.flags(), 0x01);
            assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN);
        }
    }

    #[test]
    fn sctp_chunk_classification_status_names_and_predicates_are_source_backed() {
        let data = SctpChunkType::new(SCTP_CHUNK_TYPE_DATA);
        assert_eq!(data.status(), SctpChunkTypeStatus::Assigned);
        assert!(data.is_assigned());
        assert_eq!(data.name(), Some("DATA"));

        let ecne = SctpChunkType::new(SCTP_CHUNK_TYPE_ECNE);
        assert_eq!(ecne.status(), SctpChunkTypeStatus::Reserved);
        assert!(ecne.is_reserved());
        assert_eq!(ecne.name(), Some("ECNE"));

        let extension_slot = SctpChunkType::new(SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_1);
        assert_eq!(extension_slot.status(), SctpChunkTypeStatus::Reserved);
        assert_eq!(
            extension_slot.name(),
            Some("Reserved for IETF-defined Chunk Extensions")
        );

        let dtls = SctpChunkType::new(SCTP_CHUNK_TYPE_DTLS);
        assert_eq!(dtls.status(), SctpChunkTypeStatus::Experimental);
        assert!(dtls.is_experimental());
        assert_eq!(dtls.name(), Some("DTLS"));

        let unassigned = SctpChunkType::new(129);
        assert_eq!(unassigned.status(), SctpChunkTypeStatus::Unknown);
        assert!(unassigned.is_unknown());
        assert_eq!(unassigned.name(), None);

        assert!(sctp_chunk_type_is_assigned(SCTP_CHUNK_TYPE_AUTH));
        assert!(sctp_chunk_type_is_reserved(SCTP_CHUNK_TYPE_CWR));
        assert!(sctp_chunk_type_is_experimental(SCTP_CHUNK_TYPE_DTLS));
        assert!(sctp_chunk_type_is_unknown(254));
        assert_eq!(SctpChunkTypeStatus::Reserved.to_string(), "reserved");
    }

    #[test]
    fn sctp_chunk_classification_flag_name_tables_are_per_type() {
        let data_flags: Vec<_> = SctpChunkType::new(SCTP_CHUNK_TYPE_DATA)
            .flag_names()
            .iter()
            .map(|flag| (flag.mask(), flag.name(), flag.description()))
            .collect();
        assert_eq!(
            data_flags,
            vec![
                (SCTP_DATA_FLAG_END, "E", "Ending Fragment"),
                (SCTP_DATA_FLAG_BEGIN, "B", "Beginning Fragment"),
                (SCTP_DATA_FLAG_UNORDERED, "U", "Unordered"),
                (SCTP_DATA_FLAG_SACK_IMMEDIATELY, "I", "Immediate SACK"),
            ]
        );

        assert_eq!(
            sctp_chunk_flag_name(SCTP_CHUNK_TYPE_I_DATA, SCTP_IDATA_FLAG_BEGIN),
            Some("B")
        );
        assert_eq!(
            sctp_chunk_flag_name(SCTP_CHUNK_TYPE_ABORT, SCTP_ABORT_FLAG_T),
            Some("T")
        );
        assert_eq!(
            sctp_chunk_flag_name(
                SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE,
                SCTP_SHUTDOWN_COMPLETE_FLAG_T
            ),
            Some("T")
        );
        assert_eq!(sctp_chunk_flag_name(SCTP_CHUNK_TYPE_DATA, 0x80), None);
        assert!(sctp_chunk_flag_names(SCTP_CHUNK_TYPE_PAD).is_empty());
        assert!(SctpChunkType::new(SCTP_CHUNK_TYPE_ASCONF)
            .flag_names()
            .is_empty());
    }

    #[test]
    fn sctp_chunk_classification_active_flag_names_preserve_unassigned_bits() {
        let flags =
            SCTP_DATA_FLAG_END | SCTP_DATA_FLAG_UNORDERED | SCTP_DATA_FLAG_SACK_IMMEDIATELY | 0x80;
        let chunk = SctpChunk::from_raw_parts(SCTP_CHUNK_TYPE_DATA, flags, [0; 12], []);

        assert_eq!(chunk.chunk_type_status(), SctpChunkTypeStatus::Assigned);
        assert_eq!(chunk.chunk_type_name(), Some("DATA"));
        assert_eq!(chunk.active_flag_names(), vec!["E", "U", "I"]);
        assert_eq!(chunk.unassigned_flag_bits(), 0x80);
        assert_eq!(
            sctp_chunk_active_flag_names(SCTP_CHUNK_TYPE_DATA, flags),
            vec!["E", "U", "I"]
        );

        let abort = SctpAbortChunk::new([]).with_flags(SCTP_ABORT_FLAG_T | 0x40);
        assert_eq!(abort.active_flag_names(), vec!["T"]);
        assert_eq!(abort.unassigned_flag_bits(), 0x40);

        let pad = SctpPadChunk::new([]).with_flags(0xff);
        assert!(pad.active_flag_names().is_empty());
        assert_eq!(pad.unassigned_flag_bits(), 0xff);

        let unknown = SctpUnknownChunk::new(129, 0x01, []);
        assert_eq!(unknown.chunk_type_status(), SctpChunkTypeStatus::Unknown);
        assert_eq!(unknown.chunk_type_name(), None);
        assert!(unknown.active_flag_names().is_empty());
        assert_eq!(unknown.unassigned_flag_bits(), 0x01);
    }

    #[test]
    fn sctp_chunk_model_typed_wrappers_share_raw_envelope_accessors() {
        let chunk = SctpShutdownCompleteChunk::new([])
            .with_flags(0xff)
            .with_declared_length(1)
            .with_padding([0x00, 0x01]);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE);
        assert_eq!(chunk.flags(), 0xff);
        assert_eq!(chunk.length(), 1);
        assert_eq!(chunk.explicit_length(), Some(1));
        assert_eq!(chunk.value(), &[]);
        assert_eq!(chunk.padding(), &[0x00, 0x01]);

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::ShutdownComplete(_)));
        assert_eq!(enum_chunk.length(), 1);
    }

    #[test]
    fn sctp_chunk_padding_helpers_round_declared_lengths_to_four_octets() {
        assert_eq!(sctp_chunk_padding_len(SCTP_CHUNK_HEADER_LEN), 0);
        assert_eq!(sctp_chunk_padding_len(SCTP_CHUNK_HEADER_LEN + 1), 3);
        assert_eq!(sctp_chunk_padding_len(SCTP_CHUNK_HEADER_LEN + 2), 2);
        assert_eq!(sctp_chunk_padding_len(SCTP_CHUNK_HEADER_LEN + 3), 1);
        assert_eq!(sctp_chunk_padding_len(SCTP_CHUNK_HEADER_LEN + 4), 0);
        assert_eq!(sctp_chunk_padded_len(SCTP_CHUNK_HEADER_LEN + 1), 8);
    }

    #[test]
    fn sctp_chunk_padding_auto_encoded_len_includes_required_zero_padding() {
        let chunk = SctpDataChunk::new([0xaa]);

        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.value_len(), 1);
        assert_eq!(chunk.padding(), &[]);
        assert_eq!(chunk.padding_len(), 0);
        assert_eq!(chunk.required_padding_len(), 3);
        assert_eq!(chunk.encoded_padding_len(), 3);
        assert_eq!(chunk.padded_declared_len(), SCTP_CHUNK_HEADER_LEN + 4);
        assert_eq!(chunk.encoded_len(), SCTP_CHUNK_HEADER_LEN + 4);

        let enum_chunk = SctpChunk::from(chunk);
        assert_eq!(enum_chunk.value(), &[0xaa]);
        assert_eq!(enum_chunk.value_len(), 1);
        assert_eq!(enum_chunk.padding(), &[]);
        assert_eq!(enum_chunk.padding_len(), 0);
        assert_eq!(enum_chunk.required_padding_len(), 3);
        assert_eq!(enum_chunk.encoded_padding_len(), 3);
        assert_eq!(enum_chunk.encoded_len(), SCTP_CHUNK_HEADER_LEN + 4);
    }

    #[test]
    fn sctp_chunk_padding_preserves_explicit_padding_and_malformed_length() {
        let chunk =
            SctpChunk::from_preserved_parts(SCTP_CHUNK_TYPE_INIT, 0x7e, 5, [1, 2, 3], [0xbb]);

        assert_eq!(chunk.length(), 5);
        assert_eq!(chunk.explicit_declared_length(), Some(5));
        assert_eq!(chunk.value(), &[1, 2, 3]);
        assert_eq!(chunk.value_len(), 3);
        assert_eq!(chunk.padding(), &[0xbb]);
        assert_eq!(chunk.padding_len(), 1);
        assert_eq!(chunk.required_padding_len(), 3);
        assert_eq!(chunk.encoded_padding_len(), 1);
        assert_eq!(chunk.encoded_len(), SCTP_CHUNK_HEADER_LEN + 4);
    }

    #[test]
    fn sctp_decode_chunks_walks_declared_lengths_and_preserves_padding() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_COOKIE_ECHO,
            0x03,
            0x00,
            0x05,
            0xaa,
            0x00,
            0xbb,
            0xcc,
            SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4,
            0x80,
            0x00,
            0x04,
            SCTP_CHUNK_TYPE_COOKIE_ECHO,
            0x01,
            0x00,
            0x07,
            0x11,
            0x22,
            0x33,
            0xdd,
        ];

        let chunks = decode_chunks(bytes)?;

        assert_eq!(chunks.len(), 3);
        assert!(matches!(chunks[0], SctpChunk::CookieEcho(_)));
        assert_eq!(chunks[0].chunk_type_value(), SCTP_CHUNK_TYPE_COOKIE_ECHO);
        assert_eq!(chunks[0].flags(), 0x03);
        assert_eq!(chunks[0].explicit_declared_length(), Some(5));
        assert_eq!(chunks[0].value(), &[0xaa]);
        assert_eq!(chunks[0].padding(), &[0x00, 0xbb, 0xcc]);
        assert_eq!(chunks[0].encoded_len(), 8);

        assert!(matches!(chunks[1], SctpChunk::Unknown(_)));
        assert_eq!(
            chunks[1].chunk_type_value(),
            SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4
        );
        assert_eq!(chunks[1].flags(), 0x80);
        assert_eq!(chunks[1].explicit_declared_length(), Some(4));
        assert_eq!(chunks[1].value(), &[]);
        assert_eq!(chunks[1].padding(), &[]);

        assert!(matches!(chunks[2], SctpChunk::CookieEcho(_)));
        assert_eq!(chunks[2].chunk_type_value(), SCTP_CHUNK_TYPE_COOKIE_ECHO);
        assert_eq!(chunks[2].flags(), 0x01);
        assert_eq!(chunks[2].explicit_declared_length(), Some(7));
        assert_eq!(chunks[2].value(), &[0x11, 0x22, 0x33]);
        assert_eq!(chunks[2].padding(), &[0xdd]);
        Ok(())
    }

    #[test]
    fn sctp_encode_chunks_writes_envelopes_and_auto_zero_padding() -> Result<()> {
        let chunks = vec![
            SctpCookieEchoChunk::new([0xaa]).with_flags(0x03).into(),
            SctpChunk::from_preserved_parts(
                SCTP_CHUNK_TYPE_COOKIE_ECHO,
                0x01,
                7,
                [0x11, 0x22, 0x33],
                [],
            ),
            SctpChunk::unknown(SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4, 0x80, []),
        ];
        let mut bytes = Vec::new();

        encode_chunks(&chunks, &mut bytes)?;

        assert_eq!(
            bytes,
            [
                SCTP_CHUNK_TYPE_COOKIE_ECHO,
                0x03,
                0x00,
                0x05,
                0xaa,
                0x00,
                0x00,
                0x00,
                SCTP_CHUNK_TYPE_COOKIE_ECHO,
                0x01,
                0x00,
                0x07,
                0x11,
                0x22,
                0x33,
                0x00,
                SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4,
                0x80,
                0x00,
                0x04,
            ]
        );

        let decoded = decode_chunks(&bytes)?;
        assert_eq!(decoded.len(), chunks.len());
        assert_eq!(decoded[0].explicit_declared_length(), Some(5));
        assert_eq!(decoded[0].padding(), &[0x00, 0x00, 0x00]);
        assert_eq!(decoded[1].explicit_declared_length(), Some(7));
        assert_eq!(decoded[1].padding(), &[0x00]);
        assert_eq!(decoded[2].explicit_declared_length(), Some(4));
        assert_eq!(decoded[2].padding(), &[]);
        Ok(())
    }

    #[test]
    fn sctp_data_chunk_constructor_encodes_semantic_fields_and_raw_flags() -> Result<()> {
        let chunk = SctpDataChunk::from_data_parts(
            0x8f,
            0x0102_0304,
            0x0506,
            0x0708,
            0x090a_0b0c,
            [0xde, 0xad],
        );

        assert_eq!(chunk.flags(), 0x8f);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 14);
        assert_eq!(
            chunk.value(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0xde, 0xad,]
        );
        assert_eq!(chunk.tsn()?, 0x0102_0304);
        assert_eq!(chunk.transmission_sequence_number()?, 0x0102_0304);
        assert_eq!(chunk.stream_id()?, 0x0506);
        assert_eq!(chunk.stream_identifier()?, 0x0506);
        assert_eq!(chunk.stream_sequence_number()?, 0x0708);
        assert_eq!(chunk.ppid()?, 0x090a_0b0c);
        assert_eq!(chunk.payload_protocol_identifier()?, 0x090a_0b0c);
        assert_eq!(chunk.user_data()?, &[0xde, 0xad]);
        Ok(())
    }

    #[test]
    fn sctp_ppid_classification_data_and_idata_helpers_preserve_numeric_values() -> Result<()> {
        let data = SctpDataChunk::from_data(
            0x0102_0304,
            0x0506,
            0x0708,
            SCTP_PPID_WEBRTC_DCEP,
            [0xde, 0xad],
        );
        assert_eq!(data.ppid()?, SCTP_PPID_WEBRTC_DCEP);
        assert_eq!(data.ppid_status()?, SctpPpidStatus::Assigned);
        assert_eq!(data.ppid_name()?, Some("WebRTC DCEP"));

        let unassigned = SctpDataChunk::from_data(0x0102_0304, 0x0506, 0x0708, 26, [0xde, 0xad]);
        assert_eq!(unassigned.payload_protocol_identifier()?, 26);
        assert_eq!(
            unassigned.payload_protocol_identifier_status()?,
            SctpPpidStatus::Unassigned
        );
        assert_eq!(unassigned.payload_protocol_identifier_name()?, None);

        let first = SctpIDataChunk::from_idata_parts(
            SCTP_IDATA_FLAG_BEGIN,
            0x0102_0304,
            0x0506,
            0,
            0x0708_090a,
            SCTP_PPID_DTLS_CHUNK_KEY_MANAGEMENT,
            [0xde, 0xad],
        );
        assert_eq!(first.ppid()?, Some(SCTP_PPID_DTLS_CHUNK_KEY_MANAGEMENT));
        assert_eq!(first.ppid_status()?, Some(SctpPpidStatus::Draft));
        assert_eq!(
            first.ppid_name()?,
            Some("DTLS Chunk Key-Management Messages")
        );

        let middle = SctpIDataChunk::from_idata(
            0x0102_0304,
            0x0506,
            0x0708_090a,
            SCTP_PPID_DTLS_CHUNK_KEY_MANAGEMENT,
            [0xde, 0xad],
        );
        assert_eq!(middle.ppid()?, None);
        assert_eq!(middle.ppid_status()?, None);
        assert_eq!(middle.ppid_name()?, None);
        assert_eq!(
            middle.fragment_sequence_number()?,
            Some(SCTP_PPID_DTLS_CHUNK_KEY_MANAGEMENT)
        );
        Ok(())
    }

    #[test]
    fn sctp_data_chunk_decode_exposes_semantic_fields_and_preserved_padding() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_DATA,
            0x0f,
            0x00,
            0x13,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0xde,
            0xad,
            0xbe,
            0xee,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::Data(data) = &chunks[0] else {
            panic!("DATA codepoint must decode as SctpDataChunk");
        };

        assert_eq!(data.flags(), 0x0f);
        assert_eq!(data.explicit_declared_length(), Some(19));
        assert_eq!(data.padding(), &[0xee]);
        assert_eq!(data.tsn()?, 0x0102_0304);
        assert_eq!(data.stream_id()?, 0x0506);
        assert_eq!(data.stream_sequence_number()?, 0x0708);
        assert_eq!(data.ppid()?, 0x090a_0b0c);
        assert_eq!(data.user_data()?, &[0xde, 0xad, 0xbe]);
        Ok(())
    }

    #[test]
    fn sctp_data_chunk_decode_rejects_short_semantic_value() {
        let bytes = [
            SCTP_CHUNK_TYPE_DATA,
            0x00,
            0x00,
            0x0f,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x00,
        ];

        assert_eq!(
            decode_chunks(bytes).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_DATA_CHUNK_VALUE_CONTEXT,
                SCTP_DATA_CHUNK_VALUE_HEADER_LEN,
                11,
            )
        );
    }

    #[test]
    fn sctp_data_chunk_raw_constructor_preserves_short_value_until_semantic_access() {
        let chunk = SctpDataChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.tsn().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_DATA_CHUNK_VALUE_CONTEXT,
                SCTP_DATA_CHUNK_VALUE_HEADER_LEN,
                1,
            )
        );
    }

    #[test]
    fn sctp_data_flags_constants_match_source_notes() {
        assert_eq!(SCTP_DATA_FLAG_END, 0x01);
        assert_eq!(SCTP_DATA_FLAG_BEGIN, 0x02);
        assert_eq!(SCTP_DATA_FLAG_UNORDERED, 0x04);
        assert_eq!(SCTP_DATA_FLAG_SACK_IMMEDIATELY, 0x08);
        assert_eq!(SCTP_DATA_FLAG_E, SCTP_DATA_FLAG_END);
        assert_eq!(SCTP_DATA_FLAG_B, SCTP_DATA_FLAG_BEGIN);
        assert_eq!(SCTP_DATA_FLAG_U, SCTP_DATA_FLAG_UNORDERED);
        assert_eq!(SCTP_DATA_FLAG_I, SCTP_DATA_FLAG_SACK_IMMEDIATELY);
    }

    #[test]
    fn sctp_data_flags_helpers_preserve_raw_bits_and_compose() {
        let raw_bits = 0xf0;

        let all_named = SctpDataChunk::new([])
            .with_flags(raw_bits)
            .unordered()
            .begin()
            .end()
            .sack_immediately();
        assert_eq!(all_named.flags(), raw_bits | 0x0f);

        let complete_unordered_immediate = SctpDataChunk::new([])
            .with_flags(raw_bits | SCTP_DATA_FLAG_UNORDERED | SCTP_DATA_FLAG_SACK_IMMEDIATELY)
            .complete_message();
        assert_eq!(complete_unordered_immediate.flags(), raw_bits | 0x0f);

        let middle_fragment = SctpDataChunk::new([])
            .with_flags(raw_bits | 0x0f)
            .fragmented_message();
        assert_eq!(
            middle_fragment.flags(),
            raw_bits | SCTP_DATA_FLAG_UNORDERED | SCTP_DATA_FLAG_SACK_IMMEDIATELY
        );

        let first_fragment = middle_fragment.clone().begin();
        assert_eq!(
            first_fragment.flags(),
            raw_bits
                | SCTP_DATA_FLAG_BEGIN
                | SCTP_DATA_FLAG_UNORDERED
                | SCTP_DATA_FLAG_SACK_IMMEDIATELY
        );

        let last_fragment = middle_fragment.end();
        assert_eq!(
            last_fragment.flags(),
            raw_bits
                | SCTP_DATA_FLAG_END
                | SCTP_DATA_FLAG_UNORDERED
                | SCTP_DATA_FLAG_SACK_IMMEDIATELY
        );
    }

    #[test]
    fn sctp_data_flags_setters_and_raw_flags_remain_escape_hatches() {
        let base = 0xf0 | SCTP_DATA_FLAG_END | SCTP_DATA_FLAG_BEGIN;

        let cleared = SctpDataChunk::new([])
            .with_flags(base)
            .set_begin(false)
            .set_end(false);
        assert_eq!(cleared.flags(), 0xf0);

        let toggled = SctpDataChunk::new([])
            .with_flags(0)
            .set_unordered(true)
            .set_sack_immediately(true)
            .set_unordered(false);
        assert_eq!(toggled.flags(), SCTP_DATA_FLAG_SACK_IMMEDIATELY);

        let raw_override = SctpDataChunk::new([])
            .complete_message()
            .sack_immediately()
            .with_flags(0xa0);
        assert_eq!(raw_override.flags(), 0xa0);

        let raw_bit_toggle = SctpDataChunk::new([])
            .with_flags(0xa0)
            .flag(0x40, false)
            .flag(0x20, true)
            .unordered();
        assert_eq!(
            raw_bit_toggle.flags(),
            0x80 | 0x20 | SCTP_DATA_FLAG_UNORDERED
        );
    }

    #[test]
    fn sctp_init_chunk_constructor_encodes_semantic_fields_parameters_and_raw_flags() -> Result<()>
    {
        let parameters = [0x00, 0x05, 0x00, 0x08, 192, 0, 2, 1];
        let chunk = SctpInitChunk::from_init_parts(
            0xa5,
            0x1122_3344,
            0x0000_4000,
            0x0102,
            0x0304,
            0x5566_7788,
            parameters,
        );

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_INIT);
        assert_eq!(chunk.flags(), 0xa5);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 24);
        assert_eq!(
            chunk.value(),
            &[
                0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x40, 0x00, 0x01, 0x02, 0x03, 0x04, 0x55, 0x66,
                0x77, 0x88, 0x00, 0x05, 0x00, 0x08, 192, 0, 2, 1,
            ]
        );
        assert_eq!(chunk.initiate_tag()?, 0x1122_3344);
        assert_eq!(chunk.advertised_receiver_window_credit()?, 0x0000_4000);
        assert_eq!(chunk.a_rwnd()?, 0x0000_4000);
        assert_eq!(chunk.outbound_streams()?, 0x0102);
        assert_eq!(chunk.number_of_outbound_streams()?, 0x0102);
        assert_eq!(chunk.inbound_streams()?, 0x0304);
        assert_eq!(chunk.number_of_inbound_streams()?, 0x0304);
        assert_eq!(chunk.initial_tsn()?, 0x5566_7788);
        assert_eq!(chunk.initial_transmission_sequence_number()?, 0x5566_7788);
        assert_eq!(chunk.parameters()?, &parameters);
        assert_eq!(chunk.parameter_bytes()?, &parameters);

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::Init(_)));
        assert_eq!(enum_chunk.value_len(), 24);
        Ok(())
    }

    #[test]
    fn sctp_init_chunk_decode_exposes_semantic_fields_parameters_and_preserved_padding(
    ) -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_INIT,
            0x5a,
            0x00,
            0x1d,
            0x11,
            0x22,
            0x33,
            0x44,
            0x00,
            0x00,
            0x40,
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x55,
            0x66,
            0x77,
            0x88,
            0x00,
            0x05,
            0x00,
            0x09,
            192,
            0,
            2,
            1,
            0xee,
            0xaa,
            0xbb,
            0xcc,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::Init(init) = &chunks[0] else {
            panic!("INIT codepoint must decode as SctpInitChunk");
        };

        assert_eq!(init.flags(), 0x5a);
        assert_eq!(init.explicit_declared_length(), Some(29));
        assert_eq!(init.padding(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(init.initiate_tag()?, 0x1122_3344);
        assert_eq!(init.a_rwnd()?, 0x0000_4000);
        assert_eq!(init.outbound_streams()?, 0x0102);
        assert_eq!(init.inbound_streams()?, 0x0304);
        assert_eq!(init.initial_tsn()?, 0x5566_7788);
        assert_eq!(
            init.parameters()?,
            &[0x00, 0x05, 0x00, 0x09, 192, 0, 2, 1, 0xee]
        );
        Ok(())
    }

    #[test]
    fn sctp_init_chunk_decode_rejects_short_semantic_value() {
        let bytes = [
            SCTP_CHUNK_TYPE_INIT,
            0x00,
            0x00,
            0x13,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x00,
        ];

        assert_eq!(
            decode_chunks(bytes).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_INIT_CHUNK_VALUE_CONTEXT,
                SCTP_INIT_CHUNK_VALUE_HEADER_LEN,
                15,
            )
        );
    }

    #[test]
    fn sctp_init_chunk_raw_constructor_preserves_short_value_until_semantic_access() {
        let chunk = SctpInitChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.initiate_tag().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_INIT_CHUNK_VALUE_CONTEXT,
                SCTP_INIT_CHUNK_VALUE_HEADER_LEN,
                1,
            )
        );
    }

    #[test]
    fn sctp_init_chunk_preserves_explicit_length_padding_and_malformed_raw_value() {
        let chunk = SctpInitChunk::from_init(1, 2, 3, 4, 5)
            .with_declared_length(7)
            .with_padding([0xee, 0xff])
            .with_value([0xaa]);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_INIT);
        assert_eq!(chunk.explicit_declared_length(), Some(7));
        assert_eq!(chunk.length(), 7);
        assert_eq!(chunk.padding(), &[0xee, 0xff]);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(
            chunk.initial_tsn().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_INIT_CHUNK_VALUE_CONTEXT,
                SCTP_INIT_CHUNK_VALUE_HEADER_LEN,
                1,
            )
        );

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::Init(_)));
        assert_eq!(enum_chunk.explicit_declared_length(), Some(7));
    }

    #[test]
    fn sctp_init_chunk_with_init_replaces_semantic_value_and_keeps_flags() -> Result<()> {
        let chunk = SctpInitChunk::new([]).with_flags(0xa0).with_init(
            0x0102_0304,
            0x0506_0708,
            0x090a,
            0x0b0c,
            0x0d0e_0f10,
            [0xde, 0xad],
        );

        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.initiate_tag()?, 0x0102_0304);
        assert_eq!(chunk.a_rwnd()?, 0x0506_0708);
        assert_eq!(chunk.outbound_streams()?, 0x090a);
        assert_eq!(chunk.inbound_streams()?, 0x0b0c);
        assert_eq!(chunk.initial_tsn()?, 0x0d0e_0f10);
        assert_eq!(chunk.parameters()?, &[0xde, 0xad]);
        Ok(())
    }

    #[test]
    fn sctp_init_ack_chunk_constructor_encodes_semantic_fields_parameters_and_raw_flags(
    ) -> Result<()> {
        let parameters = [0x00, 0x07, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef];
        let chunk = SctpInitAckChunk::from_init_ack_parts(
            0xa5,
            0x1122_3344,
            0x0000_4000,
            0x0102,
            0x0304,
            0x5566_7788,
            parameters,
        );

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_INIT_ACK);
        assert_eq!(chunk.flags(), 0xa5);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 24);
        assert_eq!(
            chunk.value(),
            &[
                0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x40, 0x00, 0x01, 0x02, 0x03, 0x04, 0x55, 0x66,
                0x77, 0x88, 0x00, 0x07, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef,
            ]
        );
        assert_eq!(chunk.initiate_tag()?, 0x1122_3344);
        assert_eq!(chunk.advertised_receiver_window_credit()?, 0x0000_4000);
        assert_eq!(chunk.a_rwnd()?, 0x0000_4000);
        assert_eq!(chunk.outbound_streams()?, 0x0102);
        assert_eq!(chunk.number_of_outbound_streams()?, 0x0102);
        assert_eq!(chunk.inbound_streams()?, 0x0304);
        assert_eq!(chunk.number_of_inbound_streams()?, 0x0304);
        assert_eq!(chunk.initial_tsn()?, 0x5566_7788);
        assert_eq!(chunk.initial_transmission_sequence_number()?, 0x5566_7788);
        assert_eq!(chunk.parameters()?, &parameters);
        assert_eq!(chunk.parameter_bytes()?, &parameters);

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::InitAck(_)));
        assert_eq!(enum_chunk.value_len(), 24);
        Ok(())
    }

    #[test]
    fn sctp_init_ack_chunk_decode_exposes_semantic_fields_parameters_and_preserved_padding(
    ) -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_INIT_ACK,
            0x5a,
            0x00,
            0x1d,
            0x11,
            0x22,
            0x33,
            0x44,
            0x00,
            0x00,
            0x40,
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x55,
            0x66,
            0x77,
            0x88,
            0x00,
            0x07,
            0x00,
            0x09,
            0xde,
            0xad,
            0xbe,
            0xef,
            0xee,
            0xaa,
            0xbb,
            0xcc,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::InitAck(init_ack) = &chunks[0] else {
            panic!("INIT ACK codepoint must decode as SctpInitAckChunk");
        };

        assert_eq!(init_ack.flags(), 0x5a);
        assert_eq!(init_ack.explicit_declared_length(), Some(29));
        assert_eq!(init_ack.padding(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(init_ack.initiate_tag()?, 0x1122_3344);
        assert_eq!(init_ack.a_rwnd()?, 0x0000_4000);
        assert_eq!(init_ack.outbound_streams()?, 0x0102);
        assert_eq!(init_ack.inbound_streams()?, 0x0304);
        assert_eq!(init_ack.initial_tsn()?, 0x5566_7788);
        assert_eq!(
            init_ack.parameters()?,
            &[0x00, 0x07, 0x00, 0x09, 0xde, 0xad, 0xbe, 0xef, 0xee]
        );
        Ok(())
    }

    #[test]
    fn sctp_init_ack_chunk_decode_rejects_short_semantic_value() {
        let bytes = [
            SCTP_CHUNK_TYPE_INIT_ACK,
            0x00,
            0x00,
            0x13,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x00,
        ];

        assert_eq!(
            decode_chunks(bytes).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_INIT_ACK_CHUNK_VALUE_CONTEXT,
                SCTP_INIT_ACK_CHUNK_VALUE_HEADER_LEN,
                15,
            )
        );
    }

    #[test]
    fn sctp_init_ack_chunk_raw_constructor_preserves_short_value_until_semantic_access() {
        let chunk = SctpInitAckChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.initiate_tag().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_INIT_ACK_CHUNK_VALUE_CONTEXT,
                SCTP_INIT_ACK_CHUNK_VALUE_HEADER_LEN,
                1,
            )
        );
    }

    #[test]
    fn sctp_init_ack_chunk_preserves_explicit_length_padding_and_malformed_raw_value() {
        let chunk = SctpInitAckChunk::from_init_ack(1, 2, 3, 4, 5)
            .with_declared_length(7)
            .with_padding([0xee, 0xff])
            .with_value([0xaa]);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_INIT_ACK);
        assert_eq!(chunk.explicit_declared_length(), Some(7));
        assert_eq!(chunk.length(), 7);
        assert_eq!(chunk.padding(), &[0xee, 0xff]);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(
            chunk.initial_tsn().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_INIT_ACK_CHUNK_VALUE_CONTEXT,
                SCTP_INIT_ACK_CHUNK_VALUE_HEADER_LEN,
                1,
            )
        );

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::InitAck(_)));
        assert_eq!(enum_chunk.explicit_declared_length(), Some(7));
    }

    #[test]
    fn sctp_init_ack_chunk_with_init_ack_replaces_semantic_value_and_keeps_flags() -> Result<()> {
        let chunk = SctpInitAckChunk::new([]).with_flags(0xa0).with_init_ack(
            0x0102_0304,
            0x0506_0708,
            0x090a,
            0x0b0c,
            0x0d0e_0f10,
            [0xde, 0xad],
        );

        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.initiate_tag()?, 0x0102_0304);
        assert_eq!(chunk.a_rwnd()?, 0x0506_0708);
        assert_eq!(chunk.outbound_streams()?, 0x090a);
        assert_eq!(chunk.inbound_streams()?, 0x0b0c);
        assert_eq!(chunk.initial_tsn()?, 0x0d0e_0f10);
        assert_eq!(chunk.parameters()?, &[0xde, 0xad]);
        Ok(())
    }

    #[test]
    fn sctp_sack_chunk_constructor_encodes_semantic_fields_and_raw_flags() -> Result<()> {
        let gap_ack_blocks = [
            SctpSackGapAckBlock::new(1, 3),
            SctpSackGapAckBlock::new(5, 5),
        ];
        let duplicate_tsns = [0x0102_0304, 0x0506_0708];
        let chunk = SctpSackChunk::try_from_sack_parts(
            0xa0,
            0x1122_3344,
            0x0000_4000,
            gap_ack_blocks,
            duplicate_tsns,
        )?;

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_SACK);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 28);
        assert_eq!(
            chunk.value(),
            &[
                0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x40, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x01,
                0x00, 0x03, 0x00, 0x05, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            ]
        );
        assert_eq!(chunk.cumulative_tsn_ack()?, 0x1122_3344);
        assert_eq!(
            chunk.cumulative_transmission_sequence_number_ack()?,
            0x1122_3344
        );
        assert_eq!(chunk.advertised_receiver_window_credit()?, 0x0000_4000);
        assert_eq!(chunk.a_rwnd()?, 0x0000_4000);
        assert_eq!(chunk.gap_ack_block_count()?, 2);
        assert_eq!(chunk.number_of_gap_ack_blocks()?, 2);
        assert_eq!(chunk.duplicate_tsn_count()?, 2);
        assert_eq!(chunk.number_of_duplicate_tsns()?, 2);
        assert_eq!(chunk.gap_ack_blocks()?, gap_ack_blocks);
        assert_eq!(chunk.duplicate_tsns()?, duplicate_tsns);

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::Sack(_)));
        assert_eq!(enum_chunk.value_len(), 28);
        Ok(())
    }

    #[test]
    fn sctp_sack_chunk_decode_exposes_semantic_fields_and_counts() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_SACK,
            0x5a,
            0x00,
            0x20,
            0x11,
            0x22,
            0x33,
            0x44,
            0x00,
            0x00,
            0x40,
            0x00,
            0x00,
            0x02,
            0x00,
            0x02,
            0x00,
            0x01,
            0x00,
            0x03,
            0x00,
            0x05,
            0x00,
            0x05,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::Sack(sack) = &chunks[0] else {
            panic!("SACK codepoint must decode as SctpSackChunk");
        };

        assert_eq!(sack.flags(), 0x5a);
        assert_eq!(sack.explicit_declared_length(), Some(32));
        assert_eq!(sack.cumulative_tsn_ack()?, 0x1122_3344);
        assert_eq!(sack.a_rwnd()?, 0x0000_4000);
        assert_eq!(sack.gap_ack_block_count()?, 2);
        assert_eq!(sack.duplicate_tsn_count()?, 2);
        assert_eq!(
            sack.gap_ack_blocks()?,
            [
                SctpSackGapAckBlock::new(1, 3),
                SctpSackGapAckBlock::new(5, 5)
            ]
        );
        assert_eq!(sack.duplicate_tsns()?, [0x0102_0304, 0x0506_0708]);
        Ok(())
    }

    #[test]
    fn sctp_sack_chunk_decode_rejects_short_semantic_value() {
        let bytes = [
            SCTP_CHUNK_TYPE_SACK,
            0x00,
            0x00,
            0x0f,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x00,
        ];

        assert_eq!(
            decode_chunks(bytes).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_SACK_CHUNK_VALUE_CONTEXT,
                SCTP_SACK_CHUNK_VALUE_HEADER_LEN,
                11,
            )
        );
    }

    #[test]
    fn sctp_sack_chunk_decode_rejects_count_length_mismatch() {
        let short_for_counts = [
            SCTP_CHUNK_TYPE_SACK,
            0x00,
            0x00,
            0x14,
            0x11,
            0x22,
            0x33,
            0x44,
            0x00,
            0x00,
            0x40,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,
            0x03,
        ];

        assert_eq!(
            decode_chunks(short_for_counts).unwrap_err(),
            CrafterError::buffer_too_short(SCTP_SACK_CHUNK_VALUE_CONTEXT, 20, 16)
        );

        let extra_after_counts = [
            SCTP_CHUNK_TYPE_SACK,
            0x00,
            0x00,
            0x14,
            0x11,
            0x22,
            0x33,
            0x44,
            0x00,
            0x00,
            0x40,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xde,
            0xad,
            0xbe,
            0xef,
        ];

        assert_eq!(
            decode_chunks(extra_after_counts).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_SACK_CHUNK_VALUE_CONTEXT,
                "value length must match gap ack block and duplicate TSN counts",
            )
        );
    }

    #[test]
    fn sctp_sack_chunk_raw_constructor_preserves_short_value_until_semantic_access() {
        let chunk = SctpSackChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.cumulative_tsn_ack().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_SACK_CHUNK_VALUE_CONTEXT,
                SCTP_SACK_CHUNK_VALUE_HEADER_LEN,
                1,
            )
        );
    }

    #[test]
    fn sctp_sack_chunk_try_constructor_rejects_count_overflow() {
        let too_many_gap_ack_blocks =
            vec![SctpSackGapAckBlock::new(1, 1); usize::from(u16::MAX) + 1];

        assert_eq!(
            SctpSackChunk::try_from_sack(1, 2, too_many_gap_ack_blocks, []).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_SACK_CHUNK_GAP_ACK_BLOCK_COUNT_FIELD,
                "count must fit in two bytes",
            )
        );
    }

    #[test]
    fn sctp_sack_chunk_try_with_sack_replaces_value_and_keeps_flags() -> Result<()> {
        let chunk = SctpSackChunk::new([]).with_flags(0xa0).try_with_sack(
            0x0102_0304,
            0x0506_0708,
            [SctpSackGapAckBlock::new(9, 10)],
            [0x0d0e_0f10],
        )?;

        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.cumulative_tsn_ack()?, 0x0102_0304);
        assert_eq!(chunk.a_rwnd()?, 0x0506_0708);
        assert_eq!(chunk.gap_ack_blocks()?, [SctpSackGapAckBlock::new(9, 10)]);
        assert_eq!(chunk.duplicate_tsns()?, [0x0d0e_0f10]);
        Ok(())
    }

    #[test]
    fn sctp_heartbeat_chunk_constructor_encodes_info_parameter_and_raw_flags() -> Result<()> {
        let chunk = SctpHeartbeatChunk::try_from_heartbeat_info_parts(0xa0, [0xde, 0xad, 0xbe])?;

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_HEARTBEAT);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 8);
        assert_eq!(
            chunk.value(),
            &[0x00, 0x01, 0x00, 0x07, 0xde, 0xad, 0xbe, 0x00]
        );
        assert_eq!(
            chunk.heartbeat_info_parameter_bytes()?,
            &[0x00, 0x01, 0x00, 0x07, 0xde, 0xad, 0xbe, 0x00]
        );
        assert_eq!(chunk.heartbeat_info()?, &[0xde, 0xad, 0xbe]);

        let parameter = chunk.heartbeat_info_parameter()?;
        assert_eq!(
            parameter.parameter_type_value(),
            SCTP_PARAMETER_TYPE_HEARTBEAT_INFO
        );
        assert_eq!(parameter.explicit_declared_length(), Some(7));
        assert_eq!(parameter.value(), &[0xde, 0xad, 0xbe]);
        assert_eq!(parameter.padding(), &[0x00]);

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::Heartbeat(_)));
        assert_eq!(enum_chunk.value_len(), 8);
        Ok(())
    }

    #[test]
    fn sctp_heartbeat_chunk_decode_exposes_info_parameter_and_preserved_padding() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_HEARTBEAT,
            0x5a,
            0x00,
            0x0c,
            0x00,
            0x01,
            0x00,
            0x07,
            0xde,
            0xad,
            0xbe,
            0xcc,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::Heartbeat(heartbeat) = &chunks[0] else {
            panic!("HEARTBEAT codepoint must decode as SctpHeartbeatChunk");
        };

        assert_eq!(heartbeat.flags(), 0x5a);
        assert_eq!(heartbeat.explicit_declared_length(), Some(12));
        assert_eq!(heartbeat.heartbeat_info()?, &[0xde, 0xad, 0xbe]);
        let parameter = heartbeat.heartbeat_info_parameter()?;
        assert_eq!(parameter.explicit_declared_length(), Some(7));
        assert_eq!(parameter.value(), &[0xde, 0xad, 0xbe]);
        assert_eq!(parameter.padding(), &[0xcc]);
        Ok(())
    }

    #[test]
    fn sctp_heartbeat_chunk_decode_rejects_short_or_wrong_parameter() {
        let short_value = [
            SCTP_CHUNK_TYPE_HEARTBEAT,
            0x00,
            0x00,
            0x07,
            0x00,
            0x01,
            0x00,
            0x00,
        ];

        assert_eq!(
            decode_chunks(short_value).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_HEARTBEAT_CHUNK_VALUE_CONTEXT,
                SCTP_PARAMETER_HEADER_LEN,
                3,
            )
        );

        let wrong_type = [
            SCTP_CHUNK_TYPE_HEARTBEAT,
            0x00,
            0x00,
            0x08,
            0x00,
            0x05,
            0x00,
            0x04,
        ];

        assert_eq!(
            decode_chunks(wrong_type).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_HEARTBEAT_INFO_PARAMETER_FIELD,
                "parameter type must be Heartbeat Info",
            )
        );
    }

    #[test]
    fn sctp_heartbeat_chunk_decode_rejects_invalid_length_or_extra_parameter() {
        let invalid_parameter_length = [
            SCTP_CHUNK_TYPE_HEARTBEAT,
            0x00,
            0x00,
            0x08,
            0x00,
            0x01,
            0x00,
            0x03,
        ];

        assert_eq!(
            decode_chunks(invalid_parameter_length).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_HEARTBEAT_INFO_PARAMETER_FIELD,
                "declared length must be at least 4 bytes",
            )
        );

        let extra_parameter = [
            SCTP_CHUNK_TYPE_HEARTBEAT,
            0x00,
            0x00,
            0x0c,
            0x00,
            0x01,
            0x00,
            0x04,
            0x00,
            0x01,
            0x00,
            0x04,
        ];

        assert_eq!(
            decode_chunks(extra_parameter).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_HEARTBEAT_CHUNK_VALUE_CONTEXT,
                "HEARTBEAT chunk must contain exactly one Heartbeat Info parameter",
            )
        );
    }

    #[test]
    fn sctp_heartbeat_chunk_raw_constructor_preserves_short_value_until_semantic_access() {
        let chunk = SctpHeartbeatChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.heartbeat_info().unwrap_err(),
            CrafterError::buffer_too_short(SCTP_HEARTBEAT_CHUNK_VALUE_CONTEXT, 4, 1)
        );
    }

    #[test]
    fn sctp_heartbeat_chunk_try_builder_rejects_parameter_length_overflow() {
        let oversized_info = vec![0; usize::from(u16::MAX) - SCTP_PARAMETER_HEADER_LEN + 1];

        assert_eq!(
            SctpHeartbeatChunk::try_from_heartbeat_info(oversized_info).unwrap_err(),
            CrafterError::invalid_field_value(
                "sctp.parameter.length",
                "length must fit in two bytes",
            )
        );
    }

    #[test]
    fn sctp_heartbeat_chunk_raw_parameter_bytes_and_try_with_info_keep_flags() -> Result<()> {
        let raw = SctpHeartbeatChunk::from_heartbeat_info_parameter_bytes([
            0x00, 0x01, 0x00, 0x05, 0xaa, 0xbb, 0xcc, 0xdd,
        ]);
        assert_eq!(raw.heartbeat_info()?, &[0xaa]);
        assert_eq!(
            raw.heartbeat_info_parameter()?.padding(),
            &[0xbb, 0xcc, 0xdd]
        );

        let updated = raw.with_flags(0xa0).try_with_heartbeat_info([0xde, 0xad])?;
        assert_eq!(updated.flags(), 0xa0);
        assert_eq!(updated.heartbeat_info()?, &[0xde, 0xad]);
        assert_eq!(
            updated.heartbeat_info_parameter_bytes()?,
            &[0x00, 0x01, 0x00, 0x06, 0xde, 0xad, 0x00, 0x00]
        );
        Ok(())
    }

    #[test]
    fn sctp_heartbeat_ack_chunk_constructor_encodes_info_parameter_and_raw_flags() -> Result<()> {
        let chunk = SctpHeartbeatAckChunk::try_from_heartbeat_info_parts(0xa0, [0xde, 0xad, 0xbe])?;

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_HEARTBEAT_ACK);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 8);
        assert_eq!(
            chunk.value(),
            &[0x00, 0x01, 0x00, 0x07, 0xde, 0xad, 0xbe, 0x00]
        );
        assert_eq!(
            chunk.heartbeat_info_parameter_bytes()?,
            &[0x00, 0x01, 0x00, 0x07, 0xde, 0xad, 0xbe, 0x00]
        );
        assert_eq!(chunk.heartbeat_info()?, &[0xde, 0xad, 0xbe]);

        let parameter = chunk.heartbeat_info_parameter()?;
        assert_eq!(parameter.explicit_declared_length(), Some(7));
        assert_eq!(parameter.value(), &[0xde, 0xad, 0xbe]);
        assert_eq!(parameter.padding(), &[0x00]);

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::HeartbeatAck(_)));
        assert_eq!(enum_chunk.value_len(), 8);
        Ok(())
    }

    #[test]
    fn sctp_heartbeat_ack_chunk_decode_exposes_info_parameter_and_preserved_padding() -> Result<()>
    {
        let bytes = [
            SCTP_CHUNK_TYPE_HEARTBEAT_ACK,
            0x5a,
            0x00,
            0x0c,
            0x00,
            0x01,
            0x00,
            0x07,
            0xde,
            0xad,
            0xbe,
            0xcc,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::HeartbeatAck(heartbeat_ack) = &chunks[0] else {
            panic!("HEARTBEAT ACK codepoint must decode as SctpHeartbeatAckChunk");
        };

        assert_eq!(heartbeat_ack.flags(), 0x5a);
        assert_eq!(heartbeat_ack.explicit_declared_length(), Some(12));
        assert_eq!(heartbeat_ack.heartbeat_info()?, &[0xde, 0xad, 0xbe]);
        let parameter = heartbeat_ack.heartbeat_info_parameter()?;
        assert_eq!(parameter.explicit_declared_length(), Some(7));
        assert_eq!(parameter.value(), &[0xde, 0xad, 0xbe]);
        assert_eq!(parameter.padding(), &[0xcc]);
        Ok(())
    }

    #[test]
    fn sctp_heartbeat_ack_chunk_decode_rejects_short_or_wrong_parameter() {
        let short_value = [
            SCTP_CHUNK_TYPE_HEARTBEAT_ACK,
            0x00,
            0x00,
            0x07,
            0x00,
            0x01,
            0x00,
            0x00,
        ];

        assert_eq!(
            decode_chunks(short_value).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_HEARTBEAT_ACK_CHUNK_VALUE_CONTEXT,
                SCTP_PARAMETER_HEADER_LEN,
                3,
            )
        );

        let wrong_type = [
            SCTP_CHUNK_TYPE_HEARTBEAT_ACK,
            0x00,
            0x00,
            0x08,
            0x00,
            0x05,
            0x00,
            0x04,
        ];

        assert_eq!(
            decode_chunks(wrong_type).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_HEARTBEAT_ACK_INFO_PARAMETER_FIELD,
                "parameter type must be Heartbeat Info",
            )
        );
    }

    #[test]
    fn sctp_heartbeat_ack_chunk_decode_rejects_invalid_length_or_extra_parameter() {
        let invalid_parameter_length = [
            SCTP_CHUNK_TYPE_HEARTBEAT_ACK,
            0x00,
            0x00,
            0x08,
            0x00,
            0x01,
            0x00,
            0x03,
        ];

        assert_eq!(
            decode_chunks(invalid_parameter_length).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_HEARTBEAT_ACK_INFO_PARAMETER_FIELD,
                "declared length must be at least 4 bytes",
            )
        );

        let extra_parameter = [
            SCTP_CHUNK_TYPE_HEARTBEAT_ACK,
            0x00,
            0x00,
            0x0c,
            0x00,
            0x01,
            0x00,
            0x04,
            0x00,
            0x01,
            0x00,
            0x04,
        ];

        assert_eq!(
            decode_chunks(extra_parameter).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_HEARTBEAT_ACK_CHUNK_VALUE_CONTEXT,
                "HEARTBEAT ACK chunk must contain exactly one Heartbeat Info parameter",
            )
        );
    }

    #[test]
    fn sctp_heartbeat_ack_chunk_raw_constructor_preserves_short_value_until_semantic_access() {
        let chunk = SctpHeartbeatAckChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.heartbeat_info().unwrap_err(),
            CrafterError::buffer_too_short(SCTP_HEARTBEAT_ACK_CHUNK_VALUE_CONTEXT, 4, 1)
        );
    }

    #[test]
    fn sctp_heartbeat_ack_chunk_try_builder_rejects_parameter_length_overflow() {
        let oversized_info = vec![0; usize::from(u16::MAX) - SCTP_PARAMETER_HEADER_LEN + 1];

        assert_eq!(
            SctpHeartbeatAckChunk::try_from_heartbeat_info(oversized_info).unwrap_err(),
            CrafterError::invalid_field_value(
                "sctp.parameter.length",
                "length must fit in two bytes",
            )
        );
    }

    #[test]
    fn sctp_heartbeat_ack_chunk_raw_parameter_bytes_and_try_with_info_keep_flags() -> Result<()> {
        let raw = SctpHeartbeatAckChunk::from_heartbeat_info_parameter_bytes([
            0x00, 0x01, 0x00, 0x05, 0xaa, 0xbb, 0xcc, 0xdd,
        ]);
        assert_eq!(raw.heartbeat_info()?, &[0xaa]);
        assert_eq!(
            raw.heartbeat_info_parameter()?.padding(),
            &[0xbb, 0xcc, 0xdd]
        );

        let updated = raw.with_flags(0xa0).try_with_heartbeat_info([0xde, 0xad])?;
        assert_eq!(updated.flags(), 0xa0);
        assert_eq!(updated.heartbeat_info()?, &[0xde, 0xad]);
        assert_eq!(
            updated.heartbeat_info_parameter_bytes()?,
            &[0x00, 0x01, 0x00, 0x06, 0xde, 0xad, 0x00, 0x00]
        );
        Ok(())
    }

    #[test]
    fn sctp_abort_chunk_flag_helpers_preserve_raw_bits_and_toggle_t_bit() {
        let raw_bits = 0xf0;

        let tagged = SctpAbortChunk::new([]).with_flags(raw_bits).t_bit();
        assert_eq!(tagged.flags(), raw_bits | SCTP_ABORT_FLAG_T);
        assert!(tagged.is_t_bit_set());

        let cleared = tagged.set_t_bit(false);
        assert_eq!(cleared.flags(), raw_bits);
        assert!(!cleared.is_t_bit_set());

        let raw_toggle = cleared.flag(0x40, false).flag(0x20, true).t_bit();
        assert_eq!(raw_toggle.flags(), 0x80 | 0x20 | 0x10 | SCTP_ABORT_FLAG_T);
    }

    #[test]
    fn sctp_abort_chunk_constructor_encodes_error_causes_and_t_bit() -> Result<()> {
        let causes = vec![
            SctpErrorCause::from_raw_parts(12, [0xde, 0xad], []),
            SctpErrorCause::unknown(0xbeef, []),
        ];
        let chunk = SctpAbortChunk::try_from_error_causes_parts(0xa0, &causes)?.t_bit();

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_ABORT);
        assert_eq!(chunk.flags(), 0xa0 | SCTP_ABORT_FLAG_T);
        assert!(chunk.is_t_bit_set());
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 12);
        assert_eq!(
            chunk.value(),
            &[0x00, 0x0c, 0x00, 0x06, 0xde, 0xad, 0x00, 0x00, 0xbe, 0xef, 0x00, 0x04,]
        );

        let decoded_causes = chunk.error_causes()?;
        assert_eq!(decoded_causes.len(), 2);
        assert!(matches!(
            decoded_causes[0],
            SctpErrorCause::UserInitiatedAbort(_)
        ));
        assert!(matches!(decoded_causes[1], SctpErrorCause::Unknown(_)));

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::Abort(_)));
        assert_eq!(enum_chunk.value_len(), 12);
        Ok(())
    }

    #[test]
    fn sctp_abort_chunk_decode_exposes_t_bit_and_preserved_error_causes() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_ABORT,
            0x5b,
            0x00,
            0x0c,
            0x00,
            0x0d,
            0x00,
            0x05,
            0xde,
            0xaa,
            0xbb,
            0xcc,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::Abort(abort) = &chunks[0] else {
            panic!("ABORT codepoint must decode as SctpAbortChunk");
        };

        assert_eq!(abort.flags(), 0x5b);
        assert!(abort.is_t_bit_set());
        assert_eq!(
            abort.error_cause_bytes(),
            &[0x00, 0x0d, 0x00, 0x05, 0xde, 0xaa, 0xbb, 0xcc]
        );

        let causes = abort.error_causes()?;
        let SctpErrorCause::ProtocolViolation(cause) = &causes[0] else {
            panic!("expected Protocol Violation cause");
        };
        assert_eq!(cause.explicit_declared_length(), Some(5));
        assert_eq!(cause.info(), &[0xde]);
        assert_eq!(cause.padding(), &[0xaa, 0xbb, 0xcc]);
        Ok(())
    }

    #[test]
    fn sctp_abort_chunk_decode_rejects_malformed_error_cause_sequence() {
        let bytes = [
            SCTP_CHUNK_TYPE_ABORT,
            0x00,
            0x00,
            0x08,
            0x00,
            0x01,
            0x00,
            0x03,
        ];

        assert_eq!(
            decode_chunks(bytes).unwrap_err(),
            CrafterError::invalid_field_value(
                "sctp.error_cause.length",
                "declared length must be at least 4 bytes",
            )
        );
    }

    #[test]
    fn sctp_abort_chunk_raw_constructor_preserves_malformed_causes_until_semantic_access() {
        let chunk = SctpAbortChunk::new([0x00, 0x01, 0x00]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.error_cause_bytes(), &[0x00, 0x01, 0x00]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 3);
        assert_eq!(
            chunk.error_causes().unwrap_err(),
            CrafterError::buffer_too_short("sctp.error_cause.header", 4, 3)
        );
    }

    #[test]
    fn sctp_abort_chunk_raw_bytes_and_try_with_error_causes_keep_flags() -> Result<()> {
        let raw = SctpAbortChunk::from_error_cause_bytes([0x00, 0x0d, 0x00, 0x04]);
        assert!(matches!(
            raw.error_causes()?[0],
            SctpErrorCause::ProtocolViolation(_)
        ));

        let causes = vec![SctpErrorCause::unknown(0xbeef, [0xaa])];
        let updated = raw.with_flags(0xa0).try_with_error_causes(&causes)?;
        assert_eq!(updated.flags(), 0xa0);
        assert_eq!(
            updated.error_cause_bytes(),
            &[0xbe, 0xef, 0x00, 0x05, 0xaa, 0x00, 0x00, 0x00]
        );
        Ok(())
    }

    #[test]
    fn sctp_error_chunk_constructor_encodes_error_causes_and_raw_flags() -> Result<()> {
        let causes = vec![
            SctpErrorCause::from_raw_parts(12, [0xde, 0xad], []),
            SctpErrorCause::unknown(0xbeef, []),
        ];
        let chunk = SctpErrorChunk::try_from_error_causes_parts(0xa0, &causes)?;

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_ERROR);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 12);
        assert_eq!(
            chunk.value(),
            &[0x00, 0x0c, 0x00, 0x06, 0xde, 0xad, 0x00, 0x00, 0xbe, 0xef, 0x00, 0x04,]
        );

        let decoded_causes = chunk.error_causes()?;
        assert_eq!(decoded_causes.len(), 2);
        assert!(matches!(
            decoded_causes[0],
            SctpErrorCause::UserInitiatedAbort(_)
        ));
        assert!(matches!(decoded_causes[1], SctpErrorCause::Unknown(_)));

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::Error(_)));
        assert_eq!(enum_chunk.value_len(), 12);
        Ok(())
    }

    #[test]
    fn sctp_error_chunk_decode_exposes_preserved_error_causes() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_ERROR,
            0x5a,
            0x00,
            0x0c,
            0x00,
            0x0d,
            0x00,
            0x05,
            0xde,
            0xaa,
            0xbb,
            0xcc,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::Error(error) = &chunks[0] else {
            panic!("ERROR codepoint must decode as SctpErrorChunk");
        };

        assert_eq!(error.flags(), 0x5a);
        assert_eq!(
            error.error_cause_bytes(),
            &[0x00, 0x0d, 0x00, 0x05, 0xde, 0xaa, 0xbb, 0xcc]
        );

        let causes = error.error_causes()?;
        let SctpErrorCause::ProtocolViolation(cause) = &causes[0] else {
            panic!("expected Protocol Violation cause");
        };
        assert_eq!(cause.explicit_declared_length(), Some(5));
        assert_eq!(cause.info(), &[0xde]);
        assert_eq!(cause.padding(), &[0xaa, 0xbb, 0xcc]);
        Ok(())
    }

    #[test]
    fn sctp_error_chunk_decode_rejects_malformed_error_cause_sequence() {
        let bytes = [
            SCTP_CHUNK_TYPE_ERROR,
            0x00,
            0x00,
            0x08,
            0x00,
            0x01,
            0x00,
            0x03,
        ];

        assert_eq!(
            decode_chunks(bytes).unwrap_err(),
            CrafterError::invalid_field_value(
                "sctp.error_cause.length",
                "declared length must be at least 4 bytes",
            )
        );
    }

    #[test]
    fn sctp_error_chunk_raw_constructor_preserves_malformed_causes_until_semantic_access() {
        let chunk = SctpErrorChunk::new([0x00, 0x01, 0x00]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.error_cause_bytes(), &[0x00, 0x01, 0x00]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 3);
        assert_eq!(
            chunk.error_causes().unwrap_err(),
            CrafterError::buffer_too_short("sctp.error_cause.header", 4, 3)
        );
    }

    #[test]
    fn sctp_error_chunk_raw_bytes_and_try_with_error_causes_keep_flags() -> Result<()> {
        let raw = SctpErrorChunk::from_error_cause_bytes([0x00, 0x0d, 0x00, 0x04]);
        assert!(matches!(
            raw.error_causes()?[0],
            SctpErrorCause::ProtocolViolation(_)
        ));

        let causes = vec![SctpErrorCause::unknown(0xbeef, [0xaa])];
        let updated = raw.with_flags(0xa0).try_with_error_causes(&causes)?;
        assert_eq!(updated.flags(), 0xa0);
        assert_eq!(
            updated.error_cause_bytes(),
            &[0xbe, 0xef, 0x00, 0x05, 0xaa, 0x00, 0x00, 0x00]
        );
        Ok(())
    }

    #[test]
    fn sctp_cookie_echo_chunk_preserves_cookie_bytes_and_raw_flags() {
        let chunk = SctpCookieEchoChunk::from_cookie([0xde, 0xad, 0xbe]).with_flags(0xa0);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_COOKIE_ECHO);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 3);
        assert_eq!(chunk.cookie(), &[0xde, 0xad, 0xbe]);
        assert_eq!(chunk.cookie_bytes(), &[0xde, 0xad, 0xbe]);
        assert_eq!(chunk.required_padding_len(), 1);
        assert_eq!(chunk.encoded_padding_len(), 1);

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::CookieEcho(_)));
        assert_eq!(enum_chunk.value(), &[0xde, 0xad, 0xbe]);
    }

    #[test]
    fn sctp_cookie_echo_chunk_decode_preserves_cookie_value_and_padding() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_COOKIE_ECHO,
            0x5a,
            0x00,
            0x07,
            0xde,
            0xad,
            0xbe,
            0xcc,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::CookieEcho(cookie_echo) = &chunks[0] else {
            panic!("COOKIE ECHO codepoint must decode as SctpCookieEchoChunk");
        };

        assert_eq!(cookie_echo.flags(), 0x5a);
        assert_eq!(cookie_echo.explicit_declared_length(), Some(7));
        assert_eq!(cookie_echo.cookie(), &[0xde, 0xad, 0xbe]);
        assert_eq!(cookie_echo.cookie_bytes(), &[0xde, 0xad, 0xbe]);
        assert_eq!(cookie_echo.padding(), &[0xcc]);
        Ok(())
    }

    #[test]
    fn sctp_cookie_echo_chunk_with_cookie_replaces_value_and_keeps_flags() {
        let chunk = SctpCookieEchoChunk::from_cookie([0xaa])
            .with_flags(0xf0)
            .with_cookie([0x01, 0x02, 0x03, 0x04]);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.cookie(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 4);
        assert_eq!(chunk.encoded_padding_len(), 0);
    }

    #[test]
    fn sctp_cookie_ack_chunk_constructor_uses_header_only_value_and_raw_flags() -> Result<()> {
        let chunk = SctpCookieAckChunk::from_cookie_ack_parts(0xa0);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_COOKIE_ACK);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN);
        assert_eq!(chunk.value(), &[]);
        chunk.validate_empty_value()?;

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::CookieAck(_)));
        assert_eq!(enum_chunk.value_len(), 0);
        Ok(())
    }

    #[test]
    fn sctp_cookie_ack_chunk_decode_accepts_header_only_value() -> Result<()> {
        let bytes = [SCTP_CHUNK_TYPE_COOKIE_ACK, 0x5a, 0x00, 0x04];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::CookieAck(cookie_ack) = &chunks[0] else {
            panic!("COOKIE ACK codepoint must decode as SctpCookieAckChunk");
        };

        assert_eq!(cookie_ack.flags(), 0x5a);
        assert_eq!(cookie_ack.explicit_declared_length(), Some(4));
        assert_eq!(cookie_ack.value(), &[]);
        cookie_ack.validate_empty_value()?;
        Ok(())
    }

    #[test]
    fn sctp_cookie_ack_chunk_decode_rejects_nonempty_value() {
        let bytes = [
            SCTP_CHUNK_TYPE_COOKIE_ACK,
            0x00,
            0x00,
            0x05,
            0xaa,
            0x00,
            0x00,
            0x00,
        ];

        assert_eq!(
            decode_chunks(bytes).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_COOKIE_ACK_CHUNK_VALUE_CONTEXT,
                "value must be empty",
            )
        );
    }

    #[test]
    fn sctp_cookie_ack_chunk_raw_constructor_preserves_malformed_value_until_validation() {
        let chunk = SctpCookieAckChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.validate_empty_value().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_COOKIE_ACK_CHUNK_VALUE_CONTEXT,
                "value must be empty",
            )
        );
    }

    #[test]
    fn sctp_cookie_ack_chunk_cookie_ack_helper_uses_zero_flags() {
        let chunk = SctpCookieAckChunk::cookie_ack();

        assert_eq!(chunk.flags(), 0);
        assert_eq!(chunk.value(), &[]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN);
    }

    #[test]
    fn sctp_auth_chunk_constructor_encodes_identifiers_and_hmac_bytes() -> Result<()> {
        let chunk = SctpAuthChunk::from_auth_parts(
            0xa0,
            SctpSharedKeyIdentifier::from_u16(0x0102),
            SctpHmacIdentifier::Sha256,
            [0xaa, 0xbb, 0xcc],
        );

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_AUTH);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 7);
        assert_eq!(chunk.value(), &[0x01, 0x02, 0x00, 0x03, 0xaa, 0xbb, 0xcc]);
        assert_eq!(
            chunk.shared_key_identifier()?,
            SctpSharedKeyIdentifier::from_u16(0x0102)
        );
        assert_eq!(chunk.shared_key_identifier_value()?, 0x0102);
        assert_eq!(chunk.hmac_identifier()?, SctpHmacIdentifier::Sha256);
        assert_eq!(chunk.hmac_identifier_value()?, 0x0003);
        assert_eq!(chunk.hmac()?, &[0xaa, 0xbb, 0xcc]);
        assert_eq!(chunk.hmac_bytes()?, &[0xaa, 0xbb, 0xcc]);
        assert_eq!(chunk.required_padding_len(), 1);
        chunk.validate_auth_value()?;

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::Auth(_)));
        assert_eq!(enum_chunk.value_len(), 7);
        Ok(())
    }

    #[test]
    fn sctp_auth_chunk_decode_exposes_identifiers_hmac_bytes_and_padding() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_AUTH,
            0x5a,
            0x00,
            0x0b,
            0xbe,
            0xef,
            0x12,
            0x34,
            0x01,
            0x02,
            0x03,
            0xdd,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::Auth(auth) = &chunks[0] else {
            panic!("AUTH codepoint must decode as SctpAuthChunk");
        };

        assert_eq!(auth.flags(), 0x5a);
        assert_eq!(auth.explicit_declared_length(), Some(11));
        assert_eq!(auth.shared_key_identifier_value()?, 0xbeef);
        assert_eq!(auth.hmac_identifier()?, SctpHmacIdentifier::Unknown(0x1234));
        assert_eq!(auth.hmac_identifier_value()?, 0x1234);
        assert_eq!(auth.hmac_bytes()?, &[0x01, 0x02, 0x03]);
        assert_eq!(auth.padding(), &[0xdd]);
        Ok(())
    }

    #[test]
    fn sctp_auth_chunk_decode_rejects_short_identifier_fields() {
        let bytes = [
            SCTP_CHUNK_TYPE_AUTH,
            0x00,
            0x00,
            0x07,
            0x01,
            0x02,
            0x03,
            0x00,
        ];

        assert_eq!(
            decode_chunks(bytes).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_AUTH_CHUNK_VALUE_CONTEXT,
                SCTP_AUTH_CHUNK_VALUE_HEADER_LEN,
                3,
            )
        );
    }

    #[test]
    fn sctp_auth_chunk_raw_constructor_preserves_malformed_value_until_semantic_access() {
        let chunk = SctpAuthChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.hmac_identifier().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_AUTH_CHUNK_VALUE_CONTEXT,
                SCTP_AUTH_CHUNK_VALUE_HEADER_LEN,
                1,
            )
        );
    }

    #[test]
    fn sctp_auth_chunk_with_auth_replaces_value_and_keeps_flags() -> Result<()> {
        let chunk = SctpAuthChunk::new([])
            .with_flags(0xa0)
            .with_auth(0x0102u16, 0x1234u16, [0x44; 5]);

        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.shared_key_identifier_value()?, 0x0102);
        assert_eq!(
            chunk.hmac_identifier()?,
            SctpHmacIdentifier::Unknown(0x1234)
        );
        assert_eq!(chunk.hmac_bytes()?, &[0x44; 5]);
        assert_eq!(
            chunk.value(),
            &[0x01, 0x02, 0x12, 0x34, 0x44, 0x44, 0x44, 0x44, 0x44]
        );
        Ok(())
    }

    #[test]
    fn sctp_asconf_chunk_constructor_encodes_serial_address_and_request_parameters() -> Result<()> {
        let sender_address = SctpParameter::from(SctpIpv4AddressParameter::from_address(
            Ipv4Addr::new(192, 0, 2, 1),
        ));
        let request = SctpParameter::from(
            SctpAddIpAddressParameter::from_correlation_id_and_ipv4_address(
                0x0102_0304,
                Ipv4Addr::new(198, 51, 100, 1),
            ),
        );
        let chunk = SctpAsconfChunk::try_from_asconf_parts(
            0xa0,
            0x1122_3344,
            sender_address.clone(),
            &[request.clone()],
        )?;

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_ASCONF);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 28);
        assert_eq!(chunk.serial_number()?, 0x1122_3344);
        assert_eq!(chunk.sequence_number()?, 0x1122_3344);
        assert_eq!(
            chunk.value(),
            &[
                0x11, 0x22, 0x33, 0x44, 0x00, 0x05, 0x00, 0x08, 192, 0, 2, 1, 0xc0, 0x01, 0x00,
                0x10, 0x01, 0x02, 0x03, 0x04, 0x00, 0x05, 0x00, 0x08, 198, 51, 100, 1,
            ]
        );
        assert_eq!(chunk.parameter_count()?, 2);
        let decoded_address = chunk.address_parameter()?;
        assert_eq!(
            decoded_address.parameter_type_value(),
            sender_address.parameter_type_value()
        );
        assert_eq!(decoded_address.value(), sender_address.value());
        let requests = chunk.request_parameters()?;
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].parameter_type_value(),
            request.parameter_type_value()
        );
        assert_eq!(requests[0].value(), request.value());
        assert_eq!(chunk.asconf_parameters()?.len(), 1);
        chunk.validate_asconf_value()?;

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::Asconf(_)));
        assert_eq!(enum_chunk.value_len(), 28);
        Ok(())
    }

    #[test]
    fn sctp_asconf_chunk_decode_exposes_serial_and_parameter_sequence() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_ASCONF,
            0x5a,
            0x00,
            0x20,
            0x11,
            0x22,
            0x33,
            0x44,
            0x00,
            0x05,
            0x00,
            0x08,
            192,
            0,
            2,
            1,
            0xc0,
            0x01,
            0x00,
            0x10,
            0x01,
            0x02,
            0x03,
            0x04,
            0x00,
            0x05,
            0x00,
            0x08,
            198,
            51,
            100,
            1,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::Asconf(asconf) = &chunks[0] else {
            panic!("ASCONF codepoint must decode as SctpAsconfChunk");
        };

        assert_eq!(asconf.flags(), 0x5a);
        assert_eq!(asconf.explicit_declared_length(), Some(32));
        assert_eq!(asconf.serial_number()?, 0x1122_3344);
        assert_eq!(asconf.parameter_count()?, 2);
        assert!(matches!(
            asconf.address_parameter()?,
            SctpParameter::Ipv4Address(_)
        ));
        let requests = asconf.request_parameters()?;
        assert_eq!(requests.len(), 1);
        let SctpParameter::AddIpAddress(add) = &requests[0] else {
            panic!("ASCONF request must decode as Add IP Address");
        };
        assert_eq!(add.correlation_id()?, 0x0102_0304);
        assert_eq!(add.ipv4_address()?, Ipv4Addr::new(198, 51, 100, 1));
        Ok(())
    }

    #[test]
    fn sctp_asconf_chunk_decode_rejects_short_or_malformed_parameter_sequence() {
        let short_serial = [
            SCTP_CHUNK_TYPE_ASCONF,
            0x00,
            0x00,
            0x07,
            0x01,
            0x02,
            0x03,
            0x00,
        ];
        assert_eq!(
            decode_chunks(short_serial).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_ASCONF_CHUNK_VALUE_CONTEXT,
                SCTP_ASCONF_CHUNK_VALUE_HEADER_LEN,
                3,
            )
        );

        let missing_parameters = [
            SCTP_CHUNK_TYPE_ASCONF,
            0x00,
            0x00,
            0x08,
            0x01,
            0x02,
            0x03,
            0x04,
        ];
        assert_eq!(
            decode_chunks(missing_parameters).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_ASCONF_CHUNK_PARAMETERS_CONTEXT,
                SCTP_PARAMETER_HEADER_LEN,
                0,
            )
        );

        let partial_parameter = [
            SCTP_CHUNK_TYPE_ASCONF,
            0x00,
            0x00,
            0x0b,
            0x01,
            0x02,
            0x03,
            0x04,
            0x00,
            0x05,
            0x00,
            0x00,
        ];
        assert_eq!(
            decode_chunks(partial_parameter).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_ASCONF_CHUNK_PARAMETERS_CONTEXT,
                SCTP_PARAMETER_HEADER_LEN,
                3,
            )
        );
    }

    #[test]
    fn sctp_asconf_chunk_raw_constructor_preserves_malformed_value_until_semantic_access() {
        let chunk = SctpAsconfChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.serial_number().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_ASCONF_CHUNK_VALUE_CONTEXT,
                SCTP_ASCONF_CHUNK_VALUE_HEADER_LEN,
                1,
            )
        );
    }

    #[test]
    fn sctp_asconf_chunk_try_with_asconf_replaces_value_and_keeps_flags() -> Result<()> {
        let sender_address = SctpParameter::from(SctpIpv4AddressParameter::from_address(
            Ipv4Addr::new(192, 0, 2, 9),
        ));
        let chunk = SctpAsconfChunk::new([]).with_flags(0xa0).try_with_asconf(
            0x0102_0304,
            sender_address,
            &[],
        )?;

        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.serial_number()?, 0x0102_0304);
        assert_eq!(chunk.parameter_count()?, 1);
        assert!(chunk.request_parameters()?.is_empty());
        Ok(())
    }

    #[test]
    fn sctp_asconf_ack_chunk_constructor_encodes_serial_and_response_parameters() -> Result<()> {
        let response = SctpParameter::from(
            SctpSuccessIndicationParameter::from_response_correlation_id(0x0102_0304),
        );
        let chunk =
            SctpAsconfAckChunk::try_from_asconf_ack_parts(0xa0, 0x1122_3344, &[response.clone()])?;

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_ASCONF_ACK);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 12);
        assert_eq!(chunk.serial_number()?, 0x1122_3344);
        assert_eq!(chunk.sequence_number()?, 0x1122_3344);
        assert_eq!(
            chunk.value(),
            &[0x11, 0x22, 0x33, 0x44, 0xc0, 0x05, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04,]
        );
        assert_eq!(chunk.parameter_count()?, 1);
        let responses = chunk.response_parameters()?;
        assert_eq!(responses.len(), 1);
        assert_eq!(
            responses[0].parameter_type_value(),
            response.parameter_type_value()
        );
        assert_eq!(responses[0].value(), response.value());
        chunk.validate_asconf_ack_value()?;

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::AsconfAck(_)));
        assert_eq!(enum_chunk.value_len(), 12);
        Ok(())
    }

    #[test]
    fn sctp_asconf_ack_chunk_decode_exposes_serial_and_response_parameters() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_ASCONF_ACK,
            0x5a,
            0x00,
            0x10,
            0x11,
            0x22,
            0x33,
            0x44,
            0xc0,
            0x05,
            0x00,
            0x08,
            0x01,
            0x02,
            0x03,
            0x04,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::AsconfAck(asconf_ack) = &chunks[0] else {
            panic!("ASCONF-ACK codepoint must decode as SctpAsconfAckChunk");
        };

        assert_eq!(asconf_ack.flags(), 0x5a);
        assert_eq!(asconf_ack.explicit_declared_length(), Some(16));
        assert_eq!(asconf_ack.serial_number()?, 0x1122_3344);
        assert_eq!(asconf_ack.parameter_count()?, 1);
        let responses = asconf_ack.response_parameters()?;
        let SctpParameter::SuccessIndication(success) = &responses[0] else {
            panic!("ASCONF-ACK response must decode as Success Indication");
        };
        assert_eq!(success.response_correlation_id()?, 0x0102_0304);
        Ok(())
    }

    #[test]
    fn sctp_asconf_ack_chunk_decode_accepts_empty_success_response_sequence() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_ASCONF_ACK,
            0x00,
            0x00,
            0x08,
            0x11,
            0x22,
            0x33,
            0x44,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::AsconfAck(asconf_ack) = &chunks[0] else {
            panic!("ASCONF-ACK codepoint must decode as SctpAsconfAckChunk");
        };

        assert_eq!(asconf_ack.serial_number()?, 0x1122_3344);
        assert!(asconf_ack.response_parameters()?.is_empty());
        asconf_ack.validate_asconf_ack_value()?;
        Ok(())
    }

    #[test]
    fn sctp_asconf_ack_chunk_decode_rejects_short_or_malformed_parameter_sequence() {
        let short_serial = [
            SCTP_CHUNK_TYPE_ASCONF_ACK,
            0x00,
            0x00,
            0x07,
            0x01,
            0x02,
            0x03,
            0x00,
        ];
        assert_eq!(
            decode_chunks(short_serial).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_ASCONF_ACK_CHUNK_VALUE_CONTEXT,
                SCTP_ASCONF_ACK_CHUNK_VALUE_HEADER_LEN,
                3,
            )
        );

        let partial_parameter = [
            SCTP_CHUNK_TYPE_ASCONF_ACK,
            0x00,
            0x00,
            0x0b,
            0x01,
            0x02,
            0x03,
            0x04,
            0xc0,
            0x05,
            0x00,
            0x00,
        ];
        assert_eq!(
            decode_chunks(partial_parameter).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_ASCONF_ACK_CHUNK_PARAMETERS_CONTEXT,
                SCTP_PARAMETER_HEADER_LEN,
                3,
            )
        );
    }

    #[test]
    fn sctp_asconf_ack_chunk_raw_constructor_preserves_malformed_value_until_semantic_access() {
        let chunk = SctpAsconfAckChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.serial_number().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_ASCONF_ACK_CHUNK_VALUE_CONTEXT,
                SCTP_ASCONF_ACK_CHUNK_VALUE_HEADER_LEN,
                1,
            )
        );
    }

    #[test]
    fn sctp_asconf_ack_chunk_try_with_asconf_ack_replaces_value_and_keeps_flags() -> Result<()> {
        let chunk = SctpAsconfAckChunk::new([])
            .with_flags(0xa0)
            .try_with_asconf_ack(0x0102_0304, &[])?;

        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.serial_number()?, 0x0102_0304);
        assert_eq!(chunk.parameter_count()?, 0);
        assert_eq!(chunk.value(), &[0x01, 0x02, 0x03, 0x04]);
        Ok(())
    }

    #[test]
    fn sctp_reconfig_chunk_constructor_encodes_reconfiguration_parameters() -> Result<()> {
        let response = SctpParameter::from(
            SctpReConfigurationResponseParameter::from_response_sequence_number_and_result_value(
                0x0102_0304,
                1,
            ),
        );
        let chunk = SctpReConfigChunk::try_from_reconfig_parts(0xa0, &[response.clone()])?;

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_RE_CONFIG);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 12);
        assert_eq!(
            chunk.value(),
            &[0x00, 0x10, 0x00, 0x0c, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x01]
        );
        assert_eq!(chunk.parameter_count()?, 1);
        let parameters = chunk.reconfiguration_parameters()?;
        assert_eq!(parameters.len(), 1);
        assert_eq!(
            parameters[0].parameter_type_value(),
            response.parameter_type_value()
        );
        assert_eq!(parameters[0].value(), response.value());
        chunk.validate_reconfig_value()?;

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::ReConfig(_)));
        assert_eq!(enum_chunk.value_len(), 12);
        Ok(())
    }

    #[test]
    fn sctp_reconfig_chunk_decode_exposes_reconfiguration_parameters() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_RE_CONFIG,
            0x5a,
            0x00,
            0x10,
            0x00,
            0x10,
            0x00,
            0x0c,
            0x01,
            0x02,
            0x03,
            0x04,
            0x00,
            0x00,
            0x00,
            0x01,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::ReConfig(reconfig) = &chunks[0] else {
            panic!("RE-CONFIG codepoint must decode as SctpReConfigChunk");
        };

        assert_eq!(reconfig.flags(), 0x5a);
        assert_eq!(reconfig.explicit_declared_length(), Some(16));
        assert_eq!(reconfig.parameter_count()?, 1);
        let parameters = reconfig.parameters()?;
        let SctpParameter::ReConfigurationResponse(response) = &parameters[0] else {
            panic!("RE-CONFIG parameter must decode as Re-configuration Response");
        };
        assert_eq!(response.response_sequence_number()?, 0x0102_0304);
        assert_eq!(response.result_value()?, 1);
        Ok(())
    }

    #[test]
    fn sctp_reconfig_chunk_decode_rejects_empty_or_malformed_parameter_sequence() {
        let empty = [SCTP_CHUNK_TYPE_RE_CONFIG, 0x00, 0x00, 0x04];
        assert_eq!(
            decode_chunks(empty).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_RECONFIG_CHUNK_PARAMETERS_CONTEXT,
                SCTP_PARAMETER_HEADER_LEN,
                0,
            )
        );

        let partial = [
            SCTP_CHUNK_TYPE_RE_CONFIG,
            0x00,
            0x00,
            0x07,
            0x00,
            0x10,
            0x00,
            0x00,
        ];
        assert_eq!(
            decode_chunks(partial).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_RECONFIG_CHUNK_PARAMETERS_CONTEXT,
                SCTP_PARAMETER_HEADER_LEN,
                3,
            )
        );
    }

    #[test]
    fn sctp_reconfig_chunk_raw_constructor_preserves_malformed_value_until_semantic_access() {
        let chunk = SctpReConfigChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.parameters().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_RECONFIG_CHUNK_PARAMETERS_CONTEXT,
                SCTP_PARAMETER_HEADER_LEN,
                1,
            )
        );
    }

    #[test]
    fn sctp_reconfig_chunk_try_with_reconfig_replaces_value_and_keeps_flags() -> Result<()> {
        let request = SctpParameter::from(
            SctpSsnTsnResetRequestParameter::from_request_sequence_number(0x0102_0304),
        );
        let chunk = SctpReConfigChunk::new([])
            .with_flags(0xa0)
            .try_with_reconfig(&[request])?;

        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.parameter_count()?, 1);
        assert_eq!(
            chunk.value(),
            &[0x00, 0x0f, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04]
        );
        Ok(())
    }

    #[test]
    fn sctp_reconfig_chunk_constructor_rejects_empty_parameter_sequence() {
        assert_eq!(
            SctpReConfigChunk::try_from_reconfig(&[]).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_RECONFIG_CHUNK_PARAMETERS_CONTEXT,
                SCTP_PARAMETER_HEADER_LEN,
                0,
            )
        );
    }

    #[test]
    fn sctp_pad_chunk_constructor_preserves_padding_data_and_raw_flags() {
        let chunk = SctpPadChunk::from_padding_data([0xaa, 0xbb, 0xcc]).with_flags(0xa0);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_PAD);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 3);
        assert_eq!(chunk.padding_data(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(chunk.padding_data_bytes(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(chunk.required_padding_len(), 1);
        assert_eq!(chunk.encoded_padding_len(), 1);

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::Pad(_)));
        assert_eq!(enum_chunk.value(), &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn sctp_pad_chunk_decode_preserves_padding_data_and_alignment_padding() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_PAD,
            0x5a,
            0x00,
            0x07,
            0xaa,
            0xbb,
            0xcc,
            0xdd,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::Pad(pad) = &chunks[0] else {
            panic!("PAD codepoint must decode as SctpPadChunk");
        };

        assert_eq!(pad.flags(), 0x5a);
        assert_eq!(pad.explicit_declared_length(), Some(7));
        assert_eq!(pad.padding_data(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(pad.padding(), &[0xdd]);
        Ok(())
    }

    #[test]
    fn sctp_pad_chunk_with_padding_data_replaces_value_and_keeps_flags() {
        let chunk = SctpPadChunk::new([])
            .with_flags(0xa0)
            .with_padding_data([0x11, 0x22, 0x33, 0x44]);

        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.padding_data(), &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 4);
        assert_eq!(chunk.encoded_padding_len(), 0);
    }

    #[test]
    fn sctp_pad_chunk_allows_header_only_padding_data() {
        let chunk = SctpPadChunk::from_padding_data([]);

        assert_eq!(chunk.value(), &[]);
        assert_eq!(chunk.padding_data(), &[]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN);
    }

    #[test]
    fn sctp_ecne_chunk_constructor_encodes_lowest_tsn_and_raw_flags() -> Result<()> {
        let chunk = SctpEcneChunk::from_lowest_tsn_parts(0xa0, 0x1122_3344);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_ECNE);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 4);
        assert_eq!(chunk.value(), &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(chunk.lowest_tsn()?, 0x1122_3344);
        assert_eq!(chunk.lowest_transmission_sequence_number()?, 0x1122_3344);

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::Ecne(_)));
        assert_eq!(enum_chunk.value_len(), 4);
        Ok(())
    }

    #[test]
    fn sctp_ecne_chunk_decode_exposes_lowest_tsn() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_ECNE,
            0x5a,
            0x00,
            0x08,
            0x11,
            0x22,
            0x33,
            0x44,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::Ecne(ecne) = &chunks[0] else {
            panic!("ECNE codepoint must decode as SctpEcneChunk");
        };

        assert_eq!(ecne.flags(), 0x5a);
        assert_eq!(ecne.explicit_declared_length(), Some(8));
        assert_eq!(ecne.lowest_tsn()?, 0x1122_3344);
        Ok(())
    }

    #[test]
    fn sctp_ecne_chunk_decode_rejects_short_or_extra_value() {
        let short_value = [
            SCTP_CHUNK_TYPE_ECNE,
            0x00,
            0x00,
            0x07,
            0x11,
            0x22,
            0x33,
            0x00,
        ];

        assert_eq!(
            decode_chunks(short_value).unwrap_err(),
            CrafterError::buffer_too_short(SCTP_ECNE_CHUNK_VALUE_CONTEXT, 4, 3)
        );

        let extra_value = [
            SCTP_CHUNK_TYPE_ECNE,
            0x00,
            0x00,
            0x09,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x00,
            0x00,
            0x00,
        ];

        assert_eq!(
            decode_chunks(extra_value).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_ECNE_CHUNK_VALUE_CONTEXT,
                "value length must be four bytes",
            )
        );
    }

    #[test]
    fn sctp_ecne_chunk_raw_constructor_preserves_malformed_value_until_semantic_access() {
        let chunk = SctpEcneChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.lowest_tsn().unwrap_err(),
            CrafterError::buffer_too_short(SCTP_ECNE_CHUNK_VALUE_CONTEXT, 4, 1)
        );
    }

    #[test]
    fn sctp_ecne_chunk_with_lowest_tsn_replaces_value_and_keeps_flags() -> Result<()> {
        let chunk = SctpEcneChunk::new([])
            .with_flags(0xa0)
            .with_lowest_tsn(0x0102_0304);

        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.lowest_tsn()?, 0x0102_0304);
        assert_eq!(chunk.value(), &[0x01, 0x02, 0x03, 0x04]);
        Ok(())
    }

    #[test]
    fn sctp_cwr_chunk_constructor_encodes_lowest_tsn_and_raw_flags() -> Result<()> {
        let chunk = SctpCwrChunk::from_lowest_tsn_parts(0xa0, 0x1122_3344);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_CWR);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 4);
        assert_eq!(chunk.value(), &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(chunk.lowest_tsn()?, 0x1122_3344);
        assert_eq!(chunk.lowest_transmission_sequence_number()?, 0x1122_3344);

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::Cwr(_)));
        assert_eq!(enum_chunk.value_len(), 4);
        Ok(())
    }

    #[test]
    fn sctp_cwr_chunk_decode_exposes_lowest_tsn() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_CWR,
            0x5a,
            0x00,
            0x08,
            0x11,
            0x22,
            0x33,
            0x44,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::Cwr(cwr) = &chunks[0] else {
            panic!("CWR codepoint must decode as SctpCwrChunk");
        };

        assert_eq!(cwr.flags(), 0x5a);
        assert_eq!(cwr.explicit_declared_length(), Some(8));
        assert_eq!(cwr.lowest_tsn()?, 0x1122_3344);
        Ok(())
    }

    #[test]
    fn sctp_cwr_chunk_decode_rejects_short_or_extra_value() {
        let short_value = [
            SCTP_CHUNK_TYPE_CWR,
            0x00,
            0x00,
            0x07,
            0x11,
            0x22,
            0x33,
            0x00,
        ];

        assert_eq!(
            decode_chunks(short_value).unwrap_err(),
            CrafterError::buffer_too_short(SCTP_CWR_CHUNK_VALUE_CONTEXT, 4, 3)
        );

        let extra_value = [
            SCTP_CHUNK_TYPE_CWR,
            0x00,
            0x00,
            0x09,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x00,
            0x00,
            0x00,
        ];

        assert_eq!(
            decode_chunks(extra_value).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_CWR_CHUNK_VALUE_CONTEXT,
                "value length must be four bytes",
            )
        );
    }

    #[test]
    fn sctp_cwr_chunk_raw_constructor_preserves_malformed_value_until_semantic_access() {
        let chunk = SctpCwrChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.lowest_tsn().unwrap_err(),
            CrafterError::buffer_too_short(SCTP_CWR_CHUNK_VALUE_CONTEXT, 4, 1)
        );
    }

    #[test]
    fn sctp_cwr_chunk_with_lowest_tsn_replaces_value_and_keeps_flags() -> Result<()> {
        let chunk = SctpCwrChunk::new([])
            .with_flags(0xa0)
            .with_lowest_tsn(0x0102_0304);

        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.lowest_tsn()?, 0x0102_0304);
        assert_eq!(chunk.value(), &[0x01, 0x02, 0x03, 0x04]);
        Ok(())
    }

    #[test]
    fn sctp_forward_tsn_chunk_constructor_encodes_cumulative_tsn_and_skipped_entries() -> Result<()>
    {
        let skipped = [
            SctpForwardTsnSkippedStreamSequence::new(0x0102, 0x0304),
            SctpForwardTsnSkippedStreamSequence::new(0xfffe, 0xffff),
        ];
        let chunk = SctpForwardTsnChunk::from_forward_tsn_parts(0xa0, 0x1122_3344, &skipped);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_FORWARD_TSN);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 12);
        assert_eq!(
            chunk.value(),
            &[0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x03, 0x04, 0xff, 0xfe, 0xff, 0xff,]
        );
        assert_eq!(chunk.new_cumulative_tsn()?, 0x1122_3344);
        assert_eq!(
            chunk.new_cumulative_transmission_sequence_number()?,
            0x1122_3344
        );
        assert_eq!(chunk.skipped_stream_sequence_count()?, 2);
        assert_eq!(chunk.skipped_stream_sequences()?, skipped);

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::ForwardTsn(_)));
        assert_eq!(enum_chunk.value_len(), 12);
        Ok(())
    }

    #[test]
    fn sctp_forward_tsn_chunk_decode_exposes_skipped_entries() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_FORWARD_TSN,
            0x5a,
            0x00,
            0x10,
            0x11,
            0x22,
            0x33,
            0x44,
            0x01,
            0x02,
            0x03,
            0x04,
            0xff,
            0xfe,
            0xff,
            0xff,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::ForwardTsn(forward_tsn) = &chunks[0] else {
            panic!("FORWARD TSN codepoint must decode as SctpForwardTsnChunk");
        };

        assert_eq!(forward_tsn.flags(), 0x5a);
        assert_eq!(forward_tsn.explicit_declared_length(), Some(16));
        assert_eq!(forward_tsn.new_cumulative_tsn()?, 0x1122_3344);
        assert_eq!(
            forward_tsn.skipped_stream_sequences()?,
            [
                SctpForwardTsnSkippedStreamSequence::new(0x0102, 0x0304),
                SctpForwardTsnSkippedStreamSequence::new(0xfffe, 0xffff),
            ]
        );
        Ok(())
    }

    #[test]
    fn sctp_forward_tsn_chunk_decode_rejects_short_or_partial_entries() {
        let short_value = [
            SCTP_CHUNK_TYPE_FORWARD_TSN,
            0x00,
            0x00,
            0x07,
            0x11,
            0x22,
            0x33,
            0x00,
        ];

        assert_eq!(
            decode_chunks(short_value).unwrap_err(),
            CrafterError::buffer_too_short(SCTP_FORWARD_TSN_CHUNK_VALUE_CONTEXT, 4, 3)
        );

        let partial_entry = [
            SCTP_CHUNK_TYPE_FORWARD_TSN,
            0x00,
            0x00,
            0x0a,
            0x11,
            0x22,
            0x33,
            0x44,
            0x01,
            0x02,
            0x00,
            0x00,
        ];

        assert_eq!(
            decode_chunks(partial_entry).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_FORWARD_TSN_CHUNK_VALUE_CONTEXT,
                "skipped stream sequence entries must be four bytes each",
            )
        );
    }

    #[test]
    fn sctp_forward_tsn_chunk_raw_constructor_preserves_malformed_value_until_semantic_access() {
        let chunk = SctpForwardTsnChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.new_cumulative_tsn().unwrap_err(),
            CrafterError::buffer_too_short(SCTP_FORWARD_TSN_CHUNK_VALUE_CONTEXT, 4, 1)
        );
    }

    #[test]
    fn sctp_forward_tsn_chunk_with_forward_tsn_replaces_value_and_keeps_flags() -> Result<()> {
        let skipped = [SctpForwardTsnSkippedStreamSequence::new(1, 2)];
        let chunk = SctpForwardTsnChunk::new([])
            .with_flags(0xa0)
            .with_forward_tsn(0x0102_0304, &skipped);

        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.new_cumulative_tsn()?, 0x0102_0304);
        assert_eq!(chunk.skipped_stream_sequences()?, skipped);
        assert_eq!(
            chunk.value(),
            &[0x01, 0x02, 0x03, 0x04, 0x00, 0x01, 0x00, 0x02]
        );
        Ok(())
    }

    #[test]
    fn sctp_iforward_tsn_chunk_entry_helpers_preserve_reserved_and_u_bit() {
        let ordered = SctpIForwardTsnSkippedStream::new(0x0102, 0x0304_0506);
        let unordered = SctpIForwardTsnSkippedStream::unordered(0x0102, 0x0304_0506);
        let raw = SctpIForwardTsnSkippedStream::from_parts(0x0102, 0x8001, 0x0304_0506);

        assert_eq!(ordered.stream_id(), 0x0102);
        assert_eq!(ordered.stream_identifier(), 0x0102);
        assert_eq!(ordered.flags(), 0);
        assert!(!ordered.is_u_bit_set());
        assert!(!ordered.is_unordered());
        assert_eq!(ordered.message_identifier(), 0x0304_0506);
        assert_eq!(ordered.message_id(), 0x0304_0506);

        assert_eq!(unordered.flags(), SCTP_IFORWARD_TSN_SKIPPED_STREAM_FLAG_U);
        assert!(unordered.is_u_bit_set());
        assert!(unordered.is_unordered());

        assert_eq!(raw.flags(), 0x8001);
        assert!(raw.is_u_bit_set());
        assert_eq!(raw.message_identifier(), 0x0304_0506);
    }

    #[test]
    fn sctp_iforward_tsn_chunk_constructor_encodes_cumulative_tsn_and_skipped_streams() -> Result<()>
    {
        let skipped = [
            SctpIForwardTsnSkippedStream::new(0x0102, 0x0304_0506),
            SctpIForwardTsnSkippedStream::from_parts(0xfffe, 0x8001, 0xaabb_ccdd),
        ];
        let chunk = SctpIForwardTsnChunk::from_iforward_tsn_parts(0xa0, 0x1122_3344, &skipped);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_I_FORWARD_TSN);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 20);
        assert_eq!(
            chunk.value(),
            &[
                0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x00, 0x00, 0x03, 0x04, 0x05, 0x06, 0xff, 0xfe,
                0x80, 0x01, 0xaa, 0xbb, 0xcc, 0xdd,
            ]
        );
        assert_eq!(chunk.new_cumulative_tsn()?, 0x1122_3344);
        assert_eq!(
            chunk.new_cumulative_transmission_sequence_number()?,
            0x1122_3344
        );
        assert_eq!(chunk.skipped_stream_count()?, 2);
        assert_eq!(chunk.skipped_streams()?, skipped);

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::IForwardTsn(_)));
        assert_eq!(enum_chunk.value_len(), 20);
        Ok(())
    }

    #[test]
    fn sctp_iforward_tsn_chunk_decode_exposes_skipped_streams() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_I_FORWARD_TSN,
            0x5a,
            0x00,
            0x18,
            0x11,
            0x22,
            0x33,
            0x44,
            0x01,
            0x02,
            0x00,
            0x00,
            0x03,
            0x04,
            0x05,
            0x06,
            0xff,
            0xfe,
            0x80,
            0x01,
            0xaa,
            0xbb,
            0xcc,
            0xdd,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::IForwardTsn(iforward_tsn) = &chunks[0] else {
            panic!("I-FORWARD-TSN codepoint must decode as SctpIForwardTsnChunk");
        };

        assert_eq!(iforward_tsn.flags(), 0x5a);
        assert_eq!(iforward_tsn.explicit_declared_length(), Some(24));
        assert_eq!(iforward_tsn.new_cumulative_tsn()?, 0x1122_3344);
        assert_eq!(
            iforward_tsn.skipped_streams()?,
            [
                SctpIForwardTsnSkippedStream::new(0x0102, 0x0304_0506),
                SctpIForwardTsnSkippedStream::from_parts(0xfffe, 0x8001, 0xaabb_ccdd),
            ]
        );
        Ok(())
    }

    #[test]
    fn sctp_iforward_tsn_chunk_decode_rejects_short_or_partial_entries() {
        let short_value = [
            SCTP_CHUNK_TYPE_I_FORWARD_TSN,
            0x00,
            0x00,
            0x07,
            0x11,
            0x22,
            0x33,
            0x00,
        ];

        assert_eq!(
            decode_chunks(short_value).unwrap_err(),
            CrafterError::buffer_too_short(SCTP_IFORWARD_TSN_CHUNK_VALUE_CONTEXT, 4, 3)
        );

        let partial_entry = [
            SCTP_CHUNK_TYPE_I_FORWARD_TSN,
            0x00,
            0x00,
            0x0c,
            0x11,
            0x22,
            0x33,
            0x44,
            0x01,
            0x02,
            0x00,
            0x00,
        ];

        assert_eq!(
            decode_chunks(partial_entry).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_IFORWARD_TSN_CHUNK_VALUE_CONTEXT,
                "skipped stream entries must be eight bytes each",
            )
        );
    }

    #[test]
    fn sctp_iforward_tsn_chunk_raw_constructor_preserves_malformed_value_until_semantic_access() {
        let chunk = SctpIForwardTsnChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.new_cumulative_tsn().unwrap_err(),
            CrafterError::buffer_too_short(SCTP_IFORWARD_TSN_CHUNK_VALUE_CONTEXT, 4, 1)
        );
    }

    #[test]
    fn sctp_iforward_tsn_chunk_with_iforward_tsn_replaces_value_and_keeps_flags() -> Result<()> {
        let skipped = [SctpIForwardTsnSkippedStream::unordered(1, 2)];
        let chunk = SctpIForwardTsnChunk::new([])
            .with_flags(0xa0)
            .with_iforward_tsn(0x0102_0304, &skipped);

        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.new_cumulative_tsn()?, 0x0102_0304);
        assert_eq!(chunk.skipped_streams()?, skipped);
        assert_eq!(
            chunk.value(),
            &[0x01, 0x02, 0x03, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02]
        );
        Ok(())
    }

    #[test]
    fn sctp_shutdown_chunk_constructor_encodes_cumulative_tsn_ack_and_raw_flags() -> Result<()> {
        let chunk = SctpShutdownChunk::from_shutdown_parts(0xa0, 0x1122_3344);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_SHUTDOWN);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 4);
        assert_eq!(chunk.value(), &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(chunk.cumulative_tsn_ack()?, 0x1122_3344);
        assert_eq!(
            chunk.cumulative_transmission_sequence_number_ack()?,
            0x1122_3344
        );

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::Shutdown(_)));
        assert_eq!(enum_chunk.value_len(), 4);
        Ok(())
    }

    #[test]
    fn sctp_shutdown_chunk_decode_exposes_cumulative_tsn_ack() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_SHUTDOWN,
            0x5a,
            0x00,
            0x08,
            0x11,
            0x22,
            0x33,
            0x44,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::Shutdown(shutdown) = &chunks[0] else {
            panic!("SHUTDOWN codepoint must decode as SctpShutdownChunk");
        };

        assert_eq!(shutdown.flags(), 0x5a);
        assert_eq!(shutdown.explicit_declared_length(), Some(8));
        assert_eq!(shutdown.cumulative_tsn_ack()?, 0x1122_3344);
        Ok(())
    }

    #[test]
    fn sctp_shutdown_chunk_decode_rejects_short_or_extra_value() {
        let short_value = [
            SCTP_CHUNK_TYPE_SHUTDOWN,
            0x00,
            0x00,
            0x07,
            0x11,
            0x22,
            0x33,
            0x00,
        ];

        assert_eq!(
            decode_chunks(short_value).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_SHUTDOWN_CHUNK_VALUE_CONTEXT,
                SCTP_SHUTDOWN_CHUNK_VALUE_LEN,
                3,
            )
        );

        let extra_value = [
            SCTP_CHUNK_TYPE_SHUTDOWN,
            0x00,
            0x00,
            0x09,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x00,
            0x00,
            0x00,
        ];

        assert_eq!(
            decode_chunks(extra_value).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_SHUTDOWN_CHUNK_VALUE_CONTEXT,
                "value length must be four bytes",
            )
        );
    }

    #[test]
    fn sctp_shutdown_chunk_raw_constructor_preserves_malformed_value_until_semantic_access() {
        let chunk = SctpShutdownChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.cumulative_tsn_ack().unwrap_err(),
            CrafterError::buffer_too_short(SCTP_SHUTDOWN_CHUNK_VALUE_CONTEXT, 4, 1)
        );
    }

    #[test]
    fn sctp_shutdown_chunk_with_shutdown_replaces_value_and_keeps_flags() -> Result<()> {
        let chunk = SctpShutdownChunk::new([])
            .with_flags(0xa0)
            .with_shutdown(0x0102_0304);

        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.cumulative_tsn_ack()?, 0x0102_0304);
        assert_eq!(chunk.value(), &[0x01, 0x02, 0x03, 0x04]);
        Ok(())
    }

    #[test]
    fn sctp_shutdown_ack_chunk_constructor_uses_header_only_value_and_raw_flags() -> Result<()> {
        let chunk = SctpShutdownAckChunk::from_shutdown_ack_parts(0xa0);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_SHUTDOWN_ACK);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN);
        assert_eq!(chunk.value(), &[]);
        chunk.validate_empty_value()?;

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::ShutdownAck(_)));
        assert_eq!(enum_chunk.value_len(), 0);
        Ok(())
    }

    #[test]
    fn sctp_shutdown_ack_chunk_decode_accepts_header_only_value() -> Result<()> {
        let bytes = [SCTP_CHUNK_TYPE_SHUTDOWN_ACK, 0x5a, 0x00, 0x04];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::ShutdownAck(shutdown_ack) = &chunks[0] else {
            panic!("SHUTDOWN ACK codepoint must decode as SctpShutdownAckChunk");
        };

        assert_eq!(shutdown_ack.flags(), 0x5a);
        assert_eq!(shutdown_ack.explicit_declared_length(), Some(4));
        assert_eq!(shutdown_ack.value(), &[]);
        shutdown_ack.validate_empty_value()?;
        Ok(())
    }

    #[test]
    fn sctp_shutdown_ack_chunk_decode_rejects_nonempty_value() {
        let bytes = [
            SCTP_CHUNK_TYPE_SHUTDOWN_ACK,
            0x00,
            0x00,
            0x05,
            0xaa,
            0x00,
            0x00,
            0x00,
        ];

        assert_eq!(
            decode_chunks(bytes).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_SHUTDOWN_ACK_CHUNK_VALUE_CONTEXT,
                "value must be empty",
            )
        );
    }

    #[test]
    fn sctp_shutdown_ack_chunk_raw_constructor_preserves_malformed_value_until_validation() {
        let chunk = SctpShutdownAckChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.validate_empty_value().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_SHUTDOWN_ACK_CHUNK_VALUE_CONTEXT,
                "value must be empty",
            )
        );
    }

    #[test]
    fn sctp_shutdown_ack_chunk_shutdown_ack_helper_uses_zero_flags() {
        let chunk = SctpShutdownAckChunk::shutdown_ack();

        assert_eq!(chunk.flags(), 0);
        assert_eq!(chunk.value(), &[]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN);
    }

    #[test]
    fn sctp_shutdown_complete_chunk_constructor_uses_header_only_value_and_raw_flags() -> Result<()>
    {
        let chunk = SctpShutdownCompleteChunk::from_shutdown_complete_parts(0xa0);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE);
        assert_eq!(chunk.flags(), 0xa0);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN);
        assert_eq!(chunk.value(), &[]);
        chunk.validate_empty_value()?;

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::ShutdownComplete(_)));
        assert_eq!(enum_chunk.value_len(), 0);
        Ok(())
    }

    #[test]
    fn sctp_shutdown_complete_chunk_decode_accepts_header_only_value_and_t_bit() -> Result<()> {
        let bytes = [SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE, 0x01, 0x00, 0x04];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::ShutdownComplete(shutdown_complete) = &chunks[0] else {
            panic!("SHUTDOWN COMPLETE codepoint must decode as SctpShutdownCompleteChunk");
        };

        assert_eq!(shutdown_complete.flags(), SCTP_SHUTDOWN_COMPLETE_FLAG_T);
        assert!(shutdown_complete.is_t_bit_set());
        assert_eq!(shutdown_complete.explicit_declared_length(), Some(4));
        assert_eq!(shutdown_complete.value(), &[]);
        shutdown_complete.validate_empty_value()?;
        Ok(())
    }

    #[test]
    fn sctp_shutdown_complete_chunk_decode_rejects_nonempty_value() {
        let bytes = [
            SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE,
            0x00,
            0x00,
            0x05,
            0xaa,
            0x00,
            0x00,
            0x00,
        ];

        assert_eq!(
            decode_chunks(bytes).unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_SHUTDOWN_COMPLETE_CHUNK_VALUE_CONTEXT,
                "value must be empty",
            )
        );
    }

    #[test]
    fn sctp_shutdown_complete_chunk_raw_constructor_preserves_malformed_value_until_validation() {
        let chunk = SctpShutdownCompleteChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.validate_empty_value().unwrap_err(),
            CrafterError::invalid_field_value(
                SCTP_SHUTDOWN_COMPLETE_CHUNK_VALUE_CONTEXT,
                "value must be empty",
            )
        );
    }

    #[test]
    fn sctp_shutdown_complete_chunk_flag_helpers_preserve_unrelated_bits() {
        let chunk = SctpShutdownCompleteChunk::from_shutdown_complete_parts(0xa0).t_bit();

        assert_eq!(chunk.flags(), 0xa1);
        assert!(chunk.is_t_bit_set());

        let chunk = chunk.set_t_bit(false);
        assert_eq!(chunk.flags(), 0xa0);
        assert!(!chunk.is_t_bit_set());

        let chunk = chunk.flag(0x40, true);
        assert_eq!(chunk.flags(), 0xe0);
        assert!(!chunk.is_t_bit_set());
    }

    #[test]
    fn sctp_shutdown_complete_chunk_shutdown_complete_helper_uses_zero_flags() {
        let chunk = SctpShutdownCompleteChunk::shutdown_complete();

        assert_eq!(chunk.flags(), 0);
        assert_eq!(chunk.value(), &[]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN);
    }

    #[test]
    fn sctp_idata_chunk_constructor_encodes_semantic_fields_and_raw_flags() -> Result<()> {
        let chunk = SctpIDataChunk::from_idata_parts(
            0x8f,
            0x0102_0304,
            0x0506,
            0x0708,
            0x090a_0b0c,
            0x0d0e_0f10,
            [0xde, 0xad],
        );

        assert_eq!(chunk.flags(), 0x8f);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 18);
        assert_eq!(
            chunk.value(),
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0xde, 0xad,
            ]
        );
        assert_eq!(chunk.tsn()?, 0x0102_0304);
        assert_eq!(chunk.transmission_sequence_number()?, 0x0102_0304);
        assert_eq!(chunk.stream_id()?, 0x0506);
        assert_eq!(chunk.stream_identifier()?, 0x0506);
        assert_eq!(chunk.reserved()?, 0x0708);
        assert_eq!(chunk.reserved_value()?, 0x0708);
        assert_eq!(chunk.message_id()?, 0x090a_0b0c);
        assert_eq!(chunk.message_identifier()?, 0x090a_0b0c);
        assert_eq!(chunk.ppid_fsn()?, 0x0d0e_0f10);
        assert_eq!(
            chunk.payload_protocol_identifier_or_fragment_sequence_number()?,
            0x0d0e_0f10
        );
        assert_eq!(chunk.ppid()?, Some(0x0d0e_0f10));
        assert_eq!(chunk.payload_protocol_identifier()?, Some(0x0d0e_0f10));
        assert_eq!(chunk.fsn()?, None);
        assert_eq!(chunk.fragment_sequence_number()?, None);
        assert_eq!(chunk.user_data()?, &[0xde, 0xad]);
        Ok(())
    }

    #[test]
    fn sctp_idata_chunk_decode_exposes_semantic_fields_and_preserved_padding() -> Result<()> {
        let bytes = [
            SCTP_CHUNK_TYPE_I_DATA,
            0x0d,
            0x00,
            0x17,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x10,
            0xde,
            0xad,
            0xbe,
            0xee,
        ];

        let chunks = decode_chunks(bytes)?;
        let SctpChunk::IData(data) = &chunks[0] else {
            panic!("I-DATA codepoint must decode as SctpIDataChunk");
        };

        assert_eq!(data.flags(), 0x0d);
        assert_eq!(data.explicit_declared_length(), Some(23));
        assert_eq!(data.padding(), &[0xee]);
        assert_eq!(data.tsn()?, 0x0102_0304);
        assert_eq!(data.stream_id()?, 0x0506);
        assert_eq!(data.reserved()?, 0x0708);
        assert_eq!(data.message_identifier()?, 0x090a_0b0c);
        assert_eq!(data.ppid_fsn()?, 0x0d0e_0f10);
        assert_eq!(data.payload_protocol_identifier()?, None);
        assert_eq!(data.fragment_sequence_number()?, Some(0x0d0e_0f10));
        assert_eq!(data.user_data()?, &[0xde, 0xad, 0xbe]);
        Ok(())
    }

    #[test]
    fn sctp_idata_chunk_decode_rejects_short_semantic_value() {
        let bytes = [
            SCTP_CHUNK_TYPE_I_DATA,
            0x00,
            0x00,
            0x13,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x00,
        ];

        assert_eq!(
            decode_chunks(bytes).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_IDATA_CHUNK_VALUE_CONTEXT,
                SCTP_IDATA_CHUNK_VALUE_HEADER_LEN,
                15,
            )
        );
    }

    #[test]
    fn sctp_idata_chunk_raw_constructor_preserves_short_value_until_semantic_access() {
        let chunk = SctpIDataChunk::new([0xaa]).with_flags(0xf0);

        assert_eq!(chunk.flags(), 0xf0);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(chunk.length(), SCTP_CHUNK_HEADER_LEN + 1);
        assert_eq!(
            chunk.tsn().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_IDATA_CHUNK_VALUE_CONTEXT,
                SCTP_IDATA_CHUNK_VALUE_HEADER_LEN,
                1,
            )
        );
    }

    #[test]
    fn sctp_idata_chunk_preserves_explicit_length_padding_and_malformed_raw_value() {
        let chunk =
            SctpIDataChunk::from_idata(0x0102_0304, 0x0506, 0x0708_090a, 0x0b0c_0d0e, [0xde, 0xad])
                .with_declared_length(7)
                .with_padding([0xee, 0xff])
                .with_value([0xaa]);

        assert_eq!(chunk.chunk_type_value(), SCTP_CHUNK_TYPE_I_DATA);
        assert_eq!(chunk.explicit_declared_length(), Some(7));
        assert_eq!(chunk.length(), 7);
        assert_eq!(chunk.padding(), &[0xee, 0xff]);
        assert_eq!(chunk.value(), &[0xaa]);
        assert_eq!(
            chunk.message_identifier().unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_IDATA_CHUNK_VALUE_CONTEXT,
                SCTP_IDATA_CHUNK_VALUE_HEADER_LEN,
                1,
            )
        );

        let enum_chunk = SctpChunk::from(chunk);
        assert!(matches!(enum_chunk, SctpChunk::IData(_)));
        assert_eq!(enum_chunk.explicit_declared_length(), Some(7));
    }

    #[test]
    fn sctp_idata_chunk_flags_constants_match_source_notes() {
        assert_eq!(SCTP_IDATA_FLAG_END, 0x01);
        assert_eq!(SCTP_IDATA_FLAG_BEGIN, 0x02);
        assert_eq!(SCTP_IDATA_FLAG_UNORDERED, 0x04);
        assert_eq!(SCTP_IDATA_FLAG_SACK_IMMEDIATELY, 0x08);
        assert_eq!(SCTP_IDATA_FLAG_E, SCTP_IDATA_FLAG_END);
        assert_eq!(SCTP_IDATA_FLAG_B, SCTP_IDATA_FLAG_BEGIN);
        assert_eq!(SCTP_IDATA_FLAG_U, SCTP_IDATA_FLAG_UNORDERED);
        assert_eq!(SCTP_IDATA_FLAG_I, SCTP_IDATA_FLAG_SACK_IMMEDIATELY);
    }

    #[test]
    fn sctp_idata_chunk_flags_helpers_preserve_raw_bits_and_compose() {
        let raw_bits = 0xf0;

        let all_named = SctpIDataChunk::new([])
            .with_flags(raw_bits)
            .unordered()
            .begin()
            .end()
            .sack_immediately();
        assert_eq!(all_named.flags(), raw_bits | 0x0f);
        assert!(all_named.is_begin());
        assert!(all_named.is_end());
        assert!(all_named.is_unordered());
        assert!(all_named.is_sack_immediately());

        let complete_unordered_immediate = SctpIDataChunk::new([])
            .with_flags(raw_bits | SCTP_IDATA_FLAG_UNORDERED | SCTP_IDATA_FLAG_SACK_IMMEDIATELY)
            .complete_message();
        assert_eq!(complete_unordered_immediate.flags(), raw_bits | 0x0f);

        let middle_fragment = SctpIDataChunk::new([])
            .with_flags(raw_bits | 0x0f)
            .fragmented_message();
        assert_eq!(
            middle_fragment.flags(),
            raw_bits | SCTP_IDATA_FLAG_UNORDERED | SCTP_IDATA_FLAG_SACK_IMMEDIATELY
        );
        assert!(!middle_fragment.is_begin());
        assert!(!middle_fragment.is_end());

        let first_fragment = middle_fragment.clone().begin();
        assert_eq!(
            first_fragment.flags(),
            raw_bits
                | SCTP_IDATA_FLAG_BEGIN
                | SCTP_IDATA_FLAG_UNORDERED
                | SCTP_IDATA_FLAG_SACK_IMMEDIATELY
        );

        let last_fragment = middle_fragment.end();
        assert_eq!(
            last_fragment.flags(),
            raw_bits
                | SCTP_IDATA_FLAG_END
                | SCTP_IDATA_FLAG_UNORDERED
                | SCTP_IDATA_FLAG_SACK_IMMEDIATELY
        );
    }

    #[test]
    fn sctp_idata_chunk_flags_setters_and_raw_flags_remain_escape_hatches() {
        let base = 0xf0 | SCTP_IDATA_FLAG_END | SCTP_IDATA_FLAG_BEGIN;

        let cleared = SctpIDataChunk::new([])
            .with_flags(base)
            .set_begin(false)
            .set_end(false);
        assert_eq!(cleared.flags(), 0xf0);

        let toggled = SctpIDataChunk::new([])
            .with_flags(0)
            .set_unordered(true)
            .set_sack_immediately(true)
            .set_unordered(false);
        assert_eq!(toggled.flags(), SCTP_IDATA_FLAG_SACK_IMMEDIATELY);

        let raw_override = SctpIDataChunk::new([])
            .complete_message()
            .sack_immediately()
            .with_flags(0xa0);
        assert_eq!(raw_override.flags(), 0xa0);

        let raw_bit_toggle = SctpIDataChunk::new([])
            .with_flags(0xa0)
            .flag(0x40, false)
            .flag(0x20, true)
            .unordered();
        assert_eq!(
            raw_bit_toggle.flags(),
            0x80 | 0x20 | SCTP_IDATA_FLAG_UNORDERED
        );
    }

    #[test]
    fn sctp_idata_chunk_ppid_fsn_accessors_follow_begin_flag_without_normalizing_word() -> Result<()>
    {
        let raw_word = 0x0102_0304;
        let first = SctpIDataChunk::from_idata(1, 2, 3, raw_word, []).begin();
        let middle = first.clone().set_begin(false);

        assert_eq!(first.ppid_fsn()?, raw_word);
        assert_eq!(first.payload_protocol_identifier()?, Some(raw_word));
        assert_eq!(first.fragment_sequence_number()?, None);

        assert_eq!(middle.ppid_fsn()?, raw_word);
        assert_eq!(middle.payload_protocol_identifier()?, None);
        assert_eq!(middle.fragment_sequence_number()?, Some(raw_word));
        assert_eq!(middle.value(), first.value());
        Ok(())
    }

    #[test]
    fn sctp_encode_chunks_preserves_explicit_malformed_length_and_padding() -> Result<()> {
        let chunk =
            SctpChunk::from_preserved_parts(SCTP_CHUNK_TYPE_INIT, 0x7e, 4, [1, 2, 3], [0xbb]);
        let mut bytes = Vec::new();

        encode_chunk(&chunk, &mut bytes)?;

        assert_eq!(
            bytes,
            [SCTP_CHUNK_TYPE_INIT, 0x7e, 0x00, 0x04, 1, 2, 3, 0xbb]
        );
        Ok(())
    }

    #[test]
    fn sctp_encode_chunks_rejects_auto_declared_length_overflow() {
        let oversized_value = vec![0; usize::from(u16::MAX) - SCTP_CHUNK_HEADER_LEN + 1];
        let chunk = SctpChunk::from(SctpDataChunk::new(oversized_value));
        let mut bytes = Vec::new();

        assert_eq!(
            encode_chunk(&chunk, &mut bytes).unwrap_err(),
            CrafterError::invalid_field_value("sctp.chunk.length", "length must fit in two bytes",)
        );
        assert!(bytes.is_empty());
    }

    #[test]
    fn sctp_malformed_chunks_return_structured_errors() {
        assert_eq!(
            decode_chunks([SCTP_CHUNK_TYPE_DATA, 0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("sctp.chunk.header", SCTP_CHUNK_HEADER_LEN, 3)
        );

        assert_eq!(
            decode_chunks([SCTP_CHUNK_TYPE_DATA, 0x00, 0x00, 0x03]).unwrap_err(),
            CrafterError::invalid_field_value(
                "sctp.chunk.length",
                "declared length must be at least 4 bytes",
            )
        );

        assert_eq!(
            decode_chunks([SCTP_CHUNK_TYPE_DATA, 0x00, 0x00, 0x05, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("sctp.chunk", 8, 5)
        );

        assert_eq!(
            decode_chunks([SCTP_CHUNK_TYPE_INIT, 0x00, 0x00, 0x04, 0xff]).unwrap_err(),
            CrafterError::buffer_too_short(
                SCTP_INIT_CHUNK_VALUE_CONTEXT,
                SCTP_INIT_CHUNK_VALUE_HEADER_LEN,
                0,
            )
        );

        assert_eq!(
            decode_chunks([
                SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4,
                0x00,
                0x00,
                0x04,
                0xff,
            ])
            .unwrap_err(),
            CrafterError::buffer_too_short("sctp.chunk.header", SCTP_CHUNK_HEADER_LEN, 1)
        );
    }
}
