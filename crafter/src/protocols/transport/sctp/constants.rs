//! SCTP wire constants.
//!
//! Values are sourced from `.agents/docs/sctp-rfc-manifest.md`,
//! `.agents/docs/sctp-codepoints.md`, and `.agents/docs/sctp-wire-grammar.md`.

#![allow(dead_code)]

use core::fmt;

/// Fixed SCTP common header length in octets (RFC 9260 section 3.1).
pub const SCTP_COMMON_HEADER_LEN: usize = 12;
/// Fixed SCTP chunk header length in octets (RFC 9260 section 3.2).
pub const SCTP_CHUNK_HEADER_LEN: usize = 4;
/// Fixed SCTP parameter TLV header length in octets (RFC 9260 section 3.2.1).
pub const SCTP_PARAMETER_HEADER_LEN: usize = 4;
/// Fixed SCTP error-cause header length in octets (RFC 9260 section 3.3.10).
pub const SCTP_ERROR_CAUSE_HEADER_LEN: usize = 4;
/// SCTP chunk, parameter, and cause alignment in octets (RFC 9260 section 3.2).
pub const SCTP_ALIGNMENT: usize = 4;
/// SCTP checksum field length in octets (RFC 9260 section 3.1).
pub const SCTP_CHECKSUM_LEN: usize = 4;
/// SCTP checksum field offset in the common header (RFC 9260 section 3.1).
pub const SCTP_CHECKSUM_OFFSET: usize = 8;

/// IANA IP protocol / IPv6 next-header value for SCTP.
pub const SCTP_IP_PROTOCOL: u8 = crate::protocols::ip::shared::IPPROTO_SCTP;
/// IPv4 Protocol value used for native SCTP when the field is unset.
pub const SCTP_IPV4_PROTOCOL: u8 = SCTP_IP_PROTOCOL;
/// IPv6 Next Header value used for native SCTP when the field is unset.
pub const SCTP_IPV6_NEXT_HEADER: u8 = SCTP_IP_PROTOCOL;
/// RFC 6951 UDP port for SCTP UDP encapsulation (`sctp-tunneling`).
pub const SCTP_UDP_ENCAPSULATION_PORT: u16 = 9_899;
/// Compatibility alias using the IANA service-name terminology.
pub const SCTP_UDP_TUNNELING_PORT: u16 = SCTP_UDP_ENCAPSULATION_PORT;

/// SCTP DATA chunk type (RFC 9260).
pub const SCTP_CHUNK_TYPE_DATA: u8 = 0;
/// SCTP INIT chunk type (RFC 9260).
pub const SCTP_CHUNK_TYPE_INIT: u8 = 1;
/// SCTP INIT ACK chunk type (RFC 9260).
pub const SCTP_CHUNK_TYPE_INIT_ACK: u8 = 2;
/// SCTP SACK chunk type (RFC 9260).
pub const SCTP_CHUNK_TYPE_SACK: u8 = 3;
/// SCTP HEARTBEAT chunk type (RFC 9260).
pub const SCTP_CHUNK_TYPE_HEARTBEAT: u8 = 4;
/// SCTP HEARTBEAT ACK chunk type (RFC 9260).
pub const SCTP_CHUNK_TYPE_HEARTBEAT_ACK: u8 = 5;
/// SCTP ABORT chunk type (RFC 9260).
pub const SCTP_CHUNK_TYPE_ABORT: u8 = 6;
/// SCTP SHUTDOWN chunk type (RFC 9260).
pub const SCTP_CHUNK_TYPE_SHUTDOWN: u8 = 7;
/// SCTP SHUTDOWN ACK chunk type (RFC 9260).
pub const SCTP_CHUNK_TYPE_SHUTDOWN_ACK: u8 = 8;
/// SCTP ERROR chunk type (RFC 9260).
pub const SCTP_CHUNK_TYPE_ERROR: u8 = 9;
/// SCTP COOKIE ECHO chunk type (RFC 9260).
pub const SCTP_CHUNK_TYPE_COOKIE_ECHO: u8 = 10;
/// SCTP COOKIE ACK chunk type (RFC 9260).
pub const SCTP_CHUNK_TYPE_COOKIE_ACK: u8 = 11;
/// SCTP ECNE chunk type, reserved for ECN Echo (RFC 9260 / IANA).
pub const SCTP_CHUNK_TYPE_ECNE: u8 = 12;
/// SCTP CWR chunk type, reserved for Congestion Window Reduced (RFC 9260 / IANA).
pub const SCTP_CHUNK_TYPE_CWR: u8 = 13;
/// SCTP SHUTDOWN COMPLETE chunk type (RFC 9260).
pub const SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE: u8 = 14;
/// SCTP AUTH chunk type (RFC 4895 / IANA).
pub const SCTP_CHUNK_TYPE_AUTH: u8 = 15;
/// Reserved chunk type for IETF-defined chunk extensions (RFC 9260 / IANA).
pub const SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_1: u8 = 63;
/// SCTP I-DATA chunk type (RFC 8260 / IANA).
pub const SCTP_CHUNK_TYPE_I_DATA: u8 = 64;
/// Temporary SCTP DTLS chunk type (IANA, draft-backed).
pub const SCTP_CHUNK_TYPE_DTLS: u8 = 65;
/// Reserved chunk type for IETF-defined chunk extensions (RFC 9260 / IANA).
pub const SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_2: u8 = 127;
/// SCTP ASCONF-ACK chunk type (RFC 5061 / IANA).
pub const SCTP_CHUNK_TYPE_ASCONF_ACK: u8 = 128;
/// SCTP RE-CONFIG chunk type (RFC 6525 / IANA).
pub const SCTP_CHUNK_TYPE_RE_CONFIG: u8 = 130;
/// SCTP PAD chunk type (RFC 4820 / IANA).
pub const SCTP_CHUNK_TYPE_PAD: u8 = 132;
/// Reserved chunk type for IETF-defined chunk extensions (RFC 9260 / IANA).
pub const SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_3: u8 = 191;
/// SCTP FORWARD TSN chunk type (RFC 3758 / IANA).
pub const SCTP_CHUNK_TYPE_FORWARD_TSN: u8 = 192;
/// SCTP ASCONF chunk type (RFC 5061 / IANA).
pub const SCTP_CHUNK_TYPE_ASCONF: u8 = 193;
/// SCTP I-FORWARD-TSN chunk type (RFC 8260 / IANA).
pub const SCTP_CHUNK_TYPE_I_FORWARD_TSN: u8 = 194;
/// Reserved chunk type for IETF-defined chunk extensions (RFC 9260 / IANA).
pub const SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4: u8 = 255;

/// SCTP Heartbeat Info parameter type (RFC 9260).
pub const SCTP_PARAMETER_TYPE_HEARTBEAT_INFO: u16 = 1;
/// SCTP IPv4 Address parameter type (RFC 9260).
pub const SCTP_PARAMETER_TYPE_IPV4_ADDRESS: u16 = 5;
/// SCTP IPv6 Address parameter type (RFC 9260).
pub const SCTP_PARAMETER_TYPE_IPV6_ADDRESS: u16 = 6;
/// SCTP State Cookie parameter type (RFC 9260).
pub const SCTP_PARAMETER_TYPE_STATE_COOKIE: u16 = 7;
/// SCTP Unrecognized Parameter parameter type (RFC 9260).
pub const SCTP_PARAMETER_TYPE_UNRECOGNIZED_PARAMETER: u16 = 8;
/// SCTP Cookie Preservative parameter type (RFC 9260).
pub const SCTP_PARAMETER_TYPE_COOKIE_PRESERVATIVE: u16 = 9;
/// SCTP Host Name Address parameter type (RFC 9260).
pub const SCTP_PARAMETER_TYPE_HOST_NAME_ADDRESS: u16 = 11;
/// SCTP Supported Address Types parameter type (RFC 9260).
pub const SCTP_PARAMETER_TYPE_SUPPORTED_ADDRESS_TYPES: u16 = 12;
/// SCTP Outgoing SSN Reset Request parameter type (RFC 6525 / IANA).
pub const SCTP_PARAMETER_TYPE_OUTGOING_SSN_RESET_REQUEST: u16 = 13;
/// SCTP Incoming SSN Reset Request parameter type (RFC 6525 / IANA).
pub const SCTP_PARAMETER_TYPE_INCOMING_SSN_RESET_REQUEST: u16 = 14;
/// SCTP SSN/TSN Reset Request parameter type (RFC 6525 / IANA).
pub const SCTP_PARAMETER_TYPE_SSN_TSN_RESET_REQUEST: u16 = 15;
/// SCTP Re-configuration Response parameter type (RFC 6525 / IANA).
pub const SCTP_PARAMETER_TYPE_RE_CONFIGURATION_RESPONSE: u16 = 16;
/// SCTP Add Outgoing Streams Request parameter type (RFC 6525 / IANA).
pub const SCTP_PARAMETER_TYPE_ADD_OUTGOING_STREAMS_REQUEST: u16 = 17;
/// SCTP Add Incoming Streams Request parameter type (RFC 6525 / IANA).
pub const SCTP_PARAMETER_TYPE_ADD_INCOMING_STREAMS_REQUEST: u16 = 18;
/// Reserved ECN Capable parameter type (RFC 9260 / IANA).
pub const SCTP_PARAMETER_TYPE_ECN_CAPABLE: u16 = 32_768;
/// SCTP Zero Checksum Acceptable parameter type (RFC 9653 / IANA).
pub const SCTP_PARAMETER_TYPE_ZERO_CHECKSUM_ACCEPTABLE: u16 = 32_769;
/// SCTP AUTH Random parameter type (RFC 4895 / IANA).
pub const SCTP_PARAMETER_TYPE_RANDOM: u16 = 32_770;
/// SCTP AUTH Chunk List parameter type (RFC 4895 / IANA).
pub const SCTP_PARAMETER_TYPE_CHUNK_LIST: u16 = 32_771;
/// SCTP AUTH Requested HMAC Algorithm parameter type (RFC 4895 / IANA).
pub const SCTP_PARAMETER_TYPE_REQUESTED_HMAC_ALGORITHM: u16 = 32_772;
/// SCTP Padding parameter type (RFC 4820 / IANA).
pub const SCTP_PARAMETER_TYPE_PADDING: u16 = 32_773;
/// Temporary SCTP DTLS Key Management parameter type (IANA, draft-backed).
pub const SCTP_PARAMETER_TYPE_DTLS_KEY_MANAGEMENT: u16 = 32_774;
/// SCTP Supported Extensions parameter type (RFC 5061 / IANA).
pub const SCTP_PARAMETER_TYPE_SUPPORTED_EXTENSIONS: u16 = 32_776;
/// SCTP Forward TSN supported parameter type (RFC 3758 / IANA).
pub const SCTP_PARAMETER_TYPE_FORWARD_TSN_SUPPORTED: u16 = 49_152;
/// SCTP Add IP Address parameter type (RFC 5061 / IANA).
pub const SCTP_PARAMETER_TYPE_ADD_IP_ADDRESS: u16 = 49_153;
/// SCTP Delete IP Address parameter type (RFC 5061 / IANA).
pub const SCTP_PARAMETER_TYPE_DELETE_IP_ADDRESS: u16 = 49_154;
/// SCTP Error Cause Indication parameter type (RFC 5061 / IANA).
pub const SCTP_PARAMETER_TYPE_ERROR_CAUSE_INDICATION: u16 = 49_155;
/// SCTP Set Primary Address parameter type (RFC 5061 / IANA).
pub const SCTP_PARAMETER_TYPE_SET_PRIMARY_ADDRESS: u16 = 49_156;
/// SCTP Success Indication parameter type (RFC 5061 / IANA).
pub const SCTP_PARAMETER_TYPE_SUCCESS_INDICATION: u16 = 49_157;
/// SCTP Adaptation Layer Indication parameter type (RFC 5061 / IANA).
pub const SCTP_PARAMETER_TYPE_ADAPTATION_LAYER_INDICATION: u16 = 49_158;
/// Reserved parameter type for IETF-defined chunk extensions (RFC 9260 / IANA).
pub const SCTP_PARAMETER_TYPE_IETF_DEFINED_EXTENSION: u16 = 65_535;

/// SCTP Invalid Stream Identifier error cause code (RFC 9260).
pub const SCTP_CAUSE_CODE_INVALID_STREAM_IDENTIFIER: u16 = 1;
/// SCTP Missing Mandatory Parameter error cause code (RFC 9260).
pub const SCTP_CAUSE_CODE_MISSING_MANDATORY_PARAMETER: u16 = 2;
/// SCTP Stale Cookie error cause code (RFC 9260).
pub const SCTP_CAUSE_CODE_STALE_COOKIE: u16 = 3;
/// SCTP Out of Resource error cause code (RFC 9260).
pub const SCTP_CAUSE_CODE_OUT_OF_RESOURCE: u16 = 4;
/// SCTP Unresolvable Address error cause code (RFC 9260).
pub const SCTP_CAUSE_CODE_UNRESOLVABLE_ADDRESS: u16 = 5;
/// SCTP Unrecognized Chunk Type error cause code (RFC 9260).
pub const SCTP_CAUSE_CODE_UNRECOGNIZED_CHUNK_TYPE: u16 = 6;
/// SCTP Invalid Mandatory Parameter error cause code (RFC 9260).
pub const SCTP_CAUSE_CODE_INVALID_MANDATORY_PARAMETER: u16 = 7;
/// SCTP Unrecognized Parameters error cause code (RFC 9260).
pub const SCTP_CAUSE_CODE_UNRECOGNIZED_PARAMETERS: u16 = 8;
/// SCTP No User Data error cause code (RFC 9260).
pub const SCTP_CAUSE_CODE_NO_USER_DATA: u16 = 9;
/// SCTP Cookie Received While Shutting Down error cause code (RFC 9260).
pub const SCTP_CAUSE_CODE_COOKIE_RECEIVED_WHILE_SHUTTING_DOWN: u16 = 10;
/// SCTP Restart of an Association with New Addresses error cause code (RFC 9260).
pub const SCTP_CAUSE_CODE_RESTART_WITH_NEW_ADDRESSES: u16 = 11;
/// SCTP User-Initiated Abort error cause code (RFC 9260).
pub const SCTP_CAUSE_CODE_USER_INITIATED_ABORT: u16 = 12;
/// SCTP Protocol Violation error cause code (RFC 9260).
pub const SCTP_CAUSE_CODE_PROTOCOL_VIOLATION: u16 = 13;
/// SCTP Request to Delete Last Remaining IP Address error cause code (RFC 5061).
pub const SCTP_CAUSE_CODE_DELETE_LAST_REMAINING_IP_ADDRESS: u16 = 160;
/// SCTP Operation Refused Due to Resource Shortage error cause code (RFC 5061).
pub const SCTP_CAUSE_CODE_OPERATION_REFUSED_RESOURCE_SHORTAGE: u16 = 161;
/// SCTP Request to Delete Source IP Address error cause code (RFC 5061).
pub const SCTP_CAUSE_CODE_DELETE_SOURCE_IP_ADDRESS: u16 = 162;
/// SCTP Association Aborted due to illegal ASCONF-ACK error cause code (RFC 5061).
pub const SCTP_CAUSE_CODE_ILLEGAL_ASCONF_ACK: u16 = 163;
/// SCTP Request refused - no authorization error cause code (RFC 5061).
pub const SCTP_CAUSE_CODE_REQUEST_REFUSED_NO_AUTHORIZATION: u16 = 164;
/// SCTP Unsupported HMAC Identifier error cause code (RFC 4895).
pub const SCTP_CAUSE_CODE_UNSUPPORTED_HMAC_IDENTIFIER: u16 = 261;

/// SCTP PPID 0 reserved value (RFC 9260 / IANA).
pub const SCTP_PPID_RESERVED: u32 = 0;
/// SCTP PPID for IUA.
pub const SCTP_PPID_IUA: u32 = 1;
/// SCTP PPID for M2UA.
pub const SCTP_PPID_M2UA: u32 = 2;
/// SCTP PPID for M3UA.
pub const SCTP_PPID_M3UA: u32 = 3;
/// SCTP PPID for SUA.
pub const SCTP_PPID_SUA: u32 = 4;
/// SCTP PPID for M2PA.
pub const SCTP_PPID_M2PA: u32 = 5;
/// SCTP PPID for V5UA.
pub const SCTP_PPID_V5UA: u32 = 6;
/// SCTP PPID for H.248.
pub const SCTP_PPID_H248: u32 = 7;
/// SCTP PPID for BICC/Q.2150.3.
pub const SCTP_PPID_BICC_Q2150_3: u32 = 8;
/// SCTP PPID for TALI.
pub const SCTP_PPID_TALI: u32 = 9;
/// SCTP PPID for DUA.
pub const SCTP_PPID_DUA: u32 = 10;
/// SCTP PPID for ASAP.
pub const SCTP_PPID_ASAP: u32 = 11;
/// SCTP PPID for ENRP.
pub const SCTP_PPID_ENRP: u32 = 12;
/// SCTP PPID for H.323.
pub const SCTP_PPID_H323: u32 = 13;
/// SCTP PPID for Q.IPC/Q.2150.3.
pub const SCTP_PPID_QIPC_Q2150_3: u32 = 14;
/// SCTP PPID for SIMCO.
pub const SCTP_PPID_SIMCO: u32 = 15;
/// SCTP PPID for DDP Segment Chunk.
pub const SCTP_PPID_DDP_SEGMENT_CHUNK: u32 = 16;
/// SCTP PPID for DDP Stream Session Control.
pub const SCTP_PPID_DDP_STREAM_SESSION_CONTROL: u32 = 17;
/// SCTP PPID for S1AP.
pub const SCTP_PPID_S1AP: u32 = 18;
/// SCTP PPID for RUA.
pub const SCTP_PPID_RUA: u32 = 19;
/// SCTP PPID for HNBAP.
pub const SCTP_PPID_HNBAP: u32 = 20;
/// SCTP PPID for ForCES-HP.
pub const SCTP_PPID_FORCES_HP: u32 = 21;
/// SCTP PPID for ForCES-MP.
pub const SCTP_PPID_FORCES_MP: u32 = 22;
/// SCTP PPID for ForCES-LP.
pub const SCTP_PPID_FORCES_LP: u32 = 23;
/// SCTP PPID for SBc-AP.
pub const SCTP_PPID_SBC_AP: u32 = 24;
/// SCTP PPID for NBAP.
pub const SCTP_PPID_NBAP: u32 = 25;
/// SCTP PPID for X2AP.
pub const SCTP_PPID_X2AP: u32 = 27;
/// SCTP PPID for Inter Router Capability Protocol.
pub const SCTP_PPID_IRCP: u32 = 28;
/// SCTP PPID for LCS-AP.
pub const SCTP_PPID_LCS_AP: u32 = 29;
/// SCTP PPID for MPICH2.
pub const SCTP_PPID_MPICH2: u32 = 30;
/// SCTP PPID for Service Area Broadcast Protocol.
pub const SCTP_PPID_SABP: u32 = 31;
/// SCTP PPID for Fractal Generator Protocol.
pub const SCTP_PPID_FGP: u32 = 32;
/// SCTP PPID for Ping Pong Protocol.
pub const SCTP_PPID_PING_PONG: u32 = 33;
/// SCTP PPID for CalcApp Protocol.
pub const SCTP_PPID_CALCAPP: u32 = 34;
/// SCTP PPID for Scripting Service Protocol.
pub const SCTP_PPID_SSP: u32 = 35;
/// SCTP PPID for NetPerfMeter Protocol Control Channel.
pub const SCTP_PPID_NPMP_CONTROL: u32 = 36;
/// SCTP PPID for NetPerfMeter Protocol Data Channel.
pub const SCTP_PPID_NPMP_DATA: u32 = 37;
/// SCTP PPID for Echo.
pub const SCTP_PPID_ECHO: u32 = 38;
/// SCTP PPID for Discard.
pub const SCTP_PPID_DISCARD: u32 = 39;
/// SCTP PPID for Daytime.
pub const SCTP_PPID_DAYTIME: u32 = 40;
/// SCTP PPID for Character Generator.
pub const SCTP_PPID_CHARGEN: u32 = 41;
/// SCTP PPID for 3GPP RNA.
pub const SCTP_PPID_3GPP_RNA: u32 = 42;
/// SCTP PPID for 3GPP M2AP.
pub const SCTP_PPID_3GPP_M2AP: u32 = 43;
/// SCTP PPID for 3GPP M3AP.
pub const SCTP_PPID_3GPP_M3AP: u32 = 44;
/// SCTP PPID for SSH over SCTP.
pub const SCTP_PPID_SSH_OVER_SCTP: u32 = 45;
/// SCTP PPID for Diameter in SCTP DATA (RFC 6733 / IANA).
pub const SCTP_PPID_DIAMETER: u32 = 46;
/// SCTP PPID for Diameter in DTLS/SCTP DATA (RFC 6733 / IANA).
pub const SCTP_PPID_DIAMETER_DTLS: u32 = 47;
/// SCTP PPID for R14P.
pub const SCTP_PPID_R14P: u32 = 48;
/// SCTP PPID for Generic Data Transfer.
pub const SCTP_PPID_GENERIC_DATA_TRANSFER: u32 = 49;
/// SCTP PPID for WebRTC DCEP (RFC 8831 / RFC 8832 / IANA).
pub const SCTP_PPID_WEBRTC_DCEP: u32 = 50;
/// SCTP PPID for WebRTC string (RFC 8831 / IANA).
pub const SCTP_PPID_WEBRTC_STRING: u32 = 51;
/// SCTP PPID for WebRTC binary partial (RFC 8831 / IANA).
pub const SCTP_PPID_WEBRTC_BINARY_PARTIAL: u32 = 52;
/// SCTP PPID for WebRTC binary (RFC 8831 / IANA).
pub const SCTP_PPID_WEBRTC_BINARY: u32 = 53;
/// SCTP PPID for WebRTC string partial (RFC 8831 / IANA).
pub const SCTP_PPID_WEBRTC_STRING_PARTIAL: u32 = 54;
/// SCTP PPID for 3GPP PUA.
pub const SCTP_PPID_3GPP_PUA: u32 = 55;
/// SCTP PPID for WebRTC string empty (RFC 8831 / IANA).
pub const SCTP_PPID_WEBRTC_STRING_EMPTY: u32 = 56;
/// SCTP PPID for WebRTC binary empty (RFC 8831 / IANA).
pub const SCTP_PPID_WEBRTC_BINARY_EMPTY: u32 = 57;
/// SCTP PPID for XwAP.
pub const SCTP_PPID_XWAP: u32 = 58;
/// SCTP PPID for Xw-Control Plane.
pub const SCTP_PPID_XW_CONTROL_PLANE: u32 = 59;
/// SCTP PPID for NGAP.
pub const SCTP_PPID_NGAP: u32 = 60;
/// SCTP PPID for XnAP.
pub const SCTP_PPID_XNAP: u32 = 61;
/// SCTP PPID for F1 AP.
pub const SCTP_PPID_F1AP: u32 = 62;
/// SCTP PPID for HTTP/SCTP.
pub const SCTP_PPID_HTTP_OVER_SCTP: u32 = 63;
/// SCTP PPID for E1AP.
pub const SCTP_PPID_E1AP: u32 = 64;
/// First SCTP PPID in the ELE2 LI and 3GPP DTLS-over-SCTP range.
pub const SCTP_PPID_ELE2_LI_AND_3GPP_DTLS_START: u32 = 65;
/// Last SCTP PPID in the ELE2 LI and 3GPP DTLS-over-SCTP range.
pub const SCTP_PPID_ELE2_LI_AND_3GPP_DTLS_END: u32 = 69;
/// SCTP PPID for ELE2 Lawful Interception.
pub const SCTP_PPID_ELE2_LI: u32 = 65;
/// SCTP PPID for 3GPP NGAP over DTLS over SCTP.
pub const SCTP_PPID_NGAP_DTLS: u32 = 66;
/// SCTP PPID for 3GPP XnAP over DTLS over SCTP.
pub const SCTP_PPID_XNAP_DTLS: u32 = 67;
/// SCTP PPID for 3GPP F1AP over DTLS over SCTP.
pub const SCTP_PPID_F1AP_DTLS: u32 = 68;
/// SCTP PPID for 3GPP E1AP over DTLS over SCTP.
pub const SCTP_PPID_E1AP_DTLS: u32 = 69;
/// SCTP PPID for E2-CP.
pub const SCTP_PPID_E2_CP: u32 = 70;
/// SCTP PPID for O-RAN D2.
pub const SCTP_PPID_ORAN_D2: u32 = 71;
/// SCTP PPID for E2-DU.
pub const SCTP_PPID_E2_DU: u32 = 72;
/// SCTP PPID for W1AP.
pub const SCTP_PPID_W1AP: u32 = 73;
/// SCTP PPID for draft-backed DTLS Chunk Key-Management Messages.
pub const SCTP_PPID_DTLS_CHUNK_KEY_MANAGEMENT: u32 = 4_242;

/// Registry classification for an SCTP Payload Protocol Identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SctpPpidStatus {
    /// PPID `0`, reserved by SCTP.
    Reserved,
    /// Assigned by the current SCTP PPID registry.
    Assigned,
    /// Draft-backed PPID label.
    Draft,
    /// Currently unassigned PPID value.
    Unassigned,
}

impl SctpPpidStatus {
    /// Stable lowercase status label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Assigned => "assigned",
            Self::Draft => "draft",
            Self::Unassigned => "unassigned",
        }
    }
}

impl fmt::Display for SctpPpidStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Return the source-backed registry status for an SCTP PPID.
pub const fn sctp_ppid_status(ppid: u32) -> SctpPpidStatus {
    match ppid {
        SCTP_PPID_RESERVED => SctpPpidStatus::Reserved,
        SCTP_PPID_IUA..=SCTP_PPID_NBAP
        | SCTP_PPID_X2AP..=SCTP_PPID_E1AP_DTLS
        | SCTP_PPID_E2_CP..=SCTP_PPID_W1AP => SctpPpidStatus::Assigned,
        SCTP_PPID_DTLS_CHUNK_KEY_MANAGEMENT => SctpPpidStatus::Draft,
        _ => SctpPpidStatus::Unassigned,
    }
}

/// Return true when the PPID is currently assigned.
pub const fn sctp_ppid_is_assigned(ppid: u32) -> bool {
    matches!(sctp_ppid_status(ppid), SctpPpidStatus::Assigned)
}

/// Return true when the PPID is currently reserved.
pub const fn sctp_ppid_is_reserved(ppid: u32) -> bool {
    matches!(sctp_ppid_status(ppid), SctpPpidStatus::Reserved)
}

/// Return true when the PPID is draft-backed.
pub const fn sctp_ppid_is_draft(ppid: u32) -> bool {
    matches!(sctp_ppid_status(ppid), SctpPpidStatus::Draft)
}

/// Return true when the PPID is currently unassigned.
pub const fn sctp_ppid_is_unassigned(ppid: u32) -> bool {
    matches!(sctp_ppid_status(ppid), SctpPpidStatus::Unassigned)
}

/// Return the source-backed registry label for an SCTP PPID, when known.
pub const fn sctp_ppid_name(ppid: u32) -> Option<&'static str> {
    match ppid {
        SCTP_PPID_RESERVED => Some("Reserved by SCTP"),
        SCTP_PPID_IUA => Some("IUA"),
        SCTP_PPID_M2UA => Some("M2UA"),
        SCTP_PPID_M3UA => Some("M3UA"),
        SCTP_PPID_SUA => Some("SUA"),
        SCTP_PPID_M2PA => Some("M2PA"),
        SCTP_PPID_V5UA => Some("V5UA"),
        SCTP_PPID_H248 => Some("H.248"),
        SCTP_PPID_BICC_Q2150_3 => Some("BICC/Q.2150.3"),
        SCTP_PPID_TALI => Some("TALI"),
        SCTP_PPID_DUA => Some("DUA"),
        SCTP_PPID_ASAP => Some("ASAP"),
        SCTP_PPID_ENRP => Some("ENRP"),
        SCTP_PPID_H323 => Some("H.323"),
        SCTP_PPID_QIPC_Q2150_3 => Some("Q.IPC/Q.2150.3"),
        SCTP_PPID_SIMCO => Some("SIMCO"),
        SCTP_PPID_DDP_SEGMENT_CHUNK => Some("DDP Segment Chunk"),
        SCTP_PPID_DDP_STREAM_SESSION_CONTROL => Some("DDP Stream Session Control"),
        SCTP_PPID_S1AP => Some("S1AP"),
        SCTP_PPID_RUA => Some("RUA"),
        SCTP_PPID_HNBAP => Some("HNBAP"),
        SCTP_PPID_FORCES_HP => Some("ForCES-HP"),
        SCTP_PPID_FORCES_MP => Some("ForCES-MP"),
        SCTP_PPID_FORCES_LP => Some("ForCES-LP"),
        SCTP_PPID_SBC_AP => Some("SBc-AP"),
        SCTP_PPID_NBAP => Some("NBAP"),
        SCTP_PPID_X2AP => Some("X2AP"),
        SCTP_PPID_IRCP => Some("IRCP - Inter Router Capability Protocol"),
        SCTP_PPID_LCS_AP => Some("LCS-AP"),
        SCTP_PPID_MPICH2 => Some("MPICH2"),
        SCTP_PPID_SABP => Some("Service Area Broadcast Protocol (SABP)"),
        SCTP_PPID_FGP => Some("Fractal Generator Protocol (FGP)"),
        SCTP_PPID_PING_PONG => Some("Ping Pong Protocol (PPP)"),
        SCTP_PPID_CALCAPP => Some("CalcApp Protocol (CALCAPP)"),
        SCTP_PPID_SSP => Some("Scripting Service Protocol (SSP)"),
        SCTP_PPID_NPMP_CONTROL => Some("NetPerfMeter Protocol Control Channel (NPMP-CONTROL)"),
        SCTP_PPID_NPMP_DATA => Some("NetPerfMeter Protocol Data Channel (NPMP-DATA)"),
        SCTP_PPID_ECHO => Some("Echo (ECHO)"),
        SCTP_PPID_DISCARD => Some("Discard (DISCARD)"),
        SCTP_PPID_DAYTIME => Some("Daytime (DAYTIME)"),
        SCTP_PPID_CHARGEN => Some("Character Generator (CHARGEN)"),
        SCTP_PPID_3GPP_RNA => Some("3GPP RNA"),
        SCTP_PPID_3GPP_M2AP => Some("3GPP M2AP"),
        SCTP_PPID_3GPP_M3AP => Some("3GPP M3AP"),
        SCTP_PPID_SSH_OVER_SCTP => Some("SSH over SCTP"),
        SCTP_PPID_DIAMETER => Some("Diameter in a SCTP DATA chunk"),
        SCTP_PPID_DIAMETER_DTLS => Some("Diameter in a DTLS/SCTP DATA chunk"),
        SCTP_PPID_R14P => Some("R14P. BER Encoded ASN.1 over SCTP"),
        SCTP_PPID_GENERIC_DATA_TRANSFER => Some("Generic Data Transfer (GDT) Protocol"),
        SCTP_PPID_WEBRTC_DCEP => Some("WebRTC DCEP"),
        SCTP_PPID_WEBRTC_STRING => Some("WebRTC String"),
        SCTP_PPID_WEBRTC_BINARY_PARTIAL => Some("WebRTC Binary Partial (deprecated)"),
        SCTP_PPID_WEBRTC_BINARY => Some("WebRTC Binary"),
        SCTP_PPID_WEBRTC_STRING_PARTIAL => Some("WebRTC String Partial (deprecated)"),
        SCTP_PPID_3GPP_PUA => Some("3GPP PUA"),
        SCTP_PPID_WEBRTC_STRING_EMPTY => Some("WebRTC String Empty"),
        SCTP_PPID_WEBRTC_BINARY_EMPTY => Some("WebRTC Binary Empty"),
        SCTP_PPID_XWAP => Some("3GPP XwAP"),
        SCTP_PPID_XW_CONTROL_PLANE => Some("3GPP Xw-Control Plane"),
        SCTP_PPID_NGAP => Some("3GPP NG Application Protocol (NGAP)"),
        SCTP_PPID_XNAP => Some("3GPP Xn Application Protocol (XnAP)"),
        SCTP_PPID_F1AP => Some("3GPP F1 Application Protocol (F1 AP)"),
        SCTP_PPID_HTTP_OVER_SCTP => Some("HTTP/SCTP"),
        SCTP_PPID_E1AP => Some("3GPP E1 Application Protocol (E1AP)"),
        SCTP_PPID_ELE2_LI => Some("ELE2 Lawful Interception"),
        SCTP_PPID_NGAP_DTLS => Some("3GPP NGAP over DTLS over SCTP"),
        SCTP_PPID_XNAP_DTLS => Some("3GPP XnAP over DTLS over SCTP"),
        SCTP_PPID_F1AP_DTLS => Some("3GPP F1AP over DTLS over SCTP"),
        SCTP_PPID_E1AP_DTLS => Some("3GPP E1AP over DTLS over SCTP"),
        SCTP_PPID_E2_CP => Some("E2-CP"),
        SCTP_PPID_ORAN_D2 => Some("O-RAN D2"),
        SCTP_PPID_E2_DU => Some("E2-DU"),
        SCTP_PPID_W1AP => Some("3GPP W1AP"),
        SCTP_PPID_DTLS_CHUNK_KEY_MANAGEMENT => Some("DTLS Chunk Key-Management Messages"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sctp_constants_header_lengths_protocol_numbers_and_ports_are_source_backed() {
        assert_eq!(SCTP_COMMON_HEADER_LEN, 12);
        assert_eq!(SCTP_CHUNK_HEADER_LEN, 4);
        assert_eq!(SCTP_PARAMETER_HEADER_LEN, 4);
        assert_eq!(SCTP_ERROR_CAUSE_HEADER_LEN, 4);
        assert_eq!(SCTP_ALIGNMENT, 4);
        assert_eq!(SCTP_CHECKSUM_LEN, 4);
        assert_eq!(SCTP_CHECKSUM_OFFSET, 8);

        assert_eq!(SCTP_IP_PROTOCOL, 132);
        assert_eq!(SCTP_IPV4_PROTOCOL, SCTP_IP_PROTOCOL);
        assert_eq!(SCTP_IPV6_NEXT_HEADER, SCTP_IP_PROTOCOL);
        assert_eq!(SCTP_UDP_ENCAPSULATION_PORT, 9_899);
        assert_eq!(SCTP_UDP_TUNNELING_PORT, SCTP_UDP_ENCAPSULATION_PORT);
    }

    #[test]
    fn sctp_constants_chunk_type_values_are_source_backed() {
        assert_eq!(SCTP_CHUNK_TYPE_DATA, 0);
        assert_eq!(SCTP_CHUNK_TYPE_INIT, 1);
        assert_eq!(SCTP_CHUNK_TYPE_INIT_ACK, 2);
        assert_eq!(SCTP_CHUNK_TYPE_SACK, 3);
        assert_eq!(SCTP_CHUNK_TYPE_HEARTBEAT, 4);
        assert_eq!(SCTP_CHUNK_TYPE_HEARTBEAT_ACK, 5);
        assert_eq!(SCTP_CHUNK_TYPE_ABORT, 6);
        assert_eq!(SCTP_CHUNK_TYPE_SHUTDOWN, 7);
        assert_eq!(SCTP_CHUNK_TYPE_SHUTDOWN_ACK, 8);
        assert_eq!(SCTP_CHUNK_TYPE_ERROR, 9);
        assert_eq!(SCTP_CHUNK_TYPE_COOKIE_ECHO, 10);
        assert_eq!(SCTP_CHUNK_TYPE_COOKIE_ACK, 11);
        assert_eq!(SCTP_CHUNK_TYPE_ECNE, 12);
        assert_eq!(SCTP_CHUNK_TYPE_CWR, 13);
        assert_eq!(SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE, 14);
        assert_eq!(SCTP_CHUNK_TYPE_AUTH, 15);
        assert_eq!(SCTP_CHUNK_TYPE_I_DATA, 64);
        assert_eq!(SCTP_CHUNK_TYPE_DTLS, 65);
        assert_eq!(SCTP_CHUNK_TYPE_ASCONF_ACK, 128);
        assert_eq!(SCTP_CHUNK_TYPE_RE_CONFIG, 130);
        assert_eq!(SCTP_CHUNK_TYPE_PAD, 132);
        assert_eq!(SCTP_CHUNK_TYPE_FORWARD_TSN, 192);
        assert_eq!(SCTP_CHUNK_TYPE_ASCONF, 193);
        assert_eq!(SCTP_CHUNK_TYPE_I_FORWARD_TSN, 194);
        assert_eq!(SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4, 255);
    }

    #[test]
    fn sctp_constants_parameter_and_cause_values_are_source_backed() {
        assert_eq!(SCTP_PARAMETER_TYPE_HEARTBEAT_INFO, 1);
        assert_eq!(SCTP_PARAMETER_TYPE_IPV4_ADDRESS, 5);
        assert_eq!(SCTP_PARAMETER_TYPE_IPV6_ADDRESS, 6);
        assert_eq!(SCTP_PARAMETER_TYPE_STATE_COOKIE, 7);
        assert_eq!(SCTP_PARAMETER_TYPE_UNRECOGNIZED_PARAMETER, 8);
        assert_eq!(SCTP_PARAMETER_TYPE_COOKIE_PRESERVATIVE, 9);
        assert_eq!(SCTP_PARAMETER_TYPE_HOST_NAME_ADDRESS, 11);
        assert_eq!(SCTP_PARAMETER_TYPE_SUPPORTED_ADDRESS_TYPES, 12);
        assert_eq!(SCTP_PARAMETER_TYPE_ZERO_CHECKSUM_ACCEPTABLE, 32_769);
        assert_eq!(SCTP_PARAMETER_TYPE_RANDOM, 32_770);
        assert_eq!(SCTP_PARAMETER_TYPE_SUPPORTED_EXTENSIONS, 32_776);
        assert_eq!(SCTP_PARAMETER_TYPE_FORWARD_TSN_SUPPORTED, 49_152);
        assert_eq!(SCTP_PARAMETER_TYPE_ADAPTATION_LAYER_INDICATION, 49_158);
        assert_eq!(SCTP_PARAMETER_TYPE_IETF_DEFINED_EXTENSION, 65_535);

        assert_eq!(SCTP_CAUSE_CODE_INVALID_STREAM_IDENTIFIER, 1);
        assert_eq!(SCTP_CAUSE_CODE_PROTOCOL_VIOLATION, 13);
        assert_eq!(SCTP_CAUSE_CODE_DELETE_LAST_REMAINING_IP_ADDRESS, 160);
        assert_eq!(SCTP_CAUSE_CODE_REQUEST_REFUSED_NO_AUTHORIZATION, 164);
        assert_eq!(SCTP_CAUSE_CODE_UNSUPPORTED_HMAC_IDENTIFIER, 261);
    }

    #[test]
    fn sctp_constants_ppid_values_are_source_backed() {
        assert_eq!(SCTP_PPID_RESERVED, 0);
        assert_eq!(SCTP_PPID_IUA, 1);
        assert_eq!(SCTP_PPID_V5UA, 6);
        assert_eq!(SCTP_PPID_H248, 7);
        assert_eq!(SCTP_PPID_SIMCO, 15);
        assert_eq!(SCTP_PPID_DDP_SEGMENT_CHUNK, 16);
        assert_eq!(SCTP_PPID_NBAP, 25);
        assert_eq!(SCTP_PPID_X2AP, 27);
        assert_eq!(SCTP_PPID_CHARGEN, 41);
        assert_eq!(SCTP_PPID_SSH_OVER_SCTP, 45);
        assert_eq!(SCTP_PPID_DIAMETER, 46);
        assert_eq!(SCTP_PPID_WEBRTC_DCEP, 50);
        assert_eq!(SCTP_PPID_WEBRTC_BINARY_EMPTY, 57);
        assert_eq!(SCTP_PPID_XWAP, 58);
        assert_eq!(SCTP_PPID_E1AP, 64);
        assert_eq!(SCTP_PPID_ELE2_LI_AND_3GPP_DTLS_START, 65);
        assert_eq!(SCTP_PPID_ELE2_LI, 65);
        assert_eq!(SCTP_PPID_E1AP_DTLS, 69);
        assert_eq!(SCTP_PPID_ELE2_LI_AND_3GPP_DTLS_END, 69);
        assert_eq!(SCTP_PPID_E2_CP, 70);
        assert_eq!(SCTP_PPID_W1AP, 73);
        assert_eq!(SCTP_PPID_DTLS_CHUNK_KEY_MANAGEMENT, 4_242);
    }

    #[test]
    fn sctp_ppid_classification_names_and_status_are_source_backed() {
        assert_eq!(
            sctp_ppid_status(SCTP_PPID_RESERVED),
            SctpPpidStatus::Reserved
        );
        assert_eq!(sctp_ppid_name(SCTP_PPID_RESERVED), Some("Reserved by SCTP"));
        assert!(sctp_ppid_is_reserved(SCTP_PPID_RESERVED));

        assert_eq!(
            sctp_ppid_status(SCTP_PPID_WEBRTC_DCEP),
            SctpPpidStatus::Assigned
        );
        assert_eq!(sctp_ppid_name(SCTP_PPID_WEBRTC_DCEP), Some("WebRTC DCEP"));
        assert!(sctp_ppid_is_assigned(SCTP_PPID_WEBRTC_DCEP));

        assert_eq!(
            sctp_ppid_name(SCTP_PPID_IRCP),
            Some("IRCP - Inter Router Capability Protocol")
        );
        assert_eq!(
            sctp_ppid_name(SCTP_PPID_NPMP_CONTROL),
            Some("NetPerfMeter Protocol Control Channel (NPMP-CONTROL)")
        );
        assert_eq!(
            sctp_ppid_name(SCTP_PPID_E1AP_DTLS),
            Some("3GPP E1AP over DTLS over SCTP")
        );

        assert_eq!(sctp_ppid_status(26), SctpPpidStatus::Unassigned);
        assert_eq!(sctp_ppid_name(26), None);
        assert!(sctp_ppid_is_unassigned(26));

        assert_eq!(
            sctp_ppid_status(SCTP_PPID_DTLS_CHUNK_KEY_MANAGEMENT),
            SctpPpidStatus::Draft
        );
        assert_eq!(
            sctp_ppid_name(SCTP_PPID_DTLS_CHUNK_KEY_MANAGEMENT),
            Some("DTLS Chunk Key-Management Messages")
        );
        assert!(sctp_ppid_is_draft(SCTP_PPID_DTLS_CHUNK_KEY_MANAGEMENT));
        assert_eq!(SctpPpidStatus::Draft.to_string(), "draft");
    }
}
