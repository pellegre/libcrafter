//! TCP wire and IANA option-kind constants.

/// TCP end-of-option-list kind.
pub const TCP_OPTION_EOL: u8 = 0;
/// TCP no-operation option kind.
pub const TCP_OPTION_NOP: u8 = 1;
/// TCP maximum segment size option kind.
pub const TCP_OPTION_MSS: u8 = 2;
/// TCP window scale option kind.
pub const TCP_OPTION_WINDOW_SCALE: u8 = 3;
/// TCP SACK-permitted option kind.
pub const TCP_OPTION_SACK_PERMITTED: u8 = 4;
/// TCP SACK option kind.
pub const TCP_OPTION_SACK: u8 = 5;
/// TCP timestamp option kind.
pub const TCP_OPTION_TIMESTAMP: u8 = 8;
/// TCP MD5 Signature option kind (RFC 2385, obsoleted by RFC 5925/TCP-AO).
pub const TCP_OPTION_MD5_SIGNATURE: u8 = 19;
/// TCP User Timeout (UTO) option kind (RFC 5482).
pub const TCP_OPTION_USER_TIMEOUT: u8 = 28;
/// TCP Authentication Option (TCP-AO) kind (RFC 5925).
pub const TCP_OPTION_TCP_AUTHENTICATION: u8 = 29;
/// TCP MPTCP option kind (RFC 8684).
pub const TCP_OPTION_MPTCP: u8 = 30;
/// TCP Fast Open Cookie option kind (RFC 7413).
pub const TCP_OPTION_FAST_OPEN: u8 = 34;
/// TCP Encryption Negotiation Option (TCP-ENO) kind (RFC 8547).
pub const TCP_OPTION_TCP_ENO: u8 = 69;
/// TCP Accurate ECN Order 0 (AccECN0) option kind (RFC 9768).
pub const TCP_OPTION_ACCURATE_ECN_ORDER_0: u8 = 172;
/// TCP Accurate ECN Order 1 (AccECN1) option kind (RFC 9768).
pub const TCP_OPTION_ACCURATE_ECN_ORDER_1: u8 = 174;
/// TCP RFC 3692-style experimental option kind 1 (RFC 6994).
pub const TCP_OPTION_EXPERIMENTAL_1: u8 = 253;
/// TCP RFC 3692-style experimental option kind 2 (RFC 6994).
pub const TCP_OPTION_EXPERIMENTAL_2: u8 = 254;
/// Minimum length byte of an RFC 6994 experimental option: kind, length, and a
/// 16-bit Experiment Identifier (ExID) with no experiment data.
pub const TCP_OPTION_EXPERIMENTAL_MIN_LEN: u8 = 4;
/// TCP Extended Data Offset option kind.
pub const TCP_OPTION_EDO: u8 = 237;

/// EDO request length byte.
pub const TCP_EDO_REQUEST_LEN: u8 = 2;
/// EDO length byte carrying an extended TCP header length.
pub const TCP_EDO_HEADER_LEN: u8 = 4;
/// EDO length byte carrying an extended TCP header length and segment length.
pub const TCP_EDO_HEADER_AND_SEGMENT_LEN: u8 = 6;

pub(crate) const TCP_MIN_HEADER_LEN: usize = 20;
pub(crate) const TCP_MAX_HEADER_LEN: usize = 60;
pub(crate) const TCP_MAX_DATA_OFFSET: u8 = 15;
pub(crate) const TCP_MAX_RESERVED: u8 = 0x07;
pub(crate) const TCP_MAX_FLAGS: u16 = 0x01ff;
