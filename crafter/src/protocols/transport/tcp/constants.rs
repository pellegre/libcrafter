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
/// TCP MPTCP option kind.
pub const TCP_OPTION_MPTCP: u8 = 30;
/// TCP Fast Open option kind.
pub const TCP_OPTION_FAST_OPEN: u8 = 34;
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
