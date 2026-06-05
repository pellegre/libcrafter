//! IPv4-specific constants.

/// IPv4 "reserved" flag bit.
pub const IPV4_FLAG_RESERVED: u8 = 0b100;
/// IPv4 "don't fragment" flag bit.
pub const IPV4_FLAG_DONT_FRAGMENT: u8 = 0b010;
/// IPv4 "more fragments" flag bit.
pub const IPV4_FLAG_MORE_FRAGMENTS: u8 = 0b001;

/// IPv4 end-of-option-list option kind.
pub const IPV4_OPTION_EOL: u8 = 0;
/// IPv4 no-operation option kind.
pub const IPV4_OPTION_NOP: u8 = 1;
/// IPv4 record-route option kind.
pub const IPV4_OPTION_RECORD_ROUTE: u8 = 7;
/// IPv4 timestamp option kind.
pub const IPV4_OPTION_TIMESTAMP: u8 = 0x44;
/// IPv4 traceroute option kind.
pub const IPV4_OPTION_TRACEROUTE: u8 = 0x52;
/// IPv4 loose source-and-record-route option kind.
pub const IPV4_OPTION_LOOSE_SOURCE_ROUTE: u8 = 0x83;
/// IPv4 strict source-and-record-route option kind.
pub const IPV4_OPTION_STRICT_SOURCE_ROUTE: u8 = 0x89;
/// IPv4 router-alert option kind.
pub const IPV4_OPTION_ROUTER_ALERT: u8 = 0x94;
/// IPv4 option kind reserved for experimentation and testing.
pub const IPV4_OPTION_EXPERIMENTAL_1: u8 = 30;
/// IPv4 option kind reserved for experimentation and testing.
pub const IPV4_OPTION_EXPERIMENTAL_2: u8 = 94;
/// IPv4 option kind reserved for experimentation and testing.
pub const IPV4_OPTION_EXPERIMENTAL_3: u8 = 158;
/// IPv4 option kind reserved for experimentation and testing.
pub const IPV4_OPTION_EXPERIMENTAL_4: u8 = 222;

pub(super) const IPV4_MIN_HEADER_LEN: usize = 20;
pub(super) const IPV4_MAX_HEADER_LEN: usize = 60;
pub(super) const IPV4_MAX_IHL: u8 = 15;
pub(super) const IPV4_MAX_FLAGS: u8 = 0b111;
pub(super) const IPV4_MAX_FRAGMENT_OFFSET: u16 = 0x1fff;
pub(super) const IPV4_OPTION_COPIED_MASK: u8 = 0b1000_0000;
pub(super) const IPV4_OPTION_CLASS_MASK: u8 = 0b0110_0000;
pub(super) const IPV4_OPTION_CLASS_SHIFT: u8 = 5;
pub(super) const IPV4_OPTION_NUMBER_MASK: u8 = 0b0001_1111;
pub(super) const IPV4_TIMESTAMP_MIN_LEN: usize = 4;
pub(super) const IPV4_TIMESTAMP_MAX_LEN: usize = 40;
pub(super) const IPV4_TIMESTAMP_POINTER_MIN: u8 = 5;
pub(super) const IPV4_TIMESTAMP_FLAG_TIMESTAMPS_ONLY: u8 = 0;
pub(super) const IPV4_TIMESTAMP_FLAG_ADDRESS_AND_TIMESTAMP: u8 = 1;
pub(super) const IPV4_TIMESTAMP_FLAG_PRESPECIFIED_ADDRESS: u8 = 3;
pub(super) const IPV4_TIMESTAMP_WORD_LEN: usize = 4;
pub(super) const IPV4_TIMESTAMP_ADDRESS_WORD_LEN: usize = 8;
pub(super) const IPV4_ROUTER_ALERT_LEN: usize = 4;
