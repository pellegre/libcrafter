/// UDP header length in bytes.
pub const UDP_HEADER_LEN: usize = 8;

/// UDP End of Options List option kind.
pub const UDP_OPTION_EOL: u8 = 0;
/// UDP No Operation option kind.
pub const UDP_OPTION_NOP: u8 = 1;
/// UDP Additional Payload Checksum option kind.
pub const UDP_OPTION_APC: u8 = 2;
/// UDP Fragmentation option kind.
pub const UDP_OPTION_FRAG: u8 = 3;
/// UDP Maximum Datagram Size option kind.
pub const UDP_OPTION_MDS: u8 = 4;
/// UDP Maximum Reassembled Datagram Size option kind.
pub const UDP_OPTION_MRDS: u8 = 5;
/// UDP Echo Request option kind.
pub const UDP_OPTION_REQ: u8 = 6;
/// UDP Echo Response option kind.
pub const UDP_OPTION_RES: u8 = 7;
/// UDP Timestamp option kind.
pub const UDP_OPTION_TIME: u8 = 8;
/// UDP option kind reserved for Authentication.
pub const UDP_OPTION_AUTH: u8 = 9;
/// First currently unassigned SAFE UDP option kind.
pub const UDP_OPTION_UNASSIGNED_SAFE_START: u8 = 10;
/// Last currently unassigned SAFE UDP option kind.
pub const UDP_OPTION_UNASSIGNED_SAFE_END: u8 = 126;
/// UDP RFC 3692-style SAFE experiment option kind.
pub const UDP_OPTION_EXP: u8 = 127;
/// First reserved SAFE UDP option kind.
pub const UDP_OPTION_RESERVED_SAFE_START: u8 = 128;
/// Last reserved SAFE UDP option kind.
pub const UDP_OPTION_RESERVED_SAFE_END: u8 = 191;
/// UDP option kind reserved for UNSAFE Compression.
pub const UDP_OPTION_UCMP: u8 = 192;
/// UDP option kind reserved for UNSAFE Encryption.
pub const UDP_OPTION_UENC: u8 = 193;
/// First currently unassigned UNSAFE UDP option kind.
pub const UDP_OPTION_UNASSIGNED_UNSAFE_START: u8 = 194;
/// Last currently unassigned UNSAFE UDP option kind.
pub const UDP_OPTION_UNASSIGNED_UNSAFE_END: u8 = 253;
/// UDP RFC 3692-style UNSAFE experiment option kind.
pub const UDP_OPTION_UEXP: u8 = 254;
/// Reserved UNSAFE UDP option kind.
pub const UDP_OPTION_RESERVED_UNSAFE: u8 = 255;

pub(super) const UDP_OPTION_SHORT_HEADER_LEN: usize = 2;
pub(super) const UDP_OPTION_EXTENDED_HEADER_LEN: usize = 4;
pub(super) const UDP_OPTION_EXTENDED_LEN_SENTINEL: u8 = 255;
pub(super) const UDP_OPTION_MAX_CONSECUTIVE_NOPS: usize = 7;
pub(super) const UDP_OPTION_LENGTH_CONTEXT: &str = "udp option length";
pub(super) const UDP_OPTION_PAYLOAD_CONTEXT: &str = "udp option payload";
pub(super) const UDP_OPTION_EXTENDED_LENGTH_CONTEXT: &str = "udp option extended length";
pub(super) const UDP_OPTION_EXTENDED_PAYLOAD_CONTEXT: &str = "udp option extended payload";
pub(super) const UDP_OPTION_CHECKSUM_LEN: usize = 2;
pub(super) const UDP_OPTION_APC_LEN: usize = 6;
pub(super) const UDP_OPTION_FRAG_SHORT_LEN: usize = 10;
pub(super) const UDP_OPTION_FRAG_LONG_LEN: usize = 12;
pub(super) const UDP_OPTION_MDS_LEN: usize = 4;
pub(super) const UDP_OPTION_MRDS_LEN: usize = 5;
pub(super) const UDP_OPTION_REQ_LEN: usize = 6;
pub(super) const UDP_OPTION_RES_LEN: usize = 6;
pub(super) const UDP_OPTION_TIME_LEN: usize = 10;
pub(super) const UDP_OPTION_EXPERIMENT_DATA_MIN_LEN: usize = 2;
pub(super) const UDP_OPTION_EXPERIMENT_SHORT_MIN_LEN: usize =
    UDP_OPTION_SHORT_HEADER_LEN + UDP_OPTION_EXPERIMENT_DATA_MIN_LEN;
pub(super) const UDP_OPTION_EXPERIMENT_EXTENDED_MIN_LEN: usize =
    UDP_OPTION_EXTENDED_HEADER_LEN + UDP_OPTION_EXPERIMENT_DATA_MIN_LEN;
