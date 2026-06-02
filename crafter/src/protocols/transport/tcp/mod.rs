//! TCP protocol implementation.

mod constants;
mod decode;
mod flags;
mod option;
mod segment;
mod sizing;

pub use self::constants::{
    TCP_EDO_HEADER_AND_SEGMENT_LEN, TCP_EDO_HEADER_LEN, TCP_EDO_REQUEST_LEN,
    TCP_OPTION_ACCURATE_ECN_MIN_LEN, TCP_OPTION_ACCURATE_ECN_ORDER_0,
    TCP_OPTION_ACCURATE_ECN_ORDER_1, TCP_OPTION_EDO, TCP_OPTION_EOL, TCP_OPTION_EXPERIMENTAL_1,
    TCP_OPTION_EXPERIMENTAL_2, TCP_OPTION_EXPERIMENTAL_MIN_LEN, TCP_OPTION_FAST_OPEN,
    TCP_OPTION_MD5_SIGNATURE, TCP_OPTION_MPTCP, TCP_OPTION_MSS, TCP_OPTION_NOP, TCP_OPTION_SACK,
    TCP_OPTION_SACK_PERMITTED, TCP_OPTION_TCP_AUTHENTICATION, TCP_OPTION_TCP_AUTHENTICATION_MIN_LEN,
    TCP_OPTION_TCP_ENO, TCP_OPTION_TCP_ENO_MIN_LEN, TCP_OPTION_TIMESTAMP, TCP_OPTION_USER_TIMEOUT,
    TCP_OPTION_USER_TIMEOUT_LEN, TCP_OPTION_WINDOW_SCALE,
};
pub(crate) use self::decode::append_tcp_packet_with_registry;
pub use self::flags::{
    TCP_FLAG_ACK, TCP_FLAG_AE, TCP_FLAG_CWR, TCP_FLAG_ECE, TCP_FLAG_FIN, TCP_FLAG_NS,
    TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_FLAG_URG,
};
pub use self::option::{
    tcp_option_kind_class, tcp_option_kind_is_assigned, tcp_option_kind_is_experimental,
    TcpExtendedDataOffset, TcpOption, TcpOptionIter, TcpOptionKindClass, TcpSackBlock,
};
pub use self::segment::Tcp;

#[cfg(test)]
mod tests;
