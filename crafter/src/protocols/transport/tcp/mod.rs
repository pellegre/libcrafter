//! TCP protocol implementation.

mod constants;
mod decode;
mod flags;
mod option;
mod segment;
mod sizing;

pub use self::constants::{
    TCP_EDO_HEADER_AND_SEGMENT_LEN, TCP_EDO_HEADER_LEN, TCP_EDO_REQUEST_LEN, TCP_OPTION_EDO,
    TCP_OPTION_EOL, TCP_OPTION_FAST_OPEN, TCP_OPTION_MPTCP, TCP_OPTION_MSS, TCP_OPTION_NOP,
    TCP_OPTION_SACK, TCP_OPTION_SACK_PERMITTED, TCP_OPTION_TIMESTAMP, TCP_OPTION_WINDOW_SCALE,
};
pub(crate) use self::decode::append_tcp_packet_with_registry;
pub use self::flags::{
    TCP_FLAG_ACK, TCP_FLAG_CWR, TCP_FLAG_ECE, TCP_FLAG_FIN, TCP_FLAG_NS, TCP_FLAG_PSH,
    TCP_FLAG_RST, TCP_FLAG_SYN, TCP_FLAG_URG,
};
pub use self::option::{TcpExtendedDataOffset, TcpOption, TcpOptionIter, TcpSackBlock};
pub use self::segment::Tcp;

#[cfg(test)]
mod tests;
