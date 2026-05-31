//! UDP protocol implementation.

mod constants;
mod datagram;
mod option;
mod surplus;

pub use self::constants::{
    UDP_HEADER_LEN, UDP_OPTION_APC, UDP_OPTION_AUTH, UDP_OPTION_EOL, UDP_OPTION_EXP,
    UDP_OPTION_FRAG, UDP_OPTION_MDS, UDP_OPTION_MRDS, UDP_OPTION_NOP, UDP_OPTION_REQ,
    UDP_OPTION_RES, UDP_OPTION_RESERVED_SAFE_END, UDP_OPTION_RESERVED_SAFE_START,
    UDP_OPTION_RESERVED_UNSAFE, UDP_OPTION_TIME, UDP_OPTION_UCMP, UDP_OPTION_UENC, UDP_OPTION_UEXP,
    UDP_OPTION_UNASSIGNED_SAFE_END, UDP_OPTION_UNASSIGNED_SAFE_START,
    UDP_OPTION_UNASSIGNED_UNSAFE_END, UDP_OPTION_UNASSIGNED_UNSAFE_START,
};
pub(crate) use self::datagram::append_udp_packet_with_registry;
pub use self::datagram::{Udp, UdpChecksumStatus};
pub use self::option::{
    udp_option_kind_class, udp_option_kind_is_unsafe, udp_option_kind_is_unsupported, UdpOption,
    UdpOptionIter, UdpOptionKindClass,
};
pub use self::surplus::{UdpOptionStatus, UdpOptions};

#[cfg(test)]
mod tests;
