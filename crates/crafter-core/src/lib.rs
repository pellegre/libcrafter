//! Core packet model, protocol encoding, protocol decoding, checksums, and formatting.

#![forbid(unsafe_code)]

pub mod checksum;
pub mod endian;
pub mod error;
pub mod field;
pub mod mac;
pub mod packet;
pub mod protocols;

pub use error::{CrafterError, Result};
pub use field::{Field, FieldState};
pub use mac::MacAddr;
pub use packet::{
    hexdump, CompiledPacket, IntoPacket, Layer, LayerContext, LinkType, NetworkLayer, Packet, Raw,
    TransportChecksumContext,
};
pub use protocols::{
    Arp, ArpOperation, Dot1Q, Ethernet, IpProtocol, Ipv4, LinuxSll, NullByteOrder, NullLoopback,
    Tcp, Udp, Vlan, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_VLAN, IPPROTO_ICMP,
    IPPROTO_ICMPV6, IPPROTO_IPV6, IPPROTO_TCP, IPPROTO_UDP, IPV4_FLAG_DONT_FRAGMENT,
    IPV4_FLAG_MORE_FRAGMENTS, IPV4_FLAG_RESERVED, TCP_FLAG_ACK, TCP_FLAG_CWR, TCP_FLAG_ECE,
    TCP_FLAG_FIN, TCP_FLAG_NS, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_FLAG_URG,
};
