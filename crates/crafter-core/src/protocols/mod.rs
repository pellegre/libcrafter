//! Protocol layer implementations.

pub mod link;

pub use crate::packet::Raw;
pub use link::{
    Arp, ArpOperation, Dot1Q, Ethernet, LinuxSll, NullByteOrder, NullLoopback, Vlan, ETHERTYPE_ARP,
    ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_VLAN,
};
