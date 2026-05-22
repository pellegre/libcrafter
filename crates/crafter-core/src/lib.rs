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
};
pub use protocols::{
    Arp, ArpOperation, Dot1Q, Ethernet, LinuxSll, NullByteOrder, NullLoopback, Vlan, ETHERTYPE_ARP,
    ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_VLAN,
};
