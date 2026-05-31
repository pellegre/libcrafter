//! ARP packet layer, codec, codepoints, and labeling helpers.

mod address;
mod codec;
mod constants;
mod labels;
mod layer;
mod operation;

#[cfg(test)]
mod tests;

pub(crate) use self::codec::append_arp_packet;
pub use self::constants::{
    ARP_HRD_ATM, ARP_HRD_ETHERNET, ARP_HRD_FIBRE_CHANNEL, ARP_HRD_IEEE_802, ARP_HRD_INFINIBAND,
    ARP_HRD_MAPOS, ARP_OP_ARP_NAK, ARP_OP_DRARP_ERROR, ARP_OP_DRARP_REPLY, ARP_OP_DRARP_REQUEST,
    ARP_OP_EXP1, ARP_OP_EXP2, ARP_OP_INARP_REPLY, ARP_OP_INARP_REQUEST, ARP_OP_MAPOS_UNARP,
    ARP_OP_RARP_REPLY, ARP_OP_RARP_REQUEST, ARP_OP_REPLY, ARP_OP_REQUEST, ARP_OP_RESERVED,
    ARP_OP_RESERVED_MAX, ARP_PRO_IPV4,
};
pub use self::labels::{arp_hardware_type_label, arp_protocol_type_label};
pub use self::layer::Arp;
pub use self::operation::ArpOperation;

#[cfg(test)]
use super::{Ethernet, ETHERTYPE_ARP, ETHERTYPE_IPV4};
