use super::super::ETHERTYPE_IPV4;

pub(super) const ARP_FIXED_HEADER_LEN: usize = 8;

/// ARP operation codepoint: Reserved (RFC 5494, IANA arp-parameters-1 value 0).
pub const ARP_OP_RESERVED: u16 = 0;
/// ARP operation codepoint: REQUEST (RFC 826, IANA arp-parameters-1 value 1).
pub const ARP_OP_REQUEST: u16 = 1;
/// ARP operation codepoint: REPLY (RFC 826, IANA arp-parameters-1 value 2).
pub const ARP_OP_REPLY: u16 = 2;
/// ARP operation codepoint: request Reverse / RARP request
/// (RFC 903, IANA arp-parameters-1 value 3). Codepoint-only: rides the base
/// ARP wire format with no extension-specific behavior.
pub const ARP_OP_RARP_REQUEST: u16 = 3;
/// ARP operation codepoint: reply Reverse / RARP reply
/// (RFC 903, IANA arp-parameters-1 value 4). Codepoint-only.
pub const ARP_OP_RARP_REPLY: u16 = 4;
/// ARP operation codepoint: DRARP-Request
/// (RFC 1931, IANA arp-parameters-1 value 5). Codepoint-only.
pub const ARP_OP_DRARP_REQUEST: u16 = 5;
/// ARP operation codepoint: DRARP-Reply
/// (RFC 1931, IANA arp-parameters-1 value 6). Codepoint-only.
pub const ARP_OP_DRARP_REPLY: u16 = 6;
/// ARP operation codepoint: DRARP-Error
/// (RFC 1931, IANA arp-parameters-1 value 7). Codepoint-only.
pub const ARP_OP_DRARP_ERROR: u16 = 7;
/// ARP operation codepoint: InARP-Request
/// (RFC 2390, IANA arp-parameters-1 value 8). Codepoint-only.
pub const ARP_OP_INARP_REQUEST: u16 = 8;
/// ARP operation codepoint: InARP-Reply
/// (RFC 2390, IANA arp-parameters-1 value 9). Codepoint-only.
pub const ARP_OP_INARP_REPLY: u16 = 9;
/// ARP operation codepoint: ARP-NAK
/// (RFC 1577, IANA arp-parameters-1 value 10). Codepoint-only.
pub const ARP_OP_ARP_NAK: u16 = 10;
/// ARP operation codepoint: MAPOS-UNARP
/// (RFC 2176, IANA arp-parameters-1 value 23). Codepoint-only.
pub const ARP_OP_MAPOS_UNARP: u16 = 23;
/// ARP operation codepoint: experimental OP_EXP1
/// (RFC 5494, IANA arp-parameters-1 value 24).
pub const ARP_OP_EXP1: u16 = 24;
/// ARP operation codepoint: experimental OP_EXP2
/// (RFC 5494, IANA arp-parameters-1 value 25).
pub const ARP_OP_EXP2: u16 = 25;
/// ARP operation codepoint: Reserved (RFC 5494, IANA arp-parameters-1 value 65535).
pub const ARP_OP_RESERVED_MAX: u16 = 65535;

/// ARP hardware type: Ethernet (10Mb) (IANA arp-parameters-2 value 1). Default HRD.
pub const ARP_HRD_ETHERNET: u16 = 1;
/// ARP hardware type: IEEE 802 Networks (IANA arp-parameters-2 value 6).
pub const ARP_HRD_IEEE_802: u16 = 6;
/// ARP hardware type: Fibre Channel (RFC 4338, IANA arp-parameters-2 value 18).
pub const ARP_HRD_FIBRE_CHANNEL: u16 = 18;
/// ARP hardware type: ATM (RFC 2225, IANA arp-parameters-2 value 19).
pub const ARP_HRD_ATM: u16 = 19;
/// ARP hardware type: MAPOS (RFC 2176, IANA arp-parameters-2 value 25).
pub const ARP_HRD_MAPOS: u16 = 25;
/// ARP hardware type: InfiniBand (RFC 4391, IANA arp-parameters-2 value 32).
pub const ARP_HRD_INFINIBAND: u16 = 32;

/// ARP protocol type: IPv4. The protocol-type field shares the EtherType space
/// (IANA arp-parameters-3, administered per RFC 5342), so this equals
/// [`ETHERTYPE_IPV4`]. Default PRO.
pub const ARP_PRO_IPV4: u16 = ETHERTYPE_IPV4;
