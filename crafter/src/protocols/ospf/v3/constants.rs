//! OSPFv3 (RFC 5340) wire constants.
//!
//! Codepoints and fixed lengths taken from RFC 5340 (OSPF for IPv6). OSPFv3
//! reuses the OSPFv2 packet-type numbering (RFC 5340 §A.3) but carries a distinct
//! 16-octet common header (RFC 5340 §A.3.1) with no authentication field — OSPFv3
//! relies on IPsec (RFC 5340 §2.5). These values are the codepoints the OSPFv3
//! builder, decode, and spec steps consume.

// ---------------------------------------------------------------------------
// Version (RFC 5340 §A.3.1)
// ---------------------------------------------------------------------------

/// OSPF protocol version carried in the OSPFv3 common header. RFC 5340 §A.3.1.
pub const OSPF_VERSION_3: u8 = 3;

// ---------------------------------------------------------------------------
// Packet types (RFC 5340 §A.3.1)
// ---------------------------------------------------------------------------
//
// OSPFv3 reuses the OSPFv2 packet-type numbering (RFC 5340 §A.3): Hello,
// Database Description, Link State Request, Link State Update, and Link State
// Acknowledgment carry the same Type codes as their OSPFv2 counterparts.

/// OSPFv3 Hello packet type. RFC 5340 §A.3.1 / §A.3.2.
pub const OSPFV3_TYPE_HELLO: u8 = 1;
/// OSPFv3 Database Description packet type. RFC 5340 §A.3.1 / §A.3.3.
pub const OSPFV3_TYPE_DATABASE_DESCRIPTION: u8 = 2;
/// OSPFv3 Link State Request packet type. RFC 5340 §A.3.1 / §A.3.4.
pub const OSPFV3_TYPE_LINK_STATE_REQUEST: u8 = 3;
/// OSPFv3 Link State Update packet type. RFC 5340 §A.3.1 / §A.3.5.
pub const OSPFV3_TYPE_LINK_STATE_UPDATE: u8 = 4;
/// OSPFv3 Link State Acknowledgment packet type. RFC 5340 §A.3.1 / §A.3.6.
pub const OSPFV3_TYPE_LINK_STATE_ACK: u8 = 5;

// ---------------------------------------------------------------------------
// Fixed lengths (RFC 5340 §A.3.1)
// ---------------------------------------------------------------------------

/// OSPFv3 common header length, in octets. RFC 5340 §A.3.1: Version(1) + Type(1)
/// + Packet Length(2) + Router ID(4) + Area ID(4) + Checksum(2) + Instance ID(1)
/// + Reserved(1).
pub const OSPFV3_HEADER_LEN: usize = 16;
