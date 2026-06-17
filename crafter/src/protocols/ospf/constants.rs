//! OSPFv2 (RFC 2328) wire constants.
//!
//! Codepoints and fixed lengths taken from RFC 2328 (OSPF Version 2). Each
//! constant cites its defining RFC section in a line comment. These values are
//! the codepoints the OSPF builder, decode, and spec steps consume.

// ---------------------------------------------------------------------------
// Version (RFC 2328 §A.3.1)
// ---------------------------------------------------------------------------

/// OSPF protocol version carried in the common header. RFC 2328 §A.3.1.
pub const OSPF_VERSION_2: u8 = 2;

// ---------------------------------------------------------------------------
// Packet types (RFC 2328 §A.3.1)
// ---------------------------------------------------------------------------

/// Hello packet type. RFC 2328 §A.3.1 / §A.3.2.
pub const OSPF_TYPE_HELLO: u8 = 1;
/// Database Description packet type. RFC 2328 §A.3.1 / §A.3.3.
pub const OSPF_TYPE_DATABASE_DESCRIPTION: u8 = 2;
/// Link State Request packet type. RFC 2328 §A.3.1 / §A.3.4.
pub const OSPF_TYPE_LINK_STATE_REQUEST: u8 = 3;
/// Link State Update packet type. RFC 2328 §A.3.1 / §A.3.5.
pub const OSPF_TYPE_LINK_STATE_UPDATE: u8 = 4;
/// Link State Acknowledgment packet type. RFC 2328 §A.3.1 / §A.3.6.
pub const OSPF_TYPE_LINK_STATE_ACK: u8 = 5;

// ---------------------------------------------------------------------------
// Fixed lengths (RFC 2328 §A.3.1)
// ---------------------------------------------------------------------------

/// OSPF common header length, in octets. RFC 2328 §A.3.1.
pub const OSPF_HEADER_LEN: usize = 24;
/// OSPF Authentication field length, in octets. RFC 2328 §A.3.1.
pub const OSPF_AUTH_LEN: usize = 8;

// ---------------------------------------------------------------------------
// Authentication types (RFC 2328 §A.3.1, §D)
// ---------------------------------------------------------------------------

/// Null authentication (AuType 0). RFC 2328 §D.1.
pub const OSPF_AUTYPE_NULL: u16 = 0;
/// Simple password authentication (AuType 1). RFC 2328 §D.2.
pub const OSPF_AUTYPE_SIMPLE: u16 = 1;
/// Cryptographic authentication (AuType 2). RFC 2328 §D.3.
pub const OSPF_AUTYPE_CRYPTOGRAPHIC: u16 = 2;
