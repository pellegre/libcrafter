//! Authentication Header constants (RFC 4302).
//!
//! The AH header begins with a fixed 12-octet portion — Next Header (1),
//! Payload Len (1), Reserved (2), Security Parameters Index (4), and Sequence
//! Number (4) — followed by a variable-length Integrity Check Value (RFC 4302
//! §2). The Payload Len field counts the entire AH header (including the ICV)
//! in 32-bit words, minus 2 (RFC 4302 §2.2).

/// Length of the fixed AH header preceding the ICV: Next Header (1) +
/// Payload Len (1) + Reserved (2) + SPI (4) + Sequence Number (4) = 12 octets
/// (RFC 4302 §2).
pub const AH_FIXED_LEN: usize = 12;

/// Length of the Next Header field in the AH header (RFC 4302 §2.1).
pub const AH_NEXT_HEADER_LEN: usize = 1;

/// Length of the Payload Len field in the AH header (RFC 4302 §2.2).
pub const AH_PAYLOAD_LEN_FIELD_LEN: usize = 1;

/// Length of the Reserved field in the AH header (RFC 4302 §2.3).
pub const AH_RESERVED_LEN: usize = 2;

/// Length of the Security Parameters Index field in the AH header
/// (RFC 4302 §2.4).
pub const AH_SPI_LEN: usize = 4;

/// Length of the Sequence Number field in the AH header (RFC 4302 §2.5).
pub const AH_SEQUENCE_LEN: usize = 4;

/// Length of the high-order Extended Sequence Number word (RFC 4302 §2.5.1).
///
/// When ESN is enabled the high 32 bits of the 64-bit sequence number are
/// appended to the ICV input but are never transmitted on the wire.
pub const AH_HIGH_SEQUENCE_LEN: usize = 4;

/// Width of a 32-bit word, the unit the Payload Len field is expressed in
/// (RFC 4302 §2.2).
pub const AH_LENGTH_UNIT: usize = 4;

/// Subtrahend applied to the 32-bit-word header length to form the Payload Len
/// field value (RFC 4302 §2.2: "length of this Authentication Header in 4-octet
/// units, minus 2").
pub const AH_PAYLOAD_LEN_OFFSET: u8 = 2;
