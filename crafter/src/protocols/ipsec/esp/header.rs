//! ESP header and trailer constants (RFC 4303).
//!
//! The ESP header is a fixed Security Parameters Index (4 octets) followed by a
//! Sequence Number (4 octets). The encrypted trailer carries the padding, a
//! one-octet Pad Length, and a one-octet Next Header, with the Integrity Check
//! Value appended after the ciphertext (RFC 4303 §2).

/// Length of the unencrypted ESP header: SPI (4) + Sequence Number (4).
pub const ESP_HEADER_LEN: usize = 8;

/// Length of the high-order Extended Sequence Number word (RFC 4303 §2.2.1).
///
/// When ESN is enabled the high 32 bits of the 64-bit sequence number are
/// appended to the ICV/AAD input but are never transmitted on the wire.
pub const ESP_HIGH_SEQUENCE_LEN: usize = 4;

/// Length of the Pad Length field in the ESP trailer (RFC 4303 §2.4).
pub const ESP_PAD_LENGTH_FIELD_LEN: usize = 1;

/// Length of the Next Header field in the ESP trailer (RFC 4303 §2.6).
pub const ESP_NEXT_HEADER_FIELD_LEN: usize = 1;

/// Maximum number of padding octets the ESP trailer can carry.
///
/// The Pad Length field is a single octet, so padding ranges from 0 to 255
/// octets (RFC 4303 §2.4).
pub const ESP_MAX_PAD_LEN: usize = 255;
