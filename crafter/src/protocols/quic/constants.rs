//! Stable QUIC constants.
//!
//! These version constants are the default-eligible QUIC Versions rows recorded
//! in `.agents/docs/quic-codepoints.md` and
//! `.agents/docs/quic-version-extension-matrix.md`.

/// Reserved QUIC version value used by Version Negotiation packets.
pub const QUIC_VERSION_NEGOTIATION: u32 = 0x0000_0000;

/// QUIC version 1, defined by RFC 9000.
pub const QUIC_VERSION_1: u32 = 0x0000_0001;

/// QUIC version 2, defined by RFC 9369.
pub const QUIC_VERSION_2: u32 = 0x6b33_43cf;
