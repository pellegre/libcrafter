//! QUIC packet-protection placeholder.
//!
//! Packet protection is intentionally unavailable in the skeleton. Later steps
//! add only source-backed utilities for explicit caller-supplied inputs and
//! fixed vectors; this module never implies ownership of TLS session state or a
//! complete QUIC endpoint.

use crate::error::{CrafterError, Result};

/// Placeholder for future explicit QUIC packet-protection helpers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuicCryptoContext;

impl QuicCryptoContext {
    /// Create an empty placeholder context.
    pub const fn new() -> Self {
        Self
    }

    /// Non-panicking placeholder that reports deferred packet protection.
    pub fn protect_placeholder(self, _packet: &[u8]) -> Result<Vec<u8>> {
        Err(CrafterError::invalid_field_value(
            "quic.crypto",
            "QUIC packet protection is not implemented in the module skeleton",
        ))
    }
}
