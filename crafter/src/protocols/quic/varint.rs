//! QUIC variable-length integer placeholder.
//!
//! The source-backed varint encoding and decoding rules are implemented in
//! later steps. The helpers here are non-panicking stubs that preserve a caller
//! supplied numeric value and return structured errors for attempted parsing or
//! encoding.

use crate::error::{CrafterError, Result};

/// Placeholder QUIC variable-length integer value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicVarInt {
    value: u64,
}

impl QuicVarInt {
    /// Preserve a caller-supplied value without applying future range policy.
    pub const fn from_u64_unchecked(value: u64) -> Self {
        Self { value }
    }

    /// Return the preserved numeric value.
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Placeholder encoder that fails structurally until the varint step lands.
    pub fn encode_placeholder(self, _out: &mut Vec<u8>) -> Result<()> {
        Err(CrafterError::invalid_field_value(
            "quic.varint",
            "QUIC varint encoding is not implemented in the module skeleton",
        ))
    }

    /// Placeholder decoder that reports truncation before unsupported parsing.
    pub fn decode_placeholder(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.is_empty() {
            return Err(CrafterError::buffer_too_short(
                "quic.varint.prefix",
                1,
                bytes.len(),
            ));
        }

        Err(CrafterError::invalid_field_value(
            "quic.varint",
            "QUIC varint decoding is not implemented in the module skeleton",
        ))
    }
}
