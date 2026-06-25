//! QUIC packet-number placeholder.
//!
//! Packet-number length selection and decoding are deferred. This type stores
//! caller-supplied values and explicit length overrides without normalizing
//! malformed inputs.

use crate::error::{CrafterError, Result};

/// Placeholder packet-number value and optional encoded length override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicPacketNumber {
    value: u64,
    encoded_len: Option<usize>,
}

impl QuicPacketNumber {
    /// Preserve a packet-number value without applying future length policy.
    pub const fn new(value: u64) -> Self {
        Self {
            value,
            encoded_len: None,
        }
    }

    /// Preserve an explicit encoded length override, including malformed ones.
    pub const fn with_encoded_len(mut self, encoded_len: usize) -> Self {
        self.encoded_len = Some(encoded_len);
        self
    }

    /// Return the preserved packet-number value.
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Return the explicit encoded length override, if present.
    pub const fn encoded_len_value(self) -> Option<usize> {
        self.encoded_len
    }

    /// Placeholder decoder that reports truncation before unsupported parsing.
    pub fn decode_placeholder(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.is_empty() {
            return Err(CrafterError::buffer_too_short(
                "quic.packet_number",
                1,
                bytes.len(),
            ));
        }

        Err(CrafterError::invalid_field_value(
            "quic.packet_number",
            "QUIC packet-number decoding is not implemented in the module skeleton",
        ))
    }
}
