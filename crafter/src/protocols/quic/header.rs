//! QUIC header placeholder.
//!
//! Version-independent and version-specific header classification is deferred.
//! This type records the raw header prefix and an optional caller-pinned first
//! byte so malformed construction can remain byte-preserving.

use crate::error::{CrafterError, Result};
use crate::field::{Field, FieldState};

/// Raw-preserving QUIC header placeholder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicHeader {
    first_byte: Field<u8>,
    raw: Vec<u8>,
}

impl QuicHeader {
    /// Create an empty placeholder header.
    pub fn new() -> Self {
        Self {
            first_byte: Field::unset(),
            raw: Vec::new(),
        }
    }

    /// Preserve raw header bytes recovered from the wire.
    pub fn from_decoded_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let first = *bytes
            .first()
            .ok_or_else(|| CrafterError::buffer_too_short("quic.header", 1, bytes.len()))?;
        Ok(Self {
            first_byte: Field::user(first),
            raw: bytes.to_vec(),
        })
    }

    /// Pin the first header byte explicitly.
    pub fn first_byte(mut self, first_byte: u8) -> Self {
        self.first_byte.set_user(first_byte);
        self
    }

    /// Stored first-byte value, if one has been supplied or decoded.
    pub fn first_byte_value(&self) -> Option<u8> {
        self.first_byte.value().copied()
    }

    /// State of the first-byte field.
    pub fn first_byte_state(&self) -> FieldState {
        self.first_byte.state()
    }

    /// Borrow the preserved raw header bytes.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}
