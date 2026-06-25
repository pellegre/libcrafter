//! QUIC transport-parameter placeholder.
//!
//! Transport-parameter identifier and value parsing are deferred. This type
//! keeps unknown or malformed values byte-preserving once a caller supplies an
//! explicit identifier boundary.

use super::QuicVarInt;

/// Raw-preserving transport parameter placeholder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicTransportParameter {
    identifier: Option<QuicVarInt>,
    value: Vec<u8>,
}

impl QuicTransportParameter {
    /// Preserve a transport parameter identifier and raw value bytes.
    pub fn raw(identifier: QuicVarInt, value: impl AsRef<[u8]>) -> Self {
        Self {
            identifier: Some(identifier),
            value: value.as_ref().to_vec(),
        }
    }

    /// Return the preserved identifier, if present.
    pub const fn identifier(&self) -> Option<QuicVarInt> {
        self.identifier
    }

    /// Borrow the preserved value bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}
