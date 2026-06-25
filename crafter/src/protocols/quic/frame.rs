//! QUIC frame placeholder.
//!
//! Frame type parsing and frame sequence boundaries are source-backed later.
//! This placeholder only preserves raw bytes supplied by a caller.

/// Raw-preserving QUIC frame placeholder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicFrame {
    bytes: Vec<u8>,
}

impl QuicFrame {
    /// Preserve raw frame bytes without attempting to classify them.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self {
            bytes: bytes.as_ref().to_vec(),
        }
    }

    /// Borrow the preserved frame bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the preserved frame bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when no frame bytes are present.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
