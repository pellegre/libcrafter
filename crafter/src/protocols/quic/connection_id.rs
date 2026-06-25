//! QUIC connection ID placeholder.
//!
//! The final source-backed length validation is deferred. This type preserves
//! the bytes a caller or decoder supplies so later packet/header code can keep
//! unknown and malformed connection IDs inspectable.

/// Byte-preserving QUIC connection ID placeholder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicConnectionId {
    bytes: Vec<u8>,
}

impl QuicConnectionId {
    /// Create an empty connection ID.
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Preserve connection ID bytes without applying future length policy.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self {
            bytes: bytes.as_ref().to_vec(),
        }
    }

    /// Borrow the preserved bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of preserved bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when the connection ID is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
