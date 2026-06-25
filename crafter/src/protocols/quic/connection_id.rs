//! QUIC connection ID helpers.
//!
//! QUIC v1/v2 long and short headers limit destination and source connection
//! IDs to at most 20 bytes. Invariant long-header parsing and transport
//! parameter tuples can still carry byte-complete larger values; the unchecked
//! constructor preserves those bytes for later validation.

use core::fmt;

use crate::error::{CrafterError, Result};

/// Maximum QUIC v1/v2 connection ID length.
pub const QUIC_CONNECTION_ID_MAX_LEN: usize = 20;

/// Byte-preserving QUIC connection ID.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicConnectionId {
    bytes: Vec<u8>,
}

impl QuicConnectionId {
    /// Create an empty connection ID.
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Create a checked QUIC v1/v2 connection ID.
    pub fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        validate_len(bytes.len())?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Preserve connection ID bytes without applying the v1/v2 length policy.
    ///
    /// Use this for decoded invariant-header bytes, transport parameters, or
    /// intentionally malformed construction where callers need byte-exact
    /// inspection before applying endpoint policy.
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

    /// Encoded connection ID length in bytes.
    pub fn encoded_len(&self) -> usize {
        self.len()
    }

    /// Return true when the connection ID is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Validate this connection ID against the QUIC v1/v2 20-byte limit.
    pub fn validate_v1_v2_len(&self) -> Result<()> {
        validate_len(self.len())
    }

    /// Return this connection ID as lowercase hexadecimal without separators.
    pub fn to_hex(&self) -> String {
        let mut output = String::with_capacity(self.bytes.len() * 2);
        for byte in &self.bytes {
            output.push_str(&format!("{byte:02x}"));
        }
        output
    }

    /// Return this connection ID as lowercase hexadecimal with spaces between
    /// octets for inspection output.
    pub fn to_spaced_hex(&self) -> String {
        let mut output = String::new();
        for (index, byte) in self.bytes.iter().enumerate() {
            if index > 0 {
                output.push(' ');
            }
            output.push_str(&format!("{byte:02x}"));
        }
        output
    }
}

impl AsRef<[u8]> for QuicConnectionId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for QuicConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

fn validate_len(len: usize) -> Result<()> {
    if len <= QUIC_CONNECTION_ID_MAX_LEN {
        Ok(())
    } else {
        Err(CrafterError::invalid_field_value(
            "quic.connection_id.length",
            "QUIC v1/v2 connection IDs must be at most 20 bytes",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_connection_id_accepts_zero_and_twenty_byte_values() {
        let empty = QuicConnectionId::try_from_bytes([]).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.encoded_len(), 0);
        assert_eq!(empty.to_string(), "");

        let twenty = QuicConnectionId::try_from_bytes([0xab; QUIC_CONNECTION_ID_MAX_LEN]).unwrap();
        assert_eq!(twenty.len(), QUIC_CONNECTION_ID_MAX_LEN);
        assert_eq!(twenty.encoded_len(), QUIC_CONNECTION_ID_MAX_LEN);
        assert_eq!(twenty.to_hex(), "abababababababababababababababababababab");
    }

    #[test]
    fn quic_connection_id_preserves_bytes_and_hex_helpers_roundtrip() {
        let cid = QuicConnectionId::try_from_bytes([0x83, 0x94, 0xc8, 0xf0]).unwrap();

        assert_eq!(cid.as_bytes(), [0x83, 0x94, 0xc8, 0xf0]);
        assert_eq!(cid.as_ref(), [0x83, 0x94, 0xc8, 0xf0]);
        assert_eq!(cid.to_hex(), "8394c8f0");
        assert_eq!(cid.to_spaced_hex(), "83 94 c8 f0");
        assert_eq!(format!("{cid}"), "8394c8f0");
    }

    #[test]
    fn quic_connection_id_reports_invalid_checked_lengths() {
        assert_eq!(
            QuicConnectionId::try_from_bytes([0xaa; QUIC_CONNECTION_ID_MAX_LEN + 1]).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.connection_id.length",
                "QUIC v1/v2 connection IDs must be at most 20 bytes"
            )
        );
    }

    #[test]
    fn quic_connection_id_unchecked_constructor_preserves_malformed_lengths() {
        let oversized = QuicConnectionId::from_bytes([0xaa; QUIC_CONNECTION_ID_MAX_LEN + 1]);

        assert_eq!(oversized.len(), QUIC_CONNECTION_ID_MAX_LEN + 1);
        assert_eq!(
            oversized.validate_v1_v2_len().unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.connection_id.length",
                "QUIC v1/v2 connection IDs must be at most 20 bytes"
            )
        );
    }
}
