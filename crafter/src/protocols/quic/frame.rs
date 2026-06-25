//! QUIC frame placeholder.
//!
//! Frame type parsing and frame sequence boundaries are source-backed later.
//! This placeholder only preserves raw bytes supplied by a caller.

use crate::protocols::transport::common::hex_bytes;

use super::QuicVarInt;

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

    /// Return the raw frame type varint when a byte-complete type is available.
    pub fn frame_type(&self) -> Option<QuicVarInt> {
        QuicVarInt::decode(&self.bytes)
            .ok()
            .map(|(frame_type, _)| frame_type)
    }

    /// Stable summary for packet inspection.
    pub fn summary(&self) -> String {
        match self.frame_type() {
            Some(frame_type) => format!(
                "type=0x{:x} raw_len={}",
                frame_type.value(),
                self.bytes.len()
            ),
            None if self.bytes.is_empty() => "type=<empty> raw_len=0".to_string(),
            None => format!("type=<truncated> raw_len={}", self.bytes.len()),
        }
    }

    /// Stable field/value pairs for packet inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "frame_type",
                self.frame_type()
                    .map(|frame_type| format!("0x{:x}", frame_type.value()))
                    .unwrap_or_else(|| "<unavailable>".to_string()),
            ),
            ("raw_len", self.bytes.len().to_string()),
            ("raw_bytes", hex_bytes(&self.bytes)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_summary_inspection_frame_summary_preserves_unknown_codepoint() {
        let frame = QuicFrame::from_bytes([0x40, 0xaf, 0xaa]);

        assert_eq!(frame.summary(), "type=0xaf raw_len=3");
        let fields = frame.inspection_fields();
        assert!(fields.contains(&("frame_type", "0xaf".to_string())));
        assert!(fields.contains(&("raw_bytes", "40 af aa".to_string())));
    }
}
