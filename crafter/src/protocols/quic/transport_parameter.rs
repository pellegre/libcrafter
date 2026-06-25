//! QUIC transport-parameter placeholder.
//!
//! Transport-parameter identifier and value parsing are deferred. This type
//! keeps unknown or malformed values byte-preserving once a caller supplies an
//! explicit identifier boundary.

use super::QuicVarInt;
use crate::protocols::transport::common::hex_bytes;

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

    /// Length of the preserved value bytes.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Return true when the preserved value is empty.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Stable summary for packet inspection.
    pub fn summary(&self) -> String {
        match self.identifier {
            Some(identifier) => {
                format!(
                    "id=0x{:x} value_len={}",
                    identifier.value(),
                    self.value.len()
                )
            }
            None => format!("id=<unset> value_len={}", self.value.len()),
        }
    }

    /// Stable field/value pairs for packet inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "identifier",
                self.identifier
                    .map(|identifier| format!("0x{:x}", identifier.value()))
                    .unwrap_or_else(|| "<unset>".to_string()),
            ),
            ("value_len", self.value.len().to_string()),
            ("value", hex_bytes(&self.value)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_summary_inspection_transport_parameter_summary_preserves_unknown_codepoint() {
        let parameter = QuicTransportParameter::raw(QuicVarInt::new(0xdead).unwrap(), [0xaa, 0xbb]);

        assert_eq!(parameter.summary(), "id=0xdead value_len=2");
        let fields = parameter.inspection_fields();
        assert!(fields.contains(&("identifier", "0xdead".to_string())));
        assert!(fields.contains(&("value", "aa bb".to_string())));
    }
}
