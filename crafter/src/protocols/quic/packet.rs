//! QUIC packet/datagram layers.
//!
//! [`Quic`] is a raw-preserving datagram layer. It can compile exactly the bytes
//! supplied by the caller or explicit decoder, or concatenate ordered raw
//! [`QuicPacket`] entries for coalesced datagram work in later steps. It does
//! not infer packet type, version, connection IDs, frame boundaries, packet
//! protection, or endpoint behavior.

use crate::field::{Field, FieldState};
use crate::packet::{Layer, LayerContext};
use crate::protocols::transport::common::{hex_bytes, impl_layer_div, impl_layer_object};
use crate::Result;

/// Raw-preserving QUIC UDP payload layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Quic {
    payload: Field<Vec<u8>>,
    packets: Vec<QuicPacket>,
}

impl Quic {
    /// Create an empty QUIC placeholder layer.
    pub fn new() -> Self {
        Self {
            payload: Field::unset(),
            packets: Vec::new(),
        }
    }

    /// Preserve caller-supplied QUIC payload bytes.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self {
            payload: Field::user(bytes.as_ref().to_vec()),
            packets: Vec::new(),
        }
    }

    /// Compatibility constructor for raw QUIC payload bytes.
    pub fn raw(bytes: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(bytes)
    }

    #[allow(dead_code)]
    pub(crate) fn from_decoded_payload(bytes: &[u8]) -> Self {
        Self {
            payload: Field::user(bytes.to_vec()),
            packets: Vec::new(),
        }
    }

    /// Replace payload bytes with a caller-supplied value.
    pub fn payload(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.payload.set_user(bytes.as_ref().to_vec());
        self.packets.clear();
        self
    }

    /// Append a raw QUIC packet entry to this datagram.
    pub fn packet(mut self, packet: QuicPacket) -> Self {
        if !self.payload.is_unset() {
            self.payload = Field::unset();
        }
        self.packets.push(packet);
        self
    }

    /// Append raw QUIC packet bytes to this datagram.
    pub fn packet_bytes(self, bytes: impl AsRef<[u8]>) -> Self {
        self.packet(QuicPacket::from_bytes(bytes))
    }

    /// Borrow ordered QUIC packet entries.
    pub fn packets(&self) -> &[QuicPacket] {
        &self.packets
    }

    /// Borrow the effective raw payload bytes.
    pub fn payload_bytes(&self) -> &[u8] {
        self.payload.value().map(Vec::as_slice).unwrap_or(&[])
    }

    /// Return true when the layer has no payload bytes.
    pub fn is_empty(&self) -> bool {
        self.payload_bytes().is_empty() && self.packets.is_empty()
    }

    /// Length of the raw payload.
    pub fn len(&self) -> usize {
        if self.packets.is_empty() {
            self.payload_bytes().len()
        } else {
            self.packets.iter().map(QuicPacket::len).sum()
        }
    }

    /// State of the payload field.
    pub fn payload_state(&self) -> FieldState {
        self.payload.state()
    }
}

impl Layer for Quic {
    fn name(&self) -> &'static str {
        "Quic"
    }

    fn summary(&self) -> String {
        format!(
            "Quic(raw_len={}, packets={}, status=raw)",
            self.len(),
            self.packets.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("raw_len", self.len().to_string()),
            ("packet_count", self.packets.len().to_string()),
            ("payload_state", format!("{:?}", self.payload_state())),
            ("raw_bytes", hex_bytes(self.payload_bytes())),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        if self.packets.is_empty() {
            out.extend_from_slice(self.payload_bytes());
        } else {
            for packet in &self.packets {
                out.extend_from_slice(packet.as_bytes());
            }
        }
        Ok(())
    }

    impl_layer_object!(Quic);
}

impl_layer_div!(Quic);

/// Placeholder for an individual QUIC packet within a UDP datagram.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicPacket {
    bytes: Vec<u8>,
}

impl QuicPacket {
    /// Preserve raw packet bytes until typed packet parsing is implemented.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self {
            bytes: bytes.as_ref().to_vec(),
        }
    }

    /// Borrow the preserved packet bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the preserved packet bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when no packet bytes are present.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::Packet;

    use super::*;

    #[test]
    fn quic_datagram_layer_preserves_raw_unsupported_bytes() {
        let payload = [0xc3, 0x00, 0x00, 0x00, 0x01, 0xaa, 0xbb];
        let quic = Quic::from_bytes(payload);

        assert_eq!(quic.payload_bytes(), payload);
        assert_eq!(quic.encoded_len(), payload.len());
        assert_eq!(quic.len(), payload.len());
        assert!(quic.packets().is_empty());
        assert_eq!(quic.summary(), "Quic(raw_len=7, packets=0, status=raw)");
    }

    #[test]
    fn quic_datagram_layer_compiles_raw_payload_through_packet_stack() -> crate::Result<()> {
        let payload = [0xc3, 0x00, 0x00, 0x00, 0x01];
        let compiled = Packet::from_layer(Quic::from_bytes(payload)).compile()?;

        assert_eq!(compiled.as_bytes(), payload);
        Ok(())
    }

    #[test]
    fn quic_datagram_layer_compiles_ordered_raw_packets() -> crate::Result<()> {
        let datagram = Quic::new()
            .packet_bytes([0xc3, 0x00, 0x00])
            .packet(QuicPacket::from_bytes([0xd3, 0x01]));
        let compiled = Packet::from_layer(datagram.clone()).compile()?;

        assert_eq!(datagram.len(), 5);
        assert_eq!(datagram.packets().len(), 2);
        assert_eq!(compiled.as_bytes(), [0xc3, 0x00, 0x00, 0xd3, 0x01]);
        Ok(())
    }

    #[test]
    fn quic_datagram_layer_payload_replaces_packet_entries() -> crate::Result<()> {
        let datagram = Quic::new()
            .packet_bytes([0xc3, 0x00, 0x00])
            .payload([0xaa, 0xbb]);
        let compiled = Packet::from_layer(datagram.clone()).compile()?;

        assert!(datagram.packets().is_empty());
        assert_eq!(datagram.payload_bytes(), [0xaa, 0xbb]);
        assert_eq!(compiled.as_bytes(), [0xaa, 0xbb]);
        Ok(())
    }
}
