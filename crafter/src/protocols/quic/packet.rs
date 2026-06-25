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

use super::header::{classify_quic_header, QuicHeaderClassification};

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

    /// Number of decoded frame entries currently available.
    pub fn frame_count(&self) -> usize {
        0
    }

    /// Number of decoded transport parameter entries currently available.
    pub fn transport_parameter_count(&self) -> usize {
        0
    }

    fn first_packet_bytes_for_inspection(&self) -> &[u8] {
        if let Some(packet) = self.packets.first() {
            packet.as_bytes()
        } else {
            self.payload_bytes()
        }
    }

    fn header_classification_for_inspection(&self) -> Option<Result<QuicHeaderClassification>> {
        let bytes = self.first_packet_bytes_for_inspection();
        if bytes.is_empty() {
            None
        } else {
            Some(classify_quic_header(bytes))
        }
    }

    fn header_summary_for_inspection(&self) -> String {
        match self.header_classification_for_inspection() {
            Some(Ok(classification)) => classification.summary(),
            Some(Err(err)) => format!("header=malformed error={err}"),
            None => "header=empty".to_string(),
        }
    }
}

impl Layer for Quic {
    fn name(&self) -> &'static str {
        "Quic"
    }

    fn summary(&self) -> String {
        format!(
            "Quic(raw_len={}, packets={}, {}, frames={}, transport_parameters={})",
            self.len(),
            self.packets.len(),
            self.header_summary_for_inspection(),
            self.frame_count(),
            self.transport_parameter_count()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("raw_len", self.len().to_string()),
            ("packet_count", self.packets.len().to_string()),
            ("payload_state", format!("{:?}", self.payload_state())),
            ("raw_bytes", hex_bytes(self.payload_bytes())),
            ("frame_count", self.frame_count().to_string()),
            (
                "transport_parameter_count",
                self.transport_parameter_count().to_string(),
            ),
        ];

        match self.header_classification_for_inspection() {
            Some(Ok(classification)) => fields.extend(classification.inspection_fields()),
            Some(Err(err)) => {
                fields.push(("classification", "malformed".to_string()));
                fields.push(("classification_error", err.to_string()));
            }
            None => fields.push(("classification", "empty".to_string())),
        }

        for (index, packet) in self.packets.iter().enumerate() {
            fields.push(("packet", format!("#{index} {}", packet.summary())));
        }

        fields
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

    /// One-line packet summary for datagram inspection.
    pub fn summary(&self) -> String {
        match classify_quic_header(&self.bytes) {
            Ok(classification) => {
                format!("raw_len={} {}", self.bytes.len(), classification.summary())
            }
            Err(err) => format!("raw_len={} header=malformed error={err}", self.bytes.len()),
        }
    }

    /// Stable field/value pairs for packet inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("raw_len", self.bytes.len().to_string()),
            ("raw_bytes", hex_bytes(&self.bytes)),
        ];
        match classify_quic_header(&self.bytes) {
            Ok(classification) => fields.extend(classification.inspection_fields()),
            Err(err) => {
                fields.push(("classification", "malformed".to_string()));
                fields.push(("classification_error", err.to_string()));
            }
        }
        fields
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
        assert_eq!(
            quic.summary(),
            "Quic(raw_len=7, packets=0, header=malformed error=quic.header.long.dcid requires 176 bytes, but only 7 bytes are available, frames=0, transport_parameters=0)"
        );
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

    #[test]
    fn quic_summary_inspection_datagram_exposes_header_and_counts() {
        let payload = [
            0xc3, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x00,
        ];
        let packet = Packet::from_layer(Quic::from_bytes(payload));

        assert_eq!(
            packet.summary(),
            "Quic(raw_len=13, packets=0, header=long kind=Initial version=0x00000001(QUIC v1) dcid=len=4 value=8394c8f0 scid=len=1 value=aa protected_or_raw_len=1, frames=0, transport_parameters=0)"
        );
        let show = packet.show();
        assert!(show.contains("classification: long_header"), "{show}");
        assert!(show.contains("version: 0x00000001 (QUIC v1)"), "{show}");
        assert!(
            show.contains("destination_connection_id: 83 94 c8 f0"),
            "{show}"
        );
        assert!(show.contains("frame_count: 0"), "{show}");
        assert!(show.contains("transport_parameter_count: 0"), "{show}");
    }

    #[test]
    fn quic_summary_inspection_packet_entry_summary_is_stable() {
        let quic_packet = QuicPacket::from_bytes([0x40, 0x83, 0x94, 0xc8, 0xf0, 0x12, 0x34]);

        assert_eq!(
            quic_packet.summary(),
            "raw_len=7 header=short-ambiguous first_byte=0x40 fixed_bit=true"
        );
        let fields = quic_packet.inspection_fields();
        assert!(fields.contains(&("classification", "short_header_ambiguous".to_string())));
        assert!(fields.contains(&("raw_len", "7".to_string())));
    }
}
