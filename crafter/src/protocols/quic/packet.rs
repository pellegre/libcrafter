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
use crate::{CrafterError, Result};

use super::constants::{quic_version_label, quic_version_status};
use super::header::{classify_quic_header, QuicHeaderClassification, QuicLongPacketKind};
use super::QuicConnectionId;

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
    version_negotiation: Option<QuicVersionNegotiationPacket>,
}

impl QuicPacket {
    /// Preserve raw packet bytes until typed packet parsing is implemented.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self {
            bytes: bytes.as_ref().to_vec(),
            version_negotiation: None,
        }
    }

    /// Decode a QUIC packet entry where source-backed typed parsing exists.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        match classify_quic_header(bytes)? {
            QuicHeaderClassification::LongHeader {
                packet_kind: QuicLongPacketKind::VersionNegotiation,
                ..
            } => {
                let version_negotiation = QuicVersionNegotiationPacket::decode(bytes)?;
                Ok(Self {
                    bytes: bytes.to_vec(),
                    version_negotiation: Some(version_negotiation),
                })
            }
            _ => Ok(Self::from_bytes(bytes)),
        }
    }

    /// Return the decoded Version Negotiation packet, when this packet is one.
    pub fn version_negotiation(&self) -> Option<&QuicVersionNegotiationPacket> {
        self.version_negotiation.as_ref()
    }

    /// Return true when this packet is a decoded Version Negotiation packet.
    pub fn is_version_negotiation(&self) -> bool {
        self.version_negotiation.is_some()
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
        if let Some(version_negotiation) = &self.version_negotiation {
            return version_negotiation.summary();
        }
        match classify_quic_header(&self.bytes) {
            Ok(classification) => {
                format!("raw_len={} {}", self.bytes.len(), classification.summary())
            }
            Err(err) => format!("raw_len={} header=malformed error={err}", self.bytes.len()),
        }
    }

    /// Stable field/value pairs for packet inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        if let Some(version_negotiation) = &self.version_negotiation {
            return version_negotiation.inspection_fields();
        }
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

/// Decoded QUIC Version Negotiation packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicVersionNegotiationPacket {
    first_byte: u8,
    destination_connection_id: QuicConnectionId,
    source_connection_id: QuicConnectionId,
    supported_versions: Vec<u32>,
    raw: Vec<u8>,
}

impl QuicVersionNegotiationPacket {
    /// Decode a byte-complete Version Negotiation packet.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let classification = classify_quic_header(bytes)?;
        let QuicHeaderClassification::LongHeader {
            first_byte,
            destination_connection_id,
            source_connection_id,
            invariant_len,
            packet_kind: QuicLongPacketKind::VersionNegotiation,
            ..
        } = classification
        else {
            return Err(CrafterError::invalid_field_value(
                "quic.version_negotiation",
                "packet is not a Version Negotiation packet",
            ));
        };

        let version_bytes = &bytes[invariant_len..];
        if version_bytes.is_empty() || version_bytes.len() % 4 != 0 {
            let missing = if version_bytes.is_empty() {
                4
            } else {
                4 - (version_bytes.len() % 4)
            };
            return Err(CrafterError::buffer_too_short(
                "quic.version_negotiation.supported_versions",
                bytes.len() + missing,
                bytes.len(),
            ));
        }

        let supported_versions = version_bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();

        Ok(Self {
            first_byte,
            destination_connection_id,
            source_connection_id,
            supported_versions,
            raw: bytes.to_vec(),
        })
    }

    /// Raw first byte, including the unused low seven bits.
    pub const fn first_byte(&self) -> u8 {
        self.first_byte
    }

    /// Borrow the Destination Connection ID.
    pub fn destination_connection_id(&self) -> &QuicConnectionId {
        &self.destination_connection_id
    }

    /// Borrow the Source Connection ID.
    pub fn source_connection_id(&self) -> &QuicConnectionId {
        &self.source_connection_id
    }

    /// Borrow the offered supported-version list.
    pub fn supported_versions(&self) -> &[u32] {
        &self.supported_versions
    }

    /// Borrow the preserved packet bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Packet length in bytes.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Return true when the packet has no bytes.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// One-line Version Negotiation summary.
    pub fn summary(&self) -> String {
        format!(
            "VersionNegotiation(raw_len={}, dcid={}, scid={}, supported_versions={})",
            self.raw.len(),
            self.destination_connection_id.summary(),
            self.source_connection_id.summary(),
            version_list_summary(&self.supported_versions)
        )
    }

    /// Stable field/value pairs for packet inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("classification", "version_negotiation".to_string()),
            ("first_byte", format!("0x{:02x}", self.first_byte)),
            (
                "destination_connection_id_len",
                self.destination_connection_id.len().to_string(),
            ),
            (
                "destination_connection_id",
                self.destination_connection_id.to_spaced_hex(),
            ),
            (
                "source_connection_id_len",
                self.source_connection_id.len().to_string(),
            ),
            (
                "source_connection_id",
                self.source_connection_id.to_spaced_hex(),
            ),
            (
                "supported_version_count",
                self.supported_versions.len().to_string(),
            ),
            (
                "supported_versions",
                version_list_summary(&self.supported_versions),
            ),
            (
                "supported_version_statuses",
                self.supported_versions
                    .iter()
                    .map(|version| format!("0x{version:08x}:{:?}", quic_version_status(*version)))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("raw_len", self.raw.len().to_string()),
            ("raw_bytes", hex_bytes(&self.raw)),
        ]
    }
}

fn version_list_summary(versions: &[u32]) -> String {
    versions
        .iter()
        .map(|version| format!("0x{version:08x}({})", quic_version_label(*version)))
        .collect::<Vec<_>>()
        .join(",")
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

    #[test]
    fn quic_version_negotiation_decode_preserves_versions_and_bytes() {
        let bytes = [
            0xc0, 0x00, 0x00, 0x00, 0x00, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x00, 0x00,
            0x00, 0x01, 0x6b, 0x33, 0x43, 0xcf, 0xfa, 0xce, 0xfe, 0xed,
        ];

        let vn = QuicVersionNegotiationPacket::decode(bytes).unwrap();

        assert_eq!(vn.first_byte(), 0xc0);
        assert_eq!(
            vn.destination_connection_id().as_bytes(),
            [0x83, 0x94, 0xc8, 0xf0]
        );
        assert_eq!(vn.source_connection_id().as_bytes(), [0xaa]);
        assert_eq!(
            vn.supported_versions(),
            [0x0000_0001, 0x6b33_43cf, 0xface_feed]
        );
        assert_eq!(vn.as_bytes(), bytes);
        assert_eq!(
            vn.summary(),
            "VersionNegotiation(raw_len=24, dcid=len=4 value=8394c8f0, scid=len=1 value=aa, supported_versions=0x00000001(QUIC v1),0x6b3343cf(QUIC v2),0xfacefeed(unknown version 0xfacefeed))"
        );

        let packet = QuicPacket::decode(bytes).unwrap();
        assert!(packet.is_version_negotiation());
        assert_eq!(packet.as_bytes(), bytes);
        assert_eq!(
            packet.version_negotiation().unwrap().supported_versions(),
            vn.supported_versions()
        );
    }

    #[test]
    fn quic_version_negotiation_decode_inspection_fields_are_stable() {
        let packet = QuicPacket::decode([
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6b, 0x33, 0x43, 0xcf,
        ])
        .unwrap();
        let fields = packet.inspection_fields();

        assert!(fields.contains(&("classification", "version_negotiation".to_string())));
        assert!(fields.contains(&("first_byte", "0x80".to_string())));
        assert!(fields.contains(&("destination_connection_id_len", "0".to_string())));
        assert!(fields.contains(&("source_connection_id_len", "0".to_string())));
        assert!(fields.contains(&("supported_version_count", "1".to_string())));
        assert!(fields.contains(&("supported_versions", "0x6b3343cf(QUIC v2)".to_string(),)));
    }

    #[test]
    fn quic_version_negotiation_decode_reports_missing_or_truncated_versions() {
        assert_eq!(
            QuicVersionNegotiationPacket::decode([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,])
                .unwrap_err(),
            CrafterError::buffer_too_short("quic.version_negotiation.supported_versions", 11, 7,)
        );
        assert_eq!(
            QuicVersionNegotiationPacket::decode([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,])
                .unwrap_err(),
            CrafterError::buffer_too_short("quic.version_negotiation.supported_versions", 11, 8,)
        );
    }

    #[test]
    fn quic_version_negotiation_decode_rejects_non_vn_packets() {
        assert_eq!(
            QuicVersionNegotiationPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,])
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.version_negotiation",
                "packet is not a Version Negotiation packet",
            )
        );
    }
}
