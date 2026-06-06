//! Packet record and metadata types.

use std::path::{Path, PathBuf};

use crate::pcap::{PcapLinkType, PcapPacket, PcapRecord, PcapTimestamp};
use crate::{IntoPacket, LinkType, Packet};

/// A packet plus inspectable metadata from capture, transforms, and writers.
#[derive(Debug, Clone)]
pub struct PacketRecord {
    packet: Packet,
    metadata: PacketMetadata,
}

impl PacketRecord {
    /// Create a packet record with default metadata.
    pub fn new(packet: impl IntoPacket) -> Self {
        Self {
            packet: packet.into_packet(),
            metadata: PacketMetadata::default(),
        }
    }

    /// Create a packet record with explicit metadata.
    pub fn from_packet_metadata(packet: impl IntoPacket, metadata: PacketMetadata) -> Self {
        Self {
            packet: packet.into_packet(),
            metadata,
        }
    }

    /// Decode a raw pcap record into a packet record, preserving pcap metadata.
    pub fn try_from_pcap_record(record: PcapRecord) -> crate::Result<Self> {
        let packet = record.decode()?;
        Ok(Self::from_pcap_parts(
            packet,
            record.timestamp(),
            record.original_len(),
            record.data().to_vec(),
            record.pcap_link_type(),
        ))
    }

    /// Convert a decoded pcap packet wrapper into a packet record.
    pub fn from_pcap_packet(packet: PcapPacket) -> Self {
        let timestamp = packet.timestamp();
        let original_len = packet.original_len();
        let captured_bytes = packet.data().to_vec();
        let pcap_link_type = packet.pcap_link_type();
        Self::from_pcap_parts(
            packet.into_packet(),
            timestamp,
            original_len,
            captured_bytes,
            pcap_link_type,
        )
    }

    fn from_pcap_parts(
        packet: Packet,
        timestamp: PcapTimestamp,
        original_len: u32,
        captured_bytes: Vec<u8>,
        pcap_link_type: PcapLinkType,
    ) -> Self {
        let captured_len = captured_bytes.len() as u32;
        Self::new(packet)
            .with_origin(PacketOrigin::Captured)
            .with_pcap_metadata(timestamp, original_len, captured_len, pcap_link_type)
            .with_captured_bytes(captured_bytes)
    }

    /// Borrow the packet.
    pub const fn packet(&self) -> &Packet {
        &self.packet
    }

    /// Mutably borrow the packet.
    pub fn packet_mut(&mut self) -> &mut Packet {
        &mut self.packet
    }

    /// Borrow the record metadata.
    pub const fn metadata(&self) -> &PacketMetadata {
        &self.metadata
    }

    /// Mutably borrow the record metadata.
    pub fn metadata_mut(&mut self) -> &mut PacketMetadata {
        &mut self.metadata
    }

    /// Consume the record and return the packet.
    pub fn into_packet(self) -> Packet {
        self.packet
    }

    /// Consume the record and return the metadata.
    pub fn into_metadata(self) -> PacketMetadata {
        self.metadata
    }

    /// Consume the record and return both packet and metadata.
    pub fn into_parts(self) -> (Packet, PacketMetadata) {
        (self.packet, self.metadata)
    }

    /// Replace the metadata and return the record for builder chaining.
    pub fn with_metadata(mut self, metadata: PacketMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set the packet origin.
    pub fn with_origin(mut self, origin: PacketOrigin) -> Self {
        self.metadata = self.metadata.with_origin(origin);
        self
    }

    /// Set the backend kind.
    pub fn with_backend(mut self, backend: BackendKind) -> Self {
        self.metadata = self.metadata.with_backend(backend);
        self
    }

    /// Set the interface name.
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.metadata = self.metadata.with_interface(interface);
        self
    }

    /// Set the file path.
    pub fn with_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.metadata = self.metadata.with_file(file);
        self
    }

    /// Set pcap-style timestamp, lengths, and link type metadata.
    pub fn with_pcap_metadata(
        mut self,
        timestamp: PcapTimestamp,
        original_len: u32,
        captured_len: u32,
        pcap_link_type: PcapLinkType,
    ) -> Self {
        self.metadata =
            self.metadata
                .with_pcap_metadata(timestamp, original_len, captured_len, pcap_link_type);
        self
    }

    /// Set the capture timestamp.
    pub fn with_timestamp(mut self, timestamp: PcapTimestamp) -> Self {
        self.metadata = self.metadata.with_timestamp(timestamp);
        self
    }

    /// Set original on-wire length metadata.
    pub fn with_original_len(mut self, original_len: u32) -> Self {
        self.metadata = self.metadata.with_original_len(original_len);
        self
    }

    /// Set captured length metadata.
    pub fn with_captured_len(mut self, captured_len: u32) -> Self {
        self.metadata = self.metadata.with_captured_len(captured_len);
        self
    }

    /// Store captured bytes and update captured length metadata.
    pub fn with_captured_bytes(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.metadata = self.metadata.with_captured_bytes(bytes);
        self
    }

    /// Set emitted length metadata.
    pub fn with_emitted_len(mut self, emitted_len: u32) -> Self {
        self.metadata = self.metadata.with_emitted_len(emitted_len);
        self
    }

    /// Set core link-type metadata.
    pub fn with_link_type(mut self, link_type: LinkType) -> Self {
        self.metadata = self.metadata.with_link_type(link_type);
        self
    }

    /// Set pcap link-type metadata and its best-effort core link type.
    pub fn with_pcap_link_type(mut self, pcap_link_type: PcapLinkType) -> Self {
        self.metadata = self.metadata.with_pcap_link_type(pcap_link_type);
        self
    }

    /// Set medium-specific metadata.
    pub fn with_medium(mut self, medium: MediumMetadata) -> Self {
        self.metadata = self.metadata.with_medium(medium);
        self
    }

    /// Append a transform trace.
    pub fn with_transform_trace(mut self, trace: TransformTrace) -> Self {
        self.metadata.push_transform_trace(trace);
        self
    }
}

impl TryFrom<PcapRecord> for PacketRecord {
    type Error = crate::CrafterError;

    fn try_from(value: PcapRecord) -> Result<Self, Self::Error> {
        Self::try_from_pcap_record(value)
    }
}

impl From<PcapPacket> for PacketRecord {
    fn from(value: PcapPacket) -> Self {
        Self::from_pcap_packet(value)
    }
}

/// Metadata attached to a packet record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMetadata {
    origin: PacketOrigin,
    backend: BackendKind,
    interface: Option<String>,
    file: Option<PathBuf>,
    timestamp: Option<PcapTimestamp>,
    original_len: Option<u32>,
    captured_len: Option<u32>,
    captured_bytes: Option<Vec<u8>>,
    emitted_len: Option<u32>,
    link_type: Option<LinkType>,
    pcap_link_type: Option<PcapLinkType>,
    medium: Option<MediumMetadata>,
    transforms: Vec<TransformTrace>,
}

impl PacketMetadata {
    /// Create empty metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Packet origin.
    pub const fn origin(&self) -> PacketOrigin {
        self.origin
    }

    /// Backend kind that produced or will consume this record.
    pub const fn backend(&self) -> &BackendKind {
        &self.backend
    }

    /// Interface name when the record is tied to one.
    pub fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// File path when the record is tied to one.
    pub fn file(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    /// Capture timestamp when available.
    pub const fn timestamp(&self) -> Option<PcapTimestamp> {
        self.timestamp
    }

    /// Original on-wire length when available.
    pub const fn original_len(&self) -> Option<u32> {
        self.original_len
    }

    /// Captured length when available.
    pub const fn captured_len(&self) -> Option<u32> {
        self.captured_len
    }

    /// Captured bytes exactly as the backend supplied them.
    pub fn captured_bytes(&self) -> Option<&[u8]> {
        self.captured_bytes.as_deref()
    }

    /// Consume the metadata and return captured bytes.
    pub fn into_captured_bytes(self) -> Option<Vec<u8>> {
        self.captured_bytes
    }

    /// Emitted length when a writer or transform recorded it.
    pub const fn emitted_len(&self) -> Option<u32> {
        self.emitted_len
    }

    /// Core link-layer decode type when known.
    pub const fn link_type(&self) -> Option<LinkType> {
        self.link_type
    }

    /// Pcap data-link type when known.
    pub const fn pcap_link_type(&self) -> Option<PcapLinkType> {
        self.pcap_link_type
    }

    /// Medium-specific annotations.
    pub const fn medium(&self) -> Option<&MediumMetadata> {
        self.medium.as_ref()
    }

    /// Ordered transform history.
    pub fn transforms(&self) -> &[TransformTrace] {
        &self.transforms
    }

    /// Set packet origin.
    pub const fn with_origin(mut self, origin: PacketOrigin) -> Self {
        self.origin = origin;
        self
    }

    /// Set backend kind.
    pub fn with_backend(mut self, backend: BackendKind) -> Self {
        self.backend = backend;
        self
    }

    /// Set interface name.
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
    }

    /// Clear interface metadata.
    pub fn clear_interface(mut self) -> Self {
        self.interface = None;
        self
    }

    /// Set file path.
    pub fn with_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.file = Some(file.into());
        self
    }

    /// Clear file metadata.
    pub fn clear_file(mut self) -> Self {
        self.file = None;
        self
    }

    /// Set pcap-style timestamp, lengths, and link type metadata.
    pub const fn with_pcap_metadata(
        mut self,
        timestamp: PcapTimestamp,
        original_len: u32,
        captured_len: u32,
        pcap_link_type: PcapLinkType,
    ) -> Self {
        self.timestamp = Some(timestamp);
        self.original_len = Some(original_len);
        self.captured_len = Some(captured_len);
        self.pcap_link_type = Some(pcap_link_type);
        self.link_type = Some(pcap_link_type.link_type());
        self
    }

    /// Set capture timestamp.
    pub const fn with_timestamp(mut self, timestamp: PcapTimestamp) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Clear capture timestamp.
    pub const fn clear_timestamp(mut self) -> Self {
        self.timestamp = None;
        self
    }

    /// Set original on-wire length metadata.
    pub const fn with_original_len(mut self, original_len: u32) -> Self {
        self.original_len = Some(original_len);
        self
    }

    /// Set captured length metadata.
    pub const fn with_captured_len(mut self, captured_len: u32) -> Self {
        self.captured_len = Some(captured_len);
        self
    }

    /// Store captured bytes and update captured length metadata.
    pub fn with_captured_bytes(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        self.captured_len = Some(bytes.len() as u32);
        self.captured_bytes = Some(bytes);
        self
    }

    /// Clear captured bytes without changing length metadata.
    pub fn clear_captured_bytes(mut self) -> Self {
        self.captured_bytes = None;
        self
    }

    /// Set emitted length metadata.
    pub const fn with_emitted_len(mut self, emitted_len: u32) -> Self {
        self.emitted_len = Some(emitted_len);
        self
    }

    /// Set core link-type metadata.
    pub const fn with_link_type(mut self, link_type: LinkType) -> Self {
        self.link_type = Some(link_type);
        self
    }

    /// Set pcap link-type metadata and its best-effort core link type.
    pub const fn with_pcap_link_type(mut self, pcap_link_type: PcapLinkType) -> Self {
        self.pcap_link_type = Some(pcap_link_type);
        self.link_type = Some(pcap_link_type.link_type());
        self
    }

    /// Set medium-specific metadata.
    pub fn with_medium(mut self, medium: MediumMetadata) -> Self {
        self.medium = Some(medium);
        self
    }

    /// Clear medium-specific metadata.
    pub fn clear_medium(mut self) -> Self {
        self.medium = None;
        self
    }

    /// Append a transform trace and return the metadata for builder chaining.
    pub fn with_transform_trace(mut self, trace: TransformTrace) -> Self {
        self.transforms.push(trace);
        self
    }

    /// Append a transform trace in place.
    pub fn push_transform_trace(&mut self, trace: TransformTrace) -> &mut Self {
        self.transforms.push(trace);
        self
    }
}

impl Default for PacketMetadata {
    fn default() -> Self {
        Self {
            origin: PacketOrigin::Unknown,
            backend: BackendKind::Unknown,
            interface: None,
            file: None,
            timestamp: None,
            original_len: None,
            captured_len: None,
            captured_bytes: None,
            emitted_len: None,
            link_type: None,
            pcap_link_type: None,
            medium: None,
            transforms: Vec::new(),
        }
    }
}

/// How a packet record entered the wire pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PacketOrigin {
    /// Origin has not been recorded.
    #[default]
    Unknown,
    /// Created locally by caller code.
    Generated,
    /// Captured from a file, interface, or provider endpoint.
    Captured,
    /// Produced by a transform from one or more input records.
    Transformed,
    /// Replayed from an existing packet record.
    Replayed,
}

/// Backend family associated with a packet record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum BackendKind {
    /// Backend has not been recorded.
    #[default]
    Unknown,
    /// Classic pcap file backend.
    PcapFile,
    /// Live pcap interface backend.
    PcapInterface,
    /// Raw socket send or receive backend.
    RawSocket,
    /// Provider-backed endpoint backend.
    Endpoint,
    /// In-memory test or synthetic backend.
    Memory,
    /// Caller-defined backend.
    Other(String),
}

/// Medium-specific annotations attached to a packet record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MediumMetadata {
    /// IEEE 802.11 / Wi-Fi annotations.
    Wifi(WifiMetadata),
    /// Bluetooth or BLE annotations.
    Bluetooth(BluetoothMetadata),
    /// Generic radio capture annotations.
    Radio(RadioMetadata),
    /// Caller-defined medium annotation.
    Other(String),
}

/// Initial Wi-Fi annotations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct WifiMetadata {
    channel: Option<u16>,
    frequency_mhz: Option<u32>,
    signal_dbm: Option<i16>,
    protected: Option<bool>,
}

impl WifiMetadata {
    /// Create empty Wi-Fi metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Channel number when known.
    pub const fn channel(&self) -> Option<u16> {
        self.channel
    }

    /// Center frequency in MHz when known.
    pub const fn frequency_mhz(&self) -> Option<u32> {
        self.frequency_mhz
    }

    /// Received signal strength in dBm when known.
    pub const fn signal_dbm(&self) -> Option<i16> {
        self.signal_dbm
    }

    /// Whether the frame was marked protected when known.
    pub const fn protected(&self) -> Option<bool> {
        self.protected
    }

    /// Set channel number.
    pub const fn with_channel(mut self, channel: u16) -> Self {
        self.channel = Some(channel);
        self
    }

    /// Set center frequency in MHz.
    pub const fn with_frequency_mhz(mut self, frequency_mhz: u32) -> Self {
        self.frequency_mhz = Some(frequency_mhz);
        self
    }

    /// Set received signal strength in dBm.
    pub const fn with_signal_dbm(mut self, signal_dbm: i16) -> Self {
        self.signal_dbm = Some(signal_dbm);
        self
    }

    /// Set protected-frame marker.
    pub const fn with_protected(mut self, protected: bool) -> Self {
        self.protected = Some(protected);
        self
    }
}

/// Initial Bluetooth annotations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct BluetoothMetadata {
    address: Option<String>,
    channel: Option<u16>,
    signal_dbm: Option<i16>,
    protocol: Option<String>,
}

impl BluetoothMetadata {
    /// Create empty Bluetooth metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bluetooth address when known.
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    /// Channel when known.
    pub const fn channel(&self) -> Option<u16> {
        self.channel
    }

    /// Received signal strength in dBm when known.
    pub const fn signal_dbm(&self) -> Option<i16> {
        self.signal_dbm
    }

    /// Protocol label when known.
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    /// Set Bluetooth address.
    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.address = Some(address.into());
        self
    }

    /// Set channel.
    pub const fn with_channel(mut self, channel: u16) -> Self {
        self.channel = Some(channel);
        self
    }

    /// Set received signal strength in dBm.
    pub const fn with_signal_dbm(mut self, signal_dbm: i16) -> Self {
        self.signal_dbm = Some(signal_dbm);
        self
    }

    /// Set protocol label.
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }
}

/// Initial generic radio annotations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct RadioMetadata {
    frequency_hz: Option<u64>,
    bandwidth_hz: Option<u64>,
    signal_dbm: Option<i16>,
    noise_dbm: Option<i16>,
    modulation: Option<String>,
}

impl RadioMetadata {
    /// Create empty radio metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Center frequency in Hz when known.
    pub const fn frequency_hz(&self) -> Option<u64> {
        self.frequency_hz
    }

    /// Bandwidth in Hz when known.
    pub const fn bandwidth_hz(&self) -> Option<u64> {
        self.bandwidth_hz
    }

    /// Received signal strength in dBm when known.
    pub const fn signal_dbm(&self) -> Option<i16> {
        self.signal_dbm
    }

    /// Noise level in dBm when known.
    pub const fn noise_dbm(&self) -> Option<i16> {
        self.noise_dbm
    }

    /// Modulation label when known.
    pub fn modulation(&self) -> Option<&str> {
        self.modulation.as_deref()
    }

    /// Set center frequency in Hz.
    pub const fn with_frequency_hz(mut self, frequency_hz: u64) -> Self {
        self.frequency_hz = Some(frequency_hz);
        self
    }

    /// Set bandwidth in Hz.
    pub const fn with_bandwidth_hz(mut self, bandwidth_hz: u64) -> Self {
        self.bandwidth_hz = Some(bandwidth_hz);
        self
    }

    /// Set received signal strength in dBm.
    pub const fn with_signal_dbm(mut self, signal_dbm: i16) -> Self {
        self.signal_dbm = Some(signal_dbm);
        self
    }

    /// Set noise level in dBm.
    pub const fn with_noise_dbm(mut self, noise_dbm: i16) -> Self {
        self.noise_dbm = Some(noise_dbm);
        self
    }

    /// Set modulation label.
    pub fn with_modulation(mut self, modulation: impl Into<String>) -> Self {
        self.modulation = Some(modulation.into());
        self
    }
}

/// One transform step recorded in packet metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransformTrace {
    name: String,
    note: Option<String>,
    input_len: Option<u32>,
    output_len: Option<u32>,
}

impl TransformTrace {
    /// Create a transform trace with a stable transform name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            note: None,
            input_len: None,
            output_len: None,
        }
    }

    /// Transform name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Optional transform diagnostic note.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// Input length observed by the transform.
    pub const fn input_len(&self) -> Option<u32> {
        self.input_len
    }

    /// Output length emitted by the transform.
    pub const fn output_len(&self) -> Option<u32> {
        self.output_len
    }

    /// Set transform diagnostic note.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Set input length observed by the transform.
    pub const fn with_input_len(mut self, input_len: u32) -> Self {
        self.input_len = Some(input_len);
        self
    }

    /// Set output length emitted by the transform.
    pub const fn with_output_len(mut self, output_len: u32) -> Self {
        self.output_len = Some(output_len);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Raw;

    #[test]
    fn constructs_packet_records() {
        let record = PacketRecord::new(Raw::from("payload"))
            .with_origin(PacketOrigin::Generated)
            .with_backend(BackendKind::Memory)
            .with_interface("lo");

        assert_eq!(record.packet().summary(), "Raw(len=7)");
        assert_eq!(record.metadata().origin(), PacketOrigin::Generated);
        assert_eq!(record.metadata().backend(), &BackendKind::Memory);
        assert_eq!(record.metadata().interface(), Some("lo"));

        let (packet, metadata) = record.into_parts();
        assert_eq!(packet.summary(), "Raw(len=7)");
        assert_eq!(metadata.origin(), PacketOrigin::Generated);
    }

    #[test]
    fn preserves_pcap_metadata() {
        let timestamp = PcapTimestamp::nanos(1_700_000_000, 123).unwrap();
        let captured = vec![0xde, 0xad, 0xbe, 0xef];
        let record = PacketRecord::new(Raw::from(captured.as_slice()))
            .with_origin(PacketOrigin::Captured)
            .with_backend(BackendKind::PcapFile)
            .with_file("fixtures/sample.pcap")
            .with_pcap_metadata(timestamp, 64, captured.len() as u32, PcapLinkType::Ethernet)
            .with_captured_bytes(captured.clone());

        let metadata = record.metadata();
        assert_eq!(metadata.origin(), PacketOrigin::Captured);
        assert_eq!(metadata.backend(), &BackendKind::PcapFile);
        assert_eq!(metadata.file(), Some(Path::new("fixtures/sample.pcap")));
        assert_eq!(metadata.timestamp(), Some(timestamp));
        assert_eq!(metadata.original_len(), Some(64));
        assert_eq!(metadata.captured_len(), Some(4));
        assert_eq!(metadata.captured_bytes(), Some(captured.as_slice()));
        assert_eq!(metadata.link_type(), Some(LinkType::Ethernet));
        assert_eq!(metadata.pcap_link_type(), Some(PcapLinkType::Ethernet));
    }

    #[test]
    fn pcap_packet_metadata_from_record_preserves_timestamp_and_link_types() {
        let timestamp = PcapTimestamp::nanos(1_700_000_001, 987_654_321).unwrap();
        let captured = vec![0xde, 0xad, 0xbe, 0xef];
        let pcap_link_type = PcapLinkType::Unknown(65_000);
        let record = PcapRecord::new(timestamp, 64, captured.clone(), pcap_link_type).unwrap();

        let record = PacketRecord::try_from_pcap_record(record).unwrap();

        assert_eq!(record.packet().summary(), "Raw(len=4)");
        let metadata = record.metadata();
        assert_eq!(metadata.origin(), PacketOrigin::Captured);
        assert_eq!(metadata.backend(), &BackendKind::Unknown);
        assert_eq!(metadata.timestamp(), Some(timestamp));
        assert_eq!(metadata.original_len(), Some(64));
        assert_eq!(metadata.captured_len(), Some(captured.len() as u32));
        assert_eq!(metadata.captured_bytes(), Some(captured.as_slice()));
        assert_eq!(metadata.pcap_link_type(), Some(pcap_link_type));
        assert_eq!(metadata.link_type(), Some(LinkType::Raw));
    }

    #[test]
    fn pcap_packet_metadata_from_packet_preserves_timestamp_and_link_types() {
        let timestamp = PcapTimestamp::micros(1_700_000_002, 123_456).unwrap();
        let captured = vec![0x08, 0x01, 0x02, 0x03, 0x04];
        let packet = Packet::decode_raw(&captured).unwrap();
        let pcap_packet = PcapPacket::new(
            timestamp,
            128,
            captured.clone(),
            PcapLinkType::Ieee80211,
            packet,
        );

        let record = PacketRecord::from_pcap_packet(pcap_packet);

        assert_eq!(record.packet().summary(), "Raw(len=5)");
        let metadata = record.metadata();
        assert_eq!(metadata.origin(), PacketOrigin::Captured);
        assert_eq!(metadata.backend(), &BackendKind::Unknown);
        assert_eq!(metadata.timestamp(), Some(timestamp));
        assert_eq!(metadata.original_len(), Some(128));
        assert_eq!(metadata.captured_len(), Some(captured.len() as u32));
        assert_eq!(metadata.captured_bytes(), Some(captured.as_slice()));
        assert_eq!(metadata.pcap_link_type(), Some(PcapLinkType::Ieee80211));
        assert_eq!(metadata.link_type(), Some(LinkType::Ieee80211));
    }

    #[test]
    fn appends_transform_traces() {
        let mut record = PacketRecord::new(Raw::from("payload")).with_transform_trace(
            TransformTrace::new("dedupe")
                .with_note("accepted")
                .with_input_len(7)
                .with_output_len(7),
        );
        record
            .metadata_mut()
            .push_transform_trace(TransformTrace::new("rewrite").with_output_len(9));

        let transforms = record.metadata().transforms();
        assert_eq!(transforms.len(), 2);
        assert_eq!(transforms[0].name(), "dedupe");
        assert_eq!(transforms[0].note(), Some("accepted"));
        assert_eq!(transforms[0].input_len(), Some(7));
        assert_eq!(transforms[0].output_len(), Some(7));
        assert_eq!(transforms[1].name(), "rewrite");
        assert_eq!(transforms[1].output_len(), Some(9));
    }
}
