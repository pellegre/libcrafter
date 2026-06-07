//! Packet record and metadata types.
//!
//! A wire pipeline never yields bare bytes. It yields [`PacketRecord`] values:
//! typed packets plus metadata gathered from sources, transforms, and writers.
//! Keeping metadata beside the packet lets later transforms know which backend,
//! interface, file, link type, or radio medium produced a record without
//! changing the packet abstraction itself.

use std::path::{Path, PathBuf};

use super::ip::{IpDefragMetadata, IpFragmentMetadata};
use super::wpa::WpaMetadata;
use crate::pcap::{PcapLinkType, PcapPacket, PcapRecord, PcapTimestamp};
use crate::{
    Dot11ControlSubtype, Dot11DataSubtype, Dot11FrameType, Dot11ManagementSubtype, IntoPacket,
    LinkType, MacAddr, Packet,
};

/// A packet plus inspectable metadata from capture, transforms, and writers.
///
/// `PacketRecord` is the common item type for [`crate::wire::PacketSource`],
/// [`crate::wire::Sniffer`], [`crate::wire::PacketTransform`],
/// [`crate::wire::Transmitter`], and [`crate::wire::PacketWriter`]. The packet
/// remains a normal [`Packet`]; metadata is additive context for routing,
/// filtering, diagnostics, and future transforms such as WPA decryption.
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

    /// Set Wi-Fi medium metadata.
    pub fn with_wifi_metadata(mut self, wifi: WifiMetadata) -> Self {
        self.metadata = self.metadata.with_wifi_metadata(wifi);
        self
    }

    /// Append IP fragmentation metadata.
    pub fn with_ip_fragment_metadata(mut self, metadata: IpFragmentMetadata) -> Self {
        self.metadata = self.metadata.with_ip_fragment_metadata(metadata);
        self
    }

    /// Append IP defragmentation metadata.
    pub fn with_ip_defrag_metadata(mut self, metadata: IpDefragMetadata) -> Self {
        self.metadata = self.metadata.with_ip_defrag_metadata(metadata);
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
///
/// Metadata is intentionally inspectable and extensible. Backends can attach
/// pcap timestamps and link types, live interfaces can attach interface names,
/// transforms can append trace entries, and medium transforms can add Wi-Fi,
/// Bluetooth, or generic radio annotations.
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
    ip_fragments: Vec<IpFragmentMetadata>,
    ip_defrags: Vec<IpDefragMetadata>,
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

    /// IP fragmentation metadata attached by transmit-side transforms.
    pub fn ip_fragment_metadata(&self) -> &[IpFragmentMetadata] {
        &self.ip_fragments
    }

    /// IP defragmentation metadata attached by receive-side transforms.
    pub fn ip_defrag_metadata(&self) -> &[IpDefragMetadata] {
        &self.ip_defrags
    }

    /// Wi-Fi medium metadata when this record carries Wi-Fi annotations.
    pub const fn wifi(&self) -> Option<&WifiMetadata> {
        match self.medium.as_ref() {
            Some(MediumMetadata::Wifi(wifi)) => Some(wifi),
            _ => None,
        }
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

    /// Set Wi-Fi medium metadata.
    pub fn with_wifi_metadata(self, wifi: WifiMetadata) -> Self {
        self.with_medium(MediumMetadata::Wifi(wifi))
    }

    /// Append IP fragmentation metadata.
    pub fn with_ip_fragment_metadata(mut self, metadata: IpFragmentMetadata) -> Self {
        self.ip_fragments.push(metadata);
        self
    }

    /// Append IP defragmentation metadata.
    pub fn with_ip_defrag_metadata(mut self, metadata: IpDefragMetadata) -> Self {
        self.ip_defrags.push(metadata);
        self
    }

    /// Clear medium-specific metadata.
    pub fn clear_medium(mut self) -> Self {
        self.medium = None;
        self
    }

    /// Append IP fragmentation metadata in place.
    pub fn push_ip_fragment_metadata(&mut self, metadata: IpFragmentMetadata) -> &mut Self {
        self.ip_fragments.push(metadata);
        self
    }

    /// Append IP defragmentation metadata in place.
    pub fn push_ip_defrag_metadata(&mut self, metadata: IpDefragMetadata) -> &mut Self {
        self.ip_defrags.push(metadata);
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
            ip_fragments: Vec::new(),
            ip_defrags: Vec::new(),
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

/// Protection marker extracted from an IEEE 802.11 frame when known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WifiProtectionStatus {
    /// The frame is not marked as protected.
    Unprotected,
    /// The frame is marked as protected.
    Protected,
}

impl WifiProtectionStatus {
    /// Return true when the frame is marked as protected.
    pub const fn is_protected(self) -> bool {
        matches!(self, Self::Protected)
    }
}

impl From<bool> for WifiProtectionStatus {
    fn from(protected: bool) -> Self {
        if protected {
            Self::Protected
        } else {
            Self::Unprotected
        }
    }
}

/// Decryption status for future Wi-Fi transforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WifiDecryptState {
    /// The frame did not require decryption.
    NotRequired,
    /// The frame may require decryption, but no transform attempted it yet.
    NotAttempted,
    /// A transform is waiting for key material before it can decrypt.
    KeyMaterialMissing,
    /// A transform successfully decrypted the frame payload.
    Decrypted,
    /// A transform attempted decryption and could not decrypt the payload.
    Failed,
}

/// Initial Wi-Fi annotations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct WifiMetadata {
    ssid: Option<Vec<u8>>,
    bssid: Option<MacAddr>,
    transmitter: Option<MacAddr>,
    receiver: Option<MacAddr>,
    channel: Option<u16>,
    frequency_mhz: Option<u32>,
    signal_dbm: Option<i16>,
    dot11_frame_type: Option<Dot11FrameType>,
    dot11_management_subtype: Option<Dot11ManagementSubtype>,
    dot11_control_subtype: Option<Dot11ControlSubtype>,
    dot11_data_subtype: Option<Dot11DataSubtype>,
    protection: Option<WifiProtectionStatus>,
    key_id: Option<u8>,
    decrypt_state: Option<WifiDecryptState>,
    wpa_metadata: Option<WpaMetadata>,
}

impl WifiMetadata {
    /// Create empty Wi-Fi metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// SSID bytes when known.
    ///
    /// SSIDs are bytes on the wire and are not guaranteed to be UTF-8.
    pub fn ssid(&self) -> Option<&[u8]> {
        self.ssid.as_deref()
    }

    /// SSID as UTF-8 when the captured bytes are valid text.
    pub fn ssid_str(&self) -> Option<&str> {
        self.ssid
            .as_deref()
            .and_then(|ssid| core::str::from_utf8(ssid).ok())
    }

    /// BSSID when known.
    pub const fn bssid(&self) -> Option<MacAddr> {
        self.bssid
    }

    /// Transmitter address when known.
    pub const fn transmitter(&self) -> Option<MacAddr> {
        self.transmitter
    }

    /// Receiver address when known.
    pub const fn receiver(&self) -> Option<MacAddr> {
        self.receiver
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

    /// RSSI in dBm when known.
    pub const fn rssi_dbm(&self) -> Option<i16> {
        self.signal_dbm
    }

    /// IEEE 802.11 frame type when known.
    pub const fn dot11_frame_type(&self) -> Option<Dot11FrameType> {
        self.dot11_frame_type
    }

    /// IEEE 802.11 management subtype when known.
    pub const fn dot11_management_subtype(&self) -> Option<Dot11ManagementSubtype> {
        self.dot11_management_subtype
    }

    /// IEEE 802.11 control subtype when known.
    pub const fn dot11_control_subtype(&self) -> Option<Dot11ControlSubtype> {
        self.dot11_control_subtype
    }

    /// IEEE 802.11 data subtype when known.
    pub const fn dot11_data_subtype(&self) -> Option<Dot11DataSubtype> {
        self.dot11_data_subtype
    }

    /// Protected-frame status when known.
    pub const fn protection_status(&self) -> Option<WifiProtectionStatus> {
        self.protection
    }

    /// Whether the frame was marked protected when known.
    pub const fn protected(&self) -> Option<bool> {
        match self.protection {
            Some(status) => Some(status.is_protected()),
            None => None,
        }
    }

    /// Key identifier when known.
    pub const fn key_id(&self) -> Option<u8> {
        self.key_id
    }

    /// Decrypt state recorded by a future Wi-Fi transform when known.
    pub const fn decrypt_state(&self) -> Option<WifiDecryptState> {
        self.decrypt_state
    }

    /// WPA decryption metadata when a WPA transform attached details.
    pub const fn wpa_metadata(&self) -> Option<&WpaMetadata> {
        self.wpa_metadata.as_ref()
    }

    /// Set SSID bytes.
    pub fn with_ssid(mut self, ssid: impl Into<Vec<u8>>) -> Self {
        self.ssid = Some(ssid.into());
        self
    }

    /// Set SSID from text.
    pub fn with_ssid_str(self, ssid: impl Into<String>) -> Self {
        self.with_ssid(ssid.into().into_bytes())
    }

    /// Set BSSID.
    pub const fn with_bssid(mut self, bssid: MacAddr) -> Self {
        self.bssid = Some(bssid);
        self
    }

    /// Set transmitter address.
    pub const fn with_transmitter(mut self, transmitter: MacAddr) -> Self {
        self.transmitter = Some(transmitter);
        self
    }

    /// Set receiver address.
    pub const fn with_receiver(mut self, receiver: MacAddr) -> Self {
        self.receiver = Some(receiver);
        self
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

    /// Set RSSI in dBm.
    pub const fn with_rssi_dbm(self, rssi_dbm: i16) -> Self {
        self.with_signal_dbm(rssi_dbm)
    }

    /// Set IEEE 802.11 frame type.
    pub const fn with_dot11_frame_type(mut self, frame_type: Dot11FrameType) -> Self {
        self.dot11_frame_type = Some(frame_type);
        self
    }

    /// Set IEEE 802.11 management subtype.
    pub const fn with_dot11_management_subtype(mut self, subtype: Dot11ManagementSubtype) -> Self {
        self.dot11_management_subtype = Some(subtype);
        self
    }

    /// Set IEEE 802.11 control subtype.
    pub const fn with_dot11_control_subtype(mut self, subtype: Dot11ControlSubtype) -> Self {
        self.dot11_control_subtype = Some(subtype);
        self
    }

    /// Set IEEE 802.11 data subtype.
    pub const fn with_dot11_data_subtype(mut self, subtype: Dot11DataSubtype) -> Self {
        self.dot11_data_subtype = Some(subtype);
        self
    }

    /// Set protected-frame status.
    pub const fn with_protection_status(mut self, protection: WifiProtectionStatus) -> Self {
        self.protection = Some(protection);
        self
    }

    /// Set protected-frame marker.
    pub const fn with_protected(mut self, protected: bool) -> Self {
        self.protection = Some(if protected {
            WifiProtectionStatus::Protected
        } else {
            WifiProtectionStatus::Unprotected
        });
        self
    }

    /// Set key identifier.
    pub const fn with_key_id(mut self, key_id: u8) -> Self {
        self.key_id = Some(key_id);
        self
    }

    /// Set decrypt state.
    pub const fn with_decrypt_state(mut self, decrypt_state: WifiDecryptState) -> Self {
        self.decrypt_state = Some(decrypt_state);
        self
    }

    /// Attach WPA decryption metadata.
    pub fn with_wpa_metadata(mut self, wpa_metadata: WpaMetadata) -> Self {
        self.wpa_metadata = Some(wpa_metadata);
        self
    }

    /// Clear attached WPA decryption metadata.
    pub fn clear_wpa_metadata(mut self) -> Self {
        self.wpa_metadata = None;
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
    use crate::wire::ip::{
        IpDefragEvictionReason, IpDefragMetadata, IpDefragOverlapStatus, IpFragmentFamily,
        IpFragmentMetadata, IpFragmentRange, IpFragmentReason,
    };
    use crate::wire::{
        WpaAkm, WpaCipher, WpaCredentialStatus, WpaDecryptReason, WpaHandshakeStatus, WpaKeyKind,
    };
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
    fn wifi_metadata_attaches_to_packet_record() {
        let bssid = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]);
        let transmitter = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x02]);
        let receiver = MacAddr::BROADCAST;
        let wifi = WifiMetadata::new()
            .with_ssid_str("labnet")
            .with_bssid(bssid)
            .with_transmitter(transmitter)
            .with_receiver(receiver)
            .with_channel(6)
            .with_frequency_mhz(2437)
            .with_rssi_dbm(-42)
            .with_protection_status(WifiProtectionStatus::Protected)
            .with_key_id(2)
            .with_decrypt_state(WifiDecryptState::KeyMaterialMissing);

        let record = PacketRecord::new(Raw::from("dot11")).with_wifi_metadata(wifi.clone());
        let metadata = record.metadata();
        assert_eq!(metadata.wifi(), Some(&wifi));
        assert!(matches!(metadata.medium(), Some(MediumMetadata::Wifi(_))));

        let attached = metadata.wifi().unwrap();
        assert_eq!(attached.ssid(), Some("labnet".as_bytes()));
        assert_eq!(attached.ssid_str(), Some("labnet"));
        assert_eq!(attached.bssid(), Some(bssid));
        assert_eq!(attached.transmitter(), Some(transmitter));
        assert_eq!(attached.receiver(), Some(receiver));
        assert_eq!(attached.channel(), Some(6));
        assert_eq!(attached.frequency_mhz(), Some(2437));
        assert_eq!(attached.signal_dbm(), Some(-42));
        assert_eq!(attached.rssi_dbm(), Some(-42));
        assert_eq!(
            attached.protection_status(),
            Some(WifiProtectionStatus::Protected)
        );
        assert_eq!(attached.protected(), Some(true));
        assert_eq!(attached.key_id(), Some(2));
        assert_eq!(
            attached.decrypt_state(),
            Some(WifiDecryptState::KeyMaterialMissing)
        );
    }

    #[test]
    fn wifi_metadata_preserves_raw_ssid_bytes_and_legacy_protected_marker() {
        let wifi = WifiMetadata::new()
            .with_ssid(vec![0xff, 0x00, b'a'])
            .with_protected(false)
            .with_decrypt_state(WifiDecryptState::NotRequired);
        let metadata = PacketMetadata::new().with_wifi_metadata(wifi.clone());

        let attached = metadata.wifi().unwrap();
        assert_eq!(attached.ssid(), Some(&[0xff, 0x00, b'a'][..]));
        assert_eq!(attached.ssid_str(), None);
        assert_eq!(
            attached.protection_status(),
            Some(WifiProtectionStatus::Unprotected)
        );
        assert_eq!(attached.protected(), Some(false));
        assert_eq!(
            attached.decrypt_state(),
            Some(WifiDecryptState::NotRequired)
        );
        assert_eq!(metadata.medium(), Some(&MediumMetadata::Wifi(wifi)));
    }

    #[test]
    fn wifi_metadata_carries_wpa_metadata() {
        let bssid = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]);
        let station = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x44]);
        let wpa = WpaMetadata::new()
            .with_bssid(bssid)
            .with_station(station)
            .with_cipher(WpaCipher::Ccmp128)
            .with_akm(WpaAkm::Psk)
            .with_key_kind(WpaKeyKind::Pairwise)
            .with_key_id(1)
            .with_packet_number(0x0000_0102_0304)
            .with_handshake_status(WpaHandshakeStatus::MicVerified)
            .with_decrypt_reason(WpaDecryptReason::Decrypted)
            .with_credential_status(WpaCredentialStatus::Matched);
        let wifi = WifiMetadata::new()
            .with_ssid_str("labnet")
            .with_bssid(bssid)
            .with_wpa_metadata(wpa.clone());

        let record = PacketRecord::new(Raw::from("dot11")).with_wifi_metadata(wifi.clone());
        let attached_wifi = record.metadata().wifi().unwrap();
        let attached_wpa = attached_wifi.wpa_metadata().unwrap();

        assert_eq!(attached_wifi, &wifi);
        assert_eq!(attached_wpa, &wpa);
        assert_eq!(attached_wpa.clone(), wpa);
        assert_eq!(attached_wpa.bssid(), Some(bssid));
        assert_eq!(attached_wpa.station(), Some(station));
        assert_eq!(attached_wpa.cipher(), Some(WpaCipher::Ccmp128));
        assert_eq!(attached_wpa.akm(), Some(WpaAkm::Psk));
        assert_eq!(attached_wpa.key_kind(), Some(WpaKeyKind::Pairwise));
        assert_eq!(attached_wpa.key_id(), Some(1));
        assert_eq!(attached_wpa.packet_number(), Some(0x0000_0102_0304));
        assert_eq!(
            attached_wpa.handshake_status(),
            Some(WpaHandshakeStatus::MicVerified)
        );
        assert_eq!(
            attached_wpa.decrypt_reason(),
            Some(WpaDecryptReason::Decrypted)
        );
        assert_eq!(
            attached_wpa.credential_status(),
            Some(WpaCredentialStatus::Matched)
        );
        assert_eq!(attached_wpa.credentials_matched(), Some(true));
    }

    #[test]
    fn ip_metadata_does_not_replace_wifi_or_wpa_metadata() {
        let bssid = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]);
        let wpa = WpaMetadata::new()
            .with_bssid(bssid)
            .with_cipher(WpaCipher::Ccmp128);
        let wifi = WifiMetadata::new()
            .with_ssid_str("labnet")
            .with_bssid(bssid)
            .with_wpa_metadata(wpa.clone());
        let fragment = IpFragmentMetadata::new(
            IpFragmentFamily::Ipv4,
            576,
            0x1234,
            2,
            true,
            3,
            1,
            IpFragmentRange::new(16, 32),
        )
        .with_original_len(96)
        .with_reason(IpFragmentReason::Fragmented);
        let defrag = IpDefragMetadata::new(IpFragmentFamily::Ipv4, 0x1234)
            .with_datagram_key("192.0.2.1>198.51.100.1 proto=17 id=0x1234")
            .with_fragment_count(3)
            .with_duplicate_count(1)
            .with_overlap_status(IpDefragOverlapStatus::NonConflicting)
            .with_byte_ranges([IpFragmentRange::new(0, 16), IpFragmentRange::new(16, 32)])
            .with_total_len(96)
            .with_eviction_reason(IpDefragEvictionReason::Timeout);

        let record = PacketRecord::new(Raw::from("dot11"))
            .with_wifi_metadata(wifi.clone())
            .with_ip_fragment_metadata(fragment.clone())
            .with_ip_defrag_metadata(defrag.clone());

        let metadata = record.metadata();
        assert_eq!(metadata.wifi(), Some(&wifi));
        assert_eq!(metadata.wifi().unwrap().wpa_metadata(), Some(&wpa));
        assert_eq!(metadata.ip_fragment_metadata(), &[fragment]);
        assert_eq!(metadata.ip_defrag_metadata(), &[defrag]);
        assert!(matches!(metadata.medium(), Some(MediumMetadata::Wifi(_))));
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
