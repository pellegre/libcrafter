//! Opt-in packet interface normalization and monitor framing adapters.

use super::backend::pcap::PcapRecord;
use super::{
    PacketMetadata, PacketOrigin, PacketRecord, PacketSource, PacketWriter, Result, WireError,
    WriteReport,
};
use crate::{CrafterError, Dot11, Dot11FrameControl, LinkType, Packet, Radiotap};

/// Packet representation presented to an application, independent of transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketFormat {
    /// Ethernet frames, including externally associated managed Wi-Fi.
    Ethernet,
    /// Bare IEEE 802.11 MAC frames.
    Dot11,
    /// A raw capture format, without normalization.
    Capture(LinkType),
}

/// Interface operation, independent of backend identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceMode {
    /// Ethernet network interface.
    Ethernet,
    /// Externally associated Wi-Fi network interface.
    ManagedWifi,
    /// Monitor interface presenting normalized MAC frames.
    MonitorWifi,
    /// Wi-Fi codec over radio samples.
    WifiIq,
    /// Unmodified capture records.
    RawCapture(LinkType),
}

impl InterfaceMode {
    /// Packet representation for this operating mode.
    pub const fn packet_format(self) -> PacketFormat {
        match self {
            Self::Ethernet | Self::ManagedWifi => PacketFormat::Ethernet,
            Self::MonitorWifi | Self::WifiIq => PacketFormat::Dot11,
            Self::RawCapture(link) => PacketFormat::Capture(link),
        }
    }
}

/// Application-facing format and opened I/O capabilities, independent of backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInterfaceDescriptor {
    /// Selected operating mode; absent when the backend does not identify it.
    /// Managed Wi-Fi is caller-declared, not proof of association.
    pub mode: Option<InterfaceMode>,
    /// Record representation. Unknown remains absent, rather than assumed Ethernet.
    pub packet_format: Option<PacketFormat>,
    pub receive: bool,
    pub transmit: bool,
    /// Whether directions share one RF chain, when known by the backend.
    pub half_duplex: Option<bool>,
}

/// Capture trailer evidence; absence of evidence never implies a valid FCS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureFcs {
    /// No trailer presence information was supplied.
    Unknown,
    /// Capture flags explicitly say the trailer is absent.
    Absent,
    /// Complete trailer, retained verbatim. Validity is independently checked.
    Present {
        /// Captured trailer in wire order.
        bytes: [u8; 4],
        /// CRC-32 comparison after removing capture-only padding.
        valid: bool,
    },
    /// The capture ended before the complete trailer was available.
    Truncated {
        /// Captured prefix of the trailer; empty if none arrived.
        bytes: Vec<u8>,
    },
}

/// Original framing, separate from normalized packet and capture provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiCaptureMetadata {
    /// Original framing at this normalization boundary.
    pub link_type: LinkType,
    /// Decoded capture wrapper including unknown fields and explicit values.
    pub radiotap: Option<Radiotap>,
    /// Removed MAC alignment padding, retained verbatim.
    pub padding: Vec<u8>,
    /// Trailer presence and computed integrity evidence.
    pub fcs: CaptureFcs,
    /// Driver-reported failure, independent of the computed checksum.
    pub driver_failed_fcs: Option<bool>,
    /// Hardware decryption indication, when an upstream backend supplies it.
    /// Standard radiotap flags alone do not establish this fact.
    pub hardware_decrypted: Option<bool>,
}

/// Decode a capture at the backend boundary, before padding or FCS can be
/// mistaken for protocol payload. The raw pcap constructors remain unchanged.
pub fn normalized_wifi_pcap_record(record: PcapRecord) -> Result<PacketRecord> {
    let metadata = PacketMetadata::new()
        .with_origin(PacketOrigin::Captured)
        .with_pcap_metadata(
            record.timestamp(),
            record.original_len(),
            record.captured_len(),
            record.pcap_link_type(),
        )
        .with_captured_bytes(record.data().to_vec());
    normalize_bytes(record.data(), record.link_type(), metadata)
}

/// Normalize one unmodified capture record. Already normalized records are
/// returned unchanged, so repeated adapter application cannot strip payload.
pub fn normalize_wifi_record(record: PacketRecord) -> Result<PacketRecord> {
    if record.metadata().wifi_capture().is_some() {
        require_dot11(record.packet())?;
        return Ok(record);
    }
    let root = record.packet().get(0);
    let link = if root.is_some_and(|layer| layer.as_any().is::<Radiotap>()) {
        LinkType::Radiotap
    } else if root.is_some_and(|layer| layer.as_any().is::<Dot11>()) {
        LinkType::Ieee80211
    } else {
        return Err(incompatible_root());
    };
    let capture_link = record
        .metadata()
        .pcap_link_type()
        .map(|link| link.link_type())
        .or(record.metadata().link_type());
    let bytes = match record.metadata().captured_bytes() {
        Some(bytes) if capture_link == Some(link) => bytes.to_vec(),
        _ => record.packet().compile()?.as_bytes().to_vec(),
    };
    let (_, metadata) = record.into_parts();
    normalize_bytes(&bytes, link, metadata)
}

fn normalize_bytes(bytes: &[u8], link: LinkType, metadata: PacketMetadata) -> Result<PacketRecord> {
    let (radiotap, mut frame) = match link {
        LinkType::Ieee80211 => (None, bytes.to_vec()),
        LinkType::Radiotap => {
            if bytes.len() < 8 {
                return Err(
                    CrafterError::buffer_too_short("radiotap.header", 8, bytes.len()).into(),
                );
            }
            let len = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
            if len < 8 || len > bytes.len() {
                return Err(CrafterError::buffer_too_short(
                    "radiotap.header",
                    len.max(8),
                    bytes.len().min(len),
                )
                .into());
            }
            let header = Packet::decode_from_link(LinkType::Radiotap, &bytes[..len])?;
            (header.layer::<Radiotap>().cloned(), bytes[len..].to_vec())
        }
        _ => return Err(incompatible_root()),
    };
    let flags = radiotap.as_ref().and_then(Radiotap::flags_value);
    let driver_failed_fcs = flags.map(|flags| flags.failed_fcs());
    let mut fcs = match flags {
        Some(flags) if !flags.fcs_present() => CaptureFcs::Absent,
        _ => CaptureFcs::Unknown,
    };
    if flags.is_some_and(|flags| flags.fcs_present()) {
        let missing = metadata
            .original_len()
            .zip(metadata.captured_len())
            .map_or(0, |(original, captured)| {
                original.saturating_sub(captured) as usize
            });
        let trailer_len = 4usize.saturating_sub(missing);
        let minimum = Dot11::mac_header_len_for(Dot11FrameControl::decode(&frame)?);
        if frame.len() < minimum + trailer_len {
            return Err(CrafterError::buffer_too_short(
                "wifi.fcs",
                minimum + trailer_len,
                frame.len(),
            )
            .into());
        }
        let trailer = frame.split_off(frame.len() - trailer_len);
        fcs = if missing == 0 {
            CaptureFcs::Present {
                bytes: trailer.try_into().expect("four-byte trailer"),
                valid: false,
            }
        } else {
            CaptureFcs::Truncated { bytes: trailer }
        };
    }
    let mut padding = Vec::new();
    if flags.is_some_and(|flags| flags.bits() & 0x20 != 0) {
        let header_len = Dot11::mac_header_len_for(Dot11FrameControl::decode(&frame)?);
        let padded_len = (header_len + 3) & !3;
        if frame.len() < padded_len {
            return Err(
                CrafterError::buffer_too_short("wifi.padding", padded_len, frame.len()).into(),
            );
        }
        padding = frame.drain(header_len..padded_len).collect();
    }
    if let CaptureFcs::Present { bytes, valid } = &mut fcs {
        *valid = crc32(&frame) == u32::from_le_bytes(*bytes);
    }
    let packet = Packet::decode_from_link(LinkType::Ieee80211, &frame)?;
    let mut wifi = super::dot11_metadata::metadata_from_packet(&packet, metadata.wifi().cloned());
    if let Some(header) = &radiotap {
        wifi =
            super::dot11_metadata::metadata_from_packet(&Packet::from_layer(header.clone()), wifi);
    }
    let metadata = metadata
        .with_link_type(LinkType::Ieee80211)
        .with_wifi_capture(WifiCaptureMetadata {
            link_type: link,
            radiotap,
            padding,
            fcs,
            driver_failed_fcs,
            hardware_decrypted: None,
        });
    let metadata = match wifi {
        Some(wifi) => metadata.with_wifi_metadata(wifi),
        None => metadata,
    };
    Ok(PacketRecord::from_packet_metadata(packet, metadata))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn incompatible_root() -> WireError {
    CrafterError::invalid_field_value(
        "wifi.packet_root",
        "expected a bare Dot11 packet or supported Wi-Fi capture wrapper",
    )
    .into()
}

fn require_dot11(packet: &Packet) -> Result<()> {
    if packet
        .get(0)
        .is_some_and(|layer| layer.as_any().is::<Dot11>())
    {
        Ok(())
    } else {
        Err(incompatible_root())
    }
}

/// Normalize each Wi-Fi record yielded by an existing source.
pub struct NormalizedWifiSource<S> {
    inner: S,
}

impl<S> NormalizedWifiSource<S> {
    /// Wrap an existing packet source.
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }
    /// Recover the source and its lifecycle controls.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: PacketSource> PacketSource for NormalizedWifiSource<S> {
    fn next_record(&mut self) -> Result<Option<PacketRecord>> {
        self.inner
            .next_record()?
            .map(normalize_wifi_record)
            .transpose()
    }
}

/// Adapt bare Dot11 output to a monitor driver's packet representation.
pub struct MonitorWriter<W> {
    inner: W,
    framing: Option<Radiotap>,
}

impl<W> MonitorWriter<W> {
    /// A radiotap driver with a minimal wrapper and no invented radio settings.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            framing: Some(Radiotap::new()),
        }
    }
    /// A driver that accepts bare Dot11 frames.
    pub const fn bare(inner: W) -> Self {
        Self {
            inner,
            framing: None,
        }
    }
    /// Replace the driver wrapper, preserving all explicit field overrides.
    pub fn with_radiotap(mut self, framing: Radiotap) -> Self {
        self.framing = Some(framing);
        self
    }
    /// Recover the underlying writer and its lifecycle controls.
    pub fn into_inner(self) -> W {
        self.inner
    }
    /// Materialize the exact typed driver representation without submitting it.
    pub fn frame_record(&self, record: &PacketRecord) -> Result<PacketRecord> {
        require_dot11(record.packet())?;
        let packet = match &self.framing {
            Some(header) => Packet::from_layer(header.clone()).concat(record.packet().clone()),
            None => record.packet().clone(),
        };
        Ok(PacketRecord::from_packet_metadata(
            packet,
            record.metadata().clone(),
        ))
    }
}

impl<W: PacketWriter> PacketWriter for MonitorWriter<W> {
    fn write_record(&mut self, record: &PacketRecord) -> Result<WriteReport> {
        self.inner.write_record(&self.frame_record(record)?)
    }
}
