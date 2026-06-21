//! Pcap packet wire backend.
//!
//! This module owns the classic pcap codec, record metadata, file readers and
//! writers, libpcap filtering/capture glue, and the packet wire adapters that
//! expose those pieces through [`crate::wire::PacketSource`] and
//! [`crate::wire::PacketWriter`]. Application code should normally construct
//! these through [`crate::wire::PacketWire`] instead of naming backend types
//! directly.

#![forbid(unsafe_code)]

mod codec;
mod error;
mod libpcap;
mod types;

pub mod reader;
pub mod writer;

pub use error::{PcapError, Result};
pub(crate) use libpcap::{LibpcapCapture, LibpcapOfflineCapture};
pub use reader::{PcapReader, PcapRecords};
pub use types::{
    PcapHeader, PcapLinkType, PcapPacket, PcapRecord, PcapTimestamp, TimestampPrecision,
    DLT_BLUETOOTH_LE_LL_WITH_PHDR, DLT_EN10MB, DLT_IEEE802_11, DLT_IEEE802_11_RADIO, DLT_LINUX_SLL,
    DLT_LOOP, DLT_NULL, DLT_RAW, LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR, LINKTYPE_IEEE802_11,
    LINKTYPE_IEEE802_11_RADIOTAP,
};
pub use writer::{PcapWriter, PcapWriterOptions};

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{BleRadio, Dot11, Ethernet, Ipv4, Ipv6, LinuxSll, NullLoopback, Radiotap};

use super::super::record::{BackendKind, PacketRecord};
use super::super::source::PacketSource;
use super::super::writer::{PacketWriter, WriteReport};
use super::super::Result as WireResult;

pub(crate) const DEFAULT_INTERFACE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const DEFAULT_INTERFACE_SNAPLEN: u32 = 65_535;
pub(crate) const DEFAULT_INTERFACE_PROMISC: bool = true;
pub(crate) const DEFAULT_INTERFACE_IMMEDIATE: bool = true;
pub(crate) const DEFAULT_INTERFACE_NONBLOCKING: bool = false;

/// Offline pcap packet source.
#[derive(Debug)]
pub struct OfflinePcapSource {
    path: PathBuf,
    filter: Option<String>,
    inner: OfflinePcapSourceInner,
}

#[derive(Debug)]
enum OfflinePcapSourceInner {
    Reader(PcapReader<BufReader<File>>),
    Filtered(LibpcapOfflineCapture),
}

impl OfflinePcapSource {
    /// Open an offline pcap file source with no filter.
    pub fn open(path: impl AsRef<Path>) -> WireResult<Self> {
        Self::open_with_optional_filter(path, None)
    }

    /// Open an offline pcap file source with a libpcap BPF filter.
    pub fn open_filtered(path: impl AsRef<Path>, filter: impl AsRef<str>) -> WireResult<Self> {
        Self::open_with_optional_filter(path, Some(filter.as_ref()))
    }

    pub(crate) fn open_with_optional_filter(
        path: impl AsRef<Path>,
        filter: Option<&str>,
    ) -> WireResult<Self> {
        let path = path.as_ref().to_path_buf();
        let filter = filter
            .map(str::trim)
            .filter(|filter| !filter.is_empty())
            .map(ToOwned::to_owned);

        let inner = if let Some(filter) = filter.as_deref() {
            OfflinePcapSourceInner::Filtered(LibpcapOfflineCapture::open(&path, Some(filter))?)
        } else {
            OfflinePcapSourceInner::Reader(PcapReader::open(&path)?)
        };

        Ok(Self {
            path,
            filter,
            inner,
        })
    }

    /// File backing this offline source.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Configured BPF filter, if this source is filtered.
    pub fn filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }

    fn next_pcap_record(&mut self) -> WireResult<Option<PcapRecord>> {
        match &mut self.inner {
            OfflinePcapSourceInner::Reader(reader) => reader.next_record().map_err(Into::into),
            OfflinePcapSourceInner::Filtered(capture) => capture.next_record().map_err(Into::into),
        }
    }
}

impl PacketSource for OfflinePcapSource {
    fn next_record(&mut self) -> WireResult<Option<PacketRecord>> {
        self.next_pcap_record()?
            .map(|record| pcap_record_to_packet_record(self.path(), record))
            .transpose()
    }
}

/// Builder for a live pcap interface packet source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapInterfaceSourceBuilder {
    interface: String,
    filter: Option<String>,
    timeout: Option<Duration>,
    snaplen: u32,
    promisc: bool,
    immediate: bool,
    nonblocking: bool,
}

impl PcapInterfaceSourceBuilder {
    /// Create a live pcap interface source builder.
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            filter: None,
            timeout: Some(DEFAULT_INTERFACE_TIMEOUT),
            snaplen: DEFAULT_INTERFACE_SNAPLEN,
            promisc: DEFAULT_INTERFACE_PROMISC,
            immediate: DEFAULT_INTERFACE_IMMEDIATE,
            nonblocking: DEFAULT_INTERFACE_NONBLOCKING,
        }
    }

    /// Interface this source will open.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Set a libpcap BPF filter.
    pub fn filter(mut self, filter: impl Into<String>) -> Self {
        let filter = filter.into();
        self.filter = filter_trimmed(filter);
        self
    }

    /// Remove any configured BPF filter.
    pub fn clear_filter(mut self) -> Self {
        self.filter = None;
        self
    }

    /// Configured libpcap BPF filter, if any.
    pub fn pcap_filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }

    /// Set the libpcap read timeout used while opening the interface.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Disable the libpcap read timeout.
    pub fn no_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    /// Configured libpcap read timeout.
    pub const fn timeout_limit(&self) -> Option<Duration> {
        self.timeout
    }

    /// Set the snapshot length for live capture.
    pub const fn snaplen(mut self, snaplen: u32) -> Self {
        self.snaplen = snaplen;
        self
    }

    /// Configured live capture snapshot length.
    pub const fn snaplen_value(&self) -> u32 {
        self.snaplen
    }

    /// Enable or disable promiscuous mode.
    pub const fn promisc(mut self, promisc: bool) -> Self {
        self.promisc = promisc;
        self
    }

    /// Whether promiscuous mode is enabled.
    pub const fn promisc_enabled(&self) -> bool {
        self.promisc
    }

    /// Enable or disable immediate mode.
    pub const fn immediate_mode(mut self, immediate: bool) -> Self {
        self.immediate = immediate;
        self
    }

    /// Whether immediate mode is enabled.
    pub const fn immediate_mode_enabled(&self) -> bool {
        self.immediate
    }

    /// Enable or disable nonblocking reads.
    pub const fn nonblocking(mut self, nonblocking: bool) -> Self {
        self.nonblocking = nonblocking;
        self
    }

    /// Enable nonblocking reads.
    pub const fn nonblock(self) -> Self {
        self.nonblocking(true)
    }

    /// Whether nonblocking reads are enabled.
    pub const fn nonblocking_enabled(&self) -> bool {
        self.nonblocking
    }

    /// Open this live pcap interface source.
    pub fn open(self) -> WireResult<PcapInterfaceSource> {
        let inner = LibpcapCapture::open(
            &self.interface,
            self.filter.as_deref(),
            self.timeout,
            self.snaplen,
            self.promisc,
            self.immediate,
            self.nonblocking,
        )?;

        Ok(PcapInterfaceSource {
            interface: self.interface,
            filter: self.filter,
            timeout: self.timeout,
            snaplen: self.snaplen,
            promisc: self.promisc,
            immediate: self.immediate,
            nonblocking: self.nonblocking,
            inner,
        })
    }
}

/// Live pcap interface packet source.
#[derive(Debug)]
pub struct PcapInterfaceSource {
    interface: String,
    filter: Option<String>,
    timeout: Option<Duration>,
    snaplen: u32,
    promisc: bool,
    immediate: bool,
    nonblocking: bool,
    inner: LibpcapCapture,
}

impl PcapInterfaceSource {
    /// Create a builder for a live pcap interface packet source.
    pub fn builder(interface: impl Into<String>) -> PcapInterfaceSourceBuilder {
        PcapInterfaceSourceBuilder::new(interface)
    }

    /// Open a live pcap interface source with default options.
    pub fn open(interface: impl Into<String>) -> WireResult<Self> {
        Self::builder(interface).open()
    }

    /// Interface backing this live source.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Configured BPF filter, if this source is filtered.
    pub fn filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }

    /// Configured libpcap read timeout.
    pub const fn timeout_limit(&self) -> Option<Duration> {
        self.timeout
    }

    /// Configured snapshot length.
    pub const fn snaplen_value(&self) -> u32 {
        self.snaplen
    }

    /// Whether promiscuous mode is enabled.
    pub const fn promisc_enabled(&self) -> bool {
        self.promisc
    }

    /// Whether immediate mode is enabled.
    pub const fn immediate_mode_enabled(&self) -> bool {
        self.immediate
    }

    /// Whether nonblocking reads are enabled.
    pub const fn nonblocking_enabled(&self) -> bool {
        self.nonblocking
    }
}

impl PacketSource for PcapInterfaceSource {
    fn next_record(&mut self) -> WireResult<Option<PacketRecord>> {
        self.inner
            .next_record()?
            .map(|record| pcap_interface_record_to_packet_record(self.interface(), record))
            .transpose()
    }
}

/// Builder for a live pcap interface packet writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapInterfaceWriterBuilder {
    interface: String,
    timeout: Option<Duration>,
    snaplen: u32,
    promisc: bool,
    immediate: bool,
    nonblocking: bool,
}

impl PcapInterfaceWriterBuilder {
    /// Create a live pcap interface writer builder.
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            timeout: Some(DEFAULT_INTERFACE_TIMEOUT),
            snaplen: DEFAULT_INTERFACE_SNAPLEN,
            promisc: DEFAULT_INTERFACE_PROMISC,
            immediate: DEFAULT_INTERFACE_IMMEDIATE,
            nonblocking: DEFAULT_INTERFACE_NONBLOCKING,
        }
    }

    /// Interface this writer will open.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Set the libpcap timeout used while opening the interface.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Disable the libpcap timeout.
    pub fn no_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    /// Configured libpcap timeout.
    pub const fn timeout_limit(&self) -> Option<Duration> {
        self.timeout
    }

    /// Set the snapshot length for the live pcap handle.
    pub const fn snaplen(mut self, snaplen: u32) -> Self {
        self.snaplen = snaplen;
        self
    }

    /// Configured live pcap snapshot length.
    pub const fn snaplen_value(&self) -> u32 {
        self.snaplen
    }

    /// Enable or disable promiscuous mode.
    pub const fn promisc(mut self, promisc: bool) -> Self {
        self.promisc = promisc;
        self
    }

    /// Whether promiscuous mode is enabled.
    pub const fn promisc_enabled(&self) -> bool {
        self.promisc
    }

    /// Enable or disable immediate mode.
    pub const fn immediate_mode(mut self, immediate: bool) -> Self {
        self.immediate = immediate;
        self
    }

    /// Whether immediate mode is enabled.
    pub const fn immediate_mode_enabled(&self) -> bool {
        self.immediate
    }

    /// Enable or disable nonblocking mode.
    pub const fn nonblocking(mut self, nonblocking: bool) -> Self {
        self.nonblocking = nonblocking;
        self
    }

    /// Enable nonblocking mode.
    pub const fn nonblock(self) -> Self {
        self.nonblocking(true)
    }

    /// Whether nonblocking mode is enabled.
    pub const fn nonblocking_enabled(&self) -> bool {
        self.nonblocking
    }

    /// Open this live pcap interface writer.
    pub fn open(self) -> WireResult<PcapInterfaceWriter> {
        let inner = LibpcapCapture::open(
            &self.interface,
            None,
            self.timeout,
            self.snaplen,
            self.promisc,
            self.immediate,
            self.nonblocking,
        )?;
        let link_type = inner.link_type();

        Ok(PcapInterfaceWriter {
            interface: self.interface,
            timeout: self.timeout,
            snaplen: self.snaplen,
            promisc: self.promisc,
            immediate: self.immediate,
            nonblocking: self.nonblocking,
            link_type,
            inner,
        })
    }
}

/// Live pcap interface packet writer.
#[derive(Debug)]
pub struct PcapInterfaceWriter {
    interface: String,
    timeout: Option<Duration>,
    snaplen: u32,
    promisc: bool,
    immediate: bool,
    nonblocking: bool,
    link_type: PcapLinkType,
    inner: LibpcapCapture,
}

impl PcapInterfaceWriter {
    /// Create a builder for a live pcap interface packet writer.
    pub fn builder(interface: impl Into<String>) -> PcapInterfaceWriterBuilder {
        PcapInterfaceWriterBuilder::new(interface)
    }

    /// Open a live pcap interface writer with default options.
    pub fn open(interface: impl Into<String>) -> WireResult<Self> {
        Self::builder(interface).open()
    }

    /// Interface backing this live writer.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Configured libpcap timeout.
    pub const fn timeout_limit(&self) -> Option<Duration> {
        self.timeout
    }

    /// Configured snapshot length.
    pub const fn snaplen_value(&self) -> u32 {
        self.snaplen
    }

    /// Whether promiscuous mode is enabled.
    pub const fn promisc_enabled(&self) -> bool {
        self.promisc
    }

    /// Whether immediate mode is enabled.
    pub const fn immediate_mode_enabled(&self) -> bool {
        self.immediate
    }

    /// Whether nonblocking mode is enabled.
    pub const fn nonblocking_enabled(&self) -> bool {
        self.nonblocking
    }

    /// Pcap data-link type reported by the live interface.
    pub const fn pcap_link_type(&self) -> PcapLinkType {
        self.link_type
    }
}

impl PacketWriter for PcapInterfaceWriter {
    fn write_record(&mut self, record: &PacketRecord) -> WireResult<WriteReport> {
        ensure_record_link_type(record, self.link_type)?;

        let compiled = record.packet().compile()?;
        let bytes = compiled.into_bytes();
        let byte_len = bytes.len();
        self.inner.send_packet(&bytes)?;

        Ok(
            WriteReport::new(BackendKind::PcapInterface, byte_len, byte_len, false)
                .with_target_details(self.interface.clone()),
        )
    }
}

/// Offline pcap packet writer.
#[derive(Debug)]
pub struct PcapFileWriter {
    path: PathBuf,
    link_type: PcapLinkType,
    inner: PcapWriter,
}

impl PcapFileWriter {
    /// Create a pcap file writer with the supplied pcap data-link type.
    pub fn create(path: impl AsRef<Path>, link_type: impl Into<PcapLinkType>) -> WireResult<Self> {
        let path = path.as_ref().to_path_buf();
        let link_type = link_type.into();
        let inner = PcapWriter::create(&path, link_type)?;
        Ok(Self {
            path,
            link_type,
            inner,
        })
    }

    /// File backing this pcap writer.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Pcap data-link type enforced by this writer.
    pub const fn pcap_link_type(&self) -> PcapLinkType {
        self.link_type
    }

    /// Flush buffered pcap output.
    pub fn flush(&mut self) -> WireResult<()> {
        self.inner.flush().map_err(Into::into)
    }
}

impl PacketWriter for PcapFileWriter {
    fn write_record(&mut self, record: &PacketRecord) -> WireResult<WriteReport> {
        ensure_record_link_type(record, self.link_type)?;

        let compiled = record.packet().compile()?;
        let bytes = compiled.into_bytes();
        let byte_len = bytes.len();
        let captured_len = u32::try_from(byte_len).map_err(|_| PcapError::RecordTooLarge {
            field: "captured length",
            max: u32::MAX as u64,
            actual: byte_len as u64,
        })?;
        let timestamp = record
            .metadata()
            .timestamp()
            .unwrap_or_else(PcapTimestamp::zero);
        let pcap_record = PcapRecord::new(timestamp, captured_len, bytes, self.link_type)?;

        self.inner.write_record(&pcap_record)?;
        self.inner.flush()?;

        Ok(
            WriteReport::new(BackendKind::PcapFile, byte_len, byte_len, false)
                .with_target_details(self.path.display().to_string()),
        )
    }
}

fn pcap_record_to_packet_record(path: &Path, record: PcapRecord) -> WireResult<PacketRecord> {
    Ok(PacketRecord::try_from_pcap_record(record)?
        .with_backend(BackendKind::PcapFile)
        .with_file(path.to_path_buf()))
}

fn pcap_interface_record_to_packet_record(
    interface: &str,
    record: PcapRecord,
) -> WireResult<PacketRecord> {
    Ok(PacketRecord::try_from_pcap_record(record)?
        .with_backend(BackendKind::PcapInterface)
        .with_interface(interface))
}

fn record_pcap_link_type(record: &PacketRecord) -> Option<PcapLinkType> {
    record
        .metadata()
        .pcap_link_type()
        .or_else(|| record.metadata().link_type().map(PcapLinkType::from))
        .or_else(|| packet_pcap_link_type(record))
}

fn packet_pcap_link_type(record: &PacketRecord) -> Option<PcapLinkType> {
    let first = record.packet().get(0)?;
    if first.as_any().is::<Ethernet>() {
        Some(PcapLinkType::Ethernet)
    } else if first.as_any().is::<Dot11>() {
        Some(PcapLinkType::Ieee80211)
    } else if first.as_any().is::<Radiotap>() {
        Some(PcapLinkType::Ieee80211Radiotap)
    } else if first.as_any().is::<BleRadio>() {
        Some(PcapLinkType::BluetoothLeLl)
    } else if first.as_any().is::<LinuxSll>() {
        Some(PcapLinkType::LinuxSll)
    } else if first.as_any().is::<NullLoopback>() {
        Some(PcapLinkType::NullLoopback)
    } else if first.as_any().is::<Ipv4>() || first.as_any().is::<Ipv6>() {
        Some(PcapLinkType::RawIp)
    } else {
        None
    }
}

fn ensure_record_link_type(record: &PacketRecord, link_type: PcapLinkType) -> WireResult<()> {
    if let Some(record_link_type) = record_pcap_link_type(record) {
        if record_link_type != link_type {
            return Err(
                PcapError::InvalidRecord("record link type must match writer link type").into(),
            );
        }
    }

    Ok(())
}

pub(crate) fn filter_trimmed(filter: impl Into<String>) -> Option<String> {
    let filter = filter.into();
    let filter = filter.trim();
    (!filter.is_empty()).then(|| filter.to_owned())
}

#[cfg(test)]
mod codec_tests;

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::{
        AdStructure, BleLlAdv, BleRadio, Dot11, Ethernet, Ipv4, LinkType, MacAddr, Packet,
        PacketOrigin, PacketWire, Radiotap, Raw, Sniffer, Tcp, Transmitter, WireError,
    };

    static NEXT_TEMP_PCAP: AtomicUsize = AtomicUsize::new(0);

    struct TempPcap {
        path: PathBuf,
    }

    impl TempPcap {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempPcap {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn temp_pcap_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "wire-pcap-{name}-{}-{}.pcap",
            std::process::id(),
            NEXT_TEMP_PCAP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn write_temp_pcap(
        name: &str,
        packets: impl IntoIterator<Item = (Packet, PcapTimestamp)>,
    ) -> TempPcap {
        let path = temp_pcap_path(name);
        {
            let mut writer = PcapWriter::create(&path, LinkType::Ethernet).unwrap();
            for (packet, timestamp) in packets {
                writer
                    .write_packet_with_timestamp(&packet, timestamp)
                    .unwrap();
            }
            writer.flush().unwrap();
        }
        TempPcap { path }
    }

    fn tcp_packet(source_port: u16, destination_port: u16) -> Packet {
        Ethernet::new()
            .src(MacAddr::new([0x02, 0, 0, 0, 0, 1]))
            .dst(MacAddr::BROADCAST)
            / Ipv4::new()
                .src_str("192.0.2.10")
                .unwrap()
                .dst_str("198.51.100.20")
                .unwrap()
            / Tcp::new().sport(source_port).dport(destination_port)
            / Raw::from("payload")
    }

    #[test]
    fn offline_source_reads_records_with_pcap_metadata() {
        let timestamp = PcapTimestamp::micros(123, 456).unwrap();
        let packet = tcp_packet(40000, 443);
        let captured = packet.compile().unwrap().into_bytes();
        let temp = write_temp_pcap("metadata", [(packet, timestamp)]);
        let mut source = OfflinePcapSource::open(temp.path()).unwrap();

        let record = source.next_record().unwrap().unwrap();

        assert!(record.packet().layer::<Tcp>().is_some());
        assert_eq!(record.metadata().origin(), PacketOrigin::Captured);
        assert_eq!(record.metadata().backend(), &BackendKind::PcapFile);
        assert_eq!(record.metadata().file(), Some(temp.path()));
        assert_eq!(record.metadata().timestamp(), Some(timestamp));
        assert_eq!(
            record.metadata().original_len(),
            Some(captured.len() as u32)
        );
        assert_eq!(
            record.metadata().captured_len(),
            Some(captured.len() as u32)
        );
        assert_eq!(
            record.metadata().captured_bytes(),
            Some(captured.as_slice())
        );
        assert_eq!(record.metadata().link_type(), Some(LinkType::Ethernet));
        assert_eq!(
            record.metadata().pcap_link_type(),
            Some(PcapLinkType::Ethernet)
        );
        assert!(source.next_record().unwrap().is_none());
    }

    #[test]
    fn offline_source_filtered_uses_libpcap_bpf() {
        let https = tcp_packet(12345, 443);
        let http = tcp_packet(12345, 80);
        let temp = write_temp_pcap(
            "filtered",
            [
                (https, PcapTimestamp::micros(1, 0).unwrap()),
                (http, PcapTimestamp::micros(2, 0).unwrap()),
            ],
        );
        let mut source =
            OfflinePcapSource::open_filtered(temp.path(), "tcp and dst port 443").unwrap();

        assert_eq!(source.filter(), Some("tcp and dst port 443"));

        let record = source.next_record().unwrap().unwrap();
        assert_eq!(
            record
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .destination_port_value(),
            443
        );
        assert!(source.next_record().unwrap().is_none());
    }

    #[test]
    fn pcap_file_wire_sniffer_supports_filtered_iteration_and_spawn() {
        let temp = write_temp_pcap(
            "sniffer-wire",
            [
                (tcp_packet(10, 80), PcapTimestamp::micros(1, 0).unwrap()),
                (tcp_packet(11, 443), PcapTimestamp::micros(2, 0).unwrap()),
            ],
        );

        let source = PacketWire::pcap_file(temp.path())
            .filter("tcp and dst port 80")
            .open()
            .unwrap()
            .source()
            .unwrap();
        let mut sniffer = Sniffer::new(source).count(1);
        let first = sniffer.next_record().unwrap().unwrap();
        assert_eq!(
            first.metadata().timestamp(),
            Some(PcapTimestamp::micros(1, 0).unwrap())
        );
        assert_eq!(first.metadata().link_type(), Some(LinkType::Ethernet));
        assert_eq!(
            first.metadata().pcap_link_type(),
            Some(PcapLinkType::Ethernet)
        );
        assert_eq!(first.metadata().backend(), &BackendKind::PcapFile);
        assert_eq!(first.metadata().file(), Some(temp.path()));
        assert_eq!(
            first
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .destination_port_value(),
            80
        );
        assert!(sniffer.next_record().unwrap().is_none());

        let source = PacketWire::pcap_file(temp.path())
            .filter("tcp")
            .open()
            .unwrap()
            .source()
            .unwrap();
        let mut sniffer = Sniffer::new(source).count(10);
        let mut accepted = 0;
        while let Some(record) = sniffer.next_record().unwrap() {
            accepted += 1;
            if record
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .destination_port_value()
                == 443
            {
                assert_eq!(
                    record.metadata().timestamp(),
                    Some(PcapTimestamp::micros(2, 0).unwrap())
                );
                assert_eq!(record.metadata().link_type(), Some(LinkType::Ethernet));
                break;
            }
        }
        assert_eq!(accepted, 2);

        let source = PacketWire::pcap_file(temp.path())
            .filter("tcp")
            .open()
            .unwrap()
            .source()
            .unwrap();
        let records = Sniffer::new(source).spawn_count(2).unwrap().join().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records
                .iter()
                .map(|record| record.metadata().timestamp().unwrap())
                .collect::<Vec<_>>(),
            vec![
                PcapTimestamp::micros(1, 0).unwrap(),
                PcapTimestamp::micros(2, 0).unwrap()
            ]
        );
        assert!(records
            .iter()
            .all(|record| record.metadata().link_type() == Some(LinkType::Ethernet)));
        assert!(records
            .iter()
            .all(|record| record.packet().layer::<Tcp>().is_some()));
    }

    #[test]
    fn pcap_file_wire_sniffer_uses_libpcap_bpf() {
        let https = tcp_packet(12345, 443);
        let http = tcp_packet(12345, 80);
        let temp = write_temp_pcap(
            "bpf-filter",
            [
                (https, PcapTimestamp::micros(1, 0).unwrap()),
                (http, PcapTimestamp::micros(2, 0).unwrap()),
            ],
        );

        let source = PacketWire::pcap_file(temp.path())
            .filter("tcp and dst port 443")
            .open()
            .unwrap()
            .source()
            .unwrap();
        let packets = Sniffer::new(source).collect_records().unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(
            packets[0]
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .destination_port_value(),
            443
        );
        assert_eq!(
            packets[0].metadata().timestamp(),
            Some(PcapTimestamp::micros(1, 0).unwrap())
        );
        assert_eq!(packets[0].metadata().link_type(), Some(LinkType::Ethernet));
        assert_eq!(
            packets[0].metadata().pcap_link_type(),
            Some(PcapLinkType::Ethernet)
        );

        let source = PacketWire::pcap_file(temp.path())
            .filter("tcp and not dst port 443")
            .open()
            .unwrap()
            .source()
            .unwrap();
        let packets = Sniffer::new(source).collect_records().unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(
            packets[0]
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .destination_port_value(),
            80
        );
        assert_eq!(
            packets[0].metadata().timestamp(),
            Some(PcapTimestamp::micros(2, 0).unwrap())
        );
        assert_eq!(packets[0].metadata().link_type(), Some(LinkType::Ethernet));
    }

    #[test]
    fn pcap_interface_source_builder_uses_live_capture_defaults() {
        let builder = PcapInterfaceSource::builder("eth0");

        assert_eq!(builder.interface(), "eth0");
        assert_eq!(builder.pcap_filter(), None);
        assert_eq!(builder.timeout_limit(), Some(DEFAULT_INTERFACE_TIMEOUT));
        assert_eq!(builder.snaplen_value(), DEFAULT_INTERFACE_SNAPLEN);
        assert_eq!(builder.promisc_enabled(), DEFAULT_INTERFACE_PROMISC);
        assert_eq!(
            builder.immediate_mode_enabled(),
            DEFAULT_INTERFACE_IMMEDIATE
        );
        assert_eq!(builder.nonblocking_enabled(), DEFAULT_INTERFACE_NONBLOCKING);
    }

    #[test]
    fn pcap_interface_source_builder_preserves_configured_options() {
        let builder = PcapInterfaceSource::builder("wlan0mon")
            .filter("  tcp and port 443  ")
            .timeout(Duration::from_millis(250))
            .snaplen(4096)
            .promisc(false)
            .immediate_mode(false)
            .nonblock();

        assert_eq!(builder.interface(), "wlan0mon");
        assert_eq!(builder.pcap_filter(), Some("tcp and port 443"));
        assert_eq!(builder.timeout_limit(), Some(Duration::from_millis(250)));
        assert_eq!(builder.snaplen_value(), 4096);
        assert!(!builder.promisc_enabled());
        assert!(!builder.immediate_mode_enabled());
        assert!(builder.nonblocking_enabled());

        let cleared = builder.clear_filter().no_timeout().nonblocking(false);
        assert_eq!(cleared.pcap_filter(), None);
        assert_eq!(cleared.timeout_limit(), None);
        assert!(!cleared.nonblocking_enabled());
    }

    #[test]
    fn pcap_interface_writer_builder_uses_live_capture_defaults() {
        let builder = PcapInterfaceWriter::builder("eth0");

        assert_eq!(builder.interface(), "eth0");
        assert_eq!(builder.timeout_limit(), Some(DEFAULT_INTERFACE_TIMEOUT));
        assert_eq!(builder.snaplen_value(), DEFAULT_INTERFACE_SNAPLEN);
        assert_eq!(builder.promisc_enabled(), DEFAULT_INTERFACE_PROMISC);
        assert_eq!(
            builder.immediate_mode_enabled(),
            DEFAULT_INTERFACE_IMMEDIATE
        );
        assert_eq!(builder.nonblocking_enabled(), DEFAULT_INTERFACE_NONBLOCKING);
    }

    #[test]
    fn pcap_interface_writer_builder_preserves_configured_options() {
        let builder = PcapInterfaceWriter::builder("wlan0mon")
            .timeout(Duration::from_millis(250))
            .snaplen(4096)
            .promisc(false)
            .immediate_mode(false)
            .nonblock();

        assert_eq!(builder.interface(), "wlan0mon");
        assert_eq!(builder.timeout_limit(), Some(Duration::from_millis(250)));
        assert_eq!(builder.snaplen_value(), 4096);
        assert!(!builder.promisc_enabled());
        assert!(!builder.immediate_mode_enabled());
        assert!(builder.nonblocking_enabled());

        let cleared = builder.no_timeout().nonblocking(false);
        assert_eq!(cleared.timeout_limit(), None);
        assert!(!cleared.nonblocking_enabled());
    }

    #[test]
    fn pcap_interface_record_decode_attaches_interface_metadata() {
        let timestamp = PcapTimestamp::micros(12, 34).unwrap();
        let packet = tcp_packet(50000, 22);
        let captured = packet.compile().unwrap().into_bytes();
        let pcap_record = PcapRecord::new(
            timestamp,
            captured.len() as u32,
            captured.clone(),
            PcapLinkType::Ethernet,
        )
        .unwrap();

        let record = pcap_interface_record_to_packet_record("eth0", pcap_record).unwrap();

        assert_eq!(
            record
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .destination_port_value(),
            22
        );
        assert_eq!(record.metadata().origin(), PacketOrigin::Captured);
        assert_eq!(record.metadata().backend(), &BackendKind::PcapInterface);
        assert_eq!(record.metadata().interface(), Some("eth0"));
        assert_eq!(record.metadata().file(), None);
        assert_eq!(record.metadata().timestamp(), Some(timestamp));
        assert_eq!(
            record.metadata().original_len(),
            Some(captured.len() as u32)
        );
        assert_eq!(
            record.metadata().captured_len(),
            Some(captured.len() as u32)
        );
        assert_eq!(
            record.metadata().captured_bytes(),
            Some(captured.as_slice())
        );
        assert_eq!(record.metadata().link_type(), Some(LinkType::Ethernet));
        assert_eq!(
            record.metadata().pcap_link_type(),
            Some(PcapLinkType::Ethernet)
        );
    }

    #[test]
    fn pcap_interface_source_open_rejects_empty_interface_without_live_capture() {
        assert_empty_interface_error(PcapInterfaceSource::builder("   ").open());
    }

    #[test]
    fn pcap_interface_writer_open_rejects_empty_interface_without_live_capture() {
        assert_empty_interface_error(PcapInterfaceWriter::builder("   ").open());
    }

    #[test]
    #[ignore = "live capture is reserved for disposable wire endpoint execution"]
    fn pcap_interface_wire_sniffer_live_endpoint_only() {
        let Some(iface) = std::env::var_os("LIBCRAFTER_LIVE_CAPTURE_IFACE") else {
            return;
        };
        let source = PacketWire::pcap_interface(iface.to_string_lossy().into_owned())
            .filter("icmp or arp")
            .timeout(Duration::from_secs(2))
            .open()
            .unwrap()
            .source()
            .unwrap();
        let packets = Sniffer::new(source)
            .count(1)
            .timeout(Duration::from_secs(2))
            .collect_records()
            .unwrap();
        assert!(packets.len() <= 1);
        for packet in packets {
            assert_eq!(packet.metadata().backend(), &BackendKind::PcapInterface);
            assert_eq!(
                packet.metadata().interface(),
                Some(iface.to_string_lossy().as_ref())
            );
            assert!(packet.metadata().timestamp().is_some());
            assert!(packet.metadata().link_type().is_some());
        }
    }

    #[test]
    fn packet_wire_pcap_interface_open_rejects_empty_interface_without_live_capture() {
        assert_empty_interface_error(PacketWire::pcap_interface("").open());
    }

    #[test]
    fn packet_wire_pcap_file_opens_offline_source() {
        let temp = write_temp_pcap(
            "packet-wire",
            [(tcp_packet(40000, 80), PcapTimestamp::zero())],
        );
        let wire = PacketWire::pcap_file(temp.path()).open().unwrap();

        assert!(wire.has_source());
        assert!(!wire.has_writer());

        let mut source = wire.source().unwrap();
        let record = source.next_record().unwrap().unwrap();
        assert_eq!(
            record
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .destination_port_value(),
            80
        );
    }

    #[test]
    fn packet_wire_pcap_file_filter_opens_filtered_source() {
        let temp = write_temp_pcap(
            "packet-wire-filtered",
            [
                (tcp_packet(11111, 443), PcapTimestamp::zero()),
                (tcp_packet(11111, 80), PcapTimestamp::zero()),
            ],
        );
        let mut source = PacketWire::pcap_file(temp.path())
            .filter("tcp and dst port 80")
            .open()
            .unwrap()
            .source()
            .unwrap();

        let record = source.next_record().unwrap().unwrap();
        assert_eq!(
            record
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .destination_port_value(),
            80
        );
        assert!(source.next_record().unwrap().is_none());
    }

    #[test]
    fn packet_wire_pcap_file_open_reports_missing_file() {
        let path = temp_pcap_path("missing");
        let err = PacketWire::pcap_file(&path).open().unwrap_err();

        match err {
            WireError::Pcap(_) => {}
            other => panic!("expected pcap error for missing file, got {other:?}"),
        }
    }

    #[test]
    fn pcap_file_writer_transmitter_round_trips_records_through_packet_wire() {
        let temp = TempPcap {
            path: temp_pcap_path("writer-roundtrip"),
        };
        let first_timestamp = PcapTimestamp::micros(123, 456).unwrap();
        let second_timestamp = PcapTimestamp::micros(124, 789).unwrap();
        let first = PacketRecord::new(tcp_packet(41000, 443))
            .with_pcap_link_type(PcapLinkType::Ethernet)
            .with_timestamp(first_timestamp);
        let second = PacketRecord::new(tcp_packet(41001, 80))
            .with_pcap_link_type(PcapLinkType::Ethernet)
            .with_timestamp(second_timestamp);
        let first_compiled = first.packet().compile().unwrap();
        let second_compiled = second.packet().compile().unwrap();
        let expected_summaries = vec![
            PcapLinkType::Ethernet
                .decode(first_compiled.as_bytes())
                .unwrap()
                .summary(),
            PcapLinkType::Ethernet
                .decode(second_compiled.as_bytes())
                .unwrap()
                .summary(),
        ];
        let expected_timestamps = vec![first_timestamp, second_timestamp];
        let first_len = first_compiled.as_bytes().len();
        let second_len = second_compiled.as_bytes().len();

        {
            let writer = PacketWire::pcap_recorder(temp.path(), LinkType::Ethernet)
                .open()
                .unwrap()
                .writer()
                .unwrap();
            let mut transmitter = Transmitter::new(writer);

            let first_reports = transmitter.write_record(first).unwrap();
            let second_reports = transmitter.write_record(second).unwrap();

            assert_eq!(first_reports.len(), 1);
            assert_eq!(first_reports[0].backend(), &BackendKind::PcapFile);
            assert_eq!(first_reports[0].bytes_requested(), first_len);
            assert_eq!(first_reports[0].bytes_written(), first_len);
            assert!(!first_reports[0].is_dry_run());
            assert_eq!(
                first_reports[0].target_details(),
                Some(temp.path().display().to_string().as_str())
            );
            assert_eq!(second_reports.len(), 1);
            assert_eq!(second_reports[0].bytes_requested(), second_len);
            assert_eq!(second_reports[0].bytes_written(), second_len);
        }

        let mut source = PacketWire::pcap_file(temp.path())
            .open()
            .unwrap()
            .source()
            .unwrap();
        let mut actual_summaries = Vec::new();
        let mut actual_timestamps = Vec::new();

        while let Some(record) = source.next_record().unwrap() {
            actual_summaries.push(record.packet().summary());
            actual_timestamps.push(record.metadata().timestamp().unwrap());
        }

        assert_eq!(actual_summaries, expected_summaries);
        assert_eq!(actual_timestamps, expected_timestamps);
    }

    #[test]
    fn pcap_write_ble() {
        let temp = TempPcap {
            path: temp_pcap_path("write-ble"),
        };
        let packet = BleRadio::advertising(37)
            / BleLlAdv::adv_ind()
                .adv_a_str("C0:FF:EE:11:22:33")
                .unwrap()
                .push_ad(AdStructure::flags_general_disc());
        let record = PacketRecord::new(packet);
        assert_eq!(
            record_pcap_link_type(&record),
            Some(PcapLinkType::BluetoothLeLl)
        );

        {
            let writer = PacketWire::pcap_recorder(temp.path(), LinkType::BluetoothLeLl)
                .open()
                .unwrap()
                .writer()
                .unwrap();
            let mut transmitter = Transmitter::new(writer);
            let reports = transmitter.write_record(record).unwrap();

            assert_eq!(reports.len(), 1);
            assert_eq!(reports[0].backend(), &BackendKind::PcapFile);
            assert!(!reports[0].is_dry_run());
        }

        let reader = PcapReader::open(temp.path()).unwrap();
        assert_eq!(
            reader.header().pcap_link_type(),
            PcapLinkType::BluetoothLeLl
        );
        assert_eq!(
            reader.header().pcap_link_type().datalink(),
            DLT_BLUETOOTH_LE_LL_WITH_PHDR
        );
    }

    #[test]
    fn pcap_file_writer_rejects_record_link_type_mismatch() {
        let temp = TempPcap {
            path: temp_pcap_path("writer-link-type-mismatch"),
        };
        let writer = PacketWire::pcap_recorder(temp.path(), LinkType::Ethernet)
            .open()
            .unwrap()
            .writer()
            .unwrap();
        let mut transmitter = Transmitter::new(writer);
        let record =
            PacketRecord::new(Raw::from("payload")).with_pcap_link_type(PcapLinkType::RawIp);

        let err = transmitter.write_record(record).unwrap_err();

        match err {
            WireError::Pcap(PcapError::InvalidRecord(reason)) => {
                assert_eq!(reason, "record link type must match writer link type");
            }
            other => panic!("expected pcap link-type error, got {other:?}"),
        }
    }

    #[test]
    fn pcap_interface_writer_link_type_validation_is_explicit() {
        let matching =
            PacketRecord::new(tcp_packet(43000, 443)).with_pcap_link_type(PcapLinkType::Ethernet);
        let inferred = PacketRecord::new(tcp_packet(43001, 443)).with_link_type(LinkType::Ethernet);
        let untyped_raw = PacketRecord::new(Raw::from("opaque"));
        let mismatched =
            PacketRecord::new(Raw::from("radiotap")).with_pcap_link_type(PcapLinkType::RawIp);
        let inferred_mismatch = PacketRecord::new(Radiotap::new() / Dot11::data());

        ensure_record_link_type(&matching, PcapLinkType::Ethernet).unwrap();
        ensure_record_link_type(&inferred, PcapLinkType::Ethernet).unwrap();
        ensure_record_link_type(&untyped_raw, PcapLinkType::Ieee80211Radiotap).unwrap();

        let err = ensure_record_link_type(&mismatched, PcapLinkType::Ethernet).unwrap_err();
        match err {
            WireError::Pcap(PcapError::InvalidRecord(reason)) => {
                assert_eq!(reason, "record link type must match writer link type");
            }
            other => panic!("expected pcap link-type error, got {other:?}"),
        }

        let err = ensure_record_link_type(&inferred_mismatch, PcapLinkType::Ethernet).unwrap_err();
        match err {
            WireError::Pcap(PcapError::InvalidRecord(reason)) => {
                assert_eq!(reason, "record link type must match writer link type");
            }
            other => panic!("expected inferred pcap link-type error, got {other:?}"),
        }
    }

    fn assert_empty_interface_error<T>(result: WireResult<T>) {
        let err = match result {
            Ok(_) => panic!("expected empty interface to fail"),
            Err(err) => err,
        };

        match err {
            WireError::Pcap(PcapError::LiveCaptureUnavailable(reason)) => {
                assert!(reason.contains("interface name"));
            }
            other => panic!("expected live capture unavailable error, got {other:?}"),
        }
    }
}
