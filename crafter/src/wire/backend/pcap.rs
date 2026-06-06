//! Pcap packet wire backend adapters.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::pcap::{LibpcapCapture, LibpcapOfflineCapture, PcapReader, PcapRecord};

use super::super::record::{BackendKind, PacketRecord};
use super::super::source::PacketSource;
use super::super::Result;

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
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_optional_filter(path, None)
    }

    /// Open an offline pcap file source with a libpcap BPF filter.
    pub fn open_filtered(path: impl AsRef<Path>, filter: impl AsRef<str>) -> Result<Self> {
        Self::open_with_optional_filter(path, Some(filter.as_ref()))
    }

    pub(crate) fn open_with_optional_filter(
        path: impl AsRef<Path>,
        filter: Option<&str>,
    ) -> Result<Self> {
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

    fn next_pcap_record(&mut self) -> Result<Option<PcapRecord>> {
        match &mut self.inner {
            OfflinePcapSourceInner::Reader(reader) => reader.next_record().map_err(Into::into),
            OfflinePcapSourceInner::Filtered(capture) => capture.next_record().map_err(Into::into),
        }
    }
}

impl PacketSource for OfflinePcapSource {
    fn next_record(&mut self) -> Result<Option<PacketRecord>> {
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
    pub fn open(self) -> Result<PcapInterfaceSource> {
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
    pub fn open(interface: impl Into<String>) -> Result<Self> {
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
    fn next_record(&mut self) -> Result<Option<PacketRecord>> {
        self.inner
            .next_record()?
            .map(|record| pcap_interface_record_to_packet_record(self.interface(), record))
            .transpose()
    }
}

fn pcap_record_to_packet_record(path: &Path, record: PcapRecord) -> Result<PacketRecord> {
    Ok(PacketRecord::try_from_pcap_record(record)?
        .with_backend(BackendKind::PcapFile)
        .with_file(path.to_path_buf()))
}

fn pcap_interface_record_to_packet_record(
    interface: &str,
    record: PcapRecord,
) -> Result<PacketRecord> {
    Ok(PacketRecord::try_from_pcap_record(record)?
        .with_backend(BackendKind::PcapInterface)
        .with_interface(interface))
}

pub(crate) fn filter_trimmed(filter: impl Into<String>) -> Option<String> {
    let filter = filter.into();
    let filter = filter.trim();
    (!filter.is_empty()).then(|| filter.to_owned())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::pcap::{PcapError, PcapLinkType, PcapRecord, PcapTimestamp, PcapWriter};
    use crate::{
        Ethernet, Ipv4, LinkType, MacAddr, Packet, PacketOrigin, PacketWire, Raw, Tcp, WireError,
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

    fn assert_empty_interface_error<T>(result: Result<T>) {
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
