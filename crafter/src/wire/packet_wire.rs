//! Packet wire builders and opened backend handles.
//!
//! A [`PacketWire`] represents exactly one packet-capable target: a pcap file,
//! pcap recorder, live pcap interface, or raw socket interface. It advertises
//! source and writer capabilities explicitly so callers can wire the opened
//! direction into [`crate::wire::Sniffer`] or [`crate::wire::Transmitter`].

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::net::send::validated_interface;
use crate::net::{SendMode, SendOptions};
use crate::wire::backend::pcap::PcapLinkType;

use super::backend::pcap::{
    filter_trimmed, OfflinePcapSource, PcapFileWriter, PcapInterfaceSource, PcapInterfaceWriter,
    DEFAULT_INTERFACE_IMMEDIATE, DEFAULT_INTERFACE_NONBLOCKING, DEFAULT_INTERFACE_PROMISC,
    DEFAULT_INTERFACE_SNAPLEN, DEFAULT_INTERFACE_TIMEOUT,
};
use super::backend::raw_socket::RawSocketWriter;
use super::source::PacketSource;
use super::writer::PacketWriter;
use super::{Result, WireError};

/// Boxed packet source returned by an opened packet wire.
///
/// The boxed trait object keeps backend-specific capture state hidden while
/// preserving the common [`PacketSource`] stream contract.
pub type OpenedPacketSource = Box<dyn PacketSource + Send>;

/// Boxed packet writer returned by an opened packet wire.
///
/// The boxed trait object keeps backend-specific emission state hidden while
/// preserving the common [`PacketWriter`] contract.
pub type OpenedPacketWriter = Box<dyn PacketWriter + Send>;

/// One packet-capable backend or interface target.
///
/// A target describes exactly one pcap file, pcap recorder, or live interface.
/// Applications that need multiple media should create multiple
/// [`PacketWire`] values and orchestrate them outside the crate, usually by
/// running one sniffer or transmitter per opened source or writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketWireTarget {
    /// Offline pcap file input.
    PcapFile {
        /// Path to the pcap file to read.
        path: PathBuf,
    },
    /// Offline pcap file output.
    PcapRecorder {
        /// Path to the pcap file to create.
        path: PathBuf,
        /// Pcap data-link type for emitted packet records.
        link_type: PcapLinkType,
    },
    /// Live pcap interface input and, when supported, output.
    PcapInterface {
        /// Interface name.
        interface: String,
    },
    /// Write-only raw socket interface target.
    RawSocketInterface {
        /// Interface name selected for raw socket send planning and live send.
        interface: String,
    },
}

impl PacketWireTarget {
    /// Return the pcap file path when this target is file-backed.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::PcapFile { path } | Self::PcapRecorder { path, .. } => Some(path.as_path()),
            Self::PcapInterface { .. } | Self::RawSocketInterface { .. } => None,
        }
    }

    /// Return the interface name when this target is interface-backed.
    pub fn interface(&self) -> Option<&str> {
        match self {
            Self::PcapInterface { interface } | Self::RawSocketInterface { interface } => {
                Some(interface)
            }
            Self::PcapFile { .. } | Self::PcapRecorder { .. } => None,
        }
    }

    /// Return the pcap link type configured for recorder targets.
    pub const fn pcap_link_type(&self) -> Option<PcapLinkType> {
        match self {
            Self::PcapRecorder { link_type, .. } => Some(*link_type),
            Self::PcapFile { .. }
            | Self::PcapInterface { .. }
            | Self::RawSocketInterface { .. } => None,
        }
    }

    fn backend_identifier(&self) -> String {
        match self {
            Self::PcapFile { path } => format!("pcap-file:{}", path.display()),
            Self::PcapRecorder { path, .. } => format!("pcap-recorder:{}", path.display()),
            Self::PcapInterface { interface } => format!("pcap-interface:{interface}"),
            Self::RawSocketInterface { interface } => format!("raw-socket:{interface}"),
        }
    }
}

/// Builder for one packet wire target.
///
/// The builder records which backend or interface should be opened. Backend
/// adapters attach concrete source and writer capabilities during `open`;
/// unsupported directions fail as typed [`WireError::UnsupportedCapability`]
/// values.
pub struct PacketWireBuilder {
    target: PacketWireTarget,
    pcap_filter: Option<String>,
    pcap_timeout: Option<Duration>,
    pcap_snaplen: u32,
    pcap_promisc: bool,
    pcap_immediate: bool,
    pcap_nonblocking: bool,
    source: Option<OpenedPacketSource>,
    writer: Option<OpenedPacketWriter>,
}

impl PacketWireBuilder {
    fn new(target: PacketWireTarget) -> Self {
        Self {
            target,
            pcap_filter: None,
            pcap_timeout: Some(DEFAULT_INTERFACE_TIMEOUT),
            pcap_snaplen: DEFAULT_INTERFACE_SNAPLEN,
            pcap_promisc: DEFAULT_INTERFACE_PROMISC,
            pcap_immediate: DEFAULT_INTERFACE_IMMEDIATE,
            pcap_nonblocking: DEFAULT_INTERFACE_NONBLOCKING,
            source: None,
            writer: None,
        }
    }

    /// Inspect the single target this builder will open.
    pub const fn target(&self) -> &PacketWireTarget {
        &self.target
    }

    /// Set a libpcap BPF filter for pcap source targets.
    pub fn filter(mut self, filter: impl Into<String>) -> Self {
        self.pcap_filter = filter_trimmed(filter);
        self
    }

    /// Remove any configured libpcap BPF filter.
    pub fn clear_filter(mut self) -> Self {
        self.pcap_filter = None;
        self
    }

    /// Configured libpcap BPF filter, if any.
    pub fn pcap_filter(&self) -> Option<&str> {
        self.pcap_filter.as_deref()
    }

    /// Set the libpcap read timeout for live pcap interface sources.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.pcap_timeout = Some(timeout);
        self
    }

    /// Disable the libpcap read timeout for live pcap interface sources.
    pub fn no_timeout(mut self) -> Self {
        self.pcap_timeout = None;
        self
    }

    /// Configured live pcap interface read timeout.
    pub const fn pcap_timeout(&self) -> Option<Duration> {
        self.pcap_timeout
    }

    /// Set the snapshot length for live pcap interface capture.
    pub const fn snaplen(mut self, snaplen: u32) -> Self {
        self.pcap_snaplen = snaplen;
        self
    }

    /// Configured live pcap interface snapshot length.
    pub const fn pcap_snaplen(&self) -> u32 {
        self.pcap_snaplen
    }

    /// Enable or disable promiscuous mode for live pcap interface capture.
    pub const fn promisc(mut self, promisc: bool) -> Self {
        self.pcap_promisc = promisc;
        self
    }

    /// Whether live pcap interface promiscuous mode is enabled.
    pub const fn pcap_promisc(&self) -> bool {
        self.pcap_promisc
    }

    /// Enable or disable immediate mode for live pcap interface capture.
    pub const fn immediate_mode(mut self, immediate: bool) -> Self {
        self.pcap_immediate = immediate;
        self
    }

    /// Whether live pcap interface immediate mode is enabled.
    pub const fn pcap_immediate_mode(&self) -> bool {
        self.pcap_immediate
    }

    /// Enable or disable nonblocking reads for live pcap interface capture.
    pub const fn nonblocking(mut self, nonblocking: bool) -> Self {
        self.pcap_nonblocking = nonblocking;
        self
    }

    /// Enable nonblocking reads for live pcap interface capture.
    pub const fn nonblock(self) -> Self {
        self.nonblocking(true)
    }

    /// Whether live pcap interface nonblocking reads are enabled.
    pub const fn pcap_nonblocking(&self) -> bool {
        self.pcap_nonblocking
    }

    /// Open this target as one packet wire.
    pub fn open(mut self) -> Result<PacketWire> {
        if self.source.is_none() {
            match &self.target {
                PacketWireTarget::PcapFile { path } => {
                    self.source = Some(Box::new(OfflinePcapSource::open_with_optional_filter(
                        path,
                        self.pcap_filter.as_deref(),
                    )?));
                }
                PacketWireTarget::PcapInterface { interface } => {
                    let mut builder = PcapInterfaceSource::builder(interface.clone())
                        .snaplen(self.pcap_snaplen)
                        .promisc(self.pcap_promisc)
                        .immediate_mode(self.pcap_immediate)
                        .nonblocking(self.pcap_nonblocking);
                    if let Some(timeout) = self.pcap_timeout {
                        builder = builder.timeout(timeout);
                    } else {
                        builder = builder.no_timeout();
                    }
                    if let Some(filter) = self.pcap_filter.as_deref() {
                        builder = builder.filter(filter);
                    }
                    self.source = Some(Box::new(builder.open()?));
                }
                PacketWireTarget::PcapRecorder { .. } => {}
                PacketWireTarget::RawSocketInterface { .. } => {}
            }
        }

        if self.writer.is_none() {
            match &self.target {
                PacketWireTarget::PcapRecorder { path, link_type } => {
                    self.writer = Some(Box::new(PcapFileWriter::create(path, *link_type)?));
                }
                PacketWireTarget::PcapInterface { interface } => {
                    let mut builder = PcapInterfaceWriter::builder(interface.clone())
                        .snaplen(self.pcap_snaplen)
                        .promisc(self.pcap_promisc)
                        .immediate_mode(self.pcap_immediate)
                        .nonblocking(self.pcap_nonblocking);
                    if let Some(timeout) = self.pcap_timeout {
                        builder = builder.timeout(timeout);
                    } else {
                        builder = builder.no_timeout();
                    }
                    self.writer = Some(Box::new(builder.open()?));
                }
                PacketWireTarget::PcapFile { .. } => {}
                PacketWireTarget::RawSocketInterface { .. } => {}
            }
        }

        Ok(PacketWire {
            target: self.target,
            source: self.source,
            writer: self.writer,
        })
    }

    #[cfg(test)]
    fn with_source(mut self, source: impl PacketSource + Send + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    #[cfg(test)]
    fn with_writer(mut self, writer: impl PacketWriter + Send + 'static) -> Self {
        self.writer = Some(Box::new(writer));
        self
    }
}

/// Builder for a write-only raw socket packet wire.
///
/// This builder is intentionally separate from [`PacketWireBuilder`] because a
/// raw socket writer adapts [`SocketSender`](crate::net::SocketSender), not a
/// libpcap capture handle. It defaults to dry-run send planning so the packet
/// wire API keeps offline behavior as the default; call [`Self::live`] to opt
/// in to live raw socket transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSocketWireBuilder {
    options: SendOptions,
}

impl RawSocketWireBuilder {
    fn new(interface: impl Into<String>) -> Self {
        Self {
            options: SendOptions::new().interface(interface).dry_run(),
        }
    }

    /// Borrow the send options this raw socket writer will use.
    pub const fn options(&self) -> &SendOptions {
        &self.options
    }

    /// Interface selected for raw socket send planning and live send.
    pub fn interface(&self) -> Option<&str> {
        self.options.interface_name()
    }

    /// Set the raw socket send mode.
    pub fn mode(mut self, mode: SendMode) -> Self {
        self.options = self.options.mode(mode);
        self
    }

    /// Require a link-layer raw socket send plan.
    pub fn link_layer(self) -> Self {
        self.mode(SendMode::LinkLayer)
    }

    /// Require a network-layer raw socket send plan.
    pub fn network_layer(self) -> Self {
        self.mode(SendMode::NetworkLayer)
    }

    /// Compile and plan records without transmitting bytes.
    pub fn dry_run(mut self) -> Self {
        self.options = self.options.dry_run();
        self
    }

    /// Opt in to live raw socket transmission.
    pub fn live(mut self) -> Self {
        self.options = self.options.live();
        self
    }

    /// Set the raw socket write timeout hint.
    pub fn write_timeout(mut self, timeout: Duration) -> Self {
        self.options = self.options.write_timeout(timeout);
        self
    }

    /// Clear the raw socket write timeout hint.
    pub fn no_write_timeout(mut self) -> Self {
        self.options = self.options.no_write_timeout();
        self
    }

    /// Set the raw socket write buffer size hint.
    pub fn write_buffer_size(mut self, size: usize) -> Self {
        self.options = self.options.write_buffer_size(size);
        self
    }

    /// Open this write-only raw socket target as one packet wire.
    pub fn open(self) -> Result<PacketWire> {
        let interface = validated_interface(&self.options)?;
        let writer = RawSocketWriter::new(self.options);

        Ok(PacketWire {
            target: PacketWireTarget::RawSocketInterface { interface },
            source: None,
            writer: Some(Box::new(writer)),
        })
    }
}

impl fmt::Debug for PacketWireBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketWireBuilder")
            .field("target", &self.target)
            .field("pcap_filter", &self.pcap_filter)
            .field("pcap_timeout", &self.pcap_timeout)
            .field("pcap_snaplen", &self.pcap_snaplen)
            .field("pcap_promisc", &self.pcap_promisc)
            .field("pcap_immediate", &self.pcap_immediate)
            .field("pcap_nonblocking", &self.pcap_nonblocking)
            .field("has_source", &self.source.is_some())
            .field("has_writer", &self.writer.is_some())
            .finish()
    }
}

/// One opened packet-capable backend or interface.
///
/// `PacketWire` is a capability handle, not a multiplexer. Consuming
/// [`source`](Self::source), [`writer`](Self::writer), or [`split`](Self::split)
/// moves the backend into the caller's pipeline. Unsupported directions return
/// typed errors, for example trying to read from a pcap recorder or write to a
/// read-only pcap file input.
pub struct PacketWire {
    target: PacketWireTarget,
    source: Option<OpenedPacketSource>,
    writer: Option<OpenedPacketWriter>,
}

impl PacketWire {
    /// Build an offline pcap file input target.
    pub fn pcap_file(path: impl Into<PathBuf>) -> PacketWireBuilder {
        PacketWireBuilder::new(PacketWireTarget::PcapFile { path: path.into() })
    }

    /// Build an offline pcap file recorder target.
    pub fn pcap_recorder(
        path: impl Into<PathBuf>,
        link_type: impl Into<PcapLinkType>,
    ) -> PacketWireBuilder {
        PacketWireBuilder::new(PacketWireTarget::PcapRecorder {
            path: path.into(),
            link_type: link_type.into(),
        })
    }

    /// Build a live pcap interface target.
    pub fn pcap_interface(interface: impl Into<String>) -> PacketWireBuilder {
        PacketWireBuilder::new(PacketWireTarget::PcapInterface {
            interface: interface.into(),
        })
    }

    /// Build a write-only raw socket interface target.
    ///
    /// This constructor is distinct from [`Self::pcap_interface`] because the
    /// raw socket path wraps [`SocketSender`](crate::net::SocketSender) and
    /// preserves its send-mode validation, dry-run plans, and live-send gates.
    /// It defaults to dry-run planning; call
    /// [`RawSocketWireBuilder::live`] to explicitly opt in to live raw socket
    /// transmission. Unsupported radiotap injection remains a `SocketSender`
    /// validation error rather than being rerouted through raw socket behavior.
    pub fn raw_socket_interface(interface: impl Into<String>) -> RawSocketWireBuilder {
        RawSocketWireBuilder::new(interface)
    }

    /// Inspect the single backend or interface opened by this wire.
    pub const fn target(&self) -> &PacketWireTarget {
        &self.target
    }

    /// Whether this opened wire currently has packet-source capability.
    pub const fn has_source(&self) -> bool {
        self.source.is_some()
    }

    /// Whether this opened wire currently has packet-writer capability.
    pub const fn has_writer(&self) -> bool {
        self.writer.is_some()
    }

    /// Consume this wire and return its packet source.
    pub fn source(self) -> Result<OpenedPacketSource> {
        let Self { target, source, .. } = self;
        source.ok_or_else(|| unsupported_source(&target))
    }

    /// Consume this wire and return its packet writer.
    pub fn writer(self) -> Result<OpenedPacketWriter> {
        let Self { target, writer, .. } = self;
        writer.ok_or_else(|| unsupported_writer(&target))
    }

    /// Consume this wire and return both packet source and writer capabilities.
    pub fn split(self) -> Result<(OpenedPacketSource, OpenedPacketWriter)> {
        let Self {
            target,
            source,
            writer,
        } = self;

        match (source, writer) {
            (Some(source), Some(writer)) => Ok((source, writer)),
            (source, writer) => Err(unsupported_split(
                &target,
                source.is_some(),
                writer.is_some(),
            )),
        }
    }
}

impl fmt::Debug for PacketWire {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketWire")
            .field("target", &self.target)
            .field("has_source", &self.source.is_some())
            .field("has_writer", &self.writer.is_some())
            .finish()
    }
}

fn unsupported_source(target: &PacketWireTarget) -> WireError {
    WireError::unsupported_capability(
        "read",
        Some(target.backend_identifier()),
        unsupported_source_reason(target),
    )
}

fn unsupported_source_reason(target: &PacketWireTarget) -> &'static str {
    match target {
        PacketWireTarget::PcapRecorder { .. } => {
            "pcap recorder targets are write-only; use pcap_file for pcap input"
        }
        PacketWireTarget::RawSocketInterface { .. } => {
            "raw socket interface targets are write-only; use pcap_interface for capture"
        }
        PacketWireTarget::PcapFile { .. } | PacketWireTarget::PcapInterface { .. } => {
            "no packet source has been opened for this wire"
        }
    }
}

fn unsupported_writer(target: &PacketWireTarget) -> WireError {
    WireError::unsupported_capability(
        "write",
        Some(target.backend_identifier()),
        unsupported_writer_reason(target),
    )
}

fn unsupported_writer_reason(target: &PacketWireTarget) -> &'static str {
    match target {
        PacketWireTarget::PcapFile { .. } => {
            "pcap file targets are read-only; use pcap_recorder for pcap output"
        }
        PacketWireTarget::PcapRecorder { .. }
        | PacketWireTarget::PcapInterface { .. }
        | PacketWireTarget::RawSocketInterface { .. } => {
            "no packet writer has been opened for this wire"
        }
    }
}

fn unsupported_split(target: &PacketWireTarget, has_source: bool, has_writer: bool) -> WireError {
    let reason = match (has_source, has_writer) {
        (false, false) => "source and writer capabilities are not both available",
        (false, true) => unsupported_source_reason(target),
        (true, false) => unsupported_writer_reason(target),
        (true, true) => unreachable!("split is only unsupported when a capability is missing"),
    };
    WireError::unsupported_capability("split", Some(target.backend_identifier()), reason)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::super::record::{BackendKind, PacketRecord};
    use super::super::source::VecPacketSource;
    use super::super::writer::MemoryPacketWriter;
    use super::*;
    use crate::{LinkType, PcapWriter, Raw};

    static NEXT_TEMP_PCAP: AtomicUsize = AtomicUsize::new(0);

    struct TempPcap {
        path: PathBuf,
    }

    impl Drop for TempPcap {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn empty_temp_pcap(name: &str) -> TempPcap {
        let path = std::env::temp_dir().join(format!(
            "packet-wire-{name}-{}-{}.pcap",
            std::process::id(),
            NEXT_TEMP_PCAP.fetch_add(1, Ordering::Relaxed)
        ));
        {
            let mut writer = PcapWriter::create(&path, LinkType::Ethernet).unwrap();
            writer.flush().unwrap();
        }
        TempPcap { path }
    }

    #[test]
    fn pcap_file_builder_records_one_file_target() {
        let temp = empty_temp_pcap("input");
        let builder = PacketWire::pcap_file(&temp.path);

        assert_eq!(
            builder.target(),
            &PacketWireTarget::PcapFile {
                path: temp.path.clone()
            }
        );

        let wire = builder.open().unwrap();
        assert_eq!(wire.target().path(), Some(temp.path.as_path()));
        assert_eq!(wire.target().interface(), None);
        assert!(wire.has_source());
        assert!(!wire.has_writer());
    }

    #[test]
    fn pcap_recorder_builder_records_output_link_type() {
        let builder = PacketWire::pcap_recorder("artifacts/out.pcap", LinkType::Ethernet);

        assert_eq!(
            builder.target(),
            &PacketWireTarget::PcapRecorder {
                path: PathBuf::from("artifacts/out.pcap"),
                link_type: PcapLinkType::Ethernet,
            }
        );
        assert_eq!(
            builder.target().pcap_link_type(),
            Some(PcapLinkType::Ethernet)
        );
    }

    #[test]
    fn pcap_interface_builder_records_one_interface_target() {
        let builder = PacketWire::pcap_interface("wlan0mon");

        assert_eq!(
            builder.target(),
            &PacketWireTarget::PcapInterface {
                interface: "wlan0mon".to_string()
            }
        );

        let wire = builder
            .with_source(VecPacketSource::empty())
            .with_writer(MemoryPacketWriter::new())
            .open()
            .unwrap();
        assert_eq!(wire.target().interface(), Some("wlan0mon"));
        assert_eq!(wire.target().path(), None);
    }

    #[test]
    fn unsupported_source_returns_typed_capability_error() {
        let temp = empty_temp_pcap("source-unsupported");

        assert_unsupported(
            PacketWire::pcap_recorder(&temp.path, LinkType::Ethernet)
                .open()
                .unwrap()
                .source(),
            "read",
            &format!("pcap-recorder:{}", temp.path.display()),
            "pcap recorder targets are write-only; use pcap_file for pcap input",
        );
    }

    #[test]
    fn unsupported_writer_returns_typed_capability_error() {
        let temp = empty_temp_pcap("writer-unsupported");
        assert_unsupported(
            PacketWire::pcap_file(&temp.path).open().unwrap().writer(),
            "write",
            &format!("pcap-file:{}", temp.path.display()),
            "pcap file targets are read-only; use pcap_recorder for pcap output",
        );
    }

    #[test]
    fn pcap_file_split_reports_read_only_capability() {
        let temp = empty_temp_pcap("split-unsupported");

        assert_unsupported(
            PacketWire::pcap_file(&temp.path).open().unwrap().split(),
            "split",
            &format!("pcap-file:{}", temp.path.display()),
            "pcap file targets are read-only; use pcap_recorder for pcap output",
        );
    }

    #[test]
    fn pcap_recorder_split_reports_write_only_capability() {
        let temp = empty_temp_pcap("split-recorder-unsupported");

        let wire = PacketWire::pcap_recorder(&temp.path, LinkType::Ethernet)
            .open()
            .unwrap();
        assert!(!wire.has_source());
        assert!(wire.has_writer());

        assert_unsupported(
            wire.split(),
            "split",
            &format!("pcap-recorder:{}", temp.path.display()),
            "pcap recorder targets are write-only; use pcap_file for pcap input",
        );
    }

    #[test]
    fn source_returns_opened_packet_source() {
        let mut source = PacketWire::pcap_file("input.pcap")
            .with_source(VecPacketSource::from_packets([Raw::from("packet")]))
            .open()
            .unwrap()
            .source()
            .unwrap();

        let record = source.next_record().unwrap().unwrap();
        assert_eq!(record.packet().summary(), "Raw(len=6)");
        assert!(source.next_record().unwrap().is_none());
    }

    #[test]
    fn writer_returns_opened_packet_writer() {
        let mut writer = PacketWire::pcap_recorder("out.pcap", LinkType::Ethernet)
            .with_writer(MemoryPacketWriter::dry_run())
            .open()
            .unwrap()
            .writer()
            .unwrap();

        let report = writer
            .write_record(
                &PacketRecord::new(Raw::from("payload")).with_backend(BackendKind::Memory),
            )
            .unwrap();

        assert_eq!(report.backend(), &BackendKind::Memory);
        assert_eq!(report.bytes_written(), 7);
        assert!(report.is_dry_run());
    }

    #[test]
    fn split_returns_opened_source_and_writer() {
        let (mut source, mut writer) = PacketWire::pcap_interface("eth0")
            .with_source(VecPacketSource::from_packets([Raw::from("rx")]))
            .with_writer(MemoryPacketWriter::new())
            .open()
            .unwrap()
            .split()
            .unwrap();

        let record = source.next_record().unwrap().unwrap();
        assert_eq!(record.packet().summary(), "Raw(len=2)");

        let report = writer
            .write_record(&PacketRecord::new(Raw::from("tx")))
            .unwrap();
        assert_eq!(report.bytes_written(), 2);
    }

    fn assert_unsupported<T>(
        result: Result<T>,
        capability: &'static str,
        backend: &str,
        expected_reason: &'static str,
    ) {
        let err = match result {
            Ok(_) => panic!("expected unsupported capability error"),
            Err(err) => err,
        };

        match err {
            WireError::UnsupportedCapability {
                capability: actual_capability,
                backend: Some(actual_backend),
                reason,
            } => {
                assert_eq!(actual_capability, capability);
                assert_eq!(actual_backend, backend);
                assert_eq!(reason, expected_reason);
            }
            other => panic!("expected unsupported capability error, got {other:?}"),
        }
    }
}
