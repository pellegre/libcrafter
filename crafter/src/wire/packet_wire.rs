//! Opened packet wire abstraction.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::pcap::PcapLinkType;

use super::backend::pcap::OfflinePcapSource;
use super::source::PacketSource;
use super::writer::PacketWriter;
use super::{Result, WireError};

/// Boxed packet source returned by an opened packet wire.
pub type OpenedPacketSource = Box<dyn PacketSource + Send>;

/// Boxed packet writer returned by an opened packet wire.
pub type OpenedPacketWriter = Box<dyn PacketWriter + Send>;

/// One packet-capable backend or interface target.
///
/// A target describes exactly one pcap file, pcap recorder, or live interface.
/// Applications that need multiple media should create multiple
/// [`PacketWire`] values and orchestrate them outside the crate.
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
}

impl PacketWireTarget {
    /// Return the pcap file path when this target is file-backed.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::PcapFile { path } | Self::PcapRecorder { path, .. } => Some(path.as_path()),
            Self::PcapInterface { .. } => None,
        }
    }

    /// Return the interface name when this target is interface-backed.
    pub fn interface(&self) -> Option<&str> {
        match self {
            Self::PcapInterface { interface } => Some(interface),
            Self::PcapFile { .. } | Self::PcapRecorder { .. } => None,
        }
    }

    /// Return the pcap link type configured for recorder targets.
    pub const fn pcap_link_type(&self) -> Option<PcapLinkType> {
        match self {
            Self::PcapRecorder { link_type, .. } => Some(*link_type),
            Self::PcapFile { .. } | Self::PcapInterface { .. } => None,
        }
    }

    fn backend_identifier(&self) -> String {
        match self {
            Self::PcapFile { path } => format!("pcap-file:{}", path.display()),
            Self::PcapRecorder { path, .. } => format!("pcap-recorder:{}", path.display()),
            Self::PcapInterface { interface } => format!("pcap-interface:{interface}"),
        }
    }
}

/// Builder for one packet wire target.
///
/// The builder records which backend or interface should be opened. Backend
/// adapters attach concrete source and writer capabilities during `open`; until
/// those adapters are wired in, unsupported operations fail as typed
/// [`WireError::UnsupportedCapability`] values.
pub struct PacketWireBuilder {
    target: PacketWireTarget,
    pcap_filter: Option<String>,
    source: Option<OpenedPacketSource>,
    writer: Option<OpenedPacketWriter>,
}

impl PacketWireBuilder {
    fn new(target: PacketWireTarget) -> Self {
        Self {
            target,
            pcap_filter: None,
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
        self.pcap_filter = Some(filter.into());
        self
    }

    /// Configured libpcap BPF filter, if any.
    pub fn pcap_filter(&self) -> Option<&str> {
        self.pcap_filter.as_deref()
    }

    /// Open this target as one packet wire.
    pub fn open(mut self) -> Result<PacketWire> {
        if self.source.is_none() {
            if let PacketWireTarget::PcapFile { path } = &self.target {
                self.source = Some(Box::new(OfflinePcapSource::open_with_optional_filter(
                    path,
                    self.pcap_filter.as_deref(),
                )?));
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

impl fmt::Debug for PacketWireBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketWireBuilder")
            .field("target", &self.target)
            .field("pcap_filter", &self.pcap_filter)
            .field("has_source", &self.source.is_some())
            .field("has_writer", &self.writer.is_some())
            .finish()
    }
}

/// One opened packet-capable backend or interface.
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
    let reason = match target {
        PacketWireTarget::PcapRecorder { .. } => {
            "pcap recorder targets are write-only; use pcap_file for pcap input"
        }
        PacketWireTarget::PcapFile { .. } | PacketWireTarget::PcapInterface { .. } => {
            "no packet source has been opened for this wire"
        }
    };
    WireError::unsupported_capability("read", Some(target.backend_identifier()), reason)
}

fn unsupported_writer(target: &PacketWireTarget) -> WireError {
    let reason = match target {
        PacketWireTarget::PcapFile { .. } => {
            "pcap file targets are read-only; use pcap_recorder for pcap output"
        }
        PacketWireTarget::PcapRecorder { .. } | PacketWireTarget::PcapInterface { .. } => {
            "no packet writer has been opened for this wire"
        }
    };
    WireError::unsupported_capability("write", Some(target.backend_identifier()), reason)
}

fn unsupported_split(target: &PacketWireTarget, has_source: bool, has_writer: bool) -> WireError {
    let reason = match (has_source, has_writer) {
        (false, false) => "source and writer capabilities are not both available",
        (false, true) => "source capability is not available",
        (true, false) => "writer capability is not available",
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

        let wire = builder.open().unwrap();
        assert_eq!(wire.target().interface(), Some("wlan0mon"));
        assert_eq!(wire.target().path(), None);
    }

    #[test]
    fn unsupported_source_returns_typed_capability_error() {
        assert_unsupported(
            PacketWire::pcap_recorder("out.pcap", LinkType::Ethernet)
                .open()
                .unwrap()
                .source(),
            "read",
            "pcap-recorder:out.pcap",
        );
    }

    #[test]
    fn unsupported_writer_returns_typed_capability_error() {
        let temp = empty_temp_pcap("writer-unsupported");
        assert_unsupported(
            PacketWire::pcap_file(&temp.path).open().unwrap().writer(),
            "write",
            &format!("pcap-file:{}", temp.path.display()),
        );
    }

    #[test]
    fn unsupported_split_reports_missing_capability() {
        assert_unsupported(
            PacketWire::pcap_interface("eth0")
                .with_source(VecPacketSource::empty())
                .open()
                .unwrap()
                .split(),
            "split",
            "pcap-interface:eth0",
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

    fn assert_unsupported<T>(result: Result<T>, capability: &'static str, backend: &str) {
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
                assert!(!reason.is_empty());
            }
            other => panic!("expected unsupported capability error, got {other:?}"),
        }
    }
}
