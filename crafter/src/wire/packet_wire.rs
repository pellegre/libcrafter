//! Packet wire builders and opened backend handles.
//!
//! A [`PacketWire`] represents exactly one packet-capable target: a pcap file,
//! pcap recorder, live pcap interface, or raw socket interface. It advertises
//! source and writer capabilities explicitly so callers can wire the opened
//! direction into [`crate::wire::Sniffer`] or [`crate::wire::Transmitter`].

#[cfg(feature = "whad")]
use std::collections::VecDeque;
use std::fmt;
use std::path::{Path, PathBuf};
#[cfg(feature = "whad")]
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::net::send::validated_interface;
use crate::net::{SendMode, SendOptions};
use crate::wire::backend::pcap::PcapLinkType;
use crate::wire::backend::whad::{WhadBleMode, WhadDot15d4Mode};

use super::backend::pcap::{
    filter_trimmed, OfflinePcapSource, PcapFileWriter, PcapInterfaceSource, PcapInterfaceWriter,
    DEFAULT_INTERFACE_IMMEDIATE, DEFAULT_INTERFACE_NONBLOCKING, DEFAULT_INTERFACE_PROMISC,
    DEFAULT_INTERFACE_SNAPLEN, DEFAULT_INTERFACE_TIMEOUT,
};
use super::backend::raw_socket::RawSocketWriter;
#[cfg(feature = "whad")]
use super::backend::whad::{
    capability::{enter_ble, enter_dot15d4},
    discovery::{discover, WhadDevice},
    messages::{WhadDeviceInfo, WhadDomainCommands, WhadDomains, WhadFirmwareVersion},
    proto,
    reader::WhadReader,
    transport::{SerialChannel, WhadByteChannel, WhadLink},
    writer::WhadWriter,
    WHAD_TARGET_PROTOCOL_VERSION,
};
use super::source::PacketSource;
use super::writer::PacketWriter;
use super::{Result, WireError};

#[cfg(not(feature = "whad"))]
const WHAD_FEATURE_DISABLED_REASON: &str =
    "the whad feature is disabled; enable the whad feature to open WHAD serial targets";
const WHAD_DEFAULT_BLE_CHANNEL: u8 = 37;

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

/// In-memory WHAD byte channel for feature-gated integration tests.
#[cfg(feature = "whad")]
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct WhadMockChannel {
    state: Arc<Mutex<WhadMockChannelState>>,
}

#[cfg(feature = "whad")]
#[derive(Default)]
struct WhadMockChannelState {
    inbound: VecDeque<u8>,
    written: Vec<u8>,
}

#[cfg(feature = "whad")]
impl WhadMockChannel {
    /// Create an empty mock WHAD channel.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue one complete framed WHAD message for later reads.
    pub fn queue_frame(&self, frame: impl AsRef<[u8]>) {
        self.state
            .lock()
            .expect("WHAD mock channel state poisoned")
            .inbound
            .extend(frame.as_ref().iter().copied());
    }

    /// Copy all bytes written by the backend so far.
    pub fn written_bytes(&self) -> Vec<u8> {
        self.state
            .lock()
            .expect("WHAD mock channel state poisoned")
            .written
            .clone()
    }

    /// Return and clear all bytes written by the backend so far.
    pub fn take_written_bytes(&self) -> Vec<u8> {
        std::mem::take(
            &mut self
                .state
                .lock()
                .expect("WHAD mock channel state poisoned")
                .written,
        )
    }
}

#[cfg(feature = "whad")]
impl fmt::Debug for WhadMockChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WhadMockChannel").finish_non_exhaustive()
    }
}

#[cfg(feature = "whad")]
impl PartialEq for WhadMockChannel {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}

#[cfg(feature = "whad")]
impl Eq for WhadMockChannel {}

#[cfg(feature = "whad")]
impl WhadByteChannel for WhadMockChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut state = self.state.lock().expect("WHAD mock channel state poisoned");
        let n = buf.len().min(state.inbound.len());
        for slot in &mut buf[..n] {
            *slot = state.inbound.pop_front().expect("mock byte disappeared");
        }
        Ok(n)
    }

    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.state
            .lock()
            .expect("WHAD mock channel state poisoned")
            .written
            .extend_from_slice(data);
        Ok(())
    }
}

/// Radio domain and operating mode requested for a WHAD serial target.
///
/// A WHAD dongle serves one radio domain at a time. This wraps the BLE and
/// 802.15.4 operating modes in a single value so a [`PacketWireTarget::WhadSerial`]
/// target carries exactly one mode while the `path`/`interface`/`pcap_link_type`/
/// capability matches stay exhaustive across both domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhadMode {
    /// Bluetooth Low Energy sniff or inject mode.
    Ble(WhadBleMode),
    /// IEEE 802.15.4 sniff or send mode.
    Dot15d4(WhadDot15d4Mode),
}

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
    /// WHAD-compatible serial dongle target for BLE or 802.15.4 sniff/inject.
    WhadSerial {
        /// Serial port path or name, for example `/dev/ttyACM0` or `COM3`.
        port: String,
        /// Radio domain and mode to enter after discovery.
        mode: WhadMode,
        /// Whether opening this target must avoid serial I/O and live WHAD control frames.
        dry_run: bool,
    },
}

impl PacketWireTarget {
    /// Return the pcap file path when this target is file-backed.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::PcapFile { path } | Self::PcapRecorder { path, .. } => Some(path.as_path()),
            Self::PcapInterface { .. }
            | Self::RawSocketInterface { .. }
            | Self::WhadSerial { .. } => None,
        }
    }

    /// Return the interface name when this target is interface-backed.
    pub fn interface(&self) -> Option<&str> {
        match self {
            Self::PcapInterface { interface } | Self::RawSocketInterface { interface } => {
                Some(interface.as_str())
            }
            Self::WhadSerial { port, .. } => Some(port.as_str()),
            Self::PcapFile { .. } | Self::PcapRecorder { .. } => None,
        }
    }

    /// Return the pcap link type configured for recorder targets.
    pub const fn pcap_link_type(&self) -> Option<PcapLinkType> {
        match self {
            Self::PcapRecorder { link_type, .. } => Some(*link_type),
            Self::PcapFile { .. }
            | Self::PcapInterface { .. }
            | Self::RawSocketInterface { .. }
            | Self::WhadSerial { .. } => None,
        }
    }

    fn backend_identifier(&self) -> String {
        match self {
            Self::PcapFile { path } => format!("pcap-file:{}", path.display()),
            Self::PcapRecorder { path, .. } => format!("pcap-recorder:{}", path.display()),
            Self::PcapInterface { interface } => format!("pcap-interface:{interface}"),
            Self::RawSocketInterface { interface } => format!("raw-socket:{interface}"),
            Self::WhadSerial { .. } => "whad".to_string(),
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
    whad_channel: u8,
    #[cfg(feature = "whad")]
    whad_mock_channel: Option<WhadMockChannel>,
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
            whad_channel: WHAD_DEFAULT_BLE_CHANNEL,
            #[cfg(feature = "whad")]
            whad_mock_channel: None,
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
                PacketWireTarget::WhadSerial {
                    port,
                    mode,
                    dry_run,
                } => {
                    #[cfg(feature = "whad")]
                    {
                        self.source = open_whad_serial_source(
                            port,
                            *mode,
                            *dry_run,
                            self.whad_mock_channel.clone(),
                        )?;
                    }
                    #[cfg(not(feature = "whad"))]
                    {
                        self.source = open_whad_serial_source(port, *mode, *dry_run)?;
                    }
                }
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
                PacketWireTarget::WhadSerial {
                    port,
                    mode,
                    dry_run,
                } => {
                    #[cfg(feature = "whad")]
                    {
                        self.writer = open_whad_serial_writer(
                            port,
                            *mode,
                            *dry_run,
                            self.whad_channel,
                            self.whad_mock_channel.clone(),
                        )?;
                    }
                    #[cfg(not(feature = "whad"))]
                    {
                        self.writer =
                            open_whad_serial_writer(port, *mode, *dry_run, self.whad_channel)?;
                    }
                }
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

    fn whad_channel(mut self, channel: u8) -> Self {
        self.whad_channel = channel;
        self
    }

    #[cfg(feature = "whad")]
    fn whad_mock_channel(mut self, channel: WhadMockChannel) -> Self {
        self.whad_mock_channel = Some(channel);
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

/// Builder for a WHAD-compatible BLE serial packet wire.
///
/// WHAD devices are live serial endpoints, so this builder defaults to a
/// dry-run capability handle that records the requested port and BLE mode
/// without opening the serial port or sending WHAD control frames. Call
/// [`Self::live`] to explicitly opt in to serial discovery and BLE mode entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhadWireBuilder {
    port: String,
    mode: WhadBleMode,
    dot15d4_mode: Option<WhadDot15d4Mode>,
    channel: u8,
    live: bool,
    #[cfg(feature = "whad")]
    mock_channel: Option<WhadMockChannel>,
}

impl WhadWireBuilder {
    fn new(port: impl Into<String>) -> Self {
        Self {
            port: port.into(),
            mode: WhadBleMode::SniffAdv {
                channel: WHAD_DEFAULT_BLE_CHANNEL,
            },
            dot15d4_mode: None,
            channel: WHAD_DEFAULT_BLE_CHANNEL,
            live: false,
            #[cfg(feature = "whad")]
            mock_channel: None,
        }
    }

    /// Serial port path or name selected for WHAD discovery and live traffic.
    pub fn port(&self) -> &str {
        self.port.as_str()
    }

    /// BLE mode this builder will request when opened live.
    ///
    /// This reports the BLE mode only. When an 802.15.4 mode has been selected
    /// with [`Self::dot15d4_sniff`] or [`Self::dot15d4_send`], inspect
    /// [`Self::dot15d4_mode`] or the opened [`PacketWireTarget::WhadSerial`]
    /// `mode` instead.
    pub const fn mode(&self) -> WhadBleMode {
        self.mode
    }

    /// 802.15.4 mode this builder will request when opened live, if any.
    pub const fn dot15d4_mode(&self) -> Option<WhadDot15d4Mode> {
        self.dot15d4_mode
    }

    /// Radio domain and mode this builder will request when opened live.
    pub const fn whad_mode(&self) -> WhadMode {
        match self.dot15d4_mode {
            Some(mode) => WhadMode::Dot15d4(mode),
            None => WhadMode::Ble(self.mode),
        }
    }

    /// Whether this builder will open the WHAD serial port.
    pub const fn is_live(&self) -> bool {
        self.live
    }

    /// Whether this builder will avoid serial I/O and live WHAD control frames.
    pub const fn is_dry_run(&self) -> bool {
        !self.live
    }

    /// Capture BLE advertising PDUs on the selected advertising channel.
    pub const fn ble_sniff(mut self, channel: u8) -> Self {
        self.channel = channel;
        self.mode = WhadBleMode::SniffAdv { channel };
        self.dot15d4_mode = None;
        self
    }

    /// Inject BLE raw PDUs through WHAD's central/raw-PDU path.
    pub const fn ble_inject(mut self) -> Self {
        self.mode = WhadBleMode::Inject;
        self.dot15d4_mode = None;
        self
    }

    /// Capture IEEE 802.15.4 frames on the selected channel.
    ///
    /// This is a read-only source mode, mirroring [`Self::ble_sniff`]: the
    /// opened wire exposes a [`PacketWire::source`] but no writer.
    pub const fn dot15d4_sniff(mut self, channel: u8) -> Self {
        self.channel = channel;
        self.dot15d4_mode = Some(WhadDot15d4Mode::Sniff { channel });
        self
    }

    /// Inject IEEE 802.15.4 frames through WHAD's send/raw-send path.
    ///
    /// This is a write-only writer mode, mirroring [`Self::ble_inject`]: the
    /// opened wire exposes a [`PacketWire::writer`] but no source.
    pub const fn dot15d4_send(mut self) -> Self {
        self.dot15d4_mode = Some(WhadDot15d4Mode::Send);
        self
    }

    /// Set the channel used by sniff mode and inject/send fallback writes.
    ///
    /// Updates the selected sniff channel for whichever domain is active: the
    /// BLE advertising sniff channel, or the 802.15.4 sniff channel.
    pub const fn channel(mut self, channel: u8) -> Self {
        self.channel = channel;
        if let Some(WhadDot15d4Mode::Sniff { .. }) = self.dot15d4_mode {
            self.dot15d4_mode = Some(WhadDot15d4Mode::Sniff { channel });
        } else if let WhadBleMode::SniffAdv { .. } = self.mode {
            self.mode = WhadBleMode::SniffAdv { channel };
        }
        self
    }

    /// Keep this WHAD target offline.
    pub const fn dry_run(mut self) -> Self {
        self.live = false;
        self
    }

    /// Opt in to live WHAD serial discovery, mode entry, and packet I/O.
    pub const fn live(mut self) -> Self {
        self.live = true;
        self
    }

    /// Use an in-memory WHAD byte channel instead of opening a serial port.
    #[cfg(feature = "whad")]
    #[doc(hidden)]
    pub fn with_mock_channel(mut self, channel: WhadMockChannel) -> Self {
        self.mock_channel = Some(channel);
        self
    }

    /// Open this WHAD serial target as one packet wire.
    pub fn open(self) -> Result<PacketWire> {
        self.into_packet_wire_builder().open()
    }

    fn into_packet_wire_builder(self) -> PacketWireBuilder {
        let mode = match self.dot15d4_mode {
            Some(mode) => WhadMode::Dot15d4(mode),
            None => WhadMode::Ble(self.mode),
        };
        let builder = PacketWireBuilder::new(PacketWireTarget::WhadSerial {
            port: self.port,
            mode,
            dry_run: !self.live,
        })
        .whad_channel(self.channel);

        #[cfg(feature = "whad")]
        {
            if let Some(channel) = self.mock_channel {
                return builder.whad_mock_channel(channel);
            }
        }

        builder
    }

    #[cfg(all(test, feature = "whad"))]
    fn with_source(self, source: impl PacketSource + Send + 'static) -> PacketWireBuilder {
        self.into_packet_wire_builder().with_source(source)
    }

    #[cfg(all(test, feature = "whad"))]
    fn with_writer(self, writer: impl PacketWriter + Send + 'static) -> PacketWireBuilder {
        self.into_packet_wire_builder().with_writer(writer)
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
            .field("whad_channel", &self.whad_channel)
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

    /// Build a WHAD-compatible BLE serial target.
    ///
    /// This constructor defaults to dry-run mode so opening the returned
    /// builder does not touch the serial port. Call [`WhadWireBuilder::live`]
    /// to explicitly opt in to WHAD serial discovery, BLE mode entry, and
    /// packet I/O.
    pub fn whad_serial(port: impl Into<String>) -> WhadWireBuilder {
        WhadWireBuilder::new(port)
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
        PacketWireTarget::WhadSerial {
            mode: WhadMode::Ble(WhadBleMode::Inject),
            ..
        } => "WHAD serial inject targets are write-only; use SniffAdv mode for capture",
        PacketWireTarget::WhadSerial {
            mode: WhadMode::Dot15d4(WhadDot15d4Mode::Send),
            ..
        } => "WHAD serial 802.15.4 send targets are write-only; use Sniff mode for capture",
        PacketWireTarget::PcapFile { .. } | PacketWireTarget::PcapInterface { .. } => {
            "no packet source has been opened for this wire"
        }
        PacketWireTarget::WhadSerial {
            mode: WhadMode::Ble(WhadBleMode::SniffAdv { .. }),
            ..
        } => "no WHAD packet source has been opened for this wire",
        PacketWireTarget::WhadSerial {
            mode: WhadMode::Dot15d4(WhadDot15d4Mode::Sniff { .. }),
            ..
        } => "no WHAD packet source has been opened for this wire",
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
        PacketWireTarget::WhadSerial {
            mode: WhadMode::Ble(WhadBleMode::SniffAdv { .. }),
            ..
        } => "WHAD serial advertising sniff targets are read-only; use Inject mode for writing",
        PacketWireTarget::WhadSerial {
            mode: WhadMode::Dot15d4(WhadDot15d4Mode::Sniff { .. }),
            ..
        } => "WHAD serial 802.15.4 sniff targets are read-only; use Send mode for writing",
        PacketWireTarget::WhadSerial {
            mode: WhadMode::Ble(WhadBleMode::Inject),
            ..
        } => "no WHAD packet writer has been opened for this wire",
        PacketWireTarget::WhadSerial {
            mode: WhadMode::Dot15d4(WhadDot15d4Mode::Send),
            ..
        } => "no WHAD packet writer has been opened for this wire",
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

#[cfg(feature = "whad")]
fn open_whad_serial_source(
    port: &str,
    mode: WhadMode,
    dry_run: bool,
    mock_channel: Option<WhadMockChannel>,
) -> Result<Option<OpenedPacketSource>> {
    if dry_run {
        return Ok(None);
    }

    // Sniff (BLE advertising or 802.15.4) is the only read-only source mode;
    // inject/send modes expose a writer, not a source. The WHAD reader is
    // domain-agnostic (it routes received frames by their notification kind),
    // so the source open path only needs to enter the right sniff mode.
    let is_sniff = matches!(
        mode,
        WhadMode::Ble(WhadBleMode::SniffAdv { .. })
            | WhadMode::Dot15d4(WhadDot15d4Mode::Sniff { .. })
    );
    if !is_sniff {
        return Ok(None);
    }

    if let Some(channel) = mock_channel {
        let (link, _) = open_whad_link_from_channel(channel, mode)?;
        Ok(Some(Box::new(WhadReader::new(link))))
    } else {
        let (link, _) = open_whad_serial_link(port, mode)?;
        Ok(Some(Box::new(WhadReader::new(link))))
    }
}

#[cfg(not(feature = "whad"))]
fn open_whad_serial_source(
    _port: &str,
    _mode: WhadMode,
    dry_run: bool,
) -> Result<Option<OpenedPacketSource>> {
    if dry_run {
        Ok(None)
    } else {
        Err(whad_feature_disabled())
    }
}

#[cfg(feature = "whad")]
fn open_whad_serial_writer(
    port: &str,
    mode: WhadMode,
    dry_run: bool,
    channel: u8,
    mock_channel: Option<WhadMockChannel>,
) -> Result<Option<OpenedPacketWriter>> {
    if dry_run {
        if let Some(mock_channel) = mock_channel {
            return Ok(Some(Box::new(WhadWriter::dry_run(
                WhadLink::new(mock_channel),
                dry_run_whad_device(),
                channel,
            ))));
        }
        return Ok(None);
    }

    // Inject (BLE) and send (802.15.4) are the write-only writer modes; sniff
    // modes expose a source, not a writer. The WHAD writer is domain-agnostic
    // (it routes records to the BLE or 802.15.4 send path by their layers), so
    // the writer open path only needs to enter the right inject/send mode.
    let is_writer = matches!(
        mode,
        WhadMode::Ble(WhadBleMode::Inject) | WhadMode::Dot15d4(WhadDot15d4Mode::Send)
    );
    if !is_writer {
        return Ok(None);
    }

    if let Some(mock_channel) = mock_channel {
        let (link, device) = open_whad_link_from_channel(mock_channel, mode)?;
        Ok(Some(Box::new(
            WhadWriter::new(link, device, channel).with_dry_run(dry_run),
        )))
    } else {
        let (link, device) = open_whad_serial_link(port, mode)?;
        Ok(Some(Box::new(
            WhadWriter::new(link, device, channel).with_dry_run(dry_run),
        )))
    }
}

#[cfg(not(feature = "whad"))]
fn open_whad_serial_writer(
    _port: &str,
    _mode: WhadMode,
    dry_run: bool,
    _channel: u8,
) -> Result<Option<OpenedPacketWriter>> {
    if dry_run {
        Ok(None)
    } else {
        Err(whad_feature_disabled())
    }
}

#[cfg(feature = "whad")]
fn open_whad_serial_link(
    port: &str,
    mode: WhadMode,
) -> Result<(WhadLink<SerialChannel>, WhadDevice)> {
    let channel = SerialChannel::open(port)?;
    open_whad_link_from_channel(channel, mode)
}

#[cfg(feature = "whad")]
fn open_whad_link_from_channel<C: WhadByteChannel>(
    channel: C,
    mode: WhadMode,
) -> Result<(WhadLink<C>, WhadDevice)> {
    let mut link = WhadLink::new(channel);
    let device = discover(&mut link)?;
    match mode {
        WhadMode::Ble(mode) => enter_ble(&mut link, &device, mode)?,
        WhadMode::Dot15d4(mode) => enter_dot15d4(&mut link, &device, mode)?,
    }
    Ok((link, device))
}

#[cfg(feature = "whad")]
fn dry_run_whad_device() -> WhadDevice {
    let ble_domain = proto::discovery::Domain::BtLe as u32;
    WhadDevice {
        info: WhadDeviceInfo {
            device_type: proto::discovery::DeviceType::Butterfly as u32,
            device_id: vec![0x10, 0x20, 0x30, 0x40],
            protocol_min_version: WHAD_TARGET_PROTOCOL_VERSION,
            max_speed: 1_000_000,
            firmware_author: "whad-dry-run".to_string(),
            firmware_url: "https://example.invalid/whad".to_string(),
            firmware_version: WhadFirmwareVersion {
                major: 0,
                minor: 0,
                revision: 0,
            },
            supported_domains: vec![ble_domain],
        },
        domains: WhadDomains {
            supported_domains: vec![ble_domain],
            commands: vec![WhadDomainCommands {
                domain: ble_domain,
                supported_commands: 0,
            }],
        },
    }
}

#[cfg(not(feature = "whad"))]
fn whad_feature_disabled() -> WireError {
    WireError::unsupported_capability("open", Some("whad"), WHAD_FEATURE_DISABLED_REASON)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::super::record::{BackendKind, PacketRecord};
    use super::super::source::VecPacketSource;
    use super::super::writer::MemoryPacketWriter;
    use super::*;
    use crate::wire::backend::pcap::PcapWriter;
    use crate::{LinkType, Raw};

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
    fn whad_serial_target_reports_port_and_backend_metadata() {
        let target = PacketWireTarget::WhadSerial {
            port: "/dev/ttyACM0".to_string(),
            mode: WhadMode::Ble(WhadBleMode::SniffAdv { channel: 37 }),
            dry_run: true,
        };

        assert_eq!(target.path(), None);
        assert_eq!(target.interface(), Some("/dev/ttyACM0"));
        assert_eq!(target.pcap_link_type(), None);
        assert_eq!(target.backend_identifier(), "whad");
    }

    #[cfg(not(feature = "whad"))]
    #[test]
    fn whad_serial_open_without_feature_returns_typed_capability_error() {
        assert_unsupported(
            PacketWireBuilder::new(PacketWireTarget::WhadSerial {
                port: "/dev/ttyACM0".to_string(),
                mode: WhadMode::Ble(WhadBleMode::Inject),
                dry_run: false,
            })
            .open(),
            "open",
            "whad",
            WHAD_FEATURE_DISABLED_REASON,
        );
    }

    #[cfg(all(test, feature = "whad"))]
    #[test]
    fn whad_builder_defaults_to_dry_run_without_opening_serial() {
        let builder = PacketWire::whad_serial("/dev/ttyACM0");

        assert_eq!(builder.port(), "/dev/ttyACM0");
        assert_eq!(builder.mode(), WhadBleMode::SniffAdv { channel: 37 });
        assert!(builder.is_dry_run());
        assert!(!builder.is_live());

        let wire = builder.open().unwrap();
        assert_eq!(
            wire.target(),
            &PacketWireTarget::WhadSerial {
                port: "/dev/ttyACM0".to_string(),
                mode: WhadMode::Ble(WhadBleMode::SniffAdv { channel: 37 }),
                dry_run: true,
            }
        );
        assert!(!wire.has_source());
        assert!(!wire.has_writer());
    }

    #[cfg(all(test, feature = "whad"))]
    #[test]
    fn whad_builder_live_flips_target_to_live_without_opening_in_dry_run_path() {
        let builder = PacketWire::whad_serial("/dev/ttyACM0").ble_inject().live();

        assert_eq!(builder.mode(), WhadBleMode::Inject);
        assert!(builder.is_live());
        assert!(!builder.is_dry_run());

        let target = PacketWireTarget::WhadSerial {
            port: builder.port().to_string(),
            mode: builder.whad_mode(),
            dry_run: builder.is_dry_run(),
        };

        assert_eq!(
            target,
            PacketWireTarget::WhadSerial {
                port: "/dev/ttyACM0".to_string(),
                mode: WhadMode::Ble(WhadBleMode::Inject),
                dry_run: false,
            }
        );
    }

    #[cfg(all(test, feature = "whad"))]
    #[test]
    fn whad_builder_channel_updates_sniff_mode_and_preserves_inject_mode() {
        let sniff = PacketWire::whad_serial("/dev/ttyACM0").channel(39);
        assert_eq!(sniff.mode(), WhadBleMode::SniffAdv { channel: 39 });

        let inject = PacketWire::whad_serial("/dev/ttyACM0")
            .ble_inject()
            .channel(38);
        assert_eq!(inject.mode(), WhadBleMode::Inject);
    }

    #[cfg(all(test, feature = "whad"))]
    #[test]
    fn whad_packetwire_sniff_source_returns_injected_source() {
        let mut source = PacketWire::whad_serial("/dev/ttyACM0")
            .ble_sniff(37)
            .with_source(VecPacketSource::from_packets([Raw::from("adv")]))
            .open()
            .unwrap()
            .source()
            .unwrap();

        let record = source.next_record().unwrap().unwrap();
        assert_eq!(record.packet().summary(), "Raw(len=3)");
        assert!(source.next_record().unwrap().is_none());
    }

    #[cfg(all(test, feature = "whad"))]
    #[test]
    fn whad_packetwire_inject_writer_returns_injected_writer() {
        let mut writer = PacketWire::whad_serial("/dev/ttyACM0")
            .ble_inject()
            .with_writer(MemoryPacketWriter::dry_run())
            .open()
            .unwrap()
            .writer()
            .unwrap();

        let report = writer
            .write_record(&PacketRecord::new(Raw::from("pdu")))
            .unwrap();

        assert_eq!(report.backend(), &BackendKind::Memory);
        assert_eq!(report.bytes_requested(), 3);
        assert!(report.is_dry_run());
    }

    #[cfg(all(test, feature = "whad"))]
    #[test]
    fn packetwire_dot15d4_sniff_builder_sets_sniff_target_and_mode() {
        let builder = PacketWire::whad_serial("/dev/ttyACM0").dot15d4_sniff(15);

        assert_eq!(
            builder.dot15d4_mode(),
            Some(WhadDot15d4Mode::Sniff { channel: 15 })
        );
        assert_eq!(
            builder.whad_mode(),
            WhadMode::Dot15d4(WhadDot15d4Mode::Sniff { channel: 15 })
        );
        assert!(builder.is_dry_run());

        let wire = builder.open().unwrap();
        assert_eq!(
            wire.target(),
            &PacketWireTarget::WhadSerial {
                port: "/dev/ttyACM0".to_string(),
                mode: WhadMode::Dot15d4(WhadDot15d4Mode::Sniff { channel: 15 }),
                dry_run: true,
            }
        );
        // Dry-run does not open the serial backend, so no capabilities attach.
        assert!(!wire.has_source());
        assert!(!wire.has_writer());
    }

    #[cfg(all(test, feature = "whad"))]
    #[test]
    fn packetwire_dot15d4_send_builder_sets_send_target_and_mode() {
        let builder = PacketWire::whad_serial("/dev/ttyACM0").dot15d4_send();

        assert_eq!(builder.dot15d4_mode(), Some(WhadDot15d4Mode::Send));
        assert_eq!(
            builder.whad_mode(),
            WhadMode::Dot15d4(WhadDot15d4Mode::Send)
        );

        let target = PacketWireTarget::WhadSerial {
            port: builder.port().to_string(),
            mode: builder.whad_mode(),
            dry_run: builder.is_dry_run(),
        };
        assert_eq!(
            target,
            PacketWireTarget::WhadSerial {
                port: "/dev/ttyACM0".to_string(),
                mode: WhadMode::Dot15d4(WhadDot15d4Mode::Send),
                dry_run: true,
            }
        );
    }

    #[cfg(all(test, feature = "whad"))]
    #[test]
    fn packetwire_dot15d4_live_flips_dry_run_off() {
        let builder = PacketWire::whad_serial("/dev/ttyACM0")
            .dot15d4_sniff(20)
            .live();

        assert!(builder.is_live());
        assert!(!builder.is_dry_run());
        assert_eq!(
            builder.whad_mode(),
            WhadMode::Dot15d4(WhadDot15d4Mode::Sniff { channel: 20 })
        );
    }

    #[cfg(all(test, feature = "whad"))]
    #[test]
    fn packetwire_dot15d4_channel_updates_sniff_and_preserves_send() {
        let sniff = PacketWire::whad_serial("/dev/ttyACM0")
            .dot15d4_sniff(11)
            .channel(26);
        assert_eq!(
            sniff.dot15d4_mode(),
            Some(WhadDot15d4Mode::Sniff { channel: 26 })
        );

        let send = PacketWire::whad_serial("/dev/ttyACM0")
            .dot15d4_send()
            .channel(26);
        assert_eq!(send.dot15d4_mode(), Some(WhadDot15d4Mode::Send));
    }

    #[cfg(all(test, feature = "whad"))]
    #[test]
    fn packetwire_dot15d4_sniff_source_returns_injected_source() {
        // Sniff is read-only: the source/writer split exposes a source.
        let mut source = PacketWire::whad_serial("/dev/ttyACM0")
            .dot15d4_sniff(15)
            .with_source(VecPacketSource::from_packets([Raw::from("mac")]))
            .open()
            .unwrap()
            .source()
            .unwrap();

        let record = source.next_record().unwrap().unwrap();
        assert_eq!(record.packet().summary(), "Raw(len=3)");
        assert!(source.next_record().unwrap().is_none());
    }

    #[cfg(all(test, feature = "whad"))]
    #[test]
    fn packetwire_dot15d4_send_writer_returns_injected_writer() {
        // Send is write-only: the source/writer split exposes a writer.
        let mut writer = PacketWire::whad_serial("/dev/ttyACM0")
            .dot15d4_send()
            .with_writer(MemoryPacketWriter::dry_run())
            .open()
            .unwrap()
            .writer()
            .unwrap();

        let report = writer
            .write_record(&PacketRecord::new(Raw::from("pdu")))
            .unwrap();

        assert_eq!(report.backend(), &BackendKind::Memory);
        assert_eq!(report.bytes_requested(), 3);
        assert!(report.is_dry_run());
    }

    #[cfg(all(test, feature = "whad"))]
    #[test]
    fn packetwire_dot15d4_sniff_target_is_read_only_for_writer() {
        // A sniff target reports a write-only-mismatch reason when a writer is
        // requested, mirroring the BLE advertising sniff capability error.
        let target = PacketWireTarget::WhadSerial {
            port: "/dev/ttyACM0".to_string(),
            mode: WhadMode::Dot15d4(WhadDot15d4Mode::Sniff { channel: 15 }),
            dry_run: true,
        };
        assert_eq!(
            unsupported_writer_reason(&target),
            "WHAD serial 802.15.4 sniff targets are read-only; use Send mode for writing"
        );
    }

    #[cfg(all(test, feature = "whad"))]
    #[test]
    fn packetwire_dot15d4_send_target_is_write_only_for_source() {
        // A send target reports a read-only-mismatch reason when a source is
        // requested, mirroring the BLE inject capability error.
        let target = PacketWireTarget::WhadSerial {
            port: "/dev/ttyACM0".to_string(),
            mode: WhadMode::Dot15d4(WhadDot15d4Mode::Send),
            dry_run: true,
        };
        assert_eq!(
            unsupported_source_reason(&target),
            "WHAD serial 802.15.4 send targets are write-only; use Sniff mode for capture"
        );
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
