//! Classic pcap read/write, libpcap BPF filtering, and bounded
//! capture helpers.
//!
//! Offline pcap APIs are rootless and deterministic. Live capture is explicit
//! and bounded by count and timeout controls, using native libpcap for interface
//! capture and BPF filtering.

#![forbid(unsafe_code)]

use std::borrow::Borrow;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::{CrafterError, LinkType, NetworkLayer, Packet, ProtocolRegistry};

const PCAP_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const DEFAULT_SNAPLEN: u32 = 65_535;
const DEFAULT_CAPTURE_TIMEOUT: Duration = Duration::from_secs(10);

/// BSD null/loopback pcap data-link type.
pub const DLT_NULL: u32 = 0;
/// Ethernet pcap data-link type.
pub const DLT_EN10MB: u32 = 1;
/// BSD loopback pcap data-link type.
pub const DLT_LOOP: u32 = 108;
/// Raw IPv4/IPv6 pcap data-link type.
pub const DLT_RAW: u32 = 101;
/// Linux cooked capture v1 pcap data-link type.
pub const DLT_LINUX_SLL: u32 = 113;
const DLT_RAW_BSD: u32 = 12;
const DLT_IPV4: u32 = 228;
const DLT_IPV6: u32 = 229;

/// Result type returned by pcap helpers.
pub type Result<T> = std::result::Result<T, PcapError>;

/// Errors returned by pcap file helpers.
#[derive(Debug)]
pub enum PcapError {
    /// An underlying file or stream operation failed.
    Io(io::Error),
    /// Packet compile or decode failed.
    Packet(CrafterError),
    /// Native libpcap failed while opening, filtering, or reading capture.
    Libpcap(pcap::Error),
    /// The pcap global header is malformed or unsupported.
    InvalidHeader(&'static str),
    /// A pcap record header or body is malformed.
    InvalidRecord(&'static str),
    /// A packet or record cannot fit in the configured pcap writer.
    RecordTooLarge {
        /// Record field being written.
        field: &'static str,
        /// Maximum accepted value.
        max: u64,
        /// Actual value.
        actual: u64,
    },
    /// A sniffer was opened without selecting a pcap file or interface.
    CaptureSourceMissing,
    /// Live capture cannot be opened in the current environment.
    LiveCaptureUnavailable(&'static str),
    /// A spawned capture thread panicked.
    CaptureThreadPanicked,
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Packet(err) => write!(f, "{err}"),
            Self::Libpcap(err) => write!(f, "{err}"),
            Self::InvalidHeader(reason) => write!(f, "invalid pcap header: {reason}"),
            Self::InvalidRecord(reason) => write!(f, "invalid pcap record: {reason}"),
            Self::RecordTooLarge { field, max, actual } => {
                write!(f, "pcap {field} value {actual} exceeds maximum {max}")
            }
            Self::CaptureSourceMissing => write!(f, "capture source is missing"),
            Self::LiveCaptureUnavailable(reason) => {
                write!(f, "live capture is unavailable: {reason}")
            }
            Self::CaptureThreadPanicked => write!(f, "capture thread panicked"),
        }
    }
}

impl std::error::Error for PcapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Packet(err) => Some(err),
            Self::Libpcap(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for PcapError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<CrafterError> for PcapError {
    fn from(value: CrafterError) -> Self {
        Self::Packet(value)
    }
}

impl From<pcap::Error> for PcapError {
    fn from(value: pcap::Error) -> Self {
        Self::Libpcap(value)
    }
}

/// Timestamp precision used by a pcap file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimestampPrecision {
    /// Classic pcap microsecond timestamps.
    Microseconds,
    /// Nanosecond-resolution pcap timestamps.
    Nanoseconds,
}

impl TimestampPrecision {
    fn units_per_second(self) -> u32 {
        match self {
            Self::Microseconds => 1_000_000,
            Self::Nanoseconds => 1_000_000_000,
        }
    }

    fn duration_factor(self) -> u32 {
        match self {
            Self::Microseconds => 1_000,
            Self::Nanoseconds => 1,
        }
    }
}

/// Timestamp attached to a pcap record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcapTimestamp {
    seconds: u64,
    fractional: u32,
    precision: TimestampPrecision,
}

impl PcapTimestamp {
    /// Create a zero timestamp.
    pub const fn zero() -> Self {
        Self {
            seconds: 0,
            fractional: 0,
            precision: TimestampPrecision::Microseconds,
        }
    }

    /// Create a microsecond-precision timestamp.
    pub fn micros(seconds: u64, micros: u32) -> Result<Self> {
        Self::new(seconds, micros, TimestampPrecision::Microseconds)
    }

    /// Create a nanosecond-precision timestamp.
    pub fn nanos(seconds: u64, nanos: u32) -> Result<Self> {
        Self::new(seconds, nanos, TimestampPrecision::Nanoseconds)
    }

    /// Create a timestamp in the supplied precision.
    pub fn new(seconds: u64, fractional: u32, precision: TimestampPrecision) -> Result<Self> {
        if fractional >= precision.units_per_second() {
            return Err(PcapError::InvalidRecord(
                "timestamp fractional field must be below one second",
            ));
        }

        Ok(Self {
            seconds,
            fractional,
            precision,
        })
    }

    /// Create a timestamp from a duration, truncating to the requested precision.
    pub fn from_duration(duration: Duration, precision: TimestampPrecision) -> Result<Self> {
        let seconds = duration.as_secs();
        let fractional = match precision {
            TimestampPrecision::Microseconds => duration.subsec_micros(),
            TimestampPrecision::Nanoseconds => duration.subsec_nanos(),
        };

        Self::new(seconds, fractional, precision)
    }

    /// Whole seconds since the epoch stored in the pcap record.
    pub const fn seconds(self) -> u64 {
        self.seconds
    }

    /// Fractional timestamp component in this timestamp's precision.
    pub const fn fractional(self) -> u32 {
        self.fractional
    }

    /// Precision used by the fractional component.
    pub const fn precision(self) -> TimestampPrecision {
        self.precision
    }

    /// Convert this timestamp to a [`Duration`].
    pub fn as_duration(self) -> Duration {
        Duration::new(
            self.seconds,
            self.fractional * self.precision.duration_factor(),
        )
    }

    /// Convert to a target pcap precision.
    pub fn to_precision(self, precision: TimestampPrecision) -> Result<Self> {
        if self.precision == precision {
            Ok(self)
        } else {
            Self::from_duration(self.as_duration(), precision)
        }
    }

    fn pcap_fields(self, precision: TimestampPrecision) -> Result<(u32, u32)> {
        let timestamp = self.to_precision(precision)?;
        let seconds = u32::try_from(timestamp.seconds).map_err(|_| PcapError::RecordTooLarge {
            field: "timestamp seconds",
            max: u32::MAX as u64,
            actual: timestamp.seconds,
        })?;
        Ok((seconds, timestamp.fractional))
    }
}

impl Default for PcapTimestamp {
    fn default() -> Self {
        Self::zero()
    }
}

/// Pcap data-link type metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcapLinkType {
    /// BSD null/loopback capture header.
    NullLoopback,
    /// Ethernet frames.
    Ethernet,
    /// Raw IPv4/IPv6 packets without a link-layer header.
    RawIp,
    /// Linux cooked capture v1.
    LinuxSll,
    /// Unsupported or caller-defined pcap data-link type.
    Unknown(u32),
}

impl PcapLinkType {
    /// Convert a pcap numeric DLT value into a typed value.
    pub const fn from_datalink(datalink: u32) -> Self {
        match datalink {
            DLT_NULL | DLT_LOOP => Self::NullLoopback,
            DLT_EN10MB => Self::Ethernet,
            DLT_RAW | DLT_RAW_BSD | DLT_IPV4 | DLT_IPV6 => Self::RawIp,
            DLT_LINUX_SLL => Self::LinuxSll,
            value => Self::Unknown(value),
        }
    }

    /// Numeric pcap DLT value.
    pub const fn datalink(self) -> u32 {
        match self {
            Self::NullLoopback => DLT_NULL,
            Self::Ethernet => DLT_EN10MB,
            Self::RawIp => DLT_RAW,
            Self::LinuxSll => DLT_LINUX_SLL,
            Self::Unknown(value) => value,
        }
    }

    /// Best-effort core link-layer entrypoint.
    pub const fn link_type(self) -> LinkType {
        match self {
            Self::NullLoopback => LinkType::NullLoopback,
            Self::Ethernet => LinkType::Ethernet,
            Self::LinuxSll => LinkType::LinuxSll,
            Self::RawIp | Self::Unknown(_) => LinkType::Raw,
        }
    }

    /// Decode bytes according to this pcap data-link type.
    pub fn decode(self, bytes: impl AsRef<[u8]>) -> crate::Result<Packet> {
        self.decode_with_registry(&ProtocolRegistry::new(), bytes)
    }

    /// Decode bytes using an explicit protocol registry.
    pub fn decode_with_registry(
        self,
        registry: &ProtocolRegistry,
        bytes: impl AsRef<[u8]>,
    ) -> crate::Result<Packet> {
        let bytes = bytes.as_ref();
        match self {
            Self::NullLoopback | Self::Ethernet | Self::LinuxSll => {
                Packet::decode_from_link_with_registry(registry, self.link_type(), bytes)
            }
            Self::RawIp => decode_raw_ip_with_registry(registry, bytes),
            Self::Unknown(_) => Packet::decode_raw(bytes),
        }
    }
}

impl From<LinkType> for PcapLinkType {
    fn from(value: LinkType) -> Self {
        match value {
            LinkType::Raw => Self::RawIp,
            LinkType::Ethernet => Self::Ethernet,
            LinkType::LinuxCooked | LinkType::LinuxSll => Self::LinuxSll,
            LinkType::NullLoopback => Self::NullLoopback,
        }
    }
}

/// Parsed pcap global header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcapHeader {
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    link_type: PcapLinkType,
    precision: TimestampPrecision,
}

impl PcapHeader {
    /// Create a standard pcap header.
    pub fn new(link_type: impl Into<PcapLinkType>) -> Self {
        Self {
            version_major: PCAP_VERSION_MAJOR,
            version_minor: PCAP_VERSION_MINOR,
            thiszone: 0,
            sigfigs: 0,
            snaplen: DEFAULT_SNAPLEN,
            link_type: link_type.into(),
            precision: TimestampPrecision::Microseconds,
        }
    }

    /// Pcap major version.
    pub const fn version_major(self) -> u16 {
        self.version_major
    }

    /// Pcap minor version.
    pub const fn version_minor(self) -> u16 {
        self.version_minor
    }

    /// Timezone correction field from the pcap header.
    pub const fn thiszone(self) -> i32 {
        self.thiszone
    }

    /// Timestamp accuracy field from the pcap header.
    pub const fn sigfigs(self) -> u32 {
        self.sigfigs
    }

    /// Snapshot length from the pcap header.
    pub const fn snaplen(self) -> u32 {
        self.snaplen
    }

    /// Best-effort core link-layer type.
    pub const fn link_type(self) -> LinkType {
        self.link_type.link_type()
    }

    /// Pcap data-link type metadata.
    pub const fn pcap_link_type(self) -> PcapLinkType {
        self.link_type
    }

    /// Timestamp precision used by the file.
    pub const fn precision(self) -> TimestampPrecision {
        self.precision
    }
}

/// Writer configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcapWriterOptions {
    header: PcapHeader,
}

impl PcapWriterOptions {
    /// Create default writer options for a link type.
    pub fn new(link_type: impl Into<PcapLinkType>) -> Self {
        Self {
            header: PcapHeader::new(link_type),
        }
    }

    /// Set the snapshot length.
    pub fn snaplen(mut self, snaplen: u32) -> Self {
        self.header.snaplen = snaplen;
        self
    }

    /// Set timestamp precision.
    pub fn precision(mut self, precision: TimestampPrecision) -> Self {
        self.header.precision = precision;
        self
    }

    /// Set the timezone correction field.
    pub fn thiszone(mut self, thiszone: i32) -> Self {
        self.header.thiszone = thiszone;
        self
    }

    /// Set the timestamp accuracy field.
    pub fn sigfigs(mut self, sigfigs: u32) -> Self {
        self.header.sigfigs = sigfigs;
        self
    }

    /// Return the configured header.
    pub const fn header(self) -> PcapHeader {
        self.header
    }
}

/// Raw pcap record plus global link-type metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapRecord {
    timestamp: PcapTimestamp,
    original_len: u32,
    data: Vec<u8>,
    link_type: PcapLinkType,
}

impl PcapRecord {
    /// Create a raw record.
    pub fn new(
        timestamp: PcapTimestamp,
        original_len: u32,
        data: impl Into<Vec<u8>>,
        link_type: impl Into<PcapLinkType>,
    ) -> Result<Self> {
        let data = data.into();
        if original_len < data.len() as u32 {
            return Err(PcapError::InvalidRecord(
                "original length must be at least captured length",
            ));
        }

        Ok(Self {
            timestamp,
            original_len,
            data,
            link_type: link_type.into(),
        })
    }

    /// Record timestamp.
    pub const fn timestamp(&self) -> PcapTimestamp {
        self.timestamp
    }

    /// Captured length.
    pub fn captured_len(&self) -> u32 {
        self.data.len() as u32
    }

    /// Original on-wire length.
    pub const fn original_len(&self) -> u32 {
        self.original_len
    }

    /// Captured bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consume and return captured bytes.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Best-effort core link-layer type.
    pub const fn link_type(&self) -> LinkType {
        self.link_type.link_type()
    }

    /// Pcap data-link type metadata.
    pub const fn pcap_link_type(&self) -> PcapLinkType {
        self.link_type
    }

    /// Decode this record with the default protocol registry.
    pub fn decode(&self) -> crate::Result<Packet> {
        self.link_type.decode(&self.data)
    }

    /// Decode this record with an explicit protocol registry.
    pub fn decode_with_registry(&self, registry: &ProtocolRegistry) -> crate::Result<Packet> {
        self.link_type.decode_with_registry(registry, &self.data)
    }
}

/// Decoded packet with pcap record metadata preserved.
#[derive(Debug, Clone)]
pub struct PcapPacket {
    timestamp: PcapTimestamp,
    original_len: u32,
    link_type: PcapLinkType,
    packet: Packet,
}

impl PcapPacket {
    /// Create a decoded pcap packet wrapper.
    pub const fn new(
        timestamp: PcapTimestamp,
        original_len: u32,
        link_type: PcapLinkType,
        packet: Packet,
    ) -> Self {
        Self {
            timestamp,
            original_len,
            link_type,
            packet,
        }
    }

    /// Metadata timestamp.
    pub const fn timestamp(&self) -> PcapTimestamp {
        self.timestamp
    }

    /// Original on-wire length.
    pub const fn original_len(&self) -> u32 {
        self.original_len
    }

    /// Best-effort core link-layer type.
    pub const fn link_type(&self) -> LinkType {
        self.link_type.link_type()
    }

    /// Pcap data-link type metadata.
    pub const fn pcap_link_type(&self) -> PcapLinkType {
        self.link_type
    }

    /// Borrow the decoded packet.
    pub const fn packet(&self) -> &Packet {
        &self.packet
    }

    /// Consume and return the decoded packet.
    pub fn into_packet(self) -> Packet {
        self.packet
    }
}

/// Offline pcap reader.
#[derive(Debug)]
pub struct PcapReader<R = BufReader<File>> {
    reader: R,
    header: PcapHeader,
    endian: Endian,
}

impl PcapReader<BufReader<File>> {
    /// Open a pcap file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_reader(BufReader::new(File::open(path)?))
    }
}

impl<R> PcapReader<R>
where
    R: Read,
{
    /// Read a pcap global header from an existing reader.
    pub fn from_reader(mut reader: R) -> Result<Self> {
        let mut bytes = [0u8; PCAP_HEADER_LEN];
        reader.read_exact(&mut bytes)?;
        let (header, endian) = parse_header(&bytes)?;

        Ok(Self {
            reader,
            header,
            endian,
        })
    }

    /// Parsed pcap global header.
    pub const fn header(&self) -> PcapHeader {
        self.header
    }

    /// Best-effort core link-layer type.
    pub const fn link_type(&self) -> LinkType {
        self.header.link_type()
    }

    /// Pcap data-link type metadata.
    pub const fn pcap_link_type(&self) -> PcapLinkType {
        self.header.pcap_link_type()
    }

    /// Read the next accepted pcap record.
    pub fn next_record(&mut self) -> Result<Option<PcapRecord>> {
        self.read_next_record()
    }

    /// Consume the reader and return an iterator over records.
    pub fn records(self) -> PcapRecords<R> {
        PcapRecords {
            reader: self,
            done: false,
        }
    }

    /// Collect raw records.
    pub fn collect_records(mut self) -> Result<Vec<PcapRecord>> {
        let mut records = Vec::new();
        while let Some(record) = self.next_record()? {
            records.push(record);
        }
        Ok(records)
    }

    /// Collect decoded packets while preserving pcap metadata.
    pub fn collect_packets(mut self) -> Result<Vec<PcapPacket>> {
        let mut packets = Vec::new();
        while let Some(record) = self.next_record()? {
            let packet = record.decode()?;
            packets.push(PcapPacket::new(
                record.timestamp,
                record.original_len,
                record.link_type,
                packet,
            ));
        }
        Ok(packets)
    }

    fn read_next_record(&mut self) -> Result<Option<PcapRecord>> {
        let mut header = [0u8; PCAP_RECORD_HEADER_LEN];
        if !read_exact_or_eof(&mut self.reader, &mut header)? {
            return Ok(None);
        }

        let ts_sec = read_u32(&header[0..4], self.endian);
        let ts_frac = read_u32(&header[4..8], self.endian);
        let captured_len = read_u32(&header[8..12], self.endian);
        let original_len = read_u32(&header[12..16], self.endian);

        if captured_len > original_len {
            return Err(PcapError::InvalidRecord(
                "captured length must not exceed original length",
            ));
        }
        if captured_len > self.header.snaplen {
            return Err(PcapError::InvalidRecord(
                "captured length exceeds pcap snapshot length",
            ));
        }

        let mut data = vec![0u8; captured_len as usize];
        self.reader.read_exact(&mut data)?;

        Ok(Some(PcapRecord::new(
            PcapTimestamp::new(ts_sec as u64, ts_frac, self.header.precision)?,
            original_len,
            data,
            self.header.link_type,
        )?))
    }
}

/// Iterator over pcap records.
#[derive(Debug)]
pub struct PcapRecords<R>
where
    R: Read,
{
    reader: PcapReader<R>,
    done: bool,
}

impl<R> Iterator for PcapRecords<R>
where
    R: Read,
{
    type Item = Result<PcapRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        match self.reader.next_record() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(err) => {
                self.done = true;
                Some(Err(err))
            }
        }
    }
}

/// Offline pcap writer.
#[derive(Debug)]
pub struct PcapWriter<W = BufWriter<File>> {
    writer: W,
    header: PcapHeader,
    endian: Endian,
}

impl PcapWriter<BufWriter<File>> {
    /// Create a pcap file and write the global header.
    pub fn create(path: impl AsRef<Path>, link_type: impl Into<PcapLinkType>) -> Result<Self> {
        Self::from_writer(BufWriter::new(File::create(path)?), link_type)
    }

    /// Create a pcap file using explicit writer options.
    pub fn create_with_options(path: impl AsRef<Path>, options: PcapWriterOptions) -> Result<Self> {
        Self::from_writer_with_options(BufWriter::new(File::create(path)?), options)
    }
}

impl<W> PcapWriter<W>
where
    W: Write,
{
    /// Write a pcap global header to an existing writer.
    pub fn from_writer(writer: W, link_type: impl Into<PcapLinkType>) -> Result<Self> {
        Self::from_writer_with_options(writer, PcapWriterOptions::new(link_type))
    }

    /// Write a pcap global header using explicit writer options.
    pub fn from_writer_with_options(mut writer: W, options: PcapWriterOptions) -> Result<Self> {
        let endian = Endian::Little;
        let header = options.header();
        write_header(&mut writer, header, endian)?;
        Ok(Self {
            writer,
            header,
            endian,
        })
    }

    /// Parsed pcap header written by this writer.
    pub const fn header(&self) -> PcapHeader {
        self.header
    }

    /// Write a raw record.
    pub fn write_record(&mut self, record: &PcapRecord) -> Result<&mut Self> {
        if record.pcap_link_type() != self.header.link_type {
            return Err(PcapError::InvalidRecord(
                "record link type must match writer link type",
            ));
        }

        self.write_raw(
            record.timestamp(),
            record.data(),
            Some(record.original_len()),
        )
    }

    /// Write compiled packet bytes with a zero timestamp.
    pub fn write_packet(&mut self, packet: &Packet) -> Result<&mut Self> {
        self.write_packet_with_timestamp(packet, PcapTimestamp::zero())
    }

    /// Write compiled packet bytes with an explicit timestamp.
    pub fn write_packet_with_timestamp(
        &mut self,
        packet: &Packet,
        timestamp: PcapTimestamp,
    ) -> Result<&mut Self> {
        let bytes = packet.compile()?;
        self.write_raw(timestamp, bytes.as_bytes(), None)
    }

    /// Write a collection of packets with zero timestamps.
    pub fn write_packets<I, P>(&mut self, packets: I) -> Result<&mut Self>
    where
        I: IntoIterator<Item = P>,
        P: Borrow<Packet>,
    {
        for packet in packets {
            self.write_packet(packet.borrow())?;
        }
        Ok(self)
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    /// Flush and return the underlying writer.
    pub fn into_inner(mut self) -> Result<W> {
        self.flush()?;
        Ok(self.writer)
    }

    fn write_raw(
        &mut self,
        timestamp: PcapTimestamp,
        data: &[u8],
        original_len: Option<u32>,
    ) -> Result<&mut Self> {
        if data.len() > self.header.snaplen as usize {
            return Err(PcapError::RecordTooLarge {
                field: "captured length",
                max: self.header.snaplen as u64,
                actual: data.len() as u64,
            });
        }

        let captured_len = u32::try_from(data.len()).map_err(|_| PcapError::RecordTooLarge {
            field: "captured length",
            max: u32::MAX as u64,
            actual: data.len() as u64,
        })?;
        let original_len = original_len.unwrap_or(captured_len);
        if original_len < captured_len {
            return Err(PcapError::InvalidRecord(
                "original length must be at least captured length",
            ));
        }

        let (seconds, fractional) = timestamp.pcap_fields(self.header.precision)?;
        write_u32(&mut self.writer, self.endian, seconds)?;
        write_u32(&mut self.writer, self.endian, fractional)?;
        write_u32(&mut self.writer, self.endian, captured_len)?;
        write_u32(&mut self.writer, self.endian, original_len)?;
        self.writer.write_all(data)?;
        Ok(self)
    }
}

/// Read and decode all packets from a pcap file.
pub fn read_pcap(path: impl AsRef<Path>) -> Result<Vec<PcapPacket>> {
    PcapReader::open(path)?.collect_packets()
}

/// Read and decode all packets from a pcap file with an offline filter.
pub fn read_pcap_filtered(path: impl AsRef<Path>, filter: &str) -> Result<Vec<PcapPacket>> {
    let mut capture = LibpcapOfflineCapture::open(path, Some(filter))?;
    let mut packets = Vec::new();
    while let Some(record) = capture.next_record()? {
        let packet = record.decode()?;
        packets.push(PcapPacket::new(
            record.timestamp,
            record.original_len,
            record.link_type,
            packet,
        ));
    }
    Ok(packets)
}

/// Dump packets to a pcap file.
pub fn dump_pcap<I, P>(
    path: impl AsRef<Path>,
    packets: I,
    link_type: impl Into<PcapLinkType>,
) -> Result<()>
where
    I: IntoIterator<Item = P>,
    P: Borrow<Packet>,
{
    let mut writer = PcapWriter::create(path, link_type)?;
    writer.write_packets(packets)?;
    writer.flush()
}

/// Builder for offline and live packet capture.
///
/// Offline capture reads pcap files through [`PcapReader`] unless a filter is
/// configured, in which case libpcap compiles and applies the BPF expression.
/// Live capture opens interfaces directly through libpcap.
#[derive(Debug, Clone)]
pub struct Sniffer {
    source: CaptureSource,
    filter: Option<String>,
    count_limit: Option<usize>,
    timeout: Option<Duration>,
    snaplen: u32,
    promisc: bool,
    immediate: bool,
}

impl Sniffer {
    /// Create a sniffer builder with safe bounded live-capture defaults.
    pub fn new() -> Self {
        Self {
            source: CaptureSource::Unset,
            filter: None,
            count_limit: None,
            timeout: Some(DEFAULT_CAPTURE_TIMEOUT),
            snaplen: DEFAULT_SNAPLEN,
            promisc: true,
            immediate: true,
        }
    }

    /// Create a builder that captures from an offline pcap file.
    pub fn offline(path: impl AsRef<Path>) -> Self {
        Self::new().pcap(path)
    }

    /// Create a builder that captures from a network interface.
    pub fn interface(name: impl Into<String>) -> Self {
        Self::new().iface(name)
    }

    /// Select a network interface for live capture.
    pub fn iface(mut self, name: impl Into<String>) -> Self {
        self.source = CaptureSource::Interface(name.into());
        self
    }

    /// Select an offline pcap file for capture.
    pub fn pcap(mut self, path: impl AsRef<Path>) -> Self {
        self.source = CaptureSource::Offline(path.as_ref().to_path_buf());
        self
    }

    /// Attach a BPF-style filter expression.
    ///
    /// Filters are compiled by libpcap when the capture is opened.
    pub fn filter(mut self, filter: impl Into<String>) -> Self {
        let filter = filter.into();
        self.filter = (!filter.trim().is_empty()).then_some(filter);
        self
    }

    /// Remove any configured filter.
    pub fn clear_filter(mut self) -> Self {
        self.filter = None;
        self
    }

    /// Limit the number of packets yielded by this capture.
    pub fn count(mut self, count: usize) -> Self {
        self.count_limit = Some(count);
        self
    }

    /// Remove the configured packet count limit.
    pub fn unlimited_count(mut self) -> Self {
        self.count_limit = None;
        self
    }

    /// Set a wall-clock capture timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Disable the capture timeout.
    pub fn no_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    /// Set the snapshot length for live capture.
    pub fn snaplen(mut self, snaplen: u32) -> Self {
        self.snaplen = snaplen;
        self
    }

    /// Enable or disable promiscuous mode for live capture.
    pub fn promisc(mut self, promisc: bool) -> Self {
        self.promisc = promisc;
        self
    }

    /// Enable or disable packet-buffer flushing for live capture.
    pub fn immediate_mode(mut self, immediate: bool) -> Self {
        self.immediate = immediate;
        self
    }

    /// Open the capture and return an iterator over decoded packets.
    pub fn open(self) -> Result<Capture> {
        self.open_with_cancel(Arc::new(AtomicBool::new(false)))
    }

    /// Capture packets with a callback until count, timeout, EOF, cancellation,
    /// or [`CaptureControl::Stop`] is reached.
    pub fn capture<F>(self, count: usize, mut callback: F) -> Result<usize>
    where
        F: FnMut(PcapPacket) -> Result<CaptureControl>,
    {
        let mut capture = self.count(count).open()?;
        let mut accepted = 0;
        while let Some(packet) = capture.next_packet()? {
            accepted += 1;
            if callback(packet)? == CaptureControl::Stop {
                break;
            }
        }
        Ok(accepted)
    }

    /// Collect packets into memory using the configured limits.
    pub fn collect(self) -> Result<Vec<PcapPacket>> {
        self.open()?.collect_packets()
    }

    /// Start a background capture and return a handle that can be joined or
    /// cancelled.
    pub fn spawn(self, count: usize) -> Result<CaptureHandle> {
        self.validate()?;

        let cancel = Arc::new(AtomicBool::new(false));
        let thread_cancel = Arc::clone(&cancel);
        let sniffer = self.count(count);
        let join = thread::Builder::new()
            .name("crafter-sniffer".to_string())
            .spawn(move || {
                let capture = sniffer.open_with_cancel(thread_cancel)?;
                capture.collect_packets()
            })?;

        Ok(CaptureHandle { cancel, join })
    }

    fn validate(&self) -> Result<()> {
        match &self.source {
            CaptureSource::Unset => Err(PcapError::CaptureSourceMissing),
            CaptureSource::Offline(_) | CaptureSource::Interface(_) => Ok(()),
        }
    }

    fn open_with_cancel(self, cancel: Arc<AtomicBool>) -> Result<Capture> {
        let count_limit = self.count_limit;
        let deadline = capture_deadline(self.timeout);
        let inner = match self.source {
            CaptureSource::Unset => return Err(PcapError::CaptureSourceMissing),
            CaptureSource::Offline(path) => {
                if let Some(filter) = self.filter.as_deref() {
                    CaptureInner::OfflineFiltered(LibpcapOfflineCapture::open(path, Some(filter))?)
                } else {
                    CaptureInner::Offline(PcapReader::open(path)?)
                }
            }
            CaptureSource::Interface(name) => CaptureInner::Live(LibpcapCapture::open(
                &name,
                self.filter.as_deref(),
                self.timeout,
                self.snaplen,
                self.promisc,
                self.immediate,
            )?),
        };

        Ok(Capture {
            inner,
            count_limit,
            yielded: 0,
            deadline,
            cancel,
        })
    }
}

impl Default for Sniffer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
enum CaptureSource {
    Unset,
    Offline(PathBuf),
    Interface(String),
}

/// Callback decision returned from [`Sniffer::capture`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaptureControl {
    /// Continue capture.
    Continue,
    /// Stop capture after the current packet.
    Stop,
}

/// Open packet capture iterator.
#[derive(Debug)]
pub struct Capture {
    inner: CaptureInner,
    count_limit: Option<usize>,
    yielded: usize,
    deadline: Option<Instant>,
    cancel: Arc<AtomicBool>,
}

impl Capture {
    /// Read the next decoded packet, returning `Ok(None)` on EOF, timeout,
    /// cancellation, or count exhaustion.
    pub fn next_packet(&mut self) -> Result<Option<PcapPacket>> {
        if self.cancel.load(Ordering::Relaxed) || self.reached_limit() || self.timed_out() {
            return Ok(None);
        }

        let Some(record) = self.inner.next_record()? else {
            return Ok(None);
        };
        self.yielded += 1;
        let packet = record.decode()?;
        Ok(Some(PcapPacket::new(
            record.timestamp,
            record.original_len,
            record.link_type,
            packet,
        )))
    }

    /// Collect remaining packets into memory.
    pub fn collect_packets(mut self) -> Result<Vec<PcapPacket>> {
        let mut packets = Vec::new();
        while let Some(packet) = self.next_packet()? {
            packets.push(packet);
        }
        Ok(packets)
    }

    /// Number of packets yielded by this capture so far.
    pub const fn yielded(&self) -> usize {
        self.yielded
    }

    fn reached_limit(&self) -> bool {
        self.count_limit
            .is_some_and(|count_limit| self.yielded >= count_limit)
    }

    fn timed_out(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
}

impl Iterator for Capture {
    type Item = Result<PcapPacket>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_packet() {
            Ok(Some(packet)) => Some(Ok(packet)),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        }
    }
}

#[derive(Debug)]
enum CaptureInner {
    Offline(PcapReader<BufReader<File>>),
    OfflineFiltered(LibpcapOfflineCapture),
    Live(LibpcapCapture),
}

impl CaptureInner {
    fn next_record(&mut self) -> Result<Option<PcapRecord>> {
        match self {
            Self::Offline(reader) => reader.next_record(),
            Self::OfflineFiltered(capture) => capture.next_record(),
            Self::Live(capture) => capture.next_record(),
        }
    }
}

/// Background capture handle returned by [`Sniffer::spawn`].
#[derive(Debug)]
pub struct CaptureHandle {
    cancel: Arc<AtomicBool>,
    join: JoinHandle<Result<Vec<PcapPacket>>>,
}

impl CaptureHandle {
    /// Request cooperative cancellation.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Wait for the capture thread and return collected packets.
    pub fn join(self) -> Result<Vec<PcapPacket>> {
        self.join
            .join()
            .map_err(|_| PcapError::CaptureThreadPanicked)?
    }
}

struct LibpcapOfflineCapture {
    capture: pcap::Capture<pcap::Offline>,
    link_type: PcapLinkType,
}

impl fmt::Debug for LibpcapOfflineCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LibpcapOfflineCapture")
            .field("link_type", &self.link_type)
            .finish_non_exhaustive()
    }
}

impl LibpcapOfflineCapture {
    fn open(path: impl AsRef<Path>, filter: Option<&str>) -> Result<Self> {
        let mut capture = pcap::Capture::from_file(path)?;
        if let Some(filter) = filter.filter(|filter| !filter.trim().is_empty()) {
            capture.filter(filter, true)?;
        }
        let link_type = pcap_link_type(capture.get_datalink());
        Ok(Self { capture, link_type })
    }

    fn next_record(&mut self) -> Result<Option<PcapRecord>> {
        next_libpcap_record(&mut self.capture, self.link_type)
    }
}

struct LibpcapCapture {
    capture: pcap::Capture<pcap::Active>,
    link_type: PcapLinkType,
}

impl fmt::Debug for LibpcapCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LibpcapCapture")
            .field("link_type", &self.link_type)
            .finish_non_exhaustive()
    }
}

impl LibpcapCapture {
    fn open(
        iface: &str,
        filter: Option<&str>,
        timeout: Option<Duration>,
        snaplen: u32,
        promisc: bool,
        immediate: bool,
    ) -> Result<Self> {
        if iface.trim().is_empty() {
            return Err(PcapError::LiveCaptureUnavailable(
                "interface name must not be empty",
            ));
        }

        let mut capture = pcap::Capture::from_device(iface)?
            .promisc(promisc)
            .snaplen(snaplen_to_i32(snaplen))
            .timeout(timeout_to_millis(timeout))
            .immediate_mode(immediate)
            .open()?;

        if let Some(filter) = filter.filter(|filter| !filter.trim().is_empty()) {
            capture.filter(filter, true)?;
        }

        let link_type = pcap_link_type(capture.get_datalink());
        Ok(Self { capture, link_type })
    }

    fn next_record(&mut self) -> Result<Option<PcapRecord>> {
        next_libpcap_record(&mut self.capture, self.link_type)
    }
}

fn capture_deadline(timeout: Option<Duration>) -> Option<Instant> {
    timeout.and_then(|duration| Instant::now().checked_add(duration))
}

fn next_libpcap_record<T>(
    capture: &mut pcap::Capture<T>,
    link_type: PcapLinkType,
) -> Result<Option<PcapRecord>>
where
    T: pcap::Activated,
{
    match capture.next_packet() {
        Ok(packet) => {
            let timestamp = libpcap_timestamp(packet.header)?;
            PcapRecord::new(
                timestamp,
                packet.header.len,
                packet.data.to_vec(),
                link_type,
            )
            .map(Some)
        }
        Err(pcap::Error::TimeoutExpired | pcap::Error::NoMorePackets) => Ok(None),
        Err(err) => Err(PcapError::Libpcap(err)),
    }
}

fn libpcap_timestamp(header: &pcap::PacketHeader) -> Result<PcapTimestamp> {
    let seconds = u64::try_from(header.ts.tv_sec)
        .map_err(|_| PcapError::InvalidRecord("timestamp seconds must be non-negative"))?;
    let micros = u32::try_from(header.ts.tv_usec)
        .map_err(|_| PcapError::InvalidRecord("timestamp fractional field is out of range"))?;
    PcapTimestamp::micros(seconds, micros)
}

fn pcap_link_type(link_type: pcap::Linktype) -> PcapLinkType {
    u32::try_from(link_type.0)
        .map(PcapLinkType::from_datalink)
        .unwrap_or(PcapLinkType::Unknown(link_type.0 as u32))
}

fn timeout_to_millis(timeout: Option<Duration>) -> i32 {
    timeout
        .map(|timeout| timeout.as_millis().clamp(1, i32::MAX as u128) as i32)
        .unwrap_or(0)
}

fn snaplen_to_i32(snaplen: u32) -> i32 {
    snaplen.min(i32::MAX as u32) as i32
}

/// File-backed pcap reader alias used by generated examples.
pub type FileSniffer = PcapReader<BufReader<File>>;

/// Reader-oriented re-exports.
pub mod reader {
    pub use crate::{read_pcap, read_pcap_filtered, FileSniffer, PcapReader, PcapRecords};
}

/// Writer-oriented re-exports.
pub mod writer {
    pub use crate::{dump_pcap, PcapWriter, PcapWriterOptions};
}

/// Capture-oriented placeholder module for live sniffing steps.
pub mod capture {
    pub use crate::{Capture, CaptureControl, CaptureHandle, FileSniffer, Sniffer};
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Endian {
    Little,
    Big,
}

fn decode_raw_ip_with_registry(registry: &ProtocolRegistry, bytes: &[u8]) -> crate::Result<Packet> {
    match bytes.first().map(|byte| byte >> 4) {
        Some(4) => registry.decode_from_l3(NetworkLayer::Ipv4, bytes),
        Some(6) => registry.decode_from_l3(NetworkLayer::Ipv6, bytes),
        _ => Packet::decode_raw(bytes),
    }
}

fn parse_header(bytes: &[u8; PCAP_HEADER_LEN]) -> Result<(PcapHeader, Endian)> {
    let (endian, precision) = match &bytes[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, TimestampPrecision::Microseconds),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, TimestampPrecision::Microseconds),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, TimestampPrecision::Nanoseconds),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, TimestampPrecision::Nanoseconds),
        _ => return Err(PcapError::InvalidHeader("unknown magic number")),
    };

    let version_major = read_u16(&bytes[4..6], endian);
    let version_minor = read_u16(&bytes[6..8], endian);
    if version_major != PCAP_VERSION_MAJOR {
        return Err(PcapError::InvalidHeader("unsupported major version"));
    }

    let thiszone = read_i32(&bytes[8..12], endian);
    let sigfigs = read_u32(&bytes[12..16], endian);
    let snaplen = read_u32(&bytes[16..20], endian);
    if snaplen == 0 {
        return Err(PcapError::InvalidHeader("snapshot length must be non-zero"));
    }
    let link_type = PcapLinkType::from_datalink(read_u32(&bytes[20..24], endian));

    Ok((
        PcapHeader {
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            snaplen,
            link_type,
            precision,
        },
        endian,
    ))
}

fn write_header<W>(writer: &mut W, header: PcapHeader, endian: Endian) -> Result<()>
where
    W: Write,
{
    let magic = match (endian, header.precision) {
        (Endian::Little, TimestampPrecision::Microseconds) => [0xd4, 0xc3, 0xb2, 0xa1],
        (Endian::Big, TimestampPrecision::Microseconds) => [0xa1, 0xb2, 0xc3, 0xd4],
        (Endian::Little, TimestampPrecision::Nanoseconds) => [0x4d, 0x3c, 0xb2, 0xa1],
        (Endian::Big, TimestampPrecision::Nanoseconds) => [0xa1, 0xb2, 0x3c, 0x4d],
    };

    writer.write_all(&magic)?;
    write_u16(writer, endian, header.version_major)?;
    write_u16(writer, endian, header.version_minor)?;
    write_i32(writer, endian, header.thiszone)?;
    write_u32(writer, endian, header.sigfigs)?;
    write_u32(writer, endian, header.snaplen)?;
    write_u32(writer, endian, header.link_type.datalink())?;
    Ok(())
}

fn read_exact_or_eof<R>(reader: &mut R, out: &mut [u8]) -> io::Result<bool>
where
    R: Read,
{
    let mut offset = 0;
    while offset < out.len() {
        match reader.read(&mut out[offset..]) {
            Ok(0) if offset == 0 => return Ok(false),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "partial pcap record header",
                ))
            }
            Ok(read) => offset += read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(true)
}

fn read_u16(bytes: &[u8], endian: Endian) -> u16 {
    let mut value = [0u8; 2];
    value.copy_from_slice(bytes);
    match endian {
        Endian::Little => u16::from_le_bytes(value),
        Endian::Big => u16::from_be_bytes(value),
    }
}

fn read_u32(bytes: &[u8], endian: Endian) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(bytes);
    match endian {
        Endian::Little => u32::from_le_bytes(value),
        Endian::Big => u32::from_be_bytes(value),
    }
}

fn read_i32(bytes: &[u8], endian: Endian) -> i32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(bytes);
    match endian {
        Endian::Little => i32::from_le_bytes(value),
        Endian::Big => i32::from_be_bytes(value),
    }
}

fn write_u16<W>(writer: &mut W, endian: Endian, value: u16) -> io::Result<()>
where
    W: Write,
{
    match endian {
        Endian::Little => writer.write_all(&value.to_le_bytes()),
        Endian::Big => writer.write_all(&value.to_be_bytes()),
    }
}

fn write_u32<W>(writer: &mut W, endian: Endian, value: u32) -> io::Result<()>
where
    W: Write,
{
    match endian {
        Endian::Little => writer.write_all(&value.to_le_bytes()),
        Endian::Big => writer.write_all(&value.to_be_bytes()),
    }
}

fn write_i32<W>(writer: &mut W, endian: Endian, value: i32) -> io::Result<()>
where
    W: Write,
{
    match endian {
        Endian::Little => writer.write_all(&value.to_le_bytes()),
        Endian::Big => writer.write_all(&value.to_be_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::{Arp, Ethernet, Ipv4, LinkType, MacAddr, Packet, Raw, Tcp, Udp, ETHERTYPE_ARP};

    use super::{
        dump_pcap, CaptureControl, PcapLinkType, PcapReader, PcapTimestamp, PcapWriter,
        PcapWriterOptions, Sniffer, TimestampPrecision, DLT_EN10MB, PCAP_HEADER_LEN,
    };

    const ARP_REQUEST: &[u8] = fixture_bytes!("bytes/arp-who-has.bin");
    static NEXT_TEMP_PCAP: AtomicUsize = AtomicUsize::new(0);

    fn ethernet_arp_packet() -> Packet {
        Packet::decode_from_link(LinkType::Ethernet, ARP_REQUEST).unwrap()
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

    fn udp_packet(source_port: u16, destination_port: u16) -> Packet {
        Ethernet::new()
            .src(MacAddr::new([0x02, 0, 0, 0, 0, 2]))
            .dst(MacAddr::BROADCAST)
            / Ipv4::new()
                .src_str("203.0.113.30")
                .unwrap()
                .dst_str("198.51.100.20")
                .unwrap()
            / Udp::new().sport(source_port).dport(destination_port)
            / Raw::from("payload")
    }

    fn temp_pcap_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "crafter-pcap-{name}-{}.pcap",
            NEXT_TEMP_PCAP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn write_temp_pcap(name: &str, packets: &[Packet]) -> PathBuf {
        let path = temp_pcap_path(name);
        {
            let mut writer = PcapWriter::create(&path, LinkType::Ethernet).unwrap();
            for packet in packets {
                writer.write_packet(packet).unwrap();
            }
            writer.flush().unwrap();
        }
        path
    }

    #[test]
    fn pcap_write_emits_global_and_record_headers() {
        let packet = ethernet_arp_packet();
        let mut output = Vec::new();
        {
            let mut writer = PcapWriter::from_writer(&mut output, LinkType::Ethernet).unwrap();
            writer
                .write_packet_with_timestamp(&packet, PcapTimestamp::micros(7, 42).unwrap())
                .unwrap();
            writer.flush().unwrap();
        }

        assert_eq!(&output[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(
            u32::from_le_bytes(output[20..24].try_into().unwrap()),
            DLT_EN10MB
        );
        assert_eq!(
            u32::from_le_bytes(
                output[PCAP_HEADER_LEN..PCAP_HEADER_LEN + 4]
                    .try_into()
                    .unwrap()
            ),
            7
        );
        assert_eq!(
            u32::from_le_bytes(
                output[PCAP_HEADER_LEN + 4..PCAP_HEADER_LEN + 8]
                    .try_into()
                    .unwrap()
            ),
            42
        );
        assert_eq!(&output[PCAP_HEADER_LEN + 16..], ARP_REQUEST);
    }

    #[test]
    fn pcap_write_supports_nanosecond_precision() {
        let mut output = Vec::new();
        let options =
            PcapWriterOptions::new(LinkType::Ethernet).precision(TimestampPrecision::Nanoseconds);
        {
            let mut writer = PcapWriter::from_writer_with_options(&mut output, options).unwrap();
            writer
                .write_packet_with_timestamp(
                    &ethernet_arp_packet(),
                    PcapTimestamp::nanos(11, 123).unwrap(),
                )
                .unwrap();
            writer.flush().unwrap();
        }

        assert_eq!(&output[..4], &[0x4d, 0x3c, 0xb2, 0xa1]);
        let reader = PcapReader::from_reader(Cursor::new(output))
            .unwrap()
            .collect_records()
            .unwrap();
        assert_eq!(
            reader[0].timestamp(),
            PcapTimestamp::nanos(11, 123).unwrap()
        );
    }

    #[test]
    fn pcap_read_decodes_ethernet_fixture() {
        let mut output = Vec::new();
        {
            let mut writer = PcapWriter::from_writer(&mut output, LinkType::Ethernet).unwrap();
            writer
                .write_packet_with_timestamp(
                    &ethernet_arp_packet(),
                    PcapTimestamp::micros(1, 500).unwrap(),
                )
                .unwrap();
        }

        let mut reader = PcapReader::from_reader(Cursor::new(output)).unwrap();
        assert_eq!(reader.link_type(), LinkType::Ethernet);

        let record = reader.next_record().unwrap().unwrap();
        assert_eq!(record.timestamp(), PcapTimestamp::micros(1, 500).unwrap());
        assert_eq!(record.link_type(), LinkType::Ethernet);
        assert_eq!(record.pcap_link_type(), PcapLinkType::Ethernet);
        assert_eq!(record.data(), ARP_REQUEST);

        let decoded = record.decode().unwrap();
        assert!(decoded.layer::<Arp>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), ARP_REQUEST);
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn pcap_read_filter_uses_libpcap_bpf() {
        let one = tcp_packet(10, 80);
        let two = tcp_packet(11, 443);
        let path = write_temp_pcap("read-filter", &[one, two]);

        let packets = super::read_pcap_filtered(&path, "tcp and port 10").unwrap();

        assert_eq!(packets.len(), 1);
        assert_eq!(
            packets[0]
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .source_port_value(),
            10
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pcap_read_filter_supports_bpf_host_and_ether_proto() {
        let packet = Ethernet::new()
            .src(MacAddr::new([0x02, 0, 0, 0, 0, 1]))
            .dst(MacAddr::BROADCAST)
            / Ipv4::new()
                .src_str("192.0.2.10")
                .unwrap()
                .dst_str("198.51.100.20")
                .unwrap()
            / Udp::new().sport(53).dport(53000);
        let path = write_temp_pcap("read-filter-host", &[packet]);

        let packets =
            super::read_pcap_filtered(&path, "ip and src host 192.0.2.10 and ether proto 0x0800")
                .unwrap();

        assert_eq!(packets.len(), 1);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pcap_roundtrip_preserves_records_and_decoded_bytes() {
        let packet = ethernet_arp_packet();
        let mut first = Vec::new();
        {
            let mut writer = PcapWriter::from_writer(&mut first, LinkType::Ethernet).unwrap();
            writer
                .write_packet_with_timestamp(&packet, PcapTimestamp::micros(123, 456).unwrap())
                .unwrap();
        }

        let records = PcapReader::from_reader(Cursor::new(&first))
            .unwrap()
            .collect_records()
            .unwrap();
        let mut second = Vec::new();
        {
            let mut writer = PcapWriter::from_writer(&mut second, LinkType::Ethernet).unwrap();
            for record in &records {
                writer.write_record(record).unwrap();
            }
        }

        assert_eq!(first, second);
        let decoded = records[0].decode().unwrap();
        assert_eq!(
            decoded.compile().unwrap().as_bytes(),
            packet.compile().unwrap().as_bytes()
        );
    }

    #[test]
    fn pcap_roundtrip_dump_and_read_helpers() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "crafter-pcap-roundtrip-{}.pcap",
            NEXT_TEMP_PCAP.fetch_add(1, Ordering::Relaxed)
        ));
        let packet = ethernet_arp_packet();

        dump_pcap(&path, [&packet], LinkType::Ethernet).unwrap();
        let packets = super::read_pcap(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(packets.len(), 1);
        assert!(packets[0].packet().layer::<Arp>().is_some());
    }

    #[test]
    fn pcap_write_rejects_link_type_mismatch() {
        let record = super::PcapRecord::new(
            PcapTimestamp::zero(),
            ARP_REQUEST.len() as u32,
            ARP_REQUEST,
            PcapLinkType::Ethernet,
        )
        .unwrap();
        let mut output = Vec::new();
        let mut writer = PcapWriter::from_writer(&mut output, PcapLinkType::RawIp).unwrap();

        assert!(writer.write_record(&record).is_err());
    }

    #[test]
    fn pcap_read_null_loopback_link_type_is_preserved() {
        let packet = crate::NullLoopback::ipv4() / Raw::from("loopback");
        let mut output = Vec::new();
        {
            let mut writer = PcapWriter::from_writer(&mut output, LinkType::NullLoopback).unwrap();
            writer.write_packet(&packet).unwrap();
        }

        let record = PcapReader::from_reader(Cursor::new(output))
            .unwrap()
            .next_record()
            .unwrap()
            .unwrap();
        assert_eq!(record.link_type(), LinkType::NullLoopback);
        assert_eq!(
            record.decode().unwrap().summary(),
            "NullLoopback(family=2) / Raw(len=8)"
        );
    }

    #[test]
    fn pcap_write_uses_autofilled_ether_type() {
        let packet = Ethernet::new() / Arp::new();
        let mut output = Vec::new();
        {
            let mut writer = PcapWriter::from_writer(&mut output, LinkType::Ethernet).unwrap();
            writer.write_packet(&packet).unwrap();
        }

        let record = PcapReader::from_reader(Cursor::new(output))
            .unwrap()
            .next_record()
            .unwrap()
            .unwrap();
        let decoded = record.decode().unwrap();
        assert_eq!(
            decoded.layer::<Ethernet>().unwrap().ethertype_value(),
            Some(ETHERTYPE_ARP)
        );
    }

    #[test]
    fn sniffer_offline_supports_iterator_callback_and_spawn() {
        let tcp = tcp_packet(10, 80);
        let udp = udp_packet(53000, 53001);
        let path = write_temp_pcap("sniffer-offline", &[tcp, udp]);

        let mut capture = Sniffer::offline(&path)
            .filter("tcp")
            .count(1)
            .open()
            .unwrap();
        let first = capture.next_packet().unwrap().unwrap();
        assert!(first.packet().layer::<Tcp>().is_some());
        assert!(capture.next_packet().unwrap().is_none());

        let mut summaries = Vec::new();
        let callback_count = Sniffer::offline(&path)
            .filter("udp")
            .capture(10, |packet| {
                summaries.push(packet.packet().summary());
                Ok(CaptureControl::Continue)
            })
            .unwrap();
        assert_eq!(callback_count, 1);
        assert!(summaries[0].contains("Udp"));

        let spawned_packets = Sniffer::offline(&path)
            .filter("tcp or udp")
            .spawn(2)
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(spawned_packets.len(), 2);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn bpf_filter_sniffer_offline_uses_libpcap() {
        let https = tcp_packet(12345, 443);
        let http = tcp_packet(12345, 80);
        let path = write_temp_pcap("bpf-filter", &[https, http]);

        let packets = Sniffer::offline(&path)
            .filter("tcp and dst port 443")
            .collect()
            .unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(
            packets[0]
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .destination_port_value(),
            443
        );

        let packets = Sniffer::offline(&path)
            .filter("tcp and not dst port 443")
            .collect()
            .unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(
            packets[0]
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .destination_port_value(),
            80
        );

        let mut callback_count = 0;
        let accepted = Sniffer::offline(&path)
            .filter("tcp")
            .capture(10, |_packet| {
                callback_count += 1;
                Ok(CaptureControl::Stop)
            })
            .unwrap();
        assert_eq!(accepted, 1);
        assert_eq!(callback_count, 1);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    #[ignore = "live capture is reserved for disposable live-lab execution"]
    fn sniffer_live_capture_live_lab_only() {
        let Some(iface) = std::env::var_os("LIBCRAFTER_LIVE_CAPTURE_IFACE") else {
            return;
        };
        let packets = Sniffer::interface(iface.to_string_lossy().into_owned())
            .filter("icmp or arp")
            .count(1)
            .timeout(Duration::from_secs(2))
            .collect()
            .unwrap();
        assert!(packets.len() <= 1);
    }
}
