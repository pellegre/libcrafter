//! Offline pcap read/write helpers.

#![forbid(unsafe_code)]

use std::borrow::Borrow;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use crafter_core::{
    Arp, CrafterError, Ethernet, Icmp, Icmpv6, Ipv4, Ipv6, LinkType, LinuxSll, NetworkLayer,
    Packet, ProtocolRegistry, Tcp, Udp, Vlan,
};

const PCAP_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const DEFAULT_SNAPLEN: u32 = 65_535;

/// BSD null/loopback pcap data-link type.
pub const DLT_NULL: u32 = 0;
/// Ethernet pcap data-link type.
pub const DLT_EN10MB: u32 = 1;
/// Raw IPv4/IPv6 pcap data-link type.
pub const DLT_RAW: u32 = 12;
/// BSD loopback pcap data-link type.
pub const DLT_LOOP: u32 = 108;
/// Linux cooked capture v1 pcap data-link type.
pub const DLT_LINUX_SLL: u32 = 113;

/// Result type returned by pcap helpers.
pub type Result<T> = std::result::Result<T, PcapError>;

/// Errors returned by pcap file helpers.
#[derive(Debug)]
pub enum PcapError {
    /// An underlying file or stream operation failed.
    Io(io::Error),
    /// Packet compile or decode failed.
    Packet(CrafterError),
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
    /// The offline filter string is outside the supported deterministic subset.
    InvalidFilter {
        /// Original filter expression.
        filter: String,
        /// Stable reason for diagnostics.
        reason: &'static str,
    },
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Packet(err) => write!(f, "{err}"),
            Self::InvalidHeader(reason) => write!(f, "invalid pcap header: {reason}"),
            Self::InvalidRecord(reason) => write!(f, "invalid pcap record: {reason}"),
            Self::RecordTooLarge { field, max, actual } => {
                write!(f, "pcap {field} value {actual} exceeds maximum {max}")
            }
            Self::InvalidFilter { filter, reason } => {
                write!(f, "invalid pcap filter '{filter}': {reason}")
            }
        }
    }
}

impl std::error::Error for PcapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Packet(err) => Some(err),
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
            DLT_RAW => Self::RawIp,
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
    pub fn decode(self, bytes: impl AsRef<[u8]>) -> crafter_core::Result<Packet> {
        self.decode_with_registry(&ProtocolRegistry::new(), bytes)
    }

    /// Decode bytes using an explicit protocol registry.
    pub fn decode_with_registry(
        self,
        registry: &ProtocolRegistry,
        bytes: impl AsRef<[u8]>,
    ) -> crafter_core::Result<Packet> {
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
    pub fn decode(&self) -> crafter_core::Result<Packet> {
        self.link_type.decode(&self.data)
    }

    /// Decode this record with an explicit protocol registry.
    pub fn decode_with_registry(
        &self,
        registry: &ProtocolRegistry,
    ) -> crafter_core::Result<Packet> {
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
    filter: PcapFilter,
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
            filter: PcapFilter::all(),
        })
    }

    /// Attach an offline filter expression.
    ///
    /// Supported expressions intentionally cover a deterministic subset:
    /// `tcp`, `udp`, `icmp`, `icmp6`, `ip`, `ip6`, `arp`, `port N`,
    /// `src port N`, `dst port N`, `host ADDRESS`, `src host ADDRESS`,
    /// `dst host ADDRESS`, `ether proto VALUE`, and `and`/`or`/`not`.
    pub fn filter(mut self, filter: &str) -> Result<Self> {
        self.filter = PcapFilter::parse(filter)?;
        Ok(self)
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
        loop {
            let record = match self.read_next_record()? {
                Some(record) => record,
                None => return Ok(None),
            };

            if self.filter.matches(&record)? {
                return Ok(Some(record));
            }
        }
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
    PcapReader::open(path)?.filter(filter)?.collect_packets()
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
    pub use crate::{FileSniffer, PcapFilter};
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapFilter {
    original: String,
    expression: Option<FilterExpression>,
}

impl PcapFilter {
    /// Match every record.
    pub fn all() -> Self {
        Self {
            original: String::new(),
            expression: None,
        }
    }

    /// Parse a deterministic offline filter subset.
    pub fn parse(filter: &str) -> Result<Self> {
        let original = filter.trim().to_string();
        if original.is_empty() {
            return Ok(Self::all());
        }

        let tokens = tokenize_filter(&original);
        let mut parser = FilterParser::new(&original, tokens);
        let expression = parser.parse_expression()?;
        if parser.peek().is_some() {
            return Err(invalid_filter(&original, "unexpected trailing token"));
        }

        Ok(Self {
            original,
            expression: Some(expression),
        })
    }

    /// Original filter string.
    pub fn original(&self) -> &str {
        &self.original
    }

    /// Return true when the filter accepts the record.
    pub fn matches(&self, record: &PcapRecord) -> Result<bool> {
        match &self.expression {
            Some(expression) => {
                let packet = record.decode()?;
                Ok(expression.matches(&packet))
            }
            None => Ok(true),
        }
    }
}

impl Default for PcapFilter {
    fn default() -> Self {
        Self::all()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FilterExpression {
    Protocol(FilterProtocol),
    Port(FilterDirection, u16),
    Host(FilterDirection, IpAddr),
    EtherProto(u16),
    And(Box<FilterExpression>, Box<FilterExpression>),
    Or(Box<FilterExpression>, Box<FilterExpression>),
    Not(Box<FilterExpression>),
}

impl FilterExpression {
    fn matches(&self, packet: &Packet) -> bool {
        match self {
            Self::Protocol(protocol) => protocol.matches(packet),
            Self::Port(direction, port) => port_matches(packet, *direction, *port),
            Self::Host(direction, host) => host_matches(packet, *direction, *host),
            Self::EtherProto(ethertype) => ethertype_matches(packet, *ethertype),
            Self::And(left, right) => left.matches(packet) && right.matches(packet),
            Self::Or(left, right) => left.matches(packet) || right.matches(packet),
            Self::Not(inner) => !inner.matches(packet),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterProtocol {
    Arp,
    Icmp,
    Icmpv6,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
}

impl FilterProtocol {
    fn matches(self, packet: &Packet) -> bool {
        match self {
            Self::Arp => packet.layer::<Arp>().is_some(),
            Self::Icmp => packet.layer::<Icmp>().is_some(),
            Self::Icmpv6 => packet.layer::<Icmpv6>().is_some(),
            Self::Ipv4 => packet.layer::<Ipv4>().is_some(),
            Self::Ipv6 => packet.layer::<Ipv6>().is_some(),
            Self::Tcp => packet.layer::<Tcp>().is_some(),
            Self::Udp => packet.layer::<Udp>().is_some(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterDirection {
    Any,
    Source,
    Destination,
}

#[derive(Debug)]
struct FilterParser<'a> {
    original: &'a str,
    tokens: Vec<String>,
    offset: usize,
}

impl<'a> FilterParser<'a> {
    fn new(original: &'a str, tokens: Vec<String>) -> Self {
        Self {
            original,
            tokens,
            offset: 0,
        }
    }

    fn parse_expression(&mut self) -> Result<FilterExpression> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<FilterExpression> {
        let mut expr = self.parse_and()?;
        while self.consume("or") {
            let right = self.parse_and()?;
            expr = FilterExpression::Or(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    fn parse_and(&mut self) -> Result<FilterExpression> {
        let mut expr = self.parse_not()?;
        while self.consume("and") || self.starts_implicit_and() {
            let right = self.parse_not()?;
            expr = FilterExpression::And(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    fn parse_not(&mut self) -> Result<FilterExpression> {
        if self.consume("not") {
            Ok(FilterExpression::Not(Box::new(self.parse_not()?)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<FilterExpression> {
        if self.consume("(") {
            let expr = self.parse_expression()?;
            if !self.consume(")") {
                return Err(invalid_filter(self.original, "missing closing parenthesis"));
            }
            return Ok(expr);
        }

        let token = self
            .next()
            .ok_or_else(|| invalid_filter(self.original, "expected filter term"))?;
        match token.as_str() {
            "arp" => Ok(FilterExpression::Protocol(FilterProtocol::Arp)),
            "icmp" => Ok(FilterExpression::Protocol(FilterProtocol::Icmp)),
            "icmp6" | "icmpv6" => Ok(FilterExpression::Protocol(FilterProtocol::Icmpv6)),
            "ip" => Ok(FilterExpression::Protocol(FilterProtocol::Ipv4)),
            "ip6" | "ipv6" => Ok(FilterExpression::Protocol(FilterProtocol::Ipv6)),
            "tcp" => Ok(FilterExpression::Protocol(FilterProtocol::Tcp)),
            "udp" => Ok(FilterExpression::Protocol(FilterProtocol::Udp)),
            "port" => self.parse_port(FilterDirection::Any),
            "host" => self.parse_host(FilterDirection::Any),
            "src" => self.parse_directed(FilterDirection::Source),
            "dst" => self.parse_directed(FilterDirection::Destination),
            "ether" => self.parse_ether(),
            _ => Err(invalid_filter(self.original, "unsupported filter term")),
        }
    }

    fn parse_directed(&mut self, direction: FilterDirection) -> Result<FilterExpression> {
        let token = self
            .next()
            .ok_or_else(|| invalid_filter(self.original, "expected directed filter term"))?;
        match token.as_str() {
            "port" => self.parse_port(direction),
            "host" => self.parse_host(direction),
            _ => Err(invalid_filter(
                self.original,
                "expected 'port' or 'host' after direction",
            )),
        }
    }

    fn parse_port(&mut self, direction: FilterDirection) -> Result<FilterExpression> {
        let token = self
            .next()
            .ok_or_else(|| invalid_filter(self.original, "expected port number"))?;
        Ok(FilterExpression::Port(
            direction,
            parse_u16(&token, self.original, "port")?,
        ))
    }

    fn parse_host(&mut self, direction: FilterDirection) -> Result<FilterExpression> {
        let token = self
            .next()
            .ok_or_else(|| invalid_filter(self.original, "expected host address"))?;
        let host = token
            .parse::<IpAddr>()
            .map_err(|_| invalid_filter(self.original, "host must be an IP address"))?;
        Ok(FilterExpression::Host(direction, host))
    }

    fn parse_ether(&mut self) -> Result<FilterExpression> {
        if !self.consume("proto") {
            return Err(invalid_filter(
                self.original,
                "expected 'proto' after ether",
            ));
        }
        let token = self
            .next()
            .ok_or_else(|| invalid_filter(self.original, "expected ethertype"))?;
        Ok(FilterExpression::EtherProto(parse_u16(
            &token,
            self.original,
            "ethertype",
        )?))
    }

    fn starts_implicit_and(&self) -> bool {
        matches!(
            self.peek(),
            Some(
                "arp"
                    | "icmp"
                    | "icmp6"
                    | "icmpv6"
                    | "ip"
                    | "ip6"
                    | "ipv6"
                    | "tcp"
                    | "udp"
                    | "port"
                    | "host"
                    | "src"
                    | "dst"
                    | "ether"
                    | "not"
                    | "("
            )
        )
    }

    fn consume(&mut self, expected: &str) -> bool {
        if self.peek() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn next(&mut self) -> Option<String> {
        let token = self.tokens.get(self.offset)?.clone();
        self.offset += 1;
        Some(token)
    }

    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.offset).map(String::as_str)
    }
}

fn invalid_filter(filter: &str, reason: &'static str) -> PcapError {
    PcapError::InvalidFilter {
        filter: filter.to_string(),
        reason,
    }
}

fn tokenize_filter(filter: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    for ch in filter.chars() {
        match ch {
            '(' | ')' => {
                if !current.is_empty() {
                    tokens.push(current.to_ascii_lowercase());
                    current.clear();
                }
                tokens.push(ch.to_string());
            }
            ch if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(current.to_ascii_lowercase());
                    current.clear();
                }
            }
            ch => current.push(ch),
        }
    }

    if !current.is_empty() {
        tokens.push(current.to_ascii_lowercase());
    }

    tokens
}

fn parse_u16(token: &str, original: &str, field: &'static str) -> Result<u16> {
    let parsed = if let Some(hex) = token.strip_prefix("0x") {
        u16::from_str_radix(hex, 16)
    } else {
        token.parse()
    };
    parsed.map_err(|_| invalid_filter(original, field))
}

fn port_matches(packet: &Packet, direction: FilterDirection, port: u16) -> bool {
    let udp = packet.layer::<Udp>().is_some_and(|udp| {
        directed_port_matches(
            udp.source_port_value(),
            udp.destination_port_value(),
            direction,
            port,
        )
    });
    let tcp = packet.layer::<Tcp>().is_some_and(|tcp| {
        directed_port_matches(
            tcp.source_port_value(),
            tcp.destination_port_value(),
            direction,
            port,
        )
    });

    udp || tcp
}

fn directed_port_matches(
    source: u16,
    destination: u16,
    direction: FilterDirection,
    port: u16,
) -> bool {
    match direction {
        FilterDirection::Any => source == port || destination == port,
        FilterDirection::Source => source == port,
        FilterDirection::Destination => destination == port,
    }
}

fn host_matches(packet: &Packet, direction: FilterDirection, host: IpAddr) -> bool {
    match host {
        IpAddr::V4(host) => {
            packet.layer::<Ipv4>().is_some_and(|ip| {
                directed_host_matches(
                    ip.source().into(),
                    ip.destination().into(),
                    direction,
                    host.into(),
                )
            }) || packet.layer::<Arp>().is_some_and(|arp| {
                let source = arp.sender_ipv4().map(IpAddr::V4);
                let destination = arp.target_ipv4().map(IpAddr::V4);
                directed_optional_host_matches(source, destination, direction, IpAddr::V4(host))
            })
        }
        IpAddr::V6(host) => packet.layer::<Ipv6>().is_some_and(|ip| {
            directed_host_matches(
                ip.source().into(),
                ip.destination().into(),
                direction,
                host.into(),
            )
        }),
    }
}

fn directed_host_matches(
    source: IpAddr,
    destination: IpAddr,
    direction: FilterDirection,
    host: IpAddr,
) -> bool {
    match direction {
        FilterDirection::Any => source == host || destination == host,
        FilterDirection::Source => source == host,
        FilterDirection::Destination => destination == host,
    }
}

fn directed_optional_host_matches(
    source: Option<IpAddr>,
    destination: Option<IpAddr>,
    direction: FilterDirection,
    host: IpAddr,
) -> bool {
    match direction {
        FilterDirection::Any => source == Some(host) || destination == Some(host),
        FilterDirection::Source => source == Some(host),
        FilterDirection::Destination => destination == Some(host),
    }
}

fn ethertype_matches(packet: &Packet, ethertype: u16) -> bool {
    packet
        .layer::<Ethernet>()
        .and_then(Ethernet::ethertype_value)
        .is_some_and(|value| value == ethertype)
        || packet
            .layer::<Vlan>()
            .is_some_and(|vlan| vlan.ethertype_value() == ethertype)
        || packet
            .layer::<LinuxSll>()
            .is_some_and(|sll| sll.protocol_value() == ethertype)
}

fn decode_raw_ip_with_registry(
    registry: &ProtocolRegistry,
    bytes: &[u8],
) -> crafter_core::Result<Packet> {
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

    use crafter_core::{
        Arp, Ethernet, Ipv4, LinkType, MacAddr, Packet, Raw, Tcp, Udp, ETHERTYPE_ARP,
    };

    use super::{
        dump_pcap, PcapLinkType, PcapReader, PcapTimestamp, PcapWriter, PcapWriterOptions,
        TimestampPrecision, DLT_EN10MB, PCAP_HEADER_LEN,
    };

    const ARP_REQUEST: &[u8] = include_bytes!("../../../tests/fixtures/scapy/arp-request.bin");

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
    fn pcap_read_filter_accepts_tcpdump_style_subset() {
        let one = tcp_packet(10, 80);
        let two = tcp_packet(11, 443);
        let mut output = Vec::new();
        {
            let mut writer = PcapWriter::from_writer(&mut output, LinkType::Ethernet).unwrap();
            writer.write_packet(&one).unwrap();
            writer.write_packet(&two).unwrap();
        }

        let packets = PcapReader::from_reader(Cursor::new(output))
            .unwrap()
            .filter("tcp and port 10")
            .unwrap()
            .collect_packets()
            .unwrap();

        assert_eq!(packets.len(), 1);
        assert_eq!(
            packets[0]
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .source_port_value(),
            10
        );
    }

    #[test]
    fn pcap_read_filter_supports_host_and_ether_proto() {
        let packet = Ethernet::new()
            .src(MacAddr::new([0x02, 0, 0, 0, 0, 1]))
            .dst(MacAddr::BROADCAST)
            / Ipv4::new()
                .src_str("192.0.2.10")
                .unwrap()
                .dst_str("198.51.100.20")
                .unwrap()
            / Udp::new().sport(53).dport(53000);
        let mut output = Vec::new();
        {
            let mut writer = PcapWriter::from_writer(&mut output, LinkType::Ethernet).unwrap();
            writer.write_packet(&packet).unwrap();
        }

        let packets = PcapReader::from_reader(Cursor::new(output))
            .unwrap()
            .filter("ip and src host 192.0.2.10 and ether proto 0x0800")
            .unwrap()
            .collect_packets()
            .unwrap();

        assert_eq!(packets.len(), 1);
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
            "crafter-pcap-roundtrip-{}-{}.pcap",
            std::process::id(),
            1
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
        let packet = crafter_core::NullLoopback::ipv4() / Raw::from("loopback");
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
}
