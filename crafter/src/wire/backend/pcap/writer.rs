use std::borrow::Borrow;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::Packet;

use super::codec::{write_header, write_u32, Endian};
use super::{
    PcapError, PcapHeader, PcapLinkType, PcapRecord, PcapTimestamp, Result, TimestampPrecision,
};

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
