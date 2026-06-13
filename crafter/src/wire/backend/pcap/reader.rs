use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use crate::LinkType;

use super::codec::{
    parse_header, read_exact_or_eof, read_u32, Endian, PCAP_HEADER_LEN, PCAP_RECORD_HEADER_LEN,
};
use super::libpcap::LibpcapOfflineCapture;
use super::{PcapError, PcapHeader, PcapLinkType, PcapPacket, PcapRecord, PcapTimestamp, Result};

/// Offline pcap file reader.
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
                record.timestamp(),
                record.original_len(),
                record.data(),
                record.pcap_link_type(),
                packet,
            ));
        }
        Ok(packets)
    }

    fn read_next_record(&mut self) -> Result<Option<PcapRecord>> {
        let mut header = [0u8; PCAP_RECORD_HEADER_LEN];
        match read_exact_or_eof(&mut self.reader, &mut header) {
            Ok(true) => {}
            Ok(false) => return Ok(None),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(PcapError::InvalidRecord("partial pcap record header"));
            }
            Err(err) => return Err(PcapError::Io(err)),
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
        if let Err(err) = self.reader.read_exact(&mut data) {
            if err.kind() == io::ErrorKind::UnexpectedEof {
                return Err(PcapError::InvalidRecord("truncated pcap record body"));
            }
            return Err(PcapError::Io(err));
        }

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

/// File-backed pcap reader alias.
///
/// Prefer [`crate::wire::Sniffer`] with `PacketWire::pcap_file(...)` for
/// packet-stream capture and transform pipelines.
pub type FileSniffer = PcapReader<BufReader<File>>;

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
            record.timestamp(),
            record.original_len(),
            record.data(),
            record.pcap_link_type(),
            packet,
        ));
    }
    Ok(packets)
}
