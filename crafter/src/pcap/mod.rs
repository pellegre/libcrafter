//! Classic pcap read/write, record metadata, and libpcap backend helpers.
//!
//! This module owns the low-level pcap file codec: [`PcapReader`],
//! [`PcapWriter`], [`PcapRecord`], [`PcapPacket`], [`PcapTimestamp`],
//! [`PcapLinkType`], timestamp precision, and offline libpcap BPF filtering.
//! It is intentionally not the high-level packet capture API; in the wire
//! architecture, pcap is one backend family and one file format.
//!
//! New sniffer code should use [`crate::wire::Sniffer`] with a
//! [`crate::wire::PacketWire`] source, such as `PacketWire::pcap_file(...)` or
//! `PacketWire::pcap_interface(...)`. Recording packet streams should use
//! `PacketWire::pcap_recorder(...)` through the wire writer/transmitter path
//! when transform metadata and backend write reports matter.

#![forbid(unsafe_code)]

mod codec;
mod error;
mod libpcap;
mod types;

pub mod reader;
pub mod writer;

pub use error::{PcapError, Result};
pub(crate) use libpcap::{LibpcapCapture, LibpcapOfflineCapture};
pub use reader::{read_pcap, read_pcap_filtered, PcapReader, PcapRecords};
pub use types::{
    PcapHeader, PcapLinkType, PcapPacket, PcapRecord, PcapTimestamp, TimestampPrecision,
    DLT_EN10MB, DLT_IEEE802_11, DLT_IEEE802_11_RADIO, DLT_LINUX_SLL, DLT_LOOP, DLT_NULL, DLT_RAW,
    LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP,
};
pub use writer::{dump_pcap, PcapWriter, PcapWriterOptions};

#[cfg(test)]
mod tests;
