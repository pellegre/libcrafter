//! Classic pcap read/write and libpcap BPF filtering helpers.
//!
//! Offline pcap APIs are rootless and deterministic. Public live capture uses
//! the `wire` pcap backend; this module keeps the low-level pcap file codec and
//! offline libpcap filtering surface.

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
