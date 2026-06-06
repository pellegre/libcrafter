//! Classic pcap read/write, libpcap BPF filtering, and bounded
//! capture helpers.
//!
//! Offline pcap APIs are rootless and deterministic. Live capture is explicit
//! and bounded by count and timeout controls, using native libpcap for interface
//! capture and BPF filtering.

#![forbid(unsafe_code)]

mod codec;
mod error;
mod libpcap;
mod types;

pub mod capture;
pub mod reader;
pub mod writer;

pub use capture::{Capture, CaptureControl, CaptureHandle, Sniffer};
pub use error::{PcapError, Result};
pub(crate) use libpcap::{LibpcapCapture, LibpcapOfflineCapture};
pub use reader::{read_pcap, read_pcap_filtered, FileSniffer, PcapReader, PcapRecords};
pub use types::{
    PcapHeader, PcapLinkType, PcapPacket, PcapRecord, PcapTimestamp, TimestampPrecision,
    DLT_EN10MB, DLT_IEEE802_11, DLT_IEEE802_11_RADIO, DLT_LINUX_SLL, DLT_LOOP, DLT_NULL, DLT_RAW,
    LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP,
};
pub use writer::{dump_pcap, PcapWriter, PcapWriterOptions};

#[cfg(test)]
mod tests;
