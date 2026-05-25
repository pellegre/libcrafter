use std::fmt;
use std::io;

use crate::CrafterError;

pub type Result<T> = std::result::Result<T, PcapError>;

/// Errors returned by pcap file helpers.
#[derive(Debug)]
pub enum PcapError {
    /// An underlying file or stream operation failed.
    Io(io::Error),
    /// Packet compile or decode failed.
    Packet(CrafterError),
    /// Native libpcap failed while opening, filtering, or reading capture.
    Libpcap(::pcap::Error),
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

impl From<::pcap::Error> for PcapError {
    fn from(value: ::pcap::Error) -> Self {
        Self::Libpcap(value)
    }
}
