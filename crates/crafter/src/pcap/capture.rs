use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::codec::DEFAULT_SNAPLEN;
use super::libpcap::{LibpcapCapture, LibpcapOfflineCapture};
pub use super::reader::FileSniffer;
use super::{PcapError, PcapPacket, PcapReader, PcapRecord, Result};

const DEFAULT_CAPTURE_TIMEOUT: Duration = Duration::from_secs(10);

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
            record.timestamp(),
            record.original_len(),
            record.data(),
            record.pcap_link_type(),
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

fn capture_deadline(timeout: Option<Duration>) -> Option<Instant> {
    timeout.and_then(|duration| Instant::now().checked_add(duration))
}
