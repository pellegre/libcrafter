use std::time::Duration;

use crate::Packet;

use super::error::Result;
use super::send::{SendMode, SendOptions, SendReport, SocketSender};
use super::send_recv::SendRecv;
pub use super::send_recv::{
    send_recv_packets, BatchSendRecv, BatchSendRecvEntry, BatchSendRecvReport,
    PacketBatchSendRecvExt,
};

pub struct BatchSend {
    send_options: SendOptions,
    concurrency_limit: usize,
    retries: usize,
    retry_timeout: Duration,
}

impl BatchSend {
    /// Create batch send options with libcrafter-like conservative defaults.
    pub fn new() -> Self {
        Self {
            send_options: SendOptions::new(),
            concurrency_limit: 64,
            retries: 1,
            retry_timeout: Duration::ZERO,
        }
    }

    /// Select the interface used for sending.
    pub fn interface(mut self, interface: impl Into<String>) -> Self {
        self.send_options = self.send_options.interface(interface);
        self
    }

    /// Compatibility alias for [`Self::interface`].
    pub fn iface(self, interface: impl Into<String>) -> Self {
        self.interface(interface)
    }

    /// Set the send mode used for each packet.
    pub fn mode(mut self, mode: SendMode) -> Self {
        self.send_options = self.send_options.mode(mode);
        self
    }

    /// Require link-layer send plans.
    pub fn link_layer(self) -> Self {
        self.mode(SendMode::LinkLayer)
    }

    /// Require network-layer send plans.
    pub fn network_layer(self) -> Self {
        self.mode(SendMode::NetworkLayer)
    }

    /// Compile and plan sends without transmitting bytes.
    pub fn dry_run(mut self) -> Self {
        self.send_options = self.send_options.dry_run();
        self
    }

    /// Enable live transmission.
    pub fn live(mut self) -> Self {
        self.send_options = self.send_options.live();
        self
    }

    /// Set the raw socket write timeout hint.
    pub fn write_timeout(mut self, timeout: Duration) -> Self {
        self.send_options = self.send_options.write_timeout(timeout);
        self
    }

    /// Set the raw socket write buffer size hint.
    pub fn write_buffer_size(mut self, size: usize) -> Self {
        self.send_options = self.send_options.write_buffer_size(size);
        self
    }

    /// Set the maximum number of requests processed in one batch window.
    pub fn concurrency_limit(mut self, limit: usize) -> Self {
        self.concurrency_limit = limit.max(1);
        self
    }

    /// Set the number of send attempts per packet. A zero value is treated as one attempt.
    pub fn retries(mut self, retries: usize) -> Self {
        self.retries = retries.max(1);
        self
    }

    /// libcrafter-style singular alias for [`Self::retries`].
    pub fn retry(self, retries: usize) -> Self {
        self.retries(retries)
    }

    /// Set the delay between live retry attempts. Dry-runs never sleep.
    pub fn retry_timeout(mut self, timeout: Duration) -> Self {
        self.retry_timeout = timeout;
        self
    }

    /// Alias for [`Self::retry_timeout`].
    pub fn timeout(self, timeout: Duration) -> Self {
        self.retry_timeout(timeout)
    }

    /// Borrow the underlying send options.
    pub const fn send_options(&self) -> &SendOptions {
        &self.send_options
    }

    /// Configured concurrency limit.
    pub const fn concurrency_limit_value(&self) -> usize {
        self.concurrency_limit
    }

    /// Configured retry count.
    pub const fn retries_value(&self) -> usize {
        self.retries
    }

    /// Configured live retry delay.
    pub const fn retry_timeout_value(&self) -> Duration {
        self.retry_timeout
    }

    /// Send every packet and return reports aligned with the request order.
    pub fn send_all(&self, packets: &[Packet]) -> Result<BatchSendReport> {
        let mut entries = (0..packets.len())
            .map(BatchSendEntry::new)
            .collect::<Vec<_>>();
        let sender = SocketSender::new(self.send_options.clone());

        for chunk_start in (0..packets.len()).step_by(self.concurrency_limit) {
            let chunk_end = (chunk_start + self.concurrency_limit).min(packets.len());
            for attempt in 0..self.retries {
                for request_index in chunk_start..chunk_end {
                    entries[request_index]
                        .send_reports
                        .push(sender.send(&packets[request_index])?);
                }
                maybe_wait_between_live_retries(
                    self.send_options.is_dry_run(),
                    self.retry_timeout,
                    attempt,
                    self.retries,
                );
            }
        }

        Ok(BatchSendReport::new(
            entries,
            self.concurrency_limit,
            self.retries,
            self.retry_timeout,
            self.send_options.is_dry_run(),
        ))
    }
}

impl Default for BatchSend {
    fn default() -> Self {
        Self::new()
    }
}

impl From<SendOptions> for BatchSend {
    fn from(send_options: SendOptions) -> Self {
        Self::new().with_send_options(send_options)
    }
}

impl From<SendRecv> for BatchSend {
    fn from(send_recv: SendRecv) -> Self {
        Self::new()
            .with_send_options(send_recv.send_options().clone())
            .retries(send_recv.retries_value())
            .retry_timeout(send_recv.timeout_value())
    }
}

impl From<&str> for BatchSend {
    fn from(interface: &str) -> Self {
        Self::new().iface(interface)
    }
}

impl From<String> for BatchSend {
    fn from(interface: String) -> Self {
        Self::new().iface(interface)
    }
}

impl BatchSend {
    fn with_send_options(mut self, send_options: SendOptions) -> Self {
        self.send_options = send_options;
        self
    }
}

/// Per-request result in a batch send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchSendEntry {
    request_index: usize,
    send_reports: Vec<SendReport>,
}

impl BatchSendEntry {
    fn new(request_index: usize) -> Self {
        Self {
            request_index,
            send_reports: Vec::new(),
        }
    }

    /// Index of the request packet in the input collection.
    pub const fn request_index(&self) -> usize {
        self.request_index
    }

    /// Per-attempt send reports for this request.
    pub fn send_reports(&self) -> &[SendReport] {
        &self.send_reports
    }

    /// Number of send attempts made for this request.
    pub fn attempts(&self) -> usize {
        self.send_reports.len()
    }
}

/// Detailed result returned by batch send operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchSendReport {
    entries: Vec<BatchSendEntry>,
    concurrency_limit: usize,
    retries: usize,
    retry_timeout: Duration,
    dry_run: bool,
}

impl BatchSendReport {
    fn new(
        entries: Vec<BatchSendEntry>,
        concurrency_limit: usize,
        retries: usize,
        retry_timeout: Duration,
        dry_run: bool,
    ) -> Self {
        Self {
            entries,
            concurrency_limit,
            retries,
            retry_timeout,
            dry_run,
        }
    }

    /// Per-request reports in the same order as the input packets.
    pub fn entries(&self) -> &[BatchSendEntry] {
        &self.entries
    }

    /// Borrow one report by request index.
    pub fn entry(&self, request_index: usize) -> Option<&BatchSendEntry> {
        self.entries.get(request_index)
    }

    /// Number of request packets represented by this report.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true when no request packets were supplied.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Concurrency limit used by the batch.
    pub const fn concurrency_limit(&self) -> usize {
        self.concurrency_limit
    }

    /// Retry count used by the batch.
    pub const fn retries(&self) -> usize {
        self.retries
    }

    /// Live retry delay used by the batch.
    pub const fn retry_timeout(&self) -> Duration {
        self.retry_timeout
    }

    /// Return true when the batch was compile-only.
    pub const fn is_dry_run(&self) -> bool {
        self.dry_run
    }
}

/// Extension methods for sending packet collections.
pub trait PacketBatchSendExt {
    /// Send every packet and return reports aligned with the request order.
    fn batch_send(&self, options: impl Into<BatchSend>) -> Result<BatchSendReport>;

    /// Compile and plan every packet without transmitting bytes.
    fn batch_send_dry_run(&self, options: impl Into<BatchSend>) -> Result<BatchSendReport>;
}

impl PacketBatchSendExt for [Packet] {
    fn batch_send(&self, options: impl Into<BatchSend>) -> Result<BatchSendReport> {
        options.into().send_all(self)
    }

    fn batch_send_dry_run(&self, options: impl Into<BatchSend>) -> Result<BatchSendReport> {
        options.into().dry_run().send_all(self)
    }
}

/// Send a packet collection in one call.
pub fn send_packets(packets: &[Packet], options: impl Into<BatchSend>) -> Result<BatchSendReport> {
    options.into().send_all(packets)
}

fn maybe_wait_between_live_retries(
    dry_run: bool,
    timeout: Duration,
    attempt: usize,
    attempts: usize,
) {
    if !dry_run && !timeout.is_zero() && attempt + 1 < attempts {
        std::thread::sleep(timeout);
    }
}
