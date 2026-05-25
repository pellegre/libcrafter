use std::time::Duration;

use crate::pcap::Sniffer;
use crate::Packet;

use super::error::Result;
use super::reply::{batch_reply_filter, combine_filters};
pub use super::reply::{reply_filter, reply_matches, ReplyMatcher};
use super::send::{validated_interface, SendMode, SendOptions, SendReport, SocketSender};

/// Configuration object for send-and-receive request/reply workflows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRecv {
    send_options: SendOptions,
    timeout: Duration,
    retries: usize,
    filter: Option<String>,
    capture_limit: usize,
}

impl SendRecv {
    /// Create send/receive options with libcrafter-like defaults.
    pub fn new() -> Self {
        Self {
            send_options: SendOptions::new(),
            timeout: Duration::from_secs(1),
            retries: 3,
            filter: None,
            capture_limit: 64,
        }
    }

    /// Select the interface used for both sending and capture.
    pub fn interface(mut self, interface: impl Into<String>) -> Self {
        self.send_options = self.send_options.interface(interface);
        self
    }

    /// Compatibility alias for [`Self::interface`].
    pub fn iface(self, interface: impl Into<String>) -> Self {
        self.interface(interface)
    }

    /// Set the send mode.
    pub fn mode(mut self, mode: SendMode) -> Self {
        self.send_options = self.send_options.mode(mode);
        self
    }

    /// Require a link-layer send path.
    pub fn link_layer(self) -> Self {
        self.mode(SendMode::LinkLayer)
    }

    /// Require a network-layer send path.
    pub fn network_layer(self) -> Self {
        self.mode(SendMode::NetworkLayer)
    }

    /// Compile and plan the send without transmitting or opening capture.
    pub fn dry_run(mut self) -> Self {
        self.send_options = self.send_options.dry_run();
        self
    }

    /// Enable live send/receive behavior.
    pub fn live(mut self) -> Self {
        self.send_options = self.send_options.live();
        self
    }

    /// Set the per-attempt capture timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the number of send attempts. A zero value is treated as one attempt.
    pub fn retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    /// libcrafter-style singular alias for [`Self::retries`].
    pub fn retry(self, retries: usize) -> Self {
        self.retries(retries)
    }

    /// Add a caller-supplied BPF filter. It is combined with the derived reply filter.
    pub fn filter(mut self, filter: impl Into<String>) -> Self {
        let filter = filter.into();
        self.filter = (!filter.trim().is_empty()).then_some(filter);
        self
    }

    /// Remove any caller-supplied BPF filter.
    pub fn clear_filter(mut self) -> Self {
        self.filter = None;
        self
    }

    /// Set the maximum captured packets inspected per send attempt.
    pub fn capture_limit(mut self, capture_limit: usize) -> Self {
        self.capture_limit = capture_limit.max(1);
        self
    }

    /// Borrow the underlying send options.
    pub const fn send_options(&self) -> &SendOptions {
        &self.send_options
    }

    /// Per-attempt timeout.
    pub const fn timeout_value(&self) -> Duration {
        self.timeout
    }

    /// Configured retry count.
    pub const fn retries_value(&self) -> usize {
        self.retries
    }

    /// Caller-supplied BPF filter, if present.
    pub fn user_filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }

    /// Effective BPF filter used for capture, combining derived and user filters.
    pub fn effective_filter(&self, packet: &Packet) -> Option<String> {
        combine_filters(
            ReplyMatcher::from_packet(packet).reply_filter(),
            self.user_filter(),
        )
    }

    /// Send a packet and return the first matching reply, if any.
    pub fn send_recv(&self, packet: &Packet) -> Result<Option<Packet>> {
        Ok(self.send_recv_report(packet)?.into_reply())
    }

    /// Send a packet and return the detailed send/receive report.
    pub fn send_recv_report(&self, packet: &Packet) -> Result<SendRecvReport> {
        let interface = validated_interface(&self.send_options)?;
        let matcher = ReplyMatcher::from_packet(packet);
        let effective_filter = combine_filters(matcher.reply_filter(), self.user_filter());
        let sender = SocketSender::new(self.send_options.clone());
        let mut send_reports = Vec::new();

        if self.send_options.is_dry_run() {
            send_reports.push(sender.send(packet)?);
            return Ok(SendRecvReport::new(send_reports, None, effective_filter));
        }

        for _ in 0..self.retries.max(1) {
            let mut sniffer = Sniffer::interface(interface.clone())
                .timeout(self.timeout)
                .count(self.capture_limit);
            if let Some(filter) = effective_filter.as_deref() {
                sniffer = sniffer.filter(filter);
            }

            let mut capture = sniffer.open()?;
            send_reports.push(sender.send(packet)?);
            while let Some(reply) = capture.next_packet()? {
                if matcher.matches(reply.packet()) {
                    return Ok(SendRecvReport::new(
                        send_reports,
                        Some(reply.into_packet()),
                        effective_filter,
                    ));
                }
            }
        }

        Ok(SendRecvReport::new(send_reports, None, effective_filter))
    }
}

impl Default for SendRecv {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&str> for SendRecv {
    fn from(interface: &str) -> Self {
        Self::new().iface(interface)
    }
}

impl From<String> for SendRecv {
    fn from(interface: String) -> Self {
        Self::new().iface(interface)
    }
}

/// Backwards-compatible alias for callers that prefer an options suffix.
pub type SendRecvOptions = SendRecv;

/// Detailed result returned by send/receive operations.
#[derive(Debug, Clone)]
pub struct SendRecvReport {
    send_reports: Vec<SendReport>,
    reply: Option<Packet>,
    effective_filter: Option<String>,
}

impl SendRecvReport {
    /// Create a send/receive report.
    pub fn new(
        send_reports: Vec<SendReport>,
        reply: Option<Packet>,
        effective_filter: Option<String>,
    ) -> Self {
        Self {
            send_reports,
            reply,
            effective_filter,
        }
    }

    /// Per-attempt send reports.
    pub fn send_reports(&self) -> &[SendReport] {
        &self.send_reports
    }

    /// Number of send attempts made.
    pub fn attempts(&self) -> usize {
        self.send_reports.len()
    }

    /// Borrow the matching reply, if one was captured.
    pub fn reply(&self) -> Option<&Packet> {
        self.reply.as_ref()
    }

    /// Consume this report and return the matching reply, if one was captured.
    pub fn into_reply(self) -> Option<Packet> {
        self.reply
    }

    /// Effective capture filter used for this send/receive operation.
    pub fn effective_filter(&self) -> Option<&str> {
        self.effective_filter.as_deref()
    }

    /// Return true when no matching reply was captured.
    pub fn timed_out(&self) -> bool {
        self.reply.is_none()
    }
}

/// Protocol-aware matcher for replies to one request packet.

pub trait PacketSendRecvExt {
    /// Derive a BPF-style filter for likely replies.
    fn reply_filter(&self) -> Result<String>;

    /// Send a packet and return the first matching reply, if any.
    fn send_recv(&self, options: impl Into<SendRecv>) -> Result<Option<Packet>>;

    /// Send a packet and return a detailed send/receive report.
    fn send_recv_report(&self, options: impl Into<SendRecv>) -> Result<SendRecvReport>;
}

impl PacketSendRecvExt for Packet {
    fn reply_filter(&self) -> Result<String> {
        Ok(reply_filter(self).unwrap_or_default())
    }

    fn send_recv(&self, options: impl Into<SendRecv>) -> Result<Option<Packet>> {
        options.into().send_recv(self)
    }

    fn send_recv_report(&self, options: impl Into<SendRecv>) -> Result<SendRecvReport> {
        options.into().send_recv_report(self)
    }
}

/// Send a packet and return the first matching reply, if any.
pub fn send_recv_packet(packet: &Packet, options: impl Into<SendRecv>) -> Result<Option<Packet>> {
    options.into().send_recv(packet)
}

/// Configuration object for send-and-receive workflows over packet collections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchSendRecv {
    send_recv: SendRecv,
    concurrency_limit: usize,
}

impl BatchSendRecv {
    /// Create batch send/receive options with libcrafter-like defaults.
    pub fn new() -> Self {
        Self {
            send_recv: SendRecv::new(),
            concurrency_limit: 64,
        }
    }

    /// Select the interface used for both sending and capture.
    pub fn interface(mut self, interface: impl Into<String>) -> Self {
        self.send_recv = self.send_recv.interface(interface);
        self
    }

    /// Compatibility alias for [`Self::interface`].
    pub fn iface(self, interface: impl Into<String>) -> Self {
        self.interface(interface)
    }

    /// Set the send mode.
    pub fn mode(mut self, mode: SendMode) -> Self {
        self.send_recv = self.send_recv.mode(mode);
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

    /// Compile and plan sends without transmitting or opening capture.
    pub fn dry_run(mut self) -> Self {
        self.send_recv = self.send_recv.dry_run();
        self
    }

    /// Enable live send/receive behavior.
    pub fn live(mut self) -> Self {
        self.send_recv = self.send_recv.live();
        self
    }

    /// Set the per-attempt capture timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.send_recv = self.send_recv.timeout(timeout);
        self
    }

    /// Set the number of send attempts per request. A zero value is treated as one attempt.
    pub fn retries(mut self, retries: usize) -> Self {
        self.send_recv = self.send_recv.retries(retries);
        self
    }

    /// libcrafter-style singular alias for [`Self::retries`].
    pub fn retry(self, retries: usize) -> Self {
        self.retries(retries)
    }

    /// Add a caller-supplied BPF filter. It is combined with the derived batch reply filter.
    pub fn filter(mut self, filter: impl Into<String>) -> Self {
        self.send_recv = self.send_recv.filter(filter);
        self
    }

    /// Remove any caller-supplied BPF filter.
    pub fn clear_filter(mut self) -> Self {
        self.send_recv = self.send_recv.clear_filter();
        self
    }

    /// Set the maximum captured packets inspected per request in each batch window.
    pub fn capture_limit(mut self, capture_limit: usize) -> Self {
        self.send_recv = self.send_recv.capture_limit(capture_limit);
        self
    }

    /// Set the maximum number of requests sent before collecting replies.
    pub fn concurrency_limit(mut self, limit: usize) -> Self {
        self.concurrency_limit = limit.max(1);
        self
    }

    /// Borrow the underlying single-request send/receive options.
    pub const fn send_recv_options(&self) -> &SendRecv {
        &self.send_recv
    }

    /// Configured concurrency limit.
    pub const fn concurrency_limit_value(&self) -> usize {
        self.concurrency_limit
    }

    /// Effective BPF filter for the whole request collection.
    pub fn effective_filter(&self, packets: &[Packet]) -> Option<String> {
        combine_filters(batch_reply_filter(packets), self.send_recv.user_filter())
    }

    /// Send every request and collect matching replies in request order.
    pub fn send_recv_all(&self, packets: &[Packet]) -> Result<BatchSendRecvReport> {
        let mut entries = (0..packets.len())
            .map(BatchSendRecvEntry::new)
            .collect::<Vec<_>>();
        let effective_filter = self.effective_filter(packets);

        if packets.is_empty() {
            return Ok(BatchSendRecvReport::new(
                entries,
                effective_filter,
                self.concurrency_limit,
                self.send_recv.retries_value().max(1),
                self.send_recv.timeout_value(),
            ));
        }

        let sender = SocketSender::new(self.send_recv.send_options().clone());

        if self.send_recv.send_options().is_dry_run() {
            for chunk_start in (0..packets.len()).step_by(self.concurrency_limit) {
                let chunk_end = (chunk_start + self.concurrency_limit).min(packets.len());
                for _ in 0..self.send_recv.retries_value().max(1) {
                    for request_index in chunk_start..chunk_end {
                        entries[request_index]
                            .send_reports
                            .push(sender.send(&packets[request_index])?);
                    }
                }
            }
            return Ok(BatchSendRecvReport::new(
                entries,
                effective_filter,
                self.concurrency_limit,
                self.send_recv.retries_value().max(1),
                self.send_recv.timeout_value(),
            ));
        }

        let interface = validated_interface(self.send_recv.send_options())?;
        for chunk_start in (0..packets.len()).step_by(self.concurrency_limit) {
            let chunk_end = (chunk_start + self.concurrency_limit).min(packets.len());
            for _ in 0..self.send_recv.retries_value().max(1) {
                let pending = (chunk_start..chunk_end)
                    .filter(|request_index| entries[*request_index].reply.is_none())
                    .collect::<Vec<_>>();
                if pending.is_empty() {
                    break;
                }

                let mut sniffer = Sniffer::interface(interface.clone())
                    .timeout(self.send_recv.timeout_value())
                    .count(
                        self.send_recv
                            .capture_limit
                            .saturating_mul(pending.len().max(1))
                            .max(1),
                    );
                if let Some(filter) = effective_filter.as_deref() {
                    sniffer = sniffer.filter(filter);
                }

                let mut capture = sniffer.open()?;
                for request_index in pending.iter().copied() {
                    entries[request_index]
                        .send_reports
                        .push(sender.send(&packets[request_index])?);
                }

                while let Some(reply) = capture.next_packet()? {
                    let packet = reply.into_packet();
                    assign_reply_to_first_match(&mut entries, packets, packet);
                    if pending
                        .iter()
                        .all(|request_index| entries[*request_index].reply.is_some())
                    {
                        break;
                    }
                }
            }
        }

        Ok(BatchSendRecvReport::new(
            entries,
            effective_filter,
            self.concurrency_limit,
            self.send_recv.retries_value().max(1),
            self.send_recv.timeout_value(),
        ))
    }

    /// Match already-captured candidate replies to requests without sending packets.
    pub fn collect_replies_from_candidates<I>(
        &self,
        requests: &[Packet],
        candidates: I,
    ) -> BatchSendRecvReport
    where
        I: IntoIterator<Item = Packet>,
    {
        let mut entries = (0..requests.len())
            .map(BatchSendRecvEntry::new)
            .collect::<Vec<_>>();

        for candidate in candidates {
            assign_reply_to_first_match(&mut entries, requests, candidate);
        }

        BatchSendRecvReport::new(
            entries,
            self.effective_filter(requests),
            self.concurrency_limit,
            self.send_recv.retries_value().max(1),
            self.send_recv.timeout_value(),
        )
    }
}

impl Default for BatchSendRecv {
    fn default() -> Self {
        Self::new()
    }
}

impl From<SendRecv> for BatchSendRecv {
    fn from(send_recv: SendRecv) -> Self {
        Self::new().with_send_recv(send_recv)
    }
}

impl From<SendOptions> for BatchSendRecv {
    fn from(send_options: SendOptions) -> Self {
        Self::new().with_send_recv(SendRecv::new().with_send_options(send_options))
    }
}

impl From<&str> for BatchSendRecv {
    fn from(interface: &str) -> Self {
        Self::new().iface(interface)
    }
}

impl From<String> for BatchSendRecv {
    fn from(interface: String) -> Self {
        Self::new().iface(interface)
    }
}

impl BatchSendRecv {
    fn with_send_recv(mut self, send_recv: SendRecv) -> Self {
        self.send_recv = send_recv;
        self
    }
}

impl SendRecv {
    fn with_send_options(mut self, send_options: SendOptions) -> Self {
        self.send_options = send_options;
        self
    }
}

/// Per-request result in a batch send/receive operation.
#[derive(Debug, Clone)]
pub struct BatchSendRecvEntry {
    request_index: usize,
    send_reports: Vec<SendReport>,
    reply: Option<Packet>,
}

impl BatchSendRecvEntry {
    fn new(request_index: usize) -> Self {
        Self {
            request_index,
            send_reports: Vec::new(),
            reply: None,
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

    /// Borrow the matching reply, if one was collected.
    pub fn reply(&self) -> Option<&Packet> {
        self.reply.as_ref()
    }

    /// Consume this entry and return the matching reply, if one was collected.
    pub fn into_reply(self) -> Option<Packet> {
        self.reply
    }

    /// Return true when no matching reply was collected.
    pub fn timed_out(&self) -> bool {
        self.reply.is_none()
    }
}

/// Detailed result returned by batch send/receive operations.
#[derive(Debug, Clone)]
pub struct BatchSendRecvReport {
    entries: Vec<BatchSendRecvEntry>,
    effective_filter: Option<String>,
    concurrency_limit: usize,
    retries: usize,
    timeout: Duration,
}

impl BatchSendRecvReport {
    fn new(
        entries: Vec<BatchSendRecvEntry>,
        effective_filter: Option<String>,
        concurrency_limit: usize,
        retries: usize,
        timeout: Duration,
    ) -> Self {
        Self {
            entries,
            effective_filter,
            concurrency_limit,
            retries,
            timeout,
        }
    }

    /// Per-request reports in the same order as the input packets.
    pub fn entries(&self) -> &[BatchSendRecvEntry] {
        &self.entries
    }

    /// Borrow one entry by request index.
    pub fn entry(&self, request_index: usize) -> Option<&BatchSendRecvEntry> {
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

    /// Borrow replies in request order.
    pub fn replies(&self) -> Vec<Option<&Packet>> {
        self.entries.iter().map(BatchSendRecvEntry::reply).collect()
    }

    /// Consume this report and return replies in request order.
    pub fn into_replies(self) -> Vec<Option<Packet>> {
        self.entries
            .into_iter()
            .map(BatchSendRecvEntry::into_reply)
            .collect()
    }

    /// Number of requests with matching replies.
    pub fn reply_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.reply.is_some())
            .count()
    }

    /// Number of requests without matching replies.
    pub fn timed_out_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.reply.is_none())
            .count()
    }

    /// Request indexes that did not receive a matching reply.
    pub fn timed_out_indices(&self) -> Vec<usize> {
        self.entries
            .iter()
            .filter(|entry| entry.reply.is_none())
            .map(BatchSendRecvEntry::request_index)
            .collect()
    }

    /// Effective capture filter used for the batch.
    pub fn effective_filter(&self) -> Option<&str> {
        self.effective_filter.as_deref()
    }

    /// Concurrency limit used by the batch.
    pub const fn concurrency_limit(&self) -> usize {
        self.concurrency_limit
    }

    /// Retry count used by the batch.
    pub const fn retries(&self) -> usize {
        self.retries
    }

    /// Per-attempt timeout used by the batch.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Extension methods for send/receive packet collections.
pub trait PacketBatchSendRecvExt {
    /// Send every request and collect matching replies in request order.
    fn batch_send_recv(&self, options: impl Into<BatchSendRecv>) -> Result<BatchSendRecvReport>;

    /// Compile and plan every request without transmitting or opening capture.
    fn batch_send_recv_dry_run(
        &self,
        options: impl Into<BatchSendRecv>,
    ) -> Result<BatchSendRecvReport>;
}

impl PacketBatchSendRecvExt for [Packet] {
    fn batch_send_recv(&self, options: impl Into<BatchSendRecv>) -> Result<BatchSendRecvReport> {
        options.into().send_recv_all(self)
    }

    fn batch_send_recv_dry_run(
        &self,
        options: impl Into<BatchSendRecv>,
    ) -> Result<BatchSendRecvReport> {
        options.into().dry_run().send_recv_all(self)
    }
}

/// Send a packet collection and collect replies in one call.
pub fn send_recv_packets(
    packets: &[Packet],
    options: impl Into<BatchSendRecv>,
) -> Result<BatchSendRecvReport> {
    options.into().send_recv_all(packets)
}

fn assign_reply_to_first_match(
    entries: &mut [BatchSendRecvEntry],
    requests: &[Packet],
    candidate: Packet,
) -> bool {
    let Some(entry_index) = entries.iter().position(|entry| {
        entry.reply.is_none() && reply_matches(&requests[entry.request_index], &candidate)
    }) else {
        return false;
    };

    entries[entry_index].reply = Some(candidate);
    true
}
