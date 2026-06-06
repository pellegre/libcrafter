//! Packet sniffer pipeline.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::record::PacketRecord;
use super::source::PacketSource;
use super::transform::PacketTransform;
use super::{Result, WireError};

const DEFAULT_SNIFFER_TIMEOUT: Duration = Duration::from_secs(10);

/// Inbound packet stream pipeline.
///
/// A sniffer owns one [`PacketSource`] and an ordered chain of packet
/// transforms. Each source record flows through the full transform chain before
/// any emitted record is yielded to the caller.
pub struct Sniffer {
    source: Box<dyn PacketSource + Send>,
    transforms: Vec<Box<dyn PacketTransform + Send>>,
    buffered: VecDeque<PacketRecord>,
    count_limit: Option<usize>,
    yielded: usize,
    timeout: Option<Duration>,
    deadline: Option<Instant>,
    started: bool,
    cancel: Arc<AtomicBool>,
}

impl Sniffer {
    /// Create a sniffer from an already-open packet source.
    pub fn new(source: impl PacketSource + Send + 'static) -> Self {
        Self {
            source: Box::new(source),
            transforms: Vec::new(),
            buffered: VecDeque::new(),
            count_limit: None,
            yielded: 0,
            timeout: Some(DEFAULT_SNIFFER_TIMEOUT),
            deadline: None,
            started: false,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Append one inbound transform to the pipeline.
    pub fn with(mut self, transform: impl PacketTransform + Send + 'static) -> Self {
        self.transforms.push(Box::new(transform));
        self
    }

    /// Limit the number of transformed records yielded by this sniffer.
    pub fn count(mut self, count: usize) -> Self {
        self.count_limit = Some(count);
        self
    }

    /// Remove the configured transformed-record count limit.
    pub fn unlimited_count(mut self) -> Self {
        self.count_limit = None;
        self
    }

    /// Set a wall-clock sniffer timeout.
    ///
    /// The timeout starts when the sniffer is first polled. Because packet
    /// sources expose a synchronous `next_record` call, timeout enforcement is
    /// cooperative at sniffer boundaries and after a source call returns.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self.deadline = None;
        self.started = false;
        self
    }

    /// Disable wall-clock timeout enforcement.
    pub fn no_timeout(mut self) -> Self {
        self.timeout = None;
        self.deadline = None;
        self.started = false;
        self
    }

    /// Attach a cooperative cancellation token.
    pub fn with_cancel(mut self, cancel: SnifferCancel) -> Self {
        self.cancel = cancel.cancelled;
        self
    }

    /// Return a cancellation token shared with this sniffer.
    pub fn cancel_token(&self) -> SnifferCancel {
        SnifferCancel {
            cancelled: Arc::clone(&self.cancel),
        }
    }

    /// Request cooperative cancellation.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Configured transformed-record count limit.
    pub const fn count_limit(&self) -> Option<usize> {
        self.count_limit
    }

    /// Configured wall-clock timeout.
    pub const fn timeout_limit(&self) -> Option<Duration> {
        self.timeout
    }

    /// Number of transformed records yielded so far.
    pub const fn yielded(&self) -> usize {
        self.yielded
    }

    /// Number of configured transforms.
    pub fn transform_count(&self) -> usize {
        self.transforms.len()
    }

    /// Number of transformed records waiting to be yielded.
    pub fn buffered_len(&self) -> usize {
        self.buffered.len()
    }

    /// Whether there are no transformed records waiting to be yielded.
    pub fn is_buffer_empty(&self) -> bool {
        self.buffered.is_empty()
    }

    /// Return the next transformed packet record.
    ///
    /// Buffered transform output is drained before pulling another source
    /// record. This preserves one-input-to-many-output ordering for transforms
    /// such as decryption, defragmentation, and stream reconstruction.
    pub fn next_record(&mut self) -> Result<Option<PacketRecord>> {
        self.start_timeout();

        loop {
            if self.should_stop() {
                return Ok(None);
            }

            if let Some(record) = self.buffered.pop_front() {
                self.yielded += 1;
                return Ok(Some(record));
            }

            let Some(record) = self.source.next_record()? else {
                return Ok(None);
            };
            if self.should_stop() {
                return Ok(None);
            }
            self.process_record(record)?;
        }
    }

    /// Collect all remaining transformed packet records.
    pub fn collect_records(mut self) -> Result<Vec<PacketRecord>> {
        let mut records = Vec::new();
        while let Some(record) = self.next_record()? {
            records.push(record);
        }
        Ok(records)
    }

    /// Start background collection and return a handle that can be joined or
    /// cancelled.
    pub fn spawn(self) -> Result<SnifferHandle> {
        let cancel = self.cancel_token();
        let join = thread::Builder::new()
            .name("crafter-wire-sniffer".to_string())
            .spawn(move || self.collect_records())
            .map_err(|err| WireError::io("spawn sniffer thread", err))?;

        Ok(SnifferHandle { cancel, join })
    }

    /// Set a count limit and start background collection.
    pub fn spawn_count(self, count: usize) -> Result<SnifferHandle> {
        self.count(count).spawn()
    }

    fn process_record(&mut self, record: PacketRecord) -> Result<()> {
        let mut current = VecDeque::new();
        current.push_back(record);

        for transform in &mut self.transforms {
            let mut next = VecDeque::new();
            while let Some(record) = current.pop_front() {
                transform.transform(record, &mut |record| {
                    next.push_back(record);
                    Ok(())
                })?;
            }
            current = next;
            if current.is_empty() {
                break;
            }
        }

        self.buffered.extend(current);
        Ok(())
    }

    fn start_timeout(&mut self) {
        if !self.started {
            self.deadline = sniffer_deadline(self.timeout);
            self.started = true;
        }
    }

    fn should_stop(&self) -> bool {
        self.is_cancelled() || self.reached_limit() || self.timed_out()
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

impl fmt::Debug for Sniffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sniffer")
            .field("transform_count", &self.transforms.len())
            .field("buffered_len", &self.buffered.len())
            .field("count_limit", &self.count_limit)
            .field("yielded", &self.yielded)
            .field("timeout", &self.timeout)
            .field("started", &self.started)
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl Iterator for Sniffer {
    type Item = Result<PacketRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_record() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        }
    }
}

/// Cooperative cancellation token for a [`Sniffer`].
#[derive(Debug, Clone)]
pub struct SnifferCancel {
    cancelled: Arc<AtomicBool>,
}

impl SnifferCancel {
    /// Create an independent cancellation token.
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Request cooperative cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

impl Default for SnifferCancel {
    fn default() -> Self {
        Self::new()
    }
}

/// Background sniffer collection handle returned by [`Sniffer::spawn`].
#[derive(Debug)]
pub struct SnifferHandle {
    cancel: SnifferCancel,
    join: JoinHandle<Result<Vec<PacketRecord>>>,
}

impl SnifferHandle {
    /// Return a cancellation token shared with the background sniffer.
    pub fn cancel_token(&self) -> SnifferCancel {
        self.cancel.clone()
    }

    /// Request cooperative cancellation.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Wait for the background sniffer and return collected records.
    pub fn join(self) -> Result<Vec<PacketRecord>> {
        self.join.join().map_err(|_| {
            WireError::backend("sniffer", "join", "background sniffer thread panicked")
        })?
    }
}

fn sniffer_deadline(timeout: Option<Duration>) -> Option<Instant> {
    timeout.and_then(|duration| Instant::now().checked_add(duration))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use std::thread;

    use super::super::record::{BackendKind, PacketRecord};
    use super::super::source::{PacketSource, VecPacketSource};
    use super::super::transform::{DropAllTransform, DuplicateTransform, TraceAppendTransform};
    use super::super::Result;
    use super::*;
    use crate::Raw;

    fn record(payload: &'static str) -> PacketRecord {
        PacketRecord::new(Raw::from(payload))
            .with_backend(BackendKind::Memory)
            .with_interface(payload)
    }

    #[test]
    fn sniffer_without_transforms_yields_source_records() {
        let source = VecPacketSource::new([record("first"), record("second")]);
        let mut sniffer = Sniffer::new(source);

        assert_eq!(sniffer.transform_count(), 0);
        assert_eq!(sniffer.count_limit(), None);
        assert_eq!(sniffer.timeout_limit(), Some(DEFAULT_SNIFFER_TIMEOUT));
        assert_eq!(sniffer.yielded(), 0);
        assert!(sniffer.is_buffer_empty());

        let first = sniffer.next_record().unwrap().unwrap();
        assert_eq!(first.metadata().interface(), Some("first"));
        assert_eq!(first.packet().summary(), "Raw(len=5)");
        assert_eq!(sniffer.yielded(), 1);

        let second = sniffer.next_record().unwrap().unwrap();
        assert_eq!(second.metadata().interface(), Some("second"));
        assert_eq!(second.packet().summary(), "Raw(len=6)");
        assert_eq!(sniffer.yielded(), 2);

        assert!(sniffer.next_record().unwrap().is_none());
    }

    #[test]
    fn sniffer_applies_transforms_in_order() {
        let source = VecPacketSource::new([record("payload")]);
        let records = Sniffer::new(source)
            .with(TraceAppendTransform::new("first"))
            .with(TraceAppendTransform::new("second"))
            .collect_records()
            .unwrap();

        assert_eq!(records.len(), 1);
        let traces = records[0].metadata().transforms();
        assert_eq!(traces.len(), 2);
        assert_eq!(traces[0].name(), "first");
        assert_eq!(traces[1].name(), "second");
    }

    #[test]
    fn sniffer_continues_after_zero_output_transform() {
        let source = VecPacketSource::new([record("first"), record("second")]);
        let records = Sniffer::new(source)
            .with(DropAllTransform::new())
            .collect_records()
            .unwrap();

        assert!(records.is_empty());
    }

    #[test]
    fn sniffer_processes_many_outputs_through_later_transforms() {
        let source = VecPacketSource::new([record("payload")]);
        let records = Sniffer::new(source)
            .with(DuplicateTransform::new())
            .with(TraceAppendTransform::new("mark"))
            .collect_records()
            .unwrap();

        assert_eq!(records.len(), 2);
        for record in records {
            assert_eq!(record.packet().summary(), "Raw(len=7)");
            let traces = record.metadata().transforms();
            assert_eq!(traces.len(), 1);
            assert_eq!(traces[0].name(), "mark");
        }
    }

    #[test]
    fn sniffer_drains_buffered_outputs_before_pulling_source_again() {
        let pulls = Arc::new(AtomicUsize::new(0));
        let source = CountingSource::new([record("first"), record("second")], Arc::clone(&pulls));
        let mut sniffer = Sniffer::new(source).with(DuplicateTransform::new());

        let first = sniffer.next_record().unwrap().unwrap();
        assert_eq!(first.metadata().interface(), Some("first"));
        assert_eq!(pulls.load(Ordering::Relaxed), 1);
        assert_eq!(sniffer.buffered_len(), 1);

        let duplicate = sniffer.next_record().unwrap().unwrap();
        assert_eq!(duplicate.metadata().interface(), Some("first"));
        assert_eq!(pulls.load(Ordering::Relaxed), 1);
        assert!(sniffer.is_buffer_empty());

        let second = sniffer.next_record().unwrap().unwrap();
        assert_eq!(second.metadata().interface(), Some("second"));
        assert_eq!(pulls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn sniffer_iterator_yields_records_until_exhausted() {
        let source = VecPacketSource::new([record("one"), record("two")]);

        let records: Result<Vec<_>> = Sniffer::new(source).collect();

        let records = records.unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].metadata().interface(), Some("one"));
        assert_eq!(records[1].metadata().interface(), Some("two"));
    }

    #[test]
    fn sniffer_count_limit_applies_to_transformed_outputs() {
        let source = VecPacketSource::new([record("first"), record("second")]);

        let records = Sniffer::new(source)
            .with(DuplicateTransform::new())
            .count(3)
            .collect_records()
            .unwrap();

        assert_eq!(records.len(), 3);
        assert_eq!(records[0].metadata().interface(), Some("first"));
        assert_eq!(records[1].metadata().interface(), Some("first"));
        assert_eq!(records[2].metadata().interface(), Some("second"));
    }

    #[test]
    fn sniffer_zero_count_does_not_poll_source() {
        let pulls = Arc::new(AtomicUsize::new(0));
        let source = CountingSource::new([record("payload")], Arc::clone(&pulls));

        let records = Sniffer::new(source).count(0).collect_records().unwrap();

        assert!(records.is_empty());
        assert_eq!(pulls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn sniffer_timeout_can_stop_before_polling_source() {
        let pulls = Arc::new(AtomicUsize::new(0));
        let source = CountingSource::new([record("payload")], Arc::clone(&pulls));

        let records = Sniffer::new(source)
            .timeout(Duration::ZERO)
            .collect_records()
            .unwrap();

        assert!(records.is_empty());
        assert_eq!(pulls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn sniffer_timeout_drops_record_that_arrives_after_deadline() {
        let pulls = Arc::new(AtomicUsize::new(0));
        let source = WaitingSource::new(
            [record("late")],
            Duration::from_millis(20),
            Arc::clone(&pulls),
        );

        let records = Sniffer::new(source)
            .timeout(Duration::from_millis(1))
            .collect_records()
            .unwrap();

        assert!(records.is_empty());
        assert_eq!(pulls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sniffer_returns_none_when_waiting_source_exhausts() {
        let pulls = Arc::new(AtomicUsize::new(0));
        let source = WaitingSource::new(
            Vec::<PacketRecord>::new(),
            Duration::from_millis(1),
            Arc::clone(&pulls),
        );

        let records = Sniffer::new(source).no_timeout().collect_records().unwrap();

        assert!(records.is_empty());
        assert_eq!(pulls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sniffer_cancel_token_stops_collection() {
        let source = VecPacketSource::new([record("first"), record("second")]);
        let mut sniffer = Sniffer::new(source).no_timeout();
        let cancel = sniffer.cancel_token();

        let first = sniffer.next_record().unwrap().unwrap();
        assert_eq!(first.metadata().interface(), Some("first"));

        cancel.cancel();

        assert!(sniffer.next_record().unwrap().is_none());
        assert!(sniffer.is_cancelled());
        assert_eq!(sniffer.yielded(), 1);
    }

    #[test]
    fn sniffer_accepts_external_cancel_token() {
        let cancel = SnifferCancel::new();
        cancel.cancel();
        let source = VecPacketSource::new([record("payload")]);

        let records = Sniffer::new(source)
            .with_cancel(cancel.clone())
            .no_timeout()
            .collect_records()
            .unwrap();

        assert!(records.is_empty());
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn sniffer_spawn_collects_records_in_background() {
        let source = VecPacketSource::new([record("one"), record("two"), record("three")]);

        let handle = Sniffer::new(source).spawn_count(2).unwrap();
        let records = handle.join().unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].metadata().interface(), Some("one"));
        assert_eq!(records[1].metadata().interface(), Some("two"));
    }

    #[test]
    fn sniffer_handle_can_cancel_before_join() {
        let source = WaitingSource::new(
            [record("one"), record("two")],
            Duration::from_millis(20),
            Arc::new(AtomicUsize::new(0)),
        );

        let handle = Sniffer::new(source).no_timeout().spawn().unwrap();
        handle.cancel();
        let records = handle.join().unwrap();

        assert!(records.is_empty());
    }

    struct CountingSource {
        records: VecDeque<PacketRecord>,
        pulls: Arc<AtomicUsize>,
    }

    impl CountingSource {
        fn new(records: impl IntoIterator<Item = PacketRecord>, pulls: Arc<AtomicUsize>) -> Self {
            Self {
                records: records.into_iter().collect(),
                pulls,
            }
        }
    }

    impl PacketSource for CountingSource {
        fn next_record(&mut self) -> Result<Option<PacketRecord>> {
            self.pulls.fetch_add(1, Ordering::Relaxed);
            Ok(self.records.pop_front())
        }
    }

    struct WaitingSource {
        records: VecDeque<PacketRecord>,
        delay: Duration,
        pulls: Arc<AtomicUsize>,
    }

    impl WaitingSource {
        fn new(
            records: impl IntoIterator<Item = PacketRecord>,
            delay: Duration,
            pulls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                records: records.into_iter().collect(),
                delay,
                pulls,
            }
        }
    }

    impl PacketSource for WaitingSource {
        fn next_record(&mut self) -> Result<Option<PacketRecord>> {
            self.pulls.fetch_add(1, Ordering::Relaxed);
            thread::sleep(self.delay);
            Ok(self.records.pop_front())
        }
    }
}
