//! Packet sniffer pipeline.

use std::collections::VecDeque;
use std::fmt;

use super::record::PacketRecord;
use super::source::PacketSource;
use super::transform::PacketTransform;
use super::Result;

/// Inbound packet stream pipeline.
///
/// A sniffer owns one [`PacketSource`] and an ordered chain of packet
/// transforms. Each source record flows through the full transform chain before
/// any emitted record is yielded to the caller.
pub struct Sniffer {
    source: Box<dyn PacketSource>,
    transforms: Vec<Box<dyn PacketTransform>>,
    buffered: VecDeque<PacketRecord>,
}

impl Sniffer {
    /// Create a sniffer from an already-open packet source.
    pub fn new(source: impl PacketSource + 'static) -> Self {
        Self {
            source: Box::new(source),
            transforms: Vec::new(),
            buffered: VecDeque::new(),
        }
    }

    /// Append one inbound transform to the pipeline.
    pub fn with(mut self, transform: impl PacketTransform + 'static) -> Self {
        self.transforms.push(Box::new(transform));
        self
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
        loop {
            if let Some(record) = self.buffered.pop_front() {
                return Ok(Some(record));
            }

            let Some(record) = self.source.next_record()? else {
                return Ok(None);
            };
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
}

impl fmt::Debug for Sniffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sniffer")
            .field("transform_count", &self.transforms.len())
            .field("buffered_len", &self.buffered.len())
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::rc::Rc;

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
        assert!(sniffer.is_buffer_empty());

        let first = sniffer.next_record().unwrap().unwrap();
        assert_eq!(first.metadata().interface(), Some("first"));
        assert_eq!(first.packet().summary(), "Raw(len=5)");

        let second = sniffer.next_record().unwrap().unwrap();
        assert_eq!(second.metadata().interface(), Some("second"));
        assert_eq!(second.packet().summary(), "Raw(len=6)");

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
        let pulls = Rc::new(Cell::new(0));
        let source = CountingSource::new([record("first"), record("second")], Rc::clone(&pulls));
        let mut sniffer = Sniffer::new(source).with(DuplicateTransform::new());

        let first = sniffer.next_record().unwrap().unwrap();
        assert_eq!(first.metadata().interface(), Some("first"));
        assert_eq!(pulls.get(), 1);
        assert_eq!(sniffer.buffered_len(), 1);

        let duplicate = sniffer.next_record().unwrap().unwrap();
        assert_eq!(duplicate.metadata().interface(), Some("first"));
        assert_eq!(pulls.get(), 1);
        assert!(sniffer.is_buffer_empty());

        let second = sniffer.next_record().unwrap().unwrap();
        assert_eq!(second.metadata().interface(), Some("second"));
        assert_eq!(pulls.get(), 2);
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

    struct CountingSource {
        records: VecDeque<PacketRecord>,
        pulls: Rc<Cell<usize>>,
    }

    impl CountingSource {
        fn new(records: impl IntoIterator<Item = PacketRecord>, pulls: Rc<Cell<usize>>) -> Self {
            Self {
                records: records.into_iter().collect(),
                pulls,
            }
        }
    }

    impl PacketSource for CountingSource {
        fn next_record(&mut self) -> Result<Option<PacketRecord>> {
            self.pulls.set(self.pulls.get() + 1);
            Ok(self.records.pop_front())
        }
    }
}
