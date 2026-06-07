//! Outbound packet transmitter pipeline.

use std::collections::VecDeque;
use std::fmt;

use crate::IntoPacket;

use super::record::{PacketOrigin, PacketRecord};
use super::transform::PacketTransform;
use super::writer::{PacketWriter, WriteReport};
use super::Result;

/// Outbound packet stream pipeline.
///
/// A transmitter owns one [`PacketWriter`] and an ordered chain of packet
/// transforms. Each input record flows through the full transform chain before
/// every emitted record is written to the backend. To transmit through multiple
/// interfaces or media, open multiple [`crate::wire::PacketWire`] values and
/// run one transmitter per writer.
pub struct Transmitter {
    writer: Box<dyn PacketWriter + Send>,
    transforms: Vec<Box<dyn PacketTransform + Send>>,
}

impl Transmitter {
    /// Create a transmitter from an already-open packet writer.
    pub fn new(writer: impl PacketWriter + Send + 'static) -> Self {
        Self {
            writer: Box::new(writer),
            transforms: Vec::new(),
        }
    }

    /// Append one outbound transform to the pipeline.
    pub fn with(mut self, transform: impl PacketTransform + Send + 'static) -> Self {
        self.transforms.push(Box::new(transform));
        self
    }

    /// Number of configured transforms.
    pub fn transform_count(&self) -> usize {
        self.transforms.len()
    }

    /// Send a generated packet through the outbound pipeline.
    ///
    /// Transform output controls how many backend writes happen: zero emitted
    /// records returns an empty report list, one emitted record returns one
    /// report, and many emitted records return every write report in order.
    pub fn send(&mut self, packet: impl IntoPacket) -> Result<Vec<WriteReport>> {
        self.send_record(PacketRecord::new(packet).with_origin(PacketOrigin::Generated))
    }

    /// Send a packet record through the outbound pipeline.
    pub fn send_record(&mut self, record: PacketRecord) -> Result<Vec<WriteReport>> {
        self.write_record(record)
    }

    /// Transform and write one packet record.
    pub fn write_record(&mut self, record: PacketRecord) -> Result<Vec<WriteReport>> {
        let records = self.process_record(record)?;
        let mut reports = Vec::with_capacity(records.len());

        for record in records {
            reports.push(self.writer.write_record(&record)?);
        }

        Ok(reports)
    }

    fn process_record(&mut self, record: PacketRecord) -> Result<VecDeque<PacketRecord>> {
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

        Ok(current)
    }
}

impl fmt::Debug for Transmitter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transmitter")
            .field("transform_count", &self.transforms.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::super::record::{BackendKind, PacketRecord};
    use super::super::transform::{DropAllTransform, DuplicateTransform};
    use super::super::writer::MemoryPacketWriter;
    use super::super::{IpFragment, IpFragmentFamily, IpFragmentMetadata, IpFragmentRange};
    use super::*;
    use crate::{Ipv4, Raw};
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    fn record(payload: &'static str) -> PacketRecord {
        PacketRecord::new(Raw::from(payload))
            .with_backend(BackendKind::Memory)
            .with_interface(payload)
    }

    fn ipv4_record(payload: &[u8]) -> PacketRecord {
        let ipv4 = Ipv4::with_addresses(
            Ipv4Addr::new(192, 0, 2, 29),
            Ipv4Addr::new(198, 51, 100, 29),
        )
        .protocol(253)
        .identification(0x2929);

        PacketRecord::new(ipv4 / Raw::from_bytes(payload))
    }

    #[test]
    fn send_writes_generated_packet_without_transforms() {
        let mut transmitter = Transmitter::new(MemoryPacketWriter::new());

        let reports = transmitter.send(Raw::from("payload")).unwrap();

        assert_eq!(transmitter.transform_count(), 0);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].backend(), &BackendKind::Memory);
        assert_eq!(reports[0].bytes_requested(), 7);
        assert_eq!(reports[0].bytes_written(), 7);
    }

    #[test]
    fn write_record_returns_no_reports_when_transform_drops_input() {
        let mut transmitter =
            Transmitter::new(MemoryPacketWriter::new()).with(DropAllTransform::new());

        let reports = transmitter.write_record(record("dropped")).unwrap();

        assert!(reports.is_empty());
    }

    #[test]
    fn send_record_returns_one_report_for_one_transformed_output() {
        let mut transmitter = Transmitter::new(MemoryPacketWriter::new())
            .with(RewritePayloadTransform::new("rewritten"));

        let reports = transmitter.send_record(record("input")).unwrap();

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].bytes_requested(), 9);
        assert_eq!(reports[0].bytes_written(), 9);
    }

    #[test]
    fn send_record_returns_all_reports_for_many_transformed_outputs() {
        let mut transmitter =
            Transmitter::new(MemoryPacketWriter::new()).with(DuplicateTransform::new());

        let reports = transmitter.send_record(record("payload")).unwrap();

        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].bytes_requested(), 7);
        assert_eq!(reports[0].bytes_written(), 7);
        assert_eq!(reports[1].bytes_requested(), 7);
        assert_eq!(reports[1].bytes_written(), 7);
    }

    #[test]
    fn send_record_returns_reports_in_fragment_metadata_order() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let writer = FragmentMetadataOrderWriter::new(Arc::clone(&writes));
        let mut transmitter = Transmitter::new(writer).with(FragmentMetadataTransform);

        let reports = transmitter.send_record(record("input")).unwrap();

        assert_eq!(reports.len(), 3);
        assert_eq!(
            reports
                .iter()
                .map(WriteReport::bytes_requested)
                .collect::<Vec<_>>(),
            [5, 3, 7]
        );
        let writes = writes.lock().unwrap();
        assert_eq!(*writes, [(0, 0, 5), (1, 8, 11), (2, 16, 23)]);
    }

    #[test]
    fn ip_fragment_transform_writes_multiple_fragments_through_memory_writer() {
        let payload = (0u8..21).collect::<Vec<_>>();
        let mut transmitter = Transmitter::new(MemoryPacketWriter::new()).with(IpFragment::new(40));

        let reports = transmitter.write_record(ipv4_record(&payload)).unwrap();

        assert_eq!(reports.len(), 2);
        assert_eq!(
            reports
                .iter()
                .map(WriteReport::bytes_requested)
                .collect::<Vec<_>>(),
            [36, 25]
        );
        assert_eq!(
            reports
                .iter()
                .map(WriteReport::bytes_written)
                .collect::<Vec<_>>(),
            [36, 25]
        );
        assert!(reports
            .iter()
            .all(|report| report.backend() == &BackendKind::Memory));
    }

    #[derive(Debug, Clone)]
    struct RewritePayloadTransform {
        payload: &'static str,
    }

    impl RewritePayloadTransform {
        const fn new(payload: &'static str) -> Self {
            Self { payload }
        }
    }

    impl PacketTransform for RewritePayloadTransform {
        fn name(&self) -> &'static str {
            "rewrite-payload"
        }

        fn transform(
            &mut self,
            _record: PacketRecord,
            emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
        ) -> Result<()> {
            emit(record(self.payload))
        }
    }

    #[derive(Debug, Clone)]
    struct FragmentMetadataTransform;

    impl PacketTransform for FragmentMetadataTransform {
        fn name(&self) -> &'static str {
            "fragment-metadata-test"
        }

        fn transform(
            &mut self,
            _record: PacketRecord,
            emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
        ) -> Result<()> {
            for (index, payload, range) in [
                (0, "first", IpFragmentRange::new(0, 5)),
                (1, "mid", IpFragmentRange::new(8, 11)),
                (2, "trailer", IpFragmentRange::new(16, 23)),
            ] {
                emit(
                    PacketRecord::new(Raw::from(payload)).with_ip_fragment_metadata(
                        IpFragmentMetadata::new(
                            IpFragmentFamily::Ipv4,
                            28,
                            0x4321,
                            (range.start() / 8) as u16,
                            index < 2,
                            3,
                            index,
                            range,
                        ),
                    ),
                )?;
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    struct FragmentMetadataOrderWriter {
        writes: Arc<Mutex<Vec<(usize, u32, u32)>>>,
    }

    impl FragmentMetadataOrderWriter {
        fn new(writes: Arc<Mutex<Vec<(usize, u32, u32)>>>) -> Self {
            Self { writes }
        }
    }

    impl PacketWriter for FragmentMetadataOrderWriter {
        fn write_record(&mut self, record: &PacketRecord) -> Result<WriteReport> {
            let metadata = &record.metadata().ip_fragment_metadata()[0];
            self.writes.lock().unwrap().push((
                metadata.fragment_index(),
                metadata.byte_range().start(),
                metadata.byte_range().end(),
            ));

            let byte_len = record.packet().compile()?.as_bytes().len();
            Ok(WriteReport::new(
                BackendKind::Memory,
                byte_len,
                byte_len,
                false,
            ))
        }
    }
}
