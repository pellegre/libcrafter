//! Packet writer contracts.

use super::record::{BackendKind, PacketRecord};
use super::Result;

/// Packet-shaped output for transmitters and outbound transform pipelines.
///
/// Implementers may write to pcap files, live interfaces, provider endpoints,
/// radio backends, or in-memory fixtures. The writer compiles packet records
/// into backend-specific bytes and returns an inspectable report for each
/// write.
pub trait PacketWriter {
    /// Write one packet record and report what the backend accepted.
    fn write_record(&mut self, record: &PacketRecord) -> Result<WriteReport>;
}

impl<T> PacketWriter for Box<T>
where
    T: PacketWriter + ?Sized,
{
    fn write_record(&mut self, record: &PacketRecord) -> Result<WriteReport> {
        self.as_mut().write_record(record)
    }
}

/// Report returned by a packet writer after one outbound record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteReport {
    backend: BackendKind,
    bytes_requested: usize,
    bytes_written: usize,
    dry_run: bool,
    target_details: Option<String>,
}

impl WriteReport {
    /// Create a write report.
    pub fn new(
        backend: BackendKind,
        bytes_requested: usize,
        bytes_written: usize,
        dry_run: bool,
    ) -> Self {
        Self {
            backend,
            bytes_requested,
            bytes_written,
            dry_run,
            target_details: None,
        }
    }

    /// Backend that handled the write.
    pub const fn backend(&self) -> &BackendKind {
        &self.backend
    }

    /// Number of bytes requested for output.
    pub const fn bytes_requested(&self) -> usize {
        self.bytes_requested
    }

    /// Number of bytes accepted by the backend.
    pub const fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    /// Return true when the write was planned without live backend emission.
    pub const fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Optional backend target details, such as an interface or file path.
    pub fn target_details(&self) -> Option<&str> {
        self.target_details.as_deref()
    }

    /// Set backend target details.
    pub fn with_target_details(mut self, target_details: impl Into<String>) -> Self {
        self.target_details = Some(target_details.into());
        self
    }

    /// Clear backend target details.
    pub fn clear_target_details(mut self) -> Self {
        self.target_details = None;
        self
    }
}

/// One packet write captured by [`MemoryPacketWriter`].
#[derive(Debug, Clone)]
pub struct MemoryWrite {
    record: PacketRecord,
    bytes: Vec<u8>,
    report: WriteReport,
}

impl MemoryWrite {
    /// Packet record supplied to the writer.
    pub const fn record(&self) -> &PacketRecord {
        &self.record
    }

    /// Compiled packet bytes written by the memory backend.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Report generated for this write.
    pub const fn report(&self) -> &WriteReport {
        &self.report
    }
}

/// In-memory packet writer for deterministic tests and synthetic pipelines.
#[derive(Debug, Clone, Default)]
pub struct MemoryPacketWriter {
    writes: Vec<MemoryWrite>,
    dry_run: bool,
    target_details: Option<String>,
}

impl MemoryPacketWriter {
    /// Create a memory writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a memory writer whose reports are marked as dry-run writes.
    pub fn dry_run() -> Self {
        Self {
            dry_run: true,
            ..Self::default()
        }
    }

    /// Set whether generated reports are marked as dry-run writes.
    pub const fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Set target details copied into every generated write report.
    pub fn with_target_details(mut self, target_details: impl Into<String>) -> Self {
        self.target_details = Some(target_details.into());
        self
    }

    /// Clear target details copied into generated write reports.
    pub fn clear_target_details(mut self) -> Self {
        self.target_details = None;
        self
    }

    /// Captured writes in write order.
    pub fn writes(&self) -> &[MemoryWrite] {
        &self.writes
    }

    /// Number of captured writes.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Whether the writer has not captured any writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Remove all captured writes.
    pub fn clear(&mut self) -> &mut Self {
        self.writes.clear();
        self
    }

    /// Consume the writer and return captured writes in write order.
    pub fn into_writes(self) -> Vec<MemoryWrite> {
        self.writes
    }
}

impl PacketWriter for MemoryPacketWriter {
    fn write_record(&mut self, record: &PacketRecord) -> Result<WriteReport> {
        let compiled = record.packet().compile()?;
        let bytes = compiled.into_bytes();
        let byte_len = bytes.len();
        let mut report = WriteReport::new(BackendKind::Memory, byte_len, byte_len, self.dry_run);
        if let Some(target_details) = &self.target_details {
            report = report.with_target_details(target_details.clone());
        }

        self.writes.push(MemoryWrite {
            record: record.clone(),
            bytes,
            report: report.clone(),
        });

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Raw;

    #[test]
    fn write_report_tracks_backend_counts_dry_run_and_target() {
        let report = WriteReport::new(BackendKind::Memory, 10, 8, true)
            .with_target_details("memory-fixture");

        assert_eq!(report.backend(), &BackendKind::Memory);
        assert_eq!(report.bytes_requested(), 10);
        assert_eq!(report.bytes_written(), 8);
        assert!(report.is_dry_run());
        assert_eq!(report.target_details(), Some("memory-fixture"));

        let report = report.clear_target_details();
        assert_eq!(report.target_details(), None);
    }

    #[test]
    fn memory_packet_writer_records_compiled_writes_in_order() {
        let mut writer = MemoryPacketWriter::new().with_target_details("tx-fixture");
        let first = PacketRecord::new(Raw::from("first"));
        let second = PacketRecord::new(Raw::from("second"));

        let first_report = writer.write_record(&first).unwrap();
        let second_report = writer.write_record(&second).unwrap();

        assert_eq!(first_report.bytes_requested(), 5);
        assert_eq!(first_report.bytes_written(), 5);
        assert_eq!(first_report.backend(), &BackendKind::Memory);
        assert!(!first_report.is_dry_run());
        assert_eq!(first_report.target_details(), Some("tx-fixture"));

        assert_eq!(second_report.bytes_requested(), 6);
        assert_eq!(writer.len(), 2);
        assert_eq!(writer.writes()[0].bytes(), b"first");
        assert_eq!(writer.writes()[0].record().packet().summary(), "Raw(len=5)");
        assert_eq!(writer.writes()[0].report(), &first_report);
        assert_eq!(writer.writes()[1].bytes(), b"second");
        assert_eq!(writer.writes()[1].report(), &second_report);
    }

    #[test]
    fn memory_packet_writer_can_mark_reports_as_dry_run() {
        let mut writer = MemoryPacketWriter::dry_run();
        let report = writer
            .write_record(&PacketRecord::new(Raw::from("payload")))
            .unwrap();

        assert!(report.is_dry_run());
        assert_eq!(report.bytes_requested(), 7);
        assert_eq!(report.bytes_written(), 7);
        assert_eq!(writer.writes()[0].report(), &report);
    }

    #[test]
    fn memory_packet_writer_supports_clearing_and_consuming_writes() {
        let mut writer = MemoryPacketWriter::new();
        assert!(writer.is_empty());

        writer
            .write_record(&PacketRecord::new(Raw::from("one")))
            .unwrap();
        assert!(!writer.is_empty());
        writer.clear();
        assert!(writer.is_empty());

        writer
            .write_record(&PacketRecord::new(Raw::from("two")))
            .unwrap();
        let writes = writer.into_writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].bytes(), b"two");
    }

    #[test]
    fn packet_writer_is_object_safe() {
        let mut writer = MemoryPacketWriter::new();
        let writer: &mut dyn PacketWriter = &mut writer;

        let report = writer
            .write_record(&PacketRecord::new(Raw::from("payload")))
            .unwrap();
        assert_eq!(report.bytes_written(), 7);
    }
}
