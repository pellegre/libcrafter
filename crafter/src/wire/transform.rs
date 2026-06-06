//! Stateful packet transform contracts.

use super::record::{PacketRecord, TransformTrace};
use super::Result;

/// Stateful packet-record transform for sniffer and transmitter pipelines.
///
/// A transform consumes one [`PacketRecord`] and may emit zero, one, or many
/// packet records through the supplied callback. Implementers can keep state
/// across calls for decryption, defragmentation, reassembly, or protocol
/// decoding without changing the packet-shaped stream contract. Future WPA
/// decryptors belong here: they can observe handshake records, retain key
/// state, and emit decrypted packet records when payload frames become
/// decodable.
pub trait PacketTransform {
    /// Stable transform name used in diagnostics and transform traces.
    fn name(&self) -> &'static str;

    /// Transform one input record and emit zero or more output records.
    fn transform(
        &mut self,
        record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()>;

    /// Run the transform and collect emitted records into a small buffer.
    fn transform_to_output(&mut self, record: PacketRecord) -> Result<TransformOutput>
    where
        Self: Sized,
    {
        let mut output = TransformOutput::new();
        self.transform(record, &mut |record| {
            output.push(record);
            Ok(())
        })?;
        Ok(output)
    }
}

/// Buffered output from one packet transform invocation.
#[derive(Debug, Clone, Default)]
pub struct TransformOutput {
    records: Vec<PacketRecord>,
}

impl TransformOutput {
    /// Create an empty transform output buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Buffered records in emission order.
    pub fn records(&self) -> &[PacketRecord] {
        &self.records
    }

    /// Number of buffered records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no records were emitted.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Append one output record.
    pub fn push(&mut self, record: PacketRecord) -> &mut Self {
        self.records.push(record);
        self
    }

    /// Append one output record through a callback-compatible method.
    pub fn emit(&mut self, record: PacketRecord) -> Result<()> {
        self.records.push(record);
        Ok(())
    }

    /// Remove all buffered output records.
    pub fn clear(&mut self) -> &mut Self {
        self.records.clear();
        self
    }

    /// Consume the output buffer and return records in emission order.
    pub fn into_records(self) -> Vec<PacketRecord> {
        self.records
    }
}

/// Test and fixture transform that emits each input record unchanged.
#[derive(Debug, Clone, Default)]
pub struct PassThroughTransform {
    input_count: usize,
    emitted_count: usize,
}

impl PassThroughTransform {
    /// Create a pass-through transform.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of input records seen.
    pub const fn input_count(&self) -> usize {
        self.input_count
    }

    /// Number of records successfully emitted.
    pub const fn emitted_count(&self) -> usize {
        self.emitted_count
    }
}

impl PacketTransform for PassThroughTransform {
    fn name(&self) -> &'static str {
        "pass-through"
    }

    fn transform(
        &mut self,
        record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        self.input_count += 1;
        emit(record)?;
        self.emitted_count += 1;
        Ok(())
    }
}

/// Test and fixture transform that drops every input record.
#[derive(Debug, Clone, Default)]
pub struct DropAllTransform {
    dropped_count: usize,
}

impl DropAllTransform {
    /// Create a drop-all transform.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of input records dropped.
    pub const fn dropped_count(&self) -> usize {
        self.dropped_count
    }
}

impl PacketTransform for DropAllTransform {
    fn name(&self) -> &'static str {
        "drop-all"
    }

    fn transform(
        &mut self,
        _record: PacketRecord,
        _emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        self.dropped_count += 1;
        Ok(())
    }
}

/// Test and fixture transform that emits two copies of each input record.
#[derive(Debug, Clone, Default)]
pub struct DuplicateTransform {
    input_count: usize,
    emitted_count: usize,
}

impl DuplicateTransform {
    /// Create a duplicate transform.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of input records seen.
    pub const fn input_count(&self) -> usize {
        self.input_count
    }

    /// Number of records successfully emitted.
    pub const fn emitted_count(&self) -> usize {
        self.emitted_count
    }
}

impl PacketTransform for DuplicateTransform {
    fn name(&self) -> &'static str {
        "duplicate"
    }

    fn transform(
        &mut self,
        record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        self.input_count += 1;
        emit(record.clone())?;
        self.emitted_count += 1;
        emit(record)?;
        self.emitted_count += 1;
        Ok(())
    }
}

/// Test and fixture transform that appends a transform trace and emits one record.
#[derive(Debug, Clone)]
pub struct TraceAppendTransform {
    name: &'static str,
    note: Option<String>,
    input_count: usize,
    emitted_count: usize,
}

impl TraceAppendTransform {
    /// Create a trace-append transform with a stable trace name.
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            note: None,
            input_count: 0,
            emitted_count: 0,
        }
    }

    /// Create the default trace-append helper.
    pub const fn trace_append() -> Self {
        Self::new("trace-append")
    }

    /// Set a note copied into appended transform traces.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Number of input records seen.
    pub const fn input_count(&self) -> usize {
        self.input_count
    }

    /// Number of records successfully emitted.
    pub const fn emitted_count(&self) -> usize {
        self.emitted_count
    }
}

impl Default for TraceAppendTransform {
    fn default() -> Self {
        Self::trace_append()
    }
}

impl PacketTransform for TraceAppendTransform {
    fn name(&self) -> &'static str {
        self.name
    }

    fn transform(
        &mut self,
        mut record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        self.input_count += 1;

        let mut trace = TransformTrace::new(self.name());
        if let Some(note) = &self.note {
            trace = trace.with_note(note.clone());
        }
        record.metadata_mut().push_transform_trace(trace);

        emit(record)?;
        self.emitted_count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::record::{BackendKind, PacketOrigin};
    use super::super::WireError;
    use super::*;
    use crate::Raw;

    fn record(payload: &'static str) -> PacketRecord {
        PacketRecord::new(Raw::from(payload))
            .with_origin(PacketOrigin::Generated)
            .with_backend(BackendKind::Memory)
            .with_interface("lo")
    }

    #[test]
    fn transform_output_buffers_records_in_order() {
        let mut output = TransformOutput::new();
        assert!(output.is_empty());

        output.push(record("one"));
        output.emit(record("two")).unwrap();

        assert_eq!(output.len(), 2);
        assert_eq!(output.records()[0].packet().summary(), "Raw(len=3)");
        assert_eq!(output.records()[1].packet().summary(), "Raw(len=3)");

        output.clear();
        assert!(output.is_empty());
    }

    #[test]
    fn pass_through_emits_one_record_unchanged() {
        let input = record("payload");
        let mut transform = PassThroughTransform::new();

        let output = transform.transform_to_output(input).unwrap();

        assert_eq!(transform.name(), "pass-through");
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 1);
        assert_eq!(output.len(), 1);
        assert_eq!(output.records()[0].packet().summary(), "Raw(len=7)");
        assert_eq!(
            output.records()[0].metadata().origin(),
            PacketOrigin::Generated
        );
        assert_eq!(
            output.records()[0].metadata().backend(),
            &BackendKind::Memory
        );
        assert_eq!(output.records()[0].metadata().interface(), Some("lo"));
    }

    #[test]
    fn drop_all_emits_zero_records() {
        let mut transform = DropAllTransform::new();

        let output = transform.transform_to_output(record("payload")).unwrap();

        assert_eq!(transform.name(), "drop-all");
        assert_eq!(transform.dropped_count(), 1);
        assert!(output.is_empty());
    }

    #[test]
    fn duplicate_emits_two_records_per_input() {
        let mut transform = DuplicateTransform::new();

        let output = transform.transform_to_output(record("payload")).unwrap();

        assert_eq!(transform.name(), "duplicate");
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 2);
        assert_eq!(output.len(), 2);
        assert_eq!(output.records()[0].packet().summary(), "Raw(len=7)");
        assert_eq!(output.records()[1].packet().summary(), "Raw(len=7)");
        assert_eq!(
            output.records()[0].metadata().origin(),
            PacketOrigin::Generated
        );
        assert_eq!(
            output.records()[1].metadata().backend(),
            &BackendKind::Memory
        );
    }

    #[test]
    fn trace_append_adds_transform_history() {
        let mut transform = TraceAppendTransform::new("decode-ip").with_note("decoded");

        let output = transform.transform_to_output(record("payload")).unwrap();

        assert_eq!(transform.name(), "decode-ip");
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 1);
        assert_eq!(output.len(), 1);
        let traces = output.records()[0].metadata().transforms();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].name(), "decode-ip");
        assert_eq!(traces[0].note(), Some("decoded"));
        assert_eq!(output.records()[0].packet().summary(), "Raw(len=7)");
    }

    #[test]
    fn packet_transform_is_object_safe() {
        let mut transform: Box<dyn PacketTransform> = Box::new(PassThroughTransform::new());
        let mut output = TransformOutput::new();

        transform
            .transform(record("payload"), &mut |record| output.emit(record))
            .unwrap();

        assert_eq!(transform.name(), "pass-through");
        assert_eq!(output.len(), 1);
        assert_eq!(output.records()[0].packet().summary(), "Raw(len=7)");
    }

    #[test]
    fn transform_propagates_emitter_errors() {
        let mut transform = DuplicateTransform::new();

        let err = transform
            .transform(record("payload"), &mut |_record| {
                Err(WireError::transform("collector", "closed"))
            })
            .unwrap_err();

        assert_eq!(err.to_string(), "wire transform 'collector' failed: closed");
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 0);
    }
}
