use std::sync::{Arc, Mutex};

use std::net::Ipv4Addr;

use crate::{Ipv4, Raw};

use super::{
    BackendKind, DropAllTransform, DuplicateTransform, IpDefrag, PacketOrigin, PacketRecord,
    PacketTransform, PacketWriter, PassThroughTransform, Result, Sniffer, TraceAppendTransform,
    TransformTrace, Transmitter, VecPacketSource, WireError, WriteReport,
};

fn make_record(payload: impl Into<String>) -> PacketRecord {
    let payload = payload.into();
    PacketRecord::new(Raw::from(payload.clone()))
        .with_origin(PacketOrigin::Generated)
        .with_backend(BackendKind::Memory)
        .with_interface(payload)
}

fn packet_bytes(record: &PacketRecord) -> Vec<u8> {
    record.packet().compile().unwrap().into_bytes()
}

fn packet_text(record: &PacketRecord) -> String {
    String::from_utf8(packet_bytes(record)).unwrap()
}

fn assert_packet_shaped(records: &[PacketRecord]) {
    for record in records {
        assert!(!record.packet().compile().unwrap().as_bytes().is_empty());
    }
}

#[test]
fn transform_contract_sniffer_emits_zero_one_and_many_packet_records() {
    let one = Sniffer::new(VecPacketSource::new([make_record("one")]))
        .with(PassThroughTransform::new())
        .no_timeout()
        .collect_records()
        .unwrap();
    assert_eq!(texts(&one), ["one"]);
    assert_packet_shaped(&one);

    let zero = Sniffer::new(VecPacketSource::new([make_record("drop")]))
        .with(DropAllTransform::new())
        .no_timeout()
        .collect_records()
        .unwrap();
    assert!(zero.is_empty());

    let many = Sniffer::new(VecPacketSource::new([make_record("many")]))
        .with(DuplicateTransform::new())
        .no_timeout()
        .collect_records()
        .unwrap();
    assert_eq!(texts(&many), ["many", "many"]);
    assert_packet_shaped(&many);
}

#[test]
fn transform_contract_transmitter_emits_zero_one_and_many_packet_records() {
    let writes = SharedWrites::default();
    let mut transmitter =
        Transmitter::new(RecordingWriter::new(writes.clone())).with(PassThroughTransform::new());
    let reports = transmitter.write_record(make_record("one")).unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(writes.texts(), ["one"]);

    let writes = SharedWrites::default();
    let mut transmitter =
        Transmitter::new(RecordingWriter::new(writes.clone())).with(DropAllTransform::new());
    let reports = transmitter.write_record(make_record("drop")).unwrap();
    assert!(reports.is_empty());
    assert!(writes.records().is_empty());

    let writes = SharedWrites::default();
    let mut transmitter =
        Transmitter::new(RecordingWriter::new(writes.clone())).with(DuplicateTransform::new());
    let reports = transmitter.write_record(make_record("many")).unwrap();
    assert_eq!(reports.len(), 2);
    assert_eq!(writes.texts(), ["many", "many"]);
    assert_packet_shaped(&writes.records());
}

#[test]
fn transform_contract_trace_metadata_is_preserved_on_both_paths() {
    let sniffer_records = Sniffer::new(VecPacketSource::new([make_record("rx")]))
        .with(TraceAppendTransform::new("decode-l2").with_note("packet-shaped"))
        .no_timeout()
        .collect_records()
        .unwrap();
    assert_trace(&sniffer_records[0], "decode-l2", Some("packet-shaped"));

    let writes = SharedWrites::default();
    let mut transmitter = Transmitter::new(RecordingWriter::new(writes.clone()))
        .with(TraceAppendTransform::new("encode-l2").with_note("packet-shaped"));
    let reports = transmitter.write_record(make_record("tx")).unwrap();
    assert_eq!(reports.len(), 1);

    let written = writes.records();
    assert_eq!(written.len(), 1);
    assert_trace(&written[0], "encode-l2", Some("packet-shaped"));
    assert_packet_shaped(&written);
}

#[test]
fn transform_contract_errors_stop_sniffer_and_transmitter_outputs() {
    let mut sniffer = Sniffer::new(VecPacketSource::new([make_record("rx")]))
        .with(FailTransform::new("rx-fail"))
        .no_timeout();
    let err = sniffer.next_record().unwrap_err();
    assert_eq!(
        err.to_string(),
        "wire transform 'rx-fail' failed: contract failure"
    );

    let writes = SharedWrites::default();
    let mut transmitter =
        Transmitter::new(RecordingWriter::new(writes.clone())).with(FailTransform::new("tx-fail"));
    let err = transmitter.write_record(make_record("tx")).unwrap_err();
    assert_eq!(
        err.to_string(),
        "wire transform 'tx-fail' failed: contract failure"
    );
    assert!(writes.records().is_empty());
}

#[test]
fn transform_contract_buffered_outputs_keep_input_ordering() {
    let records = Sniffer::new(VecPacketSource::new([
        make_record("first"),
        make_record("second"),
    ]))
    .with(SequencedFanoutTransform::new())
    .no_timeout()
    .collect_records()
    .unwrap();

    assert_eq!(
        texts(&records),
        [
            "first:copy-1",
            "first:copy-2",
            "second:copy-1",
            "second:copy-2"
        ]
    );
    assert_packet_shaped(&records);

    let writes = SharedWrites::default();
    let mut transmitter = Transmitter::new(RecordingWriter::new(writes.clone()))
        .with(SequencedFanoutTransform::new());
    let reports = transmitter.write_record(make_record("tx")).unwrap();

    assert_eq!(reports.len(), 2);
    assert_eq!(writes.texts(), ["tx:copy-1", "tx:copy-2"]);
}

#[test]
fn transform_contract_stateful_handshake_update_can_emit_later_packet() {
    let source = VecPacketSource::new([
        make_record("handshake:labnet"),
        make_record("protected:ipv4-payload"),
    ]);

    let records = Sniffer::new(source)
        .with(HandshakeLikeDecryptTransform::new("labnet"))
        .no_timeout()
        .collect_records()
        .unwrap();

    assert_eq!(texts(&records), ["decrypted:labnet:ipv4-payload"]);
    assert_eq!(records[0].metadata().origin(), PacketOrigin::Transformed);
    assert_trace(&records[0], "handshake-like-decrypt", Some("keys-ready"));
    assert_packet_shaped(&records);
}

#[test]
fn transform_contract_ip_defrag_uses_zero_one_and_passthrough_outputs() {
    let mut direct = IpDefrag::new();
    let incomplete = direct
        .transform_to_output(ipv4_fragment_record(0, true, b"abcdefgh"))
        .unwrap();
    assert!(incomplete.is_empty());

    let complete = direct
        .transform_to_output(ipv4_fragment_record(1, false, b"ijkl"))
        .unwrap();
    assert_eq!(complete.len(), 1);
    assert_packet_shaped(complete.records());

    let non_fragmented = direct
        .transform_to_output(ipv4_non_fragmented_record())
        .unwrap();
    assert_eq!(non_fragmented.len(), 1);
    assert_packet_shaped(non_fragmented.records());

    let sniffer_records = Sniffer::new(VecPacketSource::new([
        ipv4_fragment_record(0, true, b"abcdefgh"),
        ipv4_fragment_record(1, false, b"ijkl"),
        ipv4_non_fragmented_record(),
    ]))
    .with(IpDefrag::new())
    .no_timeout()
    .collect_records()
    .unwrap();
    assert_eq!(sniffer_records.len(), 2);
    assert_packet_shaped(&sniffer_records);
}

fn texts(records: &[PacketRecord]) -> Vec<String> {
    records.iter().map(packet_text).collect()
}

fn assert_trace(record: &PacketRecord, name: &str, note: Option<&str>) {
    let traces = record.metadata().transforms();
    assert_eq!(traces.len(), 1);
    assert_eq!(traces[0].name(), name);
    assert_eq!(traces[0].note(), note);
}

fn ipv4_fragment_record(
    fragment_offset: u16,
    more_fragments: bool,
    payload: &[u8],
) -> PacketRecord {
    PacketRecord::new(
        Ipv4::with_addresses(
            Ipv4Addr::new(192, 0, 2, 77),
            Ipv4Addr::new(198, 51, 100, 77),
        )
        .protocol(17)
        .identification(0x7777)
        .fragment_offset(fragment_offset)
        .more_fragments(more_fragments)
            / Raw::from_bytes(payload),
    )
}

fn ipv4_non_fragmented_record() -> PacketRecord {
    PacketRecord::new(
        Ipv4::with_addresses(
            Ipv4Addr::new(192, 0, 2, 77),
            Ipv4Addr::new(198, 51, 100, 77),
        )
        .protocol(6)
            / Raw::from_bytes(b"not-fragmented"),
    )
}

#[derive(Debug, Clone, Default)]
struct SharedWrites {
    records: Arc<Mutex<Vec<PacketRecord>>>,
}

impl SharedWrites {
    fn records(&self) -> Vec<PacketRecord> {
        self.records.lock().unwrap().clone()
    }

    fn texts(&self) -> Vec<String> {
        texts(&self.records())
    }
}

#[derive(Debug, Clone)]
struct RecordingWriter {
    writes: SharedWrites,
}

impl RecordingWriter {
    const fn new(writes: SharedWrites) -> Self {
        Self { writes }
    }
}

impl PacketWriter for RecordingWriter {
    fn write_record(&mut self, record: &PacketRecord) -> Result<WriteReport> {
        let compiled = record.packet().compile()?;
        let len = compiled.len();
        self.writes.records.lock().unwrap().push(record.clone());
        Ok(WriteReport::new(BackendKind::Memory, len, len, false))
    }
}

#[derive(Debug, Clone)]
struct FailTransform {
    name: &'static str,
}

impl FailTransform {
    const fn new(name: &'static str) -> Self {
        Self { name }
    }
}

impl PacketTransform for FailTransform {
    fn name(&self) -> &'static str {
        self.name
    }

    fn transform(
        &mut self,
        _record: PacketRecord,
        _emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        Err(WireError::transform(self.name, "contract failure"))
    }
}

#[derive(Debug, Clone, Default)]
struct SequencedFanoutTransform;

impl SequencedFanoutTransform {
    const fn new() -> Self {
        Self
    }
}

impl PacketTransform for SequencedFanoutTransform {
    fn name(&self) -> &'static str {
        "sequenced-fanout"
    }

    fn transform(
        &mut self,
        record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        let text = packet_text(&record);
        emit(make_record(format!("{text}:copy-1")))?;
        emit(make_record(format!("{text}:copy-2")))
    }
}

#[derive(Debug, Clone)]
struct HandshakeLikeDecryptTransform {
    ssid: &'static str,
    handshake_seen: bool,
}

impl HandshakeLikeDecryptTransform {
    const fn new(ssid: &'static str) -> Self {
        Self {
            ssid,
            handshake_seen: false,
        }
    }
}

impl PacketTransform for HandshakeLikeDecryptTransform {
    fn name(&self) -> &'static str {
        "handshake-like-decrypt"
    }

    fn transform(
        &mut self,
        record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        let text = packet_text(&record);
        if text == format!("handshake:{}", self.ssid) {
            self.handshake_seen = true;
            return Ok(());
        }

        if let Some(payload) = text.strip_prefix("protected:") {
            if self.handshake_seen {
                let output =
                    PacketRecord::new(Raw::from(format!("decrypted:{}:{payload}", self.ssid)))
                        .with_origin(PacketOrigin::Transformed)
                        .with_backend(BackendKind::Memory)
                        .with_transform_trace(
                            TransformTrace::new(self.name())
                                .with_note("keys-ready")
                                .with_input_len(text.len() as u32)
                                .with_output_len((self.ssid.len() + payload.len() + 11) as u32),
                        );
                return emit(output);
            }
        }

        emit(record)
    }
}
