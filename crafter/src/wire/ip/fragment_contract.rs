use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use super::{IpFragment, IpFragmentFamily, IpFragmentMetadata, IpFragmentRange, IpFragmentReason};
use crate::wire::{
    BackendKind, PacketRecord, PacketWriter, Result, Transmitter, WireError, WriteReport,
};
use crate::{Ipv4, Raw};

const MTU: usize = 40;
const IDENTIFICATION: u16 = 0x3535;
const PROTOCOL: u8 = 253;

fn source() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 35)
}

fn destination() -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, 35)
}

fn ipv4_record(payload: &[u8]) -> PacketRecord {
    PacketRecord::new(
        Ipv4::with_addresses(source(), destination())
            .protocol(PROTOCOL)
            .identification(IDENTIFICATION)
            / Raw::from_bytes(payload),
    )
}

fn df_ipv4_record(payload: &[u8]) -> PacketRecord {
    PacketRecord::new(
        Ipv4::with_addresses(source(), destination())
            .protocol(PROTOCOL)
            .identification(IDENTIFICATION)
            .dont_fragment(true)
            / Raw::from_bytes(payload),
    )
}

fn opaque_record() -> PacketRecord {
    PacketRecord::new(Raw::from_bytes([0x01, 0x35, 0x00, 0xff]))
        .with_backend(BackendKind::Memory)
        .with_interface("fragment-contract")
}

fn preexisting_metadata() -> IpFragmentMetadata {
    IpFragmentMetadata::new(
        IpFragmentFamily::Ipv4,
        MTU,
        0xabcd,
        9,
        false,
        1,
        0,
        IpFragmentRange::new(72, 80),
    )
    .with_reason(IpFragmentReason::AlreadyFits)
}

#[test]
fn ip_fragment_pass_through_emits_one_record_without_queueing() {
    let input = opaque_record();
    let expected_packet = input.packet().compile().unwrap().into_bytes();
    let expected_metadata = input.metadata().clone();
    let mut transform = IpFragment::new(1280);

    let output = transform.fragment_record(input).unwrap();

    assert_eq!(output.len(), 1);
    assert_eq!(transform.input_count(), 1);
    assert_eq!(transform.emitted_count(), 1);
    assert_eq!(
        output.records()[0].packet().compile().unwrap().as_bytes(),
        expected_packet.as_slice()
    );
    assert_eq!(output.records()[0].metadata(), &expected_metadata);
}

#[test]
fn ip_fragment_multi_fragment_emission_keeps_metadata_order() {
    let payload = (0u8..21).collect::<Vec<_>>();
    let prior = preexisting_metadata();
    let mut transform = IpFragment::new(MTU);

    let output = transform
        .fragment_record(ipv4_record(&payload).with_ip_fragment_metadata(prior.clone()))
        .unwrap();

    assert_eq!(output.len(), 2);
    assert_eq!(transform.input_count(), 1);
    assert_eq!(transform.emitted_count(), 2);
    assert_ordered_fragment_metadata(
        output.records(),
        &payload,
        &prior,
        &[(0, 16, 0, true, 36), (16, 21, 2, false, 25)],
    );
}

#[test]
fn transmitter_write_report_order_follows_fragment_emission_order() {
    let writes = SharedFragmentWrites::default();
    let mut transmitter =
        Transmitter::new(RecordingFragmentWriter::new(writes.clone())).with(IpFragment::new(MTU));
    let payload = (0u8..21).collect::<Vec<_>>();

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

    let writes = writes.entries();
    assert_eq!(
        writes.len(),
        reports.len(),
        "no background queue or delayed flush should hold fragment writes after write_record returns"
    );
    assert_eq!(
        writes.iter().map(|write| write.index).collect::<Vec<_>>(),
        [0, 1],
        "emission order must match fragment metadata order"
    );
    assert_eq!(
        writes
            .iter()
            .map(|write| (write.start, write.end))
            .collect::<Vec<_>>(),
        [(0, 16), (16, 21)]
    );
    assert_eq!(
        writes
            .iter()
            .map(|write| write.bytes_requested)
            .collect::<Vec<_>>(),
        reports
            .iter()
            .map(WriteReport::bytes_requested)
            .collect::<Vec<_>>()
    );
}

#[test]
fn ip_fragment_structured_error_stops_transmitter_writes() {
    let writes = SharedFragmentWrites::default();
    let mut transmitter =
        Transmitter::new(RecordingFragmentWriter::new(writes.clone())).with(IpFragment::new(MTU));
    let payload = (0u8..21).collect::<Vec<_>>();

    let error = transmitter
        .write_record(df_ipv4_record(&payload))
        .unwrap_err();

    match error {
        WireError::Transform { transform, reason } => {
            assert_eq!(transform, "ip-fragment");
            assert_eq!(
                reason,
                "IPv4 Don't Fragment is set and packet exceeds configured MTU"
            );
        }
        other => panic!("expected structured transform error, got {other:?}"),
    }
    assert!(
        writes.entries().is_empty(),
        "no background writes should happen after a structured transform error"
    );
}

fn assert_ordered_fragment_metadata(
    records: &[PacketRecord],
    payload: &[u8],
    prior: &IpFragmentMetadata,
    expected: &[(usize, usize, u16, bool, u16)],
) {
    assert_eq!(records.len(), expected.len());
    for (index, (record, &(start, end, offset, more_fragments, total_len))) in
        records.iter().zip(expected).enumerate()
    {
        let metadata = record.metadata().ip_fragment_metadata();
        assert_eq!(metadata.len(), 2);
        assert_eq!(&metadata[0], prior);

        let fragment = &metadata[1];
        assert_eq!(fragment.family(), IpFragmentFamily::Ipv4);
        assert_eq!(fragment.mtu(), MTU);
        assert_eq!(fragment.identification(), u32::from(IDENTIFICATION));
        assert_eq!(fragment.fragment_offset(), offset);
        assert_eq!(fragment.more_fragments(), more_fragments);
        assert_eq!(fragment.fragment_count(), expected.len());
        assert_eq!(
            fragment.fragment_index(),
            index,
            "emission order must match appended fragment metadata"
        );
        assert_eq!(
            fragment.byte_range(),
            IpFragmentRange::new(start as u32, end as u32)
        );
        assert_eq!(fragment.original_len(), Some(payload.len() as u32));
        assert_eq!(fragment.reason(), Some(&IpFragmentReason::Fragmented));

        let ipv4 = record.packet().layer::<Ipv4>().unwrap();
        let raw = record.packet().layer::<Raw>().unwrap();
        assert_eq!(ipv4.total_length_value(), Some(total_len));
        assert_eq!(raw.as_bytes(), &payload[start..end]);
    }
}

#[derive(Debug, Clone, Default)]
struct SharedFragmentWrites {
    entries: Arc<Mutex<Vec<FragmentWrite>>>,
}

impl SharedFragmentWrites {
    fn entries(&self) -> Vec<FragmentWrite> {
        self.entries.lock().unwrap().clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FragmentWrite {
    index: usize,
    start: u32,
    end: u32,
    bytes_requested: usize,
}

#[derive(Debug, Clone)]
struct RecordingFragmentWriter {
    writes: SharedFragmentWrites,
}

impl RecordingFragmentWriter {
    const fn new(writes: SharedFragmentWrites) -> Self {
        Self { writes }
    }
}

impl PacketWriter for RecordingFragmentWriter {
    fn write_record(&mut self, record: &PacketRecord) -> Result<WriteReport> {
        let compiled = record.packet().compile()?;
        let byte_len = compiled.len();
        let metadata = record
            .metadata()
            .ip_fragment_metadata()
            .last()
            .expect("fragment metadata should be attached before write");
        self.writes.entries.lock().unwrap().push(FragmentWrite {
            index: metadata.fragment_index(),
            start: metadata.byte_range().start(),
            end: metadata.byte_range().end(),
            bytes_requested: byte_len,
        });

        Ok(WriteReport::new(
            BackendKind::Memory,
            byte_len,
            byte_len,
            false,
        ))
    }
}
