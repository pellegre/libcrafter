use std::net::{Ipv4Addr, Ipv6Addr};

use crate::wire::{IpDefrag, PacketRecord, PacketTransform, Sniffer, VecPacketSource, WireError};
use crate::{CrafterError, Ipv4, Ipv6, Ipv6FragmentHeader, Raw, IPPROTO_TCP, IPPROTO_UDP};

const IPV4_ID: u16 = 0x4222;
const IPV6_ID: u32 = 0x6000_4222;

fn ipv4_source() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 42)
}

fn ipv4_destination() -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, 42)
}

fn ipv6_source() -> Ipv6Addr {
    "2001:db8:42::1".parse().unwrap()
}

fn ipv6_destination() -> Ipv6Addr {
    "2001:db8:42::2".parse().unwrap()
}

fn ipv4_fragment(fragment_offset: u16, more_fragments: bool, payload: &[u8]) -> PacketRecord {
    PacketRecord::new(
        Ipv4::with_addresses(ipv4_source(), ipv4_destination())
            .protocol(IPPROTO_UDP)
            .identification(IPV4_ID)
            .fragment_offset(fragment_offset)
            .more_fragments(more_fragments)
            / Raw::from_bytes(payload),
    )
}

fn ipv4_non_fragment() -> PacketRecord {
    PacketRecord::new(
        Ipv4::with_addresses(ipv4_source(), ipv4_destination()).protocol(IPPROTO_TCP)
            / Raw::from_bytes(b"not-fragmented"),
    )
}

fn ipv6_fragment(fragment_offset: u16, more_fragments: bool, payload: &[u8]) -> PacketRecord {
    PacketRecord::new(
        Ipv6::new().src(ipv6_source()).dst(ipv6_destination())
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_UDP)
                .identification(IPV6_ID)
                .fragment_offset(fragment_offset)
                .more_fragments(more_fragments)
            / Raw::from_bytes(payload),
    )
}

fn ipv6_non_fragment() -> PacketRecord {
    PacketRecord::new(
        Ipv6::new()
            .src(ipv6_source())
            .dst(ipv6_destination())
            .next_header(IPPROTO_TCP)
            / Raw::from_bytes(b"not-fragmented"),
    )
}

#[test]
fn defrag_contract_transform_to_output_incomplete_fragment_sets_emit_zero_records() {
    let mut ipv4_transform = IpDefrag::new();
    let ipv4_output = ipv4_transform
        .transform_to_output(ipv4_fragment(0, true, b"abcdefgh"))
        .unwrap();
    assert_eq!(ipv4_output.len(), 0);

    let mut ipv6_transform = IpDefrag::new();
    let ipv6_output = ipv6_transform
        .transform_to_output(ipv6_fragment(0, true, b"abcdefgh"))
        .unwrap();
    assert_eq!(ipv6_output.len(), 0);
}

#[test]
fn defrag_contract_sniffer_incomplete_fragment_sets_emit_zero_records() {
    let ipv4_records = Sniffer::new(VecPacketSource::new([ipv4_fragment(0, true, b"abcdefgh")]))
        .with(IpDefrag::new())
        .no_timeout()
        .collect_records()
        .unwrap();
    assert_eq!(ipv4_records.len(), 0);

    let ipv6_records = Sniffer::new(VecPacketSource::new([ipv6_fragment(0, true, b"abcdefgh")]))
        .with(IpDefrag::new())
        .no_timeout()
        .collect_records()
        .unwrap();
    assert_eq!(ipv6_records.len(), 0);
}

#[test]
fn defrag_contract_transform_to_output_complete_fragment_sets_emit_one_record() {
    let mut ipv4_transform = IpDefrag::new();
    assert!(ipv4_transform
        .transform_to_output(ipv4_fragment(1, false, b"ijkl"))
        .unwrap()
        .is_empty());
    let ipv4_output = ipv4_transform
        .transform_to_output(ipv4_fragment(0, true, b"abcdefgh"))
        .unwrap();
    assert_eq!(ipv4_output.len(), 1);
    assert_eq!(
        ipv4_output.records()[0]
            .metadata()
            .ip_defrag_metadata()
            .len(),
        1
    );

    let mut ipv6_transform = IpDefrag::new();
    assert!(ipv6_transform
        .transform_to_output(ipv6_fragment(1, false, b"ijkl"))
        .unwrap()
        .is_empty());
    let ipv6_output = ipv6_transform
        .transform_to_output(ipv6_fragment(0, true, b"abcdefgh"))
        .unwrap();
    assert_eq!(ipv6_output.len(), 1);
    assert_eq!(
        ipv6_output.records()[0]
            .metadata()
            .ip_defrag_metadata()
            .len(),
        1
    );
}

#[test]
fn defrag_contract_sniffer_complete_fragment_sets_emit_one_record() {
    let ipv4_records = Sniffer::new(VecPacketSource::new([
        ipv4_fragment(1, false, b"ijkl"),
        ipv4_fragment(0, true, b"abcdefgh"),
    ]))
    .with(IpDefrag::new())
    .no_timeout()
    .collect_records()
    .unwrap();
    assert_eq!(ipv4_records.len(), 1);
    assert_eq!(ipv4_records[0].metadata().ip_defrag_metadata().len(), 1);

    let ipv6_records = Sniffer::new(VecPacketSource::new([
        ipv6_fragment(1, false, b"ijkl"),
        ipv6_fragment(0, true, b"abcdefgh"),
    ]))
    .with(IpDefrag::new())
    .no_timeout()
    .collect_records()
    .unwrap();
    assert_eq!(ipv6_records.len(), 1);
    assert_eq!(ipv6_records[0].metadata().ip_defrag_metadata().len(), 1);
}

#[test]
fn defrag_contract_transform_to_output_non_fragmented_records_emit_one_record() {
    let mut ipv4_transform = IpDefrag::new();
    let ipv4_output = ipv4_transform
        .transform_to_output(ipv4_non_fragment())
        .unwrap();
    assert_eq!(ipv4_output.len(), 1);
    assert!(ipv4_output.records()[0]
        .metadata()
        .ip_defrag_metadata()
        .is_empty());

    let mut ipv6_transform = IpDefrag::new();
    let ipv6_output = ipv6_transform
        .transform_to_output(ipv6_non_fragment())
        .unwrap();
    assert_eq!(ipv6_output.len(), 1);
    assert!(ipv6_output.records()[0]
        .metadata()
        .ip_defrag_metadata()
        .is_empty());
}

#[test]
fn defrag_contract_sniffer_non_fragmented_records_emit_one_record() {
    let ipv4_records = Sniffer::new(VecPacketSource::new([ipv4_non_fragment()]))
        .with(IpDefrag::new())
        .no_timeout()
        .collect_records()
        .unwrap();
    assert_eq!(ipv4_records.len(), 1);

    let ipv6_records = Sniffer::new(VecPacketSource::new([ipv6_non_fragment()]))
        .with(IpDefrag::new())
        .no_timeout()
        .collect_records()
        .unwrap();
    assert_eq!(ipv6_records.len(), 1);
}

#[test]
fn defrag_contract_conflicting_overlaps_do_not_emit_ambiguous_reassemblies() {
    let mut ipv4_transform = IpDefrag::new();
    assert!(ipv4_transform
        .transform_to_output(ipv4_fragment(0, true, b"abcdefghijklmnop"))
        .unwrap()
        .is_empty());
    let ipv4_error = ipv4_transform
        .transform_to_output(ipv4_fragment(1, false, b"QRSTUVWX"))
        .unwrap_err();
    assert_ambiguous_overlap_error(ipv4_error, "ip.defrag.ipv4.overlap");
    assert_eq!(ipv4_transform.emitted_count(), 0);

    let mut ipv6_transform = IpDefrag::new();
    assert!(ipv6_transform
        .transform_to_output(ipv6_fragment(0, true, b"abcdefghijklmnop"))
        .unwrap()
        .is_empty());
    let ipv6_error = ipv6_transform
        .transform_to_output(ipv6_fragment(1, false, b"QRSTUVWX"))
        .unwrap_err();
    assert_ambiguous_overlap_error(ipv6_error, "ip.defrag.ipv6.overlap");
    assert_eq!(ipv6_transform.emitted_count(), 0);
}

#[test]
fn defrag_contract_sniffer_conflicting_overlaps_do_not_emit_ambiguous_reassemblies() {
    let mut ipv4_sniffer = Sniffer::new(VecPacketSource::new([
        ipv4_fragment(0, true, b"abcdefghijklmnop"),
        ipv4_fragment(1, false, b"QRSTUVWX"),
    ]))
    .with(IpDefrag::new())
    .no_timeout();
    let ipv4_error = ipv4_sniffer.next_record().unwrap_err();
    assert_ambiguous_overlap_error(ipv4_error, "ip.defrag.ipv4.overlap");
    assert_eq!(ipv4_sniffer.yielded(), 0);

    let mut ipv6_sniffer = Sniffer::new(VecPacketSource::new([
        ipv6_fragment(0, true, b"abcdefghijklmnop"),
        ipv6_fragment(1, false, b"QRSTUVWX"),
    ]))
    .with(IpDefrag::new())
    .no_timeout();
    let ipv6_error = ipv6_sniffer.next_record().unwrap_err();
    assert_ambiguous_overlap_error(ipv6_error, "ip.defrag.ipv6.overlap");
    assert_eq!(ipv6_sniffer.yielded(), 0);
}

fn assert_ambiguous_overlap_error(error: WireError, expected_field: &str) {
    match error {
        WireError::Packet(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, expected_field);
            assert!(reason.contains("ambiguous"));
        }
        other => panic!("expected ambiguous overlap error, got {other:?}"),
    }
}
