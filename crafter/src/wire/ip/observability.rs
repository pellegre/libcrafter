use std::net::Ipv4Addr;

use super::{IpDefrag, IpFragment};
use crate::wire::record::PacketRecord;
use crate::{Ipv4, Raw};

const MTU: usize = 40;
const IDENTIFICATION: u16 = 0x3939;
const PROTOCOL: u8 = 253;

fn source() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 39)
}

fn destination() -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, 39)
}

fn source_two() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 40)
}

fn raw_record(payload: &[u8]) -> PacketRecord {
    PacketRecord::new(Raw::from_bytes(payload))
}

fn ipv4_fragment_record(
    source: Ipv4Addr,
    fragment_offset: u16,
    more_fragments: bool,
    payload: &[u8],
) -> PacketRecord {
    PacketRecord::new(
        Ipv4::with_addresses(source, destination())
            .protocol(PROTOCOL)
            .identification(IDENTIFICATION)
            .fragment_offset(fragment_offset)
            .more_fragments(more_fragments)
            / Raw::from_bytes(payload),
    )
}

fn oversized_ipv4_record(payload: &[u8]) -> PacketRecord {
    PacketRecord::new(
        Ipv4::with_addresses(source(), destination())
            .protocol(PROTOCOL)
            .identification(IDENTIFICATION)
            / Raw::from_bytes(payload),
    )
}

fn oversized_df_ipv4_record(payload: &[u8]) -> PacketRecord {
    PacketRecord::new(
        Ipv4::with_addresses(source(), destination())
            .protocol(PROTOCOL)
            .identification(IDENTIFICATION)
            .dont_fragment(true)
            / Raw::from_bytes(payload),
    )
}

#[test]
fn defrag_stats_count_pass_through_and_completed_datagrams() {
    let mut transform = IpDefrag::new().trace_passthrough(true);

    let pass_through = transform.defrag_record(raw_record(b"opaque")).unwrap();
    assert_eq!(pass_through.len(), 1);
    assert!(transform
        .defrag_record(ipv4_fragment_record(source(), 1, false, b"ijkl"))
        .unwrap()
        .is_empty());
    let reassembled = transform
        .defrag_record(ipv4_fragment_record(source(), 0, true, b"abcdefgh"))
        .unwrap();

    assert_eq!(reassembled.len(), 1);
    assert_eq!(transform.input_count(), 3);
    assert_eq!(transform.emitted_count(), 2);
    assert_eq!(transform.pass_through_count(), 1);
    assert_eq!(transform.fragments_observed(), 2);
    assert_eq!(transform.completed_datagrams(), 1);
    assert_eq!(transform.evicted_datagrams(), 0);
    assert_eq!(transform.conflicts(), 0);
    assert_eq!(transform.errors(), 0);

    let stats = transform.stats();
    assert_eq!(stats.input_count(), 3);
    assert_eq!(stats.emitted_count(), 2);
    assert_eq!(stats.pass_through_count(), 1);
    assert_eq!(stats.fragments_observed(), 2);
    assert_eq!(stats.completed_datagrams(), 1);
    assert_eq!(stats.evicted_datagrams(), 0);
    assert_eq!(stats.conflicts(), 0);
    assert_eq!(stats.errors(), 0);
}

#[test]
fn defrag_stats_count_evicted_datagrams_conflicts_and_errors() {
    let mut evicting = IpDefrag::new().max_datagrams(1);
    assert!(evicting
        .defrag_record(ipv4_fragment_record(source(), 0, true, b"abcdefgh"))
        .unwrap()
        .is_empty());
    assert!(evicting
        .defrag_record(ipv4_fragment_record(source_two(), 0, true, b"abcdefgh"))
        .unwrap()
        .is_empty());
    assert_eq!(evicting.fragments_observed(), 2);
    assert_eq!(evicting.evicted_datagrams(), 1);
    assert_eq!(evicting.stats().evicted_datagrams(), 1);

    let mut conflicting = IpDefrag::new();
    assert!(conflicting
        .defrag_record(ipv4_fragment_record(source(), 0, true, b"abcdefghijklmnop"))
        .unwrap()
        .is_empty());
    let error = conflicting
        .defrag_record(ipv4_fragment_record(source(), 1, false, b"QRSTUVWX"))
        .unwrap_err();
    assert!(!error.to_string().is_empty());
    assert_eq!(conflicting.fragments_observed(), 2);
    assert_eq!(conflicting.conflicts(), 1);
    assert_eq!(conflicting.errors(), 1);
    assert_eq!(conflicting.stats().conflicts(), 1);
    assert_eq!(conflicting.stats().errors(), 1);
}

#[test]
fn fragment_stats_count_emitted_fragments_and_pass_through() {
    let payload = (0u8..21).collect::<Vec<_>>();
    let mut transform = IpFragment::new(MTU);

    let fragments = transform
        .fragment_record(oversized_ipv4_record(&payload))
        .unwrap();
    assert_eq!(fragments.len(), 2);
    assert_eq!(transform.input_count(), 1);
    assert_eq!(transform.emitted_count(), 2);
    assert_eq!(transform.pass_through_count(), 0);
    assert_eq!(transform.fragments_observed(), 2);
    assert_eq!(transform.completed_datagrams(), 1);
    assert_eq!(transform.evicted_datagrams(), 0);
    assert_eq!(transform.conflicts(), 0);
    assert_eq!(transform.errors(), 0);

    let pass_through = transform.fragment_record(raw_record(b"opaque")).unwrap();
    assert_eq!(pass_through.len(), 1);
    let stats = transform.stats();
    assert_eq!(stats.input_count(), 2);
    assert_eq!(stats.emitted_count(), 3);
    assert_eq!(stats.pass_through_count(), 1);
    assert_eq!(stats.fragments_observed(), 2);
    assert_eq!(stats.completed_datagrams(), 1);
    assert_eq!(stats.evicted_datagrams(), 0);
    assert_eq!(stats.conflicts(), 0);
    assert_eq!(stats.errors(), 0);
}

#[test]
fn fragment_stats_count_errors() {
    let payload = (0u8..21).collect::<Vec<_>>();
    let mut transform = IpFragment::new(MTU);

    let error = transform
        .fragment_record(oversized_df_ipv4_record(&payload))
        .unwrap_err();

    assert!(!error.to_string().is_empty());
    assert_eq!(transform.input_count(), 1);
    assert_eq!(transform.emitted_count(), 0);
    assert_eq!(transform.pass_through_count(), 0);
    assert_eq!(transform.fragments_observed(), 0);
    assert_eq!(transform.completed_datagrams(), 0);
    assert_eq!(transform.errors(), 1);
    assert_eq!(transform.stats().errors(), 1);
}
