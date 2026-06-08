use super::{IpDefrag, IpDefragConfig};
use crate::pcap::PcapTimestamp;
use crate::wire::record::{BackendKind, PacketRecord};
use crate::{Ipv4, Ipv6, Ipv6FragmentHeader, Raw, IPPROTO_UDP};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

const IPV4_PROTOCOL: u8 = 253;
const IPV4_IDENT_BASE: u16 = 0x7000;
const IPV6_IDENT_BASE: u32 = 0x7000_0000;

fn ipv4_source(index: usize) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 1 + (index % 200) as u8)
}

fn ipv4_destination() -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, 58)
}

fn ipv6_source(index: usize) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 0x58, 0, 0, 0, 0, 1 + index as u16)
}

fn ipv6_destination() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 0x58, 0, 0, 0, 0, 0x100)
}

fn ipv4_fragment_record(
    index: usize,
    fragment_offset: u16,
    more_fragments: bool,
    payload: &[u8],
    seconds: u64,
) -> PacketRecord {
    let packet = Ipv4::new()
        .src(ipv4_source(index))
        .dst(ipv4_destination())
        .protocol(IPV4_PROTOCOL)
        .identification(IPV4_IDENT_BASE.wrapping_add(index as u16))
        .more_fragments(more_fragments)
        .fragment_offset(fragment_offset)
        / Raw::from_bytes(payload);

    PacketRecord::new(packet)
        .with_timestamp(PcapTimestamp::micros(seconds, 0).unwrap())
        .with_backend(BackendKind::Memory)
}

fn ipv6_fragment_record(
    index: usize,
    fragment_offset: u16,
    more_fragments: bool,
    payload: &[u8],
    seconds: u64,
) -> PacketRecord {
    let packet = Ipv6::new().src(ipv6_source(index)).dst(ipv6_destination())
        / Ipv6FragmentHeader::new()
            .next_header(IPPROTO_UDP)
            .identification(IPV6_IDENT_BASE + index as u32)
            .fragment_offset(fragment_offset)
            .more_fragments(more_fragments)
        / Raw::from_bytes(payload);

    PacketRecord::new(packet)
        .with_timestamp(PcapTimestamp::micros(seconds, 0).unwrap())
        .with_backend(BackendKind::Memory)
}

#[test]
fn many_incomplete_mixed_datagrams_respect_max_datagrams_bound() {
    const MAX_DATAGRAMS: usize = 32;
    const INPUTS: usize = 160;
    let payload = [0x5a; 8];
    let config = IpDefragConfig::new()
        .max_datagrams(MAX_DATAGRAMS)
        .max_bytes_per_datagram(4096);
    let mut transform = IpDefrag::new().with_config(config);

    for index in 0..INPUTS {
        let output = if index % 2 == 0 {
            transform.defrag_record(ipv4_fragment_record(index, 0, true, &payload, 1))
        } else {
            transform.defrag_record(ipv6_fragment_record(index, 0, true, &payload, 1))
        }
        .unwrap();

        assert!(output.is_empty());
        assert!(
            transform.pending_datagram_count() <= MAX_DATAGRAMS,
            "pending defrag state exceeded max_datagrams after input {index}"
        );
    }

    assert_eq!(transform.pending_datagram_count(), MAX_DATAGRAMS);
    assert_eq!(transform.eviction_count(), INPUTS - MAX_DATAGRAMS);
    assert_eq!(
        transform.datagram_limit_eviction_count(),
        INPUTS - MAX_DATAGRAMS
    );
    assert_eq!(transform.byte_limit_eviction_count(), 0);
    assert_eq!(transform.timeout_eviction_count(), 0);
    assert_eq!(transform.emitted_count(), 0);
}

#[test]
fn large_bounded_fragments_evict_at_max_bytes_without_completion() {
    const CHUNK_LEN: usize = 1024;
    const MAX_BYTES: usize = CHUNK_LEN * 8;
    let payload = vec![0xa5; CHUNK_LEN];
    let config = IpDefragConfig::new()
        .max_datagrams(8)
        .max_bytes_per_datagram(MAX_BYTES);
    let mut transform = IpDefrag::new().with_config(config);

    for fragment_index in 0..=MAX_BYTES / CHUNK_LEN {
        let output = transform
            .defrag_record(ipv4_fragment_record(
                1,
                (fragment_index * CHUNK_LEN / 8) as u16,
                true,
                &payload,
                1 + fragment_index as u64,
            ))
            .unwrap();

        assert!(output.is_empty());
        assert!(transform.pending_datagram_count() <= 1);
    }

    assert_eq!(transform.pending_datagram_count(), 0);
    assert_eq!(transform.eviction_count(), 1);
    assert_eq!(transform.byte_limit_eviction_count(), 1);
    assert_eq!(transform.datagram_limit_eviction_count(), 0);
    assert_eq!(transform.emitted_count(), 0);
}

#[test]
fn timeout_eviction_sweeps_many_incomplete_datagrams_deterministically() {
    const OLD_DATAGRAMS: usize = 64;
    let payload = [0x3c; 8];
    let config = IpDefragConfig::new()
        .max_datagrams(OLD_DATAGRAMS + 1)
        .max_age(Duration::from_secs(5));
    let mut transform = IpDefrag::new().with_config(config);

    for index in 0..OLD_DATAGRAMS {
        let output = transform
            .defrag_record(ipv4_fragment_record(index, 0, true, &payload, 10))
            .unwrap();

        assert!(output.is_empty());
    }
    assert_eq!(transform.pending_datagram_count(), OLD_DATAGRAMS);

    let output = transform
        .defrag_record(ipv4_fragment_record(OLD_DATAGRAMS, 0, true, &payload, 20))
        .unwrap();

    assert!(output.is_empty());
    assert_eq!(transform.pending_datagram_count(), 1);
    assert_eq!(transform.eviction_count(), OLD_DATAGRAMS);
    assert_eq!(transform.timeout_eviction_count(), OLD_DATAGRAMS);
    assert_eq!(transform.datagram_limit_eviction_count(), 0);
    assert_eq!(transform.byte_limit_eviction_count(), 0);
}
