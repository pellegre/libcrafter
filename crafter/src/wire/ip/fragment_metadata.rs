use std::net::{Ipv4Addr, Ipv6Addr};

use super::{IpFragment, IpFragmentFamily, IpFragmentRange, IpFragmentReason};
use crate::wire::record::PacketRecord;
use crate::{Ipv4, Ipv6, Ipv6FragmentHeader, Raw, IPPROTO_TCP, IPPROTO_UDP};

fn ipv4_source() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 24)
}

fn ipv4_destination() -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, 24)
}

fn ipv6_source() -> Ipv6Addr {
    "2001:db8:24::1".parse().unwrap()
}

fn ipv6_destination() -> Ipv6Addr {
    "2001:db8:24::2".parse().unwrap()
}

#[test]
fn ipv4_single_emission_attaches_fragment_metadata() {
    let record = PacketRecord::new(
        Ipv4::with_addresses(ipv4_source(), ipv4_destination())
            .protocol(IPPROTO_UDP)
            .identification(0x2457)
            / Raw::from_bytes(b"abcdefghijklmnop"),
    );
    let mut transform = IpFragment::new(1500);

    let output = transform.fragment_record(record).unwrap();

    assert_eq!(output.len(), 1);
    let metadata = output.records()[0].metadata().ip_fragment_metadata();
    assert_eq!(metadata.len(), 1);
    let metadata = &metadata[0];
    assert_eq!(metadata.family(), IpFragmentFamily::Ipv4);
    assert_eq!(metadata.mtu(), 1500);
    assert_eq!(metadata.identification(), 0x2457);
    assert_eq!(metadata.fragment_offset(), 0);
    assert_eq!(metadata.fragment_offset_bytes(), 0);
    assert!(!metadata.more_fragments());
    assert_eq!(metadata.fragment_count(), 1);
    assert_eq!(metadata.fragment_index(), 0);
    assert_eq!(metadata.emitted_index(), 0);
    assert_eq!(metadata.byte_range(), IpFragmentRange::new(0, 16));
    assert_eq!(metadata.original_len(), Some(16));
    assert_eq!(metadata.reason(), Some(&IpFragmentReason::AlreadyFits));
}

#[test]
fn ipv4_fragment_emission_records_offset_range_and_more_fragments() {
    let record = PacketRecord::new(
        Ipv4::with_addresses(ipv4_source(), ipv4_destination())
            .protocol(IPPROTO_TCP)
            .identification(0x2468)
            .fragment_offset(3)
            .more_fragments(true)
            / Raw::from_bytes(b"qrstuvwx"),
    );
    let mut transform = IpFragment::new(576);

    let output = transform.fragment_record(record).unwrap();

    let metadata = &output.records()[0].metadata().ip_fragment_metadata()[0];
    assert_eq!(metadata.family(), IpFragmentFamily::Ipv4);
    assert_eq!(metadata.mtu(), 576);
    assert_eq!(metadata.identification(), 0x2468);
    assert_eq!(metadata.fragment_offset(), 3);
    assert_eq!(metadata.fragment_offset_bytes(), 24);
    assert!(metadata.more_fragments());
    assert_eq!(metadata.fragment_count(), 1);
    assert_eq!(metadata.fragment_index(), 0);
    assert_eq!(metadata.byte_range(), IpFragmentRange::new(24, 32));
    assert_eq!(metadata.original_len(), Some(8));
    assert_eq!(metadata.reason(), Some(&IpFragmentReason::Fragmented));
}

#[test]
fn ipv6_fragment_header_emission_attaches_fragment_metadata() {
    let record = PacketRecord::new(
        Ipv6::new()
            .src(ipv6_source())
            .dst(ipv6_destination())
            .next_header(crate::IPPROTO_IPV6_FRAGMENT)
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_UDP)
                .identification(0x1020_3040)
                .fragment_offset(2)
                .more_fragments(true)
            / Raw::from_bytes(b"abcdefgh"),
    );
    let mut transform = IpFragment::new(1280);

    let output = transform.fragment_record(record).unwrap();

    let metadata = &output.records()[0].metadata().ip_fragment_metadata()[0];
    assert_eq!(metadata.family(), IpFragmentFamily::Ipv6);
    assert_eq!(metadata.mtu(), 1280);
    assert_eq!(metadata.identification(), 0x1020_3040);
    assert_eq!(metadata.fragment_offset(), 2);
    assert_eq!(metadata.fragment_offset_bytes(), 16);
    assert!(metadata.more_fragments());
    assert_eq!(metadata.fragment_count(), 1);
    assert_eq!(metadata.fragment_index(), 0);
    assert_eq!(metadata.byte_range(), IpFragmentRange::new(16, 24));
    assert_eq!(metadata.original_len(), Some(8));
    assert_eq!(metadata.reason(), Some(&IpFragmentReason::Fragmented));
}
