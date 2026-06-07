mod ipv4 {
    use std::net::Ipv4Addr;

    use super::super::{
        IpDefrag, IpDefragOverlapStatus, IpFragment, IpFragmentFamily, IpFragmentRange,
        IpFragmentReason,
    };
    use crate::wire::record::{PacketOrigin, PacketRecord};
    use crate::{Ethernet, Ipv4, Ipv4ChecksumStatus, MacAddr, Packet, Raw, ETHERTYPE_IPV4};

    const MTU: usize = 44;
    const IDENTIFICATION: u16 = 0x3636;
    const PROTOCOL: u8 = 253;

    fn source() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 36)
    }

    fn destination() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 36)
    }

    fn source_mac() -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x36, 0x01])
    }

    fn destination_mac() -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x36, 0x02])
    }

    fn oversized_ipv4_packet(payload: &[u8]) -> Packet {
        Ipv4::with_addresses(source(), destination())
            .protocol(PROTOCOL)
            .identification(IDENTIFICATION)
            .ttl(36)
            .ds_field(0xb8)
            / Raw::from_bytes(payload)
    }

    fn raw_l3_record(payload: &[u8]) -> PacketRecord {
        PacketRecord::new(oversized_ipv4_packet(payload)).with_interface("roundtrip-raw")
    }

    fn ethernet_record(payload: &[u8]) -> PacketRecord {
        PacketRecord::new(
            Ethernet::new()
                .src(source_mac())
                .dst(destination_mac())
                .ethertype(ETHERTYPE_IPV4)
                / oversized_ipv4_packet(payload),
        )
        .with_interface("roundtrip-ethernet")
    }

    fn fragment_and_reorder(record: PacketRecord) -> Vec<PacketRecord> {
        let mut fragment = IpFragment::new(MTU);
        let output = fragment.fragment_record(record).unwrap();
        assert_eq!(fragment.input_count(), 1);
        assert_eq!(fragment.emitted_count(), 3);
        assert_eq!(output.len(), 3);

        let records = output.records();
        let reordered = vec![records[2].clone(), records[0].clone(), records[1].clone()];
        assert_eq!(
            reordered
                .iter()
                .map(|record| record.metadata().ip_fragment_metadata()[0].fragment_index())
                .collect::<Vec<_>>(),
            [2, 0, 1],
            "reorder fragments before feeding IpFragment output into IpDefrag"
        );
        reordered
    }

    fn defrag_reordered(fragments: Vec<PacketRecord>) -> PacketRecord {
        let mut defrag = IpDefrag::new();
        let mut emitted = Vec::new();

        for fragment in fragments {
            emitted.extend(
                defrag
                    .defrag_record(fragment)
                    .unwrap()
                    .records()
                    .iter()
                    .cloned(),
            );
        }

        assert_eq!(defrag.input_count(), 3);
        assert_eq!(defrag.emitted_count(), 1);
        assert_eq!(emitted.len(), 1);
        emitted.pop().unwrap()
    }

    fn assert_roundtripped_ipv4(record: &PacketRecord, payload: &[u8], interface: &str) {
        let ipv4 = record.packet().layer::<Ipv4>().unwrap();
        let raw = record.packet().layer::<Raw>().unwrap();

        assert_eq!(ipv4.source(), source());
        assert_eq!(ipv4.destination(), destination());
        assert_eq!(ipv4.protocol_value(), PROTOCOL);
        assert_eq!(ipv4.identification_value(), IDENTIFICATION);
        assert_eq!(ipv4.ttl_value(), 36);
        assert_eq!(ipv4.ds_field_value(), 0xb8);
        assert_eq!(ipv4.flags_value(), 0);
        assert_eq!(ipv4.fragment_offset_value(), 0);
        assert!(!ipv4.is_fragmented());
        assert_eq!(ipv4.total_length_value(), Some(75));
        assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);
        assert_eq!(raw.as_bytes(), payload);

        let compiled = record.packet().compile().unwrap();
        let l3_offset = if record.packet().layer::<Ethernet>().is_some() {
            14
        } else {
            0
        };
        assert_eq!(
            u16::from_be_bytes([
                compiled.as_bytes()[l3_offset + 2],
                compiled.as_bytes()[l3_offset + 3]
            ]),
            75
        );
        assert_eq!(
            u16::from_be_bytes([
                compiled.as_bytes()[l3_offset + 6],
                compiled.as_bytes()[l3_offset + 7]
            ]),
            0
        );

        assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
        assert_eq!(record.metadata().interface(), Some(interface));

        let fragment_metadata = record.metadata().ip_fragment_metadata();
        assert_eq!(fragment_metadata.len(), 1);
        let fragment = &fragment_metadata[0];
        assert_eq!(fragment.family(), IpFragmentFamily::Ipv4);
        assert_eq!(fragment.mtu(), MTU);
        assert_eq!(fragment.identification(), u32::from(IDENTIFICATION));
        assert_eq!(fragment.fragment_count(), 3);
        assert_eq!(fragment.fragment_index(), 0);
        assert_eq!(fragment.byte_range(), IpFragmentRange::new(0, 24));
        assert_eq!(fragment.original_len(), Some(payload.len() as u32));
        assert_eq!(fragment.reason(), Some(&IpFragmentReason::Fragmented));

        let defrag_metadata = record.metadata().ip_defrag_metadata();
        assert_eq!(defrag_metadata.len(), 1);
        let defrag = &defrag_metadata[0];
        assert_eq!(defrag.family(), IpFragmentFamily::Ipv4);
        assert_eq!(defrag.identification(), u32::from(IDENTIFICATION));
        assert_eq!(
            defrag.datagram_key(),
            Some("192.0.2.36>198.51.100.36 proto=253 id=0x3636")
        );
        assert_eq!(defrag.fragment_count(), 3);
        assert_eq!(defrag.duplicate_count(), 0);
        assert_eq!(defrag.overlap_status(), IpDefragOverlapStatus::None);
        assert_eq!(
            defrag.byte_ranges(),
            &[
                IpFragmentRange::new(0, 24),
                IpFragmentRange::new(24, 48),
                IpFragmentRange::new(48, 55),
            ]
        );
        assert_eq!(defrag.total_len(), Some(75));

        let traces = record.metadata().transforms();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].name(), "ip-defrag");
        assert_eq!(traces[0].note(), Some("reassembled"));
    }

    #[test]
    fn raw_l3_roundtrip_ipv4_reorders_fragments_through_defrag() {
        let payload = (0u8..55).collect::<Vec<_>>();
        let record = defrag_reordered(fragment_and_reorder(raw_l3_record(&payload)));

        assert!(record.packet().layer::<Ethernet>().is_none());
        assert_roundtripped_ipv4(&record, &payload, "roundtrip-raw");
    }

    #[test]
    fn ethernet_wrapped_roundtrip_ipv4_reorders_fragments_through_defrag() {
        let payload = (0u8..55).collect::<Vec<_>>();
        let record = defrag_reordered(fragment_and_reorder(ethernet_record(&payload)));

        let ethernet = record.packet().layer::<Ethernet>().unwrap();
        assert_eq!(ethernet.source(), Some(source_mac()));
        assert_eq!(ethernet.destination(), Some(destination_mac()));
        assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_IPV4));
        assert_roundtripped_ipv4(&record, &payload, "roundtrip-ethernet");
    }
}
