mod ipv6_tests {
    use super::super::{Ipv6, IPPROTO_IPV6_ROUTE};
    use crate::checksum::ipv6_pseudo_header_checksum;
    use crate::{NetworkLayer, Packet, Raw, Tcp, TCP_FLAG_SYN};
    use core::net::Ipv6Addr;

    fn src() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1)
    }

    fn dst() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 2)
    }

    #[test]
    fn ipv6_tcp_header_autofills_length_next_header_and_checksum() {
        let packet = Ipv6::new()
            .src(src())
            .dst(dst())
            .tc(0xab)
            .fl(0x12345)
            .hlim(32)
            / Tcp::new().sport(1234).dport(80).seq(7).flags(TCP_FLAG_SYN)
            / Raw::from("abc");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[0], 0x6a);
        assert_eq!(&bytes.as_bytes()[4..6], &(23u16).to_be_bytes());
        assert_eq!(bytes.as_bytes()[6], crate::IPPROTO_TCP);
        assert_eq!(bytes.as_bytes()[7], 32);

        let mut tcp = bytes.as_bytes()[40..].to_vec();
        tcp[16] = 0;
        tcp[17] = 0;
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[56], bytes.as_bytes()[57]]),
            ipv6_pseudo_header_checksum(src(), dst(), crate::IPPROTO_TCP, &tcp)
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let ipv6 = decoded.layer::<Ipv6>().unwrap();
        assert_eq!(ipv6.source(), src());
        assert_eq!(ipv6.destination(), dst());
        assert_eq!(ipv6.traffic_class_value(), 0xab);
        assert_eq!(ipv6.flow_label_value(), 0x12345);
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_explicit_base_next_header_is_preserved() {
        let bytes = (Ipv6::new().src(src()).dst(dst()).nh(IPPROTO_IPV6_ROUTE) / Raw::from("abc"))
            .compile()
            .unwrap();

        assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_ROUTE);
    }

    #[test]
    fn ipv6_decode_rejects_short_and_malformed_headers() {
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, [0u8; 39]).is_err());

        let mut bad_version = (Ipv6::new() / Raw::from("abc"))
            .compile()
            .unwrap()
            .into_bytes();
        bad_version[0] = 0x40;
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, bad_version).is_err());

        let mut bad_length = (Ipv6::new() / Raw::from("abc"))
            .compile()
            .unwrap()
            .into_bytes();
        bad_length[4..6].copy_from_slice(&(10u16).to_be_bytes());
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, bad_length).is_err());
    }
}

mod ipv6_extensions {
    use super::super::{Ipv6FragmentHeader, IPPROTO_IPV6_FRAGMENT};
    use crate::checksum::ipv6_pseudo_header_checksum;
    use crate::{Ipv6, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv6Addr;

    fn src() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 10, 0, 0, 0, 0, 1)
    }

    fn dst() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 20, 0, 0, 0, 0, 2)
    }

    #[test]
    fn ipv6_fragment_header_chains_to_udp_and_preserves_checksum_context() {
        let packet = Ipv6::new().src(src()).dst(dst())
            / Ipv6FragmentHeader::new()
                .identification(0x0102_0304)
                .more_fragments(true)
            / Udp::new().sport(1234).dport(5678)
            / Raw::from("payload");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_FRAGMENT);
        assert_eq!(bytes.as_bytes()[40], crate::IPPROTO_UDP);
        assert_eq!(&bytes.as_bytes()[42..44], &1u16.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[44..48], &0x0102_0304u32.to_be_bytes());

        let mut udp = bytes.as_bytes()[48..].to_vec();
        udp[6] = 0;
        udp[7] = 0;
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[54], bytes.as_bytes()[55]]),
            ipv6_pseudo_header_checksum(src(), dst(), crate::IPPROTO_UDP, &udp)
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let fragment = decoded.layer::<Ipv6FragmentHeader>().unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(fragment.identification_value(), 0x0102_0304);
        assert!(fragment.has_more_fragments());
        assert_eq!(udp.source_port_value(), 1234);
        assert_eq!(raw.as_bytes(), b"payload");
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_non_initial_fragments_preserve_remaining_bytes_as_raw() {
        let bytes = (Ipv6::new().src(src()).dst(dst())
            / Ipv6FragmentHeader::new()
                .nh(crate::IPPROTO_UDP)
                .fragment_offset(2)
                .identification(9)
            / Raw::from_bytes([1, 2, 3, 4]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        assert!(decoded.layer::<Udp>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn ipv6_unknown_next_header_preserves_payload_as_raw() {
        let bytes = (Ipv6::new().src(src()).dst(dst()).nh(253) / Raw::from_bytes([9, 8, 7]))
            .compile()
            .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();

        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[9, 8, 7]);
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_extension_decode_rejects_short_fragment_headers() {
        let bytes = (Ipv6::new().src(src()).dst(dst()).nh(IPPROTO_IPV6_FRAGMENT)
            / Raw::from_bytes([0u8; 7]))
        .compile()
        .unwrap();

        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).is_err());
    }
}

mod ipv6_routing_header {
    use super::super::{
        Ipv6MobileRoutingHeader, Ipv6RoutingHeader, Ipv6SegmentRoutingHeader, IPPROTO_IPV6_ROUTE,
        IPV6_ROUTING_TYPE_SEGMENT,
    };
    use crate::{Ipv6, NetworkLayer, Packet, Raw, Tcp};
    use core::net::Ipv6Addr;

    fn src() -> Ipv6Addr {
        "2001:db8:dead:beef:cafe::".parse().unwrap()
    }

    fn dst() -> Ipv6Addr {
        "2001:db8:1234::1".parse().unwrap()
    }

    #[test]
    fn ipv6_segment_routing_header_matches_rfc8754_shape() {
        let sr_header = Ipv6SegmentRoutingHeader::new()
            .push_ipv6_segment("2001:db8:1234::2")
            .unwrap()
            .push_ipv6_segment("2001:db8:1234::3")
            .unwrap()
            .push_ipv6_segment("2001:db8:1234::4")
            .unwrap()
            .push_ipv6_segment("2001:db8:1234::5")
            .unwrap()
            .last_entry(3)
            .flags(0x40)
            .tag(0x1234)
            .raw_trailing_data([0x05, 0x02, 0xaa, 0xbb]);
        let packet = Ipv6::new().src(src()).dst(dst())
            / sr_header
            / Tcp::new().sport(1234).dport(80)
            / Raw::from("Hello World!");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_ROUTE);
        assert_eq!(bytes.as_bytes()[40], crate::IPPROTO_TCP);
        assert_eq!(bytes.as_bytes()[41], 9);
        assert_eq!(bytes.as_bytes()[42], IPV6_ROUTING_TYPE_SEGMENT);
        assert_eq!(bytes.as_bytes()[43], 3);
        assert_eq!(bytes.as_bytes()[44], 3);
        assert_eq!(bytes.as_bytes()[45], 0x40);
        assert_eq!(&bytes.as_bytes()[46..48], &[0x12, 0x34]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let sr = decoded.layer::<Ipv6SegmentRoutingHeader>().unwrap();
        assert_eq!(sr.segments().len(), 4);
        assert_eq!(sr.segments_left_value(), 3);
        assert_eq!(sr.last_entry_value(), 3);
        assert_eq!(sr.first_segment_value(), 3);
        assert_eq!(sr.flags_value(), 0x40);
        assert!(sr.p_flag_value());
        assert_eq!(sr.tag_value(), 0x1234);
        assert_eq!(
            sr.raw_trailing_data_bytes(),
            &[0x05, 0x02, 0xaa, 0xbb, 0, 0, 0, 0]
        );
        assert_eq!(decoded.layer::<Tcp>().unwrap().destination_port_value(), 80);
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), b"Hello World!");
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_mobile_routing_header_encodes_home_address_and_decodes_tcp() {
        let packet = Ipv6::new().src(src()).dst(dst())
            / Ipv6MobileRoutingHeader::new()
                .home_address_str("2001:db8::1")
                .unwrap()
            / Tcp::new().sport(1111).dport(2222)
            / Raw::from("mobile");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_ROUTE);
        assert_eq!(bytes.as_bytes()[40], crate::IPPROTO_TCP);
        assert_eq!(bytes.as_bytes()[41], 2);
        assert_eq!(bytes.as_bytes()[42], 2);
        assert_eq!(bytes.as_bytes()[43], 1);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let mobile = decoded.layer::<Ipv6MobileRoutingHeader>().unwrap();
        assert_eq!(
            mobile.home_address_value(),
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(decoded.layer::<Tcp>().unwrap().source_port_value(), 1111);
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_generic_routing_header_preserves_unknown_type_data() {
        let data = [0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5];
        let packet = Ipv6::new().src(src()).dst(dst())
            / Ipv6RoutingHeader::new()
                .nh(crate::IPPROTO_IPV6_EXPERIMENTAL_1)
                .routing_type(253)
                .segments_left(0)
                .append_type_data(data)
            / Raw::from("tail");
        let bytes = packet.compile().unwrap();
        assert_eq!(bytes.as_bytes()[40], crate::IPPROTO_IPV6_EXPERIMENTAL_1);
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let routing = decoded.layer::<Ipv6RoutingHeader>().unwrap();

        assert_eq!(routing.routing_type_value(), 253);
        assert_eq!(&routing.type_data_bytes()[..data.len()], &data);
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), b"tail");
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_routing_header_builder_rejects_malformed_segment_fields() {
        let bad_empty_segment_header = Packet::new().push(Ipv6SegmentRoutingHeader::new());
        assert!(bad_empty_segment_header.compile().is_err());

        let bad_policy_flag = Ipv6SegmentRoutingHeader::new().policy_flag(4, 1);
        assert!(bad_policy_flag.is_err());
    }
}
