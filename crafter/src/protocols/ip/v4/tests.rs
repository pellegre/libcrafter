use super::protocol::protocol_summary;
use super::*;

#[cfg(test)]
mod ipv4_protocol {
    use super::{
        protocol_summary, Ipv4, Ipv4Protocol, IPPROTO_AH, IPPROTO_ESP, IPPROTO_EXPERIMENTAL_1,
        IPPROTO_EXPERIMENTAL_2, IPPROTO_GRE, IPPROTO_OSPF, IPPROTO_SCTP,
    };
    use crate::{Layer, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn protocol_summary_labels_source_backed_ip_protocol_values() {
        let cases = [
            (Ipv4Protocol::Gre, IPPROTO_GRE, "gre(47)"),
            (Ipv4Protocol::Esp, IPPROTO_ESP, "esp(50)"),
            (Ipv4Protocol::Ah, IPPROTO_AH, "ah(51)"),
            (Ipv4Protocol::Ospf, IPPROTO_OSPF, "ospf(89)"),
            (Ipv4Protocol::Sctp, IPPROTO_SCTP, "sctp(132)"),
            (
                Ipv4Protocol::Experimental1,
                IPPROTO_EXPERIMENTAL_1,
                "experimental(253)",
            ),
            (
                Ipv4Protocol::Experimental2,
                IPPROTO_EXPERIMENTAL_2,
                "experimental(254)",
            ),
        ];

        for (protocol, value, label) in cases {
            assert_eq!(u8::from(protocol), value);
            assert_eq!(protocol_summary(value), label);
        }
    }

    #[test]
    fn protocol_summary_uses_numeric_fallback_for_unknown_values() {
        assert_eq!(protocol_summary(252), "252");
    }

    #[test]
    fn protocol_summary_labels_appear_in_summary_and_inspection_fields() {
        let cases = [
            (Ipv4Protocol::Gre, "gre(47)"),
            (Ipv4Protocol::Esp, "esp(50)"),
            (Ipv4Protocol::Ah, "ah(51)"),
            (Ipv4Protocol::Ospf, "ospf(89)"),
            (Ipv4Protocol::Sctp, "sctp(132)"),
            (Ipv4Protocol::Experimental1, "experimental(253)"),
            (Ipv4Protocol::Experimental2, "experimental(254)"),
        ];

        for (protocol, label) in cases {
            let ipv4 = Ipv4::new().src(src()).dst(dst()).ipv4_protocol(protocol);

            assert_eq!(
                ipv4.summary(),
                format!("Ipv4(src={}, dst={}, proto={label})", src(), dst())
            );
            assert_eq!(
                ipv4.inspection_fields()
                    .iter()
                    .find(|(name, _)| *name == "protocol")
                    .map(|(_, value)| value.as_str()),
                Some(label)
            );
        }

        let ipv4 = Ipv4::new().src(src()).dst(dst()).protocol(252);

        assert_eq!(
            ipv4.summary(),
            format!("Ipv4(src={}, dst={}, proto=252)", src(), dst())
        );
        assert_eq!(
            ipv4.inspection_fields()
                .iter()
                .find(|(name, _)| *name == "protocol")
                .map(|(_, value)| value.as_str()),
            Some("252")
        );
    }

    #[test]
    fn ip_protocol_source_backed_unsupported_values_decode_as_raw_payload() {
        // ESP (protocol 50), AH (protocol 51), and OSPF (protocol 89) are
        // intentionally absent: the built-in registry now decodes them to typed
        // layers (an opaque `Esp` with an 8-octet minimum, an `Ah` with its
        // 12-octet fixed header, an `Ospfv2` with a 24-octet common header that
        // surfaces a structured truncation error on short input), not a `Raw`
        // fallback. Their decode is covered by the ESP/AH and OSPF registry tests.
        let cases = [
            Ipv4Protocol::Gre,
            Ipv4Protocol::Sctp,
            Ipv4Protocol::Experimental1,
            Ipv4Protocol::Experimental2,
        ];

        for protocol in cases {
            let payload = [u8::from(protocol), 0xde, 0xad, 0xbe, 0xef];
            let bytes = (Ipv4::new().src(src()).dst(dst()).ipv4_protocol(protocol)
                / Raw::from_bytes(payload))
            .compile()
            .unwrap();
            assert_eq!(bytes.as_bytes()[9], u8::from(protocol));

            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
            let ipv4 = decoded.layer::<Ipv4>().unwrap();
            let raw = decoded.layer::<Raw>().unwrap();

            assert_eq!(ipv4.protocol_value(), u8::from(protocol));
            assert_eq!(raw.as_bytes(), payload);
        }
    }

    #[test]
    fn ipv4_autoderives_ospf_protocol_for_ospfv2_layer() {
        use crate::protocols::ospf::constants::OSPF_TYPE_LINK_STATE_ACK;
        use crate::protocols::ospf::Ospfv2;

        // No explicit IPv4 protocol is set: the following `Ospfv2` layer must
        // auto-derive protocol 89 (RFC 2328 §A.1 runs OSPF directly over IP). A
        // non-Hello packet type with a raw body keeps this auto-derive case
        // independent of typed-body decoding (type 1 dispatches to a Hello body).
        let body = [0xde, 0xad, 0xbe, 0xef];
        let packet = Ipv4::new().src(src()).dst(dst())
            / Ospfv2::new()
                .packet_type(OSPF_TYPE_LINK_STATE_ACK)
                .raw_body(body);

        let bytes = packet.compile().unwrap();

        // The IPv4 protocol octet (offset 9) is 89.
        assert_eq!(bytes.as_bytes()[9], IPPROTO_OSPF);

        // Decoding the IPv4 header recovers the auto-derived protocol number and
        // the total length covers the 20-octet IPv4 header plus the OSPF packet
        // (24-octet common header + 4-octet body).
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();
        assert_eq!(ipv4.protocol_value(), IPPROTO_OSPF);

        let expected_total = 20 + 24 + body.len();
        assert_eq!(&bytes.as_bytes()[2..4], &(expected_total as u16).to_be_bytes());
        assert_eq!(ipv4.total_length_value(), Some(expected_total as u16));
    }
}

#[cfg(test)]
mod ipv4_ds_field {
    use super::{Dscp, Ecn, Ipv4};
    use crate::{NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    #[test]
    fn ipv4_ds_field_builder_sets_full_byte_and_exposes_subfields() {
        let ip = Ipv4::new().ds_field(0xab);

        assert_eq!(ip.ds_field_value(), 0xab);
        assert_eq!(ip.tos_value(), 0xab);
        assert_eq!(ip.dscp_value().value(), 42);
        assert_eq!(ip.ecn_value(), Ecn::Ce);
    }

    #[test]
    fn ipv4_ds_field_alias_composes_with_dscp_and_ecn_builders() {
        let ip = Ipv4::new()
            .ds_field(0xab)
            .dscp(Dscp::new(10).unwrap())
            .ecn(Ecn::Ect0);

        assert_eq!(ip.ds_field_value(), 0x2a);
        assert_eq!(ip.tos_value(), 0x2a);
        assert_eq!(ip.dscp_value().value(), 10);
        assert_eq!(ip.ecn_value(), Ecn::Ect0);
    }

    #[test]
    fn ipv4_ds_field_round_trips_through_compile_and_decode() {
        let packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            .protocol(253)
            .ds_field(0xb9)
            / Raw::from_bytes([1, 2, 3, 4]);

        let bytes = packet.compile().unwrap();
        assert_eq!(bytes.as_bytes()[1], 0xb9);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();

        assert_eq!(ipv4.ds_field_value(), 0xb9);
        assert_eq!(ipv4.tos_value(), 0xb9);
        assert_eq!(ipv4.dscp_value().value(), 46);
        assert_eq!(ipv4.ecn_value(), Ecn::Ect1);
    }
}

#[cfg(test)]
mod ipv4_dscp_ecn {
    use super::{Dscp, Ecn, Ipv4};
    use crate::{NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn dscp_constructor_accepts_six_bit_values_and_rejects_overflow() {
        assert_eq!(Dscp::new(0).unwrap().value(), 0);
        assert_eq!(Dscp::new(63).unwrap().value(), 63);

        let err = Dscp::new(64).unwrap_err();
        assert!(err.to_string().contains("ipv4.dscp"));
    }

    #[test]
    fn dscp_test_covers_ecn_constructor_values_and_overflow() {
        assert_eq!(Ecn::new(0).unwrap(), Ecn::NotEct);
        assert_eq!(Ecn::new(1).unwrap(), Ecn::Ect1);
        assert_eq!(Ecn::new(2).unwrap(), Ecn::Ect0);
        assert_eq!(Ecn::new(3).unwrap(), Ecn::Ce);

        let err = Ecn::new(4).unwrap_err();
        assert!(err.to_string().contains("ipv4.ecn"));
    }

    #[test]
    fn dscp_and_ecn_builders_compose_without_changing_tos_alias() {
        let ip = Ipv4::new().tos(0xa5);
        assert_eq!(ip.tos_value(), 0xa5);
        assert_eq!(ip.dscp_value().value(), 0x29);
        assert_eq!(ip.ecn_value(), Ecn::Ect1);

        let ip = ip.dscp(Dscp::new(46).unwrap());
        assert_eq!(ip.tos_value(), 0xb9);
        assert_eq!(ip.dscp_value().value(), 46);
        assert_eq!(ip.ecn_value(), Ecn::Ect1);

        let ip = ip.ecn(Ecn::Ce);
        assert_eq!(ip.tos_value(), 0xbb);
        assert_eq!(ip.dscp_value().value(), 46);
        assert_eq!(ip.ecn_value(), Ecn::Ce);
    }

    #[test]
    fn dscp_and_ecn_round_trip_through_compile_and_decode() {
        let packet = Ipv4::new()
            .src(src())
            .dst(dst())
            .protocol(253)
            .dscp(Dscp::new(46).unwrap())
            .ecn(Ecn::Ce)
            / Raw::from_bytes([1, 2, 3, 4]);

        let bytes = packet.compile().unwrap();
        assert_eq!(bytes.as_bytes()[1], 0xbb);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();

        assert_eq!(ipv4.tos_value(), 0xbb);
        assert_eq!(ipv4.dscp_value().value(), 46);
        assert_eq!(ipv4.ecn_value(), Ecn::Ce);
    }
}

#[cfg(test)]
mod ipv4_tests {
    use super::{
        Ipv4, Ipv4Protocol, IPPROTO_ICMP, IPPROTO_ICMPV6, IPV4_FLAG_DONT_FRAGMENT,
        IPV4_FLAG_MORE_FRAGMENTS,
    };
    use crate::{Icmpv4, LinkType, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    const IPV4_ICMP_FIXTURE: &[u8] = fixture_bytes!("bytes/ipv4-icmp-echo-request.bin");

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn ipv4_header_matches_golden_bytes_with_raw_icmp_payload() {
        let packet = Ipv4::new()
            .src(src())
            .dst(dst())
            .id(0x1234)
            .dont_fragment(true)
            .ipv4_protocol(Ipv4Protocol::Icmpv4)
            / Raw::from_bytes(&IPV4_ICMP_FIXTURE[20..]);

        assert_eq!(packet.compile().unwrap().as_bytes(), IPV4_ICMP_FIXTURE);
    }

    #[test]
    fn ipv4_decode_exposes_header_fields_and_preserves_payload() {
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, IPV4_ICMP_FIXTURE).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();
        let icmp = decoded.layer::<Icmpv4>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(ipv4.version_value(), 4);
        assert_eq!(ipv4.ihl_value(), 5);
        assert_eq!(ipv4.total_length_value(), Some(43));
        assert_eq!(ipv4.identification_value(), 0x1234);
        assert_eq!(ipv4.flags_value(), IPV4_FLAG_DONT_FRAGMENT);
        assert_eq!(ipv4.fragment_offset_value(), 0);
        assert_eq!(ipv4.ttl_value(), 64);
        assert_eq!(ipv4.protocol_value(), IPPROTO_ICMP);
        assert_eq!(ipv4.checksum_value(), Some(0x3c4c));
        assert_eq!(ipv4.source(), src());
        assert_eq!(ipv4.destination(), dst());
        assert_eq!(icmp.identifier_value(), Some(0x4242));
        assert_eq!(icmp.sequence_number_value(), Some(1));
        assert_eq!(raw.as_bytes(), b"libcrafter-icmp");
        assert_eq!(decoded.compile().unwrap().as_bytes(), IPV4_ICMP_FIXTURE);
    }

    #[test]
    fn ipv4_decode_from_ethernet_stack_autofills_link_ethertype() {
        let frame = crate::Ethernet::new()
            .src("02:00:5e:00:53:01".parse::<crate::MacAddr>().unwrap())
            / (Ipv4::new()
                .src(src())
                .dst(dst())
                .ipv4_protocol(Ipv4Protocol::Icmpv4)
                / Raw::from_bytes(&IPV4_ICMP_FIXTURE[20..]));

        let bytes = frame.compile().unwrap();
        assert_eq!(
            &bytes.as_bytes()[12..14],
            &crate::ETHERTYPE_IPV4.to_be_bytes()
        );

        let decoded = Packet::decode_from_link(LinkType::Ethernet, bytes.as_bytes()).unwrap();
        assert!(decoded.layer::<crate::Ethernet>().is_some());
        assert!(decoded.layer::<Ipv4>().is_some());
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv4_options_are_padded_and_update_ihl_and_total_length() {
        let packet = Ipv4::new()
            .src(src())
            .dst(dst())
            .ttl(60)
            .id(0x1239)
            .ipv4_protocol(Ipv4Protocol::Icmpv4)
            .option([0x01])
            .option([0x07, 0x07, 0x04, 0xc0, 0x00, 0x02, 0x01])
            / Raw::from([0u8; 8]);
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[0], 0x47);
        assert_eq!(&bytes.as_bytes()[2..4], &(36u16).to_be_bytes());
        assert_eq!(
            &bytes.as_bytes()[20..28],
            &[0x01, 0x07, 0x07, 0x04, 0xc0, 0x00, 0x02, 0x01]
        );
    }

    #[test]
    fn ipv4_decode_rejects_short_and_malformed_headers() {
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, [0u8; 19]).is_err());

        let mut bad_version = IPV4_ICMP_FIXTURE.to_vec();
        bad_version[0] = 0x65;
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, bad_version).is_err());

        let mut bad_ihl = IPV4_ICMP_FIXTURE.to_vec();
        bad_ihl[0] = 0x44;
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, bad_ihl).is_err());

        let mut bad_total = IPV4_ICMP_FIXTURE.to_vec();
        bad_total[2..4].copy_from_slice(&(19u16).to_be_bytes());
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, bad_total).is_err());
    }

    #[test]
    fn ipv4_builder_validates_flags_fragments_and_lengths() {
        let bad_flags = Packet::new().push(Ipv4::new().flags(8));
        assert!(bad_flags
            .compile()
            .unwrap_err()
            .to_string()
            .contains("flags"));

        let bad_fragment = Packet::new().push(Ipv4::new().frag(0x2000));
        assert!(bad_fragment
            .compile()
            .unwrap_err()
            .to_string()
            .contains("fragment"));

        let bad_total = Packet::new().push(Ipv4::new().len(19));
        assert!(bad_total
            .compile()
            .unwrap_err()
            .to_string()
            .contains("total length"));

        let flags = Ipv4::new()
            .dont_fragment(true)
            .more_fragments(true)
            .flags_value();
        assert_eq!(flags, IPV4_FLAG_DONT_FRAGMENT | IPV4_FLAG_MORE_FRAGMENTS);
    }

    #[test]
    fn ipv4_protocol_selector_sets_wire_value_and_raw_protocol_override_wins() {
        let typed = (Ipv4::new().ipv4_protocol(Ipv4Protocol::Icmpv6) / Raw::from("typed"))
            .compile()
            .unwrap();
        let raw = (Ipv4::new().ipv4_protocol(Ipv4Protocol::Tcp).protocol(253) / Raw::from("raw"))
            .compile()
            .unwrap();

        assert_eq!(u8::from(Ipv4Protocol::Icmpv4), IPPROTO_ICMP);
        assert_eq!(typed.as_bytes()[9], IPPROTO_ICMPV6);
        assert_eq!(raw.as_bytes()[9], 253);
    }
}

#[cfg(test)]
mod ipv4_fragment_info {
    use super::{
        Ipv4, Ipv4FragmentInfo, Ipv4Protocol, IPV4_FLAG_DONT_FRAGMENT, IPV4_FLAG_MORE_FRAGMENTS,
        IPV4_FLAG_RESERVED,
    };
    use crate::{NetworkLayer, Packet, Raw, Tcp, Udp};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn ipv4_fragment_info_defaults_are_atomic() {
        let ip = Ipv4::new().src(src()).dst(dst());
        let info: Ipv4FragmentInfo = ip.fragment_info();

        assert_eq!(info.identification(), 1);
        assert_eq!(info.flags(), 0);
        assert_eq!(info.fragment_offset(), 0);
        assert!(!info.is_reserved_flag_set());
        assert!(!info.is_dont_fragment());
        assert!(!info.has_more_fragments());
        assert!(!info.is_fragmented());
        assert!(!ip.is_reserved_flag_set());
        assert!(!ip.is_fragmented());
    }

    #[test]
    fn ipv4_reserved_flag_builder_sets_only_reserved_flag() {
        let ip = Ipv4::new()
            .dont_fragment(true)
            .more_fragments(true)
            .reserved_flag(true);

        assert_eq!(
            ip.flags_value(),
            IPV4_FLAG_RESERVED | IPV4_FLAG_DONT_FRAGMENT | IPV4_FLAG_MORE_FRAGMENTS
        );
        assert!(ip.is_reserved_flag_set());
        assert!(ip.is_dont_fragment());
        assert!(ip.has_more_fragments());
    }

    #[test]
    fn ipv4_reserved_flag_builder_clears_only_reserved_flag() {
        let ip = Ipv4::new()
            .flags(IPV4_FLAG_RESERVED | IPV4_FLAG_DONT_FRAGMENT | IPV4_FLAG_MORE_FRAGMENTS)
            .reserved_flag(false);

        assert_eq!(
            ip.flags_value(),
            IPV4_FLAG_DONT_FRAGMENT | IPV4_FLAG_MORE_FRAGMENTS
        );
        assert!(!ip.is_reserved_flag_set());
        assert!(ip.is_dont_fragment());
        assert!(ip.has_more_fragments());
    }

    #[test]
    fn ipv4_fragment_info_exposes_flags_offset_and_fragmented_predicate() {
        let ip = Ipv4::new()
            .id(0x4567)
            .flags(IPV4_FLAG_RESERVED)
            .dont_fragment(true)
            .more_fragments(true)
            .frag(0x0123);
        let info = ip.fragment_info();

        assert_eq!(info.identification(), 0x4567);
        assert_eq!(
            info.flags(),
            IPV4_FLAG_RESERVED | IPV4_FLAG_DONT_FRAGMENT | IPV4_FLAG_MORE_FRAGMENTS
        );
        assert_eq!(info.fragment_offset(), 0x0123);
        assert!(info.is_reserved_flag_set());
        assert!(info.is_dont_fragment());
        assert!(info.has_more_fragments());
        assert!(info.is_fragmented());
        assert!(ip.is_reserved_flag_set());
        assert!(ip.is_dont_fragment());
        assert!(ip.has_more_fragments());
        assert!(ip.is_fragmented());

        assert!(!Ipv4::new().dont_fragment(true).is_fragmented());
        assert!(Ipv4::new().more_fragments(true).is_fragmented());
        assert!(Ipv4::new().frag(1).is_fragmented());
    }

    #[test]
    fn ipv4_fragment_info_round_trips_through_compile_and_decode() {
        let packet = Ipv4::new()
            .src(src())
            .dst(dst())
            .id(0x4567)
            .flags(IPV4_FLAG_RESERVED | IPV4_FLAG_DONT_FRAGMENT | IPV4_FLAG_MORE_FRAGMENTS)
            .frag(0x0123)
            .ipv4_protocol(Ipv4Protocol::Experimental1)
            / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef]);
        let bytes = packet.compile().unwrap();

        assert_eq!(&bytes.as_bytes()[4..6], &0x4567u16.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[6..8], &0xe123u16.to_be_bytes());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();
        let info = ipv4.fragment_info();

        assert_eq!(info.identification(), 0x4567);
        assert_eq!(
            info.flags(),
            IPV4_FLAG_RESERVED | IPV4_FLAG_DONT_FRAGMENT | IPV4_FLAG_MORE_FRAGMENTS
        );
        assert_eq!(info.fragment_offset(), 0x0123);
        assert!(info.is_reserved_flag_set());
        assert!(info.is_dont_fragment());
        assert!(info.has_more_fragments());
        assert!(info.is_fragmented());
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn noninitial_fragment_udp_payload_decodes_as_raw_without_udp_layer() {
        let payload = [0x12, 0x34, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];
        let bytes = (Ipv4::new()
            .src(src())
            .dst(dst())
            .id(0x4568)
            .frag(1)
            .ipv4_protocol(Ipv4Protocol::Udp)
            / Raw::from_bytes(payload))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();
        let raw_layers = decoded.layers::<Raw>().collect::<Vec<_>>();

        assert_eq!(ipv4.fragment_offset_value(), 1);
        assert!(decoded.layer::<Udp>().is_none());
        assert_eq!(raw_layers.len(), 1);
        assert_eq!(raw_layers[0].as_bytes(), payload);
    }

    #[test]
    fn noninitial_fragment_tcp_payload_decodes_as_raw_without_tcp_layer() {
        let payload = [
            0x12, 0x34, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let bytes = (Ipv4::new()
            .src(src())
            .dst(dst())
            .id(0x4569)
            .frag(1)
            .ipv4_protocol(Ipv4Protocol::Tcp)
            / Raw::from_bytes(payload))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();
        let raw_layers = decoded.layers::<Raw>().collect::<Vec<_>>();

        assert_eq!(ipv4.fragment_offset_value(), 1);
        assert!(decoded.layer::<Tcp>().is_none());
        assert_eq!(raw_layers.len(), 1);
        assert_eq!(raw_layers[0].as_bytes(), payload);
    }

    #[test]
    fn initial_fragment_decode_types_complete_udp_header() {
        let bytes = (Ipv4::new()
            .src(src())
            .dst(dst())
            .id(0x4570)
            .more_fragments(true)
            / Udp::new().sport(49152).dport(49153))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();
        let udp = decoded.layer::<Udp>().unwrap();

        assert_eq!(ipv4.fragment_offset_value(), 0);
        assert!(ipv4.has_more_fragments());
        assert!(ipv4.is_fragmented());
        assert_eq!(udp.source_port_value(), 49152);
        assert_eq!(udp.destination_port_value(), 49153);
        assert!(decoded.layer::<Raw>().is_none());
    }

    #[test]
    fn initial_fragment_decode_preserves_truncated_udp_header_as_raw() {
        let payload = [0x12, 0x34, 0x00, 0x35, 0x00, 0x08, 0x00];
        let bytes = (Ipv4::new()
            .src(src())
            .dst(dst())
            .id(0x4571)
            .more_fragments(true)
            .ipv4_protocol(Ipv4Protocol::Udp)
            / Raw::from_bytes(payload))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();
        let raw_layers = decoded.layers::<Raw>().collect::<Vec<_>>();

        assert_eq!(ipv4.fragment_offset_value(), 0);
        assert!(ipv4.has_more_fragments());
        assert!(decoded.layer::<Udp>().is_none());
        assert_eq!(raw_layers.len(), 1);
        assert_eq!(raw_layers[0].as_bytes(), payload);
    }

    #[test]
    fn initial_fragment_decode_preserves_unknown_protocol_payload_as_raw() {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let bytes = (Ipv4::new()
            .src(src())
            .dst(dst())
            .id(0x4572)
            .more_fragments(true)
            .protocol(252)
            / Raw::from_bytes(payload))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();
        let raw_layers = decoded.layers::<Raw>().collect::<Vec<_>>();

        assert_eq!(ipv4.fragment_offset_value(), 0);
        assert!(ipv4.has_more_fragments());
        assert_eq!(ipv4.protocol_value(), 252);
        assert!(decoded.layer::<Udp>().is_none());
        assert_eq!(raw_layers.len(), 1);
        assert_eq!(raw_layers[0].as_bytes(), payload);
    }
}

#[cfg(test)]
mod ipv4_header_length {
    use super::{Ipv4, Ipv4Protocol, IPV4_OPTION_NOP};
    use crate::{CrafterError, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn ipv4_header_length_defaults_to_minimum_without_options() {
        let ip = Ipv4::new()
            .src(src())
            .dst(dst())
            .ipv4_protocol(Ipv4Protocol::Experimental1);

        assert_eq!(ip.ihl_value(), 5);
        assert_eq!(ip.header_len(), 20);

        let bytes = (ip / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef]))
            .compile()
            .unwrap();

        assert_eq!(bytes.as_bytes()[0], 0x45);
        assert_eq!(&bytes.as_bytes()[2..4], &(24u16).to_be_bytes());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let decoded_ip = decoded.layer::<Ipv4>().unwrap();

        assert_eq!(decoded_ip.ihl_value(), 5);
        assert_eq!(decoded_ip.header_len(), 20);
        assert!(decoded_ip.option_bytes().is_empty());
    }

    #[test]
    fn ipv4_header_length_pads_options_to_word_boundary() {
        let ip = Ipv4::new()
            .src(src())
            .dst(dst())
            .ipv4_protocol(Ipv4Protocol::Experimental1)
            .option([IPV4_OPTION_NOP]);

        assert_eq!(ip.ihl_value(), 6);
        assert_eq!(ip.header_len(), 24);

        let bytes = (ip / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef]))
            .compile()
            .unwrap();

        assert_eq!(bytes.as_bytes()[0], 0x46);
        assert_eq!(&bytes.as_bytes()[2..4], &(28u16).to_be_bytes());
        assert_eq!(&bytes.as_bytes()[20..24], &[IPV4_OPTION_NOP, 0, 0, 0]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let decoded_ip = decoded.layer::<Ipv4>().unwrap();

        assert_eq!(decoded_ip.ihl_value(), 6);
        assert_eq!(decoded_ip.header_len(), 24);
        assert_eq!(decoded_ip.option_bytes(), &[IPV4_OPTION_NOP, 0, 0, 0]);
    }

    #[test]
    fn ipv4_header_length_preserves_explicit_ihl() {
        let ip = Ipv4::new()
            .src(src())
            .dst(dst())
            .ipv4_protocol(Ipv4Protocol::Experimental1)
            .ihl(7);

        assert_eq!(ip.ihl_value(), 7);
        assert_eq!(ip.header_len(), 28);

        let bytes = (ip / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef]))
            .compile()
            .unwrap();

        assert_eq!(bytes.as_bytes()[0], 0x47);
        assert_eq!(&bytes.as_bytes()[2..4], &(32u16).to_be_bytes());
        assert_eq!(&bytes.as_bytes()[20..28], &[0; 8]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let decoded_ip = decoded.layer::<Ipv4>().unwrap();

        assert_eq!(decoded_ip.ihl_value(), 7);
        assert_eq!(decoded_ip.header_len(), 28);
        assert_eq!(decoded_ip.option_bytes(), &[0; 8]);
    }

    #[test]
    fn ipv4_header_length_rejects_too_small_ihl_errors() {
        let error = Packet::new()
            .push(Ipv4::new().ihl(4))
            .compile()
            .unwrap_err();
        assert_eq!(
            error,
            CrafterError::InvalidFieldValue {
                field: "ipv4.ihl",
                reason: "internet header length must be at least 5 words",
            }
        );

        let error = Packet::new()
            .push(Ipv4::new().ihl(5).option([IPV4_OPTION_NOP]))
            .compile()
            .unwrap_err();
        assert_eq!(
            error,
            CrafterError::InvalidFieldValue {
                field: "ipv4.ihl",
                reason: "internet header length is too small for option bytes",
            }
        );

        let mut bytes = [0u8; 20];
        bytes[0] = 0x44;
        bytes[2..4].copy_from_slice(&(20u16).to_be_bytes());

        let error = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap_err();
        assert_eq!(
            error,
            CrafterError::InvalidFieldValue {
                field: "ipv4.ihl",
                reason: "internet header length must be at least 5 words",
            }
        );
    }
}

#[cfg(test)]
mod ipv4_option_padding {
    use super::{Ipv4, Ipv4ChecksumStatus, Ipv4Protocol, IPV4_OPTION_NOP};
    use crate::{checksum::verify_internet_checksum, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    const PAYLOAD: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    fn assert_ipv4_option_padding(options: &[u8], padded_options: &[u8]) {
        let bytes = (Ipv4::new()
            .src(src())
            .dst(dst())
            .ipv4_protocol(Ipv4Protocol::Experimental1)
            .option(options)
            / Raw::from_bytes(PAYLOAD))
        .compile()
        .unwrap();
        let wire = bytes.as_bytes();
        let header_len = 20 + padded_options.len();
        let total_len = header_len + PAYLOAD.len();

        assert_eq!(wire[0], 0x40 | (header_len / 4) as u8);
        assert_eq!(&wire[2..4], &(total_len as u16).to_be_bytes());
        assert_eq!(&wire[20..header_len], padded_options);
        assert_eq!(&wire[header_len..total_len], &PAYLOAD);
        assert!(verify_internet_checksum(&wire[..header_len]));

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, wire).unwrap();
        let decoded_ip = decoded.layer::<Ipv4>().unwrap();

        assert_eq!(decoded_ip.ihl_value(), (header_len / 4) as u8);
        assert_eq!(decoded_ip.header_len(), header_len);
        assert_eq!(decoded_ip.total_length_value(), Some(total_len as u16));
        assert_eq!(decoded_ip.checksum_status(), Ipv4ChecksumStatus::Valid);
        assert_eq!(decoded_ip.option_bytes(), padded_options);
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &PAYLOAD);
        assert_eq!(decoded.compile().unwrap().as_bytes(), wire);
    }

    #[test]
    fn ipv4_option_padding_one_byte_option_area() {
        assert_ipv4_option_padding(&[IPV4_OPTION_NOP], &[IPV4_OPTION_NOP, 0, 0, 0]);
    }

    #[test]
    fn ipv4_option_padding_two_byte_option_area() {
        assert_ipv4_option_padding(
            &[IPV4_OPTION_NOP, IPV4_OPTION_NOP],
            &[IPV4_OPTION_NOP, IPV4_OPTION_NOP, 0, 0],
        );
    }

    #[test]
    fn ipv4_option_padding_three_byte_option_area() {
        assert_ipv4_option_padding(
            &[IPV4_OPTION_NOP, IPV4_OPTION_NOP, IPV4_OPTION_NOP],
            &[IPV4_OPTION_NOP, IPV4_OPTION_NOP, IPV4_OPTION_NOP, 0],
        );
    }

    #[test]
    fn ipv4_option_padding_already_aligned_option_area() {
        assert_ipv4_option_padding(
            &[
                IPV4_OPTION_NOP,
                IPV4_OPTION_NOP,
                IPV4_OPTION_NOP,
                IPV4_OPTION_NOP,
            ],
            &[
                IPV4_OPTION_NOP,
                IPV4_OPTION_NOP,
                IPV4_OPTION_NOP,
                IPV4_OPTION_NOP,
            ],
        );
    }
}

#[cfg(test)]
mod ipv4_eol_padding {
    use super::{Ipv4, Ipv4Option, Ipv4Protocol, IPV4_OPTION_EOL, IPV4_OPTION_NOP};
    use crate::{NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    const EOL_PADDED_OPTIONS: [u8; 4] = [IPV4_OPTION_NOP, IPV4_OPTION_EOL, 0, 0];
    const PAYLOAD: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn ipv4_eol_padding_option_parser_stops_at_first_eol() -> crate::Result<()> {
        let parsed = Ipv4Option::decode_all(&EOL_PADDED_OPTIONS)?;

        assert_eq!(parsed, vec![Ipv4Option::NoOperation, Ipv4Option::EndOfList]);
        Ok(())
    }

    #[test]
    fn ipv4_eol_padding_decode_preserves_raw_padding_bytes() -> crate::Result<()> {
        let bytes = (Ipv4::new()
            .src(src())
            .dst(dst())
            .ipv4_protocol(Ipv4Protocol::Experimental1)
            .option([IPV4_OPTION_NOP, IPV4_OPTION_EOL])
            / Raw::from_bytes(PAYLOAD))
        .compile()?;

        let wire = bytes.as_bytes();
        assert_eq!(&wire[20..24], &EOL_PADDED_OPTIONS);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, wire)?;
        let decoded_ip = decoded.layer::<Ipv4>().unwrap();

        assert_eq!(decoded_ip.option_bytes(), &EOL_PADDED_OPTIONS);
        assert_eq!(
            decoded_ip.parsed_options()?,
            vec![Ipv4Option::NoOperation, Ipv4Option::EndOfList]
        );
        assert_eq!(decoded.compile()?.as_bytes(), wire);
        Ok(())
    }
}

#[cfg(test)]
mod ipv4_option_kind {
    use super::{
        Ipv4OptionKind, IPV4_OPTION_EOL, IPV4_OPTION_EXPERIMENTAL_1, IPV4_OPTION_EXPERIMENTAL_2,
        IPV4_OPTION_EXPERIMENTAL_3, IPV4_OPTION_EXPERIMENTAL_4, IPV4_OPTION_LOOSE_SOURCE_ROUTE,
        IPV4_OPTION_NOP, IPV4_OPTION_RECORD_ROUTE, IPV4_OPTION_ROUTER_ALERT,
        IPV4_OPTION_STRICT_SOURCE_ROUTE, IPV4_OPTION_TIMESTAMP, IPV4_OPTION_TRACEROUTE,
    };

    fn assert_kind(value: u8, copied: bool, class: u8, number: u8) {
        let kind = Ipv4OptionKind::new(value);

        assert_eq!(kind.value(), value, "kind {value:#04x}");
        assert_eq!(kind.copied(), copied, "kind {value:#04x}");
        assert_eq!(kind.class(), class, "kind {value:#04x}");
        assert_eq!(kind.number(), number, "kind {value:#04x}");
        assert_eq!(u8::from(kind), value, "kind {value:#04x}");
        assert_eq!(Ipv4OptionKind::from(value), kind, "kind {value:#04x}");
    }

    #[test]
    fn ipv4_option_kind_classifies_standard_option_values() {
        assert_kind(IPV4_OPTION_EOL, false, 0, 0);
        assert_kind(IPV4_OPTION_NOP, false, 0, 1);
        assert_kind(IPV4_OPTION_RECORD_ROUTE, false, 0, 7);
        assert_kind(IPV4_OPTION_LOOSE_SOURCE_ROUTE, true, 0, 3);
        assert_kind(IPV4_OPTION_STRICT_SOURCE_ROUTE, true, 0, 9);
        assert_kind(IPV4_OPTION_TIMESTAMP, false, 2, 4);
        assert_kind(IPV4_OPTION_ROUTER_ALERT, true, 0, 20);
        assert_kind(IPV4_OPTION_TRACEROUTE, false, 2, 18);
    }

    #[test]
    fn ipv4_option_kind_classifies_experiment_values() {
        assert_kind(IPV4_OPTION_EXPERIMENTAL_1, false, 0, 30);
        assert_kind(IPV4_OPTION_EXPERIMENTAL_2, false, 2, 30);
        assert_kind(IPV4_OPTION_EXPERIMENTAL_3, true, 0, 30);
        assert_kind(IPV4_OPTION_EXPERIMENTAL_4, true, 2, 30);
    }

    #[test]
    fn ipv4_option_kind_accessors_are_const_friendly() {
        const KIND: Ipv4OptionKind = Ipv4OptionKind::new(IPV4_OPTION_ROUTER_ALERT);
        const VALUE: u8 = KIND.value();
        const COPIED: bool = KIND.copied();
        const CLASS: u8 = KIND.class();
        const NUMBER: u8 = KIND.number();

        assert_eq!((VALUE, COPIED, CLASS, NUMBER), (0x94, true, 0, 20));
    }
}

#[cfg(test)]
mod ipv4_experimental_options {
    use super::{
        Ipv4, Ipv4Option, Ipv4OptionKind, IPV4_OPTION_EXPERIMENTAL_1, IPV4_OPTION_EXPERIMENTAL_2,
        IPV4_OPTION_EXPERIMENTAL_3, IPV4_OPTION_EXPERIMENTAL_4, IPV4_OPTION_RECORD_ROUTE,
        IPV4_OPTION_ROUTER_ALERT, IPV4_OPTION_TIMESTAMP,
    };
    use crate::{NetworkLayer, Packet};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn ipv4_experimental_options_classify_rfc4727_values() {
        let cases = [
            (IPV4_OPTION_EXPERIMENTAL_1, false, 0, 30),
            (IPV4_OPTION_EXPERIMENTAL_2, false, 2, 30),
            (IPV4_OPTION_EXPERIMENTAL_3, true, 0, 30),
            (IPV4_OPTION_EXPERIMENTAL_4, true, 2, 30),
        ];

        for (value, copied, class, number) in cases {
            let kind = Ipv4OptionKind::new(value);

            assert_eq!(kind.value(), value, "kind {value:#04x}");
            assert_eq!(kind.copied(), copied, "kind {value:#04x}");
            assert_eq!(kind.class(), class, "kind {value:#04x}");
            assert_eq!(kind.number(), number, "kind {value:#04x}");
            assert!(kind.is_experimental(), "kind {value:#04x}");
            assert_eq!(
                kind.experimental_label(),
                Some("RFC3692-style Experiment"),
                "kind {value:#04x}"
            );
        }
    }

    #[test]
    fn ipv4_experimental_options_leave_standard_values_unclassified() {
        for value in [
            IPV4_OPTION_RECORD_ROUTE,
            IPV4_OPTION_TIMESTAMP,
            IPV4_OPTION_ROUTER_ALERT,
        ] {
            let kind = Ipv4OptionKind::new(value);

            assert!(!kind.is_experimental(), "kind {value:#04x}");
            assert_eq!(kind.experimental_label(), None, "kind {value:#04x}");
        }
    }

    #[test]
    fn ipv4_experimental_options_decode_as_generic_but_classify_kind() -> crate::Result<()> {
        let option = Ipv4Option::generic(IPV4_OPTION_EXPERIMENTAL_2, [0xaa, 0xbb]);
        let encoded = option.encode()?;
        let decoded = Ipv4Option::decode_all(&encoded)?;

        assert_eq!(encoded, [IPV4_OPTION_EXPERIMENTAL_2, 4, 0xaa, 0xbb]);
        assert_eq!(decoded, vec![option]);

        let kind = Ipv4OptionKind::new(decoded[0].kind());
        assert!(kind.is_experimental());
        assert_eq!(kind.experimental_label(), Some("RFC3692-style Experiment"));

        Ok(())
    }

    #[test]
    fn ipv4_experimental_options_default_ipv4_emits_no_experiment_options() -> crate::Result<()> {
        let compiled = Packet::from_layer(Ipv4::new().src(src()).dst(dst())).compile()?;
        let bytes = compiled.as_bytes();
        let header_len = ((bytes[0] & 0x0f) as usize) * 4;
        let option_bytes = &bytes[20..header_len];

        assert_eq!(header_len, 20);
        assert!(option_bytes.is_empty());
        for value in [
            IPV4_OPTION_EXPERIMENTAL_1,
            IPV4_OPTION_EXPERIMENTAL_2,
            IPV4_OPTION_EXPERIMENTAL_3,
            IPV4_OPTION_EXPERIMENTAL_4,
        ] {
            assert!(!option_bytes.contains(&value), "kind {value:#04x}");
        }

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
        let ipv4 = decoded.layer::<Ipv4>().expect("decoded IPv4 layer");
        assert!(ipv4.option_bytes().is_empty());
        assert!(ipv4.parsed_options()?.is_empty());

        Ok(())
    }

    #[test]
    fn ipv4_experimental_options_helpers_are_const_friendly() {
        const KIND: Ipv4OptionKind = Ipv4OptionKind::new(IPV4_OPTION_EXPERIMENTAL_4);
        const IS_EXPERIMENTAL: bool = KIND.is_experimental();
        const LABEL: Option<&'static str> = KIND.experimental_label();
        const _: () = assert!(IS_EXPERIMENTAL);

        assert_eq!(LABEL, Some("RFC3692-style Experiment"));
    }
}

#[cfg(test)]
mod ip_options {
    use super::{Ipv4, Ipv4Option, Ipv4Protocol, Ipv4RouteOptionKind, IPV4_OPTION_NOP};
    use crate::{NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn ip_options_encode_decode_typed_and_generic_values() {
        let routes = vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(2, 3, 4, 5)];
        let ip = Ipv4::new()
            .src(src())
            .dst(dst())
            .id(0x4321)
            .ipv4_protocol(Ipv4Protocol::Icmpv4)
            .ipv4_option(Ipv4Option::record_route(4, routes.clone()))
            .unwrap()
            .ipv4_option(Ipv4Option::traceroute(0x1234, 1, 0xffff, src()))
            .unwrap()
            .ipv4_option(Ipv4Option::generic(8, [1, 1]))
            .unwrap();
        let packet = ip / Raw::from_bytes([0u8; 8]);
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let decoded_ip = decoded.layer::<Ipv4>().unwrap();
        let options = decoded_ip.parsed_options().unwrap();

        assert_eq!(
            options[0],
            Ipv4Option::Route {
                kind: Ipv4RouteOptionKind::RecordRoute,
                pointer: 4,
                routes
            }
        );
        assert_eq!(options[1], Ipv4Option::traceroute(0x1234, 1, 0xffff, src()));
        assert_eq!(options[2], Ipv4Option::generic(8, [1, 1]));
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ip_options_reject_malformed_option_lengths_on_decode() {
        let mut bytes = [0u8; 24];
        bytes[0] = 0x46;
        bytes[2..4].copy_from_slice(&(24u16).to_be_bytes());
        bytes[8] = 64;
        bytes[20..24].copy_from_slice(&[7, 10, 4, 0]);

        let error = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap_err();
        assert!(error.to_string().contains("ipv4 option"));
    }

    #[test]
    fn ip_options_iterator_can_be_reused_without_consuming_raw_bytes() {
        let ip = Ipv4::new().option([IPV4_OPTION_NOP]);

        let first = ip.parsed_options().unwrap();
        let second = ip.parsed_options().unwrap();

        assert_eq!(first, vec![Ipv4Option::NoOperation]);
        assert_eq!(second, first);
        assert_eq!(ip.option_bytes(), &[IPV4_OPTION_NOP]);
    }
}

#[cfg(test)]
mod ipv4_timestamp_option {
    use super::{Ipv4, Ipv4Option, Ipv4Protocol, IPV4_OPTION_TIMESTAMP};
    use crate::{CrafterError, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn ipv4_timestamp_option_encodes_and_decodes_timestamp_only() {
        let option = Ipv4Option::timestamp(13, 2, vec![0x0102_0304, 0x8000_0001]);
        let encoded = option.encode().unwrap();

        assert_eq!(
            encoded,
            vec![
                IPV4_OPTION_TIMESTAMP,
                12,
                13,
                0x20,
                0x01,
                0x02,
                0x03,
                0x04,
                0x80,
                0x00,
                0x00,
                0x01,
            ]
        );

        let decoded = Ipv4Option::decode_all(&encoded).unwrap();
        assert_eq!(decoded, vec![option.clone()]);
        assert_eq!(decoded[0].timestamp_pointer(), Some(13));
        assert_eq!(decoded[0].timestamp_overflow(), Some(2));
        assert_eq!(decoded[0].timestamp_flag(), Some(0));
        assert_eq!(
            decoded[0].timestamp_values(),
            Some(&[0x0102_0304, 0x8000_0001][..])
        );
        assert_eq!(decoded[0].timestamp_address_values(), None);
    }

    #[test]
    fn ipv4_timestamp_option_address_modes_round_trip() {
        let entries = vec![(src(), 0x0102_0304), (dst(), 0x8000_0002)];
        let option = Ipv4Option::timestamp_with_addresses(21, 1, entries.clone());
        let packet = Ipv4::new()
            .src(src())
            .dst(dst())
            .ipv4_protocol(Ipv4Protocol::Experimental1)
            .ipv4_option(option.clone())
            .unwrap()
            / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef]);
        let bytes = packet.compile().unwrap();

        assert_eq!(
            &bytes.as_bytes()[20..40],
            &[
                IPV4_OPTION_TIMESTAMP,
                20,
                21,
                0x11,
                192,
                0,
                2,
                10,
                0x01,
                0x02,
                0x03,
                0x04,
                198,
                51,
                100,
                20,
                0x80,
                0x00,
                0x00,
                0x02,
            ]
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let decoded_ip = decoded.layer::<Ipv4>().unwrap();
        let options = decoded_ip.parsed_options().unwrap();

        assert_eq!(options, vec![option.clone()]);
        assert_eq!(options[0].timestamp_pointer(), Some(21));
        assert_eq!(options[0].timestamp_overflow(), Some(1));
        assert_eq!(options[0].timestamp_flag(), Some(1));
        assert_eq!(options[0].timestamp_address_values(), Some(&entries[..]));
        assert_eq!(decoded.compile().unwrap(), bytes);

        let prespecified = Ipv4Option::timestamp_prespecified(13, 0, vec![(dst(), 0x0102_0304)]);
        let prespecified_encoded = prespecified.encode().unwrap();
        assert_eq!(prespecified_encoded[3], 3);
        assert_eq!(
            Ipv4Option::decode_all(&prespecified_encoded).unwrap(),
            vec![prespecified]
        );
    }

    #[test]
    fn ipv4_timestamp_option_rejects_invalid_constructed_fields() {
        assert_eq!(
            Ipv4Option::timestamp(4, 0, Vec::<u32>::new())
                .encode()
                .unwrap_err(),
            CrafterError::InvalidFieldValue {
                field: "ipv4.option.pointer",
                reason: "timestamp option pointer must be at least 5",
            }
        );

        assert_eq!(
            Ipv4Option::timestamp(5, 16, Vec::<u32>::new())
                .encode()
                .unwrap_err(),
            CrafterError::InvalidFieldValue {
                field: "ipv4.option.timestamp.overflow",
                reason: "timestamp option overflow must fit in four bits",
            }
        );

        assert_eq!(
            Ipv4Option::timestamp(41, 0, vec![0; 10])
                .encode()
                .unwrap_err(),
            CrafterError::InvalidFieldValue {
                field: "ipv4.option.length",
                reason: "timestamp option length must be at most 40 bytes",
            }
        );

        assert_eq!(
            Ipv4Option::timestamp(14, 0, vec![0]).encode().unwrap_err(),
            CrafterError::InvalidFieldValue {
                field: "ipv4.option.pointer",
                reason: "timestamp option pointer must not exceed option length plus one",
            }
        );
    }

    #[test]
    fn ipv4_timestamp_option_decode_falls_back_or_errors_by_variant() {
        let unsupported = [IPV4_OPTION_TIMESTAMP, 4, 5, 0x02];
        assert_eq!(
            Ipv4Option::decode_all(&unsupported).unwrap(),
            vec![Ipv4Option::generic(IPV4_OPTION_TIMESTAMP, [5, 0x02])]
        );

        assert_eq!(
            Ipv4Option::decode_all(&[IPV4_OPTION_TIMESTAMP, 4, 4, 0x00]).unwrap_err(),
            CrafterError::InvalidFieldValue {
                field: "ipv4.option.pointer",
                reason: "timestamp option pointer must be at least 5",
            }
        );

        assert_eq!(
            Ipv4Option::decode_all(&[IPV4_OPTION_TIMESTAMP, 5, 5, 0x00, 0x00]).unwrap_err(),
            CrafterError::InvalidFieldValue {
                field: "ipv4.option.timestamp",
                reason: "timestamp-only option data must contain whole 32-bit timestamps",
            }
        );
    }
}

#[cfg(test)]
mod ipv4_router_alert_option {
    use super::{Ipv4, Ipv4Option, Ipv4Protocol, IPV4_OPTION_ROUTER_ALERT};
    use crate::{CrafterError, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn ipv4_router_alert_option_encodes_and_decodes_value_zero() {
        let option = Ipv4Option::router_alert(0);
        let encoded = option.encode().unwrap();

        assert_eq!(encoded, vec![IPV4_OPTION_ROUTER_ALERT, 4, 0, 0]);
        assert_eq!(option.kind(), IPV4_OPTION_ROUTER_ALERT);
        assert_eq!(option.encoded_len(), 4);

        let decoded = Ipv4Option::decode_all(&encoded).unwrap();
        assert_eq!(decoded, vec![option.clone()]);
        assert_eq!(decoded[0].router_alert_value(), Some(0));
    }

    #[test]
    fn ipv4_router_alert_option_preserves_unknown_value_numbers() {
        let option = Ipv4Option::router_alert(0xbeef);
        let packet = Ipv4::new()
            .src(src())
            .dst(dst())
            .ipv4_protocol(Ipv4Protocol::Experimental1)
            .ipv4_option(option.clone())
            .unwrap()
            / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef]);
        let bytes = packet.compile().unwrap();

        assert_eq!(
            &bytes.as_bytes()[20..24],
            &[IPV4_OPTION_ROUTER_ALERT, 4, 0xbe, 0xef]
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let decoded_ip = decoded.layer::<Ipv4>().unwrap();
        let options = decoded_ip.parsed_options().unwrap();

        assert_eq!(options, vec![option.clone()]);
        assert_eq!(options[0].router_alert_value(), Some(0xbeef));
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv4_router_alert_option_rejects_non_fixed_lengths() {
        assert_eq!(
            Ipv4Option::decode_all(&[IPV4_OPTION_ROUTER_ALERT, 3, 0]).unwrap_err(),
            CrafterError::InvalidFieldValue {
                field: "ipv4.option.length",
                reason: "router alert option length must be 4 bytes",
            }
        );

        assert_eq!(
            Ipv4Option::decode_all(&[IPV4_OPTION_ROUTER_ALERT, 5, 0, 0, 0]).unwrap_err(),
            CrafterError::InvalidFieldValue {
                field: "ipv4.option.length",
                reason: "router alert option length must be 4 bytes",
            }
        );
    }
}

#[cfg(test)]
mod ipv4_checksum {
    use super::{Ipv4, Ipv4ChecksumStatus, Ipv4Protocol};
    use crate::{checksum::verify_internet_checksum, Raw};
    use core::net::Ipv4Addr;

    const IPV4_ICMP_FIXTURE: &[u8] = fixture_bytes!("bytes/ipv4-icmp-echo-request.bin");

    #[test]
    fn ipv4_header_checksum_matches_golden_bytes() {
        let packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            .id(0x1234)
            .dont_fragment(true)
            .ipv4_protocol(Ipv4Protocol::Icmpv4)
            / Raw::from_bytes(&IPV4_ICMP_FIXTURE[20..]);
        let bytes = packet.compile().unwrap();

        assert_eq!(&bytes.as_bytes()[10..12], &[0x3c, 0x4c]);
        assert!(verify_internet_checksum(&bytes.as_bytes()[..20]));
    }

    #[test]
    fn explicit_ipv4_checksum_is_preserved() {
        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            .id(0x1234)
            .dont_fragment(true)
            .ipv4_protocol(Ipv4Protocol::Icmpv4)
            .checksum(0x1111)
            / Raw::from_bytes(&IPV4_ICMP_FIXTURE[20..]))
        .compile()
        .unwrap();

        assert_eq!(&bytes.as_bytes()[10..12], &[0x11, 0x11]);
        assert!(!verify_internet_checksum(&bytes.as_bytes()[..20]));
    }

    #[test]
    fn explicit_ipv4_checksum_is_preserved_with_options() {
        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            .id(0x1234)
            .dont_fragment(true)
            .ipv4_protocol(Ipv4Protocol::Icmpv4)
            .checksum(0xbeef)
            .option([0x01])
            .option([0x07, 0x07, 0x04, 0xc0, 0x00, 0x02, 0x01])
            / Raw::from_bytes(&IPV4_ICMP_FIXTURE[20..]))
        .compile()
        .unwrap();

        assert_eq!(bytes.as_bytes()[0], 0x47);
        assert_eq!(&bytes.as_bytes()[10..12], &[0xbe, 0xef]);
        assert_eq!(
            &bytes.as_bytes()[20..28],
            &[0x01, 0x07, 0x07, 0x04, 0xc0, 0x00, 0x02, 0x01]
        );
        assert!(!verify_internet_checksum(&bytes.as_bytes()[..28]));
    }

    #[test]
    fn decoded_ipv4_checksum_verifies() {
        let decoded =
            crate::Packet::decode_from_l3(crate::NetworkLayer::Ipv4, IPV4_ICMP_FIXTURE).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();

        assert_eq!(ipv4.checksum_value(), Some(0x3c4c));
        assert!(verify_internet_checksum(&IPV4_ICMP_FIXTURE[..20]));
    }

    #[test]
    fn ipv4_checksum_status_valid_for_decoded_header() {
        let decoded =
            crate::Packet::decode_from_l3(crate::NetworkLayer::Ipv4, IPV4_ICMP_FIXTURE).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();

        assert_eq!(ipv4.checksum_value(), Some(0x3c4c));
        assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);
        assert_eq!(decoded.compile().unwrap().as_bytes(), IPV4_ICMP_FIXTURE);
    }

    #[test]
    fn ipv4_checksum_status_invalid_for_decoded_header_without_rejecting_packet() {
        let mut bytes = IPV4_ICMP_FIXTURE.to_vec();
        bytes[10] ^= 0xff;

        let decoded = crate::Packet::decode_from_l3(crate::NetworkLayer::Ipv4, &bytes).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();

        assert_eq!(ipv4.checksum_value(), Some(0xc34c));
        assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Invalid);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }
}
