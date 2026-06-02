//! Unit tests for the TCP folder module.

mod tcp {
    use super::super::{Tcp, TCP_FLAG_ACK, TCP_FLAG_SYN};
    use crate::checksum::ipv4_pseudo_header_checksum;
    use crate::{IpProtocol, Ipv4, Packet, Raw, IPPROTO_TCP};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_autofills_ipv4_checksum_for_odd_payload_and_flags() {
        let packet = Ipv4::new().src(src()).dst(dst()).id(0x2223)
            / Tcp::new()
                .sport(44444)
                .dport(80)
                .seq(0x0102_0304)
                .ack(0x0506_0708)
                .flags(TCP_FLAG_SYN | TCP_FLAG_ACK)
                .window(64240)
            / Raw::from_bytes([0xaa, 0xbb, 0xcc]);
        let bytes = packet.compile().unwrap();

        assert_eq!(&bytes.as_bytes()[2..4], &(43u16).to_be_bytes());
        assert_eq!(&bytes.as_bytes()[20..22], &44444u16.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[22..24], &80u16.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[24..28], &0x0102_0304u32.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[28..32], &0x0506_0708u32.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[32..34], &[0x50, 0x12]);
        let mut tcp = bytes.as_bytes()[20..].to_vec();
        tcp[16] = 0;
        tcp[17] = 0;
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[36], bytes.as_bytes()[37]]),
            ipv4_pseudo_header_checksum(src(), dst(), IPPROTO_TCP, &tcp)
        );
    }

    #[test]
    fn tcp_decode_exposes_header_fields_and_payload() {
        let original = Ipv4::new().src(src()).dst(dst()).id(0x2224)
            / Tcp::new()
                .sport(12345)
                .dport(443)
                .seq(0x1111_2222)
                .ack(0x3333_4444)
                .flags(TCP_FLAG_ACK)
                .window(4096)
                .urgent_pointer(9)
            / Raw::from("GET");
        let bytes = original.compile().unwrap();
        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let tcp = decoded.layer::<Tcp>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(tcp.source_port_value(), 12345);
        assert_eq!(tcp.destination_port_value(), 443);
        assert_eq!(tcp.sequence_number_value(), 0x1111_2222);
        assert_eq!(tcp.acknowledgment_number_value(), 0x3333_4444);
        assert_eq!(tcp.flags_value(), TCP_FLAG_ACK);
        assert_eq!(tcp.window_value(), 4096);
        assert_eq!(tcp.urgent_pointer_value(), 9);
        assert_eq!(raw.as_bytes(), b"GET");
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn explicit_tcp_checksum_is_preserved() {
        let bytes =
            (Ipv4::new().src(src()).dst(dst()) / Tcp::new().checksum(0x1111) / Raw::from("abc"))
                .compile()
                .unwrap();

        assert_eq!(&bytes.as_bytes()[36..38], &[0x11, 0x11]);
    }

    #[test]
    fn tcp_decode_rejects_short_and_malformed_inputs() {
        let short = (Ipv4::new().proto(IpProtocol::Tcp) / Raw::from_bytes([0u8; 19]))
            .compile()
            .unwrap();
        assert!(Packet::decode_from_l3(crate::NetworkLayer::Ipv4, short.as_bytes()).is_err());

        let mut malformed = [0u8; 20];
        malformed[12] = 0x40;
        let bytes = (Ipv4::new().proto(IpProtocol::Tcp) / Raw::from_bytes(malformed))
            .compile()
            .unwrap();
        assert!(Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).is_err());
    }
}

mod tcp_options {
    use super::super::{Tcp, TcpExtendedDataOffset, TcpOption, TcpSackBlock, TCP_FLAG_ACK, TCP_FLAG_SYN};
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_options_encode_decode_common_typed_options() {
        let mut tcp = Tcp::new()
            .sport(44444)
            .dport(443)
            .seq(0x0102_0304)
            .flags(TCP_FLAG_SYN | TCP_FLAG_ACK);
        tcp = tcp.tcp_option(TcpOption::mss(1460)).unwrap();
        tcp = tcp.tcp_option(TcpOption::window_scale(7)).unwrap();
        tcp = tcp
            .tcp_option(TcpOption::timestamp(398_303_815, 12_345))
            .unwrap();
        tcp = tcp.tcp_option(TcpOption::sack_permitted()).unwrap();
        tcp = tcp
            .tcp_option(TcpOption::sack(vec![TcpSackBlock::new(10, 20)]))
            .unwrap();

        let packet = Ipv4::new().src(src()).dst(dst()).id(0x2225) / tcp / Raw::from("payload");
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let tcp = decoded.layer::<Tcp>().unwrap();
        let options = tcp.parsed_options().unwrap();

        assert_eq!(options[0], TcpOption::MaximumSegmentSize(1460));
        assert_eq!(options[1], TcpOption::WindowScale(7));
        assert_eq!(
            options[2],
            TcpOption::Timestamp {
                value: 398_303_815,
                echo_reply: 12_345
            }
        );
        assert_eq!(options[3], TcpOption::SackPermitted);
        assert_eq!(options[4], TcpOption::Sack(vec![TcpSackBlock::new(10, 20)]));
        assert_eq!(options[5], TcpOption::EndOfList);
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn tcp_options_preserve_edo_mptcp_fast_open_and_generic_values() {
        let mut tcp = Tcp::new().sport(12345).dport(80);
        tcp = tcp.tcp_option(TcpOption::extended_data_offset(9)).unwrap();
        tcp = tcp
            .tcp_option(TcpOption::multipath_tcp(1, [0x03, 0xaa, 0xbb]))
            .unwrap();
        tcp = tcp.tcp_option(TcpOption::fast_open([0xca, 0xfe])).unwrap();
        tcp = tcp.tcp_option(TcpOption::generic(76, [0x55])).unwrap();

        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2226) / tcp)
            .compile()
            .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let options = decoded.layer::<Tcp>().unwrap().parsed_options().unwrap();

        assert_eq!(
            options[0],
            TcpOption::ExtendedDataOffset(TcpExtendedDataOffset::HeaderLength { header_length: 9 })
        );
        assert_eq!(
            options[1],
            TcpOption::MultipathTcp {
                subtype: 1,
                data: vec![0x13, 0xaa, 0xbb]
            }
        );
        assert_eq!(options[2], TcpOption::FastOpen(vec![0xca, 0xfe]));
        assert_eq!(
            options[3],
            TcpOption::Generic {
                kind: 76,
                data: vec![0x55]
            }
        );
    }

    #[test]
    fn tcp_options_reject_malformed_option_lengths_on_decode() {
        let mut tcp = [0u8; 24];
        tcp[12] = 0x60;
        tcp[13] = TCP_FLAG_SYN as u8;
        tcp[20..24].copy_from_slice(&[2, 5, 0x05, 0xb4]);
        let bytes = (Ipv4::new().proto(IpProtocol::Tcp) / Raw::from_bytes(tcp))
            .compile()
            .unwrap();

        let error = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("tcp option"));
    }

    #[test]
    fn tcp_options_iterator_can_be_reused_without_consuming_raw_bytes() {
        let tcp = Tcp::new().option([1, 1, 0]);

        let first = tcp.parsed_options().unwrap();
        let second = tcp.parsed_options().unwrap();

        assert_eq!(
            first,
            vec![
                TcpOption::NoOperation,
                TcpOption::NoOperation,
                TcpOption::EndOfList
            ]
        );
        assert_eq!(second, first);
        assert_eq!(tcp.option_bytes(), &[1, 1, 0]);
    }
}

mod option_classification {
    use super::super::{
        tcp_option_kind_class, tcp_option_kind_is_assigned, tcp_option_kind_is_experimental,
        TcpOption, TcpOptionKindClass, TCP_OPTION_EOL, TCP_OPTION_EXPERIMENTAL_1,
        TCP_OPTION_EXPERIMENTAL_2, TCP_OPTION_MSS, TCP_OPTION_NOP,
    };

    #[test]
    fn tcp_option_kind_classification() {
        // Assigned base/standard kinds.
        assert_eq!(
            tcp_option_kind_class(TCP_OPTION_EOL),
            TcpOptionKindClass::Assigned
        );
        assert_eq!(
            tcp_option_kind_class(TCP_OPTION_NOP),
            TcpOptionKindClass::Assigned
        );
        assert_eq!(
            tcp_option_kind_class(TCP_OPTION_MSS),
            TcpOptionKindClass::Assigned
        );
        assert!(tcp_option_kind_is_assigned(TCP_OPTION_MSS));
        assert!(!tcp_option_kind_is_experimental(TCP_OPTION_MSS));

        // RFC 6994 experimental kinds 253 and 254.
        assert_eq!(
            tcp_option_kind_class(TCP_OPTION_EXPERIMENTAL_1),
            TcpOptionKindClass::Experimental
        );
        assert_eq!(
            tcp_option_kind_class(TCP_OPTION_EXPERIMENTAL_2),
            TcpOptionKindClass::Experimental
        );
        assert!(tcp_option_kind_is_experimental(TCP_OPTION_EXPERIMENTAL_1));
        assert!(tcp_option_kind_is_experimental(TCP_OPTION_EXPERIMENTAL_2));
        // Experimental kinds are still assigned by IANA.
        assert!(tcp_option_kind_is_assigned(TCP_OPTION_EXPERIMENTAL_1));

        // An unassigned kind (16 is unassigned in the IANA registry, as is the
        // draft-only EDO kind 237).
        assert_eq!(
            tcp_option_kind_class(16),
            TcpOptionKindClass::Unassigned
        );
        assert_eq!(
            tcp_option_kind_class(237),
            TcpOptionKindClass::Unassigned
        );
        assert!(!tcp_option_kind_is_assigned(16));
        assert!(!tcp_option_kind_is_experimental(16));

        // The classification is reachable from a typed option value too.
        assert_eq!(
            TcpOption::mss(1460).kind_class(),
            TcpOptionKindClass::Assigned
        );
        assert!(TcpOption::generic(253, [0x00, 0x01]).kind_is_experimental());
        assert!(!TcpOption::generic(16, []).kind_is_assigned());
    }
}

mod option_value_accessors {
    use super::super::{TcpExtendedDataOffset, TcpOption, TcpSackBlock};

    #[test]
    fn tcp_option_value_accessors() {
        // MSS.
        let mss = TcpOption::mss(1460);
        assert_eq!(mss.maximum_segment_size_value(), Some(1460));
        assert_eq!(mss.window_scale_shift(), None);

        // Window Scale.
        let ws = TcpOption::window_scale(7);
        assert_eq!(ws.window_scale_shift(), Some(7));
        assert_eq!(ws.maximum_segment_size_value(), None);

        // SACK Permitted.
        let sack_permitted = TcpOption::sack_permitted();
        assert!(sack_permitted.is_sack_permitted());
        assert!(!mss.is_sack_permitted());
        assert_eq!(sack_permitted.sack_blocks(), None);

        // SACK blocks.
        let blocks = vec![TcpSackBlock::new(10, 20), TcpSackBlock::new(30, 40)];
        let sack = TcpOption::sack(blocks.clone());
        assert_eq!(sack.sack_blocks(), Some(blocks.as_slice()));
        assert!(!sack.is_sack_permitted());

        // Timestamp.
        let ts = TcpOption::timestamp(398_303_815, 12_345);
        assert_eq!(ts.timestamp_values(), Some((398_303_815, 12_345)));
        assert_eq!(mss.timestamp_values(), None);

        // MPTCP subtype/data.
        let mptcp = TcpOption::multipath_tcp(1, [0x13, 0xaa, 0xbb]);
        assert_eq!(mptcp.mptcp_subtype(), Some(1));
        assert_eq!(mptcp.mptcp_data(), Some(&[0x13u8, 0xaa, 0xbb][..]));
        assert_eq!(mss.mptcp_subtype(), None);
        assert_eq!(mss.mptcp_data(), None);

        // EDO value.
        let edo = TcpOption::extended_data_offset(9);
        assert_eq!(
            edo.extended_data_offset_value(),
            Some(TcpExtendedDataOffset::HeaderLength { header_length: 9 })
        );
        assert_eq!(mss.extended_data_offset_value(), None);

        // Fast Open cookie.
        let fast_open = TcpOption::fast_open([0xca, 0xfe]);
        assert_eq!(fast_open.fast_open_cookie(), Some(&[0xcau8, 0xfe][..]));
        assert_eq!(mss.fast_open_cookie(), None);

        // Generic kind/data.
        let generic = TcpOption::generic(76, [0x55]);
        assert_eq!(generic.generic_kind(), Some(76));
        assert_eq!(generic.generic_data(), Some(&[0x55u8][..]));
        assert_eq!(mss.generic_kind(), None);
        assert_eq!(mss.generic_data(), None);
    }
}

mod option_padding {
    use super::super::{Tcp, TcpOption};
    use crate::{IpProtocol, Ipv4, Ipv4Option, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_option_padding_semantics() {
        // libcrafter's chosen TCP option padding behavior, asserted against the
        // real compile/decode path:
        //
        // 1. compile() pads the TCP option area to the data-offset (32-bit
        //    word) boundary with zero bytes. Because TCP_OPTION_EOL == 0, those
        //    trailing pad bytes are End-of-Option-List (EOL) bytes.
        // 2. decode preserves every padding byte in option_bytes().
        // 3. TcpOptionIter stops at the first EOL byte (it yields one
        //    EndOfList and then ends).
        // 4. Recompiling a decoded segment round-trips the padding byte-for-byte.

        // MSS (4 bytes) + Window Scale (3 bytes) = 7 option bytes. Padding to a
        // 32-bit boundary needs one trailing zero/EOL byte (8 bytes total).
        let mut tcp = Tcp::new();
        tcp = tcp.tcp_option(TcpOption::mss(1460)).unwrap();
        tcp = tcp.tcp_option(TcpOption::window_scale(7)).unwrap();

        // Before compile, only the raw option bytes are stored (no padding yet).
        assert_eq!(tcp.option_bytes(), &[2, 4, 0x05, 0xb4, 3, 3, 7]);

        let bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Tcp) / tcp)
            .compile()
            .unwrap();

        // (1) data offset reflects the padded header: 20 + 8 = 28 bytes => 7 words.
        assert_eq!(bytes.as_bytes()[32] >> 4, 7);
        // The option area is padded to the boundary with a zero/EOL byte.
        assert_eq!(
            &bytes.as_bytes()[40..48],
            &[2, 4, 0x05, 0xb4, 3, 3, 7, 0]
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let decoded_tcp = decoded.layer::<Tcp>().unwrap();

        // (2) decode keeps the padding byte in the raw option slice.
        assert_eq!(
            decoded_tcp.option_bytes(),
            &[2, 4, 0x05, 0xb4, 3, 3, 7, 0]
        );

        // (3) the iterator stops at the EOL padding byte: it surfaces MSS,
        // Window Scale, and a single EndOfList, then ends.
        let parsed = decoded_tcp.parsed_options().unwrap();
        assert_eq!(
            parsed,
            vec![
                TcpOption::MaximumSegmentSize(1460),
                TcpOption::WindowScale(7),
                TcpOption::EndOfList,
            ]
        );
        // The raw iterator yields exactly these three items and then None.
        let mut iter = decoded_tcp.option_iter();
        assert_eq!(iter.next().unwrap().unwrap(), TcpOption::MaximumSegmentSize(1460));
        assert_eq!(iter.next().unwrap().unwrap(), TcpOption::WindowScale(7));
        assert_eq!(iter.next().unwrap().unwrap(), TcpOption::EndOfList);
        assert!(iter.next().is_none());

        // (4) recompiling the decoded segment round-trips the padding exactly.
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn option_padding_uses_eol_bytes_for_ipv4_and_tcp_alignment() {
        let ip = Ipv4::new()
            .src(src())
            .dst(dst())
            .protocol(0)
            .ip_option(Ipv4Option::generic(8, [1]))
            .unwrap();
        let ip_bytes = (ip / Raw::from("x")).compile().unwrap();
        assert_eq!(ip_bytes.as_bytes()[0], 0x46);
        assert_eq!(&ip_bytes.as_bytes()[20..24], &[8, 3, 1, 0]);

        let decoded_ip = Packet::decode_from_l3(NetworkLayer::Ipv4, ip_bytes.as_bytes()).unwrap();
        assert_eq!(
            decoded_ip
                .layer::<Ipv4>()
                .unwrap()
                .parsed_options()
                .unwrap(),
            vec![Ipv4Option::generic(8, [1]), Ipv4Option::EndOfList]
        );

        let mut tcp = Tcp::new();
        tcp = tcp.tcp_option(TcpOption::mss(1460)).unwrap();
        tcp = tcp.tcp_option(TcpOption::window_scale(7)).unwrap();
        let tcp_bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Tcp) / tcp)
            .compile()
            .unwrap();
        assert_eq!(tcp_bytes.as_bytes()[32] >> 4, 7);
        assert_eq!(
            &tcp_bytes.as_bytes()[40..48],
            &[2, 4, 0x05, 0xb4, 3, 3, 7, 0]
        );
    }
}
