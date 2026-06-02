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

    #[test]
    fn tcp_accurate_ecn_flag_aliases_ns() {
        use super::super::{TCP_FLAG_AE, TCP_FLAG_NS};

        // RFC 9768 assigns the 0x100 control bit to AE (Accurate ECN); the
        // older ECN-nonce `NS` name (deprecated by RFC 8311) remains a
        // compatibility alias for the same bit. Both names must resolve to the
        // same value. See docs/tcp-rfc-manifest.md.
        assert_eq!(TCP_FLAG_AE, TCP_FLAG_NS);

        // A segment built with the current `AE` name must serialize to the same
        // bytes as one built with the legacy `NS` alias, since they set the same
        // control bit.
        let ae = (Ipv4::new().src(src()).dst(dst()).id(0x2225)
            / Tcp::new()
                .sport(40000)
                .dport(80)
                .seq(0x0a0b_0c0d)
                .ack(0x0e0f_1011)
                .flags(TCP_FLAG_AE | TCP_FLAG_SYN)
                .window(65535)
            / Raw::from("hi"))
        .compile()
        .unwrap();
        let ns = (Ipv4::new().src(src()).dst(dst()).id(0x2225)
            / Tcp::new()
                .sport(40000)
                .dport(80)
                .seq(0x0a0b_0c0d)
                .ack(0x0e0f_1011)
                .flags(TCP_FLAG_NS | TCP_FLAG_SYN)
                .window(65535)
            / Raw::from("hi"))
        .compile()
        .unwrap();
        assert_eq!(ae, ns);
    }

    #[test]
    fn tcp_ecn_flag_helpers_preserve_raw_flags() {
        use super::super::{TCP_FLAG_AE, TCP_FLAG_CWR, TCP_FLAG_ECE, TCP_FLAG_URG};

        // The ECN helpers (set_cwr/set_ece/set_ae, ecn_setup_syn,
        // accurate_ecn_setup, clear_ecn) are thin convenience wrappers over the
        // raw flag escape hatches `flags()` and `flag()`. They must compose with
        // raw flag control and must not disturb unrelated bits. Classic ECN
        // (CWR/ECE) is RFC 3168; the AE bit is RFC 9768. See
        // docs/tcp-rfc-manifest.md.

        // Starting from a raw flag word, the ECN setters only touch their own
        // bit and preserve every explicitly-set raw flag (here SYN | ACK | URG).
        let base = TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_URG;
        let with_ecn = Tcp::new().flags(base).set_cwr(true).set_ece(true).set_ae(true);
        assert_eq!(
            with_ecn.flags_value(),
            base | TCP_FLAG_CWR | TCP_FLAG_ECE | TCP_FLAG_AE
        );
        assert!(with_ecn.has_flag(TCP_FLAG_URG));
        assert!(with_ecn.has_flag(TCP_FLAG_SYN));

        // The setters clear their own bit without disturbing the rest.
        let cleared = with_ecn.clone().set_cwr(false).set_ece(false).set_ae(false);
        assert_eq!(cleared.flags_value(), base);
        // clear_ecn is equivalent and also leaves the raw flags intact.
        assert_eq!(
            Tcp::new().flags(base | TCP_FLAG_CWR | TCP_FLAG_ECE | TCP_FLAG_AE)
                .clear_ecn()
                .flags_value(),
            base
        );

        // The combination helpers compose on top of raw flags: an ECN-setup SYN
        // sets ECE | CWR (RFC 3168 §6.1.1) without clobbering the raw SYN bit set
        // via flags().
        let setup = Tcp::new().flags(TCP_FLAG_SYN).ecn_setup_syn();
        assert_eq!(
            setup.flags_value(),
            TCP_FLAG_SYN | TCP_FLAG_ECE | TCP_FLAG_CWR
        );
        // The AccECN setup adds the AE bit (RFC 9768) to the classic pair.
        let accecn = Tcp::new().flags(TCP_FLAG_SYN).accurate_ecn_setup();
        assert_eq!(
            accecn.flags_value(),
            TCP_FLAG_SYN | TCP_FLAG_AE | TCP_FLAG_CWR | TCP_FLAG_ECE
        );

        // The raw escape hatches still win when used after a helper: an explicit
        // deliberate (malformed) value set via flags() replaces helper-set bits
        // wholesale, proving the helpers do not lock out raw control.
        let raw_override = Tcp::new().set_cwr(true).set_ece(true).flags(0x000);
        assert_eq!(raw_override.flags_value(), 0x000);

        // And flag() composes the other direction: a helper-set ECN bit survives
        // an unrelated raw flag() toggle, and the helper does not re-clear a bit
        // the raw escape hatch deliberately set. Start from an explicit empty
        // flag word so the default SYN bit does not enter the comparison.
        let mixed = Tcp::new()
            .flags(0x000)
            .set_ece(true)
            .flag(TCP_FLAG_CWR, true)
            .set_ae(true);
        assert_eq!(
            mixed.flags_value(),
            TCP_FLAG_ECE | TCP_FLAG_CWR | TCP_FLAG_AE
        );
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

mod unknown_option_roundtrip {
    use super::super::{Tcp, TcpOption, TcpOptionKindClass};
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_unknown_options_roundtrip_exact_bytes() {
        // A TCP segment carrying several unknown option kinds, interleaved NOP
        // padding, a terminating EOL, and trailing zero padding must decode into
        // inspectable generic options and recompile to the exact original bytes.
        //
        // The raw option region is built to already sit on a 32-bit word
        // boundary (12 bytes), so compile() adds no padding of its own and the
        // recompiled bytes can be compared byte-for-byte:
        //
        //   [200, 4, 0xAA, 0xBB]  unknown kind 200, len 4 (2 data bytes)
        //   [1]                   NOP padding
        //   [222, 3, 0xCC]        unknown kind 222, len 3 (1 data byte)
        //   [1]                   NOP padding
        //   [0]                   EOL terminator
        //   [0, 0]                trailing zero padding to the word boundary
        let raw_options = [200u8, 4, 0xAA, 0xBB, 1, 222, 3, 0xCC, 1, 0, 0, 0];
        assert_eq!(raw_options.len() % 4, 0);

        let tcp = Tcp::new().sport(44444).dport(443).option(raw_options);

        // Before compile the layer holds exactly the raw option bytes.
        assert_eq!(tcp.option_bytes(), &raw_options);

        let bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Tcp) / tcp / Raw::from("payload"))
            .compile()
            .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let decoded_tcp = decoded.layer::<Tcp>().unwrap();

        // option_bytes() preserves the raw option region verbatim, including the
        // NOP bytes, the EOL terminator, and the trailing zero padding.
        assert_eq!(decoded_tcp.option_bytes(), &raw_options);

        // The unknown kinds surface as inspectable Generic options carrying their
        // raw payload bytes; the iterator stops at the EOL terminator.
        let parsed = decoded_tcp.parsed_options().unwrap();
        assert_eq!(
            parsed,
            vec![
                TcpOption::Generic {
                    kind: 200,
                    data: vec![0xAA, 0xBB],
                },
                TcpOption::NoOperation,
                TcpOption::Generic {
                    kind: 222,
                    data: vec![0xCC],
                },
                TcpOption::NoOperation,
                TcpOption::EndOfList,
            ]
        );

        // The generic options are classified as unknown (unassigned) IANA kinds
        // rather than being confused with a typed option.
        assert_eq!(parsed[0].generic_kind(), Some(200));
        assert_eq!(parsed[0].generic_data(), Some(&[0xAAu8, 0xBB][..]));
        assert_eq!(parsed[0].kind_class(), TcpOptionKindClass::Unassigned);
        assert_eq!(parsed[2].generic_kind(), Some(222));
        assert_eq!(parsed[2].generic_data(), Some(&[0xCCu8][..]));
        assert_eq!(parsed[2].kind_class(), TcpOptionKindClass::Unassigned);

        // Recompiling the decoded segment reproduces the original wire bytes
        // exactly: unknown option kinds round-trip without losing any bytes.
        assert_eq!(decoded.compile().unwrap(), bytes);
    }
}

mod option_errors {
    use super::super::TcpOption;

    // Decode a raw TCP option byte slice and return the rendered error string
    // for the first malformed option. Panics if the slice decodes cleanly,
    // because every input here is deliberately malformed.
    fn decode_error(bytes: &[u8]) -> String {
        TcpOption::decode_all(bytes)
            .expect_err("malformed TCP options must not decode cleanly")
            .to_string()
    }

    #[test]
    fn tcp_option_malformed_lengths_have_context() {
        // Every malformed-length decode path must surface a structured error
        // whose context identifies the failing option, so generated tools can
        // tell which option was wrong instead of log-fishing. The asserted
        // substrings are the stable `context`/`field` slots carried by
        // `CrafterError` and rendered through its `Display`.

        // 1. Length underflow: an option length byte below the two-byte
        //    minimum. The trailing zero keeps this from being an overrun so the
        //    `< 2` path (not the buffer check) is exercised.
        let underflow = decode_error(&[super::super::TCP_OPTION_MSS, 1, 0, 0]);
        assert!(
            underflow.contains("tcp.option.length"),
            "length underflow error must carry tcp.option.length context, got: {underflow}"
        );

        // 2. Fixed-length mismatch: MSS declares length 3 but MSS is fixed at 4
        //    bytes. The trailing padding byte keeps the declared length inside
        //    the buffer so the fixed-length validator runs.
        let mss_mismatch = decode_error(&[super::super::TCP_OPTION_MSS, 3, 0, 0]);
        assert!(
            mss_mismatch.contains("tcp.option.mss"),
            "MSS fixed-length mismatch must carry tcp.option.mss context, got: {mss_mismatch}"
        );

        // A second fixed-length option: Timestamp is fixed at 10 bytes.
        let timestamp_mismatch =
            decode_error(&[super::super::TCP_OPTION_TIMESTAMP, 4, 0, 0]);
        assert!(
            timestamp_mismatch.contains("tcp.option.timestamp"),
            "timestamp fixed-length mismatch must carry tcp.option.timestamp context, got: {timestamp_mismatch}"
        );

        // 3. Overrun beyond available bytes: MSS declares length 5 but only 4
        //    option bytes are present.
        let overrun = decode_error(&[super::super::TCP_OPTION_MSS, 5, 0x05, 0xb4]);
        assert!(
            overrun.contains("tcp option"),
            "option overrun must carry the tcp option buffer context, got: {overrun}"
        );

        // 4. Invalid semantic length: SACK declares a length that fits in the
        //    buffer and is >= 2 but does not frame a whole number of 8-byte
        //    SACK blocks.
        let sack_semantic = decode_error(&[super::super::TCP_OPTION_SACK, 4, 0, 0]);
        assert!(
            sack_semantic.contains("tcp.option.sack"),
            "SACK semantic-length error must carry tcp.option.sack context, got: {sack_semantic}"
        );

        // A second semantic-length path: EDO must be 2, 4, or 6 bytes; a
        // declared length of 5 is structurally valid but semantically invalid.
        let edo_semantic = decode_error(&[super::super::TCP_OPTION_EDO, 5, 0, 0, 0]);
        assert!(
            edo_semantic.contains("tcp.option.edo"),
            "EDO semantic-length error must carry tcp.option.edo context, got: {edo_semantic}"
        );
    }
}

mod experimental_exid_options {
    use super::super::{
        Tcp, TcpOption, TcpOptionKindClass, TCP_OPTION_EXPERIMENTAL_1, TCP_OPTION_EXPERIMENTAL_2,
        TCP_OPTION_EXPERIMENTAL_MIN_LEN,
    };
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_experimental_exid_options_roundtrip() {
        // RFC 6994 experimental TCP options (kinds 253 and 254) carry a 16-bit
        // Experiment Identifier (ExID) immediately after the length byte,
        // followed by arbitrary experiment data. The ExID values used here are
        // documentation-only examples, not registered IANA ExID assignments.
        const EXID_A: u16 = 0xABCD;
        const EXID_B: u16 = 0x0102;

        // 1. Both experimental kinds encode the ExID then preserve the
        //    experiment data, and decode back to the same typed option byte-for
        //    byte.
        for (kind, exid, data) in [
            (TCP_OPTION_EXPERIMENTAL_1, EXID_A, vec![0xDE, 0xAD, 0xBE, 0xEF]),
            (TCP_OPTION_EXPERIMENTAL_2, EXID_B, vec![0x11, 0x22]),
            // Empty experiment data: the minimum-length (4-byte) experimental
            // option carries only the ExID.
            (TCP_OPTION_EXPERIMENTAL_1, EXID_B, Vec::new()),
        ] {
            let option = TcpOption::experimental(kind, exid, data.clone());
            assert!(option.is_experimental());
            assert_eq!(option.kind(), kind);
            assert_eq!(option.experiment_id(), Some(exid));
            assert_eq!(option.experiment_data(), Some(data.as_slice()));
            assert_eq!(option.kind_class(), TcpOptionKindClass::Experimental);
            assert!(option.kind_is_experimental());
            assert!(option.kind_is_assigned());

            // Encoded length is kind + length + 16-bit ExID + experiment data.
            let encoded = option.encode().unwrap();
            assert_eq!(encoded.len(), 4 + data.len());
            assert_eq!(encoded[0], kind);
            assert_eq!(encoded[1] as usize, 4 + data.len());
            assert_eq!(&encoded[2..4], &exid.to_be_bytes());
            assert_eq!(&encoded[4..], data.as_slice());

            // Round-trip through decode preserves the typed representation.
            let decoded = TcpOption::decode_all(&encoded).unwrap();
            assert_eq!(decoded, vec![option.clone()]);
            assert_eq!(decoded[0].encode().unwrap(), encoded);
        }

        // 2. The kind-1 and kind-2 convenience constructors select the right
        //    experimental kind.
        assert_eq!(
            TcpOption::experimental_1(EXID_A, [0x01]).kind(),
            TCP_OPTION_EXPERIMENTAL_1
        );
        assert_eq!(
            TcpOption::experimental_2(EXID_A, [0x01]).kind(),
            TCP_OPTION_EXPERIMENTAL_2
        );

        // 3. A full TCP segment carrying an experimental option compiles,
        //    decodes, exposes the typed ExID + data, and recompiles to the exact
        //    original wire bytes.
        let tcp = Tcp::new()
            .sport(44444)
            .dport(443)
            .tcp_option(TcpOption::experimental_1(EXID_A, [0xDE, 0xAD, 0xBE, 0xEF]))
            .unwrap();
        let bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Tcp)
            / tcp
            / Raw::from("payload"))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let options = decoded.layer::<Tcp>().unwrap().parsed_options().unwrap();
        assert_eq!(
            options[0],
            TcpOption::Experimental {
                kind: TCP_OPTION_EXPERIMENTAL_1,
                experiment_id: EXID_A,
                data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }
        );
        assert_eq!(options[0].experiment_id(), Some(EXID_A));
        assert_eq!(
            options[0].experiment_data(),
            Some(&[0xDEu8, 0xAD, 0xBE, 0xEF][..])
        );
        assert_eq!(decoded.compile().unwrap(), bytes);

        // 4. An experimental option shorter than the 4-byte minimum (no room for
        //    a full 16-bit ExID) decodes to a structured, contextful error
        //    rather than a panic or a silent generic blob.
        let too_short = TcpOption::decode_all(&[TCP_OPTION_EXPERIMENTAL_1, 3, 0x00]).unwrap_err();
        assert!(
            too_short
                .to_string()
                .contains("tcp.option.experimental.length"),
            "experimental min-length error must carry context, got: {too_short}"
        );
        assert_eq!(TCP_OPTION_EXPERIMENTAL_MIN_LEN, 4);
    }
}

mod user_timeout_option {
    use super::super::{
        Tcp, TcpOption, TcpOptionKindClass, TCP_OPTION_USER_TIMEOUT, TCP_OPTION_USER_TIMEOUT_LEN,
    };
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_user_timeout_option_roundtrip() {
        // RFC 5482 section 3: the User Timeout option (kind 28, length 4) carries
        // a single 16-bit field whose most-significant bit is the Granularity (G)
        // flag and whose remaining 15 bits are the User Timeout value. The values
        // below are documentation-only examples.

        // 1. Both granularity settings encode the G flag in the top bit and the
        //    15-bit value in the remaining bits, and decode back byte-for-byte.
        for (granularity, value) in [
            (false, 0x0000_u16),
            (false, 0x1234_u16),
            (true, 0x0001_u16),
            // Maximum 15-bit value with the granularity flag set.
            (true, 0x7fff_u16),
        ] {
            let option = TcpOption::user_timeout(granularity, value);
            assert_eq!(option.kind(), TCP_OPTION_USER_TIMEOUT);
            assert_eq!(option.user_timeout_value(), Some((granularity, value)));
            assert_eq!(option.kind_class(), TcpOptionKindClass::Assigned);
            assert!(option.kind_is_assigned());

            // Encoded wire bytes: kind, length 4, then the 16-bit field with the
            // G flag in the most-significant bit.
            let encoded = option.encode().unwrap();
            let expected_field = ((granularity as u16) << 15) | (value & 0x7fff);
            assert_eq!(encoded.len(), TCP_OPTION_USER_TIMEOUT_LEN as usize);
            assert_eq!(encoded[0], TCP_OPTION_USER_TIMEOUT);
            assert_eq!(encoded[1], TCP_OPTION_USER_TIMEOUT_LEN);
            assert_eq!(&encoded[2..4], &expected_field.to_be_bytes());

            // Round-trip through decode preserves the typed representation.
            let decoded = TcpOption::decode_all(&encoded).unwrap();
            assert_eq!(decoded, vec![option.clone()]);
            assert_eq!(decoded[0].encode().unwrap(), encoded);
        }

        // 2. Only the low 15 bits of the value are wire-significant; a value with
        //    its top bit set does not leak into the Granularity flag.
        let masked = TcpOption::user_timeout(false, 0xffff);
        let masked_encoded = masked.encode().unwrap();
        assert_eq!(&masked_encoded[2..4], &0x7fff_u16.to_be_bytes());
        assert_eq!(
            TcpOption::decode_all(&masked_encoded).unwrap()[0].user_timeout_value(),
            Some((false, 0x7fff))
        );

        // 3. A full TCP segment carrying the User Timeout option compiles,
        //    decodes, exposes the typed granularity + value, and recompiles to
        //    the exact original wire bytes.
        let tcp = Tcp::new()
            .sport(33333)
            .dport(80)
            .tcp_option(TcpOption::user_timeout(true, 0x0240))
            .unwrap();
        let bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Tcp)
            / tcp
            / Raw::from("payload"))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let options = decoded.layer::<Tcp>().unwrap().parsed_options().unwrap();
        assert_eq!(
            options[0],
            TcpOption::UserTimeout {
                granularity: true,
                value: 0x0240,
            }
        );
        assert_eq!(options[0].user_timeout_value(), Some((true, 0x0240)));
        assert_eq!(decoded.compile().unwrap(), bytes);

        // 4. A User Timeout option with the wrong fixed length decodes to a
        //    structured, contextful error rather than a panic or silent blob.
        let wrong_len = TcpOption::decode_all(&[TCP_OPTION_USER_TIMEOUT, 3, 0x00]).unwrap_err();
        assert!(
            wrong_len.to_string().contains("tcp.option.user_timeout"),
            "User Timeout fixed-length error must carry context, got: {wrong_len}"
        );
        assert_eq!(TCP_OPTION_USER_TIMEOUT_LEN, 4);
    }
}

mod authentication_option {
    use super::super::{
        Tcp, TcpOption, TcpOptionKindClass, TCP_OPTION_TCP_AUTHENTICATION,
        TCP_OPTION_TCP_AUTHENTICATION_MIN_LEN,
    };
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_authentication_option_preserves_mac_bytes() {
        // RFC 5925 section 2.2: the TCP Authentication Option (TCP-AO, kind 29)
        // carries a KeyID, an RNextKeyID, and a Message Authentication Code
        // (MAC). libcrafter only preserves the wire bytes; it never computes or
        // validates the MAC (authentication is out of scope for the primitive
        // packet layer). The KeyID/RNextKeyID and MAC values below are
        // documentation-only examples.
        const KEY_ID: u8 = 0x2A;
        const RNEXT_KEY_ID: u8 = 0x05;

        // 1. Several MAC lengths encode KeyID + RNextKeyID + MAC and decode back
        //    byte-for-byte, preserving the MAC bytes verbatim.
        for mac in [
            // A 12-byte MAC, the truncation length of HMAC-SHA-1-96 / AES-128-CMAC-96.
            vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            ],
            // A single MAC byte.
            vec![0xFF],
            // The minimum (empty) MAC: the 4-byte option header alone.
            Vec::new(),
        ] {
            let option = TcpOption::tcp_authentication(KEY_ID, RNEXT_KEY_ID, mac.clone());
            assert_eq!(option.kind(), TCP_OPTION_TCP_AUTHENTICATION);
            assert_eq!(option.key_id(), Some(KEY_ID));
            assert_eq!(option.rnext_key_id(), Some(RNEXT_KEY_ID));
            assert_eq!(option.authentication_mac(), Some(mac.as_slice()));
            assert_eq!(
                option.tcp_authentication_value(),
                Some((KEY_ID, RNEXT_KEY_ID, mac.as_slice()))
            );
            // TCP-AO (kind 29) has a current IANA registry assignment.
            assert_eq!(option.kind_class(), TcpOptionKindClass::Assigned);
            assert!(option.kind_is_assigned());

            // Encoded wire bytes: kind, length, KeyID, RNextKeyID, then the MAC.
            let encoded = option.encode().unwrap();
            assert_eq!(encoded.len(), 4 + mac.len());
            assert_eq!(encoded[0], TCP_OPTION_TCP_AUTHENTICATION);
            assert_eq!(encoded[1] as usize, 4 + mac.len());
            assert_eq!(encoded[2], KEY_ID);
            assert_eq!(encoded[3], RNEXT_KEY_ID);
            assert_eq!(&encoded[4..], mac.as_slice());

            // Round-trip through decode preserves the typed representation and
            // the exact MAC bytes.
            let decoded = TcpOption::decode_all(&encoded).unwrap();
            assert_eq!(decoded, vec![option.clone()]);
            assert_eq!(decoded[0].authentication_mac(), Some(mac.as_slice()));
            assert_eq!(decoded[0].encode().unwrap(), encoded);
        }

        // 2. A full TCP segment carrying a TCP-AO option compiles, decodes,
        //    exposes the typed KeyID/RNextKeyID/MAC, and recompiles to the exact
        //    original wire bytes (the MAC is preserved, not recomputed).
        let mac = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x11, 0x22, 0x33,
        ];
        let tcp = Tcp::new()
            .sport(55555)
            .dport(179)
            .tcp_option(TcpOption::tcp_authentication(KEY_ID, RNEXT_KEY_ID, mac.clone()))
            .unwrap();
        let bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Tcp)
            / tcp
            / Raw::from("payload"))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let options = decoded.layer::<Tcp>().unwrap().parsed_options().unwrap();
        assert_eq!(
            options[0],
            TcpOption::AuthenticationOption {
                key_id: KEY_ID,
                rnext_key_id: RNEXT_KEY_ID,
                mac: mac.clone(),
            }
        );
        assert_eq!(options[0].authentication_mac(), Some(mac.as_slice()));
        assert_eq!(decoded.compile().unwrap(), bytes);

        // 3. A TCP-AO option shorter than the 4-byte minimum (no room for both
        //    the KeyID and RNextKeyID) decodes to a structured, contextful error
        //    rather than a panic or a silent generic blob.
        let too_short =
            TcpOption::decode_all(&[TCP_OPTION_TCP_AUTHENTICATION, 3, 0x00]).unwrap_err();
        assert!(
            too_short
                .to_string()
                .contains("tcp.option.authentication.length"),
            "TCP-AO min-length error must carry context, got: {too_short}"
        );
        assert_eq!(TCP_OPTION_TCP_AUTHENTICATION_MIN_LEN, 4);
    }
}

mod tcp_eno_option {
    use super::super::{
        Tcp, TcpOption, TcpOptionKindClass, TCP_OPTION_TCP_ENO, TCP_OPTION_TCP_ENO_MIN_LEN,
    };
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_eno_option_preserves_suboptions() {
        // RFC 8547 section 4: the TCP Encryption Negotiation Option (TCP-ENO,
        // kind 69) carries a sequence of suboption bytes after the kind/length
        // header. libcrafter only preserves the raw suboption bytes; it never
        // negotiates, parses, or validates them, and implements no TCP-ENO
        // handshake or tcpcrypt session behavior (RFC 8548) -- that is out of
        // scope for the primitive packet layer. The suboption bytes below are
        // documentation-only examples, not real negotiated specs.

        // 1. Several suboption sequences encode the option and decode back
        //    byte-for-byte, preserving the suboption bytes verbatim.
        for suboptions in [
            // A couple of global-byte suboptions (the high bit / byte values
            // here are illustrative only).
            vec![0x01u8, 0x02, 0x21, 0x22],
            // A single suboption byte.
            vec![0xA5u8],
            // The minimum (empty) suboption sequence: the 2-byte option header
            // alone.
            Vec::new(),
        ] {
            let option = TcpOption::tcp_eno(suboptions.clone());
            assert_eq!(option.kind(), TCP_OPTION_TCP_ENO);
            assert_eq!(option.tcp_eno_suboptions(), Some(suboptions.as_slice()));
            // TCP-ENO (kind 69) has a current IANA registry assignment.
            assert_eq!(option.kind_class(), TcpOptionKindClass::Assigned);
            assert!(option.kind_is_assigned());
            assert!(!option.kind_is_experimental());

            // Encoded wire bytes: kind, length, then the suboption sequence.
            let encoded = option.encode().unwrap();
            assert_eq!(encoded.len(), 2 + suboptions.len());
            assert_eq!(encoded[0], TCP_OPTION_TCP_ENO);
            assert_eq!(encoded[1] as usize, 2 + suboptions.len());
            assert_eq!(&encoded[2..], suboptions.as_slice());

            // Round-trip through decode preserves the typed representation and
            // the exact suboption bytes.
            let decoded = TcpOption::decode_all(&encoded).unwrap();
            assert_eq!(decoded, vec![option.clone()]);
            assert_eq!(decoded[0].tcp_eno_suboptions(), Some(suboptions.as_slice()));
            assert_eq!(decoded[0].encode().unwrap(), encoded);
        }

        // 2. A non-TCP-ENO option returns None from the suboptions accessor.
        assert_eq!(TcpOption::mss(1460).tcp_eno_suboptions(), None);

        // 3. A full TCP segment carrying a TCP-ENO option compiles, decodes,
        //    exposes the typed suboption bytes, and recompiles to the exact
        //    original wire bytes (the suboptions are preserved, not negotiated).
        let suboptions = vec![0x00u8, 0x01, 0x82, 0x83];
        let tcp = Tcp::new()
            .sport(45678)
            .dport(443)
            .tcp_option(TcpOption::tcp_eno(suboptions.clone()))
            .unwrap();
        let bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Tcp)
            / tcp
            / Raw::from("payload"))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let options = decoded.layer::<Tcp>().unwrap().parsed_options().unwrap();
        assert_eq!(
            options[0],
            TcpOption::TcpEno {
                suboptions: suboptions.clone(),
            }
        );
        assert_eq!(options[0].tcp_eno_suboptions(), Some(suboptions.as_slice()));
        assert_eq!(decoded.compile().unwrap(), bytes);

        // 4. A TCP-ENO option shorter than the 2-byte minimum decodes to a
        //    structured, contextful error rather than a panic or a silent blob.
        //    (A standalone kind byte with no length byte is below the minimum
        //    framing.)
        let too_short = TcpOption::decode_all(&[TCP_OPTION_TCP_ENO, 1]).unwrap_err();
        assert!(
            too_short.to_string().contains("tcp.option.length"),
            "TCP-ENO underflow error must carry context, got: {too_short}"
        );
        assert_eq!(TCP_OPTION_TCP_ENO_MIN_LEN, 2);
    }
}

mod legacy_security_options {
    use super::super::{Tcp, TcpOption, TcpOptionKindClass, TCP_OPTION_MD5_SIGNATURE};
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_legacy_security_options_preserve_bytes() {
        // RFC 2385 defines the legacy TCP MD5 Signature option (kind 19): a
        // fixed 18-byte option carrying a 16-byte MD5 digest. It was obsoleted by
        // RFC 5925 (TCP-AO, kind 29) but still holds an IANA registry name.
        // `crafter` preserves and classifies the option bytes; it implements no
        // signing, key management, or signature validation. The digest bytes
        // below are an arbitrary documentation-only example, never a real MD5.
        assert_eq!(TCP_OPTION_MD5_SIGNATURE, 19);

        // An arbitrary 16-byte "signature" that `crafter` must round-trip
        // verbatim without interpreting or recomputing it.
        let signature: Vec<u8> = (0u8..16).map(|i| i.wrapping_mul(17).wrapping_add(3)).collect();

        // 1. The MD5 option is represented as a byte-preserving Generic option
        //    (kind 19, no typed variant), and decoding the wire bytes yields an
        //    inspectable option that exposes the signature bytes verbatim.
        let option = TcpOption::generic(TCP_OPTION_MD5_SIGNATURE, signature.clone());
        assert_eq!(option.kind(), TCP_OPTION_MD5_SIGNATURE);
        assert_eq!(option.generic_kind(), Some(TCP_OPTION_MD5_SIGNATURE));
        assert_eq!(option.generic_data(), Some(signature.as_slice()));
        // The legacy MD5 kind still has an IANA registry assignment, so it must
        // not be reported as Unassigned.
        assert_eq!(option.kind_class(), TcpOptionKindClass::Assigned);
        assert!(option.kind_is_assigned());
        assert!(!option.kind_is_experimental());

        // Wire bytes: kind, length (18 = 2 header + 16 signature), then the
        // signature, preserved exactly.
        let encoded = option.encode().unwrap();
        assert_eq!(encoded.len(), 18);
        assert_eq!(encoded[0], TCP_OPTION_MD5_SIGNATURE);
        assert_eq!(encoded[1], 18);
        assert_eq!(&encoded[2..], signature.as_slice());

        // Decoding the raw option bytes produces an inspectable, byte-preserving
        // representation that recompiles to the identical bytes.
        let decoded = TcpOption::decode_all(&encoded).unwrap();
        assert_eq!(decoded, vec![option.clone()]);
        assert_eq!(decoded[0].generic_data(), Some(signature.as_slice()));
        assert_eq!(decoded[0].encode().unwrap(), encoded);

        // 2. A full TCP segment carrying the legacy MD5 option compiles, decodes
        //    through the standard packet entrypoints, exposes the signature bytes
        //    verbatim, and recompiles to the exact original wire bytes (the
        //    signature is preserved, never recomputed or validated).
        let tcp = Tcp::new()
            .sport(50000)
            .dport(179)
            .tcp_option(TcpOption::generic(TCP_OPTION_MD5_SIGNATURE, signature.clone()))
            .unwrap();
        let bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Tcp)
            / tcp
            / Raw::from("payload"))
        .compile()
        .unwrap();

        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let options = packet.layer::<Tcp>().unwrap().parsed_options().unwrap();
        assert_eq!(
            options[0],
            TcpOption::Generic {
                kind: TCP_OPTION_MD5_SIGNATURE,
                data: signature.clone(),
            }
        );
        assert_eq!(options[0].generic_data(), Some(signature.as_slice()));
        assert_eq!(packet.compile().unwrap(), bytes);
    }
}

mod accurate_ecn_options {
    use super::super::{
        Tcp, TcpOption, TcpOptionKindClass, TCP_OPTION_ACCURATE_ECN_MIN_LEN,
        TCP_OPTION_ACCURATE_ECN_ORDER_0, TCP_OPTION_ACCURATE_ECN_ORDER_1,
    };
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_accurate_ecn_options_roundtrip() {
        // RFC 9768 section 3.2.3.3: the Accurate ECN (AccECN) option carries zero
        // to three 24-bit ECN byte counters after the kind/length header. Two
        // option kinds -- AccECN0 (172) and AccECN1 (174) -- encode the same
        // counters in a different ORDER so an endpoint can hedge against
        // middleboxes that zero specific counter positions. libcrafter preserves
        // the order (the kind) and the raw counter bytes verbatim; it never parses
        // the counters and implements no AccECN feedback or congestion-control
        // reaction -- that is out of scope for the primitive packet layer. The
        // counter bytes below are documentation-only manifest-style sample
        // encodings, not measured congestion feedback.

        // Manifest-backed sample encodings: for each AccECN order kind, several
        // counter payloads (including the empty payload, a single 24-bit counter,
        // and the full three-counter payload) round-trip byte-for-byte.
        for kind in [
            TCP_OPTION_ACCURATE_ECN_ORDER_0,
            TCP_OPTION_ACCURATE_ECN_ORDER_1,
        ] {
            for data in [
                // Empty: the 2-byte option header alone (no counter fields).
                Vec::new(),
                // One 24-bit ECN byte counter (illustrative value).
                vec![0x00u8, 0x12, 0x34],
                // Two 24-bit counters.
                vec![0x00u8, 0x12, 0x34, 0x00, 0xAB, 0xCD],
                // Three 24-bit counters: the full AccECN payload (9 counter bytes).
                vec![0x01u8, 0x02, 0x03, 0x11, 0x22, 0x33, 0xFE, 0xDC, 0xBA],
            ] {
                let option = TcpOption::accurate_ecn(kind, data.clone());
                assert_eq!(option.kind(), kind);
                // The kind encodes the wire-significant counter order; both the
                // order accessor and the raw counter accessor expose it.
                assert_eq!(option.accurate_ecn_order(), Some(kind));
                assert_eq!(option.accurate_ecn_data(), Some(data.as_slice()));
                assert_eq!(option.accurate_ecn_value(), Some((kind, data.as_slice())));
                assert!(option.is_accurate_ecn());
                // AccECN kinds 172/174 have current IANA registry assignments and
                // must classify distinctly from generic private/unassigned data.
                assert_eq!(option.kind_class(), TcpOptionKindClass::Assigned);
                assert!(option.kind_is_assigned());
                assert!(!option.kind_is_experimental());

                // Encoded wire bytes: kind, length, then the order-specific
                // counter bytes preserved verbatim.
                let encoded = option.encode().unwrap();
                assert_eq!(encoded.len(), 2 + data.len());
                assert_eq!(encoded[0], kind);
                assert_eq!(encoded[1] as usize, 2 + data.len());
                assert_eq!(&encoded[2..], data.as_slice());

                // Round-trip through decode preserves the typed representation,
                // the order (kind), and the exact counter bytes.
                let decoded = TcpOption::decode_all(&encoded).unwrap();
                assert_eq!(decoded, vec![option.clone()]);
                assert_eq!(decoded[0].accurate_ecn_order(), Some(kind));
                assert_eq!(decoded[0].accurate_ecn_data(), Some(data.as_slice()));
                assert_eq!(decoded[0].encode().unwrap(), encoded);
            }
        }

        // The convenience order constructors select the matching kind.
        assert_eq!(
            TcpOption::accurate_ecn_order_0(vec![0xAAu8]).accurate_ecn_order(),
            Some(TCP_OPTION_ACCURATE_ECN_ORDER_0)
        );
        assert_eq!(
            TcpOption::accurate_ecn_order_1(vec![0xBBu8]).accurate_ecn_order(),
            Some(TCP_OPTION_ACCURATE_ECN_ORDER_1)
        );

        // AccECN0 and AccECN1 with the same counter bytes are distinct options:
        // the order (kind) is preserved, not normalized away.
        let counters = vec![0x00u8, 0x12, 0x34, 0x00, 0xAB, 0xCD];
        let order0 = TcpOption::accurate_ecn_order_0(counters.clone());
        let order1 = TcpOption::accurate_ecn_order_1(counters.clone());
        assert_ne!(order0, order1);
        assert_ne!(order0.encode().unwrap(), order1.encode().unwrap());

        // A non-AccECN option returns None from the AccECN accessors.
        assert_eq!(TcpOption::mss(1460).accurate_ecn_order(), None);
        assert_eq!(TcpOption::mss(1460).accurate_ecn_data(), None);
        assert_eq!(TcpOption::mss(1460).accurate_ecn_value(), None);
        assert!(!TcpOption::mss(1460).is_accurate_ecn());

        // A full TCP segment carrying an AccECN1 option compiles, decodes through
        // the standard packet entrypoints, exposes the typed order and counter
        // bytes, and recompiles to the exact original wire bytes.
        let counters = vec![0x00u8, 0x10, 0x20, 0x00, 0x30, 0x40, 0x00, 0x50, 0x60];
        let tcp = Tcp::new()
            .sport(40000)
            .dport(443)
            .tcp_option(TcpOption::accurate_ecn_order_1(counters.clone()))
            .unwrap();
        let bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Tcp)
            / tcp
            / Raw::from("payload"))
        .compile()
        .unwrap();

        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let options = packet.layer::<Tcp>().unwrap().parsed_options().unwrap();
        assert_eq!(
            options[0],
            TcpOption::AccurateEcn {
                kind: TCP_OPTION_ACCURATE_ECN_ORDER_1,
                data: counters.clone(),
            }
        );
        assert_eq!(
            options[0].accurate_ecn_order(),
            Some(TCP_OPTION_ACCURATE_ECN_ORDER_1)
        );
        assert_eq!(options[0].accurate_ecn_data(), Some(counters.as_slice()));
        assert_eq!(packet.compile().unwrap(), bytes);

        // An AccECN option shorter than the 2-byte minimum decodes to a
        // structured, contextful error rather than a panic or silent blob. (A
        // standalone kind byte with a length byte below the 2-byte framing
        // minimum is rejected by the option iterator with option-length context.)
        let too_short =
            TcpOption::decode_all(&[TCP_OPTION_ACCURATE_ECN_ORDER_0, 1]).unwrap_err();
        assert!(
            too_short.to_string().contains("tcp.option.length"),
            "AccECN underflow error must carry context, got: {too_short}"
        );
        assert_eq!(TCP_OPTION_ACCURATE_ECN_MIN_LEN, 2);
    }
}

mod mptcp_accessors {
    use super::super::{
        Tcp, TcpOption, TCP_OPTION_MPTCP, MPTCP_SUBTYPE_DSS, MPTCP_SUBTYPE_MP_CAPABLE,
        MPTCP_SUBTYPE_MP_JOIN,
    };
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_mptcp_accessors_preserve_generic_bytes() {
        // RFC 8684 section 3 packs the MPTCP subtype in the high nibble of the
        // byte that follows the option kind/length header and reserves the low
        // nibble for subtype-specific use (flags for several subtypes). libcrafter
        // preserves these bytes generically -- it never interprets a particular
        // subtype layout and implements no MPTCP state. The accessors below only
        // expose the generically meaningful slices: the subtype nibble, the flags
        // nibble, the subtype-specific payload, and the full subtype data. The
        // byte values are documentation-style sample encodings, not captured
        // MPTCP signalling.
        //
        // Each case is (subtype, flags nibble, payload-after-first-byte). The
        // first wire byte is (subtype << 4) | flags; `data` is that byte followed
        // by the payload.
        let cases: [(u8, u8, &[u8]); 3] = [
            // MP_CAPABLE with no flags and a key-shaped payload.
            (MPTCP_SUBTYPE_MP_CAPABLE, 0x0, &[0x01, 0xaa, 0xbb, 0xcc]),
            // MP_JOIN with a flags nibble set and a token-shaped payload.
            (MPTCP_SUBTYPE_MP_JOIN, 0x5, &[0xde, 0xad, 0xbe, 0xef]),
            // DSS carrying only the subtype/flags byte (empty payload).
            (MPTCP_SUBTYPE_DSS, 0x3, &[]),
        ];

        for (subtype, flags, payload) in cases {
            // `data` is the bytes after the kind/length header, including the
            // first subtype/flags byte, exactly as the generic variant stores it.
            let first = (subtype << 4) | (flags & 0x0f);
            let mut data = vec![first];
            data.extend_from_slice(payload);

            let option = TcpOption::multipath_tcp(subtype, data.clone());
            assert_eq!(option.kind(), TCP_OPTION_MPTCP);
            assert!(option.is_multipath_tcp());

            // Accessors expose the generically meaningful views.
            assert_eq!(option.mptcp_subtype(), Some(subtype));
            assert_eq!(option.mptcp_flags(), Some(flags));
            assert_eq!(option.mptcp_data(), Some(data.as_slice()));
            assert_eq!(option.mptcp_subtype_data(), Some(payload));

            // Encoded wire bytes: kind, length, the subtype/flags byte rebuilt
            // from the subtype nibble plus the preserved low nibble, then the
            // payload verbatim. The encode preserves the bytes byte-for-byte.
            let encoded = option.encode().unwrap();
            assert_eq!(encoded.len(), 2 + data.len());
            assert_eq!(encoded[0], TCP_OPTION_MPTCP);
            assert_eq!(encoded[1] as usize, 2 + data.len());
            assert_eq!(encoded[2], first);
            assert_eq!(&encoded[2..], data.as_slice());

            // Round-trip through decode preserves the typed representation, the
            // subtype, and the exact subtype data -- byte-for-byte.
            let decoded = TcpOption::decode_all(&encoded).unwrap();
            assert_eq!(decoded, vec![option.clone()]);
            assert_eq!(decoded[0].mptcp_subtype(), Some(subtype));
            assert_eq!(decoded[0].mptcp_flags(), Some(flags));
            assert_eq!(decoded[0].mptcp_data(), Some(data.as_slice()));
            assert_eq!(decoded[0].mptcp_subtype_data(), Some(payload));
            assert_eq!(decoded[0].encode().unwrap(), encoded);
        }

        // A non-MPTCP option returns None from every MPTCP accessor.
        let mss = TcpOption::mss(1460);
        assert!(!mss.is_multipath_tcp());
        assert_eq!(mss.mptcp_subtype(), None);
        assert_eq!(mss.mptcp_flags(), None);
        assert_eq!(mss.mptcp_data(), None);
        assert_eq!(mss.mptcp_subtype_data(), None);

        // A full TCP segment carrying a generic MP_JOIN MPTCP option compiles,
        // decodes through the standard packet entrypoints, exposes the typed
        // subtype/flags/payload, and recompiles to the exact original wire bytes.
        let subtype = MPTCP_SUBTYPE_MP_JOIN;
        let flags = 0x1u8;
        let payload: &[u8] = &[0x12, 0x34, 0x56, 0x78];
        let mut data = vec![(subtype << 4) | flags];
        data.extend_from_slice(payload);

        let tcp = Tcp::new()
            .sport(40000)
            .dport(443)
            .tcp_option(TcpOption::multipath_tcp(subtype, data.clone()))
            .unwrap();
        let bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Tcp)
            / tcp
            / Raw::from("payload"))
        .compile()
        .unwrap();

        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let options = packet.layer::<Tcp>().unwrap().parsed_options().unwrap();
        assert_eq!(
            options[0],
            TcpOption::MultipathTcp {
                subtype,
                data: data.clone(),
            }
        );
        assert_eq!(options[0].mptcp_subtype(), Some(subtype));
        assert_eq!(options[0].mptcp_flags(), Some(flags));
        assert_eq!(options[0].mptcp_data(), Some(data.as_slice()));
        assert_eq!(options[0].mptcp_subtype_data(), Some(payload));
        assert_eq!(packet.compile().unwrap(), bytes);
    }
}

mod fast_open_helpers {
    use super::super::{Tcp, TcpOption, TCP_OPTION_FAST_OPEN};
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_fast_open_helpers_roundtrip() {
        // RFC 7413 defines two forms of the TCP Fast Open option (kind 34):
        //   * a cookie REQUEST sent on the initial SYN, carrying an empty cookie,
        //     so the on-wire option is just the kind and length bytes (length 2);
        //   * a cookie-carrying option whose cookie is 4 to 16 bytes (even), so
        //     the on-wire length is 2 + cookie_len.
        // `crafter` preserves the cookie bytes verbatim and does not reject
        // deliberately malformed lengths, so generated tools can build both well
        // formed and intentionally invalid Fast Open options.

        // 1. The cookie-request form carries an empty cookie. Encoded it is the
        //    bare 2-byte option header (kind 34, length 2), and it reports itself
        //    as a cookie request.
        let request = TcpOption::fast_open_cookie_request();
        assert_eq!(request.kind(), TCP_OPTION_FAST_OPEN);
        assert_eq!(request.fast_open_cookie(), Some(&[][..]));
        assert!(request.is_fast_open_cookie_request());
        let encoded = request.encode().unwrap();
        assert_eq!(encoded, vec![TCP_OPTION_FAST_OPEN, 2]);
        // The request constructor is equivalent to an empty-cookie `fast_open`.
        assert_eq!(request, TcpOption::fast_open([]));
        // Round-trip through decode preserves the typed representation.
        let decoded = TcpOption::decode_all(&encoded).unwrap();
        assert_eq!(decoded, vec![request.clone()]);
        assert_eq!(decoded[0].encode().unwrap(), encoded);
        assert!(decoded[0].is_fast_open_cookie_request());

        // 2. A non-empty cookie and the maximum valid cookie length per RFC 7413
        //    (16 bytes) round-trip byte-for-byte, and are NOT classified as
        //    cookie requests.
        let max_cookie: Vec<u8> = (0u8..16).collect();
        for cookie in [vec![0xCA, 0xFE, 0xBA, 0xBE], max_cookie.clone()] {
            let option = TcpOption::fast_open(cookie.clone());
            assert_eq!(option.kind(), TCP_OPTION_FAST_OPEN);
            assert_eq!(option.fast_open_cookie(), Some(cookie.as_slice()));
            assert!(!option.is_fast_open_cookie_request());

            // Encoded length is kind + length + cookie bytes (2 + cookie_len).
            let encoded = option.encode().unwrap();
            assert_eq!(encoded.len(), 2 + cookie.len());
            assert_eq!(encoded[0], TCP_OPTION_FAST_OPEN);
            assert_eq!(encoded[1] as usize, 2 + cookie.len());
            assert_eq!(&encoded[2..], cookie.as_slice());

            // Round-trip through decode preserves the typed representation.
            let decoded = TcpOption::decode_all(&encoded).unwrap();
            assert_eq!(decoded, vec![option.clone()]);
            assert_eq!(decoded[0].encode().unwrap(), encoded);
            assert!(!decoded[0].is_fast_open_cookie_request());
        }
        // The maximum valid cookie is 16 bytes (RFC 7413 section 2).
        assert_eq!(max_cookie.len(), 16);

        // 3. Deliberately malformed cookie lengths (odd, and over the 16-byte
        //    maximum) are preserved verbatim rather than rejected, so generated
        //    tools can exercise a stack with invalid Fast Open options. The
        //    cookie bytes round-trip exactly.
        for cookie in [vec![0x01, 0x02, 0x03], (0u8..20).collect::<Vec<u8>>()] {
            let option = TcpOption::fast_open(cookie.clone());
            let encoded = option.encode().unwrap();
            assert_eq!(encoded.len(), 2 + cookie.len());
            let decoded = TcpOption::decode_all(&encoded).unwrap();
            assert_eq!(decoded[0].fast_open_cookie(), Some(cookie.as_slice()));
            assert_eq!(decoded[0].encode().unwrap(), encoded);
        }

        // 4. Full TCP segments carrying each form compile, decode, expose the
        //    typed cookie, and recompile to the exact original wire bytes.
        for option in [
            TcpOption::fast_open_cookie_request(),
            TcpOption::fast_open(max_cookie.clone()),
        ] {
            let expect_request = option.is_fast_open_cookie_request();
            let expect_cookie = option.fast_open_cookie().map(<[u8]>::to_vec);
            let tcp = Tcp::new()
                .sport(44444)
                .dport(443)
                .tcp_option(option)
                .unwrap();
            let bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Tcp)
                / tcp
                / Raw::from("payload"))
            .compile()
            .unwrap();

            let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
            let options = packet.layer::<Tcp>().unwrap().parsed_options().unwrap();
            assert_eq!(options[0].kind(), TCP_OPTION_FAST_OPEN);
            assert_eq!(
                options[0].fast_open_cookie(),
                expect_cookie.as_deref()
            );
            assert_eq!(options[0].is_fast_open_cookie_request(), expect_request);
            assert_eq!(packet.compile().unwrap(), bytes);
        }
    }
}

mod sack_dsack_accessors {
    use super::super::{TcpOption, TcpSackBlock, TCP_OPTION_SACK};

    #[test]
    fn tcp_sack_dsack_accessors() {
        // RFC 2018 defines the SACK option (kind 5) as a list of 8-byte
        // {left_edge, right_edge} blocks. RFC 2883 reuses the exact same wire
        // format for D-SACK: a D-SACK report is a reinterpretation of SACK block
        // *ordering*, where the first block reports an already-received
        // (duplicate) range. The accessors under test never change the wire
        // bytes; they only inspect the parsed block list.

        // Non-SACK options report None from every SACK accessor, so callers can
        // distinguish "not a SACK option" from "an empty SACK option".
        let not_sack = TcpOption::sack_permitted();
        assert_eq!(not_sack.sack_blocks(), None);
        assert_eq!(not_sack.sack_block_count(), None);
        assert_eq!(not_sack.first_sack_block(), None);
        assert_eq!(not_sack.remaining_sack_blocks(), None);
        assert_eq!(not_sack.is_potential_dsack_first_block(1000), None);

        // 1. One-block SACK. The single block is the first block, there are no
        //    remaining blocks, and the count is one.
        let one = TcpOption::sack(vec![TcpSackBlock::new(1000, 2000)]);
        assert_eq!(one.sack_block_count(), Some(1));
        assert_eq!(one.first_sack_block(), Some(TcpSackBlock::new(1000, 2000)));
        assert_eq!(one.remaining_sack_blocks(), Some(&[][..]));
        assert_eq!(one.sack_blocks(), Some(&[TcpSackBlock::new(1000, 2000)][..]));

        // A single block whose right edge is at or below the cumulative ACK is a
        // D-SACK report per RFC 2883 rule (1): it covers data the receiver has
        // already acknowledged.
        assert_eq!(one.is_potential_dsack_first_block(2000), Some(true));
        assert_eq!(one.is_potential_dsack_first_block(2500), Some(true));
        // A single block strictly above the cumulative ACK is an ordinary
        // RFC 2018 SACK block, not D-SACK.
        assert_eq!(one.is_potential_dsack_first_block(1000), Some(false));
        assert_eq!(one.is_potential_dsack_first_block(500), Some(false));

        // 2. Multi-block SACK. The first/remaining split is exact.
        let first = TcpSackBlock::new(1000, 1500);
        let second = TcpSackBlock::new(900, 2000);
        let third = TcpSackBlock::new(3000, 4000);
        let multi = TcpOption::sack(vec![first, second, third]);
        assert_eq!(multi.sack_block_count(), Some(3));
        assert_eq!(multi.first_sack_block(), Some(first));
        assert_eq!(multi.remaining_sack_blocks(), Some(&[second, third][..]));

        // RFC 2883 rule (2): the first block is a subset of (contained within)
        // the second block, so it reports a duplicate range even though it is
        // above the cumulative ACK. Here [1000,1500) is inside [900,2000).
        assert_eq!(multi.is_potential_dsack_first_block(500), Some(true));

        // When the first block is neither below the cumulative ACK nor a subset
        // of the second block, it is an ordinary RFC 2018 first block.
        let ordinary = TcpOption::sack(vec![
            TcpSackBlock::new(5000, 6000),
            TcpSackBlock::new(7000, 8000),
        ]);
        assert_eq!(ordinary.is_potential_dsack_first_block(4000), Some(false));
        // ...but rule (1) still fires for the same blocks once the cumulative
        // ACK advances past the first block's right edge.
        assert_eq!(ordinary.is_potential_dsack_first_block(6000), Some(true));

        // Serial-number arithmetic (RFC 1982 / RFC 9293) keeps the comparisons
        // correct across the 32-bit sequence-number wrap. A block just below the
        // wrap with a cumulative ACK just above it is still D-SACK by rule (1).
        let wrapped = TcpOption::sack(vec![TcpSackBlock::new(
            0xFFFF_F000,
            0xFFFF_FF00,
        )]);
        assert_eq!(wrapped.is_potential_dsack_first_block(0x0000_0100), Some(true));

        // 3. Malformed SACK lengths surface a structured decode error rather
        //    than panicking or silently dropping the option. A SACK payload must
        //    be one or more whole 8-byte blocks (on-wire length 2 + 8*n).
        //    Length 4 declares a SACK that cannot hold a full block.
        let short = TcpOption::decode_all(&[TCP_OPTION_SACK, 4, 0, 0])
            .expect_err("a SACK option too short for a block must not decode cleanly")
            .to_string();
        assert!(
            short.contains("tcp.option.sack"),
            "malformed SACK length must carry tcp.option.sack context, got: {short}"
        );
        // A length that is not 2 + a multiple of 8 (here 12 = 2 + 10) is also
        // rejected: 10 payload bytes are not a whole number of 8-byte blocks.
        let unaligned = [TCP_OPTION_SACK, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let unaligned_err = TcpOption::decode_all(&unaligned)
            .expect_err("a SACK option with a non-block-aligned length must not decode cleanly")
            .to_string();
        assert!(
            unaligned_err.contains("tcp.option.sack"),
            "non-block-aligned SACK length must carry tcp.option.sack context, got: {unaligned_err}"
        );
    }
}
