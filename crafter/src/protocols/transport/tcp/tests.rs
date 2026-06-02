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
