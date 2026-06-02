use std::net::Ipv4Addr;

use crafter::prelude::*;

#[test]
fn prelude_builds_and_compiles_packet() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Icmp::echo_request().id(0x4242).seq(1)
        / Raw::from("hello");

    let compiled = packet.compile()?;

    assert!(!compiled.is_empty());
    assert_eq!(compiled.as_bytes()[0] >> 4, 4);
    assert!(packet.summary().contains("Icmp(type=echo-request"));

    Ok(())
}

#[test]
fn public_module_paths_expose_representative_items() -> crafter::Result<()> {
    let packet = crafter::core::Packet::from_layer(crafter::core::Raw::from("core"));
    assert_eq!(packet.compile()?.as_bytes(), b"core");

    let pcap_header = crafter::pcap::PcapHeader::new(crafter::pcap::PcapLinkType::RawIp);
    assert_eq!(
        pcap_header.precision(),
        crafter::pcap::TimestampPrecision::Microseconds
    );

    let send_options = crafter::net::SendOptions::new()
        .iface("dry-run0")
        .network_layer()
        .dry_run();
    assert!(send_options.is_dry_run());
    assert_eq!(send_options.interface_name(), Some("dry-run0"));

    let _socket_options = crafter::net::socket::SendOptions::new().dry_run();
    let _range = crafter::net::range::Ipv4Range::parse("192.0.2.1").unwrap();
    let _batch = crafter::net::batch::BatchSendRecv::new().dry_run();
    let _matcher = crafter::net::send_recv::ReplyMatcher::from_packet(&packet);

    Ok(())
}

#[test]
fn udp_public_api_paths_are_usable() -> crafter::Result<()> {
    let prelude_udp: Udp = Udp::new().sport(1111).dport(2222);
    let core_udp = crafter::core::Udp::new().sport(3333).dport(4444);
    let root_udp = crafter::Udp::new().sport(5555).dport(6666);
    let protocols_udp = crafter::protocols::Udp::new().sport(7777).dport(8888);
    let transport_udp = crafter::protocols::transport::Udp::new()
        .sport(9999)
        .dport(10000);
    let prelude_options: UdpOptions = UdpOptions::from_bytes([UDP_OPTION_NOP]);
    let core_options = crafter::core::UdpOptions::from_bytes([UDP_OPTION_EOL]);
    let root_options = crafter::UdpOptions::from_bytes([UDP_OPTION_REQ]);
    let protocols_options = crafter::protocols::UdpOptions::from_bytes([UDP_OPTION_RES]);
    let transport_options = crafter::protocols::transport::UdpOptions::from_bytes([UDP_OPTION_MDS]);

    let prelude_packet = (prelude_udp / Raw::from("prelude")).compile()?;
    let core_packet = (core_udp / crafter::core::Raw::from("core")).compile()?;
    let root_packet = (root_udp / crafter::Raw::from("root")).compile()?;
    let protocols_packet =
        (protocols_udp / crafter::protocols::Raw::from("protocols")).compile()?;
    let transport_packet =
        (transport_udp / crafter::protocols::Raw::from("transport")).compile()?;

    assert_eq!(&prelude_packet.as_bytes()[0..2], &1111u16.to_be_bytes());
    assert_eq!(&prelude_packet.as_bytes()[2..4], &2222u16.to_be_bytes());
    assert_eq!(&core_packet.as_bytes()[0..2], &3333u16.to_be_bytes());
    assert_eq!(&core_packet.as_bytes()[2..4], &4444u16.to_be_bytes());
    assert_eq!(&root_packet.as_bytes()[0..2], &5555u16.to_be_bytes());
    assert_eq!(&root_packet.as_bytes()[2..4], &6666u16.to_be_bytes());
    assert_eq!(&protocols_packet.as_bytes()[0..2], &7777u16.to_be_bytes());
    assert_eq!(&protocols_packet.as_bytes()[2..4], &8888u16.to_be_bytes());
    assert_eq!(&transport_packet.as_bytes()[0..2], &9999u16.to_be_bytes());
    assert_eq!(&transport_packet.as_bytes()[2..4], &10000u16.to_be_bytes());
    assert_eq!(prelude_options.as_bytes(), &[UDP_OPTION_NOP]);
    assert_eq!(core_options.as_bytes(), &[UDP_OPTION_EOL]);
    assert_eq!(root_options.as_bytes(), &[UDP_OPTION_REQ]);
    assert_eq!(protocols_options.as_bytes(), &[UDP_OPTION_RES]);
    assert_eq!(transport_options.as_bytes(), &[UDP_OPTION_MDS]);

    Ok(())
}

#[test]
fn udp_option_constants_and_statuses_are_public() {
    let prelude_checksum_status: UdpChecksumStatus = UdpChecksumStatus::NotChecked;
    let prelude_option_status: UdpOptionStatus = UdpOptionStatus::NoSurplus;
    let core_checksum_status: crafter::core::UdpChecksumStatus =
        crafter::core::UdpChecksumStatus::Valid;
    let root_option_status: crafter::UdpOptionStatus = crafter::UdpOptionStatus::Unsupported;
    let protocols_checksum_status: crafter::protocols::UdpChecksumStatus =
        crafter::protocols::UdpChecksumStatus::Ipv4NoChecksum;
    let transport_option_status: crafter::protocols::transport::UdpOptionStatus =
        crafter::protocols::transport::UdpOptionStatus::OptionChecksumInvalid;

    assert_eq!(UDP_HEADER_LEN, 8);
    assert_eq!(crafter::core::UDP_OPTION_EOL, 0);
    assert_eq!(crafter::UDP_OPTION_NOP, 1);
    assert_eq!(crafter::UDP_OPTION_APC, 2);
    assert_eq!(crafter::protocols::UDP_OPTION_FRAG, 3);
    assert_eq!(crafter::protocols::transport::UDP_OPTION_MDS, 4);
    assert_eq!(crafter::UDP_OPTION_MRDS, 5);
    assert_eq!(crafter::UDP_OPTION_REQ, 6);
    assert_eq!(crafter::UDP_OPTION_RES, 7);
    assert_eq!(crafter::protocols::transport::UDP_OPTION_TIME, 8);
    assert_eq!(crafter::UDP_OPTION_AUTH, 9);
    assert_eq!(crafter::UDP_OPTION_UNASSIGNED_SAFE_START, 10);
    assert_eq!(crafter::UDP_OPTION_UNASSIGNED_SAFE_END, 126);
    assert_eq!(crafter::UDP_OPTION_EXP, 127);
    assert_eq!(crafter::UDP_OPTION_RESERVED_SAFE_START, 128);
    assert_eq!(crafter::UDP_OPTION_RESERVED_SAFE_END, 191);
    assert_eq!(crafter::UDP_OPTION_UCMP, 192);
    assert_eq!(crafter::UDP_OPTION_UENC, 193);
    assert_eq!(crafter::UDP_OPTION_UNASSIGNED_UNSAFE_START, 194);
    assert_eq!(crafter::UDP_OPTION_UNASSIGNED_UNSAFE_END, 253);
    assert_eq!(crafter::UDP_OPTION_UEXP, 254);
    assert_eq!(crafter::UDP_OPTION_RESERVED_UNSAFE, 255);

    assert_eq!(prelude_checksum_status, UdpChecksumStatus::NotChecked);
    assert_eq!(prelude_option_status, UdpOptionStatus::NoSurplus);
    assert_eq!(
        core_checksum_status,
        crafter::core::UdpChecksumStatus::Valid
    );
    assert_eq!(root_option_status, crafter::UdpOptionStatus::Unsupported);
    assert_eq!(
        protocols_checksum_status,
        crafter::protocols::UdpChecksumStatus::Ipv4NoChecksum
    );
    assert_eq!(
        transport_option_status,
        crafter::protocols::transport::UdpOptionStatus::OptionChecksumInvalid
    );
    assert_eq!(
        udp_option_kind_class(UDP_OPTION_TIME),
        UdpOptionKindClass::KnownSafe
    );
    assert_eq!(
        crafter::core::udp_option_kind_class(crafter::core::UDP_OPTION_UEXP),
        crafter::core::UdpOptionKindClass::ExperimentalUnsafe
    );
    assert_eq!(
        crafter::protocols::udp_option_kind_class(crafter::protocols::UDP_OPTION_AUTH),
        crafter::protocols::UdpOptionKindClass::ReservedSafe
    );
    assert!(crafter::udp_option_kind_is_unsafe(crafter::UDP_OPTION_UEXP));
    assert!(crafter::protocols::udp_option_kind_is_unsupported(
        crafter::protocols::UDP_OPTION_FRAG
    ));
    assert!(crafter::protocols::transport::udp_option_kind_is_unsafe(
        crafter::protocols::transport::UDP_OPTION_RESERVED_UNSAFE
    ));
}

#[test]
fn udp_option_enum_and_iterator_public_paths_are_usable() -> crafter::Result<()> {
    let prelude_option: UdpOption = UdpOption::no_operation();
    let core_option = crafter::core::UdpOption::maximum_datagram_size(0x05b4);
    let root_option = crafter::UdpOption::extended_generic(crafter::UDP_OPTION_EXP, [0x12, 0x34]);
    let iter = crafter::protocols::UdpOptionIter::new(&[
        crafter::UDP_OPTION_NOP,
        crafter::UDP_OPTION_MDS,
        4,
        0x05,
        0xb4,
    ]);
    let transport_options = crafter::protocols::transport::UdpOptions::from_options(vec![
        prelude_option.clone(),
        core_option.clone(),
        root_option.clone(),
    ])?;

    assert_eq!(prelude_option.kind(), crafter::UDP_OPTION_NOP);
    assert_eq!(
        core_option.encode()?,
        vec![crafter::UDP_OPTION_MDS, 4, 0x05, 0xb4]
    );
    assert_eq!(
        root_option.encode()?,
        vec![crafter::UDP_OPTION_EXP, 255, 0, 6, 0x12, 0x34]
    );
    assert_eq!(
        iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![prelude_option, core_option.clone()]
    );
    assert_eq!(transport_options.status(), UdpOptionStatus::Valid);
    assert_eq!(core_option.maximum_datagram_size_value(), Some(0x05b4));

    Ok(())
}

#[test]
fn udp_options_prelude_typed_packet_builds_and_inspects() -> crafter::Result<()> {
    let options = UdpOptions::new()
        .udp_option(UdpOption::maximum_datagram_size(1200))?
        .udp_option(UdpOption::maximum_reassembled_datagram_size(9000, 8))?
        .udp_option(UdpOption::echo_request(0x0102_0304))?
        .udp_option(UdpOption::echo_response(0x0506_0708))?
        .udp_option(UdpOption::timestamp(0x1122_3344, 0x5566_7788))?
        .udp_option(UdpOption::experimental(0x1234, [0xaa, 0xbb]))?
        .udp_option(UdpOption::unsafe_experimental(0x5678, [0xcc]))?;
    let parsed = options.options();
    let checksum_status: UdpChecksumStatus = UdpChecksumStatus::Valid;

    assert_eq!(options.status(), UdpOptionStatus::Valid);
    assert_eq!(options.option_checksum_value(), None);
    assert_eq!(options.alignment_bytes(), None);
    assert_eq!(
        options.option_iter().collect::<crafter::Result<Vec<_>>>()?,
        parsed
    );
    assert_eq!(checksum_status, UdpChecksumStatus::Valid);
    assert_eq!(parsed[0].maximum_datagram_size_value(), Some(1200));
    assert_eq!(
        parsed[1].maximum_reassembled_datagram_size_values(),
        Some((9000, 8))
    );
    assert_eq!(parsed[2].echo_request_token(), Some(0x0102_0304));
    assert_eq!(parsed[3].echo_response_token(), Some(0x0506_0708));
    assert_eq!(
        parsed[4].timestamp_values(),
        Some((0x1122_3344, 0x5566_7788))
    );
    assert_eq!(parsed[5].experiment_id(), Some(0x1234));
    assert_eq!(parsed[5].experiment_data(), Some(&[0xaa, 0xbb][..]));
    assert_eq!(parsed[6].experiment_id(), Some(0x5678));
    assert_eq!(parsed[6].experiment_data(), Some(&[0xcc][..]));
    assert_eq!(
        parsed[6].kind_class(),
        UdpOptionKindClass::ExperimentalUnsafe
    );
    assert!(parsed[6].is_unsafe());
    assert!(!parsed[6].is_unsupported());

    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 30))
        .dst(Ipv4Addr::new(198, 51, 100, 40))
        / Udp::new().sport(53003).dport(9998)
        / Raw::from("data")
        / options;

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let udp = decoded.layer::<Udp>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();
    let decoded_options = decoded.layer::<UdpOptions>().unwrap();

    assert_eq!(udp.source_port_value(), 53003);
    assert_eq!(udp.destination_port_value(), 9998);
    assert_eq!(udp.length_value(), Some((UDP_HEADER_LEN + 4) as u16));
    assert_eq!(raw.as_bytes(), b"data");
    assert_eq!(decoded_options.status(), UdpOptionStatus::Valid);
    assert!(decoded_options.option_checksum_value().is_some());
    assert_eq!(
        decoded_options.options()[2].echo_request_token(),
        Some(0x0102_0304)
    );
    assert_eq!(
        decoded_options.options()[4].timestamp_values(),
        Some((0x1122_3344, 0x5566_7788))
    );

    Ok(())
}

#[test]
fn tcp_public_api_paths_are_usable() -> crafter::Result<()> {
    let prelude_tcp: Tcp = Tcp::new().sport(1111).dport(2222);
    let core_tcp = crafter::core::Tcp::new().sport(3333).dport(4444);
    let root_tcp = crafter::Tcp::new().sport(5555).dport(6666);
    let protocols_tcp = crafter::protocols::Tcp::new().sport(7777).dport(8888);
    let transport_tcp = crafter::protocols::transport::Tcp::new()
        .sport(9999)
        .dport(10000);

    let prelude_packet = (prelude_tcp / Raw::from("prelude")).compile()?;
    let core_packet = (core_tcp / crafter::core::Raw::from("core")).compile()?;
    let root_packet = (root_tcp / crafter::Raw::from("root")).compile()?;
    let protocols_packet =
        (protocols_tcp / crafter::protocols::Raw::from("protocols")).compile()?;
    let transport_packet =
        (transport_tcp / crafter::protocols::Raw::from("transport")).compile()?;

    assert_eq!(&prelude_packet.as_bytes()[0..2], &1111u16.to_be_bytes());
    assert_eq!(&prelude_packet.as_bytes()[2..4], &2222u16.to_be_bytes());
    assert_eq!(&core_packet.as_bytes()[0..2], &3333u16.to_be_bytes());
    assert_eq!(&core_packet.as_bytes()[2..4], &4444u16.to_be_bytes());
    assert_eq!(&root_packet.as_bytes()[0..2], &5555u16.to_be_bytes());
    assert_eq!(&root_packet.as_bytes()[2..4], &6666u16.to_be_bytes());
    assert_eq!(&protocols_packet.as_bytes()[0..2], &7777u16.to_be_bytes());
    assert_eq!(&protocols_packet.as_bytes()[2..4], &8888u16.to_be_bytes());
    assert_eq!(&transport_packet.as_bytes()[0..2], &9999u16.to_be_bytes());
    assert_eq!(&transport_packet.as_bytes()[2..4], &10000u16.to_be_bytes());

    Ok(())
}

#[test]
fn tcp_option_constants_and_types_are_public() -> crafter::Result<()> {
    // TCP option/types reach through prelude, core, root, protocols, and
    // protocols::transport, mirroring the UDP public-api coverage.
    let prelude_option: TcpOption = TcpOption::maximum_segment_size(1460);
    let core_option = crafter::core::TcpOption::window_scale(7);
    let root_option = crafter::TcpOption::sack_permitted();
    let protocols_option = crafter::protocols::TcpOption::timestamp(0x1122_3344, 0x5566_7788);
    let transport_option = crafter::protocols::transport::TcpOption::generic(0xfe, [0xaa, 0xbb]);

    let prelude_sack: TcpSackBlock = TcpSackBlock::new(100, 200);
    let core_sack = crafter::core::TcpSackBlock::new(300, 400);
    let root_sack = crafter::TcpSackBlock::new(500, 600);
    let protocols_sack = crafter::protocols::TcpSackBlock::new(700, 800);
    let transport_sack = crafter::protocols::transport::TcpSackBlock::new(900, 1000);

    let prelude_edo: TcpExtendedDataOffset = TcpExtendedDataOffset::Request;
    let core_edo = crafter::core::TcpExtendedDataOffset::HeaderLength { header_length: 16 };
    let root_edo = crafter::TcpExtendedDataOffset::HeaderAndSegmentLength {
        header_length: 16,
        segment_length: 1200,
    };
    let protocols_edo = crafter::protocols::TcpExtendedDataOffset::Request;
    let transport_edo = crafter::protocols::transport::TcpExtendedDataOffset::Request;

    let prelude_iter: TcpOptionIter = TcpOptionIter::new(&[TCP_OPTION_NOP, TCP_OPTION_EOL]);
    let core_iter = crafter::core::TcpOptionIter::new(&[crafter::core::TCP_OPTION_NOP]);
    let root_iter = crafter::TcpOptionIter::new(&[crafter::TCP_OPTION_NOP]);
    let protocols_iter =
        crafter::protocols::TcpOptionIter::new(&[crafter::protocols::TCP_OPTION_NOP]);
    let transport_iter = crafter::protocols::transport::TcpOptionIter::new(&[
        crafter::protocols::transport::TCP_OPTION_NOP,
    ]);

    // Existing TCP option constants through the same public paths.
    assert_eq!(TCP_OPTION_EOL, 0);
    assert_eq!(crafter::core::TCP_OPTION_NOP, 1);
    assert_eq!(crafter::TCP_OPTION_MSS, 2);
    assert_eq!(crafter::protocols::TCP_OPTION_WINDOW_SCALE, 3);
    assert_eq!(crafter::protocols::transport::TCP_OPTION_SACK_PERMITTED, 4);
    assert_eq!(crafter::TCP_OPTION_SACK, 5);
    assert_eq!(crafter::core::TCP_OPTION_TIMESTAMP, 8);
    assert_eq!(crafter::protocols::TCP_OPTION_MPTCP, 30);
    assert_eq!(crafter::protocols::transport::TCP_OPTION_FAST_OPEN, 34);
    assert_eq!(crafter::TCP_OPTION_EDO, 237);
    assert_eq!(crafter::core::TCP_EDO_REQUEST_LEN, 2);
    assert_eq!(crafter::protocols::TCP_EDO_HEADER_LEN, 4);
    assert_eq!(crafter::protocols::transport::TCP_EDO_HEADER_AND_SEGMENT_LEN, 6);

    // Existing TCP flag constants through the same public paths.
    assert_eq!(TCP_FLAG_FIN, 0x001);
    assert_eq!(crafter::core::TCP_FLAG_SYN, 0x002);
    assert_eq!(crafter::TCP_FLAG_RST, 0x004);
    assert_eq!(crafter::protocols::TCP_FLAG_PSH, 0x008);
    assert_eq!(crafter::protocols::transport::TCP_FLAG_ACK, 0x010);
    assert_eq!(crafter::TCP_FLAG_URG, 0x020);
    assert_eq!(crafter::core::TCP_FLAG_ECE, 0x040);
    assert_eq!(crafter::protocols::TCP_FLAG_CWR, 0x080);

    // TCP_FLAG_NS stays as a compatibility alias for the 0x100 control bit.
    assert_eq!(TCP_FLAG_NS, 0x100);
    assert_eq!(crafter::core::TCP_FLAG_NS, 0x100);
    assert_eq!(crafter::TCP_FLAG_NS, 0x100);
    assert_eq!(crafter::protocols::TCP_FLAG_NS, 0x100);
    assert_eq!(crafter::protocols::transport::TCP_FLAG_NS, 0x100);

    // The new TCP_FLAG_AE compatibility alias shares the bit with TCP_FLAG_NS.
    // It is exported through protocols::transport.
    assert_eq!(crafter::protocols::transport::TCP_FLAG_AE, 0x100);
    assert_eq!(
        crafter::protocols::transport::TCP_FLAG_AE,
        crafter::protocols::transport::TCP_FLAG_NS
    );

    assert_eq!(prelude_option.kind(), TCP_OPTION_MSS);
    assert_eq!(core_option.kind(), crafter::core::TCP_OPTION_WINDOW_SCALE);
    assert_eq!(root_option.kind(), crafter::TCP_OPTION_SACK_PERMITTED);
    assert_eq!(protocols_option.kind(), crafter::protocols::TCP_OPTION_TIMESTAMP);
    assert_eq!(transport_option.kind(), 0xfe);
    assert_eq!(transport_option.encode()?, vec![0xfe, 4, 0xaa, 0xbb]);

    assert_eq!(prelude_sack, TcpSackBlock::new(100, 200));
    assert_eq!(core_sack.left_edge, 300);
    assert_eq!(root_sack.right_edge, 600);
    assert_eq!(protocols_sack.left_edge, 700);
    assert_eq!(transport_sack.right_edge, 1000);

    assert_eq!(prelude_edo.option_len(), crafter::TCP_EDO_REQUEST_LEN);
    assert_eq!(core_edo.option_len(), crafter::TCP_EDO_HEADER_LEN);
    assert_eq!(
        root_edo.option_len(),
        crafter::TCP_EDO_HEADER_AND_SEGMENT_LEN
    );
    assert_eq!(protocols_edo, TcpExtendedDataOffset::Request);
    assert_eq!(transport_edo, TcpExtendedDataOffset::Request);

    assert_eq!(
        prelude_iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![TcpOption::NoOperation, TcpOption::EndOfList]
    );
    assert_eq!(
        core_iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![TcpOption::NoOperation]
    );
    assert_eq!(
        root_iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![TcpOption::NoOperation]
    );
    assert_eq!(
        protocols_iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![TcpOption::NoOperation]
    );
    assert_eq!(
        transport_iter.collect::<crafter::Result<Vec<_>>>()?,
        vec![TcpOption::NoOperation]
    );

    // The Tcp layer accepts the option/flag constants and round-trips them.
    let mss = TcpOption::maximum_segment_size(1460).encode()?;
    let tcp: Tcp = Tcp::new()
        .sport(40000)
        .dport(80)
        .flag(TCP_FLAG_SYN, true)
        .flag(TCP_FLAG_NS, true)
        .option(&mss);
    assert_eq!(tcp.flags_value() & TCP_FLAG_SYN, TCP_FLAG_SYN);
    assert_eq!(tcp.flags_value() & TCP_FLAG_NS, TCP_FLAG_NS);
    assert_eq!(
        tcp.option_iter().collect::<crafter::Result<Vec<_>>>()?,
        vec![TcpOption::maximum_segment_size(1460)]
    );

    Ok(())
}

#[test]
fn udp_dhcp_helpers_compile_expected_ports() -> crafter::Result<()> {
    let client = (Udp::dhcp_client() / Raw::from("discover")).compile()?;
    let server = (Udp::dhcp_server() / Raw::from("offer")).compile()?;

    assert_eq!(&client.as_bytes()[0..2], &68u16.to_be_bytes());
    assert_eq!(&client.as_bytes()[2..4], &67u16.to_be_bytes());
    assert_eq!(&server.as_bytes()[0..2], &67u16.to_be_bytes());
    assert_eq!(&server.as_bytes()[2..4], &68u16.to_be_bytes());

    Ok(())
}

#[test]
fn udp_dns_packet_compiles_and_decodes() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 53))
        .id(0x1237)
        .ttl(61)
        / Udp::new().sport(53001).dport(DNS_PORT)
        / Dns::new()
            .id(0xbeef)
            .question(DnsQuestion::new("example.com.", DNS_TYPE_A));

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let udp = decoded.layer::<Udp>().unwrap();
    let dns = decoded.layer::<Dns>().unwrap();

    assert_eq!(udp.source_port_value(), 53001);
    assert_eq!(udp.destination_port_value(), DNS_PORT);
    assert_eq!(dns.id_value(), 0xbeef);
    assert_eq!(dns.questions()[0].name(), "example.com.");
    assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_A);

    Ok(())
}

#[test]
fn udp_raw_payload_packet_compiles_and_decodes() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 20))
        .dst(Ipv4Addr::new(198, 51, 100, 30))
        / Udp::new().sport(53002).dport(9999)
        / Raw::from("payload");

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let udp = decoded.layer::<Udp>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();

    assert_eq!(udp.source_port_value(), 53002);
    assert_eq!(udp.destination_port_value(), 9999);
    assert_eq!(raw.as_bytes(), b"payload");

    Ok(())
}
