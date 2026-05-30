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
