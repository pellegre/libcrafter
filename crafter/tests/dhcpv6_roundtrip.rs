#[macro_use]
mod support;

use std::net::Ipv6Addr;

use crafter::prelude::*;
use crafter::protocols::dhcp::{
    Dhcpv6, Dhcpv6IaAddr, Dhcpv6IaNa, Dhcpv6IaPd, Dhcpv6IaPrefix, Dhcpv6MessageType, Dhcpv6Option,
    Dhcpv6StatusCode,
};

fn doc_addr(host: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, host)
}

fn doc_prefix(subnet: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, subnet, 0, 0, 0, 0, 0)
}

fn client_duid() -> [u8; 10] {
    [0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x5e, 0x00, 0x00, 0x01]
}

fn server_duid() -> [u8; 10] {
    [0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x5e, 0x00, 0x00, 0x02]
}

fn packet(src: Ipv6Addr, dst: Ipv6Addr, udp: Udp, dhcpv6: Dhcpv6) -> Packet {
    Ipv6::new().src(src).dst(dst) / udp / dhcpv6
}

fn assert_packet_roundtrip(name: &str, packet: Packet) -> crafter::Result<Packet> {
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())?;
    let recompiled = decoded.compile()?;
    assert_eq!(
        recompiled.as_bytes(),
        compiled.as_bytes(),
        "{name} did not preserve bytes across compile/decode/compile"
    );
    Ok(decoded)
}

fn assert_fixture_roundtrip(name: &str, hex: &str) -> crafter::Result<Packet> {
    let bytes = parse_hex(name, hex);
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, &bytes)?;
    let recompiled = decoded.compile()?;
    assert_eq!(
        recompiled.as_bytes(),
        bytes.as_slice(),
        "{name} fixture did not preserve bytes across decode/compile"
    );
    Ok(decoded)
}

fn parse_hex(name: &str, input: &str) -> Vec<u8> {
    let mut digits = String::new();
    for line in input.lines() {
        let data = line.split('#').next().unwrap_or_default();
        digits.extend(data.chars().filter(|ch| !ch.is_whitespace()));
    }
    assert!(
        digits.len() % 2 == 0,
        "{name} fixture has an odd number of hex digits"
    );

    digits
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = core::str::from_utf8(chunk)
                .unwrap_or_else(|_| panic!("{name} fixture contains non-UTF8 hex"));
            u8::from_str_radix(byte, 16)
                .unwrap_or_else(|_| panic!("{name} fixture has invalid hex byte {byte}"))
        })
        .collect()
}

#[test]
fn dhcpv6_client_server_messages_compile_decode_compile() -> crafter::Result<()> {
    let client = client_duid();
    let server = server_duid();
    let client_addr = doc_addr(0x0010);
    let server_addr = doc_addr(0x0001);
    let cases = [
        (
            "solicit",
            packet(
                client_addr,
                server_addr,
                Udp::dhcpv6_client(),
                Dhcpv6::solicit(0x010203)
                    .client_id(client)
                    .oro([23u16, 24u16])
                    .elapsed_time(1),
            ),
            Dhcpv6MessageType::Solicit,
            0x010203,
        ),
        (
            "advertise",
            packet(
                server_addr,
                client_addr,
                Udp::dhcpv6_server(),
                Dhcpv6::advertise(0x010203)
                    .client_id(client)
                    .server_id(server)
                    .preference(100),
            ),
            Dhcpv6MessageType::Advertise,
            0x010203,
        ),
        (
            "request",
            packet(
                client_addr,
                server_addr,
                Udp::dhcpv6_client(),
                Dhcpv6::request(0x020304)
                    .client_id(client)
                    .server_id(server)
                    .oro([23u16, 24u16]),
            ),
            Dhcpv6MessageType::Request,
            0x020304,
        ),
        (
            "reply",
            packet(
                server_addr,
                client_addr,
                Udp::dhcpv6_server(),
                Dhcpv6::reply(0x020304)
                    .client_id(client)
                    .server_id(server)
                    .status(Dhcpv6StatusCode::Success),
            ),
            Dhcpv6MessageType::Reply,
            0x020304,
        ),
        (
            "information-request",
            packet(
                client_addr,
                server_addr,
                Udp::dhcpv6_client(),
                Dhcpv6::information_request(0x030405)
                    .client_id(client)
                    .oro([23u16, 24u16])
                    .elapsed_time(2),
            ),
            Dhcpv6MessageType::InformationRequest,
            0x030405,
        ),
    ];

    for (name, packet, expected_type, expected_xid) in cases {
        let decoded = assert_packet_roundtrip(name, packet)?;
        let dhcpv6 = decoded
            .layer::<Dhcpv6>()
            .unwrap_or_else(|| panic!("{name} should decode to a DHCPv6 layer"));
        assert_eq!(dhcpv6.message_type_value(), expected_type, "{name}");
        assert_eq!(dhcpv6.transaction_id_value(), expected_xid, "{name}");
    }

    Ok(())
}

#[test]
fn dhcpv6_checked_in_fixtures_roundtrip_exactly() -> crafter::Result<()> {
    let cases = [
        (
            "solicit",
            fixture_str!("bytes/ipv6-udp-dhcpv6-solicit.hex"),
            Dhcpv6MessageType::Solicit,
        ),
        (
            "advertise",
            fixture_str!("bytes/ipv6-udp-dhcpv6-advertise.hex"),
            Dhcpv6MessageType::Advertise,
        ),
        (
            "request",
            fixture_str!("bytes/ipv6-udp-dhcpv6-request.hex"),
            Dhcpv6MessageType::Request,
        ),
        (
            "reply",
            fixture_str!("bytes/ipv6-udp-dhcpv6-reply.hex"),
            Dhcpv6MessageType::Reply,
        ),
        (
            "information-request",
            fixture_str!("bytes/ipv6-udp-dhcpv6-information-request.hex"),
            Dhcpv6MessageType::InformationRequest,
        ),
        (
            "relay-forward",
            fixture_str!("bytes/ipv6-udp-dhcpv6-relay-forward.hex"),
            Dhcpv6MessageType::RelayForw,
        ),
        (
            "relay-reply",
            fixture_str!("bytes/ipv6-udp-dhcpv6-relay-reply.hex"),
            Dhcpv6MessageType::RelayRepl,
        ),
        (
            "ia-na-iaaddr",
            fixture_str!("bytes/ipv6-udp-dhcpv6-ia-na-iaaddr.hex"),
            Dhcpv6MessageType::Reply,
        ),
        (
            "ia-pd-iaprefix",
            fixture_str!("bytes/ipv6-udp-dhcpv6-ia-pd-iaprefix.hex"),
            Dhcpv6MessageType::Reply,
        ),
        (
            "unknown-option",
            fixture_str!("bytes/ipv6-udp-dhcpv6-unknown-option.hex"),
            Dhcpv6MessageType::Reply,
        ),
    ];

    for (name, hex, expected_type) in cases {
        let decoded = assert_fixture_roundtrip(name, hex)?;
        let dhcpv6 = decoded
            .layer::<Dhcpv6>()
            .unwrap_or_else(|| panic!("{name} fixture should decode to DHCPv6"));
        assert_eq!(dhcpv6.message_type_value(), expected_type, "{name}");
    }

    Ok(())
}

#[test]
fn dhcpv6_relay_nesting_roundtrips_inner_messages() -> crafter::Result<()> {
    let client = client_duid();
    let server = server_duid();
    let relay_forward = Dhcpv6::relay_forward(doc_prefix(0x0100), doc_addr(0x0011))
        .hop_count(1)
        .interface_id(b"uplink-1".to_vec())
        .relay_message(Dhcpv6::solicit(0x0a0b0c).client_id(client))?;
    let relay_reply = Dhcpv6::relay_reply(doc_prefix(0x0100), doc_addr(0x0011))
        .hop_count(1)
        .interface_id(b"uplink-1".to_vec())
        .relay_message(
            Dhcpv6::advertise(0x0a0b0c)
                .client_id(client)
                .server_id(server)
                .preference(100),
        )?;

    let decoded_forward = assert_packet_roundtrip(
        "relay-forward",
        packet(
            doc_addr(0x00fe),
            doc_addr(0x0001),
            Udp::dhcpv6_relay(),
            relay_forward,
        ),
    )?;
    let forward = decoded_forward.layer::<Dhcpv6>().unwrap();
    let forward_inner = forward
        .relayed_message_value()?
        .expect("relay-forward should preserve inner message");
    assert_eq!(
        forward_inner.message_type_value(),
        Dhcpv6MessageType::Solicit
    );
    assert_eq!(forward_inner.transaction_id_value(), 0x0a0b0c);
    assert_eq!(forward_inner.client_id_value(), Some(client.as_slice()));

    let decoded_reply = assert_packet_roundtrip(
        "relay-reply",
        packet(
            doc_addr(0x0001),
            doc_addr(0x00fe),
            Udp::dhcpv6_relay(),
            relay_reply,
        ),
    )?;
    let reply = decoded_reply.layer::<Dhcpv6>().unwrap();
    let reply_inner = reply
        .relayed_message_value()?
        .expect("relay-reply should preserve inner message");
    assert_eq!(
        reply_inner.message_type_value(),
        Dhcpv6MessageType::Advertise
    );
    assert_eq!(reply_inner.transaction_id_value(), 0x0a0b0c);
    assert_eq!(reply_inner.client_id_value(), Some(client.as_slice()));
    assert_eq!(reply_inner.server_id_value(), Some(server.as_slice()));
    assert_eq!(reply_inner.preference_value()?, Some(100));

    Ok(())
}

#[test]
fn dhcpv6_nested_ia_options_roundtrip_typed_fields() -> crafter::Result<()> {
    let ia_na = Dhcpv6IaNa::new(0x0102_0304, 60, 120).ia_addr(Dhcpv6IaAddr::new(
        doc_addr(0x0100),
        300,
        600,
    ))?;
    let ia_pd = Dhcpv6IaPd::new(0x0506_0708, 90, 180).ia_prefix(Dhcpv6IaPrefix::new(
        300,
        600,
        56,
        doc_prefix(0x0200),
    ))?;
    let decoded = assert_packet_roundtrip(
        "ia-na-ia-pd",
        packet(
            doc_addr(0x0001),
            doc_addr(0x0010),
            Udp::dhcpv6_server(),
            Dhcpv6::reply(0x040506)
                .client_id(client_duid())
                .server_id(server_duid())
                .ia_na(ia_na)?
                .ia_pd(ia_pd)?,
        ),
    )?;
    let dhcpv6 = decoded.layer::<Dhcpv6>().unwrap();

    let decoded_ia_na = dhcpv6
        .ia_na_value()?
        .expect("round-tripped message should preserve IA_NA");
    assert_eq!(decoded_ia_na.iaid(), 0x0102_0304);
    let decoded_ia_addr = decoded_ia_na.options_ref()[0]
        .ia_addr_value()?
        .expect("round-tripped IA_NA should preserve IAADDR");
    assert_eq!(decoded_ia_addr.address(), doc_addr(0x0100));
    assert_eq!(decoded_ia_addr.preferred_lifetime(), 300);
    assert_eq!(decoded_ia_addr.valid_lifetime(), 600);

    let decoded_ia_pd = dhcpv6
        .ia_pd_value()?
        .expect("round-tripped message should preserve IA_PD");
    assert_eq!(decoded_ia_pd.iaid(), 0x0506_0708);
    let decoded_prefix = decoded_ia_pd.options_ref()[0]
        .ia_prefix_value()?
        .expect("round-tripped IA_PD should preserve IAPREFIX");
    assert_eq!(decoded_prefix.prefix_length(), 56);
    assert_eq!(decoded_prefix.prefix(), doc_prefix(0x0200));

    Ok(())
}

#[test]
fn dhcpv6_unknown_duplicate_and_raw_escape_hatches_roundtrip() -> crafter::Result<()> {
    let decoded = assert_packet_roundtrip(
        "raw-escape",
        packet(
            doc_addr(0x0010),
            doc_addr(0x0001),
            Udp::dhcpv6_client(),
            Dhcpv6::new()
                .message_type_code(250)
                .transaction_id(0x0c0d0e)
                .raw_option(1u16, client_duid())
                .raw_option(1u16, client_duid())
                .raw_option(65_000u16, [0xde, 0xad, 0xbe, 0xef])
                .empty_option(65_001u16),
        ),
    )?;
    let dhcpv6 = decoded.layer::<Dhcpv6>().unwrap();
    assert_eq!(dhcpv6.message_type_code_value(), 250);
    assert_eq!(dhcpv6.transaction_id_value(), 0x0c0d0e);
    assert!(dhcpv6.option_repetition_report().has_duplicate_singletons());

    let options = dhcpv6.options_ref();
    assert_eq!(options[2].codepoint(), 65_000);
    assert_eq!(options[2].payload(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(options[3].codepoint(), 65_001);
    assert!(options[3].payload().is_empty());

    Ok(())
}

#[test]
fn dhcpv6_summary_and_show_stay_stable_after_roundtrip() -> crafter::Result<()> {
    let ia_na = Dhcpv6IaNa::new(0x0102_0304, 60, 120).ia_addr(Dhcpv6IaAddr::new(
        doc_addr(0x0100),
        300,
        600,
    ))?;
    let packet = packet(
        doc_addr(0x0001),
        doc_addr(0x0010),
        Udp::dhcpv6_server(),
        Dhcpv6::reply(0x0a0b0c)
            .client_id(client_duid())
            .server_id(server_duid())
            .ia_na(ia_na)?
            .status_message(Dhcpv6StatusCode::NoAddrsAvail, b"no addresses")
            .option(Dhcpv6Option::raw(65_000u16, [0xde, 0xad])),
    );
    let first = assert_packet_roundtrip("summary-show", packet)?;
    let summary = first.summary();
    let show = first.show();
    assert!(summary.contains("Dhcpv6(type=reply"));
    assert!(show.contains("OPTION_IA_NA"));
    assert!(show.contains("code65000"));

    let second_bytes = first.compile()?;
    let second = Packet::decode_from_l3(NetworkLayer::Ipv6, second_bytes.as_bytes())?;
    assert_eq!(second.summary(), summary);
    assert_eq!(second.show(), show);

    Ok(())
}
