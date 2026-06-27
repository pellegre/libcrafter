use crafter::prelude::*;
use crafter::protocols::dhcp::{Dhcpv6, Dhcpv6MessageType};

const IPV6_HEADER_LEN: usize = 40;
const UDP_CHECKSUM_OFFSET: usize = IPV6_HEADER_LEN + 6;
const UDP_LENGTH_OFFSET: usize = IPV6_HEADER_LEN + 4;

#[test]
fn dhcpv6_ipv6_udp_stack_autofills_and_decodes() -> crafter::Result<()> {
    let packet = Ipv6::new() / Udp::dhcpv6_client() / Dhcpv6::solicit(0x010203);
    let bytes = packet.compile()?;

    assert_eq!(bytes.as_bytes()[6], IPPROTO_UDP);
    assert_eq!(&bytes.as_bytes()[4..6], &12u16.to_be_bytes());
    assert_eq!(
        &bytes.as_bytes()[UDP_LENGTH_OFFSET..UDP_LENGTH_OFFSET + 2],
        &12u16.to_be_bytes(),
    );
    assert_ne!(
        u16::from_be_bytes([
            bytes.as_bytes()[UDP_CHECKSUM_OFFSET],
            bytes.as_bytes()[UDP_CHECKSUM_OFFSET + 1],
        ]),
        0,
    );

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())?;
    let ipv6 = decoded.layer::<Ipv6>().unwrap();
    let udp = decoded.layer::<Udp>().unwrap();
    let dhcpv6 = decoded.layer::<Dhcpv6>().unwrap();

    assert_eq!(ipv6.next_header_value(), IPPROTO_UDP);
    assert_eq!(ipv6.payload_length_value(), Some(12));
    assert_eq!(udp.length_value(), Some(12));
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
    assert_eq!(dhcpv6.message_type_value(), Dhcpv6MessageType::Solicit);
    assert_eq!(dhcpv6.transaction_id_value(), 0x010203);
    assert!(decoded.layer::<Raw>().is_none());

    Ok(())
}

#[test]
fn dhcpv6_ipv6_udp_stack_preserves_udp_overrides() -> crafter::Result<()> {
    let packet =
        Ipv6::new() / Udp::dhcpv6_client().length(11).checksum(0x1234) / Dhcpv6::solicit(0x010203);
    let bytes = packet.compile()?;

    assert_eq!(
        &bytes.as_bytes()[UDP_LENGTH_OFFSET..UDP_LENGTH_OFFSET + 2],
        &11u16.to_be_bytes(),
    );
    assert_eq!(
        &bytes.as_bytes()[UDP_CHECKSUM_OFFSET..UDP_CHECKSUM_OFFSET + 2],
        &0x1234u16.to_be_bytes(),
    );

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())?;
    let udp = decoded.layer::<Udp>().unwrap();

    assert_eq!(udp.length_value(), Some(11));
    assert_eq!(udp.checksum_value(), Some(0x1234));
    assert!(decoded.layer::<Dhcpv6>().is_none());

    Ok(())
}

#[test]
fn dhcpv6_core_builders_compile_and_decode_message_types() -> crafter::Result<()> {
    let cases: &[(&str, fn(u32) -> Dhcpv6, Dhcpv6MessageType)] = &[
        ("solicit", Dhcpv6::solicit, Dhcpv6MessageType::Solicit),
        ("advertise", Dhcpv6::advertise, Dhcpv6MessageType::Advertise),
        ("request", Dhcpv6::request, Dhcpv6MessageType::Request),
        ("confirm", Dhcpv6::confirm, Dhcpv6MessageType::Confirm),
        ("renew", Dhcpv6::renew, Dhcpv6MessageType::Renew),
        ("rebind", Dhcpv6::rebind, Dhcpv6MessageType::Rebind),
        ("reply", Dhcpv6::reply, Dhcpv6MessageType::Reply),
        ("release", Dhcpv6::release, Dhcpv6MessageType::Release),
        ("decline", Dhcpv6::decline, Dhcpv6MessageType::Decline),
        (
            "reconfigure",
            Dhcpv6::reconfigure,
            Dhcpv6MessageType::Reconfigure,
        ),
        (
            "information-request",
            Dhcpv6::information_request,
            Dhcpv6MessageType::InformationRequest,
        ),
    ];

    for (name, builder, expected) in cases {
        let message = builder(0x0a0b0c);
        assert_eq!(message.message_type_value(), *expected, "{name}");
        assert_eq!(message.transaction_id_value(), 0x0a0b0c, "{name}");
        assert!(message.options_ref().is_empty(), "{name}");

        let bytes = Packet::from_layer(message).compile()?;
        assert_eq!(bytes.as_bytes()[0], expected.code(), "{name}");

        let decoded = Dhcpv6::decode(bytes.as_bytes())?;
        assert_eq!(decoded.message_type_value(), *expected, "{name}");
        assert_eq!(decoded.transaction_id_value(), 0x0a0b0c, "{name}");
        assert!(decoded.options_ref().is_empty(), "{name}");
    }

    Ok(())
}
