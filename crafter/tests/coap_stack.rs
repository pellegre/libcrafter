use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const CLIENT_PORT: u16 = 49_152;
const IPV4_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const IPV4_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
const IPV6_CLIENT: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
const IPV6_SERVER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x20);

fn request(message_id: u16) -> Coap {
    Coap::get()
        .confirmable()
        .message_id(message_id)
        .token(CoapToken::from_bytes([0xaa, 0xbb]))
        .option(CoapOption::from_string(COAP_OPTION_URI_PATH, "status"))
}

fn response(message_id: u16) -> Coap {
    Coap::response(CoapCode::content())
        .acknowledgement()
        .message_id(message_id)
        .token(CoapToken::from_bytes([0xaa, 0xbb]))
        .option(CoapOption::from_uint(COAP_OPTION_CONTENT_FORMAT, 0))
        .payload(b"ready".to_vec())
}

fn compiled_coap(message: Coap) -> crafter::Result<Vec<u8>> {
    Ok(Packet::from_layer(message).compile()?.into_bytes())
}

#[test]
fn ipv4_request_autofills_udp_and_decodes_to_typed_coap() -> crafter::Result<()> {
    let coap = request(0x1234);
    let coap_len = compiled_coap(coap.clone())?.len();
    let udp_len = UDP_HEADER_LEN + coap_len;
    let total_len = IPV4_HEADER_LEN + udp_len;
    let packet = Ipv4::with_addresses(IPV4_CLIENT, IPV4_SERVER)
        / Udp::new().sport(CLIENT_PORT).dport(COAP_PORT)
        / coap;

    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(bytes.len(), total_len);
    assert_eq!(bytes[9], IPPROTO_UDP);
    assert_eq!(&bytes[2..4], &(total_len as u16).to_be_bytes());
    assert_eq!(
        &bytes[IPV4_HEADER_LEN + 4..IPV4_HEADER_LEN + 6],
        &(udp_len as u16).to_be_bytes()
    );
    assert_ne!(&bytes[IPV4_HEADER_LEN + 6..IPV4_HEADER_LEN + 8], &[0, 0]);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
    let ipv4 = decoded.layer::<Ipv4>().expect("decoded IPv4 layer");
    let udp = decoded.layer::<Udp>().expect("decoded UDP layer");
    let coap = decoded.layer::<Coap>().expect("decoded CoAP layer");

    assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);
    assert_eq!(ipv4.total_length_value(), Some(total_len as u16));
    assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);
    assert_eq!(udp.source_port_value(), CLIENT_PORT);
    assert_eq!(udp.destination_port_value(), COAP_PORT);
    assert_eq!(udp.length_value(), Some(udp_len as u16));
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
    assert_eq!(coap.code_value(), CoapCode::get());
    assert_eq!(coap.message_id_value(), 0x1234);
    assert_eq!(coap.token_value().as_bytes(), [0xaa, 0xbb]);
    assert!(decoded.layer::<Raw>().is_none());
    Ok(())
}

#[test]
fn ipv6_response_autofills_udp_and_decodes_to_typed_coap() -> crafter::Result<()> {
    let coap = response(0x1234);
    let coap_len = compiled_coap(coap.clone())?.len();
    let udp_len = UDP_HEADER_LEN + coap_len;
    let packet = Ipv6::with_addresses(IPV6_SERVER, IPV6_CLIENT)
        / Udp::new().sport(COAP_PORT).dport(CLIENT_PORT)
        / coap;

    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(bytes.len(), IPV6_HEADER_LEN + udp_len);
    assert_eq!(bytes[6], IPPROTO_UDP);
    assert_eq!(&bytes[4..6], &(udp_len as u16).to_be_bytes());
    assert_eq!(
        &bytes[IPV6_HEADER_LEN + 4..IPV6_HEADER_LEN + 6],
        &(udp_len as u16).to_be_bytes()
    );
    assert_ne!(&bytes[IPV6_HEADER_LEN + 6..IPV6_HEADER_LEN + 8], &[0, 0]);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("decoded IPv6 layer");
    let udp = decoded.layer::<Udp>().expect("decoded UDP layer");
    let coap = decoded.layer::<Coap>().expect("decoded CoAP layer");

    assert_eq!(ipv6.next_header_value(), IPPROTO_UDP);
    assert_eq!(ipv6.payload_length_value(), Some(udp_len as u16));
    assert_eq!(udp.source_port_value(), COAP_PORT);
    assert_eq!(udp.destination_port_value(), CLIENT_PORT);
    assert_eq!(udp.length_value(), Some(udp_len as u16));
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
    assert_eq!(coap.message_type_value(), CoapMessageType::Acknowledgement);
    assert_eq!(coap.code_value(), CoapCode::content());
    assert_eq!(coap.message_id_value(), 0x1234);
    assert_eq!(coap.payload_value(), b"ready");
    assert!(decoded.layer::<Raw>().is_none());
    Ok(())
}

#[test]
fn explicit_ip_and_udp_wire_overrides_survive_compile() -> crafter::Result<()> {
    let ipv4 = (Ipv4::with_addresses(IPV4_CLIENT, IPV4_SERVER)
        .total_length(0x1234)
        .protocol(253)
        .checksum(0x4567)
        / Udp::new()
            .sport(40_001)
            .dport(COAP_PORT)
            .length(0x2345)
            .checksum(0x5678)
        / request(0x4001))
    .compile()?;
    let ipv4 = ipv4.as_bytes();

    assert_eq!(&ipv4[2..4], &0x1234u16.to_be_bytes());
    assert_eq!(ipv4[9], 253);
    assert_eq!(&ipv4[10..12], &0x4567u16.to_be_bytes());
    assert_eq!(&ipv4[20..22], &40_001u16.to_be_bytes());
    assert_eq!(&ipv4[22..24], &COAP_PORT.to_be_bytes());
    assert_eq!(&ipv4[24..26], &0x2345u16.to_be_bytes());
    assert_eq!(&ipv4[26..28], &0x5678u16.to_be_bytes());

    let ipv6 = (Ipv6::with_addresses(IPV6_CLIENT, IPV6_SERVER)
        .payload_length(0x3456)
        .next_header(254)
        / Udp::new()
            .sport(40_002)
            .dport(COAP_PORT)
            .length(0x4567)
            .checksum(0x6789)
        / request(0x4002))
    .compile()?;
    let ipv6 = ipv6.as_bytes();

    assert_eq!(&ipv6[4..6], &0x3456u16.to_be_bytes());
    assert_eq!(ipv6[6], 254);
    assert_eq!(&ipv6[40..42], &40_002u16.to_be_bytes());
    assert_eq!(&ipv6[42..44], &COAP_PORT.to_be_bytes());
    assert_eq!(&ipv6[44..46], &0x4567u16.to_be_bytes());
    assert_eq!(&ipv6[46..48], &0x6789u16.to_be_bytes());
    Ok(())
}

#[test]
fn coap_decode_stops_at_the_declared_udp_length() -> crafter::Result<()> {
    let coap = request(0x5001);
    let coap_len = compiled_coap(coap.clone())?.len();
    let surplus = [UDP_OPTION_NOP, UDP_OPTION_EOL];
    let packet = Ipv4::with_addresses(IPV4_CLIENT, IPV4_SERVER)
        / Udp::new().sport(CLIENT_PORT).dport(COAP_PORT)
        / coap
        / UdpOptions::from_bytes(surplus);

    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();
    let declared_udp_len = u16::from_be_bytes([bytes[24], bytes[25]]) as usize;

    assert_eq!(declared_udp_len, UDP_HEADER_LEN + coap_len);
    assert!(bytes.len() > IPV4_HEADER_LEN + declared_udp_len);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
    let coap = decoded.layer::<Coap>().expect("CoAP inside UDP length");
    let udp_options = decoded
        .layer::<UdpOptions>()
        .expect("surplus remains outside CoAP");

    assert_eq!(coap.message_id_value(), 0x5001);
    assert_eq!(coap.options_value()[0].value(), b"status");
    assert_eq!(udp_options.as_bytes(), surplus);
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert!(decoded.layer::<Raw>().is_none());
    Ok(())
}

#[test]
fn application_decoding_false_preserves_valid_coap_as_raw() -> crafter::Result<()> {
    let payload = compiled_coap(request(0x6001))?;
    let packet = Ipv4::with_addresses(IPV4_CLIENT, IPV4_SERVER)
        / Udp::new().sport(CLIENT_PORT).dport(COAP_PORT)
        / Raw::from_bytes(&payload);
    let compiled = packet.compile()?;
    let registry = ProtocolRegistry::new().application_decoding(false);

    let decoded = registry.decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    assert!(decoded.layer::<Udp>().is_some());
    assert!(decoded.layer::<Coap>().is_none());
    assert_eq!(
        decoded.layer::<Raw>().expect("raw CoAP payload").as_bytes(),
        payload
    );
    Ok(())
}

#[test]
fn registry_fallbacks_keep_wrong_malformed_and_secure_payloads_raw() -> crafter::Result<()> {
    let valid = compiled_coap(request(0x7001))?;
    let malformed = vec![0x40, 0x01, 0x12];
    let cases = [
        ("wrong-port", 60_000, valid.as_slice()),
        ("malformed-cleartext-port", COAP_PORT, malformed.as_slice()),
        ("secure-port", COAPS_PORT, valid.as_slice()),
    ];

    for (name, destination_port, payload) in cases {
        let packet = Ipv4::with_addresses(IPV4_CLIENT, IPV4_SERVER)
            / Udp::new().sport(CLIENT_PORT).dport(destination_port)
            / Raw::from_bytes(payload);
        let compiled = packet.compile()?;
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

        assert!(decoded.layer::<Coap>().is_none(), "{name}");
        assert_eq!(
            decoded
                .layer::<Raw>()
                .unwrap_or_else(|| panic!("{name}: raw UDP payload"))
                .as_bytes(),
            payload,
            "{name}"
        );
    }
    Ok(())
}
