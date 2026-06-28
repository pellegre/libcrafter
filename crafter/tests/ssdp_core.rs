use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const IPV4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const SSDP_IPV4_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

fn ipv4_search_message() -> Ssdp {
    Ssdp::m_search()
        .with_raw_header(SSDP_HEADER_HOST, SSDP_IPV4_MULTICAST_HOST)
        .expect("HOST header is valid")
        .with_raw_header(SSDP_HEADER_MAN, SSDP_MAN_DISCOVER)
        .expect("MAN header is valid")
        .with_raw_header(SSDP_HEADER_MX, "1")
        .expect("MX header is valid")
        .with_raw_header(SSDP_HEADER_ST, SSDP_ST_ALL)
        .expect("ST header is valid")
}

fn ipv6_response_message() -> Ssdp {
    Ssdp::response_ok()
        .with_raw_header(SSDP_HEADER_EXT, "")
        .expect("EXT header is valid")
        .with_raw_header(SSDP_HEADER_ST, SSDP_ST_ALL)
        .expect("ST header is valid")
        .with_raw_header(SSDP_HEADER_USN, "uuid:device-1::ssdp:all")
        .expect("USN header is valid")
}

#[test]
fn ipv4_ssdp_construct_compile_decode_and_inspect() -> crafter::Result<()> {
    let ssdp = ipv4_search_message();
    let ssdp_len = ssdp.to_bytes().len();
    let udp_len = UDP_HEADER_LEN + ssdp_len;
    let total_len = IPV4_HEADER_LEN + udp_len;
    let packet = Ipv4::new().src(IPV4_SRC).dst(SSDP_IPV4_GROUP) / Ssdp::udp().sport(49_152) / ssdp;

    let compiled = packet.compile()?;
    assert_eq!(compiled.as_bytes().len(), total_len);
    assert_eq!(
        &compiled.as_bytes()[2..4],
        &(total_len as u16).to_be_bytes()
    );
    assert_eq!(
        &compiled.as_bytes()[IPV4_HEADER_LEN + 4..IPV4_HEADER_LEN + 6],
        &(udp_len as u16).to_be_bytes()
    );

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let ipv4 = decoded.layer::<Ipv4>().expect("IPv4 layer");
    let udp = decoded.layer::<Udp>().expect("UDP layer");
    let ssdp = decoded.layer::<Ssdp>().expect("SSDP layer");

    assert_eq!(ipv4.total_length_value(), Some(total_len as u16));
    assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);
    assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);
    assert_eq!(udp.source_port_value(), 49_152);
    assert_eq!(udp.destination_port_value(), SSDP_UDP_PORT);
    assert_eq!(udp.length_value(), Some(udp_len as u16));
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
    assert!(decoded.layer::<Raw>().is_none());

    let request = ssdp
        .message()
        .start_line()
        .as_request()
        .expect("SSDP request line");
    assert_eq!(request.method(), &SsdpMethod::MSearch);
    assert!(request.target().is_asterisk());
    assert!(request.version().is_http_1_1());
    assert_eq!(
        ssdp.headers()
            .get_first(SsdpHeaderNameKind::St)
            .expect("ST header")
            .as_bytes(),
        SSDP_ST_ALL.as_bytes()
    );

    let summary = decoded.summary();
    assert!(summary.contains("Ipv4("), "{summary}");
    assert!(summary.contains("Udp("), "{summary}");
    assert!(summary.contains("SSDP("), "{summary}");
    assert!(summary.contains("M-SEARCH * HTTP/1.1"), "{summary}");

    Ok(())
}

#[test]
fn ipv6_ssdp_construct_compile_decode_and_inspect() -> crafter::Result<()> {
    let source = "2001:db8::10".parse::<Ipv6Addr>().unwrap();
    let destination = SSDP_IPV6_LINK_LOCAL_MULTICAST.parse::<Ipv6Addr>().unwrap();
    let ssdp = ipv6_response_message();
    let ssdp_len = ssdp.to_bytes().len();
    let udp_len = UDP_HEADER_LEN + ssdp_len;
    let packet = Ipv6::new().src(source).dst(destination) / Ssdp::udp().dport(49_153) / ssdp;

    let compiled = packet.compile()?;
    assert_eq!(compiled.as_bytes().len(), IPV6_HEADER_LEN + udp_len);
    assert_eq!(&compiled.as_bytes()[4..6], &(udp_len as u16).to_be_bytes());
    assert_eq!(compiled.as_bytes()[6], IPPROTO_UDP);
    assert_eq!(
        &compiled.as_bytes()[IPV6_HEADER_LEN + 4..IPV6_HEADER_LEN + 6],
        &(udp_len as u16).to_be_bytes()
    );

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())?;
    let ipv6 = decoded.layer::<Ipv6>().expect("IPv6 layer");
    let udp = decoded.layer::<Udp>().expect("UDP layer");
    let ssdp = decoded.layer::<Ssdp>().expect("SSDP layer");

    assert_eq!(ipv6.payload_length_value(), Some(udp_len as u16));
    assert_eq!(ipv6.next_header_value(), IPPROTO_UDP);
    assert_eq!(udp.source_port_value(), SSDP_UDP_PORT);
    assert_eq!(udp.destination_port_value(), 49_153);
    assert_eq!(udp.length_value(), Some(udp_len as u16));
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
    assert!(decoded.layer::<Raw>().is_none());

    let response = ssdp
        .message()
        .start_line()
        .as_response()
        .expect("SSDP response line");
    assert!(response.code().is_ok());
    assert!(response.reason().is_ok());
    assert_eq!(
        ssdp.headers()
            .get_first(SsdpHeaderNameKind::Ext)
            .expect("EXT header")
            .as_bytes(),
        b""
    );

    let summary = decoded.summary();
    assert!(summary.contains("Ipv6("), "{summary}");
    assert!(summary.contains("Udp("), "{summary}");
    assert!(summary.contains("SSDP("), "{summary}");
    assert!(summary.contains("HTTP/1.1 200 OK"), "{summary}");

    Ok(())
}

#[test]
fn overrides_survive_compile_for_malformed_udp_and_ssdp_fields() -> crafter::Result<()> {
    let ssdp = Ssdp::request(
        SsdpMethod::Unknown("BAD METHOD".to_string()),
        SsdpRequestTarget::new("/device.xml").expect("valid explicit target"),
        SsdpVersion::new("HTTP/1.0").expect("valid explicit version"),
    )
    .with_raw_header(SSDP_HEADER_HOST, "example.invalid")
    .expect("HOST header is valid")
    .with_body(b"body".to_vec());
    let packet = Ipv4::new()
        .src(IPV4_SRC)
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new()
            .sport(1_901)
            .dport(1_902)
            .length(0x1234)
            .checksum(0xbeef)
        / ssdp;

    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();
    let payload = &bytes[IPV4_HEADER_LEN + UDP_HEADER_LEN..];

    assert_eq!(u16::from_be_bytes([bytes[20], bytes[21]]), 1_901);
    assert_eq!(u16::from_be_bytes([bytes[22], bytes[23]]), 1_902);
    assert_eq!(&bytes[24..26], &0x1234u16.to_be_bytes());
    assert_eq!(&bytes[26..28], &0xbeefu16.to_be_bytes());
    assert_eq!(
        payload,
        b"BAD METHOD /device.xml HTTP/1.0\r\nHOST: example.invalid\r\n\r\nbody"
    );

    Ok(())
}
