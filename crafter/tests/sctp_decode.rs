use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

const DOC_V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 44);
const DOC_V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 55);
const DOC_V6_SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x44, 0, 0, 0, 0, 1);
const DOC_V6_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x55, 0, 0, 0, 0, 2);

#[test]
fn sctp_direct_decode_ipv4_and_ipv6_data_chunks() -> crafter::Result<()> {
    let ipv4_bytes = (Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST)
        / Sctp::data(
            0x0102_0304,
            7,
            9,
            SCTP_PPID_WEBRTC_STRING,
            b"v4-data".to_vec(),
        )
        .sport(12_000)
        .dport(12_001)
        .vtag(0x1122_3344))
    .compile()?;

    let decoded_v4 = Packet::decode_from_l3(NetworkLayer::Ipv4, ipv4_bytes.as_bytes())?;
    let ipv4 = decoded_v4.layer::<Ipv4>().expect("IPv4 layer");
    let sctp_v4 = decoded_v4.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(ipv4.protocol_value(), IPPROTO_SCTP);
    assert_eq!(sctp_v4.source_port_value(), 12_000);
    assert_eq!(sctp_v4.destination_port_value(), 12_001);
    assert_eq!(sctp_v4.verification_tag_value(), 0x1122_3344);
    assert_eq!(sctp_v4.checksum_status(), SctpChecksumStatus::Valid);
    assert_eq!(sctp_v4.chunk_count(), 1);
    let SctpChunk::Data(data_v4) = &sctp_v4.chunks()[0] else {
        panic!("expected IPv4 DATA chunk");
    };
    assert_eq!(data_v4.user_data()?, b"v4-data");
    assert!(decoded_v4.layer::<Raw>().is_none());
    assert_eq!(decoded_v4.compile()?, ipv4_bytes);

    let ipv6_bytes = (Ipv6::new().src(DOC_V6_SRC).dst(DOC_V6_DST)
        / Sctp::data(0x0506_0708, 11, 13, 0xfeed_beef, b"v6-data".to_vec())
            .sport(12_100)
            .dport(12_101)
            .vtag(0x5566_7788))
    .compile()?;

    let decoded_v6 = Packet::decode_from_l3(NetworkLayer::Ipv6, ipv6_bytes.as_bytes())?;
    let ipv6 = decoded_v6.layer::<Ipv6>().expect("IPv6 layer");
    let sctp_v6 = decoded_v6.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(ipv6.next_header_value(), IPPROTO_SCTP);
    assert_eq!(sctp_v6.source_port_value(), 12_100);
    assert_eq!(sctp_v6.destination_port_value(), 12_101);
    assert_eq!(sctp_v6.verification_tag_value(), 0x5566_7788);
    assert_eq!(sctp_v6.checksum_status(), SctpChecksumStatus::Valid);
    assert_eq!(sctp_v6.chunk_count(), 1);
    let SctpChunk::Data(data_v6) = &sctp_v6.chunks()[0] else {
        panic!("expected IPv6 DATA chunk");
    };
    assert_eq!(data_v6.user_data()?, b"v6-data");
    assert!(decoded_v6.layer::<Raw>().is_none());
    assert_eq!(decoded_v6.compile()?, ipv6_bytes);

    Ok(())
}

#[test]
fn sctp_direct_decode_preserves_unknown_chunks_over_ip() -> crafter::Result<()> {
    let unknown = SctpChunk::unknown(SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4, 0xa0, [0xde, 0xad]);
    let bytes = (Ipv6::new().src(DOC_V6_SRC).dst(DOC_V6_DST)
        / Sctp::new()
            .sport(13_000)
            .dport(13_001)
            .vtag(0xaabb_ccdd)
            .chunk(unknown))
    .compile()?;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())?;
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(sctp.chunk_count(), 1);
    let SctpChunk::Unknown(unknown) = &sctp.chunks()[0] else {
        panic!("expected unknown SCTP chunk");
    };
    assert_eq!(
        unknown.chunk_type_value(),
        SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4
    );
    assert_eq!(unknown.flags(), 0xa0);
    assert_eq!(unknown.value(), &[0xde, 0xad]);
    assert_eq!(unknown.padding(), &[0x00, 0x00]);
    assert!(decoded.layer::<Raw>().is_none());
    assert_eq!(decoded.compile()?, bytes);

    Ok(())
}

#[test]
fn sctp_direct_decode_raw_fallback_for_unsupported_ip_payloads() -> crafter::Result<()> {
    let ipv4_bytes = (Ipv4::new()
        .src(DOC_V4_SRC)
        .dst(DOC_V4_DST)
        .protocol(IPPROTO_EXPERIMENTAL_1)
        / Raw::from("unsupported-v4"))
    .compile()?;
    let decoded_v4 = Packet::decode_from_l3(NetworkLayer::Ipv4, ipv4_bytes.as_bytes())?;

    assert_eq!(
        decoded_v4
            .layer::<Ipv4>()
            .expect("IPv4 layer")
            .protocol_value(),
        IPPROTO_EXPERIMENTAL_1
    );
    assert!(decoded_v4.layer::<Sctp>().is_none());
    assert_eq!(
        decoded_v4
            .layer::<Raw>()
            .expect("raw IPv4 payload")
            .as_bytes(),
        b"unsupported-v4"
    );

    let ipv6_bytes = (Ipv6::new()
        .src(DOC_V6_SRC)
        .dst(DOC_V6_DST)
        .nh(IPPROTO_IPV6_EXPERIMENTAL_1)
        / Raw::from("unsupported-v6"))
    .compile()?;
    let decoded_v6 = Packet::decode_from_l3(NetworkLayer::Ipv6, ipv6_bytes.as_bytes())?;

    assert_eq!(
        decoded_v6
            .layer::<Ipv6>()
            .expect("IPv6 layer")
            .next_header_value(),
        IPPROTO_IPV6_EXPERIMENTAL_1
    );
    assert!(decoded_v6.layer::<Sctp>().is_none());
    assert_eq!(
        decoded_v6
            .layer::<Raw>()
            .expect("raw IPv6 payload")
            .as_bytes(),
        b"unsupported-v6"
    );

    Ok(())
}

#[test]
fn sctp_udp_encapsulation_decodes_rfc6951_payloads() -> crafter::Result<()> {
    let ipv4_bytes = (Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST)
        / Udp::new().sport(49_152).dport(SCTP_UDP_ENCAPSULATION_PORT)
        / Sctp::data(0x1111_2222, 1, 2, 0x0102_0304, b"udp-v4".to_vec())
            .sport(14_000)
            .dport(14_001)
            .vtag(0x1020_3040))
    .compile()?;

    let decoded_v4 = Packet::decode_from_l3(NetworkLayer::Ipv4, ipv4_bytes.as_bytes())?;
    let udp_v4 = decoded_v4.layer::<Udp>().expect("IPv4 UDP layer");
    let sctp_v4 = decoded_v4.layer::<Sctp>().expect("IPv4 SCTP layer");

    assert_eq!(udp_v4.destination_port_value(), SCTP_UDP_ENCAPSULATION_PORT);
    assert_eq!(udp_v4.checksum_status(), UdpChecksumStatus::Valid);
    assert_eq!(sctp_v4.source_port_value(), 14_000);
    assert_eq!(sctp_v4.destination_port_value(), 14_001);
    assert_eq!(sctp_v4.checksum_status(), SctpChecksumStatus::Valid);
    let SctpChunk::Data(data_v4) = &sctp_v4.chunks()[0] else {
        panic!("expected IPv4 UDP-encapsulated DATA chunk");
    };
    assert_eq!(data_v4.user_data()?, b"udp-v4");
    assert!(decoded_v4.layer::<Raw>().is_none());

    let ipv6_bytes = (Ipv6::new().src(DOC_V6_SRC).dst(DOC_V6_DST)
        / Udp::new().sport(49_153).dport(SCTP_UDP_ENCAPSULATION_PORT)
        / Sctp::data(0x3333_4444, 3, 4, 0x0506_0708, b"udp-v6".to_vec())
            .sport(14_100)
            .dport(14_101)
            .vtag(0x5060_7080))
    .compile()?;

    let decoded_v6 = Packet::decode_from_l3(NetworkLayer::Ipv6, ipv6_bytes.as_bytes())?;
    let udp_v6 = decoded_v6.layer::<Udp>().expect("IPv6 UDP layer");
    let sctp_v6 = decoded_v6.layer::<Sctp>().expect("IPv6 SCTP layer");

    assert_eq!(udp_v6.destination_port_value(), SCTP_UDP_ENCAPSULATION_PORT);
    assert_eq!(udp_v6.checksum_status(), UdpChecksumStatus::Valid);
    assert_eq!(sctp_v6.source_port_value(), 14_100);
    assert_eq!(sctp_v6.destination_port_value(), 14_101);
    assert_eq!(sctp_v6.checksum_status(), SctpChecksumStatus::Valid);
    let SctpChunk::Data(data_v6) = &sctp_v6.chunks()[0] else {
        panic!("expected IPv6 UDP-encapsulated DATA chunk");
    };
    assert_eq!(data_v6.user_data()?, b"udp-v6");
    assert!(decoded_v6.layer::<Raw>().is_none());

    Ok(())
}

#[test]
fn sctp_udp_encapsulation_unrelated_port_9899_payload_stays_raw() -> crafter::Result<()> {
    let bytes = (Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST)
        / Udp::new().sport(49_154).dport(SCTP_UDP_ENCAPSULATION_PORT)
        / Raw::from("not an sctp packet"))
    .compile()?;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    let udp = decoded.layer::<Udp>().expect("UDP layer");

    assert_eq!(udp.destination_port_value(), SCTP_UDP_ENCAPSULATION_PORT);
    assert!(decoded.layer::<Sctp>().is_none());
    assert_eq!(
        decoded.layer::<Raw>().expect("raw UDP payload").as_bytes(),
        b"not an sctp packet"
    );
    assert_eq!(decoded.compile()?, bytes);

    Ok(())
}

#[test]
fn sctp_udp_encapsulation_application_decoding_optout_keeps_payload_raw() -> crafter::Result<()> {
    let registry = ProtocolRegistry::new().application_decoding(false);
    let sctp = Sctp::data(0x7777_8888, 5, 6, 0x090a_0b0c, b"opt-out".to_vec())
        .sport(14_200)
        .dport(14_201)
        .vtag(0x90a0_b0c0);
    let sctp_bytes = Packet::from_layer(sctp.clone()).compile()?;
    let bytes = (Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST)
        / Udp::new().sport(49_155).dport(SCTP_UDP_ENCAPSULATION_PORT)
        / sctp)
        .compile()?;

    let decoded = registry.decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    let udp = decoded.layer::<Udp>().expect("UDP layer");

    assert_eq!(udp.destination_port_value(), SCTP_UDP_ENCAPSULATION_PORT);
    assert!(decoded.layer::<Sctp>().is_none());
    assert_eq!(
        decoded.layer::<Raw>().expect("raw SCTP payload").as_bytes(),
        sctp_bytes.as_bytes()
    );

    Ok(())
}
