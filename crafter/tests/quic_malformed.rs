//! QUIC malformed input coverage.
//!
//! These tests stay offline and use documentation address space when an IP/UDP
//! wrapper is needed to reach the public decode path.

use crafter::protocols::quic::QuicHeader;
use crafter::{
    CrafterError, Ipv4, NetworkLayer, Packet, QuicLongHeaderPacket, QuicPacket, QuicPacketNumber,
    QuicRetryPacket, Raw, Udp,
};
use std::net::Ipv4Addr;

fn assert_buffer_too_short(
    err: CrafterError,
    context: &'static str,
    required: usize,
    available: usize,
) {
    assert_eq!(
        err,
        CrafterError::buffer_too_short(context, required, available)
    );
}

fn udp_ipv4_quic_payload(payload: &[u8]) -> crafter::Result<Vec<u8>> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().sport(49_152).dport(4433)
        / Raw::from_bytes(payload);
    Ok(packet.compile()?.as_bytes().to_vec())
}

#[test]
fn quic_header_truncation_parser_boundaries() -> crafter::Result<()> {
    assert_buffer_too_short(
        QuicHeader::from_decoded_bytes([]).unwrap_err(),
        "quic.header",
        1,
        0,
    );

    assert_buffer_too_short(
        QuicPacket::decode([0xc0]).unwrap_err(),
        "quic.header.long.version",
        5,
        1,
    );
    assert_buffer_too_short(
        QuicPacket::decode([0xc0, 0x00, 0x00, 0x00]).unwrap_err(),
        "quic.header.long.version",
        5,
        4,
    );
    assert_buffer_too_short(
        QuicPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01]).unwrap_err(),
        "quic.header.long.dcid_len",
        6,
        5,
    );
    assert_buffer_too_short(
        QuicPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01, 0x04, 0xaa]).unwrap_err(),
        "quic.header.long.dcid",
        10,
        7,
    );

    assert_buffer_too_short(
        QuicLongHeaderPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]).unwrap_err(),
        "quic.initial.token_length",
        8,
        7,
    );
    assert_buffer_too_short(
        QuicLongHeaderPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40])
            .unwrap_err(),
        "quic.long_header.length",
        10,
        9,
    );
    assert_buffer_too_short(
        QuicLongHeaderPacket::decode([0xe1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0xaa])
            .unwrap_err(),
        "quic.long_header.packet_number",
        10,
        9,
    );
    assert_buffer_too_short(
        QuicRetryPacket::decode([0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]).unwrap_err(),
        "quic.retry.integrity_tag",
        23,
        8,
    );

    let initial = QuicLongHeaderPacket::initial_builder()
        .packet_number(QuicPacketNumber::new(1))
        .payload([0xbe])
        .build()?;
    let malformed_handshake = [0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x02, 0xef];
    let mut coalesced = initial.as_bytes().to_vec();
    coalesced.extend_from_slice(&malformed_handshake);
    let wrapped = udp_ipv4_quic_payload(&coalesced)?;

    assert_buffer_too_short(
        Packet::decode_from_l3(NetworkLayer::Ipv4, &wrapped).unwrap_err(),
        "quic.long_header.protected_payload",
        11,
        malformed_handshake.len(),
    );

    Ok(())
}
