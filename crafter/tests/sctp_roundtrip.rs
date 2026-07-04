use std::net::Ipv4Addr;

use crafter::prelude::*;

const DOC_V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 79);
const DOC_V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 79);

fn preserved_chunk(
    chunk_type: u8,
    flags: u8,
    value: impl Into<Vec<u8>>,
    padding: impl Into<Vec<u8>>,
) -> SctpChunk {
    let value = value.into();
    let declared_length = (SCTP_CHUNK_HEADER_LEN + value.len()) as u16;
    SctpChunk::from_preserved_parts(chunk_type, flags, declared_length, value, padding)
}

fn chunk_variant_name(chunk: &SctpChunk) -> &'static str {
    match chunk {
        SctpChunk::Data(_) => "DATA",
        SctpChunk::Init(_) => "INIT",
        SctpChunk::InitAck(_) => "INIT ACK",
        SctpChunk::Sack(_) => "SACK",
        SctpChunk::Heartbeat(_) => "HEARTBEAT",
        SctpChunk::HeartbeatAck(_) => "HEARTBEAT ACK",
        SctpChunk::Abort(_) => "ABORT",
        SctpChunk::Shutdown(_) => "SHUTDOWN",
        SctpChunk::ShutdownAck(_) => "SHUTDOWN ACK",
        SctpChunk::Error(_) => "ERROR",
        SctpChunk::CookieEcho(_) => "COOKIE ECHO",
        SctpChunk::CookieAck(_) => "COOKIE ACK",
        SctpChunk::Ecne(_) => "ECNE",
        SctpChunk::Cwr(_) => "CWR",
        SctpChunk::ShutdownComplete(_) => "SHUTDOWN COMPLETE",
        SctpChunk::Auth(_) => "AUTH",
        SctpChunk::IData(_) => "I-DATA",
        SctpChunk::AsconfAck(_) => "ASCONF ACK",
        SctpChunk::ReConfig(_) => "RE-CONFIG",
        SctpChunk::Pad(_) => "PAD",
        SctpChunk::ForwardTsn(_) => "FORWARD TSN",
        SctpChunk::Asconf(_) => "ASCONF",
        SctpChunk::IForwardTsn(_) => "I-FORWARD TSN",
        SctpChunk::Unknown(_) => "UNKNOWN",
    }
}

#[test]
fn sctp_chunk_roundtrip_all_typed_chunks_preserve_source_bytes() -> crafter::Result<()> {
    let cases = vec![
        (
            "DATA",
            preserved_chunk(
                SCTP_CHUNK_TYPE_DATA,
                0x03,
                [
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0xde,
                ],
                [0xe1, 0xe2, 0xe3],
            ),
        ),
        (
            "INIT",
            preserved_chunk(
                SCTP_CHUNK_TYPE_INIT,
                0x80,
                [
                    0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x40, 0x00, 0x00, 0x05, 0x00, 0x06, 0xaa,
                    0xbb, 0xcc, 0xdd,
                ],
                [],
            ),
        ),
        (
            "INIT ACK",
            preserved_chunk(
                SCTP_CHUNK_TYPE_INIT_ACK,
                0x40,
                [
                    0x55, 0x66, 0x77, 0x88, 0x00, 0x00, 0x50, 0x00, 0x00, 0x07, 0x00, 0x08, 0x12,
                    0x34, 0x56, 0x78,
                ],
                [],
            ),
        ),
        (
            "SACK",
            preserved_chunk(
                SCTP_CHUNK_TYPE_SACK,
                0x5a,
                [
                    0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x40, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                    0x01, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04,
                ],
                [],
            ),
        ),
        (
            "HEARTBEAT",
            preserved_chunk(
                SCTP_CHUNK_TYPE_HEARTBEAT,
                0x5a,
                [0x00, 0x01, 0x00, 0x07, 0xde, 0xad, 0xbe, 0xcc],
                [],
            ),
        ),
        (
            "HEARTBEAT ACK",
            preserved_chunk(
                SCTP_CHUNK_TYPE_HEARTBEAT_ACK,
                0x5a,
                [0x00, 0x01, 0x00, 0x07, 0xde, 0xad, 0xbe, 0xcc],
                [],
            ),
        ),
        (
            "ABORT",
            preserved_chunk(
                SCTP_CHUNK_TYPE_ABORT,
                0x5b,
                [0x00, 0x0d, 0x00, 0x05, 0xde, 0xaa, 0xbb, 0xcc],
                [],
            ),
        ),
        (
            "SHUTDOWN",
            preserved_chunk(SCTP_CHUNK_TYPE_SHUTDOWN, 0x11, [0x01, 0x02, 0x03, 0x04], []),
        ),
        (
            "SHUTDOWN ACK",
            preserved_chunk(SCTP_CHUNK_TYPE_SHUTDOWN_ACK, 0x22, [], []),
        ),
        (
            "ERROR",
            preserved_chunk(
                SCTP_CHUNK_TYPE_ERROR,
                0x5a,
                [0x00, 0x0d, 0x00, 0x05, 0xde, 0xaa, 0xbb, 0xcc],
                [],
            ),
        ),
        (
            "COOKIE ECHO",
            preserved_chunk(
                SCTP_CHUNK_TYPE_COOKIE_ECHO,
                0x5a,
                [0xde, 0xad, 0xbe],
                [0xcc],
            ),
        ),
        (
            "COOKIE ACK",
            preserved_chunk(SCTP_CHUNK_TYPE_COOKIE_ACK, 0x33, [], []),
        ),
        (
            "ECNE",
            preserved_chunk(SCTP_CHUNK_TYPE_ECNE, 0x44, [0x11, 0x22, 0x33, 0x44], []),
        ),
        (
            "CWR",
            preserved_chunk(SCTP_CHUNK_TYPE_CWR, 0x55, [0x55, 0x66, 0x77, 0x88], []),
        ),
        (
            "SHUTDOWN COMPLETE",
            preserved_chunk(SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE, 0x01, [], []),
        ),
        (
            "AUTH",
            preserved_chunk(
                SCTP_CHUNK_TYPE_AUTH,
                0x5a,
                [0xbe, 0xef, 0x12, 0x34, 0x01, 0x02, 0x03],
                [0xdd],
            ),
        ),
        (
            "I-DATA",
            preserved_chunk(
                SCTP_CHUNK_TYPE_I_DATA,
                0x0d,
                [
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0xde, 0xad, 0xbe,
                ],
                [0xee],
            ),
        ),
        (
            "ASCONF ACK",
            preserved_chunk(
                SCTP_CHUNK_TYPE_ASCONF_ACK,
                0x5a,
                [
                    0x11, 0x22, 0x33, 0x44, 0xc0, 0x05, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04,
                ],
                [],
            ),
        ),
        (
            "RE-CONFIG",
            preserved_chunk(
                SCTP_CHUNK_TYPE_RE_CONFIG,
                0x5a,
                [
                    0x00, 0x10, 0x00, 0x0c, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x01,
                ],
                [],
            ),
        ),
        (
            "PAD",
            preserved_chunk(SCTP_CHUNK_TYPE_PAD, 0x66, [0xaa, 0xbb, 0xcc], [0xdd]),
        ),
        (
            "FORWARD TSN",
            preserved_chunk(
                SCTP_CHUNK_TYPE_FORWARD_TSN,
                0x5a,
                [
                    0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x03, 0x04, 0xff, 0xfe, 0xff, 0xff,
                ],
                [],
            ),
        ),
        (
            "ASCONF",
            preserved_chunk(
                SCTP_CHUNK_TYPE_ASCONF,
                0x5a,
                [
                    0x11, 0x22, 0x33, 0x44, 0x00, 0x05, 0x00, 0x08, 192, 0, 2, 1, 0xc0, 0x01, 0x00,
                    0x10, 0x01, 0x02, 0x03, 0x04, 0x00, 0x05, 0x00, 0x08, 198, 51, 100, 1,
                ],
                [],
            ),
        ),
        (
            "I-FORWARD TSN",
            preserved_chunk(
                SCTP_CHUNK_TYPE_I_FORWARD_TSN,
                0x5a,
                [
                    0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x00, 0x00, 0x03, 0x04, 0x05, 0x06, 0xff,
                    0xfe, 0x80, 0x01, 0xaa, 0xbb, 0xcc, 0xdd,
                ],
                [],
            ),
        ),
    ];
    let chunks = cases
        .iter()
        .map(|(_, chunk)| chunk.clone())
        .collect::<Vec<_>>();
    let packet = Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST)
        / Sctp::new()
            .sport(16_000)
            .dport(16_001)
            .vtag(0x1122_3344)
            .checksum(0)
            .with_chunks(chunks);
    let compiled = packet.compile()?;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(sctp.checksum_value(), Some(0));
    assert_eq!(sctp.checksum_status(), SctpChecksumStatus::ZeroChecksum);
    assert_eq!(sctp.chunk_count(), cases.len());
    for ((expected_name, _), chunk) in cases.iter().zip(sctp.chunks()) {
        assert_eq!(chunk_variant_name(chunk), *expected_name);
        assert!(chunk.explicit_declared_length().is_some());
    }
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());

    Ok(())
}
