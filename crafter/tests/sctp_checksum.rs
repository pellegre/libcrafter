#[macro_use]
mod support;

use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

const DOC_V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 76);
const DOC_V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 77);
const DOC_V6_SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x76, 0, 0, 0, 0, 1);
const DOC_V6_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x77, 0, 0, 0, 0, 2);
const IPV4_SCTP_OFFSET: usize = 20;
const IPV6_SCTP_OFFSET: usize = 40;
const SCTP_CHUNK_LENGTH_FIELD_OFFSET: usize = 2;

struct SctpChecksumCorpusCase {
    name: &'static str,
    fixture_hex: &'static str,
    target: NetworkLayer,
    sctp_offset: usize,
    expected_checksum: u32,
}

const SCTP_CHECKSUM_CORPUS: &[SctpChecksumCorpusCase] = &[
    SctpChecksumCorpusCase {
        name: "ipv4-sctp-init",
        fixture_hex: fixture_str!("bytes/ipv4-sctp-init.hex"),
        target: NetworkLayer::Ipv4,
        sctp_offset: IPV4_SCTP_OFFSET,
        expected_checksum: 0xb72e_618a,
    },
    SctpChecksumCorpusCase {
        name: "ipv6-sctp-init",
        fixture_hex: fixture_str!("bytes/ipv6-sctp-init.hex"),
        target: NetworkLayer::Ipv6,
        sctp_offset: IPV6_SCTP_OFFSET,
        expected_checksum: 0xb72e_618a,
    },
    SctpChecksumCorpusCase {
        name: "ipv4-sctp-init-ack",
        fixture_hex: fixture_str!("bytes/ipv4-sctp-init-ack.hex"),
        target: NetworkLayer::Ipv4,
        sctp_offset: IPV4_SCTP_OFFSET,
        expected_checksum: 0xbd52_c947,
    },
    SctpChecksumCorpusCase {
        name: "ipv4-sctp-data",
        fixture_hex: fixture_str!("bytes/ipv4-sctp-data.hex"),
        target: NetworkLayer::Ipv4,
        sctp_offset: IPV4_SCTP_OFFSET,
        expected_checksum: 0x389a_b289,
    },
    SctpChecksumCorpusCase {
        name: "ipv4-sctp-sack",
        fixture_hex: fixture_str!("bytes/ipv4-sctp-sack.hex"),
        target: NetworkLayer::Ipv4,
        sctp_offset: IPV4_SCTP_OFFSET,
        expected_checksum: 0xaabf_982b,
    },
    SctpChecksumCorpusCase {
        name: "ipv4-sctp-control-chunks",
        fixture_hex: fixture_str!("bytes/ipv4-sctp-control-chunks.hex"),
        target: NetworkLayer::Ipv4,
        sctp_offset: IPV4_SCTP_OFFSET,
        expected_checksum: 0x2012_b1cf,
    },
];

fn read_u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn sctp_checksum(bytes: &[u8], sctp_offset: usize) -> u32 {
    read_u32_at(bytes, sctp_offset + SCTP_CHECKSUM_OFFSET)
}

fn decode_hex_fixture(label: &str, text: &str) -> Vec<u8> {
    text.split_whitespace()
        .map(|byte| {
            u8::from_str_radix(byte, 16)
                .unwrap_or_else(|_| panic!("hex fixture {label} has invalid byte {byte:?}"))
        })
        .collect()
}

fn sctp_layer_from_l3<'a>(case: &SctpChecksumCorpusCase, packet: &'a Packet) -> &'a Sctp {
    packet
        .layer::<Sctp>()
        .unwrap_or_else(|| panic!("fixture {} should decode an SCTP layer", case.name))
}

#[test]
fn sctp_checksum_corpus_vectors_match_committed_fixtures() -> crafter::Result<()> {
    for case in SCTP_CHECKSUM_CORPUS {
        let bytes = decode_hex_fixture(case.name, case.fixture_hex);
        assert_eq!(
            sctp_checksum(&bytes, case.sctp_offset),
            case.expected_checksum,
            "fixture {} checksum word changed",
            case.name
        );

        let decoded = Packet::decode_from_l3(case.target, &bytes)?;
        let sctp = sctp_layer_from_l3(case, &decoded);
        assert_eq!(sctp.checksum_value(), Some(case.expected_checksum));
        assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Valid);
        assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());
    }

    Ok(())
}

#[test]
fn sctp_checksum_corpus_corrupted_checksums_decode_invalid() -> crafter::Result<()> {
    for case in SCTP_CHECKSUM_CORPUS {
        let mut bytes = decode_hex_fixture(case.name, case.fixture_hex);
        let checksum_offset = case.sctp_offset + SCTP_CHECKSUM_OFFSET;
        let mut bad_checksum = case.expected_checksum ^ 0xffff_ffff;
        if bad_checksum == 0 {
            bad_checksum = 1;
        }
        bytes[checksum_offset..checksum_offset + SCTP_CHECKSUM_LEN]
            .copy_from_slice(&bad_checksum.to_be_bytes());

        let decoded = Packet::decode_from_l3(case.target, &bytes)?;
        let sctp = sctp_layer_from_l3(case, &decoded);
        assert_eq!(sctp.checksum_value(), Some(bad_checksum));
        assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Invalid);
        assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());
    }

    Ok(())
}

#[test]
fn sctp_compile_checksum_autofills_odd_and_even_chunks() -> crafter::Result<()> {
    let odd = (Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST)
        / Sctp::data(0x0102_0304, 1, 1, 0x1111_2222, [0xaa])
            .sport(15_000)
            .dport(15_001)
            .vtag(0x1122_3344))
    .compile()?;
    let odd_bytes = odd.as_bytes();
    let odd_chunk_len = read_u16_at(
        odd_bytes,
        IPV4_SCTP_OFFSET + SCTP_COMMON_HEADER_LEN + SCTP_CHUNK_LENGTH_FIELD_OFFSET,
    );

    assert_eq!(odd_bytes[9], IPPROTO_SCTP);
    assert_eq!(odd_chunk_len, 17, "DATA chunk with one byte has odd length");
    assert_ne!(sctp_checksum(odd_bytes, IPV4_SCTP_OFFSET), 0);
    let odd_decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, odd_bytes)?;
    assert_eq!(
        odd_decoded
            .layer::<Sctp>()
            .expect("odd SCTP layer")
            .checksum_status(),
        SctpChecksumStatus::Valid
    );

    let even = (Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST)
        / Sctp::data(0x0506_0708, 2, 2, 0x3333_4444, [0xbb, 0xcc])
            .sport(15_002)
            .dport(15_003)
            .vtag(0x5566_7788))
    .compile()?;
    let even_bytes = even.as_bytes();
    let even_chunk_len = read_u16_at(
        even_bytes,
        IPV4_SCTP_OFFSET + SCTP_COMMON_HEADER_LEN + SCTP_CHUNK_LENGTH_FIELD_OFFSET,
    );

    assert_eq!(even_bytes[9], IPPROTO_SCTP);
    assert_eq!(
        even_chunk_len, 18,
        "DATA chunk with two bytes has even non-aligned length"
    );
    assert_ne!(sctp_checksum(even_bytes, IPV4_SCTP_OFFSET), 0);
    let even_decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, even_bytes)?;
    assert_eq!(
        even_decoded
            .layer::<Sctp>()
            .expect("even SCTP layer")
            .checksum_status(),
        SctpChecksumStatus::Valid
    );

    Ok(())
}

#[test]
fn sctp_compile_checksum_autofills_multi_chunk_packets() -> crafter::Result<()> {
    let packet = Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST)
        / Sctp::new()
            .sport(15_100)
            .dport(15_101)
            .vtag(0xaabb_ccdd)
            .chunk(SctpDataChunk::from_data(
                0x1111_1111,
                3,
                4,
                0x0102_0304,
                [0xaa],
            ))
            .chunk(SctpDataChunk::from_data(
                0x2222_2222,
                3,
                5,
                0x0506_0708,
                [0xbb, 0xcc],
            ))
            .chunk(SctpShutdownChunk::from_shutdown(0x3333_3333));
    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(bytes[9], IPPROTO_SCTP);
    assert_ne!(sctp_checksum(bytes, IPV4_SCTP_OFFSET), 0);
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(sctp.source_port_value(), 15_100);
    assert_eq!(sctp.destination_port_value(), 15_101);
    assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Valid);
    assert_eq!(sctp.chunk_count(), 3);
    assert!(matches!(sctp.chunks()[0], SctpChunk::Data(_)));
    assert!(matches!(sctp.chunks()[1], SctpChunk::Data(_)));
    assert!(matches!(sctp.chunks()[2], SctpChunk::Shutdown(_)));
    assert_eq!(decoded.compile()?, compiled);

    Ok(())
}

#[test]
fn sctp_compile_checksum_autofills_direct_ipv4_and_ipv6_packets() -> crafter::Result<()> {
    let ipv4 = (Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST)
        / Sctp::data(0x4444_4444, 7, 8, 0x090a_0b0c, b"ipv4-checksum".to_vec())
            .sport(15_200)
            .dport(15_201)
            .vtag(0x1020_3040))
    .compile()?;
    let ipv4_bytes = ipv4.as_bytes();

    assert_eq!(ipv4_bytes[9], IPPROTO_SCTP);
    assert_ne!(sctp_checksum(ipv4_bytes, IPV4_SCTP_OFFSET), 0);
    assert_eq!(
        Packet::decode_from_l3(NetworkLayer::Ipv4, ipv4_bytes)?
            .layer::<Sctp>()
            .expect("IPv4 SCTP layer")
            .checksum_status(),
        SctpChecksumStatus::Valid
    );

    let ipv6 = (Ipv6::new().src(DOC_V6_SRC).dst(DOC_V6_DST)
        / Sctp::data(0x5555_5555, 9, 10, 0x0d0e_0f10, b"ipv6-checksum".to_vec())
            .sport(15_300)
            .dport(15_301)
            .vtag(0x5060_7080))
    .compile()?;
    let ipv6_bytes = ipv6.as_bytes();

    assert_eq!(ipv6_bytes[6], IPPROTO_SCTP);
    assert_ne!(sctp_checksum(ipv6_bytes, IPV6_SCTP_OFFSET), 0);
    assert_eq!(
        Packet::decode_from_l3(NetworkLayer::Ipv6, ipv6_bytes)?
            .layer::<Sctp>()
            .expect("IPv6 SCTP layer")
            .checksum_status(),
        SctpChecksumStatus::Valid
    );

    Ok(())
}

#[test]
fn sctp_checksum_override_preserves_wrong_nonzero_values() -> crafter::Result<()> {
    let ipv4_sctp = Sctp::data(0xaaaa_0001, 11, 12, 0x1111_1111, b"wrong-v4".to_vec())
        .sport(15_400)
        .dport(15_401)
        .vtag(0x1111_2222);
    let ipv4_auto = (Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST) / ipv4_sctp.clone()).compile()?;
    let mut ipv4_wrong = sctp_checksum(ipv4_auto.as_bytes(), IPV4_SCTP_OFFSET) ^ 0xffff_ffff;
    if ipv4_wrong == 0 {
        ipv4_wrong = 1;
    }
    let ipv4_override =
        (Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST) / ipv4_sctp.checksum(ipv4_wrong)).compile()?;
    let ipv4_bytes = ipv4_override.as_bytes();

    assert_eq!(sctp_checksum(ipv4_bytes, IPV4_SCTP_OFFSET), ipv4_wrong);
    assert_ne!(
        sctp_checksum(ipv4_bytes, IPV4_SCTP_OFFSET),
        sctp_checksum(ipv4_auto.as_bytes(), IPV4_SCTP_OFFSET)
    );
    assert_eq!(
        Packet::decode_from_l3(NetworkLayer::Ipv4, ipv4_bytes)?
            .layer::<Sctp>()
            .expect("IPv4 SCTP layer")
            .checksum_status(),
        SctpChecksumStatus::Invalid
    );

    let ipv6_sctp = Sctp::data(0xbbbb_0002, 13, 14, 0x2222_2222, b"wrong-v6".to_vec())
        .sport(15_500)
        .dport(15_501)
        .vtag(0x3333_4444);
    let ipv6_auto = (Ipv6::new().src(DOC_V6_SRC).dst(DOC_V6_DST) / ipv6_sctp.clone()).compile()?;
    let mut ipv6_wrong = sctp_checksum(ipv6_auto.as_bytes(), IPV6_SCTP_OFFSET) ^ 0xffff_ffff;
    if ipv6_wrong == 0 {
        ipv6_wrong = 1;
    }
    let ipv6_override =
        (Ipv6::new().src(DOC_V6_SRC).dst(DOC_V6_DST) / ipv6_sctp.checksum(ipv6_wrong)).compile()?;
    let ipv6_bytes = ipv6_override.as_bytes();

    assert_eq!(sctp_checksum(ipv6_bytes, IPV6_SCTP_OFFSET), ipv6_wrong);
    assert_ne!(
        sctp_checksum(ipv6_bytes, IPV6_SCTP_OFFSET),
        sctp_checksum(ipv6_auto.as_bytes(), IPV6_SCTP_OFFSET)
    );
    assert_eq!(
        Packet::decode_from_l3(NetworkLayer::Ipv6, ipv6_bytes)?
            .layer::<Sctp>()
            .expect("IPv6 SCTP layer")
            .checksum_status(),
        SctpChecksumStatus::Invalid
    );

    Ok(())
}

#[test]
fn sctp_checksum_override_preserves_zero_value() -> crafter::Result<()> {
    let bytes = (Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST)
        / Sctp::data(0xcccc_0003, 15, 16, 0x3333_3333, b"zero".to_vec())
            .sport(15_600)
            .dport(15_601)
            .vtag(0x5555_6666)
            .checksum(0))
    .compile()?;
    let wire = bytes.as_bytes();

    assert_eq!(sctp_checksum(wire, IPV4_SCTP_OFFSET), 0);
    assert_eq!(
        Packet::decode_from_l3(NetworkLayer::Ipv4, wire)?
            .layer::<Sctp>()
            .expect("SCTP layer")
            .checksum_status(),
        SctpChecksumStatus::ZeroChecksum
    );

    Ok(())
}
