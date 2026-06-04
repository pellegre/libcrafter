//! Public-surface baseline tests for the IPv4 layer.
//!
//! These tests pin the current construction, compile, decode, summary, show,
//! and typed access behavior used by generated tools through
//! `crafter::prelude::*`. They stay fully offline and use documentation address
//! space only.

use std::net::Ipv4Addr;

use crafter::prelude::*;

const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

const EXPECTED_BYTES: &[u8] = &[
    0x45, 0x2e, 0x00, 0x18, 0x12, 0x34, 0x40, 0x00, 0x2a, 0x00, 0x52, 0x32, 0xc0, 0x00, 0x02,
    0x0a, 0xc6, 0x33, 0x64, 0x14, b'i', b'p', b'v', b'4',
];

fn ipv4_raw_packet() -> Packet {
    Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_DST)
        .tos(0x2e)
        .id(0x1234)
        .dont_fragment(true)
        .ttl(42)
        / Raw::from("ipv4")
}

#[test]
fn ipv4_new_with_raw_compiles_to_current_wire_header() -> crafter::Result<()> {
    let packet = ipv4_raw_packet();
    let compiled = packet.compile()?;

    assert_eq!(compiled.as_bytes(), EXPECTED_BYTES);
    assert_eq!(compiled.len(), 24);
    assert!(!compiled.is_empty());
    Ok(())
}

#[test]
fn ipv4_decode_from_l3_returns_typed_ipv4_and_raw_tail() -> crafter::Result<()> {
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, EXPECTED_BYTES)?;

    assert_eq!(decoded.len(), 2);

    let ipv4 = decoded.layer::<Ipv4>().expect("ipv4 layer");
    assert_eq!(ipv4.version_value(), 4);
    assert_eq!(ipv4.ihl_value(), 5);
    assert_eq!(ipv4.header_len(), 20);
    assert_eq!(ipv4.tos_value(), 0x2e);
    assert_eq!(ipv4.total_length_value(), Some(24));
    assert_eq!(ipv4.identification_value(), 0x1234);
    assert_eq!(ipv4.flags_value(), IPV4_FLAG_DONT_FRAGMENT);
    assert!(ipv4.is_dont_fragment());
    assert!(!ipv4.has_more_fragments());
    assert_eq!(ipv4.fragment_offset_value(), 0);
    assert_eq!(ipv4.ttl_value(), 42);
    assert_eq!(ipv4.protocol_value(), 0);
    assert_eq!(ipv4.checksum_value(), Some(0x5232));
    assert_eq!(ipv4.source(), DOC_SRC);
    assert_eq!(ipv4.destination(), DOC_DST);
    assert_eq!(ipv4.option_bytes(), &[] as &[u8]);

    let raw = decoded.layer::<Raw>().expect("raw layer");
    assert_eq!(raw.as_bytes(), b"ipv4");
    assert_eq!(decoded.compile()?.as_bytes(), EXPECTED_BYTES);
    Ok(())
}

#[test]
fn ipv4_summary_and_show_pin_current_public_inspection() -> crafter::Result<()> {
    let packet = ipv4_raw_packet();

    assert_eq!(
        packet.summary(),
        "Ipv4(src=192.0.2.10, dst=198.51.100.20, proto=hopopt(0)) / Raw(len=4)"
    );

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, packet.compile()?.as_bytes())?;

    assert_eq!(
        decoded.show(),
        concat!(
            "Packet(len=24, layers=2)\n",
            "  [0] Ipv4\n",
            "      version: 4\n",
            "      ihl: 5\n",
            "      tos: 46\n",
            "      total_length: 24\n",
            "      id: 0x1234\n",
            "      flags: DF\n",
            "      fragment_offset: 0\n",
            "      ttl: 42\n",
            "      protocol: hopopt(0)\n",
            "      checksum: 0x5232\n",
            "      src: 192.0.2.10\n",
            "      dst: 198.51.100.20\n",
            "      options: \n",
            "  [1] Raw\n",
            "      len: 4\n",
            "      bytes: 69 70 76 34\n",
            "      text_lossy: \"ipv4\"",
        )
    );
    Ok(())
}
