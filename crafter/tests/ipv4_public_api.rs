//! Public-surface baseline tests for the IPv4 layer.
//!
//! These tests pin the current construction, compile, decode, summary, show,
//! and typed access behavior used by generated tools through
//! `crafter::prelude::*`. They stay fully offline and use documentation address
//! space only.

use std::net::Ipv4Addr;

use crafter::prelude::*;
use crafter::protocols::{Dscp as ProtocolDscp, Ecn as ProtocolEcn};
use crafter::{Dscp as RootDscp, Ecn as RootEcn};

const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

const EXPECTED_BYTES: &[u8] = &[
    0x45, 0x2e, 0x00, 0x18, 0x12, 0x34, 0x40, 0x00, 0x2a, 0x00, 0x52, 0x32, 0xc0, 0x00, 0x02, 0x0a,
    0xc6, 0x33, 0x64, 0x14, b'i', b'p', b'v', b'4',
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

fn read_u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn ones_complement_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);

    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

fn assert_dscp_ecn_roundtrip(
    name: &str,
    packet: Packet,
    expected_ds_field: u8,
    expected_dscp: Dscp,
    expected_ecn: Ecn,
) -> crafter::Result<()> {
    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();
    assert_eq!(bytes[1], expected_ds_field, "{name} wire ds field");

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
    let ipv4 = decoded.layer::<Ipv4>().expect("ipv4 layer");
    assert_eq!(ipv4.ds_field_value(), expected_ds_field, "{name} ds field");
    assert_eq!(ipv4.tos_value(), expected_ds_field, "{name} tos alias");
    assert_eq!(ipv4.dscp_value(), expected_dscp, "{name} dscp");
    assert_eq!(ipv4.ecn_value(), expected_ecn, "{name} ecn");

    let recompiled = decoded.compile()?;
    assert_eq!(recompiled.as_bytes(), bytes, "{name} recompiled bytes");
    Ok(())
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

#[test]
fn ipv4_autofills_header_fields_for_icmp_tcp_udp_stacks() -> crafter::Result<()> {
    let cases = vec![
        (
            "icmp",
            IPPROTO_ICMP,
            6,
            32,
            Ipv4::new()
                .src(DOC_SRC)
                .dst(DOC_DST)
                .option([IPV4_OPTION_NOP])
                / Icmpv4::echo_request().id(0x1001).seq(1),
        ),
        (
            "tcp",
            IPPROTO_TCP,
            5,
            40,
            Ipv4::new().src(DOC_SRC).dst(DOC_DST) / Tcp::new().sport(40000).dport(443).syn(),
        ),
        (
            "udp",
            IPPROTO_UDP,
            5,
            28,
            Ipv4::new().src(DOC_SRC).dst(DOC_DST) / Udp::new().sport(53000).dport(53),
        ),
    ];

    for (name, expected_protocol, expected_ihl, expected_total_length, packet) in cases {
        let compiled = packet.compile()?;
        let bytes = compiled.as_bytes();
        let expected_header_len = expected_ihl as usize * 4;

        assert_eq!(bytes[0] >> 4, 4, "{name} version");
        assert_eq!(bytes[0] & 0x0f, expected_ihl, "{name} ihl");
        assert_eq!(
            read_u16_at(bytes, 2),
            expected_total_length,
            "{name} total length"
        );
        assert_eq!(compiled.len(), expected_total_length as usize, "{name} len");
        assert_eq!(bytes[9], expected_protocol, "{name} protocol");
        assert_eq!(
            ones_complement_checksum(&bytes[..expected_header_len]),
            0,
            "{name} ipv4 header checksum"
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
        let ipv4 = decoded.layer::<Ipv4>().expect("ipv4 layer");
        assert_eq!(ipv4.ihl_value(), expected_ihl, "{name} decoded ihl");
        assert_eq!(
            ipv4.header_len(),
            expected_header_len,
            "{name} decoded header length"
        );
        assert_eq!(
            ipv4.total_length_value(),
            Some(expected_total_length),
            "{name} decoded total length"
        );
        assert_eq!(
            ipv4.protocol_value(),
            expected_protocol,
            "{name} decoded protocol"
        );
        assert_eq!(
            ipv4.checksum_value(),
            Some(read_u16_at(bytes, 10)),
            "{name} decoded checksum"
        );
    }

    Ok(())
}

#[test]
fn ipv4_preserves_explicit_compile_overrides_that_fit_wire_fields() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_DST)
        .ihl(15)
        .tos(0xff)
        .total_length(0xffff)
        .identification(0xffff)
        .flags(0b111)
        .fragment_offset(0x1fff)
        .protocol(0xff)
        .checksum(0xffff)
        / Udp::new().sport(49152).dport(33434);

    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(bytes[0] >> 4, 4, "version");
    assert_eq!(bytes[0] & 0x0f, 15, "ihl");
    assert_eq!(bytes[1], 0xff, "tos/ds field");
    assert_eq!(read_u16_at(bytes, 2), 0xffff, "total length");
    assert_eq!(read_u16_at(bytes, 4), 0xffff, "identification");
    assert_eq!(bytes[6] >> 5, 0b111, "flags");
    assert_eq!(read_u16_at(bytes, 6) & 0x1fff, 0x1fff, "fragment offset");
    assert_eq!(bytes[9], 0xff, "protocol");
    assert_eq!(read_u16_at(bytes, 10), 0xffff, "checksum");
    assert_eq!(
        compiled.len(),
        68,
        "compiled bytes are not truncated to total length"
    );
    assert_eq!(&bytes[20..60], &[0; 40], "explicit ihl pads header bytes");

    Ok(())
}

#[test]
fn dscp_ecn_roundtrip_common_dscp_values() -> crafter::Result<()> {
    let cases = [
        ("default", 0),
        ("cs1", 8),
        ("af11", 10),
        ("af21", 18),
        ("af31", 26),
        ("af41", 34),
        ("ef", 46),
    ];

    for (name, dscp_value) in cases {
        let dscp = Dscp::new(dscp_value)?;
        let packet = Ipv4::new()
            .src(DOC_SRC)
            .dst(DOC_DST)
            .ecn(Ecn::Ect0)
            .dscp(dscp)
            / Raw::from(name);

        assert_dscp_ecn_roundtrip(name, packet, (dscp_value << 2) | 0x02, dscp, Ecn::Ect0)?;
    }

    Ok(())
}

#[test]
fn dscp_ecn_roundtrip_all_ecn_codepoints() -> crafter::Result<()> {
    let dscp = Dscp::new(46)?;
    let cases = [
        ("not-ect", Ecn::NotEct, 0),
        ("ect1", Ecn::Ect1, 1),
        ("ect0", Ecn::Ect0, 2),
        ("ce", Ecn::Ce, 3),
    ];

    for (name, ecn, ecn_value) in cases {
        let packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST).dscp(dscp).ecn(ecn) / Raw::from(name);

        assert_dscp_ecn_roundtrip(name, packet, (46 << 2) | ecn_value, dscp, ecn)?;
    }

    Ok(())
}

#[test]
fn dscp_ecn_roundtrip_combined_byte_preservation() -> crafter::Result<()> {
    for ds_field in [0x00, 0x01, 0x2e, 0xbb, 0xfc, 0xff] {
        let name = format!("ds-field-0x{ds_field:02x}");
        let packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST).ds_field(ds_field) / Raw::from("ds");

        assert_dscp_ecn_roundtrip(
            &name,
            packet,
            ds_field,
            Dscp::from_ds_field(ds_field),
            Ecn::from_ds_field(ds_field),
        )?;
    }

    Ok(())
}

#[test]
fn dscp_ecn_public_api() -> crafter::Result<()> {
    let dscp = Dscp::new(46)?;
    let packet = Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_DST)
        .ds_field(0xff)
        .dscp(dscp)
        .ecn(Ecn::Ce)
        / Raw::from("api");

    let compiled = packet.compile()?;
    assert_eq!(compiled.as_bytes()[1], 0xbb);
    assert_eq!(RootDscp::new(46)?, dscp);
    assert_eq!(ProtocolDscp::from_ds_field(0xbb), dscp);
    assert_eq!(u8::from(dscp), 46);
    assert_eq!(RootEcn::Ce, Ecn::Ce);
    assert_eq!(ProtocolEcn::from_ds_field(0xbb), Ecn::Ce);
    assert_eq!(u8::from(Ecn::Ce), 3);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let ipv4 = decoded.layer::<Ipv4>().expect("ipv4 layer");
    assert_eq!(ipv4.ds_field_value(), 0xbb);
    assert_eq!(ipv4.dscp_value(), dscp);
    assert_eq!(ipv4.ecn_value(), Ecn::Ce);

    Ok(())
}
