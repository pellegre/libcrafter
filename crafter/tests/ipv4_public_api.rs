//! Public-surface baseline tests for the IPv4 layer.
//!
//! These tests pin the current construction, compile, decode, summary, show,
//! and typed access behavior used by generated tools through
//! `crafter::prelude::*`. They stay fully offline and use documentation address
//! space only.

use std::net::Ipv4Addr;

use crafter::prelude::*;
use crafter::protocols::ip::Ipv4ChecksumStatus;
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

fn write_u16_at(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
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

fn assert_ttl_roundtrip(
    name: &str,
    packet: Packet,
    expected_ttl: u8,
    expected_raw_len: usize,
) -> crafter::Result<()> {
    let expected_summary = format!(
        "Ipv4(src={DOC_SRC}, dst={DOC_DST}, proto=hopopt(0)) / Raw(len={expected_raw_len})"
    );

    assert_eq!(packet.summary(), expected_summary, "{name} summary");

    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();
    assert_eq!(bytes[8], expected_ttl, "{name} wire ttl");

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
    let ipv4 = decoded.layer::<Ipv4>().expect("ipv4 layer");
    assert_eq!(ipv4.ttl_value(), expected_ttl, "{name} decoded ttl");
    assert_eq!(
        decoded.summary(),
        expected_summary,
        "{name} decoded summary"
    );

    let show = decoded.show();
    assert!(
        show.contains(&format!("      ttl: {expected_ttl}\n")),
        "{name} show output should include ttl {expected_ttl}:\n{show}"
    );

    let recompiled = decoded.compile()?;
    assert_eq!(recompiled.as_bytes(), bytes, "{name} recompiled bytes");

    Ok(())
}

fn assert_fragment_fields_roundtrip(
    name: &str,
    ipv4: Ipv4,
    expected_identification: u16,
    expected_flags: u8,
    expected_fragment_offset: u16,
) -> crafter::Result<()> {
    let payload = format!("fragment-fields-{name}");
    let packet = ipv4 / Raw::from(payload.as_str());
    let expected_flags_fragment = ((expected_flags as u16) << 13) | expected_fragment_offset;

    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();
    assert_eq!(
        read_u16_at(bytes, 4),
        expected_identification,
        "{name} wire identification"
    );
    assert_eq!(
        read_u16_at(bytes, 6),
        expected_flags_fragment,
        "{name} wire flags and fragment offset"
    );

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;
    let ipv4 = decoded.layer::<Ipv4>().expect("ipv4 layer");
    let fragment_info = ipv4.fragment_info();
    let expected_fragmented =
        expected_flags & IPV4_FLAG_MORE_FRAGMENTS != 0 || expected_fragment_offset != 0;

    assert_eq!(
        ipv4.identification_value(),
        expected_identification,
        "{name} decoded identification"
    );
    assert_eq!(ipv4.flags_value(), expected_flags, "{name} decoded flags");
    assert_eq!(
        ipv4.fragment_offset_value(),
        expected_fragment_offset,
        "{name} decoded fragment offset"
    );
    assert_eq!(
        fragment_info.identification(),
        expected_identification,
        "{name} fragment info identification"
    );
    assert_eq!(
        fragment_info.flags(),
        expected_flags,
        "{name} fragment info flags"
    );
    assert_eq!(
        fragment_info.fragment_offset(),
        expected_fragment_offset,
        "{name} fragment info offset"
    );
    assert_eq!(
        ipv4.is_reserved_flag_set(),
        expected_flags & IPV4_FLAG_RESERVED != 0,
        "{name} reserved flag accessor"
    );
    assert_eq!(
        ipv4.is_dont_fragment(),
        expected_flags & IPV4_FLAG_DONT_FRAGMENT != 0,
        "{name} DF accessor"
    );
    assert_eq!(
        ipv4.has_more_fragments(),
        expected_flags & IPV4_FLAG_MORE_FRAGMENTS != 0,
        "{name} MF accessor"
    );
    assert_eq!(
        ipv4.is_fragmented(),
        expected_fragmented,
        "{name} fragmented accessor"
    );
    assert_eq!(
        fragment_info.is_fragmented(),
        expected_fragmented,
        "{name} fragment info fragmented accessor"
    );
    assert_eq!(
        decoded.layer::<Raw>().expect("raw layer").as_bytes(),
        payload.as_bytes(),
        "{name} raw payload"
    );

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
fn fragment_fields_roundtrip_supported_flags_and_offsets() -> crafter::Result<()> {
    assert_fragment_fields_roundtrip(
        "df-zero-offset",
        Ipv4::new()
            .src(DOC_SRC)
            .dst(DOC_DST)
            .id(0x1001)
            .dont_fragment(true)
            .fragment_offset(0),
        0x1001,
        IPV4_FLAG_DONT_FRAGMENT,
        0,
    )?;

    assert_fragment_fields_roundtrip(
        "mf-zero-offset",
        Ipv4::new()
            .src(DOC_SRC)
            .dst(DOC_DST)
            .id(0x1002)
            .more_fragments(true)
            .fragment_offset(0),
        0x1002,
        IPV4_FLAG_MORE_FRAGMENTS,
        0,
    )?;

    assert_fragment_fields_roundtrip(
        "reserved-zero-offset",
        Ipv4::new()
            .src(DOC_SRC)
            .dst(DOC_DST)
            .identification(0x1003)
            .reserved_flag(true)
            .frag(0),
        0x1003,
        IPV4_FLAG_RESERVED,
        0,
    )?;

    assert_fragment_fields_roundtrip(
        "combined-raw-flags",
        Ipv4::new()
            .src(DOC_SRC)
            .dst(DOC_DST)
            .id(0x1004)
            .flags(IPV4_FLAG_RESERVED | IPV4_FLAG_DONT_FRAGMENT | IPV4_FLAG_MORE_FRAGMENTS)
            .fragment_offset(0x0123),
        0x1004,
        IPV4_FLAG_RESERVED | IPV4_FLAG_DONT_FRAGMENT | IPV4_FLAG_MORE_FRAGMENTS,
        0x0123,
    )?;

    assert_fragment_fields_roundtrip(
        "maximum-offset",
        Ipv4::new()
            .src(DOC_SRC)
            .dst(DOC_DST)
            .id(0x1005)
            .frag(0x1fff),
        0x1005,
        0,
        0x1fff,
    )?;

    Ok(())
}

#[test]
fn fragment_fields_reject_invalid_offset() {
    let packet = Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_DST)
        .id(0x1006)
        .fragment_offset(0x2000)
        / Raw::from("bad-offset");

    match packet.compile() {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, "ipv4.fragment_offset");
            assert_eq!(reason, "fragment offset must fit in 13 bits");
        }
        other => panic!("invalid fragment offset should be rejected, got {other:?}"),
    }
}

#[test]
fn ipv4_ttl_default_explicit_zero_decode_summary_and_show() -> crafter::Result<()> {
    let default_ipv4 = Ipv4::new().src(DOC_SRC).dst(DOC_DST);
    assert_eq!(default_ipv4.ttl_value(), 64, "default ipv4 ttl");
    assert_ttl_roundtrip("default", default_ipv4 / Raw::from("ttl-default"), 64, 11)?;

    let cases = [
        ("zero", 0, "ttl-zero"),
        ("one", 1, "ttl-one"),
        ("sixty-four", 64, "ttl-sixty-four"),
        ("max", 255, "ttl-max"),
    ];

    for (name, ttl, payload) in cases {
        let ipv4 = Ipv4::new().src(DOC_SRC).dst(DOC_DST).ttl(ttl);
        assert_eq!(ipv4.ttl_value(), ttl, "{name} builder ttl");
        assert_ttl_roundtrip(name, ipv4 / Raw::from(payload), ttl, payload.len())?;
    }

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
fn ipv4_checksum_status_invalid_decode_summary_and_show() -> crafter::Result<()> {
    let mut bytes = EXPECTED_BYTES.to_vec();
    bytes[10] ^= 0xff;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes)?;
    let ipv4 = decoded.layer::<Ipv4>().expect("ipv4 layer");

    assert_eq!(ipv4.checksum_value(), Some(read_u16_at(&bytes, 10)));
    assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Invalid);
    assert_eq!(
        decoded.layer::<Raw>().expect("raw layer").as_bytes(),
        b"ipv4"
    );

    let summary = decoded.summary();
    assert!(
        summary.contains("checksum_status=invalid"),
        "summary should expose invalid checksum status:\n{summary}"
    );

    let show = decoded.show();
    assert!(
        show.contains("      checksum_status: invalid\n"),
        "show output should expose invalid checksum status:\n{show}"
    );

    assert_eq!(decoded.compile()?.as_bytes(), bytes);
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
fn ipv4_protocol_autofill_for_icmp_tcp_udp_and_raw_stacks() -> crafter::Result<()> {
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
        (
            "raw",
            0,
            5,
            23,
            Ipv4::new().src(DOC_SRC).dst(DOC_DST) / Raw::from("raw"),
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
fn option_kind_public_api_reexports_metadata_and_constants() {
    const PRELUDE_KIND: Ipv4OptionKind = Ipv4OptionKind::new(IPV4_OPTION_ROUTER_ALERT);
    const PRELUDE_METADATA: (u8, bool, u8, u8) = (
        PRELUDE_KIND.value(),
        PRELUDE_KIND.copied(),
        PRELUDE_KIND.class(),
        PRELUDE_KIND.number(),
    );
    const EXPECTED_OPTION_CONSTANTS: [u8; 6] = [0x44, 0x94, 30, 94, 158, 222];

    assert_eq!(PRELUDE_METADATA, (0x94, true, 0, 20));
    assert_eq!(
        [
            IPV4_OPTION_TIMESTAMP,
            IPV4_OPTION_ROUTER_ALERT,
            IPV4_OPTION_EXPERIMENTAL_1,
            IPV4_OPTION_EXPERIMENTAL_2,
            IPV4_OPTION_EXPERIMENTAL_3,
            IPV4_OPTION_EXPERIMENTAL_4,
        ],
        EXPECTED_OPTION_CONSTANTS
    );
    assert_eq!(
        [
            crafter::IPV4_OPTION_TIMESTAMP,
            crafter::IPV4_OPTION_ROUTER_ALERT,
            crafter::IPV4_OPTION_EXPERIMENTAL_1,
            crafter::IPV4_OPTION_EXPERIMENTAL_2,
            crafter::IPV4_OPTION_EXPERIMENTAL_3,
            crafter::IPV4_OPTION_EXPERIMENTAL_4,
        ],
        EXPECTED_OPTION_CONSTANTS
    );
    assert_eq!(
        [
            crafter::core::IPV4_OPTION_TIMESTAMP,
            crafter::core::IPV4_OPTION_ROUTER_ALERT,
            crafter::core::IPV4_OPTION_EXPERIMENTAL_1,
            crafter::core::IPV4_OPTION_EXPERIMENTAL_2,
            crafter::core::IPV4_OPTION_EXPERIMENTAL_3,
            crafter::core::IPV4_OPTION_EXPERIMENTAL_4,
        ],
        EXPECTED_OPTION_CONSTANTS
    );
    assert_eq!(
        [
            crafter::protocols::IPV4_OPTION_TIMESTAMP,
            crafter::protocols::IPV4_OPTION_ROUTER_ALERT,
            crafter::protocols::IPV4_OPTION_EXPERIMENTAL_1,
            crafter::protocols::IPV4_OPTION_EXPERIMENTAL_2,
            crafter::protocols::IPV4_OPTION_EXPERIMENTAL_3,
            crafter::protocols::IPV4_OPTION_EXPERIMENTAL_4,
        ],
        EXPECTED_OPTION_CONSTANTS
    );

    let root_kind = crafter::Ipv4OptionKind::from(crafter::IPV4_OPTION_TIMESTAMP);
    let core_kind = crafter::core::Ipv4OptionKind::new(crafter::core::IPV4_OPTION_EXPERIMENTAL_4);
    let protocols_kind =
        crafter::protocols::Ipv4OptionKind::new(crafter::protocols::IPV4_OPTION_EXPERIMENTAL_3);

    assert_eq!(
        (
            root_kind.value(),
            root_kind.copied(),
            root_kind.class(),
            root_kind.number()
        ),
        (0x44, false, 2, 4)
    );
    assert_eq!(
        (
            core_kind.value(),
            core_kind.copied(),
            core_kind.class(),
            core_kind.number()
        ),
        (222, true, 2, 30)
    );
    assert_eq!(
        (
            protocols_kind.value(),
            protocols_kind.copied(),
            protocols_kind.class(),
            protocols_kind.number()
        ),
        (158, true, 0, 30)
    );
    assert_eq!(u8::from(root_kind), crafter::IPV4_OPTION_TIMESTAMP);
}

#[test]
fn ipv4_protocol_autofill_preserves_explicit_compile_overrides() -> crafter::Result<()> {
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
fn ipv4_length_boundaries_accept_header_payload_and_trailing_bytes() -> crafter::Result<()> {
    let header_only =
        Packet::from_layer(Ipv4::new().src(DOC_SRC).dst(DOC_DST).ttl(32)).compile()?;
    let header_only_bytes = header_only.as_bytes();
    assert_eq!(header_only_bytes.len(), 20);
    assert_eq!(read_u16_at(header_only_bytes, 2), 20);

    let decoded_header_only = Packet::decode_from_l3(NetworkLayer::Ipv4, header_only_bytes)?;
    assert_eq!(decoded_header_only.len(), 1);
    let ipv4 = decoded_header_only.layer::<Ipv4>().expect("ipv4 layer");
    assert_eq!(ipv4.header_len(), 20);
    assert_eq!(ipv4.total_length_value(), Some(20));
    assert!(decoded_header_only.layer::<Raw>().is_none());
    assert_eq!(decoded_header_only.compile()?.as_bytes(), header_only_bytes);

    let with_payload =
        (Ipv4::new().src(DOC_SRC).dst(DOC_DST).ttl(33) / Raw::from("data")).compile()?;
    let with_payload_bytes = with_payload.as_bytes();
    assert_eq!(with_payload_bytes.len(), 24);
    assert_eq!(read_u16_at(with_payload_bytes, 2), 24);

    let decoded_with_payload = Packet::decode_from_l3(NetworkLayer::Ipv4, with_payload_bytes)?;
    assert_eq!(decoded_with_payload.len(), 2);
    let ipv4 = decoded_with_payload.layer::<Ipv4>().expect("ipv4 layer");
    assert_eq!(ipv4.header_len(), 20);
    assert_eq!(ipv4.total_length_value(), Some(24));
    assert_eq!(
        decoded_with_payload
            .layer::<Raw>()
            .expect("raw payload")
            .as_bytes(),
        b"data"
    );
    assert_eq!(
        decoded_with_payload.compile()?.as_bytes(),
        with_payload_bytes
    );

    let mut with_trailing = with_payload_bytes.to_vec();
    with_trailing.extend_from_slice(b"tail");
    let decoded_with_trailing = Packet::decode_from_l3(NetworkLayer::Ipv4, &with_trailing)?;
    assert_eq!(decoded_with_trailing.len(), 3);
    let ipv4 = decoded_with_trailing.layer::<Ipv4>().expect("ipv4 layer");
    assert_eq!(ipv4.header_len(), 20);
    assert_eq!(ipv4.total_length_value(), Some(24));
    let raw_layers: Vec<_> = decoded_with_trailing
        .layers::<Raw>()
        .map(Raw::as_bytes)
        .collect();
    assert_eq!(raw_layers, vec![b"data".as_slice(), b"tail".as_slice()]);
    assert_eq!(decoded_with_trailing.compile()?.as_bytes(), with_trailing);

    Ok(())
}

#[test]
fn ipv4_length_boundaries_reject_inconsistent_total_lengths() -> crafter::Result<()> {
    let header_only =
        Packet::from_layer(Ipv4::new().src(DOC_SRC).dst(DOC_DST).ttl(34)).compile()?;

    let mut below_header = header_only.as_bytes().to_vec();
    write_u16_at(&mut below_header, 2, 19);
    match Packet::decode_from_l3(NetworkLayer::Ipv4, &below_header) {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, "ipv4.total_length");
            assert_eq!(
                reason,
                "total length must be at least the IPv4 header length"
            );
        }
        other => panic!("total length below header should return InvalidFieldValue, got {other:?}"),
    }

    let mut larger_than_available = header_only.as_bytes().to_vec();
    write_u16_at(&mut larger_than_available, 2, 21);
    match Packet::decode_from_l3(NetworkLayer::Ipv4, &larger_than_available) {
        Err(CrafterError::BufferTooShort {
            context,
            required,
            available,
        }) => {
            assert_eq!(context, "ipv4 packet");
            assert_eq!(required, 21);
            assert_eq!(available, larger_than_available.len());
            assert!(required > available);
        }
        other => {
            panic!("total length larger than available should return BufferTooShort, got {other:?}")
        }
    }

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
