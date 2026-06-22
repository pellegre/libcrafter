//! Committed hex-fixture decode tests for IEEE 802.15.4 / Zigbee frames.
//!
//! Mirrors `crafter/tests/ble_decode.rs` (`#[macro_use] mod support;` +
//! `fixture_str!`). Each fixture in `crafter/tests/fixtures/dot15d4/` holds one
//! full frame as raw hex octets; this test decodes it through the public
//! `Packet::decode_from_link` entrypoint and asserts the decoded layer fields,
//! locking the wire contract for representative frames.

#[macro_use]
mod support;

use crafter::prelude::*;

#[test]
fn dot15d4_hex_fixture_decodes_short_data_frame() {
    // Bare MAC Data frame, short addressing, PAN-ID compression.
    let frame = decode_hex_fixture("mac-data-short", fixture_str!("dot15d4/mac-data-short.hex"));
    let packet = Packet::decode_from_link(LinkType::Ieee802154, &frame)
        .expect("decode bare 802.15.4 short-addressing frame");

    let mac = packet
        .layer::<Dot15d4>()
        .expect("Dot15d4 MAC layer present");
    let fields = mac.inspection_fields();

    assert_eq!(field_value(&fields, "frame_type"), Some("Data"));
    assert_eq!(field_value(&fields, "seq"), Some("42"));
    assert_eq!(field_value(&fields, "dest_addr"), Some("0x0000"));
    assert_eq!(field_value(&fields, "src_addr"), Some("0xABCD"));
    assert_eq!(field_value(&fields, "pan_id_compression"), Some("true"));

    // No Zigbee layers ride on this MAC frame; the raw payload is preserved.
    assert!(
        packet.layer::<ZigbeeNwk>().is_none(),
        "short MAC fixture should carry no Zigbee NWK layer"
    );
}

#[test]
fn dot15d4_hex_fixture_decodes_extended_data_frame() {
    // Bare MAC Data frame, extended addressing + PAN-ID compression.
    let frame = decode_hex_fixture(
        "mac-data-extended",
        fixture_str!("dot15d4/mac-data-extended.hex"),
    );
    let packet = Packet::decode_from_link(LinkType::Ieee802154, &frame)
        .expect("decode bare 802.15.4 extended-addressing frame");

    let mac = packet
        .layer::<Dot15d4>()
        .expect("Dot15d4 MAC layer present");
    let fields = mac.inspection_fields();

    assert_eq!(field_value(&fields, "frame_type"), Some("Data"));
    assert_eq!(field_value(&fields, "seq"), Some("17"));
    assert_eq!(
        field_value(&fields, "dest_addr"),
        Some("0x0011223344556677")
    );
    assert_eq!(
        field_value(&fields, "src_addr"),
        Some("0x8899AABBCCDDEEFF")
    );
    assert_eq!(field_value(&fields, "pan_id_compression"), Some("true"));
}

#[test]
fn dot15d4_hex_fixture_decodes_full_zigbee_nwk_aps_stack() {
    // Full MAC / Zigbee NWK / Zigbee APS Data stack.
    let frame = decode_hex_fixture("zigbee-nwk-aps", fixture_str!("dot15d4/zigbee-nwk-aps.hex"));
    let packet = Packet::decode_from_link(LinkType::Ieee802154, &frame)
        .expect("decode bare 802.15.4 MAC + Zigbee NWK + APS frame");

    // MAC layer.
    let mac = packet
        .layer::<Dot15d4>()
        .expect("Dot15d4 MAC layer present");
    let mac_fields = mac.inspection_fields();
    assert_eq!(field_value(&mac_fields, "frame_type"), Some("Data"));
    assert_eq!(field_value(&mac_fields, "seq"), Some("7"));
    assert_eq!(field_value(&mac_fields, "dest_addr"), Some("0x0000"));
    assert_eq!(field_value(&mac_fields, "src_addr"), Some("0xABCD"));

    // Zigbee NWK layer.
    let nwk = packet
        .layer::<ZigbeeNwk>()
        .expect("ZigbeeNwk layer present");
    let nwk_fields = nwk.inspection_fields();
    assert_eq!(field_value(&nwk_fields, "dest"), Some("0x0000"));
    assert_eq!(field_value(&nwk_fields, "src"), Some("0xabcd"));
    assert_eq!(field_value(&nwk_fields, "radius"), Some("30"));
    assert_eq!(field_value(&nwk_fields, "seq"), Some("66"));

    // Zigbee APS layer.
    let aps = packet
        .layer::<ZigbeeAps>()
        .expect("ZigbeeAps layer present");
    let aps_fields = aps.inspection_fields();
    assert_eq!(field_value(&aps_fields, "cluster"), Some("0x0006"));
    assert_eq!(field_value(&aps_fields, "profile"), Some("0x0104"));
    assert_eq!(field_value(&aps_fields, "dest_endpoint"), Some("1"));
    assert_eq!(field_value(&aps_fields, "src_endpoint"), Some("1"));
    assert_eq!(field_value(&aps_fields, "counter"), Some("9"));
}

/// Look up an inspection field's value by name.
fn field_value<'a>(fields: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(field, _)| *field == name)
        .map(|(_, value)| value.as_str())
}

/// Decode a whitespace- and comment-tolerant hex fixture into raw bytes.
///
/// Mirrors the helper in `ble_decode.rs`: blank lines and `#`-prefixed lines are
/// skipped, all other whitespace is ignored, and the remaining hex digits are
/// paired into octets.
fn decode_hex_fixture(label: &str, text: &str) -> Vec<u8> {
    let mut compact = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        for ch in line.chars().filter(|ch| !ch.is_whitespace()) {
            assert!(
                ch.is_ascii_hexdigit(),
                "hex fixture {label} contains non-hex character {ch:?}"
            );
            compact.push(ch);
        }
    }

    assert!(
        compact.len() % 2 == 0,
        "hex fixture {label} has an odd hex length"
    );

    compact
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk)
                .unwrap_or_else(|_| panic!("hex fixture {label} contains non-UTF8 hex"));
            u8::from_str_radix(byte, 16)
                .unwrap_or_else(|_| panic!("hex fixture {label} has invalid hex byte {byte}"))
        })
        .collect()
}
