//! Public API surface for the IEEE 802.15.4 / Zigbee layers.
//!
//! Every type this test names is imported solely through `crafter::prelude::*`,
//! which proves the new layer types reach downstream tools the same way the BLE
//! types do (crate root -> `protocols::exports` -> `core` -> `prelude`). The
//! test also exercises the build -> compile -> decode round-trip through the
//! public `Packet::decode_from_link` entrypoint.

use crafter::prelude::*;

/// The public `Dot15d4` / `Dot15d4Radio` builder types compose into a TAP
/// radio + MAC packet, compile to bytes, and decode back into the same typed
/// layers with matching addressing fields.
#[test]
fn prelude_dot15d4_tap_round_trip() {
    // All builder types below resolve through `crafter::prelude::*`.
    let radio: Dot15d4Radio = Dot15d4Radio::on_channel(20).rssi(-55);
    let mac: Dot15d4 = Dot15d4::data()
        .seq(9)
        .dest_short(0x1234, 0x0000)
        .src_short(0x1234, 0xABCD);

    // Compose the TAP radio pseudo-header over the MAC frame and compile.
    // `radio / mac` already yields a `Packet`.
    let packet: Packet = radio / mac;
    let bytes = packet
        .compile()
        .expect("compile TAP + MAC packet")
        .as_bytes()
        .to_vec();

    // Decode back through the public link-layer entrypoint.
    let decoded = Packet::decode_from_link(LinkType::Ieee802154Tap, &bytes)
        .expect("decode TAP 802.15.4 frame");

    // Both typed layers are reachable and present after the round-trip.
    let radio_layer = decoded
        .layer::<Dot15d4Radio>()
        .expect("Dot15d4Radio layer present");
    let mac_layer = decoded.layer::<Dot15d4>().expect("Dot15d4 MAC layer present");

    // The radio descriptor preserves the channel.
    assert!(
        radio_layer.summary().contains("ch=20"),
        "radio summary: {}",
        radio_layer.summary()
    );

    // The MAC addressing fields survive the round-trip.
    let mac_summary = mac_layer.summary();
    assert!(mac_summary.contains("Data"), "mac summary: {mac_summary}");
    assert!(mac_summary.contains("seq=9"), "mac summary: {mac_summary}");
    assert!(
        mac_summary.contains("dst=0x0000"),
        "mac summary: {mac_summary}"
    );
    assert!(
        mac_summary.contains("src=0xABCD"),
        "mac summary: {mac_summary}"
    );
}

/// The Zigbee NWK/APS frame-control discriminant types and the MAC frame-type /
/// addressing-mode enums are all importable from the prelude.
#[test]
fn prelude_exposes_zigbee_and_dot15d4_enum_types() {
    // Naming each public type here is the reachability assertion: the test only
    // compiles if every type below resolves through `crafter::prelude::*`.
    let _frame_type: Dot15d4FrameType = Dot15d4FrameType::Data;
    let _addr_mode: Dot15d4AddrMode = Dot15d4AddrMode::Short;

    // The Zigbee NWK and APS layers stack on the MAC payload by `/` composition,
    // which already yields a `Packet`.
    let stack: Packet = Dot15d4::data()
        .seq(1)
        .dest_short(0x1234, 0x0000)
        .src_short(0x1234, 0xABCD)
        / ZigbeeNwk::data().dest(0x0000).src(0xABCD).radius(30).seq(5)
        / ZigbeeAps::data()
            .cluster(0x0006)
            .profile(0x0104)
            .dest_endpoint(1)
            .src_endpoint(1)
            .counter(7)
            .payload(&[0x01, 0x02]);

    let bytes = stack
        .compile()
        .expect("compile bare MAC + Zigbee NWK + APS frame")
        .as_bytes()
        .to_vec();

    let decoded =
        Packet::decode_from_link(LinkType::Ieee802154, &bytes).expect("decode bare 802.15.4 frame");

    assert!(
        decoded.layer::<Dot15d4>().is_some(),
        "Dot15d4 MAC layer present"
    );
    assert!(
        decoded.layer::<ZigbeeNwk>().is_some(),
        "ZigbeeNwk layer present"
    );
    assert!(
        decoded.layer::<ZigbeeAps>().is_some(),
        "ZigbeeAps layer present"
    );
}
