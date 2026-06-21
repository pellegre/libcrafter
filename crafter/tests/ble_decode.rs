#[macro_use]
mod support;

use std::fs;

use crafter::core::{CrafterError, LayerContext, LinkType, Packet, Result};
use crafter::{BleLlAdv, Layer, MacAddr};

#[test]
fn ble_hex_fixtures_decode_representative_advertisements() -> Result<()> {
    assert_ble_fixture(
        "adv_ind_flags_name",
        fixture_str!("ble/adv_ind_flags_name.hex"),
        "ADV_IND",
        MacAddr::new([0xc2, 0x00, 0x5e, 0x00, 0x53, 0x47]),
        &[
            "AdStructure { ad_type: 1, data: [6], length_override: None }",
            "AdStructure { ad_type: 9, data: [99, 114, 97, 102, 116, 101, 114, 45, 97, 100, 118], length_override: None }",
        ],
    )?;
    assert_ble_fixture(
        "adv_nonconn_ind_mfg_data",
        fixture_str!("ble/adv_nonconn_ind_mfg_data.hex"),
        "ADV_NONCONN_IND",
        MacAddr::new([0xc2, 0x00, 0x5e, 0x00, 0x53, 0x48]),
        &["AdStructure { ad_type: 255, data: [255, 255, 1, 2, 3, 4], length_override: None }"],
    )?;
    assert_ble_fixture(
        "scan_rsp_name",
        fixture_str!("ble/scan_rsp_name.hex"),
        "SCAN_RSP",
        MacAddr::new([0xc2, 0x00, 0x5e, 0x00, 0x53, 0x49]),
        &["AdStructure { ad_type: 9, data: [99, 114, 97, 102, 116, 101, 114, 45, 115, 99, 97, 110], length_override: None }"],
    )
}

#[test]
fn public_decode_from_link_decodes_ble_advertising_frame() -> Result<()> {
    let frame = ble_advertising_frame();
    let packet = Packet::decode_from_link(LinkType::BluetoothLeLl, &frame)?;

    let layer_names = packet.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    assert_eq!(layer_names, vec!["BleRadio", "BleLlAdv"]);

    let radio = packet.get(0).expect("decoded radio layer");
    let radio_summary = radio.summary();
    assert!(radio_summary.contains("ch=37"), "{radio_summary}");
    assert!(radio_summary.contains("aa=0x8e89bed6"), "{radio_summary}");

    let radio_fields = radio.inspection_fields();
    assert_eq!(field_value(&radio_fields, "channel"), Some("37"));
    assert_eq!(
        field_value(&radio_fields, "access_address"),
        Some("0x8e89bed6")
    );

    let adv = packet.get(1).expect("decoded advertising layer");
    let adv_summary = adv.summary();
    assert!(adv_summary.contains("ADV_IND"), "{adv_summary}");
    assert!(
        adv_summary.contains("AdvA=C0:FF:EE:11:22:33"),
        "{adv_summary}"
    );
    assert!(adv_summary.contains("len=25"), "{adv_summary}");

    let adv_fields = adv.inspection_fields();
    assert_eq!(field_value(&adv_fields, "pdu_type"), Some("ADV_IND"));
    assert_eq!(field_value(&adv_fields, "adv_a"), Some("C0:FF:EE:11:22:33"));
    assert_eq!(field_value(&adv_fields, "length"), Some("25"));

    let mut compiled_adv = Vec::new();
    adv.compile(&LayerContext::new(&packet, 1), &mut compiled_adv)?;
    assert_eq!(compiled_adv, expected_advertising_pdu());

    Ok(())
}

#[test]
fn ble_summary_golden_snapshots_match_hex_fixtures() -> Result<()> {
    assert_ble_summary_fixture(
        "adv_ind_flags_name",
        fixture_str!("ble/adv_ind_flags_name.hex"),
        "summaries/ble-adv_ind_flags_name.summary.txt",
    )?;
    assert_ble_summary_fixture(
        "adv_nonconn_ind_mfg_data",
        fixture_str!("ble/adv_nonconn_ind_mfg_data.hex"),
        "summaries/ble-adv_nonconn_ind_mfg_data.summary.txt",
    )?;
    assert_ble_summary_fixture(
        "scan_rsp_name",
        fixture_str!("ble/scan_rsp_name.hex"),
        "summaries/ble-scan_rsp_name.summary.txt",
    )
}

#[test]
fn public_decode_from_link_reports_truncated_ble_access_address() {
    let frame = [
        37, 0xc4, 0x00, 0x00, 0xd6, 0xbe, 0x89, 0x8e, 0x13, 0x0c, 0xd6, 0xbe, 0x89,
    ];

    let err = Packet::decode_from_link(LinkType::BluetoothLeLl, frame)
        .expect_err("truncated LL access address must be rejected");
    assert_eq!(
        err,
        CrafterError::BufferTooShort {
            context: "ble.ll.access_address",
            required: 4,
            available: 3,
        }
    );
}

fn ble_advertising_frame() -> Vec<u8> {
    let mut frame = vec![
        37, 0xc4, 0x00, 0x00, 0xd6, 0xbe, 0x89, 0x8e, 0x13, 0x0c, 0xd6, 0xbe, 0x89, 0x8e,
    ];
    frame.extend_from_slice(&expected_advertising_pdu());
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    frame
}

fn expected_advertising_pdu() -> Vec<u8> {
    let mut pdu = vec![
        0x40, 25, 0x33, 0x22, 0x11, 0xee, 0xff, 0xc0, 0x02, 0x01, 0x06, 0x0f, 0x09,
    ];
    pdu.extend_from_slice(b"libcrafter-nrf");
    pdu
}

fn field_value<'a>(fields: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(field, _)| *field == name)
        .map(|(_, value)| value.as_str())
}

fn assert_ble_fixture(
    label: &str,
    hex: &str,
    expected_pdu_type: &str,
    expected_adv_a: MacAddr,
    expected_ad_debug: &[&str],
) -> Result<()> {
    let frame = decode_hex_fixture(label, hex);
    let packet = Packet::decode_from_link(LinkType::BluetoothLeLl, &frame)?;
    let adv = packet
        .layer::<BleLlAdv>()
        .unwrap_or_else(|| panic!("{label} should decode a BleLlAdv layer"));

    let fields = adv.inspection_fields();
    assert_eq!(field_value(&fields, "pdu_type"), Some(expected_pdu_type));
    assert_eq!(adv.adv_a_value(), Some(expected_adv_a));

    let adv_debug = format!("{adv:?}");
    for needle in expected_ad_debug {
        assert!(
            adv_debug.contains(needle),
            "{label} decoded AD fields should contain {needle}: {adv_debug}"
        );
    }

    Ok(())
}

fn assert_ble_summary_fixture(label: &str, hex: &str, summary_path: &str) -> Result<()> {
    let frame = decode_hex_fixture(label, hex);
    let packet = Packet::decode_from_link(LinkType::BluetoothLeLl, &frame)?;
    let expected = read_summary_fixture(summary_path);
    assert_eq!(
        expected.trim_end(),
        packet.summary().trim_end(),
        "{label} summary did not match {summary_path}"
    );

    Ok(())
}

fn read_summary_fixture(path: &str) -> String {
    fs::read_to_string(support::fixture_path(path))
        .unwrap_or_else(|err| panic!("summary fixture {path} should be readable: {err}"))
}

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
