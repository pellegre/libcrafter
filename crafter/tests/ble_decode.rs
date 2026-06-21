use crafter::core::{CrafterError, LayerContext, LinkType, Packet, Result};

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
