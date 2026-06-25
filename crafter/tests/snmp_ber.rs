use crafter::protocols::snmp::{SnmpOid, SnmpVarBind, SnmpVarBindList};

const NAME_TLV: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00];

fn varbind_bytes(value_tlv: &[u8]) -> Vec<u8> {
    let content_len = NAME_TLV.len() + value_tlv.len();
    assert!(content_len <= 0x7f);

    let mut bytes = Vec::with_capacity(2 + content_len);
    bytes.push(0x30);
    bytes.push(content_len as u8);
    bytes.extend_from_slice(NAME_TLV);
    bytes.extend_from_slice(value_tlv);
    bytes
}

fn assert_unknown_varbind_roundtrip(
    value_tlv: &[u8],
    class: &'static str,
    constructed: bool,
    tag_number: u8,
    content: &[u8],
) -> crafter::Result<()> {
    let bytes = varbind_bytes(value_tlv);
    let (decoded, rest) = SnmpVarBind::decode(&bytes)?;

    assert!(rest.is_empty());
    assert_eq!(decoded.unknown_value_class(), Some(class));
    assert_eq!(decoded.unknown_value_is_constructed(), Some(constructed));
    assert_eq!(decoded.unknown_value_tag_number(), Some(tag_number));
    assert_eq!(decoded.unknown_value_content(), Some(content));
    assert_eq!(decoded.unknown_value_tlv_bytes(), Some(value_tlv));
    assert_eq!(decoded.compile()?, bytes);

    Ok(())
}

#[test]
fn snmp_ber_unknown_value_tlvs_inside_varbind_are_inspectable_and_byte_exact() -> crafter::Result<()>
{
    assert_unknown_varbind_roundtrip(&[0x01, 0x01, 0xff], "universal", false, 1, &[0xff])?;
    assert_unknown_varbind_roundtrip(
        &[0x45, 0x81, 0x02, 0xde, 0xad],
        "application",
        false,
        5,
        &[0xde, 0xad],
    )?;
    assert_unknown_varbind_roundtrip(
        &[0xb4, 0x02, 0x05, 0x00],
        "context-specific",
        true,
        20,
        &[0x05, 0x00],
    )?;
    assert_unknown_varbind_roundtrip(&[0xe3, 0x02, 0x04, 0x00], "private", true, 3, &[0x04, 0x00])?;

    Ok(())
}

#[test]
fn snmp_ber_summary_and_show_fields_cover_supported_and_unknown_varbinds() -> crafter::Result<()> {
    let name = SnmpOid::from_dotted("1.3.6.1.2.1.1.5.0")?;
    assert_eq!(name.summary_label(), "object-identifier");
    assert_eq!(name.summary(), "oid=1.3.6.1.2.1.1.5.0");
    assert_eq!(
        name.inspection_fields(),
        [
            ("type", "object-identifier".to_string()),
            ("oid", "1.3.6.1.2.1.1.5.0".to_string()),
            ("arc_count", "9".to_string()),
        ]
    );

    let supported = SnmpVarBind::time_ticks(name.clone(), 12_345);
    assert_eq!(supported.value_summary(), "time-ticks");
    assert_eq!(supported.summary(), "1.3.6.1.2.1.1.5.0=time-ticks");
    assert!(supported
        .inspection_fields()
        .contains(&("value", "12345".to_string())));

    let unknown_bytes = varbind_bytes(&[0x45, 0x81, 0x02, 0xde, 0xad]);
    let (unknown, rest) = SnmpVarBind::decode(&unknown_bytes)?;
    assert!(rest.is_empty());
    assert_eq!(unknown.value_summary(), "application-5");
    assert_eq!(unknown.summary(), "1.3.6.1.2.1.1.5.0=application-5");

    let unknown_fields = unknown.inspection_fields();
    assert!(unknown_fields.contains(&("value_ber_tag_number", "5".to_string())));
    assert!(unknown_fields.contains(&("value_ber_identifier", "0x45".to_string())));
    assert!(unknown_fields.contains(&("value_content_len", "2".to_string())));
    assert!(unknown_fields.contains(&("value_tlv_len", "5".to_string())));

    let list = SnmpVarBindList::new(vec![supported, unknown]);
    assert_eq!(list.summary(), "varbinds=2");
    assert_eq!(
        list.inspection_fields(),
        [
            ("varbind_count", "2".to_string()),
            ("varbind[0]", "1.3.6.1.2.1.1.5.0=time-ticks".to_string()),
            ("varbind[1]", "1.3.6.1.2.1.1.5.0=application-5".to_string()),
        ]
    );

    Ok(())
}
