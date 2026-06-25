use crafter::protocols::snmp::SnmpVarBind;

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
