use crafter::protocols::snmp::{SnmpOid, SnmpPdu, SnmpVarBind, SnmpVarBindList};
use crafter::CrafterError;

const NAME_TLV: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00];

#[test]
fn snmp_malformed_nested_value_length_override_is_emitted() -> crafter::Result<()> {
    let name = SnmpOid::from_dotted("1.3.6.1.2.1.1.5.0")?;
    let varbind = SnmpVarBind::raw_value_tlv_with_length(name, 0x04, 5, [0xaa])?;

    let mut expected = vec![0x30, 0x0d];
    expected.extend_from_slice(NAME_TLV);
    expected.extend_from_slice(&[0x04, 0x05, 0xaa]);
    assert_eq!(varbind.compile()?, expected);

    assert_eq!(
        SnmpVarBind::decode(&expected),
        Err(CrafterError::buffer_too_short("snmp.value", 7, 3))
    );

    Ok(())
}

#[test]
fn snmp_malformed_pdu_underreported_length_preserves_body_bytes() -> crafter::Result<()> {
    let pdu = SnmpPdu::get_request(1, SnmpVarBindList::empty())?.length(0);
    let bytes = pdu.compile()?;

    assert_eq!(&bytes[..2], &[0xa0, 0x00]);
    assert_eq!(
        &bytes[2..],
        &[0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00]
    );

    let (decoded, rest) = SnmpPdu::decode(&bytes)?;
    assert!(decoded.body().is_empty());
    assert_eq!(rest, &bytes[2..]);

    Ok(())
}

#[test]
fn snmp_malformed_pdu_overreported_length_is_structured_error() -> crafter::Result<()> {
    let pdu = SnmpPdu::get_request(1, SnmpVarBindList::empty())?.length(12);
    let bytes = pdu.compile()?;

    assert_eq!(&bytes[..2], &[0xa0, 0x0c]);
    assert_eq!(
        SnmpPdu::decode(&bytes),
        Err(CrafterError::buffer_too_short("snmp.pdu", 14, 13))
    );

    Ok(())
}

#[test]
fn snmp_malformed_unset_pdu_and_value_lengths_auto_fill() -> crafter::Result<()> {
    let name = SnmpOid::from_dotted("1.3.6.1.2.1.1.5.0")?;
    let varbind = SnmpVarBind::octet_string(name, [0xaa]);
    let pdu = SnmpPdu::get_request(1, SnmpVarBindList::new(vec![varbind]))?;

    let bytes = pdu.compile()?;
    assert_eq!(&bytes[..2], &[0xa0, 0x1a]);
    assert_eq!(&bytes[25..28], &[0x04, 0x01, 0xaa]);

    let (decoded, rest) = SnmpPdu::decode(&bytes)?;
    assert!(rest.is_empty());
    assert_eq!(decoded.compile()?, bytes);

    Ok(())
}
