use crafter::protocols::snmp::{
    Snmp, SnmpOid, SnmpPdu, SnmpVarBind, SnmpVarBindList, SNMP_SECURITY_MODEL_USM,
};
use crafter::CrafterError;
use std::fmt::Debug;
use std::panic::{self, UnwindSafe};

const NAME_TLV: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00];

fn minimal_plaintext_scoped_data() -> Vec<u8> {
    vec![
        0x30, 0x11, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02,
        0x01, 0x00, 0x30, 0x00,
    ]
}

fn decode_pdu_without_panic<'a>(
    name: &'static str,
    bytes: &'a [u8],
) -> crafter::Result<(SnmpPdu, &'a [u8])> {
    panic::catch_unwind(|| SnmpPdu::decode(bytes))
        .unwrap_or_else(|_| panic!("{name} panicked during PDU decode"))
}

fn assert_snmp_decode_error(name: &'static str, bytes: &[u8], expected: CrafterError) {
    let result = panic::catch_unwind(|| Snmp::decode(bytes))
        .unwrap_or_else(|_| panic!("{name} panicked during SNMP message decode"));
    assert_eq!(result, Err(expected), "{name}");
}

fn assert_snmp_decode_error_context(
    name: &'static str,
    bytes: &[u8],
    expected_context: &'static str,
) {
    let result = panic::catch_unwind(|| Snmp::decode(bytes))
        .unwrap_or_else(|_| panic!("{name} panicked during SNMP message decode"));
    match result {
        Err(CrafterError::BufferTooShort { context, .. }) => {
            assert_eq!(context, expected_context, "{name}");
        }
        Err(CrafterError::InvalidFieldValue { field, .. }) => {
            assert_eq!(field, expected_context, "{name}");
        }
        other => panic!("{name} returned unexpected result {other:?}"),
    }
}

fn assert_accessor_error<T, F>(name: &'static str, accessor: F, expected: CrafterError)
where
    T: Debug,
    F: FnOnce() -> crafter::Result<Option<T>> + UnwindSafe,
{
    let result = panic::catch_unwind(accessor)
        .unwrap_or_else(|_| panic!("{name} panicked during PDU body decode"));
    match result {
        Err(error) => assert_eq!(error, expected, "{name}"),
        Ok(value) => panic!("{name} decoded unexpectedly as {value:?}"),
    }
}

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

#[test]
fn snmp_malformed_message_underreported_length_preserves_content_bytes() -> crafter::Result<()> {
    let auto = Snmp::v2c_get_request(b"public".to_vec(), 1, SnmpVarBindList::empty())?;
    let bytes = auto.clone().length(0).compile()?;
    let auto_bytes = auto.compile()?;

    assert_eq!(&bytes[..2], &[0x30, 0x00]);
    assert_eq!(&bytes[2..], &auto_bytes[2..]);
    assert_snmp_decode_error(
        "underreported outer message length",
        &bytes,
        CrafterError::invalid_field_value("snmp.ber.sequence", "trailing bytes after SEQUENCE TLV"),
    );

    Ok(())
}

#[test]
fn snmp_malformed_message_overreported_length_is_structured_error() -> crafter::Result<()> {
    let bytes = Snmp::v2c_get_request(b"public".to_vec(), 1, SnmpVarBindList::empty())?
        .length(25)
        .compile()?;

    assert_eq!(&bytes[..2], &[0x30, 0x19]);
    assert_snmp_decode_error(
        "overreported outer message length",
        &bytes,
        CrafterError::buffer_too_short("snmp.ber.sequence", 27, 26),
    );

    Ok(())
}

#[test]
fn snmp_malformed_message_long_form_overreported_length_is_structured_error() {
    assert_snmp_decode_error(
        "long-form overreported outer message length",
        &[0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x01],
        CrafterError::buffer_too_short("snmp.ber.sequence", 260, 7),
    );
}

#[test]
fn snmp_malformed_v3_raw_security_parameters_length_is_structured_error() {
    let bytes = [
        0x30, 0x16, 0x02, 0x01, 0x03, 0x30, 0x0e, 0x02, 0x01, 0x01, 0x02, 0x02, 0x05, 0xdc, 0x04,
        0x01, 0x00, 0x02, 0x02, 0x03, 0xe7, 0x04, 0x03, 0xaa,
    ];

    assert_snmp_decode_error(
        "overreported v3 raw security parameters",
        &bytes,
        CrafterError::buffer_too_short("snmp.v3.security_parameters", 5, 3),
    );
}

#[test]
fn snmp_malformed_v3_short_global_data_is_structured_error() {
    let bytes = [0x30, 0x07, 0x02, 0x01, 0x03, 0x30, 0x02, 0x02, 0x01];

    assert_snmp_decode_error_context("short v3 global data", &bytes, "snmp.ber.integer");
}

#[test]
fn snmp_malformed_v3_flags_length_is_structured_error() {
    let bytes = [
        0x30, 0x0f, 0x02, 0x01, 0x03, 0x30, 0x0a, 0x02, 0x01, 0x01, 0x02, 0x02, 0x05, 0xdc, 0x04,
        0x02, 0x00,
    ];

    assert_snmp_decode_error_context("truncated v3 flags field", &bytes, "snmp.v3.flags");
}

#[test]
fn snmp_malformed_v3_usm_sequence_accessor_is_structured_error() -> crafter::Result<()> {
    let malformed_usm = vec![0x30, 0x03, 0x04, 0x01, 0xaa];
    let message = Snmp::v3(
        21,
        1500,
        [0x00],
        SNMP_SECURITY_MODEL_USM,
        malformed_usm.clone(),
        minimal_plaintext_scoped_data(),
    );
    let decoded = Snmp::decode(&message.compile()?)?;
    let v3 = decoded.as_v3().expect("v3 wrapper");

    assert_eq!(v3.security_parameters(), malformed_usm);
    assert_eq!(
        v3.usm_security_parameters().expect_err("malformed USM"),
        CrafterError::buffer_too_short("snmp.ber.identifier", 1, 0)
    );
    assert_eq!(decoded.compile()?, message.compile()?);

    Ok(())
}

#[test]
fn snmp_malformed_v3_truncated_scoped_pdu_is_structured_error() -> crafter::Result<()> {
    let message = Snmp::v3(
        22,
        1500,
        [0x00],
        SNMP_SECURITY_MODEL_USM,
        Vec::<u8>::new(),
        [0x30, 0x02, 0x04],
    );

    assert_snmp_decode_error_context(
        "truncated plaintext ScopedPDU",
        &message.compile()?,
        "snmp.v3.scoped_data",
    );

    Ok(())
}

#[test]
fn snmp_malformed_v3_encrypted_payload_missing_bytes_is_structured_error() -> crafter::Result<()> {
    let message = Snmp::v3(
        23,
        1500,
        [0x02],
        SNMP_SECURITY_MODEL_USM,
        Vec::<u8>::new(),
        [0x04, 0x04, 0xde, 0xad],
    );

    assert_snmp_decode_error_context(
        "truncated encryptedPDU",
        &message.compile()?,
        "snmp.v3.scoped_data",
    );

    Ok(())
}

#[test]
fn snmp_malformed_v3_unknown_security_model_preserves_raw_bytes() -> crafter::Result<()> {
    let message = Snmp::v3(
        24,
        1500,
        [0x00],
        777,
        [0xaa, 0xbb, 0xcc],
        minimal_plaintext_scoped_data(),
    );
    let bytes = message.compile()?;
    let decoded = Snmp::decode(&bytes)?;
    let v3 = decoded.as_v3().expect("v3 wrapper");

    assert_eq!(v3.security_model(), 777);
    assert_eq!(v3.security_parameters(), &[0xaa, 0xbb, 0xcc]);
    assert_eq!(v3.usm_security_parameters()?, None);
    assert_eq!(decoded.compile()?, bytes);

    Ok(())
}

#[test]
fn snmp_malformed_varbind_list_underreported_length_preserves_member_bytes() -> crafter::Result<()>
{
    let name = SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?;
    let list = SnmpVarBindList::new(vec![SnmpVarBind::null(name)]).length(0);
    let bytes = list.compile()?;

    assert_eq!(&bytes[..2], &[0x30, 0x00]);
    let (decoded, rest) = SnmpVarBindList::decode(&bytes)?;
    assert!(decoded.is_empty());
    assert_eq!(rest, &bytes[2..]);
    assert_eq!(&list.clear_length().compile()?[..2], &[0x30, 0x0e]);

    Ok(())
}

#[test]
fn snmp_malformed_request_varbind_invalid_oid_is_structured_error() -> crafter::Result<()> {
    let bytes = [
        0x30, 0x1e, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x11,
        0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x06, 0x30, 0x04, 0x06, 0x00,
        0x05, 0x00,
    ];
    let decoded = Snmp::decode(&bytes)?;

    assert_accessor_error(
        "request varbind invalid OID",
        || decoded.pdu().as_get_request(),
        CrafterError::invalid_field_value(
            "snmp.ber.object_identifier",
            "object identifier requires at least one content octet",
        ),
    );

    Ok(())
}

#[test]
fn snmp_malformed_message_short_outer_sequence_is_structured_error() {
    assert_snmp_decode_error(
        "short outer message sequence",
        &[0x30, 0x05, 0x02, 0x01, 0x00],
        CrafterError::buffer_too_short("snmp.ber.sequence", 7, 5),
    );
}

#[test]
fn snmp_malformed_message_short_version_is_structured_error() {
    assert_snmp_decode_error(
        "short version integer",
        &[0x30, 0x02, 0x02, 0x01],
        CrafterError::buffer_too_short("snmp.ber.integer", 3, 2),
    );
}

#[test]
fn snmp_malformed_message_short_community_is_structured_error() {
    assert_snmp_decode_error(
        "short community octet string",
        &[0x30, 0x06, 0x02, 0x01, 0x00, 0x04, 0x02, 0xaa],
        CrafterError::buffer_too_short("snmp.message.community", 4, 3),
    );
}

#[test]
fn snmp_malformed_message_short_pdu_is_structured_error() {
    assert_snmp_decode_error(
        "short PDU TLV",
        &[0x30, 0x08, 0x02, 0x01, 0x00, 0x04, 0x00, 0xa0, 0x02, 0x02],
        CrafterError::buffer_too_short("snmp.pdu", 4, 3),
    );
}

#[test]
fn snmp_malformed_request_pdu_truncated_fields_return_structured_errors() -> crafter::Result<()> {
    let bytes = [0xa0, 0x03, 0x02, 0x01, 0x01];
    let (decoded, rest) = decode_pdu_without_panic("truncated request fields", &bytes)?;

    assert!(rest.is_empty());
    assert_accessor_error(
        "truncated request fields",
        || decoded.as_get_request(),
        CrafterError::buffer_too_short("snmp.ber.identifier", 1, 0),
    );

    Ok(())
}

#[test]
fn snmp_malformed_bad_varbind_list_sequence_is_structured_error() -> crafter::Result<()> {
    let bytes = [
        0xa0, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x00,
    ];
    let (decoded, rest) = decode_pdu_without_panic("bad varbind list sequence", &bytes)?;

    assert!(rest.is_empty());
    assert_accessor_error(
        "bad varbind list sequence",
        || decoded.as_get_request(),
        CrafterError::invalid_field_value(
            "snmp.ber.sequence",
            "expected universal constructed SEQUENCE",
        ),
    );

    Ok(())
}

#[test]
fn snmp_malformed_v1_trap_short_body_returns_structured_error() -> crafter::Result<()> {
    let bytes = [0xa4, 0x04, 0x06, 0x02, 0x2b, 0x06];
    let (decoded, rest) = decode_pdu_without_panic("short v1 trap body", &bytes)?;

    assert!(rest.is_empty());
    assert_accessor_error(
        "short v1 trap body",
        || decoded.as_v1_trap(),
        CrafterError::buffer_too_short("snmp.ber.identifier", 1, 0),
    );

    Ok(())
}

#[test]
fn snmp_malformed_get_bulk_fields_return_structured_error() -> crafter::Result<()> {
    let bytes = [0xa5, 0x06, 0x02, 0x01, 0x07, 0x02, 0x02, 0x00];
    let (decoded, rest) = decode_pdu_without_panic("malformed bulk fields", &bytes)?;

    assert!(rest.is_empty());
    assert_accessor_error(
        "malformed bulk fields",
        || decoded.as_get_bulk_request(),
        CrafterError::buffer_too_short("snmp.ber.integer", 4, 3),
    );

    Ok(())
}

#[test]
fn snmp_malformed_constructed_request_integer_is_structured_error() -> crafter::Result<()> {
    let bytes = [
        0xa0, 0x0b, 0x22, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
    ];
    let (decoded, rest) = decode_pdu_without_panic("constructed request integer", &bytes)?;

    assert!(rest.is_empty());
    assert_accessor_error(
        "constructed request integer",
        || decoded.as_get_request(),
        CrafterError::invalid_field_value(
            "snmp.ber.integer",
            "expected universal primitive INTEGER",
        ),
    );

    Ok(())
}

#[test]
fn snmp_malformed_primitive_known_pdu_tag_is_preserved_as_unknown() -> crafter::Result<()> {
    let bytes = [0x80, 0x01, 0xaa, 0xcc];
    let (decoded, rest) = decode_pdu_without_panic("primitive known PDU tag", &bytes)?;
    let unknown = decoded.as_unknown().expect("primitive PDU is raw");

    assert_eq!(unknown.tag_number(), SnmpPdu::TAG_GET_REQUEST);
    assert!(!unknown.is_constructed());
    assert_eq!(unknown.body(), &[0xaa]);
    assert_eq!(unknown.raw_tlv_bytes(), Some(&bytes[..3]));
    assert_eq!(decoded.raw_tlv_bytes(), Some(&bytes[..3]));
    assert_eq!(decoded.as_get_request()?, None);
    assert_eq!(decoded.compile()?, bytes[..3]);
    assert_eq!(rest, &[0xcc]);

    Ok(())
}

#[test]
fn snmp_malformed_unknown_pdu_preserves_raw_tlv() -> crafter::Result<()> {
    let bytes = [0xa9, 0x03, 0x02, 0x01, 0x05, 0xee];
    let (decoded, rest) = decode_pdu_without_panic("unknown PDU", &bytes)?;
    let unknown = decoded.as_unknown().expect("unknown PDU is raw");

    assert_eq!(unknown.tag_number(), 9);
    assert!(unknown.is_constructed());
    assert_eq!(unknown.body(), &[0x02, 0x01, 0x05]);
    assert_eq!(unknown.raw_tlv_bytes(), Some(&bytes[..5]));
    assert_eq!(decoded.raw_tlv_bytes(), Some(&bytes[..5]));
    assert_eq!(decoded.as_get_request()?, None);
    assert_eq!(decoded.as_get_bulk_request()?, None);
    assert_eq!(decoded.as_v1_trap()?, None);
    assert_eq!(decoded.compile()?, bytes[..5]);
    assert_eq!(rest, &[0xee]);

    Ok(())
}
