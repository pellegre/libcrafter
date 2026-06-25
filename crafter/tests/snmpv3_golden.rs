use crafter::packet::Packet;
use crafter::protocols::snmp::{
    Snmp, SnmpEncryptedScopedData, SnmpOid, SnmpPdu, SnmpUsmSecurityParameters, SnmpV3Message,
    SnmpVarBind, SnmpVarBindList, SnmpVersion, SNMP_SECURITY_MODEL_USM, SNMP_V3_FLAG_AUTH,
    SNMP_V3_FLAG_PRIVACY, SNMP_V3_FLAG_REPORTABLE,
};

fn minimal_plaintext_scoped_data() -> Vec<u8> {
    vec![
        0x30, 0x11, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02,
        0x01, 0x00, 0x30, 0x00,
    ]
}

fn sample_usm_parameters() -> SnmpUsmSecurityParameters {
    SnmpUsmSecurityParameters::new(
        [0x80, 0x00, 0x1f],
        7,
        9,
        [0xff, 0x00, b'u'],
        [0xaa, 0xbb, 0xcc],
        [0xde, 0xad],
    )
}

fn oid(dotted: &str) -> crafter::Result<SnmpOid> {
    SnmpOid::from_dotted(dotted)
}

#[test]
fn snmpv3_golden_plaintext_scoped_pdu_decodes_minimal_get_request() -> crafter::Result<()> {
    let bytes = vec![
        0x30, 0x27, 0x02, 0x01, 0x03, 0x30, 0x0d, 0x02, 0x01, 0x01, 0x02, 0x02, 0x05, 0xdc, 0x04,
        0x01, 0x00, 0x02, 0x01, 0x03, 0x04, 0x00, 0x30, 0x11, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0b,
        0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
    ];

    // Source-backed: docs/snmp-rfc-manifest.md records RFC 3412 Section 6 for
    // SNMPv3Message, HeaderData, and plaintext ScopedPDU.
    let decoded = Snmp::decode(&bytes)?;
    let v3 = decoded.as_v3().expect("v3 wrapper");
    let scoped = v3.scoped_pdu()?.expect("plaintext scoped PDU");
    let request = scoped.pdu().as_get_request()?.expect("GetRequest fields");

    assert_eq!(decoded.version(), SnmpVersion::V3);
    assert_eq!(v3.msg_id(), 1);
    assert_eq!(v3.max_size(), 1500);
    assert_eq!(v3.flags(), &[0x00]);
    assert_eq!(v3.security_model(), SNMP_SECURITY_MODEL_USM);
    assert_eq!(v3.security_parameters(), b"");
    assert_eq!(v3.scoped_data_kind(), "plaintext");
    assert_eq!(scoped.context_engine_id(), b"");
    assert_eq!(scoped.context_name(), b"");
    assert_eq!(scoped.pdu().tag_number(), SnmpPdu::TAG_GET_REQUEST);
    assert_eq!(request.request_id(), 1);
    assert!(request.varbinds().is_empty());
    assert_eq!(decoded.compile()?, bytes);
    assert!(decoded.summary().contains("scoped_data_kind=plaintext"));
    assert!(decoded.summary().contains("pdu_type=get-request"));
    assert!(decoded.show().contains("msg_security_model_label: usm"));

    Ok(())
}

#[test]
fn snmpv3_golden_usm_parameters_decode_and_recompile() -> crafter::Result<()> {
    let usm = sample_usm_parameters();
    let message = SnmpV3Message::new_usm(
        11,
        1500,
        [0x00],
        usm.clone(),
        minimal_plaintext_scoped_data(),
    )?;
    let bytes = Snmp::from_v3_message(message).compile()?;
    let decoded = Snmp::decode(&bytes)?;
    let v3 = decoded.as_v3().expect("v3 wrapper");
    let decoded_usm = v3
        .usm_security_parameters()?
        .expect("USM security parameters");

    assert_eq!(v3.raw_security_parameters().bytes(), usm.compile()?);
    assert_eq!(decoded_usm, usm);
    assert_eq!(decoded_usm.engine_id(), &[0x80, 0x00, 0x1f]);
    assert_eq!(decoded_usm.engine_boots(), 7);
    assert_eq!(decoded_usm.engine_time(), 9);
    assert_eq!(decoded_usm.authentication_parameters(), &[0xaa, 0xbb, 0xcc]);
    assert_eq!(decoded_usm.privacy_parameters(), &[0xde, 0xad]);
    assert_eq!(decoded.compile()?, bytes);
    assert!(!decoded.summary().contains("aa bb"));
    assert!(!decoded.show().contains("de ad"));

    Ok(())
}

#[test]
fn snmpv3_golden_unknown_security_model_preserves_raw_security() -> crafter::Result<()> {
    let message = Snmp::v3(
        7,
        65_535,
        [SNMP_V3_FLAG_REPORTABLE],
        999,
        [0xaa, 0xbb],
        minimal_plaintext_scoped_data(),
    );
    let bytes = message.compile()?;
    let decoded = Snmp::decode(&bytes)?;
    let v3 = decoded.as_v3().expect("v3 wrapper");

    assert_eq!(v3.security_model(), 999);
    assert_eq!(
        v3.raw_security_parameters().security_model_label(),
        "security-model-999"
    );
    assert_eq!(v3.security_parameters(), &[0xaa, 0xbb]);
    assert_eq!(v3.usm_security_parameters()?, None);
    assert_eq!(
        v3.scoped_pdu()?.expect("plaintext scoped PDU").compile()?,
        minimal_plaintext_scoped_data()
    );
    assert_eq!(decoded.compile()?, bytes);
    assert!(decoded
        .summary()
        .contains("msg_security_model_label=security-model-999"));
    assert!(!decoded.summary().contains("aa bb"));

    Ok(())
}

#[test]
fn snmpv3_golden_encrypted_scoped_data_is_opaque() -> crafter::Result<()> {
    let usm = sample_usm_parameters().with_privacy_parameters([0x01, 0x02, 0x03, 0x04]);
    let encrypted_pdu = [0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
    let message = Snmp::v3_encrypted_usm(
        16,
        1500,
        [SNMP_V3_FLAG_AUTH | SNMP_V3_FLAG_PRIVACY],
        usm.clone(),
        encrypted_pdu,
    )?;
    let bytes = message.compile()?;
    let decoded = Snmp::decode(&bytes)?;
    let v3 = decoded.as_v3().expect("v3 wrapper");
    let encrypted = v3.encrypted_scoped_data()?.expect("encrypted scoped data");

    assert_eq!(v3.scoped_data_kind(), "encrypted");
    assert!(v3.flags_value().privacy());
    assert!(v3.scoped_pdu()?.is_none());
    assert_eq!(encrypted.encrypted_pdu(), encrypted_pdu);
    assert_eq!(encrypted.privacy_parameters(), &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(
        SnmpEncryptedScopedData::new(Vec::<u8>::new(), encrypted_pdu).compile()?,
        v3.scoped_data()
    );
    assert_eq!(v3.raw_security_parameters().bytes(), usm.compile()?);
    assert_eq!(decoded.compile()?, bytes);
    assert!(decoded.summary().contains("scoped_data_kind=encrypted"));
    assert!(!decoded.summary().contains("de ad"));
    assert!(!encrypted.show().contains("de ad"));

    Ok(())
}

#[test]
fn snmpv3_golden_report_message_decodes_plaintext_scoped_pdu() -> crafter::Result<()> {
    let usm = sample_usm_parameters();
    let varbinds = SnmpVarBindList::new(vec![SnmpVarBind::time_ticks(
        oid("1.3.6.1.2.1.1.3.0")?,
        12_345,
    )]);
    let message = Snmp::v3_usm_report(
        20,
        1500,
        [SNMP_V3_FLAG_REPORTABLE],
        usm,
        b"engine".to_vec(),
        b"context".to_vec(),
        101,
        varbinds,
    )?;
    let packet = Packet::from_layer(message.clone());
    let bytes = packet.compile()?.into_bytes();
    let decoded = Snmp::decode(&bytes)?;
    let v3 = decoded.as_v3().expect("v3 wrapper");
    let scoped = v3.scoped_pdu()?.expect("plaintext scoped PDU");
    let report = scoped.pdu().as_report()?.expect("Report fields");

    assert_eq!(scoped.context_engine_id(), b"engine");
    assert_eq!(scoped.context_name(), b"context");
    assert_eq!(scoped.pdu().tag_number(), SnmpPdu::TAG_REPORT);
    assert_eq!(report.request_id(), 101);
    assert_eq!(report.varbinds().len(), 1);
    assert_eq!(decoded.compile()?, bytes);
    assert!(decoded.summary().contains("pdu_type=report"));
    assert!(packet.summary().contains("pdu_type=report"));

    Ok(())
}
