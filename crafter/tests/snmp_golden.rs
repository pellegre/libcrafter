use crafter::protocols::snmp::{Snmp, SnmpOid, SnmpPdu, SnmpVarBind, SnmpVarBindList, SnmpVersion};

struct MessageCase {
    name: &'static str,
    message: Snmp,
    expected: Vec<u8>,
    version: SnmpVersion,
    pdu_tag: u8,
    summary_snippets: &'static [&'static str],
    show_snippets: &'static [&'static str],
}

fn oid(dotted: &str) -> crafter::Result<SnmpOid> {
    SnmpOid::from_dotted(dotted)
}

fn assert_message_case(case: MessageCase) -> crafter::Result<Snmp> {
    let compiled = case.message.compile()?;
    assert_eq!(compiled, case.expected, "{}", case.name);

    let decoded = Snmp::decode(&case.expected)?;
    assert_eq!(decoded.compile()?, case.expected, "{}", case.name);
    assert_eq!(decoded.version(), case.version, "{}", case.name);
    assert_eq!(decoded.pdu().tag_number(), case.pdu_tag, "{}", case.name);

    let summary = decoded.summary();
    for snippet in case.summary_snippets {
        assert!(
            summary.contains(snippet),
            "{} summary {summary:?} did not contain {snippet:?}",
            case.name
        );
    }

    let show = decoded.show();
    for snippet in case.show_snippets {
        assert!(
            show.contains(snippet),
            "{} show output did not contain {snippet:?}:\n{show}",
            case.name
        );
    }

    Ok(decoded)
}

#[test]
fn snmp_golden_v1_get_request_roundtrips() -> crafter::Result<()> {
    let varbind = SnmpVarBind::null(oid("1.3.6.1.2.1.1.3.0")?);
    let message = Snmp::v1_get_request(b"public".to_vec(), 7, SnmpVarBindList::new(vec![varbind]))?;

    // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 1157 Section 4.1.2
    // for GetRequest-PDU and RFC 1157 Section 4.1 for the message wrapper.
    assert_message_case(MessageCase {
        name: "v1-get-request",
        message,
        expected: vec![
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
            0x19, 0x02, 0x01, 0x07, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c,
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
        ],
        version: SnmpVersion::V1,
        pdu_tag: SnmpPdu::TAG_GET_REQUEST,
        summary_snippets: &[
            "version=v1",
            "pdu_type=get-request",
            "request_id=7",
            "varbind_count=1",
        ],
        show_snippets: &[
            "version: v1",
            "pdu_type: get-request",
            "request_id: 7",
            "varbind_count: 1",
        ],
    })?;

    Ok(())
}

#[test]
fn snmp_golden_v1_trap_roundtrips() -> crafter::Result<()> {
    let varbind = SnmpVarBind::null(oid("1.3.6.1.2.1.1.3.0")?);
    let message = Snmp::v1_trap(
        b"public".to_vec(),
        oid("1.3.6.1.4.1")?,
        [192, 0, 2, 44],
        6,
        4_321,
        12_345,
        SnmpVarBindList::new(vec![varbind]),
    )?;

    // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 1157 Section 4.1.6
    // for Trap-PDU fields.
    assert_message_case(MessageCase {
        name: "v1-trap",
        message,
        expected: vec![
            0x30, 0x35, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa4,
            0x28, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x40, 0x04, 192, 0, 2, 44, 0x02, 0x01,
            0x06, 0x02, 0x02, 0x10, 0xe1, 0x43, 0x02, 0x30, 0x39, 0x30, 0x0e, 0x30, 0x0c, 0x06,
            0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
        ],
        version: SnmpVersion::V1,
        pdu_tag: SnmpPdu::TAG_TRAP,
        summary_snippets: &[
            "version=v1",
            "pdu_type=trap",
            "agent_address=192.0.2.44",
            "generic_trap=6",
            "specific_trap=4321",
            "timestamp=12345",
        ],
        show_snippets: &[
            "pdu_type: trap",
            "agent_address: 192.0.2.44",
            "specific_trap: 4321",
        ],
    })?;

    Ok(())
}

#[test]
fn snmp_golden_v2c_get_bulk_roundtrips() -> crafter::Result<()> {
    let varbind = SnmpVarBind::null(oid("1.3.6.1.2.1.1.3.0")?);
    let message = Snmp::v2c_get_bulk_request(
        b"public".to_vec(),
        7,
        1,
        10,
        SnmpVarBindList::new(vec![varbind]),
    )?;

    // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 3416 Sections 3
    // and 4.2.3 for GetBulkRequest-PDU.
    assert_message_case(MessageCase {
        name: "v2c-get-bulk",
        message,
        expected: vec![
            0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa5,
            0x19, 0x02, 0x01, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0a, 0x30, 0x0e, 0x30, 0x0c,
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
        ],
        version: SnmpVersion::V2c,
        pdu_tag: SnmpPdu::TAG_GET_BULK_REQUEST,
        summary_snippets: &[
            "version=v2c",
            "pdu_type=get-bulk-request",
            "request_id=7",
            "max_repetitions=10",
        ],
        show_snippets: &[
            "pdu_type: get-bulk-request",
            "non_repeaters: 1",
            "max_repetitions: 10",
        ],
    })?;

    Ok(())
}

#[test]
fn snmp_golden_v2c_response_roundtrips() -> crafter::Result<()> {
    let varbind = SnmpVarBind::time_ticks(oid("1.3.6.1.2.1.1.3.0")?, 12_345);
    let message = Snmp::v2c_response(b"public".to_vec(), 42, SnmpVarBindList::new(vec![varbind]))?;

    assert_message_case(MessageCase {
        name: "v2c-response",
        message,
        expected: vec![
            0x30, 0x28, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa2,
            0x1b, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x10, 0x30, 0x0e,
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43, 0x02, 0x30, 0x39,
        ],
        version: SnmpVersion::V2c,
        pdu_tag: SnmpPdu::TAG_RESPONSE,
        summary_snippets: &[
            "version=v2c",
            "pdu_type=response",
            "request_id=42",
            "varbind_count=1",
        ],
        show_snippets: &[
            "pdu_type: response",
            "request_id: 42",
            "varbind[0]: 1.3.6.1.2.1.1.3.0=time-ticks",
        ],
    })?;

    Ok(())
}

#[test]
fn snmp_golden_v2c_trap_inform_and_report_roundtrip() -> crafter::Result<()> {
    let uptime = SnmpVarBind::time_ticks(oid("1.3.6.1.2.1.1.3.0")?, 12_345);
    let trap_oid =
        SnmpVarBind::object_identifier(oid("1.3.6.1.6.3.1.1.4.1.0")?, oid("1.3.6.1.6.3.1.1.5.1")?);
    let null_sys_uptime = SnmpVarBind::null(oid("1.3.6.1.2.1.1.3.0")?);

    let cases = vec![
        MessageCase {
            name: "v2c-trap",
            message: Snmp::v2c_snmpv2_trap(
                b"public".to_vec(),
                42,
                SnmpVarBindList::new(vec![uptime.clone(), trap_oid]),
            )?,
            expected: vec![
                0x30, 0x41, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa7,
                0x34, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x29, 0x30, 0x0e,
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43, 0x02, 0x30, 0x39,
                0x30, 0x17, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x04, 0x01, 0x00,
                0x06, 0x09, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x05, 0x01,
            ],
            version: SnmpVersion::V2c,
            pdu_tag: SnmpPdu::TAG_TRAP_V2,
            summary_snippets: &["pdu_type=snmpv2-trap", "request_id=42", "varbind_count=2"],
            show_snippets: &["pdu_type: snmpv2-trap", "varbind_count: 2"],
        },
        MessageCase {
            name: "v2c-inform",
            message: Snmp::v2c_inform_request(
                b"public".to_vec(),
                7,
                SnmpVarBindList::new(vec![null_sys_uptime]),
            )?,
            expected: vec![
                0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa6,
                0x19, 0x02, 0x01, 0x07, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c,
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
            ],
            version: SnmpVersion::V2c,
            pdu_tag: SnmpPdu::TAG_INFORM_REQUEST,
            summary_snippets: &["pdu_type=inform-request", "request_id=7", "varbind_count=1"],
            show_snippets: &["pdu_type: inform-request", "request_id: 7"],
        },
        MessageCase {
            name: "v2c-report",
            message: Snmp::v2c_report(b"public".to_vec(), 128, SnmpVarBindList::empty())?,
            expected: vec![
                0x30, 0x19, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa8,
                0x0c, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
            ],
            version: SnmpVersion::V2c,
            pdu_tag: SnmpPdu::TAG_REPORT,
            summary_snippets: &["pdu_type=report", "request_id=128", "varbind_count=0"],
            show_snippets: &["pdu_type: report", "request_id: 128"],
        },
    ];

    for case in cases {
        assert_message_case(case)?;
    }

    Ok(())
}

#[test]
fn snmp_golden_unknown_pdu_preservation_roundtrips() -> crafter::Result<()> {
    let message = Snmp::v2c(b"x".to_vec(), SnmpPdu::unknown(9, true, [0x02, 0x01, 0x05]));
    let decoded = assert_message_case(MessageCase {
        name: "unknown-pdu",
        message,
        expected: vec![
            0x30, 0x0b, 0x02, 0x01, 0x01, 0x04, 0x01, b'x', 0xa9, 0x03, 0x02, 0x01, 0x05,
        ],
        version: SnmpVersion::V2c,
        pdu_tag: 9,
        summary_snippets: &["pdu_type=pdu-9", "pdu_tag=9", "body_length=3"],
        show_snippets: &["pdu_tag_status: unknown", "pdu_tlv_bytes: a9 03 02 01 05"],
    })?;

    assert_eq!(
        decoded.pdu().raw_tlv_bytes(),
        Some(&[0xa9, 0x03, 0x02, 0x01, 0x05][..])
    );

    Ok(())
}
