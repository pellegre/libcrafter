use crafter::protocols::snmp::{
    SnmpOid, SnmpPdu, SnmpPduTagStatus, SnmpRequestPdu, SnmpVarBind, SnmpVarBindList,
};

struct CommonPduCase {
    name: &'static str,
    pdu: SnmpPdu,
    expected: Vec<u8>,
    tag: u8,
    label: &'static str,
    request_id: i64,
    error_status: i64,
    error_index: i64,
    varbind_count: usize,
    summary_snippets: &'static [&'static str],
}

fn oid(dotted: &str) -> crafter::Result<SnmpOid> {
    SnmpOid::from_dotted(dotted)
}

fn assert_build_decode_compile_roundtrip(
    pdu: SnmpPdu,
    expected: &[u8],
) -> crafter::Result<SnmpPdu> {
    let compiled = pdu.compile()?;
    assert_eq!(compiled.as_slice(), expected);

    let (decoded, rest) = SnmpPdu::decode(&compiled)?;
    assert!(rest.is_empty());
    assert_eq!(decoded.compile()?.as_slice(), expected);

    Ok(decoded)
}

fn assert_summary_contains(summary: &str, snippets: &[&str]) {
    for snippet in snippets {
        assert!(
            summary.contains(snippet),
            "summary {summary:?} did not contain {snippet:?}"
        );
    }
}

fn common_fields_for(pdu: &SnmpPdu, tag: u8) -> crafter::Result<SnmpRequestPdu> {
    let fields = match tag {
        SnmpPdu::TAG_GET_REQUEST => pdu.as_get_request()?,
        SnmpPdu::TAG_GET_NEXT_REQUEST => pdu.as_get_next_request()?,
        SnmpPdu::TAG_RESPONSE => pdu.as_response()?,
        SnmpPdu::TAG_SET_REQUEST => pdu.as_set_request()?,
        SnmpPdu::TAG_INFORM_REQUEST => pdu.as_inform_request()?,
        SnmpPdu::TAG_TRAP_V2 => pdu.as_snmpv2_trap()?,
        SnmpPdu::TAG_REPORT => pdu.as_report()?,
        other => panic!("unsupported common PDU tag {other}"),
    };

    Ok(fields.expect("common PDU fields"))
}

#[test]
fn snmp_request_style_pdu_golden_matrix_roundtrips() -> crafter::Result<()> {
    let null_sys_uptime = SnmpVarBind::null(oid("1.3.6.1.2.1.1.3.0")?);
    let uptime_value = SnmpVarBind::time_ticks(oid("1.3.6.1.2.1.1.3.0")?, 12_345);
    let trap_oid =
        SnmpVarBind::object_identifier(oid("1.3.6.1.6.3.1.1.4.1.0")?, oid("1.3.6.1.6.3.1.1.5.1")?);

    let cases = vec![
        CommonPduCase {
            name: "get-request",
            pdu: SnmpPdu::get_request(1, SnmpVarBindList::empty())?,
            // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 1157
            // Section 4.1.2 and RFC 3416 Sections 3 and 4.2.1 for
            // GetRequest-PDU tag 0 carrying request-id, error-status,
            // error-index, and VarBindList.
            expected: vec![
                0xa0, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
            ],
            tag: SnmpPdu::TAG_GET_REQUEST,
            label: "get-request",
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbind_count: 0,
            summary_snippets: &[
                "pdu_type=get-request request_id=1",
                "error_status=no-error(0)",
                "varbind_count=0",
            ],
        },
        CommonPduCase {
            name: "get-next-request",
            pdu: SnmpPdu::get_next_request(1, SnmpVarBindList::empty())?,
            // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 1157
            // Section 4.1.3 and RFC 3416 Sections 3 and 4.2.2 for
            // GetNextRequest-PDU tag 1 using the common request fields.
            expected: vec![
                0xa1, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
            ],
            tag: SnmpPdu::TAG_GET_NEXT_REQUEST,
            label: "get-next-request",
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbind_count: 0,
            summary_snippets: &[
                "pdu_type=get-next-request request_id=1",
                "error_status=no-error(0)",
                "varbind_count=0",
            ],
        },
        CommonPduCase {
            name: "set-request",
            pdu: SnmpPdu::set_request(1, SnmpVarBindList::empty())?,
            // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 1157
            // Section 4.1.5 and RFC 3416 Sections 3 and 4.2.5 for
            // SetRequest-PDU tag 3 using the common request fields.
            expected: vec![
                0xa3, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
            ],
            tag: SnmpPdu::TAG_SET_REQUEST,
            label: "set-request",
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbind_count: 0,
            summary_snippets: &[
                "pdu_type=set-request request_id=1",
                "error_status=no-error(0)",
                "varbind_count=0",
            ],
        },
        CommonPduCase {
            name: "response",
            pdu: SnmpPdu::response(42, SnmpVarBindList::new(vec![uptime_value.clone()]))?,
            // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 1157
            // Section 4.1.4 and RFC 3416 Sections 3 and 4.2.4 for
            // Response/GetResponse-PDU tag 2 using the common request fields.
            expected: vec![
                0xa2, 0x1b, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x10, 0x30,
                0x0e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43, 0x02, 0x30,
                0x39,
            ],
            tag: SnmpPdu::TAG_RESPONSE,
            label: "response",
            request_id: 42,
            error_status: 0,
            error_index: 0,
            varbind_count: 1,
            summary_snippets: &[
                "pdu_type=response request_id=42",
                "error_status=no-error(0)",
                "varbind_count=1",
            ],
        },
        CommonPduCase {
            name: "inform-request",
            pdu: SnmpPdu::inform_request(7, SnmpVarBindList::new(vec![null_sys_uptime.clone()]))?,
            // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 3416
            // Sections 3 and 4.2.7 for InformRequest-PDU tag 6 using the
            // common request fields.
            expected: vec![
                0xa6, 0x19, 0x02, 0x01, 0x07, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
                0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
            ],
            tag: SnmpPdu::TAG_INFORM_REQUEST,
            label: "inform-request",
            request_id: 7,
            error_status: 0,
            error_index: 0,
            varbind_count: 1,
            summary_snippets: &[
                "pdu_type=inform-request request_id=7",
                "error_status=no-error(0)",
                "varbind_count=1",
            ],
        },
        CommonPduCase {
            name: "snmpv2-trap",
            pdu: SnmpPdu::snmpv2_trap(
                42,
                SnmpVarBindList::new(vec![uptime_value.clone(), trap_oid.clone()]),
            )?,
            // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 3416
            // Sections 3 and 4.2.6 for SNMPv2-Trap-PDU tag 7. RFC 3418
            // Section 5 records sysUpTime.0 and snmpTrapOID notification
            // object identifiers used in this deterministic VarBindList.
            expected: vec![
                0xa7, 0x34, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x29, 0x30,
                0x0e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43, 0x02, 0x30,
                0x39, 0x30, 0x17, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x04, 0x01,
                0x00, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x05, 0x01,
            ],
            tag: SnmpPdu::TAG_TRAP_V2,
            label: "snmpv2-trap",
            request_id: 42,
            error_status: 0,
            error_index: 0,
            varbind_count: 2,
            summary_snippets: &[
                "pdu_type=snmpv2-trap request_id=42",
                "error_status=no-error(0)",
                "varbind_count=2",
            ],
        },
        CommonPduCase {
            name: "report",
            pdu: SnmpPdu::report_with_fields(128, 2, 3, SnmpVarBindList::empty())?,
            // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 3416
            // Section 3 and Section 4.2 notes for Report-PDU tag 8 using the
            // common PDU byte shape; administrative-framework behavior is
            // outside this packet primitive.
            expected: vec![
                0xa8, 0x0c, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x30, 0x00,
            ],
            tag: SnmpPdu::TAG_REPORT,
            label: "report",
            request_id: 128,
            error_status: 2,
            error_index: 3,
            varbind_count: 0,
            summary_snippets: &[
                "pdu_type=report request_id=128",
                "error_status=no-such-name(2)",
                "varbind_count=0",
            ],
        },
    ];

    for case in cases {
        let decoded = assert_build_decode_compile_roundtrip(case.pdu, &case.expected)?;
        let fields = common_fields_for(&decoded, case.tag)?;

        assert_eq!(decoded.tag_number(), case.tag, "{}", case.name);
        assert_eq!(decoded.tag_label(), case.label, "{}", case.name);
        assert_eq!(fields.request_id(), case.request_id, "{}", case.name);
        assert_eq!(fields.error_status(), case.error_status, "{}", case.name);
        assert_eq!(fields.error_index(), case.error_index, "{}", case.name);
        assert_eq!(fields.varbinds().len(), case.varbind_count, "{}", case.name);
        assert_summary_contains(
            &fields.summary_with_label(case.label),
            case.summary_snippets,
        );
        assert_summary_contains(&decoded.summary(), case.summary_snippets);
        let show = decoded.show();
        assert!(show.contains(&format!("  pdu_type: {}", case.label)));
        assert!(show.contains(&format!("  request_id: {}", case.request_id)));
        assert!(show.contains(&format!("  error_status: {}", case.error_status)));
        assert!(show.contains(&format!("  error_index: {}", case.error_index)));
        assert!(show.contains(&format!("  varbind_count: {}", case.varbind_count)));
    }

    Ok(())
}

#[test]
fn snmp_get_bulk_pdu_golden_roundtrips() -> crafter::Result<()> {
    let varbind = SnmpVarBind::null(oid("1.3.6.1.2.1.1.3.0")?);
    let pdu = SnmpPdu::get_bulk_request(7, 1, 10, SnmpVarBindList::new(vec![varbind.clone()]))?;

    // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 3416 Sections 3
    // and 4.2.3 for GetBulkRequest-PDU tag 5 with request-id,
    // non-repeaters, max-repetitions, and VarBindList fields.
    let expected = [
        0xa5, 0x19, 0x02, 0x01, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0a, 0x30, 0x0e, 0x30, 0x0c,
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
    ];
    let decoded = assert_build_decode_compile_roundtrip(pdu, &expected)?;
    let fields = decoded
        .as_get_bulk_request()?
        .expect("GetBulkRequest fields");

    assert_eq!(decoded.tag_number(), SnmpPdu::TAG_GET_BULK_REQUEST);
    assert_eq!(decoded.tag_label(), "get-bulk-request");
    assert_eq!(fields.request_id(), 7);
    assert_eq!(fields.non_repeaters(), 1);
    assert_eq!(fields.max_repetitions(), 10);
    assert_eq!(fields.varbinds().as_slice(), &[varbind]);
    assert_summary_contains(
        &fields.summary(),
        &[
            "pdu_type=get-bulk-request request_id=7",
            "non_repeaters=1",
            "max_repetitions=10",
            "varbind_count=1",
        ],
    );
    assert_summary_contains(
        &decoded.summary(),
        &[
            "pdu_type=get-bulk-request request_id=7",
            "non_repeaters=1",
            "max_repetitions=10",
            "varbind_count=1",
        ],
    );
    let show = decoded.show();
    assert!(show.contains("  pdu_type: get-bulk-request"));
    assert!(show.contains("  request_id: 7"));
    assert!(show.contains("  non_repeaters: 1"));
    assert!(show.contains("  max_repetitions: 10"));
    assert!(show.contains("  varbind_count: 1"));

    Ok(())
}

#[test]
fn snmp_v1_trap_pdu_golden_roundtrips() -> crafter::Result<()> {
    let enterprise = oid("1.3.6.1.4.1")?;
    let varbind = SnmpVarBind::null(oid("1.3.6.1.2.1.1.3.0")?);
    let pdu = SnmpPdu::v1_trap(
        enterprise.clone(),
        [192, 0, 2, 44],
        6,
        4_321,
        12_345,
        SnmpVarBindList::new(vec![varbind.clone()]),
    )?;

    // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 1157 Sections
    // 4.1.6 and 5 for SNMPv1 Trap-PDU tag 4 with enterprise, agent address,
    // generic trap, specific trap, timestamp, and VarBindList fields.
    let expected = [
        0xa4, 0x28, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x40, 0x04, 192, 0, 2, 44, 0x02,
        0x01, 0x06, 0x02, 0x02, 0x10, 0xe1, 0x43, 0x02, 0x30, 0x39, 0x30, 0x0e, 0x30, 0x0c, 0x06,
        0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00,
    ];
    let decoded = assert_build_decode_compile_roundtrip(pdu, &expected)?;
    let fields = decoded.as_v1_trap()?.expect("Trap fields");

    assert_eq!(decoded.tag_number(), SnmpPdu::TAG_TRAP);
    assert_eq!(decoded.tag_label(), "trap");
    assert_eq!(fields.enterprise(), &enterprise);
    assert_eq!(fields.agent_address(), [192, 0, 2, 44]);
    assert_eq!(fields.generic_trap(), 6);
    assert_eq!(fields.specific_trap(), 4_321);
    assert_eq!(fields.timestamp(), 12_345);
    assert_eq!(fields.varbinds().as_slice(), &[varbind]);
    assert_summary_contains(
        &fields.summary(),
        &[
            "pdu_type=trap enterprise=1.3.6.1.4.1",
            "agent_address=192.0.2.44",
            "generic_trap=6",
            "specific_trap=4321",
            "timestamp=12345",
            "varbind_count=1",
        ],
    );
    assert_summary_contains(
        &decoded.summary(),
        &[
            "pdu_type=trap enterprise=1.3.6.1.4.1",
            "agent_address=192.0.2.44",
            "generic_trap=6",
            "specific_trap=4321",
            "timestamp=12345",
            "varbind_count=1",
        ],
    );
    let show = decoded.show();
    assert!(show.contains("  pdu_type: trap"));
    assert!(show.contains("  enterprise: 1.3.6.1.4.1"));
    assert!(show.contains("  agent_address: 192.0.2.44"));
    assert!(show.contains("  generic_trap: 6"));
    assert!(show.contains("  specific_trap: 4321"));
    assert!(show.contains("  timestamp: 12345"));
    assert!(show.contains("  varbind_count: 1"));

    Ok(())
}

#[test]
fn snmp_unknown_pdu_golden_roundtrips() -> crafter::Result<()> {
    let pdu = SnmpPdu::unknown(9, true, [0x02, 0x01, 0x05]);

    // Source-backed: .agents/docs/snmp-rfc-manifest.md records RFC 3416 Section 3
    // for assigned PDU tags 0 through 8, and records unknown PDU tags as
    // byte-preserving when the enclosing context-specific BER TLV is valid.
    let expected = [0xa9, 0x03, 0x02, 0x01, 0x05];
    let decoded = assert_build_decode_compile_roundtrip(pdu, &expected)?;
    let unknown = decoded.as_unknown().expect("unknown PDU");

    assert_eq!(decoded.tag_number(), 9);
    assert_eq!(decoded.tag_label(), "pdu-9");
    assert_eq!(decoded.tag_status(), SnmpPduTagStatus::Unknown);
    assert_eq!(unknown.tag_number(), 9);
    assert!(unknown.is_constructed());
    assert_eq!(unknown.body(), &[0x02, 0x01, 0x05]);
    assert_eq!(unknown.raw_tlv_bytes(), Some(&expected[..]));
    assert_eq!(
        decoded.summary(),
        "SnmpPdu(pdu_type=pdu-9 pdu_tag=9 constructed=true body_length=3)"
    );
    assert_eq!(
        decoded.show(),
        concat!(
            "SnmpPdu\n",
            "  pdu_type: pdu-9\n",
            "  pdu_tag: 9\n",
            "  pdu_tag_status: unknown\n",
            "  constructed: true\n",
            "  body_length: 3\n",
            "  pdu_ber_length: 3\n",
            "  body_bytes: 02 01 05\n",
            "  pdu_tlv_len: 5\n",
            "  pdu_tlv_bytes: a9 03 02 01 05",
        )
    );

    let primitive_known_tag = SnmpPdu::unknown(SnmpPdu::TAG_GET_REQUEST, false, [0xaa]);
    let primitive_expected = [0x80, 0x01, 0xaa];
    let decoded = assert_build_decode_compile_roundtrip(primitive_known_tag, &primitive_expected)?;
    let unknown = decoded.as_unknown().expect("primitive known tag is raw");

    assert_eq!(decoded.tag_number(), SnmpPdu::TAG_GET_REQUEST);
    assert_eq!(decoded.tag_label(), "get-request");
    assert_eq!(decoded.tag_status(), SnmpPduTagStatus::Assigned);
    assert!(!unknown.is_constructed());
    assert_eq!(unknown.body(), &[0xaa]);

    Ok(())
}
