use crafter::protocols::snmp::{SnmpOid, SnmpVarBind, SnmpVarBindList};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

fn prop_result<T>(result: crafter::Result<T>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn oid_arcs() -> impl Strategy<Value = Vec<u32>> {
    (
        0u32..=2,
        0u32..=39,
        prop::collection::vec(0u32..=16_384, 0..8),
    )
        .prop_map(|(first, second, rest)| {
            let mut arcs = Vec::with_capacity(2 + rest.len());
            arcs.push(first);
            arcs.push(second);
            arcs.extend(rest);
            arcs
        })
}

fn oid_from_arcs(arcs: Vec<u32>) -> Result<SnmpOid, TestCaseError> {
    prop_result(SnmpOid::from_arcs(arcs))
}

fn assert_varbind_roundtrip(varbind: SnmpVarBind) -> Result<(), TestCaseError> {
    let bytes = prop_result(varbind.compile())?;
    let (decoded, rest) = prop_result(SnmpVarBind::decode(&bytes))?;

    prop_assert!(rest.is_empty());
    prop_assert_eq!(prop_result(decoded.compile())?, bytes);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn snmp_prop_oid_roundtrips(arcs in oid_arcs()) {
        let oid = oid_from_arcs(arcs.clone())?;
        let bytes = prop_result(oid.to_bytes())?;
        let (decoded, rest) = prop_result(SnmpOid::decode(&bytes))?;

        prop_assert!(rest.is_empty());
        prop_assert_eq!(decoded.as_slice(), arcs.as_slice());
        prop_assert_eq!(prop_result(decoded.to_bytes())?, bytes);
    }

    #[test]
    fn snmp_prop_integer_and_octet_varbinds_roundtrip(
        name_arcs in oid_arcs(),
        integer in -1_000_000i64..=1_000_000,
        octets in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let name = oid_from_arcs(name_arcs.clone())?;
        assert_varbind_roundtrip(SnmpVarBind::integer(name.clone(), integer))?;
        assert_varbind_roundtrip(SnmpVarBind::octet_string(name, octets))?;
    }

    #[test]
    fn snmp_prop_application_varbinds_roundtrip(
        name_arcs in oid_arcs(),
        selector in 0u8..=4,
        value in any::<u64>(),
    ) {
        let name = oid_from_arcs(name_arcs)?;
        let octets = value.to_be_bytes();
        let varbind = match selector {
            0 => SnmpVarBind::ip_address(name, [octets[4], octets[5], octets[6], octets[7]]),
            1 => SnmpVarBind::counter32(name, value as u32),
            2 => SnmpVarBind::gauge32(name, value as u32),
            3 => SnmpVarBind::time_ticks(name, value as u32),
            _ => SnmpVarBind::counter64(name, value),
        };

        assert_varbind_roundtrip(varbind)?;
    }

    #[test]
    fn snmp_prop_varbind_lists_preserve_order(name_arcs in prop::collection::vec(oid_arcs(), 0..6)) {
        let mut expected_names = Vec::with_capacity(name_arcs.len());
        let mut varbinds = Vec::with_capacity(name_arcs.len());
        for arcs in name_arcs {
            let oid = oid_from_arcs(arcs)?;
            expected_names.push(oid.clone());
            varbinds.push(SnmpVarBind::null(oid));
        }
        let list = SnmpVarBindList::new(varbinds);
        let bytes = prop_result(list.compile())?;
        let (decoded, rest) = prop_result(SnmpVarBindList::decode(&bytes))?;

        prop_assert!(rest.is_empty());
        prop_assert_eq!(decoded.len(), expected_names.len());
        for (decoded, expected) in decoded.as_slice().iter().zip(expected_names.iter()) {
            prop_assert_eq!(decoded.name(), expected);
            prop_assert!(decoded.is_null_value());
        }
        prop_assert_eq!(prop_result(decoded.compile())?, bytes);
    }

    #[test]
    fn snmp_prop_raw_unknown_tlvs_roundtrip(
        name_arcs in oid_arcs(),
        tag in 0u8..=30,
        content in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let name = oid_from_arcs(name_arcs)?;
        let mut raw_tlv = Vec::with_capacity(2 + content.len());
        raw_tlv.push(0xc0 | tag);
        raw_tlv.push(content.len() as u8);
        raw_tlv.extend_from_slice(&content);
        let varbind = SnmpVarBind::raw_value_tlv(name, raw_tlv.clone());

        let bytes = prop_result(varbind.compile())?;
        let (decoded, rest) = prop_result(SnmpVarBind::decode(&bytes))?;

        prop_assert!(rest.is_empty());
        prop_assert_eq!(decoded.raw_value_tlv_bytes(), Some(raw_tlv.as_slice()));
        prop_assert_eq!(decoded.unknown_value_class(), Some("private"));
        prop_assert_eq!(decoded.unknown_value_content(), Some(content.as_slice()));
        prop_assert_eq!(prop_result(decoded.compile())?, bytes);
    }
}
