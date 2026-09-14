use super::*;
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn radio_vht_reference_independent_metadata() {
    let rows = include_str!("../../tests/fixtures/iq/vht-reference-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 9253);
    for row in rows.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        let expected: Value = serde_json::from_str(c[3]).unwrap();
        let a = if c[2].is_empty() {
            None
        } else {
            Some(hex(c[2]).try_into().unwrap())
        };
        let result = VhtPhy::reference(hex(c[1]).try_into().unwrap(), a);
        match result {
            Ok(actual) => assert_eq!(serde_json::to_value(actual).unwrap(), expected, "{}", c[0]),
            Err(_) => assert!(expected.is_null(), "{}", c[0]),
        }
    }
}
fn recovered() -> Value {
    serde_json::json!({"vht":{
        "mcs":8, "bandwidth_code":0, "space_time_streams":1, "stbc":false,
        "coding":"bcc", "guard_interval_ns":400, "short_gi_disambiguation":false,
        "group_id":63, "partial_aid":0, "beamformed":false,
        "txop_ps_not_allowed":false, "ldpc_extra_symbol":false,
        "apep_length_bounds":[97,100], "service_crc_verified":true,
    },"ampdu":{"delimiter_offset":0,"control_bits":1}})
}
#[test]
fn radio_vht_recovered_fields_and_bounds() {
    let value = recovered();
    let actual = VhtPhy::recovered(&value, 60).unwrap();
    let reference = VhtPhy::reference([255, 1, 4, 0, 129, 0, 0, 0, 0, 63, 0, 0], None).unwrap();
    assert!(actual.compatible(&reference));
    assert_eq!(actual.rate_bps(), 86_666_666);
    assert!(!reference.unknown_configuration());
    for (key, bad) in [
        ("mcs", serde_json::json!(9)),
        ("mcs", serde_json::json!(-1)),
        ("bandwidth_code", serde_json::json!(1)),
        ("space_time_streams", serde_json::json!(2)),
        ("stbc", serde_json::json!(true)),
        ("coding", serde_json::json!("unknown")),
        ("guard_interval_ns", serde_json::json!(1600)),
        ("short_gi_disambiguation", Value::Null),
        ("group_id", serde_json::json!(1)),
        ("partial_aid", serde_json::json!(512)),
        ("beamformed", Value::Null),
        ("service_crc_verified", serde_json::json!(false)),
        ("apep_length_bounds", serde_json::json!([0, 0])),
        ("apep_length_bounds", serde_json::json!([97, 99])),
        ("apep_length_bounds", serde_json::json!([96, 100])),
        ("apep_length_bounds", serde_json::json!([524285, 524288])),
        ("txop_ps_not_allowed", serde_json::json!(0)),
        ("ldpc_extra_symbol", serde_json::json!(true)),
    ] {
        let mut bad_value = value.clone();
        bad_value["vht"][key] = bad;
        assert!(VhtPhy::recovered(&bad_value, 60).is_err(), "{key}");
    }
    for bad in [
        serde_json::json!(1),
        serde_json::json!(40),
        serde_json::json!(u64::MAX),
        Value::Null,
    ] {
        let mut invalid = value.clone();
        invalid["ampdu"]["delimiter_offset"] = bad;
        assert!(VhtPhy::recovered(&invalid, 60).is_err());
    }
    let mut ldpc = value.clone();
    ldpc["vht"]["coding"] = serde_json::json!("ldpc");
    ldpc["vht"]["ldpc_extra_symbol"] = serde_json::json!(true);
    let decoded = VhtPhy::recovered(&ldpc, 60).unwrap();
    let reference_ldpc =
        VhtPhy::reference([255, 1, 20, 0, 129, 0, 0, 0, 1, 63, 0, 0], None).unwrap();
    assert!(decoded.compatible(&reference_ldpc));
    assert!(!decoded.compatible(&reference));
    let mut old = value;
    old["vht"]
        .as_object_mut()
        .unwrap()
        .remove("txop_ps_not_allowed");
    old["vht"]
        .as_object_mut()
        .unwrap()
        .remove("ldpc_extra_symbol");
    assert!(VhtPhy::recovered(&old, 60).unwrap().compatible(&reference));
}
#[test]
fn radio_vht_stbc_metadata_uses_spatial_not_space_time_streams() {
    for ldpc in [false, true] {
        let mut value = recovered();
        value["vht"]["stbc"] = serde_json::json!(true);
        value["vht"]["space_time_streams"] = serde_json::json!(2);
        value["vht"]["coding"] = serde_json::json!(if ldpc { "ldpc" } else { "bcc" });
        let actual = VhtPhy::recovered(&value, 60).unwrap();
        let reference =
            VhtPhy::reference([255, 1, 5, 0, 129, 0, 0, 0, u8::from(ldpc), 63, 0, 0], None)
                .unwrap();
        assert_eq!(actual.spatial_streams, 1);
        assert_eq!(actual.stbc, Some(true));
        assert!(actual.compatible(&reference));
        value["vht"]["short_gi_disambiguation"] = serde_json::json!(true);
        assert!(VhtPhy::recovered(&value, 60).is_err());
        assert!(VhtPhy::reference(
            [255, 1, 13, 0, 129, 0, 0, 0, u8::from(ldpc), 63, 0, 0],
            None
        )
        .is_err());
    }
}

#[test]
fn radio_vht_unknown_fields_and_conflicts() {
    let actual = VhtPhy::recovered(&recovered(), 60).unwrap();
    let unknown = VhtPhy::reference(
        [
            0x44, 0, 0xff, 0xe0, 0x81, 0xf0, 0xf0, 0xf0, 0xfe, 201, 255, 255,
        ],
        None,
    )
    .unwrap();
    assert!(unknown.unknown_configuration());
    assert!(actual.compatible(&unknown));
    let mut conflict = actual.clone();
    conflict.group_id = Some(0);
    assert!(!actual.compatible(&conflict));
    conflict = actual.clone();
    conflict.beamformed = Some(true);
    assert!(!actual.compatible(&conflict));
    conflict = actual.clone();
    conflict.partial_aid = Some(1);
    assert!(!actual.compatible(&conflict));
    conflict = actual.clone();
    conflict.short_gi_disambiguation = Some(true);
    assert!(!actual.compatible(&conflict));
    conflict = actual.clone();
    conflict.txop_ps_not_allowed = Some(true);
    assert!(!actual.compatible(&conflict));
    conflict = actual.clone();
    conflict.eof = Some(false);
    assert!(!actual.compatible(&conflict));
    conflict = actual.clone();
    conflict.ldpc = true;
    assert!(!actual.compatible(&conflict));
}
