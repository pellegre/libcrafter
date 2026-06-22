use super::super::*;
use super::*;
use crate::error::CrafterError;

#[test]
fn dot11_constants_frame_control_masks_match_ieee_layout() {
    assert_eq!(DOT11_FRAME_CONTROL_LEN, 2);
    assert_eq!(DOT11_DURATION_ID_LEN, 2);
    assert_eq!(DOT11_ADDRESS_LEN, 6);
    assert_eq!(DOT11_SEQUENCE_CONTROL_LEN, 2);
    assert_eq!(DOT11_QOS_CONTROL_LEN, 2);
    assert_eq!(DOT11_HT_CONTROL_LEN, 4);
    assert_eq!(DOT11_MIN_HEADER_LEN, 10);
    assert_eq!(DOT11_DATA_HEADER_LEN, 24);
    assert_eq!(DOT11_DATA_ADDR4_HEADER_LEN, 30);
    assert_eq!(DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN, 10);
    assert_eq!(DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN, 16);

    assert_eq!(DOT11_FC_PROTOCOL_VERSION_MASK, 0x0003);
    assert_eq!(DOT11_FC_PROTOCOL_VERSION_SHIFT, 0);
    assert_eq!(DOT11_FC_TYPE_MASK, 0x000c);
    assert_eq!(DOT11_FC_TYPE_SHIFT, 2);
    assert_eq!(DOT11_FC_SUBTYPE_MASK, 0x00f0);
    assert_eq!(DOT11_FC_SUBTYPE_SHIFT, 4);

    assert_eq!(DOT11_FC_TO_DS, 0x0100);
    assert_eq!(DOT11_FC_FROM_DS, 0x0200);
    assert_eq!(DOT11_FC_MORE_FRAGMENTS, 0x0400);
    assert_eq!(DOT11_FC_RETRY, 0x0800);
    assert_eq!(DOT11_FC_POWER_MANAGEMENT, 0x1000);
    assert_eq!(DOT11_FC_MORE_DATA, 0x2000);
    assert_eq!(DOT11_FC_PROTECTED, 0x4000);
    assert_eq!(DOT11_FC_ORDER, 0x8000);
}

#[test]
fn dot11_header_length_data_family_tracks_ds_qos_and_ht_control_boundaries() {
    let data = dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_DATA);
    let four_address = data.with_to_ds(true).with_from_ds(true);
    let qos = dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_QOS_DATA);
    let qos_four_address = qos.with_to_ds(true).with_from_ds(true);
    let qos_four_address_htc = qos_four_address.with_order(true);
    let non_qos_order = data.with_order(true);

    assert_eq!(Dot11::minimum_header_len_for(data), DOT11_DATA_HEADER_LEN);
    assert_eq!(
        Dot11::minimum_header_len_for(four_address),
        DOT11_DATA_ADDR4_HEADER_LEN
    );
    assert_eq!(
        Dot11::minimum_header_len_for(qos),
        DOT11_DATA_HEADER_LEN + DOT11_QOS_CONTROL_LEN
    );
    assert_eq!(
        Dot11::minimum_header_len_for(qos_four_address),
        DOT11_DATA_ADDR4_HEADER_LEN + DOT11_QOS_CONTROL_LEN
    );
    assert_eq!(
        Dot11::minimum_header_len_for(qos_four_address_htc),
        DOT11_DATA_ADDR4_HEADER_LEN + DOT11_QOS_CONTROL_LEN + DOT11_HT_CONTROL_LEN
    );
    assert_eq!(
        Dot11::minimum_header_len_for(non_qos_order),
        DOT11_DATA_HEADER_LEN
    );
    assert_eq!(Dot11::data().minimum_header_len(), DOT11_DATA_HEADER_LEN);
    assert_eq!(
        Dot11::qos_data().minimum_header_len(),
        DOT11_DATA_HEADER_LEN + DOT11_QOS_CONTROL_LEN
    );
}

#[test]
fn dot11_header_length_management_family_includes_selected_fixed_fields() {
    let cases = [
        (
            DOT11_MGMT_SUBTYPE_ASSOCIATION_REQUEST,
            DOT11_MGMT_ASSOCIATION_REQUEST_FIXED_LEN,
        ),
        (
            DOT11_MGMT_SUBTYPE_ASSOCIATION_RESPONSE,
            DOT11_MGMT_ASSOCIATION_RESPONSE_FIXED_LEN,
        ),
        (
            DOT11_MGMT_SUBTYPE_REASSOCIATION_REQUEST,
            DOT11_MGMT_REASSOCIATION_REQUEST_FIXED_LEN,
        ),
        (
            DOT11_MGMT_SUBTYPE_REASSOCIATION_RESPONSE,
            DOT11_MGMT_REASSOCIATION_RESPONSE_FIXED_LEN,
        ),
        (DOT11_MGMT_SUBTYPE_PROBE_REQUEST, 0),
        (
            DOT11_MGMT_SUBTYPE_PROBE_RESPONSE,
            DOT11_MGMT_PROBE_RESPONSE_FIXED_LEN,
        ),
        (DOT11_MGMT_SUBTYPE_BEACON, DOT11_MGMT_BEACON_FIXED_LEN),
        (DOT11_MGMT_SUBTYPE_ATIM, 0),
        (
            DOT11_MGMT_SUBTYPE_DISASSOCIATION,
            DOT11_MGMT_DISASSOCIATION_FIXED_LEN,
        ),
        (
            DOT11_MGMT_SUBTYPE_AUTHENTICATION,
            DOT11_MGMT_AUTHENTICATION_FIXED_LEN,
        ),
        (
            DOT11_MGMT_SUBTYPE_DEAUTHENTICATION,
            DOT11_MGMT_DEAUTHENTICATION_FIXED_LEN,
        ),
        (DOT11_MGMT_SUBTYPE_ACTION, DOT11_MGMT_ACTION_FIXED_LEN),
        (
            DOT11_MGMT_SUBTYPE_ACTION_NO_ACK,
            DOT11_MGMT_ACTION_FIXED_LEN,
        ),
        (7, 0),
    ];

    for (subtype, fixed_len) in cases {
        let frame_control = dot11_test_frame_control(DOT11_FRAME_TYPE_MANAGEMENT, subtype);

        assert_eq!(
            Dot11::minimum_header_len_for(frame_control),
            DOT11_DATA_HEADER_LEN + fixed_len,
            "management subtype {subtype}"
        );
    }

    let beacon_with_ht_control =
        dot11_test_frame_control(DOT11_FRAME_TYPE_MANAGEMENT, DOT11_MGMT_SUBTYPE_BEACON)
            .with_order(true);

    assert_eq!(
        Dot11::minimum_header_len_for(beacon_with_ht_control),
        DOT11_DATA_HEADER_LEN + DOT11_HT_CONTROL_LEN + DOT11_MGMT_BEACON_FIXED_LEN
    );
}

#[test]
fn dot11_header_length_control_family_uses_subtype_address_layouts() {
    let one_address = [
        DOT11_CONTROL_SUBTYPE_CTS,
        DOT11_CONTROL_SUBTYPE_ACK,
        0,
        DOT11_CONTROL_SUBTYPE_TRIGGER,
    ];
    let two_address = [
        DOT11_CONTROL_SUBTYPE_BLOCK_ACK_REQUEST,
        DOT11_CONTROL_SUBTYPE_BLOCK_ACK,
        DOT11_CONTROL_SUBTYPE_RTS,
        DOT11_CONTROL_SUBTYPE_PS_POLL,
        DOT11_CONTROL_SUBTYPE_CF_END,
        DOT11_CONTROL_SUBTYPE_CF_END_CF_ACK,
    ];

    for subtype in one_address {
        let frame_control = dot11_test_frame_control(DOT11_FRAME_TYPE_CONTROL, subtype);

        assert_eq!(
            Dot11::minimum_header_len_for(frame_control),
            DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN,
            "control subtype {subtype}"
        );
    }

    for subtype in two_address {
        let frame_control = dot11_test_frame_control(DOT11_FRAME_TYPE_CONTROL, subtype);

        assert_eq!(
            Dot11::minimum_header_len_for(frame_control),
            DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            "control subtype {subtype}"
        );
    }
}

#[test]
fn dot11_header_length_from_bytes_reports_supported_boundaries() {
    let qos_four_address_htc =
        dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_QOS_DATA)
            .with_to_ds(true)
            .with_from_ds(true)
            .with_order(true);
    let header_len = DOT11_DATA_ADDR4_HEADER_LEN + DOT11_QOS_CONTROL_LEN + DOT11_HT_CONTROL_LEN;
    let bytes = dot11_test_bytes(qos_four_address_htc, header_len + 3);

    assert_eq!(Dot11::header_len_from_bytes(&bytes).unwrap(), header_len);

    let ack = dot11_test_frame_control(DOT11_FRAME_TYPE_CONTROL, DOT11_CONTROL_SUBTYPE_ACK);
    let bytes = dot11_test_bytes(ack, DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN);

    assert_eq!(
        Dot11::header_len_from_bytes(&bytes).unwrap(),
        DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN
    );
}

#[test]
fn dot11_header_length_from_bytes_rejects_truncated_boundaries() {
    let err = Dot11::header_len_from_bytes([0x08]).unwrap_err();

    assert_eq!(
        err,
        CrafterError::buffer_too_short("dot11.frame_control", 2, 1)
    );

    let beacon = dot11_test_frame_control(DOT11_FRAME_TYPE_MANAGEMENT, DOT11_MGMT_SUBTYPE_BEACON);
    let beacon_header_len = DOT11_DATA_HEADER_LEN + DOT11_MGMT_BEACON_FIXED_LEN;
    let err =
        Dot11::header_len_from_bytes(dot11_test_bytes(beacon, beacon_header_len - 1)).unwrap_err();

    assert_eq!(
        err,
        CrafterError::buffer_too_short("dot11.header", beacon_header_len, beacon_header_len - 1)
    );

    let qos_four_address =
        dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_QOS_DATA)
            .with_to_ds(true)
            .with_from_ds(true);
    let qos_header_len = DOT11_DATA_ADDR4_HEADER_LEN + DOT11_QOS_CONTROL_LEN;
    let err = Dot11::header_len_from_bytes(dot11_test_bytes(qos_four_address, qos_header_len - 1))
        .unwrap_err();

    assert_eq!(
        err,
        CrafterError::buffer_too_short("dot11.header", qos_header_len, qos_header_len - 1)
    );

    let ack = dot11_test_frame_control(DOT11_FRAME_TYPE_CONTROL, DOT11_CONTROL_SUBTYPE_ACK);
    let err = Dot11::header_len_from_bytes(dot11_test_bytes(
        ack,
        DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN - 1,
    ))
    .unwrap_err();

    assert_eq!(
        err,
        CrafterError::buffer_too_short(
            "dot11.header",
            DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN,
            DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN - 1
        )
    );
}

#[test]
fn dot11_constants_type_and_subtype_values_are_stable() {
    assert_eq!(DOT11_FRAME_TYPE_MANAGEMENT, 0);
    assert_eq!(DOT11_FRAME_TYPE_CONTROL, 1);
    assert_eq!(DOT11_FRAME_TYPE_DATA, 2);
    assert_eq!(DOT11_FRAME_TYPE_EXTENSION, 3);

    assert_eq!(DOT11_MGMT_SUBTYPE_ASSOCIATION_REQUEST, 0);
    assert_eq!(DOT11_MGMT_SUBTYPE_PROBE_REQUEST, 4);
    assert_eq!(DOT11_MGMT_SUBTYPE_BEACON, 8);
    assert_eq!(DOT11_MGMT_SUBTYPE_AUTHENTICATION, 11);
    assert_eq!(DOT11_MGMT_SUBTYPE_DEAUTHENTICATION, 12);
    assert_eq!(DOT11_MGMT_SUBTYPE_ACTION_NO_ACK, 14);

    assert_eq!(DOT11_CONTROL_SUBTYPE_TRIGGER, 2);
    assert_eq!(DOT11_CONTROL_SUBTYPE_BLOCK_ACK_REQUEST, 8);
    assert_eq!(DOT11_CONTROL_SUBTYPE_RTS, 11);
    assert_eq!(DOT11_CONTROL_SUBTYPE_CTS, 12);
    assert_eq!(DOT11_CONTROL_SUBTYPE_ACK, 13);

    assert_eq!(DOT11_DATA_SUBTYPE_DATA, 0);
    assert_eq!(DOT11_DATA_SUBTYPE_NULL, 4);
    assert_eq!(DOT11_DATA_SUBTYPE_QOS_DATA, 8);
    assert_eq!(DOT11_DATA_SUBTYPE_QOS_NULL, 12);
    assert_eq!(DOT11_DATA_SUBTYPE_QOS_CF_ACK_CF_POLL, 15);
}

#[test]
fn dot11_constants_label_helpers_cover_known_values() {
    assert_eq!(
        dot11_frame_type_label(DOT11_FRAME_TYPE_MANAGEMENT),
        "management"
    );
    assert_eq!(dot11_frame_type_label(DOT11_FRAME_TYPE_CONTROL), "control");
    assert_eq!(dot11_frame_type_label(DOT11_FRAME_TYPE_DATA), "data");
    assert_eq!(
        dot11_frame_type_label(DOT11_FRAME_TYPE_EXTENSION),
        "extension"
    );

    assert_eq!(
        dot11_management_subtype_label(DOT11_MGMT_SUBTYPE_BEACON),
        "beacon"
    );
    assert_eq!(
        dot11_management_subtype_label(DOT11_MGMT_SUBTYPE_AUTHENTICATION),
        "authentication"
    );
    assert_eq!(
        dot11_control_subtype_label(DOT11_CONTROL_SUBTYPE_RTS),
        "rts"
    );
    assert_eq!(
        dot11_control_subtype_label(DOT11_CONTROL_SUBTYPE_ACK),
        "ack"
    );
    assert_eq!(dot11_data_subtype_label(DOT11_DATA_SUBTYPE_DATA), "data");
    assert_eq!(
        dot11_data_subtype_label(DOT11_DATA_SUBTYPE_QOS_DATA),
        "qos-data"
    );

    assert_eq!(
        dot11_subtype_label(
            DOT11_FRAME_TYPE_MANAGEMENT,
            DOT11_MGMT_SUBTYPE_PROBE_REQUEST
        ),
        "probe-request"
    );
    assert_eq!(
        dot11_subtype_label(DOT11_FRAME_TYPE_CONTROL, DOT11_CONTROL_SUBTYPE_CTS),
        "cts"
    );
    assert_eq!(
        dot11_subtype_label(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_QOS_NULL),
        "qos-null"
    );
}

#[test]
fn dot11_constants_label_helpers_format_unknown_fallbacks() {
    assert_eq!(dot11_frame_type_label(4), "unknown-frame-type(4)");
    assert_eq!(
        dot11_management_subtype_label(7),
        "unknown-management-subtype(7)"
    );
    assert_eq!(dot11_control_subtype_label(0), "unknown-control-subtype(0)");
    assert_eq!(dot11_data_subtype_label(13), "unknown-data-subtype(13)");
    assert_eq!(
        dot11_subtype_label(DOT11_FRAME_TYPE_EXTENSION, 9),
        "extension-subtype(9)"
    );
    assert_eq!(
        dot11_subtype_label(6, 1),
        "unknown-frame-type(6)-subtype(1)"
    );
    assert_eq!(dot11_category_label(42), "unknown-category(42)");
}

#[test]
fn dot11_constants_sequence_category_and_capability_values_are_stable() {
    assert_eq!(DOT11_SEQUENCE_FRAGMENT_NUMBER_MASK, 0x000f);
    assert_eq!(DOT11_SEQUENCE_FRAGMENT_NUMBER_SHIFT, 0);
    assert_eq!(DOT11_SEQUENCE_NUMBER_MASK, 0xfff0);
    assert_eq!(DOT11_SEQUENCE_NUMBER_SHIFT, 4);

    assert_eq!(DOT11_CATEGORY_SPECTRUM_MANAGEMENT, 0);
    assert_eq!(DOT11_CATEGORY_BLOCK_ACK, 3);
    assert_eq!(DOT11_CATEGORY_PUBLIC, 4);
    assert_eq!(DOT11_CATEGORY_SA_QUERY, 8);
    assert_eq!(DOT11_CATEGORY_SELF_PROTECTED, 15);
    assert_eq!(
        dot11_category_label(DOT11_CATEGORY_PROTECTED_DUAL_OF_PUBLIC_ACTION),
        "protected-dual-of-public-action"
    );

    assert_eq!(DOT11_CAPABILITY_ESS, 0x0001);
    assert_eq!(DOT11_CAPABILITY_IBSS, 0x0002);
    assert_eq!(DOT11_CAPABILITY_PRIVACY, 0x0010);
    assert_eq!(DOT11_CAPABILITY_QOS, 0x0200);
    assert_eq!(DOT11_CAPABILITY_SHORT_SLOT_TIME, 0x0400);
    assert_eq!(DOT11_CAPABILITY_IMMEDIATE_BLOCK_ACK, 0x8000);

    assert_eq!(DOT11_TAG_SSID, 0);
    assert_eq!(DOT11_TAG_SUPPORTED_RATES, 1);
    assert_eq!(DOT11_TAG_DS_PARAMETER_SET, 3);
    assert_eq!(DOT11_TAG_TIM, 5);
    assert_eq!(DOT11_TAG_RSN, 48);
}
