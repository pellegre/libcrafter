use super::super::*;
use super::*;
use crate::error::CrafterError;
use crate::packet::Layer;
use crate::registry::ProtocolRegistry;
use crate::{Ipv4, LinkType, LlcSnap, Packet, Radiotap, Raw};

#[test]
fn dot11_decode_basic_three_address_data_preserves_raw_tail() {
    let frame_control = dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_DATA);
    let mut bytes = dot11_decode_test_header(frame_control);
    bytes.extend_from_slice(b"payload");

    let decoded = decode_dot11_basic(&bytes);
    let dot11 = decoded.layer::<Dot11>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();

    assert_eq!(dot11.frame_control_value(), frame_control);
    assert_eq!(dot11.duration_id_value(), Some(0x1234));
    assert_eq!(dot11.addr1_value(), Some(dot11_role_mac(1)));
    assert_eq!(dot11.addr2_value(), Some(dot11_role_mac(2)));
    assert_eq!(dot11.addr3_value(), Some(dot11_role_mac(3)));
    assert_eq!(
        dot11.sequence_control_value(),
        Some(Dot11SequenceControl::from_bits(0x5678))
    );
    assert_eq!(dot11.addr4_value(), None);
    assert_eq!(dot11.qos_control_value(), None);
    assert_eq!(raw.as_bytes(), b"payload");
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
}

#[test]
fn dot11_decode_from_link_ieee80211_uses_typed_dot11_root() {
    let frame_control = dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_DATA);
    let mut bytes = dot11_decode_test_header(frame_control);
    bytes.extend_from_slice(b"link-root-payload");

    let decoded = Packet::decode_from_link(LinkType::Ieee80211, &bytes).unwrap();
    let dot11 = decoded.layer::<Dot11>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();

    assert_eq!(dot11.frame_control_value(), frame_control);
    assert_eq!(dot11.addr1_value(), Some(dot11_role_mac(1)));
    assert_eq!(dot11.addr2_value(), Some(dot11_role_mac(2)));
    assert_eq!(dot11.addr3_value(), Some(dot11_role_mac(3)));
    assert_eq!(raw.as_bytes(), b"link-root-payload");
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
}

#[test]
fn dot11_decode_from_link_radiotap_uses_typed_radiotap_root() {
    let bytes = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];

    let decoded = Packet::decode_from_link(LinkType::Radiotap, bytes).unwrap();

    let radiotap = decoded.layer::<Radiotap>().unwrap();
    assert_eq!(radiotap.version_value(), Some(0));
    assert_eq!(radiotap.length_value(), Some(8));
    assert!(radiotap.fields().is_empty());
    assert!(decoded.layer::<Dot11>().is_none());
    assert!(decoded.layer::<Raw>().is_none());
    assert_eq!(decoded.compile().unwrap().as_bytes(), &bytes);
}

#[test]
fn dot11_decode_basic_qos_four_address_data_reads_optional_header_fields() {
    let frame_control =
        dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_QOS_DATA)
            .with_to_ds(true)
            .with_from_ds(true)
            .with_order(true)
            .with_protected(true);
    let mut bytes = dot11_decode_test_header(frame_control);
    bytes.extend_from_slice(&dot11_role_mac(4).octets());
    bytes.extend_from_slice(&0xabcd_u16.to_le_bytes());
    bytes.extend_from_slice(&0x1234_5678_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    let decoded = decode_dot11_basic(&bytes);
    let dot11 = decoded.layer::<Dot11>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();

    assert_eq!(dot11.frame_control_value(), frame_control);
    assert!(dot11.is_protected());
    assert_eq!(dot11.addr4_value(), Some(dot11_role_mac(4)));
    assert_eq!(dot11.qos_control_value(), Some(0xabcd));
    assert_eq!(dot11.ht_control_value(), Some(0x1234_5678));
    assert_eq!(dot11.source(), Some(dot11_role_mac(4)));
    assert_eq!(raw.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
}

#[test]
fn dot11_fragment_metadata_decode_first_middle_and_final_fragments() {
    let cases = [
        ("first", 0x345, 0, true, b"first-fragment".as_slice()),
        ("middle", 0x345, 1, true, b"middle-fragment".as_slice()),
        ("final", 0x345, 2, false, b"final-fragment".as_slice()),
    ];

    for (name, sequence_number, fragment_number, more_fragments, payload) in cases {
        let frame_control =
            dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_DATA)
                .with_more_fragments(more_fragments);
        let sequence_control = Dot11SequenceControl::new()
            .with_sequence_number(sequence_number)
            .with_fragment_number(fragment_number);
        let mut bytes = dot11_decode_test_header(frame_control);
        let sequence_offset =
            DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN + (DOT11_ADDRESS_LEN * 3);
        bytes[sequence_offset..sequence_offset + DOT11_SEQUENCE_CONTROL_LEN]
            .copy_from_slice(&sequence_control.compile());
        bytes.extend_from_slice(payload);

        let decoded = Packet::decode_from_link(LinkType::Ieee80211, &bytes).unwrap();
        let dot11 = decoded.layer::<Dot11>().unwrap();

        assert_eq!(
            dot11.sequence_number_value(),
            Some(sequence_number),
            "{name} sequence number"
        );
        assert_eq!(
            dot11.fragment_number_value(),
            Some(fragment_number),
            "{name} fragment number"
        );
        assert_eq!(
            dot11.has_more_fragments(),
            more_fragments,
            "{name} more-fragments status"
        );
        assert!(dot11.is_fragmented(), "{name} fragmented predicate");
        assert!(decoded.layer::<LlcSnap>().is_none(), "{name} llc dispatch");
        assert_eq!(
            decoded.layer::<Raw>().unwrap().as_bytes(),
            payload,
            "{name} payload remains frame-local raw bytes"
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    let unfragmented = Dot11::data()
        .sequence_number(0x123)
        .fragment_number(0)
        .more_fragments(false);

    assert_eq!(unfragmented.sequence_number_value(), Some(0x123));
    assert_eq!(unfragmented.fragment_number_value(), Some(0));
    assert!(!unfragmented.has_more_fragments());
    assert!(!unfragmented.is_fragmented());
}

#[test]
fn dot11_qos_data_control_fields_encode_decode() {
    let qos_control = Dot11QosControl::new()
        .with_tid(0x2f)
        .with_eosp(true)
        .with_ack_policy(0x07)
        .with_a_msdu_present(true)
        .with_txop_queue_size(0xab);

    assert_eq!(qos_control.bits(), 0xabff);
    assert_eq!(qos_control.tid(), 0x0f);
    assert!(qos_control.eosp());
    assert_eq!(qos_control.ack_policy(), 0x03);
    assert!(qos_control.a_msdu_present());
    assert_eq!(qos_control.txop_queue_size(), 0xab);
    assert_eq!(
        Dot11QosControl::decode(qos_control.compile()).unwrap(),
        qos_control
    );

    let packet = Dot11::qos_data().with_qos_control_fields(qos_control) / Raw::from([0xde, 0xad]);
    let bytes = packet.compile().unwrap();

    assert_eq!(
        &bytes.as_bytes()[DOT11_DATA_HEADER_LEN..DOT11_DATA_HEADER_LEN + DOT11_QOS_CONTROL_LEN],
        &qos_control.compile()
    );

    let decoded = decode_dot11_basic(bytes.as_bytes());
    let dot11 = decoded.layer::<Dot11>().unwrap();
    let decoded_qos = dot11.qos_control_fields().unwrap();

    assert_eq!(dot11.qos_control_value(), Some(qos_control.bits()));
    assert_eq!(decoded_qos, qos_control);
    assert_eq!(decoded_qos.tid(), 0x0f);
    assert!(decoded_qos.eosp());
    assert_eq!(decoded_qos.ack_policy(), 0x03);
    assert!(decoded_qos.a_msdu_present());
    assert_eq!(decoded_qos.txop_queue_size(), 0xab);
    assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[0xde, 0xad]);
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn dot11_qos_data_subtypes_require_qos_control_from_frame_control() {
    let cases = [
        (DOT11_DATA_SUBTYPE_QOS_DATA, Dot11DataSubtype::QosData),
        (
            DOT11_DATA_SUBTYPE_QOS_DATA_CF_ACK,
            Dot11DataSubtype::QosDataCfAck,
        ),
        (
            DOT11_DATA_SUBTYPE_QOS_DATA_CF_POLL,
            Dot11DataSubtype::QosDataCfPoll,
        ),
        (
            DOT11_DATA_SUBTYPE_QOS_DATA_CF_ACK_CF_POLL,
            Dot11DataSubtype::QosDataCfAckCfPoll,
        ),
        (DOT11_DATA_SUBTYPE_QOS_NULL, Dot11DataSubtype::QosNull),
        (13, Dot11DataSubtype::Unknown(13)),
        (DOT11_DATA_SUBTYPE_QOS_CF_POLL, Dot11DataSubtype::QosCfPoll),
        (
            DOT11_DATA_SUBTYPE_QOS_CF_ACK_CF_POLL,
            Dot11DataSubtype::QosCfAckCfPoll,
        ),
    ];

    for (subtype, typed_subtype) in cases {
        let frame_control = dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, subtype);

        assert_eq!(frame_control.data_subtype_value(), Some(typed_subtype));
        assert_eq!(
            Dot11::minimum_header_len_for(frame_control),
            DOT11_DATA_HEADER_LEN + DOT11_QOS_CONTROL_LEN,
            "data subtype {subtype}"
        );

        let mut bytes = dot11_decode_test_header(frame_control);
        bytes.extend_from_slice(&0x1201_u16.to_le_bytes());

        let decoded = decode_dot11_basic(&bytes);
        let dot11 = decoded.layer::<Dot11>().unwrap();
        let qos = dot11.qos_control_fields().unwrap();

        assert_eq!(dot11.data_subtype(), Some(typed_subtype));
        assert_eq!(qos.tid(), 1);
        assert_eq!(qos.txop_queue_size(), 0x12);
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }
}

#[test]
fn dot11_qos_data_truncated_before_qos_control_returns_structured_error() {
    let frame_control =
        dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_QOS_DATA);
    let required = DOT11_DATA_HEADER_LEN + DOT11_QOS_CONTROL_LEN;

    let err = decode_dot11_with_registry(
        &ProtocolRegistry::new(),
        &dot11_test_bytes(frame_control, required - 1),
    )
    .unwrap_err();

    assert_eq!(
        err,
        CrafterError::buffer_too_short("dot11.header", required, required - 1)
    );
}

#[test]
fn dot11_qos_data_absent_for_plain_data_preserves_tail_as_raw() {
    let frame_control = dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_DATA);
    let mut bytes = dot11_decode_test_header(frame_control);
    bytes.extend_from_slice(&0xabcd_u16.to_le_bytes());

    let decoded = decode_dot11_basic(&bytes);
    let dot11 = decoded.layer::<Dot11>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();

    assert_eq!(
        Dot11::header_len_from_bytes(&bytes).unwrap(),
        DOT11_DATA_HEADER_LEN
    );
    assert_eq!(dot11.data_subtype(), Some(Dot11DataSubtype::Data));
    assert_eq!(dot11.qos_control_value(), None);
    assert_eq!(dot11.qos_control_fields(), None);
    assert_eq!(raw.as_bytes(), &0xabcd_u16.to_le_bytes());
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
}

#[test]
fn dot11_qos_data_explicit_raw_override_preserved_on_non_qos_compile() {
    let qos_control = Dot11QosControl::from_bits(0xf135);
    let dot11 = Dot11::data().qos_control(qos_control.bits());
    let packet = Packet::from_layer(dot11.clone());
    let bytes = packet.compile().unwrap();

    assert_eq!(dot11.data_subtype(), Some(Dot11DataSubtype::Data));
    assert_eq!(dot11.qos_control_value(), Some(qos_control.bits()));
    assert_eq!(dot11.qos_control_fields(), Some(qos_control));
    assert_eq!(
        dot11.encoded_len(),
        DOT11_DATA_HEADER_LEN + DOT11_QOS_CONTROL_LEN
    );
    assert_eq!(
        &bytes.as_bytes()[DOT11_DATA_HEADER_LEN..DOT11_DATA_HEADER_LEN + DOT11_QOS_CONTROL_LEN],
        &qos_control.compile()
    );

    let decoded = decode_dot11_basic(bytes.as_bytes());

    assert_eq!(decoded.layer::<Dot11>().unwrap().qos_control_value(), None);
    assert_eq!(
        decoded.layer::<Raw>().unwrap().as_bytes(),
        &qos_control.compile()
    );
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn dot11_decode_basic_unknown_valid_subtype_stays_typed_with_raw_tail() {
    let frame_control = dot11_test_frame_control(DOT11_FRAME_TYPE_MANAGEMENT, 7).with_retry(true);
    let mut bytes = dot11_decode_test_header(frame_control);
    bytes.extend_from_slice(b"unknown-management-body");

    let decoded = decode_dot11_basic(&bytes);
    let dot11 = decoded.layer::<Dot11>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();

    assert_eq!(
        dot11.management_subtype(),
        Some(Dot11ManagementSubtype::Unknown(7))
    );
    assert!(dot11.frame_control_value().retry());
    assert_eq!(raw.as_bytes(), b"unknown-management-body");
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
}

#[test]
fn dot11_llc_dispatch_unprotected_data_decodes_snap_ipv4() {
    let packet = Dot11::data() / LlcSnap::new() / Ipv4::new() / Raw::from("v4");
    let bytes = packet.compile().unwrap();

    let decoded = Packet::decode_from_link(LinkType::Ieee80211, bytes.as_bytes()).unwrap();

    assert!(decoded.layer::<Dot11>().is_some());
    assert!(decoded.layer::<LlcSnap>().is_some());
    assert!(decoded.layer::<Ipv4>().is_some());
    assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), b"v4");
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn dot11_protected_data_raw_body_len_and_no_llc_dispatch() {
    let frame_control = dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_DATA)
        .with_protected(true);
    let encrypted_body = [
        0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef,
    ];
    let mut bytes = dot11_decode_test_header(frame_control);
    bytes.extend_from_slice(&encrypted_body);

    let decoded = Packet::decode_from_link(LinkType::Ieee80211, &bytes).unwrap();
    let dot11 = decoded.layer::<Dot11>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();

    assert!(dot11.is_protected());
    assert_eq!(dot11.encrypted_body_len(), Some(encrypted_body.len()));
    assert!(decoded.layer::<LlcSnap>().is_none());
    assert!(decoded.layer::<Ipv4>().is_none());
    assert_eq!(raw.as_bytes(), encrypted_body.as_slice());

    let summary = decoded.summary();
    assert!(summary.contains("protected=true"), "{summary}");
    assert!(summary.contains("encrypted_body_len=12"), "{summary}");

    let fields = dot11.inspection_fields();
    assert_eq!(
        dot11_inspection_value(&fields, "protected"),
        Some("true".into())
    );
    assert_eq!(
        dot11_inspection_value(&fields, "encrypted_body_len"),
        Some("12".into())
    );
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_slice());
}

#[test]
fn dot11_llc_dispatch_protected_data_keeps_body_raw() {
    let frame_control = Dot11::data().frame_control_value().with_protected(true);
    let dot11 = Dot11::data().frame_control(frame_control);
    let packet = dot11.clone() / LlcSnap::new() / Ipv4::new() / Raw::from("v4");
    let bytes = packet.compile().unwrap();

    let decoded = Packet::decode_from_link(LinkType::Ieee80211, bytes.as_bytes()).unwrap();

    assert!(decoded.layer::<LlcSnap>().is_none());
    assert!(decoded.layer::<Ipv4>().is_none());
    assert_eq!(
        decoded.layer::<Raw>().unwrap().as_bytes(),
        &bytes.as_bytes()[dot11.encoded_len()..]
    );
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn dot11_llc_dispatch_non_data_frame_keeps_tail_raw() {
    let mut bytes = Packet::from_layer(Dot11::deauthentication())
        .compile()
        .unwrap()
        .into_bytes();
    let llc_bytes = (LlcSnap::new() / Raw::from("management-tail"))
        .compile()
        .unwrap();
    bytes.extend_from_slice(llc_bytes.as_bytes());

    let decoded = Packet::decode_from_link(LinkType::Ieee80211, &bytes).unwrap();

    assert!(decoded.layer::<LlcSnap>().is_none());
    assert!(decoded.layer::<Ipv4>().is_none());
    assert_eq!(
        decoded.layer::<Raw>().unwrap().as_bytes(),
        llc_bytes.as_bytes()
    );
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_slice());
}

#[test]
fn dot11_llc_dispatch_null_data_subtype_keeps_body_raw() {
    let frame_control = dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_NULL);
    let dot11 = Dot11::data().frame_control(frame_control);
    let packet = dot11.clone() / LlcSnap::new() / Ipv4::new() / Raw::from("null-tail");
    let bytes = packet.compile().unwrap();

    let decoded = Packet::decode_from_link(LinkType::Ieee80211, bytes.as_bytes()).unwrap();

    assert!(decoded.layer::<LlcSnap>().is_none());
    assert!(decoded.layer::<Ipv4>().is_none());
    assert_eq!(
        decoded.layer::<Raw>().unwrap().as_bytes(),
        &bytes.as_bytes()[dot11.encoded_len()..]
    );
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn dot11_decode_basic_truncated_headers_return_structured_errors() {
    let err = decode_dot11_with_registry(&ProtocolRegistry::new(), &[0x08]).unwrap_err();

    assert_eq!(
        err,
        CrafterError::buffer_too_short("dot11.frame_control", 2, 1)
    );

    let data = dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_DATA);
    let err = decode_dot11_with_registry(&ProtocolRegistry::new(), &dot11_test_bytes(data, 23))
        .unwrap_err();

    assert_eq!(err, CrafterError::buffer_too_short("dot11.header", 24, 23));

    let qos_four_address_htc =
        dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_QOS_DATA)
            .with_to_ds(true)
            .with_from_ds(true)
            .with_order(true);
    let required = DOT11_DATA_ADDR4_HEADER_LEN + DOT11_QOS_CONTROL_LEN + DOT11_HT_CONTROL_LEN;
    let err = decode_dot11_with_registry(
        &ProtocolRegistry::new(),
        &dot11_test_bytes(qos_four_address_htc, required - 1),
    )
    .unwrap_err();

    assert_eq!(
        err,
        CrafterError::buffer_too_short("dot11.header", required, required - 1)
    );
}

#[test]
fn dot11_decode_basic_control_two_address_frame_preserves_supported_addresses() {
    let frame_control =
        dot11_test_frame_control(DOT11_FRAME_TYPE_CONTROL, DOT11_CONTROL_SUBTYPE_RTS);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&frame_control.compile());
    bytes.extend_from_slice(&0x9999u16.to_le_bytes());
    bytes.extend_from_slice(&dot11_role_mac(1).octets());
    bytes.extend_from_slice(&dot11_role_mac(2).octets());
    bytes.extend_from_slice(b"rts-tail");

    let decoded = decode_dot11_basic(&bytes);
    let dot11 = decoded.layer::<Dot11>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();

    assert_eq!(dot11.control_subtype(), Some(Dot11ControlSubtype::Rts));
    assert_eq!(dot11.duration_id_value(), Some(0x9999));
    assert_eq!(dot11.addr1_value(), Some(dot11_role_mac(1)));
    assert_eq!(dot11.addr2_value(), Some(dot11_role_mac(2)));
    assert_eq!(dot11.addr3_value(), None);
    assert_eq!(dot11.sequence_control_value(), None);
    assert_eq!(raw.as_bytes(), b"rts-tail");
}

#[test]
fn dot11_control_frames_encode_decode_supported_address_layouts() {
    let ra = dot11_role_mac(1);
    let ta = dot11_role_mac(2);
    let cases = [
        (
            Dot11::ack().addr1(ra),
            Dot11ControlSubtype::Ack,
            DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN,
            false,
        ),
        (
            Dot11::cts().addr1(ra),
            Dot11ControlSubtype::Cts,
            DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN,
            false,
        ),
        (
            Dot11::rts().addr1(ra).addr2(ta),
            Dot11ControlSubtype::Rts,
            DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            true,
        ),
        (
            Dot11::ps_poll().addr1(ra).addr2(ta),
            Dot11ControlSubtype::PsPoll,
            DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            true,
        ),
        (
            Dot11::cf_end().addr1(ra).addr2(ta),
            Dot11ControlSubtype::CfEnd,
            DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            true,
        ),
        (
            Dot11::cf_end_cf_ack().addr1(ra).addr2(ta),
            Dot11ControlSubtype::CfEndCfAck,
            DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            true,
        ),
        (
            Dot11::block_ack_request().addr1(ra).addr2(ta),
            Dot11ControlSubtype::BlockAckRequest,
            DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            true,
        ),
        (
            Dot11::block_ack().addr1(ra).addr2(ta),
            Dot11ControlSubtype::BlockAck,
            DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            true,
        ),
    ];

    for (frame, subtype, expected_len, has_addr2) in cases {
        let compiled = Packet::from_layer(frame.clone()).compile().unwrap();
        assert_eq!(frame.encoded_len(), expected_len);
        assert_eq!(compiled.as_bytes().len(), expected_len);

        let decoded = decode_dot11_basic(compiled.as_bytes());
        let dot11 = decoded.layer::<Dot11>().unwrap();

        assert_eq!(dot11.frame_type(), Dot11FrameType::Control);
        assert_eq!(dot11.control_subtype(), Some(subtype));
        assert_eq!(dot11.addr1_value(), Some(ra));
        if has_addr2 {
            assert_eq!(dot11.addr2_value(), Some(ta));
            assert_eq!(dot11.transmitter(), Some(ta));
        } else {
            assert_eq!(dot11.addr2_value(), None);
            assert_eq!(dot11.transmitter(), None);
        }
        assert_eq!(dot11.addr3_value(), None);
        assert_eq!(dot11.sequence_control_value(), None);
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }
}

#[test]
fn dot11_control_frames_preserve_unsupported_subtypes_as_raw_tail() {
    let frame_control =
        dot11_test_frame_control(DOT11_FRAME_TYPE_CONTROL, DOT11_CONTROL_SUBTYPE_TRIGGER);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&frame_control.compile());
    bytes.extend_from_slice(&0x0102u16.to_le_bytes());
    bytes.extend_from_slice(&dot11_role_mac(1).octets());
    bytes.extend_from_slice(b"unsupported-control-body");

    let decoded = decode_dot11_basic(&bytes);
    let dot11 = decoded.layer::<Dot11>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();

    assert_eq!(dot11.frame_type(), Dot11FrameType::Control);
    assert_eq!(dot11.control_subtype(), Some(Dot11ControlSubtype::Trigger));
    assert_eq!(dot11.addr1_value(), Some(dot11_role_mac(1)));
    assert_eq!(dot11.addr2_value(), None);
    assert_eq!(raw.as_bytes(), b"unsupported-control-body");
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
}

#[test]
fn dot11_control_frames_truncated_supported_layouts_return_structured_errors() {
    let cases = [
        (
            DOT11_CONTROL_SUBTYPE_ACK,
            DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN,
        ),
        (
            DOT11_CONTROL_SUBTYPE_CTS,
            DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN,
        ),
        (
            DOT11_CONTROL_SUBTYPE_RTS,
            DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
        ),
        (
            DOT11_CONTROL_SUBTYPE_PS_POLL,
            DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
        ),
        (
            DOT11_CONTROL_SUBTYPE_CF_END,
            DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
        ),
        (
            DOT11_CONTROL_SUBTYPE_CF_END_CF_ACK,
            DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
        ),
        (
            DOT11_CONTROL_SUBTYPE_BLOCK_ACK_REQUEST,
            DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
        ),
        (
            DOT11_CONTROL_SUBTYPE_BLOCK_ACK,
            DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
        ),
    ];

    for (subtype, required) in cases {
        let frame_control = dot11_test_frame_control(DOT11_FRAME_TYPE_CONTROL, subtype);
        let available = required - 1;
        let err = decode_dot11_with_registry(
            &ProtocolRegistry::new(),
            &dot11_test_bytes(frame_control, available),
        )
        .unwrap_err();

        assert_eq!(
            err,
            CrafterError::buffer_too_short("dot11.header", required, available),
            "control subtype {subtype}"
        );
    }
}

#[test]
fn dot11_control_frames_preserve_explicit_extra_fields_as_malformed_bytes() {
    let ra = dot11_role_mac(1);
    let ta = dot11_role_mac(2);
    let frame = Dot11::ack().addr1(ra).addr2(ta);
    let compiled = Packet::from_layer(frame.clone()).compile().unwrap();

    assert_eq!(frame.encoded_len(), DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN);
    assert_eq!(
        &compiled.as_bytes()[DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN..],
        ta.octets().as_slice()
    );

    let decoded = decode_dot11_basic(compiled.as_bytes());
    let dot11 = decoded.layer::<Dot11>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();

    assert_eq!(dot11.control_subtype(), Some(Dot11ControlSubtype::Ack));
    assert_eq!(dot11.addr1_value(), Some(ra));
    assert_eq!(dot11.addr2_value(), None);
    assert_eq!(raw.as_bytes(), ta.octets().as_slice());
    assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
}
