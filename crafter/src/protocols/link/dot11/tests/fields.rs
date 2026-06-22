use super::super::*;
use super::*;

#[test]
fn dot11_frame_control_little_endian_decode_and_compile_round_trip() {
    let frame_control = Dot11FrameControl::from_le_bytes([0x88, 0x42]);

    assert_eq!(frame_control.bits(), 0x4288);
    assert_eq!(frame_control.protocol_version(), 0);
    assert_eq!(frame_control.frame_type(), DOT11_FRAME_TYPE_DATA);
    assert_eq!(frame_control.subtype(), DOT11_DATA_SUBTYPE_QOS_DATA);
    assert!(!frame_control.to_ds());
    assert!(frame_control.from_ds());
    assert!(frame_control.protected());
    assert_eq!(frame_control.to_le_bytes(), [0x88, 0x42]);
    assert_eq!(frame_control.compile(), [0x88, 0x42]);
}

#[test]
fn dot11_frame_control_decode_short_buffer_returns_structured_error() {
    let err = Dot11FrameControl::decode([0x08]).unwrap_err();

    assert_eq!(
        err,
        crate::CrafterError::buffer_too_short("dot11.frame_control", 2, 1)
    );
}

#[test]
fn dot11_frame_control_accessors_read_numbered_subfield_bits() {
    assert_eq!(Dot11FrameControl::from_bits(0x0001).protocol_version(), 1);
    assert_eq!(Dot11FrameControl::from_bits(0x0002).protocol_version(), 2);
    assert_eq!(Dot11FrameControl::from_bits(0x0003).protocol_version(), 3);

    assert_eq!(Dot11FrameControl::from_bits(0x0004).frame_type(), 1);
    assert_eq!(Dot11FrameControl::from_bits(0x0008).frame_type(), 2);
    assert_eq!(Dot11FrameControl::from_bits(0x000c).frame_type(), 3);

    assert_eq!(Dot11FrameControl::from_bits(0x0010).subtype(), 1);
    assert_eq!(Dot11FrameControl::from_bits(0x0020).subtype(), 2);
    assert_eq!(Dot11FrameControl::from_bits(0x0040).subtype(), 4);
    assert_eq!(Dot11FrameControl::from_bits(0x0080).subtype(), 8);
    assert_eq!(Dot11FrameControl::from_bits(0x00f0).subtype(), 15);
}

#[test]
fn dot11_frame_control_accessors_read_each_flag_bit() {
    assert!(Dot11FrameControl::from_bits(DOT11_FC_TO_DS).to_ds());
    assert!(Dot11FrameControl::from_bits(DOT11_FC_FROM_DS).from_ds());
    assert!(Dot11FrameControl::from_bits(DOT11_FC_MORE_FRAGMENTS).more_fragments());
    assert!(Dot11FrameControl::from_bits(DOT11_FC_RETRY).retry());
    assert!(Dot11FrameControl::from_bits(DOT11_FC_POWER_MANAGEMENT).power_management());
    assert!(Dot11FrameControl::from_bits(DOT11_FC_MORE_DATA).more_data());
    assert!(Dot11FrameControl::from_bits(DOT11_FC_PROTECTED).protected());
    assert!(Dot11FrameControl::from_bits(DOT11_FC_ORDER).order());

    let empty = Dot11FrameControl::new();
    assert!(!empty.to_ds());
    assert!(!empty.from_ds());
    assert!(!empty.more_fragments());
    assert!(!empty.retry());
    assert!(!empty.power_management());
    assert!(!empty.more_data());
    assert!(!empty.protected());
    assert!(!empty.order());
}

#[test]
fn dot11_frame_control_builder_setters_set_every_bit_position() {
    let frame_control = Dot11FrameControl::new()
        .protocol_version_set(3)
        .frame_type_set(3)
        .subtype_set(15)
        .to_ds_set(true)
        .from_ds_set(true)
        .more_fragments_set(true)
        .retry_set(true)
        .power_management_set(true)
        .more_data_set(true)
        .protected_set(true)
        .order_set(true);

    assert_eq!(frame_control.bits(), 0xffff);
    assert_eq!(frame_control.to_le_bytes(), [0xff, 0xff]);
}

#[test]
fn dot11_frame_control_builder_setters_preserve_unrelated_bits() {
    let frame_control = Dot11FrameControl::from_bits(0xffff)
        .protocol_version_set(0)
        .frame_type_set(0)
        .subtype_set(0)
        .to_ds_set(false)
        .protected_set(false);

    assert_eq!(
        frame_control.bits(),
        !DOT11_FC_PROTOCOL_VERSION_MASK
            & !DOT11_FC_TYPE_MASK
            & !DOT11_FC_SUBTYPE_MASK
            & !DOT11_FC_TO_DS
            & !DOT11_FC_PROTECTED
    );
    assert!(frame_control.from_ds());
    assert!(frame_control.more_fragments());
    assert!(frame_control.retry());
    assert!(frame_control.power_management());
    assert!(frame_control.more_data());
    assert!(frame_control.order());
}

#[test]
fn dot11_frame_control_width_limited_setters_mask_to_wire_subfields() {
    let frame_control = Dot11FrameControl::new()
        .with_protocol_version(0xff)
        .with_frame_type(0xff)
        .with_subtype(0xff);

    assert_eq!(frame_control.protocol_version(), 3);
    assert_eq!(frame_control.frame_type(), 3);
    assert_eq!(frame_control.subtype(), 15);
    assert_eq!(
        frame_control.bits(),
        DOT11_FC_PROTOCOL_VERSION_MASK | DOT11_FC_TYPE_MASK | DOT11_FC_SUBTYPE_MASK
    );
}

#[test]
fn dot11_frame_control_raw_builder_preserves_exact_word() {
    let frame_control = Dot11FrameControl::new().raw(0xa55a);

    assert_eq!(frame_control.bits(), 0xa55a);
    assert_eq!(frame_control.compile(), [0x5a, 0xa5]);
}

#[test]
fn dot11_sequence_control_little_endian_decode_and_compile_round_trip() {
    let sequence_control = Dot11SequenceControl::from_le_bytes([0x7b, 0x12]);

    assert_eq!(sequence_control.bits(), 0x127b);
    assert_eq!(sequence_control.fragment_number(), 0x0b);
    assert_eq!(sequence_control.sequence_number(), 0x127);
    assert_eq!(sequence_control.to_le_bytes(), [0x7b, 0x12]);
    assert_eq!(sequence_control.compile(), [0x7b, 0x12]);
}

#[test]
fn dot11_sequence_control_decode_short_buffer_returns_structured_error() {
    let err = Dot11SequenceControl::decode([0x10]).unwrap_err();

    assert_eq!(
        err,
        crate::CrafterError::buffer_too_short("dot11.sequence_control", 2, 1)
    );
}

#[test]
fn dot11_sequence_control_accessors_read_boundary_values() {
    let empty = Dot11SequenceControl::new();

    assert_eq!(empty.bits(), 0);
    assert_eq!(empty.fragment_number(), 0);
    assert_eq!(empty.sequence_number(), 0);

    let max = Dot11SequenceControl::from_bits(0xffff);

    assert_eq!(max.fragment_number(), 15);
    assert_eq!(max.sequence_number(), 4095);
    assert_eq!(max.to_le_bytes(), [0xff, 0xff]);
}

#[test]
fn dot11_sequence_control_builder_setters_set_boundary_values() {
    let sequence_control = Dot11SequenceControl::new()
        .fragment_number_set(15)
        .sequence_number_set(4095);

    assert_eq!(sequence_control.bits(), 0xffff);
    assert_eq!(sequence_control.fragment_number(), 15);
    assert_eq!(sequence_control.sequence_number(), 4095);
    assert_eq!(sequence_control.compile(), [0xff, 0xff]);
}

#[test]
fn dot11_sequence_control_builder_setters_preserve_unrelated_bits() {
    let sequence_control = Dot11SequenceControl::from_bits(0xffff)
        .fragment_number_set(0)
        .sequence_number_set(0x123);

    assert_eq!(sequence_control.bits(), 0x1230);
    assert_eq!(sequence_control.fragment_number(), 0);
    assert_eq!(sequence_control.sequence_number(), 0x123);
}

#[test]
fn dot11_sequence_control_width_limited_setters_mask_to_wire_subfields() {
    let sequence_control = Dot11SequenceControl::new()
        .with_fragment_number(0xff)
        .with_sequence_number(0xffff);

    assert_eq!(sequence_control.fragment_number(), 15);
    assert_eq!(sequence_control.sequence_number(), 4095);
    assert_eq!(
        sequence_control.bits(),
        DOT11_SEQUENCE_FRAGMENT_NUMBER_MASK | DOT11_SEQUENCE_NUMBER_MASK
    );
}

#[test]
fn dot11_sequence_control_raw_builder_preserves_exact_word() {
    let sequence_control = Dot11SequenceControl::new().raw(0xa55a);

    assert_eq!(sequence_control.bits(), 0xa55a);
    assert_eq!(sequence_control.fragment_number(), 0x0a);
    assert_eq!(sequence_control.sequence_number(), 0xa55);
    assert_eq!(sequence_control.compile(), [0x5a, 0xa5]);
}

#[test]
fn dot11_frame_type_enum_converts_known_frame_types() {
    let cases = [
        (
            DOT11_FRAME_TYPE_MANAGEMENT,
            Dot11FrameType::Management,
            "management",
        ),
        (DOT11_FRAME_TYPE_CONTROL, Dot11FrameType::Control, "control"),
        (DOT11_FRAME_TYPE_DATA, Dot11FrameType::Data, "data"),
        (
            DOT11_FRAME_TYPE_EXTENSION,
            Dot11FrameType::Extension,
            "extension",
        ),
    ];

    for (raw, expected, label) in cases {
        assert_eq!(Dot11FrameType::from_raw(raw), expected);
        assert_eq!(Dot11FrameType::from(raw), expected);
        assert_eq!(expected.raw(), raw);
        assert_eq!(u8::from(expected), raw);
        assert_eq!(expected.label(), label);
    }
}

#[test]
fn dot11_frame_type_management_subtype_enum_converts_known_values() {
    let cases = [
        (
            DOT11_MGMT_SUBTYPE_ASSOCIATION_REQUEST,
            Dot11ManagementSubtype::AssociationRequest,
        ),
        (
            DOT11_MGMT_SUBTYPE_ASSOCIATION_RESPONSE,
            Dot11ManagementSubtype::AssociationResponse,
        ),
        (
            DOT11_MGMT_SUBTYPE_REASSOCIATION_REQUEST,
            Dot11ManagementSubtype::ReassociationRequest,
        ),
        (
            DOT11_MGMT_SUBTYPE_REASSOCIATION_RESPONSE,
            Dot11ManagementSubtype::ReassociationResponse,
        ),
        (
            DOT11_MGMT_SUBTYPE_PROBE_REQUEST,
            Dot11ManagementSubtype::ProbeRequest,
        ),
        (
            DOT11_MGMT_SUBTYPE_PROBE_RESPONSE,
            Dot11ManagementSubtype::ProbeResponse,
        ),
        (
            DOT11_MGMT_SUBTYPE_TIMING_ADVERTISEMENT,
            Dot11ManagementSubtype::TimingAdvertisement,
        ),
        (DOT11_MGMT_SUBTYPE_BEACON, Dot11ManagementSubtype::Beacon),
        (DOT11_MGMT_SUBTYPE_ATIM, Dot11ManagementSubtype::Atim),
        (
            DOT11_MGMT_SUBTYPE_DISASSOCIATION,
            Dot11ManagementSubtype::Disassociation,
        ),
        (
            DOT11_MGMT_SUBTYPE_AUTHENTICATION,
            Dot11ManagementSubtype::Authentication,
        ),
        (
            DOT11_MGMT_SUBTYPE_DEAUTHENTICATION,
            Dot11ManagementSubtype::Deauthentication,
        ),
        (DOT11_MGMT_SUBTYPE_ACTION, Dot11ManagementSubtype::Action),
        (
            DOT11_MGMT_SUBTYPE_ACTION_NO_ACK,
            Dot11ManagementSubtype::ActionNoAck,
        ),
    ];

    for (raw, expected) in cases {
        assert_eq!(Dot11ManagementSubtype::from_raw(raw), expected);
        assert_eq!(Dot11ManagementSubtype::from(raw), expected);
        assert_eq!(expected.raw(), raw);
        assert_eq!(u8::from(expected), raw);
        assert_eq!(expected.label(), dot11_management_subtype_label(raw));
    }
}

#[test]
fn dot11_frame_type_control_subtype_enum_converts_known_values() {
    let cases = [
        (DOT11_CONTROL_SUBTYPE_TRIGGER, Dot11ControlSubtype::Trigger),
        (
            DOT11_CONTROL_SUBTYPE_CONTROL_WRAPPER,
            Dot11ControlSubtype::ControlWrapper,
        ),
        (
            DOT11_CONTROL_SUBTYPE_BLOCK_ACK_REQUEST,
            Dot11ControlSubtype::BlockAckRequest,
        ),
        (
            DOT11_CONTROL_SUBTYPE_BLOCK_ACK,
            Dot11ControlSubtype::BlockAck,
        ),
        (DOT11_CONTROL_SUBTYPE_PS_POLL, Dot11ControlSubtype::PsPoll),
        (DOT11_CONTROL_SUBTYPE_RTS, Dot11ControlSubtype::Rts),
        (DOT11_CONTROL_SUBTYPE_CTS, Dot11ControlSubtype::Cts),
        (DOT11_CONTROL_SUBTYPE_ACK, Dot11ControlSubtype::Ack),
        (DOT11_CONTROL_SUBTYPE_CF_END, Dot11ControlSubtype::CfEnd),
        (
            DOT11_CONTROL_SUBTYPE_CF_END_CF_ACK,
            Dot11ControlSubtype::CfEndCfAck,
        ),
    ];

    for (raw, expected) in cases {
        assert_eq!(Dot11ControlSubtype::from_raw(raw), expected);
        assert_eq!(Dot11ControlSubtype::from(raw), expected);
        assert_eq!(expected.raw(), raw);
        assert_eq!(u8::from(expected), raw);
        assert_eq!(expected.label(), dot11_control_subtype_label(raw));
    }
}

#[test]
fn dot11_frame_type_data_subtype_enum_converts_known_values() {
    let cases = [
        (DOT11_DATA_SUBTYPE_DATA, Dot11DataSubtype::Data),
        (DOT11_DATA_SUBTYPE_DATA_CF_ACK, Dot11DataSubtype::DataCfAck),
        (
            DOT11_DATA_SUBTYPE_DATA_CF_POLL,
            Dot11DataSubtype::DataCfPoll,
        ),
        (
            DOT11_DATA_SUBTYPE_DATA_CF_ACK_CF_POLL,
            Dot11DataSubtype::DataCfAckCfPoll,
        ),
        (DOT11_DATA_SUBTYPE_NULL, Dot11DataSubtype::Null),
        (DOT11_DATA_SUBTYPE_CF_ACK, Dot11DataSubtype::CfAck),
        (DOT11_DATA_SUBTYPE_CF_POLL, Dot11DataSubtype::CfPoll),
        (
            DOT11_DATA_SUBTYPE_CF_ACK_CF_POLL,
            Dot11DataSubtype::CfAckCfPoll,
        ),
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
        (DOT11_DATA_SUBTYPE_QOS_CF_POLL, Dot11DataSubtype::QosCfPoll),
        (
            DOT11_DATA_SUBTYPE_QOS_CF_ACK_CF_POLL,
            Dot11DataSubtype::QosCfAckCfPoll,
        ),
    ];

    for (raw, expected) in cases {
        assert_eq!(Dot11DataSubtype::from_raw(raw), expected);
        assert_eq!(Dot11DataSubtype::from(raw), expected);
        assert_eq!(expected.raw(), raw);
        assert_eq!(u8::from(expected), raw);
        assert_eq!(expected.label(), dot11_data_subtype_label(raw));
    }
}

#[test]
fn dot11_frame_type_enums_preserve_reserved_and_unknown_raw_values() {
    assert_eq!(Dot11FrameType::from_raw(4), Dot11FrameType::Unknown(4));
    assert_eq!(Dot11FrameType::Unknown(0xff).raw(), 0xff);
    assert_eq!(
        Dot11ManagementSubtype::from_raw(7),
        Dot11ManagementSubtype::Unknown(7)
    );
    assert_eq!(Dot11ManagementSubtype::Unknown(0xff).raw(), 0xff);
    assert_eq!(
        Dot11ControlSubtype::from_raw(0),
        Dot11ControlSubtype::Unknown(0)
    );
    assert_eq!(Dot11ControlSubtype::Unknown(0xff).raw(), 0xff);
    assert_eq!(
        Dot11DataSubtype::from_raw(13),
        Dot11DataSubtype::Unknown(13)
    );
    assert_eq!(Dot11DataSubtype::Unknown(0xff).raw(), 0xff);
}

#[test]
fn dot11_frame_type_frame_control_accessors_return_typed_values() {
    let beacon = Dot11FrameControl::new()
        .with_frame_type(DOT11_FRAME_TYPE_MANAGEMENT)
        .with_subtype(DOT11_MGMT_SUBTYPE_BEACON);

    assert_eq!(beacon.frame_type_value(), Dot11FrameType::Management);
    assert_eq!(
        beacon.management_subtype_value(),
        Some(Dot11ManagementSubtype::Beacon)
    );
    assert_eq!(beacon.control_subtype_value(), None);
    assert_eq!(beacon.data_subtype_value(), None);

    let rts = Dot11FrameControl::new()
        .with_frame_type(DOT11_FRAME_TYPE_CONTROL)
        .with_subtype(DOT11_CONTROL_SUBTYPE_RTS);

    assert_eq!(rts.frame_type_value(), Dot11FrameType::Control);
    assert_eq!(rts.control_subtype_value(), Some(Dot11ControlSubtype::Rts));
    assert_eq!(rts.management_subtype_value(), None);
    assert_eq!(rts.data_subtype_value(), None);

    let qos_data = Dot11FrameControl::new()
        .with_frame_type(DOT11_FRAME_TYPE_DATA)
        .with_subtype(DOT11_DATA_SUBTYPE_QOS_DATA);

    assert_eq!(qos_data.frame_type_value(), Dot11FrameType::Data);
    assert_eq!(
        qos_data.data_subtype_value(),
        Some(Dot11DataSubtype::QosData)
    );
    assert_eq!(qos_data.management_subtype_value(), None);
    assert_eq!(qos_data.control_subtype_value(), None);

    let extension = Dot11FrameControl::new()
        .with_frame_type(DOT11_FRAME_TYPE_EXTENSION)
        .with_subtype(9);

    assert_eq!(extension.frame_type_value(), Dot11FrameType::Extension);
    assert_eq!(extension.management_subtype_value(), None);
    assert_eq!(extension.control_subtype_value(), None);
    assert_eq!(extension.data_subtype_value(), None);
}
