//! IEEE 802.11 MAC header geometry and subtype classification helpers.

use super::*;

pub(super) const fn dot11_required_header_len(frame_control: Dot11FrameControl) -> usize {
    dot11_mac_header_len(frame_control) + dot11_management_fixed_parameters_len(frame_control)
}

pub(super) fn dot11_encoded_mac_header_len(dot11: &Dot11) -> usize {
    let frame_control = dot11.frame_control_value();

    if frame_control.frame_type_value() == Dot11FrameType::Control {
        return DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN
            + if dot11_control_emit_addr2(dot11) {
                DOT11_ADDRESS_LEN
            } else {
                0
            }
            + if dot11_control_emit_addr3(dot11) {
                DOT11_ADDRESS_LEN
            } else {
                0
            }
            + if dot11_control_emit_sequence_control(dot11) {
                DOT11_SEQUENCE_CONTROL_LEN
            } else {
                0
            }
            + dot11
                .addr4
                .value()
                .map(|_| DOT11_ADDRESS_LEN)
                .unwrap_or_default()
            + dot11
                .qos_control
                .value()
                .map(|_| DOT11_QOS_CONTROL_LEN)
                .unwrap_or_default()
            + dot11
                .ht_control
                .value()
                .map(|_| DOT11_HT_CONTROL_LEN)
                .unwrap_or_default();
    }

    DOT11_DATA_HEADER_LEN
        + dot11
            .addr4
            .value()
            .map(|_| DOT11_ADDRESS_LEN)
            .unwrap_or_default()
        + dot11
            .qos_control
            .value()
            .map(|_| DOT11_QOS_CONTROL_LEN)
            .unwrap_or_default()
        + dot11
            .ht_control
            .value()
            .map(|_| DOT11_HT_CONTROL_LEN)
            .unwrap_or_default()
}

pub(super) fn dot11_control_emit_addr2(dot11: &Dot11) -> bool {
    dot11_control_subtype_has_addr2(dot11.control_subtype())
        || dot11.addr2.is_user_set()
        || dot11_control_emit_addr3(dot11)
}

pub(super) fn dot11_control_emit_addr3(dot11: &Dot11) -> bool {
    dot11.addr3.is_user_set()
        || dot11_control_emit_sequence_control(dot11)
        || dot11.addr4.value().is_some()
        || dot11.qos_control.value().is_some()
        || dot11.ht_control.value().is_some()
}

pub(super) fn dot11_control_emit_sequence_control(dot11: &Dot11) -> bool {
    dot11.sequence_control.is_user_set()
        || dot11.addr4.value().is_some()
        || dot11.qos_control.value().is_some()
        || dot11.ht_control.value().is_some()
}

pub(super) const fn dot11_mac_header_len(frame_control: Dot11FrameControl) -> usize {
    match frame_control.frame_type_value() {
        Dot11FrameType::Management => {
            DOT11_DATA_HEADER_LEN + dot11_ht_control_len(frame_control, true)
        }
        Dot11FrameType::Control => match frame_control.subtype() {
            DOT11_CONTROL_SUBTYPE_CTS | DOT11_CONTROL_SUBTYPE_ACK => {
                DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN
            }
            DOT11_CONTROL_SUBTYPE_BLOCK_ACK_REQUEST
            | DOT11_CONTROL_SUBTYPE_BLOCK_ACK
            | DOT11_CONTROL_SUBTYPE_RTS
            | DOT11_CONTROL_SUBTYPE_PS_POLL
            | DOT11_CONTROL_SUBTYPE_CF_END
            | DOT11_CONTROL_SUBTYPE_CF_END_CF_ACK => DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            _ => DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN,
        },
        Dot11FrameType::Data => {
            let mut len = DOT11_DATA_HEADER_LEN;

            if frame_control.to_ds() && frame_control.from_ds() {
                len += DOT11_ADDRESS_LEN;
            }
            if dot11_data_subtype_has_qos(frame_control.subtype()) {
                len += DOT11_QOS_CONTROL_LEN;
                len += dot11_ht_control_len(frame_control, true);
            }

            len
        }
        Dot11FrameType::Extension | Dot11FrameType::Unknown(_) => DOT11_MIN_HEADER_LEN,
    }
}

pub(super) fn dot11_control_subtype_has_known_address_layout(dot11: &Dot11) -> bool {
    matches!(
        dot11.control_subtype(),
        Some(
            Dot11ControlSubtype::Ack
                | Dot11ControlSubtype::Cts
                | Dot11ControlSubtype::Rts
                | Dot11ControlSubtype::PsPoll
                | Dot11ControlSubtype::CfEnd
                | Dot11ControlSubtype::CfEndCfAck
                | Dot11ControlSubtype::BlockAckRequest
                | Dot11ControlSubtype::BlockAck
        )
    )
}

pub(super) const fn dot11_control_subtype_has_addr2(subtype: Option<Dot11ControlSubtype>) -> bool {
    matches!(
        subtype,
        Some(
            Dot11ControlSubtype::Rts
                | Dot11ControlSubtype::PsPoll
                | Dot11ControlSubtype::CfEnd
                | Dot11ControlSubtype::CfEndCfAck
                | Dot11ControlSubtype::BlockAckRequest
                | Dot11ControlSubtype::BlockAck
        )
    )
}

pub(super) const fn dot11_ht_control_len(
    frame_control: Dot11FrameControl,
    supported_shape: bool,
) -> usize {
    if frame_control.order() && supported_shape {
        DOT11_HT_CONTROL_LEN
    } else {
        0
    }
}

pub(super) const fn dot11_data_subtype_has_qos(subtype: u8) -> bool {
    subtype & 0b1000 != 0
}

pub(super) const fn dot11_data_subtype_carries_payload(subtype: u8) -> bool {
    matches!(
        subtype,
        DOT11_DATA_SUBTYPE_DATA
            | DOT11_DATA_SUBTYPE_DATA_CF_ACK
            | DOT11_DATA_SUBTYPE_DATA_CF_POLL
            | DOT11_DATA_SUBTYPE_DATA_CF_ACK_CF_POLL
            | DOT11_DATA_SUBTYPE_QOS_DATA
            | DOT11_DATA_SUBTYPE_QOS_DATA_CF_ACK
            | DOT11_DATA_SUBTYPE_QOS_DATA_CF_POLL
            | DOT11_DATA_SUBTYPE_QOS_DATA_CF_ACK_CF_POLL
    )
}

pub(super) const fn dot11_management_subtype_has_tagged_parameters(subtype: u8) -> bool {
    matches!(
        subtype,
        DOT11_MGMT_SUBTYPE_ASSOCIATION_REQUEST
            | DOT11_MGMT_SUBTYPE_ASSOCIATION_RESPONSE
            | DOT11_MGMT_SUBTYPE_REASSOCIATION_REQUEST
            | DOT11_MGMT_SUBTYPE_REASSOCIATION_RESPONSE
            | DOT11_MGMT_SUBTYPE_PROBE_REQUEST
            | DOT11_MGMT_SUBTYPE_PROBE_RESPONSE
            | DOT11_MGMT_SUBTYPE_BEACON
    )
}

pub(super) const fn dot11_management_fixed_parameters_len(
    frame_control: Dot11FrameControl,
) -> usize {
    if !matches!(frame_control.frame_type_value(), Dot11FrameType::Management) {
        return 0;
    }

    match frame_control.subtype() {
        DOT11_MGMT_SUBTYPE_ASSOCIATION_REQUEST => DOT11_MGMT_ASSOCIATION_REQUEST_FIXED_LEN,
        DOT11_MGMT_SUBTYPE_ASSOCIATION_RESPONSE => DOT11_MGMT_ASSOCIATION_RESPONSE_FIXED_LEN,
        DOT11_MGMT_SUBTYPE_REASSOCIATION_REQUEST => DOT11_MGMT_REASSOCIATION_REQUEST_FIXED_LEN,
        DOT11_MGMT_SUBTYPE_REASSOCIATION_RESPONSE => DOT11_MGMT_REASSOCIATION_RESPONSE_FIXED_LEN,
        DOT11_MGMT_SUBTYPE_PROBE_RESPONSE => DOT11_MGMT_PROBE_RESPONSE_FIXED_LEN,
        DOT11_MGMT_SUBTYPE_BEACON => DOT11_MGMT_BEACON_FIXED_LEN,
        DOT11_MGMT_SUBTYPE_DISASSOCIATION => DOT11_MGMT_DISASSOCIATION_FIXED_LEN,
        DOT11_MGMT_SUBTYPE_AUTHENTICATION => DOT11_MGMT_AUTHENTICATION_FIXED_LEN,
        DOT11_MGMT_SUBTYPE_DEAUTHENTICATION => DOT11_MGMT_DEAUTHENTICATION_FIXED_LEN,
        DOT11_MGMT_SUBTYPE_ACTION | DOT11_MGMT_SUBTYPE_ACTION_NO_ACK => DOT11_MGMT_ACTION_FIXED_LEN,
        _ => 0,
    }
}
