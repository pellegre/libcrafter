//! IEEE 802.11 MAC layer scaffolding.

/// IEEE 802.11 frame-control field length in octets.
pub const DOT11_FRAME_CONTROL_LEN: usize = 2;
/// IEEE 802.11 duration/ID field length in octets.
pub const DOT11_DURATION_ID_LEN: usize = 2;
/// IEEE 802.11 MAC address field length in octets.
pub const DOT11_ADDRESS_LEN: usize = 6;
/// IEEE 802.11 sequence-control field length in octets.
pub const DOT11_SEQUENCE_CONTROL_LEN: usize = 2;

/// Frame-control protocol-version mask.
pub const DOT11_FC_PROTOCOL_VERSION_MASK: u16 = 0x0003;
/// Frame-control protocol-version shift.
pub const DOT11_FC_PROTOCOL_VERSION_SHIFT: u8 = 0;
/// Frame-control type mask.
pub const DOT11_FC_TYPE_MASK: u16 = 0x000c;
/// Frame-control type shift.
pub const DOT11_FC_TYPE_SHIFT: u8 = 2;
/// Frame-control subtype mask.
pub const DOT11_FC_SUBTYPE_MASK: u16 = 0x00f0;
/// Frame-control subtype shift.
pub const DOT11_FC_SUBTYPE_SHIFT: u8 = 4;
/// Frame-control To DS flag.
pub const DOT11_FC_TO_DS: u16 = 0x0100;
/// Frame-control From DS flag.
pub const DOT11_FC_FROM_DS: u16 = 0x0200;
/// Frame-control More Fragments flag.
pub const DOT11_FC_MORE_FRAGMENTS: u16 = 0x0400;
/// Frame-control Retry flag.
pub const DOT11_FC_RETRY: u16 = 0x0800;
/// Frame-control Power Management flag.
pub const DOT11_FC_POWER_MANAGEMENT: u16 = 0x1000;
/// Frame-control More Data flag.
pub const DOT11_FC_MORE_DATA: u16 = 0x2000;
/// Frame-control Protected Frame flag.
pub const DOT11_FC_PROTECTED: u16 = 0x4000;
/// Frame-control Order/+HTC flag.
pub const DOT11_FC_ORDER: u16 = 0x8000;

/// IEEE 802.11 management frame type.
pub const DOT11_FRAME_TYPE_MANAGEMENT: u8 = 0;
/// IEEE 802.11 control frame type.
pub const DOT11_FRAME_TYPE_CONTROL: u8 = 1;
/// IEEE 802.11 data frame type.
pub const DOT11_FRAME_TYPE_DATA: u8 = 2;
/// IEEE 802.11 extension frame type.
pub const DOT11_FRAME_TYPE_EXTENSION: u8 = 3;

/// Management subtype: Association Request.
pub const DOT11_MGMT_SUBTYPE_ASSOCIATION_REQUEST: u8 = 0;
/// Management subtype: Association Response.
pub const DOT11_MGMT_SUBTYPE_ASSOCIATION_RESPONSE: u8 = 1;
/// Management subtype: Reassociation Request.
pub const DOT11_MGMT_SUBTYPE_REASSOCIATION_REQUEST: u8 = 2;
/// Management subtype: Reassociation Response.
pub const DOT11_MGMT_SUBTYPE_REASSOCIATION_RESPONSE: u8 = 3;
/// Management subtype: Probe Request.
pub const DOT11_MGMT_SUBTYPE_PROBE_REQUEST: u8 = 4;
/// Management subtype: Probe Response.
pub const DOT11_MGMT_SUBTYPE_PROBE_RESPONSE: u8 = 5;
/// Management subtype: Timing Advertisement.
pub const DOT11_MGMT_SUBTYPE_TIMING_ADVERTISEMENT: u8 = 6;
/// Management subtype: Beacon.
pub const DOT11_MGMT_SUBTYPE_BEACON: u8 = 8;
/// Management subtype: ATIM.
pub const DOT11_MGMT_SUBTYPE_ATIM: u8 = 9;
/// Management subtype: Disassociation.
pub const DOT11_MGMT_SUBTYPE_DISASSOCIATION: u8 = 10;
/// Management subtype: Authentication.
pub const DOT11_MGMT_SUBTYPE_AUTHENTICATION: u8 = 11;
/// Management subtype: Deauthentication.
pub const DOT11_MGMT_SUBTYPE_DEAUTHENTICATION: u8 = 12;
/// Management subtype: Action.
pub const DOT11_MGMT_SUBTYPE_ACTION: u8 = 13;
/// Management subtype: Action No Ack.
pub const DOT11_MGMT_SUBTYPE_ACTION_NO_ACK: u8 = 14;

/// Control subtype: Trigger.
pub const DOT11_CONTROL_SUBTYPE_TRIGGER: u8 = 2;
/// Control subtype: Control Wrapper.
pub const DOT11_CONTROL_SUBTYPE_CONTROL_WRAPPER: u8 = 7;
/// Control subtype: Block Ack Request.
pub const DOT11_CONTROL_SUBTYPE_BLOCK_ACK_REQUEST: u8 = 8;
/// Control subtype: Block Ack.
pub const DOT11_CONTROL_SUBTYPE_BLOCK_ACK: u8 = 9;
/// Control subtype: PS-Poll.
pub const DOT11_CONTROL_SUBTYPE_PS_POLL: u8 = 10;
/// Control subtype: RTS.
pub const DOT11_CONTROL_SUBTYPE_RTS: u8 = 11;
/// Control subtype: CTS.
pub const DOT11_CONTROL_SUBTYPE_CTS: u8 = 12;
/// Control subtype: ACK.
pub const DOT11_CONTROL_SUBTYPE_ACK: u8 = 13;
/// Control subtype: CF-End.
pub const DOT11_CONTROL_SUBTYPE_CF_END: u8 = 14;
/// Control subtype: CF-End + CF-Ack.
pub const DOT11_CONTROL_SUBTYPE_CF_END_CF_ACK: u8 = 15;

/// Data subtype: Data.
pub const DOT11_DATA_SUBTYPE_DATA: u8 = 0;
/// Data subtype: Data + CF-Ack.
pub const DOT11_DATA_SUBTYPE_DATA_CF_ACK: u8 = 1;
/// Data subtype: Data + CF-Poll.
pub const DOT11_DATA_SUBTYPE_DATA_CF_POLL: u8 = 2;
/// Data subtype: Data + CF-Ack + CF-Poll.
pub const DOT11_DATA_SUBTYPE_DATA_CF_ACK_CF_POLL: u8 = 3;
/// Data subtype: Null.
pub const DOT11_DATA_SUBTYPE_NULL: u8 = 4;
/// Data subtype: CF-Ack.
pub const DOT11_DATA_SUBTYPE_CF_ACK: u8 = 5;
/// Data subtype: CF-Poll.
pub const DOT11_DATA_SUBTYPE_CF_POLL: u8 = 6;
/// Data subtype: CF-Ack + CF-Poll.
pub const DOT11_DATA_SUBTYPE_CF_ACK_CF_POLL: u8 = 7;
/// Data subtype: QoS Data.
pub const DOT11_DATA_SUBTYPE_QOS_DATA: u8 = 8;
/// Data subtype: QoS Data + CF-Ack.
pub const DOT11_DATA_SUBTYPE_QOS_DATA_CF_ACK: u8 = 9;
/// Data subtype: QoS Data + CF-Poll.
pub const DOT11_DATA_SUBTYPE_QOS_DATA_CF_POLL: u8 = 10;
/// Data subtype: QoS Data + CF-Ack + CF-Poll.
pub const DOT11_DATA_SUBTYPE_QOS_DATA_CF_ACK_CF_POLL: u8 = 11;
/// Data subtype: QoS Null.
pub const DOT11_DATA_SUBTYPE_QOS_NULL: u8 = 12;
/// Data subtype: QoS CF-Poll.
pub const DOT11_DATA_SUBTYPE_QOS_CF_POLL: u8 = 14;
/// Data subtype: QoS CF-Ack + CF-Poll.
pub const DOT11_DATA_SUBTYPE_QOS_CF_ACK_CF_POLL: u8 = 15;

/// Sequence-control fragment-number mask.
pub const DOT11_SEQUENCE_FRAGMENT_NUMBER_MASK: u16 = 0x000f;
/// Sequence-control fragment-number shift.
pub const DOT11_SEQUENCE_FRAGMENT_NUMBER_SHIFT: u8 = 0;
/// Sequence-control sequence-number mask.
pub const DOT11_SEQUENCE_NUMBER_MASK: u16 = 0xfff0;
/// Sequence-control sequence-number shift.
pub const DOT11_SEQUENCE_NUMBER_SHIFT: u8 = 4;

/// Action category: Spectrum Management.
pub const DOT11_CATEGORY_SPECTRUM_MANAGEMENT: u8 = 0;
/// Action category: QoS.
pub const DOT11_CATEGORY_QOS: u8 = 1;
/// Action category: DLS.
pub const DOT11_CATEGORY_DLS: u8 = 2;
/// Action category: Block Ack.
pub const DOT11_CATEGORY_BLOCK_ACK: u8 = 3;
/// Action category: Public.
pub const DOT11_CATEGORY_PUBLIC: u8 = 4;
/// Action category: Radio Measurement.
pub const DOT11_CATEGORY_RADIO_MEASUREMENT: u8 = 5;
/// Action category: Fast BSS Transition.
pub const DOT11_CATEGORY_FAST_BSS_TRANSITION: u8 = 6;
/// Action category: HT.
pub const DOT11_CATEGORY_HT: u8 = 7;
/// Action category: SA Query.
pub const DOT11_CATEGORY_SA_QUERY: u8 = 8;
/// Action category: Protected Dual of Public Action.
pub const DOT11_CATEGORY_PROTECTED_DUAL_OF_PUBLIC_ACTION: u8 = 9;
/// Action category: WNM.
pub const DOT11_CATEGORY_WNM: u8 = 10;
/// Action category: Unprotected WNM.
pub const DOT11_CATEGORY_UNPROTECTED_WNM: u8 = 11;
/// Action category: TDLS.
pub const DOT11_CATEGORY_TDLS: u8 = 12;
/// Action category: Mesh.
pub const DOT11_CATEGORY_MESH: u8 = 13;
/// Action category: Multihop.
pub const DOT11_CATEGORY_MULTIHOP: u8 = 14;
/// Action category: Self-protected.
pub const DOT11_CATEGORY_SELF_PROTECTED: u8 = 15;

/// Capability Information bit: ESS.
pub const DOT11_CAPABILITY_ESS: u16 = 0x0001;
/// Capability Information bit: IBSS.
pub const DOT11_CAPABILITY_IBSS: u16 = 0x0002;
/// Capability Information bit: CF-Pollable.
pub const DOT11_CAPABILITY_CF_POLLABLE: u16 = 0x0004;
/// Capability Information bit: CF-Poll Request.
pub const DOT11_CAPABILITY_CF_POLL_REQUEST: u16 = 0x0008;
/// Capability Information bit: Privacy.
pub const DOT11_CAPABILITY_PRIVACY: u16 = 0x0010;
/// Capability Information bit: Short Preamble.
pub const DOT11_CAPABILITY_SHORT_PREAMBLE: u16 = 0x0020;
/// Capability Information bit: PBCC.
pub const DOT11_CAPABILITY_PBCC: u16 = 0x0040;
/// Capability Information bit: Channel Agility.
pub const DOT11_CAPABILITY_CHANNEL_AGILITY: u16 = 0x0080;
/// Capability Information bit: Spectrum Management.
pub const DOT11_CAPABILITY_SPECTRUM_MANAGEMENT: u16 = 0x0100;
/// Capability Information bit: QoS.
pub const DOT11_CAPABILITY_QOS: u16 = 0x0200;
/// Capability Information bit: Short Slot Time.
pub const DOT11_CAPABILITY_SHORT_SLOT_TIME: u16 = 0x0400;
/// Capability Information bit: APSD.
pub const DOT11_CAPABILITY_APSD: u16 = 0x0800;
/// Capability Information bit: Radio Measurement.
pub const DOT11_CAPABILITY_RADIO_MEASUREMENT: u16 = 0x1000;
/// Capability Information bit: DSSS-OFDM.
pub const DOT11_CAPABILITY_DSSS_OFDM: u16 = 0x2000;
/// Capability Information bit: Delayed Block Ack.
pub const DOT11_CAPABILITY_DELAYED_BLOCK_ACK: u16 = 0x4000;
/// Capability Information bit: Immediate Block Ack.
pub const DOT11_CAPABILITY_IMMEDIATE_BLOCK_ACK: u16 = 0x8000;

/// Placeholder for the IEEE 802.11 MAC layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dot11 {
    _private: (),
}

/// Return a stable label for an IEEE 802.11 frame type.
pub fn dot11_frame_type_label(frame_type: u8) -> String {
    match frame_type {
        DOT11_FRAME_TYPE_MANAGEMENT => "management".to_string(),
        DOT11_FRAME_TYPE_CONTROL => "control".to_string(),
        DOT11_FRAME_TYPE_DATA => "data".to_string(),
        DOT11_FRAME_TYPE_EXTENSION => "extension".to_string(),
        _ => format!("unknown-frame-type({frame_type})"),
    }
}

/// Return a stable label for an IEEE 802.11 subtype under the given frame type.
pub fn dot11_subtype_label(frame_type: u8, subtype: u8) -> String {
    match frame_type {
        DOT11_FRAME_TYPE_MANAGEMENT => dot11_management_subtype_label(subtype),
        DOT11_FRAME_TYPE_CONTROL => dot11_control_subtype_label(subtype),
        DOT11_FRAME_TYPE_DATA => dot11_data_subtype_label(subtype),
        DOT11_FRAME_TYPE_EXTENSION => format!("extension-subtype({subtype})"),
        _ => format!("unknown-frame-type({frame_type})-subtype({subtype})"),
    }
}

/// Return a stable label for a known management subtype, or a numeric fallback.
pub fn dot11_management_subtype_label(subtype: u8) -> String {
    match subtype {
        DOT11_MGMT_SUBTYPE_ASSOCIATION_REQUEST => "association-request".to_string(),
        DOT11_MGMT_SUBTYPE_ASSOCIATION_RESPONSE => "association-response".to_string(),
        DOT11_MGMT_SUBTYPE_REASSOCIATION_REQUEST => "reassociation-request".to_string(),
        DOT11_MGMT_SUBTYPE_REASSOCIATION_RESPONSE => "reassociation-response".to_string(),
        DOT11_MGMT_SUBTYPE_PROBE_REQUEST => "probe-request".to_string(),
        DOT11_MGMT_SUBTYPE_PROBE_RESPONSE => "probe-response".to_string(),
        DOT11_MGMT_SUBTYPE_TIMING_ADVERTISEMENT => "timing-advertisement".to_string(),
        DOT11_MGMT_SUBTYPE_BEACON => "beacon".to_string(),
        DOT11_MGMT_SUBTYPE_ATIM => "atim".to_string(),
        DOT11_MGMT_SUBTYPE_DISASSOCIATION => "disassociation".to_string(),
        DOT11_MGMT_SUBTYPE_AUTHENTICATION => "authentication".to_string(),
        DOT11_MGMT_SUBTYPE_DEAUTHENTICATION => "deauthentication".to_string(),
        DOT11_MGMT_SUBTYPE_ACTION => "action".to_string(),
        DOT11_MGMT_SUBTYPE_ACTION_NO_ACK => "action-no-ack".to_string(),
        _ => format!("unknown-management-subtype({subtype})"),
    }
}

/// Return a stable label for a known control subtype, or a numeric fallback.
pub fn dot11_control_subtype_label(subtype: u8) -> String {
    match subtype {
        DOT11_CONTROL_SUBTYPE_TRIGGER => "trigger".to_string(),
        DOT11_CONTROL_SUBTYPE_CONTROL_WRAPPER => "control-wrapper".to_string(),
        DOT11_CONTROL_SUBTYPE_BLOCK_ACK_REQUEST => "block-ack-request".to_string(),
        DOT11_CONTROL_SUBTYPE_BLOCK_ACK => "block-ack".to_string(),
        DOT11_CONTROL_SUBTYPE_PS_POLL => "ps-poll".to_string(),
        DOT11_CONTROL_SUBTYPE_RTS => "rts".to_string(),
        DOT11_CONTROL_SUBTYPE_CTS => "cts".to_string(),
        DOT11_CONTROL_SUBTYPE_ACK => "ack".to_string(),
        DOT11_CONTROL_SUBTYPE_CF_END => "cf-end".to_string(),
        DOT11_CONTROL_SUBTYPE_CF_END_CF_ACK => "cf-end-cf-ack".to_string(),
        _ => format!("unknown-control-subtype({subtype})"),
    }
}

/// Return a stable label for a known data subtype, or a numeric fallback.
pub fn dot11_data_subtype_label(subtype: u8) -> String {
    match subtype {
        DOT11_DATA_SUBTYPE_DATA => "data".to_string(),
        DOT11_DATA_SUBTYPE_DATA_CF_ACK => "data-cf-ack".to_string(),
        DOT11_DATA_SUBTYPE_DATA_CF_POLL => "data-cf-poll".to_string(),
        DOT11_DATA_SUBTYPE_DATA_CF_ACK_CF_POLL => "data-cf-ack-cf-poll".to_string(),
        DOT11_DATA_SUBTYPE_NULL => "null".to_string(),
        DOT11_DATA_SUBTYPE_CF_ACK => "cf-ack".to_string(),
        DOT11_DATA_SUBTYPE_CF_POLL => "cf-poll".to_string(),
        DOT11_DATA_SUBTYPE_CF_ACK_CF_POLL => "cf-ack-cf-poll".to_string(),
        DOT11_DATA_SUBTYPE_QOS_DATA => "qos-data".to_string(),
        DOT11_DATA_SUBTYPE_QOS_DATA_CF_ACK => "qos-data-cf-ack".to_string(),
        DOT11_DATA_SUBTYPE_QOS_DATA_CF_POLL => "qos-data-cf-poll".to_string(),
        DOT11_DATA_SUBTYPE_QOS_DATA_CF_ACK_CF_POLL => "qos-data-cf-ack-cf-poll".to_string(),
        DOT11_DATA_SUBTYPE_QOS_NULL => "qos-null".to_string(),
        DOT11_DATA_SUBTYPE_QOS_CF_POLL => "qos-cf-poll".to_string(),
        DOT11_DATA_SUBTYPE_QOS_CF_ACK_CF_POLL => "qos-cf-ack-cf-poll".to_string(),
        _ => format!("unknown-data-subtype({subtype})"),
    }
}

/// Return a stable label for a selected action-frame category.
pub fn dot11_category_label(category: u8) -> String {
    match category {
        DOT11_CATEGORY_SPECTRUM_MANAGEMENT => "spectrum-management".to_string(),
        DOT11_CATEGORY_QOS => "qos".to_string(),
        DOT11_CATEGORY_DLS => "dls".to_string(),
        DOT11_CATEGORY_BLOCK_ACK => "block-ack".to_string(),
        DOT11_CATEGORY_PUBLIC => "public".to_string(),
        DOT11_CATEGORY_RADIO_MEASUREMENT => "radio-measurement".to_string(),
        DOT11_CATEGORY_FAST_BSS_TRANSITION => "fast-bss-transition".to_string(),
        DOT11_CATEGORY_HT => "ht".to_string(),
        DOT11_CATEGORY_SA_QUERY => "sa-query".to_string(),
        DOT11_CATEGORY_PROTECTED_DUAL_OF_PUBLIC_ACTION => {
            "protected-dual-of-public-action".to_string()
        }
        DOT11_CATEGORY_WNM => "wnm".to_string(),
        DOT11_CATEGORY_UNPROTECTED_WNM => "unprotected-wnm".to_string(),
        DOT11_CATEGORY_TDLS => "tdls".to_string(),
        DOT11_CATEGORY_MESH => "mesh".to_string(),
        DOT11_CATEGORY_MULTIHOP => "multihop".to_string(),
        DOT11_CATEGORY_SELF_PROTECTED => "self-protected".to_string(),
        _ => format!("unknown-category({category})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot11_constants_frame_control_masks_match_ieee_layout() {
        assert_eq!(DOT11_FRAME_CONTROL_LEN, 2);
        assert_eq!(DOT11_DURATION_ID_LEN, 2);
        assert_eq!(DOT11_ADDRESS_LEN, 6);
        assert_eq!(DOT11_SEQUENCE_CONTROL_LEN, 2);

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
    }
}
