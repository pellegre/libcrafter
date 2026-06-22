//! Stable human-readable labels for IEEE 802.11 frame types and subtypes.

use super::*;

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
