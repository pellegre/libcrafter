//! IEEE 802.11 frame-control, fixed-field, codepoint, and tag constants.

/// IEEE 802.11 frame-control field length in octets.
pub const DOT11_FRAME_CONTROL_LEN: usize = 2;
/// IEEE 802.11 duration/ID field length in octets.
pub const DOT11_DURATION_ID_LEN: usize = 2;
/// IEEE 802.11 MAC address field length in octets.
pub const DOT11_ADDRESS_LEN: usize = 6;
/// IEEE 802.11 sequence-control field length in octets.
pub const DOT11_SEQUENCE_CONTROL_LEN: usize = 2;
/// IEEE 802.11 QoS control field length in octets.
pub const DOT11_QOS_CONTROL_LEN: usize = 2;
/// IEEE 802.11 HT Control field length in octets.
pub const DOT11_HT_CONTROL_LEN: usize = 4;
/// Smallest IEEE 802.11 MAC header represented in phase 1.5.
pub const DOT11_MIN_HEADER_LEN: usize =
    DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN + DOT11_ADDRESS_LEN;
/// IEEE 802.11 three-address data/management MAC header length in octets.
pub const DOT11_DATA_HEADER_LEN: usize = DOT11_FRAME_CONTROL_LEN
    + DOT11_DURATION_ID_LEN
    + (DOT11_ADDRESS_LEN * 3)
    + DOT11_SEQUENCE_CONTROL_LEN;
/// IEEE 802.11 data MAC header length with a fourth address in octets.
pub const DOT11_DATA_ADDR4_HEADER_LEN: usize = DOT11_DATA_HEADER_LEN + DOT11_ADDRESS_LEN;
/// IEEE 802.11 one-address control MAC header length in octets.
pub const DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN: usize = DOT11_MIN_HEADER_LEN;
/// IEEE 802.11 two-address control MAC header length in octets.
pub const DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN: usize =
    DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN + (DOT11_ADDRESS_LEN * 2);

/// Association Request fixed management fields length in octets.
pub const DOT11_MGMT_ASSOCIATION_REQUEST_FIXED_LEN: usize = 4;
/// Association Response fixed management fields length in octets.
pub const DOT11_MGMT_ASSOCIATION_RESPONSE_FIXED_LEN: usize = 6;
/// Reassociation Request fixed management fields length in octets.
pub const DOT11_MGMT_REASSOCIATION_REQUEST_FIXED_LEN: usize = 10;
/// Reassociation Response fixed management fields length in octets.
pub const DOT11_MGMT_REASSOCIATION_RESPONSE_FIXED_LEN: usize = 6;
/// Probe Response fixed management fields length in octets.
pub const DOT11_MGMT_PROBE_RESPONSE_FIXED_LEN: usize = 12;
/// Beacon fixed management fields length in octets.
pub const DOT11_MGMT_BEACON_FIXED_LEN: usize = 12;
/// Disassociation fixed management fields length in octets.
pub const DOT11_MGMT_DISASSOCIATION_FIXED_LEN: usize = 2;
/// Authentication fixed management fields length in octets.
pub const DOT11_MGMT_AUTHENTICATION_FIXED_LEN: usize = 6;
/// Deauthentication fixed management fields length in octets.
pub const DOT11_MGMT_DEAUTHENTICATION_FIXED_LEN: usize = 2;
/// Action and Action No Ack category fixed field length in octets.
pub const DOT11_MGMT_ACTION_FIXED_LEN: usize = 1;

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

/// QoS-control Traffic Identifier mask.
pub const DOT11_QOS_TID_MASK: u16 = 0x000f;
/// QoS-control Traffic Identifier shift.
pub const DOT11_QOS_TID_SHIFT: u8 = 0;
/// QoS-control End of Service Period flag.
pub const DOT11_QOS_EOSP: u16 = 0x0010;
/// QoS-control ACK policy mask.
pub const DOT11_QOS_ACK_POLICY_MASK: u16 = 0x0060;
/// QoS-control ACK policy shift.
pub const DOT11_QOS_ACK_POLICY_SHIFT: u8 = 5;
/// QoS-control A-MSDU Present flag.
pub const DOT11_QOS_A_MSDU_PRESENT: u16 = 0x0080;
/// QoS-control context-dependent TXOP/queue-size mask.
pub const DOT11_QOS_TXOP_QUEUE_SIZE_MASK: u16 = 0xff00;
/// QoS-control context-dependent TXOP/queue-size shift.
pub const DOT11_QOS_TXOP_QUEUE_SIZE_SHIFT: u8 = 8;

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

/// Management element ID: SSID.
pub const DOT11_TAG_SSID: u8 = 0;
/// Management element ID: Supported Rates.
pub const DOT11_TAG_SUPPORTED_RATES: u8 = 1;
/// Management element ID: DS Parameter Set.
pub const DOT11_TAG_DS_PARAMETER_SET: u8 = 3;
/// Management element ID: Traffic Indication Map.
pub const DOT11_TAG_TIM: u8 = 5;
/// Management element ID: RSN.
pub const DOT11_TAG_RSN: u8 = 48;
