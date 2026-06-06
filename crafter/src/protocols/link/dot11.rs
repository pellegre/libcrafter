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

/// IEEE 802.11 frame-control field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Dot11FrameControl {
    bits: u16,
}

impl Dot11FrameControl {
    /// Create an empty frame-control word.
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Create a frame-control value from its raw host-endian bit word.
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Decode a frame-control field from exactly two little-endian wire bytes.
    pub const fn from_le_bytes(bytes: [u8; DOT11_FRAME_CONTROL_LEN]) -> Self {
        Self {
            bits: (bytes[0] as u16) | ((bytes[1] as u16) << 8),
        }
    }

    /// Decode a frame-control field from a byte slice.
    pub fn decode(bytes: impl AsRef<[u8]>) -> crate::Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() < DOT11_FRAME_CONTROL_LEN {
            return Err(crate::CrafterError::buffer_too_short(
                "dot11.frame_control",
                DOT11_FRAME_CONTROL_LEN,
                bytes.len(),
            ));
        }

        Ok(Self::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Return the raw host-endian frame-control bit word.
    pub const fn bits(&self) -> u16 {
        self.bits
    }

    /// Set the raw host-endian frame-control bit word.
    pub const fn raw(mut self, bits: u16) -> Self {
        self.bits = bits;
        self
    }

    /// Compile the frame-control field to little-endian wire bytes.
    pub const fn to_le_bytes(self) -> [u8; DOT11_FRAME_CONTROL_LEN] {
        [(self.bits & 0x00ff) as u8, (self.bits >> 8) as u8]
    }

    /// Compile the frame-control field to little-endian wire bytes.
    pub const fn compile(self) -> [u8; DOT11_FRAME_CONTROL_LEN] {
        self.to_le_bytes()
    }

    /// Protocol version subfield.
    pub const fn protocol_version(&self) -> u8 {
        ((self.bits & DOT11_FC_PROTOCOL_VERSION_MASK) >> DOT11_FC_PROTOCOL_VERSION_SHIFT) as u8
    }

    /// Frame type subfield.
    pub const fn frame_type(&self) -> u8 {
        ((self.bits & DOT11_FC_TYPE_MASK) >> DOT11_FC_TYPE_SHIFT) as u8
    }

    /// Frame subtype subfield.
    pub const fn subtype(&self) -> u8 {
        ((self.bits & DOT11_FC_SUBTYPE_MASK) >> DOT11_FC_SUBTYPE_SHIFT) as u8
    }

    /// Return true when the To DS flag is set.
    pub const fn to_ds(&self) -> bool {
        self.has_flag(DOT11_FC_TO_DS)
    }

    /// Return true when the From DS flag is set.
    pub const fn from_ds(&self) -> bool {
        self.has_flag(DOT11_FC_FROM_DS)
    }

    /// Return true when the More Fragments flag is set.
    pub const fn more_fragments(&self) -> bool {
        self.has_flag(DOT11_FC_MORE_FRAGMENTS)
    }

    /// Return true when the Retry flag is set.
    pub const fn retry(&self) -> bool {
        self.has_flag(DOT11_FC_RETRY)
    }

    /// Return true when the Power Management flag is set.
    pub const fn power_management(&self) -> bool {
        self.has_flag(DOT11_FC_POWER_MANAGEMENT)
    }

    /// Return true when the More Data flag is set.
    pub const fn more_data(&self) -> bool {
        self.has_flag(DOT11_FC_MORE_DATA)
    }

    /// Return true when the Protected Frame flag is set.
    pub const fn protected(&self) -> bool {
        self.has_flag(DOT11_FC_PROTECTED)
    }

    /// Return true when the Order/+HTC flag is set.
    pub const fn order(&self) -> bool {
        self.has_flag(DOT11_FC_ORDER)
    }

    /// Set the two-bit protocol-version subfield.
    ///
    /// Only the low two bits of `protocol_version` are representable in the
    /// frame-control word. Use [`Self::raw`] to set an exact 16-bit word.
    pub const fn protocol_version_set(mut self, protocol_version: u8) -> Self {
        self.bits = set_subfield(
            self.bits,
            DOT11_FC_PROTOCOL_VERSION_MASK,
            DOT11_FC_PROTOCOL_VERSION_SHIFT,
            protocol_version,
        );
        self
    }

    /// Builder alias for [`Self::protocol_version_set`].
    pub const fn with_protocol_version(self, protocol_version: u8) -> Self {
        self.protocol_version_set(protocol_version)
    }

    /// Set the two-bit frame type subfield.
    ///
    /// Only the low two bits of `frame_type` are representable in the
    /// frame-control word. Use [`Self::raw`] to set an exact 16-bit word.
    pub const fn frame_type_set(mut self, frame_type: u8) -> Self {
        self.bits = set_subfield(
            self.bits,
            DOT11_FC_TYPE_MASK,
            DOT11_FC_TYPE_SHIFT,
            frame_type,
        );
        self
    }

    /// Builder alias for [`Self::frame_type_set`].
    pub const fn with_frame_type(self, frame_type: u8) -> Self {
        self.frame_type_set(frame_type)
    }

    /// Set the four-bit frame subtype subfield.
    ///
    /// Only the low four bits of `subtype` are representable in the
    /// frame-control word. Use [`Self::raw`] to set an exact 16-bit word.
    pub const fn subtype_set(mut self, subtype: u8) -> Self {
        self.bits = set_subfield(
            self.bits,
            DOT11_FC_SUBTYPE_MASK,
            DOT11_FC_SUBTYPE_SHIFT,
            subtype,
        );
        self
    }

    /// Builder alias for [`Self::subtype_set`].
    pub const fn with_subtype(self, subtype: u8) -> Self {
        self.subtype_set(subtype)
    }

    /// Set or clear the To DS flag.
    pub const fn to_ds_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_TO_DS, enabled);
        self
    }

    /// Builder alias for [`Self::to_ds_set`].
    pub const fn with_to_ds(self, enabled: bool) -> Self {
        self.to_ds_set(enabled)
    }

    /// Set or clear the From DS flag.
    pub const fn from_ds_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_FROM_DS, enabled);
        self
    }

    /// Builder alias for [`Self::from_ds_set`].
    pub const fn with_from_ds(self, enabled: bool) -> Self {
        self.from_ds_set(enabled)
    }

    /// Set or clear the More Fragments flag.
    pub const fn more_fragments_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_MORE_FRAGMENTS, enabled);
        self
    }

    /// Builder alias for [`Self::more_fragments_set`].
    pub const fn with_more_fragments(self, enabled: bool) -> Self {
        self.more_fragments_set(enabled)
    }

    /// Set or clear the Retry flag.
    pub const fn retry_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_RETRY, enabled);
        self
    }

    /// Builder alias for [`Self::retry_set`].
    pub const fn with_retry(self, enabled: bool) -> Self {
        self.retry_set(enabled)
    }

    /// Set or clear the Power Management flag.
    pub const fn power_management_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_POWER_MANAGEMENT, enabled);
        self
    }

    /// Builder alias for [`Self::power_management_set`].
    pub const fn with_power_management(self, enabled: bool) -> Self {
        self.power_management_set(enabled)
    }

    /// Set or clear the More Data flag.
    pub const fn more_data_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_MORE_DATA, enabled);
        self
    }

    /// Builder alias for [`Self::more_data_set`].
    pub const fn with_more_data(self, enabled: bool) -> Self {
        self.more_data_set(enabled)
    }

    /// Set or clear the Protected Frame flag.
    pub const fn protected_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_PROTECTED, enabled);
        self
    }

    /// Builder alias for [`Self::protected_set`].
    pub const fn with_protected(self, enabled: bool) -> Self {
        self.protected_set(enabled)
    }

    /// Set or clear the Order/+HTC flag.
    pub const fn order_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_ORDER, enabled);
        self
    }

    /// Builder alias for [`Self::order_set`].
    pub const fn with_order(self, enabled: bool) -> Self {
        self.order_set(enabled)
    }

    const fn has_flag(&self, flag: u16) -> bool {
        self.bits & flag != 0
    }
}

const fn set_subfield(bits: u16, mask: u16, shift: u8, value: u8) -> u16 {
    (bits & !mask) | (((value as u16) << shift) & mask)
}

const fn set_flag(bits: u16, flag: u16, enabled: bool) -> u16 {
    if enabled {
        bits | flag
    } else {
        bits & !flag
    }
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
            0xffff
                & !DOT11_FC_PROTOCOL_VERSION_MASK
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
}
