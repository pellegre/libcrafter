//! IEEE 802.11 MAC layer scaffolding.

use core::any::Any;
use core::ops::Div;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::mac::MacAddr;
use crate::packet::Raw;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};
use crate::registry::ProtocolRegistry;

use super::append_llc_snap_packet_with_registry;

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

/// Raw IEEE 802.11 management tagged parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dot11TaggedParameter {
    id: u8,
    length: usize,
    data: Vec<u8>,
}

impl Dot11TaggedParameter {
    /// Create a tagged parameter with an element ID and raw value bytes.
    pub fn new(id: u8, data: impl Into<Vec<u8>>) -> Self {
        let data = data.into();
        let length = data.len();

        Self { id, length, data }
    }

    /// Create an SSID tagged parameter.
    pub fn ssid(ssid: impl Into<Vec<u8>>) -> Self {
        Self::new(DOT11_TAG_SSID, ssid)
    }

    /// Create a Supported Rates tagged parameter.
    pub fn supported_rates(rates: impl Into<Vec<u8>>) -> Self {
        Self::new(DOT11_TAG_SUPPORTED_RATES, rates)
    }

    /// Create a DS Parameter Set tagged parameter with the current channel.
    pub fn ds_parameter_set(current_channel: u8) -> Self {
        Self::new(DOT11_TAG_DS_PARAMETER_SET, [current_channel])
    }

    /// Create a raw TIM tagged parameter.
    pub fn tim(data: impl Into<Vec<u8>>) -> Self {
        Self::new(DOT11_TAG_TIM, data)
    }

    /// Create a raw RSN tagged parameter.
    pub fn rsn(data: impl Into<Vec<u8>>) -> Self {
        Self::new(DOT11_TAG_RSN, data)
    }

    /// Element ID.
    pub const fn id(&self) -> u8 {
        self.id
    }

    /// Declared tagged-parameter value length.
    pub const fn length(&self) -> usize {
        self.length
    }

    /// Raw value bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Raw value bytes.
    pub fn value(&self) -> &[u8] {
        &self.data
    }

    /// Override the declared value length octet.
    pub fn with_length(mut self, length: u8) -> Self {
        self.length = length as usize;
        self
    }

    /// Encoded length including ID and length octets.
    pub fn encoded_len(&self) -> usize {
        2 + self.data.len()
    }

    fn from_wire(id: u8, length: u8, data: &[u8]) -> Self {
        Self {
            id,
            length: length as usize,
            data: data.to_vec(),
        }
    }

    fn compile(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.length > u8::MAX as usize {
            return Err(CrafterError::invalid_field_value(
                "dot11.tagged_parameter.length",
                "tagged parameter length must fit in one byte",
            ));
        }

        out.push(self.id);
        out.push(self.length as u8);
        out.extend_from_slice(&self.data);
        Ok(())
    }
}

/// IEEE 802.11 MAC layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11 {
    frame_control: Field<Dot11FrameControl>,
    duration_id: Field<u16>,
    addr1: Field<MacAddr>,
    addr2: Field<MacAddr>,
    addr3: Field<MacAddr>,
    sequence_control: Field<Dot11SequenceControl>,
    addr4: Field<MacAddr>,
    qos_control: Field<u16>,
    ht_control: Field<u32>,
    fixed_parameters: Vec<u8>,
    tagged_parameters: Vec<Dot11TaggedParameter>,
}

impl Dot11 {
    /// Create a three-address data MAC header with deterministic safe defaults.
    pub fn new() -> Self {
        Self {
            frame_control: Field::defaulted(
                Dot11FrameControl::new()
                    .with_frame_type(DOT11_FRAME_TYPE_DATA)
                    .with_subtype(DOT11_DATA_SUBTYPE_DATA),
            ),
            duration_id: Field::defaulted(0),
            addr1: Field::defaulted(MacAddr::BROADCAST),
            addr2: Field::defaulted(MacAddr::ZERO),
            addr3: Field::defaulted(MacAddr::ZERO),
            sequence_control: Field::defaulted(Dot11SequenceControl::new()),
            addr4: Field::unset(),
            qos_control: Field::unset(),
            ht_control: Field::unset(),
            fixed_parameters: Vec::new(),
            tagged_parameters: Vec::new(),
        }
    }

    /// Create a management frame with the given subtype.
    pub fn management(subtype: Dot11ManagementSubtype) -> Self {
        Self::new().with_default_frame_control(DOT11_FRAME_TYPE_MANAGEMENT, subtype.raw())
    }

    /// Create a control frame with the given subtype.
    pub fn control(subtype: Dot11ControlSubtype) -> Self {
        Self::new().with_default_frame_control(DOT11_FRAME_TYPE_CONTROL, subtype.raw())
    }

    /// Create a data frame.
    pub fn data() -> Self {
        Self::data_with_subtype(Dot11DataSubtype::Data)
    }

    /// Create a QoS data frame with a zero QoS control field.
    pub fn qos_data() -> Self {
        Self::data_with_subtype(Dot11DataSubtype::QosData).with_default_qos_control(0)
    }

    /// Create a beacon management frame.
    pub fn beacon() -> Self {
        Self::management(Dot11ManagementSubtype::Beacon).with_default_fixed_parameters(12)
    }

    /// Create a probe request management frame.
    pub fn probe_request() -> Self {
        Self::management(Dot11ManagementSubtype::ProbeRequest)
    }

    /// Create a probe response management frame.
    pub fn probe_response() -> Self {
        Self::management(Dot11ManagementSubtype::ProbeResponse).with_default_fixed_parameters(12)
    }

    /// Create an association request management frame.
    pub fn association_request() -> Self {
        Self::management(Dot11ManagementSubtype::AssociationRequest)
            .with_default_fixed_parameters(4)
    }

    /// Create an association response management frame.
    pub fn association_response() -> Self {
        Self::management(Dot11ManagementSubtype::AssociationResponse)
            .with_default_fixed_parameters(6)
    }

    /// Create an authentication management frame.
    pub fn authentication() -> Self {
        Self::management(Dot11ManagementSubtype::Authentication).with_default_fixed_parameters(6)
    }

    /// Create a deauthentication management frame.
    pub fn deauthentication() -> Self {
        Self::management(Dot11ManagementSubtype::Deauthentication).with_default_fixed_parameters(2)
    }

    /// Create a disassociation management frame.
    pub fn disassociation() -> Self {
        Self::management(Dot11ManagementSubtype::Disassociation).with_default_fixed_parameters(2)
    }

    /// Create an action management frame with a zero category field.
    pub fn action() -> Self {
        Self::management(Dot11ManagementSubtype::Action).with_default_fixed_parameters(1)
    }

    /// Create an ACK control frame.
    pub fn ack() -> Self {
        Self::control(Dot11ControlSubtype::Ack)
    }

    /// Create an RTS control frame.
    pub fn rts() -> Self {
        Self::control(Dot11ControlSubtype::Rts)
    }

    /// Create a CTS control frame.
    pub fn cts() -> Self {
        Self::control(Dot11ControlSubtype::Cts)
    }

    /// Create a Block Ack control frame.
    pub fn block_ack() -> Self {
        Self::control(Dot11ControlSubtype::BlockAck)
    }

    /// Create a PS-Poll control frame.
    pub fn ps_poll() -> Self {
        Self::control(Dot11ControlSubtype::PsPoll)
    }

    /// Set the frame-control field.
    pub fn frame_control(mut self, frame_control: Dot11FrameControl) -> Self {
        self.frame_control.set_user(frame_control);
        self
    }

    /// Set the duration/ID field.
    pub fn duration_id(mut self, duration_id: u16) -> Self {
        self.duration_id.set_user(duration_id);
        self
    }

    /// Set address 1.
    pub fn addr1(mut self, addr: impl Into<MacAddr>) -> Self {
        self.addr1.set_user(addr.into());
        self
    }

    /// Set address 2.
    pub fn addr2(mut self, addr: impl Into<MacAddr>) -> Self {
        self.addr2.set_user(addr.into());
        self
    }

    /// Set address 3.
    pub fn addr3(mut self, addr: impl Into<MacAddr>) -> Self {
        self.addr3.set_user(addr.into());
        self
    }

    /// Set address 4.
    pub fn addr4(mut self, addr: impl Into<MacAddr>) -> Self {
        self.addr4.set_user(addr.into());
        self
    }

    /// Set the sequence-control field.
    pub fn sequence_control(mut self, sequence_control: Dot11SequenceControl) -> Self {
        self.sequence_control.set_user(sequence_control);
        self
    }

    /// Set the QoS control field.
    pub fn qos_control(mut self, qos_control: u16) -> Self {
        self.qos_control.set_user(qos_control);
        self
    }

    /// Set the HT Control field.
    pub fn ht_control(mut self, ht_control: u32) -> Self {
        self.ht_control.set_user(ht_control);
        self
    }

    /// Set raw fixed management-field bytes to emit after the MAC header.
    pub fn fixed_parameters(mut self, fixed_parameters: impl Into<Vec<u8>>) -> Self {
        self.fixed_parameters = fixed_parameters.into();
        self
    }

    /// Append a raw tagged parameter.
    pub fn tag(mut self, tag: Dot11TaggedParameter) -> Self {
        self.tagged_parameters.push(tag);
        self
    }

    /// Replace raw tagged parameters.
    pub fn tags(mut self, tags: impl Into<Vec<Dot11TaggedParameter>>) -> Self {
        self.tagged_parameters = tags.into();
        self
    }

    /// Append an SSID tagged parameter.
    pub fn ssid(self, ssid: impl Into<Vec<u8>>) -> Self {
        self.tag(Dot11TaggedParameter::ssid(ssid))
    }

    /// Append a Supported Rates tagged parameter.
    pub fn supported_rates(self, rates: impl Into<Vec<u8>>) -> Self {
        self.tag(Dot11TaggedParameter::supported_rates(rates))
    }

    /// Append a DS Parameter Set tagged parameter with the current channel.
    pub fn ds_parameter_set(self, current_channel: u8) -> Self {
        self.tag(Dot11TaggedParameter::ds_parameter_set(current_channel))
    }

    /// Append a raw TIM tagged parameter.
    pub fn tim(self, data: impl Into<Vec<u8>>) -> Self {
        self.tag(Dot11TaggedParameter::tim(data))
    }

    /// Append a raw RSN tagged parameter.
    pub fn rsn(self, data: impl Into<Vec<u8>>) -> Self {
        self.tag(Dot11TaggedParameter::rsn(data))
    }

    /// Current frame-control value.
    pub fn frame_control_value(&self) -> Dot11FrameControl {
        value_or_copy(&self.frame_control, Dot11::default_frame_control())
    }

    /// Current typed frame type.
    pub fn frame_type(&self) -> Dot11FrameType {
        self.frame_control_value().frame_type_value()
    }

    /// Current typed management subtype, when applicable.
    pub fn management_subtype(&self) -> Option<Dot11ManagementSubtype> {
        self.frame_control_value().management_subtype_value()
    }

    /// Current typed control subtype, when applicable.
    pub fn control_subtype(&self) -> Option<Dot11ControlSubtype> {
        self.frame_control_value().control_subtype_value()
    }

    /// Current typed data subtype, when applicable.
    pub fn data_subtype(&self) -> Option<Dot11DataSubtype> {
        self.frame_control_value().data_subtype_value()
    }

    /// Current duration/ID field value, if present.
    pub fn duration_id_value(&self) -> Option<u16> {
        self.duration_id.value().copied()
    }

    /// Current address 1 value, if present.
    pub fn addr1_value(&self) -> Option<MacAddr> {
        self.addr1.value().copied()
    }

    /// Current address 2 value, if present.
    pub fn addr2_value(&self) -> Option<MacAddr> {
        self.addr2.value().copied()
    }

    /// Current address 3 value, if present.
    pub fn addr3_value(&self) -> Option<MacAddr> {
        self.addr3.value().copied()
    }

    /// Current address 4 value, if present.
    pub fn addr4_value(&self) -> Option<MacAddr> {
        self.addr4.value().copied()
    }

    /// Receiver address for data or management frames.
    pub fn receiver(&self) -> Option<MacAddr> {
        match self.frame_type() {
            Dot11FrameType::Data | Dot11FrameType::Management => self.addr1_value(),
            _ => None,
        }
    }

    /// Transmitter address for data or management frames.
    pub fn transmitter(&self) -> Option<MacAddr> {
        match self.frame_type() {
            Dot11FrameType::Data | Dot11FrameType::Management => self.addr2_value(),
            _ => None,
        }
    }

    /// Destination address for data or management frames.
    pub fn destination(&self) -> Option<MacAddr> {
        let frame_control = self.frame_control_value();

        match frame_control.frame_type_value() {
            Dot11FrameType::Management => self.addr1_value(),
            Dot11FrameType::Data if frame_control.to_ds() && frame_control.from_ds() => {
                self.addr3_value()
            }
            Dot11FrameType::Data if frame_control.to_ds() => self.addr3_value(),
            Dot11FrameType::Data => self.addr1_value(),
            _ => None,
        }
    }

    /// Source address for data or management frames.
    pub fn source(&self) -> Option<MacAddr> {
        let frame_control = self.frame_control_value();

        match frame_control.frame_type_value() {
            Dot11FrameType::Management => self.addr2_value(),
            Dot11FrameType::Data if frame_control.to_ds() && frame_control.from_ds() => {
                self.fourth_address()
            }
            Dot11FrameType::Data if frame_control.from_ds() => self.addr3_value(),
            Dot11FrameType::Data => self.addr2_value(),
            _ => None,
        }
    }

    /// BSSID address for data or management frames when the role is defined.
    pub fn bssid(&self) -> Option<MacAddr> {
        let frame_control = self.frame_control_value();

        match frame_control.frame_type_value() {
            Dot11FrameType::Management => self.addr3_value(),
            Dot11FrameType::Data if frame_control.to_ds() && frame_control.from_ds() => None,
            Dot11FrameType::Data if frame_control.to_ds() => self.addr1_value(),
            Dot11FrameType::Data if frame_control.from_ds() => self.addr2_value(),
            Dot11FrameType::Data => self.addr3_value(),
            _ => None,
        }
    }

    /// Fourth address for four-address data frames when present.
    pub fn fourth_address(&self) -> Option<MacAddr> {
        let frame_control = self.frame_control_value();

        if frame_control.frame_type_value() == Dot11FrameType::Data
            && frame_control.to_ds()
            && frame_control.from_ds()
        {
            self.addr4_value()
        } else {
            None
        }
    }

    /// Current sequence-control field value, if present.
    pub fn sequence_control_value(&self) -> Option<Dot11SequenceControl> {
        self.sequence_control.value().copied()
    }

    /// Current QoS control field value, if present.
    pub fn qos_control_value(&self) -> Option<u16> {
        self.qos_control.value().copied()
    }

    /// Current HT Control field value, if present.
    pub fn ht_control_value(&self) -> Option<u32> {
        self.ht_control.value().copied()
    }

    /// Raw fixed management-field bytes.
    pub fn fixed_parameters_value(&self) -> &[u8] {
        &self.fixed_parameters
    }

    /// Raw tagged parameters.
    pub fn tags_value(&self) -> &[Dot11TaggedParameter] {
        &self.tagged_parameters
    }

    /// Raw tagged parameters.
    pub fn tagged_parameters(&self) -> &[Dot11TaggedParameter] {
        &self.tagged_parameters
    }

    /// Return true when the Protected Frame bit is set.
    pub fn is_protected(&self) -> bool {
        self.frame_control_value().protected()
    }

    /// Minimum header length implied by this frame's type/subtype and flags.
    ///
    /// This is the source-backed decode boundary: MAC header fields, optional
    /// address four, QoS control, HT Control when signaled by supported
    /// +HTC/Order shapes, and selected management fixed fields. It does not
    /// include tagged parameters or higher-layer payload bytes.
    pub fn minimum_header_len(&self) -> usize {
        dot11_required_header_len(self.frame_control_value())
    }

    /// Minimum header length implied by a frame-control word.
    pub fn minimum_header_len_for(frame_control: Dot11FrameControl) -> usize {
        dot11_required_header_len(frame_control)
    }

    /// Read frame control from `bytes`, compute the minimum header length, and
    /// return a structured error when the buffer is truncated before that
    /// boundary.
    pub fn header_len_from_bytes(bytes: impl AsRef<[u8]>) -> Result<usize> {
        let bytes = bytes.as_ref();
        let frame_control = Dot11FrameControl::decode(bytes)?;
        let header_len = dot11_required_header_len(frame_control);

        if bytes.len() < header_len {
            return Err(CrafterError::buffer_too_short(
                "dot11.header",
                header_len,
                bytes.len(),
            ));
        }

        Ok(header_len)
    }

    fn default_frame_control() -> Dot11FrameControl {
        Dot11FrameControl::new()
            .with_frame_type(DOT11_FRAME_TYPE_DATA)
            .with_subtype(DOT11_DATA_SUBTYPE_DATA)
    }

    fn with_default_frame_control(mut self, frame_type: u8, subtype: u8) -> Self {
        self.frame_control = Field::defaulted(
            Dot11FrameControl::new()
                .with_frame_type(frame_type)
                .with_subtype(subtype),
        );
        self
    }

    fn data_with_subtype(subtype: Dot11DataSubtype) -> Self {
        Self::new().with_default_frame_control(DOT11_FRAME_TYPE_DATA, subtype.raw())
    }

    fn with_default_fixed_parameters(mut self, len: usize) -> Self {
        self.fixed_parameters = vec![0; len];
        self
    }

    fn with_default_qos_control(mut self, qos_control: u16) -> Self {
        self.qos_control = Field::defaulted(qos_control);
        self
    }

    fn effective_duration_id(&self) -> u16 {
        value_or_copy(&self.duration_id, 0)
    }

    fn effective_addr1(&self) -> MacAddr {
        value_or_copy(&self.addr1, MacAddr::BROADCAST)
    }

    fn effective_addr2(&self) -> MacAddr {
        value_or_copy(&self.addr2, MacAddr::ZERO)
    }

    fn effective_addr3(&self) -> MacAddr {
        value_or_copy(&self.addr3, MacAddr::ZERO)
    }

    fn effective_sequence_control(&self) -> Dot11SequenceControl {
        value_or_copy(&self.sequence_control, Dot11SequenceControl::new())
    }
}

impl Default for Dot11 {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Dot11 {
    fn name(&self) -> &'static str {
        "Dot11"
    }

    fn summary(&self) -> String {
        let frame_control = self.frame_control_value();
        let mut fields = vec![
            format!(
                "type={}",
                dot11_frame_type_label(frame_control.frame_type())
            ),
            format!(
                "subtype={}",
                dot11_subtype_label(frame_control.frame_type(), frame_control.subtype())
            ),
        ];

        if let Some(source) = self.source() {
            fields.push(format!("src={source}"));
        }
        if let Some(destination) = self.destination() {
            fields.push(format!("dst={destination}"));
        }
        if let Some(bssid) = self.bssid() {
            fields.push(format!("bssid={bssid}"));
        }

        fields.push(format!("protected={}", frame_control.protected()));

        if let Some(sequence_control) = self.sequence_control_value() {
            fields.push(format!("seq={}", sequence_control.sequence_number()));
            fields.push(format!("frag={}", sequence_control.fragment_number()));
        }
        if let Some(qos_control) = self.qos_control_value() {
            fields.push(format!("qos=0x{qos_control:04x}"));
        }

        format!("Dot11({})", fields.join(", "))
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let frame_control = self.frame_control_value();
        let mut fields = Vec::new();

        fields.extend([
            (
                "frame_control",
                format!(
                    "0x{:04x} ({}/{})",
                    frame_control.bits(),
                    dot11_frame_type_label(frame_control.frame_type()),
                    dot11_subtype_label(frame_control.frame_type(), frame_control.subtype())
                ),
            ),
            ("type", dot11_frame_type_label(frame_control.frame_type())),
            (
                "subtype",
                dot11_subtype_label(frame_control.frame_type(), frame_control.subtype()),
            ),
            ("duration_id", self.effective_duration_id().to_string()),
            ("protected", frame_control.protected().to_string()),
        ]);

        if let Some(addr1) = self.addr1_value() {
            fields.push(("addr1", addr1.to_string()));
        }
        if let Some(addr2) = self.addr2_value() {
            fields.push(("addr2", addr2.to_string()));
        }
        if let Some(addr3) = self.addr3_value() {
            fields.push(("addr3", addr3.to_string()));
        }

        if let Some(addr4) = self.addr4_value() {
            fields.push(("addr4", addr4.to_string()));
        }
        if let Some(source) = self.source() {
            fields.push(("src", source.to_string()));
        }
        if let Some(destination) = self.destination() {
            fields.push(("dst", destination.to_string()));
        }
        if let Some(bssid) = self.bssid() {
            fields.push(("bssid", bssid.to_string()));
        }
        if let Some(sequence_control) = self.sequence_control_value() {
            fields.push((
                "sequence_control",
                format!("0x{:04x}", sequence_control.bits()),
            ));
            fields.push((
                "sequence_number",
                sequence_control.sequence_number().to_string(),
            ));
            fields.push((
                "fragment_number",
                sequence_control.fragment_number().to_string(),
            ));
        }
        if let Some(qos_control) = self.qos_control_value() {
            fields.push(("qos", "present".to_string()));
            fields.push(("qos_control", format!("0x{qos_control:04x}")));
        }
        if let Some(ht_control) = self.ht_control_value() {
            fields.push(("ht_control", format!("0x{ht_control:08x}")));
        }
        if !self.fixed_parameters.is_empty() {
            fields.push(("fixed_parameters", dot11_hex_bytes(&self.fixed_parameters)));
        }
        if !self.tagged_parameters.is_empty() {
            fields.push((
                "tagged_parameters",
                self.tagged_parameters.len().to_string(),
            ));
        }

        fields
    }

    fn encoded_len(&self) -> usize {
        DOT11_DATA_HEADER_LEN
            + self
                .addr4
                .value()
                .map(|_| DOT11_ADDRESS_LEN)
                .unwrap_or_default()
            + self
                .qos_control
                .value()
                .map(|_| DOT11_QOS_CONTROL_LEN)
                .unwrap_or_default()
            + self
                .ht_control
                .value()
                .map(|_| DOT11_HT_CONTROL_LEN)
                .unwrap_or_default()
            + self.fixed_parameters.len()
            + self
                .tagged_parameters
                .iter()
                .map(Dot11TaggedParameter::encoded_len)
                .sum::<usize>()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.frame_control_value().compile());
        out.extend_from_slice(&self.effective_duration_id().to_le_bytes());
        out.extend_from_slice(&self.effective_addr1().octets());
        out.extend_from_slice(&self.effective_addr2().octets());
        out.extend_from_slice(&self.effective_addr3().octets());
        out.extend_from_slice(&self.effective_sequence_control().compile());

        if let Some(addr4) = self.addr4_value() {
            out.extend_from_slice(&addr4.octets());
        }
        if let Some(qos_control) = self.qos_control_value() {
            out.extend_from_slice(&qos_control.to_le_bytes());
        }
        if let Some(ht_control) = self.ht_control_value() {
            out.extend_from_slice(&ht_control.to_le_bytes());
        }

        out.extend_from_slice(&self.fixed_parameters);
        for tag in &self.tagged_parameters {
            tag.compile(out)?;
        }

        Ok(())
    }

    fn clone_layer(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl<R> Div<R> for Dot11
where
    R: IntoPacket,
{
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

/// Decode a bare IEEE 802.11 MAC frame and preserve the undecoded body as Raw.
pub(crate) fn decode_dot11_with_registry(
    registry: &ProtocolRegistry,
    bytes: &[u8],
) -> Result<Packet> {
    let (dot11, tail) = decode_dot11(bytes)?;
    let decode_llc_snap = dot11_should_dispatch_llc_snap(&dot11);
    let packet = Packet::new().push(dot11);

    if tail.is_empty() {
        return Ok(packet);
    }

    if decode_llc_snap {
        append_llc_snap_packet_with_registry(registry, packet, tail)
    } else {
        Ok(packet.push(Raw::from_bytes(tail)))
    }
}

fn dot11_should_dispatch_llc_snap(dot11: &Dot11) -> bool {
    let frame_control = dot11.frame_control_value();

    frame_control.frame_type_value() == Dot11FrameType::Data
        && dot11_data_subtype_carries_payload(frame_control.subtype())
        && !frame_control.protected()
}

fn decode_dot11(bytes: &[u8]) -> Result<(Dot11, &[u8])> {
    let frame_control = Dot11FrameControl::decode(bytes)?;
    let header_len = dot11_required_header_len(frame_control);

    if bytes.len() < header_len {
        return Err(CrafterError::buffer_too_short(
            "dot11.header",
            header_len,
            bytes.len(),
        ));
    }

    let mut dot11 = Dot11 {
        frame_control: Field::user(frame_control),
        duration_id: Field::user(read_u16_le_at(bytes, DOT11_FRAME_CONTROL_LEN)),
        addr1: Field::user(read_mac_at(
            bytes,
            DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN,
        )),
        addr2: Field::unset(),
        addr3: Field::unset(),
        sequence_control: Field::unset(),
        addr4: Field::unset(),
        qos_control: Field::unset(),
        ht_control: Field::unset(),
        fixed_parameters: Vec::new(),
        tagged_parameters: Vec::new(),
    };

    match frame_control.frame_type_value() {
        Dot11FrameType::Management => {
            let mut offset = decode_dot11_three_address_header(bytes, &mut dot11);

            if frame_control.order() {
                dot11.ht_control = Field::user(read_u32_le_at(bytes, offset));
                offset += DOT11_HT_CONTROL_LEN;
            }

            let fixed_len = dot11_management_fixed_parameters_len(frame_control);
            dot11.fixed_parameters = bytes[offset..offset + fixed_len].to_vec();
            offset += fixed_len;

            if dot11_management_subtype_has_tagged_parameters(frame_control.subtype()) {
                dot11.tagged_parameters = decode_dot11_tagged_parameters(&bytes[offset..])?;
                Ok((dot11, &bytes[bytes.len()..]))
            } else {
                Ok((dot11, &bytes[offset..]))
            }
        }
        Dot11FrameType::Control => {
            if dot11_mac_header_len(frame_control) >= DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN {
                dot11.addr2 = Field::user(read_mac_at(
                    bytes,
                    DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN + DOT11_ADDRESS_LEN,
                ));
            }

            Ok((dot11, &bytes[header_len..]))
        }
        Dot11FrameType::Data => {
            let mut offset = decode_dot11_three_address_header(bytes, &mut dot11);

            if frame_control.to_ds() && frame_control.from_ds() {
                dot11.addr4 = Field::user(read_mac_at(bytes, offset));
                offset += DOT11_ADDRESS_LEN;
            }
            if dot11_data_subtype_has_qos(frame_control.subtype()) {
                dot11.qos_control = Field::user(read_u16_le_at(bytes, offset));
                offset += DOT11_QOS_CONTROL_LEN;

                if frame_control.order() {
                    dot11.ht_control = Field::user(read_u32_le_at(bytes, offset));
                    offset += DOT11_HT_CONTROL_LEN;
                }
            }

            Ok((dot11, &bytes[offset..]))
        }
        Dot11FrameType::Extension | Dot11FrameType::Unknown(_) => Ok((dot11, &bytes[header_len..])),
    }
}

fn decode_dot11_three_address_header(bytes: &[u8], dot11: &mut Dot11) -> usize {
    dot11.addr2 = Field::user(read_mac_at(
        bytes,
        DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN + DOT11_ADDRESS_LEN,
    ));
    dot11.addr3 = Field::user(read_mac_at(
        bytes,
        DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN + (DOT11_ADDRESS_LEN * 2),
    ));
    dot11.sequence_control = Field::user(Dot11SequenceControl::from_le_bytes([
        bytes[DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN + (DOT11_ADDRESS_LEN * 3)],
        bytes[DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN + (DOT11_ADDRESS_LEN * 3) + 1],
    ]));

    DOT11_DATA_HEADER_LEN
}

fn read_u16_le_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_le_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_mac_at(bytes: &[u8], offset: usize) -> MacAddr {
    MacAddr::new([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
    ])
}

fn decode_dot11_tagged_parameters(bytes: &[u8]) -> Result<Vec<Dot11TaggedParameter>> {
    let mut tags = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        if bytes.len() - offset < 2 {
            return Err(CrafterError::buffer_too_short(
                "dot11.tagged_parameter",
                offset + 2,
                bytes.len(),
            ));
        }

        let id = bytes[offset];
        let length = bytes[offset + 1];
        let value_start = offset + 2;
        let value_end = value_start + length as usize;

        if value_end > bytes.len() {
            return Err(CrafterError::buffer_too_short(
                "dot11.tagged_parameter",
                value_end,
                bytes.len(),
            ));
        }

        tags.push(Dot11TaggedParameter::from_wire(
            id,
            length,
            &bytes[value_start..value_end],
        ));
        offset = value_end;
    }

    Ok(tags)
}

/// IEEE 802.11 frame type subfield.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Dot11FrameType {
    /// Management frame.
    Management,
    /// Control frame.
    Control,
    /// Data frame.
    Data,
    /// Extension frame.
    Extension,
    /// Unknown caller-supplied value preserved verbatim.
    Unknown(u8),
}

impl Dot11FrameType {
    /// Create a frame type from its raw numeric value.
    pub const fn from_raw(value: u8) -> Self {
        match value {
            DOT11_FRAME_TYPE_MANAGEMENT => Self::Management,
            DOT11_FRAME_TYPE_CONTROL => Self::Control,
            DOT11_FRAME_TYPE_DATA => Self::Data,
            DOT11_FRAME_TYPE_EXTENSION => Self::Extension,
            value => Self::Unknown(value),
        }
    }

    /// Raw numeric value.
    pub const fn raw(self) -> u8 {
        match self {
            Self::Management => DOT11_FRAME_TYPE_MANAGEMENT,
            Self::Control => DOT11_FRAME_TYPE_CONTROL,
            Self::Data => DOT11_FRAME_TYPE_DATA,
            Self::Extension => DOT11_FRAME_TYPE_EXTENSION,
            Self::Unknown(value) => value,
        }
    }

    /// Short stable label.
    pub fn label(self) -> String {
        dot11_frame_type_label(self.raw())
    }
}

impl From<u8> for Dot11FrameType {
    fn from(value: u8) -> Self {
        Self::from_raw(value)
    }
}

impl From<Dot11FrameType> for u8 {
    fn from(value: Dot11FrameType) -> Self {
        value.raw()
    }
}

/// IEEE 802.11 management frame subtype subfield.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Dot11ManagementSubtype {
    /// Association Request.
    AssociationRequest,
    /// Association Response.
    AssociationResponse,
    /// Reassociation Request.
    ReassociationRequest,
    /// Reassociation Response.
    ReassociationResponse,
    /// Probe Request.
    ProbeRequest,
    /// Probe Response.
    ProbeResponse,
    /// Timing Advertisement.
    TimingAdvertisement,
    /// Beacon.
    Beacon,
    /// Announcement traffic indication message.
    Atim,
    /// Disassociation.
    Disassociation,
    /// Authentication.
    Authentication,
    /// Deauthentication.
    Deauthentication,
    /// Action.
    Action,
    /// Action No Ack.
    ActionNoAck,
    /// Unknown or reserved value preserved verbatim.
    Unknown(u8),
}

impl Dot11ManagementSubtype {
    /// Create a management subtype from its raw numeric value.
    pub const fn from_raw(value: u8) -> Self {
        match value {
            DOT11_MGMT_SUBTYPE_ASSOCIATION_REQUEST => Self::AssociationRequest,
            DOT11_MGMT_SUBTYPE_ASSOCIATION_RESPONSE => Self::AssociationResponse,
            DOT11_MGMT_SUBTYPE_REASSOCIATION_REQUEST => Self::ReassociationRequest,
            DOT11_MGMT_SUBTYPE_REASSOCIATION_RESPONSE => Self::ReassociationResponse,
            DOT11_MGMT_SUBTYPE_PROBE_REQUEST => Self::ProbeRequest,
            DOT11_MGMT_SUBTYPE_PROBE_RESPONSE => Self::ProbeResponse,
            DOT11_MGMT_SUBTYPE_TIMING_ADVERTISEMENT => Self::TimingAdvertisement,
            DOT11_MGMT_SUBTYPE_BEACON => Self::Beacon,
            DOT11_MGMT_SUBTYPE_ATIM => Self::Atim,
            DOT11_MGMT_SUBTYPE_DISASSOCIATION => Self::Disassociation,
            DOT11_MGMT_SUBTYPE_AUTHENTICATION => Self::Authentication,
            DOT11_MGMT_SUBTYPE_DEAUTHENTICATION => Self::Deauthentication,
            DOT11_MGMT_SUBTYPE_ACTION => Self::Action,
            DOT11_MGMT_SUBTYPE_ACTION_NO_ACK => Self::ActionNoAck,
            value => Self::Unknown(value),
        }
    }

    /// Raw numeric value.
    pub const fn raw(self) -> u8 {
        match self {
            Self::AssociationRequest => DOT11_MGMT_SUBTYPE_ASSOCIATION_REQUEST,
            Self::AssociationResponse => DOT11_MGMT_SUBTYPE_ASSOCIATION_RESPONSE,
            Self::ReassociationRequest => DOT11_MGMT_SUBTYPE_REASSOCIATION_REQUEST,
            Self::ReassociationResponse => DOT11_MGMT_SUBTYPE_REASSOCIATION_RESPONSE,
            Self::ProbeRequest => DOT11_MGMT_SUBTYPE_PROBE_REQUEST,
            Self::ProbeResponse => DOT11_MGMT_SUBTYPE_PROBE_RESPONSE,
            Self::TimingAdvertisement => DOT11_MGMT_SUBTYPE_TIMING_ADVERTISEMENT,
            Self::Beacon => DOT11_MGMT_SUBTYPE_BEACON,
            Self::Atim => DOT11_MGMT_SUBTYPE_ATIM,
            Self::Disassociation => DOT11_MGMT_SUBTYPE_DISASSOCIATION,
            Self::Authentication => DOT11_MGMT_SUBTYPE_AUTHENTICATION,
            Self::Deauthentication => DOT11_MGMT_SUBTYPE_DEAUTHENTICATION,
            Self::Action => DOT11_MGMT_SUBTYPE_ACTION,
            Self::ActionNoAck => DOT11_MGMT_SUBTYPE_ACTION_NO_ACK,
            Self::Unknown(value) => value,
        }
    }

    /// Short stable label.
    pub fn label(self) -> String {
        dot11_management_subtype_label(self.raw())
    }
}

impl From<u8> for Dot11ManagementSubtype {
    fn from(value: u8) -> Self {
        Self::from_raw(value)
    }
}

impl From<Dot11ManagementSubtype> for u8 {
    fn from(value: Dot11ManagementSubtype) -> Self {
        value.raw()
    }
}

/// IEEE 802.11 control frame subtype subfield.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Dot11ControlSubtype {
    /// Trigger.
    Trigger,
    /// Control Wrapper.
    ControlWrapper,
    /// Block Ack Request.
    BlockAckRequest,
    /// Block Ack.
    BlockAck,
    /// Power Save Poll.
    PsPoll,
    /// Request To Send.
    Rts,
    /// Clear To Send.
    Cts,
    /// Acknowledgment.
    Ack,
    /// Contention-Free End.
    CfEnd,
    /// Contention-Free End plus Contention-Free Ack.
    CfEndCfAck,
    /// Unknown or reserved value preserved verbatim.
    Unknown(u8),
}

impl Dot11ControlSubtype {
    /// Create a control subtype from its raw numeric value.
    pub const fn from_raw(value: u8) -> Self {
        match value {
            DOT11_CONTROL_SUBTYPE_TRIGGER => Self::Trigger,
            DOT11_CONTROL_SUBTYPE_CONTROL_WRAPPER => Self::ControlWrapper,
            DOT11_CONTROL_SUBTYPE_BLOCK_ACK_REQUEST => Self::BlockAckRequest,
            DOT11_CONTROL_SUBTYPE_BLOCK_ACK => Self::BlockAck,
            DOT11_CONTROL_SUBTYPE_PS_POLL => Self::PsPoll,
            DOT11_CONTROL_SUBTYPE_RTS => Self::Rts,
            DOT11_CONTROL_SUBTYPE_CTS => Self::Cts,
            DOT11_CONTROL_SUBTYPE_ACK => Self::Ack,
            DOT11_CONTROL_SUBTYPE_CF_END => Self::CfEnd,
            DOT11_CONTROL_SUBTYPE_CF_END_CF_ACK => Self::CfEndCfAck,
            value => Self::Unknown(value),
        }
    }

    /// Raw numeric value.
    pub const fn raw(self) -> u8 {
        match self {
            Self::Trigger => DOT11_CONTROL_SUBTYPE_TRIGGER,
            Self::ControlWrapper => DOT11_CONTROL_SUBTYPE_CONTROL_WRAPPER,
            Self::BlockAckRequest => DOT11_CONTROL_SUBTYPE_BLOCK_ACK_REQUEST,
            Self::BlockAck => DOT11_CONTROL_SUBTYPE_BLOCK_ACK,
            Self::PsPoll => DOT11_CONTROL_SUBTYPE_PS_POLL,
            Self::Rts => DOT11_CONTROL_SUBTYPE_RTS,
            Self::Cts => DOT11_CONTROL_SUBTYPE_CTS,
            Self::Ack => DOT11_CONTROL_SUBTYPE_ACK,
            Self::CfEnd => DOT11_CONTROL_SUBTYPE_CF_END,
            Self::CfEndCfAck => DOT11_CONTROL_SUBTYPE_CF_END_CF_ACK,
            Self::Unknown(value) => value,
        }
    }

    /// Short stable label.
    pub fn label(self) -> String {
        dot11_control_subtype_label(self.raw())
    }
}

impl From<u8> for Dot11ControlSubtype {
    fn from(value: u8) -> Self {
        Self::from_raw(value)
    }
}

impl From<Dot11ControlSubtype> for u8 {
    fn from(value: Dot11ControlSubtype) -> Self {
        value.raw()
    }
}

/// IEEE 802.11 data frame subtype subfield.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Dot11DataSubtype {
    /// Data.
    Data,
    /// Data plus CF-Ack.
    DataCfAck,
    /// Data plus CF-Poll.
    DataCfPoll,
    /// Data plus CF-Ack and CF-Poll.
    DataCfAckCfPoll,
    /// Null function, no data.
    Null,
    /// CF-Ack, no data.
    CfAck,
    /// CF-Poll, no data.
    CfPoll,
    /// CF-Ack plus CF-Poll, no data.
    CfAckCfPoll,
    /// QoS Data.
    QosData,
    /// QoS Data plus CF-Ack.
    QosDataCfAck,
    /// QoS Data plus CF-Poll.
    QosDataCfPoll,
    /// QoS Data plus CF-Ack and CF-Poll.
    QosDataCfAckCfPoll,
    /// QoS Null, no data.
    QosNull,
    /// QoS CF-Poll, no data.
    QosCfPoll,
    /// QoS CF-Ack plus CF-Poll, no data.
    QosCfAckCfPoll,
    /// Unknown or reserved value preserved verbatim.
    Unknown(u8),
}

impl Dot11DataSubtype {
    /// Create a data subtype from its raw numeric value.
    pub const fn from_raw(value: u8) -> Self {
        match value {
            DOT11_DATA_SUBTYPE_DATA => Self::Data,
            DOT11_DATA_SUBTYPE_DATA_CF_ACK => Self::DataCfAck,
            DOT11_DATA_SUBTYPE_DATA_CF_POLL => Self::DataCfPoll,
            DOT11_DATA_SUBTYPE_DATA_CF_ACK_CF_POLL => Self::DataCfAckCfPoll,
            DOT11_DATA_SUBTYPE_NULL => Self::Null,
            DOT11_DATA_SUBTYPE_CF_ACK => Self::CfAck,
            DOT11_DATA_SUBTYPE_CF_POLL => Self::CfPoll,
            DOT11_DATA_SUBTYPE_CF_ACK_CF_POLL => Self::CfAckCfPoll,
            DOT11_DATA_SUBTYPE_QOS_DATA => Self::QosData,
            DOT11_DATA_SUBTYPE_QOS_DATA_CF_ACK => Self::QosDataCfAck,
            DOT11_DATA_SUBTYPE_QOS_DATA_CF_POLL => Self::QosDataCfPoll,
            DOT11_DATA_SUBTYPE_QOS_DATA_CF_ACK_CF_POLL => Self::QosDataCfAckCfPoll,
            DOT11_DATA_SUBTYPE_QOS_NULL => Self::QosNull,
            DOT11_DATA_SUBTYPE_QOS_CF_POLL => Self::QosCfPoll,
            DOT11_DATA_SUBTYPE_QOS_CF_ACK_CF_POLL => Self::QosCfAckCfPoll,
            value => Self::Unknown(value),
        }
    }

    /// Raw numeric value.
    pub const fn raw(self) -> u8 {
        match self {
            Self::Data => DOT11_DATA_SUBTYPE_DATA,
            Self::DataCfAck => DOT11_DATA_SUBTYPE_DATA_CF_ACK,
            Self::DataCfPoll => DOT11_DATA_SUBTYPE_DATA_CF_POLL,
            Self::DataCfAckCfPoll => DOT11_DATA_SUBTYPE_DATA_CF_ACK_CF_POLL,
            Self::Null => DOT11_DATA_SUBTYPE_NULL,
            Self::CfAck => DOT11_DATA_SUBTYPE_CF_ACK,
            Self::CfPoll => DOT11_DATA_SUBTYPE_CF_POLL,
            Self::CfAckCfPoll => DOT11_DATA_SUBTYPE_CF_ACK_CF_POLL,
            Self::QosData => DOT11_DATA_SUBTYPE_QOS_DATA,
            Self::QosDataCfAck => DOT11_DATA_SUBTYPE_QOS_DATA_CF_ACK,
            Self::QosDataCfPoll => DOT11_DATA_SUBTYPE_QOS_DATA_CF_POLL,
            Self::QosDataCfAckCfPoll => DOT11_DATA_SUBTYPE_QOS_DATA_CF_ACK_CF_POLL,
            Self::QosNull => DOT11_DATA_SUBTYPE_QOS_NULL,
            Self::QosCfPoll => DOT11_DATA_SUBTYPE_QOS_CF_POLL,
            Self::QosCfAckCfPoll => DOT11_DATA_SUBTYPE_QOS_CF_ACK_CF_POLL,
            Self::Unknown(value) => value,
        }
    }

    /// Short stable label.
    pub fn label(self) -> String {
        dot11_data_subtype_label(self.raw())
    }
}

impl From<u8> for Dot11DataSubtype {
    fn from(value: u8) -> Self {
        Self::from_raw(value)
    }
}

impl From<Dot11DataSubtype> for u8 {
    fn from(value: Dot11DataSubtype) -> Self {
        value.raw()
    }
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

    /// Typed frame type subfield.
    pub const fn frame_type_value(&self) -> Dot11FrameType {
        Dot11FrameType::from_raw(self.frame_type())
    }

    /// Frame subtype subfield.
    pub const fn subtype(&self) -> u8 {
        ((self.bits & DOT11_FC_SUBTYPE_MASK) >> DOT11_FC_SUBTYPE_SHIFT) as u8
    }

    /// Typed management subtype when this is a management frame.
    pub const fn management_subtype_value(&self) -> Option<Dot11ManagementSubtype> {
        match self.frame_type_value() {
            Dot11FrameType::Management => Some(Dot11ManagementSubtype::from_raw(self.subtype())),
            _ => None,
        }
    }

    /// Typed control subtype when this is a control frame.
    pub const fn control_subtype_value(&self) -> Option<Dot11ControlSubtype> {
        match self.frame_type_value() {
            Dot11FrameType::Control => Some(Dot11ControlSubtype::from_raw(self.subtype())),
            _ => None,
        }
    }

    /// Typed data subtype when this is a data frame.
    pub const fn data_subtype_value(&self) -> Option<Dot11DataSubtype> {
        match self.frame_type_value() {
            Dot11FrameType::Data => Some(Dot11DataSubtype::from_raw(self.subtype())),
            _ => None,
        }
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

/// IEEE 802.11 sequence-control field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Dot11SequenceControl {
    bits: u16,
}

impl Dot11SequenceControl {
    /// Create an empty sequence-control word.
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Create a sequence-control value from its raw host-endian bit word.
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Decode a sequence-control field from exactly two little-endian wire bytes.
    pub const fn from_le_bytes(bytes: [u8; DOT11_SEQUENCE_CONTROL_LEN]) -> Self {
        Self {
            bits: (bytes[0] as u16) | ((bytes[1] as u16) << 8),
        }
    }

    /// Decode a sequence-control field from a byte slice.
    pub fn decode(bytes: impl AsRef<[u8]>) -> crate::Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() < DOT11_SEQUENCE_CONTROL_LEN {
            return Err(crate::CrafterError::buffer_too_short(
                "dot11.sequence_control",
                DOT11_SEQUENCE_CONTROL_LEN,
                bytes.len(),
            ));
        }

        Ok(Self::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Return the raw host-endian sequence-control bit word.
    pub const fn bits(&self) -> u16 {
        self.bits
    }

    /// Set the raw host-endian sequence-control bit word.
    pub const fn raw(mut self, bits: u16) -> Self {
        self.bits = bits;
        self
    }

    /// Compile the sequence-control field to little-endian wire bytes.
    pub const fn to_le_bytes(self) -> [u8; DOT11_SEQUENCE_CONTROL_LEN] {
        [(self.bits & 0x00ff) as u8, (self.bits >> 8) as u8]
    }

    /// Compile the sequence-control field to little-endian wire bytes.
    pub const fn compile(self) -> [u8; DOT11_SEQUENCE_CONTROL_LEN] {
        self.to_le_bytes()
    }

    /// Fragment number subfield.
    pub const fn fragment_number(&self) -> u8 {
        ((self.bits & DOT11_SEQUENCE_FRAGMENT_NUMBER_MASK) >> DOT11_SEQUENCE_FRAGMENT_NUMBER_SHIFT)
            as u8
    }

    /// Sequence number subfield.
    pub const fn sequence_number(&self) -> u16 {
        (self.bits & DOT11_SEQUENCE_NUMBER_MASK) >> DOT11_SEQUENCE_NUMBER_SHIFT
    }

    /// Set the four-bit fragment-number subfield.
    ///
    /// Only the low four bits of `fragment_number` are representable in the
    /// sequence-control word. Use [`Self::raw`] to set an exact 16-bit word.
    pub const fn fragment_number_set(mut self, fragment_number: u8) -> Self {
        self.bits = set_subfield(
            self.bits,
            DOT11_SEQUENCE_FRAGMENT_NUMBER_MASK,
            DOT11_SEQUENCE_FRAGMENT_NUMBER_SHIFT,
            fragment_number,
        );
        self
    }

    /// Builder alias for [`Self::fragment_number_set`].
    pub const fn with_fragment_number(self, fragment_number: u8) -> Self {
        self.fragment_number_set(fragment_number)
    }

    /// Set the twelve-bit sequence-number subfield.
    ///
    /// Only the low twelve bits of `sequence_number` are representable in the
    /// sequence-control word. Use [`Self::raw`] to set an exact 16-bit word.
    pub const fn sequence_number_set(mut self, sequence_number: u16) -> Self {
        self.bits = (self.bits & !DOT11_SEQUENCE_NUMBER_MASK)
            | ((sequence_number << DOT11_SEQUENCE_NUMBER_SHIFT) & DOT11_SEQUENCE_NUMBER_MASK);
        self
    }

    /// Builder alias for [`Self::sequence_number_set`].
    pub const fn with_sequence_number(self, sequence_number: u16) -> Self {
        self.sequence_number_set(sequence_number)
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

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn dot11_hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();

    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02x}"));
    }

    output
}

const fn dot11_required_header_len(frame_control: Dot11FrameControl) -> usize {
    dot11_mac_header_len(frame_control) + dot11_management_fixed_parameters_len(frame_control)
}

const fn dot11_mac_header_len(frame_control: Dot11FrameControl) -> usize {
    match frame_control.frame_type_value() {
        Dot11FrameType::Management => {
            DOT11_DATA_HEADER_LEN + dot11_ht_control_len(frame_control, true)
        }
        Dot11FrameType::Control => match frame_control.subtype() {
            DOT11_CONTROL_SUBTYPE_CTS | DOT11_CONTROL_SUBTYPE_ACK => {
                DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN
            }
            DOT11_CONTROL_SUBTYPE_RTS
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

const fn dot11_ht_control_len(frame_control: Dot11FrameControl, supported_shape: bool) -> usize {
    if frame_control.order() && supported_shape {
        DOT11_HT_CONTROL_LEN
    } else {
        0
    }
}

const fn dot11_data_subtype_has_qos(subtype: u8) -> bool {
    subtype & 0b1000 != 0
}

const fn dot11_data_subtype_carries_payload(subtype: u8) -> bool {
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

const fn dot11_management_subtype_has_tagged_parameters(subtype: u8) -> bool {
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

const fn dot11_management_fixed_parameters_len(frame_control: Dot11FrameControl) -> usize {
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
    use crate::registry::ProtocolRegistry;
    use crate::{Ipv4, LinkType, LlcSnap, Packet, Raw};

    fn dot11_role_mac(index: u8) -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, index])
    }

    fn dot11_test_frame_control(frame_type: u8, subtype: u8) -> Dot11FrameControl {
        Dot11FrameControl::new()
            .with_frame_type(frame_type)
            .with_subtype(subtype)
    }

    fn dot11_test_bytes(frame_control: Dot11FrameControl, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        let frame_control = frame_control.compile();
        if len > 0 {
            bytes[0] = frame_control[0];
        }
        if len > 1 {
            bytes[1] = frame_control[1];
        }
        bytes
    }

    fn dot11_decode_test_header(frame_control: Dot11FrameControl) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&frame_control.compile());
        bytes.extend_from_slice(&0x1234u16.to_le_bytes());
        bytes.extend_from_slice(&dot11_role_mac(1).octets());
        bytes.extend_from_slice(&dot11_role_mac(2).octets());
        bytes.extend_from_slice(&dot11_role_mac(3).octets());
        bytes.extend_from_slice(&0x5678u16.to_le_bytes());
        bytes
    }

    fn decode_dot11_basic(bytes: &[u8]) -> Packet {
        decode_dot11_with_registry(&ProtocolRegistry::new(), bytes).unwrap()
    }

    fn dot11_inspection_value(fields: &[(&'static str, String)], name: &str) -> Option<String> {
        fields
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, value)| value.clone())
    }

    #[test]
    fn dot11_decode_basic_three_address_data_preserves_raw_tail() {
        let frame_control =
            dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_DATA);
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
    fn dot11_summary_show_includes_data_roles_sequence_fragment_and_qos() {
        let destination = dot11_role_mac(1);
        let bssid = dot11_role_mac(2);
        let source = dot11_role_mac(3);
        let frame_control =
            dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_QOS_DATA)
                .with_from_ds(true)
                .with_protected(true);
        let sequence_control = Dot11SequenceControl::new()
            .with_sequence_number(0x123)
            .with_fragment_number(5);
        let dot11 = Dot11::qos_data()
            .frame_control(frame_control)
            .addr1(destination)
            .addr2(bssid)
            .addr3(source)
            .sequence_control(sequence_control)
            .qos_control(0xabcd);

        let summary = dot11.summary();

        for expected in [
            "type=data",
            "subtype=qos-data",
            "protected=true",
            "seq=291",
            "frag=5",
            "qos=0xabcd",
        ] {
            assert!(summary.contains(expected), "{summary}");
        }
        assert!(summary.contains(&format!("src={source}")), "{summary}");
        assert!(summary.contains(&format!("dst={destination}")), "{summary}");
        assert!(summary.contains(&format!("bssid={bssid}")), "{summary}");

        let fields = dot11.inspection_fields();
        assert_eq!(dot11_inspection_value(&fields, "type"), Some("data".into()));
        assert_eq!(
            dot11_inspection_value(&fields, "subtype"),
            Some("qos-data".into())
        );
        assert_eq!(
            dot11_inspection_value(&fields, "protected"),
            Some("true".into())
        );
        assert_eq!(
            dot11_inspection_value(&fields, "sequence_number"),
            Some("291".into())
        );
        assert_eq!(
            dot11_inspection_value(&fields, "fragment_number"),
            Some("5".into())
        );
        assert_eq!(
            dot11_inspection_value(&fields, "qos"),
            Some("present".into())
        );
        assert_eq!(
            dot11_inspection_value(&fields, "qos_control"),
            Some("0xabcd".into())
        );
        assert_eq!(
            dot11_inspection_value(&fields, "src"),
            Some(source.to_string())
        );
        assert_eq!(
            dot11_inspection_value(&fields, "dst"),
            Some(destination.to_string())
        );
        assert_eq!(
            dot11_inspection_value(&fields, "bssid"),
            Some(bssid.to_string())
        );
    }

    #[test]
    fn dot11_summary_show_exposes_management_roles_without_qos_field() {
        let destination = dot11_role_mac(1);
        let source = dot11_role_mac(2);
        let bssid = dot11_role_mac(3);
        let dot11 = Dot11::beacon()
            .addr1(destination)
            .addr2(source)
            .addr3(bssid)
            .sequence_control(Dot11SequenceControl::new().with_sequence_number(7));

        let packet = Packet::from_layer(dot11.clone());
        let summary = packet.summary();
        let show = packet.show();

        for expected in [
            "Dot11(type=management",
            "subtype=beacon",
            "protected=false",
            "seq=7",
            "frag=0",
        ] {
            assert!(summary.contains(expected), "{summary}");
        }
        for expected in [
            "type: management",
            "subtype: beacon",
            "protected: false",
            "sequence_number: 7",
            "fragment_number: 0",
        ] {
            assert!(show.contains(expected), "{show}");
        }
        assert!(show.contains(&format!("src: {source}")), "{show}");
        assert!(show.contains(&format!("dst: {destination}")), "{show}");
        assert!(show.contains(&format!("bssid: {bssid}")), "{show}");
        assert!(!show.contains("qos: present"), "{show}");
    }

    #[test]
    fn dot11_decode_from_link_ieee80211_uses_typed_dot11_root() {
        let frame_control =
            dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_DATA);
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
    fn dot11_decode_from_link_radiotap_placeholder_remains_raw() {
        let bytes = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];

        let decoded = Packet::decode_from_link(LinkType::Radiotap, bytes).unwrap();

        assert!(decoded.layer::<Dot11>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &bytes);
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
    fn dot11_decode_basic_management_fixed_bytes_and_tagged_parameters_are_kept_in_dot11() {
        let frame_control =
            dot11_test_frame_control(DOT11_FRAME_TYPE_MANAGEMENT, DOT11_MGMT_SUBTYPE_BEACON);
        let fixed = [1, 2, 3, 4, 5, 6, 7, 8, 0x64, 0x00, 0x01, 0x04];
        let tags = [DOT11_TAG_SSID, 0x03, b'f', b'o', b'o'];
        let mut bytes = dot11_decode_test_header(frame_control);
        bytes.extend_from_slice(&fixed);
        bytes.extend_from_slice(&tags);

        let decoded = decode_dot11_basic(&bytes);
        let dot11 = decoded.layer::<Dot11>().unwrap();

        assert_eq!(
            dot11.management_subtype(),
            Some(Dot11ManagementSubtype::Beacon)
        );
        assert_eq!(dot11.fixed_parameters_value(), fixed);
        assert_eq!(
            dot11.tagged_parameters(),
            &[Dot11TaggedParameter::ssid(b"foo")]
        );
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
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
    fn dot11_decode_basic_unknown_valid_subtype_stays_typed_with_raw_tail() {
        let frame_control =
            dot11_test_frame_control(DOT11_FRAME_TYPE_MANAGEMENT, 7).with_retry(true);
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
        let frame_control =
            dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_NULL);
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
            DOT11_CONTROL_SUBTYPE_BLOCK_ACK,
        ];
        let two_address = [
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

        let beacon =
            dot11_test_frame_control(DOT11_FRAME_TYPE_MANAGEMENT, DOT11_MGMT_SUBTYPE_BEACON);
        let beacon_header_len = DOT11_DATA_HEADER_LEN + DOT11_MGMT_BEACON_FIXED_LEN;
        let err = Dot11::header_len_from_bytes(dot11_test_bytes(beacon, beacon_header_len - 1))
            .unwrap_err();

        assert_eq!(
            err,
            CrafterError::buffer_too_short(
                "dot11.header",
                beacon_header_len,
                beacon_header_len - 1
            )
        );

        let qos_four_address =
            dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_QOS_DATA)
                .with_to_ds(true)
                .with_from_ds(true);
        let qos_header_len = DOT11_DATA_ADDR4_HEADER_LEN + DOT11_QOS_CONTROL_LEN;
        let err =
            Dot11::header_len_from_bytes(dot11_test_bytes(qos_four_address, qos_header_len - 1))
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

    #[test]
    fn dot11_address_roles_map_data_frames_without_distribution_system() {
        let addr1 = dot11_role_mac(1);
        let addr2 = dot11_role_mac(2);
        let addr3 = dot11_role_mac(3);
        let frame = Dot11::data().addr1(addr1).addr2(addr2).addr3(addr3);

        assert_eq!(frame.receiver(), Some(addr1));
        assert_eq!(frame.transmitter(), Some(addr2));
        assert_eq!(frame.destination(), Some(addr1));
        assert_eq!(frame.source(), Some(addr2));
        assert_eq!(frame.bssid(), Some(addr3));
        assert_eq!(frame.fourth_address(), None);
    }

    #[test]
    fn dot11_address_roles_map_data_frames_to_distribution_system() {
        let addr1 = dot11_role_mac(1);
        let addr2 = dot11_role_mac(2);
        let addr3 = dot11_role_mac(3);
        let frame = Dot11::data()
            .frame_control(
                Dot11FrameControl::new()
                    .with_frame_type(DOT11_FRAME_TYPE_DATA)
                    .with_subtype(DOT11_DATA_SUBTYPE_DATA)
                    .with_to_ds(true),
            )
            .addr1(addr1)
            .addr2(addr2)
            .addr3(addr3);

        assert_eq!(frame.receiver(), Some(addr1));
        assert_eq!(frame.transmitter(), Some(addr2));
        assert_eq!(frame.destination(), Some(addr3));
        assert_eq!(frame.source(), Some(addr2));
        assert_eq!(frame.bssid(), Some(addr1));
        assert_eq!(frame.fourth_address(), None);
    }

    #[test]
    fn dot11_address_roles_map_data_frames_from_distribution_system() {
        let addr1 = dot11_role_mac(1);
        let addr2 = dot11_role_mac(2);
        let addr3 = dot11_role_mac(3);
        let frame = Dot11::data()
            .frame_control(
                Dot11FrameControl::new()
                    .with_frame_type(DOT11_FRAME_TYPE_DATA)
                    .with_subtype(DOT11_DATA_SUBTYPE_DATA)
                    .with_from_ds(true),
            )
            .addr1(addr1)
            .addr2(addr2)
            .addr3(addr3);

        assert_eq!(frame.receiver(), Some(addr1));
        assert_eq!(frame.transmitter(), Some(addr2));
        assert_eq!(frame.destination(), Some(addr1));
        assert_eq!(frame.source(), Some(addr3));
        assert_eq!(frame.bssid(), Some(addr2));
        assert_eq!(frame.fourth_address(), None);
    }

    #[test]
    fn dot11_address_roles_map_four_address_data_frames() {
        let addr1 = dot11_role_mac(1);
        let addr2 = dot11_role_mac(2);
        let addr3 = dot11_role_mac(3);
        let addr4 = dot11_role_mac(4);
        let frame = Dot11::data()
            .frame_control(
                Dot11FrameControl::new()
                    .with_frame_type(DOT11_FRAME_TYPE_DATA)
                    .with_subtype(DOT11_DATA_SUBTYPE_DATA)
                    .with_to_ds(true)
                    .with_from_ds(true),
            )
            .addr1(addr1)
            .addr2(addr2)
            .addr3(addr3)
            .addr4(addr4);

        assert_eq!(frame.receiver(), Some(addr1));
        assert_eq!(frame.transmitter(), Some(addr2));
        assert_eq!(frame.destination(), Some(addr3));
        assert_eq!(frame.source(), Some(addr4));
        assert_eq!(frame.bssid(), None);
        assert_eq!(frame.fourth_address(), Some(addr4));
    }

    #[test]
    fn dot11_address_roles_leave_missing_fourth_address_unset() {
        let addr1 = dot11_role_mac(1);
        let addr2 = dot11_role_mac(2);
        let addr3 = dot11_role_mac(3);
        let frame = Dot11::data()
            .frame_control(
                Dot11FrameControl::new()
                    .with_frame_type(DOT11_FRAME_TYPE_DATA)
                    .with_subtype(DOT11_DATA_SUBTYPE_DATA)
                    .with_to_ds(true)
                    .with_from_ds(true),
            )
            .addr1(addr1)
            .addr2(addr2)
            .addr3(addr3);

        assert_eq!(frame.receiver(), Some(addr1));
        assert_eq!(frame.transmitter(), Some(addr2));
        assert_eq!(frame.destination(), Some(addr3));
        assert_eq!(frame.source(), None);
        assert_eq!(frame.bssid(), None);
        assert_eq!(frame.fourth_address(), None);
    }

    #[test]
    fn dot11_address_roles_map_management_frames() {
        let addr1 = dot11_role_mac(1);
        let addr2 = dot11_role_mac(2);
        let addr3 = dot11_role_mac(3);
        let frame = Dot11::beacon().addr1(addr1).addr2(addr2).addr3(addr3);

        assert_eq!(frame.receiver(), Some(addr1));
        assert_eq!(frame.transmitter(), Some(addr2));
        assert_eq!(frame.destination(), Some(addr1));
        assert_eq!(frame.source(), Some(addr2));
        assert_eq!(frame.bssid(), Some(addr3));
        assert_eq!(frame.fourth_address(), None);
    }

    #[test]
    fn dot11_address_roles_are_unset_for_control_frames_in_this_phase() {
        let frame = Dot11::ack()
            .addr1(dot11_role_mac(1))
            .addr2(dot11_role_mac(2))
            .addr3(dot11_role_mac(3))
            .addr4(dot11_role_mac(4));

        assert_eq!(frame.receiver(), None);
        assert_eq!(frame.transmitter(), None);
        assert_eq!(frame.destination(), None);
        assert_eq!(frame.source(), None);
        assert_eq!(frame.bssid(), None);
        assert_eq!(frame.fourth_address(), None);
    }

    #[test]
    fn dot11_builders_create_data_frame_defaults() {
        let data = Dot11::data();

        assert_eq!(data.frame_type(), Dot11FrameType::Data);
        assert_eq!(data.data_subtype(), Some(Dot11DataSubtype::Data));
        assert_eq!(data.control_subtype(), None);
        assert_eq!(data.management_subtype(), None);
        assert_eq!(data.qos_control_value(), None);
        assert_eq!(data.fixed_parameters_value(), &[]);
        assert_eq!(data.addr1_value(), Some(MacAddr::BROADCAST));
        assert_eq!(data.addr2_value(), Some(MacAddr::ZERO));
        assert_eq!(data.addr3_value(), Some(MacAddr::ZERO));
    }

    #[test]
    fn dot11_builders_create_qos_data_defaults() {
        let qos_data = Dot11::qos_data();

        assert_eq!(qos_data.frame_type(), Dot11FrameType::Data);
        assert_eq!(qos_data.data_subtype(), Some(Dot11DataSubtype::QosData));
        assert_eq!(qos_data.qos_control_value(), Some(0));
        assert_eq!(qos_data.fixed_parameters_value(), &[]);
        assert_eq!(
            qos_data.encoded_len(),
            DOT11_DATA_HEADER_LEN + DOT11_QOS_CONTROL_LEN
        );
    }

    #[test]
    fn dot11_builders_create_management_frame_defaults() {
        let cases = [
            (Dot11::beacon(), Dot11ManagementSubtype::Beacon, 12usize),
            (
                Dot11::probe_request(),
                Dot11ManagementSubtype::ProbeRequest,
                0,
            ),
            (
                Dot11::probe_response(),
                Dot11ManagementSubtype::ProbeResponse,
                12,
            ),
            (
                Dot11::association_request(),
                Dot11ManagementSubtype::AssociationRequest,
                4,
            ),
            (
                Dot11::association_response(),
                Dot11ManagementSubtype::AssociationResponse,
                6,
            ),
            (
                Dot11::authentication(),
                Dot11ManagementSubtype::Authentication,
                6,
            ),
            (
                Dot11::deauthentication(),
                Dot11ManagementSubtype::Deauthentication,
                2,
            ),
            (
                Dot11::disassociation(),
                Dot11ManagementSubtype::Disassociation,
                2,
            ),
            (Dot11::action(), Dot11ManagementSubtype::Action, 1),
        ];

        for (frame, subtype, fixed_len) in cases {
            assert_eq!(frame.frame_type(), Dot11FrameType::Management);
            assert_eq!(frame.management_subtype(), Some(subtype));
            assert_eq!(frame.control_subtype(), None);
            assert_eq!(frame.data_subtype(), None);
            assert_eq!(frame.fixed_parameters_value().len(), fixed_len);
            assert!(frame.fixed_parameters_value().iter().all(|byte| *byte == 0));
            assert_eq!(frame.encoded_len(), DOT11_DATA_HEADER_LEN + fixed_len);
        }
    }

    #[test]
    fn dot11_builders_create_control_frame_defaults() {
        let cases = [
            (Dot11::ack(), Dot11ControlSubtype::Ack),
            (Dot11::rts(), Dot11ControlSubtype::Rts),
            (Dot11::cts(), Dot11ControlSubtype::Cts),
            (Dot11::block_ack(), Dot11ControlSubtype::BlockAck),
            (Dot11::ps_poll(), Dot11ControlSubtype::PsPoll),
        ];

        for (frame, subtype) in cases {
            assert_eq!(frame.frame_type(), Dot11FrameType::Control);
            assert_eq!(frame.control_subtype(), Some(subtype));
            assert_eq!(frame.management_subtype(), None);
            assert_eq!(frame.data_subtype(), None);
            assert_eq!(frame.fixed_parameters_value(), &[]);
            assert_eq!(frame.qos_control_value(), None);
            assert_eq!(frame.encoded_len(), DOT11_DATA_HEADER_LEN);
        }
    }

    #[test]
    fn dot11_builders_remain_packet_composable_and_preserve_overrides() {
        let custom_fc = Dot11FrameControl::from_bits(0xffff);
        let custom_addr = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]);
        let dot11 = Dot11::beacon()
            .frame_control(custom_fc)
            .addr1(custom_addr)
            .fixed_parameters([0xaa, 0xbb]);
        let packet = dot11.clone() / Raw::from([0xcc]);

        assert_eq!(packet.layer::<Dot11>(), Some(&dot11));
        assert_eq!(dot11.frame_control_value(), custom_fc);
        assert_eq!(dot11.addr1_value(), Some(custom_addr));
        assert_eq!(dot11.fixed_parameters_value(), &[0xaa, 0xbb]);
        assert_eq!(
            packet.compile().unwrap().as_bytes(),
            &[
                0xff, 0xff, // caller-supplied frame control
                0x00, 0x00, // duration/id
                0x02, 0x00, 0x5e, 0x10, 0x00, 0x01, // address 1
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // address 2
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // address 3
                0x00, 0x00, // sequence control
                0xaa, 0xbb, // caller-supplied fixed fields
                0xcc, // Raw payload
            ]
        );
    }

    #[test]
    fn dot11_layer_compile_default_three_address_data_header() {
        let packet = Packet::from_layer(Dot11::new());
        let compiled = packet.compile().unwrap();

        assert_eq!(Dot11::new().encoded_len(), DOT11_DATA_HEADER_LEN);
        assert_eq!(
            compiled.as_bytes(),
            &[
                0x08, 0x00, // frame control: data/data, little-endian
                0x00, 0x00, // duration/id
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // address 1
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // address 2
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // address 3
                0x00, 0x00, // sequence control
            ]
        );
    }

    #[test]
    fn dot11_layer_compile_preserves_explicit_fields_and_composes_payload() {
        let addr1 = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]);
        let addr2 = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x02]);
        let addr3 = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x03]);
        let addr4 = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x04]);
        let dot11 = Dot11::new()
            .frame_control(Dot11FrameControl::from_bits(0x4288))
            .duration_id(0x1234)
            .addr1(addr1)
            .addr2(addr2)
            .addr3(addr3)
            .sequence_control(Dot11SequenceControl::from_bits(0x0abc))
            .addr4(addr4)
            .qos_control(0x55aa);
        let packet = dot11.clone() / Raw::from([0xde, 0xad]);

        assert_eq!(packet.layer::<Dot11>(), Some(&dot11));
        assert_eq!(packet.len(), 2);
        assert_eq!(
            dot11.encoded_len(),
            DOT11_DATA_ADDR4_HEADER_LEN + DOT11_QOS_CONTROL_LEN
        );
        assert_eq!(
            packet.compile().unwrap().as_bytes(),
            &[
                0x88, 0x42, // frame control
                0x34, 0x12, // duration/id
                0x02, 0x00, 0x5e, 0x10, 0x00, 0x01, // address 1
                0x02, 0x00, 0x5e, 0x10, 0x00, 0x02, // address 2
                0x02, 0x00, 0x5e, 0x10, 0x00, 0x03, // address 3
                0xbc, 0x0a, // sequence control
                0x02, 0x00, 0x5e, 0x10, 0x00, 0x04, // address 4
                0xaa, 0x55, // QoS control
                0xde, 0xad, // Raw payload
            ]
        );
    }

    #[test]
    fn dot11_layer_compile_includes_fixed_and_tagged_management_bytes() {
        let dot11 = Dot11::new()
            .fixed_parameters([0x01, 0x02])
            .tag(Dot11TaggedParameter::new(0xdd, [0xaa, 0xbb, 0xcc]));

        assert_eq!(dot11.fixed_parameters_value(), &[0x01, 0x02]);
        assert_eq!(dot11.tags_value()[0].id(), 0xdd);
        assert_eq!(dot11.tags_value()[0].length(), 3);
        assert_eq!(dot11.tags_value()[0].data(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(dot11.tags_value()[0].value(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(dot11.encoded_len(), DOT11_DATA_HEADER_LEN + 2 + 5);
        assert_eq!(
            Packet::from_layer(dot11).compile().unwrap().as_bytes(),
            &[
                0x08, 0x00, // frame control
                0x00, 0x00, // duration/id
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // address 1
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // address 2
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // address 3
                0x00, 0x00, // sequence control
                0x01, 0x02, // fixed fields
                0xdd, 0x03, 0xaa, 0xbb, 0xcc, // tagged parameter
            ]
        );
    }

    #[test]
    fn dot11_layer_compile_rejects_oversized_tagged_parameter() {
        let tag = Dot11TaggedParameter::new(0xdd, vec![0u8; 256]);
        let err = Packet::from_layer(Dot11::new().tag(tag))
            .compile()
            .unwrap_err();

        assert_eq!(
            err,
            CrafterError::invalid_field_value(
                "dot11.tagged_parameter.length",
                "tagged parameter length must fit in one byte"
            )
        );
    }

    #[test]
    fn dot11_tagged_parameters_helpers_encode_source_backed_ids() {
        let ssid = Dot11TaggedParameter::ssid(b"test");
        let supported_rates = Dot11TaggedParameter::supported_rates([0x82, 0x84, 0x8b, 0x96]);
        let ds = Dot11TaggedParameter::ds_parameter_set(6);
        let tim = Dot11TaggedParameter::tim([0x00, 0x01, 0x00, 0x00]);
        let rsn = Dot11TaggedParameter::rsn([0x01, 0x00]);

        assert_eq!(ssid.id(), DOT11_TAG_SSID);
        assert_eq!(ssid.length(), 4);
        assert_eq!(ssid.value(), b"test");
        assert_eq!(supported_rates.id(), DOT11_TAG_SUPPORTED_RATES);
        assert_eq!(supported_rates.length(), 4);
        assert_eq!(ds.id(), DOT11_TAG_DS_PARAMETER_SET);
        assert_eq!(ds.value(), &[6]);
        assert_eq!(tim.id(), DOT11_TAG_TIM);
        assert_eq!(rsn.id(), DOT11_TAG_RSN);

        let dot11 = Dot11::beacon()
            .ssid(b"test")
            .supported_rates([0x82, 0x84, 0x8b, 0x96])
            .ds_parameter_set(6)
            .tim([0x00, 0x01, 0x00, 0x00])
            .rsn([0x01, 0x00]);

        assert_eq!(
            dot11.tagged_parameters(),
            &[ssid, supported_rates, ds, tim, rsn,]
        );
    }

    #[test]
    fn dot11_tagged_parameters_decode_management_tail_and_preserve_unknown() {
        let frame_control =
            dot11_test_frame_control(DOT11_FRAME_TYPE_MANAGEMENT, DOT11_MGMT_SUBTYPE_BEACON);
        let fixed = [0u8; DOT11_MGMT_BEACON_FIXED_LEN];
        let mut bytes = dot11_decode_test_header(frame_control);
        bytes.extend_from_slice(&fixed);
        bytes.extend_from_slice(&[
            DOT11_TAG_SSID,
            0x03,
            b'a',
            b'p',
            b'1',
            0xdd,
            0x02,
            0xaa,
            0xbb,
        ]);

        let decoded = decode_dot11_basic(&bytes);
        let dot11 = decoded.layer::<Dot11>().unwrap();

        assert_eq!(dot11.fixed_parameters_value(), fixed);
        assert_eq!(
            dot11.tagged_parameters(),
            &[
                Dot11TaggedParameter::ssid(b"ap1"),
                Dot11TaggedParameter::new(0xdd, [0xaa, 0xbb]),
            ]
        );
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    #[test]
    fn dot11_tagged_parameters_truncated_tags_return_structured_errors() {
        let frame_control =
            dot11_test_frame_control(DOT11_FRAME_TYPE_MANAGEMENT, DOT11_MGMT_SUBTYPE_BEACON);
        let fixed = [0u8; DOT11_MGMT_BEACON_FIXED_LEN];
        let mut bytes = dot11_decode_test_header(frame_control);
        bytes.extend_from_slice(&fixed);
        bytes.extend_from_slice(&[DOT11_TAG_SSID, 0x03, b'a']);

        let err = decode_dot11_with_registry(&ProtocolRegistry::new(), &bytes).unwrap_err();

        assert_eq!(
            err,
            CrafterError::buffer_too_short("dot11.tagged_parameter", 5, 3)
        );

        let mut bytes = dot11_decode_test_header(frame_control);
        bytes.extend_from_slice(&fixed);
        bytes.push(DOT11_TAG_SSID);

        let err = decode_dot11_with_registry(&ProtocolRegistry::new(), &bytes).unwrap_err();

        assert_eq!(
            err,
            CrafterError::buffer_too_short("dot11.tagged_parameter", 2, 1)
        );
    }
}
