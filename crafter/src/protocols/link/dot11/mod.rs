//! IEEE 802.11 MAC layer scaffolding.

use core::any::Any;
use core::ops::Div;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::mac::MacAddr;
use crate::packet::Raw;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};
use crate::protocols::rsn::RsnInformation;
use crate::registry::ProtocolRegistry;

use super::append_llc_snap_packet_with_registry;

mod constants;
mod element;
mod fixed_fields;
mod frame_control;
mod frame_type;
mod header;
mod qos_control;
mod sequence_control;
mod subtype;
mod util;

pub use self::constants::*;
pub use self::element::Dot11TaggedParameter;
pub use self::fixed_fields::{
    Dot11ActionFixedFields, Dot11AssociationRequestFixedFields,
    Dot11AssociationResponseFixedFields, Dot11AuthenticationFixedFields, Dot11BeaconFixedFields,
    Dot11ManagementFixedFields, Dot11ReasonCodeFixedFields, Dot11ReassociationRequestFixedFields,
};
pub use self::frame_control::Dot11FrameControl;
pub use self::frame_type::Dot11FrameType;
use self::header::*;
pub use self::qos_control::Dot11QosControl;
pub use self::sequence_control::Dot11SequenceControl;
pub use self::subtype::{Dot11ControlSubtype, Dot11DataSubtype, Dot11ManagementSubtype};
use self::util::{dot11_hex_bytes, value_or_copy};

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
    encrypted_body_len: Option<usize>,
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
            encrypted_body_len: None,
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
        Self::management(Dot11ManagementSubtype::Beacon)
            .with_default_fixed_parameters(DOT11_MGMT_BEACON_FIXED_LEN)
    }

    /// Create a probe request management frame.
    pub fn probe_request() -> Self {
        Self::management(Dot11ManagementSubtype::ProbeRequest)
    }

    /// Create a probe response management frame.
    pub fn probe_response() -> Self {
        Self::management(Dot11ManagementSubtype::ProbeResponse)
            .with_default_fixed_parameters(DOT11_MGMT_PROBE_RESPONSE_FIXED_LEN)
    }

    /// Create an association request management frame.
    pub fn association_request() -> Self {
        Self::management(Dot11ManagementSubtype::AssociationRequest)
            .with_default_fixed_parameters(DOT11_MGMT_ASSOCIATION_REQUEST_FIXED_LEN)
    }

    /// Create an association response management frame.
    pub fn association_response() -> Self {
        Self::management(Dot11ManagementSubtype::AssociationResponse)
            .with_default_fixed_parameters(DOT11_MGMT_ASSOCIATION_RESPONSE_FIXED_LEN)
    }

    /// Create a reassociation request management frame.
    pub fn reassociation_request() -> Self {
        Self::management(Dot11ManagementSubtype::ReassociationRequest)
            .with_default_fixed_parameters(DOT11_MGMT_REASSOCIATION_REQUEST_FIXED_LEN)
    }

    /// Create a reassociation response management frame.
    pub fn reassociation_response() -> Self {
        Self::management(Dot11ManagementSubtype::ReassociationResponse)
            .with_default_fixed_parameters(DOT11_MGMT_REASSOCIATION_RESPONSE_FIXED_LEN)
    }

    /// Create an authentication management frame.
    pub fn authentication() -> Self {
        Self::management(Dot11ManagementSubtype::Authentication)
            .with_default_fixed_parameters(DOT11_MGMT_AUTHENTICATION_FIXED_LEN)
    }

    /// Create a deauthentication management frame.
    pub fn deauthentication() -> Self {
        Self::management(Dot11ManagementSubtype::Deauthentication)
            .with_default_fixed_parameters(DOT11_MGMT_DEAUTHENTICATION_FIXED_LEN)
    }

    /// Create a disassociation management frame.
    pub fn disassociation() -> Self {
        Self::management(Dot11ManagementSubtype::Disassociation)
            .with_default_fixed_parameters(DOT11_MGMT_DISASSOCIATION_FIXED_LEN)
    }

    /// Create an action management frame with a zero category field.
    pub fn action() -> Self {
        Self::management(Dot11ManagementSubtype::Action)
            .with_default_fixed_parameters(DOT11_MGMT_ACTION_FIXED_LEN)
    }

    /// Create an action-no-ack management frame with a zero category field.
    pub fn action_no_ack() -> Self {
        Self::management(Dot11ManagementSubtype::ActionNoAck)
            .with_default_fixed_parameters(DOT11_MGMT_ACTION_FIXED_LEN)
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

    /// Create a Block Ack Request control frame.
    pub fn block_ack_request() -> Self {
        Self::control(Dot11ControlSubtype::BlockAckRequest)
    }

    /// Create a PS-Poll control frame.
    pub fn ps_poll() -> Self {
        Self::control(Dot11ControlSubtype::PsPoll)
    }

    /// Create a CF-End control frame.
    pub fn cf_end() -> Self {
        Self::control(Dot11ControlSubtype::CfEnd)
    }

    /// Create a CF-End + CF-Ack control frame.
    pub fn cf_end_cf_ack() -> Self {
        Self::control(Dot11ControlSubtype::CfEndCfAck)
    }

    /// Set the frame-control field.
    pub fn frame_control(mut self, frame_control: Dot11FrameControl) -> Self {
        self.frame_control.set_user(frame_control);
        self
    }

    /// Set or clear the More Fragments frame-control bit.
    pub fn more_fragments(mut self, enabled: bool) -> Self {
        let frame_control = self.frame_control_value().with_more_fragments(enabled);
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

    /// Set the twelve-bit sequence number in the sequence-control field.
    pub fn sequence_number(mut self, sequence_number: u16) -> Self {
        let sequence_control = self
            .effective_sequence_control()
            .with_sequence_number(sequence_number);
        self.sequence_control.set_user(sequence_control);
        self
    }

    /// Set the four-bit fragment number in the sequence-control field.
    pub fn fragment_number(mut self, fragment_number: u8) -> Self {
        let sequence_control = self
            .effective_sequence_control()
            .with_fragment_number(fragment_number);
        self.sequence_control.set_user(sequence_control);
        self
    }

    /// Set the QoS control field.
    pub fn qos_control(mut self, qos_control: u16) -> Self {
        self.qos_control.set_user(qos_control);
        self
    }

    /// Set the QoS control field from typed subfields.
    pub fn with_qos_control_fields(mut self, qos_control: Dot11QosControl) -> Self {
        self.qos_control.set_user(qos_control.bits());
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

    /// Set Beacon fixed fields without changing the frame subtype.
    pub fn with_beacon_fixed_fields(mut self, fixed_fields: Dot11BeaconFixedFields) -> Self {
        self.fixed_parameters = fixed_fields.to_bytes().to_vec();
        self
    }

    /// Set Probe Response fixed fields without changing the frame subtype.
    pub fn with_probe_response_fixed_fields(
        mut self,
        fixed_fields: Dot11BeaconFixedFields,
    ) -> Self {
        self.fixed_parameters = fixed_fields.to_bytes().to_vec();
        self
    }

    /// Set Association Request fixed fields without changing the frame subtype.
    pub fn with_association_request_fixed_fields(
        mut self,
        fixed_fields: Dot11AssociationRequestFixedFields,
    ) -> Self {
        self.fixed_parameters = fixed_fields.to_bytes().to_vec();
        self
    }

    /// Set Association Response fixed fields without changing the frame subtype.
    pub fn with_association_response_fixed_fields(
        mut self,
        fixed_fields: Dot11AssociationResponseFixedFields,
    ) -> Self {
        self.fixed_parameters = fixed_fields.to_bytes().to_vec();
        self
    }

    /// Set Reassociation Request fixed fields without changing the frame subtype.
    pub fn with_reassociation_request_fixed_fields(
        mut self,
        fixed_fields: Dot11ReassociationRequestFixedFields,
    ) -> Self {
        self.fixed_parameters = fixed_fields.to_bytes().to_vec();
        self
    }

    /// Set Reassociation Response fixed fields without changing the frame subtype.
    pub fn with_reassociation_response_fixed_fields(
        mut self,
        fixed_fields: Dot11AssociationResponseFixedFields,
    ) -> Self {
        self.fixed_parameters = fixed_fields.to_bytes().to_vec();
        self
    }

    /// Set Authentication fixed fields without changing the frame subtype.
    pub fn with_authentication_fixed_fields(
        mut self,
        fixed_fields: Dot11AuthenticationFixedFields,
    ) -> Self {
        self.fixed_parameters = fixed_fields.to_bytes().to_vec();
        self
    }

    /// Set Deauthentication fixed fields without changing the frame subtype.
    pub fn with_deauthentication_fixed_fields(
        mut self,
        fixed_fields: Dot11ReasonCodeFixedFields,
    ) -> Self {
        self.fixed_parameters = fixed_fields.to_bytes().to_vec();
        self
    }

    /// Set Disassociation fixed fields without changing the frame subtype.
    pub fn with_disassociation_fixed_fields(
        mut self,
        fixed_fields: Dot11ReasonCodeFixedFields,
    ) -> Self {
        self.fixed_parameters = fixed_fields.to_bytes().to_vec();
        self
    }

    /// Set Action fixed fields without changing the frame subtype.
    pub fn with_action_fixed_fields(mut self, fixed_fields: Dot11ActionFixedFields) -> Self {
        self.fixed_parameters = fixed_fields.to_bytes().to_vec();
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

    /// Append an RSN tagged parameter from typed RSN information.
    pub fn with_rsn_information(self, rsn: &RsnInformation) -> Result<Self> {
        Ok(self.tag(Dot11TaggedParameter::from_rsn_information(rsn)?))
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

    /// Receiver address for data, management, or supported control frames.
    pub fn receiver(&self) -> Option<MacAddr> {
        match self.frame_type() {
            Dot11FrameType::Data | Dot11FrameType::Management => self.addr1_value(),
            Dot11FrameType::Control if dot11_control_subtype_has_known_address_layout(self) => {
                self.addr1_value()
            }
            _ => None,
        }
    }

    /// Transmitter address for data, management, or supported two-address control frames.
    pub fn transmitter(&self) -> Option<MacAddr> {
        match self.frame_type() {
            Dot11FrameType::Data | Dot11FrameType::Management => self.addr2_value(),
            Dot11FrameType::Control if dot11_control_subtype_has_addr2(self.control_subtype()) => {
                self.addr2_value()
            }
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
            Dot11FrameType::Control => match frame_control.control_subtype_value() {
                Some(Dot11ControlSubtype::PsPoll) => self.addr1_value(),
                Some(Dot11ControlSubtype::CfEnd | Dot11ControlSubtype::CfEndCfAck) => {
                    self.addr2_value()
                }
                _ => None,
            },
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

    /// Current sequence-number subfield value, if the frame has sequence control.
    pub fn sequence_number_value(&self) -> Option<u16> {
        self.sequence_control_value()
            .map(|sequence_control| sequence_control.sequence_number())
    }

    /// Current fragment-number subfield value, if the frame has sequence control.
    pub fn fragment_number_value(&self) -> Option<u8> {
        self.sequence_control_value()
            .map(|sequence_control| sequence_control.fragment_number())
    }

    /// Current QoS control field value, if present.
    pub fn qos_control_value(&self) -> Option<u16> {
        self.qos_control.value().copied()
    }

    /// Current typed QoS control field value, if present.
    pub fn qos_control_fields(&self) -> Option<Dot11QosControl> {
        self.qos_control_value().map(Dot11QosControl::from_bits)
    }

    /// Current HT Control field value, if present.
    pub fn ht_control_value(&self) -> Option<u32> {
        self.ht_control.value().copied()
    }

    /// Raw fixed management-field bytes.
    pub fn fixed_parameters_value(&self) -> &[u8] {
        &self.fixed_parameters
    }

    /// Raw fixed management-field bytes, including unsupported or malformed shapes.
    pub fn raw_fixed_parameters(&self) -> &[u8] {
        &self.fixed_parameters
    }

    /// Typed management fixed fields, or raw bytes when the shape is unsupported.
    pub fn management_fixed_fields(&self) -> Dot11ManagementFixedFields<'_> {
        match self.management_subtype() {
            Some(Dot11ManagementSubtype::Beacon) => self
                .beacon_fixed_fields()
                .map(Dot11ManagementFixedFields::Beacon)
                .unwrap_or(Dot11ManagementFixedFields::Raw(&self.fixed_parameters)),
            Some(Dot11ManagementSubtype::ProbeResponse) => self
                .probe_response_fixed_fields()
                .map(Dot11ManagementFixedFields::ProbeResponse)
                .unwrap_or(Dot11ManagementFixedFields::Raw(&self.fixed_parameters)),
            Some(Dot11ManagementSubtype::AssociationRequest) => self
                .association_request_fixed_fields()
                .map(Dot11ManagementFixedFields::AssociationRequest)
                .unwrap_or(Dot11ManagementFixedFields::Raw(&self.fixed_parameters)),
            Some(Dot11ManagementSubtype::AssociationResponse) => self
                .association_response_fixed_fields()
                .map(Dot11ManagementFixedFields::AssociationResponse)
                .unwrap_or(Dot11ManagementFixedFields::Raw(&self.fixed_parameters)),
            Some(Dot11ManagementSubtype::ReassociationRequest) => self
                .reassociation_request_fixed_fields()
                .map(Dot11ManagementFixedFields::ReassociationRequest)
                .unwrap_or(Dot11ManagementFixedFields::Raw(&self.fixed_parameters)),
            Some(Dot11ManagementSubtype::ReassociationResponse) => self
                .reassociation_response_fixed_fields()
                .map(Dot11ManagementFixedFields::ReassociationResponse)
                .unwrap_or(Dot11ManagementFixedFields::Raw(&self.fixed_parameters)),
            Some(Dot11ManagementSubtype::Authentication) => self
                .authentication_fixed_fields()
                .map(Dot11ManagementFixedFields::Authentication)
                .unwrap_or(Dot11ManagementFixedFields::Raw(&self.fixed_parameters)),
            Some(Dot11ManagementSubtype::Deauthentication) => self
                .deauthentication_fixed_fields()
                .map(Dot11ManagementFixedFields::Deauthentication)
                .unwrap_or(Dot11ManagementFixedFields::Raw(&self.fixed_parameters)),
            Some(Dot11ManagementSubtype::Disassociation) => self
                .disassociation_fixed_fields()
                .map(Dot11ManagementFixedFields::Disassociation)
                .unwrap_or(Dot11ManagementFixedFields::Raw(&self.fixed_parameters)),
            Some(Dot11ManagementSubtype::Action | Dot11ManagementSubtype::ActionNoAck) => self
                .action_fixed_fields()
                .map(Dot11ManagementFixedFields::Action)
                .unwrap_or(Dot11ManagementFixedFields::Raw(&self.fixed_parameters)),
            _ => Dot11ManagementFixedFields::Raw(&self.fixed_parameters),
        }
    }

    /// Beacon fixed fields when this frame has the supported Beacon shape.
    pub fn beacon_fixed_fields(&self) -> Option<Dot11BeaconFixedFields> {
        if self.management_subtype() == Some(Dot11ManagementSubtype::Beacon) {
            Dot11BeaconFixedFields::from_bytes(&self.fixed_parameters)
        } else {
            None
        }
    }

    /// Probe Response fixed fields when this frame has the supported shape.
    pub fn probe_response_fixed_fields(&self) -> Option<Dot11BeaconFixedFields> {
        if self.management_subtype() == Some(Dot11ManagementSubtype::ProbeResponse) {
            Dot11BeaconFixedFields::from_bytes(&self.fixed_parameters)
        } else {
            None
        }
    }

    /// Association Request fixed fields when this frame has the supported shape.
    pub fn association_request_fixed_fields(&self) -> Option<Dot11AssociationRequestFixedFields> {
        if self.management_subtype() == Some(Dot11ManagementSubtype::AssociationRequest) {
            Dot11AssociationRequestFixedFields::from_bytes(&self.fixed_parameters)
        } else {
            None
        }
    }

    /// Association Response fixed fields when this frame has the supported shape.
    pub fn association_response_fixed_fields(&self) -> Option<Dot11AssociationResponseFixedFields> {
        if self.management_subtype() == Some(Dot11ManagementSubtype::AssociationResponse) {
            Dot11AssociationResponseFixedFields::from_bytes(&self.fixed_parameters)
        } else {
            None
        }
    }

    /// Reassociation Request fixed fields when this frame has the supported shape.
    pub fn reassociation_request_fixed_fields(
        &self,
    ) -> Option<Dot11ReassociationRequestFixedFields> {
        if self.management_subtype() == Some(Dot11ManagementSubtype::ReassociationRequest) {
            Dot11ReassociationRequestFixedFields::from_bytes(&self.fixed_parameters)
        } else {
            None
        }
    }

    /// Reassociation Response fixed fields when this frame has the supported shape.
    pub fn reassociation_response_fixed_fields(
        &self,
    ) -> Option<Dot11AssociationResponseFixedFields> {
        if self.management_subtype() == Some(Dot11ManagementSubtype::ReassociationResponse) {
            Dot11AssociationResponseFixedFields::from_bytes(&self.fixed_parameters)
        } else {
            None
        }
    }

    /// Authentication fixed fields when this frame has the supported shape.
    pub fn authentication_fixed_fields(&self) -> Option<Dot11AuthenticationFixedFields> {
        if self.management_subtype() == Some(Dot11ManagementSubtype::Authentication) {
            Dot11AuthenticationFixedFields::from_bytes(&self.fixed_parameters)
        } else {
            None
        }
    }

    /// Deauthentication fixed fields when this frame has the supported shape.
    pub fn deauthentication_fixed_fields(&self) -> Option<Dot11ReasonCodeFixedFields> {
        if self.management_subtype() == Some(Dot11ManagementSubtype::Deauthentication) {
            Dot11ReasonCodeFixedFields::from_bytes(&self.fixed_parameters)
        } else {
            None
        }
    }

    /// Disassociation fixed fields when this frame has the supported shape.
    pub fn disassociation_fixed_fields(&self) -> Option<Dot11ReasonCodeFixedFields> {
        if self.management_subtype() == Some(Dot11ManagementSubtype::Disassociation) {
            Dot11ReasonCodeFixedFields::from_bytes(&self.fixed_parameters)
        } else {
            None
        }
    }

    /// Action fixed fields when this frame has the supported Action shape.
    pub fn action_fixed_fields(&self) -> Option<Dot11ActionFixedFields> {
        match self.management_subtype() {
            Some(Dot11ManagementSubtype::Action | Dot11ManagementSubtype::ActionNoAck) => {
                Dot11ActionFixedFields::from_bytes(&self.fixed_parameters)
            }
            _ => None,
        }
    }

    /// Raw tagged parameters.
    pub fn tags_value(&self) -> &[Dot11TaggedParameter] {
        &self.tagged_parameters
    }

    /// Raw tagged parameters.
    pub fn tagged_parameters(&self) -> &[Dot11TaggedParameter] {
        &self.tagged_parameters
    }

    /// First RSN information element carried by the raw tagged parameters.
    pub fn rsn_information(&self) -> Option<Result<RsnInformation>> {
        self.tagged_parameters
            .iter()
            .find_map(Dot11TaggedParameter::rsn_information)
    }

    /// RSN information elements carried by the raw tagged parameters.
    pub fn rsn_information_elements(&self) -> impl Iterator<Item = Result<RsnInformation>> + '_ {
        self.tagged_parameters
            .iter()
            .filter_map(Dot11TaggedParameter::rsn_information)
    }

    /// Return true when the Protected Frame bit is set.
    pub fn is_protected(&self) -> bool {
        self.frame_control_value().protected()
    }

    /// Return true when the More Fragments frame-control bit is set.
    pub fn has_more_fragments(&self) -> bool {
        self.frame_control_value().more_fragments()
    }

    /// Return true when this frame carries 802.11 fragmentation metadata.
    ///
    /// `crafter` exposes this metadata for inspection but does not reassemble
    /// fragmented 802.11 payloads.
    pub fn is_fragmented(&self) -> bool {
        self.has_more_fragments()
            || self
                .fragment_number_value()
                .is_some_and(|number| number != 0)
    }

    /// Decoded encrypted body length for protected data frames.
    pub fn encrypted_body_len(&self) -> Option<usize> {
        self.encrypted_body_len
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
        if let Some(encrypted_body_len) = self.encrypted_body_len() {
            fields.push(format!("encrypted_body_len={encrypted_body_len}"));
        }

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
        if let Some(encrypted_body_len) = self.encrypted_body_len() {
            fields.push(("encrypted_body_len", encrypted_body_len.to_string()));
        }

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
            let qos = Dot11QosControl::from_bits(qos_control);
            fields.push(("qos_tid", qos.tid().to_string()));
            fields.push(("qos_eosp", qos.eosp().to_string()));
            fields.push(("qos_ack_policy", qos.ack_policy().to_string()));
            fields.push(("qos_a_msdu_present", qos.a_msdu_present().to_string()));
            fields.push(("qos_txop_queue_size", qos.txop_queue_size().to_string()));
        }
        if let Some(ht_control) = self.ht_control_value() {
            fields.push(("ht_control", format!("0x{ht_control:08x}")));
        }
        if !self.fixed_parameters.is_empty() {
            fields.push(("fixed_parameters", dot11_hex_bytes(&self.fixed_parameters)));
        }
        match self.management_fixed_fields() {
            Dot11ManagementFixedFields::Beacon(fixed)
            | Dot11ManagementFixedFields::ProbeResponse(fixed) => {
                fields.push(("timestamp", fixed.timestamp().to_string()));
                fields.push(("beacon_interval", fixed.beacon_interval().to_string()));
                fields.push((
                    "capability_information",
                    format!("0x{:04x}", fixed.capability_information()),
                ));
            }
            Dot11ManagementFixedFields::AssociationRequest(fixed) => {
                fields.push((
                    "capability_information",
                    format!("0x{:04x}", fixed.capability_information()),
                ));
                fields.push(("listen_interval", fixed.listen_interval().to_string()));
            }
            Dot11ManagementFixedFields::AssociationResponse(fixed)
            | Dot11ManagementFixedFields::ReassociationResponse(fixed) => {
                fields.push((
                    "capability_information",
                    format!("0x{:04x}", fixed.capability_information()),
                ));
                fields.push(("status_code", fixed.status_code().to_string()));
                fields.push(("association_id", fixed.association_id().to_string()));
            }
            Dot11ManagementFixedFields::ReassociationRequest(fixed) => {
                fields.push((
                    "capability_information",
                    format!("0x{:04x}", fixed.capability_information()),
                ));
                fields.push(("listen_interval", fixed.listen_interval().to_string()));
                fields.push(("current_ap_address", fixed.current_ap_address().to_string()));
            }
            Dot11ManagementFixedFields::Authentication(fixed) => {
                fields.push(("algorithm_number", fixed.algorithm_number().to_string()));
                fields.push((
                    "transaction_sequence_number",
                    fixed.transaction_sequence_number().to_string(),
                ));
                fields.push(("status_code", fixed.status_code().to_string()));
            }
            Dot11ManagementFixedFields::Deauthentication(fixed)
            | Dot11ManagementFixedFields::Disassociation(fixed) => {
                fields.push(("reason_code", fixed.reason_code().to_string()));
            }
            Dot11ManagementFixedFields::Action(fixed) => {
                fields.push(("category", fixed.category().to_string()));
                fields.push(("category_label", dot11_category_label(fixed.category())));
            }
            Dot11ManagementFixedFields::Raw(_) => {}
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
        dot11_encoded_mac_header_len(self)
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

        let frame_control = self.frame_control_value();
        if frame_control.frame_type_value() == Dot11FrameType::Control {
            if dot11_control_emit_addr2(self) {
                out.extend_from_slice(&self.effective_addr2().octets());
            }
            if dot11_control_emit_addr3(self) {
                out.extend_from_slice(&self.effective_addr3().octets());
            }
            if dot11_control_emit_sequence_control(self) {
                out.extend_from_slice(&self.effective_sequence_control().compile());
            }
        } else {
            out.extend_from_slice(&self.effective_addr2().octets());
            out.extend_from_slice(&self.effective_addr3().octets());
            out.extend_from_slice(&self.effective_sequence_control().compile());
        }

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
        && !dot11.is_fragmented()
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
        encrypted_body_len: None,
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
            if frame_control.protected() {
                dot11.encrypted_body_len = Some(bytes.len() - offset);
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

pub(super) fn read_u16_le_at(bytes: &[u8], offset: usize) -> u16 {
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

pub(super) fn read_mac_at(bytes: &[u8], offset: usize) -> MacAddr {
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
    use crate::{
        Ipv4, LinkType, LlcSnap, Packet, Radiotap, Raw, RsnCapabilities, RSN_AKM_SUITE_SAE,
        RSN_CIPHER_SUITE_GCMP_256,
    };

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

    fn decode_dot11_management_fixed_fields_frame(
        subtype: u8,
        fixed: &[u8],
        tail: &[u8],
    ) -> (Packet, Vec<u8>) {
        let frame_control = dot11_test_frame_control(DOT11_FRAME_TYPE_MANAGEMENT, subtype);
        let mut bytes = dot11_decode_test_header(frame_control);
        bytes.extend_from_slice(fixed);
        bytes.extend_from_slice(tail);

        (decode_dot11_basic(&bytes), bytes)
    }

    fn dot11_compiled_management_body(dot11: Dot11) -> Vec<u8> {
        Packet::from_layer(dot11).compile().unwrap().into_bytes()[DOT11_DATA_HEADER_LEN..].to_vec()
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

        let packet =
            Dot11::qos_data().with_qos_control_fields(qos_control) / Raw::from([0xde, 0xad]);
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
        let frame_control =
            dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_DATA);
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
    fn dot11_management_fixed_fields_encode_typed_builders_for_supported_subtypes() {
        let beacon = Dot11BeaconFixedFields::new(0x0102_0304_0506_0708, 0x1000, 0x0431);
        let association_request = Dot11AssociationRequestFixedFields::new(0x1201, 0x3344);
        let association_response = Dot11AssociationResponseFixedFields::new(0x0001, 0x0000, 0xc123);
        let reassociation_request =
            Dot11ReassociationRequestFixedFields::new(0x0411, 0x0020, dot11_role_mac(4));
        let authentication = Dot11AuthenticationFixedFields::new(0x0000, 0x0002, 0x0000);
        let reason = Dot11ReasonCodeFixedFields::new(0x0007);
        let action = Dot11ActionFixedFields::new(DOT11_CATEGORY_PUBLIC);

        let frame = Dot11::beacon().with_beacon_fixed_fields(beacon);
        assert_eq!(frame.beacon_fixed_fields(), Some(beacon));
        assert_eq!(
            frame.management_fixed_fields(),
            Dot11ManagementFixedFields::Beacon(beacon)
        );
        assert_eq!(frame.raw_fixed_parameters(), beacon.to_bytes());
        assert_eq!(dot11_compiled_management_body(frame), beacon.to_bytes());

        let frame = Dot11::probe_response().with_probe_response_fixed_fields(beacon);
        assert_eq!(frame.probe_response_fixed_fields(), Some(beacon));
        assert_eq!(
            frame.management_fixed_fields(),
            Dot11ManagementFixedFields::ProbeResponse(beacon)
        );
        assert_eq!(dot11_compiled_management_body(frame), beacon.to_bytes());

        let frame =
            Dot11::association_request().with_association_request_fixed_fields(association_request);
        assert_eq!(
            frame.association_request_fixed_fields(),
            Some(association_request)
        );
        assert_eq!(
            frame.management_fixed_fields(),
            Dot11ManagementFixedFields::AssociationRequest(association_request)
        );
        assert_eq!(
            dot11_compiled_management_body(frame),
            association_request.to_bytes()
        );

        let frame = Dot11::association_response()
            .with_association_response_fixed_fields(association_response);
        assert_eq!(
            frame.association_response_fixed_fields(),
            Some(association_response)
        );
        assert_eq!(
            frame.management_fixed_fields(),
            Dot11ManagementFixedFields::AssociationResponse(association_response)
        );
        assert_eq!(
            dot11_compiled_management_body(frame),
            association_response.to_bytes()
        );

        let frame = Dot11::reassociation_request()
            .with_reassociation_request_fixed_fields(reassociation_request);
        assert_eq!(
            frame.reassociation_request_fixed_fields(),
            Some(reassociation_request)
        );
        assert_eq!(
            frame.management_fixed_fields(),
            Dot11ManagementFixedFields::ReassociationRequest(reassociation_request)
        );
        assert_eq!(
            dot11_compiled_management_body(frame),
            reassociation_request.to_bytes()
        );

        let frame = Dot11::reassociation_response()
            .with_reassociation_response_fixed_fields(association_response);
        assert_eq!(
            frame.reassociation_response_fixed_fields(),
            Some(association_response)
        );
        assert_eq!(
            frame.management_fixed_fields(),
            Dot11ManagementFixedFields::ReassociationResponse(association_response)
        );
        assert_eq!(
            dot11_compiled_management_body(frame),
            association_response.to_bytes()
        );

        let frame = Dot11::authentication().with_authentication_fixed_fields(authentication);
        assert_eq!(frame.authentication_fixed_fields(), Some(authentication));
        assert_eq!(
            frame.management_fixed_fields(),
            Dot11ManagementFixedFields::Authentication(authentication)
        );
        assert_eq!(
            dot11_compiled_management_body(frame),
            authentication.to_bytes()
        );

        let frame = Dot11::deauthentication().with_deauthentication_fixed_fields(reason);
        assert_eq!(frame.deauthentication_fixed_fields(), Some(reason));
        assert_eq!(
            frame.management_fixed_fields(),
            Dot11ManagementFixedFields::Deauthentication(reason)
        );
        assert_eq!(dot11_compiled_management_body(frame), reason.to_bytes());

        let frame = Dot11::disassociation().with_disassociation_fixed_fields(reason);
        assert_eq!(frame.disassociation_fixed_fields(), Some(reason));
        assert_eq!(
            frame.management_fixed_fields(),
            Dot11ManagementFixedFields::Disassociation(reason)
        );
        assert_eq!(dot11_compiled_management_body(frame), reason.to_bytes());

        let frame = Dot11::action().with_action_fixed_fields(action);
        assert_eq!(frame.action_fixed_fields(), Some(action));
        assert_eq!(
            frame.management_fixed_fields(),
            Dot11ManagementFixedFields::Action(action)
        );
        assert_eq!(dot11_compiled_management_body(frame), action.to_bytes());

        let frame = Dot11::action_no_ack().with_action_fixed_fields(action);
        assert_eq!(
            frame.management_subtype(),
            Some(Dot11ManagementSubtype::ActionNoAck)
        );
        assert_eq!(frame.action_fixed_fields(), Some(action));
        assert_eq!(dot11_compiled_management_body(frame), action.to_bytes());
    }

    #[test]
    fn dot11_management_fixed_fields_decode_supported_subtypes_from_wire() {
        let beacon = Dot11BeaconFixedFields::new(0x0807_0605_0403_0201, 0x0064, 0x0411);
        let association_request = Dot11AssociationRequestFixedFields::new(0x0431, 0x000a);
        let association_response = Dot11AssociationResponseFixedFields::new(0x0411, 0x0011, 0xc002);
        let reassociation_request =
            Dot11ReassociationRequestFixedFields::new(0x0421, 0x000b, dot11_role_mac(9));
        let authentication = Dot11AuthenticationFixedFields::new(0x0000, 0x0001, 0x0000);
        let reason = Dot11ReasonCodeFixedFields::new(0x0008);
        let action = Dot11ActionFixedFields::new(DOT11_CATEGORY_SA_QUERY);

        let (decoded, bytes) = decode_dot11_management_fixed_fields_frame(
            DOT11_MGMT_SUBTYPE_BEACON,
            &beacon.to_bytes(),
            &[],
        );
        let dot11 = decoded.layer::<Dot11>().unwrap();
        assert_eq!(dot11.beacon_fixed_fields(), Some(beacon));
        assert_eq!(
            dot11.management_fixed_fields(),
            Dot11ManagementFixedFields::Beacon(beacon)
        );
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);

        let (decoded, bytes) = decode_dot11_management_fixed_fields_frame(
            DOT11_MGMT_SUBTYPE_PROBE_RESPONSE,
            &beacon.to_bytes(),
            &[],
        );
        let dot11 = decoded.layer::<Dot11>().unwrap();
        assert_eq!(dot11.probe_response_fixed_fields(), Some(beacon));
        assert_eq!(
            dot11.management_fixed_fields(),
            Dot11ManagementFixedFields::ProbeResponse(beacon)
        );
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);

        let (decoded, bytes) = decode_dot11_management_fixed_fields_frame(
            DOT11_MGMT_SUBTYPE_ASSOCIATION_REQUEST,
            &association_request.to_bytes(),
            &[],
        );
        let dot11 = decoded.layer::<Dot11>().unwrap();
        assert_eq!(
            dot11.association_request_fixed_fields(),
            Some(association_request)
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);

        let (decoded, bytes) = decode_dot11_management_fixed_fields_frame(
            DOT11_MGMT_SUBTYPE_ASSOCIATION_RESPONSE,
            &association_response.to_bytes(),
            &[],
        );
        let dot11 = decoded.layer::<Dot11>().unwrap();
        assert_eq!(
            dot11.association_response_fixed_fields(),
            Some(association_response)
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);

        let (decoded, bytes) = decode_dot11_management_fixed_fields_frame(
            DOT11_MGMT_SUBTYPE_REASSOCIATION_REQUEST,
            &reassociation_request.to_bytes(),
            &[],
        );
        let dot11 = decoded.layer::<Dot11>().unwrap();
        assert_eq!(
            dot11.reassociation_request_fixed_fields(),
            Some(reassociation_request)
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);

        let (decoded, bytes) = decode_dot11_management_fixed_fields_frame(
            DOT11_MGMT_SUBTYPE_REASSOCIATION_RESPONSE,
            &association_response.to_bytes(),
            &[],
        );
        let dot11 = decoded.layer::<Dot11>().unwrap();
        assert_eq!(
            dot11.reassociation_response_fixed_fields(),
            Some(association_response)
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);

        let (decoded, bytes) = decode_dot11_management_fixed_fields_frame(
            DOT11_MGMT_SUBTYPE_AUTHENTICATION,
            &authentication.to_bytes(),
            &[],
        );
        let dot11 = decoded.layer::<Dot11>().unwrap();
        assert_eq!(dot11.authentication_fixed_fields(), Some(authentication));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);

        let (decoded, bytes) = decode_dot11_management_fixed_fields_frame(
            DOT11_MGMT_SUBTYPE_DEAUTHENTICATION,
            &reason.to_bytes(),
            &[],
        );
        let dot11 = decoded.layer::<Dot11>().unwrap();
        assert_eq!(dot11.deauthentication_fixed_fields(), Some(reason));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);

        let (decoded, bytes) = decode_dot11_management_fixed_fields_frame(
            DOT11_MGMT_SUBTYPE_DISASSOCIATION,
            &reason.to_bytes(),
            &[],
        );
        let dot11 = decoded.layer::<Dot11>().unwrap();
        assert_eq!(dot11.disassociation_fixed_fields(), Some(reason));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);

        let (decoded, bytes) = decode_dot11_management_fixed_fields_frame(
            DOT11_MGMT_SUBTYPE_ACTION,
            &action.to_bytes(),
            b"action-body",
        );
        let dot11 = decoded.layer::<Dot11>().unwrap();
        assert_eq!(dot11.action_fixed_fields(), Some(action));
        assert_eq!(
            dot11.management_fixed_fields(),
            Dot11ManagementFixedFields::Action(action)
        );
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), b"action-body");
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);

        let (decoded, bytes) = decode_dot11_management_fixed_fields_frame(
            DOT11_MGMT_SUBTYPE_ACTION_NO_ACK,
            &action.to_bytes(),
            b"no-ack-body",
        );
        let dot11 = decoded.layer::<Dot11>().unwrap();
        assert_eq!(dot11.action_fixed_fields(), Some(action));
        assert_eq!(
            dot11.management_fixed_fields(),
            Dot11ManagementFixedFields::Action(action)
        );
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), b"no-ack-body");
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    #[test]
    fn dot11_management_fixed_fields_raw_fallback_preserves_overrides() {
        let malformed = Dot11::beacon().fixed_parameters([0xaa, 0xbb]);

        assert_eq!(malformed.beacon_fixed_fields(), None);
        assert_eq!(
            malformed.management_fixed_fields(),
            Dot11ManagementFixedFields::Raw(&[0xaa, 0xbb])
        );
        assert_eq!(malformed.raw_fixed_parameters(), &[0xaa, 0xbb]);
        assert_eq!(dot11_compiled_management_body(malformed), vec![0xaa, 0xbb]);

        let unsupported = Dot11::management(Dot11ManagementSubtype::Unknown(7))
            .fixed_parameters([0x01, 0x02, 0x03]);

        assert_eq!(
            unsupported.management_fixed_fields(),
            Dot11ManagementFixedFields::Raw(&[0x01, 0x02, 0x03])
        );
        assert_eq!(
            dot11_compiled_management_body(unsupported),
            vec![0x01, 0x02, 0x03]
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
    fn dot11_protected_data_raw_body_len_and_no_llc_dispatch() {
        let frame_control =
            dot11_test_frame_control(DOT11_FRAME_TYPE_DATA, DOT11_DATA_SUBTYPE_DATA)
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
    fn dot11_address_roles_map_supported_control_frames() {
        let ra = dot11_role_mac(1);
        let ta = dot11_role_mac(2);

        let ack = Dot11::ack().addr1(ra).addr2(ta);
        assert_eq!(ack.receiver(), Some(ra));
        assert_eq!(ack.transmitter(), None);
        assert_eq!(ack.bssid(), None);

        for frame in [
            Dot11::rts().addr1(ra).addr2(ta),
            Dot11::block_ack_request().addr1(ra).addr2(ta),
            Dot11::block_ack().addr1(ra).addr2(ta),
        ] {
            assert_eq!(frame.receiver(), Some(ra));
            assert_eq!(frame.transmitter(), Some(ta));
            assert_eq!(frame.bssid(), None);
        }

        let ps_poll = Dot11::ps_poll().addr1(ra).addr2(ta);
        assert_eq!(ps_poll.receiver(), Some(ra));
        assert_eq!(ps_poll.transmitter(), Some(ta));
        assert_eq!(ps_poll.bssid(), Some(ra));

        let cf_end = Dot11::cf_end().addr1(ra).addr2(ta);
        assert_eq!(cf_end.receiver(), Some(ra));
        assert_eq!(cf_end.transmitter(), Some(ta));
        assert_eq!(cf_end.bssid(), Some(ta));

        let unsupported = Dot11::control(Dot11ControlSubtype::Trigger)
            .addr1(ra)
            .addr2(ta);
        assert_eq!(unsupported.receiver(), None);
        assert_eq!(unsupported.transmitter(), None);
        assert_eq!(unsupported.bssid(), None);

        assert_eq!(ack.destination(), None);
        assert_eq!(ack.source(), None);
        assert_eq!(ack.fourth_address(), None);
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
            (
                Dot11::ack(),
                Dot11ControlSubtype::Ack,
                DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN,
            ),
            (
                Dot11::rts(),
                Dot11ControlSubtype::Rts,
                DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            ),
            (
                Dot11::cts(),
                Dot11ControlSubtype::Cts,
                DOT11_CONTROL_ONE_ADDRESS_HEADER_LEN,
            ),
            (
                Dot11::block_ack_request(),
                Dot11ControlSubtype::BlockAckRequest,
                DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            ),
            (
                Dot11::block_ack(),
                Dot11ControlSubtype::BlockAck,
                DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            ),
            (
                Dot11::ps_poll(),
                Dot11ControlSubtype::PsPoll,
                DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            ),
            (
                Dot11::cf_end(),
                Dot11ControlSubtype::CfEnd,
                DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            ),
            (
                Dot11::cf_end_cf_ack(),
                Dot11ControlSubtype::CfEndCfAck,
                DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN,
            ),
        ];

        for (frame, subtype, encoded_len) in cases {
            assert_eq!(frame.frame_type(), Dot11FrameType::Control);
            assert_eq!(frame.control_subtype(), Some(subtype));
            assert_eq!(frame.management_subtype(), None);
            assert_eq!(frame.data_subtype(), None);
            assert_eq!(frame.fixed_parameters_value(), &[]);
            assert_eq!(frame.qos_control_value(), None);
            assert_eq!(frame.encoded_len(), encoded_len);
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
    fn dot11_rsn_tag_integration_beacon_surfaces_typed_rsn_and_preserves_raw_tags() {
        let rsn = RsnInformation::new()
            .with_capabilities(RsnCapabilities::new().with_pre_authentication(true));
        let ssid = Dot11TaggedParameter::ssid(b"rsn-ap");
        let unknown = Dot11TaggedParameter::new(0xdd, [0xaa, 0xbb, 0xcc]);
        let typed_rsn = Dot11TaggedParameter::from_rsn_information(&rsn).unwrap();
        let raw_rsn = Dot11TaggedParameter::rsn([0x01]);
        let dot11 = Dot11::beacon()
            .tag(ssid.clone())
            .tag(unknown.clone())
            .with_rsn_information(&rsn)
            .unwrap()
            .tag(raw_rsn.clone());
        let compiled = Packet::from_layer(dot11).compile().unwrap().into_bytes();

        let decoded = decode_dot11_basic(&compiled);
        let dot11 = decoded.layer::<Dot11>().unwrap();

        assert_eq!(
            dot11.management_subtype(),
            Some(Dot11ManagementSubtype::Beacon)
        );
        assert_eq!(
            dot11.tagged_parameters(),
            &[ssid, unknown.clone(), typed_rsn, raw_rsn.clone()]
        );
        assert!(unknown.rsn_information().is_none());
        assert_eq!(dot11.rsn_information().unwrap().unwrap(), rsn);
        assert_eq!(
            dot11.rsn_information_elements().next().unwrap().unwrap(),
            rsn
        );

        let raw_rsn_error = raw_rsn.rsn_information().unwrap().unwrap_err();
        assert_eq!(
            raw_rsn_error,
            CrafterError::buffer_too_short("rsn_information_element.version", 2, 1)
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_slice());
    }

    #[test]
    fn dot11_rsn_tag_integration_association_request_carries_rsn_ie() {
        let rsn = RsnInformation::new()
            .with_group_cipher_suite(RSN_CIPHER_SUITE_GCMP_256)
            .with_pairwise_cipher_list([RSN_CIPHER_SUITE_GCMP_256])
            .with_akm_list([RSN_AKM_SUITE_SAE])
            .with_capabilities(
                RsnCapabilities::new()
                    .with_management_frame_protection_required(true)
                    .with_management_frame_protection_capable(true),
            );
        let ssid = Dot11TaggedParameter::ssid(b"rsn-ap");
        let rates = Dot11TaggedParameter::supported_rates([0x82, 0x84, 0x8b, 0x96]);
        let typed_rsn = Dot11TaggedParameter::from_rsn_information(&rsn).unwrap();
        let dot11 = Dot11::association_request()
            .tag(ssid.clone())
            .tag(rates.clone())
            .with_rsn_information(&rsn)
            .unwrap();
        let compiled = Packet::from_layer(dot11).compile().unwrap().into_bytes();

        let decoded = decode_dot11_basic(&compiled);
        let dot11 = decoded.layer::<Dot11>().unwrap();

        assert_eq!(
            dot11.management_subtype(),
            Some(Dot11ManagementSubtype::AssociationRequest)
        );
        assert_eq!(
            dot11.fixed_parameters_value().len(),
            DOT11_MGMT_ASSOCIATION_REQUEST_FIXED_LEN
        );
        assert_eq!(dot11.tagged_parameters(), &[ssid, rates, typed_rsn]);
        assert_eq!(dot11.rsn_information().unwrap().unwrap(), rsn);

        let rsns: Vec<_> = dot11
            .rsn_information_elements()
            .map(|result| result.unwrap())
            .collect();
        assert_eq!(rsns, vec![rsn]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_slice());
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
