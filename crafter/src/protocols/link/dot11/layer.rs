//! IEEE 802.11 MAC layer.

use core::any::Any;
use core::ops::Div;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::mac::MacAddr;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};
use crate::protocols::rsn::RsnInformation;

use super::header::*;
use super::util::{dot11_hex_bytes, value_or_copy};
use super::*;

/// IEEE 802.11 MAC layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11 {
    pub(super) frame_control: Field<Dot11FrameControl>,
    pub(super) duration_id: Field<u16>,
    pub(super) addr1: Field<MacAddr>,
    pub(super) addr2: Field<MacAddr>,
    pub(super) addr3: Field<MacAddr>,
    pub(super) sequence_control: Field<Dot11SequenceControl>,
    pub(super) addr4: Field<MacAddr>,
    pub(super) qos_control: Field<u16>,
    pub(super) ht_control: Field<u32>,
    pub(super) fixed_parameters: Vec<u8>,
    pub(super) tagged_parameters: Vec<Dot11TaggedParameter>,
    pub(super) encrypted_body_len: Option<usize>,
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
