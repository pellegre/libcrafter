//! IEEE 802.11 frame subtype subfields.

use super::*;

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
