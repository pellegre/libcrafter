//! DHCP message type codepoints.

use super::constants::{
    DHCP_ACK, DHCP_DECLINE, DHCP_DISCOVER, DHCP_INFORM, DHCP_NAK, DHCP_OFFER, DHCP_RELEASE,
    DHCP_REQUEST,
};

/// DHCP message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpMessageType {
    /// Discover.
    Discover,
    /// Offer.
    Offer,
    /// Request.
    Request,
    /// Decline.
    Decline,
    /// ACK.
    Ack,
    /// NAK.
    Nak,
    /// Release.
    Release,
    /// Inform.
    Inform,
    /// Unknown message type value preserved from decode.
    Unknown(u8),
}

impl DhcpMessageType {
    /// Create a DHCP message type from its wire value.
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCP_DISCOVER => Self::Discover,
            DHCP_OFFER => Self::Offer,
            DHCP_REQUEST => Self::Request,
            DHCP_DECLINE => Self::Decline,
            DHCP_ACK => Self::Ack,
            DHCP_NAK => Self::Nak,
            DHCP_RELEASE => Self::Release,
            DHCP_INFORM => Self::Inform,
            value => Self::Unknown(value),
        }
    }

    /// Wire value.
    pub const fn code(self) -> u8 {
        match self {
            Self::Discover => DHCP_DISCOVER,
            Self::Offer => DHCP_OFFER,
            Self::Request => DHCP_REQUEST,
            Self::Decline => DHCP_DECLINE,
            Self::Ack => DHCP_ACK,
            Self::Nak => DHCP_NAK,
            Self::Release => DHCP_RELEASE,
            Self::Inform => DHCP_INFORM,
            Self::Unknown(value) => value,
        }
    }
}

impl From<DhcpMessageType> for u8 {
    fn from(value: DhcpMessageType) -> Self {
        value.code()
    }
}

/// Human-readable summary label for a DHCP message type.
pub(crate) fn message_type_summary(message_type: DhcpMessageType) -> String {
    match message_type {
        DhcpMessageType::Discover => "discover".to_string(),
        DhcpMessageType::Offer => "offer".to_string(),
        DhcpMessageType::Request => "request".to_string(),
        DhcpMessageType::Decline => "decline".to_string(),
        DhcpMessageType::Ack => "ack".to_string(),
        DhcpMessageType::Nak => "nak".to_string(),
        DhcpMessageType::Release => "release".to_string(),
        DhcpMessageType::Inform => "inform".to_string(),
        DhcpMessageType::Unknown(value) => format!("unknown({value})"),
    }
}
