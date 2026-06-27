//! DHCPv6 message type codepoints.
//!
//! Source: IANA "DHCPv6 Message Types" registry. Unknown and currently
//! unassigned codepoints are preserved as `Unknown(u8)`.

use super::constants::{
    DHCPV6_ACTIVE_LEASEQUERY, DHCPV6_ADDR_REG_INFORM, DHCPV6_ADDR_REG_REPLY, DHCPV6_ADVERTISE,
    DHCPV6_BNDREPLY, DHCPV6_BNDUPD, DHCPV6_CONFIRM, DHCPV6_CONNECT, DHCPV6_CONNECTREPLY,
    DHCPV6_CONTACT, DHCPV6_DECLINE, DHCPV6_DHCPV4_QUERY, DHCPV6_DHCPV4_RESPONSE, DHCPV6_DISCONNECT,
    DHCPV6_INFORMATION_REQUEST, DHCPV6_LEASEQUERY, DHCPV6_LEASEQUERY_DATA, DHCPV6_LEASEQUERY_DONE,
    DHCPV6_LEASEQUERY_REPLY, DHCPV6_POOLREQ, DHCPV6_POOLRESP, DHCPV6_REBIND, DHCPV6_RECONFIGURE,
    DHCPV6_RECONFIGURE_REPLY, DHCPV6_RECONFIGURE_REQUEST, DHCPV6_RELAY_FORW, DHCPV6_RELAY_REPL,
    DHCPV6_RELEASE, DHCPV6_RENEW, DHCPV6_REPLY, DHCPV6_REQUEST, DHCPV6_SOLICIT, DHCPV6_STARTTLS,
    DHCPV6_STATE, DHCPV6_UPDDONE, DHCPV6_UPDREQ, DHCPV6_UPDREQALL,
};

/// DHCPv6 message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6MessageType {
    /// SOLICIT (RFC 9915).
    Solicit,
    /// ADVERTISE (RFC 9915).
    Advertise,
    /// REQUEST (RFC 9915).
    Request,
    /// CONFIRM (RFC 9915).
    Confirm,
    /// RENEW (RFC 9915).
    Renew,
    /// REBIND (RFC 9915).
    Rebind,
    /// REPLY (RFC 9915).
    Reply,
    /// RELEASE (RFC 9915).
    Release,
    /// DECLINE (RFC 9915).
    Decline,
    /// RECONFIGURE (RFC 9915).
    Reconfigure,
    /// INFORMATION-REQUEST (RFC 9915).
    InformationRequest,
    /// RELAY-FORW (RFC 9915).
    RelayForw,
    /// RELAY-REPL (RFC 9915).
    RelayRepl,
    /// LEASEQUERY (RFC 5007).
    LeaseQuery,
    /// LEASEQUERY-REPLY (RFC 5007).
    LeaseQueryReply,
    /// LEASEQUERY-DONE (RFC 5460).
    LeaseQueryDone,
    /// LEASEQUERY-DATA (RFC 5460).
    LeaseQueryData,
    /// RECONFIGURE-REQUEST (RFC 6977).
    ReconfigureRequest,
    /// RECONFIGURE-REPLY (RFC 6977).
    ReconfigureReply,
    /// DHCPV4-QUERY (RFC 7341).
    Dhcpv4Query,
    /// DHCPV4-RESPONSE (RFC 7341).
    Dhcpv4Response,
    /// ACTIVELEASEQUERY (RFC 7653).
    ActiveLeaseQuery,
    /// STARTTLS (RFC 7653).
    StartTls,
    /// BNDUPD (RFC 8156).
    BndUpd,
    /// BNDREPLY (RFC 8156).
    BndReply,
    /// POOLREQ (RFC 8156).
    PoolReq,
    /// POOLRESP (RFC 8156).
    PoolResp,
    /// UPDREQ (RFC 8156).
    UpdReq,
    /// UPDREQALL (RFC 8156).
    UpdReqAll,
    /// UPDDONE (RFC 8156).
    UpdDone,
    /// CONNECT (RFC 8156).
    Connect,
    /// CONNECTREPLY (RFC 8156).
    ConnectReply,
    /// DISCONNECT (RFC 8156).
    Disconnect,
    /// STATE (RFC 8156).
    State,
    /// CONTACT (RFC 8156).
    Contact,
    /// ADDR-REG-INFORM (RFC 9686).
    AddrRegInform,
    /// ADDR-REG-REPLY (RFC 9686).
    AddrRegReply,
    /// Unknown or currently unassigned message type value preserved from decode.
    Unknown(u8),
}

impl Dhcpv6MessageType {
    /// Create a DHCPv6 message type from its wire value.
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCPV6_SOLICIT => Self::Solicit,
            DHCPV6_ADVERTISE => Self::Advertise,
            DHCPV6_REQUEST => Self::Request,
            DHCPV6_CONFIRM => Self::Confirm,
            DHCPV6_RENEW => Self::Renew,
            DHCPV6_REBIND => Self::Rebind,
            DHCPV6_REPLY => Self::Reply,
            DHCPV6_RELEASE => Self::Release,
            DHCPV6_DECLINE => Self::Decline,
            DHCPV6_RECONFIGURE => Self::Reconfigure,
            DHCPV6_INFORMATION_REQUEST => Self::InformationRequest,
            DHCPV6_RELAY_FORW => Self::RelayForw,
            DHCPV6_RELAY_REPL => Self::RelayRepl,
            DHCPV6_LEASEQUERY => Self::LeaseQuery,
            DHCPV6_LEASEQUERY_REPLY => Self::LeaseQueryReply,
            DHCPV6_LEASEQUERY_DONE => Self::LeaseQueryDone,
            DHCPV6_LEASEQUERY_DATA => Self::LeaseQueryData,
            DHCPV6_RECONFIGURE_REQUEST => Self::ReconfigureRequest,
            DHCPV6_RECONFIGURE_REPLY => Self::ReconfigureReply,
            DHCPV6_DHCPV4_QUERY => Self::Dhcpv4Query,
            DHCPV6_DHCPV4_RESPONSE => Self::Dhcpv4Response,
            DHCPV6_ACTIVE_LEASEQUERY => Self::ActiveLeaseQuery,
            DHCPV6_STARTTLS => Self::StartTls,
            DHCPV6_BNDUPD => Self::BndUpd,
            DHCPV6_BNDREPLY => Self::BndReply,
            DHCPV6_POOLREQ => Self::PoolReq,
            DHCPV6_POOLRESP => Self::PoolResp,
            DHCPV6_UPDREQ => Self::UpdReq,
            DHCPV6_UPDREQALL => Self::UpdReqAll,
            DHCPV6_UPDDONE => Self::UpdDone,
            DHCPV6_CONNECT => Self::Connect,
            DHCPV6_CONNECTREPLY => Self::ConnectReply,
            DHCPV6_DISCONNECT => Self::Disconnect,
            DHCPV6_STATE => Self::State,
            DHCPV6_CONTACT => Self::Contact,
            DHCPV6_ADDR_REG_INFORM => Self::AddrRegInform,
            DHCPV6_ADDR_REG_REPLY => Self::AddrRegReply,
            value => Self::Unknown(value),
        }
    }

    /// Wire value.
    pub const fn code(self) -> u8 {
        match self {
            Self::Solicit => DHCPV6_SOLICIT,
            Self::Advertise => DHCPV6_ADVERTISE,
            Self::Request => DHCPV6_REQUEST,
            Self::Confirm => DHCPV6_CONFIRM,
            Self::Renew => DHCPV6_RENEW,
            Self::Rebind => DHCPV6_REBIND,
            Self::Reply => DHCPV6_REPLY,
            Self::Release => DHCPV6_RELEASE,
            Self::Decline => DHCPV6_DECLINE,
            Self::Reconfigure => DHCPV6_RECONFIGURE,
            Self::InformationRequest => DHCPV6_INFORMATION_REQUEST,
            Self::RelayForw => DHCPV6_RELAY_FORW,
            Self::RelayRepl => DHCPV6_RELAY_REPL,
            Self::LeaseQuery => DHCPV6_LEASEQUERY,
            Self::LeaseQueryReply => DHCPV6_LEASEQUERY_REPLY,
            Self::LeaseQueryDone => DHCPV6_LEASEQUERY_DONE,
            Self::LeaseQueryData => DHCPV6_LEASEQUERY_DATA,
            Self::ReconfigureRequest => DHCPV6_RECONFIGURE_REQUEST,
            Self::ReconfigureReply => DHCPV6_RECONFIGURE_REPLY,
            Self::Dhcpv4Query => DHCPV6_DHCPV4_QUERY,
            Self::Dhcpv4Response => DHCPV6_DHCPV4_RESPONSE,
            Self::ActiveLeaseQuery => DHCPV6_ACTIVE_LEASEQUERY,
            Self::StartTls => DHCPV6_STARTTLS,
            Self::BndUpd => DHCPV6_BNDUPD,
            Self::BndReply => DHCPV6_BNDREPLY,
            Self::PoolReq => DHCPV6_POOLREQ,
            Self::PoolResp => DHCPV6_POOLRESP,
            Self::UpdReq => DHCPV6_UPDREQ,
            Self::UpdReqAll => DHCPV6_UPDREQALL,
            Self::UpdDone => DHCPV6_UPDDONE,
            Self::Connect => DHCPV6_CONNECT,
            Self::ConnectReply => DHCPV6_CONNECTREPLY,
            Self::Disconnect => DHCPV6_DISCONNECT,
            Self::State => DHCPV6_STATE,
            Self::Contact => DHCPV6_CONTACT,
            Self::AddrRegInform => DHCPV6_ADDR_REG_INFORM,
            Self::AddrRegReply => DHCPV6_ADDR_REG_REPLY,
            Self::Unknown(value) => value,
        }
    }
}

impl From<Dhcpv6MessageType> for u8 {
    fn from(value: Dhcpv6MessageType) -> Self {
        value.code()
    }
}

/// Every registered DHCPv6 message type, in IANA codepoint order.
///
/// Source: IANA "DHCPv6 Message Types" registry, values 1 through 37.
#[cfg(test)]
pub(crate) const REGISTERED_DHCPV6_MESSAGE_TYPES: [Dhcpv6MessageType; 37] = [
    Dhcpv6MessageType::Solicit,
    Dhcpv6MessageType::Advertise,
    Dhcpv6MessageType::Request,
    Dhcpv6MessageType::Confirm,
    Dhcpv6MessageType::Renew,
    Dhcpv6MessageType::Rebind,
    Dhcpv6MessageType::Reply,
    Dhcpv6MessageType::Release,
    Dhcpv6MessageType::Decline,
    Dhcpv6MessageType::Reconfigure,
    Dhcpv6MessageType::InformationRequest,
    Dhcpv6MessageType::RelayForw,
    Dhcpv6MessageType::RelayRepl,
    Dhcpv6MessageType::LeaseQuery,
    Dhcpv6MessageType::LeaseQueryReply,
    Dhcpv6MessageType::LeaseQueryDone,
    Dhcpv6MessageType::LeaseQueryData,
    Dhcpv6MessageType::ReconfigureRequest,
    Dhcpv6MessageType::ReconfigureReply,
    Dhcpv6MessageType::Dhcpv4Query,
    Dhcpv6MessageType::Dhcpv4Response,
    Dhcpv6MessageType::ActiveLeaseQuery,
    Dhcpv6MessageType::StartTls,
    Dhcpv6MessageType::BndUpd,
    Dhcpv6MessageType::BndReply,
    Dhcpv6MessageType::PoolReq,
    Dhcpv6MessageType::PoolResp,
    Dhcpv6MessageType::UpdReq,
    Dhcpv6MessageType::UpdReqAll,
    Dhcpv6MessageType::UpdDone,
    Dhcpv6MessageType::Connect,
    Dhcpv6MessageType::ConnectReply,
    Dhcpv6MessageType::Disconnect,
    Dhcpv6MessageType::State,
    Dhcpv6MessageType::Contact,
    Dhcpv6MessageType::AddrRegInform,
    Dhcpv6MessageType::AddrRegReply,
];

/// Human-readable summary label for a DHCPv6 message type.
pub fn dhcpv6_message_type_summary(message_type: Dhcpv6MessageType) -> String {
    match message_type {
        Dhcpv6MessageType::Solicit => "solicit".to_string(),
        Dhcpv6MessageType::Advertise => "advertise".to_string(),
        Dhcpv6MessageType::Request => "request".to_string(),
        Dhcpv6MessageType::Confirm => "confirm".to_string(),
        Dhcpv6MessageType::Renew => "renew".to_string(),
        Dhcpv6MessageType::Rebind => "rebind".to_string(),
        Dhcpv6MessageType::Reply => "reply".to_string(),
        Dhcpv6MessageType::Release => "release".to_string(),
        Dhcpv6MessageType::Decline => "decline".to_string(),
        Dhcpv6MessageType::Reconfigure => "reconfigure".to_string(),
        Dhcpv6MessageType::InformationRequest => "information-request".to_string(),
        Dhcpv6MessageType::RelayForw => "relay-forw".to_string(),
        Dhcpv6MessageType::RelayRepl => "relay-repl".to_string(),
        Dhcpv6MessageType::LeaseQuery => "leasequery".to_string(),
        Dhcpv6MessageType::LeaseQueryReply => "leasequery-reply".to_string(),
        Dhcpv6MessageType::LeaseQueryDone => "leasequery-done".to_string(),
        Dhcpv6MessageType::LeaseQueryData => "leasequery-data".to_string(),
        Dhcpv6MessageType::ReconfigureRequest => "reconfigure-request".to_string(),
        Dhcpv6MessageType::ReconfigureReply => "reconfigure-reply".to_string(),
        Dhcpv6MessageType::Dhcpv4Query => "dhcpv4-query".to_string(),
        Dhcpv6MessageType::Dhcpv4Response => "dhcpv4-response".to_string(),
        Dhcpv6MessageType::ActiveLeaseQuery => "activeleasequery".to_string(),
        Dhcpv6MessageType::StartTls => "starttls".to_string(),
        Dhcpv6MessageType::BndUpd => "bndupd".to_string(),
        Dhcpv6MessageType::BndReply => "bndreply".to_string(),
        Dhcpv6MessageType::PoolReq => "poolreq".to_string(),
        Dhcpv6MessageType::PoolResp => "poolresp".to_string(),
        Dhcpv6MessageType::UpdReq => "updreq".to_string(),
        Dhcpv6MessageType::UpdReqAll => "updreqall".to_string(),
        Dhcpv6MessageType::UpdDone => "upddone".to_string(),
        Dhcpv6MessageType::Connect => "connect".to_string(),
        Dhcpv6MessageType::ConnectReply => "connectreply".to_string(),
        Dhcpv6MessageType::Disconnect => "disconnect".to_string(),
        Dhcpv6MessageType::State => "state".to_string(),
        Dhcpv6MessageType::Contact => "contact".to_string(),
        Dhcpv6MessageType::AddrRegInform => "addr-reg-inform".to_string(),
        Dhcpv6MessageType::AddrRegReply => "addr-reg-reply".to_string(),
        Dhcpv6MessageType::Unknown(value) => format!("unknown({value})"),
    }
}

#[cfg(test)]
mod dhcpv6_message_type_tests {
    use super::super::constants::{dhcpv6_message_type_status, Dhcpv6MessageTypeStatus};
    use super::{dhcpv6_message_type_summary, Dhcpv6MessageType, REGISTERED_DHCPV6_MESSAGE_TYPES};

    const REGISTERED_CODES: [u8; 37] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
    ];

    #[test]
    fn dhcpv6_message_type_registry_is_complete() {
        assert_eq!(
            REGISTERED_DHCPV6_MESSAGE_TYPES.len(),
            REGISTERED_CODES.len(),
            "registered message type table must cover every IANA codepoint",
        );

        for (message_type, expected_code) in REGISTERED_DHCPV6_MESSAGE_TYPES
            .into_iter()
            .zip(REGISTERED_CODES)
        {
            assert_eq!(
                message_type.code(),
                expected_code,
                "{message_type:?} must encode to its IANA codepoint",
            );
            assert_eq!(
                Dhcpv6MessageType::from_code(expected_code),
                message_type,
                "code {expected_code} must decode to {message_type:?}",
            );
            assert_eq!(u8::from(message_type), expected_code);
            assert_eq!(
                dhcpv6_message_type_status(expected_code),
                Dhcpv6MessageTypeStatus::Registered,
            );
            assert!(
                !matches!(message_type, Dhcpv6MessageType::Unknown(_)),
                "{message_type:?} is registered and must not be Unknown",
            );
        }
    }

    #[test]
    fn dhcpv6_message_type_unknown_values_roundtrip() {
        let registered: std::collections::HashSet<u8> = REGISTERED_DHCPV6_MESSAGE_TYPES
            .iter()
            .map(|message_type| message_type.code())
            .collect();

        for code in 0u8..=255 {
            let message_type = Dhcpv6MessageType::from_code(code);
            if registered.contains(&code) {
                assert!(!matches!(message_type, Dhcpv6MessageType::Unknown(_)));
                continue;
            }
            assert_eq!(message_type, Dhcpv6MessageType::Unknown(code));
            assert_eq!(message_type.code(), code);
            assert_eq!(u8::from(message_type), code);
        }
    }

    #[test]
    fn dhcpv6_message_type_advanced_families_are_packet_data() {
        let families = [
            (Dhcpv6MessageType::LeaseQuery, 14),
            (Dhcpv6MessageType::Dhcpv4Query, 20),
            (Dhcpv6MessageType::ActiveLeaseQuery, 22),
            (Dhcpv6MessageType::StartTls, 23),
            (Dhcpv6MessageType::BndUpd, 24),
            (Dhcpv6MessageType::AddrRegInform, 36),
        ];

        for (message_type, expected_code) in families {
            assert_eq!(message_type.code(), expected_code);
            assert_eq!(Dhcpv6MessageType::from_code(expected_code), message_type);
            assert_eq!(
                dhcpv6_message_type_status(expected_code),
                Dhcpv6MessageTypeStatus::Registered,
            );
        }
    }

    #[test]
    fn dhcpv6_message_type_summary_labels_are_stable() {
        assert_eq!(
            dhcpv6_message_type_summary(Dhcpv6MessageType::Solicit),
            "solicit"
        );
        assert_eq!(
            dhcpv6_message_type_summary(Dhcpv6MessageType::InformationRequest),
            "information-request"
        );
        assert_eq!(
            dhcpv6_message_type_summary(Dhcpv6MessageType::Dhcpv4Response),
            "dhcpv4-response"
        );
        assert_eq!(
            dhcpv6_message_type_summary(Dhcpv6MessageType::AddrRegReply),
            "addr-reg-reply"
        );
        assert_eq!(
            dhcpv6_message_type_summary(Dhcpv6MessageType::Unknown(200)),
            "unknown(200)"
        );
    }
}
