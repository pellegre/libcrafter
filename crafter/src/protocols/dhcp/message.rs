//! DHCP message type codepoints.
//!
//! Source: IANA BOOTP/DHCP Parameters registry, "DHCP Message Type 53 Values"
//! (registry last updated 2026-02-02). Codepoints 1-18 are defined by
//! RFC 2132 (1-8), RFC 3203 (9), RFC 4388 (10-13), RFC 6926 (14-15), and
//! RFC 7724 (16-18). Unknown values are preserved as `Unknown(u8)`.

use super::constants::{
    DHCP_ACK, DHCP_ACTIVE_LEASE_QUERY, DHCP_BULK_LEASE_QUERY, DHCP_DECLINE, DHCP_DISCOVER,
    DHCP_FORCE_RENEW, DHCP_INFORM, DHCP_LEASE_ACTIVE, DHCP_LEASE_QUERY, DHCP_LEASE_QUERY_DONE,
    DHCP_LEASE_QUERY_STATUS, DHCP_LEASE_UNASSIGNED, DHCP_LEASE_UNKNOWN, DHCP_NAK, DHCP_OFFER,
    DHCP_RELEASE, DHCP_REQUEST, DHCP_TLS,
};

/// DHCP message type (option 53 value).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpMessageType {
    /// DHCPDISCOVER (RFC 2132).
    Discover,
    /// DHCPOFFER (RFC 2132).
    Offer,
    /// DHCPREQUEST (RFC 2132).
    Request,
    /// DHCPDECLINE (RFC 2132).
    Decline,
    /// DHCPACK (RFC 2132).
    Ack,
    /// DHCPNAK (RFC 2132).
    Nak,
    /// DHCPRELEASE (RFC 2132).
    Release,
    /// DHCPINFORM (RFC 2132).
    Inform,
    /// DHCPFORCERENEW (RFC 3203).
    ForceRenew,
    /// DHCPLEASEQUERY (RFC 4388).
    LeaseQuery,
    /// DHCPLEASEUNASSIGNED (RFC 4388).
    LeaseUnassigned,
    /// DHCPLEASEUNKNOWN (RFC 4388).
    LeaseUnknown,
    /// DHCPLEASEACTIVE (RFC 4388).
    LeaseActive,
    /// DHCPBULKLEASEQUERY (RFC 6926).
    BulkLeaseQuery,
    /// DHCPLEASEQUERYDONE (RFC 6926).
    LeaseQueryDone,
    /// DHCPACTIVELEASEQUERY (RFC 7724).
    ActiveLeaseQuery,
    /// DHCPLEASEQUERYSTATUS (RFC 7724).
    LeaseQueryStatus,
    /// DHCPTLS (RFC 7724).
    DhcpTls,
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
            DHCP_FORCE_RENEW => Self::ForceRenew,
            DHCP_LEASE_QUERY => Self::LeaseQuery,
            DHCP_LEASE_UNASSIGNED => Self::LeaseUnassigned,
            DHCP_LEASE_UNKNOWN => Self::LeaseUnknown,
            DHCP_LEASE_ACTIVE => Self::LeaseActive,
            DHCP_BULK_LEASE_QUERY => Self::BulkLeaseQuery,
            DHCP_LEASE_QUERY_DONE => Self::LeaseQueryDone,
            DHCP_ACTIVE_LEASE_QUERY => Self::ActiveLeaseQuery,
            DHCP_LEASE_QUERY_STATUS => Self::LeaseQueryStatus,
            DHCP_TLS => Self::DhcpTls,
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
            Self::ForceRenew => DHCP_FORCE_RENEW,
            Self::LeaseQuery => DHCP_LEASE_QUERY,
            Self::LeaseUnassigned => DHCP_LEASE_UNASSIGNED,
            Self::LeaseUnknown => DHCP_LEASE_UNKNOWN,
            Self::LeaseActive => DHCP_LEASE_ACTIVE,
            Self::BulkLeaseQuery => DHCP_BULK_LEASE_QUERY,
            Self::LeaseQueryDone => DHCP_LEASE_QUERY_DONE,
            Self::ActiveLeaseQuery => DHCP_ACTIVE_LEASE_QUERY,
            Self::LeaseQueryStatus => DHCP_LEASE_QUERY_STATUS,
            Self::DhcpTls => DHCP_TLS,
            Self::Unknown(value) => value,
        }
    }
}

/// Every registered DHCPv4 message type, in IANA codepoint order.
///
/// Source: IANA "DHCP Message Type 53 Values" registry (updated 2026-02-02),
/// values 1 through 18. Used by tests to prove the enum covers the registry.
#[cfg(test)]
pub(crate) const REGISTERED_MESSAGE_TYPES: [DhcpMessageType; 18] = [
    DhcpMessageType::Discover,
    DhcpMessageType::Offer,
    DhcpMessageType::Request,
    DhcpMessageType::Decline,
    DhcpMessageType::Ack,
    DhcpMessageType::Nak,
    DhcpMessageType::Release,
    DhcpMessageType::Inform,
    DhcpMessageType::ForceRenew,
    DhcpMessageType::LeaseQuery,
    DhcpMessageType::LeaseUnassigned,
    DhcpMessageType::LeaseUnknown,
    DhcpMessageType::LeaseActive,
    DhcpMessageType::BulkLeaseQuery,
    DhcpMessageType::LeaseQueryDone,
    DhcpMessageType::ActiveLeaseQuery,
    DhcpMessageType::LeaseQueryStatus,
    DhcpMessageType::DhcpTls,
];

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
        DhcpMessageType::ForceRenew => "forcerenew".to_string(),
        DhcpMessageType::LeaseQuery => "leasequery".to_string(),
        DhcpMessageType::LeaseUnassigned => "leaseunassigned".to_string(),
        DhcpMessageType::LeaseUnknown => "leaseunknown".to_string(),
        DhcpMessageType::LeaseActive => "leaseactive".to_string(),
        DhcpMessageType::BulkLeaseQuery => "bulkleasequery".to_string(),
        DhcpMessageType::LeaseQueryDone => "leasequerydone".to_string(),
        DhcpMessageType::ActiveLeaseQuery => "activeleasequery".to_string(),
        DhcpMessageType::LeaseQueryStatus => "leasequerystatus".to_string(),
        DhcpMessageType::DhcpTls => "dhcptls".to_string(),
        DhcpMessageType::Unknown(value) => format!("unknown({value})"),
    }
}

#[cfg(test)]
mod message_type_tests {
    use super::{DhcpMessageType, REGISTERED_MESSAGE_TYPES};

    /// Expected IANA codepoints, mirroring the "DHCP Message Type 53 Values"
    /// registry (updated 2026-02-02): values 1..=18.
    const REGISTERED_CODES: [u8; 18] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    ];

    #[test]
    fn dhcp_message_type_registry_is_complete() {
        assert_eq!(
            REGISTERED_MESSAGE_TYPES.len(),
            REGISTERED_CODES.len(),
            "registered message type table must cover every IANA codepoint",
        );

        for (message_type, expected_code) in
            REGISTERED_MESSAGE_TYPES.into_iter().zip(REGISTERED_CODES)
        {
            // enum -> code
            assert_eq!(
                message_type.code(),
                expected_code,
                "{message_type:?} must encode to its IANA codepoint",
            );
            // code -> enum
            assert_eq!(
                DhcpMessageType::from_code(expected_code),
                message_type,
                "code {expected_code} must decode to {message_type:?}",
            );
            // u8 conversion mirrors code()
            assert_eq!(u8::from(message_type), expected_code);
            // never decode a registered codepoint as Unknown
            assert!(
                !matches!(message_type, DhcpMessageType::Unknown(_)),
                "{message_type:?} is a registered type and must not be Unknown",
            );
        }

        // The expected codepoints are exactly the contiguous range 1..=18.
        assert_eq!(
            REGISTERED_CODES,
            core::array::from_fn::<u8, 18, _>(|i| (i + 1) as u8)
        );
    }

    #[test]
    fn dhcp_message_type_unknown_values_roundtrip() {
        // 0 and 19..=255 are not registered DHCP message type values.
        let registered: std::collections::HashSet<u8> =
            REGISTERED_MESSAGE_TYPES.iter().map(|m| m.code()).collect();

        for code in 0u8..=255 {
            let message_type = DhcpMessageType::from_code(code);
            if registered.contains(&code) {
                assert!(!matches!(message_type, DhcpMessageType::Unknown(_)));
                continue;
            }
            assert_eq!(
                message_type,
                DhcpMessageType::Unknown(code),
                "unregistered code {code} must be preserved as Unknown",
            );
            // Unknown values round-trip code -> enum -> code without loss.
            assert_eq!(message_type.code(), code);
            assert_eq!(u8::from(message_type), code);
        }
    }

    #[test]
    fn dhcp_leasequery_message_types_roundtrip() {
        use super::super::Dhcp;

        // The leasequery message-type family is defined by RFC 4388 (codes
        // 10-13: DHCPLEASEQUERY, DHCPLEASEUNASSIGNED, DHCPLEASEUNKNOWN,
        // DHCPLEASEACTIVE), RFC 6926 (codes 14-15: DHCPBULKLEASEQUERY,
        // DHCPLEASEQUERYDONE), and RFC 7724 (codes 16-18: DHCPACTIVELEASEQUERY,
        // DHCPLEASEQUERYSTATUS, DHCPTLS). Each value carries through option 53 in
        // a full DHCP packet without loss, and pins to its IANA codepoint.
        let leasequery_family = [
            (DhcpMessageType::LeaseQuery, 10u8),
            (DhcpMessageType::LeaseUnassigned, 11),
            (DhcpMessageType::LeaseUnknown, 12),
            (DhcpMessageType::LeaseActive, 13),
            (DhcpMessageType::BulkLeaseQuery, 14),
            (DhcpMessageType::LeaseQueryDone, 15),
            (DhcpMessageType::ActiveLeaseQuery, 16),
            (DhcpMessageType::LeaseQueryStatus, 17),
            (DhcpMessageType::DhcpTls, 18),
        ];

        for (message_type, code) in leasequery_family {
            // enum <-> codepoint mapping is exact and never Unknown.
            assert_eq!(message_type.code(), code, "{message_type:?} codepoint");
            assert_eq!(DhcpMessageType::from_code(code), message_type);
            assert!(!matches!(message_type, DhcpMessageType::Unknown(_)));

            // The message type survives a full DHCP packet compile -> decode
            // cycle through option 53, and the bytes re-compile identically.
            let dhcp = Dhcp::new()
                .op(super::super::BOOTP_REPLY)
                .message_type(message_type);
            let bytes = crate::Packet::from_layer(dhcp)
                .compile()
                .unwrap()
                .as_bytes()
                .to_vec();
            let parsed = Dhcp::decode(&bytes).unwrap();
            assert_eq!(
                parsed.message_type_value(),
                Some(message_type),
                "code {code} must decode from option 53 in a full packet",
            );
            let recompiled = crate::Packet::from_layer(parsed)
                .compile()
                .unwrap()
                .as_bytes()
                .to_vec();
            assert_eq!(recompiled, bytes, "code {code} must re-compile identically");
        }
    }
}
