//! DHCP message type codepoints.
//!
//! Source: IANA BOOTP/DHCP Parameters registry, "DHCP Message Type 53 Values"
//! (registry last updated 2026-02-02). Codepoints 1-18 are defined by
//! RFC 2132 (1-8), RFC 3203 (9), RFC 4388 (10-13), RFC 6926 (14-15), and
//! RFC 7724 (16-18). Unknown values are preserved as `Unknown(u8)`.

use super::constants::{
    DHCPV4_ACK, DHCPV4_ACTIVE_LEASE_QUERY, DHCPV4_BULK_LEASE_QUERY, DHCPV4_DECLINE,
    DHCPV4_DISCOVER, DHCPV4_FORCE_RENEW, DHCPV4_INFORM, DHCPV4_LEASE_ACTIVE, DHCPV4_LEASE_QUERY,
    DHCPV4_LEASE_QUERY_DONE, DHCPV4_LEASE_QUERY_STATUS, DHCPV4_LEASE_UNASSIGNED,
    DHCPV4_LEASE_UNKNOWN, DHCPV4_NAK, DHCPV4_OFFER, DHCPV4_RELEASE, DHCPV4_REQUEST, DHCPV4_TLS,
};

/// DHCP message type (option 53 value).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv4MessageType {
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
    Dhcpv4Tls,
    /// Unknown message type value preserved from decode.
    Unknown(u8),
}

impl Dhcpv4MessageType {
    /// Create a DHCP message type from its wire value.
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCPV4_DISCOVER => Self::Discover,
            DHCPV4_OFFER => Self::Offer,
            DHCPV4_REQUEST => Self::Request,
            DHCPV4_DECLINE => Self::Decline,
            DHCPV4_ACK => Self::Ack,
            DHCPV4_NAK => Self::Nak,
            DHCPV4_RELEASE => Self::Release,
            DHCPV4_INFORM => Self::Inform,
            DHCPV4_FORCE_RENEW => Self::ForceRenew,
            DHCPV4_LEASE_QUERY => Self::LeaseQuery,
            DHCPV4_LEASE_UNASSIGNED => Self::LeaseUnassigned,
            DHCPV4_LEASE_UNKNOWN => Self::LeaseUnknown,
            DHCPV4_LEASE_ACTIVE => Self::LeaseActive,
            DHCPV4_BULK_LEASE_QUERY => Self::BulkLeaseQuery,
            DHCPV4_LEASE_QUERY_DONE => Self::LeaseQueryDone,
            DHCPV4_ACTIVE_LEASE_QUERY => Self::ActiveLeaseQuery,
            DHCPV4_LEASE_QUERY_STATUS => Self::LeaseQueryStatus,
            DHCPV4_TLS => Self::Dhcpv4Tls,
            value => Self::Unknown(value),
        }
    }

    /// Wire value.
    pub const fn code(self) -> u8 {
        match self {
            Self::Discover => DHCPV4_DISCOVER,
            Self::Offer => DHCPV4_OFFER,
            Self::Request => DHCPV4_REQUEST,
            Self::Decline => DHCPV4_DECLINE,
            Self::Ack => DHCPV4_ACK,
            Self::Nak => DHCPV4_NAK,
            Self::Release => DHCPV4_RELEASE,
            Self::Inform => DHCPV4_INFORM,
            Self::ForceRenew => DHCPV4_FORCE_RENEW,
            Self::LeaseQuery => DHCPV4_LEASE_QUERY,
            Self::LeaseUnassigned => DHCPV4_LEASE_UNASSIGNED,
            Self::LeaseUnknown => DHCPV4_LEASE_UNKNOWN,
            Self::LeaseActive => DHCPV4_LEASE_ACTIVE,
            Self::BulkLeaseQuery => DHCPV4_BULK_LEASE_QUERY,
            Self::LeaseQueryDone => DHCPV4_LEASE_QUERY_DONE,
            Self::ActiveLeaseQuery => DHCPV4_ACTIVE_LEASE_QUERY,
            Self::LeaseQueryStatus => DHCPV4_LEASE_QUERY_STATUS,
            Self::Dhcpv4Tls => DHCPV4_TLS,
            Self::Unknown(value) => value,
        }
    }
}

/// Every registered DHCPv4 message type, in IANA codepoint order.
///
/// Source: IANA "DHCP Message Type 53 Values" registry (updated 2026-02-02),
/// values 1 through 18. Used by tests to prove the enum covers the registry.
#[cfg(test)]
pub(crate) const REGISTERED_DHCPV4_MESSAGE_TYPES: [Dhcpv4MessageType; 18] = [
    Dhcpv4MessageType::Discover,
    Dhcpv4MessageType::Offer,
    Dhcpv4MessageType::Request,
    Dhcpv4MessageType::Decline,
    Dhcpv4MessageType::Ack,
    Dhcpv4MessageType::Nak,
    Dhcpv4MessageType::Release,
    Dhcpv4MessageType::Inform,
    Dhcpv4MessageType::ForceRenew,
    Dhcpv4MessageType::LeaseQuery,
    Dhcpv4MessageType::LeaseUnassigned,
    Dhcpv4MessageType::LeaseUnknown,
    Dhcpv4MessageType::LeaseActive,
    Dhcpv4MessageType::BulkLeaseQuery,
    Dhcpv4MessageType::LeaseQueryDone,
    Dhcpv4MessageType::ActiveLeaseQuery,
    Dhcpv4MessageType::LeaseQueryStatus,
    Dhcpv4MessageType::Dhcpv4Tls,
];

impl From<Dhcpv4MessageType> for u8 {
    fn from(value: Dhcpv4MessageType) -> Self {
        value.code()
    }
}

/// Human-readable summary label for a DHCP message type.
pub(crate) fn dhcpv4_message_type_summary(message_type: Dhcpv4MessageType) -> String {
    match message_type {
        Dhcpv4MessageType::Discover => "discover".to_string(),
        Dhcpv4MessageType::Offer => "offer".to_string(),
        Dhcpv4MessageType::Request => "request".to_string(),
        Dhcpv4MessageType::Decline => "decline".to_string(),
        Dhcpv4MessageType::Ack => "ack".to_string(),
        Dhcpv4MessageType::Nak => "nak".to_string(),
        Dhcpv4MessageType::Release => "release".to_string(),
        Dhcpv4MessageType::Inform => "inform".to_string(),
        Dhcpv4MessageType::ForceRenew => "forcerenew".to_string(),
        Dhcpv4MessageType::LeaseQuery => "leasequery".to_string(),
        Dhcpv4MessageType::LeaseUnassigned => "leaseunassigned".to_string(),
        Dhcpv4MessageType::LeaseUnknown => "leaseunknown".to_string(),
        Dhcpv4MessageType::LeaseActive => "leaseactive".to_string(),
        Dhcpv4MessageType::BulkLeaseQuery => "bulkleasequery".to_string(),
        Dhcpv4MessageType::LeaseQueryDone => "leasequerydone".to_string(),
        Dhcpv4MessageType::ActiveLeaseQuery => "activeleasequery".to_string(),
        Dhcpv4MessageType::LeaseQueryStatus => "leasequerystatus".to_string(),
        Dhcpv4MessageType::Dhcpv4Tls => "dhcptls".to_string(),
        Dhcpv4MessageType::Unknown(value) => format!("unknown({value})"),
    }
}

#[cfg(test)]
mod message_type_tests {
    use super::{Dhcpv4MessageType, REGISTERED_DHCPV4_MESSAGE_TYPES};

    /// Expected IANA codepoints, mirroring the "DHCP Message Type 53 Values"
    /// registry (updated 2026-02-02): values 1..=18.
    const REGISTERED_CODES: [u8; 18] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    ];

    #[test]
    fn dhcpv4_message_type_registry_is_complete() {
        assert_eq!(
            REGISTERED_DHCPV4_MESSAGE_TYPES.len(),
            REGISTERED_CODES.len(),
            "registered message type table must cover every IANA codepoint",
        );

        for (message_type, expected_code) in REGISTERED_DHCPV4_MESSAGE_TYPES
            .into_iter()
            .zip(REGISTERED_CODES)
        {
            // enum -> code
            assert_eq!(
                message_type.code(),
                expected_code,
                "{message_type:?} must encode to its IANA codepoint",
            );
            // code -> enum
            assert_eq!(
                Dhcpv4MessageType::from_code(expected_code),
                message_type,
                "code {expected_code} must decode to {message_type:?}",
            );
            // u8 conversion mirrors code()
            assert_eq!(u8::from(message_type), expected_code);
            // never decode a registered codepoint as Unknown
            assert!(
                !matches!(message_type, Dhcpv4MessageType::Unknown(_)),
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
    fn dhcpv4_message_type_unknown_values_roundtrip() {
        // 0 and 19..=255 are not registered DHCP message type values.
        let registered: std::collections::HashSet<u8> = REGISTERED_DHCPV4_MESSAGE_TYPES
            .iter()
            .map(|m| m.code())
            .collect();

        for code in 0u8..=255 {
            let message_type = Dhcpv4MessageType::from_code(code);
            if registered.contains(&code) {
                assert!(!matches!(message_type, Dhcpv4MessageType::Unknown(_)));
                continue;
            }
            assert_eq!(
                message_type,
                Dhcpv4MessageType::Unknown(code),
                "unregistered code {code} must be preserved as Unknown",
            );
            // Unknown values round-trip code -> enum -> code without loss.
            assert_eq!(message_type.code(), code);
            assert_eq!(u8::from(message_type), code);
        }
    }

    #[test]
    fn dhcpv4_leasequery_message_types_roundtrip() {
        use super::super::Dhcpv4;

        // The leasequery message-type family is defined by RFC 4388 (codes
        // 10-13: DHCPLEASEQUERY, DHCPLEASEUNASSIGNED, DHCPLEASEUNKNOWN,
        // DHCPLEASEACTIVE), RFC 6926 (codes 14-15: DHCPBULKLEASEQUERY,
        // DHCPLEASEQUERYDONE), and RFC 7724 (codes 16-18: DHCPACTIVELEASEQUERY,
        // DHCPLEASEQUERYSTATUS, DHCPTLS). Each value carries through option 53 in
        // a full DHCPv4 packet without loss, and pins to its IANA codepoint.
        let leasequery_family = [
            (Dhcpv4MessageType::LeaseQuery, 10u8),
            (Dhcpv4MessageType::LeaseUnassigned, 11),
            (Dhcpv4MessageType::LeaseUnknown, 12),
            (Dhcpv4MessageType::LeaseActive, 13),
            (Dhcpv4MessageType::BulkLeaseQuery, 14),
            (Dhcpv4MessageType::LeaseQueryDone, 15),
            (Dhcpv4MessageType::ActiveLeaseQuery, 16),
            (Dhcpv4MessageType::LeaseQueryStatus, 17),
            (Dhcpv4MessageType::Dhcpv4Tls, 18),
        ];

        for (message_type, code) in leasequery_family {
            // enum <-> codepoint mapping is exact and never Unknown.
            assert_eq!(message_type.code(), code, "{message_type:?} codepoint");
            assert_eq!(Dhcpv4MessageType::from_code(code), message_type);
            assert!(!matches!(message_type, Dhcpv4MessageType::Unknown(_)));

            // The message type survives a full DHCPv4 packet compile -> decode
            // cycle through option 53, and the bytes re-compile identically.
            let dhcpv4 = Dhcpv4::new()
                .op(super::super::BOOTP_REPLY)
                .message_type(message_type);
            let bytes = crate::Packet::from_layer(dhcpv4)
                .compile()
                .unwrap()
                .as_bytes()
                .to_vec();
            let parsed = Dhcpv4::decode(&bytes).unwrap();
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

    #[test]
    fn dhcpv4_message_type_matrix_full_packet_roundtrip() {
        use super::super::Dhcpv4;

        // Every implemented Dhcpv4MessageType (the full IANA option-53 matrix,
        // codes 1..=18: RFC 2132 1-8, RFC 3203 9, RFC 4388 10-13, RFC 6926
        // 14-15, RFC 7724 16-18) must encode, decode, and re-encode through a
        // full DHCPv4 packet without loss. This test is named so the
        // `dhcpv4_message` filter covers the complete matrix, not just the
        // RFC 2132 base types.
        for message_type in REGISTERED_DHCPV4_MESSAGE_TYPES {
            // The opcode does not affect the option-53 round-trip; BOOTREPLY is
            // a valid carrier for both request- and reply-side message types.
            let dhcpv4 = Dhcpv4::new()
                .op(super::super::BOOTP_REPLY)
                .message_type(message_type);
            let bytes = crate::Packet::from_layer(dhcpv4)
                .compile()
                .unwrap()
                .as_bytes()
                .to_vec();

            let parsed = Dhcpv4::decode(&bytes).unwrap();
            assert_eq!(
                parsed.message_type_value(),
                Some(message_type),
                "{message_type:?} must survive option-53 decode in a full packet",
            );
            // A registered type must never normalize into Unknown.
            assert!(
                !matches!(
                    parsed.message_type_value(),
                    Some(Dhcpv4MessageType::Unknown(_))
                ),
                "{message_type:?} must decode to a registered type, not Unknown",
            );

            let recompiled = crate::Packet::from_layer(parsed)
                .compile()
                .unwrap()
                .as_bytes()
                .to_vec();
            assert_eq!(
                recompiled, bytes,
                "{message_type:?} must re-encode to identical bytes",
            );
        }
    }
}
