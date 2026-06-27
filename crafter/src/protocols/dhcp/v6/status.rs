//! DHCPv6 status code values.
//!
//! Source: IANA "DHCPv6 Status Codes" registry. Unknown and currently
//! unassigned codepoints are preserved as `Unknown(u16)`.

use core::fmt;

use super::constants::{
    DHCPV6_STATUS_ADDRESS_IN_USE, DHCPV6_STATUS_CATCH_UP_COMPLETE,
    DHCPV6_STATUS_CONFIGURATION_CONFLICT, DHCPV6_STATUS_DATA_MISSING,
    DHCPV6_STATUS_DNS_UPDATE_NOT_SUPPORTED, DHCPV6_STATUS_EXCESSIVE_TIME_SKEW,
    DHCPV6_STATUS_MALFORMED_QUERY, DHCPV6_STATUS_MISSING_BINDING_INFORMATION,
    DHCPV6_STATUS_NOT_ALLOWED, DHCPV6_STATUS_NOT_CONFIGURED, DHCPV6_STATUS_NOT_ON_LINK,
    DHCPV6_STATUS_NOT_SUPPORTED, DHCPV6_STATUS_NO_ADDRS_AVAIL, DHCPV6_STATUS_NO_BINDING,
    DHCPV6_STATUS_NO_PREFIX_AVAIL, DHCPV6_STATUS_NO_SRV6_LOCATOR_AVAIL,
    DHCPV6_STATUS_OUTDATED_BINDING_INFORMATION, DHCPV6_STATUS_QUERY_TERMINATED,
    DHCPV6_STATUS_SERVER_SHUTTING_DOWN, DHCPV6_STATUS_SUCCESS,
    DHCPV6_STATUS_TLS_CONNECTION_REFUSED, DHCPV6_STATUS_UNKNOWN_QUERY_TYPE,
    DHCPV6_STATUS_UNSPEC_FAIL, DHCPV6_STATUS_USE_MULTICAST,
};

/// DHCPv6 status code value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6StatusCode {
    /// Success (RFC 9915).
    Success,
    /// UnspecFail (RFC 9915).
    UnspecFail,
    /// NoAddrsAvail (RFC 9915).
    NoAddrsAvail,
    /// NoBinding (RFC 9915).
    NoBinding,
    /// NotOnLink (RFC 9915).
    NotOnLink,
    /// UseMulticast (obsolete, RFC 9915 registry row).
    UseMulticast,
    /// NoPrefixAvail (RFC 3633 / RFC 9915).
    NoPrefixAvail,
    /// UnknownQueryType (RFC 5007).
    UnknownQueryType,
    /// MalformedQuery (RFC 5007).
    MalformedQuery,
    /// NotConfigured (RFC 5007).
    NotConfigured,
    /// NotAllowed (RFC 5007).
    NotAllowed,
    /// QueryTerminated (RFC 5460).
    QueryTerminated,
    /// DataMissing (RFC 7653).
    DataMissing,
    /// CatchUpComplete (RFC 7653).
    CatchUpComplete,
    /// NotSupported (RFC 7653).
    NotSupported,
    /// TLSConnectionRefused (RFC 7653).
    TlsConnectionRefused,
    /// AddressInUse (RFC 8156).
    AddressInUse,
    /// ConfigurationConflict (RFC 8156).
    ConfigurationConflict,
    /// MissingBindingInformation (RFC 8156).
    MissingBindingInformation,
    /// OutdatedBindingInformation (RFC 8156).
    OutdatedBindingInformation,
    /// ServerShuttingDown (RFC 8156).
    ServerShuttingDown,
    /// DNSUpdateNotSupported (RFC 8156).
    DnsUpdateNotSupported,
    /// ExcessiveTimeSkew (RFC 8156).
    ExcessiveTimeSkew,
    /// NoSRv6LocatorAvail.
    NoSrv6LocatorAvail,
    /// Unknown or currently unassigned status code value preserved from decode.
    Unknown(u16),
}

impl Dhcpv6StatusCode {
    /// Create a DHCPv6 status code from its wire value.
    pub const fn from_code(code: u16) -> Self {
        match code {
            DHCPV6_STATUS_SUCCESS => Self::Success,
            DHCPV6_STATUS_UNSPEC_FAIL => Self::UnspecFail,
            DHCPV6_STATUS_NO_ADDRS_AVAIL => Self::NoAddrsAvail,
            DHCPV6_STATUS_NO_BINDING => Self::NoBinding,
            DHCPV6_STATUS_NOT_ON_LINK => Self::NotOnLink,
            DHCPV6_STATUS_USE_MULTICAST => Self::UseMulticast,
            DHCPV6_STATUS_NO_PREFIX_AVAIL => Self::NoPrefixAvail,
            DHCPV6_STATUS_UNKNOWN_QUERY_TYPE => Self::UnknownQueryType,
            DHCPV6_STATUS_MALFORMED_QUERY => Self::MalformedQuery,
            DHCPV6_STATUS_NOT_CONFIGURED => Self::NotConfigured,
            DHCPV6_STATUS_NOT_ALLOWED => Self::NotAllowed,
            DHCPV6_STATUS_QUERY_TERMINATED => Self::QueryTerminated,
            DHCPV6_STATUS_DATA_MISSING => Self::DataMissing,
            DHCPV6_STATUS_CATCH_UP_COMPLETE => Self::CatchUpComplete,
            DHCPV6_STATUS_NOT_SUPPORTED => Self::NotSupported,
            DHCPV6_STATUS_TLS_CONNECTION_REFUSED => Self::TlsConnectionRefused,
            DHCPV6_STATUS_ADDRESS_IN_USE => Self::AddressInUse,
            DHCPV6_STATUS_CONFIGURATION_CONFLICT => Self::ConfigurationConflict,
            DHCPV6_STATUS_MISSING_BINDING_INFORMATION => Self::MissingBindingInformation,
            DHCPV6_STATUS_OUTDATED_BINDING_INFORMATION => Self::OutdatedBindingInformation,
            DHCPV6_STATUS_SERVER_SHUTTING_DOWN => Self::ServerShuttingDown,
            DHCPV6_STATUS_DNS_UPDATE_NOT_SUPPORTED => Self::DnsUpdateNotSupported,
            DHCPV6_STATUS_EXCESSIVE_TIME_SKEW => Self::ExcessiveTimeSkew,
            DHCPV6_STATUS_NO_SRV6_LOCATOR_AVAIL => Self::NoSrv6LocatorAvail,
            value => Self::Unknown(value),
        }
    }

    /// Wire value.
    pub const fn code(self) -> u16 {
        match self {
            Self::Success => DHCPV6_STATUS_SUCCESS,
            Self::UnspecFail => DHCPV6_STATUS_UNSPEC_FAIL,
            Self::NoAddrsAvail => DHCPV6_STATUS_NO_ADDRS_AVAIL,
            Self::NoBinding => DHCPV6_STATUS_NO_BINDING,
            Self::NotOnLink => DHCPV6_STATUS_NOT_ON_LINK,
            Self::UseMulticast => DHCPV6_STATUS_USE_MULTICAST,
            Self::NoPrefixAvail => DHCPV6_STATUS_NO_PREFIX_AVAIL,
            Self::UnknownQueryType => DHCPV6_STATUS_UNKNOWN_QUERY_TYPE,
            Self::MalformedQuery => DHCPV6_STATUS_MALFORMED_QUERY,
            Self::NotConfigured => DHCPV6_STATUS_NOT_CONFIGURED,
            Self::NotAllowed => DHCPV6_STATUS_NOT_ALLOWED,
            Self::QueryTerminated => DHCPV6_STATUS_QUERY_TERMINATED,
            Self::DataMissing => DHCPV6_STATUS_DATA_MISSING,
            Self::CatchUpComplete => DHCPV6_STATUS_CATCH_UP_COMPLETE,
            Self::NotSupported => DHCPV6_STATUS_NOT_SUPPORTED,
            Self::TlsConnectionRefused => DHCPV6_STATUS_TLS_CONNECTION_REFUSED,
            Self::AddressInUse => DHCPV6_STATUS_ADDRESS_IN_USE,
            Self::ConfigurationConflict => DHCPV6_STATUS_CONFIGURATION_CONFLICT,
            Self::MissingBindingInformation => DHCPV6_STATUS_MISSING_BINDING_INFORMATION,
            Self::OutdatedBindingInformation => DHCPV6_STATUS_OUTDATED_BINDING_INFORMATION,
            Self::ServerShuttingDown => DHCPV6_STATUS_SERVER_SHUTTING_DOWN,
            Self::DnsUpdateNotSupported => DHCPV6_STATUS_DNS_UPDATE_NOT_SUPPORTED,
            Self::ExcessiveTimeSkew => DHCPV6_STATUS_EXCESSIVE_TIME_SKEW,
            Self::NoSrv6LocatorAvail => DHCPV6_STATUS_NO_SRV6_LOCATOR_AVAIL,
            Self::Unknown(value) => value,
        }
    }

    /// Registered status-code label, when the status is known.
    pub const fn registered_label(self) -> Option<&'static str> {
        match self {
            Self::Success => Some("Success"),
            Self::UnspecFail => Some("UnspecFail"),
            Self::NoAddrsAvail => Some("NoAddrsAvail"),
            Self::NoBinding => Some("NoBinding"),
            Self::NotOnLink => Some("NotOnLink"),
            Self::UseMulticast => Some("UseMulticast"),
            Self::NoPrefixAvail => Some("NoPrefixAvail"),
            Self::UnknownQueryType => Some("UnknownQueryType"),
            Self::MalformedQuery => Some("MalformedQuery"),
            Self::NotConfigured => Some("NotConfigured"),
            Self::NotAllowed => Some("NotAllowed"),
            Self::QueryTerminated => Some("QueryTerminated"),
            Self::DataMissing => Some("DataMissing"),
            Self::CatchUpComplete => Some("CatchUpComplete"),
            Self::NotSupported => Some("NotSupported"),
            Self::TlsConnectionRefused => Some("TLSConnectionRefused"),
            Self::AddressInUse => Some("AddressInUse"),
            Self::ConfigurationConflict => Some("ConfigurationConflict"),
            Self::MissingBindingInformation => Some("MissingBindingInformation"),
            Self::OutdatedBindingInformation => Some("OutdatedBindingInformation"),
            Self::ServerShuttingDown => Some("ServerShuttingDown"),
            Self::DnsUpdateNotSupported => Some("DNSUpdateNotSupported"),
            Self::ExcessiveTimeSkew => Some("ExcessiveTimeSkew"),
            Self::NoSrv6LocatorAvail => Some("NoSRv6LocatorAvail"),
            Self::Unknown(_) => None,
        }
    }
}

impl From<Dhcpv6StatusCode> for u16 {
    fn from(value: Dhcpv6StatusCode) -> Self {
        value.code()
    }
}

impl fmt::Display for Dhcpv6StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.registered_label() {
            Some(label) => f.write_str(label),
            None => write!(f, "Unknown({})", self.code()),
        }
    }
}

/// Every registered DHCPv6 status code, in IANA codepoint order.
///
/// Source: IANA "DHCPv6 Status Codes" registry, values 0 through 23.
#[cfg(test)]
pub(crate) const REGISTERED_DHCPV6_STATUS_CODES: [Dhcpv6StatusCode; 24] = [
    Dhcpv6StatusCode::Success,
    Dhcpv6StatusCode::UnspecFail,
    Dhcpv6StatusCode::NoAddrsAvail,
    Dhcpv6StatusCode::NoBinding,
    Dhcpv6StatusCode::NotOnLink,
    Dhcpv6StatusCode::UseMulticast,
    Dhcpv6StatusCode::NoPrefixAvail,
    Dhcpv6StatusCode::UnknownQueryType,
    Dhcpv6StatusCode::MalformedQuery,
    Dhcpv6StatusCode::NotConfigured,
    Dhcpv6StatusCode::NotAllowed,
    Dhcpv6StatusCode::QueryTerminated,
    Dhcpv6StatusCode::DataMissing,
    Dhcpv6StatusCode::CatchUpComplete,
    Dhcpv6StatusCode::NotSupported,
    Dhcpv6StatusCode::TlsConnectionRefused,
    Dhcpv6StatusCode::AddressInUse,
    Dhcpv6StatusCode::ConfigurationConflict,
    Dhcpv6StatusCode::MissingBindingInformation,
    Dhcpv6StatusCode::OutdatedBindingInformation,
    Dhcpv6StatusCode::ServerShuttingDown,
    Dhcpv6StatusCode::DnsUpdateNotSupported,
    Dhcpv6StatusCode::ExcessiveTimeSkew,
    Dhcpv6StatusCode::NoSrv6LocatorAvail,
];

/// Human-readable label for a DHCPv6 status code.
pub fn dhcpv6_status_code_label(status: Dhcpv6StatusCode) -> String {
    status.to_string()
}

#[cfg(test)]
mod dhcpv6_status_code_tests {
    use super::super::constants::{
        dhcpv6_status_code_meta, dhcpv6_status_code_name, dhcpv6_status_code_status,
        Dhcpv6StatusCodeStatus, DHCPV6_STATUS_UNASSIGNED_START, DHCPV6_STATUS_USE_MULTICAST,
    };
    use super::{dhcpv6_status_code_label, Dhcpv6StatusCode, REGISTERED_DHCPV6_STATUS_CODES};

    const REGISTERED_CODES: [u16; 24] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    ];

    #[test]
    fn dhcpv6_status_code_registry_is_complete() {
        assert_eq!(
            REGISTERED_DHCPV6_STATUS_CODES.len(),
            REGISTERED_CODES.len(),
            "registered status code table must cover every IANA codepoint",
        );

        for (status, expected_code) in REGISTERED_DHCPV6_STATUS_CODES
            .into_iter()
            .zip(REGISTERED_CODES)
        {
            assert_eq!(
                status.code(),
                expected_code,
                "{status:?} must encode to its IANA codepoint",
            );
            assert_eq!(
                Dhcpv6StatusCode::from_code(expected_code),
                status,
                "code {expected_code} must decode to {status:?}",
            );
            assert_eq!(u16::from(status), expected_code);
            assert_eq!(
                dhcpv6_status_code_name(expected_code),
                status.registered_label(),
            );
            assert!(!matches!(status, Dhcpv6StatusCode::Unknown(_)));
        }
    }

    #[test]
    fn dhcpv6_status_code_unknown_values_roundtrip() {
        let registered: std::collections::HashSet<u16> = REGISTERED_DHCPV6_STATUS_CODES
            .iter()
            .map(|status| status.code())
            .collect();

        for code in 0u16..=u16::MAX {
            let status = Dhcpv6StatusCode::from_code(code);
            if registered.contains(&code) {
                assert!(!matches!(status, Dhcpv6StatusCode::Unknown(_)));
                continue;
            }
            assert_eq!(status, Dhcpv6StatusCode::Unknown(code));
            assert_eq!(status.code(), code);
            assert_eq!(u16::from(status), code);
            assert_eq!(status.registered_label(), None);
        }
    }

    #[test]
    fn dhcpv6_status_code_registry_metadata_preserves_obsolete_and_unassigned() {
        let obsolete = dhcpv6_status_code_meta(DHCPV6_STATUS_USE_MULTICAST);
        assert_eq!(obsolete.name, "UseMulticast");
        assert_eq!(obsolete.status, Dhcpv6StatusCodeStatus::Obsolete);
        assert_eq!(
            Dhcpv6StatusCode::from_code(DHCPV6_STATUS_USE_MULTICAST),
            Dhcpv6StatusCode::UseMulticast,
        );

        let unassigned = dhcpv6_status_code_meta(DHCPV6_STATUS_UNASSIGNED_START);
        assert_eq!(unassigned.name, "Unassigned");
        assert_eq!(unassigned.status, Dhcpv6StatusCodeStatus::Unassigned);
        assert_eq!(
            dhcpv6_status_code_status(DHCPV6_STATUS_UNASSIGNED_START),
            Dhcpv6StatusCodeStatus::Unassigned,
        );
    }

    #[test]
    fn dhcpv6_status_code_labels_are_display_only() {
        assert_eq!(
            dhcpv6_status_code_label(Dhcpv6StatusCode::NoAddrsAvail),
            "NoAddrsAvail",
        );
        assert_eq!(
            dhcpv6_status_code_label(Dhcpv6StatusCode::TlsConnectionRefused),
            "TLSConnectionRefused",
        );
        assert_eq!(
            dhcpv6_status_code_label(Dhcpv6StatusCode::NoSrv6LocatorAvail),
            "NoSRv6LocatorAvail",
        );
        assert_eq!(
            dhcpv6_status_code_label(Dhcpv6StatusCode::Unknown(65000)),
            "Unknown(65000)",
        );
    }
}
