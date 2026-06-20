//! IGMP registry metadata.
//!
//! This module is metadata only: it names and classifies source-backed IGMP
//! type/code values without deciding whether a decoder accepts a typed body.
//! Unsupported-but-registered values remain valid byte values that later decode
//! steps can preserve as raw payloads.

use super::constants::{
    IGMP_QUERY_CODE_MAX_RESPONSE_FIRST, IGMP_QUERY_CODE_MAX_RESPONSE_LAST, IGMP_QUERY_CODE_V1,
    IGMP_TYPE_CISCO_TRACE_MESSAGES, IGMP_TYPE_DVMRP, IGMP_TYPE_EXPERIMENTAL_FIRST,
    IGMP_TYPE_EXPERIMENTAL_LAST, IGMP_TYPE_MEMBERSHIP_QUERY,
    IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT, IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION,
    IGMP_TYPE_MULTICAST_ROUTER_TERMINATION, IGMP_TYPE_MULTICAST_TRACEROUTE,
    IGMP_TYPE_MULTICAST_TRACEROUTE_RESPONSE, IGMP_TYPE_OBSOLETE_RESERVED_FIRST,
    IGMP_TYPE_OBSOLETE_RESERVED_LAST, IGMP_TYPE_PIM_V1, IGMP_TYPE_RESERVED,
    IGMP_TYPE_UNASSIGNED_FIRST, IGMP_TYPE_UNASSIGNED_LAST, IGMP_TYPE_V1_MEMBERSHIP_REPORT,
    IGMP_TYPE_V2_LEAVE_GROUP, IGMP_TYPE_V2_MEMBERSHIP_REPORT, IGMP_TYPE_V3_MEMBERSHIP_REPORT,
};

/// Source-backed IGMP Type value.
///
/// Values without a named packet-layer body are still preserved as typed range
/// variants carrying the original wire code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IgmpType {
    /// Type 0, reserved by IANA.
    Reserved,
    /// RFC 988 obsolete-reserved range 1-8.
    ObsoleteReserved(u8),
    /// Values not assigned to a named IGMP Type.
    Unassigned(u8),
    /// IGMP Membership Query, Type 0x11.
    MembershipQuery,
    /// IGMPv1 Membership Report, Type 0x12.
    V1MembershipReport,
    /// DVMRP, Type 0x13. Registered but not a typed IGMP body here.
    Dvmrp,
    /// PIM version 1, Type 0x14. Registered but not a typed IGMP body here.
    PimV1,
    /// Cisco Trace Messages, Type 0x15.
    CiscoTraceMessages,
    /// IGMPv2 Membership Report, Type 0x16.
    V2MembershipReport,
    /// IGMPv2 Leave Group, Type 0x17.
    V2LeaveGroup,
    /// Multicast Traceroute Response, Type 0x1e.
    MulticastTracerouteResponse,
    /// Multicast Traceroute, Type 0x1f.
    MulticastTraceroute,
    /// IGMPv3 Membership Report, Type 0x22.
    V3MembershipReport,
    /// Multicast Router Advertisement, Type 0x30.
    MulticastRouterAdvertisement,
    /// Multicast Router Solicitation, Type 0x31.
    MulticastRouterSolicitation,
    /// Multicast Router Termination, Type 0x32.
    MulticastRouterTermination,
    /// RFC 9778 experimental-use range 0xf0-0xff.
    Experimental(u8),
}

impl IgmpType {
    /// Return the raw wire Type code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Reserved => IGMP_TYPE_RESERVED,
            Self::ObsoleteReserved(code) => code,
            Self::Unassigned(code) => code,
            Self::MembershipQuery => IGMP_TYPE_MEMBERSHIP_QUERY,
            Self::V1MembershipReport => IGMP_TYPE_V1_MEMBERSHIP_REPORT,
            Self::Dvmrp => IGMP_TYPE_DVMRP,
            Self::PimV1 => IGMP_TYPE_PIM_V1,
            Self::CiscoTraceMessages => IGMP_TYPE_CISCO_TRACE_MESSAGES,
            Self::V2MembershipReport => IGMP_TYPE_V2_MEMBERSHIP_REPORT,
            Self::V2LeaveGroup => IGMP_TYPE_V2_LEAVE_GROUP,
            Self::MulticastTracerouteResponse => IGMP_TYPE_MULTICAST_TRACEROUTE_RESPONSE,
            Self::MulticastTraceroute => IGMP_TYPE_MULTICAST_TRACEROUTE,
            Self::V3MembershipReport => IGMP_TYPE_V3_MEMBERSHIP_REPORT,
            Self::MulticastRouterAdvertisement => IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT,
            Self::MulticastRouterSolicitation => IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION,
            Self::MulticastRouterTermination => IGMP_TYPE_MULTICAST_ROUTER_TERMINATION,
            Self::Experimental(code) => code,
        }
    }

    /// Return source-backed metadata for this Type.
    pub const fn meta(self) -> IgmpTypeMeta {
        igmp_type_meta(self.code())
    }
}

/// Registry assignment status for an IGMP Type or scoped Code value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IgmpTypeStatus {
    /// Assigned to an IGMP packet-layer type this plan will model directly.
    Assigned,
    /// Assigned in the IGMP Type/Code registry, but not a typed body here.
    UnsupportedAssigned,
    /// Reserved by the current registry.
    Reserved,
    /// Reserved by an obsolete historical allocation.
    ObsoleteReserved,
    /// Not assigned by the reviewed registry.
    Unassigned,
    /// Reserved for experimental use.
    Experimental,
}

/// One source-backed IGMP Type registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IgmpTypeMeta {
    /// Raw wire Type code.
    pub code: u8,
    /// Type classification preserving raw range values.
    pub igmp_type: IgmpType,
    /// Registered short name, or a status label for range-derived values.
    pub name: &'static str,
    /// Registry assignment status.
    pub status: IgmpTypeStatus,
}

/// One source-backed IGMP Code registry entry scoped by Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IgmpCodeMeta {
    /// Raw enclosing IGMP Type code.
    pub type_code: u8,
    /// Enclosing Type classification preserving raw range values.
    pub igmp_type: IgmpType,
    /// Raw scoped Code value.
    pub code: u8,
    /// Registered short name, or a status label for unregistered codes.
    pub name: &'static str,
    /// Scoped registry assignment status.
    pub status: IgmpTypeStatus,
}

/// Classify an IGMP Type code without rejecting unassigned values.
pub const fn igmp_type(code: u8) -> IgmpType {
    match code {
        IGMP_TYPE_RESERVED => IgmpType::Reserved,
        IGMP_TYPE_OBSOLETE_RESERVED_FIRST..=IGMP_TYPE_OBSOLETE_RESERVED_LAST => {
            IgmpType::ObsoleteReserved(code)
        }
        IGMP_TYPE_UNASSIGNED_FIRST..=IGMP_TYPE_UNASSIGNED_LAST => IgmpType::Unassigned(code),
        IGMP_TYPE_MEMBERSHIP_QUERY => IgmpType::MembershipQuery,
        IGMP_TYPE_V1_MEMBERSHIP_REPORT => IgmpType::V1MembershipReport,
        IGMP_TYPE_DVMRP => IgmpType::Dvmrp,
        IGMP_TYPE_PIM_V1 => IgmpType::PimV1,
        IGMP_TYPE_CISCO_TRACE_MESSAGES => IgmpType::CiscoTraceMessages,
        IGMP_TYPE_V2_MEMBERSHIP_REPORT => IgmpType::V2MembershipReport,
        IGMP_TYPE_V2_LEAVE_GROUP => IgmpType::V2LeaveGroup,
        IGMP_TYPE_MULTICAST_TRACEROUTE_RESPONSE => IgmpType::MulticastTracerouteResponse,
        IGMP_TYPE_MULTICAST_TRACEROUTE => IgmpType::MulticastTraceroute,
        IGMP_TYPE_V3_MEMBERSHIP_REPORT => IgmpType::V3MembershipReport,
        IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT => IgmpType::MulticastRouterAdvertisement,
        IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION => IgmpType::MulticastRouterSolicitation,
        IGMP_TYPE_MULTICAST_ROUTER_TERMINATION => IgmpType::MulticastRouterTermination,
        IGMP_TYPE_EXPERIMENTAL_FIRST..=IGMP_TYPE_EXPERIMENTAL_LAST => IgmpType::Experimental(code),
        other => IgmpType::Unassigned(other),
    }
}

/// Return registry metadata for an IGMP Type code.
pub const fn igmp_type_meta(code: u8) -> IgmpTypeMeta {
    match code {
        IGMP_TYPE_RESERVED => type_meta(
            code,
            IgmpType::Reserved,
            "Reserved",
            IgmpTypeStatus::Reserved,
        ),
        IGMP_TYPE_OBSOLETE_RESERVED_FIRST..=IGMP_TYPE_OBSOLETE_RESERVED_LAST => type_meta(
            code,
            IgmpType::ObsoleteReserved(code),
            "Reserved (Obsolete)",
            IgmpTypeStatus::ObsoleteReserved,
        ),
        IGMP_TYPE_UNASSIGNED_FIRST..=IGMP_TYPE_UNASSIGNED_LAST => type_meta(
            code,
            IgmpType::Unassigned(code),
            "Unassigned",
            IgmpTypeStatus::Unassigned,
        ),
        IGMP_TYPE_MEMBERSHIP_QUERY => type_meta(
            code,
            IgmpType::MembershipQuery,
            "IGMP Membership Query",
            IgmpTypeStatus::Assigned,
        ),
        IGMP_TYPE_V1_MEMBERSHIP_REPORT => type_meta(
            code,
            IgmpType::V1MembershipReport,
            "IGMPv1 Membership Report",
            IgmpTypeStatus::Assigned,
        ),
        IGMP_TYPE_DVMRP => type_meta(
            code,
            IgmpType::Dvmrp,
            "DVMRP",
            IgmpTypeStatus::UnsupportedAssigned,
        ),
        IGMP_TYPE_PIM_V1 => type_meta(
            code,
            IgmpType::PimV1,
            "PIM version 1",
            IgmpTypeStatus::UnsupportedAssigned,
        ),
        IGMP_TYPE_CISCO_TRACE_MESSAGES => type_meta(
            code,
            IgmpType::CiscoTraceMessages,
            "Cisco Trace Messages",
            IgmpTypeStatus::UnsupportedAssigned,
        ),
        IGMP_TYPE_V2_MEMBERSHIP_REPORT => type_meta(
            code,
            IgmpType::V2MembershipReport,
            "IGMPv2 Membership Report",
            IgmpTypeStatus::Assigned,
        ),
        IGMP_TYPE_V2_LEAVE_GROUP => type_meta(
            code,
            IgmpType::V2LeaveGroup,
            "IGMPv2 Leave Group",
            IgmpTypeStatus::Assigned,
        ),
        IGMP_TYPE_MULTICAST_TRACEROUTE_RESPONSE => type_meta(
            code,
            IgmpType::MulticastTracerouteResponse,
            "Multicast Traceroute Response",
            IgmpTypeStatus::UnsupportedAssigned,
        ),
        IGMP_TYPE_MULTICAST_TRACEROUTE => type_meta(
            code,
            IgmpType::MulticastTraceroute,
            "Multicast Traceroute",
            IgmpTypeStatus::UnsupportedAssigned,
        ),
        IGMP_TYPE_V3_MEMBERSHIP_REPORT => type_meta(
            code,
            IgmpType::V3MembershipReport,
            "IGMPv3 Membership Report",
            IgmpTypeStatus::Assigned,
        ),
        IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT => type_meta(
            code,
            IgmpType::MulticastRouterAdvertisement,
            "Multicast Router Advertisement",
            IgmpTypeStatus::Assigned,
        ),
        IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION => type_meta(
            code,
            IgmpType::MulticastRouterSolicitation,
            "Multicast Router Solicitation",
            IgmpTypeStatus::Assigned,
        ),
        IGMP_TYPE_MULTICAST_ROUTER_TERMINATION => type_meta(
            code,
            IgmpType::MulticastRouterTermination,
            "Multicast Router Termination",
            IgmpTypeStatus::Assigned,
        ),
        IGMP_TYPE_EXPERIMENTAL_FIRST..=IGMP_TYPE_EXPERIMENTAL_LAST => type_meta(
            code,
            IgmpType::Experimental(code),
            "Reserved for experimentation",
            IgmpTypeStatus::Experimental,
        ),
        other => type_meta(
            other,
            IgmpType::Unassigned(other),
            "Unassigned",
            IgmpTypeStatus::Unassigned,
        ),
    }
}

/// Return the registry status for an IGMP Type code.
pub const fn igmp_type_status(code: u8) -> IgmpTypeStatus {
    igmp_type_meta(code).status
}

/// Return a source-backed Type name when the reviewed registry names the value.
pub const fn igmp_type_name(code: u8) -> Option<&'static str> {
    let meta = igmp_type_meta(code);
    match meta.status {
        IgmpTypeStatus::Unassigned => None,
        _ => Some(meta.name),
    }
}

/// Return registry metadata for a scoped IGMP Code field.
pub const fn igmp_code_meta(type_code: u8, code: u8) -> IgmpCodeMeta {
    match type_code {
        IGMP_TYPE_MEMBERSHIP_QUERY => match code {
            IGMP_QUERY_CODE_V1 => {
                code_meta(type_code, code, "IGMP Version 1", IgmpTypeStatus::Assigned)
            }
            IGMP_QUERY_CODE_MAX_RESPONSE_FIRST..=IGMP_QUERY_CODE_MAX_RESPONSE_LAST => code_meta(
                type_code,
                code,
                "Max Response Time",
                IgmpTypeStatus::Assigned,
            ),
        },
        IGMP_TYPE_DVMRP => dvmrp_code_meta(type_code, code),
        IGMP_TYPE_PIM_V1 => pim_v1_code_meta(type_code, code),
        other => {
            let type_status = igmp_type_status(other);
            let status = match type_status {
                IgmpTypeStatus::Reserved => IgmpTypeStatus::Reserved,
                IgmpTypeStatus::ObsoleteReserved => IgmpTypeStatus::ObsoleteReserved,
                IgmpTypeStatus::Experimental => IgmpTypeStatus::Experimental,
                _ => IgmpTypeStatus::Unassigned,
            };
            code_meta(other, code, "No registered code", status)
        }
    }
}

/// Return the registry status for a scoped IGMP Code field.
pub const fn igmp_code_status(type_code: u8, code: u8) -> IgmpTypeStatus {
    igmp_code_meta(type_code, code).status
}

/// Return a source-backed Code name when the reviewed registry names the value.
pub const fn igmp_code_name(type_code: u8, code: u8) -> Option<&'static str> {
    let meta = igmp_code_meta(type_code, code);
    match meta.status {
        IgmpTypeStatus::Assigned | IgmpTypeStatus::UnsupportedAssigned => Some(meta.name),
        _ => None,
    }
}

const fn type_meta(
    code: u8,
    igmp_type: IgmpType,
    name: &'static str,
    status: IgmpTypeStatus,
) -> IgmpTypeMeta {
    IgmpTypeMeta {
        code,
        igmp_type,
        name,
        status,
    }
}

const fn code_meta(
    type_code: u8,
    code: u8,
    name: &'static str,
    status: IgmpTypeStatus,
) -> IgmpCodeMeta {
    IgmpCodeMeta {
        type_code,
        igmp_type: igmp_type(type_code),
        code,
        name,
        status,
    }
}

const fn dvmrp_code_meta(type_code: u8, code: u8) -> IgmpCodeMeta {
    let name = match code {
        1 => "Probe",
        2 => "Route Report",
        3 => "Old Ask Neighbors",
        4 => "Old Neighbors Reply",
        5 => "Ask Neighbors",
        6 => "Neighbors Reply",
        7 => "Prune",
        8 => "Graft",
        9 => "Graft Ack",
        _ => "Unassigned",
    };
    let status = match code {
        1..=9 => IgmpTypeStatus::UnsupportedAssigned,
        _ => IgmpTypeStatus::Unassigned,
    };
    code_meta(type_code, code, name, status)
}

const fn pim_v1_code_meta(type_code: u8, code: u8) -> IgmpCodeMeta {
    let name = match code {
        0 => "Query",
        1 => "Register",
        2 => "Register-Stop",
        3 => "Join/Prune",
        4 => "RP-Reachable",
        5 => "Assert",
        6 => "Graft",
        7 => "Graft Ack",
        8 => "Mode",
        _ => "Unassigned",
    };
    let status = match code {
        0..=8 => IgmpTypeStatus::UnsupportedAssigned,
        _ => IgmpTypeStatus::Unassigned,
    };
    code_meta(type_code, code, name, status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn igmp_registry_classifies_known_type_metadata() {
        let query = igmp_type_meta(IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(query.code, 0x11);
        assert_eq!(query.igmp_type, IgmpType::MembershipQuery);
        assert_eq!(query.name, "IGMP Membership Query");
        assert_eq!(query.status, IgmpTypeStatus::Assigned);
        assert_eq!(igmp_type_name(IGMP_TYPE_MEMBERSHIP_QUERY), Some(query.name));

        let v3_report = IgmpType::V3MembershipReport.meta();
        assert_eq!(v3_report.code, IGMP_TYPE_V3_MEMBERSHIP_REPORT);
        assert_eq!(v3_report.status, IgmpTypeStatus::Assigned);

        let dvmrp = igmp_type_meta(IGMP_TYPE_DVMRP);
        assert_eq!(dvmrp.name, "DVMRP");
        assert_eq!(dvmrp.status, IgmpTypeStatus::UnsupportedAssigned);
        assert_eq!(igmp_type_name(IGMP_TYPE_DVMRP), Some("DVMRP"));
    }

    #[test]
    fn igmp_registry_preserves_reserved_experimental_and_unknown_types() {
        assert_eq!(igmp_type(IGMP_TYPE_RESERVED), IgmpType::Reserved);
        assert_eq!(
            igmp_type_status(IGMP_TYPE_RESERVED),
            IgmpTypeStatus::Reserved
        );

        let obsolete = igmp_type_meta(0x08);
        assert_eq!(obsolete.igmp_type, IgmpType::ObsoleteReserved(0x08));
        assert_eq!(obsolete.status, IgmpTypeStatus::ObsoleteReserved);
        assert_eq!(igmp_type_name(0x08), Some("Reserved (Obsolete)"));

        let first_unassigned = igmp_type_meta(IGMP_TYPE_UNASSIGNED_FIRST);
        assert_eq!(
            first_unassigned.igmp_type,
            IgmpType::Unassigned(IGMP_TYPE_UNASSIGNED_FIRST)
        );
        assert_eq!(first_unassigned.status, IgmpTypeStatus::Unassigned);
        assert_eq!(igmp_type_name(IGMP_TYPE_UNASSIGNED_FIRST), None);

        let unknown_gap = igmp_type_meta(0x80);
        assert_eq!(unknown_gap.igmp_type, IgmpType::Unassigned(0x80));
        assert_eq!(unknown_gap.status, IgmpTypeStatus::Unassigned);
        assert_eq!(unknown_gap.code, 0x80);

        let experimental = igmp_type_meta(0xf7);
        assert_eq!(experimental.igmp_type, IgmpType::Experimental(0xf7));
        assert_eq!(experimental.status, IgmpTypeStatus::Experimental);
        assert_eq!(igmp_type_name(0xf7), Some("Reserved for experimentation"));
    }

    #[test]
    fn igmp_registry_classifies_scoped_code_metadata() {
        let v1_query = igmp_code_meta(IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_QUERY_CODE_V1);
        assert_eq!(v1_query.type_code, IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(v1_query.igmp_type, IgmpType::MembershipQuery);
        assert_eq!(v1_query.name, "IGMP Version 1");
        assert_eq!(v1_query.status, IgmpTypeStatus::Assigned);
        assert_eq!(
            igmp_code_name(IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_QUERY_CODE_V1),
            Some("IGMP Version 1")
        );

        let max_resp = igmp_code_meta(IGMP_TYPE_MEMBERSHIP_QUERY, 100);
        assert_eq!(max_resp.name, "Max Response Time");
        assert_eq!(max_resp.status, IgmpTypeStatus::Assigned);

        let dvmrp_probe = igmp_code_meta(IGMP_TYPE_DVMRP, 1);
        assert_eq!(dvmrp_probe.name, "Probe");
        assert_eq!(dvmrp_probe.status, IgmpTypeStatus::UnsupportedAssigned);

        let pim_assert = igmp_code_meta(IGMP_TYPE_PIM_V1, 5);
        assert_eq!(pim_assert.name, "Assert");
        assert_eq!(pim_assert.status, IgmpTypeStatus::UnsupportedAssigned);

        let report_code = igmp_code_meta(IGMP_TYPE_V3_MEMBERSHIP_REPORT, 9);
        assert_eq!(report_code.name, "No registered code");
        assert_eq!(report_code.status, IgmpTypeStatus::Unassigned);
        assert_eq!(igmp_code_name(IGMP_TYPE_V3_MEMBERSHIP_REPORT, 9), None);

        let experimental_code = igmp_code_meta(0xf0, 33);
        assert_eq!(experimental_code.igmp_type, IgmpType::Experimental(0xf0));
        assert_eq!(experimental_code.status, IgmpTypeStatus::Experimental);
    }

    #[test]
    fn igmp_registry_covers_every_type_without_panic() {
        for code in 0u8..=255 {
            let meta = igmp_type_meta(code);
            assert_eq!(meta.code, code);
            assert_eq!(meta.igmp_type.code(), code);
            assert!(!meta.name.is_empty());
        }
    }
}
