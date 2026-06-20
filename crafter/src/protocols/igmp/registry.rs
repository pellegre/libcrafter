//! IGMP registry metadata.
//!
//! This module is metadata only: it names and classifies source-backed IGMP
//! type/code values without deciding whether a decoder accepts a typed body.
//! Unsupported-but-registered values remain valid byte values that later decode
//! steps can preserve as raw payloads.

use super::constants::{
    IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST, IGMP_EXTENSION_TYPE_EXPERIMENTAL_LAST,
    IGMP_EXTENSION_TYPE_NOOP, IGMP_EXTENSION_TYPE_UNASSIGNED_FIRST,
    IGMP_EXTENSION_TYPE_UNASSIGNED_LAST, IGMP_QUERY_CODE_MAX_RESPONSE_FIRST,
    IGMP_QUERY_CODE_MAX_RESPONSE_LAST, IGMP_QUERY_CODE_V1, IGMP_TYPE_CISCO_TRACE_MESSAGES,
    IGMP_TYPE_DVMRP, IGMP_TYPE_EXPERIMENTAL_FIRST, IGMP_TYPE_EXPERIMENTAL_LAST,
    IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT,
    IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION, IGMP_TYPE_MULTICAST_ROUTER_TERMINATION,
    IGMP_TYPE_MULTICAST_TRACEROUTE, IGMP_TYPE_MULTICAST_TRACEROUTE_RESPONSE,
    IGMP_TYPE_OBSOLETE_RESERVED_FIRST, IGMP_TYPE_OBSOLETE_RESERVED_LAST, IGMP_TYPE_PIM_V1,
    IGMP_TYPE_RESERVED, IGMP_TYPE_UNASSIGNED_FIRST, IGMP_TYPE_UNASSIGNED_LAST,
    IGMP_TYPE_V1_MEMBERSHIP_REPORT, IGMP_TYPE_V2_LEAVE_GROUP, IGMP_TYPE_V2_MEMBERSHIP_REPORT,
    IGMP_TYPE_V3_MEMBERSHIP_REPORT, IGMP_V3_QUERY_FLAG_EXTENSION, IGMP_V3_REPORT_FLAG_EXTENSION,
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

/// Registry assignment status for an IGMP/MLD message flag bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IgmpFlagStatus {
    /// Assigned by the reviewed IGMP/MLD flag registry.
    Assigned,
    /// In the registry-managed flag range but not currently assigned.
    Unassigned,
    /// Not part of this message's registry-managed flag field.
    NotFlag,
}

/// Source-backed IGMPv3 Query flag bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IgmpQueryFlag {
    /// RFC 9279 Extension flag, registry bit 0.
    Extension,
    /// Registry-managed but currently unassigned query flag bit.
    Unassigned(u8),
    /// Bits outside the IGMP/MLD Query Message Flags registry.
    NotFlag(u8),
}

impl IgmpQueryFlag {
    /// Return the IANA registry bit number.
    pub const fn bit(self) -> u8 {
        match self {
            Self::Extension => 0,
            Self::Unassigned(bit) | Self::NotFlag(bit) => bit,
        }
    }

    /// Return the wire mask for this registry bit, or zero for non-flag bits.
    pub const fn mask(self) -> u8 {
        igmp_query_flag_mask(self.bit())
    }

    /// Return source-backed metadata for this query flag bit.
    pub const fn meta(self) -> IgmpQueryFlagMeta {
        igmp_query_flag_meta(self.bit())
    }
}

/// One source-backed IGMP/MLD Query Message Flags registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IgmpQueryFlagMeta {
    /// IANA registry bit number.
    pub bit: u8,
    /// Wire mask in the IGMPv3 Flags/S/QRV octet, or zero for non-flag bits.
    pub mask: u8,
    /// Flag classification preserving raw bit values.
    pub flag: IgmpQueryFlag,
    /// Registered short name, status label, or non-flag label.
    pub name: &'static str,
    /// Registry assignment status.
    pub status: IgmpFlagStatus,
}

/// Source-backed IGMPv3 Report flag bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IgmpReportFlag {
    /// RFC 9279 Extension flag, registry bit 0.
    Extension,
    /// Registry-managed but currently unassigned report flag bit.
    Unassigned(u8),
    /// Bits outside the IGMP/MLD Report Message Flags registry.
    NotFlag(u8),
}

impl IgmpReportFlag {
    /// Return the IANA registry bit number.
    pub const fn bit(self) -> u8 {
        match self {
            Self::Extension => 0,
            Self::Unassigned(bit) | Self::NotFlag(bit) => bit,
        }
    }

    /// Return the wire mask for this registry bit, or zero for non-flag bits.
    pub const fn mask(self) -> u16 {
        igmp_report_flag_mask(self.bit())
    }

    /// Return source-backed metadata for this report flag bit.
    pub const fn meta(self) -> IgmpReportFlagMeta {
        igmp_report_flag_meta(self.bit())
    }
}

/// One source-backed IGMP/MLD Report Message Flags registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IgmpReportFlagMeta {
    /// IANA registry bit number.
    pub bit: u8,
    /// Wire mask in the IGMPv3 Report Flags field, or zero for non-flag bits.
    pub mask: u16,
    /// Flag classification preserving raw bit values.
    pub flag: IgmpReportFlag,
    /// Registered short name, status label, or non-flag label.
    pub name: &'static str,
    /// Registry assignment status.
    pub status: IgmpFlagStatus,
}

/// Source-backed IGMP/MLD extension type value.
///
/// RFC 9279 and the common IANA IGMP/MLD Extension Types registry currently
/// assign only Type 0 (No-op). Unassigned and experimental-use values remain
/// typed range variants carrying the original wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IgmpExtensionType {
    /// No-op Extension Type, value 0.
    Noop,
    /// Registry-managed but currently unassigned Extension Type.
    Unassigned(u16),
    /// Reserved for experimental use by RFC 9279 / IANA.
    Experimental(u16),
}

impl IgmpExtensionType {
    /// Return the raw wire Extension Type value.
    pub const fn code(self) -> u16 {
        match self {
            Self::Noop => IGMP_EXTENSION_TYPE_NOOP,
            Self::Unassigned(code) | Self::Experimental(code) => code,
        }
    }

    /// Return the raw wire Extension Type value.
    pub const fn raw(self) -> u16 {
        self.code()
    }

    /// Return the raw wire Extension Type value.
    pub const fn to_u16(self) -> u16 {
        self.code()
    }

    /// Classify a raw Extension Type value without rejecting unknown values.
    pub const fn from_u16(code: u16) -> Self {
        igmp_extension_type(code)
    }

    /// Return source-backed metadata for this Extension Type.
    pub const fn meta(self) -> IgmpExtensionTypeMeta {
        igmp_extension_type_meta(self.code())
    }
}

impl core::fmt::Display for IgmpExtensionType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let meta = self.meta();
        match meta.status {
            IgmpExtensionTypeStatus::Unassigned => write!(f, "Unknown({})", meta.code),
            _ => f.write_str(meta.name),
        }
    }
}

/// Registry assignment status for an IGMP/MLD extension type value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IgmpExtensionTypeStatus {
    /// Assigned by the reviewed extension type registry.
    Assigned,
    /// In the registry-managed range but not currently assigned.
    Unassigned,
    /// Reserved for experimental use.
    Experimental,
}

/// One source-backed IGMP/MLD Extension Types registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IgmpExtensionTypeMeta {
    /// Raw wire Extension Type value.
    pub code: u16,
    /// Extension Type classification preserving raw range values.
    pub extension_type: IgmpExtensionType,
    /// Registered short name, or a status label for range-derived values.
    pub name: &'static str,
    /// Registry assignment status.
    pub status: IgmpExtensionTypeStatus,
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

/// Classify an IGMP/MLD Query Message Flags registry bit.
pub const fn igmp_query_flag(bit: u8) -> IgmpQueryFlag {
    match bit {
        0 => IgmpQueryFlag::Extension,
        1..=3 => IgmpQueryFlag::Unassigned(bit),
        other => IgmpQueryFlag::NotFlag(other),
    }
}

/// Return registry metadata for an IGMP/MLD Query Message Flags bit.
pub const fn igmp_query_flag_meta(bit: u8) -> IgmpQueryFlagMeta {
    match bit {
        0 => query_flag_meta(
            bit,
            IGMP_V3_QUERY_FLAG_EXTENSION,
            IgmpQueryFlag::Extension,
            "Extension",
            IgmpFlagStatus::Assigned,
        ),
        1..=3 => query_flag_meta(
            bit,
            igmp_query_flag_mask(bit),
            IgmpQueryFlag::Unassigned(bit),
            "Unassigned",
            IgmpFlagStatus::Unassigned,
        ),
        other => query_flag_meta(
            other,
            0,
            IgmpQueryFlag::NotFlag(other),
            "Not a query flag",
            IgmpFlagStatus::NotFlag,
        ),
    }
}

/// Return the registry status for an IGMP/MLD Query Message Flags bit.
pub const fn igmp_query_flag_status(bit: u8) -> IgmpFlagStatus {
    igmp_query_flag_meta(bit).status
}

/// Return a source-backed Query Message Flag name when the registry assigns it.
pub const fn igmp_query_flag_name(bit: u8) -> Option<&'static str> {
    let meta = igmp_query_flag_meta(bit);
    match meta.status {
        IgmpFlagStatus::Assigned => Some(meta.name),
        _ => None,
    }
}

/// Classify an IGMP/MLD Report Message Flags registry bit.
pub const fn igmp_report_flag(bit: u8) -> IgmpReportFlag {
    match bit {
        0 => IgmpReportFlag::Extension,
        1..=15 => IgmpReportFlag::Unassigned(bit),
        other => IgmpReportFlag::NotFlag(other),
    }
}

/// Return registry metadata for an IGMP/MLD Report Message Flags bit.
pub const fn igmp_report_flag_meta(bit: u8) -> IgmpReportFlagMeta {
    match bit {
        0 => report_flag_meta(
            bit,
            IGMP_V3_REPORT_FLAG_EXTENSION,
            IgmpReportFlag::Extension,
            "Extension",
            IgmpFlagStatus::Assigned,
        ),
        1..=15 => report_flag_meta(
            bit,
            igmp_report_flag_mask(bit),
            IgmpReportFlag::Unassigned(bit),
            "Unassigned",
            IgmpFlagStatus::Unassigned,
        ),
        other => report_flag_meta(
            other,
            0,
            IgmpReportFlag::NotFlag(other),
            "Not a report flag",
            IgmpFlagStatus::NotFlag,
        ),
    }
}

/// Return the registry status for an IGMP/MLD Report Message Flags bit.
pub const fn igmp_report_flag_status(bit: u8) -> IgmpFlagStatus {
    igmp_report_flag_meta(bit).status
}

/// Return a source-backed Report Message Flag name when the registry assigns it.
pub const fn igmp_report_flag_name(bit: u8) -> Option<&'static str> {
    let meta = igmp_report_flag_meta(bit);
    match meta.status {
        IgmpFlagStatus::Assigned => Some(meta.name),
        _ => None,
    }
}

/// Classify an IGMP/MLD Extension Type value without rejecting unknown values.
pub const fn igmp_extension_type(code: u16) -> IgmpExtensionType {
    match code {
        IGMP_EXTENSION_TYPE_NOOP => IgmpExtensionType::Noop,
        IGMP_EXTENSION_TYPE_UNASSIGNED_FIRST..=IGMP_EXTENSION_TYPE_UNASSIGNED_LAST => {
            IgmpExtensionType::Unassigned(code)
        }
        IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST..=IGMP_EXTENSION_TYPE_EXPERIMENTAL_LAST => {
            IgmpExtensionType::Experimental(code)
        }
    }
}

/// Return registry metadata for an IGMP/MLD Extension Type value.
pub const fn igmp_extension_type_meta(code: u16) -> IgmpExtensionTypeMeta {
    match code {
        IGMP_EXTENSION_TYPE_NOOP => extension_type_meta(
            code,
            IgmpExtensionType::Noop,
            "No-op",
            IgmpExtensionTypeStatus::Assigned,
        ),
        IGMP_EXTENSION_TYPE_UNASSIGNED_FIRST..=IGMP_EXTENSION_TYPE_UNASSIGNED_LAST => {
            extension_type_meta(
                code,
                IgmpExtensionType::Unassigned(code),
                "Unassigned",
                IgmpExtensionTypeStatus::Unassigned,
            )
        }
        IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST..=IGMP_EXTENSION_TYPE_EXPERIMENTAL_LAST => {
            extension_type_meta(
                code,
                IgmpExtensionType::Experimental(code),
                "Reserved for Experimental Use",
                IgmpExtensionTypeStatus::Experimental,
            )
        }
    }
}

/// Return the registry status for an IGMP/MLD Extension Type value.
pub const fn igmp_extension_type_status(code: u16) -> IgmpExtensionTypeStatus {
    igmp_extension_type_meta(code).status
}

/// Return a source-backed Extension Type name when the registry assigns one.
pub const fn igmp_extension_type_name(code: u16) -> Option<&'static str> {
    let meta = igmp_extension_type_meta(code);
    match meta.status {
        IgmpExtensionTypeStatus::Assigned | IgmpExtensionTypeStatus::Experimental => {
            Some(meta.name)
        }
        IgmpExtensionTypeStatus::Unassigned => None,
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

const fn query_flag_meta(
    bit: u8,
    mask: u8,
    flag: IgmpQueryFlag,
    name: &'static str,
    status: IgmpFlagStatus,
) -> IgmpQueryFlagMeta {
    IgmpQueryFlagMeta {
        bit,
        mask,
        flag,
        name,
        status,
    }
}

const fn report_flag_meta(
    bit: u8,
    mask: u16,
    flag: IgmpReportFlag,
    name: &'static str,
    status: IgmpFlagStatus,
) -> IgmpReportFlagMeta {
    IgmpReportFlagMeta {
        bit,
        mask,
        flag,
        name,
        status,
    }
}

const fn igmp_query_flag_mask(bit: u8) -> u8 {
    match bit {
        0..=3 => 0x80 >> bit,
        _ => 0,
    }
}

const fn igmp_report_flag_mask(bit: u8) -> u16 {
    match bit {
        0..=15 => 0x8000 >> bit,
        _ => 0,
    }
}

const fn extension_type_meta(
    code: u16,
    extension_type: IgmpExtensionType,
    name: &'static str,
    status: IgmpExtensionTypeStatus,
) -> IgmpExtensionTypeMeta {
    IgmpExtensionTypeMeta {
        code,
        extension_type,
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

    #[test]
    fn igmp_extension_flags_registry_names_query_and_report_bits() {
        let query_extension = igmp_query_flag_meta(0);
        assert_eq!(query_extension.bit, 0);
        assert_eq!(query_extension.mask, IGMP_V3_QUERY_FLAG_EXTENSION);
        assert_eq!(query_extension.flag, IgmpQueryFlag::Extension);
        assert_eq!(query_extension.name, "Extension");
        assert_eq!(query_extension.status, IgmpFlagStatus::Assigned);
        assert_eq!(IgmpQueryFlag::Extension.bit(), 0);
        assert_eq!(
            IgmpQueryFlag::Extension.mask(),
            IGMP_V3_QUERY_FLAG_EXTENSION
        );
        assert_eq!(IgmpQueryFlag::Extension.meta(), query_extension);
        assert_eq!(igmp_query_flag(0), IgmpQueryFlag::Extension);
        assert_eq!(igmp_query_flag_name(0), Some("Extension"));
        assert_eq!(igmp_query_flag_status(0), IgmpFlagStatus::Assigned);

        let query_unassigned = igmp_query_flag_meta(3);
        assert_eq!(query_unassigned.mask, 0x10);
        assert_eq!(query_unassigned.flag, IgmpQueryFlag::Unassigned(3));
        assert_eq!(query_unassigned.status, IgmpFlagStatus::Unassigned);
        assert_eq!(igmp_query_flag_name(3), None);
        assert_eq!(igmp_query_flag_meta(4).flag, IgmpQueryFlag::NotFlag(4));

        let report_extension = igmp_report_flag_meta(0);
        assert_eq!(report_extension.bit, 0);
        assert_eq!(report_extension.mask, IGMP_V3_REPORT_FLAG_EXTENSION);
        assert_eq!(report_extension.flag, IgmpReportFlag::Extension);
        assert_eq!(report_extension.name, "Extension");
        assert_eq!(report_extension.status, IgmpFlagStatus::Assigned);
        assert_eq!(IgmpReportFlag::Extension.bit(), 0);
        assert_eq!(
            IgmpReportFlag::Extension.mask(),
            IGMP_V3_REPORT_FLAG_EXTENSION
        );
        assert_eq!(IgmpReportFlag::Extension.meta(), report_extension);
        assert_eq!(igmp_report_flag(0), IgmpReportFlag::Extension);
        assert_eq!(igmp_report_flag_name(0), Some("Extension"));
        assert_eq!(igmp_report_flag_status(0), IgmpFlagStatus::Assigned);

        let report_unassigned = igmp_report_flag_meta(15);
        assert_eq!(report_unassigned.mask, 0x0001);
        assert_eq!(report_unassigned.flag, IgmpReportFlag::Unassigned(15));
        assert_eq!(report_unassigned.status, IgmpFlagStatus::Unassigned);
        assert_eq!(igmp_report_flag_name(15), None);
        assert_eq!(igmp_report_flag_meta(16).flag, IgmpReportFlag::NotFlag(16));
    }

    #[test]
    fn igmp_extension_type_metadata_names_known_noop() {
        let noop = igmp_extension_type_meta(IGMP_EXTENSION_TYPE_NOOP);
        assert_eq!(noop.code, 0);
        assert_eq!(noop.extension_type, IgmpExtensionType::Noop);
        assert_eq!(noop.name, "No-op");
        assert_eq!(noop.status, IgmpExtensionTypeStatus::Assigned);
        assert_eq!(
            igmp_extension_type(IGMP_EXTENSION_TYPE_NOOP),
            IgmpExtensionType::Noop
        );
        assert_eq!(
            igmp_extension_type_status(IGMP_EXTENSION_TYPE_NOOP),
            IgmpExtensionTypeStatus::Assigned
        );
        assert_eq!(
            igmp_extension_type_name(IGMP_EXTENSION_TYPE_NOOP),
            Some("No-op")
        );
        assert_eq!(IgmpExtensionType::Noop.code(), IGMP_EXTENSION_TYPE_NOOP);
        assert_eq!(IgmpExtensionType::Noop.raw(), IGMP_EXTENSION_TYPE_NOOP);
        assert_eq!(IgmpExtensionType::Noop.to_u16(), IGMP_EXTENSION_TYPE_NOOP);
        assert_eq!(
            IgmpExtensionType::from_u16(IGMP_EXTENSION_TYPE_NOOP),
            IgmpExtensionType::Noop
        );
        assert_eq!(IgmpExtensionType::Noop.meta(), noop);
        assert_eq!(IgmpExtensionType::Noop.to_string(), "No-op");
    }

    #[test]
    fn igmp_extension_type_metadata_preserves_unknown_and_reserved_experimental_values() {
        let first_unassigned = igmp_extension_type_meta(IGMP_EXTENSION_TYPE_UNASSIGNED_FIRST);
        assert_eq!(
            first_unassigned.extension_type,
            IgmpExtensionType::Unassigned(IGMP_EXTENSION_TYPE_UNASSIGNED_FIRST)
        );
        assert_eq!(first_unassigned.name, "Unassigned");
        assert_eq!(first_unassigned.status, IgmpExtensionTypeStatus::Unassigned);
        assert_eq!(
            igmp_extension_type_name(IGMP_EXTENSION_TYPE_UNASSIGNED_FIRST),
            None
        );
        assert_eq!(
            IgmpExtensionType::from_u16(IGMP_EXTENSION_TYPE_UNASSIGNED_LAST),
            IgmpExtensionType::Unassigned(IGMP_EXTENSION_TYPE_UNASSIGNED_LAST)
        );
        assert_eq!(IgmpExtensionType::Unassigned(17).to_string(), "Unknown(17)");

        let first_experimental = igmp_extension_type_meta(IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST);
        assert_eq!(
            first_experimental.extension_type,
            IgmpExtensionType::Experimental(IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST)
        );
        assert_eq!(first_experimental.name, "Reserved for Experimental Use");
        assert_eq!(
            first_experimental.status,
            IgmpExtensionTypeStatus::Experimental
        );
        assert_eq!(
            igmp_extension_type_status(IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST),
            IgmpExtensionTypeStatus::Experimental
        );
        assert_eq!(
            igmp_extension_type_name(IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST),
            Some("Reserved for Experimental Use")
        );

        let reserved_experimental = igmp_extension_type_meta(IGMP_EXTENSION_TYPE_EXPERIMENTAL_LAST);
        assert_eq!(
            reserved_experimental.extension_type,
            IgmpExtensionType::Experimental(IGMP_EXTENSION_TYPE_EXPERIMENTAL_LAST)
        );
        assert_eq!(
            reserved_experimental.status,
            IgmpExtensionTypeStatus::Experimental
        );
        assert_eq!(
            IgmpExtensionType::Experimental(IGMP_EXTENSION_TYPE_EXPERIMENTAL_LAST).to_string(),
            "Reserved for Experimental Use"
        );
    }

    #[test]
    fn igmp_extension_type_metadata_covers_all_raw_values() {
        for code in 0u16..=u16::MAX {
            let meta = igmp_extension_type_meta(code);
            assert_eq!(meta.code, code);
            assert_eq!(meta.extension_type.code(), code);
            assert!(!meta.name.is_empty());
        }
    }
}
