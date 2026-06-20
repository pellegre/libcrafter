//! IGMP group-record model.
//!
//! Group records are populated during the IGMPv3 report steps.

use super::constants::{
    IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES, IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES,
    IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE, IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE,
    IGMP_RECORD_TYPE_MODE_IS_EXCLUDE, IGMP_RECORD_TYPE_MODE_IS_INCLUDE,
};

/// Source-backed IGMPv3 Group Record Type value.
///
/// RFC 9776 section 4.2.13 defines values `1..=6`. Value `0` is kept as a
/// reserved byte, and every other value is preserved as [`IgmpRecordType::Unknown`]
/// so future or malformed records remain constructible and inspectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IgmpRecordType {
    /// Reserved zero value.
    Reserved,
    /// MODE_IS_INCLUDE (1), a Current-State Record.
    ModeIsInclude,
    /// MODE_IS_EXCLUDE (2), a Current-State Record.
    ModeIsExclude,
    /// CHANGE_TO_INCLUDE_MODE (3), a Filter-Mode-Change Record.
    ChangeToIncludeMode,
    /// CHANGE_TO_EXCLUDE_MODE (4), a Filter-Mode-Change Record.
    ChangeToExcludeMode,
    /// ALLOW_NEW_SOURCES (5), a Source-List-Change Record.
    AllowNewSources,
    /// BLOCK_OLD_SOURCES (6), a Source-List-Change Record.
    BlockOldSources,
    /// Any Record Type not defined by RFC 9776 section 4.2.13.
    Unknown(u8),
}

impl IgmpRecordType {
    /// Return the raw wire Record Type byte.
    pub const fn code(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::ModeIsInclude => IGMP_RECORD_TYPE_MODE_IS_INCLUDE,
            Self::ModeIsExclude => IGMP_RECORD_TYPE_MODE_IS_EXCLUDE,
            Self::ChangeToIncludeMode => IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE,
            Self::ChangeToExcludeMode => IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE,
            Self::AllowNewSources => IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES,
            Self::BlockOldSources => IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES,
            Self::Unknown(code) => code,
        }
    }

    /// Return the raw wire Record Type byte.
    pub const fn raw(self) -> u8 {
        self.code()
    }

    /// Return the raw wire Record Type byte.
    pub const fn to_u8(self) -> u8 {
        self.code()
    }

    /// Classify a raw Record Type byte without rejecting unknown values.
    pub const fn from_u8(code: u8) -> Self {
        igmp_record_type(code)
    }

    /// Return source-backed metadata for this Record Type.
    pub const fn meta(self) -> IgmpRecordTypeMeta {
        igmp_record_type_meta(self.code())
    }
}

impl core::fmt::Display for IgmpRecordType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let meta = self.meta();
        match meta.status {
            IgmpRecordTypeStatus::Unassigned => write!(f, "Unknown({})", meta.code),
            _ => f.write_str(meta.name),
        }
    }
}

/// Assignment status for an IGMPv3 Group Record Type value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IgmpRecordTypeStatus {
    /// Defined by RFC 9776 section 4.2.13.
    Assigned,
    /// Reserved zero value.
    Reserved,
    /// Not defined by RFC 9776 section 4.2.13.
    Unassigned,
}

/// One source-backed IGMPv3 Group Record Type metadata entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IgmpRecordTypeMeta {
    /// Raw wire Record Type byte.
    pub code: u8,
    /// Record Type classification preserving raw unknown values.
    pub record_type: IgmpRecordType,
    /// Stable RFC token, or a status label for unassigned values.
    pub name: &'static str,
    /// Stable summary label suitable for later `summary()` and `show()` output.
    pub summary: &'static str,
    /// Assignment status.
    pub status: IgmpRecordTypeStatus,
}

/// Classify an IGMPv3 Group Record Type byte without rejecting unknown values.
pub const fn igmp_record_type(code: u8) -> IgmpRecordType {
    match code {
        0 => IgmpRecordType::Reserved,
        IGMP_RECORD_TYPE_MODE_IS_INCLUDE => IgmpRecordType::ModeIsInclude,
        IGMP_RECORD_TYPE_MODE_IS_EXCLUDE => IgmpRecordType::ModeIsExclude,
        IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE => IgmpRecordType::ChangeToIncludeMode,
        IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE => IgmpRecordType::ChangeToExcludeMode,
        IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES => IgmpRecordType::AllowNewSources,
        IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES => IgmpRecordType::BlockOldSources,
        other => IgmpRecordType::Unknown(other),
    }
}

/// Return metadata for an IGMPv3 Group Record Type byte.
pub const fn igmp_record_type_meta(code: u8) -> IgmpRecordTypeMeta {
    match code {
        0 => record_type_meta(
            code,
            IgmpRecordType::Reserved,
            "Reserved",
            "Reserved Record Type",
            IgmpRecordTypeStatus::Reserved,
        ),
        IGMP_RECORD_TYPE_MODE_IS_INCLUDE => record_type_meta(
            code,
            IgmpRecordType::ModeIsInclude,
            "MODE_IS_INCLUDE",
            "Current-State Record: MODE_IS_INCLUDE",
            IgmpRecordTypeStatus::Assigned,
        ),
        IGMP_RECORD_TYPE_MODE_IS_EXCLUDE => record_type_meta(
            code,
            IgmpRecordType::ModeIsExclude,
            "MODE_IS_EXCLUDE",
            "Current-State Record: MODE_IS_EXCLUDE",
            IgmpRecordTypeStatus::Assigned,
        ),
        IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE => record_type_meta(
            code,
            IgmpRecordType::ChangeToIncludeMode,
            "CHANGE_TO_INCLUDE_MODE",
            "Filter-Mode-Change Record: CHANGE_TO_INCLUDE_MODE",
            IgmpRecordTypeStatus::Assigned,
        ),
        IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE => record_type_meta(
            code,
            IgmpRecordType::ChangeToExcludeMode,
            "CHANGE_TO_EXCLUDE_MODE",
            "Filter-Mode-Change Record: CHANGE_TO_EXCLUDE_MODE",
            IgmpRecordTypeStatus::Assigned,
        ),
        IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES => record_type_meta(
            code,
            IgmpRecordType::AllowNewSources,
            "ALLOW_NEW_SOURCES",
            "Source-List-Change Record: ALLOW_NEW_SOURCES",
            IgmpRecordTypeStatus::Assigned,
        ),
        IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES => record_type_meta(
            code,
            IgmpRecordType::BlockOldSources,
            "BLOCK_OLD_SOURCES",
            "Source-List-Change Record: BLOCK_OLD_SOURCES",
            IgmpRecordTypeStatus::Assigned,
        ),
        other => record_type_meta(
            other,
            IgmpRecordType::Unknown(other),
            "Unassigned",
            "Unknown Record Type",
            IgmpRecordTypeStatus::Unassigned,
        ),
    }
}

/// Return the assignment status for an IGMPv3 Group Record Type byte.
pub const fn igmp_record_type_status(code: u8) -> IgmpRecordTypeStatus {
    igmp_record_type_meta(code).status
}

/// Return a source-backed name when the Record Type byte has one.
pub const fn igmp_record_type_name(code: u8) -> Option<&'static str> {
    let meta = igmp_record_type_meta(code);
    match meta.status {
        IgmpRecordTypeStatus::Unassigned => None,
        _ => Some(meta.name),
    }
}

/// Return a stable summary label for an IGMPv3 Group Record Type byte.
pub const fn igmp_record_type_summary(code: u8) -> &'static str {
    igmp_record_type_meta(code).summary
}

const fn record_type_meta(
    code: u8,
    record_type: IgmpRecordType,
    name: &'static str,
    summary: &'static str,
    status: IgmpRecordTypeStatus,
) -> IgmpRecordTypeMeta {
    IgmpRecordTypeMeta {
        code,
        record_type,
        name,
        summary,
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_RECORD_TYPES: &[(u8, IgmpRecordType, &str, &str)] = &[
        (
            IGMP_RECORD_TYPE_MODE_IS_INCLUDE,
            IgmpRecordType::ModeIsInclude,
            "MODE_IS_INCLUDE",
            "Current-State Record: MODE_IS_INCLUDE",
        ),
        (
            IGMP_RECORD_TYPE_MODE_IS_EXCLUDE,
            IgmpRecordType::ModeIsExclude,
            "MODE_IS_EXCLUDE",
            "Current-State Record: MODE_IS_EXCLUDE",
        ),
        (
            IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE,
            IgmpRecordType::ChangeToIncludeMode,
            "CHANGE_TO_INCLUDE_MODE",
            "Filter-Mode-Change Record: CHANGE_TO_INCLUDE_MODE",
        ),
        (
            IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE,
            IgmpRecordType::ChangeToExcludeMode,
            "CHANGE_TO_EXCLUDE_MODE",
            "Filter-Mode-Change Record: CHANGE_TO_EXCLUDE_MODE",
        ),
        (
            IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES,
            IgmpRecordType::AllowNewSources,
            "ALLOW_NEW_SOURCES",
            "Source-List-Change Record: ALLOW_NEW_SOURCES",
        ),
        (
            IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES,
            IgmpRecordType::BlockOldSources,
            "BLOCK_OLD_SOURCES",
            "Source-List-Change Record: BLOCK_OLD_SOURCES",
        ),
    ];

    #[test]
    fn igmp_record_type_classifies_every_known_type() {
        for &(code, record_type, name, summary) in KNOWN_RECORD_TYPES {
            let meta = igmp_record_type_meta(code);

            assert_eq!(igmp_record_type(code), record_type);
            assert_eq!(IgmpRecordType::from_u8(code), record_type);
            assert_eq!(record_type.code(), code);
            assert_eq!(record_type.raw(), code);
            assert_eq!(record_type.to_u8(), code);
            assert_eq!(record_type.meta(), meta);
            assert_eq!(meta.code, code);
            assert_eq!(meta.record_type, record_type);
            assert_eq!(meta.name, name);
            assert_eq!(meta.summary, summary);
            assert_eq!(meta.status, IgmpRecordTypeStatus::Assigned);
            assert_eq!(
                igmp_record_type_status(code),
                IgmpRecordTypeStatus::Assigned
            );
            assert_eq!(igmp_record_type_name(code), Some(name));
            assert_eq!(igmp_record_type_summary(code), summary);
            assert_eq!(record_type.to_string(), name);
        }
    }

    #[test]
    fn igmp_record_type_preserves_reserved_zero() {
        let meta = igmp_record_type_meta(0);

        assert_eq!(igmp_record_type(0), IgmpRecordType::Reserved);
        assert_eq!(IgmpRecordType::Reserved.code(), 0);
        assert_eq!(IgmpRecordType::Reserved.raw(), 0);
        assert_eq!(meta.code, 0);
        assert_eq!(meta.record_type, IgmpRecordType::Reserved);
        assert_eq!(meta.name, "Reserved");
        assert_eq!(meta.summary, "Reserved Record Type");
        assert_eq!(meta.status, IgmpRecordTypeStatus::Reserved);
        assert_eq!(igmp_record_type_status(0), IgmpRecordTypeStatus::Reserved);
        assert_eq!(igmp_record_type_name(0), Some("Reserved"));
        assert_eq!(igmp_record_type_summary(0), "Reserved Record Type");
        assert_eq!(IgmpRecordType::Reserved.to_string(), "Reserved");
    }

    #[test]
    fn igmp_record_type_preserves_unknown_values() {
        for code in [7, 200, u8::MAX] {
            let record_type = IgmpRecordType::Unknown(code);
            let meta = igmp_record_type_meta(code);

            assert_eq!(igmp_record_type(code), record_type);
            assert_eq!(IgmpRecordType::from_u8(code), record_type);
            assert_eq!(record_type.code(), code);
            assert_eq!(record_type.raw(), code);
            assert_eq!(record_type.to_u8(), code);
            assert_eq!(record_type.meta(), meta);
            assert_eq!(meta.code, code);
            assert_eq!(meta.record_type, record_type);
            assert_eq!(meta.name, "Unassigned");
            assert_eq!(meta.summary, "Unknown Record Type");
            assert_eq!(meta.status, IgmpRecordTypeStatus::Unassigned);
            assert_eq!(
                igmp_record_type_status(code),
                IgmpRecordTypeStatus::Unassigned
            );
            assert_eq!(igmp_record_type_name(code), None);
            assert_eq!(igmp_record_type_summary(code), "Unknown Record Type");
            assert_eq!(record_type.to_string(), format!("Unknown({code})"));
        }
    }

    #[test]
    fn igmp_record_type_metadata_covers_all_raw_values() {
        for code in 0u8..=u8::MAX {
            let meta = igmp_record_type_meta(code);

            assert_eq!(meta.code, code);
            assert_eq!(meta.record_type.code(), code);
            assert!(!meta.name.is_empty());
            assert!(!meta.summary.is_empty());
        }
    }
}
