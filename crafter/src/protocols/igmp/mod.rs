//! Internet Group Management Protocol (IGMP) support.
//!
//! IGMP is the IPv4 multicast group-management protocol. Source authority for
//! this implementation is tracked in `docs/igmp-rfc-manifest.md`; field-level
//! behavior should be added only after the corresponding source-review step.
//!
//! This module starts as a private scaffold. Later steps add the typed header,
//! query, report, record, decode, validation, and registry behavior. Decode
//! support must preserve unsupported IGMP types as raw payload bytes wherever
//! the enclosing IGMP header can be parsed defensibly.

pub mod constants;
mod decode;
mod message;
pub mod query;
pub mod record;
pub mod registry;
pub mod report;
mod validation;

pub use self::constants::*;
pub(crate) use self::decode::append_igmp_packet;
pub use self::message::{Igmp, IgmpChecksumStatus};
pub use self::query::IgmpQuery;
pub use self::record::{
    igmp_record_type, igmp_record_type_meta, igmp_record_type_name, igmp_record_type_status,
    igmp_record_type_summary, IgmpGroupRecord, IgmpRecordType, IgmpRecordTypeMeta,
    IgmpRecordTypeStatus,
};
pub use self::registry::{
    igmp_code_meta, igmp_code_name, igmp_code_status, igmp_query_flag, igmp_query_flag_meta,
    igmp_query_flag_name, igmp_query_flag_status, igmp_report_flag, igmp_report_flag_meta,
    igmp_report_flag_name, igmp_report_flag_status, igmp_type, igmp_type_meta, igmp_type_name,
    igmp_type_status, IgmpCodeMeta, IgmpFlagStatus, IgmpQueryFlag, IgmpQueryFlagMeta,
    IgmpReportFlag, IgmpReportFlagMeta, IgmpType, IgmpTypeMeta, IgmpTypeStatus,
};
pub use self::report::IgmpReport;
pub use self::validation::{
    igmp_group_address_class, igmp_group_address_class_name, IgmpGroupAddressClass,
    IGMP_ALL_ROUTERS_GROUP, IGMP_ALL_SYSTEMS_GROUP,
};
