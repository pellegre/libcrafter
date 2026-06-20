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
pub use self::message::Igmp;
pub use self::registry::{
    igmp_code_meta, igmp_code_name, igmp_code_status, igmp_type, igmp_type_meta, igmp_type_name,
    igmp_type_status, IgmpCodeMeta, IgmpType, IgmpTypeMeta, IgmpTypeStatus,
};
