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

mod constants;
mod decode;
mod message;
mod query;
mod record;
mod registry;
mod report;
mod validation;
