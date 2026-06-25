//! Simple Network Management Protocol (SNMP) module scaffold.
//!
//! SNMP support is being added in source-backed slices. This module is only
//! the Rust home for those later slices; it does not expose a packet layer,
//! builders, decode entrypoint, or UDP registry dispatch yet.
//!
//! Source gate: any SNMP wire behavior added here must first be authorized by
//! `docs/snmp-rfc-manifest.md`.

mod ber;
mod constants;
mod decode;
mod message;
mod pdu;
mod registry;
mod value;
