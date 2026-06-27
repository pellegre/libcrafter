//! DHCPv6 protocol-family home.
//!
//! This module is the target home for the DHCPv6 packet layer defined by
//! RFC 9915, "Dynamic Host Configuration Protocol for IPv6 (DHCPv6)", plus
//! public IANA DHCPv6 registry metadata and packet-data extensions.
//!
//! The module is intentionally a skeleton at this stage. It exposes no packet
//! builders, decoders, option types, or UDP bindings until later steps add
//! source-backed DHCPv6 wire behavior.

pub mod constants;
pub mod duid;
pub mod layer;
pub mod message;
pub mod option;
pub mod registry;
pub mod status;

pub use constants::*;
pub use duid::Dhcpv6Duid;
pub(crate) use layer::{append_dhcpv6_packet, looks_like_dhcpv6_payload};
pub use layer::{Dhcpv6, Dhcpv6RelayHeader};
pub use message::Dhcpv6MessageType;
pub use option::{
    Dhcpv6IaAddr, Dhcpv6IaNa, Dhcpv6IaPd, Dhcpv6Option, Dhcpv6OptionCode, Dhcpv6OptionFormat,
    Dhcpv6OptionValue,
};
pub use registry::{
    dhcpv6_option_meta, dhcpv6_option_name, dhcpv6_option_status, Dhcpv6ClientOro,
    Dhcpv6OptionMeta, Dhcpv6OptionSingleton, Dhcpv6OptionStatus,
};
pub use status::Dhcpv6StatusCode;
