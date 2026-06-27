//! DHCPv6 protocol-family home.
//!
//! This module is the target home for the DHCPv6 packet layer defined by
//! RFC 9915, "Dynamic Host Configuration Protocol for IPv6 (DHCPv6)", plus
//! public IANA DHCPv6 registry metadata and packet-data extensions.
//!
//! The module exposes packet builders, decoders, typed option helpers, UDP
//! bindings, and registry metadata while keeping unknown codepoints and payloads
//! round-trip safe.
//!
//! DHCPv6 Authentication is packet data only. The crate can encode and decode
//! the option fields, but it never derives keys, signs messages, verifies MACs,
//! or interprets authentication secrets.

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
    Dhcpv6AuthAlgorithm, Dhcpv6AuthProtocol, Dhcpv6Authentication, Dhcpv6BootfileParam,
    Dhcpv6ClientArchitecture, Dhcpv6ClientFqdn, Dhcpv6ClientLinkLayerAddress, Dhcpv6DomainList,
    Dhcpv6IaAddr, Dhcpv6IaNa, Dhcpv6IaPd, Dhcpv6IaPrefix, Dhcpv6NetworkInterfaceIdentifier,
    Dhcpv6NtpServer, Dhcpv6NtpSuboption, Dhcpv6Option, Dhcpv6OptionCode, Dhcpv6OptionFormat,
    Dhcpv6OptionValue, Dhcpv6PdExclude, Dhcpv6RelaySuppliedOptions, Dhcpv6RemoteId,
    Dhcpv6ReplayDetectionMethod, Dhcpv6S46Container, Dhcpv6S46ContainerKind, Dhcpv6S46Priority,
    Dhcpv6StatusCodeOption, Dhcpv6UserClass, Dhcpv6VendorClass, Dhcpv6VendorOption,
    Dhcpv6VendorOptions,
};
pub use registry::{
    dhcpv6_option_meta, dhcpv6_option_name, dhcpv6_option_status, dhcpv6_rsoo_option_permission,
    dhcpv6_rsoo_option_permitted, dhcpv6_s46_priority_option_permission,
    dhcpv6_s46_priority_option_permitted, Dhcpv6ClientOro, Dhcpv6OptionMeta, Dhcpv6OptionSingleton,
    Dhcpv6OptionStatus, Dhcpv6RsooOptionPermission, Dhcpv6S46PriorityOptionPermission,
};
pub use status::Dhcpv6StatusCode;
