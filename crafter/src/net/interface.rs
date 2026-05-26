use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::MacAddr;
use pnet_datalink as datalink;

use super::error::{NetError, Result};

/// One IP address assigned to a network interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceAddress {
    address: IpAddr,
    prefix_len: u8,
}

impl InterfaceAddress {
    /// Create an interface address with a prefix length.
    pub fn new(address: IpAddr, prefix_len: u8) -> Self {
        let max_prefix = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self {
            address,
            prefix_len: prefix_len.min(max_prefix),
        }
    }

    /// The host address.
    pub const fn address(&self) -> IpAddr {
        self.address
    }

    /// The network prefix length.
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Return true when this is an IPv4 address.
    pub const fn is_ipv4(&self) -> bool {
        matches!(self.address, IpAddr::V4(_))
    }

    /// Return true when this is an IPv6 address.
    pub const fn is_ipv6(&self) -> bool {
        matches!(self.address, IpAddr::V6(_))
    }

    /// Return true when `candidate` belongs to this address prefix.
    pub fn contains(&self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(base), IpAddr::V4(candidate)) => {
                ipv4_in_prefix(candidate, base, self.prefix_len)
            }
            (IpAddr::V6(base), IpAddr::V6(candidate)) => {
                ipv6_in_prefix(candidate, base, self.prefix_len)
            }
            _ => false,
        }
    }
}

/// Stable interface snapshot used by generated tools and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    name: String,
    description: String,
    index: u32,
    mac: Option<MacAddr>,
    addresses: Vec<InterfaceAddress>,
    flags: u64,
    up: bool,
    loopback: bool,
    running: bool,
}

impl InterfaceInfo {
    /// Create a mockable interface snapshot.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            index: 0,
            mac: None,
            addresses: Vec::new(),
            flags: 0,
            up: false,
            loopback: false,
            running: false,
        }
    }

    /// Snapshot a pnet interface into the stable public type.
    pub fn from_pnet(interface: &datalink::NetworkInterface) -> Self {
        let mac = interface.mac.map(|mac| MacAddr::new(mac.octets()));
        let addresses = interface
            .ips
            .iter()
            .map(|network| InterfaceAddress::new(network.ip(), network.prefix()))
            .collect();

        Self {
            name: interface.name.clone(),
            description: interface.description.clone(),
            index: interface.index,
            mac,
            addresses,
            flags: interface.flags as u64,
            up: interface.is_up(),
            loopback: interface.is_loopback(),
            running: interface_is_running(interface),
        }
    }

    /// Set a human-readable description.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set the platform interface index.
    pub const fn index(mut self, index: u32) -> Self {
        self.index = index;
        self
    }

    /// Set the MAC address.
    pub fn mac(mut self, mac: impl Into<MacAddr>) -> Self {
        self.mac = Some(mac.into());
        self
    }

    /// Add an interface address.
    pub fn address(mut self, address: IpAddr, prefix_len: u8) -> Self {
        self.addresses
            .push(InterfaceAddress::new(address, prefix_len));
        self
    }

    /// Add an IPv4 address.
    pub fn ipv4(self, address: Ipv4Addr, prefix_len: u8) -> Self {
        self.address(IpAddr::V4(address), prefix_len)
    }

    /// Add an IPv6 address.
    pub fn ipv6(self, address: Ipv6Addr, prefix_len: u8) -> Self {
        self.address(IpAddr::V6(address), prefix_len)
    }

    /// Set whether the interface is up.
    pub const fn up(mut self, up: bool) -> Self {
        self.up = up;
        self
    }

    /// Set whether the interface is loopback.
    pub const fn loopback(mut self, loopback: bool) -> Self {
        self.loopback = loopback;
        self
    }

    /// Set whether the interface is running.
    pub const fn running(mut self, running: bool) -> Self {
        self.running = running;
        self
    }

    /// Interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Interface description.
    pub fn description_value(&self) -> &str {
        &self.description
    }

    /// Platform interface index.
    pub const fn index_value(&self) -> u32 {
        self.index
    }

    /// Platform flags as a stable unsigned value.
    pub const fn flags(&self) -> u64 {
        self.flags
    }

    /// Interface MAC address.
    pub const fn mac_address(&self) -> Option<MacAddr> {
        self.mac
    }

    /// Assigned interface addresses.
    pub fn addresses(&self) -> &[InterfaceAddress] {
        &self.addresses
    }

    /// IPv4 addresses assigned to the interface.
    pub fn ipv4_addresses(&self) -> Vec<Ipv4Addr> {
        self.addresses
            .iter()
            .filter_map(|address| match address.address() {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
            })
            .collect()
    }

    /// IPv6 addresses assigned to the interface.
    pub fn ipv6_addresses(&self) -> Vec<Ipv6Addr> {
        self.addresses
            .iter()
            .filter_map(|address| match address.address() {
                IpAddr::V4(_) => None,
                IpAddr::V6(ip) => Some(ip),
            })
            .collect()
    }

    /// First IPv4 address, if present.
    pub fn first_ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4_addresses().into_iter().next()
    }

    /// First IPv6 address, optionally skipping link-local addresses.
    pub fn first_ipv6(&self, include_link_local: bool) -> Option<Ipv6Addr> {
        self.ipv6_addresses()
            .into_iter()
            .find(|addr| include_link_local || !is_ipv6_link_local(*addr))
    }

    /// Return true when the interface is reported up.
    pub const fn is_up(&self) -> bool {
        self.up
    }

    /// Return true when the interface is loopback.
    pub const fn is_loopback(&self) -> bool {
        self.loopback
    }

    /// Return true when the platform reports the interface as running.
    pub const fn is_running(&self) -> bool {
        self.running
    }

    /// Return true when this is a useful default interface candidate.
    pub fn is_default_candidate(&self) -> bool {
        self.is_up()
            && !self.is_loopback()
            && (self.first_ipv4().is_some() || self.first_ipv6(true).is_some())
    }

    /// Return true when any assigned address contains `destination`.
    pub fn contains_destination(&self, destination: IpAddr) -> bool {
        self.addresses
            .iter()
            .any(|address| address.contains(destination))
    }
}

/// Parsed IPv4 target range compatible with libcrafter's wildcard examples.
pub fn interfaces() -> Vec<InterfaceInfo> {
    datalink::interfaces()
        .iter()
        .map(InterfaceInfo::from_pnet)
        .collect()
}

/// Find an interface by exact name.
pub fn find_interface(name: impl AsRef<str>) -> Result<InterfaceInfo> {
    find_interface_in(name, &interfaces())
}

/// Find an interface in a supplied interface table.
pub fn find_interface_in(name: impl AsRef<str>, table: &[InterfaceInfo]) -> Result<InterfaceInfo> {
    let name = name.as_ref();
    validate_interface_name(name)?;
    table
        .iter()
        .find(|interface| interface.name() == name)
        .cloned()
        .ok_or_else(|| NetError::InterfaceNotFound {
            name: name.to_string(),
        })
}

/// Select a likely default interface from the local interface table.
pub fn default_interface() -> Result<InterfaceInfo> {
    default_interface_in(&interfaces())
}

/// Select a likely default interface from a supplied table.
pub fn default_interface_in(table: &[InterfaceInfo]) -> Result<InterfaceInfo> {
    table
        .iter()
        .find(|interface| interface.is_default_candidate() && interface.is_running())
        .or_else(|| {
            table
                .iter()
                .find(|interface| interface.is_default_candidate())
        })
        .cloned()
        .ok_or(NetError::NoDefaultInterface)
}

/// Return the likely default interface name.
pub fn default_interface_name() -> Result<String> {
    Ok(default_interface()?.name().to_string())
}

/// Select an interface that can directly reach `destination`, falling back to default.
pub fn interface_for(destination: IpAddr) -> Result<InterfaceInfo> {
    interface_for_in(destination, &interfaces())
}

/// Select an interface for `destination` from a supplied table.
pub fn interface_for_in(destination: IpAddr, table: &[InterfaceInfo]) -> Result<InterfaceInfo> {
    table
        .iter()
        .find(|interface| {
            interface.is_up()
                && !interface.is_loopback()
                && interface.contains_destination(destination)
        })
        .cloned()
        .or_else(|| default_interface_in(table).ok())
        .ok_or(NetError::NoDefaultInterface)
}

/// Get the selected interface MAC address.
pub fn get_my_mac(interface: impl AsRef<str>) -> Result<MacAddr> {
    get_my_mac_in(interface, &interfaces())
}

/// Get the selected interface MAC address from a supplied table.
pub fn get_my_mac_in(interface: impl AsRef<str>, table: &[InterfaceInfo]) -> Result<MacAddr> {
    let interface = select_interface(interface.as_ref(), table)?;
    interface
        .mac_address()
        .ok_or_else(|| NetError::InterfaceMacNotFound {
            name: interface.name().to_string(),
        })
}

/// Get the selected interface IPv4 address.
pub fn get_my_ip(interface: impl AsRef<str>) -> Result<Ipv4Addr> {
    get_my_ip_in(interface, &interfaces())
}

/// Get the selected interface IPv4 address from a supplied table.
pub fn get_my_ip_in(interface: impl AsRef<str>, table: &[InterfaceInfo]) -> Result<Ipv4Addr> {
    let interface = select_interface(interface.as_ref(), table)?;
    interface
        .first_ipv4()
        .ok_or_else(|| NetError::InterfaceAddressNotFound {
            name: interface.name().to_string(),
            family: "ipv4",
        })
}

/// Get the selected interface IPv6 address.
pub fn get_my_ipv6(interface: impl AsRef<str>, include_link_local: bool) -> Result<Ipv6Addr> {
    get_my_ipv6_in(interface, include_link_local, &interfaces())
}

/// Get the selected interface IPv6 address from a supplied table.
pub fn get_my_ipv6_in(
    interface: impl AsRef<str>,
    include_link_local: bool,
    table: &[InterfaceInfo],
) -> Result<Ipv6Addr> {
    let interface = select_interface(interface.as_ref(), table)?;
    interface
        .first_ipv6(include_link_local)
        .ok_or_else(|| NetError::InterfaceAddressNotFound {
            name: interface.name().to_string(),
            family: "ipv6",
        })
}

fn select_interface(name: &str, table: &[InterfaceInfo]) -> Result<InterfaceInfo> {
    if name.trim().is_empty() {
        default_interface_in(table)
    } else {
        find_interface_in(name, table)
    }
}

fn validate_interface_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(NetError::InvalidInterfaceName {
            name: name.to_string(),
            reason: "interface name must not be empty",
        });
    }
    if name.as_bytes().contains(&0) {
        return Err(NetError::InvalidInterfaceName {
            name: name.to_string(),
            reason: "interface name must not contain NUL bytes",
        });
    }
    Ok(())
}

fn is_ipv6_link_local(address: Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

fn ipv4_in_prefix(candidate: Ipv4Addr, base: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = ipv4_mask(prefix_len.min(32));
    (u32::from(candidate) & mask) == (u32::from(base) & mask)
}

fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn ipv6_in_prefix(candidate: Ipv6Addr, base: Ipv6Addr, prefix_len: u8) -> bool {
    let prefix_len = prefix_len.min(128);
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    let candidate = u128::from_be_bytes(candidate.octets());
    let base = u128::from_be_bytes(base.octets());
    (candidate & mask) == (base & mask)
}

#[cfg(unix)]
fn interface_is_running(interface: &datalink::NetworkInterface) -> bool {
    interface.is_running()
}

#[cfg(not(unix))]
fn interface_is_running(interface: &datalink::NetworkInterface) -> bool {
    interface.is_up()
}
