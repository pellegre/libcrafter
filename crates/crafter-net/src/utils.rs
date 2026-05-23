use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crafter_core::{Arp, Ethernet, MacAddr, Packet};
use pnet_datalink as datalink;

use crate::{NetError, Result, SendRecv};

const MAX_COLLECTED_IPS: u64 = 1_048_576;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Range {
    addresses: Vec<Ipv4Addr>,
}

impl Ipv4Range {
    /// Parse a range expression.
    pub fn parse(input: &str) -> Result<Self> {
        parse_ipv4_range(input)
    }

    /// Borrow parsed addresses in deterministic order.
    pub fn addresses(&self) -> &[Ipv4Addr] {
        &self.addresses
    }

    /// Number of addresses in the range.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Return true when the range contains no addresses.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Return true when the range contains the address.
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        self.addresses.contains(&address)
    }

    /// Iterate over addresses by value.
    pub fn iter(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.addresses.iter().copied()
    }

    fn from_addresses(input: &str, addresses: Vec<Ipv4Addr>) -> Result<Self> {
        if addresses.len() as u64 > MAX_COLLECTED_IPS {
            return Err(NetError::InvalidIpRange {
                input: input.to_string(),
                reason: "range expands past the collection safety limit",
            });
        }
        Ok(Self { addresses })
    }
}

impl IntoIterator for Ipv4Range {
    type Item = Ipv4Addr;
    type IntoIter = std::vec::IntoIter<Ipv4Addr>;

    fn into_iter(self) -> Self::IntoIter {
        self.addresses.into_iter()
    }
}

/// Options for live-lab-safe ARP resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpResolveOptions {
    interface: Option<String>,
    timeout: Duration,
    retries: usize,
    dry_run: bool,
    source_ip: Option<Ipv4Addr>,
    source_mac: Option<MacAddr>,
}

impl ArpResolveOptions {
    /// Create ARP options. Defaults to dry-run planning.
    pub fn new() -> Self {
        Self {
            interface: None,
            timeout: Duration::from_secs(1),
            retries: 3,
            dry_run: true,
            source_ip: None,
            source_mac: None,
        }
    }

    /// Select the interface used for ARP.
    pub fn interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
    }

    /// Scapy/libcrafter-style alias for [`Self::interface`].
    pub fn iface(self, interface: impl Into<String>) -> Self {
        self.interface(interface)
    }

    /// Set the capture timeout per attempt.
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the number of attempts. Zero is treated as one attempt.
    pub fn retries(mut self, retries: usize) -> Self {
        self.retries = retries.max(1);
        self
    }

    /// libcrafter-style singular alias for [`Self::retries`].
    pub fn retry(self, retries: usize) -> Self {
        self.retries(retries)
    }

    /// Keep the operation compile-only.
    pub const fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Allow live ARP send/receive. Use only in a disposable live lab.
    pub const fn live(mut self) -> Self {
        self.dry_run = false;
        self
    }

    /// Override the sender IPv4 address.
    pub const fn source_ip(mut self, source_ip: Ipv4Addr) -> Self {
        self.source_ip = Some(source_ip);
        self
    }

    /// Override the sender MAC address.
    pub const fn source_mac(mut self, source_mac: MacAddr) -> Self {
        self.source_mac = Some(source_mac);
        self
    }
}

impl Default for ArpResolveOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&str> for ArpResolveOptions {
    fn from(interface: &str) -> Self {
        Self::new().interface(interface)
    }
}

impl From<String> for ArpResolveOptions {
    fn from(interface: String) -> Self {
        Self::new().interface(interface)
    }
}

/// Report returned by ARP resolution.
#[derive(Debug, Clone)]
pub struct ArpResolveReport {
    interface: String,
    target: Ipv4Addr,
    request: Packet,
    reply: Option<Packet>,
    mac: Option<MacAddr>,
    dry_run: bool,
}

impl ArpResolveReport {
    fn new(
        interface: String,
        target: Ipv4Addr,
        request: Packet,
        reply: Option<Packet>,
        mac: Option<MacAddr>,
        dry_run: bool,
    ) -> Self {
        Self {
            interface,
            target,
            request,
            reply,
            mac,
            dry_run,
        }
    }

    /// Interface used for the request.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Target IPv4 address being resolved.
    pub const fn target(&self) -> Ipv4Addr {
        self.target
    }

    /// Crafted ARP request packet.
    pub fn request(&self) -> &Packet {
        &self.request
    }

    /// Matching ARP reply, if captured.
    pub fn reply(&self) -> Option<&Packet> {
        self.reply.as_ref()
    }

    /// Resolved MAC address, if available.
    pub const fn mac(&self) -> Option<MacAddr> {
        self.mac
    }

    /// Return true when no live traffic was sent.
    pub const fn is_dry_run(&self) -> bool {
        self.dry_run
    }
}

/// Return a stable snapshot of local interfaces.
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

/// Resolve a neighbor MAC address. IPv4 uses live ARP only when options opt in.
pub fn resolve_mac(
    address: IpAddr,
    options: impl Into<ArpResolveOptions>,
) -> Result<Option<MacAddr>> {
    match address {
        IpAddr::V4(ipv4) => Ok(arp_resolve(ipv4, options)?.mac()),
        IpAddr::V6(ipv6) => Ok(Some(derive_mac_from_ipv6(ipv6))),
    }
}

/// libcrafter-style helper returning one MAC address or a structured error.
///
/// IPv4 resolution sends live ARP only when called through this convenience
/// function. Prefer [`arp_resolve`] with explicit options in generated tools.
pub fn get_mac(address: IpAddr, interface: impl AsRef<str>) -> Result<MacAddr> {
    match address {
        IpAddr::V4(target) => {
            let report = arp_resolve(
                target,
                ArpResolveOptions::new().iface(interface.as_ref()).live(),
            )?;
            report.mac().ok_or(NetError::ArpResolutionTimedOut {
                target,
                interface: report.interface().to_string(),
            })
        }
        IpAddr::V6(address) => Ok(derive_mac_from_ipv6(address)),
    }
}

/// Build and optionally run an ARP request for an IPv4 neighbor.
pub fn arp_resolve(
    target: Ipv4Addr,
    options: impl Into<ArpResolveOptions>,
) -> Result<ArpResolveReport> {
    let options = options.into();
    let table = interfaces();
    let interface = select_interface(options.interface.as_deref().unwrap_or(""), &table)?;
    let source_ip = match options.source_ip {
        Some(source_ip) => source_ip,
        None => interface
            .first_ipv4()
            .ok_or_else(|| NetError::InterfaceAddressNotFound {
                name: interface.name().to_string(),
                family: "ipv4",
            })?,
    };
    let source_mac = match options.source_mac {
        Some(source_mac) => source_mac,
        None => interface
            .mac_address()
            .ok_or_else(|| NetError::InterfaceMacNotFound {
                name: interface.name().to_string(),
            })?,
    };

    let request = Ethernet::new().src(source_mac).dst(MacAddr::BROADCAST)
        / Arp::who_has(source_ip, target, source_mac);

    let mut send_recv = SendRecv::new()
        .iface(interface.name().to_string())
        .timeout(options.timeout)
        .retries(options.retries)
        .link_layer();
    if options.dry_run {
        send_recv = send_recv.dry_run();
    } else {
        send_recv = send_recv.live();
    }

    let report = send_recv.send_recv_report(&request)?;
    let reply = report.into_reply();
    let mac = reply
        .as_ref()
        .and_then(|packet| packet.layer::<Arp>())
        .and_then(Arp::sender_mac);

    Ok(ArpResolveReport::new(
        interface.name().to_string(),
        target,
        request,
        reply,
        mac,
        options.dry_run,
    ))
}

/// Derive a MAC address from an IPv6 EUI-64 style interface identifier.
pub fn derive_mac_from_ipv6(address: Ipv6Addr) -> MacAddr {
    let octets = address.octets();
    MacAddr::new([
        octets[8] ^ 0x02,
        octets[9],
        octets[10],
        octets[13],
        octets[14],
        octets[15],
    ])
}

/// Parse libcrafter/nmap-style IPv4 targets.
pub fn parse_ip_range(input: &str) -> Result<Ipv4Range> {
    parse_ipv4_range(input)
}

/// libcrafter-style range helper returning IPv4 addresses.
pub fn get_ips(input: &str) -> Result<Vec<Ipv4Addr>> {
    Ok(parse_ip_range(input)?.addresses().to_vec())
}

/// libcrafter-style range helper returning display strings.
pub fn get_ip_strings(input: &str) -> Result<Vec<String>> {
    Ok(get_ips(input)?
        .into_iter()
        .map(|addr| addr.to_string())
        .collect())
}

/// Parse comma-separated numbers and inclusive ranges.
pub fn parse_numbers(input: &str) -> Result<Vec<u16>> {
    let input = input.trim();
    if input.is_empty() {
        return Err(NetError::InvalidIpRange {
            input: input.to_string(),
            reason: "number range must not be empty",
        });
    }

    let mut numbers = BTreeSet::new();
    for token in input.split(',') {
        parse_number_token(input, token.trim(), &mut numbers)?;
    }
    Ok(numbers.into_iter().collect())
}

fn parse_ipv4_range(input: &str) -> Result<Ipv4Range> {
    let input = input.trim();
    if input.is_empty() {
        return Err(NetError::InvalidIpRange {
            input: input.to_string(),
            reason: "range must not be empty",
        });
    }

    if let Some(range) = parse_ipv4_cidr(input)? {
        return Ok(range);
    }
    if let Some(range) = parse_ipv4_full_bounds(input)? {
        return Ok(range);
    }

    parse_ipv4_component_range(input)
}

fn parse_ipv4_cidr(input: &str) -> Result<Option<Ipv4Range>> {
    let Some((addr, prefix)) = input.split_once('/') else {
        return Ok(None);
    };
    let addr: Ipv4Addr = addr.trim().parse().map_err(|_| NetError::InvalidIpRange {
        input: input.to_string(),
        reason: "invalid IPv4 CIDR address",
    })?;
    let prefix: u8 = prefix
        .trim()
        .parse()
        .map_err(|_| NetError::InvalidIpRange {
            input: input.to_string(),
            reason: "invalid IPv4 CIDR prefix",
        })?;
    if prefix > 32 {
        return Err(NetError::InvalidIpRange {
            input: input.to_string(),
            reason: "IPv4 CIDR prefix must be at most 32",
        });
    }

    let mask = ipv4_mask(prefix);
    let network = u32::from(addr) & mask;
    let size = 1u64 << (32 - prefix);
    if size > MAX_COLLECTED_IPS {
        return Err(NetError::InvalidIpRange {
            input: input.to_string(),
            reason: "CIDR range expands past the collection safety limit",
        });
    }

    let addresses = (0..size)
        .map(|offset| Ipv4Addr::from(network + offset as u32))
        .collect();
    Ok(Some(Ipv4Range { addresses }))
}

fn parse_ipv4_full_bounds(input: &str) -> Result<Option<Ipv4Range>> {
    let Some((left, right)) = input.split_once('-') else {
        return Ok(None);
    };
    if left.contains(',') || right.contains(',') {
        return Ok(None);
    }
    let Ok(left) = left.trim().parse::<Ipv4Addr>() else {
        return Ok(None);
    };
    let Ok(right) = right.trim().parse::<Ipv4Addr>() else {
        return Ok(None);
    };

    let start = u32::from(left);
    let end = u32::from(right);
    if start > end {
        return Err(NetError::InvalidIpRange {
            input: input.to_string(),
            reason: "range start must not exceed range end",
        });
    }
    let size = u64::from(end - start) + 1;
    if size > MAX_COLLECTED_IPS {
        return Err(NetError::InvalidIpRange {
            input: input.to_string(),
            reason: "range expands past the collection safety limit",
        });
    }

    let addresses = (start..=end).map(Ipv4Addr::from).collect();
    Ok(Some(Ipv4Range { addresses }))
}

fn parse_ipv4_component_range(input: &str) -> Result<Ipv4Range> {
    let parts = input.split('.').collect::<Vec<_>>();
    if parts.len() != 4 {
        return Err(NetError::InvalidIpRange {
            input: input.to_string(),
            reason: "IPv4 range must contain four octets",
        });
    }

    let octets = [
        parse_octet_set(input, parts[0])?,
        parse_octet_set(input, parts[1])?,
        parse_octet_set(input, parts[2])?,
        parse_octet_set(input, parts[3])?,
    ];
    let size = octets
        .iter()
        .map(|values| values.len() as u64)
        .product::<u64>();
    if size > MAX_COLLECTED_IPS {
        return Err(NetError::InvalidIpRange {
            input: input.to_string(),
            reason: "range expands past the collection safety limit",
        });
    }

    let mut addresses = Vec::with_capacity(size as usize);
    for a in &octets[0] {
        for b in &octets[1] {
            for c in &octets[2] {
                for d in &octets[3] {
                    addresses.push(Ipv4Addr::new(*a, *b, *c, *d));
                }
            }
        }
    }
    Ipv4Range::from_addresses(input, addresses)
}

fn parse_octet_set(input: &str, part: &str) -> Result<Vec<u8>> {
    let part = part.trim();
    if part.is_empty() {
        return Err(NetError::InvalidIpRange {
            input: input.to_string(),
            reason: "octet must not be empty",
        });
    }

    let mut values = BTreeSet::new();
    for token in part.split(',') {
        let token = token.trim();
        if token == "*" {
            values.extend(0..=u8::MAX);
        } else if let Some((left, right)) = token.split_once('-') {
            let left = parse_octet(input, left)?;
            let right = parse_octet(input, right)?;
            if left > right {
                return Err(NetError::InvalidIpRange {
                    input: input.to_string(),
                    reason: "octet range start must not exceed range end",
                });
            }
            values.extend(left..=right);
        } else {
            values.insert(parse_octet(input, token)?);
        }
    }

    Ok(values.into_iter().collect())
}

fn parse_octet(input: &str, token: &str) -> Result<u8> {
    token
        .trim()
        .parse::<u8>()
        .map_err(|_| NetError::InvalidIpRange {
            input: input.to_string(),
            reason: "octet must be a number from 0 through 255",
        })
}

fn parse_number_token(input: &str, token: &str, numbers: &mut BTreeSet<u16>) -> Result<()> {
    if token.is_empty() {
        return Err(NetError::InvalidIpRange {
            input: input.to_string(),
            reason: "number token must not be empty",
        });
    }
    if let Some((left, right)) = token.split_once('-') {
        let left = parse_number(input, left)?;
        let right = parse_number(input, right)?;
        if left > right {
            return Err(NetError::InvalidIpRange {
                input: input.to_string(),
                reason: "number range start must not exceed range end",
            });
        }
        numbers.extend(left..=right);
    } else {
        numbers.insert(parse_number(input, token)?);
    }
    Ok(())
}

fn parse_number(input: &str, token: &str) -> Result<u16> {
    token
        .trim()
        .parse::<u16>()
        .map_err(|_| NetError::InvalidIpRange {
            input: input.to_string(),
            reason: "number must be from 0 through 65535",
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

#[cfg(test)]
mod ip_ranges {
    use std::net::Ipv4Addr;

    use super::{get_ip_strings, get_ips, parse_ip_range, parse_numbers, Ipv4Range};

    #[test]
    fn parses_libcrafter_wildcard_range() {
        let range = Ipv4Range::parse("192.168.0.*").unwrap();

        assert_eq!(range.len(), 256);
        assert_eq!(range.addresses()[0], Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(range.addresses()[255], Ipv4Addr::new(192, 168, 0, 255));
        assert!(range.contains(Ipv4Addr::new(192, 168, 0, 42)));
    }

    #[test]
    fn parses_per_octet_lists_and_ranges_in_order() {
        let ips = get_ips("10.0,2.1-2.7,9").unwrap();

        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(10, 0, 1, 7),
                Ipv4Addr::new(10, 0, 1, 9),
                Ipv4Addr::new(10, 0, 2, 7),
                Ipv4Addr::new(10, 0, 2, 9),
                Ipv4Addr::new(10, 2, 1, 7),
                Ipv4Addr::new(10, 2, 1, 9),
                Ipv4Addr::new(10, 2, 2, 7),
                Ipv4Addr::new(10, 2, 2, 9),
            ]
        );
    }

    #[test]
    fn parses_cidr_and_full_ip_bounds() {
        assert_eq!(
            get_ips("192.0.2.4/30").unwrap(),
            vec![
                Ipv4Addr::new(192, 0, 2, 4),
                Ipv4Addr::new(192, 0, 2, 5),
                Ipv4Addr::new(192, 0, 2, 6),
                Ipv4Addr::new(192, 0, 2, 7),
            ]
        );
        assert_eq!(
            get_ip_strings("192.0.2.9-192.0.2.11").unwrap(),
            vec!["192.0.2.9", "192.0.2.10", "192.0.2.11"]
        );
    }

    #[test]
    fn parses_number_ranges_compatibly() {
        assert_eq!(
            parse_numbers("80,443,1000-1002").unwrap(),
            vec![80, 443, 1000, 1001, 1002]
        );
    }

    #[test]
    fn rejects_malformed_ranges() {
        assert!(parse_ip_range("192.168.0").is_err());
        assert!(parse_ip_range("192.168.0.5-3").is_err());
        assert!(parse_ip_range("192.168.0.300").is_err());
        assert!(parse_ip_range("*.*.*.*").is_err());
    }
}

#[cfg(test)]
mod interface_helpers {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crafter_core::MacAddr;

    use super::{
        default_interface_in, find_interface_in, get_my_ip_in, get_my_ipv6_in, get_my_mac_in,
        interface_for_in, InterfaceAddress, InterfaceInfo,
    };

    fn table() -> Vec<InterfaceInfo> {
        vec![
            InterfaceInfo::new("lo")
                .up(true)
                .running(true)
                .loopback(true)
                .ipv4(Ipv4Addr::new(127, 0, 0, 1), 8),
            InterfaceInfo::new("eth0")
                .up(true)
                .running(true)
                .mac(MacAddr::new([0x02, 0, 0, 0, 0, 1]))
                .ipv4(Ipv4Addr::new(192, 0, 2, 10), 24)
                .ipv6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64)
                .ipv6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 10), 64),
            InterfaceInfo::new("down0")
                .mac(MacAddr::new([0x02, 0, 0, 0, 0, 2]))
                .ipv4(Ipv4Addr::new(198, 51, 100, 10), 24),
        ]
    }

    #[test]
    fn selects_default_non_loopback_interface() {
        let default = default_interface_in(&table()).unwrap();

        assert_eq!(default.name(), "eth0");
        assert_eq!(default.first_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
    }

    #[test]
    fn finds_interface_and_addresses_from_mock_table() {
        let table = table();

        assert_eq!(find_interface_in("eth0", &table).unwrap().name(), "eth0");
        assert_eq!(
            get_my_mac_in("eth0", &table).unwrap(),
            MacAddr::new([0x02, 0, 0, 0, 0, 1])
        );
        assert_eq!(
            get_my_ip_in("eth0", &table).unwrap(),
            Ipv4Addr::new(192, 0, 2, 10)
        );
    }

    #[test]
    fn ipv6_helper_can_skip_link_local_addresses() {
        let table = table();

        assert_eq!(
            get_my_ipv6_in("eth0", true, &table).unwrap(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
        );
        assert_eq!(
            get_my_ipv6_in("eth0", false, &table).unwrap(),
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 10)
        );
    }

    #[test]
    fn route_hint_prefers_matching_prefix_before_default() {
        let table = vec![
            InterfaceInfo::new("eth0")
                .up(true)
                .running(true)
                .ipv4(Ipv4Addr::new(192, 0, 2, 10), 24),
            InterfaceInfo::new("eth1")
                .up(true)
                .running(true)
                .ipv4(Ipv4Addr::new(198, 51, 100, 10), 24),
        ];

        let selected =
            interface_for_in(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99)), &table).unwrap();
        assert_eq!(selected.name(), "eth1");
    }

    #[test]
    fn interface_address_contains_same_prefix() {
        let address = InterfaceAddress::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 25);

        assert!(address.contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100))));
        assert!(!address.contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200))));
    }
}
