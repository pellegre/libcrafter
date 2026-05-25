use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use super::error::{NetError, Result};

const MAX_COLLECTED_IPS: u64 = 1_048_576;

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

fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}
