//! MAC address parsing and formatting.

use core::fmt;
use core::str::FromStr;

use crate::error::CrafterError;

/// A six-octet Ethernet MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// The all-zero MAC address.
    pub const ZERO: Self = Self([0, 0, 0, 0, 0, 0]);

    /// The broadcast MAC address.
    pub const BROADCAST: Self = Self([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

    /// Create a MAC address from six octets.
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// Return the six address octets.
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// Return true when this address is the broadcast address.
    pub const fn is_broadcast(self) -> bool {
        self.0[0] == 0xff
            && self.0[1] == 0xff
            && self.0[2] == 0xff
            && self.0[3] == 0xff
            && self.0[4] == 0xff
            && self.0[5] == 0xff
    }

    /// Return true when the address is multicast or broadcast.
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 1 == 1
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(value: [u8; 6]) -> Self {
        Self(value)
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(value: MacAddr) -> Self {
        value.0
    }
}

impl AsRef<[u8; 6]> for MacAddr {
    fn as_ref(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = CrafterError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let separator = if input.contains(':') {
            ':'
        } else if input.contains('-') {
            '-'
        } else {
            return Err(CrafterError::invalid_mac_address(
                input,
                "expected ':' or '-' separators",
            ));
        };

        let mut octets = [0u8; 6];
        let mut count = 0usize;
        for part in input.split(separator) {
            if count == octets.len() {
                return Err(CrafterError::invalid_mac_address(
                    input,
                    "expected exactly six octets",
                ));
            }
            if part.len() != 2 {
                return Err(CrafterError::invalid_mac_address(
                    input,
                    "each octet must contain two hex digits",
                ));
            }
            octets[count] = u8::from_str_radix(part, 16).map_err(|_| {
                CrafterError::invalid_mac_address(input, "octet contains non-hex digits")
            })?;
            count += 1;
        }

        if count != octets.len() {
            return Err(CrafterError::invalid_mac_address(
                input,
                "expected exactly six octets",
            ));
        }

        Ok(Self(octets))
    }
}

#[cfg(test)]
mod field_primitives {
    use super::MacAddr;

    #[test]
    fn parses_colon_mac_address() {
        let mac: MacAddr = "02:00:5e:10:00:01".parse().unwrap();

        assert_eq!(mac.octets(), [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]);
        assert_eq!(mac.to_string(), "02:00:5e:10:00:01");
    }

    #[test]
    fn parses_hyphen_mac_address() {
        let mac: MacAddr = "AA-BB-CC-DD-EE-FF".parse().unwrap();

        assert_eq!(mac.octets(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn rejects_invalid_octet_count() {
        let err = "00:11:22:33:44".parse::<MacAddr>().unwrap_err();

        assert!(err.to_string().contains("six octets"));
    }

    #[test]
    fn rejects_invalid_hex() {
        let err = "00:11:22:33:44:xx".parse::<MacAddr>().unwrap_err();

        assert!(err.to_string().contains("non-hex"));
    }

    #[test]
    fn detects_broadcast_and_multicast_addresses() {
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(MacAddr::BROADCAST.is_multicast());
        assert!(!MacAddr::ZERO.is_multicast());
    }
}
