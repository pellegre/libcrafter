//! Documentation-only addresses for tracked flow examples and tests.
//!
//! These constants use documentation ranges per repository policy and must be
//! used in tracked flows, examples, and tests instead of real network targets.

use std::net::Ipv4Addr;

use crafter::MacAddr;

/// Representative client address from `192.0.2.0/24`.
pub const CLIENT_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

/// Representative server address from `198.51.100.0/24`.
pub const SERVER_IPV4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

/// Sample gateway address from documentation space.
pub const GATEWAY_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// Sample DNS resolver address from documentation space.
pub const DNS_IPV4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 53);

/// Example client MAC address for offline flows and fixtures.
pub const CLIENT_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]);

/// Example local node MAC address for offline injection flows and fixtures.
pub const LOCAL_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x66]);

#[cfg(test)]
mod tests {
    use super::{CLIENT_IPV4, SERVER_IPV4};

    #[test]
    fn docaddr_client_and_server_ipv4_use_documentation_ranges() {
        assert_eq!(CLIENT_IPV4.octets()[0..3], [192, 0, 2]);
        assert_eq!(SERVER_IPV4.octets()[0..3], [198, 51, 100]);
    }
}
