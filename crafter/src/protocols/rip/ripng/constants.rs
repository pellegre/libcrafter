//! RIPng — RIP for IPv6 (RFC 2080) wire constants.
//!
//! Values come from RFC 2080 (RIPng for IPv6). These are kept separate from the
//! IPv4 `rip/constants.rs` because RIPng runs over a different UDP port, uses an
//! IPv6 multicast group, and carries a single-octet metric. Each constant cites
//! its defining RFC source in a line comment.

use std::net::Ipv6Addr;

// ---------------------------------------------------------------------------
// Fixed protocol constants (RFC 2080 §2)
// ---------------------------------------------------------------------------

/// RIPng UDP port. RFC 2080 §2.
pub const RIPNG_UDP_PORT: u16 = 521;
/// RIPng message header length (command, version, 2-octet reserved), in octets.
/// RFC 2080 §2.
pub const RIPNG_HEADER_LEN: usize = 4;
/// RIPng Route Table Entry (RTE) length, in octets. RFC 2080 §2.1.
pub const RIPNG_RTE_LEN: usize = 20;
/// Metric value denoting an unreachable destination (infinity). RFC 2080 §2.1.
pub const RIPNG_METRIC_INFINITY: u8 = 16;
/// Metric value marking a next-hop RTE. RFC 2080 §2.1.1.
pub const RIPNG_NEXT_HOP_METRIC: u8 = 0xFF;

// ---------------------------------------------------------------------------
// Version number (RFC 2080 §2)
// ---------------------------------------------------------------------------

/// RIPng version 1. RFC 2080 §2.
pub const RIPNG_VERSION_1: u8 = 1;

// ---------------------------------------------------------------------------
// Command codes (RFC 2080 §2.1)
// ---------------------------------------------------------------------------

/// Request command: ask a router for all or part of its routing table.
/// RFC 2080 §2.1.
pub const RIPNG_COMMAND_REQUEST: u8 = 1;
/// Response command: a routing table message, solicited or unsolicited.
/// RFC 2080 §2.1.
pub const RIPNG_COMMAND_RESPONSE: u8 = 2;

// ---------------------------------------------------------------------------
// Multicast group (RFC 2080 §2)
// ---------------------------------------------------------------------------

/// RIPng all-RIP-routers link-local multicast group (`ff02::9`). RFC 2080 §2.
pub const RIPNG_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 9);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ripng_constants_match_rfc() {
        // UDP port (RFC 2080 §2).
        assert_eq!(RIPNG_UDP_PORT, 521);

        // Header and RTE sizes (RFC 2080 §2 / §2.1).
        assert_eq!(RIPNG_HEADER_LEN, 4);
        assert_eq!(RIPNG_RTE_LEN, 20);

        // Unreachable metric and next-hop marker (RFC 2080 §2.1 / §2.1.1).
        assert_eq!(RIPNG_METRIC_INFINITY, 16);
        assert_eq!(RIPNG_NEXT_HOP_METRIC, 0xFF);

        // Version and command codes (RFC 2080 §2 / §2.1).
        assert_eq!(RIPNG_VERSION_1, 1);
        assert_eq!(RIPNG_COMMAND_REQUEST, 1);
        assert_eq!(RIPNG_COMMAND_RESPONSE, 2);

        // RIPng multicast group (RFC 2080 §2).
        assert_eq!(RIPNG_MULTICAST, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 9));
    }
}
