//! Routing Information Protocol (RIPv1/RIPv2) wire constants.
//!
//! Values come from RFC 1058 (RIP version 1) and RFC 2453 (RIP version 2),
//! plus the IANA Address Family Numbers registry. RIPng (RFC 2080) constants
//! live under the RIPng submodule, added in a later step. Each constant cites
//! its defining RFC / IANA source in a line comment.

use std::net::Ipv4Addr;

// ---------------------------------------------------------------------------
// Fixed protocol constants (RFC 1058 §3.1, RFC 2453 §4)
// ---------------------------------------------------------------------------

/// RIP UDP port for IPv4 RIP. RFC 1058 §3.1 / IANA service registry.
pub const RIP_UDP_PORT: u16 = 520;
/// RIP message header length (command, version, 2-octet reserved), in octets.
/// RFC 1058 §3.1 / RFC 2453 §4.
pub const RIP_HEADER_LEN: usize = 4;
/// RIP route entry length, in octets. RFC 1058 §3.1 / RFC 2453 §4.
pub const RIP_ENTRY_LEN: usize = 20;
/// Maximum route entries per RIP message (generation guideline). RFC 2453 §4.
pub const RIP_MAX_ENTRIES: usize = 25;
/// Metric value denoting an unreachable destination (infinity). RFC 1058 §3.1.
pub const RIP_METRIC_INFINITY: u32 = 16;

// ---------------------------------------------------------------------------
// Command codes (RFC 1058 §3.1, RFC 2453 §4)
// ---------------------------------------------------------------------------

/// Request command: ask a router for all or part of its routing table.
/// RFC 1058 §3.1.
pub const RIP_COMMAND_REQUEST: u8 = 1;
/// Response command: a routing table message, solicited or unsolicited.
/// RFC 1058 §3.1.
pub const RIP_COMMAND_RESPONSE: u8 = 2;

// ---------------------------------------------------------------------------
// Demand/triggered-RIP command codes (RFC 2091 §2.3)
// ---------------------------------------------------------------------------

/// Update Request command: demand-RIP request for routes on an on-demand
/// circuit. RFC 2091 §2.3.
pub const RIP_COMMAND_UPDATE_REQUEST: u8 = 9;
/// Update Response command: demand-RIP routing update on an on-demand circuit.
/// RFC 2091 §2.3.
pub const RIP_COMMAND_UPDATE_RESPONSE: u8 = 10;
/// Update Acknowledge command: demand-RIP acknowledgement of an Update
/// Response. RFC 2091 §2.3.
pub const RIP_COMMAND_UPDATE_ACK: u8 = 11;

// ---------------------------------------------------------------------------
// Version numbers (RFC 1058 §3.1, RFC 2453 §4)
// ---------------------------------------------------------------------------

/// RIP version 1. RFC 1058 §3.1.
pub const RIP_VERSION_1: u8 = 1;
/// RIP version 2. RFC 2453 §4.
pub const RIP_VERSION_2: u8 = 2;

// ---------------------------------------------------------------------------
// Address Family Identifiers (IANA Address Family Numbers; RFC 2453 §4.1)
// ---------------------------------------------------------------------------

/// IP (IPv4) address family identifier carried in a route entry.
/// IANA Address Family Numbers.
pub const RIP_AFI_IP: u16 = 2;
/// Authentication entry marker address family. RFC 2453 §4.1.
pub const RIP_AFI_AUTH: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// Multicast group (RFC 2453 §3.5)
// ---------------------------------------------------------------------------

/// RIPv2 IPv4 multicast group for periodic responses. RFC 2453 §3.5.
pub const RIP_V2_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 9);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rip_constants_match_rfc() {
        // Header and entry sizes (RFC 1058 §3.1 / RFC 2453 §4).
        assert_eq!(RIP_HEADER_LEN, 4);
        assert_eq!(RIP_ENTRY_LEN, 20);
        assert_eq!(RIP_MAX_ENTRIES, 25);

        // Unreachable metric (RFC 1058 §3.1).
        assert_eq!(RIP_METRIC_INFINITY, 16);

        // UDP port, command codes, versions, and AFIs.
        assert_eq!(RIP_UDP_PORT, 520);
        assert_eq!(RIP_COMMAND_REQUEST, 1);
        assert_eq!(RIP_COMMAND_RESPONSE, 2);

        // Demand/triggered-RIP command codes (RFC 2091 §2.3).
        assert_eq!(RIP_COMMAND_UPDATE_REQUEST, 9);
        assert_eq!(RIP_COMMAND_UPDATE_RESPONSE, 10);
        assert_eq!(RIP_COMMAND_UPDATE_ACK, 11);
        assert_eq!(RIP_VERSION_1, 1);
        assert_eq!(RIP_VERSION_2, 2);
        assert_eq!(RIP_AFI_IP, 2);
        assert_eq!(RIP_AFI_AUTH, 0xFFFF);

        // RIPv2 multicast group (RFC 2453 §3.5).
        assert_eq!(RIP_V2_MULTICAST, Ipv4Addr::new(224, 0, 0, 9));
    }
}
