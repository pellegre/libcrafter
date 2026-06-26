//! DHCPv4 protocol-family home.
//!
//! This module is the target home for the DHCPv4 packet layer and its
//! IPv4/BOOTP option model. It mirrors the versioned family layout used by
//! `crafter/src/protocols/ip/` and `crafter/src/protocols/icmp/`.
//!
//! The implementation remains in the DHCP family root until the follow-up
//! rename and move steps place the DHCPv4 layer, constants, message types,
//! option codec, and registry metadata under this subtree.
