//! ICMPv6 message bodies that ride on top of the [`Icmpv6`](super::Icmpv6)
//! header: Neighbor Discovery (RFC 4861), MLD (RFC 2710 / RFC 3810), node
//! information (RFC 4620), and extended echo (RFC 8335).
//!
//! This subtree groups the version-6-specific message families as typed bodies
//! that compose under an `Icmpv6` header, mirroring the way ICMPv4 layers its
//! timestamp / address-mask / quoted-IP bodies. It currently holds the shared
//! Neighbor Discovery option TLV framework
//! ([`ndp_option`]); the concrete NDP/MLD/node-info/extended-echo message bodies
//! are added in later steps.

pub mod ndp_option;
