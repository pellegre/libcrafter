//! ICMPv6 message bodies that ride on top of the [`Icmpv6`](super::Icmpv6)
//! header: Neighbor Discovery (RFC 4861), MLD (RFC 2710 / RFC 3810), node
//! information (RFC 4620), and extended echo (RFC 8335).
//!
//! This subtree groups the version-6-specific message families as typed bodies
//! that compose under an `Icmpv6` header, mirroring the way ICMPv4 layers its
//! timestamp / address-mask / quoted-IP bodies. It holds the shared Neighbor
//! Discovery option TLV framework ([`ndp_option`]), the Neighbor Discovery
//! message bodies ([`ndp`]), and the RFC 8335 extended echo request / reply
//! builders ([`extended_echo`]); the remaining MLD / node-info message bodies
//! are added in later steps following the pattern documented in [`ndp`].

pub mod extended_echo;
pub mod ndp;
pub mod ndp_option;
