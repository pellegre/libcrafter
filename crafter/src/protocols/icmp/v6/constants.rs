//! ICMPv6 (`ICMPV6_*`) codepoint constants.
//!
//! Moved verbatim out of `icmp/constants.rs` into the `icmp/v6/` subtree so the
//! ICMPv6 codepoints sit beside the [`Icmpv6`](super::Icmpv6) header that uses
//! them, mirroring the `icmp/v4/` layout. Nothing here changes wire behavior,
//! defaults, or the public API surface: these are re-exported back through
//! `icmp/constants.rs` (and, via `icmp/mod.rs`, the crate root and prelude), so
//! every existing path — `crate::protocols::icmp::ICMPV6_*`, the
//! `protocols::mod.rs` re-exports, and the prelude — keeps resolving to the same
//! names. The full IANA ICMPv6 type range is added in a later step; only the
//! six previously defined types live here for now.

/// ICMPv6 destination unreachable type.
pub const ICMPV6_DESTINATION_UNREACHABLE: u8 = 1;

/// ICMPv6 packet-too-big type.
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;

/// ICMPv6 time exceeded type.
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;

/// ICMPv6 parameter problem type.
pub const ICMPV6_PARAMETER_PROBLEM: u8 = 4;

/// ICMPv6 echo request type.
pub const ICMPV6_ECHO_REQUEST: u8 = 128;

/// ICMPv6 echo reply type.
pub const ICMPV6_ECHO_REPLY: u8 = 129;
