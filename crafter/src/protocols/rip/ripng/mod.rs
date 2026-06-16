//! RIPng — RIP for IPv6 (RFC 2080).
//!
//! RIPng is the IPv6 variant of the Routing Information Protocol. It runs over
//! UDP port 521 and uses the link-local multicast group `ff02::9` for periodic
//! and triggered responses. Following the project's explicit v4/v6 layer-naming
//! convention (mirroring `Icmpv4`/`Icmpv6`), RIPng is modeled as its own
//! `Ripng` layer rather than being folded into the IPv4 `Rip` layer.
//!
//! Types and constants are populated in later steps; this module starts as an
//! empty scaffold so the rest of the crate has a stable home to build against.

pub mod constants;
pub mod rte;

pub use constants::*;
pub use rte::RipngRte;

use crate::field::Field;
use crate::protocols::rip::message::RipCommand;

/// A RIPng message over IPv6/UDP 521 (RFC 2080 §2).
///
/// A `Ripng` is the 4-octet RIPng header (command, version, 2-octet reserved)
/// followed by zero or more fixed 20-octet route table entries
/// ([`RipngRte`]). RIPng is the IPv6 variant of RIP; following the project's
/// explicit v4/v6 layer-naming convention (mirroring `Icmpv4`/`Icmpv6`), it is
/// modeled as its own `Ripng` layer rather than folded into the IPv4 [`Rip`]
/// layer. The IPv4 [`RipCommand`] enum is reused for the command octet, since
/// RIPng shares the Request/Response codepoints (RFC 2080 §2.1).
///
/// [`Rip`]: crate::protocols::rip::Rip
///
/// Header fields are held in [`Field`] wrappers so a later `compile()` step can
/// fill defaults (version, reserved) only when the caller left a field unset and
/// leave caller-set values — including deliberately wrong ones — untouched. The
/// builders mark touched fields caller-set via `set_user`.
///
/// The `command`/`rtes` builders use `with_`-prefixed names so they do not
/// collide with the same-named [`Ripng::command`]/[`Ripng::rtes`] accessors
/// (Rust rejects two inherent methods with the same name).
#[derive(Debug, Clone)]
pub struct Ripng {
    /// RIPng command octet (RFC 2080 §2.1); modeled as a raw code so unknown
    /// commands round-trip. Read it as a typed [`RipCommand`] via
    /// [`Ripng::command`].
    pub command: Field<u8>,
    /// RIPng version octet (RFC 2080 §2).
    pub version: Field<u8>,
    /// Reserved 2-octet header field, must be zero (RFC 2080 §2).
    pub reserved: Field<u16>,
    /// Route table entries that follow the header (RFC 2080 §2.1).
    pub rtes: Vec<RipngRte>,
}

impl Ripng {
    /// Create a RIPng message with library defaults.
    ///
    /// The command defaults to [`RipCommand::Response`], the version to
    /// [`RIPNG_VERSION_1`], the reserved field to `0`, and the RTE list is
    /// empty. None of these defaults are marked caller-set, so a later
    /// `compile()` step may overwrite them.
    pub fn new() -> Self {
        Self {
            command: Field::defaulted(RIPNG_COMMAND_RESPONSE),
            version: Field::defaulted(RIPNG_VERSION_1),
            reserved: Field::defaulted(0),
            rtes: Vec::new(),
        }
    }

    /// Build a RIPng Request message (RFC 2080 §2.1).
    ///
    /// Sets the command to [`RipCommand::Request`] and the version to
    /// [`RIPNG_VERSION_1`]; both are marked caller-set.
    pub fn request() -> Self {
        Self::new()
            .with_command(RipCommand::Request)
            .version(RIPNG_VERSION_1)
    }

    /// Build a RIPng Response message (RFC 2080 §2.1).
    ///
    /// Sets the command to [`RipCommand::Response`] and the version to
    /// [`RIPNG_VERSION_1`]; both are marked caller-set.
    pub fn response() -> Self {
        Self::new()
            .with_command(RipCommand::Response)
            .version(RIPNG_VERSION_1)
    }

    /// Set the command from a typed [`RipCommand`] (caller-set).
    ///
    /// Stores the command's wire code via [`RipCommand::code`].
    pub fn with_command(mut self, command: RipCommand) -> Self {
        self.command.set_user(command.code());
        self
    }

    /// Set the command from a raw wire code (caller-set).
    ///
    /// Use this to emit an unrecognized command octet verbatim.
    pub fn command_code(mut self, code: u8) -> Self {
        self.command.set_user(code);
        self
    }

    /// Set the version octet (caller-set).
    pub fn version(mut self, version: u8) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the reserved header field (caller-set).
    ///
    /// The reserved field must be zero on the wire (RFC 2080 §2); this builder
    /// exists so generated tools can emit a deliberately non-zero value.
    pub fn reserved(mut self, reserved: u16) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Append a single route table entry.
    pub fn rte(mut self, rte: RipngRte) -> Self {
        self.rtes.push(rte);
        self
    }

    /// Replace the route table entries with the given list.
    pub fn with_rtes(mut self, rtes: impl Into<Vec<RipngRte>>) -> Self {
        self.rtes = rtes.into();
        self
    }

    /// Effective command wire code (caller-set or default).
    pub fn command_value(&self) -> u8 {
        self.command
            .value()
            .copied()
            .unwrap_or(RIPNG_COMMAND_RESPONSE)
    }

    /// Effective command as a typed [`RipCommand`] (caller-set or default).
    pub fn command(&self) -> RipCommand {
        RipCommand::from_code(self.command_value())
    }

    /// Effective version octet (caller-set or default).
    pub fn version_value(&self) -> u8 {
        self.version.value().copied().unwrap_or(RIPNG_VERSION_1)
    }

    /// Effective reserved header field (caller-set or default).
    pub fn reserved_value(&self) -> u16 {
        self.reserved.value().copied().unwrap_or(0)
    }

    /// The route table entries that follow the header.
    pub fn rtes(&self) -> &[RipngRte] {
        &self.rtes
    }
}

impl Default for Ripng {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod ripng_layer_builder {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn ripng_layer_builder_sets_header_and_rtes() {
        // response() reports a typed Response command and version 1.
        let response = Ripng::response();
        assert_eq!(response.command(), RipCommand::Response);
        assert_eq!(response.command_value(), RIPNG_COMMAND_RESPONSE);
        assert_eq!(response.version_value(), RIPNG_VERSION_1);
        assert!(response.rtes().is_empty());

        // request() reports a typed Request command and version 1.
        let request = Ripng::request();
        assert_eq!(request.command(), RipCommand::Request);
        assert_eq!(request.command_value(), RIPNG_COMMAND_REQUEST);
        assert_eq!(request.version_value(), RIPNG_VERSION_1);

        // new() defaults to a Response command, version 1, reserved 0, no RTEs.
        let default = Ripng::new();
        assert_eq!(default.command(), RipCommand::Response);
        assert_eq!(default.version_value(), RIPNG_VERSION_1);
        assert_eq!(default.reserved_value(), 0);
        assert!(default.rtes().is_empty());

        // .rte(..) appends RTEs in order.
        let prefix = "2001:db8::".parse::<Ipv6Addr>().expect("valid prefix");
        let route = RipngRte::route(prefix, 32, 3);
        let with_one = Ripng::response().rte(route.clone());
        assert_eq!(with_one.rtes().len(), 1);
        assert_eq!(with_one.rtes()[0], route);

        // with_rtes(..) replaces the RTE list.
        let second = RipngRte::route(
            "2001:db8:1::".parse::<Ipv6Addr>().expect("valid prefix"),
            48,
            5,
        );
        let with_two = Ripng::response().with_rtes(vec![route.clone(), second.clone()]);
        assert_eq!(with_two.rtes().len(), 2);
        assert_eq!(with_two.rtes()[1], second);
    }
}
