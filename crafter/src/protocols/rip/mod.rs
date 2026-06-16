//! Routing Information Protocol (RIP) support.
//!
//! RIP is a distance-vector interior gateway protocol. This module provides
//! packet-layer construction and decoding for RIP messages, added
//! incrementally across the governing specifications:
//!
//! - RFC 1058 — RIP version 1.
//! - RFC 2453 — RIP version 2.
//! - RFC 2080 — RIPng for IPv6 (RIPng).
//! - RFC 2082 / RFC 4822 — RIP version 2 cryptographic authentication.
//! - RFC 2091 — triggered (demand) RIP for on-demand circuits.
//!
//! Types and constants are populated in later steps; this module starts as an
//! empty scaffold so the rest of the crate has a stable home to build against.

pub mod constants;
pub mod entry;
pub mod message;
pub mod registry;

pub use constants::*;

use core::any::Any;
use core::ops::Div;

use crate::error::Result;
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use entry::RipEntry;
use message::RipCommand;

macro_rules! impl_layer_object {
    ($type:ty) => {
        fn clone_layer(&self) -> Box<dyn Layer> {
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }

        fn into_any(self: Box<Self>) -> Box<dyn Any> {
            self
        }
    };
}

macro_rules! impl_layer_div {
    ($type:ty) => {
        impl<R> Div<R> for $type
        where
            R: IntoPacket,
        {
            type Output = Packet;

            fn div(self, rhs: R) -> Self::Output {
                Packet::from_layer(self).concat(rhs)
            }
        }
    };
}

/// A Routing Information Protocol message over IPv4/UDP 520 (RFC 1058,
/// RFC 2453).
///
/// A `Rip` is the 4-octet RIP header (command, version, 2-octet reserved)
/// followed by zero or more fixed 20-octet route table entries
/// ([`RipEntry`]). The same layer covers RIP version 1 (RFC 1058) and
/// version 2 (RFC 2453): both share the header and the 20-octet entry slot
/// and differ only in how the previously-reserved entry fields are
/// interpreted, selected by the `version` field.
///
/// Header fields are held in [`Field`] wrappers so a later `compile()` step
/// can fill defaults (version, reserved) only when the caller left a field
/// unset and leave caller-set values — including deliberately wrong ones —
/// untouched. The builders mark touched fields caller-set via `set_user`.
///
/// The `command`/`entries` builders use `with_`-prefixed names so they do not
/// collide with the same-named [`Rip::command`]/[`Rip::entries`] accessors
/// (Rust rejects two inherent methods with the same name).
#[derive(Debug, Clone)]
pub struct Rip {
    /// RIP command octet (RFC 1058 §3.1); modeled as a raw code so unknown
    /// commands round-trip. Read it as a typed [`RipCommand`] via
    /// [`Rip::command`].
    pub command: Field<u8>,
    /// RIP version octet (RFC 1058 §3.1 / RFC 2453 §4).
    pub version: Field<u8>,
    /// Reserved 2-octet header field, must be zero (RFC 1058 §3.1).
    pub reserved: Field<u16>,
    /// Route table entries that follow the header (RFC 2453 §4).
    pub entries: Vec<RipEntry>,
}

impl Rip {
    /// Create a RIP message with library defaults.
    ///
    /// The command defaults to [`RipCommand::Response`], the version to
    /// [`RIP_VERSION_2`], the reserved field to `0`, and the entry list is
    /// empty. None of these defaults are marked caller-set, so a later
    /// `compile()` step may overwrite them.
    pub fn new() -> Self {
        Self {
            command: Field::defaulted(RIP_COMMAND_RESPONSE),
            version: Field::defaulted(RIP_VERSION_2),
            reserved: Field::defaulted(0),
            entries: Vec::new(),
        }
    }

    /// Build a RIP version 2 Request message (RFC 2453 §3.9.1).
    ///
    /// Sets the command to [`RipCommand::Request`] and the version to 2; both
    /// are marked caller-set.
    pub fn request() -> Self {
        Self::new()
            .with_command(RipCommand::Request)
            .version(RIP_VERSION_2)
    }

    /// Build a RIP version 2 Response message (RFC 2453 §3.9.2).
    ///
    /// Sets the command to [`RipCommand::Response`] and the version to 2; both
    /// are marked caller-set.
    pub fn response() -> Self {
        Self::new()
            .with_command(RipCommand::Response)
            .version(RIP_VERSION_2)
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
    /// The reserved field must be zero on the wire (RFC 1058 §3.1); this
    /// builder exists so generated tools can emit a deliberately non-zero
    /// value.
    pub fn reserved(mut self, reserved: u16) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Append a single route table entry.
    pub fn entry(mut self, entry: RipEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Replace the route table entries with the given list.
    pub fn with_entries(mut self, entries: impl Into<Vec<RipEntry>>) -> Self {
        self.entries = entries.into();
        self
    }

    /// Effective command wire code (caller-set or default).
    pub fn command_value(&self) -> u8 {
        self.command.value().copied().unwrap_or(RIP_COMMAND_RESPONSE)
    }

    /// Effective command as a typed [`RipCommand`] (caller-set or default).
    pub fn command(&self) -> RipCommand {
        RipCommand::from_code(self.command_value())
    }

    /// Effective version octet (caller-set or default).
    pub fn version_value(&self) -> u8 {
        self.version.value().copied().unwrap_or(RIP_VERSION_2)
    }

    /// Effective reserved header field (caller-set or default).
    pub fn reserved_value(&self) -> u16 {
        self.reserved.value().copied().unwrap_or(0)
    }

    /// The route table entries that follow the header.
    pub fn entries(&self) -> &[RipEntry] {
        &self.entries
    }
}

impl Default for Rip {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Rip {
    fn name(&self) -> &'static str {
        "Rip"
    }

    fn encoded_len(&self) -> usize {
        RIP_HEADER_LEN + self.entries.len() * RIP_ENTRY_LEN
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // RFC 1058 §3.1: 4-octet header (command, version, 2-octet reserved)
        // followed by each route entry's 20 octets. Effective values are used
        // as-is, so caller-set command/version/reserved (including deliberately
        // wrong ones) serialize exactly as set.
        out.reserve(self.encoded_len());
        out.push(self.command_value());
        out.push(self.version_value());
        out.extend_from_slice(&self.reserved_value().to_be_bytes());
        for entry in &self.entries {
            entry.encode(out);
        }
        Ok(())
    }

    fn summary(&self) -> String {
        // Compact one-line summary: command name, version, and entry count, e.g.
        // "Rip v2 Response (2 entries)". Uses effective values so a decoded or
        // caller-set message reads correctly.
        let count = self.entries.len();
        let plural = if count == 1 { "entry" } else { "entries" };
        format!(
            "Rip v{} {} ({} {})",
            self.version_value(),
            self.command().name(),
            count,
            plural
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        // Surface the header fields and entry count so decoded messages are
        // readable via show()/summary() without log-fishing.
        vec![
            ("command", self.command().name().to_string()),
            ("version", self.version_value().to_string()),
            ("reserved", self.reserved_value().to_string()),
            ("entries", self.entries.len().to_string()),
        ]
    }

    impl_layer_object!(Rip);
}

impl_layer_div!(Rip);

#[cfg(test)]
mod rip_layer_builder {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn rip_layer_builder_sets_header_and_entries() {
        // Request() reports a typed Request command and the default version 2.
        let request = Rip::request();
        assert_eq!(request.command(), RipCommand::Request);
        assert_eq!(request.command_value(), RIP_COMMAND_REQUEST);
        assert_eq!(request.version_value(), RIP_VERSION_2);
        assert!(request.entries().is_empty());

        // new() defaults to a Response command, version 2, reserved 0, no entries.
        let default = Rip::new();
        assert_eq!(default.command(), RipCommand::Response);
        assert_eq!(default.version_value(), RIP_VERSION_2);

        // .entry(..) appends entries in order.
        let route = RipEntry::ipv2_route(
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            3,
        );
        let with_one = Rip::response().entry(route.clone());
        assert_eq!(with_one.entries().len(), 1);
        assert_eq!(with_one.entries()[0], route);

        // with_entries(..) replaces the entry list.
        let second = RipEntry::ipv1_route(Ipv4Addr::new(198, 51, 100, 1), 5);
        let with_two = Rip::response().with_entries(vec![route.clone(), second.clone()]);
        assert_eq!(with_two.entries().len(), 2);
        assert_eq!(with_two.entries()[1], second);
    }
}

#[cfg(test)]
mod rip_layer_compiles {
    use super::*;
    use crate::packet::LayerContext;
    use crate::protocols::transport::Udp;
    use std::net::Ipv4Addr;

    #[test]
    fn rip_layer_compiles_header_and_entries() {
        let rip = Rip::response().entry(RipEntry::ipv2_route(
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            1,
        ));

        // Compile the layer in isolation via a single-layer packet context.
        let packet = Packet::from_layer(rip.clone());
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        rip.compile(&ctx, &mut out).expect("rip compiles");

        // RFC 1058 §3.1 header: command=Response(2), version=2, reserved=0.
        assert_eq!(&out[..RIP_HEADER_LEN], &[0x02, 0x02, 0x00, 0x00]);
        // Header plus one 20-octet entry.
        assert_eq!(out.len(), RIP_HEADER_LEN + RIP_ENTRY_LEN);
        assert_eq!(rip.encoded_len(), RIP_HEADER_LEN + RIP_ENTRY_LEN);
    }

    #[test]
    fn rip_layer_div_composes_into_packet() {
        let rip = Rip::response().entry(RipEntry::ipv2_route(
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            1,
        ));

        // The `/` operator composes a Udp datagram and a Rip layer into a Packet
        // whose layer stack includes the Rip layer.
        let packet = Udp::new() / rip;
        assert!(packet.layer::<Rip>().is_some());
    }
}

#[cfg(test)]
mod rip_layer_summary {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn rip_layer_summary_mentions_command_and_count() {
        // A Response with two entries reports its command name, version, and the
        // entry count in the summary line.
        let rip = Rip::response().with_entries(vec![
            RipEntry::ipv2_route(
                Ipv4Addr::new(192, 0, 2, 0),
                Ipv4Addr::new(255, 255, 255, 0),
                1,
            ),
            RipEntry::ipv2_route(
                Ipv4Addr::new(198, 51, 100, 0),
                Ipv4Addr::new(255, 255, 255, 0),
                2,
            ),
        ]);

        let summary = rip.summary();
        assert!(summary.contains("Response"), "summary: {summary}");
        assert!(summary.contains("v2"), "summary: {summary}");
        assert!(summary.contains('2'), "summary: {summary}");
    }

    #[test]
    fn rip_layer_inspection_fields_present() {
        // inspection_fields() exposes the header fields and entry count, keyed by
        // name like other layers.
        let rip = Rip::response().entry(RipEntry::ipv2_route(
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            1,
        ));

        let fields = rip.inspection_fields();
        assert!(
            fields.iter().any(|(key, _)| *key == "command"),
            "expected a \"command\" field: {fields:?}"
        );
        assert!(
            fields.iter().any(|(key, _)| *key == "entries"),
            "expected an \"entries\" field: {fields:?}"
        );
    }
}
