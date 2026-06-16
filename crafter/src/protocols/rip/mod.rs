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

pub mod auth;
pub mod constants;
pub mod entry;
pub mod message;
pub mod registry;

pub use constants::*;
pub use entry::RipEntry;
pub use message::RipCommand;
pub use registry::{RipAddressFamily, RipAuthType, RipCommandMeta, RipCommandStatus};

use core::any::Any;
use core::ops::Div;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

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

/// Decode a UDP payload into a [`Rip`] layer (RFC 1058 §3.1, RFC 2453 §4).
///
/// A RIP message is the 4-octet header (command, version, 2-octet reserved)
/// followed by a whole number of 20-octet route table entries. The header
/// command, version, and reserved fields are marked caller-set (`set_user`) so
/// the decoded layer re-`compile()`s byte-for-byte, and each entry is parsed
/// with [`RipEntry::decode`].
///
/// Decoding never panics on a short or partial buffer. A body shorter than
/// [`RIP_HEADER_LEN`] yields the crate's structured
/// [`CrafterError::buffer_too_short`] with context `"RIP header"`; a trailing
/// run of bytes that is not a whole multiple of [`RIP_ENTRY_LEN`] yields the
/// same structured error for the partial entry rather than dropping bytes.
///
/// The RFC 2453 §4 25-entry limit is a generation guideline, not a decode-time
/// rejection: every present entry is decoded.
pub fn decode(bytes: &[u8]) -> Result<Rip> {
    if bytes.len() < RIP_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "RIP header",
            RIP_HEADER_LEN,
            bytes.len(),
        ));
    }

    let command = bytes[0];
    let version = bytes[1];
    let reserved = u16::from_be_bytes([bytes[2], bytes[3]]);

    let mut rip = Rip::new();
    rip.command.set_user(command);
    rip.version.set_user(version);
    rip.reserved.set_user(reserved);

    let mut rest = &bytes[RIP_HEADER_LEN..];
    while !rest.is_empty() {
        let entry = RipEntry::decode(rest)?;
        rip.entries.push(entry);
        rest = &rest[RIP_ENTRY_LEN..];
    }

    Ok(rip)
}

/// Build a complete RIPv2 multicast response packet (RFC 2453 §3.5).
///
/// RIPv2 sends its periodic and triggered routing updates to the well-known
/// multicast group [`RIP_V2_MULTICAST`] (`224.0.0.9`) over UDP port
/// [`RIP_UDP_PORT`] (520). This convenience assembles that stack with the
/// project's layer composition idiom and returns a typed [`Packet`]:
///
/// - an [`Ipv4`](crate::protocols::ip::v4::Ipv4) layer whose source is `source`
///   and whose destination is the well-known RIPv2 multicast group
///   [`RIP_V2_MULTICAST`],
/// - a [`Udp`](crate::protocols::transport::Udp) datagram with source and
///   destination port [`RIP_UDP_PORT`], and
/// - a [`Rip::response`] message at [`RIP_VERSION_2`] carrying `entries`.
///
/// Lengths and checksums are left for [`Packet::compile`] to fill. Callers
/// supply a documentation-range source address (`192.0.2.0/24`,
/// `198.51.100.0/24`); the destination is fixed to the RIPv2 multicast group.
pub fn rip_v2_multicast_response(
    source: std::net::Ipv4Addr,
    entries: impl Into<Vec<RipEntry>>,
) -> Packet {
    use crate::protocols::ip::v4::Ipv4;
    use crate::protocols::transport::Udp;

    Ipv4::new().src(source).dst(RIP_V2_MULTICAST)
        / Udp::new().sport(RIP_UDP_PORT).dport(RIP_UDP_PORT)
        / Rip::response().version(RIP_VERSION_2).with_entries(entries)
}

/// Build a complete RIPv1 whole-table request packet (RFC 1058 §3.4.1).
///
/// A RIP node asks a neighbor for its full routing table by sending a Request
/// message carrying a single special entry: address family 0 with metric 16
/// (infinity), the whole-table sentinel (RFC 1058 §3.4.1, RFC 2453 §3.9.1).
/// Step 11's [`RipEntry::whole_table_request`] builds that sentinel entry.
///
/// This convenience assembles the request stack with the project's layer
/// composition idiom and returns a typed [`Packet`]:
///
/// - an [`Ipv4`](crate::protocols::ip::v4::Ipv4) layer whose source is `source`
///   and whose destination is `destination`,
/// - a [`Udp`](crate::protocols::transport::Udp) datagram with source and
///   destination port [`RIP_UDP_PORT`] (520), and
/// - a [`Rip::request`] message pinned to [`RIP_VERSION_1`] carrying the single
///   whole-table sentinel entry.
///
/// Lengths and checksums are left for [`Packet::compile`] to fill. Callers
/// supply documentation-range addresses (`192.0.2.0/24`, `198.51.100.0/24`).
pub fn rip_v1_whole_table_request(
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
) -> Packet {
    use crate::protocols::ip::v4::Ipv4;
    use crate::protocols::transport::Udp;

    Ipv4::new().src(source).dst(destination)
        / Udp::new().sport(RIP_UDP_PORT).dport(RIP_UDP_PORT)
        / Rip::request()
            .version(RIP_VERSION_1)
            .entry(RipEntry::whole_table_request())
}

/// Build a complete RIPv2 whole-table request packet (RFC 2453 §3.9.1).
///
/// Like [`rip_v1_whole_table_request`] but pinned to [`RIP_VERSION_2`] and
/// addressed to the well-known RIPv2 multicast group [`RIP_V2_MULTICAST`]
/// (`224.0.0.9`). The single entry is the whole-table sentinel (address
/// family 0, metric 16) of RFC 1058 §3.4.1 / RFC 2453 §3.9.1.
///
/// This convenience assembles the request stack with the project's layer
/// composition idiom and returns a typed [`Packet`]:
///
/// - an [`Ipv4`](crate::protocols::ip::v4::Ipv4) layer whose source is `source`
///   and whose destination is [`RIP_V2_MULTICAST`],
/// - a [`Udp`](crate::protocols::transport::Udp) datagram with source and
///   destination port [`RIP_UDP_PORT`] (520), and
/// - a [`Rip::request`] message at [`RIP_VERSION_2`] carrying the single
///   whole-table sentinel entry.
///
/// Lengths and checksums are left for [`Packet::compile`] to fill. Callers
/// supply a documentation-range source address (`192.0.2.0/24`,
/// `198.51.100.0/24`); the destination is fixed to the RIPv2 multicast group.
pub fn rip_v2_whole_table_request(source: std::net::Ipv4Addr) -> Packet {
    use crate::protocols::ip::v4::Ipv4;
    use crate::protocols::transport::Udp;

    Ipv4::new().src(source).dst(RIP_V2_MULTICAST)
        / Udp::new().sport(RIP_UDP_PORT).dport(RIP_UDP_PORT)
        / Rip::request()
            .version(RIP_VERSION_2)
            .entry(RipEntry::whole_table_request())
}

/// Append a decoded RIP message to an existing packet stack.
///
/// Mirrors the DHCP UDP-application decode entry: [`decode`] parses the UDP
/// payload into a [`Rip`] layer, which is then pushed onto the packet. Used by
/// the protocol registry's conservative UDP/520 binding.
pub(crate) fn append_rip_packet(packet: Packet, bytes: &[u8]) -> Result<Packet> {
    Ok(packet.push(decode(bytes)?))
}

/// Return true when bytes have enough RIP structure to bind on UDP/520.
///
/// The check is deliberately conservative so unrelated traffic on port 520
/// falls through to `Raw` rather than misdecoding as `Rip`: the payload must be
/// at least the 4-octet header ([`RIP_HEADER_LEN`]), the command must be a known
/// RIP command (Request/Response 1/2 or the RFC 2091 demand commands 9/10/11),
/// the version must be 1 or 2, and the bytes after the header must be a whole
/// multiple of the 20-octet entry length ([`RIP_ENTRY_LEN`]).
pub(crate) fn looks_like_rip_payload(bytes: &[u8]) -> bool {
    if bytes.len() < RIP_HEADER_LEN {
        return false;
    }
    let command = bytes[0];
    let version = bytes[1];
    matches!(command, 1 | 2 | 9 | 10 | 11)
        && matches!(version, RIP_VERSION_1 | RIP_VERSION_2)
        && (bytes.len() - RIP_HEADER_LEN) % RIP_ENTRY_LEN == 0
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

#[cfg(test)]
mod rip_decode_roundtrips_response {
    use super::*;
    use crate::packet::LayerContext;
    use std::net::Ipv4Addr;

    fn compile_bytes(rip: &Rip) -> Vec<u8> {
        let packet = Packet::from_layer(rip.clone());
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        rip.compile(&ctx, &mut out).expect("rip compiles");
        out
    }

    #[test]
    fn decode_reproduces_header_and_entries_and_recompiles_identically() {
        // A two-entry Response, compiled to wire bytes.
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
        let bytes = compile_bytes(&rip);

        // Decode reproduces the header fields and the two entries.
        let decoded = decode(&bytes).expect("two-entry response decodes");
        assert_eq!(decoded.command(), rip.command());
        assert_eq!(decoded.command_value(), rip.command_value());
        assert_eq!(decoded.version_value(), rip.version_value());
        assert_eq!(decoded.reserved_value(), rip.reserved_value());

        // Entries round-trip by effective value. (Derived PartialEq on RipEntry
        // is Field-variant-sensitive: decode marks every field caller-set, while
        // the built entries leave route_tag/next_hop defaulted, so compare the
        // effective values rather than the wrapper variants.)
        assert_eq!(decoded.entries().len(), rip.entries().len());
        for (got, want) in decoded.entries().iter().zip(rip.entries()) {
            assert_eq!(got.address_family_value(), want.address_family_value());
            assert_eq!(got.route_tag_value(), want.route_tag_value());
            assert_eq!(got.address_value(), want.address_value());
            assert_eq!(got.subnet_mask_value(), want.subnet_mask_value());
            assert_eq!(got.next_hop_value(), want.next_hop_value());
            assert_eq!(got.metric_value(), want.metric_value());
        }

        // Re-compiling the decoded layer yields byte-identical output.
        let recompiled = compile_bytes(&decoded);
        assert_eq!(recompiled, bytes);
    }
}

#[cfg(test)]
mod rip_decode_partial_entry_is_error {
    use super::*;

    #[test]
    fn header_plus_partial_entry_returns_structured_error_without_panic() {
        // 4-octet header followed by 10 octets: a partial (non-multiple-of-20)
        // trailing entry must surface a structured length error, not a panic.
        let mut bytes = vec![RIP_COMMAND_RESPONSE, RIP_VERSION_2, 0x00, 0x00];
        bytes.extend_from_slice(&[0u8; 10]);

        let err = decode(&bytes).expect_err("partial trailing entry is an error");

        match err {
            CrafterError::BufferTooShort {
                required,
                available,
                ..
            } => {
                // The partial entry needs a full 20 octets but only 10 remain.
                assert_eq!(required, RIP_ENTRY_LEN);
                assert_eq!(available, 10);
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod rip_udp_binding {
    use super::*;
    use crate::packet::{NetworkLayer, Raw};
    use crate::protocols::ip::v4::Ipv4;
    use crate::protocols::transport::Udp;
    use std::net::Ipv4Addr;

    #[test]
    fn rip_decodes_from_udp_520() {
        // An IPv4/UDP(520)/Rip Response with one route entry.
        let rip = Rip::response().entry(RipEntry::ipv2_route(
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            1,
        ));
        let packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::new().sport(RIP_UDP_PORT).dport(RIP_UDP_PORT)
            / rip;

        let compiled = packet.compile().expect("rip stack compiles");

        // The conservative UDP/520 binding routes the payload to the Rip decoder.
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())
            .expect("ipv4/udp/rip decodes");

        let decoded_rip = decoded
            .layer::<Rip>()
            .expect("decoded packet includes a Rip layer");
        assert_eq!(decoded_rip.command(), RipCommand::Response);
        assert_eq!(decoded_rip.entries().len(), 1);
        assert!(decoded.layer::<Raw>().is_none());
    }

    #[test]
    fn rip_non_rip_udp_520_stays_raw() {
        // A UDP/520 datagram whose payload fails looks_like_rip_payload: an
        // unknown command (0xFF) with a non-multiple-of-20 trailing length, so it
        // must fall through to Raw rather than decode as Rip.
        let payload = vec![0xFFu8, 0xFF, 0x00, 0x00, 0x01, 0x02, 0x03];
        assert!(
            !looks_like_rip_payload(&payload),
            "fixture payload must not look like RIP"
        );

        let packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::new().sport(RIP_UDP_PORT).dport(RIP_UDP_PORT)
            / Raw::from_bytes(&payload);

        let compiled = packet.compile().expect("udp/raw stack compiles");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())
            .expect("ipv4/udp/raw decodes");

        assert!(
            decoded.layer::<Rip>().is_none(),
            "non-RIP port-520 payload must not decode as Rip"
        );
        assert!(
            decoded.layer::<Raw>().is_some(),
            "non-RIP port-520 payload must remain Raw"
        );
    }
}

#[cfg(test)]
mod rip_v2_multicast_response_helper {
    use super::*;
    use crate::packet::NetworkLayer;
    use std::net::Ipv4Addr;

    #[test]
    fn rip_v2_multicast_response_targets_group() {
        // Build a RIPv2 multicast response from a documentation source address,
        // carrying a single IPv4 route entry.
        let packet = rip_v2_multicast_response(
            Ipv4Addr::new(192, 0, 2, 1),
            vec![RipEntry::ipv2_route(
                Ipv4Addr::new(192, 0, 2, 0),
                Ipv4Addr::new(255, 255, 255, 0),
                1,
            )],
        );

        let compiled = packet.compile().expect("multicast response compiles");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())
            .expect("ipv4/udp/rip multicast response decodes");

        // The IPv4 destination is the well-known RIPv2 multicast group.
        let ipv4 = decoded
            .layer::<crate::protocols::ip::v4::Ipv4>()
            .expect("decoded packet includes an Ipv4 layer");
        assert_eq!(ipv4.destination(), RIP_V2_MULTICAST);
        assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 9));

        // The UDP destination port is the RIP port (520).
        let udp = decoded
            .layer::<crate::protocols::transport::Udp>()
            .expect("decoded packet includes a Udp layer");
        assert_eq!(udp.destination_port_value(), RIP_UDP_PORT);
        assert_eq!(udp.destination_port_value(), 520);

        // A Rip layer is present in the decoded stack.
        assert!(
            decoded.layer::<Rip>().is_some(),
            "decoded packet must include a Rip layer"
        );
    }
}

#[cfg(test)]
mod rip_whole_table_request_helpers {
    use super::*;
    use crate::packet::NetworkLayer;
    use std::net::Ipv4Addr;

    // Decode the helper-built packet and return its Rip layer, asserting the
    // command is Request and the single entry is the whole-table sentinel
    // (RFC 1058 §3.4.1, RFC 2453 §3.9.1).
    fn assert_whole_table_request(packet: Packet) -> Packet {
        let compiled = packet.compile().expect("whole-table request compiles");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())
            .expect("ipv4/udp/rip whole-table request decodes");

        let rip = decoded
            .layer::<Rip>()
            .expect("decoded packet includes a Rip layer");
        assert_eq!(rip.command(), RipCommand::Request);
        assert_eq!(rip.entries().len(), 1, "request carries a single entry");
        assert!(
            rip.entries()[0].is_whole_table_request(),
            "the single entry is the whole-table sentinel"
        );

        decoded
    }

    #[test]
    fn rip_whole_table_requests_build() {
        // RIPv1 whole-table request to a documentation unicast destination.
        let v1 = rip_v1_whole_table_request(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 2),
        );
        let v1_decoded = assert_whole_table_request(v1);
        let v1_rip = v1_decoded
            .layer::<Rip>()
            .expect("v1 decoded packet includes a Rip layer");
        assert_eq!(v1_rip.version_value(), RIP_VERSION_1);

        // RIPv2 whole-table request to the well-known multicast group.
        let v2 = rip_v2_whole_table_request(Ipv4Addr::new(192, 0, 2, 1));
        let v2_decoded = assert_whole_table_request(v2);
        let v2_rip = v2_decoded
            .layer::<Rip>()
            .expect("v2 decoded packet includes a Rip layer");
        assert_eq!(v2_rip.version_value(), RIP_VERSION_2);

        // The v2 helper targets the RIPv2 multicast group 224.0.0.9.
        let v2_ipv4 = v2_decoded
            .layer::<crate::protocols::ip::v4::Ipv4>()
            .expect("v2 decoded packet includes an Ipv4 layer");
        assert_eq!(v2_ipv4.destination(), RIP_V2_MULTICAST);
        assert_eq!(v2_ipv4.destination(), Ipv4Addr::new(224, 0, 0, 9));
    }
}
