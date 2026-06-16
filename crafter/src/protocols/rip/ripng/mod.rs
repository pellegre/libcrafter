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

use core::any::Any;
use core::ops::Div;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};
use crate::protocols::rip::message::RipCommand;

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

impl Layer for Ripng {
    fn name(&self) -> &'static str {
        "Ripng"
    }

    fn encoded_len(&self) -> usize {
        // RFC 2080 §2: 4-octet header plus 20 octets per route table entry.
        RIPNG_HEADER_LEN + self.rtes.len() * RIPNG_RTE_LEN
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // RFC 2080 §2: 4-octet header (command, version, 2-octet reserved)
        // followed by each route table entry's 20 octets. Effective values are
        // used as-is, so caller-set command/version/reserved (including
        // deliberately wrong ones) serialize exactly as set.
        out.reserve(self.encoded_len());
        out.push(self.command_value());
        out.push(self.version_value());
        out.extend_from_slice(&self.reserved_value().to_be_bytes());

        for rte in &self.rtes {
            rte.encode(out);
        }
        Ok(())
    }

    fn summary(&self) -> String {
        // Compact one-line summary: command name, version, and RTE count, e.g.
        // "Ripng v1 Response (2 RTEs)". Uses effective values so a decoded or
        // caller-set message reads correctly.
        let count = self.rtes.len();
        let plural = if count == 1 { "RTE" } else { "RTEs" };
        format!(
            "Ripng v{} {} ({} {})",
            self.version_value(),
            self.command().name(),
            count,
            plural
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        // Surface the header fields and RTE count so decoded messages are
        // readable via show()/summary() without log-fishing.
        vec![
            ("command", self.command().name().to_string()),
            ("version", self.version_value().to_string()),
            ("reserved", self.reserved_value().to_string()),
            ("rtes", self.rtes.len().to_string()),
        ]
    }

    impl_layer_object!(Ripng);
}

impl_layer_div!(Ripng);

/// Decode a UDP payload into a [`Ripng`] layer (RFC 2080 §2).
///
/// A RIPng message is the 4-octet header (command, version, 2-octet reserved)
/// followed by a whole number of 20-octet route table entries. The header
/// command, version, and reserved fields are marked caller-set (`set_user`) so
/// the decoded layer re-`compile()`s byte-for-byte, and each RTE is parsed with
/// [`RipngRte::decode`].
///
/// Decoding never panics on a short or partial buffer. A body shorter than
/// [`RIPNG_HEADER_LEN`] yields the crate's structured
/// [`CrafterError::buffer_too_short`] with context `"RIPng header"`; a trailing
/// run of bytes that is not a whole multiple of [`RIPNG_RTE_LEN`] yields the
/// same structured error for the partial RTE rather than dropping bytes.
///
/// The RFC 2080 §2.1 25-RTE limit is a generation guideline, not a decode-time
/// rejection: every present RTE is decoded.
pub fn decode(bytes: &[u8]) -> Result<Ripng> {
    if bytes.len() < RIPNG_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "RIPng header",
            RIPNG_HEADER_LEN,
            bytes.len(),
        ));
    }

    let command = bytes[0];
    let version = bytes[1];
    let reserved = u16::from_be_bytes([bytes[2], bytes[3]]);

    let mut ripng = Ripng::new();
    ripng.command.set_user(command);
    ripng.version.set_user(version);
    ripng.reserved.set_user(reserved);

    let mut rest = &bytes[RIPNG_HEADER_LEN..];
    while !rest.is_empty() {
        let rte = RipngRte::decode(rest)?;
        ripng.rtes.push(rte);
        rest = &rest[RIPNG_RTE_LEN..];
    }

    Ok(ripng)
}

/// Append a decoded RIPng message to an existing packet stack.
///
/// Mirrors the RIP UDP-application decode entry: [`decode`] parses the UDP
/// payload into a [`Ripng`] layer, which is then pushed onto the packet. Used by
/// the protocol registry's conservative UDP/521 binding.
pub(crate) fn append_ripng_packet(packet: Packet, bytes: &[u8]) -> Result<Packet> {
    Ok(packet.push(decode(bytes)?))
}

/// Return true when bytes have enough RIPng structure to bind on UDP/521.
///
/// The check is deliberately conservative so unrelated traffic on port 521
/// falls through to `Raw` rather than misdecoding as `Ripng`: the payload must
/// be at least the 4-octet header ([`RIPNG_HEADER_LEN`]), the command must be a
/// known RIPng command (Request/Response 1/2), the version must be 1, and the
/// bytes after the header must be a whole multiple of the 20-octet RTE length
/// ([`RIPNG_RTE_LEN`]).
pub(crate) fn looks_like_ripng_payload(bytes: &[u8]) -> bool {
    if bytes.len() < RIPNG_HEADER_LEN {
        return false;
    }
    let command = bytes[0];
    let version = bytes[1];
    matches!(command, RIPNG_COMMAND_REQUEST | RIPNG_COMMAND_RESPONSE)
        && version == RIPNG_VERSION_1
        && (bytes.len() - RIPNG_HEADER_LEN) % RIPNG_RTE_LEN == 0
}

/// Build a RIPng whole-table-request message (RFC 2080 §2.4.1).
///
/// RFC 2080 §2.4.1 specifies that a request for the peer's complete routing
/// table is a Request message carrying exactly one RTE whose prefix is `::`,
/// prefix length is `0`, route tag is `0`, and metric is infinity (16) — the
/// [`RipngRte::whole_table_request`] sentinel.
///
/// This convenience assembles the request stack with the project's layer
/// composition idiom and returns a typed [`Packet`]:
///
/// - an [`Ipv6`](crate::protocols::ip::v6::Ipv6) layer whose source is `source`
///   and whose destination is the well-known RIPng multicast group
///   [`RIPNG_MULTICAST`] (`ff02::9`),
/// - a [`Udp`](crate::protocols::transport::Udp) datagram with source and
///   destination port [`RIPNG_UDP_PORT`] (521), and
/// - a [`Ripng::request`] message carrying the single whole-table sentinel RTE.
///
/// Lengths and checksums are left for [`Packet::compile`] to fill. Callers
/// supply a documentation-range source address (`2001:db8::/32`); the
/// destination is fixed to the RIPng multicast group.
pub fn ripng_whole_table_request(source: std::net::Ipv6Addr) -> Packet {
    use crate::protocols::ip::v6::Ipv6;
    use crate::protocols::transport::Udp;

    Ipv6::new().src(source).dst(RIPNG_MULTICAST)
        / Udp::new().sport(RIPNG_UDP_PORT).dport(RIPNG_UDP_PORT)
        / Ripng::request().rte(RipngRte::whole_table_request())
}

#[cfg(test)]
mod ripng_decode_roundtrips_response {
    use super::*;
    use crate::packet::LayerContext;
    use std::net::Ipv6Addr;

    #[test]
    fn ripng_decode_roundtrips_response() {
        // A two-RTE Response message.
        let first = RipngRte::route(
            "2001:db8::".parse::<Ipv6Addr>().expect("valid prefix"),
            64,
            1,
        );
        let second = RipngRte::route(
            "2001:db8:1::".parse::<Ipv6Addr>().expect("valid prefix"),
            48,
            3,
        )
        .route_tag(0x1234);
        let ripng = Ripng::response().with_rtes(vec![first.clone(), second.clone()]);

        // Compile the layer to its wire bytes via a single-layer packet context.
        let packet = Packet::from_layer(ripng.clone());
        let ctx = LayerContext::new(&packet, 0);
        let mut bytes = Vec::new();
        ripng.compile(&ctx, &mut bytes).expect("ripng compiles");

        // Decode reproduces equal command, version, and RTE field values.
        let decoded = decode(&bytes).expect("two-RTE response decodes");
        assert_eq!(decoded.command(), RipCommand::Response);
        assert_eq!(decoded.command_value(), ripng.command_value());
        assert_eq!(decoded.version_value(), ripng.version_value());
        assert_eq!(decoded.rtes().len(), 2);

        // Compare RTEs via their effective values (derived PartialEq on Field is
        // user-vs-default sensitive; decode marks all fields caller-set).
        for (got, want) in decoded.rtes().iter().zip([&first, &second]) {
            assert_eq!(got.prefix_value(), want.prefix_value());
            assert_eq!(got.route_tag_value(), want.route_tag_value());
            assert_eq!(got.prefix_len_value(), want.prefix_len_value());
            assert_eq!(got.metric_value(), want.metric_value());
        }

        // The decoded layer re-compiles to byte-identical wire form.
        let repacket = Packet::from_layer(decoded.clone());
        let rectx = LayerContext::new(&repacket, 0);
        let mut recompiled = Vec::new();
        decoded
            .compile(&rectx, &mut recompiled)
            .expect("decoded ripng recompiles");
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn short_header_returns_structured_error_without_panic() {
        // 3 octets is fewer than the fixed 4-octet header (RFC 2080 §2).
        let short = [0u8; 3];
        let err = decode(&short).expect_err("3 octets is too short");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert!(
                    context.contains("RIPng"),
                    "context should mention RIPng, got {context:?}"
                );
                assert_eq!(required, RIPNG_HEADER_LEN);
                assert_eq!(available, short.len());
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }

    #[test]
    fn partial_trailing_rte_returns_structured_error() {
        // Valid 4-octet header plus 12 octets: not a whole multiple of 20.
        let mut bytes = vec![0x02, 0x01, 0x00, 0x00];
        bytes.extend_from_slice(&[0u8; 12]);
        let err = decode(&bytes).expect_err("partial RTE is too short");
        match err {
            CrafterError::BufferTooShort {
                required,
                available,
                ..
            } => {
                assert_eq!(required, RIPNG_RTE_LEN);
                assert_eq!(available, 12);
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod ripng_summary_mentions_command_and_count {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn ripng_summary_mentions_command_and_count() {
        // A Response message carrying three RTEs.
        let rtes = vec![
            RipngRte::route("2001:db8::".parse::<Ipv6Addr>().expect("valid prefix"), 64, 1),
            RipngRte::route(
                "2001:db8:1::".parse::<Ipv6Addr>().expect("valid prefix"),
                48,
                2,
            ),
            RipngRte::route(
                "2001:db8:2::".parse::<Ipv6Addr>().expect("valid prefix"),
                56,
                3,
            ),
        ];
        let summary = Ripng::response().with_rtes(rtes).summary();

        // The one-line summary names the command, the version, and the RTE count.
        assert!(
            summary.contains("Response"),
            "summary should name the command, got {summary:?}"
        );
        assert!(
            summary.contains("v1"),
            "summary should name the version, got {summary:?}"
        );
        assert!(
            summary.contains('3'),
            "summary should report the RTE count, got {summary:?}"
        );
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

#[cfg(test)]
mod ripng_layer_compiles {
    use super::*;
    use crate::packet::LayerContext;
    use std::net::Ipv6Addr;

    #[test]
    fn ripng_layer_compiles_header_and_rtes() {
        let prefix = "2001:db8::".parse::<Ipv6Addr>().expect("valid prefix");
        let ripng = Ripng::response().rte(RipngRte::route(prefix, 64, 1));

        // Compile the layer in isolation via a single-layer packet context.
        let packet = Packet::from_layer(ripng.clone());
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        ripng.compile(&ctx, &mut out).expect("ripng compiles");

        // RFC 2080 §2 header: command=Response(2), version=1, reserved=0.
        assert_eq!(&out[..RIPNG_HEADER_LEN], &[0x02, 0x01, 0x00, 0x00]);
        // Header plus one 20-octet RTE.
        assert_eq!(out.len(), RIPNG_HEADER_LEN + RIPNG_RTE_LEN);
        assert_eq!(ripng.encoded_len(), RIPNG_HEADER_LEN + RIPNG_RTE_LEN);
    }
}

#[cfg(test)]
mod ripng_layer_div {
    use super::*;
    use crate::protocols::ip::v6::Ipv6;
    use crate::protocols::transport::Udp;
    use std::net::Ipv6Addr;

    #[test]
    fn ripng_layer_div_composes_into_packet() {
        let prefix = "2001:db8::".parse::<Ipv6Addr>().expect("valid prefix");
        let ripng = Ripng::response().rte(RipngRte::route(prefix, 64, 1));

        // The `/` operator composes an IPv6/UDP stack and a Ripng layer into a
        // Packet whose layer stack includes the Ripng layer.
        let packet = Ipv6::new()
            .src("2001:db8::1".parse::<Ipv6Addr>().expect("valid source"))
            .dst(RIPNG_MULTICAST)
            / Udp::new().sport(RIPNG_UDP_PORT).dport(RIPNG_UDP_PORT)
            / ripng;
        assert!(packet.layer::<Ripng>().is_some());
    }
}

#[cfg(test)]
mod ripng_udp_binding {
    use super::*;
    use crate::packet::{NetworkLayer, Raw};
    use crate::protocols::ip::v6::Ipv6;
    use crate::protocols::transport::Udp;
    use std::net::Ipv6Addr;

    #[test]
    fn ripng_decodes_from_udp_521() {
        // An IPv6/UDP(521)/Ripng Response with one route table entry.
        let prefix = "2001:db8::".parse::<Ipv6Addr>().expect("valid prefix");
        let ripng = Ripng::response().rte(RipngRte::route(prefix, 64, 1));
        let packet = Ipv6::new()
            .src("2001:db8::1".parse::<Ipv6Addr>().expect("valid source"))
            .dst(RIPNG_MULTICAST)
            / Udp::new().sport(RIPNG_UDP_PORT).dport(RIPNG_UDP_PORT)
            / ripng;

        let compiled = packet.compile().expect("ripng stack compiles");

        // The conservative UDP/521 binding routes the payload to the Ripng decoder.
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())
            .expect("ipv6/udp/ripng decodes");

        let decoded_ripng = decoded
            .layer::<Ripng>()
            .expect("decoded packet includes a Ripng layer");
        assert_eq!(decoded_ripng.command(), RipCommand::Response);
        assert_eq!(decoded_ripng.rtes().len(), 1);
        assert!(decoded.layer::<Raw>().is_none());
    }

    #[test]
    fn ripng_non_ripng_udp_521_stays_raw() {
        // A UDP/521 datagram whose payload fails looks_like_ripng_payload: an
        // unknown command (0xFF) with a non-multiple-of-20 trailing length, so it
        // must fall through to Raw rather than decode as Ripng.
        let payload = vec![0xFFu8, 0xFF, 0x00, 0x00, 0x01, 0x02, 0x03];
        assert!(
            !looks_like_ripng_payload(&payload),
            "fixture payload must not look like RIPng"
        );

        let packet = Ipv6::new()
            .src("2001:db8::1".parse::<Ipv6Addr>().expect("valid source"))
            .dst("2001:db8::2".parse::<Ipv6Addr>().expect("valid dest"))
            / Udp::new().sport(RIPNG_UDP_PORT).dport(RIPNG_UDP_PORT)
            / Raw::from_bytes(&payload);

        let compiled = packet.compile().expect("udp/raw stack compiles");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())
            .expect("ipv6/udp/raw decodes");

        assert!(
            decoded.layer::<Ripng>().is_none(),
            "non-RIPng port-521 payload must not decode as Ripng"
        );
        assert!(
            decoded.layer::<Raw>().is_some(),
            "non-RIPng port-521 payload must remain Raw"
        );
    }
}

#[cfg(test)]
mod ripng_whole_table_request_builds {
    use super::*;
    use crate::packet::NetworkLayer;
    use crate::protocols::ip::v6::Ipv6;
    use std::net::Ipv6Addr;

    #[test]
    fn ripng_whole_table_request_builds() {
        let source = "2001:db8::1".parse::<Ipv6Addr>().expect("valid source");
        let packet = ripng_whole_table_request(source);

        // The stack compiles and decodes back to a Ripng layer.
        let compiled = packet.compile().expect("ripng request stack compiles");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())
            .expect("ipv6/udp/ripng request decodes");

        // The IPv6 layer targets the well-known RIPng multicast group ff02::9.
        let ipv6 = decoded
            .layer::<Ipv6>()
            .expect("decoded packet includes an Ipv6 layer");
        assert_eq!(ipv6.destination(), RIPNG_MULTICAST);
        assert_eq!(RIPNG_MULTICAST, "ff02::9".parse::<Ipv6Addr>().expect("ff02::9"));

        // The Ripng layer is a Request carrying exactly one whole-table sentinel
        // RTE (RFC 2080 §2.4.1).
        let ripng = decoded
            .layer::<Ripng>()
            .expect("decoded packet includes a Ripng layer");
        assert_eq!(ripng.command(), RipCommand::Request);
        assert_eq!(ripng.rtes().len(), 1);
        assert!(
            ripng.rtes()[0].is_whole_table_request(),
            "the single RTE must be the whole-table-request sentinel"
        );
    }
}
