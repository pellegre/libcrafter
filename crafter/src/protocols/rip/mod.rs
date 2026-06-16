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
pub mod ripng;

pub use auth::{
    verify, RipAuth, RipAuthPayload, RipAuthVerification, RipDigestAlgorithm, RipKeyedDigestHeader,
};
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
    /// Optional RIPv2 authentication configuration (RFC 2453 §4.1, RFC 4822 §3).
    ///
    /// When set, `compile()` emits the leading AFI-0xFFFF authentication entry
    /// before the route entries and — for the keyed-digest form — appends the
    /// trailing digest block after them, auto-computing the digest from
    /// [`Self::auth_key`] unless the caller pinned one.
    pub auth: Option<RipAuth>,
    /// The authentication key used to compute the keyed digest on `compile()`.
    ///
    /// The key is never serialized onto the wire (except where the RFC 2082
    /// Keyed-MD5 construction folds it into the digest region before hashing);
    /// it is held only so `compile()` can derive the trailing digest.
    pub auth_key: Vec<u8>,
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
            auth: None,
            auth_key: Vec::new(),
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

    /// Build a demand-RIP Update Request message (RFC 2091 §2.3).
    ///
    /// Sets the command to [`RipCommand::UpdateRequest`] (code 9) and the
    /// version to [`RIP_VERSION_2`]; both are marked caller-set. Demand RIP
    /// (RFC 2091) layers on the RIPv2 core, so the version is pinned to 2.
    pub fn update_request() -> Self {
        Self::new()
            .with_command(RipCommand::UpdateRequest)
            .version(RIP_VERSION_2)
    }

    /// Build a demand-RIP Update Response message (RFC 2091 §2.3).
    ///
    /// Sets the command to [`RipCommand::UpdateResponse`] (code 10) and the
    /// version to [`RIP_VERSION_2`]; both are marked caller-set.
    pub fn update_response() -> Self {
        Self::new()
            .with_command(RipCommand::UpdateResponse)
            .version(RIP_VERSION_2)
    }

    /// Build a demand-RIP Update Acknowledge message (RFC 2091 §2.3).
    ///
    /// Sets the command to [`RipCommand::UpdateAcknowledge`] (code 11) and the
    /// version to [`RIP_VERSION_2`]; both are marked caller-set.
    pub fn update_acknowledge() -> Self {
        Self::new()
            .with_command(RipCommand::UpdateAcknowledge)
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

    /// Attach RIPv2 authentication to the message (RFC 2453 §4.1, RFC 4822 §3).
    ///
    /// Stores the [`RipAuth`] configuration and the authentication `key`. On
    /// [`compile()`](Layer::compile) the leading AFI-0xFFFF authentication entry
    /// is emitted before the route entries; for the keyed-digest form, the
    /// trailing digest block is appended after them with the digest computed from
    /// `key` (RFC 2082 Keyed-MD5 / RFC 4822 HMAC-SHA) unless the caller pinned an
    /// explicit digest, in which case the pinned digest survives untouched. The
    /// key is used only for digest computation and is not otherwise serialized.
    pub fn auth(mut self, auth: RipAuth, key: impl Into<Vec<u8>>) -> Self {
        self.auth = Some(auth);
        self.auth_key = key.into();
        self
    }

    /// Record a demand-RIP Sequence Number into the header (RFC 2091 §2.3).
    ///
    /// On demand circuits (RFC 2091), the Update Request / Update Response /
    /// Update Acknowledge messages carry a Sequence Number used to match
    /// retransmitted updates with their acknowledgements. RFC 2091 §2.3 places
    /// that 2-octet Sequence Number in the header field RIP otherwise reserves
    /// (the 2 octets following the command/version octets), so this builder
    /// records the sequence there via the [`reserved`](Self::reserved) field's
    /// `set_user`. Because the value is caller-set, `compile()` serializes it
    /// exactly as given and a subsequent `decode()` reproduces it byte-for-byte.
    ///
    /// This view is meaningful only for the demand/triggered Update* commands;
    /// see [`demand_sequence_value`](Self::demand_sequence_value), which returns
    /// `None` for a plain Request/Response message.
    pub fn demand_sequence(mut self, sequence: u16) -> Rip {
        self.reserved.set_user(sequence);
        self
    }

    /// The demand-RIP Sequence Number, if this is a demand message (RFC 2091 §2.3).
    ///
    /// Returns `Some(sequence)` only for the demand/triggered Update* commands
    /// ([`RipCommand::UpdateRequest`], [`RipCommand::UpdateResponse`],
    /// [`RipCommand::UpdateAcknowledge`]), reading the value back out of the
    /// header field RFC 2091 §2.3 reuses for the Sequence Number (the 2 octets
    /// RIP otherwise reserves). For a plain RFC 1058 / RFC 2453 Request or
    /// Response — where those octets are simply the reserved field — it returns
    /// `None`, since the bytes do not carry a demand sequence number there.
    pub fn demand_sequence_value(&self) -> Option<u16> {
        match self.command() {
            RipCommand::UpdateRequest
            | RipCommand::UpdateResponse
            | RipCommand::UpdateAcknowledge => Some(self.reserved_value()),
            _ => None,
        }
    }

    /// Effective command wire code (caller-set or default).
    pub fn command_value(&self) -> u8 {
        self.command
            .value()
            .copied()
            .unwrap_or(RIP_COMMAND_RESPONSE)
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

    /// The attached RIPv2 authentication configuration, if any (RFC 2453 §4.1).
    ///
    /// Returns `Some` when the message carries authentication — either set by the
    /// [`Rip::auth`] builder or recognized from a leading AFI-0xFFFF entry on
    /// [`decode`]. For a decoded keyed-digest message this exposes the parsed
    /// header; verification of the trailing digest is via [`verify`] on the raw
    /// message bytes. (Named `auth_config` so it does not collide with the
    /// same-named [`Rip::auth`] builder; Rust rejects two inherent methods with
    /// the same name.)
    pub fn auth_config(&self) -> Option<&RipAuth> {
        self.auth.as_ref()
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

    // RFC 2453 §4.1 / RFC 4822 §3: when the leading entry is an AFI-0xFFFF
    // authentication entry, recognize and expose it on the layer. The route
    // entries still round-trip byte-for-byte (they remain in `entries`); digest
    // verification is via the [`verify`] helper on the raw message bytes.
    if let Some(first) = rip.entries.first() {
        if first.is_auth_marker() {
            rip.auth = auth::decode_auth_entry(first);
        }
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
        // 4-octet header plus 20 octets per route entry. When authentication is
        // attached, add the leading AFI-0xFFFF authentication entry and — for the
        // keyed-digest form — the trailing digest block (4-octet introduction
        // plus the digest itself, RFC 4822 §3.1).
        let mut len = RIP_HEADER_LEN + self.entries.len() * RIP_ENTRY_LEN;
        if let Some(auth) = &self.auth {
            len += RIP_ENTRY_LEN;
            if let RipAuthPayload::KeyedDigest(header) = &auth.payload {
                len += 4 + header.algorithm.digest_len();
            }
        }
        len
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

        match &self.auth {
            // RFC 2453 §4.1 / RFC 4822 §3: the leading authentication entry
            // (AFI 0xFFFF) precedes the route entries. Simple-password emits only
            // that entry; keyed-digest emits the header entry and a trailing
            // digest block after the route entries.
            Some(auth) => match &auth.payload {
                auth::RipAuthPayload::SimplePassword(_) => {
                    auth.as_entry().encode(out);
                    for entry in &self.entries {
                        entry.encode(out);
                    }
                }
                auth::RipAuthPayload::KeyedDigest(header) => {
                    // Leading keyed-digest header entry, then the route entries.
                    auth.keyed_digest_header_entry().encode(out);
                    for entry in &self.entries {
                        entry.encode(out);
                    }

                    // Trailing block introduction (AFI 0xFFFF, trailer 0x0001),
                    // then the digest. A caller-pinned digest survives untouched;
                    // otherwise it is computed over the assembled message with the
                    // trailing digest region replaced by the key (RFC 2082 §3.2.1
                    // Keyed-MD5 / RFC 4822 §3 HMAC-SHA), exactly as verify()
                    // recomputes it.
                    out.extend_from_slice(&RIP_AFI_AUTH.to_be_bytes());
                    out.extend_from_slice(&auth::RIP_AUTH_TRAILER_MARKER.to_be_bytes());

                    if let Some(pinned) = header.digest {
                        out.extend_from_slice(&pinned);
                    } else {
                        let digest = match header.algorithm {
                            RipDigestAlgorithm::KeyedMd5 => {
                                // RFC 2082 §3.2.1: append a zeroed 16-octet digest
                                // region, then let compute_md5_digest fold the key
                                // into it before hashing the whole message.
                                let mut message = out.clone();
                                message.extend_from_slice(&[0u8; auth::RIP_MD5_DIGEST_LEN]);
                                auth::compute_md5_digest(&message, &self.auth_key).to_vec()
                            }
                            RipDigestAlgorithm::HmacSha1 | RipDigestAlgorithm::HmacSha256 => {
                                // RFC 4822 §3: HMAC over the message up to (not
                                // including) the digest region.
                                auth::compute_hmac_digest(header.algorithm, out, &self.auth_key)
                            }
                        };
                        out.extend_from_slice(&digest);
                    }
                }
            },
            None => {
                for entry in &self.entries {
                    entry.encode(out);
                }
            }
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
        let v1 =
            rip_v1_whole_table_request(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::LayerContext;

    fn compile_bytes(rip: &Rip) -> Vec<u8> {
        let packet = Packet::from_layer(rip.clone());
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        rip.compile(&ctx, &mut out).expect("rip compiles");
        out
    }

    #[test]
    fn rip_demand_commands_roundtrip() {
        // RFC 2091 §2.3 demand/triggered-RIP commands. Each builder reports the
        // right typed RipCommand variant and wire code, pins version 2, and
        // survives a compile/decode round-trip with the command preserved.
        let cases = [
            (
                Rip::update_request(),
                RipCommand::UpdateRequest,
                RIP_COMMAND_UPDATE_REQUEST,
                9u8,
            ),
            (
                Rip::update_response(),
                RipCommand::UpdateResponse,
                RIP_COMMAND_UPDATE_RESPONSE,
                10,
            ),
            (
                Rip::update_acknowledge(),
                RipCommand::UpdateAcknowledge,
                RIP_COMMAND_UPDATE_ACK,
                11,
            ),
        ];

        for (rip, want_variant, want_const, want_code) in cases {
            // The constants name the RFC 2091 §2.3 codepoints.
            assert_eq!(want_const, want_code, "constant matches RFC codepoint");

            // The builder reports the typed variant, the wire code, and version 2.
            assert_eq!(rip.command(), want_variant);
            assert_eq!(rip.command_value(), want_code);
            assert_eq!(rip.version_value(), RIP_VERSION_2);

            // compile() emits the command octet verbatim and decode() preserves it.
            let bytes = compile_bytes(&rip);
            assert_eq!(bytes[0], want_code, "header command octet");
            assert_eq!(bytes[1], RIP_VERSION_2, "header version octet");

            let decoded = decode(&bytes).expect("demand command decodes");
            assert_eq!(decoded.command(), want_variant);
            assert_eq!(decoded.command_value(), want_code);
            assert_eq!(decoded.version_value(), RIP_VERSION_2);

            // Re-compiling the decoded layer is byte-identical.
            assert_eq!(compile_bytes(&decoded), bytes);
        }
    }
}

#[cfg(test)]
mod rip_demand_sequence {
    use super::*;
    use crate::packet::LayerContext;

    fn compile_bytes(rip: &Rip) -> Vec<u8> {
        let packet = Packet::from_layer(rip.clone());
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        rip.compile(&ctx, &mut out).expect("rip compiles");
        out
    }

    #[test]
    fn rip_demand_sequence_roundtrips() {
        // RFC 2091 §2.3: a demand Update Request carries a Sequence Number in
        // the header field RIP otherwise reserves. demand_sequence() records it
        // there (caller-set), so compile() serializes it verbatim and decode()
        // reproduces it byte-for-byte.
        let rip = Rip::update_request().demand_sequence(0x0102);

        // The typed view reports the demand sequence for an Update* command.
        assert_eq!(rip.demand_sequence_value(), Some(0x0102));

        // compile() places the sequence in the 2 octets after command/version.
        let bytes = compile_bytes(&rip);
        assert_eq!(bytes[0], RIP_COMMAND_UPDATE_REQUEST, "command octet");
        assert_eq!(bytes[1], RIP_VERSION_2, "version octet");
        assert_eq!(&bytes[2..4], &0x0102u16.to_be_bytes(), "sequence octets");

        // decode() round-trips the sequence bytes exactly and re-compiles
        // byte-identically.
        let decoded = decode(&bytes).expect("demand update request decodes");
        assert_eq!(decoded.command(), RipCommand::UpdateRequest);
        assert_eq!(decoded.demand_sequence_value(), Some(0x0102));
        assert_eq!(decoded.reserved_value(), 0x0102);
        assert_eq!(compile_bytes(&decoded), bytes);

        // For a plain Request/Response the same header octets are simply the
        // reserved field, so the demand view returns None.
        assert_eq!(Rip::request().demand_sequence_value(), None);
        assert_eq!(Rip::response().demand_sequence_value(), None);
    }
}

#[cfg(test)]
mod rip_layer_auth_integration {
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
    fn rip_layer_keyed_md5_autofills_and_verifies() {
        // RFC 2082 §3.2.1: a keyed-MD5 authenticated Response with one route
        // entry and no pinned digest. compile() must emit the leading auth header
        // entry, the route entry, the trailing block (AFI 0xFFFF, trailer 0x0001),
        // and the auto-computed 16-octet digest — in the exact byte layout the
        // decode-side verify() helper expects.
        let key = b"rip-md5-key";
        let rip = Rip::response()
            .entry(RipEntry::ipv2_route(
                Ipv4Addr::new(192, 0, 2, 0),
                Ipv4Addr::new(255, 255, 255, 0),
                1,
            ))
            .auth(
                RipAuth::keyed_digest(1, auth::RIP_MD5_DIGEST_LEN as u8),
                key.to_vec(),
            );

        let bytes = compile_bytes(&rip);

        // Layout: header(4) + leading auth entry(20) + route entry(20)
        //   + trailing block intro(4) + digest(16).
        assert_eq!(
            bytes.len(),
            RIP_HEADER_LEN + RIP_ENTRY_LEN + RIP_ENTRY_LEN + 4 + auth::RIP_MD5_DIGEST_LEN
        );
        assert_eq!(rip.encoded_len(), bytes.len());

        // The leading entry is the AFI-0xFFFF / type-3 keyed-digest header entry.
        assert_eq!(&bytes[RIP_HEADER_LEN..RIP_HEADER_LEN + 2], &[0xFF, 0xFF]);
        assert_eq!(
            &bytes[RIP_HEADER_LEN + 2..RIP_HEADER_LEN + 4],
            &[0x00, 0x03]
        );

        // The auto-filled digest verifies for the correct key.
        assert_eq!(verify(&bytes, key), RipAuthVerification::DigestOk);

        // A wrong key recomputes a different digest and is a mismatch (no panic).
        assert_eq!(
            verify(&bytes, b"wrong-key"),
            RipAuthVerification::DigestMismatch
        );
    }

    #[test]
    fn rip_layer_pinned_digest_preserved() {
        // RFC 2082 §3.2.1: a caller may pin an explicit (here deliberately
        // arbitrary) digest; compile() must emit it verbatim rather than
        // recomputing it, so generated tools can exercise a verifier with a
        // wrong-on-purpose digest.
        let pinned = [0xAB_u8; auth::RIP_MD5_DIGEST_LEN];
        let mut keyed = RipAuth::keyed_digest(1, auth::RIP_MD5_DIGEST_LEN as u8);
        match &mut keyed.payload {
            RipAuthPayload::KeyedDigest(header) => {
                header.digest = Some(pinned);
            }
            other => panic!("expected KeyedDigest payload, got {other:?}"),
        }

        let rip = Rip::response()
            .entry(RipEntry::ipv2_route(
                Ipv4Addr::new(192, 0, 2, 0),
                Ipv4Addr::new(255, 255, 255, 0),
                1,
            ))
            .auth(keyed, b"rip-md5-key".to_vec());

        let bytes = compile_bytes(&rip);

        // The trailing 16 octets are exactly the pinned digest, untouched.
        let digest_start = bytes.len() - auth::RIP_MD5_DIGEST_LEN;
        assert_eq!(&bytes[digest_start..], &pinned);

        // Because the pinned digest is arbitrary (not the real MD5), verify()
        // reports a mismatch — proving compile() did not overwrite it with a
        // freshly computed digest.
        assert_eq!(
            verify(&bytes, b"rip-md5-key"),
            RipAuthVerification::DigestMismatch
        );
    }
}
