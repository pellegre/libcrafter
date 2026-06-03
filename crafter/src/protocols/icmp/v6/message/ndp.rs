//! IPv6 Neighbor Discovery (NDP) message bodies (RFC 4861).
//!
//! Neighbor Discovery messages are ICMPv6 messages: an [`Icmpv6`] header
//! (type / code / checksum / four-byte rest-of-header) followed by a
//! message-specific body. This module holds those bodies as typed [`Layer`]
//! objects that ride **after** an `Icmpv6` header and compose with `/`, exactly
//! the way ICMPv4 layers its timestamp / address-mask / quoted-IP bodies after
//! the fixed ICMP header (see `icmp/v4/bodies.rs`). Keeping the body in a
//! trailing layer means:
//!
//! - the proven `Icmpv6` serialization and IPv6-pseudo-header checksum path is
//!   reused unchanged — the header's `compile()` already sums every byte after
//!   the header (via `payload_bytes_after`), so the body's bytes (the NDP
//!   options, and for later messages the target/destination addresses) are
//!   covered by the auto-filled ICMPv6 checksum without any new checksum code;
//!   and
//! - the typed-body classifier in `icmp/v6/body.rs` keeps describing the message
//!   from the header `type`, so `summary()` / `show()` stay consistent.
//!
//! ## NDP message pattern (established here; followed by Router Advertisement,
//! Neighbor Solicitation/Advertisement, and Redirect — steps 16–20)
//!
//! The split between the `Icmpv6` header and the trailing body mirrors the wire
//! layout and the way ICMPv4 splits its rest-of-header from its bodies:
//!
//! - **The four rest-of-header bytes belong to the `Icmpv6` header.** They are
//!   the message-specific fixed word that immediately follows the checksum: the
//!   `Reserved` field for Router/Neighbor Solicitation and Redirect, the
//!   Cur-Hop-Limit / flags / Router-Lifetime word for Router Advertisement, and
//!   the R/S/O flag word for Neighbor Advertisement. A message's builder sets
//!   these on the header (Router Solicitation simply leaves the reserved word
//!   zero); they are read back through the header's typed-body classifier in
//!   `body.rs`.
//! - **The trailing body layer owns everything after byte 8.** For Router
//!   Solicitation that is just the ordered [`NdpOptions`]. The
//!   solicitation/advertisement/redirect messages prepend their 16-byte
//!   target/destination [`Ipv6Addr`](core::net::Ipv6Addr) field(s) (and Router
//!   Advertisement its Reachable-Time / Retrans-Timer words) ahead of the same
//!   option list — added as `Field`s on the per-message body struct in later
//!   steps, serialized `fixed fields || options.encode()`.
//!
//! Each message gets an `Icmpv6::<message>()` builder that returns a [`Packet`]
//! composing the `Icmpv6` header (right `type`/`code`, rest-of-header set as
//! above) `/` the body layer, so an agent writes `Icmpv6::router_solicitation()`
//! and gets a complete, checksummable packet. The decode side dispatches on the
//! header `type` in `icmp/v6/mod.rs` and pushes the typed body, in lockstep with
//! the `body.rs` classifier.
//!
//! Wire facts grounded against RFC 4861 (the local `rfc-protocol-spec` manifest
//! cache is sparse for NDP, so the Router Solicitation format in section 4.1 and
//! the Source Link-Layer Address option in section 4.6.1 were read directly from
//! the authoritative RFC text); see the per-item citations below.

use super::super::*;
use super::ndp_option::NdpOptions;

/// Router Solicitation message body (RFC 4861 section 4.1).
///
/// On the wire a Router Solicitation is ICMPv6 `type` 133, `code` 0, a 32-bit
/// Reserved field (RFC 4861 section 4.1: "This field is unused. It MUST be
/// initialized to zero by the sender and MUST be ignored by the receiver."),
/// then zero or more options — commonly the Source Link-Layer Address option
/// (RFC 4861 section 4.6.1).
///
/// The 32-bit Reserved field is the [`Icmpv6`] header's four-byte rest-of-header
/// (bytes 4..8 of the ICMPv6 header), set on the header — not in this body — so
/// the split matches the wire layout and the way ICMPv4 keeps its rest-of-header
/// fields on the header. This body therefore carries exactly the part of the
/// message that follows the fixed 8-byte header: the ordered [`NdpOptions`].
/// Build a complete message with [`Icmpv6::router_solicitation`], which composes
/// the `Icmpv6` header (type 133, code 0, reserved word zero) and this body
/// under `/`; the header auto-fills the ICMPv6 checksum over the IPv6
/// pseudo-header, covering this body's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterSolicitation {
    // `pub(crate)` so the ICMPv6 decode path in `icmp/v6/mod.rs` can construct
    // the body from wire bytes; invisible downstream, so the public API is the
    // builder/accessor surface below.
    pub(crate) options: NdpOptions,
}

impl RouterSolicitation {
    /// Create an empty Router Solicitation body: no options. Compose it under an
    /// [`Icmpv6`] header (type 133, code 0) — or use
    /// [`Icmpv6::router_solicitation`], which does that for you.
    pub fn new() -> Self {
        Self {
            options: NdpOptions::new(),
        }
    }

    /// Append an NDP option (RFC 4861 section 4.6), preserving order.
    ///
    /// The common option on a Router Solicitation is the Source Link-Layer
    /// Address (RFC 4861 section 4.6.1); see
    /// [`Icmpv6::router_solicitation_with_source_link_layer`] for the shorthand,
    /// or build one with [`NdpOption::source_link_layer_address`].
    pub fn option(mut self, option: NdpOption) -> Self {
        self.options.add(option);
        self
    }

    /// Replace the whole ordered option list.
    pub fn options(mut self, options: NdpOptions) -> Self {
        self.options = options;
        self
    }

    /// The ordered NDP options carried after the fixed ICMPv6 header.
    pub fn options_ref(&self) -> &NdpOptions {
        &self.options
    }
}

impl Default for RouterSolicitation {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for RouterSolicitation {
    fn name(&self) -> &'static str {
        "RouterSolicitation"
    }

    fn summary(&self) -> String {
        format!("RouterSolicitation(options={})", self.options.len())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![("option_count", self.options.len().to_string())];
        for (index, option) in self.options.iter().enumerate() {
            fields.push((option_field_name(index), option.to_string()));
        }
        fields
    }

    fn encoded_len(&self) -> usize {
        self.options.encoded_len().unwrap_or(0)
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.options.encode()?);
        Ok(())
    }

    impl_layer_object!(RouterSolicitation);
}

impl_layer_div!(RouterSolicitation);

/// Stable inspection-field label for the option at `index` in a body's option
/// list (`option[0]`, `option[1]`, ...). The index is bounded by a small set of
/// pre-allocated labels; options beyond that share the generic `option[*]`
/// label, which is enough for `show()` inspection.
fn option_field_name(index: usize) -> &'static str {
    const NAMES: [&str; 8] = [
        "option[0]",
        "option[1]",
        "option[2]",
        "option[3]",
        "option[4]",
        "option[5]",
        "option[6]",
        "option[7]",
    ];
    NAMES.get(index).copied().unwrap_or("option[*]")
}

impl Icmpv6 {
    /// Build a Router Solicitation packet (RFC 4861 section 4.1).
    ///
    /// Returns a [`Packet`] composing the [`Icmpv6`] header (type 133, code 0,
    /// the four-byte Reserved rest-of-header left zero per RFC 4861 section 4.1)
    /// with an empty [`RouterSolicitation`] body. Attach options by building the
    /// body explicitly — for example
    /// `Icmpv6::new().icmp_type(ICMPV6_ROUTER_SOLICITATION).code(0) /
    /// RouterSolicitation::new().option(...)` — or use
    /// [`Icmpv6::router_solicitation_with_source_link_layer`] for the common
    /// case. `compile()` auto-fills the ICMPv6 checksum over the IPv6
    /// pseudo-header, covering the body's bytes.
    pub fn router_solicitation() -> Packet {
        Self::router_solicitation_body(RouterSolicitation::new())
    }

    /// Build a Router Solicitation packet carrying a Source Link-Layer Address
    /// option (RFC 4861 sections 4.1 and 4.6.1) with the sender's MAC.
    ///
    /// This is the common Router Solicitation an Ethernet host sends so the
    /// router can reply without a separate address resolution. Equivalent to
    /// [`Icmpv6::router_solicitation`] with a single
    /// [`NdpOption::source_link_layer_address`] option appended.
    pub fn router_solicitation_with_source_link_layer(mac: crate::MacAddr) -> Packet {
        Self::router_solicitation_body(
            RouterSolicitation::new().option(NdpOption::source_link_layer_address(mac)),
        )
    }

    /// Compose the Router Solicitation header (type 133, code 0, reserved word
    /// zero) with a caller-built [`RouterSolicitation`] body.
    fn router_solicitation_body(body: RouterSolicitation) -> Packet {
        Self::new().icmp_type(ICMPV6_ROUTER_SOLICITATION).code(0) / body
    }
}

/// Decode the body of an ICMPv6 Router Solicitation: the NDP option area that
/// follows the fixed 8-byte ICMPv6 header (the Reserved field lives in the
/// header's rest-of-header and is decoded there).
///
/// Returns a structured [`CrafterError`] (never a panic) when an option is
/// malformed (a zero length or an overrun); the option walk is delegated to
/// [`NdpOptions::decode`]. An empty option area decodes to an empty body.
pub(crate) fn decode_router_solicitation(bytes: &[u8]) -> Result<RouterSolicitation> {
    let options = NdpOptions::decode(bytes)?;
    Ok(RouterSolicitation { options })
}

// --- Router Advertisement (RFC 4861 section 4.2) ---------------------------

/// Width, in octets, of the Reachable-Time / Retrans-Timer words that lead a
/// Router Advertisement body (RFC 4861 section 4.2: each is a 32-bit value).
const RA_TIMER_LEN: usize = 4;

/// Combined width, in octets, of the two fixed Router Advertisement body words
/// (Reachable Time + Retrans Timer) that precede the option area.
const RA_BODY_FIXED_LEN: usize = RA_TIMER_LEN * 2;

/// Bit mask for the Managed Address Configuration (M) flag in the Router
/// Advertisement flags byte (RFC 4861 section 4.2: the high bit, 0x80). RFC 4862
/// section 5.2: when set, the host should use stateful (DHCPv6) address
/// configuration.
pub const ICMPV6_RA_FLAG_MANAGED: u8 = 0x80;

/// Bit mask for the Other Configuration (O) flag in the Router Advertisement
/// flags byte (RFC 4861 section 4.2: the next bit, 0x40). RFC 4862 section 5.2:
/// when set, other configuration information (e.g. DNS) is available via DHCPv6.
pub const ICMPV6_RA_FLAG_OTHER: u8 = 0x40;

/// Mask of the six Reserved bits in the Router Advertisement flags byte
/// (RFC 4861 section 4.2: "A 6-bit unused field. It MUST be initialized to zero
/// by the sender and MUST be ignored by the receiver."). These bits are
/// preserved verbatim through build/decode for forward-compatibility — later
/// specifications (RFC 5175 RA Flags Extension, RFC 4191 default-router
/// preference) assign meaning inside this field.
pub const ICMPV6_RA_FLAGS_RESERVED: u8 = 0x3f;

/// Default Cur Hop Limit emitted by [`Icmpv6::router_advertisement`] when the
/// agent does not set one. A common, conservative IPv6 default hop limit
/// (RFC 4861 section 4.2 leaves the value to the router; zero means
/// "unspecified", which we avoid as a default).
pub const ICMPV6_RA_DEFAULT_CUR_HOP_LIMIT: u8 = 64;

/// Default Router Lifetime (seconds) emitted by
/// [`Icmpv6::router_advertisement`] when the agent does not set one. RFC 4861
/// section 6.2.1 recommends `AdvDefaultLifetime = 3 * MaxRtrAdvInterval` with a
/// default `MaxRtrAdvInterval` of 600 s, giving 1800 s.
pub const ICMPV6_RA_DEFAULT_ROUTER_LIFETIME: u16 = 1800;

/// Router Advertisement message body (RFC 4861 section 4.2).
///
/// On the wire a Router Advertisement is ICMPv6 `type` 134, `code` 0, then the
/// four-byte rest-of-header — Cur Hop Limit (1 octet), a flags octet (bit 0x80 =
/// M "Managed address configuration", bit 0x40 = O "Other configuration", the
/// low six bits Reserved), and Router Lifetime (2 octets, seconds) — followed by
/// Reachable Time (4 octets, milliseconds), Retrans Timer (4 octets,
/// milliseconds), and zero or more options.
///
/// Following the NDP message pattern established by [`RouterSolicitation`], the
/// rest-of-header word (Cur Hop Limit / flags / Router Lifetime) lives on the
/// [`Icmpv6`] header — set by the [`Icmpv6::router_advertisement`] builder — and
/// is read back through the header's typed-body classifier in `body.rs`. This
/// body therefore carries exactly the part after the fixed 8-byte header: the
/// Reachable-Time and Retrans-Timer words and the ordered [`NdpOptions`]. The
/// header auto-fills the ICMPv6 checksum over the IPv6 pseudo-header, covering
/// this body's bytes.
///
/// RFC 4862 (SLAAC) section 5.2 defines how the M and O flags drive host
/// configuration: M selects stateful (DHCPv6) address configuration, O signals
/// that other configuration is available via DHCPv6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAdvertisement {
    // `pub(crate)` so the ICMPv6 decode path in `icmp/v6/mod.rs` can construct
    // the body from wire bytes; the public surface is the builder/accessors.
    pub(crate) reachable_time: u32,
    pub(crate) retrans_timer: u32,
    pub(crate) options: NdpOptions,
}

impl RouterAdvertisement {
    /// Create a Router Advertisement body with the RFC 4861 section 4.2 "unset"
    /// timer defaults (Reachable Time 0, Retrans Timer 0 — both meaning
    /// "unspecified, use the receiver's default") and no options. Compose it
    /// under an [`Icmpv6`] header (type 134, code 0) — or use
    /// [`Icmpv6::router_advertisement`], which sets the header rest-of-header
    /// (Cur Hop Limit / flags / Router Lifetime) for you.
    pub fn new() -> Self {
        Self {
            reachable_time: 0,
            retrans_timer: 0,
            options: NdpOptions::new(),
        }
    }

    /// Set the Reachable Time field (milliseconds; RFC 4861 section 4.2: how
    /// long a neighbor is considered reachable after a reachability
    /// confirmation; 0 = unspecified).
    pub fn reachable_time(mut self, reachable_time: u32) -> Self {
        self.reachable_time = reachable_time;
        self
    }

    /// Set the Retrans Timer field (milliseconds; RFC 4861 section 4.2: the
    /// interval between retransmitted Neighbor Solicitations; 0 = unspecified).
    pub fn retrans_timer(mut self, retrans_timer: u32) -> Self {
        self.retrans_timer = retrans_timer;
        self
    }

    /// Append an NDP option (RFC 4861 section 4.6), preserving order.
    ///
    /// Router Advertisements commonly carry a Source Link-Layer Address, MTU,
    /// and Prefix Information options (added as typed constructors in later
    /// steps); build one with the [`NdpOption`] constructors.
    pub fn option(mut self, option: NdpOption) -> Self {
        self.options.add(option);
        self
    }

    /// Replace the whole ordered option list.
    pub fn options(mut self, options: NdpOptions) -> Self {
        self.options = options;
        self
    }

    /// The Reachable Time field (milliseconds).
    pub fn reachable_time_value(&self) -> u32 {
        self.reachable_time
    }

    /// The Retrans Timer field (milliseconds).
    pub fn retrans_timer_value(&self) -> u32 {
        self.retrans_timer
    }

    /// The ordered NDP options carried after the fixed Router Advertisement
    /// fields.
    pub fn options_ref(&self) -> &NdpOptions {
        &self.options
    }
}

impl Default for RouterAdvertisement {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for RouterAdvertisement {
    fn name(&self) -> &'static str {
        "RouterAdvertisement"
    }

    fn summary(&self) -> String {
        format!(
            "RouterAdvertisement(reachable={}, retrans={}, options={})",
            self.reachable_time,
            self.retrans_timer,
            self.options.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("reachable_time", self.reachable_time.to_string()),
            ("retrans_timer", self.retrans_timer.to_string()),
            ("option_count", self.options.len().to_string()),
        ];
        for (index, option) in self.options.iter().enumerate() {
            fields.push((option_field_name(index), option.to_string()));
        }
        fields
    }

    fn encoded_len(&self) -> usize {
        RA_BODY_FIXED_LEN + self.options.encoded_len().unwrap_or(0)
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.reachable_time.to_be_bytes());
        out.extend_from_slice(&self.retrans_timer.to_be_bytes());
        out.extend_from_slice(&self.options.encode()?);
        Ok(())
    }

    impl_layer_object!(RouterAdvertisement);
}

impl_layer_div!(RouterAdvertisement);

/// Pack the Router Advertisement rest-of-header (RFC 4861 section 4.2): Cur Hop
/// Limit (1 byte), the flags byte (M | O | reserved bits), and Router Lifetime
/// (2 bytes, big-endian).
fn router_advertisement_rest_of_header(
    cur_hop_limit: u8,
    flags: u8,
    router_lifetime: u16,
) -> [u8; 4] {
    let lifetime = router_lifetime.to_be_bytes();
    [cur_hop_limit, flags, lifetime[0], lifetime[1]]
}

impl Icmpv6 {
    /// Build a Router Advertisement packet (RFC 4861 section 4.2) with
    /// deterministic, documented defaults.
    ///
    /// Returns a [`Packet`] composing the [`Icmpv6`] header (type 134, code 0,
    /// the rest-of-header set to Cur Hop Limit
    /// [`ICMPV6_RA_DEFAULT_CUR_HOP_LIMIT`] = 64, flags byte 0 — M and O clear,
    /// Reserved zero — and Router Lifetime
    /// [`ICMPV6_RA_DEFAULT_ROUTER_LIFETIME`] = 1800 s) with a
    /// [`RouterAdvertisement`] body whose Reachable Time and Retrans Timer are 0
    /// (unspecified) and no options. Customize header fields with
    /// [`Icmpv6::router_advertisement_with`] or by setting the header
    /// rest-of-header directly; `compile()` auto-fills the ICMPv6 checksum over
    /// the IPv6 pseudo-header.
    pub fn router_advertisement() -> Packet {
        Self::router_advertisement_with(
            ICMPV6_RA_DEFAULT_CUR_HOP_LIMIT,
            false,
            false,
            ICMPV6_RA_DEFAULT_ROUTER_LIFETIME,
            RouterAdvertisement::new(),
        )
    }

    /// Build a Router Advertisement packet (RFC 4861 section 4.2) with explicit
    /// header fields and a caller-built [`RouterAdvertisement`] body.
    ///
    /// `cur_hop_limit`, `managed` (the M / Managed Address Configuration flag),
    /// `other` (the O / Other Configuration flag), and `router_lifetime`
    /// (seconds) become the [`Icmpv6`] header rest-of-header (Cur Hop Limit /
    /// flags / Router Lifetime). The six Reserved flag bits are sent zero; to set
    /// them on purpose (a deliberately malformed packet, or a forward-compatible
    /// RFC 5175/4191 bit), build the header rest-of-header directly with
    /// [`Icmpv6::rest_of_header`] (the value survives `compile()` untouched). The
    /// body carries the Reachable Time / Retrans Timer words and the options.
    pub fn router_advertisement_with(
        cur_hop_limit: u8,
        managed: bool,
        other: bool,
        router_lifetime: u16,
        body: RouterAdvertisement,
    ) -> Packet {
        let mut flags = 0u8;
        if managed {
            flags |= ICMPV6_RA_FLAG_MANAGED;
        }
        if other {
            flags |= ICMPV6_RA_FLAG_OTHER;
        }
        let rest = router_advertisement_rest_of_header(cur_hop_limit, flags, router_lifetime);
        Self::new()
            .icmp_type(ICMPV6_ROUTER_ADVERTISEMENT)
            .code(0)
            .rest_of_header(rest)
            / body
    }
}

/// Decode the body of an ICMPv6 Router Advertisement: the Reachable Time and
/// Retrans Timer words (RFC 4861 section 4.2) followed by the NDP option area.
/// The Cur Hop Limit / flags / Router Lifetime rest-of-header lives in the
/// header and is decoded there.
///
/// Returns a structured [`CrafterError`] (never a panic) when the body is too
/// short to hold the two timer words, or when an option is malformed (a zero
/// length or an overrun); the option walk is delegated to
/// [`NdpOptions::decode`].
pub(crate) fn decode_router_advertisement(bytes: &[u8]) -> Result<RouterAdvertisement> {
    if bytes.len() < RA_BODY_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "icmpv6.router_advertisement.body",
            RA_BODY_FIXED_LEN,
            bytes.len(),
        ));
    }
    let reachable_time = u32::from_be_bytes(copy_array_4(&bytes[0..4]));
    let retrans_timer = u32::from_be_bytes(copy_array_4(&bytes[4..8]));
    let options = NdpOptions::decode(&bytes[RA_BODY_FIXED_LEN..])?;
    Ok(RouterAdvertisement {
        reachable_time,
        retrans_timer,
        options,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::icmp::{Icmpv6Body, NDP_OPT_SOURCE_LINK_LAYER_ADDR};
    use crate::{Ipv6, MacAddr, NetworkLayer, Packet};
    use core::net::Ipv6Addr;

    // Link-local source per RFC 4861 (a host solicits from its link-local
    // address); fe80::/10. The router-solicitation destination is the
    // all-routers multicast ff02::2.
    fn link_local_src() -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0001)
    }

    fn all_routers() -> Ipv6Addr {
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0002)
    }

    // Documentation MAC from the RFC 7042 reserved range.
    fn doc_mac() -> MacAddr {
        MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x2a])
    }

    // RFC 4861 sec 4.1 + 4.6.1: a Router Solicitation with a Source Link-Layer
    // Address option compiles to type 133 / code 0, a zero Reserved word, and the
    // SLLA option, and decodes back to the same fields with the checksum
    // verifying over the IPv6 pseudo-header.
    #[test]
    fn router_solicitation_with_slla_round_trips() {
        let packet = Ipv6::new()
            .src(link_local_src())
            .dst(all_routers())
            .hlim(255)
            / Icmpv6::router_solicitation_with_source_link_layer(doc_mac());
        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes();

        // ICMPv6 starts at offset 40 (fixed 40-byte IPv6 header).
        assert_eq!(bytes[40], ICMPV6_ROUTER_SOLICITATION);
        assert_eq!(bytes[41], 0, "code is 0");
        // Reserved field (ICMPv6 rest-of-header, bytes 4..8) is zero.
        assert_eq!(&bytes[44..48], &[0, 0, 0, 0]);
        // SLLA option starts right after the 8-byte header: type 1, length 1 (one
        // 8-octet unit), then the 6-byte MAC.
        assert_eq!(&bytes[48..50], &[NDP_OPT_SOURCE_LINK_LAYER_ADDR, 1]);
        assert_eq!(&bytes[50..56], &doc_mac().octets());
        // Total: IPv6(40) + ICMPv6 header(8) + one SLLA option(8) = 56 bytes.
        assert_eq!(bytes.len(), 56);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.icmp_type_value(), ICMPV6_ROUTER_SOLICITATION);
        assert_eq!(icmpv6.code_value(), 0);
        // The header classifies the message as a Router Solicitation body with a
        // zero Reserved field.
        assert_eq!(
            icmpv6.body(),
            Icmpv6Body::RouterSolicitation { reserved: 0 }
        );

        let rs = decoded.layer::<RouterSolicitation>().unwrap();
        assert_eq!(rs.options_ref().len(), 1);
        let slla = &rs.options_ref().options()[0];
        assert_eq!(slla.option_type(), NDP_OPT_SOURCE_LINK_LAYER_ADDR);
        assert_eq!(slla.link_layer_address(), Some(doc_mac()));

        // The whole packet round-trips byte-for-byte (checksum included).
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // An empty Router Solicitation (no options) is the minimal valid message:
    // type 133, code 0, four zero reserved bytes, nothing after.
    #[test]
    fn empty_router_solicitation_round_trips() {
        let packet = Ipv6::new()
            .src(link_local_src())
            .dst(all_routers())
            .hlim(255)
            / Icmpv6::router_solicitation();
        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes();
        // ICMPv6 header (8 bytes) only, no options.
        assert_eq!(bytes.len(), 40 + 8);
        assert_eq!(bytes[40], ICMPV6_ROUTER_SOLICITATION);
        assert_eq!(&bytes[44..48], &[0, 0, 0, 0]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let rs = decoded.layer::<RouterSolicitation>().unwrap();
        assert!(rs.options_ref().is_empty());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // RFC 4861 sec 4.1 requires the Reserved field be sent as zero, but an agent
    // can set it (via the header rest-of-header) to a deliberately non-zero value
    // for a malformed-packet test; that value is honored verbatim through
    // compile() and survives a decode round-trip in the header's typed body.
    #[test]
    fn explicit_reserved_is_preserved() {
        let packet = Ipv6::new().src(link_local_src()).dst(all_routers())
            / (Icmpv6::new()
                .icmp_type(ICMPV6_ROUTER_SOLICITATION)
                .code(0)
                .rest_of_header([0xde, 0xad, 0xbe, 0xef])
                / RouterSolicitation::new());
        let compiled = packet.compile().unwrap();
        // The reserved word is the ICMPv6 rest-of-header (bytes 4..8).
        assert_eq!(&compiled.as_bytes()[44..48], &[0xde, 0xad, 0xbe, 0xef]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes()).unwrap();
        assert_eq!(
            decoded.layer::<Icmpv6>().unwrap().body(),
            Icmpv6Body::RouterSolicitation {
                reserved: 0xdead_beef
            }
        );
    }

    // summary() / show() describe the body for agent inspection.
    #[test]
    fn router_solicitation_summary_and_show() {
        let body =
            RouterSolicitation::new().option(NdpOption::source_link_layer_address(doc_mac()));
        assert_eq!(body.summary(), "RouterSolicitation(options=1)");

        let option_field = body
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "option[0]")
            .map(|(_, value)| value)
            .expect("show() exposes the first option");
        assert!(option_field.starts_with("Source Link-Layer Address"));

        // The header summarizes from its type (the body model is a view); the
        // Router Solicitation name comes from `icmpv6_type_summary`.
        let header = Icmpv6::new().icmp_type(ICMPV6_ROUTER_SOLICITATION).code(0);
        assert_eq!(
            header.summary(),
            "Icmpv6(type=router-solicitation(133), code=0, id=-, seq=-)"
        );
        // The header's body-detail field reports the Router Solicitation body
        // with its Reserved field.
        let body_field = header
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "body")
            .map(|(_, value)| value)
            .expect("show() exposes a body field");
        assert_eq!(body_field, "router-solicitation(reserved=0x00000000)");
    }

    // RFC 4861 sec 4.2: the builder defaults are documented and deterministic —
    // Cur Hop Limit 64, M and O clear (flags byte 0), Router Lifetime 1800 s,
    // Reachable Time / Retrans Timer 0, no options.
    #[test]
    fn router_advertisement_defaults_are_documented() {
        let packet = Ipv6::new()
            .src(link_local_src())
            .dst(all_routers())
            .hlim(255)
            / Icmpv6::router_advertisement();
        let bytes = packet.compile().unwrap();
        let bytes = bytes.as_bytes();

        // ICMPv6 starts at offset 40. type 134, code 0.
        assert_eq!(bytes[40], ICMPV6_ROUTER_ADVERTISEMENT);
        assert_eq!(bytes[41], 0, "code is 0");
        // rest-of-header (bytes 44..48): cur_hop_limit=64, flags=0,
        // router_lifetime=1800.
        assert_eq!(bytes[44], ICMPV6_RA_DEFAULT_CUR_HOP_LIMIT);
        assert_eq!(bytes[44], 64);
        assert_eq!(bytes[45], 0, "M/O/reserved flags all clear by default");
        assert_eq!(
            u16::from_be_bytes([bytes[46], bytes[47]]),
            ICMPV6_RA_DEFAULT_ROUTER_LIFETIME
        );
        assert_eq!(u16::from_be_bytes([bytes[46], bytes[47]]), 1800);
        // Body: Reachable Time (4) + Retrans Timer (4) both zero, no options.
        assert_eq!(&bytes[48..52], &[0, 0, 0, 0], "reachable time = 0");
        assert_eq!(&bytes[52..56], &[0, 0, 0, 0], "retrans timer = 0");
        // IPv6(40) + ICMPv6 header(8) + reachable(4) + retrans(4) = 56.
        assert_eq!(bytes.len(), 56);
    }

    // RFC 4861 sec 4.2: a fully-populated Router Advertisement (header fields,
    // both flags, timers, and an SLLA option) compiles to the wire layout and
    // decodes back to every field, with the checksum verifying over the IPv6
    // pseudo-header.
    #[test]
    fn router_advertisement_with_option_round_trips() {
        let body = RouterAdvertisement::new()
            .reachable_time(30_000)
            .retrans_timer(1_000)
            .option(NdpOption::source_link_layer_address(doc_mac()));
        let packet = Ipv6::new()
            .src(link_local_src())
            .dst(all_routers())
            .hlim(255)
            / Icmpv6::router_advertisement_with(255, true, true, 1800, body);
        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes();

        assert_eq!(bytes[40], ICMPV6_ROUTER_ADVERTISEMENT);
        assert_eq!(bytes[41], 0);
        // rest-of-header: cur_hop_limit=255, flags=M|O=0xc0, lifetime=1800.
        assert_eq!(bytes[44], 255);
        assert_eq!(bytes[45], ICMPV6_RA_FLAG_MANAGED | ICMPV6_RA_FLAG_OTHER);
        assert_eq!(bytes[45], 0xc0);
        assert_eq!(u16::from_be_bytes([bytes[46], bytes[47]]), 1800);
        // reachable time = 30000, retrans timer = 1000.
        assert_eq!(
            u32::from_be_bytes([bytes[48], bytes[49], bytes[50], bytes[51]]),
            30_000
        );
        assert_eq!(
            u32::from_be_bytes([bytes[52], bytes[53], bytes[54], bytes[55]]),
            1_000
        );
        // SLLA option follows: type 1, length 1, 6-byte MAC.
        assert_eq!(&bytes[56..58], &[NDP_OPT_SOURCE_LINK_LAYER_ADDR, 1]);
        assert_eq!(&bytes[58..64], &doc_mac().octets());
        // IPv6(40) + header(8) + timers(8) + option(8) = 64.
        assert_eq!(bytes.len(), 64);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.icmp_type_value(), ICMPV6_ROUTER_ADVERTISEMENT);
        assert_eq!(
            icmpv6.body(),
            Icmpv6Body::RouterAdvertisement {
                cur_hop_limit: 255,
                managed: true,
                other: true,
                reserved_flags: 0,
                router_lifetime: 1800,
            }
        );

        let ra = decoded.layer::<RouterAdvertisement>().unwrap();
        assert_eq!(ra.reachable_time_value(), 30_000);
        assert_eq!(ra.retrans_timer_value(), 1_000);
        assert_eq!(ra.options_ref().len(), 1);
        assert_eq!(
            ra.options_ref().options()[0].link_layer_address(),
            Some(doc_mac())
        );

        // Whole packet round-trips byte-for-byte (checksum included).
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // RFC 4861 sec 4.2 / RFC 4862 sec 5.2: the M and O flags are independent.
    // Exercise every boundary combination (neither / M only / O only / both) and
    // assert each flag is reported independently from the decoded header.
    #[test]
    fn router_advertisement_flag_combinations_are_independent() {
        for (managed, other) in [(false, false), (true, false), (false, true), (true, true)] {
            let packet = Ipv6::new().src(link_local_src()).dst(all_routers())
                / Icmpv6::router_advertisement_with(
                    64,
                    managed,
                    other,
                    1800,
                    RouterAdvertisement::new(),
                );
            let compiled = packet.compile().unwrap();
            let bytes = compiled.as_bytes();

            // The flags byte (rest-of-header byte 1) carries exactly the set bits.
            let mut expected = 0u8;
            if managed {
                expected |= ICMPV6_RA_FLAG_MANAGED;
            }
            if other {
                expected |= ICMPV6_RA_FLAG_OTHER;
            }
            assert_eq!(bytes[45], expected, "M={managed} O={other}");

            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
            match decoded.layer::<Icmpv6>().unwrap().body() {
                Icmpv6Body::RouterAdvertisement {
                    managed: m,
                    other: o,
                    reserved_flags,
                    ..
                } => {
                    assert_eq!(m, managed, "M decoded independently");
                    assert_eq!(o, other, "O decoded independently");
                    assert_eq!(reserved_flags, 0, "no reserved bits set");
                }
                other => panic!("expected RouterAdvertisement body, got {other:?}"),
            }
        }
    }

    // Honored overrides: an agent can set a deliberately-wrong header word
    // (here the six Reserved flag bits, which RFC 4861 sec 4.2 says to send as
    // zero, plus an out-of-spec lifetime) via the header rest-of-header, and the
    // value survives compile() and decode unchanged. The Reserved bits are
    // preserved for forward-compat (RFC 5175 / RFC 4191).
    #[test]
    fn router_advertisement_reserved_bits_and_overrides_survive() {
        // cur_hop_limit=1, flags=0xff (M=1, O=1, all six reserved bits set),
        // router_lifetime=0xffff.
        let packet = Ipv6::new().src(link_local_src()).dst(all_routers())
            / (Icmpv6::new()
                .icmp_type(ICMPV6_ROUTER_ADVERTISEMENT)
                .code(0)
                .rest_of_header([0x01, 0xff, 0xff, 0xff])
                / RouterAdvertisement::new());
        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes();
        // The header word survives verbatim.
        assert_eq!(&bytes[44..48], &[0x01, 0xff, 0xff, 0xff]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        assert_eq!(
            decoded.layer::<Icmpv6>().unwrap().body(),
            Icmpv6Body::RouterAdvertisement {
                cur_hop_limit: 0x01,
                managed: true,
                other: true,
                // The six reserved bits (0x3f) are preserved, not masked away.
                reserved_flags: ICMPV6_RA_FLAGS_RESERVED,
                router_lifetime: 0xffff,
            }
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // summary() / show(): the body layer summarizes its own fields, and the
    // header's body-detail field reports the Router Advertisement classification.
    #[test]
    fn router_advertisement_summary_and_show() {
        let body = RouterAdvertisement::new()
            .reachable_time(5)
            .retrans_timer(7)
            .option(NdpOption::source_link_layer_address(doc_mac()));
        assert_eq!(
            body.summary(),
            "RouterAdvertisement(reachable=5, retrans=7, options=1)"
        );

        let header = Icmpv6::new()
            .icmp_type(ICMPV6_ROUTER_ADVERTISEMENT)
            .code(0)
            .rest_of_header(router_advertisement_rest_of_header(
                64,
                ICMPV6_RA_FLAG_MANAGED,
                1800,
            ));
        assert_eq!(
            header.summary(),
            "Icmpv6(type=router-advertisement(134), code=0, id=-, seq=-)"
        );
        let body_field = header
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "body")
            .map(|(_, value)| value)
            .expect("show() exposes a body field");
        assert_eq!(
            body_field,
            "router-advertisement(cur_hop_limit=64, M=true, O=false, reserved_flags=0x00, \
             router_lifetime=1800)"
        );
    }
}
