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
//! ## IPv6 Hop Limit 255 is mandatory for NDP
//!
//! RFC 4861 section 11.2 requires every Neighbor Discovery message to be sent
//! with an IPv6 **Hop Limit of 255**, and a conformant receiver silently
//! discards an NDP message whose Hop Limit is not 255 (this prevents off-link
//! spoofing). These builders return the `Icmpv6` header `/` body and do **not**
//! own the enclosing [`Ipv6`](crate::protocols::Ipv6) layer, so — by the
//! crate's honored-overrides rule — they cannot and do not set the Hop Limit
//! for you. When composing an NDP packet the caller **must** set the IPv6 Hop
//! Limit to 255:
//!
//! ```text
//! Ipv6::new().src(...).dst(...).hop_limit(255)
//!     / Icmpv6::neighbor_solicitation(target)
//! ```
//!
//! A packet built without this still compiles and serializes (the crate emits
//! exactly what you asked for), but real receivers drop it. This was observed
//! against a live Linux kernel: a Neighbor Solicitation sent with the default
//! Hop Limit (64) was counted but never answered, while the same frame with Hop
//! Limit 255 was answered with a Neighbor Advertisement.
//!
//! Wire facts grounded against RFC 4861 (the local `rfc-protocol-spec` manifest
//! cache is sparse for NDP, so the Router Solicitation format in section 4.1 and
//! the Source Link-Layer Address option in section 4.6.1 were read directly from
//! the authoritative RFC text); see the per-item citations below.

use super::super::*;
use super::ndp_option::{NdpOptions, Prf};

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
        self.options.encode_into(out)?;
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
        self.options.encode_into(out)?;
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
    /// flags / Router Lifetime). The Default Router Preference (Prf) is the
    /// default, Medium ([`Prf::Medium`], wire value 0); use
    /// [`Icmpv6::router_advertisement_with_preference`] to set it. The remaining
    /// Reserved flag bits are sent zero; to set them on purpose (a deliberately
    /// malformed packet, or a forward-compatible RFC 5175 bit), build the header
    /// rest-of-header directly with [`Icmpv6::rest_of_header`] (the value survives
    /// `compile()` untouched). The body carries the Reachable Time / Retrans Timer
    /// words and the options.
    pub fn router_advertisement_with(
        cur_hop_limit: u8,
        managed: bool,
        other: bool,
        router_lifetime: u16,
        body: RouterAdvertisement,
    ) -> Packet {
        Self::router_advertisement_with_preference(
            cur_hop_limit,
            managed,
            other,
            Prf::Medium,
            router_lifetime,
            body,
        )
    }

    /// Build a Router Advertisement packet (RFC 4861 section 4.2) with an explicit
    /// Default Router Preference (Prf), RFC 4191 section 2.2.
    ///
    /// This is [`Icmpv6::router_advertisement_with`] plus the RFC 4191 Default
    /// Router Preference. The `preference` is encoded into bits `0x18`
    /// ([`NDP_PRF_MASK`]) of the Router Advertisement flags byte — *without*
    /// disturbing the M (0x80) and O (0x40) flags, which are still driven by
    /// `managed` / `other`. The remaining Reserved bits (RFC 4861's send-as-zero
    /// field, including the RFC 5175 "H" bit at 0x20) stay zero. A receiver of an
    /// RFC 4191 RA reads the preference back through the decoded
    /// [`Icmpv6Body::RouterAdvertisement`](super::super::Icmpv6Body::RouterAdvertisement)
    /// `preference` field.
    ///
    /// [`Prf::Reserved`] (the 2-bit value `10`) "MUST NOT be sent" per RFC 4191
    /// section 2.1; `crafter` still emits it faithfully so an agent can exercise a
    /// peer's handling of the reserved value.
    pub fn router_advertisement_with_preference(
        cur_hop_limit: u8,
        managed: bool,
        other: bool,
        preference: Prf,
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
        // RFC 4191 sec 2.2: the Default Router Preference occupies bits 0x18 of
        // the flags byte, leaving M/O (0x80/0x40) and the other Reserved bits
        // untouched.
        flags |= preference.to_flag_bits();
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

// --- Neighbor Solicitation (RFC 4861 section 4.3) --------------------------

/// Width, in octets, of the Target Address that leads a Neighbor Solicitation
/// body (RFC 4861 section 4.3: a 128-bit IPv6 address).
const NS_TARGET_ADDRESS_LEN: usize = 16;

/// Neighbor Solicitation message body (RFC 4861 section 4.3).
///
/// On the wire a Neighbor Solicitation is ICMPv6 `type` 135, `code` 0, a 32-bit
/// Reserved field (RFC 4861 section 4.3: "This field is unused. It MUST be
/// initialized to zero by the sender and MUST be ignored by the receiver."), a
/// 128-bit Target Address — "The IP address of the target of the solicitation.
/// It MUST NOT be a multicast address." — then zero or more options, commonly
/// the Source Link-Layer Address option (RFC 4861 section 4.6.1).
///
/// Neighbor Solicitation is the IPv6 analogue of ARP "who-has": a host sends it
/// to resolve a neighbor's link-layer address (the Target Address is the address
/// being resolved, the solicited-node multicast `ff02::1:ffXX:XXXX` is the usual
/// IPv6 destination) and as a Duplicate Address Detection (DAD) probe (RFC 4862
/// section 5.4: the probe carries the tentative address as the Target Address and
/// is sent from the unspecified source `::`, which per RFC 4861 section 4.3 means
/// the Source Link-Layer Address option MUST NOT be present).
///
/// Following the NDP message pattern established by [`RouterSolicitation`], the
/// 32-bit Reserved field is the [`Icmpv6`] header's four-byte rest-of-header
/// (set on the header — not in this body — by [`Icmpv6::neighbor_solicitation`])
/// so the split matches the wire layout and the way ICMPv4 keeps its
/// rest-of-header fields on the header. This body carries exactly the part after
/// the fixed 8-byte header: the 16-byte Target Address and the ordered
/// [`NdpOptions`]. The header auto-fills the ICMPv6 checksum over the IPv6
/// pseudo-header, covering this body's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborSolicitation {
    // `pub(crate)` so the ICMPv6 decode path in `icmp/v6/mod.rs` can construct
    // the body from wire bytes; the public surface is the builder/accessors.
    pub(crate) target_address: core::net::Ipv6Addr,
    pub(crate) options: NdpOptions,
}

impl NeighborSolicitation {
    /// Create a Neighbor Solicitation body resolving `target_address` (the IPv6
    /// address being resolved — RFC 4861 section 4.3 requires it MUST NOT be a
    /// multicast address) with no options. Compose it under an [`Icmpv6`] header
    /// (type 135, code 0) — or use [`Icmpv6::neighbor_solicitation`], which sets
    /// the header type/code and zero Reserved word for you.
    pub fn new(target_address: core::net::Ipv6Addr) -> Self {
        Self {
            target_address,
            options: NdpOptions::new(),
        }
    }

    /// Set the Target Address (RFC 4861 section 4.3: the address being resolved;
    /// MUST NOT be a multicast address).
    pub fn target_address(mut self, target_address: core::net::Ipv6Addr) -> Self {
        self.target_address = target_address;
        self
    }

    /// Append an NDP option (RFC 4861 section 4.6), preserving order.
    ///
    /// The common option on a Neighbor Solicitation is the Source Link-Layer
    /// Address (RFC 4861 section 4.6.1); see
    /// [`Icmpv6::neighbor_solicitation_with_source_link_layer`] for the shorthand,
    /// or build one with [`NdpOption::source_link_layer_address`]. Note RFC 4861
    /// section 4.3: this option MUST NOT be included when the source IP address is
    /// the unspecified address (a DAD probe).
    pub fn option(mut self, option: NdpOption) -> Self {
        self.options.add(option);
        self
    }

    /// Replace the whole ordered option list.
    pub fn options(mut self, options: NdpOptions) -> Self {
        self.options = options;
        self
    }

    /// The Target Address field (the IPv6 address being resolved).
    pub fn target_address_value(&self) -> core::net::Ipv6Addr {
        self.target_address
    }

    /// The ordered NDP options carried after the Target Address.
    pub fn options_ref(&self) -> &NdpOptions {
        &self.options
    }
}

impl Layer for NeighborSolicitation {
    fn name(&self) -> &'static str {
        "NeighborSolicitation"
    }

    fn summary(&self) -> String {
        format!(
            "NeighborSolicitation(target={}, options={})",
            self.target_address,
            self.options.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("target_address", self.target_address.to_string()),
            ("option_count", self.options.len().to_string()),
        ];
        for (index, option) in self.options.iter().enumerate() {
            fields.push((option_field_name(index), option.to_string()));
        }
        fields
    }

    fn encoded_len(&self) -> usize {
        NS_TARGET_ADDRESS_LEN + self.options.encoded_len().unwrap_or(0)
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.target_address.octets());
        self.options.encode_into(out)?;
        Ok(())
    }

    impl_layer_object!(NeighborSolicitation);
}

impl_layer_div!(NeighborSolicitation);

impl Icmpv6 {
    /// Build a Neighbor Solicitation packet (RFC 4861 section 4.3) resolving
    /// `target`.
    ///
    /// Returns a [`Packet`] composing the [`Icmpv6`] header (type 135, code 0, the
    /// four-byte Reserved rest-of-header left zero per RFC 4861 section 4.3) with a
    /// [`NeighborSolicitation`] body carrying `target` (the IPv6 address being
    /// resolved — RFC 4861 section 4.3 requires it MUST NOT be a multicast
    /// address) and no options. Attach a Source Link-Layer Address option with
    /// [`Icmpv6::neighbor_solicitation_with_source_link_layer`], or build the body
    /// explicitly. `compile()` auto-fills the ICMPv6 checksum over the IPv6
    /// pseudo-header, covering the body's bytes.
    ///
    /// A Neighbor Solicitation sent from the unspecified source `::` (with no
    /// Source Link-Layer Address option) is a Duplicate Address Detection probe
    /// (RFC 4862 section 5.4); set the source on the enclosing [`Ipv6`](crate::Ipv6)
    /// layer.
    pub fn neighbor_solicitation(target: core::net::Ipv6Addr) -> Packet {
        Self::neighbor_solicitation_body(NeighborSolicitation::new(target))
    }

    /// Build a Neighbor Solicitation packet resolving `target` and carrying a
    /// Source Link-Layer Address option (RFC 4861 sections 4.3 and 4.6.1) with the
    /// sender's MAC.
    ///
    /// This is the common address-resolution Neighbor Solicitation an Ethernet
    /// host sends (RFC 4861 section 4.3: the Source Link-Layer Address option MUST
    /// be included in multicast solicitations on link layers that have addresses).
    /// Equivalent to [`Icmpv6::neighbor_solicitation`] with a single
    /// [`NdpOption::source_link_layer_address`] option appended. Do **not** use
    /// this for a DAD probe — RFC 4861 section 4.3 forbids the option when the
    /// source is the unspecified address.
    pub fn neighbor_solicitation_with_source_link_layer(
        target: core::net::Ipv6Addr,
        mac: crate::MacAddr,
    ) -> Packet {
        Self::neighbor_solicitation_body(
            NeighborSolicitation::new(target).option(NdpOption::source_link_layer_address(mac)),
        )
    }

    /// Compose the Neighbor Solicitation header (type 135, code 0, reserved word
    /// zero) with a caller-built [`NeighborSolicitation`] body.
    fn neighbor_solicitation_body(body: NeighborSolicitation) -> Packet {
        Self::new().icmp_type(ICMPV6_NEIGHBOR_SOLICITATION).code(0) / body
    }
}

/// Decode the body of an ICMPv6 Neighbor Solicitation: the 128-bit Target Address
/// (RFC 4861 section 4.3) followed by the NDP option area. The 32-bit Reserved
/// rest-of-header lives in the header and is decoded there.
///
/// Returns a structured [`CrafterError`] (never a panic) when the body is too
/// short to hold the Target Address, or when an option is malformed (a zero
/// length or an overrun); the option walk is delegated to [`NdpOptions::decode`].
pub(crate) fn decode_neighbor_solicitation(bytes: &[u8]) -> Result<NeighborSolicitation> {
    if bytes.len() < NS_TARGET_ADDRESS_LEN {
        return Err(CrafterError::buffer_too_short(
            "icmpv6.neighbor_solicitation.target_address",
            NS_TARGET_ADDRESS_LEN,
            bytes.len(),
        ));
    }
    let mut octets = [0u8; NS_TARGET_ADDRESS_LEN];
    octets.copy_from_slice(&bytes[..NS_TARGET_ADDRESS_LEN]);
    let target_address = core::net::Ipv6Addr::from(octets);
    let options = NdpOptions::decode(&bytes[NS_TARGET_ADDRESS_LEN..])?;
    Ok(NeighborSolicitation {
        target_address,
        options,
    })
}

// --- Neighbor Advertisement (RFC 4861 section 4.4) -------------------------

/// Width, in octets, of the Target Address that leads a Neighbor Advertisement
/// body (RFC 4861 section 4.4: a 128-bit IPv6 address).
const NA_TARGET_ADDRESS_LEN: usize = 16;

/// Bit mask for the R (Router) flag in the first byte of the Neighbor
/// Advertisement rest-of-header (RFC 4861 section 4.4: "the most significant
/// bit"). Equivalently `0x80000000` in the 32-bit flags word. "When set, the
/// R-bit indicates that the sender is a router."
pub const ICMPV6_NA_FLAG_ROUTER: u8 = 0x80;

/// Bit mask for the S (Solicited) flag in the first byte of the Neighbor
/// Advertisement rest-of-header (RFC 4861 section 4.4: the second bit, 0x40).
/// Equivalently `0x40000000` in the 32-bit flags word. "When set, the S-bit
/// indicates that the advertisement was sent in response to a Neighbor
/// Solicitation."
pub const ICMPV6_NA_FLAG_SOLICITED: u8 = 0x40;

/// Bit mask for the O (Override) flag in the first byte of the Neighbor
/// Advertisement rest-of-header (RFC 4861 section 4.4: the third bit, 0x20).
/// Equivalently `0x20000000` in the 32-bit flags word. "When set, the O-bit
/// indicates that the advertisement should override an existing cache entry and
/// update the cached link-layer address."
pub const ICMPV6_NA_FLAG_OVERRIDE: u8 = 0x20;

/// Mask of the 29 Reserved bits in the Neighbor Advertisement flags word
/// (RFC 4861 section 4.4: "A 29-bit unused field. It MUST be initialized to zero
/// by the sender and MUST be ignored by the receiver."). These bits are
/// preserved verbatim through build/decode for forward-compatibility. The mask
/// is the low 29 bits of the 32-bit rest-of-header word (the three high bits are
/// the R/S/O flags).
pub const ICMPV6_NA_FLAGS_RESERVED: u32 = 0x1fff_ffff;

/// Neighbor Advertisement message body (RFC 4861 section 4.4).
///
/// On the wire a Neighbor Advertisement is ICMPv6 `type` 136, `code` 0, then a
/// 32-bit flags word — R (Router, bit 0x80000000), S (Solicited, bit
/// 0x40000000), O (Override, bit 0x20000000), and 29 Reserved bits ("MUST be
/// initialized to zero by the sender and MUST be ignored by the receiver") — a
/// 128-bit Target Address ("the Target Address field in the Neighbor
/// Solicitation message that prompted this advertisement"; for an unsolicited
/// advertisement, the address whose link-layer address changed), then zero or
/// more options, commonly the Target Link-Layer Address option (RFC 4861 section
/// 4.6.1).
///
/// Neighbor Advertisement is the IPv6 analogue of ARP "is-at": it answers a
/// Neighbor Solicitation, carrying the responder's link-layer address in a Target
/// Link-Layer Address option.
///
/// Following the NDP message pattern established by [`RouterSolicitation`], the
/// 32-bit flags word (R/S/O plus the 29 Reserved bits) is the [`Icmpv6`]
/// header's four-byte rest-of-header (set on the header — not in this body — by
/// [`Icmpv6::neighbor_advertisement`]) so the split matches the wire layout and
/// the way ICMPv4 keeps its rest-of-header fields on the header. This body carries
/// exactly the part after the fixed 8-byte header: the 16-byte Target Address and
/// the ordered [`NdpOptions`]. The header auto-fills the ICMPv6 checksum over the
/// IPv6 pseudo-header, covering this body's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborAdvertisement {
    // `pub(crate)` so the ICMPv6 decode path in `icmp/v6/mod.rs` can construct
    // the body from wire bytes; the public surface is the builder/accessors.
    pub(crate) target_address: core::net::Ipv6Addr,
    pub(crate) options: NdpOptions,
}

impl NeighborAdvertisement {
    /// Create a Neighbor Advertisement body whose Target Address is
    /// `target_address` (RFC 4861 section 4.4: for a solicited advertisement, the
    /// Target Address of the Neighbor Solicitation being answered; MUST NOT be a
    /// multicast address) with no options. Compose it under an [`Icmpv6`] header
    /// (type 136, code 0) — or use [`Icmpv6::neighbor_advertisement`], which sets
    /// the header type/code and the R/S/O flags word for you.
    pub fn new(target_address: core::net::Ipv6Addr) -> Self {
        Self {
            target_address,
            options: NdpOptions::new(),
        }
    }

    /// Set the Target Address (RFC 4861 section 4.4: the address whose link-layer
    /// address this advertisement reports; MUST NOT be a multicast address).
    pub fn target_address(mut self, target_address: core::net::Ipv6Addr) -> Self {
        self.target_address = target_address;
        self
    }

    /// Append an NDP option (RFC 4861 section 4.6), preserving order.
    ///
    /// The common option on a Neighbor Advertisement is the Target Link-Layer
    /// Address (RFC 4861 section 4.6.1), which carries the responder's MAC; see
    /// [`Icmpv6::neighbor_advertisement_with_target_link_layer`] for the shorthand,
    /// or build one with [`NdpOption::target_link_layer_address`].
    pub fn option(mut self, option: NdpOption) -> Self {
        self.options.add(option);
        self
    }

    /// Replace the whole ordered option list.
    pub fn options(mut self, options: NdpOptions) -> Self {
        self.options = options;
        self
    }

    /// The Target Address field (the IPv6 address whose link-layer address this
    /// advertisement reports).
    pub fn target_address_value(&self) -> core::net::Ipv6Addr {
        self.target_address
    }

    /// The ordered NDP options carried after the Target Address.
    pub fn options_ref(&self) -> &NdpOptions {
        &self.options
    }
}

impl Layer for NeighborAdvertisement {
    fn name(&self) -> &'static str {
        "NeighborAdvertisement"
    }

    fn summary(&self) -> String {
        format!(
            "NeighborAdvertisement(target={}, options={})",
            self.target_address,
            self.options.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("target_address", self.target_address.to_string()),
            ("option_count", self.options.len().to_string()),
        ];
        for (index, option) in self.options.iter().enumerate() {
            fields.push((option_field_name(index), option.to_string()));
        }
        fields
    }

    fn encoded_len(&self) -> usize {
        NA_TARGET_ADDRESS_LEN + self.options.encoded_len().unwrap_or(0)
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.target_address.octets());
        self.options.encode_into(out)?;
        Ok(())
    }

    impl_layer_object!(NeighborAdvertisement);
}

impl_layer_div!(NeighborAdvertisement);

/// Pack the Neighbor Advertisement rest-of-header (RFC 4861 section 4.4): the
/// 32-bit flags word with the R/S/O bits in the three most-significant bits and
/// the 29 Reserved bits left zero (big-endian).
fn neighbor_advertisement_rest_of_header(
    router: bool,
    solicited: bool,
    override_flag: bool,
) -> [u8; 4] {
    let mut flags = 0u8;
    if router {
        flags |= ICMPV6_NA_FLAG_ROUTER;
    }
    if solicited {
        flags |= ICMPV6_NA_FLAG_SOLICITED;
    }
    if override_flag {
        flags |= ICMPV6_NA_FLAG_OVERRIDE;
    }
    // Flags occupy the top three bits of the first byte; the remaining 29 bits
    // (the rest of byte 0 and bytes 1..4) are Reserved and sent as zero.
    [flags, 0, 0, 0]
}

impl Icmpv6 {
    /// Build a Neighbor Advertisement packet (RFC 4861 section 4.4) for `target`,
    /// with the R/S/O flags clear and no options.
    ///
    /// Returns a [`Packet`] composing the [`Icmpv6`] header (type 136, code 0, the
    /// four-byte flags rest-of-header with R/S/O clear and the 29 Reserved bits
    /// zero) with a [`NeighborAdvertisement`] body carrying `target` (RFC 4861
    /// section 4.4 requires the Target Address MUST NOT be a multicast address) and
    /// no options. Set the flags with
    /// [`Icmpv6::neighbor_advertisement_with`], attach a Target Link-Layer Address
    /// option with [`Icmpv6::neighbor_advertisement_with_target_link_layer`], or
    /// build the body explicitly. `compile()` auto-fills the ICMPv6 checksum over
    /// the IPv6 pseudo-header, covering the body's bytes.
    pub fn neighbor_advertisement(target: core::net::Ipv6Addr) -> Packet {
        Self::neighbor_advertisement_with(false, false, false, NeighborAdvertisement::new(target))
    }

    /// Build a Neighbor Advertisement packet (RFC 4861 section 4.4) with explicit
    /// R/S/O flags and a caller-built [`NeighborAdvertisement`] body.
    ///
    /// `router` (the R / Router flag — the sender is a router), `solicited` (the
    /// S / Solicited flag — sent in response to a Neighbor Solicitation), and
    /// `override_flag` (the O / Override flag — override an existing cache entry)
    /// become the three most-significant bits of the [`Icmpv6`] header's four-byte
    /// rest-of-header flags word; the 29 Reserved bits are sent zero. To set the
    /// Reserved bits on purpose (a deliberately malformed packet), build the header
    /// rest-of-header directly with [`Icmpv6::rest_of_header`] — the value survives
    /// `compile()` untouched. The body carries the Target Address and any options.
    pub fn neighbor_advertisement_with(
        router: bool,
        solicited: bool,
        override_flag: bool,
        body: NeighborAdvertisement,
    ) -> Packet {
        let rest = neighbor_advertisement_rest_of_header(router, solicited, override_flag);
        Self::new()
            .icmp_type(ICMPV6_NEIGHBOR_ADVERTISEMENT)
            .code(0)
            .rest_of_header(rest)
            / body
    }

    /// Build a Neighbor Advertisement packet for `target` carrying a Target
    /// Link-Layer Address option (RFC 4861 sections 4.4 and 4.6.1) with the
    /// responder's MAC, and the R/S/O flags set as requested.
    ///
    /// This is the common "is-at" reply an Ethernet host sends to answer a Neighbor
    /// Solicitation (RFC 4861 section 4.4: the Target Link-Layer Address option MUST
    /// be included when responding to multicast solicitations on link layers that
    /// have addresses). A solicited reply to a unicast neighbor typically sets
    /// `solicited` and `override_flag`; set `router` when the sender is a router.
    /// Equivalent to [`Icmpv6::neighbor_advertisement_with`] with a single
    /// [`NdpOption::target_link_layer_address`] option appended.
    pub fn neighbor_advertisement_with_target_link_layer(
        target: core::net::Ipv6Addr,
        mac: crate::MacAddr,
        router: bool,
        solicited: bool,
        override_flag: bool,
    ) -> Packet {
        Self::neighbor_advertisement_with(
            router,
            solicited,
            override_flag,
            NeighborAdvertisement::new(target).option(NdpOption::target_link_layer_address(mac)),
        )
    }
}

/// Decode the body of an ICMPv6 Neighbor Advertisement: the 128-bit Target Address
/// (RFC 4861 section 4.4) followed by the NDP option area. The 32-bit R/S/O flags
/// word (and its 29 Reserved bits) is the header's rest-of-header and is decoded
/// there.
///
/// Returns a structured [`CrafterError`] (never a panic) when the body is too
/// short to hold the Target Address, or when an option is malformed (a zero
/// length or an overrun); the option walk is delegated to [`NdpOptions::decode`].
pub(crate) fn decode_neighbor_advertisement(bytes: &[u8]) -> Result<NeighborAdvertisement> {
    if bytes.len() < NA_TARGET_ADDRESS_LEN {
        return Err(CrafterError::buffer_too_short(
            "icmpv6.neighbor_advertisement.target_address",
            NA_TARGET_ADDRESS_LEN,
            bytes.len(),
        ));
    }
    let mut octets = [0u8; NA_TARGET_ADDRESS_LEN];
    octets.copy_from_slice(&bytes[..NA_TARGET_ADDRESS_LEN]);
    let target_address = core::net::Ipv6Addr::from(octets);
    let options = NdpOptions::decode(&bytes[NA_TARGET_ADDRESS_LEN..])?;
    Ok(NeighborAdvertisement {
        target_address,
        options,
    })
}

// --- Redirect (RFC 4861 section 4.5) ---------------------------------------

/// Width, in octets, of each of the two 128-bit IPv6 addresses (Target Address
/// and Destination Address) that lead a Redirect body (RFC 4861 section 4.5).
const REDIRECT_ADDRESS_LEN: usize = 16;

/// Combined width, in octets, of the two fixed Redirect addresses (Target
/// Address + Destination Address) that precede the option area.
const REDIRECT_BODY_FIXED_LEN: usize = REDIRECT_ADDRESS_LEN * 2;

/// Redirect message body (RFC 4861 section 4.5).
///
/// On the wire a Redirect is ICMPv6 `type` 137, `code` 0, a 32-bit Reserved
/// field (RFC 4861 section 4.5: "This field is unused. It MUST be initialized to
/// zero by the sender and MUST be ignored by the receiver."), a 128-bit Target
/// Address — "An IP address that is a better first hop to use for the ICMP
/// Destination Address ... The Target Address MUST NOT be a multicast address."
/// — a 128-bit Destination Address — "The IP address of the destination that is
/// redirected to the target." — then zero or more options, commonly the Target
/// Link-Layer Address option (RFC 4861 section 4.6.1) and the Redirected Header
/// option (RFC 4861 section 4.6.3) carrying as much of the packet that triggered
/// the Redirect as fits.
///
/// A router sends a Redirect to inform a host of a better first hop for a
/// destination (the analogue of an ICMPv4 Redirect, type 5): the Target Address
/// is the better next hop and the Destination Address is the destination being
/// redirected. When the target is the destination itself (the destination is in
/// fact a neighbor), Target Address and Destination Address are equal.
///
/// Following the NDP message pattern established by [`RouterSolicitation`], the
/// 32-bit Reserved field is the [`Icmpv6`] header's four-byte rest-of-header
/// (set on the header — not in this body — by [`Icmpv6::redirect`]) so the split
/// matches the wire layout and the way ICMPv4 keeps its rest-of-header fields on
/// the header. This body carries exactly the part after the fixed 8-byte header:
/// the 16-byte Target Address, the 16-byte Destination Address, and the ordered
/// [`NdpOptions`]. The header auto-fills the ICMPv6 checksum over the IPv6
/// pseudo-header, covering this body's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    // `pub(crate)` so the ICMPv6 decode path in `icmp/v6/mod.rs` can construct
    // the body from wire bytes; the public surface is the builder/accessors.
    pub(crate) target_address: core::net::Ipv6Addr,
    pub(crate) destination_address: core::net::Ipv6Addr,
    pub(crate) options: NdpOptions,
}

impl Redirect {
    /// Create a Redirect body advertising `target_address` (the better first hop;
    /// RFC 4861 section 4.5 requires it MUST NOT be a multicast address) for
    /// `destination_address` (the destination being redirected) with no options.
    /// Compose it under an [`Icmpv6`] header (type 137, code 0) — or use
    /// [`Icmpv6::redirect`], which sets the header type/code and zero Reserved
    /// word for you.
    pub fn new(
        target_address: core::net::Ipv6Addr,
        destination_address: core::net::Ipv6Addr,
    ) -> Self {
        Self {
            target_address,
            destination_address,
            options: NdpOptions::new(),
        }
    }

    /// Set the Target Address (RFC 4861 section 4.5: a better first hop for the
    /// Destination Address; MUST NOT be a multicast address).
    pub fn target_address(mut self, target_address: core::net::Ipv6Addr) -> Self {
        self.target_address = target_address;
        self
    }

    /// Set the Destination Address (RFC 4861 section 4.5: the destination that is
    /// redirected to the target).
    pub fn destination_address(mut self, destination_address: core::net::Ipv6Addr) -> Self {
        self.destination_address = destination_address;
        self
    }

    /// Append an NDP option (RFC 4861 section 4.6), preserving order.
    ///
    /// The common options on a Redirect are the Target Link-Layer Address
    /// (RFC 4861 section 4.6.1), carrying the target's MAC, and the Redirected
    /// Header (RFC 4861 section 4.6.3), carrying the packet that triggered the
    /// Redirect; build them with [`NdpOption::target_link_layer_address`] and
    /// [`NdpOption::redirected_header`].
    pub fn option(mut self, option: NdpOption) -> Self {
        self.options.add(option);
        self
    }

    /// Replace the whole ordered option list.
    pub fn options(mut self, options: NdpOptions) -> Self {
        self.options = options;
        self
    }

    /// The Target Address field (the better first hop for the Destination
    /// Address).
    pub fn target_address_value(&self) -> core::net::Ipv6Addr {
        self.target_address
    }

    /// The Destination Address field (the destination being redirected).
    pub fn destination_address_value(&self) -> core::net::Ipv6Addr {
        self.destination_address
    }

    /// The ordered NDP options carried after the Target and Destination
    /// Addresses.
    pub fn options_ref(&self) -> &NdpOptions {
        &self.options
    }
}

impl Layer for Redirect {
    fn name(&self) -> &'static str {
        "Redirect"
    }

    fn summary(&self) -> String {
        format!(
            "Redirect(target={}, destination={}, options={})",
            self.target_address,
            self.destination_address,
            self.options.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("target_address", self.target_address.to_string()),
            ("destination_address", self.destination_address.to_string()),
            ("option_count", self.options.len().to_string()),
        ];
        for (index, option) in self.options.iter().enumerate() {
            fields.push((option_field_name(index), option.to_string()));
        }
        fields
    }

    fn encoded_len(&self) -> usize {
        REDIRECT_BODY_FIXED_LEN + self.options.encoded_len().unwrap_or(0)
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.target_address.octets());
        out.extend_from_slice(&self.destination_address.octets());
        self.options.encode_into(out)?;
        Ok(())
    }

    impl_layer_object!(Redirect);
}

impl_layer_div!(Redirect);

impl Icmpv6 {
    /// Build a Redirect packet (RFC 4861 section 4.5) advertising `target` as a
    /// better first hop for `destination`.
    ///
    /// Returns a [`Packet`] composing the [`Icmpv6`] header (type 137, code 0, the
    /// four-byte Reserved rest-of-header left zero per RFC 4861 section 4.5) with a
    /// [`Redirect`] body carrying `target` (the better first hop — RFC 4861
    /// section 4.5 requires it MUST NOT be a multicast address) and `destination`
    /// (the destination being redirected) and no options. Attach a Target
    /// Link-Layer Address option ([`NdpOption::target_link_layer_address`]) and/or
    /// a Redirected Header option ([`NdpOption::redirected_header`]) by building
    /// the body explicitly — for example
    /// `Icmpv6::new().icmp_type(ICMPV6_REDIRECT).code(0) /
    /// Redirect::new(target, destination).option(...)`. `compile()` auto-fills the
    /// ICMPv6 checksum over the IPv6 pseudo-header, covering the body's bytes.
    ///
    /// When the destination is in fact a neighbor, the target and destination are
    /// the same address (RFC 4861 section 4.5).
    pub fn redirect(target: core::net::Ipv6Addr, destination: core::net::Ipv6Addr) -> Packet {
        Self::redirect_body(Redirect::new(target, destination))
    }

    /// Compose the Redirect header (type 137, code 0, reserved word zero) with a
    /// caller-built [`Redirect`] body.
    fn redirect_body(body: Redirect) -> Packet {
        Self::new().icmp_type(ICMPV6_REDIRECT).code(0) / body
    }
}

/// Decode the body of an ICMPv6 Redirect: the 128-bit Target Address followed by
/// the 128-bit Destination Address (RFC 4861 section 4.5) and then the NDP option
/// area. The 32-bit Reserved rest-of-header lives in the header and is decoded
/// there.
///
/// Returns a structured [`CrafterError`] (never a panic) when the body is too
/// short to hold both addresses, or when an option is malformed (a zero length or
/// an overrun); the option walk is delegated to [`NdpOptions::decode`].
pub(crate) fn decode_redirect(bytes: &[u8]) -> Result<Redirect> {
    if bytes.len() < REDIRECT_BODY_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "icmpv6.redirect.addresses",
            REDIRECT_BODY_FIXED_LEN,
            bytes.len(),
        ));
    }
    let mut target = [0u8; REDIRECT_ADDRESS_LEN];
    target.copy_from_slice(&bytes[..REDIRECT_ADDRESS_LEN]);
    let mut destination = [0u8; REDIRECT_ADDRESS_LEN];
    destination.copy_from_slice(&bytes[REDIRECT_ADDRESS_LEN..REDIRECT_BODY_FIXED_LEN]);
    let options = NdpOptions::decode(&bytes[REDIRECT_BODY_FIXED_LEN..])?;
    Ok(Redirect {
        target_address: core::net::Ipv6Addr::from(target),
        destination_address: core::net::Ipv6Addr::from(destination),
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
                preference: Prf::Medium,
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
                // flags byte 0xff: M (0x80) | O (0x40) | the RFC 4191 Prf bits
                // (0x18 = 0b11 = Low) | the remaining reserved bits (0x27). The
                // Prf bits decode to Prf::Low and the reserved bits (0x27, the
                // 0x20 "H" bit and the low three reserved bits) are preserved,
                // not masked away.
                preference: Prf::Low,
                reserved_flags: ICMPV6_RA_FLAGS_RESERVED & !NDP_PRF_MASK,
                router_lifetime: 0xffff,
            }
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // RFC 4191 sec 2.2: the Default Router Preference (Prf) rides in bits 0x18 of
    // the RA flags byte. Build an RA with each preference value and assert: the
    // wire flags byte carries M/O plus exactly the Prf bits (nothing in the
    // remaining reserved bits), the decoded body reports the right preference,
    // and M/O and the reserved bits are unaffected.
    #[test]
    fn router_advertisement_default_router_preference_round_trips() {
        for prf in [Prf::Medium, Prf::High, Prf::Low] {
            // Set M=true, O=false to prove the Prf wiring leaves M/O alone.
            let packet = Ipv6::new().src(link_local_src()).dst(all_routers())
                / Icmpv6::router_advertisement_with_preference(
                    64,
                    true,
                    false,
                    prf,
                    1800,
                    RouterAdvertisement::new(),
                );
            let compiled = packet.compile().unwrap();
            let bytes = compiled.as_bytes();

            // The flags byte (rest-of-header byte 1, packet offset 45) is exactly
            // M | Prf, with no stray reserved bits.
            let expected_flags = ICMPV6_RA_FLAG_MANAGED | prf.to_flag_bits();
            assert_eq!(bytes[45], expected_flags, "flags byte for {prf:?}");
            assert_eq!(bytes[45] & ICMPV6_RA_FLAG_OTHER, 0, "O stays clear");

            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
            assert_eq!(
                decoded.layer::<Icmpv6>().unwrap().body(),
                Icmpv6Body::RouterAdvertisement {
                    cur_hop_limit: 64,
                    managed: true,
                    other: false,
                    preference: prf,
                    // The Prf bits were split out, so the remaining reserved bits
                    // are zero — unaffected by setting the preference.
                    reserved_flags: 0,
                    router_lifetime: 1800,
                },
                "decoded preference and untouched M/O/reserved for {prf:?}"
            );
            assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
        }
    }

    // RFC 4861 sec 4.6.2 + 4.6.4: a Router Advertisement carrying a Prefix
    // Information option (doc prefix 2001:db8::/64) and an MTU option together,
    // in arbitrary order, round-trips through compile()/decode preserving option
    // order and every field. The packet also exercises the checksum over the
    // larger option area.
    #[test]
    fn router_advertisement_with_prefix_and_mtu_round_trips() {
        use crate::protocols::icmp::{NDP_OPT_MTU, NDP_OPT_PREFIX_INFORMATION};

        // Documentation prefix (RFC 3849) 2001:db8::/64.
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        // Deliberately put MTU *before* Prefix Information to prove arbitrary
        // order survives.
        let body = RouterAdvertisement::new()
            .reachable_time(30_000)
            .retrans_timer(1_000)
            .options(NdpOptions::new().push(NdpOption::mtu(1500)).push(
                NdpOption::prefix_information(prefix, 64, true, true, 2_592_000, 604_800),
            ));
        let packet = Ipv6::new()
            .src(link_local_src())
            .dst(all_routers())
            .hlim(255)
            / Icmpv6::router_advertisement_with(64, false, false, 1800, body);
        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let ra = decoded.layer::<RouterAdvertisement>().unwrap();
        assert_eq!(ra.reachable_time_value(), 30_000);
        assert_eq!(ra.retrans_timer_value(), 1_000);
        assert_eq!(ra.options_ref().len(), 2);

        // Order is preserved: MTU first, Prefix Information second.
        let opts = ra.options_ref().options();
        assert_eq!(opts[0].option_type(), NDP_OPT_MTU);
        assert_eq!(opts[0].mtu_value(), Some(1500));
        assert_eq!(opts[1].option_type(), NDP_OPT_PREFIX_INFORMATION);
        assert_eq!(opts[1].prefix(), Some(prefix));
        assert_eq!(opts[1].prefix_length(), Some(64));
        assert_eq!(opts[1].prefix_on_link(), Some(true));
        assert_eq!(opts[1].prefix_autonomous(), Some(true));
        assert_eq!(opts[1].prefix_valid_lifetime(), Some(2_592_000));
        assert_eq!(opts[1].prefix_preferred_lifetime(), Some(604_800));

        // Whole packet round-trips byte-for-byte (checksum over the IPv6
        // pseudo-header includes both options).
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // L/A flag independence asserted end-to-end through a Router Advertisement:
    // neither / L / A / both each decode independently from the carried Prefix
    // Information option.
    #[test]
    fn router_advertisement_prefix_flag_independence() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        for (on_link, autonomous) in [(false, false), (true, false), (false, true), (true, true)] {
            let body = RouterAdvertisement::new().option(NdpOption::prefix_information(
                prefix, 64, on_link, autonomous, 86_400, 14_400,
            ));
            let packet = Ipv6::new().src(link_local_src()).dst(all_routers())
                / Icmpv6::router_advertisement_with(64, false, false, 1800, body);
            let bytes = packet.compile().unwrap();
            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
            let pi = &decoded
                .layer::<RouterAdvertisement>()
                .unwrap()
                .options_ref()
                .options()[0];
            assert_eq!(
                pi.prefix_on_link(),
                Some(on_link),
                "L independent (L={on_link} A={autonomous})"
            );
            assert_eq!(
                pi.prefix_autonomous(),
                Some(autonomous),
                "A independent (L={on_link} A={autonomous})"
            );
            assert_eq!(pi.prefix_valid_lifetime(), Some(86_400));
            assert_eq!(pi.prefix_preferred_lifetime(), Some(14_400));
        }
    }

    // A deliberately-wrong option length on a Prefix Information option carried by
    // a Router Advertisement survives compile() (honored overrides), so the
    // emitted option-area Length byte stays the wrong value.
    #[test]
    fn router_advertisement_wrong_prefix_length_survives() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        // Pin the Prefix Information length to 5 units (out of spec; real is 4).
        let body = RouterAdvertisement::new()
            .option(NdpOption::prefix_information(prefix, 64, true, false, 0, 0).length(5));
        let packet = Ipv6::new().src(link_local_src()).dst(all_routers())
            / Icmpv6::router_advertisement_with(64, false, false, 1800, body);
        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes();
        // ICMPv6 at offset 40; header(8) + reachable(4) + retrans(4) = option area
        // starts at offset 40+16 = 56. Option Length byte is at 56+1 = 57.
        assert_eq!(
            bytes[56],
            crate::protocols::icmp::NDP_OPT_PREFIX_INFORMATION
        );
        assert_eq!(
            bytes[57], 5,
            "deliberately-wrong option length survives compile()"
        );
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
            "router-advertisement(cur_hop_limit=64, M=true, O=false, prf=Medium, \
             reserved_flags=0x00, router_lifetime=1800)"
        );
    }

    // The address being resolved in the address-resolution and DAD tests: a
    // documentation unicast address (RFC 3849 2001:db8::/32). RFC 4861 sec 4.3
    // requires the Target Address MUST NOT be a multicast address.
    fn doc_target() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0042)
    }

    // The solicited-node multicast address ff02::1:ff42:0042 derived from
    // doc_target() (RFC 4861 sec 2: ff02::1:ffXX:XXXX, the low 24 bits of the
    // target). This is the usual IPv6 *destination* of an address-resolution
    // Neighbor Solicitation — the Target Address itself stays the unicast
    // doc_target().
    fn solicited_node_multicast() -> Ipv6Addr {
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff42, 0x0042)
    }

    // RFC 4861 sec 4.3 + 4.6.1: an address-resolution Neighbor Solicitation
    // (Target Address = the unicast address being resolved, carrying a Source
    // Link-Layer Address option, sent to the solicited-node multicast) compiles to
    // type 135 / code 0, a zero Reserved word, the 16-byte Target Address, and the
    // SLLA option, and decodes back to the same fields with the checksum verifying
    // over the IPv6 pseudo-header.
    #[test]
    fn neighbor_solicitation_with_slla_round_trips() {
        let target = doc_target();
        let packet = Ipv6::new()
            .src(link_local_src())
            .dst(solicited_node_multicast())
            .hlim(255)
            / Icmpv6::neighbor_solicitation_with_source_link_layer(target, doc_mac());
        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes();

        // ICMPv6 starts at offset 40. type 135, code 0.
        assert_eq!(bytes[40], ICMPV6_NEIGHBOR_SOLICITATION);
        assert_eq!(bytes[41], 0, "code is 0");
        // Reserved field (ICMPv6 rest-of-header, bytes 4..8) is zero.
        assert_eq!(&bytes[44..48], &[0, 0, 0, 0]);
        // Target Address: the 16 octets right after the fixed 8-byte header.
        assert_eq!(&bytes[48..64], &target.octets());
        // SLLA option follows the Target Address: type 1, length 1, 6-byte MAC.
        assert_eq!(&bytes[64..66], &[NDP_OPT_SOURCE_LINK_LAYER_ADDR, 1]);
        assert_eq!(&bytes[66..72], &doc_mac().octets());
        // IPv6(40) + ICMPv6 header(8) + target(16) + one SLLA option(8) = 72 bytes.
        assert_eq!(bytes.len(), 72);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.icmp_type_value(), ICMPV6_NEIGHBOR_SOLICITATION);
        assert_eq!(icmpv6.code_value(), 0);
        // The header classifies the message as a Neighbor Solicitation body with a
        // zero Reserved field.
        assert_eq!(
            icmpv6.body(),
            Icmpv6Body::NeighborSolicitation { reserved: 0 }
        );

        let ns = decoded.layer::<NeighborSolicitation>().unwrap();
        assert_eq!(ns.target_address_value(), target);
        assert_eq!(ns.options_ref().len(), 1);
        let slla = &ns.options_ref().options()[0];
        assert_eq!(slla.option_type(), NDP_OPT_SOURCE_LINK_LAYER_ADDR);
        assert_eq!(slla.link_layer_address(), Some(doc_mac()));

        // The whole packet round-trips byte-for-byte (checksum included).
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // RFC 4862 sec 5.4: a Duplicate Address Detection probe is a Neighbor
    // Solicitation whose source IP is the unspecified address `::`, carrying the
    // tentative address as the Target Address and — per RFC 4861 sec 4.3 — NO
    // Source Link-Layer Address option. It is sent to the solicited-node multicast
    // of the tentative address.
    #[test]
    fn dad_neighbor_solicitation_round_trips() {
        let tentative = doc_target();
        let packet = Ipv6::new()
            .src(Ipv6Addr::UNSPECIFIED)
            .dst(solicited_node_multicast())
            .hlim(255)
            / Icmpv6::neighbor_solicitation(tentative);
        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes();

        // Source address (IPv6 header bytes 8..24) is the unspecified `::`.
        assert_eq!(&bytes[8..24], &Ipv6Addr::UNSPECIFIED.octets());
        assert_eq!(bytes[40], ICMPV6_NEIGHBOR_SOLICITATION);
        assert_eq!(&bytes[44..48], &[0, 0, 0, 0], "reserved word is zero");
        assert_eq!(&bytes[48..64], &tentative.octets());
        // No options after the Target Address: header(8) + target(16) only.
        assert_eq!(bytes.len(), 40 + 8 + 16);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        assert_eq!(
            decoded.layer::<Ipv6>().unwrap().source(),
            Ipv6Addr::UNSPECIFIED
        );
        let ns = decoded.layer::<NeighborSolicitation>().unwrap();
        assert_eq!(ns.target_address_value(), tentative);
        assert!(
            ns.options_ref().is_empty(),
            "a DAD probe carries no Source Link-Layer Address option"
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // RFC 4861 sec 4.3 requires the Reserved field be sent as zero, but an agent
    // can set it (via the header rest-of-header) to a deliberately non-zero value
    // for a malformed-packet test; that value is honored verbatim through
    // compile() and survives a decode round-trip in the header's typed body.
    #[test]
    fn neighbor_solicitation_explicit_reserved_is_preserved() {
        let target = doc_target();
        let packet = Ipv6::new()
            .src(link_local_src())
            .dst(solicited_node_multicast())
            / (Icmpv6::new()
                .icmp_type(ICMPV6_NEIGHBOR_SOLICITATION)
                .code(0)
                .rest_of_header([0xde, 0xad, 0xbe, 0xef])
                / NeighborSolicitation::new(target));
        let compiled = packet.compile().unwrap();
        // The reserved word is the ICMPv6 rest-of-header (bytes 4..8).
        assert_eq!(&compiled.as_bytes()[44..48], &[0xde, 0xad, 0xbe, 0xef]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes()).unwrap();
        assert_eq!(
            decoded.layer::<Icmpv6>().unwrap().body(),
            Icmpv6Body::NeighborSolicitation {
                reserved: 0xdead_beef
            }
        );
        assert_eq!(
            decoded
                .layer::<NeighborSolicitation>()
                .unwrap()
                .target_address_value(),
            target
        );
    }

    // summary() / show(): the body layer summarizes its own fields (Target Address
    // and option count), and the header's body-detail field reports the Neighbor
    // Solicitation classification with its Reserved field.
    #[test]
    fn neighbor_solicitation_summary_and_show() {
        let target = doc_target();
        let body = NeighborSolicitation::new(target)
            .option(NdpOption::source_link_layer_address(doc_mac()));
        assert_eq!(
            body.summary(),
            format!("NeighborSolicitation(target={target}, options=1)")
        );

        let target_field = body
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "target_address")
            .map(|(_, value)| value)
            .expect("show() exposes the target address");
        assert_eq!(target_field, target.to_string());

        let option_field = body
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "option[0]")
            .map(|(_, value)| value)
            .expect("show() exposes the first option");
        assert!(option_field.starts_with("Source Link-Layer Address"));

        // The header summarizes from its type; the Neighbor Solicitation name
        // comes from `icmpv6_type_summary`.
        let header = Icmpv6::new()
            .icmp_type(ICMPV6_NEIGHBOR_SOLICITATION)
            .code(0);
        assert_eq!(
            header.summary(),
            "Icmpv6(type=neighbor-solicitation(135), code=0, id=-, seq=-)"
        );
        let body_field = header
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "body")
            .map(|(_, value)| value)
            .expect("show() exposes a body field");
        assert_eq!(body_field, "neighbor-solicitation(reserved=0x00000000)");
    }

    // A Neighbor Solicitation body truncated below the 16-byte Target Address
    // surfaces a structured error from the decoder (never a panic); the decode
    // dispatch then falls back to a single Raw payload so nothing is dropped.
    #[test]
    fn neighbor_solicitation_short_target_is_structured_error() {
        let err = decode_neighbor_solicitation(&[0u8; 8]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }

    // RFC 4861 sec 4.4 + 4.6.1: a solicited "is-at" Neighbor Advertisement (Target
    // Address = the unicast address being advertised, the S and O flags set,
    // carrying a Target Link-Layer Address option with the responder's MAC)
    // compiles to type 136 / code 0, the S|O flags word, the 16-byte Target
    // Address, and the TLLA option, and decodes back to the same fields with the
    // checksum verifying over the IPv6 pseudo-header.
    #[test]
    fn neighbor_advertisement_with_tlla_round_trips() {
        use crate::protocols::icmp::NDP_OPT_TARGET_LINK_LAYER_ADDR;

        let target = doc_target();
        // A solicited unicast reply: S=1 (in response to a solicitation), O=1
        // (override the cache), R=0 (the sender is a host, not a router).
        let packet = Ipv6::new()
            .src(link_local_src())
            .dst(link_local_src())
            .hlim(255)
            / Icmpv6::neighbor_advertisement_with_target_link_layer(
                target,
                doc_mac(),
                false,
                true,
                true,
            );
        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes();

        // ICMPv6 starts at offset 40. type 136, code 0.
        assert_eq!(bytes[40], ICMPV6_NEIGHBOR_ADVERTISEMENT);
        assert_eq!(bytes[41], 0, "code is 0");
        // Flags word (ICMPv6 rest-of-header, bytes 4..8): R=0, S=1, O=1 in the top
        // three bits of byte 0; the 29 reserved bits are zero.
        assert_eq!(
            bytes[44],
            ICMPV6_NA_FLAG_SOLICITED | ICMPV6_NA_FLAG_OVERRIDE
        );
        assert_eq!(bytes[44], 0x60);
        assert_eq!(&bytes[45..48], &[0, 0, 0], "29 reserved bits are zero");
        // Target Address: the 16 octets right after the fixed 8-byte header.
        assert_eq!(&bytes[48..64], &target.octets());
        // TLLA option follows the Target Address: type 2, length 1, 6-byte MAC.
        assert_eq!(&bytes[64..66], &[NDP_OPT_TARGET_LINK_LAYER_ADDR, 1]);
        assert_eq!(&bytes[66..72], &doc_mac().octets());
        // IPv6(40) + ICMPv6 header(8) + target(16) + one TLLA option(8) = 72 bytes.
        assert_eq!(bytes.len(), 72);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.icmp_type_value(), ICMPV6_NEIGHBOR_ADVERTISEMENT);
        assert_eq!(icmpv6.code_value(), 0);
        // The header classifies the message as a Neighbor Advertisement body with
        // S and O set, R clear, and no reserved bits.
        assert_eq!(
            icmpv6.body(),
            Icmpv6Body::NeighborAdvertisement {
                router: false,
                solicited: true,
                override_flag: true,
                reserved: 0,
            }
        );

        let na = decoded.layer::<NeighborAdvertisement>().unwrap();
        assert_eq!(na.target_address_value(), target);
        assert_eq!(na.options_ref().len(), 1);
        let tlla = &na.options_ref().options()[0];
        assert_eq!(tlla.option_type(), NDP_OPT_TARGET_LINK_LAYER_ADDR);
        assert_eq!(tlla.link_layer_address(), Some(doc_mac()));

        // The whole packet round-trips byte-for-byte (checksum included).
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // RFC 4861 sec 4.4: the R, S, and O flags are independent. Exercise every one
    // of the 8 boundary combinations and assert each flag is reported
    // independently from the decoded header, with the 29 reserved bits zero in
    // every case.
    #[test]
    fn neighbor_advertisement_flag_combinations_are_independent() {
        let target = doc_target();
        for router in [false, true] {
            for solicited in [false, true] {
                for override_flag in [false, true] {
                    let packet = Ipv6::new().src(link_local_src()).dst(link_local_src())
                        / Icmpv6::neighbor_advertisement_with(
                            router,
                            solicited,
                            override_flag,
                            NeighborAdvertisement::new(target),
                        );
                    let compiled = packet.compile().unwrap();
                    let bytes = compiled.as_bytes();

                    // The flags byte (rest-of-header byte 0) carries exactly the
                    // set bits in its top three bits.
                    let mut expected = 0u8;
                    if router {
                        expected |= ICMPV6_NA_FLAG_ROUTER;
                    }
                    if solicited {
                        expected |= ICMPV6_NA_FLAG_SOLICITED;
                    }
                    if override_flag {
                        expected |= ICMPV6_NA_FLAG_OVERRIDE;
                    }
                    assert_eq!(
                        bytes[44], expected,
                        "R={router} S={solicited} O={override_flag}"
                    );
                    // The 29 reserved bits (rest of byte 0 plus bytes 1..4) stay 0.
                    assert_eq!(bytes[44] & 0x1f, 0, "low five bits of byte 0 reserved");
                    assert_eq!(&bytes[45..48], &[0, 0, 0]);

                    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
                    match decoded.layer::<Icmpv6>().unwrap().body() {
                        Icmpv6Body::NeighborAdvertisement {
                            router: r,
                            solicited: s,
                            override_flag: o,
                            reserved,
                        } => {
                            assert_eq!(r, router, "R decoded independently");
                            assert_eq!(s, solicited, "S decoded independently");
                            assert_eq!(o, override_flag, "O decoded independently");
                            assert_eq!(reserved, 0, "no reserved bits set");
                        }
                        other => panic!("expected NeighborAdvertisement body, got {other:?}"),
                    }
                    // The Target Address survives the round trip too.
                    assert_eq!(
                        decoded
                            .layer::<NeighborAdvertisement>()
                            .unwrap()
                            .target_address_value(),
                        target
                    );
                    // Whole packet round-trips byte-for-byte (checksum included).
                    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
                }
            }
        }
    }

    // Honored overrides: an agent can set the 29 Reserved bits (RFC 4861 sec 4.4
    // says send-as-zero) and any flag combination via the header rest-of-header,
    // and the value survives compile() and decode unchanged. The reserved bits are
    // surfaced in the typed body for inspection without masking the flag bits.
    #[test]
    fn neighbor_advertisement_reserved_bits_survive() {
        let target = doc_target();
        // flags word 0xff_ff_ff_ff: R=1, S=1, O=1, plus all 29 reserved bits set.
        let packet = Ipv6::new().src(link_local_src()).dst(link_local_src())
            / (Icmpv6::new()
                .icmp_type(ICMPV6_NEIGHBOR_ADVERTISEMENT)
                .code(0)
                .rest_of_header([0xff, 0xff, 0xff, 0xff])
                / NeighborAdvertisement::new(target));
        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes();
        // The flags word survives verbatim.
        assert_eq!(&bytes[44..48], &[0xff, 0xff, 0xff, 0xff]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        assert_eq!(
            decoded.layer::<Icmpv6>().unwrap().body(),
            Icmpv6Body::NeighborAdvertisement {
                router: true,
                solicited: true,
                override_flag: true,
                // The 29 reserved bits (0x1fffffff) are preserved, not masked away.
                reserved: ICMPV6_NA_FLAGS_RESERVED,
            }
        );
        assert_eq!(
            decoded
                .layer::<NeighborAdvertisement>()
                .unwrap()
                .target_address_value(),
            target
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // The default builder leaves all three flags clear and carries no options:
    // type 136, code 0, a zero flags word, the 16-byte Target Address, nothing
    // after.
    #[test]
    fn neighbor_advertisement_defaults_are_documented() {
        let target = doc_target();
        let packet = Ipv6::new()
            .src(link_local_src())
            .dst(link_local_src())
            .hlim(255)
            / Icmpv6::neighbor_advertisement(target);
        let bytes = packet.compile().unwrap();
        let bytes = bytes.as_bytes();

        assert_eq!(bytes[40], ICMPV6_NEIGHBOR_ADVERTISEMENT);
        assert_eq!(bytes[41], 0, "code is 0");
        assert_eq!(
            &bytes[44..48],
            &[0, 0, 0, 0],
            "R/S/O and reserved all clear"
        );
        assert_eq!(&bytes[48..64], &target.octets());
        // IPv6(40) + ICMPv6 header(8) + target(16), no options.
        assert_eq!(bytes.len(), 40 + 8 + 16);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let na = decoded.layer::<NeighborAdvertisement>().unwrap();
        assert_eq!(na.target_address_value(), target);
        assert!(na.options_ref().is_empty());
    }

    // summary() / show(): the body layer summarizes its own fields (Target Address
    // and option count), and the header's body-detail field reports the Neighbor
    // Advertisement classification with its R/S/O flags and reserved bits.
    #[test]
    fn neighbor_advertisement_summary_and_show() {
        let target = doc_target();
        let body = NeighborAdvertisement::new(target)
            .option(NdpOption::target_link_layer_address(doc_mac()));
        assert_eq!(
            body.summary(),
            format!("NeighborAdvertisement(target={target}, options=1)")
        );

        let target_field = body
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "target_address")
            .map(|(_, value)| value)
            .expect("show() exposes the target address");
        assert_eq!(target_field, target.to_string());

        let option_field = body
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "option[0]")
            .map(|(_, value)| value)
            .expect("show() exposes the first option");
        assert!(option_field.starts_with("Target Link-Layer Address"));

        // The header summarizes from its type; the Neighbor Advertisement name
        // comes from `icmpv6_type_summary`.
        let header = Icmpv6::new()
            .icmp_type(ICMPV6_NEIGHBOR_ADVERTISEMENT)
            .code(0)
            .rest_of_header(neighbor_advertisement_rest_of_header(false, true, true));
        assert_eq!(
            header.summary(),
            "Icmpv6(type=neighbor-advertisement(136), code=0, id=-, seq=-)"
        );
        let body_field = header
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "body")
            .map(|(_, value)| value)
            .expect("show() exposes a body field");
        assert_eq!(
            body_field,
            "neighbor-advertisement(R=false, S=true, O=true, reserved=0x00000000)"
        );
    }

    // A Neighbor Advertisement body truncated below the 16-byte Target Address
    // surfaces a structured error from the decoder (never a panic); the decode
    // dispatch then falls back to a single Raw payload so nothing is dropped.
    #[test]
    fn neighbor_advertisement_short_target_is_structured_error() {
        let err = decode_neighbor_advertisement(&[0u8; 8]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }

    // The better first hop a Redirect advertises: a link-local router address
    // (fe80::/10). The destination being redirected is a documentation unicast
    // address (RFC 3849 2001:db8::/32).
    fn redirect_target() -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x00ff)
    }

    fn redirect_destination() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 3, 0, 0, 0, 0, 0x0064)
    }

    // RFC 4861 sec 4.5 + 4.6.1 + 4.6.3: a Redirect with a Target Link-Layer
    // Address option and a Redirected Header option carrying a truncated original
    // datagram compiles to type 137 / code 0, a zero Reserved word, the Target and
    // Destination Addresses, and the two options, and decodes back to every field
    // — including the embedded datagram (with its auto-fill padding) — with the
    // checksum verifying over the IPv6 pseudo-header.
    #[test]
    fn redirect_with_redirected_header_round_trips() {
        use crate::protocols::icmp::{NDP_OPT_REDIRECTED_HEADER, NDP_OPT_TARGET_LINK_LAYER_ADDR};

        let target = redirect_target();
        let destination = redirect_destination();
        // A small stand-in for the original datagram that triggered the redirect:
        // a 12-byte IPv6 header prefix + payload byte slice (opaque bytes, no
        // decode required). Total Redirected Header option = header(2) +
        // Reserved(6) + 12 = 20 bytes, rounding up to three 8-octet units (24
        // bytes) with 4 bytes of zero padding.
        let original = [
            0x60, 0x00, 0x00, 0x00, // IPv6 version/TC/flow
            0x00, 0x04, 0x3a, 0x40, // payload len 4, next header ICMPv6, hop 64
            0xde, 0xad, 0xbe, 0xef, // start of payload
        ];

        // Build the Redirect header explicitly so it carries the two options;
        // `Icmpv6::redirect` is exercised by the defaults test below.
        let packet = Ipv6::new()
            .src(redirect_target())
            .dst(link_local_src())
            .hlim(255)
            / (Icmpv6::new().icmp_type(ICMPV6_REDIRECT).code(0)
                / Redirect::new(target, destination)
                    .option(NdpOption::target_link_layer_address(doc_mac()))
                    .option(NdpOption::redirected_header(&original)));

        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes();

        // ICMPv6 starts at offset 40. type 137, code 0.
        assert_eq!(bytes[40], ICMPV6_REDIRECT);
        assert_eq!(bytes[41], 0, "code is 0");
        // Reserved field (ICMPv6 rest-of-header, bytes 44..48) is zero.
        assert_eq!(&bytes[44..48], &[0, 0, 0, 0]);
        // Target Address (bytes 48..64) then Destination Address (bytes 64..80).
        assert_eq!(&bytes[48..64], &target.octets());
        assert_eq!(&bytes[64..80], &destination.octets());
        // TLLA option (one 8-octet unit) at bytes 80..88.
        assert_eq!(&bytes[80..82], &[NDP_OPT_TARGET_LINK_LAYER_ADDR, 1]);
        assert_eq!(&bytes[82..88], &doc_mac().octets());
        // Redirected Header option (three 8-octet units) at bytes 88..112.
        assert_eq!(&bytes[88..90], &[NDP_OPT_REDIRECTED_HEADER, 3]);
        // 6 Reserved octets sent zero.
        assert_eq!(&bytes[90..96], &[0, 0, 0, 0, 0, 0]);
        // The embedded datagram, then 4 bytes of zero padding to the boundary.
        assert_eq!(&bytes[96..108], &original);
        assert_eq!(&bytes[108..112], &[0, 0, 0, 0]);
        // IPv6(40) + ICMPv6 header(8) + target(16) + dest(16) + TLLA(8) +
        // Redirected Header(24) = 112.
        assert_eq!(bytes.len(), 112);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.icmp_type_value(), ICMPV6_REDIRECT);
        assert_eq!(icmpv6.code_value(), 0);
        // The header classifies the message as a Redirect with a zero Reserved
        // field.
        assert_eq!(icmpv6.body(), Icmpv6Body::Redirect { reserved: 0 });

        let redirect = decoded.layer::<Redirect>().unwrap();
        assert_eq!(redirect.target_address_value(), target);
        assert_eq!(redirect.destination_address_value(), destination);
        assert_eq!(redirect.options_ref().len(), 2);

        let tlla = &redirect.options_ref().options()[0];
        assert_eq!(tlla.option_type(), NDP_OPT_TARGET_LINK_LAYER_ADDR);
        assert_eq!(tlla.link_layer_address(), Some(doc_mac()));

        let rh = &redirect.options_ref().options()[1];
        assert_eq!(rh.option_type(), NDP_OPT_REDIRECTED_HEADER);
        // The embedded portion round-trips, including the 4 padding bytes the
        // 8-octet auto-fill appended (RFC 4861 sec 4.6.3 records no embedded
        // length in the option).
        let mut expected_embedded = original.to_vec();
        expected_embedded.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(rh.redirected_header_data(), Some(&expected_embedded[..]));

        // The whole packet round-trips byte-for-byte (checksum included).
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // The default builder leaves the Reserved word zero and carries no options:
    // type 137, code 0, a zero Reserved word, the Target and Destination
    // Addresses, nothing after. When the destination is itself a neighbor the
    // target and destination are equal (RFC 4861 sec 4.5).
    #[test]
    fn redirect_defaults_and_target_equals_destination() {
        let neighbor = redirect_destination();
        let packet = Ipv6::new()
            .src(redirect_target())
            .dst(link_local_src())
            .hlim(255)
            / Icmpv6::redirect(neighbor, neighbor);
        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes();

        assert_eq!(bytes[40], ICMPV6_REDIRECT);
        assert_eq!(bytes[41], 0, "code is 0");
        assert_eq!(&bytes[44..48], &[0, 0, 0, 0], "reserved word zero");
        assert_eq!(&bytes[48..64], &neighbor.octets());
        assert_eq!(&bytes[64..80], &neighbor.octets());
        // IPv6(40) + ICMPv6 header(8) + target(16) + dest(16), no options.
        assert_eq!(bytes.len(), 40 + 8 + 16 + 16);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let redirect = decoded.layer::<Redirect>().unwrap();
        assert_eq!(redirect.target_address_value(), neighbor);
        assert_eq!(redirect.destination_address_value(), neighbor);
        assert!(redirect.options_ref().is_empty());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // RFC 4861 sec 4.5 requires the Reserved field be sent as zero, but an agent
    // can set it (via the header rest-of-header) to a deliberately non-zero value
    // for a malformed-packet test; that value is honored verbatim through
    // compile() and survives a decode round-trip in the header's typed body.
    #[test]
    fn redirect_explicit_reserved_is_preserved() {
        let target = redirect_target();
        let destination = redirect_destination();
        let packet = Ipv6::new().src(redirect_target()).dst(link_local_src())
            / (Icmpv6::new()
                .icmp_type(ICMPV6_REDIRECT)
                .code(0)
                .rest_of_header([0xca, 0xfe, 0xf0, 0x0d])
                / Redirect::new(target, destination));
        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes();
        // The reserved word is the ICMPv6 rest-of-header (bytes 44..48).
        assert_eq!(&bytes[44..48], &[0xca, 0xfe, 0xf0, 0x0d]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        assert_eq!(
            decoded.layer::<Icmpv6>().unwrap().body(),
            Icmpv6Body::Redirect {
                reserved: 0xcafe_f00d
            }
        );
        let redirect = decoded.layer::<Redirect>().unwrap();
        assert_eq!(redirect.target_address_value(), target);
        assert_eq!(redirect.destination_address_value(), destination);
    }

    // summary() / show(): the body layer summarizes its own fields (Target and
    // Destination Addresses and option count), and the header's body-detail field
    // reports the Redirect classification with its Reserved field.
    #[test]
    fn redirect_summary_and_show() {
        let target = redirect_target();
        let destination = redirect_destination();
        let body = Redirect::new(target, destination)
            .option(NdpOption::target_link_layer_address(doc_mac()));
        assert_eq!(
            body.summary(),
            format!("Redirect(target={target}, destination={destination}, options=1)")
        );

        let target_field = body
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "target_address")
            .map(|(_, value)| value)
            .expect("show() exposes the target address");
        assert_eq!(target_field, target.to_string());

        let destination_field = body
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "destination_address")
            .map(|(_, value)| value)
            .expect("show() exposes the destination address");
        assert_eq!(destination_field, destination.to_string());

        let option_field = body
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "option[0]")
            .map(|(_, value)| value)
            .expect("show() exposes the first option");
        assert!(option_field.starts_with("Target Link-Layer Address"));

        // The header summarizes from its type; the Redirect name comes from
        // `icmpv6_type_summary`.
        let header = Icmpv6::new().icmp_type(ICMPV6_REDIRECT).code(0);
        assert_eq!(
            header.summary(),
            "Icmpv6(type=redirect(137), code=0, id=-, seq=-)"
        );
        let body_field = header
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "body")
            .map(|(_, value)| value)
            .expect("show() exposes a body field");
        assert_eq!(body_field, "redirect(reserved=0x00000000)");
    }

    // A Redirect body truncated below the two 16-byte addresses surfaces a
    // structured error from the decoder (never a panic); the decode dispatch then
    // falls back to a single Raw payload so nothing is dropped.
    #[test]
    fn redirect_short_addresses_is_structured_error() {
        // 16 bytes is enough for only one of the two required addresses.
        let err = decode_redirect(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }
}
