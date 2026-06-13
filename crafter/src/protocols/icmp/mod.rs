//! ICMP, ICMPv6, and ICMP extension implementations.
//!
//! # ICMPv4 surface
//!
//! [`Icmp`] is the fixed 8-byte ICMPv4 header and the front of every ICMPv4
//! packet. Typed constructors cover the IANA registry: the RFC 792 echo, error,
//! timestamp, and information families; RFC 950 address mask; RFC 1256 router
//! discovery; RFC 8335 extended echo; and by-name constructors for the
//! deprecated and experimental legacy types. Data that follows the fixed header
//! is modeled as its own typed body or extension layer composed with `/`:
//!
//! - [`Icmpv4QuotedIp`] — the quoted original datagram in an ICMPv4 error.
//! - [`Icmpv4Timestamp`] — RFC 792 originate/receive/transmit timestamps.
//! - [`Icmpv4AddressMask`] — the RFC 950 address mask.
//! - [`Icmpv4RouterAdvertisementEntry`] — one RFC 1256 advertised router entry.
//! - [`IcmpExtension`] + [`IcmpExtensionObject`] — RFC 4884 multi-part framing
//!   and a generic extension object, with typed object bodies for RFC 4950 MPLS
//!   ([`IcmpExtensionMpls`]), RFC 5837 interface information
//!   ([`IcmpExtensionInterfaceInfo`]), and RFC 8335 interface identification
//!   ([`IcmpExtensionInterfaceId`]).
//!
//! `compile()` fills protocol-correct defaults the caller left unset — the ICMP
//! checksum, RFC 4884 length and zero padding, extension checksums, router
//! advertisement counts and entry size, and type-specific default codes — while
//! any value set explicitly survives untouched, including intentionally invalid
//! ones. The raw escape hatches [`Icmp::type_`], [`Icmp::code`],
//! [`Icmp::checksum`], and [`Icmp::rest_of_header`] (plus a [`Raw`] body) build
//! malformed or not-yet-typed messages.
//!
//! `decode_from_l3` (see [`crate::core::Packet::decode_from_l3`]) types the
//! header and any body it can parse defensibly; ambiguous, unknown, or
//! truncated trailing bytes stay a [`Raw`] payload, and genuine header
//! truncation returns a structured buffer error rather than panicking.
//! [`Packet::summary`](crate::core::Packet::summary) names known types and codes
//! while still printing raw numeric values, and
//! [`show`](crate::core::Packet::show) lists every typed field.
//!
//! ```rust
//! use crafter::prelude::*;
//! use std::net::Ipv4Addr;
//!
//! # fn main() -> crafter::Result<()> {
//! // A port-unreachable error quoting the datagram that triggered it.
//! let offending = Ipv4::new()
//!     .src(Ipv4Addr::new(198, 51, 100, 20))
//!     .dst(Ipv4Addr::new(192, 0, 2, 10))
//!     / Udp::new().sport(40000).dport(53)
//!     / Raw::from("query");
//!
//! let packet = Ipv4::new()
//!     .src(Ipv4Addr::new(192, 0, 2, 10))
//!     .dst(Ipv4Addr::new(198, 51, 100, 20))
//!     / Icmpv4::destination_unreachable().code(ICMP_CODE_DU_PORT_UNREACHABLE)
//!     / Icmpv4QuotedIp::new(offending);
//!
//! // compile() auto-fills the ICMP checksum and IPv4 length/protocol.
//! let bytes = packet.compile()?;
//!
//! // decode_from_l3 recovers the typed header and quoted datagram.
//! let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
//! let icmp = decoded.layer::<Icmpv4>().expect("icmp header");
//! assert_eq!(icmp.icmp_type_value(), ICMP_DESTINATION_UNREACHABLE);
//! let quote = decoded.layer::<Icmpv4QuotedIp>().expect("quoted datagram");
//! assert!(quote.quoted_layer::<Ipv4>().is_some());
//! # Ok(())
//! # }
//! ```

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;
use core::str::FromStr;

use crate::checksum::internet_checksum;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, Raw, TransportChecksumContext};
use crate::protocols::ipv4::IPPROTO_ICMPV6;

mod constants;
pub use self::constants::*;

// ICMPv4 type numbers from the IANA ICMP Parameters registry
// (<https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml>).
// Status annotations follow the registry: Deprecated values are marked in their
// doc comments per RFC 6633 (Source Quench) and RFC 6918 (the bulk legacy
// deprecations). Deprecated and reserved values remain constructible and
// decodable; this step only names them and never refuses them.

// ICMPv4 code-field registries from the IANA ICMP Parameters registry.

const ICMP_HEADER_LEN: usize = 8;
/// RFC 792 timestamp body: originate, receive, and transmit timestamps, each a
/// 32-bit value (12 bytes total) following the fixed ICMP header.
const ICMP_TIMESTAMP_BODY_LEN: usize = 12;
/// RFC 950 address mask body: a single 32-bit address mask (4 bytes) following
/// the fixed ICMP header.
const ICMP_ADDRESS_MASK_BODY_LEN: usize = 4;
/// RFC 1256 router advertisement entry: a 32-bit router address plus a 32-bit
/// preference level (8 bytes total).
const ICMP_ROUTER_ADVERTISEMENT_ENTRY_LEN: usize = 8;
const ICMP_EXTENSION_HEADER_LEN: usize = 4;
const ICMP_EXTENSION_OBJECT_LEN: usize = 4;
const ICMP_EXTENSION_MPLS_LEN: usize = 4;
/// RFC 5837 ifIndex sub-object: a single 32-bit interface index.
const ICMP_INTERFACE_IFINDEX_LEN: usize = 4;
/// RFC 5837 IP Address sub-object fixed prefix: 16-bit AFI plus 16-bit reserved.
const ICMP_INTERFACE_IP_ADDRESS_PREFIX_LEN: usize = 4;
/// RFC 5837 MTU sub-object: a single 32-bit MTU value.
const ICMP_INTERFACE_MTU_LEN: usize = 4;
/// RFC 5837 maximum interface-name octets (the length octet plus up to 63 name
/// octets, capped at 64 total).
const ICMP_INTERFACE_NAME_MAX: usize = 63;
/// RFC 8335 Interface Identification Object ifIndex body: a single 32-bit index.
const ICMP_INTERFACE_ID_INDEX_LEN: usize = 4;
/// RFC 8335 Interface Identification Object address body fixed prefix: 16-bit
/// AFI, 8-bit address length, and 8-bit reserved.
const ICMP_INTERFACE_ID_ADDRESS_PREFIX_LEN: usize = 4;
/// RFC 4884 expected extension header version for ICMP multi-part messages.
const ICMP_EXTENSION_VERSION: u8 = 2;
/// RFC 4884 minimum "original datagram" size, in octets, when an ICMPv4 message
/// carries an appended extension structure. Shorter quoted datagrams are zero
/// padded up to this length before the extension header.
const ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM: usize = 128;
const MPLS_MAX_LABEL: u32 = 0x000f_ffff;
const MPLS_MAX_EXP: u8 = 0x07;

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
// `shared` is declared here, after the `impl_layer_object!` / `impl_layer_div!`
// macros above, so its `extensions` submodule sits inside their textual macro
// scope. The `pub use self::shared::*;` re-export surfaces the version-neutral
// `IcmpKind`, `IcmpLayer`, and the RFC 4884 extension types at the `icmp` root.
mod shared;
pub use self::shared::*;

// `v6` is declared here, after the `impl_layer_object!` / `impl_layer_div!`
// macros above, so the ICMPv6 layer it holds sits inside their textual macro
// scope (it invokes both). The `Icmpv6` type and the `ICMPV6_*` codepoint
// constants in `v6/constants.rs` are re-exported at the `icmp` root so the
// `protocols::mod.rs` re-exports, the registry IPv6 next-header 58 binding, and
// the prelude keep resolving to the same names.
mod v6;
pub(crate) use self::v6::append_icmpv6_packet;
pub use self::v6::Icmpv6;
// The typed ICMPv6 message-body model lives in `v6/body.rs`. Re-export it at the
// `icmp` root so the `protocols::mod.rs` re-exports and the prelude surface it
// alongside the `Icmpv6` header, the same way the ICMPv4 bodies are surfaced.
pub use self::v6::{Icmpv6Body, Icmpv6ErrorBody};
// The shared Neighbor Discovery option TLV framework lives in
// `v6/message/ndp_option.rs` (RFC 4861 section 4.6). Re-export the option types,
// the `NDP_OPT_*` codepoints, and the type-name helpers at the `icmp` root so
// the `protocols::mod.rs` re-exports and the prelude surface them alongside the
// `Icmpv6` header, like the other ICMPv6 types.
pub use self::v6::{
    ndp_option_type_is_known, ndp_option_type_name, ndp_rdnss_length_units, NdpOption, NdpOptions,
    Pref64Plc, Prf, NDP_DNS_LIFETIME_INFINITY, NDP_DNS_RESERVED_LEN,
    NDP_LINK_LAYER_ADDR_ETHERNET_LEN, NDP_MTU_OPTION_LEN, NDP_MTU_OPTION_UNITS, NDP_NONCE_MIN_LEN,
    NDP_OPTION_HEADER_LEN, NDP_OPTION_LENGTH_UNIT, NDP_OPT_CAPTIVE_PORTAL, NDP_OPT_DNSSL,
    NDP_OPT_MTU, NDP_OPT_NONCE, NDP_OPT_PREF64, NDP_OPT_PREFIX_INFORMATION,
    NDP_OPT_RA_FLAGS_EXTENSION, NDP_OPT_RDNSS, NDP_OPT_REDIRECTED_HEADER,
    NDP_OPT_ROUTE_INFORMATION, NDP_OPT_SOURCE_LINK_LAYER_ADDR, NDP_OPT_TARGET_LINK_LAYER_ADDR,
    NDP_PREF64_LEN, NDP_PREF64_PLC_MASK, NDP_PREF64_PREFIX_LEN, NDP_PREF64_SCALED_LIFETIME_MAX,
    NDP_PREF64_SCALED_LIFETIME_SHIFT, NDP_PREF64_UNITS, NDP_PREFIX_FLAGS_RESERVED,
    NDP_PREFIX_FLAG_AUTONOMOUS, NDP_PREFIX_FLAG_ON_LINK, NDP_PREFIX_INFORMATION_LEN,
    NDP_PREFIX_INFORMATION_UNITS, NDP_PREFIX_LIFETIME_INFINITY, NDP_PRF_MASK, NDP_PRF_SHIFT,
    NDP_RA_FLAGS_EXTENSION_BITS_LEN, NDP_RA_FLAGS_EXTENSION_LEN, NDP_RA_FLAGS_EXTENSION_UNITS,
    NDP_RDNSS_ADDRESS_LEN, NDP_REDIRECTED_HEADER_RESERVED_LEN,
    NDP_ROUTE_INFORMATION_LEN_FULL_PREFIX, NDP_ROUTE_INFORMATION_LEN_HALF_PREFIX,
    NDP_ROUTE_INFORMATION_LEN_NO_PREFIX, NDP_ROUTE_LIFETIME_INFINITY,
};
// The Router Solicitation (RFC 4861 section 4.1), Router Advertisement
// (RFC 4861 section 4.2), Neighbor Solicitation (RFC 4861 section 4.3), Neighbor
// Advertisement (RFC 4861 section 4.4), and Redirect (RFC 4861 section 4.5)
// message bodies — the NDP message bodies — live in `v6/message/ndp.rs`.
// Re-export them, and the Router/Neighbor Advertisement flag-bit / default
// constants, at the `icmp` root so the `protocols::mod.rs` re-exports and the
// prelude surface them alongside the `Icmpv6` header, like the other ICMPv6
// message types.
pub use self::v6::{
    NeighborAdvertisement, NeighborSolicitation, Redirect, RouterAdvertisement, RouterSolicitation,
    ICMPV6_NA_FLAGS_RESERVED, ICMPV6_NA_FLAG_OVERRIDE, ICMPV6_NA_FLAG_ROUTER,
    ICMPV6_NA_FLAG_SOLICITED, ICMPV6_RA_DEFAULT_CUR_HOP_LIMIT, ICMPV6_RA_DEFAULT_ROUTER_LIFETIME,
    ICMPV6_RA_FLAGS_RESERVED, ICMPV6_RA_FLAG_MANAGED, ICMPV6_RA_FLAG_OTHER,
};
// The MLDv1 message body (RFC 2710 section 3, types 130-132) and the MLDv2
// message bodies (RFC 3810: the type-143 Version 2 Report with its Multicast
// Address Records, and the extended type-130 Query) live in
// `v6/message/mld.rs`. Re-export them — and the MLDv2 record type and Query
// flag/length constants — at the `icmp` root so the `protocols::mod.rs`
// re-exports and the prelude surface them alongside the `Icmpv6` header, like the
// other ICMPv6 message bodies.
pub use self::v6::{
    Mldv2Query, Mldv2Report, MulticastAddressRecord, MulticastListenerMessage, MulticastRecordType,
    MLDV2_QUERY_MIN_BODY_LEN, MLDV2_QUERY_QRV_MASK, MLDV2_QUERY_RESV_MASK, MLDV2_QUERY_S_FLAG,
};
// The experimental RFC 4620 Node Information Query / Response body (types
// 139/140) and its Qtype / Code constants live in `v6/message/node_info.rs`.
// Re-export them at the `icmp` root so the `protocols::mod.rs` re-exports and the
// prelude surface them alongside the `Icmpv6` header, like the other ICMPv6
// message bodies.
pub use self::v6::{
    NodeInformation, NI_NONCE_LEN, NI_QTYPE_IPV4_ADDRESSES, NI_QTYPE_NODE_ADDRESSES,
    NI_QTYPE_NODE_NAME, NI_QTYPE_NOOP, NI_QUERY_CODE_SUBJECT_IPV4, NI_QUERY_CODE_SUBJECT_IPV6,
    NI_QUERY_CODE_SUBJECT_NAME, NI_RESPONSE_CODE_REFUSED, NI_RESPONSE_CODE_SUCCESS,
    NI_RESPONSE_CODE_UNKNOWN_QTYPE,
};
// The RFC 8335 ICMPv6 extended echo (types 160/161) flag-byte masks, reply
// codes, and State values live in `v6/message/extended_echo.rs`. Re-export them
// at the `icmp` root so the `protocols::mod.rs` re-exports and the prelude
// surface them alongside the `Icmpv6` header, like the other ICMPv6 codepoints
// (the type constants `ICMPV6_EXTENDED_ECHO_REQUEST` / `_REPLY` already surface
// through `v6/constants.rs`).
pub use self::v6::{
    ICMPV6_CODE_EXTENDED_ECHO_REPLY_MALFORMED_QUERY,
    ICMPV6_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES, ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_ERROR,
    ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_INTERFACE,
    ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_TABLE_ENTRY, ICMPV6_EXTENDED_ECHO_REPLY_ACTIVE,
    ICMPV6_EXTENDED_ECHO_REPLY_IPV4, ICMPV6_EXTENDED_ECHO_REPLY_IPV6,
    ICMPV6_EXTENDED_ECHO_REPLY_STATE_DELAY, ICMPV6_EXTENDED_ECHO_REPLY_STATE_FAILED,
    ICMPV6_EXTENDED_ECHO_REPLY_STATE_INCOMPLETE, ICMPV6_EXTENDED_ECHO_REPLY_STATE_PROBE,
    ICMPV6_EXTENDED_ECHO_REPLY_STATE_REACHABLE, ICMPV6_EXTENDED_ECHO_REPLY_STATE_RESERVED,
    ICMPV6_EXTENDED_ECHO_REPLY_STATE_STALE, ICMPV6_EXTENDED_ECHO_REQUEST_L_BIT,
};
// The ICMPv6 (`ICMPV6_*`) codepoint constants live in `v6/constants.rs` and are
// re-exported through `constants.rs` (which `pub use`s them), so the existing
// `pub use self::constants::*;` above keeps `crate::protocols::icmp::ICMPV6_*`,
// the `protocols::mod.rs` re-exports, and the prelude resolving unchanged.

// The RFC 4884 multi-part extension framework moved into `icmp/shared/`
// (it is version-neutral and serves both ICMPv4 and ICMPv6 error messages).
// Its public types now surface through `pub use self::shared::*;` above, so the
// `protocols::mod.rs` re-export names resolve unchanged.

mod decode;
pub(crate) use self::decode::append_icmp_packet;
// The RFC 4884 extension-structure decoder for an RFC 8335 extended echo request
// is version-neutral (the same structure rides under ICMPv4 type 42 and ICMPv6
// type 160). Surface it at the `icmp` root so the ICMPv6 decode path in
// `v6/mod.rs` (which reaches the root through `use super::*;`) reuses it without
// duplicating the extension framework.
pub(crate) use self::decode::decode_extended_echo_extension;

mod v4;
pub use self::v4::Icmpv4;
/// Deprecated alias for the ICMPv4 layer struct, renamed to [`Icmpv4`].
///
/// Kept for one minor cycle so downstream code that imported `Icmp` keeps
/// compiling (with a deprecation warning). Prefer the version-explicit
/// [`Icmpv4`] name.
#[deprecated(since = "2.1.0", note = "renamed to Icmpv4; use the v4-explicit name")]
pub type Icmp = Icmpv4;
// The ICMPv4 message bodies live in `v4/bodies.rs` under the explicit
// `Icmpv4*` names. Re-export the canonical names at the `icmp` root so the
// `protocols::mod.rs` names and the prelude resolve to them.
pub use self::v4::{
    Icmpv4AddressMask, Icmpv4QuotedIp, Icmpv4RouterAdvertisementEntry, Icmpv4Timestamp,
};
// Re-export the deprecated `Icmp*` body aliases separately so the
// `#[allow(deprecated)]` scope stays narrow: only these aliases are exempt from
// the deprecation warning, while the rest of the icmp surface keeps full lint
// coverage. Kept for one minor cycle so downstream code that imported the old
// names keeps compiling (with a deprecation warning).
#[allow(deprecated)]
pub use self::v4::{IcmpAddressMask, IcmpQuotedIpv4, IcmpRouterAdvertisementEntry, IcmpTimestamp};
// The ICMPv4 (`ICMP_*`) codepoint constants live in `v4/constants.rs` and are
// re-exported through `constants.rs` (which `pub use`s them), so the existing
// `pub use self::constants::*;` above keeps `crate::protocols::icmp::ICMP_*`,
// the `protocols::mod.rs` re-exports, and the prelude resolving unchanged.

fn payload_bytes_after(ctx: LayerContext<'_>) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    for (index, layer) in ctx.packet().iter().enumerate().skip(ctx.index() + 1) {
        let layer_ctx = LayerContext::new(ctx.packet(), index);
        layer.compile(&layer_ctx, &mut payload)?;
        if layer.consumes_following() {
            break;
        }
    }
    Ok(payload)
}

fn payload_len_after(ctx: LayerContext<'_>) -> usize {
    let mut total = 0;
    for (index, layer) in ctx.packet().iter().enumerate().skip(ctx.index() + 1) {
        let layer_ctx = LayerContext::new(ctx.packet(), index);
        total += layer.encoded_len_with_context(&layer_ctx);
        if layer.consumes_following() {
            break;
        }
    }
    total
}

fn router_advertisement_entry_count(ctx: LayerContext<'_>) -> usize {
    ctx.packet()
        .iter()
        .skip(ctx.index() + 1)
        .take_while(|layer| layer.as_any().is::<Icmpv4RouterAdvertisementEntry>())
        .count()
}

fn encoded_len_until_extension(ctx: LayerContext<'_>) -> usize {
    ctx.packet()
        .iter()
        .skip(ctx.index() + 1)
        .take_while(|layer| !layer.as_any().is::<IcmpExtension>())
        .map(Layer::encoded_len)
        .sum()
}

/// True when an [`IcmpExtension`] header follows the layer at `ctx` (looking
/// past the quoted original datagram). RFC 4884 length, padding, and the
/// minimum original datagram size only apply when an extension structure is
/// actually appended.
fn following_extension_present(ctx: LayerContext<'_>) -> bool {
    ctx.packet()
        .iter()
        .skip(ctx.index() + 1)
        .any(|layer| layer.as_any().is::<IcmpExtension>())
}

/// RFC 4884 padded "original datagram" length, in octets.
///
/// The quoted datagram is zero padded to the nearest 32-bit (`unit`-byte)
/// boundary and to at least [`ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM`] octets, so
/// the appended extension structure starts at a predictable offset that a
/// compliant receiver can locate from the length field.
fn rfc4884_padded_original_len(raw_len: usize, unit: usize) -> usize {
    let unit = unit.max(1);
    let rounded = raw_len.div_ceil(unit) * unit;
    rounded.max(ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM)
}

/// Zero-padding inserted between the quoted original datagram and the
/// [`IcmpExtension`] at `ctx`, so the original datagram field reaches its RFC
/// 4884 padded length.
///
/// The padding target is driven by the preceding [`Icmp`] length field: an
/// explicit (or decoded) length is honored verbatim so deliberately malformed
/// or non-canonical packets round-trip, while an unset length falls back to the
/// auto-computed minimum/word-rounded size. This keeps the byte the length
/// field claims and the bytes actually emitted consistent.
fn extension_original_datagram_padding(ctx: LayerContext<'_>) -> usize {
    // RFC 4884 original-datagram padding is scoped to ICMPv4 here: when no
    // ICMPv4 `Icmp` header precedes the extension (for example an ICMPv6 stack,
    // whose RFC 4884 framing is not in scope), nothing is padded so the layer's
    // size stays its bare header length.
    let Some(target) = preceding_icmp_original_datagram_len(ctx) else {
        return 0;
    };
    let raw_len = original_datagram_len_before_extension(ctx);
    target.saturating_sub(raw_len)
}

/// Sum of encoded lengths of the layers strictly between the nearest preceding
/// [`Icmp`] header and the [`IcmpExtension`] at `ctx` — i.e. the unpadded
/// quoted original datagram bytes.
fn original_datagram_len_before_extension(ctx: LayerContext<'_>) -> usize {
    let Some(icmp_index) = preceding_icmp_index(ctx) else {
        return 0;
    };
    ((icmp_index + 1)..ctx.index())
        .filter_map(|index| ctx.packet().get(index))
        .map(Layer::encoded_len)
        .sum()
}

/// Padded original datagram length, in octets, claimed by the nearest preceding
/// [`Icmp`] header's RFC 4884 length field. Returns `None` when there is no
/// preceding ICMPv4 header or it carries no length field.
fn preceding_icmp_original_datagram_len(ctx: LayerContext<'_>) -> Option<usize> {
    let icmp_index = preceding_icmp_index(ctx)?;
    let icmp = ctx
        .packet()
        .get(icmp_index)?
        .as_any()
        .downcast_ref::<Icmpv4>()?;
    let icmp_ctx = LayerContext::new(ctx.packet(), icmp_index);
    let words = icmp
        .effective_extension_length(Some(icmp_ctx), ICMP_EXTENSION_OBJECT_LEN)
        .ok()??;
    Some(words as usize * ICMP_EXTENSION_OBJECT_LEN)
}

/// Index of the nearest [`Icmp`] layer preceding `ctx`, if any.
fn preceding_icmp_index(ctx: LayerContext<'_>) -> Option<usize> {
    (0..ctx.index()).rev().find(|&index| {
        ctx.packet()
            .get(index)
            .is_some_and(|layer| layer.as_any().is::<Icmpv4>())
    })
}

fn extension_object_payload_len(ctx: LayerContext<'_>) -> usize {
    ctx.packet()
        .iter()
        .skip(ctx.index() + 1)
        .take_while(|layer| {
            !layer.as_any().is::<IcmpExtensionObject>() && !layer.as_any().is::<IcmpExtension>()
        })
        .map(Layer::encoded_len)
        .sum()
}

fn checksum_context(
    ctx: LayerContext<'_>,
    transport_protocol: u8,
) -> Option<TransportChecksumContext> {
    (0..ctx.index()).rev().find_map(|index| {
        ctx.packet()
            .get(index)
            .and_then(|layer| layer.transport_checksum_context(transport_protocol))
    })
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn value_or_u16_from_rest(field: &Field<u16>, rest: &Field<[u8; 4]>, offset: usize) -> u16 {
    field.value().copied().unwrap_or_else(|| {
        let rest = rest.value().copied().unwrap_or([0; 4]);
        u16::from_be_bytes([rest[offset], rest[offset + 1]])
    })
}

fn value_or_u8_from_rest(field: &Field<u8>, rest: &Field<[u8; 4]>, offset: usize) -> u8 {
    field.value().copied().unwrap_or_else(|| {
        let rest = rest.value().copied().unwrap_or([0; 4]);
        rest[offset]
    })
}

fn field_from_echo(
    icmp_type: u8,
    rest: &[u8; 4],
    offset: usize,
    is_echo: fn(u8) -> bool,
) -> Field<u16> {
    if is_echo(icmp_type) {
        Field::user(u16::from_be_bytes([rest[offset], rest[offset + 1]]))
    } else {
        Field::unset()
    }
}

fn parse_ipv4(input: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(input).map_err(|_| {
        CrafterError::invalid_field_value("ipv4_address", "expected dotted-quad IPv4 address")
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();

    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02x}"));
    }

    output
}

fn copy_array_4(bytes: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    out.copy_from_slice(&bytes[..4]);
    out
}
