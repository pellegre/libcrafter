//! IPv6 Neighbor Discovery (NDP) option TLV framework.
//!
//! RFC 4861 section 4.6 defines a single, uniform option layout shared by every
//! Neighbor Discovery message (Router Solicitation, Router Advertisement,
//! Neighbor Solicitation, Neighbor Advertisement, Redirect):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |    Length     |              ...              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-                               -
//! ~                              ...                              ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! - `Type` is a one-byte option type codepoint.
//! - `Length` is a one-byte field expressed **in units of 8 octets** and counts
//!   the **whole** option, including the two-byte Type/Length header. RFC 4861
//!   section 4.6: "The length of the option (including the type and length
//!   fields) in units of 8 octets. The value 0 is invalid. Nodes MUST silently
//!   discard an ND packet that contains an option with length zero."
//! - The remaining bytes are the option value.
//!
//! Options form an **ordered list** that round-trips in order. Each message
//! carries zero or more of them.
//!
//! This module is the shared framework only: it models a recognized option's
//! raw value bytes plus an [`NdpOption::Unknown`] variant that preserves an
//! unrecognized option's bytes verbatim, auto-fills the length field (whole
//! option padded to the 8-octet boundary) when the agent did not set it,
//! preserves an explicitly-set length even when it is wrong, and decodes into a
//! structured [`CrafterError`] (never a panic) on a zero length or a buffer
//! overrun. Typed accessors/constructors for individual options (Source/Target
//! Link-Layer Address, Prefix Information, MTU, ...) are layered on top of this
//! framework in later steps.
//!
//! Codepoints below are grounded against the IANA "IPv6 Neighbor Discovery
//! Option Formats" registry
//! (<https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5>)
//! and the defining RFC is cited per constant. (The local `rfc-protocol-spec`
//! manifest cache is sparse for NDP, so the values were grounded directly
//! against the live IANA registry plus RFC 4861 section 4.6.)

use core::fmt;
use core::net::Ipv6Addr;

use crate::error::{CrafterError, Result};
use crate::mac::MacAddr;
use crate::protocols::dns::{decode_dns_name_typed, DnsName};

// --- NDP option type codepoints (IANA "IPv6 Neighbor Discovery Option
// Formats" registry) -------------------------------------------------------

/// Source Link-Layer Address option (RFC 4861 section 4.6.1).
pub const NDP_OPT_SOURCE_LINK_LAYER_ADDR: u8 = 1;

/// Target Link-Layer Address option (RFC 4861 section 4.6.1).
pub const NDP_OPT_TARGET_LINK_LAYER_ADDR: u8 = 2;

/// Prefix Information option (RFC 4861 section 4.6.2).
pub const NDP_OPT_PREFIX_INFORMATION: u8 = 3;

/// Redirected Header option (RFC 4861 section 4.6.3).
pub const NDP_OPT_REDIRECTED_HEADER: u8 = 4;

/// MTU option (RFC 4861 section 4.6.4).
pub const NDP_OPT_MTU: u8 = 5;

/// Nonce option (RFC 3971 section 5.3.2; used for SEND and RFC 7527 DAD).
pub const NDP_OPT_NONCE: u8 = 14;

/// Route Information option (RFC 4191 section 2.3).
pub const NDP_OPT_ROUTE_INFORMATION: u8 = 24;

/// Recursive DNS Server (RDNSS) option (RFC 8106 section 5.1; originally
/// RFC 5006, obsoleted by RFC 8106).
pub const NDP_OPT_RDNSS: u8 = 25;

/// RA Flags Extension option (RFC 5175 section 4).
pub const NDP_OPT_RA_FLAGS_EXTENSION: u8 = 26;

/// DNS Search List (DNSSL) option (RFC 8106 section 5.2).
pub const NDP_OPT_DNSSL: u8 = 31;

/// Captive Portal option (RFC 8910 section 2; IANA name "DHCP Captive-Portal").
pub const NDP_OPT_CAPTIVE_PORTAL: u8 = 37;

/// PREF64 option (RFC 8781 section 4).
pub const NDP_OPT_PREF64: u8 = 38;

/// The unit, in octets, of the NDP option `Length` field (RFC 4861 sec 4.6:
/// "in units of 8 octets").
pub const NDP_OPTION_LENGTH_UNIT: usize = 8;

/// Width, in octets, of the Type/Length header that precedes every NDP option
/// value (RFC 4861 sec 4.6).
pub const NDP_OPTION_HEADER_LEN: usize = 2;

/// Width, in octets, of an Ethernet / IEEE 802 (48-bit) link-layer address as
/// carried in the Source/Target Link-Layer Address option value (RFC 4861 sec
/// 4.6.1: for IEEE 802 addresses the option length is 1 — eight octets total —
/// of which six are the link-layer address).
pub const NDP_LINK_LAYER_ADDR_ETHERNET_LEN: usize = 6;

/// Bit mask for the on-link (L) flag in the Prefix Information option flags
/// octet (RFC 4861 sec 4.6.2: "the highest bit position", 0x80). When set, the
/// prefix can be used for on-link determination.
pub const NDP_PREFIX_FLAG_ON_LINK: u8 = 0x80;

/// Bit mask for the autonomous address-configuration (A) flag in the Prefix
/// Information option flags octet (RFC 4861 sec 4.6.2: "the next bit", 0x40).
/// RFC 4862 sec 5.5.3: when set, the prefix can be used for stateless address
/// autoconfiguration (SLAAC).
pub const NDP_PREFIX_FLAG_AUTONOMOUS: u8 = 0x40;

/// Mask of the six Reserved1 bits in the Prefix Information option flags octet
/// (RFC 4861 sec 4.6.2: "Reserved1 — 6-bit unused field. It MUST be initialized
/// to zero by the sender and MUST be ignored by the receiver."). Preserved
/// verbatim through build/decode for forward-compatibility.
pub const NDP_PREFIX_FLAGS_RESERVED: u8 = 0x3f;

/// The Valid / Preferred Lifetime value (seconds) that RFC 4861 sec 4.6.2
/// defines as infinity (`0xffffffff`).
pub const NDP_PREFIX_LIFETIME_INFINITY: u32 = 0xffff_ffff;

/// Total length, in octets, of a Prefix Information option (RFC 4861 sec 4.6.2:
/// Length field 4, i.e. four 8-octet units = 32 bytes).
pub const NDP_PREFIX_INFORMATION_LEN: usize = 32;

/// The Prefix Information option `Length` field value, in 8-octet units
/// (RFC 4861 sec 4.6.2: 4).
pub const NDP_PREFIX_INFORMATION_UNITS: u8 = 4;

/// Total length, in octets, of an MTU option (RFC 4861 sec 4.6.4: Length field
/// 1, i.e. one 8-octet unit = 8 bytes).
pub const NDP_MTU_OPTION_LEN: usize = 8;

/// The MTU option `Length` field value, in 8-octet units (RFC 4861 sec 4.6.4:
/// 1).
pub const NDP_MTU_OPTION_UNITS: u8 = 1;

/// Width, in octets, of the Reserved area that precedes the embedded original
/// packet in a Redirected Header option (RFC 4861 sec 4.6.3). The option's first
/// word is Type(1) | Length(1) | a 16-bit Reserved field, and its second word is
/// a 32-bit Reserved field; together the two Reserved fields are 6 octets (after
/// the two-byte Type/Length header), all "MUST be initialized to zero by the
/// sender and MUST be ignored by the receiver".
pub const NDP_REDIRECTED_HEADER_RESERVED_LEN: usize = 6;

/// Bit mask of the 2-bit Route Preference (Prf) field as it sits inside a flags
/// byte (RFC 4191 sec 2.1 / sec 2.3: the two bits after the M/O/H flags, mask
/// `0x18` = binary `00011000`). The same mask and 2-bit encoding apply to the
/// Default Router Preference in the Router Advertisement flags byte and to the
/// Prf field in the Route Information option's flags/reserved byte.
pub const NDP_PRF_MASK: u8 = 0x18;

/// Bit position (number of low bits below the field) of the 2-bit Route
/// Preference (Prf) field inside a flags byte (RFC 4191: the field occupies bits
/// 4..=3, so it is shifted left by 3).
pub const NDP_PRF_SHIFT: u8 = 3;

/// Total length, in octets, of a Route Information option whose `Length` field is
/// 1 (RFC 4191 sec 2.3: no Prefix — Type, Length, Prefix Length, the flags byte,
/// and the 4-byte Route Lifetime fill exactly one 8-octet unit).
pub const NDP_ROUTE_INFORMATION_LEN_NO_PREFIX: usize = 8;

/// Total length, in octets, of a Route Information option whose `Length` field is
/// 2 (RFC 4191 sec 2.3: an 8-octet Prefix — the high 64 bits).
pub const NDP_ROUTE_INFORMATION_LEN_HALF_PREFIX: usize = 16;

/// Total length, in octets, of a Route Information option whose `Length` field is
/// 3 (RFC 4191 sec 2.3: a 16-octet Prefix — the full 128-bit address).
pub const NDP_ROUTE_INFORMATION_LEN_FULL_PREFIX: usize = 24;

/// The Route Lifetime value (seconds) that RFC 4191 sec 2.3 defines as infinity
/// (`0xffffffff`).
pub const NDP_ROUTE_LIFETIME_INFINITY: u32 = 0xffff_ffff;

/// Width, in octets, of the Reserved field that precedes the Lifetime in both
/// the RDNSS (RFC 8106 sec 5.1) and DNSSL (RFC 8106 sec 5.2) options: a 16-bit
/// field, "initialized to zero by the sender and ignored by the receiver".
pub const NDP_DNS_RESERVED_LEN: usize = 2;

/// Width, in octets, of an IPv6 address carried in the RDNSS option value
/// (RFC 8106 sec 5.1: "One or more 128-bit IPv6 addresses").
pub const NDP_RDNSS_ADDRESS_LEN: usize = 16;

/// The RDNSS / DNSSL Lifetime value (seconds) that RFC 8106 (sec 5.1, sec 5.2)
/// defines as infinity (`0xffffffff`). A value of zero means the addresses /
/// domain names MUST no longer be used.
pub const NDP_DNS_LIFETIME_INFINITY: u32 = 0xffff_ffff;

/// The RDNSS option `Length` field value, in 8-octet units, for an option
/// carrying `addresses` IPv6 addresses (RFC 8106 sec 5.1: "Length ... is in
/// units of 8 octets. The minimum value is 3 if one IPv6 address is contained
/// in the option" — i.e. `1 + 2 * n`, since the two-byte Type/Length header, the
/// 2-byte Reserved field, and the 4-byte Lifetime fill the first 8-octet unit
/// and each 16-byte address is two more units).
pub const fn ndp_rdnss_length_units(addresses: usize) -> usize {
    1 + 2 * addresses
}

/// Width, in octets, of the Bit Fields area that follows the Type/Length header
/// in an RA Flags Extension option (RFC 5175 sec 4: the option is one 8-octet
/// unit — a two-byte Type/Length header plus a 6-octet, 48-bit "Bit fields
/// available for assignment" area, numbered 8..=55, that continues the Router
/// Advertisement flags byte).
pub const NDP_RA_FLAGS_EXTENSION_BITS_LEN: usize = 6;

/// Total length, in octets, of an RA Flags Extension option (RFC 5175 sec 4:
/// Length field 1, i.e. one 8-octet unit = 8 bytes).
pub const NDP_RA_FLAGS_EXTENSION_LEN: usize = 8;

/// The RA Flags Extension option `Length` field value, in 8-octet units
/// (RFC 5175 sec 4: 1).
pub const NDP_RA_FLAGS_EXTENSION_UNITS: u8 = 1;

/// Minimum width, in octets, of the random Nonce field carried by a Nonce option
/// (RFC 3971 sec 5.3.2: "The length of the random number MUST be at least 6
/// bytes."). The sender picks the nonce length so that the whole option is a
/// multiple of 8 octets; with the two-byte Type/Length header a 6-byte nonce
/// gives exactly one 8-octet unit.
pub const NDP_NONCE_MIN_LEN: usize = 6;

/// Total length, in octets, of a PREF64 option (RFC 8781 sec 4: Length field 2,
/// i.e. two 8-octet units = 16 bytes).
pub const NDP_PREF64_LEN: usize = 16;

/// The PREF64 option `Length` field value, in 8-octet units (RFC 8781 sec 4: 2).
pub const NDP_PREF64_UNITS: u8 = 2;

/// Width, in octets, of the NAT64 prefix carried by a PREF64 option (RFC 8781
/// sec 4: "Highest 96 Bits of Prefix", 12 octets / 96 bits).
pub const NDP_PREF64_PREFIX_LEN: usize = 12;

/// Number of low bits the 13-bit Scaled Lifetime field is shifted left by inside
/// the PREF64 option's first 16-bit word (RFC 8781 sec 4: the word is Scaled
/// Lifetime (13 bits) || PLC (3 bits), so the lifetime occupies bits 15..=3 and
/// the PLC the low 3 bits).
pub const NDP_PREF64_SCALED_LIFETIME_SHIFT: u8 = 3;

/// Bit mask of the 3-bit PLC (Prefix Length Code) field as it sits in the low
/// three bits of the PREF64 option's first 16-bit word (RFC 8781 sec 4).
pub const NDP_PREF64_PLC_MASK: u16 = 0x0007;

/// Maximum value of the 13-bit Scaled Lifetime field carried by a PREF64 option
/// (RFC 8781 sec 4: a 13-bit unsigned integer, units of 8 seconds).
pub const NDP_PREF64_SCALED_LIFETIME_MAX: u16 = 0x1fff;

/// IPv6 Route / Default Router Preference (Prf), RFC 4191 sections 2.1 and 2.3.
///
/// The preference is "encoded as a two-bit signed integer" and appears in two
/// places with the same encoding: the Default Router Preference in the Router
/// Advertisement flags byte (RFC 4191 sec 2.2, mask [`NDP_PRF_MASK`] = `0x18`)
/// and the Route Preference in the Route Information option (RFC 4191 sec 2.3,
/// same mask). The four 2-bit codepoints are (RFC 4191 sec 2.1):
///
/// ```text
/// 01  High
/// 00  Medium (default)
/// 11  Low
/// 10  Reserved - MUST NOT be sent
/// ```
///
/// [`Prf::Reserved`] (`10`) "MUST NOT be sent" and, per RFC 4191 sec 2.1, a
/// receiver "MUST treat a value of 10 as if it were 00 (Medium)". `crafter`
/// preserves the wire value faithfully — it decodes `10` to [`Prf::Reserved`]
/// rather than silently folding it to Medium — so an agent can both inspect a
/// peer that sent the reserved value and emit it on purpose to exercise a stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Prf {
    /// High preference (RFC 4191 sec 2.1: 2-bit value `01`).
    High,
    /// Medium preference — the default (RFC 4191 sec 2.1: 2-bit value `00`).
    #[default]
    Medium,
    /// Low preference (RFC 4191 sec 2.1: 2-bit value `11`).
    Low,
    /// The reserved 2-bit value `10` (RFC 4191 sec 2.1: "MUST NOT be sent";
    /// treated as Medium on receipt). Preserved verbatim so it round-trips.
    Reserved,
}

impl Prf {
    /// The 2-bit value (0..=3) for this preference (RFC 4191 sec 2.1).
    ///
    /// Returns the raw two-bit code, *not* the value shifted into the `0x18`
    /// field position; see [`Prf::to_flag_bits`] for the in-byte placement.
    pub const fn to_bits(self) -> u8 {
        match self {
            // RFC 4191 sec 2.1: 01 High, 00 Medium, 11 Low, 10 Reserved.
            Prf::High => 0b01,
            Prf::Medium => 0b00,
            Prf::Low => 0b11,
            Prf::Reserved => 0b10,
        }
    }

    /// Decode a 2-bit value (only the low two bits are consulted) into a [`Prf`]
    /// (RFC 4191 sec 2.1).
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b01 => Prf::High,
            0b00 => Prf::Medium,
            0b11 => Prf::Low,
            // 0b10
            _ => Prf::Reserved,
        }
    }

    /// Place this preference into its `0x18` field position within a flags byte
    /// (RFC 4191 sec 2.2 / sec 2.3): the 2-bit value shifted left by
    /// [`NDP_PRF_SHIFT`] and masked with [`NDP_PRF_MASK`].
    pub const fn to_flag_bits(self) -> u8 {
        (self.to_bits() << NDP_PRF_SHIFT) & NDP_PRF_MASK
    }

    /// Read the preference out of a flags byte (RFC 4191 sec 2.2 / sec 2.3):
    /// extract the `0x18` field and decode it.
    pub const fn from_flag_byte(flags: u8) -> Self {
        Self::from_bits((flags & NDP_PRF_MASK) >> NDP_PRF_SHIFT)
    }
}

/// PREF64 Prefix Length Code (PLC), RFC 8781 section 4.
///
/// The PREF64 option (type 38) carries a NAT64 prefix whose length is not sent
/// directly; instead a 3-bit PLC field encodes it. RFC 8781 section 4 defines
/// six assigned codes and reserves the rest:
///
/// ```text
/// PLC  Prefix length
/// 0    96 bits
/// 1    64 bits
/// 2    56 bits
/// 3    48 bits
/// 4    40 bits
/// 5    32 bits
/// (6, 7 are reserved)
/// ```
///
/// `crafter` preserves the wire value faithfully: it decodes a reserved code
/// (6 or 7) to [`Pref64Plc::Reserved`] carrying the raw value rather than
/// rejecting it, so an agent can inspect a peer that sent a reserved code and
/// emit one on purpose to exercise a stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Pref64Plc {
    /// A NAT64 prefix length the registry assigns (RFC 8781 sec 4): one of 96,
    /// 64, 56, 48, 40, or 32 bits.
    PrefixLength(u8),
    /// A reserved PLC code (6 or 7), preserved verbatim with its raw 3-bit value
    /// so it round-trips (RFC 8781 sec 4: only 0..=5 are assigned).
    Reserved(u8),
}

impl Pref64Plc {
    /// The NAT64 prefix length, in bits, for a recognized PLC code, or `None`
    /// for a reserved code (RFC 8781 sec 4).
    pub const fn prefix_length_bits(self) -> Option<u8> {
        match self {
            Pref64Plc::PrefixLength(bits) => Some(bits),
            Pref64Plc::Reserved(_) => None,
        }
    }

    /// The raw 3-bit PLC code (0..=7) for this prefix length (RFC 8781 sec 4),
    /// or `None` for a [`Pref64Plc::PrefixLength`] that is not one of the six
    /// assigned NAT64 prefix lengths.
    pub const fn to_plc(self) -> Option<u8> {
        match self {
            // RFC 8781 sec 4: 0->96, 1->64, 2->56, 3->48, 4->40, 5->32.
            Pref64Plc::PrefixLength(96) => Some(0),
            Pref64Plc::PrefixLength(64) => Some(1),
            Pref64Plc::PrefixLength(56) => Some(2),
            Pref64Plc::PrefixLength(48) => Some(3),
            Pref64Plc::PrefixLength(40) => Some(4),
            Pref64Plc::PrefixLength(32) => Some(5),
            Pref64Plc::PrefixLength(_) => None,
            Pref64Plc::Reserved(code) => Some(code & 0x07),
        }
    }

    /// Decode a 3-bit PLC code (only the low three bits are consulted) into a
    /// [`Pref64Plc`] (RFC 8781 sec 4).
    pub const fn from_plc(code: u8) -> Self {
        match code & 0x07 {
            0 => Pref64Plc::PrefixLength(96),
            1 => Pref64Plc::PrefixLength(64),
            2 => Pref64Plc::PrefixLength(56),
            3 => Pref64Plc::PrefixLength(48),
            4 => Pref64Plc::PrefixLength(40),
            5 => Pref64Plc::PrefixLength(32),
            // 6, 7 are reserved (RFC 8781 sec 4).
            other => Pref64Plc::Reserved(other),
        }
    }

    /// Build a [`Pref64Plc`] from a NAT64 prefix length in bits, mapping one of
    /// the six RFC 8781 section 4 assigned lengths to its code. A length that is
    /// not assigned is carried as [`Pref64Plc::PrefixLength`] verbatim; the
    /// PREF64 constructor then rejects it (or it encodes as a reserved code via
    /// [`NdpOption::pref64_raw`]).
    pub const fn from_prefix_length_bits(bits: u8) -> Self {
        Pref64Plc::PrefixLength(bits)
    }
}

/// Return the human-readable name for a recognized NDP option type, or `None`
/// for an unassigned/unrecognized type.
///
/// Names match the IANA "IPv6 Neighbor Discovery Option Formats" registry
/// descriptions.
pub const fn ndp_option_type_name(ty: u8) -> Option<&'static str> {
    match ty {
        NDP_OPT_SOURCE_LINK_LAYER_ADDR => Some("Source Link-Layer Address"),
        NDP_OPT_TARGET_LINK_LAYER_ADDR => Some("Target Link-Layer Address"),
        NDP_OPT_PREFIX_INFORMATION => Some("Prefix Information"),
        NDP_OPT_REDIRECTED_HEADER => Some("Redirected Header"),
        NDP_OPT_MTU => Some("MTU"),
        NDP_OPT_NONCE => Some("Nonce"),
        NDP_OPT_ROUTE_INFORMATION => Some("Route Information"),
        NDP_OPT_RDNSS => Some("Recursive DNS Server"),
        NDP_OPT_RA_FLAGS_EXTENSION => Some("RA Flags Extension"),
        NDP_OPT_DNSSL => Some("DNS Search List"),
        NDP_OPT_CAPTIVE_PORTAL => Some("Captive Portal"),
        NDP_OPT_PREF64 => Some("PREF64"),
        _ => None,
    }
}

/// Return true when `ty` is an NDP option type `crafter` recognizes by name.
pub const fn ndp_option_type_is_known(ty: u8) -> bool {
    ndp_option_type_name(ty).is_some()
}

/// A single Neighbor Discovery option (RFC 4861 section 4.6).
///
/// This is the framework-level representation: a `{type, value-bytes}` option
/// with the length field auto-filled (or preserved verbatim when set on
/// purpose). [`Self::Generic`] holds a recognized option type with its raw
/// value bytes, and [`Self::Unknown`] preserves an unrecognized option's value
/// bytes byte-for-byte so they round-trip. Both carry an optional explicit
/// `length` override so a deliberately-wrong length survives `encode()`.
///
/// Typed option views and constructors (Source/Target Link-Layer Address,
/// Prefix Information, MTU, ...) build on top of this representation in later
/// steps; this enum is `#[non_exhaustive]` so those variants can be added
/// without breaking the framework's callers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NdpOption {
    /// A recognized option type carried as raw value bytes (the bytes after the
    /// two-byte Type/Length header), with the length field auto-filled unless
    /// `length` is set.
    Generic {
        /// Option type codepoint (a recognized [`ndp_option_type_is_known`]
        /// value).
        ty: u8,
        /// Option value bytes (everything after the Type/Length header).
        value: Vec<u8>,
        /// Explicit `Length` field (in units of 8 octets) when the agent set it
        /// on purpose. `None` means auto-fill on encode. An explicitly-set
        /// value is preserved even when it disagrees with `value` — the
        /// honored-overrides rule.
        length: Option<u8>,
    },
    /// An unrecognized option type, preserved verbatim so its bytes round-trip
    /// unchanged.
    Unknown {
        /// Option type codepoint (an unrecognized value).
        ty: u8,
        /// Option value bytes (everything after the Type/Length header),
        /// preserved exactly as decoded.
        bytes: Vec<u8>,
        /// Explicit `Length` field (in units of 8 octets) when set; `None`
        /// auto-fills on encode.
        length: Option<u8>,
    },
}

impl NdpOption {
    /// Build a recognized-type option from its type codepoint and raw value
    /// bytes, with the length field auto-filled on encode.
    pub fn generic(ty: u8, value: impl Into<Vec<u8>>) -> Self {
        Self::Generic {
            ty,
            value: value.into(),
            length: None,
        }
    }

    /// Build an unrecognized-type option whose bytes are preserved verbatim,
    /// with the length field auto-filled on encode.
    pub fn unknown(ty: u8, bytes: impl Into<Vec<u8>>) -> Self {
        Self::Unknown {
            ty,
            bytes: bytes.into(),
            length: None,
        }
    }

    /// Build a Source Link-Layer Address option (type 1) carrying an Ethernet /
    /// IEEE 802 (48-bit) MAC address.
    ///
    /// RFC 4861 section 4.6.1: the option contains the link-layer address of the
    /// sender of the packet. For IEEE 802 addresses the option occupies one
    /// 8-octet unit — a two-byte Type/Length header plus the six-byte address —
    /// so the auto-filled length is 1. This is a typed constructor over the
    /// framework: it produces a [`NdpOption::Generic`] whose six value bytes are
    /// the MAC, so it round-trips through [`NdpOptions`] exactly like any other
    /// recognized option, and [`NdpOption::link_layer_address`] reads it back.
    pub fn source_link_layer_address(mac: MacAddr) -> Self {
        Self::generic(NDP_OPT_SOURCE_LINK_LAYER_ADDR, mac.octets().to_vec())
    }

    /// Build a Target Link-Layer Address option (type 2) carrying an Ethernet /
    /// IEEE 802 (48-bit) MAC address.
    ///
    /// RFC 4861 section 4.6.1: the option contains the link-layer address of the
    /// target; it shares the Source Link-Layer Address layout and is used by
    /// Neighbor and Router Advertisements (modeled in later steps). Provided here
    /// alongside the source option so both link-layer-address codepoints share
    /// one typed constructor/accessor pair.
    pub fn target_link_layer_address(mac: MacAddr) -> Self {
        Self::generic(NDP_OPT_TARGET_LINK_LAYER_ADDR, mac.octets().to_vec())
    }

    /// Read the Ethernet / IEEE 802 (48-bit) MAC carried by a Source (type 1) or
    /// Target (type 2) Link-Layer Address option.
    ///
    /// Returns `None` when the option is not a link-layer-address option or when
    /// its value does not hold a full six-byte IEEE 802 address (for example a
    /// non-Ethernet link layer with a different address width, or a truncated
    /// option). The first six value bytes are interpreted as the address, which
    /// matches the RFC 4861 section 4.6.1 Ethernet layout (length 1, no padding).
    pub fn link_layer_address(&self) -> Option<MacAddr> {
        match self.option_type() {
            NDP_OPT_SOURCE_LINK_LAYER_ADDR | NDP_OPT_TARGET_LINK_LAYER_ADDR => {
                let value = self.value();
                if value.len() < NDP_LINK_LAYER_ADDR_ETHERNET_LEN {
                    return None;
                }
                let mut octets = [0u8; NDP_LINK_LAYER_ADDR_ETHERNET_LEN];
                octets.copy_from_slice(&value[..NDP_LINK_LAYER_ADDR_ETHERNET_LEN]);
                Some(MacAddr::new(octets))
            }
            _ => None,
        }
    }

    /// Build a Prefix Information option (type 3) carrying an IPv6 prefix and the
    /// SLAAC-relevant lifetimes and flags (RFC 4861 section 4.6.2).
    ///
    /// The 30-byte value (everything after the two-byte Type/Length header) is
    /// laid out per RFC 4861 section 4.6.2:
    ///
    /// ```text
    /// Prefix Length (1) | Flags (1: L|A|Reserved1) |
    /// Valid Lifetime (4) | Preferred Lifetime (4) | Reserved2 (4) | Prefix (16)
    /// ```
    ///
    /// With the two-byte header that is exactly 32 bytes — four 8-octet units —
    /// so the auto-filled `Length` is 4 ([`NDP_PREFIX_INFORMATION_UNITS`]) and no
    /// padding is needed. This is a typed constructor over the framework: it
    /// produces a [`NdpOption::Generic`] whose value bytes are the option fields,
    /// so it round-trips through [`NdpOptions`] exactly like any other recognized
    /// option, and the [`NdpOption::prefix`] / [`NdpOption::prefix_length`] /
    /// [`NdpOption::prefix_on_link`] / [`NdpOption::prefix_autonomous`] /
    /// [`NdpOption::prefix_valid_lifetime`] /
    /// [`NdpOption::prefix_preferred_lifetime`] accessors read each field back.
    ///
    /// `on_link` sets the L flag (RFC 4861 sec 4.6.2: prefix usable for on-link
    /// determination); `autonomous` sets the A flag (RFC 4862 sec 5.5.3: prefix
    /// usable for stateless address autoconfiguration). The two flags are
    /// independent. The six Reserved1 bits and the 32-bit Reserved2 field are sent
    /// zero; [`NdpOption::prefix_reserved1`] / [`NdpOption::prefix_reserved2`]
    /// read them back, and [`NdpOption::prefix_information_raw`] sets them on
    /// purpose. Lifetimes are in seconds; [`NDP_PREFIX_LIFETIME_INFINITY`]
    /// (`0xffffffff`) means infinity.
    pub fn prefix_information(
        prefix: Ipv6Addr,
        prefix_len: u8,
        on_link: bool,
        autonomous: bool,
        valid_lifetime: u32,
        preferred_lifetime: u32,
    ) -> Self {
        let mut flags = 0u8;
        if on_link {
            flags |= NDP_PREFIX_FLAG_ON_LINK;
        }
        if autonomous {
            flags |= NDP_PREFIX_FLAG_AUTONOMOUS;
        }
        Self::prefix_information_raw(
            prefix,
            prefix_len,
            flags,
            valid_lifetime,
            preferred_lifetime,
            0,
        )
    }

    /// Build a Prefix Information option (type 3) with the full flags octet and
    /// Reserved2 field set explicitly (RFC 4861 section 4.6.2).
    ///
    /// This is the honored-overrides escape hatch behind
    /// [`NdpOption::prefix_information`]: it writes the `flags` octet
    /// (L | A | the six Reserved1 bits) and the 32-bit `reserved2` field verbatim,
    /// so an agent can set the Reserved1 bits or Reserved2 — which RFC 4861 says to
    /// send as zero — on purpose, for a forward-compatible or deliberately
    /// malformed packet. Those values survive an encode/decode round-trip
    /// untouched.
    pub fn prefix_information_raw(
        prefix: Ipv6Addr,
        prefix_len: u8,
        flags: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        reserved2: u32,
    ) -> Self {
        // RFC 4861 sec 4.6.2 value layout (after the Type/Length header):
        //   Prefix Length(1) Flags(1) Valid(4) Preferred(4) Reserved2(4) Prefix(16)
        let mut value = Vec::with_capacity(NDP_PREFIX_INFORMATION_LEN - NDP_OPTION_HEADER_LEN);
        value.push(prefix_len);
        value.push(flags);
        value.extend_from_slice(&valid_lifetime.to_be_bytes());
        value.extend_from_slice(&preferred_lifetime.to_be_bytes());
        value.extend_from_slice(&reserved2.to_be_bytes());
        value.extend_from_slice(&prefix.octets());
        Self::generic(NDP_OPT_PREFIX_INFORMATION, value)
    }

    /// Read the raw flags octet (L | A | Reserved1) of a Prefix Information
    /// option (type 3), or `None` for any other option or a truncated value.
    fn prefix_flags(&self) -> Option<u8> {
        if self.option_type() != NDP_OPT_PREFIX_INFORMATION {
            return None;
        }
        // value[1] is the flags octet (value[0] is Prefix Length).
        self.value().get(1).copied()
    }

    /// Read the Prefix Length field (0..=128) of a Prefix Information option
    /// (type 3), or `None` for any other option or a truncated value.
    pub fn prefix_length(&self) -> Option<u8> {
        if self.option_type() != NDP_OPT_PREFIX_INFORMATION {
            return None;
        }
        self.value().first().copied()
    }

    /// Read the on-link (L) flag of a Prefix Information option (type 3), or
    /// `None` for any other option or a truncated value (RFC 4861 sec 4.6.2).
    pub fn prefix_on_link(&self) -> Option<bool> {
        self.prefix_flags()
            .map(|flags| flags & NDP_PREFIX_FLAG_ON_LINK != 0)
    }

    /// Read the autonomous address-configuration (A) flag of a Prefix Information
    /// option (type 3), or `None` for any other option or a truncated value
    /// (RFC 4861 sec 4.6.2 / RFC 4862 sec 5.5.3).
    pub fn prefix_autonomous(&self) -> Option<bool> {
        self.prefix_flags()
            .map(|flags| flags & NDP_PREFIX_FLAG_AUTONOMOUS != 0)
    }

    /// Read the six Reserved1 bits (the low six bits of the flags octet) of a
    /// Prefix Information option (type 3), preserved verbatim, or `None` for any
    /// other option or a truncated value (RFC 4861 sec 4.6.2).
    pub fn prefix_reserved1(&self) -> Option<u8> {
        self.prefix_flags()
            .map(|flags| flags & NDP_PREFIX_FLAGS_RESERVED)
    }

    /// Read the Valid Lifetime (seconds; `0xffffffff` = infinity) of a Prefix
    /// Information option (type 3), or `None` for any other option or a truncated
    /// value (RFC 4861 sec 4.6.2).
    pub fn prefix_valid_lifetime(&self) -> Option<u32> {
        self.prefix_u32_at(2)
    }

    /// Read the Preferred Lifetime (seconds; `0xffffffff` = infinity) of a Prefix
    /// Information option (type 3), or `None` for any other option or a truncated
    /// value (RFC 4861 sec 4.6.2).
    pub fn prefix_preferred_lifetime(&self) -> Option<u32> {
        self.prefix_u32_at(6)
    }

    /// Read the 32-bit Reserved2 field of a Prefix Information option (type 3),
    /// preserved verbatim, or `None` for any other option or a truncated value
    /// (RFC 4861 sec 4.6.2).
    pub fn prefix_reserved2(&self) -> Option<u32> {
        self.prefix_u32_at(10)
    }

    /// Read the Prefix (128-bit IPv6 address/prefix) of a Prefix Information
    /// option (type 3), or `None` for any other option or a truncated value
    /// (RFC 4861 sec 4.6.2).
    pub fn prefix(&self) -> Option<Ipv6Addr> {
        if self.option_type() != NDP_OPT_PREFIX_INFORMATION {
            return None;
        }
        let value = self.value();
        // Prefix occupies value bytes 14..30 (after PrefixLen, Flags, the two
        // lifetimes, and Reserved2).
        let prefix = value.get(14..30)?;
        let mut octets = [0u8; 16];
        octets.copy_from_slice(prefix);
        Some(Ipv6Addr::from(octets))
    }

    /// Read a big-endian `u32` from offset `at` of a Prefix Information option's
    /// value bytes, returning `None` when the option is not a Prefix Information
    /// option or the value is too short.
    fn prefix_u32_at(&self, at: usize) -> Option<u32> {
        if self.option_type() != NDP_OPT_PREFIX_INFORMATION {
            return None;
        }
        let value = self.value();
        let word = value.get(at..at + 4)?;
        Some(u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
    }

    /// Build an MTU option (type 5) carrying the recommended link MTU
    /// (RFC 4861 section 4.6.4).
    ///
    /// The 6-byte value (after the two-byte Type/Length header) is a 16-bit
    /// Reserved field (sent zero) followed by the 32-bit MTU, giving exactly one
    /// 8-octet unit — so the auto-filled `Length` is 1
    /// ([`NDP_MTU_OPTION_UNITS`]). This is a typed constructor over the framework:
    /// it produces a [`NdpOption::Generic`] and [`NdpOption::mtu_value`] reads the
    /// MTU back.
    pub fn mtu(mtu: u32) -> Self {
        // RFC 4861 sec 4.6.4 value layout: Reserved(2, zero) || MTU(4).
        let mut value = Vec::with_capacity(NDP_MTU_OPTION_LEN - NDP_OPTION_HEADER_LEN);
        value.extend_from_slice(&[0u8, 0u8]);
        value.extend_from_slice(&mtu.to_be_bytes());
        Self::generic(NDP_OPT_MTU, value)
    }

    /// Read the MTU (octets) carried by an MTU option (type 5), or `None` for any
    /// other option or a truncated value (RFC 4861 section 4.6.4).
    pub fn mtu_value(&self) -> Option<u32> {
        if self.option_type() != NDP_OPT_MTU {
            return None;
        }
        let value = self.value();
        // The MTU is the 32-bit field after the 16-bit Reserved field.
        let word = value.get(2..6)?;
        Some(u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
    }

    /// Build a Redirected Header option (type 4) carrying as much of the original
    /// packet that triggered a Redirect as `original_packet` supplies (RFC 4861
    /// section 4.6.3).
    ///
    /// The value (everything after the two-byte Type/Length header) is laid out
    /// per RFC 4861 section 4.6.3:
    ///
    /// ```text
    /// Reserved (6 octets, sent zero) | IP header + data
    /// ```
    ///
    /// The "IP header + data" is the original datagram (its IPv6 header and as
    /// much of the payload as fits); RFC 4861 section 4.6.3 truncates it "to
    /// ensure that the size of the redirect message does not exceed the minimum
    /// MTU required to support IPv6". `crafter` preserves whatever bytes the
    /// caller passes verbatim — the embedded portion is opaque, so no decode is
    /// required — and the framework auto-fills the option `Length` to the next
    /// 8-octet boundary, zero-padding the embedded bytes to fill the last unit.
    /// This is a typed constructor over the framework: it produces a
    /// [`NdpOption::Generic`] whose value bytes are the six Reserved octets
    /// followed by the embedded packet, so it round-trips through [`NdpOptions`]
    /// exactly like any other recognized option, and
    /// [`NdpOption::redirected_header_data`] reads the embedded bytes back.
    ///
    /// The 6-octet Reserved area (a 16-bit field in the first word and a 32-bit
    /// field in the second) is sent zero per RFC 4861 section 4.6.3; to set it on
    /// purpose, build the option with [`NdpOption::generic`] and a hand-laid value.
    pub fn redirected_header(original_packet: &[u8]) -> Self {
        // RFC 4861 sec 4.6.3 value layout (after the Type/Length header):
        //   Reserved(6, zero) || IP header + data.
        let mut value =
            Vec::with_capacity(NDP_REDIRECTED_HEADER_RESERVED_LEN + original_packet.len());
        value.extend_from_slice(&[0u8; NDP_REDIRECTED_HEADER_RESERVED_LEN]);
        value.extend_from_slice(original_packet);
        Self::generic(NDP_OPT_REDIRECTED_HEADER, value)
    }

    /// Read the embedded "IP header + data" of a Redirected Header option (type
    /// 4): the bytes after the 6-octet Reserved area (RFC 4861 section 4.6.3).
    ///
    /// Returns `None` for any other option, or when the value is too short to hold
    /// the 6-octet Reserved area. The returned slice is the embedded original
    /// packet exactly as carried on the wire, including any zero padding the
    /// option `Length` auto-fill appended to reach the 8-octet boundary — callers
    /// that need the unpadded original must track its length out of band, since
    /// RFC 4861 section 4.6.3 does not record the embedded length in the option.
    pub fn redirected_header_data(&self) -> Option<&[u8]> {
        if self.option_type() != NDP_OPT_REDIRECTED_HEADER {
            return None;
        }
        self.value().get(NDP_REDIRECTED_HEADER_RESERVED_LEN..)
    }

    /// Build a Route Information option (type 24) advertising a more-specific
    /// route and its preference (RFC 4191 section 2.3).
    ///
    /// The number of 8-octet units the option occupies is chosen from
    /// `prefix_len`, per RFC 4191 section 2.3 ("The Prefix field is 0, 8, or 16
    /// octets depending on Length", and the Length field "is 1, 2, or 3 depending
    /// on the Prefix Length"):
    ///
    /// - `prefix_len == 0` → `Length` 1, **no** Prefix octets (a default-route
    ///   preference);
    /// - `1..=64` → `Length` 2, the high **8** octets of the prefix;
    /// - `65..=128` → `Length` 3, the full **16**-octet prefix.
    ///
    /// The encoded value (after the two-byte Type/Length header) is laid out per
    /// RFC 4191 section 2.3:
    ///
    /// ```text
    /// Prefix Length (1) | Resvd|Prf|Resvd (1) | Route Lifetime (4) | Prefix (0/8/16)
    /// ```
    ///
    /// where the flags byte carries the [`Prf`] preference in bits `0x18`
    /// ([`NDP_PRF_MASK`]) and all other bits Reserved (sent zero). The prefix is
    /// truncated to the number of octets the chosen `Length` carries, so only the
    /// leading bits that `prefix_len` covers are placed on the wire (RFC 4191
    /// section 2.3: "The bits in the prefix after the prefix length are reserved
    /// and MUST be initialized to zero by the sender and ignored by the
    /// receiver"). `route_lifetime` is in seconds;
    /// [`NDP_ROUTE_LIFETIME_INFINITY`] (`0xffffffff`) means infinity.
    ///
    /// This is a typed constructor over the framework: it produces a
    /// [`NdpOption::Generic`] whose value bytes are the option fields, so it
    /// round-trips through [`NdpOptions`] exactly like any other recognized
    /// option, and [`NdpOption::route_prefix`] /
    /// [`NdpOption::route_prefix_length`] / [`NdpOption::route_preference`] /
    /// [`NdpOption::route_lifetime`] read each field back. To choose the encoded
    /// `Length` (and therefore the carried prefix octets) independently of
    /// `prefix_len`, or to set the Reserved bits on purpose, use
    /// [`NdpOption::route_information_raw`].
    pub fn route_information(
        prefix: Ipv6Addr,
        prefix_len: u8,
        preference: Prf,
        route_lifetime: u32,
    ) -> Self {
        // RFC 4191 sec 2.3: the Length field (and therefore the carried prefix
        // octets) follows from the Prefix Length.
        let prefix_octets = route_prefix_octets_for_len(prefix_len);
        Self::route_information_raw(
            prefix,
            prefix_len,
            preference.to_flag_bits(),
            route_lifetime,
            prefix_octets,
        )
    }

    /// Build a Route Information option (type 24) with the full flags byte and an
    /// explicit number of carried prefix octets (RFC 4191 section 2.3).
    ///
    /// This is the honored-overrides escape hatch behind
    /// [`NdpOption::route_information`]: `flags` is written verbatim (so the Prf
    /// bits *and* the Reserved bits — which RFC 4191 says to send as zero — survive
    /// untouched, for a forward-compatible or deliberately malformed packet), and
    /// `prefix_octets` selects exactly how many leading octets of `prefix` are
    /// placed on the wire. `prefix_octets` is clamped to 16; passing 0, 8, or 16
    /// yields the RFC 4191 section 2.3 `Length` 1/2/3 forms (the auto-filled
    /// option `Length` rounds the whole option up to the 8-octet boundary). Any
    /// carried prefix octets beyond `prefix_octets` are dropped; if `prefix_octets`
    /// is not a multiple of 8, the framework's length auto-fill zero-pads the value
    /// up to the next unit.
    pub fn route_information_raw(
        prefix: Ipv6Addr,
        prefix_len: u8,
        flags: u8,
        route_lifetime: u32,
        prefix_octets: usize,
    ) -> Self {
        // RFC 4191 sec 2.3 value layout (after the Type/Length header):
        //   Prefix Length(1) | Resvd|Prf|Resvd(1) | Route Lifetime(4) | Prefix(0/8/16)
        let carried = prefix_octets.min(16);
        let mut value = Vec::with_capacity(6 + carried);
        value.push(prefix_len);
        value.push(flags);
        value.extend_from_slice(&route_lifetime.to_be_bytes());
        value.extend_from_slice(&prefix.octets()[..carried]);
        Self::generic(NDP_OPT_ROUTE_INFORMATION, value)
    }

    /// Read the raw flags byte (`Resvd|Prf|Resvd`) of a Route Information option
    /// (type 24), or `None` for any other option or a truncated value (RFC 4191
    /// sec 2.3).
    fn route_flags(&self) -> Option<u8> {
        if self.option_type() != NDP_OPT_ROUTE_INFORMATION {
            return None;
        }
        // value[1] is the flags byte (value[0] is Prefix Length).
        self.value().get(1).copied()
    }

    /// Read the Prefix Length field (0..=128) of a Route Information option (type
    /// 24), or `None` for any other option or a truncated value (RFC 4191 sec
    /// 2.3).
    pub fn route_prefix_length(&self) -> Option<u8> {
        if self.option_type() != NDP_OPT_ROUTE_INFORMATION {
            return None;
        }
        self.value().first().copied()
    }

    /// Read the Route Preference (Prf) of a Route Information option (type 24),
    /// decoded from the `0x18` bits of the flags byte (RFC 4191 sec 2.3), or
    /// `None` for any other option or a truncated value.
    pub fn route_preference(&self) -> Option<Prf> {
        self.route_flags().map(Prf::from_flag_byte)
    }

    /// Read the Route Lifetime (seconds; `0xffffffff` = infinity) of a Route
    /// Information option (type 24), or `None` for any other option or a truncated
    /// value (RFC 4191 sec 2.3).
    pub fn route_lifetime(&self) -> Option<u32> {
        if self.option_type() != NDP_OPT_ROUTE_INFORMATION {
            return None;
        }
        let value = self.value();
        let word = value.get(2..6)?;
        Some(u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
    }

    /// Read the Prefix carried by a Route Information option (type 24) as a full
    /// 128-bit [`Ipv6Addr`], zero-extending the trailing octets that the option's
    /// `Length` form did not carry (RFC 4191 sec 2.3: a Length-1 option carries no
    /// prefix octets, Length-2 the high 8, Length-3 all 16).
    ///
    /// Returns `None` for any other option or a value too short to hold the
    /// 6-octet fixed head (Prefix Length, flags, Route Lifetime). The carried
    /// prefix octets are taken verbatim and the rest are zero — matching the wire,
    /// where the bits beyond the prefix length are reserved and sent zero.
    pub fn route_prefix(&self) -> Option<Ipv6Addr> {
        if self.option_type() != NDP_OPT_ROUTE_INFORMATION {
            return None;
        }
        let value = self.value();
        // The prefix octets follow the 6-byte fixed head; there are 0, 8, or 16
        // of them. Capture however many are present (up to 16) and zero-extend.
        let carried = value.get(6..)?;
        let take = carried.len().min(16);
        let mut octets = [0u8; 16];
        octets[..take].copy_from_slice(&carried[..take]);
        Some(Ipv6Addr::from(octets))
    }

    /// Build a Recursive DNS Server (RDNSS) option (type 25) advertising one or
    /// more recursive DNS resolvers and the lifetime over which they may be used
    /// (RFC 8106 section 5.1).
    ///
    /// The value (everything after the two-byte Type/Length header) is laid out
    /// per RFC 8106 section 5.1:
    ///
    /// ```text
    /// Reserved (2, sent zero) | Lifetime (4) | Address[0..n] (16 each)
    /// ```
    ///
    /// With the two-byte header that is `8 + 16 * n` bytes — exactly `1 + 2 * n`
    /// 8-octet units ([`ndp_rdnss_length_units`]) — so no padding is needed and
    /// the framework's auto-fill produces the RFC's "minimum value is 3 if one
    /// IPv6 address" length. `lifetime` is in seconds;
    /// [`NDP_DNS_LIFETIME_INFINITY`] (`0xffffffff`) means infinity and a value of
    /// zero means the addresses MUST no longer be used.
    ///
    /// This is a typed constructor over the framework: it produces a
    /// [`NdpOption::Generic`] whose value bytes are the option fields, so it
    /// round-trips through [`NdpOptions`] exactly like any other recognized
    /// option, and [`NdpOption::rdnss_lifetime`] / [`NdpOption::rdnss_servers`]
    /// read the fields back. RFC 8106 section 5.1 says the option SHOULD carry at
    /// least one address, but `crafter` does not reject an empty list so an agent
    /// can emit a deliberately malformed option to exercise a parser.
    pub fn rdnss(lifetime: u32, servers: &[Ipv6Addr]) -> Self {
        // RFC 8106 sec 5.1 value layout (after the Type/Length header):
        //   Reserved(2, zero) || Lifetime(4) || Address(16) * n.
        let mut value =
            Vec::with_capacity(NDP_DNS_RESERVED_LEN + 4 + servers.len() * NDP_RDNSS_ADDRESS_LEN);
        value.extend_from_slice(&[0u8; NDP_DNS_RESERVED_LEN]);
        value.extend_from_slice(&lifetime.to_be_bytes());
        for server in servers {
            value.extend_from_slice(&server.octets());
        }
        Self::generic(NDP_OPT_RDNSS, value)
    }

    /// Read the Lifetime (seconds; `0xffffffff` = infinity, `0` = no longer use)
    /// of an RDNSS option (type 25), or `None` for any other option or a value
    /// too short to hold the Reserved + Lifetime head (RFC 8106 section 5.1).
    pub fn rdnss_lifetime(&self) -> Option<u32> {
        if self.option_type() != NDP_OPT_RDNSS {
            return None;
        }
        // The Lifetime is the 32-bit field after the 16-bit Reserved field.
        let word = self
            .value()
            .get(NDP_DNS_RESERVED_LEN..NDP_DNS_RESERVED_LEN + 4)?;
        Some(u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
    }

    /// Read the recursive DNS server addresses carried by an RDNSS option (type
    /// 25), in order, or `None` for any other option (RFC 8106 section 5.1).
    ///
    /// Returns an empty `Vec` for a well-formed option that carries no addresses.
    /// Any trailing bytes that do not form a complete 16-byte address (a
    /// truncated or padded value) are ignored, so the accessor never panics on a
    /// malformed option.
    pub fn rdnss_servers(&self) -> Option<Vec<Ipv6Addr>> {
        if self.option_type() != NDP_OPT_RDNSS {
            return None;
        }
        let value = self.value();
        // Addresses follow the 2-byte Reserved field and the 4-byte Lifetime.
        let addresses = value.get(NDP_DNS_RESERVED_LEN + 4..)?;
        let mut servers = Vec::with_capacity(addresses.len() / NDP_RDNSS_ADDRESS_LEN);
        for chunk in addresses.chunks_exact(NDP_RDNSS_ADDRESS_LEN) {
            let mut octets = [0u8; NDP_RDNSS_ADDRESS_LEN];
            octets.copy_from_slice(chunk);
            servers.push(Ipv6Addr::from(octets));
        }
        Some(servers)
    }

    /// Build a DNS Search List (DNSSL) option (type 31) advertising one or more
    /// DNS search-list domain names and the lifetime over which they may be used
    /// (RFC 8106 section 5.2).
    ///
    /// The value (everything after the two-byte Type/Length header) is laid out
    /// per RFC 8106 section 5.2:
    ///
    /// ```text
    /// Reserved (2, sent zero) | Lifetime (4) | Domain Names | zero padding
    /// ```
    ///
    /// Each domain name is encoded with the crate's existing RFC 1035 Section 3.1
    /// label codec ([`DnsName::encode_uncompressed`]) — length-prefixed labels
    /// terminated by a zero-length (root) label, **without** compression pointers,
    /// exactly as RFC 8106 section 5.2 requires ("MUST be encoded as described in
    /// Section 3.1 of RFC 1035" and "MUST NOT be encoded in the compressed
    /// form"). The concatenated names are then zero-padded so the whole value
    /// reaches a multiple of 8 octets; the framework's [`Self::encode`] length
    /// auto-fill performs that padding (the trailing zero octets are
    /// indistinguishable from extra root labels, which RFC 8106 section 5.2 notes
    /// a parser must tolerate). `lifetime` is in seconds;
    /// [`NDP_DNS_LIFETIME_INFINITY`] (`0xffffffff`) means infinity and zero means
    /// the domain names MUST no longer be used.
    ///
    /// This is a typed constructor over the framework: it produces a
    /// [`NdpOption::Generic`] whose value bytes are the option fields, and
    /// [`NdpOption::dnssl_lifetime`] / [`NdpOption::dnssl_domains`] read the
    /// fields back. A domain string that does not parse as an RFC 1035 name (an
    /// over-long label or name) is skipped rather than aborting the build, so the
    /// infallible builder call sites keep composing; use
    /// [`NdpOption::dnssl_checked`] when an encoding error is meaningful.
    pub fn dnssl<S: AsRef<str>>(lifetime: u32, domains: &[S]) -> Self {
        Self::dnssl_checked(lifetime, domains).unwrap_or_else(|_| {
            // Fall back to a names-free option (Reserved + Lifetime only) when a
            // domain fails to encode, mirroring the infallible-builder idiom the
            // rest of the NDP option constructors use.
            let mut value = Vec::with_capacity(NDP_DNS_RESERVED_LEN + 4);
            value.extend_from_slice(&[0u8; NDP_DNS_RESERVED_LEN]);
            value.extend_from_slice(&lifetime.to_be_bytes());
            Self::generic(NDP_OPT_DNSSL, value)
        })
    }

    /// Build a DNS Search List (DNSSL) option (type 31), surfacing an RFC 1035
    /// name-encoding error instead of silently skipping the offending domain
    /// (RFC 8106 section 5.2).
    ///
    /// This is the fallible form behind [`NdpOption::dnssl`]: each domain is
    /// parsed and encoded with [`DnsName::encode_uncompressed`], and the first
    /// label/name that violates the RFC 1035 length bounds returns a structured
    /// [`CrafterError`].
    pub fn dnssl_checked<S: AsRef<str>>(lifetime: u32, domains: &[S]) -> Result<Self> {
        // RFC 8106 sec 5.2 value layout (after the Type/Length header):
        //   Reserved(2, zero) || Lifetime(4) || encoded names || zero padding.
        let mut value = Vec::with_capacity(NDP_DNS_RESERVED_LEN + 4 + domains.len() * 8);
        value.extend_from_slice(&[0u8; NDP_DNS_RESERVED_LEN]);
        value.extend_from_slice(&lifetime.to_be_bytes());
        for domain in domains {
            let name = DnsName::parse(domain.as_ref())?;
            // Reuse the crate's RFC 1035 Section 3.1 label writer (uncompressed),
            // not a hand-rolled encoder.
            value.extend_from_slice(&name.encode_uncompressed()?);
        }
        // The 8-octet-boundary zero padding is applied by the framework's length
        // auto-fill on encode; the in-memory value carries only the names.
        Ok(Self::generic(NDP_OPT_DNSSL, value))
    }

    /// Read the Lifetime (seconds; `0xffffffff` = infinity, `0` = no longer use)
    /// of a DNSSL option (type 31), or `None` for any other option or a value too
    /// short to hold the Reserved + Lifetime head (RFC 8106 section 5.2).
    pub fn dnssl_lifetime(&self) -> Option<u32> {
        if self.option_type() != NDP_OPT_DNSSL {
            return None;
        }
        let word = self
            .value()
            .get(NDP_DNS_RESERVED_LEN..NDP_DNS_RESERVED_LEN + 4)?;
        Some(u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
    }

    /// Read the DNS search-list domain names carried by a DNSSL option (type 31),
    /// in order, as canonical trailing-dot presentation strings (RFC 8106 section
    /// 5.2).
    ///
    /// Returns `None` for any other option. The names are decoded with the
    /// crate's RFC 1035 Section 3.1 label codec
    /// ([`crate::protocols::dns::decode_dns_name_typed`], no compression in this
    /// context). Decoding stops at the trailing zero padding: RFC 8106 section
    /// 5.2 pads the value to the 8-octet boundary with zero octets, which decode
    /// as empty (root) names, so a zero-length name marks the end of the real
    /// search list and is not reported. A name that runs past the option value
    /// (a truncated/malformed option) ends the walk without a panic, returning the
    /// names decoded so far.
    pub fn dnssl_domains(&self) -> Option<Vec<String>> {
        if self.option_type() != NDP_OPT_DNSSL {
            return None;
        }
        let value = self.value();
        // Names follow the 2-byte Reserved field and the 4-byte Lifetime.
        let names_area = match value.get(NDP_DNS_RESERVED_LEN + 4..) {
            Some(area) => area,
            None => return Some(Vec::new()),
        };
        let mut domains = Vec::new();
        let mut offset = 0usize;
        while offset < names_area.len() {
            // A zero octet is either an explicit root label terminating a name or
            // the start of the 8-octet-boundary zero padding; either way the real
            // search list has ended.
            if names_area[offset] == 0 {
                break;
            }
            match decode_dns_name_typed(names_area, offset) {
                Ok((name, used)) if used > 0 => {
                    domains.push(name.presentation().to_string());
                    offset += used;
                }
                // A name that does not decode (truncation/overrun) or makes no
                // progress ends the walk; never panic on a malformed option.
                _ => break,
            }
        }
        Some(domains)
    }

    /// Build an RA Flags Extension option (type 26) carrying the 48-bit Bit
    /// Fields area that extends the Router Advertisement flags (RFC 5175
    /// section 4). NDP option family: RaFlagsExtension.
    ///
    /// RFC 5175 section 4: the Router Advertisement flags byte has room for only
    /// eight flags, so this option carries 48 more flag bits "available for
    /// assignment", numbered 8..=55 (continuing the RA flags). The option is
    /// exactly one 8-octet unit — a two-byte Type/Length header plus the six
    /// Bit Fields octets — so the auto-filled `Length` is 1
    /// ([`NDP_RA_FLAGS_EXTENSION_UNITS`]) and no padding is needed. `crafter`
    /// treats the Bit Fields area as a six-byte raw bitfield the agent sets and
    /// inspects directly; no individual extension flags are assigned yet (the
    /// registry leaves them unallocated), so the caller carries whatever bits it
    /// needs.
    ///
    /// This is a typed constructor over the framework: it produces a
    /// [`NdpOption::Generic`] whose six value bytes are `bits`, so it round-trips
    /// through [`NdpOptions`] exactly like any other recognized option, and
    /// [`NdpOption::ra_flags_extension_bits`] reads the bytes back.
    pub fn ra_flags_extension(bits: [u8; NDP_RA_FLAGS_EXTENSION_BITS_LEN]) -> Self {
        // RFC 5175 sec 4 value layout (after the Type/Length header): a 6-octet
        // Bit Fields area continuing the RA flags.
        Self::generic(NDP_OPT_RA_FLAGS_EXTENSION, bits.to_vec())
    }

    /// Read the 48-bit Bit Fields area of an RA Flags Extension option (type 26)
    /// as a six-byte array, or `None` for any other option or a value too short
    /// to hold the six octets (RFC 5175 section 4).
    pub fn ra_flags_extension_bits(&self) -> Option<[u8; NDP_RA_FLAGS_EXTENSION_BITS_LEN]> {
        if self.option_type() != NDP_OPT_RA_FLAGS_EXTENSION {
            return None;
        }
        let value = self.value();
        let bits = value.get(..NDP_RA_FLAGS_EXTENSION_BITS_LEN)?;
        let mut octets = [0u8; NDP_RA_FLAGS_EXTENSION_BITS_LEN];
        octets.copy_from_slice(bits);
        Some(octets)
    }

    /// Build a Nonce option (type 14) carrying the random nonce SEND and RFC 7527
    /// Enhanced DAD use to detect looped-back solicitations (RFC 3971
    /// section 5.3.2).
    ///
    /// RFC 3971 section 5.3.2: the option is "Type, Length, and Nonce fields"
    /// and "The length of the random number MUST be at least 6 bytes. The length
    /// of the random number MUST be selected so that the length of the nonce
    /// option is a multiple of 8 octets." There is **no** separate nonce-length
    /// subfield: the option's `Length` (in 8-octet units) governs the whole
    /// option, and the nonce occupies everything after the two-byte Type/Length
    /// header.
    ///
    /// `crafter` stores the caller's `nonce` bytes verbatim and lets the
    /// framework auto-fill the option `Length`, zero-padding the value to the
    /// next 8-octet boundary on [`Self::encode`]. Because RFC 3971 records no
    /// nonce length separately, [`NdpOption::nonce_value`] returns the **whole**
    /// value area on decode — including any zero padding the boundary alignment
    /// appended — so a caller that needs the exact original nonce must track its
    /// length out of band. `crafter` does not enforce the 6-byte minimum, so an
    /// agent can emit a deliberately short nonce to exercise a parser.
    ///
    /// This is a typed constructor over the framework: it produces a
    /// [`NdpOption::Generic`] whose value bytes are the nonce, so it round-trips
    /// through [`NdpOptions`] exactly like any other recognized option.
    pub fn nonce(nonce: &[u8]) -> Self {
        // RFC 3971 sec 5.3.2 value layout (after the Type/Length header): the
        // random Nonce, padded by the framework to the 8-octet boundary.
        Self::generic(NDP_OPT_NONCE, nonce.to_vec())
    }

    /// Read the Nonce value carried by a Nonce option (type 14): the whole value
    /// area after the two-byte Type/Length header (RFC 3971 section 5.3.2).
    ///
    /// Returns `None` for any other option. RFC 3971 section 5.3.2 records no
    /// separate nonce-length field, so the returned slice is the entire value
    /// area — on a decoded option that includes whatever zero padding the option
    /// `Length` carried to reach the 8-octet boundary. A caller that needs the
    /// unpadded nonce must know its length out of band.
    pub fn nonce_value(&self) -> Option<&[u8]> {
        if self.option_type() != NDP_OPT_NONCE {
            return None;
        }
        Some(self.value())
    }

    /// Build a PREF64 option (type 38) advertising a NAT64 prefix and the
    /// scaled lifetime over which it is valid (RFC 8781 section 4).
    ///
    /// The value (everything after the two-byte Type/Length header) is laid out
    /// per RFC 8781 section 4:
    ///
    /// ```text
    /// Scaled Lifetime (13 bits) | PLC (3 bits) | Highest 96 Bits of Prefix (12 octets)
    /// ```
    ///
    /// With the two-byte header that is exactly 16 bytes — two 8-octet units —
    /// so the auto-filled `Length` is 2 ([`NDP_PREF64_UNITS`]) and no padding is
    /// needed. `scaled_lifetime` is a 13-bit unsigned value in units of 8 seconds
    /// (RFC 8781 sec 4); it is masked to 13 bits ([`NDP_PREF64_SCALED_LIFETIME_MAX`]).
    /// `prefix_length` is the NAT64 prefix length in bits and MUST be one of the
    /// six RFC 8781 section 4 lengths (96, 64, 56, 48, 40, 32) — any other value
    /// returns a structured [`CrafterError`]; use [`NdpOption::pref64_raw`] to
    /// emit a reserved PLC code on purpose. Only the high 96 bits of `prefix` are
    /// placed on the wire; the low 32 bits are dropped per the option layout.
    ///
    /// This is a typed constructor over the framework: it produces a
    /// [`NdpOption::Generic`] whose value bytes are the option fields, so it
    /// round-trips through [`NdpOptions`] exactly like any other recognized
    /// option, and [`NdpOption::pref64_scaled_lifetime`] /
    /// [`NdpOption::pref64_prefix_length`] / [`NdpOption::pref64_plc`] /
    /// [`NdpOption::pref64_prefix`] read each field back.
    pub fn pref64(scaled_lifetime: u16, prefix_length: u8, prefix: Ipv6Addr) -> Result<Self> {
        let plc = Pref64Plc::from_prefix_length_bits(prefix_length)
            .to_plc()
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "ndp.pref64.prefix_length",
                    "PREF64 prefix length must be one of 96, 64, 56, 48, 40, or 32 bits (RFC 8781 sec 4)",
                )
            })?;
        Ok(Self::pref64_raw(scaled_lifetime, plc, prefix))
    }

    /// Build a PREF64 option (type 38) with an explicit raw PLC (Prefix Length
    /// Code) value (RFC 8781 section 4).
    ///
    /// This is the honored-overrides escape hatch behind [`NdpOption::pref64`]:
    /// `plc` is written verbatim into the low three bits of the first 16-bit
    /// word, so an agent can emit a reserved PLC code (6 or 7) — which RFC 8781
    /// section 4 does not assign — on purpose for a forward-compatible or
    /// deliberately malformed packet. `scaled_lifetime` is masked to its 13-bit
    /// field and `plc` to its 3-bit field; only the high 96 bits of `prefix` are
    /// carried.
    pub fn pref64_raw(scaled_lifetime: u16, plc: u8, prefix: Ipv6Addr) -> Self {
        // RFC 8781 sec 4 value layout (after the Type/Length header): a 16-bit
        // word of Scaled Lifetime(13) || PLC(3), then the high 96 prefix bits.
        let word = ((scaled_lifetime & NDP_PREF64_SCALED_LIFETIME_MAX)
            << NDP_PREF64_SCALED_LIFETIME_SHIFT)
            | (u16::from(plc) & NDP_PREF64_PLC_MASK);
        let mut value = Vec::with_capacity(NDP_PREF64_LEN - NDP_OPTION_HEADER_LEN);
        value.extend_from_slice(&word.to_be_bytes());
        value.extend_from_slice(&prefix.octets()[..NDP_PREF64_PREFIX_LEN]);
        Self::generic(NDP_OPT_PREF64, value)
    }

    /// Read the first 16-bit word (Scaled Lifetime || PLC) of a PREF64 option
    /// (type 38), or `None` for any other option or a truncated value.
    fn pref64_word(&self) -> Option<u16> {
        if self.option_type() != NDP_OPT_PREF64 {
            return None;
        }
        let word = self.value().get(0..2)?;
        Some(u16::from_be_bytes([word[0], word[1]]))
    }

    /// Read the 13-bit Scaled Lifetime field (units of 8 seconds) of a PREF64
    /// option (type 38), or `None` for any other option or a truncated value
    /// (RFC 8781 section 4).
    pub fn pref64_scaled_lifetime(&self) -> Option<u16> {
        self.pref64_word()
            .map(|word| word >> NDP_PREF64_SCALED_LIFETIME_SHIFT)
    }

    /// Read the PLC (Prefix Length Code) of a PREF64 option (type 38) as a
    /// typed [`Pref64Plc`], or `None` for any other option or a truncated value
    /// (RFC 8781 section 4).
    pub fn pref64_plc(&self) -> Option<Pref64Plc> {
        self.pref64_word()
            .map(|word| Pref64Plc::from_plc((word & NDP_PREF64_PLC_MASK) as u8))
    }

    /// Read the NAT64 prefix length, in bits, of a PREF64 option (type 38),
    /// decoded from its PLC (RFC 8781 section 4), or `None` for any other option,
    /// a truncated value, or a reserved PLC code (6 or 7) that maps to no
    /// assigned length.
    pub fn pref64_prefix_length(&self) -> Option<u8> {
        self.pref64_plc().and_then(Pref64Plc::prefix_length_bits)
    }

    /// Read the NAT64 prefix carried by a PREF64 option (type 38) as a full
    /// 128-bit [`Ipv6Addr`], zero-extending the low 32 bits the option does not
    /// carry (RFC 8781 section 4: only the high 96 bits are on the wire).
    ///
    /// Returns `None` for any other option or a value too short to hold the
    /// 16-bit word plus the 12-octet prefix.
    pub fn pref64_prefix(&self) -> Option<Ipv6Addr> {
        if self.option_type() != NDP_OPT_PREF64 {
            return None;
        }
        let value = self.value();
        // The 96-bit prefix follows the 16-bit Scaled Lifetime/PLC word.
        let prefix = value.get(2..2 + NDP_PREF64_PREFIX_LEN)?;
        let mut octets = [0u8; 16];
        octets[..NDP_PREF64_PREFIX_LEN].copy_from_slice(prefix);
        Some(Ipv6Addr::from(octets))
    }

    /// Build a Captive Portal option (type 37) carrying the URI of the captive
    /// portal API endpoint (RFC 8910 section 2.3). NDP option family:
    /// CaptivePortal.
    ///
    /// RFC 8910 section 2.3: the option carries a UTF-8 URI after the two-byte
    /// Type/Length header, and "This MUST be padded with NUL (0x00) to make the
    /// total option length (including the Type and Length fields) a multiple of
    /// 8 bytes." The URI "is not guaranteed to be null terminated", so a receiver
    /// recovers it by taking the value area (option length minus the two-byte
    /// header) and stripping the trailing NUL padding.
    ///
    /// `crafter` stores the URI's UTF-8 bytes verbatim and lets the framework
    /// auto-fill the option `Length`, zero (NUL)-padding the value to the next
    /// 8-octet boundary on [`Self::encode`]. This is a typed constructor over the
    /// framework: it produces a [`NdpOption::Generic`] whose value bytes are the
    /// URI, so it round-trips through [`NdpOptions`] exactly like any other
    /// recognized option, and [`NdpOption::captive_portal_uri`] reads the URI
    /// back, stripping the trailing NUL padding.
    pub fn captive_portal(uri: &str) -> Self {
        // RFC 8910 sec 2.3 value layout (after the Type/Length header): the
        // UTF-8 URI, NUL-padded by the framework to the 8-octet boundary.
        Self::generic(NDP_OPT_CAPTIVE_PORTAL, uri.as_bytes().to_vec())
    }

    /// Read the captive portal URI carried by a Captive Portal option (type 37),
    /// stripping the trailing NUL padding (RFC 8910 section 2.3).
    ///
    /// Returns `None` for any other option or when the value (after stripping the
    /// trailing NUL bytes) is not valid UTF-8. RFC 8910 section 2.3 pads the URI
    /// with NUL (0x00) to the 8-octet boundary and the URI "is not guaranteed to
    /// be null terminated", so this accessor strips **all** trailing NUL octets —
    /// which a well-formed URI never contains internally — before decoding the
    /// remaining bytes as UTF-8.
    pub fn captive_portal_uri(&self) -> Option<String> {
        if self.option_type() != NDP_OPT_CAPTIVE_PORTAL {
            return None;
        }
        let value = self.value();
        // Strip the trailing NUL padding RFC 8910 sec 2.3 appended to reach the
        // 8-octet boundary; the URI itself contains no interior NUL.
        let end = value
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |last| last + 1);
        core::str::from_utf8(&value[..end])
            .ok()
            .map(|uri| uri.to_string())
    }

    /// Pin the `Length` field (in units of 8 octets) to an explicit value.
    ///
    /// The pinned value is emitted verbatim by [`Self::encode`], even when it
    /// disagrees with the value bytes — generated tools often need a malformed
    /// option to exercise a peer's parser (the honored-overrides rule). Pass a
    /// fresh option through [`Self::generic`]/[`Self::unknown`] (or
    /// [`Self::clear_length`]) to return to auto-fill.
    pub fn length(mut self, length: u8) -> Self {
        match &mut self {
            Self::Generic { length: l, .. } | Self::Unknown { length: l, .. } => {
                *l = Some(length);
            }
        }
        self
    }

    /// Drop any explicit `Length` override so the field auto-fills on encode.
    pub fn clear_length(mut self) -> Self {
        match &mut self {
            Self::Generic { length: l, .. } | Self::Unknown { length: l, .. } => {
                *l = None;
            }
        }
        self
    }

    /// Option type codepoint.
    pub const fn option_type(&self) -> u8 {
        match self {
            Self::Generic { ty, .. } | Self::Unknown { ty, .. } => *ty,
        }
    }

    /// Option value bytes (everything after the two-byte Type/Length header).
    pub fn value(&self) -> &[u8] {
        match self {
            Self::Generic { value, .. } => value,
            Self::Unknown { bytes, .. } => bytes,
        }
    }

    /// Explicit `Length` field (in units of 8 octets) when one is pinned, else
    /// `None` (auto-fill on encode).
    pub const fn explicit_length(&self) -> Option<u8> {
        match self {
            Self::Generic { length, .. } | Self::Unknown { length, .. } => *length,
        }
    }

    /// True when this option's type is recognized by name.
    pub const fn is_known(&self) -> bool {
        ndp_option_type_is_known(self.option_type())
    }

    /// The `Length` field (in units of 8 octets) that [`Self::encode`] will
    /// emit: the pinned value when set, otherwise the auto-filled length that
    /// rounds the whole option up to the next 8-octet boundary.
    ///
    /// Returns an error only when the auto-filled length would exceed the
    /// one-byte field's range (a value longer than `255 * 8 - 2` bytes); a
    /// pinned length is always returned as-is.
    pub fn effective_length(&self) -> Result<u8> {
        if let Some(length) = self.explicit_length() {
            return Ok(length);
        }
        auto_fill_length(self.value().len())
    }

    /// Total encoded length of this option in bytes, including the Type/Length
    /// header and any zero padding implied by the (auto-filled or pinned)
    /// length field.
    ///
    /// A pinned length drives the encoded size (the honored-overrides rule), so
    /// a deliberately-wrong length yields a deliberately-wrong size.
    pub fn encoded_len(&self) -> Result<usize> {
        Ok(self.effective_length()? as usize * NDP_OPTION_LENGTH_UNIT)
    }

    /// Encode this single option to bytes (RFC 4861 section 4.6 layout).
    ///
    /// The `Length` field is auto-filled to round the whole option (header plus
    /// value) up to the next 8-octet boundary, zero-padding the value, unless
    /// the agent pinned a length via [`Self::length`] — in which case the
    /// pinned length is emitted verbatim and the value is padded (or, for a too
    /// small pinned length, truncated) to match, so the wrong value survives.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.encoded_len()?.max(NDP_OPTION_HEADER_LEN));
        self.encode_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Append this single encoded option to an existing buffer.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        let length = self.effective_length()?;
        let ty = self.option_type();
        let value = self.value();

        let total = length as usize * NDP_OPTION_LENGTH_UNIT;
        let start = out.len();
        out.push(ty);
        out.push(length);

        // The value occupies whatever space the (header + value) leaves inside
        // the length-declared total, padded with zeros to the boundary. When a
        // pinned length is too small to hold the value, the value is truncated
        // to the declared size — the pinned length, not the value, is the
        // source of truth (honored overrides).
        let value_capacity = total.saturating_sub(NDP_OPTION_HEADER_LEN);
        if value.len() >= value_capacity {
            out.extend_from_slice(&value[..value_capacity]);
        } else {
            out.extend_from_slice(value);
            let target = start + total;
            if out.len() < target {
                out.resize(target, 0);
            }
        }

        Ok(())
    }

    /// Decode a single option from the front of `bytes`, returning the option
    /// and the number of bytes it consumed.
    ///
    /// Returns a structured [`CrafterError`] (never a panic) when fewer than two
    /// bytes are available, when the `Length` field is zero (RFC 4861 sec 4.6:
    /// "The value 0 is invalid"), or when the declared length runs past the end
    /// of `bytes`.
    ///
    /// The whole declared option (header plus value, including any padding) is
    /// captured as the option's value bytes so it round-trips verbatim, and the
    /// decoded length is pinned on the returned option so re-encoding reproduces
    /// the original bytes.
    pub fn decode_one(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < NDP_OPTION_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "ndp.option.header",
                NDP_OPTION_HEADER_LEN,
                bytes.len(),
            ));
        }

        let ty = bytes[0];
        let length = bytes[1];
        if length == 0 {
            // RFC 4861 sec 4.6: a length of 0 is invalid.
            return Err(CrafterError::invalid_field_value(
                "ndp.option.length",
                "NDP option length field must not be zero",
            ));
        }

        let total = length as usize * NDP_OPTION_LENGTH_UNIT;
        if total > bytes.len() {
            return Err(CrafterError::buffer_too_short(
                "ndp.option.value",
                total,
                bytes.len(),
            ));
        }

        let value = bytes[NDP_OPTION_HEADER_LEN..total].to_vec();
        let option = if ndp_option_type_is_known(ty) {
            Self::Generic {
                ty,
                value,
                length: Some(length),
            }
        } else {
            Self::Unknown {
                ty,
                bytes: value,
                length: Some(length),
            }
        };
        Ok((option, total))
    }
}

impl fmt::Display for NdpOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ty = self.option_type();
        let name = ndp_option_type_name(ty).unwrap_or("Unknown");
        let length = match self.explicit_length() {
            Some(length) => length.to_string(),
            None => "auto".to_string(),
        };
        write!(
            f,
            "{name}(type={ty}, len={length}, value_len={})",
            self.value().len()
        )
    }
}

/// An ordered list of Neighbor Discovery options (RFC 4861 section 4.6).
///
/// NDP options are an ordered sequence; this container preserves insertion /
/// decode order so a re-encode reproduces the original ordering. Decoding walks
/// the option area option-by-option and never panics: it surfaces the first
/// malformed option as a structured [`CrafterError`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NdpOptions {
    options: Vec<NdpOption>,
}

impl NdpOptions {
    /// Create an empty option list.
    pub const fn new() -> Self {
        Self {
            options: Vec::new(),
        }
    }

    /// Append an option, preserving order.
    pub fn push(mut self, option: NdpOption) -> Self {
        self.options.push(option);
        self
    }

    /// Append an option in place, preserving order.
    pub fn add(&mut self, option: NdpOption) {
        self.options.push(option);
    }

    /// The options in order.
    pub fn options(&self) -> &[NdpOption] {
        &self.options
    }

    /// Number of options.
    pub fn len(&self) -> usize {
        self.options.len()
    }

    /// True when there are no options.
    pub fn is_empty(&self) -> bool {
        self.options.is_empty()
    }

    /// Iterate over the options in order.
    pub fn iter(&self) -> core::slice::Iter<'_, NdpOption> {
        self.options.iter()
    }

    /// Total encoded length, in bytes, of all options.
    pub fn encoded_len(&self) -> Result<usize> {
        let mut total = 0usize;
        for option in &self.options {
            total += option.encoded_len()?;
        }
        Ok(total)
    }

    /// Encode every option in order into a single option-area byte buffer.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.encoded_len()?);
        self.encode_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Append every option in order to an existing buffer.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        for option in &self.options {
            option.encode_into(out)?;
        }
        Ok(())
    }

    /// Decode an entire NDP option area into an ordered list.
    ///
    /// Walks `bytes` option-by-option. Returns a structured [`CrafterError`]
    /// (never a panic) on the first option with a zero length or one that runs
    /// past the end of the buffer. Order is preserved and unrecognized options
    /// are kept verbatim as [`NdpOption::Unknown`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut options = Vec::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let (option, consumed) = NdpOption::decode_one(&bytes[offset..])?;
            // `decode_one` rejects a zero length, so `consumed` is always > 0;
            // the loop therefore always makes progress and terminates.
            offset += consumed;
            options.push(option);
        }
        Ok(Self { options })
    }
}

impl FromIterator<NdpOption> for NdpOptions {
    fn from_iter<I: IntoIterator<Item = NdpOption>>(iter: I) -> Self {
        Self {
            options: iter.into_iter().collect(),
        }
    }
}

impl<'a> IntoIterator for &'a NdpOptions {
    type Item = &'a NdpOption;
    type IntoIter = core::slice::Iter<'a, NdpOption>;

    fn into_iter(self) -> Self::IntoIter {
        self.options.iter()
    }
}

/// Choose how many octets of the prefix a Route Information option carries from
/// its Prefix Length, per RFC 4191 section 2.3 (the Length field "is 1, 2, or 3
/// depending on the Prefix Length", carrying 0, 8, or 16 prefix octets):
///
/// - `0` → 0 octets (Length 1, no prefix);
/// - `1..=64` → 8 octets (Length 2, the high 64 bits);
/// - `65..=128` → 16 octets (Length 3, the full address).
///
/// A `prefix_len` above 128 is out of range; it is clamped to the 16-octet form
/// (the most that can be carried) rather than rejected, so a deliberately
/// out-of-range length still produces a well-formed option.
fn route_prefix_octets_for_len(prefix_len: u8) -> usize {
    match prefix_len {
        0 => 0,
        1..=64 => 8,
        _ => 16,
    }
}

/// Compute the auto-filled `Length` field (in units of 8 octets) for an option
/// whose value is `value_len` bytes long: round the whole option (the two-byte
/// header plus the value) up to the next 8-octet boundary (RFC 4861 sec 4.6).
///
/// Returns an error when the rounded length would exceed the one-byte field's
/// range.
fn auto_fill_length(value_len: usize) -> Result<u8> {
    let total = NDP_OPTION_HEADER_LEN + value_len;
    // Round up to the next multiple of 8 octets, then convert to units.
    let units = total.div_ceil(NDP_OPTION_LENGTH_UNIT);
    // A well-formed option is at least one 8-octet unit even when empty.
    let units = units.max(1);
    u8::try_from(units).map_err(|_| {
        CrafterError::invalid_field_value(
            "ndp.option.length",
            "NDP option length in 8-octet units does not fit in one byte",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The named codepoints match the IANA "IPv6 Neighbor Discovery Option
    // Formats" registry. Hard-coded literals are the independent oracle.
    #[test]
    fn ndp_option_codepoints_match_iana_registry() {
        assert_eq!(NDP_OPT_SOURCE_LINK_LAYER_ADDR, 1);
        assert_eq!(NDP_OPT_TARGET_LINK_LAYER_ADDR, 2);
        assert_eq!(NDP_OPT_PREFIX_INFORMATION, 3);
        assert_eq!(NDP_OPT_REDIRECTED_HEADER, 4);
        assert_eq!(NDP_OPT_MTU, 5);
        assert_eq!(NDP_OPT_NONCE, 14);
        assert_eq!(NDP_OPT_ROUTE_INFORMATION, 24);
        assert_eq!(NDP_OPT_RDNSS, 25);
        assert_eq!(NDP_OPT_RA_FLAGS_EXTENSION, 26);
        assert_eq!(NDP_OPT_DNSSL, 31);
        assert_eq!(NDP_OPT_CAPTIVE_PORTAL, 37);
        assert_eq!(NDP_OPT_PREF64, 38);
    }

    // RFC 4861 sec 4.6.1: the Source Link-Layer Address option (type 1) carries
    // a 6-byte Ethernet MAC, occupies one 8-octet unit (length 1), and reads
    // back through the typed accessor after a full encode/decode round-trip.
    #[test]
    fn source_link_layer_address_round_trips() {
        // Documentation MAC (locally administered, RFC 7042 doc range).
        let mac = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
        let opt = NdpOption::source_link_layer_address(mac);
        assert_eq!(opt.option_type(), NDP_OPT_SOURCE_LINK_LAYER_ADDR);
        assert!(opt.is_known());
        assert_eq!(opt.link_layer_address(), Some(mac));

        let bytes = opt.encode().unwrap();
        // type(1) + length(1=one 8-octet unit) + 6-byte MAC = 8 bytes, no padding.
        assert_eq!(bytes.len(), 8);
        assert_eq!(&bytes[0..2], &[NDP_OPT_SOURCE_LINK_LAYER_ADDR, 1]);
        assert_eq!(&bytes[2..8], &mac.octets());

        let (decoded, consumed) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(decoded.option_type(), NDP_OPT_SOURCE_LINK_LAYER_ADDR);
        assert_eq!(decoded.link_layer_address(), Some(mac));
        // Target Link-Layer Address (type 2) shares the layout.
        let tlla = NdpOption::target_link_layer_address(mac);
        assert_eq!(tlla.option_type(), NDP_OPT_TARGET_LINK_LAYER_ADDR);
        assert_eq!(tlla.link_layer_address(), Some(mac));
    }

    #[test]
    fn link_layer_address_accessor_rejects_other_options() {
        // MTU (type 5) is not a link-layer-address option.
        assert_eq!(
            NdpOption::generic(NDP_OPT_MTU, [0, 0, 0, 0, 5, 0xdc]).link_layer_address(),
            None
        );
        // A truncated type-1 option (fewer than 6 value bytes) yields None.
        assert_eq!(
            NdpOption::generic(NDP_OPT_SOURCE_LINK_LAYER_ADDR, [1, 2, 3]).link_layer_address(),
            None
        );
    }

    #[test]
    fn known_vs_unknown_type_classification() {
        assert!(ndp_option_type_is_known(NDP_OPT_MTU));
        assert_eq!(ndp_option_type_name(NDP_OPT_MTU), Some("MTU"));
        // 99 is unassigned in the NDP option registry.
        assert!(!ndp_option_type_is_known(99));
        assert_eq!(ndp_option_type_name(99), None);
    }

    // A known-type generic option and an unknown option round-trip in order,
    // preserving both the ordering and the exact value bytes.
    #[test]
    fn ordered_known_and_unknown_round_trip() {
        // MTU option (type 5): the RFC 4861 sec 4.6.4 layout is type/length +
        // 2 reserved bytes + 4-byte MTU = 8 bytes total (length unit 1).
        let mtu = NdpOption::generic(NDP_OPT_MTU, [0x00, 0x00, 0x00, 0x00, 0x05, 0xdc]);
        // An unrecognized option type carrying arbitrary 6-byte value, which
        // pads to one 8-octet unit.
        let unknown = NdpOption::unknown(0x99, [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]);

        let options = NdpOptions::new().push(mtu.clone()).push(unknown.clone());

        let encoded = options.encode().unwrap();
        // Two options, each exactly one 8-octet unit.
        assert_eq!(encoded.len(), 16);
        // First option header.
        assert_eq!(&encoded[0..2], &[NDP_OPT_MTU, 1]);
        // Second option header.
        assert_eq!(&encoded[8..10], &[0x99, 1]);

        let decoded = NdpOptions::decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);

        // Order preserved: MTU first, unknown second.
        assert_eq!(decoded.options()[0].option_type(), NDP_OPT_MTU);
        assert!(decoded.options()[0].is_known());
        assert!(matches!(decoded.options()[0], NdpOption::Generic { .. }));

        assert_eq!(decoded.options()[1].option_type(), 0x99);
        assert!(!decoded.options()[1].is_known());
        // Unknown bytes preserved verbatim (incl. the trailing zero padding the
        // encoder added to reach the 8-octet boundary).
        match &decoded.options()[1] {
            NdpOption::Unknown { bytes, .. } => {
                assert_eq!(bytes, &[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }

        // Re-encode reproduces the original bytes exactly.
        assert_eq!(decoded.encode().unwrap(), encoded);
    }

    // The length field auto-fills to the next 8-octet boundary, zero-padding
    // the value (RFC 4861 sec 4.6).
    #[test]
    fn length_auto_fills_to_eight_octet_boundary() {
        // 6-byte value + 2-byte header = 8 bytes -> exactly 1 unit, no padding.
        let exact = NdpOption::generic(NDP_OPT_SOURCE_LINK_LAYER_ADDR, [1, 2, 3, 4, 5, 6]);
        assert_eq!(exact.effective_length().unwrap(), 1);
        let exact_bytes = exact.encode().unwrap();
        assert_eq!(exact_bytes.len(), 8);
        assert_eq!(exact_bytes[1], 1);
        assert_eq!(&exact_bytes[2..8], &[1, 2, 3, 4, 5, 6]);

        // 7-byte value + 2-byte header = 9 bytes -> rounds up to 2 units (16
        // bytes), padding the last 7 bytes with zeros.
        let padded = NdpOption::generic(NDP_OPT_PREFIX_INFORMATION, [9; 7]);
        assert_eq!(padded.effective_length().unwrap(), 2);
        let padded_bytes = padded.encode().unwrap();
        assert_eq!(padded_bytes.len(), 16);
        assert_eq!(padded_bytes[1], 2);
        assert_eq!(&padded_bytes[2..9], &[9; 7]);
        assert_eq!(&padded_bytes[9..16], &[0; 7]);

        // An empty-value option still occupies one 8-octet unit.
        let empty = NdpOption::generic(NDP_OPT_NONCE, []);
        assert_eq!(empty.effective_length().unwrap(), 1);
        assert_eq!(
            empty.encode().unwrap(),
            [NDP_OPT_NONCE, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    // A deliberately-wrong explicit length is emitted verbatim (honored
    // overrides): generated tools need malformed options to exercise a parser.
    #[test]
    fn explicit_wrong_length_is_preserved() {
        // The value is one unit's worth, but the agent pins length=4 (claims 32
        // bytes). The encoder must emit length=4 untouched.
        let wrong = NdpOption::generic(NDP_OPT_MTU, [0, 0, 0, 0, 5, 0xdc]).length(4);
        assert_eq!(wrong.explicit_length(), Some(4));
        assert_eq!(wrong.effective_length().unwrap(), 4);
        let bytes = wrong.encode().unwrap();
        assert_eq!(bytes[1], 4, "pinned length survives untouched");
        assert_eq!(bytes.len(), 32, "pinned length drives the encoded size");
        // The real value bytes are still present at the front, zero-padded out.
        assert_eq!(&bytes[2..8], &[0, 0, 0, 0, 5, 0xdc]);
        assert_eq!(&bytes[8..32], &[0; 24]);

        // A pinned length smaller than the value truncates to the declared size
        // rather than silently growing it — the length stays the source of
        // truth.
        let tiny = NdpOption::unknown(0x99, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).length(1);
        let tiny_bytes = tiny.encode().unwrap();
        assert_eq!(tiny_bytes.len(), 8);
        assert_eq!(tiny_bytes[1], 1);
        assert_eq!(&tiny_bytes[2..8], &[1, 2, 3, 4, 5, 6]);

        // clear_length returns to auto-fill.
        let restored = wrong.clear_length();
        assert_eq!(restored.explicit_length(), None);
        assert_eq!(restored.effective_length().unwrap(), 1);
    }

    // A zero length field is invalid (RFC 4861 sec 4.6) and decodes to a
    // structured error, never a panic.
    #[test]
    fn zero_length_is_a_structured_error() {
        let bytes = [NDP_OPT_MTU, 0, 0, 0, 0, 0, 0, 0];
        let err = NdpOption::decode_one(&bytes).unwrap_err();
        assert_eq!(
            err,
            CrafterError::invalid_field_value(
                "ndp.option.length",
                "NDP option length field must not be zero",
            )
        );

        // The same error surfaces when walking a full option area.
        assert_eq!(NdpOptions::decode(&bytes).unwrap_err(), err);
    }

    // A length that runs past the end of the buffer (truncation/overrun)
    // decodes to a structured BufferTooShort error, never a panic.
    #[test]
    fn truncated_option_is_a_structured_error() {
        // Declares length=2 (16 bytes) but only 8 bytes are present.
        let bytes = [NDP_OPT_PREFIX_INFORMATION, 2, 0, 0, 0, 0, 0, 0];
        let err = NdpOption::decode_one(&bytes).unwrap_err();
        assert_eq!(
            err,
            CrafterError::buffer_too_short("ndp.option.value", 16, 8)
        );

        // A header that is itself truncated (one byte) is also a structured
        // error, not a panic.
        let stub = [NDP_OPT_MTU];
        let header_err = NdpOption::decode_one(&stub).unwrap_err();
        assert_eq!(
            header_err,
            CrafterError::buffer_too_short("ndp.option.header", 2, 1)
        );

        // And it surfaces through the option-area walk too.
        assert_eq!(NdpOptions::decode(&bytes).unwrap_err(), err);
    }

    // RFC 4861 sec 4.6.2: a Prefix Information option (type 3) carries the
    // documentation prefix 2001:db8::/64, the L/A flags, and the two lifetimes;
    // it occupies four 8-octet units (length 4 / 32 bytes) and every field reads
    // back through the typed accessors after a full encode/decode round-trip.
    #[test]
    fn prefix_information_round_trips() {
        // Documentation prefix (RFC 3849) 2001:db8::/64.
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let opt = NdpOption::prefix_information(
            prefix, 64,        // prefix length
            true,      // on-link (L)
            true,      // autonomous (A)
            2_592_000, // valid lifetime (30 days)
            604_800,   // preferred lifetime (7 days)
        );
        assert_eq!(opt.option_type(), NDP_OPT_PREFIX_INFORMATION);
        assert!(opt.is_known());
        assert_eq!(opt.prefix_length(), Some(64));
        assert_eq!(opt.prefix_on_link(), Some(true));
        assert_eq!(opt.prefix_autonomous(), Some(true));
        assert_eq!(opt.prefix_reserved1(), Some(0));
        assert_eq!(opt.prefix_valid_lifetime(), Some(2_592_000));
        assert_eq!(opt.prefix_preferred_lifetime(), Some(604_800));
        assert_eq!(opt.prefix_reserved2(), Some(0));
        assert_eq!(opt.prefix(), Some(prefix));

        let bytes = opt.encode().unwrap();
        // type(1) + length(1) + 30 value bytes = 32 bytes = four 8-octet units.
        assert_eq!(bytes.len(), NDP_PREFIX_INFORMATION_LEN);
        assert_eq!(
            &bytes[0..2],
            &[NDP_OPT_PREFIX_INFORMATION, NDP_PREFIX_INFORMATION_UNITS]
        );
        // Prefix Length, then the flags octet with both L and A set.
        assert_eq!(bytes[2], 64);
        assert_eq!(
            bytes[3],
            NDP_PREFIX_FLAG_ON_LINK | NDP_PREFIX_FLAG_AUTONOMOUS
        );
        // Valid / Preferred Lifetimes (big-endian).
        assert_eq!(&bytes[4..8], &2_592_000u32.to_be_bytes());
        assert_eq!(&bytes[8..12], &604_800u32.to_be_bytes());
        // Reserved2 sent zero.
        assert_eq!(&bytes[12..16], &[0, 0, 0, 0]);
        // The 16-byte prefix.
        assert_eq!(&bytes[16..32], &prefix.octets());

        let (decoded, consumed) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(consumed, NDP_PREFIX_INFORMATION_LEN);
        assert_eq!(decoded.prefix_length(), Some(64));
        assert_eq!(decoded.prefix_on_link(), Some(true));
        assert_eq!(decoded.prefix_autonomous(), Some(true));
        assert_eq!(decoded.prefix_valid_lifetime(), Some(2_592_000));
        assert_eq!(decoded.prefix_preferred_lifetime(), Some(604_800));
        assert_eq!(decoded.prefix(), Some(prefix));
        // Re-encode reproduces the original bytes exactly.
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    // RFC 4861 sec 4.6.2 / RFC 4862 sec 5.5.3: the L (on-link) and A (autonomous)
    // flags are independent. Exercise every boundary combination (neither / L / A
    // / both) and assert each flag reads back independently.
    #[test]
    fn prefix_information_flag_independence() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        for (on_link, autonomous) in [(false, false), (true, false), (false, true), (true, true)] {
            let opt = NdpOption::prefix_information(prefix, 64, on_link, autonomous, 0, 0);
            // Round-trip through encode/decode and read the flags back.
            let bytes = opt.encode().unwrap();
            let (decoded, _) = NdpOption::decode_one(&bytes).unwrap();
            assert_eq!(
                decoded.prefix_on_link(),
                Some(on_link),
                "L read independently (L={on_link} A={autonomous})"
            );
            assert_eq!(
                decoded.prefix_autonomous(),
                Some(autonomous),
                "A read independently (L={on_link} A={autonomous})"
            );
            // The flags octet carries exactly the set bits and nothing in the
            // reserved field.
            let mut expected = 0u8;
            if on_link {
                expected |= NDP_PREFIX_FLAG_ON_LINK;
            }
            if autonomous {
                expected |= NDP_PREFIX_FLAG_AUTONOMOUS;
            }
            assert_eq!(bytes[3], expected);
            assert_eq!(decoded.prefix_reserved1(), Some(0));
        }
    }

    // The lifetimes round-trip the infinity sentinel (0xffffffff) and the
    // Reserved1 / Reserved2 fields are preserved verbatim when set on purpose
    // (honored overrides) via prefix_information_raw.
    #[test]
    fn prefix_information_reserved_and_infinity_preserved() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        // flags = L | A | all six Reserved1 bits set; Reserved2 deliberately
        // non-zero. Lifetimes are infinity.
        let flags =
            NDP_PREFIX_FLAG_ON_LINK | NDP_PREFIX_FLAG_AUTONOMOUS | NDP_PREFIX_FLAGS_RESERVED;
        let opt = NdpOption::prefix_information_raw(
            prefix,
            128,
            flags,
            NDP_PREFIX_LIFETIME_INFINITY,
            NDP_PREFIX_LIFETIME_INFINITY,
            0xdead_beef,
        );
        let bytes = opt.encode().unwrap();
        let (decoded, _) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(decoded.prefix_on_link(), Some(true));
        assert_eq!(decoded.prefix_autonomous(), Some(true));
        // The six Reserved1 bits survive untouched, not masked away.
        assert_eq!(decoded.prefix_reserved1(), Some(NDP_PREFIX_FLAGS_RESERVED));
        assert_eq!(
            decoded.prefix_valid_lifetime(),
            Some(NDP_PREFIX_LIFETIME_INFINITY)
        );
        assert_eq!(
            decoded.prefix_preferred_lifetime(),
            Some(NDP_PREFIX_LIFETIME_INFINITY)
        );
        assert_eq!(decoded.prefix_reserved2(), Some(0xdead_beef));
        assert_eq!(decoded.prefix(), Some(prefix));
    }

    // The Prefix Information accessors reject other option types (no false reads).
    #[test]
    fn prefix_accessors_reject_other_options() {
        let mtu = NdpOption::mtu(1500);
        assert_eq!(mtu.prefix_length(), None);
        assert_eq!(mtu.prefix_on_link(), None);
        assert_eq!(mtu.prefix_autonomous(), None);
        assert_eq!(mtu.prefix_valid_lifetime(), None);
        assert_eq!(mtu.prefix(), None);
    }

    // RFC 4861 sec 4.6.4: an MTU option (type 5) carries a 16-bit Reserved field
    // and a 32-bit MTU, occupies one 8-octet unit (length 1 / 8 bytes), and reads
    // back through the typed accessor after a full encode/decode round-trip.
    #[test]
    fn mtu_option_round_trips() {
        let opt = NdpOption::mtu(1500);
        assert_eq!(opt.option_type(), NDP_OPT_MTU);
        assert!(opt.is_known());
        assert_eq!(opt.mtu_value(), Some(1500));

        let bytes = opt.encode().unwrap();
        // type(1) + length(1) + Reserved(2) + MTU(4) = 8 bytes = one 8-octet unit.
        assert_eq!(bytes.len(), NDP_MTU_OPTION_LEN);
        assert_eq!(&bytes[0..2], &[NDP_OPT_MTU, NDP_MTU_OPTION_UNITS]);
        // Reserved field sent zero.
        assert_eq!(&bytes[2..4], &[0, 0]);
        assert_eq!(&bytes[4..8], &1500u32.to_be_bytes());

        let (decoded, consumed) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(consumed, NDP_MTU_OPTION_LEN);
        assert_eq!(decoded.option_type(), NDP_OPT_MTU);
        assert_eq!(decoded.mtu_value(), Some(1500));
        // A jumbo MTU round-trips too.
        assert_eq!(NdpOption::mtu(9000).mtu_value(), Some(9000));
        // The accessor rejects other option types.
        assert_eq!(NdpOption::generic(NDP_OPT_NONCE, []).mtu_value(), None);
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    // A deliberately-wrong explicit length on a typed Prefix Information / MTU
    // option survives encode untouched (honored overrides) — same rule as the
    // generic options.
    #[test]
    fn typed_option_explicit_wrong_length_is_preserved() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        // A Prefix Information option's real length is 4 units; pin it to 5 (an
        // out-of-spec value). The encoder must emit length=5 untouched and pad to
        // 40 bytes.
        let wrong = NdpOption::prefix_information(prefix, 64, true, false, 0, 0).length(5);
        assert_eq!(wrong.explicit_length(), Some(5));
        let bytes = wrong.encode().unwrap();
        assert_eq!(bytes[1], 5, "pinned length survives untouched");
        assert_eq!(bytes.len(), 40, "pinned length drives the encoded size");
        // The real prefix bytes are still present at the front; clearing the
        // override returns to auto-fill (4 units).
        assert_eq!(&bytes[16..32], &prefix.octets());
        assert_eq!(wrong.clear_length().effective_length().unwrap(), 4);

        // Likewise an MTU option pinned to a wrong length emits it verbatim.
        let mtu_wrong = NdpOption::mtu(1500).length(2);
        let mtu_bytes = mtu_wrong.encode().unwrap();
        assert_eq!(mtu_bytes[1], 2);
        assert_eq!(mtu_bytes.len(), 16);
    }

    // RFC 4861 sec 4.6.3: a Redirected Header option (type 4) carries a 6-octet
    // Reserved area (sent zero) followed by the embedded original packet; the
    // option `Length` auto-fills to the next 8-octet boundary, zero-padding the
    // embedded bytes, and the embedded portion reads back through the typed
    // accessor after a full encode/decode round-trip.
    #[test]
    fn redirected_header_round_trips() {
        // A small stand-in for the original datagram that triggered the redirect:
        // a 4-byte slice. Total option = header(2) + Reserved(6) + 4 = 12 bytes,
        // which rounds up to two 8-octet units (16 bytes), padding the embedded
        // bytes with 4 zeros.
        let original = [0x60u8, 0x00, 0x00, 0x00];
        let opt = NdpOption::redirected_header(&original);
        assert_eq!(opt.option_type(), NDP_OPT_REDIRECTED_HEADER);
        assert!(opt.is_known());
        // The accessor returns the embedded bytes; before encode there is no
        // padding, so it is exactly the original.
        assert_eq!(opt.redirected_header_data(), Some(&original[..]));

        let bytes = opt.encode().unwrap();
        // type(1) + length(1) + Reserved(6) + 4 embedded + 4 padding = 16 bytes
        // = two 8-octet units.
        assert_eq!(bytes.len(), 16);
        assert_eq!(&bytes[0..2], &[NDP_OPT_REDIRECTED_HEADER, 2]);
        // The 6 Reserved octets are zero.
        assert_eq!(&bytes[2..8], &[0; NDP_REDIRECTED_HEADER_RESERVED_LEN]);
        // The embedded original packet, then zero padding to the boundary.
        assert_eq!(&bytes[8..12], &original);
        assert_eq!(&bytes[12..16], &[0, 0, 0, 0]);

        let (decoded, consumed) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(consumed, 16);
        assert_eq!(decoded.option_type(), NDP_OPT_REDIRECTED_HEADER);
        // The decoded accessor sees the embedded bytes *plus* the auto-fill
        // padding (RFC 4861 sec 4.6.3 records no embedded length in the option).
        assert_eq!(
            decoded.redirected_header_data(),
            Some(&[0x60, 0x00, 0x00, 0x00, 0, 0, 0, 0][..])
        );
        // Re-encode reproduces the original bytes exactly.
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    // An exactly-aligned embedded packet needs no padding: header(2) +
    // Reserved(6) + 8 = 16 bytes = two units, and the accessor returns the
    // embedded bytes unchanged with no trailing zeros.
    #[test]
    fn redirected_header_aligned_embedded_has_no_padding() {
        let original = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let opt = NdpOption::redirected_header(&original);
        let bytes = opt.encode().unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[1], 2);
        let (decoded, _) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(decoded.redirected_header_data(), Some(&original[..]));
    }

    // The Redirected Header accessor rejects other option types and a value too
    // short to hold the 6-octet Reserved area (no false reads, no panic).
    #[test]
    fn redirected_header_accessor_rejects_other_options() {
        assert_eq!(NdpOption::mtu(1500).redirected_header_data(), None);
        // A type-4 option whose value is shorter than the 6 Reserved octets.
        assert_eq!(
            NdpOption::generic(NDP_OPT_REDIRECTED_HEADER, [0, 0, 0]).redirected_header_data(),
            None
        );
        // An empty embedded packet is valid: the accessor returns an empty slice.
        let empty = NdpOption::redirected_header(&[]);
        assert_eq!(empty.redirected_header_data(), Some(&[][..]));
    }

    // A trailing malformed option after a valid one still surfaces as an error,
    // and the walk made progress (did not loop or panic).
    #[test]
    fn malformed_trailing_option_after_valid_one_errors() {
        let mut area = Vec::new();
        area.extend_from_slice(
            &NdpOption::generic(NDP_OPT_MTU, [0, 0, 0, 0, 5, 0xdc])
                .encode()
                .unwrap(),
        );
        // Append a second option that overruns.
        area.extend_from_slice(&[NDP_OPT_RDNSS, 5, 0, 0]);
        let err = NdpOptions::decode(&area).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }

    // RFC 4191 sec 2.1: the 2-bit Prf encoding round-trips to/from its raw value
    // (01 High, 00 Medium, 11 Low, 10 Reserved) and to/from its `0x18` field
    // position inside a flags byte.
    #[test]
    fn prf_encoding_round_trips() {
        // Raw 2-bit values per RFC 4191 sec 2.1.
        assert_eq!(Prf::High.to_bits(), 0b01);
        assert_eq!(Prf::Medium.to_bits(), 0b00);
        assert_eq!(Prf::Low.to_bits(), 0b11);
        assert_eq!(Prf::Reserved.to_bits(), 0b10);
        // Medium is the default (RFC 4191 sec 2.1).
        assert_eq!(Prf::default(), Prf::Medium);

        for prf in [Prf::High, Prf::Medium, Prf::Low, Prf::Reserved] {
            // Raw value round-trips.
            assert_eq!(Prf::from_bits(prf.to_bits()), prf);
            // Field-position (0x18) round-trips, and the placed bits never
            // escape the mask.
            let flag_bits = prf.to_flag_bits();
            assert_eq!(flag_bits & !NDP_PRF_MASK, 0, "Prf bits stay within 0x18");
            assert_eq!(Prf::from_flag_byte(flag_bits), prf);
            // Other bits in the flags byte are ignored when reading Prf back.
            assert_eq!(Prf::from_flag_byte(flag_bits | !NDP_PRF_MASK), prf);
        }

        // Concrete placements: High=01 -> 0x08, Low=11 -> 0x18, Reserved=10 -> 0x10.
        assert_eq!(Prf::High.to_flag_bits(), 0x08);
        assert_eq!(Prf::Medium.to_flag_bits(), 0x00);
        assert_eq!(Prf::Low.to_flag_bits(), 0x18);
        assert_eq!(Prf::Reserved.to_flag_bits(), 0x10);
    }

    // RFC 4191 sec 2.3: a Route Information option (type 24) takes 1, 2, or 3
    // 8-octet units depending on the Prefix Length, carrying 0, 8, or 16 prefix
    // octets. Round-trip each form and assert the on-wire Length field, the
    // carried prefix octets, and every typed accessor.
    #[test]
    fn route_information_round_trips_each_prefix_form() {
        // (prefix, prefix_len, expected Length field, expected carried octets)
        let cases = [
            // Default-route preference: no prefix (RFC 4191 Length 1).
            (Ipv6Addr::UNSPECIFIED, 0u8, 1u8, 0usize),
            // 2001:db8::/32 -> high 8 octets (RFC 4191 Length 2).
            (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32, 2, 8),
            // 2001:db8:1::/48 -> still the high 8 octets (Length 2).
            (
                Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 0),
                48,
                2,
                8,
            ),
            // 2001:db8:1:2::/96 -> full 16 octets (RFC 4191 Length 3).
            (
                Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0x0002, 0, 0, 0, 0),
                96,
                3,
                16,
            ),
        ];

        for (prefix, prefix_len, expected_length, expected_carried) in cases {
            let opt = NdpOption::route_information(prefix, prefix_len, Prf::High, 1800);
            assert_eq!(opt.option_type(), NDP_OPT_ROUTE_INFORMATION);
            assert!(opt.is_known());
            assert_eq!(opt.route_prefix_length(), Some(prefix_len));
            assert_eq!(opt.route_preference(), Some(Prf::High));
            assert_eq!(opt.route_lifetime(), Some(1800));

            let bytes = opt.encode().unwrap();
            assert_eq!(
                bytes[0], NDP_OPT_ROUTE_INFORMATION,
                "type 24 (prefix_len={prefix_len})"
            );
            assert_eq!(
                bytes[1], expected_length,
                "Length field in 8-octet units (prefix_len={prefix_len})"
            );
            assert_eq!(
                bytes.len(),
                expected_length as usize * NDP_OPTION_LENGTH_UNIT,
                "encoded size matches Length (prefix_len={prefix_len})"
            );
            // Prefix Length byte, then the flags byte carrying Prf=High (0x08)
            // and nothing else.
            assert_eq!(bytes[2], prefix_len);
            assert_eq!(bytes[3], Prf::High.to_flag_bits());
            // Route Lifetime (big-endian).
            assert_eq!(&bytes[4..8], &1800u32.to_be_bytes());
            // The carried prefix octets are the leading octets of the prefix.
            assert_eq!(
                &bytes[8..8 + expected_carried],
                &prefix.octets()[..expected_carried],
                "carried prefix octets (prefix_len={prefix_len})"
            );

            let (decoded, consumed) = NdpOption::decode_one(&bytes).unwrap();
            assert_eq!(consumed, bytes.len());
            assert_eq!(decoded.route_prefix_length(), Some(prefix_len));
            assert_eq!(decoded.route_preference(), Some(Prf::High));
            assert_eq!(decoded.route_lifetime(), Some(1800));
            // The accessor zero-extends the carried octets back to a full address.
            let mut expected_prefix = [0u8; 16];
            expected_prefix[..expected_carried]
                .copy_from_slice(&prefix.octets()[..expected_carried]);
            assert_eq!(
                decoded.route_prefix(),
                Some(Ipv6Addr::from(expected_prefix))
            );
            // Re-encode reproduces the original bytes exactly.
            assert_eq!(decoded.encode().unwrap(), bytes);
        }
    }

    // RFC 4191 sec 2.3: every Prf value round-trips through a Route Information
    // option's flags byte, leaving the other (Reserved) bits zero.
    #[test]
    fn route_information_round_trips_each_preference() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        for prf in [Prf::High, Prf::Medium, Prf::Low, Prf::Reserved] {
            let opt = NdpOption::route_information(prefix, 32, prf, NDP_ROUTE_LIFETIME_INFINITY);
            let bytes = opt.encode().unwrap();
            // The flags byte is exactly the Prf field; Reserved bits sent zero.
            assert_eq!(bytes[3], prf.to_flag_bits());
            assert_eq!(bytes[3] & !NDP_PRF_MASK, 0);

            let (decoded, _) = NdpOption::decode_one(&bytes).unwrap();
            assert_eq!(decoded.route_preference(), Some(prf), "Prf={prf:?}");
            assert_eq!(
                decoded.route_lifetime(),
                Some(NDP_ROUTE_LIFETIME_INFINITY),
                "infinity lifetime round-trips (Prf={prf:?})"
            );
        }
    }

    // The raw constructor honors an explicit flags byte (Prf + Reserved bits set
    // on purpose) and an explicit carried-octet count (honored overrides).
    #[test]
    fn route_information_raw_preserves_reserved_and_explicit_octets() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 0);
        // Prf=Low plus every Reserved bit set; carry the full 16 octets even
        // though a /48 would normally carry 8.
        let flags = Prf::Low.to_flag_bits() | !NDP_PRF_MASK;
        let opt = NdpOption::route_information_raw(prefix, 48, flags, 600, 16);
        let bytes = opt.encode().unwrap();
        // Length 3 (24 bytes) because 16 prefix octets were carried.
        assert_eq!(bytes[1], 3);
        assert_eq!(bytes.len(), NDP_ROUTE_INFORMATION_LEN_FULL_PREFIX);
        // The full flags byte (Prf + Reserved bits) survives untouched.
        assert_eq!(bytes[3], flags);

        let (decoded, _) = NdpOption::decode_one(&bytes).unwrap();
        // Prf still reads back as Low despite the Reserved bits being set.
        assert_eq!(decoded.route_preference(), Some(Prf::Low));
        // The full prefix round-trips because all 16 octets were carried.
        assert_eq!(decoded.route_prefix(), Some(prefix));
    }

    // The Route Information accessors reject other option types (no false reads).
    #[test]
    fn route_information_accessors_reject_other_options() {
        let mtu = NdpOption::mtu(1500);
        assert_eq!(mtu.route_prefix_length(), None);
        assert_eq!(mtu.route_preference(), None);
        assert_eq!(mtu.route_lifetime(), None);
        assert_eq!(mtu.route_prefix(), None);
    }

    // RFC 8106 sec 5.1: an RDNSS option (type 25) carrying a single documentation
    // resolver occupies 1 + 2*1 = 3 8-octet units (length 3 / 24 bytes) and the
    // lifetime + address read back through the typed accessors after a full
    // encode/decode round-trip.
    #[test]
    fn rdnss_single_server_round_trips() {
        // Documentation resolver (RFC 3849) 2001:db8::1.
        let server = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let opt = NdpOption::rdnss(1800, &[server]);
        assert_eq!(opt.option_type(), NDP_OPT_RDNSS);
        assert!(opt.is_known());
        assert_eq!(opt.rdnss_lifetime(), Some(1800));
        assert_eq!(opt.rdnss_servers(), Some(vec![server]));

        let bytes = opt.encode().unwrap();
        // RFC 8106 sec 5.1: Length = 1 + 2*n = 3 units = 24 bytes for one address.
        assert_eq!(bytes[0], NDP_OPT_RDNSS);
        assert_eq!(bytes[1] as usize, ndp_rdnss_length_units(1));
        assert_eq!(bytes[1], 3);
        assert_eq!(bytes.len(), 3 * NDP_OPTION_LENGTH_UNIT);
        // Reserved field (2 bytes after the Type/Length header) sent zero.
        assert_eq!(&bytes[2..4], &[0, 0]);
        // Lifetime (big-endian), then the 16-byte address with no padding.
        assert_eq!(&bytes[4..8], &1800u32.to_be_bytes());
        assert_eq!(&bytes[8..24], &server.octets());

        let (decoded, consumed) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.rdnss_lifetime(), Some(1800));
        assert_eq!(decoded.rdnss_servers(), Some(vec![server]));
        // Re-encode reproduces the original bytes exactly.
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    // RFC 8106 sec 5.1: an RDNSS option carrying two resolvers occupies
    // 1 + 2*2 = 5 8-octet units (length 5 / 40 bytes); both addresses and the
    // infinity-lifetime sentinel round-trip.
    #[test]
    fn rdnss_two_servers_round_trip() {
        let servers = [
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2),
        ];
        let opt = NdpOption::rdnss(NDP_DNS_LIFETIME_INFINITY, &servers);
        let bytes = opt.encode().unwrap();
        // Length = 1 + 2*2 = 5 units = 40 bytes.
        assert_eq!(bytes[1] as usize, ndp_rdnss_length_units(2));
        assert_eq!(bytes[1], 5);
        assert_eq!(bytes.len(), 5 * NDP_OPTION_LENGTH_UNIT);
        // The two addresses sit back-to-back after the 8-byte fixed head.
        assert_eq!(&bytes[8..24], &servers[0].octets());
        assert_eq!(&bytes[24..40], &servers[1].octets());

        let (decoded, _) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(
            decoded.rdnss_lifetime(),
            Some(NDP_DNS_LIFETIME_INFINITY),
            "infinity lifetime round-trips"
        );
        assert_eq!(decoded.rdnss_servers(), Some(servers.to_vec()));
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    // The RDNSS accessors reject other option types (no false reads).
    #[test]
    fn rdnss_accessors_reject_other_options() {
        let mtu = NdpOption::mtu(1500);
        assert_eq!(mtu.rdnss_lifetime(), None);
        assert_eq!(mtu.rdnss_servers(), None);
    }

    // RFC 8106 sec 5.2: a DNSSL option (type 31) carrying multiple search-list
    // domains encodes each name with the crate's RFC 1035 Section 3.1 label codec
    // (uncompressed), zero-pads the value to the 8-octet boundary, and reads the
    // lifetime + domains back through the typed accessors after a round-trip.
    #[test]
    fn dnssl_multiple_domains_round_trip() {
        // Documentation domains (RFC 2606 reserves example.com / example.net).
        let domains = ["example.com", "example.net"];
        let opt = NdpOption::dnssl(86_400, &domains);
        assert_eq!(opt.option_type(), NDP_OPT_DNSSL);
        assert!(opt.is_known());
        assert_eq!(opt.dnssl_lifetime(), Some(86_400));
        assert_eq!(
            opt.dnssl_domains(),
            Some(vec!["example.com.".to_string(), "example.net.".to_string()])
        );

        // The names in the in-memory value are exactly what the reused DNS
        // encoder produces (proving reuse, not a hand-rolled label writer).
        let mut expected_names = Vec::new();
        for domain in domains {
            expected_names.extend_from_slice(
                &DnsName::parse(domain)
                    .unwrap()
                    .encode_uncompressed()
                    .unwrap(),
            );
        }
        // value = Reserved(2) + Lifetime(4) + the concatenated encoded names.
        assert_eq!(
            &opt.value()[NDP_DNS_RESERVED_LEN + 4..],
            &expected_names[..]
        );

        let bytes = opt.encode().unwrap();
        assert_eq!(bytes[0], NDP_OPT_DNSSL);
        // The encoded option is a whole number of 8-octet units (RFC 8106 sec
        // 5.2: padded to a multiple of 8 octets).
        assert_eq!(bytes.len() % NDP_OPTION_LENGTH_UNIT, 0);
        assert_eq!(bytes.len(), bytes[1] as usize * NDP_OPTION_LENGTH_UNIT);
        // Reserved field sent zero, then the Lifetime.
        assert_eq!(&bytes[2..4], &[0, 0]);
        assert_eq!(&bytes[4..8], &86_400u32.to_be_bytes());

        // Two 13-byte names (1+7 "example" + 1+3 "com"/"net" + root) = 26 bytes;
        // with the 8-byte head the value is 34 bytes, which pads to 40 (5 units),
        // so the last 6 octets are zero padding (RFC 8106 sec 5.2).
        let names_len = expected_names.len();
        assert_eq!(names_len, 26);
        let padding = &bytes[8 + names_len..];
        assert!(
            !padding.is_empty(),
            "the value is padded to the 8-octet boundary"
        );
        assert!(
            padding.iter().all(|&b| b == 0),
            "RFC 8106 sec 5.2 pads with zero octets, got {padding:?}"
        );

        let (decoded, consumed) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.dnssl_lifetime(), Some(86_400));
        // The zero padding decodes as the end of the search list, not extra
        // empty domains.
        assert_eq!(
            decoded.dnssl_domains(),
            Some(vec!["example.com.".to_string(), "example.net.".to_string()])
        );
        // Re-encode reproduces the original bytes exactly (padding included).
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    // A single DNSSL domain still round-trips, and a subdomain label set encodes
    // and decodes through the reused RFC 1035 codec.
    #[test]
    fn dnssl_single_and_subdomain_round_trip() {
        let opt = NdpOption::dnssl(0, &["lab.example.org"]);
        // A zero lifetime (RFC 8106 sec 5.2: "MUST no longer be used") round-trips.
        assert_eq!(opt.dnssl_lifetime(), Some(0));
        let bytes = opt.encode().unwrap();
        let (decoded, _) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(
            decoded.dnssl_domains(),
            Some(vec!["lab.example.org.".to_string()])
        );
    }

    // A deliberately-wrong explicit length on a typed RDNSS / DNSSL option
    // survives encode untouched (honored overrides) — the same rule as the other
    // typed options.
    #[test]
    fn dns_option_explicit_wrong_length_is_preserved() {
        let server = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        // An RDNSS option's real length is 3 units; pin it to 7 (an out-of-spec
        // value). The encoder must emit length=7 untouched and pad to 56 bytes.
        let wrong = NdpOption::rdnss(1800, &[server]).length(7);
        assert_eq!(wrong.explicit_length(), Some(7));
        let bytes = wrong.encode().unwrap();
        assert_eq!(bytes[1], 7, "pinned length survives untouched");
        assert_eq!(bytes.len(), 56, "pinned length drives the encoded size");
        // The real address bytes are still present; clearing the override returns
        // to auto-fill (3 units).
        assert_eq!(&bytes[8..24], &server.octets());
        assert_eq!(wrong.clear_length().effective_length().unwrap(), 3);

        // Likewise a DNSSL option pinned to a wrong length emits it verbatim.
        let dnssl_wrong = NdpOption::dnssl(60, &["example.com"]).length(1);
        let dnssl_bytes = dnssl_wrong.encode().unwrap();
        assert_eq!(dnssl_bytes[1], 1);
        assert_eq!(dnssl_bytes.len(), 8);
    }

    // The DNSSL accessors reject other option types (no false reads).
    #[test]
    fn dnssl_accessors_reject_other_options() {
        let mtu = NdpOption::mtu(1500);
        assert_eq!(mtu.dnssl_lifetime(), None);
        assert_eq!(mtu.dnssl_domains(), None);
    }

    // RFC 5175 sec 4: an RA Flags Extension option (type 26) carries a 6-octet
    // (48-bit) Bit Fields area extending the RA flags; it occupies one 8-octet
    // unit (length 1 / 8 bytes) and the bits read back through the typed accessor
    // after a full encode/decode round-trip.
    #[test]
    fn ra_flags_extension_round_trips() {
        let bits = [0x80u8, 0x01, 0x02, 0x03, 0x04, 0x05];
        let opt = NdpOption::ra_flags_extension(bits);
        assert_eq!(opt.option_type(), NDP_OPT_RA_FLAGS_EXTENSION);
        assert!(opt.is_known());
        assert_eq!(opt.ra_flags_extension_bits(), Some(bits));

        let bytes = opt.encode().unwrap();
        // type(1) + length(1) + 6 Bit Fields octets = 8 bytes = one 8-octet unit.
        assert_eq!(bytes.len(), NDP_RA_FLAGS_EXTENSION_LEN);
        assert_eq!(
            &bytes[0..2],
            &[NDP_OPT_RA_FLAGS_EXTENSION, NDP_RA_FLAGS_EXTENSION_UNITS]
        );
        assert_eq!(&bytes[2..8], &bits);

        let (decoded, consumed) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(consumed, NDP_RA_FLAGS_EXTENSION_LEN);
        assert_eq!(decoded.option_type(), NDP_OPT_RA_FLAGS_EXTENSION);
        assert_eq!(decoded.ra_flags_extension_bits(), Some(bits));
        // Re-encode reproduces the original bytes exactly.
        assert_eq!(decoded.encode().unwrap(), bytes);
        // The accessor rejects other option types.
        assert_eq!(NdpOption::mtu(1500).ra_flags_extension_bits(), None);
    }

    // RFC 3971 sec 5.3.2: a Nonce option (type 14) carries a variable-width
    // random nonce after the Type/Length header; the framework auto-fills the
    // option Length and zero-pads the value to the 8-octet boundary. With a
    // 6-byte nonce the option is exactly one 8-octet unit and the value reads
    // back through the typed accessor.
    #[test]
    fn nonce_round_trips() {
        // A 6-byte nonce (RFC 3971 sec 5.3.2 minimum) fills exactly one unit.
        let nonce = [0xa1u8, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6];
        let opt = NdpOption::nonce(&nonce);
        assert_eq!(opt.option_type(), NDP_OPT_NONCE);
        assert!(opt.is_known());
        assert_eq!(opt.nonce_value(), Some(&nonce[..]));

        let bytes = opt.encode().unwrap();
        // type(1) + length(1) + 6-byte nonce = 8 bytes = one 8-octet unit.
        assert_eq!(bytes.len(), 8);
        assert_eq!(&bytes[0..2], &[NDP_OPT_NONCE, 1]);
        assert_eq!(&bytes[2..8], &nonce);

        let (decoded, consumed) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(decoded.nonce_value(), Some(&nonce[..]));
        // Re-encode reproduces the original bytes exactly.
        assert_eq!(decoded.encode().unwrap(), bytes);
        // The accessor rejects other option types.
        assert_eq!(NdpOption::mtu(1500).nonce_value(), None);
    }

    // RFC 3971 sec 5.3.2: a nonce whose length is not a multiple of 8 (minus the
    // 2-byte header) is zero-padded by the framework to the next 8-octet boundary;
    // because the RFC records no separate nonce length, the decoded accessor
    // returns the whole value area including that padding.
    #[test]
    fn nonce_padding_extends_the_value_area() {
        // An 8-byte nonce: header(2) + 8 = 10 bytes rounds up to 16 (two units),
        // padding the value with 6 zero octets.
        let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let opt = NdpOption::nonce(&nonce);
        let bytes = opt.encode().unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[1], 2);
        assert_eq!(&bytes[2..10], &nonce);
        assert_eq!(&bytes[10..16], &[0; 6]);

        let (decoded, _) = NdpOption::decode_one(&bytes).unwrap();
        // The decoded value area is the nonce plus the 6 padding octets (RFC 3971
        // records no separate nonce length, so padding is indistinguishable).
        assert_eq!(
            decoded.nonce_value(),
            Some(&[1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0][..])
        );
    }

    // RFC 8781 sec 4: the PLC (Prefix Length Code) maps each 3-bit code to a
    // NAT64 prefix length and round-trips; reserved codes (6, 7) are preserved.
    #[test]
    fn pref64_plc_round_trips() {
        // RFC 8781 sec 4: 0->96, 1->64, 2->56, 3->48, 4->40, 5->32.
        let assigned = [(0u8, 96u8), (1, 64), (2, 56), (3, 48), (4, 40), (5, 32)];
        for (code, bits) in assigned {
            let plc = Pref64Plc::from_plc(code);
            assert_eq!(plc, Pref64Plc::PrefixLength(bits));
            assert_eq!(plc.prefix_length_bits(), Some(bits));
            assert_eq!(plc.to_plc(), Some(code));
            assert_eq!(
                Pref64Plc::from_prefix_length_bits(bits).to_plc(),
                Some(code)
            );
        }
        // Reserved codes 6 and 7 are preserved verbatim and map to no length.
        for code in [6u8, 7] {
            let plc = Pref64Plc::from_plc(code);
            assert_eq!(plc, Pref64Plc::Reserved(code));
            assert_eq!(plc.prefix_length_bits(), None);
            assert_eq!(plc.to_plc(), Some(code));
        }
        // A prefix length that is not one of the six assigned values has no code.
        assert_eq!(Pref64Plc::from_prefix_length_bits(80).to_plc(), None);
    }

    // RFC 8781 sec 4: a PREF64 option (type 38) carries a 13-bit Scaled Lifetime,
    // a 3-bit PLC, and the high 96 bits of a NAT64 prefix; it occupies two
    // 8-octet units (length 2 / 16 bytes) and every field reads back through the
    // typed accessors after a full encode/decode round-trip.
    #[test]
    fn pref64_round_trips() {
        // The well-known NAT64 prefix 64:ff9b::/96 (RFC 6052), expressed in the
        // documentation-safe form here as its high 96 bits.
        let prefix = Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0);
        // Scaled Lifetime 600 (units of 8 s = 4800 s), PLC for /96.
        let opt = NdpOption::pref64(600, 96, prefix).unwrap();
        assert_eq!(opt.option_type(), NDP_OPT_PREF64);
        assert!(opt.is_known());
        assert_eq!(opt.pref64_scaled_lifetime(), Some(600));
        assert_eq!(opt.pref64_plc(), Some(Pref64Plc::PrefixLength(96)));
        assert_eq!(opt.pref64_prefix_length(), Some(96));
        assert_eq!(opt.pref64_prefix(), Some(prefix));

        let bytes = opt.encode().unwrap();
        // type(1) + length(1) + 2-byte word + 12-byte prefix = 16 bytes = two units.
        assert_eq!(bytes.len(), NDP_PREF64_LEN);
        assert_eq!(&bytes[0..2], &[NDP_OPT_PREF64, NDP_PREF64_UNITS]);
        // The 16-bit word is Scaled Lifetime(13)<<3 | PLC(3): 600<<3 | 0 = 4800.
        assert_eq!(&bytes[2..4], &(600u16 << 3).to_be_bytes());
        // The high 96 bits of the prefix, then nothing (option is exactly 16 B).
        assert_eq!(&bytes[4..16], &prefix.octets()[..NDP_PREF64_PREFIX_LEN]);

        let (decoded, consumed) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(consumed, NDP_PREF64_LEN);
        assert_eq!(decoded.pref64_scaled_lifetime(), Some(600));
        assert_eq!(decoded.pref64_prefix_length(), Some(96));
        assert_eq!(decoded.pref64_prefix(), Some(prefix));
        // Re-encode reproduces the original bytes exactly.
        assert_eq!(decoded.encode().unwrap(), bytes);

        // Every assigned prefix length round-trips its PLC.
        for bits in [96u8, 64, 56, 48, 40, 32] {
            let o = NdpOption::pref64(0, bits, prefix).unwrap();
            let (d, _) = NdpOption::decode_one(&o.encode().unwrap()).unwrap();
            assert_eq!(d.pref64_prefix_length(), Some(bits), "PLC for /{bits}");
        }
    }

    // RFC 8781 sec 4: pref64() rejects a prefix length that is not one of the six
    // assigned NAT64 lengths, but pref64_raw() can emit a reserved PLC on purpose
    // (honored overrides), which decodes back to a reserved code with no length.
    #[test]
    fn pref64_rejects_bad_length_but_raw_allows_reserved_plc() {
        let prefix = Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0);
        // /80 is not an assigned NAT64 prefix length.
        assert!(NdpOption::pref64(600, 80, prefix).is_err());

        // The raw constructor emits a reserved PLC (7) verbatim.
        let opt = NdpOption::pref64_raw(600, 7, prefix);
        let bytes = opt.encode().unwrap();
        assert_eq!(bytes[1], NDP_PREF64_UNITS);
        // Low three bits of the word are the reserved PLC code 7.
        let word = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert_eq!(word & NDP_PREF64_PLC_MASK, 7);
        assert_eq!(word >> NDP_PREF64_SCALED_LIFETIME_SHIFT, 600);

        let (decoded, _) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(decoded.pref64_plc(), Some(Pref64Plc::Reserved(7)));
        // A reserved PLC maps to no assigned prefix length.
        assert_eq!(decoded.pref64_prefix_length(), None);
        assert_eq!(decoded.pref64_scaled_lifetime(), Some(600));
        // The accessors reject other option types.
        assert_eq!(NdpOption::mtu(1500).pref64_scaled_lifetime(), None);
        assert_eq!(NdpOption::mtu(1500).pref64_plc(), None);
        assert_eq!(NdpOption::mtu(1500).pref64_prefix(), None);
    }

    // RFC 8910 sec 2.3: a Captive Portal option (type 37) carries a UTF-8 URI
    // NUL-padded to the 8-octet boundary; the option Length auto-fills, the URI
    // reads back through the typed accessor with the padding stripped, and a
    // documentation URI round-trips.
    #[test]
    fn captive_portal_round_trips_and_strips_padding() {
        // RFC 2606 reserves example.com for documentation.
        let uri = "https://example.com/captive-portal/api";
        let opt = NdpOption::captive_portal(uri);
        assert_eq!(opt.option_type(), NDP_OPT_CAPTIVE_PORTAL);
        assert!(opt.is_known());
        assert_eq!(opt.captive_portal_uri().as_deref(), Some(uri));

        let bytes = opt.encode().unwrap();
        assert_eq!(bytes[0], NDP_OPT_CAPTIVE_PORTAL);
        // The encoded option is a whole number of 8-octet units (RFC 8910 sec
        // 2.3: padded to a multiple of 8 bytes).
        assert_eq!(bytes.len() % NDP_OPTION_LENGTH_UNIT, 0);
        assert_eq!(bytes.len(), bytes[1] as usize * NDP_OPTION_LENGTH_UNIT);
        // The URI bytes sit right after the Type/Length header.
        assert_eq!(&bytes[2..2 + uri.len()], uri.as_bytes());
        // Everything after the URI is NUL padding (RFC 8910 sec 2.3).
        let padding = &bytes[2 + uri.len()..];
        assert!(
            padding.iter().all(|&b| b == 0),
            "RFC 8910 sec 2.3 pads with NUL, got {padding:?}"
        );

        let (decoded, consumed) = NdpOption::decode_one(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        // The accessor strips the trailing NUL padding to recover the URI.
        assert_eq!(decoded.captive_portal_uri().as_deref(), Some(uri));
        // Re-encode reproduces the original bytes exactly (padding included).
        assert_eq!(decoded.encode().unwrap(), bytes);
        // The accessor rejects other option types.
        assert_eq!(NdpOption::mtu(1500).captive_portal_uri(), None);
    }

    // A URI that exactly fills the 8-octet boundary needs no padding, and a short
    // URI strips back to itself.
    #[test]
    fn captive_portal_boundary_and_short_uri() {
        // 6-byte URI value: header(2) + 6 = 8 bytes = one unit, no padding.
        let exact = NdpOption::captive_portal("ftp://");
        let exact_bytes = exact.encode().unwrap();
        assert_eq!(exact_bytes.len(), 8);
        assert_eq!(exact_bytes[1], 1);
        let (d, _) = NdpOption::decode_one(&exact_bytes).unwrap();
        assert_eq!(d.captive_portal_uri().as_deref(), Some("ftp://"));

        // A very short URI still round-trips through the padding.
        let short = NdpOption::captive_portal("a");
        let (d2, _) = NdpOption::decode_one(&short.encode().unwrap()).unwrap();
        assert_eq!(d2.captive_portal_uri().as_deref(), Some("a"));
    }

    // SEND certificate options (CGA/RSA/cert) are out of scope; an unrecognized
    // SEND option type (e.g. CGA, type 11) is preserved verbatim as an
    // UnknownNdpOption through an NDP option-area round-trip, alongside the
    // recognized options.
    #[test]
    fn unrecognized_send_option_is_preserved_as_unknown() {
        // RFC 3971 assigns CGA = type 11; `crafter` does not model it, so it must
        // be preserved verbatim. Build it as an unknown option with arbitrary
        // (documentation) value bytes.
        const NDP_OPT_CGA: u8 = 11;
        assert!(!ndp_option_type_is_known(NDP_OPT_CGA));
        let cga_bytes = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
        let cga = NdpOption::unknown(NDP_OPT_CGA, cga_bytes);

        // Sandwich the unknown SEND option between two recognized options so the
        // walk must keep decoding past it.
        let nonce = NdpOption::nonce(&[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]);
        let portal = NdpOption::captive_portal("https://example.com/cp");
        let options = NdpOptions::new()
            .push(nonce.clone())
            .push(cga.clone())
            .push(portal.clone());

        let encoded = options.encode().unwrap();
        let decoded = NdpOptions::decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 3);

        // Order preserved; the SEND option is the middle one.
        assert_eq!(decoded.options()[0].option_type(), NDP_OPT_NONCE);
        assert_eq!(decoded.options()[2].option_type(), NDP_OPT_CAPTIVE_PORTAL);

        // The CGA option round-trips verbatim as an Unknown variant.
        let mid = &decoded.options()[1];
        assert_eq!(mid.option_type(), NDP_OPT_CGA);
        assert!(!mid.is_known());
        match mid {
            NdpOption::Unknown { bytes, .. } => {
                // Value preserved exactly (padded to the 8-octet boundary).
                assert_eq!(bytes, &cga_bytes);
            }
            other => panic!("expected Unknown SEND option, got {other:?}"),
        }
        // The other options still decode correctly past the unknown one.
        assert_eq!(
            decoded.options()[2].captive_portal_uri().as_deref(),
            Some("https://example.com/cp")
        );
        // Re-encode reproduces the original bytes exactly.
        assert_eq!(decoded.encode().unwrap(), encoded);
    }

    // A deliberately-wrong explicit length on one of the new typed options
    // survives encode untouched (honored overrides) — the same rule as the other
    // typed options.
    #[test]
    fn new_option_explicit_wrong_length_is_preserved() {
        let prefix = Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0);
        // A PREF64 option's real length is 2 units; pin it to 4 (out of spec).
        let wrong = NdpOption::pref64(600, 96, prefix).unwrap().length(4);
        assert_eq!(wrong.explicit_length(), Some(4));
        let bytes = wrong.encode().unwrap();
        assert_eq!(bytes[1], 4, "pinned length survives untouched");
        assert_eq!(bytes.len(), 32, "pinned length drives the encoded size");
        assert_eq!(wrong.clear_length().effective_length().unwrap(), 2);

        // Likewise an RA Flags Extension option pinned to a wrong length.
        let raext = NdpOption::ra_flags_extension([0; 6]).length(3);
        let raext_bytes = raext.encode().unwrap();
        assert_eq!(raext_bytes[1], 3);
        assert_eq!(raext_bytes.len(), 24);
    }
}
