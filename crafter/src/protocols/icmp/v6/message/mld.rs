//! Multicast Listener Discovery, version 1 (MLDv1, RFC 2710, types 130-132).
//!
//! MLDv1 is how IPv6 hosts report their multicast group memberships to
//! neighboring routers; it is the IPv6 analogue of IGMP and the multicast
//! counterpart to the unicast Neighbor Discovery work in [`ndp`](super::ndp). It
//! rides the same `Icmpv6` typed-body model: an [`Icmpv6`] header (type / code /
//! checksum / four-byte rest-of-header) followed by a message-specific body
//! carried as a trailing [`Layer`] that composes with `/`, exactly the way the
//! NDP messages and the ICMPv4 timestamp / address-mask bodies do.
//!
//! ## Wire layout (RFC 2710 section 3, grounded against the authoritative RFC)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |     Code      |          Checksum             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Maximum Response Delay     |          Reserved            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                                                               +
//! |                                                               |
//! +                       Multicast Address                       +
//! |                                                               |
//! +                                                               +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! - **Type** (RFC 2710 section 3.1): 130 Multicast Listener Query, 131 Multicast
//!   Listener Report, 132 Multicast Listener Done. A single body type
//!   ([`MulticastListenerMessage`]) is reused across all three — the `type` byte
//!   on the [`Icmpv6`] header distinguishes the message.
//! - **Code** (section 3.2): "Initialized to zero by the sender; ignored by
//!   receivers." All three builders send code 0.
//! - **Maximum Response Delay** (section 3.3): a 16-bit value in milliseconds. It
//!   is "meaningful only in Query messages, and specifies the maximum allowed
//!   delay before a responding Report ...  In all other messages, it is set to
//!   zero by the sender and ignored by receivers."
//! - **Reserved** (section 3.4): a 16-bit field "initialized to zero by the
//!   sender; ignored by receivers."
//! - **Multicast Address** (section 3.5): a 128-bit IPv6 multicast address. "In a
//!   Query message, [it] is set to zero when sending a General Query, and set to a
//!   specific IPv6 multicast address when sending a Multicast-Address-Specific
//!   Query. In a Report or Done message, [it] holds a specific IPv6 multicast
//!   address to which the message sender is listening or is ceasing to listen,
//!   respectively."
//!
//! Following the established `Icmpv6` typed-body pattern, the first two 16-bit
//! fields — Maximum Response Delay and Reserved — are the [`Icmpv6`] header's
//! four-byte rest-of-header (bytes 4..8 of the ICMPv6 header), set on the header
//! by the builders (mirroring how the NDP messages keep their Reserved / flags
//! word on the header and how ICMPv4 keeps its rest-of-header fields there). The
//! trailing [`MulticastListenerMessage`] body owns exactly the part after the
//! fixed 8-byte header: the 16-byte Multicast Address. The header auto-fills the
//! ICMPv6 checksum over the IPv6 pseudo-header, covering this body's bytes — no
//! new checksum code is needed.
//!
//! ## Hop-by-Hop Router Alert and link-local source (RFC 2710 section 3)
//!
//! RFC 2710 section 3 requires that "all MLD messages described in this document
//! are sent with a link-local IPv6 Source Address, an IPv6 Hop Limit of 1, and an
//! IPv6 Router Alert option ([RFC 2711]) in a Hop-by-Hop Options header." A
//! General Query is additionally sent to the link-scope all-nodes multicast
//! address `ff02::1`. These builders produce only the ICMPv6 *message body*;
//! composing the enclosing IPv6 packet — a link-local source on the
//! [`Ipv6`](crate::Ipv6) layer, a Hop Limit of 1, and the Hop-by-Hop Options
//! header carrying the Router Alert option (next-header
//! [`IpProtocol::HopByHop`](crate::IpProtocol::HopByHop), RFC 2711) — is the
//! caller's responsibility, the same separation of concerns the NDP builders use
//! (they leave the solicited-node multicast destination and link-local source to
//! the caller). The crate's IPv6 extension-header builders compose ahead of the
//! ICMPv6 header with `/` for that purpose.

use super::super::*;
use core::net::Ipv6Addr;

/// Width, in octets, of the Multicast Address that makes up an MLDv1 message body
/// (RFC 2710 section 3.5: a 128-bit IPv6 multicast address).
const MLD_MULTICAST_ADDRESS_LEN: usize = 16;

/// MLDv1 message body (RFC 2710 section 3): the 128-bit Multicast Address that
/// follows the fixed 8-byte ICMPv6 header.
///
/// On the wire an MLDv1 message is ICMPv6 `type` 130 (Query), 131 (Report), or
/// 132 (Done), `code` 0, a 16-bit Maximum Response Delay, a 16-bit Reserved
/// field, then the 128-bit Multicast Address. A single body type is reused across
/// all three message types — the `type` byte on the [`Icmpv6`] header
/// distinguishes the message — exactly as the wire format itself shares one
/// layout across Query / Report / Done.
///
/// Following the `Icmpv6` typed-body pattern, the Maximum Response Delay and
/// Reserved fields are the [`Icmpv6`] header's four-byte rest-of-header (set on
/// the header — not in this body — by [`Icmpv6::mld_query`] /
/// [`Icmpv6::mld_report`] / [`Icmpv6::mld_done`]) so the split matches the wire
/// layout and the way the NDP messages keep their rest-of-header fields on the
/// header. This body carries exactly the part after the fixed 8-byte header: the
/// 16-byte Multicast Address. The header auto-fills the ICMPv6 checksum over the
/// IPv6 pseudo-header, covering this body's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MulticastListenerMessage {
    // `pub(crate)` so the ICMPv6 decode path in `icmp/v6/mod.rs` can construct the
    // body from wire bytes; the public surface is the builder/accessors below.
    pub(crate) multicast_address: Ipv6Addr,
}

impl MulticastListenerMessage {
    /// Create an MLDv1 message body carrying `multicast_address` (RFC 2710 section
    /// 3.5).
    ///
    /// Use [`Ipv6Addr::UNSPECIFIED`] (`::`) for a General Query, or the group
    /// address for a Multicast-Address-Specific Query, a Report, or a Done.
    /// Compose this body under an [`Icmpv6`] header (type 130 / 131 / 132, code 0)
    /// — or, more simply, use [`Icmpv6::mld_query`], [`Icmpv6::mld_report`], or
    /// [`Icmpv6::mld_done`], which set the header type/code and rest-of-header for
    /// you.
    pub fn new(multicast_address: Ipv6Addr) -> Self {
        Self { multicast_address }
    }

    /// Set the Multicast Address (RFC 2710 section 3.5).
    pub fn multicast_address(mut self, multicast_address: Ipv6Addr) -> Self {
        self.multicast_address = multicast_address;
        self
    }

    /// The Multicast Address field (RFC 2710 section 3.5).
    pub fn multicast_address_value(&self) -> Ipv6Addr {
        self.multicast_address
    }
}

impl Layer for MulticastListenerMessage {
    fn name(&self) -> &'static str {
        "MulticastListenerMessage"
    }

    fn summary(&self) -> String {
        format!(
            "MulticastListenerMessage(multicast={})",
            self.multicast_address
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![("multicast_address", self.multicast_address.to_string())]
    }

    fn encoded_len(&self) -> usize {
        MLD_MULTICAST_ADDRESS_LEN
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.multicast_address.octets());
        Ok(())
    }

    impl_layer_object!(MulticastListenerMessage);
}

impl_layer_div!(MulticastListenerMessage);

/// Pack the MLDv1 rest-of-header (RFC 2710 section 3): the 16-bit Maximum
/// Response Delay (big-endian, milliseconds) followed by the 16-bit Reserved
/// field, which is sent as zero.
fn mld_rest_of_header(max_response_delay: u16) -> [u8; 4] {
    let delay = max_response_delay.to_be_bytes();
    // RFC 2710 section 3.4: Reserved is sent as zero.
    [delay[0], delay[1], 0, 0]
}

impl Icmpv6 {
    /// Build an MLDv1 Multicast Listener Query packet (RFC 2710 section 3,
    /// type 130, code 0).
    ///
    /// `multicast_address` selects the query form (RFC 2710 section 3.5): pass
    /// [`Ipv6Addr::UNSPECIFIED`] (`::`) for a **General Query** — which RFC 2710
    /// sends to the link-scope all-nodes multicast address `ff02::1` — or a
    /// specific group address for a **Multicast-Address-Specific Query**.
    /// `max_response_delay` is the Maximum Response Delay in milliseconds
    /// (RFC 2710 section 3.3): the maximum delay a responding host may insert
    /// before its Report. It is meaningful only on a Query, so the Report / Done
    /// builders always send zero.
    ///
    /// Returns a [`Packet`] composing the [`Icmpv6`] header (type 130, code 0,
    /// the rest-of-header set to the Maximum Response Delay and a zero Reserved
    /// field) with a [`MulticastListenerMessage`] body carrying the Multicast
    /// Address. `compile()` auto-fills the ICMPv6 checksum over the IPv6
    /// pseudo-header.
    ///
    /// RFC 2710 section 3 requires MLD messages to be sent with a link-local IPv6
    /// source, a Hop Limit of 1, and an IPv6 Router Alert option (RFC 2711) in a
    /// Hop-by-Hop Options header. This builder produces only the ICMPv6 message
    /// body; set the link-local source / Hop Limit on the enclosing
    /// [`Ipv6`](crate::Ipv6) layer and compose the Hop-by-Hop Options header
    /// (next-header [`IpProtocol::HopByHop`](crate::IpProtocol::HopByHop))
    /// carrying the Router Alert option ahead of the ICMPv6 header with `/`.
    pub fn mld_query(multicast_address: Ipv6Addr, max_response_delay: u16) -> Packet {
        Self::mld_message(
            ICMPV6_MULTICAST_LISTENER_QUERY,
            max_response_delay,
            MulticastListenerMessage::new(multicast_address),
        )
    }

    /// Build an MLDv1 General Query packet (RFC 2710 section 3, type 130, code 0).
    ///
    /// A General Query carries a Multicast Address of `::`
    /// ([`Ipv6Addr::UNSPECIFIED`], RFC 2710 section 3.5) and is sent to the
    /// link-scope all-nodes multicast address `ff02::1`; it asks every host on the
    /// link to report all of its multicast group memberships. This is
    /// [`Icmpv6::mld_query`] with the unspecified address. `max_response_delay` is
    /// the Maximum Response Delay in milliseconds (RFC 2710 section 3.3). The same
    /// Hop-by-Hop Router Alert / link-local source requirement noted on
    /// [`Icmpv6::mld_query`] applies, and the `ff02::1` destination is set on the
    /// enclosing [`Ipv6`](crate::Ipv6) layer.
    pub fn mld_general_query(max_response_delay: u16) -> Packet {
        Self::mld_query(Ipv6Addr::UNSPECIFIED, max_response_delay)
    }

    /// Build an MLDv1 Multicast Listener Report packet (RFC 2710 section 3,
    /// type 131, code 0).
    ///
    /// A Report announces that the sender is listening to the multicast group
    /// `group` (RFC 2710 section 3.5). The Maximum Response Delay is meaningful
    /// only on a Query, so it is sent as zero here (RFC 2710 section 3.3).
    ///
    /// Returns a [`Packet`] composing the [`Icmpv6`] header (type 131, code 0, the
    /// rest-of-header zero) with a [`MulticastListenerMessage`] body carrying
    /// `group`. The same Hop-by-Hop Router Alert / link-local source requirement
    /// noted on [`Icmpv6::mld_query`] applies; `compile()` auto-fills the ICMPv6
    /// checksum over the IPv6 pseudo-header.
    pub fn mld_report(group: Ipv6Addr) -> Packet {
        Self::mld_message(
            ICMPV6_MULTICAST_LISTENER_REPORT,
            0,
            MulticastListenerMessage::new(group),
        )
    }

    /// Build an MLDv1 Multicast Listener Done packet (RFC 2710 section 3,
    /// type 132, code 0).
    ///
    /// A Done announces that the sender is ceasing to listen to the multicast
    /// group `group` (RFC 2710 section 3.5) — the multicast analogue of an IGMP
    /// Leave. The Maximum Response Delay is meaningful only on a Query, so it is
    /// sent as zero here (RFC 2710 section 3.3).
    ///
    /// Returns a [`Packet`] composing the [`Icmpv6`] header (type 132, code 0, the
    /// rest-of-header zero) with a [`MulticastListenerMessage`] body carrying
    /// `group`. The same Hop-by-Hop Router Alert / link-local source requirement
    /// noted on [`Icmpv6::mld_query`] applies; `compile()` auto-fills the ICMPv6
    /// checksum over the IPv6 pseudo-header.
    pub fn mld_done(group: Ipv6Addr) -> Packet {
        Self::mld_message(
            ICMPV6_MULTICAST_LISTENER_DONE,
            0,
            MulticastListenerMessage::new(group),
        )
    }

    /// Compose an MLDv1 header (the given `icmp_type`, code 0, rest-of-header =
    /// Maximum Response Delay + zero Reserved) with a caller-built
    /// [`MulticastListenerMessage`] body.
    fn mld_message(
        icmp_type: u8,
        max_response_delay: u16,
        body: MulticastListenerMessage,
    ) -> Packet {
        Self::new()
            .icmp_type(icmp_type)
            .code(0)
            .rest_of_header(mld_rest_of_header(max_response_delay))
            / body
    }
}

/// Decode the body of an MLDv1 message: the 128-bit Multicast Address (RFC 2710
/// section 3.5) that follows the fixed 8-byte ICMPv6 header. The Maximum Response
/// Delay and Reserved fields live in the header's rest-of-header and are decoded
/// there.
///
/// Returns a structured [`CrafterError`] (never a panic) when the body is not
/// exactly the 16-byte Multicast Address.
///
/// NOTE (step 28 seam): the MLDv1 Query (type 130) shares its `type` byte with
/// the MLDv2 Query (RFC 3810). The two are disambiguated by **body length**: an
/// MLDv1 Query body is exactly the 16-byte Multicast Address, while an MLDv2
/// Query body is longer (it appends a flags/QRV/QQIC byte run, a Number of
/// Sources field, and a source-address list after the Multicast Address). This
/// decoder therefore accepts a type-130 body only when it is *exactly* 16 bytes;
/// the dispatch in `icmp/v6/mod.rs` requires that exact length for the MLDv1
/// classification. Step 28 adds the longer MLDv2-query branch (chosen by the
/// larger body length) ahead of / alongside this one — leaving anything that is
/// neither shape to fall through to a `Raw` tail.
pub(crate) fn decode_multicast_listener_message(bytes: &[u8]) -> Result<MulticastListenerMessage> {
    if bytes.len() != MLD_MULTICAST_ADDRESS_LEN {
        return Err(CrafterError::buffer_too_short(
            "icmpv6.mld.multicast_address",
            MLD_MULTICAST_ADDRESS_LEN,
            bytes.len(),
        ));
    }
    let mut octets = [0u8; MLD_MULTICAST_ADDRESS_LEN];
    octets.copy_from_slice(&bytes[..MLD_MULTICAST_ADDRESS_LEN]);
    Ok(MulticastListenerMessage {
        multicast_address: Ipv6Addr::from(octets),
    })
}

// ===========================================================================
// Multicast Listener Discovery, version 2 (MLDv2, RFC 3810; the IANA registry
// now cites RFC 9777, which obsoletes RFC 3810 — the two share this wire
// format). MLDv2 extends MLDv1 with source-specific multicast: the Query (still
// type 130) grows a flags / QRV / QQIC run and a source-address list, and a new
// Version 2 Report (type 143) carries one or more Multicast Address Records.
// ===========================================================================

/// Width, in octets, of an IPv6 address as it appears in an MLDv2 message — the
/// Multicast Address and each Source Address (RFC 3810 sections 5.1 and 5.2).
const MLDV2_ADDRESS_LEN: usize = 16;

/// Width, in octets, of the MLDv2 Query fields that precede the Source Address
/// list, *after* the 16-byte Multicast Address (RFC 3810 section 5.1): the
/// Resv/S/QRV byte, the QQIC byte, and the 16-bit Number of Sources field.
const MLDV2_QUERY_FLAGS_LEN: usize = 4;

/// Minimum length, in octets, of an MLDv2 Query body (the part after the fixed
/// 8-byte ICMPv6 header): the 16-byte Multicast Address plus the 4-byte
/// flags/QRV/QQIC/Number-of-Sources run, with no sources (RFC 3810 section 5.1).
/// This is the seam (step 27) that distinguishes the MLDv2 Query (body >= 20
/// bytes) from the MLDv1 Query (body == exactly 16 bytes).
pub const MLDV2_QUERY_MIN_BODY_LEN: usize = MLDV2_ADDRESS_LEN + MLDV2_QUERY_FLAGS_LEN;

/// Bit mask for the S Flag (Suppress Router-Side Processing) in the MLDv2 Query
/// Resv/S/QRV byte (RFC 3810 section 5.1.7: bit 0x08 — the fourth bit from the
/// top, just below the 4-bit Resv field).
pub const MLDV2_QUERY_S_FLAG: u8 = 0x08;

/// Bit mask for the QRV (Querier's Robustness Variable) in the MLDv2 Query
/// Resv/S/QRV byte (RFC 3810 section 5.1.8: the low 3 bits, 0x07).
pub const MLDV2_QUERY_QRV_MASK: u8 = 0x07;

/// Mask of the 4 Resv bits in the MLDv2 Query Resv/S/QRV byte (RFC 3810 section
/// 5.1.6: "set to zero on transmission, and ignored on reception" — the top 4
/// bits, 0xf0). Preserved verbatim through build/decode for forward
/// compatibility and for deliberately malformed packets.
pub const MLDV2_QUERY_RESV_MASK: u8 = 0xf0;

/// Width, in octets, of the fixed part of a Multicast Address Record that
/// precedes the Source Address list and the Auxiliary Data (RFC 3810 section
/// 5.2): Record Type (1) + Aux Data Len (1) + Number of Sources (2) + Multicast
/// Address (16).
const MLDV2_RECORD_FIXED_LEN: usize = 1 + 1 + 2 + MLDV2_ADDRESS_LEN;

/// Width, in octets, of the unit the Aux Data Len field counts (RFC 3810 section
/// 5.2.2: "the length of the Auxiliary Data field ... in units of 32-bit
/// words").
const MLDV2_AUX_DATA_UNIT: usize = 4;

/// Multicast Address Record Type values (RFC 3810 section 5.2.12).
///
/// A record's type tells the router what the source list means: a *current
/// state* record (`MODE_IS_INCLUDE` / `MODE_IS_EXCLUDE`) reports the full
/// filter for a group, a *filter-mode-change* record
/// (`CHANGE_TO_INCLUDE_MODE` / `CHANGE_TO_EXCLUDE_MODE`) announces a switch, and
/// a *source-list-change* record (`ALLOW_NEW_SOURCES` / `BLOCK_OLD_SOURCES`)
/// reports an incremental change to the source list.
///
/// Unrecognized values are preserved verbatim as
/// [`MulticastRecordType::Unknown`] so a record with a future or reserved type
/// still round-trips, matching the crate-wide rule that unknown codepoints are
/// kept rather than rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MulticastRecordType {
    /// MODE_IS_INCLUDE (1): the source list is the complete INCLUDE filter for
    /// the group (the group is being received from exactly these sources).
    ModeIsInclude,
    /// MODE_IS_EXCLUDE (2): the source list is the complete EXCLUDE filter for
    /// the group (the group is being received from all but these sources).
    ModeIsExclude,
    /// CHANGE_TO_INCLUDE_MODE (3): the group's filter changed to INCLUDE with
    /// this source list.
    ChangeToIncludeMode,
    /// CHANGE_TO_EXCLUDE_MODE (4): the group's filter changed to EXCLUDE with
    /// this source list.
    ChangeToExcludeMode,
    /// ALLOW_NEW_SOURCES (5): these sources were added to the group's source
    /// list (now being received).
    AllowNewSources,
    /// BLOCK_OLD_SOURCES (6): these sources were removed from the group's source
    /// list (no longer being received).
    BlockOldSources,
    /// Any Record Type not assigned by RFC 3810 section 5.2.12, preserved
    /// verbatim so the record round-trips unchanged.
    Unknown(u8),
}

impl MulticastRecordType {
    /// The on-wire Record Type byte (RFC 3810 section 5.2.12).
    pub fn to_u8(self) -> u8 {
        match self {
            MulticastRecordType::ModeIsInclude => 1,
            MulticastRecordType::ModeIsExclude => 2,
            MulticastRecordType::ChangeToIncludeMode => 3,
            MulticastRecordType::ChangeToExcludeMode => 4,
            MulticastRecordType::AllowNewSources => 5,
            MulticastRecordType::BlockOldSources => 6,
            MulticastRecordType::Unknown(value) => value,
        }
    }

    /// Classify a Record Type byte, preserving unknown values verbatim (RFC 3810
    /// section 5.2.12).
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => MulticastRecordType::ModeIsInclude,
            2 => MulticastRecordType::ModeIsExclude,
            3 => MulticastRecordType::ChangeToIncludeMode,
            4 => MulticastRecordType::ChangeToExcludeMode,
            5 => MulticastRecordType::AllowNewSources,
            6 => MulticastRecordType::BlockOldSources,
            other => MulticastRecordType::Unknown(other),
        }
    }
}

impl core::fmt::Display for MulticastRecordType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            MulticastRecordType::ModeIsInclude => "MODE_IS_INCLUDE",
            MulticastRecordType::ModeIsExclude => "MODE_IS_EXCLUDE",
            MulticastRecordType::ChangeToIncludeMode => "CHANGE_TO_INCLUDE_MODE",
            MulticastRecordType::ChangeToExcludeMode => "CHANGE_TO_EXCLUDE_MODE",
            MulticastRecordType::AllowNewSources => "ALLOW_NEW_SOURCES",
            MulticastRecordType::BlockOldSources => "BLOCK_OLD_SOURCES",
            MulticastRecordType::Unknown(value) => return write!(f, "Unknown({value})"),
        };
        f.write_str(name)
    }
}

/// One Multicast Address Record inside an MLDv2 Report (RFC 3810 section 5.2.1).
///
/// On the wire a record is a Record Type (1 byte), an Aux Data Len (1 byte, in
/// 32-bit words), a Number of Sources `N` (2 bytes), a 128-bit Multicast
/// Address, `N` 128-bit Source Addresses, and then `Aux Data Len * 4` bytes of
/// Auxiliary Data. The Aux Data Len and Number of Sources count fields are
/// **auto-filled** from the carried data on serialization — set the
/// `multicast_address`, `sources`, and `aux_data` and the counts follow — so an
/// agent never hand-counts. (The crate-wide convention is that explicit values
/// the agent sets survive untouched; these two are derived counters with no
/// dedicated setter, so they always reflect the data. Build a deliberately wrong
/// count by emitting the record bytes directly through a [`Raw`] body.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastAddressRecord {
    record_type: MulticastRecordType,
    multicast_address: Ipv6Addr,
    sources: Vec<Ipv6Addr>,
    aux_data: Vec<u8>,
}

impl MulticastAddressRecord {
    /// Create a Multicast Address Record of `record_type` for `multicast_address`
    /// with no sources and no auxiliary data (RFC 3810 section 5.2.1).
    ///
    /// Add sources with [`MulticastAddressRecord::source`] /
    /// [`MulticastAddressRecord::sources`] and auxiliary data with
    /// [`MulticastAddressRecord::aux_data`]; the Number of Sources and Aux Data
    /// Len fields are filled from those on serialization.
    pub fn new(record_type: MulticastRecordType, multicast_address: Ipv6Addr) -> Self {
        Self {
            record_type,
            multicast_address,
            sources: Vec::new(),
            aux_data: Vec::new(),
        }
    }

    /// Set the Record Type (RFC 3810 section 5.2.12).
    pub fn record_type(mut self, record_type: MulticastRecordType) -> Self {
        self.record_type = record_type;
        self
    }

    /// Set the Multicast Address (RFC 3810 section 5.2.4: the group the record
    /// describes).
    pub fn multicast_address(mut self, multicast_address: Ipv6Addr) -> Self {
        self.multicast_address = multicast_address;
        self
    }

    /// Append one Source Address (RFC 3810 section 5.2.5), preserving order. The
    /// Number of Sources field is filled from the source count on serialization.
    pub fn source(mut self, source: Ipv6Addr) -> Self {
        self.sources.push(source);
        self
    }

    /// Replace the whole ordered Source Address list (RFC 3810 section 5.2.5).
    pub fn sources(mut self, sources: Vec<Ipv6Addr>) -> Self {
        self.sources = sources;
        self
    }

    /// Set the Auxiliary Data (RFC 3810 section 5.2.6). The Aux Data Len field
    /// (in 32-bit words) is filled from the data length on serialization; the
    /// data is zero-padded to a 32-bit-word boundary so a non-multiple-of-4
    /// length still produces a well-formed record.
    pub fn aux_data(mut self, aux_data: impl Into<Vec<u8>>) -> Self {
        self.aux_data = aux_data.into();
        self
    }

    /// The Record Type (RFC 3810 section 5.2.12).
    pub fn record_type_value(&self) -> MulticastRecordType {
        self.record_type
    }

    /// The Multicast Address (RFC 3810 section 5.2.4).
    pub fn multicast_address_value(&self) -> Ipv6Addr {
        self.multicast_address
    }

    /// The Number of Sources field (RFC 3810 section 5.2.3), derived from the
    /// source list.
    pub fn number_of_sources(&self) -> u16 {
        self.sources.len() as u16
    }

    /// The ordered Source Address list (RFC 3810 section 5.2.5).
    pub fn sources_ref(&self) -> &[Ipv6Addr] {
        &self.sources
    }

    /// The Aux Data Len field (RFC 3810 section 5.2.2), in 32-bit words, derived
    /// from the auxiliary-data length (rounded up to a word boundary).
    pub fn aux_data_len(&self) -> u8 {
        mldv2_aux_data_len_words(self.aux_data.len())
    }

    /// The Auxiliary Data (RFC 3810 section 5.2.6).
    pub fn aux_data_value(&self) -> &[u8] {
        &self.aux_data
    }

    /// The Auxiliary Data zero-padded to a 32-bit-word boundary, the way it is
    /// serialized (RFC 3810 section 5.2.2 counts the field in 32-bit words).
    fn aux_data_padded(&self) -> Vec<u8> {
        let words = mldv2_aux_data_len_words(self.aux_data.len()) as usize;
        let mut padded = self.aux_data.clone();
        padded.resize(words * MLDV2_AUX_DATA_UNIT, 0);
        padded
    }

    /// Serialized length, in octets, of this record (fixed fields + sources +
    /// padded auxiliary data).
    fn encoded_len(&self) -> usize {
        MLDV2_RECORD_FIXED_LEN
            + self.sources.len() * MLDV2_ADDRESS_LEN
            + (mldv2_aux_data_len_words(self.aux_data.len()) as usize) * MLDV2_AUX_DATA_UNIT
    }

    /// Append this record's wire bytes to `out` (RFC 3810 section 5.2.1) with the
    /// Aux Data Len and Number of Sources count fields filled from the data.
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.record_type.to_u8());
        out.push(self.aux_data_len());
        out.extend_from_slice(&self.number_of_sources().to_be_bytes());
        out.extend_from_slice(&self.multicast_address.octets());
        for source in &self.sources {
            out.extend_from_slice(&source.octets());
        }
        out.extend_from_slice(&self.aux_data_padded());
    }
}

impl core::fmt::Display for MulticastAddressRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}(group={}, sources={}, aux={}B)",
            self.record_type,
            self.multicast_address,
            self.sources.len(),
            self.aux_data.len()
        )
    }
}

/// The Aux Data Len field (in 32-bit words) for `aux_bytes` octets of auxiliary
/// data, rounded up to a whole word (RFC 3810 section 5.2.2). Saturates at the
/// 8-bit field width so an oversized auxiliary buffer cannot panic.
fn mldv2_aux_data_len_words(aux_bytes: usize) -> u8 {
    let words = aux_bytes.div_ceil(MLDV2_AUX_DATA_UNIT);
    u8::try_from(words).unwrap_or(u8::MAX)
}

/// MLDv2 Version 2 Multicast Listener Report body (RFC 3810 section 5.2, type
/// 143): the ordered list of Multicast Address Records that follows the fixed
/// 8-byte ICMPv6 header.
///
/// On the wire a Report is ICMPv6 `type` 143, `code`/Reserved 0, a 16-bit
/// Reserved field, a 16-bit Nr of Mcast Address Records (M), then M records.
/// Following the established `Icmpv6` typed-body pattern (the NDP and MLDv1
/// messages), the two rest-of-header halves — the 16-bit Reserved field and the
/// 16-bit record count — live on the [`Icmpv6`] header (set by
/// [`Icmpv6::mldv2_report`], with the count **auto-filled** from the number of
/// records). This trailing body owns exactly the part after the fixed 8-byte
/// header: the records themselves. The header auto-fills the ICMPv6 checksum over
/// the IPv6 pseudo-header, covering this body's bytes.
///
/// The same RFC 3810 section 5 Hop-by-Hop Router Alert / link-local source /
/// `ff02::16` destination requirements that apply to MLDv1 apply here and are the
/// caller's responsibility on the enclosing IPv6 packet (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mldv2Report {
    // `pub(crate)` so the ICMPv6 decode path in `icmp/v6/mod.rs` can construct the
    // body from wire bytes; the public surface is the builder/accessors below.
    pub(crate) records: Vec<MulticastAddressRecord>,
}

impl Mldv2Report {
    /// Create an MLDv2 Report body with no records. Compose it under an
    /// [`Icmpv6`] header (type 143, code 0) — or use [`Icmpv6::mldv2_report`],
    /// which sets the header type/code and the Reserved + record-count
    /// rest-of-header for you.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Append one [`MulticastAddressRecord`] (RFC 3810 section 5.2.1), preserving
    /// order. The Nr of Mcast Address Records field on the header is filled from
    /// the record count on serialization.
    pub fn record(mut self, record: MulticastAddressRecord) -> Self {
        self.records.push(record);
        self
    }

    /// Replace the whole ordered record list.
    pub fn records(mut self, records: Vec<MulticastAddressRecord>) -> Self {
        self.records = records;
        self
    }

    /// The Nr of Mcast Address Records (M) field (RFC 3810 section 5.2), derived
    /// from the record list.
    pub fn number_of_records(&self) -> u16 {
        self.records.len() as u16
    }

    /// The ordered Multicast Address Records.
    pub fn records_ref(&self) -> &[MulticastAddressRecord] {
        &self.records
    }
}

impl Default for Mldv2Report {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Mldv2Report {
    fn name(&self) -> &'static str {
        "Mldv2Report"
    }

    fn summary(&self) -> String {
        format!("Mldv2Report(records={})", self.records.len())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![("record_count", self.records.len().to_string())];
        for (index, record) in self.records.iter().enumerate() {
            fields.push((record_field_name(index), record.to_string()));
        }
        fields
    }

    fn encoded_len(&self) -> usize {
        self.records.iter().map(|record| record.encoded_len()).sum()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        for record in &self.records {
            record.encode_into(out);
        }
        Ok(())
    }

    impl_layer_object!(Mldv2Report);
}

impl_layer_div!(Mldv2Report);

/// Stable inspection-field label for the record at `index` in a report
/// (`record[0]`, `record[1]`, ...). Mirrors `option_field_name` in `ndp.rs`.
fn record_field_name(index: usize) -> &'static str {
    const NAMES: [&str; 8] = [
        "record[0]",
        "record[1]",
        "record[2]",
        "record[3]",
        "record[4]",
        "record[5]",
        "record[6]",
        "record[7]",
    ];
    NAMES.get(index).copied().unwrap_or("record[*]")
}

/// MLDv2 Multicast Listener Query body (RFC 3810 section 5.1, type 130): the part
/// after the fixed 8-byte ICMPv6 header — the 128-bit Multicast Address, the
/// Resv/S/QRV byte, the QQIC byte, the 16-bit Number of Sources (auto-filled),
/// and the Source Address list.
///
/// On the wire an MLDv2 Query is ICMPv6 `type` 130, `code` 0, a 16-bit Maximum
/// Response Code, a 16-bit Reserved field, the 128-bit Multicast Address, then
/// the Resv(4)/S(1)/QRV(3) byte, the QQIC byte, the Number of Sources `N`, and
/// `N` Source Addresses. Following the established `Icmpv6` typed-body pattern,
/// the Maximum Response Code and Reserved fields live on the [`Icmpv6`] header's
/// four-byte rest-of-header (set by [`Icmpv6::mldv2_query`], exactly as the MLDv1
/// builders set the Maximum Response Delay there); this trailing body owns
/// everything after the fixed 8-byte header.
///
/// An MLDv2 Query reuses type 130 with the MLDv1 Query (RFC 2710). The two are
/// disambiguated by **body length**: an MLDv1 Query body is exactly the 16-byte
/// Multicast Address, while an MLDv2 Query body is at least
/// [`MLDV2_QUERY_MIN_BODY_LEN`] (20) bytes because it appends the
/// flags/QRV/QQIC/Number-of-Sources run. The decode dispatch in
/// `icmp/v6/mod.rs` uses that length to pick MLDv2 over MLDv1 (the step-27 seam).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mldv2Query {
    // `pub(crate)` so the ICMPv6 decode path in `icmp/v6/mod.rs` can construct the
    // body from wire bytes; the public surface is the builder/accessors below.
    pub(crate) multicast_address: Ipv6Addr,
    pub(crate) suppress_router_processing: bool,
    pub(crate) querier_robustness: u8,
    pub(crate) querier_query_interval_code: u8,
    pub(crate) sources: Vec<Ipv6Addr>,
    // RFC 3810 section 5.1.6: the 4 Resv bits are "set to zero on transmission,
    // and ignored on reception". Preserved verbatim so a non-zero value (a
    // deliberately malformed packet, or a future assignment) survives round-trip.
    pub(crate) reserved_bits: u8,
}

impl Mldv2Query {
    /// Create an MLDv2 Query body for `multicast_address` (RFC 3810 section 5.1):
    /// pass [`Ipv6Addr::UNSPECIFIED`] (`::`) for a General Query or the group for
    /// a Multicast-Address-(and-Source-)Specific Query. The S flag is clear, QRV
    /// and QQIC are 0, and there are no sources; set them with the builder
    /// methods. Compose it under an [`Icmpv6`] header (type 130, code 0) — or use
    /// [`Icmpv6::mldv2_query`], which sets the header type/code and the Maximum
    /// Response Code rest-of-header for you.
    pub fn new(multicast_address: Ipv6Addr) -> Self {
        Self {
            multicast_address,
            suppress_router_processing: false,
            querier_robustness: 0,
            querier_query_interval_code: 0,
            sources: Vec::new(),
            reserved_bits: 0,
        }
    }

    /// Set the Multicast Address (RFC 3810 section 5.1.5).
    pub fn multicast_address(mut self, multicast_address: Ipv6Addr) -> Self {
        self.multicast_address = multicast_address;
        self
    }

    /// Set the S Flag (Suppress Router-Side Processing, RFC 3810 section 5.1.7).
    pub fn suppress_router_processing(mut self, suppress: bool) -> Self {
        self.suppress_router_processing = suppress;
        self
    }

    /// Set the QRV (Querier's Robustness Variable, RFC 3810 section 5.1.8). Only
    /// the low 3 bits are carried on the wire ([`MLDV2_QUERY_QRV_MASK`]); a larger
    /// value is masked on serialization (RFC 3810 section 5.1.8: a robustness
    /// value greater than 7 cannot be represented).
    pub fn querier_robustness(mut self, qrv: u8) -> Self {
        self.querier_robustness = qrv;
        self
    }

    /// Set the QQIC (Querier's Query Interval Code, RFC 3810 section 5.1.9).
    pub fn querier_query_interval_code(mut self, qqic: u8) -> Self {
        self.querier_query_interval_code = qqic;
        self
    }

    /// Append one Source Address (RFC 3810 section 5.1.10), preserving order. The
    /// Number of Sources field is filled from the source count on serialization.
    pub fn source(mut self, source: Ipv6Addr) -> Self {
        self.sources.push(source);
        self
    }

    /// Replace the whole ordered Source Address list (RFC 3810 section 5.1.10).
    pub fn sources(mut self, sources: Vec<Ipv6Addr>) -> Self {
        self.sources = sources;
        self
    }

    /// The Multicast Address (RFC 3810 section 5.1.5).
    pub fn multicast_address_value(&self) -> Ipv6Addr {
        self.multicast_address
    }

    /// The S Flag (RFC 3810 section 5.1.7).
    pub fn suppress_router_processing_value(&self) -> bool {
        self.suppress_router_processing
    }

    /// The QRV (RFC 3810 section 5.1.8), the low 3 bits as carried on the wire.
    pub fn querier_robustness_value(&self) -> u8 {
        self.querier_robustness & MLDV2_QUERY_QRV_MASK
    }

    /// The QQIC (RFC 3810 section 5.1.9).
    pub fn querier_query_interval_code_value(&self) -> u8 {
        self.querier_query_interval_code
    }

    /// The Number of Sources field (RFC 3810 section 5.1, the count preceding the
    /// Source Address list), derived from the source list.
    pub fn number_of_sources(&self) -> u16 {
        self.sources.len() as u16
    }

    /// The ordered Source Address list (RFC 3810 section 5.1.10).
    pub fn sources_ref(&self) -> &[Ipv6Addr] {
        &self.sources
    }

    /// The Resv/S/QRV byte (RFC 3810 section 5.1): the preserved 4 Resv bits, the
    /// S flag (0x08), and the 3-bit QRV (0x07).
    fn resv_s_qrv_byte(&self) -> u8 {
        let mut byte = self.reserved_bits & MLDV2_QUERY_RESV_MASK;
        if self.suppress_router_processing {
            byte |= MLDV2_QUERY_S_FLAG;
        }
        byte |= self.querier_robustness & MLDV2_QUERY_QRV_MASK;
        byte
    }
}

impl Layer for Mldv2Query {
    fn name(&self) -> &'static str {
        "Mldv2Query"
    }

    fn summary(&self) -> String {
        format!(
            "Mldv2Query(multicast={}, S={}, QRV={}, QQIC={}, sources={})",
            self.multicast_address,
            self.suppress_router_processing,
            self.querier_robustness_value(),
            self.querier_query_interval_code,
            self.sources.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("multicast_address", self.multicast_address.to_string()),
            ("s_flag", self.suppress_router_processing.to_string()),
            ("qrv", self.querier_robustness_value().to_string()),
            ("qqic", self.querier_query_interval_code.to_string()),
            ("source_count", self.sources.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        MLDV2_QUERY_MIN_BODY_LEN + self.sources.len() * MLDV2_ADDRESS_LEN
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.multicast_address.octets());
        out.push(self.resv_s_qrv_byte());
        out.push(self.querier_query_interval_code);
        out.extend_from_slice(&self.number_of_sources().to_be_bytes());
        for source in &self.sources {
            out.extend_from_slice(&source.octets());
        }
        Ok(())
    }

    impl_layer_object!(Mldv2Query);
}

impl_layer_div!(Mldv2Query);

impl Icmpv6 {
    /// Build an MLDv2 Version 2 Multicast Listener Report packet (RFC 3810
    /// section 5.2, type 143, code 0).
    ///
    /// Returns a [`Packet`] composing the [`Icmpv6`] header (type 143, code 0,
    /// the rest-of-header set to a zero Reserved word and the **auto-filled** Nr
    /// of Mcast Address Records derived from `records.len()`) with an
    /// [`Mldv2Report`] body carrying the records. `compile()` auto-fills the
    /// ICMPv6 checksum over the IPv6 pseudo-header.
    ///
    /// RFC 3810 section 5.2.1 sends Reports to the all-MLDv2-capable-routers
    /// multicast address `ff02::16` with a link-local source, a Hop Limit of 1,
    /// and an IPv6 Router Alert option (RFC 2711) in a Hop-by-Hop Options header.
    /// This builder produces only the ICMPv6 message body; compose that enclosing
    /// IPv6 packet yourself, the same way the MLDv1 and NDP builders leave the
    /// IPv6-layer concerns to the caller (see the module docs).
    pub fn mldv2_report(records: Vec<MulticastAddressRecord>) -> Packet {
        let body = Mldv2Report::new().records(records);
        let count = body.number_of_records();
        // RFC 3810 section 5.2: rest-of-header = 16-bit Reserved (zero) + 16-bit
        // Nr of Mcast Address Records (auto-filled from the record count).
        let count_bytes = count.to_be_bytes();
        Self::new()
            .icmp_type(ICMPV6_MLDV2_REPORT)
            .code(0)
            .rest_of_header([0, 0, count_bytes[0], count_bytes[1]])
            / body
    }

    /// Build an MLDv2 Multicast Listener Query packet (RFC 3810 section 5.1, type
    /// 130, code 0).
    ///
    /// `max_response_code` is the Maximum Response Code (RFC 3810 section 5.1.3),
    /// carried on the [`Icmpv6`] header rest-of-header exactly as the MLDv1
    /// Maximum Response Delay is. The `query` body carries the Multicast Address,
    /// the S flag, QRV, QQIC, and the Source Address list (with the Number of
    /// Sources auto-filled). `compile()` auto-fills the ICMPv6 checksum over the
    /// IPv6 pseudo-header.
    ///
    /// An MLDv2 Query reuses type 130 with the MLDv1 Query but always carries the
    /// longer flags/QRV/QQIC/source run, so its body is at least
    /// [`MLDV2_QUERY_MIN_BODY_LEN`] (20) bytes — that is how the decoder tells the
    /// two versions apart (see [`Mldv2Query`]). RFC 3810 section 5.1 sends Queries
    /// from a link-local source with a Hop Limit of 1 and a Hop-by-Hop Router
    /// Alert option; that enclosing IPv6 packet is the caller's responsibility.
    pub fn mldv2_query(max_response_code: u16, query: Mldv2Query) -> Packet {
        Self::new()
            .icmp_type(ICMPV6_MULTICAST_LISTENER_QUERY)
            .code(0)
            .rest_of_header(mld_rest_of_header(max_response_code))
            / query
    }

    /// Build an MLDv2 General Query packet (RFC 3810 section 5.1, type 130, code
    /// 0): a Query with the unspecified Multicast Address (`::`) and the given
    /// `max_response_code`, with the S flag clear and no sources.
    ///
    /// A General Query is sent to the link-scope all-nodes multicast `ff02::1`
    /// and asks every host for its full multicast listening state. Customize the
    /// QRV / QQIC / S flag by building the [`Mldv2Query`] body and using
    /// [`Icmpv6::mldv2_query`]. The same link-local source / Hop Limit 1 /
    /// Router Alert requirement noted on [`Icmpv6::mldv2_query`] applies.
    pub fn mldv2_general_query(max_response_code: u16) -> Packet {
        Self::mldv2_query(max_response_code, Mldv2Query::new(Ipv6Addr::UNSPECIFIED))
    }
}

/// Decode an MLDv2 Multicast Listener Query body (RFC 3810 section 5.1): the
/// 128-bit Multicast Address, the Resv/S/QRV byte, the QQIC byte, the 16-bit
/// Number of Sources, and that many Source Addresses, all of which follow the
/// fixed 8-byte ICMPv6 header. The Maximum Response Code and Reserved fields live
/// in the header's rest-of-header and are decoded there.
///
/// This is the longer-body branch of the step-27 seam: the dispatch in
/// `icmp/v6/mod.rs` routes a type-130 body of at least [`MLDV2_QUERY_MIN_BODY_LEN`]
/// (20) bytes here (an MLDv2 Query), leaving an exactly-16-byte body to the MLDv1
/// decoder. Returns a structured [`CrafterError`] (never a panic) when the body
/// is too short for the fixed fields or for the declared Number of Sources.
pub(crate) fn decode_mldv2_query(bytes: &[u8]) -> Result<Mldv2Query> {
    if bytes.len() < MLDV2_QUERY_MIN_BODY_LEN {
        return Err(CrafterError::buffer_too_short(
            "icmpv6.mldv2.query",
            MLDV2_QUERY_MIN_BODY_LEN,
            bytes.len(),
        ));
    }
    let mut octets = [0u8; MLDV2_ADDRESS_LEN];
    octets.copy_from_slice(&bytes[..MLDV2_ADDRESS_LEN]);
    let multicast_address = Ipv6Addr::from(octets);

    let resv_s_qrv = bytes[MLDV2_ADDRESS_LEN];
    let querier_query_interval_code = bytes[MLDV2_ADDRESS_LEN + 1];
    let number_of_sources =
        u16::from_be_bytes([bytes[MLDV2_ADDRESS_LEN + 2], bytes[MLDV2_ADDRESS_LEN + 3]]) as usize;

    let sources_offset = MLDV2_QUERY_MIN_BODY_LEN;
    let needed = sources_offset + number_of_sources * MLDV2_ADDRESS_LEN;
    if bytes.len() < needed {
        return Err(CrafterError::buffer_too_short(
            "icmpv6.mldv2.query.sources",
            needed,
            bytes.len(),
        ));
    }
    let mut sources = Vec::with_capacity(number_of_sources);
    for index in 0..number_of_sources {
        let start = sources_offset + index * MLDV2_ADDRESS_LEN;
        let mut source = [0u8; MLDV2_ADDRESS_LEN];
        source.copy_from_slice(&bytes[start..start + MLDV2_ADDRESS_LEN]);
        sources.push(Ipv6Addr::from(source));
    }

    Ok(Mldv2Query {
        multicast_address,
        suppress_router_processing: resv_s_qrv & MLDV2_QUERY_S_FLAG != 0,
        querier_robustness: resv_s_qrv & MLDV2_QUERY_QRV_MASK,
        querier_query_interval_code,
        sources,
        reserved_bits: resv_s_qrv & MLDV2_QUERY_RESV_MASK,
    })
}

/// Decode an MLDv2 Version 2 Report body (RFC 3810 section 5.2): the list of
/// Multicast Address Records that follows the fixed 8-byte ICMPv6 header. The
/// 16-bit Reserved field and the 16-bit Nr of Mcast Address Records live in the
/// header's rest-of-header and are decoded there; this walk reads exactly the
/// records the body holds (the count is recoverable from the records, so a
/// truncated or over-stated header count cannot corrupt the walk).
///
/// Returns a structured [`CrafterError`] (never a panic) when a record runs past
/// the buffer (a short fixed header, an over-stated Number of Sources, or an
/// over-stated Aux Data Len).
pub(crate) fn decode_mldv2_report(bytes: &[u8]) -> Result<Mldv2Report> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        if remaining.len() < MLDV2_RECORD_FIXED_LEN {
            return Err(CrafterError::buffer_too_short(
                "icmpv6.mldv2.report.record",
                MLDV2_RECORD_FIXED_LEN,
                remaining.len(),
            ));
        }
        let record_type = MulticastRecordType::from_u8(remaining[0]);
        let aux_data_len_words = remaining[1] as usize;
        let number_of_sources = u16::from_be_bytes([remaining[2], remaining[3]]) as usize;

        let mut group = [0u8; MLDV2_ADDRESS_LEN];
        group.copy_from_slice(&remaining[4..4 + MLDV2_ADDRESS_LEN]);
        let multicast_address = Ipv6Addr::from(group);

        let sources_len = number_of_sources * MLDV2_ADDRESS_LEN;
        let aux_len = aux_data_len_words * MLDV2_AUX_DATA_UNIT;
        let record_len = MLDV2_RECORD_FIXED_LEN + sources_len + aux_len;
        if remaining.len() < record_len {
            return Err(CrafterError::buffer_too_short(
                "icmpv6.mldv2.report.record_body",
                record_len,
                remaining.len(),
            ));
        }

        let mut sources = Vec::with_capacity(number_of_sources);
        for index in 0..number_of_sources {
            let start = MLDV2_RECORD_FIXED_LEN + index * MLDV2_ADDRESS_LEN;
            let mut source = [0u8; MLDV2_ADDRESS_LEN];
            source.copy_from_slice(&remaining[start..start + MLDV2_ADDRESS_LEN]);
            sources.push(Ipv6Addr::from(source));
        }
        let aux_start = MLDV2_RECORD_FIXED_LEN + sources_len;
        let aux_data = remaining[aux_start..aux_start + aux_len].to_vec();

        records.push(MulticastAddressRecord {
            record_type,
            multicast_address,
            sources,
            aux_data,
        });
        offset += record_len;
    }
    Ok(Mldv2Report { records })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::icmp::{
        Icmpv6, Icmpv6Body, Mldv2Query, Mldv2Report, MulticastAddressRecord,
        MulticastListenerMessage, MulticastRecordType, ICMPV6_MLDV2_REPORT,
        ICMPV6_MULTICAST_LISTENER_DONE, ICMPV6_MULTICAST_LISTENER_QUERY,
        ICMPV6_MULTICAST_LISTENER_REPORT,
    };
    use crate::{Ipv6, NetworkLayer, Packet};

    // RFC 4291 / RFC 2710: the link-scope all-nodes multicast address ff02::1 is
    // the destination of a General Query. Used here only as IPv6-layer context.
    fn all_nodes() -> Ipv6Addr {
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
    }

    // A link-local source (fe80::/10), as RFC 2710 section 3 requires for MLD
    // messages. Documentation/link-scope only.
    fn link_local_src() -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0010)
    }

    // A documentation-scope multicast group: ff1e::db8:1 (admin-local scope,
    // within the ff00::/8 multicast space; the embedded db8 echoes the RFC 3849
    // 2001:db8::/32 documentation prefix as a mnemonic).
    fn doc_group() -> Ipv6Addr {
        Ipv6Addr::new(0xff1e, 0, 0, 0, 0, 0, 0x0db8, 0x0001)
    }

    // Locate the ICMPv6 message inside a compiled packet: the 40-byte IPv6 header
    // is followed directly by the ICMPv6 header here (no extension headers in the
    // test fixtures).
    const ICMPV6_OFFSET: usize = 40;

    // A General Query (type 130) carries a zero (unspecified) Multicast Address
    // and a Maximum Response Delay in the rest-of-header; the address round-trips
    // and the typed body classifies as a Multicast Listener message.
    #[test]
    fn mldv1_general_query_round_trips() {
        let compiled = (Ipv6::new()
            .src(link_local_src())
            .dst(all_nodes())
            .hop_limit(1)
            / Icmpv6::mld_general_query(10_000))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // Type 130, code 0.
        assert_eq!(bytes[ICMPV6_OFFSET], ICMPV6_MULTICAST_LISTENER_QUERY);
        assert_eq!(bytes[ICMPV6_OFFSET + 1], 0);
        // Maximum Response Delay (bytes 4..6 of the ICMPv6 header) = 10000 ms.
        assert_eq!(
            &bytes[ICMPV6_OFFSET + 4..ICMPV6_OFFSET + 6],
            &10_000u16.to_be_bytes()
        );
        // Reserved (bytes 6..8) is zero.
        assert_eq!(&bytes[ICMPV6_OFFSET + 6..ICMPV6_OFFSET + 8], &[0, 0]);
        // Multicast Address (bytes 8..24) is the unspecified address.
        assert_eq!(
            &bytes[ICMPV6_OFFSET + 8..ICMPV6_OFFSET + 24],
            &Ipv6Addr::UNSPECIFIED.octets()
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.icmp_type_value(), ICMPV6_MULTICAST_LISTENER_QUERY);
        assert!(matches!(
            icmpv6.body(),
            Icmpv6Body::MulticastListenerQuery { .. }
        ));
        if let Icmpv6Body::MulticastListenerQuery { max_response_delay } = icmpv6.body() {
            assert_eq!(max_response_delay, 10_000);
        }
        let mld = decoded.layer::<MulticastListenerMessage>().unwrap();
        assert_eq!(mld.multicast_address_value(), Ipv6Addr::UNSPECIFIED);
        // Byte-stable re-compile.
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // A Multicast-Address-Specific Query (type 130) carries the group address it
    // queries; the address and the Maximum Response Delay round-trip.
    #[test]
    fn mldv1_group_specific_query_round_trips() {
        let compiled = (Ipv6::new()
            .src(link_local_src())
            .dst(doc_group())
            .hop_limit(1)
            / Icmpv6::mld_query(doc_group(), 1_000))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        assert_eq!(bytes[ICMPV6_OFFSET], ICMPV6_MULTICAST_LISTENER_QUERY);
        assert_eq!(
            &bytes[ICMPV6_OFFSET + 4..ICMPV6_OFFSET + 6],
            &1_000u16.to_be_bytes()
        );
        assert_eq!(
            &bytes[ICMPV6_OFFSET + 8..ICMPV6_OFFSET + 24],
            &doc_group().octets()
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert!(matches!(
            icmpv6.body(),
            Icmpv6Body::MulticastListenerQuery {
                max_response_delay: 1_000
            }
        ));
        let mld = decoded.layer::<MulticastListenerMessage>().unwrap();
        assert_eq!(mld.multicast_address_value(), doc_group());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // A Report (type 131) carries the group the sender listens to; the Maximum
    // Response Delay is sent as zero (meaningful only on a Query). The address
    // round-trips and the body classifies as a Report.
    #[test]
    fn mldv1_report_round_trips() {
        let compiled = (Ipv6::new()
            .src(link_local_src())
            .dst(doc_group())
            .hop_limit(1)
            / Icmpv6::mld_report(doc_group()))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        assert_eq!(bytes[ICMPV6_OFFSET], ICMPV6_MULTICAST_LISTENER_REPORT);
        assert_eq!(bytes[ICMPV6_OFFSET + 1], 0);
        // Maximum Response Delay is zero in a Report.
        assert_eq!(&bytes[ICMPV6_OFFSET + 4..ICMPV6_OFFSET + 6], &[0, 0]);
        assert_eq!(
            &bytes[ICMPV6_OFFSET + 8..ICMPV6_OFFSET + 24],
            &doc_group().octets()
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.icmp_type_value(), ICMPV6_MULTICAST_LISTENER_REPORT);
        // The header-derived body view reports the (zero) Maximum Response Delay;
        // the Multicast Address lives in the trailing layer (asserted below).
        assert!(matches!(
            icmpv6.body(),
            Icmpv6Body::MulticastListenerReport {
                max_response_delay: 0
            }
        ));
        let mld = decoded.layer::<MulticastListenerMessage>().unwrap();
        assert_eq!(mld.multicast_address_value(), doc_group());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // A Done (type 132) carries the group the sender is ceasing to listen to;
    // the address round-trips and the body classifies as a Done.
    #[test]
    fn mldv1_done_round_trips() {
        let compiled = (Ipv6::new()
            .src(link_local_src())
            .dst(all_nodes())
            .hop_limit(1)
            / Icmpv6::mld_done(doc_group()))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        assert_eq!(bytes[ICMPV6_OFFSET], ICMPV6_MULTICAST_LISTENER_DONE);
        assert_eq!(bytes[ICMPV6_OFFSET + 1], 0);
        assert_eq!(&bytes[ICMPV6_OFFSET + 4..ICMPV6_OFFSET + 6], &[0, 0]);
        assert_eq!(
            &bytes[ICMPV6_OFFSET + 8..ICMPV6_OFFSET + 24],
            &doc_group().octets()
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.icmp_type_value(), ICMPV6_MULTICAST_LISTENER_DONE);
        // The header-derived body view reports the (zero) Maximum Response Delay;
        // the Multicast Address lives in the trailing layer (asserted below).
        assert!(matches!(
            icmpv6.body(),
            Icmpv6Body::MulticastListenerDone {
                max_response_delay: 0
            }
        ));
        let mld = decoded.layer::<MulticastListenerMessage>().unwrap();
        assert_eq!(mld.multicast_address_value(), doc_group());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // A type-130 body that is not exactly 16 bytes is not an MLDv1 Query (it may
    // be an MLDv2 Query, added in step 28); the decoder rejects it as an MLDv1
    // body so the dispatch can fall through rather than mis-typing it.
    #[test]
    fn mldv1_decode_rejects_non_16_byte_body() {
        // 20 bytes: too long for an MLDv1 Query body (an MLDv2 query shape).
        assert!(decode_multicast_listener_message(&[0u8; 20]).is_err());
        // 8 bytes: too short.
        assert!(decode_multicast_listener_message(&[0u8; 8]).is_err());
        // Exactly 16 bytes: a valid MLDv1 body.
        assert!(decode_multicast_listener_message(&[0u8; 16]).is_ok());
    }

    // A second documentation multicast group, distinct from doc_group(), so a
    // multi-record report carries two different groups.
    fn doc_group2() -> Ipv6Addr {
        Ipv6Addr::new(0xff1e, 0, 0, 0, 0, 0, 0x0db8, 0x0002)
    }

    // Documentation source addresses from the RFC 3849 2001:db8::/32 prefix.
    fn doc_source1() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0101)
    }

    fn doc_source2() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0102)
    }

    // RFC 3810 sec 5.2: an MLDv2 Report (type 143) with two Multicast Address
    // Records — one MODE_IS_INCLUDE with two sources, one MODE_IS_EXCLUDE with no
    // sources — round-trips: the header-derived record count, each record type,
    // multicast address, source list, and the auxiliary data all survive
    // build -> compile -> decode and the bytes re-compile identically.
    #[test]
    fn mldv2_report_two_records_round_trips() {
        let include = MulticastAddressRecord::new(MulticastRecordType::ModeIsInclude, doc_group())
            .source(doc_source1())
            .source(doc_source2())
            .aux_data([0xaa, 0xbb]); // 2 bytes -> 1 aux word (zero-padded to 4)
        let exclude = MulticastAddressRecord::new(MulticastRecordType::ModeIsExclude, doc_group2());

        let report = Icmpv6::mldv2_report(vec![include.clone(), exclude.clone()]);
        let compiled = (Ipv6::new()
            .src(link_local_src())
            .dst(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0016))
            .hop_limit(1)
            / report)
            .compile()
            .unwrap();
        let bytes = compiled.as_bytes();

        // Type 143, code/reserved 0.
        assert_eq!(bytes[ICMPV6_OFFSET], ICMPV6_MLDV2_REPORT);
        assert_eq!(bytes[ICMPV6_OFFSET + 1], 0);
        // Rest-of-header: 16-bit Reserved (zero) then 16-bit record count = 2.
        assert_eq!(&bytes[ICMPV6_OFFSET + 4..ICMPV6_OFFSET + 6], &[0, 0]);
        assert_eq!(
            &bytes[ICMPV6_OFFSET + 6..ICMPV6_OFFSET + 8],
            &2u16.to_be_bytes()
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.icmp_type_value(), ICMPV6_MLDV2_REPORT);
        assert!(matches!(
            icmpv6.body(),
            Icmpv6Body::Mldv2Report {
                number_of_records: 2
            }
        ));

        let report = decoded.layer::<Mldv2Report>().unwrap();
        assert_eq!(report.number_of_records(), 2);
        let records = report.records_ref();
        // First record: MODE_IS_INCLUDE, two sources, the auxiliary data.
        assert_eq!(
            records[0].record_type_value(),
            MulticastRecordType::ModeIsInclude
        );
        assert_eq!(records[0].multicast_address_value(), doc_group());
        assert_eq!(records[0].number_of_sources(), 2);
        assert_eq!(records[0].sources_ref(), &[doc_source1(), doc_source2()]);
        assert_eq!(records[0].aux_data_len(), 1);
        // Auxiliary data is preserved zero-padded to the 32-bit-word boundary.
        assert_eq!(records[0].aux_data_value(), &[0xaa, 0xbb, 0x00, 0x00]);
        // Second record: MODE_IS_EXCLUDE, no sources, no auxiliary data.
        assert_eq!(
            records[1].record_type_value(),
            MulticastRecordType::ModeIsExclude
        );
        assert_eq!(records[1].multicast_address_value(), doc_group2());
        assert_eq!(records[1].number_of_sources(), 0);
        assert!(records[1].sources_ref().is_empty());
        assert_eq!(records[1].aux_data_len(), 0);

        // Byte-stable re-compile.
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // RFC 3810 sec 5.1: an MLDv2 Query (type 130) with a source list round-trips —
    // the multicast address, S flag, QRV, QQIC, and the sources survive — and it
    // decodes as an MLDv2 Query (the longer body), NOT an MLDv1 Query, even though
    // both share type 130.
    #[test]
    fn mldv2_query_with_sources_round_trips_and_decodes_as_mldv2() {
        let query = Mldv2Query::new(doc_group())
            .suppress_router_processing(true)
            .querier_robustness(2)
            .querier_query_interval_code(125)
            .source(doc_source1())
            .source(doc_source2());

        let compiled = (Ipv6::new()
            .src(link_local_src())
            .dst(doc_group())
            .hop_limit(1)
            / Icmpv6::mldv2_query(10_000, query))
        .compile()
        .unwrap();
        let bytes = compiled.as_bytes();

        // Type 130, code 0; Maximum Response Code in the rest-of-header.
        assert_eq!(bytes[ICMPV6_OFFSET], ICMPV6_MULTICAST_LISTENER_QUERY);
        assert_eq!(bytes[ICMPV6_OFFSET + 1], 0);
        assert_eq!(
            &bytes[ICMPV6_OFFSET + 4..ICMPV6_OFFSET + 6],
            &10_000u16.to_be_bytes()
        );
        // Multicast Address (bytes 8..24), then the Resv/S/QRV byte (S=0x08 + QRV 2).
        assert_eq!(
            &bytes[ICMPV6_OFFSET + 8..ICMPV6_OFFSET + 24],
            &doc_group().octets()
        );
        assert_eq!(bytes[ICMPV6_OFFSET + 24], MLDV2_QUERY_S_FLAG | 2);
        // QQIC byte, then Number of Sources = 2.
        assert_eq!(bytes[ICMPV6_OFFSET + 25], 125);
        assert_eq!(
            &bytes[ICMPV6_OFFSET + 26..ICMPV6_OFFSET + 28],
            &2u16.to_be_bytes()
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.icmp_type_value(), ICMPV6_MULTICAST_LISTENER_QUERY);

        // The longer body decodes as an MLDv2 Query, not an MLDv1 message.
        let query = decoded.layer::<Mldv2Query>().unwrap();
        assert_eq!(query.multicast_address_value(), doc_group());
        assert!(query.suppress_router_processing_value());
        assert_eq!(query.querier_robustness_value(), 2);
        assert_eq!(query.querier_query_interval_code_value(), 125);
        assert_eq!(query.number_of_sources(), 2);
        assert_eq!(query.sources_ref(), &[doc_source1(), doc_source2()]);
        // It is NOT mis-decoded as an MLDv1 MulticastListenerMessage.
        assert!(decoded.layer::<MulticastListenerMessage>().is_none());

        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // The step-27/28 seam: an exactly-16-byte type-130 body still decodes as an
    // MLDv1 Query (the MulticastListenerMessage body), while a 20+ byte type-130
    // body decodes as an MLDv2 Query. This guards the body-length disambiguation.
    #[test]
    fn type_130_body_length_disambiguates_mldv1_from_mldv2() {
        // MLDv1: a group-specific query whose body is exactly the 16-byte address.
        let mldv1 = (Ipv6::new()
            .src(link_local_src())
            .dst(doc_group())
            .hop_limit(1)
            / Icmpv6::mld_query(doc_group(), 1_000))
        .compile()
        .unwrap();
        let mldv1_bytes = mldv1.as_bytes();
        // The ICMPv6 body (after the 8-byte header) is exactly 16 bytes.
        assert_eq!(mldv1_bytes.len() - (ICMPV6_OFFSET + 8), 16);
        let decoded_v1 = Packet::decode_from_l3(NetworkLayer::Ipv6, mldv1_bytes).unwrap();
        assert!(decoded_v1.layer::<MulticastListenerMessage>().is_some());
        assert!(decoded_v1.layer::<Mldv2Query>().is_none());

        // MLDv2 general query: body is 20 bytes (16-byte address + 4-byte run).
        let mldv2 = (Ipv6::new()
            .src(link_local_src())
            .dst(all_nodes())
            .hop_limit(1)
            / Icmpv6::mldv2_general_query(10_000))
        .compile()
        .unwrap();
        let mldv2_bytes = mldv2.as_bytes();
        assert_eq!(
            mldv2_bytes.len() - (ICMPV6_OFFSET + 8),
            MLDV2_QUERY_MIN_BODY_LEN
        );
        let decoded_v2 = Packet::decode_from_l3(NetworkLayer::Ipv6, mldv2_bytes).unwrap();
        assert!(decoded_v2.layer::<Mldv2Query>().is_some());
        assert!(decoded_v2.layer::<MulticastListenerMessage>().is_none());
    }

    // An unknown Record Type byte is preserved verbatim so the record round-trips
    // (the crate-wide unknown-codepoint rule), and the count auto-fills.
    #[test]
    fn mldv2_record_preserves_unknown_record_type() {
        let record = MulticastAddressRecord::new(MulticastRecordType::Unknown(200), doc_group());
        assert_eq!(
            record.record_type_value(),
            MulticastRecordType::Unknown(200)
        );

        let decoded = decode_mldv2_report(&{
            let mut out = Vec::new();
            record.encode_into(&mut out);
            out
        })
        .unwrap();
        assert_eq!(decoded.number_of_records(), 1);
        assert_eq!(
            decoded.records_ref()[0].record_type_value(),
            MulticastRecordType::Unknown(200)
        );
    }
}
