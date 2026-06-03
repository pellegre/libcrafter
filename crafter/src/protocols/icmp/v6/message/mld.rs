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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::icmp::{
        Icmpv6, Icmpv6Body, MulticastListenerMessage, ICMPV6_MULTICAST_LISTENER_DONE,
        ICMPV6_MULTICAST_LISTENER_QUERY, ICMPV6_MULTICAST_LISTENER_REPORT,
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
}
