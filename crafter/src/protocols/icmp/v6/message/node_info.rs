//! ICMPv6 Node Information Query / Response (RFC 4620, types 139 / 140).
//!
//! **EXPERIMENTAL.** RFC 4620 ("IPv6 Node Information Queries") is an
//! *Experimental* RFC, not a Standards-Track one — it was never widely deployed
//! and its codepoints (Query type 139, Response type 140) sit outside the core
//! ICMPv6 / Neighbor Discovery surface. This module is provided so the codepoint
//! space is *covered* (an agent can build and decode these messages) rather than
//! silently dropped, but callers should treat it as experimental: the field
//! semantics beyond the fixed Qtype / Flags / Nonce header are deliberately kept
//! as inspectable raw `Data` bytes rather than fully typed per Qtype, and the
//! message family may see continued churn. See RFC 4620, the IANA "ICMPv6
//! Parameters" registry, and the `// EXPERIMENTAL` marker on the body classifier
//! in [`v6/body.rs`](super::super::body).
//!
//! ## Wire layout (RFC 4620 section 4, grounded against the authoritative RFC)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |     Code      |           Checksum            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |             Qtype             |             Flags             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                             Nonce                             +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! /                             Data                              /
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! - **Type** (RFC 4620 section 4): 139 Node Information Query, 140 Node
//!   Information Response. A single body type ([`NodeInformation`]) is reused
//!   across both — the `type` byte on the [`Icmpv6`] header distinguishes Query
//!   from Response.
//! - **Code** (RFC 4620 sections 5 and 6): Qtype-dependent on a Query (0 = the
//!   Subject in Data is an IPv6 address, 1 = a name or empty, 2 = an IPv4
//!   address) and result-dependent on a Response (0 = successful, 1 = responder
//!   refuses, 2 = unknown Qtype). The Code lives on the [`Icmpv6`] header and is
//!   set with [`Icmpv6::code`]; these builders default it to 0.
//! - **Qtype** (RFC 4620 section 4, 16 bits): the question being asked — `0`
//!   NOOP, `2` Node Name, `3` Node Addresses, `4` IPv4 Addresses (see
//!   [`NI_QTYPE_NOOP`] and friends). Carried on the [`Icmpv6`] header's
//!   rest-of-header (see below).
//! - **Flags** (RFC 4620 section 4, 16 bits): Qtype-dependent (e.g. the G/S/L/C/
//!   A/T bits for Qtype 3 Node Addresses); "undefined flags must be initialized
//!   to zero by the sender and ignored by the receiver." Kept as a raw 16-bit
//!   value here so any flag combination — including reserved bits set on purpose
//!   — round-trips. Carried on the [`Icmpv6`] header's rest-of-header.
//! - **Nonce** (RFC 4620 section 4, 64 bits): "an opaque 64-bit field to help
//!   avoid spoofing and/or to aid in matching Replies with Queries." The Querier
//!   picks it; the Responder copies it unchanged. Carried in this body.
//! - **Data** (RFC 4620 section 4, variable): the Subject of a Query (an IPv6
//!   address, a DNS name, or an IPv4 address, per the Code) or the answer of a
//!   Response (TTL-prefixed addresses, DNS names, etc., per the Qtype). Its exact
//!   shape varies with the Qtype and Code, so it is kept as inspectable raw bytes
//!   here rather than fully typed for every Qtype.
//!
//! Following the established `Icmpv6` typed-body pattern (the NDP and MLD
//! messages), the first four bytes after the fixed ICMPv6 header — the 16-bit
//! Qtype and the 16-bit Flags — are the [`Icmpv6`] header's four-byte
//! rest-of-header (bytes 4..8 of the ICMPv6 header), set on the header by the
//! builders, exactly as the MLDv1 builders keep their Maximum Response Delay /
//! Reserved word there and the NDP builders keep their Reserved / flags word
//! there. The trailing [`NodeInformation`] body owns exactly the part after that:
//! the 8-byte Nonce and the variable Data. The header auto-fills the ICMPv6
//! checksum over the IPv6 pseudo-header, covering this body's bytes — no new
//! checksum code is needed.

use super::super::*;

/// Width, in octets, of the Nonce field that opens a Node Information body
/// (RFC 4620 section 4: an opaque 64-bit value).
pub const NI_NONCE_LEN: usize = 8;

/// Qtype NOOP (RFC 4620 section 4 / section 5): "no operation" — the Responder
/// replies with no Data, used to test reachability or obtain the Nonce echo.
pub const NI_QTYPE_NOOP: u16 = 0;

/// Qtype Node Name (RFC 4620 section 6.3): request the node's DNS name(s).
pub const NI_QTYPE_NODE_NAME: u16 = 2;

/// Qtype Node Addresses (RFC 4620 section 6.4): request the node's IPv6
/// addresses. The Query Flags (G/S/L/C/A/T) scope which addresses are returned.
pub const NI_QTYPE_NODE_ADDRESSES: u16 = 3;

/// Qtype IPv4 Addresses (RFC 4620 section 6.5): request the node's IPv4
/// addresses.
pub const NI_QTYPE_IPV4_ADDRESSES: u16 = 4;

/// ICMPv6 Code on a Node Information **Query** (type 139) when the Subject in the
/// Data field is an IPv6 address (RFC 4620 section 5).
pub const NI_QUERY_CODE_SUBJECT_IPV6: u8 = 0;

/// ICMPv6 Code on a Node Information **Query** (type 139) when the Subject in the
/// Data field is a name, or the Data field is empty (RFC 4620 section 5).
pub const NI_QUERY_CODE_SUBJECT_NAME: u8 = 1;

/// ICMPv6 Code on a Node Information **Query** (type 139) when the Subject in the
/// Data field is an IPv4 address (RFC 4620 section 5).
pub const NI_QUERY_CODE_SUBJECT_IPV4: u8 = 2;

/// ICMPv6 Code on a Node Information **Response** (type 140): a successful reply;
/// the Data field carries the answer (RFC 4620 section 6).
pub const NI_RESPONSE_CODE_SUCCESS: u8 = 0;

/// ICMPv6 Code on a Node Information **Response** (type 140): the Responder
/// refuses to supply the answer; no Reply Data (RFC 4620 section 6).
pub const NI_RESPONSE_CODE_REFUSED: u8 = 1;

/// ICMPv6 Code on a Node Information **Response** (type 140): the Responder does
/// not recognize the Qtype; no Reply Data (RFC 4620 section 6).
pub const NI_RESPONSE_CODE_UNKNOWN_QTYPE: u8 = 2;

/// Node Information message body (RFC 4620 section 4, **experimental**): the
/// 64-bit Nonce and the variable Data that follow the fixed 8-byte ICMPv6 header.
///
/// On the wire a Node Information message is ICMPv6 `type` 139 (Query) or 140
/// (Response), a Code, a 16-bit Qtype, a 16-bit Flags field, the 64-bit Nonce,
/// then a variable Data field. A single body type is reused across Query and
/// Response — the `type` byte on the [`Icmpv6`] header distinguishes them — the
/// same way the wire format shares one layout.
///
/// Following the `Icmpv6` typed-body pattern, the Qtype and Flags fields are the
/// [`Icmpv6`] header's four-byte rest-of-header (set on the header — not in this
/// body — by [`Icmpv6::node_information_query`] /
/// [`Icmpv6::node_information_response`]) so the split matches the wire layout
/// and the way the NDP / MLD messages keep their rest-of-header fields on the
/// header. This body carries exactly the part after the fixed 8-byte header: the
/// 8-byte Nonce and the Data. The Data's shape varies by Qtype and Code, so it is
/// kept as inspectable raw bytes rather than fully typed for every Qtype. The
/// header auto-fills the ICMPv6 checksum over the IPv6 pseudo-header, covering
/// this body's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInformation {
    // `pub(crate)` so the ICMPv6 decode path in `icmp/v6/mod.rs` can construct the
    // body from wire bytes; the public surface is the builder/accessors below.
    pub(crate) nonce: [u8; NI_NONCE_LEN],
    pub(crate) data: Vec<u8>,
}

impl NodeInformation {
    /// Create a Node Information body with the given 64-bit `nonce` and no Data
    /// (RFC 4620 section 4).
    ///
    /// Add Data — the Subject of a Query or the answer of a Response — with
    /// [`NodeInformation::data`]. Compose this body under an [`Icmpv6`] header
    /// (type 139 / 140) — or, more simply, use
    /// [`Icmpv6::node_information_query`] / [`Icmpv6::node_information_response`],
    /// which set the header type / code and the Qtype / Flags rest-of-header for
    /// you.
    pub fn new(nonce: [u8; NI_NONCE_LEN]) -> Self {
        Self {
            nonce,
            data: Vec::new(),
        }
    }

    /// Set the 64-bit Nonce (RFC 4620 section 4: the opaque value a Querier picks
    /// and a Responder echoes).
    pub fn nonce(mut self, nonce: [u8; NI_NONCE_LEN]) -> Self {
        self.nonce = nonce;
        self
    }

    /// Set the variable Data field (RFC 4620 section 4).
    ///
    /// On a Query this is the Subject (an IPv6 address, a DNS name, or an IPv4
    /// address, selected by the ICMPv6 Code); on a Response it is the answer
    /// (TTL-prefixed addresses, DNS names, etc., selected by the Qtype). The
    /// Data's shape varies by Qtype / Code, so it is carried as raw bytes — build
    /// the exact Subject / answer bytes the Qtype requires and pass them here.
    pub fn data(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.data = data.into();
        self
    }

    /// The 64-bit Nonce (RFC 4620 section 4).
    pub fn nonce_value(&self) -> [u8; NI_NONCE_LEN] {
        self.nonce
    }

    /// The variable Data field (RFC 4620 section 4), as raw bytes.
    pub fn data_value(&self) -> &[u8] {
        &self.data
    }
}

impl Layer for NodeInformation {
    fn name(&self) -> &'static str {
        "NodeInformation"
    }

    fn summary(&self) -> String {
        format!(
            "NodeInformation(nonce={}, data={}B)",
            hex_bytes(&self.nonce),
            self.data.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("nonce", hex_bytes(&self.nonce)),
            ("data_len", self.data.len().to_string()),
            ("data", hex_bytes(&self.data)),
        ]
    }

    fn encoded_len(&self) -> usize {
        NI_NONCE_LEN + self.data.len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.data);
        Ok(())
    }

    impl_layer_object!(NodeInformation);
}

impl_layer_div!(NodeInformation);

/// Pack the Node Information rest-of-header (RFC 4620 section 4): the 16-bit
/// Qtype (big-endian) followed by the 16-bit Flags field (big-endian).
fn node_info_rest_of_header(qtype: u16, flags: u16) -> [u8; 4] {
    let qtype = qtype.to_be_bytes();
    let flags = flags.to_be_bytes();
    [qtype[0], qtype[1], flags[0], flags[1]]
}

impl Icmpv6 {
    /// Build an ICMPv6 Node Information **Query** packet (RFC 4620 section 4,
    /// type 139). **Experimental** — see the [module docs](self).
    ///
    /// `qtype` is the question (RFC 4620 section 4): [`NI_QTYPE_NOOP`],
    /// [`NI_QTYPE_NODE_NAME`], [`NI_QTYPE_NODE_ADDRESSES`], or
    /// [`NI_QTYPE_IPV4_ADDRESSES`]. `flags` is the Qtype-dependent 16-bit Flags
    /// field (e.g. the G/S/L/C/A/T bits for Qtype 3) — pass `0` when no flags
    /// apply. `nonce` is the opaque 64-bit anti-spoofing value the Responder
    /// echoes. `data` is the Subject the Query asks about (an IPv6 address, a DNS
    /// name, or an IPv4 address, selected by the ICMPv6 Code); pass an empty slice
    /// for a NOOP or a self-query.
    ///
    /// The ICMPv6 Code (RFC 4620 section 5) defaults to 0
    /// ([`NI_QUERY_CODE_SUBJECT_IPV6`]); set it with [`Icmpv6::code`] when the
    /// Subject is a name ([`NI_QUERY_CODE_SUBJECT_NAME`]) or an IPv4 address
    /// ([`NI_QUERY_CODE_SUBJECT_IPV4`]).
    ///
    /// Returns a [`Packet`] composing the [`Icmpv6`] header (type 139, code 0, the
    /// rest-of-header set to the Qtype and Flags) with a [`NodeInformation`] body
    /// carrying the Nonce and Data. `compile()` auto-fills the ICMPv6 checksum
    /// over the IPv6 pseudo-header.
    pub fn node_information_query(
        qtype: u16,
        flags: u16,
        nonce: [u8; NI_NONCE_LEN],
        data: impl Into<Vec<u8>>,
    ) -> Packet {
        Self::node_information_message(
            ICMPV6_NODE_INFORMATION_QUERY,
            qtype,
            flags,
            NodeInformation::new(nonce).data(data),
        )
    }

    /// Build an ICMPv6 Node Information **Response** packet (RFC 4620 section 4,
    /// type 140). **Experimental** — see the [module docs](self).
    ///
    /// `qtype` echoes the Query's question (RFC 4620 section 4). `flags` is the
    /// Qtype-dependent 16-bit Flags field (e.g. the T bit, indicating an
    /// incomplete address set, on a Node Addresses or IPv4 Addresses reply); pass
    /// `0` when no flags apply. `nonce` MUST be the Nonce copied verbatim from the
    /// Query it answers (RFC 4620 section 4). `data` is the answer (TTL-prefixed
    /// addresses, DNS names, etc., selected by the Qtype); pass an empty slice for
    /// a NOOP reply or an error reply.
    ///
    /// The ICMPv6 Code (RFC 4620 section 6) defaults to 0
    /// ([`NI_RESPONSE_CODE_SUCCESS`]); set it with [`Icmpv6::code`] to
    /// [`NI_RESPONSE_CODE_REFUSED`] (the Responder refuses) or
    /// [`NI_RESPONSE_CODE_UNKNOWN_QTYPE`] (the Qtype is unrecognized), both of
    /// which carry no Reply Data.
    ///
    /// Returns a [`Packet`] composing the [`Icmpv6`] header (type 140, code 0, the
    /// rest-of-header set to the Qtype and Flags) with a [`NodeInformation`] body
    /// carrying the Nonce and Data. `compile()` auto-fills the ICMPv6 checksum
    /// over the IPv6 pseudo-header.
    pub fn node_information_response(
        qtype: u16,
        flags: u16,
        nonce: [u8; NI_NONCE_LEN],
        data: impl Into<Vec<u8>>,
    ) -> Packet {
        Self::node_information_message(
            ICMPV6_NODE_INFORMATION_RESPONSE,
            qtype,
            flags,
            NodeInformation::new(nonce).data(data),
        )
    }

    /// Compose a Node Information header (the given `icmp_type`, code 0,
    /// rest-of-header = Qtype + Flags) with a caller-built [`NodeInformation`]
    /// body (RFC 4620 section 4).
    fn node_information_message(
        icmp_type: u8,
        qtype: u16,
        flags: u16,
        body: NodeInformation,
    ) -> Packet {
        Self::new()
            .icmp_type(icmp_type)
            .code(0)
            .rest_of_header(node_info_rest_of_header(qtype, flags))
            / body
    }
}

/// Decode the body of an ICMPv6 Node Information message (RFC 4620 section 4):
/// the 64-bit Nonce and the variable Data that follow the fixed 8-byte ICMPv6
/// header. The Qtype and Flags fields live in the header's rest-of-header and are
/// decoded there.
///
/// Returns a structured [`CrafterError`] (never a panic) when the body is too
/// short for the fixed 8-byte Nonce.
pub(crate) fn decode_node_information(bytes: &[u8]) -> Result<NodeInformation> {
    if bytes.len() < NI_NONCE_LEN {
        return Err(CrafterError::buffer_too_short(
            "icmpv6.node_information.nonce",
            NI_NONCE_LEN,
            bytes.len(),
        ));
    }
    let mut nonce = [0u8; NI_NONCE_LEN];
    nonce.copy_from_slice(&bytes[..NI_NONCE_LEN]);
    Ok(NodeInformation {
        nonce,
        data: bytes[NI_NONCE_LEN..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::icmp::{
        Icmpv6, Icmpv6Body, NodeInformation, ICMPV6_NODE_INFORMATION_QUERY,
        ICMPV6_NODE_INFORMATION_RESPONSE,
    };
    use crate::{Ipv6, NetworkLayer, Packet};
    use core::net::Ipv6Addr;

    // Locate the ICMPv6 message inside a compiled packet: the 40-byte IPv6 header
    // is followed directly by the ICMPv6 header here (no extension headers).
    const ICMPV6_OFFSET: usize = 40;

    // Documentation-space IPv6 endpoints (RFC 3849 2001:db8::/32).
    fn doc_src() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0x0010)
    }

    fn doc_dst() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 0x0020)
    }

    // A Node Information Query (type 139) carries Qtype + Flags in the
    // rest-of-header and the Nonce + Data (here the IPv6 Subject) in the trailing
    // body. Everything round-trips and the body classifies as a Node Information
    // Query.
    #[test]
    fn node_information_query_round_trips() {
        let nonce = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        // Qtype 3 (Node Addresses) with the A flag (bit 4 => 0x0010) set; Subject
        // is the queried node's IPv6 address (Code 0, the default).
        let subject = doc_dst().octets().to_vec();
        let compiled = (Ipv6::new().src(doc_src()).dst(doc_dst()).hop_limit(64)
            / Icmpv6::node_information_query(
                NI_QTYPE_NODE_ADDRESSES,
                0x0010,
                nonce,
                subject.clone(),
            ))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // Type 139, code 0.
        assert_eq!(bytes[ICMPV6_OFFSET], ICMPV6_NODE_INFORMATION_QUERY);
        assert_eq!(bytes[ICMPV6_OFFSET + 1], 0);
        // Qtype (bytes 4..6 of the ICMPv6 header) = 3.
        assert_eq!(
            &bytes[ICMPV6_OFFSET + 4..ICMPV6_OFFSET + 6],
            &NI_QTYPE_NODE_ADDRESSES.to_be_bytes()
        );
        // Flags (bytes 6..8) = 0x0010.
        assert_eq!(
            &bytes[ICMPV6_OFFSET + 6..ICMPV6_OFFSET + 8],
            &0x0010u16.to_be_bytes()
        );
        // Nonce (bytes 8..16) round-trips verbatim.
        assert_eq!(&bytes[ICMPV6_OFFSET + 8..ICMPV6_OFFSET + 16], &nonce);
        // Data (bytes 16..) is the IPv6 Subject.
        assert_eq!(&bytes[ICMPV6_OFFSET + 16..], &subject[..]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.icmp_type_value(), ICMPV6_NODE_INFORMATION_QUERY);
        assert_eq!(
            icmpv6.body(),
            Icmpv6Body::NodeInformationQuery {
                qtype: NI_QTYPE_NODE_ADDRESSES,
                flags: 0x0010,
            }
        );
        let ni = decoded.layer::<NodeInformation>().unwrap();
        assert_eq!(ni.nonce_value(), nonce);
        assert_eq!(ni.data_value(), &subject[..]);
        // Byte-stable re-compile.
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // A Node Information Response (type 140) echoes the Qtype and the Nonce and
    // carries the answer in Data. Everything round-trips and the body classifies
    // as a Node Information Response.
    #[test]
    fn node_information_response_round_trips() {
        let nonce = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33];
        // Qtype 3 (Node Addresses) reply: a 32-bit TTL followed by one IPv6
        // address (RFC 4620 section 6.4). Kept as raw answer bytes.
        let mut answer = Vec::new();
        answer.extend_from_slice(&3600u32.to_be_bytes());
        answer.extend_from_slice(&doc_src().octets());
        let compiled = (Ipv6::new().src(doc_dst()).dst(doc_src()).hop_limit(64)
            / Icmpv6::node_information_response(NI_QTYPE_NODE_ADDRESSES, 0, nonce, answer.clone()))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        assert_eq!(bytes[ICMPV6_OFFSET], ICMPV6_NODE_INFORMATION_RESPONSE);
        assert_eq!(bytes[ICMPV6_OFFSET + 1], 0);
        assert_eq!(
            &bytes[ICMPV6_OFFSET + 4..ICMPV6_OFFSET + 6],
            &NI_QTYPE_NODE_ADDRESSES.to_be_bytes()
        );
        assert_eq!(&bytes[ICMPV6_OFFSET + 6..ICMPV6_OFFSET + 8], &[0, 0]);
        assert_eq!(&bytes[ICMPV6_OFFSET + 8..ICMPV6_OFFSET + 16], &nonce);
        assert_eq!(&bytes[ICMPV6_OFFSET + 16..], &answer[..]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.icmp_type_value(), ICMPV6_NODE_INFORMATION_RESPONSE);
        assert_eq!(
            icmpv6.body(),
            Icmpv6Body::NodeInformationResponse {
                qtype: NI_QTYPE_NODE_ADDRESSES,
                flags: 0,
            }
        );
        let ni = decoded.layer::<NodeInformation>().unwrap();
        assert_eq!(ni.nonce_value(), nonce);
        assert_eq!(ni.data_value(), &answer[..]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // A NOOP Query (Qtype 0) with no Data still carries the 8-byte Nonce; the
    // empty Data round-trips.
    #[test]
    fn node_information_noop_query_round_trips() {
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let compiled = (Ipv6::new().src(doc_src()).dst(doc_dst()).hop_limit(64)
            / Icmpv6::node_information_query(NI_QTYPE_NOOP, 0, nonce, Vec::new()))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // No Data after the 8-byte Nonce.
        assert_eq!(bytes.len(), ICMPV6_OFFSET + 8 + NI_NONCE_LEN);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let ni = decoded.layer::<NodeInformation>().unwrap();
        assert_eq!(ni.nonce_value(), nonce);
        assert!(ni.data_value().is_empty());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // A body too short for the 8-byte Nonce is a structured error, never a panic.
    #[test]
    fn node_information_short_body_is_error() {
        assert!(decode_node_information(&[0u8; NI_NONCE_LEN - 1]).is_err());
    }
}
