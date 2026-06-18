//! OSPFv2 Link State Request packet body (RFC 2328 §A.3.4).
//!
//! The Link State Request body follows the 24-octet common header and carries
//! the list of LSAs a router needs from its neighbor to bring its link-state
//! database up to date. Each request identifies one LSA by the triple that keys
//! it in the database:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          LS type                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Link State ID                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Advertising Router                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              ...                              ...
//! ```
//!
//! Unlike the 1-octet LS Type carried in the 20-octet LSA header (RFC 2328
//! §A.4.1), the request's LS type is a full 4-octet field. The body is just the
//! concatenation of these 12-octet entries, with no fixed prefix; an empty
//! request list is legal. Like the other bodies, [`OspfLinkStateRequest`] lives
//! inside the [`Ospfv2`](crate::protocols::ospf::Ospfv2) layer as an
//! [`OspfBody::LinkStateRequest`](crate::protocols::ospf::OspfBody::LinkStateRequest)
//! variant (BGP-style sub-element list); its `encode()`/`encoded_len()` are what
//! the layer's `compile()` routes to.

use std::net::Ipv4Addr;

/// The on-wire length of a single Link State Request entry, in octets: LS
/// type(4) + Link State ID(4) + Advertising Router(4).
const OSPF_LSR_ENTRY_LEN: usize = 12;

/// A single Link State Request entry (RFC 2328 §A.3.4).
///
/// Identifies one LSA the originator wants from its neighbor by the triple that
/// keys the LSA in the link-state database: the 4-octet LS type, the Link State
/// ID, and the Advertising Router. The LS type here is a full 32-bit field,
/// distinct from the 1-octet LS Type in the LSA header (RFC 2328 §A.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfLinkStateRequestEntry {
    /// The LS type of the requested LSA (RFC 2328 §A.3.4), a full 4-octet field.
    ls_type: u32,
    /// The Link State ID of the requested LSA.
    link_state_id: Ipv4Addr,
    /// The Advertising Router of the requested LSA.
    advertising_router: Ipv4Addr,
}

impl OspfLinkStateRequestEntry {
    /// Build a Link State Request entry from its three identifying fields.
    pub fn new(
        ls_type: u32,
        link_state_id: impl Into<Ipv4Addr>,
        advertising_router: impl Into<Ipv4Addr>,
    ) -> Self {
        Self {
            ls_type,
            link_state_id: link_state_id.into(),
            advertising_router: advertising_router.into(),
        }
    }

    /// The LS type of the requested LSA (a full 4-octet field).
    pub fn ls_type_value(&self) -> u32 {
        self.ls_type
    }

    /// The Link State ID of the requested LSA.
    pub fn link_state_id_value(&self) -> Ipv4Addr {
        self.link_state_id
    }

    /// The Advertising Router of the requested LSA.
    pub fn advertising_router_value(&self) -> Ipv4Addr {
        self.advertising_router
    }

    /// Append this entry as its 12 big-endian octets (LS type, Link State ID,
    /// Advertising Router) to `out`.
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ls_type.to_be_bytes());
        out.extend_from_slice(&self.link_state_id.octets());
        out.extend_from_slice(&self.advertising_router.octets());
    }
}

/// OSPFv2 Link State Request packet body (RFC 2328 §A.3.4).
///
/// Carries the list of [`OspfLinkStateRequestEntry`] entries naming the LSAs the
/// originator needs from its neighbor. The body is just the concatenation of
/// these 12-octet entries; an empty list is legal.
#[derive(Debug, Clone)]
pub struct OspfLinkStateRequest {
    /// The list of requested LSAs, in order.
    entries: Vec<OspfLinkStateRequestEntry>,
}

impl OspfLinkStateRequest {
    /// Build a Link State Request body with an empty request list.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Construct a Link State Request body from decoded wire entries.
    pub(crate) fn from_decoded_parts(entries: Vec<OspfLinkStateRequestEntry>) -> Self {
        Self { entries }
    }

    /// Append a single request entry to the request list.
    pub fn request(mut self, entry: OspfLinkStateRequestEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Append several request entries to the request list.
    pub fn requests<I>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = OspfLinkStateRequestEntry>,
    {
        self.entries.extend(entries);
        self
    }

    /// The requested-LSA entries, in order.
    pub fn entries_value(&self) -> &[OspfLinkStateRequestEntry] {
        &self.entries
    }

    /// The on-wire length of this Link State Request body, in octets: 12 octets
    /// per request entry.
    pub(crate) fn encoded_len(&self) -> usize {
        self.entries.len() * OSPF_LSR_ENTRY_LEN
    }

    /// Append the RFC 2328 §A.3.4 Link State Request body to `out`: each entry
    /// as its 12 big-endian octets, in order.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        for entry in &self.entries {
            entry.encode(out);
        }
    }
}

impl Default for OspfLinkStateRequest {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Link State Request body built with two entries compiles to the exact
    /// RFC 2328 §A.3.4 layout (two 12-octet triples), and the enclosing OSPF
    /// packet length covers the 24-octet common header plus the request body.
    #[test]
    fn ospf_link_state_request_body_compiles_with_two_entries() {
        use crate::packet::{Layer, Packet};
        use crate::protocols::ospf::lsa::{OSPF_LSA_NETWORK, OSPF_LSA_ROUTER};
        use crate::protocols::ospf::{Ospfv2, OSPF_HEADER_LEN, OSPF_TYPE_LINK_STATE_REQUEST};

        let lsr = OspfLinkStateRequest::new()
            .request(OspfLinkStateRequestEntry::new(
                u32::from(OSPF_LSA_ROUTER),
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(192, 0, 2, 1),
            ))
            .request(OspfLinkStateRequestEntry::new(
                u32::from(OSPF_LSA_NETWORK),
                Ipv4Addr::new(192, 0, 2, 2),
                Ipv4Addr::new(198, 51, 100, 7),
            ));

        // The body encodes to two 12-octet entries, with no fixed prefix.
        let mut body = Vec::new();
        lsr.encode(&mut body);
        assert_eq!(lsr.encoded_len(), 2 * OSPF_LSR_ENTRY_LEN);
        assert_eq!(body.len(), lsr.encoded_len());
        assert_eq!(body.len(), 24);

        // Hand-checked RFC 2328 §A.3.4 entries: LS type(4), Link State ID(4),
        // Advertising Router(4), big-endian.
        assert_eq!(&body[0..4], &u32::from(OSPF_LSA_ROUTER).to_be_bytes());
        assert_eq!(&body[4..8], &Ipv4Addr::new(192, 0, 2, 1).octets());
        assert_eq!(&body[8..12], &Ipv4Addr::new(192, 0, 2, 1).octets());
        assert_eq!(&body[12..16], &u32::from(OSPF_LSA_NETWORK).to_be_bytes());
        assert_eq!(&body[16..20], &Ipv4Addr::new(192, 0, 2, 2).octets());
        assert_eq!(&body[20..24], &Ipv4Addr::new(198, 51, 100, 7).octets());

        // The LSR rides inside an Ospfv2 layer; the compiled packet's Packet
        // Length field (octets 2..4) covers the common header plus the body.
        let ospf = Ospfv2::link_state_request().with_link_state_request(|r| {
            *r = lsr.clone();
        });
        let bytes = Packet::from_layer(ospf)
            .compile()
            .expect("LinkStateRequest compiles");

        let total = OSPF_HEADER_LEN + body.len();
        assert_eq!(bytes.len(), total);
        assert_eq!(&bytes[2..4], &(total as u16).to_be_bytes());
        // The header Type octet carries the Link State Request type code.
        assert_eq!(bytes[1], OSPF_TYPE_LINK_STATE_REQUEST);
        // The body bytes follow the 24-octet header verbatim.
        assert_eq!(&bytes[OSPF_HEADER_LEN..], body.as_slice());

        // `Layer::encoded_len` agrees with the emitted length.
        let layer = Ospfv2::link_state_request().with_link_state_request(|r| *r = lsr);
        assert_eq!(layer.encoded_len(), total);
    }
}
