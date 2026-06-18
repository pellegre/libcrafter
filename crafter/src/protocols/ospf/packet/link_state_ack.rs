//! OSPFv2 Link State Acknowledgment packet body (RFC 2328 §A.3.6).
//!
//! The Link State Acknowledgment body follows the 24-octet common header and
//! carries the list of bare 20-octet LSA headers acknowledging the LSAs a
//! router just received from its neighbor:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +-                                                             -+
//! |                             An LSA Header                      |
//! +-                                                             -+
//! |                                                               |
//! +-                                                             -+
//! |                                                               |
//! +-                                                             -+
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              ...                              ...
//! ```
//!
//! Unlike the Database Description body (RFC 2328 §A.3.3) the Link State
//! Acknowledgment has no fixed prefix: the body is just the concatenation of
//! bare 20-octet LSA headers (RFC 2328 §A.4.1), and an empty list is legal.
//! Like the other bodies, [`OspfLinkStateAck`] lives inside the
//! [`Ospfv2`](crate::protocols::ospf::Ospfv2) layer as an
//! [`OspfBody::LinkStateAck`](crate::protocols::ospf::OspfBody::LinkStateAck)
//! variant (BGP-style sub-element list); its `encode()`/`encoded_len()` are what
//! the layer's `compile()` routes to.

use crate::protocols::ospf::lsa::{encode_lsa_headers, OspfLsaHeader, OSPF_LSA_HEADER_LEN};

/// OSPFv2 Link State Acknowledgment packet body (RFC 2328 §A.3.6).
///
/// Carries the list of bare 20-octet LSA headers (RFC 2328 §A.4.1)
/// acknowledging the LSAs the originator just received. The body is just the
/// concatenation of these headers; an empty list is legal.
#[derive(Debug, Clone)]
pub struct OspfLinkStateAck {
    /// The list of bare 20-octet LSA headers (RFC 2328 §A.4.1) being
    /// acknowledged.
    lsa_headers: Vec<OspfLsaHeader>,
}

impl OspfLinkStateAck {
    /// Build a Link State Acknowledgment body with an empty LSA-header list.
    pub fn new() -> Self {
        Self {
            lsa_headers: Vec::new(),
        }
    }

    /// Construct a Link State Acknowledgment body from decoded wire headers.
    ///
    /// Consumed by the Link State Acknowledgment decoder added in a later step;
    /// staged here alongside the builder so the body type is complete.
    #[allow(dead_code)]
    pub(crate) fn from_decoded_parts(lsa_headers: Vec<OspfLsaHeader>) -> Self {
        Self { lsa_headers }
    }

    /// Append a single LSA header to the acknowledgment's header list.
    pub fn lsa_header(mut self, header: OspfLsaHeader) -> Self {
        self.lsa_headers.push(header);
        self
    }

    /// Append several LSA headers to the acknowledgment's header list.
    pub fn lsa_headers<I>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = OspfLsaHeader>,
    {
        self.lsa_headers.extend(headers);
        self
    }

    /// The LSA headers being acknowledged, in order.
    pub fn lsa_headers_value(&self) -> &[OspfLsaHeader] {
        &self.lsa_headers
    }

    /// The on-wire length of this Link State Acknowledgment body, in octets: 20
    /// octets per LSA header.
    pub(crate) fn encoded_len(&self) -> usize {
        self.lsa_headers.len() * OSPF_LSA_HEADER_LEN
    }

    /// Append the RFC 2328 §A.3.6 Link State Acknowledgment body to `out`: each
    /// bare 20-octet LSA header, in order.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        encode_lsa_headers(&self.lsa_headers, out);
    }
}

impl Default for OspfLinkStateAck {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    /// A Link State Acknowledgment body built with two LSA headers compiles to
    /// the exact RFC 2328 §A.3.6 layout (two bare 20-octet headers, no fixed
    /// prefix), and the enclosing OSPF packet length covers the 24-octet common
    /// header plus the acknowledgment body.
    #[test]
    fn ospf_link_state_ack_body_compiles_with_two_lsa_headers() {
        use crate::packet::{Layer, Packet};
        use crate::protocols::ospf::lsa::{OspfLsaHeader, OSPF_LSA_NETWORK, OSPF_LSA_ROUTER};
        use crate::protocols::ospf::{Ospfv2, OSPF_HEADER_LEN, OSPF_TYPE_LINK_STATE_ACK};

        let ack = OspfLinkStateAck::new()
            .lsa_header(
                OspfLsaHeader::new()
                    .ls_type(OSPF_LSA_ROUTER)
                    .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                    .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                    .ls_sequence_number(0x8000_0001),
            )
            .lsa_header(
                OspfLsaHeader::new()
                    .ls_type(OSPF_LSA_NETWORK)
                    .link_state_id(Ipv4Addr::new(192, 0, 2, 2))
                    .advertising_router(Ipv4Addr::new(198, 51, 100, 7))
                    .ls_sequence_number(0x8000_0002),
            );

        // The body encodes to two bare 20-octet LSA headers, with no fixed
        // prefix.
        let mut body = Vec::new();
        ack.encode(&mut body);
        assert_eq!(ack.encoded_len(), 2 * OSPF_LSA_HEADER_LEN);
        assert_eq!(body.len(), ack.encoded_len());
        assert_eq!(body.len(), 40);

        // The two LSA headers match standalone-encoded headers, 20 octets each.
        let mut expected_headers = Vec::new();
        encode_lsa_headers(ack.lsa_headers_value(), &mut expected_headers);
        assert_eq!(body, expected_headers);
        assert_eq!(expected_headers.len(), 2 * OSPF_LSA_HEADER_LEN);

        // The ack rides inside an Ospfv2 layer; the compiled packet's Packet
        // Length field (octets 2..4) covers the common header plus the body.
        let ospf = Ospfv2::link_state_ack().with_link_state_ack(|a| {
            *a = ack.clone();
        });
        let bytes = Packet::from_layer(ospf)
            .compile()
            .expect("LinkStateAck compiles");

        let total = OSPF_HEADER_LEN + body.len();
        assert_eq!(bytes.len(), total);
        assert_eq!(&bytes[2..4], &(total as u16).to_be_bytes());
        // The header Type octet carries the Link State Acknowledgment type code.
        assert_eq!(bytes[1], OSPF_TYPE_LINK_STATE_ACK);
        // The body bytes follow the 24-octet header verbatim.
        assert_eq!(&bytes[OSPF_HEADER_LEN..], body.as_slice());

        // `Layer::encoded_len` agrees with the emitted length.
        let layer = Ospfv2::link_state_ack().with_link_state_ack(|a| *a = ack);
        assert_eq!(layer.encoded_len(), total);
    }
}
