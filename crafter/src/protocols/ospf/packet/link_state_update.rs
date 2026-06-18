//! OSPFv2 Link State Update packet body (RFC 2328 §A.3.5).
//!
//! The Link State Update body follows the 24-octet common header and carries
//! the flooded LSAs themselves. It begins with a 4-octet count of advertisements
//! and is then the concatenation of that many complete LSAs:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            # LSAs                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +-                                                            +-+
//! |                             LSAs                              |
//! +-                                                            +-+
//! |                              ...                             ...
//! ```
//!
//! Each LSA is a 20-octet LSA header (RFC 2328 §A.4.1) immediately followed by
//! its type-specific body; the header's `length` field covers the header plus
//! the body. The `# LSAs` count auto-fills from the number of carried LSAs unless
//! the caller pinned it, so a deliberately wrong count survives `compile()`.
//! Like the other bodies, [`OspfLinkStateUpdate`] lives inside the
//! [`Ospfv2`](crate::protocols::ospf::Ospfv2) layer as an
//! [`OspfBody::LinkStateUpdate`](crate::protocols::ospf::OspfBody::LinkStateUpdate)
//! variant (BGP-style sub-element list); its `encode()`/`encoded_len()` are what
//! the layer's `compile()` routes to.

use crate::field::Field;
use crate::protocols::ospf::lsa::OspfLsa;

/// The on-wire length of the Link State Update `# LSAs` count field, in octets.
const OSPF_LSU_COUNT_LEN: usize = 4;

/// OSPFv2 Link State Update packet body (RFC 2328 §A.3.5).
///
/// Carries the list of [`OspfLsa`] advertisements being flooded, prefixed by a
/// 4-octet count. The count auto-fills from the number of carried LSAs unless
/// the caller pinned it.
#[derive(Debug, Clone)]
pub struct OspfLinkStateUpdate {
    /// The `# LSAs` count (RFC 2328 §A.3.5). Left unset so `encode()` fills it
    /// with the number of carried LSAs; a pinned value (including a deliberately
    /// wrong one) survives untouched.
    num_lsas: Field<u32>,
    /// The carried LSAs, in order.
    lsas: Vec<OspfLsa>,
}

impl OspfLinkStateUpdate {
    /// Build a Link State Update body with an empty LSA list and an unset count.
    pub fn new() -> Self {
        Self {
            num_lsas: Field::unset(),
            lsas: Vec::new(),
        }
    }

    /// Construct a Link State Update body from decoded wire parts, marking the
    /// `# LSAs` count as caller-supplied so a decoded update re-compiles
    /// byte-for-byte.
    #[allow(dead_code)]
    pub(crate) fn from_decoded_parts(num_lsas: u32, lsas: Vec<OspfLsa>) -> Self {
        Self {
            num_lsas: Field::user(num_lsas),
            lsas,
        }
    }

    /// Append a single LSA to the update's LSA list.
    pub fn lsa(mut self, lsa: OspfLsa) -> Self {
        self.lsas.push(lsa);
        self
    }

    /// Append several LSAs to the update's LSA list.
    pub fn lsas<I>(mut self, lsas: I) -> Self
    where
        I: IntoIterator<Item = OspfLsa>,
    {
        self.lsas.extend(lsas);
        self
    }

    /// Force the `# LSAs` count field (RFC 2328 §A.3.5).
    ///
    /// This preserves malformed-on-purpose updates whose declared count differs
    /// from the number of carried LSAs.
    pub fn num_lsas(mut self, num_lsas: u32) -> Self {
        self.num_lsas.set_user(num_lsas);
        self
    }

    /// The carried LSAs, in order.
    pub fn lsas_value(&self) -> &[OspfLsa] {
        &self.lsas
    }

    /// The effective `# LSAs` count: the caller value, else the number of
    /// carried LSAs.
    pub fn num_lsas_value(&self) -> u32 {
        self.num_lsas
            .value()
            .copied()
            .unwrap_or(self.lsas.len() as u32)
    }

    /// The on-wire length of this Link State Update body, in octets: the 4-octet
    /// count plus the total size of every carried LSA (each 20-octet header plus
    /// its body).
    pub(crate) fn encoded_len(&self) -> usize {
        OSPF_LSU_COUNT_LEN + self.lsas.iter().map(OspfLsa::encoded_len).sum::<usize>()
    }

    /// Append the RFC 2328 §A.3.5 Link State Update body to `out`: the `# LSAs`
    /// count (the caller value, else the number of carried LSAs), then each LSA
    /// (header + body) with its length and LS checksum auto-filled.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.num_lsas_value().to_be_bytes());
        for lsa in &self.lsas {
            lsa.encode(out);
        }
    }
}

impl Default for OspfLinkStateUpdate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::fletcher16_valid;
    use crate::packet::{Layer, Packet};
    use crate::protocols::ospf::lsa::{OspfLsaBody, OspfLsaHeader, OSPF_LSA_HEADER_LEN, OSPF_LSA_ROUTER};
    use crate::protocols::ospf::{Ospfv2, OSPF_HEADER_LEN, OSPF_TYPE_LINK_STATE_UPDATE};
    use core::net::Ipv4Addr;

    /// A Link State Update carrying one LSA with a raw body compiles to the
    /// RFC 2328 §A.3.5 layout: the `# LSAs` field reports one LSA, the LSA's
    /// `length` field covers its 20-octet header plus the body, the LSA's
    /// Fletcher checksum validates, and the enclosing OSPF packet length covers
    /// the 24-octet common header plus the update body.
    #[test]
    fn ospf_link_state_update_body_compiles_with_one_raw_lsa() {
        let lsa_body = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_ROUTER)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::Raw(lsa_body.to_vec()),
        );

        let lsu = OspfLinkStateUpdate::new().lsa(lsa);

        // One carried LSA, so the body is the 4-octet count plus one full LSA.
        assert_eq!(lsu.lsas_value().len(), 1);
        assert_eq!(lsu.num_lsas_value(), 1);

        let mut body = Vec::new();
        lsu.encode(&mut body);
        assert_eq!(body.len(), lsu.encoded_len());

        // # LSAs field (octets 0..4) reports one LSA.
        assert_eq!(&body[0..4], &1u32.to_be_bytes());

        // The single LSA follows the count: 20-octet header plus the 6-octet body.
        let lsa_bytes = &body[OSPF_LSU_COUNT_LEN..];
        assert_eq!(lsa_bytes.len(), OSPF_LSA_HEADER_LEN + lsa_body.len());

        // The LSA's length field (octets 18..20 within the LSA) covers the header
        // plus the body.
        let expected_lsa_len = (OSPF_LSA_HEADER_LEN + lsa_body.len()) as u16;
        assert_eq!(&lsa_bytes[18..20], &expected_lsa_len.to_be_bytes());

        // The LSA's Fletcher-16 checksum validates over the whole LSA.
        assert!(
            fletcher16_valid(lsa_bytes),
            "auto-filled Fletcher checksum should validate over the LSA"
        );

        // The LSU rides inside an Ospfv2 layer; the compiled packet's Packet
        // Length field (octets 2..4) covers the common header plus the body.
        let ospf = Ospfv2::link_state_update().with_link_state_update(|u| {
            *u = lsu.clone();
        });
        let bytes = Packet::from_layer(ospf)
            .compile()
            .expect("LinkStateUpdate compiles");

        let total = OSPF_HEADER_LEN + body.len();
        assert_eq!(bytes.len(), total);
        assert_eq!(&bytes[2..4], &(total as u16).to_be_bytes());
        // The header Type octet carries the Link State Update type code.
        assert_eq!(bytes[1], OSPF_TYPE_LINK_STATE_UPDATE);
        // The body bytes follow the 24-octet header verbatim.
        assert_eq!(&bytes[OSPF_HEADER_LEN..], body.as_slice());

        // `Layer::encoded_len` agrees with the emitted length.
        let layer = Ospfv2::link_state_update().with_link_state_update(|u| *u = lsu);
        assert_eq!(layer.encoded_len(), total);
    }

    /// A caller-set `# LSAs` count survives `encode()` untouched, so a
    /// malformed-on-purpose update keeps its wrong count.
    #[test]
    fn ospf_link_state_update_user_count_survives_encode() {
        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_ROUTER)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1)),
            OspfLsaBody::Raw(vec![0x00, 0x01]),
        );

        // One carried LSA but a pinned count of 5.
        let lsu = OspfLinkStateUpdate::new().lsa(lsa).num_lsas(5);
        assert_eq!(lsu.num_lsas_value(), 5);

        let mut body = Vec::new();
        lsu.encode(&mut body);
        assert_eq!(&body[0..4], &5u32.to_be_bytes());
    }
}
