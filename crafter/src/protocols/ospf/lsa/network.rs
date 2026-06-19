//! OSPFv2 Network-LSA body (RFC 2328 §A.4.3).
//!
//! The Network-LSA (LS type 2) is originated for every transit broadcast or
//! NBMA network by its designated router. It follows the 20-octet
//! [`OspfLsaHeader`](crate::protocols::ospf::lsa::OspfLsaHeader) and is the
//! network's address mask followed by the Router
//! IDs of each router attached to the network (including the designated router
//! itself):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Network Mask                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Attached Router                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              ...                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Like the other LSA bodies, [`OspfNetworkLsa`] rides inside an
//! [`OspfLsa`](crate::protocols::ospf::lsa::OspfLsa) as an
//! [`OspfLsaBody::Network`](crate::protocols::ospf::lsa::OspfLsaBody::Network)
//! variant, and `OspfLsa::encode`
//! auto-fills the enclosing LSA `length` and the Fletcher-16 checksum over the
//! header plus this body. The network mask uses a [`Field`] member so
//! `compile()` honors any value the caller pinned.

use core::net::Ipv4Addr;

use crate::field::Field;

// ---------------------------------------------------------------------------
// Fixed lengths (RFC 2328 §A.4.3)
// ---------------------------------------------------------------------------

/// The length of the network mask field, in octets (RFC 2328 §A.4.3).
const OSPF_NETWORK_LSA_MASK_LEN: usize = 4;

/// The length of a single attached-router entry, in octets: a 4-octet Router ID
/// (RFC 2328 §A.4.3).
const OSPF_NETWORK_LSA_ROUTER_LEN: usize = 4;

/// OSPFv2 Network-LSA body (RFC 2328 §A.4.3).
///
/// Carries the network's address mask and the list of attached Router IDs. The
/// `network_mask` is a [`Field`] member so `compile()` honors any value the
/// caller pinned (including a wrong-on-purpose mask). This rides inside an
/// [`OspfLsa`](crate::protocols::ospf::lsa::OspfLsa) as an
/// [`OspfLsaBody::Network`](crate::protocols::ospf::lsa::OspfLsaBody::Network)
/// variant.
#[derive(Debug, Clone)]
pub struct OspfNetworkLsa {
    /// The IP address mask of the network (RFC 2328 §A.4.3); defaults to the
    /// unspecified address.
    network_mask: Field<Ipv4Addr>,
    /// The Router IDs of each attached router, in order (RFC 2328 §A.4.3).
    attached_routers: Vec<Ipv4Addr>,
}

impl OspfNetworkLsa {
    /// Build a Network-LSA body with an unset network mask and an empty
    /// attached-router list.
    pub fn new() -> Self {
        Self {
            network_mask: Field::unset(),
            attached_routers: Vec::new(),
        }
    }

    /// Construct a Network-LSA body from decoded wire fields, marking the network
    /// mask as caller-supplied so re-compilation preserves the decoded values
    /// byte-for-byte (RFC 2328 §A.4.3).
    pub(crate) fn from_decoded_parts(
        network_mask: Ipv4Addr,
        attached_routers: Vec<Ipv4Addr>,
    ) -> Self {
        Self {
            network_mask: Field::user(network_mask),
            attached_routers,
        }
    }

    /// Set the network mask field (RFC 2328 §A.4.3).
    pub fn network_mask(mut self, network_mask: impl Into<Ipv4Addr>) -> Self {
        self.network_mask.set_user(network_mask.into());
        self
    }

    /// Append a single attached-router Router ID to the Network-LSA.
    pub fn attached_router(mut self, router_id: impl Into<Ipv4Addr>) -> Self {
        self.attached_routers.push(router_id.into());
        self
    }

    /// Append several attached-router Router IDs to the Network-LSA.
    pub fn attached_routers<I>(mut self, routers: I) -> Self
    where
        I: IntoIterator<Item = Ipv4Addr>,
    {
        self.attached_routers.extend(routers);
        self
    }

    /// The effective network mask (the caller value, else the unspecified
    /// address).
    pub fn network_mask_value(&self) -> Ipv4Addr {
        self.network_mask
            .value()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// The attached-router Router IDs, in order.
    pub fn attached_routers_value(&self) -> &[Ipv4Addr] {
        &self.attached_routers
    }

    /// A one-line summary of the Network-LSA body for `summary()` /
    /// `inspection_fields()`, like `mask=255.255.255.0 routers=2`.
    pub fn summary(&self) -> String {
        format!(
            "mask={} routers={}",
            self.network_mask_value(),
            self.attached_routers.len()
        )
    }

    /// The on-wire length of this Network-LSA body, in octets: the 4-octet
    /// network mask plus 4 octets per attached router.
    pub(crate) fn encoded_len(&self) -> usize {
        OSPF_NETWORK_LSA_MASK_LEN + self.attached_routers.len() * OSPF_NETWORK_LSA_ROUTER_LEN
    }

    /// Append the RFC 2328 §A.4.3 Network-LSA body to `out`: the 4-octet network
    /// mask followed by each attached Router ID (4 octets each).
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.network_mask_value().octets());
        for router in &self.attached_routers {
            out.extend_from_slice(&router.octets());
        }
    }
}

impl Default for OspfNetworkLsa {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::fletcher16_valid;
    use crate::protocols::ospf::lsa::{
        OspfLsa, OspfLsaBody, OspfLsaHeader, OSPF_LSA_HEADER_LEN, OSPF_LSA_NETWORK,
    };
    use crate::protocols::ospf::packet::link_state_update::OspfLinkStateUpdate;

    /// A Network-LSA built with a network mask and two attached routers encodes
    /// to the RFC 2328 §A.4.3 layout. Wrapped in an `OspfLsa` and a Link State
    /// Update, the body layout matches the hand-computed bytes, the enclosing LSA
    /// `length` auto-fills to cover the 20-octet header plus the body, and the
    /// LSA's Fletcher-16 checksum validates.
    #[test]
    fn ospf_network_lsa_two_attached_routers_round_trips_in_lsu() {
        let network = OspfNetworkLsa::new()
            .network_mask(Ipv4Addr::new(255, 255, 255, 0))
            .attached_router(Ipv4Addr::new(192, 0, 2, 1))
            .attached_router(Ipv4Addr::new(192, 0, 2, 2));

        // The effective fields report the mask and both attached routers.
        assert_eq!(
            network.network_mask_value(),
            Ipv4Addr::new(255, 255, 255, 0)
        );
        assert_eq!(network.attached_routers_value().len(), 2);

        // Encode the body alone and check the exact RFC 2328 §A.4.3 layout.
        let mut body = Vec::new();
        network.encode(&mut body);
        assert_eq!(body.len(), network.encoded_len());

        let expected: Vec<u8> = vec![
            // Network Mask 255.255.255.0
            255, 255, 255, 0, //
            // Attached Router 192.0.2.1
            192, 0, 2, 1, //
            // Attached Router 192.0.2.2
            192, 0, 2, 2,
        ];
        assert_eq!(body, expected);

        // The mask occupies the first 4 octets and each router follows it.
        assert_eq!(&body[0..4], &[255, 255, 255, 0]);
        assert_eq!(&body[4..8], &[192, 0, 2, 1]);
        assert_eq!(&body[8..12], &[192, 0, 2, 2]);

        // Wrap the Network-LSA in an OspfLsa and a Link State Update.
        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_NETWORK)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::Network(network),
        );

        let lsu = OspfLinkStateUpdate::new().lsa(lsa);

        let mut update = Vec::new();
        lsu.encode(&mut update);

        // # LSAs field (octets 0..4) reports one LSA.
        assert_eq!(&update[0..4], &1u32.to_be_bytes());

        // The single LSA follows the count: 20-octet header plus the Network body.
        let lsa_bytes = &update[4..];
        assert_eq!(lsa_bytes.len(), OSPF_LSA_HEADER_LEN + expected.len());

        // The enclosing LSA `length` field (octets 18..20 within the LSA)
        // auto-fills to cover the 20-octet header plus the Network body.
        let expected_lsa_len = (OSPF_LSA_HEADER_LEN + expected.len()) as u16;
        assert_eq!(&lsa_bytes[18..20], &expected_lsa_len.to_be_bytes());

        // The Network body bytes follow the 20-octet header verbatim.
        assert_eq!(&lsa_bytes[OSPF_LSA_HEADER_LEN..], expected.as_slice());

        // The LSA's Fletcher-16 checksum validates over the whole LSA.
        assert!(
            fletcher16_valid(lsa_bytes),
            "auto-filled Fletcher checksum should validate over the Network-LSA"
        );
    }
}
