//! OSPFv2 NSSA-LSA body (RFC 3101 §2.2).
//!
//! NSSA-LSAs (LS type 7) are originated by NSSA (not-so-stubby area) internal
//! AS boundary routers and describe a route to a destination external to the
//! OSPF autonomous system (or a default route), within a not-so-stubby area.
//! Their body layout is identical to the AS-External-LSA (RFC 2328 §A.4.5): the
//! network mask of the advertised destination followed by one or more 12-octet
//! external metric entries, each carrying an E bit and TOS code packed into one
//! octet, a 24-bit metric, a forwarding address, and an external route tag:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Network Mask                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |E|     TOS     |                  metric                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Forwarding address                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      External Route Tag                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              ...                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! What distinguishes an NSSA-LSA from an AS-External-LSA is not the body
//! layout but the LS type ([`OSPF_LSA_NSSA`](crate::protocols::ospf::lsa::OSPF_LSA_NSSA),
//! 7) and the P-bit in the enclosing LSA header's Options field
//! ([`OSPF_OPTIONS_NP`], RFC 3101 §2.5): the P-bit asks the area's NSSA border
//! router to translate the Type-7 LSA into a Type-5 AS-External-LSA when
//! propagating it into the rest of the AS. The P-bit lives on the LSA header,
//! not in this body, so callers set it via
//! [`OspfLsaHeader::options`](crate::protocols::ospf::lsa::OspfLsaHeader::options).
//!
//! Because the body is byte-for-byte the AS-External-LSA layout, [`OspfNssaLsa`]
//! is a thin wrapper around [`OspfAsExternalLsa`], reusing its
//! [`OspfExternalTos`] external metric entries and its encode logic. Like the
//! other LSA bodies, it rides inside an
//! [`OspfLsa`](crate::protocols::ospf::lsa::OspfLsa) as an
//! [`OspfLsaBody::Nssa`](crate::protocols::ospf::lsa::OspfLsaBody::Nssa)
//! variant, and [`OspfLsa::encode`](crate::protocols::ospf::lsa::OspfLsa::encode)
//! auto-fills the enclosing LSA `length` and the Fletcher-16 checksum over the
//! header plus this body.

use core::net::Ipv4Addr;

use super::external::{OspfAsExternalLsa, OspfExternalTos};

// ---------------------------------------------------------------------------
// Options bits (RFC 3101 §2.5)
// ---------------------------------------------------------------------------

/// The NSSA N/P-bit of the LSA header Options field (RFC 3101 §2.5): when set on
/// a Type-7 NSSA-LSA it requests that the NSSA's translating border router
/// propagate the LSA into the rest of the AS as a Type-5 AS-External-LSA.
///
/// This bit lives on the LSA header's Options octet, not in the NSSA-LSA body,
/// so it is set via
/// [`OspfLsaHeader::options`](crate::protocols::ospf::lsa::OspfLsaHeader::options).
pub const OSPF_OPTIONS_NP: u8 = 0x08;

/// OSPFv2 NSSA-LSA body (RFC 3101 §2.2).
///
/// The NSSA-LSA (LS type 7) shares the AS-External-LSA body layout (RFC 2328
/// §A.4.5): the network mask of the advertised external destination plus a list
/// of external metric entries. [`OspfNssaLsa`] is a thin wrapper around
/// [`OspfAsExternalLsa`], reusing its [`OspfExternalTos`] entries and encode
/// logic; the distinguishing NSSA semantics are the LS type (7) and the P-bit
/// in the enclosing LSA header Options field ([`OSPF_OPTIONS_NP`]). This rides
/// inside an [`OspfLsa`](crate::protocols::ospf::lsa::OspfLsa) as an
/// [`OspfLsaBody::Nssa`](crate::protocols::ospf::lsa::OspfLsaBody::Nssa)
/// variant.
#[derive(Debug, Clone)]
pub struct OspfNssaLsa {
    /// The shared AS-External-LSA body (RFC 2328 §A.4.5): the network mask plus
    /// the external metric entries. The network mask is a `Field` so `compile()`
    /// honors any value the caller pinned.
    external: OspfAsExternalLsa,
}

impl OspfNssaLsa {
    /// Build an NSSA-LSA body with an unset network mask and a single default
    /// TOS 0 entry (E1, metric 0, unspecified forwarding address, route tag 0),
    /// matching the AS-External-LSA default (RFC 3101 §2.2, RFC 2328 §A.4.5).
    pub fn new() -> Self {
        Self {
            external: OspfAsExternalLsa::new(),
        }
    }

    /// Construct an NSSA-LSA body from decoded wire fields, marking the network
    /// mask as caller-supplied so re-compilation preserves the decoded values
    /// byte-for-byte (RFC 3101 §2.2, RFC 2328 §A.4.5).
    ///
    /// Used by the NSSA-LSA decode arm.
    #[allow(dead_code)]
    pub(crate) fn from_decoded_parts(
        network_mask: Ipv4Addr,
        entries: Vec<OspfExternalTos>,
    ) -> Self {
        Self {
            external: OspfAsExternalLsa::from_decoded_parts(network_mask, entries),
        }
    }

    /// Set the network mask field (RFC 3101 §2.2, RFC 2328 §A.4.5). For a default
    /// route this is zero.
    pub fn network_mask(mut self, network_mask: impl Into<Ipv4Addr>) -> Self {
        self.external = self.external.network_mask(network_mask);
        self
    }

    /// Set the metric and external metric type (E bit) of the mandatory TOS 0
    /// entry (RFC 3101 §2.2, RFC 2328 §A.4.5).
    ///
    /// The metric is a 24-bit value (valid range `0..=0x00ff_ffff`). `e_bit`
    /// selects the external metric type: `true` for a Type 2 external metric
    /// (E2), `false` for a Type 1 external metric (E1).
    pub fn metric(mut self, metric: u32, e_bit: bool) -> Self {
        self.external = self.external.metric(metric, e_bit);
        self
    }

    /// Append an external metric entry to the NSSA-LSA (RFC 3101 §2.2, RFC 2328
    /// §A.4.5).
    ///
    /// The metric is a 24-bit value (valid range `0..=0x00ff_ffff`); the TOS
    /// code is packed into the low 7 bits of the combined octet.
    pub fn external_entry(
        mut self,
        e_bit: bool,
        tos: u8,
        metric: u32,
        forwarding_address: impl Into<Ipv4Addr>,
        external_route_tag: u32,
    ) -> Self {
        self.external = self
            .external
            .external_entry(e_bit, tos, metric, forwarding_address, external_route_tag);
        self
    }

    /// The effective network mask (the caller value, else the unspecified
    /// address).
    pub fn network_mask_value(&self) -> Ipv4Addr {
        self.external.network_mask_value()
    }

    /// The external metric entries, in order.
    pub fn entries_value(&self) -> &[OspfExternalTos] {
        self.external.entries_value()
    }

    /// A one-line summary of the NSSA-LSA body for `summary()` /
    /// `inspection_fields()`, like `mask=255.255.255.0 metric=10 type=E2 tos=1`.
    pub fn summary(&self) -> String {
        self.external.summary()
    }

    /// The on-wire length of this NSSA-LSA body, in octets: the 4-octet network
    /// mask plus 12 octets per external metric entry (RFC 3101 §2.2, RFC 2328
    /// §A.4.5).
    pub(crate) fn encoded_len(&self) -> usize {
        self.external.encoded_len()
    }

    /// Append the RFC 3101 §2.2 NSSA-LSA body to `out`: identical to the
    /// AS-External-LSA layout (RFC 2328 §A.4.5) — the 4-octet network mask
    /// followed by each external metric entry as a 1-octet combined E/TOS octet,
    /// a 3-octet (24-bit) big-endian metric, a 4-octet forwarding address, and a
    /// 4-octet external route tag.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        self.external.encode(out);
    }
}

impl Default for OspfNssaLsa {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::fletcher16_valid;
    use crate::protocols::ospf::lsa::{
        OspfLsa, OspfLsaBody, OspfLsaHeader, OSPF_AS_EXTERNAL_FLAG_E, OSPF_LSA_HEADER_LEN,
        OSPF_LSA_NSSA,
    };
    use crate::protocols::ospf::packet::link_state_update::OspfLinkStateUpdate;

    /// An NSSA-LSA built with a network mask and one E2 metric entry encodes to
    /// the RFC 3101 §2.2 layout (identical to the AS-External-LSA, RFC 2328
    /// §A.4.5): the E bit and TOS pack into the first octet, the metric
    /// serializes as three big-endian octets, and the forwarding address and
    /// external route tag follow. Wrapped in an `OspfLsa` (LS type 7) with the
    /// P-bit set in the header Options field, inside a Link State Update, the
    /// body layout matches the hand-computed bytes, the P-bit survives in the
    /// header Options octet, the enclosing LSA `length` auto-fills to cover the
    /// 20-octet header plus the body, and the LSA's Fletcher-16 checksum
    /// validates.
    #[test]
    fn ospf_nssa_lsa_with_p_bit_round_trips_in_lsu() {
        // 0x0a0b0c is a 24-bit metric that exercises all three octets.
        let metric = 0x000a_0b0c;

        // Build a single-entry NSSA-LSA body (the default TOS 0 entry replaced
        // via metric()) so the hand-computed layout below is unambiguous.
        let nssa = OspfNssaLsa::new()
            .network_mask(Ipv4Addr::new(255, 255, 255, 0))
            .metric(metric, true);

        // metric(.., true) sets the TOS 0 entry to E2 with the given metric.
        assert_eq!(nssa.network_mask_value(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(nssa.entries_value().len(), 1);
        assert!(nssa.entries_value()[0].e_bit_value());
        assert_eq!(nssa.entries_value()[0].tos_value(), 0);
        assert_eq!(nssa.entries_value()[0].metric_value(), metric);

        // Encode the body alone and check the exact RFC 3101 §2.2 / RFC 2328
        // §A.4.5 layout.
        let mut body = Vec::new();
        nssa.encode(&mut body);
        assert_eq!(body.len(), nssa.encoded_len());

        let expected: Vec<u8> = vec![
            // Network Mask 255.255.255.0
            255, 255, 255, 0, //
            // E bit set | TOS 0 = 0x80
            0x80, //
            // metric 0x0a0b0c as three big-endian octets
            0x0a, 0x0b, 0x0c, //
            // Forwarding address 0.0.0.0 (unspecified, the default)
            0, 0, 0, 0, //
            // External route tag 0
            0, 0, 0, 0,
        ];
        assert_eq!(body, expected);

        // The mask occupies the first 4 octets; the entry follows it.
        assert_eq!(&body[0..4], &[255, 255, 255, 0]);
        // The combined octet packs the E bit (0x80) and TOS 0 (low 7 bits = 0).
        assert_eq!(body[4], OSPF_AS_EXTERNAL_FLAG_E);
        assert_eq!(body[4] & 0x7f, 0);
        // The 24-bit metric as three octets.
        assert_eq!(&body[5..8], &[0x0a, 0x0b, 0x0c]);

        // Wrap the NSSA-LSA in an OspfLsa (LS type 7) with the P-bit set in the
        // header Options field, and a Link State Update.
        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_NSSA)
                .options(OSPF_OPTIONS_NP)
                .link_state_id(Ipv4Addr::new(198, 51, 100, 0))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::Nssa(nssa),
        );

        let lsu = OspfLinkStateUpdate::new().lsa(lsa);

        let mut update = Vec::new();
        lsu.encode(&mut update);

        // # LSAs field (octets 0..4) reports one LSA.
        assert_eq!(&update[0..4], &1u32.to_be_bytes());

        // The single LSA follows the count: 20-octet header plus the body.
        let lsa_bytes = &update[4..];
        assert_eq!(lsa_bytes.len(), OSPF_LSA_HEADER_LEN + expected.len());

        // The LSA header carries the LS type 7 (octet 3) and the P-bit in the
        // Options octet (octet 2).
        assert_eq!(lsa_bytes[3], OSPF_LSA_NSSA);
        assert_eq!(lsa_bytes[2], OSPF_OPTIONS_NP);
        assert_eq!(lsa_bytes[2] & OSPF_OPTIONS_NP, OSPF_OPTIONS_NP);

        // The enclosing LSA `length` field (octets 18..20 within the LSA)
        // auto-fills to cover the 20-octet header plus the body.
        let expected_lsa_len = (OSPF_LSA_HEADER_LEN + expected.len()) as u16;
        assert_eq!(&lsa_bytes[18..20], &expected_lsa_len.to_be_bytes());

        // The body bytes follow the 20-octet header verbatim.
        assert_eq!(&lsa_bytes[OSPF_LSA_HEADER_LEN..], expected.as_slice());

        // The LSA's Fletcher-16 checksum validates over the whole LSA.
        assert!(
            fletcher16_valid(lsa_bytes),
            "auto-filled Fletcher checksum should validate over the NSSA-LSA"
        );
    }
}
