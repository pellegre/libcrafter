//! OSPFv2 AS-External-LSA body (RFC 2328 §A.4.5).
//!
//! AS-External-LSAs (LS type 5) are originated by AS boundary routers and
//! describe a route to a destination external to the OSPF autonomous system
//! (or a default route). The body follows the 20-octet [`OspfLsaHeader`] and is
//! the network mask of the advertised destination followed by one or more
//! 12-octet external metric entries, each carrying an E bit and TOS code packed
//! into one octet, a 24-bit metric, a forwarding address, and an external route
//! tag:
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
//! The E bit (the high bit, [`OSPF_AS_EXTERNAL_FLAG_E`]) of the combined octet
//! selects the external metric type: clear is a Type 1 external metric (E1,
//! comparable to the link-state metric), set is a Type 2 external metric (E2,
//! considered larger than any link-state path). The low 7 bits hold the TOS
//! code (RFC 2328 §A.4.5).
//!
//! Like the other LSA bodies, [`OspfAsExternalLsa`] rides inside an
//! [`OspfLsa`](crate::protocols::ospf::lsa::OspfLsa) as an
//! [`OspfLsaBody::AsExternal`](crate::protocols::ospf::lsa::OspfLsaBody::AsExternal)
//! variant, and [`OspfLsa::encode`](crate::protocols::ospf::lsa::OspfLsa::encode)
//! auto-fills the enclosing LSA `length` and the Fletcher-16 checksum over the
//! header plus this body. The network mask uses a [`Field`] member so
//! `compile()` honors any value the caller pinned.

use core::net::Ipv4Addr;

use crate::field::Field;

// ---------------------------------------------------------------------------
// Flags and fixed lengths (RFC 2328 §A.4.5)
// ---------------------------------------------------------------------------

/// The E bit of the combined TOS octet (RFC 2328 §A.4.5): when set, the metric
/// is a Type 2 external metric (E2); when clear, a Type 1 external metric (E1).
/// It is the high bit of the first octet of each external metric entry.
pub const OSPF_AS_EXTERNAL_FLAG_E: u8 = 0x80;

/// The length of the network mask field, in octets (RFC 2328 §A.4.5).
const OSPF_AS_EXTERNAL_LSA_MASK_LEN: usize = 4;

/// The length of a single external metric entry, in octets: a 1-octet combined
/// E/TOS octet, a 3-octet (24-bit) metric, a 4-octet forwarding address, and a
/// 4-octet external route tag (RFC 2328 §A.4.5).
const OSPF_AS_EXTERNAL_LSA_ENTRY_LEN: usize = 12;

/// The widest value the 24-bit AS-External-LSA metric can carry (RFC 2328
/// §A.4.5): `0x00ff_ffff`.
const OSPF_AS_EXTERNAL_LSA_METRIC_MAX: u32 = 0x00ff_ffff;

/// A single external metric entry in an AS-External-LSA body (RFC 2328 §A.4.5).
///
/// Each entry pairs a TOS code and external metric type (the E bit) with the
/// cost of the advertised route for that type of service, the forwarding
/// address to which traffic should be sent, and an external route tag attached
/// by the originating ASBR. The metric is a 24-bit value on the wire, so the
/// valid range is `0..=0x00ff_ffff` (16,777,215); values wider than 24 bits are
/// masked to the low 24 bits on encode.
#[derive(Debug, Clone)]
pub struct OspfExternalTos {
    /// The external metric type: `true` selects a Type 2 external metric (E2),
    /// `false` a Type 1 external metric (E1) (RFC 2328 §A.4.5). Packed into the
    /// high bit ([`OSPF_AS_EXTERNAL_FLAG_E`]) of the combined octet.
    e_bit: bool,
    /// The IP type-of-service this metric applies to (RFC 2328 §A.4.5). Packed
    /// into the low 7 bits of the combined octet, so only `0..=0x7f` is
    /// representable on the wire.
    tos: u8,
    /// The cost of the advertised route for this type of service (RFC 2328
    /// §A.4.5). A 24-bit value: the valid range is `0..=0x00ff_ffff`.
    metric: u32,
    /// The forwarding address to which packets for the advertised destination
    /// should be forwarded (RFC 2328 §A.4.5); the unspecified address means
    /// traffic is forwarded to the originating ASBR.
    forwarding_address: Ipv4Addr,
    /// A 32-bit external route tag attached to the LSA, not used by OSPF itself
    /// (RFC 2328 §A.4.5).
    external_route_tag: u32,
}

impl OspfExternalTos {
    /// Build an external metric entry from its E bit, TOS code, 24-bit metric,
    /// forwarding address, and external route tag.
    ///
    /// The metric is a 24-bit value on the wire (valid range `0..=0x00ff_ffff`);
    /// any higher bits are dropped when the entry is encoded. The TOS code is
    /// packed into the low 7 bits of the combined octet, so only `0..=0x7f` is
    /// representable on the wire.
    pub fn new(
        e_bit: bool,
        tos: u8,
        metric: u32,
        forwarding_address: impl Into<Ipv4Addr>,
        external_route_tag: u32,
    ) -> Self {
        Self {
            e_bit,
            tos,
            metric,
            forwarding_address: forwarding_address.into(),
            external_route_tag,
        }
    }

    /// Whether the E bit is set: `true` is a Type 2 external metric (E2),
    /// `false` a Type 1 external metric (E1).
    pub fn e_bit_value(&self) -> bool {
        self.e_bit
    }

    /// The IP type-of-service this metric applies to.
    pub fn tos_value(&self) -> u8 {
        self.tos
    }

    /// The cost of the advertised route for this type of service (a 24-bit
    /// value).
    pub fn metric_value(&self) -> u32 {
        self.metric
    }

    /// The forwarding address for the advertised destination.
    pub fn forwarding_address_value(&self) -> Ipv4Addr {
        self.forwarding_address
    }

    /// The external route tag attached to the LSA.
    pub fn external_route_tag_value(&self) -> u32 {
        self.external_route_tag
    }
}

/// OSPFv2 AS-External-LSA body (RFC 2328 §A.4.5).
///
/// Carries the network mask of the advertised external destination and a list
/// of external metric entries. The `network_mask` is a [`Field`] member so
/// `compile()` honors any value the caller pinned (including a wrong-on-purpose
/// mask, or the zero mask used by a default route). This rides inside an
/// [`OspfLsa`](crate::protocols::ospf::lsa::OspfLsa) as an
/// [`OspfLsaBody::AsExternal`](crate::protocols::ospf::lsa::OspfLsaBody::AsExternal)
/// variant.
#[derive(Debug, Clone)]
pub struct OspfAsExternalLsa {
    /// The IP address mask of the advertised destination network (RFC 2328
    /// §A.4.5); defaults to the unspecified address.
    network_mask: Field<Ipv4Addr>,
    /// The external metric entries, in order (RFC 2328 §A.4.5); the first entry
    /// is the mandatory TOS 0 metric.
    entries: Vec<OspfExternalTos>,
}

impl OspfAsExternalLsa {
    /// Build an AS-External-LSA body with an unset network mask and a single
    /// default TOS 0 entry (E1, metric 0, unspecified forwarding address, route
    /// tag 0). RFC 2328 §A.4.5 requires at least the TOS 0 metric.
    pub fn new() -> Self {
        Self {
            network_mask: Field::unset(),
            entries: vec![OspfExternalTos::new(false, 0, 0, Ipv4Addr::UNSPECIFIED, 0)],
        }
    }

    /// Construct an AS-External-LSA body from decoded wire fields, marking the
    /// network mask as caller-supplied so re-compilation preserves the decoded
    /// values byte-for-byte (RFC 2328 §A.4.5).
    ///
    /// Used by the AS-External-LSA decode arm added in a later step.
    #[allow(dead_code)]
    pub(crate) fn from_decoded_parts(
        network_mask: Ipv4Addr,
        entries: Vec<OspfExternalTos>,
    ) -> Self {
        Self {
            network_mask: Field::user(network_mask),
            entries,
        }
    }

    /// Set the network mask field (RFC 2328 §A.4.5). For a default route this is
    /// zero.
    pub fn network_mask(mut self, network_mask: impl Into<Ipv4Addr>) -> Self {
        self.network_mask.set_user(network_mask.into());
        self
    }

    /// Set the metric and external metric type (E bit) of the mandatory TOS 0
    /// entry (RFC 2328 §A.4.5).
    ///
    /// The metric is a 24-bit value (valid range `0..=0x00ff_ffff`). `e_bit`
    /// selects the external metric type: `true` for a Type 2 external metric
    /// (E2), `false` for a Type 1 external metric (E1). If the body has no
    /// entries (e.g. after a caller cleared them) a fresh TOS 0 entry is
    /// created; otherwise the first entry's metric and E bit are replaced and
    /// its TOS code is reset to 0.
    pub fn metric(mut self, metric: u32, e_bit: bool) -> Self {
        match self.entries.first_mut() {
            Some(entry) => {
                entry.e_bit = e_bit;
                entry.tos = 0;
                entry.metric = metric;
            }
            None => self
                .entries
                .push(OspfExternalTos::new(e_bit, 0, metric, Ipv4Addr::UNSPECIFIED, 0)),
        }
        self
    }

    /// Append an external metric entry to the AS-External-LSA (RFC 2328
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
        self.entries.push(OspfExternalTos::new(
            e_bit,
            tos,
            metric,
            forwarding_address,
            external_route_tag,
        ));
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

    /// The external metric entries, in order.
    pub fn entries_value(&self) -> &[OspfExternalTos] {
        &self.entries
    }

    /// A one-line summary of the AS-External-LSA body for `summary()` /
    /// `inspection_fields()`, like `mask=255.255.255.0 metric=10 type=E2 tos=1`.
    pub fn summary(&self) -> String {
        let (metric, metric_type) = match self.entries.first() {
            Some(entry) => (
                (entry.metric & OSPF_AS_EXTERNAL_LSA_METRIC_MAX).to_string(),
                if entry.e_bit { "E2" } else { "E1" },
            ),
            None => ("none".to_string(), "E1"),
        };
        format!(
            "mask={} metric={} type={} tos={}",
            self.network_mask_value(),
            metric,
            metric_type,
            self.entries.len(),
        )
    }

    /// The on-wire length of this AS-External-LSA body, in octets: the 4-octet
    /// network mask plus 12 octets per external metric entry.
    pub(crate) fn encoded_len(&self) -> usize {
        OSPF_AS_EXTERNAL_LSA_MASK_LEN + self.entries.len() * OSPF_AS_EXTERNAL_LSA_ENTRY_LEN
    }

    /// Append the RFC 2328 §A.4.5 AS-External-LSA body to `out`: the 4-octet
    /// network mask followed by each external metric entry as a 1-octet combined
    /// E/TOS octet, a 3-octet (24-bit) big-endian metric, a 4-octet forwarding
    /// address, and a 4-octet external route tag.
    ///
    /// The combined octet packs the E bit ([`OSPF_AS_EXTERNAL_FLAG_E`]) and the
    /// low 7 bits of the TOS code; metrics wider than 24 bits are masked to the
    /// low 24 bits.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.network_mask_value().octets());
        for entry in &self.entries {
            let combined =
                (if entry.e_bit { OSPF_AS_EXTERNAL_FLAG_E } else { 0 }) | (entry.tos & 0x7f);
            out.push(combined);
            let metric = entry.metric & OSPF_AS_EXTERNAL_LSA_METRIC_MAX;
            out.push((metric >> 16) as u8);
            out.push((metric >> 8) as u8);
            out.push(metric as u8);
            out.extend_from_slice(&entry.forwarding_address.octets());
            out.extend_from_slice(&entry.external_route_tag.to_be_bytes());
        }
    }
}

impl Default for OspfAsExternalLsa {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::fletcher16_valid;
    use crate::protocols::ospf::lsa::{
        OspfLsa, OspfLsaBody, OspfLsaHeader, OSPF_LSA_AS_EXTERNAL, OSPF_LSA_HEADER_LEN,
    };
    use crate::protocols::ospf::packet::link_state_update::OspfLinkStateUpdate;

    /// An AS-External-LSA built with a network mask and one E2 metric entry
    /// encodes to the RFC 2328 §A.4.5 layout: the E bit and TOS pack into the
    /// first octet, the metric serializes as three big-endian octets, and the
    /// forwarding address and external route tag follow. Wrapped in an `OspfLsa`
    /// and a Link State Update, the body layout matches the hand-computed bytes,
    /// the enclosing LSA `length` auto-fills to cover the 20-octet header plus
    /// the body, and the LSA's Fletcher-16 checksum validates.
    #[test]
    fn ospf_as_external_lsa_e2_entry_round_trips_in_lsu() {
        // 0x0a0b0c is a 24-bit metric that exercises all three octets; TOS 5 sits
        // in the low 7 bits alongside the E bit.
        let metric = 0x000a_0b0c;
        let external = OspfAsExternalLsa::new()
            .network_mask(Ipv4Addr::new(255, 255, 255, 0))
            .external_entry(
                true,
                5,
                metric,
                Ipv4Addr::new(192, 0, 2, 9),
                0x1234_5678,
            );

        // The default TOS 0 entry plus the appended entry.
        assert_eq!(external.network_mask_value(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(external.entries_value().len(), 2);

        // The appended entry carries the E bit, TOS, metric, forwarding address,
        // and route tag we set.
        let entry = &external.entries_value()[1];
        assert!(entry.e_bit_value());
        assert_eq!(entry.tos_value(), 5);
        assert_eq!(entry.metric_value(), metric);
        assert_eq!(entry.forwarding_address_value(), Ipv4Addr::new(192, 0, 2, 9));
        assert_eq!(entry.external_route_tag_value(), 0x1234_5678);

        // Build a single-entry body (default TOS 0 entry replaced via metric())
        // so the hand-computed layout below is unambiguous.
        let single = OspfAsExternalLsa::new()
            .network_mask(Ipv4Addr::new(255, 255, 255, 0))
            .metric(metric, true);
        // metric(.., true) sets the TOS 0 entry to E2 with the given metric.
        assert_eq!(single.entries_value().len(), 1);
        assert!(single.entries_value()[0].e_bit_value());
        assert_eq!(single.entries_value()[0].tos_value(), 0);
        assert_eq!(single.entries_value()[0].metric_value(), metric);

        // Encode the single-entry body alone and check the exact RFC 2328 §A.4.5
        // layout.
        let mut body = Vec::new();
        single.encode(&mut body);
        assert_eq!(body.len(), single.encoded_len());

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
        assert_eq!(body[4] & OSPF_AS_EXTERNAL_FLAG_E, OSPF_AS_EXTERNAL_FLAG_E);
        assert_eq!(body[4] & 0x7f, 0);
        // The 24-bit metric as three octets.
        assert_eq!(&body[5..8], &[0x0a, 0x0b, 0x0c]);
        // Forwarding address and route tag.
        assert_eq!(&body[8..12], &[0, 0, 0, 0]);
        assert_eq!(&body[12..16], &[0, 0, 0, 0]);

        // Also check the E bit + TOS packing of a non-zero TOS entry.
        let mut packed = Vec::new();
        OspfAsExternalLsa::new()
            .network_mask(Ipv4Addr::new(255, 255, 255, 255))
            .external_entry(true, 5, metric, Ipv4Addr::new(192, 0, 2, 9), 0x1234_5678)
            .encode(&mut packed);
        // The second entry's combined octet (after mask + first default entry).
        let second_octet = packed[4 + OSPF_AS_EXTERNAL_LSA_ENTRY_LEN];
        assert_eq!(second_octet, OSPF_AS_EXTERNAL_FLAG_E | 5);
        assert_eq!(second_octet & 0x7f, 5);
        // Forwarding address and external route tag of the appended entry.
        let entry_start = 4 + 2 * OSPF_AS_EXTERNAL_LSA_ENTRY_LEN - OSPF_AS_EXTERNAL_LSA_ENTRY_LEN;
        assert_eq!(
            &packed[entry_start + 4..entry_start + 8],
            &Ipv4Addr::new(192, 0, 2, 9).octets()
        );
        assert_eq!(
            &packed[entry_start + 8..entry_start + 12],
            &0x1234_5678u32.to_be_bytes()
        );

        // Wrap the single-entry AS-External-LSA in an OspfLsa (type 5) and a Link
        // State Update.
        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_AS_EXTERNAL)
                .link_state_id(Ipv4Addr::new(198, 51, 100, 0))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::AsExternal(single),
        );

        let lsu = OspfLinkStateUpdate::new().lsa(lsa);

        let mut update = Vec::new();
        lsu.encode(&mut update);

        // # LSAs field (octets 0..4) reports one LSA.
        assert_eq!(&update[0..4], &1u32.to_be_bytes());

        // The single LSA follows the count: 20-octet header plus the body.
        let lsa_bytes = &update[4..];
        assert_eq!(lsa_bytes.len(), OSPF_LSA_HEADER_LEN + expected.len());

        // The enclosing LSA `length` field (octets 18..20 within the LSA)
        // auto-fills to cover the 20-octet header plus the body.
        let expected_lsa_len = (OSPF_LSA_HEADER_LEN + expected.len()) as u16;
        assert_eq!(&lsa_bytes[18..20], &expected_lsa_len.to_be_bytes());

        // The body bytes follow the 20-octet header verbatim.
        assert_eq!(&lsa_bytes[OSPF_LSA_HEADER_LEN..], expected.as_slice());

        // The LSA's Fletcher-16 checksum validates over the whole LSA.
        assert!(
            fletcher16_valid(lsa_bytes),
            "auto-filled Fletcher checksum should validate over the AS-External-LSA"
        );
    }
}
