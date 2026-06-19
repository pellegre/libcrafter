//! OSPFv2 AS-External-LSA body (RFC 2328 §A.4.5).
//!
//! AS-External-LSAs (LS type 5) are originated by AS boundary routers and
//! describe a route to a destination external to the OSPF autonomous system
//! (or a default route). The body follows the 20-octet
//! [`OspfLsaHeader`](crate::protocols::ospf::lsa::OspfLsaHeader) and is
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
//! variant, and `OspfLsa::encode`
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
    /// Used by the AS-External-LSA decode arm.
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
            None => self.entries.push(OspfExternalTos::new(
                e_bit,
                0,
                metric,
                Ipv4Addr::UNSPECIFIED,
                0,
            )),
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
            let combined = (if entry.e_bit {
                OSPF_AS_EXTERNAL_FLAG_E
            } else {
                0
            }) | (entry.tos & 0x7f);
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
            .external_entry(true, 5, metric, Ipv4Addr::new(192, 0, 2, 9), 0x1234_5678);

        // The default TOS 0 entry plus the appended entry.
        assert_eq!(
            external.network_mask_value(),
            Ipv4Addr::new(255, 255, 255, 0)
        );
        assert_eq!(external.entries_value().len(), 2);

        // The appended entry carries the E bit, TOS, metric, forwarding address,
        // and route tag we set.
        let entry = &external.entries_value()[1];
        assert!(entry.e_bit_value());
        assert_eq!(entry.tos_value(), 5);
        assert_eq!(entry.metric_value(), metric);
        assert_eq!(
            entry.forwarding_address_value(),
            Ipv4Addr::new(192, 0, 2, 9)
        );
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

    /// An AS-External-LSA carrying three external metric entries — mixing Type 1
    /// (E1, E bit clear) and Type 2 (E2, E bit set) metrics with distinct TOS
    /// values, forwarding addresses, and external route tags — round-trips
    /// byte-for-byte through a full build/compile/decode cycle, and every decoded
    /// entry matches the built entry in order (RFC 2328 §A.4.5). This exercises
    /// the 12-octet entry stride and the independent E-bit / 7-bit-TOS packing
    /// across multiple per-TOS entries.
    #[test]
    fn ospf_as_external_lsa_three_entries_round_trip_byte_for_byte() {
        use crate::protocols::ospf::decode::append_ospf_packet;
        use crate::protocols::ospf::{OspfBody, Ospfv2};
        use crate::Packet;

        // Build the body from three appended entries, replacing the seeded
        // default TOS 0 entry first so the entry list is exactly the three we
        // describe below. `metric(..)` mutates only the first (TOS 0) entry; the
        // two `external_entry(..)` calls append after it without clobbering it.
        //
        //   entry 0: E1 (E bit clear), TOS 0, metric 0x0000_0a,  fwd 192.0.2.10, tag 0x0000_0001
        //   entry 1: E2 (E bit set),   TOS 1, metric 0x00b1_b2b3, fwd 192.0.2.11, tag 0xdead_beef
        //   entry 2: E1 (E bit clear), TOS 2, metric 0x00ff_ffff, fwd 192.0.2.12, tag 0x1234_5678
        let external = OspfAsExternalLsa::new()
            .network_mask(Ipv4Addr::new(255, 255, 255, 0))
            .metric(0x0000_000a, false)
            .external_entry(
                true,
                1,
                0x00b1_b2b3,
                Ipv4Addr::new(192, 0, 2, 11),
                0xdead_beef,
            )
            .external_entry(
                false,
                2,
                0x00ff_ffff,
                Ipv4Addr::new(192, 0, 2, 12),
                0x1234_5678,
            );

        // The first entry's TOS code stays 0 (metric(..) resets it) and the two
        // later entries keep their own TOS values: metric(..) did not clobber
        // them.
        let built = external.entries_value();
        assert_eq!(built.len(), 3);
        assert!(!built[0].e_bit_value());
        assert_eq!(built[0].tos_value(), 0);
        assert_eq!(built[0].metric_value(), 0x0000_000a);
        assert!(built[1].e_bit_value());
        assert_eq!(built[1].tos_value(), 1);
        assert_eq!(built[2].tos_value(), 2);

        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_AS_EXTERNAL)
                .link_state_id(Ipv4Addr::new(198, 51, 100, 0))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::AsExternal(external.clone()),
        );

        let bytes = Packet::from_layer(
            Ospfv2::link_state_update()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_link_state_update(|u| {
                    *u = u.clone().lsa(lsa.clone());
                }),
        )
        .compile()
        .expect("a Link State Update with a three-entry AS-External-LSA compiles");

        let decoded = append_ospf_packet(Packet::new(), bytes.as_bytes())
            .expect("the Link State Update decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");

        let lsu = match &ospf.body {
            OspfBody::LinkStateUpdate(lsu) => lsu,
            other => panic!("expected a typed Link State Update body, got {other:?}"),
        };
        let decoded_lsas = lsu.lsas_value();
        assert_eq!(decoded_lsas.len(), 1);
        assert_eq!(decoded_lsas[0].header.ls_type_value(), OSPF_LSA_AS_EXTERNAL);

        let decoded_external = match &decoded_lsas[0].body {
            OspfLsaBody::AsExternal(external) => external,
            other => panic!("expected a typed AS-External-LSA body, got {other:?}"),
        };
        assert_eq!(
            decoded_external.network_mask_value(),
            Ipv4Addr::new(255, 255, 255, 0)
        );

        // Every decoded entry matches the built entry, in order: the E bit, the
        // 7-bit TOS code, the 24-bit metric, the forwarding address, and the
        // external route tag all round-trip independently across the three
        // 12-octet entries.
        let decoded_entries = decoded_external.entries_value();
        assert_eq!(decoded_entries.len(), built.len());
        for (decoded_entry, built_entry) in decoded_entries.iter().zip(built.iter()) {
            assert_eq!(decoded_entry.e_bit_value(), built_entry.e_bit_value());
            assert_eq!(decoded_entry.tos_value(), built_entry.tos_value());
            assert_eq!(decoded_entry.metric_value(), built_entry.metric_value());
            assert_eq!(
                decoded_entry.forwarding_address_value(),
                built_entry.forwarding_address_value()
            );
            assert_eq!(
                decoded_entry.external_route_tag_value(),
                built_entry.external_route_tag_value()
            );
        }

        // The decoded Link State Update re-compiles byte-for-byte.
        let recompiled = decoded
            .compile()
            .expect("decoded Link State Update re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// An external metric entry whose raw TOS octet has a value greater than
    /// `0x7f` is encoded with only the low 7 bits (RFC 2328 §A.4.5 reserves the
    /// high bit for the E bit), so the high bits are dropped on the wire and the
    /// decoded entry reports the masked TOS value. The encode/decode round-trip
    /// is byte-for-byte stable, and the honored-override discipline is preserved:
    /// `compile()` does not refuse the wide value, it just emits the 7-bit field
    /// the wire layout allows.
    #[test]
    fn ospf_as_external_lsa_tos_above_seven_bits_round_trips_masked() {
        use crate::protocols::ospf::decode::append_ospf_packet;
        use crate::protocols::ospf::{OspfBody, Ospfv2};
        use crate::Packet;

        // TOS 0xff with the E bit clear: the wire octet can hold only the low 7
        // bits, so 0xff & 0x7f = 0x7f is what survives, independent of the E bit.
        let raw_tos = 0xff_u8;
        let masked_tos = raw_tos & 0x7f;

        let external = OspfAsExternalLsa::new()
            .network_mask(Ipv4Addr::new(255, 255, 255, 0))
            .metric(0x0000_002a, false)
            .external_entry(false, raw_tos, 0x0000_0064, Ipv4Addr::new(192, 0, 2, 13), 0);

        // The appended entry retains the caller's raw TOS value in the typed
        // builder (an honored override); only the wire octet is 7 bits wide.
        assert_eq!(external.entries_value()[1].tos_value(), raw_tos);

        // Encode the body directly: the appended entry's combined octet keeps the
        // E bit clear and packs only the low 7 bits of the TOS.
        let mut body = Vec::new();
        external.encode(&mut body);
        let entry_octet = body[OSPF_AS_EXTERNAL_LSA_MASK_LEN + OSPF_AS_EXTERNAL_LSA_ENTRY_LEN];
        assert_eq!(entry_octet & OSPF_AS_EXTERNAL_FLAG_E, 0);
        assert_eq!(entry_octet & 0x7f, masked_tos);
        assert_eq!(entry_octet, masked_tos);

        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_AS_EXTERNAL)
                .link_state_id(Ipv4Addr::new(198, 51, 100, 0))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::AsExternal(external),
        );

        let bytes = Packet::from_layer(
            Ospfv2::link_state_update()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_link_state_update(|u| {
                    *u = u.clone().lsa(lsa.clone());
                }),
        )
        .compile()
        .expect("a Link State Update with a wide-TOS AS-External-LSA compiles");

        let decoded = append_ospf_packet(Packet::new(), bytes.as_bytes())
            .expect("the Link State Update decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        let lsu = match &ospf.body {
            OspfBody::LinkStateUpdate(lsu) => lsu,
            other => panic!("expected a typed Link State Update body, got {other:?}"),
        };
        let decoded_external = match &lsu.lsas_value()[0].body {
            OspfLsaBody::AsExternal(external) => external,
            other => panic!("expected a typed AS-External-LSA body, got {other:?}"),
        };

        // The decoded appended entry reports the masked 7-bit TOS value, the E bit
        // is clear, and the rest of the entry survives.
        let decoded_entry = &decoded_external.entries_value()[1];
        assert!(!decoded_entry.e_bit_value());
        assert_eq!(decoded_entry.tos_value(), masked_tos);
        assert_eq!(decoded_entry.metric_value(), 0x0000_0064);
        assert_eq!(
            decoded_entry.forwarding_address_value(),
            Ipv4Addr::new(192, 0, 2, 13)
        );

        // The decoded Link State Update re-compiles byte-for-byte.
        let recompiled = decoded
            .compile()
            .expect("decoded Link State Update re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }
}
