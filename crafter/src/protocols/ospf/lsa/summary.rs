//! OSPFv2 Summary-LSA body (RFC 2328 §A.4.4).
//!
//! Summary-LSAs are originated by area border routers. There are two LS types
//! that share the identical body layout: the type 3 Summary-LSA describes a
//! route to an IP network, and the type 4 Summary-LSA describes a route to an
//! AS boundary router (for type 4 the Network Mask field is not meaningful and
//! is set to zero). The body follows the 20-octet
//! [`OspfLsaHeader`](crate::protocols::ospf::lsa::OspfLsaHeader) and is the
//! network mask followed by one or more TOS/metric entries, each carrying a TOS
//! code and a 24-bit metric:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Network Mask                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      TOS      |                  metric                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              ...                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Like the other LSA bodies, [`OspfSummaryLsa`] rides inside an
//! [`OspfLsa`](crate::protocols::ospf::lsa::OspfLsa) as an
//! [`OspfLsaBody::Summary`](crate::protocols::ospf::lsa::OspfLsaBody::Summary)
//! variant (used for both LS type 3 and LS type 4), and
//! `OspfLsa::encode` auto-fills
//! the enclosing LSA `length` and the Fletcher-16 checksum over the header plus
//! this body. The network mask uses a [`Field`] member so `compile()` honors any
//! value the caller pinned.

use core::net::Ipv4Addr;

use crate::field::Field;

// ---------------------------------------------------------------------------
// Fixed lengths (RFC 2328 §A.4.4)
// ---------------------------------------------------------------------------

/// The length of the network mask field, in octets (RFC 2328 §A.4.4).
const OSPF_SUMMARY_LSA_MASK_LEN: usize = 4;

/// The length of a single TOS/metric entry, in octets: a 1-octet TOS code plus a
/// 3-octet (24-bit) metric (RFC 2328 §A.4.4).
const OSPF_SUMMARY_LSA_TOS_LEN: usize = 4;

/// The widest value the 24-bit Summary-LSA metric can carry (RFC 2328 §A.4.4):
/// `0x00ff_ffff`.
const OSPF_SUMMARY_LSA_METRIC_MAX: u32 = 0x00ff_ffff;

/// A single TOS/metric entry in a Summary-LSA body (RFC 2328 §A.4.4).
///
/// Each entry pairs a TOS code with the cost of the advertised route for that
/// type of service. The metric is a 24-bit value on the wire, so the valid range
/// is `0..=0x00ff_ffff` (16,777,215); values wider than 24 bits are masked to
/// the low 24 bits on encode.
#[derive(Debug, Clone)]
pub struct OspfSummaryTos {
    /// The IP type-of-service this metric applies to (RFC 2328 §A.4.4).
    tos: u8,
    /// The cost of the advertised route for this type of service (RFC 2328
    /// §A.4.4). A 24-bit value: the valid range is `0..=0x00ff_ffff`.
    metric: u32,
}

impl OspfSummaryTos {
    /// Build a TOS/metric entry pairing a TOS code with its 24-bit metric.
    ///
    /// The metric is a 24-bit value on the wire (valid range `0..=0x00ff_ffff`);
    /// any higher bits are dropped when the entry is encoded.
    pub fn new(tos: u8, metric: u32) -> Self {
        Self { tos, metric }
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
}

/// OSPFv2 Summary-LSA body (RFC 2328 §A.4.4), shared by LS type 3 (IP network)
/// and LS type 4 (AS boundary router).
///
/// Carries the network's address mask and a list of TOS/metric entries. The
/// `network_mask` is a [`Field`] member so `compile()` honors any value the
/// caller pinned (including a wrong-on-purpose mask, or the zero mask used by a
/// type 4 Summary-LSA). This rides inside an
/// [`OspfLsa`](crate::protocols::ospf::lsa::OspfLsa) as an
/// [`OspfLsaBody::Summary`](crate::protocols::ospf::lsa::OspfLsaBody::Summary)
/// variant.
#[derive(Debug, Clone)]
pub struct OspfSummaryLsa {
    /// The IP address mask of the destination network (RFC 2328 §A.4.4); the
    /// Network Mask is not meaningful for a type 4 Summary-LSA and should be
    /// zero. Defaults to the unspecified address.
    network_mask: Field<Ipv4Addr>,
    /// The TOS/metric entries, in order (RFC 2328 §A.4.4); the first entry is the
    /// mandatory TOS 0 metric.
    entries: Vec<OspfSummaryTos>,
}

impl OspfSummaryLsa {
    /// Build a Summary-LSA body with an unset network mask and a single default
    /// TOS 0 entry whose metric is 0 (RFC 2328 §A.4.4 requires at least the
    /// TOS 0 metric).
    pub fn new() -> Self {
        Self {
            network_mask: Field::unset(),
            entries: vec![OspfSummaryTos::new(0, 0)],
        }
    }

    /// Construct a Summary-LSA body from decoded wire fields, marking the network
    /// mask as caller-supplied so re-compilation preserves the decoded values
    /// byte-for-byte (RFC 2328 §A.4.4).
    pub(crate) fn from_decoded_parts(network_mask: Ipv4Addr, entries: Vec<OspfSummaryTos>) -> Self {
        Self {
            network_mask: Field::user(network_mask),
            entries,
        }
    }

    /// Set the network mask field (RFC 2328 §A.4.4). For a type 4 Summary-LSA
    /// this should be zero.
    pub fn network_mask(mut self, network_mask: impl Into<Ipv4Addr>) -> Self {
        self.network_mask.set_user(network_mask.into());
        self
    }

    /// Set the metric of the mandatory TOS 0 entry (RFC 2328 §A.4.4).
    ///
    /// The metric is a 24-bit value (valid range `0..=0x00ff_ffff`). If the body
    /// has no entries (e.g. after a caller cleared them) a fresh TOS 0 entry is
    /// created; otherwise the first entry's metric is replaced and its TOS code
    /// is reset to 0.
    pub fn metric(mut self, metric: u32) -> Self {
        match self.entries.first_mut() {
            Some(entry) => {
                entry.tos = 0;
                entry.metric = metric;
            }
            None => self.entries.push(OspfSummaryTos::new(0, metric)),
        }
        self
    }

    /// Append a TOS/metric entry to the Summary-LSA (RFC 2328 §A.4.4).
    ///
    /// The metric is a 24-bit value (valid range `0..=0x00ff_ffff`).
    pub fn tos_entry(mut self, tos: u8, metric: u32) -> Self {
        self.entries.push(OspfSummaryTos::new(tos, metric));
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

    /// The TOS/metric entries, in order.
    pub fn entries_value(&self) -> &[OspfSummaryTos] {
        &self.entries
    }

    /// A one-line summary of the Summary-LSA body for `summary()` /
    /// `inspection_fields()`, like `mask=255.255.255.0 metric=10 tos=1`.
    pub fn summary(&self) -> String {
        let metric = self
            .entries
            .first()
            .map(|entry| (entry.metric & OSPF_SUMMARY_LSA_METRIC_MAX).to_string())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "mask={} metric={} tos={}",
            self.network_mask_value(),
            metric,
            self.entries.len(),
        )
    }

    /// The on-wire length of this Summary-LSA body, in octets: the 4-octet
    /// network mask plus 4 octets per TOS/metric entry.
    pub(crate) fn encoded_len(&self) -> usize {
        OSPF_SUMMARY_LSA_MASK_LEN + self.entries.len() * OSPF_SUMMARY_LSA_TOS_LEN
    }

    /// Append the RFC 2328 §A.4.4 Summary-LSA body to `out`: the 4-octet network
    /// mask followed by each TOS/metric entry as a 1-octet TOS code plus a
    /// 3-octet (24-bit) big-endian metric. Metrics wider than 24 bits are masked
    /// to the low 24 bits.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.network_mask_value().octets());
        for entry in &self.entries {
            out.push(entry.tos);
            let metric = entry.metric & OSPF_SUMMARY_LSA_METRIC_MAX;
            out.push((metric >> 16) as u8);
            out.push((metric >> 8) as u8);
            out.push(metric as u8);
        }
    }
}

impl Default for OspfSummaryLsa {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::fletcher16_valid;
    use crate::protocols::ospf::lsa::{
        OspfLsa, OspfLsaBody, OspfLsaHeader, OSPF_LSA_HEADER_LEN, OSPF_LSA_SUMMARY_IP,
    };
    use crate::protocols::ospf::packet::link_state_update::OspfLinkStateUpdate;

    /// A type 3 Summary-LSA built with a network mask and one TOS 0 metric entry
    /// encodes to the RFC 2328 §A.4.4 layout with the metric serialized as three
    /// big-endian octets. Wrapped in an `OspfLsa` and a Link State Update, the
    /// body layout matches the hand-computed bytes, the enclosing LSA `length`
    /// auto-fills to cover the 20-octet header plus the body, and the LSA's
    /// Fletcher-16 checksum validates.
    #[test]
    fn ospf_summary_lsa_type3_round_trips_in_lsu() {
        // 0x0a0b0c is a 24-bit metric that exercises all three octets.
        let metric = 0x000a_0b0c;
        let summary = OspfSummaryLsa::new()
            .network_mask(Ipv4Addr::new(255, 255, 255, 0))
            .metric(metric);

        // The default TOS 0 entry carries the metric we set.
        assert_eq!(
            summary.network_mask_value(),
            Ipv4Addr::new(255, 255, 255, 0)
        );
        assert_eq!(summary.entries_value().len(), 1);
        assert_eq!(summary.entries_value()[0].tos_value(), 0);
        assert_eq!(summary.entries_value()[0].metric_value(), metric);

        // Encode the body alone and check the exact RFC 2328 §A.4.4 layout.
        let mut body = Vec::new();
        summary.encode(&mut body);
        assert_eq!(body.len(), summary.encoded_len());

        let expected: Vec<u8> = vec![
            // Network Mask 255.255.255.0
            255, 255, 255, 0, //
            // TOS 0, metric 0x0a0b0c as three big-endian octets
            0x00, 0x0a, 0x0b, 0x0c,
        ];
        assert_eq!(body, expected);

        // The mask occupies the first 4 octets; the TOS/metric entry follows it.
        assert_eq!(&body[0..4], &[255, 255, 255, 0]);
        // TOS octet, then the 24-bit metric as three octets.
        assert_eq!(body[4], 0x00);
        assert_eq!(&body[5..8], &[0x0a, 0x0b, 0x0c]);

        // Wrap the Summary-LSA in an OspfLsa (type 3) and a Link State Update.
        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_SUMMARY_IP)
                .link_state_id(Ipv4Addr::new(198, 51, 100, 0))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::Summary(summary),
        );

        let lsu = OspfLinkStateUpdate::new().lsa(lsa);

        let mut update = Vec::new();
        lsu.encode(&mut update);

        // # LSAs field (octets 0..4) reports one LSA.
        assert_eq!(&update[0..4], &1u32.to_be_bytes());

        // The single LSA follows the count: 20-octet header plus the Summary body.
        let lsa_bytes = &update[4..];
        assert_eq!(lsa_bytes.len(), OSPF_LSA_HEADER_LEN + expected.len());

        // The enclosing LSA `length` field (octets 18..20 within the LSA)
        // auto-fills to cover the 20-octet header plus the Summary body.
        let expected_lsa_len = (OSPF_LSA_HEADER_LEN + expected.len()) as u16;
        assert_eq!(&lsa_bytes[18..20], &expected_lsa_len.to_be_bytes());

        // The Summary body bytes follow the 20-octet header verbatim.
        assert_eq!(&lsa_bytes[OSPF_LSA_HEADER_LEN..], expected.as_slice());

        // The LSA's Fletcher-16 checksum validates over the whole LSA.
        assert!(
            fletcher16_valid(lsa_bytes),
            "auto-filled Fletcher checksum should validate over the Summary-LSA"
        );
    }
}
