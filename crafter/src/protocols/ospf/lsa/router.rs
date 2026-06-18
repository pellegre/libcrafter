//! OSPFv2 Router-LSA body (RFC 2328 §A.4.2).
//!
//! The Router-LSA (LS type 1) describes the collected states of a router's
//! interfaces to an area. It follows the 20-octet [`OspfLsaHeader`] and is a
//! 4-octet fixed prefix (the router-description flags, a reserved octet, and the
//! number of links) followed by that many link descriptions, each of which may
//! itself carry per-TOS metric entries:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    0    |V|E|B|        0      |            # links            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Link ID                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Link Data                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |     # TOS     |            metric            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      TOS      |       0       |          TOS  metric         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              ...                             ...
//! ```
//!
//! Like the other LSA bodies, [`OspfRouterLsa`] rides inside an
//! [`OspfLsa`](crate::protocols::ospf::lsa::OspfLsa) as an
//! [`OspfLsaBody::Router`](crate::protocols::ospf::lsa::OspfLsaBody::Router)
//! variant, and [`OspfLsa::encode`](crate::protocols::ospf::lsa::OspfLsa::encode)
//! auto-fills the enclosing LSA `length` and the Fletcher-16 checksum over the
//! header plus this body. The router-description flags and `# links` use
//! [`Field`] members so `compile()` honors any value the caller pinned while
//! filling `# links` from the carried link list otherwise.

use core::net::Ipv4Addr;

use crate::field::Field;

// ---------------------------------------------------------------------------
// Router-LSA flags (RFC 2328 §A.4.2)
// ---------------------------------------------------------------------------

/// Router-LSA flag bit B: the router is an area border router (RFC 2328 §A.4.2).
pub const OSPF_ROUTER_LSA_FLAG_B: u8 = 0x01;
/// Router-LSA flag bit E: the router is an AS boundary router (RFC 2328 §A.4.2).
pub const OSPF_ROUTER_LSA_FLAG_E: u8 = 0x02;
/// Router-LSA flag bit V: the router is an endpoint of one or more fully
/// adjacent virtual links (RFC 2328 §A.4.2).
pub const OSPF_ROUTER_LSA_FLAG_V: u8 = 0x04;

// ---------------------------------------------------------------------------
// Router-LSA link types (RFC 2328 §A.4.2)
// ---------------------------------------------------------------------------

/// Point-to-point connection to another router (RFC 2328 §A.4.2).
pub const OSPF_ROUTER_LINK_POINT_TO_POINT: u8 = 1;
/// Connection to a transit network (RFC 2328 §A.4.2).
pub const OSPF_ROUTER_LINK_TRANSIT: u8 = 2;
/// Connection to a stub network (RFC 2328 §A.4.2).
pub const OSPF_ROUTER_LINK_STUB: u8 = 3;
/// Virtual link (RFC 2328 §A.4.2).
pub const OSPF_ROUTER_LINK_VIRTUAL: u8 = 4;

/// Short human-readable name for a Router-LSA link type code (RFC 2328 §A.4.2),
/// used by `summary()` and `inspection_fields()`. Unrecognized codes map to
/// `"Unknown"`.
pub fn ospf_router_link_type_name(link_type: u8) -> &'static str {
    match link_type {
        OSPF_ROUTER_LINK_POINT_TO_POINT => "PointToPoint",
        OSPF_ROUTER_LINK_TRANSIT => "Transit",
        OSPF_ROUTER_LINK_STUB => "Stub",
        OSPF_ROUTER_LINK_VIRTUAL => "Virtual",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Fixed lengths (RFC 2328 §A.4.2)
// ---------------------------------------------------------------------------

/// The fixed (pre-link-list) length of the Router-LSA body, in octets: flags(1)
/// + reserved(1) + # links(2).
const OSPF_ROUTER_LSA_FIXED_LEN: usize = 4;

/// The length of a single link description's fixed portion, in octets:
/// Link ID(4) + Link Data(4) + Type(1) + # TOS(1) + metric(2).
const OSPF_ROUTER_LINK_FIXED_LEN: usize = 12;

/// The length of a single per-TOS entry, in octets: TOS(1) + reserved(1) +
/// TOS metric(2).
const OSPF_ROUTER_LINK_TOS_LEN: usize = 4;

/// A per-TOS metric entry attached to a Router-LSA link (RFC 2328 §A.4.2).
///
/// Each entry pairs a TOS code with the cost of using the link for that type of
/// service; the reserved octet between them is always emitted as zero.
#[derive(Debug, Clone)]
pub struct OspfRouterLinkTos {
    /// The IP type-of-service this metric applies to (RFC 2328 §A.4.2).
    tos: u8,
    /// The cost of using the link for this type of service (RFC 2328 §A.4.2).
    metric: u16,
}

impl OspfRouterLinkTos {
    /// Build a per-TOS entry pairing a TOS code with its metric.
    pub fn new(tos: u8, metric: u16) -> Self {
        Self { tos, metric }
    }

    /// The IP type-of-service this metric applies to.
    pub fn tos_value(&self) -> u8 {
        self.tos
    }

    /// The cost of using the link for this type of service.
    pub fn metric_value(&self) -> u16 {
        self.metric
    }

    /// Append this per-TOS entry to `out`: TOS(1), a zero reserved octet, then
    /// the TOS metric (2 octets, big-endian).
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.tos);
        out.push(0);
        out.extend_from_slice(&self.metric.to_be_bytes());
    }
}

/// A single link description within a Router-LSA (RFC 2328 §A.4.2).
///
/// Each link names a connected object (`link_id`), the data the router uses to
/// reach it (`link_data`), the kind of connection (`link_type`), the TOS 0
/// metric, and any additional per-TOS metrics. The `# TOS` count is derived from
/// the [`tos`](OspfRouterLink) list at encode time.
#[derive(Debug, Clone)]
pub struct OspfRouterLink {
    /// Identifies the object this link connects to (RFC 2328 §A.4.2). The
    /// meaning depends on `link_type`.
    link_id: Ipv4Addr,
    /// The router's interface data for this link (RFC 2328 §A.4.2). The meaning
    /// depends on `link_type`.
    link_data: Ipv4Addr,
    /// The kind of connection (e.g. [`OSPF_ROUTER_LINK_POINT_TO_POINT`]).
    link_type: u8,
    /// The cost of using this outbound link for TOS 0 (RFC 2328 §A.4.2).
    metric: u16,
    /// Additional per-TOS metric entries (RFC 2328 §A.4.2).
    tos: Vec<OspfRouterLinkTos>,
}

impl OspfRouterLink {
    /// Build a link description with the given Link ID, Link Data, link type,
    /// and TOS 0 metric, and an empty per-TOS list.
    pub fn new(
        link_id: impl Into<Ipv4Addr>,
        link_data: impl Into<Ipv4Addr>,
        link_type: u8,
        metric: u16,
    ) -> Self {
        Self {
            link_id: link_id.into(),
            link_data: link_data.into(),
            link_type,
            metric,
            tos: Vec::new(),
        }
    }

    /// Append a single per-TOS metric entry to this link.
    pub fn tos(mut self, tos: OspfRouterLinkTos) -> Self {
        self.tos.push(tos);
        self
    }

    /// Append several per-TOS metric entries to this link.
    pub fn tos_entries<I>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = OspfRouterLinkTos>,
    {
        self.tos.extend(entries);
        self
    }

    /// The object this link connects to.
    pub fn link_id_value(&self) -> Ipv4Addr {
        self.link_id
    }

    /// The router's interface data for this link.
    pub fn link_data_value(&self) -> Ipv4Addr {
        self.link_data
    }

    /// The kind of connection.
    pub fn link_type_value(&self) -> u8 {
        self.link_type
    }

    /// The cost of using this outbound link for TOS 0.
    pub fn metric_value(&self) -> u16 {
        self.metric
    }

    /// The additional per-TOS metric entries.
    pub fn tos_value(&self) -> &[OspfRouterLinkTos] {
        &self.tos
    }

    /// A one-line summary of this link description for `summary()` /
    /// `inspection_fields()`, like
    /// `type=PointToPoint, id=192.0.2.2, data=198.51.100.1, metric=10`.
    ///
    /// The link type renders through [`ospf_router_link_type_name`].
    pub fn summary(&self) -> String {
        format!(
            "type={}, id={}, data={}, metric={}",
            ospf_router_link_type_name(self.link_type),
            self.link_id,
            self.link_data,
            self.metric,
        )
    }

    /// The on-wire length of this link description, in octets: the 12-octet fixed
    /// portion plus 4 octets per per-TOS entry.
    fn encoded_len(&self) -> usize {
        OSPF_ROUTER_LINK_FIXED_LEN + self.tos.len() * OSPF_ROUTER_LINK_TOS_LEN
    }

    /// Append this link description to `out`: Link ID(4), Link Data(4), Type(1),
    /// the `# TOS` count derived from the per-TOS list (1), the TOS 0 metric (2),
    /// then each per-TOS entry.
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.link_id.octets());
        out.extend_from_slice(&self.link_data.octets());
        out.push(self.link_type);
        out.push(self.tos.len() as u8);
        out.extend_from_slice(&self.metric.to_be_bytes());
        for tos in &self.tos {
            tos.encode(out);
        }
    }
}

/// OSPFv2 Router-LSA body (RFC 2328 §A.4.2).
///
/// Carries the router-description flags (V/E/B), the number of links, and the
/// list of [`OspfRouterLink`] descriptions. The `flags` octet and the `# links`
/// count are [`Field`] members so `compile()` honors any value the caller
/// pinned while filling `# links` from the carried link list otherwise. This
/// rides inside an [`OspfLsa`](crate::protocols::ospf::lsa::OspfLsa) as an
/// [`OspfLsaBody::Router`](crate::protocols::ospf::lsa::OspfLsaBody::Router)
/// variant.
#[derive(Debug, Clone)]
pub struct OspfRouterLsa {
    /// The router-description flags (RFC 2328 §A.4.2 bits V/E/B); defaults to 0.
    flags: Field<u8>,
    /// The `# links` count (RFC 2328 §A.4.2). Left unset so `encode()` fills it
    /// with the number of carried links; a pinned value (including a deliberately
    /// wrong one) survives untouched.
    num_links: Field<u16>,
    /// The carried link descriptions, in order.
    links: Vec<OspfRouterLink>,
}

impl OspfRouterLsa {
    /// Build a Router-LSA body with no flags set, an unset `# links` count, and
    /// an empty link list.
    pub fn new() -> Self {
        Self {
            flags: Field::defaulted(0),
            num_links: Field::unset(),
            links: Vec::new(),
        }
    }

    /// Construct a Router-LSA body from decoded wire fields, marking the flags
    /// octet and the `# links` count as caller-supplied so re-compilation
    /// preserves the decoded values byte-for-byte (RFC 2328 §A.4.2).
    ///
    /// The on-wire `# links` count is pinned with [`Field::user`] independently
    /// of the carried link list, so an LSA whose declared count disagrees with
    /// the number of parsed links round-trips exactly.
    pub(crate) fn from_decoded_parts(
        flags: u8,
        num_links: u16,
        links: Vec<OspfRouterLink>,
    ) -> Self {
        Self {
            flags: Field::user(flags),
            num_links: Field::user(num_links),
            links,
        }
    }

    /// Set the V flag, marking the router as a virtual-link endpoint
    /// ([`OSPF_ROUTER_LSA_FLAG_V`]).
    pub fn virtual_link(mut self) -> Self {
        let flags = self.flags_value() | OSPF_ROUTER_LSA_FLAG_V;
        self.flags.set_user(flags);
        self
    }

    /// Set the E flag, marking the router as an AS boundary router
    /// ([`OSPF_ROUTER_LSA_FLAG_E`]).
    pub fn external(mut self) -> Self {
        let flags = self.flags_value() | OSPF_ROUTER_LSA_FLAG_E;
        self.flags.set_user(flags);
        self
    }

    /// Set the B flag, marking the router as an area border router
    /// ([`OSPF_ROUTER_LSA_FLAG_B`]).
    pub fn border(mut self) -> Self {
        let flags = self.flags_value() | OSPF_ROUTER_LSA_FLAG_B;
        self.flags.set_user(flags);
        self
    }

    /// Force the router-description flags octet (RFC 2328 §A.4.2).
    ///
    /// This preserves malformed-on-purpose Router-LSAs whose flags carry
    /// reserved bits the named setters do not expose.
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Append a single link description to the Router-LSA's link list.
    pub fn link(mut self, link: OspfRouterLink) -> Self {
        self.links.push(link);
        self
    }

    /// Append several link descriptions to the Router-LSA's link list.
    pub fn links<I>(mut self, links: I) -> Self
    where
        I: IntoIterator<Item = OspfRouterLink>,
    {
        self.links.extend(links);
        self
    }

    /// Force the `# links` count field (RFC 2328 §A.4.2).
    ///
    /// This preserves malformed-on-purpose Router-LSAs whose declared count
    /// differs from the number of carried links.
    pub fn num_links(mut self, num_links: u16) -> Self {
        self.num_links.set_user(num_links);
        self
    }

    /// The effective router-description flags (the caller value, else 0).
    pub fn flags_value(&self) -> u8 {
        self.flags.value().copied().unwrap_or(0)
    }

    /// The effective `# links` count: the caller value, else the number of
    /// carried links.
    pub fn num_links_value(&self) -> u16 {
        self.num_links
            .value()
            .copied()
            .unwrap_or(self.links.len() as u16)
    }

    /// The carried link descriptions, in order.
    pub fn links_value(&self) -> &[OspfRouterLink] {
        &self.links
    }

    /// A one-line summary of the Router-LSA body for `summary()` /
    /// `inspection_fields()`, like `flags=VEB links=2`.
    ///
    /// The `flags` field lists the set router-description bits in V/E/B order
    /// (RFC 2328 §A.4.2), rendering `-` when none are set, and `links` reports
    /// the effective `# links` count (the caller value, else the number of
    /// carried links).
    pub fn summary(&self) -> String {
        let flags = self.flags_value();
        let mut labels = String::new();
        if flags & OSPF_ROUTER_LSA_FLAG_V != 0 {
            labels.push('V');
        }
        if flags & OSPF_ROUTER_LSA_FLAG_E != 0 {
            labels.push('E');
        }
        if flags & OSPF_ROUTER_LSA_FLAG_B != 0 {
            labels.push('B');
        }
        if labels.is_empty() {
            labels.push('-');
        }
        format!("flags={} links={}", labels, self.num_links_value())
    }

    /// The on-wire length of this Router-LSA body, in octets: the fixed 4 octets
    /// plus the total size of every carried link (each 12-octet fixed portion
    /// plus its per-TOS entries).
    pub(crate) fn encoded_len(&self) -> usize {
        OSPF_ROUTER_LSA_FIXED_LEN
            + self.links.iter().map(OspfRouterLink::encoded_len).sum::<usize>()
    }

    /// Append the RFC 2328 §A.4.2 Router-LSA body to `out`: the flags octet, a
    /// zero reserved octet, the `# links` count (the caller value, else the
    /// number of carried links), then each link description with its own `# TOS`
    /// count and per-TOS entries.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.flags_value());
        out.push(0);
        out.extend_from_slice(&self.num_links_value().to_be_bytes());
        for link in &self.links {
            link.encode(out);
        }
    }
}

impl Default for OspfRouterLsa {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::fletcher16_valid;
    use crate::protocols::ospf::lsa::{OspfLsa, OspfLsaBody, OspfLsaHeader, OSPF_LSA_HEADER_LEN, OSPF_LSA_ROUTER};
    use crate::protocols::ospf::packet::link_state_update::OspfLinkStateUpdate;

    /// A Router-LSA built with two links (one carrying a per-TOS entry) encodes
    /// to the RFC 2328 §A.4.2 layout. Wrapped in an `OspfLsa` and a Link State
    /// Update, the `# links` count reports two links, the link layout matches the
    /// hand-computed bytes, the enclosing LSA `length` auto-fills to cover the
    /// 20-octet header plus the body, and the LSA's Fletcher-16 checksum
    /// validates.
    #[test]
    fn ospf_router_lsa_two_links_with_tos_round_trips_in_lsu() {
        let router = OspfRouterLsa::new()
            .border()
            // Link 1: point-to-point, no per-TOS entries.
            .link(OspfRouterLink::new(
                Ipv4Addr::new(192, 0, 2, 2),
                Ipv4Addr::new(198, 51, 100, 1),
                OSPF_ROUTER_LINK_POINT_TO_POINT,
                10,
            ))
            // Link 2: stub network with one per-TOS entry.
            .link(
                OspfRouterLink::new(
                    Ipv4Addr::new(198, 51, 100, 0),
                    Ipv4Addr::new(255, 255, 255, 0),
                    OSPF_ROUTER_LINK_STUB,
                    20,
                )
                .tos(OspfRouterLinkTos::new(2, 30)),
            );

        // The B flag is set and the count derives from the two carried links.
        assert_eq!(router.flags_value(), OSPF_ROUTER_LSA_FLAG_B);
        assert_eq!(router.num_links_value(), 2);
        assert_eq!(router.links_value().len(), 2);

        // Encode the body alone and check the exact RFC 2328 §A.4.2 layout.
        let mut body = Vec::new();
        router.encode(&mut body);
        assert_eq!(body.len(), router.encoded_len());

        let expected: Vec<u8> = vec![
            // flags 0x01 (B), reserved 0, # links 2
            0x01, 0x00, 0x00, 0x02,
            // Link 1: Link ID 192.0.2.2, Link Data 198.51.100.1
            192, 0, 2, 2, 198, 51, 100, 1,
            // Type 1 (point-to-point), # TOS 0, metric 10
            0x01, 0x00, 0x00, 0x0a,
            // Link 2: Link ID 198.51.100.0, Link Data 255.255.255.0
            198, 51, 100, 0, 255, 255, 255, 0,
            // Type 3 (stub), # TOS 1, metric 20
            0x03, 0x01, 0x00, 0x14,
            // TOS entry: TOS 2, reserved 0, TOS metric 30
            0x02, 0x00, 0x00, 0x1e,
        ];
        assert_eq!(body, expected);

        // The fixed prefix reports two links.
        assert_eq!(&body[2..4], &2u16.to_be_bytes());

        // Wrap the Router-LSA in an OspfLsa and a Link State Update.
        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_ROUTER)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::Router(router),
        );

        let lsu = OspfLinkStateUpdate::new().lsa(lsa);

        let mut update = Vec::new();
        lsu.encode(&mut update);

        // # LSAs field (octets 0..4) reports one LSA.
        assert_eq!(&update[0..4], &1u32.to_be_bytes());

        // The single LSA follows the count: 20-octet header plus the Router body.
        let lsa_bytes = &update[4..];
        assert_eq!(lsa_bytes.len(), OSPF_LSA_HEADER_LEN + expected.len());

        // The enclosing LSA `length` field (octets 18..20 within the LSA)
        // auto-fills to cover the 20-octet header plus the Router body.
        let expected_lsa_len = (OSPF_LSA_HEADER_LEN + expected.len()) as u16;
        assert_eq!(&lsa_bytes[18..20], &expected_lsa_len.to_be_bytes());

        // The Router body bytes follow the 20-octet header verbatim.
        assert_eq!(&lsa_bytes[OSPF_LSA_HEADER_LEN..], expected.as_slice());

        // The LSA's Fletcher-16 checksum validates over the whole LSA.
        assert!(
            fletcher16_valid(lsa_bytes),
            "auto-filled Fletcher checksum should validate over the Router-LSA"
        );
    }

    /// A Link State Update carrying a Router-LSA exposes typed Router detail
    /// through `inspection_fields()`: a `router_lsa` pair reports the V/E/B flags
    /// and the link count, and one `router_link` pair per link names the link
    /// type, so the Router-LSA body is inspectable through `Packet::show()`.
    #[test]
    fn ospf_router_lsa_inspection_describes_flags_and_links() {
        use crate::packet::Layer;
        use crate::protocols::ospf::Ospfv2;

        let router = OspfRouterLsa::new()
            .border()
            .external()
            // Link 1: point-to-point.
            .link(OspfRouterLink::new(
                Ipv4Addr::new(192, 0, 2, 2),
                Ipv4Addr::new(198, 51, 100, 1),
                OSPF_ROUTER_LINK_POINT_TO_POINT,
                10,
            ))
            // Link 2: stub network.
            .link(OspfRouterLink::new(
                Ipv4Addr::new(198, 51, 100, 0),
                Ipv4Addr::new(255, 255, 255, 0),
                OSPF_ROUTER_LINK_STUB,
                20,
            ));

        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_ROUTER)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1)),
            OspfLsaBody::Router(router),
        );

        let ospf = Ospfv2::link_state_update()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .with_link_state_update(|u| {
                *u = OspfLinkStateUpdate::new().lsa(lsa);
            });

        let fields = ospf.inspection_fields();

        // The `router_lsa` pair reports the set flags (E and B here) and the
        // link count.
        let router_lsa = fields
            .iter()
            .find(|(field, _)| *field == "router_lsa")
            .map(|(_, value)| value.as_str())
            .expect("inspection output should carry a router_lsa pair");
        assert!(
            router_lsa.contains("links=2"),
            "router_lsa missing link count: {router_lsa}"
        );
        assert!(
            router_lsa.contains("flags=EB"),
            "router_lsa missing flags: {router_lsa}"
        );

        // One `router_link` pair per link, the first naming its link type.
        let router_links: Vec<&str> = fields
            .iter()
            .filter(|(field, _)| *field == "router_link")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(router_links.len(), 2);
        assert!(
            router_links[0].contains("type=PointToPoint"),
            "first router_link missing the link type name: {}",
            router_links[0]
        );
        assert!(
            router_links[1].contains("type=Stub"),
            "second router_link missing the link type name: {}",
            router_links[1]
        );
    }
}
