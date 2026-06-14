//! Round-trip integration coverage for the five IPv6 Neighbor Discovery (NDP)
//! core messages (RFC 4861, types 133–137), their base options, and the
//! standards-track NDP option extensions — Route Information (RFC 4191), RDNSS
//! and DNSSL (RFC 8106), MTU (RFC 4861), PREF64 (RFC 8781), Captive Portal
//! (RFC 8910) — plus unknown-option preservation.
//!
//! Each test builds an NDP message with [`crafter::prelude`] builders, wraps it
//! in an [`Ipv6`] header, `compile()`s the packet, decodes the resulting bytes
//! with [`Packet::decode_from_l3`] over IPv6 (the same path
//! `crafter::protocols::icmp::v6::append_icmpv6_packet` runs through the
//! registry), and asserts that the message type/code, the rest-of-header flags
//! and addresses, and every base option round-trip unchanged. A final
//! recompile-equals-bytes check pins byte stability through the full
//! build → decode → recompile cycle.
//!
//! Addresses are documentation / link-local space only (`fe80::/10`,
//! `2001:db8::/32`, the solicited-node multicast `ff02::1:ff..`) and MACs use
//! the documentation `02:00:5e:00:53:..` range, per the project address-space
//! policy. These are the same NDP cases the oracle validates against the
//! reference backend fixture set:
//! `ndp-router-solicitation`, `ndp-router-advertisement`,
//! `ndp-neighbor-solicitation`, `ndp-neighbor-advertisement`, `ndp-redirect`).

use core::net::Ipv6Addr;

use crafter::prelude::*;

/// Link-local source address (`fe80::/10`) for a host emitting NDP.
fn host_link_local() -> Ipv6Addr {
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0200, 0x5eff, 0xfe00, 0x5301)
}

/// Link-local router address (`fe80::/10`).
fn router_link_local() -> Ipv6Addr {
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0200, 0x5eff, 0xfe00, 0x5302)
}

/// The all-routers multicast (`ff02::2`) — the usual Router Solicitation
/// destination.
fn all_routers() -> Ipv6Addr {
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2)
}

/// The all-nodes multicast (`ff02::1`) — the usual unsolicited Router/Neighbor
/// Advertisement destination.
fn all_nodes() -> Ipv6Addr {
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
}

/// A documentation target address (`2001:db8::/32`) being resolved or
/// advertised.
fn target_addr() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0x0010)
}

/// The solicited-node multicast `ff02::1:ffXX:XXXX` for [`target_addr`], the
/// usual Neighbor Solicitation destination (RFC 4861 section 4.3).
fn solicited_node_multicast() -> Ipv6Addr {
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0010)
}

fn host_mac() -> MacAddr {
    MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01])
}

fn router_mac() -> MacAddr {
    MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x02])
}

/// Compile an [`Ipv6`] / NDP packet, decode it back over IPv6, and assert the
/// build → decode → recompile cycle is byte-stable. Returns the decoded packet
/// for per-message field assertions.
fn round_trip(src: Ipv6Addr, dst: Ipv6Addr, payload: Packet) -> (Vec<u8>, Packet) {
    // hlim 255 is the NDP requirement (RFC 4861 section 11.2: receivers verify
    // the hop limit is 255 so the message originated on-link).
    let packet = Ipv6::new().src(src).dst(dst).hlim(255) / payload;
    let bytes = packet
        .compile()
        .expect("NDP packet compiles")
        .as_bytes()
        .to_vec();

    let decoded =
        Packet::decode_from_l3(NetworkLayer::Ipv6, &bytes).expect("NDP packet decodes from IPv6");
    let recompiled = decoded.compile().expect("decoded NDP packet recompiles");
    assert_eq!(
        recompiled.as_bytes(),
        bytes.as_slice(),
        "build -> decode -> recompile must be byte-stable",
    );

    let ipv6 = decoded.layer::<Ipv6>().expect("decoded packet has IPv6");
    assert_eq!(ipv6.source(), src);
    assert_eq!(ipv6.destination(), dst);

    (bytes, decoded)
}

/// Assert the decoded ICMPv6 header has the expected NDP type and code 0, and a
/// non-zero auto-filled checksum.
fn assert_ndp_header(decoded: &Packet, expected_type: u8) {
    let icmpv6 = decoded
        .layer::<Icmpv6>()
        .expect("decoded packet has ICMPv6");
    assert_eq!(icmpv6.icmp_type_value(), expected_type, "ICMPv6 type");
    assert_eq!(icmpv6.code_value(), 0, "NDP code is 0");
    let checksum = icmpv6
        .checksum_value()
        .expect("checksum is present after decode");
    assert_ne!(
        checksum, 0,
        "compile() auto-fills a non-zero ICMPv6 checksum",
    );
}

// --- Router Solicitation (type 133, RFC 4861 section 4.1) ------------------

#[test]
fn router_solicitation_round_trips_with_source_link_layer() {
    let (_, decoded) = round_trip(
        host_link_local(),
        all_routers(),
        Icmpv6::router_solicitation_with_source_link_layer(host_mac()),
    );

    assert_ndp_header(&decoded, ICMPV6_ROUTER_SOLICITATION);
    assert_eq!(
        decoded.layer::<Icmpv6>().unwrap().body(),
        Icmpv6Body::RouterSolicitation { reserved: 0 },
    );

    let rs = decoded
        .layer::<RouterSolicitation>()
        .expect("typed Router Solicitation body");
    let options = rs.options_ref();
    assert_eq!(options.len(), 1, "one SLLA option");
    let slla = &options.options()[0];
    assert_eq!(slla.option_type(), NDP_OPT_SOURCE_LINK_LAYER_ADDR);
    assert_eq!(slla.link_layer_address(), Some(host_mac()));
}

// --- Router Advertisement (type 134, RFC 4861 section 4.2) -----------------

#[test]
fn router_advertisement_round_trips_with_prefix_and_mtu() {
    // RA carrying Prefix Information (RFC 4861 section 4.6.2) + MTU (section
    // 4.6.4), the common SLAAC advertisement. Options in PI-then-MTU order to
    // prove order is preserved on decode.
    let body = RouterAdvertisement::new()
        .reachable_time(30_000)
        .retrans_timer(1_000)
        .option(NdpOption::prefix_information(
            Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0),
            64,
            true, // on-link (L)
            true, // autonomous (A)
            86_400,
            14_400,
        ))
        .option(NdpOption::mtu(1500));

    let (_, decoded) = round_trip(
        router_link_local(),
        all_nodes(),
        Icmpv6::router_advertisement_with(64, true, false, 1800, body),
    );

    assert_ndp_header(&decoded, ICMPV6_ROUTER_ADVERTISEMENT);
    assert_eq!(
        decoded.layer::<Icmpv6>().unwrap().body(),
        Icmpv6Body::RouterAdvertisement {
            cur_hop_limit: 64,
            managed: true,
            other: false,
            // router_advertisement_with defaults the RFC 4191 Default Router
            // Preference to Medium (wire value 0).
            preference: Prf::Medium,
            reserved_flags: 0,
            router_lifetime: 1800,
        },
    );

    let ra = decoded
        .layer::<RouterAdvertisement>()
        .expect("typed Router Advertisement body");
    assert_eq!(ra.reachable_time_value(), 30_000);
    assert_eq!(ra.retrans_timer_value(), 1_000);

    let options = ra.options_ref();
    assert_eq!(options.len(), 2, "PI + MTU options");

    let pi = &options.options()[0];
    assert_eq!(pi.option_type(), NDP_OPT_PREFIX_INFORMATION);
    assert_eq!(
        pi.prefix(),
        Some(Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0))
    );
    assert_eq!(pi.prefix_length(), Some(64));
    assert_eq!(pi.prefix_on_link(), Some(true));
    assert_eq!(pi.prefix_autonomous(), Some(true));
    assert_eq!(pi.prefix_valid_lifetime(), Some(86_400));
    assert_eq!(pi.prefix_preferred_lifetime(), Some(14_400));

    let mtu = &options.options()[1];
    assert_eq!(mtu.option_type(), NDP_OPT_MTU);
    assert_eq!(mtu.mtu_value(), Some(1500));
}

// --- Neighbor Solicitation (type 135, RFC 4861 section 4.3) ----------------

#[test]
fn neighbor_solicitation_round_trips_with_source_link_layer() {
    let (_, decoded) = round_trip(
        host_link_local(),
        solicited_node_multicast(),
        Icmpv6::neighbor_solicitation_with_source_link_layer(target_addr(), host_mac()),
    );

    assert_ndp_header(&decoded, ICMPV6_NEIGHBOR_SOLICITATION);
    assert_eq!(
        decoded.layer::<Icmpv6>().unwrap().body(),
        Icmpv6Body::NeighborSolicitation { reserved: 0 },
    );

    let ns = decoded
        .layer::<NeighborSolicitation>()
        .expect("typed Neighbor Solicitation body");
    assert_eq!(ns.target_address_value(), target_addr());

    let options = ns.options_ref();
    assert_eq!(options.len(), 1, "one SLLA option");
    let slla = &options.options()[0];
    assert_eq!(slla.option_type(), NDP_OPT_SOURCE_LINK_LAYER_ADDR);
    assert_eq!(slla.link_layer_address(), Some(host_mac()));
}

#[test]
fn neighbor_solicitation_dad_form_has_no_options() {
    // Duplicate Address Detection probe (RFC 4862 section 5.4): source is the
    // unspecified address `::` and there is no Source Link-Layer Address option.
    let (_, decoded) = round_trip(
        Ipv6Addr::UNSPECIFIED,
        solicited_node_multicast(),
        Icmpv6::neighbor_solicitation(target_addr()),
    );

    assert_ndp_header(&decoded, ICMPV6_NEIGHBOR_SOLICITATION);
    let ns = decoded
        .layer::<NeighborSolicitation>()
        .expect("typed Neighbor Solicitation body");
    assert_eq!(ns.target_address_value(), target_addr());
    assert!(ns.options_ref().is_empty(), "DAD probe carries no options");
}

// --- Neighbor Advertisement (type 136, RFC 4861 section 4.4) ---------------

#[test]
fn neighbor_advertisement_round_trips_with_flags_and_target_link_layer() {
    // Solicited reply: R clear (host), S set (solicited), O set (override),
    // carrying the responder's Target Link-Layer Address option.
    let (_, decoded) = round_trip(
        target_addr(),
        host_link_local(),
        Icmpv6::neighbor_advertisement_with_target_link_layer(
            target_addr(),
            host_mac(),
            false, // router (R)
            true,  // solicited (S)
            true,  // override (O)
        ),
    );

    assert_ndp_header(&decoded, ICMPV6_NEIGHBOR_ADVERTISEMENT);
    assert_eq!(
        decoded.layer::<Icmpv6>().unwrap().body(),
        Icmpv6Body::NeighborAdvertisement {
            router: false,
            solicited: true,
            override_flag: true,
            reserved: 0,
        },
    );

    let na = decoded
        .layer::<NeighborAdvertisement>()
        .expect("typed Neighbor Advertisement body");
    assert_eq!(na.target_address_value(), target_addr());

    let options = na.options_ref();
    assert_eq!(options.len(), 1, "one TLLA option");
    let tlla = &options.options()[0];
    assert_eq!(tlla.option_type(), NDP_OPT_TARGET_LINK_LAYER_ADDR);
    assert_eq!(tlla.link_layer_address(), Some(host_mac()));
}

// --- Redirect (type 137, RFC 4861 section 4.5) -----------------------------

#[test]
fn redirect_round_trips_with_target_link_layer_and_redirected_header() {
    // A router redirects the host toward a better first hop, carrying both a
    // Target Link-Layer Address (section 4.6.1) and a Redirected Header option
    // (section 4.6.3) with a sample embedded packet.
    let embedded: Vec<u8> = (0u8..40).collect();
    let body = Redirect::new(router_link_local(), target_addr())
        .option(NdpOption::target_link_layer_address(router_mac()))
        .option(NdpOption::redirected_header(&embedded));

    let (_, decoded) = round_trip(
        router_link_local(),
        host_link_local(),
        Icmpv6::new().icmp_type(ICMPV6_REDIRECT).code(0) / body,
    );

    assert_ndp_header(&decoded, ICMPV6_REDIRECT);
    assert_eq!(
        decoded.layer::<Icmpv6>().unwrap().body(),
        Icmpv6Body::Redirect { reserved: 0 },
    );

    let redirect = decoded.layer::<Redirect>().expect("typed Redirect body");
    assert_eq!(redirect.target_address_value(), router_link_local());
    assert_eq!(redirect.destination_address_value(), target_addr());

    let options = redirect.options_ref();
    assert_eq!(options.len(), 2, "TLLA + Redirected Header options");

    let tlla = &options.options()[0];
    assert_eq!(tlla.option_type(), NDP_OPT_TARGET_LINK_LAYER_ADDR);
    assert_eq!(tlla.link_layer_address(), Some(router_mac()));

    let rh = &options.options()[1];
    assert_eq!(rh.option_type(), NDP_OPT_REDIRECTED_HEADER);
    // The Redirected Header option zero-pads to the 8-octet boundary; the
    // embedded packet bytes round-trip at the front of the data field.
    let data = rh.redirected_header_data().expect("redirected header data");
    assert!(
        data.starts_with(&embedded),
        "embedded packet preserved at the front of the Redirected Header data",
    );
}

// --- Deliberately-wrong values survive compile() (honored overrides) --------

#[test]
fn neighbor_advertisement_reserved_override_survives() {
    // An agent sets the 29 Reserved flag bits on purpose; compile() must not
    // scrub them, and decode must report them verbatim.
    let body = NeighborAdvertisement::new(target_addr());
    let packet = Icmpv6::new()
        .icmp_type(ICMPV6_NEIGHBOR_ADVERTISEMENT)
        .code(0)
        // R set (0x80) plus a non-zero reserved nibble in the low bits.
        .rest_of_header([0x80, 0x00, 0x00, 0x0f])
        / body;

    let (_, decoded) = round_trip(target_addr(), host_link_local(), packet);
    assert_eq!(
        decoded.layer::<Icmpv6>().unwrap().body(),
        Icmpv6Body::NeighborAdvertisement {
            router: true,
            solicited: false,
            override_flag: false,
            reserved: 0x0000_000f,
        },
    );
}

// --- NDP option extensions (steps 22-24) -----------------------------------

/// A documentation NAT64 prefix (`64:ff9b::/96`, the RFC 6052 Well-Known
/// Prefix) advertised by PREF64.
fn nat64_prefix() -> Ipv6Addr {
    Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0)
}

/// A documentation recursive DNS server (`2001:db8:ffff::1`) for RDNSS.
fn rdnss_server() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 0xffff, 0, 0, 0, 0, 1)
}

/// A documentation route prefix (`2001:db8:2::/48`) for Route Information.
fn route_prefix() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 0)
}

#[test]
fn router_advertisement_round_trips_with_route_rdnss_dnssl_mtu() {
    // The full DNS-and-routing SLAAC advertisement: Route Information
    // (RFC 4191), RDNSS + DNSSL (RFC 8106), and MTU (RFC 4861), in that order,
    // to prove every extension field and the option order round-trip together.
    // The oracle's byte-proof for ndp-ra-route-rdnss-dnssl-mtu materializes the
    // same stack in the reference backend; that case pins the Route Information
    // option to its 16-octet (Length 3) form to match the reference encoder,
    // whereas this round-trip uses the natural
    // length-derived form (a /48 prefix carries 8 octets, Length 2).
    let body = RouterAdvertisement::new()
        .reachable_time(0)
        .retrans_timer(0)
        .option(NdpOption::route_information(
            route_prefix(),
            48,
            Prf::High,
            1800,
        ))
        .option(NdpOption::rdnss(900, &[rdnss_server()]))
        .option(NdpOption::dnssl(900, &["example.com."]))
        .option(NdpOption::mtu(1500));

    let (_, decoded) = round_trip(
        router_link_local(),
        all_nodes(),
        Icmpv6::router_advertisement_with(64, false, false, 1800, body),
    );

    assert_ndp_header(&decoded, ICMPV6_ROUTER_ADVERTISEMENT);

    let ra = decoded
        .layer::<RouterAdvertisement>()
        .expect("typed Router Advertisement body");
    let options = ra.options_ref();
    assert_eq!(
        options.len(),
        4,
        "Route Information + RDNSS + DNSSL + MTU options, in order",
    );

    // 1. Route Information (RFC 4191 section 2.3).
    let ri = &options.options()[0];
    assert_eq!(ri.option_type(), NDP_OPT_ROUTE_INFORMATION);
    assert_eq!(ri.route_prefix_length(), Some(48));
    assert_eq!(ri.route_preference(), Some(Prf::High));
    assert_eq!(ri.route_lifetime(), Some(1800));
    assert_eq!(ri.route_prefix(), Some(route_prefix()));

    // 2. RDNSS (RFC 8106 section 5.1).
    let rdnss = &options.options()[1];
    assert_eq!(rdnss.option_type(), NDP_OPT_RDNSS);
    assert_eq!(rdnss.rdnss_lifetime(), Some(900));
    assert_eq!(rdnss.rdnss_servers(), Some(vec![rdnss_server()]));

    // 3. DNSSL (RFC 8106 section 5.2).
    let dnssl = &options.options()[2];
    assert_eq!(dnssl.option_type(), NDP_OPT_DNSSL);
    assert_eq!(dnssl.dnssl_lifetime(), Some(900));
    assert_eq!(
        dnssl.dnssl_domains(),
        Some(vec!["example.com.".to_string()]),
    );

    // 4. MTU (RFC 4861 section 4.6.4).
    let mtu = &options.options()[3];
    assert_eq!(mtu.option_type(), NDP_OPT_MTU);
    assert_eq!(mtu.mtu_value(), Some(1500));
}

#[test]
fn router_advertisement_round_trips_with_pref64() {
    // PREF64 (RFC 8781 section 4) advertising the RFC 6052 Well-Known NAT64
    // prefix 64:ff9b::/96 with a scaled lifetime of 75 (units of 8 seconds).
    let body = RouterAdvertisement::new()
        .reachable_time(0)
        .retrans_timer(0)
        .option(NdpOption::pref64(75, 96, nat64_prefix()).expect("valid PREF64 prefix length"));

    let (_, decoded) = round_trip(
        router_link_local(),
        all_nodes(),
        Icmpv6::router_advertisement_with(64, false, false, 1800, body),
    );

    assert_ndp_header(&decoded, ICMPV6_ROUTER_ADVERTISEMENT);

    let ra = decoded
        .layer::<RouterAdvertisement>()
        .expect("typed Router Advertisement body");
    let options = ra.options_ref();
    assert_eq!(options.len(), 1, "one PREF64 option");

    let pref64 = &options.options()[0];
    assert_eq!(pref64.option_type(), NDP_OPT_PREF64);
    assert_eq!(pref64.pref64_scaled_lifetime(), Some(75));
    assert_eq!(pref64.pref64_prefix_length(), Some(96));
    assert_eq!(pref64.pref64_prefix(), Some(nat64_prefix()));
}

#[test]
fn neighbor_solicitation_round_trips_with_captive_portal() {
    // Captive Portal (RFC 8910 section 2.3) carried by a Neighbor Solicitation,
    // exercising the option on a non-RA message. The URI is NUL-padded to the
    // 8-octet boundary by the framework and stripped back on decode.
    let uri = "https://example.com/portal";
    let body = NeighborSolicitation::new(target_addr()).option(NdpOption::captive_portal(uri));

    let (_, decoded) = round_trip(
        host_link_local(),
        solicited_node_multicast(),
        Icmpv6::new()
            .icmp_type(ICMPV6_NEIGHBOR_SOLICITATION)
            .code(0)
            / body,
    );

    assert_ndp_header(&decoded, ICMPV6_NEIGHBOR_SOLICITATION);

    let ns = decoded
        .layer::<NeighborSolicitation>()
        .expect("typed Neighbor Solicitation body");
    assert_eq!(ns.target_address_value(), target_addr());

    let options = ns.options_ref();
    assert_eq!(options.len(), 1, "one Captive Portal option");
    let portal = &options.options()[0];
    assert_eq!(portal.option_type(), NDP_OPT_CAPTIVE_PORTAL);
    assert_eq!(portal.captive_portal_uri().as_deref(), Some(uri));
}

#[test]
fn router_advertisement_round_trips_with_unknown_option() {
    // An NDP message carrying a synthetic unknown option type (RFC 4727's
    // experimental option codepoint 253) must round-trip verbatim: the option
    // type, length, and value bytes survive build -> compile -> decode ->
    // recompile unchanged, and the framework preserves it as an
    // NdpOption::Unknown rather than rejecting or remapping it (spec.md edge
    // case: "an NDP message with an unknown option type ... round-trips").
    const UNKNOWN_OPT_TYPE: u8 = 253;
    let value: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];

    let body = RouterAdvertisement::new()
        .reachable_time(0)
        .retrans_timer(0)
        .option(NdpOption::unknown(UNKNOWN_OPT_TYPE, value.clone()));

    let (_, decoded) = round_trip(
        router_link_local(),
        all_nodes(),
        Icmpv6::router_advertisement_with(64, false, false, 1800, body),
    );

    assert_ndp_header(&decoded, ICMPV6_ROUTER_ADVERTISEMENT);

    let ra = decoded
        .layer::<RouterAdvertisement>()
        .expect("typed Router Advertisement body");
    let options = ra.options_ref();
    assert_eq!(options.len(), 1, "one unknown option");

    let unknown = &options.options()[0];
    assert_eq!(unknown.option_type(), UNKNOWN_OPT_TYPE);
    assert!(
        matches!(unknown, NdpOption::Unknown { .. }),
        "synthetic option type 253 is preserved as NdpOption::Unknown, got {unknown:?}",
    );
    // The 6 value bytes plus the 2-byte type/length header are exactly one
    // 8-octet unit, so the value round-trips with no boundary padding.
    assert_eq!(unknown.value(), value.as_slice());
}

// ===========================================================================
// RFC 4620 (experimental) Node Information Query / Response (types 139 / 140),
// and the niche-family deferral: Router Renumbering (RFC 2894, type 138) and
// Inverse Neighbor Discovery (RFC 3122, types 141 / 142) are deferred and must
// decode to an Unknown body / Raw tail without panic. See docs/internal/manifests/icmpv6-coverage.md.
// ===========================================================================

/// A documentation IPv6 address used as a Node Information Query Subject /
/// Response answer (`2001:db8::/32`).
fn node_addr() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 9, 0, 0, 0, 0, 0x0099)
}

// A Node Information Query (type 139) carries the Qtype + Flags in the
// rest-of-header and the Nonce + Data (the IPv6 Subject) in the trailing body;
// everything round-trips and the body classifies as a Node Information Query.
// RFC 4620 is experimental.
#[test]
fn node_information_query_round_trips() {
    let nonce = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let subject = node_addr().octets().to_vec();
    // Qtype 3 (Node Addresses), Flags 0x0010 (the A bit), Code 0 (IPv6 Subject).
    let packet = Ipv6::new().src(target_addr()).dst(node_addr()).hlim(64)
        / Icmpv6::node_information_query(NI_QTYPE_NODE_ADDRESSES, 0x0010, nonce, subject.clone());
    let bytes = packet
        .compile()
        .expect("NI query compiles")
        .as_bytes()
        .to_vec();

    let decoded =
        Packet::decode_from_l3(NetworkLayer::Ipv6, &bytes).expect("NI query decodes from IPv6");
    assert_eq!(
        decoded.compile().expect("recompiles").as_bytes(),
        bytes.as_slice(),
        "build -> decode -> recompile must be byte-stable",
    );

    let icmpv6 = decoded
        .layer::<Icmpv6>()
        .expect("decoded packet has ICMPv6");
    assert_eq!(icmpv6.icmp_type_value(), ICMPV6_NODE_INFORMATION_QUERY);
    assert_eq!(
        icmpv6.body(),
        Icmpv6Body::NodeInformationQuery {
            qtype: NI_QTYPE_NODE_ADDRESSES,
            flags: 0x0010,
        }
    );
    let ni = decoded
        .layer::<NodeInformation>()
        .expect("typed NodeInformation body");
    assert_eq!(ni.nonce_value(), nonce);
    assert_eq!(ni.data_value(), subject.as_slice());
}

// A Node Information Response (type 140) echoes the Qtype and Nonce and carries
// the answer in Data; everything round-trips and the body classifies as a Node
// Information Response.
#[test]
fn node_information_response_round_trips() {
    let nonce = [0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08];
    // RFC 4620 sec 6.4 Node Addresses reply: a 32-bit TTL then one IPv6 address.
    let mut answer = Vec::new();
    answer.extend_from_slice(&1800u32.to_be_bytes());
    answer.extend_from_slice(&node_addr().octets());

    let packet = Ipv6::new().src(node_addr()).dst(target_addr()).hlim(64)
        / Icmpv6::node_information_response(NI_QTYPE_NODE_ADDRESSES, 0, nonce, answer.clone());
    let bytes = packet
        .compile()
        .expect("NI response compiles")
        .as_bytes()
        .to_vec();

    let decoded =
        Packet::decode_from_l3(NetworkLayer::Ipv6, &bytes).expect("NI response decodes from IPv6");
    assert_eq!(
        decoded.compile().expect("recompiles").as_bytes(),
        bytes.as_slice(),
        "build -> decode -> recompile must be byte-stable",
    );

    let icmpv6 = decoded
        .layer::<Icmpv6>()
        .expect("decoded packet has ICMPv6");
    assert_eq!(icmpv6.icmp_type_value(), ICMPV6_NODE_INFORMATION_RESPONSE);
    assert_eq!(
        icmpv6.body(),
        Icmpv6Body::NodeInformationResponse {
            qtype: NI_QTYPE_NODE_ADDRESSES,
            flags: 0,
        }
    );
    let ni = decoded
        .layer::<NodeInformation>()
        .expect("typed NodeInformation body");
    assert_eq!(ni.nonce_value(), nonce);
    assert_eq!(ni.data_value(), answer.as_slice());
}

// The deferred niche families — Router Renumbering (138, RFC 2894) and Inverse
// Neighbor Discovery Solicitation / Advertisement (141 / 142, RFC 3122) — are
// not modeled with typed bodies (see docs/internal/manifests/icmpv6-coverage.md). The default
// ICMPv6 decode path must preserve them: a valid Icmpv6 header, the body
// classified as Icmpv6Body::Unknown with the rest-of-header preserved, and the
// trailing payload kept as a single Raw layer — never a panic and never a
// misparse into another message type.
#[test]
fn deferred_icmpv6_types_decode_to_unknown_raw_without_panic() {
    for &deferred_type in &[
        ICMPV6_ROUTER_RENUMBERING,       // 138, RFC 2894
        ICMPV6_INVERSE_ND_SOLICITATION,  // 141, RFC 3122
        ICMPV6_INVERSE_ND_ADVERTISEMENT, // 142, RFC 3122
    ] {
        // Arbitrary rest-of-header + body bytes: the decoder must keep them, not
        // interpret them.
        let body: Vec<u8> = vec![0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6];
        let packet = Ipv6::new().src(target_addr()).dst(node_addr()).hlim(64)
            / Icmpv6::new()
                .icmp_type(deferred_type)
                .code(0)
                .rest_of_header([0x11, 0x22, 0x33, 0x44])
            / Raw::from_bytes(body.clone());
        let bytes = packet
            .compile()
            .expect("deferred-type packet compiles")
            .as_bytes()
            .to_vec();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, &bytes)
            .expect("deferred ICMPv6 type decodes without error");

        let icmpv6 = decoded
            .layer::<Icmpv6>()
            .expect("decoded packet has ICMPv6");
        assert_eq!(icmpv6.icmp_type_value(), deferred_type);
        assert_eq!(
            icmpv6.body(),
            Icmpv6Body::Unknown {
                icmp_type: deferred_type,
                rest_of_header: [0x11, 0x22, 0x33, 0x44],
            },
            "deferred type {deferred_type} must classify as Unknown with its rest-of-header preserved",
        );

        // The trailing bytes survive verbatim as a single Raw layer.
        let raw = decoded
            .layer::<Raw>()
            .expect("deferred-type payload preserved as Raw");
        assert_eq!(raw.as_bytes(), body.as_slice());

        // No typed NDP/MLD body was misattached.
        assert!(decoded.layer::<NodeInformation>().is_none());

        // Byte-stable round-trip.
        assert_eq!(
            decoded.compile().expect("recompiles").as_bytes(),
            bytes.as_slice(),
        );
    }
}

// ===========================================================================
// ICMPv6 Extended Echo Request / Reply (RFC 8335, types 160 / 161) and
// Multicast Listener Discovery (MLDv1 RFC 2710 types 130-132, MLDv2 RFC 3810 /
// RFC 9777 type 143 report + type 130 v2 query). These are the primary
// executable round-trip gate for the families validated in oracle step 30.
//
// Reference backend byte agreement: MLDv1 and MLDv2 have native reference
// classes (ICMPv6MLQuery / ICMPv6MLReport / ICMPv6MLDone / ICMPv6MLQuery2 /
// ICMPv6MLReport2 / ICMPv6MLDMultAddrRec), and the oracle's MLD cases
// (mldv1-general-query, mldv1-report, mldv1-done, mldv2-report-two-records,
// mldv2-general-query in the reference fixture set) were proved byte-identical
// against the reference backend by materializing both sides and diffing the
// IPv6-level ICMPv6 bytes. ICMPv6 Extended Echo (160/161) has NO native
// reference ICMPv6 class, so its correctness is gated by these Rust round-trips
// and the per-module unit tests rather than a reference byte-proof — a
// documented limitation recorded in the oracle case notes.
// ===========================================================================

// --- ICMPv6 Extended Echo (RFC 8335, types 160 / 161) ----------------------

#[test]
fn extended_echo_request_with_interface_identification_round_trips() {
    // RFC 8335 section 3 Extended Echo Request (type 160, code 0): the 16-bit
    // Identifier, 8-bit Sequence Number, and the L (Local) bit ride the ICMPv6
    // header rest-of-header; the body is an RFC 4884 ICMP Extension Structure
    // carrying a single Interface Identification Object (class 3) naming the
    // probed interface by ifIndex — exactly like the ICMPv4 extended echo.
    let packet = Ipv6::new()
        .src(host_link_local())
        .dst(target_addr())
        .hlim(64)
        / Icmpv6::extended_echo_request()
            .id(0x1234)
            .seq(7)
            .extended_l_bit(true)
        / IcmpExtension::new()
        / IcmpExtensionObject::new()
        / IcmpExtensionInterfaceId::by_index(42);
    let bytes = packet
        .compile()
        .expect("extended echo request compiles")
        .as_bytes()
        .to_vec();

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, &bytes)
        .expect("extended echo request decodes from IPv6");
    assert_eq!(
        decoded.compile().expect("recompiles").as_bytes(),
        bytes.as_slice(),
        "build -> decode -> recompile must be byte-stable",
    );

    let icmpv6 = decoded
        .layer::<Icmpv6>()
        .expect("decoded packet has ICMPv6");
    assert_eq!(
        icmpv6.icmp_type_value(),
        ICMPV6_EXTENDED_ECHO_REQUEST,
        "type 160",
    );
    assert_eq!(icmpv6.code_value(), 0);
    assert_eq!(icmpv6.identifier_value(), Some(0x1234));
    assert_eq!(icmpv6.sequence_number_value(), Some(7));
    assert_eq!(icmpv6.extended_l_bit_value(), Some(true), "L bit set");
    assert_eq!(
        icmpv6.body(),
        Icmpv6Body::ExtendedEchoRequest {
            identifier: 0x1234,
            sequence_number: 7,
            local: true,
            reserved_flags: 0,
        },
    );

    // The Interface Identification Object surfaces the ifIndex through the typed
    // extension layer.
    assert!(
        decoded.layer::<IcmpExtension>().is_some(),
        "RFC 4884 extension structure present",
    );
    let id = decoded
        .layer::<IcmpExtensionInterfaceId>()
        .expect("Interface Identification Object");
    assert_eq!(id.index_value(), Some(42));
}

#[test]
fn extended_echo_reply_with_state_round_trips() {
    // RFC 8335 section 3 Extended Echo Reply (type 161): echoes the Identifier
    // and Sequence Number; the Code reports the query result (0 No Error) and the
    // flag byte packs the State (top 3 bits) plus the A/4/6 status bits. The reply
    // carries no body of its own. Here: State Reachable, Active, IPv6 reachable.
    let packet = Ipv6::new()
        .src(target_addr())
        .dst(host_link_local())
        .hlim(64)
        / Icmpv6::extended_echo_reply()
            .id(0xabcd)
            .seq(5)
            .code(ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_ERROR)
            .extended_state(ICMPV6_EXTENDED_ECHO_REPLY_STATE_REACHABLE)
            .extended_active(true)
            .extended_ipv4(false)
            .extended_ipv6(true);
    let bytes = packet
        .compile()
        .expect("extended echo reply compiles")
        .as_bytes()
        .to_vec();

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, &bytes)
        .expect("extended echo reply decodes from IPv6");
    assert_eq!(
        decoded.compile().expect("recompiles").as_bytes(),
        bytes.as_slice(),
        "build -> decode -> recompile must be byte-stable",
    );

    let icmpv6 = decoded
        .layer::<Icmpv6>()
        .expect("decoded packet has ICMPv6");
    assert_eq!(
        icmpv6.icmp_type_value(),
        ICMPV6_EXTENDED_ECHO_REPLY,
        "type 161",
    );
    assert_eq!(
        icmpv6.code_value(),
        ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_ERROR
    );
    assert_eq!(icmpv6.identifier_value(), Some(0xabcd));
    assert_eq!(icmpv6.sequence_number_value(), Some(5));
    assert_eq!(
        icmpv6.extended_state_value(),
        Some(ICMPV6_EXTENDED_ECHO_REPLY_STATE_REACHABLE),
    );
    assert_eq!(icmpv6.extended_active_value(), Some(true));
    assert_eq!(icmpv6.extended_ipv4_value(), Some(false));
    assert_eq!(icmpv6.extended_ipv6_value(), Some(true));
    assert_eq!(
        icmpv6.body(),
        Icmpv6Body::ExtendedEchoReply {
            identifier: 0xabcd,
            sequence_number: 5,
            state: ICMPV6_EXTENDED_ECHO_REPLY_STATE_REACHABLE,
            active: true,
            ipv4: false,
            ipv6: true,
        },
    );

    // The reply has no extension structure of its own.
    assert!(
        decoded.layer::<IcmpExtension>().is_none(),
        "an Extended Echo Reply carries no body",
    );
}

// --- Multicast Listener Discovery v1 (RFC 2710, types 130-132) -------------

/// A documentation-scope multicast group (`ff1e::db8:1`, admin-local scope; the
/// embedded `db8` echoes the RFC 3849 documentation prefix as a mnemonic).
fn mld_group() -> Ipv6Addr {
    Ipv6Addr::new(0xff1e, 0, 0, 0, 0, 0, 0x0db8, 0x0001)
}

/// A second documentation-scope multicast group (`ff1e::db8:2`).
fn mld_group2() -> Ipv6Addr {
    Ipv6Addr::new(0xff1e, 0, 0, 0, 0, 0, 0x0db8, 0x0002)
}

/// A documentation source address (`2001:db8::101`) for MLDv2 source lists.
fn mld_source1() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0101)
}

/// A second documentation source address (`2001:db8::102`).
fn mld_source2() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0102)
}

/// Compile an `Ipv6` / MLD packet (hop limit 1, per RFC 2710 section 3), decode
/// it back over IPv6, and assert the build -> decode -> recompile cycle is
/// byte-stable. Returns the decoded packet for per-message field assertions.
/// MLD's enclosing Hop-by-Hop Router Alert option (RFC 2711) is the caller's
/// concern and is not needed to exercise the ICMPv6 message round-trip here.
fn mld_round_trip(src: Ipv6Addr, dst: Ipv6Addr, payload: Packet) -> Packet {
    let packet = Ipv6::new().src(src).dst(dst).hlim(1) / payload;
    let bytes = packet
        .compile()
        .expect("MLD packet compiles")
        .as_bytes()
        .to_vec();

    let decoded =
        Packet::decode_from_l3(NetworkLayer::Ipv6, &bytes).expect("MLD packet decodes from IPv6");
    assert_eq!(
        decoded.compile().expect("recompiles").as_bytes(),
        bytes.as_slice(),
        "build -> decode -> recompile must be byte-stable",
    );
    decoded
}

#[test]
fn mldv1_general_query_round_trips() {
    // RFC 2710 section 3 General Query (type 130): the Multicast Address is the
    // unspecified address (::), sent to the all-nodes multicast ff02::1, with a
    // Maximum Response Delay in the rest-of-header.
    let decoded = mld_round_trip(
        host_link_local(),
        all_nodes(),
        Icmpv6::mld_general_query(10_000),
    );

    let icmpv6 = decoded
        .layer::<Icmpv6>()
        .expect("decoded packet has ICMPv6");
    assert_eq!(icmpv6.icmp_type_value(), ICMPV6_MULTICAST_LISTENER_QUERY);
    assert_eq!(icmpv6.code_value(), 0);
    assert_eq!(
        icmpv6.body(),
        Icmpv6Body::MulticastListenerQuery {
            max_response_delay: 10_000,
        },
    );

    let mld = decoded
        .layer::<MulticastListenerMessage>()
        .expect("typed MLDv1 body");
    assert_eq!(mld.multicast_address_value(), Ipv6Addr::UNSPECIFIED);
}

#[test]
fn mldv1_report_round_trips() {
    // RFC 2710 section 3 Report (type 131): announces the sender listens to a
    // group; the Maximum Response Delay is meaningful only on a Query, so it is
    // zero here.
    let decoded = mld_round_trip(
        host_link_local(),
        mld_group(),
        Icmpv6::mld_report(mld_group()),
    );

    let icmpv6 = decoded
        .layer::<Icmpv6>()
        .expect("decoded packet has ICMPv6");
    assert_eq!(icmpv6.icmp_type_value(), ICMPV6_MULTICAST_LISTENER_REPORT);
    assert_eq!(
        icmpv6.body(),
        Icmpv6Body::MulticastListenerReport {
            max_response_delay: 0,
        },
    );

    let mld = decoded
        .layer::<MulticastListenerMessage>()
        .expect("typed MLDv1 body");
    assert_eq!(mld.multicast_address_value(), mld_group());
}

#[test]
fn mldv1_done_round_trips() {
    // RFC 2710 section 3 Done (type 132): announces the sender is ceasing to
    // listen to a group (the multicast analogue of an IGMP Leave).
    let decoded = mld_round_trip(
        host_link_local(),
        all_routers(),
        Icmpv6::mld_done(mld_group()),
    );

    let icmpv6 = decoded
        .layer::<Icmpv6>()
        .expect("decoded packet has ICMPv6");
    assert_eq!(icmpv6.icmp_type_value(), ICMPV6_MULTICAST_LISTENER_DONE);
    assert_eq!(
        icmpv6.body(),
        Icmpv6Body::MulticastListenerDone {
            max_response_delay: 0,
        },
    );

    let mld = decoded
        .layer::<MulticastListenerMessage>()
        .expect("typed MLDv1 body");
    assert_eq!(mld.multicast_address_value(), mld_group());
}

// --- Multicast Listener Discovery v2 (RFC 3810 / RFC 9777, type 143) --------

#[test]
fn mldv2_report_with_two_records_round_trips() {
    // RFC 3810 section 5.2 Version 2 Report (type 143) with two Multicast Address
    // Records: one MODE_IS_INCLUDE with two sources, one MODE_IS_EXCLUDE with no
    // sources, sent to the all-MLDv2-routers multicast ff02::16. The record count
    // (auto-filled), each record type, multicast address, and source list all
    // round-trip. This is the spec.md edge case "an MLDv2 report with multiple
    // multicast address records and source lists ... round-trips".
    let include = MulticastAddressRecord::new(MulticastRecordType::ModeIsInclude, mld_group())
        .source(mld_source1())
        .source(mld_source2());
    let exclude = MulticastAddressRecord::new(MulticastRecordType::ModeIsExclude, mld_group2());

    let decoded = mld_round_trip(
        host_link_local(),
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0016),
        Icmpv6::mldv2_report(vec![include, exclude]),
    );

    let icmpv6 = decoded
        .layer::<Icmpv6>()
        .expect("decoded packet has ICMPv6");
    assert_eq!(icmpv6.icmp_type_value(), ICMPV6_MLDV2_REPORT);
    assert_eq!(icmpv6.code_value(), 0);
    assert_eq!(
        icmpv6.body(),
        Icmpv6Body::Mldv2Report {
            number_of_records: 2,
        },
    );

    let report = decoded.layer::<Mldv2Report>().expect("typed MLDv2 report");
    assert_eq!(report.number_of_records(), 2);
    let records = report.records_ref();

    // Record 0: MODE_IS_INCLUDE, group mld_group(), two sources in order.
    assert_eq!(
        records[0].record_type_value(),
        MulticastRecordType::ModeIsInclude,
    );
    assert_eq!(records[0].multicast_address_value(), mld_group());
    assert_eq!(records[0].number_of_sources(), 2);
    assert_eq!(records[0].sources_ref(), &[mld_source1(), mld_source2()]);

    // Record 1: MODE_IS_EXCLUDE, group mld_group2(), no sources.
    assert_eq!(
        records[1].record_type_value(),
        MulticastRecordType::ModeIsExclude,
    );
    assert_eq!(records[1].multicast_address_value(), mld_group2());
    assert_eq!(records[1].number_of_sources(), 0);
    assert!(records[1].sources_ref().is_empty());
}

#[test]
fn mldv2_general_query_round_trips() {
    // RFC 3810 section 5.1 Version 2 General Query (type 130, the longer body
    // shape) with QRV and QQIC set and no sources; it decodes as an MLDv2 Query,
    // not an MLDv1 Query, even though both share type 130 (body-length seam).
    let query = Mldv2Query::new(Ipv6Addr::UNSPECIFIED)
        .querier_robustness(2)
        .querier_query_interval_code(125);
    let decoded = mld_round_trip(
        host_link_local(),
        all_nodes(),
        Icmpv6::mldv2_query(10_000, query),
    );

    let icmpv6 = decoded
        .layer::<Icmpv6>()
        .expect("decoded packet has ICMPv6");
    assert_eq!(icmpv6.icmp_type_value(), ICMPV6_MULTICAST_LISTENER_QUERY);

    let query = decoded.layer::<Mldv2Query>().expect("typed MLDv2 query");
    assert_eq!(query.multicast_address_value(), Ipv6Addr::UNSPECIFIED);
    assert_eq!(query.querier_robustness_value(), 2);
    assert_eq!(query.querier_query_interval_code_value(), 125);
    assert!(query.number_of_sources() == 0);
    // The longer body is an MLDv2 Query, not mis-decoded as an MLDv1 message.
    assert!(decoded.layer::<MulticastListenerMessage>().is_none());
}
