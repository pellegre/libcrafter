//! Round-trip integration coverage for the five IPv6 Neighbor Discovery (NDP)
//! core messages (RFC 4861, types 133–137) and their base options.
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
//! policy. These are the same NDP cases the oracle validates against the scapy
//! reference (`tools/oracle/specs/fixtures/scapy-cases.json`:
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
