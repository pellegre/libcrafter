//! Public-surface tests for generated-tool-facing SSDP helpers.

use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

const IPV4_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const IPV6_SOURCE: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);

#[test]
fn ssdp_public_api_prelude_builds_ipv4_search_packet() -> crafter::Result<()> {
    let message = Ssdp::m_search_rootdevice().mx(2);
    let packet = ssdp_ipv4_multicast_packet(IPV4_SOURCE, message.clone());
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let ipv4 = decoded.layer::<Ipv4>().expect("IPv4 layer");
    let udp = decoded.layer::<Udp>().expect("UDP layer");
    let ssdp = decoded.layer::<Ssdp>().expect("SSDP layer");

    assert_eq!(ipv4.source(), IPV4_SOURCE);
    assert_eq!(ipv4.destination(), SSDP_IPV4_MULTICAST_ADDR);
    assert_eq!(ipv4.ttl_value(), 2);
    assert_eq!(udp.source_port_value(), SSDP_UDP_PORT);
    assert_eq!(udp.destination_port_value(), SSDP_UDP_PORT);
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
    assert_eq!(ssdp, &message);
    assert_eq!(
        ssdp.headers()
            .get_first(SsdpHeaderNameKind::St)
            .expect("ST header")
            .as_bytes(),
        SSDP_TARGET_ROOTDEVICE.as_bytes()
    );

    Ok(())
}

#[test]
fn ssdp_public_api_prelude_builds_ipv6_search_packet_with_overrides() -> crafter::Result<()> {
    let message = Ssdp::m_search()
        .host(SSDP_IPV6_LINK_LOCAL_HOST)
        .man_discover()
        .mx(1)
        .search_target(SsdpTarget::all());
    let packet = ssdp_ipv6_multicast_packet_with(
        IPV6_SOURCE,
        SSDP_IPV6_LINK_LOCAL_MULTICAST_ADDR,
        1,
        Ssdp::udp().sport(49_152),
        message.clone(),
    );
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())?;
    let ipv6 = decoded.layer::<Ipv6>().expect("IPv6 layer");
    let udp = decoded.layer::<Udp>().expect("UDP layer");
    let ssdp = decoded.layer::<Ssdp>().expect("SSDP layer");

    assert_eq!(ipv6.source(), IPV6_SOURCE);
    assert_eq!(ipv6.destination(), SSDP_IPV6_LINK_LOCAL_MULTICAST_ADDR);
    assert_eq!(ipv6.hop_limit_value(), 1);
    assert_eq!(udp.source_port_value(), 49_152);
    assert_eq!(udp.destination_port_value(), SSDP_UDP_PORT);
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
    assert_eq!(ssdp, &message);
    assert_eq!(
        ssdp.headers()
            .get_first(SsdpHeaderNameKind::Host)
            .expect("HOST header")
            .as_bytes(),
        SSDP_IPV6_LINK_LOCAL_HOST.as_bytes()
    );

    Ok(())
}

#[test]
fn ssdp_public_api_prelude_builds_notify_and_response_messages() -> crafter::Result<()> {
    let location =
        SsdpLocation::new("http://192.0.2.10:8000/rootDesc.xml").expect("location URI is valid");
    let notify = Ssdp::notify_alive()
        .notification_type(SsdpTarget::rootdevice())
        .unique_service_name(SsdpUsn::rootdevice("device-1"))
        .location(location)
        .max_age(1_800)
        .server("ExampleOS/1.0 UPnP/2.0 libcrafter/0.3")
        .boot_id(1)
        .config_id(1)
        .next_boot_id(2)
        .search_port(49_152)
        .tcp_port(49_153)
        .opt("\"http://schemas.upnp.org/upnp/1/0/\"; ns=01")
        .nls("01", "12345678")
        .expect("NLS header name is valid");
    let response = Ssdp::response_ok_with_ext()
        .search_target(SsdpTarget::all())
        .unique_service_name(SsdpUsn::target("device-1", SsdpTarget::all()))
        .secure_location("https://example.com/rootDesc.xml")
        .user_agent("ExampleOS/1.0 UPnP/2.0 libcrafter/0.3");

    let notify_roundtrip = Ssdp::parse(&notify.to_bytes()).expect("notify parses");
    let response_roundtrip = Ssdp::parse(&response.to_bytes()).expect("response parses");

    assert_eq!(notify_roundtrip, notify);
    assert_eq!(
        notify_roundtrip
            .headers()
            .get_first(SsdpHeaderNameKind::CacheControl)
            .expect("CACHE-CONTROL header")
            .as_bytes(),
        b"max-age=1800"
    );
    assert!(notify_roundtrip
        .headers()
        .get_first(SsdpHeaderNameKind::NlsPrefixed)
        .is_some());
    assert_eq!(response_roundtrip, response);
    assert_eq!(
        response_roundtrip
            .headers()
            .get_first(SsdpHeaderNameKind::Ext)
            .expect("EXT header")
            .as_bytes(),
        b""
    );

    Ok(())
}

#[test]
fn ssdp_public_api_reexports_root_core_and_prelude_surface() {
    let root: crafter::Ssdp = crafter::Ssdp::m_search_all();
    let core: crafter::core::Ssdp = crafter::core::Ssdp::notify_byebye();
    let prelude: Ssdp = Ssdp::response_ok_with_ext();

    assert_eq!(crafter::SSDP_UDP_PORT, SSDP_UDP_PORT);
    assert_eq!(crafter::core::SSDP_ST_ALL, SSDP_ST_ALL);
    assert_eq!(
        crafter::prelude::SSDP_IPV4_MULTICAST_ADDR,
        SSDP_IPV4_MULTICAST_ADDR
    );
    assert!(root.headers().get_first(SsdpHeaderNameKind::St).is_some());
    assert!(core.headers().get_first(SsdpHeaderNameKind::Nts).is_some());
    assert!(prelude
        .headers()
        .get_first(SsdpHeaderNameKind::Ext)
        .is_some());
}
