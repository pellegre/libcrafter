use std::net::Ipv4Addr;

use crafter::prelude::*;

#[test]
fn prelude_builds_and_compiles_packet() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Icmp::echo_request().id(0x4242).seq(1)
        / Raw::from("alpha");

    let compiled = packet.compile()?;

    assert!(!compiled.is_empty());
    assert_eq!(compiled.as_bytes()[0] >> 4, 4);
    assert!(packet.summary().contains("Icmp(type=echo-request"));

    Ok(())
}

#[test]
fn public_module_paths_expose_representative_items() -> crafter::Result<()> {
    let packet = crafter::core::Packet::from_layer(crafter::core::Raw::from("core"));
    assert_eq!(packet.compile()?.as_bytes(), b"core");

    let pcap_header = crafter::pcap::PcapHeader::new(crafter::pcap::PcapLinkType::RawIp);
    assert_eq!(
        pcap_header.precision(),
        crafter::pcap::TimestampPrecision::Microseconds
    );

    let send_options = crafter::net::SendOptions::new()
        .iface("dry-run0")
        .network_layer()
        .dry_run();
    assert!(send_options.is_dry_run());
    assert_eq!(send_options.interface_name(), Some("dry-run0"));

    #[allow(unused_imports)]
    use crafter::live::{artifact, provider, validation};

    Ok(())
}
