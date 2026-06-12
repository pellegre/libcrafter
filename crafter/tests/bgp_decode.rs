use std::net::Ipv4Addr;

use crafter::prelude::*;
use crafter::protocols::bgp::BGP_PORT;

fn bgp_tcp_packet(source_port: u16, destination_port: u16) -> Packet {
    Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Tcp::new()
            .sport(source_port)
            .dport(destination_port)
            .seq(0x0102_0304)
            .ack(0x0506_0708)
            .ack_segment()
        / Bgp::open()
            .my_as(64_512)
            .hold_time(90)
            .bgp_id(Ipv4Addr::new(192, 0, 2, 179))
        / Bgp::keepalive()
}

fn assert_default_registry_decodes_bgp_stack(
    source_port: u16,
    destination_port: u16,
) -> crafter::Result<()> {
    let packet = bgp_tcp_packet(source_port, destination_port);
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    let layer_names = decoded.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    assert_eq!(layer_names, vec!["Ipv4", "Tcp", "BGP", "BGP"]);

    assert!(decoded.layer::<Ipv4>().is_some());
    let tcp = decoded.layer::<Tcp>().expect("decoded tcp layer");
    assert_eq!(tcp.source_port_value(), source_port);
    assert_eq!(tcp.destination_port_value(), destination_port);

    let bgp_summaries = decoded
        .layers::<Bgp>()
        .map(|bgp| bgp.summary())
        .collect::<Vec<_>>();
    assert_eq!(bgp_summaries.len(), 2);
    assert!(bgp_summaries[0].starts_with("BGP OPEN "));
    assert_eq!(bgp_summaries[1], "BGP KEEPALIVE len=19");

    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}

#[test]
fn default_registry_decodes_bgp_destination_port_179_stack() -> crafter::Result<()> {
    assert_default_registry_decodes_bgp_stack(49_152, BGP_PORT)
}

#[test]
fn default_registry_decodes_bgp_source_port_179_stack() -> crafter::Result<()> {
    assert_default_registry_decodes_bgp_stack(BGP_PORT, 49_152)
}
