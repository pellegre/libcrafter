mod common;

use common::{local_ipv4, print_help_if_requested, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ssdp_notify --\n\nBuild, compile, decode, and inspect SSDP notification packets offline.",
    ) {
        return Ok(());
    }

    let device_uuid = "device-1";
    let location = SsdpLocation::new("http://192.0.2.10:8000/rootDesc.xml")?;
    let root = SsdpTarget::rootdevice();
    let usn = SsdpUsn::rootdevice(device_uuid);
    let packets = vec![
        (
            "alive",
            ssdp_ipv4_multicast_packet(
                local_ipv4(),
                Ssdp::notify_alive()
                    .notification_type(root.clone())
                    .unique_service_name(usn.clone())
                    .location(location.clone())
                    .max_age(1_800)
                    .server("ExampleOS/1.0 UPnP/2.0 libcrafter/0.3")
                    .boot_id(1)
                    .config_id(1),
            ),
        ),
        (
            "byebye",
            ssdp_ipv4_multicast_packet(
                local_ipv4(),
                Ssdp::notify_byebye()
                    .notification_type(root.clone())
                    .unique_service_name(usn.clone())
                    .boot_id(1)
                    .config_id(1),
            ),
        ),
        (
            "update",
            ssdp_ipv4_multicast_packet(
                local_ipv4(),
                Ssdp::notify_update()
                    .notification_type(root)
                    .unique_service_name(usn)
                    .location(location)
                    .max_age(1_800)
                    .boot_id(1)
                    .config_id(2)
                    .next_boot_id(2),
            ),
        ),
    ];

    println!("example: ssdp_notify");
    println!("mode: offline");
    for (label, packet) in packets {
        print_packet(label, &packet)?;
    }

    Ok(())
}

fn print_packet(label: &str, packet: &Packet) -> ExampleResult<()> {
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    println!("{label} summary: {}", decoded.summary());
    println!("{label} show:\n{}", decoded.show());
    println!("{label} hexdump:\n{}", compiled.hexdump());

    Ok(())
}
