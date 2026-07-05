use std::net::Ipv4Addr;

use crafter_flow::flows::dhcpv4::server_flow;
use crafter_flow::{docaddr, MemoryCaptureSource, RunOptions, Runner};

const TRANSACTION_ID: u32 = 0x5300_0001;

fn discover_packet(client_mac: crafter::MacAddr, transaction_id: u32) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(client_mac)
        .dst(crafter::MacAddr::BROADCAST)
        / crafter::Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_client()
        / crafter::Dhcpv4::discover(client_mac).xid(transaction_id)
}

fn request_packet(
    client_mac: crafter::MacAddr,
    transaction_id: u32,
    requested_ip: Ipv4Addr,
    server_identifier: Ipv4Addr,
) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(client_mac)
        .dst(crafter::MacAddr::BROADCAST)
        / crafter::Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_client()
        / crafter::Dhcpv4::request(client_mac, requested_ip, server_identifier).xid(transaction_id)
}

fn print_send_plan(index: usize, report: &crafter::net::SendReport) -> crafter_flow::Result<()> {
    let packet =
        crafter::Packet::decode_from_link(crafter::LinkType::Ethernet, report.plan().bytes())?;
    let message_type = packet
        .layer::<crafter::Dhcpv4>()
        .and_then(|dhcp| dhcp.message_type_value());
    let plan = report.plan();

    println!(
        "send plan #{index}: message_type={message_type:?} dry_run={} interface={} mode={:?} target={:?} bytes={}",
        report.is_dry_run(),
        plan.interface(),
        plan.requested_mode(),
        plan.target(),
        plan.len()
    );

    Ok(())
}

fn main() -> crafter_flow::Result<()> {
    let server_mac = docaddr::LOCAL_MAC;
    let server_ip = docaddr::SERVER_IPV4;
    let pool_base = docaddr::CLIENT_IPV4;
    let discover = discover_packet(docaddr::CLIENT_MAC, TRANSACTION_ID);
    let request = request_packet(docaddr::CLIENT_MAC, TRANSACTION_ID, pool_base, server_ip);
    let mut flow = server_flow(server_mac, server_ip, pool_base);
    let mut runner = Runner::with_source(
        RunOptions::default(),
        MemoryCaptureSource::new(vec![discover, request]),
    )?;

    println!("{}", flow.show());

    let report = runner.run(&mut flow)?;

    for (index, send_report) in runner.send_reports().iter().enumerate() {
        print_send_plan(index, send_report)?;
    }

    println!("{}", report.show());

    Ok(())
}
