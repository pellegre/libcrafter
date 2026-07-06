use std::net::Ipv4Addr;

use crafter_flow::flows::dhcpv4::{client_flow, SELECTING};
use crafter_flow::{docaddr, MemoryCaptureSource, PacketContext, RunOptions, Runner};

fn server_mac() -> crafter::MacAddr {
    crafter::MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x02])
}

fn discover_transaction_id(client_mac: crafter::MacAddr) -> u32 {
    let mut flow = client_flow(client_mac);
    let mut context = PacketContext::new();

    flow.state_mut(SELECTING)
        .expect("Selecting state exists")
        .run_entry(&mut context)
        .expect("Selecting entry succeeds")
        .expect("Selecting entry sends DISCOVER");

    context
        .get_transaction_id()
        .expect("Selecting entry stores transaction id")
}

fn offer_packet(transaction_id: u32, offered_ip: Ipv4Addr, server_id: Ipv4Addr) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(server_mac())
        .dst(crafter::MacAddr::BROADCAST)
        / crafter::Ipv4::new().src(server_id).dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_server()
        / crafter::Dhcpv4::offer(docaddr::CLIENT_MAC, offered_ip, server_id).xid(transaction_id)
}

fn ack_packet(transaction_id: u32, assigned_ip: Ipv4Addr, server_id: Ipv4Addr) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(server_mac())
        .dst(crafter::MacAddr::BROADCAST)
        / crafter::Ipv4::new().src(server_id).dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_server()
        / crafter::Dhcpv4::ack(docaddr::CLIENT_MAC, assigned_ip, server_id).xid(transaction_id)
}

fn main() -> crafter_flow::Result<()> {
    let offered_ip = Ipv4Addr::new(192, 0, 2, 44);
    let server_id = docaddr::SERVER_IPV4;
    let transaction_id = discover_transaction_id(docaddr::CLIENT_MAC);
    let offer = offer_packet(transaction_id, offered_ip, server_id);
    let ack = ack_packet(transaction_id, offered_ip, server_id);
    let mut flow = client_flow(docaddr::CLIENT_MAC);
    let mut runner = Runner::with_source(
        RunOptions::default(),
        MemoryCaptureSource::new(vec![offer, ack]),
    )?;

    println!("{}", flow.show());

    let report = runner.run(&mut flow)?;

    for (index, send_report) in runner.send_reports().iter().enumerate() {
        let plan = send_report.plan();
        println!(
            "send plan #{index}: dry_run={} interface={} mode={:?} target={:?} bytes={}",
            send_report.is_dry_run(),
            plan.interface(),
            plan.requested_mode(),
            plan.target(),
            plan.len()
        );
    }

    println!("{}", report.show());

    Ok(())
}
