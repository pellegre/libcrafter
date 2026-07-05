use std::time::Duration;

use crafter_flow::flows::arp::injector_flow;
use crafter_flow::{docaddr, Bound, MemoryCaptureSource, RunOptions, Runner};

fn who_has(
    requester_ip: std::net::Ipv4Addr,
    target_ip: std::net::Ipv4Addr,
    requester_mac: crafter::MacAddr,
) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(requester_mac)
        .dst(crafter::MacAddr::BROADCAST)
        / crafter::Arp::who_has(requester_ip, target_ip, requester_mac)
}

fn print_send_plan(
    index: usize,
    label: &str,
    report: &crafter::net::SendReport,
) -> crafter_flow::Result<()> {
    let packet =
        crafter::Packet::decode_from_link(crafter::LinkType::Ethernet, report.plan().bytes())?;
    let plan = report.plan();

    println!(
        "send plan #{index} ({label}): dry_run={} interface={} mode={:?} target={:?} bytes={} summary={}",
        report.is_dry_run(),
        plan.interface(),
        plan.requested_mode(),
        plan.target(),
        plan.len(),
        packet.summary()
    );

    if let (Some(ethernet), Some(arp)) = (
        packet.layer::<crafter::Ethernet>(),
        packet.layer::<crafter::Arp>(),
    ) {
        println!(
            "  ethernet: src={:?} dst={:?}",
            ethernet.source(),
            ethernet.destination()
        );
        println!(
            "  arp: opcode={} sender={:?}/{:?} target={:?}/{:?}",
            arp.opcode_value(),
            arp.sender_ipv4(),
            arp.sender_mac(),
            arp.target_ipv4(),
            arp.target_mac()
        );
    }

    Ok(())
}

fn main() -> crafter_flow::Result<()> {
    let bind_ip = docaddr::SERVER_IPV4;
    let bind_mac = docaddr::LOCAL_MAC;
    let requester_ip = docaddr::CLIENT_IPV4;
    let requester_mac = docaddr::CLIENT_MAC;
    let observed = who_has(requester_ip, bind_ip, requester_mac);
    let options = RunOptions::default()
        .bound(Bound::Count(2))
        .step_timeout(Duration::from_millis(1));
    let mut flow = injector_flow(bind_ip, bind_mac);
    let mut runner = Runner::with_source(options, MemoryCaptureSource::new(vec![observed]))?;

    println!("{}", flow.show());

    let report = runner.run(&mut flow)?;

    for (index, send_report) in runner.send_reports().iter().enumerate() {
        let label = match index {
            0 => "gratuitous ARP",
            1 => "forged reply",
            _ => "extra emission",
        };
        print_send_plan(index, label, send_report)?;
    }

    println!("{}", report.show());

    Ok(())
}
