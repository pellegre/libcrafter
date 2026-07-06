use std::time::Duration;

use crafter_flow::flows::arp::{injector_flow, ANNOUNCE};
use crafter_flow::{docaddr, Bound, FlowOutcome, MemoryCaptureSource, Role, RunOptions, Runner};

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

fn decode_send_plan(report: &crafter::net::SendReport) -> crafter::Packet {
    crafter::Packet::decode_from_link(crafter::LinkType::Ethernet, report.plan().bytes())
        .expect("dry-run send plan decodes as Ethernet")
}

fn assert_is_at(
    packet: &crafter::Packet,
    ethernet_src: crafter::MacAddr,
    ethernet_dst: crafter::MacAddr,
    sender_ip: std::net::Ipv4Addr,
    sender_mac: crafter::MacAddr,
    target_ip: std::net::Ipv4Addr,
    target_mac: crafter::MacAddr,
) {
    let ethernet = packet
        .layer::<crafter::Ethernet>()
        .expect("packet contains Ethernet");
    let arp = packet.layer::<crafter::Arp>().expect("packet contains ARP");

    assert_eq!(ethernet.source(), Some(ethernet_src));
    assert_eq!(ethernet.destination(), Some(ethernet_dst));
    assert_eq!(arp.opcode_value(), crafter::ArpOperation::Reply.into());
    assert_eq!(arp.sender_ipv4(), Some(sender_ip));
    assert_eq!(arp.sender_mac(), Some(sender_mac));
    assert_eq!(arp.target_ipv4(), Some(target_ip));
    assert_eq!(arp.target_mac(), Some(target_mac));
}

#[test]
fn arp_injector_flow_emits_gratuitous_arp_and_replies_to_who_has_offline() {
    let bind_ip = docaddr::SERVER_IPV4;
    let bind_mac = docaddr::LOCAL_MAC;
    let requester_ip = docaddr::CLIENT_IPV4;
    let requester_mac = docaddr::CLIENT_MAC;
    let observed = who_has(requester_ip, bind_ip, requester_mac);
    let options = RunOptions::default()
        .bound(Bound::Count(2))
        .step_timeout(Duration::from_millis(1));
    let mut flow = injector_flow(bind_ip, bind_mac);
    let mut runner = Runner::with_source(options, MemoryCaptureSource::new(vec![observed]))
        .expect("offline runner opens");

    let report = runner.run(&mut flow).expect("ARP injector flow runs");

    assert_eq!(runner.options().bound, Bound::Count(2));
    assert!(report.is_dry_run());
    assert_eq!(report.role(), Role::Injector);
    assert_eq!(report.outcome(), &FlowOutcome::TimedOut);
    assert_eq!(report.visited_states(), &[ANNOUNCE.to_string()]);
    assert_eq!(
        report.transitions_taken(),
        &["Arp where who-has target protocol address".to_string()]
    );
    assert_eq!(report.sent_count(), 2);
    assert_eq!(report.received_count(), 1);
    assert_eq!(report.iterations(), 0);
    assert_eq!(runner.send_reports().len(), 2);
    assert!(runner
        .send_reports()
        .iter()
        .all(|report| report.is_dry_run()));

    let gratuitous = decode_send_plan(&runner.send_reports()[0]);
    assert_is_at(
        &gratuitous,
        bind_mac,
        crafter::MacAddr::BROADCAST,
        bind_ip,
        bind_mac,
        bind_ip,
        crafter::MacAddr::BROADCAST,
    );

    let reply = decode_send_plan(&runner.send_reports()[1]);
    assert_is_at(
        &reply,
        bind_mac,
        requester_mac,
        bind_ip,
        bind_mac,
        requester_ip,
        requester_mac,
    );

    let report_show = report.show();
    assert!(report_show.contains("FlowReport 'arp-injector'"));
    assert!(report_show.contains("packets: sent=2, received=1"));
    assert!(report_show.contains("iterations: 0"));
    assert!(report_show.contains(ANNOUNCE));
    assert!(report_show.contains("Arp where who-has target protocol address"));
}
