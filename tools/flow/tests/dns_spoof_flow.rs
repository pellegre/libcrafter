use std::time::Duration;

use crafter_flow::flows::dns::{spoof_flow, WATCH};
use crafter_flow::{docaddr, Bound, FlowOutcome, MemoryCaptureSource, Role, RunOptions, Runner};

fn dns_query_packet(name: &str, transaction_id: u16, source_port: u16) -> crafter::Packet {
    let packet = crafter::Ipv4::new()
        .src(docaddr::CLIENT_IPV4)
        .dst(docaddr::DNS_IPV4)
        / crafter::Udp::new()
            .source_port(source_port)
            .destination_port(crafter::DNS_PORT)
        / crafter::Dns::query(name, crafter::DNS_TYPE_A).id(transaction_id);
    let compiled = packet.compile().expect("DNS query should compile");

    crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, compiled.as_bytes())
        .expect("DNS query should decode")
}

fn decode_send_plan(report: &crafter::net::SendReport) -> crafter::Packet {
    crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, report.plan().bytes())
        .expect("dry-run send plan decodes as IPv4")
}

#[test]
fn dns_spoof_flow_emits_forged_response_to_matching_query_offline() {
    let spoof_name = "www.example.test.";
    let answer_ip = docaddr::GATEWAY_IPV4;
    let transaction_id = 0x7253;
    let querier_port = 53210;
    let query = dns_query_packet(spoof_name, transaction_id, querier_port);
    let expected_questions = query
        .layer::<crafter::Dns>()
        .expect("query contains DNS")
        .questions()
        .to_vec();
    let options = RunOptions::default()
        .bound(Bound::Count(1))
        .step_timeout(Duration::from_millis(1));
    let mut flow = spoof_flow(spoof_name, answer_ip);
    let mut runner = Runner::with_source(options, MemoryCaptureSource::new(vec![query]))
        .expect("offline runner opens");

    let report = runner.run(&mut flow).expect("DNS spoof flow runs");

    assert_eq!(runner.options().bound, Bound::Count(1));
    assert!(report.is_dry_run());
    assert_eq!(report.role(), Role::Injector);
    assert_eq!(report.outcome(), &FlowOutcome::TimedOut);
    assert_eq!(report.visited_states(), &[WATCH.to_string()]);
    assert_eq!(
        report.transitions_taken(),
        &["Dns where query for www.example.test.".to_string()]
    );
    assert_eq!(report.sent_count(), 1);
    assert_eq!(report.received_count(), 1);
    assert_eq!(runner.send_reports().len(), 1);
    assert!(runner.send_reports()[0].is_dry_run());

    let response = decode_send_plan(&runner.send_reports()[0]);
    let ipv4 = response
        .layer::<crafter::Ipv4>()
        .expect("response has IPv4");
    let udp = response.layer::<crafter::Udp>().expect("response has UDP");
    let dns = response.layer::<crafter::Dns>().expect("response has DNS");
    let answer = dns.answers().first().expect("response has an answer");

    assert_eq!(ipv4.source(), docaddr::DNS_IPV4);
    assert_eq!(ipv4.destination(), docaddr::CLIENT_IPV4);
    assert_eq!(udp.source_port_value(), crafter::DNS_PORT);
    assert_eq!(udp.destination_port_value(), querier_port);
    assert!(dns.is_response());
    assert_eq!(dns.id_value(), transaction_id);
    assert_eq!(dns.questions(), expected_questions.as_slice());
    assert_eq!(answer.name(), expected_questions[0].name());
    assert_eq!(answer.record_type(), crafter::DNS_TYPE_A);
    assert_eq!(answer.data(), &crafter::DnsRecordData::A(answer_ip));

    let report_show = report.show();
    assert!(report_show.contains("FlowReport 'dns-spoof'"));
    assert!(report_show.contains("packets: sent=1, received=1"));
    assert!(report_show.contains("Dns where query for www.example.test."));
}
