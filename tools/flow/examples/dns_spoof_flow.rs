use crafter_flow::flows::dns::spoof_flow;
use crafter_flow::{docaddr, MemoryCaptureSource, RunOptions, Runner};

const SPOOF_NAME: &str = "service.example.";
const TRANSACTION_ID: u16 = 0x6844;
const QUERIER_PORT: u16 = 53253;

fn query_packet() -> crafter::Packet {
    let packet = crafter::Ipv4::new()
        .src(docaddr::CLIENT_IPV4)
        .dst(docaddr::DNS_IPV4)
        / crafter::Udp::new()
            .source_port(QUERIER_PORT)
            .destination_port(crafter::DNS_PORT)
        / crafter::Dns::query(SPOOF_NAME, crafter::DNS_TYPE_A).id(TRANSACTION_ID);
    let compiled = packet.compile().expect("DNS query should compile");

    crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, compiled.as_bytes())
        .expect("DNS query should decode")
}

fn print_send_plan(index: usize, report: &crafter::net::SendReport) -> crafter_flow::Result<()> {
    let packet =
        crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, report.plan().bytes())?;
    let plan = report.plan();

    println!(
        "send plan #{index} (forged DNS response): dry_run={} interface={} mode={:?} target={:?} bytes={} summary={}",
        report.is_dry_run(),
        plan.interface(),
        plan.requested_mode(),
        plan.target(),
        plan.len(),
        packet.summary()
    );

    if let (Some(ipv4), Some(udp), Some(dns)) = (
        packet.layer::<crafter::Ipv4>(),
        packet.layer::<crafter::Udp>(),
        packet.layer::<crafter::Dns>(),
    ) {
        println!(
            "  ipv4: src={:?} dst={:?}",
            ipv4.source(),
            ipv4.destination()
        );
        println!(
            "  udp: source_port={} destination_port={}",
            udp.source_port_value(),
            udp.destination_port_value()
        );
        println!(
            "  dns: id={} response={} questions={} answers={}",
            dns.id_value(),
            dns.is_response(),
            dns.questions().len(),
            dns.answers().len()
        );
        for answer in dns.answers() {
            println!(
                "  answer: name={} type={} data={:?}",
                answer.name(),
                answer.record_type(),
                answer.data()
            );
        }
    }

    Ok(())
}

fn main() -> crafter_flow::Result<()> {
    let answer_ip = docaddr::GATEWAY_IPV4;
    let observed = query_packet();
    let mut flow = spoof_flow(SPOOF_NAME, answer_ip);
    let mut runner = Runner::with_source(
        RunOptions::default(),
        MemoryCaptureSource::new(vec![observed]),
    )?;

    println!("{}", flow.show());

    let report = runner.run(&mut flow)?;

    for (index, send_report) in runner.send_reports().iter().enumerate() {
        print_send_plan(index, send_report)?;
    }

    println!("{}", report.show());

    Ok(())
}
