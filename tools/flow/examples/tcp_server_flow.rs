use crafter_flow::flows::tcp::server_flow;
use crafter_flow::{docaddr, FlowOutcome, MemoryCaptureSource, RunOptions, Runner};

const LISTEN_PORT: u16 = 8080;
const CLIENT_PORT: u16 = 49_153;
const CLIENT_ISS: u32 = 0x3132_3334;
const CLIENT_WINDOW: u16 = 32_768;
const CLIENT_MSS: u16 = 1_200;
const CLIENT_PAYLOAD: &[u8] = b"client request";
const SERVER_RESPONSE: &[u8] = b"server response";

fn syn_from_client(client_seq: u32) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(docaddr::CLIENT_IPV4)
            .dst(docaddr::SERVER_IPV4)
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(CLIENT_PORT)
                .dport(LISTEN_PORT)
                .seq(client_seq)
                .window(CLIENT_WINDOW)
                .syn_segment()
                .tcp_option(crafter::TcpOption::maximum_segment_size(CLIENT_MSS))
                .expect("fixed client TCP MSS option encodes"),
    )
}

fn ack_from_client(client_seq: u32, ack: u32) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(docaddr::CLIENT_IPV4)
            .dst(docaddr::SERVER_IPV4)
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(CLIENT_PORT)
                .dport(LISTEN_PORT)
                .seq(client_seq)
                .ack(ack)
                .window(CLIENT_WINDOW)
                .ack_segment(),
    )
}

fn data_from_client(client_seq: u32, ack: u32, payload: impl AsRef<[u8]>) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(docaddr::CLIENT_IPV4)
            .dst(docaddr::SERVER_IPV4)
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(CLIENT_PORT)
                .dport(LISTEN_PORT)
                .seq(client_seq)
                .ack(ack)
                .window(CLIENT_WINDOW)
                .ack_segment()
                .psh()
            / crafter::Raw::from_bytes(payload),
    )
}

fn fin_ack_from_client(client_seq: u32, ack: u32) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(docaddr::CLIENT_IPV4)
            .dst(docaddr::SERVER_IPV4)
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(CLIENT_PORT)
                .dport(LISTEN_PORT)
                .seq(client_seq)
                .ack(ack)
                .window(CLIENT_WINDOW)
                .fin_ack_segment(),
    )
}

fn decode_ipv4(packet: crafter::Packet) -> crafter::Packet {
    let compiled = packet.compile().expect("TCP packet compiles");

    crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, compiled.as_bytes())
        .expect("TCP packet decodes as IPv4")
}

fn sent_packet(report: &crafter::net::SendReport) -> crafter_flow::Result<crafter::Packet> {
    Ok(crafter::Packet::decode_from_l3(
        crafter::NetworkLayer::Ipv4,
        report.plan().bytes(),
    )?)
}

fn discover_server_send_next() -> crafter_flow::Result<u32> {
    let mut flow = server_flow(docaddr::SERVER_IPV4, LISTEN_PORT, None);
    let mut runner = Runner::with_source(
        RunOptions::default(),
        MemoryCaptureSource::new(vec![syn_from_client(CLIENT_ISS)]),
    )?;
    let _report = runner.run(&mut flow)?;
    let syn_ack = sent_packet(
        runner
            .send_reports()
            .first()
            .expect("SYN discovery emits SYN-ACK"),
    )?;
    let tcp = syn_ack
        .layer::<crafter::Tcp>()
        .expect("SYN-ACK has TCP layer");

    Ok(tcp.sequence_number_value().wrapping_add(1))
}

fn plan_label(packet: &crafter::Packet) -> &'static str {
    let Some(tcp) = packet.layer::<crafter::Tcp>() else {
        return "non-TCP";
    };

    if tcp.has_syn() {
        "SYN-ACK"
    } else if tcp.has_fin() {
        "FIN"
    } else if packet.layer::<crafter::Raw>().is_some() {
        "response"
    } else {
        "ACK"
    }
}

fn print_send_plan(index: usize, report: &crafter::net::SendReport) -> crafter_flow::Result<()> {
    let packet = sent_packet(report)?;
    let label = plan_label(&packet);
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

    if let Some(tcp) = packet.layer::<crafter::Tcp>() {
        println!(
            "  tcp: source_port={} destination_port={} seq={} ack={} flags=0x{:03x} window={}",
            tcp.source_port_value(),
            tcp.destination_port_value(),
            tcp.sequence_number_value(),
            tcp.acknowledgment_number_value(),
            tcp.flags_value(),
            tcp.window_value()
        );
    }

    if let Some(raw) = packet.layer::<crafter::Raw>() {
        println!("  payload: {:?}", String::from_utf8_lossy(raw.as_bytes()));
    }

    Ok(())
}

fn main() -> crafter_flow::Result<()> {
    let server_snd_nxt = discover_server_send_next()?;
    let client_snd_nxt = CLIENT_ISS.wrapping_add(1);
    let client_data_end = client_snd_nxt.wrapping_add(CLIENT_PAYLOAD.len() as u32);
    let server_response_end = server_snd_nxt.wrapping_add(SERVER_RESPONSE.len() as u32);
    let client_fin_end = client_data_end.wrapping_add(1);
    let server_fin_end = server_response_end.wrapping_add(1);
    let source = MemoryCaptureSource::new(vec![
        syn_from_client(CLIENT_ISS),
        ack_from_client(client_snd_nxt, server_snd_nxt),
        data_from_client(client_snd_nxt, server_snd_nxt, CLIENT_PAYLOAD),
        fin_ack_from_client(client_data_end, server_response_end),
        ack_from_client(client_fin_end, server_fin_end),
    ]);
    let mut flow = server_flow(
        docaddr::SERVER_IPV4,
        LISTEN_PORT,
        Some(SERVER_RESPONSE.to_vec()),
    );
    let mut runner = Runner::with_source(RunOptions::default(), source)?;

    println!("{}", flow.show());

    let report = runner.run(&mut flow)?;

    for (index, send_report) in runner.send_reports().iter().enumerate() {
        print_send_plan(index, send_report)?;
    }

    println!("{}", report.show());

    assert_eq!(report.outcome(), &FlowOutcome::Completed);

    Ok(())
}
