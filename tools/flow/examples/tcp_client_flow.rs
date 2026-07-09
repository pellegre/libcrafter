use crafter_flow::flows::tcp::{client_flow, SYN_SENT};
use crafter_flow::{docaddr, MemoryCaptureSource, PacketContext, RunOptions, Runner};

const REMOTE_PORT: u16 = 443;
const PEER_ISS: u32 = 0x5152_5354;
const PEER_WINDOW: u16 = 32_768;
const PEER_MSS: u16 = 1_200;
const CLIENT_PAYLOAD: &[u8] = b"client hello";
const PEER_PAYLOAD: &[u8] = b"server reply";

fn client_syn_numbers(payload: &[u8]) -> (u16, u32) {
    let mut flow = client_flow(
        docaddr::CLIENT_IPV4,
        docaddr::SERVER_IPV4,
        REMOTE_PORT,
        Some(payload.to_vec()),
    );
    let mut context = PacketContext::new();
    let step = flow
        .state_mut(SYN_SENT)
        .expect("SynSent state exists")
        .run_entry(&mut context)
        .expect("SynSent entry succeeds")
        .expect("SynSent entry sends SYN");
    let syn = step.outgoing().expect("SynSent entry has outgoing SYN");
    let tcp = syn.layer::<crafter::Tcp>().expect("SYN has TCP layer");

    (
        tcp.source_port_value(),
        context
            .get_tcp_snd_nxt()
            .expect("SynSent entry stores client snd_nxt"),
    )
}

fn syn_ack_from_peer(local_port: u16, peer_seq: u32, ack: u32) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(docaddr::SERVER_IPV4)
            .dst(docaddr::CLIENT_IPV4)
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(REMOTE_PORT)
                .dport(local_port)
                .seq(peer_seq)
                .ack(ack)
                .window(PEER_WINDOW)
                .syn_ack_segment()
                .tcp_option(crafter::TcpOption::maximum_segment_size(PEER_MSS))
                .expect("fixed peer TCP MSS option encodes"),
    )
}

fn ack_from_peer(local_port: u16, peer_seq: u32, ack: u32) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(docaddr::SERVER_IPV4)
            .dst(docaddr::CLIENT_IPV4)
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(REMOTE_PORT)
                .dport(local_port)
                .seq(peer_seq)
                .ack(ack)
                .window(PEER_WINDOW)
                .ack_segment(),
    )
}

fn data_from_peer(
    local_port: u16,
    peer_seq: u32,
    ack: u32,
    payload: impl AsRef<[u8]>,
) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(docaddr::SERVER_IPV4)
            .dst(docaddr::CLIENT_IPV4)
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(REMOTE_PORT)
                .dport(local_port)
                .seq(peer_seq)
                .ack(ack)
                .window(PEER_WINDOW)
                .ack_segment()
                .psh()
            / crafter::Raw::from_bytes(payload),
    )
}

fn fin_ack_from_peer(local_port: u16, peer_seq: u32, ack: u32) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(docaddr::SERVER_IPV4)
            .dst(docaddr::CLIENT_IPV4)
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(REMOTE_PORT)
                .dport(local_port)
                .seq(peer_seq)
                .ack(ack)
                .window(PEER_WINDOW)
                .fin_ack_segment(),
    )
}

fn decode_ipv4(packet: crafter::Packet) -> crafter::Packet {
    let compiled = packet.compile().expect("TCP packet compiles");

    crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, compiled.as_bytes())
        .expect("TCP packet decodes as IPv4")
}

fn print_send_plan(index: usize, report: &crafter::net::SendReport) -> crafter_flow::Result<()> {
    let packet =
        crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, report.plan().bytes())?;
    let plan = report.plan();

    println!(
        "send plan #{index}: dry_run={} interface={} mode={:?} target={:?} bytes={} summary={}",
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
    let (local_port, client_snd_nxt) = client_syn_numbers(CLIENT_PAYLOAD);
    let client_data_end = client_snd_nxt.wrapping_add(CLIENT_PAYLOAD.len() as u32);
    let peer_data_seq = PEER_ISS.wrapping_add(1);
    let peer_data_end = peer_data_seq.wrapping_add(PEER_PAYLOAD.len() as u32);
    let client_fin_end = client_data_end.wrapping_add(1);
    let source = MemoryCaptureSource::new(vec![
        syn_ack_from_peer(local_port, PEER_ISS, client_snd_nxt),
        ack_from_peer(local_port, peer_data_seq, client_data_end),
        data_from_peer(local_port, peer_data_seq, client_data_end, PEER_PAYLOAD),
        ack_from_peer(local_port, peer_data_end, client_fin_end),
        fin_ack_from_peer(local_port, peer_data_end, client_fin_end),
    ]);
    let mut flow = client_flow(
        docaddr::CLIENT_IPV4,
        docaddr::SERVER_IPV4,
        REMOTE_PORT,
        Some(CLIENT_PAYLOAD.to_vec()),
    );
    let mut runner = Runner::with_source(RunOptions::default(), source)?;

    println!("{}", flow.show());

    let report = runner.run(&mut flow)?;

    for (index, send_report) in runner.send_reports().iter().enumerate() {
        print_send_plan(index, send_report)?;
    }

    println!("{}", report.show());

    Ok(())
}
