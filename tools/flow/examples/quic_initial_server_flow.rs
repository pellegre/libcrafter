use crafter::{
    derive_quic_initial_secrets, quic_protect_complete_initial_packet, Ipv4, Quic, QuicFrame,
    QuicLongHeaderPacket, QuicPacketNumber, QuicVarInt, Udp, QUIC_VERSION_1,
};
use crafter_flow::flows::quic::{
    quic_initial_server_flow, QuicInitialClientConfig, QuicInitialServerConfig,
};
use crafter_flow::{MemoryCaptureSource, RunOptions, Runner};

fn protected_client_fixture(
    server: &QuicInitialServerConfig,
) -> crafter_flow::Result<crafter::Packet> {
    let client = QuicInitialClientConfig::default();
    let plaintext = QuicLongHeaderPacket::initial_builder()
        .version(QUIC_VERSION_1)
        .destination_connection_id(
            client
                .identifiers
                .original_destination_connection_id()
                .clone(),
        )
        .source_connection_id(client.identifiers.local_source_connection_id().clone())
        .packet_number(QuicPacketNumber::new(0).with_encoded_len(2))
        .protected_payload(QuicFrame::encode_sequence([
            QuicFrame::crypto(QuicVarInt::new(0)?, b"deterministic client Initial")?,
            QuicFrame::padding(1200),
        ]))
        .build()?;
    let keys = derive_quic_initial_secrets(
        QUIC_VERSION_1,
        client
            .identifiers
            .original_destination_connection_id()
            .as_bytes(),
    )?
    .client_packet_keys()?;
    let protected = quic_protect_complete_initial_packet(&plaintext, 0, &keys, 2)?;

    Ok(Ipv4::new().src(*server.peer.ip()).dst(*server.local.ip())
        / Udp::new()
            .source_port(server.peer.port())
            .destination_port(server.local.port())
        / Quic::from_packets([protected]))
}

fn print_send_plans(runner: &Runner) -> crafter_flow::Result<()> {
    for (index, send) in runner.send_reports().iter().enumerate() {
        let plan = send.plan();
        let packet = crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, plan.bytes())?;
        println!(
            "send plan #{index}: dry_run={} interface={} mode={:?} target={:?} bytes={} summary={}",
            send.is_dry_run(),
            plan.interface(),
            plan.requested_mode(),
            plan.target(),
            plan.len(),
            packet.summary()
        );
    }
    Ok(())
}

fn main() -> crafter_flow::Result<()> {
    let config = QuicInitialServerConfig::default();
    let fixture = protected_client_fixture(&config)?;
    let mut flow = quic_initial_server_flow(config)?;
    let mut runner = Runner::with_source(
        RunOptions::default(),
        MemoryCaptureSource::new(vec![fixture]),
    )?;

    println!("Offline QUIC Initial inspection; this does not establish a QUIC connection.");
    println!("{}", flow.show());

    let report = runner.run(&mut flow)?;
    print_send_plans(&runner)?;
    println!("{}", report.show());

    Ok(())
}
