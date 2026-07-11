use crafter::{
    derive_quic_initial_secrets, quic_protect_complete_initial_packet, Ipv4, Quic, QuicFrame,
    QuicLongHeaderPacket, QuicPacketNumber, QuicVarInt, Udp, QUIC_VERSION_1,
};
use crafter_flow::flows::quic::{quic_initial_client_flow, QuicInitialClientConfig};
use crafter_flow::{MemoryCaptureSource, RunOptions, Runner};

fn protected_server_fixture(
    config: &QuicInitialClientConfig,
) -> crafter_flow::Result<crafter::Packet> {
    let plaintext = QuicLongHeaderPacket::initial_builder()
        .version(QUIC_VERSION_1)
        .destination_connection_id(config.identifiers.local_source_connection_id().clone())
        .source_connection_id(config.identifiers.peer_source_connection_id().clone())
        .packet_number(QuicPacketNumber::new(0).with_encoded_len(2))
        .protected_payload(QuicFrame::encode_sequence([
            QuicFrame::ack(
                QuicVarInt::new(0)?,
                QuicVarInt::new(0)?,
                QuicVarInt::new(0)?,
                [],
            )?,
            QuicFrame::crypto(QuicVarInt::new(0)?, b"deterministic server Initial")?,
        ]))
        .build()?;
    let keys = derive_quic_initial_secrets(
        QUIC_VERSION_1,
        config
            .identifiers
            .original_destination_connection_id()
            .as_bytes(),
    )?
    .server_packet_keys()?;
    let protected = quic_protect_complete_initial_packet(&plaintext, 0, &keys, 2)?;

    Ok(Ipv4::new().src(*config.peer.ip()).dst(*config.local.ip())
        / Udp::new()
            .source_port(config.peer.port())
            .destination_port(config.local.port())
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
    let config = QuicInitialClientConfig::default();
    let fixture = protected_server_fixture(&config)?;
    let mut flow = quic_initial_client_flow(config)?;
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
