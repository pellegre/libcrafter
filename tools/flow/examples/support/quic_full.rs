use std::{net::SocketAddr, time::Duration};

use crafter::net::{SendOptions, SendPlan};
use crafter::{Ipv4, Quic, Udp};
use crafter_flow::prelude::*;
use crafter_flow::{docaddr, QuicEndpointAddresses, QuicPeerConfig, QuicSyntheticIdentity};

#[path = "../../tests/support/duplex.rs"]
mod duplex;

use duplex::{DuplexConfig, DuplexHarness, DuplexReport, TraceEventKind};
pub use duplex::{Side, StopReason};

const PRIVATE_KEY_HEX: &str = concat!(
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420",
    "faf4403a722d1287f76bda510073cf01bbd0a7f8f56497fc6173be9652ed51fda144",
    "0342000497f07570c53ac9740ca949533c9816ea6ed80ef368b4ff24250336c89fe4634e",
    "f2b64ecea26dea2f1f64bacb1126151ad209fc82e6c41617b40c77d5ac382d35",
);

const CERTIFICATE_HEX: &str = concat!(
    "308201c030820166a00302010202141a41e48f1d1641a1f9d33e76d142cb0728eb2d31",
    "300a06082a8648ce3d04030230173115301306035504030c0c717569632e6578616d706c",
    "65301e170d3236303731313133323132355a170d3336303730383133323132355a301731",
    "15301306035504030c0c717569632e6578616d706c653059301306072a8648ce3d020106",
    "082a8648ce3d0301070342000497f07570c53ac9740ca949533c9816ea6ed80ef368b4ff",
    "24250336c89fe4634ef2b64ecea26dea2f1f64bacb1126151ad209fc82e6c41617b40c7",
    "7d5ac382d35a3818f30818c301d0603551d0e04160414b07bf9242538693a5e4513b33f",
    "08e9144cb41b4a301f0603551d23041830168014b07bf9242538693a5e4513b33f08e914",
    "4cb41b4a30170603551d110410300e820c717569632e6578616d706c65300c0603551d13",
    "0101ff04023000300e0603551d0f0101ff04040302078030130603551d25040c300a0608",
    "2b06010505070301300a06082a8648ce3d0403020348003045022100eeaf706d28853535",
    "16566947544204ba8818cf87e4104c15c950bfcff956255c02200cd6a1e8d4cb0ea465",
    "1c9abd23b605557607a54a21a535febcd2b96d4bb95fea",
);

pub const REQUEST: &[u8] = b"bounded opaque example request";
pub const RESPONSE: &[u8] = b"bounded opaque example response";

fn decode_hex(input: &str) -> Vec<u8> {
    input
        .split_ascii_whitespace()
        .collect::<String>()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex fixture"), 16)
                .expect("valid synthetic identity fixture")
        })
        .collect()
}

pub fn addresses() -> (QuicEndpointAddresses, QuicEndpointAddresses) {
    let client = QuicEndpointAddresses::new(
        SocketAddr::from((docaddr::CLIENT_IPV4, 44_300)),
        SocketAddr::from((docaddr::SERVER_IPV4, 443)),
    );
    let server = QuicEndpointAddresses::new(client.peer, client.local);
    (client, server)
}

pub fn flow_pair() -> crafter_flow::Result<(Flow, Flow)> {
    let (client_addresses, server_addresses) = addresses();
    let certificate = decode_hex(CERTIFICATE_HEX);
    let client = quic_client_flow(QuicClientFlowConfig::new(
        client_addresses,
        QuicPeerConfig::new("quic.example", [b"crafter-flow".to_vec()]),
        QuicSyntheticIdentity::new(Vec::new(), Vec::new(), vec![certificate.clone()]),
        REQUEST.to_vec(),
    ))?;
    let server = quic_server_flow(QuicServerFlowConfig::new(
        server_addresses,
        QuicSyntheticIdentity::new(vec![certificate], decode_hex(PRIVATE_KEY_HEX), Vec::new()),
        RESPONSE.to_vec(),
    ))?;
    Ok((client, server))
}

pub fn run_exchange() -> crafter_flow::Result<DuplexReport> {
    let (client, server) = flow_pair()?;
    DuplexHarness::new(
        client,
        server,
        DuplexConfig {
            step_limit: 2_048,
            time_limit: Duration::from_secs(60),
            ..DuplexConfig::default()
        },
    )?
    .run()
}

pub fn print_safe_configuration(side: Side) {
    let (client, server) = addresses();
    let (role, addresses, payload_len) = match side {
        Side::Left => ("client", client, REQUEST.len()),
        Side::Right => ("server", server, RESPONSE.len()),
    };
    println!(
        "safe configuration: role={role} local={} peer={} peer_name=quic.example alpn=crafter-flow payload_bytes={} identity=synthetic-test-only clock=manual max_time=60s max_steps=2048",
        addresses.local, addresses.peer, payload_len
    );
}

pub fn print_send_plans(report: &DuplexReport, side: Side) -> crafter_flow::Result<()> {
    for event in &report.trace {
        let TraceEventKind::Emitted {
            datagram,
            batch_index,
        } = event.kind
        else {
            continue;
        };
        if event.side != side {
            continue;
        }
        let payload = report
            .protected_payloads
            .get(&datagram)
            .expect("protected payload retained by offline harness");
        let (client, server) = addresses();
        let addresses = match side {
            Side::Left => client,
            Side::Right => server,
        };
        let (SocketAddr::V4(local), SocketAddr::V4(peer)) = (addresses.local, addresses.peer)
        else {
            unreachable!("example configurations are IPv4-only")
        };
        let packet = Ipv4::new().src(*local.ip()).dst(*peer.ip())
            / Udp::new()
                .source_port(local.port())
                .destination_port(peer.port())
            / Quic::raw(payload);
        let plan = SendPlan::from_packet(
            &packet,
            SendOptions::new().iface("flow0").network_layer().dry_run(),
        )
        .map_err(|error| crafter_flow::FlowError::Send(error.to_string()))?;
        println!(
            "send plan #{datagram}.{batch_index}: dry_run=true interface={} mode={:?} target={:?} bytes={} summary={}",
            plan.interface(),
            plan.requested_mode(),
            plan.target(),
            plan.len(),
            packet.summary()
        );
    }
    Ok(())
}

pub fn print_state_trace(report: &DuplexReport, side: Side) {
    println!("state trace:");
    for event in &report.trace {
        if event.side != side {
            continue;
        }
        match &event.kind {
            TraceEventKind::Entry { state } => println!("  t={:?} enter {state}", event.at),
            TraceEventKind::Transition { from, to } => {
                println!("  t={:?} {from} -> {to}", event.at)
            }
            TraceEventKind::Completed { outcome } => {
                println!("  t={:?} completed outcome={outcome:?}", event.at)
            }
            _ => {}
        }
    }
}

pub fn print_counts(report: &DuplexReport, side: Side) -> crafter_flow::Result<()> {
    let context = match side {
        Side::Left => &report.left_context,
        Side::Right => &report.right_context,
    };
    let sent = context
        .get_namespaced_u64("quic", "application.bytes_sent")?
        .or(context.get_namespaced_u64("quic", "application.response_bytes_sent")?)
        .unwrap_or(0);
    let received = context
        .get_namespaced_u64("quic", "application.bytes_received")?
        .or(context.get_namespaced_u64("quic", "application.request_bytes_received")?)
        .unwrap_or(0);
    println!("payload counts: sent={sent} received={received}");
    let recovery = context.recovery_metrics();
    println!(
        "recovery counts: timeouts={} acknowledgements={} pto={} lost={} regenerated={} exact_replay={}",
        recovery.timeout_events(),
        recovery.acknowledgements_processed(),
        recovery.pto_firings(),
        recovery.packets_declared_lost(),
        recovery.regenerated_transmits(),
        recovery.exact_replay_transmits()
    );
    Ok(())
}
