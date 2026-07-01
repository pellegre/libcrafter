mod common;

use common::{local_ipv4, print_help_if_requested, remote_ipv4, ExampleResult, EXAMPLE_IFACE};
use crafter::prelude::*;

const CLIENT_PORT: u16 = 49_171;
const CLIENT_RANDOM: [u8; TLS_CLIENT_HELLO_RANDOM_LEN] = [0x71; TLS_CLIENT_HELLO_RANDOM_LEN];

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example tls_client_hello --\n\nBuild, decode, and inspect a documentation-safe IPv4/TCP/TLS ClientHello offline.",
    ) {
        return Ok(());
    }

    let packet = client_hello_packet(local_ipv4(), remote_ipv4())?;
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    println!("example: tls_client_hello");
    println!("mode: offline");
    println!("summary: {}", packet.summary());
    println!("decoded summary: {}", decoded.summary());
    println!("show:\n{}", decoded.show());
    println!("hexdump:\n{}", compiled.hexdump());

    let tls = decoded
        .layer::<Tls>()
        .expect("decoded ClientHello packet should contain TLS");
    println!("tls records: {}", tls.record_count());
    println!("tls first record: {}", tls.records()[0].summary());

    dry_run_plan(&packet)?;

    Ok(())
}

fn client_hello_packet(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr) -> ExampleResult<Packet> {
    Ok(Ipv4::new()
        .src(src)
        .dst(dst)
        .id(0x7101)
        .ttl(64)
        .ipv4_protocol(Ipv4Protocol::Tcp)
        / Tcp::new()
            .sport(CLIENT_PORT)
            .dport(TLS_PORT_HTTPS)
            .seq(0x7101_0001)
            .ack(0)
            .syn()
        / Tls::from_record(client_hello_record()?))
}

fn client_hello_record() -> ExampleResult<TlsRecord> {
    let hello = TlsClientHello::new()
        .with_random(CLIENT_RANDOM)
        .with_session_id([0x71, 0x72, 0x73, 0x74])
        .with_raw_cipher_suites([
            TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
            TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
        ])
        .with_extensions(vec![
            TlsRawExtension::server_name(TlsServerNameList::from_host_name("tls.example.test"))?,
            TlsRawExtension::alpn(TlsAlpnProtocols::h2_then_http_1_1())?,
            TlsRawExtension::supported_versions_client(vec![
                TlsVersion::tls_1_3(),
                TlsVersion::tls_1_2(),
            ])?,
            TlsRawExtension::supported_groups(TlsSupportedGroups::from_raws([
                TLS_NAMED_GROUP_X25519,
                TLS_NAMED_GROUP_SECP256R1,
            ]))?,
            TlsRawExtension::signature_algorithms(TlsSignatureAlgorithms::from_raws([
                TLS_SIGNATURE_SCHEME_ED25519,
                TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256,
            ]))?,
            TlsRawExtension::key_share_client(vec![TlsKeyShareEntry::x25519([0x71; 32])])?,
        ]);

    Ok(TlsRecord::handshake_messages([
        TlsHandshake::from_client_hello(hello)?,
    ])?)
}

fn dry_run_plan(packet: &Packet) -> ExampleResult<()> {
    let plan = packet.send_dry_run(SendOptions::new().iface(EXAMPLE_IFACE).network_layer())?;

    println!("dry-run plan");
    println!("interface: {}", plan.interface());
    println!("target: {:?}", plan.target());
    println!("compiled bytes: {}", plan.len());

    Ok(())
}
