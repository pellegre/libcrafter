//! TLS packet composition coverage.
//!
//! These tests stay offline and use documentation address space while exercising
//! the public packet stack around the TLS module.

use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;
use crafter::protocols::tls::constants::{
    TLS_PORT_EXAMPLE_TESTING, TLS_PORT_HTTPS, TLS_PORT_MQTT_OVER_TLS,
};
use crafter::protocols::tls::{
    Tls, TlsClientHello, TlsContentType, TlsHandshake, TlsRecord, TLS_CLIENT_HELLO_RANDOM_LEN,
    TLS_RECORD_HEADER_LEN,
};

fn client_hello_record() -> crafter::Result<TlsRecord> {
    let client_hello = TlsClientHello::new()
        .with_random([0x22; TLS_CLIENT_HELLO_RANDOM_LEN])
        .with_raw_cipher_suites([0x1301])
        .without_extensions();
    let handshake = TlsHandshake::from_client_hello(client_hello)?;
    TlsRecord::handshake_messages([handshake])
}

fn tls_client_hello_layer() -> crafter::Result<Tls> {
    Ok(Tls::from_record(client_hello_record()?))
}

#[test]
fn ipv4_tcp_tls_client_hello_compiles_and_decodes() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Tcp::new()
            .sport(49_152)
            .dport(TLS_PORT_HTTPS)
            .seq(0x0102_0304)
            .ack(0x0506_0708)
            .ack_segment()
        / tls_client_hello_layer()?;

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let names = decoded.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    let tcp = decoded.layer::<Tcp>().expect("decoded tcp layer");
    let tls = decoded.layer::<Tls>().expect("decoded tls layer");

    assert_eq!(names, ["Ipv4", "Tcp", "TLS"]);
    assert_eq!(tcp.source_port_value(), 49_152);
    assert_eq!(tcp.destination_port_value(), TLS_PORT_HTTPS);
    assert_eq!(tls.record_count(), 1);
    assert_eq!(tls.records()[0].content_type(), TlsContentType::handshake());
    assert!(tls.summary().contains("TLS records=1"));
    assert_eq!(
        u16::from_be_bytes([compiled.as_bytes()[2], compiled.as_bytes()[3]]) as usize,
        compiled.as_bytes().len()
    );
    assert_eq!(
        compiled.as_bytes().len() - 20 - tcp.header_len(),
        tls.encoded_len()
    );
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}

#[test]
fn ipv6_tcp_tls_client_hello_compiles_and_decodes() -> crafter::Result<()> {
    let packet = Ipv6::new()
        .src(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10))
        .dst(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x20))
        / Tcp::new()
            .sport(49_153)
            .dport(TLS_PORT_EXAMPLE_TESTING)
            .seq(0x1112_1314)
            .ack(0x2122_2324)
            .ack_segment()
        / tls_client_hello_layer()?;

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())?;
    let names = decoded.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    let tcp = decoded.layer::<Tcp>().expect("decoded tcp layer");
    let tls = decoded.layer::<Tls>().expect("decoded tls layer");
    let ipv6_payload_len =
        u16::from_be_bytes([compiled.as_bytes()[4], compiled.as_bytes()[5]]) as usize;

    assert_eq!(names, ["Ipv6", "Tcp", "TLS"]);
    assert_eq!(tcp.source_port_value(), 49_153);
    assert_eq!(tcp.destination_port_value(), TLS_PORT_EXAMPLE_TESTING);
    assert_eq!(tls.record_count(), 1);
    assert_eq!(tls.records()[0].content_type(), TlsContentType::handshake());
    assert_eq!(ipv6_payload_len, tcp.header_len() + tls.encoded_len());
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}

#[test]
fn explicit_tcp_source_port_and_tls_length_override_compose() -> crafter::Result<()> {
    let record = TlsRecord::application_data([0xaa]).with_length(1);
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 30))
        .dst(Ipv4Addr::new(198, 51, 100, 40))
        / Tcp::new()
            .sport(TLS_PORT_MQTT_OVER_TLS)
            .dport(49_154)
            .seq(0x3132_3334)
            .ack(0x4142_4344)
            .ack_segment()
        / Tls::from_record(record);

    let compiled = packet.compile()?;
    let tls_start = compiled.as_bytes().len() - (TLS_RECORD_HEADER_LEN + 1);
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let tcp = decoded.layer::<Tcp>().expect("decoded tcp layer");
    let tls = decoded.layer::<Tls>().expect("decoded tls layer");

    assert_eq!(tcp.source_port_value(), TLS_PORT_MQTT_OVER_TLS);
    assert_eq!(tcp.destination_port_value(), 49_154);
    assert_eq!(
        &compiled.as_bytes()[tls_start + 3..tls_start + 5],
        &[0x00, 0x01]
    );
    assert_eq!(tls.records()[0].declared_length(), Some(1));
    assert_eq!(tls.records()[0].fragment_len(), 1);
    assert_eq!(
        tls.records()[0].content_type(),
        TlsContentType::application_data()
    );
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}
