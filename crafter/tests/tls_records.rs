//! TLS non-handshake record fixture coverage.
//!
//! These tests stay offline, use documentation address space for packet stacks,
//! and exercise exact record bytes for content types outside handshake records.

use std::net::Ipv4Addr;

use crafter::prelude::*;

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected to find {needle:?} in:\n{haystack}"
    );
}

fn assert_record(name: &str, record: TlsRecord, expected: &[u8]) -> crafter::Result<TlsRecord> {
    assert_eq!(record.encode_to_vec()?, expected, "{name} encode");

    let decoded = TlsRecord::decode(expected)?;
    assert_eq!(decoded.encode_to_vec()?, expected, "{name} recompile");
    assert_eq!(
        decoded.content_type(),
        record.content_type(),
        "{name} content type"
    );
    assert_eq!(decoded.fragment(), record.fragment(), "{name} fragment");
    assert!(!decoded.summary().is_empty(), "{name} summary");

    Ok(decoded)
}

#[test]
fn tls_alert_records_preserve_typed_alert_bytes_as_opaque_fragments() -> crafter::Result<()> {
    let close_notify = TlsAlert::close_notify();
    assert_eq!(
        close_notify.summary(),
        "alert level=warning description=close_notify"
    );

    let decoded = assert_record(
        "warning close_notify",
        TlsRecord::alert(close_notify.encode_to_vec()),
        &[0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00],
    )?;
    assert_eq!(decoded.content_type(), TlsContentType::alert());
    assert_eq!(TlsAlert::decode(decoded.fragment())?, close_notify);
    assert_contains(&decoded.summary(), "opaque bytes=2");

    let fatal = TlsAlert::decode_error();
    let decoded = assert_record(
        "fatal decode_error",
        TlsRecord::alert(fatal.encode_to_vec()),
        &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32],
    )?;
    assert_eq!(TlsAlert::decode(decoded.fragment())?, fatal);
    assert_eq!(
        fatal.summary(),
        "alert level=fatal description=decode_error"
    );

    Ok(())
}

#[test]
fn tls_change_cipher_spec_application_data_and_heartbeat_records_roundtrip() -> crafter::Result<()>
{
    let ccs = assert_record(
        "standard change_cipher_spec",
        TlsRecord::standard_change_cipher_spec(),
        &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01],
    )?;
    assert_eq!(
        ccs.change_cipher_spec_body(),
        Some(&TlsChangeCipherSpec::standard())
    );
    assert_contains(
        &ccs.summary(),
        "change_cipher_spec value=change_cipher_spec",
    );

    let application_data = assert_record(
        "opaque application_data",
        TlsRecord::application_data([0xde, 0xad, 0xbe, 0xef]),
        &[0x17, 0x03, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef],
    )?;
    assert_eq!(
        application_data
            .application_data_body()
            .expect("application data")
            .bytes(),
        &[0xde, 0xad, 0xbe, 0xef]
    );
    assert_contains(&application_data.summary(), "application_data bytes=4");

    let heartbeat = TlsHeartbeat::request([0xaa], [0x55; TLS_HEARTBEAT_MIN_PADDING_LEN]);
    let decoded = assert_record(
        "heartbeat request",
        TlsRecord::from_heartbeat(heartbeat)?,
        &[
            0x18, 0x03, 0x03, 0x00, 0x14, 0x01, 0x00, 0x01, 0xaa, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        ],
    )?;
    let heartbeat = decoded.heartbeat_body().expect("decoded heartbeat");
    assert_eq!(heartbeat.message_type(), TlsHeartbeatMessageType::request());
    assert_eq!(heartbeat.payload(), &[0xaa]);
    assert_eq!(heartbeat.padding(), &[0x55; TLS_HEARTBEAT_MIN_PADDING_LEN]);
    assert_contains(&decoded.summary(), "heartbeat type=heartbeat_request");

    Ok(())
}

#[test]
fn tls_unknown_content_type_and_length_override_preserve_wire_intent() -> crafter::Result<()> {
    let decoded = assert_record(
        "unknown content type",
        TlsRecord::from_fragment(0xfe, [0xde, 0xad]).with_raw_legacy_record_version(0x4242),
        &[0xfe, 0x42, 0x42, 0x00, 0x02, 0xde, 0xad],
    )?;
    assert_eq!(decoded.raw_content_type(), 0xfe);
    assert_eq!(decoded.raw_legacy_record_version(), 0x4242);
    assert_contains(&decoded.summary(), "unassigned content type 0xfe");
    assert_contains(&decoded.summary(), "unknown protocol version 0x4242");
    assert_contains(&decoded.summary(), "opaque bytes=2");

    let override_record = TlsRecord::application_data([0xaa]).with_length(0);
    let override_bytes = override_record.encode_to_vec()?;
    assert_eq!(override_bytes, [0x17, 0x03, 0x03, 0x00, 0x00, 0xaa]);
    assert_contains(&override_record.summary(), "declared_length=0");
    assert_contains(&override_record.summary(), "fragment_bytes=1");

    let (decoded, tail) = TlsRecord::decode_prefix(&override_bytes)?;
    assert_eq!(decoded.declared_length(), Some(0));
    assert_eq!(decoded.fragment(), &[]);
    assert_eq!(tail, &[0xaa]);
    assert_eq!(decoded.encode_to_vec()?, [0x17, 0x03, 0x03, 0x00, 0x00]);

    Ok(())
}

#[test]
fn tls_stacked_non_handshake_records_decode_from_one_tcp_payload() -> crafter::Result<()> {
    let tls = Tls::from_records([
        TlsRecord::standard_change_cipher_spec(),
        TlsRecord::alert(TlsAlert::close_notify().encode_to_vec()),
        TlsRecord::application_data([0xde, 0xad]),
    ]);
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 88))
        .dst(Ipv4Addr::new(198, 51, 100, 88))
        / Tcp::new()
            .sport(49_152)
            .dport(TLS_PORT_HTTPS)
            .seq(0x8889_8a8b)
            .ack(0x9899_9a9b)
            .ack_segment()
        / tls;

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let tls = decoded.layer::<Tls>().expect("decoded TLS layer");

    assert_eq!(tls.record_count(), 3);
    assert_eq!(
        tls.records()[0].content_type(),
        TlsContentType::change_cipher_spec()
    );
    assert_eq!(
        tls.records()[0].change_cipher_spec_body(),
        Some(&TlsChangeCipherSpec::standard())
    );
    assert_eq!(tls.records()[1].content_type(), TlsContentType::alert());
    assert_eq!(
        TlsAlert::decode(tls.records()[1].fragment())?,
        TlsAlert::close_notify()
    );
    assert_eq!(
        tls.records()[2].content_type(),
        TlsContentType::application_data()
    );
    assert_eq!(tls.records()[2].fragment(), &[0xde, 0xad]);
    assert_contains(
        &tls.summary(),
        "types=[change_cipher_spec, alert, application_data]",
    );
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());

    Ok(())
}
