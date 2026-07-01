//! TLS malformed input coverage.
//!
//! These tests stay offline and exercise the public TLS packet-layer primitives.

use crafter::protocols::tls::{
    TlsAlert, TlsAlpnProtocols, TlsCertificate, TlsKeyShare, TlsRawExtension, TlsRecord,
    TlsRecordHeader, TlsServerNameList, TlsSignatureAlgorithms, TLS_ALERT_LEN,
    TLS_CERTIFICATE_LIST_LENGTH_LEN, TLS_EXTENSION_HEADER_LEN, TLS_HANDSHAKE_HEADER_LEN,
    TLS_RECORD_HEADER_LEN,
};
use crafter::{CrafterError, Result};

fn assert_buffer_too_short(
    err: CrafterError,
    context: &'static str,
    required: usize,
    available: usize,
) {
    assert_eq!(
        err,
        CrafterError::buffer_too_short(context, required, available)
    );
}

#[test]
fn tls_malformed_structured_truncation_contexts_are_public() {
    assert_buffer_too_short(
        TlsRecordHeader::decode([0x16, 0x03, 0x03, 0x00]).unwrap_err(),
        "tls.record.header",
        TLS_RECORD_HEADER_LEN,
        4,
    );
    assert_buffer_too_short(
        TlsRecord::decode([0x16, 0x03, 0x03, 0x00, 0x04, 0xaa]).unwrap_err(),
        "tls.record.fragment",
        TLS_RECORD_HEADER_LEN + 4,
        6,
    );
    assert_buffer_too_short(
        crafter::protocols::tls::TlsHandshakeHeader::decode([0x01, 0x00, 0x00]).unwrap_err(),
        "tls.handshake.header",
        TLS_HANDSHAKE_HEADER_LEN,
        3,
    );
    assert_buffer_too_short(
        TlsRawExtension::decode([0x00, 0x00, 0x00]).unwrap_err(),
        "tls.extension",
        TLS_EXTENSION_HEADER_LEN,
        3,
    );
    assert_buffer_too_short(
        TlsSignatureAlgorithms::decode([0x00, 0x04, 0x04, 0x01]).unwrap_err(),
        "tls.signature_algorithms",
        6,
        4,
    );
    assert_buffer_too_short(
        TlsCertificate::decode_tls12([0x00, 0x00]).unwrap_err(),
        "tls.certificate.certificate_list.length",
        TLS_CERTIFICATE_LIST_LENGTH_LEN,
        2,
    );
    assert_buffer_too_short(
        TlsKeyShare::decode_client([0x00, 0x04, 0x00, 0x1d]).unwrap_err(),
        "tls.key_share.client",
        6,
        4,
    );
    assert_buffer_too_short(
        TlsServerNameList::decode([0x00, 0x04, 0x00, 0x00]).unwrap_err(),
        "tls.server_name_list",
        6,
        4,
    );
    assert_buffer_too_short(
        TlsAlpnProtocols::decode([0x00, 0x03, 0x02, b'h']).unwrap_err(),
        "tls.alpn.protocol_name_list",
        5,
        4,
    );
    assert_buffer_too_short(
        TlsAlert::decode([0x01]).unwrap_err(),
        "tls.alert",
        TLS_ALERT_LEN,
        1,
    );
}

#[test]
fn tls_malformed_record_sequence_preserves_partial_tail_only_after_valid_anchor() -> Result<()> {
    let first_partial = [0x16, 0x03, 0x03, 0x00, 0x04, 0xaa];
    assert_buffer_too_short(
        TlsRecord::decode(first_partial).unwrap_err(),
        "tls.record.fragment",
        TLS_RECORD_HEADER_LEN + 4,
        first_partial.len(),
    );

    let payload = [
        0x17, 0x03, 0x03, 0x00, 0x03, b'a', b'b', b'c', 0x16, 0x03, 0x03, 0x00, 0x04, 0xde,
    ];
    let (record, tail) = TlsRecord::decode_prefix(&payload)?;

    assert_eq!(record.fragment(), b"abc");
    assert_eq!(tail, &[0x16, 0x03, 0x03, 0x00, 0x04, 0xde]);
    assert_buffer_too_short(
        TlsRecord::decode(tail).unwrap_err(),
        "tls.record.fragment",
        TLS_RECORD_HEADER_LEN + 4,
        tail.len(),
    );

    Ok(())
}
