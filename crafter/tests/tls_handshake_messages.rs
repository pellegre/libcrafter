//! TLS certificate and late-handshake message fixture coverage.
//!
//! Certificate bytes in these fixtures are synthetic opaque byte strings; the
//! tests exercise TLS framing only and do not parse or validate X.509 data.

use crafter::prelude::*;

fn handshake_fixture(handshake_type: TlsHandshakeType, body: &[u8]) -> Vec<u8> {
    let body_len = body.len();
    assert!(body_len <= 0x00ff_ffff);

    let mut out = Vec::with_capacity(TLS_HANDSHAKE_HEADER_LEN + body_len);
    out.push(handshake_type.raw());
    out.push(((body_len >> 16) & 0xff) as u8);
    out.push(((body_len >> 8) & 0xff) as u8);
    out.push((body_len & 0xff) as u8);
    out.extend_from_slice(body);
    out
}

fn assert_handshake(
    name: &str,
    handshake: TlsHandshake,
    expected: &[u8],
) -> crafter::Result<TlsHandshake> {
    assert_eq!(handshake.encode_to_vec()?, expected, "{name} encode");

    let decoded = TlsHandshake::decode(expected)?;
    assert_eq!(decoded.encode_to_vec()?, expected, "{name} recompile");
    assert_eq!(
        decoded.handshake_type(),
        handshake.handshake_type(),
        "{name} type"
    );
    assert_eq!(decoded.body_bytes(), handshake.body_bytes(), "{name} body");
    assert!(!decoded.summary().is_empty(), "{name} summary");

    Ok(decoded)
}

#[test]
fn tls_certificate_tls12_and_tls13_fixtures_roundtrip() -> crafter::Result<()> {
    let tls12 = TlsCertificate::tls12(vec![
        TlsCertificateEntry::new([0x30, 0x03, 0x01]),
        TlsCertificateEntry::new([0x30, 0x01]),
    ]);
    let tls12_body = vec![
        0x00, 0x00, 0x0b, // certificate_list length
        0x00, 0x00, 0x03, 0x30, 0x03, 0x01, // first opaque certificate
        0x00, 0x00, 0x02, 0x30, 0x01, // second opaque certificate
    ];
    assert_eq!(tls12.encode_to_vec()?, tls12_body);
    assert_eq!(TlsCertificate::decode_tls12(&tls12_body)?, tls12);

    let decoded = assert_handshake(
        "tls12 certificate",
        TlsHandshake::from_certificate(tls12.clone())?,
        &handshake_fixture(TlsHandshakeType::certificate(), &tls12_body),
    )?;
    assert_eq!(decoded.certificate_body(), Some(&tls12));
    assert!(decoded.body().is_typed_certificate());

    let tls13 = TlsCertificate::tls13(
        [0x01, 0x02],
        vec![
            TlsCertificateEntry::new([0x30, 0x82]).with_raw_extension(0xbeef, [0xaa]),
            TlsCertificateEntry::new([0x04]),
        ],
    );
    let tls13_body = vec![
        0x02, 0x01, 0x02, // certificate_request_context
        0x00, 0x00, 0x12, // certificate_list length
        0x00, 0x00, 0x02, 0x30, 0x82, // first opaque certificate
        0x00, 0x05, 0xbe, 0xef, 0x00, 0x01, 0xaa, // first entry extensions
        0x00, 0x00, 0x01, 0x04, // second opaque certificate
        0x00, 0x00, // second entry extensions
    ];
    assert_eq!(tls13.encode_to_vec()?, tls13_body);
    assert_eq!(TlsCertificate::decode_tls13(&tls13_body)?, tls13);

    let decoded = assert_handshake(
        "tls13 certificate",
        TlsHandshake::from_certificate(tls13.clone())?,
        &handshake_fixture(TlsHandshakeType::certificate(), &tls13_body),
    )?;
    let decoded_certificate = decoded.certificate_body().expect("certificate body");
    assert!(decoded_certificate.is_tls13());
    assert_eq!(decoded_certificate.request_context(), &[0x01, 0x02]);
    assert_eq!(decoded_certificate.entry_extensions_len(), 1);
    assert_eq!(
        decoded_certificate.certificate_list()[0].extensions()[0].body(),
        &[0xaa]
    );

    let record = TlsRecord::handshake_messages([
        TlsHandshake::from_certificate(tls12.clone())?,
        TlsHandshake::from_certificate(tls13.clone())?,
    ])?;
    let decoded_record = TlsRecord::decode(record.encode_to_vec()?)?;
    let TlsRecordBody::Handshake(handshake_body) = decoded_record.body() else {
        panic!("expected handshake record body");
    };
    assert_eq!(handshake_body.messages().len(), 2);
    assert_eq!(
        handshake_body.messages()[0].certificate_body(),
        Some(&tls12)
    );
    assert_eq!(
        handshake_body.messages()[1].certificate_body(),
        Some(&tls13)
    );

    Ok(())
}

#[test]
fn tls_certificate_request_tls12_and_tls13_fixtures_roundtrip() -> crafter::Result<()> {
    let authorities = TlsCertificateAuthorities::from_raws([&[0x30, 0x03, 0x31][..], &[0xaa][..]]);
    let tls12 = TlsCertificateRequest::tls12(
        vec![
            TlsClientCertificateType::rsa_sign(),
            TlsClientCertificateType::ecdsa_sign(),
            TlsClientCertificateType::from_u8(0xfe),
        ],
        TlsSignatureAlgorithms::from_raws([0x0401, 0x0807]),
        authorities.clone(),
    );
    let tls12_body = vec![
        0x03, 0x01, 0x40, 0xfe, // certificate_types
        0x00, 0x04, 0x04, 0x01, 0x08, 0x07, // signature_algorithms
        0x00, 0x08, 0x00, 0x03, 0x30, 0x03, 0x31, 0x00, 0x01, 0xaa, // certificate_authorities
    ];
    assert_eq!(tls12.encode_to_vec()?, tls12_body);
    assert_eq!(TlsCertificateRequest::decode_tls12(&tls12_body)?, tls12);

    let decoded = assert_handshake(
        "tls12 certificate_request",
        TlsHandshake::from_certificate_request(tls12.clone())?,
        &handshake_fixture(TlsHandshakeType::certificate_request(), &tls12_body),
    )?;
    assert_eq!(decoded.certificate_request_body(), Some(&tls12));
    assert_eq!(tls12.certificate_authorities(), &authorities);

    let authorities = TlsCertificateAuthorities::from_raws([&[0xde, 0xad][..]]);
    let tls13 = TlsCertificateRequest::new()
        .with_request_context([0x10])
        .with_tls13_signature_algorithms(TlsSignatureAlgorithms::from_raws([0x0807]))?
        .with_tls13_certificate_authorities(authorities.clone())?
        .with_raw_extension(0xbeef, [0xca, 0xfe]);
    let tls13_body = vec![
        0x01, 0x10, // certificate_request_context
        0x00, 0x18, // extensions length
        0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07, // signature_algorithms
        0x00, 0x2f, 0x00, 0x06, 0x00, 0x04, 0x00, 0x02, 0xde, 0xad, // certificate_authorities
        0xbe, 0xef, 0x00, 0x02, 0xca, 0xfe, // unknown extension
    ];
    assert_eq!(tls13.encode_to_vec()?, tls13_body);
    assert_eq!(TlsCertificateRequest::decode_tls13(&tls13_body)?, tls13);

    let decoded = assert_handshake(
        "tls13 certificate_request",
        TlsHandshake::from_certificate_request(tls13.clone())?,
        &handshake_fixture(TlsHandshakeType::certificate_request(), &tls13_body),
    )?;
    let decoded_request = decoded
        .certificate_request_body()
        .expect("certificate request body");
    assert!(decoded_request.is_tls13());
    assert_eq!(decoded_request.request_context(), &[0x10]);
    assert_eq!(decoded_request.extensions().len(), 3);
    assert_eq!(
        decoded_request.extensions()[1].as_certificate_authorities()?,
        authorities
    );

    Ok(())
}

#[test]
fn tls_certificate_verify_and_finished_fixtures_roundtrip() -> crafter::Result<()> {
    let certificate_verify =
        TlsCertificateVerify::from_raw_signature_scheme(0xbeef, [0xde, 0xad, 0xfa]);
    let certificate_verify_body = vec![0xbe, 0xef, 0x00, 0x03, 0xde, 0xad, 0xfa];
    assert_eq!(certificate_verify.encode_to_vec()?, certificate_verify_body);

    let decoded = assert_handshake(
        "certificate_verify",
        TlsHandshake::from_certificate_verify(certificate_verify.clone())?,
        &handshake_fixture(
            TlsHandshakeType::certificate_verify(),
            &certificate_verify_body,
        ),
    )?;
    assert_eq!(decoded.certificate_verify_body(), Some(&certificate_verify));

    let finished = TlsFinished::new([0xde, 0xad, 0xbe, 0xef]);
    let finished_body = vec![0xde, 0xad, 0xbe, 0xef];
    assert_eq!(finished.encode_to_vec()?, finished_body);

    let decoded = assert_handshake(
        "finished",
        TlsHandshake::from_finished(finished.clone())?,
        &handshake_fixture(TlsHandshakeType::finished(), &finished_body),
    )?;
    assert_eq!(decoded.finished_body(), Some(&finished));

    let record = TlsRecord::handshake_messages([
        TlsHandshake::from_certificate_verify(certificate_verify.clone())?,
        TlsHandshake::from_finished(finished.clone())?,
    ])?;
    let decoded_record = TlsRecord::decode(record.encode_to_vec()?)?;
    let TlsRecordBody::Handshake(handshake_body) = decoded_record.body() else {
        panic!("expected handshake record body");
    };
    assert_eq!(
        handshake_body.messages()[0].certificate_verify_body(),
        Some(&certificate_verify)
    );
    assert_eq!(
        handshake_body.messages()[1].finished_body(),
        Some(&finished)
    );

    Ok(())
}

#[test]
fn tls_ticket_key_update_and_end_of_early_data_fixtures_roundtrip() -> crafter::Result<()> {
    let tls12_ticket = TlsNewSessionTicket::tls12(0x0102_0304, [0xaa, 0xbb]);
    let tls12_ticket_body = vec![
        0x01, 0x02, 0x03, 0x04, // ticket_lifetime_hint
        0x00, 0x02, 0xaa, 0xbb, // ticket
    ];
    assert_eq!(tls12_ticket.encode_to_vec()?, tls12_ticket_body);

    let decoded = assert_handshake(
        "tls12 new_session_ticket",
        TlsHandshake::from_new_session_ticket(tls12_ticket.clone())?,
        &handshake_fixture(TlsHandshakeType::new_session_ticket(), &tls12_ticket_body),
    )?;
    assert_eq!(decoded.new_session_ticket_body(), Some(&tls12_ticket));

    let tls13_ticket = TlsNewSessionTicket::tls13(
        7,
        0x0102_0304,
        [0x09],
        [0xaa, 0xbb, 0xcc],
        vec![TlsRawExtension::from_raw(0xbeef, [0xde])],
    );
    let tls13_ticket_body = vec![
        0x00, 0x00, 0x00, 0x07, // ticket_lifetime
        0x01, 0x02, 0x03, 0x04, // ticket_age_add
        0x01, 0x09, // ticket_nonce
        0x00, 0x03, 0xaa, 0xbb, 0xcc, // ticket
        0x00, 0x05, 0xbe, 0xef, 0x00, 0x01, 0xde, // extensions
    ];
    assert_eq!(tls13_ticket.encode_to_vec()?, tls13_ticket_body);

    let decoded = assert_handshake(
        "tls13 new_session_ticket",
        TlsHandshake::from_new_session_ticket(tls13_ticket.clone())?,
        &handshake_fixture(TlsHandshakeType::new_session_ticket(), &tls13_ticket_body),
    )?;
    let decoded_ticket = decoded
        .new_session_ticket_body()
        .expect("new session ticket body");
    assert!(decoded_ticket.is_tls13());
    assert_eq!(decoded_ticket.extensions()[0].raw_type(), 0xbeef);

    let key_update = TlsKeyUpdate::new(TlsKeyUpdateRequest::update_requested());
    let key_update_body = vec![0x01];
    assert_eq!(key_update.encode_to_vec(), key_update_body);
    let decoded = assert_handshake(
        "key_update",
        TlsHandshake::from_key_update(key_update)?,
        &handshake_fixture(TlsHandshakeType::key_update(), &key_update_body),
    )?;
    assert_eq!(decoded.key_update_body(), Some(&key_update));

    let end_of_early_data = TlsEndOfEarlyData::new();
    let end_of_early_data_body = Vec::<u8>::new();
    assert_eq!(end_of_early_data.encode_to_vec(), end_of_early_data_body);
    let decoded = assert_handshake(
        "end_of_early_data",
        TlsHandshake::from_end_of_early_data(end_of_early_data)?,
        &handshake_fixture(
            TlsHandshakeType::end_of_early_data(),
            &end_of_early_data_body,
        ),
    )?;
    assert_eq!(decoded.end_of_early_data_body(), Some(&end_of_early_data));

    Ok(())
}
