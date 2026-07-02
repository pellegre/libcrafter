use crafter::prelude::*;

#[test]
fn ntp_nts_extensions_opaque_wrappers_roundtrip_preserve_types_and_bodies() -> crafter::Result<()> {
    let unique_body = (0u8..12).map(|offset| 0x10 + offset).collect::<Vec<_>>();
    let cookie_body = (0u8..12).map(|offset| 0x40 + offset).collect::<Vec<_>>();
    let placeholder_body = (0u8..12).map(|offset| 0x80 + offset).collect::<Vec<_>>();
    let malformed_authenticator_body = vec![
        0x00, 0x20, 0x00, 0x10, 0xaa, 0xbb, 0xcc, 0xdd, 0xe0, 0xe1, 0xe2, 0xe3, 0xf0, 0xf1, 0xf2,
        0xf3, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
    ];

    let ntp = Ntp::client()
        .extension_field(NtpExtensionField::from(
            NtpNtsUniqueIdentifierExtension::new(unique_body.clone()),
        ))
        .extension_field(NtpExtensionField::from(NtpNtsCookieExtension::new(
            cookie_body.clone(),
        )))
        .extension_field(NtpExtensionField::from(
            NtpNtsCookiePlaceholderExtension::new(placeholder_body.clone()),
        ))
        .extension_field(NtpExtensionField::from(NtpNtsAuthenticatorExtension::new(
            malformed_authenticator_body.clone(),
        )));

    let compiled = Packet::from_layer(ntp).compile()?;
    let decoded = Ntp::decode(compiled.as_bytes())?;
    let fields = decoded.extension_fields_value();

    assert_eq!(fields.len(), 4);

    assert_eq!(
        fields[0].field_type(),
        NtpNtsUniqueIdentifierExtension::FIELD_TYPE
    );
    assert_eq!(fields[0].declared_length_value(), Some(16));
    assert_eq!(fields[0].value(), unique_body.as_slice());
    assert_eq!(
        fields[0]
            .as_nts_unique_identifier()
            .expect("unique identifier typed wrapper")
            .body(),
        unique_body.as_slice()
    );
    assert_eq!(fields[0].as_nts_cookie(), None);

    assert_eq!(fields[1].field_type(), NtpNtsCookieExtension::FIELD_TYPE);
    assert_eq!(fields[1].declared_length_value(), Some(16));
    assert_eq!(fields[1].value(), cookie_body.as_slice());
    assert_eq!(
        fields[1]
            .as_nts_cookie()
            .expect("cookie typed wrapper")
            .body(),
        cookie_body.as_slice()
    );
    assert_eq!(fields[1].as_nts_cookie_placeholder(), None);

    assert_eq!(
        fields[2].field_type(),
        NtpNtsCookiePlaceholderExtension::FIELD_TYPE
    );
    assert_eq!(fields[2].declared_length_value(), Some(16));
    assert_eq!(fields[2].value(), placeholder_body.as_slice());
    assert_eq!(
        fields[2]
            .as_nts_cookie_placeholder()
            .expect("cookie placeholder typed wrapper")
            .body(),
        placeholder_body.as_slice()
    );
    assert_eq!(fields[2].as_nts_authenticator(), None);

    assert_eq!(
        fields[3].field_type(),
        NtpNtsAuthenticatorExtension::FIELD_TYPE
    );
    assert_eq!(fields[3].declared_length_value(), Some(28));
    assert_eq!(fields[3].value(), malformed_authenticator_body.as_slice());
    let authenticator = fields[3]
        .as_nts_authenticator()
        .expect("authenticator typed wrapper selected by field type");
    assert_eq!(
        authenticator.body(),
        malformed_authenticator_body.as_slice()
    );
    assert_eq!(authenticator.parts(), None);
    assert_eq!(authenticator.nonce(), None);
    assert_eq!(authenticator.ciphertext_without_tag(16), None);
    assert_eq!(authenticator.tag(16), None);
    assert_eq!(authenticator.additional_padding(), None);

    let recompiled = Packet::from_layer(decoded).compile()?;
    assert_eq!(recompiled.as_bytes(), compiled.as_bytes());

    Ok(())
}

#[test]
fn ntp_nts_extensions_authenticator_parts_roundtrip_without_crypto() -> crafter::Result<()> {
    let nonce = [0x10, 0x11, 0x12];
    let ciphertext = [0x20, 0x21, 0x22, 0x23, 0x24];
    let tag = [0x30, 0x31, 0x32];
    let additional_padding = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7];
    let authenticator =
        NtpNtsAuthenticatorExtension::from_parts(nonce, ciphertext, tag, additional_padding)?;
    let expected_body = authenticator.body().to_vec();

    let compiled =
        Packet::from_layer(Ntp::client().extension_field(NtpExtensionField::from(authenticator)))
            .compile()?;
    let decoded = Ntp::decode(compiled.as_bytes())?;
    let fields = decoded.extension_fields_value();

    assert_eq!(fields.len(), 1);
    assert_eq!(
        fields[0].field_type(),
        NtpNtsAuthenticatorExtension::FIELD_TYPE
    );
    assert_eq!(fields[0].declared_length_value(), Some(28));
    assert_eq!(fields[0].value(), expected_body.as_slice());

    let decoded_authenticator = fields[0]
        .as_nts_authenticator()
        .expect("0x0404 decodes as NTS authenticator");
    let parts = decoded_authenticator
        .parts()
        .expect("structured authenticator body splits");

    assert_eq!(decoded_authenticator.body(), expected_body.as_slice());
    assert_eq!(parts.nonce(), nonce.as_slice());
    assert_eq!(
        parts.ciphertext_without_tag(tag.len()),
        Some(ciphertext.as_slice())
    );
    assert_eq!(parts.tag(tag.len()), Some(tag.as_slice()));
    assert_eq!(parts.additional_padding(), additional_padding.as_slice());
    assert_eq!(decoded_authenticator.nonce(), Some(nonce.as_slice()));
    assert_eq!(
        decoded_authenticator.ciphertext_without_tag(tag.len()),
        Some(ciphertext.as_slice())
    );
    assert_eq!(decoded_authenticator.tag(tag.len()), Some(tag.as_slice()));
    assert_eq!(
        decoded_authenticator.additional_padding(),
        Some(additional_padding.as_slice())
    );

    let recompiled = Packet::from_layer(decoded).compile()?;
    assert_eq!(recompiled.as_bytes(), compiled.as_bytes());

    Ok(())
}
