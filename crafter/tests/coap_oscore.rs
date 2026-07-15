//! RFC 8613 OSCORE vectors and failure-safety coverage through public APIs.
//!
//! Vector bytes are from RFC 8613 Appendix C.  The small independent HKDF
//! oracle follows RFC 5869 Sections 2.2 and 2.3 and verifies the Appendix C.1
//! client/server keys without requiring `OscoreContext` to expose secrets.

use crafter::prelude::*;
use hmac::{Hmac, Mac};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const MASTER_SECRET: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];
const MASTER_SALT: [u8; 8] = [0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40];
const CLIENT_KEY: [u8; 16] = [
    0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4, 0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff,
];
const SERVER_KEY: [u8; 16] = [
    0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca, 0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10,
];
const COMMON_IV: [u8; 13] = [
    0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68, 0xee, 0xfb, 0x54, 0x98, 0x7c,
];

fn client_context() -> OscoreContext {
    OscoreContext::with_default_algorithms(MASTER_SECRET, MASTER_SALT, [], [0x01], None).unwrap()
}

fn server_context() -> OscoreContext {
    OscoreContext::with_default_algorithms(MASTER_SECRET, MASTER_SALT, [0x01], [], None).unwrap()
}

fn compile(message: Coap) -> crafter::Result<Vec<u8>> {
    Ok(Packet::from_layer(message).compile()?.into_bytes())
}

fn hkdf_sha256(info: &[u8], length: usize) -> Vec<u8> {
    let mut extract = <HmacSha256 as Mac>::new_from_slice(&MASTER_SALT).unwrap();
    extract.update(&MASTER_SECRET);
    let prk = extract.finalize().into_bytes();
    let mut output = Vec::with_capacity(length);
    let mut previous = Vec::new();
    for counter in 1u8.. {
        let mut expand = <HmacSha256 as Mac>::new_from_slice(&prk).unwrap();
        expand.update(&previous);
        expand.update(info);
        expand.update(&[counter]);
        previous = expand.finalize().into_bytes().to_vec();
        output.extend_from_slice(&previous);
        if output.len() >= length {
            output.truncate(length);
            return output;
        }
    }
    unreachable!("bounded RFC vector output always terminates")
}

fn partial_iv(sequence: u32) -> Vec<u8> {
    let bytes = sequence.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[first..].to_vec()
}

fn prop_oscore<T>(
    result: std::result::Result<T, OscoreError>,
) -> std::result::Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn prop_crafter<T>(result: crafter::Result<T>) -> std::result::Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

#[test]
fn appendix_c_keys_iv_nonce_aad_request_response_and_tags_are_exact() -> crafter::Result<()> {
    // RFC 8613 Appendix C.1 key/IV derivation metadata and outputs.
    let client = client_context();
    assert_eq!(
        hkdf_sha256(client.sender_key_derivation_info(), 16),
        CLIENT_KEY
    );
    assert_eq!(
        hkdf_sha256(client.recipient_key_derivation_info(), 16),
        SERVER_KEY
    );
    assert_eq!(
        hkdf_sha256(client.common_iv_derivation_info(), 13),
        COMMON_IV
    );
    assert_eq!(client.sender_key_len(), CLIENT_KEY.len());
    assert_eq!(client.recipient_key_len(), SERVER_KEY.len());
    assert_eq!(client.common_iv_len(), COMMON_IV.len());

    // RFC 8613 Appendices C.4 and C.7 nonce and External AAD inputs.
    assert_eq!(
        client.sender_nonce([0x14]).unwrap(),
        [0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68, 0xee, 0xfb, 0x54, 0x98, 0x68]
    );
    assert_eq!(
        server_context().sender_nonce([0x14]).unwrap(),
        [0x47, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x69, 0xee, 0xfb, 0x54, 0x98, 0x68]
    );
    assert_eq!(
        client.external_aad([], [0x14], []).unwrap(),
        [0x48, 0x85, 0x01, 0x81, 0x0a, 0x40, 0x41, 0x14, 0x40]
    );

    // RFC 8613 Appendix C.4 request, including ciphertext and eight-byte tag.
    let request = Coap::get()
        .message_id(0x5d1f)
        .token(CoapToken::from_bytes([0x00, 0x00, 0x39, 0x74]))
        .option(CoapOption::new(COAP_OPTION_URI_HOST, b"localhost"))
        .option(CoapOption::new(COAP_OPTION_URI_PATH, b"tv1"));
    let protected_request = client
        .protect(&request, OscoreProtectParams::request([0x14]))
        .unwrap();
    assert_eq!(
        protected_request.payload_value(),
        [0x61, 0x2f, 0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c, 0x16, 0x68, 0xb3, 0x82, 0x5e]
    );
    let request_wire = [
        0x44, 0x02, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68,
        0x6f, 0x73, 0x74, 0x62, 0x09, 0x14, 0xff, 0x61, 0x2f, 0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c,
        0x16, 0x68, 0xb3, 0x82, 0x5e,
    ];
    assert_eq!(compile(protected_request.clone())?, request_wire);
    let recovered_request = server_context()
        .unprotect(
            &decode_coap(&request_wire)?,
            OscoreUnprotectParams::request(),
        )
        .unwrap();
    assert_eq!(compile(recovered_request)?, compile(request)?);

    // RFC 8613 Appendix C.7 response, reusing the request nonce.
    let binding = OscoreRequestBinding::new([], [0x14]).unwrap();
    let response = Coap::content()
        .acknowledgement()
        .message_id(0x5d1f)
        .token(CoapToken::from_bytes([0x00, 0x00, 0x39, 0x74]))
        .payload(b"Hello World!");
    let protected_response = server_context()
        .protect(&response, OscoreProtectParams::response(binding.clone()))
        .unwrap();
    assert_eq!(
        protected_response.payload_value(),
        [
            0xdb, 0xaa, 0xd1, 0xe9, 0xa7, 0xe7, 0xb2, 0xa8, 0x13, 0xd3, 0xc3, 0x15, 0x24, 0x37,
            0x83, 0x03, 0xcd, 0xaf, 0xae, 0x11, 0x91, 0x06
        ]
    );
    let response_wire = [
        0x64, 0x44, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, 0x90, 0xff, 0xdb, 0xaa, 0xd1, 0xe9, 0xa7,
        0xe7, 0xb2, 0xa8, 0x13, 0xd3, 0xc3, 0x15, 0x24, 0x37, 0x83, 0x03, 0xcd, 0xaf, 0xae, 0x11,
        0x91, 0x06,
    ];
    assert_eq!(compile(protected_response.clone())?, response_wire);
    let recovered_response = client_context()
        .unprotect(
            &decode_coap(&response_wire)?,
            OscoreUnprotectParams::response(binding),
        )
        .unwrap();
    assert_eq!(compile(recovered_response)?, compile(response)?);
    Ok(())
}

#[test]
fn core_observe_block_echo_request_tag_unknown_and_empty_round_trip() -> crafter::Result<()> {
    let messages = vec![
        Coap::get().message_id(1).uri_path("core"),
        Coap::get()
            .message_id(2)
            .observe(CoapObserve::registration()),
        Coap::put()
            .message_id(3)
            .block1(CoapBlock::block1(2, false, 1)?)
            .payload([0xa5; 8]),
        Coap::post()
            .message_id(4)
            .echo(CoapEcho::try_new([0xde, 0xad])?)
            .request_tag(CoapRequestTag::try_new([0x44])?),
        Coap::get()
            .message_id(5)
            .option(CoapOption::new(65_000, [0x00, 0xff, 0x80])),
        Coap::post().message_id(6),
    ];

    for (index, message) in messages.into_iter().enumerate() {
        let protected = client_context()
            .protect(
                &message,
                OscoreProtectParams::request([u8::try_from(index + 1).unwrap()]),
            )
            .unwrap();
        let recovered = server_context()
            .unprotect(&protected, OscoreUnprotectParams::request())
            .unwrap();
        assert_eq!(compile(recovered)?, compile(message)?);
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn bounded_messages_and_sequence_values_round_trip(
        payload in prop::collection::vec(any::<u8>(), 0..48),
        sequence in 0u32..=0x00ff_ffff,
        option_number in 300u16..600u16,
        option_value in prop::collection::vec(any::<u8>(), 0..16),
    ) {
        let message = Coap::post()
            .message_id(sequence as u16)
            .token(CoapToken::from_bytes(sequence.to_be_bytes()))
            .option(CoapOption::new(option_number, option_value))
            .payload(payload);
        let protected = prop_oscore(client_context().protect(
            &message,
            OscoreProtectParams::request(partial_iv(sequence)),
        ))?;
        let recovered = prop_oscore(server_context().unprotect(
            &protected,
            OscoreUnprotectParams::request(),
        ))?;
        prop_assert_eq!(prop_crafter(compile(recovered))?, prop_crafter(compile(message))?);
    }
}

#[test]
fn every_ciphertext_and_tag_byte_is_authenticated_without_panics() {
    let protected = client_context()
        .protect(
            &Coap::post()
                .message_id(0x9000)
                .option(CoapOption::new(COAP_OPTION_URI_PATH, b"tamper"))
                .payload(b"authenticated body"),
            OscoreProtectParams::request([0x23]),
        )
        .unwrap();

    for index in 0..protected.payload_value().len() {
        let mut bytes = protected.payload_value().to_vec();
        bytes[index] ^= 1;
        let tampered = protected.clone().payload(bytes);
        let outcome = std::panic::catch_unwind(|| {
            server_context().unprotect(&tampered, OscoreUnprotectParams::request())
        });
        let error = outcome.expect("tampered input must not panic").unwrap_err();
        assert_eq!(
            error,
            OscoreError::AuthenticationFailed {
                context: "coap.oscore.authentication",
            },
            "tampered byte {index}"
        );
    }
}

#[test]
fn debug_summary_show_and_errors_redact_context_secrets_and_keys() {
    let context = client_context();
    let protected = context
        .protect(
            &Coap::get()
                .message_id(7)
                .payload(b"visible application data"),
            OscoreProtectParams::request([0x07]),
        )
        .unwrap();
    let mut tampered = protected.clone();
    let mut bytes = tampered.payload_value().to_vec();
    bytes[0] ^= 0x80;
    tampered = tampered.payload(bytes);
    let error = server_context()
        .unprotect(&tampered, OscoreUnprotectParams::request())
        .unwrap_err();

    let renderings = [
        format!("{context:?}"),
        context.summary(),
        context.to_string(),
        format!("{protected:?}"),
        protected.summary(),
        Packet::from_layer(protected).show(),
        format!("{error:?}"),
        error.to_string(),
    ];
    for rendered in renderings {
        for forbidden in [
            "0102030405060708090a0b0c0d0e0f10",
            "9e7ca92223786340",
            "f0910ed7295e6ad4b54fc793154302ff",
            "ffb14e093c94c9cac9471648b4f98710",
            "4622d4dd6d944168eefb54987c",
        ] {
            assert!(
                !rendered.to_ascii_lowercase().contains(forbidden),
                "{rendered}"
            );
        }
    }
}

#[test]
fn provisional_group_flag_is_lossless_and_rejected_by_pairwise_unprotect() {
    // IANA currently assigns OSCORE flag bit position 2 to Group OSCORE while
    // retaining an Internet-Draft reference. The remaining bytes are the
    // compressed request-option example from draft revision 28 and are tested
    // only for opaque preservation, not as a stable protection grammar.
    let raw = [0x39, 0x05, 0x03, 0x44, 0x61, 0x6c, 0x25];
    let option = OscoreOption::parse(raw).unwrap();
    assert!(option.has_provisional_group_flag());
    assert_eq!(option.partial_iv(), Some([0x05].as_slice()));
    assert_eq!(option.kid_context(), Some([0x44, 0x61, 0x6c].as_slice()));
    assert_eq!(option.kid(), Some([0x25].as_slice()));
    assert_eq!(option.as_bytes(), raw);

    let protected = Coap::post()
        .option(CoapOption::new(COAP_OPTION_OSCORE, raw))
        .payload([0xae, 0xa0, 0x15, 0x56, 0x67, 0x92, 0x4d, 0xff]);
    assert_eq!(
        server_context()
            .unprotect(&protected, OscoreUnprotectParams::request())
            .unwrap_err(),
        OscoreError::UnsupportedGroupOscoreOperation {
            operation: "pairwise-unprotect",
        }
    );
}
