//! RFC-backed QUIC packet-protection vectors.
//!
//! These tests are offline-only and use the deterministic RFC 9001 Appendix A
//! Initial examples. They do not open sockets or attempt live QUIC behavior.

use crafter::prelude::*;

const TEST_DCID: &str = "8394c8f03e515708";
const CLIENT_INITIAL_PAYLOAD_PREFIX: &str = "\
    060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868\
    04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578\
    616d706c652e636f6dff01000100000a00080006001d00170018001000070005\
    04616c706e000500050100000000003300260024001d00209370b2c9caa47fba\
    baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400\
    0d0010000e0403050306030203080408050806002d00020101001c0002400100\
    3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000\
    75300901100f088394c8f03e51570806048000ffff";
const CLIENT_INITIAL_PAYLOAD_LEN: usize = 1162;
const CLIENT_UNPROTECTED_HEADER: &str = "c300000001088394c8f03e5157080000449e00000002";
const CLIENT_PROTECTED_HEADER: &str = "c000000001088394c8f03e5157080000449e7b9aec34";
const CLIENT_PROTECTED_PACKET_PREFIX: &str =
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11";
const CLIENT_PROTECTED_PACKET_SUFFIX: &str = "\
    7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241\
    e221af44860018ab0856972e194cd934";
const CLIENT_SAMPLE: &str = "d1b1c98dd7689fb8ec11d242b123dc9b";
const CLIENT_MASK: &str = "437b9aec36";

const SERVER_INITIAL_PAYLOAD: &str = "\
    02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739\
    88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94\
    0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00\
    020304";
const SERVER_UNPROTECTED_HEADER: &str = "c1000000010008f067a5502a4262b50040750001";
const SERVER_PROTECTED_HEADER: &str = "cf000000010008f067a5502a4262b5004075c0d9";
const SERVER_PROTECTED_PACKET: &str = "\
    cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a\
    5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3\
    dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84\
    022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4\
    2158407dd074ee";
const SERVER_SAMPLE: &str = "2cd0991cd25b0aac406a5816b6394100";
const SERVER_MASK: &str = "2ec0d8356a";

#[test]
fn quic_v1_initial_vectors_encrypt_decrypt_and_preserve_decode() -> crafter::Result<()> {
    let dcid = hex_bytes(TEST_DCID);
    let secrets = derive_quic_initial_secrets(QUIC_VERSION_1, dcid)?;

    let client_keys = secrets.client_packet_keys()?;
    let client_header = hex_bytes(CLIENT_UNPROTECTED_HEADER);
    let mut client_payload = hex_bytes(CLIENT_INITIAL_PAYLOAD_PREFIX);
    client_payload.resize(CLIENT_INITIAL_PAYLOAD_LEN, 0);
    assert_eq!(
        quic_initial_payload_nonce(client_keys.iv(), 2),
        hex_array::<QUIC_INITIAL_IV_LEN>("fa044b2f42a3fd3b46fb255e")
    );

    let client_ciphertext = client_keys.protect_payload(2, &client_header, &client_payload)?;
    assert_eq!(
        client_ciphertext.len(),
        CLIENT_INITIAL_PAYLOAD_LEN + QUIC_INITIAL_AEAD_TAG_LEN
    );
    assert_eq!(
        &client_ciphertext[..QUIC_HEADER_PROTECTION_SAMPLE_LEN],
        hex_bytes(CLIENT_SAMPLE).as_slice()
    );
    let client_mask = client_keys.header_protection_mask(&client_ciphertext[..16])?;
    assert_eq!(
        client_mask,
        hex_array::<QUIC_HEADER_PROTECTION_MASK_LEN>(CLIENT_MASK)
    );

    let mut protected_client_header = client_header.clone();
    apply_long_header_protection(&mut protected_client_header, 18, 4, client_mask);
    assert_eq!(protected_client_header, hex_bytes(CLIENT_PROTECTED_HEADER));

    let mut protected_client_packet = protected_client_header;
    protected_client_packet.extend_from_slice(&client_ciphertext);
    assert!(protected_client_packet.starts_with(&hex_bytes(CLIENT_PROTECTED_PACKET_PREFIX)));
    assert!(protected_client_packet.ends_with(&hex_bytes(CLIENT_PROTECTED_PACKET_SUFFIX)));

    assert_eq!(
        client_keys.unprotect_payload(2, &client_header, &client_ciphertext)?,
        client_payload
    );
    let decoded_client = QuicPacket::decode(&protected_client_packet)?;
    assert_eq!(
        decoded_client.as_bytes(),
        protected_client_packet.as_slice()
    );
    assert!(decoded_client.is_long_header());

    let server_keys = secrets.server_packet_keys()?;
    let server_header = hex_bytes(SERVER_UNPROTECTED_HEADER);
    let server_payload = hex_bytes(SERVER_INITIAL_PAYLOAD);
    assert_eq!(
        quic_initial_payload_nonce(server_keys.iv(), 1),
        hex_array::<QUIC_INITIAL_IV_LEN>("0ac1493ca1905853b0bba03f")
    );

    let server_ciphertext =
        quic_initial_aes128gcm_protect_payload(&server_keys, 1, &server_header, &server_payload)?;
    assert_eq!(
        &server_ciphertext[2..2 + QUIC_HEADER_PROTECTION_SAMPLE_LEN],
        hex_bytes(SERVER_SAMPLE).as_slice()
    );
    let server_mask = quic_aes128_header_protection_mask(
        server_keys.header_protection_key(),
        &server_ciphertext[2..18],
    )?;
    assert_eq!(
        server_mask,
        hex_array::<QUIC_HEADER_PROTECTION_MASK_LEN>(SERVER_MASK)
    );

    let mut protected_server_header = server_header.clone();
    apply_long_header_protection(&mut protected_server_header, 18, 2, server_mask);
    assert_eq!(protected_server_header, hex_bytes(SERVER_PROTECTED_HEADER));

    let mut protected_server_packet = protected_server_header;
    protected_server_packet.extend_from_slice(&server_ciphertext);
    assert_eq!(protected_server_packet, hex_bytes(SERVER_PROTECTED_PACKET));
    assert_eq!(
        quic_initial_aes128gcm_unprotect_payload(
            &server_keys,
            1,
            &server_header,
            &server_ciphertext
        )?,
        server_payload
    );

    let decoded_server = QuicPacket::decode(&protected_server_packet)?;
    assert_eq!(
        decoded_server.as_bytes(),
        protected_server_packet.as_slice()
    );
    assert!(decoded_server.is_long_header());

    Ok(())
}

fn apply_long_header_protection(
    header: &mut [u8],
    packet_number_offset: usize,
    packet_number_len: usize,
    mask: [u8; QUIC_HEADER_PROTECTION_MASK_LEN],
) {
    header[0] ^= mask[0] & 0x0f;
    for i in 0..packet_number_len {
        header[packet_number_offset + i] ^= mask[1 + i];
    }
}

fn hex_array<const N: usize>(input: &str) -> [u8; N] {
    let bytes = hex_bytes(input);
    assert_eq!(bytes.len(), N);
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

fn hex_bytes(input: &str) -> Vec<u8> {
    let clean: String = input.chars().filter(|ch| !ch.is_whitespace()).collect();
    assert_eq!(clean.len() % 2, 0, "hex string must have even length");
    (0..clean.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&clean[index..index + 2], 16).expect("valid hex byte"))
        .collect()
}
