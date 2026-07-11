//! RFC-backed QUIC packet-protection vectors.
//!
//! These tests are offline-only and use the deterministic RFC 9001 and RFC 9369
//! Appendix A Initial examples. They do not open sockets or attempt live QUIC
//! behavior.

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
// RFC 9001, Appendix A.2 (Client Initial), complete 1200-byte protected packet.
const CLIENT_PROTECTED_PACKET: &str = "\
    c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123\
    dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b3\
    1f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1f\
    c8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89\
    eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf\
    012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5\
    a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7ba\
    d1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db\
    059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e8\
    46d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63\
    ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d50\
    8b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7\
    fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec\
    281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c481\
    9e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699d\
    bfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd\
    14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef\
    2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f254101\
    0ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f71\
    9595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd\
    d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705\
    769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d06\
    9fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb\
    5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2\
    162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f35\
    5e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db\
    82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8f\
    a9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723\
    c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b627\
    9ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc852\
    44259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f\
    5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064\
    7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44\
    860018ab0856972e194cd934";
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

const V2_CLIENT_UNPROTECTED_HEADER: &str = "d36b3343cf088394c8f03e5157080000449e00000002";
const V2_CLIENT_PROTECTED_HEADER: &str = "d76b3343cf088394c8f03e5157080000449ea0c95e82";
const V2_CLIENT_PROTECTED_PACKET_PREFIX: &str =
    "d76b3343cf088394c8f03e5157080000449ea0c95e82ffe67b6abcdb4298b485";
const V2_CLIENT_PROTECTED_PACKET_SUFFIX: &str = "\
    6f4c4938ae79324dc402894b44faf8afbab35282ab659d13c93f70412e85cb19\
    9a37ddec600545473cfb5a05e08d0b209973b2172b4d21fb69745a262ccde96b\
    a18b2faa745b6fe189cf772a9f84cbfc";
const V2_CLIENT_SAMPLE: &str = "ffe67b6abcdb4298b485dd04de806071";
const V2_CLIENT_MASK: &str = "94a0c95e80";

const V2_SERVER_UNPROTECTED_HEADER: &str = "d16b3343cf0008f067a5502a4262b50040750001";
const V2_SERVER_PROTECTED_HEADER: &str = "dc6b3343cf0008f067a5502a4262b5004075d92f";
const V2_SERVER_PROTECTED_PACKET: &str = "\
    dc6b3343cf0008f067a5502a4262b5004075d92faaf16f05d8a4398c47089698\
    baeea26b91eb761d9b89237bbf87263017915358230035f7fd3945d88965cf17\
    f9af6e16886c61bfc703106fbaf3cb4cfa52382dd16a393e42757507698075b2\
    c984c707f0a0812d8cd5a6881eaf21ceda98f4bd23f6fe1a3e2c43edd9ce7ca8\
    4bed8521e2e140";
const V2_SERVER_SAMPLE: &str = "6f05d8a4398c47089698baeea26b91eb";
const V2_SERVER_MASK: &str = "4dd92e91ea";

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

#[test]
fn quic_v2_initial_vectors_encrypt_decrypt_and_preserve_decode() -> crafter::Result<()> {
    let dcid = hex_bytes(TEST_DCID);
    let secrets = derive_quic_initial_secrets(QUIC_VERSION_2, dcid)?;

    let client_keys = secrets.client_packet_keys()?;
    let client_header = hex_bytes(V2_CLIENT_UNPROTECTED_HEADER);
    let mut client_payload = hex_bytes(CLIENT_INITIAL_PAYLOAD_PREFIX);
    client_payload.resize(CLIENT_INITIAL_PAYLOAD_LEN, 0);
    assert_eq!(
        quic_initial_payload_nonce(client_keys.iv(), 2),
        hex_array::<QUIC_INITIAL_IV_LEN>("91f73e2351d8fa91660e909d")
    );

    let client_ciphertext =
        quic_initial_aes128gcm_protect_payload(&client_keys, 2, &client_header, &client_payload)?;
    assert_eq!(
        &client_ciphertext[..QUIC_HEADER_PROTECTION_SAMPLE_LEN],
        hex_bytes(V2_CLIENT_SAMPLE).as_slice()
    );
    let client_mask = client_keys.header_protection_mask(&client_ciphertext[..16])?;
    assert_eq!(
        client_mask,
        hex_array::<QUIC_HEADER_PROTECTION_MASK_LEN>(V2_CLIENT_MASK)
    );

    let mut protected_client_header = client_header.clone();
    apply_long_header_protection(&mut protected_client_header, 18, 4, client_mask);
    assert_eq!(
        protected_client_header,
        hex_bytes(V2_CLIENT_PROTECTED_HEADER)
    );

    let mut protected_client_packet = protected_client_header;
    protected_client_packet.extend_from_slice(&client_ciphertext);
    assert!(protected_client_packet.starts_with(&hex_bytes(V2_CLIENT_PROTECTED_PACKET_PREFIX)));
    assert!(protected_client_packet.ends_with(&hex_bytes(V2_CLIENT_PROTECTED_PACKET_SUFFIX)));
    assert_eq!(
        quic_initial_aes128gcm_unprotect_payload(
            &client_keys,
            2,
            &client_header,
            &client_ciphertext
        )?,
        client_payload
    );

    let decoded_client = QuicPacket::decode(&protected_client_packet)?;
    assert_eq!(
        decoded_client.as_bytes(),
        protected_client_packet.as_slice()
    );
    assert!(decoded_client.is_long_header());

    let server_keys = secrets.server_packet_keys()?;
    let server_header = hex_bytes(V2_SERVER_UNPROTECTED_HEADER);
    let server_payload = hex_bytes(SERVER_INITIAL_PAYLOAD);
    assert_eq!(
        quic_initial_payload_nonce(server_keys.iv(), 1),
        hex_array::<QUIC_INITIAL_IV_LEN>("dd13c276499c0249d3310653")
    );

    let server_ciphertext = server_keys.protect_payload(1, &server_header, &server_payload)?;
    assert_eq!(
        &server_ciphertext[2..2 + QUIC_HEADER_PROTECTION_SAMPLE_LEN],
        hex_bytes(V2_SERVER_SAMPLE).as_slice()
    );
    let server_mask = quic_aes128_header_protection_mask(
        server_keys.header_protection_key(),
        &server_ciphertext[2..18],
    )?;
    assert_eq!(
        server_mask,
        hex_array::<QUIC_HEADER_PROTECTION_MASK_LEN>(V2_SERVER_MASK)
    );

    let mut protected_server_header = server_header.clone();
    apply_long_header_protection(&mut protected_server_header, 18, 2, server_mask);
    assert_eq!(
        protected_server_header,
        hex_bytes(V2_SERVER_PROTECTED_HEADER)
    );

    let mut protected_server_packet = protected_server_header;
    protected_server_packet.extend_from_slice(&server_ciphertext);
    assert_eq!(
        protected_server_packet,
        hex_bytes(V2_SERVER_PROTECTED_PACKET)
    );
    assert_eq!(
        server_keys.unprotect_payload(1, &server_header, &server_ciphertext)?,
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

#[test]
fn complete_initial_protection_matches_rfc_vectors() -> crafter::Result<()> {
    let original_dcid = QuicConnectionId::from_bytes(hex_bytes(TEST_DCID));
    let mut client_payload = hex_bytes(CLIENT_INITIAL_PAYLOAD_PREFIX);
    client_payload.resize(CLIENT_INITIAL_PAYLOAD_LEN, 0);

    // RFC 9001, Appendix A.2: complete QUIC v1 client Initial.
    let v1_secrets = derive_quic_initial_secrets(QUIC_VERSION_1, original_dcid.as_bytes())?;
    let v1_client_keys = v1_secrets.client_packet_keys()?;
    let v1_client = QuicLongHeaderPacket::initial_builder()
        .first_byte(0xc3)
        .version(QUIC_VERSION_1)
        .destination_connection_id(original_dcid.clone())
        .source_connection_id(QuicConnectionId::from_bytes([]))
        .token([])
        .length_encoded_len(2)
        .packet_number(QuicPacketNumber::new(2).with_encoded_len(4))
        .protected_payload(&client_payload)
        .build()?;
    let protected_v1_client =
        quic_protect_complete_initial_packet(&v1_client, 2, &v1_client_keys, 4)?;
    assert_eq!(
        protected_v1_client.as_bytes(),
        hex_bytes(CLIENT_PROTECTED_PACKET)
    );
    let decoded_v1_client = quic_decode_initial_protected_payload(
        QUIC_VERSION_1,
        original_dcid.as_bytes(),
        QuicInitialPacketDirection::Client,
        protected_v1_client.as_bytes(),
    )?;
    assert_eq!(decoded_v1_client.packet_number().value(), 2);
    assert_eq!(
        decoded_v1_client.unprotected_header(),
        hex_bytes(CLIENT_UNPROTECTED_HEADER)
    );
    assert_eq!(
        decoded_v1_client.frames(),
        QuicFrame::decode_sequence(&client_payload)?.as_slice()
    );

    let server_payload = hex_bytes(SERVER_INITIAL_PAYLOAD);
    let server_connection_id = QuicConnectionId::from_bytes(hex_bytes("f067a5502a4262b5"));

    // RFC 9001, Appendix A.3: complete QUIC v1 server Initial.
    let v1_server_keys = v1_secrets.server_packet_keys()?;
    let v1_server = QuicLongHeaderPacket::initial_builder()
        .first_byte(0xc1)
        .version(QUIC_VERSION_1)
        .destination_connection_id(QuicConnectionId::from_bytes([]))
        .source_connection_id(server_connection_id.clone())
        .token([])
        .length_encoded_len(2)
        .packet_number(QuicPacketNumber::new(1).with_encoded_len(2))
        .protected_payload(&server_payload)
        .build()?;
    let protected_v1_server =
        quic_protect_complete_initial_packet(&v1_server, 1, &v1_server_keys, 2)?;
    assert_eq!(
        protected_v1_server.as_bytes(),
        hex_bytes(SERVER_PROTECTED_PACKET)
    );
    let decoded_v1_server = quic_decode_initial_protected_payload(
        QUIC_VERSION_1,
        original_dcid.as_bytes(),
        QuicInitialPacketDirection::Server,
        protected_v1_server.as_bytes(),
    )?;
    assert_eq!(decoded_v1_server.packet_number().value(), 1);
    assert_eq!(
        decoded_v1_server.unprotected_header(),
        hex_bytes(SERVER_UNPROTECTED_HEADER)
    );
    assert_eq!(
        decoded_v1_server.frames(),
        QuicFrame::decode_sequence(&server_payload)?.as_slice()
    );

    // RFC 9369, Appendix A.3: complete QUIC v2 server Initial and v2 labels.
    let v2_secrets = derive_quic_initial_secrets(QUIC_VERSION_2, original_dcid.as_bytes())?;
    let v2_server_keys = v2_secrets.server_packet_keys()?;
    let v2_server = QuicLongHeaderPacket::initial_builder()
        .first_byte(0xd1)
        .version(QUIC_VERSION_2)
        .destination_connection_id(QuicConnectionId::from_bytes([]))
        .source_connection_id(server_connection_id)
        .token([])
        .length_encoded_len(2)
        .packet_number(QuicPacketNumber::new(1).with_encoded_len(2))
        .protected_payload(&server_payload)
        .build()?;
    let protected_v2_server =
        quic_protect_complete_initial_packet(&v2_server, 1, &v2_server_keys, 2)?;
    assert_eq!(
        protected_v2_server.as_bytes(),
        hex_bytes(V2_SERVER_PROTECTED_PACKET)
    );
    let decoded_v2_server = quic_decode_initial_protected_payload(
        QUIC_VERSION_2,
        original_dcid.as_bytes(),
        QuicInitialPacketDirection::Server,
        protected_v2_server.as_bytes(),
    )?;
    assert_eq!(decoded_v2_server.packet_number().value(), 1);
    assert_eq!(
        decoded_v2_server.unprotected_header(),
        hex_bytes(V2_SERVER_UNPROTECTED_HEADER)
    );
    assert_eq!(
        decoded_v2_server.frames(),
        QuicFrame::decode_sequence(&server_payload)?.as_slice()
    );

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
