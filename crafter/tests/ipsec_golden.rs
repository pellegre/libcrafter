//! Golden byte fixtures pinning current ESP, AH, and IKEv2 wire behavior.
//!
//! This file is a deliberate *behavior pin*: it builds representative IPSec
//! packets (ESP AES-GCM transport, ESP AES-CBC + HMAC-SHA-256 transport, AH
//! HMAC-SHA-256-128 over IPv4, and an IKE_SA_INIT message) with the current
//! public API and **fixed** keys / salt / IV / sequence / payload, compiles
//! them, and asserts the exact emitted bytes against checked-in hex constants.
//! It also decodes each compiled buffer (with an SA-carrying registry where
//! the body is encrypted) and recompiles it, asserting the round-trip is
//! byte-for-byte identical.
//!
//! These byte pins are deliberate behavior locks. Any refactor of the ESP/AH
//! serialization, the crypto driver, or the IKEv2 payload chain that changes
//! these bytes will fail this test on purpose. If a pin fails after an
//! *intended* change, only update the literal when the new bytes are
//! RFC-correct (cross-check against the oracle Scapy parity); otherwise the
//! code regressed and must be fixed.
//!
//! Everything here stays offline and uses documentation address space only
//! (`192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`) and fixed,
//! documentation-only key/IV material. The keys are never real keys.

use std::net::Ipv4Addr;

use crafter::prelude::*;

const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

/// A fixed IPv4 identification keeps the enclosing IPv4 header deterministic so
/// the golden bytes stay stable across runs.
const DOC_IP_ID: u16 = 0x1111;

// ---------------------------------------------------------------------------
// Fixed, documentation-only crypto material. None of these are real keys.
// ---------------------------------------------------------------------------

/// 16-octet AES-128-GCM key (0x24 repeated).
fn gcm_key() -> Vec<u8> {
    vec![0x24u8; 16]
}

/// 4-octet AES-GCM salt (the implicit nonce prefix, RFC 4106).
fn gcm_salt() -> Vec<u8> {
    vec![0xA1, 0xB2, 0xC3, 0xD4]
}

/// 8-octet explicit AES-GCM IV (pinned so the sealed wire bytes are stable).
fn gcm_iv() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

/// 16-octet AES-128-CBC key (0x11 repeated).
fn cbc_key() -> Vec<u8> {
    vec![0x11u8; 16]
}

/// 16-octet explicit AES-CBC IV (0x00..0x0F).
fn cbc_iv() -> Vec<u8> {
    (0u8..16).collect()
}

/// 32-octet HMAC-SHA-256 integrity key (0x33 repeated).
fn hmac_key() -> Vec<u8> {
    vec![0x33u8; 32]
}

// ---------------------------------------------------------------------------
// Shared helpers (mirroring `icmp_golden.rs`).
// ---------------------------------------------------------------------------

/// Helper used once to mint the golden constants below. Set
/// `CRAFTER_IPSEC_GOLDEN_DUMP=1` and run with `--nocapture` to print the
/// freshly-compiled hex for every case; paste the values into the `GOLDEN_*`
/// constants. Not part of normal assertions.
fn maybe_dump(name: &str, bytes: &[u8]) {
    if std::env::var_os("CRAFTER_IPSEC_GOLDEN_DUMP").is_some() {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        println!("GOLDEN {name} = \"{hex}\"");
    }
}

/// Parse a compact hex string ("00ff..") into bytes for a golden constant.
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "golden hex must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Decode an L3 buffer back into typed layers (no SA needed), recompile, and
/// assert the bytes are byte-for-byte identical to the input.
fn assert_roundtrip(layer: NetworkLayer, golden: &[u8]) {
    let decoded = Packet::decode_from_l3(layer, golden).expect("decode golden bytes");
    let recompiled = decoded.compile().expect("recompile decoded packet");
    assert_eq!(
        recompiled.as_bytes(),
        golden,
        "decode/recompile round-trip changed the bytes"
    );
}

/// Decode an L3 buffer using a registry that carries the matching SA. This
/// proves the pinned bytes are a *valid* sealed datagram: the SA-aware path
/// verifies the ICV / AEAD tag and decrypts, exposing the inner layers. It
/// returns the decoded packet so a case can assert which inner layers were
/// recovered.
///
/// Note: the SA decrypt path replaces the sealed ESP body with the recovered
/// cleartext inner layers, so re-compiling the *decoded* packet re-seals and
/// is not byte-identical to the sealed input. The byte-exact recompile lock is
/// the opaque (no-SA) path in `assert_roundtrip`, which the ESP cases also use.
fn decode_with_sa(sa: SecurityAssociation, layer: NetworkLayer, golden: &[u8]) -> Packet {
    let registry = ProtocolRegistry::new().with_security_association(sa);
    Packet::decode_from_l3_with_registry(&registry, layer, golden)
        .expect("decode golden bytes with SA (ICV/tag verifies, body decrypts)")
}

// ===========================================================================
// ESP AES-GCM-16 transport over IPv4 (RFC 4303 + RFC 4106).
// Fixed SPI / seq / key / salt / IV / payload -> the full emitted byte vector
// is header + explicit IV + ciphertext + 16-octet tag.
// ===========================================================================

const ESP_GCM_SPI: u32 = 0x0000_2100;

fn esp_gcm_sa() -> SecurityAssociation {
    SecurityAssociation::new(ESP_GCM_SPI)
        .encryption(EncryptionAlgorithm::AesGcm16, gcm_key())
        .salt(gcm_salt())
        .transport()
        .extended_sequence(false)
}

fn build_esp_gcm_transport() -> Packet {
    Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_DST)
        .id(DOC_IP_ID)
        .protocol(IPPROTO_ESP)
        / Esp::secured(esp_gcm_sa())
            .spi(ESP_GCM_SPI)
            .sequence(1)
            .iv(gcm_iv())
        / Tcp::new().sport(40001).dport(443)
        / Raw::from("esp-gcm-golden")
}

const GOLDEN_ESP_GCM_TRANSPORT: &str = "450000581111000040327d11c000020ac633641400002100000000010102030405060708322c1696fea6a541e7154dd59441486fbf7134ee7d7f9fb3719e5dacb26a36912b470b97b8dd6f930347a19ea67253081a02b1a3";

#[test]
fn ipsec_golden_esp_gcm_transport() {
    let bytes = build_esp_gcm_transport().compile().expect("compile");
    maybe_dump("ESP_GCM", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_ESP_GCM_TRANSPORT).as_slice());
    // The opaque (no-SA) decode preserves the sealed body verbatim and
    // re-compiles byte-for-byte: this is the round-trip half of the pin.
    assert_roundtrip(NetworkLayer::Ipv4, bytes.as_bytes());
    // Decode-with-SA proves the pinned bytes are a valid AEAD datagram: the tag
    // verifies and the body decrypts back to the inner TCP / Raw layers.
    let decoded = decode_with_sa(esp_gcm_sa(), NetworkLayer::Ipv4, bytes.as_bytes());
    assert_eq!(
        decoded.layer::<Esp>().unwrap().spi_value(),
        Some(ESP_GCM_SPI)
    );
    assert_eq!(
        decoded
            .layer::<Tcp>()
            .expect("inner TCP decrypts")
            .source_port_value(),
        40001
    );
    assert_eq!(
        decoded
            .layer::<Raw>()
            .expect("inner Raw decrypts")
            .as_bytes(),
        b"esp-gcm-golden"
    );
}

// ===========================================================================
// ESP AES-CBC + HMAC-SHA-256-128 transport over IPv4 (RFC 4303 + RFC 3602 +
// RFC 4868). Fixed inputs -> header + explicit IV + CBC ciphertext (payload +
// RFC 4303 §2.4 pad + pad-length + next-header) + 16-octet HMAC ICV.
// ===========================================================================

const ESP_CBC_SPI: u32 = 0x0000_2800;

fn esp_cbc_sa() -> SecurityAssociation {
    SecurityAssociation::new(ESP_CBC_SPI)
        .encryption(EncryptionAlgorithm::AesCbc, cbc_key())
        .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key())
        .transport()
        .extended_sequence(false)
}

fn build_esp_cbc_transport() -> Packet {
    Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_DST)
        .id(DOC_IP_ID)
        .protocol(IPPROTO_ESP)
        / Esp::secured(esp_cbc_sa())
            .spi(ESP_CBC_SPI)
            .sequence(1)
            .iv(cbc_iv())
        / Tcp::new().sport(41000).dport(443)
        / Raw::from("esp-cbc-golden")
}

const GOLDEN_ESP_CBC_TRANSPORT: &str = "4500006c1111000040327cfdc000020ac63364140000280000000001000102030405060708090a0b0c0d0e0f63831861e005a1ec7f6b4de5cf9defd6c9a3d1ae1e8cef9dd9e54392842e7c3e02ad906c121623b76ededc4c761ce88ea29fda02fbb114ee5474f1099c30e359";

#[test]
fn ipsec_golden_esp_cbc_hmac_transport() {
    let bytes = build_esp_cbc_transport().compile().expect("compile");
    maybe_dump("ESP_CBC", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_ESP_CBC_TRANSPORT).as_slice());
    // Opaque (no-SA) decode preserves the sealed body and re-compiles exactly.
    assert_roundtrip(NetworkLayer::Ipv4, bytes.as_bytes());
    // Decode-with-SA verifies the HMAC ICV, decrypts the CBC body, validates the
    // RFC 4303 §2.4 pad, and recovers the inner TCP / Raw.
    let decoded = decode_with_sa(esp_cbc_sa(), NetworkLayer::Ipv4, bytes.as_bytes());
    assert_eq!(
        decoded.layer::<Esp>().unwrap().spi_value(),
        Some(ESP_CBC_SPI)
    );
    assert_eq!(
        decoded
            .layer::<Tcp>()
            .expect("inner TCP decrypts")
            .source_port_value(),
        41000
    );
    assert_eq!(
        decoded
            .layer::<Raw>()
            .expect("inner Raw decrypts")
            .as_bytes(),
        b"esp-cbc-golden"
    );
}

// ===========================================================================
// AH HMAC-SHA-256-128 over IPv4 (RFC 4302 + RFC 4868). Fixed inputs -> the AH
// header (Next Header | Payload Len | Reserved | SPI | Seq | 16-octet ICV)
// followed by the cleartext upper layer. The ICV authenticates the
// canonicalized immutable IP fields, the ICV-zeroed AH header, and the payload.
// ===========================================================================

const AH_SPI: u32 = 0x0000_3100;

fn ah_sa() -> SecurityAssociation {
    SecurityAssociation::new(AH_SPI)
        .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key())
        .transport()
        .extended_sequence(false)
}

fn build_ah_hmac_ipv4() -> Packet {
    Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_DST)
        .id(DOC_IP_ID)
        .ttl(64)
        .protocol(IPPROTO_AH)
        / Ah::secured(ah_sa()).spi(AH_SPI).sequence(1)
        / Tcp::new().sport(43000).dport(443)
        / Raw::from("ah-golden")
}

const GOLDEN_AH_HMAC_IPV4: &str = "4500004d1111000040337d1bc000020ac6336414060500000000310000000001bacc1e22af74393ffafb7a77da4a74e0a7f801bb0000000000000000500220002905000061682d676f6c64656e";

#[test]
fn ipsec_golden_ah_hmac_sha256_ipv4() {
    let bytes = build_ah_hmac_ipv4().compile().expect("compile");
    maybe_dump("AH_HMAC", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_AH_HMAC_IPV4).as_slice());
    // AH never encrypts; the opaque (SA-less) decode round-trips byte-exact.
    assert_roundtrip(NetworkLayer::Ipv4, bytes.as_bytes());
    // The SA-aware path additionally verifies the ICV over the canonicalized IP
    // header, the ICV-zeroed AH header, and the cleartext payload, and (since AH
    // does not encrypt) still re-compiles byte-for-byte.
    let decoded = decode_with_sa(ah_sa(), NetworkLayer::Ipv4, bytes.as_bytes());
    let ah = decoded.layer::<Ah>().expect("typed AH recovered");
    assert_eq!(ah.spi_value(), Some(AH_SPI));
    assert_eq!(
        ah.verification_status(),
        Some(true),
        "matching SA verifies the AH ICV"
    );
    assert!(decoded.layer::<Tcp>().is_some(), "inner TCP in the clear");
    assert_eq!(
        decoded.compile().expect("recompile AH").as_bytes(),
        bytes.as_bytes(),
        "AH SA decode re-compiles byte-for-byte"
    );
}

// ===========================================================================
// IKE_SA_INIT message over UDP/500 (RFC 7296 §1.2): IkeHeader / SA / KE / Ni.
// Fixed SPIs / proposal / DH group / nonce -> the full emitted byte vector,
// including the auto-filled IKE message length and Next Payload chain.
// ===========================================================================

/// UDP port 500, the IKEv2 well-known port (RFC 7296 §2).
const IKE_UDP_PORT: u16 = 500;

fn build_ike_sa_init() -> Packet {
    let proposal = Proposal::new(1, PROTOCOL_ID_IKE)
        .with_transform(
            Transform::new(TRANSFORM_TYPE_ENCR, 20)
                .with_attribute(TransformAttribute::key_length(128)),
        )
        .with_transform(Transform::new(TRANSFORM_TYPE_DH, DH_GROUP_MODP_2048));
    let sa = IkeSaPayload::new().with_proposal(proposal);
    let ke = IkeKePayload::new(DH_GROUP_MODP_2048, vec![0xAB; 32]);
    let ni = IkeNoncePayload::new(vec![0x5A; 16]);

    let header = IkeHeader::new()
        .initiator_spi(0x0102_0304_0506_0708)
        .exchange(IKE_SA_INIT)
        .initiator();

    Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_DST)
        .id(DOC_IP_ID)
        .protocol(IPPROTO_UDP)
        / Udp::new().sport(IKE_UDP_PORT).dport(IKE_UDP_PORT)
        / header
        / sa
        / ke
        / ni
}

const GOLDEN_IKE_SA_INIT: &str = "450000941111000040117cf6c000020ac633641401f401f40080592401020304050607080000000000000000212022080000000000000078220000200000001c010100020300000c01000014800e0080000000080400000e28000028000e0000abababababababababababababababababababababababababababababababab000000145a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

#[test]
fn ipsec_golden_ike_sa_init() {
    let bytes = build_ike_sa_init().compile().expect("compile");
    maybe_dump("IKE_SA_INIT", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_IKE_SA_INIT).as_slice());
    assert_roundtrip(NetworkLayer::Ipv4, bytes.as_bytes());
}
