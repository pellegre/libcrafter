//! Public-surface baseline tests for the ESP (IPSec) layer.
//!
//! These tests confirm that the ESP layer, the `SecurityAssociation` crypto
//! context, the `IpsecMode`/`EncryptionAlgorithm`/`IntegrityAlgorithm` enums,
//! and the ESP wire constants are all reachable through `crafter::prelude::*`,
//! and that a prelude-only tool can build, compile, and decode an ESP packet.
//! They stay fully offline and use documentation address space only.

use std::net::Ipv4Addr;

use crafter::prelude::*;

const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

/// Fixed 16-octet AES-128 key (documentation-only, never a real key).
fn aes_key() -> Vec<u8> {
    vec![0x11u8; 16]
}

/// Fixed 32-octet HMAC-SHA-256 integrity key (documentation-only).
fn hmac_key() -> Vec<u8> {
    vec![0x33u8; 32]
}

/// Build a transport-mode AES-CBC + HMAC-SHA-256-128 SA using only prelude
/// names. This is the exact surface a generated tool reaches for.
fn doc_security_association() -> SecurityAssociation {
    SecurityAssociation::new(0x0000_2000)
        .encryption(EncryptionAlgorithm::AesCbc, aes_key())
        .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key())
        .transport()
        .extended_sequence(false)
}

/// Build `Ipv4 / Esp::secured(sa) / Tcp / Raw` over documentation addresses,
/// using only names reachable from `crafter::prelude::*`.
fn esp_packet() -> Packet {
    let sa = doc_security_association();
    assert!(sa.validate().is_ok(), "documentation SA validates");

    Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_ESP)
        / Esp::secured(sa).spi(0x0000_2000).sequence(1)
        / Tcp::new().sport(40000).dport(443)
        / Raw::from("esp-public-api")
}

#[test]
fn prelude_exposes_ipsec_surface() {
    // Every IPSec name used below comes from `crafter::prelude::*` only.
    // Constructing these values is the compile-time proof the re-exports land.
    let _mode_transport = IpsecMode::Transport;
    let _mode_tunnel = IpsecMode::Tunnel;
    let _enc = EncryptionAlgorithm::AesGcm16;
    let _integ = IntegrityAlgorithm::HmacSha2_256_128;
    let _sa: SecurityAssociation = SecurityAssociation::new(0x10);
    let _esp: Esp = Esp::new();

    // ESP wire constants are reachable through the prelude too.
    assert_eq!(ESP_HEADER_LEN, 8);
    assert_eq!(ESP_HIGH_SEQUENCE_LEN, 4);
    assert_eq!(ESP_PAD_LENGTH_FIELD_LEN, 1);
    assert_eq!(ESP_NEXT_HEADER_FIELD_LEN, 1);
    assert_eq!(ESP_MAX_PAD_LEN, 255);
}

#[test]
fn prelude_only_esp_build_and_compile() -> Result<()> {
    // The headline assertion: a prelude-only tool can build an ESP packet and
    // compile it to wire bytes. The enclosing IPv4 datagram advertises ESP.
    let packet = esp_packet();
    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();

    // IPv4 protocol field (offset 9) is ESP (50). The crafted body is the
    // sealed ESP datagram, so there is no cleartext TCP tail on the wire.
    assert_eq!(bytes[9], IPPROTO_ESP);

    // The ESP datagram starts after the 20-octet IPv4 header with SPI || Seq.
    assert_eq!(&bytes[20..24], &0x0000_2000u32.to_be_bytes());
    assert_eq!(&bytes[24..28], &1u32.to_be_bytes());

    // A summary is always inspectable and never leaks key material.
    let summary = packet.summary();
    assert!(summary.contains("Esp"), "summary names the ESP layer");
    Ok(())
}

#[test]
fn prelude_only_esp_decode_round_trips_opaque() -> Result<()> {
    // Compile a real sealed ESP datagram, then decode it from L3. The built-in
    // registry carries no SA, so the ESP body is preserved opaquely — but the
    // ESP header (SPI/Seq) is typed and the opaque body re-compiles byte-exact.
    let packet = esp_packet();
    let bytes = packet.compile()?;
    let wire = bytes.as_bytes().to_vec();

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire)?;

    // The decoded packet exposes a typed ESP layer reachable via the prelude.
    let esp = decoded.layer::<Esp>().expect("decoded ESP layer present");
    assert_eq!(esp.spi_value(), Some(0x0000_2000));
    assert_eq!(esp.sequence_value(), Some(1));
    // No SA in the registry: the encrypted body is preserved opaquely.
    assert!(
        esp.opaque_body().is_some(),
        "no-SA decode keeps the encrypted body opaque"
    );

    // Re-compiling the decoded packet reproduces the wire bytes exactly.
    let recompiled = decoded.compile()?;
    assert_eq!(recompiled.as_bytes(), wire.as_slice());
    Ok(())
}
