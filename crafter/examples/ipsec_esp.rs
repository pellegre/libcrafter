//! Build and inspect an ESP-protected datagram entirely offline.
//!
//! This example crafts `Ipv4 / Esp::secured(sa) / Tcp / Raw` in transport mode
//! with an AES-GCM (AEAD) security association, compiles it to wire bytes, and
//! inspects it through `summary()` / `show()` / `hexdump()`. It then decodes the
//! datagram twice: once with the default SA-less registry (the encrypted body is
//! preserved opaquely) and once with a registry carrying the matching SA (the
//! AEAD tag is verified, the body is decrypted, and the inner TCP / Raw layers
//! are recovered as typed layers).
//!
//! Everything is offline: no interface is opened and no packet is transmitted.
//! All addresses are documentation address space (RFC 5737 / RFC 3849) and the
//! keys are fixed repeated bytes — never real key material.
//!
//! Run it with:
//!
//! ```text
//! cargo run --example ipsec_esp
//! ```

use std::net::Ipv4Addr;

use crafter::prelude::*;

/// Documentation-safe source / destination pair (RFC 5737).
const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

/// The documentation SPI carried by both the SA and the ESP header.
const ESP_SPI: u32 = 0x0000_2100;

/// A fixed 16-octet AES-128-GCM key (documentation-only, never a real key).
fn gcm_key() -> Vec<u8> {
    vec![0x24u8; 16]
}

/// The fixed 4-octet AES-GCM salt (the implicit nonce prefix, RFC 4106).
fn gcm_salt() -> Vec<u8> {
    vec![0xA1, 0xB2, 0xC3, 0xD4]
}

/// A deterministic 8-octet explicit IV so the sealed wire bytes are stable.
fn gcm_iv() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

/// Build the fixed AES-GCM-16 transport-mode security association.
fn esp_security_association() -> SecurityAssociation {
    SecurityAssociation::new(ESP_SPI)
        .encryption(EncryptionAlgorithm::AesGcm16, gcm_key())
        .salt(gcm_salt())
        .transport()
        .extended_sequence(false)
}

fn main() -> Result<()> {
    let sa = esp_security_association();
    assert!(sa.validate().is_ok(), "documentation ESP SA validates");

    // Build a transport-mode ESP datagram. The enclosing IPv4 datagram advertises
    // ESP (protocol 50); the TCP / Raw upper layers are sealed inside ESP.
    let packet: Packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_ESP)
        / Esp::secured(sa.clone())
            .spi(ESP_SPI)
            .sequence(1)
            .iv(gcm_iv())
        / Tcp::new().sport(40001).dport(443)
        / Raw::from("esp-example");

    let compiled = packet.compile()?;

    println!("example: ipsec_esp");
    println!("mode: offline");
    println!("documentation address pair: {DOC_SRC} -> {DOC_DST}");
    println!("suite: AES-GCM-16 (AEAD), transport mode");
    println!("summary: {}", packet.summary());
    println!("show:\n{}", packet.show());
    println!("compiled bytes: {}", compiled.len());
    println!("hexdump:\n{}", compiled.hexdump());

    let wire = compiled.as_bytes().to_vec();
    // The IPv4 protocol field (offset 9) advertises ESP; the sealed body follows
    // the 20-octet IPv4 header, so there is no cleartext TCP tail on the wire.
    assert_eq!(wire[9], IPPROTO_ESP, "outer IPv4 advertises ESP");

    // Decode with the default registry: no SA, so the encrypted body is opaque.
    let opaque = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire)?;
    let opaque_esp = opaque.layer::<Esp>().expect("typed ESP header recovered");
    println!();
    println!("decode (no SA): {}", opaque.summary());
    println!(
        "  spi: {:#010x}",
        opaque_esp.spi_value().expect("SPI is exposed")
    );
    println!(
        "  sequence: {}",
        opaque_esp.sequence_value().expect("sequence is exposed")
    );
    println!(
        "  opaque body bytes: {}",
        opaque_esp
            .opaque_body()
            .map(<[u8]>::len)
            .expect("no-SA decode keeps the body opaque")
    );
    assert!(
        opaque.layer::<Tcp>().is_none(),
        "without an SA the inner TCP stays encrypted"
    );

    // Decode with a registry carrying the SA: the AEAD tag verifies, the body
    // decrypts, the trailer is stripped, and the inner layers decode as typed.
    let registry = ProtocolRegistry::new().with_security_association(sa);
    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &wire)?;
    println!();
    println!("decode (with SA): {}", decoded.summary());

    let esp = decoded.layer::<Esp>().expect("typed ESP recovered with SA");
    println!("  spi: {:#010x}", esp.spi_value().expect("SPI is exposed"));

    let tcp = decoded.layer::<Tcp>().expect("inner TCP decrypted");
    println!(
        "  inner tcp: {} -> {}",
        tcp.source_port_value(),
        tcp.destination_port_value()
    );

    let inner = decoded.layer::<Raw>().expect("inner Raw decrypted");
    println!("  inner raw: {:?}", inner.raw_string_lossy());

    Ok(())
}
