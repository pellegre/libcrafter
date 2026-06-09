//! Public-surface baseline tests for the ESP and AH (IPSec) layers.
//!
//! These tests confirm that the ESP and AH layers, the `SecurityAssociation`
//! crypto context, the `IpsecMode`/`EncryptionAlgorithm`/`IntegrityAlgorithm`
//! enums, and the ESP/AH wire constants are all reachable through
//! `crafter::prelude::*`, and that a prelude-only tool can build, compile, and
//! decode ESP and AH packets. They stay fully offline and use documentation
//! address space only.

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

/// Build an integrity-only (HMAC-SHA-256-128) SA in the requested IPSec mode,
/// using only prelude names. AH never encrypts, so no encryption suite is set.
fn ah_security_association(tunnel: bool) -> SecurityAssociation {
    let sa = SecurityAssociation::new(0x0000_3000)
        .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key())
        .extended_sequence(false);
    if tunnel {
        sa.tunnel()
    } else {
        sa.transport()
    }
}

#[test]
fn prelude_exposes_ah_surface() {
    // The AH layer and its wire constants are reachable through the prelude.
    let _ah: Ah = Ah::new();
    assert_eq!(AH_FIXED_LEN, 12);
    assert_eq!(AH_NEXT_HEADER_LEN, 1);
    assert_eq!(AH_PAYLOAD_LEN_FIELD_LEN, 1);
    assert_eq!(AH_RESERVED_LEN, 2);
    assert_eq!(AH_SPI_LEN, 4);
    assert_eq!(AH_SEQUENCE_LEN, 4);
    assert_eq!(AH_HIGH_SEQUENCE_LEN, 4);
    assert_eq!(AH_LENGTH_UNIT, 4);
    assert_eq!(AH_PAYLOAD_LEN_OFFSET, 2);
}

#[test]
fn prelude_only_ah_transport_build_and_decode() -> Result<()> {
    // A prelude-only tool builds a transport-mode AH packet, compiles it (the
    // SA-driven ICV authenticates the immutable IP fields, the zeroed AH header,
    // and the cleartext upper layer), then decodes it back from L3.
    let sa = ah_security_association(false);
    assert!(sa.validate().is_ok(), "documentation AH SA validates");
    assert_eq!(sa.mode, IpsecMode::Transport);

    // AH only authenticates: the TCP / Raw tail travels in the clear.
    let packet: Packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_AH)
        / Ah::secured(sa).spi(0x0000_3000).sequence(1)
        / Tcp::new().sport(40000).dport(443)
        / Raw::from("ah-public-api");

    let compiled = packet.compile()?;
    let wire = compiled.as_bytes().to_vec();

    // The enclosing IPv4 advertises AH (protocol 51) at offset 9.
    assert_eq!(wire[9], IPPROTO_AH);
    // The AH header begins right after the 20-octet IPv4 header: Next Header is
    // TCP (6), and SPI || Seq follow Payload Len + Reserved.
    assert_eq!(wire[20], IPPROTO_TCP);
    assert_eq!(&wire[24..28], &0x0000_3000u32.to_be_bytes());
    assert_eq!(&wire[28..32], &1u32.to_be_bytes());

    // The summary names the AH layer and never leaks key material.
    let summary = packet.summary();
    assert!(summary.contains("Ah"), "summary names the AH layer");

    // Decode from L3. The built-in registry carries no SA, so AH decodes opaque:
    // the typed header (SPI/Seq) plus the captured ICV that re-compiles exactly,
    // and the cleartext inner TCP layer is dispatched by Next Header.
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire)?;
    let ah = decoded.layer::<Ah>().expect("decoded AH layer present");
    assert_eq!(ah.spi_value(), Some(0x0000_3000));
    assert_eq!(ah.sequence_value(), Some(1));
    assert_eq!(ah.next_header_value(), Some(IPPROTO_TCP));
    // HMAC-SHA-256-128 emits a 16-octet ICV (RFC 4868), already 32-bit aligned.
    assert_eq!(ah.icv_value().map(<[u8]>::len), Some(16));
    // The protected upper layer survives in the clear and decodes as TCP.
    assert!(decoded.layer::<Tcp>().is_some(), "inner TCP decodes");

    // The decoded packet re-compiles to the same wire bytes (ICV preserved).
    let recompiled = decoded.compile()?;
    assert_eq!(recompiled.as_bytes(), wire.as_slice());
    Ok(())
}

#[test]
fn prelude_only_ah_tunnel_build_and_decode() -> Result<()> {
    // A prelude-only tool builds a tunnel-mode AH packet: the protected data is
    // an entire inner IPv4 datagram, so the AH Next Header is IPv4-in-IPv4 (4).
    let sa = ah_security_association(true);
    assert!(
        sa.validate().is_ok(),
        "documentation AH tunnel SA validates"
    );
    assert_eq!(sa.mode, IpsecMode::Tunnel);

    // Outer Ipv4 / Ah / inner Ipv4 / Tcp / Raw. AH authenticates the immutable
    // outer header and the cleartext inner datagram without encrypting it.
    let inner_src = Ipv4Addr::new(192, 0, 2, 30);
    let inner_dst = Ipv4Addr::new(198, 51, 100, 40);
    let packet: Packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_AH)
        / Ah::secured(sa).spi(0x0000_3000).sequence(1)
        / Ipv4::new()
            .src(inner_src)
            .dst(inner_dst)
            .protocol(IPPROTO_TCP)
        / Tcp::new().sport(50000).dport(443)
        / Raw::from("ah-tunnel-public-api");

    let compiled = packet.compile()?;
    let wire = compiled.as_bytes().to_vec();

    // The outer IPv4 advertises AH (51); the AH Next Header is IPv4-in-IPv4 (4).
    assert_eq!(wire[9], IPPROTO_AH);
    assert_eq!(
        wire[20], 4,
        "AH Next Header is IPv4-in-IPv4 for tunnel mode"
    );
    assert_eq!(&wire[24..28], &0x0000_3000u32.to_be_bytes());

    // Decode from L3: outer IPv4, the opaque AH header, and the inner IPv4
    // datagram (with its own TCP) all decode as nested typed layers.
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire)?;
    let ah = decoded.layer::<Ah>().expect("decoded AH layer present");
    assert_eq!(ah.spi_value(), Some(0x0000_3000));
    assert_eq!(ah.next_header_value(), Some(4));
    assert_eq!(ah.icv_value().map(<[u8]>::len), Some(16));

    // The inner IPv4 datagram is recovered: the decoded stack carries two IPv4
    // layers (outer + inner) and the inner TCP segment.
    let ipv4_layers = decoded.layers::<Ipv4>().count();
    assert_eq!(ipv4_layers, 2, "outer and inner IPv4 both decode");
    assert!(decoded.layer::<Tcp>().is_some(), "inner TCP decodes");

    // The decoded packet re-compiles to the same wire bytes.
    let recompiled = decoded.compile()?;
    assert_eq!(recompiled.as_bytes(), wire.as_slice());
    Ok(())
}
