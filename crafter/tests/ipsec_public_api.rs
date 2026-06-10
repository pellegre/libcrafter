//! Public-surface baseline tests for the ESP, AH, and IKEv2 (IPSec) layers.
//!
//! These tests confirm that the ESP and AH layers, the `SecurityAssociation`
//! crypto context, the `IpsecMode`/`EncryptionAlgorithm`/`IntegrityAlgorithm`
//! enums, the ESP/AH wire constants, and the IKEv2 message header, payload set,
//! and codepoints are all reachable through `crafter::prelude::*`, and that a
//! prelude-only tool can build, compile, and decode ESP, AH, and IKEv2 packets.
//! They stay fully offline and use documentation address space only.

use std::net::{Ipv4Addr, Ipv6Addr};

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

/// UDP port 500, the IKEv2 well-known port (RFC 7296 §2).
const IKE_UDP_PORT: u16 = 500;

#[test]
fn prelude_exposes_ikev2_surface() {
    // Every IKEv2 name below is reached through `crafter::prelude::*` only;
    // constructing them is the compile-time proof the re-exports land. The
    // header, the payload-type enum, the full payload set, and the per-payload
    // field enums all surface for a prelude-only tool.
    let _header: IkeHeader = IkeHeader::new().exchange(IKE_SA_INIT).initiator();
    let _sa: IkeSaPayload = IkeSaPayload::new().with_proposal(
        Proposal::new(1, PROTOCOL_ID_IKE).with_transform(
            Transform::new(TRANSFORM_TYPE_ENCR, 20)
                .with_attribute(TransformAttribute::key_length(128)),
        ),
    );
    let _ke: IkeKePayload = IkeKePayload::new(DH_GROUP_MODP_2048, vec![0u8; 32]);
    let _ni: IkeNoncePayload = IkeNoncePayload::new(vec![0u8; 16]);
    let _notify: IkeNotifyPayload =
        IkeNotifyPayload::new(NOTIFY_PROTOCOL_NONE, NotifyType::Cookie, Vec::<u8>::new());
    let _delete: IkeDeletePayload = IkeDeletePayload::new(DELETE_PROTOCOL_ESP);
    let _id: IkeIdPayload = IkeIdPayload::initiator_ipv4(Ipv4Addr::new(192, 0, 2, 10));
    let _id_role = IdRole::Initiator;
    let _auth: IkeAuthPayload = IkeAuthPayload::new(AuthMethod::SharedKeyMic, vec![0u8; 8]);
    let _vendor: IkeVendorIdPayload = IkeVendorIdPayload::new(vec![0u8; 4]);
    let _eap: IkeEapPayload = IkeEapPayload::new(vec![0u8; 4]);

    // The payload-type codepoint enum and field enums are reachable too.
    let _pt: PayloadType = PayloadType::SecurityAssociation;
    let _ts_role = TsRole::Initiator;
    let _id_type = IdType::Ipv4Addr;
    let _cfg = CfgType::Request;
    let _cert = CertEncoding::X509Signature;

    // IKEv2 wire constants are reachable through the prelude.
    assert_eq!(IKE_HEADER_LEN, 28);
    assert_eq!(IKE_VERSION_2, 0x20);
    assert_eq!(IKE_SA_INIT, 34);
    assert_eq!(GENERIC_PAYLOAD_HEADER_LEN, 4);
    assert_eq!(PAYLOAD_SA, 33);
    assert_eq!(PAYLOAD_KE, 34);
    assert_eq!(PAYLOAD_NONCE, 40);
    assert_eq!(PAYLOAD_TYPE_NONE, 0);
}

/// Build an `IKE_SA_INIT` initiator message — `IkeHeader / SA / KE / Ni` — over
/// UDP/500, using only names reachable from `crafter::prelude::*`. This is the
/// minimal first message of the IKEv2 exchange (RFC 7296 §1.2).
fn ike_sa_init_packet() -> Packet {
    // One IKE proposal carrying a single ENCR transform (AES-128) plus a D-H
    // group transform; codepoints are illustrative for the wire round-trip.
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

    Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_UDP)
        / Udp::new().sport(IKE_UDP_PORT).dport(IKE_UDP_PORT)
        / header
        / sa
        / ke
        / ni
}

#[test]
fn prelude_only_ike_sa_init_build_decode_round_trips() -> Result<()> {
    // A prelude-only tool builds the IKE_SA_INIT message, compiles it over
    // UDP/500, decodes it from L3, and confirms the typed layers plus a
    // byte-exact re-compile — the headline IKEv2 acceptance (spec §"IKEv2
    // message round-trip").
    let packet = ike_sa_init_packet();
    let compiled = packet.compile()?;
    let wire = compiled.as_bytes().to_vec();

    // The enclosing IPv4 advertises UDP (17); the IKE message follows the
    // 8-octet UDP header (after the 20-octet IPv4 header).
    assert_eq!(wire[9], IPPROTO_UDP);
    // UDP source/destination ports are both 500 (the IKEv2 port).
    assert_eq!(&wire[20..22], &IKE_UDP_PORT.to_be_bytes());
    assert_eq!(&wire[22..24], &IKE_UDP_PORT.to_be_bytes());
    // The IKE header starts at offset 28: Initiator SPI is the pinned value.
    assert_eq!(&wire[28..36], &0x0102_0304_0506_0708u64.to_be_bytes());

    // The summary names the IKE header and never leaks key material.
    let summary = packet.summary();
    assert!(
        summary.contains("IkeHeader"),
        "summary names the IKE header"
    );

    // Decode from L3. UDP/500 routes to IKEv2, and the Next Payload chain
    // produces one typed layer per payload — all reachable via the prelude.
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire)?;

    let header = decoded
        .layer::<IkeHeader>()
        .expect("decoded IKE header present");
    assert_eq!(header.exchange_type_value(), Some(IKE_SA_INIT));
    assert_eq!(header.initiator_spi_value(), Some(0x0102_0304_0506_0708));
    // The header's Next Payload names the first payload in the chain (SA, 33).
    assert_eq!(header.next_payload_value(), Some(PAYLOAD_SA));

    assert!(
        decoded.layer::<IkeSaPayload>().is_some(),
        "SA payload decodes"
    );
    assert!(
        decoded.layer::<IkeKePayload>().is_some(),
        "KE payload decodes"
    );
    assert!(
        decoded.layer::<IkeNoncePayload>().is_some(),
        "Nonce payload decodes"
    );

    // The decoded KE payload preserves the D-H group it was built with.
    let ke = decoded.layer::<IkeKePayload>().unwrap();
    assert_eq!(ke.dh_group_num(), DH_GROUP_MODP_2048);

    // Re-compiling the decoded packet reproduces the wire bytes exactly,
    // including the auto-filled IKE message length and Next Payload chain.
    let recompiled = decoded.compile()?;
    assert_eq!(recompiled.as_bytes(), wire.as_slice());
    Ok(())
}

// ===========================================================================
// End-to-end integration: ESP / AH / IKEv2 / NAT-T across transport + tunnel,
// driven entirely through `crafter::prelude::*`, including the public
// SA-carrying `ProtocolRegistry` decode path that verifies and decrypts.
// ===========================================================================

/// A 16-octet AES-128-GCM key (documentation-only, never a real key).
fn gcm_key() -> Vec<u8> {
    vec![0x24u8; 16]
}

/// The 4-octet AES-GCM salt (the implicit nonce prefix, RFC 4106).
fn gcm_salt() -> Vec<u8> {
    vec![0xA1, 0xB2, 0xC3, 0xD4]
}

/// A deterministic 8-octet explicit IV for AES-GCM (pinned so the sealed wire
/// bytes are stable and a re-compile reproduces them).
fn gcm_iv() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

/// A documentation IPv6 source / destination pair (`2001:db8::/32`).
const DOC6_SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const DOC6_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

/// Build an AES-GCM-16 (AEAD) transport-mode SA over the documentation SPI.
fn gcm_transport_sa(spi: u32) -> SecurityAssociation {
    SecurityAssociation::new(spi)
        .encryption(EncryptionAlgorithm::AesGcm16, gcm_key())
        .salt(gcm_salt())
        .transport()
        .extended_sequence(false)
}

/// Assert that no SA key, salt, or integrity-key byte run appears anywhere in a
/// rendered string. Keys are fixed repeated bytes, so a leak would surface as a
/// long repeated-hex run; spot-check the actual key/salt material directly too.
fn assert_no_key_material(rendered: &str) {
    let lowered = rendered.to_lowercase();
    // AES-GCM key is 0x24 repeated; HMAC key is 0x33 repeated; CBC key 0x11.
    for needle in ["24242424", "33333333", "11111111", "a1b2c3d4"] {
        assert!(
            !lowered.contains(needle),
            "rendered output leaked key/salt material ({needle}): {rendered}"
        );
    }
}

#[test]
fn esp_transport_aead_ipv4_decode_with_sa_recovers_inner() -> Result<()> {
    // ESP transport AEAD (AES-GCM) over IPv4: build, compile, then decode with
    // an SA-carrying registry. The SA-aware path verifies the AEAD tag, decrypts,
    // strips the trailer, and dispatches the inner TCP / Raw as typed layers.
    let spi = 0x0000_2100;
    let sa = gcm_transport_sa(spi);
    assert!(sa.validate().is_ok());

    let packet: Packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_ESP)
        / Esp::secured(sa.clone()).spi(spi).sequence(1).iv(gcm_iv())
        / Tcp::new().sport(40001).dport(443)
        / Raw::from("esp-gcm-v4");
    let wire = packet.compile()?.as_bytes().to_vec();
    assert_eq!(wire[9], IPPROTO_ESP);

    // The default SA-less registry keeps the body opaque.
    let opaque = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire)?;
    assert!(opaque.layer::<Esp>().unwrap().opaque_body().is_some());
    assert!(
        opaque.layer::<Tcp>().is_none(),
        "no SA: TCP stays encrypted"
    );

    // A registry carrying the SA decrypts and verifies, recovering inner layers.
    let registry = ProtocolRegistry::new().with_security_association(sa);
    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &wire)?;
    let esp = decoded.layer::<Esp>().expect("typed ESP recovered");
    assert_eq!(esp.spi_value(), Some(spi));
    let tcp = decoded.layer::<Tcp>().expect("inner TCP decrypted");
    assert_eq!(tcp.source_port_value(), 40001);
    assert_eq!(tcp.destination_port_value(), 443);
    assert_eq!(
        decoded
            .layer::<Raw>()
            .expect("inner Raw decrypted")
            .as_bytes(),
        b"esp-gcm-v4"
    );

    // No key material leaks through inspection of the decoded packet.
    assert_no_key_material(&decoded.summary());
    assert_no_key_material(&decoded.show());
    Ok(())
}

#[test]
fn esp_transport_aead_ipv6_decode_with_sa_recovers_inner() -> Result<()> {
    // The same AEAD transport case over IPv6: ESP is the IPv6 next-header (50).
    let spi = 0x0000_2600;
    let sa = gcm_transport_sa(spi);

    let packet: Packet = Ipv6::new()
        .src(DOC6_SRC)
        .dst(DOC6_DST)
        .nh(IPPROTO_IPV6_ESP)
        .hop_limit(64)
        / Esp::secured(sa.clone()).spi(spi).sequence(1).iv(gcm_iv())
        / Tcp::new().sport(50001).dport(8443)
        / Raw::from("esp-gcm-v6");
    let wire = packet.compile()?.as_bytes().to_vec();

    let registry = ProtocolRegistry::new().with_security_association(sa);
    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv6, &wire)?;
    assert_eq!(decoded.layer::<Esp>().unwrap().spi_value(), Some(spi));
    let tcp = decoded
        .layer::<Tcp>()
        .expect("inner TCP decrypted over IPv6");
    assert_eq!(tcp.source_port_value(), 50001);
    assert_eq!(
        decoded
            .layer::<Raw>()
            .expect("inner Raw decrypted")
            .as_bytes(),
        b"esp-gcm-v6"
    );
    assert_no_key_material(&decoded.show());
    Ok(())
}

#[test]
fn esp_tunnel_aead_decode_with_sa_recovers_inner_ip() -> Result<()> {
    // ESP tunnel mode (AEAD): the protected plaintext is a whole inner IPv4
    // datagram, so decode-with-SA recovers the inner IPv4 / Tcp stack.
    let spi = 0x0000_2700;
    let sa = SecurityAssociation::new(spi)
        .encryption(EncryptionAlgorithm::AesGcm16, gcm_key())
        .salt(gcm_salt())
        .tunnel();

    let inner_src = Ipv4Addr::new(192, 0, 2, 71);
    let inner_dst = Ipv4Addr::new(198, 51, 100, 72);
    let packet: Packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_ESP)
        / Esp::secured(sa.clone()).spi(spi).sequence(1).iv(gcm_iv())
        / Ipv4::new()
            .src(inner_src)
            .dst(inner_dst)
            .protocol(IPPROTO_TCP)
        / Tcp::new().sport(33000).dport(22)
        / Raw::from("esp-tunnel");
    let wire = packet.compile()?.as_bytes().to_vec();

    let registry = ProtocolRegistry::new().with_security_association(sa);
    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &wire)?;

    // Outer IPv4, the typed ESP, then the recovered inner IPv4 / Tcp.
    assert_eq!(decoded.layers::<Ipv4>().count(), 2, "outer + inner IPv4");
    let inner_ip = decoded
        .layers::<Ipv4>()
        .nth(1)
        .expect("inner IPv4 recovered");
    assert_eq!(inner_ip.source(), inner_src);
    assert_eq!(inner_ip.destination(), inner_dst);
    let tcp = decoded.layer::<Tcp>().expect("inner TCP decrypted");
    assert_eq!(tcp.destination_port_value(), 22);
    assert_no_key_material(&decoded.show());
    Ok(())
}

#[test]
fn esp_cbc_hmac_transport_decode_with_sa_recovers_inner() -> Result<()> {
    // ESP CBC + HMAC-SHA-256-128 transport: a separate-integrity suite. Decode
    // with the SA verifies the ICV (HMAC over aad||iv||ciphertext), decrypts the
    // CBC body, validates the RFC 4303 §2.4 monotonic pad, and recovers inner.
    let spi = 0x0000_2800;
    let cbc_key = vec![0x11u8; 16];
    let int_key = vec![0x33u8; 32];
    let sa = SecurityAssociation::new(spi)
        .encryption(EncryptionAlgorithm::AesCbc, cbc_key)
        .integrity(IntegrityAlgorithm::HmacSha2_256_128, int_key)
        .transport();
    assert!(sa.validate().is_ok());

    let cbc_iv: Vec<u8> = (0u8..16).collect();
    let packet: Packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_ESP)
        / Esp::secured(sa.clone()).spi(spi).sequence(1).iv(cbc_iv)
        / Tcp::new().sport(41000).dport(443)
        / Raw::from("esp-cbc-hmac");
    let wire = packet.compile()?.as_bytes().to_vec();

    let registry = ProtocolRegistry::new().with_security_association(sa);
    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &wire)?;
    let tcp = decoded.layer::<Tcp>().expect("inner TCP decrypted (CBC)");
    assert_eq!(tcp.source_port_value(), 41000);
    assert_eq!(
        decoded
            .layer::<Raw>()
            .expect("inner Raw decrypted")
            .as_bytes(),
        b"esp-cbc-hmac"
    );
    assert_no_key_material(&decoded.show());
    Ok(())
}

#[test]
fn esp_opaque_no_sa_round_trips() -> Result<()> {
    // ESP without any SA in the registry: the encrypted body is preserved
    // verbatim and the decoded packet re-compiles byte-for-byte.
    let spi = 0x0000_2900;
    let sa = gcm_transport_sa(spi);
    let packet: Packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_ESP)
        / Esp::secured(sa).spi(spi).sequence(1).iv(gcm_iv())
        / Tcp::new().sport(42000).dport(443)
        / Raw::from("esp-opaque");
    let wire = packet.compile()?.as_bytes().to_vec();

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire)?;
    let esp = decoded.layer::<Esp>().expect("typed ESP header");
    assert_eq!(esp.spi_value(), Some(spi));
    assert!(esp.opaque_body().is_some(), "no-SA body stays opaque");
    assert!(decoded.layer::<Tcp>().is_none(), "TCP stays sealed");
    assert_eq!(decoded.compile()?.as_bytes(), wire.as_slice());
    Ok(())
}

/// Build an integrity-only HMAC-SHA-256-128 AH SA in the requested mode.
fn ah_hmac_sa(spi: u32, tunnel: bool) -> SecurityAssociation {
    let sa = SecurityAssociation::new(spi)
        .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key())
        .extended_sequence(false);
    if tunnel {
        sa.tunnel()
    } else {
        sa.transport()
    }
}

#[test]
fn ah_transport_ipv4_decode_with_sa_verifies() -> Result<()> {
    // AH transport over IPv4 with HMAC-SHA-256-128: decode with the SA verifies
    // the ICV over the canonicalized IP header, the zeroed AH header, and the
    // cleartext upper layer, recording a verified status.
    let spi = 0x0000_3100;
    let sa = ah_hmac_sa(spi, false);
    let packet: Packet = Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_DST)
        .protocol(IPPROTO_AH)
        .ttl(64)
        / Ah::secured(sa.clone()).spi(spi).sequence(1)
        / Tcp::new().sport(43000).dport(443)
        / Raw::from("ah-v4");
    let wire = packet.compile()?.as_bytes().to_vec();
    assert_eq!(wire[9], IPPROTO_AH);

    // Default registry: AH decodes opaque (no verification status).
    let opaque = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire)?;
    assert_eq!(opaque.layer::<Ah>().unwrap().verification_status(), None);

    // SA registry: the ICV verifies and the verified status is recorded.
    let registry = ProtocolRegistry::new().with_security_association(sa);
    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &wire)?;
    let ah = decoded.layer::<Ah>().expect("typed AH recovered");
    assert_eq!(ah.spi_value(), Some(spi));
    assert_eq!(
        ah.verification_status(),
        Some(true),
        "matching SA verifies the AH ICV"
    );
    assert!(decoded.layer::<Tcp>().is_some(), "inner TCP in the clear");
    assert_no_key_material(&decoded.show());
    Ok(())
}

#[test]
fn ah_tunnel_ipv4_decode_with_sa_verifies() -> Result<()> {
    // AH tunnel over IPv4: the protected data is an inner IPv4 datagram; decode
    // with the SA verifies and recovers the nested inner IPv4 / Tcp.
    let spi = 0x0000_3200;
    let sa = ah_hmac_sa(spi, true);
    let inner_src = Ipv4Addr::new(192, 0, 2, 81);
    let inner_dst = Ipv4Addr::new(198, 51, 100, 82);
    let packet: Packet = Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_DST)
        .protocol(IPPROTO_AH)
        .ttl(64)
        / Ah::secured(sa.clone()).spi(spi).sequence(1)
        / Ipv4::new()
            .src(inner_src)
            .dst(inner_dst)
            .protocol(IPPROTO_TCP)
        / Tcp::new().sport(44000).dport(22)
        / Raw::from("ah-tunnel-v4");
    let wire = packet.compile()?.as_bytes().to_vec();

    let registry = ProtocolRegistry::new().with_security_association(sa);
    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &wire)?;
    let ah = decoded.layer::<Ah>().expect("typed AH recovered");
    assert_eq!(ah.next_header_value(), Some(4), "AH NH is IPv4-in-IPv4");
    assert_eq!(ah.verification_status(), Some(true));
    assert_eq!(decoded.layers::<Ipv4>().count(), 2, "outer + inner IPv4");
    assert!(decoded.layer::<Tcp>().is_some());
    Ok(())
}

#[test]
fn ah_transport_ipv6_decode_with_sa_verifies() -> Result<()> {
    // AH transport over IPv6 with HMAC-SHA-256-128 verify.
    let spi = 0x0000_3300;
    let sa = ah_hmac_sa(spi, false);
    let packet: Packet = Ipv6::new()
        .src(DOC6_SRC)
        .dst(DOC6_DST)
        .nh(IPPROTO_IPV6_AH)
        .hop_limit(64)
        / Ah::secured(sa.clone()).spi(spi).sequence(1)
        / Tcp::new().sport(45000).dport(443)
        / Raw::from("ah-v6");
    let wire = packet.compile()?.as_bytes().to_vec();

    let registry = ProtocolRegistry::new().with_security_association(sa);
    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv6, &wire)?;
    let ah = decoded.layer::<Ah>().expect("typed AH recovered over IPv6");
    assert_eq!(ah.spi_value(), Some(spi));
    assert_eq!(ah.verification_status(), Some(true));
    assert!(decoded.layer::<Tcp>().is_some());
    assert_no_key_material(&decoded.show());
    Ok(())
}

#[test]
fn ah_tunnel_ipv6_decode_with_sa_verifies() -> Result<()> {
    // AH tunnel over IPv6: protected data is an inner IPv6 datagram (NH 41).
    let spi = 0x0000_3400;
    let sa = ah_hmac_sa(spi, true);
    let inner_src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x11);
    let inner_dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x12);
    let packet: Packet = Ipv6::new()
        .src(DOC6_SRC)
        .dst(DOC6_DST)
        .nh(IPPROTO_IPV6_AH)
        .hop_limit(64)
        / Ah::secured(sa.clone()).spi(spi).sequence(1)
        / Ipv6::new()
            .src(inner_src)
            .dst(inner_dst)
            .nh(IPPROTO_TCP)
            .hop_limit(64)
        / Tcp::new().sport(46000).dport(22)
        / Raw::from("ah-tunnel-v6");
    let wire = packet.compile()?.as_bytes().to_vec();

    let registry = ProtocolRegistry::new().with_security_association(sa);
    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv6, &wire)?;
    let ah = decoded.layer::<Ah>().expect("typed AH recovered");
    assert_eq!(ah.next_header_value(), Some(IPPROTO_IPV6), "AH NH is IPv6");
    assert_eq!(ah.verification_status(), Some(true));
    assert_eq!(decoded.layers::<Ipv6>().count(), 2, "outer + inner IPv6");
    assert!(decoded.layer::<Tcp>().is_some());
    Ok(())
}

#[test]
fn ah_decode_with_sa_detects_tampered_payload() -> Result<()> {
    // A one-bit change to the protected upper-layer data must fail the SA-aware
    // AH verification: the decode fails closed with a structured error.
    let spi = 0x0000_3500;
    let sa = ah_hmac_sa(spi, false);
    let packet: Packet = Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_DST)
        .protocol(IPPROTO_AH)
        .ttl(64)
        / Ah::secured(sa.clone()).spi(spi).sequence(1)
        / Tcp::new().sport(47000).dport(443)
        / Raw::from("ah-tamper");
    let mut wire = packet.compile()?.as_bytes().to_vec();
    // Flip the last payload byte (well past the AH header + ICV).
    *wire.last_mut().unwrap() ^= 0x01;

    let registry = ProtocolRegistry::new().with_security_association(sa);
    let err = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &wire)
        .expect_err("a tampered payload byte must fail AH verification");
    assert!(
        matches!(err, CrafterError::InvalidFieldValue { field, .. } if field == "ipsec.ah.icv"),
        "expected an ICV mismatch error, got {err:?}"
    );
    Ok(())
}

#[test]
fn ike_auth_with_sk_payload_round_trips() -> Result<()> {
    // IKE_AUTH carrying an Encrypted (SK) payload. The SK payload owns its inner
    // payload chain and seals it under an AEAD SA. The default SA-less registry
    // decodes the SK body opaquely, but the whole message re-compiles byte-exact.
    let sk_sa = SecurityAssociation::new(0x0000_4400)
        .encryption(EncryptionAlgorithm::AesGcm16, gcm_key())
        .salt(gcm_salt());

    let id = IkeIdPayload::initiator_ipv4(Ipv4Addr::new(192, 0, 2, 10));
    let auth = IkeAuthPayload::new(AuthMethod::SharedKeyMic, vec![0x9Au8; 8]);
    let sk = IkeEncryptedPayload::new(sk_sa)
        .iv(gcm_iv())
        .payload(id)
        .payload(auth);

    let header = IkeHeader::new()
        .initiator_spi(0x1122_3344_5566_7788)
        .responder_spi(0x99AA_BBCC_DDEE_FF00)
        .exchange(IKE_AUTH)
        .initiator();

    let packet: Packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_UDP)
        / Udp::new().sport(IKE_UDP_PORT).dport(IKE_UDP_PORT)
        / header
        / sk;
    let wire = packet.compile()?.as_bytes().to_vec();
    assert_eq!(wire[9], IPPROTO_UDP);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire)?;
    let hdr = decoded.layer::<IkeHeader>().expect("IKE header decoded");
    assert_eq!(hdr.exchange_type_value(), Some(IKE_AUTH));
    assert_eq!(hdr.next_payload_value(), Some(PAYLOAD_SK));

    // The whole IKE_AUTH message re-compiles byte-for-byte (SK body opaque).
    assert_eq!(decoded.compile()?.as_bytes(), wire.as_slice());
    // No SK key material leaks through inspection of the built packet.
    assert_no_key_material(&packet.summary());
    assert_no_key_material(&packet.show());
    Ok(())
}

#[test]
fn natt_udp_4500_esp_decode_with_sa_recovers_inner() -> Result<()> {
    // NAT-T: UDP/4500 carrying a UDP-encapsulated ESP datagram (no marker). The
    // SA-carrying registry decrypts the encapsulated ESP and recovers inner TCP.
    let spi = 0x0000_4500;
    let sa = gcm_transport_sa(spi);
    let packet: Packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_UDP)
        / Udp::new().sport(4500).dport(4500)
        / Esp::secured(sa.clone()).spi(spi).sequence(1).iv(gcm_iv())
        / Tcp::new().sport(48000).dport(443)
        / Raw::from("natt-esp");
    let wire = packet.compile()?.as_bytes().to_vec();

    let registry = ProtocolRegistry::new().with_security_association(sa);
    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &wire)?;
    // UDP-encapsulated ESP: a typed Udp, the ESP, then the decrypted inner TCP.
    assert!(decoded.layer::<Udp>().is_some(), "outer UDP/4500");
    assert_eq!(decoded.layer::<Esp>().unwrap().spi_value(), Some(spi));
    let tcp = decoded
        .layer::<Tcp>()
        .expect("inner TCP decrypted under NAT-T");
    assert_eq!(tcp.source_port_value(), 48000);
    assert_eq!(
        decoded.layer::<Raw>().expect("inner Raw").as_bytes(),
        b"natt-esp"
    );
    Ok(())
}

#[test]
fn natt_udp_4500_ike_with_marker_round_trips() -> Result<()> {
    // NAT-T: UDP/4500 carrying an IKE message disambiguated by the four-octet
    // non-ESP marker (RFC 3948 §2.2). The marker decodes as a typed NatTraversal
    // layer and the IKE message follows; the datagram re-compiles byte-exact.
    let proposal = Proposal::new(1, PROTOCOL_ID_IKE)
        .with_transform(Transform::new(TRANSFORM_TYPE_ENCR, 20))
        .with_transform(Transform::new(TRANSFORM_TYPE_DH, DH_GROUP_MODP_2048));
    let ike_sa = IkeSaPayload::new().with_proposal(proposal);
    let ke = IkeKePayload::new(DH_GROUP_MODP_2048, vec![0xAB; 32]);
    let ni = IkeNoncePayload::new(vec![0x5A; 16]);
    let header = IkeHeader::new()
        .initiator_spi(0x0102_0304_0506_0708)
        .exchange(IKE_SA_INIT)
        .initiator();

    let packet: Packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_UDP)
        / Udp::new().sport(4500).dport(4500)
        / non_esp_marker()
        / header
        / ike_sa
        / ke
        / ni;
    let wire = packet.compile()?.as_bytes().to_vec();
    // The IKE message (after the 8-octet UDP header) begins with the 4-zero
    // non-ESP marker, then the IKE header's initiator SPI.
    assert_eq!(&wire[28..32], &[0, 0, 0, 0], "non-ESP marker present");

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire)?;
    assert!(
        decoded.layer::<NatTraversal>().is_some(),
        "marker decodes as a typed NatTraversal layer"
    );
    let hdr = decoded
        .layer::<IkeHeader>()
        .expect("IKE header after marker");
    assert_eq!(hdr.exchange_type_value(), Some(IKE_SA_INIT));
    assert!(decoded.layer::<IkeSaPayload>().is_some());
    assert!(decoded.layer::<IkeKePayload>().is_some());
    assert!(decoded.layer::<IkeNoncePayload>().is_some());

    // The marker + IKE message re-compiles byte-for-byte.
    assert_eq!(decoded.compile()?.as_bytes(), wire.as_slice());
    Ok(())
}
