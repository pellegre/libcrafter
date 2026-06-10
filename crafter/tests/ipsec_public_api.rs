//! Public-surface baseline tests for the ESP, AH, and IKEv2 (IPSec) layers.
//!
//! These tests confirm that the ESP and AH layers, the `SecurityAssociation`
//! crypto context, the `IpsecMode`/`EncryptionAlgorithm`/`IntegrityAlgorithm`
//! enums, the ESP/AH wire constants, and the IKEv2 message header, payload set,
//! and codepoints are all reachable through `crafter::prelude::*`, and that a
//! prelude-only tool can build, compile, and decode ESP, AH, and IKEv2 packets.
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
