//! libcrafter side of the cross-crypto IPSec behavioral parity (interop) check.
//!
//! This binary is the deterministic, network-free libcrafter half of the
//! IPSec OPEN-direction interop check wired into the probe `ipsec` profile.
//! Step 54-56 (oracle) already prove that libcrafter-sealed ESP/AH bytes equal
//! Scapy-sealed bytes (byte parity). This step proves the *open* direction:
//! each implementation can consume the packet the other sealed.
//!
//! It reads a JSON request on stdin describing a list of operations, each one
//! of two kinds, and emits a JSON response on stdout:
//!
//! * `seal` — build an ESP / AH / IKE SK packet with the public
//!   `crafter::prelude` API from the pinned key/IV/SPI material and the
//!   documentation addresses in the request, compile it, and return the wire
//!   bytes (and the recovered plaintext libcrafter itself decodes back, as a
//!   self-check). The Python harness then opens these bytes with Scapy's
//!   `SecurityAssociation.decrypt` and asserts the recovered plaintext matches.
//! * `open` — decode Scapy-sealed wire bytes from L3 with a SA-carrying
//!   `ProtocolRegistry` (the public step-48 SA-decode API) and return the
//!   recovered inner plaintext. The harness asserts it matches what Scapy
//!   sealed, and that a tampered packet fails open with a structured error
//!   rather than a panic or a silently wrong plaintext.
//!
//! Everything here uses documentation address space (`192.0.2.0/24`,
//! `198.51.100.0/24`, `2001:db8::/32`) and caller-pinned keys; there are no
//! sockets, no provider, and no live traffic.

use std::error::Error;
use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;
use crafter::protocols::ipsec::ikev2::payload::encrypted::decode_sk_payload_with_sa;
use serde::Deserialize;
use serde_json::{json, Value};

type InteropResult<T> = std::result::Result<T, Box<dyn Error>>;

/// The pinned crypto material and exchange shape for one interop operation.
///
/// Both the `seal` and `open` kinds share this shape: the pinned SPI, sequence,
/// suite, key/salt/IV material (hex), mode, and the documentation addresses and
/// inner plaintext. `seal` builds the packet from it; `open` rebuilds the
/// matching SA to decode the Scapy-sealed `wire_hex`.
#[derive(Debug, Deserialize)]
struct Operation {
    /// Stable identifier echoed back so the harness can match results.
    name: String,
    /// `"seal"` (libcrafter builds) or `"open"` (libcrafter decodes).
    kind: String,
    /// `"esp"`, `"ah"`, or `"sk"` (the IKEv2 Encrypted payload).
    protocol: String,
    /// IANA-style suite label: `aes-gcm`, `aes-cbc-hmac`, `chacha20-poly1305`,
    /// or `hmac-sha2-256-128` (AH integrity-only).
    suite: String,
    /// `"transport"` or `"tunnel"` (ESP/AH only).
    #[serde(default = "default_mode")]
    mode: String,
    spi: u32,
    #[serde(default = "default_sequence")]
    sequence: u32,
    /// Hex-encoded encryption key (empty for AH integrity-only).
    #[serde(default)]
    enc_key_hex: String,
    /// Hex-encoded AEAD/CTR salt (the implicit nonce prefix).
    #[serde(default)]
    salt_hex: String,
    /// Hex-encoded explicit IV (8 octets AEAD / 16 octets CBC).
    #[serde(default)]
    iv_hex: String,
    /// Hex-encoded integrity key (CBC+HMAC and AH).
    #[serde(default)]
    integ_key_hex: String,
    /// Documentation IP version: `"ipv4"` or `"ipv6"`.
    #[serde(default = "default_ip_version")]
    ip_version: String,
    /// Documentation source / destination addresses (outer header).
    source: String,
    destination: String,
    /// Inner upper-layer plaintext payload (ASCII) carried after a TCP header
    /// (transport / SK) or inside the inner IP datagram (tunnel).
    payload: String,
    /// For `open`: the Scapy-sealed wire bytes to decode.
    #[serde(default)]
    wire_hex: String,
}

fn default_mode() -> String {
    "transport".to_string()
}

fn default_sequence() -> u32 {
    1
}

fn default_ip_version() -> String {
    "ipv4".to_string()
}

const INNER_SRC_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 71);
const INNER_DST_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 72);
const INNER_SRC_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x71);
const INNER_DST_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x72);
const INNER_SPORT: u16 = 40001;
const INNER_DPORT: u16 = 443;

fn main() -> InteropResult<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: Value = serde_json::from_str(&input)?;
    let operations: Vec<Operation> = match request.get("operations") {
        Some(value) => serde_json::from_value(value.clone())?,
        None => serde_json::from_value(request)?,
    };

    let mut results = Vec::with_capacity(operations.len());
    for operation in &operations {
        results.push(run_operation(operation));
    }

    let ok = results
        .iter()
        .all(|result| result.get("ok").and_then(Value::as_bool).unwrap_or(false));
    let report = json!({
        "backend": "libcrafter",
        "libcrafter_version": env!("CARGO_PKG_VERSION"),
        "ok": ok,
        "count": results.len(),
        "results": results,
    });
    serde_json::to_writer_pretty(io::stdout(), &report)?;
    println!();
    Ok(())
}

/// Run one interop operation, capturing any error into the per-op result rather
/// than aborting the whole batch — a single failing suite must surface as a
/// structured, inspectable failure, not a process crash.
fn run_operation(operation: &Operation) -> Value {
    let outcome = match operation.kind.as_str() {
        "seal" => seal_operation(operation),
        "open" => open_operation(operation),
        other => Err(format!("unknown interop op kind {other:?}").into()),
    };
    match outcome {
        Ok(mut value) => {
            value["name"] = json!(operation.name);
            value["kind"] = json!(operation.kind);
            value["protocol"] = json!(operation.protocol);
            value["suite"] = json!(operation.suite);
            value["ok"] = json!(true);
            value
        }
        Err(error) => json!({
            "name": operation.name,
            "kind": operation.kind,
            "protocol": operation.protocol,
            "suite": operation.suite,
            "ok": false,
            "error": error.to_string(),
        }),
    }
}

/// Build the requested packet with libcrafter and return its wire bytes plus the
/// plaintext libcrafter recovers from its own output (the self-check), so the
/// Python harness can confirm Scapy recovers the identical plaintext.
fn seal_operation(operation: &Operation) -> InteropResult<Value> {
    let payload = operation.payload.as_bytes().to_vec();
    let (wire, network_layer, sa) = match operation.protocol.as_str() {
        "esp" => build_esp_packet(operation)?,
        "ah" => build_ah_packet(operation)?,
        "sk" => {
            // The IKE SK payload owns its inner chain. The seal direction emits
            // the whole UDP/500 IKE message *and* the standalone SK payload bytes
            // (generic header + IV || ciphertext || ICV), then opens the SK with
            // the public SA-decode API and recovers the inner Nonce data — the
            // self-check half. The harness opens the same SK body with the
            // reference AEAD (pyca/cryptography, the primitive Scapy itself uses).
            let (wire, sk_payload, sa) = build_sk_message(operation)?;
            let recovered = recover_sk_nonce(&sk_payload, &sa)?;
            return Ok(json!({
                "wire_hex": hex(&wire),
                "sk_payload_hex": hex(&sk_payload),
                "recovered_payload_hex": hex(&recovered),
                "recovered_matches": recovered == payload,
            }));
        }
        other => return Err(format!("unknown interop protocol {other:?}").into()),
    };

    // Self-check: libcrafter decodes its own sealed bytes with the SA and
    // recovers the inner plaintext. This is the libcrafter-internal half; the
    // cross-crypto assertion (Scapy opens these bytes) lives in the harness.
    let recovered = recover_inner_payload(operation, &wire, network_layer, &sa)?;
    Ok(json!({
        "wire_hex": hex(&wire),
        "recovered_payload_hex": hex(&recovered),
        "recovered_matches": recovered == payload,
    }))
}

/// Decode Scapy-sealed wire bytes with the SA-carrying registry and return the
/// recovered inner plaintext. A tampered packet fails here with a structured
/// `CrafterError`, which the harness asserts as fail-closed tamper detection.
fn open_operation(operation: &Operation) -> InteropResult<Value> {
    let wire = decode_hex(&operation.wire_hex)?;
    let network_layer = network_layer(operation)?;
    let sa = build_sa(operation)?;
    match operation.protocol.as_str() {
        "esp" | "ah" => {
            let recovered = recover_inner_payload(operation, &wire, network_layer, &sa)?;
            Ok(json!({
                "recovered_payload_hex": hex(&recovered),
                "recovered_matches": recovered == operation.payload.as_bytes(),
            }))
        }
        "sk" => {
            // `wire_hex` carries the standalone SK payload (generic header + body)
            // the reference sealed; open it with the public SA-decode API.
            let recovered = recover_sk_nonce(&wire, &sa)?;
            Ok(json!({
                "recovered_payload_hex": hex(&recovered),
                "recovered_matches": recovered == operation.payload.as_bytes(),
            }))
        }
        other => Err(format!("unknown interop protocol {other:?}").into()),
    }
}

/// Build the `SecurityAssociation` for an operation from its pinned material.
fn build_sa(operation: &Operation) -> InteropResult<SecurityAssociation> {
    let mut sa = SecurityAssociation::new(operation.spi);
    sa = match operation.suite.as_str() {
        "aes-gcm" => sa
            .encryption(
                EncryptionAlgorithm::AesGcm16,
                decode_hex(&operation.enc_key_hex)?,
            )
            .salt(decode_hex(&operation.salt_hex)?),
        "chacha20-poly1305" => sa
            .encryption(
                EncryptionAlgorithm::ChaCha20Poly1305,
                decode_hex(&operation.enc_key_hex)?,
            )
            .salt(decode_hex(&operation.salt_hex)?),
        "aes-cbc-hmac" => sa
            .encryption(
                EncryptionAlgorithm::AesCbc,
                decode_hex(&operation.enc_key_hex)?,
            )
            .integrity(
                IntegrityAlgorithm::HmacSha2_256_128,
                decode_hex(&operation.integ_key_hex)?,
            ),
        "hmac-sha2-256-128" => sa.integrity(
            IntegrityAlgorithm::HmacSha2_256_128,
            decode_hex(&operation.integ_key_hex)?,
        ),
        other => return Err(format!("unknown interop suite {other:?}").into()),
    };
    sa = if operation.mode == "tunnel" {
        sa.tunnel()
    } else {
        sa.transport()
    };
    Ok(sa)
}

/// Build a compiled ESP packet (transport: IP/ESP/TCP/Raw, tunnel: IP/ESP/innerIP/TCP/Raw).
fn build_esp_packet(
    operation: &Operation,
) -> InteropResult<(Vec<u8>, NetworkLayer, SecurityAssociation)> {
    let sa = build_sa(operation)?;
    let network_layer = network_layer(operation)?;
    let esp = Esp::secured(sa.clone())
        .spi(operation.spi)
        .sequence(operation.sequence)
        .iv(decode_hex(&operation.iv_hex)?);
    let mut packet = Packet::new().push_box(outer_ip(operation, IPPROTO_ESP)?);
    packet = packet.push(esp);
    packet = push_inner_chain(packet, operation);
    let wire = packet.compile()?.as_bytes().to_vec();
    Ok((wire, network_layer, sa))
}

/// Build a compiled AH packet (integrity-only; the inner data travels cleartext).
fn build_ah_packet(
    operation: &Operation,
) -> InteropResult<(Vec<u8>, NetworkLayer, SecurityAssociation)> {
    let sa = build_sa(operation)?;
    let network_layer = network_layer(operation)?;
    let ah = Ah::secured(sa.clone())
        .spi(operation.spi)
        .sequence(operation.sequence);
    let mut packet = Packet::new().push_box(outer_ip(operation, IPPROTO_AH)?);
    packet = packet.push(ah);
    packet = push_inner_chain(packet, operation);
    let wire = packet.compile()?.as_bytes().to_vec();
    Ok((wire, network_layer, sa))
}

/// Build a compiled IKE_AUTH message carrying an SK (Encrypted) payload that
/// seals a single inner Nonce payload whose data is the interop plaintext.
///
/// Returns the full IKE message wire bytes and the standalone SK payload bytes
/// (generic header + `IV || ciphertext || ICV`), the unit the reference crypto
/// opens.
fn build_sk_message(
    operation: &Operation,
) -> InteropResult<(Vec<u8>, Vec<u8>, SecurityAssociation)> {
    let sa = build_sa(operation)?;
    let inner = IkeNoncePayload::new(operation.payload.as_bytes().to_vec());
    let sk = IkeEncryptedPayload::new(sa.clone())
        .iv(decode_hex(&operation.iv_hex)?)
        .payload(inner);
    let header = IkeHeader::new()
        .initiator_spi(0x0102_0304_0506_0708)
        .responder_spi(0x1112_1314_1516_1718)
        .exchange(IKE_AUTH)
        .initiator();
    let src: Ipv4Addr = operation.source.parse()?;
    let dst: Ipv4Addr = operation.destination.parse()?;
    let packet = Packet::new()
        .push(Ipv4::new().src(src).dst(dst).protocol(IPPROTO_UDP))
        .push(Udp::new().sport(500).dport(500))
        .push(header)
        .push(sk);
    let wire = packet.compile()?.as_bytes().to_vec();

    // The SK payload is the whole IKE message body after the 28-octet header.
    // Decode opaquely (no SA) so the SK payload surfaces as a preserved Raw, and
    // return its exact bytes for the standalone reference open.
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire)?;
    let sk_payload = decoded
        .layer::<Raw>()
        .ok_or("SK message did not preserve the SK payload as opaque bytes")?
        .as_bytes()
        .to_vec();
    Ok((wire, sk_payload, sa))
}

/// Decode ESP/AH wire bytes with the SA registry and return the inner plaintext
/// (the bytes after the inner TCP header).
fn recover_inner_payload(
    operation: &Operation,
    wire: &[u8],
    network_layer: NetworkLayer,
    sa: &SecurityAssociation,
) -> InteropResult<Vec<u8>> {
    let registry = ProtocolRegistry::new().with_security_association(sa.clone());
    let decoded = Packet::decode_from_l3_with_registry(&registry, network_layer, wire)?;
    let raw = decoded
        .layer::<Raw>()
        .ok_or_else(|| format!("{}: no recovered inner Raw payload", operation.name))?;
    Ok(raw.as_bytes().to_vec())
}

/// Open a standalone SK payload (generic header + body) with the public
/// SA-decode API and return the inner Nonce payload's data (the interop
/// plaintext sealed inside the SK payload).
///
/// `decode_sk_payload_with_sa` verifies the ICV in constant time, decrypts, and
/// strips the pad, returning the decrypted inner IKE payload chain. The single
/// inner payload here is a Nonce (4-octet generic header + nonce data), so the
/// recovered plaintext is the bytes after that header. A tampered SK body fails
/// with a structured `CrafterError`, never a panic or wrong plaintext.
fn recover_sk_nonce(sk_payload: &[u8], sa: &SecurityAssociation) -> InteropResult<Vec<u8>> {
    let decoded = decode_sk_payload_with_sa(sk_payload, sa)?;
    let inner = &decoded.inner_payloads;
    // The inner chain is a single Nonce payload: 4-octet generic header then the
    // nonce data (RFC 7296 §3.9 / §3.2).
    const GENERIC_PAYLOAD_HEADER_LEN: usize = 4;
    if inner.len() < GENERIC_PAYLOAD_HEADER_LEN {
        return Err("recovered SK inner chain is shorter than one generic header".into());
    }
    Ok(inner[GENERIC_PAYLOAD_HEADER_LEN..].to_vec())
}

/// Build the outer IP header advertising the IPSec protocol number.
fn outer_ip(operation: &Operation, protocol: u8) -> InteropResult<Box<dyn Layer>> {
    match operation.ip_version.as_str() {
        "ipv4" => {
            let src: Ipv4Addr = operation.source.parse()?;
            let dst: Ipv4Addr = operation.destination.parse()?;
            Ok(Box::new(
                Ipv4::new().src(src).dst(dst).protocol(protocol).ttl(64),
            ))
        }
        "ipv6" => {
            let src: Ipv6Addr = operation.source.parse()?;
            let dst: Ipv6Addr = operation.destination.parse()?;
            let nh = if protocol == IPPROTO_ESP {
                IPPROTO_IPV6_ESP
            } else {
                IPPROTO_IPV6_AH
            };
            Ok(Box::new(Ipv6::new().src(src).dst(dst).nh(nh).hop_limit(64)))
        }
        other => Err(format!("unknown ip version {other:?}").into()),
    }
}

/// Push the inner cleartext chain that the SA protects onto `packet`: transport
/// mode carries TCP / Raw directly; tunnel mode wraps it in an inner IP datagram.
fn push_inner_chain(packet: Packet, operation: &Operation) -> Packet {
    let tcp = Tcp::new().sport(INNER_SPORT).dport(INNER_DPORT);
    let raw = Raw::from(operation.payload.as_bytes().to_vec());
    let mut packet = packet;
    if operation.mode == "tunnel" {
        packet = match operation.ip_version.as_str() {
            "ipv6" => packet.push(
                Ipv6::new()
                    .src(INNER_SRC_V6)
                    .dst(INNER_DST_V6)
                    .nh(IPPROTO_TCP)
                    .hop_limit(64),
            ),
            _ => packet.push(
                Ipv4::new()
                    .src(INNER_SRC_V4)
                    .dst(INNER_DST_V4)
                    .protocol(IPPROTO_TCP)
                    .ttl(64),
            ),
        };
    }
    packet.push(tcp).push(raw)
}

fn network_layer(operation: &Operation) -> InteropResult<NetworkLayer> {
    match operation.ip_version.as_str() {
        "ipv4" => Ok(NetworkLayer::Ipv4),
        "ipv6" => Ok(NetworkLayer::Ipv6),
        other => Err(format!("unknown ip version {other:?}").into()),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn decode_hex(hex: &str) -> InteropResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err("hex input must have an even number of characters".into());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        out.push(u8::from_str_radix(&hex[index..index + 2], 16)?);
    }
    Ok(out)
}
