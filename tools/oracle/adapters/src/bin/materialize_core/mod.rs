// Shared packet/DNS materializer used by BOTH the `materialize_plans` bin (the
// offline oracle vector generator) and the `live_endpoint` bin (the on-endpoint
// live sender/receiver). One source of truth prevents the live endpoint from
// drifting behind the offline materializer. Some items are used by only one bin,
// so dead code is allowed module-wide.
#![allow(dead_code)]

use crafter::prelude::*;
use crafter::protocols::bgp::attribute::{decode_attribute, BgpPathAttribute, BgpPrefix};
use crafter::protocols::bgp::{
    BgpOptParam, AFI_IPV4, AFI_IPV6, ATTR_AGGREGATOR, ATTR_AS4_AGGREGATOR, ATTR_AS4_PATH,
    ATTR_AS_PATH, ATTR_ATOMIC_AGGREGATE, ATTR_COMMUNITIES, ATTR_EXTENDED_COMMUNITIES,
    ATTR_LARGE_COMMUNITY, ATTR_LOCAL_PREF, ATTR_MP_REACH_NLRI, ATTR_MP_UNREACH_NLRI,
    ATTR_MULTI_EXIT_DISC, ATTR_NEXT_HOP, ATTR_ORIGIN, BGP_MARKER_LEN, BGP_PORT, BGP_TYPE_KEEPALIVE,
    BGP_TYPE_NOTIFICATION, BGP_TYPE_OPEN, BGP_TYPE_ROUTE_REFRESH, BGP_TYPE_UPDATE, CAP_ADD_PATH,
    CAP_ENHANCED_ROUTE_REFRESH, CAP_FOUR_OCTET_AS, CAP_GRACEFUL_RESTART, CAP_MULTIPROTOCOL,
    CAP_ROUTE_REFRESH, CAP_ROUTE_REFRESH_OLD, SAFI_MULTICAST, SAFI_UNICAST,
};
use crafter::protocols::igmp::{IgmpExtension, IGMP_ALL_ROUTERS_GROUP, IGMP_ALL_SYSTEMS_GROUP};
use crafter::protocols::link::{RadiotapChannel, RadiotapFlags, RadiotapRxFlags, RadiotapTxFlags};
use crafter::protocols::rip::ripng::{Ripng, RipngRte};
use crafter::protocols::rip::{RipAuth, RipDigestAlgorithm};
use serde_json::{json, Map, Value};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;

pub type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

const BACKEND_NAME: &str = "libcrafter";

#[derive(Debug)]
struct Args {
    input: Option<PathBuf>,
}

pub fn main() -> ExampleResult<()> {
    let args = parse_args()?;
    let input = read_input(args.input)?;
    let document: Value = serde_json::from_str(&input)?;
    let plans = extract_plans(&document)?;
    let mut vectors = Vec::with_capacity(plans.len());

    for plan in plans {
        vectors.push(materialize_plan(plan)?);
    }

    let report = json!({
        "artifacts": [],
        "artifact_paths": [],
        "backend": BACKEND_NAME,
        "backend_versions": {},
        "count": vectors.len(),
        "failures": [],
        "libcrafter": {
            "version": env!("CARGO_PKG_VERSION")
        },
        "metadata": {
            "direction": document.pointer("/metadata/direction").cloned().unwrap_or(Value::Null),
            "requested_count": document.pointer("/metadata/requested_count").cloned().unwrap_or(Value::Null),
            "vector_backend": BACKEND_NAME,
            "vectors": vectors
        },
        "mode": document.get("mode").cloned().unwrap_or_else(|| Value::String("offline".to_string())),
        "profile": document.get("profile").cloned().unwrap_or(Value::Null),
        "reproduction_commands": [],
        "results": [],
        "seed": document.get("seed").cloned().unwrap_or(Value::Null),
        "selected_specs": document.get("selected_specs").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "status": "vectors"
    });

    serde_json::to_writer_pretty(io::stdout(), &report)?;
    println!();
    Ok(())
}

fn parse_args() -> ExampleResult<Args> {
    let mut input = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--input" => {
                let value = args.next().ok_or("--input requires a path or -")?;
                input = input_path(value);
            }
            _ if arg.starts_with("--input=") => {
                let value = arg
                    .strip_prefix("--input=")
                    .expect("--input= prefix already matched");
                input = input_path(value.to_string());
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    Ok(Args { input })
}

fn input_path(value: String) -> Option<PathBuf> {
    if value == "-" {
        None
    } else {
        Some(PathBuf::from(value))
    }
}

fn print_usage() {
    println!(
        "usage: cargo run -p oracle-adapters --bin materialize_plans -- [--input PATH|-]\n\nMaterialize oracle packet plans with libcrafter and emit raw vector JSON. Reads stdin when --input is omitted or set to -."
    );
}

fn read_input(input: Option<PathBuf>) -> ExampleResult<String> {
    match input {
        Some(path) => Ok(fs::read_to_string(path)?),
        None => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            Ok(buffer)
        }
    }
}

fn extract_plans(document: &Value) -> ExampleResult<&Vec<Value>> {
    let plans = if let Some(value) = document.pointer("/metadata/plans") {
        value
    } else if let Some(value) = document.get("plans") {
        value
    } else if document.is_array() {
        document
    } else {
        return Err("input JSON must contain metadata.plans, plans, or be a plan array".into());
    };
    plans
        .as_array()
        .ok_or_else(|| "plans must be an array".into())
}

fn materialize_plan(plan: &Value) -> ExampleResult<Value> {
    let packet = build_packet(plan)?;
    let compiled = packet.compile()?;
    let raw_hex = hex_bytes(compiled.as_bytes());
    let root = plan_root(plan)?;
    let stack = string_array(plan.get("stack")).unwrap_or_default();
    let feature_tags = string_array(plan.get("feature_tags")).unwrap_or_default();
    let strict_bytes = plan
        .get("strict_bytes")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    Ok(json!({
        "backend": BACKEND_NAME,
        "decoder": root,
        "metadata": {
            "backend": BACKEND_NAME,
            "feature_tags": feature_tags,
            "libcrafter_version": env!("CARGO_PKG_VERSION"),
            "length": compiled.as_bytes().len(),
            "root_decoder": root,
            "stack_tags": feature_tags,
            "strict_bytes": strict_bytes
        },
        "plan": plan,
        "raw_hex": raw_hex,
        "root": root,
        "stack": stack
    }))
}

pub fn build_packet(plan: &Value) -> ExampleResult<Packet> {
    let stack = string_array(plan.get("stack")).ok_or("packet plan stack must be an array")?;
    let mut packet = Packet::new();
    let append_udp_options = udp_options_field(plan).is_some();
    let mut saw_udp_options_layer = false;

    let canonical_stack: Vec<String> = stack.iter().map(|layer| canonical_layer(layer)).collect();
    for (index, layer) in canonical_stack.iter().enumerate() {
        let layer = layer.as_str();
        if layer == "rsn" {
            continue;
        }
        if layer == "udp_options" {
            saw_udp_options_layer = true;
        }
        let next_layer = canonical_stack.get(index + 1).map(String::as_str);
        let piece = if layer == "esp" {
            esp_layer(plan, &canonical_stack, index)?
        } else if layer == "ah" {
            ah_layer(plan, &canonical_stack, index)?
        } else if layer == "ipv4" && matches!(next_layer, Some("esp" | "ah")) {
            // Scapy's SecurityAssociation.encrypt forces the carrying IP protocol
            // to ESP (50) / AH (51); the seeded plan leaves the outer IPv4
            // protocol "unknown". Pin it here so libcrafter's sealed datagram is
            // byte-identical to the reference.
            let proto = ipsec_protocol_for_next(next_layer);
            Box::new(ipv4_layer(plan)?.protocol(proto))
        } else if layer == "ipv6" && matches!(next_layer, Some("esp" | "ah")) {
            let proto = ipsec_protocol_for_next(next_layer);
            Box::new(ipv6_layer(plan)?.nh(proto))
        } else if layer == "tcp" {
            Box::new(tcp_layer(plan, next_layer)?)
        } else {
            build_layer(plan, layer)?
        };
        packet.push_box_mut(piece);
        if layer == "igmp" && !igmp_body_layers_follow(&canonical_stack, index) {
            for piece in igmp_inferred_body_layers(plan)? {
                packet.push_box_mut(piece);
            }
        }
        if layer == "eapol" && eapol_key_layer_is_present(plan)? {
            packet.push_box_mut(Box::new(eapol_key_layer(plan)?));
        }
    }

    if append_udp_options && !saw_udp_options_layer {
        packet.push_box_mut(Box::new(udp_options_layer(plan)?));
    }

    Ok(packet)
}

fn build_layer(plan: &Value, layer: &str) -> ExampleResult<Box<dyn Layer>> {
    match layer {
        "payload" | "raw" => Ok(Box::new(Raw::from_bytes(payload_bytes(plan)?))),
        "ethernet" => Ok(Box::new(ethernet_layer(plan)?)),
        "linux_cooked" => Ok(Box::new(linux_cooked_layer(plan)?)),
        "vlan" => Ok(Box::new(vlan_layer(plan)?)),
        "null_loopback" => Ok(Box::new(null_loopback_layer(plan)?)),
        "arp" => Ok(Box::new(arp_layer(plan)?)),
        "ipv4" => Ok(Box::new(ipv4_layer(plan)?)),
        "ipv6" => Ok(Box::new(ipv6_layer(plan)?)),
        "ikev2" => Ok(Box::new(ikev2_layer(plan)?)),
        "ipv6_hop_by_hop" => Ok(Box::new(ipv6_hop_by_hop_layer(plan)?)),
        "ipv6_destination_options" => Ok(Box::new(ipv6_destination_options_layer(plan)?)),
        "ipv6_fragment" => Ok(Box::new(ipv6_fragment_layer(plan)?)),
        "ipv6_routing" => ipv6_routing_layer(plan),
        "udp" => Ok(Box::new(udp_layer(plan)?)),
        "udp_options" => Ok(Box::new(udp_options_layer(plan)?)),
        "tcp" => Ok(Box::new(tcp_layer(plan, None)?)),
        "icmp" => Ok(Box::new(icmp_layer(plan)?)),
        "icmpv6" => Ok(Box::new(icmpv6_layer(plan)?)),
        "igmp" => Ok(Box::new(igmp_layer(plan)?)),
        "igmp_query" => Ok(Box::new(igmp_query_layer(plan)?)),
        "igmp_report" => Ok(Box::new(igmp_report_layer(plan)?)),
        "igmp_extension" => Ok(Box::new(igmp_extension_layer(plan)?)),
        "dns" => Ok(Box::new(dns_layer(plan)?)),
        "dhcp" => Ok(Box::new(dhcp_layer(plan)?)),
        "rip" => Ok(Box::new(rip_layer(plan)?)),
        "ripng" => Ok(Box::new(ripng_layer(plan)?)),
        "bgp" => Ok(Box::new(bgp_layer(plan)?)),
        "radiotap" => Ok(Box::new(radiotap_layer(plan)?)),
        "dot11" => Ok(Box::new(dot11_layer(plan)?)),
        "llc_snap" => Ok(Box::new(llc_snap_layer(plan)?)),
        "eapol" => Ok(Box::new(eapol_layer(plan)?)),
        "esp" | "ah" => Err(format!(
            "{layer} must be materialized with stack context (see build_packet)"
        )
        .into()),
        _ => Err(format!("unsupported libcrafter materialization layer: {layer}").into()),
    }
}

/// The IP protocol / next-header value the carrying IP header must advertise for
/// the ESP/AH layer that follows it (RFC 4303 §2 / RFC 4302 §2).
fn ipsec_protocol_for_next(next_layer: Option<&str>) -> u8 {
    match next_layer {
        Some("ah") => IPPROTO_AH,
        _ => IPPROTO_ESP,
    }
}

/// IP-in-IP protocol number for ESP/AH tunnel mode (RFC 4303 §3.1.1). Not an
/// exported crate constant, so it is defined locally to match `Esp`'s own
/// derivation.
const IPPROTO_IP_IN_IP: u8 = 4;

/// Resolve the ESP/AH Next Header for the sealed datagram.
///
/// Scapy's `SecurityAssociation.encrypt` derives the value from the packet it
/// seals, *before* it rewrites the carrying IP protocol to ESP/AH:
/// - Tunnel mode: the inner IP version (4 for IPv4, 41 for IPv6).
/// - Transport mode: the carrying IP header's protocol/next-header field as the
///   seeded plan set it. For plain ESP/AH the plan leaves the outer IP protocol
///   "unknown" (253); for UDP-encapsulated NAT-T it is UDP (17). The emitted
///   outer IP protocol is overridden to 50/51 separately, but the trailer Next
///   Header keeps this pre-override value, so mirror it for byte parity.
fn ipsec_next_header(plan: &Value, stack: &[String], sec_index: usize) -> ExampleResult<u8> {
    let inner = stack.get(sec_index + 1).map(String::as_str);
    if matches!(inner, Some("ipv4")) {
        return Ok(IPPROTO_IP_IN_IP);
    }
    if matches!(inner, Some("ipv6")) {
        return Ok(IPPROTO_IPV6);
    }
    // Transport mode: the Next Header is the carrying IP header's protocol field
    // as the plan set it (NAT-T's intervening UDP carries the ESP, so the carrier
    // is the UDP layer; otherwise it is the outer IP header).
    let carrier = stack.get(sec_index.wrapping_sub(1)).map(String::as_str);
    if matches!(carrier, Some("udp")) {
        return Ok(IPPROTO_UDP);
    }
    outer_ip_protocol(plan, carrier)
}

/// Read the carrying IP header's protocol / next-header value from the plan,
/// exactly as the seeded plan declared it (before any ESP/AH override).
fn outer_ip_protocol(plan: &Value, carrier: Option<&str>) -> ExampleResult<u8> {
    match carrier {
        Some("ipv4") => {
            let fields = layer_fields(plan, "ipv4")?;
            ip_protocol(required(fields, &["protocol", "proto"])?)
        }
        Some("ipv6") => {
            let fields = layer_fields(plan, "ipv6")?;
            ipv6_next_header(required(fields, &["next_header", "nh"])?)
        }
        _ => Err("ESP/AH transport materialization requires a carrying IP layer".into()),
    }
}

/// Build the ESP layer (and its Security Association) for the offline oracle.
///
/// The seeded plan pins the SPI, sequence, key/salt, and explicit IV so the
/// sealed `SPI || Seq || IV || ciphertext || ICV` is byte-reproducible against
/// the Scapy reference. The keyless `null-opaque` behavior carries the following
/// bytes verbatim as the opaque ESP body. Inner layers are appended by the
/// caller and consumed by `Esp::consumes_following()` during compile.
fn esp_layer(plan: &Value, stack: &[String], index: usize) -> ExampleResult<Box<dyn Layer>> {
    let fields = layer_fields(plan, "esp")?;
    let spi = u32_value(required(fields, &["spi"])?)?;
    let sequence = optional(fields, &["sequence", "seq"])
        .map(u32_value)
        .transpose()?
        .unwrap_or(1);

    if ipsec_feature_behavior(plan) == "null-opaque" {
        // No SA: the following bytes are preserved verbatim as the opaque body.
        let opaque = ipsec_following_bytes(plan, stack, index)?;
        let mut esp = Esp::new().spi(spi).sequence(sequence).opaque(opaque);
        if let Some(value) = optional(fields, &["next_header", "nh"]) {
            esp = esp.next_header(ipsec_next_header_field(plan, value, stack, index)?);
        }
        return Ok(Box::new(esp));
    }

    let sa = esp_security_association(plan, fields, spi)?;
    let mut esp = Esp::secured(sa)
        .spi(spi)
        .sequence(sequence)
        .next_header(ipsec_next_header(plan, stack, index)?);
    esp = esp.iv(esp_explicit_iv(plan, fields)?);
    // The trailer pad is left derived: compile() pads to the cipher block size
    // per RFC 4303 §2.4, exactly as Scapy's SecurityAssociation.encrypt does. The
    // seeded plan's `pad_length` (often 0) is only a domain marker and would
    // break CBC block alignment if forced, so it is intentionally not pinned.
    Ok(Box::new(esp))
}

/// Build the AH layer (and its Security Association) for the offline oracle.
fn ah_layer(plan: &Value, stack: &[String], index: usize) -> ExampleResult<Box<dyn Layer>> {
    let fields = layer_fields(plan, "ah")?;
    let spi = u32_value(required(fields, &["spi"])?)?;
    let sequence = optional(fields, &["sequence", "seq"])
        .map(u32_value)
        .transpose()?
        .unwrap_or(1);

    let sa = ah_security_association(plan, fields, spi)?;
    let mut ah = Ah::secured(sa)
        .spi(spi)
        .sequence(sequence)
        .next_header(ipsec_next_header(plan, stack, index)?);
    if let Some(value) = optional(fields, &["reserved"]) {
        ah = ah.reserved(u16_value(value)?);
    }
    Ok(Box::new(ah))
}

/// Build the IKEv2 message header (RFC 7296 §3.1) for the offline oracle.
///
/// The seeded plan pins the initiator/responder SPIs, next-payload, version,
/// exchange type, flags, and message id; the IKE payload chain itself is the
/// following `payload` Raw layer in the stack, which the build loop appends
/// after this header. `IkeHeader` does not consume the tail, so the auto-filled
/// message Length covers the 28-octet header plus the trailing payload bytes —
/// byte-identical to the Scapy `scapy.layers.isakmp.ISAKMP` reference, which
/// also materializes only the header and recomputes the length over the same
/// following Raw bytes. Every header field is pinned explicitly (including a
/// `next_payload` of `none`/`0` and a deliberately out-of-spec `version` such as
/// `0` or `255`) so the wire bytes match the reference verbatim.
fn ikev2_layer(plan: &Value) -> ExampleResult<IkeHeader> {
    let fields = layer_fields(plan, "ikev2")?;
    let mut header = IkeHeader::new();
    if let Some(value) = optional(fields, &["initiator_spi"]) {
        header = header.initiator_spi(ikev2_spi(value)?);
    }
    if let Some(value) = optional(fields, &["responder_spi"]) {
        header = header.responder_spi(ikev2_spi(value)?);
    }
    // The next payload is pinned explicitly: the following payload chain is an
    // opaque Raw layer that does not register an IKEv2 payload type, so the
    // header's auto-derivation cannot recover the plan's intended pointer.
    if let Some(value) = optional(fields, &["next_payload"]) {
        header = header.next_payload(ikev2_next_payload(value)?);
    }
    if let Some(value) = optional(fields, &["version"]) {
        header = header.version(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["exchange_type"]) {
        header = header.exchange(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["flags"]) {
        header = header.flags(ikev2_flags(value)?);
    }
    if let Some(value) = optional(fields, &["message_id"]) {
        header = header.message_id(u32_value(value)?);
    }
    if let Some(value) = optional(fields, &["length"]) {
        header = header.length(u32_value(value)?);
    }
    Ok(header)
}

/// Read an 8-octet IKEv2 SPI (RFC 7296 §3.1) from the plan's `{"hex": ...}` or
/// hex-string form and pack it big-endian into a `u64` for `IkeHeader`.
fn ikev2_spi(value: &Value) -> ExampleResult<u64> {
    let bytes = option_bytes(value)?;
    if bytes.len() != 8 {
        return Err(format!(
            "IKEv2 SPI must contain exactly 8 octets, got {}",
            bytes.len()
        )
        .into());
    }
    let mut octets = [0u8; 8];
    octets.copy_from_slice(&bytes);
    Ok(u64::from_be_bytes(octets))
}

/// Resolve an IKEv2 Next Payload codepoint (RFC 7296 §3.2) from the plan value.
///
/// The plan carries the libcrafter payload-type layer name (`IkeSaPayload`,
/// `IkeKePayload`, `IkeNoncePayload`), the literal `none`, or a numeric value;
/// each maps to the same wire codepoint the Scapy reference stores.
fn ikev2_next_payload(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        let lowered = text.to_ascii_lowercase().replace('-', "_");
        return match lowered.as_str() {
            "none" => Ok(0),
            "ikesapayload" | "sa" => Ok(33),
            "ikekepayload" | "ke" => Ok(34),
            "ikeidipayload" => Ok(35),
            "ikeidrpayload" => Ok(36),
            "ikecertpayload" => Ok(37),
            "ikecertreqpayload" => Ok(38),
            "ikeauthpayload" | "auth" => Ok(39),
            "ikenoncepayload" | "nonce" => Ok(40),
            "ikenotifypayload" | "notify" => Ok(41),
            "ikedeletepayload" | "delete" => Ok(42),
            "ikevendorpayload" => Ok(43),
            "iketsipayload" => Ok(44),
            "iketsrpayload" => Ok(45),
            "ikeencryptedpayload" | "encrypted" => Ok(46),
            "ikeconfigpayload" => Ok(47),
            "ikeeappayload" => Ok(48),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

/// Resolve the IKEv2 Flags octet (RFC 7296 §3.1) from the plan value.
///
/// The plan carries a list of flag names (`initiator`, `version`, `response`),
/// a single name, or a numeric value; the names OR their bit positions together
/// exactly as the Scapy reference resolves them.
fn ikev2_flags(value: &Value) -> ExampleResult<u8> {
    if let Some(items) = value.as_array() {
        let mut flags = 0u8;
        for item in items {
            flags |= ikev2_flag_bit(item)?;
        }
        return Ok(flags);
    }
    ikev2_flag_bit(value)
}

/// Resolve a single IKEv2 flag (name or numeric) to its bit (RFC 7296 §3.1).
fn ikev2_flag_bit(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        let lowered = text.to_ascii_lowercase().replace('-', "_");
        return match lowered.as_str() {
            "initiator" => Ok(IKE_FLAG_INITIATOR),
            "version" => Ok(IKE_FLAG_VERSION),
            "response" => Ok(IKE_FLAG_RESPONSE),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

/// Resolve an explicit ESP Next Header override from the plan's string/int value
/// (used only by the keyless opaque path, which has no SA to drive derivation).
fn ipsec_next_header_field(
    plan: &Value,
    value: &Value,
    stack: &[String],
    sec_index: usize,
) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().as_str() {
            "ipv4" => Ok(IPPROTO_IP_IN_IP),
            "ipv6" => Ok(IPPROTO_IPV6),
            "tcp" => Ok(IPPROTO_TCP),
            "udp" => Ok(IPPROTO_UDP),
            "icmp" => Ok(IPPROTO_ICMP),
            "payload" | "raw" | "unknown" => ipsec_next_header(plan, stack, sec_index),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

/// Resolve the pinned explicit ESP IV, mirroring the Scapy backend.
///
/// AEAD (RFC 4106) uses the 8-octet explicit IV: a per-layer `iv` override wins
/// (the generator pins it, including the all-zero `zero` domain), otherwise the
/// crypto block's `iv`/`aead_iv`. CBC (RFC 3602) uses the 16-octet `cbc_iv` from
/// the crypto block; the ESP `iv` field only carries the 8-octet AEAD IV.
fn esp_explicit_iv(plan: &Value, fields: &Map<String, Value>) -> ExampleResult<Vec<u8>> {
    let crypto = ipsec_crypto_block(fields)?;
    if ipsec_feature(plan) == "esp_aead" {
        if let Some(value) = optional(fields, &["iv"]) {
            return option_bytes(value);
        }
        return ipsec_crypto_bytes(crypto, &["iv", "aead_iv"]);
    }
    ipsec_crypto_bytes(crypto, &["cbc_iv"])
}

/// Build the ESP Security Association from the plan's pinned crypto block,
/// selecting the suite from the feature: `esp_aead` → AES-GCM-16 (AEAD), every
/// other keyed ESP → AES-CBC + HMAC-SHA2-256-128 (matching the Scapy backend's
/// `_esp_suite`).
fn esp_security_association(
    plan: &Value,
    fields: &Map<String, Value>,
    spi: u32,
) -> ExampleResult<SecurityAssociation> {
    let crypto = ipsec_crypto_block(fields)?;
    let mode = ipsec_mode(plan, stack_has_inner_ip(plan));
    let mut sa = SecurityAssociation::new(spi);
    if ipsec_feature(plan) == "esp_aead" {
        sa = sa
            .encryption(
                EncryptionAlgorithm::AesGcm16,
                ipsec_crypto_bytes(crypto, &["encryption_key"])?,
            )
            .salt(ipsec_crypto_bytes(crypto, &["salt"])?);
    } else {
        sa = sa
            .encryption(
                EncryptionAlgorithm::AesCbc,
                ipsec_crypto_bytes(crypto, &["encryption_key"])?,
            )
            .integrity(
                IntegrityAlgorithm::HmacSha2_256_128,
                ipsec_crypto_bytes(crypto, &["integrity_key"])?,
            );
    }
    sa = apply_ipsec_mode(sa, mode).extended_sequence(false);
    Ok(sa)
}

/// Build the AH Security Association (integrity-only HMAC-SHA2-256-128).
fn ah_security_association(
    plan: &Value,
    fields: &Map<String, Value>,
    spi: u32,
) -> ExampleResult<SecurityAssociation> {
    let crypto = ipsec_crypto_block(fields)?;
    let mode = ipsec_mode(plan, stack_has_inner_ip(plan));
    let sa = SecurityAssociation::new(spi).integrity(
        IntegrityAlgorithm::HmacSha2_256_128,
        ipsec_crypto_bytes(crypto, &["integrity_key"])?,
    );
    Ok(apply_ipsec_mode(sa, mode).extended_sequence(false))
}

/// Apply the resolved IPSec mode to a Security Association builder.
fn apply_ipsec_mode(sa: SecurityAssociation, tunnel: bool) -> SecurityAssociation {
    if tunnel {
        sa.tunnel()
    } else {
        sa.transport()
    }
}

/// True when the ESP/AH stack seals a whole inner IP datagram (tunnel mode).
fn stack_has_inner_ip(plan: &Value) -> bool {
    let Some(stack) = string_array(plan.get("stack")) else {
        return false;
    };
    let canonical: Vec<String> = stack.iter().map(|layer| canonical_layer(layer)).collect();
    for (index, layer) in canonical.iter().enumerate() {
        if layer == "esp" || layer == "ah" {
            return matches!(
                canonical.get(index + 1).map(String::as_str),
                Some("ipv4" | "ipv6")
            );
        }
    }
    false
}

/// Resolve the IPSec mode (tunnel when a whole inner IP datagram is sealed).
fn ipsec_mode(_plan: &Value, has_inner_ip: bool) -> bool {
    has_inner_ip
}

/// The ESP/AH pinned crypto block carried under the layer fields.
fn ipsec_crypto_block(fields: &Map<String, Value>) -> ExampleResult<&Map<String, Value>> {
    required(fields, &["crypto"])?
        .as_object()
        .ok_or_else(|| "ipsec crypto block must be an object".into())
}

/// Read a pinned crypto value (`{ "hex": ... }`) as raw bytes.
fn ipsec_crypto_bytes(crypto: &Map<String, Value>, names: &[&str]) -> ExampleResult<Vec<u8>> {
    option_bytes(required(crypto, names)?)
}

/// The IPSec feature name from the plan metadata (`esp_aead`, `esp_cbc`, …).
fn ipsec_feature(plan: &Value) -> String {
    plan.pointer("/metadata/feature")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// The IPSec feature behavior from the plan metadata (`aead-transport`, …).
fn ipsec_feature_behavior(plan: &Value) -> String {
    plan.pointer("/metadata/feature_behavior")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Collect the verbatim bytes of every layer following the ESP layer (used as
/// the opaque body for the keyless null-opaque case).
fn ipsec_following_bytes(plan: &Value, stack: &[String], index: usize) -> ExampleResult<Vec<u8>> {
    let mut bytes = Vec::new();
    for layer in stack.iter().skip(index + 1) {
        if layer == "rsn" || layer == "udp_options" {
            continue;
        }
        let piece = build_layer(plan, layer)?;
        let mut packet = Packet::new();
        packet.push_box_mut(piece);
        bytes.extend_from_slice(packet.compile()?.as_bytes());
    }
    Ok(bytes)
}

fn radiotap_layer(plan: &Value) -> ExampleResult<Radiotap> {
    let fields = layer_fields(plan, "radiotap")?;
    let mut layer = Radiotap::new()
        .version(
            optional(fields, &["version"])
                .map(u8_value)
                .transpose()?
                .unwrap_or(0),
        )
        .pad(
            optional(fields, &["pad"])
                .map(u8_value)
                .transpose()?
                .unwrap_or(0),
        );

    let has_flags =
        optional(fields, &["flags"]).is_some() || optional(fields, &["fcs_status"]).is_some();
    if has_flags {
        layer = layer.flags(RadiotapFlags::from_bits(radiotap_flags(fields)?));
    }
    if let Some(value) = optional(fields, &["rate"]) {
        layer = layer.rate(u8_value(value)?);
    }
    if optional(fields, &["channel_frequency"]).is_some()
        || optional(fields, &["channel_flags"]).is_some()
    {
        layer = layer.channel(RadiotapChannel::new(
            optional(fields, &["channel_frequency"])
                .map(u16_value)
                .transpose()?
                .unwrap_or(2412),
            radiotap_channel_flags(optional(fields, &["channel_flags"]))?,
        ));
    }
    if let Some(value) = optional(fields, &["dbm_antenna_signal"]) {
        layer = layer.antenna_signal(i8_value(value)?);
    }
    if let Some(value) = optional(fields, &["antenna"]) {
        layer = layer.antenna(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["rx_flags"]) {
        layer = layer.rx_flags(RadiotapRxFlags::from_bits(u16_value(value)?));
    }
    if let Some(value) = optional(fields, &["tx_flags"]) {
        layer = layer.tx_flags(RadiotapTxFlags::from_bits(u16_value(value)?));
    }

    Ok(layer)
}

fn dot11_layer(plan: &Value) -> ExampleResult<Dot11> {
    let fields = layer_fields(plan, "dot11")?;
    let mut layer = Dot11::new()
        .frame_control(Dot11FrameControl::from_bits(dot11_frame_control(fields)?))
        .duration_id(
            optional(fields, &["duration_id"])
                .map(u16_value)
                .transpose()?
                .unwrap_or(0),
        )
        .addr1(mac_addr_field(fields, &["addr1"], "00:00:5e:00:53:01")?)
        .addr2(mac_addr_field(fields, &["addr2"], "00:00:5e:00:53:02")?)
        .addr3(mac_addr_field(fields, &["addr3"], "00:00:5e:00:53:03")?);

    if let Some(value) = optional(fields, &["addr4"]) {
        layer = layer.addr4(mac_addr_value(value)?);
    }
    if let Some(value) = optional(fields, &["sequence_control"]) {
        layer = layer.sequence_control(Dot11SequenceControl::from_bits(u16_value(value)?));
    }
    if let Some(value) = optional(fields, &["qos_control"]) {
        layer = layer.qos_control(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["ht_control"]) {
        layer = layer.ht_control(u32_value(value)?);
    }
    if let Some(value) = optional(fields, &["management_fixed_fields"]) {
        layer = layer.fixed_parameters(option_bytes(value)?);
    }
    if let Some(value) = optional(fields, &["tagged_parameters"]) {
        for tag in dot11_tagged_parameters(value)? {
            layer = layer.tag(tag);
        }
    }
    if stack_contains(plan, "rsn") {
        if let Some(rsn) = optional_layer_fields(plan, "rsn")? {
            layer = layer.tag(rsn_tagged_parameter(rsn)?);
        }
    }

    Ok(layer)
}

fn llc_snap_layer(plan: &Value) -> ExampleResult<LlcSnap> {
    let fields = layer_fields(plan, "llc_snap")?;
    let oui = optional(fields, &["oui"])
        .map(|value| fixed_3_bytes(value, "llc_snap.oui"))
        .transpose()?
        .unwrap_or([0, 0, 0]);
    Ok(LlcSnap::new()
        .dsap(
            optional(fields, &["dsap"])
                .map(u8_value)
                .transpose()?
                .unwrap_or(0xaa),
        )
        .ssap(
            optional(fields, &["ssap"])
                .map(u8_value)
                .transpose()?
                .unwrap_or(0xaa),
        )
        .control(
            optional(fields, &["control"])
                .map(u8_value)
                .transpose()?
                .unwrap_or(0x03),
        )
        .oui(oui)
        .ethertype(
            optional(fields, &["ethertype", "type"])
                .map(ethertype_value)
                .transpose()?
                .unwrap_or_else(|| ethertype_for_next_stack_layer(plan, "llc_snap")),
        ))
}

fn eapol_layer(plan: &Value) -> ExampleResult<Eapol> {
    let fields = layer_fields(plan, "eapol")?;
    let mut layer = Eapol::new()
        .version(
            optional(fields, &["version"])
                .map(u8_value)
                .transpose()?
                .unwrap_or(EAPOL_VERSION_2),
        )
        .packet_type_raw(
            optional(fields, &["packet_type", "type"])
                .map(eapol_type_value)
                .transpose()?
                .unwrap_or(EAPOL_TYPE_EAP_PACKET),
        );
    if let Some(value) = optional(fields, &["body", "body_bytes"]) {
        layer = layer.body(option_bytes(value)?);
    }
    if let Some(value) = optional(fields, &["body_length", "len"]) {
        let length = u16_value(value)?;
        if length != 0 {
            layer = layer.body_length(length);
        }
    }
    Ok(layer)
}

fn eapol_key_layer_is_present(plan: &Value) -> ExampleResult<bool> {
    let Some(fields) = optional_layer_fields(plan, "eapol")? else {
        return Ok(false);
    };
    if optional(
        fields,
        &[
            "descriptor_type",
            "key_information",
            "key_length",
            "replay_counter",
        ],
    )
    .is_some()
    {
        return Ok(true);
    }
    Ok(optional(fields, &["packet_type", "type"])
        .map(eapol_type_value)
        .transpose()?
        == Some(EAPOL_TYPE_KEY))
}

fn eapol_key_layer(plan: &Value) -> ExampleResult<EapolKey> {
    let fields = layer_fields(plan, "eapol")?;
    let mut layer = EapolKey::new()
        .descriptor_type_raw(
            optional(fields, &["descriptor_type"])
                .map(eapol_descriptor_type)
                .transpose()?
                .unwrap_or(EAPOL_KEY_DESCRIPTOR_RSN),
        )
        .key_information(EapolKeyInformation::from_bits(
            optional(fields, &["key_information"])
                .map(u16_value)
                .transpose()?
                .unwrap_or(0),
        ))
        .key_length(
            optional(fields, &["key_length"])
                .map(u16_value)
                .transpose()?
                .unwrap_or(0),
        )
        .replay_counter(
            optional(fields, &["replay_counter"])
                .map(u64_value)
                .transpose()?
                .unwrap_or(0),
        );

    if let Some(value) = optional(fields, &["key_nonce", "nonce"]) {
        layer = layer.nonce(fixed_32_bytes(value, "eapol.key_nonce")?);
    }
    if let Some(value) = optional(fields, &["key_iv", "iv"]) {
        layer = layer.iv(fixed_16_bytes(value, "eapol.key_iv")?);
    }
    if let Some(value) = optional(fields, &["key_rsc", "rsc"]) {
        layer = layer.rsc(fixed_8_bytes(value, "eapol.key_rsc")?);
    }
    if let Some(value) = optional(fields, &["key_id", "id"]) {
        layer = layer.id(fixed_8_bytes(value, "eapol.key_id")?);
    }
    if let Some(value) = optional(fields, &["key_mic", "mic"]) {
        layer = layer.mic(fixed_16_bytes(value, "eapol.key_mic")?);
    }
    if let Some(value) = optional(fields, &["key_data"]) {
        layer = layer.key_data(option_bytes(value)?);
    }
    if let Some(value) = optional(fields, &["key_data_length", "key_data_len"]) {
        let length = u16_value(value)?;
        if length != 0 || optional(fields, &["key_data"]).is_none() {
            layer = layer.key_data_length(length);
        }
    }

    Ok(layer)
}

fn ethernet_layer(plan: &Value) -> ExampleResult<Ethernet> {
    let fields = layer_fields(plan, "ethernet")?;
    let layer = Ethernet::new()
        .src_str(text_required(fields, &["src"])?)?
        .dst_str(text_required(fields, &["dst"])?)?
        .ethertype(ethertype_value(required(fields, &["ethertype", "type"])?)?);
    Ok(layer)
}

fn vlan_layer(plan: &Value) -> ExampleResult<Vlan> {
    let fields = layer_fields(plan, "vlan")?;
    Ok(Vlan::new()
        .prio(u8_value(required(fields, &["priority", "prio"])?)?)
        .dei(
            optional(fields, &["drop_eligible", "dei"])
                .map(bool_value)
                .transpose()?
                .unwrap_or(false),
        )
        .vlan(u16_value(required(fields, &["vlan_id", "id", "vlan"])?)?)
        .ethertype(ethertype_value(required(fields, &["ethertype", "type"])?)?))
}

/// Materialize a Linux cooked-capture (SLL) header from a plan.
///
/// Mirrors the Scapy `_linux_cooked` reference: `packet_type`, `address_type`
/// (an ARPHRD hardware type), `address_length`, `source_address` (a MAC string
/// or a raw `{"hex": ...}` byte form padded to eight octets), and `protocol`
/// (an EtherType). The raw `source_address_bytes` path preserves the exact
/// eight-octet source field and the declared address length so an ARP body over
/// a linux-cooked root materializes byte-for-byte against the reference.
fn linux_cooked_layer(plan: &Value) -> ExampleResult<LinuxSll> {
    let fields = layer_fields(plan, "linux_cooked")?;
    let packet_type = linux_sll_packet_type(required(fields, &["packet_type", "pkttype"])?)?;
    let address_type = hardware_type_value(required(fields, &["address_type", "lladdrtype"])?)?;
    let address_len = u16_value(required(fields, &["address_length", "lladdrlen"])?)?;
    let source_address =
        linux_sll_source_address(required(fields, &["source_address", "src", "lladdr"])?)?;
    let protocol = ethertype_value(required(fields, &["protocol", "proto"])?)?;
    Ok(LinuxSll::new()
        .packet_type(packet_type)
        .address_type(address_type)
        .source_address_bytes(source_address, address_len)
        .protocol(protocol))
}

/// Map a Linux SLL packet-type value (named string or numeric) to its code.
///
/// Matches the Scapy reference mapping so named packet types materialize to the
/// same code; unknown strings parse as a numeric literal and numeric values
/// pass through.
fn linux_sll_packet_type(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        let lowered = text.to_ascii_lowercase().replace('-', "_");
        return match lowered.as_str() {
            "host" => Ok(0),
            "broadcast" => Ok(1),
            "multicast" => Ok(2),
            "otherhost" => Ok(3),
            "outgoing" => Ok(4),
            _ => u16_text(text),
        };
    }
    u16_value(value)
}

/// Decode a Linux SLL source address into the fixed eight-octet field.
///
/// Accepts a standard colon-separated MAC string or a raw `{"hex": ...}`/hex
/// string byte form. The decoded bytes are left-aligned into eight octets and
/// trailing octets stay zero, matching the Scapy reference's `pad_to=8`.
fn linux_sll_source_address(value: &Value) -> ExampleResult<[u8; 8]> {
    let raw = if let Some(object) = value.as_object() {
        match object.get("hex").and_then(Value::as_str) {
            Some(hex) => decode_hex(&strip_address_separators(hex))?,
            None => {
                return Err(
                    format!("unsupported linux_cooked source address object: {value:?}").into(),
                )
            }
        }
    } else if let Some(text) = value.as_str() {
        decode_hex(&strip_address_separators(text))?
    } else {
        return Err(format!("unsupported linux_cooked source address value: {value:?}").into());
    };
    if raw.len() > 8 {
        return Err(format!(
            "linux_cooked source address has {} octets, exceeds the eight-octet SLL field",
            raw.len()
        )
        .into());
    }
    let mut padded = [0u8; 8];
    padded[..raw.len()].copy_from_slice(&raw);
    Ok(padded)
}

fn null_loopback_layer(plan: &Value) -> ExampleResult<NullLoopback> {
    let fields = layer_fields(plan, "null_loopback")?;
    let family = optional(fields, &["type", "family"])
        .map(address_family_value)
        .transpose()?
        .unwrap_or(2);
    Ok(NullLoopback::new().family(family))
}

fn arp_layer(plan: &Value) -> ExampleResult<Arp> {
    let fields = layer_fields(plan, "arp")?;
    let mut layer = Arp::new()
        .hardware_type(hardware_type_value(required(
            fields,
            &["hardware_type", "hwtype"],
        )?)?)
        .protocol_type(ethertype_value(required(
            fields,
            &["protocol_type", "ptype"],
        )?)?)
        .opcode(arp_opcode(required(
            fields,
            &["opcode", "op", "operation"],
        )?)?);

    // Honor explicit ARP length fields when present. The standard
    // Ethernet/IPv4 generator omits them and lets the standard MAC/IPv4 address
    // setters default them to 6/4; when a plan carries explicit lengths
    // (variable-length or unknown-family ARP), set them through the public
    // `hardware_len`/`protocol_len` setters before the address bytes so the
    // compiled header matches the plan and the Scapy reference exactly.
    if let Some(value) = optional(fields, &["hardware_length", "hwlen"]) {
        layer = layer.hardware_len(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["protocol_length", "plen"]) {
        layer = layer.protocol_len(u8_value(value)?);
    }

    layer = apply_arp_hardware_address(
        layer,
        ArpAddressField::SenderHardware,
        required(fields, &["sender_hardware_address", "hwsrc"])?,
    )?;
    layer = apply_arp_protocol_address(
        layer,
        ArpAddressField::SenderProtocol,
        required(fields, &["sender_protocol_address", "sender_ip", "psrc"])?,
    )?;
    layer = apply_arp_hardware_address(
        layer,
        ArpAddressField::TargetHardware,
        required(fields, &["target_hardware_address", "hwdst"])?,
    )?;
    layer = apply_arp_protocol_address(
        layer,
        ArpAddressField::TargetProtocol,
        required(fields, &["target_protocol_address", "target_ip", "pdst"])?,
    )?;
    Ok(layer)
}

/// Which ARP sender/target address field is being materialized.
#[derive(Debug, Clone, Copy)]
enum ArpAddressField {
    SenderHardware,
    TargetHardware,
    SenderProtocol,
    TargetProtocol,
}

/// Standard Ethernet hardware address width in octets.
const ARP_STANDARD_HARDWARE_OCTETS: usize = 6;
/// Standard IPv4 protocol address width in octets.
const ARP_STANDARD_PROTOCOL_OCTETS: usize = 4;

/// Apply one ARP hardware (sender/target) address to the layer.
///
/// A standard colon-separated MAC string flows through the `hwsrc_str`/
/// `hwdst_str` helpers so the golden Ethernet/IPv4 ARP bytes stay stable. Any
/// raw byte form — a `{"hex": ...}` object, a hex string whose decoded width is
/// not the standard six octets, or an empty string — is set through the raw
/// `sender_hardware_bytes`/`target_hardware_bytes` setters so variable-length
/// and unknown-family hardware addresses materialize byte-for-byte.
fn apply_arp_hardware_address(
    layer: Arp,
    field: ArpAddressField,
    value: &Value,
) -> ExampleResult<Arp> {
    if let Some(text) = value.as_str() {
        if is_standard_mac(text) {
            return Ok(match field {
                ArpAddressField::SenderHardware => layer.hwsrc_str(text)?,
                ArpAddressField::TargetHardware => layer.hwdst_str(text)?,
                _ => unreachable!("hardware address field expected"),
            });
        }
    }
    let raw = arp_address_bytes(value)?;
    Ok(match field {
        ArpAddressField::SenderHardware => layer.sender_hardware_bytes(raw),
        ArpAddressField::TargetHardware => layer.target_hardware_bytes(raw),
        _ => unreachable!("hardware address field expected"),
    })
}

/// Apply one ARP protocol (sender/target) address to the layer.
///
/// A standard dotted-quad IPv4 string flows through the `psrc_str`/`pdst_str`
/// helpers so the golden Ethernet/IPv4 ARP bytes stay stable. Any raw byte
/// form materializes through the raw `sender_protocol_bytes`/
/// `target_protocol_bytes` setters so variable-length and unknown-family
/// protocol addresses materialize byte-for-byte.
fn apply_arp_protocol_address(
    layer: Arp,
    field: ArpAddressField,
    value: &Value,
) -> ExampleResult<Arp> {
    if let Some(text) = value.as_str() {
        if is_standard_ipv4(text) {
            return Ok(match field {
                ArpAddressField::SenderProtocol => layer.psrc_str(text)?,
                ArpAddressField::TargetProtocol => layer.pdst_str(text)?,
                _ => unreachable!("protocol address field expected"),
            });
        }
    }
    let raw = arp_address_bytes(value)?;
    Ok(match field {
        ArpAddressField::SenderProtocol => layer.sender_protocol_bytes(raw),
        ArpAddressField::TargetProtocol => layer.target_protocol_bytes(raw),
        _ => unreachable!("protocol address field expected"),
    })
}

/// Decode an ARP address value into raw octets for the raw byte setters.
///
/// Accepts a `{"hex": ...}` object (the form `decode_vectors` emits for
/// nonstandard addresses), a colon/dash/space-separated or bare hex string, or
/// an empty string (a zero-length HLN/PLN address). This mirrors the Scapy
/// backend's `_arp_address` raw path so both backends materialize the same
/// bytes from the same plan.
fn arp_address_bytes(value: &Value) -> ExampleResult<Vec<u8>> {
    if let Some(object) = value.as_object() {
        if let Some(hex) = object.get("hex").and_then(Value::as_str) {
            return decode_hex(&strip_address_separators(hex));
        }
        return Err(format!("unsupported ARP address object: {value:?}").into());
    }
    if let Some(text) = value.as_str() {
        return decode_hex(&strip_address_separators(text));
    }
    Err(format!("unsupported ARP address value: {value:?}").into())
}

fn strip_address_separators(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !matches!(ch, ':' | '-' | ' '))
        .collect()
}

fn is_standard_mac(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != ARP_STANDARD_HARDWARE_OCTETS {
        return false;
    }
    parts
        .iter()
        .all(|part| part.len() == 2 && u8::from_str_radix(part, 16).is_ok())
}

fn is_standard_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != ARP_STANDARD_PROTOCOL_OCTETS {
        return false;
    }
    parts
        .iter()
        .all(|part| !part.is_empty() && part.parse::<u8>().is_ok())
}

fn ipv4_layer(plan: &Value) -> ExampleResult<Ipv4> {
    let fields = layer_fields(plan, "ipv4")?;
    let mut layer = Ipv4::new()
        .src_str(text_required(fields, &["src"])?)?
        .dst_str(text_required(fields, &["dst"])?)?
        .id(u16_value(required(fields, &["identification", "id"])?)?)
        .ttl(u8_value(required(fields, &["ttl"])?)?)
        .flags(ipv4_flags(required(fields, &["flags"])?)?)
        .protocol(ip_protocol(required(fields, &["protocol", "proto"])?)?);
    if let Some(value) = optional(fields, &["ds_field", "tos"]) {
        layer = layer.tos(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["fragment_offset", "frag"]) {
        layer = layer.frag(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["options"]) {
        layer = layer.options(option_bytes(value)?);
    }
    Ok(layer)
}

fn ipv6_layer(plan: &Value) -> ExampleResult<Ipv6> {
    let fields = layer_fields(plan, "ipv6")?;
    let mut layer = Ipv6::new()
        .src_str(text_required(fields, &["src"])?)?
        .dst_str(text_required(fields, &["dst"])?)?
        .hlim(u8_value(required(fields, &["hop_limit", "hlim"])?)?)
        .nh(ipv6_next_header(required(fields, &["next_header", "nh"])?)?);
    if let Some(value) = optional(fields, &["traffic_class", "tc"]) {
        layer = layer.tc(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["flow_label", "fl"]) {
        layer = layer.fl(u32_value(value)?);
    }
    Ok(layer)
}

fn ipv6_hop_by_hop_layer(plan: &Value) -> ExampleResult<Ipv6HopByHopOptionsHeader> {
    let fields = layer_fields(plan, "ipv6_hop_by_hop")?;
    let mut layer = Ipv6HopByHopOptionsHeader::new()
        .nh(ipv6_next_header(required(fields, &["next_header", "nh"])?)?)
        .options(ipv6_options(required(fields, &["options"])?)?);
    if let Some(value) = optional(fields, &["header_ext_len", "len"]) {
        layer = layer.header_ext_len(u8_value(value)?);
    }
    Ok(layer)
}

fn ipv6_destination_options_layer(plan: &Value) -> ExampleResult<Ipv6DestinationOptionsHeader> {
    let fields = layer_fields(plan, "ipv6_destination_options")?;
    let mut layer = Ipv6DestinationOptionsHeader::new()
        .nh(ipv6_next_header(required(fields, &["next_header", "nh"])?)?)
        .options(ipv6_options(required(fields, &["options"])?)?);
    if let Some(value) = optional(fields, &["header_ext_len", "len"]) {
        layer = layer.header_ext_len(u8_value(value)?);
    }
    Ok(layer)
}

fn ipv6_options(value: &Value) -> ExampleResult<Vec<Ipv6Option>> {
    array_values(value)?
        .iter()
        .map(ipv6_option)
        .collect::<ExampleResult<Vec<_>>>()
}

fn ipv6_option(value: &Value) -> ExampleResult<Ipv6Option> {
    let item = value
        .as_object()
        .ok_or_else(|| format!("IPv6 option entry must be an object, got {value:?}"))?;
    match ipv6_option_kind(item)?.as_str() {
        "pad1" => Ok(Ipv6Option::pad1()),
        "padn" => {
            if let Some(data) = optional(item, &["data", "bytes", "value_hex", "hex"]) {
                Ipv6Option::padn_data(option_bytes(data)?).map_err(Into::into)
            } else if let Some(total) = optional(item, &["total_length", "length"]) {
                Ipv6Option::padn(usize::try_from(u64_value(total)?)?).map_err(Into::into)
            } else {
                Ipv6Option::padn(2).map_err(Into::into)
            }
        }
        "router_alert" => Ok(Ipv6Option::router_alert(u16_value(required(
            item,
            &["value"],
        )?)?)),
        "jumbo_payload" => Ok(Ipv6Option::jumbo_payload(u32_value(required(
            item,
            &["length", "jumbo_payload_length"],
        )?)?)),
        "home_address" => Ok(Ipv6Option::home_address_str(text_required(
            item,
            &["address", "home_address"],
        )?)?),
        _ => {
            let option_type = u8_value(required(item, &["option_type", "type"])?)?;
            let data = optional(item, &["data", "bytes", "value_hex", "hex"])
                .map(option_bytes)
                .transpose()?
                .unwrap_or_default();
            Ipv6Option::generic(option_type, data).map_err(Into::into)
        }
    }
}

fn ipv6_option_kind(item: &Map<String, Value>) -> ExampleResult<String> {
    if let Some(text) = text_optional(item, &["kind", "name"]) {
        let normalized = text.to_ascii_lowercase().replace('-', "_");
        if matches!(
            normalized.as_str(),
            "pad1"
                | "padn"
                | "router_alert"
                | "jumbo_payload"
                | "home_address"
                | "unknown"
                | "generic"
        ) {
            return Ok(normalized);
        }
    }
    let Some(option_type) = optional(item, &["option_type", "type"]) else {
        return Ok("unknown".to_string());
    };
    let option_type = u8_value(option_type)?;
    Ok(match option_type {
        IPV6_OPTION_PAD1 => "pad1",
        IPV6_OPTION_PADN => "padn",
        IPV6_OPTION_ROUTER_ALERT if item.contains_key("value") => "router_alert",
        IPV6_OPTION_JUMBO_PAYLOAD
            if item.contains_key("length") || item.contains_key("jumbo_payload_length") =>
        {
            "jumbo_payload"
        }
        IPV6_OPTION_HOME_ADDRESS
            if item.contains_key("address") || item.contains_key("home_address") =>
        {
            "home_address"
        }
        _ => "unknown",
    }
    .to_string())
}

fn ipv6_fragment_layer(plan: &Value) -> ExampleResult<Ipv6FragmentHeader> {
    let fields = layer_fields(plan, "ipv6_fragment")?;
    let mut layer = Ipv6FragmentHeader::new()
        .nh(ipv6_next_header(required(fields, &["next_header", "nh"])?)?)
        .id(u32_value(required(fields, &["identification", "id"])?)?)
        .fragment_offset(u16_value(required(
            fields,
            &["fragment_offset", "offset"],
        )?)?)
        .more_fragments(bool_value(required(fields, &["more_fragments", "m"])?)?);
    if let Some(value) = optional(fields, &["reserved"]) {
        layer = layer.reserved(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["res"]) {
        layer = layer.res(u8_value(value)?);
    }
    Ok(layer)
}

fn ipv6_routing_layer(plan: &Value) -> ExampleResult<Box<dyn Layer>> {
    let fields = layer_fields(plan, "ipv6_routing")?;
    let next_header = ipv6_next_header(required(fields, &["next_header", "nh"])?)?;
    let routing_type = u8_value(required(fields, &["type", "routing_type"])?)?;
    let segments_left = u8_value(required(fields, &["segments_left", "segleft"])?)?;
    let mut addresses = string_array(optional(fields, &["addresses"])).unwrap_or_default();

    if routing_type == IPV6_ROUTING_TYPE_MOBILE {
        let home = addresses.first().map(String::as_str).unwrap_or("::1");
        return Ok(Box::new(
            Ipv6MobileRoutingHeader::new()
                .nh(next_header)
                .segments_left(segments_left)
                .home_address_str(home)?,
        ));
    }

    if routing_type == IPV6_ROUTING_TYPE_SEGMENT {
        let mut layer = Ipv6SegmentRoutingHeader::new()
            .nh(next_header)
            .segments_left(segments_left);
        while addresses.len() <= segments_left as usize {
            addresses.push("::".to_string());
        }
        for address in addresses {
            layer = layer.segment_str(&address)?;
        }
        return Ok(Box::new(layer));
    }

    let mut layer = Ipv6RoutingHeader::new()
        .nh(next_header)
        .routing_type(routing_type)
        .segments_left(segments_left);
    if !addresses.is_empty() {
        let mut type_data = vec![0, 0, 0, 0];
        for address in addresses {
            type_data.extend_from_slice(&Ipv6Addr::from_str(&address)?.octets());
        }
        layer = layer.type_data(type_data);
    }
    Ok(Box::new(layer))
}

fn udp_layer(plan: &Value) -> ExampleResult<Udp> {
    let fields = layer_fields(plan, "udp")?;
    let mut layer = Udp::new()
        .sport(u16_value(required(fields, &["src_port", "sport"])?)?)
        .dport(u16_value(required(fields, &["dst_port", "dport"])?)?);
    if let Some(value) = optional(fields, &["checksum", "chksum"]) {
        layer = layer.chksum(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["length", "len"]) {
        layer = layer.len(u16_value(value)?);
    }
    Ok(layer)
}

fn udp_options_layer(plan: &Value) -> ExampleResult<UdpOptions> {
    let value = udp_options_field(plan).ok_or("packet plan requires udp options")?;
    let object = value
        .as_object()
        .ok_or("udp.options must be an object for UDP surplus materialization")?;
    if object.get("format").and_then(Value::as_str) != Some("udp_surplus_options") {
        return Err("udp.options format must be udp_surplus_options".into());
    }
    validate_udp_options_payload(plan, object)?;

    let items = object
        .get("items")
        .and_then(Value::as_array)
        .ok_or("udp.options.items must be an array")?;
    let mut layer = UdpOptions::new();
    for item in items {
        let item = item
            .as_object()
            .ok_or("udp.options.items entries must be objects")?;
        if udp_option_item_uses_auto_apc(item) {
            layer = layer.additional_payload_checksum();
            continue;
        }
        layer = layer.udp_option(udp_option_item(item)?)?;
    }

    if let Some(checksum) = object.get("option_checksum").and_then(Value::as_object) {
        if let Some(value) = checksum.get("value") {
            layer = layer.option_checksum(u16_value(value)?);
        } else if checksum.get("mode").and_then(Value::as_str) == Some("absent")
            || (checksum.get("mode").and_then(Value::as_str)
                == Some("zero_allowed_when_udp_checksum_zero")
                && udp_checksum_is_zero(plan)?)
        {
            layer = layer.option_checksum(0);
        }
    }

    Ok(layer)
}

fn udp_options_field(plan: &Value) -> Option<&Value> {
    plan.get("fields")
        .and_then(Value::as_object)
        .and_then(|fields| fields.get("udp"))
        .and_then(Value::as_object)
        .and_then(|fields| fields.get("options"))
}

fn udp_checksum_is_zero(plan: &Value) -> ExampleResult<bool> {
    let fields = layer_fields(plan, "udp")?;
    optional(fields, &["checksum", "chksum"])
        .map(u16_value)
        .transpose()
        .map(|value| value == Some(0))
}

fn validate_udp_options_payload(plan: &Value, options: &Map<String, Value>) -> ExampleResult<()> {
    let Some(payload) = options
        .get("application_payload")
        .and_then(Value::as_object)
    else {
        return Ok(());
    };
    let Some(hex) = payload.get("hex").and_then(Value::as_str) else {
        return Ok(());
    };
    if let Ok(actual) = payload_bytes(plan) {
        let declared = decode_hex(hex)?;
        if actual != declared {
            return Err("udp.options application payload does not match payload fields".into());
        }
    }
    Ok(())
}

fn udp_option_item_uses_auto_apc(item: &Map<String, Value>) -> bool {
    item.get("kind").and_then(Value::as_u64) == Some(UDP_OPTION_APC as u64)
        && item.get("checksum").and_then(Value::as_str) == Some("auto_crc32c_application_payload")
}

fn udp_option_item(item: &Map<String, Value>) -> ExampleResult<UdpOption> {
    let kind = u8_value(required(item, &["kind"])?)?;
    if kind == UDP_OPTION_EOL {
        return Ok(UdpOption::end_of_list());
    }
    if kind == UDP_OPTION_NOP {
        return Ok(UdpOption::no_operation());
    }

    let declared_length = usize::try_from(u64_value(required(item, &["length"])?)?)?;
    let data = udp_option_item_data(kind, item)?;
    let actual_length = 2 + data.len();
    if declared_length != actual_length {
        return Err(format!(
            "udp option length mismatch for kind {kind}: declared={declared_length} materialized={actual_length}"
        )
        .into());
    }
    if !(2..=255).contains(&declared_length) {
        return Err(format!("udp option length must fit one byte: {declared_length}").into());
    }

    Ok(match kind {
        UDP_OPTION_APC => {
            UdpOption::additional_payload_checksum(u32::from_be_bytes(data.as_slice().try_into()?))
        }
        UDP_OPTION_MDS => {
            UdpOption::maximum_datagram_size(u16::from_be_bytes(data.as_slice().try_into()?))
        }
        UDP_OPTION_MRDS => UdpOption::maximum_reassembled_datagram_size(
            u16::from_be_bytes(data[..2].try_into()?),
            data[2],
        ),
        UDP_OPTION_REQ => UdpOption::echo_request(u32::from_be_bytes(data.as_slice().try_into()?)),
        UDP_OPTION_RES => UdpOption::echo_response(u32::from_be_bytes(data.as_slice().try_into()?)),
        UDP_OPTION_TIME => UdpOption::timestamp(
            u32::from_be_bytes(data[..4].try_into()?),
            u32::from_be_bytes(data[4..].try_into()?),
        ),
        UDP_OPTION_EXP => {
            let exid = u16::from_be_bytes(data[..2].try_into()?);
            UdpOption::experimental(exid, data[2..].to_vec())
        }
        UDP_OPTION_UEXP => {
            let exid = u16::from_be_bytes(data[..2].try_into()?);
            UdpOption::unsafe_experimental(exid, data[2..].to_vec())
        }
        _ => UdpOption::generic(kind, data),
    })
}

fn udp_option_item_data(kind: u8, item: &Map<String, Value>) -> ExampleResult<Vec<u8>> {
    if let Some(hex) = item.get("data_hex").and_then(Value::as_str) {
        return decode_hex(hex);
    }
    Ok(match kind {
        UDP_OPTION_APC => u32_value(required(item, &["checksum"])?)?
            .to_be_bytes()
            .to_vec(),
        UDP_OPTION_MDS => u16_value(required(item, &["max_datagram_size"])?)?
            .to_be_bytes()
            .to_vec(),
        UDP_OPTION_MRDS => {
            let mut data = u16_value(required(item, &["max_reassembled_size"])?)?
                .to_be_bytes()
                .to_vec();
            data.push(u8_value(required(item, &["segment_count"])?)?);
            data
        }
        UDP_OPTION_REQ | UDP_OPTION_RES => u32_value(required(item, &["token"])?)?
            .to_be_bytes()
            .to_vec(),
        UDP_OPTION_TIME => {
            let mut data = u32_value(required(item, &["tsval"])?)?
                .to_be_bytes()
                .to_vec();
            data.extend_from_slice(&u32_value(required(item, &["tsecr"])?)?.to_be_bytes());
            data
        }
        _ => {
            let declared_length = usize::try_from(u64_value(required(item, &["length"])?)?)?;
            vec![0; declared_length.saturating_sub(2)]
        }
    })
}

fn tcp_layer(plan: &Value, next_layer: Option<&str>) -> ExampleResult<Tcp> {
    let fields = layer_fields(plan, "tcp")?;
    let source_port = u16_value(required(fields, &["src_port", "sport"])?)?;
    let mut destination_port = u16_value(required(fields, &["dst_port", "dport"])?)?;
    if next_layer == Some("bgp") {
        if source_port != BGP_PORT && destination_port != BGP_PORT {
            destination_port = BGP_PORT;
        }
    }
    let mut layer = Tcp::new()
        .sport(source_port)
        .dport(destination_port)
        .seq(u32_value(required(fields, &["sequence", "seq"])?)?)
        .ack(u32_value(required(fields, &["acknowledgement", "ack"])?)?)
        .reserved(u8_value(required(fields, &["reserved"])?)?)
        .flags(tcp_flags(required(fields, &["flags"])?)?)
        .window(u16_value(required(fields, &["window"])?)?)
        .urgptr(u16_value(required(fields, &["urgent_pointer", "urgptr"])?)?);
    if let Some(value) = optional(fields, &["checksum", "chksum"]) {
        layer = layer.chksum(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["data_offset", "dataofs"]) {
        layer = layer.dataofs(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["options"]) {
        layer = layer.options(option_bytes(value)?);
    }
    Ok(layer)
}

fn bgp_layer(plan: &Value) -> ExampleResult<Bgp> {
    let fields = layer_fields(plan, "bgp")?;
    let message_type = bgp_message_type(required(fields, &["message_type", "type"])?)?;
    let mut layer = match message_type {
        BGP_TYPE_OPEN => bgp_open_layer(fields)?,
        BGP_TYPE_UPDATE => bgp_update_layer(fields)?,
        BGP_TYPE_NOTIFICATION => bgp_notification_layer(fields)?,
        BGP_TYPE_KEEPALIVE => Bgp::keepalive(),
        BGP_TYPE_ROUTE_REFRESH => bgp_route_refresh_layer(fields)?,
        other => {
            return Err(format!(
                "unsupported BGP message type {other}; raw unknown BGP bodies are not constructible through the public Bgp layer"
            )
            .into())
        }
    };

    if let Some(value) = optional(fields, &["marker"]) {
        layer = layer.marker(bgp_marker(value)?);
    }
    if let Some(value) = optional(fields, &["length", "len"]) {
        layer = layer.length(u16_value(value)?);
    }
    Ok(layer)
}

fn bgp_open_layer(fields: &Map<String, Value>) -> ExampleResult<Bgp> {
    if let Some(body) = optional(fields, &["body", "body_hex", "raw_body", "raw"]) {
        return bgp_open_from_body(&option_bytes(body)?);
    }

    let mut layer = Bgp::open()
        .version(
            optional(fields, &["version"])
                .map(u8_value)
                .transpose()?
                .unwrap_or(4),
        )
        .my_as(
            optional(fields, &["my_as", "asn"])
                .map(u16_value)
                .transpose()?
                .unwrap_or(0),
        )
        .hold_time(
            optional(fields, &["hold_time"])
                .map(u16_value)
                .transpose()?
                .unwrap_or(0),
        )
        .bgp_id(
            optional(fields, &["bgp_id", "bgp_identifier"])
                .map(ipv4_text)
                .transpose()?
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
        );

    if let Some(value) = optional(
        fields,
        &[
            "optional_parameters",
            "optional_parameters_hex",
            "opt_params",
            "capabilities",
        ],
    ) {
        if let Some(items) = value.as_array() {
            layer = layer.capabilities(bgp_capabilities(items)?);
        } else {
            for param in bgp_opt_params_from_bytes(&option_bytes(value)?)? {
                layer = layer.push_param(param);
            }
        }
    }
    if let Some(value) = optional(fields, &["opt_param_len"]) {
        layer = layer.opt_params_len(u8_value(value)?);
    }
    Ok(layer)
}

fn bgp_open_from_body(body: &[u8]) -> ExampleResult<Bgp> {
    if body.len() < 10 {
        return Err(format!(
            "BGP OPEN body must be at least 10 bytes, got {}",
            body.len()
        )
        .into());
    }
    let mut layer = Bgp::open()
        .version(body[0])
        .my_as(u16::from_be_bytes([body[1], body[2]]))
        .hold_time(u16::from_be_bytes([body[3], body[4]]))
        .bgp_id(Ipv4Addr::new(body[5], body[6], body[7], body[8]))
        .opt_params_len(body[9]);
    for param in bgp_opt_params_from_bytes(&body[10..])? {
        layer = layer.push_param(param);
    }
    Ok(layer)
}

fn bgp_update_layer(fields: &Map<String, Value>) -> ExampleResult<Bgp> {
    if let Some(body) = optional(fields, &["body", "body_hex", "raw_body", "raw"]) {
        return bgp_update_from_body(&option_bytes(body)?);
    }

    let mut layer = Bgp::update();
    if let Some(value) = optional(fields, &["withdrawn_routes", "withdrawn_routes_hex"]) {
        for prefix in bgp_prefixes(value, 32)? {
            layer = layer.withdraw(prefix);
        }
    }
    if let Some(value) = optional(
        fields,
        &["path_attributes", "path_attributes_hex", "path_attr"],
    ) {
        for attr in bgp_path_attributes(value)? {
            layer = layer.attribute(attr);
        }
    }
    if let Some(value) = optional(fields, &["nlri", "nlri_hex"]) {
        for prefix in bgp_prefixes(value, 32)? {
            layer = layer.nlri(prefix);
        }
    }
    if let Some(value) = optional(fields, &["withdrawn_routes_len"]) {
        layer = layer.withdrawn_len(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["path_attr_len"]) {
        layer = layer.attr_len(u16_value(value)?);
    }
    Ok(layer)
}

fn bgp_update_from_body(body: &[u8]) -> ExampleResult<Bgp> {
    if body.len() < 4 {
        return Err(format!(
            "BGP UPDATE body must be at least 4 bytes, got {}",
            body.len()
        )
        .into());
    }
    let withdrawn_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + withdrawn_len + 2 {
        return Err("BGP UPDATE body is truncated before path-attribute length".into());
    }
    let withdrawn = &body[2..2 + withdrawn_len];
    let attr_len_offset = 2 + withdrawn_len;
    let attr_len = u16::from_be_bytes([body[attr_len_offset], body[attr_len_offset + 1]]) as usize;
    let attrs_start = attr_len_offset + 2;
    if body.len() < attrs_start + attr_len {
        return Err("BGP UPDATE body is truncated inside path attributes".into());
    }
    let attrs = &body[attrs_start..attrs_start + attr_len];
    let nlri = &body[attrs_start + attr_len..];

    let mut layer = Bgp::update()
        .withdrawn_len(withdrawn_len as u16)
        .attr_len(attr_len as u16);
    for prefix in bgp_prefixes_from_bytes(withdrawn, 32)? {
        layer = layer.withdraw(prefix);
    }
    for attr in bgp_path_attributes_from_bytes(attrs)? {
        layer = layer.attribute(attr);
    }
    for prefix in bgp_prefixes_from_bytes(nlri, 32)? {
        layer = layer.nlri(prefix);
    }
    Ok(layer)
}

fn bgp_notification_layer(fields: &Map<String, Value>) -> ExampleResult<Bgp> {
    if let Some(body) = optional(fields, &["body", "body_hex", "raw_body", "raw"]) {
        let bytes = option_bytes(body)?;
        if bytes.len() < 2 {
            return Err("BGP NOTIFICATION body must contain code and subcode".into());
        }
        return Ok(Bgp::notification(bytes[0], bytes[1]).data(bytes[2..].to_vec()));
    }

    let code = optional(fields, &["error_code", "code"])
        .map(u8_value)
        .transpose()?
        .unwrap_or(0);
    let subcode = optional(fields, &["error_subcode", "subcode"])
        .map(u8_value)
        .transpose()?
        .unwrap_or(0);
    let mut layer = Bgp::notification(code, subcode);
    if let Some(value) = optional(fields, &["data"]) {
        layer = layer.data(option_bytes(value)?);
    }
    Ok(layer)
}

fn bgp_route_refresh_layer(fields: &Map<String, Value>) -> ExampleResult<Bgp> {
    if let Some(body) = optional(fields, &["body", "body_hex", "raw_body", "raw"]) {
        let bytes = option_bytes(body)?;
        if bytes.len() != 4 {
            return Err(format!(
                "BGP ROUTE-REFRESH body must contain exactly 4 bytes, got {}",
                bytes.len()
            )
            .into());
        }
        return Ok(
            Bgp::route_refresh(u16::from_be_bytes([bytes[0], bytes[1]]), bytes[3])
                .subtype(bytes[2]),
        );
    }
    if optional(fields, &["orf_data"]).is_some() {
        return Err(
            "BGP ROUTE-REFRESH orf_data is not constructible through the public Bgp layer".into(),
        );
    }
    let afi = optional(fields, &["afi"])
        .map(bgp_afi)
        .transpose()?
        .unwrap_or(AFI_IPV4);
    let safi = optional(fields, &["safi"])
        .map(bgp_safi)
        .transpose()?
        .unwrap_or(SAFI_UNICAST);
    let subtype = optional(fields, &["subtype"])
        .map(u8_value)
        .transpose()?
        .unwrap_or(0);
    Ok(Bgp::route_refresh(afi, safi).subtype(subtype))
}

fn bgp_message_type(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "open" => Ok(BGP_TYPE_OPEN),
            "update" => Ok(BGP_TYPE_UPDATE),
            "notification" => Ok(BGP_TYPE_NOTIFICATION),
            "keepalive" | "keep-alive" => Ok(BGP_TYPE_KEEPALIVE),
            "route-refresh" => Ok(BGP_TYPE_ROUTE_REFRESH),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn bgp_marker(value: &Value) -> ExampleResult<[u8; BGP_MARKER_LEN]> {
    if let Some(number) = value.as_u64() {
        let mut marker = [0u8; BGP_MARKER_LEN];
        marker[8..].copy_from_slice(&number.to_be_bytes());
        return Ok(marker);
    }
    fixed_16_bytes(value, "bgp.marker")
}

fn bgp_afi(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "ipv4" | "ip" => Ok(AFI_IPV4),
            "ipv6" => Ok(AFI_IPV6),
            _ => u16_text(text),
        };
    }
    u16_value(value)
}

fn bgp_safi(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "unicast" | "nlri-unicast" => Ok(SAFI_UNICAST),
            "multicast" => Ok(SAFI_MULTICAST),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn bgp_opt_params_from_bytes(bytes: &[u8]) -> ExampleResult<Vec<BgpOptParam>> {
    let mut params = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let (param, remaining) = BgpOptParam::decode(rest)?;
        params.push(param);
        rest = remaining;
    }
    Ok(params)
}

fn bgp_capabilities(items: &[Value]) -> ExampleResult<Vec<BgpCapability>> {
    items.iter().map(bgp_capability).collect()
}

fn bgp_capability(value: &Value) -> ExampleResult<BgpCapability> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "ipv4-unicast" | "multiprotocol-ipv4-unicast" | "mp-ipv4-unicast" => {
                Ok(BgpCapability::ipv4_unicast())
            }
            "ipv6-unicast" | "multiprotocol-ipv6-unicast" | "mp-ipv6-unicast" => {
                Ok(BgpCapability::ipv6_unicast())
            }
            "route-refresh" => Ok(BgpCapability::route_refresh()),
            _ => Ok(BgpCapability::raw(u8_text(text)?, Vec::new())),
        };
    }

    let object = value
        .as_object()
        .ok_or_else(|| format!("BGP capability must be an object/string, got {value:?}"))?;
    if let Some(kind) = optional(object, &["name", "kind", "type"]) {
        if let Some(text) = kind.as_str() {
            match text.to_ascii_lowercase().replace('_', "-").as_str() {
                "multiprotocol" | "mp" => {
                    let afi = bgp_afi(required(object, &["afi"])?)?;
                    let safi = bgp_safi(required(object, &["safi"])?)?;
                    return Ok(BgpCapability::multiprotocol(afi, safi));
                }
                "four-octet-as" | "four-byte-as" | "4-octet-as" => {
                    let asn = u32_value(required(object, &["asn", "as"])?)?;
                    return Ok(BgpCapability::four_octet_as(asn));
                }
                "route-refresh" => return Ok(BgpCapability::route_refresh()),
                "graceful-restart" => {
                    let flags_time = optional(object, &["flags_time", "restart_time"])
                        .map(u16_value)
                        .transpose()?
                        .unwrap_or(0);
                    return Ok(BgpCapability::graceful_restart(flags_time, &[]));
                }
                "add-path" => {
                    return Ok(BgpCapability::raw(
                        CAP_ADD_PATH,
                        optional(object, &["value", "data", "cap_data"])
                            .map(option_bytes)
                            .transpose()?
                            .unwrap_or_default(),
                    ));
                }
                _ => {}
            }
        }
    }
    let code = optional(object, &["code", "capability_code"])
        .map(bgp_capability_code)
        .transpose()?
        .unwrap_or(CAP_MULTIPROTOCOL);
    let value = optional(object, &["value", "data", "cap_data"])
        .map(option_bytes)
        .transpose()?
        .unwrap_or_default();
    Ok(BgpCapability::raw(code, value))
}

fn bgp_capability_code(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "multiprotocol" | "mp" => Ok(CAP_MULTIPROTOCOL),
            "route-refresh" => Ok(CAP_ROUTE_REFRESH),
            "graceful-restart" => Ok(CAP_GRACEFUL_RESTART),
            "four-octet-as" | "four-byte-as" | "4-octet-as" => Ok(CAP_FOUR_OCTET_AS),
            "add-path" => Ok(CAP_ADD_PATH),
            "enhanced-route-refresh" => Ok(CAP_ENHANCED_ROUTE_REFRESH),
            "route-refresh-old" | "old-route-refresh" => Ok(CAP_ROUTE_REFRESH_OLD),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn bgp_prefixes(value: &Value, max_length: u8) -> ExampleResult<Vec<BgpPrefix>> {
    if value.as_array().is_some()
        && !value
            .as_object()
            .is_some_and(|object| object.contains_key("hex"))
    {
        return array_values(value)?
            .iter()
            .map(|item| bgp_prefix(item, max_length))
            .collect();
    }
    bgp_prefixes_from_bytes(&option_bytes(value)?, max_length)
}

fn bgp_prefixes_from_bytes(mut bytes: &[u8], max_length: u8) -> ExampleResult<Vec<BgpPrefix>> {
    let mut prefixes = Vec::new();
    while !bytes.is_empty() {
        let (prefix, consumed) = BgpPrefix::decode_prefix_with_max(bytes, max_length)?;
        prefixes.push(prefix);
        bytes = &bytes[consumed..];
    }
    Ok(prefixes)
}

fn bgp_prefix(value: &Value, max_length: u8) -> ExampleResult<BgpPrefix> {
    if let Some(text) = value.as_str() {
        return bgp_prefix_text(text, max_length);
    }
    let object = value
        .as_object()
        .ok_or_else(|| format!("BGP prefix must be an object/string, got {value:?}"))?;
    if object.contains_key("hex") {
        let prefixes = bgp_prefixes_from_bytes(&option_bytes(value)?, max_length)?;
        return prefixes
            .into_iter()
            .next()
            .ok_or_else(|| "BGP prefix hex value is empty".into());
    }
    let prefix = text_value(required(object, &["prefix", "network", "address"])?)?;
    let length = optional(object, &["length", "prefix_len", "prefix_length"])
        .map(u8_value)
        .transpose()?;
    let text = if prefix.contains('/') {
        prefix.to_string()
    } else {
        format!(
            "{prefix}/{}",
            length.ok_or("BGP prefix object without / requires length")?
        )
    };
    bgp_prefix_text(&text, max_length)
}

fn bgp_prefix_text(text: &str, max_length: u8) -> ExampleResult<BgpPrefix> {
    let (address, length) = text
        .split_once('/')
        .ok_or_else(|| format!("BGP prefix must be address/length, got {text:?}"))?;
    let length = u8_text(length)?;
    if address.contains(':') {
        if max_length < 128 {
            return Err("IPv6 BGP prefix is not valid in IPv4 NLRI fields".into());
        }
        return Ok(BgpPrefix::from_ipv6(Ipv6Addr::from_str(address)?, length)?);
    }
    Ok(BgpPrefix::from_ipv4(Ipv4Addr::from_str(address)?, length)?)
}

fn bgp_path_attributes(value: &Value) -> ExampleResult<Vec<BgpPathAttribute>> {
    if value.as_array().is_some()
        && !value
            .as_object()
            .is_some_and(|object| object.contains_key("hex"))
    {
        return array_values(value)?
            .iter()
            .map(bgp_path_attribute)
            .collect();
    }
    bgp_path_attributes_from_bytes(&option_bytes(value)?)
}

fn bgp_path_attributes_from_bytes(mut bytes: &[u8]) -> ExampleResult<Vec<BgpPathAttribute>> {
    let mut attributes = Vec::new();
    while !bytes.is_empty() {
        let before = bytes.len();
        let (attribute, consumed) = decode_attribute(bytes)?;
        if consumed == 0 || consumed > before {
            return Err("BGP path attribute decoder made no progress".into());
        }
        attributes.push(attribute);
        bytes = &bytes[consumed..];
    }
    Ok(attributes)
}

fn bgp_path_attribute(value: &Value) -> ExampleResult<BgpPathAttribute> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "origin" => Ok(BgpPathAttribute::origin(0)),
            "as-path" => Ok(BgpPathAttribute::as_sequence(&[])),
            "next-hop" => Ok(BgpPathAttribute::next_hop(Ipv4Addr::UNSPECIFIED)),
            "atomic-aggregate" => Ok(BgpPathAttribute::atomic_aggregate()),
            other => Err(format!("unsupported BGP path attribute shorthand: {other}").into()),
        };
    }
    let object = value
        .as_object()
        .ok_or_else(|| format!("BGP path attribute must be an object/string, got {value:?}"))?;
    if object.contains_key("hex") {
        return bgp_path_attributes_from_bytes(&option_bytes(value)?)?
            .into_iter()
            .next()
            .ok_or_else(|| "BGP path attribute hex value is empty".into());
    }

    let type_code = bgp_attribute_type(required(object, &["type", "type_code", "kind"])?)?;
    let mut attribute = match type_code {
        ATTR_ORIGIN => BgpPathAttribute::origin(
            optional(object, &["origin", "value"])
                .map(bgp_origin)
                .transpose()?
                .unwrap_or(0),
        ),
        ATTR_AS_PATH => BgpPathAttribute::as_sequence(&bgp_asns(object)?),
        ATTR_NEXT_HOP => BgpPathAttribute::next_hop(
            optional(object, &["next_hop", "value", "address"])
                .map(ipv4_text)
                .transpose()?
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
        ),
        ATTR_MULTI_EXIT_DISC => BgpPathAttribute::multi_exit_disc(
            optional(object, &["metric", "value"])
                .map(u32_value)
                .transpose()?
                .unwrap_or(0),
        ),
        ATTR_LOCAL_PREF => BgpPathAttribute::local_pref(
            optional(object, &["preference", "value"])
                .map(u32_value)
                .transpose()?
                .unwrap_or(0),
        ),
        ATTR_ATOMIC_AGGREGATE => BgpPathAttribute::atomic_aggregate(),
        ATTR_AGGREGATOR => BgpPathAttribute::aggregator(
            optional(object, &["asn", "as"])
                .map(u16_value)
                .transpose()?
                .unwrap_or(0),
            optional(object, &["address", "addr", "bgp_id", "bgp_identifier"])
                .map(ipv4_text)
                .transpose()?
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
        ),
        ATTR_COMMUNITIES => BgpPathAttribute::communities(&bgp_communities(object)?),
        ATTR_EXTENDED_COMMUNITIES => {
            BgpPathAttribute::extended_communities(&bgp_extended_communities(object)?)
        }
        ATTR_LARGE_COMMUNITY => {
            BgpPathAttribute::large_communities(&bgp_large_communities(object)?)
        }
        ATTR_AS4_PATH => BgpPathAttribute::as_sequence4(&bgp_asns(object)?),
        ATTR_AS4_AGGREGATOR => BgpPathAttribute::as4_aggregator(
            optional(object, &["asn", "as"])
                .map(u32_value)
                .transpose()?
                .unwrap_or(0),
            optional(object, &["address", "addr", "bgp_id", "bgp_identifier"])
                .map(ipv4_text)
                .transpose()?
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
        ),
        ATTR_MP_REACH_NLRI => bgp_mp_reach_attribute(object)?,
        ATTR_MP_UNREACH_NLRI => bgp_mp_unreach_attribute(object)?,
        other => BgpPathAttribute::unknown(
            other,
            optional(object, &["value", "data", "raw"])
                .map(option_bytes)
                .transpose()?
                .unwrap_or_default(),
        ),
    };
    if let Some(flags) = optional(object, &["flags"]) {
        attribute = attribute.with_flags(u8_value(flags)?);
    }
    Ok(attribute)
}

fn bgp_attribute_type(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "origin" => Ok(ATTR_ORIGIN),
            "as-path" => Ok(ATTR_AS_PATH),
            "next-hop" => Ok(ATTR_NEXT_HOP),
            "multi-exit-disc" | "med" => Ok(ATTR_MULTI_EXIT_DISC),
            "local-pref" => Ok(ATTR_LOCAL_PREF),
            "atomic-aggregate" => Ok(ATTR_ATOMIC_AGGREGATE),
            "aggregator" => Ok(ATTR_AGGREGATOR),
            "communities" | "community" => Ok(ATTR_COMMUNITIES),
            "mp-reach-nlri" => Ok(ATTR_MP_REACH_NLRI),
            "mp-unreach-nlri" => Ok(ATTR_MP_UNREACH_NLRI),
            "extended-communities" => Ok(ATTR_EXTENDED_COMMUNITIES),
            "as4-path" => Ok(ATTR_AS4_PATH),
            "as4-aggregator" => Ok(ATTR_AS4_AGGREGATOR),
            "large-communities" | "large-community" => Ok(ATTR_LARGE_COMMUNITY),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn bgp_origin(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().as_str() {
            "igp" => Ok(0),
            "egp" => Ok(1),
            "incomplete" => Ok(2),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn bgp_mp_reach_attribute(object: &Map<String, Value>) -> ExampleResult<BgpPathAttribute> {
    if let Some(value) = optional(object, &["value", "data", "raw"]) {
        return Ok(BgpPathAttribute::unknown(
            ATTR_MP_REACH_NLRI,
            option_bytes(value)?,
        ));
    }
    let afi = optional(object, &["afi"])
        .map(bgp_afi)
        .transpose()?
        .unwrap_or(AFI_IPV6);
    let safi = optional(object, &["safi"])
        .map(bgp_safi)
        .transpose()?
        .unwrap_or(SAFI_UNICAST);
    let next_hop = optional(object, &["next_hop", "gateway"])
        .map(bgp_next_hop_bytes)
        .transpose()?
        .unwrap_or_else(|| Ipv6Addr::UNSPECIFIED.octets().to_vec());
    let nlri = optional(object, &["nlri"])
        .map(|value| bgp_prefixes(value, if afi == AFI_IPV6 { 128 } else { 32 }))
        .transpose()?
        .unwrap_or_default();
    if afi == AFI_IPV6 && safi == SAFI_UNICAST && next_hop.len() == 16 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&next_hop);
        return Ok(BgpPathAttribute::mp_reach_ipv6(
            Ipv6Addr::from(octets),
            &nlri,
        ));
    }

    let mut value = Vec::new();
    value.extend_from_slice(&afi.to_be_bytes());
    value.push(safi);
    value.push(next_hop.len() as u8);
    value.extend_from_slice(&next_hop);
    value.push(0);
    for prefix in nlri {
        prefix.encode_prefix(&mut value);
    }
    Ok(BgpPathAttribute::unknown(ATTR_MP_REACH_NLRI, value))
}

fn bgp_mp_unreach_attribute(object: &Map<String, Value>) -> ExampleResult<BgpPathAttribute> {
    if let Some(value) = optional(object, &["value", "data", "raw"]) {
        return Ok(BgpPathAttribute::unknown(
            ATTR_MP_UNREACH_NLRI,
            option_bytes(value)?,
        ));
    }
    let afi = optional(object, &["afi"])
        .map(bgp_afi)
        .transpose()?
        .unwrap_or(AFI_IPV6);
    let safi = optional(object, &["safi"])
        .map(bgp_safi)
        .transpose()?
        .unwrap_or(SAFI_UNICAST);
    let withdrawn = optional(object, &["withdrawn", "withdrawn_routes", "nlri"])
        .map(|value| bgp_prefixes(value, if afi == AFI_IPV6 { 128 } else { 32 }))
        .transpose()?
        .unwrap_or_default();
    if afi == AFI_IPV6 && safi == SAFI_UNICAST {
        return Ok(BgpPathAttribute::mp_unreach_ipv6(&withdrawn));
    }

    let mut value = Vec::new();
    value.extend_from_slice(&afi.to_be_bytes());
    value.push(safi);
    for prefix in withdrawn {
        prefix.encode_prefix(&mut value);
    }
    Ok(BgpPathAttribute::unknown(ATTR_MP_UNREACH_NLRI, value))
}

fn bgp_next_hop_bytes(value: &Value) -> ExampleResult<Vec<u8>> {
    if let Some(text) = value.as_str() {
        if text.contains(':') {
            return Ok(Ipv6Addr::from_str(text)?.octets().to_vec());
        }
        return Ok(Ipv4Addr::from_str(text)?.octets().to_vec());
    }
    option_bytes(value)
}

fn bgp_asns(object: &Map<String, Value>) -> ExampleResult<Vec<u32>> {
    let Some(value) = optional(object, &["asns", "asn", "as_path", "value"]) else {
        return Ok(Vec::new());
    };
    if let Some(items) = value.as_array() {
        return items.iter().map(u32_value).collect();
    }
    Ok(vec![u32_value(value)?])
}

fn bgp_communities(object: &Map<String, Value>) -> ExampleResult<Vec<u32>> {
    let Some(value) = optional(object, &["communities", "community", "value"]) else {
        return Ok(Vec::new());
    };
    if let Some(items) = value.as_array() {
        return items.iter().map(u32_value).collect();
    }
    Ok(vec![u32_value(value)?])
}

fn bgp_extended_communities(object: &Map<String, Value>) -> ExampleResult<Vec<[u8; 8]>> {
    let Some(value) = optional(object, &["communities", "community", "value"]) else {
        return Ok(Vec::new());
    };
    let items = if let Some(items) = value.as_array() {
        items
            .iter()
            .map(|item| fixed_8_bytes(item, "bgp.extended_community"))
            .collect::<ExampleResult<Vec<_>>>()?
    } else {
        vec![fixed_8_bytes(value, "bgp.extended_community")?]
    };
    Ok(items)
}

fn bgp_large_communities(object: &Map<String, Value>) -> ExampleResult<Vec<[u32; 3]>> {
    let Some(value) = optional(object, &["communities", "community", "value"]) else {
        return Ok(Vec::new());
    };
    let values = if let Some(items) = value.as_array() {
        let mut out = Vec::new();
        for item in items {
            if let Some(parts) = item.as_array() {
                if parts.len() != 3 {
                    return Err("BGP large community array items must have 3 integers".into());
                }
                out.push([
                    u32_value(&parts[0])?,
                    u32_value(&parts[1])?,
                    u32_value(&parts[2])?,
                ]);
            } else {
                let bytes = option_bytes(item)?;
                if bytes.len() != 12 {
                    return Err("BGP large community byte values must be 12 bytes".into());
                }
                out.push([
                    u32::from_be_bytes(bytes[0..4].try_into()?),
                    u32::from_be_bytes(bytes[4..8].try_into()?),
                    u32::from_be_bytes(bytes[8..12].try_into()?),
                ]);
            }
        }
        out
    } else {
        let bytes = option_bytes(value)?;
        if bytes.len() != 12 {
            return Err("BGP large community byte value must be 12 bytes".into());
        }
        vec![[
            u32::from_be_bytes(bytes[0..4].try_into()?),
            u32::from_be_bytes(bytes[4..8].try_into()?),
            u32::from_be_bytes(bytes[8..12].try_into()?),
        ]]
    };
    Ok(values)
}

fn icmp_layer(plan: &Value) -> ExampleResult<Icmpv4> {
    let fields = layer_fields(plan, "icmp")?;
    let mut layer = Icmpv4::new()
        .type_(icmp_type(required(fields, &["type"])?, false)?)
        .code(u8_value(required(fields, &["code"])?)?);
    let has_rest_of_header = if let Some(value) = optional(fields, &["rest_of_header"]) {
        layer = layer.rest_of_header(fixed_4_bytes(value, "icmp.rest_of_header")?);
        true
    } else {
        false
    };
    if !has_rest_of_header {
        if let Some(value) = optional(fields, &["id", "identifier"]) {
            layer = layer.id(u16_value(value)?);
        }
        if let Some(value) = optional(fields, &["seq", "sequence"]) {
            layer = layer.seq(u16_value(value)?);
        }
    }
    if let Some(value) = optional(fields, &["pointer"]) {
        layer = layer.pointer(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["gateway"]) {
        layer = layer.gateway(ipv4_text(value)?);
    }
    if let Some(value) = optional(fields, &["length", "len"]) {
        layer = layer.length(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["next_hop_mtu", "mtu_next_hop", "mtu"]) {
        layer = layer.mtu_next_hop(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["num_addrs", "router_num_addrs"]) {
        layer = layer.num_addrs(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["addr_entry_size", "router_address_entry_size"]) {
        layer = layer.addr_entry_size(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["lifetime", "router_lifetime"]) {
        layer = layer.lifetime(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["extended_flags"]) {
        layer = layer.extended_flags(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["extended_l_bit", "l_bit"]) {
        layer = layer.extended_l_bit(bool_value(value)?);
    }
    if let Some(value) = optional(fields, &["extended_state"]) {
        layer = layer.extended_state(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["extended_active"]) {
        layer = layer.extended_active(bool_value(value)?);
    }
    if let Some(value) = optional(fields, &["extended_ipv4"]) {
        layer = layer.extended_ipv4(bool_value(value)?);
    }
    if let Some(value) = optional(fields, &["extended_ipv6"]) {
        layer = layer.extended_ipv6(bool_value(value)?);
    }
    if let Some(value) = optional(fields, &["checksum", "chksum"]) {
        layer = layer.chksum(u16_value(value)?);
    }
    Ok(layer)
}

fn icmpv6_layer(plan: &Value) -> ExampleResult<Icmpv6> {
    let fields = layer_fields(plan, "icmpv6")?;
    let mut layer = Icmpv6::new()
        .type_(icmp_type(required(fields, &["type"])?, true)?)
        .code(u8_value(required(fields, &["code"])?)?);
    if let Some(value) = optional(fields, &["id", "identifier"]) {
        layer = layer.id(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["seq", "sequence"]) {
        layer = layer.seq(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["checksum", "cksum"]) {
        layer = layer.chksum(u16_value(value)?);
    }
    Ok(layer)
}

fn igmp_layer(plan: &Value) -> ExampleResult<Igmp> {
    let fields = layer_fields(plan, "igmp")?;
    let type_code = optional(fields, &["type", "type_code"])
        .map(igmp_type_code)
        .transpose()?
        .unwrap_or(IGMP_TYPE_MEMBERSHIP_QUERY);
    let mut layer = Igmp::new()
        .type_code(type_code)
        .with_code(igmp_code_value(fields)?);
    if let Some(group_address) = igmp_group_address(fields, type_code)? {
        layer = layer.with_group_address(group_address);
    }
    if let Some(checksum) = igmp_checksum_value(fields)? {
        layer = layer.checksum(checksum);
    }
    Ok(layer)
}

fn igmp_query_layer(plan: &Value) -> ExampleResult<IgmpQuery> {
    let igmp_fields = layer_fields(plan, "igmp")?;
    let query_fields = optional_layer_fields(plan, "igmp_query")?;
    igmp_query_layer_from_fields(igmp_fields, query_fields)
}

fn igmp_query_layer_from_fields(
    igmp_fields: &Map<String, Value>,
    query_fields: Option<&Map<String, Value>>,
) -> ExampleResult<IgmpQuery> {
    let mut query =
        IgmpQuery::new().with_raw_flags_qrv(igmp_query_flags_value(igmp_fields, query_fields)?);
    if let Some(value) = optional_igmp_child(igmp_fields, query_fields, &["qqic"]) {
        query = query.with_qqic(u8_value(value)?);
    }
    if let Some(value) = optional_igmp_child(igmp_fields, query_fields, &["number_of_sources"]) {
        query = query.with_number_of_sources(u16_value(value)?);
    }
    if let Some(value) = optional_igmp_child(igmp_fields, query_fields, &["source_addresses"]) {
        query = query.with_source_addresses(igmp_ipv4_list(value)?);
    }
    Ok(query)
}

fn igmp_report_layer(plan: &Value) -> ExampleResult<IgmpReport> {
    let igmp_fields = layer_fields(plan, "igmp")?;
    let report_fields = optional_layer_fields(plan, "igmp_report")?;
    igmp_report_layer_from_fields(igmp_fields, report_fields)
}

fn igmp_report_layer_from_fields(
    igmp_fields: &Map<String, Value>,
    report_fields: Option<&Map<String, Value>>,
) -> ExampleResult<IgmpReport> {
    let mut report =
        IgmpReport::new().with_reserved_flags(igmp_report_flags_value(igmp_fields, report_fields)?);
    if let Some(value) = optional_igmp_child(
        igmp_fields,
        report_fields,
        &["number_of_group_records", "number_of_records"],
    ) {
        report = report.with_number_of_group_records(u16_value(value)?);
    }
    if let Some(value) =
        optional_igmp_child(igmp_fields, report_fields, &["group_records", "records"])
    {
        report = report.with_group_records(igmp_group_records(value)?);
    }
    Ok(report)
}

fn igmp_extension_layer(plan: &Value) -> ExampleResult<IgmpExtension> {
    let fields = layer_fields(plan, "igmp_extension")?;
    igmp_extension_from_fields(fields)
}

fn igmp_inferred_body_layers(plan: &Value) -> ExampleResult<Vec<Box<dyn Layer>>> {
    let igmp_fields = layer_fields(plan, "igmp")?;
    if let Some(value) = optional(igmp_fields, &["raw_body", "raw"]) {
        return Ok(vec![Box::new(Raw::from_bytes(igmp_bytes_value(value)?))]);
    }

    let type_code = optional(igmp_fields, &["type", "type_code"])
        .map(igmp_type_code)
        .transpose()?
        .unwrap_or(IGMP_TYPE_MEMBERSHIP_QUERY);
    let mut layers: Vec<Box<dyn Layer>> = Vec::new();
    if igmp_has_query_body(plan, igmp_fields, type_code)? {
        layers.push(Box::new(igmp_query_layer_from_fields(
            igmp_fields,
            optional_layer_fields(plan, "igmp_query")?,
        )?));
    } else if igmp_has_report_body(plan, igmp_fields, type_code)? {
        layers.push(Box::new(igmp_report_layer_from_fields(
            igmp_fields,
            optional_layer_fields(plan, "igmp_report")?,
        )?));
    }

    layers.extend(igmp_extension_layers(plan, igmp_fields)?);
    if let Some(value) = optional(igmp_fields, &["raw_tail", "tail", "payload"]) {
        layers.push(Box::new(Raw::from_bytes(igmp_bytes_value(value)?)));
    }
    Ok(layers)
}

fn igmp_body_layers_follow(stack: &[String], index: usize) -> bool {
    stack[index + 1..].iter().any(|layer| {
        matches!(
            layer.as_str(),
            "igmp_query" | "igmp_report" | "igmp_extension" | "payload"
        )
    })
}

fn igmp_has_query_body(
    plan: &Value,
    igmp_fields: &Map<String, Value>,
    type_code: u8,
) -> ExampleResult<bool> {
    if type_code != IGMP_TYPE_MEMBERSHIP_QUERY {
        return Ok(false);
    }
    if optional_layer_fields(plan, "igmp_query")?.is_some() {
        return Ok(true);
    }
    Ok([
        "flags_qrv",
        "number_of_sources",
        "qqic",
        "query_flags",
        "raw_flags_qrv",
        "source_addresses",
    ]
    .iter()
    .any(|name| igmp_fields.contains_key(*name)))
}

fn igmp_has_report_body(
    plan: &Value,
    igmp_fields: &Map<String, Value>,
    type_code: u8,
) -> ExampleResult<bool> {
    if type_code == IGMP_TYPE_V3_MEMBERSHIP_REPORT {
        return Ok(true);
    }
    if optional_layer_fields(plan, "igmp_report")?.is_some() {
        return Ok(true);
    }
    Ok([
        "group_records",
        "number_of_group_records",
        "number_of_records",
        "report_flags",
        "reserved_flags",
    ]
    .iter()
    .any(|name| igmp_fields.contains_key(*name)))
}

fn igmp_extension_layers(
    plan: &Value,
    igmp_fields: &Map<String, Value>,
) -> ExampleResult<Vec<Box<dyn Layer>>> {
    if let Some(value) = optional(igmp_fields, &["extension_tlvs", "extensions"]) {
        let mut layers: Vec<Box<dyn Layer>> = Vec::new();
        for item in array_values(value)? {
            let fields = item
                .as_object()
                .ok_or_else(|| format!("IGMP extension TLV must be an object, got {item:?}"))?;
            layers.push(Box::new(igmp_extension_from_fields(fields)?));
        }
        return Ok(layers);
    }

    if let Some(fields) = optional_layer_fields(plan, "igmp_extension")? {
        return Ok(vec![Box::new(igmp_extension_from_fields(fields)?)]);
    }
    Ok(Vec::new())
}

fn igmp_extension_from_fields(fields: &Map<String, Value>) -> ExampleResult<IgmpExtension> {
    let extension_type = optional(fields, &["extension_type", "type"])
        .map(igmp_extension_type_code)
        .transpose()?
        .unwrap_or(IGMP_EXTENSION_TYPE_NOOP);
    let value = optional(fields, &["extension_value", "value", "value_hex"])
        .map(igmp_bytes_value)
        .transpose()?
        .unwrap_or_default();
    let mut extension = IgmpExtension::raw(extension_type, value);
    if let Some(length) = optional(fields, &["extension_length", "length"]) {
        extension = extension.with_extension_length(u16_value(length)?);
    }
    Ok(extension)
}

fn igmp_group_records(value: &Value) -> ExampleResult<Vec<IgmpGroupRecord>> {
    array_values(value)?
        .iter()
        .map(igmp_group_record)
        .collect::<ExampleResult<Vec<_>>>()
}

fn igmp_group_record(value: &Value) -> ExampleResult<IgmpGroupRecord> {
    let fields = value
        .as_object()
        .ok_or_else(|| format!("IGMP group record must be an object, got {value:?}"))?;
    let multicast_address = optional(fields, &["multicast_address", "group_address", "group"])
        .map(igmp_ipv4_value)
        .transpose()?
        .unwrap_or(Ipv4Addr::UNSPECIFIED);
    let mut record = IgmpGroupRecord::raw(
        optional(fields, &["record_type", "type"])
            .map(igmp_record_type_code)
            .transpose()?
            .unwrap_or(IGMP_RECORD_TYPE_MODE_IS_INCLUDE),
        multicast_address,
    );
    if let Some(value) = optional(fields, &["source_addresses", "record_source_addresses"]) {
        record = record.with_source_addresses(igmp_ipv4_list(value)?);
    }
    if let Some(value) = optional(fields, &["number_of_sources", "record_number_of_sources"]) {
        record = record.with_number_of_sources(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["auxiliary_data"]) {
        record = record.with_auxiliary_data(igmp_bytes_value(value)?);
    }
    if let Some(value) = optional(fields, &["auxiliary_data_len", "aux_data_len"]) {
        record = record.with_auxiliary_data_len(u8_value(value)?);
    }
    Ok(record)
}

fn optional_igmp_child<'a>(
    igmp_fields: &'a Map<String, Value>,
    child_fields: Option<&'a Map<String, Value>>,
    names: &[&str],
) -> Option<&'a Value> {
    child_fields
        .and_then(|fields| optional(fields, names))
        .or_else(|| optional(igmp_fields, names))
}

fn igmp_type_code(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace(' ', "-").as_str() {
            "reserved" => Ok(IGMP_TYPE_RESERVED),
            "unassigned" => Ok(IGMP_TYPE_UNASSIGNED_FIRST),
            "membership-query" | "membership_query" => Ok(IGMP_TYPE_MEMBERSHIP_QUERY),
            "v1-membership-report" | "v1_membership_report" => Ok(IGMP_TYPE_V1_MEMBERSHIP_REPORT),
            "dvmrp" | "dvmrp-unsupported-assigned" | "dvmrp_unsupported_assigned" => {
                Ok(IGMP_TYPE_DVMRP)
            }
            "pim-v1" | "pim_v1" | "pim-v1-unsupported-assigned" | "pim_v1_unsupported_assigned" => {
                Ok(IGMP_TYPE_PIM_V1)
            }
            "cisco-trace-unsupported-assigned" | "cisco_trace_unsupported_assigned" => {
                Ok(IGMP_TYPE_CISCO_TRACE_MESSAGES)
            }
            "v2-membership-report" | "v2_membership_report" => Ok(IGMP_TYPE_V2_MEMBERSHIP_REPORT),
            "v2-leave-group" | "v2_leave_group" => Ok(IGMP_TYPE_V2_LEAVE_GROUP),
            "multicast-traceroute-response-unsupported-assigned"
            | "multicast_traceroute_response_unsupported_assigned" => {
                Ok(IGMP_TYPE_MULTICAST_TRACEROUTE_RESPONSE)
            }
            "multicast-traceroute-unsupported-assigned"
            | "multicast_traceroute_unsupported_assigned" => Ok(IGMP_TYPE_MULTICAST_TRACEROUTE),
            "v3-membership-report" | "v3_membership_report" => Ok(IGMP_TYPE_V3_MEMBERSHIP_REPORT),
            "multicast-router-advertisement" | "multicast_router_advertisement" => {
                Ok(IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT)
            }
            "multicast-router-solicitation" | "multicast_router_solicitation" => {
                Ok(IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION)
            }
            "multicast-router-termination" | "multicast_router_termination" => {
                Ok(IGMP_TYPE_MULTICAST_ROUTER_TERMINATION)
            }
            "experimental" => Ok(IGMP_TYPE_EXPERIMENTAL_FIRST),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn igmp_code_value(fields: &Map<String, Value>) -> ExampleResult<u8> {
    let Some(value) = optional(
        fields,
        &[
            "code",
            "max_response_code",
            "max_response_time_tenths",
            "v2_max_response_time_tenths",
            "mrd_advertisement_interval",
            "mrd_reserved",
        ],
    ) else {
        return Ok(IGMP_DEFAULT_CODE);
    };
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace([' ', '-'], "_").as_str() {
            "v1_query_zero" | "zero" | "reserved_zero" | "mrd_reserved" => Ok(0),
            "v2_max_response_time" | "v3_max_response_code" => Ok(100),
            "mrd_advertisement_interval" => Ok(20),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn igmp_checksum_value(fields: &Map<String, Value>) -> ExampleResult<Option<u16>> {
    let Some(value) = optional(fields, &["checksum", "chksum"]) else {
        return Ok(None);
    };
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "derived" | "auto" => Ok(None),
            "explicit" | "explicit_invalid" => Ok(Some(0x1234)),
            "boundary" => Ok(Some(u16::MAX)),
            _ => Ok(Some(u16_text(text)?)),
        };
    }
    Ok(Some(u16_value(value)?))
}

fn igmp_group_address(
    fields: &Map<String, Value>,
    type_code: u8,
) -> ExampleResult<Option<Ipv4Addr>> {
    if let Some(value) = optional(fields, &["group_address", "group", "gaddr"]) {
        return Ok(Some(igmp_ipv4_value(value)?));
    }
    if type_code == IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT
        || optional(fields, &["mrd_query_interval", "mrd_robustness_variable"]).is_some()
    {
        let query_interval = optional(fields, &["mrd_query_interval"])
            .map(u16_value)
            .transpose()?
            .unwrap_or(0);
        let robustness = optional(fields, &["mrd_robustness_variable"])
            .map(u16_value)
            .transpose()?
            .unwrap_or(0);
        let query = query_interval.to_be_bytes();
        let robustness = robustness.to_be_bytes();
        return Ok(Some(Ipv4Addr::new(
            query[0],
            query[1],
            robustness[0],
            robustness[1],
        )));
    }
    Ok(None)
}

fn igmp_query_flags_value(
    igmp_fields: &Map<String, Value>,
    query_fields: Option<&Map<String, Value>>,
) -> ExampleResult<u8> {
    if let Some(value) =
        optional_igmp_child(igmp_fields, query_fields, &["raw_flags_qrv", "flags_qrv"])
    {
        return u8_value(value);
    }
    let mut flags = igmp_flags_value(
        optional_igmp_child(igmp_fields, query_fields, &["query_flags"]),
        &[
            ("zero", 0),
            ("none", 0),
            ("extension", u16::from(IGMP_V3_QUERY_FLAG_EXTENSION)),
            ("unassigned", u16::from(IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK)),
            ("suppress_router_side_processing", 0x08),
            ("qrv", 0x02),
        ],
    )? as u8;
    if let Some(value) = optional_igmp_child(
        igmp_fields,
        query_fields,
        &["suppress_router_side_processing", "s"],
    ) {
        if bool_value(value)? {
            flags |= 0x08;
        } else {
            flags &= !0x08;
        }
    }
    if let Some(value) = optional_igmp_child(
        igmp_fields,
        query_fields,
        &["qrv", "querier_robustness_variable"],
    ) {
        flags = (flags & !0x07) | (u8_value(value)? & 0x07);
    }
    Ok(flags)
}

fn igmp_report_flags_value(
    igmp_fields: &Map<String, Value>,
    report_fields: Option<&Map<String, Value>>,
) -> ExampleResult<u16> {
    if let Some(value) = optional_igmp_child(igmp_fields, report_fields, &["reserved_flags"]) {
        return u16_value(value);
    }
    igmp_flags_value(
        optional_igmp_child(igmp_fields, report_fields, &["report_flags"]),
        &[
            ("zero", 0),
            ("none", 0),
            ("extension", IGMP_V3_REPORT_FLAG_EXTENSION),
            ("unassigned", 0x0001),
        ],
    )
}

fn igmp_flags_value(value: Option<&Value>, mapping: &[(&str, u16)]) -> ExampleResult<u16> {
    let Some(value) = value else {
        return Ok(0);
    };
    if let Some(items) = value.as_array() {
        let mut flags = 0u16;
        for item in items {
            flags |= igmp_flag_value(item, mapping)?;
        }
        return Ok(flags);
    }
    igmp_flag_value(value, mapping)
}

fn igmp_flag_value(value: &Value, mapping: &[(&str, u16)]) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        let normalized = text.to_ascii_lowercase().replace([' ', '-'], "_");
        for (name, bit) in mapping {
            if normalized == *name {
                return Ok(*bit);
            }
        }
        return u16_text(&normalized);
    }
    u16_value(value)
}

fn igmp_record_type_code(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace([' ', '-'], "_").as_str() {
            "reserved" => Ok(0),
            "mode_is_include" => Ok(IGMP_RECORD_TYPE_MODE_IS_INCLUDE),
            "mode_is_exclude" => Ok(IGMP_RECORD_TYPE_MODE_IS_EXCLUDE),
            "change_to_include_mode" => Ok(IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE),
            "change_to_exclude_mode" => Ok(IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE),
            "allow_new_sources" => Ok(IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES),
            "block_old_sources" => Ok(IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES),
            "unknown" => Ok(0xc8),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn igmp_extension_type_code(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace([' ', '-'], "_").as_str() {
            "noop" | "no_op" => Ok(IGMP_EXTENSION_TYPE_NOOP),
            "unassigned" => Ok(IGMP_EXTENSION_TYPE_UNASSIGNED_FIRST),
            "experimental" => Ok(IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST),
            _ => u16_text(text),
        };
    }
    u16_value(value)
}

fn igmp_ipv4_list(value: &Value) -> ExampleResult<Vec<Ipv4Addr>> {
    if let Some(text) = value.as_str() {
        return parse_ipv4_list(text);
    }
    array_values(value)?
        .iter()
        .map(|item| {
            if let Some(fields) = item.as_object() {
                igmp_ipv4_value(required(fields, &["address", "ip", "value"])?)
            } else {
                igmp_ipv4_value(item)
            }
        })
        .collect::<ExampleResult<Vec<_>>>()
}

fn igmp_ipv4_value(value: &Value) -> ExampleResult<Ipv4Addr> {
    let text = text_value(value)?;
    Ok(match text.to_ascii_lowercase().as_str() {
        "zero" | "zero_general_query" => Ipv4Addr::UNSPECIFIED,
        "all_systems" => IGMP_ALL_SYSTEMS_GROUP,
        "all_routers" => IGMP_ALL_ROUTERS_GROUP,
        "all_snoopers" => Ipv4Addr::new(224, 0, 0, 106),
        "documentation_multicast" => Ipv4Addr::new(233, 252, 0, 17),
        "ssm_documentation_multicast" => Ipv4Addr::new(232, 0, 0, 17),
        "non_multicast_override" => Ipv4Addr::new(192, 0, 2, 99),
        "documentation_ipv4" => Ipv4Addr::new(192, 0, 2, 44),
        _ => Ipv4Addr::from_str(text)?,
    })
}

fn igmp_bytes_value(value: &Value) -> ExampleResult<Vec<u8>> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().as_str() {
            "empty" => Ok(Vec::new()),
            "raw" => Ok(vec![0xde, 0xad, 0xbe, 0xef]),
            "padded_to_word" => Ok(vec![0xaa, 0xbb, 0xcc, 0xdd]),
            "unknown_type" => Ok(vec![0x75, 0x6e, 0x6b, 0x6e]),
            "unsupported_assigned_type" => Ok(vec![0x64, 0x76, 0x6d, 0x72]),
            "ignored_extra_octets" => Ok(vec![0xaa, 0xbb, 0xcc, 0xdd]),
            "e_flag_clear_extension_bytes" => Ok(vec![0x00, 0x00, 0x00, 0x00]),
            _ => option_bytes(value),
        };
    }
    option_bytes(value)
}

fn dns_layer(plan: &Value) -> ExampleResult<Dns> {
    let fields = layer_fields(plan, "dns")?;
    let transaction_id = optional(fields, &["transaction_id", "id"])
        .map(u16_value)
        .transpose()?
        .unwrap_or(0);
    let is_response = optional(fields, &["is_response"])
        .map(bool_value)
        .transpose()?
        .unwrap_or(false);
    let response_code = optional(fields, &["response_code"])
        .map(dns_response_code)
        .transpose()?
        .unwrap_or(0);
    let opcode = optional(fields, &["opcode"])
        .map(dns_opcode)
        .transpose()?
        .unwrap_or(DNS_OPCODE_QUERY);
    let mut layer = Dns::new()
        .id(transaction_id)
        .flags(dns_flags(fields)?)
        .response(is_response)
        .opcode(opcode)
        .rcode(response_code);

    if let Some(questions) = optional(fields, &["questions"]) {
        for question in array_values(questions)? {
            layer = layer.question(dns_question(question)?);
        }
    }

    if let Some(answers) = optional(fields, &["answers"]) {
        for answer in array_values(answers)? {
            if let Some(object) = answer.as_object() {
                layer = layer.answer(dns_record(object)?);
            }
        }
    }

    if let Some(authorities) = optional(fields, &["authority", "authorities"]) {
        for authority in array_values(authorities)? {
            if let Some(object) = authority.as_object() {
                layer = layer.authority(dns_record(object)?);
            }
        }
    }

    if let Some(additionals) = optional(fields, &["additional", "additionals"]) {
        for additional in array_values(additionals)? {
            if let Some(object) = additional.as_object() {
                layer = layer.additional(dns_record(object)?);
            }
        }
    }

    Ok(layer)
}

fn dns_question(question: &Value) -> ExampleResult<DnsQuestion> {
    let (qname, qtype, qclass) = if let Some(object) = question.as_object() {
        let qname = text_optional(object, &["qname", "name"]).unwrap_or("example.com.");
        let qtype = optional(object, &["qtype", "type"])
            .map(dns_record_type)
            .transpose()?
            .unwrap_or(DNS_TYPE_A);
        let qclass = optional(object, &["qclass", "class", "record_class"])
            .map(dns_class)
            .transpose()?;
        (qname, qtype, qclass)
    } else {
        (
            question.as_str().unwrap_or("example.com."),
            DNS_TYPE_A,
            None,
        )
    };
    let dns_question = DnsQuestion::new(DnsName::parse(qname)?, qtype);
    Ok(match qclass {
        Some(class) => dns_question.class(class),
        None => dns_question,
    })
}

fn dhcp_layer(plan: &Value) -> ExampleResult<Dhcp> {
    let fields = layer_fields(plan, "dhcp")?;
    // The fixed BOOTP header fields are optional: a minimal live-friendly DHCP
    // plan emits only op/flags/options and relies on `Dhcp::new()` defaults
    // (BOOTP_REQUEST op, Ethernet htype, hlen 6, xid 0, zero MAC, unspecified
    // addresses) for anything it does not set. Honor every field the plan does
    // provide and leave the rest at their protocol-correct defaults.
    let mut layer = Dhcp::new();
    if let Some(value) = optional(fields, &["op"]) {
        layer = layer.op(dhcp_op(value)?);
    }
    if let Some(value) = optional(fields, &["hardware_type", "htype"]) {
        layer = layer.hardware_type(hardware_type_value(value)? as u8);
    }
    if let Some(value) = optional(fields, &["hardware_length", "hlen"]) {
        layer = layer.hardware_len(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["transaction_id", "xid"]) {
        layer = layer.xid(u32_value(value)?);
    }
    if let Some(value) = optional(fields, &["flags"]) {
        layer = layer.flags(dhcp_flags(value)?);
    }
    if let Some(value) = optional(fields, &["client_ip", "ciaddr"]) {
        layer = layer.ciaddr(Ipv4Addr::from_str(text_value(value)?)?);
    }
    if let Some(value) = optional(fields, &["your_ip", "yiaddr"]) {
        layer = layer.yiaddr(Ipv4Addr::from_str(text_value(value)?)?);
    }
    if let Some(value) = optional(fields, &["client_hardware_address", "chaddr"]) {
        layer = layer.chaddr(mac_bytes(text_value(value)?)?);
    }
    if let Some(options) = optional(fields, &["options"]) {
        layer = layer.options(dhcp_options(options)?);
    }
    Ok(layer)
}

/// Materialize a RIP message (RFC 1058 / RFC 2453, IPv4 UDP port 520) from a
/// plan.
///
/// The plan's `fields.rip` object mirrors the oracle RIP layer spec and the
/// Scapy reference backend's key names: the 4-octet header
/// (`command`/`version`/`reserved`), a `entries` list of 20-octet route entries
/// (`address_family`/`route_tag`/`address`/`subnet_mask`/`next_hop`/`metric`),
/// and an optional `auth` block (AFI 0xFFFF) for simple-password or keyed
/// message-digest authentication. Every field the plan provides is honored
/// through the public `Rip`/`RipEntry`/`RipAuth` builders; anything it omits
/// stays at the protocol-correct `Rip::new()` default (Response command,
/// version 2, reserved 0). The composed `Rip` rides the plan's UDP/IPv4 stack
/// and `compile()` (driven by `build_packet`) auto-fills lengths, ports, and the
/// keyed digest when the caller left them unset.
fn rip_layer(plan: &Value) -> ExampleResult<Rip> {
    let fields = layer_fields(plan, "rip")?;
    let mut layer = Rip::new();

    // The command is required (RFC 1058 §3.1); accept a named command
    // ("request"/"response"/…) or a numeric code, mirroring the Scapy backend.
    layer = layer.command_code(rip_command_code(required(fields, &["command", "cmd"])?)?);
    if let Some(value) = optional(fields, &["version"]) {
        layer = layer.version(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["reserved", "null"]) {
        layer = layer.reserved(u16_value(value)?);
    }

    // Authentication (AFI 0xFFFF) precedes the route entries on the wire; attach
    // it through the public `Rip::auth` builder so compile() lays the leading
    // auth entry (and, for keyed digest, the trailing digest block) in order.
    if let Some(value) = optional(fields, &["auth"]) {
        let (auth, key) = rip_auth(value)?;
        layer = layer.auth(auth, key);
    }

    if let Some(value) = optional(fields, &["entries"]) {
        for entry in array_values(value)? {
            layer = layer.entry(rip_entry(entry)?);
        }
    }

    Ok(layer)
}

/// Resolve a RIP command (named string or numeric) to its wire octet.
///
/// Mirrors the Scapy `_rip_command` mapping so a named command materializes to
/// the same code; unknown strings parse as a numeric literal and numeric values
/// pass through.
fn rip_command_code(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        let lowered = text.to_ascii_lowercase().replace([' ', '-'], "_");
        return match lowered.as_str() {
            "request" => Ok(1),
            "response" => Ok(2),
            "update_request" => Ok(9),
            "update_response" => Ok(10),
            "update_ack" | "update_acknowledge" => Ok(11),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

/// Build one 20-octet RIP route entry from a plan entry object.
///
/// Reads the same per-entry keys as the Scapy reference `_rip_entry`
/// (`address_family`/`route_tag`/`address`/`subnet_mask`/`next_hop`/`metric`,
/// with the short aliases the backend accepts) and applies each through the
/// caller-set `RipEntry` field setters so the compiled entry matches the plan.
fn rip_entry(value: &Value) -> ExampleResult<RipEntry> {
    let entry = value
        .as_object()
        .ok_or_else(|| format!("RIP entry must be an object, got {value:?}"))?;
    let mut route = RipEntry::new();
    if let Some(value) = optional(entry, &["address_family", "af"]) {
        route = route.address_family(u16_value(value)?);
    }
    if let Some(value) = optional(entry, &["route_tag", "tag", "routetag"]) {
        route = route.route_tag(u16_value(value)?);
    }
    if let Some(value) = optional(entry, &["address", "addr"]) {
        route = route.address(ipv4_text(value)?);
    }
    if let Some(value) = optional(entry, &["subnet_mask", "mask"]) {
        route = route.subnet_mask(ipv4_text(value)?);
    }
    if let Some(value) = optional(entry, &["next_hop", "nexthop"]) {
        route = route.next_hop(ipv4_text(value)?);
    }
    if let Some(value) = optional(entry, &["metric"]) {
        route = route.metric(u32_value(value)?);
    }
    Ok(route)
}

/// Build a RIPv2 authentication block and its digest key from a plan `auth`
/// object (RFC 2453 §4.1 / RFC 2082 / RFC 4822 §3).
///
/// Authentication type 2 is a simple password (the 16-octet cleartext entry);
/// any other type is the keyed message-digest layout, whose algorithm is chosen
/// from the plan (`keyed-md5` / `hmac-sha1` / `hmac-sha256`) and whose key id /
/// sequence are pinned from the plan. The returned key is the shared secret
/// `Rip::auth` uses to auto-compute the trailing digest on compile(); the Scapy
/// reference omits it (it does not derive the digest), so it is read from the
/// libcrafter-only `key_value`/`key`/`secret` plan keys and defaults to empty.
fn rip_auth(value: &Value) -> ExampleResult<(RipAuth, Vec<u8>)> {
    let auth = value
        .as_object()
        .ok_or_else(|| format!("RIP auth entry must be an object, got {value:?}"))?;
    let auth_type = optional(auth, &["type", "authtype", "auth_type"])
        .map(u16_value)
        .transpose()?
        .unwrap_or(2);

    if auth_type == 2 {
        let password =
            rip_password_bytes(optional(auth, &["simple_password", "password", "secret"]))?;
        return Ok((RipAuth::simple_password(&password), Vec::new()));
    }

    // Keyed message digest (type 3): the leading 0xFFFF entry is a digest header
    // and a trailing digest block follows. The algorithm fixes the digest length
    // and the hash used when compile() computes the digest from the key.
    let algorithm = rip_digest_algorithm(optional(auth, &["algorithm", "alg"]))?;
    let key_id = optional(auth, &["key_id", "keyid"])
        .map(u8_value)
        .transpose()?
        .unwrap_or(0);
    let mut keyed = RipAuth::keyed_digest_with(algorithm, key_id);
    rip_apply_keyed_digest_fields(&mut keyed, auth)?;
    let key = rip_digest_key(optional(auth, &["key_value", "key", "secret", "key_hex"]))?;
    Ok((keyed, key))
}

/// Apply the pinned keyed-digest header fields (sequence, offset, and an
/// explicit auth-data length) the plan provides onto a keyed-digest `RipAuth`.
///
/// `RipAuth::keyed_digest_with` seeds the algorithm and key id; the remaining
/// RFC 4822 §3.1 header fields are public on `RipKeyedDigestHeader`, so a pinned
/// sequence (the oracle pins it for reproducible digests) and any explicit
/// offset / auth-data length are set caller-set here. Anything the plan omits
/// stays defaulted and is auto-filled at compile() time.
fn rip_apply_keyed_digest_fields(
    auth: &mut RipAuth,
    fields: &Map<String, Value>,
) -> ExampleResult<()> {
    use crafter::protocols::rip::RipAuthPayload;
    let RipAuthPayload::KeyedDigest(header) = &mut auth.payload else {
        return Ok(());
    };
    if let Some(value) = optional(fields, &["sequence", "seqnum"]) {
        header.sequence.set_user(u32_value(value)?);
    }
    if let Some(value) = optional(fields, &["digest_offset", "digestoffset"]) {
        header.offset.set_user(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["auth_data_len", "authdatalen"]) {
        header.auth_data_len.set_user(u8_value(value)?);
    }
    Ok(())
}

/// Resolve a RIP keyed-digest algorithm (named string or numeric) from the plan.
///
/// Defaults to Keyed-MD5 (RFC 2082) — the type the spec pins for strict
/// cross-backend comparison — and accepts the RFC 4822 HMAC-SHA variants.
fn rip_digest_algorithm(value: Option<&Value>) -> ExampleResult<RipDigestAlgorithm> {
    let Some(value) = value else {
        return Ok(RipDigestAlgorithm::KeyedMd5);
    };
    if let Some(text) = value.as_str() {
        let lowered = text.to_ascii_lowercase().replace([' ', '_'], "-");
        return match lowered.as_str() {
            "keyed-md5" | "md5" => Ok(RipDigestAlgorithm::KeyedMd5),
            "hmac-sha1" | "sha1" | "hmac-sha-1" => Ok(RipDigestAlgorithm::HmacSha1),
            "hmac-sha256" | "sha256" | "hmac-sha-256" => Ok(RipDigestAlgorithm::HmacSha256),
            other => Err(format!("unsupported RIP digest algorithm: {other}").into()),
        };
    }
    Err(format!("unsupported RIP digest algorithm value: {value:?}").into())
}

/// Decode the up-to-16-octet RIP simple password from a plan value.
///
/// Accepts a cleartext string, a `{"hex": ...}` byte object, or a hex string,
/// mirroring the Scapy backend's `_rip_password_bytes`. `RipAuth::simple_password`
/// right-pads or truncates to the fixed 16-octet field, so the raw bytes are
/// passed through unpadded here.
fn rip_password_bytes(value: Option<&Value>) -> ExampleResult<Vec<u8>> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::String(text)) => Ok(text.as_bytes().to_vec()),
        Some(value) => option_bytes(value),
    }
}

/// Decode the keyed-digest shared key from a plan value.
///
/// Accepts a cleartext string, a `{"hex": ...}` byte object, or a hex string.
/// This is the libcrafter-only key the Scapy reference does not carry; when the
/// plan omits it the key is empty and compile() derives the digest accordingly.
fn rip_digest_key(value: Option<&Value>) -> ExampleResult<Vec<u8>> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::String(text)) => Ok(text.as_bytes().to_vec()),
        Some(value) => option_bytes(value),
    }
}

/// Build a RIPng layer (RFC 2080) from a packet plan.
///
/// The plan's `fields.ripng` object mirrors the oracle RIPng layer spec (step 47)
/// and the parser-backend RIPng normalization (step 55): the 4-octet header
/// (`command`/`version`/`reserved`) and an `rtes` list of 20-octet route table
/// entries (`prefix`/`route_tag`/`prefix_len`/`metric`), including next-hop RTEs
/// (metric `0xFF`). Every field the plan provides is honored through the public
/// `Ripng`/`RipngRte` builders; anything it omits stays at the protocol-correct
/// `Ripng::new()` default (Response command, version 1, reserved 0). The composed
/// `Ripng` rides the plan's UDP/IPv6 stack and `compile()` (driven by
/// `build_packet`) auto-fills lengths and ports when the caller left them unset.
fn ripng_layer(plan: &Value) -> ExampleResult<Ripng> {
    let fields = layer_fields(plan, "ripng")?;
    let mut layer = Ripng::new();

    // The command is required (RFC 2080 §2.1); accept a named command
    // ("request"/"response") or a numeric code, reusing the RIP command mapping.
    layer = layer.command_code(rip_command_code(required(fields, &["command", "cmd"])?)?);
    if let Some(value) = optional(fields, &["version"]) {
        layer = layer.version(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["reserved", "null"]) {
        layer = layer.reserved(u16_value(value)?);
    }

    if let Some(value) = optional(fields, &["rtes", "entries"]) {
        for rte in array_values(value)? {
            layer = layer.rte(ripng_rte(rte)?);
        }
    }

    Ok(layer)
}

/// Build one 20-octet RIPng route table entry from a plan RTE object
/// (RFC 2080 §2.1).
///
/// Reads the per-RTE keys the RIPng layer spec and parser normalization use
/// (`prefix`/`route_tag`/`prefix_len`/`metric`, with short aliases) and applies
/// each through the caller-set `RipngRte` field setters so the compiled RTE
/// matches the plan. A next-hop RTE (RFC 2080 §2.1.1) is just an RTE whose metric
/// is `0xFF`; the plan carries that explicitly via `metric`, so no special-casing
/// is needed here.
fn ripng_rte(value: &Value) -> ExampleResult<RipngRte> {
    let rte = value
        .as_object()
        .ok_or_else(|| format!("RIPng RTE must be an object, got {value:?}"))?;
    let mut entry = RipngRte::new();
    if let Some(value) = optional(rte, &["prefix", "address", "addr", "ip"]) {
        entry = entry.prefix(ipv6_text(value)?);
    }
    if let Some(value) = optional(rte, &["route_tag", "tag", "routetag"]) {
        entry = entry.route_tag(u16_value(value)?);
    }
    if let Some(value) = optional(rte, &["prefix_len", "prefix_length", "plen"]) {
        entry = entry.prefix_len(u8_value(value)?);
    }
    if let Some(value) = optional(rte, &["metric"]) {
        entry = entry.metric(u8_value(value)?);
    }
    Ok(entry)
}

fn radiotap_flags(fields: &Map<String, Value>) -> ExampleResult<u8> {
    let mut flags = 0u8;
    if let Some(value) = optional(fields, &["flags"]) {
        flags |= radiotap_flags_value(value)?;
    }
    if let Some(value) = optional(fields, &["fcs_status"]) {
        flags |= radiotap_flags_value(value)?;
    }
    Ok(flags)
}

fn radiotap_flags_value(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "none" | "absent" | "0" => Ok(0),
            "fcs_present" | "present" => Ok(0x10),
            "failed_fcs" | "failed" => Ok(0x40),
            "fcs_present_failed" | "present_failed" => Ok(0x50),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn radiotap_channel_flags(value: Option<&Value>) -> ExampleResult<u16> {
    let Some(value) = value else {
        return Ok(0x00a0);
    };
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "two_ghz_cck" => Ok(0x00a0),
            "two_ghz_ofdm" => Ok(0x00c0),
            "five_ghz_ofdm" => Ok(0x0140),
            _ => u16_text(text),
        };
    }
    u16_value(value)
}

fn dot11_frame_control(fields: &Map<String, Value>) -> ExampleResult<u16> {
    if let Some(value) = optional(fields, &["frame_control"]) {
        return u16_value(value);
    }

    let mut frame_control = optional(fields, &["protocol_version"])
        .map(u16_value)
        .transpose()?
        .unwrap_or(0)
        & 0x0003;
    frame_control |=
        ((dot11_frame_type_value(optional(fields, &["frame_type"]))? as u16) & 0x03) << 2;
    frame_control |= ((dot11_subtype_value(optional(fields, &["subtype"]))? as u16) & 0x0f) << 4;
    for (name, mask) in [
        ("to_ds", 0x0100),
        ("from_ds", 0x0200),
        ("more_fragments", 0x0400),
        ("retry", 0x0800),
        ("power_management", 0x1000),
        ("more_data", 0x2000),
        ("protected", 0x4000),
        ("order", 0x8000),
    ] {
        if optional(fields, &[name])
            .map(bool_value)
            .transpose()?
            .unwrap_or(false)
        {
            frame_control |= mask;
        }
    }
    Ok(frame_control)
}

fn dot11_frame_type_value(value: Option<&Value>) -> ExampleResult<u8> {
    let Some(value) = value else {
        return Ok(DOT11_FRAME_TYPE_DATA);
    };
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "management" => Ok(DOT11_FRAME_TYPE_MANAGEMENT),
            "control" => Ok(DOT11_FRAME_TYPE_CONTROL),
            "data" => Ok(DOT11_FRAME_TYPE_DATA),
            "extension" => Ok(DOT11_FRAME_TYPE_EXTENSION),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn dot11_subtype_value(value: Option<&Value>) -> ExampleResult<u8> {
    let Some(value) = value else {
        return Ok(DOT11_DATA_SUBTYPE_DATA);
    };
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "association_request" => Ok(DOT11_MGMT_SUBTYPE_ASSOCIATION_REQUEST),
            "probe_request" => Ok(DOT11_MGMT_SUBTYPE_PROBE_REQUEST),
            "beacon" => Ok(DOT11_MGMT_SUBTYPE_BEACON),
            "authentication" => Ok(DOT11_MGMT_SUBTYPE_AUTHENTICATION),
            "deauthentication" => Ok(DOT11_MGMT_SUBTYPE_DEAUTHENTICATION),
            "rts" => Ok(DOT11_CONTROL_SUBTYPE_RTS),
            "cts" => Ok(DOT11_CONTROL_SUBTYPE_CTS),
            "ack" => Ok(DOT11_CONTROL_SUBTYPE_ACK),
            "data" => Ok(DOT11_DATA_SUBTYPE_DATA),
            "qos_data" => Ok(DOT11_DATA_SUBTYPE_QOS_DATA),
            "unknown" => Ok(15),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn mac_addr_field(
    fields: &Map<String, Value>,
    names: &[&str],
    default: &str,
) -> ExampleResult<MacAddr> {
    match optional(fields, names) {
        Some(value) => mac_addr_value(value),
        None => Ok(MacAddr::from_str(default)?),
    }
}

fn mac_addr_value(value: &Value) -> ExampleResult<MacAddr> {
    if let Some(text) = value.as_str() {
        return Ok(MacAddr::from_str(text)?);
    }
    let bytes = fixed_6_bytes(value, "dot11.mac")?;
    Ok(MacAddr::from(bytes))
}

fn dot11_tagged_parameters(value: &Value) -> ExampleResult<Vec<Dot11TaggedParameter>> {
    if let Some(items) = value.as_array() {
        return items.iter().map(dot11_tagged_parameter).collect();
    }
    Ok(vec![dot11_tagged_parameter(value)?])
}

fn dot11_tagged_parameter(value: &Value) -> ExampleResult<Dot11TaggedParameter> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("dot11 tagged parameter must be an object, got {value:?}"))?;
    let id = optional(object, &["id", "tag", "element_id"])
        .map(u8_value)
        .transpose()?
        .unwrap_or(DOT11_TAG_SSID);
    let data = optional(object, &["value", "data", "bytes"])
        .map(option_bytes)
        .transpose()?
        .unwrap_or_default();
    let mut tag = Dot11TaggedParameter::new(id, data);
    if let Some(length) = optional(object, &["length", "len"]) {
        tag = tag.with_length(u8_value(length)?);
    }
    Ok(tag)
}

fn rsn_tagged_parameter(fields: &Map<String, Value>) -> ExampleResult<Dot11TaggedParameter> {
    let element_id = optional(fields, &["element_id", "id", "tag"])
        .map(u8_value)
        .transpose()?
        .unwrap_or(DOT11_TAG_RSN);
    let rsn = rsn_information(fields)?;
    let value_bytes = rsn.to_tagged_parameter_value()?;
    let mut tag = if element_id == DOT11_TAG_RSN {
        Dot11TaggedParameter::from_rsn_information(&rsn)?
    } else {
        Dot11TaggedParameter::new(element_id, value_bytes)
    };
    if let Some(value) = optional(fields, &["length", "len"]) {
        let length = u8_value(value)?;
        if length != 0 {
            tag = tag.with_length(length);
        }
    }
    Ok(tag)
}

fn rsn_information(fields: &Map<String, Value>) -> ExampleResult<RsnInformation> {
    let mut rsn = RsnInformation::new()
        .with_version(
            optional(fields, &["version"])
                .map(u16_value)
                .transpose()?
                .unwrap_or(RSN_VERSION_1),
        )
        .without_capabilities()
        .without_pmkids()
        .without_group_management_cipher();
    if let Some(value) = optional(fields, &["group_cipher_suite", "group_cipher"]) {
        rsn = rsn.with_group_cipher_suite(rsn_cipher_suite(value)?);
    }
    if let Some(value) = optional(fields, &["pairwise_cipher_suites", "pairwise_ciphers"]) {
        rsn = rsn.with_pairwise_cipher_list(rsn_cipher_suite_list(value)?);
    }
    if let Some(value) = optional(fields, &["akm_suites", "akm_list"]) {
        rsn = rsn.with_akm_list(rsn_akm_suite_list(value)?);
    }
    if let Some(value) = optional(fields, &["capabilities"]) {
        rsn = rsn.with_capabilities(RsnCapabilities::from_bits(u16_value(value)?));
    }
    if let Some(value) = optional(fields, &["pmkid_list", "pmkids"]) {
        let pmkids = rsn_pmkid_list(value)?;
        if !pmkids.is_empty() {
            rsn = rsn.with_pmkid_list(pmkids);
        }
    }
    if let Some(value) = optional(
        fields,
        &["group_management_cipher_suite", "group_management_cipher"],
    ) {
        rsn = rsn.with_group_management_cipher_suite(rsn_cipher_suite(value)?);
    }
    if let Some(value) = optional(fields, &["trailing_bytes", "extension_bytes"]) {
        rsn = rsn.with_trailing_bytes(option_bytes(value)?);
    }
    Ok(rsn)
}

fn rsn_cipher_suite_list(value: &Value) -> ExampleResult<Vec<RsnCipherSuite>> {
    if let Some(items) = value.as_array() {
        return items.iter().map(rsn_cipher_suite).collect();
    }
    Ok(vec![rsn_cipher_suite(value)?])
}

fn rsn_akm_suite_list(value: &Value) -> ExampleResult<Vec<RsnAkmSuite>> {
    if let Some(items) = value.as_array() {
        return items.iter().map(rsn_akm_suite).collect();
    }
    Ok(vec![rsn_akm_suite(value)?])
}

fn rsn_cipher_suite(value: &Value) -> ExampleResult<RsnCipherSuite> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "use_group" => Ok(RSN_CIPHER_SUITE_USE_GROUP),
            "tkip" => Ok(RSN_CIPHER_SUITE_TKIP),
            "ccmp_128" => Ok(RSN_CIPHER_SUITE_CCMP_128),
            "ccmp_256" => Ok(RSN_CIPHER_SUITE_CCMP_256),
            "gcmp_128" => Ok(RSN_CIPHER_SUITE_GCMP_128),
            "gcmp_256" => Ok(RSN_CIPHER_SUITE_GCMP_256),
            "aes_128_cmac" | "bip_cmac_128" => Ok(RSN_CIPHER_SUITE_AES_128_CMAC),
            "bip_cmac_256" => Ok(RSN_CIPHER_SUITE_BIP_CMAC_256),
            "bip_gmac_128" => Ok(RSN_CIPHER_SUITE_BIP_GMAC_128),
            "bip_gmac_256" => Ok(RSN_CIPHER_SUITE_BIP_GMAC_256),
            "no_group_addressed" => Ok(RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED),
            _ => Ok(RsnCipherSuite::from_bytes(fixed_4_padded_bytes(
                value,
                "rsn.cipher_suite",
            )?)),
        };
    }
    Ok(RsnCipherSuite::from_bytes(fixed_4_padded_bytes(
        value,
        "rsn.cipher_suite",
    )?))
}

fn rsn_akm_suite(value: &Value) -> ExampleResult<RsnAkmSuite> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace(['-', '.'], "_").as_str() {
            "ieee8021x" | "802_1x" => Ok(RSN_AKM_SUITE_8021X),
            "psk" => Ok(RSN_AKM_SUITE_PSK),
            "ft_psk" => Ok(RSN_AKM_SUITE_FT_PSK),
            "psk_sha256" => Ok(RSN_AKM_SUITE_PSK_SHA256),
            "sae" => Ok(RSN_AKM_SUITE_SAE),
            "owe" => Ok(RSN_AKM_SUITE_OWE),
            _ => Ok(RsnAkmSuite::from_bytes(fixed_4_padded_bytes(
                value,
                "rsn.akm_suite",
            )?)),
        };
    }
    Ok(RsnAkmSuite::from_bytes(fixed_4_padded_bytes(
        value,
        "rsn.akm_suite",
    )?))
}

fn rsn_pmkid_list(value: &Value) -> ExampleResult<Vec<[u8; 16]>> {
    let bytes = option_bytes(value)?;
    if bytes.len() % 16 != 0 {
        return Err("rsn pmkid_list length must be a multiple of 16".into());
    }
    Ok(bytes
        .chunks(16)
        .map(|chunk| chunk.try_into().expect("chunk size is fixed"))
        .collect())
}

fn eapol_type_value(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "eap_packet" => Ok(EAPOL_TYPE_EAP_PACKET),
            "start" => Ok(EAPOL_TYPE_START),
            "logoff" => Ok(EAPOL_TYPE_LOGOFF),
            "key" => Ok(EAPOL_TYPE_KEY),
            "asf_alert" => Ok(EAPOL_TYPE_ASF_ALERT),
            "unknown" => Ok(255),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn eapol_descriptor_type(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "rc4_key" => Ok(1),
            "rsn_key" => Ok(EAPOL_KEY_DESCRIPTOR_RSN),
            "unknown" => Ok(254),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn stack_contains(plan: &Value, needle: &str) -> bool {
    string_array(plan.get("stack"))
        .unwrap_or_default()
        .iter()
        .map(|layer| canonical_layer(layer))
        .any(|layer| layer == needle)
}

fn ethertype_for_next_stack_layer(plan: &Value, current: &str) -> u16 {
    let stack = string_array(plan.get("stack")).unwrap_or_default();
    let canonical = stack
        .iter()
        .map(|layer| canonical_layer(layer))
        .collect::<Vec<_>>();
    let Some(index) = canonical.iter().position(|layer| layer == current) else {
        return 0x9000;
    };
    match canonical.get(index + 1).map(String::as_str) {
        Some("arp") => ETHERTYPE_ARP,
        Some("eapol") => ETHERTYPE_EAPOL,
        Some("ipv4") => ETHERTYPE_IPV4,
        Some("ipv6") => ETHERTYPE_IPV6,
        Some("vlan") => ETHERTYPE_VLAN,
        _ => 0x9000,
    }
}

fn fixed_padded_bytes<const N: usize>(value: &Value, field: &str) -> ExampleResult<[u8; N]> {
    let raw = option_bytes(value)?;
    let mut out = [0u8; N];
    let count = raw.len().min(N);
    out[..count].copy_from_slice(&raw[..count]);
    if raw.len() > N {
        return Ok(out);
    }
    let _ = field;
    Ok(out)
}

fn fixed_3_bytes(value: &Value, field: &str) -> ExampleResult<[u8; 3]> {
    fixed_padded_bytes(value, field)
}

fn fixed_4_padded_bytes(value: &Value, field: &str) -> ExampleResult<[u8; 4]> {
    fixed_padded_bytes(value, field)
}

fn fixed_6_bytes(value: &Value, field: &str) -> ExampleResult<[u8; 6]> {
    fixed_padded_bytes(value, field)
}

fn fixed_8_bytes(value: &Value, field: &str) -> ExampleResult<[u8; 8]> {
    fixed_padded_bytes(value, field)
}

fn fixed_16_bytes(value: &Value, field: &str) -> ExampleResult<[u8; 16]> {
    fixed_padded_bytes(value, field)
}

fn fixed_32_bytes(value: &Value, field: &str) -> ExampleResult<[u8; 32]> {
    fixed_padded_bytes(value, field)
}

fn dns_record(object: &Map<String, Value>) -> ExampleResult<DnsRecord> {
    let rr_type = optional(object, &["type", "record_type"])
        .map(dns_record_type)
        .transpose()?
        .unwrap_or(DNS_TYPE_A);
    let name = dns_name(text_optional(object, &["name", "rrname"]).unwrap_or("example.com."))?;
    let ttl = optional(object, &["ttl"])
        .map(u32_value)
        .transpose()?
        .unwrap_or(60);
    let class = optional(object, &["record_class", "rclass", "class"])
        .map(dns_class)
        .transpose()?
        .unwrap_or(DNS_CLASS_IN);

    match rr_type {
        DNS_TYPE_A => {
            let address = text_optional(object, &["address", "rdata"]).unwrap_or("192.0.2.53");
            Ok(dns_with_class(
                DnsRecord::a(name, Ipv4Addr::from_str(address)?, ttl),
                class,
            ))
        }
        DNS_TYPE_AAAA => {
            let address = text_optional(object, &["address", "rdata"]).unwrap_or("2001:db8::53");
            Ok(dns_with_class(
                DnsRecord::aaaa(name, Ipv6Addr::from_str(address)?, ttl),
                class,
            ))
        }
        DNS_TYPE_NS => {
            let target =
                dns_name(text_optional(object, &["target", "rdata"]).unwrap_or("ns.example.com."))?;
            Ok(DnsRecord::new(
                name,
                DNS_TYPE_NS,
                class,
                ttl,
                DnsRecordData::name(target),
            ))
        }
        DNS_TYPE_CNAME => {
            let target = dns_name(
                text_optional(object, &["target", "rdata"]).unwrap_or("alias.example.com."),
            )?;
            Ok(dns_with_class(DnsRecord::cname(name, target, ttl), class))
        }
        DNS_TYPE_PTR => {
            let target = dns_name(
                text_optional(object, &["target", "rdata"]).unwrap_or("host.example.com."),
            )?;
            Ok(DnsRecord::new(
                name,
                DNS_TYPE_PTR,
                class,
                ttl,
                DnsRecordData::name(target),
            ))
        }
        DNS_TYPE_MX => {
            let preference = optional(object, &["preference"])
                .map(u16_value)
                .transpose()?
                .unwrap_or(10);
            let exchange = dns_name(
                text_optional(object, &["exchange", "target"]).unwrap_or("mail.example.com."),
            )?;
            Ok(DnsRecord::new(
                name,
                DNS_TYPE_MX,
                class,
                ttl,
                DnsRecordData::Mx {
                    preference,
                    exchange,
                },
            ))
        }
        DNS_TYPE_TXT => Ok(DnsRecord::new(
            name,
            DNS_TYPE_TXT,
            class,
            ttl,
            DnsRecordData::Txt(dns_txt_strings(object)?),
        )),
        DNS_TYPE_SOA => Ok(dns_with_class(
            DnsRecord::soa(
                name,
                ttl,
                dns_name(
                    text_optional(object, &["primary_name", "mname"]).unwrap_or("ns1.example.com."),
                )?,
                dns_name(
                    text_optional(object, &["responsible_name", "rname"])
                        .unwrap_or("hostmaster.example.com."),
                )?,
                optional(object, &["serial"])
                    .map(u32_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["refresh"])
                    .map(u32_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["retry"])
                    .map(u32_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["expire"])
                    .map(u32_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["minimum"])
                    .map(u32_value)
                    .transpose()?
                    .unwrap_or(0),
            ),
            class,
        )),
        DNS_TYPE_SRV => Ok(dns_with_class(
            DnsRecord::srv(
                name,
                ttl,
                optional(object, &["priority"])
                    .map(u16_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["weight"])
                    .map(u16_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["port"])
                    .map(u16_value)
                    .transpose()?
                    .unwrap_or(0),
                dns_name(text_optional(object, &["target"]).unwrap_or("svc.example.com."))?,
            ),
            class,
        )),
        DNS_TYPE_DS => Ok(dns_with_class(
            DnsRecord::ds(
                name,
                ttl,
                optional(object, &["key_tag", "keytag"])
                    .map(u16_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["algorithm"])
                    .map(u8_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["digest_type", "digesttype"])
                    .map(u8_value)
                    .transpose()?
                    .unwrap_or(0),
                dns_blob(optional(object, &["digest"]))?,
            ),
            class,
        )),
        DNS_TYPE_DNSKEY => Ok(dns_with_class(
            DnsRecord::dnskey(
                name,
                ttl,
                optional(object, &["flags"])
                    .map(u16_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["protocol"])
                    .map(u8_value)
                    .transpose()?
                    .unwrap_or(3),
                optional(object, &["algorithm"])
                    .map(u8_value)
                    .transpose()?
                    .unwrap_or(0),
                dns_blob(optional(object, &["public_key", "publickey"]))?,
            ),
            class,
        )),
        DNS_TYPE_RRSIG => Ok(dns_with_class(
            DnsRecord::rrsig(
                name,
                ttl,
                optional(object, &["type_covered", "typecovered"])
                    .map(dns_record_type)
                    .transpose()?
                    .unwrap_or(DNS_TYPE_A),
                optional(object, &["algorithm"])
                    .map(u8_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["labels"])
                    .map(u8_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["original_ttl", "originalttl"])
                    .map(u32_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["signature_expiration", "expiration"])
                    .map(u32_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["signature_inception", "inception"])
                    .map(u32_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["key_tag", "keytag"])
                    .map(u16_value)
                    .transpose()?
                    .unwrap_or(0),
                dns_name(
                    text_optional(object, &["signer_name", "signersname"])
                        .unwrap_or("example.com."),
                )?,
                dns_blob(optional(object, &["signature"]))?,
            ),
            class,
        )),
        DNS_TYPE_NSEC => Ok(dns_with_class(
            DnsRecord::nsec(
                name,
                ttl,
                dns_name(
                    text_optional(object, &["next_name", "nextname"])
                        .unwrap_or("next.example.com."),
                )?,
                dns_type_bitmap_codes(optional(object, &["type_bitmaps", "typebitmaps"]))?,
            ),
            class,
        )),
        DNS_TYPE_NSEC3 => Ok(dns_with_class(
            DnsRecord::nsec3(
                name,
                ttl,
                optional(object, &["hash_algorithm", "hashalg"])
                    .map(u8_value)
                    .transpose()?
                    .unwrap_or(1),
                optional(object, &["flags"])
                    .map(u8_value)
                    .transpose()?
                    .unwrap_or(0),
                optional(object, &["iterations"])
                    .map(u16_value)
                    .transpose()?
                    .unwrap_or(0),
                dns_blob(optional(object, &["salt"]))?,
                dns_blob(optional(
                    object,
                    &["next_hashed_owner", "nexthashedownername"],
                ))?,
                dns_type_bitmap_codes(optional(object, &["type_bitmaps", "typebitmaps"]))?,
            ),
            class,
        )),
        DNS_TYPE_SVCB => Ok(dns_with_class(
            DnsRecord::svcb(
                name,
                ttl,
                optional(object, &["priority", "svc_priority"])
                    .map(u16_value)
                    .transpose()?
                    .unwrap_or(0),
                dns_name(text_optional(object, &["target", "target_name"]).unwrap_or("."))?,
                dns_svc_params(optional(object, &["params", "svc_params"]))?,
            ),
            class,
        )),
        DNS_TYPE_HTTPS => Ok(dns_with_class(
            DnsRecord::https(
                name,
                ttl,
                optional(object, &["priority", "svc_priority"])
                    .map(u16_value)
                    .transpose()?
                    .unwrap_or(0),
                dns_name(text_optional(object, &["target", "target_name"]).unwrap_or("."))?,
                dns_svc_params(optional(object, &["params", "svc_params"]))?,
            ),
            class,
        )),
        DNS_TYPE_OPT => Ok(DnsRecord::opt(
            optional(object, &["udp_payload_size", "rclass"])
                .map(u16_value)
                .transpose()?
                .unwrap_or(4096),
            optional(object, &["extended_rcode", "extrcode"])
                .map(u8_value)
                .transpose()?
                .unwrap_or(0),
            optional(object, &["version"])
                .map(u8_value)
                .transpose()?
                .unwrap_or(0),
            optional(object, &["dnssec_ok"])
                .map(bool_value)
                .transpose()?
                .unwrap_or(false),
            dns_edns_options(optional(object, &["options"]))?,
        )),
        // Unknown or intentionally deferred record types stay DnsRecordData::Raw
        // rather than being mapped to an incorrect typed record.
        _ => Ok(DnsRecord::new(
            name,
            rr_type,
            class,
            ttl,
            DnsRecordData::Raw(dns_blob(optional(object, &["data", "rdata"]))?),
        )),
    }
}

fn dns_with_class(record: DnsRecord, class: u16) -> DnsRecord {
    if class == DNS_CLASS_IN {
        return record;
    }
    DnsRecord::new(
        record.dns_name().clone(),
        record.record_type(),
        class,
        record.ttl(),
        record.data().clone(),
    )
}

fn dns_name(name: &str) -> ExampleResult<DnsName> {
    DnsName::parse(name).map_err(Into::into)
}

fn dns_txt_strings(object: &Map<String, Value>) -> ExampleResult<Vec<Vec<u8>>> {
    if let Some(value) = optional(object, &["strings", "rdata"]) {
        if let Some(items) = value.as_array() {
            return items.iter().map(dns_text_string).collect();
        }
        return Ok(vec![dns_text_string(value)?]);
    }
    Ok(vec![Vec::new()])
}

fn dns_text_string(value: &Value) -> ExampleResult<Vec<u8>> {
    if let Some(object) = value.as_object() {
        if let Some(hex) = object.get("hex").and_then(Value::as_str) {
            return decode_hex(hex);
        }
    }
    Ok(text_value(value)?.as_bytes().to_vec())
}

fn dns_blob(value: Option<&Value>) -> ExampleResult<Vec<u8>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(value) => {
            if let Some(text) = value.as_str() {
                return decode_hex(text);
            }
            if let Some(object) = value.as_object() {
                if let Some(hex) = object.get("hex").and_then(Value::as_str) {
                    return decode_hex(hex);
                }
                return Err(format!("dns blob object requires hex, got {value:?}").into());
            }
            Err(format!("expected blob-compatible dns value, got {value:?}").into())
        }
    }
}

fn dns_type_bitmap_codes(value: Option<&Value>) -> ExampleResult<Vec<u16>> {
    let value = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(value) => value,
    };
    // Accept either a bare list of record types or a {record_types: [...]} object.
    let record_types = if let Some(object) = value.as_object() {
        match object.get("record_types") {
            Some(types) => types,
            None => return Ok(Vec::new()),
        }
    } else {
        value
    };
    array_values(record_types)?
        .iter()
        .map(dns_record_type)
        .collect()
}

fn dns_edns_options(value: Option<&Value>) -> ExampleResult<Vec<EdnsOption>> {
    let value = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(value) => value,
    };
    let mut options = Vec::new();
    for option in array_values(value)? {
        if let Some(object) = option.as_object() {
            let code = optional(object, &["option_code", "optcode"])
                .map(u16_value)
                .transpose()?
                .unwrap_or(0);
            let data = dns_blob(optional(object, &["option_data", "optdata"]))?;
            options.push(EdnsOption::new(code, data));
        }
    }
    Ok(options)
}

fn dns_svc_params(value: Option<&Value>) -> ExampleResult<SvcParams> {
    let value = match value {
        None | Some(Value::Null) => return Ok(SvcParams::empty()),
        Some(value) => value,
    };
    let mut params = Vec::new();
    for param in array_values(value)? {
        if let Some(object) = param.as_object() {
            let key = optional(object, &["key"])
                .map(dns_svc_param_key)
                .transpose()?
                .unwrap_or(0);
            let value = dns_blob(optional(object, &["value"]))?;
            params.push(SvcParam::new(key, value));
        }
    }
    SvcParams::new(params).map_err(Into::into)
}

fn dns_svc_param_key(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "mandatory" => Ok(DNS_SVCB_KEY_MANDATORY),
            "alpn" => Ok(DNS_SVCB_KEY_ALPN),
            "no-default-alpn" => Ok(DNS_SVCB_KEY_NO_DEFAULT_ALPN),
            "port" => Ok(DNS_SVCB_KEY_PORT),
            "ipv4hint" => Ok(DNS_SVCB_KEY_IPV4HINT),
            "ech" => Ok(DNS_SVCB_KEY_ECH),
            "ipv6hint" => Ok(DNS_SVCB_KEY_IPV6HINT),
            "dohpath" => Ok(DNS_SVCB_KEY_DOHPATH),
            other => u16_text(other),
        };
    }
    u16_value(value)
}

fn dns_class(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_uppercase().as_str() {
            "IN" => Ok(DNS_CLASS_IN),
            "CH" => Ok(DNS_CLASS_CH),
            "HS" => Ok(DNS_CLASS_HS),
            "NONE" => Ok(DNS_CLASS_NONE),
            "ANY" => Ok(DNS_CLASS_ANY),
            _ => u16_text(text),
        };
    }
    u16_value(value)
}

fn dhcp_options(value: &Value) -> ExampleResult<Vec<DhcpOption>> {
    let mut options = Vec::new();
    for item in array_values(value)? {
        if let Some(text) = item.as_str() {
            if text == "end" {
                options.push(DhcpOption::End);
                continue;
            }
            if text == "pad" {
                options.push(DhcpOption::Pad);
                continue;
            }
            if let Some((name, raw_value)) = text.split_once('=') {
                options.push(dhcp_option_pair(name, raw_value)?);
                continue;
            }
        }
    }
    if !matches!(options.last(), Some(DhcpOption::End)) {
        options.push(DhcpOption::End);
    }
    Ok(options)
}

fn dhcp_option_pair(name: &str, value: &str) -> ExampleResult<DhcpOption> {
    match name.replace('-', "_").as_str() {
        "message_type" => Ok(DhcpOption::message_type(dhcp_message_type(value))),
        "hostname" | "host_name" => Ok(DhcpOption::host_name(value)),
        "domain_name" => Ok(DhcpOption::domain_name(value)),
        "requested_ip" | "requested_ip_address" => {
            Ok(DhcpOption::requested_ip_address(Ipv4Addr::from_str(value)?))
        }
        "server_id" | "server_identifier" => {
            Ok(DhcpOption::server_identifier(Ipv4Addr::from_str(value)?))
        }
        "router" => Ok(DhcpOption::router(parse_ipv4_list(value)?)),
        "dns" | "domain_name_server" => Ok(DhcpOption::domain_name_server(parse_ipv4_list(value)?)),
        "lease_time" => Ok(DhcpOption::lease_time(value.parse::<u32>()?)),
        _ => Ok(DhcpOption::generic(254, value.as_bytes().to_vec())),
    }
}

fn dhcp_message_type(value: &str) -> DhcpMessageType {
    match value.replace('-', "_").as_str() {
        "discover" => DhcpMessageType::Discover,
        "offer" => DhcpMessageType::Offer,
        "request" => DhcpMessageType::Request,
        "decline" => DhcpMessageType::Decline,
        "ack" => DhcpMessageType::Ack,
        "nak" => DhcpMessageType::Nak,
        "release" => DhcpMessageType::Release,
        "inform" => DhcpMessageType::Inform,
        _ => value
            .parse::<u8>()
            .map(DhcpMessageType::Unknown)
            .unwrap_or(DhcpMessageType::Discover),
    }
}

fn parse_ipv4_list(value: &str) -> ExampleResult<Vec<Ipv4Addr>> {
    value
        .split(',')
        .filter(|item| !item.is_empty())
        .map(Ipv4Addr::from_str)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn payload_bytes(plan: &Value) -> ExampleResult<Vec<u8>> {
    let fields = layer_fields(plan, "payload")?;
    let mut bytes = if let Some(value) = optional(fields, &["hex", "bytes_hex"]) {
        decode_hex(text_value(value)?)?
    } else if let Some(value) = optional(fields, &["text", "value"]) {
        text_value(value)?.as_bytes().to_vec()
    } else {
        return Err(
            "payload materialization requires bytes in hex, bytes_hex, text, or value".into(),
        );
    };

    let mut prefix = icmp_payload_prefix_bytes(plan)?;
    if prefix.is_empty() {
        Ok(bytes)
    } else {
        prefix.append(&mut bytes);
        Ok(prefix)
    }
}

fn icmp_payload_prefix_bytes(plan: &Value) -> ExampleResult<Vec<u8>> {
    let Some(fields) = optional_layer_fields(plan, "icmp")? else {
        return Ok(Vec::new());
    };

    let mut bytes = Vec::new();
    if let Some(value) = optional(fields, &["type"]) {
        match icmp_type(value, false)? {
            ICMP_TIMESTAMP | ICMP_TIMESTAMP_REPLY => {
                bytes.extend_from_slice(
                    &optional(fields, &["originate_timestamp"])
                        .map(u32_value)
                        .transpose()?
                        .unwrap_or(0)
                        .to_be_bytes(),
                );
                bytes.extend_from_slice(
                    &optional(fields, &["receive_timestamp"])
                        .map(u32_value)
                        .transpose()?
                        .unwrap_or(0)
                        .to_be_bytes(),
                );
                bytes.extend_from_slice(
                    &optional(fields, &["transmit_timestamp"])
                        .map(u32_value)
                        .transpose()?
                        .unwrap_or(0)
                        .to_be_bytes(),
                );
            }
            ICMP_ADDRESS_MASK_REQUEST | ICMP_ADDRESS_MASK_REPLY => {
                if let Some(value) = optional(fields, &["address_mask"]) {
                    bytes.extend_from_slice(&ipv4_text(value)?.octets());
                }
            }
            _ => {}
        }
    }

    if let Some(value) = optional(fields, &["embedded_header"]) {
        bytes.extend_from_slice(&option_bytes(value)?);
    }
    if let Some(value) = optional(fields, &["router_addresses"]) {
        bytes.extend_from_slice(&router_address_bytes(value)?);
    }
    if let Some(value) = optional(fields, &["extension_bytes"]) {
        bytes.extend_from_slice(&option_bytes(value)?);
    }

    Ok(bytes)
}

fn router_address_bytes(value: &Value) -> ExampleResult<Vec<u8>> {
    let mut bytes = Vec::new();
    for entry in array_values(value)? {
        let object = entry
            .as_object()
            .ok_or_else(|| format!("router address entry must be an object, got {entry:?}"))?;
        let address = ipv4_text(required(object, &["address", "rdata"])?)?;
        let preference = u32_value(required(object, &["preference"])?)?;
        bytes.extend_from_slice(&address.octets());
        bytes.extend_from_slice(&preference.to_be_bytes());
    }
    Ok(bytes)
}

fn layer_fields<'a>(plan: &'a Value, layer: &str) -> ExampleResult<&'a Map<String, Value>> {
    let fields = plan
        .get("fields")
        .and_then(Value::as_object)
        .ok_or("packet plan fields must be an object")?;
    if let Some(value) = fields.get(layer) {
        return value
            .as_object()
            .ok_or_else(|| format!("{layer} fields must be an object").into());
    }
    if layer == "ipv4" {
        if let Some(value) = fields.get("ip") {
            return value
                .as_object()
                .ok_or_else(|| "ipv4 fields must be an object".into());
        }
    }
    if layer == "payload" {
        if let Some(value) = fields.get("raw") {
            return value
                .as_object()
                .ok_or_else(|| "payload fields must be an object".into());
        }
    }
    if layer == "linux_cooked" {
        if let Some(value) = fields.get("linux_sll") {
            return value
                .as_object()
                .ok_or_else(|| "linux_sll fields must be an object".into());
        }
    }
    if layer == "null_loopback" {
        if let Some(value) = fields.get("loopback") {
            return value
                .as_object()
                .ok_or_else(|| "null_loopback fields must be an object".into());
        }
    }
    Err(format!("packet plan requires {layer} fields").into())
}

fn required<'a>(fields: &'a Map<String, Value>, names: &[&str]) -> ExampleResult<&'a Value> {
    optional(fields, names)
        .ok_or_else(|| format!("missing required field {}", names.join("/")).into())
}

fn optional<'a>(fields: &'a Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    for name in names {
        if let Some(value) = fields.get(*name) {
            return Some(value);
        }
    }
    None
}

fn optional_layer_fields<'a>(
    plan: &'a Value,
    layer: &str,
) -> ExampleResult<Option<&'a Map<String, Value>>> {
    let Some(fields) = plan.get("fields").and_then(Value::as_object) else {
        return Ok(None);
    };
    fields
        .get(layer)
        .map(|value| {
            value
                .as_object()
                .ok_or_else(|| format!("{layer} fields must be an object").into())
        })
        .transpose()
}

fn text_required<'a>(fields: &'a Map<String, Value>, names: &[&str]) -> ExampleResult<&'a str> {
    text_value(required(fields, names)?)
}

fn text_optional<'a>(fields: &'a Map<String, Value>, names: &[&str]) -> Option<&'a str> {
    optional(fields, names).and_then(Value::as_str)
}

fn text_value(value: &Value) -> ExampleResult<&str> {
    value
        .as_str()
        .ok_or_else(|| format!("expected string-compatible value, got {value:?}").into())
}

fn string_array(value: Option<&Value>) -> Option<Vec<String>> {
    value.and_then(Value::as_array).map(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect()
    })
}

fn array_values(value: &Value) -> ExampleResult<&Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| format!("expected array value, got {value:?}").into())
}

fn canonical_layer(layer: &str) -> String {
    match layer.to_ascii_lowercase().as_str() {
        "cookedlinux" | "linux_sll" | "linux-cooked" => "linux_cooked".to_string(),
        "dot1q" => "vlan".to_string(),
        "ether" => "ethernet".to_string(),
        "hop-by-hop" | "hop-by-hop-options" | "hop_by_hop" | "hop_by_hop_options" => {
            "ipv6_hop_by_hop".to_string()
        }
        "ip" => "ipv4".to_string(),
        "ipv6-destination-options" | "destination-options" | "destination_options" => {
            "ipv6_destination_options".to_string()
        }
        "ipv6-hop-by-hop" | "ipv6-hop-by-hop-options" => "ipv6_hop_by_hop".to_string(),
        "igmp-query" | "igmpquery" => "igmp_query".to_string(),
        "igmp-report" | "igmpreport" => "igmp_report".to_string(),
        "igmp-extension" | "igmpextension" => "igmp_extension".to_string(),
        "loopback" | "null-loopback" => "null_loopback".to_string(),
        "raw" => "payload".to_string(),
        "udpoptions" | "udp-options" => "udp_options".to_string(),
        value => value.to_string(),
    }
}

fn plan_root(plan: &Value) -> ExampleResult<&str> {
    plan.pointer("/metadata/root_decoder")
        .or_else(|| plan.pointer("/metadata/root"))
        .and_then(Value::as_str)
        .ok_or_else(|| "packet plan metadata must include root_decoder or root".into())
}

fn ethertype_value(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().as_str() {
            "arp" => Ok(ETHERTYPE_ARP),
            "eapol" => Ok(ETHERTYPE_EAPOL),
            "experimental" | "unknown" => Ok(0x9000),
            "ipv4" | "ip" => Ok(ETHERTYPE_IPV4),
            "ipv6" => Ok(ETHERTYPE_IPV6),
            "vlan" => Ok(ETHERTYPE_VLAN),
            _ => u16_text(text),
        };
    }
    u16_value(value)
}

fn address_family_value(value: &Value) -> ExampleResult<u32> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().as_str() {
            "ipv4" | "ip" => Ok(2),
            "ipv6" => Ok(24),
            _ => Ok(u32::try_from(u64_text(text)?)?),
        };
    }
    Ok(u32::try_from(u64_value(value)?)?)
}

fn hardware_type_value(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        if matches!(text.to_ascii_lowercase().as_str(), "ether" | "ethernet") {
            return Ok(1);
        }
        return u16_text(text);
    }
    u16_value(value)
}

fn arp_opcode(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "who-has" | "request" => Ok(1),
            "is-at" | "reply" => Ok(2),
            _ => u16_text(text),
        };
    }
    u16_value(value)
}

fn ip_protocol(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().as_str() {
            "icmp" => Ok(IPPROTO_ICMP),
            "igmp" => Ok(IPPROTO_IGMP),
            "tcp" => Ok(IPPROTO_TCP),
            "udp" => Ok(IPPROTO_UDP),
            "payload" | "raw" | "unknown" => Ok(253),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn ipv6_next_header(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().as_str() {
            "destination-options" | "destination_options" | "dstopts" => Ok(IPPROTO_IPV6_DSTOPTS),
            "fragment" => Ok(IPPROTO_IPV6_FRAGMENT),
            "hop-by-hop" | "hop-by-hop-options" | "hop_by_hop" | "hop_by_hop_options"
            | "hopopts" => Ok(IPPROTO_IPV6_HOPOPTS),
            "icmpv6" => Ok(IPPROTO_ICMPV6),
            "no-next" | "no_next" => Ok(IPPROTO_IPV6_NO_NEXT),
            "payload" | "raw" | "unknown" => Ok(253),
            "routing" => Ok(IPPROTO_IPV6_ROUTE),
            "tcp" => Ok(IPPROTO_TCP),
            "udp" => Ok(IPPROTO_UDP),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn ipv4_flags(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "none" | "0" => Ok(0),
            "df" | "dont-fragment" => Ok(IPV4_FLAG_DONT_FRAGMENT),
            "mf" | "more-fragments" => Ok(IPV4_FLAG_MORE_FRAGMENTS),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn tcp_flags(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        if text == "all" {
            return Ok(0x01ff);
        }
        return Ok(flag_text_value(text));
    }
    if let Some(items) = value.as_array() {
        let mut flags = 0;
        for item in items {
            if let Some(text) = item.as_str() {
                if text == "all" {
                    flags |= 0x01ff;
                } else {
                    flags |= flag_text_value(text);
                }
            }
        }
        return Ok(flags);
    }
    u16_value(value)
}

fn flag_text_value(text: &str) -> u16 {
    match text.to_ascii_lowercase().as_str() {
        "fin" => TCP_FLAG_FIN,
        "syn" => TCP_FLAG_SYN,
        "rst" => TCP_FLAG_RST,
        "psh" => TCP_FLAG_PSH,
        "ack" => TCP_FLAG_ACK,
        "urg" => TCP_FLAG_URG,
        "ece" => TCP_FLAG_ECE,
        "cwr" => TCP_FLAG_CWR,
        "ns" => TCP_FLAG_NS,
        other => other
            .chars()
            .fold(0, |flags, item| flags | tcp_flag_char(item)),
    }
}

fn tcp_flag_char(value: char) -> u16 {
    match value {
        'F' | 'f' => TCP_FLAG_FIN,
        'S' | 's' => TCP_FLAG_SYN,
        'R' | 'r' => TCP_FLAG_RST,
        'P' | 'p' => TCP_FLAG_PSH,
        'A' | 'a' => TCP_FLAG_ACK,
        'U' | 'u' => TCP_FLAG_URG,
        'E' | 'e' => TCP_FLAG_ECE,
        'C' | 'c' => TCP_FLAG_CWR,
        'N' | 'n' => TCP_FLAG_NS,
        _ => 0,
    }
}

fn icmp_type(value: &Value, ipv6: bool) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "echo-reply" => Ok(if ipv6 {
                ICMPV6_ECHO_REPLY
            } else {
                ICMP_ECHO_REPLY
            }),
            "echo-request" => Ok(if ipv6 {
                ICMPV6_ECHO_REQUEST
            } else {
                ICMP_ECHO_REQUEST
            }),
            "destination-unreachable" | "dest-unreach" => Ok(if ipv6 {
                ICMPV6_DESTINATION_UNREACHABLE
            } else {
                ICMP_DESTINATION_UNREACHABLE
            }),
            "packet-too-big" if ipv6 => Ok(ICMPV6_PACKET_TOO_BIG),
            "parameter-problem" => Ok(if ipv6 {
                ICMPV6_PARAMETER_PROBLEM
            } else {
                ICMP_PARAMETER_PROBLEM
            }),
            "time-exceeded" => Ok(if ipv6 {
                ICMPV6_TIME_EXCEEDED
            } else {
                ICMP_TIME_EXCEEDED
            }),
            "source-quench" if !ipv6 => Ok(ICMP_SOURCE_QUENCH),
            "redirect" if !ipv6 => Ok(ICMP_REDIRECT),
            "router-advertisement" if !ipv6 => Ok(ICMP_ROUTER_ADVERTISEMENT),
            "router-solicitation" if !ipv6 => Ok(ICMP_ROUTER_SOLICITATION),
            "timestamp" if !ipv6 => Ok(ICMP_TIMESTAMP),
            "timestamp-reply" if !ipv6 => Ok(ICMP_TIMESTAMP_REPLY),
            "information-request" if !ipv6 => Ok(ICMP_INFORMATION_REQUEST),
            "information-reply" if !ipv6 => Ok(ICMP_INFORMATION_REPLY),
            "address-mask-request" if !ipv6 => Ok(ICMP_ADDRESS_MASK_REQUEST),
            "address-mask-reply" if !ipv6 => Ok(ICMP_ADDRESS_MASK_REPLY),
            "alternate-host-address" if !ipv6 => Ok(ICMP_ALTERNATE_HOST_ADDRESS),
            "traceroute" if !ipv6 => Ok(ICMP_TRACEROUTE),
            "datagram-conversion-error" if !ipv6 => Ok(ICMP_DATAGRAM_CONVERSION_ERROR),
            "mobile-host-redirect" if !ipv6 => Ok(ICMP_MOBILE_HOST_REDIRECT),
            "ipv6-where-are-you" if !ipv6 => Ok(ICMP_IPV6_WHERE_ARE_YOU),
            "ipv6-i-am-here" if !ipv6 => Ok(ICMP_IPV6_I_AM_HERE),
            "mobile-registration-request" if !ipv6 => Ok(ICMP_MOBILE_REGISTRATION_REQUEST),
            "mobile-registration-reply" if !ipv6 => Ok(ICMP_MOBILE_REGISTRATION_REPLY),
            "domain-name-request" if !ipv6 => Ok(ICMP_DOMAIN_NAME_REQUEST),
            "domain-name-reply" if !ipv6 => Ok(ICMP_DOMAIN_NAME_REPLY),
            "skip" if !ipv6 => Ok(ICMP_SKIP),
            "photuris" if !ipv6 => Ok(ICMP_PHOTURIS),
            "seamoby-experimental" if !ipv6 => Ok(ICMP_SEAMOBY_EXPERIMENTAL),
            "extended-echo-request" if !ipv6 => Ok(ICMP_EXTENDED_ECHO_REQUEST),
            "extended-echo-reply" if !ipv6 => Ok(ICMP_EXTENDED_ECHO_REPLY),
            "experiment-1" if !ipv6 => Ok(ICMP_EXPERIMENTAL_253),
            "experiment-2" if !ipv6 => Ok(ICMP_EXPERIMENTAL_254),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn dns_flags(fields: &Map<String, Value>) -> ExampleResult<u16> {
    let mut flags = 0u16;
    if let Some(value) = optional(fields, &["flags"]) {
        for item in value.as_array().into_iter().flatten() {
            if let Some(text) = item.as_str() {
                match text.to_ascii_lowercase().replace('-', "_").as_str() {
                    "authoritative" | "aa" => flags |= DNS_FLAG_AUTHORITATIVE,
                    "truncated" | "tc" => flags |= DNS_FLAG_TRUNCATED,
                    "recursion_desired" | "rd" => flags |= DNS_FLAG_RECURSION_DESIRED,
                    "recursion_available" | "ra" => flags |= DNS_FLAG_RECURSION_AVAILABLE,
                    "authentic_data" | "authenticated_data" | "ad" => {
                        flags |= DNS_FLAG_AUTHENTIC_DATA
                    }
                    "checking_disabled" | "cd" => flags |= DNS_FLAG_CHECKING_DISABLED,
                    // Reserved Z bit (header bit 6), between RA (0x0080) and AD
                    // (0x0020). The crate has no named constant for the reserved
                    // bit, so mirror Scapy's `z` slot directly.
                    "reserved_z" | "raw" | "z" => flags |= 0x0040,
                    _ => {}
                }
            }
        }
    }
    let is_response = optional(fields, &["is_response"])
        .map(bool_value)
        .transpose()?
        .unwrap_or(false);
    if is_response {
        flags |= DNS_FLAG_QR_RESPONSE;
    }
    let response_code = optional(fields, &["response_code"])
        .map(dns_response_code)
        .transpose()?
        .unwrap_or(0);
    flags |= response_code as u16;
    Ok(flags)
}

fn dns_record_type(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_uppercase().as_str() {
            "A" => Ok(DNS_TYPE_A),
            "AAAA" => Ok(DNS_TYPE_AAAA),
            "CNAME" => Ok(DNS_TYPE_CNAME),
            "MX" => Ok(DNS_TYPE_MX),
            "NS" => Ok(DNS_TYPE_NS),
            "PTR" => Ok(DNS_TYPE_PTR),
            "TXT" => Ok(DNS_TYPE_TXT),
            "SOA" => Ok(DNS_TYPE_SOA),
            "SRV" => Ok(DNS_TYPE_SRV),
            "OPT" => Ok(DNS_TYPE_OPT),
            "DS" => Ok(DNS_TYPE_DS),
            "DNSKEY" => Ok(DNS_TYPE_DNSKEY),
            "RRSIG" => Ok(DNS_TYPE_RRSIG),
            "NSEC" => Ok(DNS_TYPE_NSEC),
            "NSEC3" => Ok(DNS_TYPE_NSEC3),
            "SVCB" => Ok(DNS_TYPE_SVCB),
            "HTTPS" => Ok(DNS_TYPE_HTTPS),
            // QTYPE ANY (*) shares IANA codepoint 255 with QCLASS ANY; the crate
            // has no named RR-type constant for it because it is a query-only
            // meta-type, so map the name to its numeric codepoint here.
            "ANY" => Ok(DNS_CLASS_ANY),
            _ => u16_text(text),
        };
    }
    u16_value(value)
}

fn dns_response_code(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "no_error" | "noerror" => Ok(DNS_RCODE_NOERROR),
            "format_error" | "formerr" => Ok(DNS_RCODE_FORMERR),
            "server_failure" | "servfail" => Ok(DNS_RCODE_SERVFAIL),
            "name_error" | "nxdomain" => Ok(DNS_RCODE_NXDOMAIN),
            "not_implemented" | "notimp" => Ok(DNS_RCODE_NOTIMP),
            "refused" => Ok(DNS_RCODE_REFUSED),
            // Mirror the Scapy backend's representable "unknown" rcode codepoint
            // (RFC 6895 reserves 11 in the base header range).
            "unknown" => Ok(DNS_RCODE_DSOTYPENI),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn dns_opcode(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "query" => Ok(DNS_OPCODE_QUERY),
            "iquery" | "inverse_query" => Ok(DNS_OPCODE_IQUERY),
            "status" => Ok(DNS_OPCODE_STATUS),
            "notify" => Ok(DNS_OPCODE_NOTIFY),
            "update" => Ok(DNS_OPCODE_UPDATE),
            "dso" => Ok(DNS_OPCODE_DSO),
            // Mirror the Scapy backend's representable "unknown" opcode codepoint
            // (14 is an unassigned base-header opcode value).
            "unknown" => Ok(14),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn dhcp_op(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "bootrequest" | "request" => Ok(BOOTP_REQUEST),
            "bootreply" | "reply" => Ok(BOOTP_REPLY),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn dhcp_flags(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "broadcast" | "b" => Ok(0x8000),
            "none" | "0" => Ok(0),
            _ => u16_text(text),
        };
    }
    u16_value(value)
}

fn option_bytes(value: &Value) -> ExampleResult<Vec<u8>> {
    bytes_value(value).map_err(|_| format!("unsupported option bytes value: {value:?}").into())
}

fn fixed_4_bytes(value: &Value, field: &str) -> ExampleResult<[u8; 4]> {
    let bytes = option_bytes(value)?;
    Ok(bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!("{field} must contain exactly 4 bytes, got {}", bytes.len())
    })?)
}

fn ipv4_text(value: &Value) -> ExampleResult<Ipv4Addr> {
    Ok(Ipv4Addr::from_str(text_value(value)?)?)
}

fn ipv6_text(value: &Value) -> ExampleResult<Ipv6Addr> {
    Ok(Ipv6Addr::from_str(text_value(value)?)?)
}

fn bytes_value(value: &Value) -> ExampleResult<Vec<u8>> {
    if let Some(text) = value.as_str() {
        if text.contains(':') {
            return mac_bytes(text);
        }
        return decode_hex(text);
    }
    if let Some(object) = value.as_object() {
        if let Some(hex) = object.get("hex").and_then(Value::as_str) {
            return decode_hex(hex);
        }
    }
    Err(format!("unsupported byte value: {value:?}").into())
}

fn bool_value(value: &Value) -> ExampleResult<bool> {
    if let Some(value) = value.as_bool() {
        return Ok(value);
    }
    if let Some(value) = value.as_i64() {
        return Ok(value != 0);
    }
    if let Some(value) = value.as_u64() {
        return Ok(value != 0);
    }
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "true" | "yes" | "broadcast" | "b" => Ok(true),
            "false" | "no" | "none" | "0" => Ok(false),
            _ => Err(format!("expected bool-compatible value, got {text:?}").into()),
        };
    }
    Err(format!("expected bool-compatible value, got {value:?}").into())
}

fn i8_value(value: &Value) -> ExampleResult<i8> {
    if let Some(value) = value.as_i64() {
        return Ok(i8::try_from(value)?);
    }
    if let Some(value) = value.as_u64() {
        return Ok(i8::try_from(value)?);
    }
    if let Some(text) = value.as_str() {
        return Ok(text.trim().parse::<i8>()?);
    }
    Err(format!("expected int8-compatible value, got {value:?}").into())
}

fn u8_value(value: &Value) -> ExampleResult<u8> {
    Ok(u8::try_from(u64_value(value)?)?)
}

fn u16_value(value: &Value) -> ExampleResult<u16> {
    Ok(u16::try_from(u64_value(value)?)?)
}

fn u32_value(value: &Value) -> ExampleResult<u32> {
    Ok(u32::try_from(u64_value(value)?)?)
}

fn u64_value(value: &Value) -> ExampleResult<u64> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    if let Some(value) = value.as_i64() {
        return Ok(u64::try_from(value)?);
    }
    if let Some(text) = value.as_str() {
        return u64_text(text);
    }
    Err(format!("expected integer-compatible value, got {value:?}").into())
}

fn u8_text(value: &str) -> ExampleResult<u8> {
    Ok(u8::try_from(u64_text(value)?)?)
}

fn u16_text(value: &str) -> ExampleResult<u16> {
    Ok(u16::try_from(u64_text(value)?)?)
}

fn u64_text(value: &str) -> ExampleResult<u64> {
    let text = value.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return Ok(u64::from_str_radix(hex, 16)?);
    }
    Ok(text.parse::<u64>()?)
}

fn mac_bytes(value: &str) -> ExampleResult<Vec<u8>> {
    Ok(MacAddr::from_str(value)?.octets().to_vec())
}

fn decode_hex(hex: &str) -> ExampleResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err("hex strings must contain an even number of characters".into());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        out.push(u8::from_str_radix(&hex[index..index + 2], 16)?);
    }
    Ok(out)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod bgp_materializer_tests {
    use super::{decode_hex, materialize_plan, BGP_PORT};
    use crafter::prelude::*;
    use serde_json::{json, Value};

    #[test]
    fn ipv4_tcp_bgp_keepalive_pins_bgp_port_and_decodes() {
        let plan = json!({
            "stack": ["ipv4", "tcp", "bgp"],
            "metadata": {"root_decoder": "l3:ipv4", "root": "l3:ipv4"},
            "fields": {
                "ipv4": {
                    "src": "192.0.2.10",
                    "dst": "198.51.100.20",
                    "identification": 4660,
                    "ttl": 64,
                    "flags": "df",
                    "protocol": "tcp"
                },
                "tcp": {
                    "src_port": 49152,
                    "dst_port": 65000,
                    "sequence": 1,
                    "acknowledgement": 0,
                    "reserved": 0,
                    "flags": "pa",
                    "window": 4096,
                    "urgent_pointer": 0
                },
                "bgp": {
                    "message_type": "keepalive"
                }
            }
        });

        let vector = materialize_plan(&plan).expect("BGP keepalive plan must materialize");
        let raw_hex = vector
            .get("raw_hex")
            .and_then(Value::as_str)
            .expect("materialized vector must carry raw_hex");
        let bytes = decode_hex(raw_hex).expect("raw_hex must decode");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes)
            .expect("materialized IPv4/TCP/BGP vector must re-decode");
        let tcp = decoded
            .layer::<Tcp>()
            .expect("decoded packet must expose TCP");
        assert_eq!(tcp.destination_port_value(), BGP_PORT);
        decoded
            .layer::<Bgp>()
            .expect("decoded packet must expose BGP through TCP/179");
    }
}

/// Native DHCPv4 oracle fixtures.
///
/// The seeded Scapy reference backend covers the DHCPv4 cases Scapy can encode
/// byte-for-byte (the message-type matrix plus simple option domains; see
/// `tools/oracle/specs/layers/dhcp.yaml`). Scapy cannot represent option
/// overload (52 across `file`/`sname`), RFC 3396 long-option concatenation,
/// typed relay-agent option 82 sub-options, RFC 4361 node-specific client
/// identifiers, RFC 3118 authentication (90), classless static routes (121),
/// or leasequery status/state options (91/92/151-157) exactly. Those cases are
/// covered here by native libcrafter round-trip fixtures: each builds a packet,
/// compiles it, decodes it back through the registry over UDP, and asserts the
/// recompiled bytes are byte-identical and that the typed accessors recover the
/// constructed value. All addresses are RFC 5737 documentation space and all
/// MACs are RFC 7042 documentation EUI-48 values; nothing here touches a
/// network.
#[cfg(test)]
mod dhcp_oracle_fixtures {
    use crafter::prelude::*;
    use std::net::Ipv4Addr;

    const CLIENT_MAC: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01];
    const RELAY_MAC: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02];

    fn client_mac() -> MacAddr {
        MacAddr::from(CLIENT_MAC)
    }

    fn relay_mac() -> MacAddr {
        MacAddr::from(RELAY_MAC)
    }

    /// Wrap a built `Dhcp` layer in an Ethernet/IPv4/UDP frame on the BOOTP
    /// port pair so the registry decodes it as DHCP, then return the compiled
    /// frame bytes.
    fn frame_bytes(dhcp: Dhcp) -> Vec<u8> {
        let packet = Ethernet::new()
            .src(relay_mac())
            .dst(MacAddr::BROADCAST)
            .ethertype(ETHERTYPE_IPV4)
            / Ipv4::new()
                .src(Ipv4Addr::new(192, 0, 2, 1))
                .dst(Ipv4Addr::new(192, 0, 2, 2))
                .ipv4_protocol(Ipv4Protocol::Udp)
            / Udp::new().sport(DHCP_SERVER_PORT).dport(DHCP_CLIENT_PORT)
            / dhcp;
        packet
            .compile()
            .expect("documentation DHCP frame must compile")
            .as_bytes()
            .to_vec()
    }

    /// Decode a compiled frame and return the recompiled bytes plus the decoded
    /// DHCP layer, asserting the registry surfaced a DHCP layer over UDP.
    fn decode_roundtrip(bytes: &[u8]) -> (Vec<u8>, Dhcp) {
        let decoded = Packet::decode_from_link(LinkType::Ethernet, bytes)
            .expect("documentation DHCP frame must decode without panic");
        let dhcp = decoded
            .layer::<Dhcp>()
            .expect("decoded frame must expose a DHCP layer over UDP")
            .clone();
        let recompiled = decoded
            .compile()
            .expect("decoded DHCP frame must recompile")
            .as_bytes()
            .to_vec();
        (recompiled, dhcp)
    }

    /// Build, compile, decode, and recompile, asserting a byte-exact round-trip.
    fn assert_byte_roundtrip(dhcp: Dhcp) -> Dhcp {
        let original = frame_bytes(dhcp);
        let (recompiled, decoded) = decode_roundtrip(&original);
        assert_eq!(
            recompiled, original,
            "DHCPv4 fixture must round-trip byte-for-byte through decode and recompile"
        );
        decoded
    }

    #[test]
    fn dhcp_option_overload_file_and_sname() {
        // Option 52 marks both file and sname as overloaded option areas
        // (RFC 2131 section 4.1). Scapy does not model overloaded BOOTP fields.
        let dhcp = Dhcp::discover(client_mac())
            .xid(0x0102_0304)
            .file_option(DhcpOption::bootfile_name(b"boot/pxelinux.0".to_vec()))
            .sname_option(DhcpOption::host_name("oracle-server"));
        let decoded = assert_byte_roundtrip(dhcp);
        assert_eq!(decoded.option_overload(), Some(OptionOverload::Both));
    }

    #[test]
    fn dhcp_rfc3396_long_option_concatenation() {
        // RFC 3396: a value longer than 255 octets is split across repeated
        // instances of the same option code and read back as one logical value.
        let long_domain = format!("{}.example", "a".repeat(300));
        let dhcp = Dhcp::discover(client_mac())
            .xid(0x1111_2222)
            .option(DhcpOption::domain_name(long_domain.clone()));
        let decoded = assert_byte_roundtrip(dhcp);
        let concatenated = decoded
            .concatenated_option(15)
            .expect("rfc3396 domain-name option must be present")
            .expect("rfc3396 concatenation must decode");
        let payload = concatenated
            .payload()
            .expect("concatenated option payload must encode");
        assert_eq!(payload, long_domain.as_bytes());
        assert!(
            payload.len() > 255,
            "rfc3396 fixture must exceed a single 255-octet option instance"
        );
    }

    #[test]
    fn dhcp_relay_agent_option82_suboptions() {
        // RFC 3046 relay-agent option 82 with typed circuit-id and remote-id
        // sub-options. Scapy treats option 82 as opaque bytes.
        let info = DhcpRelayAgentInfo::new(vec![
            DhcpRelaySuboption::circuit_id(b"eth0:vlan100".to_vec()),
            DhcpRelaySuboption::remote_id(RELAY_MAC.to_vec()),
        ]);
        let dhcp = Dhcp::discover(client_mac())
            .xid(0x3333_4444)
            .relay_agent_info(info.clone());
        let decoded = assert_byte_roundtrip(dhcp);
        let recovered = decoded
            .relay_agent_information()
            .expect("relay-agent option 82 must be present")
            .expect("relay-agent option 82 must decode");
        assert_eq!(recovered, info);
    }

    #[test]
    fn dhcp_rfc4361_node_specific_client_identifier() {
        // RFC 4361 type-255 client identifier (IAID + DUID). Scapy carries
        // option 61 only as an opaque string.
        let identifier =
            DhcpClientIdentifier::node_specific(0x0a0b_0c0d, vec![0x00, 0x01, 0x02, 0x03]);
        let dhcp = Dhcp::discover(client_mac())
            .xid(0x5555_6666)
            .option(DhcpOption::client_identifier_value(identifier.clone()));
        let decoded = assert_byte_roundtrip(dhcp);
        let recovered = decoded
            .client_identifier_value()
            .expect("client identifier option 61 must be present")
            .expect("client identifier option 61 must decode");
        assert_eq!(recovered, identifier);
    }

    #[test]
    fn dhcp_rfc3118_authentication_option() {
        // RFC 3118 option 90 delayed authentication with HMAC-MD5. Scapy has no
        // typed authentication option.
        let auth = DhcpAuthentication::new(
            DhcpAuthProtocol::Delayed,
            DhcpAuthAlgorithm::HmacMd5,
            DhcpReplayDetectionMethod::MonotonicCounter,
            0x0000_0001_0000_0002,
            vec![0xab; 16],
        );
        let dhcp = Dhcp::request(
            client_mac(),
            Ipv4Addr::new(192, 0, 2, 100),
            Ipv4Addr::new(192, 0, 2, 1),
        )
        .xid(0x7777_8888)
        .option(DhcpOption::authentication(auth.clone()));
        let decoded = assert_byte_roundtrip(dhcp);
        let recovered = decoded
            .authentication()
            .expect("authentication option 90 must be present")
            .expect("authentication option 90 must decode");
        assert_eq!(recovered, auth);
    }

    #[test]
    fn dhcp_classless_static_routes_option121() {
        // RFC 3442 classless static routes (option 121) with the canonical
        // significant-octet widths.
        let routes = vec![
            DhcpClasslessRoute::new(
                24,
                Ipv4Addr::new(192, 0, 2, 0),
                Ipv4Addr::new(198, 51, 100, 1),
            ),
            DhcpClasslessRoute::new(0, Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(198, 51, 100, 254)),
        ];
        let dhcp = Dhcp::ack(
            client_mac(),
            Ipv4Addr::new(192, 0, 2, 100),
            Ipv4Addr::new(192, 0, 2, 1),
        )
        .xid(0x9999_aaaa)
        .option(DhcpOption::typed(
            DhcpOptionKind::ClasslessStaticRoute,
            DhcpOptionValue::ClasslessRoutes(routes.clone()),
        ));
        let decoded = assert_byte_roundtrip(dhcp);
        let recovered = decoded
            .classless_static_routes()
            .expect("classless static route option 121 must be present")
            .expect("classless static route option 121 must decode");
        assert_eq!(recovered, routes);
    }

    #[test]
    fn dhcp_leasequery_status_and_state() {
        // RFC 4388 leasequery reply carrying a status-code option (151) and a
        // dhcp-state option (153). Scapy has no leasequery option support.
        let status = DhcpStatusCodeOption::new(DhcpStatusCode::Success, b"ok".to_vec());
        let dhcp = Dhcp::lease_query_by_ip(Ipv4Addr::new(192, 0, 2, 100))
            .xid(0xbbbb_cccc)
            .option(DhcpOption::status_code(status.clone()))
            .option(DhcpOption::dhcp_state(DhcpState::Active));
        let decoded = assert_byte_roundtrip(dhcp);
        let recovered = decoded
            .status_code()
            .expect("leasequery status-code option 151 must be present")
            .expect("leasequery status-code option 151 must decode");
        assert_eq!(recovered, status);
        assert_eq!(
            decoded.message_type_value(),
            Some(DhcpMessageType::LeaseQuery)
        );
    }
}

/// Materializer coverage for IPv4-root DHCP plans.
///
/// These tests drive the live offline `libcrafter_to_reference` materialization
/// path directly: they feed an `ipv4 / udp / dhcp` plan (the shape the seeded
/// generator emits for `--case dhcp-discover` rooted at `l3:ipv4`) to
/// [`materialize_plan`], then assert the emitted vector roots at `l3:ipv4`,
/// carries the BOOTP port pair (68 -> 67), and re-decodes through the public
/// `decode_from_l3` entrypoint with a recoverable DHCP message type. Addresses
/// are RFC 5737 documentation space; nothing touches a network.
#[cfg(test)]
mod ipv4_dhcp_materialization {
    use super::{decode_hex, materialize_plan};
    use crafter::prelude::*;
    use serde_json::{json, Value};

    /// A minimal live-friendly `ipv4 / udp / dhcp` plan, matching the seeded
    /// generator output: only the DHCP op/flags/options are set, so the fixed
    /// BOOTP header fields must fall back to `Dhcp::new()` defaults.
    fn ipv4_dhcp_discover_plan() -> Value {
        json!({
            "stack": ["ipv4", "udp", "dhcp"],
            "metadata": {
                "root_decoder": "l3:ipv4",
                "root": "l3:ipv4"
            },
            "feature_tags": ["ipv4", "udp", "dhcp", "dhcp_behavior"],
            "strict_bytes": true,
            "fields": {
                "ipv4": {
                    "src": "192.0.2.1",
                    "dst": "198.51.100.10",
                    "identification": 4242,
                    "ttl": 64,
                    "flags": "none",
                    "protocol": "udp"
                },
                "udp": {
                    "src_port": 68,
                    "dst_port": 67
                },
                "dhcp": {
                    "op": "bootrequest",
                    "flags": "none",
                    "options": ["message-type=discover", "end"]
                }
            }
        })
    }

    #[test]
    fn ipv4_dhcp_plan_materializes_through_public_surface() {
        let plan = ipv4_dhcp_discover_plan();
        let vector = materialize_plan(&plan).expect("ipv4/udp/dhcp plan must materialize");

        // The vector must root at the IPv4 network layer.
        assert_eq!(
            vector.get("root").and_then(Value::as_str),
            Some("l3:ipv4"),
            "materialized vector must root at l3:ipv4"
        );
        assert_eq!(
            vector.get("decoder").and_then(Value::as_str),
            Some("l3:ipv4"),
            "materialized vector decoder must be l3:ipv4"
        );
        let stack: Vec<&str> = vector
            .get("stack")
            .and_then(Value::as_array)
            .expect("vector must carry a stack array")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(stack, ["ipv4", "udp", "dhcp"]);

        let raw_hex = vector
            .get("raw_hex")
            .and_then(Value::as_str)
            .expect("vector must carry raw_hex bytes");
        assert!(!raw_hex.is_empty(), "materialized vector must not be empty");
        let bytes = decode_hex(raw_hex).expect("raw_hex must decode to bytes");

        // Re-decode the produced bytes through the public IPv4 entrypoint.
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes)
            .expect("materialized IPv4 DHCP vector must re-decode from l3");

        decoded
            .layer::<Ipv4>()
            .expect("re-decoded packet must expose an IPv4 layer");

        let udp = decoded
            .layer::<Udp>()
            .expect("re-decoded packet must expose a UDP layer");
        assert_eq!(udp.source_port_value(), 68, "BOOTP client port");
        assert_eq!(udp.destination_port_value(), 67, "BOOTP server port");

        let dhcp = decoded
            .layer::<Dhcp>()
            .expect("re-decoded packet must expose a DHCP layer over UDP");
        assert_eq!(
            dhcp.message_type_value(),
            Some(DhcpMessageType::Discover),
            "DHCP message type must be present and decode to discover"
        );
    }

    #[test]
    fn ipv4_dhcp_plan_defaults_fixed_bootp_fields() {
        // A plan that omits xid/ciaddr/yiaddr/chaddr (as the smoke generator
        // does) must still materialize via Dhcp::new() defaults rather than
        // failing with a missing-required-field error.
        let plan = ipv4_dhcp_discover_plan();
        let vector = materialize_plan(&plan)
            .expect("ipv4/udp/dhcp plan without fixed BOOTP fields must materialize");
        let raw_hex = vector
            .get("raw_hex")
            .and_then(Value::as_str)
            .expect("vector must carry raw_hex bytes");
        let bytes = decode_hex(raw_hex).expect("raw_hex must decode to bytes");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes)
            .expect("default-filled IPv4 DHCP vector must re-decode");
        let dhcp = decoded
            .layer::<Dhcp>()
            .expect("re-decoded packet must expose a DHCP layer");
        // Defaults: BOOTP request op and Ethernet hardware type/len.
        assert_eq!(dhcp.op_value(), BOOTP_REQUEST);
        assert_eq!(dhcp.hardware_type_value(), DHCP_HTYPE_ETHERNET);
        assert_eq!(dhcp.hardware_len_value(), 6);
    }
}

#[cfg(test)]
mod dot11_materialization {
    use super::{decode_hex, materialize_plan};
    use crafter::prelude::*;
    use serde_json::{json, Value};

    fn raw_bytes(vector: &Value) -> Vec<u8> {
        let raw_hex = vector
            .get("raw_hex")
            .and_then(Value::as_str)
            .expect("vector must carry raw_hex bytes");
        decode_hex(raw_hex).expect("raw_hex must decode")
    }

    #[test]
    fn radiotap_dot11_eapol_key_plan_materializes_with_public_layers() {
        let plan = json!({
            "stack": ["radiotap", "dot11", "llc_snap", "eapol", "payload"],
            "metadata": {"root_decoder": "link:radiotap", "root": "link:radiotap"},
            "feature_tags": ["radiotap", "dot11", "llc_snap", "eapol"],
            "strict_bytes": true,
            "fields": {
                "radiotap": {
                    "version": 0,
                    "pad": 0,
                    "flags": "fcs_present",
                    "rate": 2,
                    "channel_frequency": 2412,
                    "channel_flags": "two_ghz_cck",
                    "rx_flags": 0,
                    "tx_flags": 8
                },
                "dot11": {
                    "frame_control": 8,
                    "duration_id": 0,
                    "addr1": "00:00:5e:00:53:01",
                    "addr2": "00:00:5e:00:53:02",
                    "addr3": "00:00:5e:00:53:03",
                    "sequence_control": 4096
                },
                "llc_snap": {
                    "dsap": 170,
                    "ssap": 170,
                    "control": 3,
                    "oui": {"hex": "000000"},
                    "ethertype": "eapol"
                },
                "eapol": {
                    "version": 2,
                    "packet_type": "key",
                    "body_length": 0,
                    "descriptor_type": "rsn_key",
                    "key_information": 266,
                    "key_length": 16,
                    "replay_counter": 1,
                    "key_nonce": {"hex": "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"},
                    "key_iv": {"hex": "00000000000000000000000000000000"},
                    "key_rsc": {"hex": "0000000000000000"},
                    "key_id": {"hex": "0000000000000000"},
                    "key_mic": {"hex": "00000000000000000000000000000000"},
                    "key_data_length": 0,
                    "key_data": {"hex": "0100000fac040100000fac040100000fac020000"}
                },
                "payload": {"hex": "01020304", "length": 4}
            }
        });

        let vector = materialize_plan(&plan).expect("Dot11 EAPOL-Key plan must materialize");
        assert_eq!(
            vector.get("root").and_then(Value::as_str),
            Some("link:radiotap")
        );
        let bytes = raw_bytes(&vector);
        let decoded = Packet::decode_from_link(LinkType::Radiotap, &bytes)
            .expect("materialized radiotap Dot11 EAPOL-Key vector must decode");

        decoded.layer::<Radiotap>().expect("radiotap layer");
        decoded.layer::<Dot11>().expect("dot11 layer");
        decoded.layer::<LlcSnap>().expect("llc/snap layer");
        let eapol = decoded.layer::<Eapol>().expect("eapol layer");
        assert_eq!(eapol.packet_type_value(), EAPOL_TYPE_KEY);
        let key = decoded.layer::<EapolKey>().expect("eapol key layer");
        assert_eq!(key.key_data_bytes().len(), 20);
    }

    #[test]
    fn bare_dot11_control_plan_materializes_from_link_root() {
        let plan = json!({
            "stack": ["dot11", "payload"],
            "metadata": {"root_decoder": "link:dot11", "root": "link:dot11"},
            "feature_tags": ["dot11"],
            "strict_bytes": true,
            "fields": {
                "dot11": {
                    "frame_control": 180,
                    "duration_id": 314,
                    "addr1": "00:00:5e:00:53:10",
                    "addr2": "00:00:5e:00:53:20"
                },
                "payload": {"hex": "aabbcc", "length": 3}
            }
        });

        let vector = materialize_plan(&plan).expect("bare Dot11 control plan must materialize");
        assert_eq!(
            vector.get("decoder").and_then(Value::as_str),
            Some("link:dot11")
        );
        let decoded = Packet::decode_from_link(LinkType::Ieee80211, &raw_bytes(&vector))
            .expect("materialized bare Dot11 vector must decode");
        let dot11 = decoded.layer::<Dot11>().expect("dot11 layer");
        assert_eq!(
            dot11.frame_control_value().frame_type(),
            DOT11_FRAME_TYPE_CONTROL
        );
        assert_eq!(
            dot11.frame_control_value().subtype(),
            DOT11_CONTROL_SUBTYPE_RTS
        );
    }

    #[test]
    fn radiotap_dot11_rsn_plan_attaches_rsn_tag_to_dot11() {
        let plan = json!({
            "stack": ["radiotap", "dot11", "rsn"],
            "metadata": {"root_decoder": "link:radiotap", "root": "link:radiotap"},
            "feature_tags": ["radiotap", "dot11", "rsn"],
            "strict_bytes": true,
            "fields": {
                "radiotap": {"version": 0, "pad": 0},
                "dot11": {
                    "frame_control": 128,
                    "duration_id": 0,
                    "addr1": "ff:ff:ff:ff:ff:ff",
                    "addr2": "00:00:5e:00:53:02",
                    "addr3": "00:00:5e:00:53:03",
                    "sequence_control": 0,
                    "management_fixed_fields": {"hex": "000000000000000064000100"}
                },
                "rsn": {
                    "element_id": 48,
                    "version": 1,
                    "group_cipher_suite": "ccmp_128",
                    "pairwise_cipher_suites": ["ccmp_128"],
                    "akm_suites": ["psk"],
                    "capabilities": 0
                }
            }
        });

        let vector = materialize_plan(&plan).expect("Dot11 RSN plan must materialize");
        let decoded = Packet::decode_from_link(LinkType::Radiotap, &raw_bytes(&vector))
            .expect("materialized Dot11 RSN vector must decode");
        let dot11 = decoded.layer::<Dot11>().expect("dot11 layer");
        let rsn = dot11
            .rsn_information()
            .expect("RSN tag must be attached to Dot11")
            .expect("RSN tag must parse");
        assert_eq!(rsn.group_cipher_suite(), RSN_CIPHER_SUITE_CCMP_128);
        assert_eq!(rsn.akm_suites(), &[RSN_AKM_SUITE_PSK]);
    }
}

#[cfg(test)]
mod igmp_materialization {
    use super::{decode_hex, materialize_plan};
    use crafter::prelude::*;
    use crafter::protocols::igmp::IgmpExtension;
    use serde_json::{json, Value};

    fn raw_bytes(vector: &Value) -> Vec<u8> {
        let raw_hex = vector
            .get("raw_hex")
            .and_then(Value::as_str)
            .expect("vector must carry raw_hex bytes");
        decode_hex(raw_hex).expect("raw_hex must decode")
    }

    #[test]
    fn compact_igmp_report_plan_infers_report_and_extension_layers() {
        let plan = json!({
            "stack": ["ipv4", "igmp"],
            "metadata": {"root_decoder": "l3:ipv4", "root": "l3:ipv4"},
            "feature_tags": ["igmp", "igmp_v3_report"],
            "strict_bytes": true,
            "fields": {
                "ipv4": {
                    "src": "192.0.2.10",
                    "dst": "224.0.0.2",
                    "identification": 4919,
                    "ttl": 1,
                    "flags": "none",
                    "protocol": "igmp"
                },
                "igmp": {
                    "type": "v3_membership_report",
                    "report_flags": ["extension"],
                    "group_records": [
                        {
                            "record_type": "mode_is_include",
                            "multicast_address": "233.252.0.17",
                            "source_addresses": ["192.0.2.44"]
                        }
                    ],
                    "extension_tlvs": [
                        {
                            "extension_type": "unassigned",
                            "extension_value": {"hex": "0102"}
                        }
                    ]
                }
            }
        });

        let vector = materialize_plan(&plan).expect("IGMP report plan must materialize");
        assert_eq!(vector.get("root").and_then(Value::as_str), Some("l3:ipv4"));
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw_bytes(&vector))
            .expect("materialized IGMP report must decode from l3");

        decoded.layer::<Igmp>().expect("IGMP fixed header");
        let report = decoded.layer::<IgmpReport>().expect("IGMP report body");
        assert_eq!(report.number_of_group_records_value(), 1);
        decoded
            .layer::<IgmpExtension>()
            .expect("IGMP extension TLV");
    }

    #[test]
    fn explicit_igmp_query_plan_uses_child_layer_fields() {
        let plan = json!({
            "stack": ["ipv4", "igmp", "igmp_query"],
            "metadata": {"root_decoder": "l3:ipv4", "root": "l3:ipv4"},
            "feature_tags": ["igmp", "igmp_v3_query"],
            "strict_bytes": true,
            "fields": {
                "ipv4": {
                    "src": "192.0.2.10",
                    "dst": "232.0.0.17",
                    "identification": 4920,
                    "ttl": 1,
                    "flags": "none",
                    "protocol": "igmp"
                },
                "igmp": {
                    "type": "membership_query",
                    "code": 100,
                    "group_address": "232.0.0.17"
                },
                "igmp_query": {
                    "suppress_router_side_processing": true,
                    "qrv": 2,
                    "qqic": 125,
                    "source_addresses": ["192.0.2.44", "198.51.100.44"]
                }
            }
        });

        let vector = materialize_plan(&plan).expect("IGMP query plan must materialize");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw_bytes(&vector))
            .expect("materialized IGMP query must decode from l3");
        let query = decoded.layer::<IgmpQuery>().expect("IGMP query body");
        assert!(query.suppress_router_side_processing());
        assert_eq!(query.querier_robustness_variable_value(), 2);
        assert_eq!(query.number_of_sources_value(), 2);
    }
}
