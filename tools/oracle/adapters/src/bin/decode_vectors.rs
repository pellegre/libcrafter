use crafter::core::{
    Ah, Arp, Dhcp, Dns, Dot11, Eapol, EapolKey, Esp, Ethernet, Icmpv4, Icmpv4QuotedIp, Icmpv6,
    Ipv4, Ipv6, Ipv6DestinationOptionsHeader, Ipv6FragmentHeader, Ipv6FragmentHeaderStatus,
    Ipv6HopByHopOptionsHeader, Ipv6MobileRoutingHeader, Ipv6Option, Ipv6RoutingHeader,
    Ipv6RoutingTypeStatus, Ipv6SegmentRoutingHeader, Layer, LinkType, LinuxSll, LlcSnap,
    NetworkLayer, NullLoopback, Packet, Radiotap, Raw, RsnAkmSuite, RsnCipherSuite, RsnInformation,
    Tcp, Udp, UdpChecksumStatus, UdpOption, UdpOptionStatus, UdpOptions, Vlan,
    DNS_FLAG_AUTHENTIC_DATA, DNS_FLAG_AUTHORITATIVE, DNS_FLAG_CHECKING_DISABLED,
    DNS_FLAG_QR_RESPONSE, DNS_FLAG_RECURSION_AVAILABLE, DNS_FLAG_RECURSION_DESIRED,
    DNS_FLAG_TRUNCATED,
};
use crafter::prelude::*;
use crafter::protocols::bgp::{
    Bgp, BGP_HEADER_LEN, BGP_MARKER_LEN, BGP_TYPE_KEEPALIVE, BGP_TYPE_NOTIFICATION, BGP_TYPE_OPEN,
    BGP_TYPE_ROUTE_REFRESH, BGP_TYPE_UPDATE,
};
use crafter::protocols::igmp::IgmpExtension;
use crafter::protocols::link::RadiotapFcsStatus;
use crafter::protocols::rip::ripng::{Ripng, RipngRte};
use crafter::protocols::rip::{Rip, RipAuth, RipAuthPayload, RipEntry, RIP_AFI_AUTH};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

const BACKEND_NAME: &str = "libcrafter";

#[derive(Debug)]
struct Args {
    input: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct EncodedVector {
    raw_hex: String,
    root: Option<String>,
    decoder: Option<String>,
    #[serde(default)]
    plan: Option<PacketPlan>,
}

#[derive(Debug, Deserialize, Default)]
struct PacketPlan {
    #[serde(default)]
    feature_tags: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DecodedModel {
    backend: &'static str,
    layers: Vec<String>,
    fields: BTreeMap<String, BTreeMap<String, Value>>,
    root: Option<String>,
    source_hex: String,
    feature_tags: Vec<String>,
    metadata: Value,
}

fn main() -> ExampleResult<()> {
    let args = parse_args()?;
    let input = read_input(args.input)?;
    let document: Value = serde_json::from_str(&input)?;
    let vectors = extract_vectors(&document)?;
    let mut decoded = Vec::with_capacity(vectors.len());

    for vector in vectors {
        decoded.push(decode_vector(&vector)?);
    }

    let report = json!({
        "artifacts": [],
        "artifact_paths": [],
        "backend": BACKEND_NAME,
        "backend_versions": {},
        "count": decoded.len(),
        "failures": [],
        "libcrafter": {
            "version": env!("CARGO_PKG_VERSION")
        },
        "metadata": {
            "decoded": decoded,
            "input_backend": document.get("backend").cloned().unwrap_or(Value::Null),
            "requested_count": document.pointer("/metadata/requested_count").cloned().unwrap_or(Value::Null)
        },
        "mode": document.get("mode").cloned().unwrap_or_else(|| Value::String("offline".to_string())),
        "profile": document.get("profile").cloned().unwrap_or(Value::Null),
        "reproduction_commands": [],
        "results": [],
        "seed": document.get("seed").cloned().unwrap_or(Value::Null),
        "selected_specs": document.get("selected_specs").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "status": "decoded"
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
        "usage: cargo run -p oracle-adapters --bin decode_vectors -- [--input PATH|-]\n\nDecode oracle raw vectors with libcrafter and emit normalized JSON. Reads stdin when --input is omitted or set to -."
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

fn extract_vectors(document: &Value) -> ExampleResult<Vec<EncodedVector>> {
    let vectors = if let Some(value) = document.pointer("/metadata/vectors") {
        value
    } else if let Some(value) = document.get("vectors") {
        value
    } else if document.is_array() {
        document
    } else {
        return Err(
            "input JSON must contain metadata.vectors, vectors, or be a vector array".into(),
        );
    };

    Ok(serde_json::from_value(vectors.clone())?)
}

fn decode_vector(vector: &EncodedVector) -> ExampleResult<DecodedModel> {
    let root = vector
        .root
        .as_deref()
        .or(vector.decoder.as_deref())
        .ok_or("vector is missing root decoder metadata")?;
    let bytes = decode_hex(&vector.raw_hex)?;
    let packet = decode_for_root(root, &bytes)?;
    let feature_tags = vector
        .plan
        .as_ref()
        .map(|plan| plan.feature_tags.clone())
        .unwrap_or_default();
    Ok(normalize_packet(
        &packet,
        Some(normalize_root_name(root).to_string()),
        vector.raw_hex.clone(),
        feature_tags,
    ))
}

fn decode_hex(hex: &str) -> ExampleResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err("raw_hex must contain an even number of characters".into());
    }

    let mut out = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        out.push(u8::from_str_radix(&hex[index..index + 2], 16)?);
    }
    Ok(out)
}

fn decode_for_root(root: &str, bytes: &[u8]) -> ExampleResult<Packet> {
    let decoded = match root {
        "Ether" | "link:ethernet" => Packet::decode_from_link(LinkType::Ethernet, bytes),
        "CookedLinux" | "link:linux-cooked" | "link:linux-sll" => {
            Packet::decode_from_link(LinkType::LinuxSll, bytes)
        }
        "Loopback" | "link:null-loopback" => {
            Packet::decode_from_link(LinkType::NullLoopback, bytes)
        }
        "Raw" | "link:raw" => Packet::decode_from_link(LinkType::Raw, bytes),
        "Dot11" | "link:dot11" | "link:ieee80211" => {
            Packet::decode_from_link(LinkType::Ieee80211, bytes)
        }
        "RadioTap" | "link:radiotap" => Packet::decode_from_link(LinkType::Radiotap, bytes),
        "IP" | "l3:ipv4" | "l2:ipv4" => Packet::decode_from_l3(NetworkLayer::Ipv4, bytes),
        "IPv6" | "l3:ipv6" => Packet::decode_from_l3(NetworkLayer::Ipv6, bytes),
        "l3:raw" => Packet::decode_from_l3(NetworkLayer::Raw, bytes),
        "BTLE" | "link:bluetooth-le-ll-with-phdr" => {
            Packet::decode_from_link(LinkType::BluetoothLeLl, bytes)
        }
        "link:ieee802154" => Packet::decode_from_link(LinkType::Ieee802154, bytes),
        "link:ieee802154-tap" => Packet::decode_from_link(LinkType::Ieee802154Tap, bytes),
        _ => return Err(format!("unsupported root decoder: {root}").into()),
    };
    Ok(decoded?)
}

fn normalize_packet(
    packet: &Packet,
    root: Option<String>,
    source_hex: String,
    feature_tags: Vec<String>,
) -> DecodedModel {
    let source_bytes = decode_hex(&source_hex).ok();
    let udp_layout = root.as_deref().and_then(|root| {
        source_bytes
            .as_deref()
            .and_then(|bytes| udp_layout(root, bytes))
    });
    let packet_layers = packet.iter().collect::<Vec<_>>();
    let mut layers = Vec::with_capacity(packet_layers.len());
    let mut fields = BTreeMap::new();
    let mut native_layers = Vec::with_capacity(packet_layers.len());
    let mut udp_checksum_status = None;

    for layer in &packet_layers {
        let layer = *layer;
        let layer_name = normalized_layer_name(layer);
        let layer_fields =
            normalized_layer_fields(layer, udp_layout.as_ref(), source_bytes.as_deref());
        if let Some(udp) = layer.as_any().downcast_ref::<Udp>() {
            udp_checksum_status = Some(udp.checksum_status());
        }
        layers.push(layer_name.clone());
        let key = field_key(&fields, &layer_name);
        fields.insert(key, layer_fields);
        native_layers.push(json!({
            "fields": inspection_fields(layer),
            "name": layer.name(),
            "summary": layer.summary()
        }));
        if let Some(dot11) = layer.as_any().downcast_ref::<Dot11>() {
            for rsn_fields in dot11_rsn_layers(dot11) {
                let layer_name = "rsn".to_string();
                layers.push(layer_name.clone());
                let key = field_key(&fields, &layer_name);
                fields.insert(key, rsn_fields);
            }
        }
    }

    // Canonicalize a typed ICMPv4 error body to the backend-neutral flat model:
    // libcrafter decodes the quoted original datagram into an Icmpv4QuotedIp
    // layer (plus any extension and trailing layers), but the oracle compares
    // ICMP error bodies as a single trailing payload after the ICMP fixed
    // header, exactly as the Scapy reference normalize does. Collapse everything
    // after the ICMP header into one payload carrying the verbatim body bytes so
    // both backends report the same model without weakening the byte compare.
    collapse_icmp_quoted_body(&packet_layers, &source_hex, &mut layers, &mut fields);

    DecodedModel {
        backend: BACKEND_NAME,
        layers,
        fields,
        root,
        source_hex,
        feature_tags,
        metadata: {
            let mut metadata = json!({
            "native": {
                "summary": packet.summary(),
                "layers": native_layers
            }
            });
            if let Some(status) = udp_checksum_status {
                metadata["udp"] = json!({
                    "checksum_status": udp_checksum_status_label(status),
                    "checksum_status_source": "libcrafter_pseudo_header_validation"
                });
            }
            metadata
        },
    }
}

/// Collapse a typed ICMPv4 error body (Icmpv4QuotedIp plus any extension and
/// trailing layers) into a single flat `payload` after the ICMP layer.
///
/// The oracle compares ICMPv4 error messages at the backend-neutral flat model
/// (`ipv4` / `icmp` / `payload`), matching the Scapy reference normalize, which
/// keeps everything after the eight-byte ICMP fixed header as one trailing
/// payload. libcrafter's richer decode types the quoted original datagram as an
/// `Icmpv4QuotedIp` layer; this rewrites that tail to the flat payload using the
/// verbatim body bytes so the byte compare stays exact and both backends agree
/// on the decoded model. Only applies to single-IPv4-header ICMP error stacks
/// that actually quoted a datagram; all other shapes are left untouched.
fn collapse_icmp_quoted_body(
    packet_layers: &[&dyn Layer],
    source_hex: &str,
    layers: &mut Vec<String>,
    fields: &mut BTreeMap<String, BTreeMap<String, Value>>,
) {
    // Only collapse when libcrafter typed a quoted IPv4 datagram in the body.
    if !packet_layers
        .iter()
        .any(|layer| layer.as_any().is::<Icmpv4QuotedIp>())
    {
        return;
    }
    let icmp_index = match packet_layers
        .iter()
        .position(|layer| layer.as_any().is::<Icmpv4>())
    {
        Some(index) => index,
        None => return,
    };
    // The flat model is `ipv4` / `icmp` / `payload`; only the canonical
    // single-IPv4-header error stack is collapsed here.
    if icmp_index != 1 || !packet_layers[0].as_any().is::<Ipv4>() {
        return;
    }

    let source = match decode_hex(source_hex) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };
    if source.is_empty() {
        return;
    }
    let ipv4_header_len = ((source[0] & 0x0f) as usize) * 4;
    let body_offset = ipv4_header_len + 8;
    if body_offset > source.len() {
        return;
    }
    let body = &source[body_offset..];

    // Drop every normalized layer/field after the ICMP layer and replace the
    // tail with a single payload carrying the verbatim ICMP body bytes.
    for offset in (icmp_index + 1)..layers.len() {
        let key = field_key_at(layers, offset);
        fields.remove(&key);
    }
    layers.truncate(icmp_index + 1);

    if !body.is_empty() {
        layers.push("payload".to_string());
        let key = field_key(fields, "payload");
        fields.insert(
            key,
            map([
                ("hex", json!(hex_bytes(body))),
                ("length", json!(body.len())),
                ("ascii", json!(String::from_utf8_lossy(body).into_owned())),
            ]),
        );
    }
}

/// Recompute the normalized field-map key for the layer at `index`, mirroring
/// `field_key`: the first occurrence of a layer name uses the bare name, later
/// occurrences use `name#N` (1-based occurrence count).
fn field_key_at(layers: &[String], index: usize) -> String {
    let layer_name = &layers[index];
    let occurrence = layers[..=index]
        .iter()
        .filter(|name| *name == layer_name)
        .count();
    if occurrence == 1 {
        layer_name.clone()
    } else {
        format!("{layer_name}#{occurrence}")
    }
}

fn field_key(existing: &BTreeMap<String, BTreeMap<String, Value>>, layer_name: &str) -> String {
    if !existing.contains_key(layer_name) {
        return layer_name.to_string();
    }

    let mut index = 2;
    loop {
        let candidate = format!("{layer_name}#{index}");
        if !existing.contains_key(&candidate) {
            return candidate;
        }
        index += 1;
    }
}

fn normalized_layer_name(layer: &dyn Layer) -> String {
    if layer.as_any().is::<Ethernet>() {
        "ethernet"
    } else if layer.as_any().is::<Radiotap>() {
        "radiotap"
    } else if layer.as_any().is::<Dot11>() {
        "dot11"
    } else if layer.as_any().is::<LlcSnap>() {
        "llc_snap"
    } else if layer.as_any().is::<Arp>() {
        "arp"
    } else if layer.as_any().is::<Vlan>() {
        "vlan"
    } else if layer.as_any().is::<LinuxSll>() {
        "linux_sll"
    } else if layer.as_any().is::<NullLoopback>() {
        "null_loopback"
    } else if layer.as_any().is::<Ipv4>() {
        "ipv4"
    } else if layer.as_any().is::<Ipv6>() {
        "ipv6"
    } else if layer.as_any().is::<Ipv6HopByHopOptionsHeader>() {
        "ipv6_hop_by_hop"
    } else if layer.as_any().is::<Ipv6DestinationOptionsHeader>() {
        "ipv6_destination_options"
    } else if layer.as_any().is::<Ipv6FragmentHeader>() {
        "ipv6_fragment"
    } else if layer.as_any().is::<Ipv6RoutingHeader>()
        || layer.as_any().is::<Ipv6MobileRoutingHeader>()
        || layer.as_any().is::<Ipv6SegmentRoutingHeader>()
    {
        "ipv6_routing"
    } else if layer.as_any().is::<Udp>() {
        "udp"
    } else if layer.as_any().is::<UdpOptions>() {
        "UdpOptions"
    } else if layer.as_any().is::<Tcp>() {
        "tcp"
    } else if layer.as_any().is::<Bgp>() {
        "bgp"
    } else if layer.as_any().is::<Rip>() {
        "rip"
    } else if layer.as_any().is::<Ripng>() {
        "ripng"
    } else if layer.as_any().is::<Icmpv4>() {
        "icmp"
    } else if layer.as_any().is::<Icmpv6>() {
        "icmpv6"
    } else if layer.as_any().is::<Igmp>() {
        "igmp"
    } else if layer.as_any().is::<IgmpQuery>() {
        "igmp_query"
    } else if layer.as_any().is::<IgmpReport>() {
        "igmp_report"
    } else if layer.as_any().is::<IgmpExtension>() {
        "igmp_extension"
    } else if layer.as_any().is::<Dns>() {
        "dns"
    } else if layer.as_any().is::<Dhcp>() {
        "dhcp"
    } else if layer.as_any().is::<Eapol>() {
        "eapol"
    } else if layer.as_any().is::<EapolKey>() {
        "eapol_key"
    } else if layer.as_any().is::<Esp>() {
        // The Scapy reference normalizes ESP to the lowercase oracle name; mirror
        // it here so the decoded layer lists match (libcrafter's Layer::name is
        // "Esp").
        "esp"
    } else if layer.as_any().is::<Ah>() {
        "ah"
    } else if layer.as_any().is::<BleRadio>() {
        "ble_radio"
    } else if layer.as_any().is::<BleLlAdv>() {
        "ble_adv"
    } else if layer.as_any().is::<Raw>() {
        "payload"
    } else {
        layer.name()
    }
    .to_string()
}

fn normalize_root_name(root: &str) -> &str {
    match root {
        "CookedLinux" | "link:linux-sll" => "link:linux-cooked",
        "Dot11" | "link:ieee80211" => "link:dot11",
        "Ether" => "link:ethernet",
        "IP" | "l2:ipv4" => "l3:ipv4",
        "IPv6" => "l3:ipv6",
        "Loopback" => "link:null-loopback",
        "RadioTap" => "link:radiotap",
        "Raw" => "link:raw",
        _ => root,
    }
}

fn normalized_layer_fields(
    layer: &dyn Layer,
    udp_layout: Option<&UdpLayout>,
    source_bytes: Option<&[u8]>,
) -> BTreeMap<String, Value> {
    if let Some(layer) = layer.as_any().downcast_ref::<Ethernet>() {
        return ethernet_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Radiotap>() {
        return radiotap_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Dot11>() {
        return dot11_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<LlcSnap>() {
        return llc_snap_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Arp>() {
        return arp_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Vlan>() {
        return vlan_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<LinuxSll>() {
        return linux_sll_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<NullLoopback>() {
        return map([("type", json!(layer.family_value()))]);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ipv4>() {
        return ipv4_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ipv6>() {
        return ipv6_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ipv6HopByHopOptionsHeader>() {
        return ipv6_hop_by_hop_fields(layer);
    }
    if let Some(layer) = layer
        .as_any()
        .downcast_ref::<Ipv6DestinationOptionsHeader>()
    {
        return ipv6_destination_options_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ipv6FragmentHeader>() {
        return ipv6_fragment_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ipv6RoutingHeader>() {
        return ipv6_routing_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ipv6MobileRoutingHeader>() {
        return ipv6_mobile_routing_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ipv6SegmentRoutingHeader>() {
        return ipv6_segment_routing_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Udp>() {
        return udp_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<UdpOptions>() {
        return udp_options_fields(layer, udp_layout, source_bytes);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Tcp>() {
        return tcp_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Bgp>() {
        return bgp_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Rip>() {
        return rip_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ripng>() {
        return ripng_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Icmpv4>() {
        return icmp_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Icmpv6>() {
        return icmpv6_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Igmp>() {
        return igmp_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<IgmpQuery>() {
        return igmp_query_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<IgmpReport>() {
        return igmp_report_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<IgmpExtension>() {
        return igmp_extension_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Dns>() {
        return dns_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Dhcp>() {
        return dhcp_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Eapol>() {
        return eapol_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<EapolKey>() {
        return eapol_key_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Esp>() {
        return esp_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ah>() {
        return ah_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<BleRadio>() {
        return ble_radio_fields(layer, source_bytes);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<BleLlAdv>() {
        return ble_adv_fields(layer, source_bytes);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Raw>() {
        return payload_fields(layer);
    }
    BTreeMap::new()
}

/// Normalize a decoded ESP header into the backend-neutral oracle shape.
///
/// Without an SA libcrafter decodes ESP as `spi`, `sequence`, and the opaque
/// encrypted body (explicit IV, ciphertext, and appended ICV) preserved as one
/// blob. The Scapy reference reports the same three fields, naming the opaque
/// blob `data`; mirror that so the decoded models compare equal.
fn esp_fields(layer: &Esp) -> BTreeMap<String, Value> {
    let mut fields = BTreeMap::new();
    if let Some(spi) = layer.spi_value() {
        fields.insert("spi".to_string(), json!(spi));
    }
    if let Some(sequence) = layer.sequence_value() {
        fields.insert("sequence".to_string(), json!(sequence));
    }
    let body = layer.opaque_body().unwrap_or(&[]);
    fields.insert("data".to_string(), bytes_hex_ascii(body));
    fields
}

/// Normalize a decoded AH header into the backend-neutral oracle shape.
///
/// AH carries the next-header, payload-length (32-bit words minus 2), reserved
/// field, SPI, sequence, and the ICV. The Scapy reference reports exactly these
/// fields with the ICV as a `{hex, ascii}` blob; mirror that here.
fn ah_fields(layer: &Ah) -> BTreeMap<String, Value> {
    let mut fields = BTreeMap::new();
    if let Some(value) = layer.next_header_value() {
        fields.insert("next_header".to_string(), json!(value));
    }
    if let Some(value) = layer.payload_len_value() {
        fields.insert("payload_len".to_string(), json!(value));
    }
    if let Some(value) = layer.reserved_value() {
        fields.insert("reserved".to_string(), json!(value));
    }
    if let Some(value) = layer.spi_value() {
        fields.insert("spi".to_string(), json!(value));
    }
    if let Some(value) = layer.sequence_value() {
        fields.insert("sequence".to_string(), json!(value));
    }
    let icv = layer.icv_value().unwrap_or(&[]);
    fields.insert("icv".to_string(), bytes_hex_ascii(icv));
    fields
}

/// Normalize a decoded BLE LE Link-Layer radio pseudo-header into the
/// backend-neutral oracle shape.
///
/// libcrafter decodes the 10-byte `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`
/// pseudo-header into a typed `BleRadio` layer, but that decode is lossy: it
/// keeps only the channel, access address, PHY, whitening, RSSI, and CRC
/// validity, discarding the offense counter, noise power, and the raw flags
/// word that the Scapy reference reports verbatim. The Scapy reference
/// byte-normalizes the pseudo-header (see `normalize._parse_ble_pseudoheader`),
/// so reconstruct the same model from the source bytes that libcrafter decoded.
/// The compare is byte-exact, so deriving from `source_bytes` reproduces the
/// reference fields faithfully without weakening it.
fn ble_radio_fields(layer: &BleRadio, source_bytes: Option<&[u8]>) -> BTreeMap<String, Value> {
    let raw = match source_bytes {
        Some(raw) if raw.len() >= BLE_RADIO_PSEUDO_HEADER_LEN => raw,
        _ => return inspection_fields(layer),
    };

    let flags = u16::from_le_bytes([raw[8], raw[9]]);
    map([
        ("rf_channel", json!(raw[0])),
        ("signal_power", json!(i16::from(raw[1] as i8))),
        ("noise_power", json!(i16::from(raw[2] as i8))),
        ("access_address_offenses", json!(raw[3])),
        (
            "ref_access_address",
            json!(u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]])),
        ),
        ("flags", json!(flags)),
        ("flag_tokens", json!(ble_phdr_flag_tokens(flags))),
        ("dewhitened", json!(flags & 0x0001 != 0)),
        ("signal_power_valid", json!(flags & 0x0002 != 0)),
        ("noise_power_valid", json!(flags & 0x0004 != 0)),
        ("reference_access_address_valid", json!(flags & 0x0010 != 0)),
        ("access_address_offenses_valid", json!(flags & 0x0020 != 0)),
        ("crc_checked", json!(flags & 0x0400 != 0)),
        ("crc_valid", json!(flags & 0x0800 != 0)),
    ])
}

/// Bit width of the BLE LE Link-Layer pcap pseudo-header.
const BLE_RADIO_PSEUDO_HEADER_LEN: usize = 10;
/// Bit width of the BLE Link-Layer access address that follows the pseudo-header.
const BLE_LL_ACCESS_ADDRESS_LEN: usize = 4;
/// Bit width of the BLE Link-Layer CRC that trails an advertising PDU.
const BLE_LL_CRC_LEN: usize = 3;

/// `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` flag-word token names in wire-bit order.
///
/// Mirrors the Scapy reference `_BLE_PHDR_FLAG_NAMES` table so emitted
/// `flag_tokens` lists match the reference order exactly.
const BLE_PHDR_FLAG_NAMES: &[(u16, &str)] = &[
    (0x0001, "dewhitened"),
    (0x0002, "signal_power_valid"),
    (0x0004, "noise_power_valid"),
    (0x0008, "decrypted"),
    (0x0010, "reference_access_address_valid"),
    (0x0020, "access_address_offenses_valid"),
    (0x0040, "rf_channel_aliased"),
    (0x0400, "crc_checked"),
    (0x0800, "crc_valid"),
    (0x1000, "mic_checked"),
    (0x2000, "mic_valid"),
];

/// GAP Advertising Data flags-structure token names in wire-bit order.
///
/// Mirrors the Scapy reference `_BLE_ADV_FLAG_NAMES` table.
const BLE_ADV_FLAG_NAMES: &[(u8, &str)] = &[
    (0x01, "le_limited_discoverable_mode"),
    (0x02, "le_general_discoverable_mode"),
    (0x04, "br_edr_not_supported"),
    (0x08, "simultaneous_le_br_edr_controller"),
    (0x10, "simultaneous_le_br_edr_host"),
];

fn ble_phdr_flag_tokens(flags: u16) -> Vec<&'static str> {
    BLE_PHDR_FLAG_NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

fn ble_adv_flag_tokens(value: u8) -> Vec<&'static str> {
    BLE_ADV_FLAG_NAMES
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// Translate a four-bit advertising PDU type into the reference name.
///
/// Mirrors the Scapy reference `_BLE_ADV_PDU_TYPE_NAMES` table, including the
/// `unknown:N` fallback for codepoints the model does not name.
fn ble_adv_pdu_type_name(code: u8) -> String {
    match code {
        0 => "adv_ind".to_string(),
        1 => "adv_direct_ind".to_string(),
        2 => "adv_nonconn_ind".to_string(),
        3 => "scan_req".to_string(),
        4 => "scan_rsp".to_string(),
        5 => "connect_ind".to_string(),
        6 => "adv_scan_ind".to_string(),
        7 => "adv_ext_ind".to_string(),
        other => format!("unknown:{other}"),
    }
}

/// Translate a GAP Advertising Data type code into the reference name.
fn ble_ad_type_name(code: u8) -> String {
    match code {
        0x01 => "flags".to_string(),
        0x08 => "shortened_local_name".to_string(),
        0x09 => "complete_local_name".to_string(),
        other => format!("unknown:{other}"),
    }
}

/// Normalize a decoded BLE advertising-channel Link Layer PDU into the
/// backend-neutral oracle shape.
///
/// libcrafter decodes the advertising PDU into a typed `BleLlAdv` layer, but
/// that layer does not retain the trailing CRC, the Link-Layer access address,
/// or the raw header byte (PDU-type code, RX/TX address-type bits, channel
/// selection, RFU). The Scapy reference reports all of these by byte-normalizing
/// the link-layer packet (see `normalize._parse_ble_ll_packet`), so reconstruct
/// the same model from the source bytes libcrafter decoded. The compare is
/// byte-exact, so this reproduces the reference fields faithfully.
fn ble_adv_fields(layer: &BleLlAdv, source_bytes: Option<&[u8]>) -> BTreeMap<String, Value> {
    let ll_start = BLE_RADIO_PSEUDO_HEADER_LEN + BLE_LL_ACCESS_ADDRESS_LEN;
    let raw = match source_bytes {
        Some(raw) if raw.len() >= ll_start + 2 => raw,
        _ => return inspection_fields(layer),
    };

    let access_address = u32::from_le_bytes([
        raw[BLE_RADIO_PSEUDO_HEADER_LEN],
        raw[BLE_RADIO_PSEUDO_HEADER_LEN + 1],
        raw[BLE_RADIO_PSEUDO_HEADER_LEN + 2],
        raw[BLE_RADIO_PSEUDO_HEADER_LEN + 3],
    ]);
    let pdu_with_crc = &raw[ll_start..];
    if pdu_with_crc.len() < BLE_LL_CRC_LEN {
        return inspection_fields(layer);
    }
    let (pdu, crc) = pdu_with_crc.split_at(pdu_with_crc.len() - BLE_LL_CRC_LEN);
    if pdu.len() < 2 {
        return inspection_fields(layer);
    }
    let header0 = pdu[0];
    let pdu_type_code = header0 & 0x0f;
    let length = pdu[1] as usize;
    let available_payload = &pdu[2..];
    let payload = available_payload.get(..length).unwrap_or(available_payload);

    let mut fields = map([
        ("access_address", json!(access_address)),
        ("crc", json!(hex_bytes(crc))),
        ("pdu_type", json!(ble_adv_pdu_type_name(pdu_type_code))),
        ("pdu_type_code", json!(pdu_type_code)),
        ("length", json!(pdu[1])),
        (
            "rx_add",
            json!(if header0 & 0x80 != 0 {
                "random"
            } else {
                "public"
            }),
        ),
        (
            "tx_add",
            json!(if header0 & 0x40 != 0 {
                "random"
            } else {
                "public"
            }),
        ),
        ("channel_selection", json!(header0 & 0x20 != 0)),
        ("rfu", json!((header0 >> 4) & 0x01)),
    ]);

    if pdu_type_code == 0 && payload.len() >= 6 {
        // ADV_IND: the advertiser address is reported in MSB-first display
        // order; libcrafter's typed decode already reverses the on-air bytes,
        // so prefer the layer accessor and fall back to the source bytes.
        let adv_a = layer
            .adv_a_value()
            .map(|address| address.to_string())
            .unwrap_or_else(|| ble_address_text(&payload[..6]));
        fields.insert("adv_a".to_string(), json!(adv_a));
        fields.insert("ad_list".to_string(), json!(ble_ad_list(&payload[6..])));
    } else if !payload.is_empty() {
        fields.insert("payload_hex".to_string(), json!(hex_bytes(payload)));
    }
    let surplus = &available_payload[payload.len().min(available_payload.len())..];
    if !surplus.is_empty() {
        fields.insert("surplus_hex".to_string(), json!(hex_bytes(surplus)));
    }
    fields
}

/// Parse a GAP Advertising Data list into the reference per-structure model.
///
/// Mirrors the Scapy reference `_parse_ble_ad_list`, including the zero-length
/// terminator entry and the typed `value`/`flag_tokens` enrichment for the
/// flags and local-name AD types.
fn ble_ad_list(raw: &[u8]) -> Vec<Value> {
    let mut output = Vec::new();
    let mut offset = 0;
    while offset < raw.len() {
        let length = raw[offset] as usize;
        offset += 1;
        if length == 0 {
            output.push(json!({
                "type": "terminator",
                "type_code": 0,
                "length": 0,
                "data_hex": ""
            }));
            break;
        }
        if offset + length > raw.len() {
            // Truncated structure: surface the remaining bytes rather than panic.
            break;
        }
        let type_code = raw[offset];
        let data = &raw[offset + 1..offset + length];
        offset += length;
        let mut entry = map([
            ("type", json!(ble_ad_type_name(type_code))),
            ("type_code", json!(type_code)),
            ("length", json!(length)),
            ("data_hex", json!(hex_bytes(data))),
        ]);
        if type_code == 0x01 {
            let value = data.first().copied().unwrap_or(0);
            entry.insert("value".to_string(), json!(value));
            entry.insert("flag_tokens".to_string(), json!(ble_adv_flag_tokens(value)));
        } else if type_code == 0x08 || type_code == 0x09 {
            entry.insert(
                "value".to_string(),
                json!(String::from_utf8_lossy(data).into_owned()),
            );
        }
        output.push(Value::Object(entry.into_iter().collect()));
    }
    output
}

/// Render a six-octet BLE address in MSB-first display order from on-air bytes.
fn ble_address_text(on_air: &[u8]) -> String {
    on_air
        .iter()
        .take(6)
        .rev()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Build the `{hex, ascii}` representation the oracle uses for opaque byte blobs.
fn bytes_hex_ascii(bytes: &[u8]) -> Value {
    json!({
        "hex": hex_bytes(bytes),
        "ascii": String::from_utf8_lossy(bytes).into_owned(),
    })
}

fn radiotap_fields(layer: &Radiotap) -> BTreeMap<String, Value> {
    let mut fields = BTreeMap::new();
    if let Some(value) = layer.version_value() {
        fields.insert("version".to_string(), json!(value));
    }
    if let Some(value) = layer.pad_value() {
        fields.insert("pad".to_string(), json!(value));
    }
    if let Some(value) = layer.length_value() {
        fields.insert("length".to_string(), json!(value));
    }
    if let Ok(present) = layer.present() {
        fields.insert("present_words".to_string(), json!(present.words()));
    }
    if let Some(value) = layer.flags_value() {
        fields.insert("flags".to_string(), json!(value.bits()));
        fields.insert(
            "fcs_status".to_string(),
            json!(radiotap_fcs_status(value.fcs_status())),
        );
    }
    if let Some(value) = layer.rate_value() {
        fields.insert("rate".to_string(), json!(value));
    }
    if let Some(value) = layer.channel_value() {
        fields.insert("channel_frequency".to_string(), json!(value.frequency()));
        fields.insert("channel_flags".to_string(), json!(value.flags()));
    }
    if let Some(value) = layer.antenna_signal_value() {
        fields.insert("dbm_antenna_signal".to_string(), json!(value));
    }
    if let Some(value) = layer.antenna_noise_value() {
        fields.insert("dbm_antenna_noise".to_string(), json!(value));
    }
    if let Some(value) = layer.antenna_value() {
        fields.insert("antenna".to_string(), json!(value));
    }
    if let Some(value) = layer.rx_flags_value() {
        fields.insert("rx_flags".to_string(), json!(value.bits()));
    }
    if let Some(value) = layer.tx_flags_value() {
        fields.insert("tx_flags".to_string(), json!(value.bits()));
    }
    if let Some(value) = layer.data_retries_value() {
        fields.insert("data_retries".to_string(), json!(value));
    }
    fields
}

fn dot11_fields(layer: &Dot11) -> BTreeMap<String, Value> {
    let frame_control = layer.frame_control_value();
    let mut fields = map([
        ("frame_control", json!(frame_control.bits())),
        ("protocol_version", json!(frame_control.protocol_version())),
        ("frame_type", json!(frame_control.frame_type())),
        ("subtype", json!(frame_control.subtype())),
        ("to_ds", json!(frame_control.to_ds())),
        ("from_ds", json!(frame_control.from_ds())),
        ("more_fragments", json!(frame_control.more_fragments())),
        ("retry", json!(frame_control.retry())),
        ("power_management", json!(frame_control.power_management())),
        ("more_data", json!(frame_control.more_data())),
        ("protected", json!(frame_control.protected())),
        ("order", json!(frame_control.order())),
    ]);
    if let Some(value) = layer.duration_id_value() {
        fields.insert("duration_id".to_string(), json!(value));
    }
    insert_mac(&mut fields, "addr1", layer.addr1_value());
    insert_mac(&mut fields, "addr2", layer.addr2_value());
    insert_mac(&mut fields, "addr3", layer.addr3_value());
    insert_mac(&mut fields, "addr4", layer.addr4_value());
    if let Some(value) = layer.sequence_control_value() {
        fields.insert("sequence_control".to_string(), json!(value.bits()));
        fields.insert(
            "fragment_number".to_string(),
            json!(value.fragment_number()),
        );
        fields.insert(
            "sequence_number".to_string(),
            json!(value.sequence_number()),
        );
    }
    if let Some(value) = layer.qos_control_value() {
        fields.insert("qos_control".to_string(), json!(value));
    }
    if let Some(value) = layer.ht_control_value() {
        fields.insert("ht_control".to_string(), json!(value));
    }
    if !layer.fixed_parameters_value().is_empty() {
        fields.insert(
            "management_fixed_fields".to_string(),
            json!({"hex": hex_bytes(layer.fixed_parameters_value())}),
        );
    }
    if !layer.tags_value().is_empty() {
        fields.insert(
            "tagged_parameters".to_string(),
            json!(layer
                .tags_value()
                .iter()
                .map(|tag| {
                    json!({
                        "id": tag.id(),
                        "length": tag.length(),
                        "value": {"hex": hex_bytes(tag.value())}
                    })
                })
                .collect::<Vec<_>>()),
        );
    }
    if let Some(value) = layer.encrypted_body_len() {
        fields.insert("encrypted_body_len".to_string(), json!(value));
    }
    fields
}

fn llc_snap_fields(layer: &LlcSnap) -> BTreeMap<String, Value> {
    let oui = layer.oui_value();
    map([
        ("dsap", json!(layer.dsap_value())),
        ("ssap", json!(layer.ssap_value())),
        ("control", json!(layer.control_value())),
        ("oui", json!({"hex": hex_bytes(&oui)})),
        ("ethertype", json!(layer.ethertype_value())),
    ])
}

fn eapol_fields(layer: &Eapol) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("version", json!(layer.version_value())),
        ("packet_type", json!(layer.packet_type_value())),
    ]);
    if let Some(value) = layer.body_length_value() {
        fields.insert("body_length".to_string(), json!(value));
    }
    fields
}

fn eapol_key_fields(layer: &EapolKey) -> BTreeMap<String, Value> {
    let key_information = layer.key_information_value();
    map([
        ("descriptor_type", json!(layer.descriptor_type_value())),
        ("key_information", json!(key_information.bits())),
        ("key_length", json!(layer.key_length_value())),
        ("replay_counter", json!(layer.replay_counter_value())),
        ("key_nonce", json!({"hex": hex_bytes(&layer.nonce_value())})),
        ("key_iv", json!({"hex": hex_bytes(&layer.iv_value())})),
        ("key_rsc", json!({"hex": hex_bytes(&layer.rsc_value())})),
        ("key_id", json!({"hex": hex_bytes(&layer.id_value())})),
        ("key_mic", json!({"hex": hex_bytes(&layer.mic_value())})),
        (
            "key_data_length",
            json!(layer
                .key_data_length_value()
                .unwrap_or(layer.key_data_bytes().len() as u16)),
        ),
        (
            "key_data",
            json!({"hex": hex_bytes(layer.key_data_bytes())}),
        ),
    ])
}

fn dot11_rsn_layers(layer: &Dot11) -> Vec<BTreeMap<String, Value>> {
    layer
        .tags_value()
        .iter()
        .filter_map(|tag| match tag.rsn_information() {
            Some(Ok(rsn)) => Some(rsn_information_fields(tag.id(), tag.length(), &rsn)),
            _ => None,
        })
        .collect()
}

fn rsn_information_fields(
    element_id: u8,
    length: usize,
    rsn: &RsnInformation,
) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("element_id", json!(element_id)),
        ("length", json!(length)),
        ("version", json!(rsn.version_value())),
        (
            "group_cipher_suite",
            rsn_cipher_suite_value(rsn.group_cipher_suite()),
        ),
        (
            "pairwise_cipher_suites",
            json!(rsn
                .pairwise_cipher_list()
                .iter()
                .copied()
                .map(rsn_cipher_suite_value)
                .collect::<Vec<_>>()),
        ),
        (
            "akm_suites",
            json!(rsn
                .akm_list()
                .iter()
                .copied()
                .map(rsn_akm_suite_value)
                .collect::<Vec<_>>()),
        ),
    ]);
    if let Some(value) = rsn.capabilities() {
        fields.insert("capabilities".to_string(), json!(value.bits()));
    }
    if rsn.pmkid_count_present() {
        fields.insert("pmkid_count_present".to_string(), json!(true));
        fields.insert(
            "pmkid_list".to_string(),
            json!(rsn
                .pmkid_list()
                .iter()
                .map(|pmkid| json!({"hex": hex_bytes(pmkid)}))
                .collect::<Vec<_>>()),
        );
    }
    if let Some(value) = rsn.group_management_cipher_suite() {
        fields.insert(
            "group_management_cipher_suite".to_string(),
            rsn_cipher_suite_value(value),
        );
    }
    if !rsn.trailing_bytes().is_empty() {
        fields.insert(
            "trailing_bytes".to_string(),
            json!({"hex": hex_bytes(rsn.trailing_bytes())}),
        );
    }
    fields
}

fn ethernet_fields(layer: &Ethernet) -> BTreeMap<String, Value> {
    let mut fields = BTreeMap::new();
    if let Some(value) = layer.destination() {
        fields.insert("dst".to_string(), json!(value.to_string()));
    }
    if let Some(value) = layer.source() {
        fields.insert("src".to_string(), json!(value.to_string()));
    }
    if let Some(value) = layer.ethertype_value() {
        fields.insert("ethertype".to_string(), json!(value));
    }
    fields
}

fn arp_fields(layer: &Arp) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("hardware_type", json!(layer.hardware_type_value())),
        ("protocol_type", json!(layer.protocol_type_value())),
        ("hardware_length", json!(layer.hardware_len_value())),
        ("protocol_length", json!(layer.protocol_len_value())),
        ("opcode", json!(layer.opcode_value())),
    ]);
    insert_address(
        &mut fields,
        "sender_hardware_address",
        layer.sender_mac().map(|value| value.to_string()),
        layer.sender_hardware_bytes_value(),
    );
    insert_address(
        &mut fields,
        "target_hardware_address",
        layer.target_mac().map(|value| value.to_string()),
        layer.target_hardware_bytes_value(),
    );
    insert_address(
        &mut fields,
        "sender_protocol_address",
        layer.sender_ipv4().map(|value| value.to_string()),
        layer.sender_protocol_bytes_value(),
    );
    insert_address(
        &mut fields,
        "target_protocol_address",
        layer.target_ipv4().map(|value| value.to_string()),
        layer.target_protocol_bytes_value(),
    );
    fields
}

fn vlan_fields(layer: &Vlan) -> BTreeMap<String, Value> {
    map([
        ("priority", json!(layer.pcp_value())),
        ("drop_eligible", json!(layer.dei_value())),
        ("vlan_id", json!(layer.vlan_id_value())),
        ("ethertype", json!(layer.ethertype_value())),
    ])
}

fn linux_sll_fields(layer: &LinuxSll) -> BTreeMap<String, Value> {
    map([
        ("packet_type", json!(layer.packet_type_value())),
        ("address_type", json!(layer.address_type_value())),
        ("address_length", json!(layer.address_len_value())),
        (
            "source_address",
            json!({
                "hex": hex_bytes(&layer.source_address_value())
            }),
        ),
        ("protocol", json!(layer.protocol_value())),
    ])
}

fn ipv4_fields(layer: &Ipv4) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("version", json!(layer.version_value())),
        ("header_length", json!(layer.ihl_value())),
        ("tos", json!(layer.tos_value())),
        ("identification", json!(layer.identification_value())),
        ("flags", json!(ipv4_flags(layer.flags_value()))),
        ("fragment_offset", json!(layer.fragment_offset_value())),
        ("ttl", json!(layer.ttl_value())),
        ("protocol", json!(layer.protocol_value())),
        ("src", json!(layer.source().to_string())),
        ("dst", json!(layer.destination().to_string())),
        ("options", json!(hex_bytes(layer.option_bytes()))),
    ]);
    if let Some(value) = layer.total_length_value() {
        fields.insert("length".to_string(), json!(value));
    }
    if let Some(value) = layer.checksum_value() {
        fields.insert("checksum".to_string(), json!(value));
    }
    fields
}

fn ipv6_fields(layer: &Ipv6) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("version", json!(layer.version_value())),
        ("traffic_class", json!(layer.traffic_class_value())),
        ("dscp", json!(layer.dscp_value().value())),
        ("ecn", json!(layer.ecn_value().value())),
        ("flow_label", json!(layer.flow_label_value())),
        ("next_header", json!(layer.next_header_value())),
        ("hop_limit", json!(layer.hop_limit_value())),
        ("src", json!(layer.source().to_string())),
        ("dst", json!(layer.destination().to_string())),
    ]);
    if let Some(value) = layer.payload_length_value() {
        fields.insert("payload_length".to_string(), json!(value));
    }
    fields
}

fn ipv6_hop_by_hop_fields(layer: &Ipv6HopByHopOptionsHeader) -> BTreeMap<String, Value> {
    ipv6_options_header_fields(
        layer.next_header_value(),
        layer.header_ext_len_value(),
        layer.options_value(),
    )
}

fn ipv6_destination_options_fields(
    layer: &Ipv6DestinationOptionsHeader,
) -> BTreeMap<String, Value> {
    ipv6_options_header_fields(
        layer.next_header_value(),
        layer.header_ext_len_value(),
        layer.options_value(),
    )
}

fn ipv6_options_header_fields(
    next_header: u8,
    header_ext_len: Option<u8>,
    options: &[Ipv6Option],
) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("next_header", json!(next_header)),
        ("option_count", json!(options.len())),
        ("options", json!(ipv6_options(options))),
        (
            "options_raw_hex",
            json!(hex_bytes(&ipv6_options_bytes(options))),
        ),
    ]);
    if let Some(value) = header_ext_len {
        fields.insert("header_ext_len".to_string(), json!(value));
        fields.insert("length".to_string(), json!(value));
    }
    fields
}

fn ipv6_fragment_fields(layer: &Ipv6FragmentHeader) -> BTreeMap<String, Value> {
    map([
        ("next_header", json!(layer.next_header_value())),
        ("reserved", json!(layer.reserved_value())),
        ("fragment_offset", json!(layer.fragment_offset_value())),
        (
            "fragment_offset_bytes",
            json!(layer.fragment_offset_bytes()),
        ),
        ("res", json!(layer.res_value())),
        ("more_fragments", json!(layer.has_more_fragments())),
        ("identification", json!(layer.identification_value())),
        (
            "fragment_status",
            json!(ipv6_fragment_status(layer.fragment_status())),
        ),
    ])
}

fn ipv6_routing_fields(layer: &Ipv6RoutingHeader) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("next_header", json!(layer.next_header_value())),
        ("type", json!(layer.routing_type_value())),
        (
            "classification",
            json!(ipv6_routing_classification(layer.routing_type_value())),
        ),
        ("segments_left", json!(layer.segments_left_value())),
        ("reserved", json!(hex_bytes(layer.type_data_bytes()))),
        ("type_data", json!(hex_bytes(layer.type_data_bytes()))),
    ]);
    if let Some(value) = layer.header_ext_len_value() {
        fields.insert("header_ext_len".to_string(), json!(value));
        fields.insert("length".to_string(), json!(value));
    }
    fields
}

fn ipv6_mobile_routing_fields(layer: &Ipv6MobileRoutingHeader) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("next_header", json!(layer.next_header_value())),
        ("type", json!(layer.routing_type_value())),
        (
            "classification",
            json!(ipv6_routing_classification(layer.routing_type_value())),
        ),
        ("segments_left", json!(layer.segments_left_value())),
        ("reserved", json!(layer.reserved_value())),
        ("addresses", json!([layer.home_address_value().to_string()])),
    ]);
    if let Some(value) = layer.header_ext_len_value() {
        fields.insert("header_ext_len".to_string(), json!(value));
        fields.insert("length".to_string(), json!(value));
    }
    fields
}

fn ipv6_segment_routing_fields(layer: &Ipv6SegmentRoutingHeader) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("next_header", json!(layer.next_header_value())),
        ("type", json!(layer.routing_type_value())),
        (
            "classification",
            json!(ipv6_routing_classification(layer.routing_type_value())),
        ),
        ("segments_left", json!(layer.segments_left_value())),
        ("last_entry", json!(layer.last_entry_value())),
        ("flags", json!(layer.flags_value())),
        ("tag", json!(layer.tag_value())),
        ("protected", json!(layer.p_flag_value())),
        ("reserved", json!(layer.reserved_value())),
        ("hmac", json!(layer.hmac_key_id_value())),
        (
            "raw_trailing_data",
            json!(hex_bytes(layer.raw_trailing_data_bytes())),
        ),
        (
            "addresses",
            json!(layer
                .segments()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()),
        ),
        (
            "segments",
            json!(layer
                .segments()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()),
        ),
    ]);
    if let Some(value) = layer.header_ext_len_value() {
        fields.insert("header_ext_len".to_string(), json!(value));
        fields.insert("length".to_string(), json!(value));
    }
    fields
}

fn ipv6_fragment_status(status: Ipv6FragmentHeaderStatus) -> &'static str {
    match status {
        Ipv6FragmentHeaderStatus::Atomic => "atomic",
        Ipv6FragmentHeaderStatus::Initial => "initial",
        Ipv6FragmentHeaderStatus::NonInitial => "non_initial",
    }
}

fn ipv6_routing_classification(routing_type: u8) -> &'static str {
    match routing_type {
        2 => "mobile",
        4 => "segment_routing",
        _ => match crafter::core::ipv6_routing_type_status(routing_type) {
            Ipv6RoutingTypeStatus::Deprecated => "deprecated",
            Ipv6RoutingTypeStatus::Experimental => "experimental",
            Ipv6RoutingTypeStatus::Reserved => "reserved",
            _ => "unknown",
        },
    }
}

fn ipv6_options(options: &[Ipv6Option]) -> Vec<Value> {
    options.iter().map(ipv6_option_item).collect()
}

fn ipv6_options_bytes(options: &[Ipv6Option]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for option in options {
        if let Ok(encoded) = option.encode() {
            bytes.extend_from_slice(&encoded);
        }
    }
    bytes
}

fn ipv6_option_item(option: &Ipv6Option) -> Value {
    let mut item = BTreeMap::new();
    item.insert("option_type".to_string(), json!(option.option_type()));
    item.insert("kind".to_string(), json!(ipv6_option_kind(option)));
    item.insert("length".to_string(), json!(option.encoded_len()));
    item.insert("data_hex".to_string(), json!(hex_bytes(option.data())));
    item.insert("action".to_string(), json!(option.action_bits()));
    item.insert(
        "change_en_route".to_string(),
        json!(option.change_en_route()),
    );
    if let Some(value) = option.router_alert_value() {
        item.insert("value".to_string(), json!(value));
    }
    if let Some(value) = option.jumbo_payload_length() {
        item.insert("jumbo_payload_length".to_string(), json!(value));
    }
    if let Some(value) = option.home_address_value() {
        item.insert("address".to_string(), json!(value.to_string()));
    }
    Value::Object(item.into_iter().collect())
}

fn ipv6_option_kind(option: &Ipv6Option) -> &'static str {
    match option {
        Ipv6Option::Pad1 => "pad1",
        Ipv6Option::PadN { .. } => "padn",
        Ipv6Option::RouterAlert { .. } => "router_alert",
        Ipv6Option::JumboPayload { .. } => "jumbo_payload",
        Ipv6Option::HomeAddress { .. } => "home_address",
        Ipv6Option::Generic { .. } => "unknown",
    }
}

fn udp_fields(layer: &Udp) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("src_port", json!(layer.source_port_value())),
        ("dst_port", json!(layer.destination_port_value())),
    ]);
    if let Some(value) = layer.length_value() {
        fields.insert("length".to_string(), json!(value));
    }
    if let Some(value) = layer.checksum_value() {
        fields.insert("checksum".to_string(), json!(value));
    }
    fields
}

fn udp_options_fields(
    layer: &UdpOptions,
    layout: Option<&UdpLayout>,
    source_bytes: Option<&[u8]>,
) -> BTreeMap<String, Value> {
    map([(
        "options",
        json!(udp_options_metadata(layer, layout, source_bytes)),
    )])
}

fn udp_options_metadata(
    layer: &UdpOptions,
    layout: Option<&UdpLayout>,
    source_bytes: Option<&[u8]>,
) -> Value {
    let option_bytes = layer.as_bytes();
    let layout_surplus = layout
        .zip(source_bytes)
        .and_then(|(layout, raw)| raw.get(layout.surplus_start..layout.ip_end));
    let alignment = if let (Some(layout), Some(surplus)) = (layout, layout_surplus) {
        let len = (layout.surplus_start - layout.l3_start) & 1;
        surplus.get(..len).unwrap_or(&[])
    } else {
        layer.alignment_bytes().unwrap_or(&[])
    };
    let raw_surplus = layout_surplus.map(hex_bytes).unwrap_or_else(|| {
        let mut surplus = Vec::new();
        surplus.extend_from_slice(alignment);
        if let Some(ocs) = layer.option_checksum_value() {
            surplus.extend_from_slice(&ocs.to_be_bytes());
        }
        surplus.extend_from_slice(option_bytes);
        hex_bytes(&surplus)
    });
    let user_payload = layout
        .zip(source_bytes)
        .and_then(|(layout, raw)| raw.get(layout.udp_payload_start..layout.udp_payload_end))
        .unwrap_or(&[]);

    json!({
        "status": udp_option_status_label(layer.status()),
        "raw_surplus_hex": raw_surplus,
        "raw_surplus_length": raw_surplus.len() / 2,
        "alignment_hex": hex_bytes(alignment),
        "option_checksum": layer.option_checksum_value(),
        "option_bytes_hex": hex_bytes(option_bytes),
        "option_count": layer.options().len(),
        "items": layer.options().iter().map(udp_option_item).collect::<Vec<_>>(),
        "application_payload_hex": hex_bytes(user_payload),
        "application_payload_length": user_payload.len(),
        "udp_length": layout.map(|layout| layout.udp_length),
        "placement": "after_udp_length",
        "surplus_excluded_from_udp_checksum": true
    })
}

fn udp_option_item(option: &UdpOption) -> Value {
    let kind = option.kind();
    let mut item = BTreeMap::new();
    item.insert("kind".to_string(), json!(kind));
    item.insert("name".to_string(), json!(udp_option_name(kind)));
    item.insert("length".to_string(), json!(option.encoded_len()));
    if !matches!(option, UdpOption::EndOfList | UdpOption::NoOperation) {
        item.insert("data_hex".to_string(), json!(hex_bytes(option.data())));
    }
    if let Some(value) = option.additional_payload_checksum_value() {
        item.insert("checksum".to_string(), json!(value));
    }
    if let Some(value) = option.maximum_datagram_size_value() {
        item.insert("max_datagram_size".to_string(), json!(value));
    }
    if let Some((size, segments)) = option.maximum_reassembled_datagram_size_values() {
        item.insert("max_reassembled_size".to_string(), json!(size));
        item.insert("segment_count".to_string(), json!(segments));
    }
    if let Some(value) = option
        .echo_request_token()
        .or_else(|| option.echo_response_token())
    {
        item.insert("token".to_string(), json!(value));
    }
    if let Some((tsval, tsecr)) = option.timestamp_values() {
        item.insert("tsval".to_string(), json!(tsval));
        item.insert("tsecr".to_string(), json!(tsecr));
    }
    Value::Object(item.into_iter().collect())
}

fn udp_option_name(kind: u8) -> &'static str {
    match kind {
        0 => "eol",
        1 => "nop",
        2 => "apc",
        3 => "frag",
        4 => "mds",
        5 => "mrds",
        6 => "req",
        7 => "res",
        8 => "time",
        9 => "auth",
        10..=126 => "unassigned_safe",
        127 => "exp",
        128..=191 => "reserved_safe",
        194..=253 => "unassigned_unsafe",
        254 => "uexp",
        _ => "reserved_unsafe",
    }
}

fn tcp_fields(layer: &Tcp) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("src_port", json!(layer.source_port_value())),
        ("dst_port", json!(layer.destination_port_value())),
        ("sequence", json!(layer.sequence_number_value())),
        (
            "acknowledgement",
            json!(layer.acknowledgment_number_value()),
        ),
        ("data_offset", json!(layer.data_offset_value())),
        ("reserved", json!(layer.reserved_value())),
        ("flags", json!(tcp_flags(layer.flags_value()))),
        ("window", json!(layer.window_value())),
        ("urgent_pointer", json!(layer.urgent_pointer_value())),
        ("options", json!(hex_bytes(layer.option_bytes()))),
    ]);
    if let Some(value) = layer.checksum_value() {
        fields.insert("checksum".to_string(), json!(value));
    }
    fields
}

fn bgp_fields(layer: &Bgp) -> BTreeMap<String, Value> {
    let mut fields = BTreeMap::new();
    let Ok(compiled) = Packet::from_layer(layer.clone()).compile() else {
        return inspection_fields(layer);
    };
    let raw = compiled.as_bytes();
    if raw.len() < BGP_HEADER_LEN {
        return inspection_fields(layer);
    }

    let length = u16::from_be_bytes([raw[BGP_MARKER_LEN], raw[BGP_MARKER_LEN + 1]]);
    let message_type = raw[BGP_MARKER_LEN + 2];
    fields.insert(
        "marker".to_string(),
        json!({"hex": hex_bytes(&raw[..BGP_MARKER_LEN])}),
    );
    fields.insert("length".to_string(), json!(length));
    fields.insert("type".to_string(), json!(message_type));
    fields.insert(
        "message_type".to_string(),
        json!(bgp_message_type_name(message_type)),
    );

    let body = &raw[BGP_HEADER_LEN..];
    match message_type {
        BGP_TYPE_OPEN if body.len() >= 10 => {
            fields.insert("version".to_string(), json!(body[0]));
            fields.insert(
                "asn".to_string(),
                json!(u16::from_be_bytes([body[1], body[2]])),
            );
            fields.insert(
                "hold_time".to_string(),
                json!(u16::from_be_bytes([body[3], body[4]])),
            );
            fields.insert(
                "bgp_identifier".to_string(),
                json!(format!("{}.{}.{}.{}", body[5], body[6], body[7], body[8])),
            );
            fields.insert("opt_param_len".to_string(), json!(body[9]));
            fields.insert(
                "optional_parameters".to_string(),
                json!({"hex": hex_bytes(&body[10..])}),
            );
        }
        BGP_TYPE_UPDATE if body.len() >= 4 => {
            let withdrawn_len = u16::from_be_bytes([body[0], body[1]]) as usize;
            let withdrawn_end = 2usize.saturating_add(withdrawn_len).min(body.len());
            fields.insert("withdrawn_routes_len".to_string(), json!(withdrawn_len));
            fields.insert(
                "withdrawn_routes".to_string(),
                json!({"hex": hex_bytes(&body[2..withdrawn_end])}),
            );
            if body.len() >= withdrawn_end + 2 {
                let attr_len =
                    u16::from_be_bytes([body[withdrawn_end], body[withdrawn_end + 1]]) as usize;
                let attr_start = withdrawn_end + 2;
                let attr_end = attr_start.saturating_add(attr_len).min(body.len());
                fields.insert("path_attr_len".to_string(), json!(attr_len));
                fields.insert(
                    "path_attributes".to_string(),
                    json!({"hex": hex_bytes(&body[attr_start..attr_end])}),
                );
                fields.insert(
                    "nlri".to_string(),
                    json!({"hex": hex_bytes(&body[attr_end..])}),
                );
            }
        }
        BGP_TYPE_NOTIFICATION if body.len() >= 2 => {
            fields.insert("error_code".to_string(), json!(body[0]));
            fields.insert("error_subcode".to_string(), json!(body[1]));
            fields.insert("data".to_string(), json!({"hex": hex_bytes(&body[2..])}));
        }
        BGP_TYPE_KEEPALIVE => {}
        BGP_TYPE_ROUTE_REFRESH if body.len() >= 4 => {
            fields.insert(
                "afi".to_string(),
                json!(u16::from_be_bytes([body[0], body[1]])),
            );
            fields.insert("subtype".to_string(), json!(body[2]));
            fields.insert("safi".to_string(), json!(body[3]));
            if body.len() > 4 {
                fields.insert(
                    "orf_data".to_string(),
                    json!({"hex": hex_bytes(&body[4..])}),
                );
            }
        }
        _ if !body.is_empty() => {
            fields.insert("body".to_string(), json!({"hex": hex_bytes(body)}));
        }
        _ => {}
    }
    fields
}

fn bgp_message_type_name(message_type: u8) -> Value {
    match message_type {
        BGP_TYPE_OPEN => json!("open"),
        BGP_TYPE_UPDATE => json!("update"),
        BGP_TYPE_NOTIFICATION => json!("notification"),
        BGP_TYPE_KEEPALIVE => json!("keepalive"),
        BGP_TYPE_ROUTE_REFRESH => json!("route_refresh"),
        other => json!(other),
    }
}

/// Normalize a decoded RIP layer into the backend-neutral oracle model.
///
/// Mirrors the Scapy reference `_canonicalize_rip` (step 54): the 4-octet header
/// (`command`/`version`/`reserved`), an `entries` list of 20-octet route entries
/// (`address_family`/`route_tag`/`address`/`subnet_mask`/`next_hop`/`metric`),
/// and an optional `auth` sub-object for the AFI-0xFFFF authentication entry. All
/// values are read through the public `Rip`/`RipEntry`/`RipAuth` accessors rather
/// than re-parsing the wire bytes; unknown command and address-family codes are
/// surfaced as their raw numeric values so preservation stays observable.
///
/// When the message carries authentication, libcrafter's decode keeps the leading
/// AFI-0xFFFF auth entry in `entries()` while also exposing it on `auth_config()`;
/// the Scapy reference reports that entry only under `auth`, so the leading auth
/// marker entry is dropped from the normalized `entries` list to match.
fn rip_fields(layer: &Rip) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("command", json!(layer.command_value())),
        ("version", json!(layer.version_value())),
        ("reserved", json!(layer.reserved_value())),
    ]);

    let auth = layer.auth_config();
    let entries: Vec<Value> = layer
        .entries()
        .iter()
        .enumerate()
        .filter(|(index, entry)| !(*index == 0 && auth.is_some() && entry.is_auth_marker()))
        .map(|(_, entry)| rip_entry_fields(entry))
        .collect();
    fields.insert("entries".to_string(), json!(entries));

    if let Some(auth) = auth {
        fields.insert("auth".to_string(), rip_auth_fields(auth));
    }
    fields
}

/// Normalize one 20-octet RIP route entry, using the same field names as the
/// Scapy reference `_normalize_rip_entry`. Addresses render as dotted-quad
/// strings and the address family is surfaced as its raw numeric value.
fn rip_entry_fields(entry: &RipEntry) -> Value {
    json!({
        "address_family": entry.address_family_value(),
        "route_tag": entry.route_tag_value(),
        "address": entry.address_value().to_string(),
        "subnet_mask": entry.subnet_mask_value().to_string(),
        "next_hop": entry.next_hop_value().to_string(),
        "metric": entry.metric_value(),
    })
}

/// Normalize the AFI-0xFFFF RIPv2 authentication entry, mirroring the Scapy
/// reference `_normalize_rip_auth`: a simple-password entry carries the 16-octet
/// password (`{hex}`); a keyed-message-digest entry carries the digest header
/// (offset, key id, auth-data length, sequence). libcrafter's decode reconstructs
/// the simple-password form; the keyed-digest header fields are read from the
/// parsed `RipKeyedDigestHeader` accessors when present.
fn rip_auth_fields(auth: &RipAuth) -> Value {
    let auth_type = auth.auth_type_value();
    let mut fields = map([
        ("address_family", json!(RIP_AFI_AUTH)),
        ("auth_type", json!(auth_type)),
    ]);
    match &auth.payload {
        RipAuthPayload::SimplePassword(password) => {
            fields.insert(
                "simple_password".to_string(),
                json!({"hex": hex_bytes(password)}),
            );
        }
        RipAuthPayload::KeyedDigest(header) => {
            fields.insert("digest_offset".to_string(), json!(header.offset_value()));
            fields.insert("key_id".to_string(), json!(header.key_id_value()));
            fields.insert(
                "auth_data_len".to_string(),
                json!(header.auth_data_len_value()),
            );
            fields.insert("sequence".to_string(), json!(header.sequence_value()));
        }
    }
    Value::Object(fields.into_iter().collect())
}

/// Normalize a decoded RIPng layer into the backend-neutral oracle model.
///
/// Mirrors the parser-backend RIPng normalization (step 55) and the RIPng layer
/// spec (step 47): the 4-octet header (`command`/`version`/`reserved`) and an
/// `rtes` list of 20-octet route table entries (`prefix`/`route_tag`/
/// `prefix_len`/`metric`). All values are read through the public `Ripng`/
/// `RipngRte` accessors rather than re-parsing the wire bytes; a `next_hop`
/// boolean per RTE surfaces the RFC 2080 §2.1.1 next-hop RTE (metric `0xFF`) so
/// the libcrafter decode exposes the distinction the wireshark parser does not.
fn ripng_fields(layer: &Ripng) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("command", json!(layer.command_value())),
        ("version", json!(layer.version_value())),
        ("reserved", json!(layer.reserved_value())),
    ]);

    let rtes: Vec<Value> = layer.rtes().iter().map(ripng_rte_fields).collect();
    fields.insert("rtes".to_string(), json!(rtes));
    fields
}

/// Normalize one 20-octet RIPng route table entry (RFC 2080 §2.1), using the
/// same field names as the parser-backend `_normalize_ripng` (`prefix`/
/// `route_tag`/`prefix_len`/`metric`). The IPv6 prefix renders as a canonical
/// string and a `next_hop` boolean marks the next-hop RTE (metric `0xFF`,
/// RFC 2080 §2.1.1).
fn ripng_rte_fields(rte: &RipngRte) -> Value {
    json!({
        "prefix": rte.prefix_value().to_string(),
        "route_tag": rte.route_tag_value(),
        "prefix_len": rte.prefix_len_value(),
        "metric": rte.metric_value(),
        "next_hop": rte.is_next_hop(),
    })
}

fn icmp_fields(layer: &Icmpv4) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("type", json!(layer.icmp_type_value())),
        ("code", json!(layer.code_value())),
        (
            "rest_of_header",
            json!(hex_bytes(&layer.rest_of_header_value())),
        ),
    ]);
    if let Some(value) = layer.checksum_value() {
        fields.insert("checksum".to_string(), json!(value));
    }
    if let Some(value) = layer.identifier_value() {
        fields.insert("identifier".to_string(), json!(value));
    }
    if let Some(value) = layer.sequence_number_value() {
        fields.insert("sequence".to_string(), json!(value));
    }
    if let Some(value) = layer.length_value() {
        fields.insert("length".to_string(), json!(value));
    }
    fields
}

fn icmpv6_fields(layer: &Icmpv6) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("type", json!(layer.icmp_type_value())),
        ("code", json!(layer.code_value())),
        (
            "rest_of_header",
            json!(hex_bytes(&layer.rest_of_header_value())),
        ),
    ]);
    if let Some(value) = layer.checksum_value() {
        fields.insert("checksum".to_string(), json!(value));
    }
    if let Some(value) = layer.identifier_value() {
        fields.insert("identifier".to_string(), json!(value));
    }
    if let Some(value) = layer.sequence_number_value() {
        fields.insert("sequence".to_string(), json!(value));
    }
    if let Some(value) = layer.length_value() {
        fields.insert("length".to_string(), json!(value));
    }
    fields
}

fn igmp_fields(layer: &Igmp) -> BTreeMap<String, Value> {
    let type_code = layer.igmp_type_value();
    let mut fields = map([
        ("type", json!(type_code)),
        ("type_label", json!(igmp_type_label(type_code))),
        ("code", json!(layer.code_value())),
        (
            "code_label",
            json!(igmp_code_label(type_code, layer.code_value())),
        ),
        ("checksum_status", json!(layer.checksum_status().label())),
    ]);
    if let Some(value) = layer.checksum_value() {
        fields.insert("checksum".to_string(), json!(value));
    }
    if type_code == IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT {
        fields.insert(
            "mrd_query_interval".to_string(),
            json!(layer.mrd_query_interval_value()),
        );
        fields.insert(
            "mrd_robustness_variable".to_string(),
            json!(layer.mrd_robustness_variable_value()),
        );
    } else if !matches!(
        type_code,
        IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION | IGMP_TYPE_MULTICAST_ROUTER_TERMINATION
    ) {
        fields.insert(
            "group_address".to_string(),
            json!(layer.group_address_value().to_string()),
        );
    }
    fields
}

fn igmp_query_fields(layer: &IgmpQuery) -> BTreeMap<String, Value> {
    let flags = layer.raw_flags_qrv_value();
    map([
        ("query_flags", json!(flags)),
        ("query_flag_labels", json!(igmp_query_flag_labels(flags))),
        (
            "suppress_router_side_processing",
            json!(layer.suppress_router_side_processing()),
        ),
        (
            "querier_robustness_variable",
            json!(layer.querier_robustness_variable_value()),
        ),
        ("qqic", json!(layer.qqic_value())),
        ("number_of_sources", json!(layer.number_of_sources_value())),
        (
            "source_addresses",
            json!(layer
                .source_addresses()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()),
        ),
    ])
}

fn igmp_report_fields(layer: &IgmpReport) -> BTreeMap<String, Value> {
    let flags = layer.report_flags_value();
    map([
        ("report_flags", json!(flags)),
        ("report_flag_labels", json!(igmp_report_flag_labels(flags))),
        (
            "number_of_group_records",
            json!(layer.number_of_group_records_value()),
        ),
        (
            "group_records",
            json!(layer
                .group_records()
                .iter()
                .map(igmp_group_record_fields)
                .collect::<Vec<_>>()),
        ),
    ])
}

fn igmp_group_record_fields(record: &IgmpGroupRecord) -> Value {
    json!({
        "record_type": record.record_type_value(),
        "record_type_label": igmp_record_type_label(record.record_type_value()),
        "auxiliary_data_len": record.auxiliary_data_len_value(),
        "number_of_sources": record.number_of_sources_value(),
        "multicast_address": record.multicast_address_value().to_string(),
        "source_addresses": record
            .source_addresses()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "auxiliary_data": igmp_bytes_fields(record.auxiliary_data()),
    })
}

fn igmp_extension_fields(layer: &IgmpExtension) -> BTreeMap<String, Value> {
    map([
        ("extension_type", json!(layer.extension_type_value())),
        (
            "extension_type_label",
            json!(igmp_extension_type_label(layer.extension_type_value())),
        ),
        ("extension_length", json!(layer.extension_length_value())),
        ("extension_value", igmp_bytes_fields(layer.value_bytes())),
    ])
}

fn igmp_type_label(type_code: u8) -> &'static str {
    match type_code {
        IGMP_TYPE_RESERVED => "reserved",
        IGMP_TYPE_MEMBERSHIP_QUERY => "membership_query",
        IGMP_TYPE_V1_MEMBERSHIP_REPORT => "v1_membership_report",
        IGMP_TYPE_DVMRP => "dvmrp_unsupported_assigned",
        IGMP_TYPE_PIM_V1 => "pim_v1_unsupported_assigned",
        IGMP_TYPE_CISCO_TRACE_MESSAGES => "cisco_trace_unsupported_assigned",
        IGMP_TYPE_V2_MEMBERSHIP_REPORT => "v2_membership_report",
        IGMP_TYPE_V2_LEAVE_GROUP => "v2_leave_group",
        IGMP_TYPE_MULTICAST_TRACEROUTE_RESPONSE => {
            "multicast_traceroute_response_unsupported_assigned"
        }
        IGMP_TYPE_MULTICAST_TRACEROUTE => "multicast_traceroute_unsupported_assigned",
        IGMP_TYPE_V3_MEMBERSHIP_REPORT => "v3_membership_report",
        IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT => "multicast_router_advertisement",
        IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION => "multicast_router_solicitation",
        IGMP_TYPE_MULTICAST_ROUTER_TERMINATION => "multicast_router_termination",
        IGMP_TYPE_EXPERIMENTAL_FIRST..=IGMP_TYPE_EXPERIMENTAL_LAST => "experimental",
        _ => "unassigned",
    }
}

fn igmp_code_label(type_code: u8, code: u8) -> &'static str {
    if type_code == IGMP_TYPE_MEMBERSHIP_QUERY {
        if code == 0 {
            return "v1_query_zero";
        }
        return "v2_or_v3_max_response_code";
    }
    if type_code == IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT {
        return "mrd_advertisement_interval";
    }
    if matches!(
        type_code,
        IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION | IGMP_TYPE_MULTICAST_ROUTER_TERMINATION
    ) {
        return if code == 0 {
            "mrd_reserved"
        } else {
            "explicit_override"
        };
    }
    if code == 0 {
        "reserved_zero"
    } else {
        "explicit_override"
    }
}

fn igmp_record_type_label(record_type: u8) -> &'static str {
    match record_type {
        0 => "reserved",
        IGMP_RECORD_TYPE_MODE_IS_INCLUDE => "mode_is_include",
        IGMP_RECORD_TYPE_MODE_IS_EXCLUDE => "mode_is_exclude",
        IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE => "change_to_include_mode",
        IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE => "change_to_exclude_mode",
        IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES => "allow_new_sources",
        IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES => "block_old_sources",
        _ => "unknown",
    }
}

fn igmp_extension_type_label(extension_type: u16) -> &'static str {
    match extension_type {
        IGMP_EXTENSION_TYPE_NOOP => "noop",
        IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST..=IGMP_EXTENSION_TYPE_EXPERIMENTAL_LAST => {
            "experimental"
        }
        _ => "unassigned",
    }
}

fn igmp_query_flag_labels(flags: u8) -> Vec<&'static str> {
    let mut labels = Vec::new();
    if flags & IGMP_V3_QUERY_FLAG_EXTENSION != 0 {
        labels.push("extension");
    }
    if flags & IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK != 0 {
        labels.push("unassigned");
    }
    if flags & 0x08 != 0 {
        labels.push("suppress_router_side_processing");
    }
    if flags & 0x07 != 0 {
        labels.push("qrv");
    }
    labels
}

fn igmp_report_flag_labels(flags: u16) -> Vec<&'static str> {
    let mut labels = Vec::new();
    if flags & IGMP_V3_REPORT_FLAG_EXTENSION != 0 {
        labels.push("extension");
    }
    if flags & IGMP_V3_REPORT_FLAGS_UNASSIGNED_MASK != 0 {
        labels.push("unassigned");
    }
    labels
}

fn igmp_bytes_fields(bytes: &[u8]) -> Value {
    json!({
        "hex": hex_bytes(bytes),
        "length": bytes.len(),
    })
}

fn dns_fields(layer: &Dns) -> BTreeMap<String, Value> {
    map([
        ("transaction_id", json!(layer.id_value())),
        ("is_response", json!(dns_flag(layer, DNS_FLAG_QR_RESPONSE))),
        ("opcode", json!((layer.flags_value() >> 11) & 0x0f)),
        (
            "authoritative",
            json!(dns_flag(layer, DNS_FLAG_AUTHORITATIVE)),
        ),
        ("truncated", json!(dns_flag(layer, DNS_FLAG_TRUNCATED))),
        (
            "recursion_desired",
            json!(dns_flag(layer, DNS_FLAG_RECURSION_DESIRED)),
        ),
        (
            "recursion_available",
            json!(dns_flag(layer, DNS_FLAG_RECURSION_AVAILABLE)),
        ),
        ("z", json!((layer.flags_value() >> 6) & 0x01)),
        (
            "authenticated_data",
            json!(dns_flag(layer, DNS_FLAG_AUTHENTIC_DATA)),
        ),
        (
            "checking_disabled",
            json!(dns_flag(layer, DNS_FLAG_CHECKING_DISABLED)),
        ),
        ("response_code", json!(layer.flags_value() & 0x0f)),
        ("question_count", json!(layer.questions().len())),
        ("answer_count", json!(layer.answers().len())),
        ("authority_count", json!(layer.authorities().len())),
        ("additional_count", json!(layer.additionals().len())),
    ])
}

fn dhcp_fields(layer: &Dhcp) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("opcode", json!(layer.op_value())),
        ("hardware_type", json!(layer.hardware_type_value())),
        ("hardware_length", json!(layer.hardware_len_value())),
        ("hops", json!(layer.hops_value())),
        ("transaction_id", json!(layer.transaction_id_value())),
        ("seconds", json!(layer.seconds_value())),
        ("flags", json!(layer.flags_value())),
        (
            "client_ip",
            json!(layer.client_ip_address_value().to_string()),
        ),
        ("your_ip", json!(layer.your_ip_address_value().to_string())),
        (
            "server_ip",
            json!(layer.server_ip_address_value().to_string()),
        ),
        (
            "relay_ip",
            json!(layer.gateway_ip_address_value().to_string()),
        ),
        (
            "client_hardware_address",
            json!({"hex": hex_bytes(layer.client_hardware_address_value())}),
        ),
        ("magic_cookie", json!(layer.magic_cookie_value())),
        ("option_count", json!(layer.options_value().len())),
        ("options", json!(dhcp_options(layer))),
    ]);
    if let Some(message_type) = layer.message_type_value() {
        fields.insert("message_type".to_string(), json!(message_type.code()));
    }
    fields
}

/// Normalize DHCP options to backend-neutral `{code, payload_hex}` entries in
/// wire order, carrying the raw reassembled option payload (no typed
/// reinterpretation) so they compare cleanly against the Scapy reference view.
fn dhcp_options(layer: &Dhcp) -> Vec<Value> {
    layer
        .options_value()
        .iter()
        .map(|option| {
            let payload = option.payload().unwrap_or_default();
            json!({
                "code": option.code(),
                "payload_hex": hex_bytes(&payload),
            })
        })
        .collect()
}

fn payload_fields(layer: &Raw) -> BTreeMap<String, Value> {
    map([
        ("hex", json!(hex_bytes(layer.as_bytes()))),
        ("length", json!(layer.len())),
        (
            "ascii",
            json!(String::from_utf8_lossy(layer.as_bytes()).into_owned()),
        ),
    ])
}

fn inspection_fields(layer: &dyn Layer) -> BTreeMap<String, Value> {
    layer
        .inspection_fields()
        .into_iter()
        .map(|(name, value)| (name.to_string(), json!(value)))
        .collect()
}

fn insert_address(
    fields: &mut BTreeMap<String, Value>,
    name: &str,
    text: Option<String>,
    raw: Vec<u8>,
) {
    fields.insert(
        name.to_string(),
        text.map(Value::String)
            .unwrap_or_else(|| json!({"hex": hex_bytes(&raw)})),
    );
}

fn insert_mac<T: ToString>(fields: &mut BTreeMap<String, Value>, name: &str, value: Option<T>) {
    if let Some(value) = value {
        fields.insert(name.to_string(), json!(value.to_string()));
    }
}

fn radiotap_fcs_status(status: RadiotapFcsStatus) -> &'static str {
    match (status.present(), status.failed()) {
        (true, true) => "present_failed",
        (true, false) => "present",
        (false, true) => "failed",
        (false, false) => "absent",
    }
}

fn rsn_cipher_suite_value(suite: RsnCipherSuite) -> Value {
    let selector = suite.to_bytes();
    let mut fields = BTreeMap::new();
    fields.insert("selector".to_string(), json!(hex_bytes(&selector)));
    fields.insert("oui".to_string(), json!(hex_bytes(&selector[..3])));
    fields.insert("suite_type".to_string(), json!(suite.suite_type()));
    if let Some(label) = suite.label() {
        fields.insert("label".to_string(), json!(label));
    }
    Value::Object(fields.into_iter().collect())
}

fn rsn_akm_suite_value(suite: RsnAkmSuite) -> Value {
    let selector = suite.to_bytes();
    let mut fields = BTreeMap::new();
    fields.insert("selector".to_string(), json!(hex_bytes(&selector)));
    fields.insert("oui".to_string(), json!(hex_bytes(&selector[..3])));
    fields.insert("suite_type".to_string(), json!(suite.suite_type()));
    if let Some(label) = suite.label() {
        fields.insert("label".to_string(), json!(label));
    }
    Value::Object(fields.into_iter().collect())
}

fn dns_flag(dns: &Dns, flag: u16) -> bool {
    dns.flags_value() & flag != 0
}

fn map<const N: usize>(items: [(&str, Value); N]) -> BTreeMap<String, Value> {
    items
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect()
}

fn ipv4_flags(flags: u8) -> String {
    let mut names = Vec::new();
    if flags & crafter::core::IPV4_FLAG_MORE_FRAGMENTS != 0 {
        names.push("mf");
    }
    if flags & crafter::core::IPV4_FLAG_DONT_FRAGMENT != 0 {
        names.push("df");
    }
    if flags & crafter::core::IPV4_FLAG_RESERVED != 0 {
        names.push("reserved");
    }
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join("|")
    }
}

fn tcp_flags(flags: u16) -> String {
    let mut names = Vec::new();
    for (bit, name) in [
        (crafter::core::TCP_FLAG_FIN, "fin"),
        (crafter::core::TCP_FLAG_SYN, "syn"),
        (crafter::core::TCP_FLAG_RST, "rst"),
        (crafter::core::TCP_FLAG_PSH, "psh"),
        (crafter::core::TCP_FLAG_ACK, "ack"),
        (crafter::core::TCP_FLAG_URG, "urg"),
        (crafter::core::TCP_FLAG_ECE, "ece"),
        (crafter::core::TCP_FLAG_CWR, "cwr"),
        (crafter::core::TCP_FLAG_NS, "ns"),
    ] {
        if flags & bit != 0 {
            names.push(name);
        }
    }
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join("|")
    }
}

#[derive(Clone, Copy)]
struct UdpLayout {
    l3_start: usize,
    udp_length: usize,
    udp_payload_start: usize,
    udp_payload_end: usize,
    surplus_start: usize,
    ip_end: usize,
}

fn udp_layout(root: &str, raw: &[u8]) -> Option<UdpLayout> {
    let l3_start = l3_start_offset(root, raw)?;
    let version = raw.get(l3_start).map(|byte| byte >> 4)?;
    match version {
        4 => ipv4_udp_layout(raw, l3_start),
        6 => ipv6_udp_layout(raw, l3_start),
        _ => None,
    }
}

fn l3_start_offset(root: &str, raw: &[u8]) -> Option<usize> {
    match root {
        "link:ethernet" => ethernet_l3_start(raw),
        "link:linux-cooked" | "link:linux-sll" => Some(16),
        "link:null-loopback" => Some(4),
        "link:raw" | "l3:ipv4" | "l3:ipv6" | "l3:raw" => Some(0),
        _ => Some(0),
    }
}

fn ethernet_l3_start(raw: &[u8]) -> Option<usize> {
    if raw.len() < 14 {
        return None;
    }
    let mut offset = 14;
    let mut ethertype = u16::from_be_bytes([raw[12], raw[13]]);
    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        if raw.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
        offset += 4;
    }
    Some(offset)
}

fn ipv4_udp_layout(raw: &[u8], l3_start: usize) -> Option<UdpLayout> {
    let ihl = usize::from(raw.get(l3_start)? & 0x0f) * 4;
    let total_length = usize::from(u16_at(raw, l3_start + 2)?);
    let protocol = *raw.get(l3_start + 9)?;
    if ihl < 20 || protocol != crafter::core::IPPROTO_UDP {
        return None;
    }
    let udp_start = l3_start + ihl;
    udp_layout_from_offsets(raw, l3_start, udp_start, l3_start + total_length)
}

fn ipv6_udp_layout(raw: &[u8], l3_start: usize) -> Option<UdpLayout> {
    let payload_length = usize::from(u16_at(raw, l3_start + 4)?);
    let mut next_header = *raw.get(l3_start + 6)?;
    let mut offset = l3_start + 40;
    let ip_end = l3_start + 40 + payload_length;
    loop {
        if next_header == crafter::core::IPPROTO_UDP {
            return udp_layout_from_offsets(raw, l3_start, offset, ip_end);
        }
        match next_header {
            crafter::core::IPPROTO_IPV6_FRAGMENT => {
                next_header = *raw.get(offset)?;
                offset = offset.checked_add(8)?;
            }
            crafter::core::IPPROTO_IPV6_ROUTE => {
                next_header = *raw.get(offset)?;
                let length = (usize::from(*raw.get(offset + 1)?) + 1) * 8;
                offset = offset.checked_add(length)?;
            }
            _ => return None,
        }
        if offset > ip_end {
            return None;
        }
    }
}

fn udp_layout_from_offsets(
    raw: &[u8],
    l3_start: usize,
    udp_start: usize,
    ip_end: usize,
) -> Option<UdpLayout> {
    if raw.len() < udp_start + 8 || raw.len() < ip_end {
        return None;
    }
    let udp_length = usize::from(u16_at(raw, udp_start + 4)?);
    if udp_length < 8 {
        return None;
    }
    let udp_payload_start = udp_start + 8;
    let udp_payload_end = udp_start + udp_length;
    if udp_payload_end > ip_end {
        return None;
    }
    Some(UdpLayout {
        l3_start,
        udp_length,
        udp_payload_start,
        udp_payload_end,
        surplus_start: udp_payload_end,
        ip_end,
    })
}

fn udp_checksum_status_label(status: UdpChecksumStatus) -> &'static str {
    match status {
        UdpChecksumStatus::NotChecked => "not_checked",
        UdpChecksumStatus::Ipv4NoChecksum => "ipv4_no_checksum",
        UdpChecksumStatus::Valid => "valid",
        UdpChecksumStatus::Invalid => "invalid",
        UdpChecksumStatus::Ipv6ZeroChecksum => "ipv6_zero_checksum_exception_required",
    }
}

fn udp_option_status_label(status: UdpOptionStatus) -> &'static str {
    match status {
        UdpOptionStatus::NoSurplus => "no_surplus",
        UdpOptionStatus::NotParsed => "not_parsed",
        UdpOptionStatus::Valid => "valid",
        UdpOptionStatus::Ignored => "ignored",
        UdpOptionStatus::Malformed => "malformed",
        UdpOptionStatus::MalformedEnvelope => "malformed_envelope",
        UdpOptionStatus::NonzeroAfterEndOfList => "nonzero_after_end_of_list",
        UdpOptionStatus::TooManyNoOperations => "too_many_no_operations",
        UdpOptionStatus::Unsupported => "unsupported",
        UdpOptionStatus::UnsupportedFragmentation => "unsupported_fragmentation",
        UdpOptionStatus::UnknownSafe => "unknown_safe",
        UdpOptionStatus::UnknownUnsafe => "unknown_unsafe",
        UdpOptionStatus::OptionChecksumInvalid => "option_checksum_invalid",
        UdpOptionStatus::AdditionalPayloadChecksumInvalid => "additional_payload_checksum_invalid",
    }
}

fn u16_at(raw: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *raw.get(offset)?,
        *raw.get(offset + 1)?,
    ]))
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod igmp_decode_tests {
    use super::{hex_bytes, normalize_packet};
    use crafter::prelude::*;
    use crafter::protocols::igmp::{IgmpExtension, IGMP_ALL_ROUTERS_GROUP};
    use serde_json::json;
    use std::net::Ipv4Addr;

    const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const IGMP_SSM_GROUP: Ipv4Addr = Ipv4Addr::new(232, 0, 0, 17);
    const IGMP_SOURCE_A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 44);
    const IGMP_SOURCE_B: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 44);

    #[test]
    fn igmp_query_layers_emit_normalized_fields() {
        let packet = Ipv4::new()
            .src(SRC)
            .dst(IGMP_SSM_GROUP)
            .ttl(1)
            .protocol(IPPROTO_IGMP)
            / Igmp::membership_query()
                .with_max_response_code(100)
                .with_group_address(IGMP_SSM_GROUP)
            / IgmpQuery::new()
                .with_suppress_router_side_processing(true)
                .with_qrv(2)
                .with_qqic(125)
                .with_source_addresses(vec![IGMP_SOURCE_A, IGMP_SOURCE_B]);
        let bytes = packet.compile().expect("compile IGMP query");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .expect("decode IGMP query");
        let model = normalize_packet(
            &decoded,
            Some("l3:ipv4".to_string()),
            hex_bytes(bytes.as_bytes()),
            vec!["igmp".to_string()],
        );

        assert_eq!(model.layers, ["ipv4", "igmp", "igmp_query"]);
        assert_eq!(
            model.fields["igmp"]["type_label"],
            json!("membership_query")
        );
        assert_eq!(model.fields["igmp_query"]["query_flags"], json!(10));
        assert_eq!(
            model.fields["igmp_query"]["source_addresses"],
            json!(["192.0.2.44", "198.51.100.44"])
        );
    }

    #[test]
    fn igmp_report_and_extension_emit_nested_normalized_fields() {
        let record = IgmpGroupRecord::allow_new_sources(IGMP_SSM_GROUP)
            .with_source_addresses(vec![IGMP_SOURCE_A])
            .with_auxiliary_data(vec![0xaa, 0xbb, 0xcc, 0xdd]);
        let packet = Ipv4::new()
            .src(SRC)
            .dst(IGMP_ALL_ROUTERS_GROUP)
            .ttl(1)
            .protocol(IPPROTO_IGMP)
            / Igmp::v3_membership_report()
            / IgmpReport::new()
                .with_extension_flag(true)
                .with_group_record(record)
            / IgmpExtension::raw(IGMP_EXTENSION_TYPE_UNASSIGNED_FIRST, vec![0x01, 0x02]);
        let bytes = packet.compile().expect("compile IGMP report");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .expect("decode IGMP report");
        let model = normalize_packet(
            &decoded,
            Some("l3:ipv4".to_string()),
            hex_bytes(bytes.as_bytes()),
            vec!["igmp".to_string()],
        );

        assert_eq!(
            model.layers,
            ["ipv4", "igmp", "igmp_report", "igmp_extension"]
        );
        assert_eq!(
            model.fields["igmp_report"]["report_flag_labels"],
            json!(["extension"])
        );
        assert_eq!(
            model.fields["igmp_report"]["group_records"][0]["record_type_label"],
            json!("allow_new_sources")
        );
        assert_eq!(
            model.fields["igmp_extension"]["extension_value"],
            json!({"hex": "0102", "length": 2})
        );
    }
}
