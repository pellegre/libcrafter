mod common;

use common::{
    arg_value, flag_present, parse_u16_arg, parse_usize_arg, print_help_if_requested, ExampleResult,
};
use crafter::core::protocols::bgp::{
    BGP_HEADER_LEN, BGP_MARKER_LEN, BGP_MAX_MESSAGE_LEN, BGP_PORT, BGP_TYPE_KEEPALIVE,
    BGP_TYPE_NOTIFICATION, BGP_TYPE_OPEN, BGP_TYPE_UPDATE,
};
use crafter::prelude::*;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_LOCAL_AS: u16 = 65_000;
const DEFAULT_PEER_AS: u16 = 65_001;
const DEFAULT_BGP_ID: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const DEFAULT_IPV4_PREFIX: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 0);
const DEFAULT_IPV6_PREFIX: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
const DEFAULT_IPV6_NEXT_HOP: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
const DEFAULT_OUT_DIR: &str = "target/lab/bgp";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const INITIAL_READ_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_HOLD_READ_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_HOLD_READ_TIMEOUT: Duration = Duration::from_secs(30);
const POST_UPDATE_READ_TIMEOUT: Duration = Duration::from_secs(2);
const LINGER_READ_TIMEOUT: Duration = Duration::from_millis(500);
const POST_UPDATE_READ_LIMIT: usize = 8;
const LINGER_POLL_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_LINGER_SECONDS: usize = 1;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example bgp_session -- [--peer IP:PORT] [--local-as ASN] [--peer-as ASN] [--announce PREFIX] [--ipv6] [--linger-seconds SECONDS] [--out DIR]\n\nBuild an offline BGP session message plan by default. --peer opens a live TCP session to an explicitly provided BGP peer and writes a transcript under --out.",
    ) {
        return Ok(());
    }

    let config = Config::from_args()?;
    if config.peer.is_some() {
        return run_live(&config);
    }

    println!("example: bgp_session");
    println!("mode: offline");
    println!("local AS: {}", config.local_as);
    println!("peer AS: {}", config.peer_as);
    println!("BGP ID: {}", config.bgp_id);
    println!(
        "IPv4 announce: {}/{}",
        config.ipv4_prefix.0, config.ipv4_prefix.1
    );
    if config.ipv6 {
        println!(
            "IPv6 announce: {}/{}",
            config.ipv6_prefix.0, config.ipv6_prefix.1
        );
    }

    let messages = bgp_message_plan(&config)?;
    for (index, message) in messages.iter().enumerate() {
        print_message(index + 1, message.label, &message.packet)?;
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct Config {
    peer: Option<SocketAddr>,
    local_as: u16,
    peer_as: u16,
    bgp_id: Ipv4Addr,
    ipv4_next_hop: Ipv4Addr,
    ipv4_prefix: (Ipv4Addr, u8),
    ipv6_prefix: (Ipv6Addr, u8),
    ipv6: bool,
    linger: Duration,
    out_dir: PathBuf,
}

impl Config {
    fn from_args() -> ExampleResult<Self> {
        let mut config = Self {
            peer: parse_peer()?,
            local_as: parse_u16_arg("--local-as", DEFAULT_LOCAL_AS)?,
            peer_as: parse_u16_arg("--peer-as", DEFAULT_PEER_AS)?,
            bgp_id: DEFAULT_BGP_ID,
            ipv4_next_hop: DEFAULT_BGP_ID,
            ipv4_prefix: (DEFAULT_IPV4_PREFIX, 24),
            ipv6_prefix: (DEFAULT_IPV6_PREFIX, 32),
            ipv6: flag_present("--ipv6"),
            linger: Duration::from_secs(
                parse_usize_arg("--linger-seconds", DEFAULT_LINGER_SECONDS)? as u64,
            ),
            out_dir: arg_value("--out")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_OUT_DIR)),
        };

        if let Some(prefix) = arg_value("--announce") {
            match parse_prefix(&prefix)? {
                Prefix::V4(addr, len) => config.ipv4_prefix = (addr, len),
                Prefix::V6(addr, len) => config.ipv6_prefix = (addr, len),
            }
        }

        Ok(config)
    }

    #[cfg(test)]
    fn offline_default() -> Self {
        Self {
            peer: None,
            local_as: DEFAULT_LOCAL_AS,
            peer_as: DEFAULT_PEER_AS,
            bgp_id: DEFAULT_BGP_ID,
            ipv4_next_hop: DEFAULT_BGP_ID,
            ipv4_prefix: (DEFAULT_IPV4_PREFIX, 24),
            ipv6_prefix: (DEFAULT_IPV6_PREFIX, 32),
            ipv6: false,
            linger: Duration::from_secs(DEFAULT_LINGER_SECONDS as u64),
            out_dir: PathBuf::from(DEFAULT_OUT_DIR),
        }
    }
}

enum Prefix {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

fn parse_peer() -> ExampleResult<Option<SocketAddr>> {
    match arg_value("--peer") {
        Some(value) => Ok(Some(value.parse()?)),
        None => Ok(None),
    }
}

fn parse_prefix(value: &str) -> ExampleResult<Prefix> {
    let (addr, len) = value
        .split_once('/')
        .ok_or_else(|| format!("--announce expects CIDR form, got {value:?}"))?;
    let len: u8 = len.parse()?;
    match addr.parse::<IpAddr>()? {
        IpAddr::V4(addr) if len <= 32 => Ok(Prefix::V4(addr, len)),
        IpAddr::V6(addr) if len <= 128 => Ok(Prefix::V6(addr, len)),
        IpAddr::V4(_) => Err(format!("IPv4 prefix length must be <= 32, got {len}").into()),
        IpAddr::V6(_) => Err(format!("IPv6 prefix length must be <= 128, got {len}").into()),
    }
}

struct PlannedMessage {
    label: &'static str,
    packet: Packet,
}

fn bgp_message_plan(config: &Config) -> ExampleResult<Vec<PlannedMessage>> {
    let ipv4_prefix = BgpPrefix::from_ipv4(config.ipv4_prefix.0, config.ipv4_prefix.1)?;
    let ipv6_prefix = BgpPrefix::from_ipv6(config.ipv6_prefix.0, config.ipv6_prefix.1)?;

    let mut capabilities = vec![
        BgpCapability::ipv4_unicast(),
        BgpCapability::route_refresh(),
        BgpCapability::four_octet_as(config.local_as as u32),
    ];
    if config.ipv6 {
        capabilities.insert(1, BgpCapability::ipv6_unicast());
    }

    let mut messages = vec![
        PlannedMessage {
            label: "OPEN",
            packet: Packet::from_layer(
                Bgp::open()
                    .my_as(config.local_as)
                    .hold_time(90)
                    .bgp_id(config.bgp_id)
                    .capabilities(capabilities),
            ),
        },
        PlannedMessage {
            label: "KEEPALIVE",
            packet: Packet::from_layer(Bgp::keepalive()),
        },
        PlannedMessage {
            label: "UPDATE IPv4 announce",
            packet: Packet::from_layer(
                Bgp::update()
                    .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
                    .attribute(BgpPathAttribute::as_sequence4(&[config.local_as as u32]))
                    .attribute(BgpPathAttribute::next_hop(config.ipv4_next_hop))
                    .nlri(ipv4_prefix),
            ),
        },
    ];

    if config.ipv6 {
        messages.push(PlannedMessage {
            label: "UPDATE MP-BGP IPv6 announce",
            packet: Packet::from_layer(
                Bgp::update()
                    .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
                    .attribute(BgpPathAttribute::as_sequence4(&[config.local_as as u32]))
                    .attribute(BgpPathAttribute::mp_reach_ipv6(
                        DEFAULT_IPV6_NEXT_HOP,
                        &[ipv6_prefix],
                    )),
            ),
        });
    }

    messages.push(PlannedMessage {
        label: "NOTIFICATION Cease",
        packet: Packet::from_layer(Bgp::cease()),
    });

    Ok(messages)
}

fn print_message(index: usize, label: &str, packet: &Packet) -> ExampleResult<()> {
    let compiled = packet.compile()?;
    println!();
    println!("message {index}: {label}");
    println!("summary: {}", packet.summary());
    println!("bytes: {}", compiled.len());
    println!("hex: {}", compact_hex(compiled.as_bytes()));
    println!("hexdump:\n{}", compiled.hexdump());
    Ok(())
}

fn run_live(config: &Config) -> ExampleResult<()> {
    let mut config = config.clone();
    let mut transcript = Transcript::new();
    let result = run_live_inner(&mut config, &mut transcript);
    let write_result = transcript.write(&config.out_dir, &config);

    match write_result {
        Ok(path) => println!("transcript: {}", path.display()),
        Err(error) if result.is_ok() => return Err(error.into()),
        Err(error) => eprintln!("failed to write transcript: {error}"),
    }

    result
}

fn run_live_inner(config: &mut Config, transcript: &mut Transcript) -> ExampleResult<()> {
    let peer = config.peer.expect("live mode requires peer");
    println!("example: bgp_session");
    println!("mode: live");
    println!("peer: {peer}");
    println!("local AS: {}", config.local_as);
    println!("peer AS: {}", config.peer_as);
    println!("BGP ID: {}", config.bgp_id);
    println!("transcript directory: {}", config.out_dir.display());

    let mut stream = TcpStream::connect_timeout(&peer, CONNECT_TIMEOUT)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(INITIAL_READ_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    if let IpAddr::V4(addr) = stream.local_addr()?.ip() {
        config.ipv4_next_hop = addr;
    }
    println!("IPv4 next hop: {}", config.ipv4_next_hop);

    let plan = bgp_message_plan(config)?;
    let open = find_planned(&plan, "OPEN")?;
    send_planned(&mut stream, transcript, open)?;

    let peer_open = receive_required(&mut stream, transcript, "peer OPEN", BGP_TYPE_OPEN)?;
    let read_timeout = hold_read_timeout(peer_open.hold_time);
    stream.set_read_timeout(Some(read_timeout))?;
    println!("read timeout: {:?} from peer hold time", read_timeout);

    let keepalive = find_planned(&plan, "KEEPALIVE")?;
    send_planned(&mut stream, transcript, keepalive)?;
    receive_required(
        &mut stream,
        transcript,
        "peer KEEPALIVE",
        BGP_TYPE_KEEPALIVE,
    )?;
    println!("state: Established");

    for message in plan
        .iter()
        .filter(|message| matches!(message_type(&message.packet), Ok(BGP_TYPE_UPDATE)))
    {
        send_planned(&mut stream, transcript, message)?;
    }

    stream.set_read_timeout(Some(POST_UPDATE_READ_TIMEOUT))?;
    drain_inbound_with_label(&mut stream, transcript, "post-update inbound")?;
    linger_established(&mut stream, transcript, config.linger)?;

    let cease = find_planned(&plan, "NOTIFICATION Cease")?;
    send_planned(&mut stream, transcript, cease)?;
    stream.shutdown(std::net::Shutdown::Both).ok();
    Ok(())
}

fn find_planned<'a>(plan: &'a [PlannedMessage], label: &str) -> ExampleResult<&'a PlannedMessage> {
    plan.iter()
        .find(|message| message.label == label)
        .ok_or_else(|| format!("message plan did not contain {label}").into())
}

fn send_planned(
    stream: &mut TcpStream,
    transcript: &mut Transcript,
    message: &PlannedMessage,
) -> ExampleResult<()> {
    let compiled = message.packet.compile()?;
    stream.write_all(compiled.as_bytes())?;
    stream.flush()?;
    let summary = message.packet.summary();
    println!("sent {}: {}", message.label, summary);
    transcript.record("sent", message.label, &summary, compiled.as_bytes());
    Ok(())
}

fn receive_required(
    stream: &mut TcpStream,
    transcript: &mut Transcript,
    label: &'static str,
    expected_type: u8,
) -> ExampleResult<ReceivedMessage> {
    let Some(message) = receive_optional(stream, transcript, label)? else {
        return Err(format!("timed out waiting for {label}").into());
    };

    if message.message_type == BGP_TYPE_NOTIFICATION {
        return Err(format!("peer sent NOTIFICATION while waiting for {label}").into());
    }

    if message.message_type != expected_type {
        return Err(format!(
            "expected {label} type {expected_type}, got type {}",
            message.message_type
        )
        .into());
    }

    Ok(message)
}

fn receive_optional(
    stream: &mut TcpStream,
    transcript: &mut Transcript,
    label: &'static str,
) -> ExampleResult<Option<ReceivedMessage>> {
    let Some(bytes) = read_bgp_message(stream)? else {
        return Ok(None);
    };

    let decoded = decode_bgp_payload_via_registry(&bytes)?;
    let summary = bgp_summary(&decoded);
    let message = ReceivedMessage {
        message_type: bgp_message_type(&bytes).unwrap_or(0),
        hold_time: bgp_open_hold_time(&bytes),
    };

    println!("received {label}: {summary}");
    transcript.record("received", label, &summary, &bytes);
    Ok(Some(message))
}

fn drain_inbound_with_label(
    stream: &mut TcpStream,
    transcript: &mut Transcript,
    label: &'static str,
) -> ExampleResult<()> {
    for _ in 0..POST_UPDATE_READ_LIMIT {
        let Some(message) = receive_optional(stream, transcript, label)? else {
            break;
        };

        if message.message_type == BGP_TYPE_NOTIFICATION {
            return Err(format!("peer sent NOTIFICATION while reading {label}").into());
        }
    }
    Ok(())
}

fn linger_established(
    stream: &mut TcpStream,
    transcript: &mut Transcript,
    duration: Duration,
) -> ExampleResult<()> {
    if duration.is_zero() {
        return Ok(());
    }

    println!("linger: {}s", duration.as_secs());
    stream.set_read_timeout(Some(LINGER_READ_TIMEOUT))?;
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        drain_inbound_with_label(stream, transcript, "linger inbound")?;
        thread::sleep(LINGER_POLL_INTERVAL);
    }

    Ok(())
}

fn read_bgp_message(stream: &mut TcpStream) -> ExampleResult<Option<Vec<u8>>> {
    let mut header = [0u8; BGP_HEADER_LEN];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::UnexpectedEof
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    }

    let length = u16::from_be_bytes([header[BGP_MARKER_LEN], header[BGP_MARKER_LEN + 1]]) as usize;
    if !(BGP_HEADER_LEN..=BGP_MAX_MESSAGE_LEN).contains(&length) {
        return Err(format!("peer sent invalid BGP message length {length}").into());
    }

    let mut message = header.to_vec();
    message.resize(length, 0);
    if length > BGP_HEADER_LEN {
        stream.read_exact(&mut message[BGP_HEADER_LEN..])?;
    }
    Ok(Some(message))
}

fn decode_bgp_payload_via_registry(bytes: &[u8]) -> ExampleResult<Packet> {
    let wrapped = (Ipv4::new()
        .src(DEFAULT_BGP_ID)
        .dst(Ipv4Addr::new(198, 51, 100, 1))
        / Tcp::new().sport(BGP_PORT).dport(49_152)
        / Raw::from_bytes(bytes))
    .compile()?;
    let registry = ProtocolRegistry::with_builtin_bindings();
    Ok(registry.decode_from_l3(NetworkLayer::Ipv4, wrapped.as_bytes())?)
}

fn bgp_summary(packet: &Packet) -> String {
    let summaries = packet
        .layers::<Bgp>()
        .map(Layer::summary)
        .collect::<Vec<_>>();
    if summaries.is_empty() {
        packet.summary()
    } else {
        summaries.join(" / ")
    }
}

fn hold_read_timeout(hold_time: Option<u16>) -> Duration {
    let requested = Duration::from_secs(u64::from(hold_time.unwrap_or(10).max(1)));
    requested.clamp(MIN_HOLD_READ_TIMEOUT, MAX_HOLD_READ_TIMEOUT)
}

fn message_type(packet: &Packet) -> ExampleResult<u8> {
    let compiled = packet.compile()?;
    bgp_message_type(compiled.as_bytes())
        .ok_or_else(|| "compiled packet is shorter than a BGP header".into())
}

fn bgp_message_type(bytes: &[u8]) -> Option<u8> {
    bytes.get(BGP_MARKER_LEN + 2).copied()
}

fn bgp_open_hold_time(bytes: &[u8]) -> Option<u16> {
    if bgp_message_type(bytes)? != BGP_TYPE_OPEN || bytes.len() < BGP_HEADER_LEN + 5 {
        return None;
    }
    Some(u16::from_be_bytes([
        bytes[BGP_HEADER_LEN + 3],
        bytes[BGP_HEADER_LEN + 4],
    ]))
}

struct ReceivedMessage {
    message_type: u8,
    hold_time: Option<u16>,
}

struct Transcript {
    entries: Vec<TranscriptEntry>,
}

impl Transcript {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn record(&mut self, direction: &'static str, label: &str, summary: &str, bytes: &[u8]) {
        self.entries.push(TranscriptEntry {
            direction,
            label: label.to_string(),
            summary: summary.to_string(),
            hex: compact_hex(bytes),
        });
    }

    fn write(&self, out_dir: &Path, config: &Config) -> std::io::Result<PathBuf> {
        fs::create_dir_all(out_dir)?;
        let path = out_dir.join("bgp-session-transcript.txt");
        let mut body = String::new();
        body.push_str("bgp_session transcript\n");
        body.push_str(&format!("created_unix: {}\n", unix_timestamp()));
        body.push_str(&format!("peer: {:?}\n", config.peer));
        body.push_str(&format!("local_as: {}\n", config.local_as));
        body.push_str(&format!("peer_as: {}\n", config.peer_as));
        body.push_str(&format!("bgp_id: {}\n", config.bgp_id));
        body.push_str(&format!("ipv4_next_hop: {}\n", config.ipv4_next_hop));
        body.push_str(&format!(
            "ipv4_announce: {}/{}\n",
            config.ipv4_prefix.0, config.ipv4_prefix.1
        ));
        if config.ipv6 {
            body.push_str(&format!(
                "ipv6_announce: {}/{}\n",
                config.ipv6_prefix.0, config.ipv6_prefix.1
            ));
        }
        body.push_str(&format!("linger_seconds: {}\n", config.linger.as_secs()));
        body.push('\n');

        for (index, entry) in self.entries.iter().enumerate() {
            body.push_str(&format!(
                "{}. {} {}\nsummary: {}\nhex: {}\n\n",
                index + 1,
                entry.direction,
                entry.label,
                entry.summary,
                entry.hex
            ));
        }

        fs::write(&path, body)?;
        Ok(path)
    }
}

struct TranscriptEntry {
    direction: &'static str,
    label: String,
    summary: String,
    hex: String,
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn compact_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bgp_session_message_plan_default_orders_core_messages() {
        let config = Config::offline_default();
        let plan = bgp_message_plan(&config).expect("message plan");
        let types = plan
            .iter()
            .map(|message| message_type(&message.packet).expect("message type"))
            .collect::<Vec<_>>();

        assert_eq!(
            types,
            vec![
                BGP_TYPE_OPEN,
                BGP_TYPE_KEEPALIVE,
                BGP_TYPE_UPDATE,
                BGP_TYPE_NOTIFICATION
            ]
        );
    }
}
