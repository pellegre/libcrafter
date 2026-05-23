#!/usr/bin/env python3
"""Generate deterministic Scapy reference fixtures.

The generated files are pure byte fixtures and JSON metadata. No root
privileges, packet injection, or live interfaces are required.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any, Callable


def import_scapy() -> dict[str, Any]:
    try:
        import scapy  # type: ignore[import-untyped]
        from scapy.all import (  # type: ignore[import-untyped]
            ARP,
            BOOTP,
            DHCP,
            DNS,
            DNSQR,
            Dot1Q,
            Ether,
            ICMP,
            IP,
            IPOption,
            IPv6,
            Raw,
            TCP,
            UDP,
            conf,
            raw,
        )
        from scapy.layers.inet6 import (  # type: ignore[import-untyped]
            ICMPv6EchoRequest,
            IPv6ExtHdrFragment,
            IPv6ExtHdrRouting,
            IPv6ExtHdrSegmentRouting,
        )
        from scapy.layers.l2 import CookedLinux, Loopback  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:
        if exc.name != "scapy":
            raise
        maybe_reexec_with_uv()
        raise

    conf.verb = 0
    return {
        "ARP": ARP,
        "BOOTP": BOOTP,
        "CookedLinux": CookedLinux,
        "DHCP": DHCP,
        "DNS": DNS,
        "DNSQR": DNSQR,
        "Dot1Q": Dot1Q,
        "Ether": Ether,
        "ICMP": ICMP,
        "ICMPv6EchoRequest": ICMPv6EchoRequest,
        "IP": IP,
        "IPOption": IPOption,
        "IPv6": IPv6,
        "IPv6ExtHdrFragment": IPv6ExtHdrFragment,
        "IPv6ExtHdrRouting": IPv6ExtHdrRouting,
        "IPv6ExtHdrSegmentRouting": IPv6ExtHdrSegmentRouting,
        "Loopback": Loopback,
        "Raw": Raw,
        "TCP": TCP,
        "UDP": UDP,
        "version": getattr(scapy, "__version__", "unknown"),
        "raw": raw,
    }


def maybe_reexec_with_uv() -> None:
    if os.environ.get("LIBCRAFTER_SCAPY_BOOTSTRAPPED") == "1":
        print(
            "error: scapy is not importable after dependency bootstrap",
            file=sys.stderr,
        )
        sys.exit(1)

    uv = shutil.which("uv")
    if uv is None:
        print(
            "error: scapy is not installed. Run tools/reference/generate-scapy-fixtures "
            "to bootstrap it without root, or install scapy in this Python environment.",
            file=sys.stderr,
        )
        sys.exit(1)

    env = os.environ.copy()
    env["LIBCRAFTER_SCAPY_BOOTSTRAPPED"] = "1"
    env.setdefault("UV_NO_PROGRESS", "1")
    script = str(Path(__file__).resolve())
    os.execvpe(
        uv,
        [
            uv,
            "run",
            "--quiet",
            "--no-project",
            "--with",
            "scapy>=2.5,<3",
            "--",
            "python3",
            script,
            *sys.argv[1:],
        ],
        env,
    )


SCAPY = import_scapy()

ARP = SCAPY["ARP"]
BOOTP = SCAPY["BOOTP"]
CookedLinux = SCAPY["CookedLinux"]
DHCP = SCAPY["DHCP"]
DNS = SCAPY["DNS"]
DNSQR = SCAPY["DNSQR"]
Dot1Q = SCAPY["Dot1Q"]
Ether = SCAPY["Ether"]
ICMP = SCAPY["ICMP"]
ICMPv6EchoRequest = SCAPY["ICMPv6EchoRequest"]
IP = SCAPY["IP"]
IPOption = SCAPY["IPOption"]
IPv6 = SCAPY["IPv6"]
IPv6ExtHdrFragment = SCAPY["IPv6ExtHdrFragment"]
IPv6ExtHdrRouting = SCAPY["IPv6ExtHdrRouting"]
IPv6ExtHdrSegmentRouting = SCAPY["IPv6ExtHdrSegmentRouting"]
Loopback = SCAPY["Loopback"]
Raw = SCAPY["Raw"]
TCP = SCAPY["TCP"]
UDP = SCAPY["UDP"]
raw = SCAPY["raw"]
SCAPY_VERSION = SCAPY["version"]

REPO_ROOT = Path(__file__).resolve().parents[2]
SCAPY_FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "scapy"
CASE_MANIFEST = SCAPY_FIXTURE_DIR / "cases.json"

SRC_MAC = "02:00:5e:00:53:01"
DST_MAC = "02:00:5e:00:53:02"
ZERO_MAC = "00:00:00:00:00:00"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
SRC_IPV4 = "192.0.2.10"
DST_IPV4 = "198.51.100.20"
GW_IPV4 = "192.0.2.1"
SRC_IPV6 = "2001:db8:1::10"
DST_IPV6 = "2001:db8:2::20"


PacketFactory = Callable[[], Any]


class Fixture:
    def __init__(
        self,
        name: str,
        description: str,
        scapy_root: str,
        stack: list[str],
        factory: PacketFactory,
    ) -> None:
        self.name = name
        self.description = description
        self.scapy_root = scapy_root
        self.stack = stack
        self.factory = factory


def mac_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def ethernet_fixture() -> Any:
    return Ether(src=SRC_MAC, dst=DST_MAC, type=0x9000) / Raw(b"libcrafter-ethernet")


def arp_request_fixture() -> Any:
    return (
        Ether(src=SRC_MAC, dst=BROADCAST_MAC)
        / ARP(
            op=1,
            hwsrc=SRC_MAC,
            psrc=SRC_IPV4,
            hwdst=ZERO_MAC,
            pdst=GW_IPV4,
        )
    )


def raw_payload_link_fixture() -> Any:
    return Raw(b"raw-link-payload")


def arp_reply_fixture() -> Any:
    return (
        Ether(src=SRC_MAC, dst=DST_MAC)
        / ARP(
            op=2,
            hwsrc=SRC_MAC,
            psrc=SRC_IPV4,
            hwdst=DST_MAC,
            pdst=GW_IPV4,
        )
    )


def ipv4_icmp_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1234, ttl=64, flags="DF")
        / ICMP(type="echo-request", id=0x4242, seq=1)
        / Raw(b"libcrafter-icmp")
    )


def ipv4_udp_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1235, ttl=63)
        / UDP(sport=53000, dport=33434)
        / Raw(b"libcrafter-udp")
    )


def ipv4_tcp_syn_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1236, ttl=62, flags="DF")
        / TCP(sport=40000, dport=80, flags="S", seq=0x01020304, window=64240)
    )


def ipv4_boundary_fields_fixture() -> Any:
    return (
        IP(
            src=SRC_IPV4,
            dst=DST_IPV4,
            id=0x1243,
            tos=0xB8,
            ttl=0,
            flags=7,
            frag=0x1FFF,
            proto=253,
        )
        / Raw(b"v4-boundary")
    )


def ipv4_unknown_protocol_raw_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1244, ttl=64, proto=253)
        / Raw(b"unknown-ipv4")
    )


def ipv4_fragment_mf_offset_fixture() -> Any:
    return (
        IP(
            src=SRC_IPV4,
            dst=DST_IPV4,
            id=0x1245,
            flags="MF",
            frag=37,
            proto=253,
        )
        / Raw(b"fragmented-tail")
    )


def ipv4_ttl_255_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1246, ttl=255, flags="DF", proto=253)
        / Raw(b"ttl255")
    )


def dns_query_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst="198.51.100.53", id=0x1237, ttl=61)
        / UDP(sport=53001, dport=53)
        / DNS(id=0xBEEF, rd=1, qd=DNSQR(qname="example.com.", qtype="A"))
    )


def dhcp_discover_fixture() -> Any:
    return (
        Ether(src=SRC_MAC, dst=BROADCAST_MAC)
        / IP(src="0.0.0.0", dst="255.255.255.255", id=0x1238, ttl=64)
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=mac_bytes(SRC_MAC), xid=0x3903F326, flags=0x8000)
        / DHCP(
            options=[
                ("message-type", "discover"),
                ("hostname", "libcrafter-test"),
                ("param_req_list", [1, 3, 6, 15]),
                "end",
            ]
        )
    )


def ipv6_icmp_fixture() -> Any:
    return (
        IPv6(src=SRC_IPV6, dst=DST_IPV6, hlim=64, fl=0x12345)
        / ICMPv6EchoRequest(id=0x4242, seq=2, data=b"libcrafter-ipv6")
    )


def ipv4_options_fixture() -> Any:
    return (
        IP(
            src=SRC_IPV4,
            dst=DST_IPV4,
            id=0x1239,
            ttl=60,
            options=[
                IPOption(b"\x01"),
                IPOption(b"\x07\x07\x04\xc0\x00\x02\x01"),
                IPOption(b"\x1e\x04\xaa\xbb"),
                IPOption(b"\x00"),
            ],
        )
        / Raw(b"ip-options")
    )


def ipv4_options_source_route_traceroute_fixture() -> Any:
    return (
        IP(
            src=SRC_IPV4,
            dst=DST_IPV4,
            id=0x1247,
            ttl=62,
            options=[
                IPOption(b"\x83\x07\x04\xc0\x00\x02\x01"),
                IPOption(b"\x89\x07\x04\xc6\x33\x64\x14"),
                IPOption(b"\x52\x0c\x12\x34\x00\x01\xff\xff\xc0\x00\x02\x0a"),
            ],
        )
        / Raw(b"srtrace")
    )


def tcp_options_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x123A, ttl=59, flags="DF")
        / TCP(
            sport=40001,
            dport=443,
            flags="S",
            seq=0x11223344,
            window=65535,
            options=[
                ("MSS", 1460),
                ("SAckOK", b""),
                ("Timestamp", (0x01020304, 0x05060708)),
                ("WScale", 7),
            ],
        )
    )


def vlan_udp_fixture() -> Any:
    return (
        Ether(src=SRC_MAC, dst=DST_MAC)
        / Dot1Q(vlan=42, prio=3)
        / IP(src=SRC_IPV4, dst=DST_IPV4, id=0x123B, ttl=58)
        / UDP(sport=53002, dport=9999)
        / Raw(b"vlan-udp")
    )


def vlan_boundary_fields_fixture() -> Any:
    return (
        Ether(src=SRC_MAC, dst=DST_MAC)
        / Dot1Q(vlan=4094, prio=7, dei=1)
        / IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1248, ttl=57)
        / UDP(sport=53003, dport=10000)
        / Raw(b"vlan-boundary")
    )


def linux_cooked_ipv4_udp_fixture() -> Any:
    return (
        CookedLinux(
            pkttype=0,
            lladdrtype=1,
            lladdrlen=6,
            src=mac_bytes(SRC_MAC) + b"\x00\x00",
            proto=0x0800,
        )
        / IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1249, ttl=56)
        / UDP(sport=53004, dport=10001)
        / Raw(b"sll-udp")
    )


def null_loopback_ipv4_little_endian_fixture() -> Any:
    return (
        Loopback(type=2)
        / IP(src=SRC_IPV4, dst=DST_IPV4, id=0x124A, ttl=55)
        / ICMP(type="echo-request", id=0x4244, seq=4)
    )


def ipv6_boundary_fields_fixture() -> Any:
    return (
        IPv6(src=SRC_IPV6, dst=DST_IPV6, tc=0xAB, fl=0xFFFFF, hlim=0, nh=253)
        / Raw(b"v6-boundary")
    )


def ipv6_unknown_next_header_raw_fixture() -> Any:
    return (
        IPv6(src=SRC_IPV6, dst=DST_IPV6, fl=0, hlim=255, nh=253)
        / Raw(b"unknown-ipv6")
    )


def ipv6_fragment_udp_fixture() -> Any:
    return (
        IPv6(src=SRC_IPV6, dst=DST_IPV6)
        / IPv6ExtHdrFragment(nh=17, offset=0, m=1, id=0x01020304)
        / UDP(sport=53005, dport=10002)
        / Raw(b"fragudp")
    )


def ipv6_routing_generic_fixture() -> Any:
    return (
        IPv6(src=SRC_IPV6, dst=DST_IPV6)
        / IPv6ExtHdrRouting(nh=253, type=253, segleft=0, addresses=[])
        / Raw(b"route-raw")
    )


def ipv6_mobile_routing_fixture() -> Any:
    return (
        IPv6(src=SRC_IPV6, dst=DST_IPV6)
        / IPv6ExtHdrRouting(
            nh=253,
            type=2,
            segleft=1,
            addresses=["2001:db8:ffff::1"],
        )
        / Raw(b"mobile-raw")
    )


def ipv6_segment_routing_udp_fixture() -> Any:
    return (
        IPv6(src=SRC_IPV6, dst=DST_IPV6)
        / IPv6ExtHdrSegmentRouting(
            nh=17,
            segleft=1,
            addresses=["2001:db8:ffff::1", "2001:db8:ffff::2"],
        )
        / UDP(sport=53006, dport=10003)
        / Raw(b"srhudp")
    )


def ipv6_extension_chain_tcp_raw_fixture() -> Any:
    return (
        IPv6(src=SRC_IPV6, dst=DST_IPV6)
        / IPv6ExtHdrRouting(nh=6, type=253, segleft=0, addresses=[])
        / TCP(sport=53007, dport=443, flags="PA")
        / Raw(b"chain")
    )


def ipv6_routing_icmpv6_fixture() -> Any:
    return (
        IPv6(src=SRC_IPV6, dst=DST_IPV6)
        / IPv6ExtHdrRouting(nh=58, type=253, segleft=0, addresses=[])
        / ICMPv6EchoRequest(id=0x4246, seq=6, data=b"routeicmp")
    )


FIXTURES = [
    Fixture(
        "ethernet",
        "Ethernet II frame with an experimental ethertype and raw payload.",
        "Ether",
        ["Ether", "Raw"],
        ethernet_fixture,
    ),
    Fixture(
        "arp-request",
        "Ethernet ARP who-has request.",
        "Ether",
        ["Ether", "ARP"],
        arp_request_fixture,
    ),
    Fixture(
        "raw-payload-link",
        "Raw link-layer payload.",
        "Raw",
        ["Raw"],
        raw_payload_link_fixture,
    ),
    Fixture(
        "arp-reply",
        "Ethernet ARP is-at reply.",
        "Ether",
        ["Ether", "ARP"],
        arp_reply_fixture,
    ),
    Fixture(
        "ipv4-icmp",
        "IPv4 ICMP echo request with raw payload.",
        "IP",
        ["IP", "ICMP", "Raw"],
        ipv4_icmp_fixture,
    ),
    Fixture(
        "ipv4-udp",
        "IPv4 UDP datagram with raw payload.",
        "IP",
        ["IP", "UDP", "Raw"],
        ipv4_udp_fixture,
    ),
    Fixture(
        "ipv4-tcp-syn",
        "IPv4 TCP SYN packet.",
        "IP",
        ["IP", "TCP"],
        ipv4_tcp_syn_fixture,
    ),
    Fixture(
        "ipv4-boundary-fields",
        "IPv4 boundary fields with raw fallback.",
        "IP",
        ["IP", "Raw"],
        ipv4_boundary_fields_fixture,
    ),
    Fixture(
        "ipv4-unknown-protocol-raw",
        "IPv4 unknown protocol with raw payload.",
        "IP",
        ["IP", "Raw"],
        ipv4_unknown_protocol_raw_fixture,
    ),
    Fixture(
        "ipv4-fragment-mf-offset",
        "IPv4 nonzero fragment offset with raw payload.",
        "IP",
        ["IP", "Raw"],
        ipv4_fragment_mf_offset_fixture,
    ),
    Fixture(
        "ipv4-ttl-255",
        "IPv4 TTL 255 with raw payload.",
        "IP",
        ["IP", "Raw"],
        ipv4_ttl_255_fixture,
    ),
    Fixture(
        "dns-query",
        "IPv4 UDP DNS A query for example.com.",
        "IP",
        ["IP", "UDP", "DNS"],
        dns_query_fixture,
    ),
    Fixture(
        "dhcp-discover",
        "Ethernet IPv4 UDP BOOTP DHCP discover.",
        "Ether",
        ["Ether", "IP", "UDP", "BOOTP", "DHCP"],
        dhcp_discover_fixture,
    ),
    Fixture(
        "ipv6-icmp",
        "IPv6 ICMPv6 echo request.",
        "IPv6",
        ["IPv6", "ICMPv6EchoRequest"],
        ipv6_icmp_fixture,
    ),
    Fixture(
        "ipv4-options",
        "IPv4 packet with NOP, record-route, generic, and EOL options.",
        "IP",
        ["IP", "Raw"],
        ipv4_options_fixture,
    ),
    Fixture(
        "ipv4-options-source-route-traceroute",
        "IPv4 loose/strict source route and traceroute options.",
        "IP",
        ["IP", "Raw"],
        ipv4_options_source_route_traceroute_fixture,
    ),
    Fixture(
        "tcp-options",
        "IPv4 TCP SYN packet with common TCP options.",
        "IP",
        ["IP", "TCP"],
        tcp_options_fixture,
    ),
    Fixture(
        "vlan-ipv4-udp",
        "802.1Q Ethernet IPv4 UDP datagram.",
        "Ether",
        ["Ether", "Dot1Q", "IP", "UDP", "Raw"],
        vlan_udp_fixture,
    ),
    Fixture(
        "vlan-boundary-fields",
        "802.1Q Ethernet boundary PCP, DEI, and VLAN ID.",
        "Ether",
        ["Ether", "Dot1Q", "IP", "UDP", "Raw"],
        vlan_boundary_fields_fixture,
    ),
    Fixture(
        "linux-cooked-ipv4-udp",
        "Linux cooked capture IPv4 UDP datagram.",
        "CookedLinux",
        ["CookedLinux", "IP", "UDP", "Raw"],
        linux_cooked_ipv4_udp_fixture,
    ),
    Fixture(
        "null-loopback-ipv4-little-endian",
        "BSD null loopback little-endian IPv4 ICMP packet.",
        "Loopback",
        ["Loopback", "IP", "ICMP"],
        null_loopback_ipv4_little_endian_fixture,
    ),
    Fixture(
        "ipv6-boundary-fields",
        "IPv6 traffic class, max flow label, hop limit 0, and raw fallback.",
        "IPv6",
        ["IPv6", "Raw"],
        ipv6_boundary_fields_fixture,
    ),
    Fixture(
        "ipv6-unknown-next-header-raw",
        "IPv6 unknown next header with flow label 0 and hop limit 255.",
        "IPv6",
        ["IPv6", "Raw"],
        ipv6_unknown_next_header_raw_fixture,
    ),
    Fixture(
        "ipv6-fragment-udp",
        "IPv6 fragment extension header chained to UDP.",
        "IPv6",
        ["IPv6", "IPv6ExtHdrFragment", "UDP", "Raw"],
        ipv6_fragment_udp_fixture,
    ),
    Fixture(
        "ipv6-routing-generic",
        "IPv6 generic routing header chained to raw payload.",
        "IPv6",
        ["IPv6", "IPv6ExtHdrRouting", "Raw"],
        ipv6_routing_generic_fixture,
    ),
    Fixture(
        "ipv6-mobile-routing",
        "IPv6 mobile routing header chained to raw payload.",
        "IPv6",
        ["IPv6", "IPv6ExtHdrRouting", "Raw"],
        ipv6_mobile_routing_fixture,
    ),
    Fixture(
        "ipv6-segment-routing-udp",
        "IPv6 segment routing header chained to UDP.",
        "IPv6",
        ["IPv6", "IPv6ExtHdrSegmentRouting", "UDP", "Raw"],
        ipv6_segment_routing_udp_fixture,
    ),
    Fixture(
        "ipv6-extension-chain-tcp-raw",
        "IPv6 routing extension chained to TCP and raw payload.",
        "IPv6",
        ["IPv6", "IPv6ExtHdrRouting", "TCP", "Raw"],
        ipv6_extension_chain_tcp_raw_fixture,
    ),
    Fixture(
        "ipv6-routing-icmpv6",
        "IPv6 routing extension chained to ICMPv6 echo.",
        "IPv6",
        ["IPv6", "IPv6ExtHdrRouting", "ICMPv6EchoRequest"],
        ipv6_routing_icmpv6_fixture,
    ),
]

FIXTURE_MAP = {fixture.name: fixture for fixture in FIXTURES}


def load_case_manifest(path: Path = CASE_MANIFEST) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"missing Scapy case manifest: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid Scapy case manifest {path}: {exc}") from exc

    cases = manifest.get("cases")
    if not isinstance(cases, list):
        raise SystemExit(f"Scapy case manifest {path} must contain a cases list")

    by_name: dict[str, dict[str, Any]] = {}
    for case in cases:
        if not isinstance(case, dict):
            raise SystemExit(f"Scapy case manifest {path} contains a non-object case")
        name = case.get("name")
        if not isinstance(name, str) or not name:
            raise SystemExit(f"Scapy case manifest {path} contains an unnamed case")
        if name in by_name:
            raise SystemExit(f"duplicate Scapy case name in manifest: {name}")
        by_name[name] = case

    manifest["cases_by_name"] = by_name
    return manifest


CASE_DATA = load_case_manifest()
CASE_MAP: dict[str, dict[str, Any]] = CASE_DATA["cases_by_name"]


def fixture_case(fixture: Fixture) -> dict[str, Any]:
    case = CASE_MAP.get(fixture.name)
    if case is None:
        raise SystemExit(
            f"fixture {fixture.name!r} has no metadata in {CASE_MANIFEST}"
        )
    return case


def validate_fixture_manifest() -> None:
    for fixture in FIXTURES:
        case = fixture_case(fixture)
        stack = case.get("expected_stack")
        if stack != fixture.stack:
            raise SystemExit(
                f"manifest expected_stack for {fixture.name!r} does not match "
                "the Scapy factory"
            )
        if case.get("direction") != "scapy_to_libcrafter":
            raise SystemExit(
                f"fixture {fixture.name!r} must be a scapy_to_libcrafter case"
            )


validate_fixture_manifest()


def decode_root(root: str, blob: bytes) -> Any:
    decoders = {
        "CookedLinux": CookedLinux,
        "Ether": Ether,
        "IP": IP,
        "IPv6": IPv6,
        "Loopback": Loopback,
        "Raw": Raw,
    }
    return decoders[root](blob)


def json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"hex": value.hex(), "ascii": value.decode("utf-8", "replace")}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, tuple):
        return [json_value(item) for item in value]
    if isinstance(value, list):
        return [json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    return str(value)


def packet_layers(packet: Any) -> list[dict[str, Any]]:
    layers: list[dict[str, Any]] = []
    current = packet
    while current and current.__class__.__name__ != "NoPayload":
        layers.append(
            {
                "name": current.__class__.__name__,
                "fields": {
                    str(key): json_value(value)
                    for key, value in sorted(current.fields.items())
                },
            }
        )
        current = current.payload
    return layers


def packet_fields(layers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"layer": layer["name"], "fields": layer["fields"]}
        for layer in layers
    ]


def write_fixture(out_dir: Path, fixture: Fixture) -> None:
    case = fixture_case(fixture)
    packet = fixture.factory()
    blob = bytes(raw(packet))
    decoded = decode_root(fixture.scapy_root, blob)
    layers = packet_layers(decoded)
    layer_names = [layer["name"] for layer in layers]

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{fixture.name}.bin").write_bytes(blob)
    metadata = {
        "name": fixture.name,
        "description": fixture.description,
        "family": case["family"],
        "direction": case["direction"],
        "root": case["root"],
        "root_decoder": case["root"],
        "scapy_root": fixture.scapy_root,
        "scapy_version": SCAPY_VERSION,
        "expected_stack": case["expected_stack"],
        "strict_bytes": case["strict_bytes"],
        "status": case.get("status"),
        "notes": case.get("notes"),
        "length": len(blob),
        "hex": blob.hex(),
        "decoded_summary": decoded.summary(),
        "summary": decoded.summary(),
        "layer_names": layer_names,
        "relevant_fields": packet_fields(layers),
        "layers": layers,
        "scapy_show": decoded.show(dump=True),
    }
    (out_dir / f"{fixture.name}.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def split_filters(values: list[str]) -> list[str]:
    filters: list[str] = []
    for raw_value in values:
        for value in raw_value.split(","):
            normalized = value.strip()
            if normalized:
                filters.append(normalized)
    return filters


def validate_filters(kind: str, requested: list[str], known: set[str]) -> None:
    unknown = sorted(set(requested) - known)
    if unknown:
        raise SystemExit(
            f"unknown {kind}(s): {', '.join(unknown)}. known: {', '.join(sorted(known))}"
        )


def selected_fixtures(
    names: list[str],
    families: list[str],
    directions: list[str],
    base_fixtures: list[Fixture] | None = None,
) -> list[Fixture]:
    requested_families = split_filters(families)
    requested_directions = split_filters(directions)
    validate_filters(
        "family",
        requested_families,
        {str(case["family"]) for case in CASE_MAP.values()},
    )
    validate_filters(
        "direction",
        requested_directions,
        {str(case["direction"]) for case in CASE_MAP.values()},
    )

    if not names:
        selected = list(base_fixtures or FIXTURES)
    else:
        selected = []
        unknown: list[str] = []
        for name in split_filters(names):
            fixture = FIXTURE_MAP.get(name)
            if fixture is None:
                unknown.append(name)
            else:
                selected.append(fixture)

        if unknown:
            known = ", ".join(sorted(FIXTURE_MAP))
            raise SystemExit(f"unknown fixture(s): {', '.join(unknown)}. known: {known}")

    if requested_families:
        selected = [
            fixture
            for fixture in selected
            if fixture_case(fixture)["family"] in requested_families
        ]
    if requested_directions:
        selected = [
            fixture
            for fixture in selected
            if fixture_case(fixture)["direction"] in requested_directions
        ]

    return selected


def checked_in_fixtures() -> list[Fixture]:
    return [
        fixture
        for fixture in FIXTURES
        if fixture_case(fixture).get("status") == "implemented"
    ]


def default_output_dir() -> Path:
    return SCAPY_FIXTURE_DIR


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate deterministic Scapy reference fixtures."
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=default_output_dir(),
        help="output directory for .bin and .json fixtures",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="NAME",
        help="fixture name to generate; can be passed multiple times or comma-separated",
    )
    parser.add_argument(
        "--family",
        action="append",
        default=[],
        metavar="FAMILY",
        help="fixture family filter; can be passed multiple times or comma-separated",
    )
    parser.add_argument(
        "--direction",
        action="append",
        default=[],
        metavar="DIRECTION",
        help="fixture direction filter; can be passed multiple times or comma-separated",
    )
    parser.add_argument(
        "--check-drift",
        action="store_true",
        help=(
            "generate fixtures in a temporary directory and compare them with "
            "checked-in fixtures"
        ),
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="list available fixtures and exit",
    )
    return parser.parse_args()


def compare_files(generated: Path, expected: Path) -> str | None:
    if not expected.exists():
        return f"missing checked-in fixture: {expected}"
    generated_bytes = generated.read_bytes()
    expected_bytes = expected.read_bytes()
    if generated_bytes != expected_bytes:
        return f"drift detected: {expected}"
    return None


def check_drift(fixtures: list[Fixture]) -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="libcrafter-scapy-fixtures-") as tmp:
        out_dir = Path(tmp)
        for fixture in fixtures:
            write_fixture(out_dir, fixture)
            for suffix in (".bin", ".json"):
                generated = out_dir / f"{fixture.name}{suffix}"
                expected = SCAPY_FIXTURE_DIR / f"{fixture.name}{suffix}"
                failure = compare_files(generated, expected)
                if failure is not None:
                    failures.append(failure)

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print(f"checked {len(fixtures)} Scapy fixture(s); no drift detected")
    return 0


def main() -> int:
    args = parse_args()

    if args.check_drift and not args.only:
        fixtures = selected_fixtures(
            args.only,
            args.family,
            args.direction,
            base_fixtures=checked_in_fixtures(),
        )
    else:
        fixtures = selected_fixtures(args.only, args.family, args.direction)

    if args.list:
        for fixture in fixtures:
            print(f"{fixture.name}\t{fixture.description}")
        return 0

    if args.check_drift:
        return check_drift(fixtures)

    for fixture in fixtures:
        write_fixture(args.out, fixture)
        print(f"wrote {args.out / (fixture.name + '.bin')}")
        print(f"wrote {args.out / (fixture.name + '.json')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
