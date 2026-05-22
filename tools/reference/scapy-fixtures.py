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
import subprocess
import sys
from typing import Any, Callable


def import_scapy() -> dict[str, Any]:
    try:
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
        from scapy.layers.inet6 import ICMPv6EchoRequest  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:
        if exc.name != "scapy":
            raise
        maybe_reexec_with_uv()
        raise

    conf.verb = 0
    return {
        "ARP": ARP,
        "BOOTP": BOOTP,
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
        "Raw": Raw,
        "TCP": TCP,
        "UDP": UDP,
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
Raw = SCAPY["Raw"]
TCP = SCAPY["TCP"]
UDP = SCAPY["UDP"]
raw = SCAPY["raw"]

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
        root: str,
        stack: list[str],
        factory: PacketFactory,
    ) -> None:
        self.name = name
        self.description = description
        self.root = root
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
            ],
        )
        / ICMP(type="echo-request", id=0x4243, seq=3)
        / Raw(b"ip-options")
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
        "IPv4 ICMP echo request with NOP and record-route options.",
        "IP",
        ["IP", "IPOption_NOP", "IPOption_RR", "ICMP", "Raw"],
        ipv4_options_fixture,
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
]

FIXTURE_MAP = {fixture.name: fixture for fixture in FIXTURES}


def decode_root(root: str, blob: bytes) -> Any:
    decoders = {
        "Ether": Ether,
        "IP": IP,
        "IPv6": IPv6,
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


def write_fixture(out_dir: Path, fixture: Fixture) -> None:
    packet = fixture.factory()
    blob = bytes(raw(packet))
    decoded = decode_root(fixture.root, blob)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{fixture.name}.bin").write_bytes(blob)
    metadata = {
        "name": fixture.name,
        "description": fixture.description,
        "root": fixture.root,
        "expected_stack": fixture.stack,
        "length": len(blob),
        "hex": blob.hex(),
        "summary": decoded.summary(),
        "layers": packet_layers(decoded),
        "scapy_show": decoded.show(dump=True),
    }
    (out_dir / f"{fixture.name}.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def selected_fixtures(names: list[str]) -> list[Fixture]:
    if not names:
        return FIXTURES

    selected: list[Fixture] = []
    unknown: list[str] = []
    for raw_name in names:
        for name in raw_name.split(","):
            normalized = name.strip()
            if not normalized:
                continue
            fixture = FIXTURE_MAP.get(normalized)
            if fixture is None:
                unknown.append(normalized)
            else:
                selected.append(fixture)

    if unknown:
        known = ", ".join(sorted(FIXTURE_MAP))
        raise SystemExit(f"unknown fixture(s): {', '.join(unknown)}. known: {known}")

    return selected


def default_output_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "scapy"


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
        "--list",
        action="store_true",
        help="list available fixtures and exit",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.list:
        for fixture in FIXTURES:
            print(f"{fixture.name}\t{fixture.description}")
        return 0

    fixtures = selected_fixtures(args.only)
    for fixture in fixtures:
        write_fixture(args.out, fixture)
        print(f"wrote {args.out / (fixture.name + '.bin')}")
        print(f"wrote {args.out / (fixture.name + '.json')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
