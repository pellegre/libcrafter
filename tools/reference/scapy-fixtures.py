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
            load_contrib,
            Raw,
            TCP,
            UDP,
            conf,
            raw,
        )
        from scapy.layers.inet6 import (  # type: ignore[import-untyped]
            ICMPv6DestUnreach,
            ICMPv6EchoReply,
            ICMPv6EchoRequest,
            ICMPv6PacketTooBig,
            ICMPv6ParamProblem,
            ICMPv6TimeExceeded,
            IPv6ExtHdrFragment,
            IPv6ExtHdrRouting,
            IPv6ExtHdrSegmentRouting,
        )
        from scapy.layers.l2 import CookedLinux, Loopback  # type: ignore[import-untyped]
        load_contrib("mpls")
        from scapy.contrib.mpls import (  # type: ignore[import-untyped]
            ICMPExtension_MPLS,
            MPLS,
        )
        from scapy.layers.inet import ICMPExtension_Header  # type: ignore[import-untyped]
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
        "ICMPExtension_Header": ICMPExtension_Header,
        "ICMPExtension_MPLS": ICMPExtension_MPLS,
        "ICMPv6DestUnreach": ICMPv6DestUnreach,
        "ICMPv6EchoReply": ICMPv6EchoReply,
        "ICMPv6EchoRequest": ICMPv6EchoRequest,
        "ICMPv6PacketTooBig": ICMPv6PacketTooBig,
        "ICMPv6ParamProblem": ICMPv6ParamProblem,
        "ICMPv6TimeExceeded": ICMPv6TimeExceeded,
        "IP": IP,
        "IPOption": IPOption,
        "IPv6": IPv6,
        "IPv6ExtHdrFragment": IPv6ExtHdrFragment,
        "IPv6ExtHdrRouting": IPv6ExtHdrRouting,
        "IPv6ExtHdrSegmentRouting": IPv6ExtHdrSegmentRouting,
        "Loopback": Loopback,
        "MPLS": MPLS,
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
ICMPExtension_Header = SCAPY["ICMPExtension_Header"]
ICMPExtension_MPLS = SCAPY["ICMPExtension_MPLS"]
ICMPv6DestUnreach = SCAPY["ICMPv6DestUnreach"]
ICMPv6EchoReply = SCAPY["ICMPv6EchoReply"]
ICMPv6EchoRequest = SCAPY["ICMPv6EchoRequest"]
ICMPv6PacketTooBig = SCAPY["ICMPv6PacketTooBig"]
ICMPv6ParamProblem = SCAPY["ICMPv6ParamProblem"]
ICMPv6TimeExceeded = SCAPY["ICMPv6TimeExceeded"]
IP = SCAPY["IP"]
IPOption = SCAPY["IPOption"]
IPv6 = SCAPY["IPv6"]
IPv6ExtHdrFragment = SCAPY["IPv6ExtHdrFragment"]
IPv6ExtHdrRouting = SCAPY["IPv6ExtHdrRouting"]
IPv6ExtHdrSegmentRouting = SCAPY["IPv6ExtHdrSegmentRouting"]
Loopback = SCAPY["Loopback"]
MPLS = SCAPY["MPLS"]
Raw = SCAPY["Raw"]
TCP = SCAPY["TCP"]
UDP = SCAPY["UDP"]
raw = SCAPY["raw"]
SCAPY_VERSION = SCAPY["version"]

REPO_ROOT = Path(__file__).resolve().parents[2]
SCAPY_FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "scapy"
ORACLE_FIXTURE_DIR = REPO_ROOT / "target" / "oracle" / "fixtures"
CASE_MANIFEST = REPO_ROOT / "tools" / "oracle" / "specs" / "fixtures" / "scapy-cases.json"
CHECKED_IN_CASE_MANIFEST = SCAPY_FIXTURE_DIR / "cases.json"

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
FieldFactory = Callable[[list[dict[str, Any]]], list[dict[str, Any]]]


class Fixture:
    def __init__(
        self,
        name: str,
        description: str,
        scapy_root: str,
        stack: list[str],
        factory: PacketFactory,
        field_factory: FieldFactory | None = None,
    ) -> None:
        self.name = name
        self.description = description
        self.scapy_root = scapy_root
        self.stack = stack
        self.factory = factory
        self.field_factory = field_factory


def mac_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def pattern_payload(length: int, seed: int = 0) -> bytes:
    return bytes((seed + index) % 251 for index in range(length))


def quoted_ipv4_udp(payload: bytes = b"quoted") -> bytes:
    return bytes(
        raw(
            IP(src="5.6.7.8", dst="10.11.12.13", id=0x5151, ttl=32)
            / UDP(sport=5300, dport=1111)
            / Raw(payload)
        )
    )


def quoted_ipv6_udp(payload: bytes = b"quoted-v6") -> bytes:
    return bytes(
        raw(
            IPv6(src="2001:db8:feed::1", dst="2001:db8:feed::2", hlim=31)
            / UDP(sport=5301, dport=1112)
            / Raw(payload)
        )
    )


def field_subset(*specs: tuple[str, list[str]]) -> FieldFactory:
    def build(layers: list[dict[str, Any]]) -> list[dict[str, Any]]:
        occurrences: dict[str, int] = {}
        selected: list[dict[str, Any]] = []
        for layer_name, field_names in specs:
            occurrence = occurrences.get(layer_name, 0)
            matching = [layer for layer in layers if layer["name"] == layer_name]
            if occurrence >= len(matching):
                raise SystemExit(f"missing generated Scapy layer {layer_name}")
            occurrences[layer_name] = occurrence + 1
            fields = matching[occurrence]["fields"]
            selected.append(
                {
                    "layer": layer_name,
                    "fields": {
                        name: fields[name]
                        for name in field_names
                        if name in fields
                    },
                }
            )
        return selected

    return build


def outer_ipv4_icmp_fields() -> FieldFactory:
    return field_subset(("IP", ["version", "ihl", "len", "proto", "src", "dst"]), ("ICMP", ["type", "code", "chksum"]))


def outer_ipv6_icmp_fields(layer_name: str) -> FieldFactory:
    return field_subset(
        ("IPv6", ["version", "plen", "nh", "hlim", "src", "dst"]),
        (layer_name, ["type", "code", "cksum"]),
    )


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


def icmpv4_echo_reply_fixture() -> Any:
    return (
        IP(src=DST_IPV4, dst=SRC_IPV4, id=0x1260, ttl=64, flags="DF")
        / ICMP(type="echo-reply", id=0x4243, seq=3)
        / Raw(b"libcrafter-icmp-reply")
    )


def ipv4_udp_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1235, ttl=63)
        / UDP(sport=53000, dport=33434)
        / Raw(b"libcrafter-udp")
    )


def ipv4_udp_empty_payload_fixture() -> Any:
    return IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1250, ttl=63) / UDP(
        sport=53010,
        dport=33440,
    )


def ipv4_udp_odd_payload_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1251, ttl=63)
        / UDP(sport=53011, dport=33441)
        / Raw(b"odd")
    )


def ipv4_udp_max_payload_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1252, ttl=63)
        / UDP(sport=53012, dport=33442)
        / Raw(pattern_payload(1472, 7))
    )


def ipv4_udp_zero_checksum_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1253, ttl=63)
        / UDP(sport=53013, dport=33443, chksum=0)
        / Raw(b"zero-v4-udp")
    )


def ipv6_udp_empty_payload_fixture() -> Any:
    return IPv6(src=SRC_IPV6, dst=DST_IPV6, hlim=63) / UDP(
        sport=53014,
        dport=33444,
    )


def ipv6_udp_odd_payload_fixture() -> Any:
    return (
        IPv6(src=SRC_IPV6, dst=DST_IPV6, hlim=63)
        / UDP(sport=53015, dport=33445)
        / Raw(b"odd")
    )


def ipv6_udp_max_payload_fixture() -> Any:
    return (
        IPv6(src=SRC_IPV6, dst=DST_IPV6, hlim=63)
        / UDP(sport=53016, dport=33446)
        / Raw(pattern_payload(1452, 11))
    )


def ipv6_udp_computed_checksum_fixture() -> Any:
    return (
        IPv6(src=SRC_IPV6, dst=DST_IPV6, hlim=62)
        / UDP(sport=53017, dport=33447)
        / Raw(b"libcrafter-udp6")
    )


def ipv4_tcp_syn_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1236, ttl=62, flags="DF")
        / TCP(sport=40000, dport=80, flags="S", seq=0x01020304, window=64240)
    )


def tcp_syn_ack_fixture() -> Any:
    return (
        IP(src=DST_IPV4, dst=SRC_IPV4, id=0x1254, ttl=61, flags="DF")
        / TCP(
            sport=443,
            dport=40000,
            flags="SA",
            seq=0x01010101,
            ack=0x01020305,
            window=60000,
        )
    )


def tcp_fin_psh_ack_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1255, ttl=60, flags="DF")
        / TCP(
            sport=40001,
            dport=443,
            flags="FPA",
            seq=0x02030405,
            ack=0x11121314,
            window=32768,
        )
        / Raw(b"fin-psh-ack")
    )


def tcp_rst_empty_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1256, ttl=59, flags="DF")
        / TCP(sport=40002, dport=443, flags="R", seq=0x03040506, window=0)
    )


def tcp_all_flags_reserved_urgent_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1257, ttl=58, flags="DF")
        / TCP(
            sport=40003,
            dport=443,
            reserved=7,
            flags=0x1FF,
            seq=0x04050607,
            ack=0x21222324,
            window=4096,
            urgptr=0xBEEF,
            options=[("EOL", None)],
        )
        / Raw(b"all-flags")
    )


def tcp_raw_payload_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1258, ttl=57, flags="DF")
        / TCP(
            sport=40004,
            dport=8443,
            flags="PA",
            seq=0x05060708,
            ack=0x31323334,
            window=16384,
        )
        / Raw(b"tcp-raw-payload")
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


def tcp_options_eol_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x1259, ttl=56, flags="DF")
        / TCP(
            sport=40005,
            dport=443,
            flags="S",
            seq=0x06070809,
            options=[("EOL", None)],
        )
    )


def tcp_options_nop_padding_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x125A, ttl=55, flags="DF")
        / TCP(
            sport=40006,
            dport=443,
            flags="S",
            seq=0x0708090A,
            options=[("NOP", None), ("NOP", None), ("MSS", 1460)],
        )
    )


def tcp_options_sack_blocks_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x125B, ttl=54, flags="DF")
        / TCP(
            sport=40007,
            dport=443,
            flags="A",
            seq=0x08090A0B,
            ack=0x41424344,
            options=[
                (
                    "SAck",
                    (
                        0x11111111,
                        0x22222222,
                        0x33333333,
                        0x44444444,
                    ),
                )
            ],
        )
    )


def tcp_options_mptcp_fastopen_edo_generic_fixture() -> Any:
    return (
        IP(src=SRC_IPV4, dst=DST_IPV4, id=0x125C, ttl=53, flags="DF")
        / TCP(
            sport=40008,
            dport=443,
            flags="S",
            seq=0x090A0B0C,
            options=[
                (30, b"\x10\x01\x02"),
                ("TFO", b"\xde\xad"),
                (237, b""),
                (237, b"\x00\x10"),
                (237, b"\x00\x10\x00\x60"),
                (254, b"\xaa\xbb"),
            ],
        )
        / Raw(b"tcp-option-tail")
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
        "icmpv4-echo-reply",
        "IPv4 ICMP echo reply with raw payload.",
        "IP",
        ["IP", "ICMP", "Raw"],
        icmpv4_echo_reply_fixture,
    ),
    Fixture(
        "ipv4-udp",
        "IPv4 UDP datagram with raw payload.",
        "IP",
        ["IP", "UDP", "Raw"],
        ipv4_udp_fixture,
    ),
    Fixture(
        "udp-ipv6-checksum-length",
        "IPv6 UDP datagram with computed length and checksum.",
        "IPv6",
        ["IPv6", "UDP", "Raw"],
        ipv6_udp_computed_checksum_fixture,
    ),
    Fixture(
        "udp-ipv4-zero-checksum",
        "IPv4 UDP datagram with explicit zero checksum.",
        "IP",
        ["IP", "UDP", "Raw"],
        ipv4_udp_zero_checksum_fixture,
    ),
    Fixture(
        "ipv4-tcp-syn",
        "IPv4 TCP SYN packet.",
        "IP",
        ["IP", "TCP"],
        ipv4_tcp_syn_fixture,
    ),
    Fixture(
        "tcp-all-flags-reserved-offset",
        "IPv4 TCP packet with all flags, reserved bits, urgent pointer, and raw payload.",
        "IP",
        ["IP", "TCP", "Raw"],
        tcp_all_flags_reserved_urgent_fixture,
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
        field_subset(
            ("Ether", ["dst", "src", "type"]),
            ("IP", ["version", "ihl", "len", "proto", "src", "dst"]),
            ("UDP", ["sport", "dport", "len", "chksum"]),
            (
                "BOOTP",
                [
                    "op",
                    "htype",
                    "hlen",
                    "hops",
                    "xid",
                    "secs",
                    "flags",
                    "ciaddr",
                    "yiaddr",
                    "siaddr",
                    "giaddr",
                    "chaddr",
                    "options",
                ],
            ),
        ),
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
        "tcp-options-sack-blocks",
        "IPv4 TCP packet with SACK block option.",
        "IP",
        ["IP", "TCP"],
        tcp_options_sack_blocks_fixture,
    ),
    Fixture(
        "tcp-options-mptcp-fastopen-edo-generic",
        "IPv4 TCP packet with MPTCP, Fast Open, EDO, generic options, and raw payload.",
        "IP",
        ["IP", "TCP", "Raw"],
        tcp_options_mptcp_fastopen_edo_generic_fixture,
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
    relevant_fields = (
        fixture.field_factory(layers)
        if fixture.field_factory is not None
        else packet_fields(layers)
    )

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
        "relevant_fields": relevant_fields,
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
    checked_in = load_case_manifest(CHECKED_IN_CASE_MANIFEST)
    checked_in_names = [
        case["name"]
        for case in checked_in["cases"]
        if case.get("direction") == "scapy_to_libcrafter"
    ]
    missing = [name for name in checked_in_names if name not in FIXTURE_MAP]
    if missing:
        raise SystemExit(
            "checked-in fixture manifest references unknown fixture(s): "
            + ", ".join(missing)
        )
    return [FIXTURE_MAP[name] for name in checked_in_names]


def default_output_dir() -> Path:
    return ORACLE_FIXTURE_DIR


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
