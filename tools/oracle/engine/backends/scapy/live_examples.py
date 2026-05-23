"""Legacy Scapy-backed live example smoke helpers.

These commands preserve the old `tests/live` smoke behavior while keeping
Scapy packet recipes inside the oracle Scapy backend. They are examples, not
oracle validation contracts.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .bootstrap import import_scapy


CASE_NAMES = (
    "loopback-icmp-bytes",
    "loopback-icmp-live",
    "loopback-udp-tcp-bytes",
    "loopback-udp-tcp-live",
    "veth-arp-bytes",
    "veth-arp-live",
    "dns-local-bytes",
    "dns-local-live",
    "pcap-generate-live-pcap",
)


def run_case(
    *,
    case_name: str,
    suite_dir: Path,
    host_if: str | None = None,
    host_mac: str | None = None,
) -> int:
    """Run one legacy Scapy example helper."""

    suite_dir.mkdir(parents=True, exist_ok=True)
    handlers: dict[str, Callable[[Path, argparse.Namespace], None]] = {
        "loopback-icmp-bytes": _loopback_icmp_bytes,
        "loopback-icmp-live": _loopback_icmp_live,
        "loopback-udp-tcp-bytes": _loopback_udp_tcp_bytes,
        "loopback-udp-tcp-live": _loopback_udp_tcp_live,
        "veth-arp-bytes": _veth_arp_bytes,
        "veth-arp-live": _veth_arp_live,
        "dns-local-bytes": _dns_local_bytes,
        "dns-local-live": _dns_local_live,
        "pcap-generate-live-pcap": _pcap_generate_live_pcap,
    }
    args = argparse.Namespace(host_if=host_if, host_mac=host_mac)
    handlers[case_name](suite_dir, args)
    return 0


def _scapy() -> Any:
    return import_scapy()["all"]


def _write_json(path: Path, data: object) -> None:
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _loopback_icmp_bytes(suite_dir: Path, _args: argparse.Namespace) -> None:
    scapy = _scapy()
    packet = (
        scapy.IP(src="127.0.0.1", dst="127.0.0.1")
        / scapy.ICMP(id=0x4321, seq=7)
        / scapy.Raw(b"libcrafter-live-icmp")
    )
    out = suite_dir / "scapy-icmp.hex"
    out.write_text(scapy.raw(packet).hex() + "\n", encoding="utf-8")
    print(f"wrote={out}")


def _loopback_icmp_live(suite_dir: Path, _args: argparse.Namespace) -> None:
    scapy = _scapy()
    scapy.conf.verb = 0
    packet = (
        scapy.IP(src="127.0.0.1", dst="127.0.0.1")
        / scapy.ICMP(id=0x4321, seq=7)
        / scapy.Raw(b"libcrafter-live-icmp")
    )
    reply = scapy.sr1(packet, timeout=2)
    if reply is None:
        raise SystemExit("no ICMP reply captured by Scapy")
    scapy.wrpcap(str(suite_dir / "scapy-icmp.pcap"), [packet, reply])
    _write_json(
        suite_dir / "scapy-icmp.json",
        {"sent": packet.summary(), "reply": reply.summary()},
    )
    print("scapy_icmp=ok")


def _loopback_udp_tcp_bytes(suite_dir: Path, _args: argparse.Namespace) -> None:
    scapy = _scapy()
    packets = {
        "udp": (
            scapy.IP(src="127.0.0.1", dst="127.0.0.1")
            / scapy.UDP(sport=40100, dport=18181)
            / scapy.Raw(b"libcrafter-live-udp")
        ),
        "tcp": (
            scapy.IP(src="127.0.0.1", dst="127.0.0.1")
            / scapy.TCP(sport=40101, dport=18080, flags="S", seq=0x10203040)
        ),
    }
    _write_json(
        suite_dir / "scapy-udp-tcp.json",
        {
            name: {"summary": packet.summary(), "hex": scapy.raw(packet).hex()}
            for name, packet in packets.items()
        },
    )
    print("scapy_udp_tcp_bytes=ok")


def _loopback_udp_tcp_live(suite_dir: Path, _args: argparse.Namespace) -> None:
    scapy = _scapy()
    scapy.conf.verb = 0
    tcp_probe = (
        scapy.IP(dst="127.0.0.1")
        / scapy.TCP(sport=40101, dport=18080, flags="S", seq=0x10203040)
    )
    tcp_reply = scapy.sr1(tcp_probe, timeout=2)
    udp_probe = (
        scapy.IP(dst="127.0.0.1")
        / scapy.UDP(sport=40102, dport=18182)
        / scapy.Raw(b"libcrafter-live-udp")
    )
    scapy.send(udp_probe, verbose=False)
    _write_json(
        suite_dir / "scapy-udp-tcp.json",
        {
            "tcp_probe": tcp_probe.summary(),
            "tcp_reply": tcp_reply.summary() if tcp_reply is not None else None,
            "udp_probe": udp_probe.summary(),
        },
    )
    if tcp_reply is None:
        raise SystemExit("no TCP loopback response captured by Scapy")
    print("scapy_udp_tcp=ok")


def _veth_arp_bytes(suite_dir: Path, _args: argparse.Namespace) -> None:
    scapy = _scapy()
    packet = scapy.Ether(
        src="02:00:5e:00:53:01",
        dst="ff:ff:ff:ff:ff:ff",
    ) / scapy.ARP(
        op=1,
        hwsrc="02:00:5e:00:53:01",
        psrc="10.200.32.1",
        hwdst="00:00:00:00:00:00",
        pdst="10.200.32.2",
    )
    _write_json(
        suite_dir / "scapy-arp.json",
        {"summary": packet.summary(), "hex": scapy.raw(packet).hex()},
    )
    print("scapy_arp_bytes=ok")


def _veth_arp_live(suite_dir: Path, args: argparse.Namespace) -> None:
    if not args.host_if:
        raise SystemExit("--host-if is required for veth-arp-live")
    if not args.host_mac:
        raise SystemExit("--host-mac is required for veth-arp-live")

    scapy = _scapy()
    scapy.conf.verb = 0
    request = scapy.Ether(
        src=args.host_mac,
        dst="ff:ff:ff:ff:ff:ff",
    ) / scapy.ARP(
        op=1,
        hwsrc=args.host_mac,
        psrc="10.200.32.1",
        hwdst="00:00:00:00:00:00",
        pdst="10.200.32.2",
    )
    reply = scapy.srp1(request, iface=args.host_if, timeout=2)
    if reply is None:
        raise SystemExit("no ARP reply captured by Scapy")
    _write_json(
        suite_dir / "scapy-arp.json",
        {"request": request.summary(), "reply": reply.summary()},
    )
    print("scapy_arp=ok")


def _dns_local_bytes(suite_dir: Path, _args: argparse.Namespace) -> None:
    scapy = _scapy()
    packet = (
        scapy.IP(src="127.0.0.1", dst="127.0.0.1")
        / scapy.UDP(sport=53010, dport=53)
        / scapy.DNS(
            id=0x1234,
            rd=1,
            qd=scapy.DNSQR(qname="example.test.", qtype="A"),
        )
    )
    _write_json(
        suite_dir / "scapy-dns.json",
        {"summary": packet.summary(), "hex": scapy.raw(packet).hex()},
    )
    print("scapy_dns_bytes=ok")


def _dns_local_live(suite_dir: Path, _args: argparse.Namespace) -> None:
    scapy = _scapy()
    scapy.conf.verb = 0
    query = (
        scapy.IP(dst="127.0.0.1")
        / scapy.UDP(sport=53011, dport=53)
        / scapy.DNS(
            id=0x5150,
            rd=1,
            qd=scapy.DNSQR(qname="example.test.", qtype="A"),
        )
    )
    reply = scapy.sr1(query, timeout=2)
    if reply is None:
        raise SystemExit("no DNS reply captured by Scapy")
    _write_json(
        suite_dir / "scapy-dns.json",
        {"query": query.summary(), "reply": reply.summary()},
    )
    print("scapy_dns=ok")


def _pcap_generate_live_pcap(suite_dir: Path, _args: argparse.Namespace) -> None:
    scapy = _scapy()
    scapy.conf.verb = 0
    packet = (
        scapy.IP(dst="127.0.0.1")
        / scapy.ICMP(id=0x5151, seq=9)
        / scapy.Raw(b"libcrafter-live-pcap")
    )
    scapy.send(packet, verbose=False)
    print("sent=icmp-loopback")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run legacy Scapy-backed live example smoke helpers.",
    )
    parser.add_argument("--case", choices=CASE_NAMES, required=True)
    parser.add_argument("--suite-dir", type=Path, required=True)
    parser.add_argument("--host-if")
    parser.add_argument("--host-mac")
    args = parser.parse_args(argv)
    return run_case(
        case_name=args.case,
        suite_dir=args.suite_dir,
        host_if=args.host_if,
        host_mac=args.host_mac,
    )


if __name__ == "__main__":
    raise SystemExit(main())
