#!/usr/bin/env python3
"""Validate bidirectional pcap agreement between Scapy and crafter-pcap."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any


def import_scapy() -> dict[str, Any]:
    try:
        import scapy  # type: ignore[import-untyped]
        from scapy.all import (  # type: ignore[import-untyped]
            ARP,
            BOOTP,
            DHCP,
            DNS,
            DNSQR,
            Ether,
            ICMPv6EchoRequest,
            IP,
            IPv6,
            Raw,
            UDP,
            conf,
            raw,
            rdpcap,
            wrpcap,
        )
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
        "Ether": Ether,
        "ICMPv6EchoRequest": ICMPv6EchoRequest,
        "IP": IP,
        "IPv6": IPv6,
        "Raw": Raw,
        "UDP": UDP,
        "raw": raw,
        "rdpcap": rdpcap,
        "version": getattr(scapy, "__version__", "unknown"),
        "wrpcap": wrpcap,
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
            "error: scapy is not installed. Install scapy or install uv so this "
            "pcap validator can bootstrap scapy without root.",
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
Ether = SCAPY["Ether"]
ICMPv6EchoRequest = SCAPY["ICMPv6EchoRequest"]
IP = SCAPY["IP"]
IPv6 = SCAPY["IPv6"]
Raw = SCAPY["Raw"]
UDP = SCAPY["UDP"]
raw = SCAPY["raw"]
rdpcap = SCAPY["rdpcap"]
SCAPY_VERSION = SCAPY["version"]
wrpcap = SCAPY["wrpcap"]

REPO_ROOT = Path(__file__).resolve().parents[2]

SRC_MAC = "02:00:5e:00:53:01"
DST_MAC = "02:00:5e:00:53:02"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
SRC_IPV4 = "192.0.2.10"
DST_IPV4 = "198.51.100.20"
GW_IPV4 = "192.0.2.1"
DNS_IPV4 = "198.51.100.53"
SRC_IPV6 = "2001:db8:1::10"
DST_IPV6 = "2001:db8:2::20"


class ValidationError(Exception):
    pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--direction",
        action="append",
        default=[],
        help="scapy_to_libcrafter, libcrafter_to_scapy, or both",
    )
    args = parser.parse_args()

    directions = split_directions(args.direction)
    args.out.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {
        "scapy_version": SCAPY_VERSION,
        "directions": sorted(directions),
    }

    if "scapy_to_libcrafter" in directions:
        report["scapy_to_libcrafter"] = run_scapy_to_libcrafter(args.out)
    if "libcrafter_to_scapy" in directions:
        report["libcrafter_to_scapy"] = run_libcrafter_to_scapy(args.out)

    (args.out / "pcap-interop-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("pcap interop checks passed")


def split_directions(values: list[str]) -> set[str]:
    if not values:
        return {"scapy_to_libcrafter", "libcrafter_to_scapy"}

    out: set[str] = set()
    for raw_value in values:
        for value in raw_value.split(","):
            normalized = value.strip()
            if not normalized:
                continue
            if normalized == "both":
                out.update({"scapy_to_libcrafter", "libcrafter_to_scapy"})
            elif normalized in {"scapy_to_libcrafter", "libcrafter_to_scapy"}:
                out.add(normalized)
            else:
                raise SystemExit(f"unknown pcap direction: {normalized}")
    if not out:
        raise SystemExit("no pcap directions selected")
    return out


def run_scapy_to_libcrafter(out_dir: Path) -> dict[str, Any]:
    cases = build_scapy_cases()
    pcap_path = out_dir / "scapy-reference.pcap"
    expected_hex_path = out_dir / "scapy-reference.hex.tsv"

    packets = []
    expected_rows = []
    for index, case in enumerate(cases):
        packet = case["packet"]
        packet.time = index + 1
        packets.append(packet)
        expected_rows.append(f"{case['name']}\t{raw(packet).hex()}\n")

    wrpcap(str(pcap_path), packets)
    expected_hex_path.write_text("".join(expected_rows), encoding="utf-8")

    result = run_rust_pcap_example(
        "--read-scapy",
        str(pcap_path),
        "--expected-hex",
        str(expected_hex_path),
    )

    return {
        "pcap": str(pcap_path),
        "expected_hex": str(expected_hex_path),
        "rust_stdout": result.stdout.splitlines(),
    }


def run_libcrafter_to_scapy(out_dir: Path) -> dict[str, Any]:
    pcap_path = out_dir / "libcrafter-reference.pcap"
    result = run_rust_pcap_example("--write-libcrafter", str(pcap_path))
    expected = parse_libcrafter_manifest(result.stdout)

    packets = list(rdpcap(str(pcap_path)))
    if len(packets) != len(expected):
        raise ValidationError(
            f"libcrafter pcap packet count mismatch expected={len(expected)} actual={len(packets)}"
        )

    for packet, case in zip(packets, expected):
        actual_hex = raw(packet).hex()
        if actual_hex != case["hex"]:
            raise ValidationError(f"{case['name']}: Scapy-read pcap bytes differ")

        actual_layers = packet_layers(packet)
        if actual_layers != case["layers"]:
            raise ValidationError(
                f"{case['name']}: Scapy layer mismatch "
                f"expected={case['layers']!r} actual={actual_layers!r}"
            )

    return {
        "pcap": str(pcap_path),
        "cases": expected,
    }


def build_scapy_cases() -> list[dict[str, Any]]:
    return [
        {
            "name": "scapy-ethernet",
            "packet": Ether(src=SRC_MAC, dst=DST_MAC, type=0x9000)
            / Raw(b"scapy-pcap-ethernet"),
        },
        {
            "name": "scapy-arp-request",
            "packet": Ether(src=SRC_MAC, dst=BROADCAST_MAC, type=0x0806)
            / ARP(
                hwtype=1,
                ptype=0x0800,
                hwlen=6,
                plen=4,
                op=1,
                hwsrc=SRC_MAC,
                psrc=SRC_IPV4,
                hwdst=ZERO_MAC,
                pdst=GW_IPV4,
            ),
        },
        {
            "name": "scapy-ipv4-udp",
            "packet": Ether(src=SRC_MAC, dst=DST_MAC, type=0x0800)
            / IP(src=SRC_IPV4, dst=DST_IPV4, id=0x3101, ttl=61)
            / UDP(sport=53010, dport=53011)
            / Raw(b"scapy-pcap-ipv4"),
        },
        {
            "name": "scapy-ipv6-icmp",
            "packet": Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD)
            / IPv6(src=SRC_IPV6, dst=DST_IPV6, fl=0x23456, hlim=62)
            / ICMPv6EchoRequest(id=0x4244, seq=4)
            / Raw(b"scapy-pcap-ipv6"),
        },
        {
            "name": "scapy-dns-query",
            "packet": Ether(src=SRC_MAC, dst=DST_MAC, type=0x0800)
            / IP(src=SRC_IPV4, dst=DNS_IPV4, id=0x3102, ttl=62)
            / UDP(sport=53012, dport=53)
            / DNS(id=0xBEEF, rd=1, qd=DNSQR(qname="pcap.example.", qtype="A")),
        },
        {
            "name": "scapy-dhcp-discover",
            "packet": Ether(src=SRC_MAC, dst=BROADCAST_MAC, type=0x0800)
            / IP(src="0.0.0.0", dst="255.255.255.255", id=0x3103, ttl=64)
            / UDP(sport=68, dport=67)
            / BOOTP(
                op=1,
                htype=1,
                hlen=6,
                xid=0x3903F326,
                flags=0x8000,
                chaddr=mac_bytes(SRC_MAC) + (b"\x00" * 10),
            )
            / DHCP(
                options=[
                    ("message-type", "discover"),
                    ("hostname", "scapy-pcap"),
                    ("param_req_list", [1, 3, 6, 15]),
                    "end",
                ]
            ),
        },
    ]


def run_rust_pcap_example(*args: str) -> subprocess.CompletedProcess[str]:
    command = [
        "cargo",
        "run",
        "-q",
        "-p",
        "crafter-pcap",
        "--example",
        "scapy_interop_pcap",
        "--",
        *args,
    ]
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def parse_libcrafter_manifest(stdout: str) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            raise ValidationError(f"unexpected libcrafter pcap manifest row: {line!r}")
        name, packet_hex, layer_csv = parts
        layers = [layer for layer in layer_csv.split(",") if layer]
        cases.append({"name": name, "hex": packet_hex, "layers": layers})
    if not cases:
        raise ValidationError("libcrafter pcap writer emitted no manifest rows")
    return cases


def packet_layers(packet: Any) -> list[str]:
    layers: list[str] = []
    current = packet
    while current and current.__class__.__name__ != "NoPayload":
        layers.append(current.__class__.__name__)
        current = current.payload
    return layers


def mac_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, ValidationError) as exc:
        if isinstance(exc, subprocess.CalledProcessError):
            print("rust pcap interop command failed", file=sys.stderr)
            if exc.stdout:
                print(exc.stdout, file=sys.stderr)
            if exc.stderr:
                print(exc.stderr, file=sys.stderr)
        else:
            print(f"pcap validation failed: {exc}", file=sys.stderr)
        sys.exit(1)
