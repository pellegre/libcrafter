"""Live-case workload planning helpers.

This module hosts the IP-fragment workload planning that the live command
builds when running the ``ip-fragment-smoke`` profile. The functions reference
no monkeypatched ``cli`` helper and are themselves never patched by the
live-provider tests, so they can live outside :mod:`..main`. ``main``
re-imports the names below so ``cli._ip_fragment_workload_plan`` (and the
constant) remain available exactly as before.

UDP live-case selection (``_should_use_udp_live_case_selection``,
``_build_udp_live_case_corpus_report``, ``_udp_options_live_case_specs``)
intentionally stays in :mod:`..main`: ``_build_udp_live_case_corpus_report``
calls the monkeypatched ``_backend_versions``/``_libcrafter_info`` helpers and
the whole cluster reaches a web of ``main`` internals by bare name, so moving
it would break the live-provider tests' patch parity.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ...model import JSONObject, write_json

IP_FRAGMENT_SMOKE_PROFILE = "ip-fragment-smoke"


def _ip_fragment_workload_plan(
    args: argparse.Namespace,
    provider_adapter,
    *,
    dry_run: bool,
    output_dir: Path,
) -> JSONObject | None:
    if args.profile != IP_FRAGMENT_SMOKE_PROFILE:
        return None

    roles = list(getattr(provider_adapter, "endpoint_roles", ()))
    sender_role = "reference_backend" if "reference_backend" in roles else roles[0]
    receiver_role = "libcrafter" if "libcrafter" in roles else roles[-1]
    artifact_dir = output_dir / "artifacts" / IP_FRAGMENT_SMOKE_PROFILE
    capture_path = artifact_dir / "capture.pcap"
    payload_hash_path = artifact_dir / "payload-hashes.json"
    summary_path = artifact_dir / "ip-defrag-summary.json"
    mtu = 1280

    commands: list[JSONObject] = [
        {
            "name": "configure-small-mtu-sender",
            "role": sender_role,
            "description": "small MTU setup on the sending lab interface before oversized payload exchange",
            "argv": ["sudo", "ip", "link", "set", "dev", "{iface}", "mtu", str(mtu)],
            "sends_live_packets": False,
            "expects_live_packets": False,
        },
        {
            "name": "configure-small-mtu-receiver",
            "role": receiver_role,
            "description": "small MTU setup on the receiving lab interface before fragment capture",
            "argv": ["sudo", "ip", "link", "set", "dev", "{iface}", "mtu", str(mtu)],
            "sends_live_packets": False,
            "expects_live_packets": False,
        },
        {
            "name": "disable-offload-sender",
            "role": sender_role,
            "description": "offload disabling where supported: TSO, GSO, GRO, and LRO are disabled before sending",
            "argv": [
                "sh",
                "-lc",
                "command -v ethtool >/dev/null && sudo ethtool -K {iface} tso off gso off gro off lro off || true",
            ],
            "sends_live_packets": False,
            "expects_live_packets": False,
        },
        {
            "name": "disable-offload-receiver",
            "role": receiver_role,
            "description": "offload disabling where supported: receive aggregation is disabled before pcap capture",
            "argv": [
                "sh",
                "-lc",
                "command -v ethtool >/dev/null && sudo ethtool -K {iface} gro off lro off || true",
            ],
            "sends_live_packets": False,
            "expects_live_packets": False,
        },
        {
            "name": "capture-fragments",
            "role": receiver_role,
            "description": "pcap capture of IPv4 and IPv6 fragments on the constrained lab link",
            "argv": [
                "sudo",
                "tcpdump",
                "-i",
                "{iface}",
                "-s",
                "262144",
                "-w",
                str(capture_path),
                "ip or ip6",
            ],
            "sends_live_packets": False,
            "expects_live_packets": True,
        },
        {
            "name": "send-oversized-payload",
            "role": sender_role,
            "description": "send oversized ICMP or UDP payloads across the small MTU link so the provider kernel fragments them",
            "argv": [
                "tools/oracle/run",
                "live",
                "--backend",
                str(args.backend),
                "--profile",
                IP_FRAGMENT_SMOKE_PROFILE,
                "--provider",
                str(args.provider),
                "--confirm-live-run",
                "--count",
                str(args.count),
                "--seed",
                str(args.seed),
                "--out",
                str(artifact_dir / "live-report"),
            ],
            "sends_live_packets": True,
            "expects_live_packets": False,
        },
        {
            "name": "materialize-crafted-fragments",
            "role": sender_role,
            "description": "materialize oversized/crafted fragment traffic generated from deterministic IpFragment packet plans",
            "argv": [
                "cargo",
                "run",
                "-p",
                "crafter",
                "--example",
                "ip_fragment_offline",
            ],
            "sends_live_packets": False,
            "expects_live_packets": False,
        },
        {
            "name": "compare-payload-hash",
            "role": receiver_role,
            "description": "payload hash comparison between kernel-delivered packets and IpDefrag transform output",
            "argv": [
                "cargo",
                "run",
                "-p",
                "crafter",
                "--example",
                "ip_defrag_pcap_summary",
                "--",
                "--pcap",
                str(capture_path),
                "--out",
                str(summary_path),
            ],
            "sends_live_packets": False,
            "expects_live_packets": False,
        },
    ]
    return {
        "name": IP_FRAGMENT_SMOKE_PROFILE,
        "profile": IP_FRAGMENT_SMOKE_PROFILE,
        "provider": str(args.provider),
        "backend": str(args.backend),
        "seed": int(args.seed),
        "count": int(args.count),
        "dry_run": dry_run,
        "creates_infrastructure": False if dry_run else True,
        "no_live_packets_sent": dry_run,
        "workload_label": IP_FRAGMENT_SMOKE_PROFILE,
        "roles": {
            "sender": sender_role,
            "receiver": receiver_role,
        },
        "artifacts": {
            "root": str(artifact_dir),
            "pcap": str(capture_path),
            "payload_hashes": str(payload_hash_path),
            "summary": str(summary_path),
        },
        "steps": [
            "small MTU setup",
            "offload disabling where supported",
            "oversized/crafted fragment traffic",
            "pcap capture",
            "payload hash comparison",
        ],
        "commands": commands,
    }


def _write_ip_fragment_workload_plan(
    output_dir: Path,
    workload_plan: JSONObject | None,
) -> Path | None:
    if workload_plan is None:
        return None
    path = output_dir / "artifacts" / IP_FRAGMENT_SMOKE_PROFILE / "workload-plan.json"
    write_json(path, workload_plan)
    return path
