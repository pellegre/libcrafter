"""Command-line interface for probe validation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import shlex
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path

_REPO_ROOT_FOR_IMPORTS = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT_FOR_IMPORTS) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT_FOR_IMPORTS))

from tools.lab.engine.model import LabRequest, LabRole, LabSession
from tools.lab.engine import repo as lab_repo
from tools.lab.engine import session as lab_session_state
from tools.lab.engine import wire_client as lab_wire_client

from . import bootstrap as probe_bootstrap
from .lab import (
    LOCAL_DRY_RUN_PROVIDER,
    PROBE_LAB_ROLES,
    STIMULUS_ROLE,
    TARGET_ROLE,
    is_probe_lab_provider,
    probe_address_context_from_lab_session,
    probe_capabilities_for_provider,
    probe_capabilities_from_lab_capabilities,
    probe_provider_names,
    resolve_probe_lab_provider,
)
from .model import (
    EndpointRole,
    JSONObject,
    JSONValue,
    ObservedResponse,
    ProbeCase,
    ProbeReport,
    ProbeResult,
    ProbeRunRequest,
    ProbeSkip,
    json_object,
    write_json,
)
from .report import DEFAULT_OUTPUT_ROOT, REPO_ROOT


PROBE_SELECTED_SPECS = ("probe-contracts",)
SKIP_CAPABILITY_UNAVAILABLE = "provider_capability_unavailable"
SKIP_CONFIRMATION_REQUIRED = "confirm_live_run_required"
SKIP_REQUIRES_CONTROLLED_ROUTER = "requires_controlled_router"
SKIP_REQUIRES_LINK_LAYER = "requires_link_layer"
STATUS_DRY_RUN = "dry-run"
STATUS_FAILED = "failed"
STATUS_PASSED = "passed"
STATUS_UNSUPPORTED = "unsupported"
FAILURE_TIMEOUT = "timeout"
FAILURE_WRONG_PEER = "wrong_peer"
FAILURE_WRONG_PAYLOAD = "wrong_payload"
FAILURE_WRONG_FLAGS = "wrong_flags"
FAILURE_DECODE_FAILED = "decode_failed"
FAILURE_TARGET_SETUP_FAILED = "target_setup_failed"


_PROBE_CASES: tuple[ProbeCase, ...] = (
    ProbeCase(
        name="icmp-echo",
        description="Send ICMP echo request and validate echo reply from peer kernel.",
        stimulus="icmp_echo_request",
        expected_response="icmp_echo_reply",
        required_capabilities=["icmp_echo"],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "icmp", "service": "kernel"},
    ),
    ProbeCase(
        name="tcp-syn-open",
        description="Send TCP SYN to controlled listener and validate SYN/ACK.",
        stimulus="tcp_syn",
        expected_response="tcp_syn_ack",
        required_capabilities=["tcp_open_port"],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "tcp", "service": "controlled_listener"},
    ),
    ProbeCase(
        name="tcp-syn-closed",
        description="Send TCP SYN to closed port and validate RST response.",
        stimulus="tcp_syn",
        expected_response="tcp_rst",
        required_capabilities=["tcp_closed_port"],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "tcp", "service": "kernel"},
    ),
    ProbeCase(
        name="dns-query",
        description="Send DNS query to controlled DNS service and validate matching reply.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=["dns_service"],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "dns", "service": "controlled_dns"},
    ),
    ProbeCase(
        name="ttl-expired",
        description="Send low-TTL packet and validate ICMP TTL-expired from controlled hop.",
        stimulus="low_ttl_probe",
        expected_response="icmp_ttl_expired",
        required_capabilities=["controlled_router"],
        endpoint_roles=["stimulus", "router"],
        metadata={"protocol": "icmp", "service": "controlled_router"},
    ),
    ProbeCase(
        name="arp-resolution",
        description=(
            "Broadcast an ARP who-has request on the lab segment and validate the "
            "target's unicast is-at reply."
        ),
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=[
            "arp_resolution",
            "link_layer_send",
            "link_layer_capture",
            "broadcast",
        ],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "arp", "service": "kernel", "layer": "link"},
    ),
)
_PROBE_CASE_BY_NAME = {case.name: case for case in _PROBE_CASES}
_ENDPOINT_ROLES: tuple[EndpointRole, ...] = (
    EndpointRole(
        role="stimulus",
        responsibilities=["send_probe", "capture_response", "validate_response"],
        capabilities=["raw_send", "packet_capture"],
    ),
    EndpointRole(
        role="target",
        responsibilities=["expose_kernel_behavior", "run_controlled_services"],
        capabilities=["kernel_reply", "tcp_listener", "dns_service"],
    ),
    EndpointRole(
        role="router",
        responsibilities=["emit_ttl_expired"],
        capabilities=["controlled_router"],
    ),
)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tools/probe/run",
        description="Run libcrafter probe validation.",
    )
    parser.add_argument(
        "--provider",
        choices=probe_provider_names(),
        required=True,
        help="probe provider to use",
    )
    parser.add_argument(
        "--profile",
        default="smoke",
        help="probe sampling profile (default: %(default)s)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="deterministic probe selection seed (default: %(default)s)",
    )
    parser.add_argument(
        "--count",
        type=_positive_int,
        default=5,
        help="number of probe cases to plan (default: %(default)s)",
    )
    parser.add_argument(
        "--case",
        dest="case_names",
        action="append",
        help="probe case name to include; may be repeated or comma-separated",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="write a deterministic non-mutating probe plan and report",
    )
    parser.add_argument(
        "--confirm-live-run",
        action="store_true",
        help="confirm protected non-dry-run provider execution",
    )
    parser.add_argument(
        "--out",
        help="probe report output directory or report.json path",
    )
    return parser


def _run(args: argparse.Namespace) -> int:
    try:
        request = _request_from_args(args)
        selected_cases = _selected_cases(request.case_names)
        planned_cases = _planned_cases(
            selected_cases,
            seed=request.seed,
            count=request.count,
        )
        probe_plans = _probe_plans_for_cases(request, planned_cases)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    status = STATUS_DRY_RUN if request.dry_run else _live_status(request)
    report_path = _report_path(args.out, request=request, status=status)
    if request.dry_run:
        report = _dry_run_report(
            request=request,
            selected_cases=selected_cases,
            planned_cases=planned_cases,
            probe_plans=probe_plans,
            report_path=report_path,
        )
        write_json(report_path, report)
        print(
            f"probe: status={report.status} provider={request.provider} "
            f"planned={len(report.results)} report={report_path}"
        )
        return 0

    report = _guarded_live_report(
        request=request,
        selected_cases=selected_cases,
        planned_cases=planned_cases,
        probe_plans=probe_plans,
        report_path=report_path,
        status=status,
    )
    write_json(report_path, report)
    print(
        f"probe: status={report.status} provider={request.provider} "
        f"planned={len(report.results)} report={report_path}",
        file=sys.stderr,
    )
    return 0 if report.status == STATUS_PASSED else 2


def _request_from_args(args: argparse.Namespace) -> ProbeRunRequest:
    case_names = _case_name_filters(args.case_names)
    metadata: JSONObject = {
        "requested_count": args.count,
        "requested_cases": list(case_names),
        "selected_specs": list(PROBE_SELECTED_SPECS),
        "command": _requested_command(),
    }
    return ProbeRunRequest(
        provider=args.provider,
        profile=args.profile,
        seed=args.seed,
        count=args.count,
        case_names=case_names,
        dry_run=bool(args.dry_run),
        confirm_live_run=bool(args.confirm_live_run),
        out=args.out,
        metadata=metadata,
    )


def _case_name_filters(values: Sequence[str] | None) -> list[str]:
    if not values:
        return []
    names: list[str] = []
    for value in values:
        for raw_name in value.split(","):
            name = raw_name.strip()
            if name:
                names.append(name)
    return list(dict.fromkeys(names))


def _selected_cases(case_names: Sequence[str]) -> list[ProbeCase]:
    if not case_names:
        return list(_PROBE_CASES)
    unknown = [name for name in case_names if name not in _PROBE_CASE_BY_NAME]
    if unknown:
        available = ", ".join(sorted(_PROBE_CASE_BY_NAME))
        raise ValueError(
            f"unknown probe case {unknown[0]!r}; available cases: {available}"
        )
    return [_PROBE_CASE_BY_NAME[name] for name in case_names]


def _planned_cases(
    selected_cases: Sequence[ProbeCase],
    *,
    seed: int,
    count: int,
) -> list[ProbeCase]:
    if not selected_cases:
        return []
    offset = seed % len(selected_cases)
    ordered = [*selected_cases[offset:], *selected_cases[:offset]]
    return [ordered[index % len(ordered)] for index in range(count)]


def _probe_plans_for_cases(
    request: ProbeRunRequest,
    planned_cases: Sequence[ProbeCase],
) -> list[JSONObject]:
    return [
        _probe_plan_for_case(request=request, case=case, sequence=sequence)
        for sequence, case in enumerate(planned_cases)
    ]


def _probe_plan_for_case(
    *,
    request: ProbeRunRequest,
    case: ProbeCase,
    sequence: int,
) -> JSONObject:
    if case.name == "icmp-echo":
        return _icmp_echo_probe_plan(
            profile=request.profile,
            seed=request.seed,
            sequence=sequence,
        )
    if case.name in {"tcp-syn-open", "tcp-syn-closed"}:
        return _tcp_syn_probe_plan(
            case_name=case.name,
            profile=request.profile,
            seed=request.seed,
            sequence=sequence,
        )
    if case.name == "dns-query":
        return _dns_query_probe_plan(
            profile=request.profile,
            seed=request.seed,
            sequence=sequence,
        )
    if case.name == "ttl-expired":
        return _ttl_expired_probe_plan(
            profile=request.profile,
            seed=request.seed,
            sequence=sequence,
        )
    if case.name == "arp-resolution":
        return _arp_resolution_probe_plan(
            profile=request.profile,
            seed=request.seed,
            sequence=sequence,
        )
    return {
        "schema_version": 1,
        "case": case.name,
        "sequence": sequence,
        "index": sequence,
        "profile": request.profile,
        "seed": request.seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        "planned_only": True,
    }


def _icmp_echo_probe_plan(
    *,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = _deterministic_bytes("icmp-echo", profile, seed, sequence)
    identifier = int.from_bytes(digest[0:2], "big") or 1
    sequence_number = int.from_bytes(digest[2:4], "big")
    stimulus_ipv4, target_ipv4 = _deterministic_ipv4_pair(profile, seed, sequence)
    payload = (
        f"libcrafter-probe:icmp-echo:{profile}:{seed}:{sequence}:"
        f"{digest.hex()[:16]}"
    ).encode("ascii")
    return {
        "schema_version": 1,
        "case": "icmp-echo",
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "icmp_echo_request",
        "expected_response": "icmp_echo_reply",
        "identifier": identifier,
        "sequence_number": sequence_number,
        "payload_hex": payload.hex(),
        "payload_length": len(payload),
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "capture_filter": (
            f"icmp and src host {target_ipv4} and dst host {stimulus_ipv4}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "icmp_type": 0,
            "icmp_code": 0,
            "identifier": identifier,
            "sequence_number": sequence_number,
            "payload_hex": payload.hex(),
        },
    }


def _tcp_syn_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = _deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = _deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 61000 + int.from_bytes(digest[0:2], "big") % 4000
    destination_base = 18000 if case_name == "tcp-syn-open" else 22000
    destination_port = destination_base + int.from_bytes(digest[2:4], "big") % 3000
    sequence_number = int.from_bytes(digest[4:8], "big")
    expected_ack = (sequence_number + 1) & 0xFFFF_FFFF
    expected_response = "tcp_syn_ack" if case_name == "tcp-syn-open" else "tcp_rst"
    expected_flags = ["syn", "ack"] if case_name == "tcp-syn-open" else ["rst"]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "tcp_syn",
        "expected_response": expected_response,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_sequence_number": sequence_number,
        "expected_acknowledgment_number": expected_ack,
        "window": 64240,
        "target_service": {
            "required": case_name == "tcp-syn-open",
            "kind": "tcp-listener" if case_name == "tcp-syn-open" else "closed-port",
            "port": destination_port,
        },
        "stimulus_rst_guard": {
            "required": True,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": target_ipv4,
            "source_port": source_port,
            "destination_port": destination_port,
        },
        "capture_filter": (
            f"tcp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "flags": expected_flags,
            "acknowledgment_number": expected_ack,
            "allow_rst_ack": case_name == "tcp-syn-closed",
        },
    }


def _dns_query_probe_plan(
    *,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = _deterministic_bytes("dns-query", profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = _deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    query_type_value = 1 if sequence % 2 == 0 else 28
    query_type = "A" if query_type_value == 1 else "AAAA"
    query_name = _dns_query_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    if query_type == "A":
        answer_data = f"203.0.113.{1 + digest[4] % 250}"
    else:
        answer_data = (
            "2001:db8:"
            f"{int.from_bytes(digest[4:6], 'big'):x}:"
            f"{int.from_bytes(digest[6:8], 'big'):x}::"
            f"{1 + digest[8] % 65534:x}"
        )
    destination_port = 53
    answer_ttl = 60 + digest[9] % 180
    return {
        "schema_version": 1,
        "case": "dns-query",
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dns_query",
        "expected_response": "dns_response",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "query_id": query_id,
        "query_name": query_name,
        "query_type": query_type,
        "query_type_value": query_type_value,
        "query_class": "IN",
        "query_class_value": 1,
        "expected_answer_name": query_name,
        "expected_answer_type": query_type,
        "expected_answer_type_value": query_type_value,
        "expected_answer_data": answer_data,
        "expected_response_code": 0,
        "answer_ttl": answer_ttl,
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": query_name,
            "query_type": query_type,
            "answer_data": answer_data,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "query_id": query_id,
            "qr": True,
            "response_code": 0,
            "question": {
                "name": query_name,
                "type": query_type,
                "class": "IN",
            },
            "answer": {
                "name": query_name,
                "type": query_type,
                "data": answer_data,
                "ttl": answer_ttl,
            },
        },
    }


def _dns_query_name(*, profile: str, seed: int, sequence: int, digest: bytes) -> str:
    label = _dns_label(profile)
    suffix = digest.hex()[:10]
    return f"probe-{seed}-{sequence}-{suffix}.{label}.libcrafter.test."


def _ttl_expired_probe_plan(
    *,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = _deterministic_bytes("ttl-expired", profile, seed, sequence)
    stimulus_ipv4, destination_ipv4 = _deterministic_ipv4_pair(
        profile,
        seed,
        sequence,
    )
    router_ipv4 = _deterministic_router_ipv4(profile, seed, sequence)
    identifier = int.from_bytes(digest[0:2], "big") or 1
    sequence_number = int.from_bytes(digest[2:4], "big")
    payload = (
        f"libcrafter-probe:ttl-expired:{profile}:{seed}:{sequence}:"
        f"{digest.hex()[:16]}"
    ).encode("ascii")
    embedded_prefix_length = 28
    return {
        "schema_version": 1,
        "case": "ttl-expired",
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "low_ttl_probe",
        "expected_response": "icmp_ttl_expired",
        "ttl": 1,
        "identifier": identifier,
        "sequence_number": sequence_number,
        "payload_hex": payload.hex(),
        "payload_length": len(payload),
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": destination_ipv4,
        "controlled_router_ipv4": router_ipv4,
        "expected_reply_source_ipv4": router_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "expected_icmp_type": 11,
        "expected_icmp_code": 0,
        "expected_embedded_prefix_length": embedded_prefix_length,
        "capture_filter": (
            f"icmp and src host {router_ipv4} and dst host {stimulus_ipv4}"
        ),
        "validation": {
            "source_ipv4": router_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "icmp_type": 11,
            "icmp_code": 0,
            "embedded_prefix": {
                "source": "stimulus_sent_bytes",
                "length": embedded_prefix_length,
                "meaning": "original IPv4 header plus first eight bytes of payload",
            },
        },
    }


def _arp_resolution_probe_plan(
    *,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = _deterministic_bytes("arp-resolution", profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = _deterministic_ipv4_pair(profile, seed, sequence)
    stimulus_mac = _deterministic_documentation_mac(profile, seed, sequence, role="stimulus")
    target_mac = _deterministic_documentation_mac(profile, seed, sequence, role="target")
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    zero_mac = "00:00:00:00:00:00"
    return {
        "schema_version": 1,
        "case": "arp-resolution",
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "arp_who_has",
        "expected_response": "arp_is_at",
        # ARP rides Ethernet directly; these are link-layer documentation values.
        "ethertype": 0x0806,
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "hardware_length": 6,
        "protocol_length": 4,
        "operation": 1,
        "operation_label": "request",
        "sender_hardware_addr": stimulus_mac,
        "sender_protocol_addr": stimulus_ipv4,
        "target_hardware_addr": zero_mac,
        "target_protocol_addr": target_ipv4,
        "ethernet_source": stimulus_mac,
        "ethernet_destination": broadcast_mac,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        # ARP cannot be selected by host/IP BPF; match on the protocol + opcode.
        "capture_filter": "arp and arp[6:2] = 2",
        "validation": {
            "ethertype": 0x0806,
            "operation": 2,
            "operation_label": "reply",
            "sender_hardware_addr": target_mac,
            "sender_protocol_addr": target_ipv4,
            "target_hardware_addr": stimulus_mac,
            "target_protocol_addr": stimulus_ipv4,
            "ethernet_destination": stimulus_mac,
        },
        "wire_requirements": {
            "requires_link_layer_send": True,
            "requires_link_layer_capture": True,
            "requires_broadcast": True,
            "note": (
                "ARP resolution is L2 broadcast/unicast traffic; it runs only on a "
                "provider-backed lab segment, never from privileged host raw sends."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _deterministic_documentation_mac(
    profile: str,
    seed: int,
    sequence: int,
    *,
    role: str,
) -> str:
    digest = _deterministic_bytes(f"arp-mac-{role}", profile, seed, sequence)
    # RFC 7042 reserves 00:00:5e:00:53:00-ff for documentation unicast MACs.
    return f"00:00:5e:00:53:{digest[0]:02x}"


def _dns_label(value: str) -> str:
    label = "".join(char.lower() if char.isalnum() else "-" for char in value)
    label = "-".join(part for part in label.split("-") if part)
    return (label or "profile")[:32].strip("-") or "profile"


def _deterministic_bytes(case: str, profile: str, seed: int, sequence: int) -> bytes:
    material = f"{case}\0{profile}\0{seed}\0{sequence}".encode("utf-8")
    return hashlib.sha256(material).digest()


def _deterministic_ipv4_pair(profile: str, seed: int, sequence: int) -> tuple[str, str]:
    digest = _deterministic_bytes("endpoint-addresses", profile, seed, sequence)
    second = 64 + digest[0] % 64
    third = digest[1]
    return f"10.{second}.{third}.10", f"10.{second}.{third}.20"


def _deterministic_router_ipv4(profile: str, seed: int, sequence: int) -> str:
    digest = _deterministic_bytes("endpoint-addresses", profile, seed, sequence)
    second = 64 + digest[0] % 64
    third = digest[1]
    return f"10.{second}.{third}.1"


def _dry_run_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    report_path: Path,
) -> ProbeReport:
    provider_context: JSONObject = {}
    stimulus_endpoint: JSONObject = {}
    provider_capabilities = _probe_capabilities_for_request(request, dry_run=True)
    if is_probe_lab_provider(request.provider):
        lab_session = _probe_lab_dry_run_session(request)
        address_context = probe_address_context_from_lab_session(lab_session)
        stimulus_endpoint = _stimulus_endpoint_context(address_context)
        probe_plans = _probe_plans_with_lab_endpoint_addresses(
            probe_plans,
            address_context=address_context,
        )
        provider_capabilities = probe_capabilities_from_lab_capabilities(
            request.provider,
            lab_session.provider_capabilities,
            dry_run=True,
        )
        provider_context = _lab_session_probe_report_metadata(
            lab_session,
            address_context=address_context,
            provider_capabilities=provider_capabilities,
        )

    return _build_report(
        request=request,
        selected_cases=selected_cases,
        planned_cases=planned_cases,
        probe_plans=probe_plans,
        report_path=report_path,
        status=STATUS_DRY_RUN,
        dry_run=True,
        provider_context=provider_context,
        provider_capabilities=provider_capabilities,
        stimulus_endpoint=stimulus_endpoint,
    )


def _guarded_live_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    report_path: Path,
    status: str,
) -> ProbeReport:
    if is_probe_lab_provider(request.provider) and request.confirm_live_run:
        provider_capabilities = _probe_capabilities_for_request(request, dry_run=False)
        skipped_sequences = {
            sequence
            for sequence, case in enumerate(planned_cases)
            if _missing_capabilities(case, provider_capabilities)
        }
        executable_plans = [
            plan
            for plan in _stimulus_endpoint_plans(probe_plans)
            if int(plan.get("sequence", -1)) not in skipped_sequences
        ]
        unsupported = [
            case.name
            for sequence, case in enumerate(planned_cases)
            if sequence not in skipped_sequences and case.name not in _STIMULUS_ENDPOINT_CASES
        ]
        if (executable_plans or skipped_sequences) and not unsupported:
            return _lab_endpoint_live_report(
                request=request,
                selected_cases=selected_cases,
                planned_cases=planned_cases,
                probe_plans=probe_plans,
                report_path=report_path,
            )

    return _build_report(
        request=request,
        selected_cases=selected_cases,
        planned_cases=planned_cases,
        probe_plans=probe_plans,
        report_path=report_path,
        status=status,
        dry_run=False,
    )


def _build_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    report_path: Path,
    status: str,
    dry_run: bool,
    provider_context: JSONObject | None = None,
    provider_capabilities: Mapping[str, JSONValue] | None = None,
    stimulus_endpoint: Mapping[str, JSONValue] | None = None,
) -> ProbeReport:
    provider_capabilities = provider_capabilities or _probe_capabilities_for_request(
        request,
        dry_run=dry_run,
    )
    probe_plans_by_sequence = {
        int(plan["sequence"]): plan
        for plan in probe_plans
        if isinstance(plan.get("sequence"), int)
    }
    endpoint_request_path = _write_stimulus_endpoint_request_artifact(
        report_path=report_path,
        request=request,
        probe_plans=probe_plans,
        dry_run=dry_run,
        stimulus_endpoint=stimulus_endpoint,
    )
    results: list[ProbeResult] = []
    skips: list[ProbeSkip] = []
    observed_responses: list[ObservedResponse] = []
    skip_counts: dict[str, int] = {}

    for sequence, case in enumerate(planned_cases):
        probe_plan = probe_plans_by_sequence.get(sequence, {})
        capability_skip = _capability_skip_result(
            request=request,
            case=case,
            sequence=sequence,
            probe_plan=probe_plan,
            dry_run=dry_run,
            provider_capabilities=provider_capabilities,
        )
        if capability_skip is not None:
            skip, result = capability_skip
            skips.append(skip)
            skip_counts[skip.reason] = skip_counts.get(skip.reason, 0) + 1
            results.append(result)
            continue

        if not dry_run and not request.confirm_live_run:
            skip = ProbeSkip(
                case=case.name,
                sequence=sequence,
                reason=SKIP_CONFIRMATION_REQUIRED,
                metadata={
                    "provider": request.provider,
                    "requires_confirm_live_run": True,
                    "probe_plan": probe_plan,
                },
            )
            skips.append(skip)
            skip_counts[skip.reason] = skip_counts.get(skip.reason, 0) + 1
            results.append(
                ProbeResult(
                    case=case.name,
                    sequence=sequence,
                    status="skipped",
                    endpoint_role=_primary_endpoint_role(case),
                    passed=None,
                    skip=skip,
                    metadata={"dry_run": dry_run, "probe_plan": probe_plan},
                )
            )
            continue

        observed = ObservedResponse(
            case=case.name,
            sequence=sequence,
            endpoint_role=_primary_endpoint_role(case),
            observed=False,
            response_type=case.expected_response,
            metadata={
                "dry_run": dry_run,
                "planned_only": True,
                "stimulus": case.stimulus,
                "expected_response": case.expected_response,
                "probe_plan": probe_plan,
                "failure_reasons": _failure_reasons_for_case(case.name),
            },
        )
        observed_responses.append(observed)
        results.append(
            ProbeResult(
                case=case.name,
                sequence=sequence,
                status="planned" if dry_run else STATUS_UNSUPPORTED,
                endpoint_role=_primary_endpoint_role(case),
                passed=None,
                observed_response=observed,
                metadata={
                    "dry_run": dry_run,
                    "provider": request.provider,
                    "planned_only": True,
                    "probe_plan": probe_plan,
                    "failure_reasons": _failure_reasons_for_case(case.name),
                },
            )
        )

    artifact_paths = [str(report_path)]
    if endpoint_request_path is not None:
        artifact_paths.append(str(endpoint_request_path))

    metadata: JSONObject = {
        "provider": request.provider,
        "cases": [case.name for case in selected_cases],
        "requested_count": request.count,
        "planned_count": len(planned_cases),
        "selected_count": len(selected_cases),
        "executed_count": 0,
        "passed_count": 0,
        "failed_count": 0,
        "executed_cases": [],
        "failed_counts_by_reason": {},
        "skipped_count": len(skips),
        "observed_count": sum(1 for response in observed_responses if response.observed),
        "provider_capabilities": dict(provider_capabilities),
        "skip_reasons": list(skip_counts),
        "skip_counts_by_reason": skip_counts,
        "selected_case_names": [case.name for case in selected_cases],
        "planned_case_names": [case.name for case in planned_cases],
        "probe_plans": list(probe_plans),
        "selected_specs": list(PROBE_SELECTED_SPECS),
        "dry_run": dry_run,
        "creates_infrastructure": False,
        "requires_provider_lifecycle": is_probe_lab_provider(request.provider),
        "mutates_lab": False if dry_run else None,
        "target_service_setup": _target_service_setup_plan(
            probe_plans=probe_plans,
            dry_run=dry_run,
        ),
    }
    if provider_context:
        metadata.update(provider_context)
    return ProbeReport(
        mode="probe",
        provider=request.provider,
        profile=request.profile,
        seed=request.seed,
        count=len(planned_cases),
        status=status,
        request=request,
        cases=list(selected_cases),
        endpoint_roles=list(_ENDPOINT_ROLES),
        results=results,
        skips=skips,
        observed_responses=observed_responses,
        artifacts=artifact_paths,
        artifact_paths=artifact_paths,
        metadata=metadata,
    )


def _write_stimulus_endpoint_request_artifact(
    *,
    report_path: Path,
    request: ProbeRunRequest,
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
    stimulus_endpoint: Mapping[str, JSONValue] | None = None,
) -> Path | None:
    endpoint_plans = _stimulus_endpoint_plans(probe_plans)
    if not endpoint_plans:
        return None

    artifact_dir = report_path.parent / "artifacts" / "stimulus-endpoint"
    request_path = artifact_dir / "stimulus.request.json"
    endpoint_request = _stimulus_endpoint_request_object(
        request=request,
        probe_plans=endpoint_plans,
        dry_run=dry_run,
        interface=_stimulus_interface(
            stimulus_endpoint or {},
            provider=request.provider,
            dry_run=dry_run,
        ),
        artifact_root=str(artifact_dir),
        request_path=str(request_path),
        stimulus_endpoint=stimulus_endpoint,
    )
    write_json(request_path, endpoint_request)
    return request_path


_STIMULUS_ENDPOINT_CASES = frozenset(
    {"icmp-echo", "tcp-syn-open", "tcp-syn-closed", "dns-query", "ttl-expired"}
)


def _stimulus_endpoint_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    return [plan for plan in probe_plans if plan.get("case") in _STIMULUS_ENDPOINT_CASES]


def _probe_capabilities_for_request(
    request: ProbeRunRequest,
    *,
    dry_run: bool,
) -> JSONObject:
    return probe_capabilities_for_provider(request.provider, dry_run=dry_run)


def _probe_lab_dry_run_session(request: ProbeRunRequest) -> LabSession:
    adapter = resolve_probe_lab_provider(request.provider)
    return adapter.plan_session(_probe_lab_request(request, dry_run=True))


def _probe_lab_request(
    request: ProbeRunRequest,
    *,
    dry_run: bool,
    confirm_live_run: bool = False,
    remote_dir: str | None = None,
) -> LabRequest:
    return LabRequest(
        provider=request.provider,
        profile=request.profile,
        seed=request.seed,
        roles=[
            LabRole(
                name=STIMULUS_ROLE,
                peer_roles=[TARGET_ROLE],
                capabilities=["raw_send", "packet_capture"],
                workload_metadata={"workload": "probe", "role": STIMULUS_ROLE},
            ),
            LabRole(
                name=TARGET_ROLE,
                peer_roles=[STIMULUS_ROLE],
                capabilities=["kernel_reply", "controlled_services"],
                workload_metadata={"workload": "probe", "role": TARGET_ROLE},
            ),
        ],
        dry_run=dry_run,
        confirm_live_run=confirm_live_run,
        remote_dir=remote_dir,
        workload_label="probe",
        metadata={
            "workload": "probe",
            "role_names": list(PROBE_LAB_ROLES),
            "probe": {
                "provider": request.provider,
                "profile": request.profile,
                "seed": request.seed,
                "count": request.count,
                "case_names": list(request.case_names),
                "dry_run": dry_run,
                "confirm_live_run": confirm_live_run,
            },
        },
    )


def _lab_session_probe_report_metadata(
    session: LabSession,
    *,
    address_context: JSONObject,
    provider_capabilities: Mapping[str, JSONValue],
) -> JSONObject:
    infrastructure = json_object(
        session.infrastructure_metadata,
        "lab_session.infrastructure_metadata",
    )
    endpoint_context = json_object(
        address_context.get("endpoints", {}),
        "lab_address_context.endpoints",
    )
    provider_workflow = [command.to_dict() for command in session.provider_workflow]
    command_records = [command.to_dict() for command in session.command_records]

    metadata: JSONObject = {
        "provider": session.provider,
        "wire_provider": session.wire_provider,
        "wire_exposure": session.wire_exposure,
        "dry_run": session.dry_run,
        "creates_infrastructure": _metadata_bool(
            infrastructure,
            "creates_infrastructure",
            default=bool(session.created_endpoint_ids),
        ),
        "would_create_infrastructure": _metadata_bool(
            infrastructure,
            "would_create_infrastructure",
            default=session.dry_run,
        ),
        "endpoint_count": len(session.endpoints),
        "planned_infrastructure": infrastructure,
        "wire_endpoint_plan": _lab_session_wire_endpoint_plan(
            session,
            endpoints=endpoint_context,
        ),
        "wire_endpoint_lifecycle": {
            "remote_dir": session.remote_dir,
            "remote_artifact_root": session.remote_artifact_root,
            "created_endpoint_ids": list(session.created_endpoint_ids),
            "cleanup_state": dict(session.cleanup_state),
        },
        "provider_workflow": provider_workflow,
        "provider_commands": command_records,
        "command_records": command_records,
        "endpoints": endpoint_context,
        "lab_address_context": address_context,
        "lab_session": session.to_dict(),
        "provider_capabilities": dict(provider_capabilities),
    }
    metadata.update(_selected_lab_session_metadata(session.metadata))
    return metadata


def _lab_session_wire_endpoint_plan(
    session: LabSession,
    *,
    endpoints: Mapping[str, JSONValue],
) -> JSONObject:
    raw_plan = session.metadata.get("wire_endpoint_plan")
    plan: JSONObject = (
        json_object(raw_plan, "lab_session.wire_endpoint_plan")
        if isinstance(raw_plan, Mapping)
        else {}
    )
    plan.pop("live_endpoints", None)
    plan.setdefault("provider", session.provider)
    plan.setdefault("wire_provider", session.wire_provider)
    plan.setdefault("exposure", session.wire_exposure)
    plan.setdefault("wire_exposure", session.wire_exposure)
    plan.setdefault("dry_run", session.dry_run)
    plan.setdefault("endpoint_count", len(session.endpoints))
    plan.setdefault("endpoints", dict(endpoints))
    plan.setdefault(
        "endpoint_plans",
        [
            dict(endpoint.wire_manifest)
            for endpoint in session.endpoints
            if endpoint.wire_manifest
        ],
    )
    plan.setdefault(
        "command_metadata",
        [command.to_dict() for command in session.command_records],
    )
    plan.setdefault("created_endpoint_ids", list(session.created_endpoint_ids))
    if "private_group" not in plan and "private_group" in session.metadata:
        plan["private_group"] = _json_metadata_value(session.metadata["private_group"])
    if "private_network" not in plan and "private_network" in session.metadata:
        plan["private_network"] = _json_metadata_value(session.metadata["private_network"])
    if "bridged_lan" not in plan and "bridged_lan" in session.metadata:
        plan["bridged_lan"] = _json_metadata_value(session.metadata["bridged_lan"])
    plan["lab_session_id"] = session.session_id
    return plan


def _selected_lab_session_metadata(metadata: Mapping[str, object]) -> JSONObject:
    selected: JSONObject = {}
    for key in (
        "private_group",
        "private_network",
        "bridged_lan",
        "wire_policy",
        "credential_label",
        "credentials_available",
        "missing_credential_reason",
    ):
        if key in metadata:
            selected[key] = _json_metadata_value(metadata[key])
    return selected


def _json_metadata_value(value: object) -> JSONValue:
    return json_object({"value": value}, "lab_session.metadata")["value"]


def _metadata_bool(
    metadata: Mapping[str, JSONValue],
    key: str,
    *,
    default: bool,
) -> bool:
    value = metadata.get(key)
    return value if isinstance(value, bool) else default


def _probe_plans_with_lab_endpoint_addresses(
    probe_plans: Sequence[JSONObject],
    *,
    address_context: Mapping[str, JSONValue],
) -> list[JSONObject]:
    stimulus_ipv4 = _string_or(
        address_context.get("stimulus_ipv4"),
        _first_plan_address(probe_plans, "source_ipv4", "192.0.2.10"),
    )
    target_ipv4 = _string_or(
        address_context.get("target_ipv4"),
        _first_plan_address(probe_plans, "destination_ipv4", "192.0.2.20"),
    )
    return [
        _probe_plan_with_endpoint_addresses(
            plan,
            source_ipv4=stimulus_ipv4,
            target_ipv4=target_ipv4,
            rewrite_source="lab_session",
        )
        for plan in probe_plans
    ]


def _first_plan_address(
    probe_plans: Sequence[JSONObject],
    key: str,
    default: str,
) -> str:
    for plan in probe_plans:
        value = plan.get(key)
        if isinstance(value, str) and value:
            return value
    return default


def _lab_endpoint_id(endpoint: Mapping[str, JSONValue], *, role: str) -> str:
    endpoint_id = _string_or(endpoint.get("endpoint_id"), "")
    if not endpoint_id:
        raise RuntimeError(f"lab session did not include {role} endpoint ID")
    return endpoint_id


def _lab_endpoint_ipv4(endpoint: Mapping[str, JSONValue], *, role: str) -> str:
    ipv4 = _string_or(endpoint.get("address"), _string_or(endpoint.get("ipv4"), ""))
    if not ipv4:
        raise RuntimeError(f"lab session did not include {role} endpoint IPv4")
    return ipv4


def _lab_endpoint_interface(endpoint: Mapping[str, JSONValue], *, role: str) -> str:
    interface = _string_or(endpoint.get("interface"), "")
    if not interface:
        raise RuntimeError(f"lab session did not include {role} endpoint interface")
    return interface


def _wire_command_failed(command: Mapping[str, JSONValue]) -> bool:
    exit_code = command.get("exit_code")
    if isinstance(exit_code, int):
        return exit_code != 0
    ok = command.get("ok")
    if isinstance(ok, bool):
        return not ok
    metadata = command.get("metadata")
    if isinstance(metadata, Mapping):
        metadata_exit = metadata.get("exit_code")
        if isinstance(metadata_exit, int):
            return metadata_exit != 0
        metadata_ok = metadata.get("ok")
        if isinstance(metadata_ok, bool):
            return not metadata_ok
    return False


def _lab_endpoint_live_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    report_path: Path,
) -> ProbeReport:
    output_dir = report_path.parent
    endpoint_dir = output_dir / "artifacts" / "lab-stimulus-endpoint"
    endpoint_dir.mkdir(parents=True, exist_ok=True)
    provider_commands: list[JSONObject] = []
    execution_errors: list[str] = []
    endpoint_response: JSONObject | None = None
    wire_endpoint_plan: JSONObject = {}
    endpoints: JSONObject = {}
    address_context: JSONObject = {}
    lab_session: LabSession | None = None
    lab_report_metadata: JSONObject = {}
    created_endpoint_ids: list[str] = []
    endpoint_artifact_paths: list[str] = []
    provider_capabilities = _probe_capabilities_for_request(request, dry_run=False)
    skipped_results, skips, skip_counts, skipped_sequences = _capability_skip_state(
        request=request,
        planned_cases=planned_cases,
        probe_plans=probe_plans,
        dry_run=False,
        provider_capabilities=provider_capabilities,
    )
    all_live_plans = list(probe_plans)
    live_plans = [
        plan
        for plan in probe_plans
        if int(plan.get("sequence", -1)) not in skipped_sequences
    ]
    executable_planned_cases = [
        case
        for sequence, case in enumerate(planned_cases)
        if sequence not in skipped_sequences
    ]
    local_request_path = endpoint_dir / "stimulus.request.json"
    target_setup_attempted = False
    rst_guard_attempted = False
    stimulus_endpoint: JSONObject = {}
    target_endpoint: JSONObject = {}
    target_endpoint_id = ""
    stimulus_endpoint_id = ""
    remote_dir = ""
    remote_artifact_root = ""
    wire = lab_wire_client.WireClient()

    if live_plans:
        try:
            lab_adapter = resolve_probe_lab_provider(request.provider)
            lab_session = lab_session_state.create_session(
                lab_adapter,
                _probe_lab_request(
                    request,
                    dry_run=False,
                    confirm_live_run=True,
                    remote_dir=_probe_lab_remote_dir(),
                ),
                client=wire,
            )
            created_endpoint_ids = list(lab_session.created_endpoint_ids)
            address_context = probe_address_context_from_lab_session(lab_session)

            endpoints = json_object(
                address_context.get("endpoints", {}),
                "lab_address_context.endpoints",
            )
            stimulus_endpoint = _json_mapping(
                endpoints.get(STIMULUS_ROLE, {}),
                "lab.endpoints.stimulus",
            )
            target_endpoint = _json_mapping(
                endpoints.get(TARGET_ROLE, {}),
                "lab.endpoints.target",
            )
            stimulus_endpoint_id = _lab_endpoint_id(
                stimulus_endpoint,
                role=STIMULUS_ROLE,
            )
            target_endpoint_id = _lab_endpoint_id(
                target_endpoint,
                role=TARGET_ROLE,
            )

            source_ipv4 = _string_or(
                stimulus_endpoint.get("address"),
                _first_plan_address(probe_plans, "source_ipv4", "192.0.2.10"),
            )
            target_ipv4 = _string_or(
                target_endpoint.get("address"),
                _first_plan_address(probe_plans, "destination_ipv4", "192.0.2.20"),
            )
            interface = _string_or(
                stimulus_endpoint.get("interface"),
                _probe_interface(request.provider, dry_run=False),
            )
            all_live_plans = [
                _probe_plan_with_endpoint_addresses(
                    plan,
                    source_ipv4=source_ipv4,
                    target_ipv4=target_ipv4,
                )
                for plan in probe_plans
            ]
            live_plans = [
                plan
                for plan in all_live_plans
                if int(plan.get("sequence", -1)) not in skipped_sequences
            ]

            repo_archive = lab_repo.create_repository_archive(
                output_dir / "artifacts" / "lab" / "repo",
                source_root=REPO_ROOT,
            )
            lab_session = replace(
                lab_session,
                command_records=[
                    *lab_session.command_records,
                    repo_archive.command_record,
                ],
            )
            endpoint_artifact_paths.extend(
                [
                    str(repo_archive.archive_path),
                    str(repo_archive.stdout_path),
                    str(repo_archive.stderr_path),
                ]
            )
            remote_dir = _string_or(lab_session.remote_dir, "/root/libcrafter")
            bootstrap_result = lab_repo.bootstrap_lab_session(
                lab_session,
                probe_bootstrap.bootstrap_commands(),
                remote_dir=remote_dir,
                archive=repo_archive,
                output_dir=output_dir / "artifacts" / "lab" / "bootstrap",
                client=wire,
            )
            lab_session = lab_repo.session_with_bootstrap_records(
                lab_session,
                bootstrap_result,
            )
            lab_session_state.write_session_manifest(lab_session)
            endpoint_artifact_paths.extend(bootstrap_result.artifacts)
            if not bootstrap_result.ok:
                message = f"{request.provider} endpoint bootstrap failed"
                if bootstrap_result.errors:
                    message = f"{message}: {'; '.join(bootstrap_result.errors)}"
                execution_errors.append(message)
                raise RuntimeError(message)

            remote_artifact_root = posixpath.join(
                bootstrap_result.remote_artifact_root,
                "probe",
                "endpoint",
            )
            target_artifact_root = posixpath.join(
                bootstrap_result.remote_artifact_root,
                "probe",
                "target-services",
            )

            remote_request_path = posixpath.join(
                remote_artifact_root,
                "inputs",
                "stimulus.request.json",
            )
            endpoint_request = _stimulus_endpoint_request_object(
                request=request,
                probe_plans=live_plans,
                dry_run=False,
                interface=interface,
                artifact_root=remote_artifact_root,
                request_path=remote_request_path,
                stimulus_endpoint=stimulus_endpoint,
            )
            write_json(local_request_path, endpoint_request)

            target_setup = _prepare_wire_probe_target(
                wire=wire,
                target_endpoint=target_endpoint,
                artifact_root=target_artifact_root,
                probe_plans=live_plans,
                output_dir=endpoint_dir,
            )
            if target_setup is not None:
                target_setup_attempted = True
                provider_commands.append(target_setup)
                execution_errors.extend(_string_list(target_setup.get("errors", [])))
                if target_setup["exit_code"] != 0:
                    execution_errors.append("target endpoint setup failed")

            rst_setup = _install_wire_stimulus_rst_guards(
                wire=wire,
                stimulus_endpoint=stimulus_endpoint,
                probe_plans=live_plans,
                output_dir=endpoint_dir,
            )
            if rst_setup is not None:
                rst_guard_attempted = True
                provider_commands.append(rst_setup)
                execution_errors.extend(_string_list(rst_setup.get("errors", [])))
                if rst_setup["exit_code"] != 0:
                    execution_errors.append("stimulus RST guard setup failed")

            if not execution_errors:
                upload = _upload_wire_probe_request(
                    wire=wire,
                    endpoint_id=stimulus_endpoint_id,
                    local_request_path=local_request_path,
                    remote_request_path=remote_request_path,
                    output_dir=endpoint_dir,
                )
                provider_commands.append(upload)
                if upload["exit_code"] != 0:
                    execution_errors.append("failed to upload stimulus endpoint request")
            else:
                upload = None

            if not execution_errors and upload is not None:
                execution = _run_wire_stimulus_endpoint(
                    wire=wire,
                    endpoint_id=stimulus_endpoint_id,
                    remote_dir=remote_dir,
                    remote_request_path=remote_request_path,
                    remote_artifact_root=remote_artifact_root,
                    output_dir=endpoint_dir,
                    timeout_seconds=_probe_process_timeout_seconds(len(live_plans)),
                )
                provider_commands.append(execution)
                endpoint_response = execution.get("response") if isinstance(
                    execution.get("response"), dict
                ) else None
                execution_errors.extend(_string_list(execution.get("errors", [])))
                if execution["exit_code"] != 0:
                    execution_errors.append("stimulus endpoint command failed")

                downloads = _download_wire_probe_artifacts(
                    wire=wire,
                    endpoint_id=stimulus_endpoint_id,
                    artifact_paths=json_object(
                        endpoint_request.get("artifact_paths", {}),
                        "stimulus.artifact_paths",
                    ),
                    output_dir=endpoint_dir,
                    response_path=endpoint_dir / "stimulus.response.json",
                )
                provider_commands.extend(downloads)
                endpoint_artifact_paths.extend(
                    [
                        path
                        for command in downloads
                        for path in _command_artifact_paths(command)
                    ]
                )
                if endpoint_response is None:
                    endpoint_response = _probe_endpoint_response_from_path(
                        endpoint_dir / "stimulus.response.json"
                    )
                if endpoint_response is None:
                    execution_errors.append("stimulus endpoint did not return JSON")
        except Exception as exc:  # pragma: no cover - live-provider only.
            execution_errors.append(str(exc))
        finally:
            if stimulus_endpoint_id and rst_guard_attempted:
                rst_cleanup = _cleanup_wire_stimulus_rst_guards(
                    wire=wire,
                    stimulus_endpoint=stimulus_endpoint,
                    probe_plans=live_plans,
                    output_dir=endpoint_dir,
                )
                provider_commands.append(rst_cleanup)
                execution_errors.extend(_string_list(rst_cleanup.get("errors", [])))
                if rst_cleanup["exit_code"] != 0:
                    execution_errors.append("stimulus RST guard cleanup failed")
            if target_endpoint_id and target_setup_attempted:
                target_cleanup = _cleanup_wire_probe_target(
                    wire=wire,
                    target_endpoint=target_endpoint,
                    artifact_root=target_artifact_root,
                    output_dir=endpoint_dir,
                )
                provider_commands.append(target_cleanup)
                execution_errors.extend(_string_list(target_cleanup.get("errors", [])))
                if target_cleanup["exit_code"] != 0:
                    execution_errors.append("target endpoint cleanup failed")
            if lab_session is not None:
                try:
                    lab_session = lab_session_state.cleanup_lab_session(
                        lab_session,
                        client=wire,
                    )
                    lab_session_state.write_session_manifest(lab_session)
                except Exception as cleanup_exc:  # pragma: no cover - defensive fallback.
                    execution_errors.append(
                        f"{request.provider} lab cleanup failed: {cleanup_exc}"
                    )

    if lab_session is not None:
        address_context = address_context or probe_address_context_from_lab_session(
            lab_session
        )
        lab_report_metadata = _lab_session_probe_report_metadata(
            lab_session,
            address_context=address_context,
            provider_capabilities=provider_capabilities,
        )
        wire_endpoint_plan = _json_mapping(
            lab_report_metadata.get("wire_endpoint_plan", {}),
            "lab_report.wire_endpoint_plan",
        )
        endpoints = _json_mapping(
            lab_report_metadata.get("endpoints", {}),
            "lab_report.endpoints",
        )
        provider_commands = [
            *_json_list(
                lab_report_metadata.get("command_records", []),
                "lab_report.command_records",
            ),
            *provider_commands,
        ]

    if not live_plans:
        endpoint_results: list[ProbeResult] = []
        observed_responses = []
    elif endpoint_response is None:
        endpoint_results, observed_responses = _failed_live_probe_results(
            planned_cases=executable_planned_cases,
            probe_plans=live_plans,
            reason=FAILURE_DECODE_FAILED,
            errors=execution_errors,
        )
    else:
        endpoint_results, observed_responses = _probe_results_from_endpoint_response(
            endpoint_response
        )

    results = sorted(
        [*skipped_results, *endpoint_results],
        key=lambda result: result.sequence,
    )
    failures = [result for result in results if result.passed is False]
    status = STATUS_PASSED if results and not failures and not execution_errors else STATUS_FAILED
    failed_counts = _failed_counts_by_reason(results)
    executed_count = sum(1 for result in results if result.status != "skipped")
    artifact_paths = [str(report_path)]
    if local_request_path.exists():
        artifact_paths.append(str(local_request_path))
    artifact_paths.extend(endpoint_artifact_paths)
    artifact_paths.extend(
        [
            path
            for command in provider_commands
            for path in _command_artifact_paths(command)
        ]
    )
    if endpoint_response is not None:
        artifact_paths.extend(_string_list(endpoint_response.get("artifacts", [])))
        artifact_paths.extend(_string_list(endpoint_response.get("artifact_paths", [])))
    artifact_paths = _dedupe_paths(artifact_paths)
    lab_wire_endpoint_lifecycle = _json_mapping(
        lab_report_metadata.get("wire_endpoint_lifecycle", {}),
        "lab_report.wire_endpoint_lifecycle",
    )
    cleanup_state = _json_mapping(
        lab_wire_endpoint_lifecycle.get("cleanup_state", {}),
        "lab_report.cleanup_state",
    )
    destroy_attempted = bool(
        cleanup_state.get("teardown_attempted", bool(created_endpoint_ids))
    )

    return ProbeReport(
        mode="probe",
        provider=request.provider,
        profile=request.profile,
        seed=request.seed,
        count=len(planned_cases),
        status=status,
        request=request,
        cases=list(selected_cases),
        endpoint_roles=list(_ENDPOINT_ROLES),
        results=results,
        skips=skips,
        observed_responses=observed_responses,
        artifacts=artifact_paths,
        artifact_paths=artifact_paths,
        metadata={
            "provider": request.provider,
            "cases": [case.name for case in selected_cases],
            "requested_count": request.count,
            "planned_count": len(planned_cases),
            "selected_count": len(selected_cases),
            "executed_count": sum(1 for result in results if result.status != "skipped"),
            "passed_count": sum(1 for result in results if result.passed is True),
            "failed_count": len(failures),
            "executed_cases": _dedupe_strings(
                [result.case for result in results if result.status != "skipped"]
            ),
            "failed_counts_by_reason": failed_counts,
            "skipped_count": len(skips),
            "observed_count": sum(
                1 for response in observed_responses if response.observed
            ),
            "provider_capabilities": dict(provider_capabilities),
            "skip_reasons": list(skip_counts),
            "skip_counts_by_reason": skip_counts,
            "selected_case_names": [case.name for case in selected_cases],
            "planned_case_names": [case.name for case in planned_cases],
            "probe_plans": all_live_plans,
            "selected_specs": list(PROBE_SELECTED_SPECS),
            "dry_run": False,
            "creates_infrastructure": bool(created_endpoint_ids),
            "requires_provider_lifecycle": True,
            "mutates_lab": True,
            "live_packet_exchange": status == STATUS_PASSED and executed_count > 0,
            "provider_workflow": lab_report_metadata.get("provider_workflow", []),
            "wire_endpoint_plan": wire_endpoint_plan,
            "endpoints": endpoints,
            "wire_endpoint_lifecycle": {
                **lab_wire_endpoint_lifecycle,
                "remote_dir": remote_dir,
                "remote_artifact_root": remote_artifact_root,
                "created_endpoint_ids": list(created_endpoint_ids),
                "destroy_attempted": destroy_attempted,
            },
            "provider_commands": provider_commands,
            "command_records": provider_commands,
            "lab_session": lab_report_metadata.get("lab_session"),
            "planned_infrastructure": lab_report_metadata.get(
                "planned_infrastructure",
                {},
            ),
            "lab_address_context": address_context,
            "execution_errors": execution_errors,
            "target_service_setup": _target_service_setup_plan(
                probe_plans=live_plans,
                dry_run=False,
            ),
        },
    )


def _stimulus_endpoint_request_object(
    *,
    request: ProbeRunRequest,
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
    interface: str,
    artifact_root: str,
    request_path: str,
    stimulus_endpoint: Mapping[str, JSONValue] | None = None,
) -> JSONObject:
    first_plan = probe_plans[0] if probe_plans else {}
    endpoint_metadata = _stimulus_endpoint_request_metadata(
        stimulus_endpoint or {},
        provider=request.provider,
        interface=interface,
        dry_run=dry_run,
    )
    return {
        "schema_version": 1,
        "provider": request.provider,
        "profile": request.profile,
        "seed": request.seed,
        "dry_run": dry_run,
        "endpoint_role": "stimulus",
        "interface": interface,
        "local_ipv4": str(first_plan.get("source_ipv4", "")),
        "peer_ipv4": str(first_plan.get("destination_ipv4", "")),
        "timeout_seconds": _probe_timeout_seconds(len(probe_plans)),
        "probe_plans": list(probe_plans),
        "artifact_paths": {
            "request": request_path,
            "response": posixpath.join(artifact_root, "stimulus.response.json"),
            "captures": posixpath.join(artifact_root, "captures"),
        },
        "metadata": {
            "planned_only": dry_run,
            "case_count": len(probe_plans),
            "stimulus_endpoint": endpoint_metadata,
            "failure_reasons_by_case": {
                str(plan.get("case", "")): _failure_reasons_for_case(
                    str(plan.get("case", ""))
                )
                for plan in probe_plans
            },
        },
    }


def _stimulus_endpoint_context(
    address_context: Mapping[str, JSONValue],
) -> JSONObject:
    endpoints = _json_mapping(
        address_context.get("endpoints", {}),
        "lab_address_context.endpoints",
    )
    return _json_mapping(
        endpoints.get(STIMULUS_ROLE, {}),
        "lab_address_context.endpoints.stimulus",
    )


def _stimulus_interface(
    stimulus_endpoint: Mapping[str, JSONValue],
    *,
    provider: str,
    dry_run: bool,
) -> str:
    interface = _string_or(stimulus_endpoint.get("interface"), "")
    return interface or _probe_interface(provider, dry_run=dry_run)


def _stimulus_endpoint_request_metadata(
    stimulus_endpoint: Mapping[str, JSONValue],
    *,
    provider: str,
    interface: str,
    dry_run: bool,
) -> JSONObject:
    metadata = _json_mapping(
        stimulus_endpoint.get("metadata", {}),
        "stimulus_endpoint.metadata",
    )
    output: JSONObject = {
        "provider": provider,
        "role": STIMULUS_ROLE,
        "interface": interface,
        "interface_source": "lab_endpoint" if stimulus_endpoint else "probe_default",
        "dry_run": dry_run,
    }
    for source_key, target_key in (
        ("endpoint_id", "endpoint_id"),
        ("address", "ipv4"),
        ("ipv4", "ipv4"),
        ("peer_address", "peer_ipv4"),
    ):
        value = stimulus_endpoint.get(source_key)
        if isinstance(value, str) and value:
            output[target_key] = value
    for key in (
        "wire_provider",
        "wire_exposure",
        "lab_session_id",
        "private_group",
        "private_network",
        "bridged_lan",
    ):
        value = metadata.get(key)
        if value is not None:
            output[key] = value
    return output


def _probe_plan_with_endpoint_addresses(
    plan: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
    rewrite_source: str = "wire_endpoint_plan",
) -> JSONObject:
    if plan.get("case") not in _STIMULUS_ENDPOINT_CASES:
        return dict(plan)
    updated = dict(plan)
    updated["source_ipv4"] = source_ipv4
    updated["destination_ipv4"] = target_ipv4
    updated["expected_reply_source_ipv4"] = target_ipv4
    updated["expected_reply_destination_ipv4"] = source_ipv4
    case_name = str(updated.get("case", ""))
    if case_name == "icmp-echo":
        updated["capture_filter"] = (
            f"icmp and src host {target_ipv4} and dst host {source_ipv4}"
        )
    elif case_name == "ttl-expired":
        router_ipv4 = str(
            updated.get("controlled_router_ipv4") or target_ipv4
        )
        updated["source_ipv4"] = source_ipv4
        updated["destination_ipv4"] = target_ipv4
        updated["controlled_router_ipv4"] = router_ipv4
        updated["expected_reply_source_ipv4"] = router_ipv4
        updated["expected_reply_destination_ipv4"] = source_ipv4
        updated["capture_filter"] = (
            f"icmp and src host {router_ipv4} and dst host {source_ipv4}"
        )
    elif case_name.startswith("tcp-syn-"):
        source_port = int(updated.get("source_port", 0))
        destination_port = int(updated.get("destination_port", 0))
        updated["capture_filter"] = (
            f"tcp and src host {target_ipv4} and dst host {source_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        )
        target_service = dict(
            json_object(updated.get("target_service", {}), "probe_plan.target_service")
        )
        target_service.update(
            {
                "bind_ipv4": target_ipv4,
                "source_ipv4": source_ipv4,
            }
        )
        updated["target_service"] = target_service
        rst_guard = dict(
            json_object(updated.get("stimulus_rst_guard", {}), "probe_plan.rst_guard")
        )
        rst_guard.update(
            {
                "source_ipv4": source_ipv4,
                "destination_ipv4": target_ipv4,
                "source_port": source_port,
                "destination_port": destination_port,
            }
        )
        updated["stimulus_rst_guard"] = rst_guard
    elif case_name == "dns-query":
        source_port = int(updated.get("source_port", 0))
        destination_port = int(updated.get("destination_port", 53))
        updated["capture_filter"] = (
            f"udp and src host {target_ipv4} and dst host {source_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        )
        target_service = dict(
            json_object(updated.get("target_service", {}), "probe_plan.target_service")
        )
        target_service.update(
            {
                "bind_ipv4": target_ipv4,
                "port": destination_port,
                "source_ipv4": source_ipv4,
            }
        )
        updated["target_service"] = target_service
    validation = dict(json_object(updated.get("validation", {}), "probe_plan.validation"))
    validation["source_ipv4"] = (
        str(updated.get("controlled_router_ipv4"))
        if case_name == "ttl-expired" and updated.get("controlled_router_ipv4")
        else target_ipv4
    )
    validation["destination_ipv4"] = source_ipv4
    updated["validation"] = validation
    updated["live_address_rewrite"] = {
        "source": rewrite_source,
        "stimulus_ipv4": source_ipv4,
        "target_ipv4": target_ipv4,
    }
    return updated


def _probe_lab_remote_dir() -> str | None:
    remote_dir = os.environ.get("LIBCRAFTER_WIRE_REMOTE_DIR")
    if remote_dir is None or remote_dir == "":
        return None
    if not remote_dir.startswith("/"):
        raise RuntimeError("probe lab remote_dir must be an absolute path")
    if "'" in remote_dir:
        raise RuntimeError("probe lab remote_dir must not contain single quotes")
    return remote_dir.rstrip("/") or "/"


def _run_lab_wire_command(
    response: object,
    *,
    output_dir: Path,
    label: str,
) -> JSONObject:
    command_dir = output_dir / "provider"
    command_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = command_dir / f"{label}.stdout.txt"
    stderr_path = command_dir / f"{label}.stderr.txt"
    result = getattr(response, "result")
    stdout = str(getattr(result, "stdout", ""))
    stderr = str(getattr(result, "stderr", ""))
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    metadata_func = getattr(response, "metadata", None)
    metadata = (
        json_object(metadata_func(), f"{label}.metadata")
        if callable(metadata_func)
        else {}
    )
    metadata.update(
        {
            "label": label,
            "wire_command": True,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }
    )
    error = getattr(result, "error", None)
    if isinstance(error, str) and error:
        metadata["error"] = error
    collected_artifacts = _existing_paths_from_stdout(stdout)
    if collected_artifacts:
        metadata["collected_artifacts"] = collected_artifacts
    return metadata


def _upload_wire_probe_request(
    *,
    wire: object,
    endpoint_id: str,
    local_request_path: Path,
    remote_request_path: str,
    output_dir: Path,
) -> JSONObject:
    remote_parent = posixpath.dirname(remote_request_path)
    mkdir = _run_lab_wire_command(
        wire.exec(
            endpoint_id,
            ["bash", "-lc", f"mkdir -p {shlex.quote(remote_parent)}"],
            timeout=60,
        ),
        output_dir=output_dir,
        label="upload-stimulus-request-mkdir",
    )
    upload = (
        _run_lab_wire_command(
            wire.upload(endpoint_id, local_request_path, remote_request_path),
            output_dir=output_dir,
            label="upload-stimulus-request",
        )
        if mkdir["exit_code"] == 0
        else None
    )
    commands = [mkdir] + ([] if upload is None else [upload])
    exit_code = next(
        (
            int(command.get("exit_code", 1))
            for command in commands
            if command.get("exit_code") != 0
        ),
        0,
    )
    return {
        "wire_command": True,
        "operation": "upload",
        "endpoint_id": endpoint_id,
        "label": "upload-stimulus-request",
        "exit_code": exit_code,
        "request_path": str(local_request_path),
        "remote_request_path": remote_request_path,
        "commands": commands,
        "errors": [
            error
            for command in commands
            for error in _string_list(command.get("errors", []))
        ],
    }


def _run_wire_stimulus_endpoint(
    *,
    wire: object,
    endpoint_id: str,
    remote_dir: str,
    remote_request_path: str,
    remote_artifact_root: str,
    output_dir: Path,
    timeout_seconds: int,
) -> JSONObject:
    quoted_remote_dir = shlex.quote(remote_dir)
    quoted_request = shlex.quote(remote_request_path)
    quoted_out = shlex.quote(remote_artifact_root)
    script = "\n".join(
        [
            "set -euo pipefail",
            f"cd {quoted_remote_dir}",
            'if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi',
            (
                "cargo run -q -p probe-adapters --bin stimulus_endpoint -- "
                f"--live --input {quoted_request} --out {quoted_out}"
            ),
        ]
    )
    response = wire.exec(
        endpoint_id,
        ["bash", "-lc", script],
        timeout=timeout_seconds,
    )
    command = _run_lab_wire_command(
        response,
        output_dir=output_dir,
        label="stimulus-endpoint",
    )
    parsed, parse_errors = _parse_json_stdout(
        str(getattr(response.result, "stdout", "")),
        "stimulus-endpoint",
    )
    command["response"] = parsed
    command["errors"] = [
        *_string_list(command.get("errors", [])),
        *parse_errors,
    ]
    return command


def _prepare_wire_probe_target(
    *,
    wire: object,
    target_endpoint: Mapping[str, JSONValue],
    artifact_root: str,
    probe_plans: Sequence[JSONObject],
    output_dir: Path,
) -> JSONObject | None:
    tcp_plans = _tcp_probe_plans(probe_plans)
    dns_plans = _dns_probe_plans(probe_plans)
    if not tcp_plans and not dns_plans:
        return None
    endpoint_id = _lab_endpoint_id(target_endpoint, role=TARGET_ROLE)
    bind_ipv4 = _lab_endpoint_ipv4(target_endpoint, role=TARGET_ROLE)
    open_ports = _dedupe_ints(
        int(plan["destination_port"])
        for plan in tcp_plans
        if plan.get("case") == "tcp-syn-open"
    )
    closed_ports = _dedupe_ints(
        int(plan["destination_port"])
        for plan in tcp_plans
        if plan.get("case") == "tcp-syn-closed"
    )
    script = _target_service_setup_script(
        artifact_root=artifact_root,
        bind_ipv4=bind_ipv4,
        open_ports=open_ports,
        closed_ports=closed_ports,
        dns_plans=dns_plans,
    )
    return _run_lab_wire_command(
        wire.exec(endpoint_id, ["bash", "-lc", script], timeout=60),
        output_dir=output_dir,
        label="probe-target-setup",
    )


def _cleanup_wire_probe_target(
    *,
    wire: object,
    target_endpoint: Mapping[str, JSONValue],
    artifact_root: str,
    output_dir: Path,
) -> JSONObject:
    endpoint_id = _lab_endpoint_id(target_endpoint, role=TARGET_ROLE)
    cleanup_script = posixpath.join(artifact_root, "cleanup.sh")
    script = "\n".join(
        [
            "set -euo pipefail",
            f"if [ -x {shlex.quote(cleanup_script)} ]; then {shlex.quote(cleanup_script)}; fi",
        ]
    )
    return _run_lab_wire_command(
        wire.exec(endpoint_id, ["bash", "-lc", script], timeout=60),
        output_dir=output_dir,
        label="probe-target-cleanup",
    )


def _install_wire_stimulus_rst_guards(
    *,
    wire: object,
    stimulus_endpoint: Mapping[str, JSONValue],
    probe_plans: Sequence[JSONObject],
    output_dir: Path,
) -> JSONObject | None:
    tcp_plans = _tcp_probe_plans(probe_plans)
    if not tcp_plans:
        return None
    endpoint_id = _lab_endpoint_id(stimulus_endpoint, role=STIMULUS_ROLE)
    interface = _lab_endpoint_interface(stimulus_endpoint, role=STIMULUS_ROLE)
    return _run_lab_wire_command(
        wire.exec(
            endpoint_id,
            [
                "bash",
                "-lc",
                _rst_guard_script(
                    tcp_plans,
                    install=True,
                    interface=interface,
                ),
            ],
            timeout=60,
        ),
        output_dir=output_dir,
        label="probe-stimulus-rst-guard-setup",
    )


def _cleanup_wire_stimulus_rst_guards(
    *,
    wire: object,
    stimulus_endpoint: Mapping[str, JSONValue],
    probe_plans: Sequence[JSONObject],
    output_dir: Path,
) -> JSONObject:
    endpoint_id = _lab_endpoint_id(stimulus_endpoint, role=STIMULUS_ROLE)
    interface = _lab_endpoint_interface(stimulus_endpoint, role=STIMULUS_ROLE)
    return _run_lab_wire_command(
        wire.exec(
            endpoint_id,
            [
                "bash",
                "-lc",
                _rst_guard_script(
                    _tcp_probe_plans(probe_plans),
                    install=False,
                    interface=interface,
                ),
            ],
            timeout=60,
        ),
        output_dir=output_dir,
        label="probe-stimulus-rst-guard-cleanup",
    )


def _download_wire_probe_artifacts(
    *,
    wire: object,
    endpoint_id: str,
    artifact_paths: Mapping[str, JSONValue],
    output_dir: Path,
    response_path: Path,
) -> list[JSONObject]:
    local_root = output_dir / "downloads" / "stimulus"
    downloads: list[JSONObject] = []
    local_by_key = {
        "response": response_path,
        "captures": local_root / "captures",
    }
    for key, local_path in local_by_key.items():
        remote_path = artifact_paths.get(key)
        if not isinstance(remote_path, str) or not remote_path.startswith("/"):
            continue
        record = _run_lab_wire_command(
            wire.download(endpoint_id, remote_path, local_path),
            output_dir=output_dir,
            label=f"download-stimulus-{key}",
        )
        record.update(
            {
                "endpoint_id": endpoint_id,
                "endpoint_role": "stimulus",
                "artifact_key": key,
                "remote_path": remote_path,
                "local_path": str(local_path),
            }
        )
        downloads.append(record)
    return downloads


def _existing_paths_from_stdout(stdout: str) -> list[str]:
    paths: list[str] = []
    for line in stdout.splitlines():
        value = line.strip()
        if not value or "=" in value:
            continue
        path = Path(value)
        if path.exists():
            paths.append(str(path))
    return _dedupe_paths(paths)


def _probe_endpoint_response_from_path(path: Path) -> JSONObject | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(value, Mapping):
        return None
    return json_object(value, "stimulus.response")


def _target_service_setup_script(
    *,
    artifact_root: str,
    bind_ipv4: str,
    open_ports: Sequence[int],
    closed_ports: Sequence[int],
    dns_plans: Sequence[JSONObject],
) -> str:
    dns_plan_json = json.dumps(list(dns_plans), sort_keys=True)
    dns_ports = _dedupe_ints(
        int(plan["destination_port"])
        for plan in dns_plans
        if isinstance(plan.get("destination_port"), int)
    )
    lines = [
        "set -euo pipefail",
        f"artifact_root={shlex.quote(artifact_root)}",
        f"tcp_bind_ipv4={shlex.quote(bind_ipv4)}",
        f"dns_bind_ipv4={shlex.quote(bind_ipv4)}",
        'mkdir -p "$artifact_root"',
        'cleanup="$artifact_root/cleanup.sh"',
        ': > "$cleanup"',
        'chmod 700 "$cleanup"',
        "check_port_free() {",
        "  python3 - \"$1\" \"$2\" <<'PY'",
        "import socket",
        "import sys",
        "bind_ip = sys.argv[1]",
        "port = int(sys.argv[2])",
        "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
        "try:",
        "    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
        "    sock.bind((bind_ip, port))",
        "except OSError as exc:",
        "    print(f'tcp port {bind_ip}:{port} is not free: {exc}', file=sys.stderr)",
        "    sys.exit(1)",
        "finally:",
        "    sock.close()",
        "PY",
        "}",
    ]
    for port in dns_ports:
        lines.extend(
            [
                "python3 - \"$dns_bind_ipv4\" \"$1\" <<'PY'".replace("$1", str(port)),
                "import socket",
                "import sys",
                "bind_ip = sys.argv[1]",
                "port = int(sys.argv[2])",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
                "try:",
                "    sock.bind((bind_ip, port))",
                "except OSError as exc:",
                "    print(f'udp port {bind_ip}:{port} is not free: {exc}', file=sys.stderr)",
                "    sys.exit(1)",
                "finally:",
                "    sock.close()",
                "PY",
            ]
        )
    for port in closed_ports:
        lines.append(f"check_port_free \"$tcp_bind_ipv4\" {port}")
        lines.append(f"echo closed_port_{port}=free")
    for port in open_ports:
        listener_path = posixpath.join(artifact_root, f"tcp-listener-{port}.py")
        stdout_path = posixpath.join(artifact_root, f"tcp-listener-{port}.stdout.txt")
        stderr_path = posixpath.join(artifact_root, f"tcp-listener-{port}.stderr.txt")
        pid_path = posixpath.join(artifact_root, f"tcp-listener-{port}.pid")
        lines.extend(
            [
                f"check_port_free \"$tcp_bind_ipv4\" {port}",
                f"cat > {shlex.quote(listener_path)} <<'PY'",
                "import signal",
                "import socket",
                "import sys",
                "",
                "stop = False",
                "",
                "def handle_stop(_signum, _frame):",
                "    global stop",
                "    stop = True",
                "",
                "signal.signal(signal.SIGTERM, handle_stop)",
                "signal.signal(signal.SIGINT, handle_stop)",
                "bind_ip = sys.argv[1]",
                "port = int(sys.argv[2])",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
                "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
                "sock.bind((bind_ip, port))",
                "sock.listen(128)",
                "sock.settimeout(1.0)",
                "print(f'listening on {bind_ip}:{port}', flush=True)",
                "while not stop:",
                "    try:",
                "        conn, _addr = sock.accept()",
                "    except socket.timeout:",
                "        continue",
                "    conn.close()",
                "sock.close()",
                "PY",
                (
                    f"python3 {shlex.quote(listener_path)} \"$tcp_bind_ipv4\" {port} "
                    f">{shlex.quote(stdout_path)} 2>{shlex.quote(stderr_path)} &"
                ),
                "pid=$!",
                f"echo \"$pid\" > {shlex.quote(pid_path)}",
                "printf '%s\\n' \"kill $pid 2>/dev/null || true\" >> \"$cleanup\"",
                f"printf '%s\\n' \"rm -f {shlex.quote(pid_path)}\" >> \"$cleanup\"",
                "sleep 0.5",
                "if ! kill -0 \"$pid\" 2>/dev/null; then",
                f"  cat {shlex.quote(stderr_path)} >&2 || true",
                f"  echo listener_{port}=failed >&2",
                "  exit 73",
                "fi",
                f"echo listener_{port}=running",
            ]
        )
    if dns_ports:
        zone_path = posixpath.join(artifact_root, "dns-zone.json")
        service_path = posixpath.join(artifact_root, "dns-responder.py")
        lines.extend(
            [
                f"cat > {shlex.quote(zone_path)} <<'JSON'",
                dns_plan_json,
                "JSON",
                f"cat > {shlex.quote(service_path)} <<'PY'",
                "import ipaddress",
                "import json",
                "import signal",
                "import socket",
                "import struct",
                "import sys",
                "import time",
                "",
                "stop = False",
                "",
                "def handle_stop(_signum, _frame):",
                "    global stop",
                "    stop = True",
                "",
                "signal.signal(signal.SIGTERM, handle_stop)",
                "signal.signal(signal.SIGINT, handle_stop)",
                "",
                "zone_path, bind_ip, port_text = sys.argv[1:4]",
                "port = int(port_text)",
                "plans = json.load(open(zone_path, encoding='utf-8'))",
                "records = {}",
                "for plan in plans:",
                "    name = str(plan['query_name']).lower().rstrip('.') + '.'",
                "    qtype = int(plan['query_type_value'])",
                "    records[(name, qtype)] = {",
                "        'answer_data': str(plan['expected_answer_data']),",
                "        'ttl': int(plan.get('answer_ttl', 60)),",
                "    }",
                "",
                "def read_name(message, offset):",
                "    labels = []",
                "    jumped = False",
                "    consumed = 0",
                "    seen = set()",
                "    while True:",
                "        if offset >= len(message):",
                "            raise ValueError('name offset out of range')",
                "        length = message[offset]",
                "        if length & 0xc0 == 0xc0:",
                "            if offset + 1 >= len(message):",
                "                raise ValueError('truncated compression pointer')",
                "            pointer = ((length & 0x3f) << 8) | message[offset + 1]",
                "            if pointer in seen:",
                "                raise ValueError('compression pointer loop')",
                "            seen.add(pointer)",
                "            if not jumped:",
                "                consumed += 2",
                "            offset = pointer",
                "            jumped = True",
                "            continue",
                "        offset += 1",
                "        if not jumped:",
                "            consumed += 1",
                "        if length == 0:",
                "            return '.'.join(labels).lower() + '.', consumed",
                "        if length & 0xc0:",
                "            raise ValueError('unsupported dns label kind')",
                "        label = message[offset:offset + length]",
                "        if len(label) != length:",
                "            raise ValueError('truncated dns label')",
                "        labels.append(label.decode('ascii'))",
                "        offset += length",
                "        if not jumped:",
                "            consumed += length",
                "",
                "def encode_name(name):",
                "    out = bytearray()",
                "    for label in name.rstrip('.').split('.'):",
                "        raw = label.encode('ascii')",
                "        out.append(len(raw))",
                "        out.extend(raw)",
                "    out.append(0)",
                "    return bytes(out)",
                "",
                "def response_for(query):",
                "    if len(query) < 12:",
                "        raise ValueError('query shorter than dns header')",
                "    txid, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack('!HHHHHH', query[:12])",
                "    if qdcount < 1:",
                "        raise ValueError('query has no question')",
                "    name, consumed = read_name(query, 12)",
                "    question_end = 12 + consumed + 4",
                "    if question_end > len(query):",
                "        raise ValueError('truncated dns question')",
                "    qtype, qclass = struct.unpack('!HH', query[12 + consumed:question_end])",
                "    question = query[12:question_end]",
                "    record = records.get((name, qtype))",
                "    rd = flags & 0x0100",
                "    if record is None or qclass != 1:",
                "        header = struct.pack('!HHHHHH', txid, 0x8000 | rd | 3, 1, 0, 0, 0)",
                "        return header + question, {'name': name, 'qtype': qtype, 'rcode': 3}",
                "    if qtype == 1:",
                "        rdata = ipaddress.IPv4Address(record['answer_data']).packed",
                "    elif qtype == 28:",
                "        rdata = ipaddress.IPv6Address(record['answer_data']).packed",
                "    else:",
                "        raise ValueError(f'unsupported qtype {qtype}')",
                "    answer = b'\\xc0\\x0c' + struct.pack('!HHIH', qtype, 1, record['ttl'], len(rdata)) + rdata",
                "    header = struct.pack('!HHHHHH', txid, 0x8000 | rd | 0x0400 | 0x0080, 1, 1, 0, 0)",
                "    return header + question + answer, {'name': name, 'qtype': qtype, 'rcode': 0}",
                "",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
                "sock.bind((bind_ip, port))",
                "sock.settimeout(1.0)",
                "print(json.dumps({'event': 'listening', 'bind_ip': bind_ip, 'port': port}), flush=True)",
                "while not stop:",
                "    try:",
                "        data, addr = sock.recvfrom(4096)",
                "    except socket.timeout:",
                "        continue",
                "    try:",
                "        response, meta = response_for(data)",
                "        sock.sendto(response, addr)",
                "        meta.update({'event': 'answered', 'client': addr[0], 'client_port': addr[1]})",
                "        print(json.dumps(meta, sort_keys=True), flush=True)",
                "    except Exception as exc:",
                "        print(json.dumps({'event': 'error', 'error': str(exc)}), file=sys.stderr, flush=True)",
                "sock.close()",
                "print(json.dumps({'event': 'stopped', 'ts': time.time()}), flush=True)",
                "PY",
            ]
        )
    for port in dns_ports:
        stdout_path = posixpath.join(artifact_root, f"dns-responder-{port}.stdout.txt")
        stderr_path = posixpath.join(artifact_root, f"dns-responder-{port}.stderr.txt")
        pid_path = posixpath.join(artifact_root, f"dns-responder-{port}.pid")
        lines.extend(
            [
                (
                    f"python3 {shlex.quote(posixpath.join(artifact_root, 'dns-responder.py'))} "
                    f"{shlex.quote(posixpath.join(artifact_root, 'dns-zone.json'))} "
                    f"\"$dns_bind_ipv4\" {port} "
                    f">{shlex.quote(stdout_path)} 2>{shlex.quote(stderr_path)} &"
                ),
                "pid=$!",
                f"echo \"$pid\" > {shlex.quote(pid_path)}",
                "printf '%s\\n' \"kill $pid 2>/dev/null || true\" >> \"$cleanup\"",
                f"printf '%s\\n' \"rm -f {shlex.quote(pid_path)}\" >> \"$cleanup\"",
                "sleep 0.5",
                "if ! kill -0 \"$pid\" 2>/dev/null; then",
                f"  cat {shlex.quote(stderr_path)} >&2 || true",
                f"  echo dns_responder_{port}=failed >&2",
                "  exit 73",
                "fi",
                f"echo dns_responder_{port}=running",
            ]
        )
    lines.append("echo target_service_setup=ok")
    return "\n".join(lines)


def _rst_guard_script(
    probe_plans: Sequence[JSONObject],
    *,
    install: bool,
    interface: str | None = None,
) -> str:
    lines = [
        "set -euo pipefail",
        "if ! command -v iptables >/dev/null 2>&1; then",
        "  echo 'iptables is required for TCP raw SYN probes' >&2",
        "  exit 69",
        "fi",
    ]
    for argv in _rst_guard_iptables_args(probe_plans, interface=interface):
        quoted_args = " ".join(shlex.quote(arg) for arg in argv)
        check = f"iptables -C OUTPUT {quoted_args}"
        if install:
            lines.extend(
                [
                    f"if ! {check} >/dev/null 2>&1; then",
                    f"  iptables -I OUTPUT 1 {quoted_args}",
                    "fi",
                ]
            )
        else:
            lines.extend(
                [
                    f"while {check} >/dev/null 2>&1; do",
                    f"  iptables -D OUTPUT {quoted_args}",
                    "done",
                ]
            )
    lines.append(
        "echo stimulus_rst_guard={}".format("installed" if install else "removed")
    )
    return "\n".join(lines)


def _rst_guard_iptables_args(
    probe_plans: Sequence[JSONObject],
    *,
    interface: str | None = None,
) -> list[list[str]]:
    rules: list[list[str]] = []
    for plan in probe_plans:
        guard = json_object(plan.get("stimulus_rst_guard", {}), "stimulus_rst_guard")
        if guard.get("required") is not True:
            continue
        interface_args = ["-o", interface] if interface else []
        rules.append(
            [
                *interface_args,
                "-p",
                "tcp",
                "-s",
                str(guard.get("source_ipv4", plan.get("source_ipv4", ""))),
                "-d",
                str(guard.get("destination_ipv4", plan.get("destination_ipv4", ""))),
                "--sport",
                str(guard.get("source_port", plan.get("source_port", ""))),
                "--dport",
                str(guard.get("destination_port", plan.get("destination_port", ""))),
                "--tcp-flags",
                "RST",
                "RST",
                "-j",
                "DROP",
            ]
        )
    return rules


def _tcp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    return [
        plan
        for plan in probe_plans
        if str(plan.get("case", "")).startswith("tcp-syn-")
    ]


def _dns_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    return [plan for plan in probe_plans if plan.get("case") == "dns-query"]


def _dedupe_ints(values: Sequence[int]) -> list[int]:
    return list(dict.fromkeys(values))


def _run_command(
    argv: Sequence[str],
    *,
    output_dir: Path,
    label: str,
    input_text: str | None = None,
    timeout_seconds: int | None = None,
    parse_json: bool = False,
) -> JSONObject:
    stdout_path = output_dir / f"{label}.stdout.txt"
    stderr_path = output_dir / f"{label}.stderr.txt"
    try:
        process = subprocess.run(
            list(argv),
            cwd=REPO_ROOT,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
        stdout = process.stdout
        stderr = process.stderr
        exit_code = process.returncode
        errors: list[str] = []
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        exit_code = 124
        errors = [f"{label}: command timed out after {timeout_seconds}s"]
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    response: JSONObject | None = None
    if parse_json:
        response, parse_errors = _parse_json_stdout(stdout, label)
        errors.extend(parse_errors)
    return {
        "argv": _redacted_argv(argv),
        "exit_code": exit_code,
        "label": label,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "response": response,
        "errors": errors,
    }


def _redacted_argv(argv: Sequence[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for arg in argv:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        if arg == "-i":
            redacted.append(arg)
            redact_next = True
            continue
        if arg.startswith("UserKnownHostsFile="):
            redacted.append("UserKnownHostsFile=<redacted>")
            continue
        if "@" in arg and not arg.startswith("-"):
            user, _, _host = arg.partition("@")
            redacted.append(f"{user}@<redacted>")
            continue
        redacted.append(arg)
    return redacted


def _parse_json_stdout(stdout: str, label: str) -> tuple[JSONObject | None, list[str]]:
    if not stdout.strip():
        return None, [f"{label}: endpoint produced no JSON response"]
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        start = stdout.find("{")
        end = stdout.rfind("}")
        if start < 0 or end <= start:
            return None, [f"{label}: endpoint stdout was not JSON"]
        try:
            value = json.loads(stdout[start : end + 1])
        except json.JSONDecodeError as exc:
            return None, [f"{label}: endpoint stdout JSON parse failed: {exc}"]
    if not isinstance(value, Mapping):
        return None, [f"{label}: endpoint response must be a JSON object"]
    return json_object(value, f"{label}.response"), []


def _probe_results_from_endpoint_response(
    response: JSONObject,
) -> tuple[list[ProbeResult], list[ObservedResponse]]:
    results: list[ProbeResult] = []
    observed_responses: list[ObservedResponse] = []
    raw_results = response.get("results", [])
    if not isinstance(raw_results, Sequence) or isinstance(
        raw_results, (str, bytes, bytearray)
    ):
        raw_results = []

    for raw_result in raw_results:
        if not isinstance(raw_result, Mapping):
            continue
        result_obj = json_object(raw_result, "endpoint.results[]")
        observed = None
        raw_observed = result_obj.get("observed_response")
        if isinstance(raw_observed, Mapping):
            observed_obj = json_object(raw_observed, "endpoint.observed_response")
            observed = ObservedResponse(
                case=str(observed_obj.get("case", result_obj.get("case", ""))),
                sequence=int(observed_obj.get("sequence", result_obj.get("sequence", 0))),
                endpoint_role=str(observed_obj.get("endpoint_role", "stimulus")),
                observed=bool(observed_obj.get("observed")),
                response_type=_optional_string(observed_obj.get("response_type")),
                raw_hex=_optional_string(observed_obj.get("raw_hex")),
                decoded=json_object(observed_obj.get("decoded", {}), "observed.decoded"),
                metadata=json_object(observed_obj.get("metadata", {}), "observed.metadata"),
            )
            observed_responses.append(observed)
        results.append(
            ProbeResult(
                case=str(result_obj.get("case", "")),
                sequence=int(result_obj.get("sequence", 0)),
                status=str(result_obj.get("status", STATUS_FAILED)),
                endpoint_role=str(result_obj.get("endpoint_role", "stimulus")),
                passed=(
                    bool(result_obj["passed"])
                    if isinstance(result_obj.get("passed"), bool)
                    else None
                ),
                observed_response=observed,
                metadata=json_object(result_obj.get("metadata", {}), "result.metadata"),
            )
        )
    return results, observed_responses


def _failed_live_probe_results(
    *,
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    reason: str,
    errors: Sequence[str],
) -> tuple[list[ProbeResult], list[ObservedResponse]]:
    results: list[ProbeResult] = []
    for index, case in enumerate(planned_cases):
        plan = probe_plans[index] if index < len(probe_plans) else {}
        sequence = (
            int(plan["sequence"])
            if isinstance(plan.get("sequence"), int)
            else index
        )
        results.append(
            ProbeResult(
                case=case.name,
                sequence=sequence,
                status=STATUS_FAILED,
                endpoint_role=_primary_endpoint_role(case),
                passed=False,
                metadata={
                    "failure_reason": reason,
                    "errors": list(errors),
                    "probe_plan": plan,
                },
            )
        )
    return results, []


def _failed_counts_by_reason(results: Sequence[ProbeResult]) -> JSONObject:
    counts: dict[str, int] = {}
    for result in results:
        if result.passed is not False:
            continue
        reason = result.metadata.get("failure_reason")
        if isinstance(reason, str) and reason:
            counts[reason] = counts.get(reason, 0) + 1
    return counts


def _command_artifact_paths(command: Mapping[str, JSONValue]) -> list[str]:
    paths: list[str] = []
    for key in ("stdout_path", "stderr_path", "request_path"):
        value = command.get(key)
        if isinstance(value, str) and value:
            paths.append(value)
    return paths


def _probe_process_timeout_seconds(plan_count: int) -> int:
    return (_probe_timeout_seconds(plan_count) * max(plan_count, 1)) + 60


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _string_or(value: object, default: str) -> str:
    return value if isinstance(value, str) and value else default


def _string_list(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _json_mapping(value: object, name: str) -> JSONObject:
    if isinstance(value, Mapping):
        return json_object(value, name)
    return {}


def _json_list(value: object, name: str) -> list[JSONObject]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [
        json_object(item, f"{name}[]")
        for item in value
        if isinstance(item, Mapping)
    ]


def _dedupe_paths(paths: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(path for path in paths if path))


def _dedupe_strings(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _probe_interface(provider: str, *, dry_run: bool) -> str:
    if provider == LOCAL_DRY_RUN_PROVIDER:
        return "dry-run0"
    configured = os.environ.get("LIBCRAFTER_PRIVATE_INTERFACE")
    if configured:
        return configured
    if dry_run:
        return "eth1"
    return "auto"


def _probe_timeout_seconds(plan_count: int) -> int:
    return 3


def _failure_reasons_for_case(case_name: str) -> list[str]:
    if case_name == "icmp-echo":
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
        ]
    if case_name in {"tcp-syn-open", "tcp-syn-closed"}:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_FLAGS,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    if case_name == "dns-query":
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_WRONG_FLAGS,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    if case_name == "ttl-expired":
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
        ]
    if case_name == "arp-resolution":
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
        ]
    return []


def _capability_skip_result(
    *,
    request: ProbeRunRequest,
    case: ProbeCase,
    sequence: int,
    probe_plan: JSONObject,
    dry_run: bool,
    provider_capabilities: Mapping[str, JSONValue],
) -> tuple[ProbeSkip, ProbeResult] | None:
    missing = _missing_capabilities(case, provider_capabilities)
    if not missing:
        return None

    skip = ProbeSkip(
        case=case.name,
        sequence=sequence,
        reason=_skip_reason_for_missing_capability(case, missing[0]),
        capability=missing[0],
        metadata={
            "missing_capabilities": list(missing),
            "provider": request.provider,
            "dry_run": dry_run,
            "probe_plan": probe_plan,
        },
    )
    result = ProbeResult(
        case=case.name,
        sequence=sequence,
        status="skipped",
        endpoint_role=_primary_endpoint_role(case),
        passed=None,
        skip=skip,
        metadata={"dry_run": dry_run, "probe_plan": probe_plan},
    )
    return skip, result


def _capability_skip_state(
    *,
    request: ProbeRunRequest,
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
    provider_capabilities: Mapping[str, JSONValue],
) -> tuple[list[ProbeResult], list[ProbeSkip], dict[str, int], set[int]]:
    probe_plans_by_sequence = {
        int(plan["sequence"]): plan
        for plan in probe_plans
        if isinstance(plan.get("sequence"), int)
    }
    results: list[ProbeResult] = []
    skips: list[ProbeSkip] = []
    skip_counts: dict[str, int] = {}
    skipped_sequences: set[int] = set()
    for sequence, case in enumerate(planned_cases):
        capability_skip = _capability_skip_result(
            request=request,
            case=case,
            sequence=sequence,
            probe_plan=probe_plans_by_sequence.get(sequence, {}),
            dry_run=dry_run,
            provider_capabilities=provider_capabilities,
        )
        if capability_skip is None:
            continue
        skip, result = capability_skip
        skips.append(skip)
        results.append(result)
        skipped_sequences.add(sequence)
        skip_counts[skip.reason] = skip_counts.get(skip.reason, 0) + 1
    return results, skips, skip_counts, skipped_sequences


def _missing_capabilities(
    case: ProbeCase,
    provider_capabilities: Mapping[str, JSONValue],
) -> list[str]:
    missing: list[str] = []
    for capability in case.required_capabilities:
        if provider_capabilities.get(capability) is not True:
            missing.append(capability)
    return missing


def _skip_reason_for_missing_capability(case: ProbeCase, capability: str) -> str:
    if case.name == "ttl-expired" and capability == "controlled_router":
        return SKIP_REQUIRES_CONTROLLED_ROUTER
    if case.name == "arp-resolution" and capability in {
        "arp_resolution",
        "link_layer_send",
        "link_layer_capture",
        "broadcast",
    }:
        return SKIP_REQUIRES_LINK_LAYER
    return SKIP_CAPABILITY_UNAVAILABLE


def _primary_endpoint_role(case: ProbeCase) -> str:
    return case.endpoint_roles[0] if case.endpoint_roles else "stimulus"


def _live_status(request: ProbeRunRequest) -> str:
    if not request.confirm_live_run:
        return "requires-confirmation"
    return STATUS_UNSUPPORTED


def _target_service_setup_plan(
    *,
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
) -> JSONObject:
    tcp_open_plans = _plans_by_destination_port(
        plan for plan in probe_plans if plan.get("case") == "tcp-syn-open"
    )
    tcp_closed_plans = _plans_by_destination_port(
        plan for plan in probe_plans if plan.get("case") == "tcp-syn-closed"
    )
    dns_plans = _dns_probe_plans(probe_plans)
    dns_plans_by_port = _plans_by_destination_port(dns_plans)
    return {
        "role": "target",
        "planned": True,
        "starts_services": not dry_run and bool(tcp_open_plans or dns_plans_by_port),
        "dry_run_starts_services": False,
        "services": [
            *[
                {
                    "name": "tcp-open-listener",
                    "protocol": "tcp",
                    "port": port,
                    "purpose": "tcp-syn-open",
                    "deterministic": True,
                    **_target_service_address_fields(plan),
                }
                for port, plan in tcp_open_plans.items()
            ],
            *[
                {
                    "name": "dns-responder",
                    "protocol": "udp",
                    "port": port,
                    "purpose": "dns-query",
                    "deterministic": True,
                    "query_count": sum(
                        1
                        for plan in dns_plans
                        if int(plan.get("destination_port", 0)) == port
                    ),
                    **_target_service_address_fields(plan),
                    "log_paths": [
                        f"live-artifacts/probe/target-services/dns-responder-{port}.stdout.txt",
                        f"live-artifacts/probe/target-services/dns-responder-{port}.stderr.txt",
                    ],
                }
                for port, plan in dns_plans_by_port.items()
            ],
        ],
        "closed_tcp_ports": [
            {
                "port": port,
                "state": "verified-unbound" if not dry_run else "planned-unbound",
                "purpose": "tcp-syn-closed",
                "deterministic": True,
                **_target_service_address_fields(plan),
            }
            for port, plan in tcp_closed_plans.items()
        ],
        "controlled_router": {
            "available": False,
            "skip_reason": SKIP_REQUIRES_CONTROLLED_ROUTER,
        },
    }


def _plans_by_destination_port(plans: Iterable[JSONObject]) -> dict[int, JSONObject]:
    by_port: dict[int, JSONObject] = {}
    for plan in plans:
        port = int(plan["destination_port"])
        by_port.setdefault(port, plan)
    return by_port


def _target_service_address_fields(plan: Mapping[str, JSONValue]) -> JSONObject:
    target_service = _json_mapping(
        plan.get("target_service", {}),
        "probe_plan.target_service",
    )
    bind_ipv4 = _string_or(
        target_service.get("bind_ipv4"),
        _string_or(plan.get("destination_ipv4"), ""),
    )
    source_ipv4 = _string_or(
        target_service.get("source_ipv4"),
        _string_or(plan.get("source_ipv4"), ""),
    )
    fields: JSONObject = {}
    if bind_ipv4:
        fields["bind_ipv4"] = bind_ipv4
    if source_ipv4:
        fields["source_ipv4"] = source_ipv4
    return fields


def _report_path(
    out: str | None,
    *,
    request: ProbeRunRequest,
    status: str,
) -> Path:
    if out:
        output = Path(out)
    else:
        output = DEFAULT_OUTPUT_ROOT / _run_name(request=request, status=status)
    if not output.is_absolute():
        output = REPO_ROOT / output
    if output.suffix == ".json":
        return output
    return output / "report.json"


def _run_name(*, request: ProbeRunRequest, status: str) -> str:
    return "-".join(
        _slug(part)
        for part in (
            status,
            request.provider,
            request.profile,
            f"seed-{request.seed}",
            f"count-{request.count}",
        )
        if part
    )


def _slug(value: object) -> str:
    raw = str(value).strip().lower()
    chars = [char if char.isalnum() else "-" for char in raw]
    slug = "-".join(part for part in "".join(chars).split("-") if part)
    return slug or "run"


def _requested_command() -> str:
    return shlex.join(["tools/probe/run", *sys.argv[1:]])


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return _run(args)


if __name__ == "__main__":
    raise SystemExit(main())
