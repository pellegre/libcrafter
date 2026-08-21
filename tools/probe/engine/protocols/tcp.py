"""Deterministic TCP probe cases and packet plans."""

from __future__ import annotations
from ..model import JSONObject, ProbeCase
from ..planning_helpers import deterministic_bytes, deterministic_ipv4_pair
from .base import ProtocolPlugin, register

TCP_SYN_OPEN_CASE: ProbeCase = ProbeCase(
    name="tcp-syn-open",
    description="Send TCP SYN to controlled listener and validate SYN/ACK.",
    stimulus="tcp_syn",
    expected_response="tcp_syn_ack",
    required_capabilities=["tcp_open_port"],
    endpoint_roles=["stimulus", "target"],
    metadata={"protocol": "tcp", "service": "controlled_listener"},
)
TCP_SYN_CLOSED_CASE: ProbeCase = ProbeCase(
    name="tcp-syn-closed",
    description="Send TCP SYN to closed port and validate RST response.",
    stimulus="tcp_syn",
    expected_response="tcp_rst",
    required_capabilities=["tcp_closed_port"],
    endpoint_roles=["stimulus", "target"],
    metadata={"protocol": "tcp", "service": "kernel"},
)
TCP_SYN_OPTIONS_CASE: ProbeCase = ProbeCase(
    name="tcp-syn-options",
    description="Send a TCP SYN carrying a representative option set (MSS, Window Scale, SACK-Permitted, Timestamp, User Timeout) to a controlled listener and validate the SYN/ACK.",
    stimulus="tcp_syn",
    expected_response="tcp_syn_ack",
    required_capabilities=["tcp_open_port"],
    endpoint_roles=["stimulus", "target"],
    metadata={"protocol": "tcp", "service": "controlled_listener"},
)


def _tcp_syn_probe_plan(
    *, case_name: str, profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 61000 + int.from_bytes(digest[0:2], "big") % 4000
    destination_base = 18000 if case_name == "tcp-syn-open" else 22000
    destination_port = destination_base + int.from_bytes(digest[2:4], "big") % 3000
    sequence_number = int.from_bytes(digest[4:8], "big")
    expected_ack = sequence_number + 1 & 4294967295
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
        "stimulus_rst_guard": {
            "required": True,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": target_ipv4,
            "source_port": source_port,
            "destination_port": destination_port,
        },
        "capture_filter": f"tcp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
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


def _tcp_syn_options_probe_plan(
    *, case_name: str = "tcp-syn-options", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 61000 + int.from_bytes(digest[0:2], "big") % 4000
    destination_port = 18000 + int.from_bytes(digest[2:4], "big") % 3000
    sequence_number = int.from_bytes(digest[4:8], "big")
    expected_ack = sequence_number + 1 & 4294967295
    window_scale_shift = digest[8] % 15
    mss_value = 1460
    timestamp_value = int.from_bytes(digest[9:13], "big")
    user_timeout_value = 1 + int.from_bytes(digest[13:15], "big") % 32766
    tcp_options = [
        {"kind": "mss", "kind_value": 2, "mss": mss_value},
        {"kind": "sack_permitted", "kind_value": 4},
        {
            "kind": "timestamp",
            "kind_value": 8,
            "timestamp_value": timestamp_value,
            "timestamp_echo_reply": 0,
        },
        {"kind": "nop", "kind_value": 1},
        {
            "kind": "window_scale",
            "kind_value": 3,
            "window_scale_shift": window_scale_shift,
        },
        {
            "kind": "user_timeout",
            "kind_value": 28,
            "user_timeout_granularity": False,
            "user_timeout_value": user_timeout_value,
        },
    ]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "tcp_syn",
        "expected_response": "tcp_syn_ack",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_sequence_number": sequence_number,
        "expected_acknowledgment_number": expected_ack,
        "window": 64240,
        "tcp_options": tcp_options,
        "stimulus_rst_guard": {
            "required": True,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": target_ipv4,
            "source_port": source_port,
            "destination_port": destination_port,
        },
        "capture_filter": f"tcp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "flags": ["syn", "ack"],
            "acknowledgment_number": expected_ack,
            "allow_rst_ack": False,
        },
    }


_TCP_PLAN_BUILDERS: dict[str, object] = {
    "tcp-syn-open": _tcp_syn_probe_plan,
    "tcp-syn-closed": _tcp_syn_probe_plan,
    "tcp-syn-options": _tcp_syn_options_probe_plan,
}
_TCP_STIMULUS_ENDPOINT_CASES: frozenset[str] = frozenset(
    {"tcp-syn-open", "tcp-syn-closed", "tcp-syn-options"}
)


def tcp_failure_reasons(case_name: str) -> list[str] | None:
    return None


register(
    ProtocolPlugin(
        name="tcp",
        cases=(TCP_SYN_OPEN_CASE, TCP_SYN_CLOSED_CASE, TCP_SYN_OPTIONS_CASE),
        plan_builders=_TCP_PLAN_BUILDERS,
        planned_only_cases=frozenset(),
        profile_counts={},
        stimulus_endpoint_cases=_TCP_STIMULUS_ENDPOINT_CASES,
        failure_reasons=tcp_failure_reasons,
    )
)
