"""Deterministic SCTP probe cases and packet plans."""

from __future__ import annotations
from collections.abc import Mapping
from ..case_helpers import _behavior_case
from ..model import JSONObject, JSONValue, ProbeCase
from ..planning_helpers import deterministic_bytes
from .base import ProtocolPlugin, register

SCTP_SMOKE_PROFILE = "sctp-smoke"
SCTP_SERVICE_KIND = "sctp-controlled-peer"
SCTP_STIMULUS_DRIVER = "sctp_probe"
SCTP_ADAPTER_MODULE = "tools/probe/adapters/src/sctp.rs"
SCTP_DOCUMENTATION_IPV4_PREFIX = "198.51.100.0/24"
SCTP_UDP_ENCAP_PORT = 9899
SCTP_DEFAULT_DST_PORT = 5000
_SCTP_CAPABILITIES = ["sctp_controlled_peer"]
SCTP_PROBE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="sctp-native-data-exchange",
        description="Plan a native SCTP DATA exchange with a controlled peer.",
        stimulus="sctp_data",
        expected_response="sctp_data_ack",
        required_capabilities=_SCTP_CAPABILITIES,
        protocol="sctp",
        metadata={
            "service": SCTP_SERVICE_KIND,
            "transport": "sctp",
            "message_kind": "data",
            "planned_only": True,
            "live_capable": True,
            "ip_protocol": 132,
            "sctp_port": SCTP_DEFAULT_DST_PORT,
        },
    ),
    _behavior_case(
        name="sctp-init-handshake-plan",
        description="Plan INIT / INIT ACK association precondition with cookie preservation.",
        stimulus="sctp_init",
        expected_response="sctp_init_ack",
        required_capabilities=_SCTP_CAPABILITIES,
        protocol="sctp",
        metadata={
            "service": SCTP_SERVICE_KIND,
            "transport": "sctp",
            "message_kind": "init",
            "planned_only": True,
            "live_capable": True,
            "ip_protocol": 132,
            "sctp_port": SCTP_DEFAULT_DST_PORT,
        },
    ),
    _behavior_case(
        name="sctp-udp-encap-data-exchange",
        description="Plan an RFC 6951 UDP-encapsulated SCTP DATA exchange.",
        stimulus="sctp_udp_encap_data",
        expected_response="sctp_udp_encap_data_ack",
        required_capabilities=_SCTP_CAPABILITIES,
        protocol="sctp",
        metadata={
            "service": SCTP_SERVICE_KIND,
            "transport": "udp+sctp",
            "message_kind": "udp_encapsulated_data",
            "planned_only": True,
            "live_capable": True,
            "udp_port": SCTP_UDP_ENCAP_PORT,
            "sctp_port": SCTP_DEFAULT_DST_PORT,
        },
    ),
    _behavior_case(
        name="sctp-abort-error-observation",
        description="Plan SCTP ABORT/error-cause observation from a controlled peer.",
        stimulus="sctp_abort",
        expected_response="sctp_abort_observed",
        required_capabilities=_SCTP_CAPABILITIES,
        protocol="sctp",
        metadata={
            "service": SCTP_SERVICE_KIND,
            "transport": "sctp",
            "message_kind": "abort",
            "planned_only": True,
            "live_capable": True,
            "ip_protocol": 132,
            "sctp_port": SCTP_DEFAULT_DST_PORT,
        },
    ),
)
_SCTP_CASE_BY_NAME: dict[str, ProbeCase] = {
    case.name: case for case in SCTP_PROBE_CASES
}
_SCTP_PLANNED_ONLY_CASES = frozenset(_SCTP_CASE_BY_NAME)


def _sctp_probe_plan(
    *, case_name: str, profile: str, seed: int, sequence: int
) -> JSONObject:
    case = _SCTP_CASE_BY_NAME[case_name]
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    source_ipv4, target_ipv4 = _documentation_ipv4_pair(digest)
    source_port = _ephemeral_port(digest)
    destination_port = SCTP_DEFAULT_DST_PORT + digest[3] % 4
    verification_tag = int.from_bytes(digest[4:8], "big")
    initial_tsn = int.from_bytes(digest[8:12], "big")
    message_kind = str(case.metadata["message_kind"])
    transport = str(case.metadata["transport"])
    chunks = _chunks_for_case(case_name)
    packet_stack = (
        ["ipv4", "udp", "sctp"] if transport == "udp+sctp" else ["ipv4", "sctp"]
    )
    packet_layers: JSONObject = {
        "ipv4": {
            "src": source_ipv4,
            "dst": target_ipv4,
            "protocol": "udp" if transport == "udp+sctp" else "sctp",
        },
        "sctp": {
            "src_port": source_port,
            "dst_port": destination_port,
            "verification_tag": verification_tag,
            "initial_tsn": initial_tsn,
            "chunks": chunks,
        },
    }
    if transport == "udp+sctp":
        packet_layers["udp"] = {
            "src_port": SCTP_UDP_ENCAP_PORT,
            "dst_port": SCTP_UDP_ENCAP_PORT,
            "encapsulated_protocol": "sctp",
        }
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        "planned_only": True,
        "live_capable": True,
        "protocol": "sctp",
        "transport": transport,
        "message_kind": message_kind,
        "source_ipv4": source_ipv4,
        "destination_ipv4": target_ipv4,
        "target_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": source_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "documentation_prefixes": [SCTP_DOCUMENTATION_IPV4_PREFIX],
        "packet": {"stack": packet_stack, "layers": packet_layers},
        "sctp": {
            "message_kind": message_kind,
            "chunks": chunks,
            "validation": {
                "expected_decode": "sctp",
                "message_kind": message_kind,
                "chunks": chunks,
                "planned_only": True,
            },
        },
        "expected_response_packet": {
            "stack": packet_stack,
            "layers": _expected_layers(packet_layers, target_ipv4, source_ipv4),
        },
        "capture_filter": _capture_filter(
            transport=transport,
            source_ipv4=source_ipv4,
            target_ipv4=target_ipv4,
            source_port=source_port,
            destination_port=destination_port,
        ),
        "wire_requirements": {
            "requires_ipv4_unicast": True,
            "requires_controlled_service": True,
            "requires_sctp_controlled_peer": True,
            "requires_live_network": True,
            "dry_run_only_until_adapter": True,
        },
        "stimulus_driver": {
            "name": SCTP_STIMULUS_DRIVER,
            "adapter_module": SCTP_ADAPTER_MODULE,
            "state": "planned-only",
            "planned_only": True,
        },
        "required_capabilities": list(case.required_capabilities),
        "skip_reasons": {
            "capability": ["requires_sctp_controlled_peer"],
            "failure": sctp_failure_reasons(case_name) or [],
        },
        "digest_hex": digest.hex()[:16],
    }


def _chunks_for_case(case_name: str) -> list[str]:
    if case_name == "sctp-init-handshake-plan":
        return ["init"]
    if case_name == "sctp-abort-error-observation":
        return ["abort"]
    return ["data"]


def _expected_layers(
    layers: Mapping[str, JSONValue], target_ipv4: str, source_ipv4: str
) -> JSONObject:
    expected = {name: value for name, value in layers.items()}
    ipv4 = dict(expected["ipv4"]) if isinstance(expected["ipv4"], Mapping) else {}
    ipv4["src"] = target_ipv4
    ipv4["dst"] = source_ipv4
    expected["ipv4"] = ipv4
    sctp = dict(expected["sctp"]) if isinstance(expected["sctp"], Mapping) else {}
    src_port = sctp.get("src_port")
    sctp["src_port"] = sctp.get("dst_port")
    sctp["dst_port"] = src_port
    expected["sctp"] = sctp
    return expected


def _capture_filter(
    *,
    transport: str,
    source_ipv4: str,
    target_ipv4: str,
    source_port: int,
    destination_port: int,
) -> str:
    if transport == "udp+sctp":
        return f"udp and src host {target_ipv4} and dst host {source_ipv4} and src port {SCTP_UDP_ENCAP_PORT} and dst port {SCTP_UDP_ENCAP_PORT}"
    return f"sctp and src host {target_ipv4} and dst host {source_ipv4} and src port {destination_port} and dst port {source_port}"


def _documentation_ipv4_pair(digest: bytes) -> tuple[str, str]:
    source_host = 1 + digest[0] % 120
    target_host = 121 + digest[1] % 120
    return (f"198.51.100.{source_host}", f"198.51.100.{target_host}")


def _ephemeral_port(digest: bytes) -> int:
    return 49152 + int.from_bytes(digest[0:2], "big") % 12000


def sctp_failure_reasons(case_name: str) -> list[str] | None:
    return None


_SCTP_PLAN_BUILDERS = {case.name: _sctp_probe_plan for case in SCTP_PROBE_CASES}
register(
    ProtocolPlugin(
        name="sctp",
        cases=SCTP_PROBE_CASES,
        plan_builders=_SCTP_PLAN_BUILDERS,
        planned_only_cases=_SCTP_PLANNED_ONLY_CASES,
        profile_counts={
            SCTP_SMOKE_PROFILE: {case.name: 1 for case in SCTP_PROBE_CASES}
        },
        stimulus_endpoint_cases=frozenset(),
        failure_reasons=sctp_failure_reasons,
    )
)
