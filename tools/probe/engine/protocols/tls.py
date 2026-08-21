"""Deterministic TLS probe cases and packet plans."""

from __future__ import annotations
from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import deterministic_bytes, deterministic_ipv4_pair
from .base import ProtocolPlugin, register

TLS_SMOKE_PROFILE = "tls-smoke"
TLS_SERVICE_KIND = "tls-controlled-service"
TLS_PORT = 4433
TLS_STIMULUS_DRIVER = "tls_probe"
TLS_ADAPTER_SOURCE = "tools/probe/adapters/src/tls.rs"
TLS_DOCUMENTATION_IPV4_PREFIX = "198.51.100.0/24"
_TLS_CAPABILITIES = ["tls_controlled_service"]
TLS_PROBE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="tls-clienthello-observation",
        description="Plan a controlled TLS ClientHello and capture the listener observation.",
        stimulus="tls_client_hello",
        expected_response="tls_clienthello_observed",
        required_capabilities=_TLS_CAPABILITIES,
        protocol="tls",
        metadata={
            "service": TLS_SERVICE_KIND,
            "planned_only": True,
            "tcp_port": TLS_PORT,
            "record_kind": "handshake",
        },
    ),
    _behavior_case(
        name="tls-alert-observation",
        description="Plan a TLS alert record and capture the controlled listener observation.",
        stimulus="tls_alert_record",
        expected_response="tls_alert_observed",
        required_capabilities=_TLS_CAPABILITIES,
        protocol="tls",
        metadata={
            "service": TLS_SERVICE_KIND,
            "planned_only": True,
            "tcp_port": TLS_PORT,
            "record_kind": "alert",
        },
    ),
    _behavior_case(
        name="tls-application-data-capture",
        description="Plan opaque TLS application_data bytes for controlled capture.",
        stimulus="tls_application_data",
        expected_response="tls_application_data_observed",
        required_capabilities=_TLS_CAPABILITIES,
        protocol="tls",
        metadata={
            "service": TLS_SERVICE_KIND,
            "planned_only": True,
            "tcp_port": TLS_PORT,
            "record_kind": "application_data",
        },
    ),
)


def _tls_probe_plan(
    *, case_name: str, profile: str, seed: int, sequence: int
) -> JSONObject:
    case = _case(case_name)
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    source_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 49152 + int.from_bytes(digest[0:2], "big") % 12000
    payload = _tls_payload_for_case(case_name, digest)
    record = _tls_record_for_case(case_name, payload)
    capture_filter = f"tcp and port {TLS_PORT}"
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
        "protocol": "tls",
        "source_ipv4": source_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": source_ipv4,
        "source_port": source_port,
        "destination_port": TLS_PORT,
        "documentation_prefixes": [TLS_DOCUMENTATION_IPV4_PREFIX],
        "packet": {
            "stack": ["ipv4", "tcp", "tls"],
            "root": "l3:ipv4",
            "ipv4": {
                "src": source_ipv4,
                "dst": target_ipv4,
                "ttl": 64,
                "protocol": "tcp",
            },
            "tcp": {
                "src_port": source_port,
                "dst_port": TLS_PORT,
                "flags": "psh|ack",
                "sequence": int.from_bytes(digest[2:6], "big"),
                "acknowledgement": int.from_bytes(digest[6:10], "big"),
                "window": 8192,
            },
            "tls": {
                "record_content_type": record["content_type"],
                "record_legacy_version": 771,
                "record_fragment_hex": str(record["fragment_hex"]),
                "records": [record],
            },
        },
        "tls": {
            "service_name": TLS_SERVICE_KIND,
            "record": record,
            "expected_observation": {
                "record_content_type": record["content_type"],
                "fragment_hex": str(record["fragment_hex"]),
                "capture_filter": capture_filter,
            },
        },
        "expected_records": [
            {
                "content_type": record["content_type"],
                "legacy_record_version": 771,
                "fragment_hex": str(record["fragment_hex"]),
            }
        ],
        "capture": {
            "interface_role": "target",
            "filter": capture_filter,
            "artifacts": [
                "tls-listener.log",
                "tls-capture.pcap",
                "tls-observed-records.json",
            ],
        },
        "stimulus_driver": {
            "name": TLS_STIMULUS_DRIVER,
            "adapter_source": TLS_ADAPTER_SOURCE,
            "state": "planned-only",
            "planned_only": True,
        },
        "safety": {"default_mode": "dry_run", "developer_host_raw_send": False},
    }


def _tls_payload_for_case(case_name: str, digest: bytes) -> bytes:
    if case_name == "tls-clienthello-observation":
        random = bytes([19]) * 32
        session_id = bytes(digest[10:18])
        cipher_suites = bytes.fromhex("13011303")
        compression = b"\x00"
        extensions = bytes.fromhex("001000050003026832")
        body = (
            b"\x03\x03"
            + random
            + bytes([len(session_id)])
            + session_id
            + len(cipher_suites).to_bytes(2, "big")
            + cipher_suites
            + bytes([len(compression)])
            + compression
            + len(extensions).to_bytes(2, "big")
            + extensions
        )
        return b"\x01" + len(body).to_bytes(3, "big") + body
    if case_name == "tls-alert-observation":
        return bytes([2, 50])
    return bytes.fromhex("170303") + digest[:8]


def _tls_record_for_case(case_name: str, payload: bytes) -> JSONObject:
    if case_name == "tls-alert-observation":
        return {
            "content_type": "alert",
            "body_kind": "alert",
            "fragment_hex": payload.hex(),
            "alert_level": "fatal",
            "alert_description": "decode_error",
            "legacy_record_version": 771,
        }
    if case_name == "tls-application-data-capture":
        return {
            "content_type": "application_data",
            "body_kind": "application_data",
            "fragment_hex": payload.hex(),
            "application_data_hex": payload.hex(),
            "legacy_record_version": 771,
        }
    return {
        "content_type": "handshake",
        "body_kind": "handshake",
        "fragment_hex": payload.hex(),
        "handshake_messages": [
            {
                "handshake_type": "client_hello",
                "handshake_type_raw": 1,
                "handshake_length": len(payload) - 4,
                "body_hex": payload[4:].hex(),
            }
        ],
        "legacy_record_version": 771,
    }


def _case(case_name: str) -> ProbeCase:
    for case in TLS_PROBE_CASES:
        if case.name == case_name:
            return case
    raise ValueError(f"unknown TLS probe case {case_name!r}")


def _tls_failure_reasons(case_name: str) -> list[str] | None:
    if case_name not in _TLS_PLAN_BUILDERS:
        return None
    return [
        "execution environment lacks tls_controlled_service",
        "target TLS service precondition failed",
        "TLS record was not observed",
        "captured record did not match planned content type",
        "captured record bytes did not match planned stimulus",
        "capture timed out",
    ]


_TLS_PLAN_BUILDERS: dict[str, object] = {
    case.name: _tls_probe_plan for case in TLS_PROBE_CASES
}
_TLS_PLANNED_ONLY_CASES: frozenset[str] = frozenset(_TLS_PLAN_BUILDERS)
register(
    ProtocolPlugin(
        name="tls",
        cases=TLS_PROBE_CASES,
        plan_builders=_TLS_PLAN_BUILDERS,
        planned_only_cases=_TLS_PLANNED_ONLY_CASES,
        profile_counts={TLS_SMOKE_PROFILE: {case.name: 1 for case in TLS_PROBE_CASES}},
        failure_reasons=_tls_failure_reasons,
    )
)
