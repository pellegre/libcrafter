"""SNMP probe protocol plugin: dry-run peer plans and target service metadata."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..capability_derivation import capability, capability_default_true
from ..case_helpers import _behavior_case
from ..model import JSONObject, JSONValue, ProbeCase
from ..planning_helpers import deterministic_bytes
from ..target_service_helpers import (
    plans_by_destination_port,
    target_service_address_fields,
)
from .base import ProtocolPlugin, register


SNMP_SERVICE_KIND = "snmp-controlled-peer"
SNMP_RUNTIME = "probe-snmp-reference"
SNMP_AGENT_PORT = 161
SNMP_NOTIFICATION_PORT = 162
SNMP_DOCUMENTATION_IPV4_PREFIX = "198.51.100.0/24"
SNMP_STIMULUS_DRIVER = "snmp_probe"
SNMP_ADAPTER_SOURCE = "tools/probe/adapters/src/snmp.rs"
_SNMP_CAPABILITIES = ["snmp_peer"]


_SNMP_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="snmp-get-response",
        description="Plan a controlled SNMPv2c GetRequest and Response exchange.",
        stimulus="snmp_get_request",
        expected_response="snmp_response",
        required_capabilities=_SNMP_CAPABILITIES,
        protocol="snmp",
        metadata={
            "service": SNMP_SERVICE_KIND,
            "stateful": True,
            "planned_only": True,
            "udp_port": SNMP_AGENT_PORT,
        },
    ),
    _behavior_case(
        name="snmp-getbulk-response",
        description="Plan a controlled SNMPv2c GetBulkRequest and Response exchange.",
        stimulus="snmp_getbulk_request",
        expected_response="snmp_response",
        required_capabilities=_SNMP_CAPABILITIES,
        protocol="snmp",
        metadata={
            "service": SNMP_SERVICE_KIND,
            "stateful": True,
            "planned_only": True,
            "udp_port": SNMP_AGENT_PORT,
        },
    ),
    _behavior_case(
        name="snmp-notification-trap",
        description="Plan an SNMPv2-Trap notification delivered to a controlled sink.",
        stimulus="snmp_trap_notification",
        expected_response="snmp_notification_observed",
        required_capabilities=_SNMP_CAPABILITIES,
        protocol="snmp",
        metadata={
            "service": SNMP_SERVICE_KIND,
            "stateful": False,
            "planned_only": True,
            "udp_port": SNMP_NOTIFICATION_PORT,
        },
    ),
    _behavior_case(
        name="snmpv3-engine-discovery-report",
        description="Plan an SNMPv3 engine-discovery probe and Report response.",
        stimulus="snmpv3_engine_discovery",
        expected_response="snmpv3_report",
        required_capabilities=_SNMP_CAPABILITIES,
        protocol="snmp",
        metadata={
            "service": SNMP_SERVICE_KIND,
            "stateful": True,
            "planned_only": True,
            "udp_port": SNMP_AGENT_PORT,
        },
    ),
)


_SNMP_CASE_CONFIG: dict[str, JSONObject] = {
    "snmp-get-response": {
        "version": "v2c",
        "community": "doc-community",
        "request_pdu": "get_request",
        "response_pdu": "response",
        "destination_port": SNMP_AGENT_PORT,
        "oid": "1.3.6.1.2.1.1.1.0",
        "value": {"kind": "octet_string", "text": "doc-system"},
        "service_mode": "agent",
    },
    "snmp-getbulk-response": {
        "version": "v2c",
        "community": "doc-community",
        "request_pdu": "get_bulk_request",
        "response_pdu": "response",
        "destination_port": SNMP_AGENT_PORT,
        "oid": "1.3.6.1.2.1.1.3.0",
        "non_repeaters": 0,
        "max_repetitions": 2,
        "value": {"kind": "time_ticks", "ticks": 123456},
        "service_mode": "agent",
    },
    "snmp-notification-trap": {
        "version": "v2c",
        "community": "doc-community",
        "request_pdu": "snmpv2_trap",
        "response_pdu": "notification_observed",
        "destination_port": SNMP_NOTIFICATION_PORT,
        "oid": "1.3.6.1.6.3.1.1.5.1",
        "value": {"kind": "object_identifier", "oid": "1.3.6.1.6.3.1.1.5.1"},
        "service_mode": "notification_sink",
    },
    "snmpv3-engine-discovery-report": {
        "version": "v3",
        "request_pdu": "get_request",
        "response_pdu": "report",
        "destination_port": SNMP_AGENT_PORT,
        "oid": "1.3.6.1.6.3.15.1.1.4.0",
        "value": {"kind": "counter32", "value": 1},
        "engine_id": {"hex": "80000000646f632d656e67696e65"},
        "user_name": "doc-user",
        "security_model": "usm",
        "msg_flags": [],
        "service_mode": "agent",
    },
}


def _snmp_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    case = _case(case_name)
    config = dict(_SNMP_CASE_CONFIG[case_name])
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    source_ipv4, target_ipv4 = _snmp_documentation_ipv4_pair(digest)
    source_port = 42000 + int.from_bytes(digest[0:2], "big") % 10000
    request_id = int.from_bytes(digest[2:6], "big") & 0x7FFFFFFF
    destination_port = int(config["destination_port"])
    service_mode = str(config["service_mode"])

    snmp_request: JSONObject = {
        "version": str(config["version"]),
        "pdu": str(config["request_pdu"]),
        "request_id": request_id,
        "oid": str(config["oid"]),
    }
    if "community" in config:
        snmp_request["community"] = str(config["community"])
    for key in ("non_repeaters", "max_repetitions", "engine_id", "user_name"):
        if key in config:
            snmp_request[key] = config[key]
    if "security_model" in config:
        snmp_request["security_model"] = str(config["security_model"])
    msg_flags = config.get("msg_flags")
    if isinstance(msg_flags, list):
        snmp_request["msg_flags"] = list(msg_flags)

    expected_response: JSONObject = {
        "version": str(config["version"]),
        "pdu": str(config["response_pdu"]),
        "request_id": request_id,
        "oid": str(config["oid"]),
        "value": config["value"],
    }
    if "community" in config:
        expected_response["community"] = str(config["community"])
    if "engine_id" in config:
        expected_response["engine_id"] = config["engine_id"]
        expected_response["security_model"] = str(config["security_model"])

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
        "protocol": "snmp",
        "source_ipv4": source_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": source_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "documentation_prefixes": [SNMP_DOCUMENTATION_IPV4_PREFIX],
        "snmp_request": snmp_request,
        "expected_snmp_response": expected_response,
        "stimulus_driver": {
            "name": SNMP_STIMULUS_DRIVER,
            "adapter_source": SNMP_ADAPTER_SOURCE,
            "state": "planned-only",
            "planned_only": True,
        },
        "target_service": {
            "required": True,
            "kind": SNMP_SERVICE_KIND,
            "protocol": "udp",
            "port": destination_port,
            "bind_ipv4": target_ipv4,
            "source_ipv4": source_ipv4,
            "runtime": SNMP_RUNTIME,
            "service_mode": service_mode,
            "deterministic": True,
        },
        "capture_filter": (
            f"udp and host {target_ipv4} "
            f"and port {destination_port}"
        ),
        "validation": {
            "planned_only": True,
            "driver": SNMP_STIMULUS_DRIVER,
            "source_ipv4": target_ipv4,
            "destination_ipv4": source_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "response_pdu": str(config["response_pdu"]),
            "service_mode": service_mode,
        },
        "wire_requirements": {
            "requires_ipv4_unicast": True,
            "requires_controlled_service": True,
            "requires_snmp_peer": True,
            "dry_run_only_until_adapter": True,
            "note": (
                "SNMP smoke dry-run exposes controlled peer setup and "
                "source-backed wire intent without sending UDP/161 or UDP/162 "
                "traffic."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _case(case_name: str) -> ProbeCase:
    for case in _SNMP_CASES:
        if case.name == case_name:
            return case
    raise KeyError(case_name)


def _snmp_documentation_ipv4_pair(digest: bytes) -> tuple[str, str]:
    source_host = 1 + digest[6] % 120
    target_host = 121 + digest[7] % 120
    return f"198.51.100.{source_host}", f"198.51.100.{target_host}"


_SNMP_PLAN_BUILDERS: dict[str, object] = {
    case.name: _snmp_probe_plan for case in _SNMP_CASES
}


_SNMP_PLANNED_ONLY_CASES: frozenset[str] = frozenset(_SNMP_PLAN_BUILDERS)


def snmp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    return [plan for plan in probe_plans if plan.get("case") in _SNMP_PLANNED_ONLY_CASES]


def snmp_target_service_contribution(
    probe_plans: Sequence[JSONObject],
    *,
    dry_run: bool,
) -> JSONObject:
    snmp_plans = snmp_probe_plans(probe_plans)
    snmp_plans_by_port = plans_by_destination_port(snmp_plans)
    services = [
        {
            "name": SNMP_SERVICE_KIND,
            "protocol": "udp",
            "port": port,
            "purpose": _snmp_service_purpose(port),
            "runtime": SNMP_RUNTIME,
            "deterministic": True,
            "planned_only": True,
            "query_count": sum(
                1
                for item in snmp_plans
                if int(item.get("destination_port", 0)) == port
            ),
            **target_service_address_fields(plan),
            "log_paths": [
                f"live-artifacts/probe/target-services/snmp-peer-{port}.stdout.txt",
                f"live-artifacts/probe/target-services/snmp-peer-{port}.stderr.txt",
            ],
        }
        for port, plan in snmp_plans_by_port.items()
    ]
    return {
        "services": services,
        "starts_services": not dry_run and bool(snmp_plans_by_port),
    }


def _snmp_service_purpose(port: int) -> str:
    if port == SNMP_NOTIFICATION_PORT:
        return "snmp-notification-sink"
    return "snmp-agent"


def snmp_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    controlled_services = capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    return {
        "snmp_peer": (
            ipv4_unicast
            and controlled_services
            and capability_default_true(substrate, "snmp_peer")
        ),
    }


register(
    ProtocolPlugin(
        name="snmp",
        cases=_SNMP_CASES,
        plan_builders=_SNMP_PLAN_BUILDERS,
        planned_only_cases=_SNMP_PLANNED_ONLY_CASES,
        profile_counts={},
        stimulus_endpoint_cases=frozenset(),
        target_service=snmp_target_service_contribution,
        setup_script=None,
        rewrite_endpoint_addresses=None,
        failure_reasons=None,
        lab_capabilities=snmp_lab_capabilities,
    )
)
