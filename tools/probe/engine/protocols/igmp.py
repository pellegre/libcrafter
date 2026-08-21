"""Deterministic IGMP probe cases and packet plans."""

from __future__ import annotations
from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import deterministic_bytes, deterministic_ipv4_pair
from .base import ProtocolPlugin, register

_IGMP_CAPABILITIES = ["ipv4_multicast", "igmp_peer"]
IGMP_PROBE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="igmp-membership-query-observation",
        description="Observe a controlled peer's IGMP Membership Query on the isolated multicast segment.",
        stimulus="igmp_query_observation",
        expected_response="igmp_membership_query",
        required_capabilities=_IGMP_CAPABILITIES,
        protocol="igmp",
        metadata={
            "service": "igmp-router",
            "layer": "network",
            "ipv4_only": True,
            "planned_only": True,
        },
    ),
    _behavior_case(
        name="igmp-v2-membership-report-emission",
        description="Emit an IGMPv2 Membership Report to a documentation multicast group and plan peer observation.",
        stimulus="igmp_v2_membership_report",
        expected_response="igmp_membership_report_observed",
        required_capabilities=_IGMP_CAPABILITIES,
        protocol="igmp",
        metadata={
            "service": "igmp-listener",
            "layer": "network",
            "ipv4_only": True,
            "planned_only": True,
        },
    ),
    _behavior_case(
        name="igmp-v2-leave-group-emission",
        description="Emit an IGMPv2 Leave Group message toward the all-routers group and plan peer observation.",
        stimulus="igmp_v2_leave_group",
        expected_response="igmp_leave_group_observed",
        required_capabilities=_IGMP_CAPABILITIES,
        protocol="igmp",
        metadata={
            "service": "igmp-listener",
            "layer": "network",
            "ipv4_only": True,
            "planned_only": True,
        },
    ),
    _behavior_case(
        name="igmp-v3-source-list-report",
        description="Emit an IGMPv3 Membership Report carrying a deterministic MODE_IS_INCLUDE source list.",
        stimulus="igmp_v3_source_list_report",
        expected_response="igmp_v3_report_observed",
        required_capabilities=_IGMP_CAPABILITIES,
        protocol="igmp",
        metadata={
            "service": "igmp-listener",
            "layer": "network",
            "ipv4_only": True,
            "planned_only": True,
            "record_type": "mode_is_include",
        },
    ),
)
_IGMP_IP_PROTOCOL = 2
_IGMP_DEFAULT_TTL = 1
_IGMP_ALL_SYSTEMS_GROUP = "224.0.0.1"
_IGMP_ALL_ROUTERS_GROUP = "224.0.0.2"
_IGMPV3_REPORT_DESTINATION = "224.0.0.22"
_IGMP_DOCUMENTATION_MULTICAST_PREFIX = "233.252.0.0/24"
_IGMP_DOCUMENTATION_SOURCE_PREFIXES = ["192.0.2.0/24", "198.51.100.0/24"]


def _igmp_probe_plan(
    *, case_name: str, profile: str, seed: int, sequence: int
) -> JSONObject:
    from ..cases import PROBE_CASE_BY_NAME

    case = PROBE_CASE_BY_NAME[case_name]
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    group_address = deterministic_igmp_group(profile, seed, sequence)
    source_list = deterministic_igmp_source_list(profile, seed, sequence)
    if case_name == "igmp-membership-query-observation":
        destination_ipv4 = _IGMP_ALL_SYSTEMS_GROUP
        stimulus_shape: JSONObject = {
            "direction": "observe",
            "sender_role": "router",
            "igmp_type": 0x11,
            "message": "membership_query",
            "max_response_time_tenths": 10,
            "group_address": "0.0.0.0",
        }
        expected_shape = {
            **stimulus_shape,
            "source_ipv4": target_ipv4,
            "destination_ipv4": destination_ipv4,
        }
        validation: JSONObject = {
            "planned_only": True,
            "driver": "igmp_query_observation",
            "source_ipv4": target_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x11,
            "group_address": "0.0.0.0",
            "max_response_time_tenths": 10,
        }
        adapter_case = "igmp-v2-membership-query"
        capture_filter = (
            f"igmp and src host {target_ipv4} and dst host {destination_ipv4}"
        )
    elif case_name == "igmp-v2-membership-report-emission":
        destination_ipv4 = group_address
        stimulus_shape = {
            "direction": "emit",
            "igmp_type": 0x16,
            "message": "v2_membership_report",
            "group_address": group_address,
        }
        expected_shape = {
            "observer_role": "target",
            "expected_response": case.expected_response,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x16,
            "group_address": group_address,
        }
        validation = {
            "planned_only": True,
            "driver": "igmp_v2_membership_report",
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x16,
            "group_address": group_address,
        }
        adapter_case = "igmp-v2-membership-report"
        capture_filter = (
            f"igmp and src host {stimulus_ipv4} and dst host {destination_ipv4}"
        )
    elif case_name == "igmp-v2-leave-group-emission":
        destination_ipv4 = _IGMP_ALL_ROUTERS_GROUP
        stimulus_shape = {
            "direction": "emit",
            "igmp_type": 0x17,
            "message": "v2_leave_group",
            "group_address": group_address,
        }
        expected_shape = {
            "observer_role": "target",
            "expected_response": case.expected_response,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x17,
            "group_address": group_address,
        }
        validation = {
            "planned_only": True,
            "driver": "igmp_v2_leave_group",
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x17,
            "group_address": group_address,
        }
        adapter_case = "igmp-v2-leave-group"
        capture_filter = (
            f"igmp and src host {stimulus_ipv4} and dst host {destination_ipv4}"
        )
    elif case_name == "igmp-v3-source-list-report":
        destination_ipv4 = _IGMPV3_REPORT_DESTINATION
        stimulus_shape = {
            "direction": "emit",
            "igmp_type": 0x22,
            "message": "v3_membership_report",
            "record_type": "mode_is_include",
            "group_address": group_address,
            "source_addresses": source_list,
            "record_count": 1,
        }
        expected_shape = {
            "observer_role": "target",
            "expected_response": case.expected_response,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x22,
            "group_address": group_address,
            "source_addresses": source_list,
            "record_type": "mode_is_include",
        }
        validation = {
            "planned_only": True,
            "driver": "igmp_v3_source_list_report",
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x22,
            "group_address": group_address,
            "source_addresses": source_list,
            "record_type": "mode_is_include",
            "record_count": 1,
        }
        adapter_case = "igmp-v3-source-list-report"
        capture_filter = (
            f"igmp and src host {stimulus_ipv4} and dst host {destination_ipv4}"
        )
    else:
        raise ValueError(f"unsupported IGMP probe case {case_name!r}")
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
        "protocol": "igmp",
        "ip_protocol": _IGMP_IP_PROTOCOL,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": destination_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "group_address": group_address,
        "multicast_group": group_address,
        "ttl": _IGMP_DEFAULT_TTL,
        "router_alert_required": True,
        "documentation_prefixes": [
            _IGMP_DOCUMENTATION_MULTICAST_PREFIX,
            *_IGMP_DOCUMENTATION_SOURCE_PREFIXES,
        ],
        "stimulus_driver": {
            "name": case.stimulus,
            "adapter_module": "tools/probe/adapters/src/igmp.rs",
            "adapter_case": adapter_case,
            "state": "planned-only",
            "planned_only": True,
        },
        "stimulus_packet_shape": {
            "ipv4": {
                "source": stimulus_ipv4,
                "destination": destination_ipv4,
                "ttl": _IGMP_DEFAULT_TTL,
                "protocol": _IGMP_IP_PROTOCOL,
                "router_alert_required": True,
            },
            "igmp": stimulus_shape,
        },
        "expected_response_packet_shape": expected_shape,
        "capture_filter": capture_filter,
        "validation": validation,
        "wire_requirements": {
            "requires_ipv4_multicast": True,
            "requires_igmp_peer": True,
            "note": "The plan records the packet and peer-observation contract. External execution tooling must explicitly authorize any live traffic.",
        },
        "digest_hex": digest.hex()[:16],
    }


def deterministic_igmp_group(profile: str, seed: int, sequence: int) -> str:
    digest = deterministic_bytes("igmp-group", profile, seed, sequence)
    host = 1 + digest[0] % 254
    return f"233.252.0.{host}"


def deterministic_igmp_source_list(profile: str, seed: int, sequence: int) -> list[str]:
    digest = deterministic_bytes("igmp-source-list", profile, seed, sequence)
    first = 1 + digest[0] % 254
    second = 1 + digest[1] % 254
    return [f"192.0.2.{first}", f"198.51.100.{second}"]


_IGMP_PLAN_BUILDERS: dict[str, object] = {
    "igmp-membership-query-observation": _igmp_probe_plan,
    "igmp-v2-membership-report-emission": _igmp_probe_plan,
    "igmp-v2-leave-group-emission": _igmp_probe_plan,
    "igmp-v3-source-list-report": _igmp_probe_plan,
}
_IGMP_PLANNED_ONLY_CASES: frozenset[str] = frozenset(
    {
        "igmp-membership-query-observation",
        "igmp-v2-membership-report-emission",
        "igmp-v2-leave-group-emission",
        "igmp-v3-source-list-report",
    }
)


def igmp_failure_reasons(case_name: str) -> list[str] | None:
    return None


register(
    ProtocolPlugin(
        name="igmp",
        cases=IGMP_PROBE_CASES,
        plan_builders=_IGMP_PLAN_BUILDERS,
        planned_only_cases=_IGMP_PLANNED_ONLY_CASES,
        profile_counts={},
        stimulus_endpoint_cases=frozenset(),
        failure_reasons=igmp_failure_reasons,
    )
)
