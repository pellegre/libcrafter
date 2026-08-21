"""Deterministic DHCPV6 probe cases and packet plans."""

from __future__ import annotations
from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_documentation_ipv6,
    deterministic_documentation_mac,
)
from .base import ProtocolPlugin, register

DHCPV6_SERVICE_KIND = "dhcpv6-controlled-responder"
DHCPV6_STIMULUS_DRIVER = "dhcpv6_probe"
DHCPV6_ADAPTER_MODULE = "tools/probe/adapters/src/dhcpv6.rs"
DHCPV6_CLIENT_PORT = 546
DHCPV6_SERVER_PORT = 547
DHCPV6_ALL_RELAY_AGENTS_AND_SERVERS = "ff02::1:2"
DHCPV6_ALL_SERVERS = "ff05::1:3"
DHCPV6_MULTICAST_MAC_RELAY_AGENTS_AND_SERVERS = "33:33:00:01:00:02"
DHCPV6_MULTICAST_MAC_ALL_SERVERS = "33:33:00:01:00:03"
DHCPV6_DOCUMENTATION_PREFIX = "2001:db8::/32"
DHCPV6_RELAY_INTERFACE_ID_HEX = "646f632d72656c6179"
_DHCPV6_CAPABILITIES = ["dhcpv6_service"]
_DHCPV6_RELAY_CAPABILITIES = ["dhcpv6_service", "dhcpv6_relay_topology"]
_DHCPV6_ADVANCED_PROFILE = "dhcpv6-advanced"
DHCPV6_SMOKE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="dhcpv6-information-request-reply",
        description="Plan an Information-request and Reply configuration exchange.",
        stimulus="dhcpv6_information_request",
        expected_response="dhcpv6_reply",
        required_capabilities=_DHCPV6_CAPABILITIES,
        protocol="dhcpv6",
        metadata={"service": DHCPV6_SERVICE_KIND, "planned_only": True},
    ),
    _behavior_case(
        name="dhcpv6-solicit-advertise",
        description="Plan a Solicit and Advertise discovery exchange.",
        stimulus="dhcpv6_solicit",
        expected_response="dhcpv6_advertise",
        required_capabilities=_DHCPV6_CAPABILITIES,
        protocol="dhcpv6",
        metadata={"service": DHCPV6_SERVICE_KIND, "planned_only": True},
    ),
    _behavior_case(
        name="dhcpv6-request-reply-ia-na",
        description="Plan a Request and Reply exchange carrying IA_NA state.",
        stimulus="dhcpv6_request",
        expected_response="dhcpv6_reply",
        required_capabilities=_DHCPV6_CAPABILITIES,
        protocol="dhcpv6",
        metadata={"service": DHCPV6_SERVICE_KIND, "planned_only": True},
    ),
    _behavior_case(
        name="dhcpv6-prefix-delegation",
        description="Plan an IA_PD Prefix Delegation Request and Reply exchange.",
        stimulus="dhcpv6_request",
        expected_response="dhcpv6_reply",
        required_capabilities=_DHCPV6_CAPABILITIES,
        protocol="dhcpv6",
        metadata={"service": DHCPV6_SERVICE_KIND, "planned_only": True},
    ),
    _behavior_case(
        name="dhcpv6-rapid-commit",
        description="Plan a Solicit and Reply exchange using Rapid Commit.",
        stimulus="dhcpv6_solicit",
        expected_response="dhcpv6_reply",
        required_capabilities=_DHCPV6_CAPABILITIES,
        protocol="dhcpv6",
        metadata={"service": DHCPV6_SERVICE_KIND, "planned_only": True},
    ),
    _behavior_case(
        name="dhcpv6-relay-forward-reply",
        description="Plan a Relay-forward and Relay-reply exchange.",
        stimulus="dhcpv6_relay_forward",
        expected_response="dhcpv6_relay_reply",
        required_capabilities=_DHCPV6_RELAY_CAPABILITIES,
        protocol="dhcpv6",
        endpoint_roles=["stimulus", "relay", "target"],
        metadata={
            "service": DHCPV6_SERVICE_KIND,
            "planned_only": True,
            "topology": "stimulus-relay-target",
        },
    ),
    _behavior_case(
        name="dhcpv6-reconfigure-observation",
        description="Plan observation of a Reconfigure message and client response.",
        stimulus="dhcpv6_reconfigure",
        expected_response="dhcpv6_reconfigure_observed",
        required_capabilities=_DHCPV6_CAPABILITIES,
        protocol="dhcpv6",
        metadata={"service": DHCPV6_SERVICE_KIND, "planned_only": True},
    ),
    _behavior_case(
        name="dhcpv6-leasequery-plan",
        description="Plan a Leasequery and Leasequery-reply exchange.",
        stimulus="dhcpv6_leasequery",
        expected_response="dhcpv6_leasequery_reply",
        required_capabilities=_DHCPV6_CAPABILITIES,
        protocol="dhcpv6",
        metadata={"service": DHCPV6_SERVICE_KIND, "planned_only": True},
    ),
    _behavior_case(
        name="dhcpv6-bulk-leasequery-plan",
        description="Plan a Bulk Leasequery stream ending in Leasequery-done.",
        stimulus="dhcpv6_bulk_leasequery",
        expected_response="dhcpv6_leasequery_done",
        required_capabilities=_DHCPV6_CAPABILITIES,
        protocol="dhcpv6",
        metadata={
            "service": DHCPV6_SERVICE_KIND,
            "planned_only": True,
            "profile": _DHCPV6_ADVANCED_PROFILE,
        },
    ),
    _behavior_case(
        name="dhcpv6-active-leasequery-plan",
        description="Plan an Active Leasequery stream carrying live binding updates.",
        stimulus="dhcpv6_active_leasequery",
        expected_response="dhcpv6_active_leasequery_stream",
        required_capabilities=_DHCPV6_CAPABILITIES,
        protocol="dhcpv6",
        metadata={
            "service": DHCPV6_SERVICE_KIND,
            "planned_only": True,
            "profile": _DHCPV6_ADVANCED_PROFILE,
        },
    ),
    _behavior_case(
        name="dhcpv6-unknown-option-preservation",
        description="Plan a request carrying an unknown option that must be preserved.",
        stimulus="dhcpv6_information_request",
        expected_response="dhcpv6_reply",
        required_capabilities=_DHCPV6_CAPABILITIES,
        protocol="dhcpv6",
        metadata={"service": DHCPV6_SERVICE_KIND, "planned_only": True},
    ),
    _behavior_case(
        name="dhcpv6-repeated-transaction-id",
        description="Plan two deterministic sends that reuse the same transaction id.",
        stimulus="dhcpv6_information_request",
        expected_response="dhcpv6_reply",
        required_capabilities=_DHCPV6_CAPABILITIES,
        protocol="dhcpv6",
        metadata={"service": DHCPV6_SERVICE_KIND, "planned_only": True},
    ),
)
_DHCPV6_CASE_CONFIG: dict[str, JSONObject] = {
    "dhcpv6-information-request-reply": {
        "message_type": "information-request",
        "message_type_code": 11,
        "expected_message_type": "reply",
        "expected_message_type_code": 7,
        "destination": "relay_agents_and_servers",
        "behavior": "reply_configuration",
        "option_profile": "oro_dns",
    },
    "dhcpv6-solicit-advertise": {
        "message_type": "solicit",
        "message_type_code": 1,
        "expected_message_type": "advertise",
        "expected_message_type_code": 2,
        "destination": "relay_agents_and_servers",
        "behavior": "advertise_address_configuration",
        "option_profile": "solicit",
    },
    "dhcpv6-request-reply-ia-na": {
        "message_type": "request",
        "message_type_code": 3,
        "expected_message_type": "reply",
        "expected_message_type_code": 7,
        "destination": "unicast",
        "behavior": "reply_ia_na",
        "option_profile": "ia_na",
    },
    "dhcpv6-prefix-delegation": {
        "message_type": "request",
        "message_type_code": 3,
        "expected_message_type": "reply",
        "expected_message_type_code": 7,
        "destination": "unicast",
        "behavior": "reply_ia_pd",
        "option_profile": "ia_pd",
    },
    "dhcpv6-rapid-commit": {
        "message_type": "solicit",
        "message_type_code": 1,
        "expected_message_type": "reply",
        "expected_message_type_code": 7,
        "destination": "relay_agents_and_servers",
        "behavior": "rapid_commit_reply",
        "option_profile": "rapid_commit",
    },
    "dhcpv6-relay-forward-reply": {
        "message_type": "relay-forward",
        "message_type_code": 12,
        "expected_message_type": "relay-reply",
        "expected_message_type_code": 13,
        "destination": "all_servers",
        "source_port": DHCPV6_SERVER_PORT,
        "behavior": "relay_reply",
        "option_profile": "relay",
    },
    "dhcpv6-reconfigure-observation": {
        "message_type": "reconfigure",
        "message_type_code": 10,
        "expected_message_type": "information-request",
        "expected_message_type_code": 11,
        "destination": "client",
        "source_port": DHCPV6_SERVER_PORT,
        "destination_port": DHCPV6_CLIENT_PORT,
        "behavior": "observe_reconfigure",
        "option_profile": "reconfigure",
    },
    "dhcpv6-leasequery-plan": {
        "message_type": "leasequery",
        "message_type_code": 14,
        "expected_message_type": "leasequery-reply",
        "expected_message_type_code": 15,
        "destination": "unicast",
        "source_port": DHCPV6_SERVER_PORT,
        "behavior": "leasequery_reply",
        "option_profile": "leasequery",
    },
    "dhcpv6-bulk-leasequery-plan": {
        "message_type": "leasequery",
        "message_type_code": 14,
        "expected_message_type": "leasequery-done",
        "expected_message_type_code": 16,
        "destination": "unicast",
        "source_port": DHCPV6_SERVER_PORT,
        "behavior": "bulk_leasequery_done",
        "option_profile": "bulk_leasequery",
    },
    "dhcpv6-active-leasequery-plan": {
        "message_type": "activeleasequery",
        "message_type_code": 22,
        "expected_message_type": "leasequery-reply",
        "expected_message_type_code": 15,
        "destination": "unicast",
        "source_port": DHCPV6_SERVER_PORT,
        "behavior": "active_leasequery_stream",
        "option_profile": "active_leasequery",
    },
    "dhcpv6-unknown-option-preservation": {
        "message_type": "information-request",
        "message_type_code": 11,
        "expected_message_type": "reply",
        "expected_message_type_code": 7,
        "destination": "relay_agents_and_servers",
        "behavior": "preserve_unknown_options",
        "option_profile": "unknown_option",
    },
    "dhcpv6-repeated-transaction-id": {
        "message_type": "information-request",
        "message_type_code": 11,
        "expected_message_type": "reply",
        "expected_message_type_code": 7,
        "destination": "relay_agents_and_servers",
        "behavior": "deduplicate_transaction_id",
        "option_profile": "oro_dns",
        "packet_count": 2,
    },
}
_DHCPV6_CASE_BY_NAME: dict[str, ProbeCase] = {
    case.name: case for case in DHCPV6_SMOKE_CASES
}
_DHCPV6_PLANNED_ONLY_CASES = frozenset(_DHCPV6_CASE_BY_NAME)


def dhcpv6_transaction_id(
    case_name: str, profile: str, seed: int, sequence: int
) -> int:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    return int.from_bytes(digest[0:3], "big") or 1


def dhcpv6_duid_ll(profile: str, seed: int, sequence: int, *, role: str) -> str:
    mac = deterministic_documentation_mac(
        profile, seed, sequence, role=f"dhcpv6-{role}"
    )
    return "00030001" + mac.replace(":", "")


def _dhcpv6_probe_plan(
    *, case_name: str, profile: str, seed: int, sequence: int
) -> JSONObject:
    case = _DHCPV6_CASE_BY_NAME[case_name]
    config = _DHCPV6_CASE_CONFIG[case_name]
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    client_ipv6 = deterministic_documentation_ipv6(
        deterministic_bytes(f"{case_name}-client", profile, seed, sequence)
    )
    server_ipv6 = deterministic_documentation_ipv6(
        deterministic_bytes(f"{case_name}-server", profile, seed, sequence)
    )
    ia_na_ipv6 = deterministic_documentation_ipv6(
        deterministic_bytes(f"{case_name}-ia-na", profile, seed, sequence)
    )
    link_address = deterministic_documentation_ipv6(
        deterministic_bytes(f"{case_name}-relay-link", profile, seed, sequence)
    )
    delegated_prefix = _delegated_prefix(digest)
    transaction_id = dhcpv6_transaction_id(case_name, profile, seed, sequence)
    packet_count = int(config.get("packet_count", 1))
    source_port = int(config.get("source_port", DHCPV6_CLIENT_PORT))
    destination_port = int(config.get("destination_port", DHCPV6_SERVER_PORT))
    destination_ipv6, destination_mac = _destination_addresses(
        str(config["destination"]), client_ipv6=client_ipv6, server_ipv6=server_ipv6
    )
    client_duid = dhcpv6_duid_ll(profile, seed, sequence, role="client")
    server_duid = dhcpv6_duid_ll(profile, seed, sequence, role="server")
    options = _request_options(
        str(config["option_profile"]),
        client_duid=client_duid,
        server_duid=server_duid,
        transaction_id=transaction_id,
        client_ipv6=client_ipv6,
        ia_na_ipv6=ia_na_ipv6,
        delegated_prefix=delegated_prefix,
    )
    expected_options = _expected_options(
        str(config["option_profile"]),
        client_duid=client_duid,
        server_duid=server_duid,
        transaction_id=transaction_id,
        client_ipv6=client_ipv6,
        ia_na_ipv6=ia_na_ipv6,
        delegated_prefix=delegated_prefix,
    )
    sends = _dhcpv6_send_sequence(
        packet_count=packet_count,
        message_type=str(config["message_type"]),
        message_type_code=int(config["message_type_code"]),
        transaction_id=transaction_id,
    )
    plan: JSONObject = {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        "planned_only": True,
        "protocol": "dhcpv6",
        "source_ipv6": client_ipv6,
        "destination_ipv6": destination_ipv6,
        "target_ipv6": server_ipv6,
        "assigned_ipv6": ia_na_ipv6,
        "expected_reply_source_ipv6": server_ipv6,
        "expected_reply_destination_ipv6": client_ipv6,
        "source_port": source_port,
        "destination_port": destination_port,
        "source_mac": deterministic_documentation_mac(
            profile, seed, sequence, role="dhcpv6-source"
        ),
        "destination_mac": destination_mac,
        "documentation_prefixes": [DHCPV6_DOCUMENTATION_PREFIX],
        "dhcpv6": {
            "message_type": str(config["message_type"]),
            "message_type_code": int(config["message_type_code"]),
            "expected_message_type": str(config["expected_message_type"]),
            "expected_message_type_code": int(config["expected_message_type_code"]),
            "transaction_id": transaction_id,
            "packet_count": packet_count,
            "client_duid_hex": client_duid,
            "server_duid_hex": server_duid,
            "options": options,
            "expected_options": expected_options,
            "relay": _relay_metadata(
                case_name,
                option_profile=str(config["option_profile"]),
                link_address=link_address,
                peer_address=client_ipv6,
                transaction_id=transaction_id,
            ),
            "ia_na": _ia_na_validation(
                str(config["option_profile"]), iaid=transaction_id, address=ia_na_ipv6
            ),
            "ia_pd": _ia_pd_validation(
                str(config["option_profile"]),
                iaid=transaction_id,
                prefix=delegated_prefix,
            ),
            "pd_exchanges": _pd_exchange_sequence(
                str(config["option_profile"]), transaction_id=transaction_id
            ),
        },
        "dhcpv6_sends": sends,
        "stimulus_driver": {
            "name": DHCPV6_STIMULUS_DRIVER,
            "adapter_module": DHCPV6_ADAPTER_MODULE,
            "state": "planned-only",
            "planned_only": True,
        },
        "capture_filter": "udp and (port 546 or port 547)",
        "validation": {
            "planned_only": True,
            "source_port": destination_port,
            "destination_port": source_port,
            "expected_message_type": str(config["expected_message_type"]),
            "expected_message_type_code": int(config["expected_message_type_code"]),
            "transaction_id": transaction_id,
            "transaction_id_match": True,
            "packet_count": packet_count,
            "target_behavior": str(config["behavior"]),
            "client_duid_hex": client_duid,
            "server_duid_hex": server_duid,
            "ia_na": _ia_na_validation(
                str(config["option_profile"]), iaid=transaction_id, address=ia_na_ipv6
            ),
            "ia_pd": _ia_pd_validation(
                str(config["option_profile"]),
                iaid=transaction_id,
                prefix=delegated_prefix,
            ),
            "pd_exchanges": _pd_exchange_sequence(
                str(config["option_profile"]), transaction_id=transaction_id
            ),
            "route_installation": "out_of_scope",
            "reply_decode": {
                "protocol": "Dhcpv6",
                "message_type": str(config["expected_message_type"]),
                "message_type_code": int(config["expected_message_type_code"]),
                "required_options": _required_reply_option_names(
                    str(config["option_profile"])
                ),
            },
        },
        "wire_requirements": {
            "requires_ipv6_unicast": True,
            "requires_multicast": str(config["destination"]) != "unicast",
            "requires_controlled_service": True,
            "requires_dhcpv6_service": True,
            "dry_run_only_until_adapter": True,
        },
        "digest_hex": digest.hex()[:16],
    }
    if str(config["option_profile"]) == "relay":
        plan["wire_requirements"]["requires_relay_topology"] = True
        plan["validation"]["relay"] = _relay_validation(
            link_address=link_address,
            peer_address=client_ipv6,
            transaction_id=transaction_id,
        )
    return plan


def _destination_addresses(
    destination: str, *, client_ipv6: str, server_ipv6: str
) -> tuple[str, str]:
    if destination == "all_servers":
        return (DHCPV6_ALL_SERVERS, DHCPV6_MULTICAST_MAC_ALL_SERVERS)
    if destination == "relay_agents_and_servers":
        return (
            DHCPV6_ALL_RELAY_AGENTS_AND_SERVERS,
            DHCPV6_MULTICAST_MAC_RELAY_AGENTS_AND_SERVERS,
        )
    if destination == "client":
        return (
            client_ipv6,
            deterministic_documentation_mac("dhcpv6", 0, 0, role="client-destination"),
        )
    return (
        server_ipv6,
        deterministic_documentation_mac("dhcpv6", 0, 0, role="server-destination"),
    )


def _request_options(
    option_profile: str,
    *,
    client_duid: str,
    server_duid: str,
    transaction_id: int,
    client_ipv6: str,
    ia_na_ipv6: str,
    delegated_prefix: str,
) -> list[JSONObject]:
    base: list[JSONObject] = [
        {"code": 1, "name": "client_identifier", "duid_hex": client_duid}
    ]
    if option_profile in {
        "ia_na",
        "ia_pd",
        "reconfigure",
        "leasequery",
        "bulk_leasequery",
        "active_leasequery",
    }:
        base.append({"code": 2, "name": "server_identifier", "duid_hex": server_duid})
    if option_profile in {"oro_dns", "solicit", "rapid_commit", "unknown_option"}:
        base.append({"code": 6, "name": "option_request", "requested": [23, 24]})
    if option_profile in {"solicit", "rapid_commit"}:
        base.append({"code": 8, "name": "elapsed_time", "centiseconds": 0})
    if option_profile in {"solicit", "ia_na", "rapid_commit"}:
        base.append(_ia_na_option(transaction_id, ia_na_ipv6))
    if option_profile == "rapid_commit":
        base.append({"code": 14, "name": "rapid_commit"})
    if option_profile == "ia_pd":
        base.append(_ia_pd_option(transaction_id, delegated_prefix))
    if option_profile == "relay":
        base.extend(
            [
                {
                    "code": 18,
                    "name": "interface_id",
                    "hex": DHCPV6_RELAY_INTERFACE_ID_HEX,
                },
                {"code": 9, "name": "relay_message", "message_type": "solicit"},
            ]
        )
    if option_profile == "reconfigure":
        base.extend(
            [
                {
                    "code": 19,
                    "name": "reconfigure_message",
                    "message_type": "information-request",
                },
                {
                    "code": 11,
                    "name": "authentication",
                    "protocol": "delayed",
                    "algorithm": 1,
                    "rdm": 0,
                },
            ]
        )
    if option_profile == "leasequery":
        base.extend(
            [
                {
                    "code": 44,
                    "name": "lq_query",
                    "query_type": "by_address",
                    "address": client_ipv6,
                },
                {"code": 1, "name": "query_client_identifier", "duid_hex": client_duid},
            ]
        )
    if option_profile == "bulk_leasequery":
        base.extend(
            [
                {
                    "code": 44,
                    "name": "lq_query",
                    "query_type": "by_link_address",
                    "query_type_code": 4,
                    "address": client_ipv6,
                },
                {"code": 53, "name": "relay_id", "data_hex": "646f632d62756c6b"},
                {"code": 101, "name": "lq_start_time", "seconds": 0},
            ]
        )
    if option_profile == "active_leasequery":
        base.extend(
            [
                {
                    "code": 44,
                    "name": "lq_query",
                    "query_type": "by_relay_id",
                    "query_type_code": 3,
                    "address": client_ipv6,
                },
                {"code": 53, "name": "relay_id", "data_hex": "646f632d616374697665"},
                {"code": 101, "name": "lq_start_time", "seconds": 0},
            ]
        )
    if option_profile == "unknown_option":
        base.append(
            {"code": 65000, "name": "unknown", "data_hex": "646f632d756e6b6e6f776e"}
        )
    return base


def _expected_options(
    option_profile: str,
    *,
    client_duid: str,
    server_duid: str,
    transaction_id: int,
    client_ipv6: str,
    ia_na_ipv6: str,
    delegated_prefix: str,
) -> list[JSONObject]:
    options: list[JSONObject] = [
        {"code": 2, "name": "server_identifier", "duid_hex": server_duid}
    ]
    if option_profile != "leasequery":
        options.append(
            {"code": 1, "name": "client_identifier", "duid_hex": client_duid}
        )
    if option_profile in {"oro_dns", "solicit", "rapid_commit", "unknown_option"}:
        options.extend(
            [
                {
                    "code": 23,
                    "name": "dns_recursive_name_servers",
                    "servers": ["2001:db8::53"],
                },
                {"code": 24, "name": "domain_search_list", "domains": ["example.test"]},
            ]
        )
    if option_profile in {"solicit", "ia_na", "rapid_commit"}:
        options.append(_ia_na_option(transaction_id, ia_na_ipv6))
        options.append(_status_success_option())
    if option_profile == "ia_pd":
        options.append(_ia_pd_option(transaction_id, delegated_prefix))
        options.append(_status_success_option())
    if option_profile == "rapid_commit":
        options.append({"code": 14, "name": "rapid_commit"})
    if option_profile == "relay":
        options.append(
            {"code": 9, "name": "relay_message", "message_type": "advertise"}
        )
    if option_profile == "reconfigure":
        options.append({"code": 20, "name": "reconfigure_accept"})
    if option_profile == "leasequery":
        options.extend(
            [
                {
                    "code": 45,
                    "name": "client_data",
                    "client_identifier_hex": client_duid,
                },
                {"code": 46, "name": "clt_time", "seconds": 0},
                _status_success_option(),
            ]
        )
    if option_profile == "bulk_leasequery":
        options.extend(
            [
                {"code": 100, "name": "lq_base_time", "seconds": 0},
                _status_success_option(),
            ]
        )
    if option_profile == "active_leasequery":
        options.extend(
            [
                {
                    "code": 45,
                    "name": "client_data",
                    "client_identifier_hex": client_duid,
                },
                {"code": 46, "name": "clt_time", "seconds": 0},
                {"code": 100, "name": "lq_base_time", "seconds": 0},
                _status_option(13, "catch_up_complete"),
            ]
        )
    if option_profile == "unknown_option":
        options.append(
            {"code": 65000, "name": "unknown", "data_hex": "646f632d756e6b6e6f776e"}
        )
    return options


def _relay_metadata(
    case_name: str,
    *,
    option_profile: str,
    link_address: str,
    peer_address: str,
    transaction_id: int,
) -> JSONObject:
    if option_profile != "relay":
        return {"enabled": False}
    return {
        "enabled": True,
        "case": case_name,
        "hop_count": 0,
        "link_address": link_address,
        "peer_address": peer_address,
        "interface_id_hex": DHCPV6_RELAY_INTERFACE_ID_HEX,
        "relay_message": {
            "message_type": "solicit",
            "message_type_code": 1,
            "transaction_id": transaction_id,
        },
        "expected_relay_message": {
            "message_type": "advertise",
            "message_type_code": 2,
            "transaction_id": transaction_id,
        },
    }


def _relay_validation(
    *, link_address: str, peer_address: str, transaction_id: int
) -> JSONObject:
    return {
        "enabled": True,
        "topology_roles": ["stimulus", "relay", "target"],
        "relay_forward": {
            "message_type": "relay-forward",
            "message_type_code": 12,
            "hop_count": 0,
            "link_address": link_address,
            "peer_address": peer_address,
            "interface_id_hex": DHCPV6_RELAY_INTERFACE_ID_HEX,
            "relay_message": {
                "nested": True,
                "message_type": "solicit",
                "message_type_code": 1,
                "transaction_id": transaction_id,
            },
        },
        "relay_reply": {
            "message_type": "relay-reply",
            "message_type_code": 13,
            "hop_count": 0,
            "link_address": link_address,
            "peer_address": peer_address,
            "interface_id_echo": True,
            "interface_id_hex": DHCPV6_RELAY_INTERFACE_ID_HEX,
            "relay_message": {
                "nested": True,
                "message_type": "advertise",
                "message_type_code": 2,
                "transaction_id": transaction_id,
            },
        },
        "relay_message_nesting": True,
        "reply_decapsulation": {
            "enabled": True,
            "outer_message_type": "relay-reply",
            "inner_message_type": "advertise",
            "transaction_id_match": True,
        },
        "transaction_id_match": True,
    }


def _iaaddr_option(address: str) -> JSONObject:
    return {
        "code": 5,
        "name": "iaaddr",
        "ipv6": address,
        "preferred_lifetime": 3600,
        "valid_lifetime": 7200,
    }


def _ia_na_option(iaid: int, address: str) -> JSONObject:
    return {
        "code": 3,
        "name": "ia_na",
        "iaid": iaid,
        "t1": 1800,
        "t2": 2880,
        "addresses": [_iaaddr_option(address)],
    }


def _status_success_option() -> JSONObject:
    return _status_option(0, "success")


def _status_option(status_code: int, status: str) -> JSONObject:
    return {
        "code": 13,
        "name": "status_code",
        "status_code": status_code,
        "status": status,
    }


def _iaprefix_option(prefix: str) -> JSONObject:
    return {
        "code": 26,
        "name": "iaprefix",
        "prefix": prefix,
        "prefix_length": 56,
        "preferred_lifetime": 3600,
        "valid_lifetime": 7200,
    }


def _ia_pd_option(iaid: int, prefix: str) -> JSONObject:
    return {
        "code": 25,
        "name": "ia_pd",
        "iaid": iaid,
        "t1": 1800,
        "t2": 2880,
        "prefixes": [_iaprefix_option(prefix)],
    }


def _ia_na_validation(option_profile: str, *, iaid: int, address: str) -> JSONObject:
    if option_profile not in {"solicit", "ia_na", "rapid_commit"}:
        return {"enabled": False}
    return {
        "enabled": True,
        "iaid": iaid,
        "t1": 1800,
        "t2": 2880,
        "iaaddr": {"ipv6": address, "preferred_lifetime": 3600, "valid_lifetime": 7200},
        "status_code": 0,
        "status": "success",
    }


def _ia_pd_validation(option_profile: str, *, iaid: int, prefix: str) -> JSONObject:
    if option_profile != "ia_pd":
        return {"enabled": False}
    return {
        "enabled": True,
        "iaid": iaid,
        "t1": 1800,
        "t2": 2880,
        "iaprefix": {
            "prefix": prefix,
            "prefix_length": 56,
            "preferred_lifetime": 3600,
            "valid_lifetime": 7200,
        },
        "status_code": 0,
        "status": "success",
    }


def _pd_exchange_sequence(
    option_profile: str, *, transaction_id: int
) -> list[JSONObject]:
    if option_profile != "ia_pd":
        return []
    advertise_xid = transaction_id
    reply_xid = (transaction_id ^ 10855845) & 16777215 or 1
    return [
        {
            "stimulus": "solicit",
            "expected_response": "advertise",
            "transaction_id": advertise_xid,
            "transaction_id_match": True,
        },
        {
            "stimulus": "request",
            "expected_response": "reply",
            "transaction_id": reply_xid,
            "transaction_id_match": True,
        },
    ]


def _required_reply_option_names(option_profile: str) -> list[str]:
    names = ["server_identifier"]
    if option_profile in {"solicit", "ia_na", "rapid_commit"}:
        names.extend(["client_identifier", "ia_na", "iaaddr", "status_code"])
    if option_profile == "ia_pd":
        names.extend(["client_identifier", "ia_pd", "iaprefix", "status_code"])
    if option_profile == "relay":
        names.extend(["interface_id", "relay_message"])
    if option_profile == "leasequery":
        names.extend(["client_data", "clt_time", "status_code"])
    if option_profile == "bulk_leasequery":
        names.extend(["lq_base_time", "status_code"])
    if option_profile == "active_leasequery":
        names.extend(["client_data", "clt_time", "lq_base_time", "status_code"])
    return names


def _dhcpv6_send_sequence(
    *, packet_count: int, message_type: str, message_type_code: int, transaction_id: int
) -> list[JSONObject]:
    return [
        {
            "send_index": index,
            "message_type": message_type,
            "message_type_code": message_type_code,
            "transaction_id": transaction_id,
        }
        for index in range(packet_count)
    ]


def _delegated_prefix(digest: bytes) -> str:
    return f"2001:db8:{16384 + digest[12]:x}:{digest[13]:x}::"


_DHCPV6_PLAN_BUILDERS: dict[str, object] = {
    case.name: _dhcpv6_probe_plan for case in DHCPV6_SMOKE_CASES
}
register(
    ProtocolPlugin(
        name="dhcpv6",
        cases=DHCPV6_SMOKE_CASES,
        plan_builders=_DHCPV6_PLAN_BUILDERS,
        planned_only_cases=_DHCPV6_PLANNED_ONLY_CASES,
        profile_counts={},
        stimulus_endpoint_cases=frozenset(),
        failure_reasons=None,
    )
)
