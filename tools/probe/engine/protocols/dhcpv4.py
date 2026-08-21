"""Deterministic DHCPV4 probe cases and packet plans."""

from __future__ import annotations
from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_ipv4_pair,
    deterministic_router_ipv4,
    dns_label,
)
from .base import ProtocolPlugin, register

_DHCPV4_CAPABILITIES = ["dhcpv4_service"]
BEHAVIOR_DHCPV4_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="dhcpv4-discover-offer",
        description="Send a DHCPv4 Discover and validate the Offer.",
        stimulus="dhcpv4_discover",
        expected_response="dhcpv4_offer",
        required_capabilities=_DHCPV4_CAPABILITIES,
        protocol="dhcpv4",
    ),
    _behavior_case(
        name="dhcpv4-request-ack",
        description="Send a DHCPv4 Request and validate the Ack.",
        stimulus="dhcpv4_request",
        expected_response="dhcpv4_ack",
        required_capabilities=_DHCPV4_CAPABILITIES,
        protocol="dhcpv4",
    ),
    _behavior_case(
        name="dhcpv4-client-identifier",
        description="Send a Discover carrying a client identifier (option 61) and validate the matching Offer that records the client identity.",
        stimulus="dhcpv4_discover",
        expected_response="dhcpv4_offer",
        required_capabilities=_DHCPV4_CAPABILITIES,
        protocol="dhcpv4",
    ),
    _behavior_case(
        name="dhcpv4-hostname",
        description="Send a Discover with a hostname option and validate the Offer.",
        stimulus="dhcpv4_discover",
        expected_response="dhcpv4_offer",
        required_capabilities=_DHCPV4_CAPABILITIES,
        protocol="dhcpv4",
    ),
    _behavior_case(
        name="dhcpv4-parameter-request-list",
        description="Send a Discover with a parameter request list and validate the requested options in the Offer.",
        stimulus="dhcpv4_discover",
        expected_response="dhcpv4_offer",
        required_capabilities=_DHCPV4_CAPABILITIES,
        protocol="dhcpv4",
    ),
    _behavior_case(
        name="dhcpv4-lease-time",
        description="Send a Discover and validate the lease time (51), renewal T1 (58), and rebinding T2 (59) timing options in the Offer.",
        stimulus="dhcpv4_discover",
        expected_response="dhcpv4_offer",
        required_capabilities=_DHCPV4_CAPABILITIES,
        protocol="dhcpv4",
    ),
    _behavior_case(
        name="dhcpv4-renewal-unicast-ack",
        description="Send a unicast renewal Request and validate the unicast Ack.",
        stimulus="dhcpv4_request",
        expected_response="dhcpv4_ack",
        required_capabilities=_DHCPV4_CAPABILITIES,
        protocol="dhcpv4",
    ),
    _behavior_case(
        name="dhcpv4-inform-ack",
        description="Send a DHCPv4 Inform and validate the Ack with config options.",
        stimulus="dhcpv4_inform",
        expected_response="dhcpv4_ack",
        required_capabilities=_DHCPV4_CAPABILITIES,
        protocol="dhcpv4",
    ),
    _behavior_case(
        name="dhcpv4-request-nak",
        description="Request an invalid address and validate the Nak.",
        stimulus="dhcpv4_request",
        expected_response="dhcpv4_nak",
        required_capabilities=_DHCPV4_CAPABILITIES,
        protocol="dhcpv4",
    ),
    _behavior_case(
        name="dhcpv4-rapid-repeat",
        description="Send repeated Discovers and validate each independently decoded Offer.",
        stimulus="dhcpv4_discover",
        expected_response="dhcpv4_offer",
        required_capabilities=_DHCPV4_CAPABILITIES,
        protocol="dhcpv4",
    ),
)


def dhcpv4_client_mac(profile: str, seed: int, sequence: int) -> str:
    digest = deterministic_bytes(
        f"dhcpv4-client-mac-{profile}", profile, seed, sequence
    )
    return f"00:00:5e:00:53:{digest[0]:02x}"


def dhcpv4_hostname(profile: str, seed: int, sequence: int) -> str:
    label = dns_label(profile)
    return f"probe-{label}-{seed}-{sequence}"


def dhcpv4_client_identifier(profile: str, seed: int, sequence: int) -> str:
    digest = deterministic_bytes("dhcpv4-client-identifier", profile, seed, sequence)
    payload = bytearray()
    payload.append(255)
    payload.extend(digest[0:4])
    payload.extend((0, 3))
    payload.extend((0, 1))
    payload.extend((0, 0, 94, 0, 83, digest[4]))
    return payload.hex()


def dhcpv4_parameter_request_list(profile: str, seed: int, sequence: int) -> list[int]:
    return [1, 3, 6, 51, 58, 59]


def _dhcpv4_parameter_request_list_probe_plan(
    *,
    case_name: str = "dhcpv4-parameter-request-list",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcpv4_client_mac(profile, seed, sequence)
    parameter_request_list = dhcpv4_parameter_request_list(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    source_port = 68
    destination_port = 67
    offered_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    dns_server_ipv4 = f"198.51.100.{1 + digest[6] % 250}"
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = lease_time * 7 // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcpv4_discover",
        "expected_response": "dhcpv4_offer",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "parameter_request_list": parameter_request_list,
        "transaction_id": transaction_id,
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": offered_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_parameter_request_list": parameter_request_list,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_dns_ipv4": dns_server_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "offer",
            "message_type_value": 2,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "dns_ipv4": dns_server_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "requested_parameters": parameter_request_list,
            "direction": "server_to_client",
        },
    }


def _dhcpv4_lease_time_probe_plan(
    *, case_name: str = "dhcpv4-lease-time", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcpv4_client_mac(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    source_port = 68
    destination_port = 67
    offered_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = lease_time * 7 // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcpv4_discover",
        "expected_response": "dhcpv4_offer",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": offered_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "offer",
            "message_type_value": 2,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcpv4_discover_offer_probe_plan(
    *, case_name: str = "dhcpv4-discover-offer", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcpv4_client_mac(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    source_port = 68
    destination_port = 67
    offered_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = lease_time * 7 // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcpv4_discover",
        "expected_response": "dhcpv4_offer",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": offered_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "offer",
            "message_type_value": 2,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcpv4_rapid_repeat_send(
    *,
    profile: str,
    seed: int,
    sequence: int,
    digest: bytes,
    index: int,
    stimulus_ipv4: str,
    target_ipv4: str,
    transaction_id: int,
    client_mac: str,
    source_port: int,
    destination_port: int,
    offered_ipv4: str,
    subnet_mask: str,
    server_identifier: str,
    router_ipv4: str,
    lease_time: int,
    renewal_time: int,
    rebinding_time: int,
) -> JSONObject:
    return {
        "index": index,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": offered_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "offer",
            "message_type_value": 2,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcpv4_rapid_repeat_probe_plan(
    *, case_name: str = "dhcpv4-rapid-repeat", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 68
    destination_port = 67
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    base_client_mac = dhcpv4_client_mac(profile, seed, sequence)
    first_xid = int.from_bytes(digest[0:4], "big") or 1
    second_xid = int.from_bytes(digest[4:8], "big") or 2
    if second_xid == first_xid:
        second_xid = first_xid ^ 4294967295 or first_xid + 1
    transaction_ids = (first_xid, second_xid)
    mac_prefix = base_client_mac.rsplit(":", 1)[0]
    first_mac_octet = digest[8]
    second_mac_octet = digest[9]
    if second_mac_octet == first_mac_octet:
        second_mac_octet = first_mac_octet + 1 & 255
    client_macs = (
        f"{mac_prefix}:{first_mac_octet:02x}",
        f"{mac_prefix}:{second_mac_octet:02x}",
    )
    first_offer_host = 1 + digest[10] % 250
    second_offer_host = 1 + digest[11] % 250
    if second_offer_host == first_offer_host:
        second_offer_host = 1 + first_offer_host % 250
    offered_ipv4s = (
        f"198.51.100.{first_offer_host}",
        f"198.51.100.{second_offer_host}",
    )
    lease_time = 3600 + 60 * (digest[12] % 60)
    renewal_time = lease_time // 2
    rebinding_time = lease_time * 7 // 8
    sends = [
        _dhcpv4_rapid_repeat_send(
            profile=profile,
            seed=seed,
            sequence=sequence,
            digest=digest,
            index=index,
            stimulus_ipv4=stimulus_ipv4,
            target_ipv4=target_ipv4,
            transaction_id=transaction_ids[index],
            client_mac=client_macs[index],
            source_port=source_port,
            destination_port=destination_port,
            offered_ipv4=offered_ipv4s[index],
            subnet_mask=subnet_mask,
            server_identifier=server_identifier,
            router_ipv4=router_ipv4,
            lease_time=lease_time,
            renewal_time=renewal_time,
            rebinding_time=rebinding_time,
        )
        for index in range(2)
    ]
    first = sends[0]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcpv4_discover",
        "expected_response": "dhcpv4_offer",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": first["client_mac"],
        "transaction_id": first["transaction_id"],
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": first["expected_yiaddr"],
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "send_count": len(sends),
        "dhcpv4_sends": sends,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
        "validation": first["validation"],
    }


def _dhcpv4_client_identifier_probe_plan(
    *,
    case_name: str = "dhcpv4-client-identifier",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcpv4_client_mac(profile, seed, sequence)
    client_identifier_hex = dhcpv4_client_identifier(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    source_port = 68
    destination_port = 67
    offered_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = lease_time * 7 // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcpv4_discover",
        "expected_response": "dhcpv4_offer",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "client_identifier_hex": client_identifier_hex,
        "transaction_id": transaction_id,
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": offered_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_client_identifier_hex": client_identifier_hex,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "offer",
            "message_type_value": 2,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "client_identifier_hex": client_identifier_hex,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcpv4_hostname_probe_plan(
    *, case_name: str = "dhcpv4-hostname", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcpv4_client_mac(profile, seed, sequence)
    hostname = dhcpv4_hostname(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    source_port = 68
    destination_port = 67
    offered_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = lease_time * 7 // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcpv4_discover",
        "expected_response": "dhcpv4_offer",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "hostname": hostname,
        "transaction_id": transaction_id,
        "expected_message_type": "offer",
        "expected_message_type_value": 2,
        "expected_yiaddr": offered_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_hostname": hostname,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "offer",
            "message_type_value": 2,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "hostname": hostname,
            "yiaddr": offered_ipv4,
            "server_identifier": server_identifier,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcpv4_request_ack_probe_plan(
    *, case_name: str = "dhcpv4-request-ack", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcpv4_client_mac(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    source_port = 68
    destination_port = 67
    assigned_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    requested_ipv4 = assigned_ipv4
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    dns_server_ipv4 = f"198.51.100.{1 + digest[6] % 250}"
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = lease_time * 7 // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcpv4_request",
        "expected_response": "dhcpv4_ack",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        "requested_ipv4": requested_ipv4,
        "server_identifier": server_identifier,
        "expected_message_type": "ack",
        "expected_message_type_value": 5,
        "expected_yiaddr": assigned_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_dns_ipv4": dns_server_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "ack",
            "message_type_value": 5,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "yiaddr": assigned_ipv4,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "dns_ipv4": dns_server_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcpv4_renewal_unicast_ack_probe_plan(
    *,
    case_name: str = "dhcpv4-renewal-unicast-ack",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcpv4_client_mac(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    source_port = 68
    destination_port = 67
    bound_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    assigned_ipv4 = bound_ipv4
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    dns_server_ipv4 = f"198.51.100.{1 + digest[6] % 250}"
    lease_time = 3600 + 60 * (digest[5] % 60)
    renewal_time = lease_time // 2
    rebinding_time = lease_time * 7 // 8
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcpv4_request",
        "expected_response": "dhcpv4_ack",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        "client_ciaddr": bound_ipv4,
        "renewal_state": "renewing",
        "renewal_unicast": True,
        "broadcast": False,
        "parameter_request_list": [1, 3, 6, 51, 58, 59],
        "expected_message_type": "ack",
        "expected_message_type_value": 5,
        "expected_yiaddr": assigned_ipv4,
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_dns_ipv4": dns_server_ipv4,
        "expected_lease_time": lease_time,
        "expected_renewal_time": renewal_time,
        "expected_rebinding_time": rebinding_time,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "ack",
            "message_type_value": 5,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "client_ciaddr": bound_ipv4,
            "renewal_unicast": True,
            "yiaddr": assigned_ipv4,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "dns_ipv4": dns_server_ipv4,
            "lease_time": lease_time,
            "renewal_time": renewal_time,
            "rebinding_time": rebinding_time,
            "direction": "server_to_client",
        },
    }


def _dhcpv4_inform_ack_probe_plan(
    *, case_name: str = "dhcpv4-inform-ack", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcpv4_client_mac(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    source_port = 68
    destination_port = 67
    configured_ipv4 = f"198.51.100.{1 + digest[4] % 250}"
    subnet_mask = "255.255.255.0"
    server_identifier = target_ipv4
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    dns_server_ipv4 = f"198.51.100.{1 + digest[6] % 250}"
    parameter_request_list = [1, 3, 6]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcpv4_inform",
        "expected_response": "dhcpv4_ack",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        "client_ciaddr": configured_ipv4,
        "parameter_request_list": parameter_request_list,
        "expected_message_type": "ack",
        "expected_message_type_value": 5,
        "expected_yiaddr_zero": True,
        "expected_no_lease_time": True,
        "expected_server_identifier": server_identifier,
        "expected_subnet_mask": subnet_mask,
        "expected_router_ipv4": router_ipv4,
        "expected_dns_ipv4": dns_server_ipv4,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "ack",
            "message_type_value": 5,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "client_ciaddr": configured_ipv4,
            "yiaddr_zero": True,
            "no_lease_time": True,
            "server_identifier": server_identifier,
            "subnet_mask": subnet_mask,
            "router_ipv4": router_ipv4,
            "dns_ipv4": dns_server_ipv4,
            "requested_parameters": parameter_request_list,
            "direction": "server_to_client",
        },
    }


def _dhcpv4_request_nak_probe_plan(
    *, case_name: str = "dhcpv4-request-nak", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    client_mac = dhcpv4_client_mac(profile, seed, sequence)
    transaction_id = int.from_bytes(digest[0:4], "big") or 1
    source_port = 68
    destination_port = 67
    requested_ipv4 = f"192.0.2.{1 + digest[4] % 250}"
    server_identifier = target_ipv4
    message_text = f"requested address {requested_ipv4} is not on this network ({profile}:{seed}:{sequence})"
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dhcpv4_request",
        "expected_response": "dhcpv4_nak",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "client_mac": client_mac,
        "transaction_id": transaction_id,
        "requested_ipv4": requested_ipv4,
        "server_identifier": server_identifier,
        "expected_message_type": "nak",
        "expected_message_type_value": 6,
        "expected_yiaddr_zero": True,
        "expected_no_lease_time": True,
        "expected_server_identifier": server_identifier,
        "expected_message": message_text,
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {source_port}",
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "op": "reply",
            "op_value": 2,
            "message_type": "nak",
            "message_type_value": 6,
            "transaction_id": transaction_id,
            "client_hardware_address": client_mac,
            "yiaddr_zero": True,
            "no_lease_time": True,
            "server_identifier": server_identifier,
            "message": message_text,
            "direction": "server_to_client",
        },
    }


_DHCPV4_PLAN_BUILDERS: dict[str, object] = {
    "dhcpv4-discover-offer": _dhcpv4_discover_offer_probe_plan,
    "dhcpv4-request-ack": _dhcpv4_request_ack_probe_plan,
    "dhcpv4-client-identifier": _dhcpv4_client_identifier_probe_plan,
    "dhcpv4-hostname": _dhcpv4_hostname_probe_plan,
    "dhcpv4-parameter-request-list": _dhcpv4_parameter_request_list_probe_plan,
    "dhcpv4-lease-time": _dhcpv4_lease_time_probe_plan,
    "dhcpv4-renewal-unicast-ack": _dhcpv4_renewal_unicast_ack_probe_plan,
    "dhcpv4-inform-ack": _dhcpv4_inform_ack_probe_plan,
    "dhcpv4-request-nak": _dhcpv4_request_nak_probe_plan,
    "dhcpv4-rapid-repeat": _dhcpv4_rapid_repeat_probe_plan,
}
_DHCPV4_STIMULUS_ENDPOINT_CASES: frozenset[str] = frozenset(
    {
        "dhcpv4-discover-offer",
        "dhcpv4-request-ack",
        "dhcpv4-client-identifier",
        "dhcpv4-hostname",
        "dhcpv4-parameter-request-list",
        "dhcpv4-lease-time",
        "dhcpv4-renewal-unicast-ack",
        "dhcpv4-inform-ack",
        "dhcpv4-request-nak",
        "dhcpv4-rapid-repeat",
    }
)


def dhcpv4_failure_reasons(case_name: str) -> list[str] | None:
    return None


register(
    ProtocolPlugin(
        name="dhcpv4",
        cases=BEHAVIOR_DHCPV4_CASES,
        plan_builders=_DHCPV4_PLAN_BUILDERS,
        planned_only_cases=frozenset(),
        profile_counts={},
        stimulus_endpoint_cases=_DHCPV4_STIMULUS_ENDPOINT_CASES,
        failure_reasons=dhcpv4_failure_reasons,
    )
)
