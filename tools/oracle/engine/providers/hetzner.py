"""Hetzner oracle live orchestration planning.

This adapter models the oracle-specific two-endpoint Hetzner lab. The dry-run
path is intentionally report-only: it does not invoke provider commands, create
infrastructure, or send packets.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace

from tools.lab.engine.model import (
    LabCommandPlan,
    LabRequest,
    LabRole,
)
from tools.lab.engine.providers.common import validate_remote_dir
from tools.lab.engine.providers.hetzner import HETZNER_LAB_PROVIDER_ADAPTER
from tools.lab.engine import wire_client
from tools.wire.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)

from .base import LiveProviderAdapter
from ..live import (
    LiveCommandPlan,
    LiveEndpoint,
    LiveExchangePlan,
    LiveValidationCheck,
    live_endpoint_from_lab_endpoint,
)
from ..model import JSONObject, PacketPlan


PROVIDER_NAME = "hetzner"
WIRE_ENTRYPOINT = "tools/wire/run"
ORACLE_LIVE_SUITE = "oracle-live"
ORACLE_PRIVATE_GROUP = "oracle-live-private"
PRIVATE_NETWORK_CIDR = "10.42.19.0/24"
PRIVATE_NETWORK_ZONE = "provider-selected"
LIBCRAFTER_PRIVATE_ADDRESS = "10.42.19.10"
REFERENCE_PRIVATE_ADDRESS = "10.42.19.20"
LIBCRAFTER_PRIVATE_IPV6_ADDRESS = "fd42:19::10"
REFERENCE_PRIVATE_IPV6_ADDRESS = "fd42:19::20"
CAPABILITY_REPORT_ARTIFACT = "live-artifacts/oracle-live/capabilities.json"
PROVIDER_CAPABILITY_NAMES = (
    "ipv4_unicast",
    "ipv6_unicast",
    "link_layer_send",
    "link_layer_capture",
    "broadcast",
    "provider_mac_known",
    "controlled_services",
    "controlled_router",
)


def _oracle_private_group() -> str:
    """Per-run private group for live infra isolation.

    Defaults to ORACLE_PRIVATE_GROUP so unit tests stay deterministic; the
    live CLI sets ORACLE_LIVE_PRIVATE_GROUP to a unique value per invocation
    so concurrent live runs get isolated networks/IP allocations.
    """

    return os.environ.get("ORACLE_LIVE_PRIVATE_GROUP", ORACLE_PRIVATE_GROUP)


def hetzner_default_provider_capabilities(
    *,
    dry_run: bool,
    source: str = "planned-defaults",
) -> JSONObject:
    """Return conservative Hetzner capability defaults used before discovery."""

    capabilities = HETZNER_LAB_PROVIDER_ADAPTER.default_provider_capabilities(
        dry_run=dry_run,
        source=source,
    )
    capabilities["capability_report_artifact"] = CAPABILITY_REPORT_ARTIFACT
    return capabilities


def normalize_hetzner_provider_capabilities(
    raw: JSONObject,
    *,
    dry_run: bool | None = None,
    source: str | None = None,
) -> JSONObject:
    """Return flat capability keys plus legacy aliases consumed by corpus logic."""

    normalized = HETZNER_LAB_PROVIDER_ADAPTER.normalize_provider_capabilities(
        raw,
        dry_run=dry_run,
        source=source,
    )
    normalized["capability_report_artifact"] = raw.get(
        "capability_report_artifact",
        CAPABILITY_REPORT_ARTIFACT,
    )
    return normalized


def hetzner_token_configured() -> bool:
    """Return whether the process environment has Hetzner credentials."""

    return HETZNER_LAB_PROVIDER_ADAPTER.credentials_available()


def hetzner_private_network_plan(*, dry_run: bool) -> JSONObject:
    """Return the provider resources required for an oracle wire lab."""

    return _oracle_planned_infrastructure(dry_run=dry_run)


def hetzner_packet_exchange_metadata(*, dry_run: bool) -> JSONObject:
    """Return the packet-exchange network metadata for the Hetzner lab."""

    return _oracle_packet_exchange_metadata(dry_run=dry_run)


def hetzner_endpoints(*, dry_run: bool) -> dict[str, LiveEndpoint]:
    """Return deterministic endpoint roles for the Hetzner oracle lab."""

    return _oracle_planned_endpoints(dry_run=dry_run)


def hetzner_wire_endpoint_plan(
    *,
    dry_run: bool,
    client: wire_client.WireClient | None = None,
    private_group: str | None = None,
    confirm_live_run: bool = False,
    created_endpoint_ids: list[str] | None = None,
) -> dict[str, object]:
    """Create or plan the two private wire endpoints used by Hetzner oracle runs."""

    return _oracle_wire_endpoint_plan(
        dry_run=dry_run,
        client=client,
        private_group=private_group or _oracle_private_group(),
        confirm_live_run=confirm_live_run,
        created_endpoint_ids=created_endpoint_ids,
    )


def _live_endpoint_from_wire_plan(
    endpoint_plan: JSONObject,
    *,
    role: str,
    private_ip: str,
    peer_address: str,
    dry_run: bool,
) -> LiveEndpoint:
    interface = _private_interface(endpoint_plan)
    address = _string_or(interface.get("ipv4"), private_ip)
    return LiveEndpoint(
        endpoint_id=_string_or(endpoint_plan.get("endpoint_id"), f"planned-{role}"),
        role=role,
        interface=_string_or(interface.get("name"), "private"),
        address=address,
        ipv6_address=(
            LIBCRAFTER_PRIVATE_IPV6_ADDRESS
            if role == "libcrafter"
            else REFERENCE_PRIVATE_IPV6_ADDRESS
        ),
        metadata={
            "provider": PROVIDER_NAME,
            "exposure": "private",
            "dry_run": dry_run,
            "creates_infrastructure": not dry_run,
            "would_create_infrastructure": dry_run,
            "isolated_network": True,
            "private_network": True,
            "private_network_cidr": PRIVATE_NETWORK_CIDR,
            "network_zone": PRIVATE_NETWORK_ZONE,
            "resource_type": "wire-endpoint",
            "peer_role": (
                "reference_backend" if role == "libcrafter" else "libcrafter"
            ),
            "peer_address": peer_address,
            "wire_endpoint_plan": endpoint_plan,
            "manifest_path": endpoint_plan.get("manifest_path"),
            "artifact_dir": endpoint_plan.get("artifact_dir"),
            "private_group": _wire_private_group(endpoint_plan),
            "provider_network_id": interface.get("provider_network_id"),
            **({"backend": "scapy"} if role == "reference_backend" else {}),
        },
    )


def _private_interface(endpoint_plan: JSONObject) -> JSONObject:
    interfaces = endpoint_plan.get("interfaces")
    if isinstance(interfaces, list):
        for item in interfaces:
            if isinstance(item, dict) and item.get("exposure") == "private":
                return {str(key): value for key, value in item.items() if isinstance(key, str)}
        for item in interfaces:
            if isinstance(item, dict):
                return {str(key): value for key, value in item.items() if isinstance(key, str)}
    return {}


def _wire_private_group(endpoint_plan: JSONObject) -> str | None:
    metadata = endpoint_plan.get("metadata")
    if isinstance(metadata, dict):
        private_group = metadata.get("private_group")
        if isinstance(private_group, str):
            return private_group
    interface = _private_interface(endpoint_plan)
    interface_metadata = interface.get("metadata")
    if isinstance(interface_metadata, dict):
        private_group = interface_metadata.get("private_group")
        if isinstance(private_group, str):
            return private_group
    return None


def _string_or(value: object, default: str) -> str:
    return value if isinstance(value, str) and value else default


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def hetzner_provider_workflow(*, dry_run: bool) -> list[LiveCommandPlan]:
    """Plan the provider lifecycle commands used by an oracle live run."""

    return _oracle_provider_workflow(dry_run=dry_run)


def _hetzner_wire_provider_workflow(*, dry_run: bool) -> list[LiveCommandPlan]:
    dry_run_flag = ["--dry-run"] if dry_run else []
    create_guard = [] if dry_run else ["--confirm-live-run"]
    workflow = [
        (
            "doctor",
            "check-hetzner-provider",
            [
                WIRE_ENTRYPOINT,
                "doctor",
                "--provider",
                PROVIDER_NAME,
                "--exposure",
                "private",
                *dry_run_flag,
                "--json",
            ],
        ),
        (
            "create",
            "create-libcrafter-private-wire-endpoint",
            [
                WIRE_ENTRYPOINT,
                "create-endpoint",
                "--provider",
                PROVIDER_NAME,
                "--exposure",
                "private",
                "--role",
                "libcrafter",
                "--private-group",
                _oracle_private_group(),
                "--private-ip",
                LIBCRAFTER_PRIVATE_ADDRESS,
                "--private-cidr",
                PRIVATE_NETWORK_CIDR,
                *dry_run_flag,
                *create_guard,
                "--json",
                "--write-manifest",
            ],
        ),
        (
            "create",
            "create-reference-private-wire-endpoint",
            [
                WIRE_ENTRYPOINT,
                "create-endpoint",
                "--provider",
                PROVIDER_NAME,
                "--exposure",
                "private",
                "--role",
                "reference_backend",
                "--private-group",
                _oracle_private_group(),
                "--private-ip",
                REFERENCE_PRIVATE_ADDRESS,
                "--private-cidr",
                PRIVATE_NETWORK_CIDR,
                *dry_run_flag,
                *create_guard,
                "--json",
                "--write-manifest",
            ],
        ),
        (
            "exec",
            "run-oracle-live-exchange-suite",
            [
                WIRE_ENTRYPOINT,
                "exec",
                "<endpoint-id>",
                "--",
                "tools/oracle/run",
                "live-endpoint",
                "--suite",
                ORACLE_LIVE_SUITE,
            ],
        ),
        (
            "download",
            "collect-live-endpoint-artifacts",
            [WIRE_ENTRYPOINT, "download", "<endpoint-id>", "<remote>", "<local>"],
        ),
        (
            "destroy",
            "teardown-disposable-hetzner-endpoints",
            [WIRE_ENTRYPOINT, "destroy-endpoint", "<endpoint-id>", "--json"],
        ),
    ]
    commands: list[LiveCommandPlan] = []
    for operation, purpose, argv in workflow:
        commands.append(
            LiveCommandPlan(
                role="provider",
                purpose=purpose,
                argv=list(argv),
                sends_live_packets=False,
                expects_live_packets=False,
                metadata={
                    "provider": PROVIDER_NAME,
                    "exposure": "private",
                    "dry_run": dry_run,
                    "creates_infrastructure": operation == "create" and not dry_run,
                    "would_create_infrastructure": operation == "create" and dry_run,
                    "always_attempt": operation in {"download", "destroy"},
                    "oracle_two_endpoint": True,
                    "private_network": True,
                    "private_group": _oracle_private_group(),
                    "wire_command": True,
                    "operation": operation,
                },
            )
        )
    return commands


def validate_hetzner_provider_workflow(
    commands: list[LiveCommandPlan],
    *,
    dry_run: bool,
) -> LiveValidationCheck:
    """Validate provider lifecycle planning invariants."""

    errors: list[str] = []
    purposes = {command.purpose for command in commands}
    required = {
        "check-hetzner-provider",
        "create-libcrafter-private-wire-endpoint",
        "create-reference-private-wire-endpoint",
        "run-oracle-live-exchange-suite",
        "collect-live-endpoint-artifacts",
        "teardown-disposable-hetzner-endpoints",
    }
    missing = sorted(required - purposes)
    if missing:
        errors.append(f"missing provider workflow phases: {', '.join(missing)}")

    for command in commands:
        if command.role != "provider":
            errors.append(f"unexpected provider workflow role: {command.role}")
        if len(command.argv) < 2 or command.argv[0] != WIRE_ENTRYPOINT:
            errors.append(f"provider command must route through {WIRE_ENTRYPOINT}")
        if command.metadata.get("wire_command") is not True:
            errors.append("provider command must be marked as wire_command")
        if command.metadata.get("provider") != PROVIDER_NAME:
            errors.append("provider command must target Hetzner")
        if dry_run and command.metadata.get("operation") in {
            "doctor",
            "create",
        } and "--dry-run" not in command.argv:
            errors.append(f"dry-run provider command lacks --dry-run: {command.shell()}")
        if (
            not dry_run
            and command.metadata.get("operation") == "create"
            and "--confirm-live-run" not in command.argv
        ):
            errors.append("real provider create command lacks --confirm-live-run")
        if command.sends_live_packets or command.expects_live_packets:
            errors.append("provider lifecycle commands cannot be endpoint packet commands")

    return LiveValidationCheck(
        name="hetzner-provider-workflow",
        passed=not errors,
        subject=PROVIDER_NAME,
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "dry_run": dry_run,
            "creates_infrastructure": not dry_run,
            "always_collect_artifacts": True,
            "always_teardown": True,
        },
    )


def validate_hetzner_dry_run_exchange(
    exchange: LiveExchangePlan,
) -> LiveValidationCheck:
    """Validate that a Hetzner dry-run exchange is two-endpoint and non-mutating."""

    errors: list[str] = []
    if exchange.provider != PROVIDER_NAME:
        errors.append(f"unexpected provider: {exchange.provider}")
    if exchange.live_packet_exchange:
        errors.append("Hetzner dry-run cannot claim live packet exchange")
    if exchange.sender.role == exchange.receiver.role:
        errors.append("sender and receiver roles must differ")
    if not bool(exchange.sender.metadata.get("private_network")):
        errors.append("sender endpoint must use a private network")
    if not bool(exchange.receiver.metadata.get("private_network")):
        errors.append("receiver endpoint must use a private network")
    if exchange.sender.metadata.get("provider") != PROVIDER_NAME:
        errors.append("sender endpoint must be a Hetzner endpoint")
    if exchange.receiver.metadata.get("provider") != PROVIDER_NAME:
        errors.append("receiver endpoint must be a Hetzner endpoint")
    if (
        exchange.sender_command.sends_live_packets
        or exchange.receiver_command.sends_live_packets
    ):
        errors.append("Hetzner dry-run endpoint commands must not send packets")
    if (
        exchange.sender_command.expects_live_packets
        or exchange.receiver_command.expects_live_packets
    ):
        errors.append("Hetzner dry-run endpoint commands must not expect packets")

    return LiveValidationCheck(
        name="hetzner-dry-run-live-invariant",
        passed=not errors,
        subject=f"{exchange.direction}:index-{exchange.index:06d}",
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "direction": exchange.direction,
            "packet_index": exchange.index,
            "private_network": True,
            "creates_infrastructure": False,
            "live_packet_exchange": False,
        },
    )


def hetzner_wire_remote_dir() -> str:
    """Return the repository directory used by Hetzner wire endpoints."""

    return validate_remote_dir(os.environ.get("LIBCRAFTER_WIRE_REMOTE_DIR"))


def hetzner_endpoint_remote_command(
    *,
    endpoint_role: str,
    remote_dir: str,
    request_path: str,
    out_dir: str,
) -> list[str]:
    """Return the endpoint protocol command executed on a Hetzner wire endpoint."""

    quoted_remote_dir = shlex.quote(remote_dir)
    quoted_request = shlex.quote(request_path)
    quoted_out = shlex.quote(out_dir)
    if endpoint_role == "libcrafter":
        script = "\n".join(
            [
                "set -euo pipefail",
                f"cd {quoted_remote_dir}",
                'if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi',
                (
                    "cargo run -q -p oracle-adapters --bin live_endpoint -- "
                    f"--live --input {quoted_request} --out {quoted_out}"
                ),
            ]
        )
    else:
        script = "\n".join(
            [
                "set -euo pipefail",
                f"cd {quoted_remote_dir}",
                'export PYTHONPATH="tools/oracle${PYTHONPATH:+:$PYTHONPATH}"',
                (
                    "python3 -m engine.backends.scapy.live "
                    f"--live --input {quoted_request} --out {quoted_out}"
                ),
            ]
        )
    return ["bash", "-lc", script]


def hetzner_live_transit_plan(plan: PacketPlan) -> PacketPlan:
    """Apply Hetzner transit rewrites before expected-model generation."""

    fields = {
        layer: dict(layer_fields)
        for layer, layer_fields in plan.fields.items()
    }
    wire_policy = hetzner_wire_comparison_policy(plan)
    rewrites: list[JSONObject] = []
    ipv4 = fields.get("ipv4")
    if isinstance(ipv4, dict) and int(ipv4.get("ttl", 64)) < 2:
        rewrites.append(
            {
                "field": "ipv4.ttl",
                "from": ipv4.get("ttl"),
                "to": 64,
                "reason": "provider live transit decrements TTL before capture",
            }
        )
        ipv4["ttl"] = 64

    return replace(
        plan,
        fields=fields,
        strict_bytes=bool(wire_policy.get("strict_bytes", plan.strict_bytes)),
        metadata={
            **plan.metadata,
            "wire": wire_policy,
            "live_transit_rewrites": rewrites,
            "live_mutable_fields": list(wire_policy.get("mutable_fields", [])),
            "strict_bytes": bool(wire_policy.get("strict_bytes", plan.strict_bytes)),
        },
    )


def hetzner_wire_comparison_policy(plan: PacketPlan) -> JSONObject:
    """Return Hetzner wire comparison policy for one packet plan."""

    raw_policy = plan.metadata.get("wire")
    if isinstance(raw_policy, Mapping):
        policy = {
            key: value
            for key, value in raw_policy.items()
            if isinstance(key, str)
        }
    else:
        from .policy import wire_comparison_policy

        policy = wire_comparison_policy(plan, provider=PROVIDER_NAME)

    mutable_fields = policy.get("mutable_fields", [])
    if not isinstance(mutable_fields, Sequence) or isinstance(
        mutable_fields,
        (str, bytes, bytearray),
    ):
        mutable_fields = []
    policy["mutable_fields"] = [
        field
        for field in mutable_fields
        if isinstance(field, str) and field
    ]

    strict_bytes = policy.get("strict_bytes")
    if not isinstance(strict_bytes, bool):
        byte_mutable_fields = policy.get("byte_mutable_fields", policy["mutable_fields"])
        strict_bytes = bool(plan.strict_bytes and not byte_mutable_fields)
    policy["strict_bytes"] = strict_bytes

    compare_root = policy.get("compare_root")
    if compare_root is not None and not isinstance(compare_root, str):
        compare_root = None
    policy["compare_root"] = compare_root
    policy.setdefault("provider", PROVIDER_NAME)
    return policy


def _oracle_lab_request(
    *,
    dry_run: bool,
    private_group: str | None = None,
    confirm_live_run: bool = False,
) -> LabRequest:
    group = private_group or _oracle_private_group()
    return LabRequest(
        provider=PROVIDER_NAME,
        profile=ORACLE_LIVE_SUITE,
        seed=0,
        roles=[
            LabRole(
                name="libcrafter",
                requested_private_ipv4=LIBCRAFTER_PRIVATE_ADDRESS,
            ),
            LabRole(
                name="reference_backend",
                requested_private_ipv4=REFERENCE_PRIVATE_ADDRESS,
            ),
        ],
        dry_run=dry_run,
        confirm_live_run=confirm_live_run,
        workload_label=ORACLE_LIVE_SUITE,
        metadata={
            "session_id": ORACLE_LIVE_SUITE,
            "private_group": group,
            "role_private_ipv4s": {
                "libcrafter": LIBCRAFTER_PRIVATE_ADDRESS,
                "reference_backend": REFERENCE_PRIVATE_ADDRESS,
            },
        },
    )


def _oracle_planned_infrastructure(*, dry_run: bool) -> JSONObject:
    request = _oracle_lab_request(dry_run=dry_run)
    infrastructure = HETZNER_LAB_PROVIDER_ADAPTER.planned_infrastructure(request)
    provider_capabilities = infrastructure.get("provider_capabilities")
    if isinstance(provider_capabilities, dict):
        provider_capabilities["capability_report_artifact"] = CAPABILITY_REPORT_ARTIFACT
    return infrastructure


def _oracle_packet_exchange_metadata(*, dry_run: bool) -> JSONObject:
    request = _oracle_lab_request(dry_run=dry_run)
    private_group = HETZNER_LAB_PROVIDER_ADAPTER.private_group(request)
    return {
        "provider": PROVIDER_NAME,
        "wire_provider": HETZNER_LAB_PROVIDER_ADAPTER.wire_provider,
        "wire_exposure": HETZNER_LAB_PROVIDER_ADAPTER.wire_exposure,
        "endpoint_roles": ["libcrafter", "reference_backend"],
        "private_group": private_group,
        "isolated_network": True,
        "private_network": True,
        "private_network_cidr": PRIVATE_NETWORK_CIDR,
        "packet_exchange_network": HETZNER_LAB_PROVIDER_ADAPTER.wire_exposure,
        "packet_exchange_network_label": "hetzner-private-network",
        "dry_run": dry_run,
    }


def _oracle_planned_endpoints(*, dry_run: bool) -> dict[str, LiveEndpoint]:
    request = _oracle_lab_request(
        dry_run=dry_run,
        confirm_live_run=not dry_run,
    )
    roles = HETZNER_LAB_PROVIDER_ADAPTER.plan_roles(request)
    endpoints: dict[str, LiveEndpoint] = {}
    for role in roles:
        manifest = _planned_manifest_for_role(role, request=request)
        lab_endpoint = HETZNER_LAB_PROVIDER_ADAPTER.normalize_endpoint(
            manifest,
            role=role,
            peer_roles=_peer_roles_for(role, roles),
            request=request,
        )
        endpoints[role.name] = _routed_private_live_endpoint(
            live_endpoint_from_lab_endpoint(lab_endpoint)
        )
    return endpoints


def _oracle_wire_endpoint_plan(
    *,
    dry_run: bool,
    client: wire_client.WireClient | None = None,
    private_group: str | None = None,
    confirm_live_run: bool = False,
    created_endpoint_ids: list[str] | None = None,
) -> dict[str, object]:
    request = _oracle_lab_request(
        dry_run=dry_run,
        private_group=private_group,
        confirm_live_run=confirm_live_run,
    )
    plan = HETZNER_LAB_PROVIDER_ADAPTER.wire_endpoint_plan(
        request,
        client=_OracleLabWireClient(client or wire_client.WireClient()),
        created_endpoint_ids=created_endpoint_ids,
    )
    return _oracle_wire_plan_from_lab_plan(plan)


def _oracle_wire_plan_from_lab_plan(plan: JSONObject) -> dict[str, object]:
    endpoints: dict[str, LiveEndpoint] = {}
    raw_endpoints = plan.get("endpoints")
    if isinstance(raw_endpoints, Mapping):
        for role, endpoint in raw_endpoints.items():
            if isinstance(role, str) and isinstance(endpoint, Mapping):
                endpoints[role] = _routed_private_live_endpoint(
                    live_endpoint_from_lab_endpoint(endpoint)
                )
    return {
        **plan,
        "wire_exposure": plan.get("exposure", HETZNER_LAB_PROVIDER_ADAPTER.wire_exposure),
        "command_metadata": plan.get("command_records", []),
        "live_endpoints": endpoints,
    }


def _routed_private_live_endpoint(endpoint: LiveEndpoint) -> LiveEndpoint:
    metadata = dict(endpoint.metadata)
    mac_address = metadata.pop("mac_address", None)
    if isinstance(mac_address, str) and mac_address:
        metadata.setdefault("observed_mac_address", mac_address)
    metadata.setdefault("link_layer_send", False)
    metadata.setdefault("link_layer_capture", False)
    metadata.setdefault("provider_mac_known", False)
    metadata["endpoint_protocol_mac"] = False
    return replace(endpoint, metadata=metadata)


def _oracle_provider_workflow(*, dry_run: bool) -> list[LiveCommandPlan]:
    request = _oracle_lab_request(
        dry_run=dry_run,
        confirm_live_run=not dry_run,
    )
    commands = [
        _live_provider_command_from_lab(command)
        for command in HETZNER_LAB_PROVIDER_ADAPTER.provider_workflow(request)
    ]
    insert_at = next(
        (
            index
            for index, command in enumerate(commands)
            if command.purpose == "collect-live-endpoint-artifacts"
        ),
        len(commands),
    )
    commands.insert(
        insert_at,
        LiveCommandPlan(
            role="provider",
            purpose="run-oracle-live-exchange-suite",
            argv=[
                WIRE_ENTRYPOINT,
                "exec",
                "<endpoint-id>",
                "--",
                "tools/oracle/run",
                "live-endpoint",
                "--suite",
                ORACLE_LIVE_SUITE,
            ],
            sends_live_packets=False,
            expects_live_packets=False,
            metadata={
                "provider": PROVIDER_NAME,
                "exposure": HETZNER_LAB_PROVIDER_ADAPTER.wire_exposure,
                "dry_run": dry_run,
                "creates_infrastructure": False,
                "would_create_infrastructure": False,
                "oracle_two_endpoint": True,
                "private_network": True,
                "private_group": _oracle_private_group(),
                "wire_command": True,
                "operation": "exec",
            },
        ),
    )
    return commands


def _live_provider_command_from_lab(command: LabCommandPlan) -> LiveCommandPlan:
    metadata: JSONObject = dict(command.metadata)
    metadata["lab_operation"] = command.operation
    metadata["operation"] = _oracle_operation(command.operation)
    metadata.setdefault("provider", PROVIDER_NAME)
    metadata.setdefault("exposure", HETZNER_LAB_PROVIDER_ADAPTER.wire_exposure)
    metadata.setdefault("wire_command", True)
    return LiveCommandPlan(
        role="provider",
        purpose=_oracle_workflow_purpose(command),
        argv=list(command.argv),
        sends_live_packets=False,
        expects_live_packets=False,
        metadata=metadata,
    )


def _oracle_workflow_purpose(command: LabCommandPlan) -> str:
    if command.operation == "wire.doctor":
        return "check-hetzner-provider"
    if command.operation == "wire.create":
        suffix = "libcrafter" if command.role == "libcrafter" else "reference"
        return f"create-{suffix}-private-wire-endpoint"
    if command.operation == "wire.collect_artifacts":
        return "collect-live-endpoint-artifacts"
    if command.operation == "wire.destroy":
        return "teardown-disposable-hetzner-endpoints"
    return command.purpose


def _oracle_operation(operation: str) -> str:
    return {
        "wire.doctor": "doctor",
        "wire.create": "create",
        "wire.collect_artifacts": "download",
        "wire.destroy": "destroy",
    }.get(operation, operation)


def _peer_roles_for(role: LabRole, roles: Sequence[LabRole]) -> list[LabRole]:
    if role.peer_roles:
        requested = set(role.peer_roles)
        return [peer for peer in roles if peer.name in requested]
    return [peer for peer in roles if peer.name != role.name]


def _planned_manifest_for_role(role: LabRole, *, request: LabRequest) -> EndpointManifest:
    private_group = HETZNER_LAB_PROVIDER_ADAPTER.private_group(request)
    return EndpointManifest(
        endpoint_id=f"hetzner-planned-{_endpoint_suffix(role.name)}",
        provider=HETZNER_LAB_PROVIDER_ADAPTER.wire_provider,
        exposure=HETZNER_LAB_PROVIDER_ADAPTER.wire_exposure,
        status="planned" if request.dry_run else "created",
        role=role.name,
        created_at="1970-01-01T00:00:00Z",
        ssh=EndpointSSHInfo(host="127.0.0.1", user="root"),
        interfaces=[
            NetworkInterface(
                name="oracle0",
                exposure=HETZNER_LAB_PROVIDER_ADAPTER.wire_exposure,
                ipv4=role.requested_private_ipv4 or role.planned_ipv4,
                ipv6=(
                    LIBCRAFTER_PRIVATE_IPV6_ADDRESS
                    if role.name == "libcrafter"
                    else REFERENCE_PRIVATE_IPV6_ADDRESS
                ),
                provider_network_id=private_group,
                metadata={"private_group": private_group},
            )
        ],
        provider_resources=ProviderResources(),
        artifact_dir=f"/tmp/libcrafter-wire/{PROVIDER_NAME}/{role.name}",
        metadata={"private_group": private_group, "planned": True},
    )


def _endpoint_suffix(role: str) -> str:
    return "reference" if role == "reference_backend" else role


@dataclass(frozen=True, slots=True)
class _LabWireCreateResponse:
    source: object
    manifest: EndpointManifest
    json_data: JSONObject
    provider: str
    exposure: str
    role: str
    private_group: str | None
    private_ip: str | None
    dry_run: bool

    def command_plan(
        self,
        *,
        purpose: str | None = None,
        role: str | None = None,
        artifacts: Sequence[str] = (),
    ) -> LabCommandPlan:
        metadata = _source_record_metadata(self.source)
        metadata.update(
            {
                "provider": self.provider,
                "exposure": self.exposure,
                "private_group": self.private_group,
                "private_ip": self.private_ip,
                "wire_command": True,
            }
        )
        return LabCommandPlan(
            purpose=purpose or f"create {self.role} endpoint",
            role=role or self.role,
            argv=_wire_create_argv(
                provider=self.provider,
                exposure=self.exposure,
                role=self.role,
                private_group=self.private_group,
                private_ip=self.private_ip,
                dry_run=self.dry_run,
            ),
            operation="wire.create",
            dry_run=self.dry_run,
            live_mutation=not self.dry_run,
            artifacts=list(artifacts),
            metadata=metadata,
        )


class _OracleLabWireClient:
    def __init__(self, client: object) -> None:
        self._client = client

    def create(
        self,
        *,
        provider: str,
        exposure: str,
        role: str,
        private_group: str | None,
        private_ip: str | None,
        dry_run: bool,
        write_manifest: bool,
        confirm_live_run: bool,
    ) -> _LabWireCreateResponse:
        create = getattr(self._client, "create")
        try:
            response = create(
                provider=provider,
                exposure=exposure,
                role=role,
                private_group=private_group,
                private_ip=private_ip,
                dry_run=dry_run,
                write_manifest=write_manifest,
                confirm_live_run=confirm_live_run,
            )
        except TypeError:
            response = create(
                provider=provider,
                exposure=exposure,
                role=role,
                private_group=private_group,
                private_ip=private_ip,
                dry_run=dry_run,
                confirm_live_run=confirm_live_run,
            )
        manifest = _response_manifest_for_lab(
            response,
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
            dry_run=dry_run,
        )
        json_data = _response_json_for_lab(response, manifest)
        return _LabWireCreateResponse(
            source=response,
            manifest=manifest,
            json_data=json_data,
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
            dry_run=dry_run,
        )


def _response_manifest_for_lab(
    response: object,
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    dry_run: bool,
) -> EndpointManifest:
    manifest = getattr(response, "manifest", None)
    if isinstance(manifest, EndpointManifest):
        return manifest
    json_data = getattr(response, "json_data", None)
    if isinstance(json_data, Mapping):
        return _manifest_from_wire_json(
            json_data,
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
            dry_run=dry_run,
        )
    endpoint_id = getattr(manifest, "endpoint_id", None)
    return _manifest_from_wire_json(
        {"endpoint_id": endpoint_id} if isinstance(endpoint_id, str) else {},
        provider=provider,
        exposure=exposure,
        role=role,
        private_group=private_group,
        private_ip=private_ip,
        dry_run=dry_run,
    )


def _response_json_for_lab(response: object, manifest: EndpointManifest) -> JSONObject:
    json_data = getattr(response, "json_data", None)
    if isinstance(json_data, Mapping):
        return {str(key): value for key, value in json_data.items() if isinstance(key, str)}
    return manifest.to_dict()


def _manifest_from_wire_json(
    data: Mapping[str, object],
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    dry_run: bool,
) -> EndpointManifest:
    endpoint_id = data.get("endpoint_id")
    interfaces = data.get("interfaces")
    interface_models = (
        [
            _network_interface_from_json(interface)
            for interface in interfaces
            if isinstance(interface, Mapping)
        ]
        if isinstance(interfaces, list)
        else []
    )
    if not interface_models:
        interface_models = [
            NetworkInterface(
                name="oracle0",
                exposure=exposure,
                ipv4=private_ip,
                provider_network_id=private_group,
                metadata={"private_group": private_group} if private_group else {},
            )
        ]
    metadata = data.get("metadata")
    return EndpointManifest(
        endpoint_id=endpoint_id if isinstance(endpoint_id, str) else f"{provider}-{exposure}-{role}",
        provider=provider,
        exposure=exposure,
        status="planned" if dry_run else "created",
        role=role,
        created_at="1970-01-01T00:00:00Z",
        ssh=EndpointSSHInfo(host="127.0.0.1", user="root"),
        interfaces=interface_models,
        provider_resources=ProviderResources(),
        artifact_dir=f"/tmp/libcrafter-wire/{provider}/{role}",
        metadata={
            **({str(key): value for key, value in metadata.items() if isinstance(key, str)}
               if isinstance(metadata, Mapping) else {}),
            **({"private_group": private_group} if private_group else {}),
        },
    )


def _network_interface_from_json(value: Mapping[str, object]) -> NetworkInterface:
    metadata = value.get("metadata")
    return NetworkInterface(
        name=_string_or(value.get("name"), "private"),
        exposure=_string_or(value.get("exposure"), "private"),
        ipv4=_optional_string(value.get("ipv4")),
        ipv6=_optional_string(value.get("ipv6")),
        mac=_optional_string(value.get("mac")),
        provider_network_id=_optional_string(value.get("provider_network_id")),
        metadata={
            str(key): item
            for key, item in metadata.items()
            if isinstance(key, str)
        } if isinstance(metadata, Mapping) else {},
    )


def _source_record_metadata(response: object) -> JSONObject:
    record = getattr(response, "record", None)
    if record is not None:
        to_dict = getattr(record, "to_dict", None)
        if callable(to_dict):
            value = to_dict()
            if isinstance(value, Mapping):
                return {str(key): item for key, item in value.items() if isinstance(key, str)}
    return {}


def _wire_create_argv(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    dry_run: bool,
) -> list[str]:
    argv = [
        WIRE_ENTRYPOINT,
        "create-endpoint",
        "--provider",
        provider,
        "--exposure",
        exposure,
        "--role",
        role,
        "--json",
    ]
    if private_group is not None:
        argv.extend(["--private-group", private_group])
    if private_ip is not None:
        argv.extend(["--private-ip", private_ip])
        argv.extend(["--private-cidr", PRIVATE_NETWORK_CIDR])
    if dry_run:
        argv.append("--dry-run")
    return argv


@dataclass(frozen=True, slots=True)
class HetznerLiveProviderAdapter:
    """Oracle live adapter for the existing Hetzner private wire lab."""

    name: str = PROVIDER_NAME
    wire_provider: str = PROVIDER_NAME
    wire_exposure: str = "private"
    endpoint_roles: tuple[str, str] = ("libcrafter", "reference_backend")
    private_group: str | None = ORACLE_PRIVATE_GROUP
    endpoint_private_ips: Mapping[str, str] = field(
        default_factory=lambda: {
            "libcrafter": LIBCRAFTER_PRIVATE_ADDRESS,
            "reference_backend": REFERENCE_PRIVATE_ADDRESS,
        }
    )
    artifact_collection_purpose: str = "collect-live-endpoint-artifacts"
    teardown_purpose: str = "teardown-disposable-hetzner-endpoints"
    credential_label: str = "HETZNER_API_TOKEN"
    missing_credential_reason: str = "missing HETZNER_API_TOKEN"

    def token_configured(self) -> bool:
        """Return whether Hetzner credentials are present."""

        return hetzner_token_configured()

    def default_provider_capabilities(
        self,
        *,
        dry_run: bool,
        source: str = "planned-defaults",
    ) -> JSONObject:
        """Return Hetzner capability defaults before endpoint discovery."""

        return hetzner_default_provider_capabilities(dry_run=dry_run, source=source)

    def normalize_provider_capabilities(
        self,
        raw: JSONObject,
        *,
        dry_run: bool | None = None,
        source: str | None = None,
    ) -> JSONObject:
        """Normalize Hetzner provider capabilities for corpus filtering."""

        return normalize_hetzner_provider_capabilities(
            raw,
            dry_run=dry_run,
            source=source,
        )

    def planned_infrastructure(self, *, dry_run: bool) -> JSONObject:
        """Return planned Hetzner private lab infrastructure."""

        return hetzner_private_network_plan(dry_run=dry_run)

    def packet_exchange_metadata(self, *, dry_run: bool) -> JSONObject:
        """Return Hetzner packet-exchange network metadata."""

        return hetzner_packet_exchange_metadata(dry_run=dry_run)

    def endpoints(self, *, dry_run: bool) -> dict[str, LiveEndpoint]:
        """Return the two Hetzner endpoint roles."""

        return hetzner_endpoints(dry_run=dry_run)

    def wire_endpoint_plan(
        self,
        *,
        dry_run: bool,
        client: wire_client.WireClient | None = None,
        private_group: str | None = None,
        confirm_live_run: bool = False,
        created_endpoint_ids: list[str] | None = None,
    ) -> dict[str, object]:
        """Create or plan the two Hetzner private wire endpoints."""

        return hetzner_wire_endpoint_plan(
            dry_run=dry_run,
            client=client,
            private_group=private_group or _oracle_private_group(),
            confirm_live_run=confirm_live_run,
            created_endpoint_ids=created_endpoint_ids,
        )

    def provider_workflow(self, *, dry_run: bool) -> list[LiveCommandPlan]:
        """Return Hetzner provider lifecycle command plans."""

        return hetzner_provider_workflow(dry_run=dry_run)

    def validate_provider_workflow(
        self,
        commands: list[LiveCommandPlan],
        *,
        dry_run: bool,
    ) -> LiveValidationCheck:
        """Validate Hetzner provider lifecycle planning."""

        return validate_hetzner_provider_workflow(commands, dry_run=dry_run)

    def validate_dry_run_exchange(
        self,
        exchange: LiveExchangePlan,
    ) -> LiveValidationCheck:
        """Validate a Hetzner provider-backed dry-run exchange."""

        return validate_hetzner_dry_run_exchange(exchange)

    def remote_dir(self) -> str:
        """Return the remote repository directory for Hetzner wire endpoints."""

        return hetzner_wire_remote_dir()

    def wire_environment(self) -> Mapping[str, str]:
        """Return environment overrides for Hetzner wire subprocesses."""

        return {"HETZNER_PRIVATE_CIDR": PRIVATE_NETWORK_CIDR}

    def endpoint_remote_command(
        self,
        *,
        endpoint_role: str,
        remote_dir: str,
        request_path: str,
        out_dir: str,
    ) -> list[str]:
        """Return the Hetzner endpoint protocol command for one role."""

        return hetzner_endpoint_remote_command(
            endpoint_role=endpoint_role,
            remote_dir=remote_dir,
            request_path=request_path,
            out_dir=out_dir,
        )

    def normalize_live_endpoints(
        self,
        endpoints: Mapping[str, LiveEndpoint],
    ) -> Mapping[str, LiveEndpoint]:
        """Force routed private endpoints to use L3 endpoint protocol addresses."""

        return {
            role: _routed_private_live_endpoint(endpoint)
            for role, endpoint in endpoints.items()
        }

    def apply_transit_plan(self, plan: PacketPlan) -> PacketPlan:
        """Apply Hetzner transit rewrites before live comparison."""

        return hetzner_live_transit_plan(plan)

    def wire_comparison_policy(self, plan: PacketPlan) -> JSONObject:
        """Return the Hetzner wire comparison policy for one packet."""

        return hetzner_wire_comparison_policy(plan)


HETZNER_LIVE_PROVIDER_ADAPTER: LiveProviderAdapter = HetznerLiveProviderAdapter()
