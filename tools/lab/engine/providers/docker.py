"""Docker lab provider adapter.

The lab provider maps Docker to the isolated ``docker/private`` wire exposure.
LAN and WAN Docker modes remain direct wire-provider modes in this phase.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from tools.wire.engine.providers.docker.constants import (
    DOCKER_COMMAND,
    DOCKER_COMMAND_ENV,
    DOCKER_DEFAULT_IMAGE,
    DOCKER_DEFAULT_PRIVATE_CIDR,
    DOCKER_IMAGE_ENV,
    DOCKER_PRIVATE_CIDR_ENV,
)
from tools.wire.engine.providers.docker.resources import docker_private_network_name

from .. import paths
from ..model import JSONObject, LabCommandPlan, LabRequest, LabRole
from .common import (
    build_command_plan,
    normalize_provider_capabilities as normalize_common_provider_capabilities,
    request_session_label,
    slug_label,
    validate_remote_dir,
)


PROVIDER_NAME = "docker"
WIRE_PROVIDER = "docker"
WIRE_EXPOSURE = "private"
WIRE_ENTRYPOINT = "tools/wire/run"
PRIVATE_NETWORK_CIDR = DOCKER_DEFAULT_PRIVATE_CIDR
DEFAULT_PRIVATE_IPV4_PREFIX = "10.79.0"
CAPABILITY_REPORT_ARTIFACT = "artifacts/lab/capabilities.json"
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
DOCKER_WIRE_POLICY: JSONObject = {
    "ipv4_header_mutable": False,
    "l3_send_adds_link_layer_metadata": False,
    "transit_decrements_ipv4_ttl": False,
}


def docker_credentials_available() -> bool:
    """Return whether Docker live-run provider credentials are configured."""

    return True


def docker_session_id(request: LabRequest) -> str:
    """Return the deterministic session id for a Docker lab request."""

    override = _metadata_string(request.metadata, "session_id")
    if override is not None:
        return slug_label(override, fallback="docker-lab-session", max_length=127)
    return request_session_label(request, prefix="lab-docker", max_length=127)


def docker_private_group(request: LabRequest) -> str:
    """Return the deterministic Docker private network group for a request."""

    override = _metadata_string(request.metadata, "private_group")
    if override is not None:
        return slug_label(override, fallback="docker-private", max_length=63)
    return slug_label(
        f"{docker_session_id(request)}-private",
        fallback="docker-private",
        max_length=63,
    )


def docker_private_network_metadata(private_group: str) -> JSONObject:
    """Return Docker internal bridge metadata for planning output."""

    network_name = docker_private_network_name(private_group)
    return {
        "planned": True,
        "provider": PROVIDER_NAME,
        "resource_type": "docker-private-bridge",
        "type": "docker-private-network",
        "wire_provider": WIRE_PROVIDER,
        "wire_exposure": WIRE_EXPOSURE,
        "network_id": network_name,
        "network_name": network_name,
        "private_group": private_group,
        "ip_range": PRIVATE_NETWORK_CIDR,
        "cidr": PRIVATE_NETWORK_CIDR,
        "private_cidr": PRIVATE_NETWORK_CIDR,
        "backend": "docker-internal-bridge",
        "driver": "bridge",
        "internal": True,
        "isolated": True,
        "same_segment": True,
        "l2_segment": True,
        "broadcast": True,
        "address_source": "static-private-ipv4",
        "controlled_router": False,
    }


def docker_default_provider_capabilities(
    *,
    dry_run: bool,
    source: str = "planned-defaults",
) -> JSONObject:
    """Return Docker private-network capability defaults."""

    defaults: JSONObject = {
        "live_packet_exchange": True,
        "ipv4_unicast": True,
        "ipv6_unicast": False,
        "link_layer_send": True,
        "link_layer_capture": True,
        "broadcast": True,
        "provider_mac_known": True,
        "controlled_services": True,
        "controlled_router": False,
        "capability_report_artifact": CAPABILITY_REPORT_ARTIFACT,
        "wire_policy": dict(DOCKER_WIRE_POLICY),
        "checks": {
            "ipv4_unicast": {
                "status": "planned" if dry_run else "manifest_required",
                "value": True,
                "reason": "Docker private endpoint IPv4 addresses are planned",
            },
            "ipv6_unicast": {
                "status": "not_planned",
                "value": False,
                "reason": "Docker private endpoints are currently IPv4-only",
            },
            "link_layer_send": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "Docker private endpoints can send raw Ethernet frames on the internal bridge",
            },
            "link_layer_capture": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "Docker private endpoints can capture Ethernet frames on the internal bridge",
            },
            "broadcast": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "Docker internal bridge networking carries same-segment broadcast traffic",
            },
            "provider_mac_known": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "wire endpoint manifests record Docker private interface MACs before packet exchange",
            },
            "controlled_services": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "lab endpoints are disposable containers controlled by callers",
            },
            "controlled_router": {
                "status": "not_available",
                "value": False,
                "reason": "the Docker private lab is same-segment, not routed transit",
            },
        },
    }
    return normalize_docker_provider_capabilities(
        defaults,
        dry_run=dry_run,
        source=source,
    )


def normalize_docker_provider_capabilities(
    raw: JSONObject,
    *,
    dry_run: bool | None = None,
    source: str | None = None,
) -> JSONObject:
    """Normalize Docker capability data into the lab session shape."""

    normalized = normalize_common_provider_capabilities(
        raw,
        provider=PROVIDER_NAME,
        dry_run=dry_run,
        source=source,
        capability_names=PROVIDER_CAPABILITY_NAMES,
        defaults={
            "live_packet_exchange": True,
            "wire_policy": dict(DOCKER_WIRE_POLICY),
        },
    )
    normalized.setdefault("wire_policy", dict(DOCKER_WIRE_POLICY))
    return normalized


def plan_docker_roles(request: LabRequest) -> list[LabRole]:
    """Return roles with deterministic Docker private IPv4 metadata."""

    roles: list[LabRole] = []
    role_private_ipv4s = _role_private_ipv4_metadata(request.metadata)
    all_role_names = [role.name for role in request.roles]
    private_group = docker_private_group(request)

    for index, role in enumerate(request.roles):
        metadata_private_ipv4 = role_private_ipv4s.get(role.name)
        requested_private_ipv4 = role.requested_private_ipv4 or metadata_private_ipv4
        planned_ipv4 = (
            requested_private_ipv4
            or role.planned_ipv4
            or _default_private_ipv4(index)
        )
        address_source = _role_address_source(
            role=role,
            metadata_private_ipv4=metadata_private_ipv4,
        )
        peer_roles = (
            list(role.peer_roles)
            if role.peer_roles
            else [name for name in all_role_names if name != role.name]
        )
        roles.append(
            LabRole(
                name=role.name,
                requested_private_ipv4=requested_private_ipv4,
                planned_ipv4=planned_ipv4,
                peer_roles=peer_roles,
                capabilities=list(role.capabilities),
                bootstrap_metadata=dict(role.bootstrap_metadata),
                workload_metadata=dict(role.workload_metadata),
                metadata={
                    **role.metadata,
                    "provider": PROVIDER_NAME,
                    "wire_provider": WIRE_PROVIDER,
                    "wire_exposure": WIRE_EXPOSURE,
                    "private_group": private_group,
                    "private_network": True,
                    "private_network_cidr": PRIVATE_NETWORK_CIDR,
                    "packet_exchange_network": WIRE_EXPOSURE,
                    "isolated_network": True,
                    "docker_network": docker_private_network_metadata(private_group),
                    "planned_private_address": planned_ipv4,
                    "planned_private_address_source": address_source,
                    "wire_policy": dict(DOCKER_WIRE_POLICY),
                    "requested_private_ip_used_for_wire": requested_private_ipv4 is not None,
                },
            )
        )
    return roles


def docker_planned_infrastructure(request: LabRequest) -> JSONObject:
    """Return dry-run-safe Docker infrastructure metadata."""

    roles = plan_docker_roles(request)
    private_group = docker_private_group(request)
    private_network = docker_private_network_metadata(private_group)
    return {
        "provider": PROVIDER_NAME,
        "wire_provider": WIRE_PROVIDER,
        "wire_exposure": WIRE_EXPOSURE,
        "dry_run": request.dry_run,
        "creates_infrastructure": not request.dry_run,
        "would_create_infrastructure": request.dry_run,
        "network": private_network,
        "containers": [
            {
                "role": role.name,
                "name_suffix": slug_label(role.name, fallback="role"),
                "planned_private_address": role.planned_ipv4,
                "requested_private_address": role.requested_private_ipv4,
                "resource_type": "docker-container",
                "private_group": private_group,
                "network_name": private_network["network_name"],
            }
            for role in roles
        ],
        "resource_counts": {
            "containers": len(roles),
            "private_networks": 1,
            "ssh_keys": len(roles),
        },
        "container_defaults": {
            "command_env": DOCKER_COMMAND_ENV,
            "default_command": DOCKER_COMMAND,
            "image_env": DOCKER_IMAGE_ENV,
            "default_image": DOCKER_DEFAULT_IMAGE,
            "private_cidr_env": DOCKER_PRIVATE_CIDR_ENV,
            "default_private_cidr": PRIVATE_NETWORK_CIDR,
            "capabilities": ["NET_RAW", "NET_ADMIN"],
            "cap_drop_all": True,
            "no_new_privileges": True,
            "ssh_transport": "localhost-port-forward",
        },
        "public_network_policy": "not_used_private_packet_exchange",
        "packet_exchange_network": WIRE_EXPOSURE,
        "private_group": private_group,
        "private_network": True,
        "private_network_cidr": PRIVATE_NETWORK_CIDR,
        "provider_capabilities": docker_default_provider_capabilities(
            dry_run=request.dry_run,
        ),
        "wire_policy": dict(DOCKER_WIRE_POLICY),
        "credentials": {
            "label": "none",
            "available": docker_credentials_available(),
            "required_for_live": False,
            "missing_reason": "",
        },
    }


def docker_provider_workflow(request: LabRequest) -> list[LabCommandPlan]:
    """Return planned Docker provider lifecycle command records."""

    roles = plan_docker_roles(request)
    private_group = docker_private_group(request)
    private_network = docker_private_network_metadata(private_group)
    remote_dir = validate_remote_dir(request.remote_dir)
    remote_artifacts = paths.remote_artifact_root(
        docker_session_id(request),
        remote_dir=remote_dir,
    )
    dry_run_flag = ["--dry-run"] if request.dry_run else []
    live_create_flags = [] if request.dry_run else ["--confirm-live-run", "--write-manifest"]
    commands = [
        build_command_plan(
            purpose="check-docker-private-wire",
            role=None,
            argv=[
                WIRE_ENTRYPOINT,
                "doctor",
                "--provider",
                WIRE_PROVIDER,
                "--exposure",
                WIRE_EXPOSURE,
                *dry_run_flag,
                "--json",
            ],
            operation="wire.doctor",
            dry_run=request.dry_run,
            provider=PROVIDER_NAME,
            exposure=WIRE_EXPOSURE,
            metadata={
                "wire_command": True,
                "private_group": private_group,
                "private_network": True,
                "network": private_network,
                "wire_policy": dict(DOCKER_WIRE_POLICY),
            },
        )
    ]

    for role in roles:
        private_ip = role.requested_private_ipv4 or role.planned_ipv4
        commands.append(
            build_command_plan(
                purpose=f"create-{slug_label(role.name, fallback='role')}-private-wire-endpoint",
                role=role.name,
                argv=[
                    WIRE_ENTRYPOINT,
                    "create-endpoint",
                    "--provider",
                    WIRE_PROVIDER,
                    "--exposure",
                    WIRE_EXPOSURE,
                    "--role",
                    role.name,
                    "--private-group",
                    private_group,
                    "--private-ip",
                    private_ip or _default_private_ipv4(0),
                    *dry_run_flag,
                    *live_create_flags,
                    "--json",
                ],
                operation="wire.create",
                dry_run=request.dry_run,
                live_mutation=not request.dry_run,
                provider=PROVIDER_NAME,
                exposure=WIRE_EXPOSURE,
                metadata={
                    "wire_command": True,
                    "private_group": private_group,
                    "private_network": True,
                    "private_ip": private_ip,
                    "planned_private_address": role.planned_ipv4,
                    "network": private_network,
                    "creates_infrastructure": not request.dry_run,
                    "would_create_infrastructure": request.dry_run,
                    "wire_policy": dict(DOCKER_WIRE_POLICY),
                },
            )
        )

    commands.extend(
        [
            build_command_plan(
                purpose="collect-lab-artifacts",
                role=None,
                argv=[
                    WIRE_ENTRYPOINT,
                    "collect-artifacts",
                    "<endpoint-id>",
                    "--remote",
                    remote_artifacts,
                ],
                operation="wire.collect_artifacts",
                dry_run=request.dry_run,
                provider=PROVIDER_NAME,
                exposure=WIRE_EXPOSURE,
                metadata={
                    "wire_command": True,
                    "always_attempt": True,
                    "private_group": private_group,
                    "private_network": True,
                    "remote_artifact_root": remote_artifacts,
                },
            ),
            build_command_plan(
                purpose="teardown-disposable-docker-wire-endpoints",
                role=None,
                argv=[WIRE_ENTRYPOINT, "destroy-endpoint", "<endpoint-id>", "--json"],
                operation="wire.destroy",
                dry_run=request.dry_run,
                live_mutation=not request.dry_run,
                provider=PROVIDER_NAME,
                exposure=WIRE_EXPOSURE,
                metadata={
                    "wire_command": True,
                    "always_attempt": True,
                    "private_group": private_group,
                    "private_network": True,
                    "network": private_network,
                },
            ),
        ]
    )
    return commands


def _default_private_ipv4(index: int) -> str:
    host_octet = 10 + (index * 10)
    return f"{DEFAULT_PRIVATE_IPV4_PREFIX}.{host_octet}"


def _role_address_source(
    *,
    role: LabRole,
    metadata_private_ipv4: str | None,
) -> str:
    if role.requested_private_ipv4 is not None:
        return "requested_private_ipv4"
    if metadata_private_ipv4 is not None:
        return "metadata.role_private_ipv4s"
    if role.planned_ipv4 is not None:
        return "planned_ipv4"
    return "deterministic-private-default"


def _role_private_ipv4_metadata(metadata: JSONObject) -> dict[str, str]:
    value = metadata.get("role_private_ipv4s")
    if not isinstance(value, Mapping):
        return {}
    return {
        key: item
        for key, item in value.items()
        if isinstance(key, str) and isinstance(item, str) and item
    }


def _metadata_string(metadata: JSONObject, key: str) -> str | None:
    value = metadata.get(key)
    return value if isinstance(value, str) and value else None


@dataclass(frozen=True, slots=True)
class DockerLabProviderAdapter:
    """Lab adapter foundation for private Docker sessions."""

    name: str = PROVIDER_NAME
    wire_provider: str = WIRE_PROVIDER
    wire_exposure: str = WIRE_EXPOSURE
    credential_label: str = "none"
    missing_credential_reason: str = ""

    def credentials_available(self) -> bool:
        """Return whether Docker prerequisites are available for live runs."""

        return docker_credentials_available()

    def default_provider_capabilities(
        self,
        *,
        dry_run: bool,
        source: str = "planned-defaults",
    ) -> JSONObject:
        """Return Docker capability defaults before endpoint discovery."""

        return docker_default_provider_capabilities(dry_run=dry_run, source=source)

    def normalize_provider_capabilities(
        self,
        raw: JSONObject,
        *,
        dry_run: bool | None = None,
        source: str | None = None,
    ) -> JSONObject:
        """Normalize Docker provider capabilities."""

        return normalize_docker_provider_capabilities(
            raw,
            dry_run=dry_run,
            source=source,
        )

    def plan_roles(self, request: LabRequest) -> list[LabRole]:
        """Return provider-normalized roles and private address defaults."""

        return plan_docker_roles(request)

    def private_group(self, request: LabRequest) -> str:
        """Return the Docker private bridge group name."""

        return docker_private_group(request)

    def requested_private_ip(self, role: LabRole, request: LabRequest) -> str | None:
        """Return the private IPv4 address to request from wire."""

        planned_roles = {planned.name: planned for planned in plan_docker_roles(request)}
        planned = planned_roles.get(role.name, role)
        return planned.requested_private_ipv4 or planned.planned_ipv4

    def planned_infrastructure(self, request: LabRequest) -> JSONObject:
        """Return dry-run-safe Docker infrastructure metadata."""

        return docker_planned_infrastructure(request)

    def provider_workflow(self, request: LabRequest) -> list[LabCommandPlan]:
        """Return planned Docker provider lifecycle commands."""

        return docker_provider_workflow(request)


DOCKER_LAB_PROVIDER_ADAPTER = DockerLabProviderAdapter()
