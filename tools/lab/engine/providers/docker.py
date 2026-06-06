"""Docker lab provider adapter.

The lab provider maps Docker to the isolated ``docker/private`` wire exposure.
LAN and WAN Docker modes remain direct wire-provider modes in this phase.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

from tools.endpoint.engine.model import EndpointManifest
from tools.endpoint.engine.providers.docker.constants import (
    DOCKER_COMMAND,
    DOCKER_COMMAND_ENV,
    DOCKER_DEFAULT_IMAGE,
    DOCKER_DEFAULT_PRIVATE_CIDR,
    DOCKER_IMAGE_ENV,
    DOCKER_PRIVATE_CIDR_ENV,
)
from tools.endpoint.engine.providers.docker.resources import (
    docker_private_network_name,
    validate_requested_private_ipv4,
)

from .. import paths, endpoint_client
from ..model import (
    JSONObject,
    LabCommandPlan,
    LabEndpoint,
    LabRequest,
    LabRole,
    LabSession,
    LabValidationCheck,
    json_object,
)
from .base import LabProviderAdapter
from .common import (
    build_command_plan,
    lab_endpoint_from_manifest,
    normalize_provider_capabilities as normalize_common_provider_capabilities,
    request_session_label,
    slug_label,
    validate_remote_dir,
)


PROVIDER_NAME = "docker"
WIRE_PROVIDER = "docker"
WIRE_EXPOSURE = "private"
WIRE_ENTRYPOINT = "tools/endpoint/run"
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
                "reason": "endpoint manifests record Docker private interface MACs before packet exchange",
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
            operation="endpoint.doctor",
            dry_run=request.dry_run,
            provider=PROVIDER_NAME,
            exposure=WIRE_EXPOSURE,
            metadata={
                "endpoint_command": True,
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
                    "create",
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
                operation="endpoint.create",
                dry_run=request.dry_run,
                live_mutation=not request.dry_run,
                provider=PROVIDER_NAME,
                exposure=WIRE_EXPOSURE,
                metadata={
                    "endpoint_command": True,
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
                operation="endpoint.collect_artifacts",
                dry_run=request.dry_run,
                provider=PROVIDER_NAME,
                exposure=WIRE_EXPOSURE,
                metadata={
                    "endpoint_command": True,
                    "always_attempt": True,
                    "private_group": private_group,
                    "private_network": True,
                    "remote_artifact_root": remote_artifacts,
                },
            ),
            build_command_plan(
                purpose="teardown-disposable-docker-wire-endpoints",
                role=None,
                argv=[WIRE_ENTRYPOINT, "destroy", "<endpoint-id>", "--json"],
                operation="endpoint.destroy",
                dry_run=request.dry_run,
                live_mutation=not request.dry_run,
                provider=PROVIDER_NAME,
                exposure=WIRE_EXPOSURE,
                metadata={
                    "endpoint_command": True,
                    "always_attempt": True,
                    "private_group": private_group,
                    "private_network": True,
                    "network": private_network,
                },
            ),
        ]
    )
    return commands


def _request_with_planned_roles(request: LabRequest) -> LabRequest:
    return replace(request, roles=plan_docker_roles(request))


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


def _peer_roles_for(role: LabRole, roles: Sequence[LabRole]) -> list[LabRole]:
    if role.peer_roles:
        requested = set(role.peer_roles)
        return [peer for peer in roles if peer.name in requested]
    return [peer for peer in roles if peer.name != role.name]


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
        """Return the private IPv4 address to request from endpoint."""

        planned_roles = {planned.name: planned for planned in plan_docker_roles(request)}
        planned = planned_roles.get(role.name, role)
        return planned.requested_private_ipv4 or planned.planned_ipv4

    def planned_infrastructure(self, request: LabRequest) -> JSONObject:
        """Return dry-run-safe Docker infrastructure metadata."""

        return docker_planned_infrastructure(request)

    def provider_workflow(self, request: LabRequest) -> list[LabCommandPlan]:
        """Return planned Docker provider lifecycle commands."""

        return docker_provider_workflow(request)

    def wire_endpoint_plan(
        self,
        request: LabRequest,
        *,
        client: endpoint_client.EndpointClient | None = None,
        created_endpoint_ids: list[str] | None = None,
    ) -> JSONObject:
        """Plan or create Docker endpoints for all request roles."""

        planned_request = _request_with_planned_roles(request)
        validation = self.validate_request(planned_request)
        if not validation.passed:
            raise PermissionError("; ".join(validation.errors))

        endpoint_cli = client or endpoint_client.EndpointClient()
        private_group = self.private_group(planned_request)
        endpoint_plans: list[JSONObject] = []
        endpoints: dict[str, JSONObject] = {}
        command_records: list[JSONObject] = []
        created_ids: list[str] = []

        for role in planned_request.roles:
            private_ip = self.requested_private_ip(role, planned_request)
            response = endpoint_cli.create(
                provider=self.wire_provider,
                exposure=self.wire_exposure,
                role=role.name,
                private_group=private_group,
                private_ip=private_ip,
                dry_run=planned_request.dry_run,
                write_manifest=not planned_request.dry_run,
                confirm_live_run=planned_request.confirm_live_run,
            )
            manifest = _response_manifest(response)
            endpoint_plan = _response_json(response, manifest)
            endpoint_plans.append(endpoint_plan)
            endpoint = self.normalize_endpoint(
                manifest,
                role=role,
                peer_roles=_peer_roles_for(role, planned_request.roles),
                request=planned_request,
            )
            endpoints[role.name] = endpoint.to_dict()
            command_records.append(
                response.command_plan(
                    purpose=f"create {role.name} Docker private endpoint",
                    role=role.name,
                ).to_dict()
            )
            if not planned_request.dry_run:
                created_ids.append(manifest.endpoint_id)
                if created_endpoint_ids is not None:
                    created_endpoint_ids.append(manifest.endpoint_id)

        return {
            "provider": self.name,
            "wire_provider": self.wire_provider,
            "exposure": self.wire_exposure,
            "wire_exposure": self.wire_exposure,
            "dry_run": planned_request.dry_run,
            "private_group": private_group,
            "private_network": True,
            "private_network_cidr": PRIVATE_NETWORK_CIDR,
            "docker_private_network": docker_private_network_metadata(private_group),
            "wire_policy": dict(DOCKER_WIRE_POLICY),
            "endpoint_count": len(endpoint_plans),
            "endpoint_plans": endpoint_plans,
            "endpoints": endpoints,
            "command_records": command_records,
            "created_endpoint_ids": created_ids,
        }

    def normalize_endpoint(
        self,
        manifest: EndpointManifest | Mapping[str, object],
        *,
        role: LabRole,
        peer_roles: Sequence[LabRole] = (),
        request: LabRequest,
    ) -> LabEndpoint:
        """Convert an endpoint manifest into a provider-neutral endpoint."""

        private_group = self.private_group(request)
        private_network = docker_private_network_metadata(private_group)
        return lab_endpoint_from_manifest(
            manifest,
            role=role,
            exposure=self.wire_exposure,
            peer_roles=peer_roles,
            dry_run=request.dry_run,
            metadata={
                "provider": self.name,
                "wire_provider": self.wire_provider,
                "wire_exposure": self.wire_exposure,
                "private_group": private_group,
                "private_network": True,
                "private_network_cidr": PRIVATE_NETWORK_CIDR,
                "packet_exchange_network": self.wire_exposure,
                "isolated_network": True,
                "docker_private_network": private_network,
                "container_runtime": "docker",
                "ssh_transport": "localhost-port-forward",
                "required_capabilities": ["NET_RAW", "NET_ADMIN"],
                "cap_drop_all": True,
                "no_new_privileges": True,
                "planned_private_address": role.planned_ipv4,
                "planned_private_address_source": role.metadata.get(
                    "planned_private_address_source",
                    role.metadata.get(
                        "address_source",
                        "deterministic-private-default",
                    ),
                ),
                "requested_private_ip_used_for_wire": bool(
                    role.metadata.get(
                        "requested_private_ip_used_for_wire",
                        role.requested_private_ipv4 is not None,
                    )
                ),
                "wire_policy": dict(DOCKER_WIRE_POLICY),
            },
        )

    def plan_session(
        self,
        request: LabRequest,
        *,
        client: endpoint_client.EndpointClient | None = None,
    ) -> LabSession:
        """Return a planned or live Docker lab session."""

        planned_request = _request_with_planned_roles(request)
        session_id = docker_session_id(planned_request)
        remote_dir = validate_remote_dir(planned_request.remote_dir)
        remote_artifacts = paths.remote_artifact_root(session_id, remote_dir=remote_dir)
        provider_capabilities = self.default_provider_capabilities(
            dry_run=planned_request.dry_run,
        )
        provider_workflow = self.provider_workflow(planned_request)
        request_check = self.validate_request(planned_request)
        workflow_check = self.validate_provider_workflow(
            provider_workflow,
            dry_run=planned_request.dry_run,
        )
        endpoint_plan = self.wire_endpoint_plan(planned_request, client=client)
        endpoints = _endpoint_models(endpoint_plan, planned_request.roles)
        command_records = _command_models(endpoint_plan)

        session = LabSession(
            provider=self.name,
            wire_provider=self.wire_provider,
            wire_exposure=self.wire_exposure,
            session_id=session_id,
            roles=planned_request.roles,
            endpoints=endpoints,
            provider_capabilities=provider_capabilities,
            infrastructure_metadata=self.planned_infrastructure(planned_request),
            provider_workflow=provider_workflow,
            command_records=command_records,
            remote_dir=remote_dir,
            remote_artifact_root=remote_artifacts,
            created_endpoint_ids=[
                item
                for item in endpoint_plan.get("created_endpoint_ids", [])
                if isinstance(item, str)
            ],
            dry_run=planned_request.dry_run,
            cleanup_state={
                "status": "not_started",
                "artifact_collection_attempted": False,
                "teardown_attempted": False,
            },
            validation_checks=[request_check, workflow_check],
            metadata={
                "provider": self.name,
                "private_group": self.private_group(planned_request),
                "private_network": True,
                "private_network_cidr": PRIVATE_NETWORK_CIDR,
                "credential_label": self.credential_label,
                "credentials_available": self.credentials_available(),
                "missing_credential_reason": self.missing_credential_reason,
                "docker_private_network": docker_private_network_metadata(
                    self.private_group(planned_request)
                ),
                "wire_policy": dict(DOCKER_WIRE_POLICY),
                "wire_endpoint_plan": endpoint_plan,
            },
        )
        return replace(
            session,
            validation_checks=[
                *session.validation_checks,
                *self.validate_session(session),
            ],
        )

    def validate_request(self, request: LabRequest) -> LabValidationCheck:
        """Validate Docker-specific request invariants before planning."""

        errors: list[str] = []
        if request.provider != self.name:
            errors.append(f"unexpected provider: {request.provider}")
        if not request.dry_run and not request.confirm_live_run:
            errors.append("live Docker lab creation requires confirm_live_run")
        private_group = self.private_group(request)
        if private_group == "":
            errors.append("private_group must be non-empty")

        planned_roles = plan_docker_roles(request)
        planned_ips = [
            role.requested_private_ipv4 or role.planned_ipv4 for role in planned_roles
        ]
        duplicates = sorted(
            ip
            for ip in set(planned_ips)
            if ip is not None and planned_ips.count(ip) > 1
        )
        if duplicates:
            errors.append(f"duplicate private IPv4 addresses: {', '.join(duplicates)}")
        for private_ip in planned_ips:
            if private_ip is None:
                continue
            try:
                validate_requested_private_ipv4(private_ip, PRIVATE_NETWORK_CIDR)
            except ValueError as exc:
                errors.append(str(exc))

        return LabValidationCheck(
            name="docker-request",
            passed=not errors,
            subject=self.name,
            errors=errors,
            metadata={
                "provider": self.name,
                "dry_run": request.dry_run,
                "confirm_live_run": request.confirm_live_run,
                "credentials_available": self.credentials_available(),
                "private_group": private_group,
                "private_network": True,
                "private_network_cidr": PRIVATE_NETWORK_CIDR,
                "role_count": len(request.roles),
            },
        )

    def validate_provider_workflow(
        self,
        commands: list[LabCommandPlan],
        *,
        dry_run: bool,
    ) -> LabValidationCheck:
        """Validate provider lifecycle command invariants."""

        errors: list[str] = []
        purposes = {command.purpose for command in commands}
        required = {
            "check-docker-private-wire",
            "collect-lab-artifacts",
            "teardown-disposable-docker-wire-endpoints",
        }
        if not any(purpose.startswith("create-") for purpose in purposes):
            errors.append("missing provider workflow phase: create role endpoint")
        missing = sorted(required - purposes)
        if missing:
            errors.append(f"missing provider workflow phases: {', '.join(missing)}")

        for command in commands:
            if len(command.argv) < 2 or command.argv[0] != WIRE_ENTRYPOINT:
                errors.append(f"provider command must route through {WIRE_ENTRYPOINT}")
            if command.metadata.get("endpoint_command") is not True:
                errors.append("provider command must be marked as endpoint_command")
            if command.metadata.get("provider") != self.name:
                errors.append("provider command must target Docker")
            if command.metadata.get("exposure") != self.wire_exposure:
                errors.append("provider command must target private exposure")
            if command.metadata.get("private_network") is not True:
                errors.append("Docker provider command must carry private network metadata")
            if command.operation == "endpoint.create":
                if "--private-group" not in command.argv:
                    errors.append("Docker private create command lacks --private-group")
                if "--private-ip" not in command.argv:
                    errors.append("Docker private create command lacks --private-ip")
                if "--provider" not in command.argv or self.wire_provider not in command.argv:
                    errors.append("Docker private create command lacks provider argument")
                if "--exposure" not in command.argv or self.wire_exposure not in command.argv:
                    errors.append("Docker private create command lacks private exposure argument")
            if dry_run and command.operation in {"endpoint.doctor", "endpoint.create"}:
                if "--dry-run" not in command.argv:
                    errors.append(f"dry-run provider command lacks --dry-run: {command.shell()}")
                if command.live_mutation:
                    errors.append("dry-run provider command cannot be marked live_mutation")
            if not dry_run and command.operation == "endpoint.create":
                if "--confirm-live-run" not in command.argv:
                    errors.append("real provider create command lacks --confirm-live-run")
                if not command.live_mutation:
                    errors.append("real provider create command must be live_mutation")
            if command.operation in {"endpoint.collect_artifacts", "endpoint.destroy"}:
                if command.metadata.get("always_attempt") is not True:
                    errors.append(f"{command.operation} must be marked always_attempt")

        return LabValidationCheck(
            name="docker-provider-workflow",
            passed=not errors,
            subject=self.name,
            errors=errors,
            metadata={
                "provider": self.name,
                "dry_run": dry_run,
                "always_collect_artifacts": True,
                "always_teardown": True,
                "private_network": True,
                "private_network_cidr": PRIVATE_NETWORK_CIDR,
            },
        )

    def validate_session(self, session: LabSession) -> list[LabValidationCheck]:
        """Validate Docker-specific invariants on a planned session."""

        errors: list[str] = []
        if session.provider != self.name:
            errors.append(f"unexpected provider: {session.provider}")
        if session.wire_provider != self.wire_provider:
            errors.append(f"unexpected wire provider: {session.wire_provider}")
        if session.wire_exposure != self.wire_exposure:
            errors.append(f"unexpected wire exposure: {session.wire_exposure}")
        if len(session.endpoints) != len(session.roles):
            errors.append("endpoint count must match role count")
        if session.infrastructure_metadata.get("private_network") is not True:
            errors.append("infrastructure metadata must describe a private network")
        if session.infrastructure_metadata.get("wire_policy") != DOCKER_WIRE_POLICY:
            errors.append("infrastructure metadata must preserve Docker wire policy")
        network = session.infrastructure_metadata.get("network")
        if not isinstance(network, Mapping):
            errors.append("infrastructure metadata must include Docker network metadata")
        else:
            if network.get("backend") != "docker-internal-bridge":
                errors.append("Docker lab network must be an internal bridge")
            if network.get("internal") is not True:
                errors.append("Docker lab network must be internal")

        for endpoint in session.endpoints:
            if endpoint.metadata.get("private_network") is not True:
                errors.append(f"endpoint lacks private network metadata: {endpoint.role}")
            if endpoint.metadata.get("private_group") is None:
                errors.append(f"endpoint lacks private group metadata: {endpoint.role}")
            if endpoint.metadata.get("container_runtime") != "docker":
                errors.append(f"endpoint lacks Docker runtime metadata: {endpoint.role}")
            if endpoint.metadata.get("wire_policy") != DOCKER_WIRE_POLICY:
                errors.append(f"endpoint lacks Docker wire policy metadata: {endpoint.role}")

        return [
            LabValidationCheck(
                name="docker-session",
                passed=not errors,
                subject=session.session_id,
                errors=errors,
                metadata={
                    "provider": self.name,
                    "endpoint_count": len(session.endpoints),
                    "role_count": len(session.roles),
                    "dry_run": session.dry_run,
                    "private_group": session.metadata.get("private_group"),
                    "private_network": True,
                    "private_network_cidr": PRIVATE_NETWORK_CIDR,
                },
            )
        ]


def _response_manifest(response: object) -> EndpointManifest:
    manifest = getattr(response, "manifest", None)
    if isinstance(manifest, EndpointManifest):
        return manifest
    json_data = getattr(response, "json_data", None)
    if isinstance(json_data, Mapping):
        return EndpointManifest.from_dict(json_object(json_data, "wire_manifest"))
    metadata = getattr(response, "metadata", None)
    if callable(metadata):
        value = metadata()
        if isinstance(value, Mapping):
            return EndpointManifest.from_dict(json_object(value, "wire_manifest"))
    raise ValueError("endpoint create response did not include an endpoint manifest")


def _response_json(response: object, manifest: EndpointManifest) -> JSONObject:
    json_data = getattr(response, "json_data", None)
    if isinstance(json_data, Mapping):
        return json_object(json_data, "wire_create_response")
    return manifest.to_dict()


def _endpoint_models(endpoint_plan: JSONObject, roles: Sequence[LabRole]) -> list[LabEndpoint]:
    endpoints = endpoint_plan.get("endpoints")
    if not isinstance(endpoints, Mapping):
        return []
    output: list[LabEndpoint] = []
    for role in roles:
        endpoint = endpoints.get(role.name)
        if isinstance(endpoint, Mapping):
            output.append(LabEndpoint.from_dict(endpoint))
    return output


def _command_models(endpoint_plan: JSONObject) -> list[LabCommandPlan]:
    commands = endpoint_plan.get("command_records")
    if not isinstance(commands, list):
        return []
    return [
        LabCommandPlan.from_dict(command)
        for command in commands
        if isinstance(command, Mapping)
    ]


DOCKER_LAB_PROVIDER_ADAPTER: LabProviderAdapter = DockerLabProviderAdapter()
