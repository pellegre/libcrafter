"""Hetzner lab provider adapter.

The lab provider owns only substrate planning. Workload-specific bootstrap,
packet exchange, and result validation stay in oracle or probe callers.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

from tools.endpoint.engine.model import EndpointManifest
from tools.endpoint.engine.providers.hetzner.constants import (
    DEFAULT_IMAGE,
    DEFAULT_LOCATION,
    DEFAULT_PRIVATE_NETWORK_ZONE,
    DEFAULT_SERVER_TYPE,
    HCLOUD_TOKEN_ENV,
    TOKEN_ENV,
)
from tools.endpoint.engine.state import DEFAULT_PRIVATE_CIDR

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


PROVIDER_NAME = "hetzner"
WIRE_PROVIDER = "hetzner"
WIRE_EXPOSURE = "private"
WIRE_ENTRYPOINT = "tools/endpoint/run"
PRIVATE_NETWORK_CIDR = DEFAULT_PRIVATE_CIDR
PRIVATE_NETWORK_ZONE = DEFAULT_PRIVATE_NETWORK_ZONE
DEFAULT_PRIVATE_IPV4_PREFIX = "10.0.25"
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
HETZNER_WIRE_POLICY: JSONObject = {
    "ipv4_header_mutable": True,
    "l3_send_adds_link_layer_metadata": True,
    "transit_decrements_ipv4_ttl": True,
}


def hetzner_credentials_available(env: Mapping[str, str] | None = None) -> bool:
    """Return whether Hetzner live-run credentials are configured."""

    source = os.environ if env is None else env
    return bool(source.get(TOKEN_ENV) or source.get(HCLOUD_TOKEN_ENV))


def hetzner_session_id(request: LabRequest) -> str:
    """Return the deterministic session id for a Hetzner lab request."""

    override = _metadata_string(request.metadata, "session_id")
    if override is not None:
        return slug_label(override, fallback="hetzner-lab-session", max_length=127)
    return request_session_label(request, prefix="lab-hetzner", max_length=127)


def hetzner_private_group(request: LabRequest) -> str:
    """Return the deterministic private network group for a request."""

    override = _metadata_string(request.metadata, "private_group")
    if override is not None:
        return slug_label(override, fallback="hetzner-private", max_length=63)
    return slug_label(
        f"{hetzner_session_id(request)}-private",
        fallback="hetzner-private",
        max_length=63,
    )


def hetzner_default_provider_capabilities(
    *,
    dry_run: bool,
    source: str = "planned-defaults",
) -> JSONObject:
    """Return conservative Hetzner private-network capability defaults."""

    defaults: JSONObject = {
        "live_packet_exchange": True,
        "ipv4_unicast": True,
        "ipv6_unicast": False,
        "link_layer_send": False,
        "link_layer_capture": False,
        "broadcast": False,
        "provider_mac_known": False,
        "controlled_services": True,
        "controlled_router": False,
        "blocked_udp_ports": [67, 68],
        "capability_report_artifact": CAPABILITY_REPORT_ARTIFACT,
        "wire_policy": dict(HETZNER_WIRE_POLICY),
        "checks": {
            "ipv4_unicast": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "Hetzner private endpoint IPv4 addresses are planned",
            },
            "ipv6_unicast": {
                "status": "not_planned",
                "value": False,
                "reason": "private-network IPv6 is not configured by the lab substrate",
            },
            "link_layer_send": {
                "status": "not_proven",
                "value": False,
                "reason": "link-layer frame preservation is not assumed for Hetzner",
            },
            "link_layer_capture": {
                "status": "not_proven",
                "value": False,
                "reason": "link-layer capture preservation is not assumed for Hetzner",
            },
            "broadcast": {
                "status": "not_proven",
                "value": False,
                "reason": "broadcast delivery is not assumed on the provider network",
            },
            "provider_mac_known": {
                "status": "manifest_required",
                "value": False,
                "reason": "real endpoint discovery records provider interface MACs",
            },
            "controlled_services": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "lab endpoints are disposable hosts controlled by callers",
            },
            "controlled_router": {
                "status": "not_available",
                "value": False,
                "reason": "the lab has endpoints on a private network, not a controlled router",
            },
            "dhcp_udp_ports": {
                "status": "provider_reserved",
                "value": False,
                "reason": "Hetzner private networks do not preserve DHCP/BOOTP UDP 67/68 exchanges between endpoints",
            },
        },
    }
    return normalize_hetzner_provider_capabilities(
        defaults,
        dry_run=dry_run,
        source=source,
    )


def normalize_hetzner_provider_capabilities(
    raw: JSONObject,
    *,
    dry_run: bool | None = None,
    source: str | None = None,
) -> JSONObject:
    """Normalize Hetzner capability data into the lab session shape."""

    return normalize_common_provider_capabilities(
        raw,
        provider=PROVIDER_NAME,
        dry_run=dry_run,
        source=source,
        capability_names=PROVIDER_CAPABILITY_NAMES,
        defaults={
            "live_packet_exchange": True,
            "wire_policy": dict(HETZNER_WIRE_POLICY),
        },
    )


def plan_hetzner_roles(request: LabRequest) -> list[LabRole]:
    """Return roles with deterministic private IPv4 planning metadata."""

    roles: list[LabRole] = []
    role_private_ipv4s = _role_private_ipv4_metadata(request.metadata)
    all_role_names = [role.name for role in request.roles]
    private_group = hetzner_private_group(request)

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
                    "address_source": address_source,
                },
            )
        )
    return roles


def hetzner_planned_infrastructure(request: LabRequest) -> JSONObject:
    """Return dry-run-safe Hetzner infrastructure metadata."""

    roles = plan_hetzner_roles(request)
    private_group = hetzner_private_group(request)
    return {
        "provider": PROVIDER_NAME,
        "wire_provider": WIRE_PROVIDER,
        "wire_exposure": WIRE_EXPOSURE,
        "dry_run": request.dry_run,
        "creates_infrastructure": not request.dry_run,
        "would_create_infrastructure": request.dry_run,
        "network": {
            "resource_type": "hetzner-cloud-network",
            "private_group": private_group,
            "ip_range": PRIVATE_NETWORK_CIDR,
            "network_zone": PRIVATE_NETWORK_ZONE,
            "isolated": True,
        },
        "servers": [
            {
                "role": role.name,
                "name_suffix": slug_label(role.name, fallback="role"),
                "private_address": role.planned_ipv4,
                "requested_private_address": role.requested_private_ipv4,
            }
            for role in roles
        ],
        "resource_counts": {
            "servers": len(roles),
            "private_networks": 1,
            "ssh_keys": len(roles),
        },
        "server_defaults": {
            "type": DEFAULT_SERVER_TYPE,
            "image": DEFAULT_IMAGE,
            "location": DEFAULT_LOCATION,
        },
        "public_network_policy": "ssh_control_plane_only",
        "packet_exchange_network": WIRE_EXPOSURE,
        "private_network": True,
        "provider_capabilities": hetzner_default_provider_capabilities(
            dry_run=request.dry_run,
        ),
        "credentials": {
            "label": f"{TOKEN_ENV} or {HCLOUD_TOKEN_ENV}",
            "available": hetzner_credentials_available(),
            "required_for_live": True,
            "missing_reason": f"missing {TOKEN_ENV} or {HCLOUD_TOKEN_ENV}",
        },
    }


def hetzner_provider_workflow(request: LabRequest) -> list[LabCommandPlan]:
    """Return planned Hetzner provider lifecycle command records."""

    roles = plan_hetzner_roles(request)
    private_group = hetzner_private_group(request)
    remote_dir = validate_remote_dir(request.remote_dir)
    remote_artifacts = paths.remote_artifact_root(
        hetzner_session_id(request),
        remote_dir=remote_dir,
    )
    dry_run_flag = ["--dry-run"] if request.dry_run else []
    live_create_flags = [] if request.dry_run else ["--confirm-live-run", "--write-manifest"]
    commands = [
        build_command_plan(
            purpose="check-hetzner-private-wire",
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
                    "creates_infrastructure": not request.dry_run,
                    "would_create_infrastructure": request.dry_run,
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
                    "remote_artifact_root": remote_artifacts,
                },
            ),
            build_command_plan(
                purpose="teardown-disposable-hetzner-wire-endpoints",
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
                },
            ),
        ]
    )
    return commands


def _request_with_planned_roles(request: LabRequest) -> LabRequest:
    return replace(request, roles=plan_hetzner_roles(request))


def _default_private_ipv4(index: int) -> str:
    third_octet = 25 + (index // 24)
    host_octet = 10 + ((index % 24) * 10)
    return f"10.0.{third_octet}.{host_octet}"


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
    return "deterministic-default"


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
class HetznerLabProviderAdapter:
    """Lab adapter for private Hetzner multi-endpoint sessions."""

    name: str = PROVIDER_NAME
    wire_provider: str = WIRE_PROVIDER
    wire_exposure: str = WIRE_EXPOSURE
    credential_label: str = f"{TOKEN_ENV} or {HCLOUD_TOKEN_ENV}"
    missing_credential_reason: str = f"missing {TOKEN_ENV} or {HCLOUD_TOKEN_ENV}"

    def credentials_available(self) -> bool:
        """Return whether Hetzner credentials are present for live runs."""

        return hetzner_credentials_available()

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
        """Normalize Hetzner provider capabilities."""

        return normalize_hetzner_provider_capabilities(
            raw,
            dry_run=dry_run,
            source=source,
        )

    def plan_roles(self, request: LabRequest) -> list[LabRole]:
        """Return provider-normalized roles and address defaults."""

        return plan_hetzner_roles(request)

    def private_group(self, request: LabRequest) -> str:
        """Return the Hetzner private network group name."""

        return hetzner_private_group(request)

    def requested_private_ip(self, role: LabRole, request: LabRequest) -> str | None:
        """Return the private IPv4 address to request from endpoint."""

        planned_roles = {planned.name: planned for planned in plan_hetzner_roles(request)}
        planned = planned_roles.get(role.name, role)
        return planned.requested_private_ipv4 or planned.planned_ipv4

    def planned_infrastructure(self, request: LabRequest) -> JSONObject:
        """Return dry-run-safe Hetzner infrastructure metadata."""

        return hetzner_planned_infrastructure(request)

    def provider_workflow(self, request: LabRequest) -> list[LabCommandPlan]:
        """Return planned Hetzner provider lifecycle commands."""

        return hetzner_provider_workflow(request)

    def wire_endpoint_plan(
        self,
        request: LabRequest,
        *,
        client: endpoint_client.EndpointClient | None = None,
        created_endpoint_ids: list[str] | None = None,
    ) -> JSONObject:
        """Plan or create Hetzner wire endpoints for all request roles."""

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
                    purpose=f"create {role.name} Hetzner private endpoint",
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
            "dry_run": planned_request.dry_run,
            "private_group": private_group,
            "private_network": True,
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
        """Convert a wire manifest into a provider-neutral endpoint."""

        private_group = self.private_group(request)
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
            },
        )

    def plan_session(
        self,
        request: LabRequest,
        *,
        client: endpoint_client.EndpointClient | None = None,
    ) -> LabSession:
        """Return a planned or live Hetzner lab session."""

        planned_request = _request_with_planned_roles(request)
        session_id = hetzner_session_id(planned_request)
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
                "credential_label": self.credential_label,
                "credentials_available": self.credentials_available(),
                "missing_credential_reason": self.missing_credential_reason,
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
        """Validate Hetzner-specific request invariants before planning."""

        errors: list[str] = []
        if request.provider != self.name:
            errors.append(f"unexpected provider: {request.provider}")
        if not request.dry_run and not request.confirm_live_run:
            errors.append("live Hetzner lab creation requires confirm_live_run")
        if not request.dry_run and not self.credentials_available():
            errors.append(self.missing_credential_reason)
        private_group = self.private_group(request)
        if private_group == "":
            errors.append("private_group must be non-empty")

        planned_roles = plan_hetzner_roles(request)
        planned_ips = [role.requested_private_ipv4 or role.planned_ipv4 for role in planned_roles]
        duplicates = sorted(
            ip
            for ip in set(planned_ips)
            if ip is not None and planned_ips.count(ip) > 1
        )
        if duplicates:
            errors.append(f"duplicate private IPv4 addresses: {', '.join(duplicates)}")

        return LabValidationCheck(
            name="hetzner-request",
            passed=not errors,
            subject=self.name,
            errors=errors,
            metadata={
                "provider": self.name,
                "dry_run": request.dry_run,
                "confirm_live_run": request.confirm_live_run,
                "credentials_available": self.credentials_available(),
                "private_group": private_group,
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
            "check-hetzner-private-wire",
            "collect-lab-artifacts",
            "teardown-disposable-hetzner-wire-endpoints",
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
                errors.append("provider command must target Hetzner")
            if command.metadata.get("exposure") != self.wire_exposure:
                errors.append("provider command must target private exposure")
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
            name="hetzner-provider-workflow",
            passed=not errors,
            subject=self.name,
            errors=errors,
            metadata={
                "provider": self.name,
                "dry_run": dry_run,
                "always_collect_artifacts": True,
                "always_teardown": True,
            },
        )

    def validate_session(self, session: LabSession) -> list[LabValidationCheck]:
        """Validate Hetzner-specific invariants on a planned session."""

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
        for endpoint in session.endpoints:
            if endpoint.metadata.get("private_network") is not True:
                errors.append(f"endpoint lacks private network metadata: {endpoint.role}")
            if endpoint.metadata.get("private_group") is None:
                errors.append(f"endpoint lacks private group metadata: {endpoint.role}")

        return [
            LabValidationCheck(
                name="hetzner-session",
                passed=not errors,
                subject=session.session_id,
                errors=errors,
                metadata={
                    "provider": self.name,
                    "endpoint_count": len(session.endpoints),
                    "role_count": len(session.roles),
                    "dry_run": session.dry_run,
                    "private_group": session.metadata.get("private_group"),
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
    raise ValueError("wire create response did not include an endpoint manifest")


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


HETZNER_LAB_PROVIDER_ADAPTER: LabProviderAdapter = HetznerLabProviderAdapter()
