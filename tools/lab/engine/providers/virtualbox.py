"""VirtualBox lab provider adapter.

The lab provider owns only substrate planning. Workload-specific bootstrap,
packet exchange, and result validation stay in oracle or probe callers.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

from tools.endpoint.engine.model import EndpointManifest
from tools.endpoint.engine.providers.virtualbox.constants import (
    VBOXMANAGE_COMMAND,
    VBOX_DEFAULT_PRIVATE_CIDR,
)

from .. import paths, wire_client
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


PROVIDER_NAME = "virtualbox"
WIRE_PROVIDER = "virtualbox"
WIRE_EXPOSURE = "private"
WIRE_ENTRYPOINT = "tools/endpoint/run"
PRIVATE_NETWORK_CIDR = VBOX_DEFAULT_PRIVATE_CIDR
DEFAULT_PRIVATE_IPV4_PREFIX = "10.78.0"
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
VIRTUALBOX_WIRE_POLICY: JSONObject = {
    "ipv4_header_mutable": False,
    "l3_send_adds_link_layer_metadata": False,
    "transit_decrements_ipv4_ttl": False,
}


def virtualbox_credentials_available() -> bool:
    """Return whether VirtualBox live-run provider credentials are configured."""

    return True


def virtualbox_session_id(request: LabRequest) -> str:
    """Return the deterministic session id for a VirtualBox lab request."""

    override = _metadata_string(request.metadata, "session_id")
    if override is not None:
        return slug_label(override, fallback="virtualbox-lab-session", max_length=127)
    return request_session_label(request, prefix="lab-virtualbox", max_length=127)


def virtualbox_private_group(request: LabRequest) -> str:
    """Return the deterministic private internal network group for a request."""

    override = _metadata_string(request.metadata, "private_group")
    if override is not None:
        return slug_label(override, fallback="virtualbox-private", max_length=63)
    return slug_label(
        f"{virtualbox_session_id(request)}-private",
        fallback="virtualbox-private",
        max_length=63,
    )


def virtualbox_private_network_metadata(private_group: str) -> JSONObject:
    """Return VirtualBox internal-network metadata for planning output."""

    return {
        "planned": True,
        "provider": PROVIDER_NAME,
        "resource_type": "virtualbox-internal-network",
        "wire_exposure": WIRE_EXPOSURE,
        "network_id": f"virtualbox-private-group-{slug_label(private_group, fallback='private')}",
        "network_name": f"wire-vbox-{slug_label(private_group, fallback='private')}",
        "private_group": private_group,
        "ip_range": PRIVATE_NETWORK_CIDR,
        "backend": "internal-network",
        "address_source": "static-private-ipv4",
        "isolated": True,
    }


def virtualbox_default_provider_capabilities(
    *,
    dry_run: bool,
    source: str = "planned-defaults",
) -> JSONObject:
    """Return VirtualBox private-network capability defaults for same-segment VMs."""

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
        "wire_policy": dict(VIRTUALBOX_WIRE_POLICY),
        "checks": {
            "ipv4_unicast": {
                "status": "planned" if dry_run else "manifest_required",
                "value": True,
                "reason": "VirtualBox private endpoint IPv4 addresses are planned",
            },
            "ipv6_unicast": {
                "status": "not_planned",
                "value": False,
                "reason": "VirtualBox private endpoints are currently IPv4-only",
            },
            "link_layer_send": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "VirtualBox private endpoints send raw Ethernet frames on the internal network",
            },
            "link_layer_capture": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "VirtualBox private endpoints capture Ethernet frames on the internal network",
            },
            "broadcast": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "VirtualBox internal networking carries same-segment broadcast traffic",
            },
            "provider_mac_known": {
                "status": "planned" if dry_run else "manifest_required",
                "value": True,
                "reason": "wire endpoint manifests record private interface MACs before packet exchange",
            },
            "controlled_services": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "lab endpoints are disposable VMs controlled by callers",
            },
            "controlled_router": {
                "status": "not_available",
                "value": False,
                "reason": "the VirtualBox private lab is same-segment, not routed transit",
            },
        },
    }
    return normalize_virtualbox_provider_capabilities(
        defaults,
        dry_run=dry_run,
        source=source,
    )


def normalize_virtualbox_provider_capabilities(
    raw: JSONObject,
    *,
    dry_run: bool | None = None,
    source: str | None = None,
) -> JSONObject:
    """Normalize VirtualBox capability data into the lab session shape."""

    normalized = normalize_common_provider_capabilities(
        raw,
        provider=PROVIDER_NAME,
        dry_run=dry_run,
        source=source,
        capability_names=PROVIDER_CAPABILITY_NAMES,
        defaults={
            "live_packet_exchange": True,
            "wire_policy": dict(VIRTUALBOX_WIRE_POLICY),
        },
    )
    normalized.setdefault("wire_policy", dict(VIRTUALBOX_WIRE_POLICY))
    return normalized


def plan_virtualbox_roles(request: LabRequest) -> list[LabRole]:
    """Return roles with deterministic private IPv4 metadata."""

    roles: list[LabRole] = []
    role_private_ipv4s = _role_private_ipv4_metadata(request.metadata)
    all_role_names = [role.name for role in request.roles]
    private_group = virtualbox_private_group(request)

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
                    "bridged_lan": False,
                    "packet_exchange_network": WIRE_EXPOSURE,
                    "planned_private_address": planned_ipv4,
                    "planned_private_address_source": address_source,
                    "wire_policy": dict(VIRTUALBOX_WIRE_POLICY),
                    "requested_private_ip_used_for_wire": requested_private_ipv4 is not None,
                },
            )
        )
    return roles


def virtualbox_planned_infrastructure(request: LabRequest) -> JSONObject:
    """Return dry-run-safe VirtualBox infrastructure metadata."""

    roles = plan_virtualbox_roles(request)
    private_group = virtualbox_private_group(request)
    private_network = virtualbox_private_network_metadata(private_group)
    return {
        "provider": PROVIDER_NAME,
        "wire_provider": WIRE_PROVIDER,
        "wire_exposure": WIRE_EXPOSURE,
        "dry_run": request.dry_run,
        "creates_infrastructure": not request.dry_run,
        "would_create_infrastructure": request.dry_run,
        "network": private_network,
        "servers": [
            {
                "role": role.name,
                "name_suffix": slug_label(role.name, fallback="role"),
                "planned_private_address": role.planned_ipv4,
                "resource_type": "virtualbox-vm",
            }
            for role in roles
        ],
        "resource_counts": {
            "vms": len(roles),
            "private_network_adapters": len(roles),
            "nat_control_adapters": len(roles),
            "ssh_keys": len(roles),
        },
        "vm_defaults": {
            "command": VBOXMANAGE_COMMAND,
            "nat_adapter": 1,
            "private_adapter": 2,
        },
        "public_network_policy": "not_used_private_packet_exchange",
        "packet_exchange_network": WIRE_EXPOSURE,
        "private_group": private_group,
        "private_network": True,
        "bridged_lan": False,
        "provider_capabilities": virtualbox_default_provider_capabilities(
            dry_run=request.dry_run,
        ),
        "wire_policy": dict(VIRTUALBOX_WIRE_POLICY),
        "credentials": {
            "label": "none",
            "available": virtualbox_credentials_available(),
            "required_for_live": False,
            "missing_reason": "",
        },
    }


def virtualbox_provider_workflow(request: LabRequest) -> list[LabCommandPlan]:
    """Return planned VirtualBox provider lifecycle command records."""

    roles = plan_virtualbox_roles(request)
    private_group = virtualbox_private_group(request)
    private_network = virtualbox_private_network_metadata(private_group)
    remote_dir = validate_remote_dir(request.remote_dir)
    remote_artifacts = paths.remote_artifact_root(
        virtualbox_session_id(request),
        remote_dir=remote_dir,
    )
    dry_run_flag = ["--dry-run"] if request.dry_run else []
    live_create_flags = [] if request.dry_run else ["--confirm-live-run", "--write-manifest"]
    commands = [
        build_command_plan(
            purpose="check-virtualbox-private-wire",
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
                "bridged_lan": False,
                "network": private_network,
                "wire_policy": dict(VIRTUALBOX_WIRE_POLICY),
            },
        )
    ]

    for role in roles:
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
                    role.planned_ipv4 or "",
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
                    "bridged_lan": False,
                    "private_ip": role.planned_ipv4,
                    "planned_private_address": role.planned_ipv4,
                    "network": private_network,
                    "creates_infrastructure": not request.dry_run,
                    "would_create_infrastructure": request.dry_run,
                    "wire_policy": dict(VIRTUALBOX_WIRE_POLICY),
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
                    "bridged_lan": False,
                    "remote_artifact_root": remote_artifacts,
                },
            ),
            build_command_plan(
                purpose="teardown-disposable-virtualbox-wire-endpoints",
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
                    "bridged_lan": False,
                },
            ),
        ]
    )
    return commands


def _request_with_planned_roles(request: LabRequest) -> LabRequest:
    return replace(request, roles=plan_virtualbox_roles(request))


def _default_private_ipv4(index: int) -> str:
    host_octet = 10 + (index * 10)
    return f"{DEFAULT_PRIVATE_IPV4_PREFIX}.{host_octet}"


def _role_address_source(
    *,
    role: LabRole,
    metadata_private_ipv4: str | None,
) -> str:
    if metadata_private_ipv4 is not None:
        return "metadata.role_private_ipv4s"
    if role.requested_private_ipv4 is not None:
        return "requested_private_ipv4"
    if role.planned_ipv4 is not None:
        return "planned_ipv4"
    return "deterministic-private-default"


def _role_private_ipv4_metadata(metadata: JSONObject) -> dict[str, str]:
    value = metadata.get("role_private_ipv4s")
    if not isinstance(value, Mapping):
        value = metadata.get("role_lan_ipv4s")
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
class VirtualBoxLabProviderAdapter:
    """Lab adapter for VirtualBox private multi-endpoint sessions."""

    name: str = PROVIDER_NAME
    wire_provider: str = WIRE_PROVIDER
    wire_exposure: str = WIRE_EXPOSURE
    credential_label: str = "none"
    missing_credential_reason: str = ""

    def credentials_available(self) -> bool:
        """Return whether VirtualBox credentials are present for live runs."""

        return virtualbox_credentials_available()

    def default_provider_capabilities(
        self,
        *,
        dry_run: bool,
        source: str = "planned-defaults",
    ) -> JSONObject:
        """Return VirtualBox capability defaults before endpoint discovery."""

        return virtualbox_default_provider_capabilities(dry_run=dry_run, source=source)

    def normalize_provider_capabilities(
        self,
        raw: JSONObject,
        *,
        dry_run: bool | None = None,
        source: str | None = None,
    ) -> JSONObject:
        """Normalize VirtualBox provider capabilities."""

        return normalize_virtualbox_provider_capabilities(
            raw,
            dry_run=dry_run,
            source=source,
        )

    def plan_roles(self, request: LabRequest) -> list[LabRole]:
        """Return provider-normalized roles and private address assignments."""

        return plan_virtualbox_roles(request)

    def private_group(self, request: LabRequest) -> str | None:
        """Return the VirtualBox internal network group name."""

        return virtualbox_private_group(request)

    def requested_private_ip(self, role: LabRole, request: LabRequest) -> str | None:
        """Return the private IPv4 to request from wire."""

        return role.planned_ipv4

    def planned_infrastructure(self, request: LabRequest) -> JSONObject:
        """Return dry-run-safe VirtualBox infrastructure metadata."""

        return virtualbox_planned_infrastructure(request)

    def provider_workflow(self, request: LabRequest) -> list[LabCommandPlan]:
        """Return planned VirtualBox provider lifecycle commands."""

        return virtualbox_provider_workflow(request)

    def wire_endpoint_plan(
        self,
        request: LabRequest,
        *,
        client: wire_client.WireClient | None = None,
        created_endpoint_ids: list[str] | None = None,
    ) -> JSONObject:
        """Plan or create VirtualBox wire endpoints for all request roles."""

        planned_request = _request_with_planned_roles(request)
        validation = self.validate_request(planned_request)
        if not validation.passed:
            raise PermissionError("; ".join(validation.errors))

        wire = client or wire_client.WireClient()
        endpoint_plans: list[JSONObject] = []
        endpoints: dict[str, JSONObject] = {}
        command_records: list[JSONObject] = []
        created_ids: list[str] = []

        for role in planned_request.roles:
            response = wire.create(
                provider=self.wire_provider,
                exposure=self.wire_exposure,
                role=role.name,
                private_group=virtualbox_private_group(planned_request),
                private_ip=role.planned_ipv4,
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
                    purpose=f"create {role.name} VirtualBox private endpoint",
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
            "private_group": virtualbox_private_group(planned_request),
            "private_network": True,
            "bridged_lan": False,
            "wire_policy": dict(VIRTUALBOX_WIRE_POLICY),
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
                "private_group": virtualbox_private_group(request),
                "private_network": True,
                "private_network_cidr": PRIVATE_NETWORK_CIDR,
                "bridged_lan": False,
                "packet_exchange_network": self.wire_exposure,
                "isolated_network": True,
                "planned_private_address": role.planned_ipv4,
                "planned_private_address_source": role.metadata.get(
                    "planned_private_address_source",
                    "deterministic-private-default",
                ),
                "wire_policy": dict(VIRTUALBOX_WIRE_POLICY),
            },
        )

    def plan_session(
        self,
        request: LabRequest,
        *,
        client: wire_client.WireClient | None = None,
    ) -> LabSession:
        """Return a planned or live VirtualBox lab session."""

        planned_request = _request_with_planned_roles(request)
        session_id = virtualbox_session_id(planned_request)
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
                "private_group": virtualbox_private_group(planned_request),
                "private_network": True,
                "bridged_lan": False,
                "credential_label": self.credential_label,
                "credentials_available": self.credentials_available(),
                "missing_credential_reason": self.missing_credential_reason,
                "wire_policy": dict(VIRTUALBOX_WIRE_POLICY),
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
        """Validate VirtualBox-specific request invariants before planning."""

        errors: list[str] = []
        if request.provider != self.name:
            errors.append(f"unexpected provider: {request.provider}")
        if not request.dry_run and not request.confirm_live_run:
            errors.append("live VirtualBox lab creation requires confirm_live_run")

        planned_roles = plan_virtualbox_roles(request)
        planned_ips = [role.planned_ipv4 for role in planned_roles]
        duplicates = sorted(
            ip
            for ip in set(planned_ips)
            if ip is not None and planned_ips.count(ip) > 1
        )
        if duplicates:
            errors.append(f"duplicate planned private IPv4 addresses: {', '.join(duplicates)}")

        return LabValidationCheck(
            name="virtualbox-request",
            passed=not errors,
            subject=self.name,
            errors=errors,
            metadata={
                "provider": self.name,
                "dry_run": request.dry_run,
                "confirm_live_run": request.confirm_live_run,
                "credentials_available": self.credentials_available(),
                "private_group": virtualbox_private_group(request),
                "private_network": True,
                "bridged_lan": False,
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
            "check-virtualbox-private-wire",
            "collect-lab-artifacts",
            "teardown-disposable-virtualbox-wire-endpoints",
        }
        if not any(purpose.startswith("create-") for purpose in purposes):
            errors.append("missing provider workflow phase: create role endpoint")
        missing = sorted(required - purposes)
        if missing:
            errors.append(f"missing provider workflow phases: {', '.join(missing)}")

        for command in commands:
            if len(command.argv) < 2 or command.argv[0] != WIRE_ENTRYPOINT:
                errors.append(f"provider command must route through {WIRE_ENTRYPOINT}")
            if command.metadata.get("wire_command") is not True:
                errors.append("provider command must be marked as wire_command")
            if command.metadata.get("provider") != self.name:
                errors.append("provider command must target VirtualBox")
            if command.metadata.get("exposure") != self.wire_exposure:
                errors.append("provider command must target private exposure")
            if command.metadata.get("private_network") is not True:
                errors.append("VirtualBox provider command must carry private network metadata")
            if command.operation == "wire.create":
                if "--private-group" not in command.argv:
                    errors.append("VirtualBox private create command lacks --private-group")
                if "--private-ip" not in command.argv:
                    errors.append("VirtualBox private create command lacks --private-ip")
            if dry_run and command.operation in {"wire.doctor", "wire.create"}:
                if "--dry-run" not in command.argv:
                    errors.append(f"dry-run provider command lacks --dry-run: {command.shell()}")
                if command.live_mutation:
                    errors.append("dry-run provider command cannot be marked live_mutation")
            if not dry_run and command.operation == "wire.create":
                if "--confirm-live-run" not in command.argv:
                    errors.append("real provider create command lacks --confirm-live-run")
                if not command.live_mutation:
                    errors.append("real provider create command must be live_mutation")
            if command.operation in {"wire.collect_artifacts", "wire.destroy"}:
                if command.metadata.get("always_attempt") is not True:
                    errors.append(f"{command.operation} must be marked always_attempt")

        return LabValidationCheck(
            name="virtualbox-provider-workflow",
            passed=not errors,
            subject=self.name,
            errors=errors,
            metadata={
                "provider": self.name,
                "dry_run": dry_run,
                "always_collect_artifacts": True,
                "always_teardown": True,
                "private_network": True,
                "bridged_lan": False,
            },
        )

    def validate_session(self, session: LabSession) -> list[LabValidationCheck]:
        """Validate VirtualBox-specific invariants on a planned session."""

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
        if session.infrastructure_metadata.get("bridged_lan") is not False:
            errors.append("infrastructure metadata must not describe bridged LAN")
        if session.infrastructure_metadata.get("wire_policy") != VIRTUALBOX_WIRE_POLICY:
            errors.append("infrastructure metadata must preserve VirtualBox wire policy")
        for endpoint in session.endpoints:
            if endpoint.metadata.get("private_network") is not True:
                errors.append(f"endpoint must be marked private: {endpoint.role}")
            if endpoint.metadata.get("bridged_lan") is not False:
                errors.append(f"endpoint should not carry bridged LAN metadata: {endpoint.role}")
            if endpoint.metadata.get("wire_policy") != VIRTUALBOX_WIRE_POLICY:
                errors.append(f"endpoint lacks VirtualBox wire policy metadata: {endpoint.role}")

        return [
            LabValidationCheck(
                name="virtualbox-session",
                passed=not errors,
                subject=session.session_id,
                errors=errors,
                metadata={
                    "provider": self.name,
                    "endpoint_count": len(session.endpoints),
                    "role_count": len(session.roles),
                    "dry_run": session.dry_run,
                    "private_group": session.metadata.get("private_group"),
                    "bridged_lan": False,
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


VIRTUALBOX_LAB_PROVIDER_ADAPTER: LabProviderAdapter = VirtualBoxLabProviderAdapter()
