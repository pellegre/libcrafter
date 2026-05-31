"""Docker lab provider adapter.

The lab provider maps Docker to the isolated ``docker/private`` wire exposure.
LAN and WAN Docker modes remain direct wire-provider modes in this phase.
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.wire.engine.providers.docker.constants import DOCKER_DEFAULT_PRIVATE_CIDR
from tools.wire.engine.providers.docker.resources import docker_private_network_name

from ..model import JSONObject, LabRequest
from .common import (
    normalize_provider_capabilities as normalize_common_provider_capabilities,
    request_session_label,
    slug_label,
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

    def private_group(self, request: LabRequest) -> str:
        """Return the Docker private bridge group name."""

        return docker_private_group(request)


DOCKER_LAB_PROVIDER_ADAPTER = DockerLabProviderAdapter()
