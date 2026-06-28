"""Hetzner endpoint appliance substrate helpers."""

from __future__ import annotations

from collections.abc import Mapping

from tools.appliance.engine.image import requested_appliance_image

from ...appliance import DEFAULT_APPLIANCE_REMOTE_BASE
from ...appliance import (
    EndpointApplianceDeployPlan,
    render_endpoint_appliance_deploy_plan,
    resolve_endpoint_appliance_target,
)
from ...assets import AssetSSHInfo, EndpointAsset
from ...model import EndpointManifest
from .utils import _path_component


HETZNER_APPLIANCE_SUBSTRATE = "ssh-docker"
HETZNER_WAN_APPLIANCE_PROFILES = ("wan-raw",)
HETZNER_PRIVATE_APPLIANCE_PROFILES = ("lan-raw",)


def hetzner_appliance_metadata(
    exposure: str,
    *,
    endpoint_id: str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Return stable appliance metadata for one Hetzner endpoint exposure."""

    supported_profiles = _supported_profiles(exposure)
    raw_profile = supported_profiles[0] if supported_profiles else None
    metadata: dict[str, object] = {
        "appliance_capable": True,
        "nested_docker": True,
        "docker_execution_supported": True,
        "docker_command": "docker",
        "substrate": HETZNER_APPLIANCE_SUBSTRATE,
        "remote_base": DEFAULT_APPLIANCE_REMOTE_BASE,
        "supported_profiles": supported_profiles,
        "image_tag": requested_appliance_image({} if env is None else env),
        "docker_setup": "install-or-verify",
        "docker_host_readiness": "check-before-use",
    }
    if endpoint_id is not None:
        remote_root = f"{DEFAULT_APPLIANCE_REMOTE_BASE}/{_path_component(endpoint_id)}"
        metadata["remote_work_root"] = f"{remote_root}/work"
        metadata["remote_artifact_root"] = f"{remote_root}/artifacts"
    if raw_profile is not None:
        metadata["raw_profile"] = raw_profile
        metadata["profile_hints"] = {
            "raw_profile": raw_profile,
            "network_scope": "private-lab" if exposure == "private" else "wan",
        }
    if exposure == "private":
        metadata["private_lab"] = True
    return metadata


def render_hetzner_appliance_deploy_plan(
    manifest: EndpointManifest | Mapping[str, object],
    *,
    env: Mapping[str, str] | None = None,
    image_tag: str | None = None,
    docker_install_script: str | None = None,
    image_archive_remote_path: str | None = None,
    remote_context_dir: str | None = None,
    connect_timeout: int | None = None,
) -> EndpointApplianceDeployPlan:
    """Return a Docker install-or-verify appliance deploy plan for Hetzner."""

    target = resolve_endpoint_appliance_target(manifest)
    kwargs: dict[str, object] = {"install_docker": True}
    if env is not None:
        kwargs["env"] = env
    if image_tag is not None:
        kwargs["image_tag"] = image_tag
    if docker_install_script is not None:
        kwargs["docker_install_script"] = docker_install_script
    if image_archive_remote_path is not None:
        kwargs["image_archive_remote_path"] = image_archive_remote_path
    if remote_context_dir is not None:
        kwargs["remote_context_dir"] = remote_context_dir
    if connect_timeout is not None:
        kwargs["connect_timeout"] = connect_timeout
    return render_endpoint_appliance_deploy_plan(target, **kwargs)


def hetzner_endpoint_asset(
    manifest: EndpointManifest | Mapping[str, object],
    *,
    asset_id: str | None = None,
    status: str = "available",
) -> EndpointAsset:
    """Convert a Hetzner endpoint manifest into a generic SSH Docker asset."""

    endpoint = (
        manifest
        if isinstance(manifest, EndpointManifest)
        else EndpointManifest.from_dict(manifest)
    )
    target = resolve_endpoint_appliance_target(endpoint)
    appliance_metadata = dict(
        hetzner_appliance_metadata(endpoint.exposure, endpoint_id=endpoint.endpoint_id)
    )
    endpoint_appliance = endpoint.metadata.get("appliance")
    if isinstance(endpoint_appliance, Mapping):
        appliance_metadata.update(endpoint_appliance)
    appliance_metadata["remote_work_root"] = target.target.remote_work_root
    appliance_metadata["remote_artifact_root"] = target.target.remote_artifact_root

    return EndpointAsset(
        asset_id=asset_id or endpoint.endpoint_id,
        substrate=HETZNER_APPLIANCE_SUBSTRATE,
        status=status,
        supported_profiles=_supported_profiles(endpoint.exposure),
        ssh=AssetSSHInfo(
            host=endpoint.ssh.host,
            user=endpoint.ssh.user,
            port=endpoint.ssh.port,
            identity_file=endpoint.ssh.identity_file,
            known_hosts_file=endpoint.ssh.known_hosts_file,
            metadata=endpoint.ssh.metadata,
        ),
        docker={"command": target.target.docker_command},
        metadata={
            "provider": endpoint.provider,
            "endpoint_id": endpoint.endpoint_id,
            "exposure": endpoint.exposure,
            "role": endpoint.role,
            "appliance": appliance_metadata,
        },
    )


def _supported_profiles(exposure: str) -> list[str]:
    if exposure == "wan":
        return list(HETZNER_WAN_APPLIANCE_PROFILES)
    if exposure == "private":
        return list(HETZNER_PRIVATE_APPLIANCE_PROFILES)
    return []


__all__ = [
    "HETZNER_APPLIANCE_SUBSTRATE",
    "HETZNER_PRIVATE_APPLIANCE_PROFILES",
    "HETZNER_WAN_APPLIANCE_PROFILES",
    "hetzner_appliance_metadata",
    "hetzner_endpoint_asset",
    "render_hetzner_appliance_deploy_plan",
]
