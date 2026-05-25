"""Hetzner provider checks for wire endpoints."""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping

from ..model import EndpointManifest, EndpointSSHInfo, NetworkInterface, ProviderResources
from ..registry import validate_request
from ..state import endpoint_layout


TOKEN_ENV = "HETZNER_API_TOKEN"
HCLOUD_COMMAND = "hcloud"
PLANNED_CREATED_AT = "planned"


def doctor(
    *,
    provider: str,
    exposure: str,
    dry_run: bool = False,
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Return non-mutating Hetzner provider prerequisite checks."""

    validate_request(provider, exposure)

    environ = os.environ if env is None else env
    hcloud_path = shutil.which(HCLOUD_COMMAND)
    token_configured = bool(environ.get(TOKEN_ENV))
    credential_required = not dry_run

    checks: list[dict[str, object]] = [
        {
            "name": "provider_exposure",
            "ok": True,
            "message": f"{provider}/{exposure} is supported",
        },
        {
            "name": "hcloud_installed",
            "ok": hcloud_path is not None,
            "message": (
                f"{HCLOUD_COMMAND} found at {hcloud_path}"
                if hcloud_path is not None
                else f"{HCLOUD_COMMAND} was not found on PATH"
            ),
        },
        {
            "name": "hetzner_api_token",
            "ok": token_configured or dry_run,
            "message": (
                f"{TOKEN_ENV} is configured"
                if token_configured
                else f"{TOKEN_ENV} is not configured"
            ),
        },
    ]

    return {
        "provider": provider,
        "exposure": exposure,
        "dry_run": dry_run,
        "ok": all(bool(check["ok"]) for check in checks),
        "checks": checks,
        "hcloud": {
            "command": HCLOUD_COMMAND,
            "installed": hcloud_path is not None,
            "path": hcloud_path,
        },
        "credentials": {
            "env": TOKEN_ENV,
            "configured": token_configured,
            "required": credential_required,
        },
    }


def create_endpoint(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None = None,
    private_ip: str | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    """Create or plan one Hetzner endpoint."""

    validate_request(provider, exposure)
    _validate_create_request(exposure, role, private_group, private_ip)

    if not dry_run:
        raise NotImplementedError("hetzner create-endpoint is only implemented for --dry-run")

    return _planned_endpoint_manifest(
        provider=provider,
        exposure=exposure,
        role=role,
        private_group=private_group,
        private_ip=private_ip,
    )


def _planned_endpoint_manifest(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
) -> dict[str, object]:
    endpoint_id = _planned_endpoint_id(
        provider=provider,
        exposure=exposure,
        role=role,
        private_group=private_group,
    )
    layout = endpoint_layout(endpoint_id)
    metadata: dict[str, object] = {
        "created": False,
        "dry_run": True,
        "state_dir": str(layout.state_dir),
        "manifest_path": str(layout.manifest_path),
    }
    interfaces = [
        NetworkInterface(
            name="public" if exposure == "wan" else "private",
            exposure=exposure,
            ipv4=private_ip if exposure == "private" else None,
            provider_network_id=(
                _planned_private_network_id(private_group)
                if exposure == "private" and private_group is not None
                else None
            ),
            metadata=_private_interface_metadata(private_group)
            if exposure == "private"
            else {"planned": True},
        )
    ]

    if exposure == "private":
        private_metadata = _planned_private_metadata(private_group, private_ip)
        metadata["private"] = private_metadata
        if private_group is not None:
            metadata["private_group"] = private_group

    manifest = EndpointManifest(
        endpoint_id=endpoint_id,
        provider=provider,
        exposure=exposure,
        status="planned",
        role=role,
        created_at=PLANNED_CREATED_AT,
        ssh=EndpointSSHInfo(
            host="planned",
            user="root",
            identity_file=str(layout.private_key_path),
            known_hosts_file=str(layout.known_hosts_path),
            metadata={"planned": True},
        ),
        interfaces=interfaces,
        provider_resources=ProviderResources(metadata={"planned": True}),
        artifact_dir=str(layout.artifact_dir),
        metadata=metadata,
    ).to_dict()

    manifest["created"] = False
    manifest["dry_run"] = True
    manifest["state_dir"] = str(layout.state_dir)
    manifest["manifest_path"] = str(layout.manifest_path)
    return manifest


def _validate_create_request(
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
) -> None:
    if role == "":
        raise ValueError("role must be a non-empty string")
    if private_group == "":
        raise ValueError("private_group must be a non-empty string when supplied")
    if private_ip == "":
        raise ValueError("private_ip must be a non-empty string when supplied")
    if exposure != "private" and private_group is not None:
        raise ValueError("--private-group is only valid with --exposure private")
    if exposure != "private" and private_ip is not None:
        raise ValueError("--private-ip is only valid with --exposure private")


def _planned_endpoint_id(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
) -> str:
    parts = ["planned", provider, exposure, role]
    if private_group is not None:
        parts.append(private_group)
    return "-".join(_path_component(part) for part in parts)


def _path_component(value: str) -> str:
    output = "".join(character if character.isalnum() else "-" for character in value.lower())
    output = "-".join(part for part in output.split("-") if part)
    return output or "value"


def _planned_private_network_id(private_group: str | None) -> str:
    suffix = _path_component(private_group) if private_group is not None else "ungrouped"
    return f"planned-private-network-{suffix}"


def _private_interface_metadata(private_group: str | None) -> dict[str, object]:
    metadata: dict[str, object] = {
        "planned": True,
        "network": _planned_private_metadata(private_group, private_ip=None),
    }
    if private_group is not None:
        metadata["private_group"] = private_group
    return metadata


def _planned_private_metadata(
    private_group: str | None,
    private_ip: str | None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "planned": True,
        "network_id": _planned_private_network_id(private_group),
    }
    if private_group is not None:
        metadata["private_group"] = private_group
        metadata["network_name"] = f"wire-{_path_component(private_group)}"
    if private_ip is not None:
        metadata["ipv4"] = private_ip
    return metadata
