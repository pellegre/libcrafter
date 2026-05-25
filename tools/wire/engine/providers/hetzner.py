"""Hetzner provider checks and lifecycle operations for wire endpoints."""

from __future__ import annotations

import json
import os
import secrets
import shutil
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from ..model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResource,
    ProviderResources,
)
from ..process import CommandResult, run_command
from ..registry import validate_request
from ..ssh import create_key_pair, ensure_known_hosts_file
from ..state import endpoint_layout, ensure_endpoint_dirs, write_endpoint_manifest


TOKEN_ENV = "HETZNER_API_TOKEN"
HCLOUD_TOKEN_ENV = "HCLOUD_TOKEN"
HCLOUD_COMMAND = "hcloud"
PLANNED_CREATED_AT = "planned"
CONFIRMATION_ERROR = (
    "protected provider execution requires --confirm-live-run; no Hetzner resources were created"
)
DEFAULT_SERVER_TYPE = "cx22"
DEFAULT_IMAGE = "ubuntu-24.04"
DEFAULT_LOCATION = "hel1"


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
    token_configured = bool(_hetzner_token(environ))
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
                f"{TOKEN_ENV} or {HCLOUD_TOKEN_ENV} is configured"
                if token_configured
                else f"{TOKEN_ENV} or {HCLOUD_TOKEN_ENV} is not configured"
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
            "accepted_env": [TOKEN_ENV, HCLOUD_TOKEN_ENV],
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
    confirm_live_run: bool = False,
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Create or plan one Hetzner endpoint."""

    validate_request(provider, exposure)
    _validate_create_request(exposure, role, private_group, private_ip)

    if dry_run:
        return _planned_endpoint_manifest(
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
        )

    if exposure != "wan":
        raise NotImplementedError("real hetzner create-endpoint is only implemented for wan")
    if not confirm_live_run:
        raise PermissionError(CONFIRMATION_ERROR)

    return _create_wan_endpoint(provider=provider, exposure=exposure, role=role, env=env)


def cli_output_manifest(manifest: Mapping[str, object]) -> dict[str, object]:
    """Return a CLI-compatible manifest view without changing stored schema."""

    output = dict(manifest)
    provider_resources = output.get("provider_resources")
    if isinstance(provider_resources, Mapping):
        resources = provider_resources.get("resources")
        if isinstance(resources, list):
            output["provider_resources"] = [
                _compat_provider_resource(resource) for resource in resources
            ]
    return output


def _create_wan_endpoint(
    *,
    provider: str,
    exposure: str,
    role: str,
    env: Mapping[str, str] | None,
) -> dict[str, object]:
    environ = os.environ if env is None else env
    token = _hetzner_token(environ)
    if not token:
        raise RuntimeError(f"{TOKEN_ENV} or {HCLOUD_TOKEN_ENV} must be configured")
    if shutil.which(HCLOUD_COMMAND) is None:
        raise RuntimeError(f"{HCLOUD_COMMAND} was not found on PATH")

    created_at = _utc_now()
    endpoint_id = _real_endpoint_id(provider=provider, exposure=exposure, role=role)
    layout = ensure_endpoint_dirs(endpoint_id)
    ensure_known_hosts_file(layout.known_hosts_path)
    _ensure_endpoint_key(layout.private_key_path, endpoint_id)

    server_id: str | None = None
    ssh_key_id: str | None = None
    server_name = _server_name(endpoint_id)
    ssh_key_name = f"{server_name}-key"
    hcloud_env = {HCLOUD_TOKEN_ENV: token}

    try:
        ssh_key = _hcloud_json(
            [
                HCLOUD_COMMAND,
                "ssh-key",
                "create",
                "--name",
                ssh_key_name,
                "--public-key-from-file",
                str(_public_key_path(layout.private_key_path)),
                "-o",
                "json",
            ],
            env=hcloud_env,
        )
        ssh_key_id = _object_id(_json_object(ssh_key.get("ssh_key", ssh_key), "ssh_key"))

        server = _hcloud_json(
            [
                HCLOUD_COMMAND,
                "server",
                "create",
                "--name",
                server_name,
                "--type",
                _env_or_default(environ, "HETZNER_SERVER_TYPE", DEFAULT_SERVER_TYPE),
                "--image",
                _env_or_default(environ, "HETZNER_IMAGE", DEFAULT_IMAGE),
                "--location",
                _env_or_default(environ, "HETZNER_LOCATION", DEFAULT_LOCATION),
                "--ssh-key",
                ssh_key_name,
                "--label",
                "libcrafter-wire=true",
                "--label",
                f"libcrafter-wire-endpoint-id={_label_value(endpoint_id)}",
                "--label",
                f"libcrafter-wire-role={_label_value(role)}",
                "--label",
                "libcrafter-wire-exposure=wan",
                "-o",
                "json",
            ],
            env=hcloud_env,
        )
        server_object = _json_object(server.get("server", server), "server")
        server_id = _object_id(server_object)
        public_net = _json_object(server_object.get("public_net", {}), "server.public_net")
        public_ipv4 = _ip_address(public_net.get("ipv4"))
        public_ipv6 = _ip_address(public_net.get("ipv6"))
        ssh_host = public_ipv4 or public_ipv6
        if ssh_host is None:
            raise RuntimeError("hcloud server create did not return a public IPv4 or IPv6 address")

        manifest = EndpointManifest(
            endpoint_id=endpoint_id,
            provider=provider,
            exposure=exposure,
            status="active",
            role=role,
            created_at=created_at,
            ssh=EndpointSSHInfo(
                host=ssh_host,
                user="root",
                identity_file=str(layout.private_key_path),
                known_hosts_file=str(layout.known_hosts_path),
                metadata={
                    "created_by": "tools/wire",
                    "server_name": server_name,
                },
            ),
            interfaces=[
                NetworkInterface(
                    name="public",
                    exposure=exposure,
                    ipv4=public_ipv4,
                    ipv6=public_ipv6,
                    metadata={
                        "server_id": server_id,
                        "server_name": server_name,
                    },
                )
            ],
            provider_resources=ProviderResources(
                resources=[
                    ProviderResource(
                        kind="server",
                        provider_id=server_id,
                        name=server_name,
                        cleanup=True,
                        metadata={
                            "type": "server",
                            "public_ipv4": public_ipv4,
                            "public_ipv6": public_ipv6,
                        },
                    ),
                    ProviderResource(
                        kind="ssh-key",
                        provider_id=ssh_key_id,
                        name=ssh_key_name,
                        cleanup=True,
                        metadata={"type": "ssh-key"},
                    ),
                ],
                cleanup_order=["server", "ssh-key"],
                metadata={"created_by": "tools/wire", "provider": provider},
            ),
            artifact_dir=str(layout.artifact_dir),
            metadata={
                "created": True,
                "dry_run": False,
                "state_dir": str(layout.state_dir),
                "manifest_path": str(layout.manifest_path),
                "cleanup": {
                    "server_id": server_id,
                    "ssh_key_id": ssh_key_id,
                    "server_name": server_name,
                    "ssh_key_name": ssh_key_name,
                },
            },
        )
        manifest_path = write_endpoint_manifest(manifest)
        output = manifest.to_dict()
        output["created"] = True
        output["dry_run"] = False
        output["state_dir"] = str(manifest_path.parent)
        output["manifest_path"] = str(manifest_path)
        return output
    except Exception:
        _cleanup_partial_wan(server_id=server_id, ssh_key_id=ssh_key_id, env=hcloud_env)
        raise


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
        provider_resources=ProviderResources(
            resources=[
                ProviderResource(
                    kind="planned-server",
                    provider_id=f"{endpoint_id}-server",
                    name=_server_name(endpoint_id),
                    cleanup=True,
                    metadata={"planned": True, "type": "planned-server"},
                )
            ],
            cleanup_order=["server"],
            metadata={"planned": True},
        ),
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


def _compat_provider_resource(resource: object) -> dict[str, object]:
    if not isinstance(resource, Mapping):
        return {"type": "unknown", "value": str(resource)}
    output = dict(resource)
    metadata = output.get("metadata")
    resource_type = None
    if isinstance(metadata, Mapping):
        resource_type = metadata.get("type")
    if not isinstance(resource_type, str) or resource_type == "":
        kind = output.get("kind")
        resource_type = kind if isinstance(kind, str) and kind else "resource"
    output["type"] = resource_type
    return output


def _hetzner_token(environ: Mapping[str, str]) -> str | None:
    return environ.get(TOKEN_ENV) or environ.get(HCLOUD_TOKEN_ENV) or None


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _real_endpoint_id(*, provider: str, exposure: str, role: str) -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    suffix = secrets.token_hex(3)
    return "-".join(
        _path_component(part) for part in (provider, exposure, role, timestamp, suffix)
    )


def _server_name(endpoint_id: str) -> str:
    name = f"wire-{endpoint_id}"
    if len(name) <= 63:
        return name
    return name[:63].rstrip("-") or "wire-endpoint"


def _label_value(value: str) -> str:
    output = "".join(character if character.isalnum() else "-" for character in value.lower())
    output = "-".join(part for part in output.split("-") if part)
    return (output or "value")[:63].rstrip("-") or "value"


def _env_or_default(environ: Mapping[str, str], name: str, default: str) -> str:
    value = environ.get(name)
    if value is None or value == "":
        return default
    return value


def _ensure_endpoint_key(private_key_path: Path, endpoint_id: str) -> None:
    public_key_path = _public_key_path(private_key_path)
    if private_key_path.exists() and public_key_path.exists():
        return
    if private_key_path.exists() != public_key_path.exists():
        raise FileExistsError(
            f"endpoint SSH key is incomplete: {private_key_path} and {public_key_path}"
        )
    result = create_key_pair(private_key_path, comment=f"libcrafter-wire {endpoint_id}", timeout=30)
    if not result.ok:
        raise RuntimeError(_command_error("ssh-keygen failed", result))


def _public_key_path(private_key_path: Path) -> Path:
    return private_key_path.with_name(f"{private_key_path.name}.pub")


def _hcloud_json(argv: list[str], *, env: Mapping[str, str]) -> dict[str, object]:
    result = run_command(argv, env=env, timeout=180)
    if not result.ok:
        raise RuntimeError(_command_error("hcloud command failed", result))
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"hcloud command did not emit valid JSON: {result.command}") from exc
    return _json_object(value, "hcloud output")


def _cleanup_partial_wan(
    *,
    server_id: str | None,
    ssh_key_id: str | None,
    env: Mapping[str, str],
) -> None:
    if server_id is not None:
        _hcloud_cleanup([HCLOUD_COMMAND, "server", "delete", server_id], env=env)
    if ssh_key_id is not None:
        _hcloud_cleanup([HCLOUD_COMMAND, "ssh-key", "delete", ssh_key_id], env=env)


def _hcloud_cleanup(argv: list[str], *, env: Mapping[str, str]) -> None:
    run_command(argv, env=env, timeout=120)


def _command_error(message: str, result: CommandResult) -> str:
    details = result.stderr.strip() or result.stdout.strip() or result.error or "no output"
    return f"{message}: {result.command}: {details}"


def _json_object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise RuntimeError(f"{name} must be a JSON object")
    return dict(value)


def _object_id(value: Mapping[str, object]) -> str:
    provider_id = value.get("id")
    if isinstance(provider_id, int):
        return str(provider_id)
    if isinstance(provider_id, str) and provider_id:
        return provider_id
    raise RuntimeError("hcloud output did not include an object id")


def _ip_address(value: object) -> str | None:
    if isinstance(value, Mapping):
        ip = value.get("ip")
        return ip if isinstance(ip, str) and ip else None
    return None
