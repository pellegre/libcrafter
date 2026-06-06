"""Docker provider prerequisite checks."""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping
from typing import Any

from ...process import run_command
from ...registry import ProviderExposureError
from .constants import (
    DOCKER_COMMAND_ENV,
    DOCKER_DEFAULT_IMAGE,
    DOCKER_DEFAULT_LAN_NETWORK,
    DOCKER_DEFAULT_PRIVATE_CIDR,
    DOCKER_DEFAULT_WAN_NETWORK,
    DOCKER_IMAGE_ENV,
    DOCKER_LAN_NETWORK_ENV,
    DOCKER_PRIVATE_CIDR_ENV,
    DOCKER_WAN_NETWORK_ENV,
    EXPOSURE_LAN,
    EXPOSURE_PRIVATE,
    EXPOSURE_WAN,
    NAT_L3_CAPABILITIES,
    PRIVATE_CAPABILITIES,
    PROVIDER_NAME,
    SUPPORTED_EXPOSURES,
    DockerRunner,
)
from .resources import docker_argv, parse_private_cidr, private_gateway_ipv4, requested_docker_command


_DAEMON_TIMEOUT_SECONDS = 30
_DOCKER_SERVER_VERSION_ARGV = ("version", "--format", "{{json .Server}}")
_DOCKER_CAPABILITIES_BY_EXPOSURE = {
    EXPOSURE_PRIVATE: ("NET_RAW", "NET_ADMIN", "SYS_CHROOT", "SETGID", "SETUID"),
    EXPOSURE_LAN: ("NET_RAW", "SYS_CHROOT", "SETGID", "SETUID"),
    EXPOSURE_WAN: ("NET_RAW", "SYS_CHROOT", "SETGID", "SETUID"),
}
_WIRE_CAPABILITIES_BY_EXPOSURE = {
    EXPOSURE_PRIVATE: PRIVATE_CAPABILITIES,
    EXPOSURE_LAN: NAT_L3_CAPABILITIES,
    EXPOSURE_WAN: NAT_L3_CAPABILITIES,
}


def doctor(
    *,
    provider: str,
    exposure: str,
    dry_run: bool = False,
    env: Mapping[str, str] | None = None,
    command_runner: DockerRunner | None = None,
) -> dict[str, object]:
    """Return non-mutating Docker provider prerequisite checks."""

    _validate_provider_exposure(provider, exposure)

    environ = os.environ if env is None else env
    docker_command = requested_docker_command(environ)
    docker_path = shutil.which(docker_command)
    configuration = _configuration_report(exposure, environ)
    daemon = _daemon_report(
        docker_command=docker_command,
        docker_path=docker_path,
        env=environ,
        command_runner=command_runner,
    )
    security = _security_model_report(exposure)
    capabilities = _capabilities_report(exposure)

    checks: list[dict[str, object]] = [
        {
            "name": "provider_exposure",
            "ok": True,
            "message": f"{provider}/{exposure} is supported",
        },
        {
            "name": "docker_cli_installed",
            "ok": docker_path is not None,
            "message": (
                f"{docker_command} found at {docker_path}"
                if docker_path is not None
                else f"{docker_command} was not found on PATH"
            ),
        },
        daemon["check"],
        configuration["check"],
    ]
    checks.extend(security["checks"])

    return {
        "provider": provider,
        "exposure": exposure,
        "dry_run": dry_run,
        "ok": all(bool(check["ok"]) for check in checks),
        "checks": checks,
        "commands": {
            "docker": {
                "command": docker_command,
                "env": DOCKER_COMMAND_ENV,
                "installed": docker_path is not None,
                "path": docker_path,
            }
        },
        "daemon": daemon["daemon"],
        "configuration": configuration["configuration"],
        "capabilities": capabilities,
        "security_model": security["security_model"],
    }


def _validate_provider_exposure(provider: str, exposure: str) -> None:
    if provider != PROVIDER_NAME:
        raise ProviderExposureError(
            f"unsupported provider/exposure: provider={provider!r}, "
            f"exposure={exposure!r}; expected provider {PROVIDER_NAME!r}"
        )
    if exposure not in SUPPORTED_EXPOSURES:
        supported = ", ".join(sorted(SUPPORTED_EXPOSURES))
        raise ProviderExposureError(
            f"unsupported provider/exposure: provider={provider!r}, "
            f"exposure={exposure!r}; supported exposures for provider "
            f"{PROVIDER_NAME!r}: {supported}"
        )


def _daemon_report(
    *,
    docker_command: str,
    docker_path: str | None,
    env: Mapping[str, str],
    command_runner: DockerRunner | None,
) -> dict[str, object]:
    argv = docker_argv(*_DOCKER_SERVER_VERSION_ARGV, docker_command=docker_command)
    daemon: dict[str, object] = {
        "checked": docker_path is not None,
        "reachable": False,
        "command": argv,
        "non_mutating": True,
        "timeout_seconds": _DAEMON_TIMEOUT_SECONDS,
    }
    if docker_path is None:
        return {
            "check": {
                "name": "docker_daemon_reachable",
                "ok": False,
                "message": "Docker daemon check skipped because the Docker CLI was not found",
            },
            "daemon": daemon,
        }

    runner = run_command if command_runner is None else command_runner
    result = runner(argv, env=env, timeout=_DAEMON_TIMEOUT_SECONDS)
    error = result.stderr.strip() or result.error or ""
    daemon.update(
        {
            "reachable": result.ok,
            "exit_code": result.exit_code,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "error": error or None,
        }
    )
    return {
        "check": {
            "name": "docker_daemon_reachable",
            "ok": result.ok,
            "message": (
                "Docker daemon is reachable"
                if result.ok
                else f"Docker daemon is not reachable: {error or 'command failed'}"
            ),
        },
        "daemon": daemon,
    }


def _configuration_report(exposure: str, env: Mapping[str, str]) -> dict[str, object]:
    image = _env_value(env, DOCKER_IMAGE_ENV, DOCKER_DEFAULT_IMAGE)
    lan_network = _env_value(env, DOCKER_LAN_NETWORK_ENV, DOCKER_DEFAULT_LAN_NETWORK)
    wan_network = _env_value(env, DOCKER_WAN_NETWORK_ENV, DOCKER_DEFAULT_WAN_NETWORK)
    private_cidr_raw = _env_value(env, DOCKER_PRIVATE_CIDR_ENV, DOCKER_DEFAULT_PRIVATE_CIDR)
    configuration: dict[str, object] = {
        "image": {
            "env": DOCKER_IMAGE_ENV,
            "tag": image,
            "default": DOCKER_DEFAULT_IMAGE,
        },
        "networks": {
            EXPOSURE_PRIVATE: {
                "env": DOCKER_PRIVATE_CIDR_ENV,
                "cidr": private_cidr_raw,
                "default_cidr": DOCKER_DEFAULT_PRIVATE_CIDR,
                "type": "provider-owned-internal-bridge",
            },
            EXPOSURE_LAN: {
                "env": DOCKER_LAN_NETWORK_ENV,
                "network": lan_network,
                "default": DOCKER_DEFAULT_LAN_NETWORK,
                "type": "nat-backed-l3-lan",
            },
            EXPOSURE_WAN: {
                "env": DOCKER_WAN_NETWORK_ENV,
                "network": wan_network,
                "default": DOCKER_DEFAULT_WAN_NETWORK,
                "type": "nat-backed-l3-egress",
            },
        },
        "selected_exposure": exposure,
    }

    try:
        private_cidr = parse_private_cidr(private_cidr_raw, DOCKER_PRIVATE_CIDR_ENV)
    except ValueError as exc:
        return {
            "check": {
                "name": "docker_configuration",
                "ok": False,
                "message": str(exc),
            },
            "configuration": configuration,
        }

    private_network = configuration["networks"][EXPOSURE_PRIVATE]
    if isinstance(private_network, dict):
        private_network.update(
            {
                "cidr": str(private_cidr),
                "gateway_ipv4": str(private_gateway_ipv4(private_cidr)),
            }
        )

    return {
        "check": {
            "name": "docker_configuration",
            "ok": True,
            "message": f"configured Docker image {image} for {exposure} exposure",
        },
        "configuration": configuration,
    }


def _capabilities_report(exposure: str) -> dict[str, object]:
    return {
        "exposure": exposure,
        "packet_io": {
            "supported": True,
            "supported_exposures": sorted(SUPPORTED_EXPOSURES),
            "capabilities": list(_WIRE_CAPABILITIES_BY_EXPOSURE[exposure]),
            "semantics": _exposure_semantics(exposure),
        },
        "container": {
            "cap_drop": ["ALL"],
            "cap_add": list(_DOCKER_CAPABILITIES_BY_EXPOSURE[exposure]),
            "no_new_privileges": False,
        },
    }


def _security_model_report(exposure: str) -> dict[str, object]:
    security_model: dict[str, Any] = {
        "docker_socket_mounted": False,
        "privileged": False,
        "host_network": False,
        "host_pid": False,
        "broad_host_filesystem_mounts": False,
        "cap_drop": ["ALL"],
        "cap_add": list(_DOCKER_CAPABILITIES_BY_EXPOSURE[exposure]),
        "no_new_privileges": False,
        "lan_wan_semantics": "NAT-backed L3 only",
    }
    checks = [
        {
            "name": "docker_socket_not_mounted",
            "ok": True,
            "message": "provider endpoint containers do not mount the Docker socket",
        },
        {
            "name": "docker_not_privileged",
            "ok": True,
            "message": "provider endpoint containers do not use privileged mode",
        },
        {
            "name": "docker_no_host_network",
            "ok": True,
            "message": "provider endpoint containers do not use host network mode",
        },
        {
            "name": "docker_constrained_capabilities",
            "ok": True,
            "message": (
                "provider endpoint containers drop all capabilities and add only "
                f"{', '.join(_DOCKER_CAPABILITIES_BY_EXPOSURE[exposure])}"
            ),
        },
    ]
    return {"checks": checks, "security_model": security_model}


def _env_value(env: Mapping[str, str], name: str, default: str) -> str:
    value = (env.get(name) or default).strip()
    return value or default


def _exposure_semantics(exposure: str) -> str:
    if exposure == EXPOSURE_PRIVATE:
        return "isolated provider-owned bridge with same-segment L2/L3 packet exchange"
    if exposure == EXPOSURE_LAN:
        return "NAT-backed L3 reachability from Docker bridge routing to LAN targets"
    return "NAT-backed L3 egress from Docker bridge routing to internet targets"


__all__ = ["doctor"]
