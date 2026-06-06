"""Hetzner server readiness and interface discovery."""

from __future__ import annotations

import time
from collections.abc import Mapping
from pathlib import Path

from ...model import NetworkInterface
from ...process import run_command
from ..vm.discovery import discover_linux_endpoint_interfaces, parse_linux_interface_discovery
from .constants import (
    DEFAULT_SERVER_RUNNING_INTERVAL,
    DEFAULT_SERVER_RUNNING_TIMEOUT,
    HCLOUD_COMMAND,
    INTERFACE_DISCOVERY_COMMAND,
    HcloudRunner,
)
from .hcloud import _hcloud_json
from .utils import (
    _json_object,
    _positive_float,
)



def wait_for_server_running(
    *,
    server_id: str,
    env: Mapping[str, str],
    timeout: float = DEFAULT_SERVER_RUNNING_TIMEOUT,
    interval: float = DEFAULT_SERVER_RUNNING_INTERVAL,
    command_runner: HcloudRunner = run_command,
) -> dict[str, object]:
    """Wait for a Hetzner server to report the running state."""

    deadline = time.monotonic() + _positive_float(timeout, "timeout")
    sleep_interval = _positive_float(interval, "interval")
    last_status = "unknown"

    while True:
        server = _hcloud_json(
            [HCLOUD_COMMAND, "server", "describe", server_id, "-o", "json"],
            env=env,
            command_runner=command_runner,
        )
        server_object = _json_object(server.get("server", server), "server")
        status = server_object.get("status")
        if isinstance(status, str) and status:
            last_status = status
        if last_status == "running":
            return server_object

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(
                f"server running wait timed out for Hetzner server {server_id}: "
                f"last status={last_status}"
            )
        time.sleep(min(sleep_interval, remaining))


def discover_endpoint_interfaces(
    *,
    host: str,
    user: str,
    identity_file: str | Path,
    known_hosts: str | Path,
    exposure: str,
    public_ipv4: str | None = None,
    public_ipv6: str | None = None,
    prefer_public_or_default: bool = True,
) -> list[NetworkInterface]:
    """Discover endpoint interfaces with Linux ip commands over SSH."""

    return discover_linux_endpoint_interfaces(
        host=host,
        user=user,
        identity_file=identity_file,
        known_hosts=known_hosts,
        exposure=exposure,
        public_ipv4=public_ipv4,
        public_ipv6=public_ipv6,
        command=INTERFACE_DISCOVERY_COMMAND,
        metadata=_hcloud_public_metadata(public_ipv4=public_ipv4, public_ipv6=public_ipv6),
        prefer_public_or_default=prefer_public_or_default,
    )


def parse_ip_interface_discovery(
    output: str,
    *,
    exposure: str,
    public_ipv4: str | None = None,
    public_ipv6: str | None = None,
) -> list[NetworkInterface]:
    """Parse JSON emitted by the endpoint interface discovery command."""

    return parse_linux_interface_discovery(
        output,
        exposure=exposure,
        public_ipv4=public_ipv4,
        public_ipv6=public_ipv6,
        metadata=_hcloud_public_metadata(public_ipv4=public_ipv4, public_ipv6=public_ipv6),
    )


def _hcloud_public_metadata(
    *,
    public_ipv4: str | None,
    public_ipv6: str | None,
) -> dict[str, object]:
    return {
        "hcloud_public_ipv4": public_ipv4,
        "hcloud_public_ipv6": public_ipv6,
    }
