"""Docker provider constants."""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from ...process import CommandResult


PROVIDER_NAME: Final = "docker"
EXPOSURE_PRIVATE: Final = "private"
EXPOSURE_LAN: Final = "lan"
EXPOSURE_WAN: Final = "wan"
SUPPORTED_EXPOSURES: Final = frozenset(
    {
        EXPOSURE_PRIVATE,
        EXPOSURE_LAN,
        EXPOSURE_WAN,
    }
)

DOCKER_COMMAND_ENV: Final = "LIBCRAFTER_DOCKER_COMMAND"
DOCKER_IMAGE_ENV: Final = "LIBCRAFTER_DOCKER_IMAGE"
DOCKER_REBUILD_ENV: Final = "LIBCRAFTER_DOCKER_REBUILD"
DOCKER_PRIVATE_CIDR_ENV: Final = "LIBCRAFTER_DOCKER_PRIVATE_CIDR"
DOCKER_LAN_NETWORK_ENV: Final = "LIBCRAFTER_DOCKER_LAN_NETWORK"
DOCKER_WAN_NETWORK_ENV: Final = "LIBCRAFTER_DOCKER_WAN_NETWORK"

DOCKER_COMMAND: Final = "docker"
DOCKER_DEFAULT_IMAGE: Final = "libcrafter-wire-endpoint:local"
DOCKER_DEFAULT_PRIVATE_CIDR: Final = "10.79.0.0/24"
DOCKER_DEFAULT_LAN_NETWORK: Final = "bridge"
DOCKER_DEFAULT_WAN_NETWORK: Final = "bridge"

DOCKER_SSH_HOST: Final = "127.0.0.1"
DOCKER_SSH_USER: Final = "root"
DOCKER_SSH_GUEST_PORT: Final = 22
PLANNED_CREATED_AT: Final = "planned"

CONFIRMATION_ERROR: Final = (
    "protected provider execution requires --confirm-live-run; no Docker resources were created"
)

PRIVATE_CAPABILITIES: Final = (
    "ipv4_unicast",
    "link_layer_send",
    "link_layer_capture",
    "broadcast",
    "provider_mac_known",
    "controlled_services",
)

NAT_L3_CAPABILITIES: Final = (
    "ipv4_unicast",
)

DockerRunner = Callable[..., CommandResult]
