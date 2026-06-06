"""Hetzner provider constants."""

from __future__ import annotations

from collections.abc import Callable

from ...process import CommandResult
from ..vm.discovery import LINUX_INTERFACE_DISCOVERY_COMMAND

TOKEN_ENV = "HETZNER_API_TOKEN"
HCLOUD_TOKEN_ENV = "HCLOUD_TOKEN"
HCLOUD_COMMAND = "hcloud"
PLANNED_CREATED_AT = "planned"
CONFIRMATION_ERROR = (
    "protected provider execution requires --confirm-live-run; no Hetzner resources were created"
)
# cx22 was retired by Hetzner; cx23 is the current-generation 2 vCPU / 4 GB
# x86 shared instance. Overridable via HETZNER_SERVER_TYPE.
DEFAULT_SERVER_TYPE = "cx23"
DEFAULT_IMAGE = "ubuntu-24.04"
DEFAULT_LOCATION = "hel1"
DEFAULT_PRIVATE_NETWORK_ZONE = "eu-central"
DEFAULT_SERVER_RUNNING_TIMEOUT = 300
DEFAULT_SERVER_RUNNING_INTERVAL = 5
INTERFACE_DISCOVERY_COMMAND = LINUX_INTERFACE_DISCOVERY_COMMAND
HcloudRunner = Callable[..., CommandResult]
