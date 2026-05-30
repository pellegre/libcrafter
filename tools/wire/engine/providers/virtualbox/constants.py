"""VirtualBox provider constants."""

from __future__ import annotations

from collections.abc import Callable

from ...process import CommandResult


VBOXMANAGE_COMMAND = "VBoxManage"
VBOX_BRIDGE_IFACE_ENV = "LIBCRAFTER_VBOX_BRIDGE_IFACE"
VBOX_PRIVATE_CIDR_ENV = "LIBCRAFTER_VBOX_PRIVATE_CIDR"
VBOX_DEFAULT_PRIVATE_CIDR = "10.78.0.0/24"
PLANNED_CREATED_AT = "planned"
CONFIRMATION_ERROR = (
    "protected provider execution requires --confirm-live-run; no VirtualBox resources were created"
)
VirtualBoxRunner = Callable[..., CommandResult]
