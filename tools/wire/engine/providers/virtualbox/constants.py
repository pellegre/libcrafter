"""VirtualBox provider constants."""

from __future__ import annotations

from collections.abc import Callable

from ...process import CommandResult


VBOXMANAGE_COMMAND = "VBoxManage"
VBOX_BRIDGE_IFACE_ENV = "LIBCRAFTER_VBOX_BRIDGE_IFACE"
PLANNED_CREATED_AT = "planned"
CONFIRMATION_ERROR = (
    "protected provider execution requires --confirm-live-run; no VirtualBox resources were created"
)
VirtualBoxRunner = Callable[..., CommandResult]

