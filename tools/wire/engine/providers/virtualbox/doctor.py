"""VirtualBox provider prerequisite checks."""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping

from ...registry import validate_request
from ..vm import CLOUD_LOCALDS_COMMAND, QEMU_IMG_COMMAND
from .bridge import discover_bridge_interfaces, requested_bridge_interface, select_bridge_interface
from .constants import VBOXMANAGE_COMMAND, VBOX_BRIDGE_IFACE_ENV, VirtualBoxRunner


_REQUIRED_COMMANDS = (
    VBOXMANAGE_COMMAND,
    QEMU_IMG_COMMAND,
    CLOUD_LOCALDS_COMMAND,
    "ssh",
    "scp",
    "ssh-keygen",
)


def doctor(
    *,
    provider: str,
    exposure: str,
    dry_run: bool = False,
    env: Mapping[str, str] | None = None,
    command_runner: VirtualBoxRunner | None = None,
) -> dict[str, object]:
    """Return non-mutating VirtualBox provider prerequisite checks."""

    validate_request(provider, exposure)

    environ = os.environ if env is None else env
    command_paths = {command: shutil.which(command) for command in _REQUIRED_COMMANDS}
    checks: list[dict[str, object]] = [
        {
            "name": "provider_exposure",
            "ok": True,
            "message": f"{provider}/{exposure} is supported",
        }
    ]
    checks.extend(_command_checks(command_paths))

    bridge_report = _bridge_report(
        command_paths[VBOXMANAGE_COMMAND],
        env=environ,
        command_runner=command_runner,
    )
    checks.append(bridge_report["check"])

    return {
        "provider": provider,
        "exposure": exposure,
        "dry_run": dry_run,
        "ok": all(bool(check["ok"]) for check in checks),
        "checks": checks,
        "commands": {
            command: {"installed": path is not None, "path": path}
            for command, path in command_paths.items()
        },
        "bridge": bridge_report["bridge"],
    }


def _command_checks(command_paths: Mapping[str, str | None]) -> list[dict[str, object]]:
    return [
        {
            "name": f"{command}_installed",
            "ok": path is not None,
            "message": (
                f"{command} found at {path}" if path is not None else f"{command} was not found on PATH"
            ),
        }
        for command, path in command_paths.items()
    ]


def _bridge_report(
    vboxmanage_path: str | None,
    *,
    env: Mapping[str, str],
    command_runner: VirtualBoxRunner | None,
) -> dict[str, object]:
    try:
        requested = requested_bridge_interface(env)
    except ValueError as exc:
        return {
            "check": {
                "name": "bridge_discovery",
                "ok": False,
                "message": str(exc),
            },
            "bridge": {
                "env": VBOX_BRIDGE_IFACE_ENV,
                "requested_name": None,
                "selected_name": None,
                "interfaces": [],
                "discovered": False,
            },
        }
    bridge: dict[str, object] = {
        "env": VBOX_BRIDGE_IFACE_ENV,
        "requested_name": requested,
        "selected_name": None,
        "interfaces": [],
        "discovered": False,
    }
    if vboxmanage_path is None:
        return {
            "check": {
                "name": "bridge_discovery",
                "ok": False,
                "message": f"{VBOXMANAGE_COMMAND} is required to discover bridged interfaces",
            },
            "bridge": bridge,
        }
    if command_runner is None:
        from ...process import run_command

        command_runner = run_command

    try:
        interfaces = discover_bridge_interfaces(command_runner=command_runner)
    except RuntimeError as exc:
        return {
            "check": {
                "name": "bridge_discovery",
                "ok": False,
                "message": str(exc),
            },
            "bridge": bridge,
        }

    selected = select_bridge_interface(interfaces, env=env)
    bridge["interfaces"] = interfaces
    bridge["discovered"] = True
    if selected is not None:
        bridge["selected_name"] = selected.get("name")
    if requested is not None and selected is None:
        return {
            "check": {
                "name": "bridge_discovery",
                "ok": False,
                "message": (
                    f"{VBOX_BRIDGE_IFACE_ENV}={requested!r} was not found in "
                    "VBoxManage bridged interfaces"
                ),
            },
            "bridge": bridge,
        }

    return {
        "check": {
            "name": "bridge_discovery",
            "ok": selected is not None,
            "message": (
                f"selected bridge interface {selected.get('name')}"
                if selected is not None
                else "no VirtualBox bridged interfaces were discovered"
            ),
        },
        "bridge": bridge,
    }
