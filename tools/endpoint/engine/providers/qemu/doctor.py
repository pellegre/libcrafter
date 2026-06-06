"""QEMU provider prerequisite checks."""

from __future__ import annotations

import os
import platform
import shutil
from collections.abc import Mapping
from pathlib import Path

from ...process import run_command
from ...registry import validate_request
from ..vm import CLOUD_LOCALDS_COMMAND, QEMU_IMG_COMMAND
from .constants import (
    QEMU_ACCEL_ENV,
    QEMU_DEFAULT_ACCEL,
    QEMU_SYSTEM_COMMAND,
    SUPPORTED_QEMU_ACCELS,
    QemuRunner,
)


_REQUIRED_COMMANDS = (
    QEMU_SYSTEM_COMMAND,
    QEMU_IMG_COMMAND,
    CLOUD_LOCALDS_COMMAND,
    "ssh",
    "scp",
    "ssh-keygen",
)
_VBOXMANAGE_COMMAND = "VBoxManage"


def doctor(
    *,
    provider: str,
    exposure: str,
    dry_run: bool = False,
    env: Mapping[str, str] | None = None,
    command_runner: QemuRunner | None = None,
) -> dict[str, object]:
    """Return non-mutating QEMU provider prerequisite checks."""

    validate_request(provider, exposure)

    environ = os.environ if env is None else env
    command_paths = {command: shutil.which(command) for command in _REQUIRED_COMMANDS}
    vboxmanage_path = shutil.which(_VBOXMANAGE_COMMAND)
    acceleration = _acceleration_report(
        _requested_acceleration(environ),
        vboxmanage_path=vboxmanage_path,
        command_runner=command_runner,
    )
    checks: list[dict[str, object]] = [
        {
            "name": "provider_exposure",
            "ok": True,
            "message": f"{provider}/{exposure} is supported",
        }
    ]
    checks.extend(_command_checks(command_paths))
    checks.extend(acceleration["checks"])

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
        "optional_commands": {
            _VBOXMANAGE_COMMAND: {
                "installed": vboxmanage_path is not None,
                "path": vboxmanage_path,
            }
        },
        "acceleration": acceleration["metadata"],
    }


def _requested_acceleration(env: Mapping[str, str]) -> str:
    return (env.get(QEMU_ACCEL_ENV) or QEMU_DEFAULT_ACCEL).strip().lower() or QEMU_DEFAULT_ACCEL


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


def _acceleration_report(
    acceleration: str,
    *,
    vboxmanage_path: str | None,
    command_runner: QemuRunner | None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "env": QEMU_ACCEL_ENV,
        "requested": acceleration,
        "default": QEMU_DEFAULT_ACCEL,
        "supported": sorted(SUPPORTED_QEMU_ACCELS),
    }
    if acceleration not in SUPPORTED_QEMU_ACCELS:
        return {
            "checks": [
                {
                    "name": "qemu_acceleration",
                    "ok": False,
                    "message": (
                        f"{QEMU_ACCEL_ENV}={acceleration!r} is unsupported; "
                        f"supported values: {', '.join(sorted(SUPPORTED_QEMU_ACCELS))}"
                    ),
                }
            ],
            "metadata": {**metadata, "effective": None},
        }

    if acceleration == "tcg":
        return {
            "checks": [
                {
                    "name": "qemu_acceleration",
                    "ok": True,
                    "message": "using QEMU TCG acceleration",
                }
            ],
            "metadata": {
                **metadata,
                "effective": "tcg",
                "kvm": {"required": False, "checked": False},
                "virtualbox": {"checked": False},
            },
        }

    kvm = _kvm_device_report(Path("/dev/kvm"))
    virtualbox = _virtualbox_running_report(
        vboxmanage_path=vboxmanage_path,
        command_runner=command_runner,
    )
    return {
        "checks": [
            {
                "name": "qemu_acceleration",
                "ok": True,
                "message": "using QEMU KVM acceleration",
            },
            kvm["check"],
            virtualbox["check"],
        ],
        "metadata": {
            **metadata,
            "effective": "kvm",
            "kvm": kvm["metadata"],
            "virtualbox": virtualbox["metadata"],
        },
    }


def _kvm_device_report(path: Path) -> dict[str, object]:
    system = platform.system()
    metadata: dict[str, object] = {
        "required": True,
        "checked": True,
        "host_os": system,
        "path": str(path),
        "exists": False,
        "readable_writable": False,
    }
    if system != "Linux":
        return {
            "check": {
                "name": "kvm_device_access",
                "ok": False,
                "message": "KVM acceleration requires a Linux host with /dev/kvm",
            },
            "metadata": metadata,
        }
    exists = path.exists()
    readable_writable = exists and os.access(path, os.R_OK | os.W_OK)
    metadata.update({"exists": exists, "readable_writable": readable_writable})
    return {
        "check": {
            "name": "kvm_device_access",
            "ok": readable_writable,
            "message": (
                f"{path} is accessible" if readable_writable else f"{path} is not readable/writable"
            ),
        },
        "metadata": metadata,
    }


def _virtualbox_running_report(
    *,
    vboxmanage_path: str | None,
    command_runner: QemuRunner | None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "checked": True,
        "command": _VBOXMANAGE_COMMAND,
        "installed": vboxmanage_path is not None,
        "path": vboxmanage_path,
        "running_vms": [],
    }
    if vboxmanage_path is None:
        return {
            "check": {
                "name": "virtualbox_running_vms",
                "ok": True,
                "message": f"{_VBOXMANAGE_COMMAND} not found; skipped running VM check",
            },
            "metadata": metadata,
        }

    runner = run_command if command_runner is None else command_runner
    result = runner([_VBOXMANAGE_COMMAND, "list", "runningvms"], timeout=30)
    metadata["exit_code"] = result.exit_code
    if not result.ok:
        metadata["error"] = result.stderr.strip() or result.error or "command failed"
        return {
            "check": {
                "name": "virtualbox_running_vms",
                "ok": False,
                "message": f"could not inspect running VirtualBox VMs: {metadata['error']}",
            },
            "metadata": metadata,
        }

    running_vms = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    metadata["running_vms"] = running_vms
    return {
        "check": {
            "name": "virtualbox_running_vms",
            "ok": not running_vms,
            "message": (
                "no running VirtualBox VMs were reported"
                if not running_vms
                else "running VirtualBox VMs may conflict with KVM acceleration"
            ),
        },
        "metadata": metadata,
    }

