"""VirtualBox lifecycle helpers for persistent endpoint assets."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Literal

from ...assets import EndpointAsset, write_endpoint_asset
from ...config import WireConfig
from ...model import JSONObject
from ...process import CommandResult, run_command
from .constants import VBOXMANAGE_COMMAND, VirtualBoxRunner


_STARTABLE_VM_STATES = frozenset({"poweroff", "saved", "aborted", "teleported"})
_RUNNING_VM_STATES = frozenset({"running"})
_STOP_ACTIONS = frozenset({"savestate", "poweroff"})


def virtualbox_asset_vm_name(asset: EndpointAsset) -> str:
    """Return the configured VirtualBox VM name for one persistent asset."""

    if not isinstance(asset, EndpointAsset):
        raise TypeError("asset must be an EndpointAsset")
    virtualbox = asset.metadata.get("virtualbox")
    if not isinstance(virtualbox, dict):
        raise ValueError("asset.metadata.virtualbox is required")
    vm_name = virtualbox.get("vm_name")
    if not isinstance(vm_name, str) or not vm_name.strip():
        raise ValueError("asset.metadata.virtualbox.vm_name is required")
    return vm_name


def inspect_virtualbox_asset(
    asset: EndpointAsset,
    *,
    command_runner: VirtualBoxRunner = run_command,
    config: WireConfig | None = None,
    persist: bool = True,
) -> dict[str, object]:
    """Inspect an existing persistent VirtualBox VM without creating or deleting it."""

    vm_name = virtualbox_asset_vm_name(asset)
    inspected_at = _utc_now()
    command = [VBOXMANAGE_COMMAND, "showvminfo", vm_name, "--machinereadable"]
    result = command_runner(command, timeout=60)
    missing = _is_missing_vm_result(result)
    vm_info = _parse_machine_readable(result.stdout) if result.ok else {}
    vm_state = _vm_state(vm_info)
    updated_asset = (
        _asset_with_virtualbox_power_state(
            asset,
            vm_state,
            checked_at=inspected_at,
            missing=missing,
        )
        if result.ok or missing
        else asset
    )
    if persist and updated_asset is not asset:
        write_endpoint_asset(updated_asset, config)

    return {
        "kind": "virtualbox-asset-inspect",
        "asset_id": asset.asset_id,
        "vm_name": vm_name,
        "ok": result.ok,
        "executed": True,
        "commands": [_command_action("showvminfo", command, result)],
        "actions": [_command_action("showvminfo", command, result, vm_state=vm_state)],
        "missing": missing,
        "vm_state": vm_state,
        "last_power_state": _last_power_state(updated_asset),
        "last_checked_at": _last_checked_at(updated_asset),
        "vm_info": vm_info,
        "asset": updated_asset.to_dict(),
    }


def start_virtualbox_asset(
    asset: EndpointAsset,
    *,
    command_runner: VirtualBoxRunner = run_command,
    check_only: bool = False,
    config: WireConfig | None = None,
    persist: bool = True,
) -> dict[str, object]:
    """Start a persistent VirtualBox asset VM headlessly when it is not running."""

    vm_name = virtualbox_asset_vm_name(asset)
    inspected = inspect_virtualbox_asset(
        asset,
        command_runner=command_runner,
        config=config,
        persist=persist,
    )
    actions = list(inspected["actions"])  # type: ignore[arg-type]
    updated_asset = EndpointAsset.from_dict(inspected["asset"])  # type: ignore[arg-type]
    vm_state = inspected["vm_state"]
    ok = bool(inspected["ok"])
    executed = False
    planned = False

    if not ok:
        reason = "VirtualBox VM is missing" if inspected["missing"] else "showvminfo failed"
        actions.append(
            {
                "action": "start",
                "ok": False,
                "executed": False,
                "planned": False,
                "reason": reason,
            }
        )
    elif vm_state in _RUNNING_VM_STATES:
        actions.append(
            {
                "action": "start",
                "ok": True,
                "executed": False,
                "planned": False,
                "reason": "VM is already running",
            }
        )
    elif check_only:
        ok = vm_state in _STARTABLE_VM_STATES
        planned = ok
        actions.append(
            {
                "action": "start",
                "ok": ok,
                "executed": False,
                "planned": planned,
                "reason": (
                    "VM can be started headlessly"
                    if ok
                    else f"VMState {vm_state or 'unknown'} is not startable"
                ),
                "command": _render_command(
                    [VBOXMANAGE_COMMAND, "startvm", vm_name, "--type", "headless"]
                ),
            }
        )
    elif vm_state in _STARTABLE_VM_STATES:
        start_command = [VBOXMANAGE_COMMAND, "startvm", vm_name, "--type", "headless"]
        start_result = command_runner(start_command, timeout=120)
        executed = True
        ok = start_result.ok
        actions.append(_command_action("start", start_command, start_result))
        if start_result.ok:
            checked_at = _utc_now()
            updated_asset = _asset_with_virtualbox_power_state(
                updated_asset,
                "running",
                checked_at=checked_at,
                missing=False,
            )
            if persist:
                write_endpoint_asset(updated_asset, config)
    else:
        ok = False
        actions.append(
            {
                "action": "start",
                "ok": False,
                "executed": False,
                "planned": False,
                "reason": f"VMState {vm_state or 'unknown'} is not startable",
            }
        )

    return {
        "kind": "virtualbox-asset-start",
        "asset_id": asset.asset_id,
        "vm_name": vm_name,
        "ok": ok,
        "executed": executed,
        "planned": planned,
        "check_only": check_only,
        "vm_state": vm_state,
        "last_power_state": _last_power_state(updated_asset),
        "last_checked_at": _last_checked_at(updated_asset),
        "commands": _action_commands(actions),
        "actions": actions,
        "asset": updated_asset.to_dict(),
    }


def stop_virtualbox_asset(
    asset: EndpointAsset,
    *,
    action: Literal["savestate", "poweroff"] = "savestate",
    explicit: bool = False,
    check_only: bool = False,
    command_runner: VirtualBoxRunner = run_command,
    config: WireConfig | None = None,
    persist: bool = True,
) -> dict[str, object]:
    """Stop a persistent VirtualBox asset only when explicitly requested."""

    if action not in _STOP_ACTIONS:
        raise ValueError("action must be 'savestate' or 'poweroff'")
    vm_name = virtualbox_asset_vm_name(asset)
    inspected = inspect_virtualbox_asset(
        asset,
        command_runner=command_runner,
        config=config,
        persist=persist,
    )
    actions = list(inspected["actions"])  # type: ignore[arg-type]
    updated_asset = EndpointAsset.from_dict(inspected["asset"])  # type: ignore[arg-type]
    vm_state = inspected["vm_state"]
    ok = bool(inspected["ok"])
    executed = False
    planned = False

    if not ok:
        reason = "VirtualBox VM is missing" if inspected["missing"] else "showvminfo failed"
        actions.append(
            {
                "action": action,
                "ok": False,
                "executed": False,
                "planned": False,
                "reason": reason,
            }
        )
    elif not explicit:
        ok = False
        actions.append(
            {
                "action": action,
                "ok": False,
                "executed": False,
                "planned": False,
                "reason": "persistent VM stop requires explicit=True",
            }
        )
    elif vm_state not in _RUNNING_VM_STATES:
        actions.append(
            {
                "action": action,
                "ok": True,
                "executed": False,
                "planned": False,
                "reason": f"VM is already {vm_state or 'not running'}",
            }
        )
    elif check_only:
        planned = True
        actions.append(
            {
                "action": action,
                "ok": True,
                "executed": False,
                "planned": True,
                "command": _render_command([VBOXMANAGE_COMMAND, "controlvm", vm_name, action]),
            }
        )
    else:
        stop_command = [VBOXMANAGE_COMMAND, "controlvm", vm_name, action]
        stop_result = command_runner(stop_command, timeout=60)
        ok = stop_result.ok
        executed = True
        actions.append(_command_action(action, stop_command, stop_result))
        if stop_result.ok:
            checked_at = _utc_now()
            updated_asset = _asset_with_virtualbox_power_state(
                updated_asset,
                "saved" if action == "savestate" else "poweroff",
                checked_at=checked_at,
                missing=False,
            )
            if persist:
                write_endpoint_asset(updated_asset, config)

    return {
        "kind": "virtualbox-asset-stop",
        "asset_id": asset.asset_id,
        "vm_name": vm_name,
        "ok": ok,
        "executed": executed,
        "planned": planned,
        "check_only": check_only,
        "explicit": explicit,
        "stop_action": action,
        "vm_state": vm_state,
        "last_power_state": _last_power_state(updated_asset),
        "last_checked_at": _last_checked_at(updated_asset),
        "commands": _action_commands(actions),
        "actions": actions,
        "asset": updated_asset.to_dict(),
    }


def _asset_with_virtualbox_power_state(
    asset: EndpointAsset,
    vm_state: object,
    *,
    checked_at: str,
    missing: bool,
) -> EndpointAsset:
    metadata: JSONObject = {**asset.metadata}
    existing = metadata.get("virtualbox")
    virtualbox: JSONObject = dict(existing) if isinstance(existing, dict) else {}
    if vm_state is not None:
        virtualbox["last_power_state"] = str(vm_state)
    elif missing:
        virtualbox["last_power_state"] = "missing"
    virtualbox["last_checked_at"] = checked_at
    metadata["virtualbox"] = virtualbox
    return replace(asset, metadata=metadata)


def _parse_machine_readable(stdout: str) -> JSONObject:
    parsed: JSONObject = {}
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key] = _unquote_machine_value(value)
    return parsed


def _unquote_machine_value(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == '"' and stripped[-1] == '"':
        return stripped[1:-1].replace(r"\"", '"').replace(r"\\", "\\")
    return stripped


def _vm_state(info: JSONObject) -> str | None:
    value = info.get("VMState")
    if isinstance(value, str) and value:
        return value
    return None


def _is_missing_vm_result(result: CommandResult) -> bool:
    haystack = f"{result.stdout}\n{result.stderr}\n{result.error or ''}".lower()
    return (
        "could not find a registered machine named" in haystack
        or "could not find a registered machine with uuid" in haystack
        or "vbox_e_object_not_found" in haystack
    )


def _command_action(
    action: str,
    argv: list[str],
    result: CommandResult,
    *,
    vm_state: str | None = None,
) -> dict[str, object]:
    output = {
        "action": action,
        "ok": result.ok,
        "executed": True,
        "planned": False,
        "command": _render_command(argv),
        "argv": list(result.redacted_argv),
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    if result.timed_out:
        output["timed_out"] = True
    if result.error is not None:
        output["error"] = result.error
    if vm_state is not None:
        output["vm_state"] = vm_state
    return output


def _render_command(argv: list[str]) -> str:
    return " ".join(argv)


def _last_power_state(asset: EndpointAsset) -> object:
    virtualbox = asset.metadata.get("virtualbox")
    if isinstance(virtualbox, dict):
        return virtualbox.get("last_power_state")
    return None


def _last_checked_at(asset: EndpointAsset) -> object:
    virtualbox = asset.metadata.get("virtualbox")
    if isinstance(virtualbox, dict):
        return virtualbox.get("last_checked_at")
    return None


def _action_commands(actions: list[object]) -> list[object]:
    commands: list[object] = []
    for action in actions:
        if isinstance(action, dict) and "command" in action:
            commands.append(action["command"])
    return commands


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
