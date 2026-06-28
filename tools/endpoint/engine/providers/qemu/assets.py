"""QEMU lifecycle helpers for persistent endpoint assets."""

from __future__ import annotations

import errno
import os
import signal
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path

from ...assets import EndpointAsset, asset_state_dir, write_endpoint_asset
from ...config import WireConfig
from ...model import JSONObject, write_json
from ...process import CommandResult, render_argv, run_command
from .constants import QemuRunner


QEMU_ASSET_DIRNAME = "qemu"
QEMU_PIDFILE_NAME = "qemu.pid"
QEMU_COMMAND_LOG_NAME = "qemu-commands.json"

ProcessSignal = Callable[[int, int], None]


def qemu_asset_metadata(
    asset: EndpointAsset,
    *,
    config: WireConfig | None = None,
) -> dict[str, object]:
    """Return validated QEMU metadata for one prepared persistent asset."""

    if not isinstance(asset, EndpointAsset):
        raise TypeError("asset must be an EndpointAsset")
    qemu = asset.metadata.get("qemu")
    if not isinstance(qemu, dict):
        raise ValueError("asset.metadata.qemu is required")
    command = _command(qemu.get("command"))
    pidfile_path = _pidfile_path(asset, qemu.get("pidfile_path"), config=config)
    command = _command_with_pidfile(command, pidfile_path)
    return {
        "command": command,
        "pidfile_path": str(pidfile_path),
        "command_log_path": _command_log_path(asset, qemu.get("command_log_path"), config=config),
        "vm_name": _optional_string(qemu.get("vm_name")),
        "expected_profiles": _string_list(qemu.get("expected_profiles")),
        "usb_passthrough": qemu.get("usb_passthrough"),
        "last_power_state": qemu.get("last_power_state"),
        "last_checked_at": qemu.get("last_checked_at"),
        "pid": qemu.get("pid"),
        "ssh_target": _ssh_target(asset),
    }


def inspect_qemu_asset(
    asset: EndpointAsset,
    *,
    process_signal: ProcessSignal = os.kill,
    config: WireConfig | None = None,
    persist: bool = True,
) -> dict[str, object]:
    """Inspect an existing persistent QEMU VM process without creating resources."""

    metadata = qemu_asset_metadata(asset, config=config)
    pidfile_path = Path(str(metadata["pidfile_path"]))
    checked_at = _utc_now()
    pidfile_status, pid = _read_pidfile(pidfile_path)
    process_running = False
    process_error: str | None = None

    if pid is not None:
        process_running, process_error = _process_exists(pid, process_signal=process_signal)

    vm_state = "running" if process_running else "stopped"
    updated_asset = _asset_with_qemu_state(
        asset,
        last_power_state=vm_state,
        checked_at=checked_at,
        pid=pid,
        pidfile_path=pidfile_path,
        command_log_path=Path(str(metadata["command_log_path"])),
    )
    if persist:
        write_endpoint_asset(updated_asset, config)

    action: dict[str, object] = {
        "action": "inspect",
        "ok": True,
        "executed": True,
        "planned": False,
        "vm_state": vm_state,
        "pidfile_status": pidfile_status,
        "pidfile_path": str(pidfile_path),
        "process_running": process_running,
    }
    if pid is not None:
        action["pid"] = pid
    if process_error is not None:
        action["process_error"] = process_error

    return {
        "kind": "qemu-asset-inspect",
        "asset_id": asset.asset_id,
        "vm_name": metadata["vm_name"],
        "ok": True,
        "executed": True,
        "planned": False,
        "vm_state": vm_state,
        "pid": pid,
        "pidfile_status": pidfile_status,
        "pidfile_path": str(pidfile_path),
        "process_running": process_running,
        "process_error": process_error,
        "last_power_state": _last_power_state(updated_asset),
        "last_checked_at": _last_checked_at(updated_asset),
        "ssh_target": metadata["ssh_target"],
        "actions": [action],
        "commands": [],
        "asset": updated_asset.to_dict(),
    }


def plan_start_qemu_asset(
    asset: EndpointAsset,
    *,
    config: WireConfig | None = None,
) -> dict[str, object]:
    """Return the dry-run plan to start one prepared persistent QEMU asset."""

    metadata = qemu_asset_metadata(asset, config=config)
    command = list(metadata["command"])  # type: ignore[arg-type]
    action = {
        "action": "start",
        "ok": True,
        "executed": False,
        "planned": True,
        "reason": "QEMU asset start is planned",
        "command": render_argv(command),
        "argv": command,
    }
    return {
        "kind": "qemu-asset-start",
        "asset_id": asset.asset_id,
        "vm_name": metadata["vm_name"],
        "ok": True,
        "executed": False,
        "planned": True,
        "check_only": True,
        "pidfile_path": metadata["pidfile_path"],
        "command_log_path": metadata["command_log_path"],
        "ssh_target": metadata["ssh_target"],
        "commands": [action["command"]],
        "actions": [action],
        "asset": asset.to_dict(),
    }


def start_qemu_asset(
    asset: EndpointAsset,
    *,
    command_runner: QemuRunner = run_command,
    process_signal: ProcessSignal = os.kill,
    check_only: bool = False,
    config: WireConfig | None = None,
    persist: bool = True,
) -> dict[str, object]:
    """Start a prepared persistent QEMU asset when its tracked process is not running."""

    if check_only:
        return plan_start_qemu_asset(asset, config=config)

    inspected = inspect_qemu_asset(
        asset,
        process_signal=process_signal,
        config=config,
        persist=persist,
    )
    actions = list(inspected["actions"])  # type: ignore[arg-type]
    updated_asset = EndpointAsset.from_dict(inspected["asset"])  # type: ignore[arg-type]
    metadata = qemu_asset_metadata(updated_asset, config=config)
    command = list(metadata["command"])  # type: ignore[arg-type]
    pidfile_path = Path(str(metadata["pidfile_path"]))
    command_log_path = Path(str(metadata["command_log_path"]))
    executed = False
    ok = True

    if inspected["process_running"]:
        actions.append(
            {
                "action": "start",
                "ok": True,
                "executed": False,
                "planned": False,
                "reason": "VM is already running",
                "pid": inspected["pid"],
            }
        )
    else:
        pidfile_path.parent.mkdir(parents=True, exist_ok=True)
        recorder = _CommandRecorder(command_runner, command_log_path)
        result = recorder(command, timeout=120)
        executed = True
        ok = result.ok
        actions.append(_command_action("start", result))
        if result.ok:
            _, pid = _read_pidfile(pidfile_path)
            checked_at = _utc_now()
            updated_asset = _asset_with_qemu_state(
                updated_asset,
                last_power_state="running",
                checked_at=checked_at,
                pid=pid,
                pidfile_path=pidfile_path,
                command_log_path=command_log_path,
            )
            if persist:
                write_endpoint_asset(updated_asset, config)

    return {
        "kind": "qemu-asset-start",
        "asset_id": asset.asset_id,
        "vm_name": metadata["vm_name"],
        "ok": ok,
        "executed": executed,
        "planned": False,
        "check_only": False,
        "vm_state": "running" if ok and (executed or inspected["process_running"]) else inspected["vm_state"],
        "pid": _last_pid(updated_asset),
        "pidfile_path": str(pidfile_path),
        "command_log_path": str(command_log_path),
        "last_power_state": _last_power_state(updated_asset),
        "last_checked_at": _last_checked_at(updated_asset),
        "ssh_target": metadata["ssh_target"],
        "commands": _action_commands(actions),
        "actions": actions,
        "asset": updated_asset.to_dict(),
    }


def stop_qemu_asset(
    asset: EndpointAsset,
    *,
    explicit: bool = False,
    process_signal: ProcessSignal = os.kill,
    config: WireConfig | None = None,
    persist: bool = True,
) -> dict[str, object]:
    """Stop a tracked persistent QEMU asset process only when explicitly requested."""

    inspected = inspect_qemu_asset(
        asset,
        process_signal=process_signal,
        config=config,
        persist=persist,
    )
    actions = list(inspected["actions"])  # type: ignore[arg-type]
    updated_asset = EndpointAsset.from_dict(inspected["asset"])  # type: ignore[arg-type]
    ok = bool(inspected["ok"])
    executed = False

    if not explicit:
        ok = False
        actions.append(
            {
                "action": "stop",
                "ok": False,
                "executed": False,
                "planned": False,
                "reason": "persistent QEMU stop requires explicit=True",
            }
        )
    elif not inspected["process_running"]:
        actions.append(
            {
                "action": "stop",
                "ok": True,
                "executed": False,
                "planned": False,
                "reason": "VM is already stopped",
            }
        )
    else:
        pid = inspected["pid"]
        if not isinstance(pid, int):
            raise RuntimeError("running QEMU asset did not report a pid")
        process_signal(pid, signal.SIGTERM)
        executed = True
        checked_at = _utc_now()
        updated_asset = _asset_with_qemu_state(
            updated_asset,
            last_power_state="stopped",
            checked_at=checked_at,
            pid=pid,
            pidfile_path=Path(str(inspected["pidfile_path"])),
            command_log_path=_asset_command_log_path(updated_asset, config=config),
        )
        if persist:
            write_endpoint_asset(updated_asset, config)
        actions.append(
            {
                "action": "stop",
                "ok": True,
                "executed": True,
                "planned": False,
                "pid": pid,
                "signal_name": "SIGTERM",
            }
        )

    return {
        "kind": "qemu-asset-stop",
        "asset_id": asset.asset_id,
        "ok": ok,
        "executed": executed,
        "planned": False,
        "explicit": explicit,
        "vm_state": _last_power_state(updated_asset),
        "pid": _last_pid(updated_asset),
        "last_power_state": _last_power_state(updated_asset),
        "last_checked_at": _last_checked_at(updated_asset),
        "actions": actions,
        "commands": [],
        "asset": updated_asset.to_dict(),
    }


class _CommandRecorder:
    def __init__(self, runner: QemuRunner, log_path: Path) -> None:
        self._runner = runner
        self.path = log_path.resolve(strict=False)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[dict[str, object]] = []
        self._write()

    def __call__(self, argv: Sequence[object], **kwargs: object) -> CommandResult:
        result = self._runner(argv, **kwargs)
        self._records.append(_command_result_record(result))
        self._write()
        return result

    def _write(self) -> None:
        write_json(self.path, {"commands": self._records})


def _command(value: object) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("asset.metadata.qemu.command must be a list of strings")
    if not value:
        raise ValueError("asset.metadata.qemu.command must not be empty")
    command: list[str] = []
    for index, part in enumerate(value):
        if not isinstance(part, str) or not part:
            raise ValueError(
                f"asset.metadata.qemu.command[{index}] must be a non-empty string"
            )
        command.append(part)
    return command


def _pidfile_path(
    asset: EndpointAsset,
    value: object,
    *,
    config: WireConfig | None,
) -> Path:
    if value is None:
        return asset_state_dir(asset.asset_id, config) / QEMU_ASSET_DIRNAME / QEMU_PIDFILE_NAME
    if not isinstance(value, str) or not value:
        raise ValueError("asset.metadata.qemu.pidfile_path must be an absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("asset.metadata.qemu.pidfile_path must be an absolute path")
    return path


def _command_log_path(
    asset: EndpointAsset,
    value: object,
    *,
    config: WireConfig | None,
) -> str:
    if value is None:
        return str(
            asset_state_dir(asset.asset_id, config)
            / QEMU_ASSET_DIRNAME
            / QEMU_COMMAND_LOG_NAME
        )
    if not isinstance(value, str) or not value:
        raise ValueError("asset.metadata.qemu.command_log_path must be an absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("asset.metadata.qemu.command_log_path must be an absolute path")
    return str(path)


def _command_with_pidfile(command: list[str], pidfile_path: Path) -> list[str]:
    output = list(command)
    try:
        pidfile_index = output.index("-pidfile")
    except ValueError:
        output.extend(["-pidfile", str(pidfile_path)])
        return output
    value_index = pidfile_index + 1
    if value_index >= len(output):
        raise ValueError("asset.metadata.qemu.command has -pidfile without a path")
    output[value_index] = str(pidfile_path)
    return output


def _read_pidfile(path: Path) -> tuple[str, int | None]:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return "missing", None
    except OSError as exc:
        return f"unreadable: {exc}", None
    if text == "":
        return "invalid", None
    try:
        pid = int(text, 10)
    except ValueError:
        return "invalid", None
    if pid <= 0:
        return "invalid", None
    return "valid", pid


def _process_exists(
    pid: int,
    *,
    process_signal: ProcessSignal,
) -> tuple[bool, str | None]:
    try:
        process_signal(pid, 0)
    except ProcessLookupError:
        return False, None
    except PermissionError:
        return True, "permission denied while checking process"
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False, None
        if exc.errno == errno.EPERM:
            return True, "permission denied while checking process"
        return False, str(exc)
    return True, None


def _asset_with_qemu_state(
    asset: EndpointAsset,
    *,
    last_power_state: str,
    checked_at: str,
    pid: int | None,
    pidfile_path: Path,
    command_log_path: Path,
) -> EndpointAsset:
    metadata: JSONObject = {**asset.metadata}
    existing = metadata.get("qemu")
    qemu: JSONObject = dict(existing) if isinstance(existing, dict) else {}
    qemu["last_power_state"] = last_power_state
    qemu["last_checked_at"] = checked_at
    qemu["pidfile_path"] = str(pidfile_path)
    qemu["command_log_path"] = str(command_log_path)
    if pid is not None:
        qemu["pid"] = pid
    else:
        qemu.pop("pid", None)
    metadata["qemu"] = qemu
    return replace(asset, metadata=metadata)


def _asset_command_log_path(asset: EndpointAsset, *, config: WireConfig | None) -> Path:
    qemu = asset.metadata.get("qemu")
    if isinstance(qemu, dict):
        value = qemu.get("command_log_path")
        if isinstance(value, str) and value:
            return Path(value)
    return asset_state_dir(asset.asset_id, config) / QEMU_ASSET_DIRNAME / QEMU_COMMAND_LOG_NAME


def _command_action(action: str, result: CommandResult) -> dict[str, object]:
    output = {
        "action": action,
        "ok": result.ok,
        "executed": True,
        "planned": False,
        "command": result.command,
        "argv": list(result.redacted_argv),
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    if result.timed_out:
        output["timed_out"] = True
    if result.error is not None:
        output["error"] = result.error
    return output


def _command_result_record(result: CommandResult) -> dict[str, object]:
    return {
        "argv": list(result.redacted_argv),
        "command": result.command,
        "exit_code": result.exit_code,
        "ok": result.ok,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
        "timeout": result.timeout,
        "error": result.error,
    }


def _action_commands(actions: list[object]) -> list[object]:
    commands: list[object] = []
    for action in actions:
        if isinstance(action, dict) and "command" in action:
            commands.append(action["command"])
    return commands


def _last_power_state(asset: EndpointAsset) -> object:
    qemu = asset.metadata.get("qemu")
    if isinstance(qemu, dict):
        return qemu.get("last_power_state")
    return None


def _last_checked_at(asset: EndpointAsset) -> object:
    qemu = asset.metadata.get("qemu")
    if isinstance(qemu, dict):
        return qemu.get("last_checked_at")
    return None


def _last_pid(asset: EndpointAsset) -> object:
    qemu = asset.metadata.get("qemu")
    if isinstance(qemu, dict):
        return qemu.get("pid")
    return None


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and value:
        return value
    raise ValueError("optional QEMU metadata strings must be non-empty strings")


def _string_list(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("asset.metadata.qemu.expected_profiles must be a list of strings")
    output: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            raise ValueError(
                f"asset.metadata.qemu.expected_profiles[{index}] must be a non-empty string"
            )
        output.append(item)
    return output


def _ssh_target(asset: EndpointAsset) -> dict[str, object]:
    target: dict[str, object] = {
        "host": asset.ssh.host,
        "user": asset.ssh.user,
        "port": asset.ssh.port,
    }
    if asset.ssh.identity_file is not None:
        target["identity_file"] = asset.ssh.identity_file
    if asset.ssh.known_hosts_file is not None:
        target["known_hosts_file"] = asset.ssh.known_hosts_file
    return target


def _utc_now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
