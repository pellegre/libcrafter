"""VirtualBox appliance group helpers."""

from __future__ import annotations

from collections.abc import Iterable

from .constants import VBOXMANAGE_COMMAND, VBOX_DEFAULT_APPLIANCE_GROUP


def normalize_group_path(group_path: str) -> str:
    """Validate and return one normalized absolute VirtualBox group path."""

    if not isinstance(group_path, str):
        raise TypeError("group_path must be a string")
    if not group_path:
        raise ValueError("group_path must not be empty")
    if group_path != group_path.strip():
        raise ValueError("group_path must not contain leading or trailing whitespace")
    if not group_path.startswith("/"):
        raise ValueError("group_path must be absolute")
    segments = group_path[1:].split("/")
    if not segments or any(segment == "" for segment in segments):
        raise ValueError("group_path must not contain empty path segments")
    return "/" + "/".join(segments)


def normalize_group_paths(
    group_paths: str | Iterable[str] = VBOX_DEFAULT_APPLIANCE_GROUP,
) -> tuple[str, ...]:
    """Validate and return group paths in a metadata-friendly stable tuple."""

    if isinstance(group_paths, str):
        return (normalize_group_path(group_paths),)
    normalized = tuple(normalize_group_path(group_path) for group_path in group_paths)
    if not normalized:
        raise ValueError("at least one group_path is required")
    return normalized


def default_group_metadata() -> list[str]:
    """Return the default VirtualBox appliance groups for endpoint metadata."""

    return list(normalize_group_paths(VBOX_DEFAULT_APPLIANCE_GROUP))


def modifyvm_groups_command(
    vm_name: str,
    group_paths: str | Iterable[str] = VBOX_DEFAULT_APPLIANCE_GROUP,
) -> list[str]:
    """Render a VBoxManage command that assigns a VM to the given groups."""

    if not isinstance(vm_name, str) or not vm_name.strip():
        raise ValueError("vm_name must not be empty")
    groups_arg = ",".join(normalize_group_paths(group_paths))
    return [VBOXMANAGE_COMMAND, "modifyvm", vm_name, "--groups", groups_arg]


def parse_showvminfo_groups(stdout: str) -> tuple[str, ...]:
    """Parse groups from VBoxManage showvminfo --machinereadable output."""

    value = _machine_readable_value(stdout, "groups")
    if value is None:
        return ()
    return tuple(group.strip() for group in value.split(",") if group.strip())


def showvminfo_has_group(
    stdout: str,
    group_path: str = VBOX_DEFAULT_APPLIANCE_GROUP,
) -> bool:
    """Return whether showvminfo output already contains the target group."""

    return normalize_group_path(group_path) in parse_showvminfo_groups(stdout)


def _machine_readable_value(stdout: str, desired_key: str) -> str | None:
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == desired_key:
            return _unquote_machine_value(value)
    return None


def _unquote_machine_value(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == '"' and stripped[-1] == '"':
        return stripped[1:-1].replace(r"\"", '"').replace(r"\\", "\\")
    return stripped


__all__ = [
    "default_group_metadata",
    "modifyvm_groups_command",
    "normalize_group_path",
    "normalize_group_paths",
    "parse_showvminfo_groups",
    "showvminfo_has_group",
]
