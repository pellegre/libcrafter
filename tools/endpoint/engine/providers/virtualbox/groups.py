"""VirtualBox appliance group helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from ...assets import EndpointAsset, list_endpoint_assets
from ...config import WireConfig
from ...model import EndpointManifest, ProviderResource
from ...process import CommandResult, render_argv, run_command
from ...state import list_endpoint_manifests
from .constants import VBOXMANAGE_COMMAND, VBOX_DEFAULT_APPLIANCE_GROUP
from .constants import VirtualBoxRunner


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


def normalize_tracked_vm_groups(
    *,
    dry_run: bool = False,
    confirm_live_run: bool = False,
    command_runner: VirtualBoxRunner = run_command,
    config: WireConfig | None = None,
    group_path: str = VBOX_DEFAULT_APPLIANCE_GROUP,
) -> dict[str, object]:
    """Normalize tracked VirtualBox endpoint and asset VMs into the target group."""

    if dry_run and confirm_live_run:
        raise ValueError("use either --dry-run or --confirm-live-run, not both")
    if not dry_run and not confirm_live_run:
        raise PermissionError(
            "protected VirtualBox group normalization requires --dry-run or "
            "--confirm-live-run"
        )

    target_groups = normalize_group_paths(group_path)
    candidates = collect_tracked_vm_group_candidates(config=config)
    results = [
        _normalize_tracked_vm_group_candidate(
            candidate,
            target_groups=target_groups,
            dry_run=dry_run,
            command_runner=command_runner,
        )
        for candidate in candidates
    ]
    failed = [result for result in results if result.get("ok") is False]
    return {
        "kind": "virtualbox-normalize-groups",
        "ok": not failed,
        "dry_run": dry_run,
        "confirmed": confirm_live_run,
        "target_group": target_groups[0],
        "target_groups": list(target_groups),
        "candidate_count": len(candidates),
        "planned_count": _count_status(results, "planned"),
        "changed_count": _count_status(results, "updated"),
        "already_grouped_count": _count_status(results, "already-grouped"),
        "missing_count": _count_status(results, "missing"),
        "failed_count": len(failed),
        "candidates": results,
    }


def collect_tracked_vm_group_candidates(
    *,
    config: WireConfig | None = None,
) -> list[dict[str, object]]:
    """Collect tracked VirtualBox VM names from endpoint manifests and assets."""

    by_vm_name: dict[str, dict[str, object]] = {}
    for manifest in list_endpoint_manifests(config):
        for vm_name, source in _manifest_vm_sources(manifest):
            _append_candidate_source(by_vm_name, vm_name, source)
    for asset in list_endpoint_assets(config):
        source = _asset_vm_source(asset)
        if source is None:
            continue
        vm_name = source["vm_name"]
        if isinstance(vm_name, str):
            _append_candidate_source(by_vm_name, vm_name, source)
    return [by_vm_name[vm_name] for vm_name in sorted(by_vm_name)]


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


def _manifest_vm_sources(
    manifest: EndpointManifest,
) -> list[tuple[str, dict[str, object]]]:
    if manifest.provider != "virtualbox" or manifest.status == "destroyed":
        return []
    sources: list[tuple[str, dict[str, object]]] = []
    metadata_vm_name = _metadata_virtualbox_vm_name(manifest.metadata)
    if metadata_vm_name is not None:
        sources.append(
            (
                metadata_vm_name,
                {
                    "kind": "endpoint-manifest",
                    "endpoint_id": manifest.endpoint_id,
                    "status": manifest.status,
                    "vm_name": metadata_vm_name,
                    "field": "metadata.virtualbox.vm_name",
                },
            )
        )
    for resource in manifest.provider_resources.resources:
        vm_name = _resource_vm_name(resource)
        if vm_name is None:
            continue
        sources.append(
            (
                vm_name,
                {
                    "kind": "endpoint-manifest",
                    "endpoint_id": manifest.endpoint_id,
                    "status": manifest.status,
                    "vm_name": vm_name,
                    "field": "provider_resources.virtualbox-vm",
                    "provider_resource": {
                        "kind": resource.kind,
                        "provider_id": resource.provider_id,
                        "name": resource.name,
                    },
                },
            )
        )
    return sources


def _asset_vm_source(asset: EndpointAsset) -> dict[str, object] | None:
    if asset.substrate != "virtualbox":
        return None
    vm_name = _metadata_virtualbox_vm_name(asset.metadata)
    if vm_name is None:
        return None
    return {
        "kind": "endpoint-asset",
        "asset_id": asset.asset_id,
        "status": asset.status,
        "substrate": asset.substrate,
        "vm_name": vm_name,
        "field": "metadata.virtualbox.vm_name",
    }


def _append_candidate_source(
    candidates: dict[str, dict[str, object]],
    vm_name: str,
    source: dict[str, object],
) -> None:
    candidate = candidates.setdefault(vm_name, {"vm_name": vm_name, "sources": []})
    sources = candidate["sources"]
    if not isinstance(sources, list):
        raise TypeError("candidate sources must be a list")
    if source not in sources:
        sources.append(source)


def _metadata_virtualbox_vm_name(metadata: Mapping[str, object]) -> str | None:
    virtualbox = metadata.get("virtualbox")
    if not isinstance(virtualbox, Mapping):
        return None
    vm_name = virtualbox.get("vm_name")
    if isinstance(vm_name, str) and vm_name.strip():
        return vm_name
    return None


def _resource_vm_name(resource: ProviderResource) -> str | None:
    if resource.kind != "virtualbox-vm":
        return None
    metadata_vm_name = resource.metadata.get("vm_name")
    if isinstance(metadata_vm_name, str) and metadata_vm_name.strip():
        return metadata_vm_name
    if isinstance(resource.name, str) and resource.name.strip():
        return resource.name
    if resource.provider_id.strip():
        return resource.provider_id
    return None


def _normalize_tracked_vm_group_candidate(
    candidate: Mapping[str, object],
    *,
    target_groups: Sequence[str],
    dry_run: bool,
    command_runner: VirtualBoxRunner,
) -> dict[str, object]:
    vm_name = candidate.get("vm_name")
    if not isinstance(vm_name, str) or not vm_name.strip():
        return {
            "vm_name": vm_name,
            "ok": False,
            "status": "failed",
            "reason": "candidate is missing vm_name",
        }
    sources = candidate.get("sources")
    if not isinstance(sources, list):
        sources = []
    show_command = [VBOXMANAGE_COMMAND, "showvminfo", vm_name, "--machinereadable"]
    show_result = command_runner(show_command, timeout=60)
    commands: list[str] = [render_argv(show_result.redacted_argv)]
    output: dict[str, object] = {
        "vm_name": vm_name,
        "sources": sources,
        "target_groups": list(target_groups),
        "ok": show_result.ok,
        "status": "inspected",
        "planned": False,
        "executed": False,
        "changed": False,
        "commands": commands,
        "showvminfo": _command_result_output(show_result),
    }
    if not show_result.ok:
        output["ok"] = False
        output["status"] = "missing" if _is_missing_vm_result(show_result) else "failed"
        output["reason"] = (
            "VirtualBox VM is missing"
            if output["status"] == "missing"
            else "showvminfo failed"
        )
        return output

    current_groups = parse_showvminfo_groups(show_result.stdout)
    output["current_groups"] = list(current_groups)
    missing_groups = [group for group in target_groups if group not in current_groups]
    if not missing_groups:
        output["status"] = "already-grouped"
        output["reason"] = "target group is already present"
        return output

    modify_command = modifyvm_groups_command(vm_name, target_groups)
    rendered_modify = render_argv(modify_command)
    output["modify_command"] = rendered_modify
    output["modify_argv"] = modify_command
    commands.append(rendered_modify)
    if dry_run:
        output["status"] = "planned"
        output["planned"] = True
        return output

    modify_result = command_runner(modify_command, timeout=60)
    commands[-1] = render_argv(modify_result.redacted_argv)
    output["modifyvm"] = _command_result_output(modify_result)
    output["ok"] = modify_result.ok
    output["executed"] = True
    output["changed"] = modify_result.ok
    output["status"] = "updated" if modify_result.ok else "failed"
    if not modify_result.ok:
        output["reason"] = "modifyvm --groups failed"
    return output


def _command_result_output(result: CommandResult) -> dict[str, object]:
    output: dict[str, object] = {
        "ok": result.ok,
        "executed": True,
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


def _is_missing_vm_result(result: CommandResult) -> bool:
    haystack = f"{result.stdout}\n{result.stderr}\n{result.error or ''}".lower()
    return (
        "could not find a registered machine named" in haystack
        or "could not find a registered machine with uuid" in haystack
        or "vbox_e_object_not_found" in haystack
    )


def _count_status(results: Sequence[Mapping[str, object]], status: str) -> int:
    return sum(1 for result in results if result.get("status") == status)


__all__ = [
    "collect_tracked_vm_group_candidates",
    "default_group_metadata",
    "modifyvm_groups_command",
    "normalize_tracked_vm_groups",
    "normalize_group_path",
    "normalize_group_paths",
    "parse_showvminfo_groups",
    "showvminfo_has_group",
]
