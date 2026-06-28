"""Shared helpers for endpoint smoke appliance execution plans."""

from __future__ import annotations

import json
import posixpath
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DOCKER_ENDPOINT_RUNTIME = "docker-endpoint-container"
SSH_DOCKER_RUNTIME = "ssh-docker-host"


def ensure_repo_imports(repo_root: Path) -> None:
    root = str(repo_root)
    if root not in sys.path:
        sys.path.insert(0, root)


def endpoint_container_runtime_metadata(
    *,
    profile: str,
    remote_workspace: str,
    remote_artifacts: str,
) -> dict[str, object]:
    return {
        "profile": profile,
        "substrate": DOCKER_ENDPOINT_RUNTIME,
        "endpoint_container_is_appliance": True,
        "docker_endpoint_container": True,
        "nested_docker": False,
        "docker_execution_supported": False,
        "run_path": "tools/endpoint/run exec",
        "sync_path": "endpoint container appliance sync over endpoint upload/exec",
        "remote_workspace": remote_workspace,
        "remote_artifacts": remote_artifacts,
    }


def ssh_docker_runtime_metadata(
    *,
    profile: str,
    remote_workspace: str = "<endpoint_appliance_workspace>",
    remote_artifacts: str = "<endpoint_appliance_artifacts>",
) -> dict[str, object]:
    return {
        "profile": profile,
        "substrate": SSH_DOCKER_RUNTIME,
        "endpoint_container_is_appliance": False,
        "docker_endpoint_container": False,
        "nested_docker": False,
        "docker_execution_supported": True,
        "run_path": "tools/endpoint/run appliance run",
        "sync_path": "tools/endpoint/run appliance run --work-dir",
        "remote_workspace": remote_workspace,
        "remote_artifacts": remote_artifacts,
    }


def runtime_plan_lines(metadata: Mapping[str, object]) -> list[str]:
    return [
        f"appliance profile: {metadata['profile']}",
        f"appliance substrate: {metadata['substrate']}",
        f"endpoint container is appliance: {_bool_text(metadata['endpoint_container_is_appliance'])}",
        f"nested Docker: {_bool_text(metadata['nested_docker'])}",
        f"Docker execution supported: {_bool_text(metadata['docker_execution_supported'])}",
        f"appliance sync path: {metadata['sync_path']}",
        f"appliance run path: {metadata['run_path']}",
        f"appliance remote workspace: {metadata['remote_workspace']}",
        f"appliance remote artifacts: {metadata['remote_artifacts']}",
    ]


@dataclass(frozen=True, slots=True)
class EndpointContainerSyncResult:
    endpoint_id: str
    profile: str
    source_root: str
    remote_workspace_dir: str
    remote_artifact_dir: str
    command_results: list[dict[str, object]]

    @property
    def ok(self) -> bool:
        return all(bool(result["ok"]) for result in self.command_results)

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "endpoint-container-appliance-sync",
            "endpoint_id": self.endpoint_id,
            "profile": self.profile,
            "source_root": self.source_root,
            "remote_workspace_dir": self.remote_workspace_dir,
            "remote_artifact_dir": self.remote_artifact_dir,
            "ok": self.ok,
            "command_results": list(self.command_results),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def endpoint_container_workspace_dir(remote_artifacts: str) -> str:
    root = remote_artifacts.rstrip("/")
    if not root:
        raise ValueError("remote artifact path must not be empty")
    return f"{root}-workspace"


def sync_endpoint_container_workspace(
    *,
    wire: Path,
    repo_root: Path,
    endpoint_id: str,
    profile: str,
    workspace: Path,
    remote_workspace: str,
    remote_artifacts: str,
    runner: Any,
    timeout: float,
) -> EndpointContainerSyncResult:
    remote_workspace = _remote_absolute_path(remote_workspace, "remote_workspace")
    remote_artifacts = _remote_absolute_path(remote_artifacts, "remote_artifacts")
    workspace_parent = posixpath.dirname(remote_workspace) or "/"
    commands = [
        [
            str(wire),
            "exec",
            endpoint_id,
            "--",
            "sh",
            "-lc",
            "set -eu; "
            f"rm -rf {sh_quote(remote_workspace)}; "
            f"mkdir -p {sh_quote(workspace_parent)} {sh_quote(remote_artifacts)}",
        ],
        [str(wire), "upload", endpoint_id, str(workspace), remote_workspace],
    ]

    results: list[dict[str, object]] = []
    for index, command in enumerate(commands, start=1):
        result = runner(command, cwd=repo_root, timeout=timeout)
        results.append(_command_result_dict(index=index, result=result))
        if not bool(getattr(result, "ok", False)):
            break

    return EndpointContainerSyncResult(
        endpoint_id=endpoint_id,
        profile=profile,
        source_root=str(workspace),
        remote_workspace_dir=remote_workspace,
        remote_artifact_dir=remote_artifacts,
        command_results=results,
    )


def sync_endpoint_workspace(
    *,
    repo_root: Path,
    endpoint_id: str,
    workspace: Path,
    artifact_dir: Path,
    timeout: float,
) -> Any:
    ensure_repo_imports(repo_root)
    from tools.endpoint.engine.appliance import (  # pylint: disable=import-outside-toplevel
        read_endpoint_appliance_target,
        sync_endpoint_appliance_workspace,
    )
    from tools.endpoint.engine.process import run_command  # pylint: disable=import-outside-toplevel

    target = read_endpoint_appliance_target(endpoint_id)
    return sync_endpoint_appliance_workspace(
        target,
        source_root=workspace,
        artifact_dir=artifact_dir / "appliance-sync",
        runner=run_command,
        timeout=timeout,
    )


def write_crafter_workload_workspace(
    *,
    workspace: Path,
    repo_root: Path,
    package_name: str,
    bin_sources: Mapping[str, str],
) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    _write_workspace_root(workspace)
    _copy_optional(repo_root / "Cargo.lock", workspace / "Cargo.lock")
    (workspace / "README.md").write_text(
        "Temporary libcrafter endpoint smoke workspace.\n",
        encoding="utf-8",
    )
    shutil.copytree(
        repo_root / "crafter",
        workspace / "crafter",
        ignore=shutil.ignore_patterns("target", "__pycache__"),
    )
    workload = workspace / "workload"
    src_bin = workload / "src" / "bin"
    src_bin.mkdir(parents=True, exist_ok=True)
    (workload / "Cargo.toml").write_text(
        "\n".join(
            [
                "[package]",
                f'name = "{package_name}"',
                'version = "0.0.0"',
                'edition = "2021"',
                "publish = false",
                "",
                "[dependencies]",
                'crafter = { path = "../crafter" }',
                "",
            ]
        ),
        encoding="utf-8",
    )
    for bin_name, source in bin_sources.items():
        (src_bin / f"{bin_name}.rs").write_text(source.strip() + "\n", encoding="utf-8")


def _write_workspace_root(workspace: Path) -> None:
    (workspace / "Cargo.toml").write_text(
        "\n".join(
            [
                "[workspace]",
                'members = ["crafter", "workload"]',
                'exclude = ["target/package-self-test"]',
                'resolver = "2"',
                "",
                "[workspace.package]",
                'version = "0.3.2"',
                'edition = "2021"',
                'rust-version = "1.78"',
                'description = "Packet-level network interaction for Rust tools and agents."',
                'license = "MIT"',
                'repository = "https://github.com/pellegre/libcrafter"',
                'homepage = "https://github.com/pellegre/libcrafter"',
                'documentation = "https://docs.rs/crafter"',
                'readme = "README.md"',
                'keywords = ["packets", "pcap", "networking", "packet-crafting", "testing"]',
                'categories = ["network-programming", "development-tools"]',
                "",
            ]
        ),
        encoding="utf-8",
    )


def _copy_optional(source: Path, destination: Path) -> None:
    if source.is_file():
        shutil.copy2(source, destination)


def _command_result_dict(*, index: int, result: Any) -> dict[str, object]:
    return {
        "name": f"{index:02d}-{_command_result_name(result)}",
        "argv": list(getattr(result, "argv", [])),
        "command": str(getattr(result, "command", "")),
        "exit_code": int(getattr(result, "exit_code", 1)),
        "ok": bool(getattr(result, "ok", False)),
    }


def _command_result_name(result: Any) -> str:
    argv = getattr(result, "argv", [])
    if isinstance(argv, list) and len(argv) > 1:
        return str(argv[1]).replace("_", "-")
    return "command"


def _remote_absolute_path(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    if not value.startswith("/"):
        raise ValueError(f"{field_name} must be an absolute path")
    return value


def sh_quote(value: str) -> str:
    import shlex

    return shlex.quote(value)


def _bool_text(value: object) -> str:
    return "true" if bool(value) else "false"
