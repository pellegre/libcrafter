"""VirtualBox endpoint creation and planning operations."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from ipaddress import ip_address, ip_network
from pathlib import Path

from ...model import ArtifactPath, EndpointManifest, EndpointSSHInfo, NetworkInterface, write_json
from ...process import CommandResult, run_command
from ...registry import validate_request
from ...ssh import ensure_known_hosts_file, wait_for_ssh
from ...state import endpoint_layout, ensure_endpoint_dirs, write_endpoint_manifest
from ..vm import (
    build_endpoint_guest_artifacts,
    file_resource,
    free_localhost_tcp_port,
    endpoint_id as vm_endpoint_id,
    path_component,
    plan_guest_artifacts,
    provider_resources,
    select_lan_candidate_interfaces,
    short_provider_resource_name,
    utc_now,
    vm_resource,
    discover_linux_endpoint_interfaces,
    command_error,
    vm_disk_size_mib,
)
from .bridge import (
    discover_bridge_interfaces,
    planned_bridge_interface,
    requested_bridge_interface,
    select_bridge_interface,
)
from .constants import (
    CONFIRMATION_ERROR,
    PLANNED_CREATED_AT,
    VBOXMANAGE_COMMAND,
    VBOX_BRIDGE_IFACE_ENV,
)
from .constants import VirtualBoxRunner


VBOX_OSTYPE = "Ubuntu_64"
VBOX_STORAGE_CONTROLLER = "SATA"
VBOX_MEMORY_MB = "2048"
VBOX_CPUS = "2"
VBOX_NAT_ADAPTER = 1
VBOX_LAN_ADAPTER = 2
VBOX_SSH_HOST = "127.0.0.1"
VBOX_SSH_GUEST_PORT = 22
VBOX_SSH_USER = "root"
COMMAND_LOG_NAME = "virtualbox-commands.json"
DownloadRunner = Callable[[str, Path], None]


def create_endpoint(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None = None,
    private_ip: str | None = None,
    dry_run: bool = False,
    confirm_live_run: bool = False,
    env: Mapping[str, str] | None = None,
    command_runner: VirtualBoxRunner = run_command,
    download_runner: DownloadRunner | None = None,
    ssh_wait_timeout: float = 300,
    ssh_wait_interval: float = 5,
) -> dict[str, object]:
    """Create or plan one VirtualBox endpoint."""

    validate_request(provider, exposure)
    _validate_create_request(role, private_group, private_ip)

    if dry_run:
        return _planned_endpoint_manifest(
            provider=provider,
            exposure=exposure,
            role=role,
            env=os.environ if env is None else env,
        )

    if not confirm_live_run:
        raise PermissionError(CONFIRMATION_ERROR)
    return _create_live_endpoint(
        provider=provider,
        exposure=exposure,
        role=role,
        env=os.environ if env is None else env,
        command_runner=command_runner,
        download_runner=download_runner,
        ssh_wait_timeout=ssh_wait_timeout,
        ssh_wait_interval=ssh_wait_interval,
    )


def _planned_endpoint_manifest(
    *,
    provider: str,
    exposure: str,
    role: str,
    env: Mapping[str, str],
) -> dict[str, object]:
    endpoint_id = _planned_endpoint_id(provider=provider, exposure=exposure, role=role)
    layout = endpoint_layout(endpoint_id)
    artifacts = plan_guest_artifacts(
        endpoint_id=endpoint_id,
        provider=provider,
        layout=layout,
        disk_format="vdi",
        env=env,
        include_network_config=True,
    )
    bridge = planned_bridge_interface(env)
    vm_name = short_provider_resource_name("wire", endpoint_id, max_length=80)
    ssh_port = free_localhost_tcp_port()
    manifest = EndpointManifest(
        endpoint_id=endpoint_id,
        provider=provider,
        exposure=exposure,
        status="planned",
        role=role,
        created_at=PLANNED_CREATED_AT,
        ssh=EndpointSSHInfo(
            host="127.0.0.1",
            user="root",
            port=ssh_port,
            identity_file=str(layout.private_key_path),
            known_hosts_file=str(layout.known_hosts_path),
            metadata={
                "planned": True,
                "transport": "virtualbox-nat-port-forward",
                "control_interface": "nat-control",
            },
        ),
        interfaces=[
            NetworkInterface(
                name="nat-control",
                exposure="control",
                metadata={
                    "planned": True,
                    "type": "nat-control",
                    "adapter": 1,
                    "network": "nat",
                    "host": "127.0.0.1",
                    "host_port": ssh_port,
                    "guest_port": 22,
                },
            ),
            NetworkInterface(
                name="lan",
                exposure="lan",
                metadata={
                    "planned": True,
                    "type": "bridged-lan",
                    "adapter": 2,
                    "bridge_interface": bridge["name"],
                    "bridge_selection": bridge["selection"],
                    "bridge_env": bridge["env"],
                    "bridge_validated": bridge["validated"],
                },
            ),
        ],
        provider_resources=provider_resources(
            [
                vm_resource(
                    vm_name,
                    kind="virtualbox-vm",
                    metadata={
                        "planned": True,
                        "provider": provider,
                        "exposure": exposure,
                    },
                ),
                *artifacts.file_resources(include_cache=True),
                file_resource(layout.private_key_path, name="ssh-private-key"),
                file_resource(layout.known_hosts_path, name="ssh-known-hosts"),
            ],
            cleanup_order=["virtualbox-vm", "local-file"],
            metadata={
                "provider": provider,
                "exposure": exposure,
                "planned": True,
            },
        ),
        artifact_dir=str(layout.artifact_dir),
        metadata={
            "created": False,
            "dry_run": True,
            "state_dir": str(layout.state_dir),
            "manifest_path": str(layout.manifest_path),
            "virtualbox": {
                "command": VBOXMANAGE_COMMAND,
                "vm_name": vm_name,
                "nat_adapter": 1,
                "lan_adapter": 2,
                "ssh_host": "127.0.0.1",
                "ssh_port": ssh_port,
                "bridge_interface": bridge["name"],
                "bridge_selection": bridge["selection"],
                "bridge_env": bridge["env"],
            },
            **artifacts.to_manifest_metadata(),
        },
    )
    output = manifest.to_dict()
    output["metadata"]["artifact_paths"] = manifest.artifact_paths(  # type: ignore[index]
        artifacts.artifact_paths()
    ).to_dict()
    output["created"] = False
    output["dry_run"] = True
    output["state_dir"] = str(layout.state_dir)
    output["manifest_path"] = str(layout.manifest_path)
    return output


def _validate_create_request(
    role: str,
    private_group: str | None,
    private_ip: str | None,
) -> None:
    if role == "":
        raise ValueError("role must be a non-empty string")
    if private_group == "":
        raise ValueError("private_group must be a non-empty string when supplied")
    if private_ip == "":
        raise ValueError("private_ip must be a non-empty string when supplied")
    if private_group is not None:
        raise ValueError("--private-group is not valid with provider virtualbox exposure lan")
    if private_ip is not None:
        raise ValueError("--private-ip is not valid with provider virtualbox exposure lan")


def _planned_endpoint_id(*, provider: str, exposure: str, role: str) -> str:
    return "-".join(path_component(part) for part in ("planned", provider, exposure, role))


def _create_live_endpoint(
    *,
    provider: str,
    exposure: str,
    role: str,
    env: Mapping[str, str],
    command_runner: VirtualBoxRunner,
    download_runner: DownloadRunner | None,
    ssh_wait_timeout: float,
    ssh_wait_interval: float,
) -> dict[str, object]:
    created_at = utc_now()
    endpoint_id = vm_endpoint_id(provider=provider, exposure=exposure, role=role)
    layout = ensure_endpoint_dirs(endpoint_id)
    ensure_known_hosts_file(layout.known_hosts_path)
    command_log_path = layout.artifact_dir / COMMAND_LOG_NAME
    recorder = _CommandRecorder(command_runner, command_log_path)
    vm_name = short_provider_resource_name("wire", endpoint_id, max_length=80)
    ssh_port = free_localhost_tcp_port()
    bridge_name: str | None = None
    bridge_metadata: dict[str, object] = {
        "name": None,
        "selection": "unresolved",
        "env": VBOX_BRIDGE_IFACE_ENV,
        "validated": False,
    }
    vm_registered = False

    try:
        bridge_interfaces = discover_bridge_interfaces(command_runner=recorder)
        selected_bridge = select_bridge_interface(bridge_interfaces, env=env)
        requested_bridge = requested_bridge_interface(env)
        if selected_bridge is None:
            if requested_bridge is not None:
                raise RuntimeError(f"VirtualBox bridge interface {requested_bridge!r} was not found")
            raise RuntimeError("no usable VirtualBox bridged interface was discovered")
        bridge_name = str(selected_bridge["name"])
        bridge_metadata = {
            "name": bridge_name,
            "selection": "env" if requested_bridge is not None else "auto",
            "env": VBOX_BRIDGE_IFACE_ENV,
            "validated": True,
            "interface": dict(selected_bridge),
        }

        artifacts = plan_guest_artifacts(
            endpoint_id=endpoint_id,
            provider=provider,
            layout=layout,
            disk_format="vdi",
            env=env,
            include_network_config=True,
        )
        vbox_basefolder = layout.state_dir / "virtualbox"
        vbox_basefolder.mkdir(parents=True, exist_ok=True)
        build_endpoint_guest_artifacts(
            artifacts,
            private_key_path=layout.private_key_path,
            runner=recorder,
            download_runner=download_runner or _default_download_runner(),
            network_config=_virtualbox_network_config(),
        )
        _resize_virtualbox_disk(artifacts.disk_path, artifacts.disk_size, runner=recorder)

        resources = _virtualbox_provider_resources(
            vm_name=vm_name,
            artifacts=artifacts,
            layout=layout,
            vbox_basefolder=vbox_basefolder,
            bridge=bridge_metadata,
            vm_registered=vm_registered,
            include_cache=True,
        )
        metadata = _virtualbox_manifest_metadata(
            created=False,
            dry_run=False,
            layout=layout,
            vm_name=vm_name,
            ssh_port=ssh_port,
            bridge=bridge_metadata,
            artifacts=artifacts,
            command_log_path=command_log_path,
            vbox_basefolder=vbox_basefolder,
            vm_registered=vm_registered,
        )

        _run_vbox(
            [
                VBOXMANAGE_COMMAND,
                "createvm",
                "--name",
                vm_name,
                "--basefolder",
                str(vbox_basefolder),
                "--ostype",
                VBOX_OSTYPE,
                "--register",
            ],
            runner=recorder,
        )
        vm_registered = True
        resources = _virtualbox_provider_resources(
            vm_name=vm_name,
            artifacts=artifacts,
            layout=layout,
            vbox_basefolder=vbox_basefolder,
            bridge=bridge_metadata,
            vm_registered=vm_registered,
            include_cache=True,
        )
        metadata = _virtualbox_manifest_metadata(
            created=True,
            dry_run=False,
            layout=layout,
            vm_name=vm_name,
            ssh_port=ssh_port,
            bridge=bridge_metadata,
            artifacts=artifacts,
            command_log_path=command_log_path,
            vbox_basefolder=vbox_basefolder,
            vm_registered=vm_registered,
        )
        write_endpoint_manifest(
            EndpointManifest(
                endpoint_id=endpoint_id,
                provider=provider,
                exposure=exposure,
                status="creating",
                role=role,
                created_at=created_at,
                ssh=_ssh_info(
                    layout=layout,
                    vm_name=vm_name,
                    ssh_port=ssh_port,
                    control_interface="nat-control",
                ),
                interfaces=_initial_interfaces(
                    ssh_port=ssh_port,
                    bridge=bridge_metadata,
                ),
                provider_resources=resources,
                artifact_dir=str(layout.artifact_dir),
                metadata={
                    **metadata,
                    "discovery": {
                        "ssh_ready": False,
                        "interfaces": False,
                        "lan_interface": False,
                    },
                },
            )
        )

        for argv in _virtualbox_boot_commands(
            vm_name=vm_name,
            bridge_name=bridge_name,
            ssh_port=ssh_port,
            disk_path=artifacts.disk_path,
            seed_iso_path=artifacts.seed_iso_path,
        ):
            _run_vbox(argv, runner=recorder)

        try:
            wait_for_ssh(
                host=VBOX_SSH_HOST,
                user=VBOX_SSH_USER,
                identity_file=layout.private_key_path,
                known_hosts=layout.known_hosts_path,
                port=ssh_port,
                wait_timeout=ssh_wait_timeout,
                interval=ssh_wait_interval,
                runner=recorder,
            )
        except TimeoutError as exc:
            raise RuntimeError(str(exc)) from exc

        discovered_interfaces = discover_linux_endpoint_interfaces(
            host=VBOX_SSH_HOST,
            user=VBOX_SSH_USER,
            identity_file=layout.private_key_path,
            known_hosts=layout.known_hosts_path,
            exposure=exposure,
            port=ssh_port,
            runner=recorder,
            source="virtualbox-ssh-discovery",
            metadata={"vm_name": vm_name},
            prefer_public_or_default=False,
        )
        lan_candidates = select_lan_candidate_interfaces(discovered_interfaces)
        if not lan_candidates:
            raise RuntimeError("guest interface discovery did not find a non-NAT LAN interface")
        lan_interface = _lan_interface(lan_candidates[0], bridge=bridge_metadata)
        control_interface = _nat_control_interface(
            discovered_interfaces,
            ssh_port=ssh_port,
        )
        manifest = EndpointManifest(
            endpoint_id=endpoint_id,
            provider=provider,
            exposure=exposure,
            status="active",
            role=role,
            created_at=created_at,
            ssh=_ssh_info(
                layout=layout,
                vm_name=vm_name,
                ssh_port=ssh_port,
                control_interface=control_interface.name,
            ),
            interfaces=[control_interface, lan_interface],
            provider_resources=resources,
            artifact_dir=str(layout.artifact_dir),
            metadata={
                **metadata,
                "discovery": {
                    "ssh_ready": True,
                    "interfaces": True,
                    "lan_interface": True,
                    "interface_count": len(discovered_interfaces),
                },
            },
        )
        manifest_path = write_endpoint_manifest(manifest)
        output = manifest.to_dict()
        output["created"] = True
        output["dry_run"] = False
        output["state_dir"] = str(manifest_path.parent)
        output["manifest_path"] = str(manifest_path)
        output["metadata"]["artifact_paths"] = manifest.artifact_paths(  # type: ignore[index]
            _artifact_paths(artifacts, command_log_path)
        ).to_dict()
        return output
    except Exception as exc:
        _write_failed_manifest(
            endpoint_id=endpoint_id,
            provider=provider,
            exposure=exposure,
            role=role,
            created_at=created_at,
            layout=layout,
            vm_name=vm_name,
            ssh_port=ssh_port,
            bridge=bridge_metadata,
            command_log_path=command_log_path,
            vm_registered=vm_registered,
            error=str(exc),
        )
        raise


class _CommandRecorder:
    def __init__(self, runner: VirtualBoxRunner, log_path: Path) -> None:
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


def _run_vbox(argv: Sequence[object], *, runner: VirtualBoxRunner) -> CommandResult:
    result = runner(argv, timeout=120)
    if not result.ok:
        raise RuntimeError(command_error("VirtualBox command failed", result))
    return result


def _resize_virtualbox_disk(
    disk_path: Path,
    disk_size: str,
    *,
    runner: VirtualBoxRunner,
) -> None:
    _run_vbox(
        [
            VBOXMANAGE_COMMAND,
            "modifymedium",
            str(disk_path),
            "--resize",
            str(vm_disk_size_mib(disk_size)),
        ],
        runner=runner,
    )


def _virtualbox_boot_commands(
    *,
    vm_name: str,
    bridge_name: str,
    ssh_port: int,
    disk_path: Path,
    seed_iso_path: Path,
) -> list[list[object]]:
    return [
        [
            VBOXMANAGE_COMMAND,
            "modifyvm",
            vm_name,
            "--memory",
            VBOX_MEMORY_MB,
            "--cpus",
            VBOX_CPUS,
            "--boot1",
            "disk",
            "--boot2",
            "dvd",
            "--boot3",
            "none",
            "--boot4",
            "none",
        ],
        [
            VBOXMANAGE_COMMAND,
            "modifyvm",
            vm_name,
            "--nic1",
            "nat",
            "--natpf1",
            f"wire-ssh,tcp,{VBOX_SSH_HOST},{ssh_port},,{VBOX_SSH_GUEST_PORT}",
        ],
        [
            VBOXMANAGE_COMMAND,
            "modifyvm",
            vm_name,
            "--nic2",
            "bridged",
            "--bridgeadapter2",
            bridge_name,
        ],
        [
            VBOXMANAGE_COMMAND,
            "storagectl",
            vm_name,
            "--name",
            VBOX_STORAGE_CONTROLLER,
            "--add",
            "sata",
            "--controller",
            "IntelAhci",
            "--portcount",
            "2",
            "--bootable",
            "on",
        ],
        [
            VBOXMANAGE_COMMAND,
            "storageattach",
            vm_name,
            "--storagectl",
            VBOX_STORAGE_CONTROLLER,
            "--port",
            "0",
            "--device",
            "0",
            "--type",
            "hdd",
            "--medium",
            str(disk_path),
        ],
        [
            VBOXMANAGE_COMMAND,
            "storageattach",
            vm_name,
            "--storagectl",
            VBOX_STORAGE_CONTROLLER,
            "--port",
            "1",
            "--device",
            "0",
            "--type",
            "dvddrive",
            "--medium",
            str(seed_iso_path),
        ],
        [VBOXMANAGE_COMMAND, "startvm", vm_name, "--type", "headless"],
    ]


def _initial_interfaces(
    *,
    ssh_port: int,
    bridge: Mapping[str, object],
) -> list[NetworkInterface]:
    return [
        NetworkInterface(
            name="nat-control",
            exposure="control",
            metadata={
                "type": "nat-control",
                "adapter": VBOX_NAT_ADAPTER,
                "network": "nat",
                "host": VBOX_SSH_HOST,
                "host_port": ssh_port,
                "guest_port": VBOX_SSH_GUEST_PORT,
            },
        ),
        NetworkInterface(
            name="lan",
            exposure="lan",
            metadata={
                "type": "bridged-lan",
                "adapter": VBOX_LAN_ADAPTER,
                "bridge_interface": bridge.get("name"),
                "bridge_selection": bridge.get("selection"),
                "bridge_env": bridge.get("env"),
                "bridge_validated": bridge.get("validated"),
            },
        ),
    ]


def _ssh_info(
    *,
    layout: object,
    vm_name: str,
    ssh_port: int,
    control_interface: str,
) -> EndpointSSHInfo:
    return EndpointSSHInfo(
        host=VBOX_SSH_HOST,
        user=VBOX_SSH_USER,
        port=ssh_port,
        identity_file=str(getattr(layout, "private_key_path")),
        known_hosts_file=str(getattr(layout, "known_hosts_path")),
        metadata={
            "created_by": "tools/wire",
            "transport": "virtualbox-nat-port-forward",
            "vm_name": vm_name,
            "control_interface": control_interface,
        },
    )


def _lan_interface(
    interface: NetworkInterface,
    *,
    bridge: Mapping[str, object],
) -> NetworkInterface:
    return replace(
        interface,
        exposure="lan",
        metadata={
            **interface.metadata,
            "type": "bridged-lan",
            "adapter": VBOX_LAN_ADAPTER,
            "bridge_interface": bridge.get("name"),
            "bridge_selection": bridge.get("selection"),
            "bridge_env": bridge.get("env"),
            "bridge_validated": bridge.get("validated"),
        },
    )


def _nat_control_interface(
    interfaces: Sequence[NetworkInterface],
    *,
    ssh_port: int,
) -> NetworkInterface:
    discovered = _first_control_interface(interfaces)
    metadata = {
        "type": "nat-control",
        "adapter": VBOX_NAT_ADAPTER,
        "network": "nat",
        "host": VBOX_SSH_HOST,
        "host_port": ssh_port,
        "guest_port": VBOX_SSH_GUEST_PORT,
    }
    if discovered is None:
        return NetworkInterface(name="nat-control", exposure="control", metadata=metadata)
    return replace(
        discovered,
        exposure="control",
        metadata={**discovered.metadata, **metadata},
    )


def _first_control_interface(interfaces: Sequence[NetworkInterface]) -> NetworkInterface | None:
    network = ip_network("10.0.2.0/24")
    for interface in interfaces:
        if interface.ipv4 is None:
            continue
        try:
            address = ip_address(interface.ipv4)
        except ValueError:
            continue
        if address in network:
            return interface
    return None


def _virtualbox_provider_resources(
    *,
    vm_name: str,
    artifacts: object,
    layout: object,
    vbox_basefolder: Path,
    bridge: Mapping[str, object],
    vm_registered: bool,
    include_cache: bool,
) -> object:
    return provider_resources(
        [
            vm_resource(
                vm_name,
                kind="virtualbox-vm",
                metadata={
                    "provider": "virtualbox",
                    "registered": vm_registered,
                    "bridge_interface": bridge.get("name"),
                },
            ),
            *artifacts.file_resources(include_cache=include_cache),  # type: ignore[attr-defined]
            file_resource(vbox_basefolder, name="virtualbox-vm-dir"),
            file_resource(getattr(layout, "private_key_path"), name="ssh-private-key"),
            file_resource(getattr(layout, "known_hosts_path"), name="ssh-known-hosts"),
        ],
        cleanup_order=["virtualbox-vm", "local-file"],
        metadata={
            "provider": "virtualbox",
            "exposure": "lan",
            "vm_registered": vm_registered,
        },
    )


def _virtualbox_manifest_metadata(
    *,
    created: bool,
    dry_run: bool,
    layout: object,
    vm_name: str,
    ssh_port: int,
    bridge: Mapping[str, object],
    artifacts: object,
    command_log_path: Path,
    vbox_basefolder: Path,
    vm_registered: bool,
) -> dict[str, object]:
    return {
        "created": created,
        "dry_run": dry_run,
        "state_dir": str(getattr(layout, "state_dir")),
        "manifest_path": str(getattr(layout, "manifest_path")),
        "virtualbox": {
            "command": VBOXMANAGE_COMMAND,
            "vm_name": vm_name,
            "vm_registered": vm_registered,
            "basefolder": str(vbox_basefolder),
            "nat_adapter": VBOX_NAT_ADAPTER,
            "lan_adapter": VBOX_LAN_ADAPTER,
            "ssh_host": VBOX_SSH_HOST,
            "ssh_port": ssh_port,
            "ssh_guest_port": VBOX_SSH_GUEST_PORT,
            "bridge_interface": bridge.get("name"),
            "bridge_selection": bridge.get("selection"),
            "bridge_env": bridge.get("env"),
            "bridge_validated": bridge.get("validated"),
            "command_log_path": str(command_log_path),
        },
        **artifacts.to_manifest_metadata(),  # type: ignore[attr-defined]
    }


def _write_failed_manifest(
    *,
    endpoint_id: str,
    provider: str,
    exposure: str,
    role: str,
    created_at: str,
    layout: object,
    vm_name: str,
    ssh_port: int,
    bridge: Mapping[str, object],
    command_log_path: Path,
    vm_registered: bool,
    error: str,
) -> None:
    try:
        artifacts = plan_guest_artifacts(
            endpoint_id=endpoint_id,
            provider=provider,
            layout=layout,  # type: ignore[arg-type]
            disk_format="vdi",
            include_network_config=True,
        )
        vbox_basefolder = getattr(layout, "state_dir") / "virtualbox"
        manifest = EndpointManifest(
            endpoint_id=endpoint_id,
            provider=provider,
            exposure=exposure,
            status="failed",
            role=role,
            created_at=created_at,
            ssh=_ssh_info(
                layout=layout,
                vm_name=vm_name,
                ssh_port=ssh_port,
                control_interface="nat-control",
            ),
            interfaces=_initial_interfaces(ssh_port=ssh_port, bridge=bridge),
            provider_resources=_virtualbox_provider_resources(
                vm_name=vm_name,
                artifacts=artifacts,
                layout=layout,
                vbox_basefolder=vbox_basefolder,
                bridge=bridge,
                vm_registered=vm_registered,
                include_cache=True,
            ),
            artifact_dir=str(getattr(layout, "artifact_dir")),
            metadata={
                **_virtualbox_manifest_metadata(
                    created=vm_registered,
                    dry_run=False,
                    layout=layout,
                    vm_name=vm_name,
                    ssh_port=ssh_port,
                    bridge=bridge,
                    artifacts=artifacts,
                    command_log_path=command_log_path,
                    vbox_basefolder=vbox_basefolder,
                    vm_registered=vm_registered,
                ),
                "error": error,
            },
        )
        write_endpoint_manifest(manifest)
    except Exception:
        return


def _artifact_paths(artifacts: object, command_log_path: Path) -> list[ArtifactPath]:
    return [
        *artifacts.artifact_paths(),  # type: ignore[attr-defined]
        ArtifactPath(
            name="virtualbox-command-log",
            path=str(command_log_path),
        ),
    ]


def _virtualbox_network_config() -> dict[str, object]:
    return {
        "version": 2,
        "ethernets": {
            "all-en": {
                "match": {"name": "en*"},
                "dhcp4": True,
                "dhcp6": True,
                "optional": True,
            }
        },
    }


def _command_result_record(result: CommandResult) -> dict[str, object]:
    return {
        "argv": list(result.redacted_argv),
        "exit_code": result.exit_code,
        "ok": result.ok,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
        "timeout": result.timeout,
        "error": result.error,
    }


def _default_download_runner() -> DownloadRunner:
    from ..vm import download_url

    return download_url
