"""QEMU endpoint creation and planning operations."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path

from ...model import (
    ArtifactPath,
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResource,
    write_json,
)
from ...process import CommandResult, run_command
from ...registry import validate_request
from ...ssh import ensure_known_hosts_file, wait_for_ssh
from ...state import (
    endpoint_layout,
    ensure_endpoint_dirs,
    planned_private_group_record,
    read_private_group_record,
    update_private_group_allocation,
    write_endpoint_manifest,
)
from ..vm import (
    build_endpoint_guest_artifacts,
    command_error,
    discover_linux_endpoint_interfaces,
    endpoint_id as vm_endpoint_id,
    file_resource,
    free_localhost_tcp_port,
    path_component,
    plan_guest_artifacts,
    process_resource,
    provider_resources,
    short_provider_resource_name,
    utc_now,
    vm_resource,
)
from .constants import (
    CONFIRMATION_ERROR,
    PLANNED_CREATED_AT,
    QEMU_ACCEL_ENV,
    QEMU_DEFAULT_ACCEL,
    QEMU_SSH_GUEST_PORT,
    QEMU_SSH_HOST,
    QEMU_SSH_USER,
    QEMU_SYSTEM_COMMAND,
    QEMU_CPUS_ENV,
    QEMU_DEFAULT_CPUS,
    QEMU_DEFAULT_MEMORY_MB,
    QEMU_DEFAULT_PRIVATE_CIDR,
    QEMU_MEMORY_MB_ENV,
    QEMU_PRIVATE_CIDR_ENV,
    SUPPORTED_QEMU_ACCELS,
    QemuRunner,
)


COMMAND_LOG_NAME = "qemu-commands.json"
QEMU_PIDFILE_NAME = "qemu.pid"
QEMU_SERIAL_LOG_NAME = "serial.log"
QEMU_LOG_NAME = "qemu.log"
QEMU_CONTROL_NETDEV = "control0"
QEMU_PRIVATE_NETDEV = "private0"
QEMU_PRIVATE_GUEST_IFACE = "wirepriv0"
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
    command_runner: QemuRunner = run_command,
    download_runner: DownloadRunner | None = None,
    ssh_wait_timeout: float = 300,
    ssh_wait_interval: float = 5,
) -> dict[str, object]:
    """Create or plan one QEMU endpoint."""

    validate_request(provider, exposure)
    _validate_create_request(exposure, role, private_group, private_ip)

    if dry_run:
        return _planned_endpoint_manifest(
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
            env=os.environ if env is None else env,
        )

    if not confirm_live_run:
        raise PermissionError(CONFIRMATION_ERROR)
    environ = os.environ if env is None else env
    if exposure == "wan":
        return _create_live_wan_endpoint(
            provider=provider,
            exposure=exposure,
            role=role,
            env=environ,
            command_runner=command_runner,
            download_runner=download_runner,
            ssh_wait_timeout=ssh_wait_timeout,
            ssh_wait_interval=ssh_wait_interval,
        )
    if exposure == "private":
        return _create_live_private_endpoint(
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
            env=environ,
            command_runner=command_runner,
            download_runner=download_runner,
            ssh_wait_timeout=ssh_wait_timeout,
            ssh_wait_interval=ssh_wait_interval,
        )
    raise NotImplementedError(f"real qemu create-endpoint is not implemented for {exposure}")


def _planned_endpoint_manifest(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    env: Mapping[str, str],
) -> dict[str, object]:
    endpoint_id = _planned_endpoint_id(
        provider=provider,
        exposure=exposure,
        role=role,
        private_group=private_group,
    )
    layout = endpoint_layout(endpoint_id)
    artifacts = plan_guest_artifacts(
        endpoint_id=endpoint_id,
        provider=provider,
        layout=layout,
        disk_format="qcow2",
        env=env,
        include_network_config=exposure == "private",
    )
    acceleration = _requested_acceleration(env)
    private_cidr = _requested_private_cidr(env) if exposure == "private" else None
    vm_name = short_provider_resource_name("wire", endpoint_id, max_length=63)
    ssh_port = free_localhost_tcp_port()
    interfaces = _planned_interfaces(
        exposure=exposure,
        ssh_port=ssh_port,
        private_group=private_group,
        private_ip=private_ip,
    )
    qemu_metadata = _qemu_metadata(
        exposure=exposure,
        vm_name=vm_name,
        ssh_port=ssh_port,
        acceleration=acceleration,
        private_group=private_group,
        private_ip=private_ip,
        private_cidr=private_cidr,
    )
    metadata: dict[str, object] = {
        "created": False,
        "dry_run": True,
        "state_dir": str(layout.state_dir),
        "manifest_path": str(layout.manifest_path),
        "qemu": qemu_metadata,
        **artifacts.to_manifest_metadata(),
    }
    if exposure == "private":
        private_metadata = _planned_private_metadata(
            private_group,
            private_ip,
            private_cidr=private_cidr,
        )
        metadata["private"] = private_metadata
        metadata["private_network"] = private_metadata
        if private_group is not None:
            metadata["private_group"] = private_group
            metadata["private_group_record"] = planned_private_group_record(
                provider=provider,
                group=private_group,
                private_cidr=private_cidr or QEMU_DEFAULT_PRIVATE_CIDR,
                network_resource=private_metadata,
            ).to_dict()
        if private_ip is not None:
            metadata["private_ip"] = private_ip

    manifest = EndpointManifest(
        endpoint_id=endpoint_id,
        provider=provider,
        exposure=exposure,
        status="planned",
        role=role,
        created_at=PLANNED_CREATED_AT,
        ssh=EndpointSSHInfo(
            host=QEMU_SSH_HOST,
            user=QEMU_SSH_USER,
            port=ssh_port,
            identity_file=str(layout.private_key_path),
            known_hosts_file=str(layout.known_hosts_path),
            metadata={
                "planned": True,
                "transport": "qemu-user-net-hostfwd",
                "control_interface": "user-control",
                "acceleration": acceleration,
            },
        ),
        interfaces=interfaces,
        provider_resources=provider_resources(
            [
                vm_resource(
                    vm_name,
                    kind="qemu-vm",
                    metadata={
                        "planned": True,
                        "provider": provider,
                        "exposure": exposure,
                        "acceleration": acceleration,
                    },
                ),
                *artifacts.file_resources(include_cache=True),
                file_resource(layout.private_key_path, name="ssh-private-key"),
                file_resource(layout.known_hosts_path, name="ssh-known-hosts"),
            ],
            cleanup_order=["qemu-vm", "process", "local-file"],
            metadata={
                "provider": provider,
                "exposure": exposure,
                "planned": True,
            },
        ),
        artifact_dir=str(layout.artifact_dir),
        metadata=metadata,
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
    exposure: str,
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
    if exposure != "private" and private_group is not None:
        raise ValueError("--private-group is only valid with --exposure private")
    if exposure != "private" and private_ip is not None:
        raise ValueError("--private-ip is only valid with --exposure private")


def _planned_endpoint_id(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
) -> str:
    parts = ["planned", provider, exposure, role]
    if private_group is not None:
        parts.append(private_group)
    return "-".join(path_component(part) for part in parts)


def _requested_acceleration(env: Mapping[str, str]) -> str:
    acceleration = (env.get(QEMU_ACCEL_ENV) or QEMU_DEFAULT_ACCEL).strip().lower()
    if not acceleration:
        acceleration = QEMU_DEFAULT_ACCEL
    if acceleration not in SUPPORTED_QEMU_ACCELS:
        raise ValueError(
            f"{QEMU_ACCEL_ENV}={acceleration!r} is unsupported; "
            f"supported values: {', '.join(sorted(SUPPORTED_QEMU_ACCELS))}"
        )
    return acceleration


def _planned_interfaces(
    *,
    exposure: str,
    ssh_port: int,
    private_group: str | None,
    private_ip: str | None,
) -> list[NetworkInterface]:
    control = NetworkInterface(
        name="user-control",
        exposure="control",
        metadata={
            "planned": True,
            "type": "qemu-user-net-control",
            "network": "user",
            "netdev": "control0",
            "host": QEMU_SSH_HOST,
            "host_port": ssh_port,
            "guest_port": QEMU_SSH_GUEST_PORT,
        },
    )
    if exposure == "wan":
        return [
            control,
            NetworkInterface(
                name="wan",
                exposure="wan",
                metadata={
                    "planned": True,
                    "type": "qemu-user-net",
                    "network": "user",
                    "netdev": "control0",
                    "outbound_nat": True,
                    "host_forwarded_ssh": True,
                },
            ),
        ]
    return [
        control,
        NetworkInterface(
            name="private",
            exposure="private",
            ipv4=private_ip,
            provider_network_id=_planned_private_network_id(private_group),
            metadata={
                "planned": True,
                "type": "qemu-private-net",
                "network": "isolated",
                "backend": "socket-mcast",
                "netdev": "private0",
                "private_group": private_group,
                "private_ip": private_ip,
            },
        ),
    ]


def _qemu_metadata(
    *,
    exposure: str,
    vm_name: str,
    ssh_port: int,
    acceleration: str,
    private_group: str | None,
    private_ip: str | None,
    private_cidr: str | None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "command": QEMU_SYSTEM_COMMAND,
        "vm_name": vm_name,
        "acceleration": acceleration,
        "ssh_host": QEMU_SSH_HOST,
        "ssh_port": ssh_port,
        "control_netdev": "control0",
        "network": {
            "exposure": exposure,
            "control": {
                "type": "user",
                "host_forward": f"tcp:{QEMU_SSH_HOST}:{ssh_port}-:{QEMU_SSH_GUEST_PORT}",
            },
        },
    }
    if exposure == "private":
        metadata["private_group"] = private_group
        metadata["private_ip"] = private_ip
        metadata["private_cidr"] = private_cidr
        network = metadata["network"]
        if isinstance(network, dict):
            network["private"] = _planned_private_metadata(
                private_group,
                private_ip,
                private_cidr=private_cidr,
            )
    return metadata


def _planned_private_network_id(private_group: str | None) -> str:
    suffix = path_component(private_group) if private_group is not None else "ungrouped"
    return f"qemu-private-group-{suffix}"


def _create_live_wan_endpoint(
    *,
    provider: str,
    exposure: str,
    role: str,
    env: Mapping[str, str],
    command_runner: QemuRunner,
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
    vm_name = short_provider_resource_name("wire", endpoint_id, max_length=63)
    ssh_port = free_localhost_tcp_port()
    acceleration = _requested_acceleration(env)
    memory_mb = _requested_positive_int(env, QEMU_MEMORY_MB_ENV, QEMU_DEFAULT_MEMORY_MB)
    cpus = _requested_positive_int(env, QEMU_CPUS_ENV, QEMU_DEFAULT_CPUS)
    qemu_dir = layout.state_dir / "qemu"
    qemu_dir.mkdir(parents=True, exist_ok=True)
    pidfile_path = qemu_dir / QEMU_PIDFILE_NAME
    serial_log_path = layout.artifact_dir / QEMU_SERIAL_LOG_NAME
    qemu_log_path = layout.artifact_dir / QEMU_LOG_NAME
    pid: int | None = None
    qemu_started = False

    artifacts = plan_guest_artifacts(
        endpoint_id=endpoint_id,
        provider=provider,
        layout=layout,
        disk_format="qcow2",
        env=env,
        include_network_config=False,
    )

    try:
        build_endpoint_guest_artifacts(
            artifacts,
            private_key_path=layout.private_key_path,
            runner=recorder,
            download_runner=download_runner or _default_download_runner(),
        )
        command = _qemu_wan_command(
            vm_name=vm_name,
            ssh_port=ssh_port,
            acceleration=acceleration,
            memory_mb=memory_mb,
            cpus=cpus,
            disk_path=artifacts.disk_path,
            seed_iso_path=artifacts.seed_iso_path,
            pidfile_path=pidfile_path,
            serial_log_path=serial_log_path,
            qemu_log_path=qemu_log_path,
        )
        metadata = _qemu_manifest_metadata(
            created=False,
            dry_run=False,
            exposure=exposure,
            layout=layout,
            vm_name=vm_name,
            ssh_port=ssh_port,
            acceleration=acceleration,
            memory_mb=memory_mb,
            cpus=cpus,
            artifacts=artifacts,
            command_log_path=command_log_path,
            pidfile_path=pidfile_path,
            serial_log_path=serial_log_path,
            qemu_log_path=qemu_log_path,
            pid=None,
            command=command,
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
                    control_interface="wan",
                ),
                interfaces=_planned_interfaces(
                    exposure=exposure,
                    ssh_port=ssh_port,
                    private_group=None,
                    private_ip=None,
                ),
                provider_resources=_qemu_provider_resources(
                    exposure=exposure,
                    vm_name=vm_name,
                    artifacts=artifacts,
                    layout=layout,
                    pidfile_path=pidfile_path,
                    pid=None,
                    include_cache=True,
                ),
                artifact_dir=str(layout.artifact_dir),
                metadata={
                    **metadata,
                    "discovery": {
                        "ssh_ready": False,
                        "interfaces": False,
                        "wan_interface": False,
                    },
                },
            )
        )

        _run_qemu(command, runner=recorder)
        qemu_started = True
        pid = _read_pidfile(pidfile_path)
        if pid is None:
            raise RuntimeError(f"QEMU did not write pidfile {pidfile_path}")
        metadata = _qemu_manifest_metadata(
            created=True,
            dry_run=False,
            exposure=exposure,
            layout=layout,
            vm_name=vm_name,
            ssh_port=ssh_port,
            acceleration=acceleration,
            memory_mb=memory_mb,
            cpus=cpus,
            artifacts=artifacts,
            command_log_path=command_log_path,
            pidfile_path=pidfile_path,
            serial_log_path=serial_log_path,
            qemu_log_path=qemu_log_path,
            pid=pid,
            command=command,
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
                    control_interface="wan",
                ),
                interfaces=_planned_interfaces(
                    exposure=exposure,
                    ssh_port=ssh_port,
                    private_group=None,
                    private_ip=None,
                ),
                provider_resources=_qemu_provider_resources(
                    exposure=exposure,
                    vm_name=vm_name,
                    artifacts=artifacts,
                    layout=layout,
                    pidfile_path=pidfile_path,
                    pid=pid,
                    include_cache=True,
                ),
                artifact_dir=str(layout.artifact_dir),
                metadata={
                    **metadata,
                    "discovery": {
                        "ssh_ready": False,
                        "interfaces": False,
                        "wan_interface": False,
                    },
                },
            )
        )

        try:
            wait_for_ssh(
                host=QEMU_SSH_HOST,
                user=QEMU_SSH_USER,
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
            host=QEMU_SSH_HOST,
            user=QEMU_SSH_USER,
            identity_file=layout.private_key_path,
            known_hosts=layout.known_hosts_path,
            exposure=exposure,
            port=ssh_port,
            runner=recorder,
            source="qemu-ssh-discovery",
            metadata={"vm_name": vm_name, "netdev": QEMU_CONTROL_NETDEV},
        )
        if not discovered_interfaces:
            raise RuntimeError("guest interface discovery did not find a WAN interface")
        wan_interface = _wan_interface(discovered_interfaces[0], ssh_port=ssh_port)
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
                control_interface=wan_interface.name,
            ),
            interfaces=[wan_interface],
            provider_resources=_qemu_provider_resources(
                exposure=exposure,
                vm_name=vm_name,
                artifacts=artifacts,
                layout=layout,
                pidfile_path=pidfile_path,
                pid=pid,
                include_cache=True,
            ),
            artifact_dir=str(layout.artifact_dir),
            metadata={
                **metadata,
                "discovery": {
                    "ssh_ready": True,
                    "interfaces": True,
                    "wan_interface": True,
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
            _artifact_paths(artifacts, command_log_path, serial_log_path, qemu_log_path)
        ).to_dict()
        return output
    except Exception as exc:
        if pid is None:
            pid = _read_pidfile(pidfile_path)
        _write_failed_manifest(
            endpoint_id=endpoint_id,
            provider=provider,
            exposure=exposure,
            role=role,
            created_at=created_at,
            layout=layout,
            vm_name=vm_name,
            ssh_port=ssh_port,
            acceleration=acceleration,
            memory_mb=memory_mb,
            cpus=cpus,
            command_log_path=command_log_path,
            pidfile_path=pidfile_path,
            serial_log_path=serial_log_path,
            qemu_log_path=qemu_log_path,
            pid=pid,
            qemu_started=qemu_started,
            command=_qemu_wan_command(
                vm_name=vm_name,
                ssh_port=ssh_port,
                acceleration=acceleration,
                memory_mb=memory_mb,
                cpus=cpus,
                disk_path=artifacts.disk_path,
                seed_iso_path=artifacts.seed_iso_path,
                pidfile_path=pidfile_path,
                serial_log_path=serial_log_path,
                qemu_log_path=qemu_log_path,
            ),
            error=str(exc),
        )
        raise


def _create_live_private_endpoint(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    env: Mapping[str, str],
    command_runner: QemuRunner,
    download_runner: DownloadRunner | None,
    ssh_wait_timeout: float,
    ssh_wait_interval: float,
) -> dict[str, object]:
    if private_group is None:
        raise ValueError("--private-group is required for real private QEMU endpoints")

    created_at = utc_now()
    endpoint_id = vm_endpoint_id(provider=provider, exposure=exposure, role=role)
    layout = ensure_endpoint_dirs(endpoint_id)
    ensure_known_hosts_file(layout.known_hosts_path)
    command_log_path = layout.artifact_dir / COMMAND_LOG_NAME
    recorder = _CommandRecorder(command_runner, command_log_path)
    vm_name = short_provider_resource_name("wire", endpoint_id, max_length=63)
    ssh_port = free_localhost_tcp_port()
    acceleration = _requested_acceleration(env)
    memory_mb = _requested_positive_int(env, QEMU_MEMORY_MB_ENV, QEMU_DEFAULT_MEMORY_MB)
    cpus = _requested_positive_int(env, QEMU_CPUS_ENV, QEMU_DEFAULT_CPUS)
    private_cidr = _requested_private_cidr(env)
    network_resource = _qemu_private_network_resource(private_group, private_cidr)
    private_ipv4 = _allocate_qemu_private_ipv4(
        provider=provider,
        private_group=private_group,
        private_cidr=private_cidr,
        requested_private_ip=private_ip,
    )
    control_mac = _deterministic_mac("control", endpoint_id)
    private_mac = _deterministic_mac("private", private_group, endpoint_id)
    qemu_dir = layout.state_dir / "qemu"
    qemu_dir.mkdir(parents=True, exist_ok=True)
    pidfile_path = qemu_dir / QEMU_PIDFILE_NAME
    serial_log_path = layout.artifact_dir / QEMU_SERIAL_LOG_NAME
    qemu_log_path = layout.artifact_dir / QEMU_LOG_NAME
    pid: int | None = None
    qemu_started = False

    artifacts = plan_guest_artifacts(
        endpoint_id=endpoint_id,
        provider=provider,
        layout=layout,
        disk_format="qcow2",
        env=env,
        include_network_config=True,
    )
    command = _qemu_private_command(
        vm_name=vm_name,
        ssh_port=ssh_port,
        acceleration=acceleration,
        memory_mb=memory_mb,
        cpus=cpus,
        disk_path=artifacts.disk_path,
        seed_iso_path=artifacts.seed_iso_path,
        pidfile_path=pidfile_path,
        serial_log_path=serial_log_path,
        qemu_log_path=qemu_log_path,
        network_resource=network_resource,
        control_mac=control_mac,
        private_mac=private_mac,
    )

    try:
        build_endpoint_guest_artifacts(
            artifacts,
            private_key_path=layout.private_key_path,
            runner=recorder,
            download_runner=download_runner or _default_download_runner(),
            network_config=_qemu_private_network_config(
                private_ipv4=private_ipv4,
                private_cidr=private_cidr,
                control_mac=control_mac,
                private_mac=private_mac,
            ),
        )
        metadata = _qemu_manifest_metadata(
            created=False,
            dry_run=False,
            exposure=exposure,
            layout=layout,
            vm_name=vm_name,
            ssh_port=ssh_port,
            acceleration=acceleration,
            memory_mb=memory_mb,
            cpus=cpus,
            artifacts=artifacts,
            command_log_path=command_log_path,
            pidfile_path=pidfile_path,
            serial_log_path=serial_log_path,
            qemu_log_path=qemu_log_path,
            pid=None,
            command=command,
            private_group=private_group,
            private_ipv4=private_ipv4,
            private_network_resource=network_resource,
            control_mac=control_mac,
            private_mac=private_mac,
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
                    control_interface="control",
                ),
                interfaces=_private_creating_interfaces(
                    ssh_port=ssh_port,
                    private_group=private_group,
                    private_ipv4=private_ipv4,
                    network_resource=network_resource,
                    control_mac=control_mac,
                    private_mac=private_mac,
                ),
                provider_resources=_qemu_provider_resources(
                    exposure=exposure,
                    vm_name=vm_name,
                    artifacts=artifacts,
                    layout=layout,
                    pidfile_path=pidfile_path,
                    pid=None,
                    include_cache=True,
                    private_network_resource=network_resource,
                ),
                artifact_dir=str(layout.artifact_dir),
                metadata={
                    **metadata,
                    "discovery": {
                        "ssh_ready": False,
                        "interfaces": False,
                        "private_interface": False,
                    },
                },
            )
        )

        _run_qemu(command, runner=recorder)
        qemu_started = True
        pid = _read_pidfile(pidfile_path)
        if pid is None:
            raise RuntimeError(f"QEMU did not write pidfile {pidfile_path}")
        metadata = _qemu_manifest_metadata(
            created=True,
            dry_run=False,
            exposure=exposure,
            layout=layout,
            vm_name=vm_name,
            ssh_port=ssh_port,
            acceleration=acceleration,
            memory_mb=memory_mb,
            cpus=cpus,
            artifacts=artifacts,
            command_log_path=command_log_path,
            pidfile_path=pidfile_path,
            serial_log_path=serial_log_path,
            qemu_log_path=qemu_log_path,
            pid=pid,
            command=command,
            private_group=private_group,
            private_ipv4=private_ipv4,
            private_network_resource=network_resource,
            control_mac=control_mac,
            private_mac=private_mac,
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
                    control_interface="control",
                ),
                interfaces=_private_creating_interfaces(
                    ssh_port=ssh_port,
                    private_group=private_group,
                    private_ipv4=private_ipv4,
                    network_resource=network_resource,
                    control_mac=control_mac,
                    private_mac=private_mac,
                ),
                provider_resources=_qemu_provider_resources(
                    exposure=exposure,
                    vm_name=vm_name,
                    artifacts=artifacts,
                    layout=layout,
                    pidfile_path=pidfile_path,
                    pid=pid,
                    include_cache=True,
                    private_network_resource=network_resource,
                ),
                artifact_dir=str(layout.artifact_dir),
                metadata={
                    **metadata,
                    "discovery": {
                        "ssh_ready": False,
                        "interfaces": False,
                        "private_interface": False,
                    },
                },
            )
        )

        try:
            wait_for_ssh(
                host=QEMU_SSH_HOST,
                user=QEMU_SSH_USER,
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
            host=QEMU_SSH_HOST,
            user=QEMU_SSH_USER,
            identity_file=layout.private_key_path,
            known_hosts=layout.known_hosts_path,
            exposure=exposure,
            port=ssh_port,
            runner=recorder,
            source="qemu-ssh-discovery",
            metadata={"vm_name": vm_name},
            prefer_public_or_default=False,
        )
        active_interfaces = _qemu_private_active_interfaces(
            discovered_interfaces,
            ssh_port=ssh_port,
            private_group=private_group,
            private_ipv4=private_ipv4,
            network_resource=network_resource,
            control_mac=control_mac,
            private_mac=private_mac,
        )
        if not any(interface.exposure == "private" for interface in active_interfaces):
            raise RuntimeError("guest interface discovery did not find a private interface")

        private_group_record = update_private_group_allocation(
            provider=provider,
            group=private_group,
            endpoint_id=endpoint_id,
            private_ipv4=private_ipv4,
            private_cidr=private_cidr,
            network_resource=network_resource,
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
                control_interface=_control_interface_name(active_interfaces),
            ),
            interfaces=active_interfaces,
            provider_resources=_qemu_provider_resources(
                exposure=exposure,
                vm_name=vm_name,
                artifacts=artifacts,
                layout=layout,
                pidfile_path=pidfile_path,
                pid=pid,
                include_cache=True,
                private_network_resource=network_resource,
            ),
            artifact_dir=str(layout.artifact_dir),
            metadata={
                **metadata,
                "private_group_record": private_group_record.to_dict(),
                "discovery": {
                    "ssh_ready": True,
                    "interfaces": True,
                    "private_interface": True,
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
            _artifact_paths(artifacts, command_log_path, serial_log_path, qemu_log_path)
        ).to_dict()
        return output
    except Exception as exc:
        if pid is None:
            pid = _read_pidfile(pidfile_path)
        _write_failed_manifest(
            endpoint_id=endpoint_id,
            provider=provider,
            exposure=exposure,
            role=role,
            created_at=created_at,
            layout=layout,
            vm_name=vm_name,
            ssh_port=ssh_port,
            acceleration=acceleration,
            memory_mb=memory_mb,
            cpus=cpus,
            command_log_path=command_log_path,
            pidfile_path=pidfile_path,
            serial_log_path=serial_log_path,
            qemu_log_path=qemu_log_path,
            pid=pid,
            qemu_started=qemu_started,
            command=command,
            error=str(exc),
            private_group=private_group,
            private_ipv4=private_ipv4,
            private_network_resource=network_resource,
            control_mac=control_mac,
            private_mac=private_mac,
        )
        raise


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


def _run_qemu(argv: Sequence[object], *, runner: QemuRunner) -> CommandResult:
    result = runner(argv, timeout=120)
    if not result.ok:
        raise RuntimeError(command_error("QEMU command failed", result))
    return result


def _qemu_wan_command(
    *,
    vm_name: str,
    ssh_port: int,
    acceleration: str,
    memory_mb: int,
    cpus: int,
    disk_path: Path,
    seed_iso_path: Path,
    pidfile_path: Path,
    serial_log_path: Path,
    qemu_log_path: Path,
) -> list[object]:
    host_forward = f"tcp:{QEMU_SSH_HOST}:{ssh_port}-:{QEMU_SSH_GUEST_PORT}"
    return [
        QEMU_SYSTEM_COMMAND,
        "-name",
        vm_name,
        "-accel",
        acceleration,
        "-m",
        str(memory_mb),
        "-smp",
        str(cpus),
        "-drive",
        f"file={disk_path},if=virtio,format=qcow2",
        "-drive",
        f"file={seed_iso_path},if=virtio,format=raw,readonly=on",
        "-netdev",
        f"user,id={QEMU_CONTROL_NETDEV},hostfwd={host_forward}",
        "-device",
        f"virtio-net-pci,netdev={QEMU_CONTROL_NETDEV}",
        "-display",
        "none",
        "-serial",
        f"file:{serial_log_path}",
        "-D",
        str(qemu_log_path),
        "-d",
        "guest_errors",
        "-pidfile",
        str(pidfile_path),
        "-daemonize",
    ]


def _qemu_private_command(
    *,
    vm_name: str,
    ssh_port: int,
    acceleration: str,
    memory_mb: int,
    cpus: int,
    disk_path: Path,
    seed_iso_path: Path,
    pidfile_path: Path,
    serial_log_path: Path,
    qemu_log_path: Path,
    network_resource: Mapping[str, object],
    control_mac: str,
    private_mac: str,
) -> list[object]:
    command = _qemu_wan_command(
        vm_name=vm_name,
        ssh_port=ssh_port,
        acceleration=acceleration,
        memory_mb=memory_mb,
        cpus=cpus,
        disk_path=disk_path,
        seed_iso_path=seed_iso_path,
        pidfile_path=pidfile_path,
        serial_log_path=serial_log_path,
        qemu_log_path=qemu_log_path,
    )
    control_device_index = command.index(f"virtio-net-pci,netdev={QEMU_CONTROL_NETDEV}")
    command[control_device_index] = (
        f"virtio-net-pci,netdev={QEMU_CONTROL_NETDEV},mac={control_mac}"
    )
    daemonize_index = command.index("-display")
    private_endpoint = _private_mcast_endpoint(network_resource)
    command[daemonize_index:daemonize_index] = [
        "-netdev",
        f"socket,id={QEMU_PRIVATE_NETDEV},mcast={private_endpoint}",
        "-device",
        f"virtio-net-pci,netdev={QEMU_PRIVATE_NETDEV},mac={private_mac}",
    ]
    return command


def _requested_positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw_value = (env.get(name) or str(default)).strip()
    try:
        value = int(raw_value, 10)
    except ValueError as exc:
        raise ValueError(f"{name}={raw_value!r} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name}={raw_value!r} must be a positive integer")
    return value


def _requested_private_cidr(env: Mapping[str, str]) -> str:
    raw_value = (env.get(QEMU_PRIVATE_CIDR_ENV) or QEMU_DEFAULT_PRIVATE_CIDR).strip()
    if not raw_value:
        raw_value = QEMU_DEFAULT_PRIVATE_CIDR
    return str(_ipv4_network(raw_value, "private_cidr"))


def _allocate_qemu_private_ipv4(
    *,
    provider: str,
    private_group: str,
    private_cidr: str,
    requested_private_ip: str | None,
) -> str:
    network = _ipv4_network(private_cidr, "private_cidr")
    try:
        record = read_private_group_record(provider, private_group)
        allocated = set(record.allocated_private_ipv4s)
    except FileNotFoundError:
        allocated = set()

    if requested_private_ip is not None:
        address = _ipv4_address(requested_private_ip, "private_ip")
        if address not in network:
            raise ValueError(f"private_ip {requested_private_ip} is outside {private_cidr}")
        if requested_private_ip in allocated:
            raise ValueError(f"private_ip {requested_private_ip} is already allocated")
        return requested_private_ip

    for address in network.hosts():
        private_ipv4 = str(address)
        if private_ipv4.endswith(".1"):
            continue
        if private_ipv4 not in allocated:
            return private_ipv4
    raise RuntimeError(f"no private IPv4 addresses are available in {private_cidr}")


def _qemu_private_network_resource(private_group: str, private_cidr: str) -> dict[str, object]:
    group_component = path_component(private_group)
    mcast_address, mcast_port = _private_mcast_address_port(private_group)
    return {
        "type": "network",
        "provider": "qemu",
        "network_id": _planned_private_network_id(private_group),
        "network_name": f"wire-qemu-{group_component}",
        "private_group": private_group,
        "ip_range": private_cidr,
        "backend": "socket-mcast",
        "netdev": QEMU_PRIVATE_NETDEV,
        "guest_interface": QEMU_PRIVATE_GUEST_IFACE,
        "mcast_address": mcast_address,
        "mcast_port": mcast_port,
        "mcast": f"{mcast_address}:{mcast_port}",
    }


def _qemu_private_network_config(
    *,
    private_ipv4: str,
    private_cidr: str,
    control_mac: str,
    private_mac: str,
) -> dict[str, object]:
    prefixlen = _ipv4_network(private_cidr, "private_cidr").prefixlen
    return {
        "version": 2,
        "ethernets": {
            "control": {
                "match": {"macaddress": control_mac},
                "dhcp4": True,
                "dhcp6": False,
                "optional": True,
            },
            "private": {
                "match": {"macaddress": private_mac},
                "set-name": QEMU_PRIVATE_GUEST_IFACE,
                "dhcp4": False,
                "dhcp6": False,
                "addresses": [f"{private_ipv4}/{prefixlen}"],
                "optional": True,
            },
        },
    }


def _deterministic_mac(namespace: str, *parts: str) -> str:
    digest = sha256(":".join((namespace, *parts)).encode("utf-8")).digest()
    return "52:54:00:" + ":".join(f"{byte:02x}" for byte in digest[:3])


def _private_mcast_address_port(private_group: str) -> tuple[str, int]:
    digest = sha256(path_component(private_group).encode("utf-8")).digest()
    address = f"239.{192 + (digest[0] % 32)}.{digest[1]}.{digest[2]}"
    port = 20000 + (int.from_bytes(digest[3:5], "big") % 20000)
    return address, port


def _private_mcast_endpoint(network_resource: Mapping[str, object]) -> str:
    value = network_resource.get("mcast")
    if isinstance(value, str) and value:
        return value
    address = network_resource.get("mcast_address")
    port = network_resource.get("mcast_port")
    if not isinstance(address, str) or not isinstance(port, int):
        raise RuntimeError("QEMU private network resource is missing multicast endpoint")
    return f"{address}:{port}"


def _ssh_info(
    *,
    layout: object,
    vm_name: str,
    ssh_port: int,
    control_interface: str,
) -> EndpointSSHInfo:
    return EndpointSSHInfo(
        host=QEMU_SSH_HOST,
        user=QEMU_SSH_USER,
        port=ssh_port,
        identity_file=str(getattr(layout, "private_key_path")),
        known_hosts_file=str(getattr(layout, "known_hosts_path")),
        metadata={
            "created_by": "tools/endpoint",
            "transport": "qemu-user-net-hostfwd",
            "vm_name": vm_name,
            "control_interface": control_interface,
        },
    )


def _wan_interface(interface: NetworkInterface, *, ssh_port: int) -> NetworkInterface:
    return replace(
        interface,
        exposure="wan",
        metadata={
            **interface.metadata,
            "type": "qemu-user-net",
            "network": "user",
            "netdev": QEMU_CONTROL_NETDEV,
            "outbound_nat": True,
            "host_forwarded_ssh": True,
            "host": QEMU_SSH_HOST,
            "host_port": ssh_port,
            "guest_port": QEMU_SSH_GUEST_PORT,
        },
    )


def _private_creating_interfaces(
    *,
    ssh_port: int,
    private_group: str,
    private_ipv4: str,
    network_resource: Mapping[str, object],
    control_mac: str,
    private_mac: str,
) -> list[NetworkInterface]:
    return [
        NetworkInterface(
            name="control",
            exposure="control",
            mac=control_mac,
            metadata={
                "planned": True,
                "type": "qemu-user-net-control",
                "network": "user",
                "netdev": QEMU_CONTROL_NETDEV,
                "host": QEMU_SSH_HOST,
                "host_port": ssh_port,
                "guest_port": QEMU_SSH_GUEST_PORT,
            },
        ),
        NetworkInterface(
            name=QEMU_PRIVATE_GUEST_IFACE,
            exposure="private",
            ipv4=private_ipv4,
            mac=private_mac,
            provider_network_id=_network_resource_id(network_resource),
            metadata={
                "planned": True,
                "type": "qemu-private-net",
                "network": "isolated",
                "backend": "socket-mcast",
                "netdev": QEMU_PRIVATE_NETDEV,
                "private_group": private_group,
                "private_ip": private_ipv4,
                "network_resource": dict(network_resource),
                "static_ipv4": True,
            },
        ),
    ]


def _qemu_private_active_interfaces(
    discovered_interfaces: Sequence[NetworkInterface],
    *,
    ssh_port: int,
    private_group: str,
    private_ipv4: str,
    network_resource: Mapping[str, object],
    control_mac: str,
    private_mac: str,
) -> list[NetworkInterface]:
    private_interface = _select_private_interface(
        discovered_interfaces,
        private_ipv4=private_ipv4,
        private_mac=private_mac,
    )
    control_interface = _select_control_interface(
        discovered_interfaces,
        private_interface=private_interface,
        control_mac=control_mac,
    )
    output: list[NetworkInterface] = []
    if control_interface is not None:
        output.append(_control_interface(control_interface, ssh_port=ssh_port))
    if private_interface is not None:
        output.append(
            _private_interface(
                private_interface,
                private_group=private_group,
                private_ipv4=private_ipv4,
                network_resource=network_resource,
                private_mac=private_mac,
            )
        )
    return output


def _select_private_interface(
    interfaces: Sequence[NetworkInterface],
    *,
    private_ipv4: str,
    private_mac: str,
) -> NetworkInterface | None:
    private_mac_lower = private_mac.lower()
    for interface in interfaces:
        if interface.ipv4 == private_ipv4:
            return interface
    for interface in interfaces:
        if (interface.mac or "").lower() == private_mac_lower:
            return interface
    return None


def _select_control_interface(
    interfaces: Sequence[NetworkInterface],
    *,
    private_interface: NetworkInterface | None,
    control_mac: str,
) -> NetworkInterface | None:
    control_mac_lower = control_mac.lower()
    for interface in interfaces:
        if (interface.mac or "").lower() == control_mac_lower:
            return interface
    for interface in interfaces:
        if private_interface is not None and interface.name == private_interface.name:
            continue
        if bool(interface.metadata.get("default_route")):
            return interface
    for interface in interfaces:
        if private_interface is None or interface.name != private_interface.name:
            return interface
    return None


def _control_interface(interface: NetworkInterface, *, ssh_port: int) -> NetworkInterface:
    return replace(
        interface,
        exposure="control",
        provider_network_id=None,
        metadata={
            **interface.metadata,
            "type": "qemu-user-net-control",
            "network": "user",
            "netdev": QEMU_CONTROL_NETDEV,
            "host": QEMU_SSH_HOST,
            "host_port": ssh_port,
            "guest_port": QEMU_SSH_GUEST_PORT,
            "host_forwarded_ssh": True,
        },
    )


def _private_interface(
    interface: NetworkInterface,
    *,
    private_group: str,
    private_ipv4: str,
    network_resource: Mapping[str, object],
    private_mac: str,
) -> NetworkInterface:
    return replace(
        interface,
        exposure="private",
        ipv4=private_ipv4,
        mac=private_mac,
        provider_network_id=_network_resource_id(network_resource),
        metadata={
            **interface.metadata,
            "type": "qemu-private-net",
            "network": "isolated",
            "backend": "socket-mcast",
            "netdev": QEMU_PRIVATE_NETDEV,
            "private_group": private_group,
            "private_ip": private_ipv4,
            "network_resource": dict(network_resource),
            "static_ipv4": True,
        },
    )


def _control_interface_name(interfaces: Sequence[NetworkInterface]) -> str:
    for interface in interfaces:
        if interface.exposure == "control":
            return interface.name
    return "control"


def _qemu_provider_resources(
    *,
    exposure: str,
    vm_name: str,
    artifacts: object,
    layout: object,
    pidfile_path: Path,
    pid: int | None,
    include_cache: bool,
    private_network_resource: Mapping[str, object] | None = None,
) -> object:
    resources = [
        vm_resource(
            vm_name,
            kind="qemu-vm",
            metadata={
                "provider": "qemu",
                "pid": pid,
                "pidfile": str(pidfile_path),
            },
        ),
    ]
    if pid is not None:
        resources.insert(
            1,
            process_resource(
                pid,
                name=vm_name,
                metadata={
                    "provider": "qemu",
                    "vm_name": vm_name,
                    "pidfile": str(pidfile_path),
                },
            ),
        )
    if private_network_resource is not None:
        resources.append(_private_network_provider_resource(private_network_resource))
    resources.extend(
        [
            *artifacts.file_resources(include_cache=include_cache),  # type: ignore[attr-defined]
            file_resource(pidfile_path, name="qemu-pidfile", cleanup=False),
            file_resource(getattr(layout, "private_key_path"), name="ssh-private-key"),
            file_resource(getattr(layout, "known_hosts_path"), name="ssh-known-hosts"),
        ]
    )
    return provider_resources(
        resources,
        cleanup_order=["process", "qemu-vm", "local-file"],
        metadata={
            "provider": "qemu",
            "exposure": exposure,
            "pid": pid,
            "pidfile": str(pidfile_path),
        },
    )


def _qemu_manifest_metadata(
    *,
    created: bool,
    dry_run: bool,
    exposure: str,
    layout: object,
    vm_name: str,
    ssh_port: int,
    acceleration: str,
    memory_mb: int,
    cpus: int,
    artifacts: object,
    command_log_path: Path,
    pidfile_path: Path,
    serial_log_path: Path,
    qemu_log_path: Path,
    pid: int | None,
    command: Sequence[object],
    private_group: str | None = None,
    private_ipv4: str | None = None,
    private_network_resource: Mapping[str, object] | None = None,
    control_mac: str | None = None,
    private_mac: str | None = None,
) -> dict[str, object]:
    control_network: dict[str, object] = {
        "type": "user",
        "netdev": QEMU_CONTROL_NETDEV,
        "host_forward": f"tcp:{QEMU_SSH_HOST}:{ssh_port}-:{QEMU_SSH_GUEST_PORT}",
    }
    if control_mac is not None:
        control_network["mac"] = control_mac
    qemu_network: dict[str, object] = {
        "exposure": exposure,
        "control": control_network,
    }
    metadata: dict[str, object] = {
        "created": created,
        "dry_run": dry_run,
        "state_dir": str(getattr(layout, "state_dir")),
        "manifest_path": str(getattr(layout, "manifest_path")),
        "qemu": {
            "command": QEMU_SYSTEM_COMMAND,
            "argv": [str(part) for part in command],
            "vm_name": vm_name,
            "pid": pid,
            "pidfile_path": str(pidfile_path),
            "serial_log_path": str(serial_log_path),
            "qemu_log_path": str(qemu_log_path),
            "command_log_path": str(command_log_path),
            "daemonize": True,
            "acceleration": acceleration,
            "memory_mb": memory_mb,
            "cpus": cpus,
            "ssh_host": QEMU_SSH_HOST,
            "ssh_port": ssh_port,
            "ssh_guest_port": QEMU_SSH_GUEST_PORT,
            "control_netdev": QEMU_CONTROL_NETDEV,
            "network": qemu_network,
        },
        **artifacts.to_manifest_metadata(),  # type: ignore[attr-defined]
    }
    if private_network_resource is not None:
        private_metadata = dict(private_network_resource)
        if private_ipv4 is not None:
            private_metadata["private_ip"] = private_ipv4
            private_metadata["ipv4"] = private_ipv4
        if private_mac is not None:
            private_metadata["mac"] = private_mac
        if private_group is not None:
            private_metadata["private_group"] = private_group
        qemu_network["private"] = private_metadata
        metadata["private_group"] = private_group
        metadata["private_ip"] = private_ipv4
        metadata["private_network"] = private_metadata
        metadata["private"] = {
            "private_group": private_group,
            "private_ip": private_ipv4,
            "network": private_metadata,
        }
    return metadata


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
    acceleration: str,
    memory_mb: int,
    cpus: int,
    command_log_path: Path,
    pidfile_path: Path,
    serial_log_path: Path,
    qemu_log_path: Path,
    pid: int | None,
    qemu_started: bool,
    command: Sequence[object],
    error: str,
    private_group: str | None = None,
    private_ipv4: str | None = None,
    private_network_resource: Mapping[str, object] | None = None,
    control_mac: str | None = None,
    private_mac: str | None = None,
) -> None:
    try:
        artifacts = plan_guest_artifacts(
            endpoint_id=endpoint_id,
            provider=provider,
            layout=layout,  # type: ignore[arg-type]
            disk_format="qcow2",
            include_network_config=exposure == "private",
        )
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
                control_interface="control" if exposure == "private" else "wan",
            ),
            interfaces=_planned_interfaces(
                exposure=exposure,
                ssh_port=ssh_port,
                private_group=private_group,
                private_ip=private_ipv4,
            ),
            provider_resources=_qemu_provider_resources(
                exposure=exposure,
                vm_name=vm_name,
                artifacts=artifacts,
                layout=layout,
                pidfile_path=pidfile_path,
                pid=pid,
                include_cache=True,
                private_network_resource=private_network_resource,
            ),
            artifact_dir=str(getattr(layout, "artifact_dir")),
            metadata={
                **_qemu_manifest_metadata(
                    created=qemu_started,
                    dry_run=False,
                    exposure=exposure,
                    layout=layout,
                    vm_name=vm_name,
                    ssh_port=ssh_port,
                    acceleration=acceleration,
                    memory_mb=memory_mb,
                    cpus=cpus,
                    artifacts=artifacts,
                    command_log_path=command_log_path,
                    pidfile_path=pidfile_path,
                    serial_log_path=serial_log_path,
                    qemu_log_path=qemu_log_path,
                    pid=pid,
                    command=command,
                    private_group=private_group,
                    private_ipv4=private_ipv4,
                    private_network_resource=private_network_resource,
                    control_mac=control_mac,
                    private_mac=private_mac,
                ),
                "error": error,
            },
        )
        write_endpoint_manifest(manifest)
    except Exception:
        return


def _artifact_paths(
    artifacts: object,
    command_log_path: Path,
    serial_log_path: Path,
    qemu_log_path: Path,
) -> list[ArtifactPath]:
    return [
        *artifacts.artifact_paths(),  # type: ignore[attr-defined]
        ArtifactPath(name="qemu-command-log", path=str(command_log_path)),
        ArtifactPath(name="qemu-serial-log", path=str(serial_log_path)),
        ArtifactPath(name="qemu-log", path=str(qemu_log_path)),
    ]


def _private_network_provider_resource(
    network_resource: Mapping[str, object],
) -> ProviderResource:
    provider_id = _network_resource_id(network_resource)
    if provider_id is None:
        raise RuntimeError("QEMU private network resource is missing a network id")
    name = network_resource.get("network_name")
    return ProviderResource(
        kind="network",
        provider_id=provider_id,
        name=name if isinstance(name, str) and name else provider_id,
        cleanup=False,
        metadata={
            "type": "qemu-private-network",
            **dict(network_resource),
        },
    )


def _network_resource_id(network_resource: Mapping[str, object]) -> str | None:
    for key in ("network_id", "provider_id", "id"):
        value = network_resource.get(key)
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str) and value:
            return value
    return None


def _ipv4_network(value: str, name: str) -> IPv4Network:
    try:
        network = ip_network(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid IPv4 CIDR: {value}") from exc
    if not isinstance(network, IPv4Network):
        raise ValueError(f"{name} must be an IPv4 CIDR: {value}")
    return network


def _ipv4_address(value: str, name: str) -> IPv4Address:
    try:
        address = ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid IPv4 address: {value}") from exc
    if not isinstance(address, IPv4Address):
        raise ValueError(f"{name} must be an IPv4 address: {value}")
    return address


def _read_pidfile(path: Path) -> int | None:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    if text == "":
        return None
    try:
        pid = int(text, 10)
    except ValueError:
        return None
    return pid if pid > 0 else None


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


def _planned_private_metadata(
    private_group: str | None,
    private_ip: str | None,
    *,
    private_cidr: str | None = None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "planned": True,
        "provider": "qemu",
        "network_id": _planned_private_network_id(private_group),
        "backend": "socket-mcast",
        "netdev": "private0",
        "ip_range": private_cidr or QEMU_DEFAULT_PRIVATE_CIDR,
    }
    if private_group is not None:
        mcast_address, mcast_port = _private_mcast_address_port(private_group)
        metadata["private_group"] = private_group
        metadata["network_name"] = f"wire-qemu-{path_component(private_group)}"
        metadata["mcast_address"] = mcast_address
        metadata["mcast_port"] = mcast_port
        metadata["mcast"] = f"{mcast_address}:{mcast_port}"
    if private_ip is not None:
        metadata["private_ip"] = private_ip
        metadata["ipv4"] = private_ip
    return metadata
