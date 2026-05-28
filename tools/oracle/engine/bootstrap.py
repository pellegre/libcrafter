"""Oracle-owned endpoint bootstrap plans and lab bootstrap hooks."""

from __future__ import annotations

import shlex
from collections.abc import Callable, Mapping

from tools.lab.engine import bootstrap as lab_bootstrap
from tools.lab.engine.model import LabEndpoint, LabRole, LabSession
from tools.lab.engine.repo import RepoBootstrapCommand, RepoBootstrapContext

from .live import LiveCommandPlan, LiveEndpoint, LiveValidationCheck
from .model import JSONObject


LIBCRAFTER_ROLE = "libcrafter"
REFERENCE_BACKEND_ROLE = "reference_backend"
BOOTSTRAP_ROLES = (LIBCRAFTER_ROLE, REFERENCE_BACKEND_ROLE)

LIBCRAFTER_BOOTSTRAP_PACKAGES = (
    "build-essential",
    "ca-certificates",
    "clang",
    "curl",
    "git",
    "iproute2",
    "iputils-ping",
    "libpcap-dev",
    "pkg-config",
    "python3",
)
REFERENCE_BOOTSTRAP_PACKAGES = (
    "ca-certificates",
    "curl",
    "git",
    "iproute2",
    "iputils-ping",
    "python3",
)
PYTHON_DEPENDENCY_RUNNER = "uv"
DEFAULT_CAPABILITY_REPORT_ARTIFACT = "live-artifacts/oracle-live/capabilities.json"
LIBCRAFTER_VALIDATION_COMMAND = "cargo build -p oracle-adapters --bin live_endpoint"
REFERENCE_VALIDATION_COMMAND = "tools/oracle/run backend-info --backend scapy"
TOPOLOGY_METADATA_KEYS = (
    "private_network",
    "private_group",
    "bridged_lan",
    "bridge_interface_env",
)


def endpoint_bootstrap_topology(
    provider_metadata: Mapping[str, object],
    provider_capabilities: Mapping[str, object] | None = None,
) -> JSONObject:
    """Extract oracle bootstrap topology from provider-neutral report metadata."""

    topology: JSONObject = {}
    for key in TOPOLOGY_METADATA_KEYS:
        value = provider_metadata.get(key)
        if value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            topology[key] = value
    topology["capability_artifact"] = _capability_artifact(
        provider_capabilities or {},
        {},
    )
    return topology


def endpoint_bootstrap_plan(
    provider: str,
    dry_run: bool,
    provider_capabilities: Mapping[str, object],
    topology_metadata: Mapping[str, object],
) -> list[LiveCommandPlan]:
    """Return oracle endpoint bootstrap command plans for one lab provider."""

    topology = _topology_metadata(topology_metadata)
    capability_artifact = _capability_artifact(
        provider_capabilities,
        topology_metadata,
    )
    capabilities = _json_object(provider_capabilities)
    return [
        LiveCommandPlan(
            role=LIBCRAFTER_ROLE,
            purpose="bootstrap-libcrafter-endpoint",
            argv=[
                "bash",
                "-lc",
                (
                    "sync-repository && apt-get install libcrafter packages && "
                    "rustup install-if-missing && "
                    "cargo build -p oracle-adapters --bin live_endpoint"
                ),
            ],
            sends_live_packets=False,
            expects_live_packets=False,
            metadata={
                "provider": provider,
                "dry_run": dry_run,
                "repository_sync": True,
                **topology,
                "system_packages": list(LIBCRAFTER_BOOTSTRAP_PACKAGES),
                "python_dependency_runner": PYTHON_DEPENDENCY_RUNNER,
                "uv": "install_if_missing",
                "rust": "install_if_missing",
                "validation": LIBCRAFTER_VALIDATION_COMMAND,
                "artifact_path": "live-artifacts/bootstrap/libcrafter/bootstrap.env",
                "capability_artifact": capability_artifact,
                "provider_capabilities": capabilities,
            },
        ),
        LiveCommandPlan(
            role=REFERENCE_BACKEND_ROLE,
            purpose="bootstrap-reference-endpoint",
            argv=[
                "bash",
                "-lc",
                (
                    "sync-repository && apt-get install reference packages && "
                    "tools/oracle/run backend-info --backend scapy && "
                    "report optional tshark availability"
                ),
            ],
            sends_live_packets=False,
            expects_live_packets=False,
            metadata={
                "provider": provider,
                "backend": "scapy",
                "dry_run": dry_run,
                "repository_sync": True,
                **topology,
                "system_packages": list(REFERENCE_BOOTSTRAP_PACKAGES),
                "python_dependency_runner": PYTHON_DEPENDENCY_RUNNER,
                "uv": "install_if_missing",
                "validation": REFERENCE_VALIDATION_COMMAND,
                "tshark": {
                    "availability_reported": True,
                    "required_for_scapy_live_exchange": False,
                },
                "artifact_path": (
                    "live-artifacts/bootstrap/reference_backend/bootstrap.env"
                ),
                "capability_artifact": capability_artifact,
                "provider_capabilities": capabilities,
            },
        ),
    ]


def validate_endpoint_bootstrap(
    provider: str,
    commands: list[LiveCommandPlan],
    *,
    dry_run: bool,
    topology_metadata: Mapping[str, object],
) -> LiveValidationCheck:
    """Validate oracle endpoint bootstrap invariants for one provider."""

    errors: list[str] = []
    commands_by_role = {command.role: command for command in commands}
    capability_artifact = _capability_artifact({}, topology_metadata)
    topology = _topology_metadata(topology_metadata)
    for role in BOOTSTRAP_ROLES:
        if role not in commands_by_role:
            errors.append(f"missing endpoint bootstrap role: {role}")

    for command in commands:
        if command.sends_live_packets or command.expects_live_packets:
            errors.append("endpoint bootstrap commands cannot exchange live packets")
        if command.metadata.get("provider") != provider:
            errors.append(
                f"endpoint bootstrap must target {_provider_label(provider)}: {command.role}"
            )
        if not bool(command.metadata.get("repository_sync")):
            errors.append(f"endpoint bootstrap must sync repository: {command.role}")
        _validate_topology(command, topology, provider, errors)
        if not command.metadata.get("artifact_path"):
            errors.append(f"endpoint bootstrap must write artifacts: {command.role}")
        if command.metadata.get("capability_artifact") != capability_artifact:
            errors.append(f"endpoint bootstrap must report capabilities: {command.role}")

    libcrafter = commands_by_role.get(LIBCRAFTER_ROLE)
    if libcrafter is not None:
        packages = set(_string_sequence(libcrafter.metadata.get("system_packages", [])))
        for package in ("libpcap-dev", "pkg-config", "clang"):
            if package not in packages:
                errors.append(f"libcrafter bootstrap missing package: {package}")
        if (
            libcrafter.metadata.get("python_dependency_runner")
            != PYTHON_DEPENDENCY_RUNNER
        ):
            errors.append("libcrafter bootstrap must use uv for Python dependencies")
        if libcrafter.metadata.get("uv") != "install_if_missing":
            errors.append("libcrafter bootstrap must install uv when missing")
        if libcrafter.metadata.get("rust") != "install_if_missing":
            errors.append("libcrafter bootstrap must install Rust when missing")
        if libcrafter.metadata.get("validation") != LIBCRAFTER_VALIDATION_COMMAND:
            errors.append("libcrafter bootstrap must validate live_endpoint build")

    reference = commands_by_role.get(REFERENCE_BACKEND_ROLE)
    if reference is not None:
        packages = set(_string_sequence(reference.metadata.get("system_packages", [])))
        for package in ("python3", "curl"):
            if package not in packages:
                errors.append(f"reference bootstrap missing package: {package}")
        if (
            reference.metadata.get("python_dependency_runner")
            != PYTHON_DEPENDENCY_RUNNER
        ):
            errors.append("reference bootstrap must use uv for Python dependencies")
        if reference.metadata.get("uv") != "install_if_missing":
            errors.append("reference bootstrap must install uv when missing")
        if reference.metadata.get("validation") != REFERENCE_VALIDATION_COMMAND:
            errors.append("reference bootstrap must validate Scapy backend availability")
        tshark = reference.metadata.get("tshark")
        if not isinstance(tshark, dict):
            errors.append("reference bootstrap must report tshark availability")
        elif tshark.get("required_for_scapy_live_exchange") is not False:
            errors.append("tshark must remain optional for Scapy live exchange")

    return LiveValidationCheck(
        name=f"{provider}-endpoint-bootstrap",
        passed=not errors,
        subject="libcrafter,reference_backend",
        errors=errors,
        metadata={
            "provider": provider,
            "dry_run": dry_run,
            "endpoint_count": 2,
            "repository_sync": "both_endpoints",
            **_validation_topology_metadata(topology),
            "tshark_required": False,
        },
    )


def endpoint_bootstrap_command_hook(
    provider: str,
    topology_metadata: Mapping[str, object],
) -> Callable[[RepoBootstrapContext], RepoBootstrapCommand]:
    """Return a lab repo bootstrap hook for oracle endpoint roles."""

    def _hook(context: RepoBootstrapContext) -> RepoBootstrapCommand:
        return repo_bootstrap_command(
            provider=provider,
            context=context,
            topology_metadata=topology_metadata,
        )

    return _hook


def repo_bootstrap_command(
    *,
    provider: str,
    context: RepoBootstrapContext,
    topology_metadata: Mapping[str, object],
) -> RepoBootstrapCommand:
    """Render a workload bootstrap command from lab repository context."""

    script = _endpoint_bootstrap_script(context, topology_metadata=topology_metadata)
    return RepoBootstrapCommand(
        argv=["bash", "-lc", script],
        metadata={
            "provider": provider,
            "workload": "oracle-live",
            "role": context.role.name,
            "remote_dir": context.remote_dir,
            "remote_artifact_root": context.remote_artifact_root,
            **_topology_metadata(topology_metadata),
        },
    )


def endpoint_bootstrap_command(
    *,
    provider: str,
    endpoint: LiveEndpoint,
    peer: LiveEndpoint,
    remote_archive: str,
    remote_dir: str,
    topology_metadata: Mapping[str, object],
) -> list[str]:
    """Return the oracle bootstrap command for one legacy live endpoint call."""

    context = _context_from_live_endpoint(
        provider=provider,
        endpoint=endpoint,
        peer=peer,
        remote_archive=remote_archive,
        remote_dir=remote_dir,
    )
    return repo_bootstrap_command(
        provider=provider,
        context=context,
        topology_metadata=topology_metadata,
    ).argv


def _endpoint_bootstrap_script(
    context: RepoBootstrapContext,
    *,
    topology_metadata: Mapping[str, object],
) -> str:
    role = context.role.name
    if role not in BOOTSTRAP_ROLES:
        raise ValueError(f"unsupported oracle bootstrap role: {role}")

    artifact_dir = lab_bootstrap.role_artifact_dir(context, "bootstrap")
    lines = [
        "set -euo pipefail",
        lab_bootstrap.CLOUD_INIT_WAIT_LINE,
        lab_bootstrap.cd_remote_dir_line(context),
        *lab_bootstrap.context_export_lines(context, require_peer=True),
        *_topology_alias_export_lines(context, topology_metadata),
        lab_bootstrap.DEBIAN_FRONTEND_LINE,
        *lab_bootstrap.role_artifact_dir_lines(artifact_dir),
        *lab_bootstrap.package_install_lines(_packages_for_role(role)),
        *_install_uv_lines(),
    ]
    if role == LIBCRAFTER_ROLE:
        lines.extend(
            lab_bootstrap.rust_toolchain_lines(
                install=True,
                load_env=True,
                profile="minimal",
            )
        )
        lines.extend(lab_bootstrap.cargo_build_lines([LIBCRAFTER_VALIDATION_COMMAND]))
        lines.extend(
            lab_bootstrap.environment_artifact_lines(
                artifact_dir,
                _libcrafter_env_artifact(topology_metadata),
            )
        )
        return "\n".join(lines)

    lines.extend(
        [
            (
                f"{REFERENCE_VALIDATION_COMMAND} > "
                f"\"${lab_bootstrap.BOOTSTRAP_ARTIFACT_DIR_ENV}/reference-backend.json\""
            ),
            (
                "if command -v tshark >/dev/null 2>&1; then "
                "tshark_available=true; else tshark_available=false; fi"
            ),
        ]
    )
    lines.extend(
        lab_bootstrap.environment_artifact_lines(
            artifact_dir,
            _reference_env_artifact(topology_metadata),
        )
    )
    return "\n".join(lines)


def _packages_for_role(role: str) -> tuple[str, ...]:
    if role == LIBCRAFTER_ROLE:
        return LIBCRAFTER_BOOTSTRAP_PACKAGES
    if role == REFERENCE_BACKEND_ROLE:
        return REFERENCE_BOOTSTRAP_PACKAGES
    raise ValueError(f"unsupported oracle bootstrap role: {role}")


def _install_uv_lines() -> list[str]:
    return [
        "install_uv() {",
        "  if ! command -v uv >/dev/null 2>&1; then",
        "    curl -LsSf https://astral.sh/uv/install.sh | sh",
        "    export PATH=\"$HOME/.local/bin:$PATH\"",
        "    ln -sf \"$(command -v uv)\" /usr/local/bin/uv || true",
        "  fi",
        "  export PATH=\"$HOME/.local/bin:$PATH\"",
        "  command -v uv >/dev/null 2>&1",
        "}",
        "install_uv",
    ]


def _libcrafter_env_artifact(
    topology_metadata: Mapping[str, object],
) -> lab_bootstrap.BootstrapEnvArtifact:
    shell_values = _address_artifact_shell_values(topology_metadata)
    shell_values.update(
        {
            "role": "$LIBCRAFTER_ENDPOINT_ROLE",
            "uv": "$(command -v uv)",
            "rustc": "$(rustc --version)",
            "cargo": "$(cargo --version)",
            "finished_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        }
    )
    return lab_bootstrap.BootstrapEnvArtifact(
        values={
            "repository_synced": "true",
            "python_dependency_runner": PYTHON_DEPENDENCY_RUNNER,
            "libcrafter_oracle_bin": "live_endpoint",
            "libcrafter_oracle_bin_build": "ok",
        },
        shell_values=shell_values,
    )


def _reference_env_artifact(
    topology_metadata: Mapping[str, object],
) -> lab_bootstrap.BootstrapEnvArtifact:
    shell_values = _address_artifact_shell_values(topology_metadata)
    shell_values.update(
        {
            "role": "$LIBCRAFTER_ENDPOINT_ROLE",
            "uv": "$(command -v uv)",
            "tshark_available": "$tshark_available",
            "finished_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        }
    )
    return lab_bootstrap.BootstrapEnvArtifact(
        values={
            "repository_synced": "true",
            "python_dependency_runner": PYTHON_DEPENDENCY_RUNNER,
            "reference_backend_info": "ok",
            "tshark_required": "false",
        },
        shell_values=shell_values,
    )


def _address_artifact_shell_values(
    topology_metadata: Mapping[str, object],
) -> dict[str, str]:
    if bool(topology_metadata.get("bridged_lan")):
        return {
            "lan_ipv4": "$LIBCRAFTER_LAN_IPV4",
            "peer_lan_ipv4": "$LIBCRAFTER_PEER_LAN_IPV4",
            "lan_interface": "$LIBCRAFTER_LAN_INTERFACE",
        }
    return {
        "private_ipv4": "$LIBCRAFTER_PRIVATE_IPV4",
        "peer_private_ipv4": "$LIBCRAFTER_PEER_PRIVATE_IPV4",
        "private_interface": "$LIBCRAFTER_PRIVATE_INTERFACE",
    }


def _topology_alias_export_lines(
    context: RepoBootstrapContext,
    topology_metadata: Mapping[str, object],
) -> list[str]:
    if not bool(topology_metadata.get("bridged_lan")):
        return []
    peer_ipv4 = lab_bootstrap.peer_private_ipv4(context, required=True)
    return [
        f"export LIBCRAFTER_LAN_IPV4={shlex.quote(context.endpoint.ipv4)}",
        f"export LIBCRAFTER_PEER_LAN_IPV4={shlex.quote(peer_ipv4)}",
        f"export LIBCRAFTER_LAN_INTERFACE={shlex.quote(context.endpoint.interface)}",
    ]


def _context_from_live_endpoint(
    *,
    provider: str,
    endpoint: LiveEndpoint,
    peer: LiveEndpoint,
    remote_archive: str,
    remote_dir: str,
) -> RepoBootstrapContext:
    role = LabRole(name=endpoint.role, peer_roles=[peer.role])
    peer_role = LabRole(name=peer.role, peer_roles=[endpoint.role])
    lab_endpoint = LabEndpoint(
        endpoint_id=_lab_endpoint_id(endpoint.role),
        role=endpoint.role,
        interface=endpoint.interface,
        ipv4=endpoint.address,
        ipv6=endpoint.ipv6_address,
        metadata=endpoint.metadata,
    )
    lab_peer = LabEndpoint(
        endpoint_id=_lab_endpoint_id(peer.role),
        role=peer.role,
        interface=peer.interface,
        ipv4=peer.address,
        ipv6=peer.ipv6_address,
        metadata=peer.metadata,
    )
    endpoints_by_role = {
        lab_endpoint.role: lab_endpoint,
        lab_peer.role: lab_peer,
    }
    session = LabSession(
        provider=provider,
        wire_provider=provider,
        wire_exposure=_wire_exposure(endpoint.metadata),
        session_id=f"{provider}-oracle-bootstrap",
        roles=[role, peer_role],
        endpoints=[lab_endpoint, lab_peer],
        remote_dir=remote_dir,
        dry_run=True,
    )
    return RepoBootstrapContext(
        session=session,
        endpoint=lab_endpoint,
        role=role,
        remote_archive=remote_archive,
        remote_dir=remote_dir,
        remote_artifact_root="live-artifacts",
        endpoints_by_role=endpoints_by_role,
    )


def _lab_endpoint_id(role: str) -> str:
    return f"oracle-{role.replace('_', '-')}"


def _wire_exposure(metadata: Mapping[str, object]) -> str:
    exposure = metadata.get("wire_exposure") or metadata.get("exposure")
    if isinstance(exposure, str) and exposure:
        return exposure
    if bool(metadata.get("bridged_lan")):
        return "lan"
    return "private"


def _validate_topology(
    command: LiveCommandPlan,
    topology: JSONObject,
    provider: str,
    errors: list[str],
) -> None:
    if "private_network" in topology:
        expected_private = bool(topology["private_network"])
        actual_private = bool(command.metadata.get("private_network"))
        if expected_private and not actual_private:
            errors.append(
                f"endpoint bootstrap must preserve private topology: {command.role}"
            )
        if not expected_private and actual_private:
            errors.append(
                f"endpoint bootstrap must not require private network: {command.role}"
            )
    private_group = topology.get("private_group")
    if isinstance(private_group, str) and private_group:
        if command.metadata.get("private_group") != private_group:
            errors.append(
                f"endpoint bootstrap must use {provider} private group: {command.role}"
            )
    if topology.get("bridged_lan") is True and not bool(
        command.metadata.get("bridged_lan")
    ):
        errors.append(
            f"endpoint bootstrap must preserve bridged LAN topology: {command.role}"
        )
    bridge_env = topology.get("bridge_interface_env")
    if isinstance(bridge_env, str) and bridge_env:
        if command.metadata.get("bridge_interface_env") != bridge_env:
            errors.append(
                f"endpoint bootstrap must preserve bridge interface env: {command.role}"
            )


def _topology_metadata(value: Mapping[str, object]) -> JSONObject:
    output: JSONObject = {}
    for key, item in value.items():
        if key == "capability_artifact" or not isinstance(key, str):
            continue
        if isinstance(item, (str, int, float, bool)) or item is None:
            output[key] = item
    return output


def _validation_topology_metadata(topology: JSONObject) -> JSONObject:
    return {
        key: value
        for key, value in topology.items()
        if key in {"private_network", "private_group", "bridged_lan"}
    }


def _capability_artifact(
    provider_capabilities: Mapping[str, object],
    topology_metadata: Mapping[str, object],
) -> str:
    for value in (
        topology_metadata.get("capability_artifact"),
        provider_capabilities.get("capability_report_artifact"),
    ):
        if isinstance(value, str) and value:
            return value
    return DEFAULT_CAPABILITY_REPORT_ARTIFACT


def _json_object(value: Mapping[str, object]) -> JSONObject:
    return {
        str(key): item
        for key, item in value.items()
        if isinstance(key, str) and _json_scalar_or_container(item)
    }


def _json_scalar_or_container(value: object) -> bool:
    if value is None or isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, list):
        return all(_json_scalar_or_container(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _json_scalar_or_container(item)
            for key, item in value.items()
        )
    return False


def _string_sequence(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    if isinstance(value, tuple):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _provider_label(provider: str) -> str:
    return {
        "hetzner": "Hetzner",
        "qemu": "QEMU",
        "virtualbox": "VirtualBox",
    }.get(provider, provider)
