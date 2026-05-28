"""QEMU oracle live orchestration planning.

This adapter maps the oracle two-endpoint live lab onto the local QEMU wire
provider. QEMU uses a private same-segment VM network, so it does not inherit
Hetzner's routed-transit TTL or checksum mutation policy.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace

from tools.lab.engine.model import (
    LabCommandPlan,
    LabRequest,
    LabRole,
)
from tools.lab.engine.providers.common import validate_remote_dir
from tools.lab.engine.providers.qemu import QEMU_LAB_PROVIDER_ADAPTER
from tools.lab.engine import wire_client
from tools.wire.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)

from .base import LiveProviderAdapter
from .policy import wire_comparison_policy
from ..live import (
    LiveCommandPlan,
    LiveEndpoint,
    LiveExchangePlan,
    LiveValidationCheck,
    live_endpoint_from_lab_endpoint,
)
from ..model import JSONObject, PacketPlan


PROVIDER_NAME = "qemu"
WIRE_ENTRYPOINT = "tools/wire/run"
ORACLE_LIVE_SUITE = "oracle-live"
ORACLE_PRIVATE_GROUP = "oracle-live-private"
PRIVATE_NETWORK_CIDR = "10.77.0.0/24"
LIBCRAFTER_PRIVATE_ADDRESS = "10.77.0.10"
REFERENCE_PRIVATE_ADDRESS = "10.77.0.20"
LIBCRAFTER_BOOTSTRAP_PACKAGES = [
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
]
REFERENCE_BOOTSTRAP_PACKAGES = [
    "ca-certificates",
    "curl",
    "git",
    "iproute2",
    "iputils-ping",
    "python3",
]
PYTHON_DEPENDENCY_RUNNER = "uv"
CAPABILITY_REPORT_ARTIFACT = "live-artifacts/oracle-live/capabilities.json"
PROVIDER_CAPABILITY_NAMES = (
    "ipv4_unicast",
    "ipv6_unicast",
    "link_layer_send",
    "link_layer_capture",
    "broadcast",
    "provider_mac_known",
    "controlled_services",
    "controlled_router",
)
QEMU_WIRE_POLICY: JSONObject = {
    "ipv4_header_mutable": False,
    "l3_send_adds_link_layer_metadata": False,
    "transit_decrements_ipv4_ttl": False,
}


def qemu_default_provider_capabilities(
    *,
    dry_run: bool,
    source: str = "planned-defaults",
) -> JSONObject:
    """Return conservative QEMU private-network capability defaults."""

    capabilities = QEMU_LAB_PROVIDER_ADAPTER.default_provider_capabilities(
        dry_run=dry_run,
        source=source,
    )
    capabilities["capability_report_artifact"] = CAPABILITY_REPORT_ARTIFACT
    capabilities.setdefault("wire_policy", dict(QEMU_WIRE_POLICY))
    return capabilities


def normalize_qemu_provider_capabilities(
    raw: JSONObject,
    *,
    dry_run: bool | None = None,
    source: str | None = None,
) -> JSONObject:
    """Return flat capability keys plus legacy aliases consumed by corpus logic."""

    normalized = QEMU_LAB_PROVIDER_ADAPTER.normalize_provider_capabilities(
        raw,
        dry_run=dry_run,
        source=source,
    )
    normalized["capability_report_artifact"] = raw.get(
        "capability_report_artifact",
        CAPABILITY_REPORT_ARTIFACT,
    )
    normalized.setdefault("wire_policy", dict(QEMU_WIRE_POLICY))
    return normalized


def qemu_token_configured() -> bool:
    """Return whether QEMU provider execution can pass credential gating."""

    return QEMU_LAB_PROVIDER_ADAPTER.credentials_available()


def qemu_private_network_plan(*, dry_run: bool) -> JSONObject:
    """Return the local VM resources required for an oracle QEMU lab."""

    return _oracle_planned_infrastructure(dry_run=dry_run)


def qemu_packet_exchange_metadata(*, dry_run: bool) -> JSONObject:
    """Return packet-exchange network metadata for the QEMU private lab."""

    return _oracle_packet_exchange_metadata(dry_run=dry_run)


def qemu_endpoints(*, dry_run: bool) -> dict[str, LiveEndpoint]:
    """Return deterministic endpoint roles for the QEMU oracle lab."""

    return _oracle_planned_endpoints(dry_run=dry_run)


def qemu_wire_endpoint_plan(
    *,
    dry_run: bool,
    client: wire_client.WireClient | None = None,
    private_group: str = ORACLE_PRIVATE_GROUP,
    confirm_live_run: bool = False,
    created_endpoint_ids: list[str] | None = None,
) -> dict[str, object]:
    """Create or plan the two private wire endpoints used by QEMU oracle runs."""

    return _oracle_wire_endpoint_plan(
        dry_run=dry_run,
        client=client,
        private_group=private_group,
        confirm_live_run=confirm_live_run,
        created_endpoint_ids=created_endpoint_ids,
    )


def _live_endpoint_from_wire_plan(
    endpoint_plan: JSONObject,
    *,
    role: str,
    private_ip: str,
    peer_address: str,
    dry_run: bool,
) -> LiveEndpoint:
    interface = _private_interface(endpoint_plan)
    address = _string_or(interface.get("ipv4"), private_ip)
    return LiveEndpoint(
        endpoint_id=_string_or(endpoint_plan.get("endpoint_id"), f"qemu-planned-{role}"),
        role=role,
        interface=_string_or(interface.get("name"), "private"),
        address=address,
        ipv6_address=_optional_string(interface.get("ipv6")),
        metadata={
            "provider": PROVIDER_NAME,
            "exposure": "private",
            "dry_run": dry_run,
            "creates_infrastructure": not dry_run,
            "would_create_infrastructure": dry_run,
            "isolated_network": True,
            "private_network": True,
            "private_network_cidr": PRIVATE_NETWORK_CIDR,
            "resource_type": "wire-endpoint",
            "peer_role": (
                "reference_backend" if role == "libcrafter" else "libcrafter"
            ),
            "peer_address": peer_address,
            "wire_endpoint_plan": endpoint_plan,
            "manifest_path": endpoint_plan.get("manifest_path"),
            "artifact_dir": endpoint_plan.get("artifact_dir"),
            "private_group": _wire_private_group(endpoint_plan),
            "provider_network_id": interface.get("provider_network_id"),
            "mac_address": interface.get("mac"),
            **({"backend": "scapy"} if role == "reference_backend" else {}),
        },
    )


def _private_interface(endpoint_plan: JSONObject) -> JSONObject:
    interfaces = endpoint_plan.get("interfaces")
    if isinstance(interfaces, list):
        for item in interfaces:
            if isinstance(item, dict) and item.get("exposure") == "private":
                return {str(key): value for key, value in item.items() if isinstance(key, str)}
        for item in interfaces:
            if isinstance(item, dict):
                return {str(key): value for key, value in item.items() if isinstance(key, str)}
    return {}


def _wire_private_group(endpoint_plan: JSONObject) -> str | None:
    metadata = endpoint_plan.get("metadata")
    if isinstance(metadata, dict):
        private_group = metadata.get("private_group")
        if isinstance(private_group, str):
            return private_group
    interface = _private_interface(endpoint_plan)
    interface_metadata = interface.get("metadata")
    if isinstance(interface_metadata, dict):
        private_group = interface_metadata.get("private_group")
        if isinstance(private_group, str):
            return private_group
    return None


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _string_or(value: object, default: str) -> str:
    return value if isinstance(value, str) and value else default


def qemu_provider_workflow(*, dry_run: bool) -> list[LiveCommandPlan]:
    """Plan the provider lifecycle commands used by an oracle QEMU run."""

    return _oracle_provider_workflow(dry_run=dry_run)


def qemu_endpoint_bootstrap_plan(*, dry_run: bool) -> list[LiveCommandPlan]:
    """Plan role-specific endpoint bootstrap work for the QEMU lab."""

    provider_capabilities = qemu_default_provider_capabilities(dry_run=dry_run)
    return [
        LiveCommandPlan(
            role="libcrafter",
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
                "provider": PROVIDER_NAME,
                "dry_run": dry_run,
                "repository_sync": True,
                "private_network": True,
                "private_group": ORACLE_PRIVATE_GROUP,
                "system_packages": LIBCRAFTER_BOOTSTRAP_PACKAGES,
                "python_dependency_runner": PYTHON_DEPENDENCY_RUNNER,
                "uv": "install_if_missing",
                "rust": "install_if_missing",
                "validation": "cargo build -p oracle-adapters --bin live_endpoint",
                "artifact_path": "live-artifacts/bootstrap/libcrafter/bootstrap.env",
                "capability_artifact": CAPABILITY_REPORT_ARTIFACT,
                "provider_capabilities": provider_capabilities,
            },
        ),
        LiveCommandPlan(
            role="reference_backend",
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
                "provider": PROVIDER_NAME,
                "backend": "scapy",
                "dry_run": dry_run,
                "repository_sync": True,
                "private_network": True,
                "private_group": ORACLE_PRIVATE_GROUP,
                "system_packages": REFERENCE_BOOTSTRAP_PACKAGES,
                "python_dependency_runner": PYTHON_DEPENDENCY_RUNNER,
                "uv": "install_if_missing",
                "validation": "tools/oracle/run backend-info --backend scapy",
                "tshark": {
                    "availability_reported": True,
                    "required_for_scapy_live_exchange": False,
                },
                "artifact_path": "live-artifacts/bootstrap/reference_backend/bootstrap.env",
                "capability_artifact": CAPABILITY_REPORT_ARTIFACT,
                "provider_capabilities": provider_capabilities,
            },
        ),
    ]


def validate_qemu_endpoint_bootstrap(
    commands: list[LiveCommandPlan],
    *,
    dry_run: bool,
) -> LiveValidationCheck:
    """Validate that both QEMU endpoint roles are bootstrapped."""

    errors: list[str] = []
    commands_by_role = {command.role: command for command in commands}
    for role in ("libcrafter", "reference_backend"):
        if role not in commands_by_role:
            errors.append(f"missing endpoint bootstrap role: {role}")

    for command in commands:
        if command.sends_live_packets or command.expects_live_packets:
            errors.append("endpoint bootstrap commands cannot exchange live packets")
        if command.metadata.get("provider") != PROVIDER_NAME:
            errors.append(f"endpoint bootstrap must target QEMU: {command.role}")
        if not bool(command.metadata.get("repository_sync")):
            errors.append(f"endpoint bootstrap must sync repository: {command.role}")
        if not bool(command.metadata.get("private_network")):
            errors.append(f"endpoint bootstrap must preserve private topology: {command.role}")
        if command.metadata.get("private_group") != ORACLE_PRIVATE_GROUP:
            errors.append(f"endpoint bootstrap must use QEMU private group: {command.role}")
        if not command.metadata.get("artifact_path"):
            errors.append(f"endpoint bootstrap must write artifacts: {command.role}")
        if command.metadata.get("capability_artifact") != CAPABILITY_REPORT_ARTIFACT:
            errors.append(f"endpoint bootstrap must report capabilities: {command.role}")

    libcrafter = commands_by_role.get("libcrafter")
    if libcrafter is not None:
        packages = set(libcrafter.metadata.get("system_packages", []))
        for package in ("libpcap-dev", "pkg-config", "clang"):
            if package not in packages:
                errors.append(f"libcrafter bootstrap missing package: {package}")
        if libcrafter.metadata.get("python_dependency_runner") != PYTHON_DEPENDENCY_RUNNER:
            errors.append("libcrafter bootstrap must use uv for Python dependencies")
        if libcrafter.metadata.get("uv") != "install_if_missing":
            errors.append("libcrafter bootstrap must install uv when missing")
        if libcrafter.metadata.get("rust") != "install_if_missing":
            errors.append("libcrafter bootstrap must install Rust when missing")
        if (
            libcrafter.metadata.get("validation")
            != "cargo build -p oracle-adapters --bin live_endpoint"
        ):
            errors.append("libcrafter bootstrap must validate live_endpoint build")

    reference = commands_by_role.get("reference_backend")
    if reference is not None:
        packages = set(reference.metadata.get("system_packages", []))
        for package in ("python3", "curl"):
            if package not in packages:
                errors.append(f"reference bootstrap missing package: {package}")
        if reference.metadata.get("python_dependency_runner") != PYTHON_DEPENDENCY_RUNNER:
            errors.append("reference bootstrap must use uv for Python dependencies")
        if reference.metadata.get("uv") != "install_if_missing":
            errors.append("reference bootstrap must install uv when missing")
        if reference.metadata.get("validation") != (
            "tools/oracle/run backend-info --backend scapy"
        ):
            errors.append("reference bootstrap must validate Scapy backend availability")
        tshark = reference.metadata.get("tshark")
        if not isinstance(tshark, dict):
            errors.append("reference bootstrap must report tshark availability")
        elif tshark.get("required_for_scapy_live_exchange") is not False:
            errors.append("tshark must remain optional for Scapy live exchange")

    return LiveValidationCheck(
        name="qemu-endpoint-bootstrap",
        passed=not errors,
        subject="libcrafter,reference_backend",
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "dry_run": dry_run,
            "endpoint_count": 2,
            "repository_sync": "both_endpoints",
            "private_network": True,
            "private_group": ORACLE_PRIVATE_GROUP,
            "tshark_required": False,
        },
    )


def validate_qemu_provider_workflow(
    commands: list[LiveCommandPlan],
    *,
    dry_run: bool,
) -> LiveValidationCheck:
    """Validate QEMU provider lifecycle planning invariants."""

    errors: list[str] = []
    purposes = {command.purpose for command in commands}
    required = {
        "check-qemu-provider",
        "create-libcrafter-private-wire-endpoint",
        "create-reference-private-wire-endpoint",
        "run-oracle-live-exchange-suite",
        "collect-live-endpoint-artifacts",
        "teardown-disposable-qemu-endpoints",
    }
    missing = sorted(required - purposes)
    if missing:
        errors.append(f"missing provider workflow phases: {', '.join(missing)}")

    for command in commands:
        if command.role != "provider":
            errors.append(f"unexpected provider workflow role: {command.role}")
        if len(command.argv) < 2 or command.argv[0] != WIRE_ENTRYPOINT:
            errors.append(f"provider command must route through {WIRE_ENTRYPOINT}")
        if command.metadata.get("wire_command") is not True:
            errors.append("provider command must be marked as wire_command")
        if command.metadata.get("provider") != PROVIDER_NAME:
            errors.append("provider command must target QEMU")
        if command.metadata.get("private_group") != ORACLE_PRIVATE_GROUP:
            errors.append("provider command must use the QEMU oracle private group")
        if dry_run and command.metadata.get("operation") in {
            "doctor",
            "create",
        } and "--dry-run" not in command.argv:
            errors.append(f"dry-run provider command lacks --dry-run: {command.shell()}")
        if (
            not dry_run
            and command.metadata.get("operation") == "create"
            and "--confirm-live-run" not in command.argv
        ):
            errors.append("real provider create command lacks --confirm-live-run")
        if command.sends_live_packets or command.expects_live_packets:
            errors.append("provider lifecycle commands cannot be endpoint packet commands")

    return LiveValidationCheck(
        name="qemu-provider-workflow",
        passed=not errors,
        subject=PROVIDER_NAME,
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "dry_run": dry_run,
            "creates_infrastructure": not dry_run,
            "private_group": ORACLE_PRIVATE_GROUP,
            "always_collect_artifacts": True,
            "always_teardown": True,
        },
    )


def validate_qemu_dry_run_exchange(
    exchange: LiveExchangePlan,
) -> LiveValidationCheck:
    """Validate that a QEMU dry-run exchange is two-endpoint and non-mutating."""

    errors: list[str] = []
    if exchange.provider != PROVIDER_NAME:
        errors.append(f"unexpected provider: {exchange.provider}")
    if exchange.live_packet_exchange:
        errors.append("QEMU dry-run cannot claim live packet exchange")
    if exchange.sender.role == exchange.receiver.role:
        errors.append("sender and receiver roles must differ")
    if not bool(exchange.sender.metadata.get("private_network")):
        errors.append("sender endpoint must use a private network")
    if not bool(exchange.receiver.metadata.get("private_network")):
        errors.append("receiver endpoint must use a private network")
    if exchange.sender.metadata.get("private_group") != ORACLE_PRIVATE_GROUP:
        errors.append("sender endpoint must use the QEMU oracle private group")
    if exchange.receiver.metadata.get("private_group") != ORACLE_PRIVATE_GROUP:
        errors.append("receiver endpoint must use the QEMU oracle private group")
    if exchange.sender.metadata.get("provider") != PROVIDER_NAME:
        errors.append("sender endpoint must be a QEMU endpoint")
    if exchange.receiver.metadata.get("provider") != PROVIDER_NAME:
        errors.append("receiver endpoint must be a QEMU endpoint")
    if exchange.sender.address == exchange.receiver.address:
        errors.append("sender and receiver private addresses must differ")
    if (
        exchange.sender_command.sends_live_packets
        or exchange.receiver_command.sends_live_packets
    ):
        errors.append("QEMU dry-run endpoint commands must not send packets")
    if (
        exchange.sender_command.expects_live_packets
        or exchange.receiver_command.expects_live_packets
    ):
        errors.append("QEMU dry-run endpoint commands must not expect packets")

    return LiveValidationCheck(
        name="qemu-dry-run-live-invariant",
        passed=not errors,
        subject=f"{exchange.direction}:index-{exchange.index:06d}",
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "direction": exchange.direction,
            "packet_index": exchange.index,
            "private_network": True,
            "private_group": ORACLE_PRIVATE_GROUP,
            "creates_infrastructure": False,
            "live_packet_exchange": False,
        },
    )


def qemu_wire_remote_dir() -> str:
    """Return the repository directory used by QEMU wire endpoints."""

    return validate_remote_dir(os.environ.get("LIBCRAFTER_WIRE_REMOTE_DIR"))


def qemu_endpoint_remote_command(
    *,
    endpoint_role: str,
    remote_dir: str,
    request_path: str,
    out_dir: str,
) -> list[str]:
    """Return the endpoint protocol command executed on a QEMU wire endpoint."""

    quoted_remote_dir = shlex.quote(remote_dir)
    quoted_request = shlex.quote(request_path)
    quoted_out = shlex.quote(out_dir)
    if endpoint_role == "libcrafter":
        script = "\n".join(
            [
                "set -euo pipefail",
                f"cd {quoted_remote_dir}",
                'if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi',
                (
                    "cargo run -q -p oracle-adapters --bin live_endpoint -- "
                    f"--live --input {quoted_request} --out {quoted_out}"
                ),
            ]
        )
    else:
        script = "\n".join(
            [
                "set -euo pipefail",
                f"cd {quoted_remote_dir}",
                'export PYTHONPATH="tools/oracle${PYTHONPATH:+:$PYTHONPATH}"',
                (
                    "python3 -m engine.backends.scapy.live "
                    f"--live --input {quoted_request} --out {quoted_out}"
                ),
            ]
        )
    return ["bash", "-lc", script]


def qemu_endpoint_bootstrap_command(
    *,
    endpoint: LiveEndpoint,
    peer: LiveEndpoint,
    remote_archive: str,
    remote_dir: str,
) -> list[str]:
    """Return the repository bootstrap command for one QEMU endpoint."""

    return [
        "bash",
        "-lc",
        _qemu_endpoint_bootstrap_script(
            endpoint=endpoint,
            peer=peer,
            remote_archive=remote_archive,
            remote_dir=remote_dir,
        ),
    ]


def _qemu_endpoint_bootstrap_script(
    *,
    endpoint: LiveEndpoint,
    peer: LiveEndpoint,
    remote_archive: str,
    remote_dir: str,
) -> str:
    role = shlex.quote(endpoint.role)
    private_ipv4 = shlex.quote(endpoint.address)
    peer_private_ipv4 = shlex.quote(peer.address)
    private_interface = shlex.quote(endpoint.interface)
    quoted_archive = shlex.quote(remote_archive)
    quoted_remote_dir = shlex.quote(remote_dir)

    common = "\n".join(
        [
            "set -euo pipefail",
            "if command -v cloud-init >/dev/null 2>&1; then "
            "cloud-init status --wait >/dev/null 2>&1 || true; fi",
            f"rm -rf {quoted_remote_dir}",
            f"mkdir -p {quoted_remote_dir}",
            f"tar -xzf {quoted_archive} -C {quoted_remote_dir}",
            f"cd {quoted_remote_dir}",
            f"export LIBCRAFTER_ENDPOINT_ROLE={role}",
            f"export LIBCRAFTER_PRIVATE_IPV4={private_ipv4}",
            f"export LIBCRAFTER_PEER_PRIVATE_IPV4={peer_private_ipv4}",
            f"export LIBCRAFTER_PRIVATE_INTERFACE={private_interface}",
            "export DEBIAN_FRONTEND=noninteractive",
            "mkdir -p \"live-artifacts/bootstrap/$LIBCRAFTER_ENDPOINT_ROLE\"",
            "apt-get update",
        ]
    )
    install_uv = "\n".join(
        [
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
    )
    if endpoint.role == "libcrafter":
        return "\n".join(
            [
                common,
                (
                    "apt-get install -y --no-install-recommends "
                    "build-essential ca-certificates clang curl git iproute2 "
                    "iputils-ping libpcap-dev pkg-config python3"
                ),
                install_uv,
                "if ! command -v cargo >/dev/null 2>&1; then "
                "curl -fsS https://sh.rustup.rs | sh -s -- -y --profile minimal; fi",
                "if [ -f \"$HOME/.cargo/env\" ]; then . \"$HOME/.cargo/env\"; fi",
                "cargo build -p oracle-adapters --bin live_endpoint",
                "{",
                "  echo \"role=$LIBCRAFTER_ENDPOINT_ROLE\"",
                "  echo \"private_ipv4=$LIBCRAFTER_PRIVATE_IPV4\"",
                "  echo \"peer_private_ipv4=$LIBCRAFTER_PEER_PRIVATE_IPV4\"",
                "  echo \"private_interface=$LIBCRAFTER_PRIVATE_INTERFACE\"",
                "  echo \"repository_synced=true\"",
                "  echo \"python_dependency_runner=uv\"",
                "  echo \"uv=$(command -v uv)\"",
                "  echo \"rustc=$(rustc --version)\"",
                "  echo \"cargo=$(cargo --version)\"",
                "  echo \"libcrafter_oracle_bin=live_endpoint\"",
                "  echo \"libcrafter_oracle_bin_build=ok\"",
                "  echo \"finished_at=$(date -u +\"%Y-%m-%dT%H:%M:%SZ\")\"",
                "} > \"live-artifacts/bootstrap/$LIBCRAFTER_ENDPOINT_ROLE/bootstrap.env\"",
            ]
        )

    return "\n".join(
        [
            common,
            (
                "apt-get install -y --no-install-recommends "
                "ca-certificates curl git iproute2 iputils-ping python3"
            ),
            install_uv,
            "tools/oracle/run backend-info --backend scapy "
            "> \"live-artifacts/bootstrap/$LIBCRAFTER_ENDPOINT_ROLE/reference-backend.json\"",
            "if command -v tshark >/dev/null 2>&1; then "
            "tshark_available=true; else tshark_available=false; fi",
            "{",
            "  echo \"role=$LIBCRAFTER_ENDPOINT_ROLE\"",
            "  echo \"private_ipv4=$LIBCRAFTER_PRIVATE_IPV4\"",
            "  echo \"peer_private_ipv4=$LIBCRAFTER_PEER_PRIVATE_IPV4\"",
            "  echo \"private_interface=$LIBCRAFTER_PRIVATE_INTERFACE\"",
            "  echo \"repository_synced=true\"",
            "  echo \"python_dependency_runner=uv\"",
            "  echo \"uv=$(command -v uv)\"",
            "  echo \"reference_backend_info=ok\"",
            "  echo \"tshark_available=$tshark_available\"",
            "  echo \"tshark_required=false\"",
            "  echo \"finished_at=$(date -u +\"%Y-%m-%dT%H:%M:%SZ\")\"",
            "} > \"live-artifacts/bootstrap/$LIBCRAFTER_ENDPOINT_ROLE/bootstrap.env\"",
        ]
    )


def qemu_live_transit_plan(plan: PacketPlan) -> PacketPlan:
    """Apply QEMU live policy without modeling provider-routed transit rewrites."""

    wire_policy = qemu_wire_comparison_policy(plan)
    fields = {
        layer: dict(layer_fields)
        for layer, layer_fields in plan.fields.items()
    }
    return replace(
        plan,
        fields=fields,
        strict_bytes=bool(wire_policy.get("strict_bytes", plan.strict_bytes)),
        metadata={
            **plan.metadata,
            "wire": wire_policy,
            "live_transit_rewrites": [],
            "live_mutable_fields": list(wire_policy.get("mutable_fields", [])),
            "strict_bytes": bool(wire_policy.get("strict_bytes", plan.strict_bytes)),
        },
    )


def qemu_wire_comparison_policy(plan: PacketPlan) -> JSONObject:
    """Return QEMU wire comparison policy for one packet plan."""

    raw_policy = plan.metadata.get("wire")
    if isinstance(raw_policy, Mapping):
        policy = {
            key: value
            for key, value in raw_policy.items()
            if isinstance(key, str)
        }
    else:
        policy = wire_comparison_policy(
            plan,
            provider=PROVIDER_NAME,
            provider_capabilities=qemu_default_provider_capabilities(dry_run=True),
        )

    mutable_fields = policy.get("mutable_fields", [])
    if not isinstance(mutable_fields, Sequence) or isinstance(
        mutable_fields,
        (str, bytes, bytearray),
    ):
        mutable_fields = []
    policy["mutable_fields"] = [
        field
        for field in mutable_fields
        if isinstance(field, str) and field
    ]

    byte_mutable_fields = policy.get("byte_mutable_fields", [])
    if not isinstance(byte_mutable_fields, Sequence) or isinstance(
        byte_mutable_fields,
        (str, bytes, bytearray),
    ):
        byte_mutable_fields = []
    policy["byte_mutable_fields"] = [
        field
        for field in byte_mutable_fields
        if isinstance(field, str) and field
    ]

    strict_bytes = policy.get("strict_bytes")
    if not isinstance(strict_bytes, bool):
        strict_bytes = bool(plan.strict_bytes and not policy["byte_mutable_fields"])
    policy["strict_bytes"] = strict_bytes

    compare_root = policy.get("compare_root")
    if compare_root is not None and not isinstance(compare_root, str):
        compare_root = None
    policy["compare_root"] = compare_root
    policy.setdefault("provider", PROVIDER_NAME)
    return policy


def _oracle_lab_request(
    *,
    dry_run: bool,
    private_group: str | None = ORACLE_PRIVATE_GROUP,
    confirm_live_run: bool = False,
) -> LabRequest:
    group = private_group or ORACLE_PRIVATE_GROUP
    return LabRequest(
        provider=PROVIDER_NAME,
        profile=ORACLE_LIVE_SUITE,
        seed=0,
        roles=[
            LabRole(
                name="libcrafter",
                requested_private_ipv4=LIBCRAFTER_PRIVATE_ADDRESS,
            ),
            LabRole(
                name="reference_backend",
                requested_private_ipv4=REFERENCE_PRIVATE_ADDRESS,
            ),
        ],
        dry_run=dry_run,
        confirm_live_run=confirm_live_run,
        workload_label=ORACLE_LIVE_SUITE,
        metadata={
            "session_id": ORACLE_LIVE_SUITE,
            "private_group": group,
            "role_private_ipv4s": {
                "libcrafter": LIBCRAFTER_PRIVATE_ADDRESS,
                "reference_backend": REFERENCE_PRIVATE_ADDRESS,
            },
        },
    )


def _oracle_planned_infrastructure(*, dry_run: bool) -> JSONObject:
    request = _oracle_lab_request(dry_run=dry_run)
    infrastructure = QEMU_LAB_PROVIDER_ADAPTER.planned_infrastructure(request)
    provider_capabilities = infrastructure.get("provider_capabilities")
    if isinstance(provider_capabilities, dict):
        provider_capabilities["capability_report_artifact"] = CAPABILITY_REPORT_ARTIFACT
    infrastructure.setdefault("wire_policy", dict(QEMU_WIRE_POLICY))
    return infrastructure


def _oracle_packet_exchange_metadata(*, dry_run: bool) -> JSONObject:
    request = _oracle_lab_request(dry_run=dry_run)
    private_group = QEMU_LAB_PROVIDER_ADAPTER.private_group(request)
    return {
        "provider": PROVIDER_NAME,
        "wire_provider": QEMU_LAB_PROVIDER_ADAPTER.wire_provider,
        "wire_exposure": QEMU_LAB_PROVIDER_ADAPTER.wire_exposure,
        "endpoint_roles": ["libcrafter", "reference_backend"],
        "private_group": private_group,
        "isolated_network": True,
        "private_network": True,
        "private_network_cidr": PRIVATE_NETWORK_CIDR,
        "packet_exchange_network": QEMU_LAB_PROVIDER_ADAPTER.wire_exposure,
        "packet_exchange_network_label": "qemu-private-segment",
        "dry_run": dry_run,
    }


def _oracle_planned_endpoints(*, dry_run: bool) -> dict[str, LiveEndpoint]:
    request = _oracle_lab_request(
        dry_run=dry_run,
        confirm_live_run=not dry_run,
    )
    roles = QEMU_LAB_PROVIDER_ADAPTER.plan_roles(request)
    endpoints: dict[str, LiveEndpoint] = {}
    for role in roles:
        manifest = _planned_manifest_for_role(role, request=request)
        lab_endpoint = QEMU_LAB_PROVIDER_ADAPTER.normalize_endpoint(
            manifest,
            role=role,
            peer_roles=_peer_roles_for(role, roles),
            request=request,
        )
        endpoints[role.name] = live_endpoint_from_lab_endpoint(lab_endpoint)
    return endpoints


def _oracle_wire_endpoint_plan(
    *,
    dry_run: bool,
    client: wire_client.WireClient | None = None,
    private_group: str | None = ORACLE_PRIVATE_GROUP,
    confirm_live_run: bool = False,
    created_endpoint_ids: list[str] | None = None,
) -> dict[str, object]:
    request = _oracle_lab_request(
        dry_run=dry_run,
        private_group=private_group,
        confirm_live_run=confirm_live_run,
    )
    plan = QEMU_LAB_PROVIDER_ADAPTER.wire_endpoint_plan(
        request,
        client=_OracleLabWireClient(client or wire_client.WireClient()),
        created_endpoint_ids=created_endpoint_ids,
    )
    return _oracle_wire_plan_from_lab_plan(plan)


def _oracle_wire_plan_from_lab_plan(plan: JSONObject) -> dict[str, object]:
    endpoints: dict[str, LiveEndpoint] = {}
    raw_endpoints = plan.get("endpoints")
    if isinstance(raw_endpoints, Mapping):
        for role, endpoint in raw_endpoints.items():
            if isinstance(role, str) and isinstance(endpoint, Mapping):
                endpoints[role] = live_endpoint_from_lab_endpoint(endpoint)
    return {
        **plan,
        "wire_exposure": plan.get("exposure", QEMU_LAB_PROVIDER_ADAPTER.wire_exposure),
        "command_metadata": plan.get("command_records", []),
        "live_endpoints": endpoints,
    }


def _oracle_provider_workflow(*, dry_run: bool) -> list[LiveCommandPlan]:
    request = _oracle_lab_request(
        dry_run=dry_run,
        confirm_live_run=not dry_run,
    )
    commands = [
        _live_provider_command_from_lab(command)
        for command in QEMU_LAB_PROVIDER_ADAPTER.provider_workflow(request)
    ]
    insert_at = next(
        (
            index
            for index, command in enumerate(commands)
            if command.purpose == "collect-live-endpoint-artifacts"
        ),
        len(commands),
    )
    commands.insert(
        insert_at,
        LiveCommandPlan(
            role="provider",
            purpose="run-oracle-live-exchange-suite",
            argv=[
                WIRE_ENTRYPOINT,
                "exec",
                "<endpoint-id>",
                "--",
                "tools/oracle/run",
                "live-endpoint",
                "--suite",
                ORACLE_LIVE_SUITE,
            ],
            sends_live_packets=False,
            expects_live_packets=False,
            metadata={
                "provider": PROVIDER_NAME,
                "exposure": QEMU_LAB_PROVIDER_ADAPTER.wire_exposure,
                "dry_run": dry_run,
                "creates_infrastructure": False,
                "would_create_infrastructure": False,
                "oracle_two_endpoint": True,
                "private_network": True,
                "private_group": ORACLE_PRIVATE_GROUP,
                "wire_policy": dict(QEMU_WIRE_POLICY),
                "wire_command": True,
                "operation": "exec",
            },
        ),
    )
    return commands


def _live_provider_command_from_lab(command: LabCommandPlan) -> LiveCommandPlan:
    metadata: JSONObject = dict(command.metadata)
    metadata["lab_operation"] = command.operation
    metadata["operation"] = _oracle_operation(command.operation)
    metadata.setdefault("provider", PROVIDER_NAME)
    metadata.setdefault("exposure", QEMU_LAB_PROVIDER_ADAPTER.wire_exposure)
    metadata.setdefault("wire_policy", dict(QEMU_WIRE_POLICY))
    metadata.setdefault("wire_command", True)
    return LiveCommandPlan(
        role="provider",
        purpose=_oracle_workflow_purpose(command),
        argv=list(command.argv),
        sends_live_packets=False,
        expects_live_packets=False,
        metadata=metadata,
    )


def _oracle_workflow_purpose(command: LabCommandPlan) -> str:
    if command.operation == "wire.doctor":
        return "check-qemu-provider"
    if command.operation == "wire.create":
        suffix = "libcrafter" if command.role == "libcrafter" else "reference"
        return f"create-{suffix}-private-wire-endpoint"
    if command.operation == "wire.collect_artifacts":
        return "collect-live-endpoint-artifacts"
    if command.operation == "wire.destroy":
        return "teardown-disposable-qemu-endpoints"
    return command.purpose


def _oracle_operation(operation: str) -> str:
    return {
        "wire.doctor": "doctor",
        "wire.create": "create",
        "wire.collect_artifacts": "download",
        "wire.destroy": "destroy",
    }.get(operation, operation)


def _peer_roles_for(role: LabRole, roles: Sequence[LabRole]) -> list[LabRole]:
    if role.peer_roles:
        requested = set(role.peer_roles)
        return [peer for peer in roles if peer.name in requested]
    return [peer for peer in roles if peer.name != role.name]


def _planned_manifest_for_role(role: LabRole, *, request: LabRequest) -> EndpointManifest:
    private_group = QEMU_LAB_PROVIDER_ADAPTER.private_group(request)
    return EndpointManifest(
        endpoint_id=f"qemu-planned-{_endpoint_suffix(role.name)}",
        provider=QEMU_LAB_PROVIDER_ADAPTER.wire_provider,
        exposure=QEMU_LAB_PROVIDER_ADAPTER.wire_exposure,
        status="planned" if request.dry_run else "created",
        role=role.name,
        created_at="1970-01-01T00:00:00Z",
        ssh=EndpointSSHInfo(host="127.0.0.1", user="root"),
        interfaces=[
            NetworkInterface(
                name="private",
                exposure=QEMU_LAB_PROVIDER_ADAPTER.wire_exposure,
                ipv4=role.requested_private_ipv4 or role.planned_ipv4,
                provider_network_id=private_group,
                metadata={"private_group": private_group},
            )
        ],
        provider_resources=ProviderResources(),
        artifact_dir=f"/tmp/libcrafter-wire/{PROVIDER_NAME}/{role.name}",
        metadata={"private_group": private_group, "planned": True},
    )


def _endpoint_suffix(role: str) -> str:
    return "reference" if role == "reference_backend" else role


@dataclass(frozen=True, slots=True)
class _LabWireCreateResponse:
    source: object
    manifest: EndpointManifest
    json_data: JSONObject
    provider: str
    exposure: str
    role: str
    private_group: str | None
    private_ip: str | None
    dry_run: bool

    def command_plan(
        self,
        *,
        purpose: str | None = None,
        role: str | None = None,
        artifacts: Sequence[str] = (),
    ) -> LabCommandPlan:
        metadata = _source_record_metadata(self.source)
        metadata.update(
            {
                "provider": self.provider,
                "exposure": self.exposure,
                "private_group": self.private_group,
                "private_ip": self.private_ip,
                "wire_policy": dict(QEMU_WIRE_POLICY),
                "wire_command": True,
            }
        )
        return LabCommandPlan(
            purpose=purpose or f"create {self.role} endpoint",
            role=role or self.role,
            argv=_wire_create_argv(
                provider=self.provider,
                exposure=self.exposure,
                role=self.role,
                private_group=self.private_group,
                private_ip=self.private_ip,
                dry_run=self.dry_run,
            ),
            operation="wire.create",
            dry_run=self.dry_run,
            live_mutation=not self.dry_run,
            artifacts=list(artifacts),
            metadata=metadata,
        )


class _OracleLabWireClient:
    def __init__(self, client: object) -> None:
        self._client = client

    def create(
        self,
        *,
        provider: str,
        exposure: str,
        role: str,
        private_group: str | None,
        private_ip: str | None,
        dry_run: bool,
        write_manifest: bool,
        confirm_live_run: bool,
    ) -> _LabWireCreateResponse:
        create = getattr(self._client, "create")
        try:
            response = create(
                provider=provider,
                exposure=exposure,
                role=role,
                private_group=private_group,
                private_ip=private_ip,
                dry_run=dry_run,
                write_manifest=write_manifest,
                confirm_live_run=confirm_live_run,
            )
        except TypeError:
            response = create(
                provider=provider,
                exposure=exposure,
                role=role,
                private_group=private_group,
                private_ip=private_ip,
                dry_run=dry_run,
                confirm_live_run=confirm_live_run,
            )
        manifest = _response_manifest_for_lab(
            response,
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
            dry_run=dry_run,
        )
        json_data = _response_json_for_lab(response, manifest)
        return _LabWireCreateResponse(
            source=response,
            manifest=manifest,
            json_data=json_data,
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
            dry_run=dry_run,
        )


def _response_manifest_for_lab(
    response: object,
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    dry_run: bool,
) -> EndpointManifest:
    manifest = getattr(response, "manifest", None)
    if isinstance(manifest, EndpointManifest):
        return manifest
    json_data = getattr(response, "json_data", None)
    if isinstance(json_data, Mapping):
        return _manifest_from_wire_json(
            json_data,
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
            dry_run=dry_run,
        )
    endpoint_id = getattr(manifest, "endpoint_id", None)
    return _manifest_from_wire_json(
        {"endpoint_id": endpoint_id} if isinstance(endpoint_id, str) else {},
        provider=provider,
        exposure=exposure,
        role=role,
        private_group=private_group,
        private_ip=private_ip,
        dry_run=dry_run,
    )


def _response_json_for_lab(response: object, manifest: EndpointManifest) -> JSONObject:
    json_data = getattr(response, "json_data", None)
    if isinstance(json_data, Mapping):
        return {str(key): value for key, value in json_data.items() if isinstance(key, str)}
    return manifest.to_dict()


def _manifest_from_wire_json(
    data: Mapping[str, object],
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    dry_run: bool,
) -> EndpointManifest:
    endpoint_id = data.get("endpoint_id")
    interfaces = data.get("interfaces")
    interface_models = (
        [
            _network_interface_from_json(interface)
            for interface in interfaces
            if isinstance(interface, Mapping)
        ]
        if isinstance(interfaces, list)
        else []
    )
    if not interface_models:
        interface_models = [
            NetworkInterface(
                name="private",
                exposure=exposure,
                ipv4=private_ip,
                provider_network_id=private_group,
                metadata={"private_group": private_group} if private_group else {},
            )
        ]
    metadata = data.get("metadata")
    return EndpointManifest(
        endpoint_id=endpoint_id if isinstance(endpoint_id, str) else f"{provider}-{exposure}-{role}",
        provider=provider,
        exposure=exposure,
        status="planned" if dry_run else "created",
        role=role,
        created_at="1970-01-01T00:00:00Z",
        ssh=EndpointSSHInfo(host="127.0.0.1", user="root"),
        interfaces=interface_models,
        provider_resources=ProviderResources(),
        artifact_dir=f"/tmp/libcrafter-wire/{provider}/{role}",
        metadata={
            **({str(key): value for key, value in metadata.items() if isinstance(key, str)}
               if isinstance(metadata, Mapping) else {}),
            **({"private_group": private_group} if private_group else {}),
        },
    )


def _network_interface_from_json(value: Mapping[str, object]) -> NetworkInterface:
    metadata = value.get("metadata")
    return NetworkInterface(
        name=_string_or(value.get("name"), "private"),
        exposure=_string_or(value.get("exposure"), "private"),
        ipv4=_optional_string(value.get("ipv4")),
        ipv6=_optional_string(value.get("ipv6")),
        mac=_optional_string(value.get("mac")),
        provider_network_id=_optional_string(value.get("provider_network_id")),
        metadata={
            str(key): item
            for key, item in metadata.items()
            if isinstance(key, str)
        } if isinstance(metadata, Mapping) else {},
    )


def _source_record_metadata(response: object) -> JSONObject:
    record = getattr(response, "record", None)
    if record is not None:
        to_dict = getattr(record, "to_dict", None)
        if callable(to_dict):
            value = to_dict()
            if isinstance(value, Mapping):
                return {str(key): item for key, item in value.items() if isinstance(key, str)}
    return {}


def _wire_create_argv(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    dry_run: bool,
) -> list[str]:
    argv = [
        WIRE_ENTRYPOINT,
        "create-endpoint",
        "--provider",
        provider,
        "--exposure",
        exposure,
        "--role",
        role,
        "--json",
    ]
    if private_group is not None:
        argv.extend(["--private-group", private_group])
    if private_ip is not None:
        argv.extend(["--private-ip", private_ip])
    if dry_run:
        argv.append("--dry-run")
    return argv


@dataclass(frozen=True, slots=True)
class QemuLiveProviderAdapter:
    """Oracle live adapter for the local QEMU private wire lab."""

    name: str = PROVIDER_NAME
    wire_provider: str = PROVIDER_NAME
    wire_exposure: str = "private"
    endpoint_roles: tuple[str, str] = ("libcrafter", "reference_backend")
    private_group: str | None = ORACLE_PRIVATE_GROUP
    endpoint_private_ips: Mapping[str, str] = field(
        default_factory=lambda: {
            "libcrafter": LIBCRAFTER_PRIVATE_ADDRESS,
            "reference_backend": REFERENCE_PRIVATE_ADDRESS,
        }
    )
    artifact_collection_purpose: str = "collect-live-endpoint-artifacts"
    teardown_purpose: str = "teardown-disposable-qemu-endpoints"
    credential_label: str = "QEMU host prerequisites"
    missing_credential_reason: str = "missing QEMU host prerequisites"

    def token_configured(self) -> bool:
        """Return whether QEMU execution passes the generic credential gate."""

        return qemu_token_configured()

    def default_provider_capabilities(
        self,
        *,
        dry_run: bool,
        source: str = "planned-defaults",
    ) -> JSONObject:
        """Return QEMU capability defaults before endpoint discovery."""

        return qemu_default_provider_capabilities(dry_run=dry_run, source=source)

    def normalize_provider_capabilities(
        self,
        raw: JSONObject,
        *,
        dry_run: bool | None = None,
        source: str | None = None,
    ) -> JSONObject:
        """Normalize QEMU provider capabilities for corpus filtering."""

        return normalize_qemu_provider_capabilities(
            raw,
            dry_run=dry_run,
            source=source,
        )

    def planned_infrastructure(self, *, dry_run: bool) -> JSONObject:
        """Return planned QEMU private lab infrastructure."""

        return qemu_private_network_plan(dry_run=dry_run)

    def packet_exchange_metadata(self, *, dry_run: bool) -> JSONObject:
        """Return QEMU packet-exchange network metadata."""

        return qemu_packet_exchange_metadata(dry_run=dry_run)

    def endpoints(self, *, dry_run: bool) -> dict[str, LiveEndpoint]:
        """Return the two QEMU endpoint roles."""

        return qemu_endpoints(dry_run=dry_run)

    def wire_endpoint_plan(
        self,
        *,
        dry_run: bool,
        client: wire_client.WireClient | None = None,
        private_group: str | None = None,
        confirm_live_run: bool = False,
        created_endpoint_ids: list[str] | None = None,
    ) -> dict[str, object]:
        """Create or plan the two QEMU private wire endpoints."""

        return qemu_wire_endpoint_plan(
            dry_run=dry_run,
            client=client,
            private_group=private_group or self.private_group or ORACLE_PRIVATE_GROUP,
            confirm_live_run=confirm_live_run,
            created_endpoint_ids=created_endpoint_ids,
        )

    def provider_workflow(self, *, dry_run: bool) -> list[LiveCommandPlan]:
        """Return QEMU provider lifecycle command plans."""

        return qemu_provider_workflow(dry_run=dry_run)

    def endpoint_bootstrap_plan(self, *, dry_run: bool) -> list[LiveCommandPlan]:
        """Return QEMU endpoint bootstrap command plans."""

        return qemu_endpoint_bootstrap_plan(dry_run=dry_run)

    def validate_provider_workflow(
        self,
        commands: list[LiveCommandPlan],
        *,
        dry_run: bool,
    ) -> LiveValidationCheck:
        """Validate QEMU provider lifecycle planning."""

        return validate_qemu_provider_workflow(commands, dry_run=dry_run)

    def validate_endpoint_bootstrap(
        self,
        commands: list[LiveCommandPlan],
        *,
        dry_run: bool,
    ) -> LiveValidationCheck:
        """Validate QEMU endpoint bootstrap planning."""

        return validate_qemu_endpoint_bootstrap(commands, dry_run=dry_run)

    def validate_dry_run_exchange(
        self,
        exchange: LiveExchangePlan,
    ) -> LiveValidationCheck:
        """Validate a QEMU provider-backed dry-run exchange."""

        return validate_qemu_dry_run_exchange(exchange)

    def remote_dir(self) -> str:
        """Return the remote repository directory for QEMU wire endpoints."""

        return qemu_wire_remote_dir()

    def endpoint_bootstrap_command(
        self,
        *,
        endpoint: LiveEndpoint,
        peer: LiveEndpoint,
        remote_archive: str,
        remote_dir: str,
    ) -> list[str]:
        """Return the QEMU repository bootstrap command for one endpoint."""

        return qemu_endpoint_bootstrap_command(
            endpoint=endpoint,
            peer=peer,
            remote_archive=remote_archive,
            remote_dir=remote_dir,
        )

    def endpoint_remote_command(
        self,
        *,
        endpoint_role: str,
        remote_dir: str,
        request_path: str,
        out_dir: str,
    ) -> list[str]:
        """Return the QEMU endpoint protocol command for one role."""

        return qemu_endpoint_remote_command(
            endpoint_role=endpoint_role,
            remote_dir=remote_dir,
            request_path=request_path,
            out_dir=out_dir,
        )

    def apply_transit_plan(self, plan: PacketPlan) -> PacketPlan:
        """Apply QEMU live policy without provider transit rewrites."""

        return qemu_live_transit_plan(plan)

    def wire_comparison_policy(self, plan: PacketPlan) -> JSONObject:
        """Return the QEMU wire comparison policy for one packet."""

        return qemu_wire_comparison_policy(plan)


QEMU_LIVE_PROVIDER_ADAPTER: LiveProviderAdapter = QemuLiveProviderAdapter()
