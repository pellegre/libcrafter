"""Live oracle orchestration contracts.

The local dry-run provider validates orchestration plans only. It never sends
or captures packets and must not be treated as provider-backed live exchange.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field

from .model import DecodedModel, JSONObject, JsonModel, PacketPlan


LOCAL_DRY_RUN_PROVIDER = "local-dry-run"
LIVE_PROTOCOL_SPEC = "tools/oracle/LIVE.md"
LIVE_SELECTED_SPECS = [
    LIVE_PROTOCOL_SPEC,
    "tools/oracle/specs/stacks.yaml",
    "tools/oracle/specs/profiles.yaml",
]
LIVE_EXCHANGE_DIRECTIONS = ("libcrafter_to_reference", "reference_to_libcrafter")
LIVE_ENDPOINT_TIMEOUT_SECONDS = 30


@dataclass(frozen=True, slots=True)
class LiveEndpoint(JsonModel):
    """One planned live endpoint role."""

    endpoint_id: str
    role: str
    interface: str
    address: str
    ipv6_address: str | None = None
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LiveCommandPlan(JsonModel):
    """A command that a live provider would run on an endpoint."""

    role: str
    purpose: str
    argv: list[str]
    sends_live_packets: bool = False
    expects_live_packets: bool = False
    metadata: JSONObject = field(default_factory=dict)

    def shell(self) -> str:
        return shlex.join(self.argv)


@dataclass(frozen=True, slots=True)
class LiveExchangePlan(JsonModel):
    """A planned live exchange phase."""

    provider: str
    backend: str
    direction: str
    index: int
    packet_plan: PacketPlan
    sender: LiveEndpoint
    receiver: LiveEndpoint
    sender_command: LiveCommandPlan
    receiver_command: LiveCommandPlan
    live_packet_exchange: bool = False
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LiveEndpointBatchRequest(JsonModel):
    """Machine-readable endpoint input for a live packet batch."""

    provider: str
    backend: str
    seed: int
    profile: str
    packet_plans: list[PacketPlan]
    direction: str
    endpoint_id: str
    endpoint_role: str
    peer_role: str
    local_addresses: JSONObject
    peer_addresses: JSONObject
    interface: str
    timeout_seconds: int
    artifact_paths: JSONObject
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LiveCaptureArtifact(JsonModel):
    """A capture produced by one live endpoint."""

    endpoint_role: str
    path: str
    link_type: str | None = None
    packet_count: int | None = None
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LiveEndpointIndexStatus(JsonModel):
    """Per-packet endpoint execution status within a live batch."""

    index: int
    direction: str
    status: str
    sent: bool = False
    received: bool = False
    decoded_count: int = 0
    capture_paths: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LiveEndpointBatchResponse(JsonModel):
    """Machine-readable endpoint output for a live packet batch."""

    provider: str
    backend: str
    direction: str
    endpoint_id: str
    endpoint_role: str
    sent_count: int
    received_count: int
    decoded_models: list[DecodedModel]
    captures: list[LiveCaptureArtifact]
    per_index_status: list[LiveEndpointIndexStatus]
    errors: list[str]
    artifact_paths: JSONObject
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LiveValidationCheck(JsonModel):
    """A validation performed on dry-run orchestration data."""

    name: str
    passed: bool
    subject: str
    errors: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)


def live_execution_directions(direction: str) -> list[str]:
    """Expand a live direction request into concrete one-way phases."""

    if direction == "live_exchange":
        return list(LIVE_EXCHANGE_DIRECTIONS)
    if direction in LIVE_EXCHANGE_DIRECTIONS:
        return [direction]
    raise ValueError(f"unsupported live direction: {direction}")


def local_dry_run_endpoints() -> dict[str, LiveEndpoint]:
    """Return the deterministic endpoint roles for local dry-run reports."""

    return {
        "libcrafter": LiveEndpoint(
            endpoint_id="local-dry-run-libcrafter",
            role="libcrafter",
            interface="dry-run0",
            address="192.0.2.10",
            ipv6_address="2001:db8:1::10",
            metadata={
                "provider": LOCAL_DRY_RUN_PROVIDER,
                "isolated_network": False,
                "live_packet_exchange": False,
            },
        ),
        "reference_backend": LiveEndpoint(
            endpoint_id="local-dry-run-reference",
            role="reference_backend",
            interface="dry-run1",
            address="192.0.2.20",
            ipv6_address="2001:db8:1::20",
            metadata={
                "provider": LOCAL_DRY_RUN_PROVIDER,
                "isolated_network": False,
                "live_packet_exchange": False,
            },
        ),
    }


def live_endpoint_addresses(endpoint: LiveEndpoint) -> JSONObject:
    """Return the endpoint addresses exposed in live endpoint protocol inputs."""

    addresses: JSONObject = {"ipv4": endpoint.address}
    if endpoint.ipv6_address is not None:
        addresses["ipv6"] = endpoint.ipv6_address
    return addresses


def live_endpoint_artifact_paths(
    *,
    output_dir: str,
    direction: str,
    endpoint_role: str,
) -> JSONObject:
    """Return planned artifact paths for one endpoint batch."""

    root = f"{output_dir}/artifacts/{direction}/{endpoint_role}"
    return {
        "root": root,
        "request": f"{root}/request.json",
        "response": f"{root}/response.json",
        "stdout": f"{root}/stdout.log",
        "stderr": f"{root}/stderr.log",
        "captures": f"{root}/captures",
        "decoded_models": f"{root}/decoded-models.json",
    }


def build_live_endpoint_batch_request(
    *,
    provider: str,
    backend: str,
    seed: int,
    profile: str,
    packet_plans: list[PacketPlan],
    direction: str,
    endpoint: LiveEndpoint,
    peer: LiveEndpoint,
    artifact_paths: JSONObject,
    timeout_seconds: int = LIVE_ENDPOINT_TIMEOUT_SECONDS,
    metadata: JSONObject | None = None,
) -> LiveEndpointBatchRequest:
    """Build the endpoint protocol request for provider execution."""

    return LiveEndpointBatchRequest(
        provider=provider,
        backend=backend,
        seed=seed,
        profile=profile,
        packet_plans=packet_plans,
        direction=direction,
        endpoint_id=endpoint.endpoint_id,
        endpoint_role=endpoint.role,
        peer_role=peer.role,
        local_addresses=live_endpoint_addresses(endpoint),
        peer_addresses=live_endpoint_addresses(peer),
        interface=endpoint.interface,
        timeout_seconds=timeout_seconds,
        artifact_paths=artifact_paths,
        metadata=metadata or {},
    )


def dry_run_live_endpoint_batch_response(
    request: LiveEndpointBatchRequest,
) -> LiveEndpointBatchResponse:
    """Return a no-packet response for validating the endpoint protocol locally."""

    statuses = [
        LiveEndpointIndexStatus(
            index=plan.index,
            direction=request.direction,
            status="dry-run-planned",
            sent=False,
            received=False,
            decoded_count=0,
            capture_paths=[],
            errors=[],
            metadata={
                "packet_plan_index": plan.index,
                "dry_run": True,
                "live_packet_exchange": False,
                "no_live_packets_sent": True,
            },
        )
        for plan in request.packet_plans
    ]
    return LiveEndpointBatchResponse(
        provider=request.provider,
        backend=request.backend,
        direction=request.direction,
        endpoint_id=request.endpoint_id,
        endpoint_role=request.endpoint_role,
        sent_count=0,
        received_count=0,
        decoded_models=[],
        captures=[],
        per_index_status=statuses,
        errors=[],
        artifact_paths=request.artifact_paths,
        metadata={
            "dry_run": True,
            "live_packet_exchange": False,
            "no_live_packets_sent": True,
        },
    )


def libcrafter_dry_run_command_plan(
    *,
    plan: PacketPlan,
    direction: str,
    role: str,
) -> LiveCommandPlan:
    """Build a libcrafter command plan that is safe for dry-run validation."""

    if role == "sender":
        purpose = "dry-run-materialize-libcrafter-vector"
        argv = [
            "cargo",
            "run",
            "-q",
            "-p",
            "crafter",
            "--example",
            "oracle_vectors",
            "--",
            "--json",
        ]
    elif role == "receiver":
        purpose = "dry-run-decode-reference-vector"
        argv = [
            "cargo",
            "run",
            "-q",
            "-p",
            "crafter",
            "--example",
            "oracle_decode_vectors",
            "--",
            "--input",
            f"artifacts/live/index-{plan.index:06d}.reference-vectors.json",
        ]
    else:
        raise ValueError(f"unsupported libcrafter live role: {role}")

    return LiveCommandPlan(
        role="libcrafter",
        purpose=purpose,
        argv=argv,
        sends_live_packets=False,
        expects_live_packets=False,
        metadata={
            "direction": direction,
            "packet_index": plan.index,
            "dry_run": True,
            "live_packet_exchange": False,
        },
    )


def validate_libcrafter_command_plan(command: LiveCommandPlan) -> LiveValidationCheck:
    """Validate that a libcrafter command plan remains dry-run only."""

    errors: list[str] = []
    argv = command.argv
    if command.role != "libcrafter":
        errors.append(f"unexpected libcrafter command role: {command.role}")
    expected_prefix = ["cargo", "run", "-q", "-p", "crafter", "--example"]
    if len(argv) < 8 or argv[:6] != expected_prefix:
        errors.append(
            "libcrafter command must use `cargo run -q -p crafter --example`"
        )
    elif argv[6] not in {"oracle_vectors", "oracle_decode_vectors"}:
        errors.append(f"unsupported libcrafter dry-run example: {argv[6]}")
    if "--live" in argv:
        errors.append("local dry-run libcrafter command must not include --live")
    if command.sends_live_packets:
        errors.append("local dry-run libcrafter command must not send live packets")
    if command.expects_live_packets:
        errors.append("local dry-run libcrafter command must not expect live packets")

    return LiveValidationCheck(
        name="libcrafter-command-plan",
        passed=not errors,
        subject=command.shell(),
        errors=errors,
        metadata={
            "purpose": command.purpose,
            "dry_run": True,
            "live_packet_exchange": False,
        },
    )


def validate_live_endpoint_batch_contract(
    request: LiveEndpointBatchRequest,
    response: LiveEndpointBatchResponse,
    *,
    dry_run: bool,
) -> LiveValidationCheck:
    """Validate endpoint request/response protocol consistency."""

    errors: list[str] = []
    if response.provider != request.provider:
        errors.append("response provider must match request provider")
    if response.backend != request.backend:
        errors.append("response backend must match request backend")
    if response.direction != request.direction:
        errors.append("response direction must match request direction")
    if response.endpoint_id != request.endpoint_id:
        errors.append("response endpoint_id must match request endpoint_id")
    if response.endpoint_role != request.endpoint_role:
        errors.append("response endpoint_role must match request endpoint_role")
    if response.artifact_paths != request.artifact_paths:
        errors.append("response artifact paths must match request artifact paths")
    if request.timeout_seconds <= 0:
        errors.append("endpoint timeout must be positive")
    if response.sent_count < 0:
        errors.append("sent_count must not be negative")
    if response.received_count < 0:
        errors.append("received_count must not be negative")

    request_indexes = [plan.index for plan in request.packet_plans]
    status_indexes = [status.index for status in response.per_index_status]
    if status_indexes != request_indexes:
        errors.append("per-index statuses must match packet plan indexes")
    for status in response.per_index_status:
        if status.direction != request.direction:
            errors.append(f"status direction mismatch for index {status.index}")
        if status.decoded_count < 0:
            errors.append(f"decoded_count must not be negative for index {status.index}")

    if dry_run:
        if response.sent_count != 0:
            errors.append("dry-run endpoint response must not report sent packets")
        if response.received_count != 0:
            errors.append("dry-run endpoint response must not report received packets")
        if response.decoded_models:
            errors.append("dry-run endpoint response must not include decoded models")
        if response.captures:
            errors.append("dry-run endpoint response must not include captures")
        for status in response.per_index_status:
            if status.sent or status.received:
                errors.append(
                    f"dry-run endpoint status must not mark packet {status.index} sent "
                    "or received"
                )

    return LiveValidationCheck(
        name="live-endpoint-batch-protocol",
        passed=not errors,
        subject=f"{request.endpoint_role}:{request.direction}:{len(request.packet_plans)}",
        errors=errors,
        metadata={
            "provider": request.provider,
            "backend": request.backend,
            "direction": request.direction,
            "endpoint_role": request.endpoint_role,
            "packet_plan_count": len(request.packet_plans),
            "dry_run": dry_run,
        },
    )


def validate_local_dry_run_exchange(exchange: LiveExchangePlan) -> LiveValidationCheck:
    """Validate provider invariants for a local dry-run exchange plan."""

    errors: list[str] = []
    if exchange.provider != LOCAL_DRY_RUN_PROVIDER:
        errors.append(f"unexpected dry-run provider: {exchange.provider}")
    if exchange.live_packet_exchange:
        errors.append("local-dry-run exchange cannot claim live packet exchange")
    if exchange.sender.role == exchange.receiver.role:
        errors.append("sender and receiver roles must differ")
    if (
        exchange.sender_command.sends_live_packets
        or exchange.receiver_command.sends_live_packets
    ):
        errors.append("local-dry-run exchange command cannot send live packets")
    if (
        exchange.sender_command.expects_live_packets
        or exchange.receiver_command.expects_live_packets
    ):
        errors.append("local-dry-run exchange command cannot expect live packets")

    return LiveValidationCheck(
        name="local-dry-run-live-invariant",
        passed=not errors,
        subject=f"{exchange.direction}:index-{exchange.index:06d}",
        errors=errors,
        metadata={
            "provider": exchange.provider,
            "direction": exchange.direction,
            "packet_index": exchange.index,
            "live_packet_exchange": False,
        },
    )
