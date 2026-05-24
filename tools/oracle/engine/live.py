"""Live oracle orchestration contracts.

The local dry-run provider validates orchestration plans only. It never sends
or captures packets and must not be treated as provider-backed live exchange.
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping, Sequence
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
    sent_raw_hex: str | None = None
    send_root: str | None = None
    send_mode: str | None = None
    observed_raw_hex: str | None = None
    capture_root: str | None = None
    capture_link_type: str | None = None
    capture_path: str | None = None
    byte_length: int | None = None
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
    mac_address = endpoint.metadata.get("mac_address")
    if isinstance(mac_address, str) and mac_address:
        addresses["mac"] = mac_address
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

    local_addresses = live_endpoint_addresses(endpoint)
    peer_addresses = live_endpoint_addresses(peer)
    request_metadata = dict(metadata or {})
    request_metadata.update(
        _live_endpoint_request_wire_metadata(
            packet_plans,
            direction=direction,
            local_addresses=local_addresses,
            peer_addresses=peer_addresses,
        )
    )
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
        local_addresses=local_addresses,
        peer_addresses=peer_addresses,
        interface=endpoint.interface,
        timeout_seconds=timeout_seconds,
        artifact_paths=artifact_paths,
        metadata=request_metadata,
    )


def dry_run_live_endpoint_batch_response(
    request: LiveEndpointBatchRequest,
) -> LiveEndpointBatchResponse:
    """Return a no-packet response for validating the endpoint protocol locally."""

    phase_role = _endpoint_phase_role(request)
    statuses = [
        LiveEndpointIndexStatus(
            index=plan.index,
            direction=request.direction,
            status="dry-run-planned",
            sent=False,
            received=False,
            decoded_count=0,
            send_root=_plan_compare_root(plan) if phase_role == "sender" else None,
            send_mode=_send_mode_for_root(_plan_compare_root(plan))
            if phase_role == "sender"
            else None,
            capture_root=_plan_compare_root(plan) if phase_role == "receiver" else None,
            capture_paths=[],
            errors=[],
            metadata={
                "packet_plan_index": plan.index,
                "packet_id": _plan_packet_id(plan),
                "corpus_id": _plan_corpus_id(plan),
                "compare_root": _plan_compare_root(plan),
                "mutable_fields": _plan_mutable_fields(plan),
                "expected_sender_role": _expected_sender_role(request.direction),
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
            "oracle-adapters",
            "--bin",
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
            "oracle-adapters",
            "--bin",
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
    expected_prefix = ["cargo", "run", "-q", "-p", "oracle-adapters", "--bin"]
    if len(argv) < 8 or argv[:6] != expected_prefix:
        errors.append(
            "libcrafter command must use `cargo run -q -p oracle-adapters --bin`"
        )
    elif argv[6] not in {"oracle_vectors", "oracle_decode_vectors"}:
        errors.append(f"unsupported libcrafter dry-run binary: {argv[6]}")
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

    phase_role = _endpoint_phase_role(request)
    _validate_endpoint_request_wire_metadata(request, errors)
    _validate_endpoint_status_wire_fields(
        request,
        response.per_index_status,
        phase_role=phase_role,
        dry_run=dry_run,
        errors=errors,
    )

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


def _live_endpoint_request_wire_metadata(
    packet_plans: Sequence[PacketPlan],
    *,
    direction: str,
    local_addresses: Mapping[str, object],
    peer_addresses: Mapping[str, object],
) -> JSONObject:
    packet_metadata = [
        _live_endpoint_packet_wire_metadata(
            plan,
            direction=direction,
            local_addresses=local_addresses,
            peer_addresses=peer_addresses,
        )
        for plan in packet_plans
    ]
    corpus_ids = [
        packet["corpus_id"]
        for packet in packet_metadata
        if isinstance(packet.get("corpus_id"), str) and packet["corpus_id"]
    ]
    metadata: JSONObject = {
        "capture_filter": _combine_capture_filters(
            [
                packet.get("capture_filter")
                for packet in packet_metadata
                if isinstance(packet.get("capture_filter"), str)
            ]
        ),
        "packet_ids": [
            packet.get("packet_id")
            for packet in packet_metadata
            if isinstance(packet.get("packet_id"), str)
        ],
        "packets": packet_metadata,
    }
    if corpus_ids:
        metadata["corpus_id"] = corpus_ids[0]
    return metadata


def _live_endpoint_packet_wire_metadata(
    plan: PacketPlan,
    *,
    direction: str,
    local_addresses: Mapping[str, object],
    peer_addresses: Mapping[str, object],
) -> JSONObject:
    capture = _live_endpoint_capture_match(
        plan,
        local_addresses=local_addresses,
        peer_addresses=peer_addresses,
    )
    return {
        "index": plan.index,
        "corpus_id": _plan_corpus_id(plan),
        "packet_id": _plan_packet_id(plan),
        "compare_root": _plan_compare_root(plan),
        "capture_filter": capture.get("filter"),
        "capture_match": capture,
        "strict_bytes": plan.strict_bytes,
        "mutable_fields": _plan_mutable_fields(plan),
        "expected_sender_role": _expected_sender_role(direction),
    }


def _live_endpoint_capture_match(
    plan: PacketPlan,
    *,
    local_addresses: Mapping[str, object],
    peer_addresses: Mapping[str, object],
) -> JSONObject:
    family = _live_endpoint_capture_family(plan)
    protocol = _live_endpoint_capture_protocol(plan)
    source = _address_for_family(peer_addresses, family)
    destination = _address_for_family(local_addresses, family)

    terms: list[str] = []
    if family == "ipv4":
        terms.append("ip")
    elif family == "ipv6":
        terms.append("ip6")

    bpf_protocol = _capture_bpf_protocol(protocol, plan.stack)
    if bpf_protocol is not None:
        terms.append(bpf_protocol)
    if source is not None:
        terms.append(f"src host {source}")
    if destination is not None:
        terms.append(f"dst host {destination}")

    return {
        "family": family,
        "protocol": protocol,
        "layers": list(plan.stack),
        "src": source,
        "dst": destination,
        "filter": " and ".join(terms) if terms else None,
    }


def _live_endpoint_capture_family(plan: PacketPlan) -> str | None:
    compare_root = _plan_compare_root(plan)
    if compare_root in {"IP", "IPv4", "l3:ipv4"} or "ipv4" in plan.stack or "ip" in plan.stack:
        return "ipv4"
    if (
        compare_root in {"IPv6", "l3:ipv6"}
        or "ipv6" in plan.stack
        or "icmpv6" in plan.stack
    ):
        return "ipv6"
    return None


def _live_endpoint_capture_protocol(plan: PacketPlan) -> str | None:
    layers = set(plan.stack)
    if "dns" in layers:
        return "dns"
    if "tcp" in layers:
        return "tcp"
    if "icmpv6" in layers:
        return "icmpv6"
    if "icmp" in layers:
        return "icmp"
    if "udp" in layers:
        return "udp"
    if "arp" in layers:
        return "arp"
    return None


def _capture_bpf_protocol(protocol: str | None, stack: Sequence[str]) -> str | None:
    if "ipv6_fragment" in stack or "ipv6_routing" in stack:
        return None
    if protocol == "dns":
        return "udp"
    if protocol == "icmpv6":
        return "icmp6"
    return protocol


def _address_for_family(addresses: Mapping[str, object], family: str | None) -> str | None:
    if family == "ipv4":
        value = addresses.get("ipv4")
    elif family == "ipv6":
        value = addresses.get("ipv6")
    else:
        value = None
    return value if isinstance(value, str) and value else None


def _combine_capture_filters(filters: Sequence[object]) -> str | None:
    unique = [
        value
        for value in dict.fromkeys(
            item for item in filters if isinstance(item, str) and item
        )
    ]
    if not unique:
        return None
    if len(unique) == 1:
        return unique[0]
    return " or ".join(f"({value})" for value in unique)


def _validate_endpoint_request_wire_metadata(
    request: LiveEndpointBatchRequest,
    errors: list[str],
) -> None:
    metadata = request.metadata
    packet_metadata = metadata.get("packets")
    if not isinstance(packet_metadata, list):
        errors.append("endpoint request metadata.packets must describe packet wire metadata")
        packet_metadata = []
    if len(packet_metadata) != len(request.packet_plans):
        errors.append("endpoint request metadata.packets must match packet plan count")

    expected_packet_ids = [
        packet_id for plan in request.packet_plans if (packet_id := _plan_packet_id(plan))
    ]
    packet_ids = metadata.get("packet_ids")
    if not isinstance(packet_ids, list) or any(
        not isinstance(packet_id, str) for packet_id in packet_ids
    ):
        errors.append("endpoint request metadata.packet_ids must be a list of strings")
    elif expected_packet_ids and packet_ids != expected_packet_ids:
        errors.append("endpoint request metadata.packet_ids must match packet plan ids")

    expected_corpus_ids = [
        corpus_id for plan in request.packet_plans if (corpus_id := _plan_corpus_id(plan))
    ]
    if expected_corpus_ids:
        corpus_id = metadata.get("corpus_id")
        if corpus_id != expected_corpus_ids[0]:
            errors.append("endpoint request metadata.corpus_id must match packet corpus id")
        if len(set(expected_corpus_ids)) != 1:
            errors.append("endpoint request packet plans must share one corpus id")

    expected_sender_role = _expected_sender_role(request.direction)
    for offset, plan in enumerate(request.packet_plans):
        if offset >= len(packet_metadata):
            continue
        raw_packet = packet_metadata[offset]
        if not isinstance(raw_packet, Mapping):
            errors.append(f"endpoint request metadata.packets[{offset}] must be an object")
            continue
        packet = {key: value for key, value in raw_packet.items() if isinstance(key, str)}
        if packet.get("index") != plan.index:
            errors.append(f"endpoint request metadata.packets[{offset}].index mismatch")
        expected_packet_id = _plan_packet_id(plan)
        if expected_packet_id and packet.get("packet_id") != expected_packet_id:
            errors.append(f"endpoint request metadata.packets[{offset}].packet_id mismatch")
        expected_corpus_id = _plan_corpus_id(plan)
        if expected_corpus_id and packet.get("corpus_id") != expected_corpus_id:
            errors.append(f"endpoint request metadata.packets[{offset}].corpus_id mismatch")
        expected_compare_root = _plan_compare_root(plan)
        if packet.get("compare_root") != expected_compare_root:
            errors.append(
                f"endpoint request metadata.packets[{offset}].compare_root mismatch"
            )
        mutable_fields = packet.get("mutable_fields")
        if not isinstance(mutable_fields, list) or any(
            not isinstance(field, str) for field in mutable_fields
        ):
            errors.append(
                f"endpoint request metadata.packets[{offset}].mutable_fields must be strings"
            )
        elif mutable_fields != _plan_mutable_fields(plan):
            errors.append(
                f"endpoint request metadata.packets[{offset}].mutable_fields mismatch"
            )
        if packet.get("expected_sender_role") != expected_sender_role:
            errors.append(
                f"endpoint request metadata.packets[{offset}].expected_sender_role mismatch"
            )


def _validate_endpoint_status_wire_fields(
    request: LiveEndpointBatchRequest,
    statuses: Sequence[LiveEndpointIndexStatus],
    *,
    phase_role: str,
    dry_run: bool,
    errors: list[str],
) -> None:
    plans_by_index = {plan.index: plan for plan in request.packet_plans}
    for status in statuses:
        plan = plans_by_index.get(status.index)
        compare_root = _plan_compare_root(plan) if plan is not None else None
        if phase_role == "sender":
            if status.send_root is None:
                errors.append(f"sender status {status.index} requires send_root")
            if status.send_mode is None:
                errors.append(f"sender status {status.index} requires send_mode")
            if status.sent and not _is_hex_string(status.sent_raw_hex):
                errors.append(f"sender status {status.index} requires sent_raw_hex")
            if status.sent and not _positive_int(status.byte_length):
                errors.append(f"sender status {status.index} requires positive byte_length")
            if not dry_run and status.sent and status.sent_raw_hex is None:
                errors.append(f"sender status {status.index} missing sent byte evidence")
        elif phase_role == "receiver":
            if status.capture_root not in {None, compare_root}:
                errors.append(
                    f"receiver status {status.index} capture_root must match compare root"
                )
            if status.received:
                if not _is_hex_string(status.observed_raw_hex):
                    errors.append(
                        f"receiver status {status.index} requires observed_raw_hex"
                    )
                if status.capture_root is None:
                    errors.append(f"receiver status {status.index} requires capture_root")
                if status.capture_link_type is None:
                    errors.append(
                        f"receiver status {status.index} requires capture_link_type"
                    )
                if status.capture_path is None:
                    errors.append(f"receiver status {status.index} requires capture_path")
                if not _positive_int(status.byte_length):
                    errors.append(
                        f"receiver status {status.index} requires positive byte_length"
                    )


def _endpoint_phase_role(request: LiveEndpointBatchRequest) -> str:
    metadata = request.metadata
    phase_role = metadata.get("phase_role")
    if isinstance(phase_role, str) and phase_role:
        return phase_role
    expected_sender = _expected_sender_role(request.direction)
    if request.endpoint_role == expected_sender:
        return "sender"
    return "receiver"


def _expected_sender_role(direction: str) -> str | None:
    if direction == "reference_to_libcrafter":
        return "reference_backend"
    if direction == "libcrafter_to_reference":
        return "libcrafter"
    return None


def _plan_corpus_metadata(plan: PacketPlan | None) -> JSONObject:
    if plan is None:
        return {}
    value = plan.metadata.get("corpus")
    if isinstance(value, Mapping):
        return {key: item for key, item in value.items() if isinstance(key, str)}
    return {}


def _plan_wire_metadata(plan: PacketPlan | None) -> JSONObject:
    if plan is None:
        return {}
    value = plan.metadata.get("wire")
    if isinstance(value, Mapping):
        return {key: item for key, item in value.items() if isinstance(key, str)}
    return {}


def _plan_corpus_id(plan: PacketPlan | None) -> str | None:
    value = _plan_corpus_metadata(plan).get("corpus_id")
    return value if isinstance(value, str) and value else None


def _plan_packet_id(plan: PacketPlan | None) -> str | None:
    corpus_packet_id = _plan_corpus_metadata(plan).get("packet_id")
    if isinstance(corpus_packet_id, str) and corpus_packet_id:
        return corpus_packet_id
    if plan is None:
        return None
    plan_id = plan.metadata.get("plan_id")
    return plan_id if isinstance(plan_id, str) and plan_id else None


def _plan_compare_root(plan: PacketPlan | None) -> str | None:
    wire_root = _plan_wire_metadata(plan).get("compare_root")
    if isinstance(wire_root, str) and wire_root:
        return wire_root
    if plan is None:
        return None
    root = plan.metadata.get("root_decoder", plan.metadata.get("root"))
    if isinstance(root, str) and root:
        return root
    if plan.family == "ipv4":
        return "l3:ipv4"
    if plan.family == "ipv6":
        return "l3:ipv6"
    return None


def _plan_mutable_fields(plan: PacketPlan | None) -> list[str]:
    raw_fields = _plan_wire_metadata(plan).get("mutable_fields", [])
    if not isinstance(raw_fields, Sequence) or isinstance(
        raw_fields,
        (str, bytes, bytearray),
    ):
        return []
    return [field for field in raw_fields if isinstance(field, str)]


def _send_mode_for_root(root: str | None) -> str | None:
    if root in {
        "CookedLinux",
        "Ether",
        "Loopback",
        "link:ethernet",
        "link:linux-cooked",
        "link:linux-sll",
        "link:null-loopback",
    }:
        return "link-layer"
    if root is None:
        return None
    return "network-layer"


def _is_hex_string(value: str | None) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _positive_int(value: int | None) -> bool:
    return isinstance(value, int) and value > 0


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
