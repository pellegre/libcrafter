"""Scapy live backend endpoint and dry-run planning helpers."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...live import LiveCommandPlan, LiveValidationCheck
from ...model import (
    DecodedModel,
    EncodedVector,
    JSONObject,
    PacketPlan,
    json_object,
    string_list,
    write_json,
)
from ..registry import BackendCapabilities, BackendRegistration, get_backend
from .bootstrap import import_scapy
from .normalize import decode_root, normalize_packet
from .packets import encode_packet_plans


BACKEND_NAME = "scapy"
LIVE_SEND_INTERVAL_SECONDS = 0.01
CAPTURE_COMPARE_ROOTS = {
    "Ether": "link:ethernet",
    "IP": "l3:ipv4",
    "IPv4": "l3:ipv4",
    "IPv6": "l3:ipv6",
    "link:ethernet": "link:ethernet",
    "l2:ipv4": "l3:ipv4",
    "l3:ipv4": "l3:ipv4",
    "l3:ipv6": "l3:ipv6",
}


@dataclass(frozen=True, slots=True)
class CaptureSlice:
    """Capture bytes split into full-frame and compare-root views."""

    compare_root: str
    full_raw: bytes
    comparable_raw: bytes
    packet: Any


def backend_bootstrap_command_plan() -> LiveCommandPlan:
    """Return the command plan that validates Scapy bootstrap availability."""

    return LiveCommandPlan(
        role="reference_backend",
        purpose="validate-scapy-bootstrap",
        argv=["tools/oracle/run", "backend-info", "--backend", BACKEND_NAME],
        sends_live_packets=False,
        expects_live_packets=False,
        metadata={
            "backend": BACKEND_NAME,
            "dry_run": True,
            "live_packet_exchange": False,
        },
    )


def dry_run_command_plan(
    *,
    plan: PacketPlan,
    direction: str,
    role: str,
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> LiveCommandPlan:
    """Build a Scapy endpoint command plan for local dry-run validation."""

    _require_live_capability(capabilities)
    if role not in {"sender", "receiver"}:
        raise ValueError(f"unsupported Scapy live dry-run role: {role}")

    argv = [
        "python3",
        "-m",
        "engine.backends.scapy.live",
        "--dry-run",
        "--direction",
        direction,
        "--role",
        role,
        "--index",
        str(plan.index),
    ]
    if role == "sender":
        purpose = "dry-run-materialize-scapy-vector"
        argv.append("--emit-vector")
    else:
        purpose = "dry-run-decode-libcrafter-vector"
        argv.extend(
            [
                "--decode-vector",
                f"artifacts/live/index-{plan.index:06d}.libcrafter-vectors.json",
            ]
        )

    return LiveCommandPlan(
        role="reference_backend",
        purpose=purpose,
        argv=argv,
        sends_live_packets=False,
        expects_live_packets=False,
        metadata={
            "backend": BACKEND_NAME,
            "direction": direction,
            "packet_index": plan.index,
            "phase_role": role,
            "dry_run": True,
            "live_packet_exchange": False,
        },
    )


def validate_backend_bootstrap_command(command: LiveCommandPlan) -> LiveValidationCheck:
    """Validate the planned Scapy bootstrap command."""

    expected = backend_bootstrap_command_plan()
    errors: list[str] = []
    if command.role != "reference_backend":
        errors.append(f"unexpected Scapy bootstrap role: {command.role}")
    if command.argv != expected.argv:
        errors.append("Scapy bootstrap command must route through tools/oracle/run backend-info")
    if command.sends_live_packets or command.expects_live_packets:
        errors.append("Scapy bootstrap validation cannot send or expect live packets")

    return LiveValidationCheck(
        name="scapy-bootstrap-command-plan",
        passed=not errors,
        subject=command.shell(),
        errors=errors,
        metadata={
            "backend": BACKEND_NAME,
            "dry_run": True,
            "live_packet_exchange": False,
        },
    )


def validate_dry_run_command_plan(command: LiveCommandPlan) -> LiveValidationCheck:
    """Validate that a Scapy live command plan is dry-run only."""

    errors: list[str] = []
    argv = command.argv
    if command.role != "reference_backend":
        errors.append(f"unexpected Scapy command role: {command.role}")
    expected_prefix = [
        "python3",
        "-m",
        "engine.backends.scapy.live",
        "--dry-run",
        "--direction",
    ]
    if len(argv) < 9 or argv[:5] != expected_prefix:
        errors.append(
            "Scapy live command must invoke engine.backends.scapy.live with --dry-run"
        )
    if "--live" in argv:
        errors.append("local dry-run Scapy command must not include --live")
    if "--dry-run" not in argv:
        errors.append("local dry-run Scapy command must include --dry-run")
    if command.sends_live_packets:
        errors.append("local dry-run Scapy command must not send live packets")
    if command.expects_live_packets:
        errors.append("local dry-run Scapy command must not expect live packets")

    return LiveValidationCheck(
        name="scapy-command-plan",
        passed=not errors,
        subject=command.shell(),
        errors=errors,
        metadata={
            "backend": BACKEND_NAME,
            "purpose": command.purpose,
            "dry_run": True,
            "live_packet_exchange": False,
        },
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run a Scapy endpoint batch or emit dry-run command-plan metadata."""

    parser = argparse.ArgumentParser(description="Run a Scapy oracle live endpoint batch.")
    parser.add_argument("--dry-run", action="store_true", help="required dry-run guard")
    parser.add_argument("--live", action="store_true", help="send or capture live packets")
    parser.add_argument("--input", help="endpoint request JSON path, or - for stdin")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("target/oracle/scapy-live-endpoint"),
        help="endpoint artifact output directory",
    )
    parser.add_argument(
        "--direction",
        choices=("libcrafter_to_reference", "reference_to_libcrafter"),
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--role", choices=("sender", "receiver"), help=argparse.SUPPRESS)
    parser.add_argument("--index", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--emit-vector", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--decode-vector", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.dry_run and args.live:
        parser.error("--dry-run and --live are mutually exclusive")
    _require_live_capability(None)

    if args.input is None:
        return _emit_command_plan_metadata(args, parser)

    request_json = _read_request(args.input)
    response = run_endpoint(
        request_json,
        out_dir=args.out,
        dry_run=not args.live,
    )
    sys.stdout.write(json.dumps(response, indent=2, sort_keys=True) + "\n")
    return 0 if not response.get("errors") else 1


def run_endpoint(
    request_json: object,
    *,
    out_dir: Path,
    dry_run: bool,
) -> JSONObject:
    """Execute one Scapy endpoint request and write protocol artifacts."""

    request = json_object(request_json, "live endpoint request")
    if _required_string(request, "backend") != BACKEND_NAME:
        raise ValueError(f"Scapy live endpoint requires backend={BACKEND_NAME}")
    if _required_string(request, "endpoint_role") != "reference_backend":
        raise ValueError("Scapy live endpoint requires endpoint_role=reference_backend")

    out_dir.mkdir(parents=True, exist_ok=True)
    artifact_paths = json_object(
        request.get("artifact_paths", {}),
        "live endpoint request artifact_paths",
    )
    write_json(_artifact_path(out_dir, artifact_paths, "request", "request.json"), request)

    plans = [
        _packet_plan_from_object(plan, f"packet_plans[{index}]")
        for index, plan in enumerate(_packet_plan_values(request))
    ]
    phase_role = _phase_role(request)
    vectors = encode_packet_plans(plans)
    if phase_role == "sender":
        response = _run_sender(request, artifact_paths, out_dir, vectors, dry_run=dry_run)
    elif phase_role == "receiver":
        response = _run_receiver(request, artifact_paths, out_dir, vectors, dry_run=dry_run)
    else:
        raise ValueError(f"unsupported Scapy live endpoint phase_role={phase_role}")

    write_json(_artifact_path(out_dir, artifact_paths, "response", "response.json"), response)
    write_json(out_dir / "response.json", response)
    return response


def _emit_command_plan_metadata(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> int:
    if not args.dry_run:
        parser.error("Scapy command-plan metadata requires --dry-run")
    if args.direction is None or args.role is None or args.index is None:
        parser.error("--input is required for endpoint execution")
    print(
        json.dumps(
            {
                "backend": BACKEND_NAME,
                "direction": args.direction,
                "dry_run": True,
                "index": args.index,
                "live_packet_exchange": False,
                "role": args.role,
            },
            sort_keys=True,
        )
    )
    return 0


def _run_sender(
    request: JSONObject,
    artifact_paths: JSONObject,
    out_dir: Path,
    vectors: list[EncodedVector],
    *,
    dry_run: bool,
) -> JSONObject:
    scapy_all = import_scapy()["all"]
    scapy_all.conf.verb = 0
    statuses: list[JSONObject] = []
    send_records: list[JSONObject] = []
    sent_count = 0
    errors: list[str] = []

    for vector in vectors:
        packet = decode_root(vector.root or vector.decoder or "Raw", vector.to_bytes())
        send_packet, send_root, send_mode = _materialized_send_packet(
            scapy_all,
            packet,
            request,
            vector.root,
        )
        sent_raw = bytes(scapy_all.raw(send_packet))
        send_record: JSONObject = {
            "index": vector.plan.index,
            "dry_run": dry_run,
            "root": vector.root,
            "raw_hex": vector.raw_hex,
            "length": len(vector.to_bytes()),
            "send_root": send_root,
            "sent_raw_hex": sent_raw.hex(),
            "byte_length": len(sent_raw),
            "send_mode": send_mode,
        }
        sent = False
        packet_errors: list[str] = []
        if not dry_run:
            try:
                _send_packet(scapy_all, send_packet, request, send_mode)
                time.sleep(LIVE_SEND_INTERVAL_SECONDS)
                sent = True
                sent_count += 1
            except Exception as exc:  # pragma: no cover - Scapy errors vary by host.
                packet_errors.append(str(exc))
                errors.append(f"index {vector.plan.index}: {exc}")
        send_records.append(send_record)
        statuses.append(
            _index_status(
                request,
                vector.plan.index,
                "dry-run-planned" if dry_run else ("sent" if sent else "send-failed"),
                sent=sent,
                received=False,
                decoded_count=0,
                capture_paths=[],
                errors=packet_errors,
                metadata={
                    "root": vector.root,
                    "raw_hex": vector.raw_hex,
                    "sent_raw_hex": sent_raw.hex(),
                    "send_root": send_root,
                    "send_mode": send_mode,
                    "byte_length": len(sent_raw),
                    "feature_tags": list(vector.plan.feature_tags),
                },
            )
        )

    return _endpoint_response(
        request,
        dry_run=dry_run,
        sent_count=0 if dry_run else sent_count,
        received_count=0,
        decoded_models=[],
        captures=[],
        per_index_status=statuses,
        errors=errors,
        detail={
            "phase_role": "sender",
            "send_records": send_records,
            "artifact_paths": artifact_paths,
            "live_packet_exchange": not dry_run,
        },
    )


def _run_receiver(
    request: JSONObject,
    artifact_paths: JSONObject,
    out_dir: Path,
    vectors: list[EncodedVector],
    *,
    dry_run: bool,
) -> JSONObject:
    decoded_path = _artifact_path(
        out_dir,
        artifact_paths,
        "decoded_models",
        "decoded-models.json",
    )
    if dry_run:
        write_json(decoded_path, [])
        statuses = [
            _index_status(
                request,
                vector.plan.index,
                "dry-run-planned",
                sent=False,
                received=False,
                decoded_count=0,
                capture_paths=[],
                errors=[],
                metadata={
                    "root": vector.root,
                    "expected_raw_hex": vector.raw_hex,
                    "capture_root": _compare_root_for_vector(request, vector),
                    "capture_filter": _capture_filter_for_vector(request, vector),
                    "capture_match": _capture_match_for_vector(request, vector),
                    "feature_tags": list(vector.plan.feature_tags),
                },
            )
            for vector in vectors
        ]
        return _endpoint_response(
            request,
            dry_run=True,
            sent_count=0,
            received_count=0,
            decoded_models=[],
            captures=[],
            per_index_status=statuses,
            errors=[],
            detail={"phase_role": "receiver"},
        )

    scapy_all = import_scapy()["all"]
    scapy_all.conf.verb = 0
    sniff_kwargs: dict[str, Any] = {
        "iface": _resolve_capture_interface(request, scapy_all),
        "count": max(1, len(vectors)),
        "timeout": max(1, _int_value(request.get("timeout_seconds"), 30)),
        "lfilter": lambda packet: _matches_live_capture(scapy_all, packet, request),
    }
    if capture_filter := _request_capture_filter(request):
        sniff_kwargs["filter"] = capture_filter

    direction = _optional_string(request.get("direction")) or "unknown"
    ready_marker = out_dir / f"receiver-ready-{direction}"

    def _signal_receiver_ready() -> None:
        # Tell the orchestrator the capture is live so the sender only starts
        # once packets can actually be observed (avoids the send/receive race
        # where the sender's burst is gone before the receiver is listening).
        try:
            ready_marker.write_text("ready", encoding="utf-8")
        except Exception:
            pass

    sniff_kwargs["started_callback"] = _signal_receiver_ready
    captured = scapy_all.sniff(**sniff_kwargs)

    decoded_models: list[JSONObject] = []
    statuses: list[JSONObject] = []
    capture_paths: list[str] = []
    capture_dir = _artifact_path(out_dir, artifact_paths, "captures", "captures")
    capture_dir.mkdir(parents=True, exist_ok=True)
    capture_summary_path = capture_dir / "observed.json"
    capture_paths.append(str(capture_summary_path))

    for offset, vector in enumerate(vectors):
        if offset >= len(captured):
            statuses.append(
                _index_status(
                    request,
                    vector.plan.index,
                    "timeout",
                    sent=False,
                    received=False,
                    decoded_count=0,
                    capture_paths=[],
                    errors=["receiver timed out before observing packet"],
                    metadata={
                        "root": vector.root,
                        "expected_raw_hex": vector.raw_hex,
                    },
                )
            )
            continue

        try:
            capture_slice = _capture_slice_for_root(
                scapy_all,
                captured[offset],
                _compare_root_for_vector(request, vector),
            )
            observed_raw = capture_slice.comparable_raw
            decoded = _decode_observed_capture_slice(capture_slice, vector)
            decoded_models.append(decoded.to_dict())
            capture_path = str(capture_summary_path)
            capture_link_type = _packet_link_type(captured[offset])
            statuses.append(
                _index_status(
                    request,
                    vector.plan.index,
                    "received",
                    sent=False,
                    received=True,
                    decoded_count=1,
                    capture_paths=capture_paths,
                    errors=[],
                    metadata={
                        "root": vector.root,
                        "expected_raw_hex": vector.raw_hex,
                        "observed_raw_hex": observed_raw.hex(),
                        "comparable_raw_hex": observed_raw.hex(),
                        "full_capture_raw_hex": capture_slice.full_raw.hex(),
                        "capture_root": capture_slice.compare_root,
                        "capture_filter": _capture_filter_for_vector(request, vector),
                        "capture_match": _capture_match_for_vector(request, vector),
                        "capture_link_type": capture_link_type,
                        "capture_path": capture_path,
                        "byte_length": len(observed_raw),
                        "comparable_byte_length": len(observed_raw),
                        "full_capture_byte_length": len(capture_slice.full_raw),
                    },
                )
            )
        except Exception as exc:  # pragma: no cover - Scapy errors vary by host.
            statuses.append(
                _index_status(
                    request,
                    vector.plan.index,
                    "decode-failed",
                    sent=False,
                    received=True,
                    decoded_count=0,
                    capture_paths=capture_paths,
                    errors=[str(exc)],
                    metadata={
                        "root": vector.root,
                        "expected_raw_hex": vector.raw_hex,
                        "capture_root": vector.root,
                        "capture_filter": _capture_filter_for_vector(request, vector),
                        "capture_match": _capture_match_for_vector(request, vector),
                        "capture_link_type": _packet_link_type(captured[offset]),
                        "capture_path": str(capture_summary_path),
                    },
                )
            )

    write_json(decoded_path, decoded_models)
    write_json(
        capture_summary_path,
        {
            "packet_count": len(captured),
            "decoded_count": len(decoded_models),
            "packets": decoded_models,
            "capture_filter": _request_capture_filter(request),
            "observed_packets": [
                {
                    "index": status["index"],
                    "observed_raw_hex": status.get("observed_raw_hex"),
                    "comparable_raw_hex": _status_metadata(status).get(
                        "comparable_raw_hex"
                    ),
                    "full_capture_raw_hex": _status_metadata(status).get(
                        "full_capture_raw_hex"
                    ),
                    "capture_root": status.get("capture_root"),
                    "capture_link_type": status.get("capture_link_type"),
                    "byte_length": status.get("byte_length"),
                    "comparable_byte_length": _status_metadata(status).get(
                        "comparable_byte_length"
                    ),
                    "full_capture_byte_length": _status_metadata(status).get(
                        "full_capture_byte_length"
                    ),
                    "capture_path": status.get("capture_path"),
                }
                for status in statuses
                if status.get("received")
            ],
        },
    )
    return _endpoint_response(
        request,
        dry_run=False,
        sent_count=0,
        received_count=len(captured),
        decoded_models=decoded_models,
        captures=[
            {
                "endpoint_role": _required_string(request, "endpoint_role"),
                "path": str(capture_summary_path),
                "link_type": _packet_link_type(captured[0]) if captured else None,
                "packet_count": len(captured),
                "metadata": {"artifact_kind": "decoded-live-capture-summary"},
            }
        ],
        per_index_status=statuses,
        errors=[
            error
            for status in statuses
            for error in _string_values(status.get("errors", []), "status.errors")
        ],
        detail={"phase_role": "receiver"},
    )


def _resolve_capture_interface(request: JSONObject, scapy_all: Any) -> str:
    """Resolve the real OS network device for live send/capture.

    The orchestrator passes a logical interface name (for example "private"),
    which is not an actual device on the endpoint. Resolve the device that owns
    the local address first, then fall back to route-style resolution toward the
    peer and finally to the configured name.
    """

    configured = request.get("interface")
    configured = configured if isinstance(configured, str) and configured else None
    def _device_names() -> list[str | None]:
        try:
            return [getattr(device, "name", None) for device in scapy_all.conf.ifaces.values()]
        except Exception:
            return []

    if configured and configured in _device_names():
        return configured
    local_ipv4 = _address_value(request, "local_addresses", "ipv4")
    if local_ipv4:
        deadline = time.monotonic() + 40.0
        while True:
            for device_name in _device_names():
                if not device_name:
                    continue
                try:
                    if scapy_all.get_if_addr(device_name) == local_ipv4:
                        return device_name
                except Exception:
                    continue
            if time.monotonic() >= deadline:
                break
            time.sleep(0.5)
            try:
                scapy_all.conf.ifaces.reload()
            except Exception:
                pass
    peer = request.get("peer_addresses")
    peer_ipv4 = None
    if isinstance(peer, Mapping):
        value = peer.get("ipv4")
        if isinstance(value, str) and value:
            peer_ipv4 = value
    if peer_ipv4:
        try:
            resolved = scapy_all.conf.route.route(peer_ipv4)[0]
        except Exception:
            resolved = None
        if isinstance(resolved, str) and resolved and resolved != "lo":
            return resolved
    if configured:
        return configured
    raise ValueError("could not resolve a live capture interface")


def _send_packet(
    scapy_all: Any,
    packet: Any,
    request: JSONObject,
    send_mode: str,
) -> None:
    kwargs = {"iface": _resolve_capture_interface(request, scapy_all), "verbose": False}
    if send_mode == "link-layer":
        scapy_all.sendp(packet, **kwargs)
    else:
        scapy_all.send(packet, **kwargs)


def _materialized_send_packet(
    scapy_all: Any,
    packet: Any,
    request: JSONObject,
    root: str | None,
) -> tuple[Any, str | None, str]:
    send_mode = _send_mode_for_root(root)
    if send_mode == "link-layer":
        return packet, root, send_mode
    if _can_send_as_ethernet(request):
        ether_type = 0x86DD if packet.haslayer(scapy_all.IPv6) else 0x0800
        frame = (
            scapy_all.Ether(
                src=_address_value(request, "local_addresses", "mac"),
                dst=_address_value(request, "peer_addresses", "mac"),
                type=ether_type,
            )
            / packet
        )
        return frame, "link:ethernet", "link-layer"
    return packet, root, send_mode


def _can_send_as_ethernet(request: JSONObject) -> bool:
    return (
        _address_value(request, "local_addresses", "mac") is not None
        and _address_value(request, "peer_addresses", "mac") is not None
    )


def _matches_live_capture(scapy_all: Any, packet: Any, request: JSONObject) -> bool:
    matches = _request_capture_matches(request)
    if not matches:
        return True
    return any(
        _packet_matches_capture_match(scapy_all, packet, match)
        for match in matches
    )


def _request_capture_filter(request: JSONObject) -> str | None:
    metadata = json_object(request.get("metadata", {}), "metadata")
    value = metadata.get("capture_filter")
    if isinstance(value, str) and value:
        return value
    filters = [
        packet.get("capture_filter")
        for packet in _request_packet_metadata_values(request)
        if isinstance(packet.get("capture_filter"), str) and packet.get("capture_filter")
    ]
    if not filters:
        return None
    unique = list(dict.fromkeys(str(item) for item in filters))
    if len(unique) == 1:
        return unique[0]
    return " or ".join(f"({item})" for item in unique)


def _request_capture_matches(request: JSONObject) -> list[JSONObject]:
    matches: list[JSONObject] = []
    for packet in _request_packet_metadata_values(request):
        raw_match = packet.get("capture_match")
        if not isinstance(raw_match, Mapping):
            continue
        matches.append(json_object(raw_match, "metadata.packets[].capture_match"))
    return matches


def _capture_filter_for_vector(request: JSONObject, vector: EncodedVector) -> str | None:
    metadata = _request_packet_metadata(request, vector.plan.index)
    value = metadata.get("capture_filter")
    return value if isinstance(value, str) and value else None


def _capture_match_for_vector(request: JSONObject, vector: EncodedVector) -> JSONObject | None:
    metadata = _request_packet_metadata(request, vector.plan.index)
    value = metadata.get("capture_match")
    if not isinstance(value, Mapping):
        return None
    return json_object(value, "metadata.packets[].capture_match")


def _packet_matches_capture_match(
    scapy_all: Any,
    packet: Any,
    match: Mapping[str, object],
) -> bool:
    family = match.get("family")
    protocol = match.get("protocol")
    source = match.get("src")
    destination = match.get("dst")
    if family == "ipv4":
        if not packet.haslayer(scapy_all.IP):
            return False
        ip = packet[scapy_all.IP]
    elif family == "ipv6":
        if not packet.haslayer(scapy_all.IPv6):
            return False
        ip = packet[scapy_all.IPv6]
    else:
        ip = None

    if ip is not None:
        if isinstance(source, str) and source and ip.src != source:
            return False
        if isinstance(destination, str) and destination and ip.dst != destination:
            return False

    return _packet_matches_protocol(scapy_all, packet, protocol)


def _packet_matches_protocol(scapy_all: Any, packet: Any, protocol: object) -> bool:
    if protocol == "dns":
        if hasattr(scapy_all, "DNS") and packet.haslayer(scapy_all.DNS):
            return True
        if not packet.haslayer(scapy_all.UDP):
            return False
        udp = packet[scapy_all.UDP]
        return udp.sport == 53 or udp.dport == 53
    if protocol == "udp":
        return packet.haslayer(scapy_all.UDP)
    if protocol == "tcp":
        return packet.haslayer(scapy_all.TCP)
    if protocol == "icmp":
        return packet.haslayer(scapy_all.ICMP)
    if protocol == "icmpv6":
        return _has_layer_name_prefix(packet, "ICMPv6")
    if protocol == "arp":
        return hasattr(scapy_all, "ARP") and packet.haslayer(scapy_all.ARP)
    return True


def _has_layer_name_prefix(packet: Any, prefix: str) -> bool:
    try:
        layers = packet.layers()
    except Exception:
        return False
    return any(
        getattr(layer, "__name__", "").startswith(prefix)
        for layer in layers
    )


def _address_value(request: JSONObject, group: str, family: str) -> str | None:
    addresses = request.get(group)
    if not isinstance(addresses, dict):
        return None
    value = addresses.get(family)
    return value if isinstance(value, str) and value else None


def _decode_observed_capture_slice(
    capture_slice: CaptureSlice,
    vector: EncodedVector,
) -> DecodedModel:
    return normalize_packet(
        capture_slice.packet,
        root=capture_slice.compare_root,
        source_hex=capture_slice.comparable_raw.hex(),
        feature_tags=vector.plan.feature_tags,
    )


def _capture_slice_for_root(
    scapy_all: Any,
    packet: Any,
    compare_root: str | None,
) -> CaptureSlice:
    root = _canonical_compare_root(compare_root)
    full_raw = bytes(scapy_all.raw(packet))
    if root == "l3:ipv4":
        if not packet.haslayer(scapy_all.IP):
            raise ValueError("captured packet has no IPv4 header for l3:ipv4 compare root")
        comparable_raw = _trim_ipv4_capture_padding(bytes(scapy_all.raw(packet[scapy_all.IP])))
        comparable_packet = scapy_all.IP(comparable_raw)
    elif root == "l3:ipv6":
        if not packet.haslayer(scapy_all.IPv6):
            raise ValueError("captured packet has no IPv6 header for l3:ipv6 compare root")
        comparable_packet = packet[scapy_all.IPv6]
        comparable_raw = bytes(scapy_all.raw(comparable_packet))
    elif root == "link:ethernet":
        if not packet.haslayer(scapy_all.Ether):
            raise ValueError("captured packet has no Ethernet frame for link:ethernet compare root")
        comparable_packet = packet
        comparable_raw = bytes(scapy_all.raw(comparable_packet))
    else:  # pragma: no cover - _canonical_compare_root raises first.
        raise ValueError(f"unsupported capture compare root: {compare_root}")
    return CaptureSlice(
        compare_root=root,
        full_raw=full_raw,
        comparable_raw=comparable_raw,
        packet=comparable_packet,
    )


def _trim_ipv4_capture_padding(raw: bytes) -> bytes:
    if len(raw) < 4 or raw[0] >> 4 != 4:
        return raw
    ihl = (raw[0] & 0x0F) * 4
    total_length = int.from_bytes(raw[2:4], "big")
    if ihl < 20 or total_length < ihl or total_length > len(raw):
        return raw
    return raw[:total_length]


def _compare_root_for_vector(request: JSONObject, vector: EncodedVector) -> str:
    packet_metadata = _request_packet_metadata(request, vector.plan.index)
    compare_root = _optional_string(packet_metadata.get("compare_root"))
    if compare_root is None:
        compare_root = vector.root or vector.decoder
    return _canonical_compare_root(compare_root)


def _request_packet_metadata(request: JSONObject, index: int) -> JSONObject:
    for packet in _request_packet_metadata_values(request):
        if packet.get("index") == index:
            return packet
    return {}


def _request_packet_metadata_values(request: JSONObject) -> list[JSONObject]:
    metadata = json_object(request.get("metadata", {}), "metadata")
    packets = metadata.get("packets")
    if not isinstance(packets, list):
        return []
    output: list[JSONObject] = []
    for value in packets:
        if not isinstance(value, dict):
            continue
        packet = {
            key: item
            for key, item in value.items()
            if isinstance(key, str)
        }
        output.append(json_object(packet, "metadata.packets[]"))
    return output


def _canonical_compare_root(root: str | None) -> str:
    if root in CAPTURE_COMPARE_ROOTS:
        return CAPTURE_COMPARE_ROOTS[root]
    raise ValueError(f"wire compare root unavailable for live capture: {root!r}")


def _status_metadata(status: JSONObject) -> JSONObject:
    metadata = status.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _send_mode_for_root(root: str | None) -> str:
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
    return "network-layer"


def _endpoint_response(
    request: JSONObject,
    *,
    dry_run: bool,
    sent_count: int,
    received_count: int,
    decoded_models: list[JSONObject],
    captures: list[JSONObject],
    per_index_status: list[JSONObject],
    errors: list[str],
    detail: JSONObject,
) -> JSONObject:
    return {
        "provider": _required_string(request, "provider"),
        "backend": _required_string(request, "backend"),
        "direction": _required_string(request, "direction"),
        "endpoint_id": _required_string(request, "endpoint_id"),
        "endpoint_role": _required_string(request, "endpoint_role"),
        "sent_count": sent_count,
        "received_count": received_count,
        "decoded_models": decoded_models,
        "captures": captures,
        "per_index_status": per_index_status,
        "errors": errors,
        "artifact_paths": json_object(request.get("artifact_paths", {}), "artifact_paths"),
        "metadata": {
            "backend": BACKEND_NAME,
            "dry_run": dry_run,
            "live_packet_exchange": not dry_run,
            "local_addresses": json_object(
                request.get("local_addresses", {}),
                "local_addresses",
            ),
            "peer_addresses": json_object(
                request.get("peer_addresses", {}),
                "peer_addresses",
            ),
            "peer_role": _required_string(request, "peer_role"),
            "profile": _required_string(request, "profile"),
            "seed": _int_value(request.get("seed"), 0),
            "detail": detail,
        },
    }


def _index_status(
    request: JSONObject,
    index: int,
    status: str,
    *,
    sent: bool,
    received: bool,
    decoded_count: int,
    capture_paths: list[str],
    errors: list[str],
    metadata: JSONObject,
) -> JSONObject:
    return {
        "index": index,
        "direction": _required_string(request, "direction"),
        "status": status,
        "sent": sent,
        "received": received,
        "decoded_count": decoded_count,
        "sent_raw_hex": _optional_status_string(metadata.get("sent_raw_hex")),
        "send_root": _optional_status_string(metadata.get("send_root")),
        "send_mode": _optional_status_string(metadata.get("send_mode")),
        "observed_raw_hex": _optional_status_string(metadata.get("observed_raw_hex")),
        "capture_root": _optional_status_string(metadata.get("capture_root")),
        "capture_link_type": _optional_status_string(metadata.get("capture_link_type")),
        "capture_path": _optional_status_string(metadata.get("capture_path")),
        "byte_length": _optional_status_int(metadata.get("byte_length")),
        "capture_paths": capture_paths,
        "errors": errors,
        "metadata": metadata,
    }


def _optional_status_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _optional_status_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _read_request(input_path: str) -> object:
    if input_path == "-":
        return json.loads(sys.stdin.read())
    return json.loads(Path(input_path).read_text(encoding="utf-8"))


def _artifact_path(
    out_dir: Path,
    artifact_paths: JSONObject,
    key: str,
    fallback: str,
) -> Path:
    value = artifact_paths.get(key)
    path = Path(value) if isinstance(value, str) else out_dir / fallback
    if path.is_absolute():
        return path
    return out_dir / path


def _packet_plan_values(request: JSONObject) -> list[object]:
    value = request.get("packet_plans")
    if not isinstance(value, list):
        raise ValueError("live endpoint request packet_plans must be a list")
    return value


def _packet_plan_from_object(value: object, name: str) -> PacketPlan:
    plan = json_object(value, name)
    fields_object = json_object(plan.get("fields", {}), f"{name}.fields")
    fields = {
        layer: json_object(layer_fields, f"{name}.fields.{layer}")
        for layer, layer_fields in fields_object.items()
    }
    return PacketPlan(
        stack=_string_values(plan.get("stack", []), f"{name}.stack"),
        fields=fields,
        profile=_optional_string(plan.get("profile")) or "unknown",
        seed=_int_value(plan.get("seed"), 0),
        index=_int_value(plan.get("index"), 0),
        direction=_optional_string(plan.get("direction"))
        or _required_string(json_object(value, name), "direction"),
        family=_optional_string(plan.get("family")),
        feature_tags=_string_values(plan.get("feature_tags", []), f"{name}.feature_tags"),
        case=_optional_string(plan.get("case")),
        strict_bytes=plan.get("strict_bytes") is not False,
        metadata=json_object(plan.get("metadata", {}), f"{name}.metadata"),
    )


def _phase_role(request: JSONObject) -> str:
    metadata = json_object(request.get("metadata", {}), "metadata")
    phase_role = _optional_string(metadata.get("phase_role"))
    if phase_role is not None:
        return phase_role
    direction = _required_string(request, "direction")
    if direction == "reference_to_libcrafter":
        return "sender"
    if direction == "libcrafter_to_reference":
        return "receiver"
    raise ValueError(f"cannot infer Scapy endpoint phase for direction={direction}")


def _required_string(value: JSONObject, key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"live endpoint request requires string field {key}")
    return item


def _optional_string(value: object) -> str | None:
    if value is None or isinstance(value, str):
        return value
    return str(value)


def _string_values(value: object, name: str) -> list[str]:
    return string_list(value, name)


def _int_value(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return default


def _packet_link_type(packet: Any) -> str:
    name = getattr(packet, "name", None)
    return str(name) if name is not None else type(packet).__name__


def _require_live_capability(
    capabilities: BackendCapabilities | BackendRegistration | None,
) -> None:
    resolved = _capability_contract(capabilities)
    if not resolved.live_endpoint:
        raise ValueError("unsupported backend capability: Scapy live helper requires live_endpoint")


def _capability_contract(
    capabilities: BackendCapabilities | BackendRegistration | None,
) -> BackendCapabilities:
    if capabilities is None:
        return get_backend(BACKEND_NAME).capabilities
    if isinstance(capabilities, BackendRegistration):
        return capabilities.capabilities
    return capabilities


if __name__ == "__main__":
    raise SystemExit(main())
