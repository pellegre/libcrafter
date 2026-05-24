"""Scapy live backend endpoint and dry-run planning helpers."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Sequence
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
                    "capture_root": vector.root,
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
    captured = scapy_all.sniff(
        iface=_required_string(request, "interface"),
        count=max(1, len(vectors)),
        timeout=max(1, _int_value(request.get("timeout_seconds"), 30)),
        lfilter=lambda packet: _matches_live_capture(scapy_all, packet, request),
    )

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
            observed_raw = _observed_packet_bytes(scapy_all, captured[offset], vector)
            decoded = _decode_observed_packet(scapy_all, captured[offset], vector)
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
                        "capture_root": vector.root,
                        "capture_link_type": capture_link_type,
                        "capture_path": capture_path,
                        "byte_length": len(observed_raw),
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
            "observed_packets": [
                {
                    "index": status["index"],
                    "observed_raw_hex": status.get("observed_raw_hex"),
                    "capture_root": status.get("capture_root"),
                    "capture_link_type": status.get("capture_link_type"),
                    "byte_length": status.get("byte_length"),
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


def _send_packet(
    scapy_all: Any,
    packet: Any,
    request: JSONObject,
    send_mode: str,
) -> None:
    kwargs = {"iface": _required_string(request, "interface"), "verbose": False}
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
    local_ipv4 = _address_value(request, "local_addresses", "ipv4")
    peer_ipv4 = _address_value(request, "peer_addresses", "ipv4")
    if local_ipv4 is not None and peer_ipv4 is not None:
        if not packet.haslayer(scapy_all.IP):
            return False
        ip = packet[scapy_all.IP]
        if ip.src != peer_ipv4 or ip.dst != local_ipv4:
            return False
        return packet.haslayer(scapy_all.UDP)
    return True


def _address_value(request: JSONObject, group: str, family: str) -> str | None:
    addresses = request.get(group)
    if not isinstance(addresses, dict):
        return None
    value = addresses.get(family)
    return value if isinstance(value, str) and value else None


def _decode_observed_packet(
    scapy_all: Any,
    packet: Any,
    vector: EncodedVector,
) -> DecodedModel:
    root = vector.root or vector.decoder
    observed = _packet_for_root(scapy_all, packet, root)
    raw_bytes = _observed_packet_bytes(scapy_all, packet, vector)
    return normalize_packet(
        observed,
        root=root,
        source_hex=raw_bytes.hex(),
        feature_tags=vector.plan.feature_tags,
    )


def _observed_packet_bytes(
    scapy_all: Any,
    packet: Any,
    vector: EncodedVector,
) -> bytes:
    root = vector.root or vector.decoder
    observed = _packet_for_root(scapy_all, packet, root)
    return bytes(scapy_all.raw(observed))


def _packet_for_root(scapy_all: Any, packet: Any, root: str | None) -> Any:
    if root in {"IP", "l3:ipv4"} and packet.haslayer(scapy_all.IP):
        return packet[scapy_all.IP]
    if root in {"IPv6", "l3:ipv6"} and packet.haslayer(scapy_all.IPv6):
        return packet[scapy_all.IPv6]
    if root in {"Raw", "l3:raw", "link:raw"} and packet.haslayer(scapy_all.Raw):
        return packet[scapy_all.Raw]
    return packet


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
