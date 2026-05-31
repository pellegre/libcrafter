"""Command-line interface for oracle packet validation."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import posixpath
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
import time
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from . import bootstrap as oracle_bootstrap
from .backends import (
    BackendCapabilityName,
    BackendRegistration,
    UnknownBackendError,
    backend_report_metadata,
    get_backend,
    get_backend_capability_registration,
    registered_backend_names,
)
from .compare import compare_decoded_models, failure_indexes
from .model import (
    ComparisonResult,
    DecodedModel,
    EncodedVector,
    JSONObject,
    JSONValue,
    PacketPlan,
    RunReport,
    dumps_json,
    read_json,
    write_json,
)
from .report import DEFAULT_OUTPUT_ROOT, REPO_ROOT


PCAP_CONTRACT_SPEC = "features/pcap.yaml"
PCAP_LINK_TYPES_SPEC = "features/pcap-link-types.yaml"
GENERATOR_SELECTED_SPECS = (
    "tools/oracle/specs/stacks.yaml",
    "tools/oracle/specs/profiles.yaml",
)
PCAP_SELECTED_SPECS = (
    PCAP_CONTRACT_SPEC,
    PCAP_LINK_TYPES_SPEC,
    *GENERATOR_SELECTED_SPECS,
)
LIVE_COUNT_FIELDS = (
    "generated_count",
    "eligible_count",
    "skipped_count",
    "sent_count",
    "captured_count",
    "parsed_count",
    "byte_passed_count",
    "decode_passed_count",
    "failed_count",
)
LIVE_ROOT_ALIASES = {
    "Ether": "link:ethernet",
    "IP": "l3:ipv4",
    "IPv4": "l3:ipv4",
    "IPv6": "l3:ipv6",
    "link:ethernet": "link:ethernet",
    "l3:ipv4": "l3:ipv4",
    "l3:ipv6": "l3:ipv6",
    # l2:ipv4 sends IPv4 over the link path; for network-layer send the raw
    # bytes are the IPv4 datagram, so they canonicalize to l3 for comparison.
    # (Ethernet-wrapped link-layer sends record raw_root as link:ethernet and
    # are sliced to l3 by the ethernet branch in _live_comparable_wire_hex.)
    "l2:ipv4": "l3:ipv4",
    "l2:ipv6": "l3:ipv6",
}
# Seconds to let a receiver's live capture fully open (remote process start,
# pcap open, BPF filter compile) before the sender transmits. Too short loses
# the send/receive race and the receiver captures zero packets. Override via
# ORACLE_LIVE_CAPTURE_SETTLE_SECONDS for slower or faster endpoints.
LIVE_RECEIVER_STARTUP_GRACE_SECONDS = max(
    1.0, float(os.environ.get("ORACLE_LIVE_CAPTURE_SETTLE_SECONDS", "35"))
)
LIVE_VM_RECEIVER_STARTUP_GRACE_SECONDS = max(
    1.0,
    float(
        os.environ.get(
            "ORACLE_LIVE_VM_CAPTURE_SETTLE_SECONDS",
            str(LIVE_RECEIVER_STARTUP_GRACE_SECONDS),
        )
    ),
)
FINAL_REPORT_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("formatting", ("cargo", "fmt", "--all", "--", "--check")),
    ("clippy", ("cargo", "clippy", "--workspace", "--all-targets")),
    ("workspace-tests", ("cargo", "test", "--workspace")),
    ("example-builds", ("cargo", "build", "--examples")),
    (
        "oracle-offline-ci",
        (
            "tools/oracle/run",
            "offline",
            "--backend",
            "scapy",
            "--profile",
            "ci",
            "--seed",
            "12345",
            "--count",
            "2000",
        ),
    ),
    (
        "oracle-offline-smoke",
        (
            "tools/oracle/run",
            "offline",
            "--backend",
            "scapy",
            "--profile",
            "smoke",
            "--seed",
            "1",
            "--count",
            "50",
        ),
    ),
    (
        "oracle-pcap-smoke",
        (
            "tools/oracle/run",
            "pcap",
            "--backend",
            "scapy",
            "--profile",
            "smoke",
            "--seed",
            "1",
            "--count",
            "50",
        ),
    ),
    (
        "oracle-live-local-dry-run",
        (
            "tools/oracle/run",
            "live",
            "--backend",
            "scapy",
            "--provider",
            "local-dry-run",
            "--profile",
            "smoke",
            "--seed",
            "1",
            "--count",
            "10",
        ),
    ),
)
SCAPY_IMPORT_RE = re.compile(r"\b(?:from\s+scapy\b|import\s+scapy\b)")
REPORT_SCAN_ROOTS = (
    ".github",
    ".agents",
    "crates",
    "docs",
    "examples",
    "tests",
    "tools",
    "Cargo.toml",
    "README.md",
)
REPORT_SCAN_EXCLUDED_DIRS = {
    ".git",
    ".libcrafter-live",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "target",
    "venv",
}

def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="artifact output root (default: %(default)s)",
    )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def _add_generation_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--backend",
        choices=registered_backend_names(),
        default="scapy",
        help="reference backend to target (default: %(default)s)",
    )
    parser.add_argument(
        "--profile",
        default="smoke",
        help="sampling profile from profiles.yaml (default: %(default)s)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="deterministic generator seed (default: %(default)s)",
    )
    parser.add_argument(
        "--count",
        type=_positive_int,
        default=10,
        help="number of generated packet plans (default: %(default)s)",
    )
    parser.add_argument(
        "--case",
        dest="case_name",
        help="case name filter or reproduction coordinate",
    )
    parser.add_argument(
        "--feature",
        help="feature name filter or reproduction coordinate",
    )
    parser.add_argument(
        "--family",
        help="protocol family filter from stacks.yaml",
    )
    parser.add_argument(
        "--root",
        help="root decoder filter from stacks.yaml, such as link:ethernet or l3:ipv4",
    )
    parser.add_argument(
        "--index",
        type=_non_negative_int,
        help="generate one packet plan at the selected index",
    )


def _not_implemented(args: argparse.Namespace) -> int:
    print(
        f"oracle {args.mode} mode is not implemented yet; parsed output root: {args.out}",
        file=sys.stderr,
    )
    return 2


def _generate(args: argparse.Namespace) -> int:
    from .generator import generate_plans

    try:
        plans = generate_plans(
            seed=args.seed,
            profile=args.profile,
            backend=args.backend,
            count=args.count,
            root=args.root,
            family=args.family,
            case=args.case_name,
            feature=args.feature,
            direction=args.direction,
            index=args.index,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    output_dir = Path(args.out)
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    plans_path = output_dir / "plans.json"
    report = RunReport(
        mode="generate",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(plans),
        status="generated",
        selected_specs=list(GENERATOR_SELECTED_SPECS),
        artifacts=[str(plans_path)],
        artifact_paths=[str(plans_path)],
        packet_plans=plans,
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            "generated_count": len(plans),
            "root": args.root,
            "family": args.family,
            "case": args.case_name,
            "feature": args.feature,
            "plans": [plan.to_dict() for plan in plans],
        },
    )
    write_json(plans_path, report)
    print(f"generate: status=generated count={len(plans)} plans={plans_path}")
    return 0


def _corpus(args: argparse.Namespace) -> int:
    from .corpus import write_corpus_report

    direction = getattr(args, "direction", "reference_to_libcrafter")
    try:
        report = _build_corpus_report_from_generation(args, direction=direction)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    output_dir = Path(args.out)
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    plans_path = output_dir / "plans.json"
    write_corpus_report(plans_path, report)
    print(f"corpus: status=generated count={len(report.packets)} plans={plans_path}")
    return 0


def _build_corpus_report_from_generation(
    args: argparse.Namespace,
    *,
    direction: str = "reference_to_libcrafter",
):
    from .corpus import build_corpus_report
    from .generator import generate_plans

    plans = generate_plans(
        seed=args.seed,
        profile=args.profile,
        backend=args.backend,
        count=args.count,
        root=args.root,
        family=args.family,
        case=args.case_name,
        feature=args.feature,
        direction=direction,
        index=args.index,
    )
    backend_versions = _backend_versions(args.backend)
    libcrafter_info = _libcrafter_info()
    return build_corpus_report(
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=args.count,
        plans=plans,
        selected_specs=GENERATOR_SELECTED_SPECS,
        metadata={
            "requested_count": args.count,
            "generated_count": len(plans),
            "filters": {
                "root": args.root,
                "family": args.family,
                "case": args.case_name,
                "feature": args.feature,
                "index": args.index,
            },
            "backend_metadata": backend_versions.get(args.backend, {}),
            "backend_versions": backend_versions,
            "libcrafter": libcrafter_info,
        },
    )


def _build_live_corpus_report_from_generation(
    args: argparse.Namespace,
    *,
    direction: str = "reference_to_libcrafter",
):
    if not _should_use_udp_live_case_selection(args):
        return _build_corpus_report_from_generation(args, direction=direction)
    return _build_udp_live_case_corpus_report(args, direction=direction)


def _should_use_udp_live_case_selection(args: argparse.Namespace) -> bool:
    return (
        args.profile == "smoke"
        and args.family == "udp"
        and args.root is None
        and args.case_name is None
        and args.feature is None
        and args.index is None
    )


def _build_udp_live_case_corpus_report(
    args: argparse.Namespace,
    *,
    direction: str,
):
    from .corpus import build_corpus_report
    from .generator import generate_plans

    live_cases = _udp_options_live_case_specs()
    plans: list[PacketPlan] = []
    for offset in range(args.count):
        live_case = live_cases[offset % len(live_cases)]
        feature = _optional_live_case_string(live_case, "feature")
        generated = generate_plans(
            seed=args.seed,
            profile=args.profile,
            backend=args.backend,
            count=1,
            root=_required_live_case_string(live_case, "root"),
            family=_required_live_case_string(live_case, "family"),
            case=_required_live_case_string(live_case, "case"),
            feature=feature,
            direction=direction,
            index=offset,
        )
        plan = generated[0]
        selector = {
            "source": "tools/oracle/specs/features/udp-options.yaml:live_cases",
            "sequence_index": offset % len(live_cases),
            "name": _required_live_case_string(live_case, "name"),
            "case": live_case["case"],
            "root": live_case["root"],
            "family": live_case["family"],
            "feature": feature,
            "expected_live": live_case.get("expected_live"),
            "skip_reasons": live_case.get("skip_reasons", []),
        }
        plans.append(
            replace(
                plan,
                feature_tags=list(
                    dict.fromkeys([*plan.feature_tags, "live_udp_options"])
                ),
                metadata={
                    **plan.metadata,
                    "live_case_selection": selector,
                },
            )
        )

    backend_versions = _backend_versions(args.backend)
    libcrafter_info = _libcrafter_info()
    return build_corpus_report(
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=args.count,
        plans=plans,
        selected_specs=GENERATOR_SELECTED_SPECS,
        metadata={
            "requested_count": args.count,
            "generated_count": len(plans),
            "filters": {
                "root": args.root,
                "family": args.family,
                "case": args.case_name,
                "feature": args.feature,
                "index": args.index,
            },
            "live_case_selection": {
                "feature": "udp_options",
                "profile": args.profile,
                "family": args.family,
                "source": "tools/oracle/specs/features/udp-options.yaml:live_cases",
                "case_count": len(live_cases),
                "cases": live_cases,
            },
            "backend_metadata": backend_versions.get(args.backend, {}),
            "backend_versions": backend_versions,
            "libcrafter": libcrafter_info,
        },
    )


def _udp_options_live_case_specs() -> list[JSONObject]:
    from .spec_loader import load_oracle_specs

    specs = load_oracle_specs()
    feature = specs.features.get("udp_options")
    if feature is None:
        raise ValueError("udp_options feature spec is missing")
    raw_cases = feature.raw.get("live_cases", [])
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("features/udp-options.yaml live_cases must be a non-empty list")

    cases: list[JSONObject] = []
    for index, raw_case in enumerate(raw_cases):
        case = _json_object(raw_case, f"udp_options.live_cases[{index}]")
        for key in ("name", "case", "root", "family"):
            _required_live_case_string(case, key)
        feature_name = _optional_live_case_string(case, "feature")
        if feature_name is not None and feature_name != "udp_options":
            raise ValueError(
                "udp_options.live_cases feature must be null or udp_options"
            )
        cases.append(case)
    return cases


def _required_live_case_string(case: Mapping[str, object], key: str) -> str:
    value = case.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"udp_options.live_cases requires string field {key}")
    return value


def _optional_live_case_string(case: Mapping[str, object], key: str) -> str | None:
    value = case.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"udp_options.live_cases field {key} must be null or string")
    return value


def _offline_required_capabilities(
    args: argparse.Namespace,
) -> tuple[BackendCapabilityName, ...]:
    if args.emit_decoded:
        return ("encode", "decode")
    if args.emit_vectors:
        return ("encode",)
    if args.dry_plan:
        return ()
    if args.direction == "reference_to_libcrafter":
        return ("encode", "decode")
    if args.direction == "libcrafter_to_reference":
        return ("decode",)
    return ()


def _offline_corpus_plans(
    args: argparse.Namespace,
) -> tuple[list[PacketPlan], list[str], JSONObject]:
    from .corpus import CorpusFormatError, load_corpus_report

    corpus_path: Path | None = None
    corpus_source = "generated"
    if args.corpus is None:
        corpus_report = _build_corpus_report_from_generation(args, direction=args.direction)
    else:
        corpus_source = "provided"
        corpus_path = Path(args.corpus)
        if not corpus_path.is_absolute():
            corpus_path = REPO_ROOT / corpus_path
        corpus_report = load_corpus_report(corpus_path)
        if corpus_report.backend != args.backend:
            raise CorpusFormatError(
                f"{corpus_path}: backend {corpus_report.backend!r} does not match "
                f"requested backend {args.backend!r}"
            )

    packets = list(corpus_report.packets)
    if args.index is not None:
        packets = [packet for packet in packets if packet.plan.index == args.index]

    plans: list[PacketPlan] = []
    eligibility: list[JSONObject] = []
    skipped_count = 0
    for position, packet in enumerate(packets):
        eligible = packet.offline.eligible is not False
        reason = None if eligible else packet.offline.reason or "offline eligibility marked false"
        decision: JSONObject = {
            "position": position,
            "packet_id": packet.packet_id,
            "corpus_index": packet.index,
            "packet_index": packet.plan.index,
            "direction": args.direction,
            "eligible": eligible,
            "reason": reason,
        }
        eligibility.append(decision)
        if not eligible:
            skipped_count += 1
            continue
        plans.append(replace(packet.plan, direction=args.direction))

    selected_specs = list(
        dict.fromkeys([*corpus_report.selected_specs, *_selected_specs_for_plans(plans)])
    )
    metadata: JSONObject = {
        "corpus_id": corpus_report.corpus_id,
        "corpus_source": corpus_source,
        "corpus_path": str(corpus_path) if corpus_path is not None else None,
        "corpus_backend": corpus_report.backend,
        "corpus_profile": corpus_report.profile,
        "corpus_seed": corpus_report.seed,
        "corpus_count": corpus_report.count,
        "generated_count": len(packets),
        "offline_eligible_count": len(plans),
        "offline_skipped_count": skipped_count,
        "packet_indexes": [plan.index for plan in plans],
        "offline_eligibility": eligibility,
    }
    return plans, selected_specs, metadata


def _live_case_byte_policies() -> dict[str, str]:
    """Resolve spec-declared case byte policies for live/wire eligibility.

    Live exchange is a two-machine packet writer/capture comparison: a
    ``normalized`` case only agrees on the decoded model (not the declared wire
    bytes) and a ``structured_error`` case is malformed input, so both are
    marked live-ineligible with an explicit skip reason. Loaded from the same
    spec ``supported_cases`` block the corpus already reads, so live selection
    stays data-driven; returns an empty map if specs fail to load, leaving prior
    (capability-only) wire eligibility behavior intact.
    """

    try:
        from .generator import case_byte_policy_index

        return case_byte_policy_index()
    except Exception:
        return {}


def _live_corpus_plans(
    args: argparse.Namespace,
    *,
    wire_provider: str,
    direction: str,
    provider_capabilities: Mapping[str, object] | None = None,
) -> tuple[list[PacketPlan], list[str], JSONObject]:
    from .corpus import (
        CorpusFormatError,
        SKIP_PROVIDER_CAPABILITY_UNAVAILABLE,
        corpus_eligibility_summary,
        load_corpus_report,
        populate_corpus_eligibility,
        wire_comparison_policy,
    )

    corpus_path: Path | None = None
    corpus_source = "generated"
    if getattr(args, "corpus", None) is None:
        corpus_report = _build_live_corpus_report_from_generation(
            args,
            direction=direction,
        )
    else:
        corpus_source = "provided"
        corpus_path = Path(args.corpus)
        if not corpus_path.is_absolute():
            corpus_path = REPO_ROOT / corpus_path
        corpus_report = load_corpus_report(corpus_path)
        if corpus_report.backend != args.backend:
            raise CorpusFormatError(
                f"{corpus_path}: backend {corpus_report.backend!r} does not match "
                f"requested backend {args.backend!r}"
            )

    packets = list(corpus_report.packets)
    provider_capabilities_object: JSONObject | None = None
    if provider_capabilities is not None:
        provider_capabilities_object = _json_object(
            json.loads(dumps_json(provider_capabilities)),
            "provider_capabilities",
        )
        packets = populate_corpus_eligibility(
            backend=args.backend,
            packets=packets,
            provider_capabilities=provider_capabilities_object,
            wire_provider=wire_provider,
            case_byte_policies=_live_case_byte_policies(),
        )
    if args.index is not None:
        packets = [packet for packet in packets if packet.plan.index == args.index]

    plans: list[PacketPlan] = []
    eligibility: list[JSONObject] = []
    skip_reasons: dict[str, int] = {}
    skipped_count = 0
    for position, packet in enumerate(packets):
        decision = _live_wire_provider_decision(
            packet.wire.to_dict(),
            provider=wire_provider,
            fallback_reason=SKIP_PROVIDER_CAPABILITY_UNAVAILABLE,
        )
        eligible = bool(decision.get("eligible"))
        reasons = _live_wire_skip_reasons(
            decision,
            fallback_reason=SKIP_PROVIDER_CAPABILITY_UNAVAILABLE,
        )
        packet_decision: JSONObject = {
            "position": position,
            "packet_id": packet.packet_id,
            "corpus_index": packet.index,
            "packet_index": packet.plan.index,
            "provider": wire_provider,
            "eligible": eligible,
            "reason": None if eligible else reasons[0],
            "skip_reasons": [] if eligible else reasons,
        }
        if decision.get("compare_root") is not None:
            packet_decision["compare_root"] = decision["compare_root"]
        if isinstance(decision.get("strict_bytes"), bool):
            packet_decision["strict_bytes"] = decision["strict_bytes"]
        mutable_fields = _string_values(decision.get("mutable_fields", []))
        if mutable_fields:
            packet_decision["mutable_fields"] = mutable_fields
        eligibility.append(packet_decision)
        if not eligible:
            skipped_count += 1
            for reason in reasons:
                skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            continue

        policy = _live_wire_policy_from_decision(
            packet.plan,
            decision=decision,
            provider=wire_provider,
            fallback=wire_comparison_policy,
        )
        metadata = {
            **packet.plan.metadata,
            "corpus": {
                "corpus_id": corpus_report.corpus_id,
                "packet_id": packet.packet_id,
                "corpus_index": packet.index,
                "packet_index": packet.plan.index,
                "corpus_source": corpus_source,
                "corpus_path": str(corpus_path) if corpus_path is not None else None,
            },
            "wire": policy,
            "wire_eligibility": decision,
        }
        strict_bytes = decision.get("strict_bytes")
        plans.append(
            replace(
                packet.plan,
                direction=direction,
                strict_bytes=(
                    strict_bytes if isinstance(strict_bytes, bool) else packet.plan.strict_bytes
                ),
                metadata=metadata,
            )
        )

    selected_specs = list(
        dict.fromkeys(
            [
                *corpus_report.selected_specs,
                *_selected_specs_for_plans(plans),
            ]
        )
    )
    metadata: JSONObject = {
        "corpus_id": corpus_report.corpus_id,
        "corpus_source": corpus_source,
        "corpus_path": str(corpus_path) if corpus_path is not None else None,
        "corpus_backend": corpus_report.backend,
        "corpus_profile": corpus_report.profile,
        "corpus_seed": corpus_report.seed,
        "corpus_count": corpus_report.count,
        "requested_count": args.count,
        "generated_count": len(packets),
        "wire_provider": wire_provider,
        "wire_eligible_count": len(plans),
        "wire_skipped_count": skipped_count,
        "wire_skip_reasons": skip_reasons,
        "wire_skip_counts_by_reason": dict(skip_reasons),
        "wire_eligibility": eligibility,
        "packet_indexes": [plan.index for plan in plans],
    }
    live_case_selection = corpus_report.metadata.get("live_case_selection")
    if isinstance(live_case_selection, Mapping):
        metadata["live_case_selection"] = _json_object(
            json.loads(dumps_json(live_case_selection)),
            "corpus_report.metadata.live_case_selection",
        )
    if provider_capabilities_object is not None:
        metadata["provider_capabilities"] = provider_capabilities_object
        metadata["provider_capability_source"] = provider_capabilities_object.get("source")
        metadata["eligibility"] = corpus_eligibility_summary(packets)
    return plans, selected_specs, metadata


def _write_live_corpus_batch_artifact(
    output_dir: Path,
    *,
    corpus_metadata: Mapping[str, object],
    plans: Sequence[PacketPlan],
    directions: Sequence[str],
) -> Path:
    """Persist the ordered wire-eligible corpus batch used by live endpoints."""

    artifact_path = output_dir / "artifacts" / "corpus" / "wire-eligible-batch.json"
    write_json(
        artifact_path,
        {
            "corpus_id": corpus_metadata.get("corpus_id"),
            "corpus_source": corpus_metadata.get("corpus_source"),
            "corpus_path": corpus_metadata.get("corpus_path"),
            "wire_provider": corpus_metadata.get("wire_provider"),
            "generated_count": corpus_metadata.get("generated_count"),
            "wire_eligible_count": corpus_metadata.get("wire_eligible_count"),
            "wire_skipped_count": corpus_metadata.get("wire_skipped_count"),
            "wire_skip_reasons": corpus_metadata.get("wire_skip_reasons", {}),
            "execution_directions": list(directions),
            "packet_indexes": [plan.index for plan in plans],
            "packets": [plan.to_dict() for plan in plans],
            "wire_eligibility": corpus_metadata.get("wire_eligibility", []),
        },
    )
    return artifact_path


def _write_live_endpoint_protocol_artifacts(request, response) -> list[str]:
    """Write endpoint request/response artifacts referenced by the protocol."""

    artifact_paths = request.artifact_paths
    paths: list[str] = []
    request_path = artifact_paths.get("request")
    if isinstance(request_path, str) and request_path:
        write_json(request_path, request)
        paths.append(request_path)
    response_path = artifact_paths.get("response")
    if isinstance(response_path, str) and response_path:
        write_json(response_path, response)
        paths.append(response_path)
    decoded_path = artifact_paths.get("decoded_models")
    if isinstance(decoded_path, str) and decoded_path:
        write_json(decoded_path, response.decoded_models)
        paths.append(decoded_path)
    captures_path = artifact_paths.get("captures")
    if isinstance(captures_path, str) and captures_path:
        Path(captures_path).mkdir(parents=True, exist_ok=True)
        paths.append(captures_path)
    return paths


def _live_endpoint_pair_validation(
    *,
    direction: str,
    sender_request,
    receiver_request,
):
    from .live import LiveValidationCheck

    errors: list[str] = []
    sender_corpus = sender_request.metadata.get("corpus_id")
    receiver_corpus = receiver_request.metadata.get("corpus_id")
    if sender_corpus != receiver_corpus:
        errors.append("sender and receiver endpoint requests must share corpus_id")

    sender_indexes = [plan.index for plan in sender_request.packet_plans]
    receiver_indexes = [plan.index for plan in receiver_request.packet_plans]
    if sender_indexes != receiver_indexes:
        errors.append("sender and receiver endpoint requests must preserve packet order")

    sender_packet_ids = _live_endpoint_request_packet_ids(sender_request)
    receiver_packet_ids = _live_endpoint_request_packet_ids(receiver_request)
    if sender_packet_ids != receiver_packet_ids:
        errors.append("sender and receiver endpoint requests must share packet ids")

    return LiveValidationCheck(
        name="live-endpoint-pair-batch",
        passed=not errors,
        subject=direction,
        errors=errors,
        metadata={
            "direction": direction,
            "corpus_id": sender_corpus,
            "packet_indexes": sender_indexes,
            "packet_ids": sender_packet_ids,
        },
    )


def _live_endpoint_request_packet_ids(request) -> list[str]:
    packet_ids = request.metadata.get("packet_ids")
    if isinstance(packet_ids, list):
        return [packet_id for packet_id in packet_ids if isinstance(packet_id, str)]
    return []


def _live_wire_provider_decision(
    wire: Mapping[str, object],
    *,
    provider: str,
    fallback_reason: str,
) -> JSONObject:
    metadata = wire.get("metadata")
    if isinstance(metadata, Mapping):
        profiles = metadata.get("provider_profiles")
        if isinstance(profiles, Mapping):
            raw_decision = profiles.get(provider)
            if isinstance(raw_decision, Mapping):
                return {
                    key: value
                    for key, value in raw_decision.items()
                    if isinstance(key, str)
                }

        if metadata.get("provider") == provider:
            return {
                key: value
                for key, value in wire.items()
                if isinstance(key, str)
            }

    return {
        "provider": provider,
        "eligible": False,
        "reason": fallback_reason,
        "skip_reasons": [fallback_reason],
        "compare_root": wire.get("compare_root"),
        "strict_bytes": wire.get("strict_bytes"),
        "mutable_fields": wire.get("mutable_fields", []),
        "metadata": {
            "provider_available": False,
            "requested_provider": provider,
        },
    }


def _live_wire_skip_reasons(
    decision: Mapping[str, object],
    *,
    fallback_reason: str,
) -> list[str]:
    reasons = _string_values(decision.get("skip_reasons", []))
    reason = decision.get("reason")
    if isinstance(reason, str) and reason and reason not in reasons:
        reasons.insert(0, reason)
    return reasons or [fallback_reason]


def _live_wire_policy_from_decision(
    plan: PacketPlan,
    *,
    decision: Mapping[str, object],
    provider: str,
    fallback,
) -> JSONObject:
    metadata = decision.get("metadata")
    if isinstance(metadata, Mapping):
        raw_policy = metadata.get("mutation_policy")
        if isinstance(raw_policy, Mapping):
            return {
                key: value
                for key, value in raw_policy.items()
                if isinstance(key, str)
            }

    policy = fallback(plan, provider=provider)
    if decision.get("compare_root") is not None:
        policy["compare_root"] = decision["compare_root"]
    if isinstance(decision.get("strict_bytes"), bool):
        policy["strict_bytes"] = decision["strict_bytes"]
    mutable_fields = _string_values(decision.get("mutable_fields", []))
    if mutable_fields:
        policy["mutable_fields"] = mutable_fields
    policy["provider"] = provider
    return policy


def _live_corpus_accounting_validation(
    metadata: Mapping[str, object],
    *,
    provider: str,
):
    from .live import LiveValidationCheck

    generated_count = int(metadata.get("generated_count", 0))
    eligible_count = int(metadata.get("wire_eligible_count", 0))
    skipped_count = int(metadata.get("wire_skipped_count", 0))
    raw_eligibility = metadata.get("wire_eligibility", [])
    eligibility = raw_eligibility if isinstance(raw_eligibility, list) else []
    decision_eligible = sum(
        1
        for decision in eligibility
        if isinstance(decision, Mapping) and bool(decision.get("eligible"))
    )
    decision_skipped = len(eligibility) - decision_eligible
    errors: list[str] = []
    if generated_count != len(eligibility):
        errors.append("wire eligibility decisions must match generated packet count")
    if eligible_count + skipped_count != generated_count:
        errors.append("wire eligible plus skipped count must equal generated count")
    if decision_eligible != eligible_count:
        errors.append("wire eligible count must match eligibility decisions")
    if decision_skipped != skipped_count:
        errors.append("wire skipped count must match eligibility decisions")
    if skipped_count and not isinstance(metadata.get("wire_skip_reasons"), Mapping):
        errors.append("wire skipped packets must include skip counts by reason")

    return LiveValidationCheck(
        name="live-corpus-accounting",
        passed=not errors,
        subject=f"{provider}:generated-{generated_count}",
        errors=errors,
        metadata={
            "provider": provider,
            "generated_count": generated_count,
            "wire_eligible_count": eligible_count,
            "wire_skipped_count": skipped_count,
        },
    )


def _live_empty_direction_counts(
    corpus_metadata: Mapping[str, object],
    directions: Sequence[str],
) -> dict[str, JSONObject]:
    generated_count = _count_value(corpus_metadata.get("generated_count"))
    eligible_count = _count_value(corpus_metadata.get("wire_eligible_count"))
    skipped_count = _count_value(corpus_metadata.get("wire_skipped_count"))
    return {
        direction: {
            "generated_count": generated_count,
            "eligible_count": eligible_count,
            "skipped_count": skipped_count,
            "sent_count": 0,
            "captured_count": 0,
            "parsed_count": 0,
            "byte_passed_count": 0,
            "decode_passed_count": 0,
            "failed_count": 0,
        }
        for direction in directions
    }


def _live_count_metadata(direction_counts: Mapping[str, Mapping[str, object]]) -> JSONObject:
    directions: JSONObject = {}
    overall = {field: 0 for field in LIVE_COUNT_FIELDS}
    for direction, raw_counts in direction_counts.items():
        counts = {
            field: _count_value(raw_counts.get(field))
            for field in LIVE_COUNT_FIELDS
        }
        directions[direction] = counts
        for field, count in counts.items():
            overall[field] += count
    return {
        "eligible_count": overall["eligible_count"],
        "skipped_count": overall["skipped_count"],
        "sent_count": overall["sent_count"],
        "captured_count": overall["captured_count"],
        "parsed_count": overall["parsed_count"],
        "byte_passed_count": overall["byte_passed_count"],
        "decode_passed_count": overall["decode_passed_count"],
        "failed_count": overall["failed_count"],
        "live_counts": {
            **directions,
            "overall": overall,
            "directions": directions,
        },
    }


def _count_value(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return 0
    return 0


def _pcap_required_capabilities(
    args: argparse.Namespace,
) -> tuple[BackendCapabilityName, ...]:
    if args.direction == "reference_to_libcrafter":
        return ("encode", "pcap_write", "pcap_read")
    if args.direction == "libcrafter_to_reference":
        return ("pcap_read",)
    if args.direction == "roundtrip":
        return ("encode", "pcap_write", "pcap_read")
    return ()


def _require_backend_capabilities(
    args: argparse.Namespace,
    *,
    mode: str,
    required: tuple[BackendCapabilityName, ...],
    operation: str,
    report_path: Path | None,
    selected_specs: Sequence[str] = (),
) -> int | None:
    try:
        backend = get_backend(args.backend)
    except UnknownBackendError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    missing = backend.capabilities.missing(required)
    if missing:
        message = _missing_capability_message(backend, missing, operation)
        return _write_backend_support_report(
            args=args,
            mode=mode,
            backend=backend,
            message=message,
            operation=operation,
            required=required,
            missing=missing,
            report_path=report_path,
            selected_specs=selected_specs,
        )

    if required and not backend.availability.available:
        reason = backend.availability.reason or "backend dependency is unavailable"
        message = (
            f"unsupported backend availability: backend {backend.name} is unavailable: "
            f"{reason}; {operation} requires {', '.join(required)}"
        )
        return _write_backend_support_report(
            args=args,
            mode=mode,
            backend=backend,
            message=message,
            operation=operation,
            required=required,
            missing=(),
            report_path=report_path,
            selected_specs=selected_specs,
        )

    return None


def _missing_capability_message(
    backend: BackendRegistration,
    missing: Sequence[str],
    operation: str,
) -> str:
    required = ", ".join(missing)
    if backend.parser_only and any(
        capability in {"encode", "pcap_write"} for capability in missing
    ):
        return (
            f"unsupported backend capability: backend {backend.name} is parser-only "
            f"and cannot write; {operation} requires {required}"
        )
    if backend.parser_only and "live_endpoint" in missing:
        return (
            f"unsupported backend capability: backend {backend.name} is parser-only "
            f"and cannot act as a live endpoint; {operation} requires {required}"
        )
    return (
        f"unsupported backend capability: backend {backend.name} lacks {required}; "
        f"{operation} requires {required}"
    )


def _backend_not_implemented_report(
    args: argparse.Namespace,
    *,
    mode: str,
    operation: str,
    report_path: Path | None,
    selected_specs: Sequence[str] = (),
) -> int:
    backend = get_backend(args.backend)
    message = (
        f"unsupported backend implementation: backend {backend.name} has compatible "
        f"capabilities, but {operation} is not wired to an oracle adapter yet"
    )
    return _write_backend_support_report(
        args=args,
        mode=mode,
        backend=backend,
        message=message,
        operation=operation,
        required=(),
        missing=(),
        report_path=report_path,
        selected_specs=selected_specs,
    )


def _write_backend_support_report(
    *,
    args: argparse.Namespace,
    mode: str,
    backend: BackendRegistration,
    message: str,
    operation: str,
    required: Sequence[str],
    missing: Sequence[str],
    report_path: Path | None,
    selected_specs: Sequence[str],
) -> int:
    artifacts = [] if report_path is None else [str(report_path)]
    direction = getattr(args, "direction", "backend")
    if not isinstance(direction, str):
        direction = "backend"
    differences: list[JSONObject] = [
        {
            "path": "capabilities.enabled",
            "expected": list(required),
            "actual": backend.capabilities.enabled(),
        }
    ]
    if not backend.availability.available:
        differences.append(
            {
                "path": "availability",
                "expected": "available",
                "actual": backend.availability.to_dict(),
            }
        )

    reproduction_command = _requested_command()
    result = ComparisonResult(
        passed=False,
        direction=direction,
        expected={
            "operation": operation,
            "required_capabilities": list(required),
            "backend_available": True,
        },
        actual={
            "missing_capabilities": list(missing),
            "message": message,
        },
        strict_bytes=False,
        byte_equal=None,
        differences=differences,
        reproduction_command=reproduction_command,
        metadata={
            "operation": operation,
            "unsupported": True,
            "required_capabilities": list(required),
            "missing_capabilities": list(missing),
            "backend_metadata": {
                "actual": backend.to_dict(),
            },
        },
    )
    report = RunReport(
        mode=mode,
        backend=backend.name,
        profile=_arg_int_or_string(args, "profile", "unknown"),
        seed=_arg_int(args, "seed", 0),
        count=0,
        status="unsupported",
        selected_specs=list(selected_specs),
        artifacts=artifacts,
        artifact_paths=artifacts,
        results=[result],
        failures=[result],
        reproduction_commands=[reproduction_command],
        backend_versions=_backend_versions(backend.name),
        libcrafter=_libcrafter_info(),
        metadata={
            "operation": operation,
            "backend": backend.to_dict(),
            "requested_count": _arg_int(args, "count", 0),
            "unsupported_reason": message,
        },
    )
    if report_path is not None:
        write_json(report_path, report)
        print(f"{message}; report={report_path}", file=sys.stderr)
    else:
        print(message, file=sys.stderr)
    return 2


def _arg_int(args: argparse.Namespace, name: str, default: int) -> int:
    value = getattr(args, name, default)
    return value if isinstance(value, int) else default


def _arg_int_or_string(args: argparse.Namespace, name: str, default: str) -> str:
    value = getattr(args, name, default)
    return value if isinstance(value, str) else default


def _requested_command() -> str:
    return shlex.join(["tools/oracle/run", *sys.argv[1:]])


def _live_provider_workflow_command(commands: Sequence[object], purpose: str) -> object:
    for command in commands:
        if getattr(command, "purpose", None) == purpose:
            return command
    raise RuntimeError(f"provider workflow is missing purpose {purpose!r}")


def _live_provider_credential_label(provider_adapter) -> str:
    label = getattr(provider_adapter, "credential_label", None)
    if isinstance(label, str) and label:
        return label
    name = getattr(provider_adapter, "name", "provider")
    return f"{name} credentials"


def _live_provider_missing_credential_reason(provider_adapter) -> str:
    reason = getattr(provider_adapter, "missing_credential_reason", None)
    if isinstance(reason, str) and reason:
        return reason
    return f"missing {_live_provider_credential_label(provider_adapter)}"


def _live_provider_packet_exchange_metadata(
    provider_adapter,
    *,
    dry_run: bool,
) -> JSONObject:
    return _json_object(
        provider_adapter.packet_exchange_metadata(dry_run=dry_run),
        "provider packet exchange metadata",
    )


def _live_provider_endpoint_bootstrap_inputs(
    provider_adapter,
    *,
    dry_run: bool,
) -> tuple[JSONObject, JSONObject]:
    provider_capabilities = _json_object(
        provider_adapter.default_provider_capabilities(dry_run=dry_run),
        "provider capabilities",
    )
    topology_metadata = oracle_bootstrap.endpoint_bootstrap_topology(
        _live_provider_packet_exchange_metadata(provider_adapter, dry_run=dry_run),
        provider_capabilities,
    )
    return provider_capabilities, topology_metadata


def _live_provider_endpoint_bootstrap_plan(
    provider_adapter,
    *,
    dry_run: bool,
) -> list[object]:
    provider_capabilities, topology_metadata = _live_provider_endpoint_bootstrap_inputs(
        provider_adapter,
        dry_run=dry_run,
    )
    return oracle_bootstrap.endpoint_bootstrap_plan(
        provider_adapter.name,
        dry_run,
        provider_capabilities,
        topology_metadata,
    )


def _live_provider_validate_endpoint_bootstrap(
    provider_adapter,
    commands,
    *,
    dry_run: bool,
):
    _, topology_metadata = _live_provider_endpoint_bootstrap_inputs(
        provider_adapter,
        dry_run=dry_run,
    )
    return oracle_bootstrap.validate_endpoint_bootstrap(
        provider_adapter.name,
        commands,
        dry_run=dry_run,
        topology_metadata=topology_metadata,
    )


def _pcap(args: argparse.Namespace) -> int:
    if args.dry_plan:
        return _pcap_dry_plan(args)

    unsupported = _require_backend_capabilities(
        args,
        mode="pcap",
        required=_pcap_required_capabilities(args),
        operation=f"pcap {args.direction}",
        report_path=_pcap_output_dir(args.out) / "report.json",
        selected_specs=PCAP_SELECTED_SPECS,
    )
    if unsupported is not None:
        return unsupported
    if args.backend != "scapy" and args.direction != "libcrafter_to_reference":
        return _backend_not_implemented_report(
            args,
            mode="pcap",
            operation=f"pcap {args.direction}",
            report_path=_pcap_output_dir(args.out) / "report.json",
            selected_specs=PCAP_SELECTED_SPECS,
        )

    return _pcap_execute(args)


def _seed_live_private_group() -> None:
    """Give each `run live` invocation a unique provider private group.

    Concurrent live runs (e.g. an ICMP run and a DNS run, possibly in different
    worktrees) must not reuse the same Hetzner network and collide on private IP
    allocation. ``setdefault`` honours an operator-provided value (for
    coordination/reproduction) and otherwise mints a fresh per-process group.
    """

    os.environ.setdefault(
        "ORACLE_LIVE_PRIVATE_GROUP",
        f"oracle-live-{secrets.token_hex(4)}",
    )


def _live(args: argparse.Namespace) -> int:
    unsupported = _require_backend_capabilities(
        args,
        mode="live",
        required=("live_endpoint",),
        operation=f"live {args.provider}",
        report_path=_live_output_dir(args.out) / "report.json",
        selected_specs=("live",),
    )
    if unsupported is not None:
        return unsupported

    if args.provider == "local-dry-run":
        return _live_local_dry_run(args)

    from .providers.registry import resolve_live_provider

    try:
        provider_adapter = resolve_live_provider(args.provider)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    return _live_provider(args, provider_adapter)


def _live_provider(args: argparse.Namespace, provider_adapter) -> int:
    # Seed the per-run isolation group before any corpus, lab-request, or
    # provider-workflow construction so concurrent live runs (dry-run and real)
    # get isolated provider networks and IP allocations.
    _seed_live_private_group()

    from .backends.scapy.live import (
        backend_bootstrap_command_plan,
        dry_run_command_plan as scapy_dry_run_command_plan,
        validate_backend_bootstrap_command,
        validate_dry_run_command_plan as validate_scapy_dry_run_command_plan,
    )
    from .live import (
        LIVE_SELECTED_SPECS,
        LiveExchangePlan,
        LiveValidationCheck,
        build_live_endpoint_batch_request,
        dry_run_live_endpoint_batch_response,
        lab_session_oracle_report_metadata,
        libcrafter_dry_run_command_plan,
        live_endpoints_from_lab_session,
        live_endpoint_artifact_paths,
        live_execution_directions,
        validate_live_endpoint_batch_contract,
        validate_libcrafter_command_plan,
    )
    try:
        directions = live_execution_directions(args.direction)
        dry_run = bool(args.dry_run)
        provider_capabilities = provider_adapter.default_provider_capabilities(
            dry_run=dry_run,
        )
        plans, corpus_selected_specs, corpus_metadata = _live_corpus_plans(
            args,
            wire_provider=provider_adapter.name,
            direction=directions[0] if directions else "reference_to_libcrafter",
            provider_capabilities=provider_capabilities,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    output_dir = _live_output_dir(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"
    selected_specs = list(
        dict.fromkeys([*LIVE_SELECTED_SPECS, *corpus_selected_specs])
    )

    print(
        f"live {args.provider}: generated={corpus_metadata['generated_count']} "
        f"wire_eligible={corpus_metadata['wire_eligible_count']} "
        f"wire_skipped={corpus_metadata['wire_skipped_count']} "
        f"wire_skip_reasons={corpus_metadata['wire_skip_reasons']}"
    )

    token_configured = provider_adapter.token_configured()
    if not plans:
        return _live_provider_skip_no_wire_eligible(
            args=args,
            provider_adapter=provider_adapter,
            report_path=report_path,
            directions=directions,
            selected_specs=selected_specs,
            corpus_metadata=corpus_metadata,
            dry_run=dry_run,
            token_configured=token_configured,
        )
    if not dry_run and not bool(getattr(args, "confirm_live_run", False)):
        return _live_provider_requires_confirmation_report(
            args=args,
            provider_adapter=provider_adapter,
            report_path=report_path,
            directions=directions,
            selected_specs=selected_specs,
            corpus_metadata=corpus_metadata,
        )
    if not dry_run and not token_configured:
        return _live_provider_skip_no_token(
            args=args,
            provider_adapter=provider_adapter,
            report_path=report_path,
            directions=directions,
            selected_specs=selected_specs,
            corpus_metadata=corpus_metadata,
        )
    if not dry_run:
        return _live_provider_execute(
            args=args,
            provider_adapter=provider_adapter,
            report_path=report_path,
            directions=directions,
            plans=plans,
            selected_specs=selected_specs,
            corpus_metadata=corpus_metadata,
        )

    try:
        lab_session = _live_provider_dry_run_lab_session(args, provider_adapter)
        endpoints = live_endpoints_from_lab_session(lab_session)
        lab_report_metadata = lab_session_oracle_report_metadata(lab_session)
    except (PermissionError, ValueError, TypeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    missing_roles = [
        role
        for role in provider_adapter.endpoint_roles
        if role not in endpoints
    ]
    if missing_roles:
        print(
            "lab session did not include required endpoint roles: "
            f"{', '.join(missing_roles)}",
            file=sys.stderr,
        )
        return 2
    provider_workflow = provider_adapter.provider_workflow(dry_run=True)
    endpoint_bootstrap = _live_provider_endpoint_bootstrap_plan(
        provider_adapter,
        dry_run=True,
    )
    packet_exchange_metadata = _live_provider_packet_exchange_metadata(
        provider_adapter,
        dry_run=True,
    )
    bootstrap_command = backend_bootstrap_command_plan()
    corpus_batch_artifact = _write_live_corpus_batch_artifact(
        output_dir,
        corpus_metadata=corpus_metadata,
        plans=plans,
        directions=directions,
    )
    validations = [
        validate_backend_bootstrap_command(bootstrap_command),
        _live_provider_validate_endpoint_bootstrap(
            provider_adapter,
            endpoint_bootstrap,
            dry_run=True,
        ),
        provider_adapter.validate_provider_workflow(provider_workflow, dry_run=True),
        _live_corpus_accounting_validation(
            corpus_metadata,
            provider=provider_adapter.name,
        ),
        *[
            LiveValidationCheck(
                name=f"lab-{check.name}",
                passed=check.passed,
                subject=check.subject,
                errors=list(check.errors),
                metadata={
                    **dict(check.metadata),
                    "provider": lab_session.provider,
                    "lab_session_id": lab_session.session_id,
                    "source": "lab_session",
                },
            )
            for check in lab_session.validation_checks
        ],
    ]
    exchanges: list[LiveExchangePlan] = []
    endpoint_protocol_batches: list[JSONObject] = []
    endpoint_artifact_paths: list[str] = [str(corpus_batch_artifact)]

    for plan in plans:
        for direction in directions:
            if direction == "reference_to_libcrafter":
                sender = endpoints["reference_backend"]
                receiver = endpoints["libcrafter"]
                sender_command = scapy_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="sender",
                )
                receiver_command = libcrafter_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="receiver",
                )
                validations.append(validate_scapy_dry_run_command_plan(sender_command))
                validations.append(validate_libcrafter_command_plan(receiver_command))
            elif direction == "libcrafter_to_reference":
                sender = endpoints["libcrafter"]
                receiver = endpoints["reference_backend"]
                sender_command = libcrafter_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="sender",
                )
                receiver_command = scapy_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="receiver",
                )
                validations.append(validate_libcrafter_command_plan(sender_command))
                validations.append(validate_scapy_dry_run_command_plan(receiver_command))
            else:
                print(f"unsupported live direction: {direction}", file=sys.stderr)
                return 2

            exchange = LiveExchangePlan(
                provider=args.provider,
                backend=args.backend,
                direction=direction,
                index=plan.index,
                packet_plan=replace(plan, direction=direction),
                sender=sender,
                receiver=receiver,
                sender_command=sender_command,
                receiver_command=receiver_command,
                live_packet_exchange=False,
                metadata={
                    **packet_exchange_metadata,
                    "dry_run": True,
                    "creates_infrastructure": False,
                    "planned_live_packet_exchange": True,
                    "live_packet_exchange": False,
                    "no_live_packets_sent": True,
                },
            )
            exchanges.append(exchange)
            validations.append(provider_adapter.validate_dry_run_exchange(exchange))

    for direction in directions:
        direction_plans = [replace(plan, direction=direction) for plan in plans]
        if direction == "reference_to_libcrafter":
            sender = endpoints["reference_backend"]
            receiver = endpoints["libcrafter"]
        elif direction == "libcrafter_to_reference":
            sender = endpoints["libcrafter"]
            receiver = endpoints["reference_backend"]
        else:
            print(f"unsupported live direction: {direction}", file=sys.stderr)
            return 2

        sender_request = build_live_endpoint_batch_request(
            provider=args.provider,
            backend=args.backend,
            seed=args.seed,
            profile=args.profile,
            packet_plans=direction_plans,
            direction=direction,
            endpoint=sender,
            peer=receiver,
            artifact_paths=live_endpoint_artifact_paths(
                output_dir=str(output_dir),
                direction=direction,
                endpoint_role=sender.role,
            ),
            metadata={
                **packet_exchange_metadata,
                "phase_role": "sender",
                "dry_run": True,
                "planned_live_packet_exchange": True,
                "live_packet_exchange": False,
                "no_live_packets_sent": True,
                "batch_size": len(direction_plans),
            },
        )
        receiver_request = build_live_endpoint_batch_request(
            provider=args.provider,
            backend=args.backend,
            seed=args.seed,
            profile=args.profile,
            packet_plans=direction_plans,
            direction=direction,
            endpoint=receiver,
            peer=sender,
            artifact_paths=live_endpoint_artifact_paths(
                output_dir=str(output_dir),
                direction=direction,
                endpoint_role=receiver.role,
            ),
            metadata={
                **packet_exchange_metadata,
                "phase_role": "receiver",
                "dry_run": True,
                "planned_live_packet_exchange": True,
                "live_packet_exchange": False,
                "no_live_packets_sent": True,
                "batch_size": len(direction_plans),
            },
        )
        sender_response = dry_run_live_endpoint_batch_response(sender_request)
        receiver_response = dry_run_live_endpoint_batch_response(receiver_request)
        sender_validation = validate_live_endpoint_batch_contract(
            sender_request,
            sender_response,
            dry_run=True,
        )
        receiver_validation = validate_live_endpoint_batch_contract(
            receiver_request,
            receiver_response,
            dry_run=True,
        )
        pair_validation = _live_endpoint_pair_validation(
            direction=direction,
            sender_request=sender_request,
            receiver_request=receiver_request,
        )
        validations.extend([sender_validation, receiver_validation, pair_validation])
        endpoint_artifact_paths.extend(
            _write_live_endpoint_protocol_artifacts(sender_request, sender_response)
        )
        endpoint_artifact_paths.extend(
            _write_live_endpoint_protocol_artifacts(receiver_request, receiver_response)
        )
        endpoint_protocol_batches.extend(
            [
                {
                    "phase_role": "sender",
                    "request": sender_request.to_dict(),
                    "response": sender_response.to_dict(),
                    "validation": sender_validation.to_dict(),
                    "pair_validation": pair_validation.to_dict(),
                },
                {
                    "phase_role": "receiver",
                    "request": receiver_request.to_dict(),
                    "response": receiver_response.to_dict(),
                    "validation": receiver_validation.to_dict(),
                    "pair_validation": pair_validation.to_dict(),
                },
            ]
        )

    failed_validations = [validation for validation in validations if not validation.passed]
    status = "dry-run" if not failed_validations else "failed"
    live_count_metadata = _live_count_metadata(
        _live_empty_direction_counts(corpus_metadata, directions)
    )
    result = ComparisonResult(
        passed=not failed_validations,
        direction=args.direction,
        expected={
            **packet_exchange_metadata,
            "provider": args.provider,
            "dry_run": True,
            "creates_infrastructure": False,
            "endpoint_count": 2,
            "validations_pass": True,
            "generated_count": corpus_metadata["generated_count"],
            "wire_eligible_count": corpus_metadata["wire_eligible_count"],
            "wire_skipped_count": corpus_metadata["wire_skipped_count"],
        },
        actual={
            **packet_exchange_metadata,
            "provider": args.provider,
            "dry_run": True,
            "creates_infrastructure": False,
            "endpoint_count": len(endpoints),
            "validations_pass": not failed_validations,
            "failed_validations": [validation.to_dict() for validation in failed_validations],
            "generated_count": corpus_metadata["generated_count"],
            "wire_eligible_count": corpus_metadata["wire_eligible_count"],
            "wire_skipped_count": corpus_metadata["wire_skipped_count"],
        },
        strict_bytes=False,
        byte_equal=None,
        differences=[
            {
                "path": validation.name,
                "expected": "passed",
                "actual": validation.errors,
                "subject": validation.subject,
            }
            for validation in failed_validations
        ],
        reproduction_command=None
        if not failed_validations
        else _live_reproduction_command(args),
        metadata={
            **packet_exchange_metadata,
            "provider": args.provider,
            "dry_run": True,
            "creates_infrastructure": False,
            "planned_live_packet_exchange": True,
            "live_packet_exchange": False,
            "validation_count": len(validations),
        },
    )

    report = RunReport(
        mode="live",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(exchanges),
        status=status,
        selected_specs=selected_specs,
        artifacts=_dedupe_paths([str(report_path), *endpoint_artifact_paths]),
        artifact_paths=_dedupe_paths([str(report_path), *endpoint_artifact_paths]),
        results=[result],
        failures=[] if result.passed else [result],
        reproduction_commands=(
            [] if result.reproduction_command is None else [result.reproduction_command]
        ),
        backend_versions=_backend_versions(args.backend),
        libcrafter=_libcrafter_info(),
        metadata={
            "provider": args.provider,
            "dry_run": True,
            "creates_infrastructure": False,
            "would_create_infrastructure": True,
            "planned_live_packet_exchange": True,
            "live_packet_exchange": False,
            "no_live_packets_sent": True,
            "token_configured": token_configured,
            **corpus_metadata,
            **live_count_metadata,
            **packet_exchange_metadata,
            "live_corpus_artifact": str(corpus_batch_artifact),
            "execution_directions": directions,
            "planned_infrastructure": lab_report_metadata["planned_infrastructure"],
            "wire_endpoint_plan": lab_report_metadata["wire_endpoint_plan"],
            "wire_endpoint_lifecycle": lab_report_metadata["wire_endpoint_lifecycle"],
            "provider_workflow": [command.to_dict() for command in provider_workflow],
            "lab_provider_workflow": lab_report_metadata["provider_workflow"],
            "provider_commands": lab_report_metadata["provider_commands"],
            "command_records": lab_report_metadata["command_records"],
            "lab_session": lab_report_metadata["lab_session"],
            "endpoint_bootstrap": [command.to_dict() for command in endpoint_bootstrap],
            "artifact_collection": {
                "always_attempt": True,
                "command": _live_provider_workflow_command(
                    provider_workflow,
                    provider_adapter.artifact_collection_purpose,
                ).to_dict(),
            },
            "teardown": {
                "always_attempt": True,
                "command": _live_provider_workflow_command(
                    provider_workflow,
                    provider_adapter.teardown_purpose,
                ).to_dict(),
            },
            "backend_bootstrap": {
                "command": bootstrap_command.to_dict(),
                "validation": validations[0].to_dict(),
            },
            "endpoints": {
                name: endpoint.to_dict() for name, endpoint in endpoints.items()
            },
            "endpoint_protocol": {
                "version": 1,
                "batches": endpoint_protocol_batches,
                "artifact_paths": _dedupe_paths(endpoint_artifact_paths),
            },
            "exchanges": [exchange.to_dict() for exchange in exchanges],
            "validations": [validation.to_dict() for validation in validations],
        },
    )
    write_json(report_path, report)

    print(
        f"live {args.provider}: status={status} exchanges={len(exchanges)} "
        f"wire_eligible={corpus_metadata['wire_eligible_count']} "
        f"wire_skipped={corpus_metadata['wire_skipped_count']} "
        f"creates_infrastructure=false report={report_path}"
    )
    print(
        "endpoints=libcrafter:"
        f"{endpoints['libcrafter'].address},reference_backend:"
        f"{endpoints['reference_backend'].address} "
        f"packet_exchange_network={packet_exchange_metadata['packet_exchange_network']} "
        "bootstrap=planned"
    )
    if failed_validations:
        print(f"failed_validations={len(failed_validations)}", file=sys.stderr)
        print(f"reproduce: {_live_reproduction_command(args)}", file=sys.stderr)

    return 0 if status == "dry-run" else 1


def _live_provider_dry_run_lab_session(args: argparse.Namespace, provider_adapter):
    """Plan provider-backed oracle topology through the standalone lab adapter."""

    from tools.lab.engine.model import LabRequest, LabRole
    from tools.lab.engine.providers.registry import resolve_lab_provider

    lab_adapter = resolve_lab_provider(args.provider)
    planned_endpoints = provider_adapter.endpoints(dry_run=True)
    private_ips = {
        role: address
        for role, address in dict(provider_adapter.endpoint_private_ips).items()
        if isinstance(role, str) and isinstance(address, str) and address
    }
    roles: list[LabRole] = []
    for role in provider_adapter.endpoint_roles:
        peer_roles = [
            peer_role
            for peer_role in provider_adapter.endpoint_roles
            if peer_role != role
        ]
        private_ip = private_ips.get(role)
        planned_endpoint = planned_endpoints.get(role)
        planned_ipv4 = (
            None
            if private_ip is not None or planned_endpoint is None
            else planned_endpoint.address
        )
        roles.append(
            LabRole(
                name=role,
                requested_private_ipv4=private_ip,
                planned_ipv4=planned_ipv4,
                peer_roles=peer_roles,
                workload_metadata={
                    "workload": "oracle-live",
                    "backend": args.backend,
                },
            )
        )

    metadata: JSONObject = {
        "workload": "oracle-live",
        "backend": args.backend,
        "endpoint_roles": list(provider_adapter.endpoint_roles),
    }
    private_group = getattr(provider_adapter, "private_group", None)
    if isinstance(private_group, str) and private_group:
        metadata["private_group"] = os.environ.get(
            "ORACLE_LIVE_PRIVATE_GROUP",
            private_group,
        )
    if private_ips:
        metadata["role_private_ipv4s"] = dict(private_ips)
    planned_lan_ips = {
        role: endpoint.address
        for role, endpoint in planned_endpoints.items()
        if role not in private_ips
    }
    if planned_lan_ips:
        metadata["role_lan_ipv4s"] = planned_lan_ips

    request = LabRequest(
        provider=lab_adapter.name,
        profile=args.profile,
        seed=args.seed,
        roles=roles,
        dry_run=True,
        confirm_live_run=False,
        remote_dir=provider_adapter.remote_dir(),
        workload_label="oracle-live",
        metadata=metadata,
    )
    return lab_adapter.plan_session(request)


def _live_provider_resolve_lab_adapter(args: argparse.Namespace, provider_adapter):
    """Return the lab provider adapter backing an oracle live provider."""

    explicit = getattr(provider_adapter, "lab_provider_adapter", None)
    if explicit is not None:
        return explicit
    from tools.lab.engine.providers.registry import resolve_lab_provider

    return resolve_lab_provider(args.provider)


def _live_provider_lab_request(
    args: argparse.Namespace,
    provider_adapter,
    *,
    dry_run: bool,
    confirm_live_run: bool,
    remote_dir: str,
):
    """Build the provider-neutral lab request for oracle's endpoint roles."""

    from tools.lab.engine.model import LabRequest, LabRole

    endpoint_roles = [
        role
        for role in getattr(
            provider_adapter,
            "endpoint_roles",
            ("libcrafter", "reference_backend"),
        )
        if isinstance(role, str) and role
    ]
    planned_endpoints = provider_adapter.endpoints(dry_run=dry_run)
    private_ips = {
        role: address
        for role, address in dict(getattr(provider_adapter, "endpoint_private_ips", {})).items()
        if isinstance(role, str) and isinstance(address, str) and address
    }
    roles: list[LabRole] = []
    role_lan_ipv4s: dict[str, str] = {}
    for role in endpoint_roles:
        planned_endpoint = planned_endpoints.get(role)
        planned_ipv4 = (
            planned_endpoint.address
            if planned_endpoint is not None and isinstance(planned_endpoint.address, str)
            else None
        )
        requested_private_ipv4 = private_ips.get(role)
        if requested_private_ipv4 is None and planned_ipv4 is not None:
            role_lan_ipv4s[role] = planned_ipv4
        roles.append(
            LabRole(
                name=role,
                requested_private_ipv4=requested_private_ipv4,
                planned_ipv4=planned_ipv4,
                peer_roles=[peer for peer in endpoint_roles if peer != role],
                workload_metadata={
                    "workload": "oracle-live",
                    "backend": args.backend,
                },
            )
        )

    metadata: JSONObject = {
        "session_id": "oracle-live",
        "workload": "oracle-live",
        "oracle_live": True,
        "endpoint_roles": endpoint_roles,
    }
    private_group = getattr(provider_adapter, "private_group", None)
    if isinstance(private_group, str) and private_group:
        # Honour the per-run isolation group so concurrent live runs land on
        # distinct provider networks. ORACLE_LIVE_PRIVATE_GROUP is seeded once
        # per `run live` invocation by _live; when unset, fall back to the
        # adapter's static default so behaviour is unchanged.
        metadata["private_group"] = os.environ.get(
            "ORACLE_LIVE_PRIVATE_GROUP",
            private_group,
        )
    if private_ips:
        metadata["role_private_ipv4s"] = private_ips
    if role_lan_ipv4s:
        metadata["role_lan_ipv4s"] = role_lan_ipv4s

    return LabRequest(
        provider=args.provider,
        profile=args.profile,
        seed=args.seed,
        roles=roles,
        dry_run=dry_run,
        confirm_live_run=confirm_live_run,
        remote_dir=remote_dir,
        workload_label="oracle-live",
        metadata=metadata,
    )


def _cleanup_existing_live_lab_session(
    *,
    lab_session_state,
    lab_request,
    client,
) -> JSONObject:
    """Best-effort cleanup for an unfinished oracle live lab session."""

    metadata = getattr(lab_request, "metadata", {})
    session_id = (
        metadata.get("session_id")
        if isinstance(metadata, Mapping)
        else None
    )
    if not isinstance(session_id, str) or not session_id:
        return {"attempted": False, "reason": "no_session_id"}

    summary: JSONObject = {
        "attempted": False,
        "session_id": session_id,
    }
    try:
        existing = lab_session_state.read_session_manifest(session_id)
    except FileNotFoundError:
        summary["reason"] = "no_existing_session"
        return summary
    except Exception as exc:  # pragma: no cover - corrupt local state varies.
        summary["reason"] = "read_failed"
        summary["errors"] = [str(exc)]
        return summary

    if bool(getattr(existing, "dry_run", False)):
        summary["reason"] = "existing_session_is_dry_run"
        return summary
    if getattr(existing, "provider", None) != getattr(lab_request, "provider", None):
        summary["reason"] = "provider_mismatch"
        summary["existing_provider"] = getattr(existing, "provider", None)
        summary["requested_provider"] = getattr(lab_request, "provider", None)
        return summary

    cleanup_state = getattr(existing, "cleanup_state", {})
    cleanup_status = (
        cleanup_state.get("status")
        if isinstance(cleanup_state, Mapping)
        else None
    )
    if cleanup_status in {"completed", "no_endpoints"}:
        summary["reason"] = "existing_session_already_cleaned"
        summary["status"] = cleanup_status
        return summary

    endpoint_ids = list(getattr(existing, "created_endpoint_ids", []) or [])
    if not endpoint_ids:
        endpoint_ids = [
            endpoint.endpoint_id
            for endpoint in getattr(existing, "endpoints", [])
            if isinstance(getattr(endpoint, "endpoint_id", None), str)
        ]
    if not endpoint_ids:
        summary["reason"] = "existing_session_has_no_endpoints"
        return summary

    command_count = len(getattr(existing, "command_records", []) or [])
    cleaned = lab_session_state.cleanup_lab_session(existing, client=client)
    lab_session_state.write_session_manifest(cleaned)
    cleanup_commands = list(getattr(cleaned, "command_records", []) or [])[command_count:]
    cleaned_state = getattr(cleaned, "cleanup_state", {})
    errors = (
        _string_values(cleaned_state.get("errors", []))
        if isinstance(cleaned_state, Mapping)
        else []
    )
    return {
        "attempted": True,
        "session_id": session_id,
        "provider": getattr(existing, "provider", None),
        "endpoint_ids": endpoint_ids,
        "status": (
            cleaned_state.get("status")
            if isinstance(cleaned_state, Mapping)
            else None
        ),
        "errors": errors,
        "commands": _live_provider_lab_command_records(cleanup_commands),
    }


def _live_provider_bootstrap_commands(
    provider_adapter,
    *,
    endpoints: Mapping[str, object],
) -> dict[str, object]:
    """Return lab bootstrap hooks that delegate workload setup to oracle."""

    endpoint_roles = [
        role
        for role in getattr(
            provider_adapter,
            "endpoint_roles",
            ("libcrafter", "reference_backend"),
        )
        if isinstance(role, str) and role in endpoints
    ]
    _, topology_metadata = _live_provider_endpoint_bootstrap_inputs(
        provider_adapter,
        dry_run=False,
    )
    hook = oracle_bootstrap.endpoint_bootstrap_command_hook(
        provider_adapter.name,
        topology_metadata,
    )
    return {role: hook for role in endpoint_roles}


def _live_provider_lab_command_records(records: Sequence[object]) -> list[JSONObject]:
    """Convert lab command records into the oracle provider command report shape."""

    output: list[JSONObject] = []
    for index, record in enumerate(records):
        if hasattr(record, "to_dict") and callable(record.to_dict):
            raw = record.to_dict()
        elif isinstance(record, Mapping):
            raw = {
                key: value
                for key, value in record.items()
                if isinstance(key, str)
            }
        else:
            continue
        item = _json_object(raw, f"lab command record {index}")
        metadata = _json_object(item.get("metadata", {}), f"lab command record {index}.metadata")
        item.setdefault("label", _live_provider_lab_command_label(item, index))
        item.setdefault("wire_command", str(item.get("operation", "")).startswith("wire."))
        endpoint_id = _live_provider_lab_command_endpoint_id(item)
        if endpoint_id is not None:
            item.setdefault("endpoint_id", endpoint_id)
        for key in ("ok", "exit_code", "error", "stdout_path", "stderr_path"):
            if key not in item and key in metadata:
                item[key] = metadata[key]
        if "exit_code" not in item:
            ok = item.get("ok")
            if isinstance(ok, bool):
                item["exit_code"] = 0 if ok else 1
        output.append(item)
    return output


def _live_provider_lab_cleanup_attempt_records(
    cleanup_state: Mapping[str, object],
) -> list[JSONObject]:
    """Expose cleanup attempts that could not be represented as command records."""

    if not isinstance(cleanup_state, Mapping):
        return []
    output: list[JSONObject] = []
    for key, label_prefix in (
        ("artifact_collection", "98-artifact"),
        ("teardown", "99-destroy"),
    ):
        attempts = cleanup_state.get(key)
        if not isinstance(attempts, Sequence) or isinstance(
            attempts,
            (str, bytes, bytearray),
        ):
            continue
        for attempt in attempts:
            if not isinstance(attempt, Mapping):
                continue
            if bool(attempt.get("ok", False)):
                continue
            endpoint_id = attempt.get("endpoint_id")
            role = attempt.get("role")
            operation = attempt.get("operation")
            label_subject = role if isinstance(role, str) and role else endpoint_id
            output.append(
                _json_object(
                    {
                        "argv": [],
                        "operation": f"wire.{operation}" if isinstance(operation, str) else key,
                        "wire_command": True,
                        "endpoint_id": endpoint_id,
                        "endpoint_role": role,
                        "label": f"{label_prefix}-{label_subject or len(output)}",
                        "exit_code": attempt.get("exit_code", 1),
                        "ok": False,
                        "error": attempt.get("error"),
                    },
                    "lab cleanup attempt",
                )
            )
    return output


def _live_provider_lab_command_label(command: Mapping[str, object], index: int) -> str:
    operation = command.get("operation")
    role = command.get("role")
    endpoint_id = _live_provider_lab_command_endpoint_id(command)
    metadata = command.get("metadata")
    phase = metadata.get("phase") if isinstance(metadata, Mapping) else None
    if operation == "wire.create":
        return f"02-create-{role or index}"
    if operation == "lab.repo_archive":
        return "03-repo-archive"
    if operation in {"wire.upload", "wire.exec"} and isinstance(phase, str):
        return f"04-bootstrap-{role or endpoint_id or index}-{phase}"
    if operation == "wire.collect_artifacts":
        return f"98-artifact-{role or endpoint_id or index}"
    if operation == "wire.destroy":
        return f"99-destroy-{endpoint_id or role or index}"
    return f"lab-command-{index:02d}"


def _live_provider_lab_command_endpoint_id(
    command: Mapping[str, object],
) -> str | None:
    metadata = command.get("metadata")
    if isinstance(metadata, Mapping):
        endpoint_id = metadata.get("endpoint_id")
        if isinstance(endpoint_id, str) and endpoint_id:
            return endpoint_id
    endpoint_id = command.get("endpoint_id")
    if isinstance(endpoint_id, str) and endpoint_id:
        return endpoint_id
    argv = command.get("argv")
    if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes, bytearray)):
        return None
    parts = [part for part in argv if isinstance(part, str)]
    for wire_command in (
        "collect-artifacts",
        "destroy-endpoint",
        "exec",
        "upload",
        "download",
    ):
        try:
            command_index = parts.index(wire_command)
        except ValueError:
            continue
        if command_index + 1 < len(parts) and parts[command_index + 1]:
            return parts[command_index + 1]
    return None


def _live_provider_skip_no_token(
    *,
    args: argparse.Namespace,
    provider_adapter,
    report_path: Path,
    directions: list[str],
    selected_specs: list[str],
    corpus_metadata: JSONObject,
) -> int:
    endpoints = provider_adapter.endpoints(dry_run=False)
    provider_workflow = provider_adapter.provider_workflow(dry_run=False)
    endpoint_bootstrap = _live_provider_endpoint_bootstrap_plan(
        provider_adapter,
        dry_run=False,
    )
    credential_label = _live_provider_credential_label(provider_adapter)
    missing_credential_reason = _live_provider_missing_credential_reason(provider_adapter)
    print_reason = missing_credential_reason.replace(" ", "_")
    packet_exchange_metadata = _live_provider_packet_exchange_metadata(
        provider_adapter,
        dry_run=False,
    )
    live_count_metadata = _live_count_metadata(
        _live_empty_direction_counts(corpus_metadata, directions)
    )
    result = ComparisonResult(
        passed=True,
        direction=args.direction,
        expected={
            **packet_exchange_metadata,
            "provider": args.provider,
            "credential": credential_label,
            "token_configured": True,
        },
        actual={
            **packet_exchange_metadata,
            "provider": args.provider,
            "skipped": True,
            "reason": missing_credential_reason,
            "token_configured": False,
            "creates_infrastructure": False,
        },
        strict_bytes=False,
        byte_equal=None,
        metadata={
            **packet_exchange_metadata,
            "provider": args.provider,
            "skipped": True,
            "skip_reason": missing_credential_reason,
            "creates_infrastructure": False,
            "live_packet_exchange": False,
        },
    )
    report = RunReport(
        mode="live",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=0,
        status="skipped",
        selected_specs=selected_specs,
        artifacts=[str(report_path)],
        artifact_paths=[str(report_path)],
        results=[result],
        failures=[],
        backend_versions=_backend_versions(args.backend),
        libcrafter=_libcrafter_info(),
        metadata={
            "provider": args.provider,
            "dry_run": False,
            "skipped": True,
            "skip_reason": missing_credential_reason,
            "creates_infrastructure": False,
            "would_create_infrastructure_with_credentials": True,
            "live_packet_exchange": False,
            "no_live_packets_sent": True,
            "token_configured": False,
            **corpus_metadata,
            **live_count_metadata,
            **packet_exchange_metadata,
            "execution_directions": directions,
            "planned_infrastructure_if_credentials_available": provider_adapter.planned_infrastructure(
                dry_run=False
            ),
            "provider_workflow_if_credentials_available": [
                command.to_dict() for command in provider_workflow
            ],
            "endpoint_bootstrap_if_credentials_available": [
                command.to_dict() for command in endpoint_bootstrap
            ],
            "artifact_collection": {
                "always_attempt": True,
                "command": _live_provider_workflow_command(
                    provider_workflow,
                    provider_adapter.artifact_collection_purpose,
                ).to_dict(),
            },
            "teardown": {
                "always_attempt": True,
                "command": _live_provider_workflow_command(
                    provider_workflow,
                    provider_adapter.teardown_purpose,
                ).to_dict(),
            },
            "endpoints": {
                name: endpoint.to_dict() for name, endpoint in endpoints.items()
            },
        },
    )
    write_json(report_path, report)
    print(
        f"live {args.provider}: status=skipped reason={print_reason} "
        f"creates_infrastructure=false report={report_path}"
    )
    return 0


def _live_provider_requires_confirmation_report(
    *,
    args: argparse.Namespace,
    provider_adapter,
    report_path: Path,
    directions: list[str],
    selected_specs: list[str],
    corpus_metadata: JSONObject,
) -> int:
    endpoints = provider_adapter.endpoints(dry_run=False)
    provider_workflow = provider_adapter.provider_workflow(dry_run=False)
    endpoint_bootstrap = _live_provider_endpoint_bootstrap_plan(
        provider_adapter,
        dry_run=False,
    )
    packet_exchange_metadata = _live_provider_packet_exchange_metadata(
        provider_adapter,
        dry_run=False,
    )
    live_count_metadata = _live_count_metadata(
        _live_empty_direction_counts(corpus_metadata, directions)
    )
    result = ComparisonResult(
        passed=False,
        direction=args.direction,
        expected={
            **packet_exchange_metadata,
            "provider": args.provider,
            "dry_run": False,
            "live_packet_exchange": True,
        },
        actual={
            **packet_exchange_metadata,
            "provider": args.provider,
            "dry_run": False,
            "live_packet_exchange": False,
            "reason": "protected provider execution requires --confirm-live-run",
        },
        strict_bytes=False,
        byte_equal=None,
        differences=[
            {
                "path": "provider_execution",
                "expected": "protected confirmed two-endpoint live exchange",
                "actual": "missing --confirm-live-run",
            }
        ],
        reproduction_command=_live_reproduction_command(args),
        metadata={
            **packet_exchange_metadata,
            "provider": args.provider,
            "creates_infrastructure": False,
            "live_packet_exchange": False,
            "planned_infrastructure": True,
            "requires_confirmation": True,
        },
    )
    report = RunReport(
        mode="live",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=0,
        status="failed",
        selected_specs=selected_specs,
        artifacts=[str(report_path)],
        artifact_paths=[str(report_path)],
        results=[result],
        failures=[result],
        reproduction_commands=[result.reproduction_command]
        if result.reproduction_command is not None
        else [],
        backend_versions=_backend_versions(args.backend),
        libcrafter=_libcrafter_info(),
        metadata={
            "provider": args.provider,
            "dry_run": False,
            "creates_infrastructure": False,
            **packet_exchange_metadata,
            "planned_infrastructure": provider_adapter.planned_infrastructure(
                dry_run=False
            ),
            "provider_workflow": [command.to_dict() for command in provider_workflow],
            "endpoint_bootstrap": [command.to_dict() for command in endpoint_bootstrap],
            "artifact_collection": {
                "always_attempt": True,
                "command": _live_provider_workflow_command(
                    provider_workflow,
                    provider_adapter.artifact_collection_purpose,
                ).to_dict(),
            },
            "teardown": {
                "always_attempt": True,
                "command": _live_provider_workflow_command(
                    provider_workflow,
                    provider_adapter.teardown_purpose,
                ).to_dict(),
            },
            "endpoints": {
                name: endpoint.to_dict() for name, endpoint in endpoints.items()
            },
            "execution_directions": directions,
            **corpus_metadata,
            **live_count_metadata,
            **packet_exchange_metadata,
        },
    )
    write_json(report_path, report)
    print(
        f"live {args.provider}: status=failed reason=protected_wire_live_confirmation_required "
        f"confirm=missing creates_infrastructure=false report={report_path}",
        file=sys.stderr,
    )
    return 2


def _live_provider_skip_no_wire_eligible(
    *,
    args: argparse.Namespace,
    provider_adapter,
    report_path: Path,
    directions: list[str],
    selected_specs: list[str],
    corpus_metadata: JSONObject,
    dry_run: bool,
    token_configured: bool,
) -> int:
    endpoints = provider_adapter.endpoints(dry_run=dry_run)
    provider_workflow = provider_adapter.provider_workflow(dry_run=dry_run)
    endpoint_bootstrap = _live_provider_endpoint_bootstrap_plan(
        provider_adapter,
        dry_run=dry_run,
    )
    packet_exchange_metadata = _live_provider_packet_exchange_metadata(
        provider_adapter,
        dry_run=dry_run,
    )
    live_count_metadata = _live_count_metadata(
        _live_empty_direction_counts(corpus_metadata, directions)
    )
    result = ComparisonResult(
        passed=True,
        direction=args.direction,
        expected={
            **packet_exchange_metadata,
            "provider": args.provider,
            "wire_eligible_count": 0,
            "live_packet_exchange": False,
        },
        actual={
            **packet_exchange_metadata,
            "provider": args.provider,
            "skipped": True,
            "wire_eligible_count": 0,
            "wire_skipped_count": corpus_metadata["wire_skipped_count"],
            "wire_skip_reasons": corpus_metadata["wire_skip_reasons"],
            "live_packet_exchange": False,
        },
        strict_bytes=False,
        byte_equal=None,
        metadata={
            **packet_exchange_metadata,
            "provider": args.provider,
            "skipped": True,
            "skip_reason": "no_wire_eligible_packets",
            "creates_infrastructure": False,
            "live_packet_exchange": False,
        },
    )
    report = RunReport(
        mode="live",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=0,
        status="skipped",
        selected_specs=selected_specs,
        artifacts=[str(report_path)],
        artifact_paths=[str(report_path)],
        results=[result],
        failures=[],
        backend_versions=_backend_versions(args.backend),
        libcrafter=_libcrafter_info(),
        metadata={
            "provider": args.provider,
            "dry_run": dry_run,
            "skipped": True,
            "skip_reason": "no_wire_eligible_packets",
            "creates_infrastructure": False,
            "planned_live_packet_exchange": False,
            "live_packet_exchange": False,
            "no_live_packets_sent": True,
            "token_configured": token_configured,
            **corpus_metadata,
            **live_count_metadata,
            **packet_exchange_metadata,
            "execution_directions": directions,
            "planned_infrastructure_if_packets_eligible": provider_adapter.planned_infrastructure(
                dry_run=dry_run
            ),
            "provider_workflow_if_packets_eligible": [
                command.to_dict() for command in provider_workflow
            ],
            "endpoint_bootstrap_if_packets_eligible": [
                command.to_dict() for command in endpoint_bootstrap
            ],
            "endpoints": {
                name: endpoint.to_dict() for name, endpoint in endpoints.items()
            },
        },
    )
    write_json(report_path, report)
    print(
        f"live {args.provider}: status=skipped reason=no_wire_eligible_packets "
        f"creates_infrastructure=false report={report_path}"
    )
    return 0


def _live_provider_wire_environment(provider_adapter) -> dict[str, str]:
    """Return provider-specific environment for wire subprocesses."""

    environment = getattr(provider_adapter, "wire_environment", None)
    if not callable(environment):
        return {}
    value = environment()
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _live_provider_normalize_endpoints(provider_adapter, endpoints):
    """Apply provider-specific endpoint normalization after live lab creation."""

    normalizer = getattr(provider_adapter, "normalize_live_endpoints", None)
    if not callable(normalizer):
        return endpoints
    value = normalizer(endpoints)
    if not isinstance(value, Mapping):
        return endpoints
    return {
        role: endpoint
        for role, endpoint in value.items()
        if isinstance(role, str)
    }


def _live_provider_execute(
    *,
    args: argparse.Namespace,
    provider_adapter,
    report_path: Path,
    directions: list[str],
    plans: list[PacketPlan],
    selected_specs: list[str],
    corpus_metadata: JSONObject,
) -> int:
    from .backends.scapy.normalize import decode_vectors
    from .backends.scapy.packets import encode_packet_plans
    from tools.lab.engine import repo as lab_repo
    from tools.lab.engine import session as lab_session_state
    from tools.lab.engine import wire_client as lab_wire_client
    from .live import (
        LiveCommandPlan,
        LiveExchangePlan,
        build_live_endpoint_batch_request,
        lab_session_oracle_report_metadata,
        live_endpoint_artifact_paths,
        live_endpoints_from_lab_session,
        validate_live_endpoint_batch_contract,
    )

    output_dir = report_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    wire_environment = _live_provider_wire_environment(provider_adapter)
    if wire_environment:
        def run_wire_command(argv, **kwargs):
            return lab_wire_client.run_command(argv, env=wire_environment, **kwargs)

        wire = lab_wire_client.WireClient(runner=run_wire_command)
    else:
        wire = lab_wire_client.WireClient()
    endpoints = {}
    lab_session = None
    provider_workflow = provider_adapter.provider_workflow(dry_run=False)
    endpoint_bootstrap = _live_provider_endpoint_bootstrap_plan(
        provider_adapter,
        dry_run=False,
    )
    wire_endpoint_plan: JSONObject = {}
    provider_commands: list[JSONObject] = []
    endpoint_protocol_batches: list[JSONObject] = []
    exchanges: list[LiveExchangePlan] = []
    results: list[ComparisonResult] = []
    execution_errors: list[str] = []
    preflight_cleanup: JSONObject = {"attempted": False}
    keep_wire_endpoints = bool(getattr(args, "keep_wire_endpoints", False))
    created_endpoint_ids: list[str] = []
    live_packet_exchange = False
    live_direction_counts = _live_empty_direction_counts(corpus_metadata, directions)
    skipped_reason: str | None = None
    corpus_batch_artifact = _write_live_corpus_batch_artifact(
        output_dir,
        corpus_metadata=corpus_metadata,
        plans=plans,
        directions=directions,
    )
    endpoint_artifact_paths: list[str] = [str(corpus_batch_artifact)]
    remote_dir = provider_adapter.remote_dir()
    remote_artifact_root = posixpath.join(
        remote_dir,
        "live-artifacts",
        "oracle-live",
        "exchange",
    )
    packet_exchange_metadata = _live_provider_packet_exchange_metadata(
        provider_adapter,
        dry_run=False,
    )

    try:
        lab_adapter = _live_provider_resolve_lab_adapter(args, provider_adapter)
        lab_request = _live_provider_lab_request(
            args,
            provider_adapter,
            dry_run=False,
            confirm_live_run=True,
            remote_dir=remote_dir,
        )
        if not keep_wire_endpoints:
            preflight_cleanup = _cleanup_existing_live_lab_session(
                lab_session_state=lab_session_state,
                lab_request=lab_request,
                client=wire,
            )
        lab_session = lab_session_state.create_session(
            lab_adapter,
            lab_request,
            client=wire,
        )
        endpoints = live_endpoints_from_lab_session(lab_session)
        endpoints = _live_provider_normalize_endpoints(provider_adapter, endpoints)
        missing_roles = [
            role
            for role in provider_adapter.endpoint_roles
            if role not in endpoints
        ]
        if missing_roles:
            raise RuntimeError(
                "lab session did not include required endpoint roles: "
                + ", ".join(missing_roles)
            )
        created_endpoint_ids = list(lab_session.created_endpoint_ids)
        lab_report_metadata = lab_session_oracle_report_metadata(lab_session)
        wire_endpoint_plan = _json_object(
            lab_report_metadata["wire_endpoint_plan"],
            "lab_session.wire_endpoint_plan",
        )

        repo_archive = lab_repo.create_repository_archive(
            output_dir / "artifacts" / "lab" / "repo",
            source_root=REPO_ROOT,
        )
        lab_session = replace(
            lab_session,
            command_records=[
                *lab_session.command_records,
                repo_archive.command_record,
            ],
        )
        endpoint_artifact_paths.extend(
            [
                str(repo_archive.archive_path),
                str(repo_archive.stdout_path),
                str(repo_archive.stderr_path),
            ]
        )
        bootstrap_result = lab_repo.bootstrap_lab_session(
            lab_session,
            _live_provider_bootstrap_commands(
                provider_adapter,
                endpoints=endpoints,
            ),
            remote_dir=remote_dir,
            archive=repo_archive,
            output_dir=output_dir / "artifacts" / "lab" / "bootstrap",
            client=wire,
        )
        lab_session = lab_repo.session_with_bootstrap_records(
            lab_session,
            bootstrap_result,
        )
        lab_session_state.write_session_manifest(lab_session)
        endpoint_artifact_paths.extend(bootstrap_result.artifacts)
        if not bootstrap_result.ok:
            message = f"{provider_adapter.name} endpoint bootstrap failed"
            if bootstrap_result.errors:
                message = f"{message}: {'; '.join(bootstrap_result.errors)}"
            execution_errors.append(message)
            raise RuntimeError(message)

        discovered_capabilities = provider_adapter.default_provider_capabilities(
            dry_run=False,
            source="wire-endpoint-bootstrap",
        )
        capability_path = _write_wire_provider_capabilities(
            output_dir=output_dir,
            capabilities=discovered_capabilities,
            endpoints=endpoints,
        )
        endpoint_artifact_paths.append(str(capability_path))
        plans, updated_selected_specs, corpus_metadata = _live_corpus_plans(
            args,
            wire_provider=provider_adapter.name,
            direction=directions[0] if directions else "reference_to_libcrafter",
            provider_capabilities=discovered_capabilities,
        )
        selected_specs = list(dict.fromkeys([*selected_specs, *updated_selected_specs]))
        live_direction_counts = _live_empty_direction_counts(corpus_metadata, directions)
        corpus_batch_artifact = _write_live_corpus_batch_artifact(
            output_dir,
            corpus_metadata=corpus_metadata,
            plans=plans,
            directions=directions,
        )
        endpoint_artifact_paths.append(str(corpus_batch_artifact))
        if not plans:
            skipped_reason = "no_wire_eligible_packets"

        for direction in [] if skipped_reason is not None else directions:
            if direction == "reference_to_libcrafter":
                sender = endpoints["reference_backend"]
                receiver = endpoints["libcrafter"]
            elif direction == "libcrafter_to_reference":
                sender = endpoints["libcrafter"]
                receiver = endpoints["reference_backend"]
            else:
                print(f"unsupported live direction: {direction}", file=sys.stderr)
                return 2

            direction_plans = [
                provider_adapter.apply_transit_plan(
                    _live_plan_with_endpoint_addresses(
                        replace(plan, direction=direction),
                        sender=sender,
                        receiver=receiver,
                    )
                )
                for plan in plans
            ]
            expected_models = [
                decoded.to_dict()
                for decoded in decode_vectors(encode_packet_plans(direction_plans))
            ]

            sender_artifacts = live_endpoint_artifact_paths(
                output_dir=remote_artifact_root,
                direction=direction,
                endpoint_role=sender.role,
            )
            receiver_artifacts = live_endpoint_artifact_paths(
                output_dir=remote_artifact_root,
                direction=direction,
                endpoint_role=receiver.role,
            )
            sender_request = build_live_endpoint_batch_request(
                provider=args.provider,
                backend=args.backend,
                seed=args.seed,
                profile=args.profile,
                packet_plans=direction_plans,
                direction=direction,
                endpoint=sender,
                peer=receiver,
                artifact_paths=sender_artifacts,
                timeout_seconds=_live_endpoint_timeout_for_count(len(direction_plans)),
                metadata={
                    **packet_exchange_metadata,
                    "phase_role": "sender",
                    "dry_run": False,
                    "planned_live_packet_exchange": True,
                    "live_packet_exchange": False,
                    "batch_size": len(direction_plans),
                    "wire_endpoint_id": sender.endpoint_id,
                },
            )
            receiver_request = build_live_endpoint_batch_request(
                provider=args.provider,
                backend=args.backend,
                seed=args.seed,
                profile=args.profile,
                packet_plans=direction_plans,
                direction=direction,
                endpoint=receiver,
                peer=sender,
                artifact_paths=receiver_artifacts,
                timeout_seconds=_live_endpoint_timeout_for_count(len(direction_plans)),
                metadata={
                    **packet_exchange_metadata,
                    "phase_role": "receiver",
                    "dry_run": False,
                    "planned_live_packet_exchange": True,
                    "live_packet_exchange": False,
                    "batch_size": len(direction_plans),
                    "wire_endpoint_id": receiver.endpoint_id,
                },
            )

            sender_request_path = _remote_artifact_path(sender_request, "request")
            receiver_request_path = _remote_artifact_path(receiver_request, "request")
            local_direction_dir = (
                output_dir
                / "artifacts"
                / "provider-exchange"
                / provider_adapter.name
                / direction
            )
            local_direction_dir.mkdir(parents=True, exist_ok=True)
            sender_local_request_path = local_direction_dir / f"{sender.role}.request.json"
            receiver_local_request_path = (
                local_direction_dir / f"{receiver.role}.request.json"
            )
            write_json(sender_local_request_path, sender_request)
            write_json(receiver_local_request_path, receiver_request)
            endpoint_artifact_paths.extend(
                [str(sender_local_request_path), str(receiver_local_request_path)]
            )

            pair_validation = _live_endpoint_pair_validation(
                direction=direction,
                sender_request=sender_request,
                receiver_request=receiver_request,
            )
            endpoint_protocol_batches.append(
                {
                    "phase_role": "pair",
                    "direction": direction,
                    "validation": pair_validation.to_dict(),
                }
            )
            if not pair_validation.passed:
                execution_errors.append(f"{direction}: endpoint request pair validation failed")

            upload_receiver = _upload_wire_endpoint_request(
                wire=wire,
                endpoint_id=receiver.endpoint_id,
                role=receiver.role,
                remote_request_path=receiver_request_path,
                output_dir=local_direction_dir,
                label=f"upload-{receiver.role}",
                local_request_path=receiver_local_request_path,
            )
            upload_sender = _upload_wire_endpoint_request(
                wire=wire,
                endpoint_id=sender.endpoint_id,
                role=sender.role,
                remote_request_path=sender_request_path,
                output_dir=local_direction_dir,
                label=f"upload-{sender.role}",
                local_request_path=sender_local_request_path,
            )
            endpoint_protocol_batches.extend([upload_receiver, upload_sender])
            if upload_receiver["exit_code"] != 0 or upload_sender["exit_code"] != 0:
                execution_errors.append(f"{direction}: failed to upload endpoint requests")
                continue

            receiver_command = LiveCommandPlan(
                role=receiver.role,
                purpose="receive-live-packet-batch",
                argv=_wire_exec_argv(
                    wire,
                    receiver.endpoint_id,
                    provider_adapter.endpoint_remote_command(
                        endpoint_role=receiver.role,
                        remote_dir=remote_dir,
                        request_path=receiver_request_path,
                        out_dir=remote_artifact_root,
                    ),
                ),
                sends_live_packets=False,
                expects_live_packets=True,
                metadata={
                    **packet_exchange_metadata,
                    "provider": args.provider,
                    "direction": direction,
                    "phase_role": "receiver",
                    "batch_size": len(direction_plans),
                    "planned_live_packet_exchange": True,
                    "live_packet_exchange": False,
                    "wire_command": True,
                    "wire_endpoint_id": receiver.endpoint_id,
                },
            )
            sender_command = LiveCommandPlan(
                role=sender.role,
                purpose="send-live-packet-batch",
                argv=_wire_exec_argv(
                    wire,
                    sender.endpoint_id,
                    provider_adapter.endpoint_remote_command(
                        endpoint_role=sender.role,
                        remote_dir=remote_dir,
                        request_path=sender_request_path,
                        out_dir=remote_artifact_root,
                    ),
                ),
                sends_live_packets=True,
                expects_live_packets=False,
                metadata={
                    **packet_exchange_metadata,
                    "provider": args.provider,
                    "direction": direction,
                    "phase_role": "sender",
                    "batch_size": len(direction_plans),
                    "planned_live_packet_exchange": True,
                    "live_packet_exchange": False,
                    "wire_command": True,
                    "wire_endpoint_id": sender.endpoint_id,
                },
            )

            exchanges.append(
                LiveExchangePlan(
                    provider=args.provider,
                    backend=args.backend,
                    direction=direction,
                    index=direction_plans[0].index if direction_plans else 0,
                    packet_plan=direction_plans[0] if direction_plans else plans[0],
                    sender=sender,
                    receiver=receiver,
                    sender_command=sender_command,
                    receiver_command=receiver_command,
                    live_packet_exchange=False,
                    metadata={
                        **packet_exchange_metadata,
                        "dry_run": False,
                        "batch_size": len(direction_plans),
                    },
                )
            )

            receiver_process = _start_wire_endpoint_batch(
                wire=wire,
                endpoint_id=receiver.endpoint_id,
                command=provider_adapter.endpoint_remote_command(
                    endpoint_role=receiver.role,
                    remote_dir=remote_dir,
                    request_path=receiver_request_path,
                    out_dir=remote_artifact_root,
                ),
                output_dir=local_direction_dir,
                label=f"receiver-{receiver.role}",
            )
            time.sleep(_live_receiver_startup_grace_seconds(args.provider))
            sender_execution = _run_wire_endpoint_batch(
                wire=wire,
                endpoint_id=sender.endpoint_id,
                command=provider_adapter.endpoint_remote_command(
                    endpoint_role=sender.role,
                    remote_dir=remote_dir,
                    request_path=sender_request_path,
                    out_dir=remote_artifact_root,
                ),
                output_dir=local_direction_dir,
                label=f"sender-{sender.role}",
                timeout_seconds=_live_endpoint_process_timeout(sender_request.timeout_seconds),
            )
            receiver_execution = _wait_wire_endpoint_batch(
                receiver_process,
                timeout_seconds=_live_endpoint_process_timeout(
                    receiver_request.timeout_seconds
                ),
            )
            receiver_local_response_path = (
                local_direction_dir / f"{receiver.role}.response.json"
            )
            sender_local_response_path = local_direction_dir / f"{sender.role}.response.json"
            receiver_downloads = _download_wire_endpoint_artifacts(
                wire=wire,
                endpoint_id=receiver.endpoint_id,
                role=receiver.role,
                phase_role="receiver",
                artifact_paths=receiver_request.artifact_paths,
                output_dir=local_direction_dir,
                response_path=receiver_local_response_path,
                include_endpoint_artifacts=True,
            )
            sender_downloads = _download_wire_endpoint_artifacts(
                wire=wire,
                endpoint_id=sender.endpoint_id,
                role=sender.role,
                phase_role="sender",
                artifact_paths=sender_request.artifact_paths,
                output_dir=local_direction_dir,
                response_path=sender_local_response_path,
                include_endpoint_artifacts=False,
            )
            failed_downloads = [
                command
                for command in receiver_downloads + sender_downloads
                if command.get("exit_code") != 0 and command.get("required")
            ]
            if failed_downloads:
                execution_errors.append(f"{direction}: failed to download endpoint artifacts")
            endpoint_protocol_batches.extend(
                [
                    receiver_execution,
                    sender_execution,
                    {
                        "phase_role": "download",
                        "endpoint_role": receiver.role,
                        "commands": receiver_downloads,
                    },
                    {
                        "phase_role": "download",
                        "endpoint_role": sender.role,
                        "commands": sender_downloads,
                    },
                ]
            )
            endpoint_artifact_paths.extend(
                [
                    path
                    for command in receiver_downloads + sender_downloads
                    for path in _command_artifact_paths(command)
                ]
            )

            sender_response = _endpoint_response_from_execution(sender_execution)
            receiver_response = _endpoint_response_from_execution(receiver_execution)
            if sender_response is None:
                sender_response = _endpoint_response_from_path(sender_local_response_path)
            if receiver_response is None:
                receiver_response = _endpoint_response_from_path(receiver_local_response_path)
            if sender_response is None or receiver_response is None:
                execution_errors.append(f"{direction}: endpoint execution did not return JSON")
                continue
            if not sender_local_response_path.exists():
                write_json(sender_local_response_path, sender_response)
            if not receiver_local_response_path.exists():
                write_json(receiver_local_response_path, receiver_response)
            endpoint_artifact_paths.extend(
                [
                    str(sender_local_response_path),
                    str(receiver_local_response_path),
                    *_live_endpoint_response_artifact_paths(sender_response),
                    *_live_endpoint_response_artifact_paths(receiver_response),
                ]
            )

            sender_validation = validate_live_endpoint_batch_contract(
                sender_request,
                sender_response,
                dry_run=False,
            )
            receiver_validation = validate_live_endpoint_batch_contract(
                receiver_request,
                receiver_response,
                dry_run=False,
            )
            endpoint_protocol_batches.extend(
                [
                    {
                        "phase_role": "receiver",
                        "request": receiver_request.to_dict(),
                        "response": receiver_response.to_dict(),
                        "validation": receiver_validation.to_dict(),
                        "local_response_path": str(receiver_local_response_path),
                    },
                    {
                        "phase_role": "sender",
                        "request": sender_request.to_dict(),
                        "response": sender_response.to_dict(),
                        "validation": sender_validation.to_dict(),
                        "local_response_path": str(sender_local_response_path),
                    },
                ]
            )
            if not sender_validation.passed or not receiver_validation.passed:
                execution_errors.append(f"{direction}: endpoint protocol validation failed")

            direction_live_exchange = (
                sender_response.sent_count > 0
                and receiver_response.received_count > 0
                and sender_response.sent_count >= len(direction_plans)
                and receiver_response.received_count >= len(direction_plans)
            )
            live_packet_exchange = live_packet_exchange or direction_live_exchange
            exchanges[-1] = replace(
                exchanges[-1],
                live_packet_exchange=direction_live_exchange,
                metadata={
                    **exchanges[-1].metadata,
                    "live_packet_exchange": direction_live_exchange,
                    "sent_count": sender_response.sent_count,
                    "received_count": receiver_response.received_count,
                    "sender_errors": sender_response.errors,
                    "receiver_errors": receiver_response.errors,
                },
            )

            direction_results, direction_counts = _compare_live_direction_results(
                args=args,
                direction=direction,
                expected=expected_models,
                plans=direction_plans,
                corpus_metadata=corpus_metadata,
                provider_adapter=provider_adapter,
                sender_response=sender_response,
                receiver_response=receiver_response,
                sender_execution=sender_execution,
                receiver_execution=receiver_execution,
            )
            results.extend(direction_results)
            live_direction_counts[direction] = direction_counts
    except Exception as exc:  # pragma: no cover - exercised only by live providers.
        cleanup_commands = getattr(exc, "lab_cleanup_command_records", None)
        if isinstance(cleanup_commands, Sequence) and not isinstance(
            cleanup_commands,
            (str, bytes, bytearray),
        ):
            provider_commands.extend(
                _live_provider_lab_command_records(cleanup_commands)
            )
        if not execution_errors:
            execution_errors.append(str(exc))
    finally:
        if lab_session is not None:
            if not keep_wire_endpoints:
                try:
                    lab_session = lab_session_state.cleanup_lab_session(
                        lab_session,
                        client=wire,
                    )
                    lab_session_state.write_session_manifest(lab_session)
                except Exception as cleanup_exc:  # pragma: no cover - defensive fallback.
                    execution_errors.append(
                        f"{provider_adapter.name} lab cleanup failed: {cleanup_exc}"
                    )
            elif created_endpoint_ids:
                lab_session = replace(
                    lab_session,
                    cleanup_state={
                        "status": "skipped",
                        "endpoint_ids": list(created_endpoint_ids),
                        "keep_wire_endpoints": True,
                        "artifact_collection_attempted": False,
                        "teardown_attempted": False,
                    },
                )
                provider_commands.append(
                    {
                        "argv": [],
                        "exit_code": 0,
                        "label": "99-destroy-skipped",
                        "keep_wire_endpoints": True,
                        "endpoint_ids": list(created_endpoint_ids),
                    }
                )
            provider_commands = [
                *_live_provider_lab_command_records(lab_session.command_records),
                *_live_provider_lab_cleanup_attempt_records(lab_session.cleanup_state),
                *provider_commands,
            ]
            cleanup_errors = _string_values(lab_session.cleanup_state.get("errors", []))
            execution_errors.extend(
                f"{provider_adapter.name} cleanup failed: {error}"
                for error in cleanup_errors
            )

    provider_failures = [
        command
        for command in provider_commands
        if isinstance(command.get("exit_code"), int) and command["exit_code"] != 0
    ]
    if skipped_reason is not None and not execution_errors and not provider_failures:
        results.append(
            ComparisonResult(
                passed=True,
                direction=args.direction,
                expected={
                    **packet_exchange_metadata,
                    "provider": args.provider,
                    "wire_eligible_count": 0,
                    "live_packet_exchange": False,
                },
                actual={
                    **packet_exchange_metadata,
                    "provider": args.provider,
                    "skipped": True,
                    "wire_eligible_count": 0,
                    "wire_skipped_count": corpus_metadata["wire_skipped_count"],
                    "wire_skip_reasons": corpus_metadata["wire_skip_reasons"],
                    "live_packet_exchange": False,
                },
                strict_bytes=False,
                byte_equal=None,
                metadata={
                    **packet_exchange_metadata,
                    "provider": args.provider,
                    "skipped": True,
                    "skip_reason": skipped_reason,
                    "creates_infrastructure": bool(created_endpoint_ids),
                    "live_packet_exchange": False,
                },
            )
        )
    failures = [result for result in results if not result.passed]
    if skipped_reason is not None and not failures and not execution_errors and not provider_failures:
        status = "skipped"
    elif results and not failures and not execution_errors and not provider_failures:
        status = "passed"
    else:
        status = "failed"
    artifact_paths = _dedupe_paths(
        [str(report_path)]
        + endpoint_artifact_paths
        + [
            path
            for command in provider_commands + endpoint_protocol_batches
            for path in _command_artifact_paths(command)
        ]
        + _comparison_artifact_paths(failures)
    )
    lab_report_metadata = (
        lab_session_oracle_report_metadata(lab_session)
        if lab_session is not None
        else {}
    )
    lab_wire_endpoint_lifecycle = (
        _json_object(
            lab_report_metadata.get("wire_endpoint_lifecycle", {}),
            "lab_session.wire_endpoint_lifecycle",
        )
        if lab_report_metadata
        else {}
    )
    wire_endpoint_lifecycle = {
        **lab_wire_endpoint_lifecycle,
        "remote_dir": remote_dir,
        "remote_artifact_root": remote_artifact_root,
        "created_endpoint_ids": list(created_endpoint_ids),
        "keep_wire_endpoints": keep_wire_endpoints,
    }
    if lab_wire_endpoint_lifecycle.get("remote_artifact_root") != remote_artifact_root:
        wire_endpoint_lifecycle["lab_remote_artifact_root"] = (
            lab_wire_endpoint_lifecycle.get("remote_artifact_root")
        )
    report = RunReport(
        mode="live",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(results),
        status=status,
        selected_specs=selected_specs,
        artifacts=artifact_paths,
        artifact_paths=artifact_paths,
        results=results,
        failures=failures,
        reproduction_commands=_dedupe_paths(
            [
                command
                for result in failures
                if result.reproduction_command is not None
                for command in [result.reproduction_command]
            ]
        ),
        backend_versions=_backend_versions(args.backend),
        libcrafter=_libcrafter_info(),
        metadata={
            "provider": args.provider,
            "dry_run": False,
            "skipped": status == "skipped",
            "skip_reason": skipped_reason,
            "creates_infrastructure": bool(created_endpoint_ids),
            "reused_existing_lab": False,
            "planned_live_packet_exchange": True,
            "live_packet_exchange": bool(live_packet_exchange and status == "passed"),
            "token_configured": True,
            **corpus_metadata,
            **_live_count_metadata(live_direction_counts),
            **packet_exchange_metadata,
            "live_corpus_artifact": str(corpus_batch_artifact),
            "execution_directions": directions,
            "planned_infrastructure": lab_report_metadata.get(
                "planned_infrastructure",
                provider_adapter.planned_infrastructure(dry_run=False),
            ),
            "wire_endpoint_plan": lab_report_metadata.get(
                "wire_endpoint_plan",
                wire_endpoint_plan,
            ),
            "wire_endpoint_lifecycle": wire_endpoint_lifecycle,
            "provider_workflow": [command.to_dict() for command in provider_workflow],
            "lab_provider_workflow": lab_report_metadata.get("provider_workflow", []),
            "provider_commands": provider_commands,
            "command_records": lab_report_metadata.get("command_records", provider_commands),
            "lab_session": lab_report_metadata.get("lab_session"),
            "preflight_cleanup": preflight_cleanup,
            "endpoint_bootstrap": [command.to_dict() for command in endpoint_bootstrap],
            "artifact_collection": {
                "always_attempt": True,
                "command": _live_provider_workflow_command(
                    provider_workflow,
                    provider_adapter.artifact_collection_purpose,
                ).to_dict(),
            },
            "teardown": {
                "always_attempt": not keep_wire_endpoints,
                "keep_wire_endpoints": keep_wire_endpoints,
                "command": _live_provider_workflow_command(
                    provider_workflow,
                    provider_adapter.teardown_purpose,
                ).to_dict(),
            },
            "endpoints": {
                name: endpoint.to_dict() for name, endpoint in endpoints.items()
            },
            "endpoint_protocol": {
                "version": 1,
                "batches": endpoint_protocol_batches,
                "artifact_paths": _dedupe_paths(endpoint_artifact_paths),
            },
            "exchanges": [exchange.to_dict() for exchange in exchanges],
            "execution_errors": execution_errors,
        },
    )
    write_json(report_path, report)

    print(
        f"live {args.provider}: status={status} exchanges={len(exchanges)} "
        f"live_packet_exchange={str(report.metadata['live_packet_exchange']).lower()} "
        f"report={report_path}"
    )
    if status != "passed":
        for error in execution_errors:
            print(f"error: {error}", file=sys.stderr)
        print(f"reproduce: {_live_reproduction_command(args)}", file=sys.stderr)
    return 0 if status == "passed" else 1


def _run_wire_command(response, *, output_dir: Path, label: str) -> JSONObject:
    command_dir = output_dir / "provider"
    command_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = command_dir / f"{label}.stdout.txt"
    stderr_path = command_dir / f"{label}.stderr.txt"
    stdout_path.write_text(response.result.stdout, encoding="utf-8")
    stderr_path.write_text(response.result.stderr, encoding="utf-8")
    metadata = response.metadata()
    metadata.update(
        {
            "label": label,
            "wire_command": True,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }
    )
    if response.result.error:
        metadata["error"] = response.result.error
    collected_artifacts = _existing_paths_from_stdout(response.result.stdout)
    if collected_artifacts:
        metadata["collected_artifacts"] = collected_artifacts
    return metadata


def _run_wire_command_safely(command, *, output_dir: Path, label: str) -> JSONObject:
    try:
        return _run_wire_command(command(), output_dir=output_dir, label=label)
    except Exception as exc:  # pragma: no cover - depends on wire process failures.
        command_dir = output_dir / "provider"
        command_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = command_dir / f"{label}.stdout.txt"
        stderr_path = command_dir / f"{label}.stderr.txt"
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text(str(exc), encoding="utf-8")
        return {
            "argv": [],
            "exit_code": 1,
            "ok": False,
            "label": label,
            "wire_command": True,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "error": str(exc),
        }


def _existing_paths_from_stdout(stdout: str) -> list[str]:
    paths: list[str] = []
    for line in stdout.splitlines():
        value = line.strip()
        if not value or "=" in value:
            continue
        path = Path(value)
        if path.exists():
            paths.append(str(path))
    return _dedupe_paths(paths)


def _wire_create_labels(provider_adapter) -> tuple[str, ...]:
    roles = getattr(provider_adapter, "endpoint_roles", ("libcrafter", "reference_backend"))
    if (
        isinstance(roles, Sequence)
        and not isinstance(roles, (str, bytes, bytearray))
        and all(isinstance(role, str) and role for role in roles)
    ):
        return tuple(f"02-create-{role}" for role in roles)
    return ("02-create-libcrafter", "02-create-reference-backend")


def _wire_create_command_records(
    command_records: object,
    *,
    labels: Sequence[str],
) -> list[JSONObject]:
    if not isinstance(command_records, list):
        return []
    output: list[JSONObject] = []
    for index, record in enumerate(command_records):
        if not isinstance(record, dict):
            continue
        item = _json_object(record, f"wire_endpoint_plan.command_metadata[{index}]")
        item["label"] = labels[index] if index < len(labels) else f"02-create-{index}"
        item["wire_command"] = True
        output.append(item)
    return output


def _create_wire_repo_archive(output_dir: Path) -> Path:
    artifact_dir = output_dir / "artifacts" / "wire"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    archive_path = artifact_dir / "libcrafter-repo.tar.gz"
    argv = [
        "tar",
        "-C",
        str(REPO_ROOT),
        "--exclude=.git",
        "--exclude=target",
        "--exclude=tools/wire/.state",
        "--exclude=tools/wire/artifacts",
        "-czf",
        str(archive_path),
        ".",
    ]
    process = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    (artifact_dir / "repo-archive.stdout.txt").write_text(
        process.stdout,
        encoding="utf-8",
    )
    (artifact_dir / "repo-archive.stderr.txt").write_text(
        process.stderr,
        encoding="utf-8",
    )
    if process.returncode != 0:
        raise RuntimeError(f"failed to create wire repo archive: {process.stderr.strip()}")
    return archive_path


def _bootstrap_wire_endpoint(
    *,
    wire,
    endpoint,
    peer,
    repo_archive: Path,
    remote_dir: str,
    output_dir: Path,
    label: str,
    provider_adapter,
) -> list[JSONObject]:
    remote_parent = posixpath.dirname(remote_dir.rstrip("/")) or "/"
    remote_archive = posixpath.join(remote_parent, "libcrafter-repo.tar.gz")
    upload = _run_wire_command(
        wire.upload(endpoint.endpoint_id, repo_archive, remote_archive),
        output_dir=output_dir,
        label=f"{label}-upload-repo",
    )
    if upload["exit_code"] != 0:
        return [upload]

    _, topology_metadata = _live_provider_endpoint_bootstrap_inputs(
        provider_adapter,
        dry_run=False,
    )
    bootstrap = _run_wire_command(
        wire.exec(
            endpoint.endpoint_id,
            oracle_bootstrap.endpoint_bootstrap_command(
                provider=provider_adapter.name,
                endpoint=endpoint,
                peer=peer,
                remote_archive=remote_archive,
                remote_dir=remote_dir,
                topology_metadata=topology_metadata,
            ),
            timeout=1800,
        ),
        output_dir=output_dir,
        label=f"{label}-exec",
    )
    return [upload, bootstrap]


def _write_wire_provider_capabilities(
    *,
    output_dir: Path,
    capabilities: JSONObject,
    endpoints: Mapping[str, object],
) -> Path:
    capability_path = output_dir / "artifacts" / "wire" / "capabilities.json"
    capabilities["capability_report_path"] = str(capability_path)
    report = {
        "source": capabilities.get("source", "wire-endpoint-bootstrap"),
        "provider_capabilities": capabilities,
        "endpoints": {
            role: endpoint.to_dict()
            for role, endpoint in endpoints.items()
            if hasattr(endpoint, "to_dict")
        },
    }
    write_json(capability_path, report)
    return capability_path


def _live_plan_with_endpoint_addresses(
    plan: PacketPlan,
    *,
    sender,
    receiver,
) -> PacketPlan:
    fields = {
        layer: dict(layer_fields)
        for layer, layer_fields in plan.fields.items()
    }
    if "ipv4" in fields:
        fields["ipv4"]["src"] = sender.address
        fields["ipv4"]["dst"] = receiver.address
    if "ip" in fields:
        fields["ip"]["src"] = sender.address
        fields["ip"]["dst"] = receiver.address
    if (
        "ipv6" in fields
        and sender.ipv6_address is not None
        and receiver.ipv6_address is not None
    ):
        fields["ipv6"]["src"] = sender.ipv6_address
        fields["ipv6"]["dst"] = receiver.ipv6_address
    metadata = {
        **plan.metadata,
        "live_address_rewrite": {
            "sender_role": sender.role,
            "receiver_role": receiver.role,
            "sender_ipv4": sender.address,
            "receiver_ipv4": receiver.address,
            "sender_ipv6": sender.ipv6_address,
            "receiver_ipv6": receiver.ipv6_address,
        },
    }
    return replace(plan, fields=fields, metadata=metadata)


def _live_wire_policy(
    plan: PacketPlan,
    *,
    provider: str | None = None,
    provider_adapter=None,
) -> JSONObject:
    provider_name = (
        provider_adapter.name
        if provider_adapter is not None
        else provider
    )
    raw_policy = plan.metadata.get("wire")
    if isinstance(raw_policy, Mapping):
        policy = {
            key: value
            for key, value in raw_policy.items()
            if isinstance(key, str)
        }
    elif provider_adapter is not None:
        policy = provider_adapter.wire_comparison_policy(plan)
    else:
        if provider_name is None:
            raise RuntimeError("live wire policy requires a provider adapter or name")
        from .corpus import wire_comparison_policy

        policy = wire_comparison_policy(plan, provider=provider_name)

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

    strict_bytes = policy.get("strict_bytes")
    if not isinstance(strict_bytes, bool):
        byte_mutable_fields = policy.get("byte_mutable_fields", policy["mutable_fields"])
        strict_bytes = bool(plan.strict_bytes and not byte_mutable_fields)
    policy["strict_bytes"] = strict_bytes

    compare_root = policy.get("compare_root")
    if compare_root is not None and not isinstance(compare_root, str):
        compare_root = None
    policy["compare_root"] = compare_root
    policy.setdefault("provider", provider_name)
    return policy


def _remote_artifact_path(request, key: str) -> str:
    value = request.artifact_paths.get(key)
    if not isinstance(value, str) or not value.startswith("/"):
        raise RuntimeError(f"live endpoint request artifact {key!r} must be absolute")
    return value


def _upload_wire_endpoint_request(
    *,
    wire,
    endpoint_id: str,
    role: str,
    remote_request_path: str,
    output_dir: Path,
    label: str,
    local_request_path: Path,
) -> JSONObject:
    remote_parent = posixpath.dirname(remote_request_path)
    mkdir = _run_wire_command(
        wire.exec(
            endpoint_id,
            ["bash", "-lc", f"mkdir -p {shlex.quote(remote_parent)}"],
            timeout=60,
        ),
        output_dir=output_dir,
        label=f"{label}-mkdir",
    )
    upload = (
        _run_wire_command(
            wire.upload(endpoint_id, local_request_path, remote_request_path),
            output_dir=output_dir,
            label=f"{label}-upload",
        )
        if mkdir["exit_code"] == 0
        else None
    )
    commands = [mkdir] + ([] if upload is None else [upload])
    exit_code = 0
    for command in commands:
        if command.get("exit_code") != 0:
            exit_code = int(command.get("exit_code", 1))
            break
    return {
        "phase_role": "upload",
        "endpoint_role": role,
        "endpoint_id": endpoint_id,
        "wire_command": True,
        "exit_code": exit_code,
        "label": label,
        "request_path": str(local_request_path),
        "remote_request_path": remote_request_path,
        "commands": commands,
    }


def _wire_exec_argv(wire, endpoint_id: str, command: Sequence[str]) -> list[str]:
    return [wire.wire_path, "exec", endpoint_id, "--", *command]


def _start_wire_endpoint_batch(
    *,
    wire,
    endpoint_id: str,
    command: Sequence[str],
    output_dir: Path,
    label: str,
) -> JSONObject:
    stdout_path = output_dir / f"{label}.stdout.json"
    stderr_path = output_dir / f"{label}.stderr.txt"
    argv = _wire_exec_argv(wire, endpoint_id, command)
    process = subprocess.Popen(
        argv,
        cwd=wire.cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {
        "argv": argv,
        "operation": "exec",
        "wire_command": True,
        "endpoint_id": endpoint_id,
        "label": label,
        "process": process,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _run_wire_endpoint_batch(
    *,
    wire,
    endpoint_id: str,
    command: Sequence[str],
    output_dir: Path,
    label: str,
    timeout_seconds: int,
) -> JSONObject:
    stdout_path = output_dir / f"{label}.stdout.json"
    stderr_path = output_dir / f"{label}.stderr.txt"
    result = wire.exec(endpoint_id, command, timeout=timeout_seconds)
    stdout_path.write_text(result.result.stdout, encoding="utf-8")
    stderr_path.write_text(result.result.stderr, encoding="utf-8")
    response, parse_errors = _parse_endpoint_stdout(result.result.stdout, label)
    return {
        **result.record.to_dict(),
        "endpoint_id": endpoint_id,
        "wire_command": True,
        "label": label,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "response": response,
        "errors": ([result.result.error] if result.result.error else []) + parse_errors,
    }


def _wait_wire_endpoint_batch(
    execution: JSONObject,
    *,
    timeout_seconds: int,
) -> JSONObject:
    process = execution.get("process")
    if not isinstance(process, subprocess.Popen):
        return {
            **{key: value for key, value in execution.items() if key != "process"},
            "exit_code": 1,
            "response": None,
            "errors": ["receiver process handle is invalid"],
        }

    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        exit_code = process.returncode
        errors: list[str] = []
    except subprocess.TimeoutExpired:
        process.kill()
        # Drain the killed process's pipes with a hard bound so a wedged ssh
        # child (or a remote that never closes the channel) can never block the
        # orchestrator indefinitely the way an unbounded communicate() can.
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", ""
        exit_code = 124
        errors = [f"endpoint command timed out after {timeout_seconds}s"]

    stdout_path = Path(str(execution["stdout_path"]))
    stderr_path = Path(str(execution["stderr_path"]))
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    response, parse_errors = _parse_endpoint_stdout(stdout, str(execution["label"]))
    return {
        **{key: value for key, value in execution.items() if key != "process"},
        "exit_code": exit_code,
        "response": response,
        "errors": errors + parse_errors,
    }


def _download_wire_endpoint_artifacts(
    *,
    wire,
    endpoint_id: str,
    role: str,
    phase_role: str,
    artifact_paths: Mapping[str, object],
    output_dir: Path,
    response_path: Path,
    include_endpoint_artifacts: bool = True,
) -> list[JSONObject]:
    local_root = output_dir / "downloads" / role
    downloads: list[JSONObject] = []
    local_by_key = {
        "response": response_path,
    }
    if include_endpoint_artifacts and phase_role == "receiver":
        local_by_key.update(
            {
                "decoded_models": local_root / "decoded-models.json",
                "captures": local_root / "captures",
            }
        )
    for key, local_path in local_by_key.items():
        remote_path = artifact_paths.get(key)
        if not isinstance(remote_path, str) or not remote_path.startswith("/"):
            continue
        record = _run_wire_command(
            wire.download(endpoint_id, remote_path, local_path),
            output_dir=output_dir,
            label=f"download-{role}-{key}",
        )
        record.update(
            {
                "endpoint_id": endpoint_id,
                "endpoint_role": role,
                "artifact_key": key,
                "remote_path": remote_path,
                "local_path": str(local_path),
                # Only the response is a required transfer. decoded_models and
                # captures are supplementary: a sender legitimately produces
                # neither (it only transmits), and the receiver's decoded data
                # is also carried in its JSON response, so a missing/failed
                # decode/capture download must not fail an otherwise-valid run.
                "required": key == "response",
            }
        )
        downloads.append(record)
    return downloads


def _live_receiver_startup_grace_seconds(provider: str) -> float:
    if provider in {"qemu", "virtualbox"}:
        return LIVE_VM_RECEIVER_STARTUP_GRACE_SECONDS
    return LIVE_RECEIVER_STARTUP_GRACE_SECONDS


def _parse_endpoint_stdout(stdout: str, label: str) -> tuple[JSONObject | None, list[str]]:
    if not stdout.strip():
        return None, [f"{label}: endpoint produced no JSON response"]
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        start = stdout.find("{")
        end = stdout.rfind("}")
        if start < 0 or end <= start:
            return None, [f"{label}: endpoint stdout was not JSON"]
        try:
            value = json.loads(stdout[start : end + 1])
        except json.JSONDecodeError as exc:
            return None, [f"{label}: endpoint stdout JSON parse failed: {exc}"]
    if not isinstance(value, dict):
        return None, [f"{label}: endpoint response must be a JSON object"]
    return _json_object(value, f"{label}.response"), []


def _endpoint_response_from_execution(execution: JSONObject):
    from .live import (
        LiveCaptureArtifact,
        LiveEndpointBatchResponse,
        LiveEndpointIndexStatus,
    )

    response = execution.get("response")
    if not isinstance(response, dict):
        return None
    response_object = _json_object(response, "endpoint response")
    decoded_values = response_object.get("decoded_models")
    capture_values = response_object.get("captures")
    status_values = response_object.get("per_index_status")
    if not isinstance(decoded_values, list):
        return None
    if not isinstance(capture_values, list):
        return None
    if not isinstance(status_values, list):
        return None

    decoded_models = [
        _decoded_model_from_object(model, f"decoded_models[{index}]")
        for index, model in enumerate(decoded_values)
    ]
    captures = [
        _live_capture_from_object(capture, f"captures[{index}]")
        for index, capture in enumerate(capture_values)
    ]
    statuses = [
        _live_status_from_object(status, f"per_index_status[{index}]")
        for index, status in enumerate(status_values)
    ]
    return LiveEndpointBatchResponse(
        provider=_required_response_string(response_object, "provider"),
        backend=_required_response_string(response_object, "backend"),
        direction=_required_response_string(response_object, "direction"),
        endpoint_id=_required_response_string(response_object, "endpoint_id"),
        endpoint_role=_required_response_string(response_object, "endpoint_role"),
        sent_count=_object_int(response_object.get("sent_count"), 0),
        received_count=_object_int(response_object.get("received_count"), 0),
        decoded_models=decoded_models,
        captures=captures,
        per_index_status=statuses,
        errors=_string_values(response_object.get("errors", [])),
        artifact_paths=_json_object(
            response_object.get("artifact_paths", {}),
            "endpoint response artifact_paths",
        ),
        metadata=_json_object(response_object.get("metadata", {}), "endpoint metadata"),
    )


def _endpoint_response_from_path(path: Path):
    try:
        value = read_json(path)
    except Exception:
        return None
    if not isinstance(value, dict):
        return None
    return _endpoint_response_from_execution({"response": value})


def _decoded_model_from_object(value: object, name: str) -> DecodedModel:
    model = _json_object(value, name)
    fields = _json_object(model.get("fields", {}), f"{name}.fields")
    return DecodedModel(
        backend=_optional_string(model.get("backend")) or "unknown",
        layers=_string_values(model.get("layers", [])),
        fields={
            layer: _json_object(layer_fields, f"{name}.fields.{layer}")
            for layer, layer_fields in fields.items()
        },
        root=_optional_string(model.get("root")),
        source_hex=_optional_string(model.get("source_hex")),
        feature_tags=_string_values(model.get("feature_tags", [])),
        metadata=_json_object(model.get("metadata", {}), f"{name}.metadata"),
    )


def _live_capture_from_object(value: object, name: str):
    from .live import LiveCaptureArtifact

    capture = _json_object(value, name)
    return LiveCaptureArtifact(
        endpoint_role=_required_response_string(capture, "endpoint_role"),
        path=_required_response_string(capture, "path"),
        link_type=_optional_string(capture.get("link_type")),
        packet_count=_object_int(capture.get("packet_count"), 0),
        metadata=_json_object(capture.get("metadata", {}), f"{name}.metadata"),
    )


def _live_status_from_object(value: object, name: str):
    from .live import LiveEndpointIndexStatus

    status = _json_object(value, name)
    return LiveEndpointIndexStatus(
        index=_object_int(status.get("index"), 0),
        direction=_required_response_string(status, "direction"),
        status=_required_response_string(status, "status"),
        sent=bool(status.get("sent")),
        received=bool(status.get("received")),
        decoded_count=_object_int(status.get("decoded_count"), 0),
        sent_raw_hex=_optional_string(status.get("sent_raw_hex")),
        send_root=_optional_string(status.get("send_root")),
        send_mode=_optional_string(status.get("send_mode")),
        observed_raw_hex=_optional_string(status.get("observed_raw_hex")),
        capture_root=_optional_string(status.get("capture_root")),
        capture_link_type=_optional_string(status.get("capture_link_type")),
        capture_path=_optional_string(status.get("capture_path")),
        byte_length=_optional_response_int(status.get("byte_length")),
        capture_paths=_string_values(status.get("capture_paths", [])),
        errors=_string_values(status.get("errors", [])),
        metadata=_json_object(status.get("metadata", {}), f"{name}.metadata"),
    )


def _optional_response_int(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return None


def _required_response_string(value: JSONObject, key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise RuntimeError(f"endpoint response requires string field {key}")
    return item


def _live_endpoint_process_timeout(endpoint_timeout: int) -> int:
    return max(120, int(endpoint_timeout) + 90)


def _live_endpoint_timeout_for_count(packet_count: int) -> int:
    # The receiver's capture must stay open until well after the sender
    # transmits. The sender only starts after the settle window, then needs its
    # own process startup (uv + scapy import, or cargo) before it sends, so the
    # capture deadline must exceed settle + sender startup + send, or the
    # receiver times out observing zero packets even though the exchange is fine.
    return max(
        60,
        min(300, int(LIVE_CAPTURE_SETTLE_SECONDS) + 30 + int(packet_count)),
    )


def _compare_live_direction_results(
    *,
    args: argparse.Namespace,
    direction: str,
    expected: list[JSONObject],
    plans: list[PacketPlan],
    corpus_metadata: Mapping[str, object],
    provider_adapter,
    sender_response,
    receiver_response,
    sender_execution: JSONObject,
    receiver_execution: JSONObject,
) -> tuple[list[ComparisonResult], JSONObject]:
    sender_statuses = {
        status.index: status for status in sender_response.per_index_status
    }
    receiver_statuses = {
        status.index: status for status in receiver_response.per_index_status
    }
    actual_by_index = _live_decoded_models_by_index(receiver_response)
    expected_by_index = _live_sender_decoded_models_by_index(
        plans,
        sender_response,
        provider_adapter=provider_adapter,
    )
    failure_artifacts = _live_endpoint_failure_artifacts(
        sender_response,
        receiver_response,
        sender_execution,
        receiver_execution,
    )

    results: list[ComparisonResult] = []
    for position, plan in enumerate(plans):
        expected_model = expected_by_index.get(
            plan.index,
            expected[position] if position < len(expected) else {},
        )
        results.append(
            _compare_live_packet_result(
                args=args,
                direction=direction,
                plan=plan,
                expected_model=expected_model,
                actual_model=actual_by_index.get(plan.index),
                sender_status=sender_statuses.get(plan.index),
                receiver_status=receiver_statuses.get(plan.index),
                failure_artifacts=failure_artifacts,
                provider_adapter=provider_adapter,
            )
        )

    count_mismatch = _live_count_mismatch_result(
        args=args,
        direction=direction,
        expected_count=len(plans),
        sender_response=sender_response,
        receiver_response=receiver_response,
        failure_artifacts=failure_artifacts,
    )
    if count_mismatch is not None:
        results.append(count_mismatch)

    packet_results = [
        result for result in results if result.metadata.get("aggregate") is not True
    ]
    direction_counts: JSONObject = {
        "generated_count": _count_value(corpus_metadata.get("generated_count")),
        "eligible_count": len(plans),
        "skipped_count": _count_value(corpus_metadata.get("wire_skipped_count")),
        "sent_count": sender_response.sent_count,
        "captured_count": receiver_response.received_count,
        "parsed_count": len(receiver_response.decoded_models),
        "byte_passed_count": sum(
            1 for result in packet_results if result.metadata.get("byte_passed") is True
        ),
        "decode_passed_count": sum(
            1 for result in packet_results if result.metadata.get("decode_passed") is True
        ),
        "failed_count": sum(1 for result in results if not result.passed),
    }
    return results, direction_counts


def _compare_live_packet_result(
    *,
    args: argparse.Namespace,
    direction: str,
    plan: PacketPlan,
    expected_model: JSONObject,
    actual_model: JSONObject | None,
    sender_status,
    receiver_status,
    failure_artifacts: list[str],
    provider_adapter,
) -> ComparisonResult:
    wire_policy = _live_wire_policy(plan, provider_adapter=provider_adapter)
    byte_differences, byte_metadata = _live_wire_byte_differences(
        plan=plan,
        sender_status=sender_status,
        receiver_status=receiver_status,
        wire_policy=wire_policy,
    )

    decode_differences: list[JSONObject] = []
    decode_passed = False
    comparable_expected = _live_comparison_model(
        expected_model,
        plan=plan,
        provider_adapter=provider_adapter,
    )
    comparable_actual: JSONObject | None = None
    if actual_model is None:
        decode_differences.append(
            {
                "path": "decoded_model",
                "expected": "present",
                "actual": "missing",
            }
        )
    else:
        comparable_actual = _live_comparison_model(
            actual_model,
            plan=plan,
            provider_adapter=provider_adapter,
        )
        decode_result = compare_decoded_models(
            expected=comparable_expected,
            actual=comparable_actual,
            plan=replace(plan, strict_bytes=False),
            direction=direction,
            reproduction_command=_live_reproduction_command(args),
        )
        decode_passed = decode_result.passed
        decode_differences.extend(
            _live_prefixed_differences("decoded", decode_result.differences)
        )

    differences = byte_differences + decode_differences
    byte_passed = not byte_differences
    passed = byte_passed and decode_passed
    sender_status_object = sender_status.to_dict() if sender_status is not None else None
    receiver_status_object = (
        receiver_status.to_dict() if receiver_status is not None else None
    )
    return _annotate_live_comparison_result(
        ComparisonResult(
            passed=passed,
            direction=direction,
            expected={
                "sent_raw_hex": None if sender_status is None else sender_status.sent_raw_hex,
                "decoded_model": expected_model,
                "comparable_decoded_model": comparable_expected,
                "sender_status": sender_status_object,
            },
            actual={
                "observed_raw_hex": (
                    None if receiver_status is None else receiver_status.observed_raw_hex
                ),
                "decoded_model": actual_model or {},
                "comparable_decoded_model": comparable_actual or {},
                "receiver_status": receiver_status_object,
            },
            plan=plan,
            strict_bytes=bool(wire_policy.get("strict_bytes", plan.strict_bytes)),
            byte_equal=byte_passed,
            differences=differences,
            reproduction_command=None if passed else _live_reproduction_command(args),
            artifacts=[] if passed else failure_artifacts,
            metadata={
                "plan_id": _plan_id(plan),
                "sent": bool(sender_status.sent) if sender_status is not None else False,
                "captured": (
                    bool(receiver_status.received) if receiver_status is not None else False
                ),
                "parsed": actual_model is not None,
                "byte_passed": byte_passed,
                "decode_passed": decode_passed,
                "byte_comparison": byte_metadata,
            },
        ),
        plan,
        provider_adapter=provider_adapter,
    )


def _live_count_mismatch_result(
    *,
    args: argparse.Namespace,
    direction: str,
    expected_count: int,
    sender_response,
    receiver_response,
    failure_artifacts: list[str],
) -> ComparisonResult | None:
    parsed_count = len(receiver_response.decoded_models)
    differences: list[JSONObject] = []
    if (
        sender_response.sent_count != receiver_response.received_count
        or sender_response.sent_count != expected_count
        or receiver_response.received_count != expected_count
    ):
        differences.append(
            {
                "path": "sent_captured_count_mismatch",
                "expected": {
                    "eligible_count": expected_count,
                    "sent_count": expected_count,
                    "captured_count": expected_count,
                },
                "actual": {
                    "sent_count": sender_response.sent_count,
                    "captured_count": receiver_response.received_count,
                },
            }
        )
    if parsed_count != receiver_response.received_count:
        differences.append(
            {
                "path": "parsed_count",
                "expected": receiver_response.received_count,
                "actual": parsed_count,
            }
        )
    if not differences:
        return None
    return ComparisonResult(
        passed=False,
        direction=direction,
        expected={
            "eligible_count": expected_count,
            "sent_count": expected_count,
            "captured_count": expected_count,
            "parsed_count": receiver_response.received_count,
        },
        actual={
            "sent_count": sender_response.sent_count,
            "captured_count": receiver_response.received_count,
            "parsed_count": parsed_count,
            "sender_errors": list(sender_response.errors),
            "receiver_errors": list(receiver_response.errors),
        },
        strict_bytes=False,
        byte_equal=None,
        differences=differences,
        reproduction_command=_live_reproduction_command(args),
        artifacts=failure_artifacts,
        metadata={
            "aggregate": True,
            "reason": "live endpoint sent/captured/parsed count mismatch",
        },
    )


def _live_decoded_models_by_index(response) -> dict[int, JSONObject]:
    output: dict[int, JSONObject] = {}
    decoded_index = 0
    decoded_models = list(response.decoded_models)
    for status in response.per_index_status:
        for _ in range(max(0, status.decoded_count)):
            if decoded_index >= len(decoded_models):
                return output
            output.setdefault(status.index, decoded_models[decoded_index].to_dict())
            decoded_index += 1
    return output


def _live_sender_decoded_models_by_index(
    plans: Sequence[PacketPlan],
    sender_response,
    *,
    provider_adapter,
) -> dict[int, JSONObject]:
    from .backends.scapy.normalize import decode_vectors

    sender_statuses = {
        status.index: status for status in sender_response.per_index_status
    }
    vectors: list[EncodedVector] = []
    indexes: list[int] = []
    for plan in plans:
        status = sender_statuses.get(plan.index)
        if status is None or status.sent_raw_hex is None:
            continue
        wire_policy = _live_wire_policy(plan, provider_adapter=provider_adapter)
        compare_root = _optional_string(wire_policy.get("compare_root"))
        comparable_hex, _extract = _live_extract_comparable_hex(
            status.sent_raw_hex,
            raw_root=status.send_root,
            compare_root=compare_root,
        )
        root = _live_canonical_root(compare_root)
        if comparable_hex is None or root is None:
            continue
        try:
            raw = bytes.fromhex(comparable_hex)
        except ValueError:
            continue
        vectors.append(
            EncodedVector.from_bytes(
                plan=replace(plan, strict_bytes=False),
                backend="live-sender",
                raw=raw,
                root=root,
                decoder=root,
                metadata={
                    "source": "sender_sent_raw_hex",
                    "sender_role": sender_response.endpoint_role,
                    "send_root": status.send_root,
                    "compare_root": compare_root,
                },
            )
        )
        indexes.append(plan.index)

    decoded = decode_vectors(vectors) if vectors else []
    return {
        index: model.to_dict()
        for index, model in zip(indexes, decoded, strict=False)
    }


def _live_endpoint_failure_artifacts(
    sender_response,
    receiver_response,
    sender_execution: JSONObject,
    receiver_execution: JSONObject,
) -> list[str]:
    paths: list[str] = []
    for response in (sender_response, receiver_response):
        paths.extend(
            value for value in response.artifact_paths.values() if isinstance(value, str)
        )
        paths.extend(capture.path for capture in response.captures)
    paths.extend(_command_artifact_paths(sender_execution))
    paths.extend(_command_artifact_paths(receiver_execution))
    return _dedupe_paths(paths)


def _live_wire_byte_differences(
    *,
    plan: PacketPlan,
    sender_status,
    receiver_status,
    wire_policy: Mapping[str, object],
) -> tuple[list[JSONObject], JSONObject]:
    differences: list[JSONObject] = []
    compare_root = _optional_string(wire_policy.get("compare_root"))
    mutable_fields = _live_byte_mutable_fields(wire_policy)
    metadata: JSONObject = {
        "compare_root": compare_root,
        "strict_bytes": bool(wire_policy.get("strict_bytes", plan.strict_bytes)),
        "mutable_fields": _string_values(wire_policy.get("mutable_fields", [])),
        "byte_mutable_fields": mutable_fields,
        "policy_source": "wire_policy",
    }

    if sender_status is None:
        differences.append(
            {"path": "sender_status", "expected": "present", "actual": "missing"}
        )
        return differences, metadata
    if receiver_status is None:
        differences.append(
            {"path": "receiver_status", "expected": "present", "actual": "missing"}
        )
        return differences, metadata

    metadata["sender_status"] = sender_status.status
    metadata["receiver_status"] = receiver_status.status
    metadata["sender_root"] = sender_status.send_root
    metadata["receiver_root"] = receiver_status.capture_root

    if not sender_status.sent:
        differences.append({"path": "sent", "expected": True, "actual": False})
    if not receiver_status.received:
        differences.append({"path": "captured", "expected": True, "actual": False})
    if sender_status.sent_raw_hex is None:
        differences.append(
            {"path": "sent_raw_hex", "expected": "hex bytes", "actual": None}
        )
    if receiver_status.observed_raw_hex is None:
        differences.append(
            {"path": "observed_raw_hex", "expected": "hex bytes", "actual": None}
        )
    if sender_status.sent_raw_hex is None or receiver_status.observed_raw_hex is None:
        return differences, metadata

    sender_hex, sender_extract = _live_extract_comparable_hex(
        sender_status.sent_raw_hex,
        raw_root=sender_status.send_root,
        compare_root=compare_root,
    )
    receiver_hex, receiver_extract = _live_extract_comparable_hex(
        receiver_status.observed_raw_hex,
        raw_root=receiver_status.capture_root,
        compare_root=compare_root,
    )
    metadata["sender_extract"] = sender_extract
    metadata["receiver_extract"] = receiver_extract
    sender_error = _optional_string(sender_extract.get("error"))
    receiver_error = _optional_string(receiver_extract.get("error"))
    if sender_error is not None:
        differences.append(
            {
                "path": "sent_raw_hex.compare_root",
                "expected": compare_root,
                "actual": sender_error,
            }
        )
    if receiver_error is not None:
        differences.append(
            {
                "path": "observed_raw_hex.compare_root",
                "expected": compare_root,
                "actual": receiver_error,
            }
        )
    if sender_hex is None or receiver_hex is None:
        return differences, metadata

    masked_sender, sender_mask = _live_mask_wire_hex(
        sender_hex,
        compare_root=compare_root,
        mutable_fields=mutable_fields,
    )
    masked_receiver, receiver_mask = _live_mask_wire_hex(
        receiver_hex,
        compare_root=compare_root,
        mutable_fields=mutable_fields,
    )
    metadata["comparable_sent_raw_hex"] = sender_hex
    metadata["comparable_observed_raw_hex"] = receiver_hex
    metadata["masked_sent_raw_hex"] = masked_sender
    metadata["masked_observed_raw_hex"] = masked_receiver
    metadata["sender_mask"] = sender_mask
    metadata["receiver_mask"] = receiver_mask
    if masked_sender != masked_receiver:
        differences.append(
            {
                "path": "raw_hex",
                "expected": sender_hex,
                "actual": receiver_hex,
                "masked_expected": masked_sender,
                "masked_actual": masked_receiver,
                "mutable_fields": mutable_fields,
            }
        )
    return differences, metadata


def _live_byte_mutable_fields(wire_policy: Mapping[str, object]) -> list[str]:
    if "byte_mutable_fields" in wire_policy:
        return _string_values(wire_policy.get("byte_mutable_fields", []))
    return _string_values(wire_policy.get("mutable_fields", []))


def _live_extract_comparable_hex(
    raw_hex: str,
    *,
    raw_root: str | None,
    compare_root: str | None,
) -> tuple[str | None, JSONObject]:
    metadata: JSONObject = {
        "raw_root": raw_root,
        "compare_root": compare_root,
    }
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        metadata["error"] = f"invalid hex: {exc}"
        return None, metadata

    canonical_raw_root = _live_canonical_root(raw_root) or compare_root
    canonical_compare_root = _live_canonical_root(compare_root)
    metadata["canonical_raw_root"] = canonical_raw_root
    metadata["canonical_compare_root"] = canonical_compare_root
    if canonical_compare_root is None:
        metadata["error"] = "missing compare root"
        return None, metadata
    if canonical_raw_root == canonical_compare_root:
        metadata["offset"] = 0
        metadata["length"] = len(raw)
        return raw.hex(), metadata
    if canonical_raw_root == "link:ethernet" and canonical_compare_root in {
        "l3:ipv4",
        "l3:ipv6",
    }:
        payload = _live_ethernet_payload(raw)
        if payload is None:
            metadata["error"] = "ethernet frame too short"
            return None, metadata
        offset, ethertype = payload
        expected_ethertype = 0x0800 if canonical_compare_root == "l3:ipv4" else 0x86DD
        metadata["offset"] = offset
        metadata["ethertype"] = ethertype
        if ethertype != expected_ethertype:
            metadata["error"] = (
                f"ethernet ethertype 0x{ethertype:04x} does not match "
                f"{canonical_compare_root}"
            )
            return None, metadata
        comparable = raw[offset:]
        metadata["length"] = len(comparable)
        return comparable.hex(), metadata

    metadata["error"] = (
        f"cannot compare {canonical_raw_root!r} bytes as {canonical_compare_root!r}"
    )
    return None, metadata


def _live_mask_wire_hex(
    raw_hex: str,
    *,
    compare_root: str | None,
    mutable_fields: Sequence[str],
) -> tuple[str, list[JSONObject]]:
    raw = bytearray(bytes.fromhex(raw_hex))
    root = _live_canonical_root(compare_root)
    masked: list[JSONObject] = []
    for mutable_field in mutable_fields:
        for offset, length in _live_mutable_field_spans(raw, root, mutable_field):
            if offset < 0 or length <= 0 or offset + length > len(raw):
                continue
            raw[offset : offset + length] = b"\x00" * length
            masked.append(
                {
                    "field": mutable_field,
                    "offset": offset,
                    "length": length,
                }
            )
    return raw.hex(), masked


def _live_mutable_field_spans(
    raw: bytearray,
    compare_root: str | None,
    mutable_field: str,
) -> list[tuple[int, int]]:
    field = _live_normalized_mutable_field(mutable_field)
    spans: list[tuple[int, int]] = []
    if compare_root == "link:ethernet":
        if field == "ethernet.dst":
            spans.append((0, 6))
        elif field == "ethernet.src":
            spans.append((6, 6))
        elif field == "ethernet.ethertype":
            spans.append((12, 2))
    ipv4_offset = _live_ipv4_header_offset(raw, compare_root)
    if ipv4_offset is not None:
        if field in {"ipv4.id", "ipv4.identification", "ip.id", "ip.identification"}:
            spans.append((ipv4_offset + 4, 2))
        elif field in {"ipv4.ttl", "ip.ttl"}:
            spans.append((ipv4_offset + 8, 1))
        elif field in {"ipv4.checksum", "ipv4.chksum", "ip.checksum", "ip.chksum"}:
            spans.append((ipv4_offset + 10, 2))
    return spans


def _live_ipv4_header_offset(raw: bytearray, compare_root: str | None) -> int | None:
    if compare_root == "l3:ipv4":
        return 0 if len(raw) >= 20 and raw[0] >> 4 == 4 else None
    if compare_root == "link:ethernet":
        payload = _live_ethernet_payload(bytes(raw))
        if payload is None:
            return None
        offset, ethertype = payload
        if ethertype == 0x0800 and len(raw) >= offset + 20 and raw[offset] >> 4 == 4:
            return offset
    return None


def _live_ethernet_payload(raw: bytes) -> tuple[int, int] | None:
    if len(raw) < 14:
        return None
    ethertype = int.from_bytes(raw[12:14], "big")
    offset = 14
    while ethertype in {0x8100, 0x88A8, 0x9100}:
        if len(raw) < offset + 4:
            return None
        ethertype = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        offset += 4
    return offset, ethertype


def _live_canonical_root(root: str | None) -> str | None:
    if root is None:
        return None
    return LIVE_ROOT_ALIASES.get(root, root)


def _live_normalized_mutable_field(field: str) -> str:
    normalized = field.removeprefix("fields.")
    return normalized.lower()


def _live_prefixed_differences(
    prefix: str,
    differences: Sequence[Mapping[str, object]],
) -> list[JSONObject]:
    output: list[JSONObject] = []
    for difference in differences:
        path = difference.get("path")
        copied: JSONObject = {
            key: _json_difference_value(value)
            for key, value in difference.items()
            if isinstance(key, str)
        }
        copied["path"] = f"{prefix}.{path}" if isinstance(path, str) else prefix
        output.append(copied)
    return output


def _json_difference_value(value: object) -> JSONValue:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _json_difference_value(item)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_difference_value(item) for item in value]
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    return str(value)


def _plan_id(plan: PacketPlan) -> str | None:
    value = plan.metadata.get("plan_id")
    return value if isinstance(value, str) else None


def _live_comparison_model(
    model: JSONObject,
    *,
    plan: PacketPlan,
    provider_adapter,
) -> JSONObject:
    output = json.loads(json.dumps(model))
    if not isinstance(output, dict):
        return model
    fields = output.get("fields")
    if isinstance(fields, dict):
        for mutable_field in _live_mutable_fields(
            plan,
            provider_adapter=provider_adapter,
        ):
            _remove_live_mutable_field(fields, mutable_field)
    return output


def _annotate_live_comparison_result(
    result: ComparisonResult,
    plan: PacketPlan,
    *,
    provider_adapter,
) -> ComparisonResult:
    wire_policy = _live_wire_policy(plan, provider_adapter=provider_adapter)
    return replace(
        result,
        metadata={
            **result.metadata,
            "wire_policy": wire_policy,
            "live_address_rewrite": plan.metadata.get("live_address_rewrite"),
            "live_transit_rewrites": plan.metadata.get("live_transit_rewrites", []),
        },
    )


def _live_mutable_fields(
    plan: PacketPlan,
    *,
    provider_adapter,
) -> list[str]:
    return [
        field
        for field in _live_wire_policy(
            plan,
            provider_adapter=provider_adapter,
        ).get("mutable_fields", [])
        if isinstance(field, str)
    ]


def _remove_live_mutable_field(fields: JSONObject, mutable_field: str) -> None:
    parts = mutable_field.split(".")
    if len(parts) < 2:
        return
    if parts[0] == "fields":
        parts = parts[1:]
    current: object = fields
    for part in parts[:-1]:
        if not isinstance(current, dict):
            return
        current = current.get(part)
    if isinstance(current, dict):
        current.pop(parts[-1], None)


def _command_artifact_paths(command: JSONObject) -> list[str]:
    paths: list[str] = []
    for key in ("stdout_path", "stderr_path", "request_path", "response_path", "local_path"):
        value = command.get(key)
        if isinstance(value, str):
            paths.append(value)
    paths.extend(_string_values(command.get("artifacts", [])))
    paths.extend(_string_values(command.get("collected_artifacts", [])))
    nested = command.get("commands")
    if isinstance(nested, list):
        for item in nested:
            if isinstance(item, dict):
                paths.extend(_command_artifact_paths(_json_object(item, "nested command")))
    return paths


def _live_endpoint_response_artifact_paths(response) -> list[str]:
    paths: list[str] = []
    paths.extend(
        value for value in response.artifact_paths.values() if isinstance(value, str)
    )
    paths.extend(capture.path for capture in response.captures)
    return _dedupe_paths(paths)


def _live_local_dry_run(args: argparse.Namespace) -> int:
    from .backends.scapy.live import (
        backend_bootstrap_command_plan,
        dry_run_command_plan as scapy_dry_run_command_plan,
        validate_backend_bootstrap_command,
        validate_dry_run_command_plan as validate_scapy_dry_run_command_plan,
    )
    from .live import (
        LIVE_SELECTED_SPECS,
        LiveExchangePlan,
        build_live_endpoint_batch_request,
        dry_run_live_endpoint_batch_response,
        libcrafter_dry_run_command_plan,
        live_endpoint_artifact_paths,
        live_execution_directions,
        local_dry_run_endpoints,
        validate_live_endpoint_batch_contract,
        validate_libcrafter_command_plan,
        validate_local_dry_run_exchange,
    )

    try:
        directions = live_execution_directions(args.direction)
        plans, corpus_selected_specs, corpus_metadata = _live_corpus_plans(
            args,
            wire_provider="hetzner",
            direction=directions[0] if directions else "reference_to_libcrafter",
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    output_dir = _live_output_dir(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"
    selected_specs = list(
        dict.fromkeys([*LIVE_SELECTED_SPECS, *corpus_selected_specs])
    )

    print(
        f"live {args.provider}: generated={corpus_metadata['generated_count']} "
        f"wire_eligible={corpus_metadata['wire_eligible_count']} "
        f"wire_skipped={corpus_metadata['wire_skipped_count']} "
        f"wire_skip_reasons={corpus_metadata['wire_skip_reasons']}"
    )

    endpoints = local_dry_run_endpoints()
    bootstrap_command = backend_bootstrap_command_plan()
    validations = [
        validate_backend_bootstrap_command(bootstrap_command),
        _live_corpus_accounting_validation(corpus_metadata, provider="hetzner"),
    ]
    exchanges: list[LiveExchangePlan] = []

    for plan in plans:
        for direction in directions:
            if direction == "reference_to_libcrafter":
                sender = endpoints["reference_backend"]
                receiver = endpoints["libcrafter"]
                sender_command = scapy_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="sender",
                )
                receiver_command = libcrafter_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="receiver",
                )
                validations.append(validate_scapy_dry_run_command_plan(sender_command))
                validations.append(validate_libcrafter_command_plan(receiver_command))
            elif direction == "libcrafter_to_reference":
                sender = endpoints["libcrafter"]
                receiver = endpoints["reference_backend"]
                sender_command = libcrafter_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="sender",
                )
                receiver_command = scapy_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="receiver",
                )
                validations.append(validate_libcrafter_command_plan(sender_command))
                validations.append(validate_scapy_dry_run_command_plan(receiver_command))
            else:
                print(f"unsupported live direction: {direction}", file=sys.stderr)
                return 2

            exchange = LiveExchangePlan(
                provider=args.provider,
                backend=args.backend,
                direction=direction,
                index=plan.index,
                packet_plan=replace(plan, direction=direction),
                sender=sender,
                receiver=receiver,
                sender_command=sender_command,
                receiver_command=receiver_command,
                live_packet_exchange=False,
                metadata={
                    "dry_run": True,
                    "live_packet_exchange": False,
                    "no_live_packets_sent": True,
                },
            )
            exchanges.append(exchange)
            validations.append(validate_local_dry_run_exchange(exchange))

    endpoint_protocol_batches: list[JSONObject] = []
    for direction in directions:
        direction_plans = [replace(plan, direction=direction) for plan in plans]
        if direction == "reference_to_libcrafter":
            sender = endpoints["reference_backend"]
            receiver = endpoints["libcrafter"]
        elif direction == "libcrafter_to_reference":
            sender = endpoints["libcrafter"]
            receiver = endpoints["reference_backend"]
        else:
            print(f"unsupported live direction: {direction}", file=sys.stderr)
            return 2

        for phase_role, endpoint, peer in (
            ("sender", sender, receiver),
            ("receiver", receiver, sender),
        ):
            request = build_live_endpoint_batch_request(
                provider=args.provider,
                backend=args.backend,
                seed=args.seed,
                profile=args.profile,
                packet_plans=direction_plans,
                direction=direction,
                endpoint=endpoint,
                peer=peer,
                artifact_paths=live_endpoint_artifact_paths(
                    output_dir=str(output_dir),
                    direction=direction,
                    endpoint_role=endpoint.role,
                ),
                metadata={
                    "phase_role": phase_role,
                    "dry_run": True,
                    "live_packet_exchange": False,
                    "no_live_packets_sent": True,
                },
            )
            response = dry_run_live_endpoint_batch_response(request)
            validation = validate_live_endpoint_batch_contract(
                request,
                response,
                dry_run=True,
            )
            validations.append(validation)
            endpoint_protocol_batches.append(
                {
                    "phase_role": phase_role,
                    "request": request.to_dict(),
                    "response": response.to_dict(),
                    "validation": validation.to_dict(),
                }
            )

    failed_validations = [validation for validation in validations if not validation.passed]
    status = "passed" if not failed_validations else "failed"
    live_count_metadata = _live_count_metadata(
        _live_empty_direction_counts(corpus_metadata, directions)
    )
    result = ComparisonResult(
        passed=not failed_validations,
        direction=args.direction,
        expected={
            "provider": args.provider,
            "dry_run": True,
            "live_packet_exchange": False,
            "validations_pass": True,
            "endpoint_protocol_batches": len(directions) * 2,
            "generated_count": corpus_metadata["generated_count"],
            "wire_eligible_count": corpus_metadata["wire_eligible_count"],
            "wire_skipped_count": corpus_metadata["wire_skipped_count"],
        },
        actual={
            "provider": args.provider,
            "dry_run": True,
            "live_packet_exchange": False,
            "validations_pass": not failed_validations,
            "endpoint_protocol_batches": len(endpoint_protocol_batches),
            "failed_validations": [validation.to_dict() for validation in failed_validations],
            "generated_count": corpus_metadata["generated_count"],
            "wire_eligible_count": corpus_metadata["wire_eligible_count"],
            "wire_skipped_count": corpus_metadata["wire_skipped_count"],
        },
        strict_bytes=False,
        byte_equal=None,
        differences=[
            {
                "path": validation.name,
                "expected": "passed",
                "actual": validation.errors,
                "subject": validation.subject,
            }
            for validation in failed_validations
        ],
        reproduction_command=None
        if not failed_validations
        else _live_reproduction_command(args),
        metadata={
            "provider": args.provider,
            "dry_run": True,
            "live_packet_exchange": False,
            "validation_count": len(validations),
        },
    )

    report = RunReport(
        mode="live",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(exchanges),
        status=status,
        selected_specs=selected_specs,
        artifacts=[str(report_path)],
        artifact_paths=[str(report_path)],
        results=[result],
        failures=[] if result.passed else [result],
        reproduction_commands=(
            [] if result.reproduction_command is None else [result.reproduction_command]
        ),
        backend_versions=_backend_versions(args.backend),
        libcrafter=_libcrafter_info(),
        metadata={
            "provider": args.provider,
            "dry_run": True,
            "live_packet_exchange": False,
            "no_live_packets_sent": True,
            "real_provider_backed_live_mode": "not executed by local-dry-run",
            **corpus_metadata,
            **live_count_metadata,
            "execution_directions": directions,
            "backend_bootstrap": {
                "command": bootstrap_command.to_dict(),
                "validation": validations[0].to_dict(),
            },
            "endpoints": {
                name: endpoint.to_dict() for name, endpoint in endpoints.items()
            },
            "endpoint_protocol": {
                "version": 1,
                "batches": endpoint_protocol_batches,
            },
            "validation_count": len(validations),
            "exchanges": [exchange.to_dict() for exchange in exchanges],
            "validations": [validation.to_dict() for validation in validations],
        },
    )
    write_json(report_path, report)

    print(
        f"live {args.provider}: status={status} exchanges={len(exchanges)} "
        f"wire_eligible={corpus_metadata['wire_eligible_count']} "
        f"wire_skipped={corpus_metadata['wire_skipped_count']} "
        f"live_packet_exchange=false report={report_path}"
    )
    if failed_validations:
        print(f"failed_validations={len(failed_validations)}", file=sys.stderr)
        print(f"reproduce: {_live_reproduction_command(args)}", file=sys.stderr)

    return 0 if status == "passed" else 1


class PcapUnsupportedError(ValueError):
    """Raised when a selected pcap spec case cannot execute in this repository."""


def _pcap_dry_plan(args: argparse.Namespace) -> int:
    try:
        directions = _pcap_execution_directions(args.direction)
        direction_groups, selected_specs, corpus_metadata = _pcap_corpus_plan_groups(
            args,
            directions,
            materialize=False,
        )
        plans = [
            plan
            for groups in direction_groups.values()
            for group in groups
            for plan in group["plans"]  # type: ignore[index]
            if isinstance(plan, PacketPlan)
        ]
    except (ValueError, PcapUnsupportedError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    report = RunReport(
        mode="pcap",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(plans),
        status="dry-plan",
        selected_specs=selected_specs,
        metadata={
            "dry_plan": True,
            "requested_count": args.count,
            "direction": args.direction,
            "execution_directions": directions,
            **corpus_metadata,
            "timestamp_policy": {
                "deterministic": "exact",
                "backend_precision_differs": "normalized",
                "backend_generated_or_unavailable": "ignored",
            },
            "directions": _pcap_group_summaries(direction_groups),
            "plans": [plan.to_dict() for plan in plans],
        },
    )
    sys.stdout.write(dumps_json(report))
    return 0


def _pcap_execute(args: argparse.Namespace) -> int:
    output_dir = _pcap_output_dir(args.out)
    artifacts_root = output_dir / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"

    try:
        directions = _pcap_execution_directions(args.direction)
        groups_by_direction, selected_specs, corpus_metadata = _pcap_corpus_plan_groups(
            args,
            directions,
            materialize=True,
        )
        direction_groups = [
            (direction, groups_by_direction.get(direction, []))
            for direction in directions
        ]
    except PcapUnsupportedError as exc:
        return _write_pcap_unsupported_report(
            args=args,
            message=str(exc),
            report_path=report_path,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    run_dir = Path(
        tempfile.mkdtemp(
            prefix=f"{args.direction}.",
            dir=artifacts_root,
        )
    )

    try:
        backend_versions = _backend_versions(args.backend)
        libcrafter_info = _libcrafter_info()

        results: list[ComparisonResult] = []
        direction_metadata: list[JSONObject] = []
        direction_artifacts: list[str] = []
        bridge_exit_codes: list[int] = []
        generated_count = 0
        for direction, groups in direction_groups:
            for group in groups:
                vectors = group["vectors"]
                plans = group["plans"]
                if not isinstance(vectors, list) or not isinstance(plans, list):
                    raise RuntimeError("pcap vector group is malformed")
                generated_count += len(plans)
                link_type = group["link_type"]
                if not isinstance(link_type, str):
                    raise RuntimeError("pcap vector group link_type must be a string")
                label = _pcap_group_label(direction, link_type)
                vector_path = run_dir / f"{label}.vectors.json"
                vector_report = RunReport(
                    mode="pcap",
                    backend=args.backend,
                    profile=args.profile,
                    seed=args.seed,
                    count=len(vectors),
                    status="vectors",
                    selected_specs=selected_specs,
                    backend_versions=backend_versions,
                    libcrafter=libcrafter_info,
                    metadata={
                        "direction": direction,
                        "execution_directions": directions,
                        "requested_count": args.count,
                        "pcap_case": group["pcap_case"],
                        "file_format": group["file_format"],
                        "link_type": group["link_type"],
                        "vectors": [vector.to_dict() for vector in vectors],
                    },
                )
                write_json(vector_path, vector_report)

                if direction == "reference_to_libcrafter":
                    run = _pcap_reference_to_libcrafter(
                        args=args,
                        run_dir=run_dir,
                        vector_path=vector_path,
                        vectors=vectors,  # type: ignore[arg-type]
                        plans=plans,  # type: ignore[arg-type]
                        label=label,
                    )
                elif direction == "libcrafter_to_reference":
                    run = _pcap_libcrafter_to_reference(
                        args=args,
                        run_dir=run_dir,
                        vector_path=vector_path,
                        vectors=vectors,  # type: ignore[arg-type]
                        plans=plans,  # type: ignore[arg-type]
                        label=label,
                    )
                else:
                    raise RuntimeError(f"unsupported pcap execution direction: {direction}")

                results.extend(run["results"])  # type: ignore[arg-type]
                direction_metadata.append(_json_object(run["metadata"], "pcap direction metadata"))
                direction_artifacts.extend(_string_values(run["artifacts"]))
                exit_code = run.get("bridge_exit_code")
                if isinstance(exit_code, int):
                    bridge_exit_codes.append(exit_code)

        failures = [result for result in results if not result.passed]
        status = "passed" if not failures and all(code == 0 for code in bridge_exit_codes) else "failed"
        preserve_artifacts = args.keep_artifacts or status != "passed"

        artifacts = [str(report_path)]
        if preserve_artifacts:
            artifacts.append(str(run_dir))
            artifacts.extend(direction_artifacts)
        artifacts.extend(_comparison_artifact_paths(failures))
        artifacts = _dedupe_paths(artifacts)

        report = RunReport(
            mode="pcap",
            backend=args.backend,
            profile=args.profile,
            seed=args.seed,
            count=len(results),
            status=status,
            selected_specs=selected_specs,
            artifacts=artifacts,
            artifact_paths=artifacts,
            results=results,
            failures=failures,
            reproduction_commands=[
                command
                for command in (result.reproduction_command for result in failures)
                if command is not None
            ],
            backend_versions=backend_versions,
            libcrafter=libcrafter_info,
            metadata={
                "direction": args.direction,
                "execution_directions": directions,
                "requested_count": args.count,
                "generated_count": generated_count,
                **corpus_metadata,
                "artifact_dir": str(run_dir) if preserve_artifacts else None,
                "directions": direction_metadata,
                "timestamp_policy": {
                    "deterministic": "exact",
                    "precision": "microseconds",
                },
            },
        )
        write_json(report_path, report)

        if not preserve_artifacts:
            shutil.rmtree(run_dir)

        passed_count = len(results) - len(failures)
        print(
            f"pcap {args.direction}: status={status} "
            f"passed={passed_count}/{len(results)} report={report_path}"
        )
        if failures:
            indexes = ", ".join(str(index) for index in failure_indexes(failures))
            print(f"failing_indexes={indexes}", file=sys.stderr)
            if failures[0].reproduction_command:
                print(f"reproduce: {failures[0].reproduction_command}", file=sys.stderr)

        return 0 if status == "passed" else 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _offline(args: argparse.Namespace) -> int:
    required_capabilities = _offline_required_capabilities(args)
    if required_capabilities:
        unsupported = _require_backend_capabilities(
            args,
            mode="offline",
            required=required_capabilities,
            operation=f"offline {args.direction}",
            report_path=_offline_report_output_dir(args) / "report.json",
            selected_specs=GENERATOR_SELECTED_SPECS,
        )
        if unsupported is not None:
            return unsupported
        if args.backend not in {"scapy", "wireshark"}:
            return _backend_not_implemented_report(
                args,
                mode="offline",
                operation=f"offline {args.direction}",
                report_path=_offline_report_output_dir(args) / "report.json",
                selected_specs=GENERATOR_SELECTED_SPECS,
            )

    if not args.dry_plan and not args.emit_vectors and not args.emit_decoded:
        if args.direction == "reference_to_libcrafter":
            return _offline_reference_to_libcrafter(args)
        if args.direction == "libcrafter_to_reference":
            return _offline_libcrafter_to_reference(args)
        print(f"unsupported offline direction: {args.direction}", file=sys.stderr)
        return 2

    try:
        plans, selected_specs, corpus_metadata = _offline_corpus_plans(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.emit_vectors or args.emit_decoded:
        if args.backend == "scapy":
            from .backends.scapy.packets import encode_packet_plans

            vectors = encode_packet_plans(plans)
        else:
            print(f"unsupported backend: {args.backend}", file=sys.stderr)
            return 2

        if args.emit_decoded:
            from .backends.scapy.normalize import decode_vectors, validate_smoke_decodes

            decoded = decode_vectors(vectors)
            if args.profile == "smoke":
                validate_smoke_decodes(vectors, decoded)

            metadata = {
                "emit_decoded": True,
                "requested_count": args.count,
                **corpus_metadata,
                "decoded": [model.to_dict() for model in decoded],
            }
            if args.emit_vectors:
                metadata["vectors"] = [vector.to_dict() for vector in vectors]

            report = RunReport(
                mode="offline",
                backend=args.backend,
                profile=args.profile,
                seed=args.seed,
                count=len(decoded),
                status="decoded",
                selected_specs=selected_specs,
                backend_versions=_backend_versions(args.backend),
                libcrafter=_libcrafter_info(),
                metadata=metadata,
            )
            sys.stdout.write(dumps_json(report))
            return 0

        report = RunReport(
            mode="offline",
            backend=args.backend,
            profile=args.profile,
            seed=args.seed,
            count=len(vectors),
            status="vectors",
            selected_specs=selected_specs,
            backend_versions=_backend_versions(args.backend),
            libcrafter=_libcrafter_info(),
            metadata={
                "emit_vectors": True,
                "requested_count": args.count,
                **corpus_metadata,
                "vectors": [vector.to_dict() for vector in vectors],
            },
        )
        sys.stdout.write(dumps_json(report))
        return 0

    report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(plans),
        status="dry-plan",
        selected_specs=selected_specs,
        metadata={
            "dry_plan": True,
            "requested_count": args.count,
            **corpus_metadata,
            "plans": [plan.to_dict() for plan in plans],
        },
    )
    sys.stdout.write(dumps_json(report))
    return 0


def _offline_reference_to_libcrafter(args: argparse.Namespace) -> int:
    if args.direction != "reference_to_libcrafter":
        print(f"unsupported offline direction: {args.direction}", file=sys.stderr)
        return 2

    from .backends.scapy.normalize import decode_vectors
    from .backends.scapy.packets import encode_packet_plans

    if args.backend != "scapy":
        print(f"unsupported backend: {args.backend}", file=sys.stderr)
        return 2

    output_dir = _offline_report_output_dir(args)
    artifacts_root = output_dir / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"
    run_dir = Path(
        tempfile.mkdtemp(
            prefix=f"{args.direction}.",
            dir=artifacts_root,
        )
    )

    try:
        plans, selected_specs, corpus_metadata = _offline_corpus_plans(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    backend_capabilities = _offline_backend_capabilities(args)
    vectors = encode_packet_plans(plans)
    expected_decoded = decode_vectors(vectors)
    backend_versions = _backend_versions(args.backend)
    libcrafter_info = _libcrafter_info()

    vector_report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(vectors),
        status="vectors",
        selected_specs=selected_specs,
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            **corpus_metadata,
            "backend_capabilities": backend_capabilities,
            "vectors": [vector.to_dict() for vector in vectors],
        },
    )
    vector_path = run_dir / "reference-vectors.json"
    write_json(vector_path, vector_report)

    expected_path = run_dir / "reference-decoded.json"
    write_json(
        expected_path,
        RunReport(
            mode="offline",
            backend=args.backend,
            profile=args.profile,
            seed=args.seed,
            count=len(expected_decoded),
            status="decoded",
            selected_specs=selected_specs,
            backend_versions=backend_versions,
            libcrafter=libcrafter_info,
            metadata={
                "direction": args.direction,
                **corpus_metadata,
                "backend_capabilities": backend_capabilities,
                "decoded": [model.to_dict() for model in expected_decoded],
            },
        ),
    )

    bridge = _run_libcrafter_decode_bridge(vector_path, run_dir)
    actual_decoded = _decoded_models(bridge["report"]) if bridge["exit_code"] == 0 else []
    actual_path = run_dir / "libcrafter-decoded.json"
    write_json(actual_path, bridge["report"])

    results = _compare_offline_results(
        args=args,
        expected=expected_decoded,
        actual=actual_decoded,
        plans=plans,
    )
    results = _with_failure_artifacts(
        run_dir=run_dir,
        results=results,
        vectors=vectors,
        backend_decoded=expected_decoded,
        libcrafter_decoded=actual_decoded,
    )
    failures = [result for result in results if not result.passed]
    status = "passed" if not failures and bridge["exit_code"] == 0 else "failed"
    preserve_artifacts = args.keep_artifacts or status != "passed"

    artifacts = [str(report_path)]
    if preserve_artifacts:
        artifacts.extend(
            [
                str(run_dir),
                str(vector_path),
                str(expected_path),
                str(actual_path),
                str(bridge["stdout_path"]),
                str(bridge["stderr_path"]),
            ]
        )
    artifacts.extend(_comparison_artifact_paths(failures))
    artifacts = _dedupe_paths(artifacts)

    report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(results),
        status=status,
        selected_specs=selected_specs,
        artifacts=artifacts,
        artifact_paths=artifacts,
        results=results,
        failures=failures,
        reproduction_commands=[
            command
            for command in (result.reproduction_command for result in failures)
            if command is not None
        ],
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            **corpus_metadata,
            "artifact_dir": str(run_dir) if preserve_artifacts else None,
            "backend_capabilities": backend_capabilities,
            "libcrafter_bridge": {
                "argv": bridge["argv"],
                "exit_code": bridge["exit_code"],
            },
            "vectors": _vector_summaries(vectors),
        },
    )
    write_json(report_path, report)

    if not preserve_artifacts:
        shutil.rmtree(run_dir)

    passed_count = len(results) - len(failures)
    print(
        f"offline {args.direction}: status={status} "
        f"passed={passed_count}/{len(results)} report={report_path}"
    )
    if failures:
        indexes = ", ".join(str(index) for index in failure_indexes(failures))
        print(f"failing_indexes={indexes}", file=sys.stderr)
        if failures[0].reproduction_command:
            print(f"reproduce: {failures[0].reproduction_command}", file=sys.stderr)

    return 0 if status == "passed" else 1


def _offline_libcrafter_to_reference(args: argparse.Namespace) -> int:
    if args.direction != "libcrafter_to_reference":
        print(f"unsupported offline direction: {args.direction}", file=sys.stderr)
        return 2
    if args.backend not in {"scapy", "wireshark"}:
        print(f"unsupported backend: {args.backend}", file=sys.stderr)
        return 2

    if args.backend == "scapy":
        from .backends.scapy.normalize import decode_vectors
    else:
        from .backends.wireshark.normalize import decode_vectors

    output_dir = _offline_report_output_dir(args)
    artifacts_root = output_dir / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"
    backend_decoded_path = output_dir / f"{args.backend}-decoded.json"
    run_dir = Path(
        tempfile.mkdtemp(
            prefix=f"{args.direction}.",
            dir=artifacts_root,
        )
    )

    backend_versions = _backend_versions(args.backend)
    libcrafter_info = _libcrafter_info()
    try:
        plans, selected_specs, corpus_metadata = _offline_corpus_plans(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    backend_capabilities = _offline_backend_capabilities(args)

    plan_report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(plans),
        status="generated",
        selected_specs=selected_specs,
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            **corpus_metadata,
            "backend_capabilities": backend_capabilities,
            "plans": [plan.to_dict() for plan in plans],
        },
    )
    plan_path = run_dir / "libcrafter-plans.json"
    write_json(plan_path, plan_report)

    materializer = _run_libcrafter_plan_materializer(plan_path, run_dir)
    vector_report = materializer["report"]
    vectors = _encoded_vectors(vector_report) if materializer["exit_code"] == 0 else []
    vector_path = run_dir / "libcrafter-vectors.json"
    write_json(vector_path, vector_report)

    bridge = _run_libcrafter_decode_bridge(vector_path, run_dir) if vectors else {
        "argv": [],
        "exit_code": 1,
        "report": RunReport(
            mode="offline",
            backend="libcrafter",
            profile=args.profile,
            seed=args.seed,
            count=0,
            status="failed",
            selected_specs=selected_specs,
            backend_versions=backend_versions,
            libcrafter=libcrafter_info,
            metadata={
                "decoded": [],
                "error": "libcrafter plan materializer did not emit vectors",
                "materializer_exit_code": materializer["exit_code"],
            },
        ).to_dict(),
        "stdout_path": materializer["stdout_path"],
        "stderr_path": materializer["stderr_path"],
    }
    expected_decoded = _decoded_models(bridge["report"]) if bridge["exit_code"] == 0 else []
    expected_path = run_dir / "libcrafter-expected-decoded.json"
    write_json(
        expected_path,
        bridge["report"],
    )

    actual_decoded = decode_vectors(vectors) if vectors else []
    backend_report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(actual_decoded),
        status="decoded",
        selected_specs=selected_specs,
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            **corpus_metadata,
            "backend_capabilities": backend_capabilities,
            "decoded": [model.to_dict() for model in actual_decoded],
        },
    )
    actual_path = run_dir / f"{args.backend}-decoded.json"
    write_json(actual_path, backend_report)
    write_json(backend_decoded_path, backend_report)

    results = _compare_offline_results(
        args=args,
        expected=expected_decoded,
        actual=actual_decoded,
        plans=plans,
    )
    results = _with_failure_artifacts(
        run_dir=run_dir,
        results=results,
        vectors=vectors,
        backend_decoded=actual_decoded,
        libcrafter_decoded=expected_decoded,
    )
    failures = [result for result in results if not result.passed]
    status = (
        "passed"
        if not failures and materializer["exit_code"] == 0 and bridge["exit_code"] == 0
        else "failed"
    )
    preserve_artifacts = args.keep_artifacts or status != "passed"

    artifacts = [str(report_path), str(backend_decoded_path)]
    if preserve_artifacts:
        artifacts.extend(
            [
                str(run_dir),
                str(plan_path),
                str(vector_path),
                str(expected_path),
                str(actual_path),
                str(materializer["stdout_path"]),
                str(materializer["stderr_path"]),
                str(bridge["stdout_path"]),
                str(bridge["stderr_path"]),
            ]
        )
    artifacts.extend(_comparison_artifact_paths(failures))
    artifacts = _dedupe_paths(artifacts)

    report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(results),
        status=status,
        selected_specs=selected_specs,
        artifacts=artifacts,
        artifact_paths=artifacts,
        results=results,
        failures=failures,
        reproduction_commands=[
            command
            for command in (result.reproduction_command for result in failures)
            if command is not None
        ],
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            **corpus_metadata,
            "artifact_dir": str(run_dir) if preserve_artifacts else None,
            "backend_capabilities": backend_capabilities,
            "libcrafter_materializer": {
                "argv": materializer["argv"],
                "exit_code": materializer["exit_code"],
            },
            "libcrafter_bridge": {
                "argv": bridge["argv"],
                "exit_code": bridge["exit_code"],
            },
            "vectors": _vector_summaries(vectors),
        },
    )
    write_json(report_path, report)

    if not preserve_artifacts:
        shutil.rmtree(run_dir)

    passed_count = len(results) - len(failures)
    print(
        f"offline {args.direction}: status={status} "
        f"passed={passed_count}/{len(results)} report={report_path}"
    )
    if failures:
        indexes = ", ".join(str(index) for index in failure_indexes(failures))
        print(f"failing_indexes={indexes}", file=sys.stderr)
        if failures[0].reproduction_command:
            print(f"reproduce: {failures[0].reproduction_command}", file=sys.stderr)

    return 0 if status == "passed" else 1


def _pcap_reference_to_libcrafter(
    *,
    args: argparse.Namespace,
    run_dir: Path,
    vector_path: Path,
    vectors: list[EncodedVector],
    plans: list[PacketPlan],
    label: str,
) -> JSONObject:
    from .backends.scapy.pcap import read_pcap, write_pcap

    pcap_path = run_dir / f"{label}.scapy-reference.pcap"
    write_pcap(pcap_path, vectors)
    expected_records = read_pcap(pcap_path)
    expected_path = run_dir / f"{label}.scapy-reference-read.json"
    write_json(expected_path, {"records": expected_records})

    bridge = _run_libcrafter_pcap_reader(pcap_path, run_dir, f"{label}.scapy-reference")
    actual_records = _pcap_records(bridge["report"])
    actual_path = run_dir / f"{label}.libcrafter-read-scapy-reference.json"
    write_json(actual_path, bridge["report"])

    results = _compare_pcap_records(
        args=args,
        direction="reference_to_libcrafter",
        expected=expected_records,
        actual=actual_records,
        plans=plans,
    )

    artifacts = _dedupe_paths(
        [
            str(vector_path),
            str(pcap_path),
            str(expected_path),
            str(actual_path),
            str(bridge["stdout_path"]),
            str(bridge["stderr_path"]),
        ]
    )
    return {
        "results": results,
        "artifacts": artifacts,
        "bridge_exit_code": bridge["exit_code"],
        "metadata": {
            "direction": "reference_to_libcrafter",
            "writer": "scapy",
            "reader": "libcrafter",
            "label": label,
            "pcap": str(pcap_path),
            "record_count": len(expected_records),
            "libcrafter_bridge": {
                "argv": bridge["argv"],
                "exit_code": bridge["exit_code"],
            },
        },
    }


def _pcap_libcrafter_to_reference(
    *,
    args: argparse.Namespace,
    run_dir: Path,
    vector_path: Path,
    vectors: list[EncodedVector],
    plans: list[PacketPlan],
    label: str,
) -> JSONObject:
    from .backends.scapy.pcap import pcap_link_type_for_vectors

    pcap_path = run_dir / f"{label}.libcrafter-reference.pcap"
    bridge = _run_libcrafter_pcap_writer(
        vector_path=vector_path,
        pcap_path=pcap_path,
        run_dir=run_dir,
        label=f"{label}.libcrafter-reference",
        link_type=pcap_link_type_for_vectors(vectors, requested="ethernet"),
    )
    expected_records = _pcap_records(bridge["report"])
    expected_path = run_dir / f"{label}.libcrafter-reference-written.json"
    write_json(expected_path, bridge["report"])

    actual_records = _pcap_read_reference_records(args.backend, pcap_path)
    actual_path = run_dir / f"{label}.{args.backend}-read-libcrafter-reference.json"
    write_json(actual_path, {"records": actual_records})

    results = _compare_pcap_records(
        args=args,
        direction="libcrafter_to_reference",
        expected=expected_records,
        actual=actual_records,
        plans=plans,
    )

    artifacts = _dedupe_paths(
        [
            str(vector_path),
            str(pcap_path),
            str(expected_path),
            str(actual_path),
            str(bridge["stdout_path"]),
            str(bridge["stderr_path"]),
        ]
    )
    return {
        "results": results,
        "artifacts": artifacts,
        "bridge_exit_code": bridge["exit_code"],
        "metadata": {
            "direction": "libcrafter_to_reference",
            "writer": "libcrafter",
            "reader": args.backend,
            "label": label,
            "pcap": str(pcap_path),
            "record_count": len(expected_records),
            "libcrafter_bridge": {
                "argv": bridge["argv"],
                "exit_code": bridge["exit_code"],
            },
        },
    }


def _pcap_read_reference_records(backend: str, pcap_path: Path) -> list[JSONObject]:
    if backend == "scapy":
        from .backends.scapy.pcap import read_pcap

        return read_pcap(pcap_path)
    if backend == "wireshark":
        from .backends.wireshark.pcap import read_pcap

        return read_pcap(pcap_path)
    raise RuntimeError(f"unsupported pcap read backend: {backend}")


def _compare_pcap_records(
    *,
    args: argparse.Namespace,
    direction: str,
    expected: list[JSONObject],
    actual: list[JSONObject],
    plans: list[PacketPlan],
) -> list[ComparisonResult]:
    results: list[ComparisonResult] = []
    shared_count = min(len(expected), len(actual), len(plans))
    for position in range(shared_count):
        plan = replace(plans[position], direction=direction)
        differences: list[JSONObject] = []
        _pcap_diff("raw_hex", expected[position], actual[position], differences)
        _pcap_diff("link_type.name", expected[position], actual[position], differences)
        _pcap_diff("link_type.datalink", expected[position], actual[position], differences)
        _pcap_diff("timestamp", expected[position], actual[position], differences)
        _pcap_diff("layers", expected[position], actual[position], differences)

        passed = not differences
        results.append(
            ComparisonResult(
                passed=passed,
                direction=direction,
                expected=expected[position],
                actual=actual[position],
                plan=plan,
                strict_bytes=plan.strict_bytes,
                byte_equal=_pcap_value(expected[position], "raw_hex")
                == _pcap_value(actual[position], "raw_hex"),
                differences=differences,
                reproduction_command=None
                if passed
                else _pcap_reproduction_command(args, plan.index, direction),
                metadata={
                    "checks": [
                        "packet_count",
                        "link_type",
                        "raw_packet_bytes",
                        "normalized_layers",
                        "timestamp_policy",
                    ],
                    "timestamp_policy": "exact",
                },
            )
        )

    if len(actual) == len(expected) == len(plans):
        return results

    count_difference: JSONObject = {
        "path": "packet_count",
        "expected": len(expected),
        "actual": len(actual),
    }
    for position in range(shared_count, max(len(expected), len(actual), len(plans))):
        plan = replace(plans[min(position, len(plans) - 1)], direction=direction)
        results.append(
            ComparisonResult(
                passed=False,
                direction=direction,
                expected=expected[position] if position < len(expected) else {},
                actual=actual[position] if position < len(actual) else {},
                plan=plan,
                strict_bytes=plan.strict_bytes,
                byte_equal=False,
                differences=[count_difference],
                reproduction_command=_pcap_reproduction_command(args, plan.index, direction),
            )
        )
    return results


def _compare_offline_results(
    *,
    args: argparse.Namespace,
    expected: list[object],
    actual: list[object],
    plans: list[PacketPlan],
    partial_expected: bool = False,
) -> list[ComparisonResult]:
    results: list[ComparisonResult] = []
    shared_count = min(len(expected), len(actual), len(plans))
    for item in range(shared_count):
        plan = plans[item]
        results.append(
            compare_decoded_models(
                expected=expected[item],
                actual=actual[item],
                plan=plan,
                direction=args.direction,
                reproduction_command=_reproduction_command(args, plan.index),
                partial_expected=partial_expected,
                actual_strict_bytes_hex=_strict_bytes_hex(actual[item]),
            )
        )

    if len(actual) == len(expected) == len(plans):
        return results

    for item in range(shared_count, len(plans)):
        plan = plans[item]
        results.append(
            ComparisonResult(
                passed=False,
                direction=args.direction,
                expected=_model_to_object(expected[item]) if item < len(expected) else {},
                actual=_model_to_object(actual[item]) if item < len(actual) else {},
                plan=plan,
                strict_bytes=plan.strict_bytes,
                byte_equal=False,
                differences=[
                    {
                        "path": "decoded_count",
                        "expected": len(expected),
                        "actual": len(actual),
                    }
                ],
                reproduction_command=_reproduction_command(args, plan.index),
            )
        )
    return results


def _with_failure_artifacts(
    *,
    run_dir: Path,
    results: list[ComparisonResult],
    vectors: list[EncodedVector],
    backend_decoded: list[object],
    libcrafter_decoded: list[object],
) -> list[ComparisonResult]:
    """Write exact per-packet reproduction artifacts for failed comparisons."""

    updated: list[ComparisonResult] = []
    for position, result in enumerate(results):
        if result.passed:
            updated.append(result)
            continue

        index = result.plan.index if result.plan is not None else position
        failure_dir = run_dir / "failures" / f"index-{index:06d}"
        failure_dir.mkdir(parents=True, exist_ok=True)

        plan_path = failure_dir / "packet-plan.json"
        raw_path = failure_dir / "raw.hex"
        backend_path = failure_dir / "backend-decoded.json"
        libcrafter_path = failure_dir / "libcrafter-decoded.json"
        diff_path = failure_dir / "comparison-diff.json"

        write_json(plan_path, result.plan if result.plan is not None else {})
        raw_hex = vectors[position].raw_hex if position < len(vectors) else ""
        raw_path.write_text(f"{raw_hex}\n", encoding="utf-8")
        write_json(
            backend_path,
            _model_to_object(backend_decoded[position]) if position < len(backend_decoded) else {},
        )
        write_json(
            libcrafter_path,
            (
                _model_to_object(libcrafter_decoded[position])
                if position < len(libcrafter_decoded)
                else {}
            ),
        )

        artifact_paths = [
            str(plan_path),
            str(raw_path),
            str(backend_path),
            str(libcrafter_path),
            str(diff_path),
        ]
        result_with_artifacts = replace(result, artifacts=artifact_paths)
        write_json(diff_path, result_with_artifacts)
        updated.append(result_with_artifacts)

    return updated


def _comparison_artifact_paths(results: Sequence[ComparisonResult]) -> list[str]:
    paths: list[str] = []
    for result in results:
        paths.extend(result.artifacts)
    return paths


def _selected_specs_for_plans(plans: Sequence[PacketPlan]) -> list[str]:
    selected: list[str] = []
    seen: set[str] = set()
    for spec in GENERATOR_SELECTED_SPECS:
        if spec not in seen:
            selected.append(spec)
            seen.add(spec)

    for plan in plans:
        for spec in _string_values(plan.metadata.get("selected_specs", [])):
            if spec in seen:
                continue
            selected.append(spec)
            seen.add(spec)
    return selected


def _offline_backend_capabilities(args: argparse.Namespace) -> JSONObject:
    capabilities: JSONObject = {}
    try:
        capabilities["reference_backend"] = get_backend(args.backend).to_dict()
    except UnknownBackendError as exc:
        capabilities["reference_backend"] = {"name": args.backend, "error": str(exc)}
    try:
        capabilities["libcrafter"] = get_backend_capability_registration("libcrafter").to_dict()
    except UnknownBackendError as exc:
        capabilities["libcrafter"] = {"name": "libcrafter", "error": str(exc)}
    return capabilities


def _vector_summaries(vectors: Sequence[EncodedVector]) -> list[JSONObject]:
    summaries: list[JSONObject] = []
    for vector in vectors:
        summaries.append(
            {
                "index": vector.plan.index,
                "backend": vector.backend,
                "root": vector.root,
                "decoder": vector.decoder,
                "raw_hex": vector.raw_hex,
                "selected_specs": _string_values(
                    vector.plan.metadata.get("selected_specs", [])
                ),
            }
        )
    return summaries


def _dedupe_paths(paths: Sequence[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        output.append(path)
    return output


def _run_libcrafter_decode_bridge(vector_path: Path, run_dir: Path) -> JSONObject:
    argv = [
        "cargo",
        "run",
        "-q",
        "-p",
        "oracle-adapters",
        "--bin",
        "decode_vectors",
        "--",
        "--input",
        str(vector_path),
    ]
    process = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_path = run_dir / "libcrafter-decode.stdout.json"
    stderr_path = run_dir / "libcrafter-decode.stderr.txt"
    stdout_path.write_text(process.stdout, encoding="utf-8")
    stderr_path.write_text(process.stderr, encoding="utf-8")

    if process.returncode != 0:
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "decoded": [],
                "error": "libcrafter decode bridge failed",
                "exit_code": process.returncode,
            },
        )
        return {
            "argv": argv,
            "exit_code": process.returncode,
            "report": report.to_dict(),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    try:
        report = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "decoded": [],
                "error": f"libcrafter decode bridge emitted invalid JSON: {exc}",
                "exit_code": process.returncode,
            },
        )
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report.to_dict(),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }
    if not isinstance(report, dict):
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "decoded": [],
                "error": "libcrafter decode bridge report must be a JSON object",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    return {
        "argv": argv,
        "exit_code": process.returncode,
        "report": report,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _run_libcrafter_plan_materializer(plan_path: Path, run_dir: Path) -> JSONObject:
    argv = [
        "cargo",
        "run",
        "-q",
        "-p",
        "oracle-adapters",
        "--bin",
        "materialize_plans",
        "--",
        "--input",
        str(plan_path),
    ]
    process = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_path = run_dir / "libcrafter-materialize.stdout.json"
    stderr_path = run_dir / "libcrafter-materialize.stderr.txt"
    stdout_path.write_text(process.stdout, encoding="utf-8")
    stderr_path.write_text(process.stderr, encoding="utf-8")

    if process.returncode != 0:
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "vectors": [],
                "error": "libcrafter plan materializer failed",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": process.returncode,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    try:
        report = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "vectors": [],
                "error": f"libcrafter plan materializer emitted invalid JSON: {exc}",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    if not isinstance(report, dict):
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "vectors": [],
                "error": "libcrafter plan materializer report must be a JSON object",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    return {
        "argv": argv,
        "exit_code": process.returncode,
        "report": report,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _run_libcrafter_vector_emitter(run_dir: Path) -> JSONObject:
    argv = [
        "cargo",
        "run",
        "-q",
        "-p",
        "oracle-adapters",
        "--bin",
        "vectors",
        "--",
        "--json",
    ]
    process = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_path = run_dir / "libcrafter-vectors.stdout.json"
    stderr_path = run_dir / "libcrafter-vectors.stderr.txt"
    stdout_path.write_text(process.stdout, encoding="utf-8")
    stderr_path.write_text(process.stderr, encoding="utf-8")

    if process.returncode != 0:
        raise RuntimeError(
            "libcrafter vector emitter failed with exit "
            f"{process.returncode}; stderr={stderr_path}"
        )

    try:
        manifest = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"libcrafter vector emitter emitted invalid JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise RuntimeError("libcrafter vector emitter manifest must be a JSON object")

    return {
        "argv": argv,
        "exit_code": process.returncode,
        "manifest": manifest,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _run_libcrafter_pcap_reader(pcap_path: Path, run_dir: Path, label: str) -> JSONObject:
    argv = [
        "cargo",
        "run",
        "-q",
        "-p",
        "oracle-adapters",
        "--bin",
        "pcap",
        "--",
        "--read-pcap",
        str(pcap_path),
    ]
    return _run_libcrafter_json_command(argv, run_dir, f"{label}.libcrafter-read")


def _run_libcrafter_pcap_writer(
    *,
    vector_path: Path,
    pcap_path: Path,
    run_dir: Path,
    label: str,
    link_type: str,
) -> JSONObject:
    argv = [
        "cargo",
        "run",
        "-q",
        "-p",
        "oracle-adapters",
        "--bin",
        "pcap",
        "--",
        "--write-pcap",
        str(pcap_path),
        "--input",
        str(vector_path),
        "--link-type",
        link_type,
    ]
    return _run_libcrafter_json_command(argv, run_dir, f"{label}.libcrafter-write")


def _run_libcrafter_json_command(argv: list[str], run_dir: Path, label: str) -> JSONObject:
    process = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_path = run_dir / f"{label}.stdout.json"
    stderr_path = run_dir / f"{label}.stderr.txt"
    stdout_path.write_text(process.stdout, encoding="utf-8")
    stderr_path.write_text(process.stderr, encoding="utf-8")

    if process.returncode != 0:
        report = RunReport(
            mode="pcap",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "records": [],
                "error": "libcrafter pcap bridge failed",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": process.returncode,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    try:
        report = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        report = RunReport(
            mode="pcap",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "records": [],
                "error": f"libcrafter pcap bridge emitted invalid JSON: {exc}",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    if not isinstance(report, dict):
        report = RunReport(
            mode="pcap",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "records": [],
                "error": "libcrafter pcap bridge report must be a JSON object",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    return {
        "argv": argv,
        "exit_code": process.returncode,
        "report": report,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _decoded_models(report: object) -> list[JSONObject]:
    report_object = _json_object(report, "libcrafter report")
    metadata = _json_object(report_object.get("metadata", {}), "libcrafter report metadata")
    decoded = metadata.get("decoded")
    if not isinstance(decoded, list):
        raise RuntimeError("libcrafter report metadata.decoded must be a list")

    output: list[JSONObject] = []
    for index, item in enumerate(decoded):
        output.append(_json_object(item, f"decoded[{index}]"))
    return output


def _encoded_vectors(report: object) -> list[EncodedVector]:
    report_object = _json_object(report, "libcrafter materializer report")
    metadata = _json_object(
        report_object.get("metadata", {}),
        "libcrafter materializer report metadata",
    )
    vectors = metadata.get("vectors")
    if not isinstance(vectors, list):
        raise RuntimeError("libcrafter materializer report metadata.vectors must be a list")

    output: list[EncodedVector] = []
    for index, item in enumerate(vectors):
        vector = _json_object(item, f"vectors[{index}]")
        raw_hex = _optional_string(vector.get("raw_hex")) or _optional_string(vector.get("hex"))
        if raw_hex is None:
            raise RuntimeError(f"libcrafter materialized vector {index} is missing raw_hex")
        plan = _packet_plan_from_object(vector.get("plan"), f"vectors[{index}].plan")
        root = _optional_string(vector.get("root")) or _optional_string(vector.get("decoder"))
        if root is None:
            raise RuntimeError(f"libcrafter materialized vector {index} is missing root")
        output.append(
            EncodedVector(
                plan=plan,
                backend=_optional_string(vector.get("backend")) or "libcrafter",
                raw_hex=raw_hex,
                root=root,
                decoder=_optional_string(vector.get("decoder")) or root,
                metadata=_json_object(vector.get("metadata", {}), f"vectors[{index}].metadata"),
            )
        )
    return output


def _packet_plan_from_object(value: object, name: str) -> PacketPlan:
    plan = _json_object(value, name)
    fields_object = _json_object(plan.get("fields", {}), f"{name}.fields")
    fields = {
        layer: _json_object(layer_fields, f"{name}.fields.{layer}")
        for layer, layer_fields in fields_object.items()
    }
    return PacketPlan(
        stack=_string_values(plan.get("stack", [])),
        fields=fields,
        profile=_optional_string(plan.get("profile")) or "unknown",
        seed=_object_int(plan.get("seed"), 0),
        index=_object_int(plan.get("index"), 0),
        direction=_optional_string(plan.get("direction")) or "libcrafter_to_reference",
        family=_optional_string(plan.get("family")),
        feature_tags=_string_values(plan.get("feature_tags", [])),
        case=_optional_string(plan.get("case")),
        strict_bytes=plan.get("strict_bytes") is not False,
        metadata=_json_object(plan.get("metadata", {}), f"{name}.metadata"),
    )


def _object_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return default


def _pcap_records(report: object) -> list[JSONObject]:
    report_object = _json_object(report, "pcap report")
    metadata = _json_object(report_object.get("metadata", {}), "pcap report metadata")
    records = metadata.get("records")
    if not isinstance(records, list):
        raise RuntimeError("pcap report metadata.records must be a list")

    output: list[JSONObject] = []
    for index, item in enumerate(records):
        output.append(_json_object(item, f"records[{index}]"))
    return output


def _select_libcrafter_cases(
    manifest: object,
    args: argparse.Namespace,
) -> list[tuple[int, JSONObject]]:
    manifest_object = _json_object(manifest, "libcrafter vector manifest")
    cases = manifest_object.get("cases")
    if not isinstance(cases, list):
        raise RuntimeError("libcrafter vector manifest cases must be a list")

    entries: list[tuple[int, JSONObject]] = []
    for index, case in enumerate(cases):
        case_object = _json_object(case, f"cases[{index}]")
        if not _case_supports_direction(case_object, args.direction):
            continue
        entries.append((index, case_object))

    if args.case_name is not None:
        entries = [
            (index, case)
            for index, case in entries
            if case.get("name") == args.case_name
        ]
    if args.family is not None:
        entries = [
            (index, case)
            for index, case in entries
            if case.get("family") == args.family
        ]
    if args.feature is not None:
        entries = [
            (index, case)
            for index, case in entries
            if args.feature in _string_values(case.get("features", []))
            or args.feature in _string_values(case.get("feature_tags", []))
        ]
    if args.index is not None:
        entries = [
            (index, case)
            for index, case in entries
            if index == args.index
        ]
    else:
        entries = entries[: args.count]

    if not entries:
        raise RuntimeError("no libcrafter oracle vector cases selected")
    return entries


def _case_supports_direction(case: JSONObject, direction: str) -> bool:
    directions = case.get("directions")
    if isinstance(directions, list) and direction in directions:
        return True
    return case.get("direction") == direction


def _libcrafter_case_plan(
    case: JSONObject,
    args: argparse.Namespace,
    index: int,
) -> PacketPlan:
    expected = _json_object(case.get("expected_decoded", {}), f"case[{index}].expected_decoded")
    stack = _string_values(expected.get("layers", []))
    fields = _json_object(expected.get("fields", {}), f"case[{index}].expected_decoded.fields")
    name = _optional_string(case.get("name"))
    family = _optional_string(case.get("family"))
    strict_bytes = case.get("strict_bytes")
    return PacketPlan(
        stack=stack,
        fields=fields,
        profile=args.profile,
        seed=args.seed,
        index=index,
        direction=args.direction,
        family=family,
        feature_tags=_string_values(case.get("feature_tags", [])),
        case=name,
        strict_bytes=strict_bytes is not False,
        metadata={
            "plan_id": f"libcrafter:{index}",
            "case": name,
            "generator": "cargo run -q -p oracle-adapters --bin vectors -- --json",
            "source": "libcrafter oracle vector emitter",
        },
    )


def _libcrafter_case_vector(case: JSONObject, plan: PacketPlan) -> EncodedVector:
    raw_hex = _optional_string(case.get("raw_hex")) or _optional_string(case.get("hex"))
    if raw_hex is None:
        raise RuntimeError(f"libcrafter case {plan.index} is missing raw_hex")
    root = _optional_string(case.get("root_decoder")) or _optional_string(case.get("root"))
    if root is None:
        raise RuntimeError(f"libcrafter case {plan.index} is missing root/root_decoder")
    return EncodedVector(
        plan=plan,
        backend="libcrafter",
        raw_hex=raw_hex,
        root=root,
        decoder=root,
        metadata={
            "case": plan.case,
            "length": len(bytes.fromhex(raw_hex)),
            "strict_bytes": plan.strict_bytes,
            "summary": case.get("summary"),
        },
    )


def _strict_bytes_hex(model: object) -> str | None:
    model_object = model.to_dict() if isinstance(model, DecodedModel) else model
    if not isinstance(model_object, dict):
        return None
    metadata = model_object.get("metadata")
    if not isinstance(metadata, dict):
        return None
    value = metadata.get("reencoded_hex")
    if isinstance(value, str):
        return value
    error = metadata.get("reencoded_error")
    if isinstance(error, str):
        return f"<scapy re-encode failed: {error}>"
    return None


def _model_to_object(model: object) -> JSONObject:
    value = model.to_dict() if hasattr(model, "to_dict") else model
    return _json_object(value, "oracle model")


def _backend_versions(backend: str) -> JSONObject:
    try:
        return {
            backend: backend_report_metadata(
                backend,
                include_dependency_metadata=True,
            )
        }
    except UnknownBackendError:
        return {}


def _libcrafter_info() -> JSONObject:
    info: JSONObject = {}
    version = _workspace_package_version()
    if version is not None:
        info["version"] = version
    commit = _git_head_commit()
    if commit is not None:
        info["commit"] = commit
    return info


def _workspace_package_version() -> str | None:
    try:
        document = tomllib.loads((REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None

    workspace = document.get("workspace")
    if not isinstance(workspace, dict):
        return None
    package = workspace.get("package")
    if not isinstance(package, dict):
        return None
    version = package.get("version")
    return version if isinstance(version, str) else None


def _git_head_commit() -> str | None:
    git_dir = REPO_ROOT / ".git"
    try:
        if git_dir.is_file():
            content = git_dir.read_text(encoding="utf-8").strip()
            if not content.startswith("gitdir:"):
                return None
            raw_path = Path(content.split(":", 1)[1].strip())
            git_dir = raw_path if raw_path.is_absolute() else (REPO_ROOT / raw_path).resolve()

        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if not head:
            return None
        if not head.startswith("ref:"):
            return head

        ref_name = head.removeprefix("ref:").strip()
        common_dir = _git_common_dir(git_dir)
        ref_path = git_dir / ref_name
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8").strip() or None
        ref_path = common_dir / ref_name
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8").strip() or None

        for packed_refs in (git_dir / "packed-refs", common_dir / "packed-refs"):
            if not packed_refs.exists():
                continue
            for line in packed_refs.read_text(encoding="utf-8").splitlines():
                if not line or line.startswith(("#", "^")):
                    continue
                commit, _, packed_ref = line.partition(" ")
                if packed_ref == ref_name:
                    return commit
    except OSError:
        return None
    return None


def _git_common_dir(git_dir: Path) -> Path:
    common_dir_file = git_dir / "commondir"
    if not common_dir_file.exists():
        return git_dir
    try:
        raw_path = Path(common_dir_file.read_text(encoding="utf-8").strip())
    except OSError:
        return git_dir
    return raw_path if raw_path.is_absolute() else (git_dir / raw_path).resolve()


def _offline_output_dir(out: str) -> Path:
    output_root = Path(out)
    if not output_root.is_absolute():
        output_root = REPO_ROOT / output_root
    if output_root.resolve() != (REPO_ROOT / DEFAULT_OUTPUT_ROOT).resolve():
        return output_root
    return output_root / "offline"


def _offline_report_output_dir(args: argparse.Namespace) -> Path:
    output_root = Path(args.out)
    if not output_root.is_absolute():
        output_root = REPO_ROOT / output_root
    if getattr(args, "corpus", None) is not None:
        return output_root / "offline"
    return _offline_output_dir(args.out)


def _pcap_output_dir(out: str) -> Path:
    output_root = Path(out)
    if not output_root.is_absolute():
        output_root = REPO_ROOT / output_root
    return output_root / "pcap"


def _live_output_dir(out: str) -> Path:
    output_root = Path(out)
    if not output_root.is_absolute():
        output_root = REPO_ROOT / output_root
    if output_root.name == "live":
        return output_root
    return output_root / "live"


def _reproduction_command(args: argparse.Namespace, index: int) -> str:
    if getattr(args, "corpus", None) is not None:
        return shlex.join(
            [
                "tools/oracle/run",
                "offline",
                "--backend",
                args.backend,
                "--direction",
                args.direction,
                "--corpus",
                args.corpus,
                "--index",
                str(index),
            ]
        )

    argv = [
        "tools/oracle/run",
        "offline",
        "--backend",
        args.backend,
        "--direction",
        args.direction,
        "--profile",
        args.profile,
        "--seed",
        str(args.seed),
        "--count",
        "1",
        "--index",
        str(index),
    ]
    if args.case_name is not None:
        argv.extend(["--case", args.case_name])
    if args.feature is not None:
        argv.extend(["--feature", args.feature])
    if args.family is not None:
        argv.extend(["--family", args.family])
    if args.root is not None:
        argv.extend(["--root", args.root])
    return shlex.join(argv)


def _live_reproduction_command(args: argparse.Namespace) -> str:
    argv = [
        "tools/oracle/run",
        "live",
        "--backend",
        args.backend,
        "--provider",
        args.provider,
        "--direction",
        args.direction,
    ]
    if getattr(args, "corpus", None) is not None:
        argv.extend(["--corpus", args.corpus])
    argv.extend(
        [
            "--profile",
            args.profile,
            "--seed",
            str(args.seed),
            "--count",
            str(args.count),
        ]
    )
    if args.index is not None:
        argv.extend(["--index", str(args.index)])
    if args.case_name is not None:
        argv.extend(["--case", args.case_name])
    if args.feature is not None:
        argv.extend(["--feature", args.feature])
    if args.family is not None:
        argv.extend(["--family", args.family])
    if args.root is not None:
        argv.extend(["--root", args.root])
    if getattr(args, "dry_run", False):
        argv.append("--dry-run")
    if getattr(args, "confirm_live_run", False):
        argv.append("--confirm-live-run")
    if getattr(args, "keep_wire_endpoints", False):
        argv.append("--keep-wire-endpoints")
    return shlex.join(argv)


def _pcap_reproduction_command(args: argparse.Namespace, index: int, direction: str) -> str:
    if getattr(args, "corpus", None) is not None:
        argv = [
            "tools/oracle/run",
            "pcap",
            "--backend",
            args.backend,
            "--direction",
            direction,
            "--corpus",
            args.corpus,
            "--index",
            str(index),
        ]
        if args.case_name is not None:
            argv.extend(["--case", args.case_name])
        if args.feature is not None:
            argv.extend(["--feature", args.feature])
        if args.family is not None:
            argv.extend(["--family", args.family])
        if args.root is not None:
            argv.extend(["--root", args.root])
        return shlex.join(argv)

    argv = [
        "tools/oracle/run",
        "pcap",
        "--backend",
        args.backend,
        "--direction",
        direction,
        "--profile",
        args.profile,
        "--seed",
        str(args.seed),
        "--count",
        "1",
        "--index",
        str(index),
    ]
    if args.case_name is not None:
        argv.extend(["--case", args.case_name])
    if args.feature is not None:
        argv.extend(["--feature", args.feature])
    if args.family is not None:
        argv.extend(["--family", args.family])
    if args.root is not None:
        argv.extend(["--root", args.root])
    return shlex.join(argv)


def _pcap_diff(
    path: str,
    expected: JSONObject,
    actual: JSONObject,
    differences: list[JSONObject],
) -> None:
    expected_value = _pcap_value(expected, path)
    actual_value = _pcap_value(actual, path)
    if expected_value != actual_value:
        differences.append(
            {
                "path": path,
                "expected": expected_value,
                "actual": actual_value,
            }
        )


def _pcap_value(record: JSONObject, path: str) -> object:
    value: object = record
    for part in path.split("."):
        if not isinstance(value, dict):
            return "<missing>"
        value = value.get(part, "<missing>")
    return value


def _json_object(value: object, name: str) -> JSONObject:
    if not isinstance(value, dict):
        raise RuntimeError(f"{name} must be a JSON object")
    output: JSONObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise RuntimeError(f"{name} keys must be strings")
        output[key] = item  # type: ignore[assignment]
    return output


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _pcap_execution_directions(direction: str) -> list[str]:
    if direction == "roundtrip":
        return ["reference_to_libcrafter", "libcrafter_to_reference"]
    if direction in {"reference_to_libcrafter", "libcrafter_to_reference"}:
        return [direction]
    raise ValueError(f"unsupported pcap direction: {direction}")


def _pcap_cases_for_direction(
    *,
    args: argparse.Namespace,
    direction: str,
    dry_plan: bool,
) -> list[JSONObject]:
    # `--case` carries a packet-generation case (e.g. dhcp-discover) that selects
    # which packets the corpus generator emits. It is a different namespace from
    # the pcap contract case names declared in features/pcap.yaml (e.g.
    # raw-link-type, scapy-writes-pcap-libcrafter-reads). Only filter the pcap
    # contract cases by name when `--case` actually names a contract case; a
    # packet-generation case has already been applied during corpus generation,
    # so it must not eliminate every link-type contract here.
    contract_case_name = (
        args.case_name if _pcap_case_name_is_contract(args.case_name) else None
    )
    all_cases = [
        pcap_case
        for pcap_case in _pcap_spec_cases()
        if _pcap_case_supports_direction(pcap_case, direction)
        and _pcap_case_matches_filter(pcap_case, contract_case_name, args.feature)
    ]
    if dry_plan:
        selected = all_cases
    else:
        selected = [
            pcap_case
            for pcap_case in all_cases
            if _pcap_case_roles_match(pcap_case, direction, args.backend)
        ]
        if (
            not selected
            and contract_case_name is None
            and (direction == "libcrafter_to_reference" or args.feature == "pcap_link_types")
        ):
            selected = [
                _pcap_case_with_roles(pcap_case, direction, args.backend)
                for pcap_case in all_cases
                if pcap_case.get("writer") is None
                and pcap_case.get("reader") is None
                and _pcap_case_has_link_or_format(pcap_case)
                and _pcap_file_format_for_case(pcap_case) == "pcap"
            ]
        if not selected and contract_case_name is not None:
            selected = [
                _pcap_case_with_roles(pcap_case, direction, args.backend)
                for pcap_case in all_cases
                if _pcap_case_has_link_or_format(pcap_case)
            ]

    if not selected:
        detail = f" direction={direction!r}"
        if args.case_name is not None:
            detail += f" case={args.case_name!r}"
        if args.feature is not None:
            detail += f" feature={args.feature!r}"
        raise ValueError(f"no pcap spec cases match{detail}")

    return [dict(pcap_case) for pcap_case in selected]


def _pcap_case_name_is_contract(case_name: str | None) -> bool:
    if case_name is None:
        return False
    return any(pcap_case.get("name") == case_name for pcap_case in _pcap_spec_cases())


def _pcap_spec_cases() -> list[JSONObject]:
    from .spec_loader import load_oracle_specs

    specs = load_oracle_specs()
    feature = specs.features.get("pcap_contracts")
    if feature is None:
        raise ValueError("pcap feature spec is missing: pcap_contracts")
    raw_cases = feature.raw.get("supported_cases", [])
    if not isinstance(raw_cases, list):
        raise ValueError("features/pcap.yaml supported_cases must be a list")
    cases: list[JSONObject] = []
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict):
            raise ValueError("features/pcap.yaml supported_cases entries must be objects")
        pcap_case = dict(raw_case)
        pcap_case.setdefault("strict_bytes", feature.strict_bytes)
        pcap_case.setdefault("timestamp_policy", "exact")
        pcap_case["feature"] = feature.name
        cases.append(pcap_case)  # type: ignore[arg-type]
    return cases


def _pcap_corpus_plan_groups(
    args: argparse.Namespace,
    directions: Sequence[str],
    *,
    materialize: bool,
) -> tuple[dict[str, list[JSONObject]], list[str], JSONObject]:
    from .corpus import CorpusFormatError, load_corpus_report

    corpus_path: Path | None = None
    corpus_source = "generated"
    if getattr(args, "corpus", None) is None:
        corpus_direction = directions[0] if directions else "reference_to_libcrafter"
        corpus_report = _build_corpus_report_from_generation(
            args,
            direction=corpus_direction,
        )
    else:
        corpus_source = "provided"
        corpus_path = Path(args.corpus)
        if not corpus_path.is_absolute():
            corpus_path = REPO_ROOT / corpus_path
        corpus_report = load_corpus_report(corpus_path)
        if corpus_report.backend != args.backend:
            raise CorpusFormatError(
                f"{corpus_path}: backend {corpus_report.backend!r} does not match "
                f"requested backend {args.backend!r}"
            )

    packets = list(corpus_report.packets)
    if args.index is not None:
        packets = [packet for packet in packets if packet.plan.index == args.index]

    cases_by_direction: dict[str, list[JSONObject]] = {}
    case_filter_reasons: dict[str, str] = {}
    for direction in directions:
        try:
            cases_by_direction[direction] = _pcap_cases_for_direction(
                args=args,
                direction=direction,
                dry_plan=False,
            )
        except ValueError as exc:
            if not str(exc).startswith("no pcap spec cases match"):
                raise
            cases_by_direction[direction] = []
            case_filter_reasons[direction] = str(exc)

    requested_link_type = (
        _pcap_link_type_for_root(args.root) if args.root is not None else None
    )

    encode_packet_plan = None
    with_pcap_metadata = None
    if materialize:
        from .backends.scapy.packets import encode_packet_plan as scapy_encode_packet_plan
        from .backends.scapy.pcap import with_pcap_metadata as scapy_with_pcap_metadata

        encode_packet_plan = scapy_encode_packet_plan
        with_pcap_metadata = scapy_with_pcap_metadata

    groups_by_direction: dict[str, list[JSONObject]] = {direction: [] for direction in directions}
    group_maps: dict[str, dict[tuple[str, str], JSONObject]] = {
        direction: {} for direction in directions
    }
    selected_plans: list[PacketPlan] = []
    eligibility: list[JSONObject] = []
    skip_reasons: dict[str, int] = {}
    eligible_positions: set[int] = set()
    eligible_packet_indexes: list[int] = []

    for position, packet in enumerate(packets):
        root = _pcap_packet_root(packet.plan)
        packet_link_type: str | None = None
        root_reason: str | None = None
        if root is None:
            root_reason = "pcap_link_type_unavailable"
        else:
            try:
                packet_link_type = _pcap_link_type_for_root(root)
            except ValueError:
                root_reason = "pcap_link_type_unavailable"
        if (
            requested_link_type is not None
            and packet_link_type is not None
            and packet_link_type != requested_link_type
        ):
            root_reason = "pcap_link_type_unavailable"

        direction_decisions: list[JSONObject] = []
        packet_eligible = False
        corpus_skip_reason = None
        if packet.pcap.eligible is False:
            corpus_skip_reason = _pcap_normalized_skip_reason(packet.pcap.reason)

        for direction in directions:
            decision: JSONObject = {
                "direction": direction,
                "eligible": False,
                "reason": None,
                "root": root,
                "pcap_link_type": packet_link_type,
            }
            if corpus_skip_reason is not None:
                decision["reason"] = corpus_skip_reason
                direction_decisions.append(decision)
                continue
            if root_reason is not None or packet_link_type is None:
                decision["reason"] = root_reason or "pcap_link_type_unavailable"
                direction_decisions.append(decision)
                continue

            pcap_case_selection = _select_pcap_case_for_packet(
                cases_by_direction[direction],
                packet_link_type,
            )
            if pcap_case_selection is None:
                decision["reason"] = _pcap_unavailable_reason_for_cases(
                    cases_by_direction[direction],
                    packet_link_type,
                    case_filter_empty=direction in case_filter_reasons,
                )
                direction_decisions.append(decision)
                continue

            pcap_case, file_format = pcap_case_selection
            plan = _pcap_plan(
                _pcap_corpus_packet_plan(
                    packet.plan,
                    corpus_id=corpus_report.corpus_id,
                    packet_id=packet.packet_id,
                    corpus_index=packet.index,
                    direction=direction,
                ),
                pcap_case,
                direction,
                link_type=packet_link_type,
                file_format=file_format,
            )
            group_link_type = _pcap_record_link_type_for_plan(packet_link_type)
            vector = None
            if materialize:
                if encode_packet_plan is None or with_pcap_metadata is None:
                    raise RuntimeError("pcap corpus materialization is not initialized")
                vector = encode_packet_plan(plan)
                vector = with_pcap_metadata(
                    [vector],
                    link_type=_pcap_writer_link_type(packet_link_type),
                )[0]
                group_link_type = _pcap_vector_link_type(vector)

            key = (file_format, group_link_type)
            group = group_maps[direction].setdefault(
                key,
                {
                    "file_format": file_format,
                    "link_type": group_link_type,
                    "pcap_case": pcap_case,
                    "plans": [],
                    "vectors": [],
                },
            )
            group["plans"].append(plan)  # type: ignore[union-attr]
            if vector is not None:
                group["vectors"].append(vector)  # type: ignore[union-attr]
            decision.update(
                {
                    "eligible": True,
                    "reason": None,
                    "pcap_case": pcap_case.get("name"),
                    "pcap_file_format": file_format,
                    "pcap_record_link_type": group_link_type,
                }
            )
            direction_decisions.append(decision)
            packet_eligible = True
            selected_plans.append(plan)

        if packet_eligible:
            eligible_positions.add(position)
            eligible_packet_indexes.append(packet.plan.index)
        else:
            reason = _pcap_packet_skip_reason(direction_decisions)
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1

        eligibility.append(
            {
                "position": position,
                "packet_id": packet.packet_id,
                "corpus_index": packet.index,
                "packet_index": packet.plan.index,
                "eligible": packet_eligible,
                "reason": None
                if packet_eligible
                else _pcap_packet_skip_reason(direction_decisions),
                "directions": direction_decisions,
            }
        )

    for direction in directions:
        groups_by_direction[direction] = list(group_maps[direction].values())

    selected_specs = list(
        dict.fromkeys(
            [
                *corpus_report.selected_specs,
                *PCAP_SELECTED_SPECS,
                *_selected_specs_for_plans(selected_plans),
            ]
        )
    )
    metadata: JSONObject = {
        "corpus_id": corpus_report.corpus_id,
        "corpus_source": corpus_source,
        "corpus_path": str(corpus_path) if corpus_path is not None else None,
        "corpus_backend": corpus_report.backend,
        "corpus_profile": corpus_report.profile,
        "corpus_seed": corpus_report.seed,
        "corpus_count": corpus_report.count,
        "generated_count": len(packets),
        "pcap_eligible_count": len(eligible_positions),
        "pcap_skipped_count": len(packets) - len(eligible_positions),
        "pcap_skip_reasons": skip_reasons,
        "packet_indexes": list(dict.fromkeys(eligible_packet_indexes)),
        "pcap_eligibility": eligibility,
    }
    return groups_by_direction, selected_specs, metadata


def _pcap_packet_root(plan: PacketPlan) -> str | None:
    root = plan.metadata.get("root_decoder", plan.metadata.get("root"))
    return root if isinstance(root, str) and root else None


def _pcap_corpus_packet_plan(
    plan: PacketPlan,
    *,
    corpus_id: str,
    packet_id: str,
    corpus_index: int,
    direction: str,
) -> PacketPlan:
    metadata = dict(plan.metadata)
    metadata["corpus"] = {
        "corpus_id": corpus_id,
        "packet_id": packet_id,
        "corpus_index": corpus_index,
        "packet_index": plan.index,
        "packet_case": plan.case,
    }
    return replace(plan, direction=direction, metadata=metadata)


def _select_pcap_case_for_packet(
    pcap_cases: Sequence[JSONObject],
    link_type: str,
) -> tuple[JSONObject, str] | None:
    for pcap_case in pcap_cases:
        file_format = _pcap_file_format_for_case(pcap_case)
        if file_format != "pcap":
            continue
        if link_type not in _pcap_link_types_for_case(pcap_case):
            continue
        return pcap_case, file_format
    return None


def _pcap_unavailable_reason_for_cases(
    pcap_cases: Sequence[JSONObject],
    link_type: str,
    *,
    case_filter_empty: bool,
) -> str:
    if case_filter_empty:
        return "pcap_case_filter"
    for pcap_case in pcap_cases:
        if link_type not in _pcap_link_types_for_case(pcap_case):
            continue
        if _pcap_file_format_for_case(pcap_case) != "pcap":
            return "pcap_case_filter"
    return "pcap_link_type_unavailable"


def _pcap_record_link_type_for_plan(link_type: str) -> str:
    if link_type == "linux_cooked":
        return "linux_sll"
    return link_type


_PCAP_PASSTHROUGH_SKIP_REASONS = {
    "pcap_link_type_unavailable",
    "pcap_case_filter",
    # Corpus-declared byte-policy skips (a normalized-only or structured-error
    # case is not safely representable through pcap). Preserve the explicit
    # reason instead of collapsing it so the report records why each case was
    # skipped rather than silently dropping it.
    "pcap_normalized_only",
    "pcap_structured_error",
}


def _pcap_normalized_skip_reason(reason: str | None) -> str:
    if reason in _PCAP_PASSTHROUGH_SKIP_REASONS:
        return reason
    return "pcap_case_filter"


def _pcap_packet_skip_reason(direction_decisions: Sequence[JSONObject]) -> str:
    reasons = [
        decision.get("reason")
        for decision in direction_decisions
        if isinstance(decision.get("reason"), str)
    ]
    if "pcap_link_type_unavailable" in reasons:
        return "pcap_link_type_unavailable"
    for reason in ("pcap_normalized_only", "pcap_structured_error"):
        if reason in reasons:
            return reason
    if "pcap_case_filter" in reasons:
        return "pcap_case_filter"
    return "pcap_case_filter"


def _pcap_group_summaries(groups_by_direction: Mapping[str, list[JSONObject]]) -> list[JSONObject]:
    summaries: list[JSONObject] = []
    for direction, groups in groups_by_direction.items():
        group_summaries: list[JSONObject] = []
        for group in groups:
            plans = group.get("plans")
            plan_list = (
                [plan for plan in plans if isinstance(plan, PacketPlan)]
                if isinstance(plans, list)
                else []
            )
            group_summaries.append(
                {
                    "file_format": group.get("file_format"),
                    "link_type": group.get("link_type"),
                    "pcap_case": group.get("pcap_case"),
                    "count": len(plan_list),
                    "packet_indexes": [plan.index for plan in plan_list],
                }
            )
        summaries.append(
            {
                "direction": direction,
                "groups": group_summaries,
            }
        )
    return summaries


def _pcap_vector_groups(args: argparse.Namespace, direction: str) -> list[JSONObject]:
    from .backends.scapy.packets import encode_packet_plan
    from .backends.scapy.pcap import with_pcap_metadata
    from .generator import PacketGenerator

    cases = _pcap_cases_for_direction(args=args, direction=direction, dry_plan=False)
    generator = PacketGenerator(seed=args.seed, profile=args.profile, backend=args.backend)
    groups: dict[tuple[str, str], JSONObject] = {}
    for offset, index in enumerate(_pcap_indices(args)):
        pcap_case = cases[offset % len(cases)]
        file_format = _pcap_file_format_for_case(pcap_case)
        if file_format != "pcap":
            raise PcapUnsupportedError(
                f"unsupported pcap file format: {file_format} from case "
                f"{pcap_case.get('name')}; libcrafter pcap mode supports classic pcap only"
            )
        link_types = _pcap_link_types_for_case(pcap_case)
        link_type = link_types[offset % len(link_types)]
        root = _pcap_generation_root(args.root, link_type, index)
        plan = generator.generate(
            index=index,
            root=root,
            family=args.family,
            case=_pcap_generator_case(link_type, root),
            direction=direction,
        )
        plan = _pcap_plan(
            plan,
            pcap_case,
            direction,
            link_type=link_type,
            file_format=file_format,
        )
        vector = encode_packet_plan(plan)
        vector = with_pcap_metadata(
            [vector],
            link_type=_pcap_writer_link_type(link_type),
        )[0]
        record_link_type = _pcap_vector_link_type(vector)
        key = (file_format, record_link_type)
        group = groups.setdefault(
            key,
            {
                "file_format": file_format,
                "link_type": record_link_type,
                "pcap_case": pcap_case,
                "plans": [],
                "vectors": [],
            },
        )
        group["plans"].append(plan)  # type: ignore[union-attr]
        group["vectors"].append(vector)  # type: ignore[union-attr]
    return list(groups.values())


def _pcap_plan(
    plan: PacketPlan,
    pcap_case: JSONObject,
    direction: str,
    *,
    link_type: str,
    file_format: str,
) -> PacketPlan:
    strict_bytes = pcap_case.get("strict_bytes")
    metadata = dict(plan.metadata)
    metadata["pcap"] = pcap_case
    metadata["selected_spec"] = PCAP_CONTRACT_SPEC
    metadata["timestamp_policy"] = pcap_case.get("timestamp_policy")
    metadata["pcap_file_format"] = file_format
    metadata["pcap_link_type"] = link_type
    selected_specs = _string_values(metadata.get("selected_specs", []))
    for spec in PCAP_SELECTED_SPECS:
        if spec not in selected_specs:
            selected_specs.append(spec)
    metadata["selected_specs"] = selected_specs
    feature_tags = list(dict.fromkeys([*plan.feature_tags, "pcap"]))
    case_name = pcap_case.get("name")
    return replace(
        plan,
        direction=direction,
        case=case_name if isinstance(case_name, str) else plan.case,
        strict_bytes=strict_bytes if isinstance(strict_bytes, bool) else plan.strict_bytes,
        feature_tags=feature_tags,
        metadata=metadata,
    )


def _pcap_indices(args: argparse.Namespace) -> list[int]:
    if args.index is not None:
        return [args.index]
    return list(range(args.count))


def _pcap_case_supports_direction(pcap_case: JSONObject, direction: str) -> bool:
    directions = _pcap_case_directions(pcap_case)
    return direction in directions or "roundtrip" in directions


def _pcap_case_directions(pcap_case: JSONObject) -> list[str]:
    directions = _string_values(pcap_case.get("directions"))
    direction = pcap_case.get("direction")
    if isinstance(direction, str):
        directions.append(direction)
    return list(dict.fromkeys(directions))


def _pcap_case_matches_filter(
    pcap_case: JSONObject,
    case_name: str | None,
    feature: str | None,
) -> bool:
    if case_name is not None and pcap_case.get("name") != case_name:
        return False
    if feature is None:
        return True
    if feature in {"pcap", "pcap_contracts"}:
        return True
    if feature == "pcap_link_types":
        return pcap_case.get("writer") is None and pcap_case.get("reader") is None
    return False


def _pcap_case_roles_match(
    pcap_case: JSONObject,
    direction: str,
    backend: str,
) -> bool:
    writer = pcap_case.get("writer")
    reader = pcap_case.get("reader")
    if direction == "reference_to_libcrafter":
        return writer == backend and reader == "libcrafter"
    if direction == "libcrafter_to_reference":
        return writer == "libcrafter" and reader == backend
    return False


def _pcap_case_with_roles(
    pcap_case: JSONObject,
    direction: str,
    backend: str,
) -> JSONObject:
    output = dict(pcap_case)
    if direction == "reference_to_libcrafter":
        output["writer"] = backend
        output["reader"] = "libcrafter"
    elif direction == "libcrafter_to_reference":
        output["writer"] = "libcrafter"
        output["reader"] = backend
    return output


def _pcap_case_has_link_or_format(pcap_case: JSONObject) -> bool:
    return any(
        key in pcap_case
        for key in ("file_format", "file_formats", "link_type", "link_types", "roots")
    )


def _pcap_file_format_for_case(pcap_case: JSONObject) -> str:
    file_formats = _string_values(pcap_case.get("file_formats"))
    file_format = pcap_case.get("file_format")
    if isinstance(file_format, str):
        file_formats.insert(0, file_format)
    file_formats = list(dict.fromkeys(file_formats))
    if not file_formats:
        return "pcap"
    if "pcap" in file_formats:
        return "pcap"
    return file_formats[0]


def _pcap_link_types_for_case(pcap_case: JSONObject) -> list[str]:
    link_types = [_pcap_canonical_link_type(item) for item in _string_values(pcap_case.get("link_types"))]
    link_type = pcap_case.get("link_type")
    if isinstance(link_type, str):
        link_types.insert(0, _pcap_canonical_link_type(link_type))
    roots = _string_values(pcap_case.get("roots"))
    for root in roots:
        link_types.append(_pcap_link_type_for_root(root))
    link_types = list(dict.fromkeys(link_types))
    if link_types:
        return link_types
    return ["ethernet"]


def _pcap_generation_root(requested_root: str | None, link_type: str, index: int) -> str:
    if requested_root is not None:
        requested_link_type = _pcap_link_type_for_root(requested_root)
        if requested_link_type != link_type:
            raise ValueError(
                f"root {requested_root!r} is incompatible with pcap link type {link_type!r}"
            )
        return requested_root
    if link_type == "ethernet":
        return "link:ethernet"
    if link_type == "linux_cooked":
        return "link:linux-cooked"
    if link_type == "null_loopback":
        return "link:null-loopback"
    if link_type == "raw":
        return "l3:ipv6" if index % 2 else "l3:ipv4"
    raise ValueError(f"unsupported pcap link type: {link_type}")


def _pcap_generator_case(link_type: str, root: str) -> str:
    if link_type == "ethernet":
        return "arp-request"
    if link_type == "linux_cooked":
        return "linux-cooked-ipv4-udp"
    if link_type == "null_loopback":
        return "null-loopback-ipv4-little-endian"
    if link_type == "raw" and root == "link:raw":
        return "raw-payload-link"
    if link_type == "raw" and root == "l3:ipv6":
        return "udp-ipv6-checksum-length"
    if link_type == "raw":
        return "ipv4-udp"
    raise ValueError(f"unsupported pcap link type: {link_type}")


def _pcap_link_type_for_root(root: str) -> str:
    normalized = root.replace("_", "-")
    if normalized in {"link:ethernet", "ether"}:
        return "ethernet"
    if normalized in {"link:linux-cooked", "link:linux-sll", "cookedlinux"}:
        return "linux_cooked"
    if normalized in {"link:null-loopback", "loopback"}:
        return "null_loopback"
    if normalized in {"link:raw", "l3:ipv4", "l3:ipv6", "ip", "ipv6", "raw"}:
        return "raw"
    raise ValueError(f"unsupported pcap root for link type selection: {root}")


def _pcap_canonical_link_type(link_type: str) -> str:
    normalized = link_type.replace("-", "_")
    if normalized in {"linux_sll", "linux_cooked"}:
        return "linux_cooked"
    if normalized in {"ether", "ethernet"}:
        return "ethernet"
    if normalized in {"null", "null_loopback", "loopback"}:
        return "null_loopback"
    if normalized in {"raw", "raw_ip"}:
        return "raw"
    raise ValueError(f"unsupported pcap link type: {link_type}")


def _pcap_writer_link_type(link_type: str) -> str:
    if link_type == "linux_cooked":
        return "linux_sll"
    return link_type


def _pcap_vector_link_type(vector: EncodedVector) -> str:
    record = vector.metadata.get("pcap_record")
    if not isinstance(record, dict):
        raise ValueError("pcap vector metadata is missing pcap_record")
    link_type = record.get("link_type")
    if not isinstance(link_type, dict):
        raise ValueError("pcap vector metadata is missing link_type")
    name = link_type.get("name")
    if not isinstance(name, str):
        raise ValueError("pcap vector link_type.name must be a string")
    return name


def _pcap_group_label(direction: str, link_type: str) -> str:
    safe_link_type = re.sub(r"[^A-Za-z0-9_.-]+", "-", link_type)
    return f"{direction}.{safe_link_type}"


def _write_pcap_unsupported_report(
    *,
    args: argparse.Namespace,
    message: str,
    report_path: Path,
) -> int:
    try:
        backend = get_backend(args.backend)
    except UnknownBackendError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return _write_backend_support_report(
        args=args,
        mode="pcap",
        backend=backend,
        message=message,
        operation=f"pcap {args.direction}",
        required=(),
        missing=(),
        report_path=report_path,
        selected_specs=PCAP_SELECTED_SPECS,
    )


def _backend_info(args: argparse.Namespace) -> int:
    try:
        metadata = backend_report_metadata(
            args.backend,
            include_dependency_metadata=True,
        )
    except UnknownBackendError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.write(dumps_json(metadata))
    return 0


def _self_check(args: argparse.Namespace) -> int:
    from .generator import run_self_checks
    from .spec_loader import run_self_checks as run_spec_self_checks

    spec_checks = run_spec_self_checks()
    run_self_checks()
    scapy_backend = get_backend("scapy")
    wireshark_backend = get_backend("wireshark")
    if (
        not scapy_backend.capabilities.encode
        or not scapy_backend.capabilities.pcap_write
    ):
        raise AssertionError("Scapy backend must expose writer capabilities")
    if (
        wireshark_backend.capabilities.encode
        or wireshark_backend.capabilities.pcap_write
    ):
        raise AssertionError("Wireshark backend must remain parser-only")
    if (
        not wireshark_backend.capabilities.decode
        or not wireshark_backend.capabilities.pcap_read
    ):
        raise AssertionError("Wireshark backend must expose parser capabilities")
    sys.stdout.write(
        dumps_json(
            {
                "status": "ok",
                "checks": [*spec_checks, "generator", "backends"],
            }
        )
    )
    return 0


_SUITE_FEATURE_BY_FAMILY = {
    "dns": "dns_behavior",
}
_SUITE_OFFLINE_DIRECTIONS = (
    "reference_to_libcrafter",
    "libcrafter_to_reference",
)


def _suite_offline_cases(feature_name: str) -> list[JSONObject]:
    """Derive the offline suite case matrix from a feature's supported_cases.

    Each entry pairs a declared case with one supported offline direction and
    its byte policy, excluding structured_error cases (the oracle has no offline
    malformed comparison pathway). The result is sorted for reproducibility.
    """

    from .generator import load_stack_grammar

    grammar = load_stack_grammar()
    features = grammar.get("features", {})
    if not isinstance(features, Mapping) or feature_name not in features:
        raise ValueError(f"unknown suite feature: {feature_name}")
    feature_spec = features[feature_name]
    supported = feature_spec.get("supported_cases", []) if isinstance(feature_spec, Mapping) else []
    entries: list[JSONObject] = []
    for raw_case in supported:
        if not isinstance(raw_case, Mapping):
            continue
        name = raw_case.get("name")
        if not isinstance(name, str):
            continue
        byte_policy = raw_case.get("byte_policy")
        if byte_policy == "structured_error":
            continue
        directions = raw_case.get("directions", [])
        if not isinstance(directions, Sequence) or isinstance(directions, str):
            directions = []
        for direction in _SUITE_OFFLINE_DIRECTIONS:
            if direction not in directions and "roundtrip" not in directions:
                continue
            entries.append(
                {
                    "case": name,
                    "direction": direction,
                    "byte_policy": byte_policy if isinstance(byte_policy, str) else None,
                }
            )
    entries.sort(key=lambda entry: (entry["case"], entry["direction"]))
    return entries


def _specs_suite(args: argparse.Namespace) -> int:
    family = args.family
    feature_name = _SUITE_FEATURE_BY_FAMILY.get(family)
    if feature_name is None:
        print(
            f"no offline suite is defined for family {family!r}; "
            f"known families: {', '.join(sorted(_SUITE_FEATURE_BY_FAMILY))}",
            file=sys.stderr,
        )
        return 2

    try:
        cases = _suite_offline_cases(feature_name)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    out_root = posixpath.join(args.out, f"{family}-offline-suite")
    commands: list[JSONObject] = []
    for entry in cases:
        case = entry["case"]
        direction = entry["direction"]
        seed = _derive_suite_seed(args.seed, family, case, direction)
        artifact = posixpath.join(out_root, direction, case)
        argv = [
            "tools/oracle/run",
            "offline",
            "--backend",
            args.backend,
            "--profile",
            args.profile,
            "--family",
            family,
            "--case",
            case,
            "--direction",
            direction,
            "--seed",
            str(seed),
            "--count",
            "1",
            "--out",
            artifact,
        ]
        commands.append(
            {
                "case": case,
                "direction": direction,
                "byte_policy": entry["byte_policy"],
                "seed": seed,
                "artifact": artifact,
                "command": argv,
            }
        )

    summary: JSONObject = {
        "mode": "specs.suite",
        "family": family,
        "feature": feature_name,
        "backend": args.backend,
        "profile": args.profile,
        "base_seed": args.seed,
        "out": out_root,
        "count": len(commands),
        "directions": list(_SUITE_OFFLINE_DIRECTIONS),
        "commands": commands,
    }

    if args.run:
        return _run_specs_suite(summary, commands)

    if args.json:
        sys.stdout.write(dumps_json(summary))
    else:
        print(
            f"offline suite: family={family} feature={feature_name} "
            f"backend={args.backend} profile={args.profile} cases={len(commands)}"
        )
        for command in commands:
            print(
                f"  {command['direction']:<26} {command['case']:<34} "
                f"seed={command['seed']} -> {command['artifact']}"
            )
    return 0


def _derive_suite_seed(base_seed: int, family: str, case: str, direction: str) -> int:
    import hashlib

    material = "\0".join((str(base_seed), family, case, direction)).encode("utf-8")
    digest = int.from_bytes(hashlib.sha256(material).digest()[:4], byteorder="big")
    return digest % 1_000_000


def _run_specs_suite(summary: JSONObject, commands: Sequence[JSONObject]) -> int:
    results: list[JSONObject] = []
    failed = 0
    for command in commands:
        argv = list(command["command"])
        runner = REPO_ROOT / "tools" / "oracle" / "run"
        process = subprocess.run(
            [str(runner), *argv[1:]],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode != 0:
            failed += 1
        results.append(
            {
                "case": command["case"],
                "direction": command["direction"],
                "seed": command["seed"],
                "exit_code": process.returncode,
            }
        )
    status = "passed" if failed == 0 else "failed"
    summary = {
        **summary,
        "status": status,
        "passed": len(results) - failed,
        "failed": failed,
        "results": results,
    }
    sys.stdout.write(dumps_json(summary))
    return 0 if failed == 0 else 1


def _specs_validate(args: argparse.Namespace) -> int:
    from .spec_loader import SpecValidationError, load_oracle_specs

    try:
        specs = load_oracle_specs(strict=args.strict)
    except SpecValidationError as exc:
        print(f"spec validation failed: {exc}", file=sys.stderr)
        return 2

    summary = specs.summary()
    summary["strict"] = bool(args.strict)
    if args.json:
        sys.stdout.write(dumps_json(summary))
    else:
        counts = _json_object(summary["counts"], "spec validation counts")
        print(
            "oracle specs: "
            f"status=ok roots={counts['roots']} families={counts['families']} "
            f"stacks={counts['stacks']} profiles={counts['profiles']} "
            f"layers={counts['layers']} features={counts['features']}"
        )
    return 0


def _report(args: argparse.Namespace) -> int:
    output_dir = Path(args.out)
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir
    commands_dir = output_dir / "commands"
    commands_dir.mkdir(parents=True, exist_ok=True)

    command_results = [
        _run_final_report_command(label, list(argv), commands_dir)
        for label, argv in FINAL_REPORT_COMMANDS
    ]
    failed_commands = [
        result
        for result in command_results
        if result.get("exit_code") != 0
    ]
    scapy_imports = _remaining_scapy_imports()
    import_classifications = _classification_counts(scapy_imports)
    status = "passed" if not failed_commands else "failed"

    summary_path = output_dir / "summary.json"
    summary: JSONObject = {
        "mode": "report",
        "status": status,
        "generated_at": dt.datetime.now(dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "summary_path": str(summary_path),
        "backend": "scapy",
        "backend_versions": _backend_versions("scapy"),
        "libcrafter": _libcrafter_info(),
        "commands": command_results,
        "command_summary": {
            "passed": len(command_results) - len(failed_commands),
            "failed": len(failed_commands),
            "total": len(command_results),
        },
        "remaining_scapy_imports": scapy_imports,
        "remaining_scapy_import_summary": import_classifications,
        "hetzner_provider_backed_live_validation": {
            "status": "not_run",
            "reason": (
                "provider-backed Hetzner live validation requires explicit request "
                "and credentials"
            ),
        },
    }
    write_json(summary_path, summary)

    print(
        f"final report: status={status} "
        f"commands={len(command_results) - len(failed_commands)}/{len(command_results)} "
        f"scapy_import_matches={len(scapy_imports)} summary={summary_path}"
    )
    if failed_commands:
        labels = ", ".join(str(result.get("label")) for result in failed_commands)
        print(f"failed_commands={labels}", file=sys.stderr)
        return 1
    return 0


def _run_final_report_command(
    label: str,
    argv: list[str],
    commands_dir: Path,
) -> JSONObject:
    stdout_path = commands_dir / f"{label}.stdout.log"
    stderr_path = commands_dir / f"{label}.stderr.log"
    started_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    started = time.monotonic()

    try:
        process = subprocess.run(
            argv,
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        exit_code = process.returncode
        stdout = process.stdout
        stderr = process.stderr
    except OSError as exc:
        exit_code = 127
        stdout = ""
        stderr = str(exc)

    duration_seconds = round(time.monotonic() - started, 3)
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")

    return {
        "label": label,
        "command": shlex.join(argv),
        "exit_code": exit_code,
        "duration_seconds": duration_seconds,
        "started_at": started_at,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stdout_tail": _tail_text(stdout),
        "stderr_tail": _tail_text(stderr),
    }


def _tail_text(text: str, *, max_lines: int = 40, max_chars: int = 6000) -> str:
    tail = "\n".join(text.splitlines()[-max_lines:])
    if len(tail) > max_chars:
        return tail[-max_chars:]
    return tail


def _remaining_scapy_imports() -> list[JSONObject]:
    matches: list[JSONObject] = []
    for root_name in REPORT_SCAN_ROOTS:
        root = REPO_ROOT / root_name
        if not root.exists():
            continue
        paths = [root] if root.is_file() else root.rglob("*")
        for path in paths:
            if not path.is_file() or _skip_report_scan_path(path):
                continue
            relative = path.relative_to(REPO_ROOT).as_posix()
            if relative.startswith("tools/oracle/engine/backends/scapy/"):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            except OSError:
                continue
            if "\0" in text:
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not SCAPY_IMPORT_RE.search(line):
                    continue
                matches.append(
                    {
                        "path": relative,
                        "line": line_number,
                        "text": line.strip(),
                        "classification": _classify_scapy_import_match(relative),
                    }
                )
    return matches


def _skip_report_scan_path(path: Path) -> bool:
    try:
        relative = path.relative_to(REPO_ROOT)
    except ValueError:
        return True
    return any(part in REPORT_SCAN_EXCLUDED_DIRS for part in relative.parts)


def _classify_scapy_import_match(relative_path: str) -> str:
    if (
        relative_path.startswith("crafter/tests/fixtures/")
        or "/fixtures/" in relative_path
    ):
        return "fixture data"
    if (
        relative_path.startswith("docs/")
        or relative_path.startswith(".agents/skills/")
        or relative_path.endswith((".md", ".rst", ".txt"))
    ):
        return "allowed compatibility docs"
    return "follow-up cleanup"


def _classification_counts(matches: Sequence[JSONObject]) -> JSONObject:
    counts: dict[str, int] = {}
    for match in matches:
        classification = match.get("classification")
        if not isinstance(classification, str):
            classification = "follow-up cleanup"
        counts[classification] = counts.get(classification, 0) + 1
    return counts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tools/oracle/run",
        description="Run libcrafter oracle validation.",
    )
    subparsers = parser.add_subparsers(
        dest="mode",
        metavar="MODE",
        required=True,
    )

    generate_parser = subparsers.add_parser(
        "generate",
        help="generate deterministic packet plans",
        description="Generate deterministic oracle packet plans.",
    )
    _add_common_options(generate_parser)
    _add_generation_options(generate_parser)
    generate_parser.add_argument(
        "--direction",
        default="reference_to_libcrafter",
        choices=(
            "reference_to_libcrafter",
            "libcrafter_to_reference",
            "roundtrip",
            "live",
            "live_exchange",
        ),
        help="plan direction metadata (default: %(default)s)",
    )
    generate_parser.set_defaults(func=_generate)

    corpus_parser = subparsers.add_parser(
        "corpus",
        help="generate a reusable packet corpus",
        description="Generate a reusable oracle packet corpus artifact.",
    )
    corpus_parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT / "corpus"),
        help="corpus output root (default: %(default)s)",
    )
    _add_generation_options(corpus_parser)
    corpus_parser.add_argument(
        "--direction",
        default="reference_to_libcrafter",
        choices=(
            "reference_to_libcrafter",
            "libcrafter_to_reference",
            "roundtrip",
            "live",
            "live_exchange",
        ),
        help="plan direction metadata (default: %(default)s)",
    )
    corpus_parser.set_defaults(func=_corpus)

    offline_parser = subparsers.add_parser(
        "offline",
        help="run offline validation",
        description="Run offline oracle validation.",
    )
    _add_common_options(offline_parser)
    _add_generation_options(offline_parser)
    offline_parser.add_argument(
        "--direction",
        choices=("reference_to_libcrafter", "libcrafter_to_reference"),
        default="reference_to_libcrafter",
        help="offline validation direction (default: %(default)s)",
    )
    offline_parser.add_argument(
        "--corpus",
        help="read packet plans from a corpus plans.json artifact",
    )
    offline_parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="keep intermediate vector and decoded artifacts for successful runs",
    )
    offline_parser.add_argument(
        "--dry-plan",
        action="store_true",
        help="print generated packet plans without invoking a backend",
    )
    offline_parser.add_argument(
        "--emit-vectors",
        action="store_true",
        help="print Scapy-materialized packet vectors without invoking libcrafter",
    )
    offline_parser.add_argument(
        "--emit-decoded",
        action="store_true",
        help="print normalized Scapy-decoded packet models without invoking libcrafter",
    )
    offline_parser.set_defaults(func=_offline)

    pcap_parser = subparsers.add_parser(
        "pcap",
        help="run pcap validation",
        description="Run pcap oracle validation.",
    )
    _add_common_options(pcap_parser)
    _add_generation_options(pcap_parser)
    pcap_parser.add_argument(
        "--direction",
        choices=("reference_to_libcrafter", "libcrafter_to_reference", "roundtrip"),
        default="roundtrip",
        help="pcap validation direction (default: %(default)s)",
    )
    pcap_parser.add_argument(
        "--corpus",
        help="read packet plans from a corpus plans.json artifact",
    )
    pcap_parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="keep intermediate pcap and bridge artifacts for successful runs",
    )
    pcap_parser.add_argument(
        "--dry-plan",
        action="store_true",
        help="print deterministic pcap plans without invoking a backend",
    )
    pcap_parser.set_defaults(func=_pcap)

    live_parser = subparsers.add_parser(
        "live",
        help="run live validation",
        description="Run live oracle validation.",
    )
    _add_common_options(live_parser)
    _add_generation_options(live_parser)
    from .providers.registry import registered_provider_names

    live_parser.add_argument(
        "--provider",
        choices=("local-dry-run", *registered_provider_names()),
        required=True,
        help="live provider to use",
    )
    live_parser.add_argument(
        "--direction",
        choices=("libcrafter_to_reference", "reference_to_libcrafter", "live_exchange"),
        default="live_exchange",
        help="live validation direction (default: %(default)s)",
    )
    live_parser.add_argument(
        "--corpus",
        help="read packet plans from a corpus plans.json artifact",
    )
    live_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="plan provider-backed live validation without creating infrastructure",
    )
    live_parser.add_argument(
        "--confirm-live-run",
        action="store_true",
        help="confirm protected non-dry-run provider execution",
    )
    live_parser.add_argument(
        "--keep-wire-endpoints",
        action="store_true",
        help="keep provider wire endpoints after a non-dry-run for debugging",
    )
    live_parser.set_defaults(func=_live)

    backend_info_parser = subparsers.add_parser(
        "backend-info",
        help="print backend dependency and version metadata",
        description="Print oracle backend dependency and version metadata.",
    )
    backend_info_parser.add_argument(
        "--backend",
        choices=registered_backend_names(),
        default="scapy",
        help="backend to inspect (default: %(default)s)",
    )
    backend_info_parser.set_defaults(func=_backend_info)

    specs_parser = subparsers.add_parser(
        "specs",
        help="inspect executable oracle specs",
        description="Inspect executable oracle specs.",
    )
    specs_subparsers = specs_parser.add_subparsers(
        dest="specs_command",
        metavar="COMMAND",
        required=True,
    )
    specs_validate_parser = specs_subparsers.add_parser(
        "validate",
        help="load and validate all executable oracle specs",
        description="Load and validate all executable oracle specs.",
    )
    specs_validate_parser.add_argument(
        "--json",
        action="store_true",
        help="print the validation summary as JSON",
    )
    specs_validate_parser.add_argument(
        "--strict",
        action="store_true",
        help="run strict cross-file spec validation",
    )
    specs_validate_parser.set_defaults(func=_specs_validate)

    specs_suite_parser = specs_subparsers.add_parser(
        "suite",
        help="emit the reproducible offline case suite for a protocol family",
        description=(
            "Emit every offline-eligible supported case for a protocol family in "
            "each direction it declares, derived from the feature spec's "
            "supported_cases (directions + byte_policy). structured_error cases are "
            "excluded because the oracle has no offline malformed pathway."
        ),
    )
    specs_suite_parser.add_argument(
        "--family",
        default="dns",
        help="protocol family to emit the offline suite for (default: %(default)s)",
    )
    specs_suite_parser.add_argument(
        "--backend",
        default="scapy",
        choices=("scapy", "wireshark"),
        help="reference backend for the emitted commands (default: %(default)s)",
    )
    specs_suite_parser.add_argument(
        "--profile",
        default="ci",
        help="sampling profile for the emitted commands (default: %(default)s)",
    )
    specs_suite_parser.add_argument(
        "--seed",
        type=int,
        default=2701,
        help="base seed; per-case seeds derive deterministically (default: %(default)s)",
    )
    specs_suite_parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="artifact output root for the emitted commands (default: %(default)s)",
    )
    specs_suite_parser.add_argument(
        "--json",
        action="store_true",
        help="print the suite plan as JSON",
    )
    specs_suite_parser.add_argument(
        "--run",
        action="store_true",
        help="execute each emitted offline command and report the aggregate result",
    )
    specs_suite_parser.set_defaults(func=_specs_suite)

    report_parser = subparsers.add_parser(
        "report",
        help="run final oracle validation and write a summary",
        description="Run final oracle validation and write a summary.",
    )
    report_parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT / "final"),
        help="final report output directory (default: %(default)s)",
    )
    report_parser.set_defaults(func=_report)

    self_check_parser = subparsers.add_parser(
        "self-check",
        help="run oracle engine self checks",
        description="Run lightweight oracle engine self checks.",
    )
    self_check_parser.set_defaults(func=_self_check)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
