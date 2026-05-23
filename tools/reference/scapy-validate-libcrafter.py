#!/usr/bin/env python3
"""Validate libcrafter-generated interop vectors with Scapy."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Any


def import_scapy() -> dict[str, Any]:
    try:
        import scapy  # type: ignore[import-untyped]
        from scapy.all import Ether, IP, IPv6, Raw, conf, raw  # type: ignore[import-untyped]
        from scapy.layers.l2 import CookedLinux, Loopback  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:
        if exc.name != "scapy":
            raise
        maybe_reexec_with_uv()
        raise

    conf.verb = 0
    return {
        "CookedLinux": CookedLinux,
        "Ether": Ether,
        "IP": IP,
        "IPv6": IPv6,
        "Loopback": Loopback,
        "Raw": Raw,
        "raw": raw,
        "version": getattr(scapy, "__version__", "unknown"),
    }


def maybe_reexec_with_uv() -> None:
    if os.environ.get("LIBCRAFTER_SCAPY_BOOTSTRAPPED") == "1":
        print(
            "error: scapy is not importable after dependency bootstrap",
            file=sys.stderr,
        )
        sys.exit(1)

    uv = shutil.which("uv")
    if uv is None:
        print(
            "error: scapy is not installed. Install scapy or install uv so this "
            "validator can bootstrap scapy without root.",
            file=sys.stderr,
        )
        sys.exit(1)

    env = os.environ.copy()
    env["LIBCRAFTER_SCAPY_BOOTSTRAPPED"] = "1"
    env.setdefault("UV_NO_PROGRESS", "1")
    script = str(Path(__file__).resolve())
    os.execvpe(
        uv,
        [
            uv,
            "run",
            "--quiet",
            "--no-project",
            "--with",
            "scapy>=2.5,<3",
            "--",
            "python3",
            script,
            *sys.argv[1:],
        ],
        env,
    )


SCAPY = import_scapy()

CookedLinux = SCAPY["CookedLinux"]
Ether = SCAPY["Ether"]
IP = SCAPY["IP"]
IPv6 = SCAPY["IPv6"]
Loopback = SCAPY["Loopback"]
Raw = SCAPY["Raw"]
raw = SCAPY["raw"]
SCAPY_VERSION = SCAPY["version"]


class ValidationError(Exception):
    pass


def split_filters(values: list[str]) -> list[str]:
    filters: list[str] = []
    for raw_value in values:
        for value in raw_value.split(","):
            normalized = value.strip()
            if normalized:
                filters.append(normalized)
    return filters


def validate_filters(kind: str, requested: list[str], known: set[str]) -> None:
    unknown = sorted(set(requested) - known)
    if unknown:
        raise SystemExit(
            f"unknown {kind}(s): {', '.join(unknown)}. known: {', '.join(sorted(known))}"
        )


def load_manifest(path: str) -> dict[str, Any]:
    try:
        if path == "-":
            text = sys.stdin.read()
            label = "<stdin>"
        else:
            label = path
            text = Path(path).read_text(encoding="utf-8")
        manifest = json.loads(text)
    except FileNotFoundError as exc:
        raise SystemExit(f"missing libcrafter vector JSON: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid libcrafter vector JSON {label}: {exc}") from exc

    cases = manifest.get("cases")
    if not isinstance(cases, list):
        raise SystemExit(f"libcrafter vector JSON {label} must contain a cases list")
    return manifest


def selected_cases(manifest: dict[str, Any], args: argparse.Namespace) -> list[dict[str, Any]]:
    cases = [case for case in manifest["cases"] if isinstance(case, dict)]
    requested_names = split_filters(args.only)
    requested_families = split_filters(args.family)
    requested_directions = split_filters(args.direction)
    if not requested_directions:
        requested_directions = ["libcrafter_to_scapy"]

    if args.smoke and not requested_names and not requested_families:
        requested_names = ["ethernet"]

    validate_filters(
        "case",
        requested_names,
        {str(case.get("name")) for case in cases if case.get("name")},
    )
    validate_filters(
        "family",
        requested_families,
        {str(case.get("family")) for case in cases if case.get("family")},
    )
    validate_filters(
        "direction",
        requested_directions,
        {str(case.get("direction")) for case in cases if case.get("direction")},
    )

    selected = cases
    if requested_names:
        requested_name_set = set(requested_names)
        selected = [case for case in selected if case.get("name") in requested_name_set]
    if requested_families:
        requested_family_set = set(requested_families)
        selected = [case for case in selected if case.get("family") in requested_family_set]
    if requested_directions:
        requested_direction_set = set(requested_directions)
        selected = [
            case for case in selected if case.get("direction") in requested_direction_set
        ]

    if not selected:
        raise SystemExit("no libcrafter_to_scapy cases selected")
    return selected


def decode_root(root: str, blob: bytes, ctx: str) -> Any:
    decoders = {
        "link:ethernet": Ether,
        "link:linux-cooked": CookedLinux,
        "link:linux-sll": CookedLinux,
        "link:null-loopback": Loopback,
        "link:raw": Raw,
        "l3:ipv4": IP,
        "l3:ipv6": IPv6,
        "l3:raw": Raw,
    }
    decoder = decoders.get(root)
    if decoder is None:
        raise ValidationError(f"{ctx}: unsupported Scapy root {root!r}")

    try:
        return decoder(blob)
    except Exception as exc:  # pragma: no cover - Scapy exception types vary.
        raise ValidationError(f"{ctx}: Scapy decode failed for root={root}: {exc}") from exc


def json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"hex": value.hex(), "ascii": value.decode("utf-8", "replace")}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, tuple):
        return [json_value(item) for item in value]
    if isinstance(value, list):
        return [json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    return str(value)


def packet_layers(packet: Any) -> list[dict[str, Any]]:
    layers: list[dict[str, Any]] = []
    current = packet
    while current and current.__class__.__name__ != "NoPayload":
        layers.append(
            {
                "name": current.__class__.__name__,
                "fields": {
                    str(key): json_value(value)
                    for key, value in sorted(current.fields.items())
                },
                "summary": current.summary(),
            }
        )
        current = current.payload
    return layers


def assert_stack(case: dict[str, Any], layers: list[dict[str, Any]], ctx: str) -> None:
    expected_stack = case.get("expected_stack")
    if not isinstance(expected_stack, list):
        raise ValidationError(f"{ctx}: expected_stack must be a list")

    actual_stack = [str(layer["name"]) for layer in layers]
    if actual_stack != expected_stack:
        raise ValidationError(
            f"{ctx}: layer stack mismatch expected={expected_stack!r} actual={actual_stack!r}"
        )


def assert_fields(case: dict[str, Any], layers: list[dict[str, Any]], ctx: str) -> None:
    assertions = case.get("field_assertions")
    if not isinstance(assertions, list):
        raise ValidationError(f"{ctx}: field_assertions must be a list")

    occurrences: dict[str, int] = {}
    for assertion in assertions:
        if not isinstance(assertion, dict):
            raise ValidationError(f"{ctx}: field assertion must be an object")
        layer_name = assertion.get("layer")
        expected_fields = assertion.get("fields")
        if not isinstance(layer_name, str) or not isinstance(expected_fields, dict):
            raise ValidationError(f"{ctx}: field assertion must name a layer and fields")

        occurrence = occurrences.get(layer_name, 0)
        matching_layers = [layer for layer in layers if layer["name"] == layer_name]
        if occurrence >= len(matching_layers):
            raise ValidationError(
                f"{ctx}: missing layer {layer_name} occurrence {occurrence}"
            )
        occurrences[layer_name] = occurrence + 1

        actual_fields = matching_layers[occurrence]["fields"]
        for field_name, expected_value in sorted(expected_fields.items()):
            if field_name not in actual_fields:
                raise ValidationError(
                    f"{ctx}: missing field {layer_name}.{field_name}; "
                    f"available={sorted(actual_fields)}"
                )
            actual_value = actual_fields[field_name]
            if actual_value != expected_value:
                raise ValidationError(
                    f"{ctx}: field {layer_name}.{field_name} mismatch "
                    f"expected={expected_value!r} actual={actual_value!r}"
                )


def artifact_name(case_name: str) -> str:
    safe = []
    for char in case_name:
        if char.isalnum() or char in ("-", "_", "."):
            safe.append(char)
        else:
            safe.append("_")
    return "".join(safe) or "case"


def write_artifact(
    out_dir: Path | None,
    case: dict[str, Any],
    decoded: Any,
    layers: list[dict[str, Any]],
) -> None:
    if out_dir is None:
        return

    out_dir.mkdir(parents=True, exist_ok=True)
    case_name = str(case.get("name", "case"))
    artifact = {
        "name": case_name,
        "direction": case.get("direction"),
        "root": case.get("root"),
        "scapy_version": SCAPY_VERSION,
        "decoded_summary": decoded.summary(),
        "layer_names": [layer["name"] for layer in layers],
        "layers": layers,
        "scapy_show": decoded.show(dump=True),
    }
    path = out_dir / f"{artifact_name(case_name)}.decoded.json"
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_case(case: dict[str, Any], out_dir: Path | None) -> None:
    name = case.get("name")
    direction = case.get("direction")
    ctx = f"direction={direction} case={name}"

    if direction != "libcrafter_to_scapy":
        raise ValidationError(f"{ctx}: validator only accepts libcrafter_to_scapy cases")
    if not isinstance(name, str) or not name:
        raise ValidationError(f"{ctx}: case name must be a string")

    root = case.get("root_decoder", case.get("root"))
    if not isinstance(root, str):
        raise ValidationError(f"{ctx}: root/root_decoder must be a string")

    hex_value = case.get("hex")
    if not isinstance(hex_value, str):
        raise ValidationError(f"{ctx}: hex must be a string")
    try:
        blob = bytes.fromhex(hex_value)
    except ValueError as exc:
        raise ValidationError(f"{ctx}: hex is invalid: {exc}") from exc

    expected_length = case.get("length")
    if expected_length != len(blob):
        raise ValidationError(
            f"{ctx}: length mismatch expected={expected_length!r} actual={len(blob)}"
        )

    decoded = decode_root(root, blob, ctx)
    layers = packet_layers(decoded)
    assert_stack(case, layers, ctx)
    assert_fields(case, layers, ctx)

    if case.get("strict_bytes") is True:
        encoded = bytes(raw(decoded))
        if encoded != blob:
            raise ValidationError(
                f"{ctx}: strict_bytes re-encode mismatch "
                f"expected={blob.hex()} actual={encoded.hex()}"
            )

    write_artifact(out_dir, case, decoded, layers)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Decode libcrafter interop vectors with Scapy and validate fields."
    )
    parser.add_argument(
        "--input",
        "-i",
        default="-",
        help="libcrafter vector JSON path, or '-' for stdin",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="optional directory for decoded Scapy JSON artifacts",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="NAME",
        help="case name filter; can be passed multiple times or comma-separated",
    )
    parser.add_argument(
        "--family",
        action="append",
        default=[],
        metavar="FAMILY",
        help="case family filter; can be passed multiple times or comma-separated",
    )
    parser.add_argument(
        "--direction",
        action="append",
        default=[],
        metavar="DIRECTION",
        help="case direction filter; defaults to libcrafter_to_scapy",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="validate only the smallest default case unless other filters are set",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="list selected cases and exit",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = load_manifest(args.input)
    cases = selected_cases(manifest, args)

    if args.list:
        for case in cases:
            print(f"{case.get('name')}\t{case.get('family')}\t{case.get('root')}")
        return 0

    failures: list[str] = []
    for case in cases:
        try:
            validate_case(case, args.out)
        except ValidationError as exc:
            failures.append(str(exc))

    if failures:
        print("Scapy parser validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        f"checked {len(cases)} libcrafter_to_scapy vector(s) with Scapy {SCAPY_VERSION}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
