"""Scapy-backed fixture generation behind the oracle command surface."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

from ...model import JSONObject
from ...report import REPO_ROOT
from .bootstrap import backend_info, import_scapy
from .normalize import decode_bytes


BACKEND_NAME = "scapy"
LEGACY_FIXTURE_SCRIPT = REPO_ROOT / "tools" / "reference" / "scapy-fixtures.py"
CHECKED_IN_FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "scapy"

_LEGACY_METADATA_KEYS = (
    "name",
    "direction",
    "root",
    "root_decoder",
    "expected_stack",
    "strict_bytes",
    "length",
    "hex",
    "relevant_fields",
)


@dataclass(frozen=True, slots=True)
class FixtureGenerationOptions:
    """Inputs for deterministic oracle fixture generation."""

    out_dir: Path
    profile: str = "smoke"
    seed: int = 1
    names: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)
    directions: list[str] = field(default_factory=list)
    check_drift: bool = False
    list_only: bool = False


def generate_fixtures(options: FixtureGenerationOptions) -> int:
    """Generate Scapy fixture files and a selected-case manifest."""

    legacy = _legacy_module()
    fixtures = _select_fixtures(legacy, options)

    if options.list_only:
        for fixture in fixtures:
            print(f"{fixture.name}\t{fixture.description}")
        return 0

    if options.check_drift:
        return _check_drift(legacy, fixtures, options)

    _write_fixtures(legacy, fixtures, options.out_dir, options)
    print(f"wrote {len(fixtures)} oracle fixture case(s) to {options.out_dir}")
    return 0


def _legacy_module() -> ModuleType:
    import_scapy()
    spec = importlib.util.spec_from_file_location(
        "_libcrafter_legacy_scapy_fixtures",
        LEGACY_FIXTURE_SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load legacy fixture script: {LEGACY_FIXTURE_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _select_fixtures(
    legacy: ModuleType,
    options: FixtureGenerationOptions,
) -> list[Any]:
    if options.check_drift and not options.names:
        base_fixtures = legacy.checked_in_fixtures()
    else:
        base_fixtures = None
    return legacy.selected_fixtures(
        options.names,
        options.families,
        options.directions,
        base_fixtures=base_fixtures,
    )


def _write_fixtures(
    legacy: ModuleType,
    fixtures: list[Any],
    out_dir: Path,
    options: FixtureGenerationOptions,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    backend = backend_info()
    for fixture in fixtures:
        legacy.write_fixture(out_dir, fixture)
        _enrich_fixture_metadata(
            path=out_dir / f"{fixture.name}.json",
            fixture=fixture,
            backend=backend,
            options=options,
        )
    _write_case_manifest(legacy, fixtures, out_dir, backend, options)


def _enrich_fixture_metadata(
    *,
    path: Path,
    fixture: Any,
    backend: JSONObject,
    options: FixtureGenerationOptions,
) -> None:
    metadata = _read_object(path)
    raw_hex = _string(metadata.get("hex"))
    root = _string(metadata.get("root"))
    legacy_direction = _string(metadata.get("direction"))

    metadata["schema"] = "oracle.fixture.v1"
    metadata["backend"] = BACKEND_NAME
    metadata["backend_versions"] = {BACKEND_NAME: backend}
    metadata["oracle_direction"] = _oracle_direction(legacy_direction)
    metadata["raw_hex"] = raw_hex
    metadata["oracle"] = {
        "command": "tools/oracle/run fixtures",
        "backend": BACKEND_NAME,
        "profile": options.profile,
        "seed": options.seed,
        "direction": _oracle_direction(legacy_direction),
        "root": root,
    }
    metadata["legacy"] = {
        "format": "scapy_reference",
        "name": fixture.name,
        "direction": legacy_direction,
        "root_decoder": metadata.get("root_decoder"),
        "scapy_root": metadata.get("scapy_root"),
    }

    try:
        decoded = decode_bytes(bytes.fromhex(raw_hex), root=root, source_hex=raw_hex).to_dict()
    except Exception as exc:  # pragma: no cover - Scapy decode support varies by version.
        metadata["expected_decoded_error"] = str(exc)
    else:
        metadata["expected_decoded"] = {
            "root": decoded.get("root"),
            "source_hex": decoded.get("source_hex"),
            "layers": decoded.get("layers"),
            "fields": decoded.get("fields"),
        }

    path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_case_manifest(
    legacy: ModuleType,
    fixtures: list[Any],
    out_dir: Path,
    backend: JSONObject,
    options: FixtureGenerationOptions,
) -> None:
    cases = []
    for fixture in fixtures:
        case = dict(legacy.fixture_case(fixture))
        direction = _string(case.get("direction"))
        case["backend"] = BACKEND_NAME
        case["oracle_direction"] = _oracle_direction(direction)
        case["artifact_paths"] = {
            "bytes": f"{fixture.name}.bin",
            "metadata": f"{fixture.name}.json",
        }
        cases.append(case)

    manifest = {
        "schema": "oracle.fixture_cases.v1",
        "schema_version": 1,
        "schema_note": (
            "Oracle fixture manifest. Legacy case direction/root fields are "
            "preserved for existing Rust fixture tests."
        ),
        "backend": BACKEND_NAME,
        "backend_versions": {BACKEND_NAME: backend},
        "profile": options.profile,
        "seed": options.seed,
        "legacy": {
            "format": "scapy_reference",
            "checked_in_dir": str(CHECKED_IN_FIXTURE_DIR),
        },
        "documentation_values": legacy.CASE_DATA.get("documentation_values", {}),
        "cases": cases,
    }
    (out_dir / "cases.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _check_drift(
    legacy: ModuleType,
    fixtures: list[Any],
    options: FixtureGenerationOptions,
) -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="libcrafter-oracle-fixtures-") as tmp:
        out_dir = Path(tmp)
        _write_fixtures(legacy, fixtures, out_dir, options)
        for fixture in fixtures:
            generated_bin = out_dir / f"{fixture.name}.bin"
            expected_bin = CHECKED_IN_FIXTURE_DIR / f"{fixture.name}.bin"
            failure = _compare_bytes(generated_bin, expected_bin)
            if failure is not None:
                failures.append(failure)

            generated_json = out_dir / f"{fixture.name}.json"
            expected_json = CHECKED_IN_FIXTURE_DIR / f"{fixture.name}.json"
            failure = _compare_legacy_metadata(generated_json, expected_json)
            if failure is not None:
                failures.append(failure)

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print(f"checked {len(fixtures)} oracle fixture(s); no drift detected")
    return 0


def _compare_bytes(generated: Path, expected: Path) -> str | None:
    if not expected.exists():
        return f"missing checked-in fixture: {expected}"
    if generated.read_bytes() != expected.read_bytes():
        return f"drift detected: {expected}"
    return None


def _compare_legacy_metadata(generated: Path, expected: Path) -> str | None:
    if not expected.exists():
        return f"missing checked-in fixture metadata: {expected}"
    generated_object = _read_object(generated)
    expected_object = _read_object(expected)
    for key in _LEGACY_METADATA_KEYS:
        if generated_object.get(key) != expected_object.get(key):
            return f"legacy metadata drift detected: {expected} key={key}"
    return None


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object in {path}")
    return value


def _oracle_direction(direction: str) -> str:
    aliases = {
        "scapy_to_libcrafter": "reference_to_libcrafter",
        "libcrafter_to_scapy": "libcrafter_to_reference",
    }
    return aliases.get(direction, direction)


def _string(value: object) -> str:
    if isinstance(value, str):
        return value
    return str(value)
