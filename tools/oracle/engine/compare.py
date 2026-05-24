"""Backend-neutral comparison helpers for oracle decoded packet models."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .model import (
    ComparisonResult,
    DecodedModel,
    JSONObject,
    JSONValue,
    PacketPlan,
    decoded_backend_metadata,
    decoded_model_object,
    normalized_decoded_model,
)


MAX_DIFFERENCES = 100


def compare_decoded_models(
    *,
    expected: DecodedModel | Mapping[str, object],
    actual: DecodedModel | Mapping[str, object],
    plan: PacketPlan,
    direction: str,
    reproduction_command: str,
    partial_expected: bool = False,
    actual_strict_bytes_hex: str | None = None,
) -> ComparisonResult:
    """Compare two normalized decoded models and return a structured result."""

    use_partial_fields = partial_expected or _assertions_are_partial(expected)
    expected_model = comparable_decoded_model(
        expected,
        fallback_feature_tags=plan.feature_tags,
    )
    actual_model = comparable_decoded_model(
        actual,
        fallback_feature_tags=plan.feature_tags,
    )
    differences: list[JSONObject] = []

    _diff("layers", expected_model["layers"], actual_model["layers"], differences)
    if use_partial_fields:
        _diff_subset("fields", expected_model["fields"], actual_model["fields"], differences)
    else:
        _diff("fields", expected_model["fields"], actual_model["fields"], differences)
    _diff("root", expected_model["root"], actual_model["root"], differences)
    _diff(
        "feature_tags",
        expected_model["feature_tags"],
        actual_model["feature_tags"],
        differences,
    )

    actual_bytes_hex = actual_strict_bytes_hex or actual_model.get("source_hex")
    byte_equal = expected_model.get("source_hex") == actual_bytes_hex
    if plan.strict_bytes:
        _diff(
            "source_hex",
            expected_model.get("source_hex"),
            actual_bytes_hex,
            differences,
        )

    passed = not differences
    return ComparisonResult(
        passed=passed,
        direction=direction,
        expected=expected_model,
        actual=actual_model,
        plan=plan,
        strict_bytes=plan.strict_bytes,
        byte_equal=byte_equal,
        differences=differences,
        reproduction_command=None if passed else reproduction_command,
        metadata={
            "plan_id": _plan_id(plan),
            "partial_expected": use_partial_fields,
            "feature_tags": list(plan.feature_tags),
            "backend_metadata": {
                "expected": decoded_backend_metadata(expected),
                "actual": decoded_backend_metadata(actual),
            },
        },
    )


def comparable_decoded_model(
    model: DecodedModel | Mapping[str, object],
    *,
    fallback_feature_tags: Sequence[str] = (),
) -> JSONObject:
    """Return the deterministic subset used for cross-backend comparisons."""

    return normalized_decoded_model(
        model,
        fallback_feature_tags=fallback_feature_tags,
    )


def failure_indexes(results: Sequence[ComparisonResult]) -> list[int]:
    """Return packet indexes for failed comparison results."""

    output: list[int] = []
    for result in results:
        if result.passed or result.plan is None:
            continue
        output.append(result.plan.index)
    return output


def _diff(path: str, expected: JSONValue, actual: JSONValue, differences: list[JSONObject]) -> None:
    if len(differences) >= MAX_DIFFERENCES:
        return

    if isinstance(expected, Mapping) and isinstance(actual, Mapping):
        expected_keys = set(expected)
        actual_keys = set(actual)
        for key in sorted(expected_keys | actual_keys):
            child_path = f"{path}.{key}"
            if key not in expected:
                _append_difference(child_path, "<missing>", actual[key], differences)
            elif key not in actual:
                _append_difference(child_path, expected[key], "<missing>", differences)
            else:
                _diff(child_path, expected[key], actual[key], differences)
        return

    if expected != actual:
        _append_difference(path, expected, actual, differences)


def _diff_subset(
    path: str,
    expected: JSONValue,
    actual: JSONValue,
    differences: list[JSONObject],
) -> None:
    if len(differences) >= MAX_DIFFERENCES:
        return

    if isinstance(expected, Mapping):
        if not isinstance(actual, Mapping):
            _append_difference(path, expected, actual, differences)
            return
        for key in sorted(expected):
            child_path = f"{path}.{key}"
            if key not in actual:
                _append_difference(child_path, expected[key], "<missing>", differences)
            else:
                _diff_subset(child_path, expected[key], actual[key], differences)
        return

    if expected != actual:
        _append_difference(path, expected, actual, differences)


def _append_difference(
    path: str,
    expected: JSONValue | str,
    actual: JSONValue | str,
    differences: list[JSONObject],
) -> None:
    if len(differences) >= MAX_DIFFERENCES:
        return
    differences.append(
        {
            "path": path,
            "expected": _json_value(expected),
            "actual": _json_value(actual),
        }
    )
    if len(differences) == MAX_DIFFERENCES:
        differences.append(
            {
                "path": "<truncated>",
                "expected": f"first {MAX_DIFFERENCES} differences",
                "actual": "additional differences omitted",
            }
        )


def _json_value(value: object) -> JSONValue:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    return str(value)


def _plan_id(plan: PacketPlan) -> str | None:
    value = plan.metadata.get("plan_id")
    if isinstance(value, str):
        return value
    return None


def _assertions_are_partial(model: DecodedModel | Mapping[str, object]) -> bool:
    raw_model = decoded_model_object(model)
    metadata = raw_model.get("metadata")
    if not isinstance(metadata, Mapping):
        return False
    return metadata.get("assertions_are_partial") is True
