"""Validated loader for executable oracle YAML specs."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .backends.registry import (
    BACKEND_CAPABILITY_NAMES,
    BackendRegistration,
    get_backend_capability_registration,
    registered_backend_capability_names,
)
from .model import JSONObject, JSONValue, JsonModel, to_jsonable
from .report import REPO_ROOT


SPEC_ROOT = REPO_ROOT / "tools/oracle/specs"
SUPPORTED_SPEC_VERSION = 1
BACKEND_CAPABILITY_KEYS = BACKEND_CAPABILITY_NAMES
BACKEND_SUPPORT_STATUSES = ("planned", "partial", "supported")
FEATURE_DIRECTIONS = (
    "reference_to_libcrafter",
    "libcrafter_to_reference",
    "roundtrip",
    "live",
    "live_exchange",
)
PCAP_FILE_FORMATS = ("pcap", "pcapng")


class SpecValidationError(ValueError):
    """Raised when an oracle spec file cannot be loaded or validated."""


@dataclass(frozen=True, slots=True)
class BackendSupport(JsonModel):
    """Backend support metadata declared by one spec file."""

    name: str
    status: str
    encode: bool = False
    decode: bool = False
    pcap_read: bool = False
    pcap_write: bool = False
    live_endpoint: bool = False
    native_layers: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RootSpec(JsonModel):
    """One packet root and the families it can carry."""

    name: str
    layers: tuple[str, ...]
    families: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FamilySpec(JsonModel):
    """One stack family used by deterministic packet generation."""

    name: str
    default_stack: tuple[str, ...]
    feature_tags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StackSpec(JsonModel):
    """One named protocol stack from stacks.yaml."""

    name: str
    root: str
    layers: tuple[str, ...]
    coverage_cases: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class StackConstraint(JsonModel):
    """Parent/child layer constraint from stacks.yaml."""

    name: str
    parent: str
    children: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SamplingWeight(JsonModel):
    """Named integer weight used by a sampling profile."""

    name: str
    weight: int


@dataclass(frozen=True, slots=True)
class PayloadLength(JsonModel):
    """Inclusive generated payload length bounds."""

    minimum: int
    maximum: int

    def as_pair(self) -> list[int]:
        return [self.minimum, self.maximum]


@dataclass(frozen=True, slots=True)
class ProfileSpec(JsonModel):
    """One deterministic sampling profile."""

    name: str
    purpose: str
    default_count: int
    family_weights: tuple[SamplingWeight, ...]
    payload_length: PayloadLength
    feature_weights: dict[str, int]
    backend_support: dict[str, BackendSupport] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LayerField(JsonModel):
    """One layer field and the domains it can sample from."""

    name: str
    field_type: str
    required: bool
    domains: tuple[JSONValue, ...]


@dataclass(frozen=True, slots=True)
class LayerSpec(JsonModel):
    """One protocol layer spec."""

    name: str
    summary: str
    roots: tuple[str, ...]
    parents: tuple[str, ...]
    children: tuple[str, ...]
    fields: tuple[LayerField, ...]
    coverage_cases: tuple[str, ...]
    backend_support: dict[str, BackendSupport]
    raw: JSONObject


@dataclass(frozen=True, slots=True)
class FeatureSpec(JsonModel):
    """One packet behavior feature spec."""

    name: str
    summary: str
    layers: tuple[str, ...]
    directions: tuple[str, ...]
    strict_bytes: bool
    malformed: bool
    coverage_cases: tuple[str, ...]
    backend_support: dict[str, BackendSupport]
    raw: JSONObject


@dataclass(frozen=True, slots=True)
class OracleSpecs(JsonModel):
    """All loaded oracle specs, normalized for execution."""

    roots: dict[str, RootSpec]
    families: dict[str, FamilySpec]
    stacks: dict[str, StackSpec]
    constraints: dict[str, StackConstraint]
    profiles: dict[str, ProfileSpec]
    layers: dict[str, LayerSpec]
    features: dict[str, FeatureSpec]
    backend_support: dict[str, BackendSupport]
    source_paths: tuple[str, ...]

    def to_generator_grammar(self) -> JSONObject:
        """Return the JSON-compatible grammar consumed by PacketGenerator."""

        return {
            "version": SUPPORTED_SPEC_VERSION,
            "families": {
                family.name: {
                    "stack": list(family.default_stack),
                    "case": _default_case_for_family(family, self.stacks.values()),
                    "feature_tags": list(family.feature_tags),
                }
                for family in self.families.values()
            },
            "profiles": {
                profile.name: {
                    "default_count": profile.default_count,
                    "family_weights": [
                        {"name": weight.name, "weight": weight.weight}
                        for weight in profile.family_weights
                    ],
                    "payload_length": profile.payload_length.as_pair(),
                    "feature_weights": dict(profile.feature_weights),
                }
                for profile in self.profiles.values()
            },
        }

    def summary(self) -> JSONObject:
        """Return a concise validation summary for the CLI."""

        return {
            "status": "ok",
            "version": SUPPORTED_SPEC_VERSION,
            "source_paths": list(self.source_paths),
            "counts": {
                "roots": len(self.roots),
                "families": len(self.families),
                "stacks": len(self.stacks),
                "constraints": len(self.constraints),
                "profiles": len(self.profiles),
                "layers": len(self.layers),
                "features": len(self.features),
            },
            "profiles": list(self.profiles),
            "families": list(self.families),
            "backends": list(self.backend_support),
        }


def load_oracle_specs(
    spec_root: str | Path | None = None,
    *,
    strict: bool = True,
) -> OracleSpecs:
    """Load and validate all oracle specs under ``tools/oracle/specs``."""

    root = SPEC_ROOT if spec_root is None else Path(spec_root)
    if not root.exists():
        raise SpecValidationError(f"oracle spec root does not exist: {root}")
    if not root.is_dir():
        raise SpecValidationError(f"oracle spec root must be a directory: {root}")

    stacks_path = root / "stacks.yaml"
    profiles_path = root / "profiles.yaml"
    layer_paths = tuple(sorted((root / "layers").glob("*.yaml")))
    feature_paths = tuple(sorted((root / "features").glob("*.yaml")))

    if not layer_paths:
        raise SpecValidationError(f"no layer specs found under {root / 'layers'}")
    if not feature_paths:
        raise SpecValidationError(f"no feature specs found under {root / 'features'}")

    stacks_doc = _load_yaml_object(stacks_path)
    profiles_doc = _load_yaml_object(profiles_path)

    roots: dict[str, RootSpec] = {}
    families: dict[str, FamilySpec] = {}
    stacks: dict[str, StackSpec] = {}
    constraints: dict[str, StackConstraint] = {}
    stack_backend_support = _load_stacks(
        stacks_doc,
        stacks_path,
        roots=roots,
        families=families,
        stacks=stacks,
        constraints=constraints,
        require_collections=True,
    )
    stack_fragment_paths = tuple(sorted((root / "stacks.d").glob("*.yaml")))
    for fragment_path in stack_fragment_paths:
        # Per-protocol stack-grammar fragments extend the monolithic
        # stacks.yaml with the same schema (any of roots/families/stacks/
        # constraints). Entries merge into the same collections, and
        # _insert_unique rejects any duplicate name across files rather than
        # silently overriding. A missing stacks.d/ directory yields no
        # fragments, preserving back-compatibility.
        _load_stacks(
            _load_yaml_object(fragment_path),
            fragment_path,
            roots=roots,
            families=families,
            stacks=stacks,
            constraints=constraints,
            require_collections=False,
        )

    profiles, profile_backend_support = _load_profiles(profiles_doc, profiles_path)

    layers: dict[str, LayerSpec] = {}
    for path in layer_paths:
        layer = _load_layer(_load_yaml_object(path), path)
        _insert_unique(layers, layer.name, layer, path, "layer")

    features: dict[str, FeatureSpec] = {}
    for path in feature_paths:
        feature = _load_feature(_load_yaml_object(path), path)
        _insert_unique(features, feature.name, feature, path, "feature")

    if strict:
        _validate_cross_references(
            root=Path(root),
            roots=roots,
            families=families,
            stacks=stacks,
            constraints=constraints,
            profiles=profiles,
            layers=layers,
            features=features,
        )
        _validate_backend_mappings(
            root=Path(root),
            stack_backend_support=stack_backend_support,
            profile_backend_support=profile_backend_support,
            layers=layers,
            features=features,
        )

    backend_support = _merge_backend_support(
        stack_backend_support,
        profile_backend_support,
        *(layer.backend_support for layer in layers.values()),
        *(feature.backend_support for feature in features.values()),
    )
    source_paths = tuple(
        _source_path(path)
        for path in (
            stacks_path,
            *stack_fragment_paths,
            profiles_path,
            *layer_paths,
            *feature_paths,
        )
    )
    return OracleSpecs(
        roots=roots,
        families=families,
        stacks=stacks,
        constraints=constraints,
        profiles=profiles,
        layers=layers,
        features=features,
        backend_support=backend_support,
        source_paths=source_paths,
    )


def _source_path(path: Path) -> str:
    """Return a repo-relative spec path, or the absolute path when external.

    Spec roots normally live under ``REPO_ROOT``, but the loader also accepts a
    caller-supplied spec root (e.g. a temporary directory in tests). Fall back
    to the absolute path so an external root never raises ``ValueError``.
    """

    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _load_stacks(
    document: JSONObject,
    path: Path,
    *,
    roots: dict[str, RootSpec],
    families: dict[str, FamilySpec],
    stacks: dict[str, StackSpec],
    constraints: dict[str, StackConstraint],
    require_collections: bool,
) -> dict[str, BackendSupport]:
    """Parse one stack-grammar document, merging entries into shared maps.

    The monolithic ``stacks.yaml`` (``require_collections=True``) must declare
    ``roots``/``families``/``stacks``; per-protocol fragments under
    ``stacks.d/*.yaml`` (``require_collections=False``) may declare any subset.
    Duplicate root/family/stack/constraint names across files raise via
    ``_insert_unique`` rather than silently overriding.
    """

    _validate_header(document, path, kind="stack_grammar")
    list_for = _required_list if require_collections else _optional_list

    for index, item in enumerate(list_for(document, "roots", path)):
        item_obj = _object(item, path, f"roots[{index}]")
        root = RootSpec(
            name=_required_name(item_obj, "name", path, f"roots[{index}]", allow_colon=True),
            layers=_required_name_tuple(item_obj, "layers", path, f"roots[{index}]"),
            families=_required_name_tuple(item_obj, "families", path, f"roots[{index}]"),
        )
        _insert_unique(roots, root.name, root, path, "root")

    for index, item in enumerate(list_for(document, "families", path)):
        item_obj = _object(item, path, f"families[{index}]")
        family = FamilySpec(
            name=_required_name(item_obj, "name", path, f"families[{index}]"),
            default_stack=_required_name_tuple(
                item_obj,
                "default_stack",
                path,
                f"families[{index}]",
            ),
            feature_tags=_required_name_tuple(
                item_obj,
                "feature_tags",
                path,
                f"families[{index}]",
            ),
        )
        _insert_unique(families, family.name, family, path, "family")

    for index, item in enumerate(list_for(document, "stacks", path)):
        item_obj = _object(item, path, f"stacks[{index}]")
        stack = StackSpec(
            name=_required_name(item_obj, "name", path, f"stacks[{index}]"),
            root=_required_name(item_obj, "root", path, f"stacks[{index}]", allow_colon=True),
            layers=_required_name_tuple(item_obj, "layers", path, f"stacks[{index}]"),
            coverage_cases=_optional_name_tuple(
                item_obj,
                "coverage_cases",
                path,
                f"stacks[{index}]",
            ),
        )
        _insert_unique(stacks, stack.name, stack, path, "stack")

    for index, item in enumerate(_optional_list(document, "constraints", path)):
        item_obj = _object(item, path, f"constraints[{index}]")
        constraint = StackConstraint(
            name=_required_name(item_obj, "name", path, f"constraints[{index}]"),
            parent=_required_name(item_obj, "parent", path, f"constraints[{index}]"),
            children=_required_name_tuple(item_obj, "children", path, f"constraints[{index}]"),
        )
        _insert_unique(constraints, constraint.name, constraint, path, "constraint")

    return _backend_support(document, path)


def _load_profiles(
    document: JSONObject,
    path: Path,
) -> tuple[dict[str, ProfileSpec], dict[str, BackendSupport]]:
    _validate_header(document, path, kind="profiles")
    profiles: dict[str, ProfileSpec] = {}
    for index, item in enumerate(_required_list(document, "profiles", path)):
        item_obj = _object(item, path, f"profiles[{index}]")
        profile_name = _required_name(item_obj, "name", path, f"profiles[{index}]")
        weights = tuple(
            _sampling_weight(weight, path, f"profiles[{index}].family_weights[{weight_index}]")
            for weight_index, weight in enumerate(
                _required_list(item_obj, "family_weights", path, f"profiles[{index}]")
            )
        )
        payload_length_obj = _required_object(
            item_obj,
            "payload_length",
            path,
            f"profiles[{index}]",
        )
        payload_length = PayloadLength(
            minimum=_required_int(payload_length_obj, "min", path, f"profiles[{index}].payload_length"),
            maximum=_required_int(payload_length_obj, "max", path, f"profiles[{index}].payload_length"),
        )
        if payload_length.minimum > payload_length.maximum:
            raise SpecValidationError(
                f"{path}: profiles[{index}].payload_length min exceeds max"
            )
        feature_weights = _int_mapping(
            _required_object(item_obj, "feature_weights", path, f"profiles[{index}]"),
            path,
            f"profiles[{index}].feature_weights",
        )
        profile = ProfileSpec(
            name=profile_name,
            purpose=_required_string(item_obj, "purpose", path, f"profiles[{index}]"),
            default_count=_required_positive_int(
                item_obj,
                "default_count",
                path,
                f"profiles[{index}]",
            ),
            family_weights=weights,
            payload_length=payload_length,
            feature_weights=feature_weights,
        )
        _insert_unique(profiles, profile.name, profile, path, "profile")
    return profiles, _backend_support(document, path)


def _load_layer(document: JSONObject, path: Path) -> LayerSpec:
    _validate_header(document, path, kind="layer")
    fields: list[LayerField] = []
    for index, item in enumerate(_required_list(document, "fields", path)):
        item_obj = _object(item, path, f"fields[{index}]")
        field_spec = LayerField(
            name=_required_name(item_obj, "name", path, f"fields[{index}]"),
            field_type=_required_name(item_obj, "type", path, f"fields[{index}]"),
            required=_required_bool(item_obj, "required", path, f"fields[{index}]"),
            domains=tuple(
                to_jsonable(value)
                for value in _required_list(item_obj, "domains", path, f"fields[{index}]")
            ),
        )
        fields.append(field_spec)
    return LayerSpec(
        name=_required_name(document, "name", path, "document"),
        summary=_required_string(document, "summary", path, "document"),
        roots=_required_name_tuple(document, "roots", path, "document", allow_empty=True),
        parents=_required_name_tuple(document, "parents", path, "document", allow_empty=True),
        children=_required_name_tuple(document, "children", path, "document", allow_empty=True),
        fields=tuple(fields),
        coverage_cases=_required_name_tuple(document, "coverage_cases", path, "document"),
        backend_support=_backend_support(document, path),
        raw=document,
    )


def _load_feature(document: JSONObject, path: Path) -> FeatureSpec:
    _validate_header(document, path, kind="feature")
    return FeatureSpec(
        name=_required_name(document, "name", path, "document"),
        summary=_required_string(document, "summary", path, "document"),
        layers=_required_name_tuple(document, "layers", path, "document"),
        directions=_required_name_tuple(document, "directions", path, "document"),
        strict_bytes=_required_bool(document, "strict_bytes", path, "document"),
        malformed=_required_bool(document, "malformed", path, "document"),
        coverage_cases=_required_name_tuple(document, "coverage_cases", path, "document"),
        backend_support=_backend_support(document, path),
        raw=document,
    )


def _sampling_weight(value: object, path: Path, context: str) -> SamplingWeight:
    item = _object(value, path, context)
    weight = _required_int(item, "weight", path, context)
    if weight < 0:
        raise SpecValidationError(f"{path}: {context}.weight must be non-negative")
    return SamplingWeight(
        name=_required_name(item, "name", path, context),
        weight=weight,
    )


def _backend_support(document: Mapping[str, object], path: Path) -> dict[str, BackendSupport]:
    support_obj = document.get("backend_support", {})
    if support_obj is None:
        return {}
    support = _object(support_obj, path, "backend_support")
    output: dict[str, BackendSupport] = {}
    for raw_backend, raw_value in support.items():
        backend_name = _normalize_name(raw_backend, path, "backend_support backend")
        value = _object(raw_value, path, f"backend_support.{backend_name}")
        status = _required_string(value, "status", path, f"backend_support.{backend_name}")
        if status not in BACKEND_SUPPORT_STATUSES:
            supported = ", ".join(BACKEND_SUPPORT_STATUSES)
            raise SpecValidationError(
                f"{path}: backend_support.{backend_name}.status must be one of {supported}"
            )
        metadata = {
            key: item
            for key, item in value.items()
            if key
            not in {
                "status",
                "native_layers",
                "notes",
                *BACKEND_CAPABILITY_KEYS,
            }
        }
        backend_support = BackendSupport(
            name=backend_name,
            status=status,
            encode=_optional_bool(value, "encode", path, f"backend_support.{backend_name}"),
            decode=_optional_bool(value, "decode", path, f"backend_support.{backend_name}"),
            pcap_read=_optional_bool(value, "pcap_read", path, f"backend_support.{backend_name}"),
            pcap_write=_optional_bool(value, "pcap_write", path, f"backend_support.{backend_name}"),
            live_endpoint=_optional_bool(
                value,
                "live_endpoint",
                path,
                f"backend_support.{backend_name}",
            ),
            native_layers=_optional_name_tuple(
                value,
                "native_layers",
                path,
                f"backend_support.{backend_name}",
                preserve_case=True,
            ),
            notes=_optional_string_tuple(value, "notes", path, f"backend_support.{backend_name}"),
            metadata=_json_object(to_jsonable(metadata), path, f"backend_support.{backend_name}.metadata"),
        )
        _validate_backend_support_entry(
            backend_support,
            path,
            f"backend_support.{backend_name}",
        )
        output[backend_name] = backend_support
    return output


def _merge_backend_support(
    *support_maps: Mapping[str, BackendSupport],
) -> dict[str, BackendSupport]:
    merged: dict[str, BackendSupport] = {}
    for support in support_maps:
        for name, item in support.items():
            existing = merged.get(name)
            if existing is None:
                merged[name] = item
                continue
            merged[name] = BackendSupport(
                name=name,
                status=_merge_status(existing.status, item.status),
                encode=existing.encode or item.encode,
                decode=existing.decode or item.decode,
                pcap_read=existing.pcap_read or item.pcap_read,
                pcap_write=existing.pcap_write or item.pcap_write,
                live_endpoint=existing.live_endpoint or item.live_endpoint,
                native_layers=tuple(
                    dict.fromkeys([*existing.native_layers, *item.native_layers])
                ),
                notes=tuple(dict.fromkeys([*existing.notes, *item.notes])),
                metadata={**existing.metadata, **item.metadata},
            )
    return merged


def _merge_status(left: str, right: str) -> str:
    order = {"planned": 0, "partial": 1, "supported": 2}
    if order.get(right, -1) > order.get(left, -1):
        return right
    return left


def _validate_cross_references(
    *,
    root: Path,
    roots: Mapping[str, RootSpec],
    families: Mapping[str, FamilySpec],
    stacks: Mapping[str, StackSpec],
    constraints: Mapping[str, StackConstraint],
    profiles: Mapping[str, ProfileSpec],
    layers: Mapping[str, LayerSpec],
    features: Mapping[str, FeatureSpec],
) -> None:
    known_layer_names = _known_layer_names(roots, layers)
    adjacency = _layer_adjacency(layers, constraints, known_layer_names, root)

    for stack in stacks.values():
        if stack.root not in roots:
            raise SpecValidationError(
                f"{root / 'stacks.yaml'}: stack {stack.name} references unknown root {stack.root}"
            )
        if not stack.layers:
            raise SpecValidationError(f"{root / 'stacks.yaml'}: stack {stack.name} has no layers")
        if stack.layers[0] not in roots[stack.root].layers:
            raise SpecValidationError(
                f"{root / 'stacks.yaml'}: stack {stack.name} starts with "
                f"{stack.layers[0]}, which is not declared by root {stack.root}"
            )
        _validate_layer_sequence(
            root / "stacks.yaml",
            f"stack {stack.name}",
            stack.layers,
            known_layer_names,
            adjacency,
        )

    for family in families.values():
        if not family.default_stack:
            raise SpecValidationError(
                f"{root / 'stacks.yaml'}: family {family.name} has an empty default_stack"
            )
        _validate_layer_sequence(
            root / "stacks.yaml",
            f"family {family.name}.default_stack",
            family.default_stack,
            known_layer_names,
            adjacency,
        )

    for profile in profiles.values():
        if not profile.family_weights:
            raise SpecValidationError(
                f"{root / 'profiles.yaml'}: profile {profile.name} has no family weights"
            )
        weight_names: set[str] = set()
        for weight in profile.family_weights:
            if weight.name in weight_names:
                raise SpecValidationError(
                    f"{root / 'profiles.yaml'}: profile {profile.name} duplicates "
                    f"family weight {weight.name}"
                )
            weight_names.add(weight.name)
            if weight.name not in families:
                raise SpecValidationError(
                    f"{root / 'profiles.yaml'}: profile {profile.name} references "
                    f"unknown family {weight.name}"
                )
        if sum(weight.weight for weight in profile.family_weights) <= 0:
            raise SpecValidationError(
                f"{root / 'profiles.yaml'}: profile {profile.name} has no positive family weights"
            )
        if not profile.feature_weights:
            raise SpecValidationError(
                f"{root / 'profiles.yaml'}: profile {profile.name} has no feature weights"
            )
        if sum(profile.feature_weights.values()) <= 0:
            raise SpecValidationError(
                f"{root / 'profiles.yaml'}: profile {profile.name} has no positive feature weights"
            )

    for layer in layers.values():
        for root_name in layer.roots:
            if root_name not in roots:
                raise SpecValidationError(
                    f"{root / 'layers'}: layer {layer.name} references unknown root {root_name}"
                )
        for parent in layer.parents:
            if parent == "root":
                continue
            if parent not in known_layer_names:
                raise SpecValidationError(
                    f"{root / 'layers'}: layer {layer.name} references unknown parent {parent}"
                )
        for child in layer.children:
            if child not in known_layer_names:
                raise SpecValidationError(
                    f"{root / 'layers'}: layer {layer.name} references unknown child {child}"
                )

    for feature in features.values():
        _validate_feature_references(
            root=root,
            feature=feature,
            roots=roots,
            known_layer_names=known_layer_names,
        )


def _known_layer_names(
    roots: Mapping[str, RootSpec],
    layers: Mapping[str, LayerSpec],
) -> set[str]:
    known_layer_names = set(layers)
    for root_spec in roots.values():
        known_layer_names.update(root_spec.layers)
    for layer in layers.values():
        known_layer_names.update(layer.parents)
        known_layer_names.update(layer.children)
        for extension in _extension_layer_names(layer):
            known_layer_names.add(extension)
    known_layer_names.discard("root")
    return known_layer_names


def _extension_layer_names(layer: LayerSpec) -> tuple[str, ...]:
    names: list[str] = []
    raw_extensions = layer.raw.get("extension_layers", [])
    if not isinstance(raw_extensions, list):
        return ()
    for extension in raw_extensions:
        if not isinstance(extension, Mapping):
            continue
        name = extension.get("name")
        if isinstance(name, str):
            names.append(name.strip().lower())
    return tuple(name for name in names if name)


def _layer_adjacency(
    layers: Mapping[str, LayerSpec],
    constraints: Mapping[str, StackConstraint],
    known_layer_names: set[str],
    root: Path,
) -> dict[str, set[str]]:
    adjacency: dict[str, set[str]] = {
        layer.name: set(layer.children) for layer in layers.values()
    }
    for constraint in constraints.values():
        if constraint.parent not in known_layer_names:
            raise SpecValidationError(
                f"{root / 'stacks.yaml'}: constraint {constraint.name} references "
                f"unknown parent {constraint.parent}"
            )
        for child in constraint.children:
            if child not in known_layer_names:
                raise SpecValidationError(
                    f"{root / 'stacks.yaml'}: constraint {constraint.name} references "
                    f"unknown child {child}"
                )
        adjacency.setdefault(constraint.parent, set()).update(constraint.children)
    return adjacency


def _validate_layer_sequence(
    path: Path,
    context: str,
    sequence: Sequence[str],
    known_layer_names: set[str],
    adjacency: Mapping[str, set[str]],
) -> None:
    for layer_name in sequence:
        if layer_name not in known_layer_names:
            raise SpecValidationError(
                f"{path}: {context} references unknown layer {layer_name}"
            )
    for parent, child in zip(sequence, sequence[1:]):
        allowed_children = adjacency.get(parent)
        if allowed_children is not None and child not in allowed_children:
            raise SpecValidationError(
                f"{path}: {context} has unsupported child {child} after {parent}"
            )


def _validate_feature_references(
    *,
    root: Path,
    feature: FeatureSpec,
    roots: Mapping[str, RootSpec],
    known_layer_names: set[str],
) -> None:
    for layer_name in feature.layers:
        if layer_name not in known_layer_names:
            raise SpecValidationError(
                f"{root / 'features'}: feature {feature.name} references "
                f"unknown layer {layer_name}"
            )
    for direction in feature.directions:
        _validate_feature_direction(root / "features", feature.name, direction)
    _validate_feature_supported_cases(
        root=root,
        feature=feature,
        roots=roots,
    )


def _validate_feature_direction(path: Path, feature_name: str, direction: str) -> None:
    if direction not in FEATURE_DIRECTIONS:
        supported = ", ".join(FEATURE_DIRECTIONS)
        raise SpecValidationError(
            f"{path}: feature {feature_name} references unknown direction {direction}; "
            f"supported: {supported}"
        )


def _validate_feature_supported_cases(
    *,
    root: Path,
    feature: FeatureSpec,
    roots: Mapping[str, RootSpec],
) -> None:
    path = root / "features"
    for index, raw_case in enumerate(_optional_list(feature.raw, "supported_cases", path)):
        case = _object(raw_case, path, f"feature {feature.name}.supported_cases[{index}]")
        case_name = _optional_case_name(case, index)

        if "direction" in case:
            _validate_feature_direction(
                path,
                f"{feature.name}.{case_name}",
                _normalize_name(
                    case["direction"],
                    path,
                    f"feature {feature.name}.supported_cases[{index}].direction",
                ),
            )
        for direction in _optional_name_tuple(
            case,
            "directions",
            path,
            f"feature {feature.name}.supported_cases[{index}]",
        ):
            _validate_feature_direction(path, f"{feature.name}.{case_name}", direction)

        for file_format in _case_file_formats(case, path, feature.name, index):
            if file_format not in PCAP_FILE_FORMATS:
                supported = ", ".join(PCAP_FILE_FORMATS)
                raise SpecValidationError(
                    f"{path}: feature {feature.name}.{case_name} references "
                    f"unknown file format {file_format}; supported: {supported}"
                )

        for root_name in _optional_name_tuple(
            case,
            "roots",
            path,
            f"feature {feature.name}.supported_cases[{index}]",
        ):
            if root_name not in roots:
                raise SpecValidationError(
                    f"{path}: feature {feature.name}.{case_name} references "
                    f"unknown root {root_name}"
                )

        if "writer" in case:
            writer = _normalize_name(
                case["writer"],
                path,
                f"feature {feature.name}.supported_cases[{index}].writer",
            )
            _validate_case_backend_role(
                path=path,
                feature=feature,
                case_name=case_name,
                backend_name=writer,
                capability="pcap_write" if _case_uses_pcap(case) else "encode",
                role="writer",
            )
        if "reader" in case:
            reader = _normalize_name(
                case["reader"],
                path,
                f"feature {feature.name}.supported_cases[{index}].reader",
            )
            _validate_case_backend_role(
                path=path,
                feature=feature,
                case_name=case_name,
                backend_name=reader,
                capability="pcap_read" if _case_uses_pcap(case) else "decode",
                role="reader",
            )


def _optional_case_name(case: Mapping[str, object], index: int) -> str:
    name = case.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip().lower()
    return f"case[{index}]"


def _case_file_formats(
    case: Mapping[str, object],
    path: Path,
    feature_name: str,
    index: int,
) -> tuple[str, ...]:
    formats: list[str] = []
    if "file_format" in case:
        formats.append(
            _normalize_name(
                case["file_format"],
                path,
                f"feature {feature_name}.supported_cases[{index}].file_format",
            )
        )
    formats.extend(
        _optional_name_tuple(
            case,
            "file_formats",
            path,
            f"feature {feature_name}.supported_cases[{index}]",
        )
    )
    return tuple(formats)


def _case_uses_pcap(case: Mapping[str, object]) -> bool:
    return "file_format" in case or "file_formats" in case


def _validate_case_backend_role(
    *,
    path: Path,
    feature: FeatureSpec,
    case_name: str,
    backend_name: str,
    capability: str,
    role: str,
) -> None:
    if backend_name not in feature.backend_support:
        raise SpecValidationError(
            f"{path}: feature {feature.name}.{case_name} {role} backend "
            f"{backend_name} has no backend_support mapping"
        )
    backend = _backend_registration(backend_name, path, f"feature {feature.name}.{case_name}.{role}")
    _validate_backend_capability(
        backend=backend,
        capability=capability,
        path=path,
        context=f"feature {feature.name}.{case_name}.{role}",
    )


def _validate_backend_mappings(
    *,
    root: Path,
    stack_backend_support: Mapping[str, BackendSupport],
    profile_backend_support: Mapping[str, BackendSupport],
    layers: Mapping[str, LayerSpec],
    features: Mapping[str, FeatureSpec],
) -> None:
    if not stack_backend_support:
        raise SpecValidationError(f"{root / 'stacks.yaml'}: backend_support is required")
    if not profile_backend_support:
        raise SpecValidationError(f"{root / 'profiles.yaml'}: backend_support is required")
    for layer in layers.values():
        if not layer.backend_support:
            raise SpecValidationError(
                f"{root / 'layers'}: layer {layer.name} is missing backend_support"
            )
    for feature in features.values():
        if not feature.backend_support:
            raise SpecValidationError(
                f"{root / 'features'}: feature {feature.name} is missing backend_support"
            )


def _validate_backend_support_entry(
    support: BackendSupport,
    path: Path,
    context: str,
) -> None:
    backend = _backend_registration(support.name, path, context)
    for capability in BACKEND_CAPABILITY_KEYS:
        if not bool(getattr(support, capability)):
            continue
        _validate_backend_capability(
            backend=backend,
            capability=capability,
            path=path,
            context=f"{context}.{capability}",
        )


def _backend_registration(
    backend_name: str,
    path: Path,
    context: str,
) -> BackendRegistration:
    try:
        return get_backend_capability_registration(backend_name)
    except ValueError as exc:
        supported = ", ".join(registered_backend_capability_names())
        raise SpecValidationError(
            f"{path}: {context} references unknown backend {backend_name}; "
            f"supported: {supported}"
        ) from exc


def _validate_backend_capability(
    *,
    backend: BackendRegistration,
    capability: str,
    path: Path,
    context: str,
) -> None:
    if capability not in BACKEND_CAPABILITY_KEYS:
        raise SpecValidationError(f"{path}: {context} references unknown capability {capability}")
    if backend.capabilities.supports(capability):  # type: ignore[arg-type]
        return
    if backend.parser_only and capability in {"encode", "pcap_write", "live_endpoint"}:
        raise SpecValidationError(
            f"{path}: {context} requests {capability} from parser-only backend "
            f"{backend.name}"
        )
    raise SpecValidationError(
        f"{path}: {context} requests unsupported capability {capability} from "
        f"backend {backend.name}"
    )


def _default_case_for_family(
    family: FamilySpec,
    stacks: Sequence[StackSpec] | object,
) -> str:
    for stack in stacks:
        if not isinstance(stack, StackSpec):
            continue
        if stack.layers == family.default_stack and stack.coverage_cases:
            return stack.coverage_cases[0]
    return "default"


def run_self_checks() -> tuple[str, ...]:
    """Exercise the valid spec set and focused invalid in-memory fixtures."""

    load_oracle_specs(strict=True)
    _expect_spec_validation_error(
        "invalid_stack_layer",
        _invalid_stack_layer_fixture,
    )
    _expect_spec_validation_error(
        "parser_only_writer",
        lambda: _validate_backend_support_entry(
            BackendSupport(name="wireshark", status="supported", encode=True),
            Path("<oracle-spec-self-check>"),
            "backend_support.wireshark",
        ),
    )
    return ("specs", "invalid_stack_layer", "parser_only_writer")


def _expect_spec_validation_error(name: str, check: Callable[[], None]) -> None:
    try:
        check()
    except SpecValidationError:
        return
    raise AssertionError(f"spec self-check did not reject {name}")


def _invalid_stack_layer_fixture() -> None:
    path = Path("<oracle-spec-self-check>")
    backend_support = {
        "scapy": BackendSupport(
            name="scapy",
            status="supported",
            encode=True,
            decode=True,
        )
    }
    roots = {
        "link:ethernet": RootSpec(
            name="link:ethernet",
            layers=("ethernet",),
            families=("ipv4",),
        )
    }
    families = {
        "ipv4": FamilySpec(
            name="ipv4",
            default_stack=("ethernet", "payload"),
            feature_tags=("baseline",),
        )
    }
    stacks = {
        "bad": StackSpec(
            name="bad",
            root="link:ethernet",
            layers=("ethernet", "missing"),
        )
    }
    profiles = {
        "smoke": ProfileSpec(
            name="smoke",
            purpose="self-check",
            default_count=1,
            family_weights=(SamplingWeight(name="ipv4", weight=1),),
            payload_length=PayloadLength(minimum=0, maximum=1),
            feature_weights={"baseline": 1},
            backend_support=backend_support,
        )
    }
    layers = {
        "ethernet": LayerSpec(
            name="ethernet",
            summary="self-check",
            roots=("link:ethernet",),
            parents=("root",),
            children=("payload",),
            fields=(),
            coverage_cases=("baseline",),
            backend_support=backend_support,
            raw={},
        )
    }
    _validate_cross_references(
        root=path,
        roots=roots,
        families=families,
        stacks=stacks,
        constraints={},
        profiles=profiles,
        layers=layers,
        features={},
    )


def _load_yaml_object(path: Path) -> JSONObject:
    if not path.exists():
        raise SpecValidationError(f"missing oracle spec file: {path}")
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise SpecValidationError(
            "PyYAML is required to load oracle specs; run through tools/oracle/run "
            "so uv can provide oracle Python dependencies"
        ) from exc

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return _json_object(to_jsonable(data), path, "document")


def _validate_header(document: Mapping[str, object], path: Path, *, kind: str) -> None:
    version = _required_int(document, "version", path, "document")
    if version != SUPPORTED_SPEC_VERSION:
        raise SpecValidationError(
            f"{path}: unsupported spec version {version}; expected {SUPPORTED_SPEC_VERSION}"
        )
    actual_kind = _required_string(document, "kind", path, "document")
    if actual_kind != kind:
        raise SpecValidationError(f"{path}: expected kind {kind}, got {actual_kind}")
    _required_name(document, "name", path, "document")


def _insert_unique(
    target: dict[str, Any],
    name: str,
    value: Any,
    path: Path,
    label: str,
) -> None:
    if name in target:
        raise SpecValidationError(f"{path}: duplicate {label} name {name}")
    target[name] = value


def _required_object(
    document: Mapping[str, object],
    key: str,
    path: Path,
    context: str,
) -> JSONObject:
    if key not in document:
        raise SpecValidationError(f"{path}: {context}.{key} is required")
    return _object(document[key], path, f"{context}.{key}")


def _required_list(
    document: Mapping[str, object],
    key: str,
    path: Path,
    context: str = "document",
) -> list[JSONValue]:
    if key not in document:
        raise SpecValidationError(f"{path}: {context}.{key} is required")
    value = document[key]
    if not isinstance(value, list):
        raise SpecValidationError(f"{path}: {context}.{key} must be a list")
    return value


def _optional_list(
    document: Mapping[str, object],
    key: str,
    path: Path,
    context: str = "document",
) -> list[JSONValue]:
    value = document.get(key, [])
    if not isinstance(value, list):
        raise SpecValidationError(f"{path}: {context}.{key} must be a list")
    return value


def _required_name_tuple(
    document: Mapping[str, object],
    key: str,
    path: Path,
    context: str,
    *,
    allow_empty: bool = False,
    preserve_case: bool = False,
) -> tuple[str, ...]:
    values = _required_list(document, key, path, context)
    if not allow_empty and not values:
        raise SpecValidationError(f"{path}: {context}.{key} must not be empty")
    return tuple(
        _normalize_name(value, path, f"{context}.{key}[{index}]", preserve_case=preserve_case)
        for index, value in enumerate(values)
    )


def _optional_name_tuple(
    document: Mapping[str, object],
    key: str,
    path: Path,
    context: str,
    *,
    preserve_case: bool = False,
) -> tuple[str, ...]:
    return tuple(
        _normalize_name(value, path, f"{context}.{key}[{index}]", preserve_case=preserve_case)
        for index, value in enumerate(_optional_list(document, key, path, context))
    )


def _optional_string_tuple(
    document: Mapping[str, object],
    key: str,
    path: Path,
    context: str,
) -> tuple[str, ...]:
    return tuple(
        _string(value, path, f"{context}.{key}[{index}]")
        for index, value in enumerate(_optional_list(document, key, path, context))
    )


def _required_name(
    document: Mapping[str, object],
    key: str,
    path: Path,
    context: str,
    *,
    allow_colon: bool = False,
    preserve_case: bool = False,
) -> str:
    return _normalize_name(
        _required_string(document, key, path, context),
        path,
        f"{context}.{key}",
        allow_colon=allow_colon,
        preserve_case=preserve_case,
    )


def _normalize_name(
    value: object,
    path: Path,
    context: str,
    *,
    allow_colon: bool = True,
    preserve_case: bool = False,
) -> str:
    name = _string(value, path, context).strip()
    if not name:
        raise SpecValidationError(f"{path}: {context} must not be empty")
    if not preserve_case:
        name = name.lower()
    if not allow_colon and ":" in name:
        raise SpecValidationError(f"{path}: {context} must not contain ':'")
    return name


def _required_string(
    document: Mapping[str, object],
    key: str,
    path: Path,
    context: str,
) -> str:
    if key not in document:
        raise SpecValidationError(f"{path}: {context}.{key} is required")
    return _string(document[key], path, f"{context}.{key}")


def _string(value: object, path: Path, context: str) -> str:
    if not isinstance(value, str):
        raise SpecValidationError(f"{path}: {context} must be a string")
    return value


def _required_int(
    document: Mapping[str, object],
    key: str,
    path: Path,
    context: str,
) -> int:
    if key not in document:
        raise SpecValidationError(f"{path}: {context}.{key} is required")
    value = document[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise SpecValidationError(f"{path}: {context}.{key} must be an integer")
    return value


def _required_positive_int(
    document: Mapping[str, object],
    key: str,
    path: Path,
    context: str,
) -> int:
    value = _required_int(document, key, path, context)
    if value < 1:
        raise SpecValidationError(f"{path}: {context}.{key} must be positive")
    return value


def _required_bool(
    document: Mapping[str, object],
    key: str,
    path: Path,
    context: str,
) -> bool:
    if key not in document:
        raise SpecValidationError(f"{path}: {context}.{key} is required")
    value = document[key]
    if not isinstance(value, bool):
        raise SpecValidationError(f"{path}: {context}.{key} must be a boolean")
    return value


def _optional_bool(
    document: Mapping[str, object],
    key: str,
    path: Path,
    context: str,
) -> bool:
    value = document.get(key, False)
    if not isinstance(value, bool):
        raise SpecValidationError(f"{path}: {context}.{key} must be a boolean")
    return value


def _int_mapping(
    document: Mapping[str, object],
    path: Path,
    context: str,
) -> dict[str, int]:
    output: dict[str, int] = {}
    for key, value in document.items():
        if not isinstance(key, str):
            raise SpecValidationError(f"{path}: {context} keys must be strings")
        if not isinstance(value, int) or isinstance(value, bool):
            raise SpecValidationError(f"{path}: {context}.{key} must be an integer")
        if value < 0:
            raise SpecValidationError(f"{path}: {context}.{key} must be non-negative")
        output[_normalize_name(key, path, f"{context}.{key}")] = value
    return output


def _object(value: object, path: Path, context: str) -> JSONObject:
    if not isinstance(value, Mapping):
        raise SpecValidationError(f"{path}: {context} must be an object")
    output: JSONObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise SpecValidationError(f"{path}: {context} object keys must be strings")
        output[key] = item  # type: ignore[assignment]
    return output


def _json_object(value: JSONValue, path: Path, context: str) -> JSONObject:
    if not isinstance(value, dict):
        raise SpecValidationError(f"{path}: {context} must be an object")
    return value
