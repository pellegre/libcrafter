"""Strict plugin-coverage guarantees for the per-protocol oracle refactor.

With every protocol migrated and the legacy dispatchers removed, this test locks
in the plug-and-play outcome. It reads the three stage registries (generator
sampling, Scapy encode/decode, Wireshark decode) and the spec layer set and
asserts hard guarantees rather than tracking migration progress:

* Completeness: every spec layer has a registered :class:`ProtocolSampler`. There
  is no ``KNOWN_UNMIGRATED`` escape hatch any more.
* No stray registrations: every name in any stage registry is a real spec layer.
* ``supported_fields`` discipline: each sampler's ``supported_fields`` is a subset
  of the field names its layer declares in ``specs/layers/<layer>.yaml`` (a
  sampler never claims a field the spec does not declare). The gap, where present,
  is structural: fields the generator auto-fills (checksums, lengths, header
  lengths), sub-fields decomposed under a single spec field (e.g. dscp/ecn), nested
  records (DNS sections, IGMP/DHCP fixed-header fields), or behavior-driven layers
  that sample no fields directly (igmp, ble) and so carry ``frozenset()``.
* Backend coverage, derived from the specs' ``backend_support`` (not hardcoded):
  every layer whose Scapy backend is not ``unsupported`` is in
  :data:`SCAPY_REGISTRY`, and every layer that declares a ``wireshark`` backend is
  in :data:`WIRESHARK_REGISTRY`. Layers with no per-layer Wireshark path (e.g. BLE,
  IGMP, whole-packet/non-spec-name decoders) are legitimately absent and are not
  asserted into the Wireshark registry.
* Legacy structures: importing ``generator`` exposes no ``_SUPPORTED_FIELDS`` (the
  per-protocol field table removed once every layer migrated). The Scapy
  ``packets`` module's residual ``_SCAPY_LAYER_BY_LAYER`` /
  ``_SUPPORTED_FIELDS_BY_LAYER`` dicts still exist but hold only sub-layer entries
  (raw, IPv6 extension headers, IGMP sub-records), never a top-level spec layer.

The registries are imported through their ``protocols`` packages so the
package-level auto-discovery runs first; importing them — and ``generator`` and
``packets`` — must not require Scapy or tshark, so the whole test stays offline and
Scapy-free.
"""

from __future__ import annotations

import unittest

from tools.oracle.engine import generator
from tools.oracle.engine.backends.scapy import packets
from tools.oracle.engine.backends.scapy.protocols import (
    SCAPY_REGISTRY,
    STACK_ENCODER_REGISTRY,
)
from tools.oracle.engine.backends.wireshark.protocols import WIRESHARK_REGISTRY
from tools.oracle.engine.protocols import SAMPLER_REGISTRY
from tools.oracle.engine.spec_loader import OracleSpecs, load_oracle_specs


def _specs() -> OracleSpecs:
    return load_oracle_specs()


def _spec_layer_names() -> frozenset[str]:
    """Return the set of layer names declared under ``specs/layers/*.yaml``."""

    return frozenset(_specs().layers)


def _spec_field_names(specs: OracleSpecs, layer: str) -> frozenset[str]:
    """Return the field names declared for ``layer`` in its spec."""

    return frozenset(field.name for field in specs.layers[layer].fields)


class PluginCoverageTest(unittest.TestCase):
    def test_registries_importable_and_report_tuples(self) -> None:
        # Sanity: each name-keyed registry imported cleanly (Scapy-free) and
        # reports its registered layer names as a tuple.
        self.assertIsInstance(SAMPLER_REGISTRY.names(), tuple)
        self.assertIsInstance(SCAPY_REGISTRY.names(), tuple)
        self.assertIsInstance(WIRESHARK_REGISTRY.names(), tuple)
        # The whole-stack encoder registry is an ordered list of encoders.
        self.assertIsInstance(STACK_ENCODER_REGISTRY, list)

    def test_every_spec_layer_has_a_sampler(self) -> None:
        # Completeness: every spec layer is registered in the generator stage.
        # No KNOWN_UNMIGRATED allowance remains. Layers that sample no fields
        # directly (igmp, ble_radio, ble_adv are behavior-driven) are still
        # registered, with ``frozenset()`` supported_fields, so they are covered
        # here too.
        spec_layers = _spec_layer_names()
        missing = spec_layers - set(SAMPLER_REGISTRY.names())
        self.assertEqual(
            missing,
            set(),
            msg=f"spec layers without a registered sampler: {sorted(missing)}",
        )

    def test_sampler_registrations_are_spec_layers(self) -> None:
        # No stray sampler registrations: every registered generator-stage layer
        # is a real spec layer.
        spec_layers = _spec_layer_names()
        stray = set(SAMPLER_REGISTRY.names()) - spec_layers
        self.assertEqual(
            stray,
            set(),
            msg=f"sampler registry has non-spec layers: {sorted(stray)}",
        )

    def test_scapy_registrations_are_spec_layers(self) -> None:
        # No stray Scapy-stage registrations.
        spec_layers = _spec_layer_names()
        stray = set(SCAPY_REGISTRY.names()) - spec_layers
        self.assertEqual(
            stray,
            set(),
            msg=f"scapy registry has non-spec layers: {sorted(stray)}",
        )

    def test_wireshark_registrations_are_spec_layers(self) -> None:
        # No stray Wireshark-stage registrations.
        spec_layers = _spec_layer_names()
        stray = set(WIRESHARK_REGISTRY.names()) - spec_layers
        self.assertEqual(
            stray,
            set(),
            msg=f"wireshark registry has non-spec layers: {sorted(stray)}",
        )

    def test_sampler_supported_fields_within_spec(self) -> None:
        # supported_fields discipline: every sampler's supported_fields is a
        # subset of the field names its layer declares. A sampler must never claim
        # a field the spec does not declare. Where the sets are not equal the spec
        # declares additional generator-auto-filled, structurally decomposed, or
        # behavior-driven fields the sampler does not sample directly; that gap is
        # legitimate, but a superset (claiming an undeclared field) is a real bug.
        specs = _specs()
        offenders: dict[str, list[str]] = {}
        for layer in SAMPLER_REGISTRY.names():
            supported = SAMPLER_REGISTRY.require(layer).supported_fields
            extra = supported - _spec_field_names(specs, layer)
            if extra:
                offenders[layer] = sorted(extra)
        self.assertEqual(
            offenders,
            {},
            msg=(
                "samplers claim supported_fields not declared in their layer "
                f"spec: {offenders}"
            ),
        )

    def test_sampler_supported_fields_match_or_subset_is_structural(self) -> None:
        # Precise rule: for each sampler, supported_fields either equals the spec
        # field set (exact triplication-free coupling) or is a strict subset
        # (structural/auto-filled/behavior-driven gap). The empty middle ground —
        # a non-empty difference in BOTH directions — would mean the sampler and
        # spec disagree on field identity and is forbidden. At least some layers
        # must achieve exact equality, proving the field lists are genuinely
        # coupled to the specs rather than universally looser.
        specs = _specs()
        exact: list[str] = []
        for layer in SAMPLER_REGISTRY.names():
            supported = SAMPLER_REGISTRY.require(layer).supported_fields
            spec_fields = _spec_field_names(specs, layer)
            self.assertTrue(
                supported <= spec_fields,
                msg=(
                    f"{layer}: supported_fields is not a subset of spec fields; "
                    f"undeclared: {sorted(supported - spec_fields)}"
                ),
            )
            if supported == spec_fields:
                exact.append(layer)
        self.assertNotEqual(
            exact,
            [],
            msg=(
                "no layer's supported_fields exactly matches its spec field set; "
                "the spec-coupled field lists appear to have drifted entirely"
            ),
        )

    def test_scapy_registry_covers_spec_scapy_layers(self) -> None:
        # Backend coverage derived from the specs' backend_support, not a hardcoded
        # list: every spec layer whose Scapy backend is not declared unsupported
        # must have a Scapy-stage plugin.
        specs = _specs()
        registered = set(SCAPY_REGISTRY.names())
        missing: list[str] = []
        for layer, layer_spec in specs.layers.items():
            support = layer_spec.backend_support.get("scapy")
            if support is not None and support.status == "unsupported":
                continue
            if layer not in registered:
                missing.append(layer)
        self.assertEqual(
            sorted(missing),
            [],
            msg=f"spec layers with Scapy support but no Scapy plugin: {sorted(missing)}",
        )

    def test_wireshark_registry_covers_declared_layers(self) -> None:
        # Every layer that declares a wireshark backend in its spec must have a
        # Wireshark-stage plugin. Layers with no per-layer Wireshark path (BLE,
        # IGMP, whole-packet/non-spec-name decoders) declare no wireshark backend
        # and are legitimately absent — they are not asserted in.
        specs = _specs()
        registered = set(WIRESHARK_REGISTRY.names())
        missing: list[str] = []
        for layer, layer_spec in specs.layers.items():
            if "wireshark" not in layer_spec.backend_support:
                continue
            if layer not in registered:
                missing.append(layer)
        self.assertEqual(
            sorted(missing),
            [],
            msg=(
                "spec layers declaring a wireshark backend but missing a "
                f"Wireshark plugin: {sorted(missing)}"
            ),
        )

    def test_generator_legacy_field_table_removed(self) -> None:
        # The per-protocol field table was removed once every layer migrated
        # (step 40). Importing generator must expose no ``_SUPPORTED_FIELDS``.
        self.assertFalse(
            hasattr(generator, "_SUPPORTED_FIELDS"),
            msg="generator still exposes the removed _SUPPORTED_FIELDS table",
        )

    def test_scapy_packets_residue_holds_no_top_level_layer(self) -> None:
        # The Scapy ``packets`` module still carries ``_SCAPY_LAYER_BY_LAYER`` and
        # ``_SUPPORTED_FIELDS_BY_LAYER``, but only as sub-layer residue (raw, IPv6
        # extension headers, IGMP sub-records). No TOP-LEVEL spec layer may appear
        # in them — those are owned by the Scapy registry plugins now.
        spec_layers = _spec_layer_names()
        for attr in ("_SCAPY_LAYER_BY_LAYER", "_SUPPORTED_FIELDS_BY_LAYER"):
            table = getattr(packets, attr, None)
            self.assertIsNotNone(
                table, msg=f"packets.{attr} unexpectedly missing"
            )
            top_level = set(table) & spec_layers
            self.assertEqual(
                top_level,
                set(),
                msg=(
                    f"packets.{attr} still holds top-level spec layers (should be "
                    f"sub-layers only): {sorted(top_level)}"
                ),
            )


if __name__ == "__main__":
    unittest.main()
