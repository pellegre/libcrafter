"""Plugin-coverage baseline for the per-protocol oracle refactor.

This test reads the three stage registries (generator sampling, Scapy
encode/decode, Wireshark decode) and the spec layer set and makes the
migration's progress observable while it is still partial. Two directions are
checked:

* Strict from the start: every layer registered in any stage registry must be a
  real spec layer. This guards against stray or misnamed registrations the
  moment a protocol module is dropped in.
* Forward-looking and currently green: every spec layer not yet registered in
  :data:`SAMPLER_REGISTRY` must appear in :data:`KNOWN_UNMIGRATED`. The set is
  seeded below with the full current spec layer list, so the assertion passes
  today with no protocol migrated. As each Phase D step migrates a protocol it
  removes that protocol's layer(s) from :data:`KNOWN_UNMIGRATED`; the strict
  coverage step (44) deletes :data:`KNOWN_UNMIGRATED` entirely and asserts that
  no spec layer is missing.

The registries are imported through their ``protocols`` packages so the
package-level auto-discovery runs first; importing them must not require Scapy or
tshark, so the whole test stays offline and Scapy-free.
"""

from __future__ import annotations

import unittest

from tools.oracle.engine.backends.scapy.protocols import (
    SCAPY_REGISTRY,
    STACK_ENCODER_REGISTRY,
)
from tools.oracle.engine.backends.wireshark.protocols import WIRESHARK_REGISTRY
from tools.oracle.engine.protocols import SAMPLER_REGISTRY
from tools.oracle.engine.spec_loader import load_oracle_specs


# Spec layers that have not yet been migrated into the generator's sampler
# registry. Seeded with the full current spec layer set so the forward-looking
# coverage assertion passes today; each protocol migration step removes its
# layer(s) here, and step 44 deletes this set and asserts ``missing == set()``.
KNOWN_UNMIGRATED: frozenset[str] = frozenset(
    {
        "ah",
        "arp",
        "bgp",
        "ble_adv",
        "ble_radio",
        "dhcp",
        "dns",
        "dot11",
        "eapol",
        "esp",
        "ethernet",
        "icmp",
        "icmpv6",
        "igmp",
        "ikev2",
        "ipv4",
        "ipv6",
        "linux_cooked",
        "llc_snap",
        "null_loopback",
        "ospf",
        "payload",
        "radiotap",
        "rip",
        "ripng",
        "rsn",
        "tcp",
        "udp",
        "vlan",
    }
)


def _spec_layer_names() -> frozenset[str]:
    """Return the set of layer names declared under ``specs/layers/*.yaml``."""

    return frozenset(load_oracle_specs().layers)


class PluginCoverageTest(unittest.TestCase):
    def test_registries_importable_and_report_tuples(self) -> None:
        # Sanity: each name-keyed registry imported cleanly (Scapy-free) and
        # reports its registered layer names as a tuple.
        self.assertIsInstance(SAMPLER_REGISTRY.names(), tuple)
        self.assertIsInstance(SCAPY_REGISTRY.names(), tuple)
        self.assertIsInstance(WIRESHARK_REGISTRY.names(), tuple)
        # The whole-stack encoder registry is an ordered list of encoders.
        self.assertIsInstance(STACK_ENCODER_REGISTRY, list)

    def test_sampler_registrations_are_spec_layers(self) -> None:
        # Strict direction: no stray sampler registrations. Every registered
        # generator-stage layer must be a real spec layer.
        spec_layers = _spec_layer_names()
        stray = set(SAMPLER_REGISTRY.names()) - spec_layers
        self.assertEqual(
            stray,
            set(),
            msg=f"sampler registry has non-spec layers: {sorted(stray)}",
        )

    def test_scapy_registrations_are_spec_layers(self) -> None:
        # Strict direction for the Scapy encode/decode stage.
        spec_layers = _spec_layer_names()
        stray = set(SCAPY_REGISTRY.names()) - spec_layers
        self.assertEqual(
            stray,
            set(),
            msg=f"scapy registry has non-spec layers: {sorted(stray)}",
        )

    def test_wireshark_registrations_are_spec_layers(self) -> None:
        # Strict direction for the Wireshark decode stage.
        spec_layers = _spec_layer_names()
        stray = set(WIRESHARK_REGISTRY.names()) - spec_layers
        self.assertEqual(
            stray,
            set(),
            msg=f"wireshark registry has non-spec layers: {sorted(stray)}",
        )

    def test_known_unmigrated_only_lists_spec_layers(self) -> None:
        # KNOWN_UNMIGRATED must track real spec layers; a name that is not a spec
        # layer is a stale entry that should have been removed with its layer.
        spec_layers = _spec_layer_names()
        stale = KNOWN_UNMIGRATED - spec_layers
        self.assertEqual(
            stale,
            set(),
            msg=f"KNOWN_UNMIGRATED lists non-spec layers: {sorted(stale)}",
        )

    def test_unmigrated_layers_are_documented(self) -> None:
        # Forward-looking, currently green: every spec layer without a sampler
        # plugin must be accounted for in KNOWN_UNMIGRATED. As protocols migrate,
        # ``missing`` shrinks and KNOWN_UNMIGRATED shrinks with it; step 44 drops
        # the allowance entirely and requires ``missing == set()``.
        spec_layers = _spec_layer_names()
        missing = spec_layers - set(SAMPLER_REGISTRY.names())
        unexpected = missing - KNOWN_UNMIGRATED
        self.assertEqual(
            unexpected,
            set(),
            msg=(
                "spec layers are unregistered and not in KNOWN_UNMIGRATED: "
                f"{sorted(unexpected)}"
            ),
        )


if __name__ == "__main__":
    unittest.main()
