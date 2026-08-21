"""Offline oracle coverage for NTP specs, generation, and backend guards."""

from __future__ import annotations

import types
import unittest

from tools.oracle.engine.backends.scapy.protocols import SCAPY_REGISTRY
from tools.oracle.engine.backends.scapy.protocols import ntp as ntp_scapy
from tools.oracle.engine.backends.wireshark import normalize as wireshark_normalize
from tools.oracle.engine.backends.wireshark.protocols import WIRESHARK_REGISTRY
from tools.oracle.engine.backends.wireshark.protocols import ntp as ntp_wireshark
from tools.oracle.engine.generator import generate_plans
from tools.oracle.engine.protocols import SAMPLER_REGISTRY
from tools.oracle.engine.spec_loader import load_oracle_specs


_SEED = 8300
_NTP_SUPPORTED_FIELDS = frozenset(
    {
        "leap_indicator",
        "version",
        "mode",
        "stratum",
        "poll",
        "precision",
        "root_delay",
        "root_dispersion",
        "reference_id",
        "reference_timestamp",
        "origin_timestamp",
        "receive_timestamp",
        "transmit_timestamp",
        "extension_fields",
        "legacy_mac",
    }
)

_StubNoPayload = type("NoPayload", (), {})
_StubRaw = type("Raw", (types.SimpleNamespace,), {})
_StubUdp = type("UDP", (types.SimpleNamespace,), {})


def _ntp_plan(case: str, feature: str, *, root: str = "l3:ipv4-ntp"):
    plans = generate_plans(
        seed=_SEED,
        profile="ntp-smoke",
        count=1,
        backend="scapy",
        root=root,
        family="ntp",
        case=case,
        feature=feature,
        direction="backend_to_libcrafter",
    )
    assert len(plans) == 1
    return plans[0]


def _udp_packet(payload: bytes, *, sport: int = 49152, dport: int = 123) -> object:
    return _StubUdp(
        sport=sport,
        dport=dport,
        payload=_StubRaw(load=payload, payload=_StubNoPayload()),
    )


class NtpOracleSpecTest(unittest.TestCase):
    def test_specs_declare_ntp_layer_features_profiles_and_stacks(self) -> None:
        specs = load_oracle_specs()

        self.assertIn("ntp", specs.layers)
        layer = specs.layers["ntp"]
        self.assertIn("udp", layer.parents)
        self.assertIn("ntp-v4-client-request", layer.coverage_cases)
        self.assertIn("ntp-nts-extension-bytes", layer.coverage_cases)
        self.assertEqual(layer.backend_support["scapy"].status, "supported")
        self.assertEqual(layer.backend_support["wireshark"].status, "supported")
        self.assertEqual(layer.backend_support["libcrafter"].status, "supported")

        for feature_name in ("ntp_header", "ntp_extensions", "ntp_nts"):
            with self.subTest(feature=feature_name):
                feature = specs.features[feature_name]
                self.assertIn("ntp", feature.layers)
                self.assertIn("udp", feature.layers)
                self.assertTrue(feature.strict_bytes)

        for profile_name in ("ntp-smoke", "ntp-ci"):
            self.assertIn(profile_name, specs.profiles)
        self.assertIn("ntp", specs.families)

        self.assertEqual(specs.stacks["ipv4_udp_ntp"].layers, ("ipv4", "udp", "ntp"))
        self.assertEqual(specs.stacks["ipv4_udp_ntp"].root, "l3:ipv4-ntp")
        self.assertEqual(specs.stacks["ipv6_udp_ntp"].layers, ("ipv6", "udp", "ntp"))
        self.assertEqual(specs.stacks["ipv6_udp_ntp"].root, "l3:ipv6-ntp")

    def test_sampler_and_backend_plugins_match_ntp_field_surface(self) -> None:
        layer_fields = {
            field.name for field in load_oracle_specs().layers["ntp"].fields
        }

        sampler = SAMPLER_REGISTRY.require("ntp")
        self.assertEqual(sampler.supported_fields, _NTP_SUPPORTED_FIELDS)
        self.assertLessEqual(sampler.supported_fields, layer_fields)

        scapy = SCAPY_REGISTRY.require("ntp")
        self.assertEqual(scapy.scapy_class, "Raw")
        self.assertIn("payload_hex", scapy.supported_fields)
        self.assertIn("extension_fields", scapy.supported_fields)
        self.assertIsNotNone(scapy.normalize)

        wireshark = WIRESHARK_REGISTRY.require("ntp")
        self.assertIn("version", wireshark.tshark_aliases)
        self.assertEqual(wireshark_normalize._PROTOCOL_LAYER_ALIASES["ntp"], "ntp")


class NtpGeneratorTest(unittest.TestCase):
    def test_seeded_ntp_generation_is_deterministic_and_uses_ntp_stacks(self) -> None:
        first = generate_plans(
            seed=_SEED, profile="ntp-smoke", count=8, backend="scapy"
        )
        second = generate_plans(
            seed=_SEED, profile="ntp-smoke", count=8, backend="scapy"
        )

        self.assertEqual(
            [plan.to_dict() for plan in first], [plan.to_dict() for plan in second]
        )
        self.assertTrue({plan.case for plan in first})

        for plan in first:
            with self.subTest(case=plan.case, stack=plan.stack):
                self.assertEqual(plan.stack[-2:], ["udp", "ntp"])
                self.assertEqual(plan.family, "ntp")
                self.assertTrue(str(plan.metadata.get("feature")).startswith("ntp_"))
                self.assertIn(
                    123,
                    {plan.fields["udp"]["src_port"], plan.fields["udp"]["dst_port"]},
                )
                self.assertIn("ntp", plan.fields)

    def test_explicit_header_plan_matches_documentation_address_udp_context(
        self,
    ) -> None:
        plan = _ntp_plan("ntp-header-client-request", "ntp_header")

        self.assertEqual(plan.stack, ["ipv4", "udp", "ntp"])
        self.assertEqual(plan.metadata["root"], "l3:ipv4-ntp")
        self.assertEqual(plan.fields["ipv4"]["src"], "192.0.2.10")
        self.assertEqual(plan.fields["ipv4"]["dst"], "198.51.100.123")
        self.assertEqual(plan.fields["udp"]["src_port"], 49152)
        self.assertEqual(plan.fields["udp"]["dst_port"], 123)
        self.assertEqual(plan.fields["ntp"]["mode"], "client")
        self.assertTrue(plan.strict_bytes)


class NtpScapyBackendTest(unittest.TestCase):
    def test_materializer_serializes_fixed_header_golden_payload(self) -> None:
        plan = _ntp_plan("ntp-header-client-request", "ntp_header")
        payload = ntp_scapy._ntp_message_bytes(plan.fields)

        self.assertEqual(
            payload.hex(),
            (
                "230006ec00010000000200004c4f434c0000000000000000"
                "00000000000000000000000000000000ecc0000012345678"
            ),
        )
        normalized = ntp_scapy.ntp_fields_from_bytes(payload)
        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual(normalized["first_octet"], 0x23)
        self.assertEqual(normalized["mode"], 3)
        self.assertEqual(normalized["reference_id"], {"hex": "4c4f434c"})

    def test_materializer_preserves_extension_and_legacy_mac_tail(self) -> None:
        plan = _ntp_plan("ntp-extension-with-legacy-mac", "ntp_extensions")
        payload = ntp_scapy._ntp_message_bytes(plan.fields)
        normalized = ntp_scapy.ntp_fields_from_bytes(payload)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual(normalized["extension_count"], 1)
        self.assertEqual(
            normalized["extension_fields"][0]["extension_field_type"], 0x0204
        )
        self.assertEqual(normalized["legacy_mac"]["hex"], "01020304" + "cc" * 16)
        self.assertEqual(normalized["mac_total_len"], 20)

    def test_raw_fallback_payload_is_materialized_but_not_promoted_to_ntp(self) -> None:
        plan = _ntp_plan("ntp-extension-raw-fallback-boundary", "ntp_extensions")
        payload = ntp_scapy._ntp_message_bytes(plan.fields)
        layers = ["ipv4", "udp", "payload"]
        fields = {
            "ipv4": {},
            "udp": {"src_port": 49152, "dst_port": 123},
            "payload": {"hex": payload.hex(), "length": len(payload)},
        }

        self.assertIsNone(ntp_scapy.ntp_fields_from_bytes(payload))
        ntp_scapy.canonicalize_ntp_payload(_udp_packet(payload), layers, fields)

        self.assertEqual(layers, ["ipv4", "udp", "payload"])
        self.assertEqual(
            fields["payload"], {"hex": payload.hex(), "length": len(payload)}
        )

    def test_udp_123_raw_payload_is_canonicalized_to_ntp_layer(self) -> None:
        payload = ntp_scapy._ntp_message_bytes(
            _ntp_plan("ntp-header-client-request", "ntp_header").fields
        )
        layers = ["ipv4", "udp", "payload"]
        fields = {
            "ipv4": {},
            "udp": {"src_port": 49152, "dst_port": 123},
            "payload": {"hex": payload.hex(), "length": len(payload)},
        }

        ntp_scapy.canonicalize_ntp_payload(_udp_packet(payload), layers, fields)

        self.assertEqual(layers, ["ipv4", "udp", "ntp"])
        self.assertNotIn("payload", fields)
        self.assertEqual(fields["ntp"]["version"], 4)
        self.assertEqual(fields["ntp"]["mode"], 3)


class NtpWiresharkBackendTest(unittest.TestCase):
    def test_source_byte_normalization_parses_valid_ntp_payload(self) -> None:
        payload = ntp_scapy._ntp_message_bytes(
            _ntp_plan("ntp-nts-authenticator-parts", "ntp_nts").fields
        )
        normalized = ntp_wireshark._normalize_ntp({}, source_hex=payload.hex())

        self.assertEqual(normalized["first_octet"], 0x23)
        self.assertEqual(normalized["extension_count"], 1)
        self.assertEqual(
            normalized["extension_fields"][0]["extension_field_type"], 0x0404
        )
        self.assertEqual(
            normalized["extension_fields"][0]["nts_extension"], "authenticator"
        )
        self.assertTrue(
            normalized["extension_fields"][0]["authenticator"]["parts_present"]
        )

    def test_source_byte_normalization_rejects_wrong_udp_port_and_malformed_payload(
        self,
    ) -> None:
        valid = ntp_scapy._ntp_message_bytes(
            _ntp_plan("ntp-header-client-request", "ntp_header").fields
        )
        wrong_port_udp_datagram = (
            b"\xc0\x00\xc0\x01"
            + (len(valid) + 8).to_bytes(2, "big")
            + b"\x00\x00"
            + valid
        )
        raw_fallback = ntp_scapy._ntp_message_bytes(
            _ntp_plan("ntp-extension-raw-fallback-boundary", "ntp_extensions").fields
        )

        self.assertEqual(
            ntp_wireshark._normalize_ntp({}, source_hex=wrong_port_udp_datagram.hex()),
            {},
        )
        self.assertEqual(
            ntp_wireshark._normalize_ntp({}, source_hex=raw_fallback.hex()), {}
        )


if __name__ == "__main__":
    unittest.main()
