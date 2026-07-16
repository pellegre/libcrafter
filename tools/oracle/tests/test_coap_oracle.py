"""Integrated deterministic coverage for the complete offline CoAP oracle."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import unittest
from collections.abc import Mapping

from tools.oracle.engine.backends.scapy.protocols import SCAPY_REGISTRY
from tools.oracle.engine.backends.scapy.protocols.coap import (
    coap_message_bytes,
    coap_reliable_fields_from_bytes,
)
from tools.oracle.engine.backends.wireshark.protocols import WIRESHARK_REGISTRY
from tools.oracle.engine.cli import _SUITE_FEATURE_BY_FAMILY, _suite_offline_cases
from tools.oracle.engine.generator import PacketGenerator, generate_plans
from tools.oracle.engine.protocols import SAMPLER_REGISTRY
from tools.oracle.engine.spec_loader import load_oracle_specs


_REPO_ROOT = Path(__file__).resolve().parents[3]
_SEED = 95
_FEATURES = (
    "coap_datagram",
    "coap_reliable",
    "coap_observe",
    "coap_blockwise",
    "coap_extended_token",
    "coap_link_format",
    "coap_oscore",
    "coap_malformed",
    "coap_pcap",
)
_DIRECTIONS = {"backend_to_libcrafter", "libcrafter_to_backend"}
_CONTRACT_ONLY = {
    "coap-observe-wrap",
    "coap-reliable-concatenated-raw",
    "coap-udp-raw-fallback",
}
_PCAP_FIXTURES = {
    "ethernet-ipv4-udp-coap-get.pcap": (
        "baa5b9a6210dd35c4a6e427af6a23ccfc1494ab2b16d05aaba305aa47f7af477",
        1,
    ),
    "raw-ipv4-udp-coap-get.pcap": (
        "c68dbcec3312d514e9704ae519fd101e0964c5b2db18dce6f9af896bc60d5316",
        101,
    ),
    "raw-ipv6-udp-coap-content.pcap": (
        "c9775ecd969845ed8fc660e5fc47ae940b762a1b1bbefc3c887833c065fd8d40",
        101,
    ),
}


def _cargo(*args: str, input_document: object | None = None) -> subprocess.CompletedProcess[str]:
    temporary = _REPO_ROOT / "target" / "oracle" / "coap-step95" / "tmp"
    temporary.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment["TMPDIR"] = str(temporary)
    return subprocess.run(
        ["cargo", *args],
        cwd=_REPO_ROOT,
        env=environment,
        input=None if input_document is None else json.dumps(input_document),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=240,
    )


def _run_adapter(binary: str, document: object) -> dict[str, object]:
    process = _cargo(
        "run",
        "--quiet",
        "-p",
        "oracle-adapters",
        "--bin",
        binary,
        "--",
        "--input",
        "-",
        input_document=document,
    )
    if process.returncode != 0:
        raise AssertionError(
            f"{binary} failed with exit {process.returncode}\n"
            f"stdout:\n{process.stdout}\nstderr:\n{process.stderr}"
        )
    report = json.loads(process.stdout)
    assert isinstance(report, dict)
    return report


def _runnable_entries() -> list[tuple[str, Mapping[str, object]]]:
    return [
        (feature, entry)
        for feature in _FEATURES
        for entry in _suite_offline_cases(feature)
        if entry.get("contract_only") is not True
    ]


class CoapOfflineContractTest(unittest.TestCase):
    """The data-driven suite covers every truthful offline direction."""

    def test_generic_suite_registers_every_coap_feature(self) -> None:
        self.assertEqual(tuple(_SUITE_FEATURE_BY_FAMILY["coap"]), _FEATURES)

    def test_suite_matrix_matches_supported_cases_and_byte_policies(self) -> None:
        specs = load_oracle_specs()
        emitted: set[tuple[str, str, str]] = set()
        expected: set[tuple[str, str, str]] = set()
        contract_only: set[str] = set()

        for feature_name in _FEATURES:
            feature = specs.features[feature_name]
            for entry in _suite_offline_cases(feature_name):
                case = str(entry["case"])
                policy = str(entry["byte_policy"])
                emitted.add((case, str(entry["direction"]), policy))
                if entry.get("contract_only") is True:
                    contract_only.add(case)
            for raw_case in feature.raw["supported_cases"]:
                if raw_case["byte_policy"] == "structured_error":
                    continue
                for direction in _DIRECTIONS:
                    if direction in raw_case["directions"] or "roundtrip" in raw_case["directions"]:
                        expected.add((raw_case["name"], direction, raw_case["byte_policy"]))

        self.assertEqual(emitted, expected)
        self.assertEqual(contract_only, _CONTRACT_ONLY)
        self.assertTrue(any(policy == "normalized" for _, _, policy in emitted))
        self.assertTrue(any(policy == "strict_bytes" for _, _, policy in emitted))

    def test_seeded_smoke_and_ci_profiles_are_deterministic_and_offline(self) -> None:
        for profile, count in (("coap-smoke", 12), ("coap-ci", 240)):
            first = generate_plans(
                seed=_SEED,
                profile=profile,
                count=count,
                backend="libcrafter",
                family="coap",
            )
            second = generate_plans(
                seed=_SEED,
                profile=profile,
                count=count,
                backend="libcrafter",
                family="coap",
            )
            self.assertEqual([plan.to_dict() for plan in first], [plan.to_dict() for plan in second])
            self.assertEqual({plan.family for plan in first}, {"coap"})
            self.assertTrue(all(plan.direction in _DIRECTIONS for plan in first))
            self.assertTrue(all("live" not in plan.feature_tags for plan in first))
            self.assertTrue(all(plan.stack[-1] == "coap" for plan in first))

    def test_reliable_frame_parser_requires_exactly_one_complete_frame(self) -> None:
        fields = coap_reliable_fields_from_bytes(bytes.fromhex("30e1220480"))
        self.assertIsNotNone(fields)
        assert fields is not None
        self.assertEqual(fields["transport"], "reliable")
        self.assertEqual(
            fields["reliable_length"],
            {"nibble": 3, "extension_hex": "", "declared_length": 3},
        )
        self.assertEqual(fields["code"], 0xE1)
        self.assertEqual(fields["token_length"]["declared_length"], 0)
        self.assertEqual(fields["options"][0]["number"], 2)
        self.assertEqual(fields["options"][0]["value"]["hex"], "0480")
        self.assertIsNone(coap_reliable_fields_from_bytes(bytes.fromhex("30e12204")))
        self.assertIsNone(coap_reliable_fields_from_bytes(bytes.fromhex("30e12204800000")))


class CoapDirectionMatrixTest(unittest.TestCase):
    """Reference bytes and libcrafter agree for every runnable matrix entry."""

    @classmethod
    def setUpClass(cls) -> None:
        generator = PacketGenerator(seed=_SEED, profile="coap-ci", backend="libcrafter")
        cls.plans = [
            generator.generate(
                index=index,
                family="coap",
                case=str(entry["case"]),
                feature=feature,
                direction=str(entry["direction"]),
            )
            for index, (feature, entry) in enumerate(_runnable_entries())
        ]
        cls.materialized = _run_adapter(
            "materialize_plans",
            {
                "mode": "offline",
                "profile": "coap-ci",
                "seed": _SEED,
                "plans": [plan.to_dict() for plan in cls.plans],
            },
        )
        cls.decoded = _run_adapter("decode_vectors", cls.materialized)

    def test_every_runnable_case_and_direction_materializes(self) -> None:
        actual = {(plan.case, plan.direction) for plan in self.plans}
        expected = {
            (str(entry["case"]), str(entry["direction"]))
            for _, entry in _runnable_entries()
        }
        self.assertEqual(actual, expected)
        self.assertEqual({plan.direction for plan in self.plans}, _DIRECTIONS)

    def test_protocol_local_reference_bytes_match_libcrafter(self) -> None:
        vectors = self.materialized["metadata"]["vectors"]
        self.assertEqual(len(vectors), len(self.plans))
        for plan, vector in zip(self.plans, vectors, strict=True):
            expected = coap_message_bytes(plan.fields)
            actual = bytes.fromhex(vector["raw_hex"])
            with self.subTest(case=plan.case, direction=plan.direction):
                self.assertTrue(actual.endswith(expected))
                if plan.strict_bytes:
                    self.assertEqual(actual[-len(expected) :], expected)

    def test_libcrafter_decode_preserves_typed_or_secure_raw_boundary(self) -> None:
        decoded = self.decoded["metadata"]["decoded"]
        self.assertEqual(len(decoded), len(self.plans))
        for plan, packet in zip(self.plans, decoded, strict=True):
            with self.subTest(case=plan.case, direction=plan.direction):
                if plan.case == "coap-secure-port-raw":
                    self.assertEqual(packet["layers"][-1], "payload")
                    self.assertNotIn("coap", packet["fields"])
                else:
                    self.assertEqual(packet["layers"][-1], "coap")
                    self.assertIn("coap", packet["fields"])
                    self.assertEqual(packet["fields"]["coap"]["transport"], plan.fields["coap"]["transport"])


class CoapPcapAndPluginTest(unittest.TestCase):
    """Pcap fixtures and all three protocol plugin surfaces stay deterministic."""

    def test_pcap_fixtures_are_classic_deterministic_and_nonempty(self) -> None:
        fixture_root = _REPO_ROOT / "crafter" / "tests" / "fixtures" / "pcaps"
        for name, (digest, link_type) in _PCAP_FIXTURES.items():
            raw = (fixture_root / name).read_bytes()
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
                self.assertEqual(raw[:4], bytes.fromhex("d4c3b2a1"))
                self.assertEqual(struct.unpack_from("<I", raw, 20)[0], link_type)
                captured = struct.unpack_from("<I", raw, 24 + 8)[0]
                original = struct.unpack_from("<I", raw, 24 + 12)[0]
                self.assertEqual(captured, original)
                self.assertEqual(len(raw), 24 + 16 + captured)

    def test_sampler_and_reference_plugins_cover_the_declared_fields(self) -> None:
        fields = {field.name for field in load_oracle_specs().layers["coap"].fields}
        self.assertEqual(SAMPLER_REGISTRY.require("coap").supported_fields, fields)
        self.assertEqual(SCAPY_REGISTRY.require("coap").supported_fields, fields)
        aliases = set(WIRESHARK_REGISTRY.require("coap").tshark_aliases)
        self.assertLessEqual(aliases, fields)
        self.assertTrue({"version", "message_type", "code", "message_id", "token"} <= aliases)

    def test_native_scapy_core_vector_when_dependency_is_available(self) -> None:
        try:
            from scapy.all import raw  # type: ignore[import-untyped]
            from scapy.contrib.coap import CoAP  # type: ignore[import-untyped]
        except ModuleNotFoundError as exc:
            raise unittest.SkipTest("Scapy is unavailable in the bare acceptance interpreter") from exc

        expected = bytes.fromhex("41011234aab6737461747573")
        self.assertEqual(raw(CoAP(expected)), expected)


if __name__ == "__main__":
    unittest.main()
