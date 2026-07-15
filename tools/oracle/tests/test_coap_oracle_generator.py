"""Deterministic CoAP generator and libcrafter adapter coverage."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import unittest

from tools.oracle.engine.generator import PacketGenerator, case_byte_policy_index, generate_plans
from tools.oracle.engine.protocols import SAMPLER_REGISTRY
from tools.oracle.engine.spec_loader import load_oracle_specs


_REPO_ROOT = Path(__file__).resolve().parents[3]
_SEED = 93
_SUPPORTED_FIELDS = frozenset(
    {
        "transport",
        "version",
        "message_type",
        "code",
        "message_id",
        "token",
        "token_length",
        "reliable_length",
        "options",
        "payload_marker",
        "payload",
        "signaling_options",
    }
)


def _cargo(*args: str, input_document: object | None = None) -> subprocess.CompletedProcess[str]:
    tmp = _REPO_ROOT / "target" / "oracle-coap-tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment["TMPDIR"] = str(tmp)
    return subprocess.run(
        ["cargo", *args],
        cwd=_REPO_ROOT,
        env=environment,
        input=None if input_document is None else json.dumps(input_document),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=180,
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


def _plan(
    case: str,
    feature: str,
    *,
    index: int = 0,
    direction: str = "libcrafter_to_backend",
) -> dict[str, object]:
    generator = PacketGenerator(seed=_SEED, profile="coap-smoke", backend="libcrafter")
    return generator.generate(
        index=index,
        family="coap",
        case=case,
        feature=feature,
        direction=direction,
    ).to_dict()


def _materialize(plans: list[dict[str, object]]) -> dict[str, object]:
    return _run_adapter(
        "materialize_plans",
        {
            "mode": "offline",
            "profile": "coap-smoke",
            "seed": _SEED,
            "plans": plans,
        },
    )


class CoapGeneratorTest(unittest.TestCase):
    def test_sampler_matches_exact_declared_coap_field_surface(self) -> None:
        specs = load_oracle_specs()
        declared = frozenset(field.name for field in specs.layers["coap"].fields)
        sampler = SAMPLER_REGISTRY.require("coap")

        self.assertEqual(sampler.supported_fields, _SUPPORTED_FIELDS)
        self.assertEqual(sampler.supported_fields, declared)
        self.assertIsNotNone(sampler.apply_behavior)
        self.assertIsNotNone(sampler.post_sample)
        assert sampler.handles_feature is not None
        self.assertTrue(sampler.handles_feature("coap_datagram"))
        self.assertFalse(sampler.handles_feature("udp_options"))

    def test_seeded_profile_is_deterministic_and_coap_only(self) -> None:
        first = generate_plans(
            seed=_SEED,
            profile="coap-smoke",
            count=12,
            backend="libcrafter",
            family="coap",
        )
        second = generate_plans(
            seed=_SEED,
            profile="coap-smoke",
            count=12,
            backend="libcrafter",
            family="coap",
        )

        self.assertEqual([plan.to_dict() for plan in first], [plan.to_dict() for plan in second])
        for plan in first:
            with self.subTest(case=plan.case, stack=plan.stack):
                self.assertEqual(plan.family, "coap")
                self.assertEqual(plan.stack[-1], "coap")
                self.assertIn(plan.stack[-2], {"udp", "tcp"})
                self.assertIn("coap", plan.fields)
                self.assertEqual(plan.fields["coap"]["transport"], "reliable" if "tcp" in plan.stack else "datagram")
                feature = plan.metadata.get("feature")
                if feature is not None:
                    self.assertTrue(str(feature).startswith("coap_"))
                ip = plan.fields["ipv6"] if "ipv6" in plan.stack else plan.fields["ipv4"]
                self.assertTrue(str(ip["src"]).startswith(("192.0.2.", "2001:db8:")))
                self.assertTrue(str(ip["dst"]).startswith(("198.51.100.", "2001:db8:")))

    def test_structured_error_cases_stay_out_of_runnable_generation(self) -> None:
        policies = case_byte_policy_index()
        self.assertEqual(policies["malformed-coap-truncated-header"], "structured_error")
        self.assertEqual(policies["malformed-coap-reliable"], "structured_error")
        generator = PacketGenerator(seed=_SEED, profile="coap-ci", backend="libcrafter")
        with self.assertRaisesRegex(ValueError, "no stack specs match"):
            generator.generate(
                index=0,
                family="coap",
                case="malformed-coap-truncated-header",
                feature="coap_malformed",
            )


class CoapAdapterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        process = _cargo("check", "-p", "oracle-adapters")
        if process.returncode != 0:
            raise AssertionError(
                "oracle-adapters did not compile\n"
                f"stdout:\n{process.stdout}\nstderr:\n{process.stderr}"
            )

    def test_typed_datagram_and_reliable_vectors_materialize_and_normalize(self) -> None:
        report = _materialize(
            [
                _plan("coap-datagram-get", "coap_datagram", index=0),
                _plan("coap-reliable-csm", "coap_reliable", index=1),
            ]
        )
        vectors = report["metadata"]["vectors"]
        self.assertEqual(len(vectors), 2)

        decoded = _run_adapter("decode_vectors", report)["metadata"]["decoded"]
        datagram, reliable = decoded
        self.assertEqual(datagram["layers"][-2:], ["udp", "coap"])
        self.assertEqual(datagram["fields"]["coap"]["transport"], "datagram")
        self.assertEqual(datagram["fields"]["coap"]["code"], 1)
        self.assertEqual(datagram["fields"]["coap"]["message_id"], 0x1234)
        self.assertEqual(datagram["fields"]["coap"]["token"]["hex"], "aa")

        self.assertEqual(reliable["layers"][-2:], ["tcp", "coap"])
        reliable_fields = reliable["fields"]["coap"]
        self.assertEqual(reliable_fields["transport"], "reliable")
        self.assertEqual(reliable_fields["code"], 0xE1)
        self.assertEqual(len(reliable_fields["options"]), 1)
        self.assertEqual(reliable_fields["options"][0]["number"], 2)
        self.assertEqual(reliable_fields["options"][0]["value"]["hex"], "0480")

    def test_secure_port_vector_remains_opaque_without_credentials(self) -> None:
        plan = _plan(
            "coap-secure-port-raw",
            "coap_oscore",
            direction="backend_to_libcrafter",
        )
        self.assertEqual(plan["fields"]["udp"]["dst_port"], 5684)
        self.assertNotIn("context", plan["fields"]["coap"])
        report = _materialize([plan])
        decoded = _run_adapter("decode_vectors", report)["metadata"]["decoded"][0]

        self.assertEqual(decoded["layers"][-1], "payload")
        self.assertNotIn("coap", decoded["fields"])
        self.assertTrue(decoded["fields"]["payload"]["hex"])


if __name__ == "__main__":
    unittest.main()
