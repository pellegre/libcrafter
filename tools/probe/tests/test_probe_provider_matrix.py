"""Provider dry-run matrix coverage for the behavioral probe suite."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.probe.engine import capabilities, cases, provider_matrix


_MATRIX_PROVIDERS = ("hetzner", "qemu", "virtualbox", "docker")


class ProbeProviderDryRunMatrixTest(unittest.TestCase):
    def test_behavior_matrix_summarizes_provider_planning(self) -> None:
        behavior_count = len(cases.BEHAVIOR_PROFILE_CASE_NAMES)
        # Hetzner has no link-layer substrate, so every DHCP, ARP, and NDP
        # behavioral case skips for a capability reason; the IPv6 NDP cases
        # ride the same link-layer requirement as ARP. DNS and UDP unicast
        # cases stay executable.
        link_layer_skipped = (
            _behavior_cases_by_protocol("arp") | _behavior_cases_by_protocol("ndp")
        )
        dhcp_skipped = _behavior_cases_by_protocol("dhcp")
        hetzner_skipped_cases = dhcp_skipped | link_layer_skipped
        hetzner_skipped = len(hetzner_skipped_cases)
        hetzner_executable = behavior_count - hetzner_skipped
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "matrix"
            matrix = provider_matrix.build_provider_matrix(
                providers=_MATRIX_PROVIDERS,
                dry_run=True,
                profile="behavior",
                seed=1050,
                count=behavior_count,
                out=out,
            )

            matrix_path = out / provider_matrix.MATRIX_REPORT_NAME
            self.assertTrue(matrix_path.exists())
            self.assertEqual(
                json.loads(matrix_path.read_text(encoding="utf-8")),
                matrix,
            )
            self.assertEqual(matrix["mode"], "probe-provider-matrix")
            self.assertEqual(matrix["status"], "dry-run")
            self.assertEqual(matrix["providers"], list(_MATRIX_PROVIDERS))
            self.assertEqual(matrix["profile"], "behavior")
            self.assertEqual(matrix["seed"], 1050)
            self.assertEqual(matrix["planned_count"], behavior_count)
            self.assertEqual(
                matrix["selected_cases"],
                list(cases.BEHAVIOR_PROFILE_CASE_NAMES),
            )
            self.assertEqual(
                set(matrix["planned_cases"]),
                set(cases.BEHAVIOR_PROFILE_CASE_NAMES),
            )

            reports = _provider_reports(matrix)
            self.assertEqual(set(reports), set(_MATRIX_PROVIDERS))

            hetzner = reports["hetzner"]
            self.assertEqual(hetzner["planned_count"], behavior_count)
            self.assertEqual(hetzner["skipped_count"], hetzner_skipped)
            self.assertEqual(hetzner["skipped_by_capability"], hetzner_skipped)
            self.assertEqual(hetzner["skipped_by_confirmation"], 0)
            self.assertEqual(
                hetzner["skip_counts_by_reason"],
                {
                    capabilities.SKIP_CAPABILITY_UNAVAILABLE: len(dhcp_skipped),
                    capabilities.SKIP_REQUIRES_LINK_LAYER: len(link_layer_skipped),
                },
            )
            self.assertEqual(
                {case["case"] for case in hetzner["skipped_cases"]},
                hetzner_skipped_cases,
            )
            self.assertEqual(len(hetzner["executable_cases"]), hetzner_executable)
            hetzner_caps = hetzner["provider_capabilities"]
            self.assertTrue(hetzner_caps["dns_service"])
            self.assertTrue(hetzner_caps["udp_service"])
            self.assertFalse(hetzner_caps["dhcp_service"])
            self.assertFalse(hetzner_caps["arp_resolution"])
            self.assertFalse(hetzner_caps["ipv6_multicast"])

            for provider in ("qemu", "virtualbox", "docker"):
                report = reports[provider]
                with self.subTest(provider=provider):
                    self.assertEqual(report["planned_count"], behavior_count)
                    self.assertEqual(report["skipped_count"], 0)
                    self.assertEqual(report["executable_count"], behavior_count)
                    self.assertEqual(report["skip_counts_by_reason"], {})
                    caps = report["provider_capabilities"]
                    self.assertTrue(caps["dns_service"])
                    self.assertTrue(caps["dhcp_service"])
                    self.assertTrue(caps["udp_service"])
                    self.assertTrue(caps["arp_resolution"])
                    self.assertTrue(caps["link_layer_arp"])
                    self.assertTrue(caps["provider_mac"])

            for provider, report in reports.items():
                with self.subTest(provider=provider, artifacts=True):
                    report_path = Path(str(report["report_path"]))
                    stimulus_request = Path(
                        str(report["stimulus_request_artifact_path"])
                    )
                    self.assertTrue(report_path.exists())
                    self.assertTrue(stimulus_request.exists())
                    self.assertIn(str(report_path), matrix["artifact_paths"])
                    self.assertEqual(
                        matrix["stimulus_request_artifact_paths"][provider],
                        str(stimulus_request),
                    )
                    self.assertEqual(
                        matrix["provider_capabilities"][provider],
                        report["provider_capabilities"],
                    )
                    self.assertEqual(
                        matrix["target_service_setup_plans"][provider],
                        report["target_service_setup"],
                    )
                    self.assertTrue(report["target_service_setup"]["planned"])
                    self.assertTrue(report["target_service_setup"]["services"])

    def test_cli_main_writes_combined_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "provider-matrix.json"
            exit_code = provider_matrix.main(
                [
                    "--providers",
                    "qemu",
                    "--dry-run",
                    "--profile",
                    "behavior",
                    "--seed",
                    "1050",
                    "--count",
                    "40",
                    "--out",
                    str(out),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["providers"], ["qemu"])
            self.assertEqual(payload["provider_reports"][0]["provider"], "qemu")
            self.assertEqual(payload["provider_reports"][0]["skipped_count"], 0)

    def test_live_matrix_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ValueError):
                provider_matrix.build_provider_matrix(
                    providers=("qemu",),
                    dry_run=False,
                    profile="behavior",
                    seed=1050,
                    count=40,
                    out=Path(temp_dir),
                )


def _provider_reports(matrix: dict[str, object]) -> dict[str, dict[str, object]]:
    return {
        str(report["provider"]): report
        for report in _objects(matrix["provider_reports"])
    }


def _behavior_cases_by_protocol(protocol: str) -> set[str]:
    return {
        case.name
        for case in cases.profile_selected_cases("behavior", [])
        if case.metadata.get("protocol") == protocol
    }


def _objects(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise AssertionError(f"expected list, got {type(value).__name__}")
    objects: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            raise AssertionError(f"expected object, got {type(item).__name__}")
        objects.append(item)
    return objects


if __name__ == "__main__":
    unittest.main()
