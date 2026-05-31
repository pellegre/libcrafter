"""Matrix coverage for lab-backed probe dry-run reports."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.probe.engine import cli
from tools.probe.engine.lab import probe_lab_provider_names
from tools.probe.engine.model import ProbeReport, ProbeRunRequest


EXPECTED_EXPOSURES = {
    "docker": "private",
    "hetzner": "private",
    "qemu": "private",
    "virtualbox": "private",
}

EXPECTED_INTERFACES = {
    "docker": "eth0",
    "hetzner": "private",
    "qemu": "private",
    "virtualbox": "wirepriv0",
}


class ProbeLabProviderDryRunMatrixTest(unittest.TestCase):
    def test_ttl_expired_dry_run_reports_include_lab_metadata_and_stable_skip(
        self,
    ) -> None:
        self.assertEqual(
            probe_lab_provider_names(),
            tuple(EXPECTED_EXPOSURES),
        )

        for provider, expected_exposure in EXPECTED_EXPOSURES.items():
            with self.subTest(provider=provider):
                with tempfile.TemporaryDirectory() as temp_dir:
                    report_path = Path(temp_dir) / "probe-report.json"
                    report = _ttl_expired_dry_run_report(
                        provider=provider,
                        report_path=report_path,
                    )

                    self._assert_report_contract(
                        report,
                        provider=provider,
                        expected_exposure=expected_exposure,
                        expected_interface=EXPECTED_INTERFACES[provider],
                    )
                    self._assert_stimulus_request_artifact(
                        report,
                        report_path=report_path,
                        provider=provider,
                        expected_exposure=expected_exposure,
                        expected_interface=EXPECTED_INTERFACES[provider],
                    )

    def _assert_report_contract(
        self,
        report: ProbeReport,
        *,
        provider: str,
        expected_exposure: str,
        expected_interface: str,
    ) -> None:
        metadata = report.metadata
        lab_session = _object(metadata["lab_session"])
        address_context = _object(metadata["lab_address_context"])
        wire_plan = _object(metadata["wire_endpoint_plan"])
        provider_capabilities = _object(metadata["provider_capabilities"])

        self.assertEqual(report.status, cli.STATUS_DRY_RUN)
        self.assertEqual(report.provider, provider)
        self.assertEqual(report.count, 1)
        self.assertEqual(metadata["provider"], provider)
        self.assertEqual(metadata["wire_provider"], provider)
        self.assertEqual(metadata["wire_exposure"], expected_exposure)
        self.assertTrue(metadata["dry_run"])
        self.assertTrue(metadata["requires_provider_lifecycle"])
        self.assertFalse(metadata["mutates_lab"])
        self.assertFalse(provider_capabilities["controlled_router"])

        session_id = str(lab_session["session_id"])
        self.assertEqual(lab_session["provider"], provider)
        self.assertEqual(lab_session["wire_provider"], provider)
        self.assertEqual(lab_session["wire_exposure"], expected_exposure)
        self.assertEqual(lab_session["dry_run"], True)
        self.assertEqual(address_context["session_id"], session_id)
        self.assertEqual(wire_plan["lab_session_id"], session_id)

        roles = [role["name"] for role in _objects(lab_session["roles"])]
        self.assertEqual(roles, ["stimulus", "target"])
        endpoints = _object(metadata["endpoints"])
        self.assertEqual(set(endpoints), {"stimulus", "target"})
        stimulus = _object(endpoints["stimulus"])
        target = _object(endpoints["target"])
        self.assertEqual(stimulus["role"], "stimulus")
        self.assertEqual(target["role"], "target")
        self.assertEqual(stimulus["interface"], expected_interface)
        self.assertEqual(target["interface"], expected_interface)
        self.assertEqual(stimulus["metadata"]["peer_role"], "target")
        self.assertEqual(target["metadata"]["peer_role"], "stimulus")
        self.assertEqual(stimulus["metadata"]["lab_session_id"], session_id)
        self.assertEqual(target["metadata"]["lab_session_id"], session_id)

        self.assertEqual(wire_plan["provider"], provider)
        self.assertEqual(wire_plan["wire_provider"], provider)
        self.assertEqual(wire_plan["exposure"], expected_exposure)
        self.assertTrue(wire_plan["dry_run"])
        self.assertEqual(wire_plan["endpoint_count"], 2)
        self.assertEqual(set(_object(wire_plan["endpoints"])), {"stimulus", "target"})

        provider_workflow = _objects(metadata["provider_workflow"])
        provider_commands = _objects(metadata["provider_commands"])
        self.assertEqual(provider_workflow, lab_session["provider_workflow"])
        self.assertEqual(provider_commands, lab_session["command_records"])
        self.assertEqual(metadata["command_records"], provider_commands)
        self.assertEqual(
            [command["operation"] for command in provider_workflow],
            [
                "wire.doctor",
                "wire.create",
                "wire.create",
                "wire.collect_artifacts",
                "wire.destroy",
            ],
        )
        self.assertEqual(
            [command["role"] for command in provider_commands],
            ["stimulus", "target"],
        )
        self.assertTrue(
            all(command["operation"] == "wire.create" for command in provider_commands)
        )
        self.assertTrue(all(command["dry_run"] for command in provider_workflow))
        self.assertTrue(all(command["dry_run"] for command in provider_commands))
        self.assertTrue(
            all(not command["live_mutation"] for command in provider_workflow)
        )
        self.assertTrue(all(not command["live_mutation"] for command in provider_commands))
        self.assertTrue(
            all("--dry-run" in command["argv"] for command in provider_commands)
        )

        self.assertEqual(report.metadata["planned_case_names"], ["ttl-expired"])
        self.assertEqual(report.metadata["skip_reasons"], [cli.SKIP_REQUIRES_CONTROLLED_ROUTER])
        self.assertEqual(
            report.metadata["skip_counts_by_reason"],
            {cli.SKIP_REQUIRES_CONTROLLED_ROUTER: 1},
        )
        self.assertEqual(len(report.results), 1)
        self.assertEqual(len(report.skips), 1)
        result = report.results[0]
        skip = report.skips[0]
        self.assertEqual(result.case, "ttl-expired")
        self.assertEqual(result.status, "skipped")
        self.assertIs(result.skip, skip)
        self.assertEqual(skip.case, "ttl-expired")
        self.assertEqual(skip.sequence, 0)
        self.assertEqual(skip.reason, cli.SKIP_REQUIRES_CONTROLLED_ROUTER)
        self.assertEqual(skip.capability, "controlled_router")
        self.assertEqual(skip.metadata["missing_capabilities"], ["controlled_router"])
        self.assertFalse(report.observed_responses)

        probe_plan = _object(report.metadata["probe_plans"][0])
        self.assertEqual(probe_plan["case"], "ttl-expired")
        self.assertEqual(probe_plan["source_ipv4"], stimulus["ipv4"])
        self.assertEqual(probe_plan["destination_ipv4"], target["ipv4"])
        address_rewrite = _object(probe_plan["live_address_rewrite"])
        self.assertEqual(address_rewrite["source"], "lab_session")
        self.assertEqual(address_rewrite["stimulus_ipv4"], stimulus["ipv4"])
        self.assertEqual(address_rewrite["target_ipv4"], target["ipv4"])

    def _assert_stimulus_request_artifact(
        self,
        report: ProbeReport,
        *,
        report_path: Path,
        provider: str,
        expected_exposure: str,
        expected_interface: str,
    ) -> None:
        request_path = (
            report_path.parent
            / "artifacts"
            / "stimulus-endpoint"
            / "stimulus.request.json"
        )
        self.assertIn(str(request_path), report.artifact_paths)
        self.assertTrue(request_path.exists())
        self.assertEqual(report.artifacts, report.artifact_paths)

        artifact = _object(json.loads(request_path.read_text(encoding="utf-8")))
        artifact_plans = _objects(artifact["probe_plans"])
        artifact_metadata = _object(artifact["metadata"])
        stimulus_metadata = _object(artifact_metadata["stimulus_endpoint"])

        self.assertEqual(artifact["provider"], provider)
        self.assertEqual(artifact["interface"], expected_interface)
        self.assertEqual([plan["case"] for plan in artifact_plans], ["ttl-expired"])
        self.assertEqual(stimulus_metadata["provider"], provider)
        self.assertEqual(stimulus_metadata["interface"], expected_interface)
        self.assertEqual(stimulus_metadata["interface_source"], "lab_endpoint")


def _ttl_expired_dry_run_report(
    *,
    provider: str,
    report_path: Path,
) -> ProbeReport:
    request = ProbeRunRequest(
        provider=provider,
        profile="smoke",
        seed=4,
        count=1,
        case_names=["ttl-expired"],
        dry_run=True,
    )
    selected_cases = cli._selected_cases(request.case_names)
    planned_cases = cli._planned_cases(
        selected_cases,
        seed=request.seed,
        count=request.count,
    )
    probe_plans = cli._probe_plans_for_cases(request, planned_cases)
    return cli._dry_run_report(
        request=request,
        selected_cases=selected_cases,
        planned_cases=planned_cases,
        probe_plans=probe_plans,
        report_path=report_path,
    )


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AssertionError(f"expected object, got {type(value).__name__}")
    return value


def _list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise AssertionError(f"expected list, got {type(value).__name__}")
    return value


def _objects(value: object) -> list[dict[str, object]]:
    return [_object(item) for item in _list(value)]


if __name__ == "__main__":
    unittest.main()
