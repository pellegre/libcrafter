"""Unit coverage for probe-owned stimulus RST guards."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.probe.engine import cli
from tools.probe.engine.lab import probe_address_context_from_lab_session
from tools.probe.engine.model import ProbeRunRequest


class ProbeRstGuardsTest(unittest.TestCase):
    def test_rst_guard_iptables_args_scope_to_selected_interface(self) -> None:
        plan = _tcp_closed_plan(provider="qemu")

        args = cli._rst_guard_iptables_args([plan], interface="wirepriv0")

        self.assertEqual(
            args,
            [
                [
                    "-o",
                    "wirepriv0",
                    "-p",
                    "tcp",
                    "-s",
                    plan["source_ipv4"],
                    "-d",
                    plan["destination_ipv4"],
                    "--sport",
                    str(plan["source_port"]),
                    "--dport",
                    str(plan["destination_port"]),
                    "--tcp-flags",
                    "RST",
                    "RST",
                    "-j",
                    "DROP",
                ]
            ],
        )

    def test_rst_guard_setup_and_cleanup_use_stimulus_endpoint_context(self) -> None:
        plan = _tcp_closed_plan(provider="qemu")
        fake_wire = _FakeWire()
        stimulus_endpoint = {
            "endpoint_id": "qemu-stimulus",
            "interface": "wirepriv0",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            setup = cli._install_wire_stimulus_rst_guards(
                wire=fake_wire,
                stimulus_endpoint=stimulus_endpoint,
                probe_plans=[plan],
                output_dir=output_dir,
            )
            cleanup = cli._cleanup_wire_stimulus_rst_guards(
                wire=fake_wire,
                stimulus_endpoint=stimulus_endpoint,
                probe_plans=[plan],
                output_dir=output_dir,
            )

        self.assertIsNotNone(setup)
        self.assertEqual(setup["exit_code"], 0)
        self.assertEqual(cleanup["exit_code"], 0)
        self.assertEqual(fake_wire.exec_calls[0]["endpoint_id"], "qemu-stimulus")
        self.assertEqual(fake_wire.exec_calls[1]["endpoint_id"], "qemu-stimulus")
        self.assertIn("-o wirepriv0", fake_wire.exec_calls[0]["command"][2])
        self.assertIn("-o wirepriv0", fake_wire.exec_calls[1]["command"][2])

    def test_dry_run_request_artifact_uses_lab_stimulus_interfaces(self) -> None:
        cases = (
            ("hetzner", "private"),
            ("qemu", "private"),
            ("virtualbox", "lan"),
        )
        for provider, expected_interface in cases:
            with self.subTest(provider=provider):
                request = _request(provider=provider)
                plans = _rewritten_lab_plans(request)

                with tempfile.TemporaryDirectory() as temp_dir:
                    report_path = Path(temp_dir) / "probe-report.json"
                    cli._write_stimulus_endpoint_request_artifact(
                        report_path=report_path,
                        request=request,
                        probe_plans=plans,
                        dry_run=True,
                        stimulus_endpoint=_lab_stimulus_endpoint(request),
                    )
                    artifact = _read_request_artifact(report_path)

                self.assertEqual(artifact["interface"], expected_interface)
                metadata = artifact["metadata"]["stimulus_endpoint"]
                self.assertEqual(metadata["provider"], provider)
                self.assertEqual(metadata["interface"], expected_interface)
                self.assertEqual(metadata["interface_source"], "lab_endpoint")

    def test_local_dry_run_request_artifact_keeps_probe_default_interface(self) -> None:
        request = _request(provider="local-dry-run")
        plans = _plans(request)

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "probe-report.json"
            cli._write_stimulus_endpoint_request_artifact(
                report_path=report_path,
                request=request,
                probe_plans=plans,
                dry_run=True,
            )
            artifact = _read_request_artifact(report_path)

        self.assertEqual(artifact["interface"], "dry-run0")
        metadata = artifact["metadata"]["stimulus_endpoint"]
        self.assertEqual(metadata["provider"], "local-dry-run")
        self.assertEqual(metadata["interface_source"], "probe_default")


class _FakeProcessResult:
    stdout = ""
    stderr = ""
    exit_code = 0
    ok = True
    error = None


class _FakeWireResponse:
    def __init__(self, operation: str, endpoint_id: str) -> None:
        self.operation = operation
        self.endpoint_id = endpoint_id
        self.result = _FakeProcessResult()

    def metadata(self) -> dict[str, object]:
        return {
            "operation": self.operation,
            "endpoint_id": self.endpoint_id,
            "argv": ["tools/wire/run", self.operation, self.endpoint_id],
            "exit_code": self.result.exit_code,
            "ok": self.result.ok,
            "artifacts": [],
        }


class _FakeWire:
    def __init__(self) -> None:
        self.exec_calls: list[dict[str, object]] = []

    def exec(
        self,
        endpoint_id: str,
        command: list[str],
        *,
        timeout: int | float | None = None,
    ) -> _FakeWireResponse:
        self.exec_calls.append(
            {
                "endpoint_id": endpoint_id,
                "command": command,
                "timeout": timeout,
            }
        )
        return _FakeWireResponse("exec", endpoint_id)


def _request(*, provider: str) -> ProbeRunRequest:
    return ProbeRunRequest(
        provider=provider,
        profile="smoke",
        seed=3,
        count=1,
        case_names=["tcp-syn-closed"],
        dry_run=True,
    )


def _plans(request: ProbeRunRequest) -> list[dict[str, object]]:
    return cli._probe_plans_for_cases(
        request,
        [cli._PROBE_CASE_BY_NAME["tcp-syn-closed"]],
    )


def _tcp_closed_plan(*, provider: str) -> dict[str, object]:
    return _plans(_request(provider=provider))[0]


def _rewritten_lab_plans(request: ProbeRunRequest) -> list[dict[str, object]]:
    return cli._probe_plans_with_lab_endpoint_addresses(
        _plans(request),
        address_context=_lab_address_context(request),
    )


def _lab_stimulus_endpoint(request: ProbeRunRequest) -> dict[str, object]:
    return cli._stimulus_endpoint_context(_lab_address_context(request))


def _lab_address_context(request: ProbeRunRequest) -> dict[str, object]:
    session = cli._probe_lab_dry_run_session(request)
    return probe_address_context_from_lab_session(session)


def _read_request_artifact(report_path: Path) -> dict[str, object]:
    request_path = (
        report_path.parent
        / "artifacts"
        / "stimulus-endpoint"
        / "stimulus.request.json"
    )
    return json.loads(request_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
