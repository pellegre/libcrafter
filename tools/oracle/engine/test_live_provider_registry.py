"""Unit coverage for oracle live provider adapter registration."""

from __future__ import annotations

import contextlib
import io
import tempfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.oracle.engine import cli
from tools.oracle.engine.live import LiveCommandPlan, LiveEndpoint
from tools.oracle.engine.model import DecodedModel, PacketPlan, read_json
from tools.oracle.engine.providers.hetzner import ORACLE_PRIVATE_GROUP
from tools.oracle.engine.providers.registry import (
    UnknownLiveProviderError,
    registered_provider_names,
    resolve_live_provider,
)


class LiveProviderRegistryTest(unittest.TestCase):
    def test_hetzner_provider_is_registered(self) -> None:
        self.assertEqual(registered_provider_names(), ("hetzner",))

        adapter = resolve_live_provider("hetzner")

        self.assertEqual(adapter.name, "hetzner")
        self.assertEqual(adapter.wire_provider, "hetzner")
        self.assertEqual(adapter.wire_exposure, "private")
        self.assertEqual(adapter.endpoint_roles, ("libcrafter", "reference_backend"))
        self.assertEqual(adapter.private_group, ORACLE_PRIVATE_GROUP)

    def test_unknown_provider_error_names_requested_and_known_providers(self) -> None:
        with self.assertRaises(UnknownLiveProviderError) as error:
            resolve_live_provider("virtualbox")

        message = str(error.exception)
        self.assertIn("virtualbox", message)
        self.assertIn("hetzner", message)

    def test_hetzner_adapter_exposes_report_plans(self) -> None:
        adapter = resolve_live_provider("hetzner")

        capabilities = adapter.default_provider_capabilities(dry_run=True)
        infrastructure = adapter.planned_infrastructure(dry_run=True)
        exchange_metadata = adapter.packet_exchange_metadata(dry_run=True)
        endpoints = adapter.endpoints(dry_run=True)
        workflow = adapter.provider_workflow(dry_run=True)
        bootstrap = adapter.endpoint_bootstrap_plan(dry_run=True)

        self.assertEqual(capabilities["provider"], "hetzner")
        self.assertEqual(infrastructure["provider"], "hetzner")
        self.assertEqual(exchange_metadata["provider"], "hetzner")
        self.assertEqual(exchange_metadata["wire_provider"], "hetzner")
        self.assertEqual(exchange_metadata["wire_exposure"], "private")
        self.assertEqual(
            exchange_metadata["endpoint_roles"],
            ["libcrafter", "reference_backend"],
        )
        self.assertEqual(exchange_metadata["private_group"], ORACLE_PRIVATE_GROUP)
        self.assertTrue(exchange_metadata["isolated_network"])
        self.assertTrue(exchange_metadata["private_network"])
        self.assertEqual(exchange_metadata["packet_exchange_network"], "private")
        self.assertEqual(set(endpoints), {"libcrafter", "reference_backend"})
        self.assertTrue(all(endpoint.metadata["private_network"] for endpoint in endpoints.values()))
        self.assertTrue(adapter.validate_provider_workflow(workflow, dry_run=True).passed)
        self.assertTrue(adapter.validate_endpoint_bootstrap(bootstrap, dry_run=True).passed)
        self.assertEqual(
            {command.role for command in bootstrap},
            {"libcrafter", "reference_backend"},
        )

        workflow_purposes = {command.purpose for command in workflow}
        self.assertIn(adapter.artifact_collection_purpose, workflow_purposes)
        self.assertIn(adapter.teardown_purpose, workflow_purposes)
        doctor = next(command for command in workflow if command.purpose == "check-hetzner-provider")
        self.assertIn("--provider", doctor.argv)
        self.assertIn("hetzner", doctor.argv)
        self.assertIn("--exposure", doctor.argv)
        self.assertIn("private", doctor.argv)

    def test_hetzner_adapter_plans_wire_endpoints_with_private_exposure(self) -> None:
        adapter = resolve_live_provider("hetzner")
        client = _FakeWireClient()

        plan = adapter.wire_endpoint_plan(dry_run=True, client=client)

        self.assertEqual(plan["provider"], "hetzner")
        self.assertEqual(plan["exposure"], "private")
        self.assertEqual(plan["private_group"], ORACLE_PRIVATE_GROUP)
        self.assertEqual(set(plan["live_endpoints"]), {"libcrafter", "reference_backend"})
        self.assertEqual(
            [(call["provider"], call["exposure"], call["role"]) for call in client.calls],
            [
                ("hetzner", "private", "libcrafter"),
                ("hetzner", "private", "reference_backend"),
            ],
        )
        self.assertTrue(all(call["dry_run"] for call in client.calls))
        self.assertTrue(all(call["private_group"] == ORACLE_PRIVATE_GROUP for call in client.calls))

    def test_hetzner_adapter_exposes_execution_policy_hooks(self) -> None:
        adapter = resolve_live_provider("hetzner")
        plan = PacketPlan(
            stack=["ipv4"],
            fields={"ipv4": {"ttl": 1}},
            profile="default",
            seed=7,
            index=3,
            direction="reference_to_libcrafter",
            family="ipv4",
            metadata={"root": "l3:ipv4"},
        )

        policy = adapter.wire_comparison_policy(plan)
        transit_plan = adapter.apply_transit_plan(plan)
        libcrafter_command = adapter.endpoint_remote_command(
            endpoint_role="libcrafter",
            remote_dir="/root/libcrafter",
            request_path="/tmp/request.json",
            out_dir="/tmp/out",
        )
        reference_command = adapter.endpoint_remote_command(
            endpoint_role="reference_backend",
            remote_dir="/root/libcrafter",
            request_path="/tmp/request.json",
            out_dir="/tmp/out",
        )

        self.assertEqual(policy["provider"], "hetzner")
        self.assertEqual(policy["compare_root"], "l3:ipv4")
        self.assertIn("ipv4.ttl", policy["mutable_fields"])
        self.assertFalse(policy["strict_bytes"])
        self.assertEqual(transit_plan.fields["ipv4"]["ttl"], 64)
        self.assertEqual(transit_plan.metadata["wire"]["provider"], "hetzner")
        self.assertEqual(libcrafter_command[:2], ["bash", "-lc"])
        self.assertIn("cargo run", libcrafter_command[2])
        self.assertEqual(reference_command[:2], ["bash", "-lc"])
        self.assertIn("python3 -m engine.backends.scapy.live", reference_command[2])

    def test_live_parser_accepts_local_dry_run_and_registered_providers(self) -> None:
        parser = cli.build_parser()

        local_args = parser.parse_args(["live", "--provider", "local-dry-run"])
        hetzner_args = parser.parse_args(["live", "--provider", "hetzner"])

        self.assertEqual(local_args.provider, "local-dry-run")
        self.assertEqual(hetzner_args.provider, "hetzner")
        with (
            self.assertRaises(SystemExit),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            parser.parse_args(["live", "--provider", "virtualbox"])

    def test_live_dispatch_resolves_hetzner_adapter(self) -> None:
        args = _live_args("hetzner")
        seen: dict[str, object] = {}

        def fake_live_provider(_args, adapter) -> int:
            seen["provider"] = _args.provider
            seen["adapter"] = adapter
            return 17

        with patch.object(cli, "_live_provider", side_effect=fake_live_provider):
            code = cli._live(args)

        self.assertEqual(code, 17)
        self.assertEqual(seen["provider"], "hetzner")
        self.assertIs(seen["adapter"], resolve_live_provider("hetzner"))

    def test_live_dispatch_rejects_unknown_provider_before_planning(self) -> None:
        args = _live_args("virtualbox")
        stderr = io.StringIO()

        with (
            patch.object(cli, "_live_provider") as live_provider,
            contextlib.redirect_stderr(stderr),
        ):
            code = cli._live(args)

        self.assertEqual(code, 2)
        live_provider.assert_not_called()
        self.assertIn("virtualbox", stderr.getvalue())
        self.assertIn("hetzner", stderr.getvalue())

    def test_real_live_execution_uses_provider_adapter_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "oracle-live"
            report_path = output_dir / "report.json"
            args = _real_live_args("fakecloud", output_dir)
            adapter = _FakeLiveProviderAdapter()
            wire = _FakeLiveWireClient()
            plan = _fake_packet_plan()
            corpus_metadata = _fake_corpus_metadata(adapter.name, [plan])

            with (
                patch("tools.oracle.engine.wire_client.WireClient", return_value=wire),
                patch.object(cli, "_create_wire_repo_archive", side_effect=_fake_archive),
                patch.object(cli, "_backend_versions", return_value={}),
                patch.object(cli, "_libcrafter_info", return_value={}),
                patch.object(cli, "_live_corpus_plans", return_value=(
                    [plan],
                    ["fake-spec.yaml"],
                    corpus_metadata,
                )),
                patch("tools.oracle.engine.backends.scapy.packets.encode_packet_plans", side_effect=_fake_encode_packet_plans),
                patch("tools.oracle.engine.backends.scapy.normalize.decode_vectors", side_effect=_fake_decode_vectors),
                patch.object(cli.time, "sleep", return_value=None),
                patch.object(cli, "_start_wire_endpoint_batch", side_effect=_fake_start_wire_endpoint_batch),
                patch.object(cli, "_run_wire_endpoint_batch", side_effect=_fake_run_wire_endpoint_batch),
                patch.object(cli, "_wait_wire_endpoint_batch", side_effect=lambda execution, *, timeout_seconds: execution),
            ):
                code = cli._live_provider_execute(
                    args=args,
                    provider_adapter=adapter,
                    report_path=report_path,
                    directions=["reference_to_libcrafter"],
                    plans=[plan],
                    selected_specs=["base-spec.yaml"],
                    corpus_metadata=corpus_metadata,
                )

            self.assertEqual(code, 0)
            self.assertEqual(
                wire.doctor_calls,
                [{"provider": "fake-wire", "exposure": "isolated"}],
            )
            self.assertEqual(
                [(call["provider"], call["exposure"], call["role"]) for call in wire.create_calls],
                [
                    ("fake-wire", "isolated", "libcrafter"),
                    ("fake-wire", "isolated", "reference_backend"),
                ],
            )
            self.assertEqual(wire.destroyed, ["fake-reference_backend", "fake-libcrafter"])
            self.assertEqual(
                [(call["endpoint"], call["peer"]) for call in adapter.bootstrap_calls],
                [
                    ("libcrafter", "reference_backend"),
                    ("reference_backend", "libcrafter"),
                ],
            )
            self.assertEqual(adapter.transit_plan_ttls, [64])
            self.assertEqual(
                sorted({call["endpoint_role"] for call in adapter.remote_command_calls}),
                ["libcrafter", "reference_backend"],
            )

            report = read_json(report_path)
            self.assertIsInstance(report, dict)
            metadata = report["metadata"]
            self.assertEqual(report["status"], "passed")
            self.assertEqual(metadata["planned_infrastructure"]["provider"], "fakecloud")
            self.assertEqual(metadata["wire_endpoint_plan"]["provider"], "fakecloud")
            self.assertEqual(metadata["wire_provider"], "fake-wire")
            self.assertEqual(metadata["wire_exposure"], "isolated")
            self.assertEqual(metadata["packet_exchange_network"], "fake-isolated")
            self.assertFalse(metadata["private_network"])
            self.assertEqual(metadata["wire_endpoint_lifecycle"]["remote_dir"], "/srv/fake-oracle")
            self.assertEqual(
                metadata["artifact_collection"]["command"]["purpose"],
                adapter.artifact_collection_purpose,
            )
            self.assertEqual(
                metadata["teardown"]["command"]["purpose"],
                adapter.teardown_purpose,
            )
            artifact_paths = "\n".join(report["artifact_paths"])
            self.assertIn("provider-exchange/fakecloud/reference_to_libcrafter", artifact_paths)
            self.assertNotIn("hetzner-exchange", artifact_paths)

    def test_real_live_execution_tears_down_after_artifact_collection_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "oracle-live"
            report_path = output_dir / "report.json"
            args = _real_live_args("fakecloud", output_dir)
            adapter = _FakeLiveProviderAdapter()
            wire = _FakeLiveWireClient(collect_raises=True)
            plan = _fake_packet_plan()
            corpus_metadata = _fake_corpus_metadata(adapter.name, [plan])

            with (
                patch("tools.oracle.engine.wire_client.WireClient", return_value=wire),
                patch.object(cli, "_create_wire_repo_archive", side_effect=_fake_archive),
                patch.object(cli, "_backend_versions", return_value={}),
                patch.object(cli, "_libcrafter_info", return_value={}),
                patch.object(cli, "_live_corpus_plans", return_value=(
                    [],
                    ["fake-spec.yaml"],
                    _fake_corpus_metadata(adapter.name, []),
                )),
            ):
                code = cli._live_provider_execute(
                    args=args,
                    provider_adapter=adapter,
                    report_path=report_path,
                    directions=["reference_to_libcrafter"],
                    plans=[plan],
                    selected_specs=["base-spec.yaml"],
                    corpus_metadata=corpus_metadata,
                )

            self.assertEqual(code, 1)
            self.assertEqual(wire.destroyed, ["fake-reference_backend", "fake-libcrafter"])
            report = read_json(report_path)
            self.assertIsInstance(report, dict)
            provider_commands = report["metadata"]["provider_commands"]
            artifact_failures = [
                command
                for command in provider_commands
                if str(command.get("label", "")).startswith("98-artifact-")
                and command.get("exit_code") != 0
            ]
            self.assertTrue(artifact_failures)


class _FakeRecord:
    def __init__(self, role: str) -> None:
        self.role = role

    def to_dict(self) -> dict[str, object]:
        return {
            "operation": "create-endpoint",
            "role": self.role,
            "exit_code": 0,
        }


class _FakeWireClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def create(
        self,
        *,
        provider: str,
        exposure: str,
        role: str,
        private_group: str,
        private_ip: str,
        dry_run: bool,
        confirm_live_run: bool,
    ):
        self.calls.append(
            {
                "provider": provider,
                "exposure": exposure,
                "role": role,
                "private_group": private_group,
                "private_ip": private_ip,
                "dry_run": dry_run,
                "confirm_live_run": confirm_live_run,
            }
        )
        endpoint_id = f"{provider}-{exposure}-{role}"
        return SimpleNamespace(
            manifest=SimpleNamespace(endpoint_id=endpoint_id),
            record=_FakeRecord(role),
            json_data={
                "endpoint_id": endpoint_id,
                "provider": provider,
                "exposure": exposure,
                "role": role,
                "interfaces": [
                    {
                        "name": "oracle0",
                        "exposure": exposure,
                        "ipv4": private_ip,
                        "metadata": {"private_group": private_group},
                    }
                ],
                "metadata": {"private_group": private_group},
            },
        )


def _live_args(provider: str) -> SimpleNamespace:
    return SimpleNamespace(
        backend="scapy",
        provider=provider,
        out="target/oracle/test-live-provider-dispatch",
        direction="live_exchange",
        dry_run=True,
        profile="smoke",
        seed=1,
        count=1,
    )


RAW_HEX = "01020304"


def _real_live_args(provider: str, output_dir: Path) -> SimpleNamespace:
    return SimpleNamespace(
        backend="scapy",
        provider=provider,
        out=str(output_dir),
        direction="reference_to_libcrafter",
        dry_run=False,
        profile="smoke",
        seed=7,
        count=1,
        index=None,
        corpus=None,
        case_name=None,
        feature=None,
        family=None,
        root=None,
        confirm_live_run=True,
        keep_wire_endpoints=False,
    )


def _fake_packet_plan() -> PacketPlan:
    return PacketPlan(
        stack=["ipv4"],
        fields={"ipv4": {"src": "192.0.2.1", "dst": "192.0.2.2", "ttl": 1}},
        profile="smoke",
        seed=7,
        index=11,
        direction="reference_to_libcrafter",
        family="ipv4",
        strict_bytes=True,
        metadata={
            "plan_id": "fake-plan-11",
            "root": "l3:ipv4",
            "wire": {
                "provider": "fakecloud",
                "compare_root": "l3:ipv4",
                "mutable_fields": [],
                "strict_bytes": True,
            },
            "corpus": {
                "corpus_id": "fake-corpus",
                "packet_id": "fake-packet-11",
                "corpus_index": 0,
                "packet_index": 11,
                "corpus_source": "generated",
                "corpus_path": None,
            },
        },
    )


def _fake_corpus_metadata(provider: str, plans: list[PacketPlan]) -> dict[str, object]:
    return {
        "corpus_id": "fake-corpus",
        "corpus_source": "generated",
        "corpus_path": None,
        "corpus_backend": "scapy",
        "corpus_profile": "smoke",
        "corpus_seed": 7,
        "corpus_count": len(plans),
        "requested_count": 1,
        "generated_count": len(plans),
        "wire_provider": provider,
        "wire_eligible_count": len(plans),
        "wire_skipped_count": 0,
        "wire_skip_reasons": {},
        "wire_skip_counts_by_reason": {},
        "wire_eligibility": [],
        "packet_indexes": [plan.index for plan in plans],
    }


def _fake_archive(output_dir: Path) -> Path:
    archive = output_dir / "artifacts" / "wire" / "fake-repo.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_text("fake archive", encoding="utf-8")
    return archive


def _fake_encode_packet_plans(plans: list[PacketPlan]):
    return [SimpleNamespace(plan=plan, raw_hex=RAW_HEX) for plan in plans]


def _fake_decode_vectors(vectors, **_: object) -> list[DecodedModel]:
    decoded: list[DecodedModel] = []
    for vector in vectors:
        plan = vector.plan
        decoded.append(_fake_decoded_model(plan))
    return decoded


def _fake_decoded_model(plan: PacketPlan) -> DecodedModel:
    ipv4 = plan.fields.get("ipv4", {})
    return DecodedModel(
        backend="fake-live",
        layers=["ipv4"],
        fields={
            "ipv4": {
                "src": ipv4.get("src"),
                "dst": ipv4.get("dst"),
                "ttl": ipv4.get("ttl"),
            }
        },
        root="l3:ipv4",
        source_hex=RAW_HEX,
        feature_tags=list(plan.feature_tags),
        metadata={},
    )


def _fake_start_wire_endpoint_batch(
    *,
    wire,
    endpoint_id: str,
    command: list[str],
    output_dir: Path,
    label: str,
) -> dict[str, object]:
    return _fake_endpoint_execution(
        endpoint_id=endpoint_id,
        command=command,
        output_dir=output_dir,
        label=label,
    )


def _fake_run_wire_endpoint_batch(
    *,
    wire,
    endpoint_id: str,
    command: list[str],
    output_dir: Path,
    label: str,
    timeout_seconds: int,
) -> dict[str, object]:
    return _fake_endpoint_execution(
        endpoint_id=endpoint_id,
        command=command,
        output_dir=output_dir,
        label=label,
    )


def _fake_endpoint_execution(
    *,
    endpoint_id: str,
    command: list[str],
    output_dir: Path,
    label: str,
) -> dict[str, object]:
    endpoint_role = command[1]
    request = read_json(output_dir / f"{endpoint_role}.request.json")
    assert isinstance(request, dict)
    response = _fake_endpoint_response(request)
    stdout_path = output_dir / f"{label}.stdout.json"
    stderr_path = output_dir / f"{label}.stderr.txt"
    return {
        "argv": ["fake-wire", "exec", endpoint_id, "--", *command],
        "operation": "exec",
        "wire_command": True,
        "endpoint_id": endpoint_id,
        "label": label,
        "exit_code": 0,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "response": response,
        "errors": [],
    }


def _fake_endpoint_response(request: dict[str, object]) -> dict[str, object]:
    phase_role = request["metadata"]["phase_role"]
    plans = request["packet_plans"]
    assert isinstance(plans, list)
    statuses = []
    decoded = []
    for raw_plan in plans:
        assert isinstance(raw_plan, dict)
        index = raw_plan["index"]
        fields = raw_plan.get("fields", {})
        assert isinstance(fields, dict)
        plan = PacketPlan(
            stack=list(raw_plan["stack"]),
            fields={
                str(layer): dict(values)
                for layer, values in fields.items()
                if isinstance(values, dict)
            },
            profile=str(raw_plan["profile"]),
            seed=int(raw_plan["seed"]),
            index=int(index),
            direction=str(raw_plan["direction"]),
            family=raw_plan.get("family") if isinstance(raw_plan.get("family"), str) else None,
            strict_bytes=bool(raw_plan.get("strict_bytes", True)),
            metadata=dict(raw_plan.get("metadata", {})),
        )
        if phase_role == "sender":
            statuses.append(
                {
                    "index": index,
                    "direction": request["direction"],
                    "status": "sent",
                    "sent": True,
                    "received": False,
                    "decoded_count": 0,
                    "sent_raw_hex": RAW_HEX,
                    "send_root": "l3:ipv4",
                    "send_mode": "network-layer",
                    "byte_length": len(bytes.fromhex(RAW_HEX)),
                    "errors": [],
                    "metadata": {},
                }
            )
        else:
            capture_path = f"{request['artifact_paths']['captures']}/capture.pcap"
            statuses.append(
                {
                    "index": index,
                    "direction": request["direction"],
                    "status": "received",
                    "sent": False,
                    "received": True,
                    "decoded_count": 1,
                    "observed_raw_hex": RAW_HEX,
                    "capture_root": "l3:ipv4",
                    "capture_link_type": "raw-ipv4",
                    "capture_path": capture_path,
                    "byte_length": len(bytes.fromhex(RAW_HEX)),
                    "capture_paths": [capture_path],
                    "errors": [],
                    "metadata": {},
                }
            )
            decoded.append(_fake_decoded_model(plan).to_dict())
    return {
        "provider": request["provider"],
        "backend": request["backend"],
        "direction": request["direction"],
        "endpoint_id": request["endpoint_id"],
        "endpoint_role": request["endpoint_role"],
        "sent_count": len(plans) if phase_role == "sender" else 0,
        "received_count": len(plans) if phase_role == "receiver" else 0,
        "decoded_models": decoded,
        "captures": [],
        "per_index_status": statuses,
        "errors": [],
        "artifact_paths": request["artifact_paths"],
        "metadata": {"fake": True},
    }


class _FakeLiveProviderAdapter:
    name = "fakecloud"
    wire_provider = "fake-wire"
    wire_exposure = "isolated"
    endpoint_roles = ("libcrafter", "reference_backend")
    private_group = "fake-private"
    endpoint_private_ips = {
        "libcrafter": "10.0.0.10",
        "reference_backend": "10.0.0.20",
    }
    artifact_collection_purpose = "collect-fake-artifacts"
    teardown_purpose = "teardown-fake-endpoints"
    credential_label = "FAKE_TOKEN"
    missing_credential_reason = "missing FAKE_TOKEN"

    def __init__(self) -> None:
        self.bootstrap_calls: list[dict[str, str]] = []
        self.remote_command_calls: list[dict[str, str]] = []
        self.transit_plan_ttls: list[int] = []

    def token_configured(self) -> bool:
        return True

    def default_provider_capabilities(
        self,
        *,
        dry_run: bool,
        source: str = "planned-defaults",
    ) -> dict[str, object]:
        return {
            "provider": self.name,
            "dry_run": dry_run,
            "source": source,
            "ipv4": True,
            "ipv4_unicast": True,
            "controlled_services": True,
        }

    def normalize_provider_capabilities(
        self,
        raw: dict[str, object],
        *,
        dry_run: bool | None = None,
        source: str | None = None,
    ) -> dict[str, object]:
        output = dict(raw)
        if dry_run is not None:
            output["dry_run"] = dry_run
        if source is not None:
            output["source"] = source
        output.setdefault("provider", self.name)
        return output

    def planned_infrastructure(self, *, dry_run: bool) -> dict[str, object]:
        return {"provider": self.name, "dry_run": dry_run, "network": "fake-private"}

    def packet_exchange_metadata(self, *, dry_run: bool) -> dict[str, object]:
        return {
            "provider": self.name,
            "wire_provider": self.wire_provider,
            "wire_exposure": self.wire_exposure,
            "endpoint_roles": list(self.endpoint_roles),
            "private_group": self.private_group,
            "isolated_network": True,
            "private_network": False,
            "packet_exchange_network": "fake-isolated",
            "packet_exchange_network_label": "fake isolated exchange",
            "dry_run": dry_run,
        }

    def endpoints(self, *, dry_run: bool) -> dict[str, LiveEndpoint]:
        return _fake_live_endpoints(dry_run=dry_run)

    def wire_endpoint_plan(
        self,
        *,
        dry_run: bool,
        client=None,
        private_group: str | None = None,
        confirm_live_run: bool = False,
        created_endpoint_ids: list[str] | None = None,
    ) -> dict[str, object]:
        endpoints = {}
        command_metadata = []
        for role in self.endpoint_roles:
            response = client.create(
                provider=self.wire_provider,
                exposure=self.wire_exposure,
                role=role,
                private_group=private_group or self.private_group,
                private_ip=self.endpoint_private_ips[role],
                dry_run=dry_run,
                confirm_live_run=confirm_live_run,
            )
            endpoint_id = f"fake-{role}"
            if created_endpoint_ids is not None:
                created_endpoint_ids.append(endpoint_id)
            command_metadata.append(response.record.to_dict())
            endpoints[role] = _fake_live_endpoints(dry_run=dry_run)[role]
        return {
            "provider": self.name,
            "wire_provider": self.wire_provider,
            "exposure": self.wire_exposure,
            "dry_run": dry_run,
            "command_metadata": command_metadata,
            "live_endpoints": endpoints,
        }

    def provider_workflow(self, *, dry_run: bool) -> list[LiveCommandPlan]:
        return [
            LiveCommandPlan(
                role="provider",
                purpose="check-fake-provider",
                argv=["fake-wire", "doctor"],
                metadata={"operation": "doctor"},
            ),
            LiveCommandPlan(
                role="provider",
                purpose=self.artifact_collection_purpose,
                argv=["fake-wire", "collect-artifacts"],
                metadata={"operation": "download", "always_attempt": True},
            ),
            LiveCommandPlan(
                role="provider",
                purpose=self.teardown_purpose,
                argv=["fake-wire", "destroy-endpoint"],
                metadata={"operation": "destroy", "always_attempt": True},
            ),
        ]

    def endpoint_bootstrap_plan(self, *, dry_run: bool) -> list[LiveCommandPlan]:
        return [
            LiveCommandPlan(
                role=role,
                purpose=f"bootstrap-{role}",
                argv=["fake-bootstrap", role],
                metadata={"dry_run": dry_run},
            )
            for role in self.endpoint_roles
        ]

    def validate_provider_workflow(self, commands, *, dry_run: bool):
        raise AssertionError("not used by real execution test")

    def validate_endpoint_bootstrap(self, commands, *, dry_run: bool):
        raise AssertionError("not used by real execution test")

    def validate_dry_run_exchange(self, exchange):
        raise AssertionError("not used by real execution test")

    def remote_dir(self) -> str:
        return "/srv/fake-oracle"

    def endpoint_bootstrap_command(
        self,
        *,
        endpoint: LiveEndpoint,
        peer: LiveEndpoint,
        remote_archive: str,
        remote_dir: str,
    ) -> list[str]:
        self.bootstrap_calls.append(
            {
                "endpoint": endpoint.role,
                "peer": peer.role,
                "remote_archive": remote_archive,
                "remote_dir": remote_dir,
            }
        )
        return ["fake-bootstrap", endpoint.role, peer.role, remote_archive, remote_dir]

    def endpoint_remote_command(
        self,
        *,
        endpoint_role: str,
        remote_dir: str,
        request_path: str,
        out_dir: str,
    ) -> list[str]:
        self.remote_command_calls.append(
            {
                "endpoint_role": endpoint_role,
                "remote_dir": remote_dir,
                "request_path": request_path,
                "out_dir": out_dir,
            }
        )
        return ["fake-live", endpoint_role, request_path, out_dir]

    def apply_transit_plan(self, plan: PacketPlan) -> PacketPlan:
        ipv4 = dict(plan.fields.get("ipv4", {}))
        if int(ipv4.get("ttl", 64)) < 64:
            ipv4["ttl"] = 64
        fields = {layer: dict(values) for layer, values in plan.fields.items()}
        fields["ipv4"] = ipv4
        self.transit_plan_ttls.append(int(ipv4["ttl"]))
        return replace(
            plan,
            fields=fields,
            metadata={
                **plan.metadata,
                "wire": self.wire_comparison_policy(plan),
                "live_transit_rewrites": [
                    {"field": "ipv4.ttl", "to": int(ipv4["ttl"]), "provider": self.name}
                ],
            },
        )

    def wire_comparison_policy(self, plan: PacketPlan) -> dict[str, object]:
        return {
            "provider": self.name,
            "compare_root": "l3:ipv4",
            "mutable_fields": [],
            "strict_bytes": True,
        }


class _FakeLiveWireClient:
    def __init__(self, *, collect_raises: bool = False) -> None:
        self.wire_path = "fake-wire"
        self.cwd = "."
        self.collect_raises = collect_raises
        self.doctor_calls: list[dict[str, str]] = []
        self.create_calls: list[dict[str, object]] = []
        self.destroyed: list[str] = []

    def doctor(self, *, provider: str, exposure: str):
        self.doctor_calls.append({"provider": provider, "exposure": exposure})
        return _FakeWireCommandResponse("doctor")

    def create(
        self,
        *,
        provider: str,
        exposure: str,
        role: str,
        private_group: str,
        private_ip: str,
        dry_run: bool,
        confirm_live_run: bool,
    ):
        self.create_calls.append(
            {
                "provider": provider,
                "exposure": exposure,
                "role": role,
                "private_group": private_group,
                "private_ip": private_ip,
                "dry_run": dry_run,
                "confirm_live_run": confirm_live_run,
            }
        )
        return _FakeWireCommandResponse("create-endpoint", endpoint_id=f"fake-{role}")

    def upload(self, endpoint_id: str, local_path: Path, remote_path: str):
        return _FakeWireCommandResponse("upload", endpoint_id=endpoint_id)

    def exec(self, endpoint_id: str, command: list[str], *, timeout: int):
        return _FakeWireCommandResponse("exec", endpoint_id=endpoint_id)

    def download(self, endpoint_id: str, remote_path: str, local_path: Path):
        return _FakeWireCommandResponse("download", endpoint_id=endpoint_id)

    def collect_artifacts(self, endpoint_id: str, remote_path: str):
        if self.collect_raises:
            raise RuntimeError(f"collect failed for {endpoint_id}")
        return _FakeWireCommandResponse(
            "collect-artifacts",
            endpoint_id=endpoint_id,
            stdout="",
        )

    def destroy(self, endpoint_id: str):
        self.destroyed.append(endpoint_id)
        return _FakeWireCommandResponse("destroy-endpoint", endpoint_id=endpoint_id)


class _FakeWireCommandResponse:
    def __init__(
        self,
        operation: str,
        *,
        endpoint_id: str | None = None,
        exit_code: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        self.result = SimpleNamespace(
            stdout=stdout,
            stderr=stderr,
            error=None,
            exit_code=exit_code,
        )
        self.record = _FakeWireCommandRecord(operation, endpoint_id, exit_code)
        self.json_data = None
        self.manifest = (
            SimpleNamespace(endpoint_id=endpoint_id)
            if endpoint_id is not None
            else None
        )

    def metadata(self) -> dict[str, object]:
        metadata = self.record.to_dict()
        if self.manifest is not None:
            metadata["endpoint_id"] = self.manifest.endpoint_id
        return metadata


class _FakeWireCommandRecord:
    def __init__(self, operation: str, endpoint_id: str | None, exit_code: int) -> None:
        self.operation = operation
        self.endpoint_id = endpoint_id
        self.exit_code = exit_code

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "operation": self.operation,
            "argv": ["fake-wire", self.operation],
            "exit_code": self.exit_code,
            "ok": self.exit_code == 0,
        }
        if self.endpoint_id is not None:
            data["endpoint_id"] = self.endpoint_id
        return data


def _fake_live_endpoints(*, dry_run: bool) -> dict[str, LiveEndpoint]:
    return {
        "libcrafter": LiveEndpoint(
            endpoint_id="fake-libcrafter",
            role="libcrafter",
            interface="fake0",
            address="10.0.0.10",
            metadata={"provider": "fakecloud", "dry_run": dry_run},
        ),
        "reference_backend": LiveEndpoint(
            endpoint_id="fake-reference_backend",
            role="reference_backend",
            interface="fake0",
            address="10.0.0.20",
            metadata={"provider": "fakecloud", "dry_run": dry_run},
        ),
    }


if __name__ == "__main__":
    unittest.main()
