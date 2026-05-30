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

from tools.lab.engine.model import (
    LabCommandPlan,
    LabEndpoint,
    LabRequest,
    LabRole,
    LabSession,
)
from tools.lab.engine.repo import RepoArchiveResult
from tools.oracle.engine import bootstrap as oracle_bootstrap
from tools.oracle.engine import cli
from tools.oracle.engine.live import (
    LiveCommandPlan,
    LiveEndpoint,
    build_live_endpoint_batch_request,
    dry_run_live_endpoint_batch_response,
    live_endpoint_artifact_paths,
    validate_live_endpoint_batch_contract,
)
from tools.oracle.engine.model import DecodedModel, PacketPlan, read_json
from tools.oracle.engine.providers import hetzner as hetzner_provider
from tools.oracle.engine.providers.hetzner import ORACLE_PRIVATE_GROUP
from tools.oracle.engine.providers.hetzner import PRIVATE_NETWORK_CIDR as HETZNER_PRIVATE_NETWORK_CIDR
from tools.oracle.engine.providers.qemu import (
    LIBCRAFTER_PRIVATE_ADDRESS as QEMU_LIBCRAFTER_PRIVATE_ADDRESS,
    ORACLE_PRIVATE_GROUP as QEMU_ORACLE_PRIVATE_GROUP,
    PRIVATE_NETWORK_CIDR as QEMU_PRIVATE_NETWORK_CIDR,
    REFERENCE_PRIVATE_ADDRESS as QEMU_REFERENCE_PRIVATE_ADDRESS,
)
from tools.oracle.engine.providers.virtualbox import (
    LIBCRAFTER_PRIVATE_ADDRESS as VIRTUALBOX_LIBCRAFTER_PRIVATE_ADDRESS,
    ORACLE_PRIVATE_GROUP as VIRTUALBOX_ORACLE_PRIVATE_GROUP,
    PRIVATE_NETWORK_CIDR as VIRTUALBOX_PRIVATE_NETWORK_CIDR,
    REFERENCE_PRIVATE_ADDRESS as VIRTUALBOX_REFERENCE_PRIVATE_ADDRESS,
)
from tools.oracle.engine.providers.registry import (
    UnknownLiveProviderError,
    registered_provider_names,
    resolve_live_provider,
)


class LiveProviderRegistryTest(unittest.TestCase):
    def test_hetzner_provider_is_registered(self) -> None:
        self.assertEqual(registered_provider_names(), ("hetzner", "qemu", "virtualbox"))

        adapter = resolve_live_provider("hetzner")

        self.assertEqual(adapter.name, "hetzner")
        self.assertEqual(adapter.wire_provider, "hetzner")
        self.assertEqual(adapter.wire_exposure, "private")
        self.assertEqual(adapter.endpoint_roles, ("libcrafter", "reference_backend"))
        self.assertEqual(adapter.private_group, ORACLE_PRIVATE_GROUP)
        self.assertEqual(
            adapter.wire_environment(),
            {"HETZNER_PRIVATE_CIDR": HETZNER_PRIVATE_NETWORK_CIDR},
        )

    def test_qemu_provider_is_registered(self) -> None:
        adapter = resolve_live_provider("qemu")

        self.assertEqual(adapter.name, "qemu")
        self.assertEqual(adapter.wire_provider, "qemu")
        self.assertEqual(adapter.wire_exposure, "private")
        self.assertEqual(adapter.endpoint_roles, ("libcrafter", "reference_backend"))
        self.assertEqual(adapter.private_group, QEMU_ORACLE_PRIVATE_GROUP)
        self.assertEqual(
            dict(adapter.endpoint_private_ips),
            {
                "libcrafter": QEMU_LIBCRAFTER_PRIVATE_ADDRESS,
                "reference_backend": QEMU_REFERENCE_PRIVATE_ADDRESS,
            },
        )

    def test_virtualbox_provider_is_registered(self) -> None:
        adapter = resolve_live_provider("virtualbox")

        self.assertEqual(adapter.name, "virtualbox")
        self.assertEqual(adapter.wire_provider, "virtualbox")
        self.assertEqual(adapter.wire_exposure, "private")
        self.assertEqual(adapter.endpoint_roles, ("libcrafter", "reference_backend"))
        self.assertEqual(adapter.private_group, VIRTUALBOX_ORACLE_PRIVATE_GROUP)
        self.assertEqual(
            dict(adapter.endpoint_private_ips),
            {
                "libcrafter": VIRTUALBOX_LIBCRAFTER_PRIVATE_ADDRESS,
                "reference_backend": VIRTUALBOX_REFERENCE_PRIVATE_ADDRESS,
            },
        )

    def test_unknown_provider_error_names_requested_and_known_providers(self) -> None:
        with self.assertRaises(UnknownLiveProviderError) as error:
            resolve_live_provider("not-a-provider")

        message = str(error.exception)
        self.assertIn("not-a-provider", message)
        self.assertIn("hetzner", message)
        self.assertIn("qemu", message)
        self.assertIn("virtualbox", message)

    def test_hetzner_adapter_exposes_report_plans(self) -> None:
        adapter = resolve_live_provider("hetzner")

        capabilities = adapter.default_provider_capabilities(dry_run=True)
        infrastructure = adapter.planned_infrastructure(dry_run=True)
        exchange_metadata = adapter.packet_exchange_metadata(dry_run=True)
        endpoints = adapter.endpoints(dry_run=True)
        workflow = adapter.provider_workflow(dry_run=True)
        bootstrap = _endpoint_bootstrap_plan(adapter, dry_run=True)

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
        self.assertTrue(
            _validate_endpoint_bootstrap(adapter, bootstrap, dry_run=True).passed,
        )
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

    def test_qemu_adapter_exposes_report_plans(self) -> None:
        adapter = resolve_live_provider("qemu")

        capabilities = adapter.default_provider_capabilities(dry_run=True)
        infrastructure = adapter.planned_infrastructure(dry_run=True)
        exchange_metadata = adapter.packet_exchange_metadata(dry_run=True)
        endpoints = adapter.endpoints(dry_run=True)
        workflow = adapter.provider_workflow(dry_run=True)
        bootstrap = _endpoint_bootstrap_plan(adapter, dry_run=True)

        self.assertEqual(capabilities["provider"], "qemu")
        self.assertEqual(infrastructure["provider"], "qemu")
        self.assertEqual(infrastructure["network"]["private_group"], QEMU_ORACLE_PRIVATE_GROUP)
        self.assertEqual(exchange_metadata["provider"], "qemu")
        self.assertEqual(exchange_metadata["wire_provider"], "qemu")
        self.assertEqual(exchange_metadata["wire_exposure"], "private")
        self.assertEqual(
            exchange_metadata["endpoint_roles"],
            ["libcrafter", "reference_backend"],
        )
        self.assertEqual(exchange_metadata["private_group"], QEMU_ORACLE_PRIVATE_GROUP)
        self.assertTrue(exchange_metadata["isolated_network"])
        self.assertTrue(exchange_metadata["private_network"])
        self.assertEqual(exchange_metadata["private_network_cidr"], QEMU_PRIVATE_NETWORK_CIDR)
        self.assertEqual(exchange_metadata["packet_exchange_network"], "private")
        self.assertEqual(set(endpoints), {"libcrafter", "reference_backend"})
        self.assertTrue(all(endpoint.metadata["private_network"] for endpoint in endpoints.values()))
        self.assertEqual(endpoints["libcrafter"].address, QEMU_LIBCRAFTER_PRIVATE_ADDRESS)
        self.assertEqual(endpoints["reference_backend"].address, QEMU_REFERENCE_PRIVATE_ADDRESS)
        self.assertTrue(adapter.validate_provider_workflow(workflow, dry_run=True).passed)
        self.assertTrue(
            _validate_endpoint_bootstrap(adapter, bootstrap, dry_run=True).passed,
        )
        self.assertEqual(
            {command.role for command in bootstrap},
            {"libcrafter", "reference_backend"},
        )

        workflow_purposes = {command.purpose for command in workflow}
        self.assertIn(adapter.artifact_collection_purpose, workflow_purposes)
        self.assertIn(adapter.teardown_purpose, workflow_purposes)
        doctor = next(command for command in workflow if command.purpose == "check-qemu-provider")
        self.assertIn("--provider", doctor.argv)
        self.assertIn("qemu", doctor.argv)
        self.assertIn("--exposure", doctor.argv)
        self.assertIn("private", doctor.argv)

    def test_virtualbox_adapter_exposes_report_plans(self) -> None:
        adapter = resolve_live_provider("virtualbox")

        capabilities = adapter.default_provider_capabilities(dry_run=True)
        infrastructure = adapter.planned_infrastructure(dry_run=True)
        exchange_metadata = adapter.packet_exchange_metadata(dry_run=True)
        endpoints = adapter.endpoints(dry_run=True)
        workflow = adapter.provider_workflow(dry_run=True)
        bootstrap = _endpoint_bootstrap_plan(adapter, dry_run=True)

        self.assertEqual(capabilities["provider"], "virtualbox")
        self.assertEqual(capabilities["wire_policy"]["transit_decrements_ipv4_ttl"], False)
        self.assertEqual(infrastructure["provider"], "virtualbox")
        self.assertEqual(infrastructure["network"]["wire_exposure"], "private")
        self.assertEqual(infrastructure["network"]["private_group"], VIRTUALBOX_ORACLE_PRIVATE_GROUP)
        self.assertEqual(exchange_metadata["provider"], "virtualbox")
        self.assertEqual(exchange_metadata["wire_provider"], "virtualbox")
        self.assertEqual(exchange_metadata["wire_exposure"], "private")
        self.assertEqual(
            exchange_metadata["endpoint_roles"],
            ["libcrafter", "reference_backend"],
        )
        self.assertEqual(exchange_metadata["private_group"], VIRTUALBOX_ORACLE_PRIVATE_GROUP)
        self.assertTrue(exchange_metadata["isolated_network"])
        self.assertTrue(exchange_metadata["private_network"])
        self.assertEqual(exchange_metadata["private_network_cidr"], VIRTUALBOX_PRIVATE_NETWORK_CIDR)
        self.assertFalse(exchange_metadata["bridged_lan"])
        self.assertEqual(exchange_metadata["packet_exchange_network"], "private")
        self.assertEqual(set(endpoints), {"libcrafter", "reference_backend"})
        self.assertTrue(all(endpoint.metadata["private_network"] for endpoint in endpoints.values()))
        self.assertFalse(any(endpoint.metadata["bridged_lan"] for endpoint in endpoints.values()))
        self.assertEqual(
            endpoints["libcrafter"].address,
            VIRTUALBOX_LIBCRAFTER_PRIVATE_ADDRESS,
        )
        self.assertEqual(
            endpoints["reference_backend"].address,
            VIRTUALBOX_REFERENCE_PRIVATE_ADDRESS,
        )
        self.assertTrue(adapter.validate_provider_workflow(workflow, dry_run=True).passed)
        self.assertTrue(
            _validate_endpoint_bootstrap(adapter, bootstrap, dry_run=True).passed,
        )
        self.assertEqual(
            {command.role for command in bootstrap},
            {"libcrafter", "reference_backend"},
        )

        workflow_purposes = {command.purpose for command in workflow}
        self.assertIn(adapter.artifact_collection_purpose, workflow_purposes)
        self.assertIn(adapter.teardown_purpose, workflow_purposes)
        doctor = next(command for command in workflow if command.purpose == "check-virtualbox-provider")
        self.assertIn("--provider", doctor.argv)
        self.assertIn("virtualbox", doctor.argv)
        self.assertIn("--exposure", doctor.argv)
        self.assertIn("private", doctor.argv)
        create_commands = [command for command in workflow if command.metadata.get("operation") == "create"]
        self.assertTrue(create_commands)
        for command in create_commands:
            self.assertIn("--private-group", command.argv)
            self.assertIn("--private-ip", command.argv)

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

    def test_hetzner_endpoint_protocol_omits_routed_private_mac(self) -> None:
        endpoint = hetzner_provider._routed_private_live_endpoint(
            LiveEndpoint(
                endpoint_id="hetzner-private-libcrafter",
                role="libcrafter",
                interface="enp7s0",
                address="10.42.19.10",
                metadata={
                    "provider": "hetzner",
                    "mac_address": "86:00:00:55:b4:dc",
                },
            )
        )
        peer = hetzner_provider._routed_private_live_endpoint(
            LiveEndpoint(
                endpoint_id="hetzner-private-reference",
                role="reference_backend",
                interface="enp7s0",
                address="10.42.19.20",
                metadata={
                    "provider": "hetzner",
                    "mac_address": "86:00:00:55:b4:d8",
                },
            )
        )

        request = build_live_endpoint_batch_request(
            provider="hetzner",
            backend="scapy",
            seed=133,
            profile="smoke",
            packet_plans=[_ipv4_dhcp_plan(133)],
            direction="libcrafter_to_reference",
            endpoint=endpoint,
            peer=peer,
            artifact_paths=live_endpoint_artifact_paths(
                output_dir="/tmp/oracle-live",
                direction="libcrafter_to_reference",
                endpoint_role="libcrafter",
            ),
        )

        self.assertNotIn("mac", request.local_addresses)
        self.assertNotIn("mac", request.peer_addresses)
        self.assertEqual(
            endpoint.metadata["observed_mac_address"],
            "86:00:00:55:b4:dc",
        )
        self.assertFalse(endpoint.metadata["endpoint_protocol_mac"])

    def test_hetzner_execution_endpoint_normalization_omits_mac(self) -> None:
        adapter = resolve_live_provider("hetzner")
        endpoints = {
            "libcrafter": LiveEndpoint(
                endpoint_id="hetzner-private-libcrafter",
                role="libcrafter",
                interface="enp7s0",
                address="10.42.19.10",
                metadata={
                    "provider": "hetzner",
                    "mac_address": "86:00:00:55:b4:dc",
                },
            ),
            "reference_backend": LiveEndpoint(
                endpoint_id="hetzner-private-reference",
                role="reference_backend",
                interface="enp7s0",
                address="10.42.19.20",
                metadata={
                    "provider": "hetzner",
                    "mac_address": "86:00:00:55:b4:d8",
                },
            ),
        }

        normalized = cli._live_provider_normalize_endpoints(adapter, endpoints)
        request = build_live_endpoint_batch_request(
            provider="hetzner",
            backend="scapy",
            seed=133,
            profile="smoke",
            packet_plans=[_ipv4_dhcp_plan(133)],
            direction="libcrafter_to_reference",
            endpoint=normalized["libcrafter"],
            peer=normalized["reference_backend"],
            artifact_paths=live_endpoint_artifact_paths(
                output_dir="/tmp/oracle-live",
                direction="libcrafter_to_reference",
                endpoint_role="libcrafter",
            ),
        )

        self.assertNotIn("mac", request.local_addresses)
        self.assertNotIn("mac", request.peer_addresses)
        self.assertEqual(
            normalized["libcrafter"].metadata["observed_mac_address"],
            "86:00:00:55:b4:dc",
        )

    def test_qemu_adapter_plans_wire_endpoints_with_private_exposure(self) -> None:
        adapter = resolve_live_provider("qemu")
        client = _FakeWireClient()

        plan = adapter.wire_endpoint_plan(dry_run=True, client=client)

        self.assertEqual(plan["provider"], "qemu")
        self.assertEqual(plan["wire_provider"], "qemu")
        self.assertEqual(plan["exposure"], "private")
        self.assertEqual(plan["private_group"], QEMU_ORACLE_PRIVATE_GROUP)
        self.assertEqual(set(plan["live_endpoints"]), {"libcrafter", "reference_backend"})
        self.assertEqual(
            [(call["provider"], call["exposure"], call["role"]) for call in client.calls],
            [
                ("qemu", "private", "libcrafter"),
                ("qemu", "private", "reference_backend"),
            ],
        )
        self.assertEqual(
            [call["private_ip"] for call in client.calls],
            [QEMU_LIBCRAFTER_PRIVATE_ADDRESS, QEMU_REFERENCE_PRIVATE_ADDRESS],
        )
        self.assertTrue(all(call["dry_run"] for call in client.calls))
        self.assertTrue(all(call["private_group"] == QEMU_ORACLE_PRIVATE_GROUP for call in client.calls))
        self.assertEqual(
            plan["live_endpoints"]["libcrafter"].address,
            QEMU_LIBCRAFTER_PRIVATE_ADDRESS,
        )
        self.assertEqual(
            plan["live_endpoints"]["reference_backend"].address,
            QEMU_REFERENCE_PRIVATE_ADDRESS,
        )

    def test_virtualbox_adapter_plans_wire_endpoints_with_private_exposure(self) -> None:
        adapter = resolve_live_provider("virtualbox")
        client = _FakeWireClient()

        plan = adapter.wire_endpoint_plan(dry_run=True, client=client)

        self.assertEqual(plan["provider"], "virtualbox")
        self.assertEqual(plan["wire_provider"], "virtualbox")
        self.assertEqual(plan["exposure"], "private")
        self.assertEqual(plan["private_group"], VIRTUALBOX_ORACLE_PRIVATE_GROUP)
        self.assertEqual(set(plan["live_endpoints"]), {"libcrafter", "reference_backend"})
        self.assertEqual(
            [(call["provider"], call["exposure"], call["role"]) for call in client.calls],
            [
                ("virtualbox", "private", "libcrafter"),
                ("virtualbox", "private", "reference_backend"),
            ],
        )
        self.assertEqual(
            [call["private_group"] for call in client.calls],
            [VIRTUALBOX_ORACLE_PRIVATE_GROUP, VIRTUALBOX_ORACLE_PRIVATE_GROUP],
        )
        self.assertEqual(
            [call["private_ip"] for call in client.calls],
            [VIRTUALBOX_LIBCRAFTER_PRIVATE_ADDRESS, VIRTUALBOX_REFERENCE_PRIVATE_ADDRESS],
        )
        self.assertTrue(all(call["dry_run"] for call in client.calls))
        self.assertEqual(
            plan["live_endpoints"]["libcrafter"].address,
            VIRTUALBOX_LIBCRAFTER_PRIVATE_ADDRESS,
        )
        self.assertEqual(
            plan["live_endpoints"]["reference_backend"].address,
            VIRTUALBOX_REFERENCE_PRIVATE_ADDRESS,
        )
        self.assertEqual(
            plan["live_endpoints"]["libcrafter"].metadata["peer_address"],
            VIRTUALBOX_REFERENCE_PRIVATE_ADDRESS,
        )
        self.assertFalse(plan["live_endpoints"]["libcrafter"].metadata["bridged_lan"])
        self.assertTrue(plan["live_endpoints"]["libcrafter"].metadata["private_network"])

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

    def test_qemu_adapter_exposes_execution_policy_hooks_without_transit_mutation(self) -> None:
        adapter = resolve_live_provider("qemu")
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
        bootstrap_command = _endpoint_bootstrap_command(
            adapter,
            endpoint=adapter.endpoints(dry_run=True)["libcrafter"],
            peer=adapter.endpoints(dry_run=True)["reference_backend"],
            remote_archive="/tmp/repo.tar.gz",
            remote_dir="/root/libcrafter",
        )
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

        self.assertEqual(policy["provider"], "qemu")
        self.assertEqual(policy["compare_root"], "l3:ipv4")
        self.assertNotIn("ipv4.ttl", policy["mutable_fields"])
        self.assertNotIn("ipv4.checksum", policy["mutable_fields"])
        self.assertNotIn("ipv4.ttl", policy["byte_mutable_fields"])
        self.assertNotIn("ipv4.checksum", policy["byte_mutable_fields"])
        self.assertTrue(policy["strict_bytes"])
        self.assertEqual(transit_plan.fields["ipv4"]["ttl"], 1)
        self.assertEqual(transit_plan.metadata["wire"]["provider"], "qemu")
        self.assertEqual(transit_plan.metadata["live_transit_rewrites"], [])
        self.assertEqual(bootstrap_command[:2], ["bash", "-lc"])
        self.assertIn("LIBCRAFTER_PRIVATE_IPV4=10.77.0.10", bootstrap_command[2])
        self.assertIn("LIBCRAFTER_PEER_PRIVATE_IPV4=10.77.0.20", bootstrap_command[2])
        self.assertEqual(libcrafter_command[:2], ["bash", "-lc"])
        self.assertIn("cargo run", libcrafter_command[2])
        self.assertEqual(reference_command[:2], ["bash", "-lc"])
        self.assertIn("python3 -m engine.backends.scapy.live", reference_command[2])

    def test_virtualbox_adapter_exposes_execution_policy_hooks_without_transit_mutation(self) -> None:
        adapter = resolve_live_provider("virtualbox")
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
        bootstrap_command = _endpoint_bootstrap_command(
            adapter,
            endpoint=adapter.endpoints(dry_run=True)["libcrafter"],
            peer=adapter.endpoints(dry_run=True)["reference_backend"],
            remote_archive="/tmp/repo.tar.gz",
            remote_dir="/root/libcrafter",
        )
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

        self.assertEqual(policy["provider"], "virtualbox")
        self.assertEqual(policy["compare_root"], "l3:ipv4")
        self.assertNotIn("ipv4.ttl", policy["mutable_fields"])
        self.assertNotIn("ipv4.checksum", policy["mutable_fields"])
        self.assertNotIn("ipv4.ttl", policy["byte_mutable_fields"])
        self.assertNotIn("ipv4.checksum", policy["byte_mutable_fields"])
        self.assertTrue(policy["strict_bytes"])
        self.assertEqual(transit_plan.fields["ipv4"]["ttl"], 1)
        self.assertEqual(transit_plan.metadata["wire"]["provider"], "virtualbox")
        self.assertEqual(transit_plan.metadata["live_transit_rewrites"], [])
        self.assertEqual(bootstrap_command[:2], ["bash", "-lc"])
        self.assertIn("LIBCRAFTER_PRIVATE_IPV4=10.78.0.10", bootstrap_command[2])
        self.assertIn("LIBCRAFTER_PEER_PRIVATE_IPV4=10.78.0.20", bootstrap_command[2])
        self.assertEqual(libcrafter_command[:2], ["bash", "-lc"])
        self.assertIn("cargo run", libcrafter_command[2])
        self.assertEqual(reference_command[:2], ["bash", "-lc"])
        self.assertIn("python3 -m engine.backends.scapy.live", reference_command[2])

    def test_live_parser_accepts_local_dry_run_and_registered_providers(self) -> None:
        parser = cli.build_parser()

        local_args = parser.parse_args(["live", "--provider", "local-dry-run"])
        hetzner_args = parser.parse_args(["live", "--provider", "hetzner"])
        qemu_args = parser.parse_args(["live", "--provider", "qemu"])
        virtualbox_args = parser.parse_args(["live", "--provider", "virtualbox"])

        self.assertEqual(local_args.provider, "local-dry-run")
        self.assertEqual(hetzner_args.provider, "hetzner")
        self.assertEqual(qemu_args.provider, "qemu")
        self.assertEqual(virtualbox_args.provider, "virtualbox")
        with (
            self.assertRaises(SystemExit),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            parser.parse_args(["live", "--provider", "not-a-provider"])

    def test_live_dispatch_resolves_registered_provider_adapter(self) -> None:
        for provider in ("hetzner", "qemu", "virtualbox"):
            args = _live_args(provider)
            seen: dict[str, object] = {}

            def fake_live_provider(_args, adapter) -> int:
                seen["provider"] = _args.provider
                seen["adapter"] = adapter
                return 17

            with patch.object(cli, "_live_provider", side_effect=fake_live_provider):
                code = cli._live(args)

            self.assertEqual(code, 17)
            self.assertEqual(seen["provider"], provider)
            self.assertIs(seen["adapter"], resolve_live_provider(provider))

    def test_live_dispatch_rejects_unknown_provider_before_planning(self) -> None:
        args = _live_args("not-a-provider")
        stderr = io.StringIO()

        with (
            patch.object(cli, "_live_provider") as live_provider,
            contextlib.redirect_stderr(stderr),
        ):
            code = cli._live(args)

        self.assertEqual(code, 2)
        live_provider.assert_not_called()
        self.assertIn("not-a-provider", stderr.getvalue())
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
                patch("tools.lab.engine.wire_client.WireClient", return_value=wire),
                patch("tools.lab.engine.repo.create_repository_archive", side_effect=_fake_repo_archive),
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
                [],
            )
            self.assertEqual(
                [(call["provider"], call["exposure"], call["role"]) for call in wire.create_calls],
                [
                    ("fake-wire", "isolated", "libcrafter"),
                    ("fake-wire", "isolated", "reference_backend"),
                ],
            )
            self.assertEqual(wire.destroyed, ["fake-reference_backend", "fake-libcrafter"])
            self.assertEqual(adapter.transit_plan_ttls, [64])
            self.assertEqual(adapter.normalized_endpoint_roles, ["libcrafter", "reference_backend"])
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
            self.assertEqual(metadata["lab_session"]["provider"], "fakecloud")
            bootstrap_records = _workload_bootstrap_records(metadata["command_records"])
            self.assertEqual(
                [
                    (
                        record["metadata"]["context"]["role"],
                        record["metadata"]["context"]["peer_roles"],
                    )
                    for record in bootstrap_records
                ],
                [
                    ("libcrafter", ["reference_backend"]),
                    ("reference_backend", ["libcrafter"]),
                ],
            )
            self.assertEqual(
                {record["metadata"]["bootstrap"]["provider"] for record in bootstrap_records},
                {"fakecloud"},
            )
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
                patch("tools.lab.engine.wire_client.WireClient", return_value=wire),
                patch("tools.lab.engine.repo.create_repository_archive", side_effect=_fake_repo_archive),
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


_DHCP_DIRECTIONS = ("libcrafter_to_reference", "reference_to_libcrafter")
_DHCP_SENDER_ROLE = {
    "libcrafter_to_reference": "libcrafter",
    "reference_to_libcrafter": "reference_backend",
}


def _ipv4_dhcp_plan(index: int) -> PacketPlan:
    """An IPv4-root ``ipv4 / udp / dhcp`` plan carrying corpus/wire metadata.

    DHCP flows through the same generic endpoint batch contract as every other
    protocol: the live packet under test is an IPv4 packet carrying UDP 68->67
    with a DHCP payload, rooted at ``l3:ipv4`` with no Ethernet frame.
    """

    return PacketPlan(
        stack=["ipv4", "udp", "dhcp"],
        fields={
            "ipv4": {
                "src": "192.0.2.10",
                "dst": "198.51.100.10",
                "identification": 4242,
                "ttl": 64,
                "flags": "none",
                "protocol": "udp",
            },
            "udp": {"src_port": 68, "dst_port": 67},
            "dhcp": {
                "op": "bootrequest",
                "flags": "none",
                "options": ["message-type=discover", "end"],
            },
        },
        profile="smoke",
        seed=110,
        index=index,
        direction="live_exchange",
        family="ipv4",
        feature_tags=["ipv4", "udp", "dhcp", "dhcp_behavior"],
        case="dhcp-discover",
        strict_bytes=True,
        metadata={
            "plan_id": f"dhcp-discover-{index}",
            "root": "l3:ipv4",
            "root_decoder": "l3:ipv4",
            "wire": {
                "provider": "local-dry-run",
                "compare_root": "l3:ipv4",
                "mutable_fields": [],
                "strict_bytes": True,
            },
            "corpus": {
                "corpus_id": "dhcp-discover-corpus",
                "packet_id": f"dhcp-packet-{index}",
                "corpus_index": 0,
                "packet_index": index,
                "corpus_source": "generated",
                "corpus_path": None,
            },
        },
    )


class DhcpLiveEndpointContractTest(unittest.TestCase):
    """Cover live endpoint batch construction for IPv4-root DHCP.

    The IPv4-root ``ipv4 / udp / dhcp`` stack must ride the existing generic
    endpoint batch contract in both oracle directions; there is no DHCP-specific
    live endpoint protocol. Live runs stay dry-run and never send packets.
    """

    _ENDPOINTS = {
        "libcrafter": LiveEndpoint(
            endpoint_id="local-dry-run-libcrafter",
            role="libcrafter",
            interface="dry-run0",
            address="192.0.2.10",
            ipv6_address="2001:db8:1::10",
            metadata={"provider": "local-dry-run"},
        ),
        "reference_backend": LiveEndpoint(
            endpoint_id="local-dry-run-reference",
            role="reference_backend",
            interface="dry-run1",
            address="192.0.2.20",
            ipv6_address="2001:db8:1::20",
            metadata={"provider": "local-dry-run"},
        ),
    }

    def _build_request(self, direction: str, endpoint_role: str = "libcrafter"):
        plans = [_ipv4_dhcp_plan(11), _ipv4_dhcp_plan(12)]
        peer_role = (
            "reference_backend" if endpoint_role == "libcrafter" else "libcrafter"
        )
        endpoint = self._ENDPOINTS[endpoint_role]
        peer = self._ENDPOINTS[peer_role]
        artifact_paths = live_endpoint_artifact_paths(
            output_dir="target/oracle/test-dhcp-live-endpoint",
            direction=direction,
            endpoint_role=endpoint.role,
        )
        request = build_live_endpoint_batch_request(
            provider="local-dry-run",
            backend="scapy",
            seed=110,
            profile="smoke",
            packet_plans=plans,
            direction=direction,
            endpoint=endpoint,
            peer=peer,
            artifact_paths=artifact_paths,
        )
        return request, plans, artifact_paths

    def test_request_carries_dhcp_packet_ids_and_ipv4_compare_root(self) -> None:
        for direction in _DHCP_DIRECTIONS:
            with self.subTest(direction=direction):
                request, plans, _ = self._build_request(direction)

                self.assertEqual(list(request.packet_plans), plans)
                self.assertEqual(
                    request.metadata["packet_ids"],
                    ["dhcp-packet-11", "dhcp-packet-12"],
                )
                self.assertEqual(request.metadata["corpus_id"], "dhcp-discover-corpus")
                packets = request.metadata["packets"]
                self.assertEqual([packet["index"] for packet in packets], [11, 12])
                self.assertEqual(
                    [packet["packet_id"] for packet in packets],
                    ["dhcp-packet-11", "dhcp-packet-12"],
                )
                self.assertTrue(
                    all(
                        packet["compare_root"] == "l3:ipv4" for packet in packets
                    ),
                    msg=f"DHCP live packets must compare at l3:ipv4 for {direction}",
                )
                # The packet is DHCP over UDP over IPv4: the capture match
                # records the stack and an IPv4 + UDP BPF filter.
                self.assertTrue(
                    all(
                        packet["capture_match"]["layers"] == ["ipv4", "udp", "dhcp"]
                        for packet in packets
                    )
                )
                self.assertTrue(
                    all(
                        packet["capture_match"]["family"] == "ipv4"
                        for packet in packets
                    )
                )
                self.assertTrue(
                    all(
                        packet["capture_match"]["protocol"] == "udp"
                        for packet in packets
                    )
                )

    def test_request_assigns_sender_receiver_roles_and_artifacts(self) -> None:
        # Build the request from libcrafter's perspective in each direction so
        # the sender (libcrafter_to_reference) and receiver
        # (reference_to_libcrafter) role assignments are both covered.
        for direction in _DHCP_DIRECTIONS:
            with self.subTest(direction=direction):
                request, _, artifact_paths = self._build_request(
                    direction, endpoint_role="libcrafter"
                )
                expected_sender = _DHCP_SENDER_ROLE[direction]

                self.assertEqual(request.endpoint_role, "libcrafter")
                self.assertEqual(request.peer_role, "reference_backend")
                self.assertEqual(request.direction, direction)
                # The expected sender role is recorded per packet so each side
                # knows whether it sends or captures.
                self.assertTrue(
                    all(
                        packet["expected_sender_role"] == expected_sender
                        for packet in request.metadata["packets"]
                    )
                )
                self.assertEqual(request.artifact_paths, artifact_paths)
                self.assertIn(
                    f"artifacts/{direction}/libcrafter",
                    artifact_paths["root"],
                )
                self.assertTrue(artifact_paths["response"].endswith("response.json"))
                self.assertTrue(
                    artifact_paths["decoded_models"].endswith("decoded-models.json")
                )

    def test_dry_run_response_validates_against_batch_contract(self) -> None:
        # Cover libcrafter as the sending endpoint (libcrafter_to_reference) and
        # as the receiving endpoint (reference_to_libcrafter); the dry-run
        # response must satisfy the decoded-model batch contract in both phases.
        phases = {
            "libcrafter_to_reference": "send_root",
            "reference_to_libcrafter": "capture_root",
        }
        for direction, phase_root_key in phases.items():
            with self.subTest(direction=direction):
                request, plans, _ = self._build_request(
                    direction, endpoint_role="libcrafter"
                )

                response = dry_run_live_endpoint_batch_response(request)

                self.assertEqual(
                    [status.index for status in response.per_index_status],
                    [plan.index for plan in plans],
                )
                self.assertEqual(response.sent_count, 0)
                self.assertEqual(response.received_count, 0)
                self.assertEqual(response.decoded_models, [])
                self.assertTrue(response.metadata["no_live_packets_sent"])
                self.assertFalse(response.metadata["live_packet_exchange"])

                check = validate_live_endpoint_batch_contract(
                    request, response, dry_run=True
                )
                self.assertTrue(
                    check.passed,
                    msg=f"DHCP dry-run batch contract failed: {check.errors}",
                )
                # Each per-index status reports the IPv4 compare root for the
                # phase libcrafter plays in this direction.
                for status in response.per_index_status:
                    self.assertEqual(getattr(status, phase_root_key), "l3:ipv4")
                    self.assertEqual(status.metadata["compare_root"], "l3:ipv4")
                    self.assertEqual(
                        status.metadata["expected_sender_role"],
                        _DHCP_SENDER_ROLE[direction],
                    )


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
        private_group: str | None = None,
        private_ip: str | None = None,
        dry_run: bool = False,
        confirm_live_run: bool = False,
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
        interface = {
            "name": "oracle0" if provider != "virtualbox" else "private",
            "exposure": exposure,
            "ipv4": private_ip,
            "provider_network_id": private_group,
            "metadata": {"private_group": private_group},
        }
        return SimpleNamespace(
            manifest=SimpleNamespace(endpoint_id=endpoint_id),
            record=_FakeRecord(role),
            json_data={
                "endpoint_id": endpoint_id,
                "provider": provider,
                "exposure": exposure,
                "role": role,
                "interfaces": [interface],
                "metadata": (
                    {"private_group": private_group}
                    if private_group is not None
                    else {}
                ),
            },
        )


def _endpoint_bootstrap_topology(adapter, *, dry_run: bool) -> dict[str, object]:
    capabilities = adapter.default_provider_capabilities(dry_run=dry_run)
    return oracle_bootstrap.endpoint_bootstrap_topology(
        adapter.packet_exchange_metadata(dry_run=dry_run),
        capabilities,
    )


def _endpoint_bootstrap_plan(adapter, *, dry_run: bool):
    capabilities = adapter.default_provider_capabilities(dry_run=dry_run)
    return oracle_bootstrap.endpoint_bootstrap_plan(
        adapter.name,
        dry_run,
        capabilities,
        _endpoint_bootstrap_topology(adapter, dry_run=dry_run),
    )


def _validate_endpoint_bootstrap(adapter, commands, *, dry_run: bool):
    return oracle_bootstrap.validate_endpoint_bootstrap(
        adapter.name,
        commands,
        dry_run=dry_run,
        topology_metadata=_endpoint_bootstrap_topology(adapter, dry_run=dry_run),
    )


def _endpoint_bootstrap_command(
    adapter,
    *,
    endpoint: LiveEndpoint,
    peer: LiveEndpoint,
    remote_archive: str,
    remote_dir: str,
) -> list[str]:
    return oracle_bootstrap.endpoint_bootstrap_command(
        provider=adapter.name,
        endpoint=endpoint,
        peer=peer,
        remote_archive=remote_archive,
        remote_dir=remote_dir,
        topology_metadata=_endpoint_bootstrap_topology(adapter, dry_run=True),
    )


def _workload_bootstrap_records(command_records) -> list[dict[str, object]]:
    return [
        record
        for record in command_records
        if isinstance(record, dict)
        and isinstance(record.get("metadata"), dict)
        and record["metadata"].get("phase") == "workload-bootstrap"
    ]


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


def _fake_repo_archive(output_dir: Path, **_: object) -> RepoArchiveResult:
    archive = output_dir / "fake-repo.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_text("fake archive", encoding="utf-8")
    stdout = output_dir / "repo-archive.stdout.txt"
    stderr = output_dir / "repo-archive.stderr.txt"
    stdout.write_text("", encoding="utf-8")
    stderr.write_text("", encoding="utf-8")
    return RepoArchiveResult(
        archive_path=archive,
        stdout_path=stdout,
        stderr_path=stderr,
        command_record=LabCommandPlan(
            purpose="create repository archive",
            role=None,
            argv=["tar", "-czf", str(archive), "."],
            operation="lab.repo_archive",
            dry_run=False,
            live_mutation=False,
            artifacts=[str(archive), str(stdout), str(stderr)],
            metadata={
                "ok": True,
                "exit_code": 0,
                "stdout_path": str(stdout),
                "stderr_path": str(stderr),
            },
        ),
    )


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
        self.remote_command_calls: list[dict[str, str]] = []
        self.transit_plan_ttls: list[int] = []
        self.normalized_endpoint_roles: list[str] = []
        self.lab_provider_adapter = _FakeLabProviderAdapter(self)

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

    def validate_provider_workflow(self, commands, *, dry_run: bool):
        raise AssertionError("not used by real execution test")

    def validate_dry_run_exchange(self, exchange):
        raise AssertionError("not used by real execution test")

    def remote_dir(self) -> str:
        return "/srv/fake-oracle"

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

    def normalize_live_endpoints(
        self,
        endpoints: dict[str, LiveEndpoint],
    ) -> dict[str, LiveEndpoint]:
        self.normalized_endpoint_roles = sorted(endpoints)
        return endpoints

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


class _FakeLabProviderAdapter:
    def __init__(self, oracle_adapter: _FakeLiveProviderAdapter) -> None:
        self.oracle_adapter = oracle_adapter
        self.name = oracle_adapter.name
        self.wire_provider = oracle_adapter.wire_provider
        self.wire_exposure = oracle_adapter.wire_exposure
        self.credential_label = oracle_adapter.credential_label
        self.missing_credential_reason = oracle_adapter.missing_credential_reason

    def plan_session(
        self,
        request: LabRequest,
        *,
        client,
    ) -> LabSession:
        endpoints: list[LabEndpoint] = []
        command_records: list[LabCommandPlan] = []
        created_endpoint_ids: list[str] = []
        role_addresses = dict(self.oracle_adapter.endpoint_private_ips)

        for role in request.roles:
            response = client.create(
                provider=self.wire_provider,
                exposure=self.wire_exposure,
                role=role.name,
                private_group=self.oracle_adapter.private_group,
                private_ip=role_addresses[role.name],
                dry_run=request.dry_run,
                write_manifest=not request.dry_run,
                confirm_live_run=request.confirm_live_run,
            )
            endpoint_id = f"fake-{role.name}"
            created_endpoint_ids.append(endpoint_id)
            command_records.append(
                response.command_plan(
                    purpose=f"create {role.name} fake lab endpoint",
                    role=role.name,
                )
            )
            endpoints.append(
                LabEndpoint(
                    endpoint_id=endpoint_id,
                    role=role.name,
                    interface="fake0",
                    ipv4=role_addresses[role.name],
                    peer_addresses={
                        peer.name: {"ipv4": role_addresses[peer.name]}
                        for peer in request.roles
                        if peer.name != role.name
                    },
                    wire_manifest={
                        "endpoint_id": endpoint_id,
                        "provider": self.wire_provider,
                        "exposure": self.wire_exposure,
                        "role": role.name,
                    },
                    metadata={
                        "provider": self.name,
                        "wire_provider": self.wire_provider,
                        "wire_exposure": self.wire_exposure,
                    },
                )
            )

        remote_dir = request.remote_dir or "/srv/fake-oracle"
        return LabSession(
            provider=self.name,
            wire_provider=self.wire_provider,
            wire_exposure=self.wire_exposure,
            session_id="oracle-live",
            roles=list(request.roles),
            endpoints=endpoints,
            provider_capabilities=self.oracle_adapter.default_provider_capabilities(
                dry_run=request.dry_run,
            ),
            infrastructure_metadata=self.oracle_adapter.planned_infrastructure(
                dry_run=request.dry_run,
            ),
            provider_workflow=[
                LabCommandPlan(
                    purpose="check-fake-provider",
                    role=None,
                    argv=["fake-wire", "doctor"],
                    operation="wire.doctor",
                    dry_run=request.dry_run,
                    live_mutation=False,
                    metadata={"provider": self.name, "exposure": self.wire_exposure},
                )
            ],
            command_records=command_records,
            remote_dir=remote_dir,
            remote_artifact_root=f"{remote_dir}/artifacts/oracle-live",
            created_endpoint_ids=created_endpoint_ids,
            dry_run=request.dry_run,
            cleanup_state={
                "status": "not_started",
                "artifact_collection_attempted": False,
                "teardown_attempted": False,
            },
            metadata={
                "provider": self.name,
                "wire_endpoint_plan": {
                    "provider": self.name,
                    "wire_provider": self.wire_provider,
                    "wire_exposure": self.wire_exposure,
                    "exposure": self.wire_exposure,
                    "created_endpoint_ids": created_endpoint_ids,
                    "endpoint_count": len(endpoints),
                },
            },
        )


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
        write_manifest: bool = True,
        confirm_live_run: bool = False,
    ):
        del write_manifest
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
        self.ok = exit_code == 0
        self.exit_code = exit_code
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

    def command_plan(
        self,
        *,
        purpose: str | None = None,
        role: str | None = None,
        artifacts: list[str] = (),
    ) -> LabCommandPlan:
        return LabCommandPlan(
            purpose=purpose or f"wire {self.record.operation}",
            role=role,
            argv=list(self.record.to_dict()["argv"]),
            operation={
                "collect-artifacts": "wire.collect_artifacts",
                "create-endpoint": "wire.create",
                "destroy-endpoint": "wire.destroy",
                "download": "wire.download",
                "doctor": "wire.doctor",
                "exec": "wire.exec",
                "upload": "wire.upload",
            }.get(self.record.operation, f"wire.{self.record.operation}"),
            dry_run=False,
            live_mutation=self.record.operation in {"create-endpoint", "destroy-endpoint"},
            artifacts=list(artifacts),
            metadata=self.metadata(),
        )


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
