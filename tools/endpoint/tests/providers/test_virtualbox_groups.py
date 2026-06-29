"""VirtualBox appliance group helper coverage."""

from __future__ import annotations

import os
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from unittest import mock

from tools.endpoint.engine.assets import (
    AssetSSHInfo,
    EndpointAsset,
    write_endpoint_asset,
)
from tools.endpoint.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    ProviderResource,
    ProviderResources,
)
from tools.endpoint.engine.process import CommandResult
from tools.endpoint.engine.providers.virtualbox.constants import (
    VBOX_DEFAULT_APPLIANCE_GROUP,
)
from tools.endpoint.engine.providers.virtualbox.groups import (
    collect_tracked_vm_group_candidates,
    default_group_metadata,
    modifyvm_groups_command,
    normalize_group_path,
    normalize_group_paths,
    normalize_tracked_vm_groups,
    parse_showvminfo_groups,
    showvminfo_has_group,
)
from tools.endpoint.engine.state import write_endpoint_manifest


class VirtualBoxGroupHelpersTest(unittest.TestCase):
    def test_default_group_value_and_metadata(self) -> None:
        self.assertEqual(VBOX_DEFAULT_APPLIANCE_GROUP, "/libcrafter/appliances")
        self.assertEqual(default_group_metadata(), ["/libcrafter/appliances"])
        self.assertEqual(normalize_group_paths(), ("/libcrafter/appliances",))

    def test_valid_group_paths_are_normalized_for_metadata(self) -> None:
        self.assertEqual(
            normalize_group_path("/libcrafter/appliances"),
            "/libcrafter/appliances",
        )
        self.assertEqual(
            normalize_group_paths(("/libcrafter/appliances", "/libcrafter/fixtures")),
            ("/libcrafter/appliances", "/libcrafter/fixtures"),
        )

    def test_invalid_group_paths_are_rejected(self) -> None:
        invalid_values = (
            "",
            "libcrafter/appliances",
            "/",
            "/libcrafter/",
            "/libcrafter//appliances",
            " /libcrafter/appliances",
            "/libcrafter/appliances ",
        )
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_group_path(value)

    def test_modifyvm_group_command_shape(self) -> None:
        self.assertEqual(
            modifyvm_groups_command("wire-virtualbox-lan-test"),
            [
                "VBoxManage",
                "modifyvm",
                "wire-virtualbox-lan-test",
                "--groups",
                "/libcrafter/appliances",
            ],
        )
        self.assertEqual(
            modifyvm_groups_command(
                "wire-virtualbox-lan-test",
                ("/libcrafter/appliances", "/libcrafter/fixtures"),
            ),
            [
                "VBoxManage",
                "modifyvm",
                "wire-virtualbox-lan-test",
                "--groups",
                "/libcrafter/appliances,/libcrafter/fixtures",
            ],
        )

    def test_showvminfo_group_parsing_missing_group_line(self) -> None:
        stdout = 'name="wire-virtualbox-lan-test"\nVMState="running"\n'

        self.assertEqual(parse_showvminfo_groups(stdout), ())
        self.assertFalse(showvminfo_has_group(stdout))

    def test_showvminfo_group_parsing_single_group(self) -> None:
        stdout = 'name="wire-virtualbox-lan-test"\ngroups="/libcrafter/appliances"\n'

        self.assertEqual(parse_showvminfo_groups(stdout), ("/libcrafter/appliances",))
        self.assertTrue(showvminfo_has_group(stdout))

    def test_showvminfo_group_parsing_multi_group(self) -> None:
        stdout = (
            'name="wire-virtualbox-lan-test"\n'
            'groups="/manual,/libcrafter/appliances,/libcrafter/fixtures"\n'
        )

        self.assertEqual(
            parse_showvminfo_groups(stdout),
            ("/manual", "/libcrafter/appliances", "/libcrafter/fixtures"),
        )
        self.assertTrue(showvminfo_has_group(stdout))
        self.assertFalse(showvminfo_has_group(stdout, "/libcrafter/missing"))


class VirtualBoxGroupNormalizationTest(unittest.TestCase):
    def test_collect_candidates_uses_only_tracked_virtualbox_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            write_endpoint_manifest(_manifest(Path(temp_dir), vm_name="tracked-vm-a"))
            write_endpoint_manifest(
                _manifest(
                    Path(temp_dir),
                    endpoint_id="destroyed-endpoint",
                    vm_name="destroyed-vm",
                    status="destroyed",
                )
            )
            write_endpoint_asset(_asset(Path(temp_dir), vm_name="tracked-vm-a"))
            write_endpoint_asset(
                _asset(
                    Path(temp_dir),
                    asset_id="qemu-asset",
                    substrate="qemu",
                    vm_name="manual-vm",
                )
            )

            candidates = collect_tracked_vm_group_candidates()

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["vm_name"], "tracked-vm-a")
        sources = candidates[0]["sources"]  # type: ignore[index]
        self.assertEqual(
            [source["kind"] for source in sources],  # type: ignore[index]
            ["endpoint-manifest", "endpoint-manifest", "endpoint-asset"],
        )
        self.assertNotIn("destroyed-vm", str(candidates))
        self.assertNotIn("manual-vm", str(candidates))

    def test_dry_run_reports_modifyvm_without_mutating(self) -> None:
        fake = _FakeVBoxManageRunner(
            [_showvminfo("tracked-vm-a", groups=("/manual",))]
        )
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            write_endpoint_manifest(_manifest(Path(temp_dir), vm_name="tracked-vm-a"))

            output = normalize_tracked_vm_groups(dry_run=True, command_runner=fake)

        self.assertTrue(output["ok"])
        self.assertEqual(output["planned_count"], 1)
        self.assertEqual(output["changed_count"], 0)
        self.assertEqual(
            fake.calls,
            [("VBoxManage", "showvminfo", "tracked-vm-a", "--machinereadable")],
        )
        candidate = output["candidates"][0]  # type: ignore[index]
        self.assertEqual(candidate["status"], "planned")
        self.assertTrue(candidate["planned"])
        self.assertFalse(candidate["executed"])
        self.assertEqual(
            candidate["modify_command"],
            "VBoxManage modifyvm tracked-vm-a --groups /libcrafter/appliances",
        )

    def test_confirmed_run_executes_modifyvm_for_ungrouped_vm(self) -> None:
        fake = _FakeVBoxManageRunner(
            [
                _showvminfo("tracked-vm-a"),
                _result(
                    ("VBoxManage", "modifyvm", "tracked-vm-a", "--groups", "/libcrafter/appliances")
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            write_endpoint_asset(_asset(Path(temp_dir), vm_name="tracked-vm-a"))

            output = normalize_tracked_vm_groups(
                confirm_live_run=True,
                command_runner=fake,
            )

        self.assertTrue(output["ok"])
        self.assertEqual(output["changed_count"], 1)
        self.assertEqual(
            fake.calls,
            [
                ("VBoxManage", "showvminfo", "tracked-vm-a", "--machinereadable"),
                ("VBoxManage", "modifyvm", "tracked-vm-a", "--groups", "/libcrafter/appliances"),
            ],
        )
        candidate = output["candidates"][0]  # type: ignore[index]
        self.assertEqual(candidate["status"], "updated")
        self.assertTrue(candidate["executed"])
        self.assertTrue(candidate["changed"])

    def test_already_grouped_vm_is_not_modified(self) -> None:
        fake = _FakeVBoxManageRunner(
            [_showvminfo("tracked-vm-a", groups=("/libcrafter/appliances",))]
        )
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            write_endpoint_manifest(_manifest(Path(temp_dir), vm_name="tracked-vm-a"))

            output = normalize_tracked_vm_groups(
                confirm_live_run=True,
                command_runner=fake,
            )

        self.assertTrue(output["ok"])
        self.assertEqual(output["already_grouped_count"], 1)
        self.assertEqual(
            fake.calls,
            [("VBoxManage", "showvminfo", "tracked-vm-a", "--machinereadable")],
        )
        candidate = output["candidates"][0]  # type: ignore[index]
        self.assertEqual(candidate["status"], "already-grouped")
        self.assertFalse(candidate["planned"])
        self.assertFalse(candidate["executed"])

    def test_missing_vm_is_reported_without_stopping_or_destroying(self) -> None:
        fake = _FakeVBoxManageRunner(
            [
                _result(
                    ("VBoxManage", "showvminfo", "tracked-vm-a", "--machinereadable"),
                    exit_code=1,
                    stderr=(
                        "VBoxManage: error: Could not find a registered machine named "
                        "'tracked-vm-a'"
                    ),
                )
            ]
        )
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            write_endpoint_manifest(_manifest(Path(temp_dir), vm_name="tracked-vm-a"))

            output = normalize_tracked_vm_groups(dry_run=True, command_runner=fake)

        self.assertFalse(output["ok"])
        self.assertEqual(output["missing_count"], 1)
        candidate = output["candidates"][0]  # type: ignore[index]
        self.assertEqual(candidate["status"], "missing")
        self.assertIn("missing", candidate["reason"])
        flattened = [part for call in fake.calls for part in call]
        self.assertNotIn("controlvm", flattened)
        self.assertNotIn("unregistervm", flattened)

    def test_provider_resource_vm_name_is_a_candidate_when_metadata_is_partial(self) -> None:
        fake = _FakeVBoxManageRunner([_showvminfo("resource-vm")])
        with tempfile.TemporaryDirectory() as temp_dir, _endpoint_env(Path(temp_dir)):
            write_endpoint_manifest(
                _manifest(
                    Path(temp_dir),
                    vm_name=None,
                    resource_vm_name="resource-vm",
                )
            )

            output = normalize_tracked_vm_groups(dry_run=True, command_runner=fake)

        self.assertEqual(output["candidate_count"], 1)
        self.assertEqual(
            fake.calls,
            [("VBoxManage", "showvminfo", "resource-vm", "--machinereadable")],
        )
        candidate = output["candidates"][0]  # type: ignore[index]
        self.assertEqual(candidate["vm_name"], "resource-vm")

    def test_normalize_requires_dry_run_or_confirmation(self) -> None:
        with self.assertRaisesRegex(PermissionError, "requires --dry-run"):
            normalize_tracked_vm_groups()


class _FakeVBoxManageRunner:
    def __init__(self, results: Sequence[CommandResult]) -> None:
        self._results = list(results)
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[object], **_: object) -> CommandResult:
        call = tuple(str(part) for part in argv)
        self.calls.append(call)
        if not self._results:
            return _result(call, exit_code=127, stderr=f"unexpected command: {call!r}")
        expected = self._results.pop(0)
        if expected.argv != call:
            raise AssertionError(f"expected command {expected.argv!r}, got {call!r}")
        return expected


def _manifest(
    root: Path,
    *,
    endpoint_id: str = "virtualbox-lan-test",
    vm_name: str | None = "tracked-vm-a",
    resource_vm_name: str | None = None,
    status: str = "active",
) -> EndpointManifest:
    state_dir = root / "wire-state" / "endpoints" / endpoint_id
    artifact_dir = root / "wire-artifacts" / endpoint_id
    provider_id = resource_vm_name or vm_name or f"{endpoint_id}-vm"
    metadata: dict[str, object] = {"created": True}
    if vm_name is not None:
        metadata["virtualbox"] = {"vm_name": vm_name}
    return EndpointManifest(
        endpoint_id=endpoint_id,
        provider="virtualbox",
        exposure="lan",
        status=status,
        role="test",
        created_at="2026-06-29T20:00:00Z",
        ssh=EndpointSSHInfo(
            host="127.0.0.1",
            user="root",
            port=25222,
            identity_file=str(state_dir / "id_ed25519"),
            known_hosts_file=str(state_dir / "known_hosts"),
        ),
        interfaces=[],
        provider_resources=ProviderResources(
            resources=[
                ProviderResource(
                    kind="virtualbox-vm",
                    provider_id=provider_id,
                    name=provider_id,
                    metadata={"vm_name": provider_id},
                )
            ],
            cleanup_order=["virtualbox-vm"],
            metadata={"provider": "virtualbox"},
        ),
        artifact_dir=str(artifact_dir),
        metadata=metadata,
    )


def _asset(
    root: Path,
    *,
    asset_id: str = "virtualbox-asset-a",
    substrate: str = "virtualbox",
    vm_name: str = "tracked-vm-a",
) -> EndpointAsset:
    state_dir = root / "wire-state" / "assets" / asset_id
    return EndpointAsset(
        asset_id=asset_id,
        substrate=substrate,
        status="available",
        supported_profiles=["lan-raw"],
        ssh=AssetSSHInfo(
            host="127.0.0.1",
            user="root",
            port=25222,
            identity_file=str(state_dir / "id_ed25519"),
            known_hosts_file=str(state_dir / "known_hosts"),
        ),
        metadata={"virtualbox": {"vm_name": vm_name}},
    )


def _showvminfo(vm_name: str, *, groups: Sequence[str] = ()) -> CommandResult:
    lines = [f'name="{vm_name}"']
    if groups:
        lines.append(f'groups="{",".join(groups)}"')
    return _result(
        ("VBoxManage", "showvminfo", vm_name, "--machinereadable"),
        stdout="\n".join(lines),
    )


def _result(
    argv: Sequence[str],
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> CommandResult:
    return CommandResult(
        argv=tuple(argv),
        redacted_argv=tuple(argv),
        cwd=None,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
    )


def _endpoint_env(
    root: Path,
    extra: Mapping[str, str] | None = None,
) -> mock._patch_dict[str, str]:
    env = {
        "LIBCRAFTER_ENDPOINT_STATE_ROOT": str(root / "wire-state"),
        "LIBCRAFTER_ENDPOINT_ARTIFACT_ROOT": str(root / "wire-artifacts"),
    }
    if extra is not None:
        env.update(extra)
    return mock.patch.dict(os.environ, env)


if __name__ == "__main__":
    unittest.main()
