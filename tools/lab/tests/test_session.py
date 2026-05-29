"""Local contract coverage for lab paths and session state."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.lab.engine.model import LabRole, LabSession
from tools.lab.engine.paths import (
    DEFAULT_ARTIFACT_ROOT,
    DEFAULT_STATE_ROOT,
    LAB_ARTIFACT_ROOT_ENV,
    LAB_STATE_ROOT_ENV,
    LabConfig,
    command_artifact_dir,
    command_artifact_path,
    default_config,
    remote_artifact_root,
    remote_session_dir,
    session_artifact_dir,
    session_layout,
    session_manifest_path,
    session_state_dir,
)
from tools.lab.engine.session import (
    ensure_session_dirs,
    list_session_manifests,
    read_session_manifest,
    write_session_manifest,
)


class LabPathTest(unittest.TestCase):
    def test_default_roots_are_ignored_tool_local_paths(self) -> None:
        config = default_config(env={})

        self.assertEqual(config.state_root, DEFAULT_STATE_ROOT.resolve(strict=False))
        self.assertEqual(config.artifact_root, DEFAULT_ARTIFACT_ROOT.resolve(strict=False))
        self.assertEqual(config.state_root.name, ".state")
        self.assertEqual(config.artifact_root.name, "artifacts")
        self.assertEqual(config.state_root.parent.name, "lab")
        self.assertEqual(config.artifact_root.parent.name, "lab")

    def test_environment_overrides_use_libcrafter_lab_names(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            env = {
                LAB_STATE_ROOT_ENV: str(root / "lab-state"),
                LAB_ARTIFACT_ROOT_ENV: str(root / "lab-artifacts"),
            }

            config = default_config(env=env)

            self.assertEqual(config.state_root, root / "lab-state")
            self.assertEqual(config.artifact_root, root / "lab-artifacts")

    def test_session_and_command_paths_are_absolute_and_component_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = LabConfig(
                state_root=root / "lab-state",
                artifact_root=root / "lab-artifacts",
            )

            self.assertEqual(
                session_state_dir("lab-smoke-0001", config),
                root / "lab-state" / "sessions" / "lab-smoke-0001",
            )
            self.assertEqual(
                session_manifest_path("lab-smoke-0001", config),
                root / "lab-state" / "sessions" / "lab-smoke-0001" / "session.json",
            )
            self.assertEqual(
                session_artifact_dir("lab-smoke-0001", config),
                root / "lab-artifacts" / "lab-smoke-0001",
            )
            self.assertEqual(
                command_artifact_dir("lab-smoke-0001", "bootstrap-target", config),
                root / "lab-artifacts" / "lab-smoke-0001" / "commands" / "bootstrap-target",
            )
            self.assertEqual(
                command_artifact_path("lab-smoke-0001", "bootstrap-target", "stdout.log", config),
                root
                / "lab-artifacts"
                / "lab-smoke-0001"
                / "commands"
                / "bootstrap-target"
                / "stdout.log",
            )
            layout = session_layout("lab-smoke-0001", config)
            self.assertTrue(layout.manifest_path.is_absolute())
            self.assertTrue(layout.command_artifact_root.is_absolute())

        with self.assertRaisesRegex(ValueError, "session_id must be a safe path component"):
            session_manifest_path("../lab")
        with self.assertRaisesRegex(ValueError, "artifact_name must be a safe path component"):
            command_artifact_path("lab-smoke-0001", "bootstrap-target", "../stdout")

    def test_remote_session_and_artifact_paths_are_absolute_posix_paths(self) -> None:
        self.assertEqual(
            remote_session_dir("lab-smoke-0001"),
            "/opt/libcrafter-lab/lab-smoke-0001",
        )
        self.assertEqual(
            remote_artifact_root("lab-smoke-0001"),
            "/opt/libcrafter-lab/lab-smoke-0001/artifacts",
        )
        self.assertEqual(
            remote_artifact_root("lab-smoke-0001", remote_dir="/tmp/lab-session"),
            "/tmp/lab-session/artifacts",
        )

        with self.assertRaisesRegex(ValueError, "remote path must be absolute"):
            remote_artifact_root("lab-smoke-0001", remote_dir="relative/session")


class LabSessionStateTest(unittest.TestCase):
    def test_manifest_round_trip_and_listing_use_configured_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = LabConfig(
                state_root=root / "lab-state",
                artifact_root=root / "lab-artifacts",
            )
            first = _session("lab-smoke-0002")
            second = _session("lab-smoke-0001")

            first_path = write_session_manifest(first, config)
            second_path = write_session_manifest(second, config)
            loaded = read_session_manifest("lab-smoke-0002", config)
            listed = list_session_manifests(config)

            self.assertEqual(
                first_path,
                root / "lab-state" / "sessions" / "lab-smoke-0002" / "session.json",
            )
            self.assertEqual(
                second_path,
                root / "lab-state" / "sessions" / "lab-smoke-0001" / "session.json",
            )
            self.assertEqual(loaded.to_dict(), first.to_dict())
            self.assertEqual(
                [session.session_id for session in listed],
                ["lab-smoke-0001", "lab-smoke-0002"],
            )
            self.assertTrue((root / "lab-artifacts" / "lab-smoke-0002" / "commands").is_dir())

    def test_default_manifest_helpers_honor_environment_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            env = {
                LAB_STATE_ROOT_ENV: str(root / "state"),
                LAB_ARTIFACT_ROOT_ENV: str(root / "artifacts"),
            }
            with patch.dict("os.environ", env, clear=False):
                path = write_session_manifest(_session("lab-env-0001"))
                loaded = read_session_manifest("lab-env-0001")

            self.assertEqual(
                path,
                root / "state" / "sessions" / "lab-env-0001" / "session.json",
            )
            self.assertEqual(loaded.session_id, "lab-env-0001")

    def test_write_rejects_non_session(self) -> None:
        with self.assertRaisesRegex(TypeError, "session must be a LabSession"):
            write_session_manifest(object())  # type: ignore[arg-type]

    def test_ensure_session_dirs_creates_state_and_command_artifact_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = LabConfig(
                state_root=root / "lab-state",
                artifact_root=root / "lab-artifacts",
            )

            layout = ensure_session_dirs("lab-smoke-0001", config)

            self.assertTrue(layout.state_dir.is_dir())
            self.assertTrue(layout.command_artifact_root.is_dir())
            self.assertFalse(layout.manifest_path.exists())


def _session(session_id: str) -> LabSession:
    return LabSession(
        provider="qemu",
        wire_provider="qemu",
        wire_exposure="private",
        session_id=session_id,
        roles=[LabRole(name="stimulus"), LabRole(name="target")],
        remote_dir=f"/opt/libcrafter-lab/{session_id}",
        remote_artifact_root=f"/opt/libcrafter-lab/{session_id}/artifacts",
        dry_run=True,
    )


if __name__ == "__main__":
    unittest.main()
