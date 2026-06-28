"""Coverage for appliance profile manifest registry loading."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.appliance.engine.profiles import (
    UnknownApplianceProfileError,
    list_profile_names,
    load_profiles,
    resolve_profile,
)


class ApplianceProfileRegistryTest(unittest.TestCase):
    def test_lists_profile_names_in_sorted_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_profile(root / "z-wan.json", "wan-raw")
            self._write_profile(root / "a-lan.json", "lan-raw")

            self.assertEqual(list_profile_names(root), ("lan-raw", "wan-raw"))

    def test_rejects_duplicate_profile_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_profile(root / "first.json", "wan-raw")
            self._write_profile(root / "second.json", "wan-raw")

            with self.assertRaisesRegex(ValueError, "duplicate appliance profile 'wan-raw'"):
                load_profiles(root)

    def test_rejects_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bad.json").write_text("{", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "invalid JSON"):
                load_profiles(root)

    def test_resolve_profile_rejects_unknown_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_profile(root / "wan.json", "wan-raw")

            with self.assertRaises(UnknownApplianceProfileError) as captured:
                resolve_profile("lan-raw", root)

            self.assertEqual(captured.exception.name, "lan-raw")
            self.assertEqual(captured.exception.known, ("wan-raw",))
            self.assertIn("known profiles: wan-raw", str(captured.exception))

    def test_resolves_profile_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_profile(root / "wan.json", "wan-raw")

            profile = resolve_profile("wan-raw", root)

            self.assertEqual(profile.name, "wan-raw")

    def _write_profile(self, path: Path, name: str) -> None:
        path.write_text(
            (
                "{\n"
                f'  "name": "{name}",\n'
                '  "description": "test profile"\n'
                "}\n"
            ),
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
