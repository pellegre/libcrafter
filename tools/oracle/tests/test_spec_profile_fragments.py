"""Coverage for per-protocol sampling-profile fragment discovery.

The spec loader discovers and merges optional fragments from
``tools/oracle/specs/profiles.d/*.yaml`` into the monolithic ``profiles.yaml`` so
a new protocol can add its sampling ``profiles`` in its own file. These tests
point the loader at a temporary spec root that mirrors the real one (the same
technique ``test_spec_loader.py`` and ``test_spec_stack_fragments.py`` use to
drive the loader) and assert that fragment profiles appear in the merged
:class:`OracleSpecs` and that duplicate names across files are rejected rather
than silently overridden.
"""

from __future__ import annotations

import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path

from tools.oracle.engine.spec_loader import (
    SPEC_ROOT,
    ProfileSpec,
    SpecValidationError,
    load_oracle_specs,
)


_FRAGMENT_PROFILE = textwrap.dedent(
    """\
    version: 1
    kind: profiles
    name: example_protocol_profiles

    profiles:
      - name: example-fragment-smoke
        purpose: example per-protocol boundary coverage
        default_count: 10
        family_weights:
          - name: ipv4
            weight: 1
        payload_length:
          min: 0
          max: 32
        feature_weights:
          baseline: 10
          boundary: 1
    """
)

# Reuses the "smoke" profile name that already lives in profiles.yaml so the
# merge collides on a profile name and must raise.
_FRAGMENT_DUPLICATE_PROFILE = textwrap.dedent(
    """\
    version: 1
    kind: profiles
    name: duplicate_protocol_profiles

    profiles:
      - name: smoke
        purpose: duplicate of the monolithic smoke profile
        default_count: 10
        family_weights:
          - name: ipv4
            weight: 1
        payload_length:
          min: 0
          max: 32
        feature_weights:
          baseline: 10
          boundary: 1
    """
)


class ProfileFragmentTest(unittest.TestCase):
    def _mirror_spec_root(self) -> Path:
        # Mirror the real spec tree into a temporary root the loader accepts,
        # then layer fragments under profiles.d/ without touching tracked specs.
        temp_dir = Path(tempfile.mkdtemp(prefix="oracle-spec-root-"))
        self.addCleanup(shutil.rmtree, temp_dir, ignore_errors=True)
        spec_root = temp_dir / "specs"
        shutil.copytree(SPEC_ROOT, spec_root)
        return spec_root

    def _write_fragment(self, spec_root: Path, name: str, body: str) -> None:
        fragments_dir = spec_root / "profiles.d"
        fragments_dir.mkdir(exist_ok=True)
        (fragments_dir / name).write_text(body, encoding="utf-8")

    def test_mirrored_spec_root_loads_without_fragments(self) -> None:
        # The mirror itself must load (back-compat: profiles.d/ holds no .yaml).
        spec_root = self._mirror_spec_root()
        specs = load_oracle_specs(spec_root)
        self.assertIn("smoke", specs.profiles)
        self.assertNotIn("example-fragment-smoke", specs.profiles)

    def test_fragment_entries_appear_in_merged_specs(self) -> None:
        spec_root = self._mirror_spec_root()
        self._write_fragment(spec_root, "example.yaml", _FRAGMENT_PROFILE)

        specs = load_oracle_specs(spec_root)

        self.assertIn("example-fragment-smoke", specs.profiles)
        fragment_profile = specs.profiles["example-fragment-smoke"]
        self.assertIsInstance(fragment_profile, ProfileSpec)
        self.assertEqual(fragment_profile.default_count, 10)
        self.assertEqual(
            tuple((weight.name, weight.weight) for weight in fragment_profile.family_weights),
            (("ipv4", 1),),
        )
        # The monolithic profiles.yaml entries are still present alongside it.
        self.assertIn("smoke", specs.profiles)
        # The fragment file is recorded as a source path.
        self.assertTrue(
            any(path.endswith("profiles.d/example.yaml") for path in specs.source_paths),
            specs.source_paths,
        )

    def test_duplicate_profile_name_across_files_raises(self) -> None:
        spec_root = self._mirror_spec_root()
        self._write_fragment(spec_root, "duplicate.yaml", _FRAGMENT_DUPLICATE_PROFILE)

        with self.assertRaises(SpecValidationError) as ctx:
            load_oracle_specs(spec_root)
        self.assertIn("duplicate profile name smoke", str(ctx.exception))

    def test_duplicate_across_two_fragments_raises(self) -> None:
        # Sorted glob order makes the collision deterministic across fragments.
        spec_root = self._mirror_spec_root()
        self._write_fragment(spec_root, "a-example.yaml", _FRAGMENT_PROFILE)
        self._write_fragment(spec_root, "b-example.yaml", _FRAGMENT_PROFILE)

        with self.assertRaises(SpecValidationError) as ctx:
            load_oracle_specs(spec_root)
        self.assertIn(
            "duplicate profile name example-fragment-smoke", str(ctx.exception)
        )


if __name__ == "__main__":
    unittest.main()
