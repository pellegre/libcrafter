"""Coverage for per-protocol stack-grammar fragment discovery.

The spec loader discovers and merges optional fragments from
``tools/oracle/specs/stacks.d/*.yaml`` into the monolithic ``stacks.yaml`` so a
new protocol can add its ``roots``/``families``/``stacks``/``constraints`` in its
own file. These tests point the loader at a temporary spec root that mirrors the
real one (the same technique ``test_spec_loader.py`` uses to drive the loader)
and assert that fragment entries appear in the merged :class:`OracleSpecs` and
that duplicate names across files are rejected rather than silently overridden.
"""

from __future__ import annotations

import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path

from tools.oracle.engine.spec_loader import (
    SPEC_ROOT,
    SpecValidationError,
    StackSpec,
    load_oracle_specs,
)


_FRAGMENT_STACK = textwrap.dedent(
    """\
    version: 1
    kind: stack_grammar
    name: example_protocol_stacks

    stacks:
      - name: ipv4_fragment_example
        root: "l3:ipv4"
        layers:
          - ipv4
          - payload
        coverage_cases:
          - ipv4-boundary-fields
    """
)

# Reuses the "ipv4_payload" stack name that already lives in stacks.yaml so the
# merge collides on a stack name and must raise.
_FRAGMENT_DUPLICATE_STACK = textwrap.dedent(
    """\
    version: 1
    kind: stack_grammar
    name: duplicate_protocol_stacks

    stacks:
      - name: ipv4_payload
        root: "l3:ipv4"
        layers:
          - ipv4
          - payload
    """
)


class StackFragmentTest(unittest.TestCase):
    def _mirror_spec_root(self) -> Path:
        # Mirror the real spec tree into a temporary root the loader accepts,
        # then layer fragments under stacks.d/ without touching tracked specs.
        temp_dir = Path(tempfile.mkdtemp(prefix="oracle-spec-root-"))
        self.addCleanup(shutil.rmtree, temp_dir, ignore_errors=True)
        spec_root = temp_dir / "specs"
        shutil.copytree(SPEC_ROOT, spec_root)
        return spec_root

    def _write_fragment(self, spec_root: Path, name: str, body: str) -> None:
        fragments_dir = spec_root / "stacks.d"
        fragments_dir.mkdir(exist_ok=True)
        (fragments_dir / name).write_text(body, encoding="utf-8")

    def test_mirrored_spec_root_loads_without_fragments(self) -> None:
        # The mirror itself must load (back-compat: stacks.d/ holds no .yaml).
        spec_root = self._mirror_spec_root()
        specs = load_oracle_specs(spec_root)
        self.assertIn("ipv4_payload", specs.stacks)
        self.assertNotIn("ipv4_fragment_example", specs.stacks)

    def test_fragment_entries_appear_in_merged_specs(self) -> None:
        spec_root = self._mirror_spec_root()
        self._write_fragment(spec_root, "example.yaml", _FRAGMENT_STACK)

        specs = load_oracle_specs(spec_root)

        self.assertIn("ipv4_fragment_example", specs.stacks)
        fragment_stack = specs.stacks["ipv4_fragment_example"]
        self.assertIsInstance(fragment_stack, StackSpec)
        self.assertEqual(fragment_stack.root, "l3:ipv4")
        self.assertEqual(fragment_stack.layers, ("ipv4", "payload"))
        # The monolithic stacks.yaml entries are still present alongside it.
        self.assertIn("ipv4_payload", specs.stacks)
        # The fragment file is recorded as a source path.
        self.assertTrue(
            any(path.endswith("stacks.d/example.yaml") for path in specs.source_paths),
            specs.source_paths,
        )

    def test_duplicate_stack_name_across_files_raises(self) -> None:
        spec_root = self._mirror_spec_root()
        self._write_fragment(spec_root, "duplicate.yaml", _FRAGMENT_DUPLICATE_STACK)

        with self.assertRaises(SpecValidationError) as ctx:
            load_oracle_specs(spec_root)
        self.assertIn("duplicate stack name ipv4_payload", str(ctx.exception))

    def test_duplicate_across_two_fragments_raises(self) -> None:
        # Sorted glob order makes the collision deterministic across fragments.
        spec_root = self._mirror_spec_root()
        self._write_fragment(spec_root, "a-example.yaml", _FRAGMENT_STACK)
        self._write_fragment(spec_root, "b-example.yaml", _FRAGMENT_STACK)

        with self.assertRaises(SpecValidationError) as ctx:
            load_oracle_specs(spec_root)
        self.assertIn("duplicate stack name ipv4_fragment_example", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
