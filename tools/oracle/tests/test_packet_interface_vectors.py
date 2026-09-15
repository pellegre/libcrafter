"""Independent interface corpus generation and evidence controls."""
import json
import importlib.util
from pathlib import Path
import unittest

from tools.oracle.engine.backends.packet_interface_vectors import materialize, normalize


class PacketInterfaceVectors(unittest.TestCase):
    def test_interface_contract_cases_are_not_packet_generation_cases(self):
        from tools.oracle.engine.generator import PacketGenerator, load_stack_grammar

        grammar = load_stack_grammar()
        feature = grammar["features"]["packet_interface"]
        declared = {case["name"] for case in feature["supported_cases"] if case.get("contract_only")}
        self.assertEqual(declared, set(feature["coverage_cases"]))
        generator = PacketGenerator(seed=1, profile="smoke", grammar=grammar)
        for case in declared:
            for direction in feature["directions"]:
                self.assertFalse(generator._case_supported_in_direction(case, direction))

    @unittest.skipUnless(importlib.util.find_spec("scapy"), "scapy backend unavailable")
    def test_checked_corpus_matches_scapy(self):
        path = Path(__file__).resolve().parents[3] / "crafter/tests/fixtures/dot11/packet-interface-references.json"
        self.assertEqual(json.loads(path.read_text()), materialize())

    def test_integrity_states_stay_distinct(self):
        path = Path(__file__).resolve().parents[3] / "crafter/tests/fixtures/dot11/packet-interface-references.json"
        corpus = json.loads(path.read_text())
        rows = {row["name"]: row for row in corpus["cases"]}
        for row in rows.values():
            self.assertEqual(normalize(bytes.fromhex(row["capture_hex"]), row["link_type"], row["original_len"]), row["expected"])
        self.assertEqual(rows["bare-unknown"]["expected"]["fcs"]["state"], "unknown")
        self.assertEqual(rows["radiotap-absent"]["expected"]["fcs"]["state"], "absent")
        self.assertIs(rows["radiotap-valid"]["expected"]["fcs"]["valid"], True)
        self.assertIs(rows["radiotap-invalid"]["expected"]["fcs"]["valid"], False)
        self.assertEqual(rows["qos-padding-valid"]["expected"]["padding_hex"], "a55a")
        for count in range(1, 5):
            fcs = rows[f"radiotap-truncated-{count}"]["expected"]["fcs"]
            self.assertEqual(fcs["state"], "truncated")
            self.assertIsNone(fcs["valid"])
            self.assertEqual(len(bytes.fromhex(fcs["bytes_hex"])), 4 - count)

    def test_missing_or_unknown_reference_framing_is_rejected(self):
        for capture, link in [(b"", 127), (bytes.fromhex("0000ffff00000000"), 127),
                              (bytes.fromhex("0000080004000000"), 127), (bytes(24), 1)]:
            with self.subTest(capture=capture, link=link), self.assertRaises(ValueError):
                normalize(capture, link, len(capture))


if __name__ == "__main__":
    unittest.main()
