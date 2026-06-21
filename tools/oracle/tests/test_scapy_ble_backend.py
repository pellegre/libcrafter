"""Unit coverage for Scapy backend BLE advertising support."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.oracle.engine.backends.scapy import normalize, packets, pcap
from tools.oracle.engine.model import PacketPlan


BLE_ROOT = "link:bluetooth-le-ll-with-phdr"
BLE_ADV_IND_FLAGS_NAME_HEX = (
    "25d6a600d6be898e170c"
    "d6be898e0015a6a5a4a3a2a10201060b096c696263726166746572654afa"
)


def _ble_adv_plan() -> PacketPlan:
    return PacketPlan(
        stack=["ble_radio", "ble_adv"],
        fields={
            "ble_radio": {
                "rf_channel": 37,
                "signal_power": -42,
                "noise_power": -90,
                "access_address": 0x8E89BED6,
                "ref_access_address": 0x8E89BED6,
            },
            "ble_adv": {
                "pdu_type": "adv_ind",
                "adv_a": "a1:a2:a3:a4:a5:a6",
                "ad_list": [
                    {"type": "flags", "value": 0x06},
                    {"type": "complete_local_name", "value": "libcrafter"},
                ],
            },
        },
        profile="ble-smoke",
        seed=1,
        index=0,
        direction="reference_to_libcrafter",
        family="ble",
        feature_tags=["ble", "ble_advertising"],
        case="ble-adv-ind-flags-name",
        strict_bytes=True,
        metadata={"root": BLE_ROOT, "root_decoder": BLE_ROOT, "stack_name": "ble_adv_unit"},
    )


def _scapy_available() -> bool:
    try:
        import scapy  # type: ignore[import-untyped]  # noqa: F401
        import scapy.all  # type: ignore[import-untyped]  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


class ScapyBleMaterializationTest(unittest.TestCase):
    def test_adv_ind_flags_and_name_materializes_deterministically(self) -> None:
        vector = packets.encode_packet_plan(_ble_adv_plan())

        self.assertEqual(vector.root, BLE_ROOT)
        self.assertEqual(vector.decoder, "BTLE_PHDR")
        self.assertEqual(vector.raw_hex, BLE_ADV_IND_FLAGS_NAME_HEX)
        self.assertEqual(vector.metadata["scapy_stack"], ["BTLE_PHDR", "BTLE_ADV_IND"])
        self.assertIn(
            vector.metadata["ble_materialization"]["materialization"],
            {"deterministic_wire_bytes", "scapy_btle_layers"},
        )

    def test_adv_ind_flags_and_name_normalizes_back_to_ble_model(self) -> None:
        vector = packets.encode_packet_plan(_ble_adv_plan())

        decoded = normalize.decode_bytes(vector.to_bytes(), root=vector.root, source_hex=vector.raw_hex)

        self.assertEqual(decoded.root, BLE_ROOT)
        self.assertEqual(decoded.layers, ["ble_radio", "ble_adv"])
        self.assertEqual(decoded.fields["ble_radio"]["rf_channel"], 37)
        self.assertEqual(decoded.fields["ble_radio"]["signal_power"], -42)
        self.assertEqual(decoded.fields["ble_radio"]["noise_power"], -90)
        self.assertEqual(decoded.fields["ble_radio"]["ref_access_address"], 0x8E89BED6)
        self.assertTrue(decoded.fields["ble_radio"]["crc_valid"])
        self.assertEqual(decoded.fields["ble_adv"]["pdu_type"], "adv_ind")
        self.assertEqual(decoded.fields["ble_adv"]["adv_a"], "a1:a2:a3:a4:a5:a6")
        self.assertEqual(
            decoded.fields["ble_adv"]["ad_list"],
            [
                {
                    "type": "flags",
                    "type_code": 1,
                    "length": 2,
                    "data_hex": "06",
                    "value": 6,
                    "flag_tokens": [
                        "le_general_discoverable_mode",
                        "br_edr_not_supported",
                    ],
                },
                {
                    "type": "complete_local_name",
                    "type_code": 9,
                    "length": 11,
                    "data_hex": "6c696263726166746572",
                    "value": "libcrafter",
                },
            ],
        )

    def test_ble_pcap_link_type_uses_dlt_256_root(self) -> None:
        vector = pcap.with_pcap_metadata(
            [packets.encode_packet_plan(_ble_adv_plan())],
            link_type="bluetooth_le_ll_with_phdr",
        )[0]

        self.assertEqual(pcap.pcap_link_type_for_vectors([vector]), "bluetooth_le_ll_with_phdr")
        self.assertEqual(vector.metadata["pcap_record"]["link_type"]["name"], "bluetooth_le_ll_with_phdr")
        self.assertEqual(vector.metadata["pcap_record"]["link_type"]["datalink"], 256)

    @unittest.skipUnless(_scapy_available(), "scapy is not available")
    def test_ble_pcap_roundtrip_preserves_dlt_256_bytes_and_layers(self) -> None:
        vector = pcap.with_pcap_metadata(
            [packets.encode_packet_plan(_ble_adv_plan())],
            link_type="bluetooth_le_ll_with_phdr",
        )[0]

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ble.pcap"
            pcap.write_pcap(path, [vector])
            records = pcap.read_pcap(path)

        self.assertEqual(records[0]["link_type"]["name"], "bluetooth_le_ll_with_phdr")
        self.assertEqual(records[0]["link_type"]["datalink"], 256)
        self.assertEqual(records[0]["layers"], ["ble_radio", "ble_adv"])
        self.assertEqual(records[0]["raw_hex"], vector.raw_hex)
        self.assertEqual(records[0]["timestamp"], vector.metadata["pcap_record"]["timestamp"])


if __name__ == "__main__":
    unittest.main()
