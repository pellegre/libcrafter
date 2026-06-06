"""Parser-only Wireshark/tshark coverage for Dot11 decoded models."""

from __future__ import annotations

import shutil
import unittest

from tools.oracle.engine.backends.wireshark import normalize as wireshark


_RADIOTAP_DOT11_EAPOL_HEX = (
    "00000a00060000001002"
    "0800000000005e00530100005e00530200005e0053030010"
    "aaaa03000000888e0201000401020304"
)


def _synthetic_dot11_packet() -> dict:
    return {
        "_source": {
            "layers": {
                "frame": {"frame.protocols": "radiotap:wlan_radio:wlan:llc:eapol"},
                "radiotap": {
                    "radiotap.version": "0",
                    "radiotap.pad": "0",
                    "radiotap.length": "10",
                    "radiotap.present.word": "0x00000006",
                    "radiotap.flags": "0x10",
                    "radiotap.datarate": "1.0 Mb/s",
                },
                "wlan": {
                    "wlan.fc": "0x0008",
                    "wlan.fc.version": "0",
                    "wlan.fc.type": "2",
                    "wlan.fc.subtype": "0",
                    "wlan.fc.tods": "0",
                    "wlan.fc.fromds": "0",
                    "wlan.fc.protected": "0",
                    "wlan.duration": "0",
                    "wlan.addr": [
                        "00:00:5e:00:53:01",
                        "00:00:5e:00:53:02",
                        "00:00:5e:00:53:03",
                    ],
                    "wlan.seq": "256",
                    "wlan.frag": "0",
                },
                "llc": {
                    "llc.dsap": "0xaa",
                    "llc.ssap": "0xaa",
                    "llc.control": "0x03",
                    "llc.oui": "00:00:00",
                    "llc.type": "0x888e",
                },
                "eapol": {
                    "eapol.version": "2",
                    "eapol.type": "1",
                    "eapol.len": "4",
                },
            }
        }
    }


def _synthetic_rsn_packet() -> dict:
    return {
        "_source": {
            "layers": {
                "frame": {"frame.protocols": "radiotap:wlan_radio:wlan:wlan_mgt:wlan_mgt.rsn"},
                "radiotap": {
                    "radiotap.version": "0",
                    "radiotap.pad": "0",
                    "radiotap.length": "8",
                    "radiotap.present.word": "0x00000000",
                },
                "wlan": {
                    "wlan.fc": "0x0080",
                    "wlan.fc.version": "0",
                    "wlan.fc.type": "0",
                    "wlan.fc.subtype": "8",
                    "wlan.duration": "0",
                    "wlan.addr": [
                        "ff:ff:ff:ff:ff:ff",
                        "00:00:5e:00:53:02",
                        "00:00:5e:00:53:03",
                    ],
                    "wlan.seq": "0",
                    "wlan.frag": "0",
                },
                "wlan_mgt.rsn": {
                    "wlan.rsn.tag": "48",
                    "wlan.rsn.length": "20",
                    "wlan.rsn.version": "1",
                    "wlan.rsn.gcs.oui": "00:0f:ac",
                    "wlan.rsn.gcs.type": "4",
                    "wlan.rsn.pcs.type": "4",
                    "wlan.rsn.akms.type": "2",
                    "wlan.rsn.capabilities": "0x0000",
                },
            }
        }
    }


class WiresharkDot11NormalizationTest(unittest.TestCase):
    """Pure-Python tshark JSON normalizer coverage."""

    def test_normalizes_synthetic_dot11_eapol_layers(self) -> None:
        model = wireshark.normalize_packet_json(
            _synthetic_dot11_packet(),
            root="link:radiotap",
            source_hex=None,
            feature_tags=["dot11"],
        )

        self.assertEqual(model.root, "link:radiotap")
        self.assertEqual(model.layers, ["radiotap", "dot11", "llc_snap", "eapol"])
        self.assertEqual(model.fields["radiotap"]["fcs_status"], "present")
        self.assertEqual(model.fields["radiotap"]["rate"], 2)
        self.assertEqual(model.fields["dot11"]["sequence_number"], 256)
        self.assertEqual(model.fields["dot11"]["sequence_control"], 0x1000)
        self.assertEqual(model.fields["llc_snap"]["ethertype"], 0x888E)
        self.assertEqual(model.fields["eapol"]["body_length"], 4)

    def test_normalizes_synthetic_rsn_layer(self) -> None:
        model = wireshark.normalize_packet_json(
            _synthetic_rsn_packet(),
            root="link:radiotap",
            source_hex=None,
            feature_tags=["rsn"],
        )

        self.assertEqual(model.layers, ["radiotap", "dot11", "rsn"])
        self.assertEqual(model.fields["rsn"]["version"], 1)
        self.assertEqual(model.fields["rsn"]["group_cipher_suite"]["label"], "ccmp-128")
        self.assertEqual(model.fields["rsn"]["pairwise_cipher_suites"][0]["label"], "ccmp-128")
        self.assertEqual(model.fields["rsn"]["akm_suites"][0]["label"], "psk")

    def test_dot11_source_bytes_use_strict_byte_model_after_parser_json(self) -> None:
        model = wireshark.normalize_packet_json(
            _synthetic_dot11_packet(),
            root="link:radiotap",
            source_hex=_RADIOTAP_DOT11_EAPOL_HEX,
            feature_tags=["dot11"],
        )

        self.assertEqual(model.backend, "wireshark")
        self.assertEqual(model.layers, ["radiotap", "dot11", "llc_snap", "eapol", "payload"])
        self.assertEqual(model.fields["payload"]["hex"], "01020304")
        self.assertEqual(model.metadata["normalization"], "byte_level_dot11_after_tshark_parse")


@unittest.skipUnless(
    shutil.which("tshark"),
    "tshark not installed; skipping parser-only Dot11 decode",
)
class WiresharkDot11RawDecodeTest(unittest.TestCase):
    """End-to-end parser-only Dot11 decode via tshark when available."""

    def test_decode_bytes_radiotap_dot11_eapol(self) -> None:
        raw = bytes.fromhex(_RADIOTAP_DOT11_EAPOL_HEX)
        model = wireshark.decode_bytes(raw, root="link:radiotap")

        self.assertEqual(model.layers, ["radiotap", "dot11", "llc_snap", "eapol", "payload"])
        self.assertEqual(model.fields["llc_snap"]["ethertype"], 0x888E)


if __name__ == "__main__":
    unittest.main()
