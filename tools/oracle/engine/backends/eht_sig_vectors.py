"""Independent EHT-SIG non-OFDMA single-user encoding blocks.

IEEE 802.11 TGbe 11-21/0140r2 and 11-21/1148r1. The generator
constructs fields and CRCs without importing the production Rust parser.
"""
import argparse
from pathlib import Path

from eht_usig_vectors import mu_header, put
from he_signal_vectors import checksum


OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq/eht-sig-index.tsv"


def repair(bits):
    value = checksum(bits[:42])
    bits[42:46] = [(value >> shift) & 1 for shift in (3, 2, 1, 0)]


def block(case):
    bits = [0] * 52
    spatial = case % 16
    ltf_mode = (case // 2) % 4
    ltf_code = (case // 4) % 5
    extra = (case // 8) % 2
    padding_code = (case // 16) % 4
    pe = (case // 32) % 2
    disregard = (case * 11 + 3) % 16
    sta_id = (case * 977 + 2046) % 2048
    mcs = (case * 7 + 3) % 16
    reserved = (case // 64) % 2
    nss = (case * 13) % 16 + 1
    beamformed = (case // 128) % 2
    ldpc = (case // 256) % 2
    put(bits, 0, 4, spatial)
    put(bits, 4, 2, ltf_mode)
    put(bits, 6, 3, ltf_code)
    put(bits, 9, 1, extra)
    put(bits, 10, 2, padding_code)
    put(bits, 12, 1, pe)
    put(bits, 13, 4, disregard)
    put(bits, 17, 3, 0)
    put(bits, 20, 11, sta_id)
    put(bits, 31, 4, mcs)
    put(bits, 35, 1, reserved)
    put(bits, 36, 4, nss - 1)
    put(bits, 40, 1, beamformed)
    put(bits, 41, 1, ldpc)
    repair(bits)
    ltf_size, guard = [(2, 800), (2, 1600), (4, 800), (4, 3200)][ltf_mode]
    ltf_symbols = [1, 2, 4, 6, 8][ltf_code]
    padding = 4 if padding_code == 0 else padding_code
    return bits, [
        spatial, ltf_mode, ltf_size, guard, ltf_symbols, extra, padding, pe,
        disregard, sta_id, mcs, reserved, nss, beamformed, ldpc,
    ]


def generate():
    published = [int(value) for value in "".join(
        "1111 11 010 1 10 0 1111 010 10000101101 0101 1 100000".split()
    )]
    assert len(published) == 42 and checksum(published) == int("1110", 2)
    rows = [
        "usig\tbits\tspatial\tltf_mode\tltf_size\tguard\tltf_symbols\textra\tpadding\tpe\tdisregard\tsta_id\tmcs\treserved\tnss\tbeamformed\tldpc"
    ]
    for case in range(2048):
        bits, expected = block(case)
        usig, _ = mu_header(case, 0, case & 1, 1, case % 4, case % 32 + 1)
        rows.append("\t".join([
            "".join(map(str, usig)), "".join(map(str, bits)), *map(str, expected)
        ]))
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    result = generate()
    if args.write:
        OUT.write_text(result)
    else:
        assert OUT.read_text() == result, "EHT-SIG inventory differs"
    print("2048 independent EHT-SIG encoding blocks verified")
