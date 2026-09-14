"""Independent EHT-SIG non-OFDMA encoding blocks.

IEEE 802.11 TGbe 11-21/0140r2, 11-21/0298r3, 11-21/1148r1 and
11-23/0533r2. The generator constructs fields, user blocks and CRCs without
importing the production Rust parser.
"""
import argparse
from pathlib import Path

from eht_usig_vectors import mu_header, put
from he_signal_vectors import checksum


OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq/eht-sig-index.tsv"
MU_OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq/eht-mu-sig-index.tsv"
OFDMA_OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq/eht-ofdma-sig-index.tsv"

OFDMA_USERS = {
    **dict(enumerate([
        9, 8, 8, 7, 8, 7, 7, 6, 8, 7, 7, 6, 7, 6, 6, 5, 6, 5, 5, 4,
        6, 5, 5, 4, 4, 3,
    ])),
    **dict(enumerate([
        7, 6, 6, 5, 7, 6, 6, 5, 4, 4, 5, 4, 4, 3, 2, 5, 4, 4, 3, 2,
        3, 3, 5, 4,
    ], start=32)),
    **{code: code - 63 for code in range(64, 72)},
}


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


def protected(payload):
    bits = payload + [0] * 10
    value = checksum(payload)
    bits[len(payload):len(payload) + 4] = [
        (value >> shift) & 1 for shift in (3, 2, 1, 0)
    ]
    return bits


def mu_user(case, position):
    bits = [0] * 22
    sta_id = (case * 977 + position * 619 + 17) % 2046
    mcs = (case * 7 + position * 3) % 14
    ldpc = (case + position) % 2
    spatial = (case * 13 + position * 11) % 64
    put(bits, 0, 11, sta_id)
    put(bits, 11, 4, mcs)
    put(bits, 15, 1, ldpc)
    put(bits, 16, 6, spatial)
    return bits, (sta_id, mcs, ldpc, spatial)


def mu_blocks(case, users):
    common = [0] * 20
    spatial = case % 16
    ltf_mode = (case // 2) % 4
    ltf_code = (case // 4) % 5
    extra = (case // 8) % 2
    padding_code = (case // 16) % 4
    pe = (case // 32) % 2
    disregard = (case * 11 + 3) % 16
    put(common, 0, 4, spatial)
    put(common, 4, 2, ltf_mode)
    put(common, 6, 3, ltf_code)
    put(common, 9, 1, extra)
    put(common, 10, 2, padding_code)
    put(common, 12, 1, pe)
    put(common, 13, 4, disregard)
    put(common, 17, 3, users - 1)
    fields = [mu_user(case, position) for position in range(users)]
    bits = protected(common + fields[0][0])
    for start in range(1, users, 2):
        payload = fields[start][0]
        if start + 1 < users:
            payload += fields[start + 1][0]
        bits += protected(payload)
    ltf_size, guard = [(2, 800), (2, 1600), (4, 800), (4, 3200)][ltf_mode]
    ltf_symbols = [1, 2, 4, 6, 8][ltf_code]
    padding = 4 if padding_code == 0 else padding_code
    return bits, [
        spatial, ltf_mode, ltf_size, guard, ltf_symbols, extra, padding, pe,
        disregard, users,
    ], [field[1] for field in fields]


def ofdma_user(case, position):
    bits = [0] * 22
    sta_id = (case * 977 + position * 619 + 17) % 2048
    mcs = (case * 7 + position * 3) % 16
    reserved = (case + position) % 2
    nss = (case * 13 + position * 11) % 16 + 1
    beamformed = (case // 3 + position) % 2
    ldpc = (case // 5 + position) % 2
    put(bits, 0, 11, sta_id)
    put(bits, 11, 4, mcs)
    put(bits, 15, 1, reserved)
    put(bits, 16, 4, nss - 1)
    put(bits, 20, 1, beamformed)
    put(bits, 21, 1, ldpc)
    return bits, (sta_id, mcs, reserved, nss, beamformed, ldpc)


def ofdma_blocks(case, allocation):
    users = OFDMA_USERS[allocation]
    common = [0] * 26
    spatial = case % 16
    ltf_mode = (case // 2) % 4
    ltf_code = (case // 4) % 5
    extra = (case // 8) % 2
    padding_code = (case // 16) % 4
    pe = (case // 32) % 2
    disregard = (case * 11 + 3) % 16
    put(common, 0, 4, spatial)
    put(common, 4, 2, ltf_mode)
    put(common, 6, 3, ltf_code)
    put(common, 9, 1, extra)
    put(common, 10, 2, padding_code)
    put(common, 12, 1, pe)
    put(common, 13, 4, disregard)
    put(common, 17, 9, allocation)
    mu_mimo = allocation >= 65
    fields = [
        mu_user(case, position) if mu_mimo else ofdma_user(case, position)
        for position in range(users)
    ]
    bits = protected(common)
    for start in range(0, users, 2):
        payload = list(fields[start][0])
        if start + 1 < users:
            payload += fields[start + 1][0]
        bits += protected(payload)
    ltf_size, guard = [(2, 800), (2, 1600), (4, 800), (4, 3200)][ltf_mode]
    ltf_symbols = [1, 2, 4, 6, 8][ltf_code]
    padding = 4 if padding_code == 0 else padding_code
    return bits, [
        spatial, ltf_mode, ltf_size, guard, ltf_symbols, extra, padding, pe,
        disregard, allocation, users, "mu" if mu_mimo else "nonmu",
    ], [field[1] for field in fields]


def generate_single():
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


def generate_multi():
    rows = [
        "usig\tbits\tspatial\tltf_mode\tltf_size\tguard\tltf_symbols\textra\tpadding\tpe\tdisregard\tusers\tuser_fields"
    ]
    dbps = [26, 52, 104, 13]
    for users in range(2, 9):
        for case in range(256):
            seed = (users - 2) * 256 + case
            bits, common, fields = mu_blocks(seed, users)
            raw_mcs = seed % 4
            symbols = (len(bits) + dbps[raw_mcs] - 1) // dbps[raw_mcs]
            usig, _ = mu_header(seed, 0, 0, 2, raw_mcs, symbols)
            rows.append("\t".join([
                "".join(map(str, usig)),
                "".join(map(str, bits)),
                *map(str, common),
                ";".join(":".join(map(str, field)) for field in fields),
            ]))
    return "\n".join(rows) + "\n"


def generate_ofdma():
    rows = [
        "usig\tbits\tspatial\tltf_mode\tltf_size\tguard\tltf_symbols\textra\tpadding\tpe\tdisregard\tallocation\tusers\tkind\tuser_fields"
    ]
    dbps = [26, 52, 104, 13]
    for allocation in OFDMA_USERS:
        for case in range(16):
            seed = allocation * 16 + case
            bits, common, fields = ofdma_blocks(seed, allocation)
            raw_mcs = seed % 4
            symbols = (len(bits) + dbps[raw_mcs] - 1) // dbps[raw_mcs]
            usig, _ = mu_header(seed, 0, 0, 0, raw_mcs, symbols)
            rows.append("\t".join([
                "".join(map(str, usig)),
                "".join(map(str, bits)),
                *map(str, common),
                ";".join(":".join(map(str, field)) for field in fields),
            ]))
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    single = generate_single()
    multi = generate_multi()
    ofdma = generate_ofdma()
    if args.write:
        OUT.write_text(single)
        MU_OUT.write_text(multi)
        OFDMA_OUT.write_text(ofdma)
    else:
        assert OUT.read_text() == single, "EHT-SIG SU inventory differs"
        assert MU_OUT.read_text() == multi, "EHT-SIG MU inventory differs"
        assert OFDMA_OUT.read_text() == ofdma, "EHT-SIG OFDMA inventory differs"
    print(
        "2048 single-user, 1792 MU-MIMO and 928 OFDMA EHT-SIG "
        "block chains verified"
    )
