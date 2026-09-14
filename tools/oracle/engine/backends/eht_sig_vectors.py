"""Independent EHT-SIG non-OFDMA encoding blocks.

IEEE 802.11 TGbe 11-21/0140r2, 11-21/0298r3, 11-21/1148r1 and
11-23/0533r2. The generator constructs fields, user blocks and CRCs without
importing the production Rust parser.
"""
import argparse
from fractions import Fraction as F
import json
import math
from pathlib import Path

from eht_usig_vectors import mu_header, put
from eht_ofdma_ru_vectors import ALLOCATIONS
from he_signal_vectors import checksum
from ht_bcc_vectors import PUNCTURE
from ldpc_vectors import FIXTURE as LDPC_FIXTURE, encode as ldpc_encode
import ofdm_vectors as base


OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq/eht-sig-index.tsv"
MU_OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq/eht-mu-sig-index.tsv"
OFDMA_OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq/eht-ofdma-sig-index.tsv"
DATA_TIMING_OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq/eht-data-timing-index.tsv"
DATA_CAPACITY_OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq/eht-data-capacity-index.tsv"
DATA_BCC_OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq/eht-data-bcc-index.tsv"
DATA_LDPC_OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq/eht-data-ldpc-index.tsv"
DATA_LDPC_PAYLOAD_OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq/eht-data-ldpc-payload-index.tsv"

DATA_MODES = {
    0: (1, 1, 2, 0),
    1: (2, 1, 2, 0),
    2: (2, 3, 4, 0),
    3: (4, 1, 2, 0),
    4: (4, 3, 4, 0),
    5: (6, 2, 3, 0),
    6: (6, 3, 4, 0),
    7: (6, 5, 6, 0),
    8: (8, 3, 4, 0),
    9: (8, 5, 6, 0),
    10: (10, 3, 4, 0),
    11: (10, 5, 6, 0),
    12: (12, 3, 4, 0),
    13: (12, 5, 6, 0),
    15: (1, 1, 2, 1),
}
LDPC_CODES = {
    (entry["n"], tuple(entry["rate"])): entry
    for entry in json.loads(LDPC_FIXTURE.read_text())["codes"]
}

OFDMA_USERS = {
    code: sum(resource.users for resource in resources)
    for code, resources in ALLOCATIONS.items()
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


def generate_data_timing():
    rows = [
        "length\tsig_symbols\tltf_mode\tltf_size\tguard\tltf_symbols\tpe_disambiguity\tdata_symbols\tpe_samples\tdata_start\tdata_end\tpacket_end\tsignaled_end"
    ]
    lengths = [*range(3, 4096, 30), 4095]
    for sig_symbols in (1, 2, 7, 16, 32):
        for ltf_mode, (ltf_size, guard) in enumerate(
            ((2, 16), (2, 32), (4, 16), (4, 64))
        ):
            for ltf_symbols in (1, 2, 4, 6, 8):
                for pe_disambiguity in (0, 1):
                    training = ltf_symbols * (64 * ltf_size + guard)
                    fixed = 320 + 80 * sig_symbols + training
                    stride = 256 + guard
                    for length in lengths:
                        rounded = (length + 3) // 3 * 80
                        available = rounded - fixed
                        if available < 0:
                            continue
                        data_symbols = available // stride - pe_disambiguity
                        if data_symbols <= 0:
                            continue
                        data_start = 720 + 80 * sig_symbols + training
                        data_end = data_start + data_symbols * stride
                        pe_samples = (available - data_symbols * stride) // 80 * 80
                        if pe_samples > 320:
                            continue
                        rows.append("\t".join(map(str, [
                            length, sig_symbols, ltf_mode, ltf_size, guard,
                            ltf_symbols, pe_disambiguity, data_symbols,
                            pe_samples, data_start, data_end,
                            data_end + pe_samples, 400 + rounded,
                        ])))
    return "\n".join(rows) + "\n"


def generate_data_capacity():
    rows = [
        "mcs\tldpc\textra\tpadding\tsymbols\tbits_per_tone\trate_num\trate_den\tdcm\tcoded_per_symbol\tcoded_short\tdata_per_symbol\tcoded_last\tcoded_bits\tdata_bits\tpsdu_bytes\tphy_pad_bits\ttail_bits\tbcc_dcm_filler"
    ]
    for mcs, (bits, rate_num, rate_den, dcm) in DATA_MODES.items():
        for ldpc in (0, 1):
            if not ldpc and mcs not in (*range(10), 15):
                continue
            for extra in (0, 1):
                for padding in (1, 2, 3, 4):
                    for symbols in (1, 2, 3, 4, 7, 16, 31, 64, 127, 256, 400):
                        data_tones = 117 if dcm else 234
                        short_tones = 30 if dcm else 60
                        cbps = data_tones * bits
                        short_cbps = short_tones * bits
                        dbps = cbps * rate_num // rate_den
                        short_dbps = short_cbps * rate_num // rate_den
                        effective_extra = bool(ldpc and extra)
                        if effective_extra and padding == 1:
                            payload_symbols, payload_padding = symbols - 1, 4
                        elif effective_extra:
                            payload_symbols, payload_padding = symbols, padding - 1
                        else:
                            payload_symbols, payload_padding = symbols, padding
                        if payload_symbols < 1:
                            continue
                        data_last = dbps if payload_padding == 4 else payload_padding * short_dbps
                        data_bits = (payload_symbols - 1) * dbps + data_last
                        tail = 0 if ldpc else 6
                        payload = data_bits - 16 - tail
                        if payload < 0:
                            continue
                        coded_last = cbps if padding == 4 else padding * short_cbps
                        coded_bits = (symbols - 1) * cbps + coded_last
                        rows.append("\t".join(map(str, [
                            mcs, ldpc, extra, padding, symbols, bits, rate_num,
                            rate_den, dcm, cbps, short_cbps, dbps, coded_last,
                            coded_bits, data_bits, payload // 8, payload % 8,
                            tail, int(not ldpc and mcs == 15),
                        ])))
    return "\n".join(rows) + "\n"


def eht_scramble(bits, seed):
    assert 0 < seed < 2048
    state = seed
    output = []
    for bit in bits:
        generated = state >> 10
        feedback = ((state >> 10) ^ (state >> 8)) & 1
        state = ((state << 1) | feedback) & 0x7ff
        output.append(bit ^ generated)
    return output


DATA_BCC_MODES = {
    mcs: values[:3]
    for mcs, values in DATA_MODES.items()
    if mcs in (*range(10), 15)
}


def data_bcc_case(mcs, padding, symbols, psdu=None):
    bits_per_tone, rate_num, rate_den = DATA_BCC_MODES[mcs]
    dcm = mcs == 15
    data_tones = 117 if dcm else 234
    short_tones = 30 if dcm else 60
    coded_per_symbol = data_tones * bits_per_tone
    coded_short = short_tones * bits_per_tone
    data_per_symbol = coded_per_symbol * rate_num // rate_den
    data_short = coded_short * rate_num // rate_den
    puncturing = (
        PUNCTURE[mcs]
        if mcs < 8
        else ([1, 1, 1, 0, 0, 1] if mcs == 8 else
              [1, 1, 1, 0, 0, 1, 1, 0, 0, 1])
    )
    if mcs == 15:
        puncturing = [1, 1]
    coded_last = coded_per_symbol if padding == 4 else padding * coded_short
    data_last = data_per_symbol if padding == 4 else padding * data_short
    coded_bits = (symbols - 1) * coded_per_symbol + coded_last
    data_bits = (symbols - 1) * data_per_symbol + data_last
    payload_bits = data_bits - 22
    psdu_bytes, phy_pad_bits = divmod(payload_bits, 8)
    seed = 1 + (mcs * 131 + padding * 257 + symbols * 509) % 2047
    if psdu is None:
        psdu = bytes(
            (index * 37 + seed + mcs * 13) % 256
            for index in range(psdu_bytes)
        )
    else:
        psdu = bytes(psdu)
        assert len(psdu) == psdu_bytes
    information = [0] * 16 + base.bits(psdu) + [
        (seed + index) & 1 for index in range(phy_pad_bits)
    ]
    scrambled = eht_scramble(information, seed) + [0] * 6
    encoded = base.encode(scrambled)
    fec = [
        bit for index, bit in enumerate(encoded)
        if puncturing[index % len(puncturing)]
    ]
    output = []
    cursor = 0
    for symbol in range(symbols):
        keep = coded_last if symbol == symbols - 1 else coded_per_symbol
        filler = int(dcm and keep == coded_per_symbol)
        amount = keep - filler
        output.extend(fec[cursor:cursor + amount])
        cursor += amount
        if filler:
            output.append((seed + symbol) & 1)
        output.extend(
            (seed + symbol + index) & 1
            for index in range(coded_per_symbol - keep)
        )
    assert cursor == len(fec)
    assert len(output) == symbols * coded_per_symbol
    return (
        [
            mcs, padding, symbols, seed, bits_per_tone, rate_num, rate_den,
            coded_per_symbol, coded_short, data_per_symbol, coded_last,
            coded_bits, data_bits, psdu_bytes, phy_pad_bits, 6,
        ],
        psdu,
        output,
    )


def generate_data_bcc():
    rows = [
        "mcs\tpadding\tsymbols\tseed\tbits_per_tone\trate_num\trate_den\tcoded_per_symbol\tcoded_short\tdata_per_symbol\tcoded_last\tcoded_bits\tdata_bits\tpsdu_bytes\tphy_pad_bits\ttail_bits\tpsdu\tcoded"
    ]
    for mcs in DATA_BCC_MODES:
        for padding in range(1, 5):
            for symbols in (3, 5):
                values, psdu, coded = data_bcc_case(mcs, padding, symbols)
                rows.append("\t".join(map(str, [
                    *values, psdu.hex(), "".join(map(str, coded)),
                ])))
    return "\n".join(rows) + "\n"


def data_ldpc_layout(mcs, initial_symbols, initial_padding):
    bits, rate_num, rate_den, dcm = DATA_MODES[mcs]
    rate = F(rate_num, rate_den)
    coded = (117 if dcm else 234) * bits
    coded_short = (30 if dcm else 60) * bits
    data = int(coded * rate)
    data_short = int(coded_short * rate)
    payload = (initial_symbols - 1) * data
    payload += data if initial_padding == 4 else initial_padding * data_short
    available = (initial_symbols - 1) * coded
    available += coded if initial_padding == 4 else initial_padding * coded_short
    if available <= 648:
        count, size = 1, 1296 if available >= payload + 912 * (1 - rate) else 648
    elif available <= 1296:
        count, size = 1, 1944 if available >= payload + 1464 * (1 - rate) else 1296
    elif available <= 1944:
        count, size = 1, 1944
    elif available <= 2592:
        count, size = 2, 1944 if available >= payload + 2916 * (1 - rate) else 1296
    else:
        count, size = math.ceil(F(payload, 1944) / rate), 1944
    shortened = max(0, int(count * size * rate) - payload)
    punctured = max(0, count * size - available - shortened)
    parity = count * size * (1 - rate)
    extra = (
        punctured > parity / 10
        and shortened < F(6, 5) * punctured * rate / (1 - rate)
    ) or punctured > 3 * parity / 10
    symbols = initial_symbols
    padding = initial_padding
    if extra:
        available += coded - 3 * coded_short if padding == 3 else coded_short
        if padding == 4:
            symbols += 1
            padding = 1
        else:
            padding += 1
    punctured = max(0, count * size - available - shortened)
    repeated = max(0, int(available - parity - payload))
    assert count * size - shortened - punctured + repeated == available
    assert not (punctured and repeated)
    return [
        symbols,
        padding,
        int(extra),
        count,
        size,
        shortened,
        punctured,
        repeated,
        payload,
        available,
    ]


def data_ldpc_encode(bits, sizing, mcs):
    _, _, _, count, size, shortened, punctured, repeated, payload, available = sizing
    assert len(bits) == payload
    _, rate_num, rate_den, _ = DATA_MODES[mcs]
    matrix = LDPC_CODES[size, (rate_num, rate_den)]
    expansion = matrix["z"]
    information = matrix["k"]
    checks = [
        sum(
            1 << (column * expansion + (offset + shift) % expansion)
            for column, shift in enumerate(block)
            if shift >= 0
        )
        for block in matrix["matrix"]
        for offset in range(expansion)
    ]
    cursor = 0
    transmitted = []
    for index in range(count):
        short = shortened // count + int(index < shortened % count)
        puncture = punctured // count + int(index < punctured % count)
        repeat = repeated // count + int(index < repeated % count)
        word_bits = bits[cursor:cursor + information - short]
        cursor += information - short
        word = list(map(int, ldpc_encode(
            checks,
            information,
            size,
            sum(bit << position for position, bit in enumerate(word_bits)),
        )))
        word = word[:information - short] + word[information:size - puncture]
        transmitted += word
        transmitted += [word[position % len(word)] for position in range(repeat)]
    assert cursor == payload and len(transmitted) == available
    return transmitted


def data_ldpc_case(mcs, initial_symbols, initial_padding, psdu=None):
    sizing = data_ldpc_layout(mcs, initial_symbols, initial_padding)
    symbols, padding = sizing[:2]
    bits_per_tone, rate_num, rate_den, dcm = DATA_MODES[mcs]
    coded_per_symbol = (117 if dcm else 234) * bits_per_tone
    coded_short = (30 if dcm else 60) * bits_per_tone
    data_per_symbol = coded_per_symbol * rate_num // rate_den
    coded_last = coded_per_symbol if padding == 4 else padding * coded_short
    payload_bits = sizing[8] - 16
    psdu_bytes, phy_pad_bits = divmod(payload_bits, 8)
    seed = 1 + (
        mcs * 131 + initial_padding * 257 + initial_symbols * 509
    ) % 2047
    if psdu is None:
        psdu = bytes(
            (index * 37 + seed + mcs * 13) % 256
            for index in range(psdu_bytes)
        )
    else:
        psdu = bytes(psdu)
        assert len(psdu) == psdu_bytes
    information = [0] * 16 + base.bits(psdu) + [
        (seed + index) & 1 for index in range(phy_pad_bits)
    ]
    fec = data_ldpc_encode(eht_scramble(information, seed), sizing, mcs)
    output = []
    cursor = 0
    for symbol in range(symbols):
        keep = coded_last if symbol + 1 == symbols else coded_per_symbol
        output += fec[cursor:cursor + keep]
        cursor += keep
        output += [
            (seed + symbol + index) & 1
            for index in range(coded_per_symbol - keep)
        ]
    assert cursor == len(fec)
    assert len(output) == symbols * coded_per_symbol
    values = [
        mcs,
        initial_symbols,
        initial_padding,
        symbols,
        padding,
        sizing[2],
        seed,
        bits_per_tone,
        rate_num,
        rate_den,
        dcm,
        coded_per_symbol,
        coded_short,
        data_per_symbol,
        coded_last,
        sizing[9],
        sizing[8],
        psdu_bytes,
        phy_pad_bits,
        sizing[3],
        sizing[4],
        sizing[5],
        sizing[6],
        sizing[7],
    ]
    return values, psdu, output


def generate_data_ldpc():
    rows = [
        "mcs\tinitial_symbols\tinitial_padding\tsymbols\tpadding\textra\twords\tblock\tshort\tpuncture\trepeat\tpayload\tavailable"
    ]
    initial_counts = sorted(
        set(range(1, 65)) | {127, 128, 129, 199, 200, 399, 400}
    )
    for mcs in DATA_MODES:
        for initial_symbols in initial_counts:
            for initial_padding in range(1, 5):
                result = data_ldpc_layout(mcs, initial_symbols, initial_padding)
                if result[8] < 16 or result[0] > 400:
                    continue
                rows.append("\t".join(map(str, [
                    mcs, initial_symbols, initial_padding, *result,
                ])))
    return "\n".join(rows) + "\n"


def generate_data_ldpc_payloads():
    rows = [
        "mcs\tinitial_symbols\tinitial_padding\tsymbols\tpadding\textra\tseed\tbits_per_tone\trate_num\trate_den\tdcm\tcoded_per_symbol\tcoded_short\tdata_per_symbol\tcoded_last\tcoded_bits\tdata_bits\tpsdu_bytes\tphy_pad_bits\twords\tblock\tshort\tpuncture\trepeat\tpsdu\tcoded"
    ]
    for mcs in DATA_MODES:
        for initial_symbols in (2, 5):
            for initial_padding in range(1, 5):
                values, psdu, coded = data_ldpc_case(
                    mcs, initial_symbols, initial_padding
                )
                rows.append("\t".join(map(str, [
                    *values, psdu.hex(), "".join(map(str, coded)),
                ])))
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    single = generate_single()
    multi = generate_multi()
    ofdma = generate_ofdma()
    data_timing = generate_data_timing()
    data_capacity = generate_data_capacity()
    data_bcc = generate_data_bcc()
    data_ldpc = generate_data_ldpc()
    data_ldpc_payloads = generate_data_ldpc_payloads()
    if args.write:
        OUT.write_text(single)
        MU_OUT.write_text(multi)
        OFDMA_OUT.write_text(ofdma)
        DATA_TIMING_OUT.write_text(data_timing)
        DATA_CAPACITY_OUT.write_text(data_capacity)
        DATA_BCC_OUT.write_text(data_bcc)
        DATA_LDPC_OUT.write_text(data_ldpc)
        DATA_LDPC_PAYLOAD_OUT.write_text(data_ldpc_payloads)
    else:
        assert OUT.read_text() == single, "EHT-SIG SU inventory differs"
        assert MU_OUT.read_text() == multi, "EHT-SIG MU inventory differs"
        assert OFDMA_OUT.read_text() == ofdma, "EHT-SIG OFDMA inventory differs"
        assert DATA_TIMING_OUT.read_text() == data_timing, "EHT DATA timing inventory differs"
        assert DATA_CAPACITY_OUT.read_text() == data_capacity, "EHT DATA capacity inventory differs"
        assert DATA_BCC_OUT.read_text() == data_bcc, "EHT DATA BCC inventory differs"
        assert DATA_LDPC_OUT.read_text() == data_ldpc, "EHT DATA LDPC inventory differs"
        assert DATA_LDPC_PAYLOAD_OUT.read_text() == data_ldpc_payloads, "EHT DATA LDPC payload inventory differs"
    print(
        f"2048 single-user, 1792 MU-MIMO and {len(OFDMA_USERS) * 16} OFDMA EHT-SIG "
        f"block chains, {len(data_timing.splitlines()) - 1} DATA timelines and "
        f"{len(data_capacity.splitlines()) - 1} DATA capacities, and "
        f"{len(data_bcc.splitlines()) - 1} DATA BCC payloads, and "
        f"{len(data_ldpc.splitlines()) - 1} DATA LDPC layouts and "
        f"{len(data_ldpc_payloads.splitlines()) - 1} payloads verified"
    )
