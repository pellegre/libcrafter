"""Independent EHT20 OFDMA channel-training IQ vectors."""

import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile

import ofdm_vectors as base
from eht_ofdma_ru_vectors import ALLOCATIONS
from eht_sig_iq_vectors import (
    MODES,
    append_training,
    prefix,
    repair_block,
    signaling,
    split_ofdma_blocks,
)
from eht_sig_vectors import OFDMA_USERS, ofdma_blocks
from eht_usig_vectors import mu_header, put


OUT = Path(__file__).resolve().parents[6] / "crafter/tests/fixtures/iq"


def waveform(case, allocation, raw_mcs, ltf_mode, ltf_code, impaired):
    bits, _, _ = ofdma_blocks(case, allocation)
    blocks = split_ofdma_blocks(bits, OFDMA_USERS[allocation])
    put(blocks[0], 4, 2, ltf_mode)
    put(blocks[0], 6, 3, ltf_code)
    repair_block(blocks[0])
    if allocation < 65:
        for block in blocks[1:]:
            for start in range(0, len(block) - 10, 22):
                put(block, start + 16, 4, 0)
            repair_block(block)
    bits = [bit for block in blocks for bit in block]
    signal_symbols = math.ceil(len(bits) / MODES[raw_mcs][2])
    usig, _ = mu_header(case, 0, 0, 0, raw_mcs, signal_symbols)
    samples = prefix(usig) + signaling(blocks, raw_mcs, signal_symbols)
    ltf_size, guard, ltf_symbols, ltf_start, data_start = append_training(
        samples, ltf_mode, ltf_code
    )
    if impaired:
        samples = [
            (value + (0.20j * samples[index - 3] if index >= 3 else 0))
            * cmath.exp(1j * (0.40 + 0.009 * index))
            for index, value in enumerate(samples)
        ]
    peak = max(max(abs(value.real), abs(value.imag)) for value in samples)
    gain = min(180, 120 / peak)
    assert all(max(abs(value.real), abs(value.imag)) * gain < 127 for value in samples)
    return (
        base.quantize(samples, scale=gain),
        "".join(map(str, usig)),
        "".join(map(str, bits)),
        signal_symbols,
        ltf_size,
        guard,
        ltf_symbols,
        ltf_start,
        data_start,
    )


def generate(out):
    corpus = bytearray()
    rows = [
        "name\tusig\tbits\tallocation\tresources\tusers\tsupported\t"
        "mcs\tsignal_symbols\tltf_mode\tltf_size\tguard\tltf_symbols\t"
        "ltf_start\tdata_start\timpaired\toffset\tbytes\tsha256"
    ]
    for position, (allocation, resources) in enumerate(ALLOCATIONS.items()):
        raw_mcs = position % 4
        ltf_mode = (position // 4) % 4
        ltf_code = position % 5
        supported = int(all(resource.users == 1 for resource in resources))
        for impaired in (False, True):
            suffix = "offset" if impaired else "clean"
            name = f"eht-ofdma-training-a{allocation}-{suffix}"
            case = 262144 + 2 * position + int(impaired)
            fields = waveform(
                case, allocation, raw_mcs, ltf_mode, ltf_code, impaired
            )
            (
                iq,
                usig,
                bits,
                signal_symbols,
                ltf_size,
                guard,
                ltf_symbols,
                ltf_start,
                data_start,
            ) = fields
            offset = len(corpus)
            corpus.extend(iq)
            rows.append("\t".join(map(str, [
                name,
                usig,
                bits,
                allocation,
                len(resources),
                OFDMA_USERS[allocation],
                supported,
                raw_mcs,
                signal_symbols,
                ltf_mode,
                ltf_size,
                guard,
                ltf_symbols,
                ltf_start,
                data_start,
                int(impaired),
                offset,
                len(iq),
                hashlib.sha256(iq).hexdigest(),
            ])))
    (out / "eht-ofdma-training-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-ofdma-training-iq.cs8").write_bytes(corpus)
    print(f"{len(rows) - 1} independent EHT20 OFDMA training waveforms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix="eht-ofdma-training-") as temporary:
            generated = Path(temporary)
            generate(generated)
            for path in generated.iterdir():
                assert path.read_bytes() == (OUT / path.name).read_bytes(), path.name
    else:
        generate(OUT)
