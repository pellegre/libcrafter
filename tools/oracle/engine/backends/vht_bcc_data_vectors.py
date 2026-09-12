"""Independent VHT DATA BCC fixtures, IEEE 802.11-2020 21.3.10 and 21.4.3.

These are coded-bit/PSDU primitives, not complete MAC aggregates or IQ frames.
Independent encoder and polynomial CRC only; no production decoder imports.
"""
import argparse
from pathlib import Path
import ofdm_vectors as base
from ht_signal_vectors import crc
from ht_bcc_vectors import PARAMETERS, PUNCTURE

OUT = Path(__file__).resolve().parents[4] / 'crafter/tests/fixtures/iq/vht-bcc-data-index.tsv'


def generate():
    base.self_check()
    rows = ['mcs\tsymbols\tseed\tsigb\tpsdu_hex\tcoded\tvalid']
    parameters = PARAMETERS + [(8, 312)]
    punctures = PUNCTURE + [[1, 1, 1, 0, 0, 1]]

    def emit(mcs, symbols, seed, corruption=None):
        nbpsc, ndbps = parameters[mcs]
        # Fill whole PSDU octets before adding PHY pad bits and the final tail.
        octets, pad = divmod(symbols * ndbps - 22, 8)
        psdu = bytes((n * 37 + seed + mcs * 13) % 256 for n in range(octets))
        units = (len(psdu) + 3) // 4
        sigb = [(units >> n) & 1 for n in range(17)] + [1] * 3
        service = [0] * 8 + crc(sigb)
        if corruption == 'prefix':
            service[7] = 1
        if corruption == 'crc':
            service[8] ^= 1
        data = service + base.bits(psdu) + [n % 2 for n in range(pad)]
        scrambled = base.scramble(data, seed) + [0] * 6
        encoded = base.encode(scrambled)
        pattern = punctures[mcs]
        coded = [bit for i, bit in enumerate(encoded) if pattern[i % len(pattern)]]
        assert len(coded) == symbols * 52 * nbpsc
        rows.append('\t'.join(map(str, [mcs, symbols, seed,
                    ''.join(map(str, sigb + [0] * 6)), psdu.hex(),
                    ''.join(map(str, coded)), int(corruption is None and seed != 0)])))

    for mcs in range(9):
        for symbols in [2, 3, 4, 5, 10, 17]:
            seeds = range(1, 128) if mcs == 0 and symbols == 3 else [1, 93, 127]
            for seed in seeds:
                emit(mcs, symbols, seed)
        emit(mcs, 5, 93, 'prefix')
        emit(mcs, 5, 93, 'crc')
        emit(mcs, 5, 0)
    for mcs, symbols in [(0, 1512), (8, 40), (8, 1512)]:
        emit(mcs, symbols, 93)
    return '\n'.join(rows) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate()
    if args.check:
        assert OUT.read_text() == result, 'VHT BCC DATA inventory differs'
    else:
        OUT.write_text(result)
    print(f'{len(result.splitlines()) - 1} independent VHT BCC DATA cases verified')
