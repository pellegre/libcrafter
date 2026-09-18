"""Independent HT20 pilot phase bias and bounded additive DATA noise.

Rotate the four pilot tones by a common phase while leaving DATA tones intact,
then add reproducible complex sample noise. These impairments exercise phase
estimation from DATA decisions without changing packet bytes or PHY framing.
"""
import argparse
import cmath
import hashlib
import math
import random
from pathlib import Path
import tempfile

import ofdm_vectors as base

OUT = base.OUT


def generate(out):
    rows = ['name\tmcs\tguard_samples\tphase_sign\tsource_sha256\tsha256\tsamples\tpsdu_hex']
    for line in (OUT / 'ht-bcc-index.tsv').read_text().splitlines()[1:]:
        c = line.split('\t')
        if not c[0].endswith('gi800-len100-clean'):
            continue
        raw = (OUT / (c[0] + '.cs8')).read_bytes()
        source_hash = hashlib.sha256(raw).hexdigest()
        assert source_hash == c[5]
        signed = [v if v < 128 else v - 256 for v in raw]
        original = [complex(*signed[n:n + 2]) for n in range(0, len(signed), 2)]
        guard, symbols, start = int(c[2]), int(c[3]), int(c[7])
        polarity = [1 - 2 * b for b in base.scramble([0] * (symbols + 3), 127)]
        for phase_sign in [-1, 1]:
            samples = original.copy()
            for symbol in range(symbols):
                phase = phase_sign * 0.1
                tones = []
                for j, k in enumerate([-21, -7, 7, 21]):
                    amplitude = polarity[symbol + 3] * [1, 1, 1, -1][(symbol + j) % 4]
                    tones.append((k, amplitude * (cmath.exp(1j * phase) - 1)))
                delta = [300 * sum(v * cmath.exp(2j * math.pi * k * n / 64)
                                   for k, v in tones) / 64 for n in range(64)]
                for n, value in enumerate(delta[-guard:] + delta):
                    samples[start + symbol * (64 + guard) + n] += value
            rng = random.Random(911)
            for n in range(start, start + symbols * (64 + guard)):
                samples[n] += complex(rng.randint(-5, 5), rng.randint(-5, 5))
            iq = bytes(max(-128, min(127, round(value))) & 255
                       for sample in samples for value in [sample.real, sample.imag])
            name = f'ht-decision-{c[1]}-gi{guard * 50}-phase{phase_sign:+d}'
            (out / (name + '.cs8')).write_bytes(iq)
            rows.append('\t'.join(map(str, [name, c[1], guard, phase_sign, source_hash,
                                           hashlib.sha256(iq).hexdigest(), len(iq) // 2, c[4]])))
    assert len(rows) == 17
    (out / 'ht-decision-index.tsv').write_text('\n'.join(rows) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ht-decision-check-') as directory:
            path = Path(directory)
            generate(path)
            for file in path.iterdir():
                assert file.read_bytes() == (OUT / file.name).read_bytes(), file.name
    else:
        generate(OUT)
    print('16 independent HT20 DATA-decision fixtures verified')
