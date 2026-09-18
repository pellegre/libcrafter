"""Independent STF/LTF impairments with unchanged SIGNAL and DATA samples.

Short training receives bounded additive noise. Long training receives equal,
opposite, orthogonal errors, reducing repetition while preserving its averaged
channel estimate. Both use independent Python-generated legacy/HT waveforms.
"""
import argparse
import hashlib
import math
from pathlib import Path
import random
import tempfile

import ofdm_vectors as base

OUT = base.OUT


def generate(out):
    rows = ['name\tsource\timpairment\tsource_sha256\tsha256\tsamples\tpsdu_hex']
    for index, suffix, column in [('ofdm-index.tsv', '-clean', 6),
                                  ('ht-bcc-index.tsv', 'gi800-len100-clean', 4)]:
        for line in (OUT / index).read_text().splitlines()[1:]:
            c = line.split('\t')
            if not c[0].endswith(suffix):
                continue
            source = (OUT / (c[0] + '.cs8')).read_bytes()
            for impairment in ['stf32', 'stf40', 'ltf']:
                raw = bytearray(source)
                rng = random.Random(137)
                if impairment.startswith('stf'):
                    amplitude = int(impairment[3:])
                    for n in range(2 * 37, 2 * (37 + 160)):
                        value = raw[n] if raw[n] < 128 else raw[n] - 256
                        raw[n] = max(-128, min(127, value + rng.randint(-amplitude, amplitude))) & 255
                else:
                    start = 37 + 192
                    signed = [v if v < 128 else v - 256 for v in source]
                    training = [complex(*signed[2*n:2*n+2]) for n in range(start, start+64)]
                    noise = [complex(rng.uniform(-1, 1), rng.uniform(-1, 1)) for _ in training]
                    energy = sum(abs(v)**2 for v in training)
                    projection = sum(v.conjugate()*n for v, n in zip(training, noise))/energy
                    noise = [n-projection*v for v, n in zip(training, noise)]
                    scale = math.sqrt(.22*energy/sum(abs(n)**2 for n in noise))
                    noise = [complex(round(n.real*scale), round(n.imag*scale)) for n in noise]
                    for sign, offset in [(1, 0), (-1, 64)]:
                        for n, (value, error) in enumerate(zip(training, noise)):
                            altered = value + sign*error
                            assert max(abs(altered.real), abs(altered.imag)) <= 127
                            raw[2*(start+offset+n)] = int(altered.real) & 255
                            raw[2*(start+offset+n)+1] = int(altered.imag) & 255
                name = f'{c[0]}-training-{impairment}'
                (out / (name + '.cs8')).write_bytes(raw)
                rows.append('\t'.join(map(str, [name, c[0], impairment, hashlib.sha256(source).hexdigest(),
                                               hashlib.sha256(raw).hexdigest(), len(raw)//2, c[column]])))
    assert len(rows) == 49
    (out / 'ofdm-training-index.tsv').write_text('\n'.join(rows) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ofdm-training-check-') as directory:
            path = Path(directory)
            generate(path)
            for file in path.iterdir():
                assert file.read_bytes() == (OUT / file.name).read_bytes(), file.name
    else:
        generate(OUT)
    print('48 independent OFDM training-impairment fixtures verified')
