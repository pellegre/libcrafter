"""Independent HT20 waveforms with known quadrature gain and leakage errors."""
import argparse
import hashlib
from pathlib import Path
import tempfile

import ofdm_vectors as base

OUT = base.OUT


def generate(out):
    rows = ['name\tsource\tgain\tleakage\tsource_sha256\tsha256\tsamples\tpsdu_hex']
    for line in (OUT / 'ht-bcc-index.tsv').read_text().splitlines()[1:]:
        c = line.split('\t')
        if not c[0].endswith('len100-clean'):
            continue
        source = (OUT / (c[0] + '.cs8')).read_bytes()
        values = [v if v < 128 else v - 256 for v in source]
        for gain, leakage in [(.6, -.2), (.6, .2), (1.4, -.2), (1.4, .2)]:
            raw = bytearray()
            for i, q in zip(values[::2], values[1::2]):
                a, b = round(.5 * i), round(.5 * (q / gain + leakage * i))
                assert max(abs(a), abs(b)) <= 127
                raw.extend([a & 255, b & 255])
            name = f'{c[0]}-iq{gain}-{leakage}'
            (out / (name + '.cs8')).write_bytes(raw)
            rows.append('\t'.join(map(str, [name, c[0], gain, leakage,
                hashlib.sha256(source).hexdigest(), hashlib.sha256(raw).hexdigest(),
                len(raw) // 2, c[4]])))
    assert len(rows) == 65
    (out / 'ofdm-iq-balance-index.tsv').write_text('\n'.join(rows) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ofdm-iq-balance-') as directory:
            path = Path(directory)
            generate(path)
            for file in path.iterdir():
                assert file.read_bytes() == (OUT / file.name).read_bytes(), file.name
    else:
        generate(OUT)
    print('64 independent HT20 I/Q imbalance fixtures verified')
