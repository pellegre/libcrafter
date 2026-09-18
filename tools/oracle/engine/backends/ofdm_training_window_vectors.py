"""Independent legacy OFDM fixtures with noise confined to the end of L-LTF."""
import argparse
import hashlib
from pathlib import Path
import random
import tempfile

import ofdm_vectors as base

OUT = base.OUT


def generate(out):
    rows = ['name\tsource\tamplitude\tseed\tsource_sha256\tsha256\tsamples\tpsdu_hex']
    for line in (OUT / 'ofdm-index.tsv').read_text().splitlines()[1:]:
        c = line.split('\t')
        if not c[0].endswith('-clean'):
            continue
        source = (OUT / (c[0] + '.cs8')).read_bytes()
        signed = [v if v < 128 else v - 256 for v in source]
        for amplitude in [20, 40, 60]:
            for seed in [13, 37, 71, 137]:
                raw = bytearray(source)
                rng = random.Random(seed)
                for n in range(2 * (37 + 312), 2 * (37 + 320)):
                    raw[n] = max(-128, min(127, signed[n] + rng.randint(-amplitude, amplitude))) & 255
                name = f'{c[0]}-training-window-{amplitude}-{seed}'
                (out / (name + '.cs8')).write_bytes(raw)
                rows.append('\t'.join(map(str, [name, c[0], amplitude, seed,
                    hashlib.sha256(source).hexdigest(), hashlib.sha256(raw).hexdigest(),
                    len(raw) // 2, c[6]])))
    assert len(rows) == 97
    (out / 'ofdm-training-window-index.tsv').write_text('\n'.join(rows) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ofdm-training-window-') as directory:
            path = Path(directory)
            generate(path)
            for file in path.iterdir():
                assert file.read_bytes() == (OUT / file.name).read_bytes(), file.name
    else:
        generate(OUT)
    print('96 independent legacy training-window fixtures verified')
