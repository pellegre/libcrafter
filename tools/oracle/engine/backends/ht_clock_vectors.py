"""Independent receive-clock impairments of HT20 BCC oracle waveforms.

IEEE 802.11-2020 19.3.11: OFDM symbols retain a cyclic prefix; clock
offset changes their received duration. Positive ppm is a faster receiver.
No crafter encoder or receiver is used by this generator.
"""
import argparse
import hashlib
from pathlib import Path
import tempfile

import ofdm_vectors
from ofdm_clock_vectors import resample

OUT = ofdm_vectors.OUT


def generate(out):
    rows = ['name\tmcs\tguard_samples\tclock_ppm\tsource_sha256\tsha256\tsamples\tpsdu_hex']
    for line in (OUT / 'ht-bcc-index.tsv').read_text().splitlines()[1:]:
        cols = line.split('\t')
        if not cols[0].endswith('len4095-clean'):
            continue
        source = (OUT / (cols[0] + '.cs8')).read_bytes()
        source_hash = hashlib.sha256(source).hexdigest()
        assert source_hash == cols[5]
        signed = [v if v < 128 else v - 256 for v in source]
        samples = [complex(*signed[n:n + 2]) for n in range(0, len(signed), 2)]
        for ppm in [-80, 80]:
            name = f'ht-clock-{cols[1]}-gi{int(cols[2]) * 50}-{ppm:+d}ppm'
            iq = resample(samples, ppm, 37)
            (out / (name + '.cs8')).write_bytes(iq)
            rows.append('\t'.join(map(str, [name, cols[1], cols[2], ppm, source_hash,
                                           hashlib.sha256(iq).hexdigest(), len(iq) // 2, cols[4]])))
    assert len(rows) == 33
    (out / 'ht-clock-index.tsv').write_text('\n'.join(rows) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ht-clock-check-') as directory:
            path = Path(directory)
            generate(path)
            for file in path.iterdir():
                assert file.read_bytes() == (OUT / file.name).read_bytes(), file.name
    else:
        generate(OUT)
    print('32 independent HT20 clock fixtures verified')
