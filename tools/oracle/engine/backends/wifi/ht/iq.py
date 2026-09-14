"""Independent, header-only HT-mixed IQ fixtures (IEEE 802.11-2020 19.3.9).

These stop after HT-SIG; they are not complete HT PSDUs or TX qualification.
"""
import argparse
import cmath
import hashlib
from pathlib import Path
import tempfile
import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.ht.signal import crc

OUT = base.OUT


def generate(out):
    base.self_check()
    rows = ['name\tbits\tmode\tsha256\tsamples']
    for mcs in range(8):
        bits = [(mcs >> n) & 1 for n in range(7)] + [0]
        bits += [(100 >> n) & 1 for n in range(16)]
        bits += [1, 1, 1, 0, 0, 0, mcs & 1, (mcs >> 1) & 1, 0, 0]
        bits += crc(bits) + [0] * 6
        for mode in ['clean', 'offset', 'bad_crc', 'unrotated']:
            wire = bits.copy()
            if mode == 'bad_crc':
                wire[34] ^= 1
            coded = base.encode(wire)
            wave = [0j] * 37 + base.preamble()
            wave += base.symbol(base.interleave(base.encode(base.signal('1101', 100)), 1), 1, 1)
            for symbol in range(2):
                data = base.interleave(coded[symbol*48:(symbol+1)*48], 1)
                freq = [0j] * 53
                for k, bit in zip(base.CARRIERS, data):
                    freq[k+26] = (2*bit-1) * (1 if mode == 'unrotated' else 1j)
                # HT-SIG uses p1 and p2, both +1; pilot tones stay unrotated.
                for k, sign in [(-21, 1), (-7, 1), (7, 1), (21, -1)]:
                    freq[k+26] = sign
                time = base.ifft(freq)
                wave += time[-16:] + time
            wave += [0j] * 64
            if mode == 'offset':
                source = wave.copy()
                wave = [(v + (0.25j * source[n-3] if n >= 3 else 0)) * cmath.exp(1j*(0.7+0.018*n)) for n, v in enumerate(source)]
            iq = base.quantize(wave)
            name = f'ht-mixed-sig-{mcs}-{mode}'
            (out / f'{name}.cs8').write_bytes(iq)
            rows.append('\t'.join([name, ''.join(map(str, wire)), mode, hashlib.sha256(iq).hexdigest(), str(len(iq)//2)]))
    (out / 'ht-mixed-index.tsv').write_text('\n'.join(rows)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ht-iq-check-') as directory:
            output = Path(directory)
            generate(output)
            for path in output.iterdir():
                assert path.read_bytes() == (OUT / path.name).read_bytes(), path.name
    else:
        generate(OUT)
    print('32 independent HT-mixed header IQ fixtures verified')
