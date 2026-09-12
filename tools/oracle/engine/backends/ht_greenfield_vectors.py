"""Independent HT20 greenfield IQ; IEEE 802.11-2020 19.3.9.5, 19.3.11.11.3.

One space-time stream, no extension streams: long GI only (19.3.11.11.6).
This backend shares independent coding arithmetic, never production TX.
"""
import argparse
import cmath
import hashlib
import tempfile
from pathlib import Path
import ht_ampdu_vectors as aggregate
import ht_ldpc_vectors as ldpc
import ofdm_vectors as base


def generate(out):
    out.mkdir(parents=True, exist_ok=True)
    rows = ['name\tmcs\tguard_samples\tsymbols\tpsdu_hex\tsha256\tsamples\tdata_start\tframe_end\tldpc']
    for mcs in range(8):
        for coding in [False, True]:
            for extra in [44, 4039]:
                psdu = base.frame(extra)
                symbols, coded = (ldpc.encode_psdu if coding else aggregate.bcc)(psdu, mcs)
                wave, start, end = ldpc.waveform(psdu, mcs, 16, symbols, coded,
                                                ldpc=coding, greenfield=True)
                assert start == 37 + 480 and end == start + symbols * 80
                for impairment in ['clean', 'offset']:
                    impaired = wave
                    if impairment == 'offset':
                        impaired = [(v + (0.25j * wave[n-3] if n >= 3 else 0))
                                    * cmath.exp(1j * (0.7 + 0.018*n)) for n, v in enumerate(wave)]
                    iq = base.quantize(impaired)
                    name = f'ht-greenfield-{mcs}-{"ldpc" if coding else "bcc"}-len{len(psdu)}-{impairment}'
                    (out / f'{name}.cs8').write_bytes(iq)
                    rows.append('\t'.join(map(str, [name, mcs, 16, symbols, psdu.hex(),
                                                       hashlib.sha256(iq).hexdigest(), len(iq)//2,
                                                       start, end, int(coding)])))
    (out / 'ht-greenfield-index.tsv').write_text('\n'.join(rows) + '\n')
    print(f'{len(rows)-1} independent HT20 greenfield IQ fixtures verified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ht-greenfield-check-') as temporary:
            out = Path(temporary)
            generate(out)
            for file in out.iterdir():
                assert file.read_bytes() == (base.OUT / file.name).read_bytes(), file.name
    else:
        generate(base.OUT)
