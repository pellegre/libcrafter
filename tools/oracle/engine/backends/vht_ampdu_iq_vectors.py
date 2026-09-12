"""Independent complete VHT20 BCC aggregate waveforms for streaming RX.

Uses the independent PHY model and byte-framing model, never production code.
IEEE 802.11-2020 9.7, 10.12.6-8, 21.3.8/10/20.
"""
import argparse
import hashlib
from pathlib import Path
import tempfile

import ofdm_vectors as base
from vht_ampdu_vectors import aggregate, frame
from vht_bcc_iq_vectors import waveform


def generate(out):
    rows = ['name\tmcs\tguard\tpsdu_hex\tframe_offsets\tmpdu_hex\tsha256\tdata_end\tinvalid_fcs']
    for mcs in range(9):
        for guard in (8, 16):
            for case in ('duplicate', 'bad-fcs', 'large'):
                frames = [frame(4100), frame(56)] if case == 'large' else [frame(56)] * 2
                apep, offsets = aggregate(frames)
                if case == 'bad-fcs':
                    damaged = bytearray(apep)
                    damaged[offsets[0] + len(frames[0]) - 1] ^= 1
                    apep = bytes(damaged)
                    frames, offsets = frames[1:], offsets[1:]
                samples, fields = waveform(mcs, guard, 0, apep_override=apep)
                assert fields[1] <= 4095
                assert all(max(abs(v.real), abs(v.imag)) * 300 < 127 for v in samples)
                iq = base.quantize(samples)
                name = f'vht-ampdu-{mcs}-gi{guard * 50}-{case}'
                (out / f'{name}.cs8').write_bytes(iq)
                rows.append('\t'.join(map(str, [name, mcs, guard, fields[4].hex(),
                    ','.join(map(str, offsets)), ','.join(f.hex() for f in frames),
                    hashlib.sha256(iq).hexdigest(), fields[7], int(case == 'bad-fcs')])))
    (out / 'vht-ampdu-iq-index.tsv').write_text('\n'.join(rows) + '\n')
    print(f'{len(rows) - 1} independent complete VHT aggregate waveforms verified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='vht-ampdu-iq-') as temporary:
            out = Path(temporary)
            generate(out)
            for file in out.iterdir():
                assert file.read_bytes() == (base.OUT / file.name).read_bytes(), file.name
    else:
        generate(base.OUT)
