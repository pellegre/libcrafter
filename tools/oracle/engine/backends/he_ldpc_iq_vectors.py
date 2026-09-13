"""Independent complete HE20 SU LDPC IQ and MAC bytes; IEEE802.11ax-2021 27.3.

Gaussian parity encoding, direct IDFT, diagram-derived constellations and
matrix-transpose tone mapping. No production receiver or transmitter calls.
"""
import argparse
import hashlib
from pathlib import Path
import tempfile
import ofdm_vectors as base
from he_bcc_iq_vectors import waveform
from he_ampdu_iq_vectors import qos
from vht_ampdu_vectors import delimiter


def generate(out):
    rows=['name\tmcs\tltf\tguard\tpsdu\tframes\tbad_fcs\tsha256']
    invalid=['name\tsha256']
    for mcs in range(12):
        for size,guard in ((1,16),(2,16),(2,32),(4,16),(4,64)):
            for padding in (1,2,3,4):
                frames=[qos(1),qos(2)]
                bad=padding==4
                payload=bytearray()
                for i,mpdu in enumerate(frames):
                    if bad and i==0: mpdu=mpdu[:-1]+bytes([mpdu[-1]^1])
                    payload+=b'\xc7'*(-len(payload)%4)
                    payload+=delimiter(len(mpdu),int(i==0))+mpdu
                payload+=b'\xc7'*(-len(payload)%4)
                name=f'he-ldpc-iq-mcs{mcs}-ltf{size}-gi{guard*50}-pad{padding}'
                iq,fields=waveform(mcs,size,guard,'selective' if padding%2 else 'offset',
                                   payload=payload,ldpc=True,initial_padding=padding)
                (out/f'{name}.cs8').write_bytes(iq)
                rows.append('\t'.join(map(str,[name,mcs,size,guard,fields[5],
                    ','.join(v.hex() for v in frames[1 if bad else 0:]),int(bad),hashlib.sha256(iq).hexdigest()])))
    for mcs in (0,10,11):
        for error in ('service','truncated'):
            name=f'he-ldpc-iq-invalid-mcs{mcs}-{error}'
            iq,_=waveform(mcs,4,64,'flat',invalid=error,ldpc=True)
            (out/f'{name}.cs8').write_bytes(iq)
            invalid.append(f'{name}\t{hashlib.sha256(iq).hexdigest()}')
    (out/'he-ldpc-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    (out/'he-ldpc-iq-invalid-index.tsv').write_text('\n'.join(invalid)+'\n')
    print('240 complete HE LDPC MAC waveforms; six invalid IQ cases')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-ldpc-iq-') as temporary:
            out=Path(temporary);generate(out)
            for file in out.iterdir():
                assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:generate(base.OUT)
