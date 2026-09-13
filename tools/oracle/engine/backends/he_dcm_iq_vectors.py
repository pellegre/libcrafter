"""Independent complete HE20 SU one-stream DCM IQ; IEEE802.11ax-2021 27.3.12.

Includes BCC filler, LDPC half-tone permutation, midambles, MAC integrity and
all DCM-compatible SU training/guard pairs. No production receiver calls.
"""
import argparse
import hashlib
from pathlib import Path
import tempfile
import ofdm_vectors as base
from he_bcc_iq_vectors import waveform
from he_ampdu_iq_vectors import qos
from vht_ampdu_vectors import delimiter


def payload(bad=False):
    frames=[qos(1),qos(2)]
    wire=bytearray()
    for i,frame in enumerate(frames):
        if bad and i==0:frame=frame[:-1]+bytes([frame[-1]^1])
        wire+=b'\xc7'*(-len(wire)%4)
        wire+=delimiter(len(frame),int(i==0))+frame
    wire+=b'\xc7'*(-len(wire)%4)
    return wire,frames[1 if bad else 0:]


def generate(out):
    rows=['name\tmcs\tldpc\tltf\tguard\tperiod\tpsdu\tframes\tbad_fcs\tsha256']
    invalid=['name\tsha256']
    for ldpc in (False,True):
        for mcs in (0,1,3,4):
            for size,guard in ((1,16),(2,16),(2,32),(4,64)):
                for padding in (1,2,3,4):
                    period=10 if padding==3 else None
                    wire,frames=payload(padding==4)
                    name=f'he-dcm-iq-mcs{mcs}-{"ldpc" if ldpc else "bcc"}-ltf{size}-gi{guard*50}-pad{padding}'
                    iq,fields=waveform(mcs,size,guard,'changing' if period else 'selective',payload=wire,ldpc=ldpc,dcm=True,
                                       midamble_period=period,initial_symbols=22 if period else 5,initial_padding=padding)
                    (out/f'{name}.cs8').write_bytes(iq)
                    rows.append('\t'.join(map(str,[name,mcs,int(ldpc),size,guard,period or 0,fields[5],
                        ','.join(v.hex() for v in frames),int(padding==4),hashlib.sha256(iq).hexdigest()])))
        for mcs in (0,4):
            for error in ('service','truncated'):
                name=f'he-dcm-iq-invalid-mcs{mcs}-{"ldpc" if ldpc else "bcc"}-{error}'
                iq,_=waveform(mcs,4,64,'flat',payload=payload()[0],ldpc=ldpc,dcm=True,invalid=error)
                (out/f'{name}.cs8').write_bytes(iq)
                invalid.append(f'{name}\t{hashlib.sha256(iq).hexdigest()}')
    (out/'he-dcm-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    (out/'he-dcm-iq-invalid-index.tsv').write_text('\n'.join(invalid)+'\n')
    print('128 complete HE DCM IQ cases; eight invalid cases')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-dcm-iq-') as temporary:
            out=Path(temporary);generate(out)
            for file in out.iterdir():assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:generate(base.OUT)
