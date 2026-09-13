"""Independent HE SU midamble IQ, IEEE802.11ax-2021 27.3.12.16.

DATA encoding/pilots retain their indices while identical LTF waveforms are
inserted. A piecewise FIR channel changes at each training CP, exposing a
receiver that merely skips midambles without refreshing channel estimates.
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
    rows=['name\tmcs\tldpc\tltf\tguard\tperiod\tsymbols\tmidambles\tpsdu\tframes\tsha256']
    cases=[]
    for ldpc in (False,True):
        for mcs in range(12 if ldpc else 10):
            for size,guard in ((1,16),(2,16),(2,32),(4,16),(4,64)):
                for period in (10,20):cases.append((mcs,ldpc,size,guard,period,period+2))
    for mcs,ldpc in ((0,False),(9,False),(0,True),(11,True)):
        for period in (10,20):
            for count in (period-1,period,period+1,2*period,2*period+1,2*period+2):
                cases.append((mcs,ldpc,4,64,period,count))
    cases += [(0,False,1,16,10,137),(11,True,2,32,20,137)]
    frames=[qos(1),qos(2)]
    payload=bytearray()
    for i,mpdu in enumerate(frames):
        payload+=b'\xc7'*(-len(payload)%4)
        payload+=delimiter(len(mpdu),int(i==0))+mpdu
    payload+=b'\xc7'*(-len(payload)%4)
    for mcs,ldpc,size,guard,period,count in cases:
        name=f'he-midamble-iq-mcs{mcs}-{"ldpc" if ldpc else "bcc"}-ltf{size}-gi{guard*50}-p{period}-n{count}'
        iq,fields=waveform(mcs,size,guard,'changing',payload=payload,ldpc=ldpc,
                           midamble_period=period,initial_symbols=count)
        symbols=fields[4]
        midambles=sum(n%period==0 for n in range(1,symbols-1))
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append('\t'.join(map(str,[name,mcs,int(ldpc),size,guard,period,symbols,
            midambles,fields[5],','.join(v.hex() for v in frames),hashlib.sha256(iq).hexdigest()])))
    invalid=['name\tsha256']
    for mcs,ldpc in ((0,False),(9,False),(11,True)):
        for size,guard in ((1,16),(4,64)):
            for error in ('erased-midamble','truncated-midamble'):
                name=f'he-midamble-iq-invalid-mcs{mcs}-ltf{size}-{error}'
                iq,_=waveform(mcs,size,guard,'changing',payload=payload,ldpc=ldpc,
                              midamble_period=10,initial_symbols=22,invalid=error)
                (out/f'{name}.cs8').write_bytes(iq)
                invalid.append(f'{name}\t{hashlib.sha256(iq).hexdigest()}')
    (out/'he-midamble-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    (out/'he-midamble-iq-invalid-index.tsv').write_text('\n'.join(invalid)+'\n')
    print(f'{len(cases)} independent HE midamble waveforms; 12 invalid training cases')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-midamble-iq-') as temporary:
            out=Path(temporary);generate(out)
            for file in out.iterdir():
                assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:generate(base.OUT)
