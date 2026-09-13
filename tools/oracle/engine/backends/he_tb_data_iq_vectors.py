"""Independent isolated HE20 TB user waveforms, IEEE802.11ax-2021 27.3.

Uses the forward encoder/IDFT shared with MU fixtures, with explicit TB
SIG-A, STF, timing, RU normalization and pilot indexing. Synthetic PSDUs,
not MAC frames; no automatic Trigger association or multi-user CFO evidence.
"""
import argparse
import hashlib
from pathlib import Path
import tempfile
import ofdm_vectors as base
from he_mu_data_iq_vectors import waveform
from he_ru_symbol_vectors import geometry


def generate(out):
    cases=[]
    for ru in (26,52,106,242):
        for ldpc in (False,True):
            for mcs in range(12 if ldpc else 10):
                for stbc,dcm in [(False,False),(True,False)]+([(False,True)] if mcs in (0,1,3,4) else []):
                    size,guard=(2,32) if mcs%2==0 else (4,64)
                    cases.append((ru,1,mcs,ldpc,dcm,stbc,size,guard,True,1+int(stbc),0,'none'))
    for ru,index,_,_ in geometry():
        for size,guard in ((2,32),(4,64)):
            for stbc in (False,True):
                cases.append((ru,index,3,True,False,stbc,size,guard,False,1+int(stbc),0,'none'))
    for period in (10,20):
        for ldpc in (False,True):
            for stbc in (False,True):
                cases.append((52,2,3,ldpc,not stbc,stbc,4,64,True,4,period,'none'))
    for ldpc in (False,True):
        cases.append((26,3,1,ldpc,False,False,2,32,True,1,0,'service'))
    rows=['name\tru\tindex\tmcs\tldpc\tdcm\tstbc\tltf\tguard\tnltf\tperiod\tlength\tpadding\textra\tsymbols\tdamage\tpsdu\tsamples\tsha256']
    for number,(ru,index,mcs,ldpc,dcm,stbc,size,guard,impaired,nltf,period,damage) in enumerate(cases):
        trace={}
        iq,payloads,symbols=waveform(192,mcs,ldpc,dcm,size,guard,impaired,nltf,period,damage,
            stbc=stbc,stbc_case='changing' if period else 'selective',tb_ru=(ru,index),sizing_trace=trace)
        name=f'he-tb-data-{number:03d}-ru{ru}-i{index}-m{mcs}-l{int(ldpc)}-s{int(stbc)}'
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append('\t'.join(map(str,[name,ru,index,mcs,int(ldpc),int(dcm),int(stbc),size,guard,nltf,period,
            trace['length'],trace['padding']%4,int(trace['extra']),symbols,damage,payloads[0],len(iq)//2,hashlib.sha256(iq).hexdigest()])))
    (out/'he-tb-data-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent isolated TB user IQ waveforms')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-tb-data-') as temporary:
            out=Path(temporary);generate(out)
            for path in out.iterdir():
                assert path.read_bytes()==(base.OUT/path.name).read_bytes(),path.name
    else:
        generate(base.OUT)
