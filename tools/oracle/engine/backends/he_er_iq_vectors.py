"""Independent complete ER242 IQ, IEEE802.11ax-2021 27.3.11/12.

Direct-IDFT forward waveforms with repeated signaling, boosted training,
ER pilot clock, BCC/LDPC, DCM/STBC, midambles and independently framed MAC.
No receiver calls. Offline vectors do not establish hardware qualification.
"""
import argparse
import hashlib
from pathlib import Path
import tempfile
import ofdm_vectors as base
from he_bcc_iq_vectors import waveform as single
from he_stbc_iq_vectors import waveform as stbc_wave
from he_dcm_iq_vectors import payload


def waveform(mode,mcs,ldpc,size,guard,padding,invalid=None,upper106=False):
    period=10 if padding==3 else 20 if padding==4 else None
    case='changing' if period else 'selective'
    if mode=='stbc':
        return stbc_wave(mcs,size,guard,ldpc,padding,case,period,invalid,er=True,upper106=upper106)
    wire,frames=payload(padding==4)
    iq,f=single(mcs,size,guard,case,invalid=invalid,payload=wire,ldpc=ldpc,
                initial_padding=padding,midamble_period=period,
                initial_symbols=2*period+2 if period else 5,dcm=mode=='dcm',er=True,upper106=upper106)
    return iq,bytes.fromhex(f[5]),frames,f[9],f[10]


def generate(out,upper106=False):
    prefix='he-er106-iq' if upper106 else 'he-er-iq'
    rows=['name\tmcs\tldpc\tltf\tguard\tperiod\tpsdu\tframes\tbad_fcs\tdata_start\tdata_end\tdcm\tstbc\tsha256']
    invalid=['name\tsha256']
    for mode in ('plain','dcm','stbc'):
        guards=[(1,16),(2,16),(2,32),(4,64)]
        if mode=='plain':guards += [(4,16)]
        for ldpc in (False,True):
            for mcs in range(1 if upper106 else 2 if mode=='dcm' else 3):
                for size,guard in guards:
                    for padding in (1,2,3,4):
                        name=f'{prefix}-{mode}-mcs{mcs}-{"ldpc" if ldpc else "bcc"}-ltf{size}-gi{guard*50}-pad{padding}'
                        iq,psdu,frames,start,end=waveform(mode,mcs,ldpc,size,guard,padding,upper106=upper106)
                        (out/f'{name}.cs8').write_bytes(iq)
                        period=10 if padding==3 else 20 if padding==4 else 0
                        rows.append('\t'.join(map(str,[name,mcs,int(ldpc),size,guard,period,psdu.hex(),
                            ','.join(v.hex() for v in frames),int(padding==4),start,end,
                            int(mode=='dcm'),int(mode=='stbc'),hashlib.sha256(iq).hexdigest()])))
            errors=['service','truncated']
            if mode=='stbc':errors += ['erased-training','truncated-midamble']
            for error in errors:
                name=f'{prefix}-invalid-{mode}-{"ldpc" if ldpc else "bcc"}-{error}'
                iq,*_=waveform(mode,0,ldpc,4,64,3,invalid=error,upper106=upper106)
                (out/f'{name}.cs8').write_bytes(iq)
                invalid.append(f'{name}\t{hashlib.sha256(iq).hexdigest()}')
    (out/f'{prefix}-index.tsv').write_text('\n'.join(rows)+'\n')
    (out/f'{prefix}-invalid-index.tsv').write_text('\n'.join(invalid)+'\n')
    print(f'{len(rows)-1} complete ER{106 if upper106 else 242} waveforms; {len(invalid)-1} invalid cases')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--upper106',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-er-iq-') as temporary:
            out=Path(temporary);generate(out,args.upper106)
            for file in out.iterdir():assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:generate(base.OUT,args.upper106)
