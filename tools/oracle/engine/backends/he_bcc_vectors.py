"""Independent HE BCC coded-bit/PSDU vectors (not complete MAC/IQ frames).

IEEE802.11ax-2021 27.3.12.1-5. Independent forward encoder anchored by legacy
AnnexG checks; no Rust decoder imports. Arbitrary post-FEC and DCM filler bits.
"""
import argparse
from pathlib import Path
import ofdm_vectors as base
from ht_bcc_vectors import PUNCTURE
from he_capacity_vectors import BPS,DATA,SHORT

OUT=Path(__file__).resolve().parents[4]/'crafter/tests/fixtures/iq/he-bcc-index.tsv'


def generate(er_tones=None):
    base.self_check()
    rows=['mcs\tnss\tstbc\tdcm\tsymbols\tpadding\tseed\tpsdu\tcoded\tvalid']
    def emit(mcs,nss,stbc,dcm,symbols,padding,seed,invalid=False):
        group=1+stbc
        cbps=(102 if er_tones==106 else 234)*BPS[mcs]*nss//(1+dcm)
        dbps=(51 if er_tones==106 else DATA[mcs])*nss//(1+dcm)
        last=cbps if padding==4 else padding*(24 if er_tones==106 else 60)*BPS[mcs]*nss//(1+dcm)
        last_data=dbps if padding==4 else padding*(12 if er_tones==106 else SHORT[mcs])*nss//(1+dcm)
        count=(symbols-group)*dbps+group*last_data
        octets,pad=divmod(count-22,8)
        psdu=bytes((n*37+seed+13*mcs)%256 for n in range(octets))
        service=[0]*16
        if invalid: service[7]=1
        bits=base.scramble(service+base.bits(psdu)+[n%2 for n in range(pad)],seed)+[0]*6
        pattern=PUNCTURE[mcs] if mcs<8 else ([1,1,1,0,0,1] if mcs==8 else [1,1,1,0,0,1,1,0,0,1])
        coded=[b for i,b in enumerate(base.encode(bits)) if pattern[i%len(pattern)]]
        if dcm and mcs==0 and nss==1:
            filled=[]
            span=50 if er_tones==106 else 116
            for i in range(0,len(coded),span):
                chunk=coded[i:i+span];filled.extend(chunk)
                if len(chunk)==span: filled.append((seed+i)%2)
            coded=filled
        output=[];cursor=0
        for symbol in range(symbols):
            keep=last if symbol>=symbols-group else cbps
            output.extend(coded[cursor:cursor+keep]);cursor+=keep
            output.extend((seed+n+symbol)%2 for n in range(cbps-keep))
        assert cursor==len(coded) and len(output)==symbols*cbps
        rows.append('\t'.join(map(str,[mcs,nss,stbc,dcm,symbols,padding,seed,
            psdu.hex(),''.join(map(str,output)),int(not invalid and seed!=0)])))
    for mcs in range(10):
        if er_tones and mcs > (0 if er_tones==106 else 2): continue
        for dcm in ([0,1] if mcs in (0,1,3,4) else [0]):
            for padding in range(1,5):
                for symbols in (2,5):
                    for seed in (1,93): emit(mcs,1,0,dcm,symbols,padding,seed)
        if not er_tones:
            for nss in (2,4): emit(mcs,nss,0,0,3,3,127)
        for padding in range(1,5): emit(mcs,1,1,0,4,padding,93)
        if not er_tones and mcs in (0,1,3,4): emit(mcs,2,0,1,3,4,127)
        emit(mcs,1,0,0,5,3,93,True)
        emit(mcs,1,0,0,5,3,0)
    for seed in range(1,128): emit(0,1,0,0,3,1,seed)
    return '\n'.join(rows)+'\n'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--er-tones',type=int,choices=(106,242))
    args=parser.parse_args();content=generate(args.er_tones)
    output=OUT.with_name(f'he-er{args.er_tones}-bcc-index.tsv') if args.er_tones else OUT
    if args.check: assert output.read_text()==content,'HE BCC corpus differs'
    else: output.write_text(content)
    print(f'{len(content.splitlines())-1} independent HE BCC cases')
