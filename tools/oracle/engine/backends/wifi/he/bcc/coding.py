"""Independent HE BCC coded-bit/PSDU vectors (not complete MAC/IQ frames).

IEEE802.11ax-2021 27.3.12.1-5. Independent forward encoder anchored by legacy
AnnexG checks; no Rust decoder imports. Arbitrary post-FEC and DCM filler bits.
"""
import argparse
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.ht.bcc import PUNCTURE
from tools.oracle.engine.backends.wifi.he.capacity import BPS,DATA,SHORT

OUT=IQ_FIXTURES / 'he-bcc-index.tsv'


def generate(er_tones=None, mu_tones=None):
    base.self_check()
    tones=mu_tones or er_tones or 242
    full={26:[12,24,36,48,72,96,108,120,144,160],52:[24,48,72,96,144,192,216,240,288,320],106:[51,102,153,204,306,408,459,510,612,680],242:DATA}[tones]
    short={26:[3,6,9,12,18,24,27,30,36,40],52:[6,12,18,24,36,48,54,60,72,80],106:[12,24,36,48,72,96,108,120,144,160],242:SHORT}[tones]
    rows=['mcs\tnss\tstbc\tdcm\tsymbols\tpadding\tseed\tpsdu\tcoded\tvalid']
    def emit(mcs,nss,stbc,dcm,symbols,padding,seed,invalid=False):
        group=1+stbc
        cbps={26:24,52:48,106:102,242:234}[tones]*BPS[mcs]*nss//(1+dcm)
        dbps=full[mcs]*nss//(1+dcm)
        short_coded=(2 if tones==26 and dcm else {26:6,52:12,106:24,242:60}[tones]//(1+dcm))*BPS[mcs]*nss
        short_data=({0:1,1:2,3:4,4:6}[mcs]*nss if tones==26 and dcm else short[mcs]*nss//(1+dcm))
        last=cbps if padding==4 else padding*short_coded
        last_data=dbps if padding==4 else padding*short_data
        count=(symbols-group)*dbps+group*last_data
        if count<22:return
        octets,pad=divmod(count-22,8)
        psdu=bytes((n*37+seed+13*mcs)%256 for n in range(octets))
        service=[0]*16
        if invalid: service[7]=1
        bits=base.scramble(service+base.bits(psdu)+[n%2 for n in range(pad)],seed)+[0]*6
        pattern=PUNCTURE[mcs] if mcs<8 else ([1,1,1,0,0,1] if mcs==8 else [1,1,1,0,0,1,1,0,0,1])
        coded=[b for i,b in enumerate(base.encode(bits)) if pattern[i%len(pattern)]]
        if dcm and mcs==0 and nss==1 and tones in (106,242):
            filled=[]
            span=50 if tones==106 else 116
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
    parser.add_argument('--mu-tones',type=int,choices=(26,52,106,242))
    args=parser.parse_args()
    if args.er_tones and args.mu_tones:parser.error('choose ER or MU, not both')
    content=generate(args.er_tones,args.mu_tones)
    output=OUT.with_name(f'he-mu{args.mu_tones}-bcc-index.tsv') if args.mu_tones else (OUT.with_name(f'he-er{args.er_tones}-bcc-index.tsv') if args.er_tones else OUT)
    if args.check: assert output.read_text()==content,'HE BCC corpus differs'
    else: output.write_text(content)
    print(f'{len(content.splitlines())-1} independent HE BCC cases')
