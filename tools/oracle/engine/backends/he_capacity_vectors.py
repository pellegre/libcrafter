"""Independent forward HE20 SU/ER/MU padding, IEEE802.11ax-2021 27.3.12.2/5.

Starts with APEP bytes, allocates symbol segments and fills MAC/PHY padding.
LDPC extra branches are geometry checks, not puncturing-threshold/codeword
qualification. No Rust implementation imports or receive-length inversion.
MU receive budgets additionally follow Equations27-144..147; Table27-33
defines two short data tones (not three) for a 26-tone RU with DCM.
"""
import argparse
from fractions import Fraction
from math import ceil
from pathlib import Path

OUT=Path(__file__).resolve().parents[4]/'crafter/tests/fixtures/iq/he-capacity-index.tsv'
# Table27-79 (non-DCM), independently tabulated rather than receiver rate math.
BPS=[1,2,2,4,4,6,6,6,8,8,10,10]
DATA=[117,234,351,468,702,936,1053,1170,1404,1560,1755,1950]
SHORT=[30,60,90,120,180,240,270,300,360,400,450,500]


def generate(er_tones=None, mu_tones=None):
    tones=mu_tones or er_tones or 242
    full={26:[12,24,36,48,72,96,108,120,144,160,180,200],
          52:[24,48,72,96,144,192,216,240,288,320,360,400],
          106:[51,102,153,204,306,408,459,510,612,680,765,850],242:DATA}[tones]
    short={26:[3,6,9,12,18,24,27,30,36,40,45,50],
           52:[6,12,18,24,36,48,54,60,72,80,90,100],
           106:[12,24,36,48,72,96,108,120,144,160,180,200],242:SHORT}[tones]
    rows=['mcs\tsts\tdcm\tstbc\tldpc\textra\tpadding\tsymbols\tbps\tnss\tcbps\tdbps\tlast\tcoded\tdata\tpsdu\tphy_pad\ttail\tfiller']
    for nss in range(1,9):
        if er_tones and nss != 1: continue
        for mcs in range(12):
            if er_tones and mcs > (0 if er_tones==106 else 2): continue
            for dcm in ([0,1] if nss<=2 and mcs in (0,1,3,4) else [0]):
                divisor=1+dcm
                cbps={26:24,52:48,106:102,242:234}[tones]*BPS[mcs]*nss//divisor
                dbps=full[mcs]*nss//divisor
                short_data=({0:1,1:2,3:4,4:6}[mcs]*nss if tones==26 and dcm else short[mcs]*nss//divisor)
                short_coded=({26:6,52:12,106:24,242:60}[tones]//divisor if not (tones==26 and dcm) else 2)*BPS[mcs]*nss
                for stbc in ([0,1] if nss==1 and not dcm else [0]):
                    group=1+stbc
                    for ldpc in ([0,1] if nss<=4 and mcs<=9 else [1]):
                        tail=0 if ldpc else 6
                        lengths=set([0,1,3,4,7,8,15,16,30,31,32,100,127,128,129,512,1500])
                        for segment in range(1,5):
                            boundary=max(0,(group*short_data*segment-16-tail)//8)
                            lengths.update([max(0,boundary-1),boundary,boundary+1])
                        for apep in sorted(lengths):
                            needed=8*apep+16+tail
                            groups=ceil(Fraction(needed,group*dbps))
                            left=needed-(groups-1)*group*dbps
                            # Choose the first of four boundaries large enough.
                            boundaries=[group*short_data*k for k in (1,2,3)]+[group*dbps]
                            segment=next(k for k,limit in enumerate(boundaries,1) if limit>=left)
                            budget=(groups-1)*group*dbps+boundaries[segment-1]
                            pad=budget-needed
                            psdu=apep+pad//8
                            initial_symbols=groups*group
                            initial_coded=(initial_symbols-group)*cbps+group*(cbps if segment==4 else segment*short_coded)
                            for extra in ([0,1] if ldpc else [0]):
                                symbols=initial_symbols
                                padding=segment
                                coded=initial_coded
                                if extra:
                                    coded+=group*(cbps-3*short_coded if segment==3 else short_coded)
                                    if segment==4: symbols+=group; padding=1
                                    else: padding+=1
                                last=cbps if padding==4 else padding*short_coded
                                row=[mcs,nss*group,dcm,stbc,ldpc,extra,padding,symbols,BPS[mcs],nss,
                                     cbps,dbps,last,coded,budget,psdu,pad%8,tail,int(not ldpc and dcm and mcs==0 and nss==1 and tones in (106,242))]
                                rows.append('\t'.join(map(str,row)))
    return '\n'.join(rows)+'\n'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--er-tones',type=int,choices=(106,242))
    parser.add_argument('--mu-tones',type=int,choices=(26,52,106,242))
    args=parser.parse_args()
    if args.er_tones and args.mu_tones: parser.error('choose ER or MU, not both')
    content=generate(args.er_tones,args.mu_tones)
    output=OUT.with_name(f'he-mu{args.mu_tones}-capacity-index.tsv') if args.mu_tones else (OUT.with_name(f'he-er{args.er_tones}-capacity-index.tsv') if args.er_tones else OUT)
    if args.check: assert output.read_text()==content,'HE capacity corpus differs'
    else: output.write_text(content)
    print(f'{len(content.splitlines())-1} independent HE capacity cases')
