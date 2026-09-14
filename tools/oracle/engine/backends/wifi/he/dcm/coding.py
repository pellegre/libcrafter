"""Independent joint DCM distance oracle; IEEE802.11ax-2021 27.3.12.9.

Explicit axis label tables and exact rational squared distances. Observations
are stored before constellation normalization; metrics include that scaling.
"""
import argparse
from fractions import Fraction as F
import itertools
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES

OUT=IQ_FIXTURES / 'he-dcm-metrics.tsv'


def pair(bits,k,half=117):
    def point(b):
        if len(b)==1:return (-1 if b=='0' else 1,0)
        if len(b)==2:return (-1 if b[0]=='0' else 1,-1 if b[1]=='0' else 1)
        axis={'00':-3,'01':-1,'10':3,'11':1}
        return (axis[b[:2]],axis[b[2:]])
    lower=point(bits)
    if len(bits)==1:upper=(lower[0]*(-1 if (k+half)%2 else 1),0)
    elif len(bits)==2:upper=(lower[0],-lower[1])
    else:upper=point(bits[1]+bits[0]+bits[3]+bits[2])
    return (*lower,*upper)


def generate(half=117):
    rows=['bps\tk\tli\tlq\tui\tuq\tw0\tw1\tbits\tmetrics']
    for bps in (1,2,4):
        labels=[''.join(b) for b in itertools.product('01',repeat=bps)]
        energy={1:1,2:2,4:10}[bps]
        for k in (0,1,half-1):
            for label in labels:
                for noise in (0,1):
                    observed=[F(v)+noise*d for v,d in zip(pair(label,k,half),[F(1,8),F(1,4),F(-3,8),F(-1,8)])]
                    for weights in ((F(1),F(1)),(F(0),F(1)),(F(1),F(0)),(F(1,8),F(4)),(F(0),F(0))):
                        costs={b:sum(w*(o-v)**2 for o,v,w in zip(observed,pair(b,k,half),[weights[0]]*2+[weights[1]]*2))/energy for b in labels}
                        metrics=[min(v for b,v in costs.items() if b[i]=='0')-min(v for b,v in costs.items() if b[i]=='1') for i in range(bps)]
                        rows.append('\t'.join([str(bps),str(k),*[format(float(v),'.17g') for v in observed+list(weights)],label if not noise else '-',','.join(format(float(v),'.17g') for v in metrics)]))
    return '\n'.join(rows)+'\n'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');parser.add_argument('--half',type=int,choices=(12,24,117),default=117);args=parser.parse_args()
    content=generate(args.half)
    output=OUT if args.half==117 else OUT.with_name(f'he-dcm-half{args.half}-metrics.tsv')
    if args.check:assert output.read_text()==content
    else:output.write_text(content)
    print(f'{len(content.splitlines())-1} independent joint DCM metrics')
