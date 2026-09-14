"""Independent forward HE SU / ER SU timeline, IEEE802.11ax-2021 27.3.12.16/13.

Constructs every DATA/training interval before encoding L-SIG duration;
does not call or reproduce the receiver's duration inversion equations.
Timing vectors are not DATA admission or IQ/frame qualification.
"""
import argparse
from fractions import Fraction
import hashlib
from math import ceil
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES

OUT = IQ_FIXTURES / 'he-timing-index.tsv'


def generate(er=False):
    rows = ['sts\tltf\tgi\tperiod\tstbc\tsymbols\tpe\tlsig\tdisambiguity\tltf_symbols\tmidambles\tdata_start\tdata_end\tpacket_end\tsignaled_end\toffsets_sha256']
    for sts,nltf in enumerate([1,2,4,4,6,6,8,8],1):
        if er and sts > 2: continue
        for size,gi in ((1,800),(2,800),(2,1600),(4,800),(4,3200)):
            training = nltf*(Fraction(16,5)*size+Fraction(gi,1000))
            symbol = Fraction(64,5)+Fraction(gi,1000)
            for period in ([0,10,20] if sts<=4 else [0]):
                for stbc in ([0,1] if sts==2 and (size,gi)!=(4,800) else [0]):
                    if er and sts != 1+stbc: continue
                    for count in [1,2,3,9,10,11,12,19,20,21,22,29,30,31,32,39,40,41,42,99,100,101,102,333,398,399,400]:
                        if stbc and count%2: continue
                        clock = 36+8*er+training
                        start = int(clock*20)
                        offsets = []
                        midambles = 0
                        for index in range(count):
                            offsets.append(int(clock*20))
                            clock += symbol
                            if period and (index+1)%period==0 and count-index-1>=2:
                                clock += training
                                midambles += 1
                        data_end = int(clock*20)
                        for pe in [0,4,8,12,16]:
                            end = clock+pe
                            rounded = 4*ceil((end-20)/4)
                            length = 3*ceil((end-20)/4)-5+er
                            if length>4095: continue
                            ambiguity = int(pe+rounded-(end-20)>=symbol)
                            digest = hashlib.sha256(b''.join(v.to_bytes(4,'little') for v in offsets)).hexdigest()
                            row = [sts,size,gi,period,stbc,count,pe*20,length,ambiguity,nltf,
                                   midambles,start,data_end,int(end*20),int((rounded+20)*20),digest]
                            rows.append('\t'.join(map(str,row)))
    return '\n'.join(rows)+'\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--er',action='store_true')
    args = parser.parse_args()
    content = generate(args.er)
    output = OUT.with_name('he-er-timing-index.tsv') if args.er else OUT
    if args.check:
        assert output.read_text()==content,'HE forward timeline differs'
    else:
        output.write_text(content)
    print(f'{len(content.splitlines())-1} independent HE {"ER SU" if args.er else "SU"} timing cases')
