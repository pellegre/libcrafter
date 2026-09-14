"""Independent one-stream HE20 RU DATA symbols; ax-2021 27.3.12.8-10/13.

Forward interleaving/tone mapping and inverse DFT, no Rust implementation.
Floating-point IQ with a known channel, not complete packets or RF evidence.
"""
import argparse
import cmath
import math
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
import random
from tools.oracle.engine.backends.wifi.he.training import ifft
from tools.oracle.engine.backends.wifi.he.demapping import AXIS
from tools.oracle.engine.backends.wifi.vht.bcc.iq import constellation as lower_constellation

OUT = IQ_FIXTURES / 'he-ru-symbol.tsv'


def geometry():
    spans = {26:[(-121,-96),(-95,-70),(-68,-43),(-42,-17),None,(17,42),(43,68),(70,95),(96,121)],
             52:[(-121,-70),(-68,-17),(17,68),(70,121)],106:[(-122,-17),(17,122)],242:[None]}
    pilots = {26:[[-116,-102],[-90,-76],[-62,-48],[-36,-22],[-10,10],[22,36],[48,62],[76,90],[102,116]],
              52:[[-116,-102,-90,-76],[-62,-48,-36,-22],[22,36,48,62],[76,90,102,116]],
              106:[[-116,-90,-48,-22],[22,48,90,116]],242:[[-116,-90,-48,-22,22,48,90,116]]}
    for ru, ranges in spans.items():
        for index, span in enumerate(ranges, 1):
            active = list(range(span[0],span[1]+1)) if span else (list(range(-16,-3))+list(range(4,17)) if ru==26 else list(range(-122,-1))+list(range(2,123)))
            p = pilots[ru][index-1]
            yield ru,index,[k for k in active if k not in p],p


def point(bits):
    if len(bits)<10:return lower_constellation(bits)
    lookup={label:value for value,label in AXIS}
    label=''.join(map(str,bits))
    return complex(lookup[label[:5]],lookup[label[5:]])/math.sqrt(682)


def generate():
    rows=['ru\tindex\tbps\tldpc\tdcm\tcase\tsymbol\tpolarity\telapsed\tcfo\tbits\twave']
    rng=random.Random(7319)
    for ru,index,data,pilots in geometry():
        for ldpc in (False,True):
            for bps in ((1,2,4,6,8,10) if ldpc else (1,2,4,6,8)):
                for dcm in ((False,True) if bps<=4 else (False,)):
                    count=len(data)//(1+dcm)
                    bits=[rng.randrange(2) for _ in range(count*bps)]
                    mapped=bits.copy()
                    if not ldpc:
                        cols={26:8//(1+dcm),52:16//(1+dcm),106:17,242:26//(1+dcm)}[ru]
                        # Row/column transpose followed by alternating bit significance.
                        transpose=[row+col*(len(bits)//cols) for row in range(len(bits)//cols) for col in range(cols)]
                        s=max(bps//2,1)
                        for k,i in enumerate(transpose):
                            j=s*(i//s)+(i+len(bits)-cols*i//len(bits))%s
                            mapped[j]=bits[k]
                    freq=[0j]*245
                    distance=({26:1,52:1,106:3,242:9} if dcm else {26:1,52:3,106:6,242:9})[ru]
                    permutation=[row+col*distance for row in range(distance) for col in range(count//distance)]
                    for k in range(count):
                        label=mapped[k*bps:(k+1)*bps]
                        target=permutation[k] if ldpc else k
                        freq[data[target]+122]=point(label)
                        if dcm:
                            upper=point(label)*(-1 if (k+count)%2 else 1) if bps==1 else (point(label).conjugate() if bps==2 else point([label[1],label[0],label[3],label[2]]))
                            freq[data[target+count]+122]=upper
                    for case in range(3 if dcm else 2):
                        symbol=(index*3+bps+case)%17
                        polarity=-1 if (index+case)%2 else 1
                        elapsed=1137
                        cfo=.018 if case else 0.
                        f=freq.copy()
                        signs={26:[1,-1],52:[1,1,1,-1],106:[1,1,1,-1],242:[1,1,1,-1,-1,1,1,1]}[ru]
                        for j,k in enumerate(pilots):f[k+122]=polarity*signs[(symbol+j)%len(signs)]
                        for k in data+pilots:
                            h=1+.25j*cmath.exp(-2j*math.pi*k*3/256) if case else 1
                            if case==2 and k in data[:count]:h=0
                            f[k+122]*=h*cmath.exp(1j*(.7+.004*k)) if case else h
                        wave=[v*cmath.exp(1j*cfo*(elapsed+n)) for n,v in enumerate(ifft(f))]
                        rows.append('\t'.join(map(str,[ru,index,bps,int(ldpc),int(dcm),case,symbol,polarity,elapsed,cfo,
                            ''.join(map(str,bits)),','.join(format(x,'.10g') for v in wave for x in (v.real,v.imag))])))
    return '\n'.join(rows)+'\n'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    content=generate()
    if args.check:assert OUT.read_text()==content
    else:OUT.write_text(content)
    print(f'{len(content.splitlines())-1} independent HE RU DATA symbols')
