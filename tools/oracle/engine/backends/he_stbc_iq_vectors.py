"""Independent HE20 SU STBC IQ, IEEE802.11ax-2021 27.3.11.10/12.12.

Two source-mapped transmit branches, including the second STS cyclic shift,
are summed into ONE receive chain. Direct IDFT; no production decoder use.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile
import ofdm_vectors as base
import he_signal_vectors as he
import he_training_vectors as training
from he_prefix_iq_vectors import symbol
from he_capacity_vectors import BPS, DATA, SHORT
from he_bcc_iq_vectors import PILOTS, TONES
from he_dcm_iq_vectors import payload
from ht_bcc_vectors import PUNCTURE
from vht_bcc_iq_vectors import constellation
from vht_ampdu_vectors import delimiter


def waveform(mcs, size, guard, ldpc, padding, case, period=None, invalid=None, er=False, upper106=False):
    if er: assert mcs in (0,1,2)
    if upper106: assert er and mcs==0
    ru=106 if upper106 else 242
    pilots=[22,48,90,116] if upper106 else PILOTS
    tones=[k for k in range(17,123) if k not in pilots] if upper106 else TONES
    columns=17 if upper106 else 26
    distance=6 if upper106 else 9
    assert (size, guard) in ((1,16),(2,16),(2,32),(4,64))
    nsym=42 if period==20 else 22 if period else 4
    wire,frames=payload(padding==4)
    dbps=51 if upper106 else DATA[mcs]; cbps=len(tones)*BPS[mcs]
    last_data=dbps if padding==4 else padding*(12 if upper106 else SHORT[mcs])
    while ((nsym-2)*dbps+2*last_data-(16 if ldpc else 22))//8 < len(wire): nsym+=2
    octets,pad=divmod((nsym-2)*dbps+2*last_data-(16 if ldpc else 22),8)
    remaining=octets-len(wire)
    psdu=wire+delimiter(0,1)*(remaining//4)+b'\xa5'*(remaining%4)
    service=[0]*16
    if invalid=='service':service[7]=1
    bits=base.scramble(service+base.bits(psdu)+[n%2 for n in range(pad)],93)
    extra=0
    if ldpc:
        from he_ldpc_rate_vectors import layout,encode_information
        sizing=layout(mcs,1,0,2,nsym,padding,106 if upper106 else None)
        coded=encode_information(bits,sizing,mcs)
        nsym,padding,extra=sizing[:3]
    else:
        pattern=PUNCTURE[mcs] if mcs<8 else ([1,1,1,0,0,1] if mcs==8 else [1,1,1,0,0,1,1,0,0,1])
        coded=[v for i,v in enumerate(base.encode(bits+[0]*6)) if pattern[i%len(pattern)]]
    last=cbps if padding==4 else padding*(24 if upper106 else 60)*BPS[mcs]
    split=(nsym-2)*cbps
    coded=coded[:split]+coded[split:split+last]+[i%2 for i in range(cbps-last)]+coded[split+last:]+[i%2 for i in range(cbps-last)]
    assert len(coded)==nsym*cbps and nsym%2==0
    training_span=2*(size*64+guard)
    insertions=[n for n in range(1,nsym-1) if period and n%period==0]
    data_start=720+160*er+training_span
    data_end=data_start+nsym*(256+guard)+len(insertions)*training_span
    pe=80*(mcs%5)
    rounded=80*math.ceil((data_end+pe-400)/80)
    length=3*(rounded//80)-5+er
    header=[0]*52
    header[19]=int(upper106)
    for i in (0,1,14,23,34,35,40):header[i]=1
    header[3:7]=[(mcs>>i)&1 for i in range(4)]
    header[33]=int(ldpc);header[34]=extra if ldpc else 1
    code={(1,16):0,(2,16):1,(2,32):2,(4,64):3}[size,guard]
    header[21:23]=[code&1,code>>1]
    header[37:39]=[padding%4&1,padding%4>>1]
    header[39]=int(400+rounded-data_end>=256+guard)
    if period:header[41]=1;header[25]=int(period==20)
    crc=he.checksum(header[:42]);header[42:46]=[(crc>>i)&1 for i in (3,2,1,0)]
    encoded=he.encoded(header)
    legacy=base.interleave(base.encode(base.signal('1101',length)),1)
    wave=[0j]*37+[v*math.sqrt(52/56) for v in base.preamble()]
    wave+=symbol(legacy,legacy=True)*2+symbol(encoded[:52])+symbol(encoded[52:])
    if er:
        from he_er_prefix_vectors import prefix_wave
        wave=prefix_wave(header,length)
    boost=math.sqrt(2) if er else 1

    def channels(k, epoch):
        taps=[[(0,1+0j)],[(0,.4+.3j)]]
        if case!='flat':taps=[[(0,.85+.1j),(5,.2-.1j)],[(0,.45-.2j),(7,-.15j)]]
        if case=='first-null':taps=[[],[(0,1+0j),(5,.2j)]]
        if case=='second-null':taps=[[(0,1+0j),(5,.2j)],[]]
        if case=='changing' and epoch%3==1:taps=[[(0,.7-.2j),(3,.2j)],[(0,.25+.4j),(6,.1)]]
        if case=='changing' and epoch%3==2:taps=[[(0,1-.1j),(7,-.1j)],[(0,-.2+.35j),(4,.15)]]
        return [sum(h*cmath.exp(-2j*math.pi*k*(d-8*branch)/256) for d,h in path)/math.sqrt(2)
                for branch,path in enumerate(taps)]

    def emit(freq, active, useful, epoch):
        mixed=[]
        for k,(x,y) in zip(range(-122,123),freq):
            a,b=channels(k,epoch);mixed.append(a*x+b*y)
        return [v*4*math.sqrt(52/active) for v in training.ifft(mixed)][:useful]

    stf=[(0j,0j)]*245
    for k,v in zip(range(-112,113,16),[-1,-1,-1,1,1,1,-1,1,1,1,-1,1,1,-1,1]):
        if k and (not upper106 or k>=17):stf[k+122]=(v*(1+1j)/math.sqrt(2),)*2
    wave += [v*boost for v in emit(stf,6 if upper106 else 14,80,0)]
    sequence={1:training.LTF1,2:training.LTF2,4:training.LTF4}[size]
    active=ru*size/4  # Equation27-5, not the populated-tone count.

    def ltf_field(epoch):
        field=[]
        for col in range(2):
            freq=[]
            for k,sign in zip(range(-122,123),sequence):
                v={'-':-1,'+':1,'0':0}[sign]
                if upper106 and k<17:v=0
                # P rows: [1,-1], [1,1]; R repeats row1 on pilots.
                freq.append((v*(-1 if col else 1),v*(-1 if col and k in pilots else 1)))
            time=[v*boost for v in emit(freq,active,size*64,epoch)]
            field+=time[-guard:]+time
        return field

    wave+=ltf_field(0)
    assert len(wave)==37+data_start
    constellations=[]
    for n in range(nsym):
        block=coded[n*cbps:(n+1)*cbps];interleaved=[0]*cbps;s=max(1,BPS[mcs]//2)
        if ldpc:
            grid=[list(range(r*columns,(r+1)*columns)) for r in range(distance)]
            for tone,k in enumerate([grid[r][col] for col in range(columns) for r in range(distance)]):
                interleaved[tone*BPS[mcs]:(tone+1)*BPS[mcs]]=block[k*BPS[mcs]:(k+1)*BPS[mcs]]
        else:
            for k,b in enumerate(block):
                i=distance*BPS[mcs]*(k%columns)+k//columns
                j=s*(i//s)+(i+cbps-columns*i//cbps)%s
                interleaved[j]=b
        freq={}
        for i,k in enumerate(tones):
            label=interleaved[i*BPS[mcs]:(i+1)*BPS[mcs]]
            if len(label)==10:
                from he_demapping_vectors import AXIS
                lookup={b:v for v,b in AXIS};b=''.join(map(str,label))
                freq[k]=complex(lookup[b[:5]],lookup[b[5:]])/math.sqrt(682)
            else:freq[k]=constellation(label)
        constellations.append(freq)
    pilot_offset=6 if er else 4
    polarities=[1-2*b for b in base.scramble([0]*(nsym+pilot_offset),127)]
    refresh=[];epoch=0
    for n in range(nsym):
        if n in insertions:
            epoch+=1;refresh.append(len(wave));wave+=ltf_field(epoch)
        freq=[(0j,0j)]*245
        for k in tones:
            x=constellations[n][k]
            y=constellations[n-1 if n%2 else n+1][k].conjugate()*(1 if n%2 else -1)
            freq[k+122]=(x,y)
        signs=[1,1,1,-1] if upper106 else [1,1,1,-1,-1,1,1,1]
        for j,k in enumerate(pilots):
            freq[k+122]=(polarities[n+pilot_offset]*signs[(n+j)%len(signs)],)*2
        time=emit(freq,ru,256,epoch)
        wave+=time[-guard:]+time
    assert len(wave)==37+data_end
    if invalid=='truncated':wave=wave[:-1]
    elif pe:
        extension=(time*2)[:pe]
        power=sum(abs(v)**2 for v in time)/len(time)
        pe_power=sum(abs(v)**2 for v in extension)/pe
        wave += [v*math.sqrt(power/pe_power) for v in extension]
    if invalid=='erased-training':
        start=data_start+37-training_span;wave[start:start+training_span]=[0j]*training_span
    if invalid=='truncated-midamble':wave=wave[:refresh[0]+training_span-1]
    cfo=0 if case=='flat' else .018
    samples=[v*cmath.exp(1j*(.7+cfo*n)) for n,v in enumerate(wave)]
    gain=min(220,math.floor(120/max(max(abs(v.real),abs(v.imag)) for v in samples)))
    return base.quantize(samples,scale=gain),psdu,frames,data_start+37,data_end+37


def generate(out):
    rows=['name\tmcs\tldpc\tltf\tguard\tperiod\tpsdu\tframes\tbad_fcs\tdata_start\tdata_end\tsha256']
    invalid_rows=['name\tsha256']
    for ldpc in (False,True):
        for mcs in range(12 if ldpc else 10):
            for size,guard in ((1,16),(2,16),(2,32),(4,64)):
                cases=[(1,'flat',None),(2,'selective',None),(3,'changing',10),(4,'changing',20)]
                if mcs==(11 if ldpc else 0):cases +=[(2,'first-null',None),(2,'second-null',None)]
                for padding,case,period in cases:
                    name=f'he-stbc-iq-mcs{mcs}-{"ldpc" if ldpc else "bcc"}-ltf{size}-gi{guard*50}-pad{padding}-{case}'
                    iq,psdu,frames,start,end=waveform(mcs,size,guard,ldpc,padding,case,period)
                    (out/f'{name}.cs8').write_bytes(iq)
                    rows.append('\t'.join(map(str,[name,mcs,int(ldpc),size,guard,period or 0,psdu.hex(),
                        ','.join(v.hex() for v in frames),int(padding==4),start,end,hashlib.sha256(iq).hexdigest()])))
        for error in ('service','truncated','erased-training','truncated-midamble'):
            name=f'he-stbc-iq-invalid-{"ldpc" if ldpc else "bcc"}-{error}'
            iq,*_=waveform(0,4,64,ldpc,2,'selective',10,error)
            (out/f'{name}.cs8').write_bytes(iq)
            invalid_rows.append(f'{name}\t{hashlib.sha256(iq).hexdigest()}')
    (out/'he-stbc-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    (out/'he-stbc-iq-invalid-index.tsv').write_text('\n'.join(invalid_rows)+'\n')
    print(f'{len(rows)-1} independent HE STBC waveforms; {len(invalid_rows)-1} invalid cases')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-stbc-iq-') as temporary:
            out=Path(temporary);generate(out)
            for file in out.iterdir():assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:generate(base.OUT)
