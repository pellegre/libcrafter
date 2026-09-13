"""Independent HE20 MU single-stream RU PSDU waveforms, ax-2021 27.3.

Legacy acquisition, SIG-A/B, STF/LTF and BCC/LDPC DATA. Synthetic PSDUs are
not MAC frames. Forward encoding and direct inverse DFT, no receiver imports.
"""
import argparse
import cmath
from fractions import Fraction as F
import hashlib
import math
from pathlib import Path
import tempfile
import ofdm_vectors as base
import ht_bcc_vectors as ht
import he_training_vectors as training
from he_prefix_iq_vectors import symbol
from he_signal_vectors import encoded
from he_mu_signal_vectors import put, repair
from he_sig_b_common_vectors import allocation
from he_sig_b_coded_vectors import checked, encode
from he_sig_b_modulation_vectors import modulate
from he_ru_symbol_vectors import geometry, point
from he_capacity_vectors import BPS
from he_ldpc_rate_vectors import layout, encode_information, damage_codeword, RATES


def waveform(code,mcs,ldpc,dcm,size,guard,impaired=False,nltf=1,period=0,damage='none',mac_payloads=None,
             compressed=False,sig_b_mcs=0,sig_b_dcm=False):
    assert not compressed or code==192
    assert sig_b_mcs in range(6) and (not sig_b_dcm or sig_b_mcs in (0,1,3,4))
    geom={(ru,index):(data,pilots) for ru,index,data,pilots in geometry()}
    rus=[]
    for item in allocation(code)[1].split(','):
        ru,slot,users=map(int,item.split(':')); assert users==1
        index=slot if ru==26 else ({1:1,3:2,6:3,8:4}[slot] if ru==52 else (1 if slot==1 else 2) if ru==106 else 1)
        data,pilots=geom[ru,index]; rus.append((ru,data,pilots))
    initial=22 if period else 5
    padding=3
    if mac_payloads is not None:
        assert len(mac_payloads)==len(rus)
        def budget(ru,data):
            cbps=len(data)*BPS[mcs]//(1+dcm)
            short=(2 if ru==26 and dcm else {26:6,52:12,106:24,242:60}[ru]//(1+dcm))*BPS[mcs]
            return ((initial-1)*int(cbps*RATES[mcs])+padding*int(short*RATES[mcs])-(16 if ldpc else 22))//8
        while any(budget(ru,data)<len(payload) for (ru,data,_),payload in zip(rus,mac_payloads)):
            initial+=1
        assert initial<=400
    extra=ldpc and any(layout(mcs,1,dcm,1,initial,padding,mu_tones=ru)[2] for ru,_,_ in rus)
    final_padding=4 if extra else padding
    symbols=initial
    payloads=[]; streams=[]
    for user,(ru,data,pilots) in enumerate(rus):
        cbps=len(data)*BPS[mcs]//(1+dcm)
        short=(2 if ru==26 and dcm else {26:6,52:12,106:24,242:60}[ru]//(1+dcm))*BPS[mcs]
        rate=RATES[mcs]
        sizing=layout(mcs,1,dcm,1,initial,padding,mu_tones=ru,force_extra=extra) if ldpc else None
        count=sizing[8] if ldpc else (initial-1)*int(cbps*rate)+padding*int(short*rate)
        octets,phy=divmod(count-(16 if ldpc else 22),8)
        assert octets>=0
        psdu=bytes((n*37+user*11+93+mcs*13)%256 for n in range(octets))
        if mac_payloads is not None:
            from vht_ampdu_vectors import delimiter
            remaining=octets-len(mac_payloads[user])
            psdu=mac_payloads[user]+delimiter(0,1)*(remaining//4)+b'\xa5'*(remaining%4)
        payloads.append(psdu.hex())
        service=[0]*16
        if damage=='service' and user==0:service[7]=1
        scrambled=base.scramble(service+base.bits(psdu)+[n%2 for n in range(phy)],93)
        if ldpc:
            coded=encode_information(scrambled,sizing,mcs)
            if damage=='ldpc' and user==0:coded=damage_codeword(coded,sizing,sizing[3]-1)
            coded=list(map(int,coded))
        else:
            pattern=ht.PUNCTURE[mcs] if mcs<8 else ([1,1,1,0,0,1] if mcs==8 else [1,1,1,0,0,1,1,0,0,1])
            coded=[b for i,b in enumerate(base.encode(scrambled+[0]*6)) if pattern[i%len(pattern)]]
            if dcm and mcs==0 and ru in (106,242):
                stride=50 if ru==106 else 116
                filled=[]
                for i in range(0,len(coded),stride):
                    part=coded[i:i+stride];filled+=part
                    if len(part)==stride:filled.append(1)
                coded=filled
        last=cbps if final_padding==4 else final_padding*short
        output=[];cursor=0
        for n in range(symbols):
            keep=last if n==symbols-1 else cbps
            output+=coded[cursor:cursor+keep];cursor+=keep
            output += [(n+j)%2 for j in range(cbps-keep)]
        assert cursor==len(coded)
        streams.append(output)
    # Independent SIG-B block coding; one compressed user uses Table27-28.
    fields=[] if compressed else [checked([code>>i&1 for i in range(8)])]
    values=[37+i | (mcs<<15) | (int(dcm)<<19) | (int(ldpc)<<20) for i in range(len(rus))]
    for start in range(0,len(values),2):fields.append(checked([v>>i&1 for v in values[start:start+2] for i in range(21)]))
    if damage=='user-crc':fields[int(not compressed)][-10]^=1
    dbps=[26,52,78,104,156,208][sig_b_mcs]//(1+sig_b_dcm)
    nb=sum(map(len,fields));sigb=math.ceil(nb/dbps)
    pairs=[pair for field in fields for pair in encode(field)] + encode([0]*(sigb*dbps-nb))
    coded=[]
    for n,(a,b) in enumerate(pairs):
        coded.extend([a,b] if sig_b_mcs in (0,1,3) else
            ([a,b],[a],[b])[n%3] if sig_b_mcs in (2,4) else ([a,b] if n%2==0 else [a]))
    training_samples=nltf*(64*size+guard)
    midambles=(symbols-2)//period if period else 0
    end=720+80*sigb+training_samples+symbols*(256+guard)+midambles*training_samples
    units=math.ceil(F(end-400,80));length=3*units-4
    header=[0]*52
    for start,width,value in [(1,3,sig_b_mcs),(4,1,int(sig_b_dcm)),(5,6,37),(18,4,0 if compressed else min(sigb-1,15)),(22,1,int(compressed)),(23,2,{(4,16):0,(2,16):1,(2,32):2,(4,64):3}[size,guard]),
        (25,1,int(bool(period))),(33,1,1),(34,3,[1,2,4,6,8].index(nltf)),(37,1,int(extra)),(39,2,final_padding%4)]:put(header,start,width,value)
    if period==20:header[36]=1
    repair(header);siga=encoded(header)
    legacy=base.interleave(base.encode(base.signal('1101',length)),1)
    wave=[0j]*37+[v*math.sqrt(52/56) for v in base.preamble()]
    wave+=symbol(legacy,legacy=True)*2+symbol(siga[:52])+symbol(siga[52:])
    polarities=[1-2*b for b in base.scramble([0]*(4+sigb+symbols),127)]
    points=[complex(*map(float,p.split(','))) for p in modulate(''.join(map(str,coded)),sig_b_mcs,sig_b_dcm).split(';')]
    for n in range(sigb):
        freq=[0j]*57
        for k,v in zip(ht.CARRIERS,points[52*n:52*(n+1)]):freq[k+28]=v/math.sqrt([1,2,2,10,10,42][sig_b_mcs])
        for k,s in [(-21,1),(-7,1),(7,1),(21,-1)]:freq[k+28]=s*polarities[4+n]
        time=[v*math.sqrt(52/56) for v in ht.ifft(freq)];wave+=time[-16:]+time
    total=sum(ru for ru,_,_ in rus)
    stf={k:v*(1+1j)/math.sqrt(2) for k,v in zip(range(-112,113,16),[-1,-1,-1,1,1,1,-1,1,1,1,-1,1,1,-1,1]) if k}
    freq=[0j]*245
    for ru,data,pilots in rus:
        selected=[k for k in data+pilots if k in stf]
        for k in selected:freq[k+122]=stf[k]*math.sqrt(ru/len(selected)/total)
    wave += [v*4*math.sqrt(52) for v in training.ifft(freq)][:80]
    seq={2:training.LTF2,4:training.LTF4}[size]
    active={k for _,d,p in rus for k in d+p}
    ltf=[v*4*math.sqrt(52/(total*size/4)) for v in training.ifft([{'-':-1,'+':1,'0':0}[v] if k in active else 0 for k,v in zip(range(-122,123),seq)])][:64*size]
    signs=([1,-1,1,1,1,-1] if nltf==6 else [1,-1,1,1]*2)[:nltf]
    training_wave=[v*s for s in signs for v in ltf[-guard:]+ltf]
    wave+=training_wave
    for n in range(symbols):
        if period and n and n%period==0 and n//period<=midambles:wave+=training_wave
        freq=[0j]*245
        for (ru,data,pilots),stream in zip(rus,streams):
            count=len(data)//(1+dcm);cbps=count*BPS[mcs]
            bits=stream[n*cbps:(n+1)*cbps];mapped=bits.copy()
            if not ldpc:
                cols={26:8//(1+dcm),52:16//(1+dcm),106:17,242:26//(1+dcm)}[ru];s=max(BPS[mcs]//2,1)
                for k,b in enumerate(bits):
                    i=(cbps//cols)*(k%cols)+k//cols
                    mapped[s*(i//s)+(i+cbps-cols*i//cbps)%s]=b
            distance=({26:1,52:1,106:3,242:9} if dcm else {26:1,52:3,106:6,242:9})[ru]
            targets=[row+col*distance for row in range(distance) for col in range(count//distance)]
            for k in range(count):
                target=targets[k] if ldpc else k;label=mapped[k*BPS[mcs]:(k+1)*BPS[mcs]]
                lower=point(label);freq[data[target]+122]=lower
                if dcm:
                    upper=lower*(-1 if (k+count)%2 else 1) if BPS[mcs]==1 else (lower.conjugate() if BPS[mcs]==2 else point([label[1],label[0],label[3],label[2]]))
                    freq[data[target+count]+122]=upper
            signs={26:[1,-1],52:[1,1,1,-1],106:[1,1,1,-1],242:[1,1,1,-1,-1,1,1,1]}[ru]
            for j,k in enumerate(pilots):freq[k+122]=polarities[4+sigb+n]*signs[(n+j)%len(signs)]
        time=[v*4*math.sqrt(52/total) for v in training.ifft(freq)];wave+=time[-guard:]+time
    assert len(wave)==37+end
    if impaired:wave=[(v+(.25j*wave[n-3] if n>=3 else 0))*cmath.exp(1j*(.7+.018*n)) for n,v in enumerate(wave)]
    gain=min(200,120/max(max(abs(v.real),abs(v.imag)) for v in wave))
    return base.quantize(wave,scale=gain),payloads,symbols


def generate(out):
    rows=['name\tcode\tmcs\tldpc\tdcm\tltf\tguard\tnltf\tperiod\tdamage\tsymbols\tpsdus\tsamples\tsha256']
    cases=[]
    for code in (0,15,128,192):
        for ldpc in (False,True):
            for mcs in range(12 if ldpc else 10):
                for dcm in ([False,True] if mcs in (0,1,3,4) else [False]):
                    size,guard=[(4,16),(2,16),(2,32),(4,64)][mcs%4]
                    for impaired in (False,True):cases.append((code,mcs,ldpc,dcm,size,guard,impaired,1,0,'none'))
    for nltf in (2,4,6,8):cases.append((0,1,False,True,2,16,True,nltf,0,'none'))
    for period in (10,20):
        for ldpc in (False,True):cases.append((15,3,ldpc,True,4,64,True,2,period,'none'))
    for damage in ('service','user-crc'):
        for ldpc in (False,True):cases.append((0,1,ldpc,False,2,32,True,1,0,damage))
    for code,mcs,ldpc,dcm,size,guard,impaired,nltf,period,damage in cases:
        name=f'he-mu-data-a{code}-m{mcs}-l{int(ldpc)}-d{int(dcm)}-g{guard}-i{int(impaired)}-n{nltf}-p{period}-{damage}'
        iq,psdus,symbols=waveform(code,mcs,ldpc,dcm,size,guard,impaired,nltf,period,damage)
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append('\t'.join(map(str,[name,code,mcs,int(ldpc),int(dcm),size,guard,nltf,period,damage,symbols,','.join(psdus),len(iq)//2,hashlib.sha256(iq).hexdigest()])))
    (out/'he-mu-data-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent HE MU DATA IQ waveforms')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-mu-data-') as temporary:
            out=Path(temporary);generate(out)
            for path in out.iterdir():assert path.read_bytes()==(base.OUT/path.name).read_bytes(),path.name
    else:generate(base.OUT)
