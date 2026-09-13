"""Independent HE20 SU one-stream BCC IQ, IEEE802.11ax-2021 27.3.

Default corpus uses synthetic PSDUs, not MAC aggregate qualification. The
optional aligned payload input supports the separate complete MAC corpus.
Direct IDFT, source training and independently encoded payload; no receiver use.
"""
import argparse
import bisect
import cmath
import hashlib
import math
from pathlib import Path
import tempfile
import ofdm_vectors as base
import he_signal_vectors as he
from he_prefix_iq_vectors import symbol
import he_training_vectors as training
from he_capacity_vectors import BPS,DATA,SHORT
from ht_bcc_vectors import PUNCTURE
from vht_bcc_iq_vectors import constellation

PILOTS=[-116,-90,-48,-22,22,48,90,116]
TONES=[k for k in training.TONES if k not in PILOTS]


def waveform(mcs,size,guard,case,invalid=None,long=False,payload=None,ldpc=False,initial_padding=None,
             midamble_period=None,initial_symbols=None,dcm=False,er=False,upper106=False):
    if er: assert mcs in (0,1,2)
    if upper106: assert er and mcs==0
    ru=106 if upper106 else 242
    pilots=[22,48,90,116] if upper106 else PILOTS
    tones=[k for k in range(17,123) if k not in pilots] if upper106 else TONES
    short_tones=24 if upper106 else 60
    symbols=137 if long else 5
    if initial_symbols is not None: symbols=initial_symbols
    padding=mcs%4+1
    if initial_padding is not None: padding=initial_padding
    if dcm: assert mcs in (0,1,3,4) and (size,guard)!=(4,16)
    nsd=len(tones)//(1+dcm)
    cbps=nsd*BPS[mcs];dbps=(51 if upper106 else DATA[mcs])//(1+dcm)
    short=(12 if upper106 else SHORT[mcs])//(1+dcm)
    last=cbps if padding==4 else padding*(short_tones//(1+dcm))*BPS[mcs]
    if payload is not None:
        assert len(payload)%4==0
        while ((symbols-1)*dbps+(dbps if padding==4 else padding*short)-(16 if ldpc else 22))//8 < len(payload):
            symbols+=1
    count=(symbols-1)*dbps+(dbps if padding==4 else padding*short)
    octets,pad=divmod(count-(16 if ldpc else 22),8)
    psdu=bytes((n*37+mcs*13+93)%256 for n in range(octets))
    if payload is not None:
        from vht_ampdu_vectors import delimiter
        remaining=octets-len(payload)
        # HE MAC padding fills whole PSDU octets before PHY padding/tail.
        psdu=payload+delimiter(0,1)*(remaining//4)+b'\xa5'*(remaining%4)
    service=[0]*16
    if invalid=='service': service[7]=1
    bits=base.scramble(service+base.bits(psdu)+[n%2 for n in range(pad)],93)
    extra=0
    if ldpc:
        from he_ldpc_rate_vectors import layout, encode_information
        sizing=layout(mcs,1,int(dcm),1,symbols,padding,106 if upper106 else None)
        coded=encode_information(bits,sizing,mcs)
        symbols,padding,extra=sizing[:3]
        last=cbps if padding==4 else padding*(short_tones//(1+dcm))*BPS[mcs]
    else:
        pattern=PUNCTURE[mcs] if mcs<8 else ([1,1,1,0,0,1] if mcs==8 else [1,1,1,0,0,1,1,0,0,1])
        coded=[b for i,b in enumerate(base.encode(bits+[0]*6)) if pattern[i%len(pattern)]]
        if dcm and mcs==0:
            with_filler=[]
            stride=2*dbps
            for start in range(0,len(coded),stride):
                block=coded[start:start+stride]
                with_filler+=block
                if len(block)==stride:with_filler.append((start//stride)%2)
            coded=with_filler
    coded += [n%2 for n in range(cbps-last)]
    assert len(coded)==symbols*cbps
    preamble=720+160*er+size*64+guard
    insertions=[n for n in range(1,symbols-1) if midamble_period and n%midamble_period==0]
    data_end=preamble+symbols*(256+guard)+len(insertions)*(size*64+guard)
    pe=80*(mcs%5)
    rounded=80*math.ceil((data_end+pe-400)/80)
    length=3*(rounded//80)-5+er
    header=[0]*52
    header[19]=int(upper106)
    for i in (0,14,34,40):header[i]=1
    if ldpc:header[33]=1;header[34]=extra
    if dcm:header[7]=1
    if midamble_period:
        assert midamble_period in (10,20)
        header[41]=1;header[25]=int(midamble_period==20)
    header[3:7]=[(mcs>>i)&1 for i in range(4)]
    code={(1,16):0,(2,16):1,(2,32):2,(4,64):3,(4,16):3}[size,guard]
    header[21:23]=[code&1,code>>1]
    if (size,guard)==(4,16):header[7]=header[35]=1
    header[37:39]=[padding%4&1,padding%4>>1]
    header[39]=int(400+rounded-data_end>=256+guard)
    if invalid=='ldpc':header[33]=1
    if invalid=='dcm':header[7]=1
    if invalid=='stbc':header[35]=header[23]=1
    if invalid=='midamble':header[41]=1
    crc=he.checksum(header[:42]);header[42:46]=[(crc>>i)&1 for i in (3,2,1,0)]
    encoded=he.encoded(header)
    legacy=base.interleave(base.encode(base.signal('1101',length)),1)
    wave=[0j]*37+[v*math.sqrt(52/56) for v in base.preamble()]
    wave+=symbol(legacy,legacy=True)*2+symbol(encoded[:52])+symbol(encoded[52:])
    if er:
        from he_er_prefix_vectors import prefix_wave
        wave=prefix_wave(header,length)
    boost=math.sqrt(2) if er else 1
    stf=[0j]*245
    for k,v in zip(range(-112,113,16),[-1,-1,-1,1,1,1,-1,1,1,1,-1,1,1,-1,1]):
        if k and (not upper106 or k>=17):stf[k+122]=v*(1+1j)/math.sqrt(2)
    wave += [v*4*math.sqrt(52/(6 if upper106 else 14))*boost for v in training.ifft(stf)][:80]
    seq={1:training.LTF1,2:training.LTF2,4:training.LTF4}[size]
    active=ru*size/4  # Equation27-5, not the populated-tone count.
    ltf=[v*4*math.sqrt(52/active)*boost for v in training.ifft([{'-':-1,'+':1,'0':0}[v] if not upper106 or k>=17 else 0 for k,v in zip(range(-122,123),seq)])][:size*64]
    wave+=ltf[-guard:]+ltf
    assert len(wave)==37+preamble
    pilot_offset=6 if er else 4
    polarities=[1-2*b for b in base.scramble([0]*(symbols+pilot_offset),127)]
    refresh=[]
    for n in range(symbols):
        if n in insertions:
            refresh.append(len(wave))
            wave+=ltf[-guard:]+ltf
        block=coded[n*cbps:(n+1)*cbps]
        interleaved=[0]*cbps;s=max(1,BPS[mcs]//2)
        if ldpc:
            distance=(3 if dcm else 6) if upper106 else 9
            columns=nsd//distance
            grid=[list(range(r*columns,(r+1)*columns)) for r in range(distance)]
            source_order=[grid[r][col] for col in range(columns) for r in range(distance)]
            for tone,k in enumerate(source_order):
                interleaved[tone*BPS[mcs]:(tone+1)*BPS[mcs]]=block[k*BPS[mcs]:(k+1)*BPS[mcs]]
        else:
            columns=17 if upper106 else 13 if dcm else 26
            for k,b in enumerate(block):
                i=(cbps//columns)*(k%columns)+k//columns
                j=s*(i//s)+(i+cbps-columns*i//cbps)%s
                interleaved[j]=b
        freq=[0j]*245
        for i,k in enumerate(tones[:nsd]):
            label=interleaved[i*BPS[mcs]:(i+1)*BPS[mcs]]
            if len(label)==10:
                from he_demapping_vectors import AXIS
                lookup={b:v for v,b in AXIS};b=''.join(map(str,label))
                freq[k+122]=complex(lookup[b[:5]],lookup[b[5:]])/math.sqrt(682)
            else:freq[k+122]=constellation(label)
            if dcm:
                logical=source_order[i] if ldpc else i
                if BPS[mcs]==1:upper=freq[k+122]*(-1 if (logical+nsd)%2 else 1)
                elif BPS[mcs]==2:upper=freq[k+122].conjugate()
                else:upper=constellation([label[1],label[0],label[3],label[2]])
                freq[tones[i+nsd]+122]=upper
        signs=[1,1,1,-1] if upper106 else [1,1,1,-1,-1,1,1,1]
        for i,k in enumerate(pilots):freq[k+122]=polarities[n+pilot_offset]*signs[(n+i)%len(signs)]
        time=[v*4*math.sqrt(52/ru) for v in training.ifft(freq)]
        wave+=time[-guard:]+time
    assert len(wave)==37+data_end
    if invalid=='truncated':wave=wave[:-1]
    elif pe:
        # 27.3.13: arbitrary extension content, same average power as DATA.
        extension=(time*2)[:pe]
        power=sum(abs(v)**2 for v in time)/len(time)
        pe_power=sum(abs(v)**2 for v in extension)/pe
        wave += [v*math.sqrt(power/pe_power) for v in extension]
    taps=[(0,1+0j)]
    if case=='offset':taps +=[(3,.25j)]
    if case=='selective':taps +=[(5,.35+.2j),(11,-.2j)]
    cfo=0 if case=='flat' else .018
    phase=0 if case=='flat' else .7
    if case=='changing':
        channels=[[(0,1+0j),(5,.35+.2j),(11,-.2j)],
                  [(0,.65+.2j),(7,.3-.1j),(11,.15j)],
                  [(0,1.1-.1j),(3,-.2+.1j)]]
        samples=[sum(h*wave[n-d] for d,h in channels[bisect.bisect_right(refresh,n)%3] if n>=d)
                 *cmath.exp(1j*(phase+cfo*n)) for n in range(len(wave))]
    else:
        samples=[sum(h*wave[n-d] for d,h in taps if n>=d)*cmath.exp(1j*(phase+cfo*n)) for n in range(len(wave))]
    if invalid=='erased-midamble':
        start=refresh[0];samples[start:start+size*64+guard]=[0j]*(size*64+guard)
    if invalid=='truncated-midamble':samples=samples[:refresh[0]+size*64+guard-1]
    gain=min(200,math.floor(120/max(max(abs(v.real),abs(v.imag)) for v in samples)))
    assert all(max(abs(v.real),abs(v.imag))*gain<127 for v in samples)
    return base.quantize(samples,scale=gain),[mcs,size,guard,padding,symbols,psdu.hex(),cfo,
        ';'.join(f'{d}:{h.real}:{h.imag}' for d,h in taps),gain,37+preamble,37+data_end]


def generate(out):
    base.self_check()
    rows=['name\tmcs\tltf\tguard\tpadding\tsymbols\tpsdu\tcfo\ttaps\tgain\tdata_start\tdata_end\tsha256']
    for mcs in range(10):
        for size,guard in ((1,16),(2,16),(2,32),(4,16),(4,64)):
            for case in ('flat','offset','selective'):
                name=f'he-bcc-iq-mcs{mcs}-ltf{size}-gi{guard*50}-{case}'
                iq,fields=waveform(mcs,size,guard,case)
                (out/f'{name}.cs8').write_bytes(iq)
                rows.append('\t'.join(map(str,[name,*fields,hashlib.sha256(iq).hexdigest()])))
    name='he-bcc-iq-long-pilots'
    iq,fields=waveform(0,4,64,'offset',long=True)
    (out/f'{name}.cs8').write_bytes(iq)
    rows.append('\t'.join(map(str,[name,*fields,hashlib.sha256(iq).hexdigest()])))
    (out/'he-bcc-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    rows=['name\treason\tsha256']
    for reason in ('ldpc','dcm','stbc','midamble','service','truncated'):
        name=f'he-bcc-iq-invalid-{reason}'
        iq,_=waveform(0,4,64,'flat',reason)
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append(f'{name}\t{reason}\t{hashlib.sha256(iq).hexdigest()}')
    (out/'he-bcc-iq-invalid-index.tsv').write_text('\n'.join(rows)+'\n')
    print('151 HE BCC IQ cases and6 negative cases')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-bcc-iq-') as temporary:
            out=Path(temporary);generate(out)
            for file in out.iterdir():assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:generate(base.OUT)
