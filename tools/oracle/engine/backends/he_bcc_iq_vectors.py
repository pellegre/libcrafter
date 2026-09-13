"""Independent HE20 SU one-stream BCC IQ, IEEE802.11ax-2021 27.3.

Complete PHY waveforms with synthetic PSDUs, not MAC aggregate qualification.
Direct IDFT, source training and independently encoded payload; no receiver use.
"""
import argparse
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


def waveform(mcs,size,guard,case,invalid=None,long=False):
    symbols=137 if long else 5
    padding=mcs%4+1
    cbps=234*BPS[mcs];dbps=DATA[mcs]
    last=cbps if padding==4 else padding*60*BPS[mcs]
    count=(symbols-1)*dbps+(dbps if padding==4 else padding*SHORT[mcs])
    octets,pad=divmod(count-22,8)
    psdu=bytes((n*37+mcs*13+93)%256 for n in range(octets))
    service=[0]*16
    if invalid=='service': service[7]=1
    bits=base.scramble(service+base.bits(psdu)+[n%2 for n in range(pad)],93)+[0]*6
    pattern=PUNCTURE[mcs] if mcs<8 else ([1,1,1,0,0,1] if mcs==8 else [1,1,1,0,0,1,1,0,0,1])
    coded=[b for i,b in enumerate(base.encode(bits)) if pattern[i%len(pattern)]]
    coded += [n%2 for n in range(cbps-last)]
    assert len(coded)==symbols*cbps
    preamble=720+size*64+guard
    data_end=preamble+symbols*(256+guard)
    pe=80*(mcs%5)
    rounded=80*math.ceil((data_end+pe-400)/80)
    length=3*(rounded//80)-5
    header=[0]*52
    for i in (0,14,34,40):header[i]=1
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
    stf=[0j]*245
    for k,v in zip(range(-112,113,16),[-1,-1,-1,1,1,1,-1,1,1,1,-1,1,1,-1,1]):
        if k:stf[k+122]=v*(1+1j)/math.sqrt(2)
    wave += [v*4*math.sqrt(52/14) for v in training.ifft(stf)][:80]
    seq={1:training.LTF1,2:training.LTF2,4:training.LTF4}[size]
    active=len(seq)-seq.count('0')
    ltf=[v*4*math.sqrt(52/active) for v in training.ifft([{'-':-1,'+':1,'0':0}[v] for v in seq])][:size*64]
    wave+=ltf[-guard:]+ltf
    assert len(wave)==37+preamble
    polarities=[1-2*b for b in base.scramble([0]*(symbols+4),127)]
    for n in range(symbols):
        block=coded[n*cbps:(n+1)*cbps]
        interleaved=[0]*cbps;s=max(1,BPS[mcs]//2)
        for k,b in enumerate(block):
            i=9*BPS[mcs]*(k%26)+k//26
            j=s*(i//s)+(i+cbps-26*i//cbps)%s
            interleaved[j]=b
        freq=[0j]*245
        for i,k in enumerate(TONES):freq[k+122]=constellation(interleaved[i*BPS[mcs]:(i+1)*BPS[mcs]])
        for i,k in enumerate(PILOTS):freq[k+122]=polarities[n+4]*[1,1,1,-1,-1,1,1,1][(n+i)%8]
        time=[v*4*math.sqrt(52/242) for v in training.ifft(freq)]
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
    samples=[sum(h*wave[n-d] for d,h in taps if n>=d)*cmath.exp(1j*(phase+cfo*n)) for n in range(len(wave))]
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
