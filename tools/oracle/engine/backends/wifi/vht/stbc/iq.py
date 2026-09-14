"""Independent VHT20 NSS1/NSTS2 RX IQ, IEEE 802.11-2020 clauses10/21.

Two physical transmit-chain models are combined into one simulated receiver.
This is not a production transmitter or a single-antenna STBC transmit claim.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile
import tools.oracle.engine.backends.wifi.ofdm.base as base
import tools.oracle.engine.backends.wifi.ht.bcc as ht
from tools.oracle.engine.backends.wifi.ht.signal import crc
from tools.oracle.engine.backends.wifi.vht.ampdu.frame import aggregate, frame
from tools.oracle.engine.backends.wifi.vht.bcc.iq import PARAMETERS, PUNCTURE, SCALE, delimiter, little, constellation
from tools.oracle.engine.backends.wifi.vht.ldpc.rate import layout, encode_information


def waveform(apep,mcs,guard,ldpc,fault=None):
    nbpsc,ndbps = PARAMETERS[mcs]
    initial = 2*math.ceil((16+8*len(apep)+(0 if ldpc else 6))/(2*ndbps))
    psdu_len,pad = divmod(initial*ndbps-(16 if ldpc else 22),8)
    psdu = bytearray(apep)
    while len(psdu)<psdu_len and len(psdu)%4: psdu.append(0xa5)
    while len(psdu)+4<=psdu_len: psdu.extend(delimiter(0,1))
    psdu.extend(b'\x5a'*(psdu_len-len(psdu)))
    sigb = little((len(apep)+3)//4,17)+[1]*3
    data = [0]*8+crc(sigb)+base.bits(psdu)+[0]*pad
    if fault=='service': data[8]^=1
    if ldpc:
        sizing = layout(initial,mcs,2)
        symbols,extra = sizing[0],sizing[6]
        coded = encode_information(base.scramble(data,93),initial,mcs,2)
        if fault=='codeword':
            _,count,n,short,puncture,repeat,_,_ = sizing
            assert count>2
            size = lambda i: n-(short//count+(i<short%count))-(puncture//count+(i<puncture%count))+(repeat//count+(i<repeat%count))
            start,length = size(0),size(1)
            noise = hashlib.shake_256(b'vht-stbc-unrecoverable-word-1').digest((length+7)//8)
            coded[start:start+length] = base.bits(noise)[:length]
    else:
        symbols,extra = initial,0
        encoded = base.encode(base.scramble(data,93)+[0]*6)
        coded = [b for i,b in enumerate(encoded) if PUNCTURE[mcs][i%len(PUNCTURE[mcs])]]
    assert symbols%2==0 and len(coded)==symbols*52*nbpsc
    siga = little(0,2)+[1,1]+little(63,6)+little(1,12)+[1,1]
    siga += [int(guard==8),0,int(ldpc),extra]+little(mcs,4)+[0,1]
    if fault=='nsts': siga[10:13]=little(2,3)
    if fault=='disambiguation': siga[25]=1
    if fault=='extra': siga[27]^=1
    siga += crc(siga)+[0]*6
    if fault=='header_crc': siga[34]^=1
    sigb += [0]*6
    if fault=='sigb_crc': sigb[0]^=1
    length = 3*(6+math.ceil(symbols*(64+guard)/80))-3
    assert length<=4095
    if fault=='odd_symbols': length+=3
    polarity = [1-2*b for b in base.scramble([0]*(symbols+4),127)]
    chains = [[0j]*37,[0j]*37]

    def field(first,second,prefix,repeat=1,legacy=False):
        for chain,time in enumerate((first,second)):
            advance = (4 if legacy else 8)*chain
            shifted = time[advance:]+time[:advance]
            block = (shifted[-prefix:] if prefix else [])+shifted*repeat
            chains[chain].extend(v/math.sqrt(2) for v in block)

    short = base.preamble()[:16]
    long = base.ifft(base.LTF)
    field(short,short,0,10,True)
    field(long,long,32,2,True)
    signal = base.symbol(base.interleave(base.encode(base.signal('1101',length)),1),1,polarity[0])[16:]
    field(signal,signal,16,legacy=True)
    header = base.encode(siga)
    for symbol in range(2):
        freq = [0j]*53
        bits = base.interleave(header[symbol*48:(symbol+1)*48],1)
        for k,b in zip(base.CARRIERS,bits): freq[k+26]=(1j**symbol)*(2*b-1)
        for j,k in enumerate((-21,-7,7,21)): freq[k+26]=polarity[symbol+1]*[1,1,1,-1][j]
        time = base.ifft(freq)
        field(time,time,16,legacy=True)
    field(short,short,0,5)
    tones = [1,1]+base.LTF+[-1,-1]
    long = [v*SCALE for v in ht.ifft(tones)]
    field(long,long,16)
    # VHT pilots repeat row1 of P, unlike HT's per-stream pilot columns.
    second = list(tones)
    for k in (-21,-7,7,21): second[k+28]*=-1
    field([-v for v in long],[v*SCALE for v in ht.ifft(second)],16)
    sigb_bits = ht.interleave(base.encode(sigb),1)
    freq = [0j]*57
    for k,b in zip(ht.CARRIERS,sigb_bits): freq[k+28]=2*b-1
    for j,k in enumerate((-21,-7,7,21)): freq[k+28]=polarity[3]*[1,1,1,-1][j]
    time = [v*SCALE for v in ht.ifft(freq)]
    field(time,time,16)
    start = len(chains[0])
    assert start==917
    for pair in range(0,symbols,2):
        mapped = []
        for symbol in range(pair,pair+2):
            bits = coded[symbol*52*nbpsc:(symbol+1)*52*nbpsc]
            if ldpc:
                groups = [bits[n:n+nbpsc] for n in range(0,len(bits),nbpsc)]
                bits = [b for col in range(13) for row in range(4) for b in groups[row*13+col]]
            else:
                bits = ht.interleave(bits,nbpsc)
            mapped.append([constellation(bits[j*nbpsc:(j+1)*nbpsc]) for j in range(52)])
        for within in range(2):
            symbol = pair+within
            freq = [[0j]*57,[0j]*57]
            for j,k in enumerate(ht.CARRIERS):
                freq[0][k+28] = mapped[within][j]
                freq[1][k+28] = (-1 if within==0 else 1)*mapped[1-within][j].conjugate()
            for chain in range(2):
                for j,k in enumerate((-21,-7,7,21)):
                    freq[chain][k+28]=polarity[symbol+4]*[1,1,1,-1][(symbol+j)%4]
            time = [[v*SCALE for v in ht.ifft(f)] for f in freq]
            field(*time,guard)
    end = len(chains[0])
    assert end==start+symbols*(64+guard)
    if fault=='training':
        for chain in chains: chain[37+640:37+800]=[0j]*160
    if fault=='truncated':
        for chain in chains: del chain[-(64+guard):]
    padding = 37+400+80*(length//3+1)-end
    assert padding>=0
    for chain in chains: chain.extend([0j]*(padding+64))
    return chains,bytes(psdu),start,end


def combine(chains,offset=False):
    result = [a+(0.45+0.2j)*b for a,b in zip(*chains)]
    if offset:
        result = [(v+(0.2j*chains[0][n-3] if n>=3 else 0)
                   -(0.1*chains[1][n-2] if n>=2 else 0))*cmath.exp(1j*(0.7+0.018*n))
                  for n,v in enumerate(result)]
    assert all(max(abs(v.real),abs(v.imag))*300<127 for v in result)
    return base.quantize(result)


def generate(out):
    base.self_check()
    rows = ['name\tmcs\tguard\tpsdu_hex\tframe_offsets\tmpdu_hex\tsha256\tdata_end\tinvalid_fcs\tldpc']
    for mcs in range(9):
        for guard in (8,16):
            for ldpc in (False,True):
                cases = ['duplicate','offset','large']
                if mcs==3 and guard==16: cases.append('codeword' if ldpc else 'bad-fcs')
                for case in cases:
                    frames = [frame(4100),frame(56)] if case in ('large','codeword') else [frame(56)]*2
                    apep,positions = aggregate(frames)
                    if case=='bad-fcs':
                        damaged = bytearray(apep)
                        damaged[positions[0]+len(frames[0])-1]^=1
                        apep = bytes(damaged)
                    chains,psdu,start,end = waveform(apep,mcs,guard,ldpc,case if case=='codeword' else None)
                    if case in ('codeword','bad-fcs'): frames,positions=frames[1:],positions[1:]
                    iq = combine(chains,case=='offset')
                    name = f'vht-stbc-{mcs}-{"ldpc" if ldpc else "bcc"}-gi{guard*50}-{case}'
                    (out/f'{name}.cs8').write_bytes(iq)
                    rows.append('\t'.join(map(str,[name,mcs,guard,psdu.hex(),','.join(map(str,positions)),
                        ','.join(f.hex() for f in frames),hashlib.sha256(iq).hexdigest(),end,
                        int(case in ('codeword','bad-fcs')),int(ldpc)])))
    (out/'vht-stbc-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    invalid = ['name\treason\tsha256']
    apep,_ = aggregate([frame(100)])
    for fault in ('service','sigb_crc','header_crc','nsts','disambiguation','extra','odd_symbols','training','truncated'):
        chains,_,_,_ = waveform(apep,3,16,True,fault)
        iq = combine(chains)
        name = 'vht-stbc-invalid-'+fault.replace('_','-')
        (out/f'{name}.cs8').write_bytes(iq)
        invalid.append(f'{name}\t{fault}\t{hashlib.sha256(iq).hexdigest()}')
    (out/'vht-stbc-iq-invalid-index.tsv').write_text('\n'.join(invalid)+'\n')
    print(f'{len(rows)-1} independent VHT STBC IQ waveforms and {len(invalid)-1} rejection cases verified')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--check',action='store_true')
    args=p.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='vht-stbc-iq-') as temporary:
            out=Path(temporary)
            generate(out)
            for file in out.iterdir(): assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else: generate(base.OUT)
