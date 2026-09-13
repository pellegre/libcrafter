"""HE20 SU 4x channel-training oracle, IEEE802.11ax-2021 27.3.11.9-10.

The symbol after the standard preamble is an uncoded mathematical channel
probe, NOT a valid HE DATA field or a MAC-frame qualification fixture.
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

# Independently transcribed Equation27-43, signed-tone order -122..122.
LTF4 = '--+-+-+++-+++--+-----++----++-+-++++-+--++-++++--+---++++-++----+--++-+----+-+------++-----+--+++-+++-+-+-----+++---+-+++000-+-+-++-+++--+--+-+-+++-+++--+-----++------+-+----+-++--+----++-+++++++-++----+--++-+----+-+--++++--+++++-++---+---+-+-++'
TONES = list(range(-122,-1)) + list(range(2,123))
LTF1 = '00-000+000+000-000+000-000+000+000+000+000-000-000+000+000+000-000-000-000+000-000-000+000+000-000-000+000-000-000+000-0000000-000+000+000+000+000+000+000-000-000-000-000-000+000-000-000-000+000-000-000+000-000-000+000-000+000-000-000-000-000-00'
LTF2 = '-0-0-0+0+0-0+0-0-0-0-0+0-0+0-0-0+0+0-0+0+0+0+0+0-0+0-0+0-0-0+0+0-0+0-0-0-0-0+0-0+0+0+0-0-0+0-0-0-0-0-0+0-0-0-0+0+0+0-0-0+000+0-0+0+0-0+0+0-0+0+0-0-0+0-0+0+0+0+0-0+0-0+0+0-0-0+0-0-0-0-0-0+0-0+0+0-0-0+0+0-0+0-0-0-0-0+0-0+0+0+0-0-0+0-0-0-0-0-0+0-0+'
TWIDDLE = [[cmath.exp(2j*math.pi*k*t/256)/256 for k in range(-122,123)] for t in range(256)]


def ifft(freq):
    return [sum(v*w for v,w in zip(freq,row)) for row in TWIDDLE]


def waveform(guard, case, gain, invalid=None, ltf_size=4):
    assert len(LTF4) == 245 and LTF4.count('0') == 3
    bits = [0]*52
    for i in (0,14,34,40): bits[i] = 1
    bits[21:23] = [1,1]
    if guard == 16: bits[7] = bits[35] = 1  # Table27-19 escape: no DCM/STBC.
    if ltf_size != 4:
        bits[7] = bits[35] = 0
        bits[21:23] = [0,0] if ltf_size == 1 else ([1,0] if guard == 16 else [0,1])
    bits[1] = int(case == 'beam')
    if invalid == 'ltf2': bits[21:23] = [1,0]
    if invalid == 'nsts2': bits[23] = 1
    if invalid == 'stbc': bits[23] = bits[35] = 1
    crc = he.checksum(bits[:42])
    bits[42:46] = [(crc >> k)&1 for k in (3,2,1,0)]
    coded = he.encoded(bits)
    legacy = base.interleave(base.encode(base.signal('1101',301)),1)
    prefix = [0j]*37 + [v*math.sqrt(52/56) for v in base.preamble()]
    prefix += symbol(legacy,legacy=True)*2 + symbol(coded[:52]) + symbol(coded[52:])
    assert len(prefix) == 677
    stf_freq = [0j]*245
    for k,v in zip(range(-112,113,16), [-1,-1,-1,1,1,1,-1,1,1,1,-1,1,1,-1,1]):
        if k: stf_freq[k+122] = v*(1+1j)/math.sqrt(2)
    stf = [v*4*math.sqrt(52/14) for v in ifft(stf_freq)][:80]
    sequence = {1:LTF1,2:LTF2,4:LTF4}[ltf_size]
    active = len(sequence)-sequence.count('0')
    assert len(sequence) == 245 and active == {1:60,2:122,4:242}[ltf_size]
    ltf = [v*4*math.sqrt(52/active) for v in ifft([{'-':-1,'+':1,'0':0}[c] for c in sequence])][:64*ltf_size]
    he_wave = stf + ltf[-guard:] + ltf
    data_start = len(prefix)+len(he_wave)
    if invalid == 'zero': he_wave[80:] = [0j]*(guard+256)
    probe_bits = base.bits(hashlib.sha256(b'he-training-channel-probe').digest())[:242]
    probe_freq = [0j]*245
    for k,b in zip(TONES,probe_bits): probe_freq[k+122] = 2*b-1
    probe = [v*4*math.sqrt(52/242) for v in ifft(probe_freq)]
    he_wave += probe[-guard:] + probe
    beam = complex(.55,.35) if case == 'beam' else 1+0j
    samples = prefix + [v*beam for v in he_wave]
    taps = [(0,1+0j)]
    if case == 'offset': taps += [(3,.25j)]
    if case in ('selective','beam'): taps += [(5,.35+.2j),(11,-.2j)]
    cfo,phase = (0.,0.) if case == 'flat' else (.018,.7)
    samples = [sum(h*samples[n-d] for d,h in taps if n>=d)*cmath.exp(1j*(phase+cfo*n))
               for n in range(len(samples))]
    if invalid == 'truncated': samples = samples[:data_start-1]
    assert all(max(abs(v.real),abs(v.imag))*gain<127 for v in samples)
    return base.quantize(samples,scale=gain), [guard,bits[1],cfo,phase,gain,
        ';'.join(f'{d}:{h.real}:{h.imag}' for d,h in taps),beam.real,beam.imag,
        ''.join(map(str,probe_bits)),757,data_start,len(samples)]


def generate(out):
    base.self_check()
    rows = ['name\tguard\tbeam_change\tcfo\tphase\tgain\ttaps\tbeam_i\tbeam_q\tprobe_bits\tltf_start\tdata_start\tend\tsha256']
    for guard in (16,64):
        for case in ('flat','offset','selective','beam'):
            for gain in (96,160,224):
                name = f'he-training4-gi{guard*50}-{case}-gain{gain}'
                iq,fields = waveform(guard,case,gain)
                (out/f'{name}.cs8').write_bytes(iq)
                rows.append('\t'.join(map(str,[name,*fields,hashlib.sha256(iq).hexdigest()])))
    (out/'he-training4-index.tsv').write_text('\n'.join(rows)+'\n')
    rows = ['name\treason\tsha256']
    for reason in ('ltf2','nsts2','stbc','zero','truncated'):
        name = f'he-training4-invalid-{reason}'
        iq,_ = waveform(64,'flat',160,reason)
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append(f'{name}\t{reason}\t{hashlib.sha256(iq).hexdigest()}')
    (out/'he-training4-invalid-index.tsv').write_text('\n'.join(rows)+'\n')
    print('24 HE4x training/probe cases and5 negative cases')
    rows = ['name\tguard\tbeam_change\tcfo\tphase\tgain\ttaps\tbeam_i\tbeam_q\tprobe_bits\tltf_start\tdata_start\tend\tsha256\tltf_size']
    for size,guard in ((1,16),(2,16),(2,32)):
        for case in ('flat','offset','selective','beam'):
            for gain in (96,160,224):
                name = f'he-training-sparse-ltf{size}-gi{guard*50}-{case}-gain{gain}'
                iq,fields = waveform(guard,case,gain,ltf_size=size)
                (out/f'{name}.cs8').write_bytes(iq)
                rows.append('\t'.join(map(str,[name,*fields,hashlib.sha256(iq).hexdigest(),size])))
    (out/'he-training-sparse-index.tsv').write_text('\n'.join(rows)+'\n')
    print('36 sparse HE training/probe cases')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-training-') as temporary:
            out = Path(temporary)
            generate(out)
            for file in out.iterdir():
                assert file.read_bytes() == (base.OUT/file.name).read_bytes(),file.name
    else:
        generate(base.OUT)
