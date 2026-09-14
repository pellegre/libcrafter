"""Independent HE20 SU preamble prefixes, IEEE 802.11ax-2021 27.3.11/22.

Contains no DATA, so these files cannot qualify full frame reception.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile
import tools.oracle.engine.backends.wifi.ofdm.base as base
import tools.oracle.engine.backends.wifi.ht.bcc as ht
import tools.oracle.engine.backends.wifi.he.signal as he


def symbol(coded, legacy=False, rotate=False):
    freq = [0j] * 57
    for k, b in zip(base.CARRIERS if legacy else ht.CARRIERS, coded):
        freq[k+28] = (2*int(b)-1) * (1j if rotate else 1)
    if legacy:
        for k, value in zip([-28,-27,27,28], [-1,-1,-1,1]):
            freq[k+28] = value
    for k, value in [(-21,1),(-7,1),(7,1),(21,-1)]:
        freq[k+28] = value
    time = [v * math.sqrt(52/56) for v in ht.ifft(freq)]
    return time[-16:] + time


def waveform(mcs, gi, impaired=False, invalid=None):
    bits = [0] * 52
    bits[0] = bits[14] = bits[34] = bits[40] = 1
    bits[3:7] = [(mcs >> b) & 1 for b in range(4)]
    bits[21:23] = [gi & 1, gi >> 1]
    # 27.3.12.5: MCS10/11 require LDPC in actual DATA configurations.
    bits[33] = int(mcs >= 10 or bool(mcs & 1))
    if invalid == 'format': bits[0] = 0
    if invalid == 'width': bits[19] = 1
    if invalid == 'tail': bits[46] = 1
    crc = he.checksum(bits[:42])
    bits[42:46] = [(crc >> b) & 1 for b in (3,2,1,0)]
    if invalid == 'crc': bits[42] ^= 1
    coded = he.encoded(bits)
    length = {'remainder0': 300, 'remainder2': 302}.get(invalid, 301)
    lsig = base.signal('1101', length)  # R1 first: 6 Mb/s.
    repeated = base.signal('1101', length + (3 if invalid == 'repeat' else 0))
    if invalid == 'rate': lsig = base.signal('0101', length)
    if invalid == 'parity': repeated[17] ^= 1
    # HE adds epsilon=sqrt(52/56) to L-STF and L-LTF, unlike VHT.
    samples = [0j]*37 + [v*math.sqrt(52/56) for v in base.preamble()]
    samples += symbol(base.interleave(base.encode(lsig),1), legacy=True)
    samples += symbol(base.interleave(base.encode(repeated),1), legacy=True)
    samples += symbol(coded[:52], rotate=invalid == 'qbpsk') + symbol(coded[52:])
    if impaired:
        samples = [(v + (0.25j*samples[n-3] if n >= 3 else 0))*cmath.exp(1j*(0.7+0.018*n))
                   for n,v in enumerate(samples)]
    assert len(samples) == 677
    assert all(max(abs(v.real),abs(v.imag))*200 < 127 for v in samples)
    return base.quantize(samples, scale=200), ''.join(map(str,bits)), length


def generate(out):
    base.self_check()
    rows = ['name\tbits\tlength\tend_sample\tsha256']
    for mcs in range(12):
        for gi in range(4):
            for impaired in (False,True):
                name = f'he-su-prefix-{mcs}-gi{gi}-{"offset" if impaired else "clean"}'
                iq,bits,length = waveform(mcs,gi,impaired)
                (out/f'{name}.cs8').write_bytes(iq)
                rows.append(f'{name}\t{bits}\t{length}\t677\t{hashlib.sha256(iq).hexdigest()}')
    (out/'he-su-prefix-index.tsv').write_text('\n'.join(rows)+'\n')
    rows = ['name\treason\tsha256']
    for reason in ['format','width','tail','crc','remainder0','remainder2','repeat','rate','parity','qbpsk']:
        name = f'he-su-prefix-invalid-{reason}'
        iq,_,_ = waveform(0,0,invalid=reason)
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append(f'{name}\t{reason}\t{hashlib.sha256(iq).hexdigest()}')
    (out/'he-su-prefix-invalid-index.tsv').write_text('\n'.join(rows)+'\n')
    print('96 valid and 10 invalid HE SU IQ prefixes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-prefix-') as temporary:
            out = Path(temporary)
            generate(out)
            for file in out.iterdir():
                assert file.read_bytes() == (base.OUT/file.name).read_bytes(), file.name
    else:
        generate(base.OUT)
