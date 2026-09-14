"""Independent rational VHT SU LDPC model: 802.11-2020 21.3.10.5.4.

Forward sizing starts from an initial symbol count, not the receiver's inverse
SIG-A interpretation. Gaussian parity encoding is independent of Rust recovery.
"""
import argparse
from fractions import Fraction as F
from functools import lru_cache
import hashlib
import json
import math
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
from tools.oracle.engine.backends.wifi.ldpc.codeword import FIXTURE, encode

ROOT = IQ_FIXTURES
PARAMETERS = [(52,F(1,2)), (104,F(1,2)), (104,F(3,4)), (208,F(1,2)),
              (208,F(3,4)), (312,F(2,3)), (312,F(3,4)), (312,F(5,6)), (416,F(3,4))]


def layout(initial, mcs, group):
    coded, rate = PARAMETERS[mcs]
    assert initial > 0 and initial % group == 0
    payload = int(initial * coded * rate)
    available = initial * coded
    if available <= 648:
        count, size = 1, 1296 if available >= payload + 912*(1-rate) else 648
    elif available <= 1296:
        count, size = 1, 1944 if available >= payload + 1464*(1-rate) else 1296
    elif available <= 1944:
        count, size = 1, 1944
    elif available <= 2592:
        count, size = 2, 1944 if available >= payload + 2916*(1-rate) else 1296
    else:
        count, size = math.ceil(F(payload)/(1944*rate)), 1944
    short = max(0, int(count*size*rate)-payload)
    puncture = max(0, count*size-available-short)
    extra = ((puncture > F(1,10)*count*size*(1-rate)
              and short < F(6,5)*puncture*rate/(1-rate))
             or puncture > F(3,10)*count*size*(1-rate))
    available += int(extra)*group*coded
    puncture = max(0, count*size-available-short)
    repeat = max(0, available-int(count*size*(1-rate))-payload)
    assert count*size-short-puncture+repeat == available
    assert not (puncture and repeat)
    return [available//coded, count, size, short, puncture, repeat, int(extra), payload]


def generate():
    rows = ['initial\tmcs\tgroup\tsymbols\tcodewords\tblock\tshort\tpuncture\trepeat\textra\tpayload']
    for group in [1,2]:
        for mcs in range(9):
            for initial in range(group,1513,group):
                result = layout(initial,mcs,group)
                rows.append('\t'.join(map(str,[initial,mcs,group,*result])))
    return '\n'.join(rows)+'\n'


def encode_information(information, initial, mcs, group=1):
    return list(_encode_information(tuple(information),initial,mcs,group))


@lru_cache(maxsize=128)
def _encode_information(information, initial, mcs, group):
    """Encode arbitrary information bits using independent Gaussian parity."""
    symbols,count,n,short,puncture,repeat,_,payload = layout(initial,mcs,group)
    assert len(information) == payload
    coded,rate = PARAMETERS[mcs]
    matrices = {(c['n'],tuple(c['rate'])):c for c in json.loads(FIXTURE.read_text())['codes']}
    matrix = matrices[n,(rate.numerator,rate.denominator)]
    z,k = matrix['z'],matrix['k']
    checks = [sum(1 << (col*z+(offset+shift)%z)
                  for col,shift in enumerate(block) if shift >= 0)
              for block in matrix['matrix'] for offset in range(z)]
    offset,transmitted = 0,''
    for index in range(count):
        s = short//count + (index < short%count)
        p = puncture//count + (index < puncture%count)
        r = repeat//count + (index < repeat%count)
        bits = information[offset:offset+k-s]
        assert len(bits) == k-s
        offset += len(bits)
        word = encode(checks,k,n,sum(int(b)<<i for i,b in enumerate(bits)))
        word = word[:k-s]+word[k:n-p]
        transmitted += word + ''.join(word[i%len(word)] for i in range(r))
    assert offset == payload and len(transmitted) == symbols*coded
    return tuple(int(b) for b in transmitted)


def codewords():
    matrices = {(c['n'],tuple(c['rate'])):c for c in json.loads(FIXTURE.read_text())['codes']}
    rows = ['initial\tmcs\tgroup\tpayload_bits\ttransmitted_bits']
    for group in [1,2]:
        for mcs in range(9):
            for initial in [group, 12, 48]:
                symbols,count,n,short,puncture,repeat,_,payload = layout(initial,mcs,group)
                coded,rate = PARAMETERS[mcs]
                matrix = matrices[n,(rate.numerator,rate.denominator)]
                z,k = matrix['z'],matrix['k']
                checks = [sum(1 << (col*z+(offset+shift)%z)
                              for col,shift in enumerate(block) if shift >= 0)
                          for block in matrix['matrix'] for offset in range(z)]
                raw = hashlib.shake_256(f'vht-ldpc-{initial}-{mcs}-{group}'.encode()).digest((payload+7)//8)
                information = ''.join(str(b>>i&1) for b in raw for i in range(8))[:payload]
                offset,transmitted = 0,''
                for index in range(count):
                    s = short//count + (index < short%count)
                    p = puncture//count + (index < puncture%count)
                    r = repeat//count + (index < repeat%count)
                    bits = information[offset:offset+k-s]
                    assert len(bits) == k-s
                    offset += len(bits)
                    word = encode(checks,k,n,sum(int(b)<<i for i,b in enumerate(bits)))
                    word = word[:k-s]+word[k:n-p]
                    transmitted += word + ''.join(word[i%len(word)] for i in range(r))
                assert offset == payload and len(transmitted) == symbols*coded
                rows.append('\t'.join(map(str,[initial,mcs,group,information,transmitted])))
    return '\n'.join(rows)+'\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    for name,data in [('vht-ldpc-rate-index.tsv',generate()), ('vht-ldpc-rate-codewords.tsv',codewords())]:
        path = ROOT/name
        if args.check:
            assert path.read_text() == data, name
        else:
            path.write_text(data)
        print(f'{name}: {len(data.splitlines())-1} cases, sha256 {hashlib.sha256(data.encode()).hexdigest()}')
