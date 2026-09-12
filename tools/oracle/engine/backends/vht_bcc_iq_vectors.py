"""Independent full SISO VHT20 BCC IQ, IEEE 802.11-2020 clauses 9/10/21.

No production receiver/TX imports or device access. Rectangular OFDM symbols,
source-defined field normalization, diagram-derived 256-QAM labels.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile
import ofdm_vectors as base
import ht_bcc_vectors as ht
from ht_signal_vectors import crc
from vht_qam_vectors import AXIS

PARAMETERS = ht.PARAMETERS + [(8, 312)]
PUNCTURE = ht.PUNCTURE + [[1, 1, 1, 0, 0, 1]]
SCALE = math.sqrt(52 / 56)


def little(value, count):
    return [(value >> n) & 1 for n in range(count)]


def delimiter(length, eof):
    assert 0 <= length < 16384
    # The two HIGH length bits occupy header B2/B3, not the upper positions.
    header = ((length & 4095) << 4 | (length >> 12) << 2 | eof).to_bytes(2, 'little')
    checksum = sum(b << i for i, b in enumerate(crc(base.bits(header))))
    return header + bytes([checksum, 0x4e])


def constellation(bits):
    if len(bits) < 8:
        return base.constellation(bits)
    lookup = {label: value for value, label in AXIS}
    labels = ''.join(map(str, bits))
    return complex(lookup[labels[:4]], lookup[labels[4:]]) / math.sqrt(170)


def vht_symbol(bits, nbpsc, pilot_symbol, polarity, guard=16):
    freq = [0j] * 57
    for i, tone in enumerate(ht.CARRIERS):
        freq[tone + 28] = constellation(bits[i * nbpsc:(i + 1) * nbpsc])
    for j, tone in enumerate([-21, -7, 7, 21]):
        freq[tone + 28] = polarity * [1, 1, 1, -1][(pilot_symbol + j) % 4]
    time = [v * SCALE for v in ht.ifft(freq)]
    return time[-guard:] + time


def waveform(mcs, guard, extra, corruption=None):
    nbpsc, ndbps = PARAMETERS[mcs]
    mpdu = base.frame(extra)
    apep = delimiter(len(mpdu), 1) + mpdu
    symbols = (16 + 8 * len(apep) + 6 + ndbps - 1) // ndbps
    psdu_len, phy_pad = divmod(symbols * ndbps - 22, 8)
    psdu = bytearray(apep)
    while len(psdu) < psdu_len and len(psdu) % 4:
        psdu.append(0xa5)
    while len(psdu) + 4 <= psdu_len:
        psdu.extend(delimiter(0, 1))
    psdu.extend(b'\x5a' * (psdu_len - len(psdu)))
    sigb = little((len(apep) + 3) // 4, 17) + [1] * 3
    data = [0] * 8 + crc(sigb) + base.bits(psdu) + [0] * phy_pad
    encoded = base.encode(base.scramble(data, 93) + [0] * 6)
    pattern = PUNCTURE[mcs]
    coded = [b for i, b in enumerate(encoded) if pattern[i % len(pattern)]]
    assert len(coded) == symbols * 52 * nbpsc
    short = int(guard == 8)
    disambiguation = int(short and symbols % 10 == 9)
    siga = little(0, 2) + [1, 0] + little(63, 6) + little(0, 12) + [1, 1]
    siga += [short, disambiguation, 0, 0] + little(mcs, 4) + [0, 1]
    if corruption == 'mcs9': siga[28:32] = little(9, 4)
    if corruption == 'ldpc': siga[26] = 1
    if corruption == 'stbc': siga[3] = 1
    if corruption == 'cbw40': siga[0] = 1
    if corruption == 'reserved': siga[2] = 0
    siga += crc(siga) + [0] * 6
    if corruption == 'siga_crc': siga[34] ^= 1
    sigb += [0] * 6
    if corruption == 'sigb_crc': sigb[0] ^= 1
    lsig_length = 3 * (5 + math.ceil(symbols * (64 + guard) / 80)) - 3
    if corruption == 'lsig_length': lsig_length += 1
    polarities = [1 - 2 * b for b in base.scramble([0] * (symbols + 4), 127)]
    wave = [0j] * 37 + base.preamble()
    wave += base.symbol(base.interleave(base.encode(base.signal('1101', lsig_length)), 1), 1, polarities[0])
    a_coded = base.encode(siga)
    for symbol in range(2):
        freq = [0j] * 53
        block = base.interleave(a_coded[symbol * 48:(symbol + 1) * 48], 1)
        for tone, bit in zip(base.CARRIERS, block):
            freq[tone + 26] = (1j ** symbol) * (2 * bit - 1)
        for j, tone in enumerate([-21, -7, 7, 21]):
            freq[tone + 26] = polarities[symbol + 1] * [1, 1, 1, -1][j]
        time = base.ifft(freq)
        wave += time[-16:] + time
    wave += base.preamble()[:80]
    training = [v * SCALE for v in ht.ifft([1, 1] + base.LTF + [-1, -1])]
    wave += training[-16:] + training
    wave += vht_symbol(ht.interleave(base.encode(sigb), 1), 1, 0, polarities[3])
    data_start = len(wave)
    assert data_start == 837
    for symbol in range(symbols):
        block = ht.interleave(coded[symbol * 52 * nbpsc:(symbol + 1) * 52 * nbpsc], nbpsc)
        wave += vht_symbol(block, nbpsc, symbol, polarities[symbol + 4], guard)
    data_end = len(wave)
    signaled_end = 37 + 400 + 80 * (lsig_length // 3 + 1)
    assert 0 <= signaled_end - data_end < 80
    wave += [0j] * (signaled_end - data_end + 64)
    return wave, (symbols, lsig_length, siga, sigb, bytes(psdu), mpdu,
                  data_start, data_end, signaled_end, len(apep))


def generate(out):
    base.self_check()
    rows = ['name\tmcs\tguard\tsymbols\tlsig_length\tsiga\tsigb\tpsdu_hex\tmpdu_hex\tsha256\tdata_start\tdata_end\tsignaled_end\tapep_length']
    for mcs, (_, ndbps) in enumerate(PARAMETERS):
        minimum = (22 + 8 * 60 + ndbps - 1) // ndbps
        target = 9 + 10 * max(0, math.ceil((minimum - 9) / 10))
        extras = [((n * ndbps - 22) // 8) - 60 for n in [target, target + 1]] + [1444]
        for guard in [8, 16]:
            for case, extra in enumerate(extras):
                wave, fields = waveform(mcs, guard, extra)
                symbols, length, siga, sigb, psdu, mpdu, start, end, signaled, apep = fields
                if case < 2:
                    assert symbols == target + case
                for impairment in ['clean', 'offset']:
                    impaired = wave if impairment == 'clean' else [
                        (v + (0.25j * wave[n - 3] if n >= 3 else 0)) * cmath.exp(1j * (0.7 + 0.018 * n))
                        for n, v in enumerate(wave)]
                    assert all(max(abs(v.real), abs(v.imag)) * 300 < 127 for v in impaired), 'unintended ADC clipping'
                    iq = base.quantize(impaired)
                    name = f'vht-bcc-{mcs}-gi{guard * 50}-case{case}-{impairment}'
                    (out / f'{name}.cs8').write_bytes(iq)
                    rows.append('\t'.join(map(str, [name, mcs, guard, symbols, length,
                        ''.join(map(str, siga)), ''.join(map(str, sigb)), psdu.hex(), mpdu.hex(),
                        hashlib.sha256(iq).hexdigest(), start, end, signaled, apep])))
    (out / 'vht-bcc-iq-index.tsv').write_text('\n'.join(rows) + '\n')
    invalid = ['name\treason\tsha256']
    for reason in ['mcs9', 'ldpc', 'stbc', 'cbw40', 'reserved', 'siga_crc', 'sigb_crc', 'lsig_length']:
        wave, _ = waveform(0, 16, 44, reason)
        iq = base.quantize(wave)
        name = f'vht-bcc-invalid-{reason.replace("_", "-")}'
        (out / f'{name}.cs8').write_bytes(iq)
        invalid.append(f'{name}\t{reason}\t{hashlib.sha256(iq).hexdigest()}')
    (out / 'vht-bcc-iq-invalid-index.tsv').write_text('\n'.join(invalid) + '\n')
    print(f'{len(rows) - 1} independent full VHT20 BCC IQ fixtures verified')
    print(f'{len(invalid) - 1} invalid/unsupported VHT IQ fixtures verified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='vht-bcc-iq-') as temporary:
            out = Path(temporary)
            generate(out)
            for file in out.iterdir():
                assert file.read_bytes() == (base.OUT / file.name).read_bytes(), file.name
    else:
        generate(base.OUT)
