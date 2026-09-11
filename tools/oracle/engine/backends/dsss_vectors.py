"""Independent IEEE 802.11-2007 clauses 15/18 offline DSSS/CCK encoder.

Standard-library only; no production Rust imports or live radio support.
Literal evidence is documented in crafter/tests/fixtures/iq/README.md.
"""
import argparse
import cmath
import hashlib
import json
import math
from pathlib import Path
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[4]
OUT = ROOT / 'crafter/tests/fixtures/iq'
VERSION = '2'
BARKER = [1, -1, 1, 1, -1, 1, 1, 1, -1, -1, -1]
# Keys are serial pairs (first transmitted bit first).
DIFFERENTIAL = {(0, 0): 0, (0, 1): 1, (1, 1): 2, (1, 0): 3}
BINARY = {(0, 0): 0, (0, 1): 1, (1, 0): 2, (1, 1): 3}
PHASE = [1, 1j, -1, -1j]


def bits(data):
    return [(v >> k) & 1 for v in data for k in range(8)]


def crc16(data):
    crc = 0xffff
    for bit in bits(data):
        low = (crc ^ bit) & 1
        crc >>= 1
        if low:
            crc ^= 0x8408
    return crc ^ 0xffff


def scramble(data, seed):
    history = list(seed)  # Z1 is most recent output.
    out = []
    for bit in data:
        value = bit ^ history[3] ^ history[6]
        out.append(value)
        history = [value] + history[:6]
    return out


def cck(serial, common):
    if len(serial) == 4:
        b, c, d = 2 * serial[2] + 1, 0, 2 * serial[3]
    else:
        b, c, d = (BINARY[tuple(serial[k:k + 2])] for k in (2, 4, 6))
    phases = [b+c+d, c+d, b+d, d, b+c, c, b, 0]
    return [PHASE[(common + p) % 4] * (-1 if k in (3, 6) else 1)
            for k, p in enumerate(phases)]


def length_fields(octets, rate):
    length = (octets * 80 + rate - 1) // rate  # rate in 100 kbps
    extension = int(rate == 110 and 11 * length - 8 * octets >= 8)
    return length, extension


def self_check():
    assert crc16(bytes.fromhex('0a00c000')) == 0xeada
    assert bits(bytes.fromhex('daea')) == list(map(int, '0101101101010111'))
    assert cck([0, 0, 0, 0], 0) == [1j, 1, 1j, -1, 1j, 1, -1j, 1]
    assert cck([0, 0, 1, 1], 0) == [1j, -1, 1j, 1, -1j, 1, 1j, 1]
    assert DIFFERENTIAL[(1, 0)] == 3 and BINARY[(1, 0)] == 2
    assert [length_fields(n, 110) for n in (1023, 1024, 1025, 1026)] == [(744, 0), (745, 0), (746, 0), (747, 1)]
    for preamble, seed, bit, golden in [('long', [1,1,0,1,1,0,0], 1, '0111111011101100'),
                                      ('short', [0,0,1,1,0,1,1], 0, '0001100110101001')]:
        encoded = scramble([bit] * 16, seed)
        assert encoded == list(map(int, golden)), preamble
        assert [encoded[n] ^ encoded[n-4] ^ encoded[n-7] for n in range(7,16)] == [bit] * 9
    assert zlib.crc32(b'123456789') == 0xcbf43926


def pulse(t):
    # Raised cosine, rolloff .35, symmetric finite support +/-8 chips.
    # Independent continuous-time transmit pulse, not receiver interpolation.
    beta = .35
    if abs(t) >= 8:
        return 0.0
    if abs(t) < 1e-12:
        return 1.0
    if abs(abs(2 * beta * t) - 1) < 1e-10:
        return math.pi / 4 * math.sin(math.pi * t) / (math.pi * t)
    return math.sin(math.pi * t) / (math.pi * t) * math.cos(math.pi * beta * t) / (1 - (2 * beta * t)**2)


def transmit_frame():
    """Canonical Dot11 / Raw oracle input with documentation IPv4 addresses."""
    header = bytes.fromhex('080000000200000000010200000000020200000000030000aaaa030000000800')
    payload = bytes(range(32))
    ip = bytearray(bytes.fromhex('450000000001000040fd0000c0000201c6336402'))
    ip[2:4] = (20 + len(payload)).to_bytes(2, 'big')
    words = [int.from_bytes(ip[index:index + 2], 'big') for index in range(0, 20, 2)]
    total = sum(words)
    total = (total & 0xffff) + (total >> 16)
    ip[10:12] = ((~total) & 0xffff).to_bytes(2, 'big')
    return header + ip + payload


def generate_transmit(rate, preamble, *, case_id=None, fcs_override=None,
                      header_override=None):
    short = preamble == 'short'
    mac = transmit_frame()
    derived_fcs = zlib.crc32(mac).to_bytes(4, 'little')
    psdu = mac + (derived_fcs if fcs_override is None else fcs_override)
    length, extension = length_fields(len(psdu), rate)
    service = extension << 7
    derived_header = bytes([rate, service]) + length.to_bytes(2, 'little')
    derived_header += crc16(derived_header).to_bytes(2, 'little')
    header = derived_header if header_override is None else header_override
    sync = [0 if short else 1] * (56 if short else 128)
    sfd = 0x05cf if short else 0xf3a0
    raw = sync + bits(sfd.to_bytes(2, 'little')) + bits(header) + bits(psdu)
    seed = [0, 0, 1, 1, 0, 1, 1] if short else [1, 1, 0, 1, 1, 0, 0]
    serial = scramble(raw, seed)
    chips = []
    common = 0
    symbols = []
    preamble_bits = len(sync) + 16

    def barker(segment, width):
        nonlocal common
        for start in range(0, len(segment), width):
            dibit = segment[start:start + width]
            common = (common + (2 * dibit[0] if width == 1 else
                                DIFFERENTIAL[tuple(dibit)])) % 4
            chips.extend(PHASE[common] * value for value in BARKER)

    barker(serial[:preamble_bits], 1)
    barker(serial[preamble_bits:preamble_bits + 48], 2 if short else 1)
    payload_chip = len(chips)
    payload = serial[preamble_bits + 48:]
    if rate <= 20:
        barker(payload, 1 if rate == 10 else 2)
    else:
        width = 4 if rate == 55 else 8
        for number, start in enumerate(range(0, len(payload), width)):
            word = payload[start:start + width]
            common = (common + DIFFERENTIAL[tuple(word[:2])] + 2 * (number % 2)) % 4
            code = cck(word, common)
            chips.extend(code)
            symbols.append(dict(bits=word, common_quadrant=common,
                                chips=[[int(value.real), int(value.imag)] for value in code]))
    leading, trailing, gain = 64.0, 64, .48
    samples_per_chip = 20 / 11
    count = math.ceil(leading + len(chips) * samples_per_chip) + trailing

    def waveform(position):
        center = math.floor(position)
        return sum(chips[index] * pulse(position - index - .5)
                   for index in range(max(0, center - 8), min(len(chips), center + 9)))

    samples = bytearray()
    for index in range(count):
        position = (index - leading) / samples_per_chip
        value = gain * waveform(position)
        samples.extend(max(-128, min(127, round(axis * 127))) & 255
                       for axis in (value.real, value.imag))
    rate_name = {10: '1', 20: '2', 55: '5.5', 110: '11'}[rate]
    case_id = case_id or f'legacy-dsss-{rate_name}-{preamble}'
    stem = f'dsss-tx-{case_id.removeprefix("legacy-dsss-")}'
    intermediate = dict(
        case_id=case_id, header_hex=header.hex(), derived_header_hex=derived_header.hex(),
        input_bits=raw, scrambled_bits=serial, seed_z1_z7=seed,
        cck_symbols=symbols, payload_chip=payload_chip,
    )
    intermediate_bytes = (json.dumps(intermediate, separators=(',', ':')) + '\n').encode()
    (OUT / f'{stem}.cs8').write_bytes(samples)
    (OUT / f'{stem}.psdu').write_bytes(psdu)
    (OUT / f'{stem}.json').write_bytes(intermediate_bytes)
    return dict(
        case_id=case_id, artifact_stem=stem, phy='dsss_cck',
        rate_bps=rate * 100000, preamble=preamble, sample_rate_hz=20_000_000,
        chip_rate_hz=11_000_000, mac_hex=mac.hex(), psdu_hex=psdu.hex(),
        fcs_hex=psdu[-4:].hex(), fcs_policy=('auto' if fcs_override is None else 'explicit'),
        plcp_policy=('auto' if header_override is None else 'explicit'),
        header_hex=header.hex(), derived_header_hex=derived_header.hex(),
        length_us=length, length_extension=extension,
        scrambler_seed_z1_z7=seed, leading_samples=leading,
        payload_start=leading + payload_chip * samples_per_chip,
        frame_end=leading + len(chips) * samples_per_chip,
        trailing_samples=trailing, sample_count=len(samples) // 2,
        gain=gain, pulse=dict(kind='raised_cosine', rolloff=.35, support_chips=8),
        cs8_sha256=hashlib.sha256(samples).hexdigest(),
        psdu_sha256=hashlib.sha256(psdu).hexdigest(),
        intermediate_sha256=hashlib.sha256(intermediate_bytes).hexdigest(),
        expected='frame' if fcs_override is None and header_override is None else 'reject',
    )


def generate(rate, preamble, case='clean', octets=48):
    short = preamble == 'short'
    # Locally administered synthetic MAC addresses and inert deterministic body.
    body = bytes.fromhex('080000000200000000010200000000020200000000030000')
    body += bytes((k * 73 + 19) % 256 for k in range(octets - 28))
    psdu = body + zlib.crc32(body).to_bytes(4, 'little')
    if case == 'bad_fcs':
        psdu = psdu[:-1] + bytes([psdu[-1] ^ 1])
    length, extension = length_fields(len(psdu), rate)
    service = extension << 7
    if case == 'pbcc':
        service |= 8
    signal = 0xff if case == 'bad_signal' else rate
    header = bytes([signal, service]) + length.to_bytes(2, 'little')
    header += crc16(header).to_bytes(2, 'little')
    if case == 'bad_crc':
        header = header[:-1] + bytes([header[-1] ^ 1])
    sync = [0 if short else 1] * (56 if short else 128)
    sfd = (0x05cf if short else 0xf3a0) ^ int(case == 'bad_sfd')
    raw = sync + bits(sfd.to_bytes(2, 'little')) + bits(header) + bits(psdu)
    seed = ([0,0,1,1,0,1,1] if short else [1,1,0,1,1,0,0])
    if case == 'alternate_seed':
        seed = [1,0,1,0,1,1,1]
    serial = scramble(raw, seed)
    chips = []
    common = 0
    symbols = []
    preamble_bits = len(sync) + 16
    def barker(segment, width):
        nonlocal common
        for start in range(0, len(segment), width):
            dibit = segment[start:start+width]
            common = (common + (2*dibit[0] if width == 1 else DIFFERENTIAL[tuple(dibit)])) % 4
            chips.extend(PHASE[common] * value for value in BARKER)
    barker(serial[:preamble_bits], 1)
    barker(serial[preamble_bits:preamble_bits+48], 2 if short else 1)
    payload_chip = len(chips)
    payload = serial[preamble_bits+48:]
    if rate <= 20:
        barker(payload, 1 if rate == 10 else 2)
    else:
        width = 4 if rate == 55 else 8
        for number, start in enumerate(range(0, len(payload), width)):
            word = payload[start:start+width]
            common = (common + DIFFERENTIAL[tuple(word[:2])] + 2*(number % 2)) % 4
            code = cck(word, common)
            chips.extend(code)
            symbols.append(dict(bits=word, common_quadrant=common,
                                chips=[[int(v.real), int(v.imag)] for v in code]))
    interference = case == 'barker_interference'
    if interference:
        # Add a chip vector orthogonal to Barker in the final header symbol.
        # Its energy lowers correlation quality while preserving the data bit.
        # Reduce overall gain below to avoid clipping this deterministic stressor.
        symbol_phase = chips[payload_chip - 11] / BARKER[0]
        for k in range(11):
            chips[payload_chip - 11 + k] += symbol_phase * 2 * (1 - BARKER[k] / 11)
    echo = case == 'channel_echo'
    gain = .35 if echo else (.18 if interference else .48)
    impaired = case in ('impaired', 'channel_echo')
    initial = 37.375 if impaired else 37.0
    ppm = 35 if impaired else 0
    samples_per_chip = 20 / 11 * (1 + ppm * 1e-6)
    cfo = 45000 if impaired else 0
    noise = .008 if impaired else 0
    phase = .63 if impaired else .2
    delay = 1.0 if echo else (1.3 if impaired else 0)
    path = .65 * cmath.exp(1j * math.pi / 2) if echo else (.22 * cmath.exp(.7j) if impaired else 0j)
    count = math.ceil(initial + len(chips) * samples_per_chip + 40)
    state = 12345
    def rand():
        nonlocal state
        state = (1664525 * state + 1013904223) & 0xffffffff
        return state / 4294967296 * 2 - 1
    def waveform(position):
        center = math.floor(position)
        return sum(chips[k] * pulse(position-k-.5)
                   for k in range(max(0,center-8), min(len(chips),center+9)))
    samples = bytearray()
    for n in range(count):
        position = (n-initial) / samples_per_chip
        value = waveform(position)
        if impaired:
            value += path * waveform(position-delay)
        value = gain * value * cmath.exp(1j*(phase+2*math.pi*cfo*n/20_000_000))
        value += noise * complex(rand(), rand())
        samples.extend(max(-128, min(127, round(a*127))) & 255 for a in (value.real,value.imag))
    end = initial + len(chips) * samples_per_chip
    if case.startswith('truncated_'):
        boundary = {'sync': 20, 'sfd': preamble_bits-8, 'header': preamble_bits+16}
        part = case.removeprefix('truncated_')
        cutoff = (initial + boundary[part]*20 if part in boundary else end-100)
        samples = samples[:2*int(cutoff)]
    name = f'dsss-{rate}-{preamble}-{case}-{octets}'
    intermediate = dict(header_hex=header.hex(), input_bits=raw, scrambled_bits=serial,
                        seed_z1_z7=seed, cck_symbols=symbols, payload_chip=payload_chip)
    intermediate_bytes = (json.dumps(intermediate,separators=(',',':'))+'\n').encode()
    (OUT/f'{name}.json').write_bytes(intermediate_bytes)
    (OUT/f'{name}.cs8').write_bytes(samples)
    return dict(name=name, rate_bps=rate*100000, preamble=preamble, psdu_hex=psdu.hex(),
                header_hex=header.hex(), length_us=length, length_extension=extension,
                sample_count=len(samples)//2, preamble_start=initial,
                payload_start=initial+payload_chip*samples_per_chip, frame_end=end,
                chip_count=len(chips), sha256=hashlib.sha256(samples).hexdigest(),
                intermediate_sha256=hashlib.sha256(intermediate_bytes).hexdigest(),
                expected='reject' if case.startswith(('bad_', 'truncated_')) or case=='pbcc' else 'frame',
                fcs_valid=case!='bad_fcs', header_crc_valid=case!='bad_crc',
                impairment=dict(clock_ppm=ppm, carrier_hz=cfo, phase_rad=phase,
                                noise_amplitude=noise, noise_seed=12345, gain=gain,
                                header_interference_amplitude=2.0 if interference else 0.0,
                                delayed_path_chips=delay, delayed_path_amplitude=abs(path),
                                delayed_path_phase_rad=math.pi / 2 if echo else (.7 if impaired else 0)))


def main():
    self_check()
    entries = [generate(r,p) for p in ('long','short') for r in (10,20,55,110) if not(p=='short' and r==10)]
    entries += [generate(r,'long','impaired',64) for r in (10,20,55,110)]
    entries += [generate(10,'long','barker_interference',48)]
    entries += [generate(110,p,'channel_echo',64) for p in ('long','short')]
    entries += [generate(r,p,'bad_fcs') for r in (55,110) for p in ('long','short')]
    entries += [generate(110,'short','length_boundary',n) for n in (1023,1024,1025,1026)]
    entries += [generate(10,'long',case) for case in ('alternate_seed','bad_crc','bad_fcs','bad_sfd','bad_signal','pbcc','truncated_sync','truncated_sfd','truncated_header','truncated_payload')]
    manifest = dict(schema=1,generator_version=VERSION,generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    source='IEEE Std 802.11-2007 clauses 15 and 18',format='cs8',
                    sample_rate_hz=20000000,chip_rate_hz=11000000,
                    pulse=dict(kind='raised_cosine',rolloff=.35,support_chips=8,
                               chip_center=.5,causal_delay_samples=0),fixtures=entries)
    (OUT/'dsss-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    columns=['name','rate_bps','preamble','sample_count','psdu_hex','sha256','expected']
    (OUT/'dsss-index.tsv').write_text('\t'.join(columns)+'\n'+''.join('\t'.join(str(e[k]) for k in columns)+'\n' for e in entries))
    transmit = [generate_transmit(rate, preamble)
                for preamble in ('long', 'short') for rate in (10, 20, 55, 110)
                if not (preamble == 'short' and rate == 10)]
    transmit.append(generate_transmit(
        10, 'long', case_id='legacy-dsss-1-long-explicit-wrong-fcs',
        fcs_override=bytes.fromhex('00000000')))
    psdu_length = len(transmit_frame()) + 4
    length, extension = length_fields(psdu_length, 10)
    wrong_header = bytes([10, extension << 7]) + length.to_bytes(2, 'little')
    wrong_header += (crc16(wrong_header) ^ 1).to_bytes(2, 'little')
    transmit.append(generate_transmit(
        10, 'long', case_id='legacy-dsss-1-long-explicit-wrong-plcp-crc',
        header_override=wrong_header))
    tx_manifest = dict(
        schema='crafter.radio.transmit-oracle/v1', generator_version=VERSION,
        generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        source='IEEE Std 802.11-2007 clauses 15 and 18', format='cs8',
        sample_rate_hz=20_000_000, chip_rate_hz=11_000_000,
        canonical_input='Dot11 / Raw', cases=transmit,
        rejected=[
            dict(case_id='legacy-dsss-1-short', reason='short_preamble_unsupported_at_1_mbps'),
            dict(case_id='legacy-dsss-unsupported-rate', reason='unsupported_phy_rate'),
            dict(case_id='legacy-dsss-psdu-limit', reason='psdu_limit_exceeded'),
            dict(case_id='legacy-dsss-sample-limit', reason='sample_limit_exceeded'),
        ],
    )
    (OUT/'dsss-transmit-manifest.json').write_text(json.dumps(tx_manifest, indent=2)+'\n')
    tx_columns = ['case_id','artifact_stem','rate_bps','preamble','sample_count',
                  'psdu_sha256','cs8_sha256','expected']
    (OUT/'dsss-transmit-index.tsv').write_text(
        '\t'.join(tx_columns)+'\n'+''.join(
            '\t'.join(str(entry[key]) for key in tx_columns)+'\n' for entry in transmit))
    print(f'Generated {len(entries)} independent DSSS/CCK vectors; literal clause 15/18 checks passed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    if args.check:
        expected = OUT
        with tempfile.TemporaryDirectory(prefix='dsss-vectors-') as temporary:
            OUT = Path(temporary)
            main()
            generated = {p.name:p.read_bytes() for p in OUT.iterdir()}
            existing = {p.name:p.read_bytes() for p in expected.glob('dsss-*') if p.is_file()}
            if generated != existing:
                parser.exit(1,'DSSS vector outputs differ; regenerate and review fixtures.\n')
        print('All DSSS/CCK vector artifacts match the independent generator.')
    else:
        main()
