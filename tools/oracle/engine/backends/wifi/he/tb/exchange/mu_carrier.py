"""Independent multi-A-MPDU HE MU scheduling followed by HE20 TB responses.

Each downlink MU user carries its own aggregate. The cases exercise distinct,
repeated, incompatible, overlapping, and mixed Trigger/TRS scheduling context.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import struct
import tempfile
import zlib

import tools.oracle.engine.backends.wifi.he.tb.exchange.base as exchange
from tools.oracle.engine.backends.wifi.he.ampdu.iq import qos
from tools.oracle.engine.backends.wifi.he.mu.data import waveform
from tools.oracle.engine.backends.wifi.he.tb.exchange.trs import aggregate, trs_frame
import tools.oracle.engine.backends.wifi.ofdm.base as base


def trigger(common, raw_ru, aid, duration):
    user = aid | (raw_ru << 12)
    mac = (
        struct.pack('<HH', 0x24, duration)
        + bytes.fromhex('ffffffffffff00005e005301')
        + struct.pack('<Q', common)
        + user.to_bytes(5, 'little')
        + b'\x00\xff\xff'
    )
    return mac + struct.pack('<I', zlib.crc32(mac))


def response(ru_index, sequence):
    body = bytearray(qos(sequence)[:-4])
    body[4:10] = bytes.fromhex('00005e005301')
    body[10:16] = bytes.fromhex('00005e0053') + bytes([sequence])
    frame = bytes(body) + struct.pack('<I', zlib.crc32(body))
    payload = aggregate(frame)
    trace = {}
    wave, _, symbols = waveform(
        192,
        0,
        False,
        False,
        4,
        64,
        tb_ru=(26, ru_index),
        tb_user_number=sequence,
        mac_payloads=[payload],
        pre_fec_padding=4,
        sizing_trace=trace,
        return_complex=True,
        bss_color=37,
        tb_spatial_reuse=[15] * 4,
    )
    return wave[37:], frame, trace, symbols


def generate(out):
    cases = ['distinct', 'repeated', 'incompatible', 'mixed-trs', 'overlap']
    rows = [
        'name\tcase\tcarrier_end\ttb_start\tcarrier_frames\tresponse_frames'
        '\tsymbols\tsamples\tsha256'
    ]
    for case in cases:
        positions = [1] if case == 'repeated' else [1, 2, 3]
        if case == 'overlap':
            positions = [1, 2]
        waves = []
        response_frames = []
        reference = None
        symbols = None
        for index, position in enumerate(positions):
            wave, frame, trace, count = response(position, index + 1)
            if reference is None:
                reference = trace
                symbols = count
            else:
                assert reference == trace and symbols == count
            hz = -250 + 500 * index / max(len(positions) - 1, 1)
            waves.append(
                [
                    value
                    * (1 - .15 * index)
                    * cmath.exp(1j * (.11 * index + 2 * math.pi * hz * n / 20_000_000))
                    for n, value in enumerate(wave)
                ]
            )
            response_frames.append(frame)
        tb = [sum(values) for values in zip(*waves)]
        duration = math.ceil(len(tb) / 20) + 32
        common = (
            (reference['length'] << 4)
            | (2 << 20)
            | (reference['extra'] << 27)
            | (20 << 28)
            | ((reference['padding'] % 4) << 34)
            | (0xffff << 37)
            | (511 << 54)
        )
        if case == 'repeated':
            carrier_frames = [trigger(common, 0, 1, duration)] * 3
        elif case == 'incompatible':
            carrier_frames = [
                trigger(common, 2 * index, index + 1, duration) for index in range(3)
            ]
            carrier_frames[1] = trigger(common ^ (1 << 54), 2, 2, duration)
        elif case == 'mixed-trs':
            carrier_frames = [
                trigger(common, 0, 1, duration),
                trs_frame(symbols, 2, 0, duration, 'clean'),
                trs_frame(symbols, 4, 0, duration, 'clean'),
            ]
        elif case == 'overlap':
            carrier_frames = [
                trigger(common, 0, 1, duration),
                trigger(common, 0, 2, duration),
                trigger(common, 2, 3, duration),
            ]
        else:
            carrier_frames = [
                trigger(common, 2 * index, index + 1, duration) for index in range(3)
            ]
        carrier, _, _ = waveform(
            128,
            0,
            False,
            False,
            2,
            32,
            impaired=True,
            mac_payloads=[aggregate(frame) for frame in carrier_frames],
            return_complex=True,
            bss_color=37,
        )
        carrier = carrier[37:]
        carrier_end = 64 + len(carrier)
        tb_start = carrier_end + 320
        combined = [0j] * 64 + carrier + [0j] * 320 + tb + [0j] * 256
        combined = [
            value * cmath.exp(1j * (.3 + 2 * math.pi * 12000 * n / 20_000_000))
            for n, value in enumerate(combined)
        ]
        gain = min(220, 120 / max(max(abs(v.real), abs(v.imag)) for v in combined))
        iq = base.quantize(combined, scale=gain)
        expected = [] if case == 'incompatible' else response_frames
        if case == 'overlap':
            expected = response_frames[1:]
        name = f'he-tb-mu-carrier-exchange-{case}'
        (out / f'{name}.cs8').write_bytes(iq)
        rows.append(
            '\t'.join(
                map(
                    str,
                    [
                        name,
                        case,
                        carrier_end,
                        tb_start,
                        ','.join(frame.hex() for frame in carrier_frames),
                        ','.join(frame.hex() for frame in expected) or '-',
                        symbols,
                        len(iq) // 2,
                        hashlib.sha256(iq).hexdigest(),
                    ],
                )
            )
        )
    (out / 'he-tb-mu-carrier-exchange-index.tsv').write_text('\n'.join(rows) + '\n')
    print(f'{len(cases)} independent multi-A-MPDU HE MU / HE TB exchanges')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-tb-mu-carrier-check-') as temporary:
            out = Path(temporary)
            generate(out)
            for path in out.iterdir():
                assert path.read_bytes() == (base.OUT / path.name).read_bytes(), path.name
    else:
        generate(base.OUT)
