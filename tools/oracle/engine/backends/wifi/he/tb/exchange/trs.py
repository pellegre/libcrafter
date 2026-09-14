"""Independent HE TRS Control followed by an HE20 TB response.

The synthetic exchanges cover the TRS-derived RU, MCS, DCM, symbol count,
guard interval, and LTF parameters used by the passive receiver.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import struct
import tempfile
import zlib

import tools.oracle.engine.backends.wifi.he.bcc.iq as he
import tools.oracle.engine.backends.wifi.he.tb.exchange.base as exchange
import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.he.ampdu.iq import qos
from tools.oracle.engine.backends.wifi.vht.ampdu.frame import delimiter


def aggregate(frame):
    payload = bytearray(delimiter(len(frame), 0) + frame)
    payload += b'\xc7' * (-len(payload) % 4)
    return bytes(payload)


def trs_frame(symbols, raw_ru, mcs, duration, case):
    body = bytearray(qos(7)[:-4])
    body[1] |= 0x80
    body[2:4] = struct.pack('<H', duration)
    body[4:10] = (
        b'\x01\x00\x5e\x00\x53\x01'
        if case == 'group-address'
        else b'\x00\x00\x5e\x00\x53\x01'
    )
    information = (
        ((symbols - 1) & 31)
        | (raw_ru << 5)
        | (20 << 13)
        | (17 << 18)
        | (mcs << 23)
        | (int(case == 'reserved') << 25)
    )
    ht_control = 3 | (information << 6)
    body[26:26] = struct.pack('<I', ht_control)
    frame = bytes(body) + struct.pack('<I', zlib.crc32(body))
    if case == 'bad-fcs':
        frame = frame[:-1] + bytes([frame[-1] ^ 1])
    return frame


def generate(out):
    cases = [
        ('clean-26', 26, 0, False, 2, 32, 4, 64, 'he'),
        ('clean-52', 52, 1, False, 2, 16, 2, 32, 'he'),
        ('clean-106', 106, 2, False, 4, 16, 2, 32, 'he'),
        ('clean-242', 242, 3, False, 4, 64, 4, 64, 'he'),
        ('clean-dcm', 106, 3, True, 2, 32, 4, 64, 'he'),
        ('wrong-color', 26, 0, False, 2, 32, 4, 64, 'he'),
        ('wrong-symbols', 52, 1, False, 2, 16, 2, 32, 'he'),
        ('wrong-guard', 106, 2, False, 4, 64, 2, 32, 'he'),
        ('wrong-dcm', 106, 3, True, 2, 32, 4, 64, 'he'),
        ('group-address', 26, 0, False, 2, 32, 4, 64, 'he'),
        ('reserved', 26, 0, False, 2, 32, 4, 64, 'he'),
        ('bad-fcs', 26, 0, False, 2, 32, 4, 64, 'he'),
        ('legacy-carrier', 26, 0, False, 2, 32, 4, 64, 'legacy'),
    ]
    rows = [
        'name\tcase\tru\tmcs\tcarrier_dcm\tcarrier_ltf\tcarrier_guard'
        '\tresponse_ltf\tresponse_guard\tcarrier_end\ttb_start\tcarrier'
        '\tframe\tsymbols\tsamples\tsha256'
    ]
    for case, ru, mcs, carrier_dcm, carrier_ltf, carrier_guard, response_ltf, response_guard, carrier_format in cases:
        body = bytearray(qos(9)[:-4])
        body[4:10] = bytes.fromhex('00005e005301')
        response = bytes(body) + struct.pack('<I', zlib.crc32(body))
        payload = aggregate(response)
        trace = {}
        actual_dcm = False if case == 'wrong-dcm' else carrier_dcm
        tb, _, symbols = exchange.waveform(
            192,
            mcs,
            False,
            actual_dcm,
            response_ltf,
            response_guard,
            tb_ru=(ru, 1),
            mac_payloads=[payload],
            pre_fec_padding=4,
            sizing_trace=trace,
            return_complex=True,
            bss_color=38 if case == 'wrong-color' else 37,
            tb_spatial_reuse=[15] * 4,
        )
        tb = tb[37:]
        raw_ru = {26: 0, 52: 74, 106: 106, 242: 122}[ru]
        requested_symbols = symbols + (1 if case == 'wrong-symbols' else 0)
        duration = math.ceil(len(tb) / 20) + 32
        carrier = trs_frame(requested_symbols, raw_ru, mcs, duration, case)
        if carrier_format == 'legacy':
            carrier_wave = exchange.legacy(carrier)
        else:
            carrier_wave, _ = he.waveform(
                0,
                carrier_ltf,
                carrier_guard,
                'selective',
                payload=aggregate(carrier),
                initial_padding=2,
                dcm=carrier_dcm,
                bss_color=37,
                return_complex=True,
            )
        carrier_wave = carrier_wave[37:] if carrier_format == 'he' else carrier_wave
        carrier_end = 64 + len(carrier_wave)
        wait = 320
        wave = [0j] * 64 + carrier_wave + [0j] * wait + tb + [0j] * 256
        tb_start = carrier_end + wait
        wave = [
            value * cmath.exp(1j * (.3 + 2 * math.pi * 12000 * n / 20_000_000))
            for n, value in enumerate(wave)
        ]
        gain = min(220, 120 / max(max(abs(v.real), abs(v.imag)) for v in wave))
        iq = base.quantize(wave, scale=gain)
        accepted = case.startswith('clean')
        name = f'he-tb-trs-exchange-{case}'
        (out / f'{name}.cs8').write_bytes(iq)
        rows.append(
            '\t'.join(
                map(
                    str,
                    [
                        name,
                        case,
                        ru,
                        mcs,
                        int(carrier_dcm),
                        carrier_ltf,
                        carrier_guard,
                        response_ltf,
                        response_guard,
                        carrier_end,
                        tb_start,
                        '-' if case == 'bad-fcs' else carrier.hex(),
                        response.hex() if accepted else '-',
                        symbols,
                        len(iq) // 2,
                        hashlib.sha256(iq).hexdigest(),
                    ],
                )
            )
        )
    (out / 'he-tb-trs-exchange-index.tsv').write_text('\n'.join(rows) + '\n')
    print(f'{len(cases)} independent TRS Control / HE TB exchanges')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-tb-trs-check-') as temporary:
            out = Path(temporary)
            generate(out)
            for path in out.iterdir():
                assert path.read_bytes() == (base.OUT / path.name).read_bytes(), path.name
    else:
        generate(base.OUT)
