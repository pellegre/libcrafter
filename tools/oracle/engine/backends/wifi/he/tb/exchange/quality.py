"""Genie-aided full-RU STBC quality after final exchange CS8 quantization.

Uses the forward model's exact carrier, channel and Alamouti inverse, then
counts nearest 1024-QAM symbol/label errors. No production receiver is used.
"""
import argparse
import cmath
import hashlib
import math
import struct
import zlib
from tools.oracle.engine.backends.wifi.paths import REPOSITORY

import tools.oracle.engine.backends.wifi.he.tb.exchange.base as exchange
import tools.oracle.engine.backends.wifi.he.mu.data as mu
import tools.oracle.engine.backends.wifi.he.training as training
from tools.oracle.engine.backends.wifi.he.ampdu.iq import qos
from tools.oracle.engine.backends.wifi.he.ru.symbol import geometry, point
from tools.oracle.engine.backends.wifi.vht.ampdu.frame import delimiter

ROOT = REPOSITORY


def dft_tone(wave, tone):
    return sum(value * cmath.exp(-2j * math.pi * tone * n / 256)
               for n, value in enumerate(wave))


def recover_pair(y0, y1, h0, h1):
    power = abs(h0) ** 2 + abs(h1) ** 2
    return ((h0.conjugate() * y0 + h1 * y1.conjugate()) / power,
            (h0.conjugate() * y1 - h1 * y0.conjugate()) / power)


def nearest(value, constellation):
    return min(range(len(constellation)), key=lambda n: abs(value - constellation[n]))


def run(size, guard, expected_shas):
    payload = bytearray()
    for number in (1, 2):
        body = bytearray(qos(number)[:-4])
        body[4:10] = bytes.fromhex("00005e005301")
        frame = bytes(body) + struct.pack("<I", zlib.crc32(body))
        payload += delimiter(len(frame), 0) + frame
        payload += b"\xc7" * (-len(payload) % 4)

    recorded = []
    original_ifft = training.ifft

    def observe(freq):
        recorded.append(list(freq))
        return original_ifft(freq)

    training.ifft = observe
    trace = {}
    try:
        raw, _, symbols = mu.waveform(
            192, 11, True, False, size, guard, nltf=2, stbc=True,
            tb_ru=(242, 1), mac_payloads=[payload], sizing_trace=trace,
            return_complex=True,
        )
    finally:
        training.ifft = original_ifft
    tb = raw[37:]
    data_frequency = recorded[-symbols:]

    index = ROOT / "crafter/tests/fixtures/iq/he-tb-exchange-index.tsv"
    wanted = "he-tb-exchange-054-clean" if size == 2 else "he-tb-exchange-055-clean"
    row = next(line.split("\t") for line in index.read_text().splitlines() if line.startswith(wanted + "\t"))
    trigger = bytes.fromhex(row[8])
    ap = exchange.legacy(trigger)
    tb_start = 64 + len(ap) + 320
    assert tb_start == int(row[7])
    constellation = [point([(label >> bit) & 1 for bit in range(10)]) for label in range(1024)]
    rows = []
    for case_index, ap_scale in enumerate((1., .25)):
        combined = [0j] * 64 + [v * ap_scale for v in ap] + [0j] * 320 + tb + [0j] * 256
        omega = 2 * math.pi * 12000 / 20_000_000
        combined = [value * cmath.exp(1j * (.3 + omega * n))
                    for n, value in enumerate(combined)]
        gain = min(220, 120 / max(max(abs(v.real), abs(v.imag)) for v in combined))
        iq = exchange.base.quantize(combined, scale=gain)
        digest = hashlib.sha256(iq).hexdigest()
        assert digest == expected_shas[case_index]
        captured = [complex((i if i < 128 else i - 256) / gain,
                            (q if q < 128 else q - 256) / gain)
                    for i, q in zip(iq[::2], iq[1::2])]
        captured = [value * cmath.exp(-1j * (.3 + omega * n))
                    for n, value in enumerate(captured)]

        data_tones = next(data for ru, slot, data, _ in geometry() if (ru, slot) == (242, 1))
        factor = 4 * math.sqrt(52 / 242)
        data_start = tb_start + 800 + 2 * (64 * size + guard)
        observed = []
        for symbol in range(symbols):
            start = data_start + symbol * (256 + guard) + guard
            useful = captured[start:start + 256]
            observed.append({tone: dft_tone(useful, tone) / factor for tone in data_tones})

        ideal_values = []
        observed_values = []
        symbol_errors = 0
        bit_errors = 0
        for symbol in range(0, symbols, 2):
            for tone in data_tones:
                phase = cmath.exp(2j * math.pi * tone * 8 / 256)
                h0 = 1 / math.sqrt(2)
                h1 = complex(.4, .3) * phase / math.sqrt(2)
                ideal = recover_pair(data_frequency[symbol][tone + 122],
                                     data_frequency[symbol + 1][tone + 122], h0, h1)
                actual = recover_pair(observed[symbol][tone], observed[symbol + 1][tone], h0, h1)
                for reference, value in zip(ideal, actual):
                    ideal_values.append(reference)
                    observed_values.append(value)
                    expected = nearest(reference, constellation)
                    decoded = nearest(value, constellation)
                    symbol_errors += expected != decoded
                    bit_errors += (expected ^ decoded).bit_count()

        error = sum(abs(a - b) ** 2 for a, b in zip(observed_values, ideal_values))
        reference = sum(abs(v) ** 2 for v in ideal_values)
        evm = math.sqrt(error / reference)
        name = ("he-tb-exchange-054-clean" if size == 2 else "he-tb-exchange-055-clean")
        if case_index:
            name = "he-tb-exchange-063-balanced" if size == 2 else "he-tb-exchange-064-balanced"
        rows.append((name, size, guard, ap_scale, gain, 20 * math.log10(evm),
                     symbol_errors, len(ideal_values), bit_errors, digest))
    return rows


def generate():
    cases = [
        (2, 32, ("d2c029642b138230435437792efbb69f18caaa5c5a251258742ecd1a1029ef1d",
                 "fb406cc9d7a7604ae5eaf8e6c77c2a5c60db3d3477894e98c6e9862000b030c6")),
        (4, 64, ("6de1556e058a8b6ae67cab128183be461f534afab7e9b3ff41c2418b03a93d3f",
                 "817711ea59fce7bc04949421fa132662d3741efd0b37b97c5fe39c16e5f557f5")),
    ]
    rows = ["name\tltf\tguard\tap_scale\tgain\tevm_db\tsymbol_errors\tsymbols\tbit_errors\tsha256"]
    for size, guard, digests in cases:
        for values in run(size, guard, digests):
            name, ltf, gi, scale, gain, evm, errors, symbols, bits, digest = values
            rows.append("\t".join([name, str(ltf), str(gi), f"{scale:.2f}",
                f"{gain:.6f}", f"{evm:.6f}", str(errors), str(symbols),
                str(bits), digest]))
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    destination = exchange.base.OUT / "he-tb-exchange-quality.tsv"
    content = generate()
    if args.check:
        assert destination.read_text() == content
    else:
        destination.write_text(content)
    print("4 genie-aided HE TB exchange quality cases")
