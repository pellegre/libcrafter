"""Independent sampling-clock impairments of the offline IEEE OFDM oracle.

This generator imports only the independent Python encoder, never crafter DSP.
Positive ppm means a faster receiver clock: more received samples per symbol.
Run from repository root with python3 tools/oracle/engine/backends/ofdm_clock_vectors.py.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import tempfile

import ofdm_vectors as encoder

OUT = encoder.OUT


def resample(samples, ppm, origin):
    ratio = 1 + ppm * 1e-6
    count = math.ceil(origin + (len(samples) - origin) * ratio)
    output = bytearray()
    for n in range(count):
        t = origin + (n - origin) / ratio
        center = math.floor(t)
        value = 0j
        total = 0.
        # Sixteen-tap Hann-windowed sinc. The 0.475 cycles/sample cutoff
        # retains the OFDM occupied carriers while smoothing quantized IQ.
        for k in range(center - 7, center + 9):
            d = t - k
            if abs(d) >= 8:
                continue
            x = 0.95 * d
            weight = 0.95 * (1 if abs(x) < 1e-12 else math.sin(math.pi*x)/(math.pi*x))
            weight *= 0.5 + 0.5 * math.cos(math.pi*d/8)
            total += weight
            if 0 <= k < len(samples):
                value += samples[k] * weight
        value /= total
        for component in (value.real, value.imag):
            output.append(max(-128, min(127, round(component))) & 255)
    return output


def generate(out):
    entries = []
    encoder.self_check()
    with tempfile.TemporaryDirectory(prefix='ofdm-clock-base-') as temporary:
        encoder.OUT = Path(temporary)
        for index, rate in enumerate(encoder.RATES):
            for length_case in ('clean', 'max_length'):
                base = encoder.generate(*rate, index, length_case)
                source = (encoder.OUT / (base['name'] + '.cs8')).read_bytes()
                signed = [v if v < 128 else v - 256 for v in source]
                samples = [complex(*signed[n:n+2]) for n in range(0, len(signed), 2)]
                for ppm in (-20, 0, 20):
                    name = f"ofdm-clock-{rate[0]}-{length_case}-{ppm:+d}ppm"
                    iq = resample(samples, ppm, base['preamble_start'])
                    (out / (name + '.cs8')).write_bytes(iq)
                    ratio = 1 + ppm*1e-6
                    entries.append(dict(
                        name=name, rate_mbps=rate[0], receiver_clock_ppm=ppm,
                        cfo_hz=0, sample_count=len(iq)//2,
                        preamble_start=base['preamble_start'],
                        frame_end=math.ceil(base['preamble_start'] +
                            (base['frame_end']-base['preamble_start'])*ratio),
                        psdu_hex=base['psdu_hex'],
                        sha256=hashlib.sha256(iq).hexdigest()))
    manifest = dict(schema='crafter.radio.ofdm-clock/v1',
                    sample_rate_hz=20_000_000, format='cs8',
                    interpolation='16-tap normalized Hann-windowed sinc, cutoff 0.475',
                    generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    encoder_sha256=hashlib.sha256(Path(encoder.__file__).read_bytes()).hexdigest(),
                    fixtures=entries)
    (out / 'ofdm-clock-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return len(entries)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ofdm-clock-check-') as temporary:
            output = Path(temporary)
            count = generate(output)
            for path in output.iterdir():
                if path.read_bytes() != (OUT / path.name).read_bytes():
                    raise SystemExit(f'fixture differs: {path.name}')
    else:
        count = generate(OUT)
    print(f'{count} independent sampling-clock fixtures verified')
