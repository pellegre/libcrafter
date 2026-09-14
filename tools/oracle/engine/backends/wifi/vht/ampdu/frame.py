"""Independent VHT aggregate bytes: IEEE 802.11-2020 9.7, 10.12.6-8.

No production encoder/decoder is used. Length is serialized as separate
high-two/low-twelve subfields, and CRC comes from the independent bit model.
"""
import argparse
import zlib
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES

import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.ht.signal import crc

OUT = IQ_FIXTURES


def delimiter(length, eof=0, reserved=0):
    assert 0 <= length < 16384
    bits = [eof, reserved] + base.bits(bytes([length >> 12]))[:2]
    bits += base.bits((length & 4095).to_bytes(2, 'little'))[:12]
    octets = bytes(sum(bit << j for j, bit in enumerate(bits[i:i+8]))
                   for i in (0, 8))
    checksum = sum(bit << i for i, bit in enumerate(crc(bits)))
    return octets + bytes([checksum, 0x4e])


def frame(length):
    assert length >= 28
    body = base.frame(0)[:24] + bytes((i * 17 + length) % 256 for i in range(length - 28))
    return body + zlib.crc32(body).to_bytes(4, 'little')


def aggregate(frames, smpdu=False, spacing=0):
    wire = bytearray()
    offsets = []
    for i, mpdu in enumerate(frames):
        if i:
            wire += b'\xa5' * (-len(wire) % 4)
            wire += delimiter(0) * spacing
        offsets.append(len(wire) + 4)
        wire += delimiter(len(mpdu), int(smpdu)) + mpdu
    return bytes(wire), offsets


def generate():
    headers = ['header_hex\tlength\tflags']
    for length in range(16384):
        flags = length % 4
        headers.append(f'{delimiter(length, flags & 1, flags >> 1).hex()}\t{length}\t{flags}')
    cases = []

    def add(name, wire, offsets, frames, invalid=False):
        cases.append((name, wire, offsets, frames, invalid))

    # All final alignment/EOF octet counts, with/without EOF delimiters and
    # nonzero S-MPDU EOF. Padding content deliberately is not zero.
    for size in range(28, 32):
        mpdu = frame(size)
        for smpdu in (False, True):
            wire, offsets = aggregate([mpdu], smpdu)
            for pad in range((-len(wire) % 4) + 1):
                add(f'final-{size}-{int(smpdu)}-{pad}', wire + b'\xa5' * pad, offsets, [mpdu])
            aligned = wire + b'\xa5' * (-len(wire) % 4)
            for delimiters in (0, 1, 3):
                for trailing in range(4):
                    padded = aligned + delimiter(0, 1) * delimiters + b'\xc7' * trailing
                    add(f'eof-{size}-{int(smpdu)}-{delimiters}-{trailing}', padded, offsets, [mpdu])

    for size in (4095, 4096, 8191, 8192, 11454, 16383):
        mpdu = frame(size)
        wire, offsets = aggregate([mpdu], True)
        add(f'length-{size}', wire, offsets, [mpdu])

    frames = [frame(n) for n in range(28, 32)]
    wire, offsets = aggregate(frames, spacing=2)
    add('multi-spacing', wire, offsets, frames)
    large = [frame(16383)] * 5
    wire, offsets = aggregate(large)
    assert len(wire) > 65535
    add('above-ht-total-limit', wire, offsets, large)

    first, second = frame(28), frame(32)
    wire, offsets = aggregate([first, second])
    for field, index in [('crc', 2), ('signature', 3), ('fcs', 4 + len(first) - 1)]:
        bad = bytearray(wire)
        bad[index] ^= 1
        add(f'bad-{field}', bytes(bad), [offsets[1]], [second], True)

    inner = delimiter(len(first)) + first
    fake = delimiter(len(inner) + 4, 1) + inner + b'junk'
    add('false-eof-long-delimiter', fake, [8], [first], True)
    wire, offsets = aggregate([first])
    for missing in (1, 2, 3, 4, 12):
        add(f'truncated-mpdu-{missing}', wire + delimiter(len(second)) + second[:-missing],
            offsets, [first], True)
    for count in (1, 2, 3):
        add(f'bare-truncated-delimiter-{count}', b'\x00' * count, [], [], True)

    # An EOF-bearing nonzero delimiter cannot occur in a multi-MPDU aggregate;
    # once an EOF subframe is accepted, only zero-length EOF padding may follow.
    single, offsets = aggregate([first], True)
    for suffix, tail in [('frame', delimiter(len(second)) + second),
                         ('smpdu', delimiter(len(second), 1) + second),
                         ('spacing', delimiter(0))]:
        add(f'after-smpdu-{suffix}', single + tail, offsets, [first], True)
    ordinary, offsets = aggregate([first])
    add('smpdu-after-frame', ordinary + delimiter(len(second), 1) + second, offsets, [first], True)
    add('smpdu-after-eof-padding', delimiter(0, 1) + single, [], [], True)
    add('frame-after-eof-padding', delimiter(0, 1) + ordinary, [], [], True)
    add('spacing-before-smpdu', delimiter(0) * 2 + single, [12], [first])
    add('reserved-bit', delimiter(len(first), 1, 1) + first, [4], [first])

    rows = ['name\tpsdu_hex\tframe_offsets\tmpdu_hex\tinvalid']
    for name, wire, offsets, frames, invalid in cases:
        rows.append('\t'.join([name, wire.hex(), ','.join(map(str, offsets)),
                               ','.join(f.hex() for f in frames), str(int(invalid))]))
    return {'vht-ampdu-delimiters.tsv': '\n'.join(headers) + '\n',
            'vht-ampdu-index.tsv': '\n'.join(rows) + '\n'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    for name, content in generate().items():
        if args.check:
            assert (OUT / name).read_text() == content, name
        else:
            (OUT / name).write_text(content)
        print(f'{name}: {len(content.splitlines()) - 1} independent cases verified')
