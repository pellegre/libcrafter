"""HE framing: IEEE 802.11ax-2021 Table 9-527 and 26.6.2.

Independent wire encoder; shared VHT delimiter serialization is normative.
Expected frames are selected during construction, never by a decoder.
These are framing cases, not negotiated acknowledgment-policy qualification.
"""
import argparse
from itertools import product
from tools.oracle.engine.backends.wifi.vht.ampdu.frame import OUT, delimiter, frame


def generate():
    rows = ['name\tpsdu_hex\tframe_offsets\tmpdu_hex\tflags\tinvalid']

    def add(name, wire, offsets, frames, flags, invalid=False):
        rows.append('\t'.join([name, wire.hex(), ','.join(map(str, offsets)),
                               ','.join(f.hex() for f in frames),
                               ','.join(map(str, flags)), str(int(invalid))]))

    for tags in product(range(2), repeat=3):
        for trailing in range(4):
            wire = bytearray()
            offsets, frames = [], []
            for i, tag in enumerate(tags):
                wire += b'\xa5' * (-len(wire) % 4)
                wire += delimiter(0)  # Minimum-start-spacing delimiter.
                mpdu = frame(28 + i)
                offsets.append(len(wire) + 4)
                frames.append(mpdu)
                wire += delimiter(len(mpdu), tag) + mpdu
            wire += b'\xa5' * (-len(wire) % 4)
            wire += delimiter(0, 1) * 2 + b'\xc7' * trailing
            add(f'tags-{tags}-{trailing}', wire, offsets, frames, tags)

    first, second = frame(28), frame(32)
    prefix = delimiter(len(first), 1) + first
    for tag in range(2):
        suffix = delimiter(len(second), tag) + second
        add(f'frame-after-eof-{tag}', prefix + delimiter(0, 1) + suffix,
            [4], [first], [1], True)
        add(f'bad-tagged-fcs-{tag}', prefix[:-1] + bytes([prefix[-1] ^ 1]) + suffix,
            [len(prefix) + 4], [second], [tag], True)
    add('spacing-after-eof', prefix + delimiter(0, 1) + delimiter(0),
        [4], [first], [1], True)
    # Bad outer FCS must not change EOF state or hide an inner frame.
    inner = delimiter(len(first), 1) + first
    add('false-tagged-long-delimiter', delimiter(len(inner) + 4, 1) + inner + b'junk',
        [8], [first], [1], True)
    for length in (4095, 4096, 8192, 16383):
        mpdu = frame(length)
        add(f'length-{length}', delimiter(length, 1, 1) + mpdu,
            [4], [mpdu], [3])
    for count in range(1, 4):
        add(f'truncated-delimiter-{count}', b'\x00' * count, [], [], [], True)
    add('empty-eof', delimiter(0, 1) * 2 + b'\xff', [], [], [])
    return '\n'.join(rows) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    content = generate()
    path = OUT / 'he-ampdu-index.tsv'
    if args.check:
        assert path.read_text() == content
    else:
        path.write_text(content)
    print(f'{len(content.splitlines()) - 1} HE framing cases verified')
