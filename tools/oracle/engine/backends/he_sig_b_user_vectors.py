"""IEEE 802.11ax-2021 Tables 27-27..30 independent user block vectors.

Spatial configurations are enumerated as bounded integer partitions, sorted
by reversed tuples, independently of the literal Rust table. CRC uses binary
polynomial division rather than the receiver's shift-register implementation.
"""
import argparse
from itertools import product
from pathlib import Path
from he_signal_vectors import checksum


def block(values):
    bits = [v >> i & 1 for v in values for i in range(21)]
    crc = checksum(bits)
    return ''.join(map(str, bits + [crc >> i & 1 for i in (3, 2, 1, 0)] + [0]*6))


def vectors():
    rows = ['bits\tcontexts\texpected']

    def emit(values, contexts, expected):
        rows.append('\t'.join((block(values), ';'.join(contexts), ';'.join(expected))))

    good = 73 | (11 << 15) | (1 << 20)
    good_expected = 'nonmu:73:1:0:11:0:1'
    for users in range(2, 9):
        configs = sorted((p for p in product(range(1, 5), repeat=users)
                          if sum(p) <= 8 and all(a >= b for a, b in zip(p, p[1:]))),
                         key=lambda p: p[::-1])
        assert len(configs) == [10, 13, 11, 7, 4, 2, 1][users-2]
        for code in range(16):
            for pos in range(users):
                value = 123 | (code << 11) | (7 << 15) | (1 << 20)
                expected = (f'mu:123:{code}:{configs[code][pos]}:'
                            f'{sum(configs[code][:pos])}:{sum(configs[code])}:7:1'
                            if code < len(configs) else f'spatial:{users}:{code}')
                emit([value], [f'{users}:{pos}'], [expected])
                emit([value, good], [f'{users}:{pos}', 'nonmu'], [expected, good_expected])
    for raw in range(1024):
        emit([2046 | (raw << 11)]*2, ['nonmu', '8:7'], [f'unused:2046:{raw}']*2)
    for sts, beam, mcs, dcm, ldpc in product(range(1, 9), range(2), range(16), range(2), range(2)):
        value = 17 | ((sts-1) << 11) | (beam << 14) | (mcs << 15) | (dcm << 19) | (ldpc << 20)
        expected = f'nonmu:17:{sts}:{beam}:{mcs}:{dcm}:{ldpc}' if mcs < 12 else f'mcs:{mcs}'
        emit([good, value], ['nonmu', 'nonmu'], [good_expected, expected])
    emit([1 << 19, good], ['2:0', 'nonmu'], ['reserved:19', good_expected])
    for users, pos in [(0, 0), (1, 0), (9, 0), (255, 0), (2, 2), (8, 255)]:
        emit([2046, good], [f'{users}:{pos}', 'nonmu'], [f'context:{users}:{pos}', good_expected])
    return '\n'.join(rows) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    path = Path(__file__).resolve().parents[4] / 'crafter/tests/fixtures/iq/he-sig-b-users.tsv'
    content = vectors()
    if args.write:
        path.write_text(content)
    else:
        assert path.read_text() == content
    print(f'{len(content.splitlines())-1} independent HE SIG-B user blocks')
