"""Independent HE SIG-B BCC streams (27.3.11.8.5, Table 27-111).

No interleaving or IQ: output is the punctured serialized A/B stream.
Each block has its own encoder. Puncturing uses absolute source-bit indices
and A/B selections from Figure 17-9, rather than the receiver's phase cursor.
"""
import argparse
from pathlib import Path
from he_signal_vectors import checksum


def checked(payload):
    crc = checksum(payload)
    return payload + [crc >> i & 1 for i in (3, 2, 1, 0)] + [0]*6


def encode(bits):
    register = 0
    out = []
    for bit in bits:
        register = (register >> 1) | (bit << 6)
        out.append(tuple((register & mask).bit_count() % 2 for mask in (0o133, 0o171)))
    return out


def vectors():
    rows = ['mcs\tcommon\tusers\tdamage\tblocks\tcoded\tconsumed']
    for mcs in range(6):
        for common in range(2):
            for users in (range(18) if common else range(2, 9)):
                fields = []
                if common:
                    code = 192 + users - 1 if users <= 8 else 128 + (min(8, users-2)-1)*8 + (users-1-min(8, users-2))-1
                    if users == 0: code = 113  # Explicitly empty 242-tone RU.
                    fields.append(checked([code >> i & 1 for i in range(8)]))
                user_values = [37+i | ((i % 12) << 15) | ((i % 2) << 20) for i in range(users)]
                for start in range(0, users, 2):
                    fields.append(checked([v >> i & 1 for v in user_values[start:start+2] for i in range(21)]))
                for damage in ('none', 'crc', 'tail'):
                    blocks = [b.copy() for b in fields]
                    if damage != 'none':
                        blocks[0][-10 if damage == 'crc' else -1] ^= 1
                    pairs = [pair for b in blocks for pair in encode(b)]
                    boundary = len(pairs)
                    # Arbitrary encoded padding follows the final zero tail.
                    pairs += encode([1, 0, 1, 1, 0, 0, 1]*5)
                    stream = []; consumed = 0
                    for i, (a, b) in enumerate(pairs):
                        if mcs in (0, 1, 3): selected = [a, b]
                        elif mcs in (2, 4): selected = ([a, b], [a], [b])[i % 3]
                        else: selected = [a, b] if i % 2 == 0 else [a]
                        stream.extend(selected)
                        if i < boundary: consumed += len(selected)
                    rows.append('\t'.join(map(str, [mcs, common, users, damage,
                        ';'.join(''.join(map(str, b)) for b in blocks), ''.join(map(str, stream)), consumed])))
    return '\n'.join(rows)+'\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true'); args = parser.parse_args()
    path = Path(__file__).resolve().parents[4]/'crafter/tests/fixtures/iq/he-sig-b-coded.tsv'
    content = vectors()
    if args.write: path.write_text(content)
    else: assert path.read_text() == content
    print(f'{len(content.splitlines())-1} independent HE SIG-B coded streams')
