"""Independent antisymmetric pilot interference with unchanged DATA tones."""
import argparse
from pathlib import Path
import tempfile

from ht_pilot_vectors import OUT, generate

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ht-common-check-') as directory:
            path = Path(directory)
            generate(path, 0.04, 'ht-common')
            for file in path.iterdir():
                assert file.read_bytes() == (OUT / file.name).read_bytes(), file.name
    else:
        generate(OUT, 0.04, 'ht-common')
    print('32 independent common-phase recovery fixtures verified')
