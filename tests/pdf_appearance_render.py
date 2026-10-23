# SPDX-License-Identifier: GPL-3.0-or-later
"""Check a viewer's rendered coordinates, orientation and alpha compositing."""
from pathlib import Path
import subprocess
import sys
import tempfile

renderer, fixtures = sys.argv[1:]
with tempfile.TemporaryDirectory(prefix='libssig-appearance-') as directory:
    for rotation in (0, 90, 180, 270):
        prefix = Path(directory) / str(rotation)
        subprocess.run([renderer, '-f', '2', '-singlefile', '-cropbox', '-r', '72',
                        str(Path(fixtures) / f'appearance-{rotation}-1.pdf'), str(prefix)], check=True)
        magic, size, maximum, pixels = prefix.with_suffix('.ppm').read_bytes().split(b'\n', 3)
        width, height = map(int, size.split())
        assert magic == b'P6' and maximum == b'255'
        assert (width, height) == ((260, 360) if rotation % 180 else (360, 260))
        for x, y, expected in ((44, 46, (255, 0, 0)), (84, 46, (0, 255, 0)),
                               (44, 66, (0, 0, 255)), (84, 66, (127, 127, 127)),
                               (23, 60, (255, 255, 255)), (105, 60, (255, 255, 255))):
            offset = (y * width + x) * 3
            actual = tuple(pixels[offset:offset + 3])
            assert all(abs(a - b) <= 1 for a, b in zip(actual, expected)), (rotation, x, y, actual, expected)
print('PDF appearance viewer checks passed')
