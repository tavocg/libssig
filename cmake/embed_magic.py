#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Embed the matching libmagic database without installation-path dependencies."""
from pathlib import Path
import sys
import zlib

source, target = map(Path, sys.argv[1:])
data = source.read_bytes()
if not 8 <= len(data) <= 64 * 1024 * 1024:
    raise SystemExit('magic database must be between 8 bytes and 64 MiB')
compressed = zlib.compress(data, 9)
with target.open('w', encoding='ascii') as out:
    out.write('#include <stddef.h>\nconst unsigned char libssig_magic_data[] = {\n')
    for offset in range(0, len(compressed), 24):
        out.write(','.join(f'0x{x:02x}' for x in compressed[offset:offset+24]) + ',\n')
    out.write('};\n')
    out.write(f'const size_t libssig_magic_size = {len(compressed)};\n')
    out.write(f'const size_t libssig_magic_raw_size = {len(data)};\n')
