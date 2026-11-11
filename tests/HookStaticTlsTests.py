"""Reject compiler TLS in the injected hook: XP cannot load it dynamically.

This binary check catches TLS introduced by linked objects/libraries too; a
successful LoadLibrary on modern Windows alone cannot detect the XP regression.
"""
import argparse
from pathlib import Path
import struct


def check(path):
    data = path.read_bytes()
    assert data[:2] == b'MZ', f'{path}: missing DOS header'
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[pe:pe+4] == b'PE\0\0', f'{path}: missing PE header'
    optional = pe + 24
    magic = struct.unpack_from('<H', data, optional)[0]
    assert magic in (0x10b, 0x20b), f'{path}: unexpected optional header'
    directories = optional + (96 if magic == 0x10b else 112)
    count = struct.unpack_from('<I', data, directories-4)[0]
    tls = struct.unpack_from('<II', data, directories + 9*8) if count > 9 else (0, 0)
    assert tls == (0, 0), f'{path}: static TLS RVA={tls[0]:#x}, size={tls[1]} breaks XP dynamic loading'
    print(f'PASS {path.name}: no static TLS directory or loader-time TLS constructors')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin', type=Path, default=Path('bin'))
    args = parser.parse_args()
    for bits in (32, 64):
        check(args.bin / f'ProxyLaneHook{bits}.dll')
