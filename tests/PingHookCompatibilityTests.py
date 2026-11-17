"""ICMP APIs must be dynamically resolved, never required by the XP loader."""
import argparse
from pathlib import Path
import struct


def check(path):
    data = path.read_bytes()
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    sections = struct.unpack_from('<H', data, pe + 6)[0]
    optional_size = struct.unpack_from('<H', data, pe + 20)[0]
    optional = pe + 24
    magic = struct.unpack_from('<H', data, optional)[0]
    width = 4 if magic == 0x10b else 8
    directories = optional + (96 if width == 4 else 112)
    section_table = optional + optional_size

    def offset(rva):
        for i in range(sections):
            size, address, raw_size, raw = struct.unpack_from('<IIII', data, section_table + i * 40 + 8)
            if address <= rva < address + max(size, raw_size):
                return raw + rva - address
        raise AssertionError(f'unmapped RVA {rva:#x}')

    def string(rva):
        start = offset(rva)
        return data[start:data.index(b'\0', start)].decode('ascii')

    imports = struct.unpack_from('<I', data, directories + 8)[0]
    descriptor = offset(imports)
    while any(data[descriptor:descriptor+20]):
        lookup, _, _, name, address = struct.unpack_from('<IIIII', data, descriptor)
        library = string(name)
        entry = offset(lookup or address)
        while True:
            value = int.from_bytes(data[entry:entry+width], 'little')
            if not value:
                break
            if not value & (1 << (width * 8 - 1)):
                symbol = string(value + 2)
                assert not symbol.startswith('Icmp'), f'{path}: static ICMP import {library}!{symbol}'
            entry += width
        descriptor += 20
    print(f'PASS {path.name}: no static ICMP imports (including Echo2Ex)')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin', type=Path, default=Path('bin'))
    args = parser.parse_args()
    for bits in (32, 64):
        check(args.bin / f'ProxyLaneHook{bits}.dll')
