"""Read-only, exact-binary audit of Chromium QUIC certificate completion code."""
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'build/quic-probe/python'))

import capstone
import pefile


def inspect(path, output):
    raw = path.read_bytes()
    pe = pefile.PE(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION'],
                                         pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']])
    functions = [(e.struct.BeginAddress,e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION]
    starts = [a for a,b in functions]
    literals = [b'Net.QuicSession.CertVerificationResult', b'Failed to verify certificate chain: %s']
    targets = {}
    for literal in literals:
        for m in re.finditer(re.escape(literal),raw):
            targets[pe.get_rva_from_offset(m.start())] = literal.decode()
    candidates = {}
    for sec in pe.sections:
        if not sec.Characteristics & 0x20000000:
            continue
        data = sec.get_data()
        for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',data):
            pos = m.start()
            rva = sec.VirtualAddress+pos
            target = rva+7+struct.unpack_from('<i',data,pos+3)[0]
            if target not in targets:
                continue
            index = bisect.bisect_right(starts,rva)-1
            begin,end = functions[index]
            assert begin <= rva < end
            candidates.setdefault(begin,{'end':end,'refs':[]})['refs'].append({'rva':rva,'literal':targets[target]})
    output.mkdir(parents=True,exist_ok=True)
    md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    reports = []
    for begin,info in candidates.items():
        text = '\n'.join(f'{i.address:08x} {i.bytes.hex():24s} {i.mnemonic:8s} {i.op_str}'
                         for i in md.disasm(pe.get_data(begin,info['end']-begin),begin))
        (output/f'{path.stem}-{begin:x}.asm').write_text(text)
        reports.append({'begin':hex(begin),'end':hex(info['end']),'refs':info['refs']})
    result = {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),
              'image_size':pe.OPTIONAL_HEADER.SizeOfImage,'functions':reports}
    for e in getattr(pe,'DIRECTORY_ENTRY_DEBUG',[]):
        if e.struct.Type == 2:
            cv = raw[e.struct.PointerToRawData:e.struct.PointerToRawData+e.struct.SizeOfData]
            result['codeview_hex'] = cv.hex()
    (output/(path.stem+'.json')).write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    inspect(Path(sys.argv[1]),Path(sys.argv[2]))
