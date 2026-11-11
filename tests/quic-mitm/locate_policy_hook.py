"""Conservative x64 instruction-family locator. No injection or fixed browser RVAs.

Recognizes the guarded unknown-root call in the audited Chromium implementation
family. New instruction shapes are unsupported, never guessed. This is not a
general semantic equivalence prover or a promise of all-version compatibility.
"""
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'build/quic-probe/python'))
import capstone as cs
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
import pefile

ANCHORS = (b'Net.QuicSession.CertVerificationResult', b'Failed to verify certificate chain: %s')

def require(ok, message):
    if not ok: raise ValueError(message)

def locate(path, *, data=None):
    raw = Path(path).read_bytes() if data is None else data
    pe = pefile.PE(data=raw, fast_load=True)
    require(pe.FILE_HEADER.Machine == 0x8664, 'Only x64 is supported')
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
    ranges = {e.struct.BeginAddress: e.struct.EndAddress for e in pe.DIRECTORY_ENTRY_EXCEPTION}
    starts = sorted(ranges)
    targets = {}
    for literal in ANCHORS:
        for match in re.finditer(re.escape(literal), raw):
            targets[pe.get_rva_from_offset(match.start())] = literal
    refs = {}
    for section in pe.sections:
        if not section.Characteristics & 0x20000000: continue
        data = section.get_data()
        for match in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', data):
            pos = match.start()
            if pos + 7 > len(data): continue
            rva = section.VirtualAddress + pos
            target = rva + 7 + struct.unpack_from('<i', data, pos + 3)[0]
            if target not in targets: continue
            idx = bisect.bisect_right(starts, rva) - 1
            if idx >= 0 and rva < ranges[starts[idx]]:
                refs.setdefault(starts[idx], []).append((rva, targets[target]))
    candidates = [r for r, values in refs.items() if {v for _, v in values} == set(ANCHORS)]
    require(len(candidates) == 1, 'Completion anchors missing or ambiguous')
    begin = candidates[0]; end = ranges[begin]
    require(64 <= end-begin <= 16384, 'Unexpected completion size')
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64); md.detail = True
    ins = list(md.disasm(pe.get_data(begin, end-begin), begin))
    boundaries = {i.address for i in ins}
    require(sum(i.size for i in ins) == end-begin, 'Incomplete decode')
    require(all(r in boundaries for r, _ in refs[begin]), 'Anchor not at instruction boundary')

    def reg(o, name=None):
        return o.type == X86_OP_REG and (name is None or md.reg_name(o.reg) == name)
    def imm(o, n): return o.type == X86_OP_IMM and (o.imm & 0xffffffff) == (n & 0xffffffff)
    def same(a,b): return reg(a) and reg(b) and a.reg == b.reg
    def mem(o): return o.type == X86_OP_MEM and not o.mem.index
    accepted = []
    for k, call in enumerate(ins):
        if call.mnemonic != 'call' or call.operands[0].type != X86_OP_IMM or k < 8 or k+5 >= len(ins): continue
        w = ins[k-8:k+6]
        if [x.mnemonic for x in w] != ['test','jne','mov','xor','cmp','jne','mov','mov','call','xor','test','mov','cmovne','jmp']: continue
        a = [x.operands for x in w]
        result = a[0][0]
        if not (same(result,a[0][1]) and same(result,a[3][0]) and same(result,a[3][1])
                and same(result,a[11][0]) and imm(a[11][1],-380) and same(result,a[12][0])): continue
        if not (same(a[9][0],a[9][1]) and same(a[9][0],a[12][1]) and reg(a[10][0],'al') and reg(a[10][1],'al')): continue
        if not (reg(a[2][0]) and mem(a[2][1]) and mem(a[4][0]) and a[4][0].size == 1
                and a[4][0].mem.base == a[2][0].reg and imm(a[4][1],0)): continue
        if not (reg(a[6][0],'rcx') and reg(a[6][1]) and a[6][1].reg == a[2][1].mem.base
                and reg(a[7][0],'rdx') and reg(a[7][1])): continue
        join = a[1][0].imm
        if not (a[5][0].imm == join and a[13][0].imm == join and join in boundaries and join > w[-1].address): continue
        # Confirm the input result and this are preserved in these registers.
        if not any(i.mnemonic=='mov' and same(i.operands[0],result) and reg(i.operands[1],'edx') for i in ins[:16]): continue
        if not any(i.mnemonic=='mov' and same(i.operands[0],a[6][1]) and reg(i.operands[1],'rcx') for i in ins[:16]): continue
        # Reject outside branches into the middle of the recognized guard.
        if any(i.mnemonic.startswith('j') and i.operands[0].type==X86_OP_IMM
               and w[0].address < i.operands[0].imm <= w[-1].address
               and not w[0].address <= i.address <= w[-1].address for i in ins): continue
        target = call.operands[0].imm
        if target not in ranges: continue
        size = ranges[target]-target
        if not 16 <= size <= 8192: continue
        code = pe.get_data(target,size)
        callee = list(md.disasm(code,target))
        if not callee or callee[0].mnemonic in ('jmp','call','int3') or not any(i.mnemonic=='ret' for i in callee): continue
        if sum(i.size for i in callee) != size: continue
        accepted.append(dict(complete_rva=begin,complete_size=end-begin,allow_rva=target,allow_size=size,
            caller_return_rva=call.address+call.size,complete_hash=hashlib.sha256(pe.get_data(begin,end-begin)).hexdigest(),
            allow_hash=hashlib.sha256(code).hexdigest(),guard=[f'{i.mnemonic} {i.op_str}' for i in w]))
    require(len(accepted)==1, 'Guarded unknown-root call missing or ambiguous')
    return dict(schema=1,path=str(Path(path).resolve()),module_hash=hashlib.sha256(raw).hexdigest(),
                image_size=pe.OPTIONAL_HEADER.SizeOfImage,**accepted[0])

if __name__ == '__main__':
    print(json.dumps(locate(sys.argv[1]),indent=2))
