"""Execute the checked-in ARM64 bootstrap in Unicorn; no Windows runtime claim.

Dependency: Python unicorn. The API stubs check arguments and deliberately
clobber ABI-volatile registers, including all SIMD upper halves.
"""
import pathlib
import re
import struct
import unittest

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = (ROOT / 'src/remotecode/arm64/BootstrapBytes.h').read_text()
CODE = bytes(int(value, 16) for value in re.findall(r'0x([0-9a-f]{2})', HEADER))
OFFSETS = {key: int(value) for key, value in re.findall(r'(\w+)Offset = (\d+);', HEADER)}
BASE, DATA, API, STACK, STOP = 0x100000, 0x200000, 0x300000, 0x400000, 0x500000
X = [globals()['UC_ARM64_REG_X%d' % i] for i in range(31)]
Q = [globals()['UC_ARM64_REG_Q%d' % i] for i in range(32)]


class BootstrapTests(unittest.TestCase):
    def run_case(self, startup, load_ok=True, resolve_ok=True, hook_ok=True, continue_ok=True):
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for base in (BASE, DATA, API, STOP):
            cpu.mem_map(base, 0x1000)
        cpu.mem_map(STACK, 0x10000)
        code = bytearray(CODE)
        struct.pack_into('<Q', code, OFFSETS['ParameterAddress'], DATA)
        cpu.mem_write(BASE, bytes(code))
        params = bytearray(256)
        struct.pack_into('<4Q', params, 0, API, API + 4, API + 8, STOP)
        struct.pack_into('<HHIQ', params, 32, 10, 12, 0, DATA + 96)
        struct.pack_into('<HHIQ', params, 48, 13, 14, 0, DATA + 108)
        struct.pack_into('<Q', params, 64, DATA + 122)
        params[96:108] = 'x.dll\0'.encode('utf-16-le')
        params[108:122] = b'gp_HookWinsock\0'
        params[122:127] = b'pipe\0'
        cpu.mem_write(DATA, bytes(params))
        expected_x = [0x123400000000 + i * 0x101 for i in range(31)]
        expected_x[30] = STOP
        if not startup:
            expected_x[0] = DATA
        expected_q = [(0xfedcba9876543210 << 64) + i for i in range(32)]
        for reg, value in zip(X, expected_x):
            cpu.reg_write(reg, value)
        for reg, value in zip(Q, expected_q):
            cpu.reg_write(reg, value)
        original_sp = STACK + 0xf000
        cpu.reg_write(UC_ARM64_REG_SP, original_sp)
        cpu.reg_write(UC_ARM64_REG_NZCV, 0xa0000000)
        cpu.reg_write(UC_ARM64_REG_FPCR, 0x400000)
        cpu.reg_write(UC_ARM64_REG_FPSR, 0x10)
        calls = []
        captured = []

        def api_return(result):
            return_address = cpu.reg_read(X[30])
            for reg in X[:18]:
                cpu.reg_write(reg, 0xbad00000)
            for i, reg in enumerate(Q):
                # v8-v15 low 64 bits are callee saved; every upper half is volatile.
                low = cpu.reg_read(reg) & ((1 << 64) - 1) if 8 <= i <= 15 else 0xbad
                cpu.reg_write(reg, (0xdead << 64) | low)
            cpu.reg_write(UC_ARM64_REG_NZCV, 0)
            cpu.reg_write(UC_ARM64_REG_FPSR, 0)
            cpu.reg_write(X[0], result & 0xffffffff)
            cpu.reg_write(UC_ARM64_REG_PC, return_address)

        def intercept(uc, address, size, user_data):
            if address == STOP:
                calls.append('return')
                uc.emu_stop()
            elif API <= address <= API + 12:
                self.assertEqual(uc.reg_read(UC_ARM64_REG_SP) & 15, 0)
                self.assertEqual(uc.reg_read(X[18]), expected_x[18])
                if address == API:
                    calls.append('load')
                    self.assertEqual([uc.reg_read(r) for r in X[:4]], [0, 0, DATA + 32, DATA + 80])
                    uc.mem_write(DATA + 80, struct.pack('<Q', 0x98760000))
                    api_return(0 if load_ok else 0xc0000135)
                elif address == API + 4:
                    calls.append('resolve')
                    self.assertEqual([uc.reg_read(r) for r in X[:4]], [0x98760000, DATA + 48, 0, DATA + 88])
                    uc.mem_write(DATA + 88, struct.pack('<Q', API + 12))
                    api_return(0 if resolve_ok else 0xc0000139)
                elif address == API + 12:
                    calls.append('hook')
                    self.assertEqual(uc.reg_read(X[0]), DATA + 122)
                    api_return(int(hook_ok))
                else:
                    calls.append('continue')
                    self.assertEqual(uc.reg_read(X[1]), 0)
                    ctx = bytes(uc.mem_read(uc.reg_read(X[0]), 0x390))
                    captured.append(ctx)
                    if continue_ok:
                        uc.emu_stop()
                    else:
                        api_return(0xc000000d)
            # Stop just before the deliberate fail-fast breakpoint.
            elif bytes(uc.mem_read(address, 4)) == b'\x00\x00\x20\xd4':
                calls.append('failfast')
                uc.emu_stop()

        cpu.hook_add(UC_HOOK_CODE, intercept)
        cpu.emu_start(BASE + OFFSETS['Startup' if startup else 'Thread'], STOP + 4, count=1000)
        expected_calls = ['load'] + (['resolve'] if load_ok else [])
        if load_ok and resolve_ok:
            expected_calls += ['hook']
        expected_calls += ['continue'] if startup else ['return']
        if startup and not continue_ok:
            expected_calls += ['failfast']
        self.assertEqual(calls, expected_calls)
        state, status = struct.unpack('<II', cpu.mem_read(DATA + 72, 8))
        expected_state = 2 if not load_ok else 3 if not resolve_ok else 4 if not hook_ok else 5
        self.assertEqual(state, 6 if startup and not continue_ok else expected_state)
        expected_status = 0xc0000135 if not load_ok else 0xc0000139 if not resolve_ok else 0
        self.assertEqual(status, 0xc000000d if startup and not continue_ok else expected_status)
        if startup:
            ctx, = captured
            self.assertEqual(struct.unpack_from('<II', ctx), (0x400007, 0xa0000000))
            self.assertEqual(list(struct.unpack_from('<31Q', ctx, 8)), expected_x)
            self.assertEqual(struct.unpack_from('<QQ', ctx, 0x100), (original_sp, STOP))
            self.assertEqual([int.from_bytes(ctx[0x110+i*16:0x120+i*16], 'little') for i in range(32)], expected_q)
            self.assertEqual(struct.unpack_from('<II', ctx, 0x310), (0x400000, 0x10))
        else:
            self.assertEqual(cpu.reg_read(UC_ARM64_REG_SP), original_sp)
            self.assertEqual([cpu.reg_read(r) for r in X[18:]], expected_x[18:])
            self.assertEqual(cpu.reg_read(X[0]), int(load_ok and resolve_ok and hook_ok))
            for i in range(8, 16):
                self.assertEqual(cpu.reg_read(Q[i]) & ((1 << 64) - 1), expected_q[i] & ((1 << 64) - 1))

    def test_startup_paths(self):
        for options in ({}, {'load_ok': False}, {'resolve_ok': False}, {'hook_ok': False}, {'continue_ok': False}):
            with self.subTest(options=options):
                self.run_case(True, **options)

    def test_remote_thread_paths(self):
        for options in ({}, {'load_ok': False}, {'resolve_ok': False}, {'hook_ok': False}):
            with self.subTest(options=options):
                self.run_case(False, **options)


if __name__ == '__main__':
    unittest.main(verbosity=2)
