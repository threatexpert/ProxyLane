"""MSAA and window-message probe for the native chain cards; no global input."""
import ctypes as C
from ctypes import wintypes as W
import time
import uuid
from ExitWarningE2ETests import USER, wait_for

OLE = C.OleDLL('ole32')
OLE.CoInitialize(None)
ACC = C.OleDLL('oleacc')
AUTO = C.OleDLL('oleaut32')
AUTO.SysFreeString.argtypes = [C.c_void_p]


class Payload(C.Union):
    _fields_ = [('number', W.LONG), ('pointer', C.c_void_p), ('record', C.c_void_p * 2)]


class Variant(C.Structure):
    _anonymous_ = ['value']
    _fields_ = [('vt', W.USHORT), ('reserved', W.USHORT * 3), ('value', Payload)]


class ChainView:
    def __init__(self, window, locale):
        self.window, self.locale = window, locale
        self.pointer = C.c_void_p()
        iid = (C.c_byte * 16).from_buffer_copy(uuid.UUID('618736e0-3c3d-11cf-810c-00aa00389b71').bytes_le)
        ACC.AccessibleObjectFromWindow.argtypes = [W.HWND, W.DWORD, C.c_void_p, C.POINTER(C.c_void_p)]
        result = ACC.AccessibleObjectFromWindow(window, 0xfffffffc, iid, C.byref(self.pointer))
        assert result == 0 and self.pointer
        self.table = C.cast(self.pointer, C.POINTER(C.POINTER(C.c_void_p))).contents

    def call(self, slot, types, *args):
        function = C.WINFUNCTYPE(W.LONG, C.c_void_p, *types)(self.table[slot])
        result = function(self.pointer, *args)
        assert result >= 0, (slot, hex(result & 0xffffffff))
        return result

    def child(self, row):
        v = Variant(vt=3)
        v.number = row + 1
        return v

    def string(self, slot, row):
        out = C.c_void_p()
        self.call(slot, [Variant, C.POINTER(C.c_void_p)], self.child(row), C.byref(out))
        try:
            return C.wstring_at(out) if out else ''
        finally:
            AUTO.SysFreeString(out)

    def count(self):
        out = W.LONG()
        self.call(8, [C.POINTER(W.LONG)], C.byref(out))
        return out.value

    def description(self, row):
        return self.string(12, row)

    def cell(self, row, column=3):
        if column == 1:
            return self.string(10, row)
        lines = self.description(row).splitlines()
        if column == 2:
            return lines[0]
        if column == 3:
            return lines[3] if len(lines) > 4 else ''
        if column == 4:
            prefix = self.locale['chain.test.node_elapsed'].split('%s')[0]
            return next((s[len(prefix):] for s in lines if s.startswith(prefix)), '—')
        raise ValueError(column)

    def state(self, row):
        out = Variant()
        self.call(14, [Variant, C.POINTER(Variant)], self.child(row), C.byref(out))
        return out.number

    def visible(self, row):
        return not (self.state(row) & 0x10000)

    def top(self):
        return next(i for i in range(self.count()) if self.visible(i))

    def selected(self):
        out = Variant()
        self.call(19, [C.POINTER(Variant)], C.byref(out))
        return out.number - 1 if out.vt == 3 else -1

    def select(self, row):
        self.call(21, [W.LONG, Variant], 3, self.child(row))
        time.sleep(.22)  # The control uses the launcher's 180 ms snap animation.

    def rect(self, row):
        x, y, width, height = (W.LONG() for _ in range(4))
        self.call(22, [C.POINTER(W.LONG)] * 4 + [Variant], C.byref(x), C.byref(y), C.byref(width), C.byref(height), self.child(row))
        point = W.POINT(x.value, y.value)
        USER.ScreenToClient.argtypes = [W.HWND, C.POINTER(W.POINT)]
        USER.ScreenToClient(self.window, C.byref(point))
        return point.x, point.y, width.value, height.value

    def point(self, message, x, y):
        USER.SendMessageW(self.window, message, 0 if message == 0x202 else 1, (x & 0xffff) | ((y & 0xffff) << 16))

    def edit(self, double=False):
        if double:
            x, y, width, height = self.rect(self.selected())
            # Post because opening the existing dialog enters a modal loop.
            USER.PostMessageW(self.window, 0x203, 1, ((x + width // 2) & 0xffff) | (((y + height // 2) & 0xffff) << 16))
        else:
            USER.PostMessageW(self.window, 0x100, 13, 0)

    def first_page(self):
        for _ in range(self.count()):
            USER.SendMessageW(self.window, 0x100, 0x21, 0)  # Page Up
        time.sleep(.22)

    def move_before(self, row, target):
        assert target < row
        self.move_to(row, target)

    def move_to(self, row, target, right_half=False, preview=None):
        self.select(row)
        x, y, _, _ = self.rect(row)
        USER.GetDpiForWindow.argtypes = [W.HWND]
        scale = USER.GetDpiForWindow(self.window) / 96
        self.point(0x201, x + int(12 * scale), y + int(10 * scale))
        if not self.visible(target):
            client = W.RECT()
            USER.GetClientRect.argtypes = [W.HWND, C.POINTER(W.RECT)]
            USER.GetClientRect(self.window, C.byref(client))
            self.point(0x200, 1 if target < row else client.right - 1, y + int(30 * scale))
            wait_for(lambda: self.visible(target), 'cross-page reorder edge dwell')
        x, y, width, height = self.rect(target)
        drop_x = x + width - int(8 * scale) if right_half else x + int(8 * scale)
        self.point(0x200, drop_x, y + height // 2)
        if preview:
            preview()
        self.point(0x202, drop_x, y + height // 2)
        time.sleep(.22)

    def close(self):
        if self.pointer:
            self.call(2, [])
            self.pointer = None
