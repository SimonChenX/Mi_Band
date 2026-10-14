#!/usr/bin/env python3
"""Helper to analyse Huami Mi Band 6 ".fw" images.

Findings that make this work:

* the ``.fw`` file starts with a 0x400-byte container header, the image follows,
  so **address = file_offset - 0x400**;
* the payload is plain (not encrypted), full of log strings and source paths;
* the CPU is ARM Cortex-M running **Thumb** code.

Usage:
    python tools/fw_analyze.py PANGU_1.0.6.10.fw info
    python tools/fw_analyze.py PANGU_1.0.6.10.fw str motor       # list matching strings
    python tools/fw_analyze.py PANGU_1.0.6.10.fw refs 0x16feba   # code referencing an address
    python tools/fw_analyze.py PANGU_1.0.6.10.fw dis 0xcbf8 80   # disassemble
    python tools/fw_analyze.py PANGU_1.0.6.10.fw func 0xcbf8     # enclosing function + disasm
"""

from __future__ import annotations

import re
import struct
import sys

HEADER = 0x400

try:
    import capstone
    _MD = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
except Exception:  # pragma: no cover
    _MD = None


class Firmware:
    def __init__(self, path: str):
        self.path = path
        self.data = open(path, "rb").read()

    # -- address helpers ---------------------------------------------------
    def f2a(self, file_off: int) -> int:
        return file_off - HEADER

    def a2f(self, addr: int) -> int:
        return addr + HEADER

    # -- searching ---------------------------------------------------------
    def find_bytes(self, pattern: bytes) -> list[int]:
        out, start = [], 0
        while True:
            i = self.data.find(pattern, start)
            if i < 0:
                return out
            out.append(i)
            start = i + 1

    def find_string(self, needle: str, limit: int = 40) -> list[tuple[int, str]]:
        res = []
        for off in self.find_bytes(needle.encode()):
            start = self.data.rfind(b"\x00", 0, off) + 1
            end = self.data.find(b"\x00", off)
            res.append((off, self.data[start:end].decode("ascii", "replace")))
            if len(res) >= limit:
                break
        return res

    def refs(self, addr: int) -> list[int]:
        """File offsets of literal pointers to ``addr`` (all bases tried)."""
        hits = []
        for base in (0,):
            p = struct.pack("<I", addr + base)
            hits += self.find_bytes(p)
        return hits

    # -- disassembly -------------------------------------------------------
    def disasm(self, addr: int, count: int = 40, start_pad: int = 0):
        if _MD is None:
            print("capstone not installed")
            return
        start = addr - start_pad
        code = self.data[self.a2f(start): self.a2f(start) + count * 4 + 64]
        for ins in _MD.disasm(code, start):
            print("  0x%06x: %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
            count -= 1
            if count <= 0:
                break

    def function_start(self, addr: int, max_back: int = 0x800):
        """Heuristic: scan back for a push/str that opens a frame."""
        if _MD is None:
            return addr
        best = addr
        for back in range(0, max_back, 2):
            a = addr - back
            if a < 0:
                break
            code = self.data[self.a2f(a): self.a2f(a) + 16]
            ins = next(_MD.disasm(code, a), None)
            if ins and ins.mnemonic in ("push",) and "lr" in ins.op_str:
                best = a
            if ins and ins.mnemonic == "pop" and "pc" in ins.op_str:
                break
        return best


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 1
    fw = Firmware(argv[1])
    cmd = argv[2]
    args = argv[3:]
    if cmd == "info":
        print("file:", fw.path, "size:", hex(len(fw.data)))
        print("address = file_offset - 0x%x" % HEADER)
    elif cmd == "str":
        for off, s in fw.find_string(args[0]):
            print("  0x%06x (addr 0x%06x)  %r" % (off, fw.f2a(off), s))
    elif cmd == "refs":
        for off in fw.refs(int(args[0], 0)):
            print("  ref@0x%06x (addr 0x%06x)" % (off, fw.f2a(off)))
    elif cmd == "dis":
        fw.disasm(int(args[0], 0), int(args[1]) if len(args) > 1 else 40)
    elif cmd == "func":
        a = int(args[0], 0)
        s = fw.function_start(a)
        print("function start ~0x%06x" % s)
        fw.disasm(s, int(args[1]) if len(args) > 1 else 120)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))