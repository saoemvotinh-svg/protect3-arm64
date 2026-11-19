"""ARM64 instruction execution with modeled Linux syscalls, NOT an Android VM."""

import struct

from unicorn import UC_ARCH_ARM64, UC_HOOK_INTR, UC_MODE_ARM, UC_PROT_ALL, Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X5,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X30,
)

from .elf import ELF, align


class Runner:
    """Self-contained AArch64 ELF execution harness backed by Unicorn Engine."""

    def __init__(self, data=None, blob=None, bias=0x10000000, page_size=4096, files=None, paths=(), deny_mprotect=False, dirs=None):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.bias = bias
        self.elf = ELF(data) if data else None
        self.files = {
            "/proc/self/status": b"Name:\ttest\nTracerPid:\t0\n",
            "/proc/self/maps": b"10000000-10010000 r-xp 00000000 00:00 1 /test/libsample.so\n",
            "/proc/cpuinfo": b"Processor: AArch64\nHardware: test\n",
            "/proc/self/auxv": struct.pack("<4Q", 6, page_size, 0, 0),
        }
        self.files.update(files or {})
        self.dirs = dict(dirs or {})
        self.paths = set(paths)
        self.clock_wall_ns = 1700000000_000000000
        self.clock_cpu_ns = 1000_000000
        self.descriptors = {}
        self.next_fd = 10
        self.exited = None
        self.log = bytearray()
        self.android_log = []
        self.sockets = set()
        self.protections = []
        self.madvise_calls = []
        self.mmap_cursor = 0x50000000
        self.mmaps = {}
        self.deny_mprotect = deny_mprotect
        if self.elf:
            minimum = min(s.vaddr for s in self.elf.loads) & -4096
            maximum = align(max(s.vaddr + s.memsz for s in self.elf.loads), 4096)
            self.uc.mem_map(bias + minimum, maximum - minimum, UC_PROT_ALL)
            for segment in self.elf.loads:
                self.uc.mem_write(bias + segment.vaddr, data[segment.offset:segment.offset + segment.filesz])
            self.relocate()
            for segment in self.elf.loads:
                perms = (1 if segment.flags & 4 else 0) | (2 if segment.flags & 2 else 0) | (4 if segment.flags & 1 else 0)
                start = (bias + segment.vaddr) & -4096
                end = align(bias + segment.vaddr + segment.memsz, 4096)
                self.uc.mem_protect(start, end - start, perms)
        else:
            self.uc.mem_map(bias, align(len(blob), 4096), UC_PROT_ALL)
            self.uc.mem_write(bias, blob)
        self.stack = 0x70000000
        self.uc.mem_map(self.stack, 0x20000, UC_PROT_ALL)
        self.scratch = 0x71000000
        self.uc.mem_map(self.scratch, 0x20000, UC_PROT_ALL)
        self.stop = 0x72000000
        self.uc.mem_map(self.stop, 4096, UC_PROT_ALL)
        self.uc.hook_add(UC_HOOK_INTR, self.syscall)

    def relocate(self):
        symbols = self.elf.symbols()
        for section in self.elf.sections:
            if section.type != 4:
                continue
            for offset in range(section.offset, section.offset + section.size, 24):
                address, info, addend = struct.unpack_from("<QQq", self.elf.data, offset)
                kind, index = info & 0xFFFFFFFF, info >> 32
                if kind == 1027:
                    value = self.bias + addend
                elif kind in (257, 1025, 1026) and symbols[index]["shndx"]:
                    value = self.bias + symbols[index]["value"] + addend
                else:
                    raise AssertionError(f"Unmodeled test relocation {kind}/{index}")
                self.uc.mem_write(self.bias + address, struct.pack("<Q", value))

    def string(self, pointer):
        result = bytearray()
        for _ in range(4096):
            value = self.uc.mem_read(pointer, 1)[0]
            if value == 0:
                return result.decode()
            result.append(value)
            pointer += 1
        raise AssertionError("Unterminated syscall path")

    def syscall(self, uc, number, _):
        n = uc.reg_read(UC_ARM64_REG_X8)
        registers = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5]
        a = [uc.reg_read(reg) for reg in registers]
        result = 0
        if n == 56:
            path = self.string(a[1])
            if path in self.dirs:
                result = self.next_fd
                self.next_fd += 1
                self.descriptors[result] = ["DIR", list(self.dirs[path]), 0]
            elif self.files.get(path) is None:
                result = -2
            else:
                result = self.next_fd
                self.next_fd += 1
                self.descriptors[result] = [self.files[path], 0]
        elif n == 61:
            desc = self.descriptors.get(a[0])
            if not desc or desc[0] != "DIR":
                result = -9
            else:
                names, idx = desc[1], desc[2]
                buf = bytearray()
                while idx < len(names):
                    nm = names[idx].encode() + b"\x00"
                    reclen = (19 + len(nm) + 7) & ~7
                    if len(buf) + reclen > a[2]:
                        break
                    rec = struct.pack("<QQHB", idx + 1, idx + 1, reclen, 4) + nm
                    rec += bytes(reclen - len(rec))
                    buf.extend(rec)
                    idx += 1
                desc[2] = idx
                if buf:
                    uc.mem_write(a[1], bytes(buf))
                result = len(buf)
        elif n == 63:
            data, offset = self.descriptors[a[0]]
            chunk = data[offset:offset + a[2]]
            if chunk:
                uc.mem_write(a[1], chunk)
            self.descriptors[a[0]][1] += len(chunk)
            result = len(chunk)
        elif n == 57:
            self.descriptors.pop(a[0], None)
        elif n == 48:
            result = 0 if self.string(a[1]) in self.paths else -2
        elif n == 64:
            if a[0] in self.sockets:
                self.android_log.append(bytes(uc.mem_read(a[1], a[2])))
            else:
                self.log.extend(uc.mem_read(a[1], a[2]))
            result = a[2]
        elif n == 94:
            self.exited = a[0]
            uc.emu_stop()
        elif n == 226:
            self.protections.append(tuple(a[:3]))
            if self.deny_mprotect:
                result = -13
            else:
                uc.mem_protect(a[0], a[1], a[2])
        elif n == 167:
            pass
        elif n == 198:
            result = self.next_fd
            self.next_fd += 1
            self.sockets.add(result)
        elif n == 203:
            result = 0
        elif n == 78:
            result = -2
        elif n == 113:
            if a[0] == 2:
                sec = self.clock_cpu_ns // 1_000_000_000
                nsec = self.clock_cpu_ns % 1_000_000_000
            else:
                sec = self.clock_wall_ns // 1_000_000_000
                nsec = self.clock_wall_ns % 1_000_000_000
            uc.mem_write(a[1], struct.pack("<qq", sec, nsec))
        elif n == 178:
            result = 1234
        elif n == 222:
            map_sz = align(max(4096, a[1]), 4096)
            addr = self.mmap_cursor
            self.uc.mem_map(addr, map_sz, UC_PROT_ALL)
            self.mmaps[addr] = map_sz
            self.mmap_cursor += map_sz + 0x10000
            result = addr
        elif n == 215:
            if a[0] in self.mmaps:
                self.uc.mem_unmap(a[0], self.mmaps.pop(a[0]))
            result = 0
        elif n == 233:
            self.madvise_calls.append(tuple(a[:3]))
            if a[2] == 4 and a[1] > 0:
                try:
                    uc.mem_write(a[0], bytes(min(a[1], 16 * 1024 * 1024)))
                except Exception:
                    pass
            result = 0
        else:
            raise AssertionError(f"Unmodeled ARM64 syscall: {n}")
        uc.reg_write(UC_ARM64_REG_X0, result & ((1 << 64) - 1))

    def call(self, address, *args):
        self.uc.reg_write(UC_ARM64_REG_SP, self.stack + 0x1FFF0)
        self.uc.reg_write(UC_ARM64_REG_X30, self.stop)
        registers = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5]
        for register, value in zip(registers, args):
            self.uc.reg_write(register, value)
        self.uc.emu_start(address, self.stop, timeout=20_000_000, count=50_000_000)
        return self.uc.reg_read(UC_ARM64_REG_X0)

    def initialize(self, argc=3):
        if self.elf.dynamic_value(12):
            self.call(self.bias + self.elf.dynamic_value(12), argc, self.scratch, self.scratch + 0x100)
        if self.exited is not None:
            return
        address, size = self.elf.dynamic_value(25), self.elf.dynamic_value(27)
        for offset in range(0, size, 8):
            function, = struct.unpack("<Q", self.uc.mem_read(self.bias + address + offset, 8))
            self.call(function, argc, self.scratch, self.scratch + 0x100)

    def exported(self, name, *args):
        symbol = next(s for s in self.elf.symbols() if s["name"] == name)
        return self.call(self.bias + symbol["value"], *args)
