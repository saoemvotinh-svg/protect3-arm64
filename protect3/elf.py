"""Bounded ELF64 reader. No third-party binary rewriting dependencies."""

from dataclasses import dataclass, replace
import hashlib
import struct


class ProtectionError(ValueError):
    pass


EHDR = struct.Struct("<16sHHIQQQIHHHHHH")
PHDR = struct.Struct("<IIQQQQQQ")
SHDR = struct.Struct("<IIQQQQIIQQ")
DYN = struct.Struct("<qQ")
SYM = struct.Struct("<IBBHQQ")
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_PHDR = 1, 2, 3, 6
PF_X, PF_W, PF_R = 1, 2, 4
SHT_NOBITS, SHT_DYNAMIC, SHT_DYNSYM = 8, 6, 11
DT_NULL, DT_INIT, DT_FLAGS = 0, 12, 30


def align(value, alignment):
    if alignment < 1 or alignment & (alignment - 1):
        raise ProtectionError("Invalid ELF alignment (must be a power of two).")
    return (value + alignment - 1) & -alignment


def bounded(data, offset, size, label):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ProtectionError(f"Truncated/out-of-range ELF {label}.")
    return data[offset:offset + size]


def cstring(data, offset):
    if not 0 <= offset < len(data):
        raise ProtectionError("Invalid ELF string offset.")
    end = data.find(b"\0", offset)
    if end < 0:
        raise ProtectionError("Unterminated ELF string.")
    return data[offset:end].decode("utf-8", errors="replace")


@dataclass(frozen=True)
class Segment:
    type: int
    flags: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    alignment: int

    def pack(self):
        return PHDR.pack(*self.__dict__.values())


@dataclass(frozen=True)
class Section:
    name_offset: int
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entsize: int
    name: str = ""

    def pack(self):
        return SHDR.pack(*(v for k, v in self.__dict__.items() if k != "name"))


def _has_stealth_guard_magic(elf):
    """Detect obfuscated per-build p3_config stealth headers without leaking ASCII markers."""
    for seg in elf.loads:
        if not (seg.flags & PF_X) or seg.filesz < 64:
            continue
        # Only inspect realistic guard/stub tail or head windows (<= 256 KiB)
        windows = []
        if seg.filesz <= 262144:
            windows.append((seg.offset, seg.offset + seg.filesz))
        else:
            windows.append((seg.offset, seg.offset + 131072))
            windows.append((seg.offset + seg.filesz - 131072, seg.offset + seg.filesz))
        for start, end in windows:
            pos = start
            limit = end - 32
            while pos <= limit:
                ver, = struct.unpack_from("<I", elf.data, pos + 24)
                if ver == 2:
                    salt = elf.data[pos:pos + 16]
                    tag = elf.data[pos + 16:pos + 24]
                    expected = hashlib.sha256(salt + b"\x50\x33\x47\x34\x02\x00\x00\x00").digest()[:8]
                    if tag == expected:
                        return True
                pos += 8
    return False


class ELF:
    def __init__(self, data):
        self.data = bytes(data)
        if len(data) < EHDR.size or data[:4] != b"\x7fELF":
            raise ProtectionError("Input is not an ELF shared library.")
        if data[4:7] != b"\x02\x01\x01":
            raise ProtectionError("This release accepts little-endian ELF64 only.")
        self.header = list(EHDR.unpack_from(data))
        (self.ident, self.type, self.machine, self.version, self.entry, self.phoff,
         self.shoff, self.flags, self.ehsize, self.phentsize, self.phnum,
         self.shentsize, self.shnum, self.shstrndx) = self.header
        if self.version != 1 or self.ehsize != EHDR.size:
            raise ProtectionError("Invalid ELF header version/size.")
        if not 0 < self.phnum < 1024 or self.phentsize != PHDR.size:
            raise ProtectionError("Invalid/extended program header table.")
        bounded(data, self.phoff, self.phnum * PHDR.size, "program headers")
        self.segments = [Segment(*PHDR.unpack_from(data, self.phoff + i * PHDR.size))
                         for i in range(self.phnum)]
        self.loads = [s for s in self.segments if s.type == PT_LOAD]
        if not self.loads:
            raise ProtectionError("ELF has no loadable segments.")
        for s in self.segments:
            bounded(data, s.offset, s.filesz, "segment")
            if s.type == PT_LOAD:
                if s.filesz > s.memsz or s.vaddr + s.memsz >= 1 << 64:
                    raise ProtectionError("Invalid load segment size/address.")
                if s.alignment > 1:
                    align(0, s.alignment)
                    if s.vaddr % s.alignment != s.offset % s.alignment:
                        raise ProtectionError("ELF load offset/address alignment mismatch.")
        for a, b in zip(sorted(self.loads, key=lambda s: s.vaddr),
                        sorted(self.loads, key=lambda s: s.vaddr)[1:]):
            if a.vaddr + a.memsz > b.vaddr:
                raise ProtectionError("Overlapping ELF load segments are unsupported.")
        self.sections = []
        if self.shoff:
            if (self.shentsize != SHDR.size or not 0 < self.shnum < 65535
                    or not 0 <= self.shstrndx < self.shnum):
                raise ProtectionError("Invalid/extended section header table.")
            bounded(data, self.shoff, self.shnum * SHDR.size, "section headers")
            self.sections = [Section(*SHDR.unpack_from(data, self.shoff + i * SHDR.size))
                             for i in range(self.shnum)]
            for s in self.sections:
                if s.type != SHT_NOBITS:
                    bounded(data, s.offset, s.size, "section")
            names = self.section_data(self.sections[self.shstrndx])
            self.sections = [replace(s, name=cstring(names, s.name_offset))
                             for s in self.sections]
        self.dynamic_segment = next((s for s in self.segments if s.type == PT_DYNAMIC), None)
        if sum(s.type == PT_DYNAMIC for s in self.segments) > 1:
            raise ProtectionError("Multiple dynamic segments are unsupported.")
        self.dynamic = []
        if self.dynamic_segment:
            s = self.dynamic_segment
            if s.filesz % DYN.size:
                raise ProtectionError("Invalid dynamic segment size.")
            for off in range(s.offset, s.offset + s.filesz, DYN.size):
                tag, value = DYN.unpack_from(data, off)
                if tag == DT_NULL:
                    break
                self.dynamic.append((tag, value))
            else:
                raise ProtectionError("ELF dynamic table has no DT_NULL terminator.")

    def section_data(self, section):
        return bounded(self.data, section.offset, section.size, section.name or "section")

    def section(self, name):
        return next((s for s in self.sections if s.name == name), None)

    def dynamic_value(self, tag, default=0):
        return next((value for key, value in self.dynamic if key == tag), default)

    def file_offset(self, vaddr, size=1):
        for s in self.loads:
            if s.vaddr <= vaddr and vaddr + size <= s.vaddr + s.filesz:
                return s.offset + vaddr - s.vaddr
        raise ProtectionError(f"Virtual address 0x{vaddr:x} is not file-backed.")

    def symbols(self, dynamic_only=True):
        result = []
        for section in self.sections:
            if section.type not in ((SHT_DYNSYM,) if dynamic_only else (2, SHT_DYNSYM)):
                continue
            if section.entsize != SYM.size or section.size % SYM.size:
                raise ProtectionError("Invalid symbol table size.")
            if not 0 <= section.link < len(self.sections):
                raise ProtectionError("Invalid symbol string table link.")
            strings = self.section_data(self.sections[section.link])
            for off in range(section.offset, section.offset + section.size, SYM.size):
                name, info, other, shndx, value, size = SYM.unpack_from(self.data, off)
                result.append(dict(name=cstring(strings, name), info=info, other=other,
                                   shndx=shndx, value=value, size=size))
        return result

    def exported_symbols(self):
        return sorted((s["name"], s["info"], s["other"], s["value"], s["size"])
                      for s in self.symbols() if s["shndx"] and s["info"] >> 4 in (1, 2, 10))

    def has_packed_android_relocs(self):
        return (
            any(tag in (0x6000000F, 0x60000011) for tag, _ in self.dynamic)
            or any(s.type in (0x60000001, 0x60000002) and s.size > 0 for s in self.sections)
        )

    def relr_addresses(self):
        """Decode all ELF64 SHT_RELR / DT_RELR relative relocation target virtual addresses."""
        blobs = []
        seen_ranges = set()
        for s in self.sections:
            if s.type in (19, 0x6FFFFF00) and s.size >= 8 and s.size % 8 == 0:
                blobs.append(self.section_data(s))
                seen_ranges.add((s.offset, s.size))
        for va_tag, sz_tag in ((36, 35), (0x6FFFE000, 0x6FFFE001)):
            rva, rsz = self.dynamic_value(va_tag), self.dynamic_value(sz_tag)
            if rva and rsz and rsz >= 8 and rsz % 8 == 0:
                try:
                    roff = self.file_offset(rva, rsz)
                    if (roff, rsz) not in seen_ranges:
                        blobs.append(bounded(self.data, roff, rsz, "DT_RELR"))
                        seen_ranges.add((roff, rsz))
                except ProtectionError:
                    pass
        addrs = []
        for raw in blobs:
            base = 0
            for (entry,) in struct.iter_unpack("<Q", raw):
                if (entry & 1) == 0:
                    addrs.append(entry)
                    base = entry + 8
                else:
                    bits = entry >> 1
                    for i in range(63):
                        if (bits >> i) & 1:
                            addrs.append(base + i * 8)
                    base += 63 * 8
        return sorted(set(addrs))

    def summary(self):
        from .hardening import audit_hardening
        strings = b""
        if self.dynamic_value(5) and self.dynamic_value(10):
            off = self.file_offset(self.dynamic_value(5), self.dynamic_value(10))
            strings = bounded(self.data, off, self.dynamic_value(10), "dynamic strings")
        symbols = self.exported_symbols()
        return {
            "format": "ELF64 little-endian", "architecture": {183: "arm64-v8a", 62: "x86_64"}.get(self.machine, str(self.machine)),
            "type": self.type, "size": len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "soname": cstring(strings, self.dynamic_value(14)) if self.dynamic_value(14) else None,
            "needed": [cstring(strings, value) for tag, value in self.dynamic if tag == 1],
            "export_count": len(symbols), "jni_exports": [s[0] for s in symbols if s[0].startswith("Java_") or s[0] == "JNI_OnLoad"],
            "load_segments": len(self.loads),
            "elf_16k_alignment": all(s.alignment >= 16384 and (s.vaddr - s.offset) % 16384 == 0 for s in self.loads),
            "debug_sections": [s.name for s in self.sections if s.name.startswith((".debug", ".zdebug"))],
            "has_symtab": any(s.type == 2 for s in self.sections),
            "has_rwx": any(s.flags & 3 == 3 for s in self.loads),
            "has_textrel": any(tag == 22 or tag == DT_FLAGS and value & 4 for tag, value in self.dynamic),
            "protected": (
                any(marker in self.data for marker in (b"PROTECT3-GUARD-v1", b"PROTECT3-GUARD-v2"))
                or _has_stealth_guard_magic(self)
            ),
            "native_hardening_audit":audit_hardening(self),
        }

    def validate_target(self, allow_protected=False):
        if self.type != 3 or self.machine != 183 or any(s.type == PT_INTERP for s in self.segments):
            raise ProtectionError("Protection requires an Android ARM64 ET_DYN shared library, not an executable.")
        if self.entry and any(s["name"] == "_start" and s["value"] == self.entry for s in self.symbols(False)):
            raise ProtectionError("Protection requires an Android ARM64 ET_DYN shared library, not an executable.")
        if not self.sections or not self.dynamic_segment or not self.section(".dynsym"):
            raise ProtectionError("A valid section/dynamic/symbol table is required by this release.")
        if not any(s.type == SHT_DYNAMIC for s in self.sections):
            raise ProtectionError("Missing SHT_DYNAMIC section.")
        if not allow_protected and self.summary()["protected"]:
            raise ProtectionError("This library already contains a Protect3 guard; use the original input.")
        if self.summary()["has_rwx"] or self.summary()["has_textrel"]:
            raise ProtectionError("RWX segments and text relocations are unsupported.")
        if self.dynamic_value(0x6FFFFFFB) & 0x08000000:
            raise ProtectionError("DF_1_PIE executable is unsupported.")
        if any(s.flags & 0x800 for s in self.sections):
            raise ProtectionError("SHF_COMPRESSED ELF sections are unsupported.")
        # Android still reads .dynamic through section headers. Keep both views consistent.
        dynamic_sections = [s for s in self.sections if s.type == SHT_DYNAMIC]
        if len(dynamic_sections) != 1 or dynamic_sections[0].offset != self.dynamic_segment.offset:
            raise ProtectionError("Inconsistent ELF dynamic section/program header.")

    def code_sections(self):
        spans = []
        for s in self.sections:
            if s.type != 1 or not s.size or s.flags & 6 != 6:
                continue
            if s.flags & 1:
                raise ProtectionError("Writable executable section is unsupported.")
            off = self.file_offset(s.addr, s.size)
            if off != s.offset or not any(p.flags & (PF_X | PF_R) == PF_X | PF_R and p.vaddr <= s.addr and s.addr + s.size <= p.vaddr + p.filesz for p in self.loads):
                raise ProtectionError("Executable section must be in a readable executable load segment; execute-only code is unsupported.")
            spans.append(s)
        if not spans or len(spans) > 32:
            raise ProtectionError("Expected between 1 and 32 executable sections.")
        for a, b in zip(sorted(spans, key=lambda s: s.addr), sorted(spans, key=lambda s: s.addr)[1:]):
            if a.addr + a.size > b.addr:
                raise ProtectionError("Overlapping code sections are unsupported.")
        return spans
