"""ARM64 instruction decoder, relocator (F02) and function boundary recovery (F01)."""

from dataclasses import dataclass, field
import struct

from .elf import ProtectionError, bounded


def _sext(val, bits):
    sign = 1 << (bits - 1)
    return (val & (sign - 1)) - (val & sign)


def decode_bitmask_imm(sf, n, imms, immr):
    """Decode ARM64 logical immediate (N:imms:immr) to a 32/64-bit integer."""
    combined = (n << 6) | (~imms & 0x3F)
    if combined == 0:
        return None
    len_bit = combined.bit_length() - 1
    if len_bit < 1:
        return None
    esize = 1 << len_bit
    levels = esize - 1
    s = imms & levels
    r = immr & levels
    if s == levels:
        return None
    welem = (1 << (s + 1)) - 1
    if r:
        welem = ((welem >> r) | (welem << (esize - r))) & ((1 << esize) - 1)
    width = 64 if sf else 32
    result = 0
    for shift in range(0, width, esize):
        result |= welem << shift
    return result & ((1 << width) - 1)


@dataclass(frozen=True)
class Instruction:
    va: int
    raw: int
    mnemonic: str
    op_class: str  # branch, cond_branch, pc_rel, call, ret, br, alu, mem, pair, hint, other
    rd: int = -1
    rn: int = -1
    rm: int = -1
    ra: int = -1
    width: int = 64
    imm: int = 0
    cond: int = 0
    shift_type: int = 0
    shift_amount: int = 0
    target: int | None = None
    flags_set: bool = False
    flags_used: bool = False
    mem_size: int = 0
    mem_signed: bool = False
    mem_mode: int = 0  # 0=offset, 1=pre, 2=post


def decode_insn(va, raw):
    """Decode a 32-bit AArch64 instruction into structured semantics."""
    if raw == 0xD503201F:
        return Instruction(va, raw, "nop", "hint")
    if (raw & 0xFFFFF01F) == 0xD503201F:
        return Instruction(va, raw, "hint", "hint", imm=(raw >> 5) & 0x7F)
    # System register read/write: MRS / MSR (e.g., tpidr_el0 for Android stack canary)
    if (raw & 0xFFF00000) == 0xD5300000:
        return Instruction(va, raw, "mrs", "sys", rd=raw & 0x1F, imm=(raw >> 5) & 0x7FFF)
    if (raw & 0xFFF00000) == 0xD5100000:
        return Instruction(va, raw, "msr", "sys", rn=raw & 0x1F, imm=(raw >> 5) & 0x7FFF)
    # Unconditional branch immediate: B / BL
    if (raw & 0x7C000000) == 0x14000000:
        is_bl = bool(raw & 0x80000000)
        offset = _sext(raw & 0x03FFFFFF, 26) * 4
        return Instruction(va, raw, "bl" if is_bl else "b", "call" if is_bl else "branch",
                           target=va + offset, imm=offset)
    # Conditional branch: B.cond
    if (raw & 0xFF000010) == 0x54000000:
        offset = _sext((raw >> 5) & 0x7FFFF, 19) * 4
        cond = raw & 0xF
        return Instruction(va, raw, "b.cond", "cond_branch", cond=cond,
                           target=va + offset, imm=offset, flags_used=True)
    # Compare and branch: CBZ / CBNZ
    if (raw & 0x7E000000) == 0x34000000:
        sf = (raw >> 31) & 1
        is_nz = (raw >> 24) & 1
        offset = _sext((raw >> 5) & 0x7FFFF, 19) * 4
        rt = raw & 0x1F
        return Instruction(va, raw, "cbnz" if is_nz else "cbz", "cond_branch",
                           rd=rt, width=64 if sf else 32, cond=is_nz,
                           target=va + offset, imm=offset)
    # Test bit and branch: TBZ / TBNZ
    if (raw & 0x7E000000) == 0x36000000:
        is_nz = (raw >> 24) & 1
        bit = (((raw >> 31) & 1) << 5) | ((raw >> 19) & 0x1F)
        offset = _sext((raw >> 5) & 0x3FFF, 14) * 4
        rt = raw & 0x1F
        return Instruction(va, raw, "tbnz" if is_nz else "tbz", "cond_branch",
                           rd=rt, width=64 if bit >= 32 else 32, cond=is_nz,
                           shift_amount=bit, target=va + offset, imm=offset)
    # Unconditional branch register: BR / BLR / RET
    if (raw & 0xFE1FFC1F) == 0xD61F0000:
        opc = (raw >> 21) & 0x3
        rn = (raw >> 5) & 0x1F
        if opc == 0:
            return Instruction(va, raw, "br", "br", rn=rn)
        if opc == 1:
            return Instruction(va, raw, "blr", "call", rn=rn)
        if opc == 2:
            return Instruction(va, raw, "ret", "ret", rn=rn)
    # PC-relative addressing: ADR / ADRP
    if (raw & 0x1F000000) == 0x10000000:
        is_adrp = bool(raw & 0x80000000)
        immlo = (raw >> 29) & 0x3
        immhi = (raw >> 5) & 0x7FFFF
        imm = _sext((immhi << 2) | immlo, 21)
        rd = raw & 0x1F
        if is_adrp:
            target = (va & ~0xFFF) + (imm << 12)
            return Instruction(va, raw, "adrp", "pc_rel", rd=rd, target=target, imm=imm << 12)
        target = va + imm
        return Instruction(va, raw, "adr", "pc_rel", rd=rd, target=target, imm=imm)
    # Move wide immediate: MOVN / MOVZ / MOVK
    if (raw & 0x1F800000) == 0x12800000:
        sf = (raw >> 31) & 1
        opc = (raw >> 29) & 0x3
        hw = (raw >> 21) & 0x3
        imm16 = (raw >> 5) & 0xFFFF
        rd = raw & 0x1F
        if sf == 0 and hw >= 2:
            return Instruction(va, raw, "unknown", "other")
        shift = hw * 16
        if opc == 0:  # MOVN
            val = ~(imm16 << shift) & ((1 << (64 if sf else 32)) - 1)
            return Instruction(va, raw, "movn", "alu", rd=rd, width=64 if sf else 32, imm=val, shift_amount=shift)
        if opc == 2:  # MOVZ
            val = imm16 << shift
            return Instruction(va, raw, "movz", "alu", rd=rd, width=64 if sf else 32, imm=val, shift_amount=shift)
        if opc == 3:  # MOVK
            return Instruction(va, raw, "movk", "alu", rd=rd, width=64 if sf else 32, imm=imm16, shift_amount=shift)
    # Add/subtract immediate: ADD / ADDS / SUB / SUBS
    if (raw & 0x1F000000) == 0x11000000:
        sf = (raw >> 31) & 1
        op = (raw >> 30) & 1
        s = (raw >> 29) & 1
        sh = (raw >> 22) & 1
        if (raw >> 23) & 1:
            return Instruction(va, raw, "unknown", "other")
        imm12 = (raw >> 10) & 0xFFF
        rn = (raw >> 5) & 0x1F
        rd = raw & 0x1F
        imm = imm12 << (12 if sh else 0)
        mnem = ("sub" if op else "add") + ("s" if s else "")
        return Instruction(va, raw, mnem, "alu", rd=rd, rn=rn, width=64 if sf else 32,
                           imm=imm, flags_set=bool(s))
    # Logical immediate: AND / ORR / EOR / ANDS
    if (raw & 0x1F800000) == 0x12000000:
        sf = (raw >> 31) & 1
        opc = (raw >> 29) & 0x3
        n = (raw >> 22) & 1
        if sf == 0 and n == 1:
            return Instruction(va, raw, "unknown", "other")
        immr = (raw >> 16) & 0x3F
        imms = (raw >> 10) & 0x3F
        rn = (raw >> 5) & 0x1F
        rd = raw & 0x1F
        mask = decode_bitmask_imm(sf, n, imms, immr)
        if mask is None:
            return Instruction(va, raw, "unknown", "other")
        mnem = ("and", "orr", "eor", "ands")[opc]
        return Instruction(va, raw, mnem + "_imm", "alu", rd=rd, rn=rn,
                           width=64 if sf else 32, imm=mask, flags_set=(opc == 3))
    # Bitfield: SBFM / BFM / UBFM
    if (raw & 0x1F800000) == 0x13000000:
        sf = (raw >> 31) & 1
        opc = (raw >> 29) & 0x3
        n = (raw >> 22) & 1
        if sf != n or opc > 2:
            return Instruction(va, raw, "unknown", "other")
        immr = (raw >> 16) & 0x3F
        imms = (raw >> 10) & 0x3F
        rn = (raw >> 5) & 0x1F
        rd = raw & 0x1F
        mnem = ("sbfm", "bfm", "ubfm")[opc]
        return Instruction(va, raw, mnem, "alu", rd=rd, rn=rn, width=64 if sf else 32,
                           cond=opc, shift_amount=(immr << 6) | imms)
    # Add/subtract extended register: ADD / ADDS / SUB / SUBS
    if (raw & 0x1FE00000) == 0x0B200000:
        sf = (raw >> 31) & 1
        op = (raw >> 30) & 1
        s = (raw >> 29) & 1
        rm = (raw >> 16) & 0x1F
        option = (raw >> 13) & 0x7
        imm3 = (raw >> 10) & 0x7
        rn = (raw >> 5) & 0x1F
        rd = raw & 0x1F
        if imm3 <= 4:
            mnem = ("sub" if op else "add") + ("s" if s else "") + "_ext"
            return Instruction(va, raw, mnem, "alu", rd=rd, rn=rn, rm=rm,
                               width=64 if sf else 32, cond=option, shift_amount=imm3,
                               flags_set=bool(s))
    # Add/subtract shifted register: ADD / ADDS / SUB / SUBS
    if (raw & 0x1F200000) == 0x0B000000:
        sf = (raw >> 31) & 1
        op = (raw >> 30) & 1
        s = (raw >> 29) & 1
        shift = (raw >> 22) & 0x3
        if shift == 3:
            return Instruction(va, raw, "unknown", "other")
        rm = (raw >> 16) & 0x1F
        imm6 = (raw >> 10) & 0x3F
        rn = (raw >> 5) & 0x1F
        rd = raw & 0x1F
        if sf == 0 and imm6 >= 32:
            return Instruction(va, raw, "unknown", "other")
        mnem = ("sub" if op else "add") + ("s" if s else "") + "_reg"
        return Instruction(va, raw, mnem, "alu", rd=rd, rn=rn, rm=rm,
                           width=64 if sf else 32, shift_type=shift, shift_amount=imm6,
                           flags_set=bool(s))
    # Logical shifted register: AND / BIC / ORR / ORN / EOR / EON / ANDS
    if (raw & 0x1F000000) == 0x0A000000:
        sf = (raw >> 31) & 1
        opc = (raw >> 29) & 0x3
        shift = (raw >> 22) & 0x3
        inv = (raw >> 21) & 1
        rm = (raw >> 16) & 0x1F
        imm6 = (raw >> 10) & 0x3F
        rn = (raw >> 5) & 0x1F
        rd = raw & 0x1F
        if sf == 0 and imm6 >= 32:
            return Instruction(va, raw, "unknown", "other")
        table = {(0, 0): "and_reg", (0, 1): "bic_reg", (1, 0): "orr_reg", (1, 1): "orn_reg",
                 (2, 0): "eor_reg", (2, 1): "eon_reg", (3, 0): "ands_reg"}
        mnem = table.get((opc, inv))
        if not mnem:
            return Instruction(va, raw, "unknown", "other")
        return Instruction(va, raw, mnem, "alu", rd=rd, rn=rn, rm=rm,
                           width=64 if sf else 32, shift_type=shift, shift_amount=imm6,
                           flags_set=(opc == 3))
    # Data-processing (2 source): UDIV / SDIV / LSLV / LSRV / ASRV / RORV
    if (raw & 0x5FE00000) == 0x1AC00000:
        sf = (raw >> 31) & 1
        rm = (raw >> 16) & 0x1F
        opcode = (raw >> 10) & 0x3F
        rn = (raw >> 5) & 0x1F
        rd = raw & 0x1F
        ops = {2: "udiv", 3: "sdiv", 8: "lslv", 9: "lsrv", 10: "asrv", 11: "rorv"}
        if opcode in ops:
            return Instruction(va, raw, ops[opcode], "alu", rd=rd, rn=rn, rm=rm, width=64 if sf else 32)
    # Data-processing (3 source): MADD / MSUB
    if (raw & 0x7FE00000) == 0x1B000000:
        sf = (raw >> 31) & 1
        rm = (raw >> 16) & 0x1F
        o0 = (raw >> 15) & 1
        ra = (raw >> 10) & 0x1F
        rn = (raw >> 5) & 0x1F
        rd = raw & 0x1F
        return Instruction(va, raw, "msub" if o0 else "madd", "alu",
                           rd=rd, rn=rn, rm=rm, ra=ra, width=64 if sf else 32)
    # Conditional select: CSEL / CSINC / CSINV / CSNEG
    if (raw & 0x1FE00000) == 0x1A800000:
        sf = (raw >> 31) & 1
        op = (raw >> 30) & 1
        s = (raw >> 29) & 1
        rm = (raw >> 16) & 0x1F
        cond = (raw >> 12) & 0xF
        op2 = (raw >> 10) & 0x3
        rn = (raw >> 5) & 0x1F
        rd = raw & 0x1F
        if s == 0 and op2 in (0, 1):
            kind = (op << 1) | op2
            mnem = ("csel", "csinc", "csinv", "csneg")[kind]
            return Instruction(va, raw, mnem, "alu", rd=rd, rn=rn, rm=rm,
                               width=64 if sf else 32, cond=cond, shift_amount=kind, flags_used=True)
    # Load/store register pair (offset / pre / post): LDP / STP
    if (raw & 0x3E000000) == 0x28000000:
        opc = (raw >> 30) & 0x3
        v = (raw >> 26) & 1
        mode_bits = (raw >> 23) & 0x3
        l_bit = (raw >> 22) & 1
        imm7 = _sext((raw >> 15) & 0x7F, 7)
        rt2 = (raw >> 10) & 0x1F
        rn = (raw >> 5) & 0x1F
        rt = raw & 0x1F
        if v == 0 and mode_bits in (1, 2, 3) and opc in (0, 1, 2):
            if opc == 1 and not l_bit:
                return Instruction(va, raw, "unknown", "other")
            scale = 8 if opc == 2 else 4
            mode = {2: 0, 3: 1, 1: 2}[mode_bits]
            return Instruction(va, raw, "ldp" if l_bit else "stp", "pair",
                               rd=rt, rn=rn, rm=rt2, width=64 if opc == 2 else 32,
                               imm=imm7 * scale, mem_size=scale, mem_signed=(opc == 1), mem_mode=mode)
    # Load/store register (unsigned immediate): LDR / STR / LDRB / STRB / LDRH / STRH / LDRSB / LDRSH / LDRSW
    if (raw & 0x3B000000) == 0x39000000:
        size = (raw >> 30) & 0x3
        v = (raw >> 26) & 1
        opc = (raw >> 22) & 0x3
        imm12 = (raw >> 10) & 0xFFF
        rn = (raw >> 5) & 0x1F
        rt = raw & 0x1F
        if v == 0:
            scale = 1 << size
            offset = imm12 * scale
            if opc == 0:
                return Instruction(va, raw, "str", "mem", rd=rt, rn=rn,
                                   width=64 if size == 3 else 32, imm=offset, mem_size=scale, mem_mode=0)
            if opc == 1:
                return Instruction(va, raw, "ldr", "mem", rd=rt, rn=rn,
                                   width=64 if size == 3 else 32, imm=offset, mem_size=scale, mem_mode=0)
            if opc in (2, 3) and size < 3:
                if opc == 3 and size == 2:
                    return Instruction(va, raw, "unknown", "other")
                return Instruction(va, raw, "ldrs", "mem", rd=rt, rn=rn,
                                   width=64 if opc == 2 else 32, imm=offset,
                                   mem_size=scale, mem_signed=True, mem_mode=0)
    # Load/store register (unscaled immediate / pre-index / post-index)
    if (raw & 0x3B200000) == 0x38000000:
        size = (raw >> 30) & 0x3
        v = (raw >> 26) & 1
        opc = (raw >> 22) & 0x3
        imm9 = _sext((raw >> 12) & 0x1FF, 9)
        mode_bits = (raw >> 10) & 0x3
        rn = (raw >> 5) & 0x1F
        rt = raw & 0x1F
        if v == 0 and mode_bits in (0, 1, 3):
            scale = 1 << size
            mode = {0: 0, 3: 1, 1: 2}[mode_bits]
            if opc == 0:
                return Instruction(va, raw, "str", "mem", rd=rt, rn=rn,
                                   width=64 if size == 3 else 32, imm=imm9, mem_size=scale, mem_mode=mode)
            if opc == 1:
                return Instruction(va, raw, "ldr", "mem", rd=rt, rn=rn,
                                   width=64 if size == 3 else 32, imm=imm9, mem_size=scale, mem_mode=mode)
            if opc in (2, 3) and size < 3 and not (opc == 3 and size == 2):
                return Instruction(va, raw, "ldrs", "mem", rd=rt, rn=rn,
                                   width=64 if opc == 2 else 32, imm=imm9,
                                   mem_size=scale, mem_signed=True, mem_mode=mode)
    # Load/store register (register offset): LDR / STR / LDRB / STRB / LDRH / STRH / LDRSB / LDRSH / LDRSW
    if (raw & 0x3B200C00) == 0x38200800:
        size = (raw >> 30) & 0x3
        v = (raw >> 26) & 1
        opc = (raw >> 22) & 0x3
        rm = (raw >> 16) & 0x1F
        option = (raw >> 13) & 0x7
        s_bit = (raw >> 12) & 1
        rn = (raw >> 5) & 0x1F
        rt = raw & 0x1F
        if v == 0 and (option & 2):
            scale = 1 << size
            sh = size if s_bit else 0
            if opc == 0:
                return Instruction(va, raw, "str_reg", "mem", rd=rt, rn=rn, rm=rm,
                                   width=64 if size == 3 else 32, cond=option,
                                   shift_amount=sh, mem_size=scale)
            if opc == 1:
                return Instruction(va, raw, "ldr_reg", "mem", rd=rt, rn=rn, rm=rm,
                                   width=64 if size == 3 else 32, cond=option,
                                   shift_amount=sh, mem_size=scale)
            if opc in (2, 3) and size < 3 and not (opc == 3 and size == 2):
                return Instruction(va, raw, "ldrs_reg", "mem", rd=rt, rn=rn, rm=rm,
                                   width=64 if opc == 2 else 32, cond=option,
                                   shift_amount=sh, mem_size=scale, mem_signed=True)
        if v == 1 and opc in (0, 1) and (option & 2):
            return Instruction(va, raw, "simd_insn", "other", rn=rn, rm=rm)
    # PC-relative literal load: LDR (literal) GPR or SIMD
    if (raw & 0x3B000000) == 0x18000000:
        opc = (raw >> 30) & 0x3
        v = (raw >> 26) & 1
        imm19 = _sext((raw >> 5) & 0x7FFFF, 19) * 4
        rt = raw & 0x1F
        if v == 0 and opc in (0, 1, 2):
            return Instruction(va, raw, "ldr_lit", "pc_rel", rd=rt,
                               width=64 if opc >= 1 else 32, target=va + imm19, imm=imm19,
                               mem_size=8 if opc == 1 else 4, mem_signed=(opc == 2))
        return Instruction(va, raw, "unknown", "other")
    # Non-PC-relative SIMD/FP arithmetic, moves, non-literal loads/stores, and barriers
    if (raw & 0x0E000000) in (0x0E000000,) and (raw & 0x3F000000) != 0x1C000000:
        if (raw & 0x1E000000) == 0x0E000000 or (raw & 0x5E000000) == 0x1E000000:
            # Conservatively mark low 5-bit fields rd/rn/rm and flags_set (for FCMP/FCCMP/FMOV/INS)
            # so scratch-register allocation (x9..x14) and flag liveness never clobber GPR/NZCV operands.
            is_fp_scalar = (raw & 0x5E000000) == 0x1E000000
            return Instruction(va, raw, "simd_insn", "other",
                               rd=raw & 0x1F, rn=(raw >> 5) & 0x1F, rm=(raw >> 16) & 0x1F,
                               flags_set=is_fp_scalar)
    if (raw & 0x3B000000) in (0x39000000, 0x38000000) and ((raw >> 26) & 1) == 1:
        rn = (raw >> 5) & 0x1F
        return Instruction(va, raw, "simd_insn", "other", rn=rn)
    if (raw & 0x3E000000) == 0x28000000 and ((raw >> 26) & 1) == 1:
        rn = (raw >> 5) & 0x1F
        return Instruction(va, raw, "simd_insn", "other", rn=rn)
    if (raw & 0xBF400000) in (0x0C000000, 0x0C400000):
        rn = (raw >> 5) & 0x1F
        rm = (raw >> 16) & 0x1F
        return Instruction(va, raw, "simd_insn", "other", rn=rn, rm=rm)
    if (raw & 0xFFFFF01F) == 0xD503301F:  # DSB / DMB / ISB / CLREX
        return Instruction(va, raw, "barrier", "hint")
    return Instruction(va, raw, "unknown", "other")


def encode_b(from_va, to_va, link=False):
    delta = to_va - from_va
    if delta % 4 or not -(1 << 27) <= delta < (1 << 27):
        raise ProtectionError(f"ARM64 branch displacement out of ±128 MiB range: {from_va:#x} -> {to_va:#x}")
    opcode = 0x94000000 if link else 0x14000000
    return opcode | ((delta >> 2) & 0x03FFFFFF)


def encode_bcond(from_va, to_va, cond):
    delta = to_va - from_va
    if delta % 4 or not -(1 << 20) <= delta < (1 << 20):
        raise ProtectionError(f"ARM64 conditional branch out of ±1 MiB range: {from_va:#x} -> {to_va:#x}")
    return 0x54000000 | (((delta >> 2) & 0x7FFFF) << 5) | (cond & 0xF)


def encode_cbz(from_va, to_va, rt, width=64, is_nz=False):
    delta = to_va - from_va
    if delta % 4 or not -(1 << 20) <= delta < (1 << 20):
        raise ProtectionError(f"ARM64 CBZ/CBNZ out of ±1 MiB range: {from_va:#x} -> {to_va:#x}")
    sf = 1 if width == 64 else 0
    return (sf << 31) | 0x34000000 | ((1 if is_nz else 0) << 24) | (((delta >> 2) & 0x7FFFF) << 5) | (rt & 0x1F)


def encode_tbz(from_va, to_va, rt, bit, is_nz=False):
    delta = to_va - from_va
    if delta % 4 or not -(1 << 15) <= delta < (1 << 15):
        raise ProtectionError(f"ARM64 TBZ/TBNZ out of ±32 KiB range: {from_va:#x} -> {to_va:#x}")
    b5 = (bit >> 5) & 1
    b40 = bit & 0x1F
    return (b5 << 31) | 0x36000000 | ((1 if is_nz else 0) << 24) | (b40 << 19) | (((delta >> 2) & 0x3FFF) << 5) | (rt & 0x1F)


def encode_adr(from_va, to_va, rd):
    delta = to_va - from_va
    if not -(1 << 20) <= delta < (1 << 20):
        raise ProtectionError(f"ARM64 ADR displacement out of ±1 MiB range: {from_va:#x} -> {to_va:#x}")
    imm = delta & 0x1FFFFF
    immlo = imm & 0x3
    immhi = (imm >> 2) & 0x7FFFF
    return 0x10000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)


def encode_adrp(from_va, to_va, rd):
    page_delta = ((to_va & ~0xFFF) - (from_va & ~0xFFF)) >> 12
    if not -(1 << 20) <= page_delta < (1 << 20):
        raise ProtectionError(f"ARM64 ADRP displacement out of ±4 GiB range: {from_va:#x} -> {to_va:#x}")
    imm = page_delta & 0x1FFFFF
    immlo = imm & 0x3
    immhi = (imm >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)


def encode_add_imm(rd, rn, imm12, width=64, shift12=False, set_flags=False):
    sf = 1 if width == 64 else 0
    s = 1 if set_flags else 0
    sh = 1 if shift12 else 0
    return (sf << 31) | (s << 29) | 0x11000000 | (sh << 22) | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def encode_sub_imm(rd, rn, imm12, width=64, shift12=False, set_flags=False):
    sf = 1 if width == 64 else 0
    s = 1 if set_flags else 0
    sh = 1 if shift12 else 0
    return (sf << 31) | 0x40000000 | (s << 29) | 0x11000000 | (sh << 22) | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def encode_movz(rd, imm16, hw=0, width=64):
    sf = 1 if width == 64 else 0
    return (sf << 31) | 0x52800000 | ((hw & 3) << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)


def encode_movk(rd, imm16, hw=0, width=64):
    sf = 1 if width == 64 else 0
    return (sf << 31) | 0x72800000 | ((hw & 3) << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)


def encode_mov_imm(rd, value, width=64):
    """Synthesize a 32/64-bit integer into Rd using MOVZ + MOVK instructions."""
    mask = (1 << width) - 1
    value &= mask
    words = [encode_movz(rd, value & 0xFFFF, 0, width)]
    max_hw = 4 if width == 64 else 2
    for hw in range(1, max_hw):
        chunk = (value >> (hw * 16)) & 0xFFFF
        if chunk:
            words.append(encode_movk(rd, chunk, hw, width))
    return words


def encode_csel(rd, rn, rm, cond, width=64, kind=0):
    sf = 1 if width == 64 else 0
    op = (kind >> 1) & 1
    op2 = kind & 1
    return (sf << 31) | (op << 30) | 0x1A800000 | ((rm & 0x1F) << 16) | ((cond & 0xF) << 12) | (op2 << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def relocate_insn(insn, new_va, va_map=None):
    """Relocate a single instruction to `new_va`, returning a list of 32-bit instruction words."""
    va_map = va_map or {}
    target = va_map.get(insn.target, insn.target) if insn.target is not None else None
    if insn.mnemonic in ("b", "bl"):
        return [encode_b(new_va, target, link=(insn.mnemonic == "bl"))]
    if insn.mnemonic == "b.cond":
        delta = target - new_va
        if -(1 << 20) <= delta < (1 << 20):
            return [encode_bcond(new_va, target, insn.cond)]
        # Invert condition to skip over a 26-bit unconditional branch
        inv_cond = insn.cond ^ 1
        return [encode_bcond(new_va, new_va + 8, inv_cond), encode_b(new_va + 4, target)]
    if insn.mnemonic in ("cbz", "cbnz"):
        delta = target - new_va
        if -(1 << 20) <= delta < (1 << 20):
            return [encode_cbz(new_va, target, insn.rd, insn.width, insn.mnemonic == "cbnz")]
        return [encode_cbz(new_va, new_va + 8, insn.rd, insn.width, insn.mnemonic == "cbz"),
                encode_b(new_va + 4, target)]
    if insn.mnemonic in ("tbz", "tbnz"):
        delta = target - new_va
        if -(1 << 15) <= delta < (1 << 15):
            return [encode_tbz(new_va, target, insn.rd, insn.shift_amount, insn.mnemonic == "tbnz")]
        return [encode_tbz(new_va, new_va + 8, insn.rd, insn.shift_amount, insn.mnemonic == "tbz"),
                encode_b(new_va + 4, target)]
    if insn.mnemonic == "adr":
        delta = target - new_va
        if -(1 << 20) <= delta < (1 << 20):
            return [encode_adr(new_va, target, insn.rd)]
        return [encode_adrp(new_va, target, insn.rd),
                encode_add_imm(insn.rd, insn.rd, target & 0xFFF, 64)]
    if insn.mnemonic == "adrp":
        return [encode_adrp(new_va, target, insn.rd)]
    if insn.mnemonic == "ldr_lit":
        delta = target - new_va
        if delta % 4 == 0 and -(1 << 20) <= delta < (1 << 20):
            opc = (insn.raw >> 30) & 0x3
            return [(opc << 30) | 0x18000000 | (((delta >> 2) & 0x7FFFF) << 5) | (insn.rd & 0x1F)]
        raise ProtectionError(f"Out-of-range PC-relative literal load at {insn.va:#x}")
    return [insn.raw]


@dataclass
class BasicBlock:
    index: int
    start_va: int
    end_va: int
    instructions: list[Instruction] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    dead_scratch_regs: list[int] = field(default_factory=list)


@dataclass
class FunctionInfo:
    name: str
    vaddr: int
    size: int
    source: str  # symbol_dynsym, symbol_symtab, eh_frame_fde, user_map
    confidence: str  # high, medium
    is_exported: bool = False
    is_jni: bool = False
    is_early_init: bool = False
    has_exception_lsda: bool = False
    has_indirect_branch: bool = False
    has_unknown_insns: bool = False
    cfg_complete: bool = False
    vm_compatible: bool = False
    relocatable: bool = False
    insn_count: int = 0
    block_count: int = 0
    sensitivity_score: int = 0
    cost_score: int = 0
    blocks: list[BasicBlock] = field(default_factory=list)
    instructions: list[Instruction] = field(default_factory=list)
    skip_reasons: list[str] = field(default_factory=list)


def _read_dwarf_val(data, cursor, encoding, field_va, base_va):
    if encoding == 0xFF:
        return None, cursor
    fmt = encoding & 0x0F
    app = encoding & 0x70
    if fmt == 0x00:  # absptr (8 bytes on ELF64)
        val, = struct.unpack_from("<Q", data, cursor)
        cursor += 8
    elif fmt == 0x02:  # udata2
        val, = struct.unpack_from("<H", data, cursor)
        cursor += 2
    elif fmt == 0x03:  # udata4
        val, = struct.unpack_from("<I", data, cursor)
        cursor += 4
    elif fmt == 0x04:  # udata8
        val, = struct.unpack_from("<Q", data, cursor)
        cursor += 8
    elif fmt == 0x0A:  # sdata2
        val, = struct.unpack_from("<h", data, cursor)
        cursor += 2
    elif fmt == 0x0B:  # sdata4
        val, = struct.unpack_from("<i", data, cursor)
        cursor += 4
    elif fmt == 0x0C:  # sdata8
        val, = struct.unpack_from("<q", data, cursor)
        cursor += 8
    else:
        return None, cursor
    if app == 0x10:  # DW_EH_PE_pcrel
        val = (field_va + val) & 0xFFFFFFFFFFFFFFFF
    elif app == 0x30:  # DW_EH_PE_datarel
        val = (base_va + val) & 0xFFFFFFFFFFFFFFFF
    elif app != 0x00:
        return None, cursor
    return val, cursor


def _read_uleb128(data, cursor, end):
    result = 0
    shift = 0
    while cursor < end:
        byte = data[cursor]
        cursor += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, cursor
        shift += 7
    return 0, cursor


def _read_sleb128(data, cursor, end):
    result = 0
    shift = 0
    byte = 0
    while cursor < end:
        byte = data[cursor]
        cursor += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            break
    if shift < 64 and (byte & 0x40):
        result |= -(1 << shift)
    return result, cursor


def parse_eh_frame_functions(elf):
    """Recover compiler-emitted function ranges and LSDA status from .eh_frame (F01)."""
    eh = elf.section(".eh_frame")
    if not eh or not eh.size:
        return []
    data = elf.data
    cursor = eh.offset
    end = eh.offset + eh.size
    cies = {}
    fde_list = []
    while cursor + 4 <= end:
        record_start = cursor
        length, = struct.unpack_from("<I", data, cursor)
        cursor += 4
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            if cursor + 8 > end:
                break
            length, = struct.unpack_from("<Q", data, cursor)
            cursor += 8
        record_end = cursor + length
        if record_end > end or cursor + 4 > record_end:
            break
        cie_id, = struct.unpack_from("<I", data, cursor)
        id_offset = cursor
        cursor += 4
        if cie_id == 0:
            # CIE record
            if cursor >= record_end:
                break
            version = data[cursor]
            cursor += 1
            aug_end = data.find(b"\0", cursor, record_end)
            if aug_end < 0:
                cursor = record_end
                continue
            aug = data[cursor:aug_end].decode("ascii", errors="ignore")
            cursor = aug_end + 1
            _, cursor = _read_uleb128(data, cursor, record_end)  # code_align
            _, cursor = _read_sleb128(data, cursor, record_end)  # data_align
            if version == 1:
                cursor += 1
            else:
                _, cursor = _read_uleb128(data, cursor, record_end)
            fde_encoding = 0x00
            lsda_encoding = 0xFF
            if aug.startswith("z"):
                aug_len, cursor = _read_uleb128(data, cursor, record_end)
                aug_data_end = min(record_end, cursor + aug_len)
                for ch in aug[1:]:
                    if cursor >= aug_data_end:
                        break
                    if ch == "L":
                        lsda_encoding = data[cursor]
                        cursor += 1
                    elif ch == "R":
                        fde_encoding = data[cursor]
                        cursor += 1
                    elif ch == "P":
                        p_enc = data[cursor]
                        cursor += 1
                        _, cursor = _read_dwarf_val(data, cursor, p_enc & 0x7F,
                                                    eh.addr + (cursor - eh.offset), eh.addr)
                        if p_enc & 0x80:
                            pass
                    elif ch in ("S", "B"):
                        pass
            cies[record_start] = (aug, fde_encoding, lsda_encoding)
        else:
            cie_offset = id_offset - cie_id
            cie = cies.get(cie_offset)
            if cie:
                aug, fde_enc, lsda_enc = cie
                field_va = eh.addr + (cursor - eh.offset)
                pc_begin, cursor = _read_dwarf_val(data, cursor, fde_enc & 0x7F, field_va, eh.addr)
                pc_range, cursor = _read_dwarf_val(data, cursor, fde_enc & 0x0F, 0, 0)
                has_lsda = False
                if aug.startswith("z") and cursor < record_end:
                    aug_len, cursor = _read_uleb128(data, cursor, record_end)
                    if lsda_enc != 0xFF and aug_len > 0 and cursor < record_end:
                        l_va = eh.addr + (cursor - eh.offset)
                        lsda_val, _ = _read_dwarf_val(data, cursor, lsda_enc & 0x7F, l_va, eh.addr)
                        if lsda_val:
                            has_lsda = True
                if pc_begin and pc_range and pc_range > 0:
                    fde_list.append((pc_begin, pc_range, has_lsda))
        cursor = record_end
    return fde_list


def analyze_function_cfg(elf, func):
    """Build basic-block CFG, register liveness and VM/relocation compatibility (F01/F02)."""
    if func.size < 4 or func.size % 4 != 0:
        func.skip_reasons.append("unaligned_or_tiny_function")
        return func
    try:
        offset = elf.file_offset(func.vaddr, func.size)
    except ProtectionError:
        func.skip_reasons.append("not_file_backed")
        return func
    raw_bytes = bounded(elf.data, offset, func.size, func.name)
    return analyze_function_bytes(func, raw_bytes)


def analyze_function_bytes(func, raw_bytes):
    """Analyze pre-extracted ARM64 instruction bytes at `func.vaddr`."""
    if func.size < 4 or func.size % 4 != 0 or len(raw_bytes) < func.size:
        func.skip_reasons.append("unaligned_or_tiny_function")
        return func
    insns = []
    leaders = {func.vaddr}
    end_va = func.vaddr + func.size
    for i in range(0, func.size, 4):
        va = func.vaddr + i
        word, = struct.unpack_from("<I", raw_bytes, i)
        ins = decode_insn(va, word)
        insns.append(ins)
        if ins.op_class in ("branch", "cond_branch", "ret", "br"):
            if va + 4 < end_va:
                leaders.add(va + 4)
            if ins.target is not None and func.vaddr <= ins.target < end_va:
                leaders.add(ins.target)
        if ins.op_class == "br":
            func.has_indirect_branch = True
        if ins.mnemonic == "unknown":
            func.has_unknown_insns = True

    func.instructions = insns
    func.insn_count = len(insns)
    sorted_leaders = sorted(leaders)
    leader_to_idx = {va: idx for idx, va in enumerate(sorted_leaders)}

    # Scratch caller-saved registers x9..x14 not referenced anywhere in the function (computed once per function!)
    used_regs = set()
    for ins in insns:
        if ins.rd >= 0:
            used_regs.add(ins.rd)
        if ins.rn >= 0:
            used_regs.add(ins.rn)
        if ins.rm >= 0:
            used_regs.add(ins.rm)
        if ins.ra >= 0:
            used_regs.add(ins.ra)
    dead_scratch = [r for r in range(9, 15) if r not in used_regs]

    blocks = []
    base_va = func.vaddr
    for idx, start_va in enumerate(sorted_leaders):
        next_va = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else end_va
        block_insns = insns[(start_va - base_va) >> 2:(next_va - base_va) >> 2]
        succs = []
        if block_insns:
            last = block_insns[-1]
            if last.op_class == "branch":
                if last.target in leader_to_idx:
                    succs.append(leader_to_idx[last.target])
            elif last.op_class == "cond_branch":
                if last.target in leader_to_idx:
                    succs.append(leader_to_idx[last.target])
                if next_va in leader_to_idx:
                    succs.append(leader_to_idx[next_va])
            elif last.op_class not in ("ret", "br"):
                if next_va in leader_to_idx:
                    succs.append(leader_to_idx[next_va])
        blocks.append(BasicBlock(idx, start_va, next_va, block_insns, succs, dead_scratch))

    func.blocks = blocks
    func.block_count = len(blocks)
    func.cfg_complete = not func.has_indirect_branch and not func.has_unknown_insns
    if func.has_indirect_branch:
        func.skip_reasons.append("contains_indirect_branch_jump_table")
    if func.has_unknown_insns:
        func.skip_reasons.append("contains_unsupported_or_simd_instructions")
    if func.has_exception_lsda:
        func.skip_reasons.append("has_exception_unwind_lsda")
    has_internal_adr = any(
        ins.mnemonic == "adr" and ins.target is not None and func.vaddr <= ins.target < end_va
        for ins in insns
    )
    if has_internal_adr:
        func.skip_reasons.append("has_internal_adr_reference")
    # Check if any external branch into middle of function or unresolved internal branch exists
    func.relocatable = (
        func.cfg_complete
        and not func.has_exception_lsda
        and not has_internal_adr
        and not any(ins.mnemonic == "ldr_lit" for ins in insns)
        and func.insn_count >= 2
    )
    # VM compatibility check (O08): up to 120 instructions, complete CFG, supported VM ops, bounded stack frame
    total_stack_alloc = sum(
        ins.imm for ins in insns
        if ins.mnemonic == "sub" and ins.rd == 31 and ins.rn == 31
    ) + sum(
        -ins.imm for ins in insns
        if ins.mnemonic == "stp" and ins.rn == 31 and ins.mem_mode == 1 and ins.imm < 0
    )
    vm_ops_ok = all(
        ins.mnemonic not in ("unknown", "simd_insn", "ldr_lit", "br", "msr")
        and (ins.mnemonic != "mrs" or (ins.raw & 0xFFFFFFE0) == 0xD53BD040)
        and (ins.op_class != "cond_branch" or (ins.target is not None and func.vaddr <= ins.target < end_va))
        for ins in insns
    )
    reads_caller_stack = any(
        ins.rn == 31 and ins.mem_mode == 0
        and ins.mnemonic in ("ldr", "ldp", "ldrs", "ldr_reg", "ldrs_reg")
        and ins.imm >= total_stack_alloc
        for ins in insns
    )
    func.vm_compatible = (
        func.relocatable
        and vm_ops_ok
        and total_stack_alloc <= 2048
        and not reads_caller_stack
        and 1 <= func.insn_count <= 240
    )
    # Compute sensitivity & cost scores (A03): prioritize real logic over tiny CRT stubs
    sens = 10
    if func.is_jni:
        sens += 45
    elif func.is_exported:
        sens += 30
    lower = func.name.lower()
    if any(k in lower for k in ("secret", "key", "auth", "verify", "check", "token", "sign", "crypt", "jni", "init", "add", "native")):
        sens += 35
    if 12 <= func.insn_count <= 120:
        sens += 25
    elif 8 <= func.insn_count < 12:
        sens += 10
    elif func.insn_count < 8 and not func.is_exported and not func.is_jni:
        sens = max(1, sens - 8)
    if func.block_count >= 3 and func.insn_count >= 12:
        sens += 10
    if func.source != "eh_frame_fde" and func.insn_count >= 4:
        sens += 10
    func.sensitivity_score = min(100, sens)
    func.cost_score = min(100, max(5, func.insn_count // 2 + func.block_count * 3))
    return func


def _mark_external_midbody_branch_targets(elf, functions):
    """Reject functions jumped into mid-body from outside (shared cold/tail chunks)."""
    text = elf.section(".text")
    if not text or not functions:
        return
    import bisect

    text_start, text_end = text.addr, text.addr + text.size
    text_bytes = elf.section_data(text)
    starts = [fn.vaddr for fn in functions]
    n_funcs = len(functions)
    n_words = len(text_bytes) // 4
    words = struct.unpack_from(f"<{n_words}I", text_bytes)
    bad = set()

    for idx, w in enumerate(words):
        top = w >> 24
        # Fast filter: only inspect B/BL (0x14-0x17,0x94-0x97), CBZ/CBNZ (0x34-0x35,0xB4-0xB5),
        # TBZ/TBNZ (0x36-0x37,0xB6-0xB7), B.cond (0x54)
        if top not in (
            0x14, 0x15, 0x16, 0x17, 0x94, 0x95, 0x96, 0x97,
            0x34, 0x35, 0xB4, 0xB5, 0x36, 0x37, 0xB6, 0xB7, 0x54,
        ):
            continue
        va = text_start + idx * 4
        if (w & 0x7C000000) == 0x14000000:
            imm = w & 0x03FFFFFF
            if imm & (1 << 25):
                imm -= 1 << 26
            target = va + (imm << 2)
        elif (w & 0xFF000010) == 0x54000000 or (w & 0x7E000000) == 0x34000000:
            imm = (w >> 5) & 0x7FFFF
            if imm & (1 << 18):
                imm -= 1 << 19
            target = va + (imm << 2)
        elif (w & 0x7E000000) == 0x36000000:
            imm = (w >> 5) & 0x3FFF
            if imm & (1 << 13):
                imm -= 1 << 14
            target = va + (imm << 2)
        else:
            continue

        if not (text_start < target < text_end):
            continue
        t_pos = bisect.bisect_right(starts, target) - 1
        if t_pos < 0 or t_pos >= n_funcs:
            continue
        fn = functions[t_pos]
        if fn.vaddr < target < fn.vaddr + fn.size and not (fn.vaddr <= va < fn.vaddr + fn.size):
            bad.add(t_pos)

    for fn_idx in bad:
        fn = functions[fn_idx]
        if "external_mid_body_branch_target" not in fn.skip_reasons:
            fn.skip_reasons.append("external_mid_body_branch_target")
        fn.relocatable = False
        fn.vm_compatible = False


def discover_functions(elf, user_map=None):
    """Combine symbols, .eh_frame FDEs, initializer arrays and optional user map (F01)."""
    text = elf.section(".text")
    if not text:
        return []
    text_start, text_end = text.addr, text.addr + text.size
    early_vas = set()
    if elf.dynamic_value(12):
        early_vas.add(elf.dynamic_value(12))
    init_arr, init_sz = elf.dynamic_value(25), elf.dynamic_value(27)
    if init_arr and init_sz:
        for sec in elf.sections:
            if sec.type == 4 and sec.entsize == 24:
                for off in range(sec.offset, sec.offset + sec.size, 24):
                    r_off, r_info, r_addend = struct.unpack_from("<QQq", elf.data, off)
                    if init_arr <= r_off < init_arr + init_sz and (r_info & 0xFFFFFFFF) == 1027:
                        early_vas.add(r_addend)
        try:
            arr_off = elf.file_offset(init_arr, init_sz)
            for off in range(0, init_sz, 8):
                val, = struct.unpack_from("<Q", elf.data, arr_off + off)
                if val:
                    early_vas.add(val)
        except ProtectionError:
            pass

    fdes = {}
    for pc_begin, pc_range, has_lsda in parse_eh_frame_functions(elf):
        if text_start <= pc_begin and pc_begin + pc_range <= text_end:
            fdes[pc_begin] = (pc_range, has_lsda)

    by_vaddr = {}
    exported_vas = {s[3] for s in elf.exported_symbols()}
    for sym in elf.symbols(dynamic_only=False):
        if not sym["shndx"] or (sym["info"] & 0xF) != 2 or sym["size"] <= 0:
            continue
        va, sz = sym["value"], sym["size"]
        if not (text_start <= va and va + sz <= text_end):
            continue
        fde = fdes.get(va)
        has_lsda = fde[1] if fde else False
        name = sym["name"] or f"sub_{va:x}"
        if va not in by_vaddr or (by_vaddr[va].name.startswith("sub_") and not name.startswith("sub_")):
            by_vaddr[va] = FunctionInfo(
                name=name, vaddr=va, size=sz,
                source="symbol_dynsym" if va in exported_vas else "symbol_symtab",
                confidence="high",
                is_exported=(va in exported_vas),
                is_jni=(name == "JNI_OnLoad" or name.startswith("Java_")),
                is_early_init=(va in early_vas),
                has_exception_lsda=has_lsda,
            )

    for va, (sz, has_lsda) in sorted(fdes.items()):
        if va not in by_vaddr:
            by_vaddr[va] = FunctionInfo(
                name=f"fde_{va:x}", vaddr=va, size=sz,
                source="eh_frame_fde", confidence="high",
                is_exported=(va in exported_vas),
                is_jni=False,
                is_early_init=(va in early_vas),
                has_exception_lsda=has_lsda,
            )

    if user_map:
        for item in user_map:
            va = int(item["vaddr"], 0) if isinstance(item["vaddr"], str) else int(item["vaddr"])
            sz = int(item["size"], 0) if isinstance(item["size"], str) else int(item["size"])
            name = item.get("name") or f"map_{va:x}"
            if text_start <= va and va + sz <= text_end:
                fde = fdes.get(va)
                by_vaddr[va] = FunctionInfo(
                    name=name, vaddr=va, size=sz,
                    source="user_map", confidence="high",
                    is_exported=(va in exported_vas),
                    is_jni=(name == "JNI_OnLoad" or name.startswith("Java_")),
                    is_early_init=(va in early_vas),
                    has_exception_lsda=fde[1] if fde else bool(item.get("has_lsda", False)),
                )

    functions = [analyze_function_cfg(elf, fn) for _, fn in sorted(by_vaddr.items())]
    _mark_external_midbody_branch_targets(elf, functions)
    return functions


def find_rodata_string_refs(elf, functions=None):
    """Locate ADRP + ADD instruction pairs in .text referencing safe strings in .rodata (E03)."""
    cached = getattr(elf, "_cached_rodata_string_refs", None)
    if cached is not None:
        return list(cached)

    rodata = elf.section(".rodata")
    text = elf.section(".text")
    if not rodata or not text or not rodata.size or not text.size:
        elf._cached_rodata_string_refs = ()
        return []
    # Exclude dynamic string table and loader metadata
    excluded_ranges = []
    for tag, _ in elf.dynamic:
        if tag in (5, 6, 7, 17, 23, 4, 0x6FFFFEF5, 0x6FFFFFF0, 0x6FFFFFFC, 0x6FFFFFFE):
            val = elf.dynamic_value(tag)
            if rodata.addr <= val < rodata.addr + rodata.size:
                excluded_ranges.append((val, rodata.addr + rodata.size))
    if excluded_ranges:
        elf._cached_rodata_string_refs = ()
        return []

    import sys

    ro_bytes = elf.section_data(rodata)
    ro_addr = rodata.addr
    ro_end = ro_addr + rodata.size
    ro_off = rodata.offset
    text_bytes = elf.section_data(text)
    word_count = len(text_bytes) // 4
    words = (
        memoryview(text_bytes)[:word_count * 4].cast("I")
        if sys.byteorder == "little"
        else [w for (w,) in struct.iter_unpack("<I", text_bytes[:word_count * 4])]
    )
    refs = []
    # Scan for ADR Rd, target (4 bytes) or ADRP Rd, page + ADD Rd, Rd, #off (8 bytes)
    idx = 0
    while idx < word_count:
        w0 = words[idx]
        # Fast bitwise gate: both ADR (0x10000000) and ADRP (0x90000000) have bits[28:24] == 0b10000
        if (w0 & 0x1F000000) != 0x10000000:
            idx += 1
            continue
        va = text.addr + (idx << 2)
        i0 = decode_insn(va, w0)
        if i0.mnemonic == "adr" and 0 <= i0.rd < 31 and ro_addr <= i0.target < ro_end:
            rel = i0.target - ro_addr
            end = ro_bytes.find(b"\0", rel)
            if end > rel and (rel == 0 or ro_bytes[rel - 1] == 0):
                raw_str = ro_bytes[rel:end + 1]
                if 4 <= len(raw_str) <= 240 and all(32 <= b < 127 or b in (9, 10, 13) for b in raw_str[:-1]):
                    refs.append({
                        "callsite_vaddr": va,
                        "callsite_size": 4,
                        "resume_vaddr": va + 4,
                        "rd": i0.rd,
                        "string_vaddr": i0.target,
                        "string_offset": ro_off + rel,
                        "string_bytes": bytes(raw_str),
                        "string_text": raw_str[:-1].decode("utf-8", errors="replace"),
                    })
                    idx += 1
                    continue
        if i0.mnemonic == "adrp" and 0 <= i0.rd < 31 and idx + 1 < word_count:
            w1 = words[idx + 1]
            # ADD (immediate, 64-bit, no flags) has bits[31:23] == 0b100100010 -> mask 0xFF800000 == 0x91000000
            if (w1 & 0xFF800000) == 0x91000000:
                i1 = decode_insn(va + 4, w1)
                if i1.mnemonic == "add" and i1.rd == i0.rd and i1.rn == i0.rd and not i1.flags_set:
                    target = i0.target + i1.imm
                    if ro_addr <= target < ro_end:
                        rel = target - ro_addr
                        end = ro_bytes.find(b"\0", rel)
                        if end > rel and (rel == 0 or ro_bytes[rel - 1] == 0):
                            raw_str = ro_bytes[rel:end + 1]
                            if 4 <= len(raw_str) <= 240 and all(32 <= b < 127 or b in (9, 10, 13) for b in raw_str[:-1]):
                                refs.append({
                                    "callsite_vaddr": va,
                                    "callsite_size": 8,
                                    "resume_vaddr": va + 8,
                                    "rd": i0.rd,
                                    "string_vaddr": target,
                                    "string_offset": ro_off + rel,
                                    "string_bytes": bytes(raw_str),
                                    "string_text": raw_str[:-1].decode("utf-8", errors="replace"),
                                })
                                idx += 2
                                continue
        idx += 1
    counts = {}
    for r in refs:
        counts[r["string_vaddr"]] = counts.get(r["string_vaddr"], 0) + 1

    # Exclude strings also pointed to by data relocations (e.g. R_AARCH64_RELATIVE in .data.rel.ro/.data)
    reloc_ro_targets = set()
    for sec in elf.sections:
        if sec.type == 4 and sec.entsize == 24 and sec.size % 24 == 0:
            for off in range(sec.offset, sec.offset + sec.size, 24):
                _, _, r_add = struct.unpack_from("<QQq", elf.data, off)
                if ro_addr <= r_add < ro_end:
                    reloc_ro_targets.add(r_add)

    unique_refs = [
        r for r in refs
        if counts[r["string_vaddr"]] == 1
        and not any(r["string_vaddr"] <= rt < r["string_vaddr"] + len(r["string_bytes"]) for rt in reloc_ro_targets)
    ]
    elf._cached_rodata_string_refs = tuple(unique_refs)
    return unique_refs
