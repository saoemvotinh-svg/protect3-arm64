"""ARM64 binary transformations: O01-O10 obfuscation/flattening/VM/self-obf, E02+/E03/E08/E09 packer, R07 on-demand."""

import hashlib
import hmac
import json
from pathlib import Path
import random
import re
import secrets
import struct
import tempfile
import unicodedata
import zlib

from .arm64 import (
    FunctionInfo,
    Instruction,
    analyze_function_bytes,
    decode_insn,
    encode_add_imm,
    encode_adr,
    encode_adrp,
    encode_b,
    encode_bcond,
    encode_cbz,
    encode_csel,
    encode_mov_imm,
    encode_movk,
    encode_movz,
    encode_sub_imm,
    encode_tbz,
    relocate_insn,
)
from .crypto import chacha20
from .elf import (
    DYN,
    EHDR,
    ELF,
    PHDR,
    PT_DYNAMIC,
    PT_LOAD,
    PT_PHDR,
    SYM,
    ProtectionError,
    Section,
    Segment,
    align,
    bounded,
    cstring,
)
from .runtime import command, ndk_tool, rekey_guard_strings

CONFIG = struct.Struct("<24sIIQQIIQQ32s12sIQQ32sII")
SPAN = struct.Struct("<QQ32s")
CONFIG_SIZE = CONFIG.size + 32 * SPAN.size
MAGIC = b"PROTECT3-GUARD-v2"

EXT_HDR = struct.Struct("<16sIIIIIIQ16s32s32s32s32s32sQQ32sQQQQQQ32sQQQQ64s32s")
ENC_RANGE = struct.Struct("<QQII12sI32s32s")
PROLOGUE_GUARD = struct.Struct("<QII16s")
VM_PROG = struct.Struct("<QIIII12sI32s")
STRING_ENTRY = struct.Struct("<II12s32s")
P3_MAX_ENC_RANGES = 24
P3_MAX_PROLOGUES = 16
P3_MAX_VM_PROGS = 32
P3_MAX_STRINGS = 32
EXT_CONFIG_SIZE = (
    EXT_HDR.size
    + P3_MAX_ENC_RANGES * ENC_RANGE.size
    + P3_MAX_PROLOGUES * PROLOGUE_GUARD.size
    + P3_MAX_VM_PROGS * VM_PROG.size
    + P3_MAX_STRINGS * STRING_ENTRY.size
)
EXT_MAGIC = b"PROTECT3-EXT-v3\x00"
assert EXT_CONFIG_SIZE == 7456

SPARSE_DATA_CFG = struct.Struct("<QQQQII12sI32s32sQQ32s")
assert SPARSE_DATA_CFG.size == 168

PACK_SEG = struct.Struct("<QQQQQII")
assert PACK_SEG.size == 48
P3_PACK_MAX_SEGS = 8
P3_PACK_MAX_SAVED = 64
PACK_HDR = struct.Struct("<IIQQQ32s12sIQQQQQQQQQQQQQQII64Q32s")
PACK_CFG_SIZE = PACK_HDR.size + P3_PACK_MAX_SEGS * PACK_SEG.size
assert PACK_CFG_SIZE == 1128

VM_INSN = struct.Struct("<BBBBBBHQ")
assert VM_INSN.size == 16

VM_OP_NOP = 0
VM_OP_MOV_IMM = 1
VM_OP_MOVK = 2
VM_OP_MOV_REG = 3
VM_OP_ADD = 4
VM_OP_SUB = 5
VM_OP_AND = 6
VM_OP_ORR = 7
VM_OP_EOR = 8
VM_OP_BIC = 9
VM_OP_ORN = 10
VM_OP_EON = 11
VM_OP_LSL = 12
VM_OP_LSR = 13
VM_OP_ASR = 14
VM_OP_ROR = 15
VM_OP_MADD = 16
VM_OP_MSUB = 17
VM_OP_UDIV = 18
VM_OP_SDIV = 19
VM_OP_CSEL = 20
VM_OP_BFM = 21
VM_OP_ADR = 22
VM_OP_LDR = 23
VM_OP_STR = 24
VM_OP_LDP = 25
VM_OP_STP = 26
VM_OP_B = 27
VM_OP_BCOND = 28
VM_OP_CBZ = 29
VM_OP_TBZ = 30
VM_OP_CALL = 31
VM_OP_RET = 32
VM_OP_MRS_TPIDR = 33
VM_OP_LDR_REG = 34
VM_OP_STR_REG = 35
VM_OP_ADD_EXT = 36
VM_OP_SUB_EXT = 37
P3_MAX_VM_INSNS = 256


def generate_vm_opcode_tables(seed):
    """Create a per-build bijective 64-entry opcode permutation (O09/A01)."""
    rng = random.Random(seed ^ 0x5033564D)
    perm = list(range(64))
    rng.shuffle(perm)
    # decode_map[encoded_op] = canonical_op
    decode_map = bytes(perm)
    # encode_map[canonical_op] = encoded_op
    encode_map = {canonical: encoded for encoded, canonical in enumerate(perm)}
    return decode_map, encode_map


def compile_function_to_vm(func, encode_map):
    """Lift an ARM64 FunctionInfo into encrypted-ready VM bytecode instructions (O08/O09)."""
    if not func.vm_compatible:
        raise ProtectionError(f"Function {func.name} is not VM-compatible: {func.skip_reasons}")
    va_to_pc = {ins.va: idx for idx, ins in enumerate(func.instructions)}
    records = []

    def op(canon):
        return encode_map[canon]

    for ins in func.instructions:
        w_flag = 1 if ins.width == 32 else 0
        m = ins.mnemonic
        if m in ("nop", "hint"):
            records.append(VM_INSN.pack(op(VM_OP_NOP), 0, 0, 0, 0, 0, 0, 0))
        elif m in ("movz", "movn"):
            records.append(VM_INSN.pack(op(VM_OP_MOV_IMM), ins.rd, 0, 0, w_flag, 0, 0, ins.imm & 0xFFFFFFFFFFFFFFFF))
        elif m == "movk":
            records.append(VM_INSN.pack(op(VM_OP_MOVK), ins.rd, 0, 0, w_flag, 0, ins.shift_amount & 48, ins.imm & 0xFFFF))
        elif m in ("add", "adds", "sub", "subs"):
            canon = VM_OP_SUB if m.startswith("sub") else VM_OP_ADD
            cond = 0x80 if ins.flags_set else 0
            # In ADD/SUB (immediate), rn=31 is SP; rd=31 is SP unless S=1 (where rd=31 is XZR)
            aux = 0x8000 | (0x4000 if ins.rn == 31 else 0)
            records.append(VM_INSN.pack(op(canon), ins.rd, ins.rn, 0, w_flag, cond, aux, ins.imm & 0xFFFFFFFFFFFFFFFF))
        elif m in ("add_reg", "adds_reg", "sub_reg", "subs_reg"):
            canon = VM_OP_SUB if m.startswith("sub") else VM_OP_ADD
            cond = (0x80 if ins.flags_set else 0) | (ins.shift_type & 3)
            aux = (ins.shift_amount & 63) | (0x4000 if ins.rn == 31 else 0)
            records.append(VM_INSN.pack(op(canon), ins.rd, ins.rn, ins.rm, w_flag, cond, aux, 0))
        elif m in ("add_ext", "adds_ext", "sub_ext", "subs_ext"):
            canon = VM_OP_SUB_EXT if m.startswith("sub") else VM_OP_ADD_EXT
            cond = (0x80 if ins.flags_set else 0) | (ins.cond & 7)
            aux = (ins.shift_amount & 7) | (0x4000 if ins.rn == 31 else 0)
            records.append(VM_INSN.pack(op(canon), ins.rd, ins.rn, ins.rm, w_flag, cond, aux, 0))
        elif m in ("and_imm", "orr_imm", "eor_imm", "ands_imm"):
            canon = {"and_imm": VM_OP_AND, "ands_imm": VM_OP_AND, "orr_imm": VM_OP_ORR, "eor_imm": VM_OP_EOR}[m]
            cond = 0x80 if ins.flags_set else 0
            records.append(VM_INSN.pack(op(canon), ins.rd, ins.rn, 0, w_flag, cond, 0x8000, ins.imm & 0xFFFFFFFFFFFFFFFF))
        elif m in ("and_reg", "ands_reg", "orr_reg", "eor_reg", "bic_reg", "orn_reg", "eon_reg"):
            canon = {
                "and_reg": VM_OP_AND, "ands_reg": VM_OP_AND, "orr_reg": VM_OP_ORR,
                "eor_reg": VM_OP_EOR, "bic_reg": VM_OP_BIC, "orn_reg": VM_OP_ORN, "eon_reg": VM_OP_EON,
            }[m]
            cond = (0x80 if ins.flags_set else 0) | (ins.shift_type & 3)
            aux = ins.shift_amount & 63
            records.append(VM_INSN.pack(op(canon), ins.rd, ins.rn, ins.rm, w_flag, cond, aux, 0))
        elif m in ("lslv", "lsrv", "asrv", "rorv", "udiv", "sdiv"):
            canon = {
                "lslv": VM_OP_LSL, "lsrv": VM_OP_LSR, "asrv": VM_OP_ASR,
                "rorv": VM_OP_ROR, "udiv": VM_OP_UDIV, "sdiv": VM_OP_SDIV,
            }[m]
            records.append(VM_INSN.pack(op(canon), ins.rd, ins.rn, ins.rm, w_flag, 0, 0, 0))
        elif m in ("madd", "msub"):
            canon = VM_OP_MSUB if m == "msub" else VM_OP_MADD
            records.append(VM_INSN.pack(op(canon), ins.rd, ins.rn, ins.rm, w_flag, 0, ins.ra & 31, 0))
        elif m in ("csel", "csinc", "csinv", "csneg"):
            records.append(VM_INSN.pack(op(VM_OP_CSEL), ins.rd, ins.rn, ins.rm, w_flag, ins.cond & 15, ins.shift_amount & 3, 0))
        elif m in ("sbfm", "bfm", "ubfm"):
            records.append(VM_INSN.pack(op(VM_OP_BFM), ins.rd, ins.rn, 0, w_flag, ins.cond & 3, ins.shift_amount & 0xFFF, 0))
        elif m in ("adr", "adrp"):
            records.append(VM_INSN.pack(op(VM_OP_ADR), ins.rd, 0, 0, 0, 0, 0, ins.target & 0xFFFFFFFFFFFFFFFF))
        elif m == "mrs":
            records.append(VM_INSN.pack(op(VM_OP_MRS_TPIDR), ins.rd, 0, 0, 0, 0, 0, 0))
        elif m in ("ldr", "ldrs", "str"):
            canon = VM_OP_STR if m == "str" else VM_OP_LDR
            cond = (1 if ins.mem_signed else 0) | (2 if ins.mem_mode == 1 else (4 if ins.mem_mode == 2 else 0))
            aux = 1 if (ins.mem_signed and ins.width == 32) else 0
            records.append(VM_INSN.pack(op(canon), ins.rd, ins.rn, 0, ins.mem_size, cond, aux, ins.imm & 0xFFFFFFFFFFFFFFFF))
        elif m in ("ldr_reg", "ldrs_reg", "str_reg"):
            canon = VM_OP_STR_REG if m == "str_reg" else VM_OP_LDR_REG
            cond = (1 if ins.mem_signed else 0) | (2 if (ins.mem_signed and ins.width == 32) else 0)
            aux = ((ins.cond & 7) << 3) | (ins.shift_amount & 7)
            records.append(VM_INSN.pack(op(canon), ins.rd, ins.rn, ins.rm, ins.mem_size, cond, aux, 0))
        elif m in ("ldp", "stp"):
            canon = VM_OP_STP if m == "stp" else VM_OP_LDP
            cond = (1 if ins.mem_signed else 0) | (2 if ins.mem_mode == 1 else (4 if ins.mem_mode == 2 else 0))
            records.append(VM_INSN.pack(op(canon), ins.rd, ins.rn, ins.rm, ins.mem_size, cond, 0, ins.imm & 0xFFFFFFFFFFFFFFFF))
        elif m == "b":
            if ins.target in va_to_pc:
                records.append(VM_INSN.pack(op(VM_OP_B), 0, 0, 0, 0, 0, 0, va_to_pc[ins.target]))
            else:
                # Tail call to external function: execute call + return
                if len(records) + 2 > P3_MAX_VM_INSNS:
                    raise ProtectionError(f"VM bytecode exceeds {P3_MAX_VM_INSNS}-instruction limit in {func.name}")
                records.append(VM_INSN.pack(op(VM_OP_CALL), 0, 0, 0, 0, 0, 0, ins.target & 0xFFFFFFFFFFFFFFFF))
                records.append(VM_INSN.pack(op(VM_OP_RET), 0, 0, 0, 0, 0, 0, 0))
        elif m == "b.cond":
            if ins.target not in va_to_pc:
                raise ProtectionError(f"External conditional branch in {func.name} cannot be virtualized")
            records.append(VM_INSN.pack(op(VM_OP_BCOND), 0, 0, 0, 0, ins.cond & 15, 0, va_to_pc[ins.target]))
        elif m in ("cbz", "cbnz"):
            if ins.target not in va_to_pc:
                raise ProtectionError(f"External CBZ/CBNZ in {func.name} cannot be virtualized")
            records.append(VM_INSN.pack(op(VM_OP_CBZ), ins.rd, 0, 0, w_flag, 1 if m == "cbnz" else 0, 0, va_to_pc[ins.target]))
        elif m in ("tbz", "tbnz"):
            if ins.target not in va_to_pc:
                raise ProtectionError(f"External TBZ/TBNZ in {func.name} cannot be virtualized")
            records.append(VM_INSN.pack(op(VM_OP_TBZ), ins.rd, 0, 0, w_flag, 1 if m == "tbnz" else 0, ins.shift_amount & 63, va_to_pc[ins.target]))
        elif m == "bl":
            records.append(VM_INSN.pack(op(VM_OP_CALL), 0, 0, 0, 0, 0, 0, ins.target & 0xFFFFFFFFFFFFFFFF))
        elif m == "blr":
            records.append(VM_INSN.pack(op(VM_OP_CALL), 0, ins.rn, 0, 0, 1, 0, 0))
        elif m == "ret":
            records.append(VM_INSN.pack(op(VM_OP_RET), 0, ins.rn, 0, 0, 0, 0, 0))
        else:
            raise ProtectionError(f"Unsupported instruction {m} at {ins.va:#x} in {func.name}")

    if len(records) > P3_MAX_VM_INSNS:
        raise ProtectionError(f"Function {func.name} exceeds {P3_MAX_VM_INSNS} VM instructions.")
    return b"".join(records), len(records)


def build_vm_entry_stub(stub_va, prog_index, vm_bridge_va):
    """Emit an 8-byte stub: MOVZ X16, #prog_index; B p3_vm_bridge."""
    words = [
        encode_movz(16, prog_index & 0xFFFF, 0, 64),
        encode_b(stub_va + 4, vm_bridge_va, link=False),
    ]
    return b"".join(struct.pack("<I", w) for w in words)


def _encode_eor_reg(rd, rn, rm, width=64):
    sf = 1 if width == 64 else 0
    return (sf << 31) | 0x4A000000 | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def _encode_orr_reg(rd, rn, rm, width=64):
    sf = 1 if width == 64 else 0
    return (sf << 31) | 0x2A000000 | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def _encode_and_reg(rd, rn, rm, width=64):
    sf = 1 if width == 64 else 0
    return (sf << 31) | 0x0A000000 | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def _encode_bic_reg(rd, rn, rm, width=64):
    sf = 1 if width == 64 else 0
    return (sf << 31) | 0x0A200000 | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def _encode_add_reg_lsl(rd, rn, rm, shift=0, width=64):
    sf = 1 if width == 64 else 0
    return (sf << 31) | 0x0B000000 | ((rm & 0x1F) << 16) | ((shift & 0x3F) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def _encode_madd(rd, rn, rm, ra=31, width=64):
    sf = 1 if width == 64 else 0
    return (sf << 31) | 0x1B000000 | ((rm & 0x1F) << 16) | ((ra & 0x1F) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def _encode_blr(rn):
    return 0xD63F0000 | ((rn & 0x1F) << 5)


def _junk_unk_word(seed, salt):
    """Return a deterministic non-zero AArch64 unallocated instruction word (<unknown>)."""
    val = ((seed ^ ((salt + 1) * 0x9E3779B1)) & 0x00FFFFFC) | 0x02000001
    return val & 0xFFFFFFFF


def obfuscate_and_relocate_function(
    func,
    base_va,
    seed,
    enable_sub=True,
    enable_opaque_const=True,
    enable_opaque_pred=True,
    enable_indirect=True,
    enable_shuffle=True,
    enable_split=False,
    enable_flatten=False,
    gate_bridge_va=None,
    gate_id=0,
    enable_junk_islands=False,
    va_remap=None,
    ensure_bti=False,
):
    """Apply O01-O07 + A07 to `func` and emit relocated ARM64 machine code at `base_va`."""
    if not func.relocatable:
        raise ProtectionError(f"Function {func.name} is not relocatable: {func.skip_reasons}")
    rng = random.Random(seed ^ func.vaddr)

    # Split single-block functions of >= 3 instructions into synthetic basic blocks when flattening/shuffling
    raw_blocks = []
    if len(func.blocks) == 1 and len(func.instructions) >= 3 and (enable_flatten or enable_shuffle or enable_split):
        insns = func.instructions
        for idx, ins in enumerate(insns):
            succ = [idx + 1] if idx + 1 < len(insns) and ins.op_class not in ("ret", "branch", "br") else []
            raw_blocks.append((ins.va, ins.va + 4, [ins], succ, func.blocks[0].dead_scratch_regs))
    else:
        for b in func.blocks:
            raw_blocks.append((b.start_va, b.end_va, list(b.instructions), list(b.successors), list(b.dead_scratch_regs)))

    num_blocks = len(raw_blocks)
    scratch_regs = list(func.blocks[0].dead_scratch_regs) if func.blocks else []
    scratch_a = scratch_regs[0] if len(scratch_regs) >= 1 else None
    scratch_b = scratch_regs[1] if len(scratch_regs) >= 2 else None

    # State IDs for Control-Flow Flattening (O07) when two dead scratch registers exist
    use_flatten = bool(enable_flatten and scratch_a is not None and scratch_b is not None and num_blocks >= 2)
    state_ids = [rng.randint(0x1001, 0x7FFEFFFF) for _ in range(num_blocks)]
    # Ensure distinct state IDs
    for idx in range(num_blocks):
        state_ids[idx] = ((state_ids[idx] & ~0xFF) | (idx + 1)) & 0x7FFFFFFF

    block_order = list(range(num_blocks))
    if enable_shuffle and num_blocks > 2:
        middle = block_order[1:-1]
        rng.shuffle(middle)
        block_order = [0] + middle + [num_blocks - 1]

    # Two-pass assembly: pass 0 computes exact instruction counts & block VAs; pass 1 encodes branches.
    block_vas = [0] * num_blocks
    insn_va_map = {}
    dispatcher_va = base_va
    starts_with_bti = bool(func.instructions and func.instructions[0].raw == 0xD503245F)

    for _pass in range(2):
        words = []
        cur_va = base_va
        # Optional runtime gate prologue (R01/R02/R05/R06) or standalone BTI c landing pad
        if gate_bridge_va is not None:
            gate_seq = [
                0xD503245F,  # bti c
                0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
                encode_movz(16, gate_id & 0xFFFF, 0, 64),
                encode_b(cur_va + 12, gate_bridge_va, link=True) if _pass == 1 else 0x94000000,
                0xA8C17BFD,  # ldp x29, x30, [sp], #16
            ]
            words.extend(gate_seq)
            cur_va += len(gate_seq) * 4
        elif ensure_bti and not (starts_with_bti and not use_flatten and not enable_opaque_pred):
            words.append(0xD503245F)  # bti c
            cur_va += 4

        if use_flatten:
            # Initialize state register scratch_a = state_ids[0]
            init_seq = encode_mov_imm(scratch_a, state_ids[0], 32)
            words.extend(init_seq)
            cur_va += len(init_seq) * 4
            dispatcher_va = cur_va
            for b_idx in block_order:
                cmp_seq = encode_mov_imm(scratch_b, state_ids[b_idx], 32)
                # SUBS WZR, W_scratch_a, W_scratch_b
                subs_wzr = 0x6B00001F | ((scratch_b & 0x1F) << 16) | ((scratch_a & 0x1F) << 5)
                b_eq = encode_bcond(cur_va + (len(cmp_seq) + 1) * 4, block_vas[b_idx], 0) if _pass == 1 else 0x54000000
                words.extend(cmp_seq + [subs_wzr, b_eq])
                cur_va += (len(cmp_seq) + 2) * 4

        combined_map = dict(va_remap) if (_pass == 1 and va_remap) else {}
        if _pass == 1:
            combined_map.update(insn_va_map)

        for order_pos, b_idx in enumerate(block_order):
            start_va, end_va, b_insns, succs, _ = raw_blocks[b_idx]
            block_vas[b_idx] = cur_va
            if enable_junk_islands and order_pos > 0 and ((b_idx + (seed & 0xFF)) % 3 == 0):
                words.extend([
                    encode_b(cur_va, cur_va + 8, link=False),
                    _junk_unk_word(seed, b_idx ^ 0x1357),
                ])
                cur_va += 8
            # Optional O05/A07 inter-block state token or split padding
            if enable_split and order_pos > 0 and scratch_a is not None and not use_flatten:
                token = (seed ^ (b_idx * 0x9E37)) & 0xFFFF
                words.append(encode_movz(scratch_a, token, 0, 64))
                cur_va += 4
            # Optional O03 opaque predicate at block start (when no live flags)
            if (enable_opaque_pred and scratch_a is not None
                    and not any(i.flags_used or i.flags_set for i in b_insns)):
                # (X0 * (X0 + 1)) & 1 == 0 always holds for all 64-bit integers X0
                dead_word = _junk_unk_word(seed, b_idx ^ 0x2468) if enable_junk_islands else 0xD4200000
                op_seq = [
                    encode_add_imm(scratch_a, 0, 1, 64),
                    _encode_madd(scratch_a, 0, scratch_a, 31, 64),
                    encode_tbz(cur_va + 8, cur_va + 16, scratch_a, 0, is_nz=False),
                    dead_word,
                ]
                words.extend(op_seq)
                cur_va += len(op_seq) * 4

            for ins_idx, ins in enumerate(b_insns):
                insn_va_map[ins.va] = cur_va
                if _pass == 1:
                    combined_map[ins.va] = cur_va
                is_last = (ins_idx == len(b_insns) - 1)
                # O07 flattened terminator handling
                if use_flatten and is_last:
                    if ins.op_class == "branch" and succs:
                        target_b = succs[0]
                        seq = encode_mov_imm(scratch_a, state_ids[target_b], 32)
                        jmp = encode_b(cur_va + len(seq) * 4, dispatcher_va) if _pass == 1 else 0x14000000
                        words.extend(seq + [jmp])
                        cur_va += (len(seq) + 1) * 4
                        continue
                    if ins.op_class == "cond_branch" and ins.mnemonic == "b.cond" and len(succs) == 2:
                        t_seq = encode_mov_imm(scratch_b, state_ids[succs[0]], 32)
                        f_seq = encode_mov_imm(scratch_a, state_ids[succs[1]], 32)
                        csel = encode_csel(scratch_a, scratch_b, scratch_a, ins.cond, 32, 0)
                        jmp_va = cur_va + (len(t_seq) + len(f_seq) + 1) * 4
                        jmp = encode_b(jmp_va, dispatcher_va) if _pass == 1 else 0x14000000
                        words.extend(t_seq + f_seq + [csel, jmp])
                        cur_va += (len(t_seq) + len(f_seq) + 2) * 4
                        continue
                    if ins.op_class not in ("ret", "br", "branch", "cond_branch"):
                        # Emit the non-branch instruction first, then transition to fallthrough state
                        pass

                # O02: Opaque constant synthesis for MOVZ
                if (enable_opaque_const and ins.mnemonic == "movz" and scratch_b is not None
                        and ins.rd != scratch_b and ins.rd < 31):
                    mask16 = ((seed >> 8) ^ (ins.va >> 2) ^ 0x5A3C) & 0xFFFF
                    if mask16 == 0:
                        mask16 = 0x3C6E
                    raw_imm16 = (ins.imm >> ins.shift_amount) & 0xFFFF
                    hw = ins.shift_amount // 16
                    seq = [
                        encode_movz(ins.rd, raw_imm16 ^ mask16, hw, ins.width),
                        encode_movz(scratch_b, mask16, hw, ins.width),
                        _encode_eor_reg(ins.rd, ins.rd, scratch_b, ins.width),
                    ]
                    words.extend(seq)
                    cur_va += len(seq) * 4
                # O01: MBA instruction substitution for unshifted ADD_REG / EOR_REG / ADD_IMM
                elif (enable_sub and ins.mnemonic == "add_reg" and not ins.flags_set
                      and ins.shift_amount == 0 and scratch_b is not None
                      and ins.rd < 31 and ins.rn < 31 and ins.rm < 31
                      and scratch_b not in (ins.rd, ins.rn, ins.rm)):
                    seq = [
                        _encode_eor_reg(scratch_b, ins.rn, ins.rm, ins.width),
                        _encode_and_reg(ins.rd, ins.rn, ins.rm, ins.width),
                        _encode_add_reg_lsl(ins.rd, scratch_b, ins.rd, 1, ins.width),
                    ]
                    words.extend(seq)
                    cur_va += len(seq) * 4
                elif (enable_sub and ins.mnemonic == "eor_reg" and not ins.flags_set
                      and ins.shift_amount == 0 and scratch_b is not None
                      and ins.rd < 31 and ins.rn < 31 and ins.rm < 31
                      and scratch_b not in (ins.rd, ins.rn, ins.rm)):
                    seq = [
                        _encode_orr_reg(scratch_b, ins.rn, ins.rm, ins.width),
                        _encode_and_reg(ins.rd, ins.rn, ins.rm, ins.width),
                        _encode_bic_reg(ins.rd, scratch_b, ins.rd, ins.width),
                    ]
                    words.extend(seq)
                    cur_va += len(seq) * 4
                elif (enable_sub and ins.mnemonic == "add" and not ins.flags_set
                      and 2 <= ins.imm <= 4000 and ins.rd < 31 and ins.rn < 31):
                    part1 = ins.imm // 2
                    part2 = ins.imm - part1
                    seq = [
                        encode_add_imm(ins.rd, ins.rn, part1, ins.width),
                        encode_add_imm(ins.rd, ins.rd, part2, ins.width),
                    ]
                    words.extend(seq)
                    cur_va += len(seq) * 4
                # O04: Indirect call for BL target
                elif enable_indirect and ins.mnemonic == "bl" and ins.target is not None:
                    target_va = combined_map.get(ins.target, ins.target)
                    seq = [
                        encode_adrp(cur_va, target_va, 16) if _pass == 1 else 0x90000010,
                        encode_add_imm(16, 16, target_va & 0xFFF, 64),
                        _encode_blr(16),
                    ]
                    words.extend(seq)
                    cur_va += len(seq) * 4
                else:
                    if _pass == 1:
                        rel_seq = relocate_insn(ins, cur_va, combined_map)
                    else:
                        # Reserve maximum possible length for conditional branches / ADR
                        if ins.mnemonic in ("b.cond", "cbz", "cbnz", "tbz", "tbnz", "adr"):
                            rel_seq = [ins.raw, 0xD503201F]
                        else:
                            rel_seq = [ins.raw]
                    if _pass == 1 and ins.mnemonic in ("b.cond", "cbz", "cbnz", "tbz", "tbnz", "adr") and len(rel_seq) == 1:
                        rel_seq = [rel_seq[0], 0xD503201F]
                    words.extend(rel_seq)
                    cur_va += len(rel_seq) * 4

                # Connect fallthrough block transition
                if is_last and ins.op_class not in ("ret", "br", "branch"):
                    fallthrough_idx = b_idx + 1
                    if fallthrough_idx < num_blocks:
                        if use_flatten:
                            seq = encode_mov_imm(scratch_a, state_ids[fallthrough_idx], 32)
                            jmp = encode_b(cur_va + len(seq) * 4, dispatcher_va) if _pass == 1 else 0x14000000
                            words.extend(seq + [jmp])
                            cur_va += (len(seq) + 1) * 4
                        else:
                            next_in_order = block_order[order_pos + 1] if order_pos + 1 < num_blocks else -1
                            if next_in_order != fallthrough_idx:
                                jmp = encode_b(cur_va, block_vas[fallthrough_idx]) if _pass == 1 else 0x14000000
                                words.append(jmp)
                                cur_va += 4

    return b"".join(struct.pack("<I", w) for w in words)


def build_string_resolver_stub(stub_va, string_id, rd, resolve_fn_va, resume_va):
    """Emit a register-preserving stub in .guard that resolves string_id into Rd and jumps to resume_va (E03)."""
    assert 0 <= rd < 31
    words = [
        0xD102C3FF,  # sub sp, sp, #176
        0xA90007E0,  # stp x0, x1, [sp, #0]
        0xA9010FE2,  # stp x2, x3, [sp, #16]
        0xA90217E4,  # stp x4, x5, [sp, #32]
        0xA9031FE6,  # stp x6, x7, [sp, #48]
        0xA90427E8,  # stp x8, x9, [sp, #64]
        0xA9052FEA,  # stp x10, x11, [sp, #80]
        0xA90637EC,  # stp x12, x13, [sp, #96]
        0xA9073FEE,  # stp x14, x15, [sp, #112]
        0xA90847F0,  # stp x16, x17, [sp, #128]
        0xA90977F2,  # stp x18, x29, [sp, #144]
        0xD53B420F,  # mrs x15, nzcv
        0xA90A7BEF,  # stp x15, x30, [sp, #160]
        encode_movz(0, string_id & 0xFFFF, 0, 64),
    ]
    call_va = stub_va + len(words) * 4
    words.append(encode_b(call_va, resolve_fn_va, link=True))
    # Store returned X0 into stack slot for Rd (if rd <= 18 or rd in (29, 30)),
    # or copy X0 directly into callee-saved X19..X28 BEFORE restoring X0 from stack!
    if rd <= 18:
        slot_imm12 = rd  # scaled by 8 in STR X0, [SP, #(rd*8)]
        str_x0_slot = 0xF90003E0 | ((slot_imm12 & 0xFFF) << 10)
        words.append(str_x0_slot)
    elif rd == 29:
        words.append(0xF9004FE0)  # str x0, [sp, #152]
    elif rd == 30:
        words.append(0xF90057E0)  # str x0, [sp, #168]
    else:
        words.append(0xAA0003E0 | (rd & 0x1F))  # mov Xrd, x0 (for X19..X28)
    restore = [
        0xA94A7BEF,  # ldp x15, x30, [sp, #160]
        0xD51B420F,  # msr nzcv, x15
        0xA94007E0,  # ldp x0, x1, [sp, #0]
        0xA9410FE2,  # ldp x2, x3, [sp, #16]
        0xA94217E4,  # ldp x4, x5, [sp, #32]
        0xA9431FE6,  # ldp x6, x7, [sp, #48]
        0xA94427E8,  # ldp x8, x9, [sp, #64]
        0xA9452FEA,  # ldp x10, x11, [sp, #80]
        0xA94637EC,  # ldp x12, x13, [sp, #96]
        0xA9473FEE,  # ldp x14, x15, [sp, #112]
        0xA94847F0,  # ldp x16, x17, [sp, #128]
        0xA94977F2,  # ldp x18, x29, [sp, #144]
        0x9102C3FF,  # add sp, sp, #176
    ]
    words.extend(restore)
    end_va = stub_va + len(words) * 4
    words.append(encode_b(end_va, resume_va, link=False))
    return b"".join(struct.pack("<I", w) for w in words)


def build_on_demand_stub(stub_va, range_idx, relocated_body_va, toggle_fn_va):
    """Emit an entry/exit wrapper in .guard that decrypts range_idx, calls relocated_body_va, and re-encrypts (R07)."""
    words = [
        0xD503245F,  # bti c
        0xD10183FF,  # sub sp, sp, #96
        0xA90007E0,  # stp x0, x1, [sp, #0]
        0xA9010FE2,  # stp x2, x3, [sp, #16]
        0xA90217E4,  # stp x4, x5, [sp, #32]
        0xA9031FE6,  # stp x6, x7, [sp, #48]
        0xA90477E8,  # stp x8, x29, [sp, #64]
        0xF9002BFE,  # str x30, [sp, #80]
        encode_movz(0, range_idx & 0xFFFF, 0, 64),
        encode_movz(1, 1, 0, 64),
    ]
    words.append(encode_b(stub_va + len(words) * 4, toggle_fn_va, link=True))
    words.extend([
        0xA94007E0,  # ldp x0, x1, [sp, #0]
        0xA9410FE2,  # ldp x2, x3, [sp, #16]
        0xA94217E4,  # ldp x4, x5, [sp, #32]
        0xA9431FE6,  # ldp x6, x7, [sp, #48]
        0xA94477E8,  # ldp x8, x29, [sp, #64]
    ])
    words.append(encode_b(stub_va + len(words) * 4, relocated_body_va, link=True))
    words.extend([
        0xA90007E0,  # stp x0, x1, [sp, #0] (save return values)
        encode_movz(0, range_idx & 0xFFFF, 0, 64),
        encode_movz(1, 0, 0, 64),
    ])
    words.append(encode_b(stub_va + len(words) * 4, toggle_fn_va, link=True))
    words.extend([
        0xA94007E0,  # ldp x0, x1, [sp, #0]
        0xA94477E8,  # ldp x8, x29, [sp, #64]
        0xF9402BFE,  # ldr x30, [sp, #80]
        0x910183FF,  # add sp, sp, #96
        0xD65F03C0,  # ret
    ])
    return b"".join(struct.pack("<I", w) for w in words)


def scrub_elf_metadata(data, keep_debug_path=None):
    """Remove non-essential non-allocated metadata (.comment, compiler strings) without breaking Bionic (E06)."""
    elf = ELF(data)
    if keep_debug_path:
        Path(keep_debug_path).parent.mkdir(parents=True, exist_ok=True)
        Path(keep_debug_path).write_bytes(elf.data)
    out = bytearray(elf.data)
    scrubbed_sections = []
    for sec in elf.sections:
        # Never touch allocated sections or section header string table
        if (sec.flags & 0x2) or sec.type in (0, 8) or sec == elf.sections[elf.shstrndx]:
            continue
        if sec.name in (".comment", ".note.gnu.gold-version", ".ARM.attributes") or sec.name.startswith(".debug"):
            if sec.size > 0 and sec.offset + sec.size <= len(out):
                out[sec.offset:sec.offset + sec.size] = bytes(sec.size)
                scrubbed_sections.append(sec.name)
    return bytes(out), scrubbed_sections


DEFAULT_BARCODE_CHARS = "IlO0"
DEFAULT_BARCODE_LENGTH = 17
BARCODE_CHARS = DEFAULT_BARCODE_CHARS

DEFAULT_TROLL_DECOYS = [
    ("Bam_F5_Lam_Cho_Nhe_Bro_01", "[Trolled] Da bao dung bam F5 roi ma van co tinh bam =)) Tat IDA di uong ca phe di bro!", "[Trolled] Bam F5 nua cung chi ra dong nay thoi bro!"),
    ("Soi_Cai_Gi_Ma_Soi_Tat_Decompiler_Di_02", "[Trolled] Soi cai gi ma soi! Code that an ky lam roi, tim trong mo di ban oi!", "[Trolled] Nhin gi ma nhin, dong decompiler di nghi ngoi di =))"),
    ("Bypass_Protection_100_Percent_Real_03", "[Trolled] Bypass thanh cong 100%... trong tri tuong tuong cua ban =)) Chuc may man lan sau!", "[Trolled] System status: STILL PROTECTED =))"),
    ("Decrypt_AES256_MasterKey_Plaintext_04", "MasterKey = Il1lI0O0_LAM_GI_CO_KEY_O_DAY_MA_TIM_HAHA", "Secret_Key = KHONG_CO_DAU_SOI_NHAM_CHO_ROI =))"),
    ("Xin_Vinh_Biet_Cu_Sub_XXXXXX_05", "[Trolled] Xin vinh biet cu! Toan bo ham sub_XXXXXX da hoa thanh ma vach =))", "[Trolled] RIP sub_000000 - Da doi ten toan bo!"),
    ("Decompiler_Detected_Say_Hi_06", "[Trolled] Hello nguoi anh em dung IDA / Ghidra / Binary Ninja! Ngoi choi xoi nuoc nhe =))", "[Trolled] Decompiler nao cung gap cau chao nay thoi bro!"),
    ("Key_Crack_VIP_Full_Chuc_Nang_Free_07", "VIP_LICENSE_KEY = 'NGOI_DO_MA_MO_FREE_KEY_NHE_BRO_DI_NGU_DI_0x1337'", "License het han trong giac mo roi bro =))"),
    ("HexRays_F5_Decompiler_Killer_08", "[Trolled] Bam F5 ra ham C sach dep lam dung khong? Tiec la toan chuoi troll thoi =))", "[Trolled] Ctrl+F5 hay F5 cung khong cuu duoc dau!"),
    ("Tim_Dia_Chi_Bo_Nho_Bi_Mat_09", "Secret_Struct_Ptr = 0xDEAD_BEEF_CAFE_BABE; // Tim thay thi chuc mung ban da bi lua =))", "Real_Offset = 0x0000_0000_NOTHING_HERE"),
    ("Khoc_Di_Em_Reverse_Engineer_10", "[Trolled] Nhin danh sach ham hoa mat chua bro? Nho nho thuoc nho mat truoc khi soi tiep nhe!", "[Trolled] Dung quen chop mat keo can thi do bro!"),
    ("IDA_Ghidra_Binja_Radare2_Bo_Tay_11", "[Trolled] Du ban dung IDA Pro, Ghidra, Binary Ninja hay Radare2 thi cung doc dong nay thoi :)", "[Trolled] Decompile xong nho cuoi mot cai nhe =))"),
    ("Dump_Memory_Frida_GG_Thu_Xem_12", "[Trolled] Dump RAM thu xem di bro =)) Chuc ban tim vui giua bien rac thu vi nay nhe!", "[Trolled] Dump xong nho uong nuoc cho do kho co nhe!"),
    ("Code_Nay_Viet_Bang_Tinh_Yeu_Va_Nuoc_Mat_13", "[Trolled] Dung dich nguoc nua bro oi, dev thuc khuya code vat va lam, tha cho em no di uong tra sua :)", "[Trolled] Code viet bang mo hoi, ca phe va deadline day!"),
    ("Ban_Co_Tam_Nhung_Protect3_Co_Tam_Hon_14", "[Trolled] Kien tri bam F5 toi tan ham 14 luon ha? Tang ban danh hieu Tho San Ham Ao!", "[Trolled] Phia duoi con ca dong ham troll nua, co len!"),
    ("Server_Auth_Token_Private_RSA_4096_15", "-----BEGIN TROLL PRIVATE KEY----- FAKE_KEY_DO_NOT_COPY_HAHA -----END TROLL PRIVATE KEY-----", "Signature = VALID_ONLY_IN_ANOTHER_UNIVERSE"),
    ("Anti_Hook_Frida_Dobby_Substrate_Check_16", "[Trolled] Dinh hook ham nay ha? Day la ham moi (honeypot) de cau view thoi bro =))", "[Trolled] Hook vo day la an cu lua roi nguoi anh em!"),
    ("Bypass_SSL_Pinning_Certificate_Verify_17", "[Trolled] Tuong tim duoc cho tat SSL Pinning trong lib nay a? Nham to roi, thu cho khac di =))", "[Trolled] SSL_VERIFY_PIN = STILL_LOCKED =))"),
    ("Dynamic_Native_API_Resolver_Real_18", "[Trolled] Real_API_Table = 0x00000000; // Thu van may o cho khac xem sao nhe bro =))", "[Trolled] Keep looking, maybe in another section!"),
    ("Ascii_Art_Smile_For_Reverse_Engineer_19", "  ( ^_^)/  Hello Reverse Engineer! Take a break, drink some coffee, and enjoy the barcode!  \\(^_^ ) ", "   \\_(o_O)_/   Protected Library!"),
    ("Thong_Diep_Tu_Vu_Tru_Gui_Nguoi_Soi_Lib_20", "[Trolled] Vu tru nhan nhu: File .so nay da duoc khoa chat, dung ton thanh xuan ngoi doc asm nua =))", "[Trolled] Thanh xuan co han, dung soi lib vo vong!"),
    ("Bam_Ctrl_F5_Decompile_All_Thu_Xem_21", "[Trolled] Bam Ctrl+F5 Decompile All cung chi xuat ra may cau chuc suc khoe nay thoi bro oi =))", "[Trolled] Decompile All -> 100% Trolled C pseudocode!"),
    ("Check_License_Response_200_OK_22", "{\"status\": \"trolled\", \"vip\": false, \"msg\": \"Nice try bro! Di ngu som di cho khoe\"}", "{\"authorized\": false, \"hint\": \"Giac mo con dai\"}"),
    ("Unlock_Pro_Max_Ultra_VIP_Forever_23", "[Trolled] Kich hoat goi Pro Max Ultra VIP thanh cong... trong giac mo toi nay! Chuc ngu ngon =))", "[Trolled] Chuc ban ngu ngon sau mot ngay dai soi .so!"),
    ("Tra_Ve_Flag_CTF_Giai_Tri_24", "FLAG{Nhin_Biet_Ngay_La_Ban_Dang_Do_Strings_Dung_Khong_Haha}", "FLAG{Khong_Co_Flag_That_O_Day_Dau_Bro}"),
    ("Ham_Check_Root_Gia_De_Danh_Lac_Huong_25", "isDeviceRooted() { return 42; // Sua thanh return 0 cung chang anh huong gi den code that =)) }", "isEmulator() -> KEEP_GUESSING_BRO"),
    ("Giai_Ma_Chuoi_Bang_Suc_Manh_Niem_Tin_26", "[Trolled] Ban vua doc thanh cong mot cau chao buoi toi! Phan thuong la mot nu cuoi =))", "[Trolled] Chuoi that khong nam o day dau bro!"),
    ("Bao_Cao_Tien_Do_Soi_Code_Hom_Nay_27", "[Trolled] Tien do dich nguoc hom nay: 0% code that, 100% ham bay F5. Rat tuyet voi!", "[Trolled] Ngay mai soi tiep hay nghi ngoi nhi?"),
    ("Gia_Bo_Loi_Memory_Corrupt_De_Doa_28", "[Trolled] CRITICAL ALERT: Ban vua doc nham ham giai tri, he thong khong co loi gi ca =))", "[Trolled] Relax, just a harmless decoy function!"),
    ("Cong_Thuc_Tinh_Toan_Sieu_Bi_Mat_29", "secret_formula = (ca_phe * 2 + thuc_dem) / bug_phat_sinh; // Khong co thuat toan bi mat nao o day", "magic_constant = 0xCAFE_BABE_1337"),
    ("Gui_Loi_Chuc_Nguoi_Anh_Em_Mobile_Sec_30", "[Trolled] Kinh chuc anh em Mobile Security & Reverse Engineer mat sang, tay vung, ban phim ben!", "[Trolled] Gui loi chao tran trong nhat den ban!"),
    ("Ham_Phat_Hien_Bam_Tab_Qua_Assembly_31", "[Trolled] Bam Tab chuyen qua cua so Assembly xem thu ha? Cung van la may dong nay thoi bro =))", "[Trolled] Disassembly cung dep khong kem F5 dung khong?"),
    ("Gia_Vo_Export_JNI_Bi_An_32", "[Trolled] Tuong day la cho giau thuat toan bi mat ha? Chuc mung ban da doc dung ham giai tri!", "[Trolled] Day chi la ham trang tri cho dep danh sach thoi!"),
    ("Kiem_Tra_Chu_Ky_APK_Signature_Fake_33", "expected_apk_sha256 = 'HAHA_DAY_LA_HASH_GIA_DUNG_PATCH_MAT_CONG_NHE_BAN_OI';", "signature_valid = ALWAYS_FALSE_IN_YOUR_DREAMS"),
    ("Ghi_Chu_Cua_Tac_Gia_File_SO_34", "// TODO: Nho an ky doan nay truoc khi release! (Da giau ky lam roi, yen tam =))", "// NOTE: Decoy function injected cleanly."),
    ("Phan_Mem_Khong_Co_Backdoor_Chi_Co_Troll_35", "[Trolled] Yen tam, ham nay hoan toan vo hai, chi return con tro chuoi nay de treu nguoi soi thoi!", "[Trolled] Zero side effects, 100% pure humor!"),
    ("Ket_Thuc_Chuyen_Tham_Quan_Thu_Vien_36", "[Trolled] Chuyen tham quan file .so ket thuc tai day. Chuc ban mot ngay lam viec vui ve!", "[Trolled] Goodbye! See you in the next build :)"),
]
TROLL_DECOYS = DEFAULT_TROLL_DECOYS

TROLL_PHRASES = [name for name, _, _ in DEFAULT_TROLL_DECOYS]


def _fold_vietnamese_ascii(text):
    """Normalize Vietnamese diacritics into clean ASCII for C/ELF identifiers and Hex-Rays string literals."""
    text = str(text or "").replace("đ", "d").replace("Đ", "D")
    norm = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in norm if not unicodedata.combining(ch))


def sanitize_troll_symbol_name(name, fallback="Troll_Func"):
    """Clean a user-supplied symbol name into a valid ARM64 ELF / C identifier."""
    folded = _fold_vietnamese_ascii(name).strip()
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", folded).strip("_")
    if not cleaned:
        cleaned = fallback
    if cleaned[0].isdigit():
        cleaned = f"T_{cleaned}"
    return cleaned[:160]


def sanitize_troll_string(text, fallback="[Protect3] Trolled by Protect3!"):
    """Normalize troll text so Hex-Rays renders clean printable string literals instead of byte arrays."""
    raw = _fold_vietnamese_ascii(text).replace("\r\n", " ").replace("\n", " ").strip()
    ascii_clean = "".join(ch if 32 <= ord(ch) <= 126 else "?" for ch in raw).strip()
    if not ascii_clean:
        return fallback
    return ascii_clean[:1024]


def normalize_barcode_chars(chars, allow_empty=False):
    """Validate and clean user-supplied barcode characters (e.g. 'IlO0')."""
    folded = _fold_vietnamese_ascii("" if chars is None else str(chars))
    pool = [ch for ch in folded if re.match(r"^[A-Za-z0-9_]$", ch)]
    cleaned = "".join(pool)
    if not cleaned and not allow_empty:
        raise ProtectionError("Bo ky tu random troll phai chua it nhat 1 ky tu hop le ([A-Za-z0-9_], vi du: IlO0).")
    return cleaned


def validate_barcode_length(length):
    """Parse and validate requested randomized barcode length (0..128)."""
    try:
        val = int(length)
    except (TypeError, ValueError) as exc:
        raise ProtectionError(f"Do dai chuoi troll khong hop le ({length!r}); nhap so nguyen 0..128.") from exc
    if val < 0 or val > 128:
        raise ProtectionError(f"Do dai chuoi troll phai trong khoang 0..128 (nhan duoc {val}).")
    return val


def generate_troll_barcode(seed, salt, index, chars, length, used_names=None, suffix=""):
    """Generate a deterministic-per-seed randomized barcode string of exact `length` from `chars`."""
    length = validate_barcode_length(length)
    if length == 0:
        candidate = sanitize_troll_symbol_name(suffix.lstrip("_"), fallback=f"troll_{index:04x}")
        if used_names is not None:
            base = candidate
            n = 1
            while candidate in used_names:
                candidate = f"{base}_{n}"
                n += 1
            used_names.add(candidate)
        return candidate

    pool = normalize_barcode_chars(chars)
    first_pool = [c for c in pool if not c.isdigit()] or list(pool)

    def roll(attempt):
        chars_out = []
        block_idx = 0
        raw_bytes = b""
        pos = 0
        while len(chars_out) < length:
            if pos >= len(raw_bytes):
                raw_bytes = hashlib.sha256(
                    f"p3-troll-{seed}-{salt}-{index}-{attempt}-{block_idx}".encode("utf-8")
                ).digest()
                block_idx += 1
                pos = 0
            b = raw_bytes[pos]
            pos += 1
            src = first_pool if not chars_out else pool
            chars_out.append(src[b % len(src)])
        return "".join(chars_out)

    # First try exact-length re-rolls so collision avoidance preserves target length cleanly
    for attempt in range(32):
        barcode = roll(attempt)
        candidate = f"{barcode}{suffix}"
        if used_names is None or candidate not in used_names:
            if used_names is not None:
                used_names.add(candidate)
            return candidate

    # Fallback when tiny alphabet/length combinations are exhausted across thousands of symbols
    base_barcode = roll(0)
    n = 1
    while True:
        candidate = f"{base_barcode}{suffix}_{n:x}"
        if used_names is None or candidate not in used_names:
            if used_names is not None:
                used_names.add(candidate)
            return candidate
        n += 1


def parse_troll_decoys_spec(spec):
    """Parse custom decoy function names & troll strings from JSON, file path, or 'name | main | alt' lines."""
    if not spec or not str(spec).strip():
        return list(DEFAULT_TROLL_DECOYS)

    raw_text = str(spec).strip()
    if raw_text.startswith("@"):
        raw_text = Path(raw_text[1:].strip()).read_text(encoding="utf-8")
    elif "\n" not in raw_text and "|" not in raw_text and not raw_text.startswith(("[", "{")):
        maybe_path = Path(raw_text)
        if maybe_path.is_file():
            raw_text = maybe_path.read_text(encoding="utf-8")

    parsed_rows = []
    if raw_text.lstrip().startswith("["):
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ProtectionError(f"JSON danh sach ham troll khong hop le: {exc}") from exc
        if not isinstance(data, list):
            raise ProtectionError("JSON danh sach ham troll phai la mang [...].")
        for i, item in enumerate(data, start=1):
            if isinstance(item, dict):
                raw_name = item.get("name", f"Troll_Func_{i:02d}")
                raw_main = item.get("msg", item.get("main", item.get("string", "")))
                raw_alt = item.get("alt", item.get("msg_alt", ""))
            elif isinstance(item, (list, tuple)):
                if not item:
                    continue
                raw_name = item[0]
                raw_main = item[1] if len(item) > 1 else ""
                raw_alt = item[2] if len(item) > 2 else ""
            else:
                continue
            name = sanitize_troll_symbol_name(raw_name, fallback=f"Troll_Func_{i:02d}")
            msg_main = sanitize_troll_string(raw_main, fallback=f"[Protect3] Trolled by {name}!")
            msg_alt = sanitize_troll_string(raw_alt, fallback=f"[1337] {msg_main}") if str(raw_alt).strip() else f"[1337] {msg_main}"
            parsed_rows.append((name, msg_main, msg_alt))
    else:
        lines = raw_text.splitlines() if "\n" in raw_text else raw_text.split(";")
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = [p.strip() for p in stripped.split("|")]
            if len(parts) == 1 and "=>" in stripped:
                parts = [p.strip() for p in stripped.split("=>", 1)]
            raw_name = parts[0] if parts else f"Troll_Func_{i:02d}"
            raw_main = parts[1] if len(parts) > 1 else ""
            raw_alt = parts[2] if len(parts) > 2 else ""
            name = sanitize_troll_symbol_name(raw_name, fallback=f"Troll_Func_{i:02d}")
            msg_main = sanitize_troll_string(raw_main, fallback=f"[Protect3] Trolled by {name}!")
            msg_alt = sanitize_troll_string(raw_alt, fallback=f"[1337] {msg_main}") if raw_alt else f"[1337] {msg_main}"
            parsed_rows.append((name, msg_main, msg_alt))

    if not parsed_rows:
        raise ProtectionError("Danh sach ham/string troll khong co dong hop le nao.")
    if len(parsed_rows) > 128:
        raise ProtectionError("Toi da 128 ham troll F5 duoc ho tro moi thu vien.")
    return parsed_rows


def format_troll_decoys_spec(items):
    """Serialize decoy tuples to compact JSON string for Options/CLI/GUI transport."""
    payload = [
        {
            "name": sanitize_troll_symbol_name(name, fallback=f"Troll_Func_{i:02d}"),
            "msg": sanitize_troll_string(msg_main),
            "alt": sanitize_troll_string(msg_alt),
        }
        for i, (name, msg_main, msg_alt) in enumerate(items, start=1)
    ]
    return json.dumps(payload, ensure_ascii=False)


def build_gg_honeypot_page(seed=0):
    """Build a 4 KiB decoy/canary page filled with plausible fake URLs, tokens, and scanner numeric lures.

    Contains no references to Protect3 or internal protection primitives (OpSec safe).
    """
    decoy_strings = [
        b"https://api-edge-gateway.example.invalid/v2/session/verify\x00",
        b"https://auth-relay-node01.example.invalid/oauth/token\x00",
        b"https://cdn-config-sync.example.invalid/app/manifest.json\x00",
        b"wss://realtime-telemetry.example.invalid/ws/heartbeat\x00",
        b"license_tier=ULTRA_VIP_999999\x00",
        b"session_token=DECOY_0000_DEAD_BEEF_CAFE_BABE_IGNORE\x00",
        b"api_secret_salt=HONEYPOT_CANARY_VALUE_DO_NOT_EDIT\x00",
        b"admin_override_pin=13379999\x00",
        b"balance_credits=999999999\x00",
        b"unlock_all_features=1\x00",
    ]
    buf = bytearray()
    for item in decoy_strings:
        buf.extend(item)
        while len(buf) % 8:
            buf.append(0)
    # Append enticing 32-bit/64-bit integer lures often searched via memory editors
    for val in (999999, 13371337, 999999999, 88888888, 0xCAFEBABE, 0x1337C0DE, 7777777, 1000000):
        buf.extend(struct.pack("<Q", val))
    seed_bytes = str(seed).encode("utf-8")
    counter = 0
    while len(buf) < 4096:
        block = hashlib.sha256(seed_bytes + struct.pack("<I", counter)).digest()
        buf.extend(block)
        counter += 1
    return bytes(buf[:4096])


def build_ida_troll_decoys(
    base_va,
    seed=0,
    barcode_chars=DEFAULT_BARCODE_CHARS,
    barcode_length=DEFAULT_BARCODE_LENGTH,
    decoys_spec="",
):
    """Emit ARM64 2-branch decoy functions in .guard that Hex-Rays (F5) decompiles cleanly."""
    barcode_length = validate_barcode_length(barcode_length)
    chars = normalize_barcode_chars(barcode_chars, allow_empty=(barcode_length == 0))
    decoy_items = parse_troll_decoys_spec(decoys_spec)

    buf = bytearray()
    records = []
    used_names = set()
    for idx, (base_name, msg_main, msg_alt) in enumerate(decoy_items, start=1):
        clean_base = sanitize_troll_symbol_name(base_name, fallback=f"Troll_Func_{idx:02d}")
        if barcode_length > 0:
            full_name = generate_troll_barcode(
                seed, "decoy", idx, chars, barcode_length, used_names=used_names, suffix=f"_{clean_base}",
            )
        else:
            full_name = generate_troll_barcode(
                seed, "decoy", idx, "IlO0", 0, used_names=used_names, suffix=f"_{clean_base}",
            )
        off = align(len(buf), 16)
        buf.extend(bytes(off - len(buf)))
        fn_va = base_va + len(buf)
        # Emit valid 2-branch ARM64 code (28 bytes before string pool):
        #   +0:  BTI c                (0xD503245F)
        #   +4:  CMP W0, #0x539       (0x7114E41F -> imm12=0x539 = 1337)
        #   +8:  B.EQ +12             (-> +20)
        #   +12: ADR X0, #16          (-> +28 = msg_main)
        #   +16: RET                  (0xD65F03C0)
        #   +20: ADR X0, #str_alt_off (-> msg_alt)
        #   +24: RET                  (0xD65F03C0)
        s1 = sanitize_troll_string(msg_main).encode("utf-8") + b"\x00"
        s1_padded = s1 + bytes(align(len(s1), 4) - len(s1))
        s2 = sanitize_troll_string(msg_alt).encode("utf-8") + b"\x00"
        s2_padded = s2 + bytes(align(len(s2), 4) - len(s2))
        msg1_va = fn_va + 28
        msg2_va = msg1_va + len(s1_padded)
        words = [
            0xD503245F,                              # +0: bti c
            0x7114E41F,                              # +4: cmp w0, #0x539 (1337)
            encode_bcond(fn_va + 8, fn_va + 20, 0),  # +8: b.eq -> +20
            encode_adr(fn_va + 12, msg1_va, 0),      # +12: adr x0, msg_main
            0xD65F03C0,                              # +16: ret
            encode_adr(fn_va + 20, msg2_va, 0),      # +20: adr x0, msg_alt
            0xD65F03C0,                              # +24: ret
        ]
        buf.extend(b"".join(struct.pack("<I", w) for w in words))
        buf.extend(s1_padded)
        buf.extend(s2_padded)
        records.append((full_name, fn_va, len(words) * 4))
    return bytes(buf), records


def apply_ida_troll_and_block(
    data,
    pre_strip_functions=None,
    decoy_records=None,
    guard_real_end_vaddr=0,
    troll_ida=False,
    block_ida=False,
    seed=0,
    barcode_chars=DEFAULT_BARCODE_CHARS,
    barcode_length=DEFAULT_BARCODE_LENGTH,
    decoys_spec="",
):
    """Inject synthetic .symtab/.strtab barcode/troll names (--troll-ida) and/or SHT TLS segment wipe (--block-ida)."""
    barcode_length = validate_barcode_length(barcode_length)
    chars = normalize_barcode_chars(barcode_chars, allow_empty=(barcode_length == 0))
    if not troll_ida and not block_ida:
        return bytes(data), {
            "troll_ida": False,
            "block_ida": False,
            "troll_barcode_chars": chars,
            "troll_barcode_length": barcode_length,
            "custom_decoys_used": bool(str(decoys_spec or "").strip()),
            "renamed_functions_count": 0,
            "decoy_functions_count": 0,
            "decoy_names_preview": [],
        }

    out = bytearray(data)
    elf = ELF(out)
    sections = list(elf.sections)
    shstrtab_sec = sections[elf.shstrndx]
    shstrtab_bytes = bytearray(elf.section_data(shstrtab_sec))

    def add_shstr(name_str):
        off = len(shstrtab_bytes)
        shstrtab_bytes.extend(name_str.encode("utf-8") + b"\x00")
        return off

    exec_loads = [s for s in elf.loads if (s.flags & 1) and s.filesz > 0]
    guard_load = next(
        (s for s in exec_loads if decoy_records and s.vaddr <= decoy_records[0][1] < s.vaddr + s.filesz),
        max(exec_loads, key=lambda s: s.vaddr) if exec_loads else max(elf.loads, key=lambda s: s.vaddr),
    )
    guard_end_vaddr = guard_load.vaddr + guard_load.filesz
    max_mapped_vaddr = max(s.vaddr + max(s.filesz, s.memsz) for s in elf.loads)
    top_vaddr = align(max(guard_end_vaddr, max_mapped_vaddr) + 0x10000, 0x10000)

    if block_ida:
        # SHT_NOBITS + SHF_TLS wrap-around wipes real code segments in IDA into an uninitialized .tls data block
        # while Android Bionic and libhoudini ignore non-dynamic section headers completely.
        wipe_limit = guard_real_end_vaddr if (troll_ida and decoy_records and guard_real_end_vaddr) else (top_vaddr + 0x100000)
        sections.append(Section(
            name_offset=add_shstr(".p3_max"),
            type=8,  # SHT_NOBITS
            flags=2, # SHF_ALLOC
            addr=top_vaddr,
            offset=guard_load.offset,
            size=0xFFFFFFFFFFFFFFFC - top_vaddr,
            link=0, info=0, alignment=1, entsize=0, name=".p3_max",
        ))
        sections.append(Section(
            name_offset=add_shstr(".p3_tls"),
            type=8,      # SHT_NOBITS
            flags=0x402, # SHF_ALLOC | SHF_TLS
            addr=0,
            offset=guard_load.offset,
            size=wipe_limit,
            link=0, info=0, alignment=8, entsize=0, name=".p3_tls",
        ))

    renamed_count = 0
    decoy_records = decoy_records or []
    if troll_ida:
        if block_ida and decoy_records:
            decoy_base_va = decoy_records[0][1]
            decoy_file_off = guard_load.offset + (decoy_base_va - guard_load.vaddr)
            guard_shndx = len(sections)
            sections.append(Section(
                name_offset=add_shstr(".troll_ida"),
                type=1,  # SHT_PROGBITS
                flags=6, # SHF_ALLOC | SHF_EXECINSTR
                addr=decoy_base_va,
                offset=decoy_file_off,
                size=guard_end_vaddr - decoy_base_va,
                link=0, info=0, alignment=16, entsize=0, name=".troll_ida",
            ))
        else:
            guard_shndx = len(sections)
            sections.append(Section(
                name_offset=add_shstr(".guard"),
                type=1,  # SHT_PROGBITS
                flags=6, # SHF_ALLOC | SHF_EXECINSTR
                addr=guard_load.vaddr,
                offset=guard_load.offset,
                size=guard_load.filesz,
                link=0, info=0, alignment=16, entsize=0, name=".guard",
            ))

        def shndx_for_va(va):
            for i, s in enumerate(sections):
                if s.type == 1 and (s.flags & 0x4) and s.addr <= va < s.addr + s.size:
                    return i
            return guard_shndx

        func_map = {}
        explicit_names = {}
        for d_name, d_va, d_sz in decoy_records:
            func_map[d_va] = d_sz
            explicit_names[d_va] = d_name

        if not block_ida:
            for f in (pre_strip_functions or []):
                func_map.setdefault(f.vaddr, max(4, f.size))

            for sec in sections:
                if sec.type == 1 and (sec.flags & 0x4) and sec.addr:
                    func_map.setdefault(sec.addr, 16)

            exec_ranges = [(seg.vaddr, seg.vaddr + seg.filesz) for seg in elf.loads if seg.flags & 1]

            def in_exec(addr):
                return any(lo <= addr < hi for lo, hi in exec_ranges)

            # Identify noreturn functions (containing SVC #0 = 0xD4000001) in .guard
            guard_bytes = out[guard_load.offset : guard_load.offset + guard_load.filesz]
            noreturn_vas = set()
            for off in range(0, len(guard_bytes) - 3, 4):
                w, = struct.unpack_from("<I", guard_bytes, off)
                if w == 0xD4000001:
                    # Walk back to function start (STP or BTI)
                    for back in range(off, max(-1, off - 256), -4):
                        wb, = struct.unpack_from("<I", guard_bytes, back)
                        if wb == 0xD503245F or (wb & 0xFFC003FF) == 0xA98003FD or (back >= 4 and struct.unpack_from("<I", guard_bytes, back - 4)[0] == 0xD65F03C0):
                            noreturn_vas.add(guard_load.vaddr + back)
                            break

            decoy_min_va = decoy_records[0][1] if decoy_records else guard_end_vaddr
            text_sec = elf.section(".text")
            plt_sec = elf.section(".plt")
            if plt_sec and plt_sec.size >= 32:
                func_map.setdefault(plt_sec.addr, 32)
                for pva in range(plt_sec.addr + 32, plt_sec.addr + plt_sec.size, 16):
                    func_map.setdefault(pva, 16)
            branch_floor = plt_sec.addr if plt_sec else guard_load.vaddr
            for seg in elf.loads:
                if not (seg.flags & 1):
                    continue
                seg_bytes = out[seg.offset : seg.offset + seg.filesz]
                func_map.setdefault(seg.vaddr, 16)
                in_text_seg = bool(text_sec and seg.vaddr <= text_sec.addr < seg.vaddr + seg.filesz)
                for off in range(0, len(seg_bytes) - 3, 4):
                    va = seg.vaddr + off
                    if seg.vaddr == guard_load.vaddr and va >= decoy_min_va:
                        break
                    in_cipher_text = bool(in_text_seg and text_sec.addr <= va < text_sec.addr + text_sec.size)
                    w, = struct.unpack_from("<I", seg_bytes, off)
                    # Unconditional B / BL
                    if (w & 0x7C000000) == 0x14000000:
                        imm26 = w & 0x03FFFFFF
                        if imm26 & (1 << 25):
                            imm26 -= 1 << 26
                        target = va + (imm26 << 2)
                        if in_exec(target) and target < decoy_min_va:
                            if not in_cipher_text or target >= branch_floor:
                                func_map.setdefault(target, 16)
                        if not in_cipher_text and (w & 0xFC000000) == 0x94000000 and target in noreturn_vas and off + 4 < len(seg_bytes):
                            func_map.setdefault(va + 4, 16)
                    if in_cipher_text:
                        # Catch encrypted bytes decoded by IDA as ADR targeting .guard / .plt
                        if (w & 0x9F000000) == 0x10000000:
                            immlo = (w >> 29) & 0x3
                            immhi = (w >> 5) & 0x7FFFF
                            imm21 = (immhi << 2) | immlo
                            if imm21 & (1 << 20):
                                imm21 -= 1 << 21
                            target = (va + imm21) & ~3
                            if in_exec(target) and branch_floor <= target < decoy_min_va:
                                func_map.setdefault(target, 16)
                        continue
                    # B.cond or CBZ/CBNZ targeting .plt or .guard
                    if (w & 0xFF000010) == 0x54000000 or (w & 0x7E000000) == 0x34000000:
                        imm19 = (w >> 5) & 0x7FFFF
                        if imm19 & (1 << 18):
                            imm19 -= 1 << 19
                        target = va + (imm19 << 2)
                        if in_exec(target) and branch_floor <= target < decoy_min_va:
                            func_map.setdefault(target, 16)
                    # TBZ / TBNZ targeting .plt or .guard
                    if (w & 0x7E000000) == 0x36000000:
                        imm14 = (w >> 5) & 0x3FFF
                        if imm14 & (1 << 13):
                            imm14 -= 1 << 14
                        target = va + (imm14 << 2)
                        if in_exec(target) and branch_floor <= target < decoy_min_va:
                            func_map.setdefault(target, 16)
                    if w == 0xD503245F:
                        func_map.setdefault(va, 16)
                    if seg.vaddr == guard_load.vaddr and off >= 4 and w != 0:
                        prev, = struct.unpack_from("<I", seg_bytes, off - 4)
                        if (
                            prev in (0, 0xD65F03C0, 0xD63F0200)
                            or (prev & 0xFC000000) == 0x14000000
                            or (prev & 0xFFE0001F) == 0xD4200000
                        ):
                            func_map.setdefault(va, 16)

        active_phrases = [name for name, _, _ in parse_troll_decoys_spec(decoys_spec)] if troll_ida else TROLL_PHRASES
        used_sym_names = set(explicit_names.values())

        def make_troll_name(va, idx):
            if va in explicit_names:
                return explicit_names[va]
            if va >= guard_load.vaddr or idx % 5 == 0:
                phrase = sanitize_troll_symbol_name(active_phrases[idx % len(active_phrases)])
                if barcode_length > 0:
                    return generate_troll_barcode(
                        seed, f"{va:#x}", idx, chars, barcode_length, used_names=used_sym_names, suffix=f"_{phrase}",
                    )
                return generate_troll_barcode(
                    seed, f"{va:#x}", idx, "IlO0", 0, used_names=used_sym_names, suffix=f"_{phrase}",
                )
            return generate_troll_barcode(
                seed, f"{va:#x}", idx, chars if barcode_length > 0 else "IlO0", barcode_length if barcode_length > 0 else 12,
                used_names=used_sym_names,
            )

        strtab = bytearray(b"\x00")
        symtab = bytearray(SYM.pack(0, 0, 0, 0, 0, 0))
        for idx, (va, sz) in enumerate(sorted(func_map.items()), start=1):
            name_str = make_troll_name(va, idx)
            name_off = len(strtab)
            strtab.extend(name_str.encode("utf-8") + b"\x00")
            shndx = shndx_for_va(va)
            symtab.extend(SYM.pack(name_off, 2, 0, shndx, va, sz))
            renamed_count += 1

        strtab_off = align(len(out), 8)
        out.extend(bytes(strtab_off - len(out)) + strtab)
        symtab_off = align(len(out), 8)
        out.extend(bytes(symtab_off - len(out)) + symtab)

        # Replace any pre-existing unstripped .symtab/.strtab in-place so static tools cannot fall back to original names
        existing_symtab_idxs = [i for i, s in enumerate(sections) if s.type == 2]
        if existing_symtab_idxs:
            sym_idx = existing_symtab_idxs[0]
            linked = sections[sym_idx].link
            reusable_strtab = (
                0 <= linked < len(sections)
                and linked != elf.shstrndx
                and sections[linked].type == 3
                and (sections[linked].flags & 2) == 0
            )
            if reusable_strtab:
                strtab_shndx = linked
                sections[strtab_shndx] = Section(
                    name_offset=sections[strtab_shndx].name_offset,
                    type=3, flags=0, addr=0,
                    offset=strtab_off, size=len(strtab), link=0, info=0, alignment=1, entsize=0, name=".strtab",
                )
            else:
                strtab_shndx = len(sections)
                sections.append(Section(
                    name_offset=add_shstr(".strtab"), type=3, flags=0, addr=0,
                    offset=strtab_off, size=len(strtab), link=0, info=0, alignment=1, entsize=0, name=".strtab",
                ))
            sections[sym_idx] = Section(
                name_offset=sections[sym_idx].name_offset,
                type=2, flags=0, addr=0,
                offset=symtab_off, size=len(symtab), link=strtab_shndx, info=len(symtab) // SYM.size,
                alignment=8, entsize=SYM.size, name=".symtab",
            )
            for extra_idx in existing_symtab_idxs[1:]:
                sections[extra_idx] = Section(
                    name_offset=sections[extra_idx].name_offset,
                    type=0, flags=0, addr=0, offset=0, size=0, link=0, info=0, alignment=1, entsize=0,
                    name=sections[extra_idx].name,
                )
        else:
            strtab_shndx = len(sections)
            sections.append(Section(
                name_offset=add_shstr(".strtab"), type=3, flags=0, addr=0,
                offset=strtab_off, size=len(strtab), link=0, info=0, alignment=1, entsize=0, name=".strtab",
            ))
            sections.append(Section(
                name_offset=add_shstr(".symtab"), type=2, flags=0, addr=0,
                offset=symtab_off, size=len(symtab), link=strtab_shndx, info=len(symtab) // SYM.size,
                alignment=8, entsize=SYM.size, name=".symtab",
            ))

    shstr_off = align(len(out), 8)
    out.extend(bytes(shstr_off - len(out)) + shstrtab_bytes)
    sections[elf.shstrndx] = Section(
        name_offset=shstrtab_sec.name_offset, type=3, flags=0, addr=0,
        offset=shstr_off, size=len(shstrtab_bytes), link=0, info=0, alignment=1, entsize=0, name=".shstrtab",
    )

    new_shoff = align(len(out), 8)
    out.extend(bytes(new_shoff - len(out)))
    for s in sections:
        out.extend(s.pack())

    hdr = list(EHDR.unpack_from(out, 0))
    hdr[6] = new_shoff
    hdr[12] = len(sections)
    out[:EHDR.size] = EHDR.pack(*hdr)

    return bytes(out), {
        "troll_ida": bool(troll_ida),
        "block_ida": bool(block_ida),
        "troll_barcode_chars": chars,
        "troll_barcode_length": barcode_length,
        "custom_decoys_used": bool(str(decoys_spec or "").strip()),
        "renamed_functions_count": renamed_count,
        "decoy_functions_count": len(decoy_records),
        "decoy_names_preview": [r[0] for r in decoy_records[:5]],
    }


def build_wrapped_elf(
    original_elf,
    ndk=None,
    allow_protected_payload=False,
    watermark_hex="",
    strip_wrapper_symbols=False,
    clean_wrapper_metadata=False,
):
    """Build a standalone ARM64 wrapper .so embedding an encrypted payload ELF (E08)."""
    original_elf.validate_target(allow_protected=allow_protected_payload)
    exports = original_elf.exported_symbols()
    object_exports = [name for name, info, _, _, _ in exports if (info & 0xF) == 1]
    if object_exports:
        raise ProtectionError(
            f"Whole-ELF wrapper (E08) refuses libraries with exported data objects ({object_exports[:3]}); "
            "only STT_FUNC exports can be forwarded via wrapper trampolines. "
            "Hãy tắt E08 (wrap_elf) và bật E09 (pack_elf / --pack-elf) để đóng gói thư viện C++/.so có STT_OBJECT."
        )
    func_exports = [name for name, info, _, _, _ in exports if (info & 0xF) == 2 and name]
    if not func_exports:
        raise ProtectionError(
            "Whole-ELF wrapper (E08) requires at least one exported function symbol (STT_FUNC). "
            "Hãy tắt E08 (wrap_elf) và bật E09 (pack_elf / --pack-elf) thay thế."
        )

    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    payload_plain = original_elf.data
    payload_cipher = chacha20(payload_plain, key, nonce, 1)
    plain_sha = hashlib.sha256(payload_plain).digest()
    summary = original_elf.summary()
    soname = summary.get("soname") or "libwrapped.so"
    wm_bytes = bytes.fromhex(watermark_hex) if watermark_hex else b""

    c_lines = [
        "#include <dlfcn.h>",
        "#include <fcntl.h>",
        "#include <stdint.h>",
        "#include <stdlib.h>",
        "#include <sys/syscall.h>",
        "#include <unistd.h>",
        f'#include "{(Path(__file__).resolve().parent.parent / "native" / "crypto.h").as_posix()}"',
    ]
    if wm_bytes:
        c_lines.append(
            f"__attribute__((used)) static const volatile u8 P3_WRAPPER_WM[{len(wm_bytes)}] = "
            f"{{{','.join(map(str, wm_bytes))}}};"
        )
    c_lines.extend([
        f"static const u8 PAYLOAD_KEY[32] = {{{','.join(map(str, key))}}};",
        f"static const u8 PAYLOAD_NONCE[12] = {{{','.join(map(str, nonce))}}};",
        f"static const u8 PAYLOAD_DIGEST[32] = {{{','.join(map(str, plain_sha))}}};",
        f"static const u8 PAYLOAD_DATA[{len(payload_cipher)}] = {{{','.join(map(str, payload_cipher))}}};",
        f"static void *p3_targets[{len(func_exports)}];",
        f"static const char *const p3_names[{len(func_exports)}] = {{",
    ])
    for name in func_exports:
        c_lines.append(f'    "{name}",')
    c_lines.extend([
        "};",
        "__attribute__((constructor)) static void p3_wrapper_init(void) {",
        f"    usize sz = {len(payload_cipher)}ul;",
        "    u8 *buf = (u8 *)malloc(sz);",
        "    if (!buf) _exit(176);",
        "    for (usize i = 0; i < sz; ++i) buf[i] = PAYLOAD_DATA[i];",
        "    p3_chacha20(buf, sz, PAYLOAD_KEY, PAYLOAD_NONCE, 1);",
        "    u8 actual[32]; unsigned diff = 0;",
        "    p3_sha256(buf, sz, actual);",
        "    for (unsigned i = 0; i < 32; ++i) diff |= actual[i] ^ PAYLOAD_DIGEST[i];",
        "    if (diff) _exit(175);",
        '    int fd = (int)syscall(__NR_memfd_create, "p3_payload", 1);',
        "    char path[128];",
        "    int unlink_after = 0;",
        "    if (fd >= 0) {",
        "        usize off = 0;",
        "        while (off < sz) {",
        "            ssize_t w = write(fd, buf + off, sz - off);",
        "            if (w <= 0) _exit(176);",
        "            off += (usize)w;",
        "        }",
        "        free(buf);",
        '        char prefix[] = "/proc/self/fd/";',
        "        unsigned p = 0; while (prefix[p]) { path[p] = prefix[p]; ++p; }",
        "        char digits[16]; unsigned d = 0; int v = fd;",
        "        if (v == 0) digits[d++] = '0';",
        "        while (v > 0) { digits[d++] = (char)('0' + (v % 10)); v /= 10; }",
        "        while (d > 0) path[p++] = digits[--d];",
        "        path[p] = 0;",
        "    } else {",
        '        char tmpl[] = "/data/local/tmp/.p3_payload_XXXXXX.so";',
        "        for (unsigned i = 0; i <= sizeof(tmpl); ++i) path[i] = tmpl[i];",
        "        fd = mkstemps(path, 3);",
        "        if (fd < 0) _exit(176);",
        "        usize off = 0;",
        "        while (off < sz) {",
        "            ssize_t w = write(fd, buf + off, sz - off);",
        "            if (w <= 0) _exit(176);",
        "            off += (usize)w;",
        "        }",
        "        free(buf);",
        "        unlink_after = 1;",
        "    }",
        "    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);",
        "    close(fd);",
        "    if (unlink_after) unlink(path);",
        "    if (!handle) _exit(177);",
        f"    for (unsigned i = 0; i < {len(func_exports)}; ++i) {{",
        "        p3_targets[i] = dlsym(handle, p3_names[i]);",
        "        if (!p3_targets[i]) _exit(177);",
        "    }",
        "}",
    ])
    for idx, name in enumerate(func_exports):
        c_lines.extend([
            f'__attribute__((naked, visibility("default"))) void {name}(void) {{',
            "    __asm__ volatile(",
            f'        "adrp x16, p3_targets+{idx * 8}\\n"',
            f'        "ldr x16, [x16, #:lo12:p3_targets+{idx * 8}]\\n"',
            '        "br x16\\n"',
            "    );",
            "}",
        ])

    crypto_c = Path(__file__).resolve().parent.parent / "native" / "crypto.c"
    with tempfile.TemporaryDirectory(prefix="protect3-wrap-") as tmp:
        src_path = Path(tmp) / "wrapper.c"
        out_path = Path(tmp) / "wrapped.so"
        src_path.write_text("\n".join(c_lines) + "\n", encoding="utf-8")
        command([
            ndk_tool("clang", ndk), "--target=aarch64-linux-android23", "-shared", "-fPIC", "-O2",
            "-Wl,-z,max-page-size=16384", "-Wl,-z,relro", "-Wl,-z,now",
            f"-Wl,-soname,{soname}",
            str(src_path), str(crypto_c), "-ldl", "-o", str(out_path),
        ])
        if strip_wrapper_symbols:
            stripped_path = Path(tmp) / "wrapped.stripped.so"
            command([ndk_tool("llvm-strip", ndk), "--strip-unneeded", "-o", str(stripped_path), str(out_path)])
            wrapped_bytes = stripped_path.read_bytes()
        else:
            wrapped_bytes = out_path.read_bytes()
    wrapper_scrubbed = []
    if clean_wrapper_metadata:
        wrapped_bytes, wrapper_scrubbed = scrub_elf_metadata(wrapped_bytes, None)

    return wrapped_bytes, {
        "mode": "whole_elf_payload_wrapper",
        "payload_size": len(payload_plain),
        "payload_sha256": hashlib.sha256(payload_plain).hexdigest(),
        "forwarded_exports": func_exports,
        "wrapper_stripped": bool(strip_wrapper_symbols),
        "wrapper_scrubbed_sections": wrapper_scrubbed,
    }


def stealth_magic_bytes(seed, is_ext=False):
    """Derive high-entropy per-build header bytes replacing plaintext ASCII guard/ext markers."""
    sbytes = struct.pack("<Q", seed & 0xFFFFFFFFFFFFFFFF)
    if is_ext:
        return hashlib.sha256(sbytes + b"\x50\x33\x45\x34\x03").digest()[:16]
    salt = hashlib.sha256(sbytes + b"\x50\x33\x47\x34\x01").digest()[:16]
    tag = hashlib.sha256(salt + b"\x50\x33\x47\x34\x02\x00\x00\x00").digest()[:8]
    return salt + tag


def encode_uleb128(value):
    """Encode an unsigned integer in little-endian ULEB128 format."""
    if value < 0:
        raise ValueError("ULEB128 requires non-negative integer.")
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def encode_sleb128(value):
    """Encode a signed integer in SLEB128 format."""
    out = bytearray()
    more = True
    while more:
        b = value & 0x7F
        value >>= 7
        if (value == 0 and (b & 0x40) == 0) or (value == -1 and (b & 0x40) != 0):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def encode_sparse_reloc_table(offsets):
    """Encode sorted relative offsets as delta ULEB128 records matching guard.c read_uleb."""
    out = bytearray()
    prev = 0
    for off in sorted(set(offsets)):
        out.extend(encode_uleb128(off - prev))
        prev = off
    return bytes(out)


def _deflate_raw(data):
    """Compress bytes using RFC 1951 raw DEFLATE (wbits=-15)."""
    comp = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
    return comp.compress(data) + comp.flush()


def compute_cipher_mac(key, meta_va, meta_sz, nonce, data):
    """Compute E04 two-stage HMAC-SHA256 matching guard.c verify_cipher_mac_explicit."""
    meta = struct.pack("<QQ12s", meta_va & 0xFFFFFFFFFFFFFFFF, meta_sz & 0xFFFFFFFFFFFFFFFF, nonce)
    inner = hmac.new(key, meta, hashlib.sha256).digest()
    return hmac.new(inner, data, hashlib.sha256).digest()


def compute_sparse_data_cipher_mac(key, data_vaddr, data_bytes, nonce, reloc_offsets, reloc_width=8):
    """Compute E04 HMAC-SHA256 over concatenated non-relocated .data ciphertext gaps."""
    meta = struct.pack("<QQ12s", data_vaddr & 0xFFFFFFFFFFFFFFFF, len(data_bytes) & 0xFFFFFFFFFFFFFFFF, nonce)
    inner = hmac.new(key, meta, hashlib.sha256).digest()
    mac = hmac.new(inner, b"", hashlib.sha256)
    relocs = sorted(set(o for o in reloc_offsets if 0 <= o < len(data_bytes)))
    r_idx = 0
    pos = 0
    dsize = len(data_bytes)
    while pos < dsize:
        nxt = relocs[r_idx] if r_idx < len(relocs) else -1
        if nxt != -1 and pos >= nxt:
            pos += reloc_width
            r_idx += 1
            continue
        stop = nxt if (nxt != -1 and nxt < dsize) else dsize
        if stop > pos:
            mac.update(data_bytes[pos:stop])
        pos = stop
    return mac.digest()


def compute_manifest_hmac(pubkey, cfg_bytes, ext_bytes_with_mac, str_cfg_bytes, data_enc_bytes, pack_bytes):
    """Compute E05 HMAC-SHA256 over the full .p3config manifest (zeroing manifest_mac slot [128:160])."""
    ext_zero = bytearray(ext_bytes_with_mac)
    ext_zero[128:160] = bytes(32)
    h = hmac.new(pubkey, cfg_bytes, hashlib.sha256)
    h.update(ext_zero)
    h.update(str_cfg_bytes)
    h.update(data_enc_bytes)
    h.update(pack_bytes)
    return h.digest()


def _midbody_targets_in_guard(code_bytes, base_va, candidates):
    """Identify any guard candidate targeted mid-body by another instruction in guard code."""
    intervals = sorted((base_va + c["vaddr"], base_va + c["vaddr"] + c["size"], c["name"]) for c in candidates)
    bad = set()
    n_words = len(code_bytes) // 4
    words = struct.unpack_from(f"<{n_words}I", code_bytes)
    for idx, w in enumerate(words):
        top = w >> 24
        if top not in (
            0x14, 0x15, 0x16, 0x17, 0x94, 0x95, 0x96, 0x97,
            0x34, 0x35, 0xB4, 0xB5, 0x36, 0x37, 0xB6, 0xB7, 0x54,
        ):
            continue
        va = base_va + idx * 4
        ins = decode_insn(va, w)
        target = ins.target
        if target is None:
            continue
        for lo, hi, name in intervals:
            if lo < target < hi and not (lo <= va < hi):
                bad.add(name)
    return bad


def obfuscate_guard_runtime(blob, meta, guard_base_va, seed, entry_name="p3_entry", append_offset=None):
    """Relocate & self-obfuscate guard C functions with MBA/CFF/opaque/<unknown> islands (O10)."""
    out = bytearray(blob)
    cfg_off = meta["symbols"]["p3_config"]
    candidates = list(meta.get("guard_obf_candidates", []))
    skip_names = {
        "p3_vm_bridge", "p3_gate_bridge", "p3_vm_call_trampoline",
        "memcpy", "memset", "sys6", "p3_spin_lock", "p3_spin_unlock",
    }
    mid_bad = _midbody_targets_in_guard(out[:cfg_off], guard_base_va, candidates)

    analyzed = []
    for c in candidates:
        name = c["name"]
        off = c["vaddr"]
        sz = c["size"]
        if (
            name in skip_names
            or name in mid_bad
            or name.startswith("$")
            or sz < 16
            or (off % 4) != 0
            or (sz % 4) != 0
            or off < 0
            or off + sz > cfg_off
        ):
            continue
        va = guard_base_va + off
        fn = FunctionInfo(name=name, vaddr=va, size=sz, source="guard", confidence="high")
        analyze_function_bytes(fn, out[off:off + sz])
        if fn.relocatable:
            analyzed.append((c, fn))

    if not analyzed:
        return out, 0, 0, {
            "obfuscated_guard_functions": 0, "guard_ext_size": 0,
            "entry_va": guard_base_va + meta["symbols"][entry_name], "ext_bytes": b"",
        }

    rng = random.Random(seed ^ 0x4F313047)
    rng.shuffle(analyzed)

    # Keep O07 linear state-machine dispatcher off high-iteration inner crypto/DEFLATE loops for fast app load.
    hot_loop_names = {
        "inf_decode_sym", "inf_build_tree", "p3_sha256_init", "p3_sha256",
        "p3_hmac_sha256", "sha256_update_vol", "decode_str", "contains", "scan_fd",
    }

    if append_offset is None:
        rem = len(out) % 16
        if rem:
            out.extend(bytes(16 - rem))
        ext_start_off = len(out)
    else:
        ext_start_off = align(append_offset, 16)

    # Pass 1: dry layout to compute exact post-obfuscation VA of every relocated guard function.
    cursor = ext_start_off
    va_remap = {}
    planned = []
    for idx, (c, fn) in enumerate(analyzed):
        new_off = align(cursor, 16)
        new_va = guard_base_va + new_off
        use_cff = (fn.name not in hot_loop_names) and (fn.block_count <= 48)
        dry = obfuscate_and_relocate_function(
            fn, new_va, seed ^ (idx * 0x517),
            enable_sub=True,
            enable_opaque_const=True,
            enable_opaque_pred=True,
            enable_indirect=True,
            enable_shuffle=True,
            enable_split=True,
            enable_flatten=use_cff,
            gate_bridge_va=None,
            enable_junk_islands=True,
            va_remap=None,
            ensure_bti=True,
        )
        va_remap[fn.vaddr] = new_va
        gap_words = 1 + (rng.randrange(0, 3))
        planned.append((c, fn, new_off, new_va, len(dry), gap_words, use_cff))
        cursor = new_off + len(dry) + gap_words * 4

    # Pass 2: emit relocated obfuscated bodies + patch original sites with BTI+B trampolines & <unknown> junk.
    ext_buf = bytearray()
    for idx, (c, fn, new_off, new_va, expected_len, gap_words, use_cff) in enumerate(planned):
        rel_cursor = new_off - ext_start_off
        while len(ext_buf) + 4 <= rel_cursor:
            ext_buf.extend(struct.pack("<I", _junk_unk_word(seed, ext_start_off + len(ext_buf))))
        if len(ext_buf) < rel_cursor:
            ext_buf.extend(bytes(rel_cursor - len(ext_buf)))
        final_code = obfuscate_and_relocate_function(
            fn, new_va, seed ^ (idx * 0x517),
            enable_sub=True,
            enable_opaque_const=True,
            enable_opaque_pred=True,
            enable_indirect=True,
            enable_shuffle=True,
            enable_split=True,
            enable_flatten=use_cff,
            gate_bridge_va=None,
            enable_junk_islands=True,
            va_remap=va_remap,
            ensure_bti=True,
        )
        if len(final_code) != expected_len:
            raise ProtectionError(f"Guard obfuscation layout drift in {fn.name}: {len(final_code)} != {expected_len}")
        ext_buf.extend(final_code)
        for g_i in range(gap_words):
            ext_buf.extend(struct.pack("<I", _junk_unk_word(seed ^ 0xA5A5, new_off + expected_len + g_i * 4)))

        old_off = c["vaddr"]
        old_va = fn.vaddr
        tramp = struct.pack("<II", 0xD503245F, encode_b(old_va + 4, new_va, link=False))
        out[old_off:old_off + 8] = tramp
        for w_off in range(8, c["size"], 4):
            out[old_off + w_off:old_off + w_off + 4] = struct.pack("<I", _junk_unk_word(seed ^ old_off, w_off))

    aligned_len = align(len(ext_buf), 16)
    while len(ext_buf) + 4 <= aligned_len:
        ext_buf.extend(struct.pack("<I", _junk_unk_word(seed, ext_start_off + len(ext_buf))))
    if len(ext_buf) < aligned_len:
        ext_buf.extend(bytes(aligned_len - len(ext_buf)))
    ext_bytes = bytes(ext_buf)
    if append_offset is None:
        out.extend(ext_bytes)

    orig_entry_va = guard_base_va + meta["symbols"][entry_name]
    new_entry_va = va_remap.get(orig_entry_va, orig_entry_va)
    return out, ext_start_off, len(ext_bytes), {
        "obfuscated_guard_functions": len(planned),
        "guard_ext_vaddr": guard_base_va + ext_start_off,
        "guard_ext_size": len(ext_bytes),
        "entry_va": new_entry_va,
        "ext_bytes": ext_bytes,
    }


def _build_sysv_hash(sym_names):
    """Build compact SysV DT_HASH table for kept dynamic symbols."""
    nchain = len(sym_names)
    nbucket = max(1, nchain | 1)
    buckets = [0] * nbucket
    chains = [0] * nchain

    def elf_hash(raw_name):
        h = 0
        for b in raw_name:
            h = ((h << 4) + b) & 0xFFFFFFFF
            g = h & 0xF0000000
            if g:
                h ^= g >> 24
            h &= ~g
        return h

    for idx in range(1, nchain):
        b = elf_hash(sym_names[idx]) % nbucket
        chains[idx] = buckets[b]
        buckets[b] = idx
    return struct.pack(f"<2I{nbucket}I{nchain}I", nbucket, nchain, *buckets, *chains)


def _pf_to_linux_prot(pf_flags):
    """Convert ELF PF_R/PF_W/PF_X (4/2/1) to Linux PROT_READ/WRITE/EXEC (1/2/4)."""
    return ((pf_flags & 4) >> 2) | (pf_flags & 2) | ((pf_flags & 1) << 2)


def build_packed_elf(
    input_bytes,
    guard_blob,
    guard_meta,
    flags,
    ext_flags,
    seed,
    obfuscate_guard=True,
    troll_ida=False,
    barcode_chars=DEFAULT_BARCODE_CHARS,
    barcode_length=DEFAULT_BARCODE_LENGTH,
    decoys_spec="",
    watermark_hex="",
):
    """Compress & encrypt every PT_LOAD segment, reloc, and import into LOAD_PACK with a direct-syscall unpacker (E09)."""
    orig = ELF(input_bytes)
    orig.validate_target(allow_protected=True)
    orig_loads = list(orig.loads)
    if not orig_loads or len(orig_loads) > P3_PACK_MAX_SEGS:
        raise ProtectionError(f"E09 requires between 1 and {P3_PACK_MAX_SEGS} PT_LOAD segments.")

    max_align = max(16384, *(s.alignment for s in orig_loads))
    if max_align > 2 * 1024 * 1024:
        raise ProtectionError("Segment alignment above 2 MiB is unsupported.")

    orig_dyn = list(orig.dynamic)
    dyn_dict = dict(orig_dyn)
    orig_str_va, orig_str_sz = dyn_dict.get(5, 0), dyn_dict.get(10, 0)
    orig_dynstr = b""
    if orig_str_va and orig_str_sz:
        orig_dynstr = bounded(orig.data, orig.file_offset(orig_str_va, orig_str_sz), orig_str_sz, ".dynstr")

    def dyn_cstr(str_off):
        return cstring(orig_dynstr, str_off) if orig_dynstr and str_off < len(orig_dynstr) else ""

    soname = dyn_cstr(dyn_dict[14]) if 14 in dyn_dict and dyn_dict[14] else ""
    needed_libs = [dyn_cstr(val) for tag, val in orig_dyn if tag == 1 and val < len(orig_dynstr)]
    needed_libs = [n for n in needed_libs if n]

    orig_init = dyn_dict.get(12, 0)
    orig_fini = dyn_dict.get(13, 0)
    orig_init_arr = dyn_dict.get(25, 0)
    orig_init_arr_sz = dyn_dict.get(27, 0)
    orig_fini_arr = dyn_dict.get(26, 0)
    orig_fini_arr_sz = dyn_dict.get(28, 0)
    orig_dt_flags = dyn_dict.get(30, 0)
    orig_dt_flags_1 = dyn_dict.get(0x6FFFFFFB, 0)

    # Collect all relocations from DT_RELA (7/8) and DT_JMPREL (23/2) using dynamic table bounds.
    syms = orig.symbols(dynamic_only=True)
    raw_relas = []
    for va_tag, sz_tag in ((7, 8), (23, 2)):
        rva, rsz = dyn_dict.get(va_tag, 0), dyn_dict.get(sz_tag, 0)
        if rva and rsz:
            rdata = bounded(orig.data, orig.file_offset(rva, rsz), rsz, "dynamic relocs")
            for off in range(0, len(rdata), 24):
                raw_relas.append(struct.unpack_from("<QQq", rdata, off))

    rel_relocs = []
    imp_relocs = []
    kept_relocs = []
    for r_off, r_info, r_add in raw_relas:
        rtype = r_info & 0xFFFFFFFF
        sym_idx = r_info >> 32
        if rtype == 1027:  # R_AARCH64_RELATIVE
            rel_relocs.append((r_off, r_add))
        elif rtype in (1025, 257, 1026):  # GLOB_DAT / ABS64 / JUMP_SLOT
            sym = syms[sym_idx] if sym_idx < len(syms) else {"shndx": 0, "info": 0, "value": 0, "name": ""}
            bind = sym["info"] >> 4
            if sym_idx == 0 or sym["shndx"] != 0:
                imp_relocs.append((r_off, 1, sym["value"] + r_add, b""))
            else:
                flags_s = 2 if bind == 2 else 0
                imp_relocs.append((r_off, flags_s, r_add, sym["name"].encode("utf-8")))
        else:
            kept_relocs.append((r_off, r_info, r_add, sym_idx))

    if len(kept_relocs) > P3_PACK_MAX_SAVED:
        raise ProtectionError(f"Unsupported relocation count ({len(kept_relocs)}) exceeds E09 saved-slot capacity.")

    # Build minimal LOAD_STUB dynamic strings/symbols: exports + rare kept_reloc symbols ONLY (0 normal imports).
    kept_str_ba = bytearray(b"\x00")
    kept_str_map = {}

    def add_dynstr(text_s):
        if text_s not in kept_str_map:
            kept_str_map[text_s] = len(kept_str_ba)
            kept_str_ba.extend(text_s.encode("utf-8") + b"\x00")
        return kept_str_map[text_s]

    if soname:
        soname_off = add_dynstr(soname)
    else:
        soname_off = 0
    needed_offs = [add_dynstr(libn) for libn in needed_libs]

    # Collect exported symbols from orig .dynsym (shndx != 0 and global/weak/gnu_unique)
    kept_sym_entries = []  # (orig_idx_or_-1, name_off, info, other, shndx_placeholder, value_unshifted, size, raw_name_bytes)
    orig_to_new_sym = {}
    for orig_idx, sym in enumerate(syms):
        if orig_idx == 0:
            continue
        bind = sym["info"] >> 4
        if sym["shndx"] and bind in (1, 2, 10) and sym["name"]:
            orig_to_new_sym[orig_idx] = len(kept_sym_entries) + 1
            n_off = add_dynstr(sym["name"])
            kept_sym_entries.append((sym["name"].encode("utf-8"), n_off, sym["info"], sym["other"], sym["value"], sym["size"], True))

    for _, _, _, sym_idx in kept_relocs:
        if sym_idx and sym_idx not in orig_to_new_sym and sym_idx < len(syms):
            sym = syms[sym_idx]
            orig_to_new_sym[sym_idx] = len(kept_sym_entries) + 1
            n_off = add_dynstr(sym["name"]) if sym["name"] else 0
            kept_sym_entries.append((sym["name"].encode("utf-8"), n_off, sym["info"], sym["other"], sym["value"], sym["size"], bool(sym["shndx"])))

    hash_blob = _build_sysv_hash([b""] + [e[0] for e in kept_sym_entries])
    dynstr_bytes = bytes(kept_str_ba)
    dynsym_size = (1 + len(kept_sym_entries)) * SYM.size
    kept_rela_size = len(kept_relocs) * 24

    orig_relro = next((s for s in orig.segments if s.type == 0x6474E552), None)
    orig_stack = next((s for s in orig.segments if s.type == 0x6474E551), None)
    orig_eh = next((s for s in orig.segments if s.type == 0x6474E550), None)

    phnum = 4 + len(orig_loads) + (1 if orig_relro else 0) + (1 if orig_stack else 0) + (1 if orig_eh else 0)
    phdr_off = EHDR.size
    phdr_size = phnum * PHDR.size

    dynstr_off = align(phdr_off + phdr_size, 16)
    dynsym_off = align(dynstr_off + len(dynstr_bytes), 16)
    hash_off = align(dynsym_off + dynsym_size, 16)
    kept_rela_off = align(hash_off + len(hash_blob), 16)
    dyn_off = align(kept_rela_off + kept_rela_size, 16)

    dyn_count_estimate = (
        len(needed_offs)
        + (1 if soname_off else 0)
        + 1  # DT_INIT
        + (1 if orig_fini else 0)
        + (2 if orig_init_arr and orig_init_arr_sz else 0)
        + (2 if orig_fini_arr and orig_fini_arr_sz else 0)
        + 5  # HASH, STRTAB, STRSZ, SYMTAB, SYMENT
        + (3 if kept_relocs else 0)
        + 3  # DT_FLAGS, DT_FLAGS_1, DT_NULL
    )
    dyn_size = dyn_count_estimate * DYN.size
    guard_off = align(dyn_off + dyn_size, 4096)

    # Prepare LOAD_STUB guard bytes + optional O10 self-obfuscation + optional IDA troll decoys.
    guard_ba = bytearray(guard_blob)
    cfg_off = guard_meta["symbols"]["p3_config"]
    ext_cfg_off = guard_meta["symbols"]["p3_ext"]
    str_cfg_off = guard_meta["symbols"]["p3_str_cfg"]
    data_enc_off = guard_meta["symbols"]["p3_data_enc"]
    pack_cfg_off = guard_meta["symbols"]["p3_pack"]

    rekey_guard_strings(guard_ba, str_cfg_off, seed)

    guard_ext_off = 0
    guard_ext_len = 0
    obf_report = {"obfuscated_guard_functions": 0, "guard_ext_size": 0}
    pack_entry_va = guard_off + guard_meta["symbols"]["p3_pack_entry"]
    if obfuscate_guard:
        guard_ba, guard_ext_off, guard_ext_len, obf_report = obfuscate_guard_runtime(
            guard_ba, guard_meta, guard_base_va=guard_off, seed=seed, entry_name="p3_pack_entry",
        )
        pack_entry_va = obf_report["entry_va"]

    decoy_records = []
    stub_real_end_va = 0
    if troll_ida:
        rem_g = len(guard_ba) % 16
        if rem_g:
            guard_ba.extend(bytes(16 - rem_g))
        decoy_base_va = guard_off + len(guard_ba)
        stub_real_end_va = decoy_base_va
        decoy_bytes, decoy_records = build_ida_troll_decoys(
            decoy_base_va, seed=seed, barcode_chars=barcode_chars,
            barcode_length=barcode_length, decoys_spec=decoys_spec,
        )
        guard_ba.extend(decoy_bytes)

    stub_end = align(guard_off + len(guard_ba), 16)
    if len(guard_ba) < stub_end - guard_off:
        guard_ba.extend(bytes((stub_end - guard_off) - len(guard_ba)))

    # Choose randomized page-aligned SHIFT strictly >= stub_end.
    rng = random.Random(seed ^ 0x45303950)
    pack_shift = align(stub_end + (rng.randrange(1, 5) * max_align), max_align)

    # Finalize .dynsym (shifted exports) & rare kept DT_RELA.
    dynsym_ba = bytearray(SYM.pack(0, 0, 0, 0, 0, 0))
    for _, n_off, info, other, val, size, is_defined in kept_sym_entries:
        new_val = (val + pack_shift) if (is_defined and val) else val
        new_shndx = 5 if is_defined else 0  # section 5 = stub .text (or SHN_UNDEF if import)
        dynsym_ba.extend(SYM.pack(n_off, info, other, new_shndx, new_val, size))

    kept_rela_ba = bytearray()
    saved_slots = []
    for r_off, r_info, r_add, orig_sym_idx in kept_relocs:
        new_r_off = r_off + pack_shift
        saved_slots.append(new_r_off)
        new_sym_idx = orig_to_new_sym.get(orig_sym_idx, 0)
        new_r_info = (new_sym_idx << 32) | (r_info & 0xFFFFFFFF)
        kept_rela_ba.extend(struct.pack("<QQq", new_r_off, new_r_info, r_add))

    # Build final .dynamic table for LOAD_STUB.
    dyn_entries = [(1, off) for off in needed_offs]
    if soname_off:
        dyn_entries.append((14, soname_off))
    dyn_entries.append((12, pack_entry_va))  # DT_INIT = p3_pack_entry
    if orig_fini:
        dyn_entries.append((13, orig_fini + pack_shift))
    if orig_init_arr and orig_init_arr_sz:
        dyn_entries.append((25, orig_init_arr + pack_shift))
        dyn_entries.append((27, orig_init_arr_sz))
    if orig_fini_arr and orig_fini_arr_sz:
        dyn_entries.append((26, orig_fini_arr + pack_shift))
        dyn_entries.append((28, orig_fini_arr_sz))
    dyn_entries.extend([
        (4, hash_off),
        (5, dynstr_off),
        (10, len(dynstr_bytes)),
        (6, dynsym_off),
        (11, SYM.size),
    ])
    if kept_relocs:
        dyn_entries.extend([(7, kept_rela_off), (8, len(kept_rela_ba)), (9, 24)])
    dyn_entries.extend([
        (30, (orig_dt_flags | 8) & ~4),
        (0x6FFFFFFB, (orig_dt_flags_1 | 1) & ~0x08000000),
        (0, 0),
    ])
    dyn_bytes = b"".join(DYN.pack(tag, val) for tag, val in dyn_entries)

    # Compress & ChaCha20-encrypt all original PT_LOAD segments, relocs, and imports.
    cfg_key = secrets.token_bytes(32)
    key_mask = secrets.token_bytes(32)
    master_key = hmac.new(key_mask, cfg_key, hashlib.sha256).digest()
    manifest_pubkey = secrets.token_bytes(32)
    pk_nonce = secrets.token_bytes(12)

    def chunk_nonce(stream_idx):
        nb = bytearray(pk_nonce)
        for k in range(4):
            nb[8 + k] ^= (stream_idx >> (8 * k)) & 0xFF
        return bytes(nb)

    pack_blob = bytearray()
    pack_segs = []
    seg0_plain_sha256 = bytes(32)
    for seg_idx, s in enumerate(orig_loads):
        plain_seg = orig.data[s.offset:s.offset + s.filesz] if s.filesz else b""
        if seg_idx == 0 and plain_seg:
            seg0_plain_sha256 = hashlib.sha256(plain_seg).digest()
        if plain_seg:
            c_off = len(pack_blob)
            raw_c = _deflate_raw(plain_seg)
            cipher_c = chacha20(raw_c, master_key, chunk_nonce(1 + seg_idx), 1)
            pack_blob.extend(cipher_c)
            c_sz = len(cipher_c)
        else:
            c_off, c_sz = 0, 0
        is_relro = 1 if (orig_relro and s.vaddr <= orig_relro.vaddr < s.vaddr + s.memsz) else 0
        pack_segs.append(PACK_SEG.pack(
            s.vaddr + pack_shift, s.memsz, c_off, c_sz, len(plain_seg),
            _pf_to_linux_prot(s.flags), is_relro,
        ))
    while len(pack_segs) < P3_PACK_MAX_SEGS:
        pack_segs.append(PACK_SEG.pack(0, 0, 0, 0, 0, 0, 0))

    # Encode compressed ULEB/SLEB R_AARCH64_RELATIVE table.
    rel_relocs.sort(key=lambda x: x[0])
    rel_plain_ba = bytearray()
    prev_off, prev_add = 0, 0
    for r_off, r_add in rel_relocs:
        rel_plain_ba.extend(encode_uleb128(r_off - prev_off))
        rel_plain_ba.extend(encode_sleb128(r_add - prev_add))
        prev_off, prev_add = r_off, r_add
    rel_offset = len(pack_blob)
    rel_uncomp_sz = len(rel_plain_ba)
    if rel_uncomp_sz:
        rel_cipher = chacha20(_deflate_raw(bytes(rel_plain_ba)), master_key, chunk_nonce(0x100), 1)
        pack_blob.extend(rel_cipher)
        rel_comp_sz = len(rel_cipher)
    else:
        rel_comp_sz = 0

    # Encode compressed internal + dynamic import relocation table.
    imp_relocs.sort(key=lambda x: x[0])
    imp_plain_ba = bytearray()
    prev_off = 0
    for r_off, flags_s, val_or_add, raw_name in imp_relocs:
        imp_plain_ba.extend(encode_uleb128(flags_s))
        imp_plain_ba.extend(encode_uleb128(r_off - prev_off))
        imp_plain_ba.extend(encode_sleb128(val_or_add))
        if not (flags_s & 1):
            imp_plain_ba.extend(raw_name + b"\x00")
        prev_off = r_off
    imp_offset = len(pack_blob)
    imp_uncomp_sz = len(imp_plain_ba)
    if imp_uncomp_sz:
        imp_cipher = chacha20(_deflate_raw(bytes(imp_plain_ba)), master_key, chunk_nonce(0x200), 1)
        pack_blob.extend(imp_cipher)
        imp_comp_sz = len(imp_cipher)
    else:
        imp_comp_sz = 0

    needed_plain = b"".join(libn.encode("utf-8") + b"\x00" for libn in needed_libs)[:1024]
    needed_offset = len(pack_blob)
    needed_size = len(needed_plain)
    if needed_size:
        n_nonce = bytearray(pk_nonce)
        n_nonce[8] ^= 0x55
        pack_blob.extend(chacha20(needed_plain, master_key, bytes(n_nonce), 1))

    max_orig_end = max(s.vaddr + s.memsz for s in orig_loads)
    pack_file_off = align(stub_end, max_align)
    pack_va = align(max_orig_end + pack_shift, max_align)

    rw_data_min = 0
    if orig_relro:
        relro_end = orig_relro.vaddr + orig_relro.memsz
        for s in orig_loads:
            if (s.flags & 2) and s.vaddr >= relro_end:
                rw_data_min = s.vaddr + pack_shift
                break

    pack_bytes = bytes(pack_blob)
    pack_cipher_mac = compute_cipher_mac(master_key, pack_shift, len(pack_bytes), pk_nonce, pack_bytes)
    saved_padded = (saved_slots + [0] * P3_PACK_MAX_SAVED)[:P3_PACK_MAX_SAVED]

    guard_ba[pack_cfg_off:pack_cfg_off + PACK_CFG_SIZE] = (
        PACK_HDR.pack(
            0x5033504B, 1, pack_shift, pack_va, len(pack_bytes),
            pack_cipher_mac, pk_nonce, len(orig_loads),
            rel_offset, rel_comp_sz, rel_uncomp_sz, len(rel_relocs),
            imp_offset, imp_comp_sz, imp_uncomp_sz, len(imp_relocs),
            needed_offset, needed_size,
            (orig_relro.vaddr + pack_shift) if orig_relro else 0,
            orig_relro.memsz if orig_relro else 0,
            rw_data_min, orig_init, len(saved_slots), 0,
            *saved_padded, seg0_plain_sha256,
        )
        + b"".join(pack_segs)
    )

    # Populate stealth p3_config, p3_data_enc (guard_ext integrity), p3_ext & E05 manifest HMAC.
    guard_code_digest = hashlib.sha256(guard_ba[:cfg_off]).digest()
    guard_ext_digest = hashlib.sha256(guard_ba[guard_ext_off:guard_ext_off + guard_ext_len]).digest() if guard_ext_len else bytes(32)
    guard_ba[data_enc_off:data_enc_off + SPARSE_DATA_CFG.size] = SPARSE_DATA_CFG.pack(
        0, 0, 0, 0, 0, 8, bytes(12), 0, bytes(32), bytes(32),
        (guard_off + guard_ext_off) if guard_ext_len else 0,
        guard_ext_len, guard_ext_digest,
    )

    self_vaddr = guard_off + cfg_off
    stub_cfg_flags = flags & ~0x220  # Clear ENCRYPT | ENCRYPT_RODATA; E09 handles whole-segment compression/encryption.
    guard_ba[cfg_off:cfg_off + CONFIG_SIZE] = CONFIG.pack(
        stealth_magic_bytes(seed, is_ext=False), 2, stub_cfg_flags, self_vaddr, 0, 0, 0,
        0, 0, cfg_key, pk_nonce, 1, 0, 0, bytes(32), 0, 0,
    ) + (SPAN.pack(0, 0, bytes(32)) * 32)

    pack_ext_flags = (ext_flags & 0x1000) | 0x01 | 0x04 | 0x08  # DEEP_PROBES + MASKED_KEY | MANIFEST_MAC | SELF_CHECK
    wm_bytes = (bytes.fromhex(watermark_hex) if watermark_hex else b"").ljust(16, b"\x00")[:16]
    ext_hdr = EXT_HDR.pack(
        stealth_magic_bytes(seed, is_ext=True), 3, pack_ext_flags, 0, 0, 0, 0,
        seed, wm_bytes, key_mask, manifest_pubkey, bytes(32),
        bytes(32), bytes(32), guard_off, cfg_off, guard_code_digest,
        0, 0, 0, 0, 0, 0, bytes(32), 0, 0, 0, 0, bytes(64), bytes(32),
    )
    ext_padding = bytes(EXT_CONFIG_SIZE - len(ext_hdr))
    guard_ba[ext_cfg_off:ext_cfg_off + EXT_CONFIG_SIZE] = ext_hdr + ext_padding

    mac = compute_manifest_hmac(
        manifest_pubkey,
        guard_ba[cfg_off:cfg_off + CONFIG_SIZE],
        guard_ba[ext_cfg_off:ext_cfg_off + EXT_CONFIG_SIZE],
        guard_ba[str_cfg_off:data_enc_off],
        guard_ba[data_enc_off:pack_cfg_off],
        guard_ba[pack_cfg_off:pack_cfg_off + PACK_CFG_SIZE],
    )
    guard_ba[ext_cfg_off + 128:ext_cfg_off + 160] = mac

    # Build final segment table, sections, and output ELF bytes.
    total_file_pre_sh = pack_file_off + len(pack_bytes)
    new_segments = [
        Segment(PT_PHDR, 4, phdr_off, phdr_off, phdr_off, phdr_size, phdr_size, 8),
        Segment(PT_LOAD, 5, 0, 0, 0, stub_end, stub_end, max_align),
    ]
    for s in orig_loads:
        s_align = s.alignment if s.alignment >= 4096 else max_align
        aligned_va = (s.vaddr + pack_shift) & ~(s_align - 1)
        memsz_from_aligned = (s.vaddr + s.memsz + pack_shift) - aligned_va
        new_segments.append(Segment(PT_LOAD, s.flags, 0, aligned_va, aligned_va, 0, memsz_from_aligned, s.alignment))
    new_segments.append(Segment(PT_LOAD, 4, pack_file_off, pack_va, pack_va, len(pack_bytes), len(pack_bytes), max_align))
    new_segments.append(Segment(PT_DYNAMIC, 4, dyn_off, dyn_off, dyn_off, len(dyn_bytes), len(dyn_bytes), 8))
    if orig_eh:
        eh_fsz = orig_eh.filesz if orig_eh.filesz <= total_file_pre_sh else 0
        new_segments.append(Segment(
            0x6474E550, orig_eh.flags, 0, orig_eh.vaddr + pack_shift,
            orig_eh.paddr + pack_shift, eh_fsz, orig_eh.memsz, orig_eh.alignment,
        ))
    if orig_stack:
        new_segments.append(orig_stack)
    if orig_relro:
        new_segments.append(Segment(
            0x6474E552, 4, 0, orig_relro.vaddr + pack_shift,
            orig_relro.paddr + pack_shift, 0, orig_relro.memsz, orig_relro.alignment,
        ))
    assert len(new_segments) == phnum, f"PHDR count mismatch: {len(new_segments)} != {phnum}"

    shstr = bytearray(b"\x00")

    def add_shstr(name_str):
        pos = len(shstr)
        shstr.extend(name_str.encode("utf-8") + b"\x00")
        return pos

    sections = [
        Section(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ""),
        Section(add_shstr(".dynsym"), 11, 2, dynsym_off, dynsym_off, len(dynsym_ba), 2, 1, 8, SYM.size, ".dynsym"),
        Section(add_shstr(".dynstr"), 3, 2, dynstr_off, dynstr_off, len(dynstr_bytes), 0, 0, 1, 0, ".dynstr"),
        Section(add_shstr(".hash"), 5, 2, hash_off, hash_off, len(hash_blob), 1, 0, 4, 4, ".hash"),
        Section(add_shstr(".dynamic"), 6, 2, dyn_off, dyn_off, len(dyn_bytes), 2, 0, 8, DYN.size, ".dynamic"),
        Section(add_shstr(".text"), 1, 6, guard_off, guard_off, len(guard_ba), 0, 0, 16, 0, ".text"),
        Section(add_shstr(".rodata"), 1, 2, pack_va, pack_file_off, len(pack_bytes), 0, 0, max_align, 0, ".rodata"),
    ]
    shstr_name_off = add_shstr(".shstrtab")

    shstr_off = align(total_file_pre_sh, 8)
    sections.append(Section(shstr_name_off, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0, ".shstrtab"))
    shoff = align(shstr_off + len(shstr), 8)
    shstrndx = len(sections) - 1

    out = bytearray(shoff + len(sections) * EHDR.size)  # oversized slightly, trimmed cleanly below
    hdr = list(orig.header)
    hdr[4] = 0  # Clear any GNU-ld default e_entry on packed ET_DYN shared library
    hdr[5] = phdr_off
    hdr[6] = shoff
    hdr[10] = len(new_segments)
    hdr[12] = len(sections)
    hdr[13] = shstrndx
    out[:EHDR.size] = EHDR.pack(*hdr)

    pos = phdr_off
    for seg in new_segments:
        out[pos:pos + PHDR.size] = seg.pack()
        pos += PHDR.size

    out[dynstr_off:dynstr_off + len(dynstr_bytes)] = dynstr_bytes
    out[dynsym_off:dynsym_off + len(dynsym_ba)] = dynsym_ba
    out[hash_off:hash_off + len(hash_blob)] = hash_blob
    if kept_rela_ba:
        out[kept_rela_off:kept_rela_off + len(kept_rela_ba)] = kept_rela_ba
    out[dyn_off:dyn_off + len(dyn_bytes)] = dyn_bytes
    out[guard_off:guard_off + len(guard_ba)] = guard_ba
    out[pack_file_off:pack_file_off + len(pack_bytes)] = pack_bytes
    out[shstr_off:shstr_off + len(shstr)] = shstr
    out = out[:shoff]
    for sec in sections:
        out.extend(sec.pack())

    return bytes(out), {
        "mode": "compressed_in_memory_packer",
        "pack_shift": pack_shift,
        "pack_vaddr": pack_va,
        "packed_segments": len(orig_loads),
        "packed_blob_size": len(pack_bytes),
        "compressed_relocs": len(rel_relocs),
        "compressed_imports": len(imp_relocs),
        "saved_tls_slots": len(saved_slots),
        "kept_dynsym_exports": len(kept_sym_entries),
        "stub_end_vaddr": stub_end,
        "decoy_records": decoy_records,
        "stub_real_end_vaddr": stub_real_end_va,
        "obfuscated_guard": obf_report,
    }
