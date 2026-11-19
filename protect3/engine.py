"""Append-only and multi-pass ELF protection: preserve ABI, exports and relocations."""

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import struct
import tempfile

from . import __version__
from .arm64 import discover_functions, encode_b, encode_movz
from .crypto import chacha20
from .elf import (ELF, EHDR, PHDR, DYN, PT_LOAD, PT_DYNAMIC, PT_PHDR, SHT_DYNAMIC,
                  DT_INIT, ProtectionError, Segment, align)
from .planner import (
    IN_PLACE_PASS_OPTIONS,
    ROADMAP_CATALOG,
    apply_profile_defaults,
    build_protection_plan,
    evaluate_protection_benchmark,
    verify_function_semantics_unicorn,
)
from .runtime import command, load_runtime, ndk_tool
from .transforms import (
    DEFAULT_BARCODE_CHARS,
    DEFAULT_BARCODE_LENGTH,
    apply_ida_troll_and_block,
    build_gg_honeypot_page,
    build_ida_troll_decoys,
    build_on_demand_stub,
    CONFIG,
    CONFIG_SIZE,
    DEFAULT_BARCODE_CHARS,
    DEFAULT_BARCODE_LENGTH,
    ENC_RANGE,
    EXT_CONFIG_SIZE,
    EXT_HDR,
    EXT_MAGIC,
    MAGIC,
    P3_MAX_ENC_RANGES,
    P3_MAX_PROLOGUES,
    P3_MAX_STRINGS,
    P3_MAX_VM_PROGS,
    PACK_CFG_SIZE,
    PROLOGUE_GUARD,
    SPAN,
    SPARSE_DATA_CFG,
    STRING_ENTRY,
    VM_PROG,
    apply_ida_troll_and_block,
    build_gg_honeypot_page,
    build_ida_troll_decoys,
    build_on_demand_stub,
    build_packed_elf,
    build_string_resolver_stub,
    build_vm_entry_stub,
    build_wrapped_elf,
    compile_function_to_vm,
    compute_cipher_mac,
    compute_manifest_hmac,
    compute_sparse_data_cipher_mac,
    encode_sparse_reloc_table,
    generate_vm_opcode_tables,
    obfuscate_and_relocate_function,
    obfuscate_guard_runtime,
    scrub_elf_metadata,
    stealth_magic_bytes,
)
from .runtime import rekey_guard_strings

EXT_MASKED_KEY = 1 << 0
EXT_AUTH_RANGES = 1 << 1
EXT_MANIFEST_MAC = 1 << 2
EXT_GUARD_SELF_CHECK = 1 << 3
EXT_PROLOGUE_CHECK = 1 << 4
EXT_GOT_CHECK = 1 << 5
EXT_RELRO_CHECK = 1 << 6
EXT_RUNTIME_GATE = 1 << 7
EXT_RUNTIME_ANTIDEBUG = 1 << 8
EXT_VM_ENABLED = 1 << 9
EXT_STRING_VAULT = 1 << 10
EXT_ON_DEMAND = 1 << 11
EXT_DEEP_PROBES = 1 << 12
EXT_GG_HONEYPOT = 1 << 13
EXT_EPHEMERAL_STRINGS = 1 << 14
EXT_ANTI_GG = 1 << 15

RANGE_FLAG_CODE = 1 << 0
RANGE_FLAG_AUTH = 1 << 1
RANGE_FLAG_ON_DEMAND = 1 << 2
RANGE_FLAG_STRING = 1 << 3
RANGE_FLAG_CANARY = 1 << 4

MAX_INPUT = 512 * 1024 * 1024


@dataclass(frozen=True)
class Options:
    integrity: bool = True
    debugger: bool = True
    hooks: bool = False
    root: bool = False
    emulator: bool = False
    encrypt_text: bool = False
    strict_proc: bool = False
    report_only: bool = False
    deny_attach: bool = False
    strip_symbols: bool = False
    compat_layout: bool = False
    encrypt_rodata: bool = False
    diagnostics: bool = False
    encrypt_function: str = ""
    # v0.3 extended protection options
    encrypt_functions: str = ""
    encrypt_strings: bool = False
    auth_encryption: bool = False
    sign_manifest: bool = False
    clean_metadata: bool = False
    keep_debug: str = ""
    masked_key: bool = False
    wrap_elf: bool = False
    obfuscate_ops: bool = False
    obfuscate_functions: str = ""
    flatten_cfg: bool = False
    flatten_functions: str = ""
    virtualize_functions: str = ""
    virtualize_auto: bool = False
    obfuscate_jni: bool = False
    runtime_integrity: bool = False
    prologue_check: bool = False
    got_check: bool = False
    relro_check: bool = False
    runtime_anti_debug: bool = False
    guard_self_check: bool = False
    on_demand_functions: str = ""
    deep_probes: bool = False
    gg_honeypot: bool = False
    ephemeral_strings: bool = False
    anti_gg: bool = False
    profile: str = ""
    auto_select_functions: bool = False
    denylist_functions: str = ""
    seed: int | None = None
    watermark: str = ""
    verify_semantics: bool = False
    troll_ida: bool = False
    block_ida: bool = False
    troll_barcode_chars: str = DEFAULT_BARCODE_CHARS
    troll_barcode_length: int = DEFAULT_BARCODE_LENGTH
    troll_decoys: str = ""
    pack_elf: bool = False
    obfuscate_guard: bool = False
    encrypt_data: bool = False

    def flags(self):
        names = ("integrity", "debugger", "hooks", "root", "emulator", "encrypt_text",
                 "strict_proc", "report_only", "deny_attach", "encrypt_rodata", "diagnostics")
        return sum(1 << i for i, name in enumerate(names)
                   if (bool(self.encrypt_text or self.encrypt_function) if name == "encrypt_text" else getattr(self, name)))


def capabilities(options=None):
    opt = apply_profile_defaults(options) if options is not None else Options()

    def state(enabled):
        return "enabled" if options is not None and enabled else "available" if options is None else "disabled"

    has_obf = bool(
        opt.strip_symbols or opt.clean_metadata or opt.obfuscate_ops
        or opt.obfuscate_functions or (opt.profile in ("balanced", "anti-analysis", "max"))
    )
    has_code_enc = bool(opt.encrypt_text or opt.encrypt_function or opt.encrypt_functions or opt.on_demand_functions)
    has_rodata_enc = bool(opt.encrypt_rodata or opt.encrypt_strings)
    has_antitamper = bool(
        opt.integrity or has_code_enc or opt.encrypt_rodata or opt.auth_encryption
        or opt.sign_manifest or opt.guard_self_check
    )
    has_mem_integrity = bool(
        opt.integrity or has_code_enc or opt.encrypt_rodata or opt.runtime_integrity
        or opt.prologue_check or opt.got_check or opt.relro_check
    )
    has_antidebug = bool(opt.debugger or opt.deny_attach or opt.runtime_anti_debug)
    has_vm = bool(opt.virtualize_functions or opt.virtualize_auto or opt.profile == "max")
    has_flatten = bool(opt.flatten_cfg or opt.flatten_functions or opt.profile in ("anti-analysis", "max"))

    features = [
        {
            "feature": "Compressed In-Memory ELF Packer & Relocator",
            "status": state(opt.pack_elf),
            "maturity": "implemented",
            "scope": "Compresses (raw DEFLATE) and ChaCha20+HMAC encrypts all PT_LOAD segments, delta-relocs, and imports into LOAD_PACK; resolves symbols via direct-syscall libdl RAM parser (0 new libc/libdl imports), restores PT_GNU_RELRO to PROT_READ, and locks LOAD_PACK with MADV_DONTNEED + PROT_NONE (E09).",
        },
        {
            "feature": "Whole ELF payload encryption",
            "status": state(opt.wrap_elf),
            "maturity": "layered_wrapper",
            "scope": "Final outer wrapper .so decrypting embedded payload ELF (after all in-place guards/obfuscation/VM) via memfd/dlopen and forwarding STT_FUNC exports (E08).",
        },
        {
            "feature": "Guard Self-Obfuscation",
            "status": state(opt.obfuscate_guard),
            "maturity": "implemented",
            "scope": "Relocates and self-obfuscates guard C helpers per build with MBA, opaque constants, indirect calls, CFF, and unallocated <unknown> junk islands verified by dual-range R06 self-check (O10).",
        },
        {
            "feature": "Native Code Obfuscation",
            "status": "enabled" if (options is not None and has_obf) else ("available" if options is None else "disabled"),
            "maturity": "implemented_binary_passes",
            "scope": "ARM64 instruction substitution (O01), opaque constants (O02), opaque predicates (O03), indirect calls (O04), splitting/shuffling (O05/O06) and symbol/metadata stripping (E06).",
        },
        {
            "feature": "Native Code Encryption",
            "status": state(has_code_enc),
            "maturity": "implemented",
            "scope": "ChaCha20 for all .text, single/multi-function ranges (E01), or on-demand page-isolated ranges (R07), with optional HMAC-SHA256 pre-decryption tag (E04) and masked KDF key (E07).",
        },
        {
            "feature": "JNI Obfuscation",
            "status": state(opt.obfuscate_jni),
            "maturity": "implemented_so_scope",
            "scope": "Relocates JNI_OnLoad and Java_* bodies behind runtime-checked indirect guard thunks and encrypts .rodata JNI strings while preserving external ABI symbol names.",
        },
        {
            "feature": "Native Anti-Debugging",
            "status": state(has_antidebug),
            "maturity": "implemented",
            "scope": f"TracerPid check at load (debugger={opt.debugger}), optional runtime gate checks (R05={opt.runtime_anti_debug}), wchan ptrace check, and process-wide PR_SET_DUMPABLE=0 (deny_attach={opt.deny_attach}).",
        },
        {
            "feature": "Instrumentation mapping indicators",
            "status": state(opt.hooks),
            "maturity": "prototype_multi_signal",
            "scope": "Scans /proc/self/maps and thread comm for Frida/Xposed/LSPosed/Dobby/Substrate indicators (R08); combine with R02 prologue checks.",
            "verification": "synthetic_mapping_tests_only_not_live_instrumentation_test",
        },
        {
            "feature": "Anti-Tamper",
            "status": state(has_antitamper),
            "maturity": "implemented",
            "scope": "Load-time code/data SHA-256, optional pre-decryption ciphertext HMAC-SHA256 (E04), signed manifest verification (E05) and guard self-check (R06).",
        },
        {
            "feature": "Memory Integrity Checks",
            "status": state(has_mem_integrity),
            "maturity": "implemented",
            "scope": "Load-time SHA-256 plus optional post-load runtime entry gates (R01), function prologue hook checks (R02), GOT range checks (R03) and RELRO hash (R04).",
        },
        {
            "feature": "Root indicator probe",
            "status": state(opt.root),
            "maturity": "prototype_multi_signal",
            "scope": "Checks visible su/magisk/ksu/apatch paths, /proc/self/maps and /proc/self/mountinfo (R08); inaccessible paths do not prove absence.",
            "verification": "synthetic_tests_only_runtime_verification_per_output_required",
        },
        {
            "feature": "QEMU/goldfish indicator probe",
            "status": state(opt.emulator),
            "maturity": "prototype_multi_signal",
            "scope": "Checks qemu/goldfish/ranchu plus optional BlueStacks/vbox/libnb/libhoudini indicators when --deep-probes is enabled (R08).",
            "verification": "synthetic_tests_only_not_general_emulator_detection",
        },
        {
            "feature": "Read-only & Writable Data Encryption",
            "status": state(bool(has_rodata_enc or opt.encrypt_data)),
            "maturity": "implemented",
            "scope": "Full .rodata + reloc-free unwind (.eh_frame/.gcc_except_table) ChaCha20 (E02), relocation-skipping sparse .data encryption (encrypt_data), or lazy String Vault (E03).",
        },
        {
            "feature": "Native runtime diagnostics",
            "status": state(opt.diagnostics),
            "maturity": "implemented",
            "scope": "Opt-in phase/check status logs through Android logd and stderr; logging is best effort, not a security guarantee.",
        },
        {
            "feature": "ARM64 Function Virtualization",
            "status": state(has_vm),
            "maturity": "implemented_subset_vm",
            "scope": "Compiles qualifying ARM64 functions to stack-isolated bytecode executed by p3_vm_exec with per-build opcode permutation and ChaCha20 bytecode encryption (O08/O09).",
        },
        {
            "feature": "Control-Flow Flattening",
            "status": state(has_flatten),
            "maturity": "implemented",
            "scope": "Relocates qualifying ARM64 functions into a state-machine dispatcher loop with CSEL state transitions and PC-relative relocation (O07).",
        },
        {
            "feature": "IDA Pro Anti-Analysis & Barcode/Honeypot Trolling",
            "status": state(bool(opt.troll_ida or opt.block_ida)),
            "maturity": "implemented",
            "scope": "Renames internal sub_XXXXXX functions to barcode/troll names via synthetic .symtab, injects F5 Hex-Rays troll decoy functions (--troll-ida), and/or wipes static disassembler segments via SHT_NOBITS+SHF_TLS (--block-ida).",
        },
        {
            "feature": "Anti-GameGuardian / Memory Scanner Defense",
            "status": state(bool(opt.gg_honeypot or opt.ephemeral_strings or opt.anti_gg)),
            "maturity": "implemented",
            "scope": "Embeds honeypot decoy pages verified by SHA-256 canary (gg_honeypot), re-encrypts String Vault entries after access (ephemeral_strings), and detects freeze/SIGSTOP scan pauses and memory editor artifacts (anti_gg).",
        },
    ]
    for feature in features:
        feature["enabled_in_output"] = feature["status"] == "enabled" if options is not None else None
        feature.setdefault("verification", "per_output_runtime_execution_not_verified_by_protect_command")
    return features


def read_library(path):
    path = Path(path)
    if not path.is_file():
        raise ProtectionError(f"Input file not found: {path}")
    if path.stat().st_size > MAX_INPUT:
        raise ProtectionError("Input exceeds the 512 MiB limit for this release.")
    return path.read_bytes()


def check_encryption(elf, text, code=True):
    if not text or not text.size or text.size > 1024 * 1024 * 1024:
        raise ProtectionError("Text encryption requires a nonempty .text section (at most 1 GiB).")
    if any(s["info"] & 15 == 10 for s in elf.symbols(False)):
        raise ProtectionError("Text encryption refuses GNU IFUNC symbols, whose code can run before DT_INIT.")
    if any(tag in (0x6000000F, 0x60000011) for tag, _ in elf.dynamic):
        raise ProtectionError("Experimental text encryption does not support Android APS2 packed relocations. Disable encryption.")
    if any(tag in (35, 36, 37, 0x6FFFE000, 0x6FFFE001, 0x6FFFE003) for tag, _ in elf.dynamic):
        raise ProtectionError("Section encryption refuses RELR relocation layouts until range-target validation is implemented.")
    if elf.dynamic_value(32) or elf.dynamic_value(33):
        raise ProtectionError("Text encryption refuses pre-init arrays.")
    if elf.section(".note.gnu.property"):
        raise ProtectionError("Experimental text encryption does not support GNU property/BTI libraries. Disable encryption.")
    if elf.file_offset(text.addr, text.size) != text.offset or text.flags & (6 if code else 2) != (6 if code else 2):
        raise ProtectionError("Encryption target is not a valid allocated section with the required permissions.")
    for section in elf.sections:
        if section.type not in (4, 9):
            continue
        entry = struct.Struct("<QQq" if section.type == 4 else "<QQ")
        if section.entsize != entry.size or section.size % entry.size:
            raise ProtectionError("Unrecognized relocation layout; text encryption refused.")
        for off in range(section.offset, section.offset + section.size, entry.size):
            record = entry.unpack_from(elf.data, off)
            if record[1] & 0xFFFFFFFF == 1032:
                raise ProtectionError("Text encryption refuses R_AARCH64_IRELATIVE resolvers.")
            if record[0] < text.addr + text.size and record[0] + 8 > text.addr:
                raise ProtectionError("Section encryption refuses relocations targeting the encrypted section.")


def check_rodata_encryption(elf):
    section = elf.section(".rodata")
    if not section or not section.size or section.type != 1 or section.flags & 7 != 2:
        raise ProtectionError("Read-only data encryption requires a nonempty allocated, nonwritable, nonexecutable .rodata section.")
    check_encryption(elf, section, code=False)
    if section.size > 128 * 1024 * 1024:
        raise ProtectionError(".rodata exceeds the 128 MiB encryption limit.")
    segment = next((s for s in elf.loads if s.vaddr <= section.addr and section.addr + section.size <= s.vaddr + s.filesz), None)
    if segment is None or segment.flags not in (4, 5) or elf.file_offset(section.addr, section.size) != section.offset:
        raise ProtectionError(".rodata must be wholly inside a read-only R/RX segment.")
    for other in elf.sections:
        if other is section or not other.size or not other.flags & 2 or other.type == 8:
            continue
        if section.addr < other.addr + other.size and other.addr < section.addr + section.size:
            raise ProtectionError(".rodata overlaps another allocated section.")
    for tag, _ in elf.dynamic:
        if tag in (5, 6, 7, 17, 23, 4, 0x6FFFFEF5, 0x6FFFFFF0, 0x6FFFFFFC, 0x6FFFFFFE):
            value = elf.dynamic_value(tag)
            if section.addr <= value < section.addr + section.size:
                raise ProtectionError("Loader metadata lies inside .rodata; refusing encryption.")
    return section, 5 if segment.flags & 1 else 1


def _has_reloc_overlap(elf, vaddr, size):
    """Return True if any relocation entry targets [vaddr, vaddr + size)."""
    end = vaddr + size
    for section in elf.sections:
        if section.type not in (4, 9):
            continue
        entry = struct.Struct("<QQq" if section.type == 4 else "<QQ")
        if section.entsize != entry.size or section.size % entry.size:
            return True
        for off in range(section.offset, section.offset + section.size, entry.size):
            r_addr = entry.unpack_from(elf.data, off)[0]
            if r_addr < end and r_addr + 8 > vaddr:
                return True
    return False


def _collect_reloc_free_ro_unwind_ranges(elf, rodata, max_slots, auth):
    """Select reloc-free read-only unwind metadata sections (.eh_frame_hdr, .eh_frame, .gcc_except_table)."""
    ranges = []
    dyn_vas = {
        elf.dynamic_value(tag)
        for tag, _ in elf.dynamic
        if tag in (5, 6, 7, 17, 23, 4, 0x6FFFFEF5, 0x6FFFFFF0, 0x6FFFFFFC, 0x6FFFFFFE)
    }
    for name in (".eh_frame_hdr", ".eh_frame", ".gcc_except_table"):
        if len(ranges) >= max_slots:
            break
        sec = elf.section(name)
        if not sec or not sec.size or sec.type != 1 or (sec.flags & 7) != 2:
            continue
        if rodata and sec.addr < rodata.addr + rodata.size and rodata.addr < sec.addr + sec.size:
            continue
        seg = next((s for s in elf.loads if s.vaddr <= sec.addr and sec.addr + sec.size <= s.vaddr + s.filesz), None)
        if seg is None or seg.flags not in (4, 5):
            continue
        try:
            if elf.file_offset(sec.addr, sec.size) != sec.offset:
                continue
        except ProtectionError:
            continue
        if any(sec.addr <= v < sec.addr + sec.size for v in dyn_vas if v):
            continue
        if _has_reloc_overlap(elf, sec.addr, sec.size):
            continue
        ranges.append({
            "name": sec.name,
            "vaddr": sec.addr,
            "size": sec.size,
            "prot": 5 if seg.flags & 1 else 1,
            "flags": RANGE_FLAG_AUTH if auth else 0,
            "in_text": True,
            "file_offset": sec.offset,
        })
    return ranges


def _prepare_sparse_data_state(elf):
    """Inspect .data and extract relocation offsets for sparse ChaCha20 encryption (E02+)."""
    sec = elf.section(".data")
    if not sec or sec.type != 1 or (sec.flags & 3) != 3 or (sec.flags & 4) or sec.size <= 0:
        return None, []
    try:
        if elf.file_offset(sec.addr, sec.size) != sec.offset:
            return None, []
    except ProtectionError:
        return None, []

    reloc_offsets = []
    sec_end = sec.addr + sec.size
    for rsec in elf.sections:
        if rsec.type not in (4, 9):
            continue
        entry = struct.Struct("<QQq" if rsec.type == 4 else "<QQ")
        if rsec.entsize != entry.size or rsec.size % entry.size:
            return None, []
        for off in range(rsec.offset, rsec.offset + rsec.size, entry.size):
            unpacked = entry.unpack_from(elf.data, off)
            r_addr, r_info = unpacked[0], unpacked[1]
            if r_addr < sec_end and r_addr + 8 > sec.addr:
                rtype = r_info & 0xFFFFFFFF
                if rtype not in (1027, 1025, 257, 1026):
                    return None, []
                if r_addr < sec.addr or r_addr + 8 > sec_end:
                    return None, []
                reloc_offsets.append(r_addr - sec.addr)

    sorted_relocs = sorted(set(reloc_offsets))
    for a, b in zip(sorted_relocs, sorted_relocs[1:]):
        if b - a < 8:
            return None, []
    return sec, sorted_relocs


def _compute_cipher_mac(master_key, vaddr, size, nonce, ciphertext):
    return compute_cipher_mac(master_key, vaddr, size, nonce, ciphertext)


def rewrite(elf, options, blob, meta, pre_strip_functions=None, preserve_tables=None):
    opt = apply_profile_defaults(options)
    if preserve_tables is None:
        if opt.compat_layout:
            return rewrite_compatible(elf, opt, blob, meta, pre_strip_functions=pre_strip_functions)
        preserve_tables = False

    elf.validate_target()
    plan = build_protection_plan(elf, opt, pre_strip_functions=pre_strip_functions)
    spans = elf.code_sections()
    text = elf.section(".text")

    # Determine primary vs multi-range code encryption (E01)
    primary_encrypt_code = bool(opt.encrypt_text or (len(plan.encrypted_code_ranges) == 1 and not opt.encrypt_functions))
    multi_code_ranges = [] if primary_encrypt_code else list(plan.encrypted_code_ranges)

    if primary_encrypt_code and not opt.encrypt_text:
        r0 = plan.encrypted_code_ranges[0]
        if text is None or not text.addr <= r0["vaddr"] or r0["vaddr"] + r0["size"] > text.addr + text.size:
            raise ProtectionError("Selected function is outside .text.")
        text = replace(text, addr=r0["vaddr"], size=r0["size"], offset=elf.file_offset(r0["vaddr"], r0["size"]))

    if primary_encrypt_code:
        check_encryption(elf, text)
    for mr in multi_code_ranges:
        if text is None or not text.addr <= mr["vaddr"] or mr["vaddr"] + mr["size"] > text.addr + text.size:
            raise ProtectionError(f"Selected function {mr['name']} is outside .text.")
        sub_sec = replace(text, addr=mr["vaddr"], size=mr["size"], offset=elf.file_offset(mr["vaddr"], mr["size"]))
        check_encryption(elf, sub_sec)

    rodata, rodata_prot = check_rodata_encryption(elf) if opt.encrypt_rodata else (None, 0)
    if sum(s.type == PT_PHDR for s in elf.segments) > 1:
        raise ProtectionError("Multiple PT_PHDR entries are unsupported.")
    if sum(tag == DT_INIT for tag, _ in elf.dynamic) > 1:
        raise ProtectionError("Multiple DT_INIT entries are unsupported.")

    blob = bytearray(blob)
    cfg = meta["symbols"]["p3_config"]
    ext_cfg = meta["symbols"].get("p3_ext", cfg + CONFIG_SIZE)
    str_cfg = meta["symbols"].get("p3_str_cfg", ext_cfg + EXT_CONFIG_SIZE)
    data_enc_cfg = meta["symbols"].get("p3_data_enc", str_cfg + 5736)
    pack_cfg = meta["symbols"].get("p3_pack", data_enc_cfg + SPARSE_DATA_CFG.size)
    if (cfg < 0 or cfg + CONFIG_SIZE > len(blob) or blob[cfg:cfg + len(MAGIC)] != MAGIC
            or meta["symbols"]["p3_entry"] >= len(blob)):
        raise ProtectionError("Invalid runtime config/entry layout.")

    alignment = max(16384, *(s.alignment for s in elf.loads))
    if alignment > 2 * 1024 * 1024:
        raise ProtectionError("Segment alignment above 2 MiB is unsupported.")
    offset = align(len(elf.data), alignment)
    vaddr = align(max(s.vaddr + s.memsz for s in elf.loads), alignment)

    phnum = len(elf.segments) + 1 + (not any(s.type == PT_PHDR for s in elf.segments))
    if phnum >= 1024:
        raise ProtectionError("Too many program headers.")
    phsize = phnum * PHDR.size
    dyn_offset = align(phsize, 16)
    dynamic = [(tag, value) for tag, value in elf.dynamic if tag != DT_INIT]
    dyn_size = (len(dynamic) + 2) * DYN.size
    guard_offset = 0 if preserve_tables else align(dyn_offset + dyn_size, 4096)
    guard_base_va = vaddr + guard_offset
    entry = guard_base_va + meta["symbols"]["p3_entry"]
    vm_bridge_va = guard_base_va + meta["symbols"]["p3_vm_bridge"]
    gate_bridge_va = guard_base_va + meta["symbols"]["p3_gate_bridge"]
    resolve_string_va = guard_base_va + meta["symbols"]["p3_resolve_string"]
    on_demand_toggle_va = guard_base_va + meta["symbols"]["p3_on_demand_toggle"]

    result = bytearray(elf.data)
    all_funcs = {f.vaddr: f for f in (pre_strip_functions or discover_functions(elf))}

    # Stage 3 & 4: Emit relocated/obfuscated/flattened/VM stubs and auxiliary vaults after guard.bin
    ext_tail = bytearray()

    def tail_va():
        return guard_base_va + len(blob) + len(ext_tail)

    def pad_tail(align_bytes):
        rem = (len(blob) + len(ext_tail)) % align_bytes
        if rem:
            ext_tail.extend(bytes(align_bytes - rem))

    pad_tail(16)
    decode_map, encode_map = generate_vm_opcode_tables(plan.build_seed)
    vm_key = secrets.token_bytes(32) if any(a.backend == "vm" for a in plan.function_actions) else bytes(32)
    vm_bytecode_blob = bytearray()
    vm_prog_records = []
    enc_range_records = []
    on_demand_pages = []
    transformed_functions_report = []

    for gate_idx, action in enumerate(plan.function_actions):
        fn = all_funcs[action.vaddr]
        fn_off = elf.file_offset(fn.vaddr, fn.size)
        if action.backend == "vm":
            if len(vm_prog_records) >= P3_MAX_VM_PROGS:
                raise ProtectionError(f"At most {P3_MAX_VM_PROGS} virtualized functions supported per library in this release.")
            bc_plain, insn_cnt = compile_function_to_vm(fn, encode_map)
            bc_nonce = secrets.token_bytes(12)
            bc_digest = hashlib.sha256(bc_plain).digest()
            bc_cipher = chacha20(bc_plain, vm_key, bc_nonce, 1)
            bc_off = len(vm_bytecode_blob)
            vm_bytecode_blob.extend(bc_cipher)
            prog_idx = len(vm_prog_records)
            vm_prog_records.append(VM_PROG.pack(
                fn.vaddr, bc_off, len(bc_plain), insn_cnt, 1, bc_nonce, 1, bc_digest
            ))
            pad_tail(8)
            stub_va = tail_va()
            stub_bytes = build_vm_entry_stub(stub_va, prog_idx, vm_bridge_va)
            ext_tail.extend(stub_bytes)
            # Patch original function entry to branch to VM stub and scrub dead body instructions
            struct.pack_into("<I", result, fn_off, encode_b(fn.vaddr, stub_va, link=False))
            for k in range(4, fn.size, 4):
                struct.pack_into("<I", result, fn_off + k, 0xD4200000 | (((plan.build_seed + k) & 0xFFFF) << 5))
            transformed_functions_report.append({
                "name": fn.name, "vaddr": fn.vaddr, "size": fn.size,
                "backend": "vm", "stub_vaddr": stub_va, "vm_program_index": prog_idx,
                "vm_insn_count": insn_cnt, "passes": action.passes,
            })
        elif action.backend in ("flatten", "obfuscate"):
            pad_tail(16)
            reloc_va = tail_va()
            code_bytes = obfuscate_and_relocate_function(
                fn,
                reloc_va,
                plan.build_seed,
                enable_sub=True,
                enable_opaque_const=True,
                enable_opaque_pred=True,
                enable_indirect=True,
                enable_shuffle=True,
                enable_split=(action.backend == "obfuscate"),
                enable_flatten=(action.backend == "flatten"),
                gate_bridge_va=gate_bridge_va if action.runtime_gate else None,
                gate_id=gate_idx,
            )
            ext_tail.extend(code_bytes)
            struct.pack_into("<I", result, fn_off, encode_b(fn.vaddr, reloc_va, link=False))
            for k in range(4, fn.size, 4):
                struct.pack_into("<I", result, fn_off + k, 0xD4200000 | (((plan.build_seed + k) & 0xFFFF) << 5))
            transformed_functions_report.append({
                "name": fn.name, "vaddr": fn.vaddr, "size": fn.size,
                "backend": action.backend, "relocated_vaddr": reloc_va,
                "relocated_size": len(code_bytes), "passes": action.passes,
            })
        elif action.backend == "on_demand":
            on_demand_pages.append((gate_idx, action, fn))

    # Emit VM bytecode table if any
    vm_bytecode_vaddr = 0
    vm_bytecode_size = len(vm_bytecode_blob)
    if vm_bytecode_size:
        pad_tail(16)
        vm_bytecode_vaddr = tail_va()
        ext_tail.extend(vm_bytecode_blob)

    # Emit E03 String Resolver Stubs in always-RX part of .guard
    string_entries = []
    string_vault_plain = bytearray()
    for str_id, sref in enumerate(plan.string_refs[:P3_MAX_STRINGS]):
        pad_tail(8)
        stub_va = tail_va()
        stub_code = build_string_resolver_stub(
            stub_va, str_id, sref["rd"], resolve_string_va, sref["resume_vaddr"]
        )
        ext_tail.extend(stub_code)
        # Patch callsite in .text
        cs_off = elf.file_offset(sref["callsite_vaddr"], sref["callsite_size"])
        struct.pack_into("<I", result, cs_off, encode_b(sref["callsite_vaddr"], stub_va, link=False))
        if sref["callsite_size"] == 8:
            struct.pack_into("<I", result, cs_off + 4, 0xD503201F)  # NOP
        # Scrub original string in .rodata so plaintext is absent on disk and at load
        s_len = len(sref["string_bytes"])
        result[sref["string_offset"]:sref["string_offset"] + s_len] = bytes(s_len - 1) + b"\0"

        slot_off = align(len(string_vault_plain), 8)
        if slot_off > len(string_vault_plain):
            string_vault_plain.extend(bytes(slot_off - len(string_vault_plain)))
        s_nonce = secrets.token_bytes(12)
        s_digest = hashlib.sha256(sref["string_bytes"]).digest()
        string_entries.append((slot_off, s_len, s_nonce, s_digest, sref["string_bytes"]))
        # Reserve 8-byte header (0x50335345 LE) + string bytes
        string_vault_plain.extend(struct.pack("<II", 0x50335345, 0) + sref["string_bytes"])

    # Emit R07 On-Demand wrapper stubs in always-RX part, and their isolated 16 KiB pages after
    on_demand_relocated_bodies = []
    for gate_idx, action, fn in on_demand_pages:
        pad_tail(16)
        stub_va = tail_va()
        # Reserve 26 instructions (104 bytes) for build_on_demand_stub
        placeholder = bytes(26 * 4)
        stub_tail_pos = len(ext_tail)
        ext_tail.extend(placeholder)
        on_demand_relocated_bodies.append((gate_idx, action, fn, stub_va, stub_tail_pos))

    # Freeze always-RX guard code size for R06 self-check (covers guard.bin code + all stubs!)
    guard_code_vaddr = guard_base_va
    guard_code_size = cfg

    # Now emit isolated 16 KiB-aligned On-Demand code pages (R07)
    for gate_idx, action, fn, stub_va, stub_tail_pos in on_demand_relocated_bodies:
        pad_tail(16384)
        body_va = tail_va()
        body_bytes = obfuscate_and_relocate_function(
            fn, body_va, plan.build_seed,
            enable_sub=True, enable_opaque_const=True, enable_opaque_pred=False,
            enable_indirect=False, enable_shuffle=False,
        )
        range_idx = len(enc_range_records)
        stub_bytes = build_on_demand_stub(stub_va, range_idx, body_va, on_demand_toggle_va)
        assert len(stub_bytes) == 26 * 4
        ext_tail[stub_tail_pos:stub_tail_pos + len(stub_bytes)] = stub_bytes

        fn_off = elf.file_offset(fn.vaddr, fn.size)
        struct.pack_into("<I", result, fn_off, encode_b(fn.vaddr, stub_va, link=False))
        for k in range(4, fn.size, 4):
            struct.pack_into("<I", result, fn_off + k, 0xD4200000 | (((plan.build_seed + k) & 0xFFFF) << 5))

        ext_tail_pos = len(ext_tail)
        ext_tail.extend(body_bytes)
        pad_tail(16384)
        enc_range_records.append({
            "name": fn.name,
            "vaddr": body_va,
            "size": len(body_bytes),
            "prot": 5,
            "flags": RANGE_FLAG_CODE | RANGE_FLAG_ON_DEMAND | (RANGE_FLAG_AUTH if opt.auth_encryption else 0),
            "plain_bytes": bytes(body_bytes),
            "tail_offset": ext_tail_pos,
            "in_text": False,
        })
        transformed_functions_report.append({
            "name": fn.name, "vaddr": fn.vaddr, "size": fn.size,
            "backend": "on_demand", "stub_vaddr": stub_va, "isolated_page_vaddr": body_va,
            "isolated_size": len(body_bytes), "passes": action.passes,
        })

    # Emit isolated 16 KiB-aligned String Vault (E03)
    string_vault_vaddr = 0
    string_vault_size = 0
    string_vault_tail_pos = 0
    if string_entries:
        pad_tail(16384)
        string_vault_vaddr = tail_va()
        string_vault_tail_pos = len(ext_tail)
        string_vault_size = len(string_vault_plain)
        ext_tail.extend(string_vault_plain)
        pad_tail(16384)

    # Emit isolated 16 KiB-aligned RW Honeypot Memory Canary + cross-call anti-GG & thread-lock state page BEFORE guard_real_end_vaddr
    if (opt.gg_honeypot or opt.anti_gg or string_entries or on_demand_pages) and len(enc_range_records) < P3_MAX_ENC_RANGES:
        pad_tail(16384)
        honeypot_va = tail_va()
        honeypot_bytes = build_gg_honeypot_page(plan.build_seed) if opt.gg_honeypot else bytes(4096)
        honeypot_tail_pos = len(ext_tail)
        ext_tail.extend(honeypot_bytes)
        ext_tail.extend(bytes(4096))  # +4096 writable runtime state page (clocks, locks, od_refcounts)
        pad_tail(16384)
        enc_range_records.append({
            "name": "__gg_honeypot_canary",
            "vaddr": honeypot_va,
            "size": len(honeypot_bytes),
            "prot": 3,
            "flags": RANGE_FLAG_CANARY,
            "plain_bytes": honeypot_bytes,
            "tail_offset": honeypot_tail_pos,
            "in_text": False,
        })

    # Prepare relocation skip table for sparse .data encryption (E02+) and O10 guard self-obfuscation
    sparse_data_sec, sparse_data_relocs = _prepare_sparse_data_state(elf) if opt.encrypt_data else (None, [])
    sparse_skip_va = 0
    sparse_skip_size = 0
    if sparse_data_sec is not None:
        pad_tail(8)
        sparse_skip_va = tail_va()
        skip_bytes = encode_sparse_reloc_table(sparse_data_relocs)
        sparse_skip_size = len(skip_bytes)
        ext_tail.extend(skip_bytes)

    guard_ext_vaddr = 0
    guard_ext_size = 0
    guard_ext_digest = bytes(32)
    guard_obf_report = {"obfuscated_guard_functions": 0, "guard_ext_size": 0}
    if opt.obfuscate_guard:
        pad_tail(16)
        blob, _, guard_ext_size, guard_obf_report = obfuscate_guard_runtime(
            blob, meta, guard_base_va=guard_base_va, seed=plan.build_seed,
            entry_name="p3_entry", append_offset=len(blob) + len(ext_tail),
        )
        ext_bytes = guard_obf_report.get("ext_bytes", b"")
        if ext_bytes:
            guard_ext_vaddr = tail_va()
            guard_ext_digest = hashlib.sha256(ext_bytes).digest()
            ext_tail.extend(ext_bytes)
            entry = guard_obf_report["entry_va"]

    # Emit IDA Pro troll decoy functions (--troll-ida) after real guard tail
    troll_seed = (int(opt.seed) & 0xFFFFFFFFFFFFFFFF) if opt.seed is not None else secrets.randbits(64)
    pad_tail(16)
    guard_real_end_vaddr = tail_va()
    decoy_records = []
    if opt.troll_ida:
        if opt.block_ida:
            # Leave enough padding for IDA's .extern segment right after .tls wipe so decoys remain intact
            extern_gap = align(max(0x800, 8 * len(elf.symbols(dynamic_only=True)) + 0x100), 16)
            ext_tail.extend(bytes(extern_gap))
        pad_tail(16)
        decoy_bytes, decoy_records = build_ida_troll_decoys(
            tail_va(),
            troll_seed,
            barcode_chars=opt.troll_barcode_chars,
            barcode_length=opt.troll_barcode_length,
            decoys_spec=opt.troll_decoys,
        )
        ext_tail.extend(decoy_bytes)
        pad_tail(16)

    # Stage 5 & 6: Compute final plaintext baselines (spans, prologues, RELRO) AFTER code transforms!
    records = b"".join(
        SPAN.pack(s.addr, s.size, hashlib.sha256(result[s.offset:s.offset + s.size]).digest())
        for s in spans
    )

    prologue_records = []
    for pchk in plan.prologue_checks[:P3_MAX_PROLOGUES]:
        p_off = elf.file_offset(pchk["vaddr"], pchk["size"])
        expected_bytes = bytes(result[p_off:p_off + pchk["size"]]).ljust(16, b"\0")
        prologue_records.append(PROLOGUE_GUARD.pack(pchk["vaddr"], pchk["size"], 1, expected_bytes))

    # Multi-range code encryption descriptors (E01) + reloc-free read-only unwind metadata (E02+)
    for mr in multi_code_ranges[:P3_MAX_ENC_RANGES - len(enc_range_records)]:
        m_off = elf.file_offset(mr["vaddr"], mr["size"])
        enc_range_records.append({
            "name": mr["name"],
            "vaddr": mr["vaddr"],
            "size": mr["size"],
            "prot": 5,
            "flags": RANGE_FLAG_CODE | (RANGE_FLAG_AUTH if opt.auth_encryption else 0),
            "plain_bytes": bytes(result[m_off:m_off + mr["size"]]),
            "file_offset": m_off,
            "in_text": True,
        })

    ro_unwind_names = []
    if opt.encrypt_rodata:
        for uw in _collect_reloc_free_ro_unwind_ranges(
            elf, rodata, P3_MAX_ENC_RANGES - len(enc_range_records), opt.auth_encryption
        ):
            uw["plain_bytes"] = bytes(result[uw["file_offset"]:uw["file_offset"] + uw["size"]])
            enc_range_records.append(uw)
            ro_unwind_names.append(uw["name"])

    # Key generation & E07 masked key derivation
    need_crypto = bool(
        primary_encrypt_code or rodata or enc_range_records or sparse_data_sec is not None
        or string_entries or opt.auth_encryption or opt.masked_key
    )
    raw_key = secrets.token_bytes(32) if need_crypto else bytes(32)
    key_mask = secrets.token_bytes(32) if (need_crypto and opt.masked_key) else bytes(32)
    master_key = hmac.new(key_mask, raw_key, hashlib.sha256).digest() if (need_crypto and opt.masked_key) else raw_key
    nonce = secrets.token_bytes(12) if need_crypto else bytes(12)

    # Encrypt String Vault entries with master_key
    packed_strings = []
    for slot_off, s_len, s_nonce, s_digest, s_plain in string_entries:
        s_cipher = chacha20(s_plain, master_key, s_nonce, 1)
        pos = string_vault_tail_pos + slot_off + 8
        ext_tail[pos:pos + s_len] = s_cipher
        packed_strings.append(STRING_ENTRY.pack(slot_off, s_len, s_nonce, s_digest))

    # Stage 7: Encrypt primary .text, primary .rodata, sparse .data, and all enc_ranges, computing E04 MACs
    text_cipher_mac = bytes(32)
    if primary_encrypt_code:
        plain_text = bytes(result[text.offset:text.offset + text.size])
        cipher_text = chacha20(plain_text, master_key, nonce)
        result[text.offset:text.offset + text.size] = cipher_text
        if opt.auth_encryption:
            text_cipher_mac = _compute_cipher_mac(master_key, text.addr, text.size, nonce, cipher_text)

    rodata_cipher_mac = bytes(32)
    rodata_plain_digest = bytes(32)
    if rodata:
        plain_ro = bytes(result[rodata.offset:rodata.offset + rodata.size])
        rodata_plain_digest = hashlib.sha256(plain_ro).digest()
        data_nonce = nonce[:11] + bytes([nonce[11] ^ 0x80])
        cipher_ro = chacha20(plain_ro, master_key, data_nonce)
        result[rodata.offset:rodata.offset + rodata.size] = cipher_ro
        if opt.auth_encryption:
            rodata_cipher_mac = _compute_cipher_mac(master_key, rodata.addr, rodata.size, data_nonce, cipher_ro)

    data_enc_tuple = (0, 0, 0, 0, 0, 8, bytes(12), 0, bytes(32), bytes(32))
    encrypted_data_ok = False
    if sparse_data_sec is not None:
        sparse_nonce = nonce[:11] + bytes([nonce[11] ^ 0x41])
        d_off, d_sz = sparse_data_sec.offset, sparse_data_sec.size
        d_plain = bytes(result[d_off:d_off + d_sz])
        d_stream = bytearray(chacha20(d_plain, master_key, sparse_nonce, 1))
        for rel in sparse_data_relocs:
            d_stream[rel:rel + 8] = d_plain[rel:rel + 8]
        plain_gaps = bytearray()
        cursor = 0
        for rel in sparse_data_relocs:
            if rel > cursor:
                plain_gaps.extend(d_plain[cursor:rel])
            cursor = rel + 8
        if cursor < d_sz:
            plain_gaps.extend(d_plain[cursor:d_sz])
        d_plain_digest = hashlib.sha256(bytes(plain_gaps)).digest()
        d_cipher_mac = (
            compute_sparse_data_cipher_mac(
                master_key, sparse_data_sec.addr, bytes(d_stream), sparse_nonce, sparse_data_relocs, 8
            )
            if opt.auth_encryption
            else bytes(32)
        )
        result[d_off:d_off + d_sz] = d_stream
        data_enc_tuple = (
            sparse_data_sec.addr, d_sz, sparse_skip_va, sparse_skip_size,
            0x50334441, 8, sparse_nonce, 1 if opt.auth_encryption else 0,
            d_cipher_mac, d_plain_digest,
        )
        encrypted_data_ok = True

    packed_enc_ranges = []
    for er in enc_range_records:
        r_plain = er["plain_bytes"]
        r_plain_digest = hashlib.sha256(r_plain).digest()
        if er["flags"] & RANGE_FLAG_CANARY:
            # Honeypot canary remains readable in memory as scanner bait; detect any tamper via SHA-256
            r_nonce = bytes(12)
            r_mac = bytes(32)
            ext_tail[er["tail_offset"]:er["tail_offset"] + er["size"]] = r_plain
        else:
            r_nonce = secrets.token_bytes(12)
            r_cipher = chacha20(r_plain, master_key, r_nonce, 1)
            r_mac = _compute_cipher_mac(master_key, er["vaddr"], er["size"], r_nonce, r_cipher) if (er["flags"] & RANGE_FLAG_AUTH) else bytes(32)
            if er["in_text"]:
                result[er["file_offset"]:er["file_offset"] + er["size"]] = r_cipher
            else:
                ext_tail[er["tail_offset"]:er["tail_offset"] + er["size"]] = r_cipher
        packed_enc_ranges.append(ENC_RANGE.pack(
            er["vaddr"], er["size"], er["prot"], er["flags"], r_nonce, 1, r_mac, r_plain_digest
        ))

    # GOT & RELRO metadata for R03/R04
    got_sec = elf.section(".got.plt") or elf.section(".got")
    got_vaddr = got_sec.addr if (opt.got_check and got_sec) else 0
    got_size = got_sec.size if (opt.got_check and got_sec) else 0
    valid_min = min(s.addr for s in spans)
    valid_max = max(s.addr + s.size for s in spans)

    relro_sec = elf.section(".data.rel.ro")
    relro_vaddr = 0
    relro_size = 0
    relro_digest = bytes(32)
    if opt.relro_check and relro_sec and relro_sec.size > 0:
        # Only enable static SHA-256 check on .data.rel.ro if no dynamic relocations mutate it at load
        has_relro_relocs = False
        for sec in elf.sections:
            if sec.type in (4, 9):
                ent = 24 if sec.type == 4 else 16
                for off in range(sec.offset, sec.offset + sec.size, ent):
                    r_va, = struct.unpack_from("<Q", elf.data, off)
                    if relro_sec.addr <= r_va < relro_sec.addr + relro_sec.size:
                        has_relro_relocs = True
                        break
        if not has_relro_relocs:
            relro_vaddr = relro_sec.addr
            relro_size = relro_sec.size
            relro_digest = hashlib.sha256(result[relro_sec.offset:relro_sec.offset + relro_sec.size]).digest()

    # Build ext_flags
    ext_flags = 0
    if opt.masked_key and need_crypto:
        ext_flags |= EXT_MASKED_KEY
    if opt.auth_encryption and (primary_encrypt_code or rodata or enc_range_records):
        ext_flags |= EXT_AUTH_RANGES
    if opt.sign_manifest:
        ext_flags |= EXT_MANIFEST_MAC
    if opt.guard_self_check or guard_ext_size > 0:
        ext_flags |= EXT_GUARD_SELF_CHECK
    if prologue_records:
        ext_flags |= EXT_PROLOGUE_CHECK
    if got_vaddr and got_size:
        ext_flags |= EXT_GOT_CHECK
    if relro_vaddr and relro_size:
        ext_flags |= EXT_RELRO_CHECK
    if opt.runtime_integrity or any(a.runtime_gate for a in plan.function_actions):
        ext_flags |= EXT_RUNTIME_GATE
    if opt.runtime_anti_debug:
        ext_flags |= EXT_RUNTIME_ANTIDEBUG
    if vm_prog_records:
        ext_flags |= EXT_VM_ENABLED
    if packed_strings:
        ext_flags |= EXT_STRING_VAULT
    if on_demand_relocated_bodies:
        ext_flags |= EXT_ON_DEMAND
    if opt.deep_probes:
        ext_flags |= EXT_DEEP_PROBES
    if opt.gg_honeypot and any(er["flags"] & RANGE_FLAG_CANARY for er in enc_range_records):
        ext_flags |= EXT_GG_HONEYPOT
    if opt.ephemeral_strings and packed_strings:
        ext_flags |= EXT_EPHEMERAL_STRINGS
    if opt.anti_gg:
        ext_flags |= EXT_ANTI_GG

    use_ext_v3 = bool(
        ext_flags or enc_range_records or prologue_records or vm_prog_records
        or packed_strings or opt.watermark or opt.seed is not None
        or guard_ext_size > 0 or encrypted_data_ok
    )

    rekey_guard_strings(blob, str_cfg, plan.build_seed)
    blob[data_enc_cfg:data_enc_cfg + SPARSE_DATA_CFG.size] = SPARSE_DATA_CFG.pack(
        *data_enc_tuple, guard_ext_vaddr, guard_ext_size, guard_ext_digest
    )
    blob[pack_cfg:pack_cfg + PACK_CFG_SIZE] = bytes(PACK_CFG_SIZE)

    # Populate base p3_config with per-build stealth magic
    base_flags = opt.flags()
    if primary_encrypt_code:
        base_flags |= 32
    else:
        base_flags &= ~32

    header = CONFIG.pack(
        stealth_magic_bytes(plan.build_seed, is_ext=False), 2, base_flags, guard_base_va + cfg,
        elf.dynamic_value(DT_INIT), len(spans), 0,
        text.addr if primary_encrypt_code else 0,
        text.size if primary_encrypt_code else 0,
        raw_key, nonce, 1,
        rodata.addr if rodata else 0,
        rodata.size if rodata else 0,
        rodata_plain_digest, rodata_prot, 0,
    )
    blob[cfg:cfg + CONFIG_SIZE] = header + records + bytes(SPAN.size * (32 - len(spans)))

    # Populate extended p3_ext (Stage 8: Sign manifest over all .p3config structs)
    manifest_pubkey = secrets.token_bytes(32) if opt.sign_manifest else bytes(32)
    guard_code_digest = hashlib.sha256(blob[:cfg]).digest()
    wm_bytes = bytes.fromhex(plan.watermark_hex) if plan.watermark_hex else bytes(16)

    if use_ext_v3:
        ext_hdr_zero_mac = EXT_HDR.pack(
            stealth_magic_bytes(plan.build_seed, is_ext=True), 3, ext_flags,
            len(packed_enc_ranges), len(prologue_records),
            len(vm_prog_records), len(packed_strings),
            plan.build_seed, wm_bytes,
            key_mask, manifest_pubkey, bytes(32),
            text_cipher_mac, rodata_cipher_mac,
            guard_code_vaddr, guard_code_size, guard_code_digest,
            got_vaddr, got_size, valid_min, valid_max,
            relro_vaddr, relro_size, relro_digest,
            vm_bytecode_vaddr, vm_bytecode_size,
            string_vault_vaddr, string_vault_size,
            decode_map, vm_key,
        )
        ext_arrays = (
            b"".join(packed_enc_ranges) + bytes(ENC_RANGE.size * (P3_MAX_ENC_RANGES - len(packed_enc_ranges)))
            + b"".join(prologue_records) + bytes(PROLOGUE_GUARD.size * (P3_MAX_PROLOGUES - len(prologue_records)))
            + b"".join(vm_prog_records) + bytes(VM_PROG.size * (P3_MAX_VM_PROGS - len(vm_prog_records)))
            + b"".join(packed_strings) + bytes(STRING_ENTRY.size * (P3_MAX_STRINGS - len(packed_strings)))
        )
        ext_full = bytearray(ext_hdr_zero_mac + ext_arrays)
        if opt.sign_manifest:
            manifest_mac = compute_manifest_hmac(
                manifest_pubkey,
                blob[cfg:cfg + CONFIG_SIZE],
                ext_full,
                blob[str_cfg:data_enc_cfg],
                blob[data_enc_cfg:pack_cfg],
                blob[pack_cfg:pack_cfg + PACK_CFG_SIZE],
            )
            ext_full[128:160] = manifest_mac
        blob[ext_cfg:ext_cfg + EXT_CONFIG_SIZE] = ext_full

    full_guard_blob = bytes(blob) + bytes(ext_tail)
    dynamic += [(DT_INIT, entry), (0, 0)]
    dynamic_bytes = b"".join(DYN.pack(tag, value) for tag, value in dynamic)
    segment_size = guard_offset + len(full_guard_blob)
    if vaddr + segment_size >= 1 << 48:
        raise ProtectionError("Injected runtime would exceed the supported VA range.")

    phdr = Segment(PT_PHDR, 4, offset, vaddr, vaddr, phsize, phsize, 8)
    segments = [phdr]
    for segment in elf.segments:
        if segment.type == PT_PHDR:
            continue
        if segment.type == PT_DYNAMIC:
            segment = replace(segment, offset=offset + dyn_offset, vaddr=vaddr + dyn_offset,
                              paddr=vaddr + dyn_offset, filesz=dyn_size, memsz=dyn_size,
                              flags=4, alignment=8)
        segments.append(segment)
    segments.append(Segment(PT_LOAD, 5, offset, vaddr, vaddr, segment_size, segment_size, alignment))

    result.extend(bytes(offset - len(result)))
    payload = bytearray(segment_size)
    if not preserve_tables:
        payload[:phsize] = b"".join(s.pack() for s in segments)
        payload[dyn_offset:dyn_offset + dyn_size] = dynamic_bytes
    payload[guard_offset:] = full_guard_blob
    result.extend(payload)

    ida_info = {"troll_ida": False, "block_ida": False, "renamed_functions_count": 0, "decoy_functions_count": 0}
    if not preserve_tables:
        elf_header = elf.header.copy()
        elf_header[5], elf_header[10] = offset, phnum
        result[:EHDR.size] = EHDR.pack(*elf_header)
        for i, section in enumerate(elf.sections):
            if section.type == SHT_DYNAMIC:
                section = replace(section, flags=section.flags & ~1, addr=vaddr + dyn_offset,
                                  offset=offset + dyn_offset, size=dyn_size, alignment=8)
                result[elf.shoff + i * 64:elf.shoff + (i + 1) * 64] = section.pack()
        if opt.troll_ida or opt.block_ida:
            patched_bytes, ida_info = apply_ida_troll_and_block(
                result,
                pre_strip_functions=pre_strip_functions,
                decoy_records=decoy_records,
                guard_real_end_vaddr=guard_real_end_vaddr,
                troll_ida=opt.troll_ida,
                block_ida=opt.block_ida,
                seed=troll_seed,
                barcode_chars=opt.troll_barcode_chars,
                barcode_length=opt.troll_barcode_length,
                decoys_spec=opt.troll_decoys,
            )
            result = bytearray(patched_bytes)
        protected = ELF(result)
        verify_structure(protected)
        compare_abi(elf, protected)

    code_enc_report = None
    if primary_encrypt_code:
        code_enc_report = {
            "vaddr": text.addr,
            "size": text.size,
            "function": opt.encrypt_function or (plan.encrypted_code_ranges[0]["name"] if plan.encrypted_code_ranges else None),
        }
    elif multi_code_ranges:
        code_enc_report = {
            "ranges": [{"name": r["name"], "vaddr": r["vaddr"], "size": r["size"]} for r in multi_code_ranges],
        }

    out_info = {
        "segment_vaddr": vaddr,
        "segment_offset": offset,
        "entry_vaddr": entry,
        "config_offset": offset + guard_offset + cfg,
        "ext_config_offset": offset + guard_offset + ext_cfg,
        "protected_sections": [{"name": s.name, "vaddr": s.addr, "size": s.size} for s in spans],
        "runtime_sha256": meta["sha256"],
        "layout": "preserved_tables" if preserve_tables else "relocated_tables",
        "encrypted_sections": (
            ([".text"] if (primary_encrypt_code or multi_code_ranges) else [])
            + ([".rodata"] if rodata else [])
            + ro_unwind_names
            + ([".data"] if encrypted_data_ok else [])
        ),
        "obfuscated_guard": {k: v for k, v in guard_obf_report.items() if k != "ext_bytes"},
        "code_encryption_range": code_enc_report,
        "transformed_functions": transformed_functions_report,
        "encrypted_strings_count": len(packed_strings),
        "prologue_guards_count": len(prologue_records),
        "active_roadmap_ids": plan.active_ids,
        "build_seed": plan.build_seed,
        "watermark_hex": plan.watermark_hex if opt.watermark else None,
        "skipped_targets": plan.skipped_items,
        "ida_anti_analysis": ida_info,
    }
    if preserve_tables:
        out_info["_decoy_records"] = decoy_records
        out_info["_guard_real_end_vaddr"] = guard_real_end_vaddr
        out_info["_troll_seed"] = troll_seed
    return bytes(result), out_info


def _safe_note_slot(elf, segment):
    """Only discard a program-header reference to informational identity notes."""
    if segment.type == 0 and not segment.filesz and not segment.memsz:
        return True
    if segment.type != 4:
        return False
    cursor, end = segment.offset, segment.offset + segment.filesz
    while cursor < end:
        if cursor + 12 > end:
            return False
        namesz, descsz, kind = struct.unpack_from("<III", elf.data, cursor)
        cursor += 12
        if cursor + align(namesz, 4) + align(descsz, 4) > end:
            return False
        name = elf.data[cursor:cursor + namesz].rstrip(b"\0")
        if (name, kind) not in ((b"GNU", 3), (b"Android", 1)):
            return False
        cursor += align(namesz, 4) + align(descsz, 4)
    return cursor == end


def _grow_header_table_in_note(elf, data, guard):
    """Keep PT_PHDR and PT_NOTE by growing into informational note storage."""
    boundary = elf.phoff + elf.phnum * PHDR.size
    note = next((s for s in elf.segments if s.type == 4 and _safe_note_slot(elf, s)
                 and s.offset <= boundary and boundary + PHDR.size <= s.offset + s.filesz), None)
    if note is None:
        return data, False
    data = bytearray(data)
    new_note_offset = align(len(data), 16)
    new_note_vaddr = guard.vaddr + new_note_offset - guard.offset
    data.extend(bytes(new_note_offset - len(data)))
    data.extend(elf.data[note.offset:note.offset + note.filesz])
    guard = replace(guard, filesz=len(data) - guard.offset, memsz=len(data) - guard.offset)
    headers = []
    for segment in elf.segments:
        if segment.type == PT_PHDR:
            segment = replace(segment, filesz=(elf.phnum + 1) * PHDR.size, memsz=(elf.phnum + 1) * PHDR.size)
        if segment == note:
            segment = replace(segment, offset=new_note_offset, vaddr=new_note_vaddr, paddr=new_note_vaddr)
        headers.append(segment)
    index = max(i for i, s in enumerate(headers) if s.type == PT_LOAD) + 1
    headers.insert(index, guard)
    sections = []
    for section in elf.sections:
        if section.type == 7 and note.offset <= section.offset and section.offset + section.size <= note.offset + note.filesz:
            delta = section.offset - note.offset
            section = replace(section, offset=new_note_offset + delta,
                              addr=new_note_vaddr + delta if section.flags & 2 else section.addr)
        sections.append(section)
    new_shoff = align(len(data), 8)
    data.extend(bytes(new_shoff - len(data)))
    data.extend(b"".join(section.pack() for section in sections))
    header = elf.header.copy()
    header[6], header[10] = new_shoff, len(headers)
    data[:EHDR.size] = EHDR.pack(*header)
    data[elf.phoff:elf.phoff + len(headers) * PHDR.size] = b"".join(segment.pack() for segment in headers)
    return data, True


def _resign_manifest_if_needed(result, guard_offset, meta):
    """Recompute E05 manifest_mac if original_init in p3_config was updated for RELA hook."""
    rel_cfg = meta["symbols"]["p3_config"]
    rel_ext = meta["symbols"].get("p3_ext", rel_cfg + CONFIG_SIZE)
    rel_str = meta["symbols"].get("p3_str_cfg", rel_ext + EXT_CONFIG_SIZE)
    rel_data = meta["symbols"].get("p3_data_enc", rel_str + 5736)
    rel_pack = meta["symbols"].get("p3_pack", rel_data + SPARSE_DATA_CFG.size)
    cfg_off = guard_offset + rel_cfg
    ext_off = guard_offset + rel_ext
    str_off = guard_offset + rel_str
    data_off = guard_offset + rel_data
    pack_off = guard_offset + rel_pack
    ext_ver, ext_flags = struct.unpack_from("<II", result, ext_off + 16)
    if ext_ver == 3 and (ext_flags & EXT_MANIFEST_MAC):
        pubkey = bytes(result[ext_off + 96:ext_off + 128])
        mac = compute_manifest_hmac(
            pubkey,
            result[cfg_off:cfg_off + CONFIG_SIZE],
            result[ext_off:ext_off + EXT_CONFIG_SIZE],
            result[str_off:data_off],
            result[data_off:pack_off],
            result[pack_off:pack_off + PACK_CFG_SIZE],
        )
        result[ext_off + 128:ext_off + 160] = mac


def check_compat_layout_support(elf):
    """Verify whether `elf` has safe PHDR/NOTE and DT_INIT/DT_NULL slots for compat_layout."""
    header_mapped = any(s.offset == 0 and elf.phoff + elf.phnum * PHDR.size <= s.filesz for s in elf.loads)
    candidate = next((i for i, segment in enumerate(elf.segments) if header_mapped and segment.type == PT_PHDR), None)
    if candidate is None:
        candidate = next((i for i, segment in enumerate(elf.segments) if _safe_note_slot(elf, segment)), None)
    if candidate is None:
        raise ProtectionError("Compatibility layout requires a spare PT_NULL or informational PT_NOTE record; no safe slot found.")

    dynamic = elf.dynamic_segment
    slot = next((i for i, (tag, _) in enumerate(elf.dynamic) if tag == DT_INIT), None)
    replaced_tag = DT_INIT
    has_init_array_reloc = False
    if not elf.dynamic_value(DT_INIT) and elf.dynamic_value(25) and elf.dynamic_value(27) >= 8:
        first_initializer = elf.dynamic_value(25)
        for section in elf.sections:
            if section.type != 4 or section.entsize != 24:
                continue
            for cursor in range(section.offset, section.offset + section.size, 24):
                address, info, addend = struct.unpack_from("<QQq", elf.data, cursor)
                if address == first_initializer and info == 1027 and any(
                    s.flags & 1 and s.vaddr <= addend < s.vaddr + s.filesz for s in elf.loads
                ):
                    has_init_array_reloc = True
                    break
            if has_init_array_reloc:
                break
    if slot is None and not has_init_array_reloc:
        null_offset = dynamic.offset + len(elf.dynamic) * DYN.size
        if null_offset + 2 * DYN.size <= dynamic.offset + dynamic.filesz and DYN.unpack_from(elf.data, null_offset + DYN.size)[0] == 0:
            slot, replaced_tag = len(elf.dynamic), 0
        else:
            slot = next((i for i, (tag, _) in enumerate(elf.dynamic) if tag in (0x6FFFFFF9, 0x6FFFFFFA)), None)
            if slot is not None:
                replaced_tag = elf.dynamic[slot][0]
    if slot is None and not has_init_array_reloc:
        raise ProtectionError("Compatibility layout needs DT_INIT, a spare DT_NULL, or optional REL[A]COUNT; no safe dynamic slot found.")
    return candidate, slot, replaced_tag, has_init_array_reloc


def rewrite_compatible(elf, options, blob, meta, pre_strip_functions=None):
    """Keep e_phoff/PT_DYNAMIC at their original positions for native bridges."""
    candidate, slot, replaced_tag, _ = check_compat_layout_support(elf)

    generated, injection = rewrite(
        elf, options, blob, meta, pre_strip_functions=pre_strip_functions, preserve_tables=True
    )
    result = bytearray(generated)
    guard_offset = injection["segment_offset"]
    guard_vaddr = injection["segment_vaddr"]
    payload_len = len(result) - guard_offset
    config_offset = meta["symbols"]["p3_config"]
    entry = injection["entry_vaddr"]
    guard = Segment(
        PT_LOAD, 5, guard_offset, guard_vaddr, guard_vaddr,
        payload_len, payload_len, max(4096, *(s.alignment for s in elf.loads)),
    )
    segments = [segment for i, segment in enumerate(elf.segments) if i != candidate] + [guard]
    if len(segments) != elf.phnum:
        raise ProtectionError("Compatibility layout unexpectedly changed the number of program headers.")
    result[elf.phoff:elf.phoff + elf.phnum * PHDR.size] = b"".join(segment.pack() for segment in segments)

    dynamic = elf.dynamic_segment
    patched_relocations = []
    initializer_hook = None
    if not elf.dynamic_value(DT_INIT) and elf.dynamic_value(25) and elf.dynamic_value(27) >= 8:
        first_initializer = elf.dynamic_value(25)
        for section in elf.sections:
            if section.type != 4 or section.entsize != 24:
                continue
            for cursor in range(section.offset, section.offset + section.size, 24):
                address, info, addend = struct.unpack_from("<QQq", elf.data, cursor)
                if address != first_initializer or info != 1027:
                    continue
                if not any(s.flags & 1 and s.vaddr <= addend < s.vaddr + s.filesz for s in elf.loads):
                    continue
                struct.pack_into("<q", result, cursor + 16, entry)
                struct.pack_into("<Q", result, guard.offset + config_offset + 40, addend)
                _resign_manifest_if_needed(result, guard.offset, meta)
                patched_relocations.append(section.addr + cursor - section.offset + 16)
                initializer_hook = {"array_vaddr": first_initializer, "original_function_vaddr": addend,
                                    "relocation_addend_vaddr": patched_relocations[-1]}
                break
            if initializer_hook:
                break
    if initializer_hook is None:
        result[dynamic.offset + slot * DYN.size:dynamic.offset + (slot + 1) * DYN.size] = DYN.pack(DT_INIT, entry)
    result, header_growth = _grow_header_table_in_note(elf, result, guard)
    decoy_records = injection.pop("_decoy_records", [])
    guard_real_end_vaddr = injection.pop("_guard_real_end_vaddr", 0)
    troll_seed = injection.pop("_troll_seed", injection.get("build_seed", 0))
    opt = apply_profile_defaults(options)
    if opt.troll_ida or opt.block_ida:
        patched_bytes, ida_info = apply_ida_troll_and_block(
            result,
            pre_strip_functions=pre_strip_functions,
            decoy_records=decoy_records,
            guard_real_end_vaddr=guard_real_end_vaddr,
            troll_ida=opt.troll_ida,
            block_ida=opt.block_ida,
            seed=troll_seed,
            barcode_chars=opt.troll_barcode_chars,
            barcode_length=opt.troll_barcode_length,
            decoys_spec=opt.troll_decoys,
        )
        result = bytearray(patched_bytes)
        injection["ida_anti_analysis"] = ida_info
    protected = ELF(result)
    verify_structure(protected)
    compare_abi(elf, protected, patched_relocations)
    injection.update(
        entry_vaddr=entry,
        config_offset=guard.offset + config_offset,
        layout="preserved_tables",
        reused_program_header_type=hex(elf.segments[candidate].type),
        replaced_dynamic_tag=None if initializer_hook else hex(replaced_tag),
        initializer_hook=initializer_hook,
        patched_relocation_addends=patched_relocations,
        program_header_growth=header_growth,
    )
    if header_growth:
        injection["reused_program_header_type"] = None
    return bytes(result), injection


def compare_abi(before, after, patched_relocation_addends=()):
    if before.exported_symbols() != after.exported_symbols():
        raise ProtectionError("Validation failed: exported ABI changed.")
    for tag in (1, 5, 6, 10, 11, 14, 25, 26, 27, 28, 0x6FFFFFF0, 0x6FFFFFFC, 0x6FFFFFFD, 0x6FFFFFFE, 0x6FFFFFFF):
        if [v for t, v in before.dynamic if t == tag] != [v for t, v in after.dynamic if t == tag]:
            raise ProtectionError(f"Validation failed: ABI dynamic tag {tag:#x} changed.")
    for section in before.sections:
        if section.type in (4, 9, 11, 0x6FFFFFF6, 0x6FFFFFFD, 0x6FFFFFFE, 0x6FFFFFFF):
            other = after.section(section.name)
            original_data = bytearray(before.section_data(section))
            updated_data = bytearray(after.section_data(other)) if other else None
            if section.type == 4 and other and section.addr == other.addr:
                for address in patched_relocation_addends:
                    if section.addr <= address and address + 8 <= section.addr + section.size:
                        relative = address - section.addr
                        original_data[relative:relative + 8] = updated_data[relative:relative + 8]
            if other is None or original_data != updated_data:
                raise ProtectionError(f"Validation failed: relocation/symbol metadata changed: {section.name}")


def verify_structure(elf):
    phdr = next((s for s in elf.segments if s.type == PT_PHDR), None)
    if phdr and (phdr.offset != elf.phoff or phdr.filesz != elf.phnum * PHDR.size):
        raise ProtectionError("Program header table is not described by PT_PHDR.")
    if phdr and elf.file_offset(phdr.vaddr, phdr.filesz) != phdr.offset:
        raise ProtectionError("Program header table is not mapped into a load segment.")
    if not phdr and not any(s.offset <= elf.phoff and elf.phoff + elf.phnum * PHDR.size <= s.offset + s.filesz for s in elf.loads):
        raise ProtectionError("Program header table is not mapped into a load segment.")
    loads = [s.vaddr for s in elf.segments if s.type == PT_LOAD]
    if loads != sorted(loads):
        raise ProtectionError("Load segments are not sorted by virtual address.")
    for s in elf.loads:
        if s.flags & 3 == 3:
            raise ProtectionError("An RWX segment was introduced.")
    dynamic = [s for s in elf.sections if s.type == SHT_DYNAMIC]
    if len(dynamic) != 1 or dynamic[0].offset != elf.dynamic_segment.offset or dynamic[0].size != elf.dynamic_segment.filesz:
        raise ProtectionError("Dynamic section/program header mismatch.")
    if elf.file_offset(elf.dynamic_segment.vaddr, elf.dynamic_segment.filesz) != elf.dynamic_segment.offset:
        raise ProtectionError("Dynamic table is not mapped into a load segment.")
    init = elf.dynamic_value(DT_INIT)
    if init and not any(s.flags & 1 and s.vaddr <= init < s.vaddr + s.filesz for s in elf.loads):
        raise ProtectionError("DT_INIT does not point to executable memory.")
    if not init and not (elf.dynamic_value(25) and elf.dynamic_value(27) >= 8):
        raise ProtectionError("Library has no initializer entry point.")


def _publish(data, report, output, force):
    manifest = output.with_name(output.name + ".protect3.json")
    if not force and (output.exists() or manifest.exists()):
        raise ProtectionError("Output/report already exists; choose a new path or pass --force.")
    output.parent.mkdir(parents=True, exist_ok=True)
    staged = []
    created = []
    try:
        for target, content in ((output, data), (manifest, (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))):
            with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".protect3-", delete=False) as temporary:
                temporary.write(content)
                staged.append((Path(temporary.name), target))
        for temporary, target in staged:
            if force:
                os.replace(temporary, target)
            else:
                os.link(temporary, target)
                created.append(target)
    except Exception:
        if not force:
            for path in created:
                path.unlink(missing_ok=True)
        raise
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
    return manifest


def _run_f03_semantics(original, protected_bytes, transformed_functions, active_ids, log):
    """Run F03 differential Unicorn verification for exported transformed functions."""
    semantics_results = []
    if transformed_functions:
        exported_names = {s[0] for s in original.exported_symbols()}
        for tf in transformed_functions:
            if tf["name"] in exported_names:
                f03_res = verify_function_semantics_unicorn(original.data, protected_bytes, tf["name"])
                semantics_results.append(f03_res)
                if f03_res.get("status") == "failed":
                    raise ProtectionError(
                        f"F03 semantic verification failed for '{tf['name']}': "
                        f"{f03_res.get('reason') or f03_res.get('mismatches')}"
                    )
    if not semantics_results:
        semantics_results.append({
            "status": "skipped",
            "function": "(none-exported)",
            "reason": "Không có hàm export nào được biến đổi để đối chiếu F03.",
        })
    if "F03" not in active_ids:
        active_ids.append("F03")
        active_ids.sort()
    passed_f03 = sum(1 for r in semantics_results if r.get("status") == "passed")
    skipped_f03 = sum(1 for r in semantics_results if r.get("status") == "skipped")
    log(f"F03 Unicorn verification complete: {passed_f03} passed, {skipped_f03} skipped.")
    return semantics_results


def protect(input_path, output_path, options=None, ndk=None, force=False, log=None):
    raw_opt = options or Options()
    opt = apply_profile_defaults(raw_opt)
    log = log or (lambda _: None)
    source, output = Path(input_path).resolve(), Path(output_path).resolve()
    if source == output:
        raise ProtectionError("Input must never be overwritten. Choose a separate output .so.")
    if output.suffix.lower() != ".so":
        raise ProtectionError("Output filename must end in .so.")
    log("Reading and validating Android ARM64 ELF...")
    original = ELF(read_library(source))
    original.validate_target()

    # Step 1 (F01/F05): Resolve function boundaries & validate unified plan BEFORE strip/metadata cleanup
    pre_strip_functions = discover_functions(original)
    expanded_opt = apply_profile_defaults(opt)
    plan = build_protection_plan(original, opt, pre_strip_functions=pre_strip_functions)

    # Step 2 (E06): Clean metadata and strip symbols before in-place transforms and/or E08/E09 packing
    data = original.data
    scrubbed_sections = []
    if expanded_opt.clean_metadata or expanded_opt.keep_debug:
        log("Cleaning non-essential ELF metadata (E06)...")
        data, scrubbed_sections = scrub_elf_metadata(data, expanded_opt.keep_debug or None)
    if expanded_opt.strip_symbols:
        log("Stripping nonessential symbols/debug information with NDK LLVM...")
        with tempfile.TemporaryDirectory(prefix="protect3-strip-") as temporary:
            in_tmp = Path(temporary) / "input.so"
            target = Path(temporary) / "stripped.so"
            in_tmp.write_bytes(data)
            command([ndk_tool("llvm-strip", ndk), "--strip-unneeded", "-o", str(target), str(in_tmp)])
            data = target.read_bytes()
            compare_abi(original, ELF(data))

    # Step 3: In-place protection passes (O08/O09 -> O07 -> O01-O06 -> R07 -> E03 -> R09 -> R01-R06 -> E01/E02/E04/E05 -> IDA)
    from .planner import resolve_outer_packing_modes

    pack_mode, effective_wrap_elf, _, _ = resolve_outer_packing_modes(original, opt)
    if opt.wrap_elf and not effective_wrap_elf:
        log("Preferring E09 packed ELF over E08 wrapper because target exports STT_OBJECT or lacks STT_FUNC.")
    if pack_mode:
        step3_keys = (
            "obfuscate_ops", "obfuscate_functions", "flatten_cfg", "flatten_functions",
            "virtualize_functions", "virtualize_auto", "obfuscate_jni",
            "runtime_integrity", "prologue_check", "got_check", "relro_check",
            "runtime_anti_debug", "guard_self_check", "on_demand_functions",
            "encrypt_strings", "gg_honeypot", "ephemeral_strings", "anti_gg",
        )
        has_in_place = any(bool(getattr(expanded_opt, k, False)) for k in step3_keys) or bool(expanded_opt.watermark)
        step3_opt = replace(
            expanded_opt, profile="", pack_elf=False, wrap_elf=False, obfuscate_guard=False,
            encrypt_text=False, encrypt_function="", encrypt_functions="",
            encrypt_rodata=False, encrypt_data=False,
            troll_ida=False, block_ida=False, compat_layout=False, verify_semantics=False,
        )
    else:
        has_in_place = (
            not effective_wrap_elf
            or any(bool(getattr(expanded_opt, k, False)) for k in IN_PLACE_PASS_OPTIONS)
            or bool(expanded_opt.integrity or expanded_opt.debugger or expanded_opt.watermark)
        )
        step3_opt = opt

    injection = {}
    semantics_results = []
    blob = meta = None
    after_inner = None
    if has_in_place:
        log("Loading verified ARM64 runtime...")
        blob, meta = load_runtime(ndk)
        log("Applying planned native protection passes and injecting runtime...")
        protected, injection = rewrite(ELF(data), step3_opt, blob, meta, pre_strip_functions=pre_strip_functions)
        after_inner = ELF(protected)
        compare_abi(original, after_inner, injection.get("patched_relocation_addends", ()))
        if opt.verify_semantics:
            semantics_results = _run_f03_semantics(
                original, protected, injection.get("transformed_functions", []),
                injection.setdefault("active_roadmap_ids", []), log,
            )
    else:
        protected = data

    # Step 4a (E09 compressed in-memory ELF packer & custom direct-syscall relocator)
    if pack_mode:
        log("Compressing and encrypting segments/relocs/imports into packed ELF (E09)...")
        if blob is None or meta is None:
            blob, meta = load_runtime(ndk)
        wm_hex = injection.get("watermark_hex") or (plan.watermark_hex if opt.watermark else "")
        pack_ext_flags = EXT_DEEP_PROBES if opt.deep_probes else 0
        protected, pack_info = build_packed_elf(
            protected,
            blob,
            meta,
            flags=opt.flags(),
            ext_flags=pack_ext_flags,
            seed=plan.build_seed,
            obfuscate_guard=bool(opt.obfuscate_guard),
            troll_ida=bool(opt.troll_ida),
            barcode_chars=opt.troll_barcode_chars,
            barcode_length=opt.troll_barcode_length,
            decoys_spec=opt.troll_decoys,
            watermark_hex=wm_hex or "",
        )
        ida_info = {"troll_ida": False, "block_ida": False, "renamed_functions_count": 0, "decoy_functions_count": 0}
        if opt.troll_ida or opt.block_ida:
            troll_seed = (int(opt.seed) & 0xFFFFFFFFFFFFFFFF) if opt.seed is not None else plan.build_seed
            protected, ida_info = apply_ida_troll_and_block(
                protected,
                pre_strip_functions=pre_strip_functions,
                decoy_records=pack_info.get("decoy_records", []),
                guard_real_end_vaddr=pack_info.get("stub_real_end_vaddr", 0),
                troll_ida=opt.troll_ida,
                block_ida=opt.block_ida,
                seed=troll_seed,
                barcode_chars=opt.troll_barcode_chars,
                barcode_length=opt.troll_barcode_length,
                decoys_spec=opt.troll_decoys,
            )
        after_inner = ELF(protected)
        verify_structure(after_inner)
        missing_exports = {s[0] for s in original.exported_symbols() if s[0]} - {s[0] for s in after_inner.exported_symbols()}
        if missing_exports:
            raise ProtectionError(f"Packed ELF validation failed: missing exports {sorted(missing_exports)}.")

        inner_inj = dict(injection) if injection else {}
        packed_ids = list(inner_inj.get("active_roadmap_ids", []))
        for pid in ("F01", "F05", "F06", "E01", "E02", "E04", "E05", "E07", "E09", "R06"):
            if pid not in packed_ids:
                packed_ids.append(pid)
        if opt.obfuscate_guard and "O10" not in packed_ids:
            packed_ids.append("O10")
        if (expanded_opt.strip_symbols or expanded_opt.clean_metadata) and "E06" not in packed_ids:
            packed_ids.append("E06")
        if opt.watermark and "A08" not in packed_ids:
            packed_ids.append("A08")
        if opt.verify_semantics:
            if not has_in_place:
                semantics_results = _run_f03_semantics(original, protected, [], packed_ids, log)
            elif "F03" not in packed_ids:
                packed_ids.append("F03")
        packed_ids = sorted(set(packed_ids))
        pack_summary = {k: v for k, v in pack_info.items() if k != "decoy_records"}
        if "obfuscated_guard" in pack_summary and isinstance(pack_summary["obfuscated_guard"], dict):
            pack_summary["obfuscated_guard"] = {
                k: v for k, v in pack_summary["obfuscated_guard"].items() if k != "ext_bytes"
            }
        injection = {
            **pack_summary,
            "inner_protection": inner_inj or None,
            "transformed_functions": inner_inj.get("transformed_functions", []),
            "encrypted_strings_count": inner_inj.get("encrypted_strings_count", 0),
            "prologue_guards_count": inner_inj.get("prologue_guards_count", 0),
            "skipped_targets": inner_inj.get("skipped_targets", []),
            "encrypted_sections": ["ALL_PT_LOAD", ".rela.dyn", ".rela.plt", ".eh_frame", ".rodata", ".data"],
            "active_roadmap_ids": packed_ids,
            "build_seed": plan.build_seed,
            "watermark_hex": wm_hex or None,
            "ida_anti_analysis": ida_info,
        }

    # Step 4 (E08 final outer layer): Wrap the protected (or cleaned/stripped) ELF into memfd/dlopen wrapper
    wrap_info = None
    if effective_wrap_elf:
        log("Wrapping protected payload ELF into standalone ARM64 wrapper .so (E08)...")
        wm_hex = injection.get("watermark_hex") or (plan.watermark_hex if opt.watermark else "")
        protected, wrap_info = build_wrapped_elf(
            ELF(protected),
            ndk,
            allow_protected_payload=bool(injection),
            watermark_hex=wm_hex or "",
            strip_wrapper_symbols=bool(expanded_opt.strip_symbols),
            clean_wrapper_metadata=bool(expanded_opt.clean_metadata or expanded_opt.keep_debug),
        )
        after = ELF(protected)
        verify_structure(after)
        missing_exports = {s[0] for s in original.exported_symbols() if (s[1] & 0xF) == 2 and s[0]} - {s[0] for s in after.exported_symbols()}
        if missing_exports:
            raise ProtectionError(f"Whole-ELF wrapper validation failed: missing forwarded exports {sorted(missing_exports)}.")
        wrapped_ids = list(injection.get("active_roadmap_ids", []))
        for pid in ("F01", "F05", "F06", "E08"):
            if pid not in wrapped_ids:
                wrapped_ids.append(pid)
        if expanded_opt.strip_symbols or expanded_opt.clean_metadata:
            if "E06" not in wrapped_ids:
                wrapped_ids.append("E06")
        if opt.watermark and "A08" not in wrapped_ids:
            wrapped_ids.append("A08")

        exec_order = [
            "1. F01/A03: Khôi phục danh sách hàm & chấm điểm trước strip",
            "2. E06: Xóa metadata / llvm-strip" if (expanded_opt.clean_metadata or expanded_opt.strip_symbols) else "2. E06: Bỏ qua strip/clean",
            "3. F05: Kiểm tra & điều phối kế hoạch bảo vệ đa tầng",
        ]
        if injection:
            exec_order.extend([
                "4. O08/O09 -> O07 -> O01-O06 -> R07 -> E03: Biến đổi hàm & tách chuỗi Vault trong payload",
                "5. R07/E03/R09 -> R01-R06/E07 -> E01/E02/E04/E05 -> IDA: Gia cố payload nội tại",
            ])
        exec_order.extend([
            "6. F03: Kiểm chứng ngữ nghĩa payload trước khi bọc" if opt.verify_semantics else "6. F03: Bỏ qua kiểm chứng Unicorn",
            "7. E08: Mã hóa ChaCha20 toàn payload & đóng gói wrapper memfd/dlopen ở lớp ngoài cùng",
            "8. F06: Xác minh cấu trúc ELF, ABI export & xuất báo cáo",
        ])

        merged_injection = dict(wrap_info)
        if injection:
            merged_injection["inner_protection"] = injection
        if wm_hex:
            merged_injection["watermark_hex"] = wm_hex

        benchmark_summary = evaluate_protection_benchmark(original, after)
        pass_ledger = {
            "active_roadmap_ids": sorted(set(wrapped_ids)),
            "mode": "layered_in_place_plus_e08_wrapper" if injection else "whole_elf_payload_wrapper",
            "execution_order": exec_order,
            "catalog_descriptions": {
                pid: {"kind": ROADMAP_CATALOG[pid][0], "stage": ROADMAP_CATALOG[pid][1], "summary": ROADMAP_CATALOG[pid][2]}
                for pid in sorted(set(wrapped_ids)) if pid in ROADMAP_CATALOG
            },
            "transformed_functions": injection.get("transformed_functions", []),
            "encrypted_strings_count": injection.get("encrypted_strings_count", 0),
            "prologue_guards_count": injection.get("prologue_guards_count", 0),
            "scrubbed_metadata_sections": scrubbed_sections,
            "skipped_targets": injection.get("skipped_targets", []),
            "differential_semantics_F03": semantics_results,
            "benchmark_A04_A05_A06": benchmark_summary,
        }
        report = {
            "schema": 1, "tool": "Protect3", "version": __version__,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "input_name": source.name, "output_name": output.name,
            "input": original.summary(), "output": after.summary(),
            "options": asdict(opt), "features": capabilities(opt),
            "injection": merged_injection, "pass_ledger": pass_ledger,
            "warnings": [
                "Whole-ELF final wrapper (E08) uses memfd_create/dlopen at constructor time over the protected payload ELF.",
                "Exported function names are forwarded via wrapper trampolines; original function VAs differ.",
            ],
            "validation": {
                "elf_structure": "passed", "exported_abi": "forwarded_via_wrapper",
                "original_function_addresses": "wrapped_trampolines", "android_device_load": "not_tested",
            },
        }
        manifest = _publish(protected, report, output, force)
        return {"output": str(output), "report": str(manifest), "details": report}

    after = after_inner
    benchmark_summary = evaluate_protection_benchmark(original, after)

    warnings = [
        "Prototype: structural validation is not an Android device load test.",
        "Runtime checks run at load (and at gated entries when R01/R05 enabled); earlier dependency constructors run before DT_INIT.",
        "Heuristic environment detection can miss indicators or produce false positives.",
    ]
    if opt.encrypt_text or opt.encrypt_function or opt.encrypt_functions or opt.encrypt_rodata or opt.encrypt_strings:
        warnings += [
            "Section/range encryption depends on initializer order, mprotect/cache behavior and Android SELinux policy.",
            "Self-decrypting binaries must retain enough key material on device to recover plaintext when needed.",
        ]
    if opt.deny_attach:
        warnings.append("PR_SET_DUMPABLE=0 changes the entire process and may affect debugging/crash reporting.")
    if not after.summary()["elf_16k_alignment"]:
        warnings.append("Original ELF segments are not all 16 KiB aligned; the tool does not repair their alignment.")

    pass_ledger = {
        "active_roadmap_ids": injection.get("active_roadmap_ids", []),
        "mode": "compressed_in_memory_packer_plus_in_place" if (pack_mode and has_in_place) else ("compressed_in_memory_packer" if pack_mode else "in_place"),
        "execution_order": [
            "1. F01/A03: Khôi phục danh sách hàm & chấm điểm trước strip",
            "2. E06: Xóa metadata / llvm-strip" if (opt.clean_metadata or opt.strip_symbols) else "2. E06: Bỏ qua strip/clean",
            "3. F05: Điều phối thứ tự pass & cấp phát backend không trùng lặp",
            "4. O08/O09 -> O07 -> O01-O06 -> R07 -> E03: Biến đổi hàm & tách chuỗi Vault",
            "5. R07/E03/R09: Cô lập trang 16 KiB & đặt trang mồi Honeypot",
            "6. R01-R06/E07: Chốt baseline SHA-256 & dẫn xuất khóa KDF",
            "7. E01/E02/E04/E05: Mã hóa vùng code/rodata/data, tính HMAC & ký manifest",
            "8. E09 (+O10): Nén DEFLATE + ChaCha20 toàn bộ PT_LOAD/relocs/imports & bảo vệ RELRO/anti-dump" if pack_mode else ("8. compat_layout: Cấy DT_INIT/RELA vào bảng gốc & ký lại manifest" if opt.compat_layout else "8. Layout chuẩn PT_LOAD"),
            "9. IDA Anti-Analysis & F03/A04-A06/F06: Bơm bẫy F5/ẩn segment, kiểm chứng & xuất báo cáo",
        ],
        "catalog_descriptions": {
            pid: {"kind": ROADMAP_CATALOG[pid][0], "stage": ROADMAP_CATALOG[pid][1], "summary": ROADMAP_CATALOG[pid][2]}
            for pid in injection.get("active_roadmap_ids", []) if pid in ROADMAP_CATALOG
        },
        "transformed_functions": injection.get("transformed_functions", []),
        "encrypted_strings_count": injection.get("encrypted_strings_count", 0),
        "prologue_guards_count": injection.get("prologue_guards_count", 0),
        "scrubbed_metadata_sections": scrubbed_sections,
        "skipped_targets": injection.get("skipped_targets", []),
        "differential_semantics_F03": semantics_results,
        "benchmark_A04_A05_A06": benchmark_summary,
    }

    report = {
        "schema": 1, "tool": "Protect3", "version": __version__,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "input_name": source.name, "output_name": output.name,
        "input": original.summary(), "output": after.summary(),
        "options": asdict(opt), "features": capabilities(opt),
        "injection": injection, "pass_ledger": pass_ledger, "warnings": warnings,
        "validation": {
            "elf_structure": "passed", "exported_abi": "preserved",
            "original_function_addresses": "shifted_packed" if pack_mode else "preserved",
            "android_device_load": "not_tested",
        },
    }
    log("ELF structure and exports verified. Saving library and capability report...")
    manifest = _publish(protected, report, output, force)
    return {"output": str(output), "report": str(manifest), "details": report}


def verify_file(path, report_path=None):
    library = Path(path)
    report_path = Path(report_path) if report_path else library.with_name(library.name + ".protect3.json")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if report["schema"] != 1 or report["tool"] != "Protect3":
            raise ProtectionError("Unrecognized Protect3 report format.")
        elf = ELF(read_library(library))
        verify_structure(elf)
        if hashlib.sha256(elf.data).hexdigest() != report["output"]["sha256"]:
            raise ProtectionError("Output SHA-256 does not match the report.")
        wm = report.get("injection", {}).get("watermark_hex")
        wm_verified = None
        if wm:
            wm_verified = bytes.fromhex(wm) in elf.data
            if not wm_verified:
                raise ProtectionError("Embedded build watermark (A08) does not match the report.")
        return {
            "status": "passed",
            "sha256": report["output"]["sha256"],
            "watermark_verified": wm_verified,
            "active_roadmap_ids": report.get("pass_ledger", {}).get("active_roadmap_ids", []),
            "scope": "Local file hash, ELF structure and embedded watermark (if present); report is not a device test.",
        }
    except (OSError, KeyError, json.JSONDecodeError, TypeError) as exc:
        raise ProtectionError(f"Cannot verify library/report: {exc}") from exc
