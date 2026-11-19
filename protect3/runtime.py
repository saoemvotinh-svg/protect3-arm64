"""Build and verify the import-free AArch64 constructor blob."""

import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import struct
import subprocess
import tempfile

from .elf import ELF, ProtectionError

ASSETS = Path(__file__).resolve().parent / "assets"
PROJECT = Path(__file__).resolve().parent.parent

P3_STR_SLOTS = 160
P3_STR_BLOB_CAP = 4608

# Canonical encrypted string table embedded inside p3_str_cfg (0 plaintext guard strings on disk).
GUARD_STRINGS = [
    ("P3S_LOGDW", "/dev/socket/logdw"),
    ("P3S_TAG", "Protect3"),
    ("P3S_FATAL_FMT", "event=fatal code=000\n"),
    ("P3S_TRACERPID", "TracerPid:"),
    ("P3S_FRIDA_AGENT", "frida-agent"),
    ("P3S_FRIDA_GADGET", "frida-gadget"),
    ("P3S_LIBFRIDA", "libfrida"),
    ("P3S_LIBGADGET", "libgadget.so"),
    ("P3S_LIBXPOSED", "libxposed"),
    ("P3S_LIBLSPOSED", "liblsposed"),
    ("P3S_LIBEDXPOSED", "libedxposed"),
    ("P3S_GUM_JS", "gum-js-loop"),
    ("P3S_POOL_FRIDA", "pool-frida"),
    ("P3S_LINJECTOR", "linjector"),
    ("P3S_LIBSUBSTRATE", "libsubstrate"),
    ("P3S_LIBDOBBY", "libdobby"),
    ("P3S_LIBSHADOWHOOK", "libshadowhook"),
    ("P3S_ZYGISK", "zygisk"),
    ("P3S_SLASH_MAGISK", "/magisk/"),
    ("P3S_LIBMAGISK", "libmagisk"),
    ("P3S_KERNELSU", "kernelsu"),
    ("P3S_SLASH_KSU", "/ksu/"),
    ("P3S_APATCH", "apatch"),
    ("P3S_MAGISKD", "magiskd"),
    ("P3S_GOLDFISH", "goldfish"),
    ("P3S_RANCHU", "ranchu"),
    ("P3S_BLUESTACKS", "bluestacks"),
    ("P3S_BSTMODS", "bstmods"),
    ("P3S_LIBNB", "libnb.so"),
    ("P3S_LIBHOUDINI", "libhoudini.so"),
    ("P3S_VBOXGUEST", "vboxguest"),
    ("P3S_PTRACE_STOP", "ptrace_stop"),
    ("P3S_GG_NAME", "gameguardian"),
    ("P3S_CATCH_ME", "catch_.me"),
    ("P3S_GG_DAEMON", "gg_daemon"),
    ("P3S_LIBGG", "libgg"),
    ("P3S_CESERVER", "ceserver"),
    ("P3S_MEMDUMPER", "memdumper"),
    ("P3S_STATE_T", "State:\tt"),
    ("P3S_TRACING_STOP", "tracing stop"),
    ("P3S_FRIDA_PORT", ":69A2"),
    ("P3S_MEMFD_FRIDA", "memfd:frida"),
    ("P3S_BIN_SU", "/system/bin/su"),
    ("P3S_XBIN_SU", "/system/xbin/su"),
    ("P3S_SBIN_SU", "/sbin/su"),
    ("P3S_SBIN_MAGISK", "/sbin/.magisk"),
    ("P3S_ADB_MAGISK", "/data/adb/magisk"),
    ("P3S_ADB_KSU", "/data/adb/ksu"),
    ("P3S_ADB_AP", "/data/adb/ap"),
    ("P3S_SOCK_MAGISKD", "/dev/socket/magiskd"),
    ("P3S_PROC_MOUNTINFO", "/proc/self/mountinfo"),
    ("P3S_DEV_QEMU", "/dev/qemu_pipe"),
    ("P3S_DEV_GOLDFISH", "/dev/goldfish_pipe"),
    ("P3S_SOCK_QEMUD", "/dev/socket/qemud"),
    ("P3S_DEV_BST_GPS", "/dev/bst_gps"),
    ("P3S_DEV_BSTMODS", "/dev/bstmods"),
    ("P3S_DEV_VBOXGUEST", "/dev/vboxguest"),
    ("P3S_LIB_BSTFOLDER", "/system/lib/libbstfolder.so"),
    ("P3S_LIB64_NB", "/system/lib64/libnb.so"),
    ("P3S_PROC_MAPS", "/proc/self/maps"),
    ("P3S_PROC_AUXV", "/proc/self/auxv"),
    ("P3S_PROC_TASK_PFX", "/proc/self/task/"),
    ("P3S_PROC_TASK", "/proc/self/task"),
    ("P3S_PROC_STATUS", "/proc/self/status"),
    ("P3S_PROC_WCHAN", "/proc/self/wchan"),
    ("P3S_PROC_COMM", "/proc/self/comm"),
    ("P3S_PROC_CMDLINE", "/proc/self/cmdline"),
    ("P3S_PROC_ENVIRON", "/proc/self/environ"),
    ("P3S_PROC_CPUINFO", "/proc/cpuinfo"),
    ("P3S_PROC_NET_UNIX", "/proc/net/unix"),
    ("P3S_PROC_NET_TCP", "/proc/net/tcp"),
    ("P3S_PROC_NET_TCP6", "/proc/net/tcp6"),
    ("P3S_TMP_GG_DAEMON", "/data/local/tmp/gg_daemon"),
    ("P3S_TMP_LIBGG", "/data/local/tmp/libgg.so"),
    ("P3S_TMP_CESERVER", "/data/local/tmp/ceserver"),
    ("P3S_LEAF_STATUS", "status"),
    ("P3S_LEAF_WCHAN", "wchan"),
    ("P3S_LEAF_COMM", "comm"),
    ("P3S_LIBDL_SO", "/libdl.so"),
    ("P3S_SYM_DLSYM", "dlsym"),
    ("P3S_SYM_DLOPEN", "dlopen"),
    ("P3S_EV_RODATA_MAC", "event=rodata_mac_ok\n"),
    ("P3S_EV_TEXT_MAC", "event=text_mac_ok\n"),
    ("P3S_EV_DATA_MAC", "event=data_mac_ok\n"),
    ("P3S_EV_MANIFEST_MAC", "event=manifest_mac_ok\n"),
    ("P3S_EV_SELF_CHK", "event=guard_self_check_ok\n"),
    ("P3S_EV_PROLOGUE_CHK", "event=prologue_check_ok\n"),
    ("P3S_EV_GOT_CHK", "event=got_check_ok\n"),
    ("P3S_EV_RELRO_CHK", "event=relro_check_ok\n"),
    ("P3S_EV_VAULT_WIPED", "event=string_vault_wiped\n"),
    ("P3S_EV_HONEYPOT_OK", "event=honeypot_canary_ok\n"),
    ("P3S_EV_ANTI_GG_OK", "event=anti_gg_ok\n"),
    ("P3S_EV_RT_GATE_OK", "event=runtime_gate_ok\n"),
    ("P3S_EV_STR_DEC_OK", "event=string_decrypt_ok\n"),
    ("P3S_EV_OD_DEC_OK", "event=on_demand_decrypt_ok\n"),
    ("P3S_EV_OD_REENC_OK", "event=on_demand_reencrypt_ok\n"),
    ("P3S_EV_VM_OK", "event=vm_exec_ok\n"),
    ("P3S_EV_GUARD_START", "event=guard_start version=2\n"),
    ("P3S_EV_TEXT_DEC_BEG", "event=text_decrypt_begin\n"),
    ("P3S_EV_TEXT_DEC_OK", "event=text_decrypt_ok\n"),
    ("P3S_EV_RO_DEC_BEG", "event=rodata_decrypt_begin\n"),
    ("P3S_EV_RO_DEC_OK", "event=rodata_decrypt_ok\n"),
    ("P3S_EV_DATA_DEC_OK", "event=data_decrypt_ok\n"),
    ("P3S_EV_MULTI_OK", "event=multi_range_decrypt_ok\n"),
    ("P3S_EV_INT_DONE", "event=integrity_stage_complete\n"),
    ("P3S_EV_INIT_BEG", "event=original_initializer_begin\n"),
    ("P3S_EV_INIT_RET", "event=original_initializer_returned\n"),
    ("P3S_EV_GUARD_RET", "event=guard_return\n"),
    ("P3S_EV_PACK_OK", "event=pack_unpack_ok\n"),
    ("P3S_CHK_DBG_DET", "check=debugger status=detected\n"),
    ("P3S_CHK_DBG_UNAV", "check=debugger status=unavailable\n"),
    ("P3S_CHK_DBG_NO", "check=debugger status=not_observed\n"),
    ("P3S_CHK_DBG_DIS", "check=debugger status=disabled\n"),
    ("P3S_CHK_HK_DET", "check=hooks status=detected\n"),
    ("P3S_CHK_HK_UNAV", "check=hooks status=unavailable\n"),
    ("P3S_CHK_HK_NO", "check=hooks status=not_observed\n"),
    ("P3S_CHK_HK_DIS", "check=hooks status=disabled\n"),
    ("P3S_CHK_RT_DET", "check=root status=detected\n"),
    ("P3S_CHK_RT_UNAV", "check=root status=unavailable\n"),
    ("P3S_CHK_RT_NO", "check=root status=not_observed\n"),
    ("P3S_CHK_RT_DIS", "check=root status=disabled\n"),
    ("P3S_CHK_EM_DET", "check=emulator status=detected\n"),
    ("P3S_CHK_EM_UNAV", "check=emulator status=unavailable\n"),
    ("P3S_CHK_EM_NO", "check=emulator status=not_observed\n"),
    ("P3S_CHK_EM_DIS", "check=emulator status=disabled\n"),
    ("P3S_ERR_CIPHER_MAC", "Protect3: ciphertext authentication tag mismatch.\n"),
    ("P3S_ERR_PAGE_SZ", "Protect3: cannot determine page size.\n"),
    ("P3S_ERR_ENC_RANGE", "Protect3: invalid encrypted range.\n"),
    ("P3S_ERR_MPROT_RW", "Protect3: mprotect RW denied.\n"),
    ("P3S_ERR_MPROT_REST", "Protect3: restoring memory permissions denied.\n"),
    ("P3S_ERR_MANIFEST_MAC", "Protect3: signed manifest verification failed.\n"),
    ("P3S_ERR_SELF_RNG", "Protect3: invalid guard self-check range.\n"),
    ("P3S_ERR_SELF_MIS", "Protect3: guard self-integrity mismatch.\n"),
    ("P3S_ERR_PROL_CNT", "Protect3: invalid prologue guard count.\n"),
    ("P3S_ERR_PROL_SZ", "Protect3: invalid prologue size.\n"),
    ("P3S_ERR_PROL_HOOK", "Protect3: function prologue/trampoline hook detected.\n"),
    ("P3S_ERR_GOT_OOB", "Protect3: GOT entry points to non-code module region.\n"),
    ("P3S_ERR_RELRO_SZ", "Protect3: invalid RELRO check size.\n"),
    ("P3S_ERR_RELRO_MIS", "Protect3: RELRO pointer table integrity mismatch.\n"),
    ("P3S_ERR_EPH_RW", "Protect3: ephemeral vault mprotect RW denied.\n"),
    ("P3S_ERR_EPH_REST", "Protect3: ephemeral vault mprotect restore denied.\n"),
    ("P3S_ERR_HP_CNT", "Protect3: invalid range count for honeypot.\n"),
    ("P3S_ERR_HP_SZ", "Protect3: invalid honeypot size.\n"),
    ("P3S_ERR_HP_TAMPER", "Protect3: honeypot memory tamper detected.\n"),
    ("P3S_ERR_HP_PAGE", "Protect3: cannot determine page size for honeypot.\n"),
    ("P3S_ERR_HP_RW", "Protect3: honeypot mprotect RW denied.\n"),
    ("P3S_ERR_TRACE_PAUSE", "Protect3: process trace pause detected.\n"),
    ("P3S_ERR_EXT_TRACER", "Protect3: external tracer attached to thread.\n"),
    ("P3S_ERR_PTRACE_STOP", "Protect3: thread stopped by ptrace.\n"),
    ("P3S_ERR_SCANNER_THRD", "Protect3: scanner thread detected.\n"),
    ("P3S_ERR_SCANNER_IND", "Protect3: memory scanner indicator detected.\n"),
    ("P3S_ERR_FREEZE_PAUSE", "Protect3: abnormal freeze pause (memory scanner) detected.\n"),
    ("P3S_ERR_XCALL_PAUSE", "Protect3: cross-call freeze pause detected.\n"),
    ("P3S_ERR_GATE_STATE", "Protect3: invalid guard state at runtime gate.\n"),
    ("P3S_ERR_DBG_GATE", "Protect3: debugger detected at runtime gate.\n"),
    ("P3S_ERR_RT_CODE_MIS", "Protect3: runtime code integrity mismatch.\n"),
    ("P3S_ERR_VAULT_REF", "Protect3: invalid string vault reference.\n"),
    ("P3S_ERR_VAULT_OOB", "Protect3: out-of-bounds string vault entry.\n"),
    ("P3S_ERR_VAULT_HDR", "Protect3: corrupted string vault header.\n"),
    ("P3S_ERR_VAULT_RW", "Protect3: string vault mprotect RW denied.\n"),
    ("P3S_ERR_VAULT_MIS", "Protect3: lazy string integrity mismatch.\n"),
    ("P3S_ERR_VAULT_REST", "Protect3: string vault mprotect restore denied.\n"),
    ("P3S_ERR_OD_IDX", "Protect3: invalid on-demand range index.\n"),
    ("P3S_ERR_OD_CFG", "Protect3: range is not configured for on-demand toggling.\n"),
    ("P3S_ERR_OD_MIS", "Protect3: on-demand plaintext integrity mismatch.\n"),
    ("P3S_ERR_VM_IDX", "Protect3: invalid VM program index.\n"),
    ("P3S_ERR_VM_DESC", "Protect3: invalid VM bytecode descriptor.\n"),
    ("P3S_ERR_VM_MIS", "Protect3: VM bytecode integrity mismatch.\n"),
    ("P3S_ERR_VM_STEPS", "Protect3: VM step limit exceeded.\n"),
    ("P3S_ERR_VM_BR", "Protect3: VM branch out of bounds.\n"),
    ("P3S_ERR_VM_CBR", "Protect3: VM cond branch out of bounds.\n"),
    ("P3S_ERR_VM_CBZ", "Protect3: VM CBZ out of bounds.\n"),
    ("P3S_ERR_VM_TBZ", "Protect3: VM TBZ out of bounds.\n"),
    ("P3S_ERR_VM_OP", "Protect3: unknown VM opcode.\n"),
    ("P3S_ERR_CFG_INV", "Protect3: invalid guard configuration.\n"),
    ("P3S_ERR_DBG_LOAD", "Protect3: debugger detected at load.\n"),
    ("P3S_ERR_DBG_UNAV", "Protect3: debugger check unavailable.\n"),
    ("P3S_ERR_HOOKS_LOAD", "Protect3: instrumentation indicator detected.\n"),
    ("P3S_ERR_MAPS_UNAV", "Protect3: maps check unavailable.\n"),
    ("P3S_ERR_ROOT_LOAD", "Protect3: root/zygisk indicator detected.\n"),
    ("P3S_ERR_ROOT_UNAV", "Protect3: root maps check unavailable.\n"),
    ("P3S_ERR_EMU_LOAD", "Protect3: emulator indicator detected.\n"),
    ("P3S_ERR_CPU_UNAV", "Protect3: CPU check unavailable.\n"),
    ("P3S_ERR_DUMPABLE", "Protect3: PR_SET_DUMPABLE failed.\n"),
    ("P3S_ERR_RO_PROT", "Protect3: invalid rodata permissions.\n"),
    ("P3S_ERR_RO_MIS", "Protect3: rodata integrity mismatch.\n"),
    ("P3S_ERR_DATA_MIS", "Protect3: data integrity mismatch.\n"),
    ("P3S_ERR_MULTI_CNT", "Protect3: invalid multi-range count.\n"),
    ("P3S_ERR_RNG_MIS", "Protect3: encrypted range integrity mismatch.\n"),
    ("P3S_ERR_CODE_MIS", "Protect3: code integrity mismatch.\n"),
    ("P3S_ERR_PACK_MAC", "Protect3: packed payload verification failed.\n"),
    ("P3S_ERR_PACK_DEC", "Protect3: packed payload decompression failed.\n"),
    ("P3S_ERR_PACK_SYM", "Protect3: runtime symbol resolution failed.\n"),
]
# Keep slot count comfortably above len(GUARD_STRINGS)
P3_STR_SLOTS = 200
P3_STR_BLOB_CAP = 5120
assert len(GUARD_STRINGS) <= P3_STR_SLOTS


def _encode_guard_strings_payload(key16):
    """Encode all GUARD_STRINGS with `key16` into (offsets_bytes, lengths_bytes, blob_bytes)."""
    k0, = struct.unpack_from("<I", key16, 0)
    offsets = []
    lengths = []
    blob = bytearray()
    for sid, (_, text) in enumerate(GUARD_STRINGS):
        raw = text.encode("utf-8")
        if len(raw) > 255:
            raise ProtectionError(f"Guard string {sid} exceeds 255 bytes.")
        off = len(blob)
        if off + len(raw) > P3_STR_BLOB_CAP:
            raise ProtectionError("Guard string blob capacity exceeded.")
        for i, b in enumerate(raw):
            kb = key16[(i + sid) & 15] ^ (((k0 >> ((i & 3) * 8)) + i * 0x5D + sid * 17) & 0xFF)
            blob.append(b ^ kb)
        offsets.append(off)
        lengths.append(len(raw))
    while len(offsets) < P3_STR_SLOTS:
        offsets.append(0)
        lengths.append(0)
    blob.extend(bytes(P3_STR_BLOB_CAP - len(blob)))
    return offsets, lengths, bytes(blob)


def rekey_guard_strings(blob_ba, str_cfg_off, seed):
    """Re-encrypt `p3_str_cfg` inside a mutable `guard.bin` copy using a per-build seed."""
    key16 = hashlib.sha256(f"p3-str-key-{seed:#x}".encode("utf-8")).digest()[:16]
    offsets, lengths, enc_blob = _encode_guard_strings_payload(key16)
    struct.pack_into(f"<16s{P3_STR_SLOTS}H{P3_STR_SLOTS}B{P3_STR_BLOB_CAP}s",
                     blob_ba, str_cfg_off, key16, *offsets, *lengths, enc_blob)


def sync_guard_strings_header():
    """Generate `native/guard_strings.h` with compile-time encrypted literals if needed."""
    native = PROJECT / "native"
    header = native / "guard_strings.h"
    default_key = hashlib.sha256(b"protect3-compile-default-str-key").digest()[:16]
    offsets, lengths, enc_blob = _encode_guard_strings_payload(default_key)
    lines = [
        "/* Auto-generated encrypted guard string table; zero plaintext strings stored in .rodata. */",
        "#ifndef PROTECT3_GUARD_STRINGS_H",
        "#define PROTECT3_GUARD_STRINGS_H",
        f"#define P3_STR_SLOTS {P3_STR_SLOTS}u",
        f"#define P3_STR_BLOB_CAP {P3_STR_BLOB_CAP}u",
        "enum p3_str_id {",
    ]
    for sid, (name, _) in enumerate(GUARD_STRINGS):
        lines.append(f"    {name} = {sid},")
    lines.extend([
        "};",
        "struct p3_str_table {",
        "    u8 key[16];",
        f"    u16 offsets[{P3_STR_SLOTS}];",
        f"    u8 lengths[{P3_STR_SLOTS}];",
        f"    u8 blob[{P3_STR_BLOB_CAP}];",
        "};",
        f"_Static_assert(sizeof(struct p3_str_table) == {16 + 2 * P3_STR_SLOTS + P3_STR_SLOTS + P3_STR_BLOB_CAP}, \"str_table size mismatch\");",
        "",
        '#define P3_STR_TABLE_INIT { \\',
        "    .key = {" + ",".join(str(b) for b in default_key) + "}, \\",
        "    .offsets = {" + ",".join(str(x) for x in offsets) + "}, \\",
        "    .lengths = {" + ",".join(str(x) for x in lengths) + "}, \\",
        "    .blob = {" + ",".join(str(b) for b in enc_blob) + "}, \\",
        "}",
        "#endif",
        "",
    ])
    content = "\n".join(lines)
    if not header.is_file() or header.read_text(encoding="utf-8") != content:
        header.write_text(content, encoding="utf-8")


def ndk_bin(ndk=None):
    root = ndk or os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    if not root:
        sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        if sdk and (Path(sdk) / "ndk").is_dir():
            versions = sorted((Path(sdk) / "ndk").iterdir(), reverse=True)
            root = str(versions[0]) if versions else None
    if not root:
        for candidate_dir in (Path("D:/Android/ndk"), Path("C:/Android/ndk")):
            if candidate_dir.is_dir():
                versions = sorted(candidate_dir.iterdir(), reverse=True)
                if versions:
                    root = str(versions[0])
                    break
    if not root:
        raise ProtectionError("Set ANDROID_NDK_HOME, or pass --ndk <NDK directory>.")
    host = {"Windows": "windows-x86_64", "Linux": "linux-x86_64", "Darwin": "darwin-x86_64"}.get(platform.system())
    directory = Path(root) / "toolchains" / "llvm" / "prebuilt" / str(host) / "bin"
    if not directory.is_dir():
        raise ProtectionError(f"NDK LLVM directory not found: {directory}")
    return directory


def ndk_tool(name, ndk=None):
    executable = ndk_bin(ndk) / (name + (".exe" if os.name == "nt" else ""))
    if not executable.is_file():
        raise ProtectionError(f"NDK tool not found: {executable}")
    return str(executable)


def command(arguments, timeout=120):
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout,
                                creationflags=flags, encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProtectionError(f"Tool execution failed: {exc}") from exc
    if result.returncode:
        raise ProtectionError((result.stderr or result.stdout or "NDK tool failed.").strip())
    return result.stdout


def source_digest():
    files = [PROJECT / "native" / f for f in ("guard.c", "crypto.c", "crypto.h", "guard.ld")]
    if not all(p.is_file() for p in files):
        return None
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    digest.update(json.dumps(GUARD_STRINGS).encode("utf-8"))
    return digest.hexdigest()


def _extract_guard_obf_candidates(elf, symbols):
    """Collect `$d`-free C helper functions in guard.elf safe for polymorphic ARM64 relocation."""
    syms = elf.symbols(False)
    data_marks = sorted(s["value"] for s in syms if s["name"] in ("$d", "$d.0") or s["name"].startswith("$d."))
    cfg_end = symbols.get("p3_config", len(elf.data))
    bridges = {"p3_vm_call_trampoline", "p3_vm_bridge", "p3_gate_bridge"}
    # Keep high-throughput leaf crypto loops un-expanded at boot; obfuscate logic/check/VM/unpack functions
    skip = bridges | {
        "sha_block", "p3_sha256_update", "p3_sha256_final", "p3_chacha20_block",
        "p3_chacha20", "memcpy", "memset", "p3_inflate_stream",
    }
    candidates = []
    for s in syms:
        if not s["shndx"] or not s["name"] or (s["info"] & 0xF) != 2:
            continue
        va, sz = s["value"], s["size"]
        if sz < 16 or sz % 4 != 0 or va >= cfg_end or va + sz > cfg_end:
            continue
        if s["name"] in skip or s["name"].startswith(("$", "OUTLINED_FUNCTION_")):
            continue
        if any(va <= dm < va + sz for dm in data_marks):
            continue
        candidates.append({"name": s["name"], "vaddr": va, "size": sz})
    candidates.sort(key=lambda c: c["vaddr"])
    return candidates


def build_runtime(ndk=None):
    native = PROJECT / "native"
    if source_digest() is None:
        raise ProtectionError("Native sources are unavailable; rebuild from the source distribution.")
    sync_guard_strings_header()
    with tempfile.TemporaryDirectory(prefix="protect3-build-") as temporary:
        target = Path(temporary) / "guard.elf"
        command([
            ndk_tool("clang", ndk), "--target=aarch64-linux-android23", "-Os", "-std=c11",
            "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables", "-fno-jump-tables", "-fno-addrsig",
            "-mno-outline-atomics", "-mllvm", "-enable-machine-outliner=never", "-fpie",
            "-fvisibility=hidden", "-mgeneral-regs-only", "-mbranch-protection=bti",
            "-Wall", "-Wextra", "-Werror", "-nostdlib", "-static",
            "-Wl,--build-id=none", "-Wl,--no-undefined", "-Wl,--no-relax",
            "-Wl,-T," + str(native / "guard.ld"),
            str(native / "guard.c"), str(native / "crypto.c"), "-o", str(target),
        ])
        elf = ELF(target.read_bytes())
        loads = [s for s in elf.loads if s.filesz]
        if (len(loads) != 1 or loads[0].vaddr != 0 or loads[0].flags != 5
                or loads[0].filesz != loads[0].memsz or elf.dynamic):
            raise ProtectionError("Runtime must be one RX segment at VA 0, with no BSS/dynamic table.")
        if any(s.type in (4, 9) and s.size for s in elf.sections):
            raise ProtectionError("Runtime contains unresolved relocations.")
        symbols = {s["name"]: s["value"] for s in elf.symbols(False) if s["shndx"] and s["name"]}
        for name in ("p3_entry", "p3_pack_entry", "p3_config", "p3_ext", "p3_str_cfg", "p3_data_enc",
                     "p3_pack", "p3_sha256", "p3_hmac_sha256", "p3_chacha20", "p3_chacha20_block",
                     "p3_vm_exec", "p3_vm_bridge", "p3_gate_bridge", "p3_resolve_string",
                     "p3_on_demand_toggle", "p3_inflate_mem"):
            if name not in symbols:
                raise ProtectionError(f"Missing runtime symbol: {name}")
        guard_obf = _extract_guard_obf_candidates(elf, symbols)
        blob = elf.data[loads[0].offset:loads[0].offset + loads[0].filesz]
        meta = {"version": 1, "sha256": hashlib.sha256(blob).hexdigest(),
                "source_sha256": source_digest(), "size": len(blob), "symbols": symbols,
                "guard_obf_candidates": guard_obf,
                "compiler": command([ndk_tool("clang", ndk), "--version"]).splitlines()[0]}
    ASSETS.mkdir(parents=True, exist_ok=True)
    (ASSETS / "guard.bin").write_bytes(blob)
    (ASSETS / "guard.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return blob, meta


def load_runtime(ndk=None):
    binary, metadata = ASSETS / "guard.bin", ASSETS / "guard.json"
    if not binary.is_file() or not metadata.is_file():
        return build_runtime(ndk)
    try:
        blob = binary.read_bytes()
        meta = json.loads(metadata.read_text(encoding="utf-8"))
        if (meta["version"] != 1 or meta["size"] != len(blob)
                or meta["sha256"] != hashlib.sha256(blob).hexdigest()):
            raise ProtectionError("Runtime asset checksum/format mismatch; rebuild-runtime first.")
        digest = source_digest()
        if digest and digest != meta.get("source_sha256"):
            return build_runtime(ndk)
        return blob, meta
    except (OSError, KeyError, ValueError) as exc:
        raise ProtectionError(f"Cannot load verified runtime assets: {exc}") from exc
