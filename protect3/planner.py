"""Unified pass planner (F05), evidence ledger (F06), scorer (A03) and benchmark suite (A04-A06, A09)."""

from bisect import bisect_right
from dataclasses import dataclass, field, replace
import hashlib
import struct

from .arm64 import decode_insn, discover_functions, find_rodata_string_refs
from .elf import ELF, ProtectionError


ROADMAP_CATALOG = {
    "F01": ("selector", 1, "Function boundary & code/data partitioning (.dynsym, .symtab, .eh_frame FDEs, user map)"),
    "F02": ("transform", 3, "ARM64 PC-relative instruction relocator and branch range expander"),
    "F03": ("verifier", 9, "Differential execution & instruction semantics verification"),
    "F04": ("verifier", 9, "Lifecycle, page-size (4K/16K), multi-launch & native-bridge stability matrix"),
    "F05": ("policy", 2, "Unified pass planner, conflict checker, profile expander & page coordinator"),
    "F06": ("verifier", 9, "Per-artifact pass evidence ledger, byte ranges, skip reasons & verification status"),
    "E01": ("selector", 7, "Multi-function / multi-range ChaCha20 code encryption with early-init exclusion"),
    "E02": ("selector", 7, "Multi-range read-only data encryption with relocation/metadata exclusion"),
    "E03": ("transform", 3, "Per-reference lazy string encryption in page-isolated String Vault"),
    "E04": ("verifier", 7, "Authenticated encryption (pre-decryption HMAC-SHA256 over ciphertext + context)"),
    "E05": ("verifier", 8, "Signed/authenticated protection manifest verified in native guard"),
    "E06": ("transform", 4, "Non-essential ELF metadata cleanup (.comment/debug) & optional debug export"),
    "E07": ("generator", 4, "Masked split-key KDF derivation and stack key zeroization"),
    "E08": ("generator", 4, "Whole-ELF encrypted payload wrapper .so with memfd/dlopen symbol forwarding"),
    "E09": ("generator", 8, "In-memory DEFLATE+ChaCha20 ELF segment/reloc/import packer & direct-syscall relocator"),
    "O01": ("transform", 3, "ARM64 instruction substitution and MBA arithmetic/logical equivalences"),
    "O02": ("transform", 3, "Opaque constants and XOR-masked register immediate synthesis"),
    "O03": ("transform", 3, "Algebraic invariant opaque predicates on live input registers"),
    "O04": ("transform", 3, "Call and branch indirection with BTI-compatible landing pads"),
    "O05": ("transform", 3, "Function splitting / block outlining into non-contiguous guard fragments"),
    "O06": ("transform", 3, "Basic-block shuffling and PC-relative trampoline relocation"),
    "O07": ("transform", 3, "Control-flow flattening with encoded state-machine dispatcher"),
    "O08": ("generator", 3, "ARM64 function virtualization to stack-isolated bytecode VM"),
    "O09": ("generator", 3, "Per-build polymorphic VM opcode permutation & per-function bytecode stream encryption"),
    "O10": ("transform", 8, "Per-build polymorphic guard runtime self-obfuscation with dead <unknown> islands"),
    "R01": ("verifier", 6, "Post-load runtime memory integrity verification at function entry gates"),
    "R02": ("verifier", 6, "Function prologue & trampoline byte verification against inline hooks"),
    "R03": ("verifier", 6, "Post-relocation GOT/PLT target range verification"),
    "R04": ("verifier", 6, "Internal pointer table (.data.rel.ro) SHA-256 provenance check"),
    "R05": ("policy", 6, "Multi-point load + runtime anti-debugging (TracerPid, wchan, dumpable)"),
    "R06": ("verifier", 6, "Cross-checked native guard code & config self-integrity verification"),
    "R07": ("transform", 4, "On-demand function decryption and post-return re-encryption on isolated pages"),
    "R08": ("policy", 6, "Multi-signal environment indicators (Frida/Xposed/Zygisk/Root/BlueStacks)"),
    "R09": ("policy", 6, "Anti-GameGuardian memory honeypot canary, freeze-pause timing watchdog & ephemeral String Vault"),
    "A01": ("generator", 2, "Per-build structural diversification seed (separated from cryptographic keys)"),
    "A02": ("policy", 2, "Semantic-reduction composite profile (strings + constants + CFG + VM)"),
    "A03": ("selector", 2, "Automated function sensitivity & cost scorer feeding planner F05"),
    "A04": ("metric", 9, "Automated static/symbolic analysis & recovery benchmark"),
    "A05": ("metric", 9, "Cross-version disassembly / CFG / n-gram similarity metrics"),
    "A06": ("metric", 9, "Algebraic simplifier & constant-folding resistance evaluator"),
    "A07": ("transform", 3, "Inter-block / inter-fragment state token threading"),
    "A08": ("generator", 2, "Offline structural build watermark / fingerprint bound into manifest"),
    "A09": ("policy", 2, "Benchmark feedback loop generating pass recommendations for subsequent builds"),
}


@dataclass
class PlannedFunctionAction:
    name: str
    vaddr: int
    size: int
    backend: str  # "vm" (O08/O09), "flatten" (O07), "obfuscate" (O01-O06), "on_demand" (R07), "encrypt_only" (E01)
    passes: list[str] = field(default_factory=list)
    runtime_gate: bool = False
    sensitivity_score: int = 0
    cost_score: int = 0


@dataclass
class ProtectionPlan:
    profile: str
    build_seed: int
    watermark_hex: str
    active_ids: list[str]
    function_actions: list[PlannedFunctionAction]
    encrypted_code_ranges: list[dict]
    encrypted_rodata_ranges: list[dict]
    string_refs: list[dict]
    prologue_checks: list[dict]
    skipped_items: list[dict]
    warnings: list[str]


def apply_profile_defaults(options):
    """Expand --profile preset (A02/F05) without overriding explicit conflict rules."""
    profile = (options.profile or "").strip().lower()
    if not profile:
        return options
    if profile == "compat":
        return replace(
            options,
            compat_layout=True,
            auth_encryption=True,
            masked_key=True,
            sign_manifest=True,
        )
    if profile == "balanced":
        return replace(
            options,
            auth_encryption=True,
            masked_key=True,
            sign_manifest=True,
            guard_self_check=True,
            prologue_check=True,
            relro_check=True,
            obfuscate_ops=True,
            auto_select_functions=True,
        )
    if profile in ("anti-analysis", "max"):
        return replace(
            options,
            auth_encryption=True,
            masked_key=True,
            sign_manifest=True,
            clean_metadata=True,
            guard_self_check=True,
            prologue_check=True,
            got_check=True,
            relro_check=True,
            runtime_integrity=True,
            runtime_anti_debug=True,
            obfuscate_ops=True,
            obfuscate_guard=True,
            encrypt_data=True,
            flatten_cfg=True,
            encrypt_strings=True,
            auto_select_functions=True,
            virtualize_auto=(profile == "max"),
            pack_elf=(True if (profile == "max" and not options.wrap_elf) else options.pack_elf),
            gg_honeypot=True,
            anti_gg=True,
        )
    raise ProtectionError(f"Unknown protection profile: {options.profile}")


def _parse_csv(text):
    if not text:
        return []
    return [item.strip() for item in text.split(",") if item.strip()]


IN_PLACE_PASS_OPTIONS = (
    "encrypt_text",
    "encrypt_function",
    "encrypt_functions",
    "encrypt_rodata",
    "encrypt_data",
    "encrypt_strings",
    "ephemeral_strings",
    "obfuscate_ops",
    "obfuscate_guard",
    "flatten_cfg",
    "virtualize_auto",
    "virtualize_functions",
    "flatten_functions",
    "obfuscate_functions",
    "on_demand_functions",
    "auto_select_functions",
    "obfuscate_jni",
    "compat_layout",
    "runtime_integrity",
    "prologue_check",
    "got_check",
    "relro_check",
    "guard_self_check",
    "runtime_anti_debug",
    "gg_honeypot",
    "anti_gg",
    "troll_ida",
    "block_ida",
    "auth_encryption",
    "sign_manifest",
    "masked_key",
    "hooks",
    "root",
    "emulator",
    "deny_attach",
    "deep_probes",
)
IN_PLACE_CONFLICT_OPTIONS = IN_PLACE_PASS_OPTIONS


def _active_in_place_options(opt):
    return [key for key in IN_PLACE_PASS_OPTIONS if bool(getattr(opt, key, False))]


def resolve_outer_packing_modes(elf, opt):
    """Resolve effective (pack_mode, wrap_mode), preferring E09 if target exports non-func symbols."""
    exports = elf.exported_symbols()
    obj_exports = [n for n, info, _, _, _ in exports if (info & 0xF) == 1]
    fn_exports = [n for n, info, _, _, _ in exports if (info & 0xF) == 2 and n]
    wrap_mode = bool(opt.wrap_elf)
    if getattr(opt, "pack_elf", False) and wrap_mode and (obj_exports or not fn_exports):
        wrap_mode = False
    pack_mode = bool(getattr(opt, "pack_elf", False) and not wrap_mode)
    return pack_mode, wrap_mode, obj_exports, fn_exports


def build_protection_plan(elf, options, pre_strip_functions=None):
    """Validate options, resolve function targets before strip, and build a conflict-free F05 plan."""
    opt = apply_profile_defaults(options)
    pack_mode, wrap_mode, obj_exports, fn_exports = resolve_outer_packing_modes(elf, opt)
    # 1. E08 (--wrap-elf) runs LAST after all in-place passes cleanly; check only E08 export constraints here
    if wrap_mode:
        if obj_exports:
            raise ProtectionError(
                f"Whole-ELF wrapper (E08) refuses libraries with exported data objects ({obj_exports[:3]}). "
                "Hãy tắt E08 (wrap_elf) và bật E09 (--pack-elf) để đóng gói C++/.so có STT_OBJECT."
            )
        if not fn_exports:
            raise ProtectionError(
                "Whole-ELF wrapper (E08) requires at least one exported STT_FUNC function symbol. "
                "Hãy tắt E08 (wrap_elf) và bật E09 (--pack-elf) thay thế."
            )

    if opt.encrypt_text and (opt.encrypt_function or opt.encrypt_functions):
        raise ProtectionError("Choose either --encrypt-text or function-scoped code encryption, not both.")
    if opt.ephemeral_strings and not opt.encrypt_strings:
        raise ProtectionError(
            "Conflict (E03+ vs E03): --ephemeral-strings requires --encrypt-strings (String Vault) to be enabled."
        )
    # Note: E02 (--encrypt-rodata) and E03 (--encrypt-strings) CAN coexist in parallel!
    # Stage 3 (E03) moves referenced strings out of .rodata into the isolated String Vault in .guard
    # and zeroes their original bytes in .rodata; Stage 7 (E02) then encrypts the remaining .rodata
    # constants/tables on disk without double-encrypting the vault strings.

    functions = pre_strip_functions if pre_strip_functions is not None else discover_functions(elf)
    by_name = {}
    for fn in functions:
        by_name.setdefault(fn.name, []).append(fn)
    by_va = {fn.vaddr: fn for fn in functions}

    denylist = set(_parse_csv(opt.denylist_functions))
    skipped = []
    warnings = []

    def resolve_named_list(names, label, require_unambiguous=True):
        resolved = []
        for name in names:
            if name in denylist:
                skipped.append({"target": name, "stage": label, "reason": "denylisted_by_user"})
                continue
            matches = by_name.get(name, [])
            if not matches and name.startswith("0x"):
                try:
                    va = int(name, 16)
                    if va in by_va:
                        matches = [by_va[va]]
                except ValueError:
                    pass
            if len(matches) != 1:
                if require_unambiguous:
                    raise ProtectionError(
                        f"{label} requires one unambiguous STT_FUNC/FDE target for '{name}'; "
                        f"found {len(matches)} matches."
                    )
                skipped.append({"target": name, "stage": label, "reason": "ambiguous_or_missing_symbol"})
                continue
            resolved.append(matches[0])
        return resolved

    vm_targets = resolve_named_list(_parse_csv(opt.virtualize_functions), "O08 virtualization")
    flatten_targets = resolve_named_list(_parse_csv(opt.flatten_functions), "O07 flattening")
    obf_targets = resolve_named_list(_parse_csv(opt.obfuscate_functions), "O01-O06 obfuscation")
    ondemand_targets = resolve_named_list(_parse_csv(opt.on_demand_functions), "R07 on-demand")
    enc_fn_names = ([opt.encrypt_function] if opt.encrypt_function else []) + _parse_csv(opt.encrypt_functions)
    enc_fn_targets = resolve_named_list(enc_fn_names, "E01 function encryption")

    # JNI obfuscation selector (--obfuscate-jni); adapts cleanly around explicit VM/Flatten/On-Demand assignments
    if opt.obfuscate_jni:
        jni_funcs = [f for f in functions if f.is_jni and f.name not in denylist]
        for jf in jni_funcs:
            if jf not in vm_targets and jf not in flatten_targets and jf not in obf_targets and jf not in ondemand_targets:
                if jf.relocatable:
                    obf_targets.append(jf)
                else:
                    skipped.append({"target": jf.name, "stage": "JNI obfuscation", "reason": ",".join(jf.skip_reasons) or "not_relocatable"})

    # Auto-selection by A03 sensitivity/cost scorer when enabled by profile or --auto-select
    cached_string_refs = find_rodata_string_refs(elf, functions) if opt.encrypt_strings else []
    string_ref_func_vas = set()
    if cached_string_refs and functions:
        fn_spans = sorted((fn.vaddr, fn.vaddr + fn.size) for fn in functions)
        fn_starts = [va for va, _ in fn_spans]
        for r in cached_string_refs:
            cs = r["callsite_vaddr"]
            pos = bisect_right(fn_starts, cs) - 1
            if pos >= 0 and cs < fn_spans[pos][1]:
                string_ref_func_vas.add(fn_spans[pos][0])

    crt_boilerplate = {
        "original_init", "sample_constructor", "__on_dlclose", "__on_dlclose_late",
        "__emutls_unregister_key", "__emutls_get_address", "__cxa_finalize",
        "__cxa_atexit", "register_tm_clones", "deregister_tm_clones", "frame_dummy",
        "__do_global_dtors_aux", "__do_global_ctors_aux", "call_weak_fn", "atexit",
        "pthread_atfork",
    }
    if opt.auto_select_functions or opt.obfuscate_ops or opt.flatten_cfg or opt.virtualize_auto:
        all_candidates = [
            f for f in functions
            if f.relocatable and not f.is_early_init and f.name not in denylist
            and f.vaddr not in string_ref_func_vas
            and f.name not in crt_boilerplate
            and not f.name.startswith("__aeabi_")
            and f.vaddr not in {t.vaddr for t in vm_targets + flatten_targets + obf_targets + ondemand_targets}
        ]
        substantive = [
            f for f in all_candidates
            if f.source != "eh_frame_fde" or f.is_exported or f.insn_count >= 10
        ]
        candidates = substantive if substantive else all_candidates
        candidates.sort(key=lambda f: (
            -int(f.is_jni),
            -f.sensitivity_score,
            -min(f.insn_count, 96) if (f.source == "eh_frame_fde" and not f.is_exported) else f.cost_score,
            f.cost_score,
            f.vaddr,
        ))
        large_binary = len(functions) >= 50
        boosted = bool(opt.profile == "max" or opt.pack_elf)
        vm_cap = (24 if boosted else 8) if large_binary else 2
        flat_cap = (12 if boosted else 8) if large_binary else 3
        obf_cap = (16 if boosted else 12) if large_binary else 4
        scan_cap = max(12, vm_cap + flat_cap + obf_cap + 12)
        for cand in candidates[:scan_cap]:
            can_flatten = bool(
                cand.blocks
                and len(cand.blocks[0].dead_scratch_regs) >= 2
                and (cand.block_count >= 2 or cand.insn_count >= 3)
            )
            if opt.virtualize_auto and cand.vm_compatible and len(vm_targets) < vm_cap:
                vm_targets.append(cand)
            elif opt.flatten_cfg and can_flatten and len(flatten_targets) < flat_cap:
                flatten_targets.append(cand)
            elif opt.obfuscate_ops and len(obf_targets) < obf_cap:
                obf_targets.append(cand)

    # Reject conflicting transform backends on the exact same function (PASS_COMPATIBILITY.md Section 4)
    assigned_backend = {}
    function_actions = []

    def assign(fn_list, backend):
        for fn in fn_list:
            if fn.vaddr in assigned_backend and assigned_backend[fn.vaddr] != backend:
                raise ProtectionError(
                    f"Conflict on function '{fn.name}' ({fn.vaddr:#x}): cannot assign both "
                    f"'{assigned_backend[fn.vaddr]}' and '{backend}' backends to the same function body."
                )
            if backend == "vm" and not fn.vm_compatible:
                raise ProtectionError(
                    f"Function '{fn.name}' ({fn.vaddr:#x}) cannot be virtualized (O08): {fn.skip_reasons}"
                )
            if backend in ("flatten", "obfuscate", "on_demand") and not fn.relocatable:
                raise ProtectionError(
                    f"Function '{fn.name}' ({fn.vaddr:#x}) cannot be relocated for {backend}: {fn.skip_reasons}"
                )
            if fn.vaddr in assigned_backend:
                continue
            assigned_backend[fn.vaddr] = backend
            passes = []
            if backend == "vm":
                passes = ["F01", "F02", "O08", "O09"]
            elif backend == "flatten":
                passes = ["F01", "F02", "O06", "O07"]
                if opt.obfuscate_ops:
                    passes = ["F01", "F02", "O01", "O02", "O03", "O04", "O06", "O07"]
            elif backend == "obfuscate":
                passes = ["F01", "F02", "O01", "O02", "O03", "O04", "O05", "O06", "A07"]
            elif backend == "on_demand":
                passes = ["F01", "F02", "R07"]
            function_actions.append(PlannedFunctionAction(
                name=fn.name,
                vaddr=fn.vaddr,
                size=fn.size,
                backend=backend,
                passes=passes,
                runtime_gate=bool(
                    opt.runtime_integrity
                    or opt.runtime_anti_debug
                    or opt.obfuscate_jni
                    or opt.gg_honeypot
                    or opt.anti_gg
                    or opt.ephemeral_strings
                ),
                sensitivity_score=fn.sensitivity_score,
                cost_score=fn.cost_score,
            ))

    assign(vm_targets, "vm")
    assign(flatten_targets, "flatten")
    assign(obf_targets, "obfuscate")
    assign(ondemand_targets, "on_demand")

    # E01: Validate encrypted code ranges (no overlap, not early initializer if dangerous)
    encrypted_code_ranges = []
    seen_ranges = []
    for fn in enc_fn_targets:
        if fn.vaddr in assigned_backend and assigned_backend[fn.vaddr] in ("vm", "flatten", "obfuscate", "on_demand"):
            # Function body was already moved to .guard; encrypting the 4-byte entry trampoline is valid
            pass
        for s_va, s_sz, s_name in seen_ranges:
            if fn.vaddr < s_va + s_sz and s_va < fn.vaddr + fn.size:
                if fn.vaddr == s_va and fn.size == s_sz:
                    break
                raise ProtectionError(
                    f"Overlapping E01 code encryption ranges: '{fn.name}' ({fn.vaddr:#x}..{fn.vaddr+fn.size:#x}) "
                    f"overlaps '{s_name}' ({s_va:#x}..{s_va+s_sz:#x})."
                )
        else:
            seen_ranges.append((fn.vaddr, fn.size, fn.name))
            encrypted_code_ranges.append({"name": fn.name, "vaddr": fn.vaddr, "size": fn.size})

    # E03: String references (only in functions that were not replaced in-place by a 4-byte stub, or before relocation)
    string_refs = []
    if opt.encrypt_strings:
        relocated_spans = [(a.vaddr, a.vaddr + a.size) for a in function_actions]
        for ref in cached_string_refs:
            cs = ref["callsite_vaddr"]
            # If callsite is inside a function whose .text body is overwritten with a trampoline, skip in-place callsite patch
            if any(start <= cs < end for start, end in relocated_spans):
                continue
            string_refs.append(ref)
            if len(string_refs) >= 32:
                break

    # R02: Prologue checks on exported/JNI/transformed functions
    prologue_checks = []
    if opt.prologue_check or opt.runtime_integrity or opt.obfuscate_jni:
        candidates = [f for f in functions if (f.is_jni or f.is_exported) and f.size >= 4]
        for f in candidates[:16]:
            prologue_checks.append({"name": f.name, "vaddr": f.vaddr, "size": min(16, f.size if f.vaddr not in assigned_backend else 4)})

    # Build seed (A01) and watermark (A08)
    if opt.seed is not None:
        build_seed = int(opt.seed) & 0xFFFFFFFFFFFFFFFF
    else:
        build_seed = struct.unpack("<Q", hashlib.sha256(elf.data[:256] + (opt.watermark or "p3").encode()).digest()[:8])[0]

    wm_raw = hashlib.sha256(f"P3-WM:{opt.watermark}:{build_seed:#x}".encode("utf-8")).digest()[:16] if opt.watermark else bytes(16)

    # Collect active roadmap IDs (F06)
    active_ids = ["F01", "F05", "F06", "A03"]
    if function_actions or string_refs:
        active_ids.append("F02")
    if opt.encrypt_text or len(encrypted_code_ranges) == 1:
        active_ids.append("E01")
    elif len(encrypted_code_ranges) > 1:
        active_ids.append("E01")
    if opt.encrypt_rodata or opt.encrypt_data:
        active_ids.append("E02")
    if string_refs:
        active_ids.append("E03")
    if opt.auth_encryption:
        active_ids.append("E04")
    if opt.sign_manifest:
        active_ids.append("E05")
    if opt.strip_symbols or opt.clean_metadata:
        active_ids.append("E06")
    if opt.masked_key:
        active_ids.append("E07")
    if wrap_mode:
        active_ids.append("E08")
    if pack_mode:
        active_ids.append("E09")
    if opt.obfuscate_guard:
        active_ids.append("O10")
    for act in function_actions:
        for pid in act.passes:
            if pid not in active_ids:
                active_ids.append(pid)
    if opt.runtime_integrity or any(a.runtime_gate for a in function_actions):
        active_ids.append("R01")
    if prologue_checks:
        active_ids.append("R02")
    if opt.got_check:
        active_ids.append("R03")
    if opt.relro_check:
        active_ids.append("R04")
    if opt.debugger or opt.deny_attach or opt.runtime_anti_debug:
        active_ids.append("R05")
    if opt.guard_self_check:
        active_ids.append("R06")
    if opt.hooks or opt.root or opt.emulator or opt.deep_probes:
        active_ids.append("R08")
    if opt.gg_honeypot or opt.anti_gg or opt.ephemeral_strings:
        active_ids.append("R09")
    if opt.seed is not None or function_actions:
        active_ids.append("A01")
    if opt.profile:
        active_ids.append("A02")
    if opt.watermark:
        active_ids.append("A08")

    return ProtectionPlan(
        profile=opt.profile or "custom",
        build_seed=build_seed,
        watermark_hex=wm_raw.hex(),
        active_ids=sorted(set(active_ids)),
        function_actions=function_actions,
        encrypted_code_ranges=encrypted_code_ranges,
        encrypted_rodata_ranges=[{"name": ".rodata"}] if opt.encrypt_rodata else [],
        string_refs=string_refs,
        prologue_checks=prologue_checks,
        skipped_items=skipped,
        warnings=warnings,
    )


def verify_function_semantics_unicorn(original_bytes, protected_bytes, func_name, test_vectors=None):
    """Run differential execution (F03) comparing original vs protected function across inputs."""
    try:
        from .arm64_runner import Runner
    except Exception as exc:
        return {"status": "unavailable", "function": func_name, "reason": str(exc)}

    vectors = test_vectors or [(0, 0), (1, 2), (7, 13), (100, 200), (0x1234, 0x5678)]
    try:
        orig_runner = Runner(data=original_bytes)
        orig_runner.initialize(argc=5)
        expected_outputs = []
        for args in vectors:
            expected_outputs.append(orig_runner.exported(func_name, *args))
        if orig_runner.exited is not None:
            return {
                "status": "skipped",
                "function": func_name,
                "reason": f"Hàm/init gốc thoát sớm trong môi trường giả lập cô lập (code {orig_runner.exited}).",
            }
    except Exception as exc:
        return {
            "status": "skipped",
            "function": func_name,
            "reason": f"Không thể mô phỏng cô lập ngoài Android ({exc}).",
        }

    try:
        prot_runner = Runner(
            data=protected_bytes,
            files={"/proc/self/wchan": b"0", "/proc/net/unix": b"", "/proc/net/tcp": b"", "/proc/net/tcp6": b""},
        )
        prot_runner.initialize(argc=5)
        if prot_runner.exited is not None:
            return {
                "status": "failed",
                "function": func_name,
                "reason": f"Protected guard exited with code {prot_runner.exited}",
                "mismatches": [],
            }

        mismatches = []
        for args, expected in zip(vectors, expected_outputs):
            actual = prot_runner.exported(func_name, *args)
            if prot_runner.exited is not None:
                return {
                    "status": "failed",
                    "function": func_name,
                    "reason": f"Protected function triggered guard exit code {prot_runner.exited} for inputs {list(args)}",
                    "mismatches": mismatches,
                }
            if expected != actual:
                mismatches.append({"args": list(args), "expected": expected, "actual": actual})

        return {
            "status": "passed" if not mismatches else "failed",
            "function": func_name,
            "tested_vectors": len(vectors),
            "mismatches": mismatches,
        }
    except Exception as exc:
        return {
            "status": "failed",
            "function": func_name,
            "reason": f"Protected execution fault under Unicorn: {exc}",
            "mismatches": [],
        }


def evaluate_protection_benchmark(original_elf, protected_elf, report=None):
    """Compute A04/A05/A06 static/simplifier recovery metrics and A09 planner feedback."""
    orig_funcs = discover_functions(original_elf)
    orig_text = original_elf.section(".text")
    prot_text = protected_elf.section(".text")

    orig_words = []
    if orig_text and orig_text.size >= 4:
        raw = original_elf.section_data(orig_text)
        orig_words = list(struct.unpack_from(f"<{len(raw) // 4}I", raw))

    prot_words = []
    if prot_text and prot_text.size >= 4:
        raw = protected_elf.section_data(prot_text)
        prot_words = list(struct.unpack_from(f"<{len(raw) // 4}I", raw))

    # A05: 4-gram instruction Jaccard similarity in .text
    def ngrams(words, n=4):
        if len(words) < n:
            return {tuple(words)} if words else set()
        return {tuple(words[i:i + n]) for i in range(len(words) - n + 1)}

    g_orig = ngrams(orig_words)
    g_prot = ngrams(prot_words)
    union = len(g_orig | g_prot)
    jaccard = (len(g_orig & g_prot) / union) if union else 0.0

    # Function entry signature survival rate
    unchanged_entries = 0
    for fn in orig_funcs:
        try:
            off_o = original_elf.file_offset(fn.vaddr, min(16, fn.size))
            off_p = protected_elf.file_offset(fn.vaddr, min(16, fn.size))
            if original_elf.data[off_o:off_o + min(16, fn.size)] == protected_elf.data[off_p:off_p + min(16, fn.size)]:
                unchanged_entries += 1
        except ProtectionError:
            pass
    entry_survival = (unchanged_entries / len(orig_funcs)) if orig_funcs else 0.0

    # Plaintext string exposure in .rodata
    orig_refs = find_rodata_string_refs(original_elf, orig_funcs)
    unique_strings = {r["string_bytes"] for r in orig_refs}
    exposed_strings = sum(1 for s in unique_strings if s in protected_elf.data)
    string_exposure = (exposed_strings / len(unique_strings)) if unique_strings else 0.0

    # A06: Constant-folding / algebraic simplifier probe on guard/stub executable segment
    guard_load = max(
        (s for s in protected_elf.loads if (s.flags & 1) and s.filesz > 0),
        key=lambda s: s.vaddr,
        default=protected_elf.loads[-1],
    )
    guard_bytes = protected_elf.data[guard_load.offset:guard_load.offset + guard_load.filesz]
    opaque_predicates_found = 0
    opaque_constants_folded = 0
    for i in range(0, len(guard_bytes) - 12, 4):
        w0, w1, w2 = struct.unpack_from("<III", guard_bytes, i)
        i0 = decode_insn(guard_load.vaddr + i, w0)
        i1 = decode_insn(guard_load.vaddr + i + 4, w1)
        i2 = decode_insn(guard_load.vaddr + i + 8, w2)
        if i0.mnemonic == "movz" and i1.mnemonic == "movz" and i2.mnemonic == "eor_reg" and i2.rd == i0.rd:
            opaque_constants_folded += 1
        if i0.mnemonic == "add" and i1.mnemonic == "madd" and i2.mnemonic in ("tbz", "tbnz"):
            opaque_predicates_found += 1

    # A09: Generate actionable feedback for next build
    recommendations = []
    if entry_survival > 0.5:
        unprotected = [f.name for f in sorted(orig_funcs, key=lambda x: -x.sensitivity_score)[:5]]
        recommendations.append({
            "action": "enable_code_encryption_or_function_transforms",
            "reason": f"{entry_survival:.1%} of function entries in .text remain unchanged at rest.",
            "suggested_targets": unprotected,
        })
    if unique_strings and string_exposure > 0.0:
        recommendations.append({
            "action": "enable_encrypt_rodata_or_encrypt_strings",
            "reason": f"{exposed_strings}/{len(unique_strings)} referenced .rodata strings remain visible at rest.",
        })
    if not opaque_predicates_found and orig_funcs:
        recommendations.append({
            "action": "enable_obfuscate_ops_or_flatten_cfg_or_virtualize",
            "reason": "No relocated O01-O09 transformations observed in guard segment.",
        })

    return {
        "roadmap_ids": ["A04", "A05", "A06", "A09"],
        "function_count": len(orig_funcs),
        "metrics": {
            "text_4gram_jaccard_similarity": round(jaccard, 4),
            "text_4gram_divergence": round(1.0 - jaccard, 4),
            "function_entry_survival_rate": round(entry_survival, 4),
            "referenced_string_count": len(unique_strings),
            "plaintext_string_exposure_rate": round(string_exposure, 4),
            "guard_opaque_constant_sequences": opaque_constants_folded,
            "guard_input_invariant_predicates": opaque_predicates_found,
        },
        "feedback_A09": recommendations,
    }


_OPTION_LABELS_VI = {
    "wrap_elf": "E08 Bọc ELF (--wrap-elf)",
    "pack_elf": "E09 Nén & đóng gói ELF (--pack-elf)",
    "obfuscate_guard": "O10 Tự làm rối Guard (--obfuscate-guard)",
    "encrypt_data": "E02+ Mã hóa .data (--encrypt-data)",
    "encrypt_text": "E01 Mã hóa toàn .text",
    "encrypt_function": "E01 Hàm mã hóa riêng",
    "encrypt_functions": "E01 Danh sách hàm mã hóa",
    "encrypt_rodata": "E02 Mã hóa .rodata",
    "encrypt_strings": "E03 String Vault",
    "ephemeral_strings": "E03+ Tự tái mã hóa String Vault",
    "obfuscate_ops": "O01-O06 Làm rối lệnh",
    "flatten_cfg": "O07 Làm phẳng CFG",
    "virtualize_auto": "O08/O09 Tự chọn hàm VM",
    "virtualize_functions": "O08 Danh sách hàm VM",
    "flatten_functions": "O07 Danh sách hàm Flatten",
    "obfuscate_functions": "O01-O06 Danh sách hàm Làm rối",
    "on_demand_functions": "R07 Danh sách hàm On-Demand",
    "auto_select_functions": "A03 Tự chọn hàm nhạy cảm",
    "obfuscate_jni": "JNI Bảo vệ JNI_OnLoad/Java_*",
    "compat_layout": "BlueStacks/NativeBridge Compat Layout",
    "strip_symbols": "E06 NDK llvm-strip",
    "runtime_integrity": "R01 Kiểm tra toàn vẹn runtime",
    "prologue_check": "R02 Kiểm tra prologue",
    "got_check": "R03 Kiểm tra GOT/PLT",
    "relro_check": "R04 Kiểm tra .data.rel.ro",
    "guard_self_check": "R06 Guard Self-Check",
    "runtime_anti_debug": "R05+ Anti-debug runtime",
    "gg_honeypot": "R09 Honeypot chống GG",
    "anti_gg": "R09+ Watchdog chống GG/SIGSTOP",
    "troll_ida": "IDA Troll F5 / Mã vạch",
    "block_ida": "Ẩn segment .text/.guard (TLS)",
    "auth_encryption": "E04 HMAC-SHA256",
    "sign_manifest": "E05 Ký Manifest",
    "masked_key": "E07 Split-key KDF",
    "hooks": "R08 Frida/Xposed probe",
    "root": "R08 Root probe",
    "emulator": "R08 Emulator probe",
    "deny_attach": "PR_SET_DUMPABLE=0",
    "deep_probes": "R08 Deep probes",
    "denylist_functions": "F05 Denylist",
    "verify_semantics": "F03 Unicorn Semantics",
    "profile": "Profile F05",
    "seed": "Seed A01",
    "troll_barcode_chars": "Bộ ký tự mã vạch IDA",
    "troll_barcode_length": "Độ dài mã vạch IDA",
}


def analyze_option_conflicts(options, elf=None, ndk=None, functions=None, unicorn_available=None):
    """Evaluate all post-ordering feature conflicts and return structured per-option errors for red UI highlighting."""
    from .engine import check_compat_layout_support, check_encryption, check_rodata_encryption
    from .runtime import ndk_bin
    from .transforms import normalize_barcode_chars, validate_barcode_length

    conflicts = []
    option_errors = {}

    def add_conflict(code, message, opt_keys):
        conflicts.append({"code": code, "message": message, "options": list(opt_keys)})
        mapped = []
        for key in opt_keys:
            # Never turn an unchecked UI switch red if the rule came implicitly via --profile expansion
            if key in ("profile", "ndk_path") or bool(getattr(options, key, False)):
                mapped.append(key)
            elif prof and key not in mapped:
                mapped.append("profile")
        for key in mapped:
            if key not in option_errors:
                option_errors[key] = message
            elif message not in option_errors[key]:
                option_errors[key] = f"{option_errors[key]} | {message}"

    # 1. Profile syntax check before expansion
    prof = (getattr(options, "profile", "") or "").strip().lower()
    if prof and prof not in ("compat", "balanced", "anti-analysis", "max"):
        add_conflict("INVALID_PROFILE", f"Profile không hợp lệ: '{options.profile}'. Chọn compat, balanced, anti-analysis hoặc max.", ["profile"])
        opt = options
    else:
        opt = apply_profile_defaults(options)

    # 2. E01 Whole .text vs per-function encryption
    if opt.encrypt_text and (opt.encrypt_function or opt.encrypt_functions):
        keys = ["encrypt_text"]
        if opt.encrypt_functions:
            keys.append("encrypt_functions")
        if opt.encrypt_function:
            keys.append("encrypt_function")
        add_conflict(
            "E01_WHOLE_VS_FUNC",
            "Chỉ bật Mã hóa toàn .text HOẶC nhập danh sách hàm E01 riêng (không bật cả hai).",
            keys,
        )

    # 3. E03+ ephemeral_strings requires E03 encrypt_strings (only mark active E03+ switch red, not off E03 switch)
    if opt.ephemeral_strings and not opt.encrypt_strings:
        add_conflict(
            "EPHEMERAL_REQUIRES_VAULT",
            "Cần bật kèm 'String Vault (E03)' để tự tái mã hóa chuỗi sau khi dùng.",
            ["ephemeral_strings"],
        )

    # 4. E09 (--pack-elf) and E08 (--wrap-elf) are mutually exclusive outer layers
    if opt.pack_elf and opt.wrap_elf:
        add_conflict(
            "E09_VS_E08",
            "Chỉ bật E09 (--pack-elf) HOẶC E08 (--wrap-elf), không bật cả hai cùng lúc (khuyến nghị E09).",
            ["pack_elf", "wrap_elf"],
        )

    # 5. Same function assigned to multiple Stage-3 backends or both assigned + denylisted
    backend_fields = [
        ("virtualize_functions", "O08 VM", set(_parse_csv(opt.virtualize_functions))),
        ("flatten_functions", "O07 Flatten", set(_parse_csv(opt.flatten_functions))),
        ("obfuscate_functions", "O01-O06 Làm rối", set(_parse_csv(opt.obfuscate_functions))),
        ("on_demand_functions", "R07 On-Demand", set(_parse_csv(opt.on_demand_functions))),
    ]
    seen_targets = {}
    for field_key, label, items in backend_fields:
        for fn_name in items:
            if fn_name in seen_targets:
                other_key, other_label = seen_targets[fn_name]
                add_conflict(
                    "MULTI_BACKEND_FUNC",
                    f"Xung đột F05 trên hàm '{fn_name}': không thể gán cả {other_label} và {label} cho cùng một hàm.",
                    [other_key, field_key],
                )
            else:
                seen_targets[fn_name] = (field_key, label)

    denylist = set(_parse_csv(opt.denylist_functions))
    for field_key, label, items in backend_fields:
        overlap = sorted(items & denylist)
        if overlap:
            add_conflict(
                "TARGET_IN_DENYLIST",
                f"Xung đột F05: hàm {', '.join(overlap[:3])} vừa được gán {label} vừa nằm trong Denylist.",
                [field_key, "denylist_functions"],
            )

    if len(_parse_csv(opt.virtualize_functions)) > 32:
        add_conflict("VM_LIMIT", "Tối đa 32 hàm được chỉ định vào ARM64 VM (O08) cho mỗi thư viện.", ["virtualize_functions"])

    # 6. IDA barcode syntax when troll_ida enabled
    if opt.troll_ida:
        try:
            blen = validate_barcode_length(opt.troll_barcode_length)
        except ProtectionError as exc:
            add_conflict("BARCODE_LEN", str(exc), ["troll_barcode_length"])
            blen = 17
        try:
            normalize_barcode_chars(opt.troll_barcode_chars, allow_empty=(blen == 0))
        except ProtectionError as exc:
            add_conflict("BARCODE_CHARS", str(exc), ["troll_barcode_chars"])

    # 7. F03 Unicorn availability
    if opt.verify_semantics and unicorn_available is False:
        add_conflict("F03_NO_UNICORN", "F03 Semantics cần package 'unicorn' (chạy qua CLI .venv).", ["verify_semantics"])

    # 8. NDK dependency checks
    if opt.strip_symbols or opt.wrap_elf:
        try:
            ndk_bin(ndk)
        except ProtectionError as exc:
            ndk_keys = [k for k, v in (("strip_symbols", opt.strip_symbols), ("wrap_elf", opt.wrap_elf)) if v]
            ndk_keys.append("ndk_path")
            add_conflict("NDK_MISSING", f"Thiếu Android NDK ({exc}) — cần chọn thư mục NDK hợp lệ.", ndk_keys)

    # 9. Loaded ELF (.so) compatibility checks
    built_plan = None
    if elf is not None:
        funcs = functions if functions is not None else discover_functions(elf)
        by_name = {}
        for fn in funcs:
            by_name.setdefault(fn.name, []).append(fn)
        by_va = {fn.vaddr: fn for fn in funcs}

        pack_mode = bool(opt.pack_elf and not opt.wrap_elf)
        if pack_mode:
            if len(elf.loads) > 8:
                add_conflict("E09_TOO_MANY_LOADS", "E09 (--pack-elf) hỗ trợ tối đa 8 PT_LOAD segment.", ["pack_elf"])
            if any(tag in (0x6000000F, 0x60000011) for tag, _ in elf.dynamic):
                add_conflict("E09_APS2_UNSUPPORTED", "E09 chưa hỗ trợ relocation nén APS2 trên .so này.", ["pack_elf"])
            if any(tag in (35, 36, 37, 0x6FFFE000, 0x6FFFE001, 0x6FFFE003) for tag, _ in elf.dynamic):
                add_conflict("E09_RELR_UNSUPPORTED", "E09 chưa hỗ trợ relocation RELR trên .so này.", ["pack_elf"])

        if opt.wrap_elf:
            exports = elf.exported_symbols()
            obj_exports = [n for n, info, _, _, _ in exports if (info & 0xF) == 1]
            fn_exports = [n for n, info, _, _, _ in exports if (info & 0xF) == 2 and n]
            if obj_exports:
                add_conflict(
                    "E08_OBJ_EXPORT",
                    f"E08 (--wrap-elf) không hỗ trợ .so có export STT_OBJECT/RTTI ({obj_exports[:2]}). Hãy tắt E08 và bật E09 (--pack-elf) thay thế.",
                    ["wrap_elf"],
                )
            elif not fn_exports:
                add_conflict(
                    "E08_NO_EXPORT",
                    "E08 (--wrap-elf) yêu cầu .so có ít nhất 1 hàm STT_FUNC export. Hãy dùng E09 (--pack-elf) thay thế.",
                    ["wrap_elf"],
                )

        if opt.compat_layout and not pack_mode:
            try:
                check_compat_layout_support(elf)
            except ProtectionError as exc:
                add_conflict("COMPAT_LAYOUT_UNSUPPORTED", f"Compat Layout không khả dụng trên .so này: {exc}", ["compat_layout"])

        text_sec = elf.section(".text")
        if opt.encrypt_text and not pack_mode:
            try:
                check_encryption(elf, text_sec, code=True)
            except ProtectionError as exc:
                add_conflict("E01_TEXT_UNSUPPORTED", f"E01 Toàn .text xung đột với cấu trúc .so này: {exc}", ["encrypt_text"])

        if opt.encrypt_rodata and not pack_mode:
            try:
                check_rodata_encryption(elf)
            except ProtectionError as exc:
                add_conflict("E02_RODATA_UNSUPPORTED", f"E02 .rodata xung đột với cấu trúc .so này: {exc}", ["encrypt_rodata"])

        if opt.encrypt_strings and elf.section(".rodata") is None:
            add_conflict("E03_NO_RODATA", "E03 String Vault cần có section .rodata trong file .so.", ["encrypt_strings"])

        # Validate named targets against discovered functions
        def _lookup(name):
            m = by_name.get(name, [])
            if not m and name.startswith("0x"):
                try:
                    va = int(name, 16)
                    if va in by_va:
                        m = [by_va[va]]
                except ValueError:
                    pass
            return m

        for field_key, label, items in backend_fields:
            for fn_name in sorted(items):
                if fn_name in denylist:
                    continue
                matches = _lookup(fn_name)
                if len(matches) != 1:
                    add_conflict(
                        "TARGET_MISSING",
                        f"{label}: không tìm thấy duy nhất symbol '{fn_name}' (khớp {len(matches)}).",
                        [field_key],
                    )
                    continue
                fn = matches[0]
                if field_key == "virtualize_functions" and not fn.vm_compatible:
                    add_conflict(
                        "VM_INCOMPATIBLE",
                        f"Hàm '{fn_name}' không hỗ trợ O08 VM: {', '.join(fn.skip_reasons) or 'không tương thích'}.",
                        [field_key],
                    )
                elif field_key != "virtualize_functions" and not fn.relocatable:
                    add_conflict(
                        "FUNC_NOT_RELOCATABLE",
                        f"Hàm '{fn_name}' không relocate được cho {label}: {', '.join(fn.skip_reasons) or 'không tương thích'}.",
                        [field_key],
                    )

        enc_names = ([opt.encrypt_function] if opt.encrypt_function else []) + _parse_csv(opt.encrypt_functions)
        enc_key = "encrypt_functions" if opt.encrypt_functions else "encrypt_function"
        if enc_names and not opt.encrypt_text:
            seen_enc = []
            for fn_name in enc_names:
                if fn_name in denylist:
                    continue
                matches = _lookup(fn_name)
                if len(matches) != 1:
                    add_conflict("E01_FUNC_MISSING", f"E01: không tìm thấy duy nhất '{fn_name}' (khớp {len(matches)}).", [enc_key])
                    continue
                fn = matches[0]
                if not text_sec or not text_sec.addr <= fn.vaddr or fn.vaddr + fn.size > text_sec.addr + text_sec.size:
                    add_conflict("E01_OUTSIDE_TEXT", f"E01: hàm '{fn_name}' nằm ngoài section .text.", [enc_key])
                    continue
                if not pack_mode:
                    try:
                        check_encryption(elf, replace(text_sec, addr=fn.vaddr, size=fn.size, offset=elf.file_offset(fn.vaddr, fn.size)), code=True)
                    except ProtectionError as exc:
                        add_conflict("E01_FUNC_UNSUPPORTED", f"E01 hàm '{fn_name}': {exc}", [enc_key])
                        continue
                for s_va, s_sz, s_name in seen_enc:
                    if fn.vaddr < s_va + s_sz and s_va < fn.vaddr + fn.size and not (fn.vaddr == s_va and fn.size == s_sz):
                        add_conflict("E01_OVERLAP", f"E01: '{fn.name}' chồng lấn vùng với '{s_name}'.", [enc_key])
                        break
                seen_enc.append((fn.vaddr, fn.size, fn.name))

        if not conflicts:
            try:
                built_plan = build_protection_plan(elf, opt, pre_strip_functions=funcs)
            except ProtectionError as exc:
                add_conflict("PLAN_ERROR", str(exc), [])

    return {"conflicts": conflicts, "option_errors": option_errors, "plan": built_plan}
