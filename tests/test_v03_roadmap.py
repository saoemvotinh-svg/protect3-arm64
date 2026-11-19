"""Comprehensive tests for Protect3 v0.3 roadmap items (F01-F06, E01-E08, O01-O09, R01-R08, A01-A09)."""

import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import unittest

from protect3.arm64 import discover_functions
from protect3.elf import ELF, ProtectionError
from protect3.engine import Options, capabilities, protect, rewrite, verify_file
from protect3.planner import (
    analyze_option_conflicts,
    build_protection_plan,
    evaluate_protection_benchmark,
    verify_function_semantics_unicorn,
)
from protect3.runtime import load_runtime
from protect3.transforms import DEFAULT_TROLL_DECOYS, build_gg_honeypot_page
from tests.arm64_runner import Runner
from tests.fixtures import build_fixtures


class RoadmapV03Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = build_fixtures()
        cls.original = ELF(cls.source.read_bytes())
        cls.blob, cls.meta = load_runtime()

    def rewritten(self, **options):
        return rewrite(self.original, Options(**options), self.blob, self.meta)[0]

    def test_f01_recovers_functions_from_eh_frame_and_resolves_local_symbols_before_strip(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "libstripped_local.so"
            # sample_constructor is a local static function in .symtab that disappears after llvm-strip
            protect(self.source, out, Options(strip_symbols=True, encrypt_function="sample_constructor"))
            elf = ELF(out.read_bytes())
            self.assertFalse(elf.summary()["has_symtab"])
            runner = Runner(data=elf.data)
            runner.initialize()
            self.assertIsNone(runner.exited)
            self.assertEqual(45, runner.exported("sample_add", 1, 2))
            # Even after .symtab is stripped, F01 recovers functions from .eh_frame / .dynsym
            funcs = discover_functions(elf)
            self.assertGreaterEqual(len(funcs), 6)

    def test_e01_multi_function_encryption_and_overlap_rejection(self):
        data = self.rewritten(encrypt_functions="sample_add,JNI_OnLoad", diagnostics=True)
        runner = Runner(data=data)
        runner.initialize()
        self.assertIsNone(runner.exited, runner.log)
        self.assertIn(b"event=multi_range_decrypt_ok", runner.log)
        self.assertEqual(45, runner.exported("sample_add", 1, 2))
        self.assertEqual(0x10006, runner.exported("JNI_OnLoad", 0, 0))

    def test_e03_lazy_per_reference_string_vault_decrypts_only_on_use(self):
        for compat in (False, True):
            with self.subTest(compat=compat):
                data = self.rewritten(encrypt_strings=True, compat_layout=compat, diagnostics=True)
                self.assertNotIn(b"Protect3 fixture string for rodata encryption", data)
                runner = Runner(data=data)
                runner.initialize()
                self.assertIsNone(runner.exited, runner.log)
                # String is NOT decrypted during DT_INIT
                self.assertNotIn(b"event=string_decrypt_ok", runner.log)
                # Calling sample_secret triggers lazy decryption from the page-isolated String Vault
                ptr = runner.exported("sample_secret")
                self.assertEqual("Protect3 fixture string for rodata encryption", runner.string(ptr))
                self.assertIn(b"event=string_decrypt_ok", runner.log)
                # Second call reuses the decrypted String Vault entry without additional mprotect
                prot_count = len(runner.protections)
                ptr2 = runner.exported("sample_secret")
                self.assertEqual(ptr, ptr2)
                self.assertEqual(prot_count, len(runner.protections))

    def test_e04_authenticated_encryption_rejects_tampered_ciphertext_before_mprotect(self):
        data = bytearray(self.rewritten(encrypt_text=True, auth_encryption=True, diagnostics=True))
        runner_ok = Runner(data=bytes(data))
        runner_ok.initialize()
        self.assertIsNone(runner_ok.exited, runner_ok.log)
        self.assertIn(b"event=text_mac_ok", runner_ok.log)

        text = ELF(data).section(".text")
        data[text.offset + 8] ^= 0x01
        runner_bad = Runner(data=bytes(data))
        runner_bad.initialize()
        self.assertEqual(175, runner_bad.exited)
        self.assertIn(b"ciphertext authentication tag mismatch", runner_bad.log)
        # Pre-decryption MAC check fails BEFORE calling mprotect RW!
        self.assertEqual([], runner_bad.protections)

    def test_e05_and_r06_signed_manifest_and_guard_self_check(self):
        raw, injection = rewrite(
            self.original,
            Options(sign_manifest=True, guard_self_check=True, diagnostics=True),
            self.blob,
            self.meta,
        )
        runner = Runner(data=raw)
        runner.initialize()
        self.assertIsNone(runner.exited, runner.log)
        self.assertIn(b"event=manifest_mac_ok", runner.log)
        self.assertIn(b"event=guard_self_check_ok", runner.log)

        # Tamper with 1 byte of p3_config -> caught by E05 manifest_mac
        bad_cfg = bytearray(raw)
        bad_cfg[injection["config_offset"] + 28] ^= 0x01
        r_cfg = Runner(data=bytes(bad_cfg))
        r_cfg.initialize()
        self.assertEqual(175, r_cfg.exited)
        self.assertIn(b"signed manifest verification failed", r_cfg.log)

        # Tamper with 1 byte of guard.bin executable code -> caught by R06 guard_self_check
        bad_code = bytearray(raw)
        vm_exec_off = self.meta["symbols"]["p3_vm_exec"]
        bad_code[injection["segment_offset"] + (injection["entry_vaddr"] - injection["segment_vaddr"]) + vm_exec_off + 8] ^= 0x01
        r_code = Runner(data=bytes(bad_code))
        r_code.initialize()
        self.assertEqual(175, r_code.exited)
        self.assertIn(b"guard self-integrity mismatch", r_code.log)

    def test_e06_and_e07_metadata_scrub_and_masked_kdf_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            debug_copy = Path(tmp) / "debug" / "libsample.debug.so"
            out = Path(tmp) / "libsample.clean.so"
            res = protect(
                self.source,
                out,
                Options(clean_metadata=True, keep_debug=str(debug_copy), encrypt_text=True, masked_key=True),
            )
            self.assertTrue(debug_copy.is_file())
            self.assertEqual(self.original.data, debug_copy.read_bytes())
            ledger = res["details"]["pass_ledger"]
            self.assertIn(".comment", ledger["scrubbed_metadata_sections"])
            runner = Runner(data=out.read_bytes())
            runner.initialize()
            self.assertIsNone(runner.exited)
            self.assertEqual(45, runner.exported("sample_add", 1, 2))

    def test_o01_to_o06_and_a07_instruction_obfuscation_and_block_shuffling(self):
        for compat in (False, True):
            with self.subTest(compat=compat):
                data = self.rewritten(
                    obfuscate_functions="sample_add,Java_com_example_Sample_nativeValue",
                    compat_layout=compat,
                    verify_semantics=True,
                )
                runner = Runner(data=data)
                runner.initialize(argc=6)
                self.assertIsNone(runner.exited, runner.log)
                for a, b in ((1, 2), (0, 0), (100, 250), (-10 & 0xFFFFFFFF, 30)):
                    self.assertEqual((a + b + 42) & 0xFFFFFFFF, runner.exported("sample_add", a, b) & 0xFFFFFFFF)
                self.assertEqual(42, runner.exported("Java_com_example_Sample_nativeValue", 0, 0))

    def test_o07_control_flow_flattening_preserves_semantics(self):
        for compat in (False, True):
            with self.subTest(compat=compat):
                data = self.rewritten(
                    flatten_functions="sample_add,JNI_OnLoad",
                    compat_layout=compat,
                    diagnostics=True,
                )
                runner = Runner(data=data)
                runner.initialize()
                self.assertIsNone(runner.exited, runner.log)
                self.assertEqual(45, runner.exported("sample_add", 1, 2))
                self.assertEqual(142, runner.exported("sample_add", 40, 60))
                self.assertEqual(0x10006, runner.exported("JNI_OnLoad", 0, 0))

    def test_o08_and_o09_arm64_function_virtualization_and_polymorphic_vm(self):
        data_seed1, inj1 = rewrite(
            self.original,
            Options(
                virtualize_functions="sample_add,JNI_OnLoad,Java_com_example_Sample_nativeValue",
                seed=1001,
                diagnostics=True,
            ),
            self.blob,
            self.meta,
        )
        data_seed2, inj2 = rewrite(
            self.original,
            Options(
                virtualize_functions="sample_add,JNI_OnLoad,Java_com_example_Sample_nativeValue",
                seed=2002,
                diagnostics=True,
            ),
            self.blob,
            self.meta,
        )
        # Different seeds produce distinct opcode permutations in p3_ext
        ext1 = data_seed1[inj1["ext_config_offset"]:inj1["ext_config_offset"] + 480]
        ext2 = data_seed2[inj2["ext_config_offset"]:inj2["ext_config_offset"] + 480]
        self.assertNotEqual(ext1, ext2)

        for data in (data_seed1, data_seed2):
            runner = Runner(data=data)
            runner.initialize(argc=11)
            self.assertIsNone(runner.exited, runner.log)
            self.assertEqual(45, runner.exported("sample_add", 1, 2))
            self.assertEqual(342, runner.exported("sample_add", 100, 200))
            self.assertEqual(0x10006, runner.exported("JNI_OnLoad", 0, 0))
            self.assertEqual(42, runner.exported("Java_com_example_Sample_nativeValue", 0, 0))
            self.assertIn(b"event=vm_exec_ok", runner.log)

    def test_r01_r02_r05_runtime_gate_catches_late_hook_and_late_debugger(self):
        data = self.rewritten(
            obfuscate_jni=True,
            runtime_integrity=True,
            prologue_check=True,
            runtime_anti_debug=True,
            diagnostics=True,
        )
        runner = Runner(data=data)
        runner.initialize()
        self.assertIsNone(runner.exited, runner.log)
        self.assertEqual(0x10006, runner.exported("JNI_OnLoad", 0, 0))
        self.assertIn(b"event=runtime_gate_ok", runner.log)

        # Simulate late inline Frida hook patching sample_add prologue AFTER DT_INIT completed
        sym_add = next(s for s in self.original.symbols() if s["name"] == "sample_add")
        runner.uc.mem_write(runner.bias + sym_add["value"], b"\x00\x00\x20\xd4")
        runner.exported("JNI_OnLoad", 0, 0)
        self.assertEqual(175, runner.exited)
        self.assertIn(b"prologue/trampoline hook detected", runner.log)

        # Simulate debugger attaching AFTER DT_INIT completed
        runner2 = Runner(data=data)
        runner2.initialize()
        self.assertIsNone(runner2.exited)
        runner2.files["/proc/self/status"] = b"Name:\ttest\nTracerPid:\t4321\n"
        runner2.exported("JNI_OnLoad", 0, 0)
        self.assertEqual(171, runner2.exited)
        self.assertIn(b"debugger detected at runtime gate", runner2.log)

    def test_r07_on_demand_decrypt_and_reencrypt_per_call(self):
        raw, inj = rewrite(
            self.original,
            Options(on_demand_functions="sample_add", auth_encryption=True, diagnostics=True),
            self.blob,
            self.meta,
        )
        tf = inj["transformed_functions"][0]
        iso_va = tf["isolated_page_vaddr"]
        iso_sz = tf["isolated_size"]

        runner = Runner(data=raw)
        runner.initialize()
        self.assertIsNone(runner.exited, runner.log)
        # Before calling sample_add, isolated page is ciphertext
        before_call = bytes(runner.uc.mem_read(runner.bias + iso_va, iso_sz))
        self.assertNotIn(b"event=on_demand_decrypt_ok", runner.log)

        self.assertEqual(72, runner.exported("sample_add", 10, 20))
        self.assertIn(b"event=on_demand_decrypt_ok", runner.log)
        self.assertIn(b"event=on_demand_reencrypt_ok", runner.log)
        # After sample_add returns, isolated page is re-encrypted back to the exact ciphertext!
        after_call = bytes(runner.uc.mem_read(runner.bias + iso_va, iso_sz))
        self.assertEqual(before_call, after_call)
        # Calling again decrypts, computes, and re-encrypts again
        self.assertEqual(53, runner.exported("sample_add", 5, 6))

    def test_r08_deep_probes_detect_bluestacks_and_gum_threads(self):
        runner_bst = Runner(
            data=self.rewritten(emulator=True, deep_probes=True),
            paths=["/dev/bst_gps"],
        )
        runner_bst.initialize()
        self.assertEqual(174, runner_bst.exited)

        runner_gum = Runner(
            data=self.rewritten(hooks=True, deep_probes=True),
            files={"/proc/self/comm": b"gum-js-loop\n"},
        )
        runner_gum.initialize()
        self.assertEqual(172, runner_gum.exited)

    def test_f05_a02_a04_a08_profiles_watermark_benchmark_and_conflict_rejection(self):
        # Conflicting backends on the same function are rejected
        with self.assertRaisesRegex(ProtectionError, "Conflict"):
            build_protection_plan(
                self.original,
                Options(virtualize_functions="sample_add", flatten_functions="sample_add"),
            )
        # E02 (.rodata encryption) + E03 (lazy String Vault) coexist in parallel by partitioning:
        # E03 moves referenced strings into the String Vault and zeroes them in .rodata, while E02 encrypts .rodata.
        both_data = self.rewritten(encrypt_rodata=True, encrypt_strings=True, diagnostics=True)
        self.assertNotIn(b"Protect3 fixture string for rodata encryption", both_data)
        runner_both = Runner(data=both_data)
        runner_both.initialize()
        self.assertIsNone(runner_both.exited, runner_both.log)
        self.assertIn(b"event=rodata_decrypt_ok", runner_both.log)
        self.assertNotIn(b"event=string_decrypt_ok", runner_both.log)
        ptr_both = runner_both.exported("sample_secret")
        self.assertEqual("Protect3 fixture string for rodata encryption", runner_both.string(ptr_both))
        self.assertIn(b"event=string_decrypt_ok", runner_both.log)
        # Profile 'max' + watermark + verify_file + benchmark
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "libmax.so"
            res = protect(self.source, out, Options(profile="max", watermark="build-2026-v03"))
            ver = verify_file(out)
            self.assertEqual("passed", ver["status"])
            self.assertTrue(ver["watermark_verified"])
            self.assertIn("O08", ver["active_roadmap_ids"])
            self.assertIn("E03", ver["active_roadmap_ids"])

            runner = Runner(data=out.read_bytes())
            runner.initialize()
            self.assertIsNone(runner.exited, runner.log)
            self.assertEqual(45, runner.exported("sample_add", 1, 2))
            self.assertEqual(0x10006, runner.exported("JNI_OnLoad", 0, 0))
            ptr = runner.exported("sample_secret")
            self.assertEqual("Protect3 fixture string for rodata encryption", runner.string(ptr))

            bench = evaluate_protection_benchmark(self.original, ELF(out.read_bytes()))
            self.assertEqual(0.0, bench["metrics"]["plaintext_string_exposure_rate"])
            self.assertGreater(bench["metrics"]["text_4gram_divergence"], 0.5)

    def test_e08_whole_elf_payload_wrapper_builds_valid_library(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "libwrapped.so"
            res = protect(self.source, out, Options(wrap_elf=True))
            wrapped = ELF(out.read_bytes())
            self.assertEqual("arm64-v8a", wrapped.summary()["architecture"])
            exported_names = {s[0] for s in wrapped.exported_symbols()}
            for expected in ("sample_add", "JNI_OnLoad", "Java_com_example_Sample_nativeValue", "sample_secret"):
                self.assertIn(expected, exported_names)
            self.assertIn("E08", res["details"]["pass_ledger"]["active_roadmap_ids"])

    def test_ida_troll_and_segment_hide_preserve_execution_and_abi(self):
        # 1. troll_ida only (renames internal functions to randomized IlO0... barcode/troll names + 24 decoys)
        # 2. block_ida only (emits .p3_max/.p3_tls SHT_NOBITS+SHF_TLS segment wipe)
        # 3. troll_ida + block_ida combined (hides real segments + leaves .troll_ida 24 F5 decoys)
        for compat in (False, True):
            for troll, block in ((True, False), (False, True), (True, True)):
                with self.subTest(compat=compat, troll=troll, block=block):
                    with tempfile.TemporaryDirectory() as tmp:
                        out = Path(tmp) / f"libida_{int(compat)}_{int(troll)}_{int(block)}.so"
                        res = protect(
                            self.source,
                            out,
                            Options(
                                compat_layout=compat,
                                encrypt_text=True,
                                encrypt_rodata=True,
                                encrypt_strings=True,
                                obfuscate_ops=True,
                                troll_ida=troll,
                                block_ida=block,
                                seed=42,
                            ),
                        )
                        ver = verify_file(out)
                        self.assertEqual("passed", ver["status"])
                        ida_meta = res["details"]["injection"].get("ida_anti_analysis", {})
                        self.assertEqual(troll, ida_meta.get("troll_ida"))
                        self.assertEqual(block, ida_meta.get("block_ida"))

                        elf = ELF(out.read_bytes())
                        sec_names = {s.name for s in elf.sections}
                        if block:
                            self.assertIn(".p3_max", sec_names)
                            self.assertIn(".p3_tls", sec_names)
                        if troll:
                            self.assertIn(".symtab", sec_names)
                            self.assertIn(".strtab", sec_names)
                            self.assertEqual(len(DEFAULT_TROLL_DECOYS), ida_meta.get("decoy_functions_count"))
                            self.assertGreaterEqual(len(DEFAULT_TROLL_DECOYS), 36)
                            symtab_sections = [s for s in elf.sections if s.type == 2]
                            self.assertEqual(1, len(symtab_sections))
                            sym_names = {s["name"] for s in elf.symbols(dynamic_only=False)}
                            self.assertTrue(
                                any(re.fullmatch(r"[IlO][IlO0]{16}_Bam_F5_Lam_Cho_Nhe_Bro_01", n) for n in sym_names)
                            )
                            if not block:
                                self.assertTrue(any(re.fullmatch(r"[IlO][IlO0]{16}", n) for n in sym_names))
                                self.assertNotIn("sample_constructor", sym_names)
                        for n, m, a in DEFAULT_TROLL_DECOYS:
                            blob_txt = f"{n} {m} {a}".lower()
                            for forbidden in ("9.3", "9_3", "quan huy", "quan_huy", "garena"):
                                self.assertNotIn(forbidden, blob_txt)

                        runner = Runner(data=elf.data)
                        runner.initialize()
                        self.assertIsNone(runner.exited, runner.log)
                        self.assertEqual(45, runner.exported("sample_add", 1, 2))
                        ptr = runner.exported("sample_secret")
                        self.assertEqual("Protect3 fixture string for rodata encryption", runner.string(ptr))

    def test_ida_troll_custom_barcode_length_chars_and_decoys(self):
        # Custom chars ('ab9'), exact length (12), and custom Vietnamese/ASCII decoy names & F5 strings
        custom_spec = "\n".join([
            "Kiem Tra Key VIP | Khong co key dau bro =)) | Nhanh 1337 bi mat",
            "GiaiMa_Config | {" + '"ok":false' + "}",
        ])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "libcustom_troll.so"
            res = protect(
                self.source,
                out,
                Options(
                    compat_layout=True,
                    troll_ida=True,
                    block_ida=True,
                    troll_barcode_chars="ab9",
                    troll_barcode_length=12,
                    troll_decoys=custom_spec,
                    seed=7,
                ),
            )
            ida_meta = res["details"]["injection"]["ida_anti_analysis"]
            self.assertEqual(2, ida_meta["decoy_functions_count"])
            self.assertEqual(12, ida_meta["troll_barcode_length"])
            self.assertEqual("ab9", ida_meta["troll_barcode_chars"])
            self.assertTrue(ida_meta["custom_decoys_used"])

            elf = ELF(out.read_bytes())
            syms = {s["name"]: s for s in elf.symbols(dynamic_only=False) if s["name"]}
            first_match = [n for n in syms if re.fullmatch(r"[ab][ab9]{11}_Kiem_Tra_Key_VIP", n)]
            second_match = [n for n in syms if re.fullmatch(r"[ab][ab9]{11}_GiaiMa_Config", n)]
            self.assertEqual(1, len(first_match), syms.keys())
            self.assertEqual(1, len(second_match), syms.keys())

            runner = Runner(data=elf.data)
            runner.initialize()
            self.assertIsNone(runner.exited, runner.log)
            decoy_va = runner.bias + syms[first_match[0]]["value"]
            self.assertEqual("Khong co key dau bro =))", runner.string(runner.call(decoy_va, 0)))
            self.assertEqual("Nhanh 1337 bi mat", runner.string(runner.call(decoy_va, 1337)))

            # Length=0 emits bare custom names without barcode prefix
            out_bare = Path(tmp) / "libcustom_bare.so"
            protect(
                self.source,
                out_bare,
                Options(
                    compat_layout=True,
                    troll_ida=True,
                    block_ida=True,
                    troll_barcode_length=0,
                    troll_decoys="Check_Bare | Bare troll msg",
                    seed=7,
                ),
            )
            bare_names = {s["name"] for s in ELF(out_bare.read_bytes()).symbols(dynamic_only=False)}
            self.assertIn("Check_Bare", bare_names)

            # Invalid custom lengths / empty charset fail cleanly with ProtectionError
            with self.assertRaises(ProtectionError):
                protect(
                    self.source,
                    Path(tmp) / "bad_len.so",
                    Options(compat_layout=True, troll_ida=True, troll_barcode_length=-1),
                )
            with self.assertRaises(ProtectionError):
                protect(
                    self.source,
                    Path(tmp) / "bad_chars.so",
                    Options(compat_layout=True, troll_ida=True, troll_barcode_chars="   ", troll_barcode_length=8),
                )

    def test_r09_gg_honeypot_ephemeral_vault_anti_gg_and_opsec(self):
        # OpSec check: troll phrases & honeypot bait must never leak internal cipher/VM/vault architecture names
        forbidden_tech = ("chacha20", "hmac-sha256", "hmac", "arm64 vm", "string vault", "guard/vm", "guard thunk", "pt_load")
        for n, m, a in DEFAULT_TROLL_DECOYS:
            lowered = f"{n} {m} {a}".lower()
            for kw in forbidden_tech:
                self.assertNotIn(kw, lowered, f"OpSec leak '{kw}' in {n}")
        honeypot_sample = build_gg_honeypot_page(123).lower()
        for kw in ("protect3", "chacha20", "hmac", "arm64 vm", "string vault"):
            self.assertNotIn(kw.encode("utf-8"), honeypot_sample)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "libgg_shield.so"
            res = protect(
                self.source,
                out,
                Options(
                    compat_layout=True,
                    encrypt_text=True,
                    encrypt_rodata=True,
                    encrypt_strings=True,
                    auth_encryption=True,
                    sign_manifest=True,
                    masked_key=True,
                    obfuscate_ops=True,
                    flatten_cfg=True,
                    virtualize_auto=True,
                    obfuscate_jni=True,
                    runtime_integrity=True,
                    prologue_check=True,
                    guard_self_check=True,
                    gg_honeypot=True,
                    ephemeral_strings=True,
                    anti_gg=True,
                    troll_ida=True,
                    block_ida=True,
                    diagnostics=True,
                    seed=99,
                ),
            )
            self.assertIn("R09", res["details"]["pass_ledger"]["active_roadmap_ids"])
            raw = out.read_bytes()

            # 1. Normal execution with all layers + R09 anti-GG enabled
            runner = Runner(data=raw)
            runner.initialize()
            self.assertIsNone(runner.exited, runner.log)
            self.assertEqual(45, runner.exported("sample_add", 1, 2))
            self.assertEqual("Protect3 fixture string for rodata encryption", runner.string(runner.exported("sample_secret")))
            self.assertEqual(42, runner.exported("Java_com_example_Sample_nativeValue", 0, 0))
            log_txt = runner.log.decode(errors="replace")
            self.assertIn("event=honeypot_canary_ok", log_txt)
            self.assertIn("event=anti_gg_ok", log_txt)

            # 2. Tampering 1 byte of the honeypot canary page simulates GameGuardian editing/freezing lure memory -> die(179)
            marker = b"https://api-edge-gateway.example.invalid"
            pos = raw.find(marker)
            self.assertGreater(pos, 0)
            tampered = bytearray(raw)
            tampered[pos + 8] ^= 0x01
            bad_runner = Runner(data=bytes(tampered))
            bad_runner.initialize()
            self.assertEqual(179, bad_runner.exited, bad_runner.log)

            # 3. Detecting GameGuardian UNIX socket / daemon indicator -> die(180)
            gg_runner = Runner(
                data=raw,
                files={"/proc/net/unix": b"00000000: 00000002 00000000 00010000 0005 01 999 /dev/socket/gameguardian_daemon\n"},
            )
            gg_runner.initialize()
            self.assertEqual(180, gg_runner.exited, gg_runner.log)

            # 4. Non-root /proc/self/task thread tracer detection via getdents64 (main thread stays clean TracerPid=0) -> die(180)
            task_runner = Runner(
                data=raw,
                dirs={"/proc/self/task": ["1001", "1002"]},
                files={
                    "/proc/self/task/1001/status": b"Name:\tmain\nState:\tR (running)\nTracerPid:\t0\n",
                    "/proc/self/task/1002/status": b"Name:\trender\nState:\tt (tracing stop)\nTracerPid:\t4321\n",
                },
            )
            task_runner.initialize()
            self.assertEqual(180, task_runner.exited, task_runner.log)

            # 5. Cross-call SIGSTOP freeze pause (> 2.5s wall time with < 150ms process CPU time) between calls -> die(180)
            freeze_runner = Runner(data=raw)
            freeze_runner.initialize()
            self.assertIsNone(freeze_runner.exited, freeze_runner.log)
            self.assertEqual(45, freeze_runner.exported("sample_add", 1, 2))
            freeze_runner.clock_wall_ns += 5_000_000_000  # 5s external SIGSTOP pause
            freeze_runner.clock_cpu_ns += 10_000_000     # 10ms CPU progress
            freeze_runner.exported("sample_add", 1, 2)
            self.assertEqual(180, freeze_runner.exited, freeze_runner.log)

    def test_adaptive_execution_order_and_multi_conflict_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            # 1. E08 wrap_elf layers cleanly AFTER E06 + ALL in-place passes (Crypto + VM + Flatten + Obf + R09 + IDA)
            layered_out = Path(tmp) / "liblayered_e08.so"
            res_wrap = protect(
                self.source,
                layered_out,
                Options(
                    clean_metadata=True,
                    strip_symbols=True,
                    encrypt_text=True,
                    encrypt_rodata=True,
                    encrypt_strings=True,
                    ephemeral_strings=True,
                    auth_encryption=True,
                    sign_manifest=True,
                    masked_key=True,
                    obfuscate_ops=True,
                    flatten_cfg=True,
                    flatten_functions="sample_init_argc",
                    virtualize_auto=True,
                    obfuscate_jni=True,
                    gg_honeypot=True,
                    anti_gg=True,
                    troll_ida=True,
                    block_ida=True,
                    wrap_elf=True,
                    watermark="layered-e08",
                    verify_semantics=True,
                    seed=77,
                ),
            )
            ver_wrap = verify_file(layered_out)
            self.assertEqual("passed", ver_wrap["status"])
            self.assertTrue(ver_wrap["watermark_verified"])
            ledger = res_wrap["details"]["pass_ledger"]
            self.assertEqual("layered_in_place_plus_e08_wrapper", ledger["mode"])
            for pid in ("E01", "E02", "E03", "E06", "E08", "O07", "O08", "R09", "A08"):
                self.assertIn(pid, ledger["active_roadmap_ids"])
            self.assertTrue(any("E06" in step for step in ledger["execution_order"]))
            self.assertTrue(any("E08" in step for step in ledger["execution_order"]))
            wrapped_exports = {s[0] for s in ELF(layered_out.read_bytes()).exported_symbols()}
            for exp_fn in ("sample_add", "JNI_OnLoad", "Java_com_example_Sample_nativeValue", "sample_secret"):
                self.assertIn(exp_fn, wrapped_exports)

            # 2. obfuscate_jni adapts automatically around explicit R07 on_demand_functions
            jni_r07_out = Path(tmp) / "libjni_r07.so"
            res_jni = protect(
                self.source,
                jni_r07_out,
                Options(
                    compat_layout=True,
                    obfuscate_jni=True,
                    on_demand_functions="Java_com_example_Sample_nativeValue",
                    seed=19,
                ),
            )
            self.assertIn("execution_order", res_jni["details"]["pass_ledger"])
            runner = Runner(data=jni_r07_out.read_bytes())
            runner.initialize()
            self.assertIsNone(runner.exited, runner.log)
            self.assertEqual(42, runner.exported("Java_com_example_Sample_nativeValue", 0, 0))

            # 3. E03+ ephemeral_strings without E03 encrypt_strings raises ProtectionError
            with self.assertRaises(ProtectionError):
                protect(
                    self.source,
                    Path(tmp) / "bad_ephemeral.so",
                    Options(compat_layout=True, encrypt_strings=False, ephemeral_strings=True),
                )

        # 4. analyze_option_conflicts: E08 is compatible with all in-place passes; genuine conflicts only mark active keys
        diag = analyze_option_conflicts(
            Options(
                wrap_elf=True,
                encrypt_text=True,
                encrypt_functions="sample_add",
                ephemeral_strings=True,
                encrypt_strings=False,
                virtualize_functions="sample_add",
                flatten_functions="sample_add",
                denylist_functions="sample_add",
                troll_ida=True,
                troll_barcode_chars="   ",
                troll_barcode_length=8,
                verify_semantics=True,
            ),
            elf=self.original,
            ndk=r"C:\nonexistent_ndk_for_conflict_test",
            unicorn_available=False,
        )
        codes = {c["code"] for c in diag["conflicts"]}
        self.assertNotIn("E08_VS_IN_PLACE", codes)
        for expected_code in (
            "E01_WHOLE_VS_FUNC",
            "EPHEMERAL_REQUIRES_VAULT",
            "MULTI_BACKEND_FUNC",
            "TARGET_IN_DENYLIST",
            "BARCODE_CHARS",
            "F03_NO_UNICORN",
            "NDK_MISSING",
        ):
            self.assertIn(expected_code, codes, codes)
        err_map = diag["option_errors"]
        for expected_key in (
            "wrap_elf",
            "encrypt_text",
            "encrypt_functions",
            "ephemeral_strings",
            "virtualize_functions",
            "flatten_functions",
            "denylist_functions",
            "troll_barcode_chars",
            "verify_semantics",
            "ndk_path",
        ):
            self.assertIn(expected_key, err_map, err_map)
        # Never paint unchecked encrypt_strings switch red when only ephemeral_strings is ON
        self.assertNotIn("encrypt_strings", err_map, err_map)

        # 5. F03 shipped Runner & resilient skipped/failed semantic handling
        f03_ok = verify_function_semantics_unicorn(self.original.data, self.rewritten(virtualize_auto=True), "sample_add")
        self.assertEqual("passed", f03_ok["status"])
        # External unmodeled symbol/syscall in original ELF degrades gracefully to "skipped" instead of crashing builds
        f03_skip = verify_function_semantics_unicorn(b"\x00\x00\x00\x00", self.original.data, "sample_add")
        self.assertEqual("skipped", f03_skip["status"])
        # Corrupting a protected exported function result yields "failed" mismatch
        tampered_bytes = bytearray(self.original.data)
        add_sym = next(s for s in self.original.symbols() if s["name"] == "sample_add")
        # Overwrite sample_add prologue with MOV X0, #999; RET (D2807CE0 D65F03C0)
        add_off = self.original.file_offset(add_sym["value"], 8)
        tampered_bytes[add_off:add_off + 8] = struct.pack("<II", 0xD2807CE0, 0xD65F03C0)
        f03_fail = verify_function_semantics_unicorn(self.original.data, bytes(tampered_bytes), "sample_add")
        self.assertEqual("failed", f03_fail["status"])
        self.assertGreater(len(f03_fail["mismatches"]), 0)

        # 6. Auto-select excludes functions with external mid-body branches and ranks substantive FDEs over tiny stubs
        from protect3.arm64 import FunctionInfo, _mark_external_midbody_branch_targets, encode_b
        text_sec = self.original.section(".text")
        synthetic_elf_bytes = bytearray(self.original.data)
        target_mid_va = add_sym["value"] + 4
        # Patch sample_init_argc (or a dead slot inside sample_secret after RET if external) to branch mid-body into sample_add
        sec_sym = next(s for s in self.original.symbols() if s["name"] == "sample_secret")
        sec_off = self.original.file_offset(sec_sym["value"], 4)
        struct.pack_into("<I", synthetic_elf_bytes, sec_off, encode_b(sec_sym["value"], target_mid_va, link=False))
        syn_elf = ELF(bytes(synthetic_elf_bytes))
        syn_add = FunctionInfo("syn_add", add_sym["value"], add_sym["size"], source="eh_frame_fde", confidence="high", insn_count=add_sym["size"] // 4, relocatable=True, vm_compatible=True)
        syn_sec = FunctionInfo("syn_sec", sec_sym["value"], sec_sym["size"], source="symbol_dynsym", confidence="high", insn_count=sec_sym["size"] // 4, relocatable=True, vm_compatible=True)
        _mark_external_midbody_branch_targets(syn_elf, [syn_add, syn_sec] if syn_add.vaddr < syn_sec.vaddr else [syn_sec, syn_add])
        self.assertFalse(syn_add.relocatable)
        self.assertIn("external_mid_body_branch_target", syn_add.skip_reasons)
        self.assertTrue(syn_sec.relocatable)

        # Prioritization: on >=50 stripped FDE functions, planner prefers >=12-insn substantive FDEs over 2-insn stubs and scales caps above 2
        many_funcs = [
            FunctionInfo(f"fde_stub_{i}", text_sec.addr + i * 8, 8, source="eh_frame_fde", confidence="high", insn_count=2, block_count=1, relocatable=True, vm_compatible=True, sensitivity_score=2, cost_score=5)
            for i in range(40)
        ] + [
            FunctionInfo(f"fde_logic_{i}", text_sec.addr + 0x200 + i * 64, 64, source="eh_frame_fde", confidence="high", insn_count=16, block_count=3, relocatable=True, vm_compatible=True, sensitivity_score=45, cost_score=17)
            for i in range(20)
        ]
        plan_big = build_protection_plan(
            self.original,
            Options(virtualize_auto=True, flatten_cfg=False, obfuscate_ops=False, auto_select_functions=True),
            pre_strip_functions=many_funcs,
        )
        vm_chosen = [a.name for a in plan_big.function_actions if a.backend == "vm"]
        self.assertEqual(8, len(vm_chosen), vm_chosen)
        self.assertTrue(all(n.startswith("fde_logic_") for n in vm_chosen), vm_chosen)

    def test_vm_call_abi_x1_x8_stack_args_and_e03_gate_safety(self):
        from protect3.runtime import command, ndk_tool

        # 1. Verify E03+ ephemeral strings remain valid when unrelated gated helper functions execute before string read
        e03_gate_so = self.rewritten(
            encrypt_strings=True,
            ephemeral_strings=True,
            virtualize_functions="sample_add",
            runtime_integrity=True,
            gg_honeypot=True,
            anti_gg=True,
            diagnostics=True,
        )
        r_str = Runner(data=e03_gate_so)
        r_str.initialize()
        self.assertIsNone(r_str.exited, r_str.log)
        s_ptr = r_str.exported("sample_secret")
        for _ in range(4):
            self.assertEqual(45, r_str.exported("sample_add", 1, 2))
        self.assertEqual("Protect3 fixture string for rodata encryption", r_str.string(s_ptr))

        # 2. Verify O08 VM preserves X8 (sret), (X0, X1) 128-bit return pair, and outgoing [SP] stack arguments
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            c_file = t / "vm_abi.c"
            so_orig = t / "libvmabi.so"
            so_prot = t / "libvmabi.prot.so"
            c_file.write_text(
                """
struct Pair { unsigned long a; unsigned long b; };
struct Big { unsigned long v[4]; };
__attribute__((noinline)) struct Pair make_pair(unsigned long x) {
    struct Pair p = {x + 11ul, x * 3ul + 7ul};
    return p;
}
__attribute__((noinline)) struct Big make_big(unsigned long x) {
    struct Big b = {x + 1ul, x + 2ul, x + 3ul, x + 4ul};
    return b;
}
__attribute__((noinline)) unsigned long sum10(
    unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3, unsigned long a4,
    unsigned long a5, unsigned long a6, unsigned long a7, unsigned long a8, unsigned long a9
) {
    return a0 + a1*2 + a2*3 + a3*4 + a4*5 + a5*6 + a6*7 + a7*8 + a8*9 + a9*10;
}
unsigned long test_abi(unsigned long seed) {
    struct Pair p = make_pair(seed);
    struct Big b = make_big(seed);
    unsigned long s = sum10(1, 2, 3, 4, 5, 6, 7, 8, seed + 9, seed + 10);
    return p.a + p.b + b.v[0] + b.v[3] + s;
}
void original_init(int a, char **b, char **c) { (void)a; (void)b; (void)c; }
""",
                encoding="utf-8",
            )
            command([
                ndk_tool("clang"), "--target=aarch64-linux-android23", "-shared", "-fPIC", "-O1",
                "-nostdlib", "-Wl,--hash-style=both", "-Wl,-z,max-page-size=16384", "-Wl,-init,original_init",
                str(c_file), "-o", str(so_orig),
            ])
            protect(
                so_orig,
                so_prot,
                Options(
                    virtualize_functions="test_abi",
                    runtime_integrity=True,
                    gg_honeypot=True,
                    anti_gg=True,
                    auth_encryption=True,
                    sign_manifest=True,
                ),
            )
            f03 = verify_function_semantics_unicorn(
                so_orig.read_bytes(),
                so_prot.read_bytes(),
                "test_abi",
                test_vectors=[(0,), (1,), (7,), (1234,)],
            )
            self.assertEqual("passed", f03["status"], f03)

    def test_zero_guard_strings_and_stealth_magic_opsec(self):
        # Neither in-place nor E09 packed output should expose plaintext guard strings or ASCII PROTECT3 headers.
        forbidden = (
            b"PROTECT3",
            b"Protect3",
            b"EXT-v3",
            b"/proc/self/maps",
            b"/proc/self/status",
            b"/proc/self/wchan",
            b"TracerPid:",
            b"frida-agent",
            b"/data/local/tmp",
            b"libdl.so",
        )
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            out_inplace = t / "libinplace.so"
            out_packed = t / "libpacked.so"
            protect(
                self.source,
                out_inplace,
                Options(
                    encrypt_text=True, encrypt_rodata=True, encrypt_data=True,
                    obfuscate_guard=True, sign_manifest=True, clean_metadata=True,
                ),
            )
            protect(self.source, out_packed, Options(profile="max"))
            for path in (out_inplace, out_packed):
                raw = path.read_bytes()
                for marker in forbidden:
                    self.assertNotIn(marker, raw, f"Plaintext marker {marker!r} leaked in {path.name}")
                with self.assertRaises(ProtectionError):
                    protect(path, t / "reprotect.so", Options())

    def test_o10_guard_self_obfuscation_and_r06_tamper_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            out = t / "libo10.so"
            res = protect(
                self.source,
                out,
                Options(
                    obfuscate_guard=True,
                    guard_self_check=True,
                    sign_manifest=True,
                    obfuscate_ops=True,
                    diagnostics=True,
                    seed=1337,
                ),
            )
            inj = res["details"]["injection"]
            self.assertIn("O10", inj["active_roadmap_ids"])
            self.assertGreaterEqual(inj["obfuscated_guard"]["obfuscated_guard_functions"], 20)
            self.assertGreater(inj["obfuscated_guard"]["guard_ext_size"], 0)

            out_bytes = bytearray(out.read_bytes())
            runner = Runner(data=bytes(out_bytes))
            runner.initialize()
            self.assertIsNone(runner.exited, runner.log)
            self.assertIn(b"event=guard_self_check_ok", runner.log)
            self.assertEqual(45, runner.exported("sample_add", 1, 2))

            # Tampering relocated O10 guard block must trigger R06 failure (code 175).
            ext_sz = inj["obfuscated_guard"]["guard_ext_size"]
            ext_off = ELF(bytes(out_bytes)).file_offset(inj["obfuscated_guard"]["guard_ext_vaddr"], ext_sz)
            out_bytes[ext_off + ext_sz - 8] ^= 0xFF
            tampered = Runner(data=bytes(out_bytes))
            tampered.initialize()
            self.assertEqual(175, tampered.exited)

    def test_e02_unwind_and_sparse_data_encryption_preserves_runtime(self):
        from protect3.runtime import command, ndk_tool

        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            c_file = t / "data_unwind.c"
            so_orig = t / "libdata.so"
            so_prot = t / "libdata.prot.so"
            c_file.write_text(
                """
extern unsigned long sample_cb(unsigned long x);
__attribute__((noinline)) unsigned long helper_fn(unsigned long x) { return x + 77ul; }
char rw_secret[48] = "SUPER_SECRET_RW_DATA_STRING_9876543210";
unsigned long (*rw_fn_ptr)(unsigned long) = helper_fn;
const char ro_marker[] = "READONLY_RODATA_MARKER_XYZ";
const char *get_rw_secret(void) { return rw_secret; }
const char *get_ro_marker(void) { return ro_marker; }
unsigned long call_rw_ptr(unsigned long x) { return rw_fn_ptr(x); }
void original_init(int a, char **b, char **c) { (void)a; (void)b; (void)c; }
""",
                encoding="utf-8",
            )
            command([
                ndk_tool("clang"), "--target=aarch64-linux-android23", "-shared", "-fPIC", "-O2",
                "-nostdlib", "-Wl,-z,max-page-size=16384", "-Wl,-init,original_init",
                str(c_file), "-o", str(so_orig),
            ])
            res = protect(
                so_orig,
                so_prot,
                Options(
                    encrypt_rodata=True,
                    encrypt_data=True,
                    auth_encryption=True,
                    sign_manifest=True,
                    masked_key=True,
                    diagnostics=True,
                ),
            )
            prot_raw = so_prot.read_bytes()
            enc_secs = res["details"]["injection"]["encrypted_sections"]
            self.assertIn(".rodata", enc_secs)
            self.assertIn(".data", enc_secs)
            self.assertIn(".eh_frame", enc_secs)
            self.assertNotIn(b"SUPER_SECRET_RW_DATA_STRING_9876543210", prot_raw)
            self.assertNotIn(b"READONLY_RODATA_MARKER_XYZ", prot_raw)

            runner = Runner(data=prot_raw)
            runner.initialize()
            self.assertIsNone(runner.exited, runner.log)
            self.assertIn(b"event=data_decrypt_ok", runner.log)
            self.assertEqual("SUPER_SECRET_RW_DATA_STRING_9876543210", runner.string(runner.exported("get_rw_secret")))
            self.assertEqual("READONLY_RODATA_MARKER_XYZ", runner.string(runner.exported("get_ro_marker")))
            self.assertEqual(87, runner.exported("call_rw_ptr", 10))

    def test_e09_pack_elf_deflate_relocs_imports_relro_antidump_and_live_libdl_runner(self):
        from unicorn import UC_PROT_ALL
        from protect3.runtime import command, ndk_tool

        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            mock_c = t / "mockdl.c"
            mock_so = t / "libmockdl.so"
            app_c = t / "app.c"
            app_so = t / "libapp.so"
            packed_so = t / "libapp.packed.so"

            mock_c.write_text(
                """
static int eq_str(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == 0 && *b == 0;
}
unsigned long mock_ext_add(unsigned long a, unsigned long b) { return a + b + 1000ul; }
void *dlopen(const char *path, int mode) { (void)path; (void)mode; return (void *)0x20000001; }
void *dlsym(void *handle, const char *name) {
    (void)handle;
    if (eq_str(name, "mock_ext_add")) return (void *)&mock_ext_add;
    return 0;
}
""",
                encoding="utf-8",
            )
            command([
                ndk_tool("clang"), "--target=aarch64-linux-android23", "-shared", "-fPIC", "-O2",
                "-nostdlib", "-Wl,--hash-style=both", "-Wl,-z,max-page-size=16384",
                str(mock_c), "-o", str(mock_so),
            ])

            app_c.write_text(
                """
extern unsigned long mock_ext_add(unsigned long a, unsigned long b);
__attribute__((noinline)) unsigned long internal_fn(unsigned long v) { return v * 2ul; }
unsigned long (*const relro_table[2])(unsigned long) = { internal_fn, internal_fn };
const char exported_data_obj[20] = "STT_OBJECT_OK";
char rw_banner[40] = "PACKED_RW_BANNER_SECRET_01234";
const char ro_banner[] = "PACKED_RO_BANNER_SECRET_56789";
static int ctor_ran = 0;
__attribute__((constructor)) static void my_ctor(void) { ctor_ran = 1; }
unsigned long call_all(unsigned long x) {
    return mock_ext_add(x, relro_table[0](x)) + (unsigned long)ctor_ran;
}
const char *get_ro(void) { return ro_banner; }
const char *get_rw(void) { return rw_banner; }
""",
                encoding="utf-8",
            )
            command([
                ndk_tool("clang"), "--target=aarch64-linux-android23", "-shared", "-fPIC", "-O2",
                "-nostdlib", f"-L{t}", "-lmockdl", "-Wl,--allow-shlib-undefined",
                "-Wl,-z,max-page-size=16384", "-Wl,-z,relro", "-Wl,-z,now",
                str(app_c), "-o", str(app_so),
            ])

            res = protect(
                app_so,
                packed_so,
                Options(
                    pack_elf=True,
                    obfuscate_guard=True,
                    encrypt_data=True,
                    encrypt_rodata=True,
                    auth_encryption=True,
                    sign_manifest=True,
                    masked_key=True,
                    diagnostics=True,
                ),
            )
            packed_raw = packed_so.read_bytes()
            packed_elf = ELF(packed_raw)
            inj = res["details"]["injection"]
            self.assertEqual("compressed_in_memory_packer", inj["mode"])
            self.assertIn("E09", inj["active_roadmap_ids"])
            self.assertIn("O10", inj["active_roadmap_ids"])
            # 0 plaintext banners/imports, STT_OBJECT preserved, PT_GNU_RELRO preserved, 0 RELA sections
            self.assertNotIn(b"PACKED_RO_BANNER_SECRET_56789", packed_raw)
            self.assertNotIn(b"PACKED_RW_BANNER_SECRET_01234", packed_raw)
            self.assertNotIn(b"mock_ext_add", packed_raw)
            self.assertEqual([], [s for s in packed_elf.sections if s.type in (4, 9)])
            self.assertEqual([], [s for s in packed_elf.symbols(dynamic_only=True) if not s["shndx"] and s["name"]])
            self.assertIn("exported_data_obj", {s[0] for s in packed_elf.exported_symbols()})
            self.assertTrue(any(s.type == 0x6474E552 for s in packed_elf.segments))

            mock_bytes = mock_so.read_bytes()
            mock_elf = ELF(mock_bytes)
            mock_bias = 0x20000000
            runner = Runner(
                data=packed_raw,
                files={
                    "/proc/self/maps": (
                        "10000000-10010000 r-xp 00000000 00:00 1 /data/app/libapp.so\n"
                        "20000000-20020000 r-xp 00000000 00:00 2 /system/lib64/libdl.so\n"
                    ).encode(),
                    "/proc/net/tcp": b"",
                    "/proc/net/tcp6": b"",
                },
            )
            runner.uc.mem_map(mock_bias, 0x20000, UC_PROT_ALL)
            for seg in mock_elf.loads:
                runner.uc.mem_write(mock_bias + seg.vaddr, mock_bytes[seg.offset:seg.offset + seg.filesz])
            mock_syms = mock_elf.symbols(dynamic_only=True)
            for rsec in mock_elf.sections:
                if rsec.type == 4:
                    rdata = mock_elf.section_data(rsec)
                    for roff in range(0, len(rdata), 24):
                        r_off, r_info, r_add = struct.unpack_from("<QQq", rdata, roff)
                        sym_i = r_info >> 32
                        val = mock_bias + (mock_syms[sym_i]["value"] if sym_i < len(mock_syms) else 0) + r_add
                        runner.uc.mem_write(mock_bias + r_off, struct.pack("<Q", val))

            runner.initialize()
            self.assertIsNone(runner.exited, runner.log)
            self.assertIn(b"event=pack_unpack_ok", runner.log)
            self.assertTrue(any(c[2] == 4 for c in runner.madvise_calls), "MADV_DONTNEED not called on LOAD_PACK")
            self.assertTrue(any(p[2] == 0 for p in runner.protections), "PROT_NONE lockdown not called on LOAD_PACK")
            self.assertEqual(1016, runner.exported("call_all", 5))
            self.assertEqual("PACKED_RO_BANNER_SECRET_56789", runner.string(runner.exported("get_ro")))
            self.assertEqual("PACKED_RW_BANNER_SECRET_01234", runner.string(runner.exported("get_rw")))

            # Tampering LOAD_PACK ciphertext must fail pre-decryption E04 HMAC before decompression.
            bad = bytearray(packed_raw)
            pack_off = packed_elf.loads[-1].offset
            bad[pack_off + 8] ^= 0xFF
            bad_runner = Runner(data=bytes(bad))
            bad_runner.initialize()
            self.assertEqual(175, bad_runner.exited)

    def test_r08_frida_tcp_69a2_port_probe(self):
        clean_so, _ = rewrite(
            self.original,
            Options(hooks=True, deep_probes=True, integrity=True),
            *load_runtime(),
        )
        r_clean = Runner(
            data=clean_so,
            files={"/proc/net/tcp": b"sl local_address\n 0: 0100007F:1F90 00000000:0000 0A\n", "/proc/net/tcp6": b""},
        )
        r_clean.initialize()
        self.assertIsNone(r_clean.exited, r_clean.log)

        r_frida = Runner(
            data=clean_so,
            files={"/proc/net/tcp": b"sl local_address\n 0: 0100007F:69A2 00000000:0000 0A\n", "/proc/net/tcp6": b""},
        )
        r_frida.initialize()
        self.assertEqual(172, r_frida.exited)

    def test_o08_vm_mrs_tpidr_and_reg_indexing(self):
        from unicorn import UC_PROT_ALL
        from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
        from protect3.runtime import command, ndk_tool

        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            c_file = t / "vm_tpidr.c"
            so_orig = t / "libtpidr.so"
            so_prot = t / "libtpidr.vm.so"
            c_file.write_text(
                """
static const unsigned long table[6] = {3ul, 9ul, 27ul, 81ul, 243ul, 729ul};
unsigned long compute_with_tpidr(unsigned long idx) {
    unsigned long tp = 0;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
    unsigned long safe_i = idx & 3ul;
    unsigned long sub_term = idx - safe_i * 3ul;
    return (tp ^ table[safe_i]) + sub_term;
}
void original_init(int a, char **b, char **c) { (void)a; (void)b; (void)c; }
""",
                encoding="utf-8",
            )
            command([
                ndk_tool("clang"), "--target=aarch64-linux-android23", "-shared", "-fPIC", "-O2",
                "-fstack-protector-strong", "-nostdlib", "-Wl,-z,max-page-size=16384", "-Wl,-init,original_init",
                str(c_file), "-o", str(so_orig),
            ])
            protect(
                so_orig,
                so_prot,
                Options(virtualize_functions="compute_with_tpidr", auth_encryption=True, sign_manifest=True),
            )
            tp_base = 0x60000000
            for idx_arg in (0, 2, 5, 13):
                r_o = Runner(data=so_orig.read_bytes())
                r_o.uc.mem_map(tp_base, 0x1000, UC_PROT_ALL)
                r_o.uc.mem_write(tp_base + 40, struct.pack("<Q", 0xCAFEBABE12345678))
                r_o.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, tp_base)
                r_o.initialize()
                exp = r_o.exported("compute_with_tpidr", idx_arg)

                r_p = Runner(data=so_prot.read_bytes())
                r_p.uc.mem_map(tp_base, 0x1000, UC_PROT_ALL)
                r_p.uc.mem_write(tp_base + 40, struct.pack("<Q", 0xCAFEBABE12345678))
                r_p.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, tp_base)
                r_p.initialize()
                act = r_p.exported("compute_with_tpidr", idx_arg)
                self.assertEqual(exp, act)

    def test_e09_takes_precedence_over_e08_when_target_exports_stt_object(self):
        from protect3.runtime import command, ndk_tool

        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            c_file = t / "obj_export.c"
            so_orig = t / "libobjexport.so"
            so_pack = t / "libobjexport.pack.so"
            c_file.write_text(
                """
const int exported_magic_data = 0x12345678;
int add_with_data(int x) { return x + exported_magic_data; }
void original_init(int a, char **b, char **c) { (void)a; (void)b; (void)c; }
""",
                encoding="utf-8",
            )
            command([
                ndk_tool("clang"), "--target=aarch64-linux-android23", "-shared", "-fPIC", "-O2",
                "-nostdlib", "-Wl,-z,max-page-size=16384", "-Wl,-init,original_init",
                str(c_file), "-o", str(so_orig),
            ])
            with self.assertRaises(ProtectionError) as ctx:
                protect(so_orig, so_pack, Options(wrap_elf=True))
            self.assertIn("--pack-elf", str(ctx.exception))

            res = protect(so_orig, so_pack, Options(pack_elf=True, wrap_elf=True))
            active_ids = res["details"]["pass_ledger"]["active_roadmap_ids"]
            self.assertIn("E09", active_ids)
            self.assertNotIn("E08", active_ids)
            packed_elf = ELF(so_pack.read_bytes())
            self.assertIn("exported_magic_data", {s[0] for s in packed_elf.exported_symbols()})

    def test_sequential_coexistence_with_e09_and_hard_conflict_e09_vs_e08(self):
        # Genuine conflict E09_VS_E08 marks both options red in conflict analyzer
        diag_both = analyze_option_conflicts(Options(pack_elf=True, wrap_elf=True), elf=self.original)
        self.assertIn("E09_VS_E08", {c["code"] for c in diag_both["conflicts"]})
        self.assertIn("pack_elf", diag_both["option_errors"])
        self.assertIn("wrap_elf", diag_both["option_errors"])

        # All compatible passes + F03 semantics + E09 packer sequence cleanly without conflict
        full_opt = Options(
            clean_metadata=True,
            strip_symbols=True,
            encrypt_text=True,
            encrypt_rodata=True,
            encrypt_data=True,
            encrypt_strings=True,
            ephemeral_strings=True,
            auth_encryption=True,
            sign_manifest=True,
            masked_key=True,
            obfuscate_ops=True,
            flatten_cfg=True,
            flatten_functions="sample_init_argc",
            virtualize_auto=True,
            obfuscate_jni=True,
            obfuscate_guard=True,
            guard_self_check=True,
            gg_honeypot=True,
            anti_gg=True,
            troll_ida=True,
            block_ida=True,
            pack_elf=True,
            compat_layout=True,
            verify_semantics=True,
            seed=91,
        )
        diag_full = analyze_option_conflicts(full_opt, elf=self.original)
        self.assertEqual([], diag_full["conflicts"], diag_full["conflicts"])
        self.assertIsNotNone(diag_full.get("plan"))

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "libfull_e09_f03.so"
            res = protect(self.source, out, full_opt)
            ledger = res["details"]["pass_ledger"]
            for pid in ("F03", "E01", "E02", "E03", "E06", "E09", "O07", "O08", "O10", "R09"):
                self.assertIn(pid, ledger["active_roadmap_ids"])
            sems = ledger["differential_semantics_F03"]
            self.assertTrue(any(r.get("status") == "passed" for r in sems), sems)


if __name__ == "__main__":
    unittest.main()
