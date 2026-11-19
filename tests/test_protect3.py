from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from protect3.crypto import chacha20
from protect3.elf import ELF, ProtectionError
from protect3.engine import Options, protect, rewrite, verify_file
from protect3.runtime import command, load_runtime, ndk_tool
from tests.arm64_runner import Runner
from tests.fixtures import build_fixtures


class ProtectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = build_fixtures()
        cls.original = ELF(cls.source.read_bytes())
        cls.blob, cls.meta = load_runtime()

    def rewritten(self, **options):
        return rewrite(self.original, Options(**options), self.blob, self.meta)[0]

    def test_python_chacha20_rfc8439_vector(self):
        expected = bytes.fromhex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
        actual = chacha20(bytes(64), bytes(range(32)), bytes.fromhex("000000090000004a00000000"), 1)
        self.assertEqual(expected, actual)

    def test_native_sha256_padding_boundaries(self):
        runner = Runner(blob=self.blob)
        for size in (0, 1, 3, 55, 56, 63, 64, 65, 127, 128, 1000):
            with self.subTest(size=size):
                data = bytes(i % 251 for i in range(size))
                if data:
                    runner.uc.mem_write(runner.scratch, data)
                runner.call(runner.bias + self.meta["symbols"]["p3_sha256"], runner.scratch, size, runner.scratch+0x2000)
                actual = bytes(runner.uc.mem_read(runner.scratch+0x2000,32))
                self.assertEqual(hashlib.sha256(data).digest(), actual)

    def test_native_chacha20_matches_rfc_and_partial_blocks(self):
        runner = Runner(blob=self.blob)
        key, nonce = bytes(range(32)), bytes.fromhex("000000090000004a00000000")
        runner.uc.mem_write(runner.scratch+0x4000, key)
        runner.uc.mem_write(runner.scratch+0x4100, nonce)
        for size in (1, 63, 64, 65, 114, 1024):
            with self.subTest(size=size):
                data = bytes(i % 251 for i in range(size))
                runner.uc.mem_write(runner.scratch, data)
                runner.call(runner.bias+self.meta["symbols"]["p3_chacha20"], runner.scratch, size,
                            runner.scratch+0x4000, runner.scratch+0x4100, 1)
                self.assertEqual(chacha20(data,key,nonce), bytes(runner.uc.mem_read(runner.scratch,size)))

    def test_original_fixture_constructor_order(self):
        runner = Runner(data=self.original.data)
        runner.initialize()
        self.assertEqual(45, runner.exported("sample_add",1,2))

    def test_plain_guard_preserves_abi_jni_constructor_arguments_and_rebasing(self):
        data = self.rewritten()
        elf = ELF(data)
        self.assertEqual(self.original.exported_symbols(), elf.exported_symbols())
        self.assertTrue(elf.summary()["elf_16k_alignment"])
        self.assertFalse(elf.summary()["has_rwx"])
        for bias in (0x10000000, 0x40000000):
            with self.subTest(bias=bias):
                runner = Runner(data=data,bias=bias)
                runner.initialize(argc=7)
                self.assertIsNone(runner.exited, runner.log)
                self.assertEqual(45, runner.exported("sample_add",1,2))
                self.assertEqual(7, runner.exported("sample_init_argc"))
                self.assertEqual(42, runner.exported("Java_com_example_Sample_nativeValue",0,0))
                self.assertEqual(0x10006, runner.exported("JNI_OnLoad",0,0))

    def test_encryption_restores_exact_text_and_never_requests_rwx(self):
        data = self.rewritten(encrypt_text=True)
        text = self.original.section(".text")
        self.assertNotEqual(self.original.section_data(text), ELF(data).section_data(ELF(data).section(".text")))
        for page_size in (4096,16384):
            with self.subTest(page_size=page_size):
                runner = Runner(data=data,page_size=page_size)
                runner.initialize()
                self.assertIsNone(runner.exited, runner.log)
                self.assertEqual(self.original.section_data(text), bytes(runner.uc.mem_read(runner.bias+text.addr,text.size)))
                self.assertEqual([3,5], [p[2] for p in runner.protections])
                self.assertEqual(45, runner.exported("sample_add",1,2))

    def test_rodata_encryption_restores_strings_with_and_without_text(self):
        for text in (False,True):
            for compat in (False,True):
                with self.subTest(text=text,compat=compat):
                    data=self.rewritten(encrypt_text=text,encrypt_rodata=True,compat_layout=compat,diagnostics=True)
                    self.assertNotIn(b"Protect3 fixture string for rodata encryption",data)
                    runner=Runner(data=data)
                    runner.initialize()
                    self.assertIsNone(runner.exited,runner.log)
                    address=runner.exported("sample_secret")
                    self.assertEqual("Protect3 fixture string for rodata encryption",runner.string(address))
                    self.assertEqual(45,runner.exported("sample_add",1,2))
                    self.assertIn(b"event=rodata_decrypt_ok",runner.log)
                    self.assertIn(b"event=guard_return",runner.log)
                    self.assertTrue(all(p[2]!=7 for p in runner.protections))

    def test_modified_rodata_fails_before_original_code(self):
        data=bytearray(self.rewritten(encrypt_rodata=True))
        data[self.original.section('.rodata').offset]^=1
        runner=Runner(data=bytes(data));runner.initialize()
        self.assertEqual(175,runner.exited)
        self.assertIn(b"event=fatal code=175",runner.log)
        self.assertIn(b"rodata integrity mismatch",runner.log)

    def test_selected_function_encryption_changes_only_declared_code_range(self):
        original=self.original
        symbol=next(s for s in original.symbols() if s['name']=='JNI_OnLoad')
        start=original.file_offset(symbol['value'],symbol['size']);end=start+symbol['size']
        for compat in (False,True):
            with self.subTest(compat=compat):
                data=self.rewritten(encrypt_function='JNI_OnLoad',compat_layout=compat)
                text=original.section('.text')
                self.assertEqual(original.data[text.offset:start],data[text.offset:start])
                self.assertEqual(original.data[end:text.offset+text.size],data[end:text.offset+text.size])
                self.assertNotEqual(original.data[start:end],data[start:end])
                runner=Runner(data=data);runner.initialize()
                self.assertIsNone(runner.exited,runner.log)
                self.assertEqual(0x10006,runner.exported('JNI_OnLoad',0,0))

    def test_unknown_function_and_conflicting_encryption_refused(self):
        for settings in ({'encrypt_function':'nonexistent'},{'encrypt_function':'JNI_OnLoad','encrypt_text':True}):
            with self.assertRaises(ProtectionError):
                self.rewritten(**settings)

    def test_diagnostics_records_disabled_probes_and_logd_wire_format(self):
        runner=Runner(data=self.rewritten(diagnostics=True))
        runner.initialize()
        for name in (b"hooks",b"root",b"emulator"):
            self.assertIn(b"check="+name+b" status=disabled",runner.log)
        self.assertIn(b"event=original_initializer_returned",runner.log)
        self.assertTrue(runner.android_log)
        self.assertTrue(any(packet[11:].startswith(b"\x04Protect3\0event=guard_start") for packet in runner.android_log))

    def test_rodata_metadata_alias_is_rejected(self):
        from protect3.engine import check_rodata_encryption
        original=self.original
        section=original.section('.rodata')
        data=bytearray(original.data)
        for offset in range(original.dynamic_segment.offset,original.dynamic_segment.offset+original.dynamic_segment.filesz,16):
            if struct.unpack_from('<q',data,offset)[0]==5:
                struct.pack_into('<Q',data,offset+8,section.addr)
        with self.assertRaisesRegex(ProtectionError,'metadata'):
            check_rodata_encryption(ELF(data))

    def test_injects_dt_init_when_original_has_only_init_array(self):
        original = ELF((self.source.parent / "libsample.noinit.so").read_bytes())
        self.assertEqual(0, original.dynamic_value(12))
        for encrypt in (False, True):
            with self.subTest(encrypt=encrypt):
                data, _ = rewrite(original, Options(encrypt_text=encrypt), self.blob, self.meta)
                runner = Runner(data=data)
                runner.initialize()
                self.assertIsNone(runner.exited, runner.log)
                self.assertEqual(45, runner.exported("sample_add",1,2))

    def test_compat_layout_preserves_header_and_dynamic_table_positions(self):
        for encrypt in (False, True):
            with self.subTest(encrypt=encrypt):
                data = self.rewritten(encrypt_text=encrypt, compat_layout=True)
                elf = ELF(data)
                self.assertEqual(self.original.phoff, elf.phoff)
                self.assertEqual(self.original.phnum, elf.phnum)
                self.assertEqual(self.original.dynamic_segment, elf.dynamic_segment)
                self.assertEqual(self.original.section(".dynamic"), elf.section(".dynamic"))
                runner = Runner(data=data)
                runner.initialize(argc=9)
                self.assertIsNone(runner.exited, runner.log)
                self.assertEqual(45, runner.exported("sample_add",1,2))
                self.assertEqual(9, runner.exported("sample_init_argc"))

    def test_compat_layout_hooks_existing_init_array(self):
        original = ELF((self.source.parent / "libsample.noinit.so").read_bytes())
        self.assertEqual(0, original.dynamic_value(12))
        data, injection = rewrite(original, Options(encrypt_text=True, compat_layout=True), self.blob, self.meta)
        elf = ELF(data)
        self.assertEqual(original.dynamic_segment, elf.dynamic_segment)
        self.assertEqual("preserved_tables", injection["layout"])
        self.assertIsNotNone(injection["initializer_hook"])
        self.assertEqual(original.dynamic, elf.dynamic)
        runner = Runner(data=data)
        runner.initialize()
        self.assertIsNone(runner.exited, runner.log)
        self.assertEqual(45, runner.exported("sample_add",1,2))

    def test_compat_layout_preserves_unknown_loader_notes(self):
        data = bytearray(self.original.data)
        for segment in self.original.segments:
            if segment.type == 4:
                struct.pack_into("<I", data, segment.offset+8, 0xAABBCCDD)
        original = ELF(data)
        output, _ = rewrite(original, Options(compat_layout=True), self.blob, self.meta)
        protected = ELF(output)
        self.assertEqual([s for s in original.segments if s.type == 4], [s for s in protected.segments if s.type == 4])

    def test_compat_layout_grows_table_and_preserves_notes_for_crt_library(self):
        original = ELF((self.source.parent/"libsample.standard.so").read_bytes())
        data, injection = rewrite(original, Options(encrypt_text=True,compat_layout=True),self.blob,self.meta)
        elf = ELF(data)
        self.assertTrue(injection["program_header_growth"])
        self.assertEqual(original.phoff,elf.phoff)
        self.assertEqual(original.phnum+1,elf.phnum)
        self.assertEqual(original.dynamic_segment,elf.dynamic_segment)
        self.assertTrue(any(s.type==6 for s in elf.segments))
        for section in original.sections:
            if section.type==7:
                self.assertEqual(original.section_data(section),elf.section_data(elf.section(section.name)))

    def test_patched_code_is_rejected_before_original_init(self):
        for encrypt in (False,True):
            with self.subTest(encrypt=encrypt):
                data = bytearray(self.rewritten(encrypt_text=encrypt))
                text = ELF(data).section(".text")
                data[text.offset+4] ^= 0x40
                runner = Runner(data=bytes(data))
                runner.initialize()
                self.assertEqual(175,runner.exited)

    def test_debugger_detection_and_report_only(self):
        files = {"/proc/self/status": b"Name: test\nTracerPid:\t321\n"}
        for report_only in (False,True):
            with self.subTest(report_only=report_only):
                runner = Runner(data=self.rewritten(report_only=report_only),files=files)
                runner.initialize()
                self.assertEqual(None if report_only else 171,runner.exited)
                self.assertIn(b"debugger detected",runner.log)
                if report_only:
                    self.assertEqual(45,runner.exported("sample_add",1,2))

    def test_frida_and_xposed_native_mapping_indicators(self):
        for name in (b"frida-agent-64.so",b"libfrida-gadget.so",b"libxposed_art.so",b"liblsposed.so"):
            with self.subTest(name=name):
                # Put the match across the scanner's read boundary as well.
                files = {"/proc/self/maps": b"x"*8188+b"/"+name+b"\n"}
                runner = Runner(data=self.rewritten(hooks=True),files=files)
                runner.initialize()
                self.assertEqual(172,runner.exited)

    def test_root_paths_and_zygisk_mapping(self):
        for files,paths in (({},["/system/xbin/su"]),({"/proc/self/maps":b"/data/zygisk/module.so\n"},[])):
            runner = Runner(data=self.rewritten(root=True),files=files,paths=paths)
            runner.initialize()
            self.assertEqual(173,runner.exited)

    def test_emulator_indicators(self):
        for files,paths in (({},["/dev/qemu_pipe"]),({"/proc/cpuinfo":b"Hardware: ranchu\n"},[])):
            runner = Runner(data=self.rewritten(emulator=True),files=files,paths=paths)
            runner.initialize()
            self.assertEqual(174,runner.exited)

    def test_missing_procfs_reports_unknown_or_fails_strictly(self):
        for strict in (False,True):
            runner = Runner(data=self.rewritten(strict_proc=strict),files={"/proc/self/status":None})
            runner.initialize()
            self.assertEqual(178 if strict else None,runner.exited)
            self.assertIn(b"check unavailable",runner.log)

    def test_denied_memory_permission_fails_closed(self):
        runner = Runner(data=self.rewritten(encrypt_text=True),deny_mprotect=True)
        runner.initialize()
        self.assertEqual(176,runner.exited)

    def test_strip_publish_and_local_report_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/"libsample.so"
            result = protect(self.source,output,Options(strip_symbols=True,hooks=True))
            elf = ELF(output.read_bytes())
            self.assertFalse(elf.summary()["has_symtab"])
            self.assertEqual([],elf.summary()["debug_sections"])
            self.assertEqual("passed",verify_file(output)["status"])
            runner = Runner(data=elf.data)
            runner.initialize()
            self.assertEqual(45,runner.exported("sample_add",1,2))
            report = json.loads(Path(result["report"]).read_text(encoding="utf-8"))
            self.assertEqual("not_tested",report["validation"]["android_device_load"])
            self.assertTrue(any(f["feature"] == "ARM64 Function Virtualization" and f["status"] == "disabled" and f["enabled_in_output"] is False for f in report["features"]))
            self.assertTrue(any(f["feature"] == "Native Code Obfuscation" and f["status"] == "enabled" and f["enabled_in_output"] is True for f in report["features"]))
            output.write_bytes(output.read_bytes()+b"tamper")
            with self.assertRaisesRegex(ProtectionError,"SHA-256"):
                verify_file(output)

    def test_existing_output_and_input_are_never_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,output = Path(tmp)/"in.so",Path(tmp)/"out.so"
            source.write_bytes(self.original.data)
            output.write_bytes(b"keep this")
            with self.assertRaises(ProtectionError):
                protect(source,source,force=True)
            with self.assertRaises(ProtectionError):
                protect(source,output)
            self.assertEqual(b"keep this",output.read_bytes())
            self.assertEqual(self.original.data,source.read_bytes())

    def test_double_protection_and_wrong_architecture_rejected(self):
        with self.assertRaisesRegex(ProtectionError,"already"):
            rewrite(ELF(self.rewritten()),Options(),self.blob,self.meta)
        data = bytearray(self.original.data)
        struct.pack_into("<H",data,18,62)
        with self.assertRaisesRegex(ProtectionError,"ARM64"):
            rewrite(ELF(data),Options(),self.blob,self.meta)

    def test_truncated_and_malformed_elf_rejected(self):
        for data in (b"",b"not ELF",self.original.data[:63],self.original.data[:120]):
            with self.subTest(size=len(data)),self.assertRaises(ProtectionError):
                ELF(data)

    def test_llvm_accepts_output_headers_dynamic_and_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"libprotected.so"
            path.write_bytes(self.rewritten())
            result = command([ndk_tool("llvm-readelf"),"--all",str(path)])
            self.assertIn("AArch64",result)
            self.assertIn("JNI_OnLoad",result)
            self.assertIn("INIT",result)

    def test_accepts_gnu_ld_shared_library_with_nonzero_text_entry_but_rejects_executables(self):
        # GNU ld / gold often set e_entry = .text.addr on ET_DYN -shared libraries; Bionic ignores e_entry.
        text_va = self.original.section(".text").addr
        gnu_ld_so = bytearray(self.original.data)
        struct.pack_into("<Q", gnu_ld_so, 24, text_va)
        with tempfile.TemporaryDirectory() as tmp:
            in_so = Path(tmp) / "libgnuld.so"
            out_so = Path(tmp) / "libgnuld.out.so"
            in_so.write_bytes(bytes(gnu_ld_so))
            res = protect(in_so, out_so, Options(pack_elf=True, clean_metadata=True))
            self.assertEqual("passed", verify_file(res["output"], res["report"])["status"])
            self.assertEqual(0, ELF(out_so.read_bytes()).entry)

            # Real ET_EXEC (e_type=2) must still be rejected.
            exe_data = bytearray(self.original.data)
            struct.pack_into("<H", exe_data, 16, 2)
            exe_in = Path(tmp) / "exe_bin.so"
            exe_in.write_bytes(bytes(exe_data))
            with self.assertRaises(ProtectionError):
                protect(exe_in, Path(tmp) / "exe_out.so", Options())


if __name__ == "__main__":
    unittest.main()
