"""Automated regression tests for Qt Quick UI models, ViewModel workers, and zero-warning QML loading."""

import os
from pathlib import Path
import tempfile
import time
import unittest

try:
    from protect3.ui import _configure_qt_dll_paths

    _configure_qt_dll_paths()
    os.environ.setdefault("QT_QUICK_CONTROLS_STYLE", "Basic")
    from PySide6.QtCore import QUrl
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtQml import QQmlApplicationEngine
    import PySide6.QtQuick  # noqa: F401
    from protect3.ui.bridge import Protect3ViewModel

    HAS_PYSIDE6 = True
except Exception:
    HAS_PYSIDE6 = False


@unittest.skipUnless(HAS_PYSIDE6, "PySide6 is required for Qt Quick desktop UI tests")
class QtQuickStudioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QGuiApplication.instance() or QGuiApplication([])
        from tests.fixtures import build_fixtures

        cls.sample_so = build_fixtures()

    def _pump(self, pred, timeout=15.0):
        deadline = time.monotonic() + timeout
        while not pred() and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(0.02)

    def test_qml_shell_loads_without_warnings_and_binds_models(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_appdata = os.environ.get("LOCALAPPDATA")
            os.environ["LOCALAPPDATA"] = tmp
            try:
                vm = Protect3ViewModel()
                engine = QQmlApplicationEngine()
                qml_dir = Path("protect3/ui/qml").resolve()
                engine.addImportPath(str(qml_dir))
                engine.rootContext().setContextProperty("vm", vm)
                engine.rootContext().setContextProperty("fnModel", vm.function_model)
                engine.rootContext().setContextProperty("decoyModel", vm.decoy_model)
                engine.rootContext().setContextProperty("capModel", vm.capabilities_model)

                warnings = []
                engine.warnings.connect(lambda errs: warnings.extend(e.toString() for e in errs))
                engine.load(QUrl.fromLocalFile(str(qml_dir / "Main.qml")))
                self.assertEqual(1, len(engine.rootObjects()))
                self.assertEqual([], warnings)

                win = engine.rootObjects()[0]
                for tab_idx in range(5):
                    win.setProperty("currentTab", tab_idx)
                    self._pump(lambda: False, 0.08)
                self.assertEqual([], warnings)

                # Test Light Mode & Scaled Font sizes across all tabs with zero QML warnings
                vm.darkMode = False
                vm.fontScale = 1.3
                for tab_idx in range(5):
                    win.setProperty("currentTab", tab_idx)
                    self._pump(lambda: False, 0.08)
                self.assertEqual([], warnings)
                win.close()

                # Verify settings persistence & clamping across reloads
                vm2 = Protect3ViewModel()
                self.assertFalse(vm2.darkMode)
                self.assertAlmostEqual(1.3, vm2.fontScale, places=2)
                vm2.fontScale = 9.9
                self.assertAlmostEqual(1.4, vm2.fontScale, places=2)
                vm2.fontScale = 0.2
                self.assertAlmostEqual(0.9, vm2.fontScale, places=2)
                vm2.darkMode = True
                vm2.fontScale = 1.15
                vm3 = Protect3ViewModel()
                self.assertTrue(vm3.darkMode)
                self.assertAlmostEqual(1.15, vm3.fontScale, places=2)
            finally:
                if old_appdata is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = old_appdata

    def test_viewmodel_inspect_filter_assign_protect_benchmark_triage_and_troll(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_appdata = os.environ.get("LOCALAPPDATA")
            os.environ["LOCALAPPDATA"] = tmp
            try:
                vm = Protect3ViewModel()
                out_so = Path(tmp) / "libsample.protected.so"
                # Startup defaults block actively instead of logging passively
                self.assertFalse(vm.options["report_only"])
                self.assertTrue(vm.options["deny_attach"])
                self.assertTrue(vm.options["auto_select_functions"])
                self.assertTrue(vm.options["runtime_anti_debug"])
                # Neutral generic Android defaults (not locked to a single game/lib)
                self.assertEqual("com.example.app", vm.logPackageName)
                vm.sourcePath = str(self.sample_so)
                self.assertEqual(self.sample_so.name, vm.logLibName)
                vm.outputPath = str(out_so)
                vm.forceOverwrite = True

                # Presets and layered E08 compatibility + conflict validation
                vm.applyPreset("max")
                self.assertTrue(vm.options["virtualize_auto"])
                self.assertEqual("", vm.options["profile"])
                vm.setOption("wrap_elf", True)
                self.assertFalse(vm.planHasError, vm.conflictList)
                vm.setOption("obfuscate_ops", False)
                self.assertFalse(vm.options["obfuscate_ops"])
                vm.setOption("encrypt_functions", "sample_add")
                self.assertTrue(vm.planHasError)
                vm.applyPreset("apk_anti_cheat")
                self.assertFalse(vm.options["report_only"])
                self.assertTrue(vm.options["deny_attach"])
                self.assertTrue(vm.options["gg_honeypot"])
                self.assertTrue(vm.options["anti_gg"])
                vm.applyPreset("bluestacks_safe")
                self.assertTrue(vm.options["report_only"])
                self.assertFalse(vm.planHasError)

                # Inspect ELF + Filter + 1-click assignment + autoPopulateFunctions + adaptOptionsToLoadedElf
                vm.inspectLibrary(str(self.sample_so))
                self._pump(lambda: not vm.busy and vm.hasElf, 15.0)
                self.assertGreater(vm.function_model.totalCount, 0)
                vm.autoPopulateFunctions()
                self.assertFalse(vm.planHasError, vm.conflictList)
                self.assertTrue(bool(vm.options["virtualize_functions"] or vm.options["flatten_functions"]))
                vm.setOption("virtualize_functions", "sample_add")
                vm.setOption("flatten_functions", "sample_add")
                self.assertTrue(vm.planHasError)
                vm.adaptOptionsToLoadedElf()
                self.assertFalse(vm.planHasError)
                vm.setOption("virtualize_functions", "")
                vm.setOption("flatten_functions", "")
                vm.function_model.applyFilter("sample_add", "all")
                self.assertEqual(1, vm.function_model.filteredCount)
                vm.toggleFunctionAssignment("sample_add", "virtualize_functions")
                self.assertIn("sample_add", vm.options["virtualize_functions"])
                vm.function_model.applyFilter("", "assigned")
                self.assertGreaterEqual(vm.function_model.filteredCount, 1)
                vm.toggleFunctionAssignment("sample_add", "virtualize_functions")

                # Customize IDA Troll barcode + decoy list
                self.assertGreaterEqual(vm.defaultDecoysCount, 36)
                vm.setOption("troll_barcode_chars", "ab9")
                vm.setOption("troll_barcode_length", 14)
                vm.setOption("seed", "42")
                vm.addDecoy("Custom_Test_Fn", "Chao mung toi F5!", "Nhanh 1337")
                self.assertEqual(vm.defaultDecoysCount + 1, vm.decoy_model.count)
                self.assertTrue(vm.customDecoysModified)
                vm.applyBulkDecoys("Custom_One | One Msg | One Alt\nCustom_Two | Two Msg")
                self.assertEqual(2, vm.decoy_model.count)
                self.assertEqual("Custom_One", vm.getDecoy(0)["name"])

                # Enable F03 Unicorn semantic verification directly inside GUI and run protect + verify
                self.assertTrue(vm.unicornAvailable)
                vm.setOption("verify_semantics", True)
                self.assertFalse(vm.planHasError)
                vm.runProtect()
                self._pump(lambda: not vm.busy and vm.hasVerifyResult, 25.0)
                self.assertTrue(out_so.is_file())
                self.assertEqual("passed", vm.verifyResult["status"])
                self.assertIn("F03", vm.lastProtectMetrics["activeIds"])
                sem_results = vm.lastProtectMetrics["semantics"]
                self.assertGreaterEqual(len(sem_results), 1)
                self.assertTrue(any(r.get("status") == "passed" for r in sem_results), sem_results)
                self.assertEqual(2, vm.lastProtectMetrics["idaMeta"]["decoy_functions_count"])
                self.assertEqual(14, vm.lastProtectMetrics["idaMeta"]["troll_barcode_length"])

                # Benchmark A04-A06
                vm.runBenchmark()
                self._pump(lambda: not vm.busy and vm.hasBenchResult, 15.0)
                self.assertIn("text_4gram_divergence", vm.benchResult["metrics"])

                # Analyze logcat
                sample_log = (
                    "11-18 17:21:02.900 1200 1250 I ActivityManager: Start proc 22148:com.example.app/u0a88\n"
                    "11-18 17:21:03.511 22148 22148 I Protect3: event=guard_start version=2\n"
                    "11-18 17:21:03.595 22148 22148 I Protect3: event=guard_return\n"
                )
                vm.runAnalyzeLog(sample_log, "com.example.app", self.sample_so.name)
                self._pump(lambda: not vm.busy and vm.hasTriageResult, 5.0)
                self.assertEqual(2, len(vm.triageResult["guard_events"]))
            finally:
                if old_appdata is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = old_appdata

    def test_viewmodel_multi_conflict_red_fields_and_autofix(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_appdata = os.environ.get("LOCALAPPDATA")
            os.environ["LOCALAPPDATA"] = tmp
            try:
                vm = Protect3ViewModel()
                engine = QQmlApplicationEngine()
                qml_dir = Path("protect3/ui/qml").resolve()
                engine.addImportPath(str(qml_dir))
                engine.rootContext().setContextProperty("vm", vm)
                engine.rootContext().setContextProperty("fnModel", vm.function_model)
                engine.rootContext().setContextProperty("decoyModel", vm.decoy_model)
                engine.rootContext().setContextProperty("capModel", vm.capabilities_model)

                warnings = []
                engine.warnings.connect(lambda errs: warnings.extend(e.toString() for e in errs))
                engine.load(QUrl.fromLocalFile(str(qml_dir / "Main.qml")))
                self.assertEqual(1, len(engine.rootObjects()))
                win = engine.rootObjects()[0]

                # Verify E08 runs cleanly alongside all passes; genuine conflicts only highlight active switches
                vm.setOption("wrap_elf", True)
                self.assertFalse(vm.planHasError, vm.conflictList)

                # Trigger multiple genuine simultaneous conflicts (and verify OFF switches stay clean)
                vm.setOption("encrypt_text", True)
                vm.setOption("encrypt_functions", "sample_add")
                vm.setOption("encrypt_strings", False)
                vm.setOption("ephemeral_strings", True)
                vm.setOption("virtualize_functions", "sample_add")
                vm.setOption("flatten_functions", "sample_add")
                vm.setOption("troll_ida", True)
                vm.setOption("troll_barcode_chars", "!!")
                vm.setOption("troll_barcode_length", "abc")

                self.assertTrue(vm.planHasError)
                codes = {c["code"] for c in vm.conflictList}
                self.assertTrue(
                    {"E01_WHOLE_VS_FUNC", "EPHEMERAL_REQUIRES_VAULT", "MULTI_BACKEND_FUNC", "BARCODE_CHARS", "INVALID_TROLL_BARCODE_LENGTH"}.issubset(codes),
                    codes,
                )
                self.assertNotIn("E08_VS_IN_PLACE", codes)
                # Ensure unchecked encrypt_strings switch is NOT turned red while E03+ is ON
                self.assertNotIn("encrypt_strings", vm.optionConflicts, vm.optionConflicts)
                for key in ("encrypt_text", "encrypt_functions", "ephemeral_strings", "virtualize_functions", "flatten_functions", "troll_barcode_chars", "troll_barcode_length"):
                    self.assertIn(key, vm.optionConflicts, vm.optionConflicts)

                # Switch across all tabs while red conflicts are visible and confirm 0 QML warnings
                for tab_idx in range(5):
                    win.setProperty("currentTab", tab_idx)
                    self._pump(lambda: False, 0.06)
                self.assertEqual([], warnings)

                # Pre-ELF auto-fix clears option-vs-option conflicts cleanly (including invalid barcode length)
                vm.adaptOptionsToLoadedElf()
                self.assertFalse(vm.planHasError, vm.conflictList)
                self.assertEqual({}, vm.optionConflicts)
                self.assertEqual([], vm.conflictList)

                # Re-introduce conflict with loaded ELF and verify ELF-aware auto-fix clears all errors
                vm.inspectLibrary(str(self.sample_so))
                self._pump(lambda: not vm.busy and vm.hasElf, 15.0)
                vm.setOption("wrap_elf", True)
                vm.setOption("encrypt_text", True)
                vm.setOption("virtualize_functions", "sample_add")
                vm.setOption("flatten_functions", "sample_add")
                self.assertTrue(vm.planHasError)
                win.setProperty("currentTab", 0)
                self._pump(lambda: False, 0.05)
                win.setProperty("currentTab", 1)
                self._pump(lambda: False, 0.05)
                self.assertEqual([], warnings)

                vm.adaptOptionsToLoadedElf()
                self.assertFalse(vm.planHasError, vm.conflictList)
                self.assertEqual({}, vm.optionConflicts)
                win.close()
            finally:
                if old_appdata is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = old_appdata

    def test_startup_autoinspect_and_e08_e09_mutual_exclusion_on_stt_object_elf(self):
        from protect3.runtime import command, ndk_tool
        from protect3.ui.settings import save_settings

        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            c_file = t / "cpp_obj.c"
            so_obj = t / "libobjui.so"
            c_file.write_text(
                """
const int _ZTV10FakeVtable[2] = { 11, 22 };
int fn_with_vtable(int x) { return x + _ZTV10FakeVtable[0]; }
""",
                encoding="utf-8",
            )
            command([
                ndk_tool("clang"), "--target=aarch64-linux-android23", "-shared", "-fPIC", "-O2",
                "-nostdlib", "-Wl,-z,max-page-size=16384", str(c_file), "-o", str(so_obj),
            ])

            old_appdata = os.environ.get("LOCALAPPDATA")
            os.environ["LOCALAPPDATA"] = str(t / "appdata")
            try:
                save_settings({"last_source": str(so_obj), "last_output": str(t / "out.so")})
                vm = Protect3ViewModel()
                self._pump(lambda: not vm.busy and vm.hasElf, 15.0)
                self.assertTrue(vm.hasElf)

                vm.setOption("pack_elf", True)
                self.assertTrue(vm.options["pack_elf"])
                self.assertFalse(vm.options["wrap_elf"])

                vm.setOption("wrap_elf", True)
                self.assertTrue(vm.options["wrap_elf"])
                self.assertFalse(vm.options["pack_elf"])
                self.assertTrue(vm.planHasError)
                self.assertIn("wrap_elf", vm.optionConflicts)

                vm.adaptOptionsToLoadedElf()
                self.assertFalse(vm.options["wrap_elf"])
                self.assertTrue(vm.options["pack_elf"])
                self.assertFalse(vm.planHasError, vm.conflictList)
            finally:
                if old_appdata is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = old_appdata


if __name__ == "__main__":
    unittest.main()
