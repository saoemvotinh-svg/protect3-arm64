"""Presentation ViewModel connecting Qt Quick QML UI directly to the Protect3 domain engine."""

from dataclasses import asdict, replace
import json
import logging
from pathlib import Path
import secrets
import threading

from PySide6.QtCore import QObject, Property, Qt, QTimer, Signal, Slot, QUrl
from PySide6.QtGui import QGuiApplication

from .. import __version__
from ..arm64 import discover_functions, find_rodata_string_refs
from ..diagnostics import analyze_log
from ..elf import ELF, ProtectionError
from ..engine import (
    Options,
    capabilities,
    check_encryption,
    check_rodata_encryption,
    protect,
    read_library,
    verify_file,
)
from ..planner import (
    IN_PLACE_CONFLICT_OPTIONS,
    analyze_option_conflicts,
    apply_profile_defaults,
    build_protection_plan,
    evaluate_protection_benchmark,
)
from ..runtime import build_runtime, load_runtime
from ..transforms import (
    DEFAULT_BARCODE_CHARS,
    DEFAULT_BARCODE_LENGTH,
    DEFAULT_TROLL_DECOYS,
    format_troll_decoys_spec,
    generate_troll_barcode,
    normalize_barcode_chars,
    parse_troll_decoys_spec,
    sanitize_troll_string,
    sanitize_troll_symbol_name,
    validate_barcode_length,
)
from .models import CapabilitiesModel, DecoyListModel, FunctionListModel
from .settings import load_settings, log_path, save_settings


def _clean_path(raw):
    """Normalize local file path or file:/// URI from Qt FileDialog or Drag & Drop."""
    text = (raw or "").strip()
    if not text:
        return ""
    if text.startswith("file:"):
        local = QUrl(text).toLocalFile()
        if local:
            return str(Path(local))
    return str(Path(text))


def _default_ui_options():
    """Return full Options map initialized with active Anti-GG & emulator-compatible protection."""
    base = asdict(Options())
    base.update({
        "integrity": True,
        "debugger": True,
        "strip_symbols": True,
        "encrypt_text": True,
        "encrypt_rodata": True,
        "encrypt_data": True,
        "encrypt_strings": True,
        "auth_encryption": True,
        "sign_manifest": True,
        "clean_metadata": True,
        "masked_key": True,
        "obfuscate_ops": True,
        "obfuscate_guard": True,
        "flatten_cfg": True,
        "virtualize_auto": True,
        "pack_elf": False,
        "obfuscate_jni": True,
        "auto_select_functions": True,
        "runtime_integrity": True,
        "runtime_anti_debug": True,
        "prologue_check": True,
        "guard_self_check": True,
        "gg_honeypot": True,
        "ephemeral_strings": False,
        "anti_gg": True,
        "deny_attach": True,
        "report_only": False,
        "compat_layout": True,
        "diagnostics": True,
        "troll_ida": True,
        "block_ida": True,
        "troll_barcode_chars": DEFAULT_BARCODE_CHARS,
        "troll_barcode_length": DEFAULT_BARCODE_LENGTH,
        # Disabled by default so normal emulators/devices do not false-positive without GG:
        "hooks": False,
        "root": False,
        "emulator": False,
        "strict_proc": False,
        "seed": "",
    })
    return base


class Protect3ViewModel(QObject):
    """Thread-safe Qt Quick ViewModel owning application state, worker execution, and models."""

    pathsChanged = Signal()
    settingsChanged = Signal()
    optionsChanged = Signal()
    busyChanged = Signal()
    statusChanged = Signal()
    logChanged = Signal()
    elfChanged = Signal()
    planChanged = Signal()
    verifyChanged = Signal()
    benchmarkChanged = Signal()
    triageChanged = Signal()
    trollChanged = Signal()
    runtimeChanged = Signal()
    toastRequested = Signal(str, str)

    _workerFinished = Signal(str, object)
    _workerErrored = Signal(str, str)
    _logLineEmitted = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.function_model = FunctionListModel(self)
        self.decoy_model = DecoyListModel(DEFAULT_TROLL_DECOYS, self)
        self.capabilities_model = CapabilitiesModel(self)

        saved = load_settings()
        self._source_path = saved.get("last_source", "")
        self._output_path = saved.get("last_output", "")
        self._ndk_path = saved.get("ndk_path", "")
        self._recent_sources = list(saved.get("recent_sources", []))
        self._reduced_motion = bool(saved.get("reduced_motion", False))
        self._sidebar_collapsed = bool(saved.get("sidebar_collapsed", False))
        self._dark_mode = bool(saved.get("dark_mode", True))
        try:
            self._font_scale = max(0.9, min(1.4, float(saved.get("font_scale", 1.0))))
        except (TypeError, ValueError):
            self._font_scale = 1.0
        self._force_overwrite = False

        self._options = _default_ui_options()
        self._options["troll_barcode_chars"] = saved.get("troll_barcode_chars", DEFAULT_BARCODE_CHARS) or DEFAULT_BARCODE_CHARS
        try:
            self._options["troll_barcode_length"] = int(saved.get("troll_barcode_length", DEFAULT_BARCODE_LENGTH))
        except (TypeError, ValueError):
            self._options["troll_barcode_length"] = DEFAULT_BARCODE_LENGTH
        if not self._ndk_path:
            self._options["strip_symbols"] = False

        self._decoys_modified = False
        self._busy = False
        self._busy_label = ""
        self._status_text = "Sẵn sàng · chọn file .so ARM64 để phân tích hoặc bảo vệ"
        self._status_kind = "idle"
        self._log_lines = [
            f"Protect3 v{__version__} Desktop Studio sẵn sàng.",
            "File gốc đầu vào luôn được giữ nguyên. Tùy chọn mặc định đã tối ưu để chạy ổn định trên thiết bị & giả lập BlueStacks.",
        ]

        self._loaded_elf = None
        self._discovered_funcs = []
        self._elf_summary = {}
        self._hardening_summary = {}
        self._elf_sections = []
        self._has_elf = False

        self._plan_has_error = False
        self._plan_error_text = ""
        self._plan_active_ids = []
        self._plan_summary_text = ""
        self._plan_actions = []
        self._plan_skipped = []
        self._option_conflicts = {}
        self._conflict_list = []

        self._last_output_path = ""
        self._last_report_path = ""
        self._verify_result = {}
        self._has_verify_result = False
        self._last_protect_metrics = {}

        self._bench_orig_path = ""
        self._bench_prot_path = ""
        self._bench_result = {}
        self._has_bench_result = False

        self._log_package = "com.example.app"
        self._auto_log_lib_name = Path(self._source_path).name if self._source_path else "libnative.so"
        self._log_lib_name = self._auto_log_lib_name
        self._triage_input = ""
        self._triage_result = {}
        self._has_triage_result = False

        self._barcode_preview_seed = secrets.randbits(64)
        self._barcode_previews = []
        self._runtime_summary = self._read_runtime_summary()
        self._unicorn_available = self._check_unicorn()

        self._workerFinished.connect(self._on_worker_finished, Qt.QueuedConnection)
        self._workerErrored.connect(self._on_worker_errored, Qt.QueuedConnection)
        self._logLineEmitted.connect(self._append_log_line, Qt.QueuedConnection)

        self._refresh_barcode_previews()
        self.refreshPlan()
        if self._source_path and Path(self._source_path).is_file():
            QTimer.singleShot(0, self._inspect_saved_source_on_startup)

    def _inspect_saved_source_on_startup(self):
        if self._source_path and not self._busy and not self._has_elf and Path(self._source_path).is_file():
            self.inspectLibrary(self._source_path)

    def _check_unicorn(self):
        try:
            import unicorn  # noqa: F401
            return True
        except Exception:
            return False

    def _read_runtime_summary(self):
        try:
            blob, meta = load_runtime(self._ndk_path or None)
            return f"guard.bin {len(blob)} bytes · SHA256 {meta['sha256'][:12]}… · {meta.get('compiler', 'embedded')}"
        except Exception as exc:
            return f"Chưa sẵn sàng: {exc}"

    def _persist(self):
        save_settings({
            "ndk_path": self._ndk_path,
            "last_source": self._source_path,
            "last_output": self._output_path,
            "recent_sources": self._recent_sources[:6],
            "reduced_motion": self._reduced_motion,
            "sidebar_collapsed": self._sidebar_collapsed,
            "dark_mode": self._dark_mode,
            "font_scale": self._font_scale,
            "troll_barcode_chars": self._options.get("troll_barcode_chars", DEFAULT_BARCODE_CHARS),
            "troll_barcode_length": self._options.get("troll_barcode_length", DEFAULT_BARCODE_LENGTH),
        })

    def _append_log_line(self, line):
        text = str(line).rstrip("\r\n")
        if not text:
            return
        self._log_lines.append(text)
        if len(self._log_lines) > 800:
            self._log_lines = self._log_lines[-600:]
        self.logChanged.emit()

    def _set_status(self, text, kind="info"):
        self._status_text = text
        self._status_kind = kind
        self.statusChanged.emit()

    def _build_options_obj(self, strict=True, parse_errors=None):
        """Translate reactive UI state dict into a frozen engine.Options dataclass."""
        raw = dict(self._options)
        seed_raw = str(raw.get("seed", "") or "").strip()
        seed_val = None
        if seed_raw:
            try:
                seed_val = int(seed_raw, 0)
            except ValueError as exc:
                msg = f"Build seed không hợp lệ ({seed_raw!r}); nhập số nguyên (vd: 42 hoặc 0x1337) hoặc để trống."
                if strict:
                    raise ProtectionError(msg) from exc
                if parse_errors is not None:
                    parse_errors.append(("seed", msg))

        raw_len = raw.get("troll_barcode_length", DEFAULT_BARCODE_LENGTH)
        raw_chars = raw.get("troll_barcode_chars", DEFAULT_BARCODE_CHARS)
        if strict and raw.get("troll_ida"):
            troll_len = validate_barcode_length(raw_len)
            troll_chars = normalize_barcode_chars(raw_chars, allow_empty=(troll_len == 0))
        else:
            try:
                troll_len = validate_barcode_length(raw_len)
            except ProtectionError as exc:
                if strict:
                    raise
                if parse_errors is not None and raw.get("troll_ida"):
                    parse_errors.append(("troll_barcode_length", str(exc)))
                troll_len = DEFAULT_BARCODE_LENGTH
            troll_chars = str(raw_chars if raw_chars is not None else DEFAULT_BARCODE_CHARS)
        decoys_spec = format_troll_decoys_spec(self.decoy_model.items_copy()) if self._decoys_modified else ""

        valid_fields = set(Options().__dict__.keys())
        filtered = {k: v for k, v in raw.items() if k in valid_fields}
        filtered["seed"] = seed_val
        filtered["troll_barcode_chars"] = troll_chars
        filtered["troll_barcode_length"] = troll_len
        filtered["troll_decoys"] = decoys_spec
        return Options(**filtered)

    def _assignment_lookup(self):
        """Build map symbol_or_va -> short active pass badge for Function Explorer rows."""
        lookup = {}
        mapping = (
            ("virtualize_functions", "VM"),
            ("flatten_functions", "Flat"),
            ("obfuscate_functions", "Obf"),
            ("encrypt_functions", "Enc"),
            ("encrypt_function", "Enc"),
            ("on_demand_functions", "R07"),
            ("denylist_functions", "Deny"),
        )
        for key, tag in mapping:
            val = str(self._options.get(key, "") or "")
            for item in val.split(","):
                name = item.strip()
                if name:
                    lookup[name] = f"{lookup[name]}+{tag}" if name in lookup else tag
        return lookup

    # ---------------- Properties ----------------

    @Property(str, constant=True)
    def appVersion(self):
        return __version__

    @Property(bool, constant=True)
    def unicornAvailable(self):
        return self._unicorn_available

    @Property(str, constant=True)
    def logFilePath(self):
        return str(log_path())

    @Property(str, notify=pathsChanged)
    def sourcePath(self):
        return self._source_path

    @sourcePath.setter
    def sourcePath(self, value):
        cleaned = _clean_path(value)
        if cleaned != self._source_path:
            old_auto = ""
            if self._source_path:
                op = Path(self._source_path)
                old_auto = str(op.parent / "protected" / op.name)
            self._source_path = cleaned
            self._loaded_elf = None
            self._has_elf = False
            self._discovered_funcs = []
            self._elf_summary = {}
            self._hardening_summary = {}
            self._elf_sections = []
            self.function_model.set_functions([])
            self.elfChanged.emit()
            if cleaned and (not self._output_path or self._output_path == old_auto):
                p = Path(cleaned)
                self._output_path = str(p.parent / "protected" / p.name)
            if cleaned and (not self._bench_orig_path or self._bench_orig_path == old_auto):
                self._bench_orig_path = cleaned
            if cleaned:
                self._recent_sources = [cleaned] + [r for r in self._recent_sources if r != cleaned][:5]
                new_lib_name = Path(cleaned).name
                if self._log_lib_name in ("", "libnative.so", self._auto_log_lib_name):
                    self._log_lib_name = new_lib_name
                    self._auto_log_lib_name = new_lib_name
                    self.triageChanged.emit()
            self._persist()
            self.pathsChanged.emit()

    @Slot(str)
    def selectSource(self, raw_path):
        """Select a new input .so from file picker or drag-and-drop and inspect it if not busy."""
        cleaned = _clean_path(raw_path)
        if not cleaned:
            return
        self.sourcePath = cleaned
        self._bench_orig_path = cleaned
        self.benchmarkChanged.emit()
        if Path(cleaned).is_file() and not self._busy:
            self.inspectLibrary(cleaned)

    @Property(str, notify=pathsChanged)
    def outputPath(self):
        return self._output_path

    @outputPath.setter
    def outputPath(self, value):
        cleaned = _clean_path(value)
        if cleaned != self._output_path:
            self._output_path = cleaned
            self._persist()
            self.pathsChanged.emit()

    @Property(str, notify=pathsChanged)
    def ndkPath(self):
        return self._ndk_path

    @ndkPath.setter
    def ndkPath(self, value):
        cleaned = _clean_path(value)
        if cleaned != self._ndk_path:
            self._ndk_path = cleaned
            self._persist()
            self.pathsChanged.emit()
            self.refreshPlan()

    @Property(bool, notify=pathsChanged)
    def forceOverwrite(self):
        return self._force_overwrite

    @forceOverwrite.setter
    def forceOverwrite(self, value):
        val = bool(value)
        if val != self._force_overwrite:
            self._force_overwrite = val
            self.pathsChanged.emit()

    @Property("QVariantList", notify=pathsChanged)
    def recentSources(self):
        return list(self._recent_sources)

    @Property(bool, notify=settingsChanged)
    def reducedMotion(self):
        return self._reduced_motion

    @reducedMotion.setter
    def reducedMotion(self, value):
        val = bool(value)
        if val != self._reduced_motion:
            self._reduced_motion = val
            self._persist()
            self.settingsChanged.emit()

    @Property(bool, notify=settingsChanged)
    def sidebarCollapsed(self):
        return self._sidebar_collapsed

    @sidebarCollapsed.setter
    def sidebarCollapsed(self, value):
        val = bool(value)
        if val != self._sidebar_collapsed:
            self._sidebar_collapsed = val
            self._persist()
            self.settingsChanged.emit()

    @Property(bool, notify=settingsChanged)
    def darkMode(self):
        return self._dark_mode

    @darkMode.setter
    def darkMode(self, value):
        val = bool(value)
        if val != self._dark_mode:
            self._dark_mode = val
            self._persist()
            self.settingsChanged.emit()

    @Property(float, notify=settingsChanged)
    def fontScale(self):
        return self._font_scale

    @fontScale.setter
    def fontScale(self, value):
        try:
            val = round(max(0.9, min(1.4, float(value))), 2)
        except (TypeError, ValueError):
            return
        if val != self._font_scale:
            self._font_scale = val
            self._persist()
            self.settingsChanged.emit()

    @Property("QVariantMap", notify=optionsChanged)
    def options(self):
        return dict(self._options)

    @Property(bool, notify=busyChanged)
    def busy(self):
        return self._busy

    @Property(str, notify=busyChanged)
    def busyLabel(self):
        return self._busy_label

    @Property(str, notify=statusChanged)
    def statusText(self):
        return self._status_text

    @Property(str, notify=statusChanged)
    def statusKind(self):
        return self._status_kind

    @Property(str, notify=logChanged)
    def logText(self):
        return "\n".join(self._log_lines)

    @Property(bool, notify=elfChanged)
    def hasElf(self):
        return self._has_elf

    @Property(str, notify=elfChanged)
    def elfBadgeText(self):
        if not self._has_elf:
            return "Chưa nạp file .so"
        s = self._elf_summary
        mb = s.get("size", 0) / (1024 * 1024)
        return (
            f"{s.get('architecture', '?')} · {mb:.2f} MiB · "
            f"{self.function_model.totalCount} hàm · {s.get('export_count', 0)} exports"
        )

    @Property("QVariantMap", notify=elfChanged)
    def elfSummary(self):
        return dict(self._elf_summary)

    @Property("QVariantMap", notify=elfChanged)
    def hardeningSummary(self):
        return dict(self._hardening_summary)

    @Property("QVariantList", notify=elfChanged)
    def elfSections(self):
        return list(self._elf_sections)

    @Property(bool, notify=planChanged)
    def planHasError(self):
        return self._plan_has_error

    @Property(str, notify=planChanged)
    def planErrorText(self):
        return self._plan_error_text

    @Property("QVariantList", notify=planChanged)
    def planActiveIds(self):
        return list(self._plan_active_ids)

    @Property(str, notify=planChanged)
    def planSummaryText(self):
        return self._plan_summary_text

    @Property("QVariantList", notify=planChanged)
    def planActions(self):
        return list(self._plan_actions)

    @Property("QVariantList", notify=planChanged)
    def planSkipped(self):
        return list(self._plan_skipped)

    @Property("QVariantMap", notify=planChanged)
    def optionConflicts(self):
        return dict(self._option_conflicts)

    @Property("QVariantList", notify=planChanged)
    def conflictList(self):
        return list(self._conflict_list)

    @Property(str, notify=verifyChanged)
    def lastOutputPath(self):
        return self._last_output_path

    @Property("QVariantMap", notify=verifyChanged)
    def verifyResult(self):
        return dict(self._verify_result)

    @Property(bool, notify=verifyChanged)
    def hasVerifyResult(self):
        return self._has_verify_result

    @Property("QVariantMap", notify=verifyChanged)
    def lastProtectMetrics(self):
        return dict(self._last_protect_metrics)

    @Property(str, notify=benchmarkChanged)
    def benchOrigPath(self):
        return self._bench_orig_path

    @benchOrigPath.setter
    def benchOrigPath(self, value):
        cleaned = _clean_path(value)
        if cleaned != self._bench_orig_path:
            self._bench_orig_path = cleaned
            self.benchmarkChanged.emit()

    @Property(str, notify=benchmarkChanged)
    def benchProtPath(self):
        return self._bench_prot_path

    @benchProtPath.setter
    def benchProtPath(self, value):
        cleaned = _clean_path(value)
        if cleaned != self._bench_prot_path:
            self._bench_prot_path = cleaned
            self.benchmarkChanged.emit()

    @Property("QVariantMap", notify=benchmarkChanged)
    def benchResult(self):
        return dict(self._bench_result)

    @Property(bool, notify=benchmarkChanged)
    def hasBenchResult(self):
        return self._has_bench_result

    @Property(str, notify=triageChanged)
    def logPackageName(self):
        return self._log_package

    @logPackageName.setter
    def logPackageName(self, value):
        self._log_package = str(value or "").strip()
        self.triageChanged.emit()

    @Property(str, notify=triageChanged)
    def logLibName(self):
        return self._log_lib_name

    @logLibName.setter
    def logLibName(self, value):
        self._log_lib_name = str(value or "").strip()
        self.triageChanged.emit()

    @Property(str, notify=triageChanged)
    def triageInputText(self):
        return self._triage_input

    @triageInputText.setter
    def triageInputText(self, value):
        self._triage_input = str(value or "")
        self.triageChanged.emit()

    @Property("QVariantMap", notify=triageChanged)
    def triageResult(self):
        return dict(self._triage_result)

    @Property(bool, notify=triageChanged)
    def hasTriageResult(self):
        return self._has_triage_result

    @Property("QVariantList", notify=trollChanged)
    def barcodePreviews(self):
        return list(self._barcode_previews)

    @Property(bool, notify=trollChanged)
    def customDecoysModified(self):
        return self._decoys_modified

    @Property(int, constant=True)
    def defaultDecoysCount(self):
        return len(DEFAULT_TROLL_DECOYS)

    @Property(str, notify=runtimeChanged)
    def runtimeSummary(self):
        return self._runtime_summary

    # ---------------- Option, Preset & Troll Customizer Slots ----------------

    @Slot(str, "QVariant")
    def setOption(self, key, value):
        if key not in self._options:
            return
        if isinstance(self._options[key], bool):
            value = bool(value)
            # Clear static profile tag when individual passes are customized manually so UI matches reality
            if key in IN_PLACE_CONFLICT_OPTIONS and self._options.get("profile"):
                self._options["profile"] = ""
        elif key == "troll_barcode_length":
            try:
                parsed = int(value)
                value = parsed if 0 <= parsed <= 128 else str(value).strip()
            except (TypeError, ValueError):
                value = "" if value is None else str(value).strip()
        elif key == "profile":
            value = "" if value is None else str(value).strip()
            if value.lower() in ("compat", "balanced", "anti-analysis", "max"):
                current_obj = self._build_options_obj(strict=False)
                expanded = apply_profile_defaults(replace(current_obj, profile=value.lower()))
                exp_map = asdict(expanded)
                exp_map["seed"] = self._options.get("seed", "")
                exp_map["troll_barcode_chars"] = self._options.get("troll_barcode_chars", DEFAULT_BARCODE_CHARS)
                exp_map["troll_barcode_length"] = self._options.get("troll_barcode_length", DEFAULT_BARCODE_LENGTH)
                self._options = exp_map
                self._options["profile"] = value.lower()
                self.optionsChanged.emit()
                self.function_model.update_assignments(self._assignment_lookup())
                self.refreshPlan()
                return
        else:
            value = "" if value is None else str(value)

        if self._options[key] == value:
            return
        if key == "pack_elf" and value and self._options.get("wrap_elf"):
            self._options["wrap_elf"] = False
            self.toastRequested.emit(
                "Đã tự tắt E08 (Wrapper) vì E09 (Packer) đóng gói toàn ELF và hỗ trợ cả export STT_OBJECT/RTTI.",
                "info",
            )
        elif key == "wrap_elf" and value:
            if self._options.get("pack_elf"):
                self._options["pack_elf"] = False
                self.toastRequested.emit("Đã tự tắt E09 (Packer) để chuyển sang E08 (Wrapper).", "info")
            if self._loaded_elf is not None:
                obj_exports = [n for n, info, _, _, _ in self._loaded_elf.exported_symbols() if (info & 0xF) == 1]
                if obj_exports:
                    self.toastRequested.emit(
                        f"E08 không hỗ trợ .so có export STT_OBJECT ({obj_exports[0]}) — hãy dùng E09 (Packer) hoặc 'Tự chỉnh cho .so này'.",
                        "warn",
                    )
        self._options[key] = value
        self.optionsChanged.emit()
        if key in ("troll_barcode_chars", "troll_barcode_length"):
            self._persist()
            self._refresh_barcode_previews()
        if key in (
            "virtualize_functions", "flatten_functions", "obfuscate_functions",
            "encrypt_functions", "encrypt_function", "on_demand_functions", "denylist_functions",
        ):
            self.function_model.update_assignments(self._assignment_lookup())
        self.refreshPlan()

    @Slot(str)
    def applyPreset(self, preset_name):
        name = (preset_name or "").strip().lower()
        troll_chars = self._options.get("troll_barcode_chars", DEFAULT_BARCODE_CHARS)
        troll_len = self._options.get("troll_barcode_length", DEFAULT_BARCODE_LENGTH)
        if name == "bluestacks_safe":
            self._options = _default_ui_options()
            self._options.update({
                "report_only": True,
                "deny_attach": False,
                "runtime_anti_debug": False,
                "compat_layout": True,
                "diagnostics": True,
            })
            if not self._ndk_path:
                self._options["strip_symbols"] = False
            self._set_status("Đã áp dụng cấu hình test BlueStacks (còn bật report_only — chỉ ghi log, chưa tự thoát app).", "info")
        elif name in ("apk_anti_cheat", "anti_virbox"):
            self._options = _default_ui_options()
            self._options.update({
                "report_only": False,
                "deny_attach": True,
                "hooks": True,
                "deep_probes": True,
                "auto_select_functions": True,
                "runtime_integrity": True,
                "runtime_anti_debug": True,
                "compat_layout": False,
                "diagnostics": False,
                "pack_elf": True,
                "obfuscate_guard": True,
                "encrypt_data": True,
            })
            if not self._ndk_path:
                self._options["strip_symbols"] = False
            label = "Anti-Virbox Ultra (E09 Packer + O10 Guard)" if name == "anti_virbox" else "APK Release"
            self._set_status(f"Đã bật cấu hình {label} (E09 Packer, O10 Self-Obf, Anti-GG/Honeypot).", "info")
        elif name in ("compat", "balanced", "anti-analysis", "max"):
            expanded = apply_profile_defaults(Options(
                integrity=True,
                debugger=True,
                profile=name,
                encrypt_text=(name in ("anti-analysis", "max")),
                encrypt_rodata=(name in ("balanced", "anti-analysis", "max")),
                obfuscate_jni=(name in ("anti-analysis", "max")),
                compat_layout=(name == "compat"),
                strip_symbols=bool(self._ndk_path and name != "compat"),
                troll_ida=True,
                block_ida=True,
            ))
            self._options = asdict(expanded)
            self._options["seed"] = ""
            # Clear profile after expanding preset switches so individual toggles stay freely editable
            self._options["profile"] = ""
            self._set_status(f"Đã nạp preset '{name}'.", "info")
        elif name == "minimal":
            self._options = asdict(Options(integrity=True, debugger=True, compat_layout=True))
            self._options["seed"] = ""
            self._set_status("Đã chuyển về cấu hình tối thiểu (chỉ guard integrity + TracerPid).", "info")
        self._options["troll_barcode_chars"] = troll_chars
        self._options["troll_barcode_length"] = troll_len
        self.optionsChanged.emit()
        self.function_model.update_assignments(self._assignment_lookup())
        self._refresh_barcode_previews()
        self.refreshPlan()
        self.toastRequested.emit(f"Đã chọn preset: {preset_name}", "info")

    @Slot(str, str)
    def toggleFunctionAssignment(self, symbol_or_va, field_key):
        """Toggle a function name/VA in one of the target list options directly from Inspector."""
        allowed = (
            "virtualize_functions", "flatten_functions", "obfuscate_functions",
            "encrypt_functions", "on_demand_functions", "denylist_functions",
        )
        if field_key not in allowed or not symbol_or_va:
            return
        current = [x.strip() for x in str(self._options.get(field_key, "")).split(",") if x.strip()]
        if symbol_or_va in current:
            current.remove(symbol_or_va)
            action = "Gỡ"
        else:
            current.append(symbol_or_va)
            action = "Gán"
        self.setOption(field_key, ", ".join(current))
        self.toastRequested.emit(f"{action} '{symbol_or_va}' → {field_key}", "info")

    @Slot()
    def autoPopulateFunctions(self):
        """Assign top substantive non-init functions to O08 VM and O07 Flattening directly in Explorer."""
        if not self._discovered_funcs:
            self.toastRequested.emit("Hãy phân tích file .so trước khi gán nhanh hàm.", "warn")
            return
        crt_boilerplate = {
            "original_init", "sample_constructor", "__on_dlclose", "__on_dlclose_late",
            "__emutls_unregister_key", "__emutls_get_address", "__cxa_finalize",
            "__cxa_atexit", "register_tm_clones", "deregister_tm_clones", "frame_dummy",
            "__do_global_dtors_aux", "__do_global_ctors_aux", "call_weak_fn", "atexit",
            "pthread_atfork",
        }
        denylist = {x.strip() for x in str(self._options.get("denylist_functions", "")).split(",") if x.strip()}
        cands = [
            f for f in self._discovered_funcs
            if f.relocatable and not f.is_early_init and not f.is_jni
            and f.name not in denylist and f.name not in crt_boilerplate
            and not f.name.startswith("__aeabi_")
        ]
        substantive = [f for f in cands if f.insn_count >= 10 or f.is_exported]
        pool = substantive if substantive else cands
        pool.sort(key=lambda f: (
            -f.sensitivity_score,
            -min(f.insn_count, 96) if not f.is_exported else f.cost_score,
            f.vaddr,
        ))
        vm_list, flat_list = [], []
        taken = set()
        for fn in pool:
            if fn.vm_compatible and len(vm_list) < 8:
                vm_list.append(fn.name)
                taken.add(fn.vaddr)
        for fn in pool:
            if fn.vaddr in taken:
                continue
            can_flat = bool(fn.blocks and len(fn.blocks[0].dead_scratch_regs) >= 2 and (fn.block_count >= 2 or fn.insn_count >= 3))
            if can_flat and len(flat_list) < 8:
                flat_list.append(fn.name)
                taken.add(fn.vaddr)
        self._options["virtualize_functions"] = ", ".join(vm_list)
        self._options["flatten_functions"] = ", ".join(flat_list)
        self.optionsChanged.emit()
        self.function_model.update_assignments(self._assignment_lookup())
        self.refreshPlan()
        self.toastRequested.emit(f"Đã gán nhanh {len(vm_list)} hàm VM + {len(flat_list)} hàm Flatten.", "success")

    @Slot()
    def refreshPlan(self):
        """Validate option combinations, compute per-option red conflicts, and preview F05 plan."""
        parse_errors = []
        try:
            opt = self._build_options_obj(strict=False, parse_errors=parse_errors)
            caps = []
            try:
                caps = capabilities(opt)
                self.capabilities_model.set_capabilities(caps)
            except ProtectionError:
                pass
            diag = analyze_option_conflicts(
                opt,
                elf=self._loaded_elf,
                ndk=self._ndk_path or None,
                functions=self._discovered_funcs,
                unicorn_available=self._unicorn_available,
            )
            conflicts = list(diag["conflicts"])
            option_errors = dict(diag["option_errors"])
            for field_key, msg in parse_errors:
                conflicts.append({"code": f"INVALID_{field_key.upper()}", "message": msg, "options": [field_key]})
                option_errors[field_key] = msg

            if conflicts:
                self._plan_has_error = True
                self._option_conflicts = option_errors
                self._conflict_list = conflicts
                self._plan_error_text = " | ".join(c["message"] for c in conflicts)
                self._plan_summary_text = f"Phát hiện {len(conflicts)} xung đột (mục xung đột đã tô chữ đỏ):"
                self._plan_active_ids = []
                self._plan_actions = []
                self._plan_skipped = []
            else:
                self._option_conflicts = {}
                self._conflict_list = []
                self._plan_has_error = False
                self._plan_error_text = ""
                if self._loaded_elf is not None:
                    plan = diag.get("plan") or build_protection_plan(
                        self._loaded_elf, opt, pre_strip_functions=self._discovered_funcs
                    )
                    self._plan_active_ids = list(plan.active_ids)
                    self._plan_actions = [
                        {
                            "name": a.name,
                            "vaddr": f"0x{a.vaddr:x}",
                            "size": a.size,
                            "backend": a.backend,
                            "passes": ", ".join(a.passes),
                            "gate": a.runtime_gate,
                        }
                        for a in plan.function_actions
                    ]
                    self._plan_skipped = list(plan.skipped_items)
                    self._plan_summary_text = (
                        f"Hợp lệ (đã tối ưu thứ tự thực thi) · {len(plan.function_actions)} hàm biến đổi · "
                        f"{len(plan.string_refs)} chuỗi Vault · {len(plan.prologue_checks)} prologue · "
                        f"{len(plan.skipped_items)} bỏ qua"
                    )
                else:
                    enabled_caps = [c["feature"] for c in caps if c["status"] == "enabled"]
                    self._plan_active_ids = []
                    self._plan_actions = []
                    self._plan_skipped = []
                    self._plan_summary_text = (
                        f"Cấu hình hợp lệ ({len(enabled_caps)} nhóm bảo vệ theo trình tự F01→E06→O01-O09→E03→R01-R09→E01/E02/E05→IDA)"
                    )
        except ProtectionError as exc:
            self._plan_has_error = True
            self._option_conflicts = {}
            self._conflict_list = [{"code": "PLAN_ERROR", "message": str(exc), "options": []}]
            self._plan_error_text = str(exc)
            self._plan_summary_text = f"Xung đột cấu hình: {exc}"
        self.planChanged.emit()

    @Slot()
    def adaptOptionsToLoadedElf(self):
        """Auto-resolve mutually conflicting options and passes incompatible with the loaded .so/environment."""
        changed = []
        # 1. Option-vs-option conflicts (also works before loading an ELF)
        if self._options.get("profile"):
            prof_clean = str(self._options.get("profile", "")).strip().lower()
            if prof_clean not in ("compat", "balanced", "anti-analysis", "max"):
                self._options["profile"] = ""
                changed.append("xóa profile không hợp lệ")

        if self._options.get("ephemeral_strings") and not self._options.get("encrypt_strings"):
            self._options["encrypt_strings"] = True
            changed.append("bật kèm E03 String Vault cho Ephemeral Strings")

        if self._options.get("encrypt_text") and (
            str(self._options.get("encrypt_functions", "") or "").strip()
            or str(self._options.get("encrypt_function", "") or "").strip()
        ):
            self._options["encrypt_text"] = False
            changed.append("ưu tiên danh sách E01 riêng")

        # Deduplicate explicit function backends by priority: VM > Flatten > Obfuscate > On-Demand
        taken_funcs = set()
        for key, label in (
            ("virtualize_functions", "VM"),
            ("flatten_functions", "Flatten"),
            ("obfuscate_functions", "Obfuscate"),
            ("on_demand_functions", "R07"),
        ):
            items = [x.strip() for x in str(self._options.get(key, "") or "").split(",") if x.strip()]
            kept = [x for x in items if x not in taken_funcs]
            if len(kept) != len(items):
                self._options[key] = ", ".join(kept)
                changed.append(f"gỡ trùng hàm ở {label}")
            taken_funcs.update(kept)

        if self._options.get("troll_ida"):
            try:
                blen = validate_barcode_length(self._options.get("troll_barcode_length", DEFAULT_BARCODE_LENGTH))
                normalize_barcode_chars(self._options.get("troll_barcode_chars", DEFAULT_BARCODE_CHARS), allow_empty=(blen == 0))
            except ProtectionError:
                self._options["troll_barcode_chars"] = DEFAULT_BARCODE_CHARS
                self._options["troll_barcode_length"] = DEFAULT_BARCODE_LENGTH
                changed.append("khôi phục mã vạch IlO0 hợp lệ")

        if self._options.get("verify_semantics") and not self._unicorn_available:
            self._options["verify_semantics"] = False
            changed.append("tắt F03 (chưa cài unicorn)")

        from ..runtime import ndk_bin
        try:
            ndk_bin(self._ndk_path or None)
        except ProtectionError:
            if self._options.get("strip_symbols"):
                self._options["strip_symbols"] = False
                changed.append("tắt llvm-strip (thiếu NDK)")
            if self._options.get("wrap_elf"):
                self._options["wrap_elf"] = False
                changed.append("tắt wrap-elf (thiếu NDK)")

        if self._options.get("pack_elf") and self._options.get("wrap_elf"):
            self._options["wrap_elf"] = False
            changed.append("tắt E08 (ưu tiên E09 Packer)")

        # 2. Loaded ELF compatibility adjustments
        if self._loaded_elf is not None:
            if self._options.get("wrap_elf"):
                exports = self._loaded_elf.exported_symbols()
                obj_exports = [n for n, info, _, _, _ in exports if (info & 0xF) == 1]
                fn_exports = [n for n, info, _, _, _ in exports if (info & 0xF) == 2 and n]
                if obj_exports or not fn_exports:
                    self._options["wrap_elf"] = False
                    if len(self._loaded_elf.loads) <= 8 and not self._options.get("pack_elf"):
                        self._options["pack_elf"] = True
                        changed.append("chuyển E08 → E09 Packer (hỗ trợ export STT_OBJECT/RTTI)")
                    else:
                        changed.append("tắt E08 (.so không đủ điều kiện export STT_FUNC)")

            pack_mode = bool(self._options.get("pack_elf") and not self._options.get("wrap_elf"))
            from ..engine import check_compat_layout_support
            if self._options.get("compat_layout") and not pack_mode:
                try:
                    check_compat_layout_support(self._loaded_elf)
                except ProtectionError:
                    self._options["compat_layout"] = False
                    changed.append("tắt Compat Layout (không tương thích ELF)")

            text_sec = self._loaded_elf.section(".text")
            if not pack_mode:
                text_supported = True
                try:
                    check_encryption(self._loaded_elf, text_sec)
                except ProtectionError:
                    text_supported = False
                if not text_supported:
                    if self._options.get("encrypt_text"):
                        self._options["encrypt_text"] = False
                        changed.append("tắt E01 toàn .text")
                    for k in ("encrypt_functions", "encrypt_function"):
                        if str(self._options.get(k, "") or "").strip():
                            self._options[k] = ""
                            changed.append(f"xóa {k}")

                rodata_supported = True
                try:
                    check_rodata_encryption(self._loaded_elf)
                except ProtectionError:
                    rodata_supported = False
                if not rodata_supported and self._options.get("encrypt_rodata"):
                    self._options["encrypt_rodata"] = False
                    changed.append("tắt E02 .rodata")
            if self._loaded_elf.section(".rodata") is None and self._options.get("encrypt_strings"):
                self._options["encrypt_strings"] = False
                self._options["ephemeral_strings"] = False
                changed.append("tắt E03 (không có .rodata)")

        self.optionsChanged.emit()
        self.function_model.update_assignments(self._assignment_lookup())
        self.refreshPlan()
        if changed:
            msg = "Đã tự chỉnh xung đột: " + ", ".join(changed) + "."
            self._set_status(msg, "info")
            self.toastRequested.emit(msg, "success")
        else:
            self.toastRequested.emit("Cấu hình hiện tại đã tương thích hoặc cần xử lý danh sách hàm cụ thể.", "info")

    @Slot()
    def shuffleBarcodePreview(self):
        self._barcode_preview_seed = secrets.randbits(64)
        self._refresh_barcode_previews()

    def _refresh_barcode_previews(self):
        chars = self._options.get("troll_barcode_chars", DEFAULT_BARCODE_CHARS)
        raw_len = self._options.get("troll_barcode_length", DEFAULT_BARCODE_LENGTH)
        decoys = self.decoy_model.items_copy()
        samples = []
        try:
            length = validate_barcode_length(raw_len)
            clean_chars = normalize_barcode_chars(chars, allow_empty=(length == 0))
            for idx in range(min(3, len(decoys))):
                base = sanitize_troll_symbol_name(decoys[idx][0])
                samples.append(
                    generate_troll_barcode(
                        self._barcode_preview_seed, "ui-preview", idx + 1, clean_chars, length, suffix=f"_{base}"
                    )
                )
        except ProtectionError as exc:
            samples = [f"[Lỗi cấu hình]: {exc}"]
        self._barcode_previews = samples
        self.trollChanged.emit()

    @Slot(int, result="QVariantMap")
    def getDecoy(self, index):
        items = self.decoy_model.items_copy()
        if 0 <= index < len(items):
            n, m, a = items[index]
            return {"name": n, "main": m, "alt": a}
        return {"name": "", "main": "", "alt": ""}

    @Slot(int, str, str, str)
    def updateDecoy(self, index, name, main_msg, alt_msg):
        items = self.decoy_model.items_copy()
        if not (0 <= index < len(items)):
            return
        clean_name = sanitize_troll_symbol_name(name, fallback=f"Troll_Func_{index + 1:02d}")
        clean_main = sanitize_troll_string(main_msg, fallback=f"[Protect3] Trolled by {clean_name}!")
        clean_alt = sanitize_troll_string(alt_msg) if str(alt_msg or "").strip() else f"[1337] {clean_main}"
        items[index] = [clean_name, clean_main, clean_alt]
        self._set_decoys_items(items, toast="Đã cập nhật dòng hàm troll.")

    @Slot(str, str, str)
    def addDecoy(self, name, main_msg, alt_msg):
        items = self.decoy_model.items_copy()
        if len(items) >= 128:
            self.toastRequested.emit("Tối đa 128 hàm troll F5 mỗi thư viện.", "warn")
            return
        clean_name = sanitize_troll_symbol_name(name, fallback=f"Troll_Func_{len(items) + 1:02d}")
        clean_main = sanitize_troll_string(main_msg, fallback=f"[Protect3] Trolled by {clean_name}!")
        clean_alt = sanitize_troll_string(alt_msg) if str(alt_msg or "").strip() else f"[1337] {clean_main}"
        items.append([clean_name, clean_main, clean_alt])
        self._set_decoys_items(items, toast=f"Đã thêm '{clean_name}'.")

    @Slot(int)
    def deleteDecoy(self, index):
        items = self.decoy_model.items_copy()
        if len(items) <= 1:
            self.toastRequested.emit("Cần giữ ít nhất 1 hàm bẫy.", "warn")
            return
        if 0 <= index < len(items):
            removed = items.pop(index)
            self._set_decoys_items(items, toast=f"Đã xóa '{removed[0]}'.")

    @Slot(int, int)
    def moveDecoy(self, index, delta):
        items = self.decoy_model.items_copy()
        target = index + delta
        if 0 <= index < len(items) and 0 <= target < len(items):
            items[index], items[target] = items[target], items[index]
            self._set_decoys_items(items)

    @Slot()
    def resetDefaultDecoys(self):
        self._set_decoys_items(
            DEFAULT_TROLL_DECOYS,
            toast=f"Đã khôi phục {len(DEFAULT_TROLL_DECOYS)} hàm & chuỗi troll mặc định.",
        )

    @Slot(result=str)
    def exportDecoysBulkText(self):
        return "\n".join(f"{n} | {m} | {a}" for n, m, a in self.decoy_model.items_copy())

    @Slot(str)
    def applyBulkDecoys(self, text):
        try:
            parsed = parse_troll_decoys_spec(text)
            self._set_decoys_items(parsed, toast=f"Đã áp dụng {len(parsed)} hàm troll từ bulk text.")
        except ProtectionError as exc:
            self.toastRequested.emit(str(exc), "error")

    @Slot(str)
    def importDecoysFile(self, raw_path):
        path = _clean_path(raw_path)
        if not path:
            return
        try:
            parsed = parse_troll_decoys_spec(Path(path).read_text(encoding="utf-8"))
            self._set_decoys_items(parsed, toast=f"Đã nạp {len(parsed)} mục từ {Path(path).name}")
        except (OSError, ProtectionError) as exc:
            self.toastRequested.emit(f"Không nạp được file troll: {exc}", "error")

    @Slot(str)
    def exportDecoysFile(self, raw_path):
        path = _clean_path(raw_path)
        if not path:
            return
        items = self.decoy_model.items_copy()
        try:
            if path.lower().endswith(".txt"):
                content = "\n".join(f"{n} | {m} | {a}" for n, m, a in items) + "\n"
            else:
                content = json.dumps(
                    [{"name": n, "msg": m, "alt": a} for n, m, a in items],
                    indent=2,
                    ensure_ascii=False,
                ) + "\n"
            Path(path).write_text(content, encoding="utf-8")
            self.toastRequested.emit(f"Đã xuất danh sách ra {Path(path).name}", "success")
        except OSError as exc:
            self.toastRequested.emit(f"Không lưu được file: {exc}", "error")

    def _set_decoys_items(self, items, toast=None):
        self.decoy_model.set_items(items)
        self._decoys_modified = [list(x) for x in items] != [list(x) for x in DEFAULT_TROLL_DECOYS]
        self._refresh_barcode_previews()
        self.refreshPlan()
        if toast:
            self.toastRequested.emit(toast, "info")

    # ---------------- Background Backend Operations ----------------

    def _run_worker(self, task_name, label, fn):
        if self._busy:
            self.toastRequested.emit("Đang có tác vụ nền chạy, vui lòng đợi hoàn tất.", "warn")
            return
        self._busy = True
        self._busy_label = label
        self.busyChanged.emit()
        self._set_status(label, "info")
        self._append_log_line(f"\n▶ {label}")

        def target():
            try:
                result = fn()
                self._workerFinished.emit(task_name, result)
            except Exception as exc:
                logging.exception("Worker '%s' failed", task_name)
                self._workerErrored.emit(task_name, str(exc))

        threading.Thread(target=target, daemon=True).start()

    @Slot()
    @Slot(str)
    def inspectLibrary(self, explicit_path=""):
        path = _clean_path(explicit_path) or self._source_path
        if not path:
            self.toastRequested.emit("Hãy chọn file .so ARM64 đầu vào trước.", "warn")
            return
        if explicit_path:
            self.sourcePath = path

        def work():
            raw = read_library(path)
            elf = ELF(raw)
            elf.validate_target()
            summary = elf.summary()
            funcs = discover_functions(elf)
            find_rodata_string_refs(elf, funcs)
            secs = [
                {
                    "name": s.name or f"<type={s.type}>",
                    "vaddr": f"0x{s.addr:x}",
                    "offset": f"0x{s.offset:x}",
                    "size": s.size,
                    "exec": bool(s.flags & 0x4),
                    "write": bool(s.flags & 0x1),
                    "alloc": bool(s.flags & 0x2),
                }
                for s in elf.sections if s.size > 0
            ]
            return {"elf": elf, "summary": summary, "funcs": funcs, "sections": secs, "path": path}

        self._run_worker("inspect", f"Đang phân tích ELF & ranh giới hàm: {Path(path).name}…", work)

    @Slot()
    def runProtect(self):
        source = self._source_path
        output = self._output_path
        if not source or not output:
            self.toastRequested.emit("Hãy chọn đủ file .so đầu vào và đường dẫn output.", "warn")
            return
        try:
            opt = self._build_options_obj()
        except ProtectionError as exc:
            self.toastRequested.emit(str(exc), "error")
            self._set_status(str(exc), "error")
            return
        ndk = self._ndk_path or None
        force = self._force_overwrite

        def work():
            res = protect(source, output, opt, ndk=ndk, force=force, log=lambda m: self._logLineEmitted.emit(m))
            ver = verify_file(res["output"], res["report"])
            return {"protect": res, "verify": ver}

        self._run_worker("protect", f"Đang bảo vệ {Path(source).name} → {Path(output).name}…", work)

    @Slot()
    @Slot(str)
    def runVerify(self, explicit_path=""):
        path = _clean_path(explicit_path) or self._output_path or self._last_output_path
        if not path:
            self.toastRequested.emit("Chưa có file .so đầu ra để kiểm tra.", "warn")
            return

        def work():
            return verify_file(path)

        self._run_worker("verify", f"Đang xác minh cấu trúc & hash: {Path(path).name}…", work)

    @Slot()
    def runBenchmark(self):
        orig = self._bench_orig_path or self._source_path
        prot = self._bench_prot_path or self._last_output_path or self._output_path
        if not orig or not prot:
            self.toastRequested.emit("Chọn đủ file .so gốc và .so đã bảo vệ để đo benchmark.", "warn")
            return

        def work():
            orig_elf = ELF(read_library(orig))
            prot_elf = ELF(read_library(prot))
            report_file = Path(prot + ".protect3.json")
            report = json.loads(report_file.read_text(encoding="utf-8")) if report_file.is_file() else None
            return evaluate_protection_benchmark(orig_elf, prot_elf, report=report)

        self._run_worker("benchmark", f"Đang chạy benchmark A04–A06 trên {Path(prot).name}…", work)

    @Slot(str, str, str)
    def runAnalyzeLog(self, text, package_name, lib_name):
        self._triage_input = text or ""
        self._log_package = (package_name or "").strip() or "com.example.app"
        self._log_lib_name = (lib_name or "").strip() or "libnative.so"
        if not self._triage_input.strip():
            self.toastRequested.emit("Hãy dán nội dung logcat hoặc nạp file log .txt trước.", "warn")
            return

        def work():
            return analyze_log(self._triage_input, self._log_package, self._log_lib_name)

        self._run_worker("triage", f"Đang phân tích log cho package {self._log_package}…", work)

    @Slot(str)
    def loadTriageFile(self, raw_path):
        path = _clean_path(raw_path)
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
            self._triage_input = content[-250000:] if len(content) > 250000 else content
            self.triageChanged.emit()
            self.toastRequested.emit(f"Đã nạp log: {Path(path).name}", "info")
        except OSError as exc:
            self.toastRequested.emit(f"Không đọc được log: {exc}", "error")

    @Slot()
    def runBuildRuntime(self):
        ndk = self._ndk_path or None

        def work():
            blob, meta = build_runtime(ndk)
            return {"size": len(blob), "meta": meta}

        self._run_worker("build_runtime", "Đang biên dịch lại native/guard.c bằng Android NDK clang…", work)

    def _on_worker_finished(self, task_name, result):
        self._busy = False
        self._busy_label = ""
        self.busyChanged.emit()

        if task_name == "inspect":
            self._loaded_elf = result["elf"]
            self._discovered_funcs = result["funcs"]
            self._elf_summary = result["summary"]
            self._hardening_summary = result["summary"].get("native_hardening_audit", {})
            self._elf_sections = result["sections"]
            self._has_elf = True
            self.function_model.set_functions(self._discovered_funcs, self._assignment_lookup())
            self.elfChanged.emit()
            self.refreshPlan()
            msg = f"Đã phân tích {Path(result['path']).name}: {len(self._discovered_funcs)} hàm."
            self._set_status(msg, "success")
            self._append_log_line(msg)
            self.toastRequested.emit(msg, "success")

        elif task_name == "protect":
            res = result["protect"]
            ver = result["verify"]
            self._last_output_path = res["output"]
            self._last_report_path = res["report"]
            self._bench_orig_path = self._source_path
            self._bench_prot_path = res["output"]
            self._verify_result = ver
            self._has_verify_result = True

            details = res["details"]
            ledger = details.get("pass_ledger", {})
            inj = details.get("injection", {})
            ida_meta = inj.get("ida_anti_analysis", {})
            bench = ledger.get("benchmark_A04_A05_A06", {})
            self._last_protect_metrics = {
                "output": res["output"],
                "report": res["report"],
                "activeIds": ledger.get("active_roadmap_ids", []),
                "transformedCount": len(ledger.get("transformed_functions", [])),
                "stringsCount": ledger.get("encrypted_strings_count", 0),
                "warnings": details.get("warnings", []),
                "idaMeta": ida_meta,
                "benchmark": bench,
                "semantics": ledger.get("differential_semantics_F03", []),
            }
            self._append_log_line(f"✓ Đã xuất: {res['output']}")
            self._append_log_line(f"  Báo cáo: {res['report']}")
            if ledger.get("active_roadmap_ids"):
                self._append_log_line("  Roadmap IDs: " + ", ".join(ledger["active_roadmap_ids"]))
            if ida_meta.get("troll_ida") or ida_meta.get("block_ida"):
                self._append_log_line(
                    f"  IDA Anti-Analysis: block_ida={ida_meta.get('block_ida')}, troll_ida={ida_meta.get('troll_ida')}, "
                    f"renamed={ida_meta.get('renamed_functions_count')}, decoys={ida_meta.get('decoy_functions_count')}, "
                    f"chars={ida_meta.get('troll_barcode_chars')}, len={ida_meta.get('troll_barcode_length')}"
                )
            sem_list = ledger.get("differential_semantics_F03", [])
            if sem_list:
                p_cnt = sum(1 for r in sem_list if r.get("status") == "passed")
                s_cnt = sum(1 for r in sem_list if r.get("status") == "skipped")
                u_cnt = sum(1 for r in sem_list if r.get("status") == "unavailable")
                self._append_log_line(f"  Unicorn F03 Semantics: {p_cnt} passed, {s_cnt} skipped, {u_cnt} unavailable")
            self.verifyChanged.emit()
            self.benchmarkChanged.emit()
            self._set_status("Đã tạo & xác minh file .so bảo vệ thành công (cấu trúc/ABI đạt chuẩn).", "success")
            self.toastRequested.emit("Bảo vệ & xác minh file .so thành công!", "success")

        elif task_name == "verify":
            self._verify_result = result
            self._has_verify_result = True
            self.verifyChanged.emit()
            self._append_log_line(f"✓ Xác minh thành công: SHA256={result.get('sha256', '')[:16]}…")
            self._set_status("Hash SHA-256, cấu trúc ELF và watermark khớp báo cáo.", "success")
            self.toastRequested.emit("Kiểm tra output đạt chuẩn!", "success")

        elif task_name == "benchmark":
            self._bench_result = result
            self._has_bench_result = True
            self.benchmarkChanged.emit()
            metrics = result.get("metrics", {})
            self._set_status(
                f"Benchmark hoàn tất · text divergence={metrics.get('text_4gram_divergence', 0):.3f}",
                "success",
            )
            self.toastRequested.emit("Đã hoàn tất benchmark A04–A06!", "success")

        elif task_name == "triage":
            self._triage_result = result
            self._has_triage_result = True
            self.triageChanged.emit()
            cnt = len(result.get("findings", []))
            self._set_status(
                f"Phân tích log xong: {cnt} phát hiện, {len(result.get('guard_events', []))} guard events.",
                "warn" if cnt else "success",
            )
            self.toastRequested.emit("Đã phân tích xong logcat.", "info")

        elif task_name == "build_runtime":
            meta = result["meta"]
            self._runtime_summary = f"guard.bin {result['size']} bytes · SHA256 {meta['sha256'][:12]}… · {meta.get('compiler', '')}"
            self.runtimeChanged.emit()
            self._append_log_line(f"✓ Đã biên dịch lại runtime: {self._runtime_summary}")
            self._set_status("Đã biên dịch lại guard.bin bằng Android NDK.", "success")
            self.toastRequested.emit("Biên dịch guard.bin thành công!", "success")

    def _on_worker_errored(self, task_name, message):
        self._busy = False
        self._busy_label = ""
        self.busyChanged.emit()
        self._set_status(f"Lỗi ({task_name}): {message}", "error")
        self._append_log_line(f"✕ LỖI [{task_name}]: {message}")
        self.toastRequested.emit(message, "error")

    # ---------------- Utilities & Presets ----------------

    @Slot()
    def clearLog(self):
        self._log_lines = []
        self.logChanged.emit()

    @Slot(str)
    def copyText(self, text):
        cb = QGuiApplication.clipboard()
        if cb is not None:
            cb.setText(str(text or ""))
            self.toastRequested.emit("Đã sao chép vào clipboard.", "info")

    @Slot()
    def openOutputFolder(self):
        import os

        target = Path(self._last_output_path or self._output_path or ".").resolve().parent
        if not target.is_dir():
            self.toastRequested.emit("Thư mục output chưa tồn tại.", "warn")
            return
        if os.name == "nt":
            os.startfile(str(target))

    @Slot(str)
    def saveConfigProfile(self, raw_path):
        path = _clean_path(raw_path)
        if not path:
            return
        payload = {
            "schema": 1,
            "options": self._options,
            "decoys": self.decoy_model.items_copy() if self._decoys_modified else None,
        }
        try:
            Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            self.toastRequested.emit(f"Đã lưu cấu hình ra {Path(path).name}", "success")
        except OSError as exc:
            self.toastRequested.emit(f"Không lưu được cấu hình: {exc}", "error")

    @Slot(str)
    def loadConfigProfile(self, raw_path):
        path = _clean_path(raw_path)
        if not path:
            return
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            opts = payload.get("options", payload) if isinstance(payload, dict) else {}
            for k, v in opts.items():
                if k in self._options:
                    self._options[k] = v
            if self._options.get("pack_elf") and self._options.get("wrap_elf"):
                self._options["wrap_elf"] = False
            if isinstance(payload, dict) and payload.get("decoys"):
                parsed = parse_troll_decoys_spec(json.dumps(payload["decoys"]))
                self._set_decoys_items(parsed)
            self.optionsChanged.emit()
            self.function_model.update_assignments(self._assignment_lookup())
            self._refresh_barcode_previews()
            self.refreshPlan()
            self.toastRequested.emit(f"Đã nạp cấu hình từ {Path(path).name}", "success")
        except Exception as exc:
            self.toastRequested.emit(f"Không đọc được file cấu hình: {exc}", "error")
