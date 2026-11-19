"""Small offline desktop interface. Worker threads never touch Tk widgets."""

import json
import os
from pathlib import Path
import queue
import secrets
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .elf import ELF, ProtectionError
from .engine import Options, capabilities, protect, read_library, verify_file
from .transforms import (
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


class Application:
    def __init__(self, window):
        self.window = window
        window.title(f"Protect3 {__version__} — Android ARM64")
        window.geometry("1120x980")
        window.minsize(920, 800)
        window.configure(bg="#101722")
        self.events = queue.Queue()
        self.busy = False
        self.last_output = None
        self.inputs = []
        self.source = tk.StringVar()
        self.output = tk.StringVar()
        default_ndk = os.environ.get("ANDROID_NDK_HOME", os.environ.get("ANDROID_NDK_ROOT", ""))
        if not default_ndk and Path("D:/Android/ndk/android-ndk-r27d").is_dir():
            default_ndk = "D:\\Android\\ndk\\android-ndk-r27d"
        self.ndk = tk.StringVar(value=default_ndk)
        self.function = tk.StringVar()
        self.vm_functions = tk.StringVar()
        self.flatten_functions = tk.StringVar()
        self.profile = tk.StringVar(value="")
        self.watermark = tk.StringVar()
        self.troll_chars = tk.StringVar(value=DEFAULT_BARCODE_CHARS)
        self.troll_length = tk.StringVar(value=str(DEFAULT_BARCODE_LENGTH))
        self.troll_decoy_items = [list(item) for item in DEFAULT_TROLL_DECOYS]
        self.troll_decoys_modified = False
        self.status = tk.StringVar(value="Sẵn sàng · đã tích sẵn các tính năng chạy tốt trên giả lập")
        gui_defaults = {
            **{key: value for key, value in Options().__dict__.items() if isinstance(value, bool)},
            "integrity": True,
            "debugger": True,
            "strip_symbols": bool(default_ndk),
            "encrypt_text": True,
            "encrypt_rodata": True,
            "encrypt_strings": True,
            "auth_encryption": True,
            "sign_manifest": True,
            "clean_metadata": True,
            "masked_key": True,
            "obfuscate_ops": True,
            "flatten_cfg": True,
            "virtualize_auto": True,
            "obfuscate_jni": True,
            "runtime_integrity": True,
            "guard_self_check": True,
            "compat_layout": True,
            "diagnostics": True,
            "report_only": True,
            "troll_ida": True,
            "block_ida": True,
            # Keep environment/self-scan blockers unchecked on rooted BlueStacks emulator:
            "hooks": False,
            "root": False,
            "emulator": False,
            "strict_proc": False,
            "deny_attach": False,
        }
        self.flags = {key: tk.BooleanVar(value=val) for key, val in gui_defaults.items()}
        style = ttk.Style(window)
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10), background="#101722", foreground="#e4ebf5")
        style.configure("TFrame", background="#101722")
        style.configure("Card.TFrame", background="#192333")
        style.configure("TLabel", background="#101722", foreground="#e4ebf5")
        style.configure("Muted.TLabel", foreground="#a9b7cb")
        style.configure("Title.TLabel", font=("Segoe UI Semibold", 24))
        style.configure("TEntry", fieldbackground="#0d1420", foreground="#e4ebf5", padding=6)
        style.configure("TButton", background="#2b3a50", foreground="#e4ebf5", padding=(12, 7))
        style.map("TButton", background=[("active", "#3a526e"), ("disabled", "#202a39")])
        style.configure("Accent.TButton", background="#297c68", font=("Segoe UI Semibold", 11))
        style.map("Accent.TButton", background=[("active", "#369a82"), ("disabled", "#243d38")])
        style.configure("TCheckbutton", background="#101722", foreground="#e4ebf5", padding=2)
        style.map("TCheckbutton", background=[("active", "#192333")], foreground=[("disabled", "#63748a")])
        style.configure("TLabelframe", background="#101722", bordercolor="#304159")
        style.configure("TLabelframe.Label", foreground="#87d9c2", background="#101722", font=("Segoe UI Semibold", 10))
        style.configure("TNotebook", background="#101722", borderwidth=0)
        style.configure("TNotebook.Tab", background="#223047", padding=(14, 6))
        style.map("TNotebook.Tab", background=[("selected", "#30445f")])

        root = ttk.Frame(window, padding=20)
        root.pack(fill="both", expand=True)
        title = ttk.Frame(root)
        title.pack(fill="x")
        ttk.Label(title, text="Protect3", style="Title.TLabel").pack(side="left")
        ttk.Label(title, text=f"ANDROID ARM64  /  v{__version__}", style="Muted.TLabel").pack(side="right", pady=12)
        ttk.Label(
            root,
            text="Thư viện .so vào · thư viện ELF .so ra · giữ nguyên ABI · hỗ trợ mã hóa, obfuscation, CFG flattening & ARM64 VM",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(0, 10))

        paths = ttk.LabelFrame(root, text="Thư viện", padding=10)
        paths.pack(fill="x")
        self._path(paths, 0, "File đầu vào", self.source, self.choose_input)
        self._path(paths, 1, "File đầu ra", self.output, self.choose_output)
        self._path(paths, 2, "NDK (cho strip / wrapper)", self.ndk, self.choose_ndk)
        paths.columnconfigure(1, weight=1)

        choices = ttk.LabelFrame(root, text="Các lớp bảo vệ .so (F01–F06, E01–E08, O01–O09, R01–R08, A01–A09)", padding=10)
        choices.pack(fill="x", pady=(10, 0))
        labels = [
            ("integrity", "SHA-256: kiểm tra mã khi nạp"),
            ("debugger", "Phát hiện debugger qua TracerPid"),
            ("hooks", "Dấu hiệu Frida / Xposed trong maps (prototype)"),
            ("root", "Dấu hiệu root / Magisk / Zygisk (prototype)"),
            ("emulator", "Dấu hiệu emulator (qemu / BlueStacks)"),
            ("strip_symbols", "Xóa symbol/debug không cần thiết (NDK)"),
            ("encrypt_text", "Mã hóa toàn .text bằng ChaCha20"),
            ("encrypt_rodata", "Mã hóa .rodata (chuỗi/hằng) — E02"),
            ("encrypt_strings", "Mã hóa chuỗi theo reference (String Vault) — E03"),
            ("auth_encryption", "Xác thực HMAC-SHA256 trước giải mã — E04"),
            ("sign_manifest", "Ký & xác minh manifest bảo vệ — E05"),
            ("clean_metadata", "Xóa metadata .comment/debug thừa — E06"),
            ("masked_key", "Dẫn xuất khóa KDF chống lộ key tĩnh — E07"),
            ("obfuscate_ops", "Làm rối lệnh ARM64 / hằng / nhánh — O01-O06"),
            ("flatten_cfg", "Làm phẳng luồng điều khiển (CFG Flattening) — O07"),
            ("virtualize_auto", "Tự chọn hàm tương thích đưa vào ARM64 VM — O08/O09"),
            ("obfuscate_jni", "Bảo vệ JNI_OnLoad / Java_* qua thunk gián tiếp"),
            ("runtime_integrity", "Kiểm tra toàn vẹn & prologue lúc chạy — R01/R02"),
            ("guard_self_check", "Kiểm tra chéo toàn vẹn mã guard — R06"),
            ("compat_layout", "ELF tương thích BlueStacks / native bridge"),
            ("diagnostics", "Ghi log giai đoạn native vào logcat"),
            ("report_only", "Chỉ ghi log khi phát hiện môi trường"),
            ("strict_proc", "Dừng nếu không đọc được procfs"),
            ("deny_attach", "PR_SET_DUMPABLE=0 (chặn /proc/self/mem; tắt nếu .so tự quét bộ nhớ)"),
            ("troll_ida", "Troll IDA Pro: đổi tên sub_... ngẫu nhiên & bơm hàm bẫy F5"),
            ("block_ida", "Ẩn code thật trên IDA: xóa segment .text/.guard (tắt nếu muốn xem list hàm)"),
        ]
        for i, (key, label) in enumerate(labels):
            widget = ttk.Checkbutton(choices, text=label, variable=self.flags[key])
            widget.grid(row=i // 2, column=i % 2, sticky="w", padx=(0, 16), pady=1)
            self.inputs.append(widget)
        choices.columnconfigure(0, weight=1)
        choices.columnconfigure(1, weight=1)

        base_row = (len(labels) + 1) // 2
        ttk.Label(choices, text="Mã hóa hàm cụ thể (E01; tên symbol/FDE):").grid(row=base_row, column=0, sticky="w", pady=(6, 0))
        fn_entry = ttk.Entry(choices, textvariable=self.function)
        fn_entry.grid(row=base_row, column=1, sticky="ew", pady=(6, 0))
        self.inputs.append(fn_entry)

        ttk.Label(choices, text="Ảo hóa hàm ARM64 VM (O08; danh sách cách nhau dấu phẩy):").grid(row=base_row + 1, column=0, sticky="w", pady=(4, 0))
        vm_entry = ttk.Entry(choices, textvariable=self.vm_functions)
        vm_entry.grid(row=base_row + 1, column=1, sticky="ew", pady=(4, 0))
        self.inputs.append(vm_entry)

        ttk.Label(choices, text="Làm phẳng CFG hàm (O07) / Profile (compat, balanced, anti-analysis, max):").grid(row=base_row + 2, column=0, sticky="w", pady=(4, 0))
        prof_frame = ttk.Frame(choices)
        prof_frame.grid(row=base_row + 2, column=1, sticky="ew", pady=(4, 0))
        flat_entry = ttk.Entry(prof_frame, textvariable=self.flatten_functions)
        flat_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        prof_entry = ttk.Entry(prof_frame, textvariable=self.profile, width=16)
        prof_entry.pack(side="right")
        self.inputs.extend((flat_entry, prof_entry))

        ttk.Label(choices, text="Tùy chỉnh Troll IDA (ký tự / độ dài / tên hàm & string):").grid(
            row=base_row + 3, column=0, sticky="w", pady=(4, 0)
        )
        troll_frame = ttk.Frame(choices)
        troll_frame.grid(row=base_row + 3, column=1, sticky="ew", pady=(4, 0))
        ttk.Label(troll_frame, text="Ký tự:").pack(side="left", padx=(0, 4))
        chars_entry = ttk.Entry(troll_frame, textvariable=self.troll_chars, width=12)
        chars_entry.pack(side="left", padx=(0, 8))
        ttk.Label(troll_frame, text="Độ dài:").pack(side="left", padx=(0, 4))
        len_entry = ttk.Entry(troll_frame, textvariable=self.troll_length, width=5)
        len_entry.pack(side="left", padx=(0, 8))
        self.troll_edit_btn = ttk.Button(
            troll_frame,
            text=f"Chỉnh hàm & string troll ({len(self.troll_decoy_items)} mục)…",
            command=self.open_troll_editor,
        )
        self.troll_edit_btn.pack(side="right", fill="x", expand=True)
        self.inputs.extend((chars_entry, len_entry, self.troll_edit_btn))

        actions = ttk.Frame(root)
        actions.pack(fill="x", pady=(10, 0))
        for label, callback, accent in (
            ("Phân tích .so", self.inspect, False),
            ("Tạo .so bảo vệ", self.run_protection, True),
            ("Kiểm tra output", self.verify, False),
        ):
            button = ttk.Button(actions, text=label, command=callback, style="Accent.TButton" if accent else "TButton")
            button.pack(side="left", padx=(0, 8))
            self.inputs.append(button)
        ttk.Button(actions, text="Mở thư mục kết quả", command=self.open_folder).pack(side="right")
        self.progress = ttk.Progressbar(root, mode="indeterminate")
        self.progress.pack(fill="x", pady=(8, 4))
        ttk.Label(root, textvariable=self.status, style="Muted.TLabel").pack(anchor="w")

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, pady=(8, 0))
        self.log = self._text_tab(notebook, "Tiến trình / kết quả")
        self.support = self._text_tab(notebook, "Phạm vi tính năng")
        for feature in capabilities():
            self.support.insert("end", f"{feature['feature']}  [{feature['status']} · {feature.get('maturity', '')}]\n{feature['scope']}\n\n")
        self.support.configure(state="disabled")
        self._append(
            "Chọn thư viện ARM64 để bắt đầu. File gốc luôn được giữ lại.\n"
            "Giữ tắt các probe root/emulator/hooks khi chạy thử trên giả lập root đang phát triển.\n"
        )
        window.after(100, self.drain)
        window.protocol("WM_DELETE_WINDOW", self.close)

    def _text_tab(self, notebook, label):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=label)
        text = tk.Text(
            frame, bg="#0d1420", fg="#d4e3f3", insertbackground="#e4ebf5", borderwidth=0,
            font=("Consolas", 10), wrap="word", padx=12, pady=10, height=8,
        )
        scrollbar = ttk.Scrollbar(frame, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        return text

    def _path(self, parent, row, label, variable, callback):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=3)
        entry = ttk.Entry(parent, textvariable=variable)
        entry.grid(row=row, column=1, sticky="ew", pady=3)
        button = ttk.Button(parent, text="Chọn…", command=callback)
        button.grid(row=row, column=2, padx=(8, 0), pady=3)
        self.inputs.extend((entry, button))

    def choose_input(self):
        path = filedialog.askopenfilename(title="Chọn thư viện Android ARM64", filetypes=[("Shared library", "*.so"), ("All files", "*")])
        if path:
            self.source.set(path)
            p = Path(path)
            self.output.set(str(p.parent / "protected" / p.name))

    def choose_output(self):
        path = filedialog.asksaveasfilename(title="Lưu thư viện đã bảo vệ", defaultextension=".so", filetypes=[("Shared library", "*.so")])
        if path:
            self.output.set(path)

    def choose_ndk(self):
        path = filedialog.askdirectory(title="Chọn thư mục Android NDK")
        if path:
            self.ndk.set(path)

    def _append(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text if text.endswith("\n") else text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def start(self, label, operation):
        if self.busy:
            return
        self.busy = True
        self.status.set(label)
        for widget in self.inputs:
            widget.configure(state="disabled")
        self.progress.start(12)
        self._append("\n" + label)

        def worker():
            try:
                self.events.put(("done", operation()))
            except Exception as exc:
                self.events.put(("error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def inspect(self):
        source = self.source.get()
        self.start("Đang phân tích cấu trúc ELF…", lambda: ("inspect", ELF(read_library(source)).summary()))

    def open_troll_editor(self):
        dialog = TrollDecoysDialog(
            self.window,
            items=self.troll_decoy_items,
            barcode_chars=self.troll_chars.get(),
            barcode_length=self.troll_length.get(),
        )
        self.window.wait_window(dialog)
        if dialog.saved_items is not None:
            self.troll_decoy_items = [list(x) for x in dialog.saved_items]
            self.troll_decoys_modified = self.troll_decoy_items != [list(x) for x in DEFAULT_TROLL_DECOYS]
            self.troll_edit_btn.configure(text=f"Chỉnh hàm & string troll ({len(self.troll_decoy_items)} mục)…")

    def run_protection(self):
        source, output, ndk = self.source.get(), self.output.get(), self.ndk.get() or None
        if not source or not output:
            messagebox.showerror("Thiếu đường dẫn", "Chọn file đầu vào và đầu ra .so.")
            return
        try:
            troll_len = validate_barcode_length(self.troll_length.get().strip())
            troll_chars = normalize_barcode_chars(self.troll_chars.get(), allow_empty=(troll_len == 0))
            decoys_spec = format_troll_decoys_spec(self.troll_decoy_items) if self.troll_decoys_modified else ""
        except ProtectionError as exc:
            messagebox.showerror("Cấu hình Troll IDA chưa hợp lệ", str(exc))
            return
        fn_text = self.function.get().strip()
        options = Options(
            encrypt_function=fn_text if "," not in fn_text else "",
            encrypt_functions=fn_text if "," in fn_text else "",
            virtualize_functions=self.vm_functions.get().strip(),
            flatten_functions=self.flatten_functions.get().strip(),
            profile=self.profile.get().strip(),
            watermark=self.watermark.get().strip(),
            troll_barcode_chars=troll_chars,
            troll_barcode_length=troll_len,
            troll_decoys=decoys_spec,
            **{key: variable.get() for key, variable in self.flags.items()},
        )
        self.start(
            "Đang tạo thư viện bảo vệ…",
            lambda: ("protect", protect(source, output, options, ndk, log=lambda message: self.events.put(("log", message)))),
        )

    def verify(self):
        output = self.output.get()
        self.start("Đang kiểm tra hash và cấu trúc output…", lambda: ("verify", verify_file(output)))

    def open_folder(self):
        path = Path(self.last_output or self.output.get() or ".").resolve().parent
        if not path.is_dir():
            messagebox.showerror("Chưa có kết quả", "Thư mục kết quả chưa tồn tại.")
        elif os.name == "nt":
            os.startfile(str(path))

    def drain(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._append(payload)
                    continue
                self.busy = False
                self.progress.stop()
                for widget in self.inputs:
                    widget.configure(state="normal")
                if kind == "error":
                    self.status.set("Chưa tạo được kết quả — xem lỗi bên dưới")
                    self._append("LỖI: " + payload)
                    messagebox.showerror("Protect3", payload)
                else:
                    action, result = payload
                    if action == "protect":
                        self.last_output = result["output"]
                        self._append("Đã lưu: " + result["output"] + "\nBáo cáo: " + result["report"])
                        ids = result["details"].get("pass_ledger", {}).get("active_roadmap_ids", [])
                        if ids:
                            self._append("Active IDs: " + ", ".join(ids))
                        ida_meta = result["details"].get("injection", {}).get("ida_anti_analysis", {})
                        if ida_meta.get("troll_ida") or ida_meta.get("block_ida"):
                            preview = ", ".join(ida_meta.get("decoy_names_preview", [])[:3])
                            self._append(
                                f"IDA Anti-Analysis: block_ida={ida_meta.get('block_ida')}, "
                                f"troll_ida={ida_meta.get('troll_ida')}, renamed={ida_meta.get('renamed_functions_count', 0)}, "
                                f"decoys={ida_meta.get('decoy_functions_count', 0)}, chars={ida_meta.get('troll_barcode_chars')}, "
                                f"len={ida_meta.get('troll_barcode_length')}" + (f" ({preview}...)" if preview else "")
                            )
                        for warning in result["details"]["warnings"]:
                            self._append("• " + warning)
                        self.status.set("Đã tạo output; cấu trúc/ABI đạt kiểm tra. Chưa kiểm thử nạp trên thiết bị Android.")
                    else:
                        self._append(json.dumps(result, indent=2, ensure_ascii=False))
                        self.status.set("Đã phân tích." if action == "inspect" else "Hash file và cấu trúc khớp báo cáo; chưa phải kiểm thử thiết bị.")
        except queue.Empty:
            pass
        self.window.after(100, self.drain)

    def close(self):
        if self.busy:
            messagebox.showinfo("Protect3 đang xử lý", "Đợi thao tác hiện tại hoàn tất trước khi đóng.")
            return
        self.window.destroy()


class TrollDecoysDialog(tk.Toplevel):
    """Dark-themed visual editor for customizable IDA troll decoy function names and F5 strings."""

    def __init__(self, parent, items, barcode_chars, barcode_length):
        super().__init__(parent)
        self.title("Chỉnh danh sách tên hàm & string troll (IDA Pro F5)")
        self.geometry("1000x700")
        self.minsize(820, 560)
        self.configure(bg="#101722")
        self.transient(parent)
        self.grab_set()
        self.saved_items = None
        self.barcode_chars = barcode_chars
        self.barcode_length = barcode_length
        self.items = [list(x) for x in items] or [list(x) for x in DEFAULT_TROLL_DECOYS]

        style = ttk.Style(self)
        style.configure(
            "Troll.Treeview",
            background="#0d1420",
            fieldbackground="#0d1420",
            foreground="#e4ebf5",
            rowheight=24,
            borderwidth=0,
        )
        style.map("Troll.Treeview", background=[("selected", "#297c68")], foreground=[("selected", "#ffffff")])
        style.configure("Troll.Treeview.Heading", background="#223047", foreground="#e4ebf5", font=("Segoe UI Semibold", 9))

        wrap = ttk.Frame(self, padding=14)
        wrap.pack(fill="both", expand=True)

        top = ttk.Frame(wrap)
        top.pack(fill="x", pady=(0, 8))
        self.preview_var = tk.StringVar()
        ttk.Label(top, textvariable=self.preview_var, foreground="#87d9c2", font=("Consolas", 10)).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(top, text="Random thử mẫu", command=self.refresh_preview).pack(side="right")

        table_frame = ttk.Frame(wrap)
        table_frame.pack(fill="both", expand=True)
        cols = ("idx", "name", "msg", "alt")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", style="Troll.Treeview", selectmode="browse")
        self.tree.heading("idx", text="#")
        self.tree.heading("name", text="Tên hàm (gợi ý IDA Functions)")
        self.tree.heading("msg", text="String troll chính (F5 nhánh else)")
        self.tree.heading("alt", text="String phụ (khi a1 == 1337)")
        self.tree.column("idx", width=40, anchor="center", stretch=False)
        self.tree.column("name", width=260)
        self.tree.column("msg", width=400)
        self.tree.column("alt", width=240)
        ysb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        form = ttk.LabelFrame(wrap, text="Chỉnh dòng đang chọn hoặc thêm mới", padding=10)
        form.pack(fill="x", pady=(10, 0))
        self.var_name = tk.StringVar()
        self.var_main = tk.StringVar()
        self.var_alt = tk.StringVar()
        for r, (lbl, var) in enumerate((
            ("Tên hàm (tự chuẩn hóa ký tự):", self.var_name),
            ("String troll chính (F5):", self.var_main),
            ("String phụ (nếu a1==1337):", self.var_alt),
        )):
            ttk.Label(form, text=lbl).grid(row=r, column=0, sticky="w", padx=(0, 10), pady=3)
            ttk.Entry(form, textvariable=var).grid(row=r, column=1, sticky="ew", pady=3)
        form.columnconfigure(1, weight=1)

        row_btns = ttk.Frame(wrap)
        row_btns.pack(fill="x", pady=(8, 0))
        for text, cmd in (
            ("Cập nhật dòng chọn", self.update_selected),
            ("Thêm dòng mới", self.add_item),
            ("Lên", lambda: self.move_selected(-1)),
            ("Xuống", lambda: self.move_selected(1)),
            ("Xóa dòng chọn", self.delete_selected),
        ):
            ttk.Button(row_btns, text=text, command=cmd).pack(side="left", padx=(0, 6))
        ttk.Button(row_btns, text="Sửa nhanh (Text/Bulk)", command=self.open_bulk_edit).pack(side="right")

        bottom = ttk.Frame(wrap)
        bottom.pack(fill="x", pady=(10, 0))
        for text, cmd in (
            ("Nạp file (.txt/.json)", self.import_file),
            ("Lưu file (.json)", self.export_file),
            ("Khôi phục mặc định (24)", self.reset_defaults),
        ):
            ttk.Button(bottom, text=text, command=cmd).pack(side="left", padx=(0, 6))
        ttk.Button(bottom, text="Hủy", command=self.destroy).pack(side="right")
        ttk.Button(bottom, text="Lưu danh sách & Đóng", style="Accent.TButton", command=self.save_and_close).pack(
            side="right", padx=(0, 8)
        )

        self._reload_tree(select_idx=0)
        self.refresh_preview()

    def _selected_index(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return int(sel[0])

    def _reload_tree(self, select_idx=None):
        self.tree.delete(*self.tree.get_children())
        for i, (name, msg, alt) in enumerate(self.items):
            self.tree.insert("", "end", iid=str(i), values=(i + 1, name, msg, alt))
        if self.items:
            idx = max(0, min(select_idx if select_idx is not None else 0, len(self.items) - 1))
            self.tree.selection_set(str(idx))
            self.tree.see(str(idx))
            self._fill_form(idx)

    def _fill_form(self, idx):
        name, msg, alt = self.items[idx]
        self.var_name.set(name)
        self.var_main.set(msg)
        self.var_alt.set(alt)

    def _on_select(self, _event=None):
        idx = self._selected_index()
        if idx is not None and 0 <= idx < len(self.items):
            self._fill_form(idx)
            self.refresh_preview()

    def refresh_preview(self):
        idx = self._selected_index()
        base = self.items[idx][0] if (idx is not None and 0 <= idx < len(self.items)) else "Ham_Troll_01"
        clean_base = sanitize_troll_symbol_name(self.var_name.get().strip() or base)
        try:
            length = validate_barcode_length((self.barcode_length or "").strip() or "0")
            chars = normalize_barcode_chars(self.barcode_chars, allow_empty=(length == 0))
            sample = generate_troll_barcode(
                secrets.randbits(64), "preview", (idx or 0) + 1, chars, length, suffix=f"_{clean_base}"
            )
            self.preview_var.set(f"Xem trước tên hàm ({len(sample) - len(clean_base) - 1} ký tự random): {sample}")
        except ProtectionError as exc:
            self.preview_var.set(f"Cảnh báo ký tự/độ dài: {exc}")

    def _read_form_entry(self, fallback_idx):
        name = sanitize_troll_symbol_name(self.var_name.get(), fallback=f"Troll_Func_{fallback_idx:02d}")
        msg_main = sanitize_troll_string(self.var_main.get(), fallback=f"[Protect3] Trolled by {name}!")
        raw_alt = self.var_alt.get().strip()
        msg_alt = sanitize_troll_string(raw_alt) if raw_alt else f"[1337] {msg_main}"
        return [name, msg_main, msg_alt]

    def update_selected(self):
        idx = self._selected_index()
        if idx is None:
            self.add_item()
            return
        self.items[idx] = self._read_form_entry(idx + 1)
        self._reload_tree(select_idx=idx)
        self.refresh_preview()

    def add_item(self):
        if len(self.items) >= 128:
            messagebox.showwarning("Giới hạn", "Tối đa 128 hàm troll F5 mỗi thư viện.", parent=self)
            return
        entry = self._read_form_entry(len(self.items) + 1)
        self.items.append(entry)
        self._reload_tree(select_idx=len(self.items) - 1)
        self.refresh_preview()

    def delete_selected(self):
        idx = self._selected_index()
        if idx is None:
            return
        if len(self.items) <= 1:
            messagebox.showwarning("Cần ít nhất 1 mục", "Cần giữ lại ít nhất 1 hàm bẫy.", parent=self)
            return
        del self.items[idx]
        self._reload_tree(select_idx=min(idx, len(self.items) - 1))
        self.refresh_preview()

    def move_selected(self, delta):
        idx = self._selected_index()
        if idx is None:
            return
        target = idx + delta
        if 0 <= target < len(self.items):
            self.items[idx], self.items[target] = self.items[target], self.items[idx]
            self._reload_tree(select_idx=target)

    def reset_defaults(self):
        self.items = [list(x) for x in DEFAULT_TROLL_DECOYS]
        self._reload_tree(select_idx=0)
        self.refresh_preview()

    def open_bulk_edit(self):
        top = tk.Toplevel(self)
        top.title("Sửa nhanh hàng loạt (mỗi dòng: Ten_Ham | String chinh | String phu)")
        top.geometry("820x520")
        top.configure(bg="#101722")
        top.transient(self)
        top.grab_set()
        ttk.Label(
            top,
            text="Định dạng mỗi dòng: Ten_Ham | String troll F5 | String phu (tùy chọn) — hoặc dán JSON [...]",
            style="Muted.TLabel",
        ).pack(anchor="w", padx=12, pady=(10, 4))
        box = tk.Text(top, bg="#0d1420", fg="#e4ebf5", insertbackground="#e4ebf5", font=("Consolas", 10), wrap="word")
        box.pack(fill="both", expand=True, padx=12, pady=4)
        box.insert("1.0", "\n".join(f"{n} | {m} | {a}" for n, m, a in self.items))

        def apply_bulk():
            try:
                parsed = parse_troll_decoys_spec(box.get("1.0", "end"))
            except ProtectionError as exc:
                messagebox.showerror("Định dạng chưa hợp lệ", str(exc), parent=top)
                return
            self.items = [list(x) for x in parsed]
            self._reload_tree(select_idx=0)
            self.refresh_preview()
            top.destroy()

        btns = ttk.Frame(top)
        btns.pack(fill="x", padx=12, pady=(4, 10))
        ttk.Button(btns, text="Hủy", command=top.destroy).pack(side="right")
        ttk.Button(btns, text="Áp dụng danh sách", style="Accent.TButton", command=apply_bulk).pack(side="right", padx=(0, 8))

    def import_file(self):
        path = filedialog.askopenfilename(
            parent=self,
            title="Chọn file danh sách tên hàm / string troll",
            filetypes=[("Troll list", "*.txt *.json"), ("All files", "*")],
        )
        if not path:
            return
        try:
            parsed = parse_troll_decoys_spec(Path(path).read_text(encoding="utf-8"))
        except (OSError, ProtectionError) as exc:
            messagebox.showerror("Không đọc được file", str(exc), parent=self)
            return
        self.items = [list(x) for x in parsed]
        self._reload_tree(select_idx=0)
        self.refresh_preview()

    def export_file(self):
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Lưu danh sách troll ra file JSON",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Text", "*.txt")],
        )
        if not path:
            return
        if path.lower().endswith(".txt"):
            content = "\n".join(f"{n} | {m} | {a}" for n, m, a in self.items) + "\n"
        else:
            content = json.dumps(
                [{"name": n, "msg": m, "alt": a} for n, m, a in self.items],
                indent=2,
                ensure_ascii=False,
            ) + "\n"
        Path(path).write_text(content, encoding="utf-8")

    def save_and_close(self):
        self.saved_items = [list(x) for x in self.items]
        self.destroy()


def launch():
    """Launch legacy Tkinter desktop interface."""
    window = tk.Tk()
    Application(window)
    window.mainloop()
