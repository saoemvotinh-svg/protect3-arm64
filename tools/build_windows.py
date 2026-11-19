"""Build reproducible zero-dependency Windows portable distribution (Qt Quick Studio + CLI)."""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from protect3 import __version__
from protect3.runtime import build_runtime

GUI_EXCLUDES = [
    "torch", "torchaudio", "torchvision", "transformers", "scipy", "numpy", "pandas",
    "matplotlib", "cv2", "sklearn", "chromadb", "fastapi", "uvicorn", "selenium",
    "customtkinter", "tkinter", "_tkinter", "protect3.legacy_tk_gui", "capstone",
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick",
    "PySide6.Qt3DCore", "PySide6.Qt3DRender", "PySide6.Qt3DQuick", "PySide6.Qt3DInput",
    "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtGraphs",
    "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets", "PySide6.QtQuick3D",
    "PySide6.QtPdf", "PySide6.QtPdfWidgets", "PySide6.QtVirtualKeyboard",
    "PySide6.QtLocation", "PySide6.QtPositioning", "PySide6.QtSensors",
    "PySide6.QtTextToSpeech", "PySide6.QtBluetooth", "PySide6.QtNfc",
    "PySide6.QtSerialPort", "PySide6.QtSql", "PySide6.QtTest", "PySide6.QtWebSockets",
]

CLI_EXCLUDES = [
    "PySide6", "shiboken6", "customtkinter", "tkinter", "_tkinter", "PIL",
    "torch", "transformers", "scipy", "numpy", "pandas", "matplotlib",
]

DOCS_TO_INCLUDE = (
    "README.md",
    "docs/LIMITATIONS.md",
    "docs/TESTING.md",
    "docs/NATIVE_RESEARCH.md",
    "docs/PASS_COMPATIBILITY.md",
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _disable_guard_cf_for_unicorn(exe_path: Path):
    """Clear IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000) in-place so unicorn.dll QEMU longjmp does not __fastfail."""
    import pefile

    pe = pefile.PE(str(exe_path), fast_load=True)
    dc_off = pe.OPTIONAL_HEADER.get_field_absolute_offset("DllCharacteristics")
    cs_off = pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum")
    old_dc = pe.OPTIONAL_HEADER.DllCharacteristics
    pe.close()
    if not (old_dc & 0x4000):
        return
    raw = bytearray(exe_path.read_bytes())
    struct.pack_into("<H", raw, dc_off, old_dc & ~0x4000)
    pe2 = pefile.PE(data=bytes(raw), fast_load=True)
    new_cs = pe2.generate_checksum()
    pe2.close()
    struct.pack_into("<I", raw, cs_off, new_cs)
    exe_path.write_bytes(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-runtime-build", action="store_true")
    args = parser.parse_args()

    try:
        import PySide6  # noqa: F401
        import PyInstaller  # noqa: F401
        import pefile  # noqa: F401
        import unicorn  # noqa: F401
    except ImportError as exc:
        raise SystemExit(
            f"Missing packaging dependency ({exc}). Run with the Python environment that has PySide6, PyInstaller, pefile and unicorn installed."
        )

    unicorn_pkg = Path(unicorn.__file__).resolve().parent
    unicorn_dll = unicorn_pkg / "lib" / "unicorn.dll"
    if not unicorn_dll.is_file():
        raise SystemExit(f"Expected Unicorn DLL not found: {unicorn_dll}")

    if not args.skip_runtime_build:
        build_runtime()

    release_dir = ROOT / "release"
    portable_root = release_dir / "portable"
    portable_app = portable_root / "Protect3"
    portable_stage = portable_root / "Protect3.staging"
    checksums_dir = release_dir / "checksums"
    notes_dir = release_dir / "release-notes"
    dist_dir = ROOT / "dist"

    for d in (portable_root, checksums_dir, notes_dir, dist_dir):
        d.mkdir(parents=True, exist_ok=True)
    if portable_stage.exists():
        shutil.rmtree(portable_stage)
    # Fail fast BEFORE wiping existing portable_app if Protect3.exe is currently open
    if portable_app.exists():
        backup = portable_root / "Protect3.old"
        if backup.exists():
            shutil.rmtree(backup)
        try:
            portable_app.rename(backup)
            backup.rename(portable_app)
        except OSError as exc:
            raise SystemExit(
                f"Close running Protect3.exe before rebuilding portable release ({exc})."
            ) from exc

    icon_path = ROOT / "protect3" / "assets" / "protect3.ico"
    icon_args = ["--icon", str(icon_path)] if icon_path.is_file() else []

    # 1. Build Qt Quick Desktop Studio (--onedir portable bundle for fast <1s startup & zero temp extraction)
    gui_cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onedir", "--windowed",
        "--name", "Protect3",
        "--distpath", str(portable_stage),
        "--workpath", str(ROOT / "build" / "pyinstaller-Protect3"),
        "--specpath", str(ROOT / "build" / "specs"),
        "--add-data", f"{ROOT / 'protect3' / 'assets'};protect3/assets",
        "--add-data", f"{ROOT / 'protect3' / 'ui' / 'qml'};protect3/ui/qml",
        "--hidden-import", "PySide6.QtQuickShapes",
        "--hidden-import", "PySide6.QtQuickDialogs2",
        "--hidden-import", "PySide6.QtQuickControls2",
        "--collect-submodules", "unicorn",
        "--add-binary", f"{unicorn_dll};unicorn/lib",
        *icon_args,
    ]
    for mod in GUI_EXCLUDES:
        gui_cmd.extend(["--exclude-module", mod])
    gui_cmd.append(str(ROOT / "Protect3.pyw"))
    subprocess.run(gui_cmd, cwd=ROOT, check=True)
    staged_app = portable_stage / "Protect3"
    _disable_guard_cf_for_unicorn(staged_app / "Protect3.exe")

    # 2. Build standalone Console CLI (--onefile) without Qt bloat and ship alongside GUI + dist/
    cli_cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onefile", "--console",
        "--name", "protect3-cli",
        "--distpath", str(dist_dir),
        "--workpath", str(ROOT / "build" / "pyinstaller-protect3-cli"),
        "--specpath", str(ROOT / "build" / "specs"),
        "--add-data", f"{ROOT / 'protect3' / 'assets'};protect3/assets",
        "--collect-submodules", "unicorn",
        "--add-binary", f"{unicorn_dll};unicorn/lib",
        *icon_args,
    ]
    for mod in CLI_EXCLUDES:
        cli_cmd.extend(["--exclude-module", mod])
    cli_cmd.append(str(ROOT / "protect3_cli.py"))
    subprocess.run(cli_cmd, cwd=ROOT, check=True)
    _disable_guard_cf_for_unicorn(dist_dir / "protect3-cli.exe")

    if portable_app.exists():
        shutil.rmtree(portable_app)
    staged_app.rename(portable_app)
    if portable_stage.exists():
        shutil.rmtree(portable_stage, ignore_errors=True)

    shutil.copy2(dist_dir / "protect3-cli.exe", portable_app / "protect3-cli.exe")
    for doc_rel in DOCS_TO_INCLUDE:
        dst = portable_app / doc_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / doc_rel, dst)

    # Prune oversized unused Qt QML/translation plugins that aren't needed if any leaked in
    unused_qml = ("QtWebEngine", "Qt3D", "QtCharts", "QtDataVisualization", "QtGraphs",
                  "QtLocation", "QtMultimedia", "QtPositioning", "QtQuick3D", "QtSensors",
                  "QtTextToSpeech", "QtVirtualKeyboard", "QtWebChannel", "QtWebSockets", "QtWebView", "QtPdf")
    qml_root = portable_app / "_internal" / "PySide6" / "qml"
    if qml_root.is_dir():
        for name in unused_qml:
            candidate = qml_root / name
            if candidate.is_dir():
                shutil.rmtree(candidate, ignore_errors=True)
        qq_pdf = qml_root / "QtQuick" / "Pdf"
        if qq_pdf.is_dir():
            shutil.rmtree(qq_pdf, ignore_errors=True)
        qq_3d = qml_root / "QtQuick" / "Scene3D"
        if qq_3d.is_dir():
            shutil.rmtree(qq_3d, ignore_errors=True)

    # 3. Package Portable ZIP archive
    portable_zip = portable_root / f"Protect3-{__version__}-Windows-Portable.zip"
    with zipfile.ZipFile(portable_zip, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(portable_app.rglob("*")):
            if file.is_file():
                rel = file.relative_to(portable_root)
                archive.write(file, rel.as_posix())

    # Sync legacy dist zip/checksums cleanly so users checking dist/ also get the latest CLI & portable archive
    dist_zip = dist_dir / "Protect3-Windows.zip"
    shutil.copy2(portable_zip, dist_zip)
    stale_tk_exe = dist_dir / "Protect3.exe"
    if stale_tk_exe.exists():
        stale_tk_exe.unlink()

    checksums = [
        f"{_sha256(portable_app / 'Protect3.exe')}  portable/Protect3/Protect3.exe",
        f"{_sha256(portable_app / 'protect3-cli.exe')}  portable/Protect3/protect3-cli.exe",
        f"{_sha256(portable_zip)}  portable/{portable_zip.name}",
    ]
    (checksums_dir / "SHA256SUMS.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")

    dist_sums = [
        f"{_sha256(dist_dir / 'protect3-cli.exe')}  protect3-cli.exe",
        f"{_sha256(dist_zip)}  Protect3-Windows.zip",
    ]
    (dist_dir / "SHA256SUMS.txt").write_text("\n".join(dist_sums) + "\n", encoding="utf-8")

    release_notes = f"""# Protect3 {__version__} — Windows Portable Release Notes

## Phân phối Windows không cần cài đặt thủ công
- Giải nén `Protect3-{__version__}-Windows-Portable.zip` vào bất kỳ thư mục nào (hỗ trợ đường dẫn có dấu cách hoặc ký tự Unicode tiếng Việt).
- Chạy trực tiếp **`Protect3\\Protect3.exe`** bằng double-click (giao diện Qt Quick Studio, không cần cài Python, PySide6 hay Qt).
- Hoặc dùng CLI **`Protect3\\protect3-cli.exe`** cho kịch bản tự động hóa.

## Điểm mới trong bản phát hành này
- Nâng cấp toàn bộ giao diện lên **Qt Quick / PySide6 6.11.2 (Direct3D 11 RHI)** với thiết kế **Obsidian Binary Workbench**.
- Đưa toàn bộ tính năng backend ra giao diện: **Phân tích hàm F01/A03 (6.500+ hàm cuộn mượt)**, gán pass 1-click (`+VM`, `+Flat`, `+Obf`, `+Enc`, `+R07`), xem kế hoạch & xung đột F05 trực tiếp, **Benchmark A04–A06/A09**, **Phân tích Logcat**, biên dịch `guard.bin` qua NDK, cấu hình lưu tại `%LOCALAPPDATA%\\Protect3\\`.
- **Chống soi IDA Pro Studio (`--troll-ida`, `--block-ida`):** tùy chỉnh bộ ký tự random (mặc định `IlO0`), độ dài chuỗi random (`0..128`), xem trước 3 mẫu hàm trực tiếp, và trình chỉnh sửa nội tuyến đầy đủ cho danh sách tên hàm + chuỗi troll F5.

## Giới hạn môi trường ngoài ứng dụng
- Tính năng `--strip-symbols`, `--wrap-elf` và `Build guard.bin` cần **Android NDK** (các chế độ bảo vệ ELF/ChaCha20/VM/Obfuscation/String Vault/IDA Troll chạy offline hoàn toàn không cần NDK bằng `guard.bin` đã đóng gói sẵn).
- Đã tích hợp sẵn **Unicorn Engine F03 (`--verify-semantics`)** ngay bên trong cả `Protect3.exe` lẫn `protect3-cli.exe` để kiểm chứng ngữ nghĩa ARM64 trước khi lưu file `.so`.
"""
    (notes_dir / "RELEASE_NOTES.md").write_text(release_notes, encoding="utf-8")
    print(f"Built portable folder: {portable_app}")
    print(f"Built portable zip:    {portable_zip}")
    print(f"Built CLI executable:  {dist_dir / 'protect3-cli.exe'}")


if __name__ == "__main__":
    main()
