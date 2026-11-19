# Protect3 Desktop — Build & Packaging Guide

## 1. Environments
- **GUI & Windows Packaging (`Python 3.13`):** Requires `PySide6 >= 6.11` and `PyInstaller >= 6.22`.
- **Core / Unicorn Differential Tests (`.venv` `Python 3.10`):** Has `unicorn == 2.1.4` and `pyinstaller == 6.22.3`.

## 2. Running from Source
```powershell
python protect3_cli.py gui
```
Or double-click `Start-Protect3.cmd` (prefers built `release\portable\Protect3\Protect3.exe` if present).

## 3. Running Automated Tests
```powershell
# Qt Quick UI & ViewModel tests:
python -m unittest tests/test_ui_qt.py -v

# Core ELF/ARM64/VM/Crypto/Diagnostic tests (with Unicorn):
.\.venv\Scripts\python.exe -m unittest tests/test_diagnostics.py tests/test_protect3.py tests/test_v03_roadmap.py -v
```

## 4. Rebuilding the Zero-Dependency Windows Portable Release
```powershell
python tools/build_windows.py --skip-runtime-build
```
Outputs:
- `release/portable/Protect3/Protect3.exe` (`--onedir` standalone Qt Quick Studio + `_internal/`)
- `release/portable/Protect3/protect3-cli.exe` (and `dist/protect3-cli.exe`)
- `release/portable/Protect3-Windows-Portable.zip` (and synced `dist/Protect3-Windows.zip`)
- `release/checksums/SHA256SUMS.txt`
- `release/release-notes/RELEASE_NOTES.md`

To also recompile `protect3/assets/guard.bin` from `native/guard.c` using Android NDK before packaging, omit `--skip-runtime-build`.
