# Architecture Decision Record — Protect3 Desktop Studio (Phase 2)

## 1. Decision
Migrate the Protect3 desktop UI from monolithic Tkinter (`protect3/gui.py`) to **Qt Quick (QML) + PySide6 6.11.2 (Qt 6.11.2, Direct3D 11 RHI)** via clean Presentation ViewModels (`QObject`, `QAbstractListModel`, `QSortFilterProxyModel`), keeping the existing Python core engine (`protect3/*.py`) intact without rewrites or local HTTP/WebSocket servers.

## 2. Evaluated Options & Scoring Rationale

| Option | Core Compatibility | UI/Motion Freedom | Performance & List Scale | Distribution Portability | Verdict |
|---|---|---|---|---|---|
| **Qt Quick + QML + PySide6 6.11.2** | Direct in-process Python calls; zero IPC | Declarative tokens, D3D11 RHI animations, SVG `Shape` | Native GPU Scene Graph; virtualized `ListView` for 6,500+ ELF functions | PyInstaller `--onedir` standalone portable folder verified locally | **Selected** |
| **PySide6 Qt Widgets** | Direct in-process | Less cohesive custom motion & token styling | CPU/backingstore widgets; heavier custom paint code | Same as above | Rejected |
| **Tkinter / CustomTkinter** | Direct in-process | No real GPU animations; canvas flicker on scroll | Poor table virtualization for 6,500+ functions; High-DPI weak | Smaller binary but dated UX | Rejected (kept only as emergency fallback if PySide6 absent in dev source runs) |
| **Tauri / Electron (WebView)** | Requires HTTP/WebSocket/stdio IPC to Python | High | Higher RAM + WebView anti-pattern (`C3`) | Dual Python+Node runtime complexity | Rejected |
| **Avalonia UI (C# .NET 10)** | Would require rewriting ~4,500 LOC ELF/ARM64/VM engine or brittle CLI IPC | High | High | Native .NET | Rejected (`C2`: preserve Python core) |

## 3. Runtime Bootstrap & Technical Constraints Discovered
- **Windows Store Python QML Plugin Fix:** On Windows Store Python 3.13, `qtquick2plugin.dll` failed with `The specified module could not be found` until `PySide6/` and `shiboken6/` directories were explicitly registered via `os.add_dll_directory()` and prepended to `PATH` prior to instantiating `QQmlApplicationEngine`.
- **High-DPI & RHI Resilience:** Use `QtQuick.Controls.Basic` style so OS theme leakage cannot override obsidian design tokens; support `PROTECT3_SOFTWARE_RENDER=1` / `QT_QUICK_BACKEND=software` fallback environment handling if a user runs inside a GPU-less VM.

## 4. Target Module Architecture
```text
protect3/
  elf.py, arm64.py, crypto.py, hardening.py,
  planner.py, transforms.py, engine.py,
  diagnostics.py, runtime.py                <-- Existing Domain Core (untouched algorithms)
  ui/
    __init__.py         # Entrypoint launcher (DLL path setup + QML bootstrap)
    settings.py         # AppData JSON user preferences & preset persistence
    bridge.py           # Main Protect3ViewModel (QObject Properties, Slots, Signals)
    models.py           # Virtualized FunctionListModel & DecoyListModel & LogModel
    workers.py          # QRunnable / QThread background task runner (inspect/protect/verify/bench/triage)
    qml/
      Main.qml
      Theme.qml         # Single source of truth: color, type, spacing, radius, motion tokens
      components/       # Reusable styled buttons, switches, badges, cards, toast, dialog
      views/            # InspectorView, ProtectionMatrixView, IdaTrollView, BuildView, ToolsView
  gui.py                # Thin launcher delegating to protect3.ui.launch() (+ Tkinter fallback note)
```

## 5. Threading & Error Handling
- Heavy ELF parsing, ARM64 disassembly/discovery, ChaCha20/VM transformation, NDK `llvm-strip`/`clang`, and benchmark diffing run on dedicated worker threads (`threading.Thread` + Qt queued `Signal` emissions — never blocking UI thread or touching QML items from worker threads).
- Prevent duplicate overlapping jobs via explicit `busy` state lock; support cooperative cancellation before `protect()` starts/between stages; show actionable Vietnamese messages in UI while writing full diagnostic details to `%LOCALAPPDATA%\Protect3\protect3-desktop.log`.

## 6. Release Packaging Decision (`I2`)
- Use PyInstaller **`--onedir` portable bundle** under `release/portable/Protect3/` (with explicit module excludes for unused heavy packages like `QtWebEngine`, `Qt3D`, `torch`, `matplotlib`), zipped to `release/portable/Protect3-Windows-Portable.zip` + SHA-256 checksums (`release/checksums/`) + release notes (`release/release-notes/`), avoiding slow `--onefile` Qt6 extraction on startup. Keep `tools/build_windows.py` updated to produce reproducible builds.
