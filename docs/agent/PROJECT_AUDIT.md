# Protect3 Project Audit (Phase 1)

## 1. Repository Reality & Environment
- **Location:** `c:\Users\hung\Desktop\Protect3` (non-Git workspace directory; rollback requires explicit backups before destructive edits).
- **Version:** `0.3.0` (`pyproject.toml`, `protect3/__init__.py`).
- **Core Domain:** Offline **Android ARM64 (`ET_DYN` ELF64 LE) Native Binary Protector, Obfuscator, Bytecode VM Compiler & Anti-Analysis Studio** (`.so -> .so` without source code).
- **Primary Persona:** Android C++/NDK security developer protecting compiled game/app native libraries (`.so`) against static disassembly (IDA Pro / Hex-Rays / Ghidra) and runtime tampering/hooking while preserving `.dynsym`/JNI ABI compatibility.
- **Python Environments Observed:**
  - `.venv` (`Python 3.10.5`): `unicorn 2.1.4`, `pillow 12.3.0`, `pyinstaller 6.22.3` (no `PySide6`).
  - System Python (`Python 3.13.14` WindowsApps): `PySide6 6.11.2` (`Qt 6.11.2`, Direct3D 11 RHI), `PySide6_Addons 6.11.2`, `PySide6_Essentials 6.11.2`, `pyinstaller 6.22.3`, `pillow 12.3.0`, `customtkinter 5.2.2`.
  - Bundled native runtime: `protect3/assets/guard.bin` (25,104 bytes) + `guard.json`, built from `native/guard.c`, `native/crypto.c`, `native/crypto.h`, `native/guard.ld` via Android NDK (`D:\Android\ndk\android-ndk-r27d`).

## 2. Functional Inventory (`B3`)

| Function | Entry Point | Current UI (`gui.py` Tkinter) | Backend Module | Dependencies | Risk | Migration Strategy |
|---|---|---|---|---|---|---|
| ELF Summary & Hardening Audit | `CLI inspect`, `Application.inspect` | Dumps raw JSON to 8-line text log | `elf.py`, `hardening.py` | Pure Python stdlib | Low | Dedicated Inspector metrics & badges |
| Function Discovery & A03 Scorer | `CLI inspect --functions` | **Hidden** (not exposed) | `arm64.py` (`discover_functions`) | Pure Python stdlib | Medium (6k+ rows need virtualized list) | `QAbstractListModel` + `FilterProxyModel` table + 1-click assignment |
| Protection Execution | `CLI protect`, `Application.run_protection` | 26 checkboxes + 5 inputs, 1 screen | `engine.py` (`protect`, `rewrite`, `rewrite_compatible`) | Stdlib (+ NDK only for strip/wrap_elf) | High (ABI/ELF invariants) | Preserve `protect()` call verbatim in worker thread |
| F05 Plan & Conflict Validation | `CLI plan` | **Hidden** (errors only after clicking Build) | `planner.py` (`build_protection_plan`) | Pure Python stdlib | Low | Debounced live plan preview & conflict banner |
| A02 Composite Profiles | `CLI --profile` | Raw text entry box | `planner.py` (`apply_profile_defaults`) | Pure Python stdlib | Low | Interactive preset selector chips + BlueStacks-safe preset |
| E01-E08 Crypto & Wrapper | `Options.*` | Partial (`wrap_elf`, `keep_debug` missing) | `engine.py`, `transforms.py`, `crypto.py` | Stdlib (+ NDK for `wrap_elf`) | Medium | Expose all E01-E08 options with inline conflict checks |
| O01-O09 Obfuscation & VM | `Options.*` | Partial (`obfuscate_functions` missing) | `transforms.py`, `arm64.py` | Pure Python stdlib | Medium | Expose + link directly from Function Inspector selection |
| R01-R08 Runtime & Env Probes | `Options.*` | Partial (`got_check`, `relro_check`, `prologue_check`, `runtime_anti_debug`, `deep_probes`, `on_demand_functions` missing) | `engine.py`, `native/guard.c` | Stdlib + `guard.bin` | Low | Grouped cards + BlueStacks root safety guidance |
| A01 Seed, A08 Watermark, F03 Semantics | `Options.seed`, `watermark`, `verify_semantics` | Orphan `self.watermark` var with no input widget; `seed` & `verify_semantics` missing | `planner.py` | Stdlib (+ optional `unicorn` for F03) | Low | Expose inputs + graceful F03 badge if `unicorn` absent |
| IDA Troll & Segment Hide | `--troll-ida`, `--block-ida`, custom chars/len/decoys | 2 checkboxes + 2 entries + modal `TrollDecoysDialog` | `transforms.py`, `engine.py` | Pure Python stdlib | Low | Inline full studio tab with live barcode preview & editable table |
| Output Verification | `CLI verify`, `Application.verify` | Button dumping raw JSON | `engine.py` (`verify_file`) | Pure Python stdlib | Low | Structured verification card + checksum/roadmap badges |
| Benchmark (A04-A06, A09) | `CLI benchmark` | **Hidden** | `planner.py` (`evaluate_protection_benchmark`) | Pure Python stdlib | Low | Dedicated Benchmark comparison tab |
| Logcat Crash Triage | `CLI analyze-log` | **Hidden** | `diagnostics.py` (`analyze_log`) | Pure Python stdlib | Low | Dedicated Log Triage tab (timeline + crash backtraces) |
| Runtime Rebuild | `CLI build-runtime` | **Hidden** | `runtime.py` (`build_runtime`) | Android NDK clang | Medium | Runtime status card & NDK compile action in Build workspace |
| Capability Matrix | `CLI capabilities` | Plain dump in second text tab | `engine.py` (`capabilities`) | Pure Python stdlib | Low | Interactive roadmap/capability status panel |

## 3. Usability Problems Found in Current `gui.py`
1. **Cognitive overload:** 26 checkboxes packed into one scroll-less frame alongside inputs and logs.
2. **Orphaned / hidden features:** ~60% of backend capabilities (`inspect --functions`, `plan`, `benchmark`, `analyze-log`, `build-runtime`, `R03/R04/R05/R07/R08/E08/A01/A08`) are absent from GUI; `self.watermark` was wired to `Options` with no text box.
3. **No interactive symbol picking:** Engineers must manually copy-paste stripped FDE names like `fde_73030` or JNI symbols instead of clicking them in a discovered function list.
4. **No `--force` overwrite option or preset persistence:** Output collisions fail the build instead of letting users opt into overwriting or remembering NDK/last paths.
5. **Tkinter limitations:** No hardware-accelerated transitions, sluggish rendering on large lists, fixed 1120x980 geometry without responsive pane adaptation.
