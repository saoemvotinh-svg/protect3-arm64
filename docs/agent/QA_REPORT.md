# Protect3 Desktop Studio — QA Verification Report (Phase 8 + R09 + Adaptive Execution & Red Conflicts)

## 1. Test Summary (All Verified After Final Code Edits)

| Suite / Check | Environment | Result | Details |
|---|---|---|---|
| `tests/test_ui_qt.py` | Python 3.13 (`PySide6 6.11.2`, `unicorn 2.1.4`) | **3 / 3 OK** (`5.850s`) | Zero QML warnings across all 5 tabs in Dark (`1.0x`) and Light (`1.3x`) modes AND under simultaneous active conflicts; verifies default active-blocking startup (`report_only=False`, `deny_attach=True`, `runtime_anti_debug=True`, `auto_select_functions=True`), `autoPopulateFunctions()`, `apk_anti_cheat` + `bluestacks_safe` presets, live `F03`, and layered `E08`. |
| `tests/test_diagnostics.py`, `tests/test_protect3.py`, `tests/test_v03_roadmap.py` | `.venv` Python 3.10.5 (`unicorn 2.1.4`) | **55 / 55 OK** (`8.857s`) | Rebuilt `guard.bin` (`29648` bytes, `a455d9f61052`); verifies `p3_vm_call_trampoline` ABI (`X8` `sret`, 128-bit `(X0, X1)`, outgoing `[SP]` stack args), `E03+` survival across `p3_runtime_check` gates, throttled heavy `.text` hash via `st[4]`, `arm64.py` `has_internal_adr_reference` / `reads_caller_stack` guards, `RW` Honeypot (`179`), `/proc/self/task` (`180`), `SIGSTOP` (`180`), and layered `E08`. |
| `libloader.so` (`C:\Users\hung\Desktop\libloader.so`, `4.49 MB`, `2253` FDEs) | `.venv` Python 3.10.5 Unicorn verification | **PASSED** | Verified `fde_29f330` bit-for-bit 16-octet outgoing stack args `(X2..X7 + SP+0..72)` to `BL 0x26d128`, `fde_26de14` 5-call throttled gate (`0.032s`), and `E03+` vault survival across `p3_runtime_check` (`task-2786`/`task-2803`). Live APK device re-test pending by user. |
| `tools/preview_gui.py` | Python 3.13 (`PySide6 6.11.2`, `unicorn 2.1.4`) | **PASSED** | End-to-end protect + verify on `libsample.so` and captured `build/gui-preview.png`. |
| Live Desktop & Standalone F03/Anti-GG Smoke Test | Rebuilt `release/portable/Protect3/Protect3.exe`, `release/portable/Protect3/protect3-cli.exe` & `dist/protect3-cli.exe` | **PASSED** | All three EXEs confirmed `DllCharacteristics=0x8160` (`GUARD_CF=False`); `Protect3.exe` opened GUI window (`GUI_ALIVE=True`, `HWND=7998316`, `NO_LOG_ERRORS=True`); `protect3-cli.exe protect ... --virtualize-auto --gg-honeypot --anti-gg --deny-attach --verify-semantics` under stripped `PATH=C:\Windows\System32;C:\Windows` exited `0` (`GUARD_SHA=a455d9f61052`, `R09_IN_LEDGER=True`, `Java_com_example_Sample_nativeValue:passed, JNI_OnLoad:passed`); `dist/protect3-cli.exe capabilities` exited `0`. |

## 2. Release Artifacts Verified
- `release/portable/Protect3/Protect3.exe` — SHA-256 `c6c99b31e3a368930c94fc79017dee28255e3fa34052bd03cbf07a265334e3b4`
- `release/portable/Protect3/protect3-cli.exe` — SHA-256 `f8a4332cb5f6bafdddb6621552ecfb504abdf8df370e1e443c7f5c102d158c78`
- `release/portable/Protect3-0.3.0-Windows-Portable.zip` — SHA-256 `0a3cc6ea3d2047804320df4161e698cb928030604dc26131fc82b23460d81ba`
- `release/checksums/SHA256SUMS.txt` & `release/release-notes/RELEASE_NOTES.md`
- `dist/protect3-cli.exe` synced cleanly.

## 3. Scope & Unverified Items (Honest Disclosure)
- **Clean bare Windows VM (no Python/VC runtime anywhere on host):** Tested using stripped `PATH=C:\Windows\System32;C:\Windows` and isolated `LOCALAPPDATA`/`APPDATA` in a Unicode+Spaces directory on the host Windows 11 machine; has **not** been tested inside a separate clean Windows VM devoid of system-wide Microsoft Visual C++ Redistributable DLLs.
- **`--strip-symbols`, `--wrap-elf`, and `Build guard.bin`:** Verified functional with host Android NDK (`r27d`); naturally require an external Android NDK installation when enabled by the user.
- **UI regression tests under `.venv`:** Running `unittest discover` under `.venv` skips `tests/test_ui_qt.py` cleanly because `.venv` has `unicorn` rather than `PySide6`; conversely Python 3.13 runs `test_ui_qt.py` with `PySide6`.
- **Simulated `SIGSTOP` pause under `libnb.so` timing:** Inside the temporary `libnb.so` harness, an external `fork()` `SIGSTOP` can land between gate calls rather than inside the ~0.2ms `CLOCK_MONOTONIC`/`CLOCK_PROCESS_CPUTIME_ID` check window; deterministic `wall_ms > 2500 && cpu_ms < 250 -> exit 180` behavior is covered in `test_r09_gg_honeypot_ephemeral_vault_anti_gg_and_opsec` (Unicorn).
