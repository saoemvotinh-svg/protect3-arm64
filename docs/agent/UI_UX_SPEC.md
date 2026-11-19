# UI/UX Specification & Design System — Protect3 Studio (Phase 3)

## 1. Visual Identity: "Obsidian Binary Workbench"
- **Tone:** Quiet, high-precision engineering workbench inspired by modern minimalist dark studios — deep obsidian surfaces, subtle 1px structural borders, high-contrast neutral text, tabular monospace addresses (`Consolas`), jade-mint active signal (`#2EC4A0`), warm amber warning (`#E8A849`), crimson fault (`#E56B6F`).
- **Why not SaaS cards:** Focuses maximum vertical space on dense binary diagnostics, 6,500+ searchable functions, conflict-checked pass toggles, live IDA symbol preview, and streaming build evidence without decorative noise.

## 2. Design Tokens (`Theme.qml`)
- **Surfaces:**
  - `bgCanvas`: `#0B1018`
  - `bgSidebar`: `#0F1622`
  - `bgSurface`: `#141D2B`
  - `bgElevated`: `#1A2537`
  - `bgInput`: `#0B111A`
  - `bgHover`: `#223045`
- **Borders:** `borderSubtle`: `#233146`, `borderStrong`: `#344763`, `borderFocus`: `#2EC4A0`
- **Typography:** Primary `"Segoe UI"`, Mono `"Consolas"` (`typeTitle: 20`, `typeHeading: 14`, `typeBody: 12`, `typeCaption: 10`, `typeMono: 11`)
- **Spacing Scale:** `sp4: 4`, `sp8: 8`, `sp12: 12`, `sp16: 16`, `sp20: 20`, `sp24: 24`
- **Radius Scale:** `radSm: 6`, `radMd: 10`, `radLg: 14`, `radPill: 999`
- **Accent & Semantic:** `accent: "#2EC4A0"`, `accentHover: "#39D6B0"`, `accentDim: "#173D39"`, `warn: "#E8A849"`, `warnDim: "#3A2D16"`, `danger: "#E56B6F"`, `dangerDim: "#3D1C22"`, `info: "#5EA1F2"`
- **Motion Tokens (`reducedMotion` respects toggle):**
  - `durMicro`: `120 ms` (button press scale `0.98`, switch thumb, hover tint)
  - `durPanel`: `200 ms` (active nav pill slide, inspector drawer reveal, expandable sub-sections)
  - `durContext`: `240 ms` (workspace crossfade + subtle `y: +6 -> 0` entrance)

## 3. Navigation & Workspaces
1. **Persistent Top Bar:** Target `.so` path picker + Drag & Drop zone + `Output .so` + `Overwrite (--force)` chip + Quick ELF Badge (`arm64-v8a · X MB · Y funcs`) + Primary CTA **`Tạo .so bảo vệ`**.
2. **Left Rail (Fixed 216px, collapsible to 64px):**
   1. `Phân tích & Hàm` (Inspector + Function Explorer + A03 sensitivity + Hardening audit)
   2. `Lớp bảo vệ` (Presets + Crypto E01-E08 + Obfuscation/VM O01-O09 + Integrity R01-R08 + Watermark/Seed/Semantics)
   3. `Chống soi IDA Pro` (Anti-IDA segment hide, randomized `IlO0` length & live roll, full inline F5 decoy/string editor)
   4. `Thực thi & Kết quả` (Live F05 plan preview, Build progress/logcat stream, Output verification, NDK runtime build)
   5. `Benchmark & Logcat` (Original vs Protected A04-A06/A09 comparison + Android crash/guard triage)
3. **Status Bar + Toast Notifications:** Non-blocking top-right toast feedback + persistent bottom operational bar showing runtime asset SHA, selected target summary, and last check result.

## 4. State Coverage (`E5`)
Every workspace explicitly handles: Empty state (drop `.so` guidance), Loading/Scanning (indeterminate indicator + status), Processing (locked Build controls + animated progress bar + streaming console), Success (verified badges + toast + open folder action), Error/Conflict (inline banner + human explanation + technical log tab), Disabled (grayed incompatible controls with tooltip reason), Hover/Focus/Selected/Cancelled/Recovery (remembered last paths & NDK in `%LOCALAPPDATA%\Protect3\settings.json`).
