# Protect3 — công cụ bảo vệ Android ARM64 `.so → .so`

**Phiên bản 0.3.0 tập trung bảo vệ trực tiếp thư viện `.so` Android ARM64.** Nhận ELF `.so` có sẵn, phân tích ranh giới hàm/CFG, áp dụng các pass biến đổi lệnh/luồng điều khiển/ảo hóa VM/mã hóa/xác thực đã chọn, nhúng runtime guard và xuất ELF `.so` mới cùng báo cáo bằng chứng JSON (`pass_ledger`); không cần mã nguồn đầu vào. Bảo vệ DEX, XML và các thành phần ngoài `.so` nằm ngoài phạm vi dự án.

Đầu ra giữ nguyên ABI/export/JNI và cách `System.loadLibrary`/`dlopen`. Công cụ kiểm tra cấu trúc ELF, ABI và tùy chọn đối chiếu ngữ nghĩa bằng Unicorn (`--verify-semantics`) trước khi ghi file. Đã kiểm thử bản 0.3.0 trên `libMyLibName.so` (`com.garena.game.kgvn`) chạy trên BlueStacks Android 9 root với `--compat-layout` (kết hợp mã hóa `.text`/`.rodata`, xác thực HMAC trước giải mã `E04`, ký manifest `E05`, khóa dẫn xuất `E07`, tự kiểm tra guard `R06`, kiểm tra prologue `R02`, làm rối + cổng kiểm tra runtime trên `JNI_OnLoad`, ảo hóa VM `O08/O09` và làm phẳng CFG `O07` trên các hàm FDE).

## Chạy trên Windows

- Mở `dist/Protect3.exe` sau khi build, hoặc giải nén `dist/Protect3-Windows.zip` và mở `Protect3.exe`. Bản EXE đã kèm runtime ARM64; không cần cài Python.
- Chạy từ mã nguồn: mở `Start-Protect3.cmd` (Python 3.10+ có Tkinter), hoặc `py -3 -m protect3 gui`.
- Chọn `.so` đầu vào, đường dẫn `.so` đầu ra khác, chọn tính năng hoặc profile rồi bấm **Tạo .so bảo vệ**.
- `Xóa symbol/debug` (`--strip-symbols`) và chế độ bọc toàn bộ ELF (`--wrap-elf`) cần NDK với biến môi trường `ANDROID_NDK_HOME`, hoặc chọn thư mục NDK trong GUI. Các tùy chọn khác (kể cả xóa metadata không cấp phát `--clean-metadata`, mã hóa, obfuscation, flattening, ARM64 VM) dùng engine Python + runtime đóng gói sẵn, không cần NDK.

Không ghi đè file đầu vào. Khi output/report đã tồn tại, chọn tên mới hoặc dùng CLI với `--force`. Báo cáo nằm cạnh output, tên `libname.so.protect3.json`.

## Phạm vi thực tế ở 0.3.0

| Tính năng trong `.so` | Thực hiện đến đâu | Bằng chứng / giới hạn |
| --- | --- | --- |
| Đầu vào `.so` → đầu ra `.so` | **Đã có** | Nhận ELF Android ARM64 có sẵn, nhúng guard và xuất thư viện mới; giữ export, địa chỉ hàm gốc và liên kết JNI |
| Mã hóa toàn bộ ELF dưới dạng payload (`E08`) | **Đã có — chế độ wrapper (`--wrap-elf`)** | Biên dịch thư viện vỏ `.so` giải mã payload qua `memfd_create`/`dlopen` và chuyển tiếp toàn bộ export `STT_FUNC`; từ chối thư viện export biến dữ liệu `STT_OBJECT`. Đã kiểm thử trên Bionic ARM64 |
| Native Code Obfuscation (`O01–O06`, `E06`) | **Đã có** | Thay lệnh tương đương/MBA (`O01`), hằng số ẩn (`O02`), vị từ bất biến theo thanh ghi đầu vào (`O03`), gọi gián tiếp có `BTI` (`O04`), tách/xáo trộn khối cơ bản (`O05/O06`), xóa metadata `.comment`/debug (`E06`) và strip symbol bằng NDK |
| Native Code Encryption (`E01`, `E04`, `E07`) | **Đã có** | ChaCha20 cho toàn `.text`, một hoặc **nhiều hàm/vùng chọn** (`--encrypt-functions`, khôi phục được hàm đã strip từ `.eh_frame` FDE), kèm xác thực HMAC-SHA256 trước giải mã (`E04`) và dẫn xuất khóa KDF (`E07`) |
| Mã hóa chuỗi/hằng trong `.rodata` (`E02`, `E03`) | **Đã có** | Mã hóa toàn `.rodata` khi nạp (`E02`) hoặc **mã hóa từng chuỗi theo reference (`--encrypt-strings`, `E03`)** trong String Vault tách trang 16 KiB, chỉ giải mã khi lệnh tham chiếu chuỗi thực sự chạy |
| JNI Obfuscation (`--obfuscate-jni`) | **Đã có (phạm vi `.so`)** | Di chuyển và làm rối thân hàm `JNI_OnLoad` / `Java_*` sang `.guard` phía sau thunk kiểm tra runtime (`R01/R02`), giữ nguyên tên symbol ABI để không cần sửa DEX |
| Native Anti-Debugging (`R05`) | **Đã có — khi nạp & lúc chạy** | Kiểm tra `TracerPid` và `wchan` (`ptrace_stop`) khi nạp và tại cổng hàm bảo vệ (`--runtime-anti-debug`); tùy chọn `PR_SET_DUMPABLE=0` |
| Probe Frida / Xposed + kiểm tra prologue (`R02`, `R08`) | **Đã nâng cấp đa tín hiệu + kiểm tra byte đầu hàm** | Kiểm tra byte prologue/trampoline (`R02`) phát hiện inline hook sau khi nạp; dò thêm `gum-js-loop`/`linjector`/`dobby`/`substrate` khi bật `--deep-probes`. Chưa thử với Frida/Xposed thật trên thiết bị vật lý |
| Anti-Tamper mã & manifest (`E04`, `E05`, `R06`) | **Đã có** | Xác thực HMAC-SHA256 trên ciphertext + descriptor trước khi đổi quyền bộ nhớ (`E04`), ký và xác minh manifest cấu hình (`E05`), kiểm tra chéo mã thực thi của chính guard (`R06`) |
| Memory Integrity Checks (`R01–R04`) | **Đã có — khi nạp & tại cổng hàm** | SHA-256 lúc nạp cộng kiểm tra lại tại cổng hàm lúc chạy (`R01`), kiểm tra prologue (`R02`), kiểm tra phạm vi đích GOT (`R03`) và bảng pointer `.data.rel.ro` (`R04`) |
| Giải mã theo nhu cầu & tái mã hóa (`R07`) | **Đã có (`--on-demand-functions`)** | Đặt thân hàm trên trang 16 KiB riêng trong `.guard`; giải mã trước khi gọi, kiểm tra SHA-256 và **tái mã hóa ngay sau khi hàm trả về** |
| Probe root / Magisk / Zygisk / KernelSU (`R08`) | **Prototype đa tín hiệu, mặc định tắt** | Dò đường dẫn `su`/`magisk`/`ksu`/`apatch`, `/proc/self/maps` và `/proc/self/mountinfo`. Giữ tắt trên môi trường kiểm thử giả lập đã root |
| Probe emulator (`qemu` / `goldfish` / `BlueStacks`) (`R08`) | **Prototype đa tín hiệu, mặc định tắt** | Hỗ trợ thêm dấu hiệu `/dev/bst*`, `libnb.so`, `libhoudini.so`, `vbox` khi bật `--deep-probes`; mặc định tắt để không chặn giả lập phát triển |
| ARM64 Function Virtualization (`O08`, `O09`) | **Đã có — tập lệnh số nguyên/nhánh/bộ nhớ/call** | Dịch hàm ARM64 tương thích sang bytecode 16-byte chạy trên máy ảo stack-isolated `p3_vm_exec`; hoán vị bảng opcode theo từng bản build và mã hóa luồng bytecode bằng ChaCha20 (`O09`) |
| Control-Flow Flattening (`O07`) | **Đã có (`--flatten-functions` / `--flatten-cfg`)** | Biến đổi các khối cơ bản của hàm ARM64 thành vòng lặp state-machine dispatcher dùng chuyển trạng thái `CSEL` và tính lại toàn bộ lệnh phụ thuộc PC (`F02`) |
| Planner, Scoring, Watermark & Benchmark (`F01–F06`, `A01–A09`) | **Đã có** | Tự động khôi phục ranh giới hàm từ symbol + `.eh_frame` (`F01`), chấm điểm độ nhạy (`A03`), chặn tổ hợp xung đột (`F05`), nhúng watermark (`A08`), đo độ lệch n-gram/simplifier (`A04–A06`) và gợi ý kế hoạch (`A09`) |

## Trạng thái 40 hạng mục lộ trình (`F01–F06`, `E01–E08`, `O01–O09`, `R01–R08`, `A01–A09`)

Tất cả 40 ID đã được triển khai trong mã nguồn ([arm64.py](protect3/arm64.py), [transforms.py](protect3/transforms.py), [planner.py](protect3/planner.py), [engine.py](protect3/engine.py), [guard.c](native/guard.c)) và có bài kiểm thử tự động trong [test_v03_roadmap.py](tests/test_v03_roadmap.py) cũng như [smoke_bionic.py](tools/smoke_bionic.py):

### F — Nền tảng phân tích, di chuyển lệnh, kiểm chứng và điều phối

| ID | Hạng mục | Trạng thái ở 0.3.0 |的实现 & Bằng chứng |
| --- | --- | --- | --- |
| F01 | Phân vùng code/data và khôi phục ranh giới hàm | **Đã triển khai** | Kết hợp `.dynsym`, `.symtab` (đọc trước khi strip), `.eh_frame` CIE/FDE (nhận diện hàm có exception LSDA) và user map (`discover_functions` trong `protect3/arm64.py`). Khôi phục 6.560 hàm trên `libMyLibName.so` đã strip |
| F02 | Engine giải mã và di chuyển lệnh ARM64 | **Đã triển khai** | Giải mã nhánh, `ADR`/`ADRP`, `LDR/STR/LDP/STP`, ALU, bitfield, `CSEL`, `MRS/MSR`; tự mở rộng `ADR` vượt ±1 MiB thành `ADRP + ADD` và nhánh có điều kiện vượt ±1 MiB (`relocate_insn` trong `protect3/arm64.py`) |
| F03 | Differential execution kiểm tra ngữ nghĩa | **Đã triển khai** | `verify_function_semantics_unicorn` trong `protect3/planner.py` và tùy chọn `--verify-semantics` đối chiếu kết quả thực thi Unicorn trước/sau biến đổi trên nhiều vector đầu vào |
| F04 | Ma trận ổn định (page size 4/16 KiB, Bionic, ADB) | **Đã triển khai** | 50 unit/Unicorn tests (4 KiB & 16 KiB), 33 ca Bionic ARM64 trong Docker và kiểm thử lặp nhiều lần khởi động trên BlueStacks Android 9 |
| F05 | Planner, kiểm tra xung đột và quản lý trang nhớ | **Đã triển khai** | `build_protection_plan` trong `protect3/planner.py` kiểm tra xung đột backend trên cùng hàm, xung đột `E02`/`E03`, `E08` và tách trang 16 KiB riêng cho `E03`/`R07` |
| F06 | Báo cáo bằng chứng theo artifact (`pass_ledger`) | **Đã triển khai** | Ghi đầy đủ ID pass hoạt động, danh sách hàm đã biến đổi, số chuỗi mã hóa, mục bị bỏ qua kèm lý do, kết quả F03 và metric A04–A06 trong `.protect3.json` |

### E — Mã hóa code, chuỗi, xác thực, chữ ký manifest và đóng gói

| ID | Hạng mục | Trạng thái ở 0.3.0 | Thực hiện & Bằng chứng |
| --- | --- | --- | --- |
| E01 | Mã hóa nhiều hàm/vùng chọn | **Đã triển khai** | `--encrypt-functions f1,f2,...` mã hóa tới 16 vùng hàm độc lập với nonce riêng và kiểm tra không chồng lấn |
| E02 | Bảo vệ vùng dữ liệu read-only | **Đã triển khai** | `--encrypt-rodata` kiểm tra loại trừ relocation và metadata của dynamic linker trước khi mã hóa |
| E03 | Mã hóa string theo reference, giải mã khi dùng | **Đã triển khai** | `--encrypt-strings` tìm các lệnh `ADR` và `ADRP + ADD` trỏ vào `.rodata`, xóa chuỗi gốc trên đĩa, chuyển chuỗi vào String Vault tách trang 16 KiB và chỉ giải mã qua `p3_resolve_string` khi lệnh tham chiếu chạy |
| E04 | Mã hóa có xác thực theo vùng (ciphertext MAC) | **Đã triển khai** | `--auth-encryption` tính và kiểm tra `HMAC-SHA256(key, vaddr || size || nonce || ciphertext)` trong `guard.c` **trước khi** gọi `mprotect` hoặc giải mã |
| E05 | Ký và xác minh manifest cấu hình | **Đã triển khai** | `--sign-manifest` xác thực toàn bộ `p3_config` + `p3_ext` bằng khóa manifest trong `guard.c` lúc nạp và tại các cổng kiểm tra runtime |
| E06 | Dọn metadata không cần chạy & tách debug | **Đã triển khai** | `--clean-metadata` xóa nội dung `.comment`/debug không cấp phát mà không cần NDK; `--keep-debug <path>` lưu bản sao đầy đủ symbol trước khi strip |
| E07 | Dẫn xuất khóa KDF và xóa key tạm trên stack | **Đã triển khai** | `--masked-key` tách `raw_key` và `key_mask`, dẫn xuất khóa chủ bằng `p3_hmac_sha256` trên stack lúc chạy và xóa bộ đệm bằng con trỏ `volatile` |
| E08 | Đóng gói toàn bộ ELF dưới thư viện vỏ | **Đã triển khai** | `--wrap-elf` biên dịch `.so` vỏ chứa payload mã hóa ChaCha20 + SHA-256, nạp qua `memfd_create`/`dlopen` và chuyển tiếp toàn bộ hàm export `STT_FUNC` |

### O — Làm rối lệnh native, Control-Flow Flattening và ARM64 Virtualization

| ID | Hạng mục | Trạng thái ở 0.3.0 | Thực hiện & Bằng chứng |
| --- | --- | --- | --- |
| O01 | Thay lệnh bằng chuỗi tương đương / MBA | **Đã triển khai** | Thay `ADD`/`EOR`/immediate bằng chuỗi biến đổi Mixed Boolean-Arithmetic bảo toàn cờ và thanh ghi trong `protect3/transforms.py` |
| O02 | Opaque constants & tổng hợp hằng qua XOR | **Đã triển khai** | Biến đổi `MOVZ` thành chuỗi tổng hợp nhiều lệnh với mặt nạ phụ thuộc seed build `A01` |
| O03 | Vị từ bất biến (Opaque predicates) | **Đã triển khai** | Chèn nhánh điều kiện bất biến đại số dựa trên thanh ghi đầu vào $x(x+1) \equiv 0 \pmod 2$ (`ADD` + `MADD` + `TBZ`) vượt qua bước gập hằng tĩnh đơn giản |
| O04 | Gián tiếp hóa cạnh gọi/nhánh | **Đã triển khai** | Chuyển lệnh gọi trực tiếp `BL` trong hàm đã di chuyển thành chuỗi tính địa chỉ động `ADRP + ADD + BLR X16` tương thích `BTI` |
| O05 | Tách hàm / phân mảnh khối lệnh | **Đã triển khai** | Tách và đặt các khối lệnh kèm truyền state token qua thanh ghi tạm (`A07`) trong vùng `.guard` |
| O06 | Hoán vị basic block và trampoline | **Đã triển khai** | Xáo trộn thứ tự basic block theo seed, nối lại cạnh fallthrough, sửa toàn bộ tham chiếu PC-relative và đặt trampoline 4-byte tại địa chỉ hàm gốc |
| O07 | Control-Flow Flattening | **Đã triển khai** | `--flatten-functions` / `--flatten-cfg` gom các basic block vào vòng lặp state-machine dispatcher dùng lệnh `CSEL` để cập nhật trạng thái |
| O08 | ARM64 Function Virtualization | **Đã triển khai** | `--virtualize-functions` / `--virtualize-auto` biên dịch hàm ARM64 sang tập 33 lệnh bytecode 16-byte chạy trên máy ảo `p3_vm_exec` có vùng stack 1 KiB cô lập |
| O09 | Đa dạng hóa VM theo bản build & hàm | **Đã triển khai** | Hoán vị ngẫu nhiên bảng 64 opcode (`vm_opcode_map`) theo seed build và mã hóa riêng từng chương trình bytecode bằng ChaCha20 + SHA-256 |

### R — Toàn vẹn và bảo vệ trong lúc chạy

| ID | Hạng mục | Trạng thái ở 0.3.0 | Thực hiện & Bằng chứng |
| --- | --- | --- | --- |
| R01 | Kiểm tra toàn vẹn bộ nhớ sau thời điểm nạp | **Đã triển khai** | `--runtime-integrity` gắn cổng `p3_gate_bridge` → `p3_runtime_check` kiểm tra lại SHA-256 của code và manifest khi hàm được gọi lúc chạy |
| R02 | Kiểm tra prologue và đích trampoline | **Đã triển khai** | `--prologue-check` lưu tới 16 byte đầu của các hàm export/JNI/trampoline và phát hiện hành vi chèn inline hook trước/sau khi nạp |
| R03 | Kiểm tra phạm vi đích GOT/PLT | **Đã triển khai** | `--got-check` kiểm tra các slot `.got.plt`/`.got` không bị trỏ lệch vào vùng dữ liệu nội bộ ngoài các section thực thi hợp lệ |
| R04 | Kiểm tra bảng con trỏ `.data.rel.ro` | **Đã triển khai** | `--relro-check` kiểm tra SHA-256 của `.data.rel.ro` khi không có relocation động ghi đè lúc nạp |
| R05 | Anti-debug nhiều thời điểm | **Đã triển khai** | `--runtime-anti-debug` kiểm tra `TracerPid` và `/proc/self/wchan` (`ptrace_stop`) ngay tại cổng hàm và lối vào VM lúc ứng dụng đang chạy |
| R06 | Kiểm tra chéo toàn vẹn mã guard | **Đã triển khai** | `--guard-self-check` kiểm tra SHA-256 của chính vùng mã `guard.bin` tại cả thời điểm nạp (`p3_entry`) và các cổng runtime (`p3_runtime_check`) |
| R07 | Giải mã theo nhu cầu & tái mã hóa khi trả về | **Đã triển khai** | `--on-demand-functions` đặt thân hàm trên trang 16 KiB riêng; tự động giải mã trước khi chạy và tái mã hóa ChaCha20 ngay khi hàm `ret` |
| R08 | Mở rộng detector đa tín hiệu | **Đã triển khai** | `--deep-probes` bổ sung kiểm tra `/proc/self/comm` (`gum-js-loop`), `/proc/self/mountinfo` (`kernelsu`/`magisk`) và dấu hiệu BlueStacks (`/dev/bst*`, `libnb.so`) |

### A — Đa dạng hóa cấu trúc, chống phân tích tự động và đánh giá

| ID | Hạng mục | Trạng thái ở 0.3.0 | Thực hiện & Bằng chứng |
| --- | --- | --- | --- |
| A01 | Seed đa dạng hóa cấu trúc theo build | **Đã triển khai** | `--seed <int>` điều khiển thứ tự basic block, hằng số ẩn, trạng thái flattening và bảng opcode VM mà không tái sử dụng khóa/nonce mã hóa |
| A02 | Profile giảm lộ ngữ nghĩa tĩnh | **Đã triển khai** | `--profile compat\|balanced\|anti-analysis\|max` tự động phối hợp các pass theo thứ tự chuẩn của `F05` |
| A03 | Bộ chấm điểm độ nhạy và chi phí hàm | **Đã triển khai** | Chấm điểm từng hàm (`sensitivity_score`, `cost_score`) trong `protect3/arm64.py` để ưu tiên bảo vệ hàm JNI/export/nhạy cảm |
| A04 | Benchmark khôi phục tĩnh/symbolic | **Đã triển khai** | Lệnh `protect3 benchmark` và báo cáo tự động đo tỷ lệ lộ chuỗi, tỷ lệ sống sót prologue hàm và số cấu trúc làm rối |
| A05 | Metric tương đồng qua các phiên bản | **Đã triển khai** | Đo `text_4gram_jaccard_similarity` và `text_4gram_divergence` giữa bản gốc và các bản bảo vệ khác seed |
| A06 | Đánh giá khả năng kháng bộ rút gọn đại số | **Đã triển khai** | Quét và kiểm tra các chuỗi tổng hợp hằng số ẩn (`O02`) và vị từ bất biến phụ thuộc input (`O03`) trong segment `.guard` |
| A07 | Truyền state liên khối/liên mảnh | **Đã triển khai** | Tích hợp cùng `O05`/`O06`/`O07` trong `obfuscate_and_relocate_function` |
| A08 | Watermark/fingerprint cấu trúc offline | **Đã triển khai** | `--watermark <tag>` nhúng định danh băm 128-bit vào `p3_ext.watermark` (được bảo vệ bởi chữ ký manifest `E05`) và xác minh qua `protect3 verify` |
| A09 | Vòng phản hồi từ benchmark về planner | **Đã triển khai** | Trường `feedback_A09` trong báo cáo benchmark đề xuất cụ thể các pass/hàm cần tăng cường cho lần build kế tiếp |

## Kết quả kiểm thử và triển khai trên BlueStacks (18/11/2026)

1. **Kiểm thử tự động trên máy phát triển:**
   - **50/50** bài kiểm thử đơn vị, giải mã lệnh và thực thi đối chiếu bằng Unicorn ARM64 (`tests/test_protect3.py`, `tests/test_v03_roadmap.py`, `tests/test_diagnostics.py`) đạt 100%.
   - **33/33** ca kiểm thử nạp thực tế bằng Bionic ARM64 linker trong container Termux Docker (`tools/smoke_bionic.py`, kết quả lưu tại `build/bionic-smoke.json`) đạt 100%.
2. **Thử nghiệm thực tế bản 0.3.0 trên `com.garena.game.kgvn` (`libMyLibName.so`) qua ADB root (`127.0.0.1:5555`):**
   - Cấu hình: `--compat-layout --encrypt-text --encrypt-rodata --auth-encryption --sign-manifest --masked-key --guard-self-check --prologue-check --clean-metadata --obfuscate-jni --virtualize-functions fde_73030,fde_73040 --flatten-functions fde_73064 --watermark kgvn-v03-verified --diagnostics` (giữ tắt `hooks`, `root`, `emulator`, `deny_attach` trên giả lập phát triển).
   - Logcat thu được từ tiến trình game xác nhận đầy đủ chuỗi sự kiện:
     - Lúc nạp (`DT_INIT` / RELA hook): `guard_start` → `manifest_mac_ok` (`E05`) → `guard_self_check_ok` (`R06`) → `text_mac_ok` (`E04`) → `text_decrypt_ok` → `rodata_mac_ok` (`E04`) → `rodata_decrypt_ok` (`E02`) → `prologue_check_ok` (`R02`) → `integrity_stage_complete` → `original_initializer_returned` → `guard_return`.
     - Khi ART gọi `JNI_OnLoad` (đã di chuyển và làm rối trong `.guard`): cổng kiểm tra runtime chạy và ghi `manifest_mac_ok` → `guard_self_check_ok` → `prologue_check_ok` → `runtime_gate_ok` (`R01`), hàm trả về `JNI_VERSION_1_6` và game chạy ổn định ở foreground.
   - Ba lần khởi động lặp lại tiếp theo (`tools/audit_adb.py`, mỗi lần ~20 giây) đều ghi nhận thư viện nạp thành công, không có crash. Xem [báo cáo thử nghiệm v0.3](output/adb-com.garena.game.kgvn-20261118-144806-8c00ae5d/trial.json), [báo cáo kiểm thử lặp lại](output/audit-20261118-144938/audit.json) và [bản triển khai hiện hành](output/kgvn/deployment.json).

## CLI

Sau khi build, có thể thay `py -3 -m protect3` bằng `dist\protect3-cli.exe`.

```powershell
# Phân tích cấu trúc ELF và bảng hàm khôi phục từ symbol + .eh_frame (F01/A03)
py -3 -m protect3 inspect .\libdemo.so --functions

# Xem trước kế hoạch bảo vệ theo profile (F05/A02/A03)
py -3 -m protect3 plan .\libdemo.so --profile anti-analysis

# Bảo vệ đầy đủ với mã hóa xác thực, ký manifest, dẫn xuất khóa, làm rối JNI, VM và CFG flattening
py -3 -m protect3 protect .\libdemo.so -o .\protected\libdemo.so `
  --compat-layout --encrypt-text --encrypt-rodata --auth-encryption `
  --sign-manifest --masked-key --guard-self-check --prologue-check `
  --clean-metadata --obfuscate-jni --virtualize-functions sample_add `
  --flatten-functions JNI_OnLoad --watermark release-v03 --diagnostics

# Dùng profile tổng hợp (compat, balanced, anti-analysis, max)
py -3 -m protect3 protect .\libdemo.so -o .\max\libdemo.so --profile max --compat-layout --watermark build-01

# Mã hóa chuỗi theo reference trong String Vault (giải mã khi dùng - E03)
py -3 -m protect3 protect .\libdemo.so -o .\str\libdemo.so --encrypt-strings --compat-layout --diagnostics

# Giải mã hàm theo nhu cầu và tái mã hóa ngay sau khi hàm trả về (R07)
py -3 -m protect3 protect .\libdemo.so -o .\ondemand\libdemo.so --on-demand-functions sample_add --compat-layout

# Đóng gói toàn bộ ELF dưới một thư viện vỏ .so độc lập (E08; cần NDK)
py -3 -m protect3 protect .\libdemo.so -o .\wrapped\libdemo.so --wrap-elf

# Kiểm tra hash file, cấu trúc ELF và watermark đã nhúng (A08)
py -3 -m protect3 verify .\protected\libdemo.so

# Đánh giá các chỉ số chống phân tích tĩnh (A04/A05/A06/A09)
py -3 -m protect3 benchmark .\libdemo.so .\protected\libdemo.so
```

## Biên dịch và kiểm thử

```powershell
$env:ANDROID_NDK_HOME = 'D:\Android\ndk\android-ndk-r27d'
.\.venv\Scripts\python.exe -m protect3 build-runtime
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe tools\smoke_bionic.py
.\.venv\Scripts\python.exe tools\build_windows.py
```

Đọc thêm chi tiết kỹ thuật tại:
- [Giới hạn và thiết kế kỹ thuật](docs/LIMITATIONS.md)
- [Khảo sát bảo vệ `.so` và đối chiếu thực tế](docs/NATIVE_RESEARCH.md)
- [Quy tắc phối hợp pass và ma trận tương thích](docs/PASS_COMPATIBILITY.md)
- [Chi tiết kiểm thử tự động và ADB](docs/TESTING.md)
