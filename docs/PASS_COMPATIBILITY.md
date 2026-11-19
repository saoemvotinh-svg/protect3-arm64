# Quy tắc phối hợp pass và kiểm tra xung đột (v0.3.0)

Tài liệu này mô tả bộ điều phối `F05` đã được triển khai trong [planner.py](../protect3/planner.py) và [engine.py](../protect3/engine.py) ở phiên bản **0.3.0**.

## 1. Các điểm lệch của bản 0.2 đã được khắc phục ở 0.3.0

| Vấn đề ghi nhận ở 0.2 | Cách đã giải quyết ở 0.3.0 |
| --- | --- |
| `--strip-symbols` chạy trước khi phân giải symbol của `--encrypt-function`, làm mất symbol local | `protect()` chạy `discover_functions(original)` (`F01`) **trước** bước `llvm-strip` và truyền bảng hàm đã định danh vào `rewrite()` |
| `Native Code Obfuscation` trả về `status="partial"` khiến `enabled_in_output` thành `False` dù đã bật strip | Tách trường `maturity` riêng; `status` trả về `"enabled"` và `enabled_in_output` là `True` bất cứ khi nào bật strip, xóa metadata hoặc `O01–O06` |
| `Anti-Tamper` và `Memory Integrity Checks` bỏ sót `encrypt_function` và `encrypt_rodata` khi dùng `--no-integrity` | `capabilities()` tính chính xác theo toàn bộ các cờ mã hóa code/data, `E04`, `E05`, `R01–R04` và `R06` |
| `Native Anti-Debugging` chưa phản ánh riêng `deny_attach` và kiểm tra lúc chạy | Báo cáo rõ trạng thái của `debugger` (`TracerPid`), `runtime_anti_debug` (`R05`) và `deny_attach` (`PR_SET_DUMPABLE=0`) |

## 2. Trình tự thực thi 9 giai đoạn trong `engine.py`

1. **Đọc & Định danh (`F01`):** Khôi phục toàn bộ hàm từ `.dynsym`, `.symtab` (trước strip) và `.eh_frame` CIE/FDE; đánh dấu hàm khởi tạo sớm và hàm có LSDA exception; chấm điểm nhạy cảm/chi phí (`A03`).
2. **Lập kế hoạch & Chặn xung đột (`F05`, `A01`, `A02`, `A08`):** Mở rộng `--profile`, gán một backend duy nhất (`vm`, `flatten`, `obfuscate`, hoặc `on_demand`) cho mỗi thân hàm, từ chối các tổ hợp xung đột (`E08` kết hợp sửa tại chỗ, `E02` toàn `.rodata` kết hợp `E03` trên cùng section, hoặc các vùng mã hóa chồng lấn).
3. **Biến đổi ngữ nghĩa (`O01–O09`, `E03`):** Dịch hàm VM sang bytecode đã hoán vị opcode (`O08/O09`), làm phẳng/làm rối hàm native (`O01–O07`), tạo các stub giải mã chuỗi (`E03`) và ghi trampoline 4-byte vào đầu hàm gốc trong `.text`.
4. **Cấp phát trang cô lập 16 KiB (`E03`, `R07`):** Đặt các trang On-Demand Code (`R07`) và String Vault (`E03`) trên ranh giới 16 KiB riêng ở cuối segment `.guard` để lệnh `mprotect` lúc chạy không bao giờ chạm vào trang chứa `guard.bin` hay `.text`.
5. **Chốt Baseline Plaintext (`R01`, `R02`, `R04`, `R06`):** Tính SHA-256 của các section thực thi (`spans`), lưu byte prologue sau khi đặt trampoline (`prologues`), tính SHA-256 của `.data.rel.ro` tĩnh (`R04`) và mã thực thi `guard.bin` (`R06`).
6. **Dẫn xuất khóa (`E07`):** Sinh `raw_key` và `key_mask`, dẫn xuất `master_key = HMAC-SHA256(key_mask, raw_key)`.
7. **Mã hóa & Tính Tag Xác thực (`E01`, `E02`, `E03`, `E04`, `R07`):** Mã hóa `.text`, `.rodata`, các vùng `enc_ranges` và String Vault bằng ChaCha20; tính `cipher_mac` (`HMAC-SHA256` ràng buộc `vaddr`, `size`, `nonce` và `ciphertext`).
8. **Ký Manifest (`E05`):** Tính `manifest_mac` trên toàn bộ `p3_config` + `p3_ext` (và tự động ký lại nếu `--compat-layout` cập nhật `original_init` cho RELA hook).
9. **Kiểm chứng & Xuất Báo cáo (`F03`, `F06`, `A04–A06`, `A09`):** Kiểm tra cấu trúc ELF, đối chiếu ABI, chạy differential execution Unicorn nếu bật `--verify-semantics`, tính chỉ số benchmark và ghi `pass_ledger` vào `.protect3.json`.

## Thích nghi đa tính năng & Cảnh báo chữ đỏ thời gian thực

- **Chế độ bọc toàn ELF (`E08`) chạy ở lớp cuối cùng (hỗ trợ chạy kèm tất cả pass):** `F01 -> E06 Clean/Strip -> F05 -> Rewrite tại chỗ (O01-O09, R01-R09, E01-E07, IDA Troll/Block) -> F03 -> E08 Wrap ELF (memfd/dlopen) -> E06 Strip outer wrapper -> F06 Verify`. Nhờ đó `wrap_elf` chạy chung được với toàn bộ các lớp bảo vệ khác (chỉ từ chối khi `.so` có export biến dữ liệu `STT_OBJECT`, không có hàm `STT_FUNC` export, hoặc thiếu NDK).
- **Điều phối `obfuscate_jni` + `R07`:** Bộ chọn JNI tự động né các hàm đã chỉ định cho `O08 VM`, `O07 Flatten`, `R07 On-Demand` và `Denylist` thay vì gây đụng độ cấp phát hàm.
- **Báo xung đột chữ đỏ trực tiếp (`analyze_option_conflicts`):** Chỉ đánh dấu đỏ (`Theme.danger`) các tùy chọn đang thực sự bật/nhập và xung đột với nhau hoặc với ELF/NDK (không tô đỏ oan các nút đang TẮT):
  - `E01_WHOLE_VS_FUNC`: bật đồng thời `encrypt_text` và `encrypt_function` / `encrypt_functions`.
  - `EPHEMERAL_REQUIRES_VAULT`: bật `ephemeral_strings` (`E03+`) nhưng tắt `encrypt_strings` (`E03`) — chỉ báo đỏ tại `ephemeral_strings`.
  - `MULTI_BACKEND_FUNC` / `TARGET_IN_DENYLIST`: trùng một hàm giữa nhiều backend (`O08` / `O07` / `O01-O06` / `R07`) hoặc trùng với `Denylist`.
  - `VM_LIMIT`, `BARCODE_LEN`, `BARCODE_CHARS`, `F03_NO_UNICORN`, `NDK_MISSING`, `E08_OBJ_EXPORT`, `E08_NO_EXPORT`, và kiểm tra cấu trúc ELF thực tế (`COMPAT_LAYOUT_UNSUPPORTED`, `E01_TEXT_UNSUPPORTED`, `E02_RODATA_UNSUPPORTED`, `E03_NO_RODATA`, `VM_INCOMPATIBLE`, `FUNC_NOT_RELOCATABLE`).
