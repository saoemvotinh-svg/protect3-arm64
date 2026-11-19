# Khảo sát bảo vệ `.so` và trạng thái thực hiện (v0.3.0)

Phạm vi của Protect3 là **ELF Android ARM64 có sẵn → ELF `.so` nạp trực tiếp**.

## Đối chiếu các cơ chế bảo vệ `.so` ở phiên bản 0.3.0

| Cơ chế | Nguồn tham khảo kỹ thuật | Trạng thái ở Protect3 0.3.0 | Ghi chú phạm vi |
| --- | --- | --- | --- |
| Khôi phục ranh giới hàm & phân tích CFG (`F01`, `F02`) | DWARF `.eh_frame` / ARM64 ISA | **Đã có** | Khôi phục hàm từ `.dynsym`, `.symtab` (trước strip) và `.eh_frame` CIE/FDE; nhận diện hàm có LSDA exception |
| Bảo vệ chọn nhiều hàm (`E01`) | Virbox `.so` function selection | **Đã có** | Hỗ trợ mã hóa nhiều hàm/vùng (`--encrypt-functions`), tự động chấm điểm độ nhạy (`A03`) |
| Mã hóa chuỗi theo reference (`E03`) | O-MVLL Strings Encoding | **Đã có** | Xóa chuỗi trong `.rodata`, chuyển vào String Vault tách trang 16 KiB và giải mã lười (lazy) qua stub bảo toàn thanh ghi |
| Làm rối lệnh, hằng và nhánh (`O01–O06`) | O-MVLL Arithmetic / Opaque Constants / Indirect Branch | **Đã có** | Thay thế MBA (`O01`), tổng hợp hằng XOR (`O02`), vị từ đại số $x(x+1) \bmod 2 == 0$ (`O03`), gọi gián tiếp có `BTI` (`O04`), tách/xáo trộn khối (`O05/O06`) |
| Control-Flow Flattening (`O07`) | O-MVLL Control-Flow Flattening | **Đã có** | Biến đổi basic block sang vòng lặp dispatcher dùng `CSEL` và mã hóa trạng thái theo seed |
| ARM64 Function Virtualization (`O08`, `O09`) | Virbox Virtualization / Tigress Virtualize | **Đã có (tập lệnh số nguyên/nhánh/mem/call)** | Dịch hàm tương thích sang bytecode 16-byte chạy trên `p3_vm_exec` (stack 1 KiB riêng), hoán vị 64 opcode theo build và mã hóa luồng bytecode |
| JNI Obfuscation (`.so` độc lập) | Android JNI ABI | **Đã có (phạm vi `.so`)** | Giữ tên export cho ART nhưng chuyển thân hàm `JNI_OnLoad`/`Java_*` sang vùng `.guard` đã làm rối kèm cổng kiểm tra runtime |
| Xác thực ciphertext, ký manifest & KDF (`E04`, `E05`, `E07`) | RFC 2104 HMAC-SHA256 / RFC 8439 ChaCha20 | **Đã có** | Kiểm tra HMAC trước `mprotect` (`E04`), xác thực cấu hình `p3_config`+`p3_ext` (`E05`), dẫn xuất khóa từ `key_mask` (`E07`) |
| Đóng gói toàn bộ ELF (`E08`) | Custom ELF wrapper | **Đã có (`--wrap-elf`)** | Tạo thư viện vỏ giải mã payload vào `memfd_create`, nạp qua `dlopen` và chuyển tiếp các hàm export `STT_FUNC` |
| Toàn vẹn bộ nhớ & chống hook lúc chạy (`R01–R07`) | Runtime integrity & prologue guard | **Đã có** | Cổng kiểm tra runtime (`R01`), kiểm tra byte đầu hàm chống inline hook (`R02`), kiểm tra GOT/RELRO (`R03/R04`), anti-debug lúc chạy (`R05`), tự kiểm tra mã guard (`R06`), giải mã/tái mã hóa theo lượt gọi (`R07`) |
| Đa dạng hóa & Benchmark chống phân tích tự động (`A01–A09`) | LLM4Decompile / Binary similarity | **Đã có** | Seed cấu trúc (`A01`), profile (`A02`), scorer (`A03`), benchmark n-gram/simplifier (`A04–A06`), watermark (`A08`) và gợi ý kế hoạch (`A09`) |
