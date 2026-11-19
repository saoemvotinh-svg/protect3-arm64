# Giới hạn và cách hoạt động (v0.3.0)

## 1. Cách phân tích và viết lại ELF

1. Chỉ chấp nhận ELF64 little-endian ARM64, `ET_DYN` shared library có section headers và dynamic symbol table; không nhận Windows DLL, ARM32, x86 hoặc executable PIE.
2. Phân tích ranh giới hàm (`F01`) kết hợp `.dynsym`, `.symtab` (được đọc **trước** bước `llvm-strip` để không làm mất symbol local), và bảng unwind `.eh_frame` (CIE/FDE, tự động nhận diện hàm có con trỏ exception LSDA `.gcc_except_table`).
3. Thêm một segment RX ở cuối file (hoặc mở rộng bảng program header tại chỗ với `--compat-layout`). Các vùng cần đổi quyền bộ nhớ lúc chạy (`E03` String Vault và `R07` On-Demand Code Page) được căn chỉnh trên ranh giới trang **16 KiB riêng biệt** ở cuối segment `.guard`, tách hoàn toàn khỏi mã thực thi của `guard.bin` và `.text`. Không bao giờ tạo segment RWX.
4. Thay `DT_INIT` (hoặc hook addend RELA đầu tiên của `.init_array` trong `--compat-layout`) bằng `p3_entry`.

## 2. Biến đổi hàm Native, Flattening và ARM64 VM (`O01–O09`)

- Các hàm được chọn cho `O01–O06` (làm rối lệnh/hằng/nhánh/xáo trộn khối), `O07` (Control-Flow Flattening) hoặc `O08/O09` (ARM64 Bytecode VM) giữ nguyên địa chỉ hàm gốc trong `.text` bằng một lệnh nhảy 4-byte (`B stub`) tới vùng `.guard`; phần thân hàm cũ trong `.text` sau lệnh nhảy được ghi đè bằng các lệnh bẫy ngẫu nhiên theo seed.
- **Giới hạn của bộ di chuyển lệnh (`F02`) và VM (`O08`):**
  - Tự động từ chối hoặc bỏ qua (ghi rõ lý do trong `skipped_targets`) các hàm có nhánh gián tiếp `BR Xn` (jump table chưa xác định), hàm có exception LSDA (`.gcc_except_table`), hoặc lệnh SIMD/floating-point chưa nằm trong tập 33 opcode số nguyên của VM.
  - Mỗi thư viện hỗ trợ tối đa 16 hàm ảo hóa VM, 16 vùng mã hóa bổ sung, 16 chuỗi lazy trong String Vault và 16 bản ghi kiểm tra prologue trong cấu trúc tĩnh `p3_ext`.

## 3. Mã hóa, Xác thực và Quản lý Khóa (`E01–E08`)

- **Xác thực trước giải mã (`E04`) và Ký Manifest (`E05`):** Phát hiện mọi chỉnh sửa lên ciphertext, nonce, phạm vi hoặc cấu hình `p3_config`/`p3_ext` trước khi cấp quyền ghi (`mprotect`) hay chạy code. Tuy nhiên, vì thư viện phải tự xác minh và tự giải mã trên thiết bị người dùng, người phân tích có toàn quyền sửa binary vẫn có thể patch bỏ các lệnh kiểm tra trong `guard.bin`.
- **Dẫn xuất khóa (`E07`):** `--masked-key` không lưu trực tiếp khóa ChaCha20 trong cấu hình tĩnh mà dẫn xuất trên stack qua `HMAC-SHA256(key_mask, raw_key)` rồi xóa ngay sau khi dùng. Đây là cơ chế giảm lộ khóa tĩnh trên đĩa, không phải DRM phần cứng.
- **String Vault (`E03`):** Chỉ giải mã chuỗi khi lệnh `ADR` / `ADRP + ADD` tham chiếu chuỗi đó được thực thi. Sau lần gọi đầu tiên, chuỗi đã giải mã được giữ trong trang read-only của String Vault để bảo toàn hợp đồng con trỏ `const char *` cho caller.
- **On-Demand Decryption (`R07`):** Giải mã trang hàm 16 KiB riêng khi vào hàm và tái mã hóa khi hàm kết thúc. Chỉ dùng cho các hàm tuần tự, không đệ quy và không gọi đồng thời từ nhiều luồng cùng lúc.
- **Whole-ELF Payload Wrapper (`E08`, `--wrap-elf`):** Đóng gói toàn bộ `.so` gốc vào một `.so` vỏ và nạp qua `memfd_create`/`dlopen`. Chỉ hỗ trợ chuyển tiếp các symbol hàm (`STT_FUNC`), từ chối thư viện có export biến dữ liệu (`STT_OBJECT`).

## 4. Kiểm tra Toàn vẹn Runtime và Dò Môi trường (`R01–R08`)

- Các cổng kiểm tra runtime (`R01`, `R02`, `R05`, `R06`) chạy khi những hàm được gắn cổng (như `JNI_OnLoad`, hàm JNI hoặc hàm VM/obfuscated) được gọi. Không dùng background thread tạo trong `DT_INIT` để tránh deadlock khóa của Bionic linker.
- Các probe môi trường (`hooks`, `root`, `emulator`, kể cả khi bật `--deep-probes`) vẫn dựa trên dấu hiệu quan sát được từ không gian người dùng; quyền SELinux hoặc công cụ che giấu ở mức kernel/mount namespace có thể ẩn dấu hiệu. Mặc định giữ tắt ba probe này khi thử nghiệm trên giả lập đã root.
