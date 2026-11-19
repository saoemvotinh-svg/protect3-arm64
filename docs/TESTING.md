# Kiểm thử (v0.3.0)

## 1. Bộ kiểm thử tự động ở 0.3.0

Chạy toàn bộ 50 bài kiểm thử đơn vị, mô phỏng lệnh ARM64 và differential execution (`F03`):

```powershell
$env:ANDROID_NDK_HOME = 'D:\Android\ndk\android-ndk-r27d'
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Các bài kiểm thử trong `tests/test_protect3.py`, `tests/test_v03_roadmap.py` và `tests/test_diagnostics.py` xác minh:
- **F01 & Strip Ordering:** Phân giải hàm local (`sample_constructor`) trước khi chạy `llvm-strip` và khôi phục hàm từ `.eh_frame` sau khi đã xóa `.symtab`.
- **E01, E03, E04, E05, E06, E07, E08:** Mã hóa nhiều hàm, giải mã chuỗi lười (lazy) từ String Vault tách trang 16 KiB chỉ khi hàm gọi tới chuỗi, chặn ciphertext bị sửa **trước khi** gọi `mprotect` bằng HMAC-SHA256 (`E04`), phát hiện sửa cấu hình bằng chữ ký manifest (`E05`), xóa metadata `.comment`, dẫn xuất khóa KDF (`E07`) và tạo thư viện vỏ bọc toàn bộ ELF (`E08`).
- **O01–O09:** Làm rối lệnh MBA (`O01`), hằng số ẩn (`O02`), vị từ bất biến theo input (`O03`), gọi gián tiếp (`O04`), tách/xáo trộn khối (`O05/O06`), làm phẳng luồng điều khiển (`O07`), và ảo hóa hàm ARM64 sang bytecode VM với bảng opcode đa hình theo seed (`O08/O09`).
- **R01–R08:** Phát hiện inline hook chèn vào prologue hàm **sau khi** thư viện đã nạp xong (`R01/R02`), phát hiện debugger gắn vào **sau khi** nạp (`R05`), tự kiểm tra toàn vẹn mã `guard.bin` (`R06`), giải mã trước khi gọi và tái mã hóa ngay sau khi hàm trả về (`R07`), cùng các dấu hiệu mở rộng cho BlueStacks và thread Frida (`R08`).

## 2. Kiểm thử Bionic ARM64 trong Docker (`tools/smoke_bionic.py`)

Chạy **33 ca nạp thực tế** bằng Bionic linker ARM64 trong container Termux Docker:

```powershell
.\.venv\Scripts\python.exe tools\smoke_bionic.py
```

Tất cả 33/33 ca (bao gồm `multi_function_e01`, `lazy_strings_e03`, `obfuscated_o01_o06`, `flattened_o07`, `virtualized_o08_o09`, `on_demand_r07`, `jni_runtime_r01_r06`, `profile_max`, `wrapped_e08` và các ca phát hiện tamper dừng với mã `175`) đều đạt và được ghi vào `build/bionic-smoke.json`.

## 3. Kiểm thử thực tế trên BlueStacks Android 9 (`com.garena.game.kgvn`)

Ngày **18/11/2026**, bản **0.3.0** của `libMyLibName.so` đã được nạp và kiểm thử trên `com.garena.game.kgvn` (`127.0.0.1:5555`) qua `tools/trial_adb.py` và `tools/audit_adb.py`:
- Bật đồng thời: `--compat-layout --encrypt-text --encrypt-rodata --auth-encryption --sign-manifest --masked-key --guard-self-check --prologue-check --clean-metadata --obfuscate-jni --virtualize-functions fde_73030,fde_73040 --flatten-functions fde_73064 --watermark kgvn-v03-verified --diagnostics`.
- Kết quả quan sát 30 giây đầu và 3 lần khởi động lặp lại (mỗi lần 20 giây) đều thành công, ghi nhận đầy đủ cả log khởi tạo (`manifest_mac_ok`, `guard_self_check_ok`, `text_mac_ok`, `rodata_mac_ok`, `prologue_check_ok`, `guard_return`) lẫn log cổng kiểm tra runtime (`runtime_gate_ok`) khi `JNI_OnLoad` được gọi.
- Chi tiết bằng chứng lưu tại:
  - `output/adb-com.garena.game.kgvn-20261118-144806-8c00ae5d/trial.json`
  - `output/audit-20261118-144938/audit.json`
  - `output/kgvn/deployment.json`
