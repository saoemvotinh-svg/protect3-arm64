# Protect3 0.3.0 — Windows Portable Release Notes

## Phân phối Windows không cần cài đặt thủ công
- Giải nén `Protect3-0.3.0-Windows-Portable.zip` vào bất kỳ thư mục nào (hỗ trợ đường dẫn có dấu cách hoặc ký tự Unicode tiếng Việt).
- Chạy trực tiếp **`Protect3\Protect3.exe`** bằng double-click (giao diện Qt Quick Studio, không cần cài Python, PySide6 hay Qt).
- Hoặc dùng CLI **`Protect3\protect3-cli.exe`** cho kịch bản tự động hóa.

## Điểm mới trong bản phát hành này
- Nâng cấp toàn bộ giao diện lên **Qt Quick / PySide6 6.11.2 (Direct3D 11 RHI)** với thiết kế **Obsidian Binary Workbench**.
- Đưa toàn bộ tính năng backend ra giao diện: **Phân tích hàm F01/A03 (6.500+ hàm cuộn mượt)**, gán pass 1-click (`+VM`, `+Flat`, `+Obf`, `+Enc`, `+R07`), xem kế hoạch & xung đột F05 trực tiếp, **Benchmark A04–A06/A09**, **Phân tích Logcat**, biên dịch `guard.bin` qua NDK, cấu hình lưu tại `%LOCALAPPDATA%\Protect3\`.
- **Chống soi IDA Pro Studio (`--troll-ida`, `--block-ida`):** tùy chỉnh bộ ký tự random (mặc định `IlO0`), độ dài chuỗi random (`0..128`), xem trước 3 mẫu hàm trực tiếp, và trình chỉnh sửa nội tuyến đầy đủ cho danh sách tên hàm + chuỗi troll F5.

## Giới hạn môi trường ngoài ứng dụng
- Tính năng `--strip-symbols`, `--wrap-elf` và `Build guard.bin` cần **Android NDK** (các chế độ bảo vệ ELF/ChaCha20/VM/Obfuscation/String Vault/IDA Troll chạy offline hoàn toàn không cần NDK bằng `guard.bin` đã đóng gói sẵn).
- Đã tích hợp sẵn **Unicorn Engine F03 (`--verify-semantics`)** ngay bên trong cả `Protect3.exe` lẫn `protect3-cli.exe` để kiểm chứng ngữ nghĩa ARM64 trước khi lưu file `.so`.
