# Controlled real Windows authentication lab

Updated: 2026-11-10.

This lab produces genuine Windows Security authentication telemetry rather than generated CSV
rows. It targets localhost with a deliberately nonexistent username, so no real user is modified
or locked. Windows records Event ID 4625, the Wazuh Agent collects it, and the run manifest records
the exact time range and controlled ground truth.

Run once from **PowerShell as Administrator**:

```powershell
cd C:\Users\Admin\Documents\GITHUB\Train-Model
powershell -ExecutionPolicy Bypass -File .\scripts\run_real_windows_auth_lab.ps1
```

The script enables success/failure Logon auditing, restarts the Wazuh Agent after enrollment,
performs six failed localhost SMB authentications, reads the resulting Security events and writes
an external-test-only manifest under `data/windows_auth_lab/`. Do not append the resulting events
to Train until an independent review confirms the event/run mapping.

## Vì sao cần manifest

Event ID 4625 chỉ chứng minh Windows ghi nhận đăng nhập thất bại; bản thân event không chứng minh
ý định tấn công. Manifest khóa trước:

- thời gian bắt đầu/kết thúc run;
- account prefix ngẫu nhiên;
- số event dự kiến;
- scenario và nhãn có kiểm soát;
- session split.

Exporter chỉ gán ground truth khi event khớp cả time window và account prefix. Count mismatch phải
làm run thất bại thay vì âm thầm tạo dataset thiếu.

## Thu thập bộ authentication có kiểm soát

Để tạo nhiều session Train/Validation/Test độc lập, chạy PowerShell với quyền Administrator:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\collect_real_windows_auth_sessions.ps1
```

Sau khi Wazuh và Backend đã nhận đủ log, export dataset bằng manifest tương ứng:

```powershell
.venv\Scripts\python.exe scripts\export_real_windows_auth_dataset.py `
  --manifest data\real_windows_auth_lab\<manifest>.json `
  --backend-env ..\SecuraAI-Backend\.env `
  --output data\real_windows_auth_lab\real_windows_auth_v1.csv
```

Không để một `scenario_id` xuất hiện ở nhiều split. Feature temporal phải được tính trong từng
session và chỉ nhìn event quá khứ.

## Vai trò trong candidate v8

`scripts/train_temporal_candidate.py` đọc:

```text
data/real_windows_auth_lab/real_windows_auth_v1.csv
```

Dữ liệu này được kết hợp với scenario SecuraAI và multi-window scenario. Candidate v8 sử dụng
context 1, 5, 15 và 60 phút; nó không dùng quy tắc “đủ N lần là chắc chắn tấn công” làm quyết định
toàn cục. Model và threshold được chọn trên Validation, sau đó mới đánh giá Test.

## Giới hạn an toàn và báo cáo

- Chỉ dùng account không tồn tại hoặc account lab được phép; không thử mật khẩu của người dùng thật.
- Tránh gây account lockout và không chạy trên máy production.
- Log là telemetry Windows thật nhưng kịch bản vẫn có kiểm soát.
- Không gọi kết quả lab là độ chính xác production.
- Không dùng Test để chỉnh feature, threshold hoặc chọn lại model.
