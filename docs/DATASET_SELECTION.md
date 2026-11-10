# Lựa chọn dataset bổ sung cho SecuraAI

Ngày kiểm tra nguồn ban đầu: 2026-11-03. Cập nhật trạng thái pipeline: 2026-11-10.

## Quyết định

Chọn **RADAR 2024** làm nguồn bổ sung chính và **SILRAD 2025** làm external test chuyên biệt
ransomware. Cả hai đã được tải trong `data/downloads/`; không cần tải COMISET.

Quyết định này chỉ áp dụng cho nhánh nghiên cứu **Windows endpoint/ransomware**. RADAR và SILRAD
không được dùng để giả lập ground truth cho ba nghiệp vụ chính của SecuraAI là Authentication,
VPN/SSO và Application Access. Candidate temporal hiện tại sử dụng scenario/lab có manifest riêng
cho ba nghiệp vụ này.

### RADAR 2024 — nguồn bổ sung chính

- Windows 11 Sysmon, gồm goodware và ransomware trong luồng liên tục.
- 413.556 event; 302.260 benign và 111.296 ransomware-related theo tài liệu nguồn.
- Có raw CSV, nhãn `target-class` được nhập riêng thay vì suy ra từ trường Sysmon.
- Có các tập mất cân bằng 5% và 10%, phù hợp kiểm tra false positive và concept drift.
- Gói đã tải: `data/downloads/RADAR-v0.0.1-beta.zip` (khoảng 73 MB).
- Giấy phép CC BY 4.0; DOI `10.5281/zenodo.14542547`.

Hạn chế: timestamp của một số luồng đã được điều chỉnh để mô phỏng continuous stream; đây vẫn là
lab data. Dataset tập trung ransomware/Sysmon, không có ground truth cho VPN/SSO, brute force hay
application access của SecuraAI.

### SILRAD 2025 — external ransomware test

- Gần 200.000 Sysmon event: 176.130 goodware và 20.710 ransomware từ 50 mẫu thuộc sáu họ.
- Có train/test do tác giả cung cấp và nhãn 0/1.
- Gói đã tải: `data/downloads/SILRAD-1.0.zip` (khoảng 3,6 MB); CSV đã giải nén trong
  `data/silrad/`.
- Phù hợp kiểm tra domain shift ransomware, nhưng các feature đã được FastText biến đổi nên không
  giống trực tiếp JSON Wazuh và không nên trộn mù với feature temporal hiện tại.

## Kết quả thử nghiệm sau lựa chọn

RADAR được chia chặt theo **họ ransomware**, không chỉ theo file mẫu:

- Train: CyberVolk, LockBit, Lynx, Meow;
- Validation: Medusa;
- Test chưa thấy trong Train: Akira, BlackBasta.

Decision Tree được chọn trên Validation. Test RADAR family-held-out đạt Accuracy 96,03%, Recall
89,76%, F2 91,64%, TN 60.452, FP 0, FN 3.915, TP 34.312. Kết quả thấp hơn split theo mẫu
nhưng đáng tin hơn vì không có cùng họ ransomware ở nhiều split.

Transfer trực tiếp sang 156.841 dòng trong test split của SILRAD thất bại: Accuracy 12,45%,
Balanced Accuracy 50%, TN 0, FP 137.312, FN 0, TP 19.529. Model dự đoán toàn bộ dòng là
ransomware. Đây là bằng chứng domain/schema shift: SILRAD công bố các cột FastText đã biến đổi,
trong khi model triển khai cần raw process/file/network fields. Không dùng SILRAD để tuyên bố model
RADAR tổng quát hóa và không điều chỉnh threshold dựa trên kết quả test này.

## Dataset không chọn làm hướng chính

- **COMISET**: công bố năm 2025 nhưng thu thập năm 2022; LAB zip 4,9 GB và REAL zip 31,7 GB.
  Quy mô vượt nhu cầu hiện tại và mốc thu thập không còn nằm trong ba năm gần nhất vào năm 2026.
- **ATLASv2**: có Windows Security Audit và Sysmon cùng attack windows, nhưng dữ liệu thu năm 2022,
  Windows 7 và tổng raw telemetry khoảng 154 GB. Ground truth công bố rõ nhất cho Security Audit;
  không phù hợp giới hạn dung lượng của project.
- **WinMET**: execution trace CAPE, không phải Windows Event Log/Wazuh; khoảng 13 GB nén và hàng
  trăm GB sau giải nén.

## Vai trò trong pipeline hiện tại

Project hiện tách dữ liệu thành ba mục đích, không trộn tất cả vào một tập rồi chia ngẫu nhiên:

1. **Windows-APT 2025:** baseline theo từng event để trình bày đầy đủ quy trình EDA, K-Fold,
   Validation, Test và so sánh thuật toán.
2. **RADAR/SILRAD:** thí nghiệm transfer cho endpoint/ransomware và minh họa domain shift.
3. **SecuraAI temporal:** scenario Authentication, VPN/SSO, Application Access, Windows lab có
   kiểm soát và scenario multi-window. Đây là dữ liệu của candidate v8.

Candidate v8 không sử dụng raw dataset identity làm feature. Nó dùng `event_family`, `event_type`,
đặc trưng thời gian/IP/port và context quá khứ 1, 5, 15, 60 phút. Split được giữ theo
`scenario_id`; threshold chỉ chọn trên Validation.

## Khoảng trống còn lại

Không tìm thấy một dataset công khai 2023–2026, nhỏ hơn 5 GB, đồng thời có raw Wazuh/Windows logs
và ground truth đầy đủ cho cả Authentication, VPN/SSO và Application Access. Vì vậy không nên ép
RADAR/SILRAD thành nhãn cho ba nghiệp vụ này. Hướng đúng là:

1. dùng RADAR/SILRAD cho nhánh Windows endpoint/ransomware;
2. dùng candidate temporal cho Auth/VPN/App như một mô hình **controlled-lab experimental**;
3. tiếp tục thu controlled runs có manifest và giữ nguyên session khi chia dữ liệu;
4. khi có log operational, lấy analyst review làm external ground truth trước khi retrain hoặc
   cho phép model ảnh hưởng trực tiếp đến alert.

Không dùng label của model hoặc Wazuh rule tag làm ground truth độc lập.
