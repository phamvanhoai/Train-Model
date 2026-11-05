# Hướng dẫn review log Wazuh mô phỏng ngoài benchmark

File cần review: `data/securaai_review/wazuh_review_scored.csv`. Toàn bộ dữ liệu PostgreSQL hiện
tại là dữ liệu mô phỏng. File này không được mô tả là log production hay dữ liệu người dùng thật.

Model đã dự đoán trước và khóa kết quả trong các cột `model_score` và
`model_prediction`. Hai cột này **không phải ground truth**. Để giảm thiên lệch, người review nên
quyết định từ timestamp, event type, rule, tài khoản/IP và chuỗi sự kiện trong cùng
`review_session_id`, sau đó mới đối chiếu dự đoán.

Chỉ sửa ba cột:

- `reviewer_label`: `BENIGN` hoặc `MALICIOUS_APT`;
- `include_for_training`: đặt `true` khi đủ bằng chứng để dùng nhãn;
- `review_notes`: ghi lý do, ví dụ “người dùng xác nhận nhập sai mật khẩu” hoặc mã kịch bản lab.

Ground truth chỉ hợp lệ khi đối chiếu được với kịch bản/manifest đã sinh log. Không tự coi Wazuh
rule level cao, dữ liệu đã nằm trong PostgreSQL hoặc model prediction là nhãn. Nếu không đủ bằng chứng, giữ
`include_for_training=false`. Với burst đăng nhập, cần xác minh đó là kịch bản tấn công/lab hay
hành vi hợp lệ; số lần lỗi một mình không chứng minh ý định tấn công.

Sau khi review, chạy:

```powershell
.\.venv\Scripts\python.exe -m securaai_ml.wazuh_review --validate data\securaai_review\wazuh_review_scored.csv
.\.venv\Scripts\python.exe scripts\evaluate_reviewed_wazuh.py data\securaai_review\wazuh_review_scored.csv
```

Báo cáo chỉ được tạo khi các dòng được chọn có nhãn hợp lệ và có cả hai lớp. Đây vẫn là external
test mô phỏng, không phải đánh giá production. Không dùng test này để đổi threshold; nếu cần
retrain, phải tạo split mới theo session/thời gian rồi đánh giá trên một test khác chưa từng xem.
