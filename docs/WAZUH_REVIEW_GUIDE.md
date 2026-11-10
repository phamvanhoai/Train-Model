# Hướng dẫn review log Wazuh ngoài benchmark

Cập nhật: 2026-11-10.

File cần review: `data/securaai_review/wazuh_review_scored.csv`. Toàn bộ dữ liệu PostgreSQL hiện
tại là dữ liệu mô phỏng. File này không được mô tả là log production hay dữ liệu người dùng thật.

Nếu làm việc với nguồn khác, phải ghi đúng nguồn dữ liệu. Việc một event đi qua Wazuh hoặc được lưu
trong SecuraAI không tự biến nó thành ground truth.

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

## Tạo và chấm hàng đợi review

Export event đã chuẩn hóa từ Backend:

```powershell
.venv\Scripts\python.exe -m securaai_ml.wazuh_review `
  --backend-env ..\SecuraAI-Backend\.env `
  --output data\securaai_review\wazuh_review.csv
```

Có thể chạy model hiện tại để hỗ trợ sắp xếp thứ tự review, nhưng kết quả vẫn không phải nhãn:

```powershell
.venv\Scripts\python.exe scripts\score_wazuh_review_queue.py `
  data\securaai_review\wazuh_review.csv `
  --artifacts artifacts-temporal-1m5m15m60m-candidate `
  --output data\securaai_review\wazuh_review_scored.csv
```

Script chia `review_session_id` theo principal, event family và idle gap để context của các chuỗi
không liên quan không bị trộn với nhau.

## Bằng chứng cần xem

Người review nên kiểm tra tối thiểu:

- timestamp và thứ tự event;
- user/account, source IP và host;
- event family/type và trạng thái;
- ứng dụng hoặc destination liên quan;
- các event cùng `review_session_id`;
- manifest/ticket/xác nhận người dùng nếu có.

Không quyết định chỉ dựa vào score, số lượng trong một cửa sổ, giờ ngoài hành chính hoặc Wazuh rule
level. Với chuỗi kéo dài, cần xem cả bối cảnh 1/5/15/60 phút thay vì chỉ một event riêng lẻ.

Sau khi review, chạy:

```powershell
.\.venv\Scripts\python.exe -m securaai_ml.wazuh_review --validate data\securaai_review\wazuh_review_scored.csv
.\.venv\Scripts\python.exe scripts\evaluate_reviewed_wazuh.py data\securaai_review\wazuh_review_scored.csv
```

Báo cáo chỉ được tạo khi các dòng được chọn có nhãn hợp lệ và có cả hai lớp. Đây vẫn là external
test mô phỏng, không phải đánh giá production. Không dùng test này để đổi threshold; nếu cần
retrain, phải tạo split mới theo session/thời gian rồi đánh giá trên một test khác chưa từng xem.

## Đưa dữ liệu đã review vào huấn luyện

Chỉ các dòng có `include_for_training=true`, nhãn hợp lệ và bằng chứng đủ mạnh mới được xem xét đưa
vào lần huấn luyện sau. Khi retrain:

1. khóa toàn bộ session vào đúng một split;
2. không dùng prediction cũ hoặc rule tag làm nhãn;
3. fit preprocessing trong Train/CV;
4. chọn threshold trên Validation;
5. đánh giá một lần trên Test chưa từng xem;
6. lưu model version, dataset manifest và metric theo từng nguồn.

Candidate v8 vẫn là `EXPERIMENTAL_CONTROLLED_LAB_ONLY`. Dữ liệu review độc lập là điều kiện cần để
đánh giá domain shift trước khi cho phép model ảnh hưởng trực tiếp đến alert.
