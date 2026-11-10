# SecuraAI – Trained Detection Model

Project này xây dựng, đánh giá và phục vụ **mô hình Machine Learning tự huấn luyện** cho SecuraAI. Mô hình nhận log bảo mật đã được Backend chuẩn hóa, kết hợp ngữ cảnh hành vi trong các cửa sổ **1, 5, 15 và 60 phút**, sau đó trả về nhãn, score và ngưỡng quyết định.

Repository này **không trực tiếp đọc Wazuh, không tự tạo alert và không chạy LLM**. Việc lấy log theo chu kỳ, chuẩn hóa, tạo context nhiều cửa sổ, gọi Foundation-Sec, lưu kết quả và tạo/gộp alert thuộc `SecuraAI-Backend`.

## Luồng tích hợp

```text
Wazuh
  → SecuraAI Backend lấy log mới theo chu kỳ
  → chuẩn hóa event
  → tính context quá khứ 1/5/15/60 phút
  → POST /v1/predict của Train-Model
  → Backend quyết định có chuyển sang Foundation-Sec hay không
  → Backend lưu kết quả và xử lý alert
```

API trong repository này chỉ thực hiện bước ML:

```text
Normalized event + temporal context
  → feature engineering
  → trained scikit-learn pipeline
  → score + locked threshold + label
```

Score là **điểm phân loại thực nghiệm**, không phải xác suất tấn công đã được hiệu chỉnh.

## Phạm vi phát hiện

Candidate temporal hiện tập trung vào ba nhóm log đã chuẩn hóa của SecuraAI:

- `AUTHENTICATION`: đăng nhập thất bại, brute force, password spray và success-after-failure.
- `VPN_SSO`: chuỗi đăng nhập VPN/SSO thất bại hoặc phân tán.
- `APPLICATION_ACCESS`: chuỗi truy cập ứng dụng bị từ chối và hành vi liên quan.

Đầu ra nhị phân của mô hình:

- `BENIGN`
- `MALICIOUS_APT`

Tên `MALICIOUS_APT` là nhãn lịch sử của pipeline. Nó không có nghĩa mô hình đã được kiểm chứng cho mọi loại APT, malware, ransomware, process injection, Linux hay network attack.

## Các nhánh thí nghiệm trong project

### 1. Baseline Windows-APT theo từng event

Pipeline trong `src/securaai_ml/train.py`:

- Đọc Windows-APT 2025 v4.
- Chia Train/Validation/Test xấp xỉ 60/20/20 theo thời gian và giữ nguyên ngày thu thập.
- Tune Decision Tree, Random Forest, Complement Naive Bayes, Linear SVM và Logistic Regression bằng `StratifiedGroupKFold`.
- Xây thêm Soft Voting.
- Chọn model trên Validation và chỉ mở Test sau khi khóa lựa chọn.

Dataset: Mozaffari, Yazdinejad, Dehghantanha, *Windows-APT 2025*, Mendeley Data v4, DOI [`10.17632/b8fmtzvpy8.4`](https://data.mendeley.com/datasets/b8fmtzvpy8/4), CC BY 4.0.

Baseline này hữu ích để trình bày quy trình ML nhưng đã bộc lộ **domain shift** khi áp dụng trực tiếp cho log SecuraAI.

### 2. Thử nghiệm combined/transfer

Các script `train_combined_candidate.py`, `evaluate_radar_external.py` và `evaluate_silrad_transfer.py` dùng để nghiên cứu khả năng chuyển miền giữa Windows-APT, RADAR, SILRAD và dữ liệu Wazuh đã review.

Các artifact này là thử nghiệm nghiên cứu; không mặc nhiên là model đang được Backend sử dụng.

### 3. Candidate temporal 1/5/15/60 phút

Candidate mới nhất được tạo bởi `scripts/train_temporal_candidate.py`:

- Model version: `securaai-temporal-1m5m15m60m-lab-candidate-v8`.
- Model được chọn trên Validation: `Bagging`.
- Artifact: `artifacts-temporal-1m5m15m60m-candidate/`.
- Feature chính: `event_family`, `event_type`, thời gian, thông tin IP/port và các thống kê quá khứ 1/5/15/60 phút.
- Train-CV: 5-Fold `StratifiedGroupKFold` theo `scenario_id`.
- Tiêu chí lựa chọn chính: F2; tie-break bằng Recall, Precision, Train-CV F2 và độ lệch chuẩn CV.
- Threshold được chọn trên Validation với điều kiện FPR không vượt quá 5%.

Dữ liệu của candidate v8 gồm:

- Scenario SecuraAI có kiểm soát.
- Windows authentication lab có kiểm soát.
- Scenario multi-window có kiểm soát.

Metadata đánh dấu model là `EXPERIMENTAL_CONTROLLED_LAB_ONLY`. Kết quả 100% trên một số split/case kiểm soát **không phải độ chính xác production** và không chứng minh model tổng quát hóa với log thực tế chưa được chuyên gia gán nhãn.

## Feature temporal

`src/securaai_ml/temporal.py` tạo feature theo quá khứ trong cùng `scenario_id`, không dùng dữ liệu tương lai và không trộn các session:

- 1 phút: `events_1m`, `failures_1m`.
- 5 phút: tổng event, failed login, access denial, VPN failure, số account/IP khác nhau và success-after-failure.
- 15 phút: `events_15m`, `failures_15m`.
- 60 phút: `events_60m`, `failures_60m`.
- Khoảng cách tới event trước: `seconds_since_previous`.

Các cửa sổ này là **feature đầu vào của ML**, không phải luật cố định tự kết luận tấn công. Backend phải tính context theo quá khứ và gửi cùng event hiện tại khi gọi API.

## Chính sách chống leakage

- MITRE/Wazuh tags chỉ được dùng để tạo nhãn thí nghiệm, không được đưa vào feature.
- Không dùng raw `full_log`, unique ID, agent identity hoặc chuỗi hash làm feature nhận diện nhãn.
- One-Hot Encoder được fit bên trong pipeline và từng fold CV.
- Train, Validation và Test không dùng chung collection date hoặc scenario session, tùy pipeline.
- Model, siêu tham số và threshold được chọn bằng Train/Validation; Test chỉ dùng để báo cáo cuối.
- Challenge v2/v3/v4 có `include_for_training=false` và không được đưa ngược vào dữ liệu huấn luyện.

Nhãn từ rule/manifest vẫn có thể chứa sai lệch. Metric đo mức khớp với ground truth của thí nghiệm, không phải hiệu năng phổ quát ngoài thực tế.

## Cài đặt

Yêu cầu Python 3.11–3.13. Không cần GPU.

```powershell
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m pip install -e .
```

`requirements-dev.txt` đã bao gồm thư viện runtime, pytest và Jupyter.

## Dữ liệu

Raw dataset và artifact lớn được loại khỏi Git. Với baseline Windows-APT, đặt một trong hai dạng sau vào `data/raw/`:

- `combined.csv`; hoặc
- các file CSV theo từng giai đoạn thu thập.

Khi có `combined.csv`, loader ưu tiên file này để tránh đọc trùng dữ liệu.

Không tắt Windows Security chỉ để đọc dataset. Log tấn công có thể chứa command bị endpoint protection phát hiện; nên dùng môi trường lab được phê duyệt hoặc cấu hình exclusion có phạm vi tối thiểu.

## Chạy baseline Windows-APT

```powershell
.venv\Scripts\python.exe -m securaai_ml.inspect_data --input data\raw
.venv\Scripts\python.exe -m securaai_ml.train --input data\raw
```

Kết quả được ghi vào:

- `artifacts/model.joblib`
- `artifacts/model_metadata.json`
- `reports/model_comparison.csv`
- `reports/summary.json`
- confusion matrix, ROC và biểu đồ so sánh model trong `reports/`

Lưu ý: `scripts/export_selected_model.py` export lại Soft Voting từ bộ notebook baseline. Script này **không export candidate temporal v8**.

## Chạy candidate temporal mới nhất

Script dùng các đường dẫn dữ liệu cố định trong project:

```powershell
.venv\Scripts\python.exe scripts\train_temporal_candidate.py
```

Các input cần có:

```text
data/securaai_scenarios/securaai_scenarios.csv
data/securaai_scenarios/securaai_multiwindow_scenarios.csv
data/real_windows_auth_lab/real_windows_auth_v1.csv
```

Output:

```text
artifacts-temporal-1m5m15m60m-candidate/model.joblib
artifacts-temporal-1m5m15m60m-candidate/model_metadata.json
```

## Chạy API

Mặc định API đọc artifact trong `artifacts/`. Muốn chạy candidate temporal v8 phải chỉ định rõ thư mục:

```powershell
$env:SECURAAI_MODEL_ARTIFACT_DIR = "artifacts-temporal-1m5m15m60m-candidate"
.venv\Scripts\python.exe -m uvicorn securaai_ml.api:app --host 127.0.0.1 --port 8002
```

Kiểm tra trạng thái:

```powershell
Invoke-RestMethod http://127.0.0.1:8002/health
```

Swagger UI: `http://127.0.0.1:8002/docs`.

### `POST /v1/predict`

Ví dụ tối thiểu có context temporal:

```json
{
  "timestamp": "2026-11-10T09:15:00Z",
  "eventFamily": "authentication",
  "eventType": "LOGIN_FAILURE",
  "eventId": "4625",
  "sourceIp": "203.0.113.25",
  "status": "FAILURE",
  "events1m": 3,
  "failures1m": 3,
  "events5m": 8,
  "failedLogins5m": 7,
  "distinctAccounts5m": 1,
  "distinctSourceIps5m": 1,
  "events15m": 12,
  "failures15m": 9,
  "events60m": 20,
  "failures60m": 12
}
```

Response:

```json
{
  "label": "MALICIOUS_APT",
  "malicious": true,
  "score": 1.0,
  "threshold": 0.5,
  "escalationThreshold": 0.5,
  "scoreSemantics": "experimental temporal classifier score; not calibrated attack probability",
  "modelVersion": "securaai-temporal-1m5m15m60m-lab-candidate-v8"
}
```

Giá trị trên chỉ minh họa cấu trúc response, không phải kết quả bảo đảm cho mọi request.

## Trạng thái artifact

| Thư mục | Mục đích | Trạng thái |
|---|---|---|
| `artifacts/` | Baseline theo từng event, Soft Voting v1 | Artifact mặc định của API nếu không đặt biến môi trường |
| `artifacts-temporal-1m5m15m60m-candidate/` | Candidate temporal v8, Bagging | Candidate mới nhất; controlled-lab only |
| `artifacts-temporal-candidate/` | Candidate temporal v6 | Kết quả lịch sử |
| `artifacts-temporal-multiwindow-candidate/` | Candidate temporal v7 | Kết quả lịch sử |
| `artifacts-combined-candidate/`, `artifacts-radar-*` | Thử nghiệm combined/transfer | Không mặc nhiên được triển khai |

Không nên gọi một artifact là “production” chỉ vì file tồn tại trong repository. Backend phải cấu hình chính xác `SECURAAI_MODEL_ARTIFACT_DIR` và kiểm tra `modelVersion` qua `/health`.

## Notebook

`notebooks/` gồm 12 notebook theo trình tự giảng viên:

| Notebook | Nội dung |
|---|---|
| `00_Data_EDA_Preprocessing.ipynb` | Audit dữ liệu, EDA, preprocessing và split |
| `01_Decision_Tree.ipynb` | Decision Tree |
| `02_Naive_Bayes.ipynb` | Complement Naive Bayes |
| `03_Rule_Based.ipynb` | Baseline rule-based để đối chiếu |
| `04_Bagging.ipynb` | Bagging |
| `05_Random_Forest.ipynb` | Random Forest |
| `06_AdaBoost.ipynb` | AdaBoost |
| `07_Soft_Voting.ipynb` | Soft Voting |
| `08_Lua_Chon_Mo_Hinh_Va_Bao_Cao.ipynb` | So sánh, chọn model và báo cáo |
| `09_Linear_SVM_Extra.ipynb` | Linear SVM |
| `10_Logistic_Regression_Extra.ipynb` | Logistic Regression |
| `11_Export_Model_FastAPI.ipynb` | Kiểm tra/export và hướng dẫn FastAPI |

Các artifact notebook dùng để so sánh phải có cùng `split_hash`. Nếu notebook 08 báo split khác nhau, cần chạy lại những notebook model có artifact cũ; không được bỏ assertion để trộn kết quả từ các split khác nhau.

## Review log Wazuh

Log Wazuh chưa có ground truth phải đi qua hàng đợi review, không được tự động lấy Wazuh rule làm nhãn huấn luyện:

```powershell
.venv\Scripts\python.exe -m securaai_ml.wazuh_review `
  --backend-env ..\SecuraAI-Backend\.env `
  --output data\securaai_review\wazuh_review.csv
```

Người review điền `reviewer_label` bằng `BENIGN` hoặc `MALICIOUS_APT` và chỉ đặt `include_for_training=true` khi đủ bằng chứng. Kiểm tra file sau khi review:

```powershell
.venv\Scripts\python.exe -m securaai_ml.wazuh_review `
  --validate data\securaai_review\wazuh_review.csv
```

`review_suggestion` chỉ hỗ trợ sắp xếp hàng đợi, không phải ground truth.

## Kiểm thử

```powershell
.venv\Scripts\python.exe -m pytest -q
```

Test hiện bao phủ:

- Load dữ liệu và ưu tiên `combined.csv`.
- Feature engineering và chống label leakage.
- Temporal split và grouped CV.
- Feature 1/5/15/60 phút không nhìn tương lai, không trộn session.
- Mapping RADAR và Wazuh review.
- API health/predict và locked threshold.
- Scenario/challenge độc lập không bị đưa vào Train.

## Tài liệu liên quan

- [`docs/DATASET_SELECTION.md`](docs/DATASET_SELECTION.md): lý do chọn và giới hạn dataset.
- [`docs/MODEL_CARD.md`](docs/MODEL_CARD.md): lịch sử thí nghiệm, metric và giới hạn model.
- [`docs/REAL_WINDOWS_LAB.md`](docs/REAL_WINDOWS_LAB.md): quy trình Windows lab có kiểm soát.
- [`docs/WAZUH_REVIEW_GUIDE.md`](docs/WAZUH_REVIEW_GUIDE.md): hướng dẫn review log Wazuh.

## Giới hạn hiện tại

- Phần lớn dữ liệu temporal vẫn là scenario/lab có kiểm soát.
- Chưa có tập log Wazuh production đủ lớn được chuyên gia gán nhãn độc lập.
- Metric rất cao trên synthetic/lab có thể phản ánh ranh giới sinh dữ liệu dễ học.
- Model chưa được chứng minh cho mọi loại log hoặc mọi môi trường doanh nghiệp.
- API không tự tạo context; Backend phải cung cấp đúng thống kê quá khứ.
- Scheduler đọc log mỗi phút, Foundation-Sec, timeout/retry và trạng thái lỗi thuộc Backend/Frontend, không thuộc repository này.

Vì các giới hạn trên, model nên được đánh giá bằng dữ liệu ngoài miền và log đã review trước khi được phép tự động quyết định alert.
