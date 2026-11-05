# SecuraAI Windows APT model

Leakage-aware training pipeline for the **Windows-APT 2025 v4** dataset. It follows the
project guidance: inspect and clean labeled data, make a chronological 60/20/20 split,
tune five CPU-friendly classifiers with grouped K-Fold, add Soft Voting, report metrics, export the selected model,
and serve it through FastAPI.

## Scope

The model predicts `BENIGN` or `MALICIOUS_APT` for Windows host telemetry collected by
Wazuh/Sysmon. It does **not** claim to detect VPN/SSO attacks, web attacks, Linux attacks, or
calibrated attack probability.

Dataset: Mozaffari, Yazdinejad, Dehghantanha, *Windows-APT 2025*, Mendeley Data v4,
DOI [`10.17632/b8fmtzvpy8.4`](https://data.mendeley.com/datasets/b8fmtzvpy8/4), CC BY 4.0.

## Leakage policy

MITRE tags define the experimental target. MITRE, Wazuh rule fields, scenario metadata,
raw `full_log`, unique IDs, hashes and agent identity are never model inputs. Train, Validation
and Test are chronological and keep each collection date intact. K-Fold tuning occurs only on
Train; Validation selects the final model and Test remains untouched until final evaluation.

The target is rule-derived ground truth and may contain false positives or missed attacks.
Results measure agreement with this dataset's labels, not universal real-world accuracy.

## Setup and run

Requires Python 3.11–3.13.

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m pip install -e .
```

Download `combined.csv` into `data/raw/combined.csv`, or put the 16 per-period CSV files in
`data/raw/` and pass that directory as `--input`. Raw
attack logs may trigger endpoint protection because they contain attack commands; use an
approved isolated environment and never disable security software. Raw data is excluded from Git.

```powershell
.venv\Scripts\python -m securaai_ml.inspect_data --input data/raw/combined.csv
.venv\Scripts\python -m securaai_ml.train --input data/raw/combined.csv
.venv\Scripts\uvicorn securaai_ml.api:app --host 127.0.0.1 --port 8000
```

Export the validation-selected Soft Voting model before starting inference:

```powershell
.venv\Scripts\python.exe scripts\export_selected_model.py
```

The API applies the locked Validation threshold stored in
`artifacts/model_metadata.json`; it does not use the estimator's default
threshold. SecuraAI Backend can consume this endpoint in shadow mode without
changing its existing alert or incident decisions.

Training writes the fitted pipeline to `artifacts/` and tuning/validation/test metrics, confusion matrix,
ROC curve and a combined model comparison chart to `reports/`.

The `notebooks/` directory contains a lecturer-style suite: EDA/preprocessing, one notebook
per algorithm, Soft Voting, final comparison and FastAPI export. They reuse the production
feature/training modules so notebook experiments and the deployed artifact follow one policy.

`POST /v1/predict` accepts canonical Windows event fields that SecuraAI can map from a
normalized Wazuh event. Missing fields remain missing; no fake IP or account is created. The
returned score is an experimental classifier score, not a calibrated attack probability.

## Build a SecuraAI Wazuh review dataset

Real Wazuh events must be reviewed separately from the public experimental dataset. Exporting
does not turn Wazuh rules into ground truth: every row starts excluded and without a label.

```powershell
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m securaai_ml.wazuh_review `
  --backend-env ..\SecuraAI-Backend\.env `
  --output data\securaai_review\wazuh_review.csv
```

Review `reviewer_label` as `BENIGN` or `MALICIOUS_APT`, set `include_for_training=true` only
when evidence is sufficient, and leave uncertain records excluded. `review_suggestion` is a
queueing aid, never a training label. Validate the edited file with:

```powershell
.venv\Scripts\python -m securaai_ml.wazuh_review `
  --validate data\securaai_review\wazuh_review.csv
```

For a safe controlled Windows lab run, execute `scripts\run_wazuh_lab.ps1`. After Wazuh has
forwarded all events, export the exact time window and account prefix recorded by its manifest:

```powershell
.venv\Scripts\python scripts\export_wazuh_lab_run.py `
  data\securaai_lab\securaai-lab-<id>.json `
  --backend-env ..\SecuraAI-Backend\.env
```

Only events matched by both the manifest time window and its random lab-account prefix receive
the controlled `MALICIOUS_APT` ground truth. A count mismatch fails instead of silently producing
an incomplete training run.
