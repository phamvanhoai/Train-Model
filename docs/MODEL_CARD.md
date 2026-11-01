# SecuraAI Windows APT classifier — experimental model card

## Intended use

Binary classification of Windows host events collected through Wazuh/Sysmon into
`BENIGN` and `MALICIOUS_APT`. The model is an integration feasibility experiment for the
SecuraAI software project, not a replacement for Wazuh rules or analyst review.

## Dataset and protocol

- Windows-APT 2025 v4, DOI `10.17632/b8fmtzvpy8.4`, CC BY 4.0.
- 102,011 events: 63,792 MITRE-tagged and 38,219 untagged.
- 40 UTC collection dates; no invalid timestamps after normalization.
- Chronological, date-grouped split: 61,277 Train (60.07%), 20,176 Validation (19.78%),
  and 20,558 Test (20.15%). A collection date never crosses split boundaries.
- Hyperparameters were tuned only on Train with five-fold `StratifiedGroupKFold`.
- Validation selected the model by F2; Test was opened only after selection.
- Preprocessing was fitted independently inside every fold.

MITRE/Wazuh rule tags define the experimental target but are excluded from model inputs.
Wazuh rule metadata, raw logs, scenarios, record IDs, agent identity and hashes are also
excluded to reduce direct target and environment leakage.

## Model comparison

Validation results after K-Fold/Grid Search tuning:

| Model | Accuracy | Precision | Recall | F1 | F2 | ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|
| Linear SVM | 0.9982 | 0.9996 | 0.9971 | 0.9984 | 0.9976 | 0.9997 |
| Logistic Regression | 0.9956 | 0.9996 | 0.9923 | 0.9960 | 0.9938 | 0.9998 |
| Random Forest | 0.9917 | 0.9996 | 0.9852 | 0.9923 | 0.9880 | 0.9999 |
| Decision Tree | 0.9797 | 0.9995 | 0.9635 | 0.9812 | 0.9705 | 0.9830 |
| Soft Voting | 0.9795 | 0.9997 | 0.9629 | 0.9810 | 0.9701 | 0.9999 |
| Complement Naive Bayes | 0.4550 | 1.0000 | 0.0057 | 0.0113 | 0.0071 | 0.9712 |

Linear SVM (`C=0.1`) was selected by Validation F2. On the untouched 20,558-event Test set:

- Accuracy: 0.9958
- Precision: 0.9993
- Recall: 0.9933
- F1: 0.9963
- F2: 0.9945
- ROC-AUC: 0.9995

## Limitations

- Labels are derived from Wazuh/MITRE rules, not independently adjudicated ground truth.
  High scores may partly reflect stable relationships between event fields and those rules.
- The dataset is controlled, simulated Windows APT telemetry. Results do not establish
  performance on production environments, novel attacks, Linux, application access, VPN/SSO,
  brute force, or concept drift.
- Untagged does not guarantee benign; attacks missed by the source rules may be mislabeled.
- The classifier score is not a calibrated attack probability.
- External validation on separately collected SecuraAI/Wazuh data is required before deployment.

## Integration requirement

Deploy first in shadow mode. Persist the model version and score beside existing SecuraAI
detection evidence, compare results with analyst feedback, and do not automatically create or
close incidents solely from this model output.
