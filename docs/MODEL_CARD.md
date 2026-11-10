# SecuraAI trained detection models — experimental model card

Trạng thái tài liệu: cập nhật ngày 2026-11-10. Các mục v1–v6 bên dưới là lịch sử thí nghiệm,
không phải mô tả duy nhất của artifact mới nhất. Candidate temporal mới nhất hiện là
`securaai-temporal-1m5m15m60m-lab-candidate-v8`.

## Intended use

Binary classification of normalized SecuraAI security events into `BENIGN` and
`MALICIOUS_APT`. The current temporal candidate focuses on Authentication, VPN/SSO and
Application Access sequences using past-only 1/5/15/60-minute context. It is an integration
feasibility experiment, not proof of production accuracy or a replacement for analyst review.

## Baseline Windows-APT dataset and protocol

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

## Current integration contract

This repository serves only the trained ML stage. SecuraAI Backend is responsible for periodically
reading new Wazuh events, normalization, past-only 1/5/15/60-minute aggregation, second-stage
Foundation-Sec review, persistence, retry/timeout handling and alert grouping.

`POST /v1/predict` returns the model label, raw classifier score, locked decision threshold,
escalation threshold and model version. The score is not a calibrated probability. The API does
not ingest Wazuh directly and does not create an alert. Candidate v8 remains marked
`EXPERIMENTAL_CONTROLLED_LAB_ONLY`; promotion requires independently reviewed operational data.

# Historical deployment findings

The following sections preserve the chronological evidence produced by earlier candidates. Terms
such as “shadow mode”, “contribution zero” and “existing alert engine” describe the architecture at
the date of each experiment and must not be read as the current Train-Model API contract.

## Controlled Wazuh evaluation (2026-11-02)

The selected Windows-APT Soft Voting model was evaluated in shadow mode through the complete
Windows Agent -> Wazuh Manager -> SecuraAI pipeline. A controlled failed-login burst produced
eight independently captured Windows Security 4625 events. The model detected all eight as
`MALICIOUS_APT`. After preserving provider, channel, decoder, authentication package, status,
sub-status and source-port fields, the score for the repeated scenario increased from about
0.411 to 0.608 (locked threshold 0.205).

This is not sufficient production validation. All current SecuraAI PostgreSQL records are
simulated. On the available non-demo simulated records, the
same model classified all 48 Windows Security 4624 login-success events as malicious. Therefore:

- notebook metrics must not be presented as real Wazuh accuracy;
- the model must remain shadow-only;
- changing only the threshold cannot solve the observed domain mismatch;
- authentication burst detection needs sequence/window features and a separately validated
  authentication model (or the existing correlation engine), rather than this event-level APT
  classifier;
- future evaluation must split by lab run/collection period so events from one scenario never
  occur in both training and test data.

## Temporal candidate and boundary benchmark (2026-11-03)

The replacement candidate uses event-family/type plus past-only five-minute counters. It is
trained on 600 controlled sessions (4,656 events), including benign bursts immediately below
the documented operational thresholds. Authentication and VPN failures are blocked before the
fifth event, and application denials before the tenth event; the gate never forces a positive
prediction after that boundary.

On the held-out synthetic Test split it achieved 94.33% accuracy, 84.97% recall and a 3.49%
false-positive rate (TN 718, FP 26, FN 26, TP 147). A separate 15-run integration benchmark
passed through Wazuh, SecuraAI Backend, PostgreSQL and the shadow model API and produced TN 74,
FP 0, FN 0, TP 27. The resulting 100% is only boundary-test coverage over 101 controlled events,
not an estimate of production accuracy or proof of generalization. The candidate remains
`EXPERIMENTAL_SYNTHETIC_ONLY`, must contribute zero to alert decisions, and requires independently
reviewed production Wazuh logs before promotion. No such production dataset is
currently available in this project.

The current v2 synthetic suite contains 3,000 sessions and approximately 24,600 events. It adds
password spraying, distributed attacks, success-after-failure and multi-user background noise.
Two past-only context features (`distinct_accounts_5m` and `distinct_source_ips_5m`) distinguish
one-source/many-account and many-source/one-account patterns from unrelated concurrent users.
The held-out synthetic Test produced TN 4,016, FP 1, FN 0 and TP 925. This near-perfect result is
expected because most labels follow explicit scenario-manifest boundaries; it is not production
accuracy and does not supersede the requirement for independently reviewed operational data.

## Locked Challenge V2 (2026-11-03)

An independently generated synthetic robustness challenge was hashed before evaluation and marked
never-train. It contains 600 sessions and 4,750 events covering aliases, slow attempts, interleaved
users, missing context, duplicate timestamps and off-hours benign activity. Candidate v2 was
evaluated once and achieved 90.53% accuracy, 72.73% recall, 74.77% F2 and 4.11% FPR (TN 3,500,
FP 150, FN 300, TP 800).

The frozen result exposed three failures: all malicious `LOGIN_FAILED` aliases were missed, all
malicious `SSO_LOGIN_FAILURE` aliases were missed, and missing-account/missing-IP bursts produced
150 false positives. Challenge V2 must not be used for threshold selection or appended to training.
Corrections require Train/Validation examples followed by a separately generated Challenge V3.

## Locked Challenges V3 and V4 (2026-11-03)

Candidate v3 was evaluated once on frozen Challenge V3 and achieved 92.00% accuracy, 82.61%
recall, 83.30% F2 and 4.68% FPR (TN 3,098, FP 152, FN 200, TP 950). All 200 false negatives
were account-only authentication attacks, revealing a genuine missing training case. Of the 152
false positives, 150 came from a challenge specification conflict: `APP_SHORT_BURST` contained
12 denials labelled benign although the documented application boundary is 10. This frozen
result is retained unchanged and was not used as training data.

Candidate v4 added account-only attack examples to Train/Validation and fixed a generator defect
where an intentionally empty account was replaced by a default username. After the model and
threshold were locked, the newly generated Challenge V4 was hashed and evaluated once. It contains
500 sessions and 4,800 events and achieved 96.06% accuracy, 96.29% recall, 94.29% F2 and 4.00%
FPR (TN 3,600, FP 150, FN 39, TP 1,011). It correctly handled all account-only attacks, true
sub-threshold application bursts, staggered application denials and missing-context benign cases.
Remaining errors are concentrated in independent-user background failures (150 FP) and IP-only
authentication attacks (39 FN). Challenge V4 is frozen and must never be used for retraining,
threshold selection or feature selection. These are synthetic robustness results, not production
accuracy.

## SecuraAI end-to-end persistence verification (2026-11-03)

The demo Backend image and durable Docker worker were rebuilt from the current shadow-inference
source and configured to call the host candidate-v4 service. A stale worker image had previously
claimed some detection jobs without writing ML shadow evidence. After aligning both workers, a new
15-run Wazuh benchmark delivered 101 events through Wazuh, Backend and PostgreSQL. All 101 events
produced detections, all 101 stored an `ml_shadow_prediction`, and all 101 referenced
`securaai-temporal-synthetic-candidate-v4`; no benchmark jobs remained pending. The boundary labels
again produced TN 74, FP 0, FN 0 and TP 27. This verifies integration and persistence coverage only,
not production accuracy. Shadow contribution remains zero and the existing SecuraAI detection
engine remains solely responsible for alerts.

## Controlled real Windows authentication run (2026-11-03)

The Windows 11 lab host generated six genuine Security Event ID 4625 records through failed SMB
network authentication (Logon Type 3, NTLM) against its own address. Each attempt used a distinct,
deliberately nonexistent account, so no real account was modified or exposed to lockout. Wazuh
Agent 002 collected the events and Wazuh correlated the sequence as rule 60204, `Multiple Windows
Logon Failures`. All six events were ingested, detected and scored by candidate v4 in shadow mode.

An initial run exposed that Backend ML context was scoped only by account, causing a same-IP
password spray across different accounts to appear as isolated failures. The ML-only context query
was corrected to include events sharing either the account or source IP, without changing the
existing alert engine. On a new six-event run using source `192.168.1.63`, events 1–4 were BENIGN
and events 5–6 were MALICIOUS_APT (scores 0.834 and 0.863), yielding TN 4, FP 0, FN 0 and TP 2.
This is a controlled real-telemetry boundary test, not a production accuracy estimate, and remains
external-test-only rather than training data.

## Hybrid controlled-lab candidate v5 (2026-11-03)

A second controlled collection produced 30 independent real Windows sessions and 133 Security
authentication events. Session membership and the 60/20/20 split were fixed in the manifest before
model evaluation: 18 Train sessions (79 events), 6 Validation sessions (29 events), and 6 locked
Test sessions (25 events). No session crosses splits. The collection contains benign one-to-four
failure sessions and five-to-eight-event password-spray sessions; only the fifth and subsequent
events in malicious sessions are positive. Wazuh correlation rule 60204 events are retained as
login-failure evidence rather than incorrectly discarded by a rule-60122-only filter.

Candidate v5 trains on synthetic Train plus controlled-real Train, selects its model and threshold
using synthetic plus controlled-real Validation, and opens the real Test only for the final report.
The locked real-lab Test produced TN 17, FP 0, FN 0 and TP 8. A subsequent six-event live run, not
part of that dataset, classified events 1–4 as BENIGN and events 5–6 as MALICIOUS_APT with scores
0.949 and 0.967. The artifact is `securaai-temporal-hybrid-lab-candidate-v5`, remains experimental
and shadow-only, and these small controlled runs do not estimate production accuracy.

## SecuraAI AUTH, VPN/SSO and APP_ACCESS shadow benchmark (2026-11-03)

A new end-to-end benchmark sent 15 isolated runs (101 events) through the Wazuh integration,
SecuraAI Backend, PostgreSQL and the live candidate-v5 API. Every run used a unique source IP so
the five-minute temporal context represented the declared session. The evaluator read the actual
`ml_shadow_prediction` stored by SecuraAI rather than re-running the model offline. It covered
normal traffic plus AUTH and VPN bursts of 2, 4, 5, 6 and 10 events, and APP_ACCESS denial bursts
of 8, 10, 11 and 15 events. The locked operational boundaries were the fifth AUTH/VPN failure and
the tenth application denial. Results were TN 74, FP 0, FN 0 and TP 27.

A deliberately non-isolated run reused one source IP across otherwise separate accounts. SecuraAI
correctly accumulated those events as a possible password-spray sequence; treating each run as an
independent benign session produced 144 apparent false positives. This demonstrates that evaluation
must preserve identity and temporal semantics. These are controlled simulated VPN/application logs,
not telemetry exported from a real VPN, SSO provider or production application.

## Temporal candidate v6 model selection (2026-11-03)

Candidate v6 aligns the deployable temporal experiment with the lecturer's methodology. Seven
algorithms (Decision Tree, Complement Naive Bayes, Bagging, Random Forest, AdaBoost, Linear SVM and
Logistic Regression) use the same features and are tuned by five-fold `StratifiedGroupKFold` on
Train, grouping complete `scenario_id` sessions. A weighted Soft Voting candidate is built from the
probabilistic components using Train-CV F2 weights. Validation alone selects the candidate and locks
its threshold; Test is opened only afterward.

Bagging was selected: Train-CV F2 `1.000 ± 0.000`, Validation TN 3,970 / FP 0 / FN 0 / TP 912,
and locked Test TN 4,141 / FP 0 / FN 0 / TP 874 at threshold 0.5. The controlled-real Windows Test
subset remained TN 17 / FP 0 / FN 0 / TP 8. These perfect controlled results reflect rule-defined
scenario boundaries and must not be presented as production accuracy. LLM fusion and ML-driven alert
creation remain explicitly out of scope until model validation is finished.

The exported v6 artifact was then exercised through the live SecuraAI shadow pipeline using 15 new,
isolated AUTH, VPN/SSO and APP_ACCESS runs (101 events). The predictions persisted by Backend were
TN 74 / FP 0 / FN 0 / TP 27 and all referenced candidate v6. This verifies the selected artifact's
integration behavior in the controlled lab; it does not change the production-accuracy limitation.

## Multi-window candidate v7 (historical)

Candidate v7 extended the temporal representation beyond the five-minute window. It introduced
past-only counters for 1, 15 and 60 minutes while retaining the detailed five-minute counters.
The purpose was to detect both short bursts and low-and-slow sequences without turning a window
count into a fixed global attack rule. The artifact is retained under
`artifacts-temporal-multiwindow-candidate/` for reproducibility and is not the latest candidate.

## Temporal candidate v8 — current experimental artifact (2026-11-10)

Candidate v8 is stored in `artifacts-temporal-1m5m15m60m-candidate/` with model version
`securaai-temporal-1m5m15m60m-lab-candidate-v8`. It combines three controlled origins:

- SecuraAI Authentication, VPN/SSO and Application Access scenarios;
- controlled real Windows authentication lab sessions;
- controlled multi-window scenarios.

Every candidate uses the same temporal feature contract. Seven individual algorithms—Decision
Tree, Complement Naive Bayes, Bagging, Random Forest, AdaBoost, Linear SVM and Logistic
Regression—are tuned by five-fold `StratifiedGroupKFold` on Train. Weighted Soft Voting is also
evaluated. Validation selects the model and threshold; Test remains locked until selection.

Bagging was selected. The locked threshold and escalation threshold are both `0.5`. The controlled
Validation result was TN 4,223 / FP 0 / FN 0 / TP 1,096; the controlled Test result was TN 4,404 /
FP 0 / FN 0 / TP 1,061. The controlled-real Test subset was TN 17 / FP 0 / FN 0 / TP 8.

These perfect values reflect controlled scenario/manifest boundaries and are **not production
accuracy**. They do not prove performance on unseen organizations, arbitrary Wazuh rules, malware,
ransomware, Linux or general network attacks. Candidate v8 requires the Backend to provide correct
past-only 1/5/15/60-minute context. It is not approved as standalone evidence for automatic alert
creation.

## RADAR family-held-out and SILRAD transfer findings (2026-11-03)

A separate endpoint-ransomware candidate was trained on RADAR raw Sysmon with complete ransomware
families held out by split. Training used CyberVolk, LockBit, Lynx and Meow; validation used
Medusa; Test contained only Akira and BlackBasta. The locked Decision Tree achieved 96.03%
accuracy and 89.76% recall on that RADAR Test (TN 60,452, FP 0, FN 3,915, TP 34,312).

Strict transfer to SILRAD's 156,841-row author test split failed: 12.45% accuracy, 50% balanced
accuracy, TN 0, FP 137,312, FN 0, TP 19,529. SILRAD publishes FastText-transformed features, so
only `event.code` could be mapped honestly to the raw Wazuh contract. This failure demonstrates
schema/domain shift and prohibits presenting the RADAR metric as cross-dataset performance.
