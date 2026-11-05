"""Generate the lecturer-style SecuraAI notebook suite."""
from __future__ import annotations

import json, hashlib
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "notebooks"


def md(text: str) -> dict:
    return {"cell_type": "markdown", "id": hashlib.sha1(("md:" + text).encode()).hexdigest()[:12],
            "metadata": {}, "source": text.splitlines(keepends=True)}


def code(text: str) -> dict:
    return {"cell_type": "code", "id": hashlib.sha1(("code:" + text).encode()).hexdigest()[:12],
            "execution_count": None, "metadata": {}, "outputs": [],
            "source": text.splitlines(keepends=True)}


def notebook(cells: list[dict]) -> dict:
    return {
        "cells": cells,
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3.11+"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }


COMBINED_UPDATE = [
    md("""## Cập nhật pipeline dữ liệu hợp nhất

Notebook này thuộc bộ thí nghiệm SecuraAI mới. Có hai tầng kết quả cần phân biệt:

- **Thí nghiệm giảng dạy 00–10:** so sánh thuật toán trên cùng split Windows-APT để bảo đảm công bằng.
- **Baseline hợp nhất theo từng event:** Windows-APT 2025 + RADAR + log Wazuh đã bộc lộ domain shift khi test trực tiếp.
- **Ứng viên temporal:** dùng `event_family`, `event_type` và thống kê cửa sổ 5 phút; vẫn chỉ chạy shadow.

RADAR bổ sung ground truth ransomware/Sysmon theo từng mẫu thực thi. Log Wazuh hiện tại chỉ là kiểm thử lab và weak-benign; không được trình bày như bằng chứng production. Test, threshold và dữ liệu ngoài miền được giữ tách biệt để giảm leakage."""),
    code("""import pandas as pd

combined_artifact_dir = ROOT / 'artifacts-combined-candidate'
combined_metadata_path = combined_artifact_dir / 'model_metadata.json'
combined_source_report_path = ROOT / 'reports' / 'combined_candidate_by_source.json'
temporal_artifact_dir = ROOT / 'artifacts-temporal-candidate'
temporal_metadata_path = temporal_artifact_dir / 'model_metadata.json'

if combined_metadata_path.exists():
    combined_metadata = json.loads(combined_metadata_path.read_text(encoding='utf-8'))
    display(pd.DataFrame({
        'value': [
            combined_metadata['selectedModel'],
            combined_metadata['lockedThreshold'],
            ', '.join(combined_metadata['datasets']),
            combined_metadata['test']['f2'],
            combined_metadata['test']['precision'],
            combined_metadata['test']['recall'],
        ]
    }, index=['selected_model','locked_threshold','datasets','combined_test_f2','combined_test_precision','combined_test_recall']))
else:
    print('Chưa có artifacts-combined-candidate. Chạy scripts/train_combined_candidate.py trước.')

if temporal_metadata_path.exists():
    temporal_metadata = json.loads(temporal_metadata_path.read_text(encoding='utf-8'))
    display(pd.DataFrame({
        'value': [
            temporal_metadata['selectedModel'], temporal_metadata['lockedThreshold'],
            temporal_metadata['validation']['f2'], temporal_metadata['test']['f2'],
            temporal_metadata['test']['falsePositiveRate'], temporal_metadata['status'],
        ]
    }, index=['temporal_model','temporal_threshold','validation_f2','test_f2','test_fpr','status']))
else:
    print('Chưa có artifacts-temporal-candidate. Chạy scripts/train_temporal_candidate.py trước.')
"""),
]


def add_combined_update(book: dict) -> dict:
    """Append the current deployable-candidate context to every teaching notebook."""
    book["cells"].extend(COMBINED_UPDATE)
    return book


SETUP = """from pathlib import Path
import json, hashlib
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import platform, sklearn
import importlib
from IPython.display import display
from sklearn.base import clone
from sklearn.metrics import (ConfusionMatrixDisplay, RocCurveDisplay, PrecisionRecallDisplay,
    accuracy_score, precision_score, recall_score, f1_score, fbeta_score, roc_auc_score,
    average_precision_score, confusion_matrix, make_scorer)
from sklearn.model_selection import GridSearchCV, StratifiedGroupKFold
from sklearn.dummy import DummyClassifier
from securaai_ml.data import load_training_data
import securaai_ml.modeling as modeling_module
importlib.reload(modeling_module)  # tránh module cache cũ khi source vừa được cập nhật
from securaai_ml.modeling import (candidate_factories, decision_scores, parameter_grids,
    teaching_candidate_factories, teaching_parameter_grids)
from securaai_ml.schema import MODEL_FEATURES, TARGET_COLUMN, GROUP_COLUMN
from securaai_ml.train import temporal_train_validation_test

ROOT = Path.cwd().parent if Path.cwd().name == 'notebooks' else Path.cwd()
data, audit = load_training_data(ROOT / 'data' / 'raw')
train, validation, test = temporal_train_validation_test(data)
X_train, y_train = train.loc[:, MODEL_FEATURES], train[TARGET_COLUMN]
X_validation, y_validation = validation.loc[:, MODEL_FEATURES], validation[TARGET_COLUMN]
groups = train[GROUP_COLUMN]
cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
audit"""


def algorithm_notebook(number: str, title: str, key: str, explanation: str) -> dict:
    training = f"""model_name = '{key}'
search = GridSearchCV(
    teaching_candidate_factories(42)[model_name](),
    teaching_parameter_grids()[model_name],
    scoring={{'f2': make_scorer(fbeta_score, beta=2, zero_division=0),
             'f1': 'f1', 'roc_auc': 'roc_auc', 'average_precision': 'average_precision'}},
    refit='f2',
    cv=cv, n_jobs=1, return_train_score=True,
)
search.fit(X_train, y_train, groups=groups)
print('Best parameters:', search.best_params_)
print('Mean CV F2:', search.best_score_)
model = search.best_estimator_"""
    evaluation = """pred = model.predict(X_validation)
score = decision_scores(model, X_validation)
result = pd.Series({
    'accuracy': accuracy_score(y_validation, pred),
    'precision': precision_score(y_validation, pred, zero_division=0),
    'recall': recall_score(y_validation, pred, zero_division=0),
    'f1': f1_score(y_validation, pred, zero_division=0),
    'f2': fbeta_score(y_validation, pred, beta=2, zero_division=0),
    'roc_auc': roc_auc_score(y_validation, score),
    'average_precision': average_precision_score(y_validation, score),
})
display(result.to_frame('Validation'))
tn, fp, fn, tp = confusion_matrix(y_validation, pred, labels=[0, 1]).ravel()
fpr_at_threshold = fp / (fp + tn)
tpr_at_threshold = tp / (tp + fn)
fig, axes = plt.subplots(1, 3, figsize=(17, 4.8))
ConfusionMatrixDisplay.from_predictions(y_validation, pred, display_labels=['BENIGN','MALICIOUS_APT'], ax=axes[0])
axes[0].set_title('Validation — Confusion Matrix')
RocCurveDisplay.from_predictions(y_validation, score, name=model_name.replace('_', ' ').title(), ax=axes[1])
axes[1].plot([0, 1], [0, 1], '--', color='gray', label='Random')
axes[1].scatter([fpr_at_threshold], [tpr_at_threshold], color='darkorange', zorder=5, label='Decision threshold')
axes[1].set_title('ROC — VALIDATION'); axes[1].legend()
PrecisionRecallDisplay.from_predictions(y_validation, score, name=model_name.replace('_', ' ').title(), ax=axes[2])
base_rate = float(y_validation.mean())
axes[2].axhline(base_rate, ls='--', color='gray', label=f'Positive rate={base_rate:.3f}')
axes[2].set_title('Precision–Recall — VALIDATION'); axes[2].legend()
plt.tight_layout(); plt.show()"""
    mechanism_visual = []
    diagnostic = []
    if key == "decision_tree":
        mechanism_visual = [
            code("import matplotlib.pyplot as plt"),
            code("# Sơ đồ minh họa cơ chế chia nhánh; chưa phải cây đã học từ dataset.\nfig, ax = plt.subplots(figsize=(12, 6))\nax.axis('off')\nnodes = {\n    'root': (0.50, 0.88, 'process_name = cmd.exe?'),\n    'left': (0.25, 0.58, 'has_command_line = 1?'),\n    'right': (0.75, 0.58, 'event_id đáng chú ý?'),\n    'll': (0.12, 0.23, 'MALICIOUS_APT'),\n    'lr': (0.38, 0.23, 'BENIGN'),\n    'rl': (0.62, 0.23, 'MALICIOUS_APT'),\n    'rr': (0.88, 0.23, 'BENIGN'),\n}\nfor key_name, (x, y, label) in nodes.items():\n    leaf = key_name in {'ll','lr','rl','rr'}\n    color = '#e76f51' if label == 'MALICIOUS_APT' else ('#2a9d8f' if label == 'BENIGN' else '#d9eaf0')\n    ax.text(x, y, label, ha='center', va='center', fontsize=11,\n            bbox=dict(boxstyle='round,pad=0.55', facecolor=color, edgecolor='#264653'))\nfor parent, child, branch in [('root','left','Có'),('root','right','Không'),('left','ll','Có'),('left','lr','Không'),('right','rl','Có'),('right','rr','Không')]:\n    x1,y1,_=nodes[parent]; x2,y2,_=nodes[child]\n    ax.annotate('', xy=(x2,y2+0.055), xytext=(x1,y1-0.055), arrowprops=dict(arrowstyle='->',lw=1.5,color='#555'))\n    ax.text((x1+x2)/2,(y1+y2)/2,branch,fontsize=9,ha='center',backgroundcolor='white')\nax.set_title('Minh họa cơ chế Decision Tree (không phải luật thật của model)', fontsize=14)\nplt.show()"),
            md("**Cách đọc:** bắt đầu từ nút trên cùng, kiểm tra điều kiện rồi đi theo nhánh Có/Không cho đến nút lá. Sau khi mô hình được huấn luyện, mục 9 sẽ hiển thị cây thật và các feature mà model thực sự sử dụng."),
        ]
        diagnostic = [
            md("## 9. Trực quan cây và diễn giải\nChỉ vẽ ba tầng đầu để đọc được; cây đầy đủ vẫn được giữ trong model."),
            code("from sklearn.tree import plot_tree, export_text\npre=model.named_steps['preprocess']\ntree=model.named_steps['model']\nfeature_names=pre.get_feature_names_out()\nplt.figure(figsize=(22,9))\nplot_tree(tree,max_depth=3,feature_names=feature_names,class_names=['BENIGN','MALICIOUS_APT'],filled=True,rounded=True,fontsize=7)\nplt.title('Decision Tree — ba tầng đầu'); plt.show()\nprint(export_text(tree,feature_names=list(feature_names),max_depth=3))"),
        ]
    return notebook([
        md(f"# {number} — {title}\nNotebook thực nghiệm độc lập cho SecuraAI / Windows-APT 2025. Mọi lựa chọn được khóa bằng Train/Validation trước khi đánh giá Test."),
        md("## 0. Chuẩn bị môi trường\nChạy từ thư mục project hoặc thư mục `notebooks`. Không cần GPU."),
        code(SETUP),
        md("### Tính tái lập\nCố định seed và in phiên bản. Đổi seed là một thí nghiệm mới, không chọn seed bằng kết quả Test."),
        code("import platform\nimport numpy as np\nimport matplotlib.pyplot as plt\nimport sklearn\n\nSEED=42\nnp.random.seed(SEED)\nplt.rcParams.update({'figure.dpi':110,'font.family':'DejaVu Sans','font.size':10})\nprint('Python:',platform.python_version(),'| sklearn:',sklearn.__version__,'| seed:',SEED)"),
        md("## 1. Xác thực dữ liệu và ý nghĩa nhãn\nNhãn MALICIOUS_APT được suy ra từ MITRE/Wazuh tag, không phải ground truth do chuyên gia xét duyệt. Các cột tạo nhãn bị loại khỏi đầu vào."),
        code("display(pd.Series(audit.__dict__,name='value').to_frame())\nassert audit.rows==len(data)\nassert data[TARGET_COLUMN].nunique()==2\nassert data[GROUP_COLUMN].ne('unknown-date').all()\nprint('Dataset checks passed')"),
        md("## 2. Chia Train/Validation/Test và dấu vân tay\nChia xấp xỉ 60/20/20 theo ngày; không có ngày nào xuất hiện ở hai tập."),
        code("split_table=pd.DataFrame([{'set':name,'rows':len(part),'benign':int((part[TARGET_COLUMN]==0).sum()),'malicious':int((part[TARGET_COLUMN]==1).sum()),'attack_rate':float(part[TARGET_COLUMN].mean()),'dates':part[GROUP_COLUMN].nunique()} for name,part in [('Train',train),('Validation',validation),('Test',test)]])\ndisplay(split_table)\nassert set(train[GROUP_COLUMN]).isdisjoint(validation[GROUP_COLUMN])\nassert set(train[GROUP_COLUMN]).isdisjoint(test[GROUP_COLUMN])\nassert set(validation[GROUP_COLUMN]).isdisjoint(test[GROUP_COLUMN])\nsplit_hash=hashlib.sha256(json.dumps({'train':sorted(train[GROUP_COLUMN].unique()),'validation':sorted(validation[GROUP_COLUMN].unique()),'test':sorted(test[GROUP_COLUMN].unique())},sort_keys=True).encode()).hexdigest()\nprint('Split hash:',split_hash[:16])"),
        md("## 3. EDA chỉ trên Train\nQuan sát mất cân bằng và tỷ lệ tấn công theo nhóm sự kiện mà không dùng Test để định hướng mô hình."),
        code("fig,ax=plt.subplots(1,2,figsize=(13,4))\ntrain[TARGET_COLUMN].map({0:'BENIGN',1:'MALICIOUS_APT'}).value_counts().plot.bar(ax=ax[0],rot=0,color=['#9bb5c5','#087f8c']); ax[0].set_title('Phân bố nhãn — TRAIN'); ax[0].set_ylabel('Số log')\nprovider_rate=train.groupby('provider')[TARGET_COLUMN].agg(['count','mean']).query('count >= 100').sort_values('count',ascending=False).head(12)\nprovider_rate['mean'].plot.bar(ax=ax[1],color='#087f8c'); ax[1].set_title('Tỷ lệ tấn công theo provider — TRAIN'); ax[1].set_ylabel('Tỷ lệ MALICIOUS_APT')\nplt.tight_layout(); plt.show(); display(provider_rate)"),
        md("## 4. Cơ chế thuật toán và phạm vi triển khai\n" + explanation),
        *mechanism_visual,
        md("## 5. Tiền xử lý an toàn trong Pipeline\nOne-Hot Encoder được fit bên trong từng fold. Không fit preprocessing trên toàn bộ dữ liệu trước CV."),
        code("from sklearn import set_config\nfrom IPython.display import display\n\nset_config(display='diagram')\ncandidate=teaching_candidate_factories(SEED)['" + key + "']()\ngrid=teaching_parameter_grids()['" + key + "']\n\n# Trong Jupyter, object Pipeline cuối cell được render thành sơ đồ HTML có thể mở rộng.\ndisplay(candidate)\n\ngrid_table=pd.DataFrame([\n    {'hyperparameter':name, 'candidate_values':str(values), 'purpose':(\n        'Giới hạn độ sâu, kiểm soát độ phức tạp' if 'max_depth' in name else\n        'Số mẫu tối thiểu ở mỗi lá, hạn chế overfit' if 'min_samples_leaf' in name else\n        'Giá trị được Grid Search thử nghiệm')}\n    for name,values in grid.items()\n])\ndisplay(grid_table)"),
        md("## 6. Độ đo và Dummy baseline\nAccuracy có thể gây hiểu nhầm. F2 nhấn mạnh Recall; ROC-AUC đo xếp hạng; AP hữu ích khi mất cân bằng."),
        code("dummy=DummyClassifier(strategy='prior').fit(X_train,y_train)\ndummy_pred=dummy.predict(X_validation); dummy_score=dummy.predict_proba(X_validation)[:,1]\ndisplay(pd.Series({'accuracy':accuracy_score(y_validation,dummy_pred),'precision':precision_score(y_validation,dummy_pred,zero_division=0),'recall':recall_score(y_validation,dummy_pred,zero_division=0),'f1':f1_score(y_validation,dummy_pred,zero_division=0),'f2':fbeta_score(y_validation,dummy_pred,beta=2,zero_division=0),'roc_auc':roc_auc_score(y_validation,dummy_score),'average_precision':average_precision_score(y_validation,dummy_score)},name='Dummy — Validation').to_frame())"),
        md("## 7. Chọn siêu tham số bằng 5-Fold chỉ trên Train\nGrid Search chấm F2, F1, ROC-AUC và AP; `refit='f2'` khóa tiêu chí lựa chọn trước khi xem Test."),
        code(training),
        code("cv_table=pd.DataFrame(search.cv_results_).sort_values('rank_test_f2')\ndisplay(cv_table[['params','mean_train_f2','mean_test_f2','std_test_f2','mean_test_roc_auc','mean_test_average_precision']].head(12))"),
        md("## 8. Đánh giá trên Validation\nConfusion Matrix cho biết TN/FP/FN/TP. ROC và PR phải dùng score liên tục, không dùng nhãn 0/1 đã cắt."),
        code(evaluation),
        *diagnostic,
        md("## 10. Chọn và khóa ngưỡng trên Validation\nVới score rời rạc, thử toàn bộ giá trị duy nhất; với score liên tục, thử các phân vị. Luôn bổ sung ngưỡng mặc định rồi chọn F2 cao nhất. Không điều chỉnh lại sau khi xem Test."),
        code("validation_score=decision_scores(model,X_validation)\nunique_scores=np.unique(validation_score)\ndefault_threshold=0.5 if hasattr(model,'predict_proba') else 0.0\nif len(unique_scores)<=1000:\n    threshold_grid=unique_scores\n    grid_strategy='all unique scores'\nelse:\n    threshold_grid=np.unique(np.quantile(validation_score,np.linspace(0.001,0.999,999)))\n    grid_strategy='score quantiles'\nthreshold_grid=np.unique(np.append(threshold_grid,default_threshold))\nprint(f'Score levels: {len(unique_scores):,} | strategy: {grid_strategy} | default: {default_threshold}')\nthreshold_rows=[]\nfor threshold in threshold_grid:\n    p=(validation_score>=threshold).astype(int)\n    threshold_rows.append({'threshold':float(threshold),'precision':precision_score(y_validation,p,zero_division=0),'recall':recall_score(y_validation,p,zero_division=0),'f1':f1_score(y_validation,p,zero_division=0),'f2':fbeta_score(y_validation,p,beta=2,zero_division=0)})\nthreshold_table=pd.DataFrame(threshold_rows).sort_values('threshold')\nchosen=threshold_table.sort_values(['f2','recall','precision'],ascending=False).iloc[0]\nlocked_threshold=float(chosen.threshold)\ndisplay(threshold_table.sort_values('f2',ascending=False).head(10))\nthreshold_table.plot(x='threshold',y=['precision','recall','f1','f2'],figsize=(11,5)); plt.axvline(locked_threshold,color='black',ls='--',label=f'locked={locked_threshold:.4g}'); plt.legend(); plt.show()"),
        md("## 11. Đánh giá Test đúng một lần\nSiêu tham số và ngưỡng đã khóa. Kết quả Test chỉ dùng báo cáo cuối, không quay lại sửa thiết kế."),
        code("X_test,y_test=test.loc[:,MODEL_FEATURES],test[TARGET_COLUMN]\ntest_score=decision_scores(model,X_test)\ntest_pred=(test_score>=locked_threshold).astype(int)\ntest_result=pd.Series({'accuracy':accuracy_score(y_test,test_pred),'precision':precision_score(y_test,test_pred,zero_division=0),'recall':recall_score(y_test,test_pred,zero_division=0),'f1':f1_score(y_test,test_pred,zero_division=0),'f2':fbeta_score(y_test,test_pred,beta=2,zero_division=0),'roc_auc':roc_auc_score(y_test,test_score),'average_precision':average_precision_score(y_test,test_score)})\ndisplay(test_result.to_frame('TEST'))\ntn,fp,fn,tp=confusion_matrix(y_test,test_pred,labels=[0,1]).ravel()\nfig,axes=plt.subplots(1,3,figsize=(17,4.8))\nConfusionMatrixDisplay.from_predictions(y_test,test_pred,display_labels=['BENIGN','MALICIOUS_APT'],ax=axes[0]); axes[0].set_title(f'TEST — locked threshold {locked_threshold:.4g}')\nRocCurveDisplay.from_predictions(y_test,test_score,name=f\"AUC={test_result['roc_auc']:.3f}\",ax=axes[1]); axes[1].plot([0,1],[0,1],'--',color='gray'); axes[1].scatter([fp/(fp+tn)],[tp/(tp+fn)],color='darkorange',zorder=5,label='Locked threshold'); axes[1].set_title('ROC — TEST'); axes[1].legend()\nPrecisionRecallDisplay.from_predictions(y_test,test_score,name=f\"AP={test_result['average_precision']:.3f}\",ax=axes[2]); axes[2].axhline(float(y_test.mean()),ls='--',color='gray',label=f'Attack rate={y_test.mean():.3f}'); axes[2].set_title('Precision–Recall — TEST'); axes[2].legend(); plt.tight_layout(); plt.show()"),
        md("## 12. Khoảng bất định bằng bootstrap\nBootstrap trên Test chỉ để mô tả độ bất định, không huấn luyện hoặc chọn ngưỡng lại."),
        code("rng=np.random.default_rng(SEED); boot=[]\ny_array=y_test.to_numpy()\nfor _ in range(300):\n    idx=rng.integers(0,len(y_array),len(y_array))\n    if np.unique(y_array[idx]).size<2: continue\n    boot.append({'f2':fbeta_score(y_array[idx],test_pred[idx],beta=2,zero_division=0),'roc_auc':roc_auc_score(y_array[idx],test_score[idx]),'average_precision':average_precision_score(y_array[idx],test_score[idx])})\nboot=pd.DataFrame(boot)\ndisplay(pd.DataFrame({'estimate':test_result[['f2','roc_auc','average_precision']], 'ci_2.5%':boot.quantile(.025), 'ci_97.5%':boot.quantile(.975)}))"),
        md("## 13. Lưu kết quả thực nghiệm\nLưu model, ngưỡng, split hash và metric để notebook so sánh tổng hợp có thể kiểm tra nguồn gốc."),
        code("experiment_dir=ROOT/'reports'/'notebook_experiments'; experiment_dir.mkdir(parents=True,exist_ok=True)\nslug='" + number + "_" + key + "'\njoblib.dump(model,experiment_dir/f'{slug}.joblib')\nvalidation_locked_pred=(validation_score>=locked_threshold).astype(int)\nvalidation_locked=pd.Series({'accuracy':accuracy_score(y_validation,validation_locked_pred),'precision':precision_score(y_validation,validation_locked_pred,zero_division=0),'recall':recall_score(y_validation,validation_locked_pred,zero_division=0),'f1':f1_score(y_validation,validation_locked_pred,zero_division=0),'f2':fbeta_score(y_validation,validation_locked_pred,beta=2,zero_division=0),'roc_auc':roc_auc_score(y_validation,validation_score),'average_precision':average_precision_score(y_validation,validation_score)})\nrecord={'schema_version':2,'model':model_name,'best_params':search.best_params_,'cv_best_f2':float(search.best_score_),'locked_threshold':locked_threshold,'split_hash':split_hash,'validation_default_threshold':{k:float(v) for k,v in result.items()},'validation_locked_threshold':{k:float(v) for k,v in validation_locked.items()},'test_locked_threshold':{k:float(v) for k,v in test_result.items()}}\n(experiment_dir/f'{slug}.json').write_text(json.dumps(record,indent=2),encoding='utf-8')\nrecord"),
        md("## 14. Kết luận\nSo sánh chính thức ở `08_Lua_Chon_Mo_Hinh_Va_Bao_Cao.ipynb`. Giới hạn: nhãn rule-derived, dữ liệu mô phỏng Windows APT và chưa phải bằng chứng hiệu năng production."),
    ])


notebooks = {
    "00_Data_EDA_Preprocessing.ipynb": notebook([
        md("# 00 — EDA và tiền xử lý dữ liệu SecuraAI\nKiểm tra Windows-APT 2025 trước khi huấn luyện và giải thích lựa chọn feature."),
        code(SETUP),
        md("## 1. Kích thước và phân bố nhãn"),
        code("labels = data[TARGET_COLUMN].map({0:'BENIGN',1:'MALICIOUS_APT'})\ndisplay(labels.value_counts().to_frame('rows'))\nlabels.value_counts().plot.bar(rot=0, title='Label distribution'); plt.show()"),
        md("## 2. Phân bố theo thời gian"),
        code("daily = data.groupby([GROUP_COLUMN,TARGET_COLUMN]).size().unstack(fill_value=0)\ndisplay(daily)\ndaily.plot(figsize=(13,5), title='Events by collection date'); plt.show()"),
        md("## 3. Chia 60/20/20 theo thời gian\nGiữ nguyên nhóm ngày để giảm leakage giữa các phiên thu thập liên quan."),
        code("splits=pd.DataFrame({'rows':[len(train),len(validation),len(test)]},index=['Train','Validation','Test']); splits['ratio']=splits.rows/len(data); splits"),
        md("## 4. Feature engineering\nDùng event/provider/channel/severity, basename tiến trình, protocol/status, giờ/ngày, after-hours, cờ IP private/present, port và cờ tồn tại command/hash. Không dùng dữ liệu tiết lộ trực tiếp nhãn."),
        code("display(pd.Series(MODEL_FEATURES, name='model_feature').to_frame())\nprint('Missing values after canonical feature building:', int(data.loc[:, MODEL_FEATURES].isna().sum().sum()))"),
        md("## 5. Giảm chiều\nKhông dùng PCA: dữ liệu phần lớn categorical sparse và feature đã chọn theo ngữ nghĩa bảo mật. OneHotEncoder dùng `min_frequency=2` để hạn chế category hiếm."),
    ]),
    "01_Decision_Tree.ipynb": algorithm_notebook("01", "Decision Tree", "decision_tree", "Cây chia dữ liệu theo điều kiện feature. Dễ giải thích nhưng dễ overfit; tuning `max_depth` và `min_samples_leaf`."),
    "02_Naive_Bayes.ipynb": algorithm_notebook("02", "Complement Naive Bayes", "naive_bayes", "Mô hình xác suất với giả định feature độc lập có điều kiện. ComplementNB phù hợp ma trận One-Hot không âm; tuning hệ số làm trơn `alpha`."),
    "04_Bagging.ipynb": algorithm_notebook("04", "Bagging", "bagging", "Huấn luyện nhiều cây trên các bootstrap sample rồi bỏ phiếu để giảm phương sai so với một cây đơn. Tuning số cây và tỷ lệ mẫu mỗi cây."),
    "05_Random_Forest.ipynb": algorithm_notebook("05", "Random Forest", "random_forest", "Bagging nhiều cây trên các mẫu/feature ngẫu nhiên để giảm phương sai. Tuning số cây, độ sâu và kích thước lá."),
    "06_AdaBoost.ipynb": algorithm_notebook("06", "AdaBoost", "adaboost", "Huấn luyện tuần tự các cây yếu, tăng trọng số cho mẫu bị phân loại sai. Tuning số estimator và learning rate."),
    "09_Linear_SVM_Extra.ipynb": algorithm_notebook("09", "Linear SVM — mở rộng SecuraAI", "linear_svm", "Tìm siêu phẳng có biên phân cách lớn trong không gian One-Hot thưa. Đây là mô hình mở rộng phù hợp log bảo mật, không thuộc chuỗi 01–08 của demo giảng viên."),
    "10_Logistic_Regression_Extra.ipynb": algorithm_notebook("10", "Logistic Regression — mở rộng SecuraAI", "logistic_regression", "Mô hình tuyến tính mạnh, ổn định và dễ triển khai. Đây là phần mở rộng ngoài chuỗi demo chính."),
}

notebooks["03_Rule_Based.ipynb"] = notebook([
    md("# 03 — Rule-Based baseline\nBaseline luật minh bạch để so sánh với mô hình học máy. Đây không phải mô hình được train và không được trình bày như AI."),
    code(SETUP),
    md("## 1. Luật chỉ dùng feature hợp lệ\nCộng điểm khi có command line, parent command, hash, target file, IP nguồn hoặc event status bất thường. Không dùng MITRE tag/Wazuh rule tạo nhãn."),
    code("def rule_score(frame):\n    return (2*frame['has_command_line'] + frame['has_parent_command_line'] + 2*frame['has_hashes'] + frame['has_target_file'] + frame['has_source_ip'] + frame['event_status'].isin(['failure','failed','denied']).astype(int)).to_numpy(dtype=float)\nvalidation_score=rule_score(X_validation)\nvalidation_score[:10]"),
    md("## 2. Chọn ngưỡng trên Validation"),
    code("rows=[]\nfor threshold in np.arange(1,8):\n    pred=(validation_score>=threshold).astype(int)\n    rows.append({'threshold':threshold,'precision':precision_score(y_validation,pred,zero_division=0),'recall':recall_score(y_validation,pred,zero_division=0),'f1':f1_score(y_validation,pred,zero_division=0),'f2':fbeta_score(y_validation,pred,beta=2,zero_division=0)})\nthreshold_table=pd.DataFrame(rows); display(threshold_table)\nlocked_threshold=int(threshold_table.sort_values(['f2','recall'],ascending=False).iloc[0].threshold)\nprint('Locked threshold:',locked_threshold)"),
    md("## 3. Test sau khi khóa luật/ngưỡng"),
    code("X_test,y_test=test.loc[:,MODEL_FEATURES],test[TARGET_COLUMN]\ntest_score=rule_score(X_test); test_pred=(test_score>=locked_threshold).astype(int)\nresult=pd.Series({'accuracy':accuracy_score(y_test,test_pred),'precision':precision_score(y_test,test_pred,zero_division=0),'recall':recall_score(y_test,test_pred,zero_division=0),'f1':f1_score(y_test,test_pred,zero_division=0),'f2':fbeta_score(y_test,test_pred,beta=2,zero_division=0),'roc_auc':roc_auc_score(y_test,test_score),'average_precision':average_precision_score(y_test,test_score)})\ndisplay(result.to_frame('TEST'))\ntn,fp,fn,tp=confusion_matrix(y_test,test_pred,labels=[0,1]).ravel()\nfig,axes=plt.subplots(1,3,figsize=(17,4.8))\nConfusionMatrixDisplay.from_predictions(y_test,test_pred,display_labels=['BENIGN','MALICIOUS_APT'],ax=axes[0]); axes[0].set_title(f'TEST — Rule threshold {locked_threshold}')\nRocCurveDisplay.from_predictions(y_test,test_score,name=f\"Rule AUC={result['roc_auc']:.3f}\",ax=axes[1]); axes[1].plot([0,1],[0,1],'--',color='gray',label='Random'); axes[1].scatter([fp/(fp+tn)],[tp/(tp+fn)],color='darkorange',zorder=5,label='Locked threshold'); axes[1].set_title('ROC — TEST'); axes[1].legend()\nPrecisionRecallDisplay.from_predictions(y_test,test_score,name=f\"Rule AP={result['average_precision']:.3f}\",ax=axes[2]); axes[2].axhline(float(y_test.mean()),ls='--',color='gray',label=f'Attack rate={y_test.mean():.3f}'); axes[2].set_title('Precision–Recall — TEST'); axes[2].legend()\nplt.tight_layout(); plt.show()\nprint('Rule score chỉ có',len(np.unique(test_score)),'mức nên ROC/PR có ít điểm hơn mô hình xác suất.')"),
    md("## 4. Kết luận\nRule-Based là baseline giải thích được nhưng khó bao phủ hành vi mới. Chỉ dùng để chứng minh mô hình học máy có cải thiện thực sự so với luật thủ công."),
])

notebooks["07_Soft_Voting.ipynb"] = notebook([
    md("# 07 — Soft Voting Ensemble\nThực nghiệm đầy đủ cho SecuraAI / Windows-APT 2025. Mọi quyết định được khóa bằng Train/Validation trước khi mở Test."),
    md("## 0. Chuẩn bị môi trường\nChạy từ thư mục project hoặc `notebooks`. Không cần GPU; dùng `n_jobs=1` để tương thích Windows/Python 3.13."),
    code(SETUP + "\nfrom sklearn.ensemble import VotingClassifier"),
    md("### Tính tái lập\nCố định seed và in phiên bản. Không chọn seed dựa trên Test."),
    code("SEED=42\nnp.random.seed(SEED)\nplt.rcParams.update({'figure.dpi':110,'font.family':'DejaVu Sans','font.size':10})\nprint('Python:',platform.python_version(),'| sklearn:',sklearn.__version__,'| seed:',SEED)"),
    md("## 1. Xác thực dữ liệu và ý nghĩa nhãn\nNhãn MALICIOUS_APT suy ra từ MITRE/Wazuh tag, không phải ground truth do chuyên gia xét duyệt. Các cột tạo nhãn không nằm trong đầu vào."),
    code("display(pd.Series(audit.__dict__,name='value').to_frame())\nassert audit.rows==len(data) and data[TARGET_COLUMN].nunique()==2\nassert data[GROUP_COLUMN].ne('unknown-date').all()\nprint('Dataset checks passed')"),
    md("## 2. Chia Train/Validation/Test và dấu vân tay\nGiữ nguyên nhóm ngày; không có ngày nào xuất hiện ở hai tập."),
    code("split_table=pd.DataFrame([{'set':name,'rows':len(part),'benign':int((part[TARGET_COLUMN]==0).sum()),'malicious':int((part[TARGET_COLUMN]==1).sum()),'attack_rate':float(part[TARGET_COLUMN].mean()),'dates':part[GROUP_COLUMN].nunique()} for name,part in [('Train',train),('Validation',validation),('Test',test)]])\ndisplay(split_table)\nassert set(train[GROUP_COLUMN]).isdisjoint(validation[GROUP_COLUMN]) and set(train[GROUP_COLUMN]).isdisjoint(test[GROUP_COLUMN]) and set(validation[GROUP_COLUMN]).isdisjoint(test[GROUP_COLUMN])\nsplit_hash=hashlib.sha256(json.dumps({'train':sorted(train[GROUP_COLUMN].unique()),'validation':sorted(validation[GROUP_COLUMN].unique()),'test':sorted(test[GROUP_COLUMN].unique())},sort_keys=True).encode()).hexdigest()\nprint('Split hash:',split_hash[:16])"),
    md("## 3. EDA chỉ trên Train\nQuan sát phân bố nhãn và provider mà không dùng Test để định hướng ensemble."),
    code("fig,axes=plt.subplots(1,2,figsize=(13,4))\ntrain[TARGET_COLUMN].map({0:'BENIGN',1:'MALICIOUS_APT'}).value_counts().plot.bar(ax=axes[0],rot=0,title='Phân bố nhãn — TRAIN')\ntrain.groupby('provider')[TARGET_COLUMN].agg(['count','mean']).query('count>=100').sort_values('count',ascending=False).head(12)['mean'].plot.bar(ax=axes[1],title='Tỷ lệ tấn công theo provider — TRAIN')\nplt.tight_layout(); plt.show()"),
    md("## 4. Cơ chế Soft Voting và phạm vi triển khai\nCác mô hình sinh score lớp MALICIOUS_APT. Soft Voting lấy trung bình có trọng số rồi so với threshold. Ensemble không mặc nhiên tốt hơn mô hình đơn."),
    code("display(pd.DataFrame({'Bước':['1','2','3','4'],'Xử lý':['Log chuẩn hóa','Các pipeline dự đoán xác suất','Trung bình theo trọng số CV','So sánh threshold đã khóa']}))"),
    md("## 5. Tiền xử lý an toàn trong Pipeline\nMỗi mô hình chứa OneHotEncoder riêng được fit bên trong từng fold; không preprocessing toàn bộ dữ liệu trước CV."),
    code("factories=teaching_candidate_factories(SEED)\ngrids=teaching_parameter_grids()\nbase_names=['decision_tree','naive_bayes','bagging','random_forest','adaboost']\ndisplay(pd.DataFrame({'model':base_names,'parameter_grid':[str(grids[name]) for name in base_names]}))"),
    md("## 6. Dummy baseline\nBaseline theo prior là mức tối thiểu ensemble phải vượt qua."),
    code("dummy=DummyClassifier(strategy='prior').fit(X_train,y_train)\ndummy_pred=dummy.predict(X_validation); dummy_score=dummy.predict_proba(X_validation)[:,1]\ndisplay(pd.Series({'accuracy':accuracy_score(y_validation,dummy_pred),'precision':precision_score(y_validation,dummy_pred,zero_division=0),'recall':recall_score(y_validation,dummy_pred,zero_division=0),'f1':f1_score(y_validation,dummy_pred,zero_division=0),'f2':fbeta_score(y_validation,dummy_pred,beta=2,zero_division=0),'roc_auc':roc_auc_score(y_validation,dummy_score),'average_precision':average_precision_score(y_validation,dummy_score)},name='Dummy — Validation').to_frame())"),
    md("## 7. Tuning mô hình thành phần bằng 5-Fold chỉ trên Train\nMỗi mô hình được chọn theo CV F2. CV F2 cũng làm trọng số Voting, vì vậy Naive Bayes yếu không còn quyền biểu quyết ngang hàng. Không dùng Validation/Test để tạo trọng số."),
    code("estimators=[]; component_rows=[]\nfor name in base_names:\n    component_search=GridSearchCV(factories[name](),grids[name],scoring={'f2':make_scorer(fbeta_score,beta=2,zero_division=0),'roc_auc':'roc_auc','average_precision':'average_precision'},refit='f2',cv=cv,n_jobs=1,return_train_score=True)\n    component_search.fit(X_train,y_train,groups=groups)\n    estimators.append((name,component_search.best_estimator_))\n    component_rows.append({'model':name,'best_params':component_search.best_params_,'cv_f2':float(component_search.best_score_)})\ncomponent_table=pd.DataFrame(component_rows).sort_values('cv_f2',ascending=False)\ncomponent_weights=[max(next(row['cv_f2'] for row in component_rows if row['model']==name),1e-6) for name in base_names]\ndisplay(component_table)\ndisplay(pd.DataFrame({'model':base_names,'raw_weight':component_weights,'normalized_weight':np.array(component_weights)/sum(component_weights)}))"),
    md("## 8. Huấn luyện Soft Voting và Validation ở ngưỡng mặc định\nĐây là kết quả threshold 0.5 trước khi khóa threshold theo F2."),
    code("model=VotingClassifier(estimators=estimators,voting='soft',weights=component_weights,n_jobs=1)\nmodel.fit(X_train,y_train)\nvalidation_score=model.predict_proba(X_validation)[:,1]\nvalidation_default_pred=(validation_score>=0.5).astype(int)\nvalidation_default=pd.Series({'accuracy':accuracy_score(y_validation,validation_default_pred),'precision':precision_score(y_validation,validation_default_pred,zero_division=0),'recall':recall_score(y_validation,validation_default_pred,zero_division=0),'f1':f1_score(y_validation,validation_default_pred,zero_division=0),'f2':fbeta_score(y_validation,validation_default_pred,beta=2,zero_division=0),'roc_auc':roc_auc_score(y_validation,validation_score),'average_precision':average_precision_score(y_validation,validation_score)})\ndisplay(validation_default.to_frame('Validation — threshold 0.5'))"),
    md("## 9. Chọn và khóa ngưỡng trên Validation\nQuét score/phân vị, luôn bổ sung 0.5; chọn F2 cao nhất rồi không chỉnh lại sau khi xem Test."),
    code("unique_scores=np.unique(validation_score)\nif len(unique_scores)<=1000:\n    threshold_grid=unique_scores; grid_strategy='all unique scores'\nelse:\n    threshold_grid=np.unique(np.quantile(validation_score,np.linspace(0.001,0.999,999))); grid_strategy='score quantiles'\nthreshold_grid=np.unique(np.append(threshold_grid,0.5)); threshold_rows=[]\nfor threshold in threshold_grid:\n    p=(validation_score>=threshold).astype(int)\n    threshold_rows.append({'threshold':float(threshold),'precision':precision_score(y_validation,p,zero_division=0),'recall':recall_score(y_validation,p,zero_division=0),'f1':f1_score(y_validation,p,zero_division=0),'f2':fbeta_score(y_validation,p,beta=2,zero_division=0)})\nthreshold_table=pd.DataFrame(threshold_rows).sort_values('threshold')\nchosen=threshold_table.sort_values(['f2','recall','precision'],ascending=False).iloc[0]; locked_threshold=float(chosen.threshold)\nprint(f'Score levels: {len(unique_scores):,} | strategy: {grid_strategy} | locked: {locked_threshold:.6g}')\ndisplay(threshold_table.sort_values('f2',ascending=False).head(10))\nthreshold_table.plot(x='threshold',y=['precision','recall','f1','f2'],figsize=(11,5)); plt.axvline(locked_threshold,color='black',ls='--',label=f'locked={locked_threshold:.4g}'); plt.legend(); plt.show()"),
    md("## 10. Đánh giá Validation tại ngưỡng khóa\nConfusion Matrix, ROC và Precision–Recall dùng score liên tục đúng cách."),
    code("validation_pred=(validation_score>=locked_threshold).astype(int)\nvalidation_result=pd.Series({'accuracy':accuracy_score(y_validation,validation_pred),'precision':precision_score(y_validation,validation_pred,zero_division=0),'recall':recall_score(y_validation,validation_pred,zero_division=0),'f1':f1_score(y_validation,validation_pred,zero_division=0),'f2':fbeta_score(y_validation,validation_pred,beta=2,zero_division=0),'roc_auc':roc_auc_score(y_validation,validation_score),'average_precision':average_precision_score(y_validation,validation_score)})\ndisplay(validation_result.to_frame('VALIDATION — locked threshold'))\ntn,fp,fn,tp=confusion_matrix(y_validation,validation_pred,labels=[0,1]).ravel()\nfig,axes=plt.subplots(1,3,figsize=(17,4.8))\nConfusionMatrixDisplay.from_predictions(y_validation,validation_pred,display_labels=['BENIGN','MALICIOUS_APT'],ax=axes[0])\nRocCurveDisplay.from_predictions(y_validation,validation_score,name=f\"AUC={validation_result['roc_auc']:.3f}\",ax=axes[1]); axes[1].plot([0,1],[0,1],'--',color='gray'); axes[1].scatter([fp/(fp+tn)],[tp/(tp+fn)],color='darkorange',label='Locked threshold'); axes[1].legend()\nPrecisionRecallDisplay.from_predictions(y_validation,validation_score,name=f\"AP={validation_result['average_precision']:.3f}\",ax=axes[2]); axes[2].axhline(float(y_validation.mean()),ls='--',color='gray',label=f'Positive rate={y_validation.mean():.3f}'); axes[2].legend(); plt.tight_layout(); plt.show()"),
    md("## 11. Đánh giá Test đúng một lần\nMô hình, trọng số và threshold đã khóa. Test chỉ dùng báo cáo cuối."),
    code("X_test,y_test=test.loc[:,MODEL_FEATURES],test[TARGET_COLUMN]\ntest_score=model.predict_proba(X_test)[:,1]; test_pred=(test_score>=locked_threshold).astype(int)\ntest_result=pd.Series({'accuracy':accuracy_score(y_test,test_pred),'precision':precision_score(y_test,test_pred,zero_division=0),'recall':recall_score(y_test,test_pred,zero_division=0),'f1':f1_score(y_test,test_pred,zero_division=0),'f2':fbeta_score(y_test,test_pred,beta=2,zero_division=0),'roc_auc':roc_auc_score(y_test,test_score),'average_precision':average_precision_score(y_test,test_score)})\ndisplay(test_result.to_frame('TEST'))\ntn,fp,fn,tp=confusion_matrix(y_test,test_pred,labels=[0,1]).ravel(); print({'TN':int(tn),'FP':int(fp),'FN':int(fn),'TP':int(tp)})\nfig,axes=plt.subplots(1,3,figsize=(17,4.8))\nConfusionMatrixDisplay.from_predictions(y_test,test_pred,display_labels=['BENIGN','MALICIOUS_APT'],ax=axes[0]); axes[0].set_title(f'TEST — locked threshold {locked_threshold:.4g}')\nRocCurveDisplay.from_predictions(y_test,test_score,name=f\"AUC={test_result['roc_auc']:.3f}\",ax=axes[1]); axes[1].plot([0,1],[0,1],'--',color='gray'); axes[1].scatter([fp/(fp+tn)],[tp/(tp+fn)],color='darkorange',label='Locked threshold'); axes[1].legend()\nPrecisionRecallDisplay.from_predictions(y_test,test_score,name=f\"AP={test_result['average_precision']:.3f}\",ax=axes[2]); axes[2].axhline(float(y_test.mean()),ls='--',color='gray',label=f'Attack rate={y_test.mean():.3f}'); axes[2].legend(); plt.tight_layout(); plt.show()"),
    md("## 12. Khoảng bất định bằng bootstrap\nBootstrap Test chỉ mô tả độ bất định, không chọn lại mô hình hoặc threshold."),
    code("rng=np.random.default_rng(SEED); boot=[]; y_array=y_test.to_numpy()\nfor _ in range(300):\n    idx=rng.integers(0,len(y_array),len(y_array))\n    if np.unique(y_array[idx]).size<2: continue\n    boot.append({'f2':fbeta_score(y_array[idx],test_pred[idx],beta=2,zero_division=0),'roc_auc':roc_auc_score(y_array[idx],test_score[idx]),'average_precision':average_precision_score(y_array[idx],test_score[idx])})\nboot=pd.DataFrame(boot)\ndisplay(pd.DataFrame({'estimate':test_result[['f2','roc_auc','average_precision']],'ci_2.5%':boot.quantile(.025),'ci_97.5%':boot.quantile(.975)}))"),
    md("## 13. Lưu kết quả thực nghiệm\nLưu model, trọng số, threshold, split hash và tách rõ Validation mặc định/đã khóa với Test đã khóa."),
    code("experiment_dir=ROOT/'reports'/'notebook_experiments'; experiment_dir.mkdir(parents=True,exist_ok=True)\nslug='07_soft_voting'; joblib.dump(model,experiment_dir/f'{slug}.joblib')\nrecord={'schema_version':2,'model':'soft_voting','base_models':base_names,'component_cv':component_rows,'weights':dict(zip(base_names,map(float,component_weights))),'locked_threshold':locked_threshold,'split_hash':split_hash,'validation_default_threshold':{k:float(v) for k,v in validation_default.items()},'validation_locked_threshold':{k:float(v) for k,v in validation_result.items()},'test_locked_threshold':{k:float(v) for k,v in test_result.items()}}\n(experiment_dir/f'{slug}.json').write_text(json.dumps(record,indent=2),encoding='utf-8'); record"),
    md("## 14. Kết luận và giới hạn\nChỉ chọn Voting nếu Validation F2 tốt hơn mô hình đơn theo cùng giao thức. Nhãn rule-derived, dữ liệu Windows APT mô phỏng và Validation chỉ có hai nhóm ngày; cần external validation bằng log Wazuh thật trước production."),
])

notebooks["08_Lua_Chon_Mo_Hinh_Va_Bao_Cao.ipynb"] = notebook([
    md("# 08 — Lựa chọn mô hình và báo cáo cuối\nTổng hợp trực tiếp chín ứng viên từ các notebook 01–07 và 09–10. Chọn mô hình chỉ bằng Validation F2; sau đó mới mở Test để báo cáo và vẽ so sánh mô tả giống cấu trúc của giảng viên."),
    md("## 0. Chuẩn bị môi trường và quy tắc báo cáo\nChạy 01–07, 09 và 10 trước notebook này. Không dùng kết quả Test để đổi feature, siêu tham số, trọng số hoặc threshold."),
    code("from pathlib import Path\nimport json, joblib\nimport numpy as np\nimport pandas as pd\nimport matplotlib.pyplot as plt\nfrom IPython.display import display\nfrom sklearn.metrics import (ConfusionMatrixDisplay, RocCurveDisplay, PrecisionRecallDisplay,\n    accuracy_score, precision_score, recall_score, f1_score, fbeta_score,\n    roc_auc_score, average_precision_score, confusion_matrix)\nfrom securaai_ml.data import load_training_data\nfrom securaai_ml.modeling import decision_scores\nfrom securaai_ml.schema import MODEL_FEATURES, TARGET_COLUMN, GROUP_COLUMN\nfrom securaai_ml.train import temporal_train_validation_test\nROOT=Path.cwd().parent if Path.cwd().name=='notebooks' else Path.cwd()\nEXPERIMENTS=ROOT/'reports'/'notebook_experiments'\ndata,audit=load_training_data(ROOT/'data'/'raw')\ntrain,validation,test=temporal_train_validation_test(data)\nX_validation,y_validation=validation.loc[:,MODEL_FEATURES],validation[TARGET_COLUMN]\nX_test,y_test=test.loc[:,MODEL_FEATURES],test[TARGET_COLUMN]\nSEED=42\nprint(audit)"),
    md("## 1. Kiểm tra giao thức và artifact\nBảy ứng viên theo chuỗi giảng viên cùng hai mô hình mở rộng Linear SVM và Logistic Regression đều tham gia một phép so sánh thống nhất."),
    code("main_specs=[\n ('01_decision_tree','Decision Tree','model'),('02_naive_bayes','Naive Bayes','model'),\n ('03_rule_based','Rule-Based','rule'),('04_bagging','Bagging','model'),\n ('05_random_forest','Random Forest','model'),('06_adaboost','AdaBoost','model'),\n ('07_soft_voting','Soft Voting','model'),('09_linear_svm','Linear SVM','model'),\n ('10_logistic_regression','Logistic Regression','model')]\nmissing=[slug for slug,_,kind in main_specs if not (EXPERIMENTS/f'{slug}.json').exists() or (kind=='model' and not (EXPERIMENTS/f'{slug}.joblib').exists())]\nassert not missing, f'Chạy lại notebook để tạo artifact còn thiếu: {missing}'\nrecords={slug:json.loads((EXPERIMENTS/f'{slug}.json').read_text(encoding='utf-8')) for slug,_,_ in main_specs}\nsplit_hashes={r['split_hash'] for r in records.values()}\nassert len(split_hashes)==1, 'Artifact không cùng data split; phải chạy lại các notebook mô hình.'\nprint('Artifacts hợp lệ:',len(main_specs),'mô hình | split hash:',next(iter(split_hashes))[:16])"),
    md("## 2. Chuẩn hóa metric từ schema mới\nSchema v2 tách rõ Validation mặc định, Validation ngưỡng khóa và Test ngưỡng khóa. Hàm fallback chỉ giúp đọc artifact cũ trong lúc chuyển đổi."),
    code("def metrics_at(record,stage):\n    if stage=='validation':\n        return record.get('validation_locked_threshold',record.get('validation'))\n    return record.get('test_locked_threshold',record.get('test'))\ndef rule_score(frame):\n    return (2*frame['has_command_line']+frame['has_parent_command_line']+2*frame['has_hashes']+frame['has_target_file']+frame['has_source_ip']+frame['event_status'].isin(['failure','failed','denied']).astype(int)).to_numpy(float)\ndef measured_metrics(y,score,pred):\n    return {'accuracy':accuracy_score(y,pred),'precision':precision_score(y,pred,zero_division=0),'recall':recall_score(y,pred,zero_division=0),'f1':f1_score(y,pred,zero_division=0),'f2':fbeta_score(y,pred,beta=2,zero_division=0),'roc_auc':roc_auc_score(y,score),'average_precision':average_precision_score(y,score)}\nrows=[]; fitted_models={}\nfor slug,label,kind in main_specs:\n    record=records[slug]; threshold=float(record['locked_threshold'])\n    if kind=='rule': score=rule_score(X_validation)\n    else:\n        fitted_models[slug]=joblib.load(EXPERIMENTS/f'{slug}.joblib')\n        score=decision_scores(fitted_models[slug],X_validation)\n    pred=(score>=threshold).astype(int); metric=measured_metrics(y_validation,score,pred)\n    rows.append({'slug':slug,'model':label,'threshold':threshold,'cv_f2':record.get('cv_best_f2',np.nan),**metric})\ncomparison=pd.DataFrame(rows).sort_values(['f2','recall','precision'],ascending=False).reset_index(drop=True)\ndisplay(comparison[['model','threshold','cv_f2','accuracy','precision','recall','f1','f2','roc_auc','average_precision']])"),
    md("## 3. So sánh metric trên Validation\nF2 là tiêu chí chốt vì bài toán SOC ưu tiên giảm FN, nhưng vẫn báo cáo Precision để thể hiện tải cảnh báo giả."),
    code("metrics=['accuracy','precision','recall','f1','f2','roc_auc','average_precision']\nax=comparison.set_index('model')[metrics].plot.bar(figsize=(15,6),ylim=(0,1.02),width=.82)\nax.set_ylabel('Validation score'); ax.set_title('So sánh mô hình — VALIDATION (locked threshold)'); plt.xticks(rotation=20,ha='right'); plt.legend(ncol=4,fontsize=8); plt.tight_layout(); plt.show()"),
    md("## 4. Chọn và khóa mô hình bằng Validation\nMô hình đứng đầu F2 được chọn trước khi đọc bất kỳ kết quả Test nào trong notebook này. Nếu hòa, ưu tiên Recall rồi Precision."),
    code("selected=comparison.iloc[0]\nselected_slug=selected['slug']; selected_label=selected['model']; selected_record=records[selected_slug]\nprint('Mô hình được chọn:',selected_label)\nprint('Validation F2:',selected['f2'],'| threshold:',selected['threshold'])\ndisplay(selected.to_frame('selected_on_validation'))"),
    md("## 5. Tạo score Test cho các đường ROC/PR\nĐây là so sánh mô tả sau khi lựa chọn đã khóa, giống notebook giảng viên. Không dùng biểu đồ Test để đổi người thắng."),
    code("results={}\nfor slug,label,kind in main_specs:\n    record=records[slug]; threshold=float(record['locked_threshold'])\n    score=rule_score(X_test) if kind=='rule' else decision_scores(fitted_models[slug],X_test)\n    pred=(score>=threshold).astype(int)\n    results[slug]={'label':label,'score':score,'pred':pred,'threshold':threshold}\nprint('Đã tính score Test cho',len(results),'ứng viên; quyết định lựa chọn vẫn là',selected_label)"),
    md("## 6. ROC và Precision–Recall của tất cả mô hình\nSố trong ngoặc là ROC-AUC/AP. Đường gạch PR là tỷ lệ MALICIOUS_APT trong Test, không phải một hằng số cố định."),
    code("fig,axes=plt.subplots(1,2,figsize=(16,6))\nfor slug,label,_ in main_specs:\n    score=results[slug]['score']\n    auc=roc_auc_score(y_test,score); ap=average_precision_score(y_test,score)\n    RocCurveDisplay.from_predictions(y_test,score,name=f'{label} ({auc:.3f})',ax=axes[0])\n    PrecisionRecallDisplay.from_predictions(y_test,score,name=f'{label} ({ap:.3f})',ax=axes[1])\naxes[0].plot([0,1],[0,1],'--',color='gray',label='Random'); axes[0].set_title('ROC — số trong ngoặc là ROC-AUC')\naxes[1].axhline(float(y_test.mean()),ls='--',color='gray',label=f'Attack rate={y_test.mean():.3f}'); axes[1].set_title('PR — số trong ngoặc là Average Precision')\nfor ax in axes: ax.legend(fontsize=8)\nplt.tight_layout(); plt.show()"),
    md("## 7. Bảng Test mô tả sau khi đã khóa lựa chọn\nBảng này không được dùng để đổi mô hình thắng. Nếu thay thiết kế sau khi xem bảng, cần một Test độc lập mới."),
    code("test_rows=[]\nfor slug,label,_ in main_specs:\n    pred=results[slug]['pred']; score=results[slug]['score']; tn,fp,fn,tp=confusion_matrix(y_test,pred,labels=[0,1]).ravel()\n    test_rows.append({'model':label,'TN':tn,'FP':fp,'FN':fn,'TP':tp,'accuracy':accuracy_score(y_test,pred),'precision':precision_score(y_test,pred,zero_division=0),'recall':recall_score(y_test,pred,zero_division=0),'f1':f1_score(y_test,pred,zero_division=0),'f2':fbeta_score(y_test,pred,beta=2,zero_division=0),'roc_auc':roc_auc_score(y_test,score),'average_precision':average_precision_score(y_test,score)})\ntest_comparison=pd.DataFrame(test_rows)\ndisplay(test_comparison)"),
    md("## 8. Confusion Matrix của mô hình đã chọn\nHàng là nhãn thật, cột là dự đoán: FN là tấn công bị bỏ sót; FP là cảnh báo giả làm tăng tải analyst."),
    code("chosen=results[selected_slug]\ntn,fp,fn,tp=confusion_matrix(y_test,chosen['pred'],labels=[0,1]).ravel()\nfig,ax=plt.subplots(figsize=(6,5))\nConfusionMatrixDisplay.from_predictions(y_test,chosen['pred'],display_labels=['BENIGN','MALICIOUS_APT'],ax=ax,cmap='Blues')\nax.set_title(f'{selected_label} — TEST — threshold {chosen[\"threshold\"]:.4g}'); plt.tight_layout(); plt.show()\nprint(f'Phát hiện đúng {tp:,} tấn công, bỏ sót {fn:,}, cảnh báo giả {fp:,}, loại đúng {tn:,} log benign.')"),
    md("## 9. Khoảng bất định của mô hình đã chọn\nBootstrap theo dòng Test chỉ mô tả độ dao động nội bộ; không thay thế validation theo ngày hoặc external validation."),
    code("rng=np.random.default_rng(SEED); boot=[]; y_array=y_test.to_numpy(); pred=chosen['pred']; score=chosen['score']\nfor _ in range(300):\n    idx=rng.integers(0,len(y_array),len(y_array))\n    if np.unique(y_array[idx]).size<2: continue\n    boot.append({'f2':fbeta_score(y_array[idx],pred[idx],beta=2,zero_division=0),'roc_auc':roc_auc_score(y_array[idx],score[idx]),'average_precision':average_precision_score(y_array[idx],score[idx])})\nboot=pd.DataFrame(boot); display(pd.DataFrame({'estimate':test_comparison.set_index('model').loc[selected_label,['f2','roc_auc','average_precision']],'ci_2.5%':boot.quantile(.025),'ci_97.5%':boot.quantile(.975)}))"),
    md("## 10. Kiểm tra đủ mô hình trên báo cáo\nBảng, biểu đồ metric, ROC và PR phía trên phải cùng chứa đủ chín mô hình. Một số đường gần như trùng nhau do score rất cao, nhưng legend vẫn liệt kê riêng từng mô hình."),
    code("reported_models=[label for _,label,_ in main_specs]\nassert len(reported_models)==9 and comparison['model'].nunique()==9 and test_comparison['model'].nunique()==9\ndisplay(pd.DataFrame({'order':range(1,10),'model':reported_models}))\nprint('Đã tổng hợp đủ',len(reported_models),'mô hình.')"),
    md("## 11. Kết luận phương pháp\n- Train học preprocessing và siêu tham số bằng grouped K-Fold.\n- Validation chọn threshold và mô hình theo F2.\n- Test chỉ báo cáo sau khi khóa lựa chọn.\n- Ensemble chỉ thắng khi Validation chứng minh tốt hơn.\n- Không dùng Test để quay lại sửa thiết kế; nếu sửa cần Test mới."),
    md("## 12. Giới hạn bắt buộc khi bảo vệ\n- Nhãn bắt nguồn từ MITRE/Wazuh rule, không phải ground truth độc lập.\n- Dữ liệu Windows APT là môi trường mô phỏng; chưa chứng minh VPN/SSO, web, Linux, brute-force hoặc zero-day.\n- Validation hiện chỉ có hai nhóm ngày.\n- Score không mặc nhiên là xác suất đã hiệu chỉnh.\n- Cần external validation bằng log Wazuh thật của SecuraAI trước production."),
    md("## 13. Kết luận cuối\nPhần ML chứng minh quy trình xây dựng, đánh giá và tích hợp mô hình vào hệ thống phần mềm. Không tuyên bố mô hình thay thế Wazuh, SOC analyst hoặc LLM; ưu tiên mô hình đáp ứng F2, tải cảnh báo và chi phí triển khai hợp lý."),
])

notebooks["11_Export_Model_FastAPI.ipynb"] = notebook([
    md("# 11 — Export model và kiểm thử FastAPI\nPhần mở rộng triển khai sau chuỗi báo cáo 01–08 của giảng viên."),
    code("from pathlib import Path\nimport json, joblib\nfrom fastapi.testclient import TestClient\nimport securaai_ml.api as api_module\nROOT=Path.cwd().parent if Path.cwd().name=='notebooks' else Path.cwd()\napi_module.ARTIFACT_DIR=ROOT/'artifacts'\napi_module.load_artifacts.cache_clear()\napp=api_module.app\nmodel=joblib.load(ROOT/'artifacts'/'model.joblib')\nmetadata=json.loads((ROOT/'artifacts'/'model_metadata.json').read_text(encoding='utf-8'))\nmetadata"),
    md("## Health check"),
    code("client=TestClient(app)\nclient.get('/health').json()"),
    md("## Gửi một event chuẩn hóa"),
    code("payload={'timestamp':'2024-12-22T10:00:00Z','eventId':'1','providerName':'Microsoft-Windows-Sysmon','channel':'Microsoft-Windows-Sysmon/Operational','severityValue':'INFORMATION'}\nresponse=client.post('/v1/predict',json=payload)\nprint(response.status_code)\nresponse.json()"),
    md("## Nguyên tắc tích hợp\nChạy shadow mode; lưu model version và evidence; không tự động đóng/mở incident chỉ từ score. Score không phải xác suất đã hiệu chỉnh."),
])

# Rule-Based không học tham số, nhưng vẫn phải tuân thủ đầy đủ giao thức đánh giá.
notebooks["03_Rule_Based.ipynb"] = notebook([
    md("# 03 — Rule-Based baseline\nBaseline luật minh bạch để kiểm tra xem mô hình học máy có thực sự cải thiện so với logic thủ công hay không. Đây không phải mô hình AI được huấn luyện."),
    md("## 0. Chuẩn bị môi trường và tính tái lập\nDùng cùng dữ liệu, phép chia và seed với các notebook khác."),
    code(SETUP),
    code("SEED=42\nnp.random.seed(SEED)\nprint('Rows:',len(data),'| Train:',len(train),'| Validation:',len(validation),'| Test:',len(test),'| Seed:',SEED)"),
    md("## 1. Xác thực dữ liệu và ý nghĩa nhãn\nNhãn là rule-derived ground truth; MITRE/Wazuh tag tạo nhãn không được dùng trong luật baseline."),
    code("display(pd.Series(audit.__dict__,name='value').to_frame())\nassert audit.rows==len(data) and data[TARGET_COLUMN].nunique()==2\nassert data[GROUP_COLUMN].ne('unknown-date').all()\nprint('Dataset checks passed')"),
    md("## 2. Chia Train/Validation/Test và dấu vân tay\nRule được thiết kế trước; Validation chỉ chọn ngưỡng, Test chỉ mở sau khi khóa."),
    code("split_table=pd.DataFrame([{'set':name,'rows':len(part),'attack_rate':float(part[TARGET_COLUMN].mean()),'dates':part[GROUP_COLUMN].nunique()} for name,part in [('Train',train),('Validation',validation),('Test',test)]])\ndisplay(split_table)\nsplit_hash=hashlib.sha256(json.dumps({'train':sorted(train[GROUP_COLUMN].unique()),'validation':sorted(validation[GROUP_COLUMN].unique()),'test':sorted(test[GROUP_COLUMN].unique())},sort_keys=True).encode()).hexdigest()\nprint('Split hash:',split_hash[:16])"),
    md("## 3. EDA chỉ trên Train\nQuan sát phân bố nhãn và các feature mà rule sẽ sử dụng, không xem Test để sửa luật."),
    code("fig,axes=plt.subplots(1,2,figsize=(13,4))\ntrain[TARGET_COLUMN].map({0:'BENIGN',1:'MALICIOUS_APT'}).value_counts().plot.bar(ax=axes[0],rot=0,title='Phân bố nhãn — TRAIN')\ntrain[['has_command_line','has_parent_command_line','has_hashes','has_target_file','has_source_ip']].mean().plot.bar(ax=axes[1],rot=25,title='Tỷ lệ feature bật — TRAIN')\nplt.tight_layout(); plt.show()"),
    md("## 4. Cơ chế luật và phạm vi triển khai\nMỗi dấu hiệu cộng một số điểm cố định. Luật dễ giải thích nhưng không tự học tương tác mới và không thay thế Wazuh rule."),
    code("rule_weights=pd.DataFrame([('has_command_line',2),('has_parent_command_line',1),('has_hashes',2),('has_target_file',1),('has_source_ip',1),('event_status failure/failed/denied',1)],columns=['condition','points'])\ndisplay(rule_weights)\ndef rule_score(frame):\n    return (2*frame['has_command_line'] + frame['has_parent_command_line'] + 2*frame['has_hashes'] + frame['has_target_file'] + frame['has_source_ip'] + frame['event_status'].isin(['failure','failed','denied']).astype(int)).to_numpy(dtype=float)"),
    md("## 5. Phân bố điểm luật trên Train\nNếu hai lớp chồng lấn nhiều, luật không thể phân tách tốt chỉ bằng một threshold."),
    code("train_scores=rule_score(X_train)\nscore_distribution=pd.crosstab(train_scores,y_train).rename(columns={0:'BENIGN',1:'MALICIOUS_APT'})\ndisplay(score_distribution)\nscore_distribution.plot.bar(figsize=(10,4),title='Rule score theo nhãn — TRAIN'); plt.ylabel('Số log'); plt.show()"),
    md("## 6. Dummy baseline\nRule-Based phải tốt hơn chiến lược đoán theo lớp phổ biến mới có giá trị."),
    code("dummy=DummyClassifier(strategy='prior').fit(X_train,y_train)\ndummy_pred=dummy.predict(X_validation)\ndisplay(pd.Series({'accuracy':accuracy_score(y_validation,dummy_pred),'precision':precision_score(y_validation,dummy_pred,zero_division=0),'recall':recall_score(y_validation,dummy_pred,zero_division=0),'f1':f1_score(y_validation,dummy_pred,zero_division=0),'f2':fbeta_score(y_validation,dummy_pred,beta=2,zero_division=0)},name='Dummy — Validation').to_frame())"),
    md("## 7. Chọn và khóa ngưỡng trên Validation\nThử toàn bộ ngưỡng nguyên có thể, chọn F2 cao nhất rồi không chỉnh lại sau khi xem Test."),
    code("validation_score=rule_score(X_validation)\nrows=[]\nfor threshold in range(1,9):\n    pred=(validation_score>=threshold).astype(int)\n    rows.append({'threshold':threshold,'accuracy':accuracy_score(y_validation,pred),'precision':precision_score(y_validation,pred,zero_division=0),'recall':recall_score(y_validation,pred,zero_division=0),'f1':f1_score(y_validation,pred,zero_division=0),'f2':fbeta_score(y_validation,pred,beta=2,zero_division=0)})\nthreshold_table=pd.DataFrame(rows); display(threshold_table)\nchosen=threshold_table.sort_values(['f2','recall','precision'],ascending=False).iloc[0]\nlocked_threshold=int(chosen.threshold)\nthreshold_table.plot(x='threshold',y=['precision','recall','f1','f2'],figsize=(11,5)); plt.axvline(locked_threshold,color='black',ls='--',label=f'locked={locked_threshold}'); plt.legend(); plt.show()"),
    md("## 8. Đánh giá trên Validation\nBáo cáo Confusion Matrix, ROC và Precision–Recall tại ngưỡng đã khóa."),
    code("validation_pred=(validation_score>=locked_threshold).astype(int)\nvalidation_result=pd.Series({'accuracy':accuracy_score(y_validation,validation_pred),'precision':precision_score(y_validation,validation_pred,zero_division=0),'recall':recall_score(y_validation,validation_pred,zero_division=0),'f1':f1_score(y_validation,validation_pred,zero_division=0),'f2':fbeta_score(y_validation,validation_pred,beta=2,zero_division=0),'roc_auc':roc_auc_score(y_validation,validation_score),'average_precision':average_precision_score(y_validation,validation_score)})\ndisplay(validation_result.to_frame('VALIDATION'))\nfig,axes=plt.subplots(1,3,figsize=(17,4.8)); ConfusionMatrixDisplay.from_predictions(y_validation,validation_pred,display_labels=['BENIGN','MALICIOUS_APT'],ax=axes[0]); RocCurveDisplay.from_predictions(y_validation,validation_score,name='Rule-Based',ax=axes[1]); axes[1].plot([0,1],[0,1],'--',color='gray'); PrecisionRecallDisplay.from_predictions(y_validation,validation_score,name='Rule-Based',ax=axes[2]); axes[2].axhline(float(y_validation.mean()),ls='--',color='gray'); plt.tight_layout(); plt.show()"),
    md("## 9. Đánh giá Test đúng một lần\nDùng nguyên luật và threshold đã khóa trên Validation."),
    code("X_test,y_test=test.loc[:,MODEL_FEATURES],test[TARGET_COLUMN]\ntest_score=rule_score(X_test); test_pred=(test_score>=locked_threshold).astype(int)\ntest_result=pd.Series({'accuracy':accuracy_score(y_test,test_pred),'precision':precision_score(y_test,test_pred,zero_division=0),'recall':recall_score(y_test,test_pred,zero_division=0),'f1':f1_score(y_test,test_pred,zero_division=0),'f2':fbeta_score(y_test,test_pred,beta=2,zero_division=0),'roc_auc':roc_auc_score(y_test,test_score),'average_precision':average_precision_score(y_test,test_score)})\ndisplay(test_result.to_frame('TEST'))\ntn,fp,fn,tp=confusion_matrix(y_test,test_pred,labels=[0,1]).ravel(); print({'TN':int(tn),'FP':int(fp),'FN':int(fn),'TP':int(tp)})\nfig,axes=plt.subplots(1,3,figsize=(17,4.8)); ConfusionMatrixDisplay.from_predictions(y_test,test_pred,display_labels=['BENIGN','MALICIOUS_APT'],ax=axes[0]); RocCurveDisplay.from_predictions(y_test,test_score,name='Rule-Based',ax=axes[1]); axes[1].plot([0,1],[0,1],'--',color='gray'); PrecisionRecallDisplay.from_predictions(y_test,test_score,name='Rule-Based',ax=axes[2]); axes[2].axhline(float(y_test.mean()),ls='--',color='gray'); plt.tight_layout(); plt.show()"),
    md("## 10. Khoảng bất định bằng bootstrap\nBootstrap theo từng dòng Test chỉ mô tả độ dao động nội bộ, không chọn lại luật/ngưỡng."),
    code("rng=np.random.default_rng(SEED); boot=[]; y_array=y_test.to_numpy()\nfor _ in range(300):\n    idx=rng.integers(0,len(y_array),len(y_array))\n    if np.unique(y_array[idx]).size<2: continue\n    boot.append({'f2':fbeta_score(y_array[idx],test_pred[idx],beta=2,zero_division=0),'roc_auc':roc_auc_score(y_array[idx],test_score[idx]),'average_precision':average_precision_score(y_array[idx],test_score[idx])})\nboot=pd.DataFrame(boot)\ndisplay(pd.DataFrame({'estimate':test_result[['f2','roc_auc','average_precision']],'ci_2.5%':boot.quantile(.025),'ci_97.5%':boot.quantile(.975)}))"),
    md("## 11. Lưu kết quả thực nghiệm\nRule-Based không có model `.joblib`; lưu định nghĩa luật, threshold, split hash và metric vào JSON."),
    code("experiment_dir=ROOT/'reports'/'notebook_experiments'; experiment_dir.mkdir(parents=True,exist_ok=True)\nrecord={'schema_version':2,'model':'rule_based','rule_weights':dict(rule_weights.values.tolist()),'locked_threshold':locked_threshold,'split_hash':split_hash,'validation_locked_threshold':{k:float(v) for k,v in validation_result.items()},'test_locked_threshold':{k:float(v) for k,v in test_result.items()}}\n(experiment_dir/'03_rule_based.json').write_text(json.dumps(record,indent=2),encoding='utf-8'); record"),
    md("## 12. Kết luận và giới hạn\nRule-Based là baseline giải thích được nhưng độ bao phủ thấp và không tự thích nghi. Chỉ dùng để chứng minh mô hình học máy có cải thiện thực sự; không trình bày đây là mô hình AI hoặc thay thế Wazuh."),
])

import argparse

parser = argparse.ArgumentParser(description="Generate SecuraAI notebooks")
parser.add_argument("--only", action="append", help="Generate only this notebook filename; repeatable")
args = parser.parse_args()
selected = set(args.only or notebooks)
unknown = selected.difference(notebooks)
if unknown:
    parser.error(f"Unknown notebook(s): {', '.join(sorted(unknown))}")

OUT.mkdir(parents=True, exist_ok=True)
for filename, content in notebooks.items():
    if filename not in selected:
        continue
    add_combined_update(content)
    if filename == "00_Data_EDA_Preprocessing.ipynb":
        content["cells"].extend([
            md("""## Nguồn dữ liệu mới và vai trò của từng nguồn

| Nguồn | Vai trò | Nhãn | Cách chia |
|---|---|---|---|
| Windows-APT 2025 v4 | hành vi Windows APT mô phỏng | MITRE/Wazuh-derived | theo ngày 60/20/20 |
| RADAR v0.0.1-beta | Sysmon ransomware và goodware | ground truth theo executable/sample | mẫu độc lập 60/20/20 |
| SecuraAI/Wazuh lab | kiểm tra khả năng nhận log của project | kịch bản kiểm soát | chỉ train bổ sung hoặc external test |
| Wazuh benign candidates | giảm cảnh báo giả trên log gần miền đích | weak label, phải rà soát | chỉ bổ sung Train |

Không trộn Test trở lại Train. Không coi weak label hoặc bốn log lab là ground truth production."""),
            code("""if combined_source_report_path.exists():
    source_report = json.loads(combined_source_report_path.read_text(encoding='utf-8'))
    source_rows = []
    for source, values in source_report.items():
        row = {'source': source}
        if isinstance(values, dict):
            for key in ['rows','accuracy','precision','recall','f2','roc_auc','predicted_benign','predicted_malicious']:
                if key in values: row[key] = values[key]
        source_rows.append(row)
    display(pd.DataFrame(source_rows).set_index('source'))
"""),
            md("""## Dataset scenario temporal

Bộ scenario hiện có **3.000 session / khoảng 24.600 event**, chia nguyên session thành Train/Validation/Test và có manifest ground truth riêng. Ngoài burst benign sát ngưỡng, dữ liệu còn có password spraying, distributed attack, success-after-failure và hard-negative nhiều tài khoản/IP độc lập. Nhãn event phản ánh thời điểm ra quyết định: event thứ năm trong burst xác thực/VPN và event thứ mười trong burst ứng dụng mới bắt đầu là malicious. Metric rất cao trên bộ này đo khả năng tái hiện kịch bản mô phỏng, không phải accuracy production."""),
            code("""scenario_path=ROOT/'data'/'securaai_scenarios'/'securaai_scenarios.csv'
if scenario_path.exists():
    scenario_data=pd.read_csv(scenario_path,dtype=str).fillna('')
    display(pd.crosstab(scenario_data['session_split'],scenario_data['reviewer_label'],margins=True))
    display(scenario_data.groupby(['session_split','scenario'])['scenario_id'].nunique().rename('sessions').to_frame())
    assert scenario_data.groupby('scenario_id')['session_split'].nunique().max()==1
    print('Không có session nào đi qua nhiều split.')
"""),
        ])
    elif filename == "08_Lua_Chon_Mo_Hinh_Va_Bao_Cao.ipynb":
        content["cells"].extend([
            md("""## Quyết định cuối cho SecuraAI

Kết quả 9 mô hình phía trên là **so sánh thuật toán có kiểm soát trên Windows-APT**. Model dùng thử với SecuraAI hiện tại là ứng viên hợp nhất, được chọn lại trên Validation sau khi thêm RADAR và dữ liệu Wazuh. Vì tập dữ liệu đã thay đổi, không xếp hạng trực tiếp metric của hai thí nghiệm như cùng một cuộc thi."""),
            code("""if combined_metadata_path.exists():
    m = combined_metadata
    final_rows = [
        {'evaluation':'Combined validation', **{k:v for k,v in m['validation'].items() if k != 'confusion_matrix'}},
        {'evaluation':'Combined test', **{k:v for k,v in m['test'].items() if k != 'confusion_matrix'}},
    ]
    display(pd.DataFrame(final_rows).set_index('evaluation'))
    print('CHỌN TRIỂN KHAI THỬ:', m['selectedModel'])
    print('Ngưỡng khóa:', m['lockedThreshold'])
    print('Không gọi score là xác suất:', m['scoreSemantics'])
"""),
            md("""## External validation và ứng viên temporal

Baseline hợp nhất đạt điểm nội bộ cao nhưng chỉ đạt khoảng 49% trên bộ scenario độc lập và báo sai các log Normal khi chạy qua SecuraAI. Vì vậy không chọn baseline này cho alert. Candidate temporal loại các feature nhận diện dataset (`provider`, `location`, raw event ID) và dùng lịch sử năm phút. Nhãn malicious chỉ bắt đầu tại event đạt ngưỡng burst, không gắn nhãn tấn công cho một lần nhập sai đơn lẻ."""),
            code("""temporal_path=ROOT/'artifacts-temporal-candidate'/'model_metadata.json'
if temporal_path.exists():
    temporal=json.loads(temporal_path.read_text(encoding='utf-8'))
    display(pd.DataFrame([
        {'stage':'Validation',**{k:v for k,v in temporal['validation'].items() if k!='confusionMatrix'}},
        {'stage':'Test',**{k:v for k,v in temporal['test'].items() if k!='confusionMatrix'}},
    ]).set_index('stage'))
    print('Candidate:',temporal['selectedModel'],'| threshold:',temporal['lockedThreshold'])
    print('Status:',temporal['status'],'— chưa được phép tự tạo alert')
"""),
            md("""## Kiểm thử trực tiếp qua SecuraAI

Luồng đã kiểm tra: `Wazuh demo → custom normalizer → Backend → PostgreSQL → model shadow`.

Ba lần đánh giá dùng run ID mới, không tái sử dụng kết quả cũ:

| Phiên bản | Thay đổi | TN | FP | FN | TP | FPR |
|---|---|---:|---:|---:|---:|---:|
| V1 | Candidate ban đầu | 66 | 8 | 0 | 27 | 10,81% |
| V2 | Thêm burst benign sát ngưỡng | 69 | 5 | 3 | 24 | 6,76% |
| V3 | Thêm operational gate, ngưỡng chọn trên Validation | 74 | 0 | 0 | 27 | 0% |

V3 đạt 100% trên **101 event/15 case kiểm tra biên**, nhưng đây không phải bằng chứng model tổng quát hóa 100%. Toàn bộ dữ liệu PostgreSQL hiện tại cũng là dữ liệu mô phỏng; các case được kiểm soát và cùng ngữ nghĩa ngưỡng với dữ liệu thiết kế. Kết quả nội bộ Test rộng hơn chỉ đạt khoảng 94,33% Accuracy, 84,97% Recall và 3,49% FPR. Model tiếp tục ở shadow mode, contribution bằng 0; dự án hiện chưa có log Wazuh production được chuyên gia gán nhãn để đánh giá thực tế."""),
            code("""external_files={
    'V1':ROOT/'reports'/'securaai_external_benchmark.json',
    'V2':ROOT/'reports'/'securaai_external_benchmark_v2.json',
    'V3':ROOT/'reports'/'securaai_external_benchmark_v3.json',
}
external_rows=[]
for version,path in external_files.items():
    if path.exists():
        report=json.loads(path.read_text(encoding='utf-8'))
        summary=report['summary']; cm=summary['confusionMatrix']
        external_rows.append({'version':version,**{k:v for k,v in summary.items() if k!='confusionMatrix'},**cm})
if external_rows:
    display(pd.DataFrame(external_rows).set_index('version'))
if external_files['V3'].exists():
    external_v3=json.loads(external_files['V3'].read_text(encoding='utf-8'))
    display(pd.DataFrame(external_v3['byCase']))
"""),
            md("""## Challenge V2 khóa trước khi đánh giá

Challenge V2 được sinh bằng generator độc lập, khóa SHA-256 và đánh giá đúng một lần. File này không bao giờ được đưa vào Train hoặc dùng chọn threshold. Đây là stress test synthetic, không phải accuracy production."""),
            code("""challenge_path=ROOT/'reports'/'challenge_v2_result.json'
if challenge_path.exists():
    challenge=json.loads(challenge_path.read_text(encoding='utf-8'))
    display(pd.Series(challenge['summary'],name='Challenge V2').to_frame())
    challenge_rows=[]
    for scenario,values in challenge['byScenario'].items():
        challenge_rows.append({'scenario':scenario,**{k:v for k,v in values.items() if k!='confusionMatrix'},**values['confusionMatrix']})
    display(pd.DataFrame(challenge_rows).set_index('scenario'))
    print('Không retrain hoặc chỉnh threshold bằng Challenge V2.')
"""),
            md("""## Locked robustness challenges V3 and V4

V3 exposed an account-only authentication weakness. Its application short-burst case also had a test-spec conflict: 12 denials were labelled benign although the documented operational boundary is 10. The frozen result is reported unchanged. V4 was created only after candidate v4 was locked, uses a true sub-threshold application burst (8 events), and is never training data."""),
            code("""for version in ('v3','v4'):
    path=ROOT/'reports'/f'challenge_{version}_result.json'
    if not path.exists():
        continue
    result=json.loads(path.read_text(encoding='utf-8'))
    print(result['challengeVersion'],'| model:',result['modelVersion'])
    display(pd.Series(result['summary'],name=result['challengeVersion']).to_frame())
    rows=[]
    for scenario,values in result['byScenario'].items():
        rows.append({'scenario':scenario,**{k:v for k,v in values.items() if k!='confusionMatrix'},**values['confusionMatrix']})
    display(pd.DataFrame(rows).set_index('scenario'))
print('Never retrain or tune a model with any locked challenge.')
"""),
            md("""## Candidate v6: lựa chọn model temporal đúng quy trình

Candidate v6 dùng cùng feature temporal cho bảy thuật toán và Soft Voting. Siêu tham số được chọn bằng 5-Fold `StratifiedGroupKFold` theo session chỉ trên Train; model và threshold được khóa bằng Validation trước khi mở Test. Dữ liệu gồm scenario mô phỏng và 133 Windows Security Event 4625 thật trong lab. Đây **không phải dữ liệu production**."""),
            code("""real_report_path=ROOT/'reports'/'real_windows_auth_lab_v5_live.json'
temporal_metadata_path=ROOT/'artifacts-temporal-candidate'/'model_metadata.json'
if real_report_path.exists():
    real_report=json.loads(real_report_path.read_text(encoding='utf-8'))
    live_cm=real_report['confusionMatrix']
    live_model=real_report['rows'][0]['prediction']['modelVersion'] if real_report.get('rows') else 'missing'
    display(pd.DataFrame({
        'value':[real_report.get('events'),live_cm['tn'],live_cm['fp'],live_cm['fn'],live_cm['tp'],live_model]
    },index=['live_events','tn','fp','fn','tp','model_version']))
if temporal_metadata_path.exists():
    temporal_candidate=json.loads(temporal_metadata_path.read_text(encoding='utf-8'))
    by_origin=temporal_candidate.get('testByOrigin',{})
    rows=[]
    for origin,metric in by_origin.items():
        rows.append({'origin':origin,**{k:v for k,v in metric.items() if k!='confusionMatrix'},**metric.get('confusionMatrix',{})})
    if rows: display(pd.DataFrame(rows).set_index('origin'))
    cv_rows=[]
    for name,result in temporal_candidate['allValidationCandidates'].items():
        cv=temporal_candidate['trainCrossValidation']['candidates'].get(name,{})
        cv_rows.append({'model':name,'mean_cv_f2':cv.get('meanCvF2'),'std_cv_f2':cv.get('stdCvF2'),
                        'validation_f2':result['f2'],'validation_precision':result['precision'],
                        'validation_recall':result['recall'],'threshold':result['threshold']})
    display(pd.DataFrame(cv_rows).sort_values(['validation_f2','mean_cv_f2'],ascending=False))
    print('Candidate:',temporal_candidate['modelVersion'])
    print('Model được chọn:',temporal_candidate['selectedModel'])
    print('Status:',temporal_candidate['status'])
    print('Giới hạn:',temporal_candidate.get('limitations',[]))
"""),
            md("""## Kiểm thử end-to-end AUTH, VPN/SSO và APP_ACCESS

Benchmark này đọc chính `ml_shadow_prediction` đã được Backend SecuraAI lưu trong PostgreSQL. Mỗi run dùng IP riêng để cửa sổ năm phút không trộn các session độc lập. AUTH/VPN được kiểm tra ở 2, 4, 5, 6 và 10 event; APP_ACCESS ở 8, 10, 11 và 15 event. Đây vẫn là log lab mô phỏng đúng contract, chưa phải log xuất từ VPN/SSO hay ứng dụng production thật."""),
            code("""shadow_report_path=ROOT/'reports'/'securaai_shadow_benchmark_v6_isolated.json'
if shadow_report_path.exists():
    shadow_report=json.loads(shadow_report_path.read_text(encoding='utf-8'))
    summary=shadow_report['summary']
    display(pd.DataFrame({'value':summary}).drop(index=['confusionMatrix'],errors='ignore'))
    display(pd.DataFrame(shadow_report['byCase']))
    print('Confusion matrix:',summary['confusionMatrix'])
    print('Lưu ý: dùng chung IP giữa nhiều account trong 5 phút là password spraying, không phải các session độc lập.')
"""),
        ])
    elif filename == "11_Export_Model_FastAPI.ipynb":
        content["cells"].extend([
            md("""## Export ứng viên temporal cho SecuraAI

Không ghi đè model production. API trỏ vào `artifacts-temporal-candidate` và backend gửi cả context năm phút. Model vẫn phải chạy shadow với contribution bằng 0."""),
            code("""import securaai_ml.api as temporal_api
temporal_api.ARTIFACT_DIR = ROOT / 'artifacts-temporal-candidate'
temporal_api.load_artifacts.cache_clear()
temporal_client = TestClient(temporal_api.app)
health = temporal_client.get('/health')
print('HTTP', health.status_code)
display(health.json())
"""),
            md("""### Kiểm thử payload temporal

Payload phải có `eventFamily`, `eventType` và các bộ đếm cửa sổ năm phút. Score chỉ là điểm classifier, không phải xác suất tấn công."""),
            code("""response=temporal_client.post('/v1/predict',json={
    'timestamp':'2026-11-03T02:00:00Z','eventFamily':'AUTHENTICATION',
    'eventType':'LOGIN_FAILURE','sourceIp':'203.0.113.10','status':'failure',
    'events5m':5,'failedLogins5m':5,'secondsSincePrevious':8,
})
print('HTTP',response.status_code); display(response.json())
assert response.status_code==200
"""),
        ])
    (OUT / filename).write_text(json.dumps(content, ensure_ascii=False, indent=1), encoding="utf-8")
print(f"Generated {len(selected)} notebook(s) in {OUT}")
