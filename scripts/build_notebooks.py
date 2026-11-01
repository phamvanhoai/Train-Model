"""Generate the lecturer-style SecuraAI notebook suite."""
from __future__ import annotations

import json, hashlib
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "notebooks"


def md(text: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": text.splitlines(keepends=True)}


def code(text: str) -> dict:
    return {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [],
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
        code("experiment_dir=ROOT/'reports'/'notebook_experiments'; experiment_dir.mkdir(parents=True,exist_ok=True)\nslug='" + number + "_" + key + "'\njoblib.dump(model,experiment_dir/f'{slug}.joblib')\nrecord={'model':model_name,'best_params':search.best_params_,'cv_best_f2':float(search.best_score_),'locked_threshold':locked_threshold,'split_hash':split_hash,'validation':{k:float(v) for k,v in result.items()},'test':{k:float(v) for k,v in test_result.items()}}\n(experiment_dir/f'{slug}.json').write_text(json.dumps(record,indent=2),encoding='utf-8')\nrecord"),
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
    md("# 07 — Soft Voting Ensemble\nKết hợp Decision Tree, Naive Bayes, Bagging, Random Forest và AdaBoost bằng trung bình xác suất."),
    code(SETUP + "\nfrom sklearn.ensemble import VotingClassifier"),
    md("## 1. Tạo ensemble\nLinear SVM không có `predict_proba` nguyên bản nên không tham gia Soft Voting."),
    code("factories=teaching_candidate_factories(42)\ngrids=teaching_parameter_grids()\nbase=['decision_tree','naive_bayes','bagging','random_forest','adaboost']\nestimators=[]\nfor name in base:\n    search=GridSearchCV(factories[name](),grids[name],scoring=make_scorer(fbeta_score,beta=2),cv=cv,n_jobs=1)\n    search.fit(X_train,y_train,groups=groups)\n    print(name, search.best_params_, search.best_score_)\n    estimators.append((name, search.best_estimator_))\nmodel=VotingClassifier(estimators=estimators,voting='soft',n_jobs=1)\nmodel.fit(X_train,y_train)"),
    md("## 2. Đánh giá Validation"),
    code("pred=model.predict(X_validation)\nscore=model.predict_proba(X_validation)[:,1]\nap=average_precision_score(y_validation,score)\nresult=pd.Series({'accuracy':accuracy_score(y_validation,pred),'precision':precision_score(y_validation,pred),'recall':recall_score(y_validation,pred),'f1':f1_score(y_validation,pred),'f2':fbeta_score(y_validation,pred,beta=2),'roc_auc':roc_auc_score(y_validation,score),'average_precision':ap})\ndisplay(result.to_frame('Validation'))\ntn,fp,fn,tp=confusion_matrix(y_validation,pred,labels=[0,1]).ravel()\nfig,axes=plt.subplots(1,3,figsize=(17,4.8))\nConfusionMatrixDisplay.from_predictions(y_validation,pred,display_labels=['BENIGN','MALICIOUS_APT'],ax=axes[0]); axes[0].set_title('Validation — Confusion Matrix')\nRocCurveDisplay.from_predictions(y_validation,score,name=f\"AUC={result['roc_auc']:.3f}\",ax=axes[1]); axes[1].plot([0,1],[0,1],'--',color='gray'); axes[1].scatter([fp/(fp+tn)],[tp/(tp+fn)],color='darkorange',zorder=5,label='Decision threshold'); axes[1].set_title('ROC — VALIDATION'); axes[1].legend()\nPrecisionRecallDisplay.from_predictions(y_validation,score,name=f'AP={ap:.3f}',ax=axes[2]); axes[2].axhline(float(y_validation.mean()),ls='--',color='gray',label=f'Positive rate={y_validation.mean():.3f}'); axes[2].set_title('Precision–Recall — VALIDATION'); axes[2].legend()\nplt.tight_layout(); plt.show()"),
    md("## 3. Lưu ý\nVoting không mặc nhiên tốt hơn mô hình đơn. Chỉ chọn nếu Validation F2 thực sự cao hơn."),
])

notebooks["08_Lua_Chon_Mo_Hinh_Va_Bao_Cao.ipynb"] = notebook([
    md("# 07 — Lựa chọn mô hình và báo cáo cuối\nNotebook này tổng hợp kết quả đã tạo bởi pipeline chuẩn. Xếp hạng chỉ dựa trên Validation; Test chỉ dùng báo cáo sau khi quyết định đã khóa."),
    code("from pathlib import Path\nimport json\nimport numpy as np\nimport pandas as pd\nimport matplotlib.pyplot as plt\nfrom IPython.display import display, Image\nfrom sklearn.metrics import confusion_matrix\nROOT=Path.cwd().parent if Path.cwd().name=='notebooks' else Path.cwd()\nreports=ROOT/'reports'\nsummary=json.loads((reports/'summary.json').read_text(encoding='utf-8'))"),
    md("## 1. Kiểm tra giao thức thực nghiệm"),
    code("display(pd.DataFrame({'rows':summary['splitRows'],'ratio':summary['splitRatios']}))\ntrain_dates=set(summary['splitGroups']['train']); validation_dates=set(summary['splitGroups']['validation']); test_dates=set(summary['splitGroups']['test'])\nassert train_dates.isdisjoint(validation_dates) and train_dates.isdisjoint(test_dates) and validation_dates.isdisjoint(test_dates)\nprint('Không có ngày thu thập giao nhau giữa ba tập.')"),
    md("## 2. Bảng so sánh trên Validation\nF2 là tiêu chí chốt vì với SOC, bỏ sót tấn công thường nguy hiểm hơn một cảnh báo cần kiểm tra thêm."),
    code("comparison=pd.read_csv(reports/'model_comparison.csv').sort_values(['f2','recall','precision'],ascending=False)\ndisplay(comparison[['model','best_params','cv_best_f2','accuracy','precision','recall','f1','f2','roc_auc','average_precision']])"),
    md("## 3. So sánh trực quan các metric\nKhông kết luận từ Accuracy một mình. Precision phản ánh tải cảnh báo giả; Recall phản ánh tỷ lệ tấn công được phát hiện."),
    code("metrics=['accuracy','precision','recall','f1','f2','roc_auc','average_precision']\nax=comparison.set_index('model')[metrics].plot.bar(figsize=(14,6),ylim=(0,1.05))\nax.set_ylabel('Validation score'); ax.set_title('So sánh mô hình — VALIDATION'); plt.xticks(rotation=25,ha='right'); plt.tight_layout(); plt.show()"),
    md("## 4. Quy tắc lựa chọn đã khóa\nMô hình có Validation F2 cao nhất được chọn. Ensemble không mặc định là người thắng; Voting chỉ được chọn nếu điểm Validation thực sự tốt hơn mô hình đơn."),
    code("selected_validation=comparison.iloc[0]\nprint('Theo bảng Validation:',selected_validation['model'])\nprint('Artifact chính thức:',summary['selectedModel'])\nassert selected_validation['model']==summary['selectedModel']\ndisplay(selected_validation.to_frame('selected'))"),
    md("## 5. Mở Test đúng một lần\nKhông dùng bảng này để quay lại đổi feature, siêu tham số hoặc mô hình. Nếu thay thiết kế, cần một Test mới độc lập."),
    code("test_metrics=pd.Series(summary['testMetrics'],name='Untouched Test')\ndisplay(test_metrics.to_frame())\ndisplay(Image(filename=str(reports/'confusion_matrix.png')))\ndisplay(Image(filename=str(reports/'roc_curve.png')))"),
    md("## 6. Ý nghĩa SOC của Confusion Matrix\n- **TP:** log tấn công được phát hiện.\n- **FN:** tấn công bị bỏ sót — rủi ro cần ưu tiên giảm.\n- **FP:** log bình thường bị cảnh báo — làm tăng tải analyst.\n- **TN:** log bình thường được bỏ qua đúng.\n\nDataset không cung cấp chi phí tiền tệ thực tế, vì vậy không tự suy diễn ROI từ các số đếm."),
    code("# Đọc số đếm từ dự đoán không được lưu riêng; hiển thị ảnh chính thức và diễn giải từ metric.\nrecall=test_metrics['recall']; precision=test_metrics['precision']\nprint(f'Mô hình phát hiện khoảng {recall:.2%} mẫu tấn công được gán nhãn trong Test.')\nprint(f'Trong các cảnh báo dương của mô hình, khoảng {precision:.2%} khớp nhãn tấn công của dataset.')\nprint('Đây là agreement với nhãn rule-derived, không phải tỷ lệ hiệu quả production đã được chứng minh.')"),
    md("## 7. Kiểm tra khoảng cách Validation–Test\nKhoảng cách lớn có thể báo hiệu overfit theo giai đoạn hoặc concept drift."),
    code("selected_metrics=selected_validation[metrics].astype(float)\ncommon=[m for m in metrics if m in test_metrics.index]\ngap=pd.DataFrame({'validation':selected_metrics[common],'test':test_metrics[common]})\ngap['absolute_gap']=(gap.validation-gap.test).abs()\ndisplay(gap)\ngap[['validation','test']].plot.bar(figsize=(11,5),ylim=(0,1.05),title='Validation và Test'); plt.tight_layout(); plt.show()"),
    md("## 8. Kết luận phương pháp\n- **Train:** học preprocessing, tham số và chạy K-Fold.\n- **Validation:** chọn mô hình/ngưỡng; chưa phải kết luận cuối.\n- **Test:** chỉ báo cáo sau khi khóa quyết định.\n- **Ensemble:** chỉ dùng khi có bằng chứng Validation tốt hơn.\n- **Không refit tùy tiện:** refit Train+Validation thay đổi mô hình đã đánh giá; nếu refit để triển khai cần hiệu chuẩn/ngưỡng mới bằng out-of-fold hoặc một validation mới.\n- **Khả năng triển khai:** chạy shadow mode, lưu model version/evidence và theo dõi drift trước khi tự động hóa incident."),
    md("## 9. Giới hạn bắt buộc khi bảo vệ\n- Nhãn bắt nguồn từ MITRE/Wazuh rule, không phải ground truth độc lập.\n- Dữ liệu là môi trường Windows APT mô phỏng.\n- Không chứng minh hiệu năng cho VPN/SSO, web, Linux, brute-force hoặc zero-day.\n- Điểm classifier không phải xác suất tấn công đã hiệu chỉnh.\n- Cần external validation bằng log Wazuh thật của SecuraAI trước production."),
    md("## 10. Kết luận cuối\nMục tiêu của phần ML là chứng minh nhóm hiểu quy trình xây dựng, đánh giá và tích hợp mô hình vào hệ thống phần mềm. Kết quả không nhằm tuyên bố vượt qua Wazuh, SOC analyst hoặc LLM lớn."),
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
    code("experiment_dir=ROOT/'reports'/'notebook_experiments'; experiment_dir.mkdir(parents=True,exist_ok=True)\nrecord={'model':'rule_based','rule_weights':dict(rule_weights.values.tolist()),'locked_threshold':locked_threshold,'split_hash':split_hash,'validation':{k:float(v) for k,v in validation_result.items()},'test':{k:float(v) for k,v in test_result.items()}}\n(experiment_dir/'03_rule_based.json').write_text(json.dumps(record,indent=2),encoding='utf-8'); record"),
    md("## 12. Kết luận và giới hạn\nRule-Based là baseline giải thích được nhưng độ bao phủ thấp và không tự thích nghi. Chỉ dùng để chứng minh mô hình học máy có cải thiện thực sự; không trình bày đây là mô hình AI hoặc thay thế Wazuh."),
])

OUT.mkdir(parents=True, exist_ok=True)
for filename, content in notebooks.items():
    (OUT / filename).write_text(json.dumps(content, ensure_ascii=False, indent=1), encoding="utf-8")
print(f"Generated {len(notebooks)} notebooks in {OUT}")
